use std::time::Instant;

use rnmdb_catalog::{Catalog, OperatorSignature, Privilege, RowPolicy};
use rnmdb_common::{
    Result,
    ids::{DatabaseId, RelationId, RoleId},
};
use rnmdb_executor::{
    memory::{ExecutionResult, MemoryExecutor, ParallelQueryConfig},
    vector::VectorBatch,
};
use rnmdb_planner::{logical::LogicalPlanner, optimizer::RuleOptimizer};
use rnmdb_sql::{
    ast::{BoundStatement, ColumnDef, ObjectName},
    binder::Binder,
    parser::parse_statement,
};
use rnmdb_storage::{
    SingleFileBackupReport, SingleFileInspection, SingleFileRestoreDryRun,
    SingleFileVerificationReport, backup_single_file, inspect_single_file,
    restore_single_file_dry_run, verify_single_file,
};
use rnmdb_types::SqlType;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandOutput {
    Rows(VectorBatch),
    RowsAffected(u64),
    SchemaChanged,
    Text(String),
}

pub struct LocalSession {
    catalog: Catalog,
    role_id: RoleId,
    executor: MemoryExecutor,
    planner: LogicalPlanner,
    optimizer: RuleOptimizer,
    execution: LocalExecutionConfig,
}

impl LocalSession {
    pub fn memory() -> Result<Self> {
        Self::memory_with_execution(LocalExecutionConfig::default())
    }

    pub fn memory_parallel(worker_threads: usize) -> Result<Self> {
        Self::memory_with_execution(LocalExecutionConfig::parallel(worker_threads)?)
    }

    pub fn memory_with_execution(execution: LocalExecutionConfig) -> Result<Self> {
        let mut catalog = Catalog::new(DatabaseId::new(1));
        catalog.create_schema("public")?;
        register_builtin_functions(&mut catalog)?;
        let role = catalog.create_role("local")?;
        Ok(Self {
            catalog,
            role_id: role.role_id(),
            executor: MemoryExecutor::new(),
            planner: LogicalPlanner::new(),
            optimizer: RuleOptimizer::new(),
            execution,
        })
    }

    pub fn execute(&mut self, sql: &str) -> Result<CommandOutput> {
        let statement = parse_statement(sql)?;
        let bound = Binder::new(&self.catalog).bind_for_role(&statement, self.role_id)?;

        match &bound {
            BoundStatement::CreateTable { name, columns } => {
                self.apply_catalog_create_table(name, columns)?;
                let plan = self.planner.plan(&bound)?;
                self.executor.execute_mut(&plan).map(CommandOutput::from)
            }
            BoundStatement::CreateIndex {
                name,
                relation_id,
                columns,
                unique,
                ..
            } => {
                self.apply_catalog_create_index(name, *relation_id, columns, *unique)?;
                Ok(CommandOutput::SchemaChanged)
            }
            BoundStatement::DropIndex { name, if_exists } => {
                self.apply_catalog_drop_index(name, *if_exists)?;
                Ok(CommandOutput::SchemaChanged)
            }
            BoundStatement::AlterTableAddColumn { table, column, .. } => {
                self.apply_catalog_add_column(table, column)?;
                let plan = self.planner.plan(&bound)?;
                self.executor.execute_mut(&plan).map(CommandOutput::from)
            }
            BoundStatement::CreateFunction {
                name,
                argument_types,
                return_type,
            } => {
                self.catalog.register_function(
                    name.as_str(),
                    argument_types.clone(),
                    return_type.clone(),
                )?;
                Ok(CommandOutput::SchemaChanged)
            }
            BoundStatement::CreateOperator { signature } => {
                self.catalog.register_operator(signature.clone())?;
                Ok(CommandOutput::SchemaChanged)
            }
            BoundStatement::CreateRole { name } => {
                self.catalog.create_role(name.as_str())?;
                Ok(CommandOutput::SchemaChanged)
            }
            BoundStatement::CreatePolicy {
                name,
                relation_id,
                predicate,
            } => {
                self.catalog.add_row_policy(RowPolicy::new(
                    name.as_str(),
                    *relation_id,
                    predicate.as_str(),
                ))?;
                Ok(CommandOutput::SchemaChanged)
            }
            BoundStatement::GrantTablePrivilege {
                role_id,
                relation_id,
                privilege,
            } => {
                self.catalog
                    .grant_table_privilege(*role_id, *relation_id, *privilege)?;
                Ok(CommandOutput::SchemaChanged)
            }
            statement if is_read_query(statement) => {
                let plan = self.optimize_read_plan(self.planner.plan(&bound)?);
                self.executor
                    .execute_parallel(&plan, self.execution.parallel_query())
                    .map(CommandOutput::Rows)
            }
            BoundStatement::Explain { analyze, statement } => {
                let plan = self.optimize_read_plan(self.planner.plan(statement)?);
                if *analyze {
                    let started = Instant::now();
                    let batch = self
                        .executor
                        .execute_parallel(&plan, self.execution.parallel_query())?;
                    let elapsed = started.elapsed();
                    Ok(CommandOutput::Text(format!(
                        "{}Analyze rows={} elapsed_us={}\n",
                        plan.explain(),
                        batch.rows().len(),
                        elapsed.as_micros()
                    )))
                } else {
                    Ok(CommandOutput::Text(plan.explain()))
                }
            }
            _ => {
                let plan = self.planner.plan(&bound)?;
                self.executor.execute_mut(&plan).map(CommandOutput::from)
            }
        }
    }

    fn apply_catalog_create_table(
        &mut self,
        name: &ObjectName,
        columns: &[ColumnDef],
    ) -> Result<()> {
        let schema = name.schema().unwrap_or("public");
        let columns = columns
            .iter()
            .map(ColumnDef::to_catalog_column)
            .collect::<Vec<_>>();
        let relation_id = self
            .catalog
            .create_table(schema, name.object(), columns)?
            .relation_id();
        self.grant_local_table_privileges(relation_id)
    }

    fn apply_catalog_create_index(
        &mut self,
        name: &ObjectName,
        relation_id: RelationId,
        columns: &[rnmdb_sql::ast::BoundColumn],
        unique: bool,
    ) -> Result<()> {
        let schema = name.schema().unwrap_or("public");
        let columns = columns
            .iter()
            .map(|column| column.name.clone())
            .collect::<Vec<_>>();
        self.catalog
            .create_index(schema, name.object(), relation_id, columns, unique)?;
        Ok(())
    }

    fn apply_catalog_drop_index(&mut self, name: &ObjectName, if_exists: bool) -> Result<()> {
        let schema = name.schema().unwrap_or("public");
        match self.catalog.drop_index(schema, name.object())? {
            Some(_) => Ok(()),
            None if if_exists => Ok(()),
            None => Err(rnmdb_common::RnovError::new(
                rnmdb_common::ErrorKind::NotFound,
                format!("index does not exist: {schema}.{}", name.object()),
            )),
        }
    }

    fn apply_catalog_add_column(&mut self, table: &ObjectName, column: &ColumnDef) -> Result<()> {
        let schema = table.schema().unwrap_or("public");
        self.catalog
            .add_column(schema, table.object(), column.to_catalog_column())?;
        Ok(())
    }

    fn grant_local_table_privileges(&mut self, relation_id: RelationId) -> Result<()> {
        for privilege in [
            Privilege::Select,
            Privilege::Insert,
            Privilege::Update,
            Privilege::Delete,
        ] {
            self.catalog
                .grant_table_privilege(self.role_id, relation_id, privilege)?;
        }
        Ok(())
    }

    fn optimize_read_plan(
        &self,
        plan: rnmdb_planner::logical::LogicalPlan,
    ) -> rnmdb_planner::logical::LogicalPlan {
        self.optimizer
            .optimize_parallel(plan, self.execution.worker_threads())
    }
}

fn is_read_query(statement: &BoundStatement) -> bool {
    matches!(
        statement,
        BoundStatement::Select(_)
            | BoundStatement::Union(_)
            | BoundStatement::Intersect(_)
            | BoundStatement::Except(_)
            | BoundStatement::Query(_)
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalExecutionConfig {
    worker_threads: usize,
    min_parallel_rows: usize,
}

impl LocalExecutionConfig {
    pub fn parallel(worker_threads: usize) -> Result<Self> {
        Self::new(worker_threads, 1024)
    }

    pub fn new(worker_threads: usize, min_parallel_rows: usize) -> Result<Self> {
        if worker_threads == 0 {
            return Err(rnmdb_common::RnovError::new(
                rnmdb_common::ErrorKind::InvalidInput,
                "local execution worker count must be greater than zero",
            ));
        }
        Ok(Self {
            worker_threads,
            min_parallel_rows,
        })
    }

    pub fn worker_threads(self) -> usize {
        self.worker_threads
    }

    pub fn min_parallel_rows(self) -> usize {
        self.min_parallel_rows
    }

    pub fn parallel_query(self) -> ParallelQueryConfig {
        ParallelQueryConfig::new(self.worker_threads, self.min_parallel_rows)
    }
}

impl Default for LocalExecutionConfig {
    fn default() -> Self {
        Self {
            worker_threads: 1,
            min_parallel_rows: 1024,
        }
    }
}

fn register_builtin_functions(catalog: &mut Catalog) -> Result<()> {
    let text_contains = catalog.register_function(
        "text_contains",
        vec![SqlType::Text, SqlType::Text],
        SqlType::Bool,
    )?;
    catalog.register_operator(OperatorSignature::new(
        "@@",
        SqlType::Text,
        SqlType::Text,
        SqlType::Bool,
        text_contains.function_id(),
    ))?;
    Ok(())
}

impl From<ExecutionResult> for CommandOutput {
    fn from(result: ExecutionResult) -> Self {
        match result {
            ExecutionResult::Batch(batch) => Self::Rows(batch),
            ExecutionResult::RowsAffected(rows) => Self::RowsAffected(rows),
            ExecutionResult::SchemaChanged => Self::SchemaChanged,
        }
    }
}

pub fn inspect_storage(path: impl AsRef<std::path::Path>) -> Result<SingleFileInspection> {
    inspect_single_file(path)
}

pub fn backup_storage(
    source: impl AsRef<std::path::Path>,
    destination: impl AsRef<std::path::Path>,
) -> Result<SingleFileBackupReport> {
    backup_single_file(source, destination)
}

pub fn verify_storage(path: impl AsRef<std::path::Path>) -> Result<SingleFileVerificationReport> {
    verify_single_file(path)
}

pub fn restore_storage_dry_run(
    backup: impl AsRef<std::path::Path>,
    target: impl AsRef<std::path::Path>,
) -> Result<SingleFileRestoreDryRun> {
    restore_single_file_dry_run(backup, target)
}
