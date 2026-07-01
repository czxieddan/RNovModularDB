use std::time::Instant;

use rnmdb_catalog::{Catalog, IndexKey, OperatorSignature, Privilege, RowPolicy};
use rnmdb_common::{
    ErrorKind, Result, RnovError,
    ids::{DatabaseId, RelationId, RoleId},
};
use rnmdb_executor::{
    memory::{ExecutionResult, MemoryExecutor, ParallelQueryConfig},
    vector::VectorBatch,
};
use rnmdb_planner::{
    cost::{CostModel, StatisticsCatalog},
    logical::{LogicalPlan, LogicalPlanner},
    optimizer::RuleOptimizer,
    physical::{IndexAccessPath, IndexCatalog, PhysicalPlanner},
};
use rnmdb_sql::{
    ast::{BoundStatement, ColumnDef, ExplainFormat, ObjectName},
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
            BoundStatement::CreateTable {
                name,
                columns,
                if_not_exists,
            } => {
                self.apply_catalog_create_table(name, columns, *if_not_exists)?;
                let plan = self.planner.plan(&bound)?;
                self.executor.execute_mut(&plan).map(CommandOutput::from)
            }
            BoundStatement::CreateIndex {
                name,
                relation_id,
                keys,
                method,
                unique,
                if_not_exists,
                ..
            } => {
                let plan = self.planner.plan(&bound)?;
                self.executor.execute_mut(&plan)?;
                self.apply_catalog_create_index(
                    name,
                    *relation_id,
                    keys,
                    *method,
                    *unique,
                    *if_not_exists,
                )?;
                Ok(CommandOutput::SchemaChanged)
            }
            BoundStatement::DropIndex { name, if_exists } => {
                let plan = self.planner.plan(&bound)?;
                self.executor.execute_mut(&plan)?;
                self.apply_catalog_drop_index(name, *if_exists)?;
                Ok(CommandOutput::SchemaChanged)
            }
            BoundStatement::DropFunction {
                name,
                argument_types,
                if_exists,
            } => {
                self.apply_catalog_drop_function(name.as_str(), argument_types, *if_exists)?;
                Ok(CommandOutput::SchemaChanged)
            }
            BoundStatement::DropProcedure {
                name,
                argument_types,
                if_exists,
            } => {
                self.apply_catalog_drop_procedure(name.as_str(), argument_types, *if_exists)?;
                Ok(CommandOutput::SchemaChanged)
            }
            BoundStatement::DropOperator {
                symbol,
                left_type,
                right_type,
                if_exists,
            } => {
                self.apply_catalog_drop_operator(symbol, left_type, right_type, *if_exists)?;
                Ok(CommandOutput::SchemaChanged)
            }
            BoundStatement::DropRole { name, if_exists } => {
                self.apply_catalog_drop_role(name.as_str(), *if_exists)?;
                Ok(CommandOutput::SchemaChanged)
            }
            BoundStatement::DropPolicy {
                name,
                relation_id,
                if_exists,
            } => {
                self.apply_catalog_drop_policy(name.as_str(), *relation_id, *if_exists)?;
                Ok(CommandOutput::SchemaChanged)
            }
            BoundStatement::AlterTableAddColumn {
                table,
                column,
                if_not_exists,
                ..
            } => {
                self.apply_catalog_add_column(table, column, *if_not_exists)?;
                let plan = self.planner.plan(&bound)?;
                self.executor.execute_mut(&plan).map(CommandOutput::from)
            }
            BoundStatement::AlterColumnEncryption {
                table,
                column,
                encrypted,
                ..
            } => {
                self.apply_catalog_set_column_encrypted(table, column.as_str(), *encrypted)?;
                let plan = self.planner.plan(&bound)?;
                self.executor.execute_mut(&plan).map(CommandOutput::from)
            }
            BoundStatement::DropTable {
                name, if_exists, ..
            } => {
                self.apply_catalog_drop_table(name, *if_exists)?;
                let plan = self.planner.plan(&bound)?;
                self.executor.execute_mut(&plan).map(CommandOutput::from)
            }
            BoundStatement::CreateFunction {
                name,
                argument_types,
                return_type,
                if_not_exists,
            } => {
                self.apply_catalog_create_function(
                    name.as_str(),
                    argument_types,
                    return_type,
                    *if_not_exists,
                )?;
                Ok(CommandOutput::SchemaChanged)
            }
            BoundStatement::CreateProcedure {
                name,
                argument_types,
                body,
                if_not_exists,
            } => {
                self.apply_catalog_create_procedure(
                    name.as_str(),
                    argument_types,
                    body,
                    *if_not_exists,
                )?;
                Ok(CommandOutput::SchemaChanged)
            }
            BoundStatement::CallProcedure { body, args, .. } => {
                let expanded = expand_procedure_body(body, args)?;
                self.execute(expanded.as_str())
            }
            BoundStatement::CreateOperator { signature } => {
                self.catalog.register_operator(signature.clone())?;
                Ok(CommandOutput::SchemaChanged)
            }
            BoundStatement::CreateRole {
                name,
                if_not_exists,
            } => {
                self.apply_catalog_create_role(name.as_str(), *if_not_exists)?;
                Ok(CommandOutput::SchemaChanged)
            }
            BoundStatement::CreatePolicy {
                name,
                relation_id,
                predicate,
                if_not_exists,
            } => {
                self.apply_catalog_create_policy(
                    name.as_str(),
                    *relation_id,
                    predicate.as_str(),
                    *if_not_exists,
                )?;
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
            BoundStatement::Explain {
                analyze,
                format,
                statement,
            } => {
                let plan = self.optimize_read_plan(self.planner.plan(statement)?);
                let mut text = self.explain_plan(&plan, *format);
                if *analyze {
                    let started = Instant::now();
                    let batch = self
                        .executor
                        .execute_parallel(&plan, self.execution.parallel_query())?;
                    let elapsed = started.elapsed();
                    text.push_str(&format!(
                        "Analyze rows={} elapsed_us={}\n",
                        batch.rows().len(),
                        elapsed.as_micros()
                    ));
                }
                Ok(CommandOutput::Text(text))
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
        if_not_exists: bool,
    ) -> Result<()> {
        let schema = name.schema().unwrap_or("public");
        if self.catalog.get_table(schema, name.object()).is_some() && if_not_exists {
            return Ok(());
        }
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
        keys: &[rnmdb_sql::ast::BoundIndexKey],
        method: rnmdb_catalog::IndexMethod,
        unique: bool,
        if_not_exists: bool,
    ) -> Result<()> {
        let schema = name.schema().unwrap_or("public");
        if self.catalog.get_index(schema, name.object()).is_some() && if_not_exists {
            return Ok(());
        }
        let keys = keys
            .iter()
            .map(|key| match key {
                rnmdb_sql::ast::BoundIndexKey::Column(column) => {
                    IndexKey::column(column.name.clone())
                }
                rnmdb_sql::ast::BoundIndexKey::Expression { expr, .. } => {
                    IndexKey::expression(expr.to_string())
                }
            })
            .collect::<Vec<_>>();
        self.catalog.create_index_with_keys(
            schema,
            name.object(),
            relation_id,
            keys,
            method,
            unique,
        )?;
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

    fn apply_catalog_drop_function(
        &mut self,
        name: &str,
        argument_types: &[SqlType],
        if_exists: bool,
    ) -> Result<()> {
        match self.catalog.drop_function(name, argument_types)? {
            Some(_) => Ok(()),
            None if if_exists => Ok(()),
            None => Err(rnmdb_common::RnovError::new(
                rnmdb_common::ErrorKind::NotFound,
                format!("function does not exist: {name}"),
            )),
        }
    }

    fn apply_catalog_drop_procedure(
        &mut self,
        name: &str,
        argument_types: &[SqlType],
        if_exists: bool,
    ) -> Result<()> {
        match self.catalog.drop_procedure(name, argument_types)? {
            Some(_) => Ok(()),
            None if if_exists => Ok(()),
            None => Err(rnmdb_common::RnovError::new(
                rnmdb_common::ErrorKind::NotFound,
                format!("procedure does not exist: {name}"),
            )),
        }
    }

    fn apply_catalog_drop_operator(
        &mut self,
        symbol: &str,
        left_type: &SqlType,
        right_type: &SqlType,
        if_exists: bool,
    ) -> Result<()> {
        match self.catalog.drop_operator(symbol, left_type, right_type)? {
            Some(_) => Ok(()),
            None if if_exists => Ok(()),
            None => Err(rnmdb_common::RnovError::new(
                rnmdb_common::ErrorKind::NotFound,
                format!("operator does not exist: {symbol}"),
            )),
        }
    }

    fn apply_catalog_drop_role(&mut self, name: &str, if_exists: bool) -> Result<()> {
        match self.catalog.drop_role(name)? {
            Some(_) => Ok(()),
            None if if_exists => Ok(()),
            None => Err(rnmdb_common::RnovError::new(
                rnmdb_common::ErrorKind::NotFound,
                format!("role does not exist: {name}"),
            )),
        }
    }

    fn apply_catalog_drop_policy(
        &mut self,
        name: &str,
        relation_id: RelationId,
        if_exists: bool,
    ) -> Result<()> {
        match self.catalog.drop_row_policy(relation_id, name)? {
            Some(_) => Ok(()),
            None if if_exists => Ok(()),
            None => Err(rnmdb_common::RnovError::new(
                rnmdb_common::ErrorKind::NotFound,
                format!("row policy does not exist: {name}"),
            )),
        }
    }

    fn apply_catalog_add_column(
        &mut self,
        table: &ObjectName,
        column: &ColumnDef,
        if_not_exists: bool,
    ) -> Result<()> {
        let schema = table.schema().unwrap_or("public");
        if self
            .catalog
            .get_table(schema, table.object())
            .is_some_and(|table| {
                table
                    .columns()
                    .iter()
                    .any(|existing| existing.name().eq_ignore_ascii_case(column.name.as_str()))
            })
            && if_not_exists
        {
            return Ok(());
        }
        self.catalog
            .add_column(schema, table.object(), column.to_catalog_column())?;
        Ok(())
    }

    fn apply_catalog_set_column_encrypted(
        &mut self,
        table: &ObjectName,
        column: &str,
        encrypted: bool,
    ) -> Result<()> {
        let schema = table.schema().unwrap_or("public");
        self.catalog
            .set_column_encrypted(schema, table.object(), column, encrypted)?;
        Ok(())
    }

    fn apply_catalog_drop_table(&mut self, name: &ObjectName, if_exists: bool) -> Result<()> {
        let schema = name.schema().unwrap_or("public");
        match self.catalog.drop_table(schema, name.object())? {
            Some(_) => Ok(()),
            None if if_exists => Ok(()),
            None => Err(rnmdb_common::RnovError::new(
                rnmdb_common::ErrorKind::NotFound,
                format!("table does not exist: {schema}.{}", name.object()),
            )),
        }
    }

    fn apply_catalog_create_function(
        &mut self,
        name: &str,
        argument_types: &[SqlType],
        return_type: &SqlType,
        if_not_exists: bool,
    ) -> Result<()> {
        if self.catalog.get_function(name, argument_types).is_some() && if_not_exists {
            return Ok(());
        }
        self.catalog
            .register_function(name, argument_types.to_vec(), return_type.clone())?;
        Ok(())
    }

    fn apply_catalog_create_procedure(
        &mut self,
        name: &str,
        argument_types: &[SqlType],
        body: &str,
        if_not_exists: bool,
    ) -> Result<()> {
        if self.catalog.get_procedure(name, argument_types).is_some() && if_not_exists {
            return Ok(());
        }
        self.catalog
            .register_procedure(name, argument_types.to_vec(), body)?;
        Ok(())
    }

    fn apply_catalog_create_role(&mut self, name: &str, if_not_exists: bool) -> Result<()> {
        if self.catalog.get_role(name).is_some() && if_not_exists {
            return Ok(());
        }
        self.catalog.create_role(name)?;
        Ok(())
    }

    fn apply_catalog_create_policy(
        &mut self,
        name: &str,
        relation_id: RelationId,
        predicate: &str,
        if_not_exists: bool,
    ) -> Result<()> {
        if self.catalog.get_row_policy(relation_id, name).is_some() && if_not_exists {
            return Ok(());
        }
        self.catalog
            .add_row_policy(RowPolicy::new(name, relation_id, predicate))?;
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

    fn optimize_read_plan(&self, plan: LogicalPlan) -> LogicalPlan {
        self.optimizer
            .optimize_parallel(plan, self.execution.worker_threads())
    }

    fn explain_plan(&self, plan: &LogicalPlan, format: ExplainFormat) -> String {
        let cost_model = self.cost_model_for_plan(plan);
        match format {
            ExplainFormat::Logical => plan.explain(),
            ExplainFormat::Costs => plan.explain_with_costs(&cost_model),
            ExplainFormat::Physical => PhysicalPlanner::new(cost_model)
                .with_indexes(self.index_catalog())
                .plan(plan)
                .explain(),
        }
    }

    fn index_catalog(&self) -> IndexCatalog {
        let mut catalog = IndexCatalog::new();
        for index in self.catalog.indexes() {
            catalog.add_index(IndexAccessPath::new(
                format!("{}.{}", index.schema_name(), index.name()),
                index.relation_id(),
                index.keys().to_vec(),
                index.method(),
                index.unique(),
            ));
        }
        catalog
    }

    fn cost_model_for_plan(&self, plan: &LogicalPlan) -> CostModel {
        let mut statistics = StatisticsCatalog::new();
        self.collect_plan_statistics(plan, &mut statistics);
        CostModel::new(statistics)
    }

    fn collect_plan_statistics(&self, plan: &LogicalPlan, statistics: &mut StatisticsCatalog) {
        match plan {
            LogicalPlan::Scan { relation_id, table } => {
                if let Some(table_statistics) = self.executor.table_statistics(table) {
                    statistics.set_table(*relation_id, table_statistics);
                }
            }
            LogicalPlan::TextSearch {
                relation_id,
                table,
                column,
                cost_hint,
                ..
            } => {
                if let Some(table_statistics) = self.executor.table_statistics(table) {
                    statistics.set_table(*relation_id, table_statistics);
                }
                for term in cost_hint
                    .required_terms
                    .iter()
                    .chain(cost_hint.optional_terms.iter())
                    .chain(cost_hint.excluded_terms.iter())
                {
                    if let Ok(Some(lexeme_statistics)) =
                        self.executor.text_lexeme_statistics(table, column, term)
                    {
                        statistics.set_text_lexeme(
                            *relation_id,
                            column.as_str(),
                            term.as_str(),
                            lexeme_statistics,
                        );
                    }
                }
            }
            LogicalPlan::Filter { input, .. }
            | LogicalPlan::Project { input, .. }
            | LogicalPlan::Aggregate { input, .. }
            | LogicalPlan::GroupedAggregate { input, .. }
            | LogicalPlan::GroupingSetsAggregate { input, .. }
            | LogicalPlan::Distinct { input }
            | LogicalPlan::Sort { input, .. }
            | LogicalPlan::Limit { input, .. }
            | LogicalPlan::Offset { input, .. }
            | LogicalPlan::Explain { input, .. }
            | LogicalPlan::Parallel { input, .. } => {
                self.collect_plan_statistics(input, statistics);
            }
            LogicalPlan::Union { left, right, .. }
            | LogicalPlan::Intersect { left, right, .. }
            | LogicalPlan::Except { left, right, .. } => {
                self.collect_plan_statistics(left, statistics);
                self.collect_plan_statistics(right, statistics);
            }
            LogicalPlan::RecursiveCte {
                seed,
                recursive,
                query,
                ..
            } => {
                self.collect_plan_statistics(seed, statistics);
                self.collect_plan_statistics(recursive, statistics);
                self.collect_plan_statistics(query, statistics);
            }
            _ => {}
        }
    }
}

fn is_read_query(statement: &BoundStatement) -> bool {
    matches!(
        statement,
        BoundStatement::Select(_)
            | BoundStatement::Union(_)
            | BoundStatement::Intersect(_)
            | BoundStatement::Except(_)
            | BoundStatement::RecursiveCte(_)
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

fn expand_procedure_body(body: &str, args: &[rnmdb_sql::ast::Expr]) -> Result<String> {
    let mut expanded = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\'' {
            expanded.push(ch);
            while let Some(inner) = chars.next() {
                expanded.push(inner);
                if inner == '\'' {
                    if chars.peek() == Some(&'\'') {
                        expanded.push(chars.next().expect("peeked quote must be present"));
                        continue;
                    }
                    break;
                }
            }
            continue;
        }

        if ch != '$' || !chars.peek().is_some_and(|next| next.is_ascii_digit()) {
            expanded.push(ch);
            continue;
        }

        let mut raw_index = String::new();
        while chars.peek().is_some_and(|next| next.is_ascii_digit()) {
            raw_index.push(chars.next().expect("peeked digit must be present"));
        }
        let index = raw_index.parse::<usize>().map_err(|_| {
            RnovError::new(
                ErrorKind::InvalidInput,
                format!("procedure parameter ${raw_index} is out of range"),
            )
        })?;
        if index == 0 || index > args.len() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("procedure parameter ${index} has no argument"),
            ));
        }
        expanded.push_str(procedure_argument_sql_literal(&args[index - 1])?.as_str());
    }
    Ok(expanded)
}

fn procedure_argument_sql_literal(expr: &rnmdb_sql::ast::Expr) -> Result<String> {
    match expr {
        rnmdb_sql::ast::Expr::Integer(value) => Ok(value.to_string()),
        rnmdb_sql::ast::Expr::String(value) => Ok(format!("'{}'", value.replace('\'', "''"))),
        rnmdb_sql::ast::Expr::Bool(true) => Ok("TRUE".to_string()),
        rnmdb_sql::ast::Expr::Bool(false) => Ok("FALSE".to_string()),
        rnmdb_sql::ast::Expr::Null => Ok("NULL".to_string()),
        _ => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "procedure arguments must be literal values",
        )),
    }
}

fn register_builtin_functions(catalog: &mut Catalog) -> Result<()> {
    let text_contains_text = catalog.register_function(
        "text_contains",
        vec![SqlType::Text, SqlType::Text],
        SqlType::Bool,
    )?;
    catalog.register_operator(OperatorSignature::new(
        "@@",
        SqlType::Text,
        SqlType::Text,
        SqlType::Bool,
        text_contains_text.function_id(),
    ))?;
    let text_contains_vector = catalog.register_function(
        "text_contains",
        vec![SqlType::TextVector, SqlType::Text],
        SqlType::Bool,
    )?;
    catalog.register_operator(OperatorSignature::new(
        "@@",
        SqlType::TextVector,
        SqlType::Text,
        SqlType::Bool,
        text_contains_vector.function_id(),
    ))?;
    catalog.register_function(
        "text_rank",
        vec![SqlType::Text, SqlType::Text],
        SqlType::Int64,
    )?;
    catalog.register_function(
        "text_rank",
        vec![SqlType::TextVector, SqlType::Text],
        SqlType::Int64,
    )?;
    catalog.register_function(
        "text_phrase_match",
        vec![SqlType::Text, SqlType::Text, SqlType::Int64],
        SqlType::Bool,
    )?;
    catalog.register_function(
        "text_phrase_match",
        vec![SqlType::TextVector, SqlType::Text, SqlType::Int64],
        SqlType::Bool,
    )?;
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
