use rnovdb_catalog::{Catalog, OperatorSignature, Privilege, RowPolicy};
use rnovdb_common::{
    Result,
    ids::{DatabaseId, RelationId, RoleId},
};
use rnovdb_executor::{
    memory::{ExecutionResult, MemoryExecutor},
    vector::VectorBatch,
};
use rnovdb_planner::logical::LogicalPlanner;
use rnovdb_sql::{
    ast::{BoundStatement, ColumnDef, ObjectName},
    binder::Binder,
    parser::parse_statement,
};
use rnovdb_types::SqlType;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandOutput {
    Rows(VectorBatch),
    RowsAffected(u64),
    SchemaChanged,
}

pub struct LocalSession {
    catalog: Catalog,
    role_id: RoleId,
    executor: MemoryExecutor,
    planner: LogicalPlanner,
}

impl LocalSession {
    pub fn memory() -> Result<Self> {
        let mut catalog = Catalog::new(DatabaseId::new(1));
        catalog.create_schema("public")?;
        register_builtin_functions(&mut catalog)?;
        let role = catalog.create_role("local")?;
        Ok(Self {
            catalog,
            role_id: role.role_id(),
            executor: MemoryExecutor::new(),
            planner: LogicalPlanner::new(),
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
            BoundStatement::Select(_) => {
                let plan = self.planner.plan(&bound)?;
                self.executor.execute(&plan).map(CommandOutput::Rows)
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
