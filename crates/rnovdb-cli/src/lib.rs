use rnovdb_catalog::{Catalog, Privilege};
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
        let plan = self.planner.plan(&bound)?;

        match &bound {
            BoundStatement::CreateTable { name, columns } => {
                self.apply_catalog_create_table(name, columns)?;
                self.executor.execute_mut(&plan).map(CommandOutput::from)
            }
            BoundStatement::AlterTableAddColumn { table, column, .. } => {
                self.apply_catalog_add_column(table, column)?;
                self.executor.execute_mut(&plan).map(CommandOutput::from)
            }
            BoundStatement::Select(_) => self.executor.execute(&plan).map(CommandOutput::Rows),
            _ => self.executor.execute_mut(&plan).map(CommandOutput::from),
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

impl From<ExecutionResult> for CommandOutput {
    fn from(result: ExecutionResult) -> Self {
        match result {
            ExecutionResult::Batch(batch) => Self::Rows(batch),
            ExecutionResult::RowsAffected(rows) => Self::RowsAffected(rows),
            ExecutionResult::SchemaChanged => Self::SchemaChanged,
        }
    }
}
