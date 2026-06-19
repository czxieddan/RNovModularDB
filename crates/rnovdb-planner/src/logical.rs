use rnovdb_common::ids::RelationId;
use rnovdb_common::{ErrorKind, Result, RnovError};
use rnovdb_sql::ast::{BoundStatement, ColumnDef, Expr, ObjectName, TransactionAction};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogicalPlan {
    Scan {
        relation_id: RelationId,
        table: String,
    },
    Filter {
        predicate: Expr,
        input: Box<LogicalPlan>,
    },
    Project {
        columns: Vec<String>,
        input: Box<LogicalPlan>,
    },
    Insert {
        table: String,
        columns: Vec<String>,
        values: Vec<Expr>,
    },
    Update {
        relation_id: RelationId,
        table: String,
        assignments: Vec<(String, Expr)>,
        selection: Option<Expr>,
    },
    Delete {
        relation_id: RelationId,
        table: String,
        selection: Option<Expr>,
    },
    CreateTable {
        table: String,
        columns: Vec<ColumnDef>,
    },
    AlterTableAddColumn {
        relation_id: RelationId,
        table: String,
        column: ColumnDef,
    },
    DropTable {
        relation_id: Option<RelationId>,
        table: String,
        if_exists: bool,
    },
    Transaction {
        action: String,
    },
}

#[derive(Clone, Debug, Default)]
pub struct LogicalPlanner;

impl LogicalPlanner {
    pub fn new() -> Self {
        Self
    }

    pub fn plan(&self, statement: &BoundStatement) -> Result<LogicalPlan> {
        match statement {
            BoundStatement::CreateTable { name, columns } => Ok(LogicalPlan::CreateTable {
                table: object_name(name),
                columns: columns.clone(),
            }),
            BoundStatement::AlterTableAddColumn {
                relation_id,
                table,
                column,
            } => Ok(LogicalPlan::AlterTableAddColumn {
                relation_id: *relation_id,
                table: object_name(table),
                column: column.clone(),
            }),
            BoundStatement::DropTable {
                relation_id,
                name,
                if_exists,
            } => Ok(LogicalPlan::DropTable {
                relation_id: *relation_id,
                table: object_name(name),
                if_exists: *if_exists,
            }),
            BoundStatement::Insert {
                table,
                columns,
                values,
            } => Ok(LogicalPlan::Insert {
                table: object_name(table),
                columns: columns.iter().map(|column| column.name.clone()).collect(),
                values: values.clone(),
            }),
            BoundStatement::Update(update) => Ok(LogicalPlan::Update {
                relation_id: update.relation_id,
                table: object_name(&update.table),
                assignments: update
                    .assignments
                    .iter()
                    .map(|assignment| (assignment.column.name.clone(), assignment.value.clone()))
                    .collect(),
                selection: update.selection.clone(),
            }),
            BoundStatement::Delete(delete) => Ok(LogicalPlan::Delete {
                relation_id: delete.relation_id,
                table: object_name(&delete.table),
                selection: delete.selection.clone(),
            }),
            BoundStatement::Select(select) => {
                let mut plan = LogicalPlan::Scan {
                    relation_id: select.relation_id,
                    table: object_name(&select.table),
                };
                if let Some(predicate) = &select.selection {
                    plan = LogicalPlan::Filter {
                        predicate: predicate.clone(),
                        input: Box::new(plan),
                    };
                }
                Ok(LogicalPlan::Project {
                    columns: select
                        .columns
                        .iter()
                        .map(|column| column.name.clone())
                        .collect(),
                    input: Box::new(plan),
                })
            }
            BoundStatement::CreateFunction { .. }
            | BoundStatement::CreateOperator { .. }
            | BoundStatement::CreateRole { .. }
            | BoundStatement::CreatePolicy { .. }
            | BoundStatement::GrantTablePrivilege { .. } => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "logical planning for this statement is not implemented yet",
            )),
            BoundStatement::Transaction { action } => Ok(LogicalPlan::Transaction {
                action: transaction_action_name(*action).to_string(),
            }),
        }
    }
}

fn object_name(name: &ObjectName) -> String {
    name.to_string()
}

fn transaction_action_name(action: TransactionAction) -> &'static str {
    match action {
        TransactionAction::Begin => "begin",
        TransactionAction::Commit => "commit",
        TransactionAction::Rollback => "rollback",
    }
}
