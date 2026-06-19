use rnovdb_common::ids::RelationId;
use rnovdb_common::{ErrorKind, Result, RnovError};
use rnovdb_sql::ast::{BoundStatement, Expr, ObjectName, TransactionAction};

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
    CreateTable {
        table: String,
        columns: Vec<String>,
    },
    AlterTableAddColumn {
        relation_id: RelationId,
        table: String,
        column: String,
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
                columns: columns
                    .iter()
                    .map(|column| column.name.as_str().to_string())
                    .collect(),
            }),
            BoundStatement::AlterTableAddColumn {
                relation_id,
                table,
                column,
            } => Ok(LogicalPlan::AlterTableAddColumn {
                relation_id: *relation_id,
                table: object_name(table),
                column: column.name.as_str().to_string(),
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
            BoundStatement::Update(_)
            | BoundStatement::Delete(_)
            | BoundStatement::CreateFunction { .. }
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
