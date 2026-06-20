use rnovdb_common::ids::RelationId;
use rnovdb_common::{ErrorKind, Result, RnovError};
use rnovdb_fts::TextQuery;
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
    TextSearch {
        relation_id: RelationId,
        table: String,
        column: String,
        query: String,
        cost_hint: TextSearchCostHint,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextSearchCostHint {
    pub required_terms: Vec<String>,
    pub optional_terms: Vec<String>,
    pub excluded_terms: Vec<String>,
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
                    plan = plan_selection(select.relation_id, &select.table, predicate, plan)?;
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

fn plan_selection(
    relation_id: RelationId,
    table: &ObjectName,
    predicate: &Expr,
    fallback_input: LogicalPlan,
) -> Result<LogicalPlan> {
    if let Some((column, query)) = text_search_predicate(predicate) {
        let parsed = TextQuery::parse(query)?;
        return Ok(LogicalPlan::TextSearch {
            relation_id,
            table: object_name(table),
            column: column.to_string(),
            query: query.to_string(),
            cost_hint: TextSearchCostHint {
                required_terms: parsed
                    .required_terms()
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                optional_terms: parsed
                    .optional_terms()
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                excluded_terms: parsed
                    .excluded_terms()
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            },
        });
    }

    Ok(LogicalPlan::Filter {
        predicate: predicate.clone(),
        input: Box::new(fallback_input),
    })
}

fn text_search_predicate(predicate: &Expr) -> Option<(&str, &str)> {
    let Expr::Binary { left, op, right } = predicate else {
        return None;
    };
    if op != "@@" {
        return None;
    }

    let Expr::Identifier(column) = left.as_ref() else {
        return None;
    };
    let Expr::String(query) = right.as_ref() else {
        return None;
    };

    Some((column.as_str(), query.as_str()))
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
