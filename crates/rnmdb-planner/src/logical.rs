use rnmdb_common::ids::RelationId;
use rnmdb_common::{ErrorKind, Result, RnovError};
use rnmdb_fts::TextQuery;
use rnmdb_sql::ast::{BoundStatement, ColumnDef, Expr, ObjectName, OrderByExpr, TransactionAction};

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
        items: Vec<ProjectionItem>,
        input: Box<LogicalPlan>,
    },
    Sort {
        keys: Vec<OrderByExpr>,
        input: Box<LogicalPlan>,
    },
    Limit {
        count: usize,
        input: Box<LogicalPlan>,
    },
    Offset {
        count: usize,
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
    Explain {
        analyze: bool,
        input: Box<LogicalPlan>,
    },
    Parallel {
        hint: ParallelPlanHint,
        input: Box<LogicalPlan>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionItem {
    pub name: String,
    pub expr: Expr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextSearchCostHint {
    pub required_terms: Vec<String>,
    pub optional_terms: Vec<String>,
    pub excluded_terms: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParallelPlanHint {
    pub workers: usize,
    pub reason: String,
}

impl ParallelPlanHint {
    pub fn new(workers: usize, reason: impl Into<String>) -> Result<Self> {
        if workers == 0 {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "parallel plan worker count must be greater than zero",
            ));
        }
        Ok(Self {
            workers,
            reason: reason.into(),
        })
    }
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
                for policy in &select.row_policy_predicates {
                    plan =
                        plan_selection(select.relation_id, &select.table, &policy.predicate, plan)?;
                }
                if let Some(predicate) = &select.selection {
                    plan = plan_selection(select.relation_id, &select.table, predicate, plan)?;
                }
                if !select.order_by.is_empty() {
                    plan = LogicalPlan::Sort {
                        keys: select.order_by.clone(),
                        input: Box::new(plan),
                    };
                }
                let plan = LogicalPlan::Project {
                    items: select
                        .projection
                        .iter()
                        .map(|item| ProjectionItem {
                            name: item.column.name.clone(),
                            expr: item.expr.clone(),
                        })
                        .collect(),
                    input: Box::new(plan),
                };
                let plan = if let Some(count) = select.offset {
                    LogicalPlan::Offset {
                        count,
                        input: Box::new(plan),
                    }
                } else {
                    plan
                };
                if let Some(count) = select.limit {
                    Ok(LogicalPlan::Limit {
                        count,
                        input: Box::new(plan),
                    })
                } else {
                    Ok(plan)
                }
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
            BoundStatement::Explain { analyze, statement } => Ok(LogicalPlan::Explain {
                analyze: *analyze,
                input: Box::new(self.plan(statement)?),
            }),
        }
    }
}

impl LogicalPlan {
    pub fn explain(&self) -> String {
        let mut out = String::new();
        write_plan(self, 0, &mut out);
        out
    }
}

fn write_plan(plan: &LogicalPlan, indent: usize, out: &mut String) {
    let prefix = "  ".repeat(indent);
    match plan {
        LogicalPlan::Scan { table, .. } => {
            out.push_str(&format!("{prefix}Scan table={table}\n"));
        }
        LogicalPlan::Filter { predicate, input } => {
            out.push_str(&format!("{prefix}Filter predicate={predicate}\n"));
            write_plan(input, indent + 1, out);
        }
        LogicalPlan::TextSearch {
            table,
            column,
            query,
            ..
        } => {
            out.push_str(&format!(
                "{prefix}TextSearch table={table} column={column} query='{query}'\n"
            ));
        }
        LogicalPlan::Project { items, input } => {
            let columns = items
                .iter()
                .map(|item| format!("{} := {}", item.name, item.expr))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("{prefix}Project {columns}\n"));
            write_plan(input, indent + 1, out);
        }
        LogicalPlan::Sort { keys, input } => {
            let keys = keys
                .iter()
                .map(|key| format!("{} {}", key.expr, sort_direction_name(key.direction)))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("{prefix}Sort {keys}\n"));
            write_plan(input, indent + 1, out);
        }
        LogicalPlan::Limit { count, input } => {
            out.push_str(&format!("{prefix}Limit count={count}\n"));
            write_plan(input, indent + 1, out);
        }
        LogicalPlan::Offset { count, input } => {
            out.push_str(&format!("{prefix}Offset count={count}\n"));
            write_plan(input, indent + 1, out);
        }
        LogicalPlan::Insert { table, columns, .. } => {
            out.push_str(&format!(
                "{prefix}Insert table={table} columns={}\n",
                columns.join(", ")
            ));
        }
        LogicalPlan::Update {
            table,
            assignments,
            selection,
            ..
        } => {
            let assignments = assignments
                .iter()
                .map(|(column, expr)| format!("{column} = {expr}"))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("{prefix}Update table={table} set={assignments}"));
            if let Some(selection) = selection {
                out.push_str(&format!(" where={selection}"));
            }
            out.push('\n');
        }
        LogicalPlan::Delete {
            table, selection, ..
        } => {
            out.push_str(&format!("{prefix}Delete table={table}"));
            if let Some(selection) = selection {
                out.push_str(&format!(" where={selection}"));
            }
            out.push('\n');
        }
        LogicalPlan::CreateTable { table, columns } => {
            out.push_str(&format!(
                "{prefix}CreateTable table={table} columns={}\n",
                columns
                    .iter()
                    .map(|column| column.name.as_str().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        LogicalPlan::AlterTableAddColumn { table, column, .. } => {
            out.push_str(&format!(
                "{prefix}AlterTableAddColumn table={table} column={}\n",
                column.name
            ));
        }
        LogicalPlan::DropTable {
            table, if_exists, ..
        } => {
            out.push_str(&format!(
                "{prefix}DropTable table={table} if_exists={if_exists}\n"
            ));
        }
        LogicalPlan::Transaction { action } => {
            out.push_str(&format!("{prefix}Transaction action={action}\n"));
        }
        LogicalPlan::Explain { analyze, input } => {
            out.push_str(&format!("{prefix}Explain analyze={analyze}\n"));
            write_plan(input, indent + 1, out);
        }
        LogicalPlan::Parallel { hint, input } => {
            out.push_str(&format!(
                "{prefix}Parallel workers={} reason={}\n",
                hint.workers, hint.reason
            ));
            write_plan(input, indent + 1, out);
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

fn sort_direction_name(direction: rnmdb_sql::ast::SortDirection) -> &'static str {
    match direction {
        rnmdb_sql::ast::SortDirection::Asc => "ASC",
        rnmdb_sql::ast::SortDirection::Desc => "DESC",
    }
}
