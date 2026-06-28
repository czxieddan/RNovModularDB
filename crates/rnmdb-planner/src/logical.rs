use rnmdb_common::ids::{FunctionId, RelationId, RoleId};
use rnmdb_common::{ErrorKind, Result, RnovError};
use rnmdb_fts::TextQuery;
use rnmdb_sql::ast::{BoundStatement, ColumnDef, Expr, ObjectName, OrderByExpr, TransactionAction};
use rnmdb_types::SqlType;

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
    Aggregate {
        items: Vec<AggregateItem>,
        input: Box<LogicalPlan>,
    },
    GroupedAggregate {
        group_by: Vec<Expr>,
        items: Vec<GroupedAggregateItem>,
        input: Box<LogicalPlan>,
    },
    Distinct {
        input: Box<LogicalPlan>,
    },
    Union {
        all: bool,
        left: Box<LogicalPlan>,
        right: Box<LogicalPlan>,
    },
    Intersect {
        left: Box<LogicalPlan>,
        right: Box<LogicalPlan>,
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
    CreateFunction {
        name: String,
        argument_types: Vec<SqlType>,
        return_type: SqlType,
    },
    CreateOperator {
        symbol: String,
        left_type: SqlType,
        right_type: SqlType,
        result_type: SqlType,
        function_id: FunctionId,
    },
    CreateRole {
        name: String,
    },
    CreatePolicy {
        name: String,
        relation_id: RelationId,
        predicate: String,
    },
    GrantTablePrivilege {
        role_id: RoleId,
        relation_id: RelationId,
        privilege: String,
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
pub struct AggregateItem {
    pub name: String,
    pub function: AggregateFunction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AggregateFunction {
    CountStar,
    Count(Expr),
    CountDistinct(Expr),
    Sum(Expr),
    Min(Expr),
    Max(Expr),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupedAggregateItem {
    pub name: String,
    pub kind: GroupedAggregateItemKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GroupedAggregateItemKind {
    GroupKey(Expr),
    Aggregate(AggregateFunction),
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
                let grouped = !select.group_by.is_empty();
                let aggregate_functions = select_aggregate_functions(select);
                if !grouped && aggregate_functions.is_none() && !select.order_by.is_empty() {
                    plan = LogicalPlan::Sort {
                        keys: select.order_by.clone(),
                        input: Box::new(plan),
                    };
                }
                let mut plan = if grouped {
                    LogicalPlan::GroupedAggregate {
                        group_by: select.group_by.clone(),
                        items: select
                            .projection
                            .iter()
                            .map(|item| GroupedAggregateItem {
                                name: item.column.name.clone(),
                                kind: grouped_aggregate_item_kind(&item.expr),
                            })
                            .collect(),
                        input: Box::new(plan),
                    }
                } else if let Some(functions) = select_aggregate_functions(select) {
                    LogicalPlan::Aggregate {
                        items: select
                            .projection
                            .iter()
                            .zip(functions)
                            .map(|(item, function)| AggregateItem {
                                name: item.column.name.clone(),
                                function,
                            })
                            .collect(),
                        input: Box::new(plan),
                    }
                } else {
                    LogicalPlan::Project {
                        items: select
                            .projection
                            .iter()
                            .map(|item| ProjectionItem {
                                name: item.column.name.clone(),
                                expr: item.expr.clone(),
                            })
                            .collect(),
                        input: Box::new(plan),
                    }
                };
                if let Some(predicate) = &select.having {
                    plan = LogicalPlan::Filter {
                        predicate: predicate.clone(),
                        input: Box::new(plan),
                    };
                }
                if !grouped && aggregate_functions.is_some() && !select.order_by.is_empty() {
                    plan = LogicalPlan::Sort {
                        keys: select.order_by.clone(),
                        input: Box::new(plan),
                    };
                }
                if grouped && !select.order_by.is_empty() {
                    plan = LogicalPlan::Sort {
                        keys: select.order_by.clone(),
                        input: Box::new(plan),
                    };
                }
                if select.distinct {
                    plan = LogicalPlan::Distinct {
                        input: Box::new(plan),
                    };
                }
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
            BoundStatement::Union(union) => Ok(LogicalPlan::Union {
                all: union.all,
                left: Box::new(self.plan(&union.left)?),
                right: Box::new(self.plan(&union.right)?),
            }),
            BoundStatement::Intersect(intersect) => Ok(LogicalPlan::Intersect {
                left: Box::new(self.plan(&intersect.left)?),
                right: Box::new(self.plan(&intersect.right)?),
            }),
            BoundStatement::CreateFunction {
                name,
                argument_types,
                return_type,
            } => Ok(LogicalPlan::CreateFunction {
                name: name.as_str().to_string(),
                argument_types: argument_types.clone(),
                return_type: return_type.clone(),
            }),
            BoundStatement::CreateOperator { signature } => Ok(LogicalPlan::CreateOperator {
                symbol: signature.symbol().to_string(),
                left_type: signature.left_type().clone(),
                right_type: signature.right_type().clone(),
                result_type: signature.result_type().clone(),
                function_id: signature.function_id(),
            }),
            BoundStatement::CreateRole { name } => Ok(LogicalPlan::CreateRole {
                name: name.as_str().to_string(),
            }),
            BoundStatement::CreatePolicy {
                name,
                relation_id,
                predicate,
            } => Ok(LogicalPlan::CreatePolicy {
                name: name.as_str().to_string(),
                relation_id: *relation_id,
                predicate: predicate.clone(),
            }),
            BoundStatement::GrantTablePrivilege {
                role_id,
                relation_id,
                privilege,
            } => Ok(LogicalPlan::GrantTablePrivilege {
                role_id: *role_id,
                relation_id: *relation_id,
                privilege: format!("{privilege:?}"),
            }),
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
        LogicalPlan::Aggregate { items, input } => {
            let aggregates = items
                .iter()
                .map(|item| {
                    format!(
                        "{} := {}",
                        item.name,
                        aggregate_function_name(&item.function)
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("{prefix}Aggregate {aggregates}\n"));
            write_plan(input, indent + 1, out);
        }
        LogicalPlan::GroupedAggregate {
            group_by,
            items,
            input,
        } => {
            let group_by = group_by
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let items = items
                .iter()
                .map(|item| match &item.kind {
                    GroupedAggregateItemKind::GroupKey(expr) => {
                        format!("{} := {}", item.name, expr)
                    }
                    GroupedAggregateItemKind::Aggregate(function) => {
                        format!("{} := {}", item.name, aggregate_function_name(function))
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!(
                "{prefix}GroupedAggregate group_by={group_by} {items}\n"
            ));
            write_plan(input, indent + 1, out);
        }
        LogicalPlan::Distinct { input } => {
            out.push_str(&format!("{prefix}Distinct\n"));
            write_plan(input, indent + 1, out);
        }
        LogicalPlan::Union { all, left, right } => {
            let mode = if *all { "ALL" } else { "DISTINCT" };
            out.push_str(&format!("{prefix}Union {mode}\n"));
            write_plan(left, indent + 1, out);
            write_plan(right, indent + 1, out);
        }
        LogicalPlan::Intersect { left, right } => {
            out.push_str(&format!("{prefix}Intersect DISTINCT\n"));
            write_plan(left, indent + 1, out);
            write_plan(right, indent + 1, out);
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
        LogicalPlan::CreateFunction {
            name,
            argument_types,
            return_type,
        } => {
            out.push_str(&format!(
                "{prefix}CreateFunction name={name} args={} returns={return_type:?}\n",
                sql_type_list(argument_types)
            ));
        }
        LogicalPlan::CreateOperator {
            symbol,
            left_type,
            right_type,
            result_type,
            function_id,
        } => {
            out.push_str(&format!(
                "{prefix}CreateOperator symbol={symbol} left={left_type:?} right={right_type:?} returns={result_type:?} function={function_id}\n"
            ));
        }
        LogicalPlan::CreateRole { name } => {
            out.push_str(&format!("{prefix}CreateRole name={name}\n"));
        }
        LogicalPlan::CreatePolicy {
            name,
            relation_id,
            predicate,
        } => {
            out.push_str(&format!(
                "{prefix}CreatePolicy name={name} relation={relation_id} predicate={predicate}\n"
            ));
        }
        LogicalPlan::GrantTablePrivilege {
            role_id,
            relation_id,
            privilege,
        } => {
            out.push_str(&format!(
                "{prefix}GrantTablePrivilege role={role_id} relation={relation_id} privilege={privilege}\n"
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

fn sql_type_list(types: &[SqlType]) -> String {
    types
        .iter()
        .map(|data_type| format!("{data_type:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn select_aggregate_functions(
    select: &rnmdb_sql::ast::BoundSelect,
) -> Option<Vec<AggregateFunction>> {
    if select.projection.is_empty() {
        return None;
    }
    let mut functions = Vec::with_capacity(select.projection.len());
    for item in &select.projection {
        functions.push(aggregate_function(&item.expr)?);
    }
    Some(functions)
}

fn grouped_aggregate_item_kind(expr: &Expr) -> GroupedAggregateItemKind {
    match aggregate_function(expr) {
        Some(function) => GroupedAggregateItemKind::Aggregate(function),
        None => GroupedAggregateItemKind::GroupKey(expr.clone()),
    }
}

fn aggregate_function(expr: &Expr) -> Option<AggregateFunction> {
    match expr {
        Expr::CountStar => Some(AggregateFunction::CountStar),
        Expr::Count(expr) => Some(AggregateFunction::Count((**expr).clone())),
        Expr::CountDistinct(expr) => Some(AggregateFunction::CountDistinct((**expr).clone())),
        Expr::Sum(expr) => Some(AggregateFunction::Sum((**expr).clone())),
        Expr::Min(expr) => Some(AggregateFunction::Min((**expr).clone())),
        Expr::Max(expr) => Some(AggregateFunction::Max((**expr).clone())),
        _ => None,
    }
}

fn aggregate_function_name(function: &AggregateFunction) -> String {
    match function {
        AggregateFunction::CountStar => "count(*)".to_string(),
        AggregateFunction::Count(expr) => format!("count({expr})"),
        AggregateFunction::CountDistinct(expr) => format!("count(DISTINCT {expr})"),
        AggregateFunction::Sum(expr) => format!("sum({expr})"),
        AggregateFunction::Min(expr) => format!("min({expr})"),
        AggregateFunction::Max(expr) => format!("max({expr})"),
    }
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
        rnmdb_sql::ast::SortDirection::AscNullsFirst => "ASC NULLS FIRST",
        rnmdb_sql::ast::SortDirection::AscNullsLast => "ASC NULLS LAST",
        rnmdb_sql::ast::SortDirection::DescNullsFirst => "DESC NULLS FIRST",
        rnmdb_sql::ast::SortDirection::DescNullsLast => "DESC NULLS LAST",
    }
}
