use rnmdb_catalog::{IndexMethod, TriggerEvent, TriggerTiming};
use rnmdb_common::ids::{FunctionId, RelationId, RoleId};
use rnmdb_common::{ErrorKind, Result, RnovError};
use rnmdb_fts::TextQuery;
use rnmdb_sql::ast::{
    BoundIndexKey, BoundJoin, BoundStatement, ColumnDef, ExplainFormat, Expr, Ident, IndexKeyDef,
    JoinKind, ObjectName, OrderByExpr, TransactionAction,
};
use rnmdb_types::SqlType;

use crate::cost::{CostModel, PlanCost};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogicalPlan {
    Scan {
        relation_id: RelationId,
        table: String,
    },
    RecursiveScan {
        name: String,
        columns: Vec<String>,
    },
    Filter {
        predicate: Expr,
        input: Box<LogicalPlan>,
    },
    InSubqueryFilter {
        expr: Expr,
        subquery: Box<LogicalPlan>,
        negated: bool,
        input: Box<LogicalPlan>,
    },
    ExistsSubqueryFilter {
        subquery: Box<LogicalPlan>,
        negated: bool,
        input: Box<LogicalPlan>,
    },
    TextSearch {
        relation_id: RelationId,
        table: String,
        column: String,
        query: String,
        cost_hint: TextSearchCostHint,
    },
    SidewaysLookup {
        outer: Box<LogicalPlan>,
        inner_relation_id: RelationId,
        inner_table: String,
        inner_column: String,
        outer_column: String,
    },
    NestedLoopJoin {
        kind: JoinKind,
        left: Box<LogicalPlan>,
        right: Box<LogicalPlan>,
        predicate: Expr,
    },
    Project {
        items: Vec<ProjectionItem>,
        input: Box<LogicalPlan>,
    },
    Window {
        items: Vec<WindowItem>,
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
    GroupingSetsAggregate {
        group_by: Vec<Expr>,
        grouping_sets: Vec<Vec<Expr>>,
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
        all: bool,
        left: Box<LogicalPlan>,
        right: Box<LogicalPlan>,
    },
    Except {
        all: bool,
        left: Box<LogicalPlan>,
        right: Box<LogicalPlan>,
    },
    RecursiveCte {
        name: String,
        columns: Vec<String>,
        seed: Box<LogicalPlan>,
        recursive: Box<LogicalPlan>,
        query: Box<LogicalPlan>,
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
        if_not_exists: bool,
    },
    CreateIndex {
        name: String,
        relation_id: RelationId,
        table: String,
        keys: Vec<IndexKeyDef>,
        method: IndexMethod,
        unique: bool,
        if_not_exists: bool,
    },
    CreateTrigger {
        name: String,
        relation_id: RelationId,
        table: String,
        timing: TriggerTiming,
        event: TriggerEvent,
        body: String,
        if_not_exists: bool,
    },
    AlterTableAddColumn {
        relation_id: RelationId,
        table: String,
        column: ColumnDef,
        if_not_exists: bool,
    },
    AlterColumnEncryption {
        relation_id: RelationId,
        table: String,
        column: String,
        encrypted: bool,
    },
    DropTable {
        relation_id: Option<RelationId>,
        table: String,
        if_exists: bool,
    },
    DropIndex {
        name: String,
        if_exists: bool,
    },
    DropFunction {
        name: String,
        argument_types: Vec<SqlType>,
        if_exists: bool,
    },
    DropProcedure {
        name: String,
        argument_types: Vec<SqlType>,
        if_exists: bool,
    },
    DropOperator {
        symbol: String,
        left_type: SqlType,
        right_type: SqlType,
        if_exists: bool,
    },
    DropRole {
        name: String,
        if_exists: bool,
    },
    DropPolicy {
        name: String,
        relation_id: RelationId,
        if_exists: bool,
    },
    CreateFunction {
        name: String,
        argument_types: Vec<SqlType>,
        return_type: SqlType,
        if_not_exists: bool,
    },
    CreateProcedure {
        name: String,
        argument_types: Vec<SqlType>,
        body: String,
        if_not_exists: bool,
    },
    CreateOperator {
        symbol: String,
        left_type: SqlType,
        right_type: SqlType,
        result_type: SqlType,
        function_id: FunctionId,
        precedence: Option<u8>,
        commutator: Option<String>,
        negator: Option<String>,
        selectivity_function_id: Option<FunctionId>,
    },
    CreateRole {
        name: String,
        if_not_exists: bool,
    },
    CreatePolicy {
        name: String,
        relation_id: RelationId,
        predicate: String,
        if_not_exists: bool,
    },
    GrantTablePrivilege {
        role_id: RoleId,
        relation_id: RelationId,
        privilege: String,
    },
    GrantProcedurePrivilege {
        role_id: RoleId,
        procedure_id: FunctionId,
        privilege: String,
    },
    CallProcedure {
        name: String,
        body: String,
        args: Vec<Expr>,
    },
    Transaction {
        action: String,
    },
    Explain {
        analyze: bool,
        format: ExplainFormat,
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
pub struct WindowItem {
    pub name: String,
    pub function: WindowFunction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowFunction {
    RowNumber { order_by: Vec<OrderByExpr> },
    Rank { order_by: Vec<OrderByExpr> },
    DenseRank { order_by: Vec<OrderByExpr> },
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
            BoundStatement::CreateTable {
                name,
                columns,
                if_not_exists,
            } => Ok(LogicalPlan::CreateTable {
                table: object_name(name),
                columns: columns.clone(),
                if_not_exists: *if_not_exists,
            }),
            BoundStatement::CreateIndex {
                name,
                relation_id,
                table,
                keys,
                method,
                unique,
                if_not_exists,
            } => Ok(LogicalPlan::CreateIndex {
                name: object_name(name),
                relation_id: *relation_id,
                table: object_name(table),
                keys: keys.iter().map(index_key_def_from_bound).collect(),
                method: *method,
                unique: *unique,
                if_not_exists: *if_not_exists,
            }),
            BoundStatement::CreateTrigger {
                name,
                relation_id,
                table,
                timing,
                event,
                body,
                if_not_exists,
            } => Ok(LogicalPlan::CreateTrigger {
                name: name.as_str().to_string(),
                relation_id: *relation_id,
                table: object_name(table),
                timing: *timing,
                event: *event,
                body: body.clone(),
                if_not_exists: *if_not_exists,
            }),
            BoundStatement::AlterTableAddColumn {
                relation_id,
                table,
                column,
                if_not_exists,
            } => Ok(LogicalPlan::AlterTableAddColumn {
                relation_id: *relation_id,
                table: object_name(table),
                column: column.clone(),
                if_not_exists: *if_not_exists,
            }),
            BoundStatement::AlterColumnEncryption {
                relation_id,
                table,
                column,
                encrypted,
            } => Ok(LogicalPlan::AlterColumnEncryption {
                relation_id: *relation_id,
                table: object_name(table),
                column: column.as_str().to_string(),
                encrypted: *encrypted,
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
            BoundStatement::DropIndex { name, if_exists } => Ok(LogicalPlan::DropIndex {
                name: object_name(name),
                if_exists: *if_exists,
            }),
            BoundStatement::DropFunction {
                name,
                argument_types,
                if_exists,
            } => Ok(LogicalPlan::DropFunction {
                name: name.as_str().to_string(),
                argument_types: argument_types.clone(),
                if_exists: *if_exists,
            }),
            BoundStatement::DropProcedure {
                name,
                argument_types,
                if_exists,
            } => Ok(LogicalPlan::DropProcedure {
                name: name.as_str().to_string(),
                argument_types: argument_types.clone(),
                if_exists: *if_exists,
            }),
            BoundStatement::DropOperator {
                symbol,
                left_type,
                right_type,
                if_exists,
            } => Ok(LogicalPlan::DropOperator {
                symbol: symbol.clone(),
                left_type: left_type.clone(),
                right_type: right_type.clone(),
                if_exists: *if_exists,
            }),
            BoundStatement::DropRole { name, if_exists } => Ok(LogicalPlan::DropRole {
                name: name.as_str().to_string(),
                if_exists: *if_exists,
            }),
            BoundStatement::DropPolicy {
                name,
                relation_id,
                if_exists,
            } => Ok(LogicalPlan::DropPolicy {
                name: name.as_str().to_string(),
                relation_id: *relation_id,
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
                let input = LogicalPlan::Scan {
                    relation_id: select.relation_id,
                    table: object_name(&select.table),
                };
                self.plan_select_with_input(select, input, true)
            }
            BoundStatement::SelectJoin(join_select) => {
                let input = LogicalPlan::Scan {
                    relation_id: join_select.select.relation_id,
                    table: object_name(&join_select.select.table),
                };
                self.plan_select_join(&join_select.select, &join_select.join, input)
            }
            BoundStatement::Union(union) => Ok(LogicalPlan::Union {
                all: union.all,
                left: Box::new(self.plan(&union.left)?),
                right: Box::new(self.plan(&union.right)?),
            }),
            BoundStatement::Intersect(intersect) => Ok(LogicalPlan::Intersect {
                all: intersect.all,
                left: Box::new(self.plan(&intersect.left)?),
                right: Box::new(self.plan(&intersect.right)?),
            }),
            BoundStatement::Except(except) => Ok(LogicalPlan::Except {
                all: except.all,
                left: Box::new(self.plan(&except.left)?),
                right: Box::new(self.plan(&except.right)?),
            }),
            BoundStatement::RecursiveCte(cte) => {
                let seed = self.plan(&cte.seed)?;
                let recursive_input = LogicalPlan::RecursiveScan {
                    name: object_name(&cte.name),
                    columns: cte
                        .columns
                        .iter()
                        .map(|column| column.name.clone())
                        .collect(),
                };
                let recursive = self.plan_select_with_input(
                    bound_select_from_statement(&cte.recursive)?,
                    recursive_input,
                    false,
                )?;
                let query_input = LogicalPlan::RecursiveScan {
                    name: object_name(&cte.name),
                    columns: cte
                        .columns
                        .iter()
                        .map(|column| column.name.clone())
                        .collect(),
                };
                let query = self.plan_select_with_input(&cte.query, query_input, false)?;
                Ok(LogicalPlan::RecursiveCte {
                    name: object_name(&cte.name),
                    columns: cte
                        .columns
                        .iter()
                        .map(|column| column.name.clone())
                        .collect(),
                    seed: Box::new(seed),
                    recursive: Box::new(recursive),
                    query: Box::new(query),
                })
            }
            BoundStatement::Query(query) => {
                let plan = self.plan(&query.input)?;
                Ok(apply_query_tail(
                    plan,
                    &query.order_by,
                    query.limit,
                    query.offset,
                ))
            }
            BoundStatement::CreateFunction {
                name,
                argument_types,
                return_type,
                if_not_exists,
            } => Ok(LogicalPlan::CreateFunction {
                name: name.as_str().to_string(),
                argument_types: argument_types.clone(),
                return_type: return_type.clone(),
                if_not_exists: *if_not_exists,
            }),
            BoundStatement::CreateProcedure {
                name,
                argument_types,
                body,
                if_not_exists,
            } => Ok(LogicalPlan::CreateProcedure {
                name: name.as_str().to_string(),
                argument_types: argument_types.clone(),
                body: body.clone(),
                if_not_exists: *if_not_exists,
            }),
            BoundStatement::CreateOperator { signature } => Ok(LogicalPlan::CreateOperator {
                symbol: signature.symbol().to_string(),
                left_type: signature.left_type().clone(),
                right_type: signature.right_type().clone(),
                result_type: signature.result_type().clone(),
                function_id: signature.function_id(),
                precedence: signature.precedence(),
                commutator: signature.commutator().map(str::to_string),
                negator: signature.negator().map(str::to_string),
                selectivity_function_id: signature.selectivity_function_id(),
            }),
            BoundStatement::CreateRole {
                name,
                if_not_exists,
            } => Ok(LogicalPlan::CreateRole {
                name: name.as_str().to_string(),
                if_not_exists: *if_not_exists,
            }),
            BoundStatement::CreatePolicy {
                name,
                relation_id,
                predicate,
                if_not_exists,
            } => Ok(LogicalPlan::CreatePolicy {
                name: name.as_str().to_string(),
                relation_id: *relation_id,
                predicate: predicate.clone(),
                if_not_exists: *if_not_exists,
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
            BoundStatement::GrantProcedurePrivilege {
                role_id,
                procedure_id,
                privilege,
            } => Ok(LogicalPlan::GrantProcedurePrivilege {
                role_id: *role_id,
                procedure_id: *procedure_id,
                privilege: format!("{privilege:?}"),
            }),
            BoundStatement::CallProcedure { name, body, args } => Ok(LogicalPlan::CallProcedure {
                name: name.as_str().to_string(),
                body: body.clone(),
                args: args.clone(),
            }),
            BoundStatement::Transaction { action } => Ok(LogicalPlan::Transaction {
                action: transaction_action_name(*action).to_string(),
            }),
            BoundStatement::Explain {
                analyze,
                format,
                statement,
            } => Ok(LogicalPlan::Explain {
                analyze: *analyze,
                format: *format,
                input: Box::new(self.plan(statement)?),
            }),
        }
    }

    fn plan_select_with_input(
        &self,
        select: &rnmdb_sql::ast::BoundSelect,
        mut plan: LogicalPlan,
        include_table_dependent_rewrites: bool,
    ) -> Result<LogicalPlan> {
        if include_table_dependent_rewrites {
            for policy in &select.row_policy_predicates {
                plan = plan_selection(select.relation_id, &select.table, &policy.predicate, plan)?;
            }
            if let Some(lateral_join) = &select.lateral_join {
                plan = LogicalPlan::SidewaysLookup {
                    outer: Box::new(plan),
                    inner_relation_id: lateral_join.inner_relation_id,
                    inner_table: object_name(&lateral_join.inner_table),
                    inner_column: lateral_join.inner_column.clone(),
                    outer_column: lateral_join.outer_column.clone(),
                };
            }
        }
        if let Some(predicate) = &select.selection {
            plan = if include_table_dependent_rewrites {
                self.plan_select_predicate(select.relation_id, &select.table, predicate, plan)?
            } else {
                self.plan_bound_predicate(predicate, plan)?
            };
        }
        let grouping_sets = !select.grouping_sets.is_empty();
        let grouped = !select.group_by.is_empty() || grouping_sets;
        let aggregate_functions = select_aggregate_functions(select);
        let mut order_by = select.order_by.clone();
        let mut project_internal_outputs =
            !select.hidden_group_keys.is_empty() || !select.hidden_aggregates.is_empty();
        if !grouped && aggregate_functions.is_none() && !order_by.is_empty() {
            plan = LogicalPlan::Sort {
                keys: order_by.clone(),
                input: Box::new(plan),
            };
        }
        let mut plan = if grouped {
            let mut items = select
                .projection
                .iter()
                .chain(select.hidden_group_keys.iter())
                .chain(select.hidden_aggregates.iter())
                .map(|item| GroupedAggregateItem {
                    name: item.column.name.clone(),
                    kind: grouped_aggregate_item_kind(&item.expr),
                })
                .collect::<Vec<_>>();
            project_internal_outputs |=
                add_grouped_sort_keys(&mut items, &mut order_by, &select.group_by);
            if grouping_sets {
                LogicalPlan::GroupingSetsAggregate {
                    group_by: select.group_by.clone(),
                    grouping_sets: select.grouping_sets.clone(),
                    items,
                    input: Box::new(plan),
                }
            } else {
                LogicalPlan::GroupedAggregate {
                    group_by: select.group_by.clone(),
                    items,
                    input: Box::new(plan),
                }
            }
        } else if let Some(functions) = select_aggregate_functions(select) {
            LogicalPlan::Aggregate {
                items: select
                    .projection
                    .iter()
                    .chain(select.hidden_aggregates.iter())
                    .zip(functions)
                    .map(|(item, function)| AggregateItem {
                        name: item.column.name.clone(),
                        function,
                    })
                    .collect(),
                input: Box::new(plan),
            }
        } else {
            let window_items = select_window_items(select);
            if !window_items.is_empty() {
                plan = LogicalPlan::Window {
                    items: window_items,
                    input: Box::new(plan),
                };
            }
            LogicalPlan::Project {
                items: select
                    .projection
                    .iter()
                    .map(|item| ProjectionItem {
                        name: item.column.name.clone(),
                        expr: projection_expr_after_windows(item),
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
        if !grouped && aggregate_functions.is_some() && !order_by.is_empty() {
            plan = LogicalPlan::Sort {
                keys: order_by.clone(),
                input: Box::new(plan),
            };
        }
        if grouped && !order_by.is_empty() {
            plan = LogicalPlan::Sort {
                keys: order_by.clone(),
                input: Box::new(plan),
            };
        }
        if project_internal_outputs {
            plan = LogicalPlan::Project {
                items: select
                    .projection
                    .iter()
                    .map(|item| ProjectionItem {
                        name: item.column.name.clone(),
                        expr: Expr::Identifier(Ident::new(item.column.name.as_str())),
                    })
                    .collect(),
                input: Box::new(plan),
            };
        }
        if select.distinct {
            plan = LogicalPlan::Distinct {
                input: Box::new(plan),
            };
        }
        if let Some(count) = select.offset {
            plan = LogicalPlan::Offset {
                count,
                input: Box::new(plan),
            };
        }
        if let Some(count) = select.limit {
            Ok(LogicalPlan::Limit {
                count,
                input: Box::new(plan),
            })
        } else {
            Ok(plan)
        }
    }

    fn plan_select_join(
        &self,
        select: &rnmdb_sql::ast::BoundSelect,
        join: &BoundJoin,
        mut plan: LogicalPlan,
    ) -> Result<LogicalPlan> {
        for policy in &select.row_policy_predicates {
            plan = plan_selection(select.relation_id, &select.table, &policy.predicate, plan)?;
        }
        plan = LogicalPlan::NestedLoopJoin {
            kind: join.kind,
            left: Box::new(plan),
            right: Box::new(join_right_plan(join)?),
            predicate: join.predicate.clone(),
        };
        self.plan_select_with_input(select, plan, false)
    }

    fn plan_select_predicate(
        &self,
        relation_id: RelationId,
        table: &ObjectName,
        predicate: &Expr,
        input: LogicalPlan,
    ) -> Result<LogicalPlan> {
        match predicate {
            Expr::Binary { left, op, right } if op == "AND" => {
                let input = self.plan_select_predicate(relation_id, table, left, input)?;
                self.plan_select_predicate(relation_id, table, right, input)
            }
            Expr::InSubquery { .. } | Expr::Not(_) => self.plan_bound_predicate(predicate, input),
            Expr::ExistsSubquery { .. } => self.plan_bound_predicate(predicate, input),
            _ if contains_in_subquery(predicate) => Err(unsupported_in_subquery_predicate()),
            _ => plan_selection(relation_id, table, predicate, input),
        }
    }

    fn plan_bound_predicate(&self, predicate: &Expr, input: LogicalPlan) -> Result<LogicalPlan> {
        match predicate {
            Expr::Binary { left, op, right } if op == "AND" => {
                let input = self.plan_bound_predicate(left, input)?;
                self.plan_bound_predicate(right, input)
            }
            Expr::Not(expr) => self.plan_negated_bound_predicate(expr, input),
            Expr::InSubquery {
                expr,
                query,
                negated,
            } => self.plan_in_subquery_filter(expr, query.bound(), *negated, input),
            Expr::ExistsSubquery { query } => {
                self.plan_exists_subquery_filter(query.bound(), false, input)
            }
            _ if contains_in_subquery(predicate) => Err(unsupported_in_subquery_predicate()),
            _ => Ok(LogicalPlan::Filter {
                predicate: predicate.clone(),
                input: Box::new(input),
            }),
        }
    }

    fn plan_negated_bound_predicate(&self, expr: &Expr, input: LogicalPlan) -> Result<LogicalPlan> {
        match expr {
            Expr::InSubquery {
                expr,
                query,
                negated,
            } => self.plan_in_subquery_filter(expr, query.bound(), !*negated, input),
            Expr::ExistsSubquery { query } => {
                self.plan_exists_subquery_filter(query.bound(), true, input)
            }
            _ if contains_in_subquery(expr) => Err(unsupported_in_subquery_predicate()),
            _ => Ok(LogicalPlan::Filter {
                predicate: Expr::Not(Box::new(expr.clone())),
                input: Box::new(input),
            }),
        }
    }

    fn plan_in_subquery_filter(
        &self,
        expr: &Expr,
        query: Option<&BoundStatement>,
        negated: bool,
        input: LogicalPlan,
    ) -> Result<LogicalPlan> {
        let query = query.ok_or_else(|| {
            RnovError::new(
                ErrorKind::Internal,
                "IN subquery was not bound before planning",
            )
        })?;
        Ok(LogicalPlan::InSubqueryFilter {
            expr: expr.clone(),
            subquery: Box::new(self.plan(query)?),
            negated,
            input: Box::new(input),
        })
    }

    fn plan_exists_subquery_filter(
        &self,
        query: Option<&BoundStatement>,
        negated: bool,
        input: LogicalPlan,
    ) -> Result<LogicalPlan> {
        let query = query.ok_or_else(|| {
            RnovError::new(
                ErrorKind::Internal,
                "EXISTS subquery was not bound before planning",
            )
        })?;
        Ok(LogicalPlan::ExistsSubqueryFilter {
            subquery: Box::new(self.plan(query)?),
            negated,
            input: Box::new(input),
        })
    }
}

impl LogicalPlan {
    pub fn explain(&self) -> String {
        let mut out = String::new();
        write_plan(self, 0, &mut out);
        out
    }

    pub fn explain_with_costs(&self, cost_model: &CostModel) -> String {
        let mut out = String::new();
        write_plan_with_costs(self, 0, cost_model, &mut out);
        out
    }
}

fn write_plan(plan: &LogicalPlan, indent: usize, out: &mut String) {
    let prefix = "  ".repeat(indent);
    match plan {
        LogicalPlan::Scan { table, .. } => {
            out.push_str(&format!("{prefix}Scan table={table}\n"));
        }
        LogicalPlan::RecursiveScan { name, columns } => {
            out.push_str(&format!(
                "{prefix}RecursiveScan {name}({})\n",
                columns.join(", ")
            ));
        }
        LogicalPlan::Filter { predicate, input } => {
            out.push_str(&format!("{prefix}Filter predicate={predicate}\n"));
            write_plan(input, indent + 1, out);
        }
        LogicalPlan::InSubqueryFilter {
            expr,
            subquery,
            negated,
            input,
        } => {
            let op = if *negated { "NOT IN" } else { "IN" };
            out.push_str(&format!("{prefix}InSubqueryFilter expr={expr} op={op}\n"));
            write_plan(input, indent + 1, out);
            write_plan(subquery, indent + 1, out);
        }
        LogicalPlan::ExistsSubqueryFilter {
            subquery,
            negated,
            input,
        } => {
            let op = if *negated { "NOT EXISTS" } else { "EXISTS" };
            out.push_str(&format!("{prefix}ExistsSubqueryFilter op={op}\n"));
            write_plan(input, indent + 1, out);
            write_plan(subquery, indent + 1, out);
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
        LogicalPlan::SidewaysLookup {
            outer,
            inner_table,
            inner_column,
            outer_column,
            ..
        } => {
            out.push_str(&format!(
                "{prefix}SidewaysLookup inner={inner_table} inner_column={inner_column} outer_column={outer_column}\n"
            ));
            write_plan(outer, indent + 1, out);
        }
        LogicalPlan::NestedLoopJoin {
            kind,
            left,
            right,
            predicate,
        } => {
            out.push_str(&format!(
                "{prefix}NestedLoopJoin kind={} predicate={predicate}\n",
                join_kind_name(*kind)
            ));
            write_plan(left, indent + 1, out);
            write_plan(right, indent + 1, out);
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
        LogicalPlan::Window { items, input } => {
            let functions = items
                .iter()
                .map(|item| format!("{} := {}", item.name, window_function_name(&item.function)))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("{prefix}Window {functions}\n"));
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
        LogicalPlan::GroupingSetsAggregate {
            group_by,
            grouping_sets,
            items,
            input,
        } => {
            let group_by = group_by
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let grouping_sets = grouping_sets
                .iter()
                .map(|grouping_set| {
                    if grouping_set.is_empty() {
                        "()".to_string()
                    } else {
                        format!(
                            "({})",
                            grouping_set
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    }
                })
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
                "{prefix}GroupingSetsAggregate group_by={group_by} sets={grouping_sets} {items}\n"
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
        LogicalPlan::Intersect { all, left, right } => {
            let mode = if *all { "ALL" } else { "DISTINCT" };
            out.push_str(&format!("{prefix}Intersect {mode}\n"));
            write_plan(left, indent + 1, out);
            write_plan(right, indent + 1, out);
        }
        LogicalPlan::Except { all, left, right } => {
            let mode = if *all { "ALL" } else { "DISTINCT" };
            out.push_str(&format!("{prefix}Except {mode}\n"));
            write_plan(left, indent + 1, out);
            write_plan(right, indent + 1, out);
        }
        LogicalPlan::RecursiveCte {
            name,
            columns,
            seed,
            recursive,
            query,
        } => {
            out.push_str(&format!(
                "{prefix}RecursiveCte {name}({})\n",
                columns.join(", ")
            ));
            out.push_str(&format!("{prefix}  Seed\n"));
            write_plan(seed, indent + 2, out);
            out.push_str(&format!("{prefix}  Recursive\n"));
            write_recursive_step_summary(recursive, indent + 2, out);
            write_plan(recursive, indent + 2, out);
            out.push_str(&format!("{prefix}  Query\n"));
            write_plan(query, indent + 2, out);
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
        LogicalPlan::CreateTable {
            table,
            columns,
            if_not_exists,
        } => {
            let exists = if *if_not_exists {
                " if_not_exists=true"
            } else {
                ""
            };
            out.push_str(&format!(
                "{prefix}CreateTable table={table} columns={}{}\n",
                columns
                    .iter()
                    .map(|column| column.name.as_str().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                exists
            ));
        }
        LogicalPlan::CreateIndex {
            name,
            table,
            keys,
            method,
            unique,
            if_not_exists,
            ..
        } => {
            let mode = if *unique { "unique " } else { "" };
            let exists = if *if_not_exists {
                " if_not_exists=true"
            } else {
                ""
            };
            out.push_str(&format!(
                "{prefix}CreateIndex {mode}name={name} table={table} method={} keys={}{}\n",
                method.as_str(),
                keys.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                exists
            ));
        }
        LogicalPlan::CreateTrigger {
            name,
            table,
            timing,
            event,
            if_not_exists,
            ..
        } => {
            let exists = if *if_not_exists {
                " if_not_exists=true"
            } else {
                ""
            };
            out.push_str(&format!(
                "{prefix}CreateTrigger name={name} table={table} timing={timing:?} event={event:?}{exists}\n"
            ));
        }
        LogicalPlan::AlterTableAddColumn {
            table,
            column,
            if_not_exists,
            ..
        } => {
            let exists = if *if_not_exists {
                " if_not_exists=true"
            } else {
                ""
            };
            out.push_str(&format!(
                "{prefix}AlterTableAddColumn table={table} column={}{}\n",
                column.name, exists
            ));
        }
        LogicalPlan::AlterColumnEncryption {
            table,
            column,
            encrypted,
            ..
        } => {
            out.push_str(&format!(
                "{prefix}AlterColumnEncryption table={table} column={column} encrypted={encrypted}\n"
            ));
        }
        LogicalPlan::DropTable {
            table, if_exists, ..
        } => {
            out.push_str(&format!(
                "{prefix}DropTable table={table} if_exists={if_exists}\n"
            ));
        }
        LogicalPlan::DropIndex { name, if_exists } => {
            out.push_str(&format!(
                "{prefix}DropIndex name={name} if_exists={if_exists}\n"
            ));
        }
        LogicalPlan::DropFunction {
            name,
            argument_types,
            if_exists,
        } => {
            out.push_str(&format!(
                "{prefix}DropFunction name={name} args={} if_exists={if_exists}\n",
                sql_type_list(argument_types)
            ));
        }
        LogicalPlan::DropProcedure {
            name,
            argument_types,
            if_exists,
        } => {
            out.push_str(&format!(
                "{prefix}DropProcedure name={name} args={} if_exists={if_exists}\n",
                sql_type_list(argument_types)
            ));
        }
        LogicalPlan::DropOperator {
            symbol,
            left_type,
            right_type,
            if_exists,
        } => {
            out.push_str(&format!(
                "{prefix}DropOperator symbol={symbol} left={left_type:?} right={right_type:?} if_exists={if_exists}\n"
            ));
        }
        LogicalPlan::DropRole { name, if_exists } => {
            out.push_str(&format!(
                "{prefix}DropRole name={name} if_exists={if_exists}\n"
            ));
        }
        LogicalPlan::DropPolicy {
            name,
            relation_id,
            if_exists,
        } => {
            out.push_str(&format!(
                "{prefix}DropPolicy name={name} relation={relation_id} if_exists={if_exists}\n"
            ));
        }
        LogicalPlan::CreateFunction {
            name,
            argument_types,
            return_type,
            if_not_exists,
        } => {
            let exists = if *if_not_exists {
                " if_not_exists=true"
            } else {
                ""
            };
            out.push_str(&format!(
                "{prefix}CreateFunction name={name} args={} returns={return_type:?}{}\n",
                sql_type_list(argument_types),
                exists
            ));
        }
        LogicalPlan::CreateProcedure {
            name,
            argument_types,
            if_not_exists,
            ..
        } => {
            let exists = if *if_not_exists {
                " if_not_exists=true"
            } else {
                ""
            };
            out.push_str(&format!(
                "{prefix}CreateProcedure name={name} args={}{}\n",
                sql_type_list(argument_types),
                exists
            ));
        }
        LogicalPlan::CreateOperator {
            symbol,
            left_type,
            right_type,
            result_type,
            function_id,
            precedence,
            commutator,
            negator,
            selectivity_function_id,
        } => {
            let precedence = precedence
                .map(|value| format!(" precedence={value}"))
                .unwrap_or_default();
            let commutator = commutator
                .as_ref()
                .map(|value| format!(" commutator={value}"))
                .unwrap_or_default();
            let negator = negator
                .as_ref()
                .map(|value| format!(" negator={value}"))
                .unwrap_or_default();
            let selectivity = selectivity_function_id
                .map(|value| format!(" selectivity={value}"))
                .unwrap_or_default();
            out.push_str(&format!(
                "{prefix}CreateOperator symbol={symbol} left={left_type:?} right={right_type:?} returns={result_type:?} function={function_id}{precedence}{commutator}{negator}{selectivity}\n"
            ));
        }
        LogicalPlan::CreateRole {
            name,
            if_not_exists,
        } => {
            let exists = if *if_not_exists {
                " if_not_exists=true"
            } else {
                ""
            };
            out.push_str(&format!("{prefix}CreateRole name={name}{exists}\n"));
        }
        LogicalPlan::CreatePolicy {
            name,
            relation_id,
            predicate,
            if_not_exists,
        } => {
            let exists = if *if_not_exists {
                " if_not_exists=true"
            } else {
                ""
            };
            out.push_str(&format!(
                "{prefix}CreatePolicy name={name} relation={relation_id} predicate={predicate}{exists}\n"
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
        LogicalPlan::GrantProcedurePrivilege {
            role_id,
            procedure_id,
            privilege,
        } => {
            out.push_str(&format!(
                "{prefix}GrantProcedurePrivilege role={role_id} procedure={procedure_id} privilege={privilege}\n"
            ));
        }
        LogicalPlan::CallProcedure { name, args, .. } => {
            out.push_str(&format!(
                "{prefix}CallProcedure name={name} args={}\n",
                args.len()
            ));
        }
        LogicalPlan::Transaction { action } => {
            out.push_str(&format!("{prefix}Transaction action={action}\n"));
        }
        LogicalPlan::Explain {
            analyze,
            format,
            input,
        } => {
            let format = if *format == ExplainFormat::Logical {
                ""
            } else {
                explain_format_suffix(*format)
            };
            out.push_str(&format!("{prefix}Explain analyze={analyze}{format}\n"));
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

fn write_plan_with_costs(
    plan: &LogicalPlan,
    indent: usize,
    cost_model: &CostModel,
    out: &mut String,
) {
    let before = out.len();
    write_plan(plan, indent, out);
    let Some(line_end) = out[before..].find('\n').map(|offset| before + offset) else {
        return;
    };
    let cost = cost_model.estimate(plan);
    out.insert_str(line_end, &format_plan_cost(cost));
    match plan {
        LogicalPlan::Filter { input, .. }
        | LogicalPlan::Project { input, .. }
        | LogicalPlan::Window { input, .. }
        | LogicalPlan::Aggregate { input, .. }
        | LogicalPlan::GroupedAggregate { input, .. }
        | LogicalPlan::GroupingSetsAggregate { input, .. }
        | LogicalPlan::Distinct { input }
        | LogicalPlan::Sort { input, .. }
        | LogicalPlan::Limit { input, .. }
        | LogicalPlan::Offset { input, .. }
        | LogicalPlan::Explain { input, .. }
        | LogicalPlan::Parallel { input, .. } => {
            truncate_child_lines(out, line_end + format_plan_cost(cost).len() + 1);
            write_plan_with_costs(input, indent + 1, cost_model, out);
        }
        LogicalPlan::InSubqueryFilter {
            input, subquery, ..
        } => {
            truncate_child_lines(out, line_end + format_plan_cost(cost).len() + 1);
            write_plan_with_costs(input, indent + 1, cost_model, out);
            write_plan_with_costs(subquery, indent + 1, cost_model, out);
        }
        LogicalPlan::ExistsSubqueryFilter {
            input, subquery, ..
        } => {
            truncate_child_lines(out, line_end + format_plan_cost(cost).len() + 1);
            write_plan_with_costs(input, indent + 1, cost_model, out);
            write_plan_with_costs(subquery, indent + 1, cost_model, out);
        }
        LogicalPlan::SidewaysLookup { outer, .. } => {
            truncate_child_lines(out, line_end + format_plan_cost(cost).len() + 1);
            write_plan_with_costs(outer, indent + 1, cost_model, out);
        }
        LogicalPlan::NestedLoopJoin { left, right, .. }
        | LogicalPlan::Union { left, right, .. }
        | LogicalPlan::Intersect { left, right, .. }
        | LogicalPlan::Except { left, right, .. } => {
            truncate_child_lines(out, line_end + format_plan_cost(cost).len() + 1);
            write_plan_with_costs(left, indent + 1, cost_model, out);
            write_plan_with_costs(right, indent + 1, cost_model, out);
        }
        _ => {}
    }
}

fn truncate_child_lines(out: &mut String, keep_len: usize) {
    out.truncate(keep_len);
}

fn write_recursive_step_summary(plan: &LogicalPlan, indent: usize, out: &mut String) {
    let prefix = "  ".repeat(indent);
    if let Some(items) = first_project_items(plan) {
        let columns = items
            .iter()
            .map(|item| format!("{} := {}", item.name, item.expr))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("{prefix}RecursiveStep {columns}\n"));
    }
    if let Some(predicate) = first_filter_predicate(plan) {
        out.push_str(&format!("{prefix}RecursiveFilter {predicate}\n"));
    }
}

fn first_project_items(plan: &LogicalPlan) -> Option<&[ProjectionItem]> {
    match plan {
        LogicalPlan::Project { items, .. } => Some(items),
        LogicalPlan::Filter { input, .. }
        | LogicalPlan::InSubqueryFilter { input, .. }
        | LogicalPlan::ExistsSubqueryFilter { input, .. }
        | LogicalPlan::Sort { input, .. }
        | LogicalPlan::Limit { input, .. }
        | LogicalPlan::Offset { input, .. }
        | LogicalPlan::Distinct { input }
        | LogicalPlan::Parallel { input, .. } => first_project_items(input),
        _ => None,
    }
}

fn first_filter_predicate(plan: &LogicalPlan) -> Option<&Expr> {
    match plan {
        LogicalPlan::Filter { predicate, .. } => Some(predicate),
        LogicalPlan::InSubqueryFilter { .. } | LogicalPlan::ExistsSubqueryFilter { .. } => None,
        LogicalPlan::Project { input, .. }
        | LogicalPlan::Sort { input, .. }
        | LogicalPlan::Limit { input, .. }
        | LogicalPlan::Offset { input, .. }
        | LogicalPlan::Distinct { input }
        | LogicalPlan::Parallel { input, .. } => first_filter_predicate(input),
        _ => None,
    }
}

fn format_plan_cost(cost: PlanCost) -> String {
    format!(
        " rows={:.0} width={:.0} cost={:.2}",
        cost.rows,
        cost.row_width_bytes,
        cost.total()
    )
}

fn explain_format_suffix(format: ExplainFormat) -> &'static str {
    match format {
        ExplainFormat::Logical => "",
        ExplainFormat::Costs => " format=costs",
        ExplainFormat::Physical => " format=physical",
    }
}

fn plan_selection(
    relation_id: RelationId,
    table: &ObjectName,
    predicate: &Expr,
    fallback_input: LogicalPlan,
) -> Result<LogicalPlan> {
    if base_scan_matches(&fallback_input, relation_id, table)
        && let Some((column, query)) = text_search_predicate(predicate)
    {
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

fn base_scan_matches(input: &LogicalPlan, relation_id: RelationId, table: &ObjectName) -> bool {
    let LogicalPlan::Scan {
        relation_id: input_relation,
        table: input_table,
    } = input
    else {
        return false;
    };
    *input_relation == relation_id && input_table == &object_name(table)
}

fn join_right_plan(join: &BoundJoin) -> Result<LogicalPlan> {
    let mut plan = LogicalPlan::Scan {
        relation_id: join.right_relation_id,
        table: object_name(&join.right_table),
    };
    for policy in &join.row_policy_predicates {
        plan = plan_selection(
            join.right_relation_id,
            &join.right_table,
            &policy.predicate,
            plan,
        )?;
    }
    Ok(plan)
}

fn join_kind_name(kind: JoinKind) -> &'static str {
    match kind {
        JoinKind::Inner => "inner",
        JoinKind::Left => "left",
    }
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

fn contains_in_subquery(expr: &Expr) -> bool {
    matches!(expr, Expr::InSubquery { .. } | Expr::ExistsSubquery { .. })
        || contains_in_subquery_operator(expr)
        || contains_in_subquery_predicate(expr)
        || contains_in_subquery_construct(expr)
        || contains_in_subquery_collection(expr)
}

fn contains_in_subquery_operator(expr: &Expr) -> bool {
    match expr {
        Expr::Binary { left, right, .. } => {
            contains_in_subquery(left) || contains_in_subquery(right)
        }
        Expr::Unary { expr, .. } | Expr::Not(expr) | Expr::Cast { expr, .. } => {
            contains_in_subquery(expr)
        }
        _ => false,
    }
}

fn contains_in_subquery_predicate(expr: &Expr) -> bool {
    match expr {
        Expr::IsNull { expr, .. } | Expr::IsTruth { expr, .. } | Expr::IsUnknown { expr, .. } => {
            contains_in_subquery(expr)
        }
        Expr::IsDistinctFrom { left, right, .. } | Expr::NullIf { left, right } => {
            contains_in_subquery(left) || contains_in_subquery(right)
        }
        Expr::Between {
            expr, low, high, ..
        } => contains_in_subquery(expr) || contains_in_subquery(low) || contains_in_subquery(high),
        Expr::InList { expr, values, .. } => {
            contains_in_subquery(expr) || values.iter().any(contains_in_subquery)
        }
        Expr::Like { expr, pattern, .. } => {
            contains_in_subquery(expr) || contains_in_subquery(pattern)
        }
        _ => false,
    }
}

fn contains_in_subquery_construct(expr: &Expr) -> bool {
    match expr {
        Expr::Coalesce(values) | Expr::Array(values) => values.iter().any(contains_in_subquery),
        Expr::Case {
            operand,
            whens,
            else_expr,
        } => {
            operand.as_deref().is_some_and(contains_in_subquery)
                || whens.iter().any(|arm| {
                    contains_in_subquery(&arm.condition) || contains_in_subquery(&arm.result)
                })
                || else_expr.as_deref().is_some_and(contains_in_subquery)
        }
        Expr::Call { args, .. } => args.iter().any(contains_in_subquery),
        _ => false,
    }
}

fn contains_in_subquery_collection(expr: &Expr) -> bool {
    match expr {
        Expr::RowNumberOver { order_by }
        | Expr::RankOver { order_by }
        | Expr::DenseRankOver { order_by } => {
            order_by.iter().any(|key| contains_in_subquery(&key.expr))
        }
        Expr::Range { lower, upper, .. } => {
            contains_in_subquery(lower) || contains_in_subquery(upper)
        }
        _ => false,
    }
}

fn unsupported_in_subquery_predicate() -> RnovError {
    RnovError::new(
        ErrorKind::InvalidInput,
        "subquery predicates currently support top-level terms combined with AND",
    )
}

fn bound_select_from_statement(statement: &BoundStatement) -> Result<&rnmdb_sql::ast::BoundSelect> {
    match statement {
        BoundStatement::Select(select) => Ok(select),
        _ => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "recursive CTE term must be a SELECT query",
        )),
    }
}

fn object_name(name: &ObjectName) -> String {
    name.to_string()
}

fn index_key_def_from_bound(key: &BoundIndexKey) -> IndexKeyDef {
    match key {
        BoundIndexKey::Column(column) => IndexKeyDef::Column(Ident::new(&column.name)),
        BoundIndexKey::Expression { expr, .. } => IndexKeyDef::Expression(expr.clone()),
    }
}

fn apply_query_tail(
    mut plan: LogicalPlan,
    order_by: &[OrderByExpr],
    limit: Option<usize>,
    offset: Option<usize>,
) -> LogicalPlan {
    if !order_by.is_empty() {
        plan = LogicalPlan::Sort {
            keys: order_by.to_vec(),
            input: Box::new(plan),
        };
    }
    if let Some(count) = offset {
        plan = LogicalPlan::Offset {
            count,
            input: Box::new(plan),
        };
    }
    if let Some(count) = limit {
        plan = LogicalPlan::Limit {
            count,
            input: Box::new(plan),
        };
    }
    plan
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
    let mut functions =
        Vec::with_capacity(select.projection.len() + select.hidden_aggregates.len());
    for item in select
        .projection
        .iter()
        .chain(select.hidden_aggregates.iter())
    {
        functions.push(aggregate_function(&item.expr)?);
    }
    Some(functions)
}

fn select_window_items(select: &rnmdb_sql::ast::BoundSelect) -> Vec<WindowItem> {
    select
        .projection
        .iter()
        .filter_map(|item| {
            Some(WindowItem {
                name: item.column.name.clone(),
                function: window_function(&item.expr)?,
            })
        })
        .collect()
}

fn projection_expr_after_windows(item: &rnmdb_sql::ast::BoundSelectItem) -> Expr {
    if window_function(&item.expr).is_some() {
        Expr::Identifier(Ident::new(item.column.name.as_str()))
    } else {
        item.expr.clone()
    }
}

fn window_function(expr: &Expr) -> Option<WindowFunction> {
    match expr {
        Expr::RowNumberOver { order_by } => Some(WindowFunction::RowNumber {
            order_by: order_by.clone(),
        }),
        Expr::RankOver { order_by } => Some(WindowFunction::Rank {
            order_by: order_by.clone(),
        }),
        Expr::DenseRankOver { order_by } => Some(WindowFunction::DenseRank {
            order_by: order_by.clone(),
        }),
        _ => None,
    }
}

fn grouped_aggregate_item_kind(expr: &Expr) -> GroupedAggregateItemKind {
    match aggregate_function(expr) {
        Some(function) => GroupedAggregateItemKind::Aggregate(function),
        None => GroupedAggregateItemKind::GroupKey(expr.clone()),
    }
}

fn add_grouped_sort_keys(
    items: &mut Vec<GroupedAggregateItem>,
    order_by: &mut [OrderByExpr],
    group_by: &[Expr],
) -> bool {
    let mut added = false;
    for (index, key) in order_by.iter_mut().enumerate() {
        if let Some(name) = grouped_output_column_name(items, &key.expr) {
            key.expr = Expr::Identifier(Ident::new(name.as_str()));
            continue;
        }
        if let Some(expr) = group_by.iter().find(|expr| *expr == &key.expr) {
            let name = grouped_sort_key_name(items, expr, index);
            items.push(GroupedAggregateItem {
                name: name.clone(),
                kind: GroupedAggregateItemKind::GroupKey(expr.clone()),
            });
            key.expr = Expr::Identifier(Ident::new(name.as_str()));
            added = true;
        }
    }
    added
}

fn grouped_output_column_name(items: &[GroupedAggregateItem], expr: &Expr) -> Option<String> {
    if let Expr::Identifier(identifier) = expr
        && let Some(item) = items
            .iter()
            .find(|item| item.name.eq_ignore_ascii_case(identifier.as_str()))
    {
        return Some(item.name.clone());
    }
    items.iter().find_map(|item| match &item.kind {
        GroupedAggregateItemKind::GroupKey(group_expr) if group_expr == expr => {
            Some(item.name.clone())
        }
        _ => None,
    })
}

fn grouped_sort_key_name(items: &[GroupedAggregateItem], expr: &Expr, index: usize) -> String {
    if let Expr::Identifier(identifier) = expr
        && items
            .iter()
            .all(|item| !item.name.eq_ignore_ascii_case(identifier.as_str()))
    {
        return identifier.as_str().to_string();
    }
    unique_grouped_sort_key_name(items, index + 1)
}

fn unique_grouped_sort_key_name(items: &[GroupedAggregateItem], index: usize) -> String {
    let mut suffix = index;
    loop {
        let name = format!("__group_sort{suffix}");
        if items
            .iter()
            .all(|item| !item.name.eq_ignore_ascii_case(name.as_str()))
        {
            return name;
        }
        suffix += 1;
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

fn window_function_name(function: &WindowFunction) -> String {
    match function {
        WindowFunction::RowNumber { order_by } => {
            let order_by = order_by
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            format!("row_number() OVER (ORDER BY {order_by})")
        }
        WindowFunction::Rank { order_by } => {
            let order_by = order_by
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            format!("rank() OVER (ORDER BY {order_by})")
        }
        WindowFunction::DenseRank { order_by } => {
            let order_by = order_by
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            format!("dense_rank() OVER (ORDER BY {order_by})")
        }
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
