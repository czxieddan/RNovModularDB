use std::collections::BTreeMap;

use crate::{
    cost::{CostModel, PlanCost},
    logical::{AggregateItem, GroupedAggregateItem, LogicalPlan, ParallelPlanHint, ProjectionItem},
};
use rnmdb_common::ids::RelationId;
use rnmdb_sql::ast::{ExplainFormat, Expr, OrderByExpr};

#[derive(Clone, Debug, PartialEq)]
pub enum PhysicalPlan {
    SeqScan {
        relation_id: RelationId,
        table: String,
        cost: PlanCost,
    },
    IndexScan {
        relation_id: RelationId,
        table: String,
        index: String,
        column: String,
        value: Expr,
        cost: PlanCost,
    },
    IndexRangeScan {
        relation_id: RelationId,
        table: String,
        index: String,
        column: String,
        lower: Option<Expr>,
        lower_inclusive: bool,
        upper: Option<Expr>,
        upper_inclusive: bool,
        cost: PlanCost,
    },
    TextSearchScan {
        relation_id: RelationId,
        table: String,
        column: String,
        query: String,
        cost: PlanCost,
    },
    Filter {
        predicate: Expr,
        input: Box<PhysicalPlan>,
        cost: PlanCost,
    },
    Projection {
        items: Vec<ProjectionItem>,
        input: Box<PhysicalPlan>,
        cost: PlanCost,
    },
    Aggregate {
        items: Vec<AggregateItem>,
        input: Box<PhysicalPlan>,
        cost: PlanCost,
    },
    GroupedAggregate {
        group_by: Vec<Expr>,
        items: Vec<GroupedAggregateItem>,
        input: Box<PhysicalPlan>,
        cost: PlanCost,
    },
    Distinct {
        input: Box<PhysicalPlan>,
        cost: PlanCost,
    },
    Sort {
        keys: Vec<OrderByExpr>,
        input: Box<PhysicalPlan>,
        cost: PlanCost,
    },
    Limit {
        count: usize,
        input: Box<PhysicalPlan>,
        cost: PlanCost,
    },
    Offset {
        count: usize,
        input: Box<PhysicalPlan>,
        cost: PlanCost,
    },
    SetOperation {
        kind: SetOperationKind,
        all: bool,
        left: Box<PhysicalPlan>,
        right: Box<PhysicalPlan>,
        cost: PlanCost,
    },
    Parallel {
        hint: ParallelPlanHint,
        input: Box<PhysicalPlan>,
        cost: PlanCost,
    },
    Mutation {
        kind: MutationKind,
        table: String,
        cost: PlanCost,
    },
    Ddl {
        description: String,
        cost: PlanCost,
    },
    Transaction {
        action: String,
        cost: PlanCost,
    },
    Explain {
        analyze: bool,
        format: ExplainFormat,
        input: Box<PhysicalPlan>,
        cost: PlanCost,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetOperationKind {
    Union,
    Intersect,
    Except,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationKind {
    Insert,
    Update,
    Delete,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexCatalog {
    indexes: BTreeMap<RelationId, Vec<IndexAccessPath>>,
}

impl IndexCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_index(&mut self, index: IndexAccessPath) {
        self.indexes
            .entry(index.relation_id)
            .or_default()
            .push(index);
    }

    fn best_for_column(&self, relation_id: RelationId, column: &str) -> Option<&IndexAccessPath> {
        self.indexes.get(&relation_id)?.iter().find(|index| {
            index
                .columns
                .first()
                .is_some_and(|leading| leading.eq_ignore_ascii_case(column))
        })
    }

    fn best_single_column_for(
        &self,
        relation_id: RelationId,
        column: &str,
    ) -> Option<&IndexAccessPath> {
        self.indexes.get(&relation_id)?.iter().find(|index| {
            index.columns.len() == 1
                && index
                    .columns
                    .first()
                    .is_some_and(|leading| leading.eq_ignore_ascii_case(column))
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexAccessPath {
    name: String,
    relation_id: RelationId,
    columns: Vec<String>,
    unique: bool,
}

impl IndexAccessPath {
    pub fn new(
        name: impl Into<String>,
        relation_id: RelationId,
        columns: Vec<String>,
        unique: bool,
    ) -> Self {
        Self {
            name: name.into(),
            relation_id,
            columns,
            unique,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PhysicalPlanner {
    cost_model: CostModel,
    indexes: IndexCatalog,
}

impl PhysicalPlanner {
    pub fn new(cost_model: CostModel) -> Self {
        Self {
            cost_model,
            indexes: IndexCatalog::new(),
        }
    }

    pub fn with_indexes(mut self, indexes: IndexCatalog) -> Self {
        self.indexes = indexes;
        self
    }

    pub fn plan(&self, logical: &LogicalPlan) -> PhysicalPlan {
        let cost = self.cost_model.estimate(logical);
        match logical {
            LogicalPlan::Scan { relation_id, table } => PhysicalPlan::SeqScan {
                relation_id: *relation_id,
                table: table.clone(),
                cost,
            },
            LogicalPlan::TextSearch {
                relation_id,
                table,
                column,
                query,
                ..
            } => PhysicalPlan::TextSearchScan {
                relation_id: *relation_id,
                table: table.clone(),
                column: column.clone(),
                query: query.clone(),
                cost,
            },
            LogicalPlan::Filter { predicate, input } => {
                if let Some(scan) = self.index_scan(predicate, input, cost) {
                    return scan;
                }
                PhysicalPlan::Filter {
                    predicate: predicate.clone(),
                    input: Box::new(self.plan(input)),
                    cost,
                }
            }
            LogicalPlan::Project { items, input } => PhysicalPlan::Projection {
                items: items.clone(),
                input: Box::new(self.plan(input)),
                cost,
            },
            LogicalPlan::Aggregate { items, input } => PhysicalPlan::Aggregate {
                items: items.clone(),
                input: Box::new(self.plan(input)),
                cost,
            },
            LogicalPlan::GroupedAggregate {
                group_by,
                items,
                input,
            } => PhysicalPlan::GroupedAggregate {
                group_by: group_by.clone(),
                items: items.clone(),
                input: Box::new(self.plan(input)),
                cost,
            },
            LogicalPlan::Distinct { input } => PhysicalPlan::Distinct {
                input: Box::new(self.plan(input)),
                cost,
            },
            LogicalPlan::Sort { keys, input } => PhysicalPlan::Sort {
                keys: keys.clone(),
                input: Box::new(self.plan(input)),
                cost,
            },
            LogicalPlan::Limit { count, input } => PhysicalPlan::Limit {
                count: *count,
                input: Box::new(self.plan(input)),
                cost,
            },
            LogicalPlan::Offset { count, input } => PhysicalPlan::Offset {
                count: *count,
                input: Box::new(self.plan(input)),
                cost,
            },
            LogicalPlan::Union { all, left, right } => PhysicalPlan::SetOperation {
                kind: SetOperationKind::Union,
                all: *all,
                left: Box::new(self.plan(left)),
                right: Box::new(self.plan(right)),
                cost,
            },
            LogicalPlan::Intersect { all, left, right } => PhysicalPlan::SetOperation {
                kind: SetOperationKind::Intersect,
                all: *all,
                left: Box::new(self.plan(left)),
                right: Box::new(self.plan(right)),
                cost,
            },
            LogicalPlan::Except { all, left, right } => PhysicalPlan::SetOperation {
                kind: SetOperationKind::Except,
                all: *all,
                left: Box::new(self.plan(left)),
                right: Box::new(self.plan(right)),
                cost,
            },
            LogicalPlan::Parallel { hint, input } => PhysicalPlan::Parallel {
                hint: hint.clone(),
                input: Box::new(self.plan(input)),
                cost,
            },
            LogicalPlan::Insert { table, .. } => PhysicalPlan::Mutation {
                kind: MutationKind::Insert,
                table: table.clone(),
                cost,
            },
            LogicalPlan::Update { table, .. } => PhysicalPlan::Mutation {
                kind: MutationKind::Update,
                table: table.clone(),
                cost,
            },
            LogicalPlan::Delete { table, .. } => PhysicalPlan::Mutation {
                kind: MutationKind::Delete,
                table: table.clone(),
                cost,
            },
            LogicalPlan::Transaction { action } => PhysicalPlan::Transaction {
                action: action.clone(),
                cost,
            },
            LogicalPlan::Explain {
                analyze,
                format,
                input,
            } => PhysicalPlan::Explain {
                analyze: *analyze,
                format: *format,
                input: Box::new(self.plan(input)),
                cost,
            },
            other => PhysicalPlan::Ddl {
                description: ddl_description(other),
                cost,
            },
        }
    }
}

impl PhysicalPlan {
    pub fn cost(&self) -> PlanCost {
        match self {
            PhysicalPlan::SeqScan { cost, .. }
            | PhysicalPlan::IndexScan { cost, .. }
            | PhysicalPlan::IndexRangeScan { cost, .. }
            | PhysicalPlan::TextSearchScan { cost, .. }
            | PhysicalPlan::Filter { cost, .. }
            | PhysicalPlan::Projection { cost, .. }
            | PhysicalPlan::Aggregate { cost, .. }
            | PhysicalPlan::GroupedAggregate { cost, .. }
            | PhysicalPlan::Distinct { cost, .. }
            | PhysicalPlan::Sort { cost, .. }
            | PhysicalPlan::Limit { cost, .. }
            | PhysicalPlan::Offset { cost, .. }
            | PhysicalPlan::SetOperation { cost, .. }
            | PhysicalPlan::Parallel { cost, .. }
            | PhysicalPlan::Mutation { cost, .. }
            | PhysicalPlan::Ddl { cost, .. }
            | PhysicalPlan::Transaction { cost, .. }
            | PhysicalPlan::Explain { cost, .. } => *cost,
        }
    }

    pub fn explain(&self) -> String {
        let mut out = String::new();
        write_physical_plan(self, 0, &mut out);
        out
    }
}

fn write_physical_plan(plan: &PhysicalPlan, indent: usize, out: &mut String) {
    let prefix = "  ".repeat(indent);
    match plan {
        PhysicalPlan::SeqScan { table, cost, .. } => {
            out.push_str(&format!(
                "{prefix}SeqScan table={table}{}\n",
                cost_suffix(*cost)
            ));
        }
        PhysicalPlan::IndexScan {
            table,
            index,
            column,
            value,
            cost,
            ..
        } => {
            out.push_str(&format!(
                "{prefix}IndexScan table={table} index={index} column={column} value={value}{}\n",
                cost_suffix(*cost)
            ));
        }
        PhysicalPlan::IndexRangeScan {
            table,
            index,
            column,
            lower,
            lower_inclusive,
            upper,
            upper_inclusive,
            cost,
            ..
        } => {
            out.push_str(&format!(
                "{prefix}IndexRangeScan table={table} index={index} column={column} lower={} {} upper={} {}{}\n",
                bound_expr(lower),
                inclusive_label(*lower_inclusive),
                bound_expr(upper),
                inclusive_label(*upper_inclusive),
                cost_suffix(*cost)
            ));
        }
        PhysicalPlan::TextSearchScan {
            table,
            column,
            query,
            cost,
            ..
        } => {
            out.push_str(&format!(
                "{prefix}TextSearchScan table={table} column={column} query='{query}'{}\n",
                cost_suffix(*cost)
            ));
        }
        PhysicalPlan::Filter {
            predicate,
            input,
            cost,
        } => {
            out.push_str(&format!(
                "{prefix}Filter predicate={predicate}{}\n",
                cost_suffix(*cost)
            ));
            write_physical_plan(input, indent + 1, out);
        }
        PhysicalPlan::Projection { items, input, cost } => {
            let columns = items
                .iter()
                .map(|item| format!("{} := {}", item.name, item.expr))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!(
                "{prefix}Projection {columns}{}\n",
                cost_suffix(*cost)
            ));
            write_physical_plan(input, indent + 1, out);
        }
        PhysicalPlan::Aggregate { items, input, cost } => {
            out.push_str(&format!(
                "{prefix}Aggregate items={}{}\n",
                items.len(),
                cost_suffix(*cost)
            ));
            write_physical_plan(input, indent + 1, out);
        }
        PhysicalPlan::GroupedAggregate {
            group_by,
            items,
            input,
            cost,
        } => {
            out.push_str(&format!(
                "{prefix}GroupedAggregate groups={} items={}{}\n",
                group_by.len(),
                items.len(),
                cost_suffix(*cost)
            ));
            write_physical_plan(input, indent + 1, out);
        }
        PhysicalPlan::Distinct { input, cost } => {
            out.push_str(&format!("{prefix}Distinct{}\n", cost_suffix(*cost)));
            write_physical_plan(input, indent + 1, out);
        }
        PhysicalPlan::Sort { keys, input, cost } => {
            out.push_str(&format!(
                "{prefix}Sort keys={}{}\n",
                keys.len(),
                cost_suffix(*cost)
            ));
            write_physical_plan(input, indent + 1, out);
        }
        PhysicalPlan::Limit { count, input, cost } => {
            out.push_str(&format!(
                "{prefix}Limit count={count}{}\n",
                cost_suffix(*cost)
            ));
            write_physical_plan(input, indent + 1, out);
        }
        PhysicalPlan::Offset { count, input, cost } => {
            out.push_str(&format!(
                "{prefix}Offset count={count}{}\n",
                cost_suffix(*cost)
            ));
            write_physical_plan(input, indent + 1, out);
        }
        PhysicalPlan::SetOperation {
            kind,
            all,
            left,
            right,
            cost,
        } => {
            let mode = if *all { "ALL" } else { "DISTINCT" };
            out.push_str(&format!("{prefix}{kind:?} {mode}{}\n", cost_suffix(*cost)));
            write_physical_plan(left, indent + 1, out);
            write_physical_plan(right, indent + 1, out);
        }
        PhysicalPlan::Parallel { hint, input, cost } => {
            out.push_str(&format!(
                "{prefix}Parallel workers={} reason={}{}\n",
                hint.workers,
                hint.reason,
                cost_suffix(*cost)
            ));
            write_physical_plan(input, indent + 1, out);
        }
        PhysicalPlan::Mutation { kind, table, cost } => {
            out.push_str(&format!(
                "{prefix}{kind:?} table={table}{}\n",
                cost_suffix(*cost)
            ));
        }
        PhysicalPlan::Ddl { description, cost } => {
            out.push_str(&format!(
                "{prefix}Ddl {description}{}\n",
                cost_suffix(*cost)
            ));
        }
        PhysicalPlan::Transaction { action, cost } => {
            out.push_str(&format!(
                "{prefix}Transaction action={action}{}\n",
                cost_suffix(*cost)
            ));
        }
        PhysicalPlan::Explain {
            analyze,
            format,
            input,
            cost,
        } => {
            let format = if *format == ExplainFormat::Logical {
                ""
            } else {
                explain_format_suffix(*format)
            };
            out.push_str(&format!(
                "{prefix}Explain analyze={analyze}{format}{}\n",
                cost_suffix(*cost)
            ));
            write_physical_plan(input, indent + 1, out);
        }
    }
}

impl PhysicalPlanner {
    fn index_scan(
        &self,
        predicate: &Expr,
        input: &LogicalPlan,
        sequential_cost: PlanCost,
    ) -> Option<PhysicalPlan> {
        let LogicalPlan::Scan { relation_id, table } = input else {
            return None;
        };
        if let Some((column, value)) = indexable_equality(predicate) {
            if let Some(index) = self.indexes.best_for_column(*relation_id, column) {
                let cost = self
                    .cost_model
                    .estimate_index_scan(*relation_id, index.unique);
                if cost.total() <= sequential_cost.total() {
                    return Some(PhysicalPlan::IndexScan {
                        relation_id: *relation_id,
                        table: table.clone(),
                        index: index.name.clone(),
                        column: column.to_string(),
                        value: value.clone(),
                        cost,
                    });
                }
            }
        }

        let range = indexable_range(predicate)?;
        let index = self
            .indexes
            .best_single_column_for(*relation_id, range.column)?;
        let cost = self.cost_model.estimate_index_range_scan(*relation_id);
        if cost.total() > sequential_cost.total() {
            return None;
        }
        Some(PhysicalPlan::IndexRangeScan {
            relation_id: *relation_id,
            table: table.clone(),
            index: index.name.clone(),
            column: range.column.to_string(),
            lower: range.lower.cloned(),
            lower_inclusive: range.lower_inclusive,
            upper: range.upper.cloned(),
            upper_inclusive: range.upper_inclusive,
            cost,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct IndexableRange<'a> {
    column: &'a str,
    lower: Option<&'a Expr>,
    lower_inclusive: bool,
    upper: Option<&'a Expr>,
    upper_inclusive: bool,
}

fn indexable_equality(predicate: &Expr) -> Option<(&str, &Expr)> {
    let Expr::Binary { left, op, right } = predicate else {
        return None;
    };
    if op != "=" {
        return None;
    }
    match (left.as_ref(), right.as_ref()) {
        (Expr::Identifier(column), value) if is_index_literal(value) => {
            Some((column.as_str(), value))
        }
        (value, Expr::Identifier(column)) if is_index_literal(value) => {
            Some((column.as_str(), value))
        }
        _ => None,
    }
}

fn indexable_range(predicate: &Expr) -> Option<IndexableRange<'_>> {
    let Expr::Binary { left, op, right } = predicate else {
        return None;
    };
    match (left.as_ref(), op.as_str(), right.as_ref()) {
        (Expr::Identifier(column), ">", value) if is_index_literal(value) => Some(IndexableRange {
            column: column.as_str(),
            lower: Some(value),
            lower_inclusive: false,
            upper: None,
            upper_inclusive: true,
        }),
        (Expr::Identifier(column), ">=", value) if is_index_literal(value) => {
            Some(IndexableRange {
                column: column.as_str(),
                lower: Some(value),
                lower_inclusive: true,
                upper: None,
                upper_inclusive: true,
            })
        }
        (Expr::Identifier(column), "<", value) if is_index_literal(value) => Some(IndexableRange {
            column: column.as_str(),
            lower: None,
            lower_inclusive: true,
            upper: Some(value),
            upper_inclusive: false,
        }),
        (Expr::Identifier(column), "<=", value) if is_index_literal(value) => {
            Some(IndexableRange {
                column: column.as_str(),
                lower: None,
                lower_inclusive: true,
                upper: Some(value),
                upper_inclusive: true,
            })
        }
        (value, "<", Expr::Identifier(column)) if is_index_literal(value) => Some(IndexableRange {
            column: column.as_str(),
            lower: Some(value),
            lower_inclusive: false,
            upper: None,
            upper_inclusive: true,
        }),
        (value, "<=", Expr::Identifier(column)) if is_index_literal(value) => {
            Some(IndexableRange {
                column: column.as_str(),
                lower: Some(value),
                lower_inclusive: true,
                upper: None,
                upper_inclusive: true,
            })
        }
        (value, ">", Expr::Identifier(column)) if is_index_literal(value) => Some(IndexableRange {
            column: column.as_str(),
            lower: None,
            lower_inclusive: true,
            upper: Some(value),
            upper_inclusive: false,
        }),
        (value, ">=", Expr::Identifier(column)) if is_index_literal(value) => {
            Some(IndexableRange {
                column: column.as_str(),
                lower: None,
                lower_inclusive: true,
                upper: Some(value),
                upper_inclusive: true,
            })
        }
        _ => None,
    }
}

fn is_index_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::Integer(_) | Expr::String(_))
}

fn bound_expr(expr: &Option<Expr>) -> String {
    expr.as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| "unbounded".to_string())
}

fn inclusive_label(inclusive: bool) -> &'static str {
    if inclusive { "inclusive" } else { "exclusive" }
}

fn cost_suffix(cost: PlanCost) -> String {
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

fn ddl_description(plan: &LogicalPlan) -> String {
    match plan {
        LogicalPlan::CreateTable { table, .. } => format!("CreateTable table={table}"),
        LogicalPlan::CreateIndex { name, .. } => format!("CreateIndex name={name}"),
        LogicalPlan::AlterTableAddColumn { table, column, .. } => {
            format!("AlterTableAddColumn table={table} column={}", column.name)
        }
        LogicalPlan::DropTable { table, .. } => format!("DropTable table={table}"),
        LogicalPlan::DropIndex { name, .. } => format!("DropIndex name={name}"),
        LogicalPlan::DropFunction { name, .. } => format!("DropFunction name={name}"),
        LogicalPlan::DropOperator { symbol, .. } => format!("DropOperator symbol={symbol}"),
        LogicalPlan::DropRole { name, .. } => format!("DropRole name={name}"),
        LogicalPlan::DropPolicy { name, .. } => format!("DropPolicy name={name}"),
        LogicalPlan::CreateFunction { name, .. } => format!("CreateFunction name={name}"),
        LogicalPlan::CreateOperator { symbol, .. } => format!("CreateOperator symbol={symbol}"),
        LogicalPlan::CreateRole { name, .. } => format!("CreateRole name={name}"),
        LogicalPlan::CreatePolicy { name, .. } => format!("CreatePolicy name={name}"),
        LogicalPlan::GrantTablePrivilege { relation_id, .. } => {
            format!("GrantTablePrivilege relation={relation_id}")
        }
        _ => "Unsupported".to_string(),
    }
}
