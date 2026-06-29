use std::{collections::BTreeMap, fmt};

use crate::{
    cost::{CostModel, PlanCost},
    logical::{AggregateItem, GroupedAggregateItem, LogicalPlan, ParallelPlanHint, ProjectionItem},
};
use rnmdb_catalog::IndexMethod;
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
    IndexSkipScan {
        relation_id: RelationId,
        table: String,
        index: String,
        column: String,
        value: Expr,
        cost: PlanCost,
    },
    TextSearchScan {
        relation_id: RelationId,
        table: String,
        column: String,
        query: String,
        cost: PlanCost,
    },
    InvertedTextScan {
        relation_id: RelationId,
        table: String,
        index: String,
        column: String,
        query: String,
        cost: PlanCost,
    },
    InvertedValueScan {
        relation_id: RelationId,
        table: String,
        index: String,
        column: String,
        query: InvertedValueQuery,
        cost: PlanCost,
    },
    BlockSummaryScan {
        relation_id: RelationId,
        table: String,
        index: String,
        column: String,
        lower: Expr,
        lower_inclusive: bool,
        upper: Expr,
        upper_inclusive: bool,
        cost: PlanCost,
    },
    RangeOverlapScan {
        relation_id: RelationId,
        table: String,
        index: String,
        column: String,
        range: Expr,
        cost: PlanCost,
    },
    BoundsOverlapScan {
        relation_id: RelationId,
        table: String,
        index: String,
        column: String,
        bounds: Expr,
        cost: PlanCost,
    },
    SidewaysIndexLookup {
        outer: Box<PhysicalPlan>,
        inner_relation_id: RelationId,
        inner_table: String,
        inner_index: String,
        inner_column: String,
        outer_column: String,
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

#[derive(Clone, Debug, PartialEq)]
pub enum InvertedValueQuery {
    ArrayContains {
        values: Vec<Expr>,
    },
    HStoreKey {
        key: String,
    },
    HStoreContains {
        entries: Vec<(String, Option<String>)>,
    },
}

impl InvertedValueQuery {
    fn token_count(&self) -> usize {
        match self {
            Self::ArrayContains { values } => values.len(),
            Self::HStoreKey { .. } => 1,
            Self::HStoreContains { entries } => entries.len(),
        }
    }

    fn is_empty(&self) -> bool {
        self.token_count() == 0
    }
}

impl fmt::Display for InvertedValueQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArrayContains { values } => {
                write!(f, "array_contains({})", Expr::Array(values.clone()))
            }
            Self::HStoreKey { key } => write!(f, "hstore_key('{key}')"),
            Self::HStoreContains { entries } => {
                write!(f, "hstore_contains({})", Expr::HStore(entries.clone()))
            }
        }
    }
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
            index.supports_equality()
                && index
                    .columns
                    .first()
                    .is_some_and(|leading| leading.eq_ignore_ascii_case(column))
        })
    }

    fn best_sideways_lookup_for(
        &self,
        relation_id: RelationId,
        column: &str,
    ) -> Option<&IndexAccessPath> {
        self.best_for_column(relation_id, column)
    }

    fn best_single_column_for(
        &self,
        relation_id: RelationId,
        column: &str,
    ) -> Option<&IndexAccessPath> {
        self.indexes.get(&relation_id)?.iter().find(|index| {
            index.supports_range()
                && index.columns.len() == 1
                && index
                    .columns
                    .first()
                    .is_some_and(|leading| leading.eq_ignore_ascii_case(column))
        })
    }

    fn best_skip_scan_for(
        &self,
        relation_id: RelationId,
        column: &str,
    ) -> Option<&IndexAccessPath> {
        self.indexes.get(&relation_id)?.iter().find(|index| {
            index.supports_skip_scan()
                && !index
                    .columns
                    .first()
                    .is_some_and(|leading| leading.eq_ignore_ascii_case(column))
                && index
                    .columns
                    .iter()
                    .any(|indexed_column| indexed_column.eq_ignore_ascii_case(column))
        })
    }

    fn best_text_search_for(
        &self,
        relation_id: RelationId,
        column: &str,
    ) -> Option<&IndexAccessPath> {
        self.indexes.get(&relation_id)?.iter().find(|index| {
            index.supports_text_search()
                && index.columns.len() == 1
                && index
                    .columns
                    .first()
                    .is_some_and(|indexed_column| indexed_column.eq_ignore_ascii_case(column))
        })
    }

    fn best_range_overlap_for(
        &self,
        relation_id: RelationId,
        column: &str,
    ) -> Option<&IndexAccessPath> {
        self.indexes.get(&relation_id)?.iter().find(|index| {
            index.supports_range_overlap()
                && index.columns.len() == 1
                && index
                    .columns
                    .first()
                    .is_some_and(|indexed_column| indexed_column.eq_ignore_ascii_case(column))
        })
    }

    fn best_bounds_overlap_for(
        &self,
        relation_id: RelationId,
        column: &str,
    ) -> Option<&IndexAccessPath> {
        self.indexes.get(&relation_id)?.iter().find(|index| {
            index.supports_range_overlap()
                && index.columns.len() == 1
                && index
                    .columns
                    .first()
                    .is_some_and(|indexed_column| indexed_column.eq_ignore_ascii_case(column))
        })
    }

    fn best_inverted_value_for(
        &self,
        relation_id: RelationId,
        column: &str,
    ) -> Option<&IndexAccessPath> {
        self.indexes.get(&relation_id)?.iter().find(|index| {
            index.supports_inverted_value()
                && index.columns.len() == 1
                && index
                    .columns
                    .first()
                    .is_some_and(|indexed_column| indexed_column.eq_ignore_ascii_case(column))
        })
    }

    fn best_block_summary_for(
        &self,
        relation_id: RelationId,
        column: &str,
    ) -> Option<&IndexAccessPath> {
        self.indexes.get(&relation_id)?.iter().find(|index| {
            index.supports_block_summary()
                && index.columns.len() == 1
                && index
                    .columns
                    .first()
                    .is_some_and(|indexed_column| indexed_column.eq_ignore_ascii_case(column))
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexAccessPath {
    name: String,
    relation_id: RelationId,
    columns: Vec<String>,
    method: IndexMethod,
    unique: bool,
}

impl IndexAccessPath {
    pub fn new(
        name: impl Into<String>,
        relation_id: RelationId,
        columns: Vec<String>,
        method: IndexMethod,
        unique: bool,
    ) -> Self {
        Self {
            name: name.into(),
            relation_id,
            columns,
            method,
            unique,
        }
    }

    fn supports_equality(&self) -> bool {
        matches!(self.method, IndexMethod::BTree | IndexMethod::Hash)
    }

    fn supports_range(&self) -> bool {
        self.method == IndexMethod::BTree
    }

    fn supports_skip_scan(&self) -> bool {
        self.method == IndexMethod::BTree && self.columns.len() > 1
    }

    fn supports_text_search(&self) -> bool {
        self.method == IndexMethod::Gin
    }

    fn supports_inverted_value(&self) -> bool {
        self.method == IndexMethod::Gin
    }

    fn supports_range_overlap(&self) -> bool {
        self.method == IndexMethod::Gist
    }

    fn supports_block_summary(&self) -> bool {
        self.method == IndexMethod::Brin
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
                cost_hint,
            } => PhysicalPlan::TextSearchScan {
                relation_id: *relation_id,
                table: table.clone(),
                column: column.clone(),
                query: query.clone(),
                cost,
            }
            .indexed_if_cheaper(
                &self.indexes,
                &self.cost_model,
                *relation_id,
                &cost_hint.required_terms,
            ),
            LogicalPlan::SidewaysLookup {
                outer,
                inner_relation_id,
                inner_table,
                inner_column,
                outer_column,
            } => self.sideways_lookup_plan(
                outer,
                *inner_relation_id,
                inner_table,
                inner_column,
                outer_column,
                cost,
            ),
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
    fn indexed_if_cheaper(
        self,
        indexes: &IndexCatalog,
        cost_model: &CostModel,
        relation_id: RelationId,
        required_terms: &[String],
    ) -> Self {
        let PhysicalPlan::TextSearchScan {
            relation_id: scan_relation_id,
            table,
            column,
            query,
            cost,
        } = self
        else {
            return self;
        };

        if !required_terms.is_empty() {
            if let Some(index) = indexes.best_text_search_for(relation_id, &column) {
                let index_cost =
                    cost_model.estimate_inverted_text_scan(relation_id, &column, required_terms);
                if index_cost.total() <= cost.total() {
                    return PhysicalPlan::InvertedTextScan {
                        relation_id: scan_relation_id,
                        table,
                        index: index.name.clone(),
                        column,
                        query,
                        cost: index_cost,
                    };
                }
            }
        }

        PhysicalPlan::TextSearchScan {
            relation_id: scan_relation_id,
            table,
            column,
            query,
            cost,
        }
    }

    pub fn cost(&self) -> PlanCost {
        match self {
            PhysicalPlan::SeqScan { cost, .. }
            | PhysicalPlan::IndexScan { cost, .. }
            | PhysicalPlan::IndexRangeScan { cost, .. }
            | PhysicalPlan::IndexSkipScan { cost, .. }
            | PhysicalPlan::TextSearchScan { cost, .. }
            | PhysicalPlan::InvertedTextScan { cost, .. }
            | PhysicalPlan::InvertedValueScan { cost, .. }
            | PhysicalPlan::BlockSummaryScan { cost, .. }
            | PhysicalPlan::RangeOverlapScan { cost, .. }
            | PhysicalPlan::BoundsOverlapScan { cost, .. }
            | PhysicalPlan::SidewaysIndexLookup { cost, .. }
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
        PhysicalPlan::IndexSkipScan {
            table,
            index,
            column,
            value,
            cost,
            ..
        } => {
            out.push_str(&format!(
                "{prefix}IndexSkipScan table={table} index={index} column={column} value={value}{}\n",
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
        PhysicalPlan::InvertedTextScan {
            table,
            index,
            column,
            query,
            cost,
            ..
        } => {
            out.push_str(&format!(
                "{prefix}InvertedTextScan table={table} index={index} column={column} query='{query}'{}\n",
                cost_suffix(*cost)
            ));
        }
        PhysicalPlan::InvertedValueScan {
            table,
            index,
            column,
            query,
            cost,
            ..
        } => {
            out.push_str(&format!(
                "{prefix}InvertedValueScan table={table} index={index} column={column} query={query}{}\n",
                cost_suffix(*cost)
            ));
        }
        PhysicalPlan::BlockSummaryScan {
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
                "{prefix}BlockSummaryScan table={table} index={index} column={column} lower={lower} {} upper={upper} {}{}\n",
                inclusive_label(*lower_inclusive),
                inclusive_label(*upper_inclusive),
                cost_suffix(*cost)
            ));
        }
        PhysicalPlan::RangeOverlapScan {
            table,
            index,
            column,
            range,
            cost,
            ..
        } => {
            out.push_str(&format!(
                "{prefix}RangeOverlapScan table={table} index={index} column={column} range={range}{}\n",
                cost_suffix(*cost)
            ));
        }
        PhysicalPlan::BoundsOverlapScan {
            table,
            index,
            column,
            bounds,
            cost,
            ..
        } => {
            out.push_str(&format!(
                "{prefix}BoundsOverlapScan table={table} index={index} column={column} bounds={bounds}{}\n",
                cost_suffix(*cost)
            ));
        }
        PhysicalPlan::SidewaysIndexLookup {
            outer,
            inner_table,
            inner_index,
            inner_column,
            outer_column,
            cost,
            ..
        } => {
            out.push_str(&format!(
                "{prefix}SidewaysIndexLookup inner={inner_table} index={inner_index} inner_column={inner_column} outer_column={outer_column}{}\n",
                cost_suffix(*cost)
            ));
            write_physical_plan(outer, indent + 1, out);
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
    fn sideways_lookup_plan(
        &self,
        outer: &LogicalPlan,
        inner_relation_id: RelationId,
        inner_table: &str,
        inner_column: &str,
        outer_column: &str,
        fallback_cost: PlanCost,
    ) -> PhysicalPlan {
        let outer = Box::new(self.plan(outer));
        if let Some(index) = self
            .indexes
            .best_sideways_lookup_for(inner_relation_id, inner_column)
        {
            let lookup_cost = self
                .cost_model
                .estimate_index_scan(inner_relation_id, index.unique);
            let outer_rows = outer.cost().rows.max(1.0);
            let cost = PlanCost::new(
                (outer_rows * lookup_cost.rows).max(1.0),
                outer.cost().row_width_bytes + lookup_cost.row_width_bytes,
                outer.cost().cpu + outer_rows * lookup_cost.cpu,
                outer.cost().io + outer_rows * lookup_cost.io,
            );
            return PhysicalPlan::SidewaysIndexLookup {
                outer,
                inner_relation_id,
                inner_table: inner_table.to_string(),
                inner_index: index.name.clone(),
                inner_column: inner_column.to_string(),
                outer_column: outer_column.to_string(),
                cost,
            };
        }

        PhysicalPlan::Ddl {
            description: format!(
                "SidewaysLookup inner={inner_table} inner_column={inner_column} outer_column={outer_column}"
            ),
            cost: fallback_cost,
        }
    }

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
            if let Some(index) = self.indexes.best_skip_scan_for(*relation_id, column) {
                let cost = self.cost_model.estimate_index_skip_scan(*relation_id);
                if cost.total() <= sequential_cost.total() {
                    return Some(PhysicalPlan::IndexSkipScan {
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

        if let Some((column, range)) = indexable_range_overlap(predicate) {
            if let Some(index) = self.indexes.best_range_overlap_for(*relation_id, column) {
                let cost = self.cost_model.estimate_range_overlap_scan(*relation_id);
                if cost.total() <= sequential_cost.total() {
                    return Some(PhysicalPlan::RangeOverlapScan {
                        relation_id: *relation_id,
                        table: table.clone(),
                        index: index.name.clone(),
                        column: column.to_string(),
                        range: range.clone(),
                        cost,
                    });
                }
            }
        }

        if let Some((column, bounds)) = indexable_bounds_overlap(predicate) {
            if let Some(index) = self.indexes.best_bounds_overlap_for(*relation_id, column) {
                let axes = match bounds {
                    Expr::Array(values) => values.len(),
                    _ => 1,
                };
                let cost = self
                    .cost_model
                    .estimate_bounds_overlap_scan(*relation_id, axes);
                if cost.total() <= sequential_cost.total() {
                    return Some(PhysicalPlan::BoundsOverlapScan {
                        relation_id: *relation_id,
                        table: table.clone(),
                        index: index.name.clone(),
                        column: column.to_string(),
                        bounds: bounds.clone(),
                        cost,
                    });
                }
            }
        }

        if let Some((column, query)) = indexable_inverted_value(predicate) {
            if !query.is_empty() {
                if let Some(index) = self.indexes.best_inverted_value_for(*relation_id, column) {
                    let cost = self
                        .cost_model
                        .estimate_inverted_value_scan(*relation_id, query.token_count());
                    if cost.total() <= sequential_cost.total() {
                        return Some(PhysicalPlan::InvertedValueScan {
                            relation_id: *relation_id,
                            table: table.clone(),
                            index: index.name.clone(),
                            column: column.to_string(),
                            query,
                            cost,
                        });
                    }
                }
            }
        }

        let range = indexable_range(predicate)?;
        if let Some(index) = self
            .indexes
            .best_block_summary_for(*relation_id, range.column)
        {
            if let (Some(lower), Some(upper)) = (range.lower, range.upper) {
                let cost = self.cost_model.estimate_block_summary_scan(*relation_id);
                if cost.total() <= sequential_cost.total() {
                    return Some(PhysicalPlan::BlockSummaryScan {
                        relation_id: *relation_id,
                        table: table.clone(),
                        index: index.name.clone(),
                        column: range.column.to_string(),
                        lower: lower.clone(),
                        lower_inclusive: range.lower_inclusive,
                        upper: upper.clone(),
                        upper_inclusive: range.upper_inclusive,
                        cost,
                    });
                }
            }
        }
        if let Some(index) = self
            .indexes
            .best_single_column_for(*relation_id, range.column)
        {
            let cost = self.cost_model.estimate_index_range_scan(*relation_id);
            if cost.total() > sequential_cost.total() {
                return None;
            }
            return Some(PhysicalPlan::IndexRangeScan {
                relation_id: *relation_id,
                table: table.clone(),
                index: index.name.clone(),
                column: range.column.to_string(),
                lower: range.lower.cloned(),
                lower_inclusive: range.lower_inclusive,
                upper: range.upper.cloned(),
                upper_inclusive: range.upper_inclusive,
                cost,
            });
        }
        None
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
    if let Expr::Between {
        expr,
        low,
        high,
        negated: false,
    } = predicate
    {
        if let (Expr::Identifier(column), low, high) = (expr.as_ref(), low.as_ref(), high.as_ref())
        {
            if is_index_literal(low) && is_index_literal(high) {
                return Some(IndexableRange {
                    column: column.as_str(),
                    lower: Some(low),
                    lower_inclusive: true,
                    upper: Some(high),
                    upper_inclusive: true,
                });
            }
        }
    }
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

fn indexable_range_overlap(predicate: &Expr) -> Option<(&str, &Expr)> {
    let Expr::Binary { left, op, right } = predicate else {
        return None;
    };
    if op != "&&" {
        return None;
    }
    match (left.as_ref(), right.as_ref()) {
        (Expr::Identifier(column), range @ Expr::Range { .. }) => Some((column.as_str(), range)),
        (range @ Expr::Range { .. }, Expr::Identifier(column)) => Some((column.as_str(), range)),
        _ => None,
    }
}

fn indexable_bounds_overlap(predicate: &Expr) -> Option<(&str, &Expr)> {
    let Expr::Binary { left, op, right } = predicate else {
        return None;
    };
    if op != "&&" {
        return None;
    }
    match (left.as_ref(), right.as_ref()) {
        (Expr::Identifier(column), bounds @ Expr::Array(values))
            if values
                .iter()
                .all(|value| matches!(value, Expr::Range { .. })) =>
        {
            Some((column.as_str(), bounds))
        }
        (bounds @ Expr::Array(values), Expr::Identifier(column))
            if values
                .iter()
                .all(|value| matches!(value, Expr::Range { .. })) =>
        {
            Some((column.as_str(), bounds))
        }
        _ => None,
    }
}

fn indexable_inverted_value(predicate: &Expr) -> Option<(&str, InvertedValueQuery)> {
    let Expr::Binary { left, op, right } = predicate else {
        return None;
    };
    match (left.as_ref(), op.as_str(), right.as_ref()) {
        (Expr::Identifier(column), "@>", Expr::Array(values)) => Some((
            column.as_str(),
            InvertedValueQuery::ArrayContains {
                values: values.clone(),
            },
        )),
        (Expr::Identifier(column), "@>", Expr::HStore(entries)) => Some((
            column.as_str(),
            InvertedValueQuery::HStoreContains {
                entries: entries.clone(),
            },
        )),
        (Expr::Identifier(column), "?", Expr::String(key)) => Some((
            column.as_str(),
            InvertedValueQuery::HStoreKey { key: key.clone() },
        )),
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
