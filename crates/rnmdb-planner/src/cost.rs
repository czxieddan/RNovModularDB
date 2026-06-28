use std::collections::BTreeMap;

use rnmdb_common::ids::RelationId;

use crate::logical::LogicalPlan;

const DEFAULT_SCAN_ROWS: f64 = 1_000.0;
const DEFAULT_ROW_WIDTH_BYTES: f64 = 64.0;
const DEFAULT_FILTER_SELECTIVITY: f64 = 0.1;
const DEFAULT_TEXT_SEARCH_SELECTIVITY: f64 = 0.05;
const DEFAULT_INDEX_SELECTIVITY: f64 = 0.01;
const DEFAULT_DISTINCT_SELECTIVITY: f64 = 0.5;
const DEFAULT_GROUP_SELECTIVITY: f64 = 0.1;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TableStatistics {
    row_count: f64,
    row_width_bytes: f64,
}

impl TableStatistics {
    pub fn new(row_count: f64, row_width_bytes: f64) -> Self {
        Self {
            row_count: row_count.max(0.0),
            row_width_bytes: row_width_bytes.max(1.0),
        }
    }

    pub fn row_count(self) -> f64 {
        self.row_count
    }

    pub fn row_width_bytes(self) -> f64 {
        self.row_width_bytes
    }
}

impl Default for TableStatistics {
    fn default() -> Self {
        Self::new(DEFAULT_SCAN_ROWS, DEFAULT_ROW_WIDTH_BYTES)
    }
}

#[derive(Clone, Debug, Default)]
pub struct StatisticsCatalog {
    tables: BTreeMap<RelationId, TableStatistics>,
}

impl StatisticsCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_table(&mut self, relation_id: RelationId, statistics: TableStatistics) {
        self.tables.insert(relation_id, statistics);
    }

    pub fn table(&self, relation_id: RelationId) -> TableStatistics {
        self.tables.get(&relation_id).copied().unwrap_or_default()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PlanCost {
    pub rows: f64,
    pub row_width_bytes: f64,
    pub cpu: f64,
    pub io: f64,
}

impl PlanCost {
    pub fn new(rows: f64, row_width_bytes: f64, cpu: f64, io: f64) -> Self {
        Self {
            rows: rows.max(0.0),
            row_width_bytes: row_width_bytes.max(1.0),
            cpu: cpu.max(0.0),
            io: io.max(0.0),
        }
    }

    pub fn total(self) -> f64 {
        self.cpu + self.io
    }

    fn with_rows(self, rows: f64) -> Self {
        Self::new(rows, self.row_width_bytes, self.cpu, self.io)
    }

    fn add_cpu(self, cpu: f64) -> Self {
        Self::new(self.rows, self.row_width_bytes, self.cpu + cpu, self.io)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CostParameters {
    pub seq_page_cost: f64,
    pub cpu_tuple_cost: f64,
    pub cpu_operator_cost: f64,
    pub sort_row_cost: f64,
    pub aggregate_row_cost: f64,
    pub parallel_setup_cost: f64,
    pub parallel_tuple_discount: f64,
}

impl Default for CostParameters {
    fn default() -> Self {
        Self {
            seq_page_cost: 1.0,
            cpu_tuple_cost: 0.01,
            cpu_operator_cost: 0.0025,
            sort_row_cost: 0.02,
            aggregate_row_cost: 0.015,
            parallel_setup_cost: 1.0,
            parallel_tuple_discount: 0.6,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CostModel {
    statistics: StatisticsCatalog,
    parameters: CostParameters,
}

impl CostModel {
    pub fn new(statistics: StatisticsCatalog) -> Self {
        Self {
            statistics,
            parameters: CostParameters::default(),
        }
    }

    pub fn with_parameters(mut self, parameters: CostParameters) -> Self {
        self.parameters = parameters;
        self
    }

    pub fn statistics(&self) -> &StatisticsCatalog {
        &self.statistics
    }

    pub fn estimate(&self, plan: &LogicalPlan) -> PlanCost {
        match plan {
            LogicalPlan::Scan { relation_id, .. } => {
                let stats = self.statistics.table(*relation_id);
                let pages = (stats.row_count() * stats.row_width_bytes() / 8192.0).ceil();
                PlanCost::new(
                    stats.row_count(),
                    stats.row_width_bytes(),
                    stats.row_count() * self.parameters.cpu_tuple_cost,
                    pages * self.parameters.seq_page_cost,
                )
            }
            LogicalPlan::TextSearch {
                relation_id,
                cost_hint,
                ..
            } => {
                let stats = self.statistics.table(*relation_id);
                let term_count = cost_hint.required_terms.len()
                    + cost_hint.optional_terms.len()
                    + cost_hint.excluded_terms.len();
                let selectivity =
                    (DEFAULT_TEXT_SEARCH_SELECTIVITY / term_count.max(1) as f64).max(0.005);
                let rows = stats.row_count() * selectivity;
                PlanCost::new(
                    rows,
                    stats.row_width_bytes(),
                    stats.row_count()
                        * self.parameters.cpu_operator_cost
                        * term_count.max(1) as f64,
                    rows.max(1.0).ceil() * self.parameters.seq_page_cost * 0.25,
                )
            }
            LogicalPlan::Filter { input, .. } => {
                let input = self.estimate(input);
                input
                    .with_rows(input.rows * DEFAULT_FILTER_SELECTIVITY)
                    .add_cpu(input.rows * self.parameters.cpu_operator_cost)
            }
            LogicalPlan::Project { items, input } => {
                let input = self.estimate(input);
                input.add_cpu(input.rows * self.parameters.cpu_operator_cost * items.len() as f64)
            }
            LogicalPlan::Aggregate { items, input } => {
                let input = self.estimate(input);
                PlanCost::new(
                    1.0,
                    input.row_width_bytes,
                    input.cpu
                        + input.rows
                            * self.parameters.aggregate_row_cost
                            * items.len().max(1) as f64,
                    input.io,
                )
            }
            LogicalPlan::GroupedAggregate { items, input, .. } => {
                let input = self.estimate(input);
                PlanCost::new(
                    (input.rows * DEFAULT_GROUP_SELECTIVITY).max(1.0),
                    input.row_width_bytes,
                    input.cpu
                        + input.rows
                            * self.parameters.aggregate_row_cost
                            * items.len().max(1) as f64,
                    input.io,
                )
            }
            LogicalPlan::Distinct { input } => {
                let input = self.estimate(input);
                input
                    .with_rows((input.rows * DEFAULT_DISTINCT_SELECTIVITY).max(1.0))
                    .add_cpu(input.rows * self.parameters.cpu_operator_cost)
            }
            LogicalPlan::Sort { input, .. } => {
                let input = self.estimate(input);
                let log_rows = input.rows.max(2.0).log2();
                input.add_cpu(input.rows * log_rows * self.parameters.sort_row_cost)
            }
            LogicalPlan::Limit { count, input } => {
                let input = self.estimate(input);
                input.with_rows(input.rows.min(*count as f64))
            }
            LogicalPlan::Offset { count, input } => {
                let input = self.estimate(input);
                input.with_rows((input.rows - *count as f64).max(0.0))
            }
            LogicalPlan::Union { all, left, right } => {
                let left = self.estimate(left);
                let right = self.estimate(right);
                let rows = if *all {
                    left.rows + right.rows
                } else {
                    (left.rows + right.rows) * DEFAULT_DISTINCT_SELECTIVITY
                };
                PlanCost::new(
                    rows,
                    left.row_width_bytes.max(right.row_width_bytes),
                    left.cpu + right.cpu + rows * self.parameters.cpu_operator_cost,
                    left.io + right.io,
                )
            }
            LogicalPlan::Intersect { all, left, right } => {
                let left = self.estimate(left);
                let right = self.estimate(right);
                let rows = if *all {
                    left.rows.min(right.rows)
                } else {
                    left.rows.min(right.rows) * DEFAULT_DISTINCT_SELECTIVITY
                };
                PlanCost::new(
                    rows,
                    left.row_width_bytes.max(right.row_width_bytes),
                    left.cpu
                        + right.cpu
                        + (left.rows + right.rows) * self.parameters.cpu_operator_cost,
                    left.io + right.io,
                )
            }
            LogicalPlan::Except { all, left, right } => {
                let left = self.estimate(left);
                let right = self.estimate(right);
                let retained = if *all { 0.75 } else { 0.5 };
                PlanCost::new(
                    left.rows * retained,
                    left.row_width_bytes.max(right.row_width_bytes),
                    left.cpu
                        + right.cpu
                        + (left.rows + right.rows) * self.parameters.cpu_operator_cost,
                    left.io + right.io,
                )
            }
            LogicalPlan::Parallel { hint, input } => {
                let input = self.estimate(input);
                let workers = hint.workers.max(1) as f64;
                PlanCost::new(
                    input.rows,
                    input.row_width_bytes,
                    self.parameters.parallel_setup_cost
                        + (input.cpu / workers) * self.parameters.parallel_tuple_discount,
                    input.io,
                )
            }
            LogicalPlan::Explain { input, .. } => self.estimate(input),
            LogicalPlan::Insert { values, .. } => PlanCost::new(
                1.0,
                DEFAULT_ROW_WIDTH_BYTES,
                values.len().max(1) as f64 * self.parameters.cpu_tuple_cost,
                1.0,
            ),
            LogicalPlan::Update { selection, .. } | LogicalPlan::Delete { selection, .. } => {
                let selectivity = if selection.is_some() {
                    DEFAULT_FILTER_SELECTIVITY
                } else {
                    1.0
                };
                PlanCost::new(
                    DEFAULT_SCAN_ROWS * selectivity,
                    DEFAULT_ROW_WIDTH_BYTES,
                    DEFAULT_SCAN_ROWS * self.parameters.cpu_tuple_cost,
                    (DEFAULT_SCAN_ROWS * DEFAULT_ROW_WIDTH_BYTES / 8192.0).ceil(),
                )
            }
            _ => PlanCost::new(
                0.0,
                DEFAULT_ROW_WIDTH_BYTES,
                self.parameters.cpu_tuple_cost,
                0.0,
            ),
        }
    }

    pub fn estimate_index_scan(&self, relation_id: RelationId, unique: bool) -> PlanCost {
        let stats = self.statistics.table(relation_id);
        let rows = if unique {
            stats.row_count().min(1.0)
        } else {
            (stats.row_count() * DEFAULT_INDEX_SELECTIVITY)
                .max(1.0)
                .min(stats.row_count())
        };
        let descent_cost = stats.row_count().max(2.0).log2() * self.parameters.cpu_operator_cost;
        PlanCost::new(
            rows,
            stats.row_width_bytes(),
            descent_cost + rows * self.parameters.cpu_tuple_cost,
            rows.max(1.0).ceil() * self.parameters.seq_page_cost * 0.1,
        )
    }
}

impl Default for CostModel {
    fn default() -> Self {
        Self::new(StatisticsCatalog::default())
    }
}
