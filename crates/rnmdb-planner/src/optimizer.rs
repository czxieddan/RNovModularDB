use crate::logical::{LogicalPlan, ParallelPlanHint};

#[derive(Clone, Debug, Default)]
pub struct RuleOptimizer;

impl RuleOptimizer {
    pub fn new() -> Self {
        Self
    }

    pub fn optimize(&self, plan: LogicalPlan) -> LogicalPlan {
        optimize_plan(plan)
    }

    pub fn optimize_parallel(&self, plan: LogicalPlan, workers: usize) -> LogicalPlan {
        if workers <= 1 {
            return self.optimize(plan);
        }
        annotate_parallel(self.optimize(plan), workers)
    }
}

fn optimize_plan(plan: LogicalPlan) -> LogicalPlan {
    match plan {
        LogicalPlan::Filter { predicate, input } => {
            let input = optimize_plan(*input);
            match input {
                LogicalPlan::Project {
                    items,
                    input: project_input,
                } => LogicalPlan::Project {
                    items,
                    input: Box::new(optimize_plan(LogicalPlan::Filter {
                        predicate,
                        input: project_input,
                    })),
                },
                input => LogicalPlan::Filter {
                    predicate,
                    input: Box::new(input),
                },
            }
        }
        LogicalPlan::Project { items, input } => LogicalPlan::Project {
            items,
            input: Box::new(optimize_plan(*input)),
        },
        LogicalPlan::Aggregate { items, input } => LogicalPlan::Aggregate {
            items,
            input: Box::new(optimize_plan(*input)),
        },
        LogicalPlan::GroupedAggregate {
            group_by,
            items,
            input,
        } => LogicalPlan::GroupedAggregate {
            group_by,
            items,
            input: Box::new(optimize_plan(*input)),
        },
        LogicalPlan::Distinct { input } => LogicalPlan::Distinct {
            input: Box::new(optimize_plan(*input)),
        },
        LogicalPlan::Union { all, left, right } => LogicalPlan::Union {
            all,
            left: Box::new(optimize_plan(*left)),
            right: Box::new(optimize_plan(*right)),
        },
        LogicalPlan::Intersect { all, left, right } => LogicalPlan::Intersect {
            all,
            left: Box::new(optimize_plan(*left)),
            right: Box::new(optimize_plan(*right)),
        },
        LogicalPlan::Except { all, left, right } => LogicalPlan::Except {
            all,
            left: Box::new(optimize_plan(*left)),
            right: Box::new(optimize_plan(*right)),
        },
        LogicalPlan::Sort { keys, input } => LogicalPlan::Sort {
            keys,
            input: Box::new(optimize_plan(*input)),
        },
        LogicalPlan::Limit { count, input } => LogicalPlan::Limit {
            count,
            input: Box::new(optimize_plan(*input)),
        },
        LogicalPlan::Offset { count, input } => LogicalPlan::Offset {
            count,
            input: Box::new(optimize_plan(*input)),
        },
        LogicalPlan::Parallel { hint, input } => LogicalPlan::Parallel {
            hint,
            input: Box::new(optimize_plan(*input)),
        },
        LogicalPlan::SidewaysLookup {
            outer,
            inner_relation_id,
            inner_table,
            inner_column,
            outer_column,
        } => LogicalPlan::SidewaysLookup {
            outer: Box::new(optimize_plan(*outer)),
            inner_relation_id,
            inner_table,
            inner_column,
            outer_column,
        },
        other => other,
    }
}

fn annotate_parallel(plan: LogicalPlan, workers: usize) -> LogicalPlan {
    match plan {
        LogicalPlan::Scan { .. } | LogicalPlan::TextSearch { .. } => LogicalPlan::Parallel {
            hint: ParallelPlanHint::new(workers, "parallel read candidate")
                .expect("workers greater than one are valid"),
            input: Box::new(plan),
        },
        LogicalPlan::Filter { predicate, input } => LogicalPlan::Filter {
            predicate,
            input: Box::new(annotate_parallel(*input, workers)),
        },
        LogicalPlan::Project { items, input } => LogicalPlan::Project {
            items,
            input: Box::new(annotate_parallel(*input, workers)),
        },
        LogicalPlan::Aggregate { items, input } => LogicalPlan::Aggregate {
            items,
            input: Box::new(annotate_parallel(*input, workers)),
        },
        LogicalPlan::GroupedAggregate {
            group_by,
            items,
            input,
        } => LogicalPlan::GroupedAggregate {
            group_by,
            items,
            input: Box::new(annotate_parallel(*input, workers)),
        },
        LogicalPlan::Distinct { input } => LogicalPlan::Distinct {
            input: Box::new(annotate_parallel(*input, workers)),
        },
        LogicalPlan::Union { all, left, right } => LogicalPlan::Union {
            all,
            left: Box::new(annotate_parallel(*left, workers)),
            right: Box::new(annotate_parallel(*right, workers)),
        },
        LogicalPlan::Intersect { all, left, right } => LogicalPlan::Intersect {
            all,
            left: Box::new(annotate_parallel(*left, workers)),
            right: Box::new(annotate_parallel(*right, workers)),
        },
        LogicalPlan::Except { all, left, right } => LogicalPlan::Except {
            all,
            left: Box::new(annotate_parallel(*left, workers)),
            right: Box::new(annotate_parallel(*right, workers)),
        },
        LogicalPlan::Sort { keys, input } => LogicalPlan::Sort {
            keys,
            input: Box::new(annotate_parallel(*input, workers)),
        },
        LogicalPlan::Limit { count, input } => LogicalPlan::Limit {
            count,
            input: Box::new(annotate_parallel(*input, workers)),
        },
        LogicalPlan::Offset { count, input } => LogicalPlan::Offset {
            count,
            input: Box::new(annotate_parallel(*input, workers)),
        },
        LogicalPlan::Explain {
            analyze,
            format,
            input,
        } => LogicalPlan::Explain {
            analyze,
            format,
            input: Box::new(annotate_parallel(*input, workers)),
        },
        LogicalPlan::Parallel { hint, input } => LogicalPlan::Parallel {
            hint,
            input: Box::new(annotate_parallel(*input, workers)),
        },
        LogicalPlan::SidewaysLookup {
            outer,
            inner_relation_id,
            inner_table,
            inner_column,
            outer_column,
        } => LogicalPlan::SidewaysLookup {
            outer: Box::new(annotate_parallel(*outer, workers)),
            inner_relation_id,
            inner_table,
            inner_column,
            outer_column,
        },
        other => other,
    }
}
