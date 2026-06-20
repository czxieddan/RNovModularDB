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
        LogicalPlan::Parallel { hint, input } => LogicalPlan::Parallel {
            hint,
            input: Box::new(optimize_plan(*input)),
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
        LogicalPlan::Explain { input } => LogicalPlan::Explain {
            input: Box::new(annotate_parallel(*input, workers)),
        },
        LogicalPlan::Parallel { hint, input } => LogicalPlan::Parallel {
            hint,
            input: Box::new(annotate_parallel(*input, workers)),
        },
        other => other,
    }
}
