use crate::logical::LogicalPlan;

#[derive(Clone, Debug, Default)]
pub struct RuleOptimizer;

impl RuleOptimizer {
    pub fn new() -> Self {
        Self
    }

    pub fn optimize(&self, plan: LogicalPlan) -> LogicalPlan {
        optimize_plan(plan)
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
        other => other,
    }
}
