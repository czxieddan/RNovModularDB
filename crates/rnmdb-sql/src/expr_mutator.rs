use rnmdb_common::Result;

use crate::ast::{CaseWhen, Expr, Ident, OrderByExpr};

struct QualifiedIdentifierRewriter<'a, F>
where
    F: FnMut(&Ident, &Ident) -> Result<Expr>,
{
    resolver: &'a mut F,
}

impl<F> QualifiedIdentifierRewriter<'_, F>
where
    F: FnMut(&Ident, &Ident) -> Result<Expr>,
{
    fn rewrite_qualified_identifier(&mut self, qualifier: &Ident, name: &Ident) -> Result<Expr> {
        (self.resolver)(qualifier, name)
    }

    fn rewrite_expr(&mut self, expr: &Expr) -> Result<Expr> {
        self.rewrite_expr_candidate(expr)?
            .map_or_else(|| Ok(expr.clone()), Ok)
    }

    fn rewrite_expr_candidate(&mut self, expr: &Expr) -> Result<Option<Expr>> {
        if let Some(expr) = self.rewrite_qualified_identifier_expr(expr)? {
            return Ok(Some(expr));
        }
        self.rewrite_non_identifier_expr(expr)
    }

    fn rewrite_qualified_identifier_expr(&mut self, expr: &Expr) -> Result<Option<Expr>> {
        match expr {
            Expr::QualifiedIdentifier { qualifier, name } => {
                self.rewrite_qualified_identifier(qualifier, name).map(Some)
            }
            _ => Ok(None),
        }
    }

    fn rewrite_non_identifier_expr(&mut self, expr: &Expr) -> Result<Option<Expr>> {
        if let Some(expr) = self.rewrite_operator_expr(expr)? {
            return Ok(Some(expr));
        }
        if let Some(expr) = self.rewrite_predicate_expr(expr)? {
            return Ok(Some(expr));
        }
        if let Some(expr) = self.rewrite_construct_expr(expr)? {
            return Ok(Some(expr));
        }
        self.rewrite_remaining_expr(expr)
    }

    fn rewrite_remaining_expr(&mut self, expr: &Expr) -> Result<Option<Expr>> {
        if let Some(expr) = self.rewrite_aggregate_expr(expr)? {
            return Ok(Some(expr));
        }
        if let Some(expr) = self.rewrite_window_expr(expr)? {
            return Ok(Some(expr));
        }
        self.rewrite_collection_expr(expr)
    }

    fn rewrite_operator_expr(&mut self, expr: &Expr) -> Result<Option<Expr>> {
        match expr {
            Expr::Binary { left, op, right } => Ok(Expr::Binary {
                left: Box::new(self.rewrite_expr(left)?),
                op: op.clone(),
                right: Box::new(self.rewrite_expr(right)?),
            }
            .into()),
            Expr::Unary { op, expr } => Ok(Expr::Unary {
                op: op.clone(),
                expr: Box::new(self.rewrite_expr(expr)?),
            }
            .into()),
            Expr::Not(expr) => Ok(Some(Expr::Not(Box::new(self.rewrite_expr(expr)?)))),
            _ => Ok(None),
        }
    }

    fn rewrite_predicate_expr(&mut self, expr: &Expr) -> Result<Option<Expr>> {
        if let Some(expr) = self.rewrite_simple_predicate_expr(expr)? {
            return Ok(Some(expr));
        }
        self.rewrite_multi_predicate_expr(expr)
    }

    fn rewrite_simple_predicate_expr(&mut self, expr: &Expr) -> Result<Option<Expr>> {
        match expr {
            Expr::IsNull { expr, negated } => Ok(Expr::IsNull {
                expr: Box::new(self.rewrite_expr(expr)?),
                negated: *negated,
            }
            .into()),
            Expr::IsTruth {
                expr,
                value,
                negated,
            } => Ok(Expr::IsTruth {
                expr: Box::new(self.rewrite_expr(expr)?),
                value: *value,
                negated: *negated,
            }
            .into()),
            Expr::IsUnknown { expr, negated } => Ok(Expr::IsUnknown {
                expr: Box::new(self.rewrite_expr(expr)?),
                negated: *negated,
            }
            .into()),
            Expr::IsDistinctFrom {
                left,
                right,
                negated,
            } => Ok(Expr::IsDistinctFrom {
                left: Box::new(self.rewrite_expr(left)?),
                right: Box::new(self.rewrite_expr(right)?),
                negated: *negated,
            }
            .into()),
            _ => Ok(None),
        }
    }

    fn rewrite_multi_predicate_expr(&mut self, expr: &Expr) -> Result<Option<Expr>> {
        if let Some(expr) = self.rewrite_between_expr(expr)? {
            return Ok(Some(expr));
        }
        if let Some(expr) = self.rewrite_in_list_expr(expr)? {
            return Ok(Some(expr));
        }
        if let Some(expr) = self.rewrite_in_subquery_expr(expr)? {
            return Ok(Some(expr));
        }
        self.rewrite_like_expr(expr)
    }

    fn rewrite_between_expr(&mut self, expr: &Expr) -> Result<Option<Expr>> {
        match expr {
            Expr::Between {
                expr,
                low,
                high,
                negated,
            } => Ok(Expr::Between {
                expr: Box::new(self.rewrite_expr(expr)?),
                low: Box::new(self.rewrite_expr(low)?),
                high: Box::new(self.rewrite_expr(high)?),
                negated: *negated,
            }
            .into()),
            _ => Ok(None),
        }
    }

    fn rewrite_in_list_expr(&mut self, expr: &Expr) -> Result<Option<Expr>> {
        match expr {
            Expr::InList {
                expr,
                values,
                negated,
            } => Ok(Expr::InList {
                expr: Box::new(self.rewrite_expr(expr)?),
                values: values
                    .iter()
                    .map(|value| self.rewrite_expr(value))
                    .collect::<Result<Vec<_>>>()?,
                negated: *negated,
            }
            .into()),
            _ => Ok(None),
        }
    }

    fn rewrite_in_subquery_expr(&mut self, expr: &Expr) -> Result<Option<Expr>> {
        match expr {
            Expr::InSubquery {
                expr,
                query,
                negated,
            } => Ok(Expr::InSubquery {
                expr: Box::new(self.rewrite_expr(expr)?),
                query: query.clone(),
                negated: *negated,
            }
            .into()),
            _ => Ok(None),
        }
    }

    fn rewrite_like_expr(&mut self, expr: &Expr) -> Result<Option<Expr>> {
        match expr {
            Expr::Like {
                expr,
                pattern,
                negated,
            } => Ok(Expr::Like {
                expr: Box::new(self.rewrite_expr(expr)?),
                pattern: Box::new(self.rewrite_expr(pattern)?),
                negated: *negated,
            }
            .into()),
            _ => Ok(None),
        }
    }

    fn rewrite_construct_expr(&mut self, expr: &Expr) -> Result<Option<Expr>> {
        match expr {
            Expr::Coalesce(values) => values
                .iter()
                .map(|value| self.rewrite_expr(value))
                .collect::<Result<Vec<_>>>()
                .map(Expr::Coalesce)
                .map(Some),
            Expr::NullIf { left, right } => Ok(Expr::NullIf {
                left: Box::new(self.rewrite_expr(left)?),
                right: Box::new(self.rewrite_expr(right)?),
            }
            .into()),
            Expr::Case { .. } => self.rewrite_case_expr(expr).map(Some),
            Expr::Cast { expr, data_type } => Ok(Expr::Cast {
                expr: Box::new(self.rewrite_expr(expr)?),
                data_type: data_type.clone(),
            }
            .into()),
            Expr::Call { name, args } => args
                .iter()
                .map(|arg| self.rewrite_expr(arg))
                .collect::<Result<Vec<_>>>()
                .map(|args| Expr::Call {
                    name: name.clone(),
                    args,
                })
                .map(Some),
            _ => Ok(None),
        }
    }

    fn rewrite_case_expr(&mut self, expr: &Expr) -> Result<Expr> {
        let Expr::Case {
            operand,
            whens,
            else_expr,
        } = expr
        else {
            unreachable!("rewrite_case_expr only accepts CASE expressions");
        };
        Ok(Expr::Case {
            operand: operand
                .as_ref()
                .map(|operand| self.rewrite_expr(operand))
                .transpose()?
                .map(Box::new),
            whens: whens
                .iter()
                .map(|arm| {
                    Ok(CaseWhen {
                        condition: self.rewrite_expr(&arm.condition)?,
                        result: self.rewrite_expr(&arm.result)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            else_expr: else_expr
                .as_ref()
                .map(|else_expr| self.rewrite_expr(else_expr))
                .transpose()?
                .map(Box::new),
        })
    }

    fn rewrite_aggregate_expr(&mut self, expr: &Expr) -> Result<Option<Expr>> {
        match expr {
            Expr::Count(expr) => Ok(Some(Expr::Count(Box::new(self.rewrite_expr(expr)?)))),
            Expr::CountDistinct(expr) => Ok(Some(Expr::CountDistinct(Box::new(
                self.rewrite_expr(expr)?,
            )))),
            Expr::Sum(expr) => Ok(Some(Expr::Sum(Box::new(self.rewrite_expr(expr)?)))),
            Expr::Min(expr) => Ok(Some(Expr::Min(Box::new(self.rewrite_expr(expr)?)))),
            Expr::Max(expr) => Ok(Some(Expr::Max(Box::new(self.rewrite_expr(expr)?)))),
            _ => Ok(None),
        }
    }

    fn rewrite_window_expr(&mut self, expr: &Expr) -> Result<Option<Expr>> {
        match expr {
            Expr::RowNumberOver { order_by } => self
                .rewrite_order_by_exprs(order_by)
                .map(|order_by| Some(Expr::RowNumberOver { order_by })),
            Expr::RankOver { order_by } => self
                .rewrite_order_by_exprs(order_by)
                .map(|order_by| Some(Expr::RankOver { order_by })),
            Expr::DenseRankOver { order_by } => self
                .rewrite_order_by_exprs(order_by)
                .map(|order_by| Some(Expr::DenseRankOver { order_by })),
            _ => Ok(None),
        }
    }

    fn rewrite_order_by_exprs(&mut self, order_by: &[OrderByExpr]) -> Result<Vec<OrderByExpr>> {
        order_by
            .iter()
            .map(|order_by| {
                Ok(OrderByExpr {
                    expr: self.rewrite_expr(&order_by.expr)?,
                    direction: order_by.direction,
                })
            })
            .collect()
    }

    fn rewrite_collection_expr(&mut self, expr: &Expr) -> Result<Option<Expr>> {
        match expr {
            Expr::Array(values) => values
                .iter()
                .map(|value| self.rewrite_expr(value))
                .collect::<Result<Vec<_>>>()
                .map(Expr::Array)
                .map(Some),
            Expr::Range {
                lower,
                upper,
                bounds,
            } => Ok(Expr::Range {
                lower: Box::new(self.rewrite_expr(lower)?),
                upper: Box::new(self.rewrite_expr(upper)?),
                bounds: *bounds,
            }
            .into()),
            _ => Ok(None),
        }
    }
}

pub(crate) fn rewrite_qualified_expr<F>(expr: &Expr, resolver: &mut F) -> Result<Expr>
where
    F: FnMut(&Ident, &Ident) -> Result<Expr>,
{
    QualifiedIdentifierRewriter { resolver }.rewrite_expr(expr)
}
