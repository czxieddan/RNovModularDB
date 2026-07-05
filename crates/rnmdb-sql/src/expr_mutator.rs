use rnmdb_common::Result;

use crate::ast::{CaseWhen, Expr, Ident, OrderByExpr};

pub(crate) trait ExprMutator {
    fn rewrite_qualified_identifier(&mut self, qualifier: &Ident, name: &Ident) -> Result<Expr>;

    fn rewrite_expr(&mut self, expr: &Expr) -> Result<Expr> {
        match expr {
            Expr::QualifiedIdentifier { qualifier, name } => {
                self.rewrite_qualified_identifier(qualifier, name)
            }
            Expr::Binary { left, op, right } => Ok(Expr::Binary {
                left: Box::new(self.rewrite_expr(left)?),
                op: op.clone(),
                right: Box::new(self.rewrite_expr(right)?),
            }),
            Expr::Unary { op, expr } => Ok(Expr::Unary {
                op: op.clone(),
                expr: Box::new(self.rewrite_expr(expr)?),
            }),
            Expr::Not(expr) => Ok(Expr::Not(Box::new(self.rewrite_expr(expr)?))),
            Expr::IsNull { expr, negated } => Ok(Expr::IsNull {
                expr: Box::new(self.rewrite_expr(expr)?),
                negated: *negated,
            }),
            Expr::IsTruth {
                expr,
                value,
                negated,
            } => Ok(Expr::IsTruth {
                expr: Box::new(self.rewrite_expr(expr)?),
                value: *value,
                negated: *negated,
            }),
            Expr::IsUnknown { expr, negated } => Ok(Expr::IsUnknown {
                expr: Box::new(self.rewrite_expr(expr)?),
                negated: *negated,
            }),
            Expr::IsDistinctFrom {
                left,
                right,
                negated,
            } => Ok(Expr::IsDistinctFrom {
                left: Box::new(self.rewrite_expr(left)?),
                right: Box::new(self.rewrite_expr(right)?),
                negated: *negated,
            }),
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
            }),
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
            }),
            Expr::Like {
                expr,
                pattern,
                negated,
            } => Ok(Expr::Like {
                expr: Box::new(self.rewrite_expr(expr)?),
                pattern: Box::new(self.rewrite_expr(pattern)?),
                negated: *negated,
            }),
            Expr::Coalesce(values) => values
                .iter()
                .map(|value| self.rewrite_expr(value))
                .collect::<Result<Vec<_>>>()
                .map(Expr::Coalesce),
            Expr::NullIf { left, right } => Ok(Expr::NullIf {
                left: Box::new(self.rewrite_expr(left)?),
                right: Box::new(self.rewrite_expr(right)?),
            }),
            Expr::Case {
                operand,
                whens,
                else_expr,
            } => Ok(Expr::Case {
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
            }),
            Expr::Cast { expr, data_type } => Ok(Expr::Cast {
                expr: Box::new(self.rewrite_expr(expr)?),
                data_type: data_type.clone(),
            }),
            Expr::Call { name, args } => args
                .iter()
                .map(|arg| self.rewrite_expr(arg))
                .collect::<Result<Vec<_>>>()
                .map(|args| Expr::Call {
                    name: name.clone(),
                    args,
                }),
            Expr::Count(expr) => Ok(Expr::Count(Box::new(self.rewrite_expr(expr)?))),
            Expr::CountDistinct(expr) => {
                Ok(Expr::CountDistinct(Box::new(self.rewrite_expr(expr)?)))
            }
            Expr::Sum(expr) => Ok(Expr::Sum(Box::new(self.rewrite_expr(expr)?))),
            Expr::Min(expr) => Ok(Expr::Min(Box::new(self.rewrite_expr(expr)?))),
            Expr::Max(expr) => Ok(Expr::Max(Box::new(self.rewrite_expr(expr)?))),
            Expr::RowNumberOver { order_by } => order_by
                .iter()
                .map(|order_by| {
                    Ok(OrderByExpr {
                        expr: self.rewrite_expr(&order_by.expr)?,
                        direction: order_by.direction,
                    })
                })
                .collect::<Result<Vec<_>>>()
                .map(|order_by| Expr::RowNumberOver { order_by }),
            Expr::RankOver { order_by } => order_by
                .iter()
                .map(|order_by| {
                    Ok(OrderByExpr {
                        expr: self.rewrite_expr(&order_by.expr)?,
                        direction: order_by.direction,
                    })
                })
                .collect::<Result<Vec<_>>>()
                .map(|order_by| Expr::RankOver { order_by }),
            Expr::DenseRankOver { order_by } => order_by
                .iter()
                .map(|order_by| {
                    Ok(OrderByExpr {
                        expr: self.rewrite_expr(&order_by.expr)?,
                        direction: order_by.direction,
                    })
                })
                .collect::<Result<Vec<_>>>()
                .map(|order_by| Expr::DenseRankOver { order_by }),
            Expr::Array(values) => values
                .iter()
                .map(|value| self.rewrite_expr(value))
                .collect::<Result<Vec<_>>>()
                .map(Expr::Array),
            Expr::Range {
                lower,
                upper,
                bounds,
            } => Ok(Expr::Range {
                lower: Box::new(self.rewrite_expr(lower)?),
                upper: Box::new(self.rewrite_expr(upper)?),
                bounds: *bounds,
            }),
            Expr::Identifier(_)
            | Expr::Integer(_)
            | Expr::String(_)
            | Expr::Bool(_)
            | Expr::Null
            | Expr::CountStar
            | Expr::HStore(_) => Ok(expr.clone()),
        }
    }
}

struct QualifiedIdentifierRewriter<'a, F>
where
    F: FnMut(&Ident, &Ident) -> Result<Expr>,
{
    resolver: &'a mut F,
}

impl<F> ExprMutator for QualifiedIdentifierRewriter<'_, F>
where
    F: FnMut(&Ident, &Ident) -> Result<Expr>,
{
    fn rewrite_qualified_identifier(&mut self, qualifier: &Ident, name: &Ident) -> Result<Expr> {
        (self.resolver)(qualifier, name)
    }
}

pub(crate) fn rewrite_qualified_expr<F>(expr: &Expr, resolver: &mut F) -> Result<Expr>
where
    F: FnMut(&Ident, &Ident) -> Result<Expr>,
{
    QualifiedIdentifierRewriter { resolver }.rewrite_expr(expr)
}
