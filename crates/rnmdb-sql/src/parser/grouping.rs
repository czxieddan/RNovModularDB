use rnmdb_common::{ErrorKind, Result, RnovError};

use crate::ast::Expr;

const MAX_CUBE_GROUPING_EXPRESSIONS: usize = 16;

pub(super) fn grouping_sets_union(grouping_sets: &[Vec<Expr>]) -> Vec<Expr> {
    let mut group_by = Vec::new();
    for grouping_set in grouping_sets {
        for expr in grouping_set {
            if !group_by.iter().any(|existing| existing == expr) {
                group_by.push(expr.clone());
            }
        }
    }
    group_by
}

pub(super) fn rollup_grouping_sets(group_by: &[Expr]) -> Vec<Vec<Expr>> {
    (0..=group_by.len())
        .rev()
        .map(|count| group_by[..count].to_vec())
        .collect()
}

pub(super) fn cube_grouping_sets(group_by: &[Expr]) -> Result<Vec<Vec<Expr>>> {
    let bits = usize::BITS as usize;
    if group_by.len() > MAX_CUBE_GROUPING_EXPRESSIONS || group_by.len() >= bits {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "CUBE has too many grouping expressions",
        ));
    }
    let set_count = 1usize << group_by.len();
    Ok((0..set_count)
        .rev()
        .map(|mask| {
            group_by
                .iter()
                .enumerate()
                .filter_map(|(index, expr)| {
                    let bit = 1usize << (group_by.len() - index - 1);
                    if mask & bit == 0 {
                        None
                    } else {
                        Some(expr.clone())
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect())
}
