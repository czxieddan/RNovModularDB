use std::cmp::Ordering;

use rnmdb_common::{ErrorKind, Result, RnovError};
use rnmdb_sql::ast::{OrderByExpr, SortDirection};
use rnmdb_types::SqlValue;

use crate::vector::{Row, VectorBatch};

use super::{CancellationToken, eval_expr, sortable_type};

#[derive(Clone, Debug)]
pub(super) struct SortRow {
    keys: Vec<SqlValue>,
    pub(super) original_index: usize,
    row: Row,
}

pub(super) fn apply_sort_cancellable(
    batch: VectorBatch,
    keys: &[OrderByExpr],
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    if keys.is_empty() {
        return Ok(batch);
    }

    let mut rows = sort_rows(&batch, keys, cancellation)?;
    rows.sort_by(|left, right| compare_sort_rows(left, right, keys));
    cancellation.check()?;
    VectorBatch::new(
        batch.columns().to_vec(),
        rows.into_iter().map(|row| row.row).collect(),
    )
}

pub(super) fn sort_rows(
    batch: &VectorBatch,
    keys: &[OrderByExpr],
    cancellation: &CancellationToken,
) -> Result<Vec<SortRow>> {
    let mut rows = Vec::with_capacity(batch.rows().len());
    for (original_index, row) in batch.rows().iter().enumerate() {
        cancellation.check()?;
        let sort_keys = keys
            .iter()
            .map(|key| eval_expr(batch.columns(), row, &key.expr))
            .collect::<Result<Vec<_>>>()?;
        rows.push(SortRow {
            keys: sort_keys,
            original_index,
            row: row.clone(),
        });
    }
    validate_sort_key_types(&rows, keys.len())?;
    Ok(rows)
}

fn validate_sort_key_types(rows: &[SortRow], key_count: usize) -> Result<()> {
    let mut key_types = vec![None; key_count];
    for row in rows {
        for (index, value) in row.keys.iter().enumerate() {
            if value.is_null() {
                continue;
            }
            let data_type = value.data_type();
            if !sortable_type(&data_type) {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("ORDER BY expression type is not sortable: {data_type:?}"),
                ));
            }
            match &key_types[index] {
                Some(existing) if *existing != data_type => {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        "ORDER BY expression produced mixed value types",
                    ));
                }
                Some(_) => {}
                None => key_types[index] = Some(data_type),
            }
        }
    }
    Ok(())
}

pub(super) fn compare_sort_rows(left: &SortRow, right: &SortRow, keys: &[OrderByExpr]) -> Ordering {
    let ordering = compare_sort_row_keys(left, right, keys);
    if ordering != Ordering::Equal {
        return ordering;
    }
    left.original_index.cmp(&right.original_index)
}

pub(super) fn compare_sort_row_keys(
    left: &SortRow,
    right: &SortRow,
    keys: &[OrderByExpr],
) -> Ordering {
    for (index, key) in keys.iter().enumerate() {
        let ordering = compare_sort_values(&left.keys[index], &right.keys[index], key.direction);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    Ordering::Equal
}

fn compare_sort_values(left: &SqlValue, right: &SqlValue, direction: SortDirection) -> Ordering {
    match (left.is_null(), right.is_null()) {
        (true, true) => return Ordering::Equal,
        (true, false) => {
            return if sort_nulls_first(direction) {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }
        (false, true) => {
            return if sort_nulls_first(direction) {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        (false, false) => {}
    }

    let ordering = match (left, right) {
        (SqlValue::Bool(left), SqlValue::Bool(right)) => left.cmp(right),
        (SqlValue::Int64(left), SqlValue::Int64(right)) => left.cmp(right),
        (SqlValue::UInt64(left), SqlValue::UInt64(right)) => left.cmp(right),
        (SqlValue::Float64(left), SqlValue::Float64(right)) => left
            .get()
            .partial_cmp(&right.get())
            .unwrap_or(Ordering::Equal),
        (SqlValue::Uuid(left), SqlValue::Uuid(right)) => left.cmp(right),
        (SqlValue::Text(left), SqlValue::Text(right)) => left.cmp(right),
        (SqlValue::Bytes(left), SqlValue::Bytes(right)) => left.cmp(right),
        _ => Ordering::Equal,
    };
    if sort_descending(direction) {
        ordering.reverse()
    } else {
        ordering
    }
}

fn sort_descending(direction: SortDirection) -> bool {
    matches!(
        direction,
        SortDirection::Desc | SortDirection::DescNullsFirst | SortDirection::DescNullsLast
    )
}

fn sort_nulls_first(direction: SortDirection) -> bool {
    matches!(
        direction,
        SortDirection::AscNullsFirst | SortDirection::Desc | SortDirection::DescNullsFirst
    )
}
