use std::collections::{HashMap, HashSet};

use rnmdb_common::{ErrorKind, Result, RnovError};

use crate::vector::{Row, VectorBatch};

use super::CancellationToken;

pub(super) fn apply_distinct_cancellable(
    batch: VectorBatch,
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    let mut rows = Vec::new();
    let mut seen = HashSet::new();
    for row in batch.rows() {
        cancellation.check()?;
        if seen.insert(row.clone()) {
            rows.push(row.clone());
        }
    }
    cancellation.check()?;
    VectorBatch::new(batch.columns().to_vec(), rows)
}

pub(super) fn apply_union_cancellable(
    left: VectorBatch,
    right: VectorBatch,
    all: bool,
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    validate_union_columns(&left, &right)?;
    let rows = combined_rows(left.rows(), right.rows(), cancellation)?;
    let batch = VectorBatch::new(left.columns().to_vec(), rows)?;
    match all {
        true => Ok(batch),
        false => apply_distinct_cancellable(batch, cancellation),
    }
}

pub(super) fn apply_intersect_cancellable(
    left: VectorBatch,
    right: VectorBatch,
    all: bool,
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    validate_set_operation_columns("INTERSECT", &left, &right)?;
    if all {
        return apply_intersect_all_cancellable(left, right, cancellation);
    }
    let rows = distinct_rows_by_right_membership(left.rows(), &right, true, cancellation)?;
    VectorBatch::new(left.columns().to_vec(), rows)
}

pub(super) fn apply_except_cancellable(
    left: VectorBatch,
    right: VectorBatch,
    all: bool,
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    validate_set_operation_columns("EXCEPT", &left, &right)?;
    if all {
        return apply_except_all_cancellable(left, right, cancellation);
    }
    let rows = distinct_rows_by_right_membership(left.rows(), &right, false, cancellation)?;
    VectorBatch::new(left.columns().to_vec(), rows)
}

fn apply_intersect_all_cancellable(
    left: VectorBatch,
    right: VectorBatch,
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    let mut right_counts = row_counts(right.rows(), cancellation)?;
    let mut rows = Vec::new();
    for row in left.rows() {
        cancellation.check()?;
        match right_counts.get_mut(row) {
            Some(count) if *count > 0 => {
                rows.push(row.clone());
                *count -= 1;
            }
            _ => {}
        }
    }
    cancellation.check()?;
    VectorBatch::new(left.columns().to_vec(), rows)
}

fn apply_except_all_cancellable(
    left: VectorBatch,
    right: VectorBatch,
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    let mut right_counts = row_counts(right.rows(), cancellation)?;
    let mut rows = Vec::new();
    for row in left.rows() {
        cancellation.check()?;
        match right_counts.get_mut(row) {
            Some(count) if *count > 0 => {
                *count -= 1;
                continue;
            }
            _ => {}
        }
        rows.push(row.clone());
    }
    cancellation.check()?;
    VectorBatch::new(left.columns().to_vec(), rows)
}

fn row_set(rows: &[Row], cancellation: &CancellationToken) -> Result<HashSet<Row>> {
    let mut set = HashSet::new();
    for row in rows {
        cancellation.check()?;
        set.insert(row.clone());
    }
    Ok(set)
}

fn combined_rows(
    left: &[Row],
    right: &[Row],
    cancellation: &CancellationToken,
) -> Result<Vec<Row>> {
    let mut rows = Vec::with_capacity(left.len() + right.len());
    append_rows(&mut rows, left, cancellation)?;
    append_rows(&mut rows, right, cancellation)?;
    cancellation.check()?;
    Ok(rows)
}

fn append_rows(
    output: &mut Vec<Row>,
    rows: &[Row],
    cancellation: &CancellationToken,
) -> Result<()> {
    for row in rows {
        cancellation.check()?;
        output.push(row.clone());
    }
    Ok(())
}

fn distinct_rows_by_right_membership(
    left: &[Row],
    right: &VectorBatch,
    keep_matches: bool,
    cancellation: &CancellationToken,
) -> Result<Vec<Row>> {
    let right_rows = row_set(right.rows(), cancellation)?;
    let mut emitted = HashSet::new();
    let mut rows = Vec::new();
    for row in left {
        cancellation.check()?;
        if (right_rows.contains(row) == keep_matches) && emitted.insert(row.clone()) {
            rows.push(row.clone());
        }
    }
    cancellation.check()?;
    Ok(rows)
}

fn row_counts(rows: &[Row], cancellation: &CancellationToken) -> Result<HashMap<Row, usize>> {
    let mut counts = HashMap::new();
    for row in rows {
        cancellation.check()?;
        *counts.entry(row.clone()).or_insert(0) += 1;
    }
    Ok(counts)
}

fn validate_union_columns(left: &VectorBatch, right: &VectorBatch) -> Result<()> {
    validate_set_operation_columns("UNION", left, right)
}

fn validate_set_operation_columns(
    operation: &str,
    left: &VectorBatch,
    right: &VectorBatch,
) -> Result<()> {
    if left.columns().len() != right.columns().len() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "{operation} column count mismatch: left has {}, right has {}",
                left.columns().len(),
                right.columns().len()
            ),
        ));
    }
    for (index, (left, right)) in left.columns().iter().zip(right.columns()).enumerate() {
        if left.data_type() != right.data_type() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "{operation} column {} type mismatch: left is {:?}, right is {:?}",
                    index + 1,
                    left.data_type(),
                    right.data_type()
                ),
            ));
        }
    }
    Ok(())
}
