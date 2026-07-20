use rnmdb_common::{ErrorKind, Result, RnovError, ids::RelationId};
use rnmdb_sql::ast::Expr;

use crate::{
    column_crypto::ColumnCryptoState,
    vector::{ColumnSchema, Row},
};

use super::{ScalarFunctionRuntime, eval_predicate_with_runtime};

#[derive(Clone, Copy)]
pub(super) struct MutationPolicies<'a> {
    pub(super) visibility: &'a [Expr],
    pub(super) checks: &'a [Expr],
}

impl<'a> MutationPolicies<'a> {
    pub(super) fn new(visibility: &'a [Expr], checks: &'a [Expr]) -> Self {
        Self { visibility, checks }
    }
}

#[derive(Clone, Copy)]
pub(super) struct RowMutationContext<'a> {
    pub(super) relation_id: RelationId,
    pub(super) column_crypto: &'a ColumnCryptoState,
    pub(super) runtime: Option<&'a dyn ScalarFunctionRuntime>,
}

pub(super) fn row_satisfies_policy_predicates(
    columns: &[ColumnSchema],
    row: &Row,
    predicates: &[Expr],
    runtime: Option<&dyn ScalarFunctionRuntime>,
) -> Result<bool> {
    for predicate in predicates {
        if !eval_predicate_with_runtime(runtime, columns, row, predicate)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn enforce_row_policy_checks(
    columns: &[ColumnSchema],
    row: &Row,
    predicates: &[Expr],
    runtime: Option<&dyn ScalarFunctionRuntime>,
) -> Result<()> {
    if row_satisfies_policy_predicates(columns, row, predicates, runtime)? {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::Security,
        "row policy check rejected mutation",
    ))
}
