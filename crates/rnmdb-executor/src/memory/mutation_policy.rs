// crates/rnmdb-executor/src/memory/mutation_policy.rs - RNovModularDB source module.
// Copyright (C) 2026 czxieddan
// This file is part of RNovModularDB and is provided under version 1.1 of the
// Aperip Heimdall Commons License (AHCL). The applicable version is also
// subject to the AHCL provisions concerning Continuous AHCL Licensing Segments
// and migration to later official versions. After a reasonable opportunity to
// read AHCL, all applicable Additional Restrictions, and all version notices,
// use, copying, modification, building, dependency use, deployment,
// distribution, or network operation constitutes acceptance to the extent
// permitted by applicable law.
// License notice updated: September 17, 2026.
// Official AHCL text and public notices: https://ahcl.aperip.com
// AHCL Materials Directory: .ahcl/
// Repository official or recognized AHCL copy: .ahcl/AHCL-1.1.md
// Canonical repository: https://github.com/czxieddan/RNovModularDB
// Project notice: .ahcl/AHCL-PROJECT-NOTICE.md
// Version records: .ahcl/AHCL-VERSION-ADOPTION.md
// Source and history: .ahcl/AHCL-SOURCE.md
// Dependencies and licenses: .ahcl/AHCL-DEPENDENCIES.md
// Additional Restrictions: None.
// SPDX-License-Identifier: LicenseRef-AHCL-1.1
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
