// crates/rnmdb-cli/src/tenant_context.rs - RNovModularDB source module.
// Copyright (C) 2026 czxieddan
// This file is part of RNovModularDB and is provided under version 1.0 of the
// Aperip Heimdall Commons License (AHCL). The applicable version is also
// subject to the AHCL provisions concerning Continuous AHCL Licensing Segments
// and migration to later official versions. After a reasonable opportunity to
// read AHCL, all applicable Additional Restrictions, and all version notices,
// use, copying, modification, building, dependency use, deployment,
// distribution, or network operation constitutes acceptance to the extent
// permitted by applicable law.
// License notice updated: August 12, 2026.
// Official text and notices: https://ahcl.aperip.com
// Repository license copy: AHCL/AHCL-1.0.md
// Canonical repository: https://github.com/czxieddan/RNovModularDB
// Project notice: AHCL/AHCL-PROJECT-NOTICE.md
// Version records: AHCL/AHCL-VERSION-ADOPTION.md
// Source and history: AHCL/AHCL-SOURCE.md
// Dependencies and licenses: AHCL/AHCL-DEPENDENCIES.md
// Additional Restrictions: None.
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
use std::{
    fmt,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    sync::Arc,
};

use rnmdb_catalog::{Catalog, FunctionImplementation as CatalogFunctionImplementation};
use rnmdb_common::{
    ErrorKind, Result, RnovError,
    ids::{FunctionId, RoleId},
};
use rnmdb_executor::{
    memory::ScalarFunctionRuntime,
    vector::{ColumnSchema, Row, VectorBatch},
};
use rnmdb_sql::{
    ast::BoundStatement,
    lexer::{Token, TokenKind, lex},
};
use rnmdb_types::{SqlType, SqlValue};
use rnmdb_udf::{UdfDefinition, UdfRegistry, WasmScalarRuntime};

use super::{CommandOutput, LocalSession};

const CURRENT_TENANT_FUNCTION: &str = "current_tenant";
const MAX_SESSION_TENANT_BYTES: usize = 256;

pub(super) struct TenantContextState {
    current_tenant_function_id: FunctionId,
    active: Option<SessionTenantContext>,
    tainted: bool,
}

#[derive(Clone)]
struct SessionTenantContext {
    value: String,
}

#[derive(Clone)]
struct SessionIdentity {
    role_id: RoleId,
    tenant_context: Option<SessionTenantContext>,
}

#[derive(Clone, Copy)]
enum TenantScopeCleanup {
    Rollback,
    #[cfg(feature = "test-hooks")]
    InjectFailure,
}

struct SessionScalarRuntime {
    registry: UdfRegistry,
    runtime: WasmScalarRuntime,
    current_tenant_function_id: FunctionId,
    tenant_context: Option<SessionTenantContext>,
}

impl TenantContextState {
    pub(super) fn new(catalog: &mut Catalog) -> Result<Self> {
        Ok(Self {
            current_tenant_function_id: ensure_current_tenant_function(catalog)?,
            active: None,
            tainted: false,
        })
    }
}

impl fmt::Debug for SessionScalarRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionScalarRuntime")
            .field("registered_functions", &self.registry.len())
            .field("tenant_context_bound", &self.tenant_context.is_some())
            .finish_non_exhaustive()
    }
}

impl ScalarFunctionRuntime for SessionScalarRuntime {
    fn return_type(&self, function_id: FunctionId) -> Option<SqlType> {
        if function_id == self.current_tenant_function_id {
            return Some(SqlType::Text);
        }
        self.registry
            .resolve_by_id(function_id)
            .and_then(UdfDefinition::return_type)
            .cloned()
    }

    fn execute(&self, function_id: FunctionId, arguments: &[SqlValue]) -> Result<Option<SqlValue>> {
        if function_id == self.current_tenant_function_id {
            return self.execute_current_tenant(arguments).map(Some);
        }
        let Some(definition) = self.registry.resolve_by_id(function_id) else {
            return Ok(None);
        };
        self.runtime.execute_scalar(definition, arguments).map(Some)
    }
}

impl SessionScalarRuntime {
    fn execute_current_tenant(&self, arguments: &[SqlValue]) -> Result<SqlValue> {
        if !arguments.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "current_tenant does not accept arguments",
            ));
        }
        Ok(current_tenant_value(self.tenant_context.as_ref()))
    }
}

impl SessionTenantContext {
    fn parse(value: &str) -> Result<Self> {
        if value.is_empty()
            || value.len() > MAX_SESSION_TENANT_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "session tenant must contain 1 to {MAX_SESSION_TENANT_BYTES} non-control UTF-8 bytes"
                ),
            ));
        }
        Ok(Self {
            value: value.to_string(),
        })
    }
}

impl LocalSession {
    /// Runs an operation under a bounded tenant context and a named database role.
    ///
    /// The role must already exist and must not be a superuser. The tenant value is available to
    /// row policies through the trusted `current_tenant()` built-in for the duration of `operation`
    /// only. The previous role and tenant context are restored whether the operation succeeds or
    /// returns an error.
    ///
    /// # Errors
    ///
    /// Returns an error when a transaction is already active, the tenant value is empty or exceeds
    /// 256 UTF-8 bytes, the role is missing or is a superuser, the operation fails, or the operation
    /// leaves a transaction active. A transaction left by the operation is rolled back before the
    /// previous session identity is restored.
    pub fn with_tenant_context<T, F>(
        &mut self,
        role_name: &str,
        tenant: &str,
        operation: F,
    ) -> Result<T>
    where
        F: FnOnce(&mut Self) -> Result<T>,
    {
        self.with_tenant_context_inner(role_name, tenant, TenantScopeCleanup::Rollback, operation)
    }

    /// Runs one tenant scope with a scope-bound cleanup failure for contract verification.
    ///
    /// The failure is local to this invocation. It is injected only when `operation` leaves a
    /// transaction active, after which the session rejects every subsequent operation.
    ///
    /// # Errors
    ///
    /// Returns the same entry and operation errors as [`Self::with_tenant_context`]. If cleanup is
    /// injected, returns an internal error and permanently marks this session unavailable.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn with_tenant_context_injected_cleanup_failure<T, F>(
        &mut self,
        role_name: &str,
        tenant: &str,
        operation: F,
    ) -> Result<T>
    where
        F: FnOnce(&mut Self) -> Result<T>,
    {
        self.with_tenant_context_inner(
            role_name,
            tenant,
            TenantScopeCleanup::InjectFailure,
            operation,
        )
    }

    pub(super) fn ensure_checkpoint_allowed(&self) -> Result<()> {
        self.ensure_usable()?;
        if self.tenant_context.active.is_some() {
            return Err(RnovError::new(
                ErrorKind::Security,
                "tenant contexts cannot request checkpoints",
            ));
        }
        Ok(())
    }

    pub(super) fn ensure_column_encryption_configuration_allowed(&self) -> Result<()> {
        self.ensure_usable()?;
        if self.tenant_context.active.is_some() {
            return Err(RnovError::new(
                ErrorKind::Security,
                "tenant contexts cannot configure column encryption",
            ));
        }
        Ok(())
    }

    pub(super) fn ensure_role_change_allowed(&self) -> Result<()> {
        self.ensure_usable()?;
        if self.tenant_context.active.is_some() {
            return Err(RnovError::new(
                ErrorKind::Security,
                "cannot change the active role while a tenant context is active",
            ));
        }
        Ok(())
    }

    pub(super) fn ensure_usable(&self) -> Result<()> {
        if self.tenant_context.tainted {
            return Err(RnovError::new(
                ErrorKind::Security,
                "local session is unavailable after tenant cleanup failure",
            ));
        }
        Ok(())
    }

    pub(super) fn execute_session_query(&self, sql: &str) -> Result<Option<CommandOutput>> {
        let tokens = lex(sql)?;
        if !is_current_tenant_query(&tokens) {
            return Ok(None);
        }
        let columns = vec![ColumnSchema::new(CURRENT_TENANT_FUNCTION, SqlType::Text)];
        let rows = vec![Row::new(vec![current_tenant_value(
            self.tenant_context.active.as_ref(),
        )])];
        VectorBatch::new(columns, rows)
            .map(CommandOutput::Rows)
            .map(Some)
    }

    pub(super) fn validate_tenant_context_statement(
        &self,
        statement: &BoundStatement,
    ) -> Result<()> {
        if self.tenant_context.active.is_some() && !tenant_context_allows_statement(statement) {
            return Err(RnovError::new(
                ErrorKind::Security,
                "tenant contexts cannot execute control-plane statements",
            ));
        }
        Ok(())
    }

    pub(super) fn refresh_scalar_function_runtime(&mut self) {
        self.executor
            .set_scalar_function_runtime(Some(Arc::new(SessionScalarRuntime {
                registry: self.udf_registry.clone(),
                runtime: self.wasm_runtime.clone(),
                current_tenant_function_id: self.tenant_context.current_tenant_function_id,
                tenant_context: self.tenant_context.active.clone(),
            })));
    }

    fn with_tenant_context_inner<T, F>(
        &mut self,
        role_name: &str,
        tenant: &str,
        cleanup: TenantScopeCleanup,
        operation: F,
    ) -> Result<T>
    where
        F: FnOnce(&mut Self) -> Result<T>,
    {
        self.ensure_usable()?;
        let identity = self.resolve_tenant_identity(role_name, tenant)?;
        let previous = self.session_identity();
        self.activate_session_identity(identity);
        let operation_result = catch_unwind(AssertUnwindSafe(|| operation(self)));
        let transaction_result = self.close_tenant_scope_transaction(cleanup);
        if transaction_result.is_err() && self.in_transaction() {
            self.tenant_context.tainted = true;
        }
        self.activate_session_identity(previous);
        match operation_result {
            Ok(operation_result) => transaction_result.and(operation_result),
            Err(payload) => resume_unwind(payload),
        }
    }

    fn resolve_tenant_identity(&self, role_name: &str, tenant: &str) -> Result<SessionIdentity> {
        if self.tenant_context.active.is_some() {
            return Err(RnovError::new(
                ErrorKind::Security,
                "nested tenant contexts are forbidden",
            ));
        }
        if self.in_transaction() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "cannot enter a tenant context while a transaction is active",
            ));
        }
        let tenant_context = SessionTenantContext::parse(tenant)?;
        let role = self
            .catalog
            .get_role(role_name)
            .ok_or_else(|| RnovError::new(ErrorKind::NotFound, "role does not exist"))?;
        let role_id = role.role_id();
        let owns_relation = self
            .catalog
            .tables()
            .iter()
            .any(|table| table.owner_role_id() == Some(role_id));
        if role.is_superuser() || owns_relation {
            return Err(RnovError::new(
                ErrorKind::Security,
                "tenant context roles must not be superusers or relation owners",
            ));
        }
        Ok(SessionIdentity {
            role_id,
            tenant_context: Some(tenant_context),
        })
    }

    fn session_identity(&self) -> SessionIdentity {
        SessionIdentity {
            role_id: self.role_id,
            tenant_context: self.tenant_context.active.clone(),
        }
    }

    fn activate_session_identity(&mut self, identity: SessionIdentity) {
        self.role_id = identity.role_id;
        self.tenant_context.active = identity.tenant_context;
        self.executor.set_active_role(identity.role_id);
        self.refresh_scalar_function_runtime();
    }

    fn close_tenant_scope_transaction(&mut self, _cleanup: TenantScopeCleanup) -> Result<()> {
        if !self.in_transaction() {
            return Ok(());
        }
        #[cfg(feature = "test-hooks")]
        if matches!(_cleanup, TenantScopeCleanup::InjectFailure) {
            return Err(RnovError::new(
                ErrorKind::Internal,
                "injected tenant scope cleanup failure",
            ));
        }
        self.rollback_transaction()?;
        Err(RnovError::new(
            ErrorKind::InvalidInput,
            "tenant context operation left a transaction active",
        ))
    }
}

pub(super) fn is_current_tenant_signature(name: &str, argument_types: &[SqlType]) -> bool {
    name == CURRENT_TENANT_FUNCTION && argument_types.is_empty()
}

fn ensure_current_tenant_function(catalog: &mut Catalog) -> Result<FunctionId> {
    if let Some(function) = catalog.get_function(CURRENT_TENANT_FUNCTION, &[]) {
        if function.return_type() == &SqlType::Text
            && matches!(
                function.implementation(),
                CatalogFunctionImplementation::MetadataOnly
            )
        {
            return Ok(function.function_id());
        }
        return Err(RnovError::new(
            ErrorKind::Corruption,
            "catalog contains an incompatible current_tenant function",
        ));
    }
    catalog
        .register_function(CURRENT_TENANT_FUNCTION, Vec::new(), SqlType::Text)
        .map(|function| function.function_id())
}

fn current_tenant_value(context: Option<&SessionTenantContext>) -> SqlValue {
    match context {
        Some(context) => SqlValue::Text(context.value.clone()),
        None => SqlValue::Null,
    }
}

fn is_current_tenant_query(tokens: &[Token]) -> bool {
    match tokens {
        [select, function, left, right] => {
            is_current_tenant_query_tokens(select, function, left, right)
        }
        [select, function, left, right, semicolon] => {
            is_current_tenant_query_tokens(select, function, left, right)
                && matches!(semicolon.kind(), TokenKind::Semicolon)
        }
        _ => false,
    }
}

fn is_current_tenant_query_tokens(
    select: &Token,
    function: &Token,
    left: &Token,
    right: &Token,
) -> bool {
    matches!(select.kind(), TokenKind::Select)
        && matches!(function.kind(), TokenKind::Identifier(name) if name == CURRENT_TENANT_FUNCTION)
        && matches!(left.kind(), TokenKind::LeftParen)
        && matches!(right.kind(), TokenKind::RightParen)
}

fn tenant_context_allows_statement(statement: &BoundStatement) -> bool {
    match statement {
        BoundStatement::CallProcedure { .. }
        | BoundStatement::Select(_)
        | BoundStatement::SelectJoin(_)
        | BoundStatement::Union(_)
        | BoundStatement::Intersect(_)
        | BoundStatement::Except(_)
        | BoundStatement::RecursiveCte(_)
        | BoundStatement::Query(_)
        | BoundStatement::Transaction { .. }
        | BoundStatement::Insert { .. }
        | BoundStatement::Update(_)
        | BoundStatement::Delete(_) => true,
        BoundStatement::Explain { statement, .. } => tenant_context_allows_statement(statement),
        BoundStatement::CreateTable { .. }
        | BoundStatement::CreateIndex { .. }
        | BoundStatement::CreateTrigger { .. }
        | BoundStatement::AlterTableAddColumn { .. }
        | BoundStatement::AlterColumnEncryption { .. }
        | BoundStatement::DropTable { .. }
        | BoundStatement::DropIndex { .. }
        | BoundStatement::DropTrigger { .. }
        | BoundStatement::CreateFunction { .. }
        | BoundStatement::CreateProcedure { .. }
        | BoundStatement::CreateOperator { .. }
        | BoundStatement::CreateRole { .. }
        | BoundStatement::CreatePolicy { .. }
        | BoundStatement::DropFunction { .. }
        | BoundStatement::DropProcedure { .. }
        | BoundStatement::DropOperator { .. }
        | BoundStatement::DropRole { .. }
        | BoundStatement::DropPolicy { .. }
        | BoundStatement::GrantTablePrivilege { .. }
        | BoundStatement::GrantProcedurePrivilege { .. } => false,
    }
}
