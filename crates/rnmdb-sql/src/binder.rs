use rnmdb_catalog::{
    Catalog, IndexMethod, OperatorSignature, Privilege, Table, WasmFunctionImplementation,
};
use rnmdb_common::{
    ErrorKind, Result, RnovError,
    ids::{RelationId, RoleId},
};
use rnmdb_types::SqlType;

use crate::ast::{
    Assignment, BoundAssignment, BoundColumn, BoundDelete, BoundExcept, BoundHashJoinKeys,
    BoundIndexKey, BoundIntersect, BoundJoin, BoundJoinSelect, BoundLateralJoin, BoundQuery,
    BoundRecursiveCte, BoundRowPolicy, BoundSelect, BoundSelectItem, BoundStatement, BoundUnion,
    BoundUpdate, ColumnDef, CreateFunctionImplementation, Expr, Ident, IndexKeyDef,
    JoinClause, JoinKind, LateralJoin, ObjectName, OrderByExpr, SelectItem, SelectSubquery,
    Statement, TransactionAction, WasmFunctionBody,
};
use crate::expr_mutator::{rewrite_expr_tree, rewrite_qualified_expr};
use crate::parser::{parse_expr, parse_statement};

const RLS_DENY_DEFAULT_POLICY: &str = "rnmdb_rls_deny_default";

pub struct Binder<'a> {
    catalog: &'a Catalog,
}

struct CreateOperatorInput<'a> {
    symbol: &'a str,
    left_type: &'a SqlType,
    right_type: &'a SqlType,
    result_type: &'a SqlType,
    function_name: &'a str,
    precedence: Option<u8>,
    commutator: Option<&'a str>,
    negator: Option<&'a str>,
    selectivity: Option<&'a str>,
}

struct SelectInput<'a> {
    distinct: bool,
    select_items: &'a [SelectItem],
    from: &'a ObjectName,
    join: Option<&'a JoinClause>,
    lateral_join: Option<&'a LateralJoin>,
    selection: &'a Option<Expr>,
    group_by: &'a [Expr],
    grouping_sets: &'a [Vec<Expr>],
    having: &'a Option<Expr>,
    order_by: &'a [OrderByExpr],
    limit: Option<usize>,
    offset: Option<usize>,
    role_id: RoleId,
}

struct CteSelectInput<'a> {
    distinct: bool,
    projection: &'a [SelectItem],
    from: &'a ObjectName,
    selection: &'a Option<Expr>,
    order_by: &'a [OrderByExpr],
    limit: Option<usize>,
    offset: Option<usize>,
}

struct JoinBindingContext<'a> {
    right_table: &'a Table,
    joined_columns: Vec<LateralColumn>,
    bound_columns: Vec<BoundColumn>,
}

struct LateralBindingContext<'a> {
    inner_table: &'a Table,
    lateral_columns: Vec<LateralColumn>,
    bound_columns: Vec<BoundColumn>,
    inner_column: String,
    outer_column: String,
}

struct SelectGrouping {
    group_by: Vec<Expr>,
    grouping_sets: Vec<Vec<Expr>>,
    grouped: bool,
    aggregate_count: usize,
}

#[derive(Default)]
struct SelectHavingOutputs {
    having: Option<Expr>,
    hidden_group_keys: Vec<BoundSelectItem>,
    hidden_aggregates: Vec<BoundSelectItem>,
}

struct SelectSortContext<'a> {
    table: &'a Table,
    projection: &'a [BoundSelectItem],
    group_by: &'a [Expr],
    grouped: bool,
    aggregate_count: usize,
    role_id: RoleId,
}

struct ProjectionOutputs<'a> {
    projection: &'a mut Vec<BoundSelectItem>,
    columns: &'a mut Vec<BoundColumn>,
}

struct OperatorSignatureMetadata<'a> {
    precedence: Option<u8>,
    commutator: Option<&'a str>,
    negator: Option<&'a str>,
    selectivity_function_id: Option<rnmdb_common::ids::FunctionId>,
}

#[derive(Clone, Copy)]
enum OuterQueryScope<'a> {
    Table(&'a Table),
    Columns(&'a [LateralColumn]),
}

impl<'a> Binder<'a> {
    pub fn new(catalog: &'a Catalog) -> Self {
        Self { catalog }
    }

    pub fn bind_for_role(&self, statement: &Statement, role_id: RoleId) -> Result<BoundStatement> {
        self.bind_for_role_with_outer(statement, role_id, None)
    }

    fn bind_for_role_with_outer(
        &self,
        statement: &Statement,
        role_id: RoleId,
        outer_scope: Option<OuterQueryScope<'_>>,
    ) -> Result<BoundStatement> {
        match statement {
            Statement::CreateTable {
                name,
                columns,
                if_not_exists,
            } => self.bind_create_table(name, columns, *if_not_exists),
            Statement::CreateIndex {
                name,
                table,
                keys,
                method,
                unique,
                if_not_exists,
            } => self.bind_create_index(name, table, keys, *method, *unique, *if_not_exists),
            Statement::CreateTrigger {
                name,
                table,
                timing,
                event,
                body,
                if_not_exists,
            } => self.bind_create_trigger(name, table, *timing, *event, body, *if_not_exists),
            Statement::AlterTableAddColumn {
                table,
                column,
                if_not_exists,
            } => self.bind_alter_table_add_column(table, column, *if_not_exists),
            Statement::AlterColumnEncryption {
                table,
                column,
                encrypted,
            } => self.bind_alter_column_encryption(table, column, *encrypted),
            Statement::DropTable { name, if_exists } => self.bind_drop_table(name, *if_exists),
            Statement::DropIndex { name, if_exists } => self.bind_drop_index(name, *if_exists),
            Statement::DropTrigger {
                name,
                table,
                if_exists,
            } => self.bind_drop_trigger(name, table, *if_exists),
            Statement::DropFunction {
                name,
                argument_types,
                if_exists,
            } => self.bind_drop_function(name, argument_types, *if_exists),
            Statement::DropProcedure {
                name,
                argument_types,
                if_exists,
            } => self.bind_drop_procedure(name, argument_types, *if_exists),
            Statement::DropOperator {
                symbol,
                left_type,
                right_type,
                if_exists,
            } => self.bind_drop_operator(symbol, left_type, right_type, *if_exists),
            Statement::DropRole { name, if_exists } => self.bind_drop_role(name, *if_exists),
            Statement::DropPolicy {
                name,
                table,
                if_exists,
            } => self.bind_drop_policy(name, table, *if_exists),
            Statement::CreateFunction {
                name,
                argument_types,
                return_type,
                implementation,
                if_not_exists,
            } => self.bind_create_function(
                name,
                argument_types,
                return_type,
                implementation,
                *if_not_exists,
            ),
            Statement::CreateProcedure {
                name,
                argument_types,
                body,
                if_not_exists,
            } => self.bind_create_procedure(name, argument_types, body, *if_not_exists),
            Statement::CreateOperator {
                symbol,
                left_type,
                right_type,
                result_type,
                function,
                precedence,
                commutator,
                negator,
                selectivity,
            } => self.bind_create_operator(CreateOperatorInput {
                symbol,
                left_type,
                right_type,
                result_type,
                function_name: function.as_str(),
                precedence: *precedence,
                commutator: commutator.as_deref(),
                negator: negator.as_deref(),
                selectivity: selectivity.as_ref().map(Ident::as_str),
            }),
            Statement::CreateRole {
                name,
                if_not_exists,
            } => self.bind_create_role(name, *if_not_exists),
            Statement::CreatePolicy {
                name,
                table,
                predicate,
                if_not_exists,
            } => self.bind_create_policy(name, table, predicate, *if_not_exists),
            Statement::GrantTablePrivilege {
                privilege,
                table,
                role,
            } => self.bind_grant_table_privilege(*privilege, table, role),
            Statement::GrantProcedurePrivilege {
                privilege,
                name,
                argument_types,
                role,
            } => self.bind_grant_procedure_privilege(*privilege, name, argument_types, role),
            Statement::CallProcedure { name, args } => {
                self.bind_call_procedure(name, args, role_id)
            }
            Statement::Insert {
                table,
                columns,
                values,
            } => self.bind_insert(table, columns, values, role_id),
            Statement::Update {
                table,
                assignments,
                selection,
            } => self.bind_update(table, assignments, selection, role_id),
            Statement::Delete { table, selection } => self.bind_delete(table, selection, role_id),
            Statement::Select {
                distinct,
                projection,
                from,
                selection,
                group_by,
                having,
                order_by,
                limit,
                offset,
            } => self.bind_select(
                SelectInput {
                    distinct: *distinct,
                    select_items: projection,
                    from,
                    join: None,
                    lateral_join: None,
                    selection,
                    group_by,
                    grouping_sets: &[],
                    having,
                    order_by,
                    limit: *limit,
                    offset: *offset,
                    role_id,
                },
                outer_scope,
            ),
            Statement::SelectJoin {
                distinct,
                projection,
                from,
                join,
                selection,
                group_by,
                having,
                order_by,
                limit,
                offset,
            } => self.bind_select(
                SelectInput {
                    distinct: *distinct,
                    select_items: projection,
                    from,
                    join: Some(join),
                    lateral_join: None,
                    selection,
                    group_by,
                    grouping_sets: &[],
                    having,
                    order_by,
                    limit: *limit,
                    offset: *offset,
                    role_id,
                },
                outer_scope,
            ),
            Statement::SelectLateral {
                distinct,
                projection,
                from,
                lateral_join,
                selection,
                group_by,
                having,
                order_by,
                limit,
                offset,
            } => self.bind_select(
                SelectInput {
                    distinct: *distinct,
                    select_items: projection,
                    from,
                    join: None,
                    lateral_join: Some(lateral_join),
                    selection,
                    group_by,
                    grouping_sets: &[],
                    having,
                    order_by,
                    limit: *limit,
                    offset: *offset,
                    role_id,
                },
                outer_scope,
            ),
            Statement::SelectGroupingSets {
                distinct,
                projection,
                from,
                selection,
                group_by,
                grouping_sets,
                having,
                order_by,
                limit,
                offset,
            } => self.bind_select(
                SelectInput {
                    distinct: *distinct,
                    select_items: projection,
                    from,
                    join: None,
                    lateral_join: None,
                    selection,
                    group_by,
                    grouping_sets,
                    having,
                    order_by,
                    limit: *limit,
                    offset: *offset,
                    role_id,
                },
                outer_scope,
            ),
            Statement::Union { all, left, right } => {
                self.bind_union(*all, left, right, role_id, outer_scope)
            }
            Statement::Intersect { all, left, right } => {
                self.bind_intersect(*all, left, right, role_id, outer_scope)
            }
            Statement::Except { all, left, right } => {
                self.bind_except(*all, left, right, role_id, outer_scope)
            }
            Statement::RecursiveCte {
                name,
                columns,
                seed,
                recursive,
                query,
            } => self.bind_recursive_cte(name, columns, seed, recursive, query, role_id),
            Statement::Query {
                input,
                order_by,
                limit,
                offset,
            } => self.bind_query(input, order_by, *limit, *offset, role_id, outer_scope),
            Statement::Transaction { action } => {
                Ok(BoundStatement::Transaction { action: *action })
            }
            Statement::Explain {
                analyze,
                format,
                statement,
            } => self.bind_explain(*analyze, *format, statement, role_id),
        }
    }

    fn bind_create_table(
        &self,
        name: &ObjectName,
        columns: &[ColumnDef],
        if_not_exists: bool,
    ) -> Result<BoundStatement> {
        self.validate_create_columns(columns)?;
        Ok(BoundStatement::CreateTable {
            name: name.clone(),
            columns: columns.to_vec(),
            if_not_exists,
        })
    }

    fn bind_alter_table_add_column(
        &self,
        table: &ObjectName,
        column: &ColumnDef,
        if_not_exists: bool,
    ) -> Result<BoundStatement> {
        let resolved = self.resolve_table(table)?;
        if resolved
            .columns()
            .iter()
            .any(|existing| existing.name().eq_ignore_ascii_case(column.name.as_str()))
            && !if_not_exists
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("column already exists: {}", column.name),
            ));
        }
        self.validate_column_definition(column)?;
        Ok(BoundStatement::AlterTableAddColumn {
            relation_id: resolved.relation_id(),
            table: table.clone(),
            column: column.clone(),
            if_not_exists,
        })
    }

    fn bind_drop_trigger(
        &self,
        name: &Ident,
        table: &ObjectName,
        if_exists: bool,
    ) -> Result<BoundStatement> {
        let resolved = self.resolve_table(table)?;
        Ok(BoundStatement::DropTrigger {
            name: name.clone(),
            relation_id: resolved.relation_id(),
            table: table.clone(),
            if_exists,
        })
    }

    fn bind_create_procedure(
        &self,
        name: &Ident,
        argument_types: &[SqlType],
        body: &str,
        if_not_exists: bool,
    ) -> Result<BoundStatement> {
        validate_sql_procedure_body(body)?;
        if self
            .catalog
            .get_procedure(name.as_str(), argument_types)
            .is_some()
            && !if_not_exists
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("procedure already exists: {}", name.as_str()),
            ));
        }
        Ok(BoundStatement::CreateProcedure {
            name: name.clone(),
            argument_types: argument_types.to_vec(),
            body: body.to_string(),
            if_not_exists,
        })
    }

    fn bind_create_role(&self, name: &Ident, if_not_exists: bool) -> Result<BoundStatement> {
        if self.catalog.get_role(name.as_str()).is_some() && !if_not_exists {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("role already exists: {}", name.as_str()),
            ));
        }
        Ok(BoundStatement::CreateRole {
            name: name.clone(),
            if_not_exists,
        })
    }

    fn bind_create_policy(
        &self,
        name: &Ident,
        table: &ObjectName,
        predicate: &Expr,
        if_not_exists: bool,
    ) -> Result<BoundStatement> {
        let table = self.resolve_table(table)?;
        if self
            .catalog
            .row_policies(table.relation_id())
            .iter()
            .any(|policy| policy.name() == name.as_str())
            && !if_not_exists
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("row policy already exists: {}", name.as_str()),
            ));
        }
        Ok(BoundStatement::CreatePolicy {
            name: name.clone(),
            relation_id: table.relation_id(),
            predicate: predicate.to_string(),
            if_not_exists,
        })
    }

    fn bind_grant_table_privilege(
        &self,
        privilege: Privilege,
        table: &ObjectName,
        role: &Ident,
    ) -> Result<BoundStatement> {
        let table = self.resolve_table(table)?;
        let role = self.catalog.get_role(role.as_str()).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("role does not exist: {}", role.as_str()),
            )
        })?;
        Ok(BoundStatement::GrantTablePrivilege {
            role_id: role.role_id(),
            relation_id: table.relation_id(),
            privilege,
        })
    }

    fn bind_grant_procedure_privilege(
        &self,
        privilege: Privilege,
        name: &Ident,
        argument_types: &[SqlType],
        role: &Ident,
    ) -> Result<BoundStatement> {
        if privilege != Privilege::Execute {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "procedure grants only support EXECUTE privilege",
            ));
        }
        let procedure = self
            .catalog
            .get_procedure(name.as_str(), argument_types)
            .ok_or_else(|| {
                RnovError::new(
                    ErrorKind::NotFound,
                    format!("procedure does not exist: {}", name.as_str()),
                )
            })?;
        let role = self.catalog.get_role(role.as_str()).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("role does not exist: {}", role.as_str()),
            )
        })?;
        Ok(BoundStatement::GrantProcedurePrivilege {
            role_id: role.role_id(),
            procedure_id: procedure.procedure_id(),
            privilege,
        })
    }

    fn bind_explain(
        &self,
        analyze: bool,
        format: crate::ast::ExplainFormat,
        statement: &Statement,
        role_id: RoleId,
    ) -> Result<BoundStatement> {
        Ok(BoundStatement::Explain {
            analyze,
            format,
            statement: Box::new(self.bind_for_role(statement, role_id)?),
        })
    }

    fn bind_drop_table(&self, name: &ObjectName, if_exists: bool) -> Result<BoundStatement> {
        let relation_id = match self.resolve_table(name) {
            Ok(table) => Some(table.relation_id()),
            Err(err) if if_exists && err.kind() == ErrorKind::NotFound => None,
            Err(err) => return Err(err),
        };

        Ok(BoundStatement::DropTable {
            relation_id,
            name: name.clone(),
            if_exists,
        })
    }

    fn bind_create_function(
        &self,
        name: &Ident,
        argument_types: &[SqlType],
        return_type: &SqlType,
        implementation: &CreateFunctionImplementation,
        if_not_exists: bool,
    ) -> Result<BoundStatement> {
        if self
            .catalog
            .get_function(name.as_str(), argument_types)
            .is_some()
            && !if_not_exists
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("function already exists: {}", name.as_str()),
            ));
        }
        validate_create_function_implementation(argument_types, return_type, implementation)?;
        Ok(BoundStatement::CreateFunction {
            name: name.clone(),
            argument_types: argument_types.to_vec(),
            return_type: return_type.clone(),
            implementation: implementation.clone(),
            if_not_exists,
        })
    }

    fn bind_drop_index(&self, name: &ObjectName, if_exists: bool) -> Result<BoundStatement> {
        let schema = name.schema().unwrap_or("public");
        if self.catalog.get_index(schema, name.object()).is_none() && !if_exists {
            return Err(RnovError::new(
                ErrorKind::NotFound,
                format!("index does not exist: {schema}.{}", name.object()),
            ));
        }

        Ok(BoundStatement::DropIndex {
            name: ObjectName::qualified(schema, name.object()),
            if_exists,
        })
    }

    fn bind_drop_function(
        &self,
        name: &Ident,
        argument_types: &[SqlType],
        if_exists: bool,
    ) -> Result<BoundStatement> {
        if self
            .catalog
            .get_function(name.as_str(), argument_types)
            .is_none()
            && !if_exists
        {
            return Err(RnovError::new(
                ErrorKind::NotFound,
                format!("function does not exist: {}", name.as_str()),
            ));
        }
        Ok(BoundStatement::DropFunction {
            name: name.clone(),
            argument_types: argument_types.to_vec(),
            if_exists,
        })
    }

    fn bind_alter_column_encryption(
        &self,
        table: &ObjectName,
        column: &Ident,
        encrypted: bool,
    ) -> Result<BoundStatement> {
        let resolved = self.resolve_table(table)?;
        if !resolved
            .columns()
            .iter()
            .any(|existing| existing.name().eq_ignore_ascii_case(column.as_str()))
        {
            return Err(RnovError::new(
                ErrorKind::NotFound,
                format!("column does not exist: {}", column.as_str()),
            ));
        }
        Ok(BoundStatement::AlterColumnEncryption {
            relation_id: resolved.relation_id(),
            table: table.clone(),
            column: column.clone(),
            encrypted,
        })
    }

    fn bind_drop_procedure(
        &self,
        name: &Ident,
        argument_types: &[SqlType],
        if_exists: bool,
    ) -> Result<BoundStatement> {
        if self
            .catalog
            .get_procedure(name.as_str(), argument_types)
            .is_none()
            && !if_exists
        {
            return Err(RnovError::new(
                ErrorKind::NotFound,
                format!("procedure does not exist: {}", name.as_str()),
            ));
        }
        Ok(BoundStatement::DropProcedure {
            name: name.clone(),
            argument_types: argument_types.to_vec(),
            if_exists,
        })
    }

    fn bind_drop_operator(
        &self,
        symbol: &str,
        left_type: &SqlType,
        right_type: &SqlType,
        if_exists: bool,
    ) -> Result<BoundStatement> {
        if self
            .catalog
            .get_operator(symbol, left_type, right_type)
            .is_none()
            && !if_exists
        {
            return Err(RnovError::new(
                ErrorKind::NotFound,
                format!("operator does not exist: {symbol}"),
            ));
        }
        Ok(BoundStatement::DropOperator {
            symbol: symbol.to_string(),
            left_type: left_type.clone(),
            right_type: right_type.clone(),
            if_exists,
        })
    }

    fn bind_drop_role(&self, name: &Ident, if_exists: bool) -> Result<BoundStatement> {
        if self.catalog.get_role(name.as_str()).is_none() && !if_exists {
            return Err(RnovError::new(
                ErrorKind::NotFound,
                format!("role does not exist: {}", name.as_str()),
            ));
        }
        Ok(BoundStatement::DropRole {
            name: name.clone(),
            if_exists,
        })
    }

    fn bind_drop_policy(
        &self,
        name: &Ident,
        table: &ObjectName,
        if_exists: bool,
    ) -> Result<BoundStatement> {
        let table = self.resolve_table(table)?;
        if self
            .catalog
            .get_row_policy(table.relation_id(), name.as_str())
            .is_none()
            && !if_exists
        {
            return Err(RnovError::new(
                ErrorKind::NotFound,
                format!("row policy does not exist: {}", name.as_str()),
            ));
        }
        Ok(BoundStatement::DropPolicy {
            name: name.clone(),
            relation_id: table.relation_id(),
            if_exists,
        })
    }

    fn bind_create_index(
        &self,
        name: &ObjectName,
        table: &ObjectName,
        keys: &[IndexKeyDef],
        method: IndexMethod,
        unique: bool,
        if_not_exists: bool,
    ) -> Result<BoundStatement> {
        let index_name = qualified_index_name(name, table);
        self.ensure_index_available(&index_name, if_not_exists)?;
        let resolved = self.resolve_table(table)?;
        let available_columns = bound_columns_for_table(resolved)?;
        let bound_keys = self.bind_index_keys(resolved, &available_columns, keys, method)?;
        Ok(BoundStatement::CreateIndex {
            name: index_name,
            relation_id: resolved.relation_id(),
            table: table.clone(),
            keys: bound_keys,
            method,
            unique,
            if_not_exists,
        })
    }

    fn ensure_index_available(&self, name: &ObjectName, if_not_exists: bool) -> Result<()> {
        let schema = name.schema().expect("qualified index name");
        if self.catalog.get_index(schema, name.object()).is_some() && !if_not_exists {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("index already exists: {schema}.{}", name.object()),
            ));
        }
        Ok(())
    }

    fn bind_index_keys(
        &self,
        table: &Table,
        available_columns: &[BoundColumn],
        keys: &[IndexKeyDef],
        method: IndexMethod,
    ) -> Result<Vec<BoundIndexKey>> {
        keys.iter()
            .map(|key| self.bind_index_key(table, available_columns, keys.len(), method, key))
            .collect()
    }

    fn bind_index_key(
        &self,
        table: &Table,
        available_columns: &[BoundColumn],
        key_count: usize,
        method: IndexMethod,
        key: &IndexKeyDef,
    ) -> Result<BoundIndexKey> {
        match key {
            IndexKeyDef::Column(column) => Ok(BoundIndexKey::Column(
                self.resolve_column(table, column.as_str())?,
            )),
            IndexKeyDef::Expression(expr) => {
                self.bind_expression_index_key(available_columns, key_count, method, expr)
            }
        }
    }

    fn bind_expression_index_key(
        &self,
        available_columns: &[BoundColumn],
        key_count: usize,
        method: IndexMethod,
        expr: &Expr,
    ) -> Result<BoundIndexKey> {
        self.validate_expression_index_shape(method, key_count)?;
        let data_type = self
            .infer_expr_type_from_columns(available_columns, expr)?
            .ok_or_else(|| {
                RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("cannot infer expression index type: {expr}"),
                )
            })?;
        if !matches!(data_type, SqlType::Int64 | SqlType::Text) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("expression index requires INT64 or TEXT expression, got {data_type:?}"),
            ));
        }
        Ok(BoundIndexKey::Expression {
            expr: expr.clone(),
            data_type,
        })
    }

    fn validate_expression_index_shape(&self, method: IndexMethod, key_count: usize) -> Result<()> {
        if !matches!(method, IndexMethod::BTree | IndexMethod::Hash) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "expression indexes support only btree and hash methods",
            ));
        }
        if key_count != 1 {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "expression indexes support exactly one expression",
            ));
        }
        Ok(())
    }

    fn bind_query(
        &self,
        input: &Statement,
        order_by: &[OrderByExpr],
        limit: Option<usize>,
        offset: Option<usize>,
        role_id: RoleId,
        outer_scope: Option<OuterQueryScope<'_>>,
    ) -> Result<BoundStatement> {
        let input = self.bind_for_role_with_outer(input, role_id, outer_scope)?;
        let columns = query_output_columns(&input)?.to_vec();
        let order_by = self.bind_query_output_order_by(&columns, order_by)?;
        Ok(BoundStatement::Query(BoundQuery {
            columns,
            input: Box::new(input),
            order_by,
            limit,
            offset,
        }))
    }

    fn bind_create_operator(&self, input: CreateOperatorInput<'_>) -> Result<BoundStatement> {
        let CreateOperatorInput {
            symbol,
            left_type,
            right_type,
            result_type,
            function_name,
            precedence,
            commutator,
            negator,
            selectivity,
        } = input;
        let argument_types = [left_type.clone(), right_type.clone()];
        let function_id =
            self.resolve_operator_function_id(symbol, function_name, &argument_types, result_type)?;
        let selectivity_function_id =
            self.resolve_operator_selectivity_function_id(symbol, selectivity, &argument_types)?;

        Ok(BoundStatement::CreateOperator {
            signature: operator_signature_with_metadata(
                symbol,
                left_type.clone(),
                right_type.clone(),
                result_type.clone(),
                function_id,
                OperatorSignatureMetadata {
                    precedence,
                    commutator,
                    negator,
                    selectivity_function_id,
                },
            ),
        })
    }

    fn resolve_operator_function_id(
        &self,
        symbol: &str,
        name: &str,
        argument_types: &[SqlType; 2],
        result_type: &SqlType,
    ) -> Result<rnmdb_common::ids::FunctionId> {
        self.catalog
            .functions()
            .iter()
            .find(|function| {
                function.name() == name
                    && function.argument_types() == *argument_types
                    && function.return_type() == result_type
            })
            .map(|function| function.function_id())
            .ok_or_else(|| {
                RnovError::new(
                    ErrorKind::NotFound,
                    format!("function does not exist for operator {symbol}: {name}"),
                )
            })
    }

    fn resolve_operator_selectivity_function_id(
        &self,
        symbol: &str,
        selectivity: Option<&str>,
        argument_types: &[SqlType; 2],
    ) -> Result<Option<rnmdb_common::ids::FunctionId>> {
        let Some(name) = selectivity else {
            return Ok(None);
        };
        self.catalog
            .functions()
            .iter()
            .find(|function| {
                function.name() == name
                    && function.argument_types() == *argument_types
                    && function.return_type() == &SqlType::Int64
            })
            .map(|function| Some(function.function_id()))
            .ok_or_else(|| {
                RnovError::new(
                    ErrorKind::NotFound,
                    format!("selectivity function does not exist for operator {symbol}: {name}"),
                )
            })
    }

    fn bind_call_procedure(
        &self,
        name: &Ident,
        args: &[Expr],
        role_id: RoleId,
    ) -> Result<BoundStatement> {
        let argument_types = args
            .iter()
            .map(procedure_argument_type)
            .collect::<Result<Vec<_>>>()?;
        let procedure = self
            .catalog
            .get_procedure(name.as_str(), &argument_types)
            .ok_or_else(|| {
                RnovError::new(
                    ErrorKind::NotFound,
                    format!("procedure does not exist: {}", name.as_str()),
                )
            })?;
        self.require_procedure_privilege(role_id, procedure.procedure_id(), Privilege::Execute)?;
        validate_sql_procedure_body(procedure.body())?;
        Ok(BoundStatement::CallProcedure {
            name: name.clone(),
            body: procedure.body().to_string(),
            args: args.to_vec(),
        })
    }

    fn validate_create_columns(&self, columns: &[ColumnDef]) -> Result<()> {
        let mut available = Vec::new();
        for column in columns {
            self.validate_column_definition(column)?;
            if let Some(generated) = &column.generated {
                let generated_type =
                    self.infer_expr_type_from_columns(&available, &generated.expr)?;
                if generated_type != Some(column.data_type.clone()) {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "generated column {} expression type {:?} does not match declared type {:?}",
                            column.name,
                            generated_type.unwrap_or(SqlType::Null),
                            column.data_type
                        ),
                    ));
                }
                if !generated.stored {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        "only stored generated columns are supported",
                    ));
                }
            }
            available.push(BoundColumn {
                name: column.name.as_str().to_string(),
                data_type: column.data_type.clone(),
                nullable: column.nullable,
                encrypted: column.encrypted,
                generated: column.generated.clone(),
            });
        }
        Ok(())
    }

    fn validate_column_definition(&self, column: &ColumnDef) -> Result<()> {
        if column
            .generated
            .as_ref()
            .is_some_and(|generated| !generated.stored)
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "only stored generated columns are supported",
            ));
        }
        Ok(())
    }

    fn bind_create_trigger(
        &self,
        name: &Ident,
        table: &ObjectName,
        timing: rnmdb_catalog::TriggerTiming,
        event: rnmdb_catalog::TriggerEvent,
        body: &str,
        if_not_exists: bool,
    ) -> Result<BoundStatement> {
        let resolved = self.resolve_table(table)?;
        validate_trigger_sql_body(body)?;
        Ok(BoundStatement::CreateTrigger {
            name: name.clone(),
            relation_id: resolved.relation_id(),
            table: table.clone(),
            timing,
            event,
            body: body.to_string(),
            if_not_exists,
        })
    }

    fn bind_insert(
        &self,
        table_name: &ObjectName,
        columns: &[crate::ast::Ident],
        values: &[Expr],
        role_id: RoleId,
    ) -> Result<BoundStatement> {
        let table = self.resolve_table(table_name)?;
        self.require_table_privilege(role_id, table.relation_id(), Privilege::Insert)?;
        let mut bound_columns = Vec::with_capacity(columns.len());
        let mut bound_values = Vec::with_capacity(values.len());
        for (ident, value) in columns.iter().zip(values) {
            let column = self.resolve_column(table, ident.as_str())?;
            if column.generated.is_some() {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "cannot insert explicit value for generated column {}",
                        column.name
                    ),
                ));
            }
            let mut infer = |candidate: &Expr| self.infer_expr_type(table, candidate);
            let value = self.bind_function_calls(value, &mut infer)?;
            self.ensure_expr_assignable(table, &column, &value)?;
            bound_columns.push(column);
            bound_values.push(value);
        }
        Ok(BoundStatement::Insert {
            relation_id: table.relation_id(),
            table: table_name.clone(),
            columns: bound_columns,
            values: bound_values,
        })
    }

    fn bind_update(
        &self,
        table_name: &ObjectName,
        assignments: &[Assignment],
        selection: &Option<Expr>,
        role_id: RoleId,
    ) -> Result<BoundStatement> {
        let table = self.resolve_table(table_name)?;
        self.require_table_privilege(role_id, table.relation_id(), Privilege::Update)?;
        let bound_assignments = assignments
            .iter()
            .map(|assignment| self.bind_update_assignment(table, assignment))
            .collect::<Result<Vec<_>>>()?;
        let selection = self.bind_table_selection(table, selection)?;
        Ok(BoundStatement::Update(BoundUpdate {
            relation_id: table.relation_id(),
            table: table_name.clone(),
            assignments: bound_assignments,
            selection,
            applied_row_policies: self.applied_row_policy_names(role_id, table.relation_id()),
            row_policy_predicates: self.bind_row_policies(role_id, table)?,
        }))
    }

    fn bind_update_assignment(
        &self,
        table: &Table,
        assignment: &Assignment,
    ) -> Result<BoundAssignment> {
        let column = self.resolve_column(table, assignment.column.as_str())?;
        if column.generated.is_some() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("cannot update generated column {}", column.name),
            ));
        }
        let value = self.rewrite_table_qualified_expr(table, &assignment.value)?;
        self.ensure_expr_assignable(table, &column, &value)?;
        Ok(BoundAssignment { column, value })
    }

    fn bind_table_selection(
        &self,
        table: &Table,
        selection: &Option<Expr>,
    ) -> Result<Option<Expr>> {
        let Some(selection) = selection else {
            return Ok(None);
        };
        let selection = self.rewrite_table_qualified_expr(table, selection)?;
        self.validate_predicate(table, &selection)?;
        Ok(Some(selection))
    }

    fn bind_except(
        &self,
        all: bool,
        left: &Statement,
        right: &Statement,
        role_id: RoleId,
        outer_scope: Option<OuterQueryScope<'_>>,
    ) -> Result<BoundStatement> {
        let left = self.bind_for_role_with_outer(left, role_id, outer_scope)?;
        let right = self.bind_for_role_with_outer(right, role_id, outer_scope)?;
        let columns = validate_set_operation_columns("EXCEPT", &left, &right)?;
        Ok(BoundStatement::Except(BoundExcept {
            all,
            columns,
            left: Box::new(left),
            right: Box::new(right),
        }))
    }

    fn bind_delete(
        &self,
        table_name: &ObjectName,
        selection: &Option<Expr>,
        role_id: RoleId,
    ) -> Result<BoundStatement> {
        let table = self.resolve_table(table_name)?;
        self.require_table_privilege(role_id, table.relation_id(), Privilege::Delete)?;
        let selection = self.bind_table_selection(table, selection)?;

        Ok(BoundStatement::Delete(BoundDelete {
            relation_id: table.relation_id(),
            table: table_name.clone(),
            selection,
            applied_row_policies: self.applied_row_policy_names(role_id, table.relation_id()),
            row_policy_predicates: self.bind_row_policies(role_id, table)?,
        }))
    }

    fn bind_union(
        &self,
        all: bool,
        left: &Statement,
        right: &Statement,
        role_id: RoleId,
        outer_scope: Option<OuterQueryScope<'_>>,
    ) -> Result<BoundStatement> {
        let left = self.bind_for_role_with_outer(left, role_id, outer_scope)?;
        let right = self.bind_for_role_with_outer(right, role_id, outer_scope)?;
        let columns = validate_set_operation_columns("UNION", &left, &right)?;
        Ok(BoundStatement::Union(BoundUnion {
            all,
            columns,
            left: Box::new(left),
            right: Box::new(right),
        }))
    }

    fn bind_recursive_cte(
        &self,
        name: &ObjectName,
        column_names: &[Ident],
        seed: &Statement,
        recursive: &Statement,
        query: &Statement,
        role_id: RoleId,
    ) -> Result<BoundStatement> {
        validate_recursive_cte_name(name)?;
        let (seed, cte_columns) = self.bind_recursive_cte_seed(seed, column_names, role_id)?;
        let recursive = self.bind_recursive_cte_step(name, &cte_columns, recursive)?;
        let recursive_columns = query_output_columns(&recursive)?;
        validate_recursive_cte_columns(&cte_columns, recursive_columns)?;
        let query = self.bind_recursive_cte_query(name, &cte_columns, query)?;

        Ok(BoundStatement::RecursiveCte(BoundRecursiveCte {
            name: name.clone(),
            columns: cte_columns,
            seed: Box::new(seed),
            recursive: Box::new(recursive),
            query,
        }))
    }

    fn bind_recursive_cte_seed(
        &self,
        statement: &Statement,
        column_names: &[Ident],
        role_id: RoleId,
    ) -> Result<(BoundStatement, Vec<BoundColumn>)> {
        let seed = self.bind_for_role(statement, role_id)?;
        let seed_columns = query_output_columns(&seed)?;
        let cte_columns = recursive_cte_columns(seed_columns, column_names)?;
        Ok((seed, cte_columns))
    }

    fn bind_recursive_cte_step(
        &self,
        name: &ObjectName,
        cte_columns: &[BoundColumn],
        statement: &Statement,
    ) -> Result<BoundStatement> {
        let mut select = self.bind_select_from_columns(statement, name, cte_columns)?;
        rename_select_output_columns(&mut select, cte_columns);
        Ok(BoundStatement::Select(select))
    }

    fn bind_recursive_cte_query(
        &self,
        name: &ObjectName,
        cte_columns: &[BoundColumn],
        statement: &Statement,
    ) -> Result<BoundSelect> {
        self.bind_select_from_columns(statement, name, cte_columns)
    }

    fn bind_intersect(
        &self,
        all: bool,
        left: &Statement,
        right: &Statement,
        role_id: RoleId,
        outer_scope: Option<OuterQueryScope<'_>>,
    ) -> Result<BoundStatement> {
        let left = self.bind_for_role_with_outer(left, role_id, outer_scope)?;
        let right = self.bind_for_role_with_outer(right, role_id, outer_scope)?;
        let columns = validate_set_operation_columns("INTERSECT", &left, &right)?;
        Ok(BoundStatement::Intersect(BoundIntersect {
            all,
            columns,
            left: Box::new(left),
            right: Box::new(right),
        }))
    }

    fn bind_select(
        &self,
        input: SelectInput<'_>,
        outer_scope: Option<OuterQueryScope<'_>>,
    ) -> Result<BoundStatement> {
        let table = self.resolve_table(input.from)?;
        self.require_table_privilege(input.role_id, table.relation_id(), Privilege::Select)?;
        if let Some(lateral_join) = input.lateral_join {
            return self.bind_lateral_select(&input, table, lateral_join);
        }
        if let Some(join) = input.join {
            return self.bind_join_select(&input, table, join);
        }

        self.bind_table_select(input, outer_scope, table)
    }

    fn bind_table_select(
        &self,
        input: SelectInput<'_>,
        outer_scope: Option<OuterQueryScope<'_>>,
        table: &Table,
    ) -> Result<BoundStatement> {
        let (projection, columns) =
            self.bind_select_projection(table, input.select_items, input.role_id)?;
        self.finish_table_select(input, outer_scope, table, projection, columns)
    }

    fn bind_select_projection(
        &self,
        table: &Table,
        select_items: &[SelectItem],
        role_id: RoleId,
    ) -> Result<(Vec<BoundSelectItem>, Vec<BoundColumn>)> {
        let mut columns = Vec::new();
        let mut projection = Vec::new();
        for item in select_items {
            self.bind_select_projection_item(
                table,
                item,
                role_id,
                ProjectionOutputs {
                    projection: &mut projection,
                    columns: &mut columns,
                },
            )?;
        }
        Ok((projection, columns))
    }

    fn bind_select_projection_item(
        &self,
        table: &Table,
        item: &SelectItem,
        role_id: RoleId,
        outputs: ProjectionOutputs<'_>,
    ) -> Result<()> {
        let ProjectionOutputs {
            projection,
            columns,
        } = outputs;
        match item {
            SelectItem::Wildcard => self.bind_table_wildcard_projection(
                table,
                ProjectionOutputs {
                    projection,
                    columns,
                },
            ),
            SelectItem::Expr {
                expr: Expr::Identifier(identifier),
                alias,
            } => self.bind_table_identifier_projection(
                table,
                identifier,
                alias,
                ProjectionOutputs {
                    projection,
                    columns,
                },
            ),
            SelectItem::Expr {
                expr: Expr::QualifiedIdentifier { qualifier, name },
                alias,
            } => self.bind_table_qualified_projection(
                table,
                qualifier,
                name,
                alias,
                ProjectionOutputs {
                    projection,
                    columns,
                },
            ),
            SelectItem::Expr {
                expr: Expr::CountStar,
                alias,
            } => bind_count_star_projection(
                alias,
                ProjectionOutputs {
                    projection,
                    columns,
                },
            ),
            SelectItem::Expr {
                expr: Expr::Count(expr),
                alias,
            } => self.bind_count_projection(
                table,
                expr,
                alias,
                false,
                ProjectionOutputs {
                    projection,
                    columns,
                },
            ),
            SelectItem::Expr {
                expr: Expr::CountDistinct(expr),
                alias,
            } => self.bind_count_projection(
                table,
                expr,
                alias,
                true,
                ProjectionOutputs {
                    projection,
                    columns,
                },
            ),
            SelectItem::Expr {
                expr: Expr::Sum(expr),
                alias,
            } => self.bind_sum_projection(
                table,
                expr,
                alias,
                ProjectionOutputs {
                    projection,
                    columns,
                },
            ),
            SelectItem::Expr {
                expr: Expr::Min(expr),
                alias,
            } => self.bind_ordered_aggregate_projection(
                table,
                expr,
                alias,
                "MIN",
                ProjectionOutputs {
                    projection,
                    columns,
                },
            ),
            SelectItem::Expr {
                expr: Expr::Max(expr),
                alias,
            } => self.bind_ordered_aggregate_projection(
                table,
                expr,
                alias,
                "MAX",
                ProjectionOutputs {
                    projection,
                    columns,
                },
            ),
            SelectItem::Expr {
                expr: Expr::RowNumberOver { order_by },
                alias,
            } => self.bind_ranking_window_projection(
                table,
                "row_number",
                order_by,
                alias,
                ProjectionOutputs {
                    projection,
                    columns,
                },
                |order_by| Expr::RowNumberOver { order_by },
            ),
            SelectItem::Expr {
                expr: Expr::RankOver { order_by },
                alias,
            } => self.bind_ranking_window_projection(
                table,
                "rank",
                order_by,
                alias,
                ProjectionOutputs {
                    projection,
                    columns,
                },
                |order_by| Expr::RankOver { order_by },
            ),
            SelectItem::Expr {
                expr: Expr::DenseRankOver { order_by },
                alias,
            } => self.bind_ranking_window_projection(
                table,
                "dense_rank",
                order_by,
                alias,
                ProjectionOutputs {
                    projection,
                    columns,
                },
                |order_by| Expr::DenseRankOver { order_by },
            ),
            SelectItem::Expr { expr, alias } => self.bind_general_select_projection(
                table,
                expr,
                alias,
                role_id,
                ProjectionOutputs {
                    projection,
                    columns,
                },
            ),
        }
    }

    fn bind_table_wildcard_projection(
        &self,
        table: &Table,
        mut outputs: ProjectionOutputs<'_>,
    ) -> Result<()> {
        for column in table.columns() {
            let generated = column
                .generated_expr()
                .map(|expr| {
                    parse_expr(expr).map(|expr| crate::ast::GeneratedColumn {
                        expr,
                        stored: column.generated_stored(),
                    })
                })
                .transpose()?;
            let bound_column = BoundColumn {
                name: column.name().to_string(),
                data_type: column.data_type().clone(),
                nullable: column.nullable(),
                encrypted: column.is_encrypted(),
                generated,
            };
            push_select_projection(
                &mut outputs,
                bound_column,
                Expr::Identifier(Ident::new(column.name())),
            );
        }
        Ok(())
    }

    fn bind_table_identifier_projection(
        &self,
        table: &Table,
        identifier: &Ident,
        alias: &Option<Ident>,
        mut outputs: ProjectionOutputs<'_>,
    ) -> Result<()> {
        let column = self.resolve_column(table, identifier.as_str())?;
        let column = aliased_bound_column(column, alias);
        push_select_projection(&mut outputs, column, Expr::Identifier(identifier.clone()));
        Ok(())
    }

    fn bind_table_qualified_projection(
        &self,
        table: &Table,
        qualifier: &Ident,
        name: &Ident,
        alias: &Option<Ident>,
        mut outputs: ProjectionOutputs<'_>,
    ) -> Result<()> {
        self.ensure_table_qualifier(table, qualifier)?;
        let column = self.resolve_column(table, name.as_str())?;
        let column = aliased_bound_column(column, alias);
        push_select_projection(&mut outputs, column, Expr::Identifier(name.clone()));
        Ok(())
    }

    fn bind_count_projection(
        &self,
        table: &Table,
        expr: &Expr,
        alias: &Option<Ident>,
        distinct: bool,
        mut outputs: ProjectionOutputs<'_>,
    ) -> Result<()> {
        let expr = self.rewrite_table_qualified_expr(table, expr)?;
        let aggregate_name = if distinct { "COUNT DISTINCT" } else { "COUNT" };
        let _ = self.infer_expr_type(table, &expr)?.ok_or_else(|| {
            RnovError::new(
                ErrorKind::InvalidInput,
                format!("cannot infer {aggregate_name} expression type: {expr}"),
            )
        })?;
        let column = aggregate_bound_column(outputs.columns, "count", SqlType::Int64, false);
        let column = aliased_bound_column(column, alias);
        let expr = if distinct {
            Expr::CountDistinct(Box::new(expr))
        } else {
            Expr::Count(Box::new(expr))
        };
        push_select_projection(&mut outputs, column, expr);
        Ok(())
    }

    fn bind_sum_projection(
        &self,
        table: &Table,
        expr: &Expr,
        alias: &Option<Ident>,
        mut outputs: ProjectionOutputs<'_>,
    ) -> Result<()> {
        let expr = self.rewrite_table_qualified_expr(table, expr)?;
        let expr_type = self.infer_expr_type(table, &expr)?.ok_or_else(|| {
            RnovError::new(
                ErrorKind::InvalidInput,
                format!("cannot infer SUM expression type: {expr}"),
            )
        })?;
        if expr_type != SqlType::Int64 && expr_type != SqlType::Null {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("SUM expression must be INT64, got {expr_type:?}"),
            ));
        }
        let column = aggregate_bound_column(outputs.columns, "sum", SqlType::Int64, true);
        let column = aliased_bound_column(column, alias);
        push_select_projection(&mut outputs, column, Expr::Sum(Box::new(expr)));
        Ok(())
    }

    fn bind_ordered_aggregate_projection(
        &self,
        table: &Table,
        expr: &Expr,
        alias: &Option<Ident>,
        aggregate_name: &'static str,
        mut outputs: ProjectionOutputs<'_>,
    ) -> Result<()> {
        let expr = self.rewrite_table_qualified_expr(table, expr)?;
        let expr_type = self.infer_expr_type(table, &expr)?.ok_or_else(|| {
            RnovError::new(
                ErrorKind::InvalidInput,
                format!("cannot infer {aggregate_name} expression type: {expr}"),
            )
        })?;
        self.ensure_ordered_aggregate_type(aggregate_name, &expr_type)?;
        let (column_name, expr) = match aggregate_name {
            "MIN" => ("min", Expr::Min(Box::new(expr))),
            "MAX" => ("max", Expr::Max(Box::new(expr))),
            _ => unreachable!("ordered aggregate binding supports MIN and MAX"),
        };
        let column = aggregate_bound_column(outputs.columns, column_name, expr_type, true);
        let column = aliased_bound_column(column, alias);
        push_select_projection(&mut outputs, column, expr);
        Ok(())
    }

    fn bind_general_select_projection(
        &self,
        table: &Table,
        expr: &Expr,
        alias: &Option<Ident>,
        role_id: RoleId,
        mut outputs: ProjectionOutputs<'_>,
    ) -> Result<()> {
        let expr = self.rewrite_table_qualified_expr(table, expr)?;
        let mut infer = |candidate: &Expr| self.infer_expr_type(table, candidate);
        let expr = self.bind_predicate_subqueries(
            &expr,
            role_id,
            &mut infer,
            Some(OuterQueryScope::Table(table)),
        )?;
        let data_type = self.infer_expr_type(table, &expr)?.ok_or_else(|| {
            RnovError::new(
                ErrorKind::InvalidInput,
                format!("cannot infer select expression type: {expr}"),
            )
        })?;
        let column = BoundColumn {
            name: format!("expr{}", outputs.columns.len() + 1),
            data_type,
            nullable: true,
            encrypted: false,
            generated: None,
        };
        let column = aliased_bound_column(column, alias);
        push_select_projection(&mut outputs, column, expr);
        Ok(())
    }

    fn finish_table_select(
        &self,
        input: SelectInput<'_>,
        outer_scope: Option<OuterQueryScope<'_>>,
        table: &Table,
        mut projection: Vec<BoundSelectItem>,
        mut columns: Vec<BoundColumn>,
    ) -> Result<BoundStatement> {
        let grouping = self.bind_select_grouping(
            table,
            input.group_by,
            input.grouping_sets,
            ProjectionOutputs {
                projection: &mut projection,
                columns: &mut columns,
            },
        )?;
        let mut having_outputs = self.bind_select_having(
            table,
            &projection,
            &grouping,
            input.having.as_ref(),
            input.role_id,
        )?;
        let selection =
            self.bind_select_selection(table, input.selection, input.role_id, outer_scope)?;
        let bound_order_by = self.bind_select_order_by(
            input.order_by,
            SelectSortContext {
                table,
                projection: &projection,
                group_by: &grouping.group_by,
                grouped: grouping.grouped,
                aggregate_count: grouping.aggregate_count,
                role_id: input.role_id,
            },
            &mut having_outputs.hidden_aggregates,
        )?;

        Ok(BoundStatement::Select(BoundSelect {
            relation_id: table.relation_id(),
            table: input.from.clone(),
            lateral_join: None,
            distinct: input.distinct,
            projection,
            hidden_group_keys: having_outputs.hidden_group_keys,
            hidden_aggregates: having_outputs.hidden_aggregates,
            columns,
            selection,
            group_by: grouping.group_by,
            grouping_sets: grouping.grouping_sets,
            having: having_outputs.having,
            order_by: bound_order_by,
            limit: input.limit,
            offset: input.offset,
            applied_row_policies: self.applied_row_policy_names(input.role_id, table.relation_id()),
            row_policy_predicates: self.bind_row_policies(input.role_id, table)?,
        }))
    }

    fn bind_select_grouping(
        &self,
        table: &Table,
        group_by: &[Expr],
        grouping_sets: &[Vec<Expr>],
        outputs: ProjectionOutputs<'_>,
    ) -> Result<SelectGrouping> {
        let aggregate_count = outputs
            .projection
            .iter()
            .filter(|item| is_aggregate_expr(&item.expr))
            .count();
        let (group_by, grouping_sets) =
            self.bind_grouping_expressions(table, outputs.projection, group_by, grouping_sets)?;
        if !grouping_sets.is_empty() {
            mark_grouping_set_projection_columns_nullable(
                outputs.projection,
                outputs.columns,
                &group_by,
            );
        }
        let grouped = !group_by.is_empty() || !grouping_sets.is_empty();
        self.validate_select_grouping_projection(
            outputs.projection,
            &group_by,
            grouped,
            aggregate_count,
        )?;
        Ok(SelectGrouping {
            group_by,
            grouping_sets,
            grouped,
            aggregate_count,
        })
    }

    fn bind_grouping_expressions(
        &self,
        table: &Table,
        projection: &[BoundSelectItem],
        group_by: &[Expr],
        grouping_sets: &[Vec<Expr>],
    ) -> Result<(Vec<Expr>, Vec<Vec<Expr>>)> {
        let group_by = self.bind_group_by_exprs(table, projection, group_by)?;
        let grouping_sets = self.bind_grouping_sets(table, projection, grouping_sets)?;
        if !group_by.is_empty() {
            self.validate_group_by_exprs(table, &group_by)?;
        }
        for grouping_set in &grouping_sets {
            self.validate_group_by_exprs(table, grouping_set)?;
        }
        Ok((group_by, grouping_sets))
    }

    fn validate_select_grouping_projection(
        &self,
        projection: &[BoundSelectItem],
        group_by: &[Expr],
        grouped: bool,
        aggregate_count: usize,
    ) -> Result<()> {
        if aggregate_count > 0 && aggregate_count != projection.len() {
            self.validate_grouped_projection(projection, group_by)?;
        }
        if aggregate_count == 0 && grouped {
            self.validate_grouped_projection(projection, group_by)?;
        }
        Ok(())
    }

    fn bind_select_having(
        &self,
        table: &Table,
        projection: &[BoundSelectItem],
        grouping: &SelectGrouping,
        having: Option<&Expr>,
        role_id: RoleId,
    ) -> Result<SelectHavingOutputs> {
        let Some(having) = having else {
            return Ok(SelectHavingOutputs::default());
        };
        if !grouping.grouped && grouping.aggregate_count == 0 {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "HAVING requires GROUP BY or aggregate projection in this SQL slice",
            ));
        }
        let mut outputs = SelectHavingOutputs::default();
        let having = self.rewrite_grouped_having_expr(
            table,
            projection,
            &grouping.group_by,
            &mut outputs.hidden_group_keys,
            &mut outputs.hidden_aggregates,
            having,
        )?;
        let mut grouped_outputs = projection.to_vec();
        grouped_outputs.extend(outputs.hidden_group_keys.iter().cloned());
        grouped_outputs.extend(outputs.hidden_aggregates.iter().cloned());
        let mut infer =
            |candidate: &Expr| self.infer_grouped_output_expr_type(&grouped_outputs, candidate);
        let having = self.bind_predicate_subqueries(&having, role_id, &mut infer, None)?;
        self.validate_grouped_having_expr(&grouped_outputs, &having)?;
        outputs.having = Some(having);
        Ok(outputs)
    }

    fn bind_select_order_by(
        &self,
        order_by: &[OrderByExpr],
        context: SelectSortContext<'_>,
        hidden_aggregates: &mut Vec<BoundSelectItem>,
    ) -> Result<Vec<OrderByExpr>> {
        let mut bound_order_by = Vec::with_capacity(order_by.len());
        for order_by in order_by {
            bound_order_by.push(self.bind_select_order_item(
                order_by,
                &context,
                hidden_aggregates,
            )?);
        }
        Ok(bound_order_by)
    }

    fn bind_select_order_item(
        &self,
        order_by: &OrderByExpr,
        context: &SelectSortContext<'_>,
        hidden_aggregates: &mut Vec<BoundSelectItem>,
    ) -> Result<OrderByExpr> {
        let order_by = OrderByExpr {
            expr: self.rewrite_table_qualified_expr(context.table, &order_by.expr)?,
            direction: order_by.direction,
        };
        if context.grouped || context.aggregate_count > 0 {
            return self.bind_grouped_sort_expr(
                context.table,
                context.projection,
                hidden_aggregates,
                context.group_by,
                &order_by,
                context.role_id,
            );
        }
        self.bind_plain_sort_expr(
            context.table,
            context.projection,
            &order_by,
            context.role_id,
        )
    }

    fn bind_select_from_columns(
        &self,
        statement: &Statement,
        source: &ObjectName,
        available_columns: &[BoundColumn],
    ) -> Result<BoundSelect> {
        let input = recursive_cte_select_input(statement, source)?;
        let (projection, columns) =
            self.bind_cte_projection(input.projection, available_columns)?;
        let selection = self.bind_cte_selection(input.selection, available_columns)?;
        let order_by = self.bind_cte_order_by(input.order_by, available_columns)?;

        Ok(BoundSelect {
            relation_id: recursive_cte_relation_id(source),
            table: input.from.clone(),
            lateral_join: None,
            distinct: input.distinct,
            projection,
            hidden_group_keys: Vec::new(),
            hidden_aggregates: Vec::new(),
            columns,
            selection,
            group_by: Vec::new(),
            grouping_sets: Vec::new(),
            having: None,
            order_by,
            limit: input.limit,
            offset: input.offset,
            applied_row_policies: Vec::new(),
            row_policy_predicates: Vec::new(),
        })
    }

    fn bind_cte_selection(
        &self,
        selection: &Option<Expr>,
        available_columns: &[BoundColumn],
    ) -> Result<Option<Expr>> {
        let Some(selection) = selection else {
            return Ok(None);
        };
        let selection = self.rewrite_cte_expr(available_columns, selection)?;
        self.validate_predicate_from_columns(available_columns, &selection)?;
        Ok(Some(selection))
    }

    fn bind_cte_order_by(
        &self,
        order_by: &[OrderByExpr],
        available_columns: &[BoundColumn],
    ) -> Result<Vec<OrderByExpr>> {
        order_by
            .iter()
            .map(|order_by| {
                let expr = self.rewrite_cte_expr(available_columns, &order_by.expr)?;
                self.validate_sort_expr_from_columns(available_columns, &expr)?;
                Ok(OrderByExpr {
                    expr,
                    direction: order_by.direction,
                })
            })
            .collect()
    }

    fn bind_cte_projection(
        &self,
        select_items: &[SelectItem],
        available_columns: &[BoundColumn],
    ) -> Result<(Vec<BoundSelectItem>, Vec<BoundColumn>)> {
        let mut projection = Vec::new();
        let mut columns = Vec::new();
        for item in select_items {
            self.bind_cte_projection_item(item, available_columns, &mut projection, &mut columns)?;
        }
        Ok((projection, columns))
    }

    fn bind_cte_projection_item(
        &self,
        item: &SelectItem,
        available_columns: &[BoundColumn],
        projection: &mut Vec<BoundSelectItem>,
        columns: &mut Vec<BoundColumn>,
    ) -> Result<()> {
        match item {
            SelectItem::Wildcard => {
                bind_cte_wildcard(available_columns, projection, columns);
                Ok(())
            }
            SelectItem::Expr {
                expr: Expr::Identifier(identifier),
                alias,
            } => {
                self.bind_cte_identifier(identifier, alias, available_columns, projection, columns)
            }
            SelectItem::Expr {
                expr: qualified @ Expr::QualifiedIdentifier { .. },
                alias,
            } => self.bind_cte_qualified_identifier(
                qualified,
                alias,
                available_columns,
                projection,
                columns,
            ),
            SelectItem::Expr { expr, alias } => {
                self.bind_cte_expression(expr, alias, available_columns, projection, columns)
            }
        }
    }

    fn bind_cte_identifier(
        &self,
        identifier: &Ident,
        alias: &Option<Ident>,
        available_columns: &[BoundColumn],
        projection: &mut Vec<BoundSelectItem>,
        columns: &mut Vec<BoundColumn>,
    ) -> Result<()> {
        let column = self.resolve_column_from_bound(available_columns, identifier)?;
        let column = aliased_bound_column(column, alias);
        push_cte_projection(
            projection,
            columns,
            column,
            Expr::Identifier(identifier.clone()),
        );
        Ok(())
    }

    fn bind_cte_qualified_identifier(
        &self,
        qualified: &Expr,
        alias: &Option<Ident>,
        available_columns: &[BoundColumn],
        projection: &mut Vec<BoundSelectItem>,
        columns: &mut Vec<BoundColumn>,
    ) -> Result<()> {
        let expr = self.rewrite_cte_expr(available_columns, qualified)?;
        let Expr::Identifier(name) = expr else {
            return Err(RnovError::new(
                ErrorKind::Internal,
                "qualified recursive CTE column did not rewrite to identifier",
            ));
        };
        let column = self.resolve_column_from_bound(available_columns, &name)?;
        let column = aliased_bound_column(column, alias);
        push_cte_projection(projection, columns, column, Expr::Identifier(name));
        Ok(())
    }

    fn bind_cte_expression(
        &self,
        expr: &Expr,
        alias: &Option<Ident>,
        available_columns: &[BoundColumn],
        projection: &mut Vec<BoundSelectItem>,
        columns: &mut Vec<BoundColumn>,
    ) -> Result<()> {
        let expr = self.rewrite_cte_expr(available_columns, expr)?;
        let data_type = self
            .infer_expr_type_from_columns(available_columns, &expr)?
            .ok_or_else(|| {
                RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("cannot infer recursive CTE expression type: {expr}"),
                )
            })?;
        let column = BoundColumn {
            name: format!("expr{}", columns.len() + 1),
            data_type,
            nullable: true,
            encrypted: false,
            generated: None,
        };
        let column = aliased_bound_column(column, alias);
        push_cte_projection(projection, columns, column, expr);
        Ok(())
    }

    fn bind_lateral_select(
        &self,
        input: &SelectInput<'_>,
        outer_table: &Table,
        lateral_join: &LateralJoin,
    ) -> Result<BoundStatement> {
        let context = self.bind_lateral_context(input, outer_table, lateral_join)?;
        let (projection, columns) = self.bind_lateral_projection(
            input.select_items,
            &context.lateral_columns,
            &context.bound_columns,
        )?;
        let selection = self.bind_lateral_selection(
            input.selection,
            &context.lateral_columns,
            &context.bound_columns,
            input.role_id,
        )?;
        let bound_order_by = self.bind_lateral_order_by(
            input.order_by,
            &context.lateral_columns,
            &context.bound_columns,
            &projection,
            input.role_id,
        )?;

        Ok(BoundStatement::Select(BoundSelect {
            relation_id: outer_table.relation_id(),
            table: input.from.clone(),
            lateral_join: Some(BoundLateralJoin {
                inner_relation_id: context.inner_table.relation_id(),
                inner_table: lateral_join.table.clone(),
                inner_column: context.inner_column,
                outer_column: context.outer_column,
            }),
            distinct: input.distinct,
            projection,
            hidden_group_keys: Vec::new(),
            hidden_aggregates: Vec::new(),
            columns,
            selection,
            group_by: Vec::new(),
            grouping_sets: Vec::new(),
            having: None,
            order_by: bound_order_by,
            limit: input.limit,
            offset: input.offset,
            applied_row_policies: self
                .applied_row_policy_names(input.role_id, outer_table.relation_id()),
            row_policy_predicates: self.bind_row_policies(input.role_id, outer_table)?,
        }))
    }

    fn bind_lateral_context<'b>(
        &'b self,
        input: &SelectInput<'_>,
        outer_table: &Table,
        lateral_join: &LateralJoin,
    ) -> Result<LateralBindingContext<'b>> {
        self.validate_lateral_select_shape(input)?;
        let inner_table = self.resolve_lateral_inner_table(input.role_id, lateral_join)?;
        let lateral_columns = lateral_join_columns(outer_table, inner_table)?;
        let bound_columns = lateral_columns_to_bound(&lateral_columns);
        let (inner_column, outer_column) = self.bind_lateral_equality(
            outer_table,
            input.from,
            inner_table,
            &lateral_join.table,
            &lateral_join.on,
        )?;
        Ok(LateralBindingContext {
            inner_table,
            lateral_columns,
            bound_columns,
            inner_column,
            outer_column,
        })
    }

    fn validate_lateral_select_shape(&self, input: &SelectInput<'_>) -> Result<()> {
        if !input.group_by.is_empty() || input.having.is_some() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "JOIN LATERAL does not support GROUP BY or HAVING in this SQL slice",
            ));
        }
        Ok(())
    }

    fn resolve_lateral_inner_table<'b>(
        &'b self,
        role_id: RoleId,
        lateral_join: &LateralJoin,
    ) -> Result<&'b Table> {
        let inner_table = self.resolve_table(&lateral_join.table)?;
        self.require_table_privilege(role_id, inner_table.relation_id(), Privilege::Select)?;
        if !self.bind_row_policies(role_id, inner_table)?.is_empty() {
            return Err(RnovError::new(
                ErrorKind::Security,
                "JOIN LATERAL does not support row policies on the inner table",
            ));
        }
        Ok(inner_table)
    }

    fn bind_lateral_projection(
        &self,
        select_items: &[SelectItem],
        lateral_columns: &[LateralColumn],
        bound_columns: &[BoundColumn],
    ) -> Result<(Vec<BoundSelectItem>, Vec<BoundColumn>)> {
        let mut projection = Vec::new();
        let mut columns = Vec::new();
        for item in select_items {
            self.bind_lateral_projection_item(
                item,
                lateral_columns,
                bound_columns,
                &mut projection,
                &mut columns,
            )?;
        }
        Ok((projection, columns))
    }

    fn bind_lateral_projection_item(
        &self,
        item: &SelectItem,
        lateral_columns: &[LateralColumn],
        bound_columns: &[BoundColumn],
        projection: &mut Vec<BoundSelectItem>,
        columns: &mut Vec<BoundColumn>,
    ) -> Result<()> {
        match item {
            SelectItem::Wildcard => {
                push_lateral_wildcard(lateral_columns, projection, columns);
                Ok(())
            }
            SelectItem::Expr { expr, alias } => self.bind_lateral_projection_expr(
                expr,
                alias,
                lateral_columns,
                bound_columns,
                projection,
                columns,
            ),
        }
    }

    fn bind_lateral_projection_expr(
        &self,
        expr: &Expr,
        alias: &Option<Ident>,
        lateral_columns: &[LateralColumn],
        bound_columns: &[BoundColumn],
        projection: &mut Vec<BoundSelectItem>,
        columns: &mut Vec<BoundColumn>,
    ) -> Result<()> {
        let expr = self.rewrite_lateral_expr(lateral_columns, expr)?;
        let data_type = self
            .infer_expr_type_from_columns(bound_columns, &expr)?
            .ok_or_else(|| {
                RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("cannot infer select expression type: {expr}"),
                )
            })?;
        let column = lateral_projection_column(lateral_columns, columns.len(), &expr, data_type);
        let column = aliased_bound_column(column, alias);
        projection.push(BoundSelectItem {
            column: column.clone(),
            expr,
        });
        columns.push(column);
        Ok(())
    }

    fn bind_lateral_selection(
        &self,
        selection: &Option<Expr>,
        lateral_columns: &[LateralColumn],
        bound_columns: &[BoundColumn],
        role_id: RoleId,
    ) -> Result<Option<Expr>> {
        let selection = selection
            .as_ref()
            .map(|selection| self.rewrite_lateral_expr(lateral_columns, selection))
            .transpose()?;
        self.bind_columns_selection(selection.as_ref(), bound_columns, role_id)
    }

    fn bind_lateral_order_by(
        &self,
        order_by: &[OrderByExpr],
        lateral_columns: &[LateralColumn],
        bound_columns: &[BoundColumn],
        projection: &[BoundSelectItem],
        role_id: RoleId,
    ) -> Result<Vec<OrderByExpr>> {
        let mut bound_order_by = Vec::with_capacity(order_by.len());
        for order_by in order_by {
            let order_by = OrderByExpr {
                expr: self.rewrite_lateral_expr(lateral_columns, &order_by.expr)?,
                direction: order_by.direction,
            };
            bound_order_by.push(self.bind_plain_output_sort_expr(
                bound_columns,
                projection,
                &order_by,
                role_id,
            )?);
        }
        Ok(bound_order_by)
    }

    fn bind_join_select(
        &self,
        input: &SelectInput<'_>,
        left_table: &Table,
        join: &JoinClause,
    ) -> Result<BoundStatement> {
        let context = self.bind_join_context(input, left_table, join)?;
        let (predicate, hash_keys) = self.bind_join_on_predicate(
            join,
            &context.joined_columns,
            &context.bound_columns,
            input.role_id,
        )?;
        let (projection, columns) = self.bind_join_projection(
            input.select_items,
            &context.joined_columns,
            &context.bound_columns,
            input.role_id,
        )?;
        let selection = self.bind_join_selection(
            input.selection,
            &context.joined_columns,
            &context.bound_columns,
            input.role_id,
        )?;
        let order_by = self.bind_join_order_by(
            input.order_by,
            &context.joined_columns,
            &context.bound_columns,
            &projection,
            input.role_id,
        )?;

        let select = BoundSelect {
            relation_id: left_table.relation_id(),
            table: input.from.clone(),
            lateral_join: None,
            distinct: input.distinct,
            projection,
            hidden_group_keys: Vec::new(),
            hidden_aggregates: Vec::new(),
            columns,
            selection,
            group_by: Vec::new(),
            grouping_sets: Vec::new(),
            having: None,
            order_by,
            limit: input.limit,
            offset: input.offset,
            applied_row_policies: self
                .applied_row_policy_names(input.role_id, left_table.relation_id()),
            row_policy_predicates: self.bind_row_policies(input.role_id, left_table)?,
        };
        Ok(BoundStatement::SelectJoin(BoundJoinSelect {
            select,
            join: BoundJoin {
                kind: join.kind,
                right_relation_id: context.right_table.relation_id(),
                right_table: join.table.clone(),
                predicate,
                hash_keys,
                applied_row_policies: self
                    .applied_row_policy_names(input.role_id, context.right_table.relation_id()),
                row_policy_predicates: self
                    .bind_row_policies(input.role_id, context.right_table)?,
            },
        }))
    }

    fn bind_join_context<'b>(
        &'b self,
        input: &SelectInput<'_>,
        left_table: &Table,
        join: &JoinClause,
    ) -> Result<JoinBindingContext<'b>> {
        self.validate_join_select_shape(input)?;
        let right_table = self.resolve_table(&join.table)?;
        self.require_table_privilege(input.role_id, right_table.relation_id(), Privilege::Select)?;
        let joined_columns = join_clause_columns(left_table, right_table, join.kind)?;
        let bound_columns = lateral_columns_to_bound(&joined_columns);
        Ok(JoinBindingContext {
            right_table,
            joined_columns,
            bound_columns,
        })
    }

    fn bind_join_on_predicate(
        &self,
        join: &JoinClause,
        joined_columns: &[LateralColumn],
        bound_columns: &[BoundColumn],
        role_id: RoleId,
    ) -> Result<(Expr, Option<BoundHashJoinKeys>)> {
        let hash_keys = hash_join_keys(joined_columns, &join.on);
        let predicate = self.rewrite_lateral_expr(joined_columns, &join.on)?;
        let predicate = self.bind_join_predicate_subqueries(
            joined_columns,
            bound_columns,
            &predicate,
            role_id,
        )?;
        self.validate_predicate_from_columns(bound_columns, &predicate)?;
        Ok((predicate, hash_keys))
    }

    fn validate_join_select_shape(&self, input: &SelectInput<'_>) -> Result<()> {
        if input.group_by.is_empty() && input.grouping_sets.is_empty() && input.having.is_none() {
            return Ok(());
        }
        Err(RnovError::new(
            ErrorKind::InvalidInput,
            "JOIN does not support GROUP BY, GROUPING SETS, or HAVING in this SQL slice",
        ))
    }

    fn bind_join_projection(
        &self,
        select_items: &[SelectItem],
        joined_columns: &[LateralColumn],
        bound_columns: &[BoundColumn],
        role_id: RoleId,
    ) -> Result<(Vec<BoundSelectItem>, Vec<BoundColumn>)> {
        let mut projection = Vec::new();
        let mut columns = Vec::new();
        for item in select_items {
            self.push_join_projection_item(
                item,
                joined_columns,
                bound_columns,
                role_id,
                &mut projection,
                &mut columns,
            )?;
        }
        Ok((projection, columns))
    }

    fn push_join_projection_item(
        &self,
        item: &SelectItem,
        joined_columns: &[LateralColumn],
        bound_columns: &[BoundColumn],
        role_id: RoleId,
        projection: &mut Vec<BoundSelectItem>,
        columns: &mut Vec<BoundColumn>,
    ) -> Result<()> {
        match item {
            SelectItem::Wildcard => self.push_join_wildcard(joined_columns, projection, columns),
            SelectItem::Expr { expr, alias } => {
                let expr = self.rewrite_lateral_expr(joined_columns, expr)?;
                let mut infer =
                    |candidate: &Expr| self.infer_expr_type_from_columns(bound_columns, candidate);
                let expr = self.bind_predicate_subqueries(&expr, role_id, &mut infer, None)?;
                let column = self.join_projection_column(
                    joined_columns,
                    bound_columns,
                    columns,
                    &expr,
                    alias,
                )?;
                projection.push(BoundSelectItem {
                    column: column.clone(),
                    expr,
                });
                columns.push(column);
                Ok(())
            }
        }
    }

    fn push_join_wildcard(
        &self,
        joined_columns: &[LateralColumn],
        projection: &mut Vec<BoundSelectItem>,
        columns: &mut Vec<BoundColumn>,
    ) -> Result<()> {
        for joined_column in joined_columns {
            projection.push(BoundSelectItem {
                column: joined_column.column.clone(),
                expr: Expr::Identifier(Ident::new(joined_column.output_name.as_str())),
            });
            columns.push(joined_column.column.clone());
        }
        Ok(())
    }

    fn join_projection_column(
        &self,
        joined_columns: &[LateralColumn],
        bound_columns: &[BoundColumn],
        columns: &[BoundColumn],
        expr: &Expr,
        alias: &Option<Ident>,
    ) -> Result<BoundColumn> {
        let data_type = self
            .infer_expr_type_from_columns(bound_columns, expr)?
            .ok_or_else(|| {
                RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("cannot infer select expression type: {expr}"),
                )
            })?;
        let column = join_expr_column(joined_columns, columns, expr, data_type);
        Ok(aliased_bound_column(column, alias))
    }

    fn bind_join_selection(
        &self,
        selection: &Option<Expr>,
        joined_columns: &[LateralColumn],
        bound_columns: &[BoundColumn],
        role_id: RoleId,
    ) -> Result<Option<Expr>> {
        let selection = selection
            .as_ref()
            .map(|selection| self.rewrite_lateral_expr(joined_columns, selection))
            .transpose()?;
        self.bind_columns_selection(selection.as_ref(), bound_columns, role_id)
    }

    fn bind_join_predicate_subqueries(
        &self,
        joined_columns: &[LateralColumn],
        bound_columns: &[BoundColumn],
        expr: &Expr,
        role_id: RoleId,
    ) -> Result<Expr> {
        let mut infer =
            |candidate: &Expr| self.infer_expr_type_from_columns(bound_columns, candidate);
        self.bind_predicate_subqueries(
            expr,
            role_id,
            &mut infer,
            Some(OuterQueryScope::Columns(joined_columns)),
        )
    }

    fn bind_join_order_by(
        &self,
        order_by: &[OrderByExpr],
        joined_columns: &[LateralColumn],
        bound_columns: &[BoundColumn],
        projection: &[BoundSelectItem],
        role_id: RoleId,
    ) -> Result<Vec<OrderByExpr>> {
        order_by
            .iter()
            .map(|order_by| {
                let order_by = OrderByExpr {
                    expr: self.rewrite_lateral_expr(joined_columns, &order_by.expr)?,
                    direction: order_by.direction,
                };
                self.bind_plain_output_sort_expr(bound_columns, projection, &order_by, role_id)
            })
            .collect()
    }

    fn validate_predicate(&self, table: &Table, expr: &Expr) -> Result<()> {
        match self.infer_expr_type(table, expr)? {
            Some(SqlType::Bool | SqlType::Null) => Ok(()),
            Some(other) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("predicate must be bool, got {other:?}"),
            )),
            None => Ok(()),
        }
    }

    fn validate_predicate_with_outer(
        &self,
        table: &Table,
        expr: &Expr,
        outer_scope: Option<OuterQueryScope<'_>>,
    ) -> Result<()> {
        let expr = self.replace_outer_refs_for_type_validation(expr, outer_scope)?;
        self.validate_predicate(table, &expr)
    }

    fn validate_predicate_from_columns(&self, columns: &[BoundColumn], expr: &Expr) -> Result<()> {
        match self.infer_expr_type_from_columns(columns, expr)? {
            Some(SqlType::Bool | SqlType::Null) => Ok(()),
            Some(other) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("predicate must be bool, got {other:?}"),
            )),
            None => Ok(()),
        }
    }

    fn bind_select_selection(
        &self,
        table: &Table,
        selection: &Option<Expr>,
        role_id: RoleId,
        outer_scope: Option<OuterQueryScope<'_>>,
    ) -> Result<Option<Expr>> {
        let Some(selection) = selection else {
            return Ok(None);
        };
        let selection =
            self.rewrite_table_qualified_expr_with_outer(table, selection, outer_scope)?;
        let selection = self.bind_table_subqueries(table, &selection, role_id)?;
        self.validate_predicate_with_outer(table, &selection, outer_scope)?;
        Ok(Some(selection))
    }

    fn bind_columns_selection(
        &self,
        selection: Option<&Expr>,
        columns: &[BoundColumn],
        role_id: RoleId,
    ) -> Result<Option<Expr>> {
        let Some(selection) = selection else {
            return Ok(None);
        };
        let selection = self.bind_column_subqueries(columns, selection, role_id)?;
        self.validate_predicate_from_columns(columns, &selection)?;
        Ok(Some(selection))
    }

    fn bind_table_subqueries(&self, table: &Table, expr: &Expr, role_id: RoleId) -> Result<Expr> {
        let mut infer = |candidate: &Expr| self.infer_expr_type(table, candidate);
        self.bind_predicate_subqueries(
            expr,
            role_id,
            &mut infer,
            Some(OuterQueryScope::Table(table)),
        )
    }

    fn bind_column_subqueries(
        &self,
        columns: &[BoundColumn],
        expr: &Expr,
        role_id: RoleId,
    ) -> Result<Expr> {
        let mut infer = |candidate: &Expr| self.infer_expr_type_from_columns(columns, candidate);
        self.bind_predicate_subqueries(expr, role_id, &mut infer, None)
    }

    fn bind_predicate_subqueries<F>(
        &self,
        expr: &Expr,
        role_id: RoleId,
        infer: &mut F,
        subquery_outer_scope: Option<OuterQueryScope<'_>>,
    ) -> Result<Expr>
    where
        F: FnMut(&Expr) -> Result<Option<SqlType>>,
    {
        crate::rewrite_expr_tree(expr, &mut |candidate| match candidate {
            Expr::InSubquery {
                expr,
                query,
                negated,
            } => self
                .bind_in_subquery_expr(expr, query, *negated, role_id, infer, subquery_outer_scope)
                .map(Some),
            Expr::ExistsSubquery { query } => self
                .bind_exists_subquery_expr(query, role_id, subquery_outer_scope)
                .map(Some),
            Expr::ScalarSubquery { query } => self
                .bind_scalar_subquery_expr(query, role_id, subquery_outer_scope)
                .map(Some),
            _ => Ok(None),
        })
    }

    fn bind_in_subquery_expr<F>(
        &self,
        expr: &Expr,
        query: &SelectSubquery,
        negated: bool,
        role_id: RoleId,
        infer: &mut F,
        outer_scope: Option<OuterQueryScope<'_>>,
    ) -> Result<Expr>
    where
        F: FnMut(&Expr) -> Result<Option<SqlType>>,
    {
        let expr = self.bind_predicate_subqueries(expr, role_id, infer, None)?;
        let bound = self.bind_in_subquery(query, role_id, outer_scope)?;
        self.validate_in_subquery_types(&expr, &bound, infer)?;
        Ok(Expr::InSubquery {
            expr: Box::new(expr),
            query: SelectSubquery::Bound(Box::new(bound)),
            negated,
        })
    }

    fn validate_in_subquery_types<F>(
        &self,
        expr: &Expr,
        bound: &BoundStatement,
        infer: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&Expr) -> Result<Option<SqlType>>,
    {
        let expr_type = infer(expr)?.ok_or_else(|| {
            RnovError::new(
                ErrorKind::InvalidInput,
                format!("cannot infer IN subquery expression type: {expr}"),
            )
        })?;
        let subquery_type = single_query_output_type(bound)?;
        self.infer_in_list_result_type(&expr_type, std::slice::from_ref(&subquery_type))?;
        Ok(())
    }

    fn bind_in_subquery(
        &self,
        query: &SelectSubquery,
        role_id: RoleId,
        outer_scope: Option<OuterQueryScope<'_>>,
    ) -> Result<BoundStatement> {
        match query {
            SelectSubquery::Parsed(statement) => {
                let bound = self.bind_for_role_with_outer(statement, role_id, outer_scope)?;
                let _ = single_query_output_type(&bound)?;
                Ok(bound)
            }
            SelectSubquery::Bound(statement) => Ok((**statement).clone()),
        }
    }

    fn bind_exists_subquery_expr(
        &self,
        query: &SelectSubquery,
        role_id: RoleId,
        outer_scope: Option<OuterQueryScope<'_>>,
    ) -> Result<Expr> {
        let bound = self.bind_exists_subquery(query, role_id, outer_scope)?;
        Ok(Expr::ExistsSubquery {
            query: SelectSubquery::Bound(Box::new(bound)),
        })
    }

    fn bind_exists_subquery(
        &self,
        query: &SelectSubquery,
        role_id: RoleId,
        outer_scope: Option<OuterQueryScope<'_>>,
    ) -> Result<BoundStatement> {
        match query {
            SelectSubquery::Parsed(statement) => {
                let bound = self.bind_for_role_with_outer(statement, role_id, outer_scope)?;
                let _ = query_output_columns(&bound)?;
                Ok(bound)
            }
            SelectSubquery::Bound(statement) => Ok((**statement).clone()),
        }
    }

    fn bind_scalar_subquery_expr(
        &self,
        query: &SelectSubquery,
        role_id: RoleId,
        outer_scope: Option<OuterQueryScope<'_>>,
    ) -> Result<Expr> {
        let (bound, data_type) = self.bind_scalar_subquery(query, role_id, outer_scope)?;
        Ok(Expr::Cast {
            expr: Box::new(Expr::ScalarSubquery {
                query: SelectSubquery::Bound(Box::new(bound)),
            }),
            data_type,
        })
    }

    fn bind_scalar_subquery(
        &self,
        query: &SelectSubquery,
        role_id: RoleId,
        outer_scope: Option<OuterQueryScope<'_>>,
    ) -> Result<(BoundStatement, SqlType)> {
        match query {
            SelectSubquery::Parsed(statement) => {
                let bound = self.bind_for_role_with_outer(statement, role_id, outer_scope)?;
                let data_type = single_query_output_type_for(&bound, "scalar subquery")?;
                Ok((bound, data_type))
            }
            SelectSubquery::Bound(statement) => {
                let statement = (**statement).clone();
                let data_type = single_query_output_type_for(&statement, "scalar subquery")?;
                Ok((statement, data_type))
            }
        }
    }

    fn infer_bound_predicate_subquery_type(
        &self,
        query: &SelectSubquery,
        context: &str,
    ) -> Result<Option<SqlType>> {
        if query.bound().is_some() {
            Ok(Some(SqlType::Bool))
        } else {
            Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("{context} is only supported after binding"),
            ))
        }
    }

    fn infer_bound_scalar_subquery_type(&self, query: &SelectSubquery) -> Result<Option<SqlType>> {
        let Some(bound) = query.bound() else {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "scalar subquery is only supported after binding",
            ));
        };
        single_query_output_type_for(bound, "scalar subquery").map(Some)
    }

    fn bind_ranking_window_projection(
        &self,
        table: &Table,
        function_name: &str,
        order_by: &[OrderByExpr],
        alias: &Option<Ident>,
        outputs: ProjectionOutputs<'_>,
        expr: impl FnOnce(Vec<OrderByExpr>) -> Expr,
    ) -> Result<()> {
        let order_by = self.bind_ranking_window_order_by(table, function_name, order_by)?;
        let column = aggregate_bound_column(outputs.columns, function_name, SqlType::Int64, false);
        let column = aliased_bound_column(column, alias);
        outputs.projection.push(BoundSelectItem {
            column: column.clone(),
            expr: expr(order_by),
        });
        outputs.columns.push(column);
        Ok(())
    }

    fn bind_ranking_window_order_by(
        &self,
        table: &Table,
        function_name: &str,
        order_by: &[OrderByExpr],
    ) -> Result<Vec<OrderByExpr>> {
        let order_by = order_by
            .iter()
            .map(|order_by| {
                Ok(OrderByExpr {
                    expr: self.rewrite_table_qualified_expr(table, &order_by.expr)?,
                    direction: order_by.direction,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if order_by.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("{function_name}() OVER requires ORDER BY"),
            ));
        }
        for order_by in &order_by {
            let Some(data_type) = self.infer_expr_type(table, &order_by.expr)? else {
                continue;
            };
            self.ensure_sortable_type(&data_type)?;
        }
        Ok(order_by)
    }

    fn validate_sort_expr(&self, table: &Table, expr: &Expr) -> Result<()> {
        match self.infer_expr_type(table, expr)? {
            Some(
                SqlType::Null
                | SqlType::Bool
                | SqlType::Int64
                | SqlType::UInt64
                | SqlType::Float64
                | SqlType::Uuid
                | SqlType::Timestamp
                | SqlType::Text
                | SqlType::Bytes,
            ) => Ok(()),
            Some(other) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("ORDER BY expression type is not sortable: {other:?}"),
            )),
            None => Ok(()),
        }
    }

    fn validate_sort_expr_from_columns(&self, columns: &[BoundColumn], expr: &Expr) -> Result<()> {
        match self.infer_expr_type_from_columns(columns, expr)? {
            Some(
                SqlType::Null
                | SqlType::Bool
                | SqlType::Int64
                | SqlType::UInt64
                | SqlType::Float64
                | SqlType::Uuid
                | SqlType::Timestamp
                | SqlType::Text
                | SqlType::Bytes,
            ) => Ok(()),
            Some(other) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("ORDER BY expression type is not sortable: {other:?}"),
            )),
            None => Ok(()),
        }
    }

    fn bind_plain_output_sort_expr(
        &self,
        columns: &[BoundColumn],
        projection: &[BoundSelectItem],
        order_by: &OrderByExpr,
        role_id: RoleId,
    ) -> Result<OrderByExpr> {
        let expr = match &order_by.expr {
            Expr::Integer(value) => self
                .projection_ordinal_item(projection, *value, "ORDER BY")?
                .expr
                .clone(),
            Expr::Identifier(identifier) => projection
                .iter()
                .find(|item| item.column.name.eq_ignore_ascii_case(identifier.as_str()))
                .map(|item| item.expr.clone())
                .unwrap_or_else(|| order_by.expr.clone()),
            _ => order_by.expr.clone(),
        };
        let mut infer = |candidate: &Expr| self.infer_expr_type_from_columns(columns, candidate);
        let expr = self.bind_predicate_subqueries(&expr, role_id, &mut infer, None)?;
        match self.infer_expr_type_from_columns(columns, &expr)? {
            Some(
                SqlType::Null
                | SqlType::Bool
                | SqlType::Int64
                | SqlType::UInt64
                | SqlType::Float64
                | SqlType::Uuid
                | SqlType::Timestamp
                | SqlType::Text
                | SqlType::Bytes,
            )
            | None => Ok(OrderByExpr {
                expr,
                direction: order_by.direction,
            }),
            Some(other) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("ORDER BY expression type is not sortable: {other:?}"),
            )),
        }
    }

    fn bind_plain_sort_expr(
        &self,
        table: &Table,
        projection: &[BoundSelectItem],
        order_by: &OrderByExpr,
        role_id: RoleId,
    ) -> Result<OrderByExpr> {
        let expr = match &order_by.expr {
            Expr::Integer(value) => self
                .projection_ordinal_item(projection, *value, "ORDER BY")?
                .expr
                .clone(),
            Expr::Identifier(identifier) => projection
                .iter()
                .find(|item| item.column.name.eq_ignore_ascii_case(identifier.as_str()))
                .map(|item| item.expr.clone())
                .unwrap_or_else(|| order_by.expr.clone()),
            _ => order_by.expr.clone(),
        };
        let mut infer = |candidate: &Expr| self.infer_expr_type(table, candidate);
        let expr = self.bind_predicate_subqueries(
            &expr,
            role_id,
            &mut infer,
            Some(OuterQueryScope::Table(table)),
        )?;
        self.validate_sort_expr(table, &expr)?;
        Ok(OrderByExpr {
            expr,
            direction: order_by.direction,
        })
    }

    fn bind_query_output_order_by(
        &self,
        columns: &[BoundColumn],
        order_by: &[OrderByExpr],
    ) -> Result<Vec<OrderByExpr>> {
        order_by
            .iter()
            .map(|order_by| self.bind_query_output_sort_expr(columns, order_by))
            .collect()
    }

    fn bind_query_output_sort_expr(
        &self,
        columns: &[BoundColumn],
        order_by: &OrderByExpr,
    ) -> Result<OrderByExpr> {
        let column = match &order_by.expr {
            Expr::Integer(value) => self.query_output_ordinal_column(columns, *value, "ORDER BY")?,
            Expr::Identifier(identifier) => columns
                .iter()
                .find(|column| column.name.eq_ignore_ascii_case(identifier.as_str()))
                .ok_or_else(|| {
                    RnovError::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "ORDER BY for set operation queries must reference an output column: {}",
                            identifier.as_str()
                        ),
                    )
                })?,
            _ => {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "ORDER BY for set operation queries must reference an output column or position",
                ));
            }
        };
        self.ensure_sortable_type(&column.data_type)?;
        Ok(OrderByExpr {
            expr: Expr::Identifier(Ident::new(column.name.as_str())),
            direction: order_by.direction,
        })
    }

    fn query_output_ordinal_column<'b>(
        &self,
        columns: &'b [BoundColumn],
        value: i64,
        clause_name: &str,
    ) -> Result<&'b BoundColumn> {
        let ordinal = usize::try_from(value).map_err(|_| {
            RnovError::new(
                ErrorKind::InvalidInput,
                format!("{clause_name} position must be positive: {value}"),
            )
        })?;
        if ordinal == 0 || ordinal > columns.len() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "{clause_name} position {ordinal} is out of range for {} query output columns",
                    columns.len()
                ),
            ));
        }
        Ok(&columns[ordinal - 1])
    }

    fn bind_grouped_sort_expr(
        &self,
        table: &Table,
        projection: &[BoundSelectItem],
        hidden_aggregates: &mut Vec<BoundSelectItem>,
        group_by: &[Expr],
        order_by: &OrderByExpr,
        role_id: RoleId,
    ) -> Result<OrderByExpr> {
        let expr = match &order_by.expr {
            Expr::Integer(value) => Expr::Identifier(Ident::new(
                self.projection_ordinal_item(projection, *value, "ORDER BY")?
                    .column
                    .name
                    .as_str(),
            )),
            _ => {
                if let Some(item) = projection
                    .iter()
                    .chain(hidden_aggregates.iter())
                    .find(|item| item.expr == order_by.expr)
                {
                    Expr::Identifier(Ident::new(item.column.name.as_str()))
                } else if is_aggregate_expr(&order_by.expr) {
                    self.rewrite_having_aggregate_expr(
                        table,
                        projection,
                        hidden_aggregates,
                        &order_by.expr,
                    )?
                } else {
                    order_by.expr.clone()
                }
            }
        };
        let mut grouped_outputs = projection.to_vec();
        grouped_outputs.extend(hidden_aggregates.iter().cloned());
        let mut infer =
            |candidate: &Expr| self.infer_grouped_output_expr_type(&grouped_outputs, candidate);
        let expr = self.bind_predicate_subqueries(&expr, role_id, &mut infer, None)?;
        self.validate_grouped_sort_expr(table, &grouped_outputs, group_by, &expr)?;
        Ok(OrderByExpr {
            expr,
            direction: order_by.direction,
        })
    }

    fn projection_ordinal_item<'b>(
        &self,
        projection: &'b [BoundSelectItem],
        value: i64,
        clause_name: &str,
    ) -> Result<&'b BoundSelectItem> {
        let ordinal = usize::try_from(value).map_err(|_| {
            RnovError::new(
                ErrorKind::InvalidInput,
                format!("{clause_name} position must be positive: {value}"),
            )
        })?;
        if ordinal == 0 || ordinal > projection.len() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "{clause_name} position {ordinal} is out of range for {} select items",
                    projection.len()
                ),
            ));
        }
        Ok(&projection[ordinal - 1])
    }

    fn bind_group_by_exprs(
        &self,
        table: &Table,
        projection: &[BoundSelectItem],
        group_by: &[Expr],
    ) -> Result<Vec<Expr>> {
        group_by
            .iter()
            .map(|expr| self.bind_group_by_expr(table, projection, expr))
            .collect()
    }

    fn bind_group_by_expr(
        &self,
        table: &Table,
        projection: &[BoundSelectItem],
        expr: &Expr,
    ) -> Result<Expr> {
        let expr = match expr {
            Expr::Integer(value) => self
                .projection_ordinal_item(projection, *value, "GROUP BY")?
                .expr
                .clone(),
            Expr::Identifier(identifier) => projection
                .iter()
                .find(|item| item.column.name.eq_ignore_ascii_case(identifier.as_str()))
                .map(|item| item.expr.clone())
                .unwrap_or_else(|| expr.clone()),
            _ => expr.clone(),
        };
        self.rewrite_table_qualified_expr(table, &expr)
    }

    fn bind_grouping_sets(
        &self,
        table: &Table,
        projection: &[BoundSelectItem],
        grouping_sets: &[Vec<Expr>],
    ) -> Result<Vec<Vec<Expr>>> {
        grouping_sets
            .iter()
            .map(|grouping_set| self.bind_group_by_exprs(table, projection, grouping_set))
            .collect()
    }

    fn validate_group_by_exprs(&self, table: &Table, group_by: &[Expr]) -> Result<()> {
        for expr in group_by {
            self.validate_group_by_expr_shape(expr)?;
            match self.infer_expr_type(table, expr)? {
                Some(
                    SqlType::Null
                    | SqlType::Bool
                    | SqlType::Int64
                    | SqlType::UInt64
                    | SqlType::Float64
                    | SqlType::Uuid
                    | SqlType::Timestamp
                    | SqlType::Text
                    | SqlType::Bytes,
                ) => {}
                Some(other) => {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        format!("GROUP BY expression type is not groupable: {other:?}"),
                    ));
                }
                None => {}
            }
        }
        Ok(())
    }

    fn validate_group_by_expr_shape(&self, expr: &Expr) -> Result<()> {
        match expr {
            Expr::Identifier(_)
            | Expr::QualifiedIdentifier { .. }
            | Expr::Integer(_)
            | Expr::Float64(_)
            | Expr::String(_)
            | Expr::Bool(_)
            | Expr::Null
            | Expr::RuntimeValue(_)
            | Expr::HStore(_) => Ok(()),
            Expr::Array(values) | Expr::Coalesce(values) | Expr::Call { args: values, .. } => {
                self.validate_group_by_expr_list(values)
            }
            Expr::Range { lower, upper, .. } => self.validate_group_by_pair(lower, upper),
            Expr::Binary { left, op, right } => self.validate_group_by_binary(left, op, right),
            Expr::Unary { op, expr } => self.validate_group_by_unary(op, expr),
            Expr::Not(expr)
            | Expr::IsNull { expr, .. }
            | Expr::IsTruth { expr, .. }
            | Expr::IsUnknown { expr, .. }
            | Expr::Cast { expr, .. } => self.validate_group_by_expr_shape(expr),
            Expr::IsDistinctFrom { left, right, .. }
            | Expr::Like {
                expr: left,
                pattern: right,
                ..
            }
            | Expr::NullIf { left, right } => self.validate_group_by_pair(left, right),
            Expr::Between {
                expr, low, high, ..
            } => self.validate_group_by_triple(expr, low, high),
            Expr::InList { expr, values, .. } => {
                self.validate_group_by_expr_shape(expr)?;
                self.validate_group_by_expr_list(values)
            }
            Expr::InSubquery { .. } | Expr::ExistsSubquery { .. } | Expr::ScalarSubquery { .. } => {
                Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "GROUP BY does not support subqueries",
                ))
            }
            Expr::Case { .. } => self.validate_group_by_case(expr),
            Expr::CountStar
            | Expr::Count(_)
            | Expr::CountDistinct(_)
            | Expr::Sum(_)
            | Expr::Min(_)
            | Expr::Max(_) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "GROUP BY does not support aggregate expressions",
            )),
            Expr::RowNumberOver { .. } | Expr::RankOver { .. } | Expr::DenseRankOver { .. } => {
                Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "GROUP BY does not support window expressions",
                ))
            }
        }
    }

    fn validate_group_by_expr_list(&self, values: &[Expr]) -> Result<()> {
        values
            .iter()
            .try_for_each(|value| self.validate_group_by_expr_shape(value))
    }

    fn validate_group_by_pair(&self, left: &Expr, right: &Expr) -> Result<()> {
        self.validate_group_by_expr_shape(left)?;
        self.validate_group_by_expr_shape(right)
    }

    fn validate_group_by_triple(&self, first: &Expr, second: &Expr, third: &Expr) -> Result<()> {
        self.validate_group_by_expr_shape(first)?;
        self.validate_group_by_expr_shape(second)?;
        self.validate_group_by_expr_shape(third)
    }

    fn validate_group_by_binary(&self, left: &Expr, op: &str, right: &Expr) -> Result<()> {
        if !matches!(
            op,
            "=" | "<>"
                | "!="
                | "<"
                | "<="
                | ">"
                | ">="
                | "@@"
                | "AND"
                | "OR"
                | "||"
                | "+"
                | "-"
                | "*"
                | "/"
                | "%"
        ) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("GROUP BY does not support operator {op} yet"),
            ));
        }
        self.validate_group_by_pair(left, right)
    }

    fn validate_group_by_unary(&self, op: &str, expr: &Expr) -> Result<()> {
        if !matches!(op, "+" | "-") {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("GROUP BY does not support unary operator {op} yet"),
            ));
        }
        self.validate_group_by_expr_shape(expr)
    }

    fn validate_group_by_case(&self, expr: &Expr) -> Result<()> {
        let Expr::Case {
            operand,
            whens,
            else_expr,
        } = expr
        else {
            return Err(RnovError::new(
                ErrorKind::Internal,
                "GROUP BY case validator received a non-CASE expression",
            ));
        };
        if let Some(operand) = operand {
            self.validate_group_by_expr_shape(operand)?;
        }
        for arm in whens {
            self.validate_group_by_pair(&arm.condition, &arm.result)?;
        }
        if let Some(else_expr) = else_expr {
            self.validate_group_by_expr_shape(else_expr)?;
        }
        Ok(())
    }

    fn validate_grouped_sort_expr(
        &self,
        table: &Table,
        projection: &[BoundSelectItem],
        group_by: &[Expr],
        expr: &Expr,
    ) -> Result<()> {
        if let Expr::Identifier(identifier) = expr
            && let Some(column) = projection
                .iter()
                .find(|item| item.column.name.eq_ignore_ascii_case(identifier.as_str()))
        {
            return self.ensure_sortable_type(&column.column.data_type);
        }
        if group_by.iter().any(|group| group == expr) {
            let data_type = self.infer_expr_type(table, expr)?;
            return self.ensure_optional_sortable_type(data_type);
        }
        if grouped_sort_expr_references_outputs(projection, expr) {
            let data_type = self.infer_grouped_output_expr_type(projection, expr)?;
            return self.ensure_optional_sortable_type(data_type);
        }
        Err(grouped_sort_reference_error(expr))
    }

    fn ensure_optional_sortable_type(&self, data_type: Option<SqlType>) -> Result<()> {
        match data_type {
            Some(data_type) => self.ensure_sortable_type(&data_type),
            None => Ok(()),
        }
    }

    fn ensure_sortable_type(&self, data_type: &SqlType) -> Result<()> {
        match data_type {
            SqlType::Null
            | SqlType::Bool
            | SqlType::Int64
            | SqlType::UInt64
            | SqlType::Float64
            | SqlType::Uuid
            | SqlType::Timestamp
            | SqlType::Text
            | SqlType::Bytes => Ok(()),
            other => Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("ORDER BY expression type is not sortable: {other:?}"),
            )),
        }
    }

    fn validate_grouped_having_expr(
        &self,
        projection: &[BoundSelectItem],
        expr: &Expr,
    ) -> Result<()> {
        match self.infer_grouped_output_expr_type(projection, expr)? {
            Some(SqlType::Bool | SqlType::Null) => Ok(()),
            Some(other) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("HAVING predicate must be bool, got {other:?}"),
            )),
            None => Ok(()),
        }
    }

    fn rewrite_grouped_having_expr(
        &self,
        table: &Table,
        projection: &[BoundSelectItem],
        group_by: &[Expr],
        hidden_group_keys: &mut Vec<BoundSelectItem>,
        hidden_aggregates: &mut Vec<BoundSelectItem>,
        expr: &Expr,
    ) -> Result<Expr> {
        rewrite_expr_tree(expr, &mut |candidate| {
            if let Some(item) = projection
                .iter()
                .chain(hidden_group_keys.iter())
                .chain(hidden_aggregates.iter())
                .find(|item| &item.expr == candidate)
            {
                return Ok(Some(Expr::Identifier(Ident::new(
                    item.column.name.as_str(),
                ))));
            }
            if group_by.iter().any(|group| group == candidate) {
                return self
                    .rewrite_having_group_key_expr(
                        table,
                        projection,
                        hidden_group_keys,
                        hidden_aggregates,
                        candidate,
                    )
                    .map(Some);
            }
            if is_aggregate_expr(candidate) {
                return self
                    .rewrite_having_aggregate_expr(table, projection, hidden_aggregates, candidate)
                    .map(Some);
            }
            if matches!(
                candidate,
                Expr::RowNumberOver { .. } | Expr::RankOver { .. } | Expr::DenseRankOver { .. }
            ) {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "HAVING does not support window expressions",
                ));
            }
            Ok(None)
        })
    }

    fn rewrite_having_group_key_expr(
        &self,
        table: &Table,
        projection: &[BoundSelectItem],
        hidden_group_keys: &mut Vec<BoundSelectItem>,
        hidden_aggregates: &[BoundSelectItem],
        expr: &Expr,
    ) -> Result<Expr> {
        if let Some(item) = projection
            .iter()
            .chain(hidden_group_keys.iter())
            .find(|item| &item.expr == expr)
        {
            return Ok(Expr::Identifier(Ident::new(item.column.name.as_str())));
        }

        let data_type = self.infer_expr_type(table, expr)?.ok_or_else(|| {
            RnovError::new(
                ErrorKind::InvalidInput,
                format!("cannot infer GROUP BY expression type: {expr}"),
            )
        })?;
        let existing_columns = projection
            .iter()
            .chain(hidden_group_keys.iter())
            .chain(hidden_aggregates.iter())
            .map(|item| item.column.clone())
            .collect::<Vec<_>>();
        let base_name = match expr {
            Expr::Identifier(identifier) => identifier.as_str(),
            _ => "group_key",
        };
        let column = BoundColumn {
            name: unique_column_name(&existing_columns, base_name),
            data_type,
            nullable: hidden_group_key_nullable(table, expr),
            encrypted: false,
            generated: None,
        };
        let name = column.name.clone();
        hidden_group_keys.push(BoundSelectItem {
            column,
            expr: expr.clone(),
        });
        Ok(Expr::Identifier(Ident::new(name.as_str())))
    }

    fn rewrite_having_aggregate_expr(
        &self,
        table: &Table,
        projection: &[BoundSelectItem],
        hidden_aggregates: &mut Vec<BoundSelectItem>,
        expr: &Expr,
    ) -> Result<Expr> {
        if let Some(item) = projection
            .iter()
            .chain(hidden_aggregates.iter())
            .find(|item| &item.expr == expr)
        {
            return Ok(Expr::Identifier(Ident::new(item.column.name.as_str())));
        }

        let item = self.hidden_having_aggregate_item(table, projection, hidden_aggregates, expr)?;
        let name = item.column.name.clone();
        hidden_aggregates.push(item);
        Ok(Expr::Identifier(Ident::new(name.as_str())))
    }

    fn hidden_having_aggregate_item(
        &self,
        table: &Table,
        projection: &[BoundSelectItem],
        hidden_aggregates: &[BoundSelectItem],
        expr: &Expr,
    ) -> Result<BoundSelectItem> {
        let existing_columns = projection
            .iter()
            .chain(hidden_aggregates.iter())
            .map(|item| item.column.clone())
            .collect::<Vec<_>>();
        let column = match expr {
            Expr::CountStar => Ok(aggregate_bound_column(
                &existing_columns,
                "count",
                SqlType::Int64,
                false,
            )),
            Expr::Count(expr) | Expr::CountDistinct(expr) => {
                self.hidden_count_column(table, &existing_columns, expr)
            }
            Expr::Sum(expr) => self.hidden_sum_column(table, &existing_columns, expr),
            Expr::Min(expr) => self.hidden_ordered_column(table, &existing_columns, expr, "MIN"),
            Expr::Max(expr) => self.hidden_ordered_column(table, &existing_columns, expr, "MAX"),
            _ => Err(RnovError::new(
                ErrorKind::Internal,
                "hidden HAVING aggregate requires aggregate expression",
            )),
        }?;

        Ok(BoundSelectItem {
            column,
            expr: expr.clone(),
        })
    }

    fn hidden_count_column(
        &self,
        table: &Table,
        existing_columns: &[BoundColumn],
        expr: &Expr,
    ) -> Result<BoundColumn> {
        let _ = self.infer_expr_type(table, expr)?.ok_or_else(|| {
            RnovError::new(
                ErrorKind::InvalidInput,
                format!("cannot infer COUNT expression type: {expr}"),
            )
        })?;
        Ok(aggregate_bound_column(
            existing_columns,
            "count",
            SqlType::Int64,
            false,
        ))
    }

    fn hidden_sum_column(
        &self,
        table: &Table,
        existing_columns: &[BoundColumn],
        expr: &Expr,
    ) -> Result<BoundColumn> {
        let expr_type = self.infer_expr_type(table, expr)?.ok_or_else(|| {
            RnovError::new(
                ErrorKind::InvalidInput,
                format!("cannot infer SUM expression type: {expr}"),
            )
        })?;
        if expr_type != SqlType::Int64 && expr_type != SqlType::Null {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("SUM expression must be INT64, got {expr_type:?}"),
            ));
        }
        Ok(aggregate_bound_column(
            existing_columns,
            "sum",
            SqlType::Int64,
            true,
        ))
    }

    fn hidden_ordered_column(
        &self,
        table: &Table,
        existing_columns: &[BoundColumn],
        expr: &Expr,
        aggregate_name: &'static str,
    ) -> Result<BoundColumn> {
        let expr_type = self.infer_expr_type(table, expr)?.ok_or_else(|| {
            RnovError::new(
                ErrorKind::InvalidInput,
                format!("cannot infer {aggregate_name} expression type: {expr}"),
            )
        })?;
        self.ensure_ordered_aggregate_type(aggregate_name, &expr_type)?;
        let column_name = aggregate_name.to_ascii_lowercase();
        Ok(aggregate_bound_column(
            existing_columns,
            &column_name,
            expr_type,
            true,
        ))
    }

    fn infer_grouped_output_expr_type(
        &self,
        projection: &[BoundSelectItem],
        expr: &Expr,
    ) -> Result<Option<SqlType>> {
        match expr {
            Expr::Identifier(identifier) => projection
                .iter()
                .find(|item| item.column.name.eq_ignore_ascii_case(identifier.as_str()))
                .map(|item| Some(item.column.data_type.clone()))
                .ok_or_else(|| {
                    RnovError::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "HAVING must reference a projected column: {}",
                            identifier.as_str()
                        ),
                    )
                }),
            Expr::QualifiedIdentifier { .. } => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "HAVING does not support qualified column references after binding",
            )),
            Expr::Integer(_) => Ok(Some(SqlType::Int64)),
            Expr::Float64(_) => Ok(Some(SqlType::Float64)),
            Expr::String(_) => Ok(Some(SqlType::Text)),
            Expr::Bool(_) => Ok(Some(SqlType::Bool)),
            Expr::Null => Ok(Some(SqlType::Null)),
            Expr::RuntimeValue(value) => Ok(Some(value.data_type())),
            Expr::ScalarSubquery { query } => self.infer_bound_scalar_subquery_type(query),
            Expr::CountStar
            | Expr::Count(_)
            | Expr::CountDistinct(_)
            | Expr::Sum(_)
            | Expr::Min(_)
            | Expr::Max(_) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "HAVING only supports projected aggregate output columns yet",
            )),
            Expr::RowNumberOver { .. } | Expr::RankOver { .. } | Expr::DenseRankOver { .. } => {
                Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "HAVING does not support window expressions",
                ))
            }
            Expr::Array(values) => self.infer_array_expr_type(values, |value| {
                self.infer_grouped_output_expr_type(projection, value)
            }),
            Expr::HStore(_) => Ok(Some(SqlType::HStore)),
            Expr::Range { lower, upper, .. } => {
                self.infer_range_expr_type(lower, upper, true, |expr| {
                    self.infer_grouped_output_expr_type(projection, expr)
                })
            }
            Expr::Binary { left, right, .. } => {
                let Some(left_type) = self.infer_grouped_output_expr_type(projection, left)? else {
                    return Ok(None);
                };
                let Some(right_type) = self.infer_grouped_output_expr_type(projection, right)?
                else {
                    return Ok(None);
                };
                self.infer_operator_result_type(expr, &left_type, &right_type)
            }
            Expr::Unary { op, expr } => {
                let Some(data_type) = self.infer_grouped_output_expr_type(projection, expr)? else {
                    return Ok(None);
                };
                self.infer_unary_arithmetic_result_type(op, &data_type)
            }
            Expr::Not(expr) => {
                let Some(data_type) = self.infer_grouped_output_expr_type(projection, expr)? else {
                    return Ok(None);
                };
                self.infer_not_result_type(&data_type)
            }
            Expr::IsNull { expr, .. } => {
                let _ = self.infer_grouped_output_expr_type(projection, expr)?;
                Ok(Some(SqlType::Bool))
            }
            Expr::IsTruth { expr, value, .. } => {
                let Some(data_type) = self.infer_grouped_output_expr_type(projection, expr)? else {
                    return Ok(None);
                };
                self.infer_truth_test_result_type(truth_test_name(*value), &data_type)
            }
            Expr::IsUnknown { expr, .. } => {
                let Some(data_type) = self.infer_grouped_output_expr_type(projection, expr)? else {
                    return Ok(None);
                };
                self.infer_truth_test_result_type("IS UNKNOWN", &data_type)
            }
            Expr::IsDistinctFrom { left, right, .. } => {
                let Some(left_type) = self.infer_grouped_output_expr_type(projection, left)? else {
                    return Ok(None);
                };
                let Some(right_type) = self.infer_grouped_output_expr_type(projection, right)?
                else {
                    return Ok(None);
                };
                self.infer_null_safe_comparison_result_type(
                    "IS DISTINCT FROM",
                    &left_type,
                    &right_type,
                )
            }
            Expr::Between {
                expr, low, high, ..
            } => {
                let Some(expr_type) = self.infer_grouped_output_expr_type(projection, expr)? else {
                    return Ok(None);
                };
                let Some(low_type) = self.infer_grouped_output_expr_type(projection, low)? else {
                    return Ok(None);
                };
                let Some(high_type) = self.infer_grouped_output_expr_type(projection, high)? else {
                    return Ok(None);
                };
                self.infer_between_result_type(&expr_type, &low_type, &high_type)
            }
            Expr::InList { expr, values, .. } => {
                let Some(expr_type) = self.infer_grouped_output_expr_type(projection, expr)? else {
                    return Ok(None);
                };
                let mut value_types = Vec::with_capacity(values.len());
                for value in values {
                    let Some(value_type) =
                        self.infer_grouped_output_expr_type(projection, value)?
                    else {
                        return Ok(None);
                    };
                    value_types.push(value_type);
                }
                self.infer_in_list_result_type(&expr_type, &value_types)
            }
            Expr::InSubquery { query, .. } => {
                self.infer_bound_predicate_subquery_type(query, "IN subquery")
            }
            Expr::ExistsSubquery { query } => {
                self.infer_bound_predicate_subquery_type(query, "EXISTS subquery")
            }
            Expr::Like { expr, pattern, .. } => {
                let Some(expr_type) = self.infer_grouped_output_expr_type(projection, expr)? else {
                    return Ok(None);
                };
                let Some(pattern_type) =
                    self.infer_grouped_output_expr_type(projection, pattern)?
                else {
                    return Ok(None);
                };
                self.infer_like_result_type(&expr_type, &pattern_type)
            }
            Expr::Coalesce(values) => {
                let mut value_types = Vec::with_capacity(values.len());
                for value in values {
                    let Some(value_type) =
                        self.infer_grouped_output_expr_type(projection, value)?
                    else {
                        return Ok(None);
                    };
                    value_types.push(value_type);
                }
                self.infer_coalesce_result_type(&value_types)
            }
            Expr::NullIf { left, right } => {
                let Some(left_type) = self.infer_grouped_output_expr_type(projection, left)? else {
                    return Ok(None);
                };
                let Some(right_type) = self.infer_grouped_output_expr_type(projection, right)?
                else {
                    return Ok(None);
                };
                self.infer_nullif_result_type(&left_type, &right_type)
            }
            Expr::Case {
                operand,
                whens,
                else_expr,
            } => {
                let operand_type = match operand {
                    Some(operand) => {
                        match self.infer_grouped_output_expr_type(projection, operand)? {
                            Some(data_type) => Some(data_type),
                            None => return Ok(None),
                        }
                    }
                    None => None,
                };
                let mut result_types = Vec::with_capacity(whens.len());
                for arm in whens {
                    let Some(condition_type) =
                        self.infer_grouped_output_expr_type(projection, &arm.condition)?
                    else {
                        return Ok(None);
                    };
                    self.infer_case_condition_type(operand_type.as_ref(), &condition_type)?;
                    let Some(result_type) =
                        self.infer_grouped_output_expr_type(projection, &arm.result)?
                    else {
                        return Ok(None);
                    };
                    result_types.push(result_type);
                }
                let else_type = match else_expr {
                    Some(else_expr) => {
                        self.infer_grouped_output_expr_type(projection, else_expr)?
                    }
                    None => Some(SqlType::Null),
                };
                let Some(else_type) = else_type else {
                    return Ok(None);
                };
                self.infer_case_result_type(&result_types, &else_type)
            }
            Expr::Cast { expr, data_type } => {
                let Some(source_type) = self.infer_grouped_output_expr_type(projection, expr)?
                else {
                    return Ok(None);
                };
                self.infer_cast_result_type(&source_type, data_type)
            }
            Expr::Call { .. } => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "HAVING does not support function calls yet",
            )),
        }
    }

    fn validate_grouped_projection(
        &self,
        projection: &[BoundSelectItem],
        group_by: &[Expr],
    ) -> Result<()> {
        if group_by.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "aggregate expressions cannot be mixed with other select items yet",
            ));
        }
        for item in projection {
            if is_aggregate_expr(&item.expr) {
                continue;
            }
            if !group_by.iter().any(|expr| expr == &item.expr) {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "non-aggregate select items must appear in GROUP BY",
                ));
            }
        }
        Ok(())
    }

    fn ensure_ordered_aggregate_type(&self, function: &str, data_type: &SqlType) -> Result<()> {
        match data_type {
            SqlType::Null
            | SqlType::Bool
            | SqlType::Int64
            | SqlType::UInt64
            | SqlType::Float64
            | SqlType::Uuid
            | SqlType::Timestamp
            | SqlType::Text
            | SqlType::Bytes => Ok(()),
            other => Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("{function} expression type is not orderable: {other:?}"),
            )),
        }
    }

    fn resolve_table(&self, name: &ObjectName) -> Result<&Table> {
        let schema = name.schema().unwrap_or("public");
        self.catalog
            .get_table(schema, name.object())
            .ok_or_else(|| {
                RnovError::new(
                    ErrorKind::NotFound,
                    format!("table does not exist: {schema}.{}", name.object()),
                )
            })
    }

    fn resolve_column(&self, table: &Table, column_name: &str) -> Result<BoundColumn> {
        let mut matches = table
            .columns()
            .iter()
            .filter(|column| column.name().eq_ignore_ascii_case(column_name));
        let column = matches.next().ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("column does not exist: {}.{column_name}", table.name()),
            )
        })?;
        if matches.next().is_some() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "ambiguous column reference {}.{column_name}: multiple case variants exist",
                    table.name()
                ),
            ));
        }

        let generated = column
            .generated_expr()
            .map(|expr| {
                parse_expr(expr).map(|expr| crate::ast::GeneratedColumn {
                    expr,
                    stored: column.generated_stored(),
                })
            })
            .transpose()?;

        Ok(BoundColumn {
            name: column.name().to_string(),
            data_type: column.data_type().clone(),
            nullable: column.nullable(),
            encrypted: column.is_encrypted(),
            generated,
        })
    }

    fn resolve_column_from_bound(
        &self,
        columns: &[BoundColumn],
        column_name: &Ident,
    ) -> Result<BoundColumn> {
        columns
            .iter()
            .find(|column| column.name.eq_ignore_ascii_case(column_name.as_str()))
            .cloned()
            .ok_or_else(|| {
                RnovError::new(
                    ErrorKind::NotFound,
                    format!("column does not exist: {}", column_name.as_str()),
                )
            })
    }

    fn ensure_table_qualifier(&self, table: &Table, qualifier: &Ident) -> Result<()> {
        if self.table_qualifier_matches(table, qualifier) {
            Ok(())
        } else {
            Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "qualified column references table {}, but current table is {}",
                    qualifier.as_str(),
                    table.name()
                ),
            ))
        }
    }

    fn table_qualifier_matches(&self, table: &Table, qualifier: &Ident) -> bool {
        qualifier.as_str().eq_ignore_ascii_case(table.name())
            || qualifier.as_str().eq_ignore_ascii_case(table.schema_name())
    }

    fn rewrite_table_qualified_expr(&self, table: &Table, expr: &Expr) -> Result<Expr> {
        let rewritten = rewrite_qualified_expr(expr, &mut |qualifier, name| {
            self.ensure_table_qualifier(table, qualifier)?;
            let _ = self.resolve_column(table, name.as_str())?;
            Ok(Expr::Identifier(name.clone()))
        })?;
        let mut infer = |candidate: &Expr| self.infer_expr_type(table, candidate);
        self.bind_function_calls(&rewritten, &mut infer)
    }

    fn bind_function_calls<F>(&self, expr: &Expr, infer: &mut F) -> Result<Expr>
    where
        F: FnMut(&Expr) -> Result<Option<SqlType>>,
    {
        rewrite_expr_tree(expr, &mut |candidate| {
            let Expr::Call { name, args, .. } = candidate else {
                return Ok(None);
            };
            let mut bound_args = Vec::with_capacity(args.len());
            for arg in args {
                bound_args.push(self.bind_function_calls(arg, infer)?);
            }
            let Some(argument_types) = self.infer_expr_type_list(&bound_args, |arg| infer(arg))?
            else {
                return Ok(None);
            };
            let function = self
                .catalog
                .get_function(name.object(), &argument_types)
                .ok_or_else(|| {
                    RnovError::new(
                        ErrorKind::NotFound,
                        format!("function does not exist: {name}"),
                    )
                })?;
            Ok(Some(Expr::Call {
                function_id: Some(function.function_id()),
                name: name.clone(),
                args: bound_args,
            }))
        })
    }

    fn rewrite_table_qualified_expr_with_outer(
        &self,
        table: &Table,
        expr: &Expr,
        outer_scope: Option<OuterQueryScope<'_>>,
    ) -> Result<Expr> {
        let rewritten = rewrite_qualified_expr(expr, &mut |qualifier, name| {
            self.rewrite_table_qualified_identifier(table, outer_scope, qualifier, name)
        })?;
        let mut infer = |candidate: &Expr| {
            let typed = self.replace_outer_refs_for_type_validation(candidate, outer_scope)?;
            self.infer_expr_type(table, &typed)
        };
        self.bind_function_calls(&rewritten, &mut infer)
    }

    fn rewrite_table_qualified_identifier(
        &self,
        table: &Table,
        outer_scope: Option<OuterQueryScope<'_>>,
        qualifier: &Ident,
        name: &Ident,
    ) -> Result<Expr> {
        if self.table_qualifier_matches(table, qualifier) {
            let _ = self.resolve_column(table, name.as_str())?;
            return Ok(Expr::Identifier(name.clone()));
        }
        if let Some(outer_scope) = outer_scope
            && let Some(expr) =
                self.rewrite_outer_qualified_identifier(outer_scope, qualifier, name)?
        {
            return Ok(expr);
        }
        self.ensure_table_qualifier(table, qualifier)?;
        unreachable!("ensure_table_qualifier returned Ok for a non-matching qualifier")
    }

    fn rewrite_outer_qualified_identifier(
        &self,
        outer_scope: OuterQueryScope<'_>,
        qualifier: &Ident,
        name: &Ident,
    ) -> Result<Option<Expr>> {
        match outer_scope {
            OuterQueryScope::Table(table) => {
                if !self.table_qualifier_matches(table, qualifier) {
                    return Ok(None);
                }
                let _ = self.resolve_column(table, name.as_str())?;
                Ok(Some(Expr::QualifiedIdentifier {
                    qualifier: qualifier.clone(),
                    name: name.clone(),
                }))
            }
            OuterQueryScope::Columns(columns) => {
                let Some(column) = outer_lateral_column(columns, qualifier, name)? else {
                    return Ok(None);
                };
                Ok(Some(Expr::QualifiedIdentifier {
                    qualifier: qualifier.clone(),
                    name: Ident::new(column.output_name.as_str()),
                }))
            }
        }
    }

    fn replace_outer_refs_for_type_validation(
        &self,
        expr: &Expr,
        outer_scope: Option<OuterQueryScope<'_>>,
    ) -> Result<Expr> {
        let Some(outer_scope) = outer_scope else {
            return Ok(expr.clone());
        };
        rewrite_qualified_expr(expr, &mut |qualifier, name| {
            if let Some(expr) = self.typed_null_for_outer_ref(outer_scope, qualifier, name)? {
                return Ok(expr);
            }
            Ok(Expr::QualifiedIdentifier {
                qualifier: qualifier.clone(),
                name: name.clone(),
            })
        })
    }

    fn typed_null_for_outer_ref(
        &self,
        outer_scope: OuterQueryScope<'_>,
        qualifier: &Ident,
        name: &Ident,
    ) -> Result<Option<Expr>> {
        match outer_scope {
            OuterQueryScope::Table(table) => {
                if !self.table_qualifier_matches(table, qualifier) {
                    return Ok(None);
                }
                let column = self.resolve_column(table, name.as_str())?;
                Ok(Some(typed_null_expr(column.data_type)))
            }
            OuterQueryScope::Columns(columns) => {
                let Some(column) = outer_lateral_column(columns, qualifier, name)? else {
                    return Ok(None);
                };
                Ok(Some(typed_null_expr(column.column.data_type.clone())))
            }
        }
    }

    fn rewrite_lateral_expr(&self, columns: &[LateralColumn], expr: &Expr) -> Result<Expr> {
        let rewritten = rewrite_qualified_expr(expr, &mut |qualifier, name| {
            let matches = columns
                .iter()
                .filter(|column| {
                    column.table_name.eq_ignore_ascii_case(qualifier.as_str())
                        && column.source_name.eq_ignore_ascii_case(name.as_str())
                })
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [column] => Ok(Expr::Identifier(Ident::new(column.output_name.as_str()))),
                [] => Err(RnovError::new(
                    ErrorKind::NotFound,
                    format!("column does not exist: {qualifier}.{name}"),
                )),
                _ => Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("ambiguous qualified column reference: {qualifier}.{name}"),
                )),
            }
        })?;
        let bound_columns = lateral_columns_to_bound(columns);
        let mut infer =
            |candidate: &Expr| self.infer_expr_type_from_columns(&bound_columns, candidate);
        self.bind_function_calls(&rewritten, &mut infer)
    }

    fn rewrite_cte_expr(&self, columns: &[BoundColumn], expr: &Expr) -> Result<Expr> {
        let rewritten = rewrite_qualified_expr(expr, &mut |qualifier, name| {
            if qualifier.as_str().eq_ignore_ascii_case("__cte") {
                let _ = self.resolve_column_from_bound(columns, name)?;
                Ok(Expr::Identifier(name.clone()))
            } else {
                Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("recursive CTE column reference uses unknown qualifier {qualifier}"),
                ))
            }
        })?;
        self.validate_cte_identifiers(columns, &rewritten)?;
        let mut infer = |candidate: &Expr| self.infer_expr_type_from_columns(columns, candidate);
        self.bind_function_calls(&rewritten, &mut infer)
    }

    fn validate_cte_identifiers(&self, columns: &[BoundColumn], expr: &Expr) -> Result<()> {
        match expr {
            Expr::Identifier(identifier) => {
                let _ = self.resolve_column_from_bound(columns, identifier)?;
                Ok(())
            }
            Expr::QualifiedIdentifier { .. } => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "bound recursive CTE expression must not contain qualified column references",
            )),
            Expr::RuntimeValue(_) => Ok(()),
            Expr::Binary { left, right, .. } => {
                self.validate_cte_identifiers(columns, left)?;
                self.validate_cte_identifiers(columns, right)
            }
            Expr::Unary { expr, .. }
            | Expr::Not(expr)
            | Expr::Count(expr)
            | Expr::CountDistinct(expr)
            | Expr::Sum(expr)
            | Expr::Min(expr)
            | Expr::Max(expr)
            | Expr::Cast { expr, .. } => self.validate_cte_identifiers(columns, expr),
            Expr::IsNull { expr, .. }
            | Expr::IsTruth { expr, .. }
            | Expr::IsUnknown { expr, .. } => self.validate_cte_identifiers(columns, expr),
            Expr::IsDistinctFrom { left, right, .. } | Expr::NullIf { left, right } => {
                self.validate_cte_identifiers(columns, left)?;
                self.validate_cte_identifiers(columns, right)
            }
            Expr::Between {
                expr, low, high, ..
            } => {
                self.validate_cte_identifiers(columns, expr)?;
                self.validate_cte_identifiers(columns, low)?;
                self.validate_cte_identifiers(columns, high)
            }
            Expr::InList { expr, values, .. } => {
                self.validate_cte_identifiers(columns, expr)?;
                for value in values {
                    self.validate_cte_identifiers(columns, value)?;
                }
                Ok(())
            }
            Expr::InSubquery { .. } => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "recursive CTE expressions do not support subqueries",
            )),
            Expr::ExistsSubquery { .. } => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "recursive CTE expressions do not support subqueries",
            )),
            Expr::ScalarSubquery { .. } => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "recursive CTE expressions do not support subqueries",
            )),
            Expr::Like { expr, pattern, .. } => {
                self.validate_cte_identifiers(columns, expr)?;
                self.validate_cte_identifiers(columns, pattern)
            }
            Expr::Coalesce(values) | Expr::Array(values) => {
                for value in values {
                    self.validate_cte_identifiers(columns, value)?;
                }
                Ok(())
            }
            Expr::Case {
                operand,
                whens,
                else_expr,
            } => {
                if let Some(operand) = operand {
                    self.validate_cte_identifiers(columns, operand)?;
                }
                for arm in whens {
                    self.validate_cte_identifiers(columns, &arm.condition)?;
                    self.validate_cte_identifiers(columns, &arm.result)?;
                }
                if let Some(else_expr) = else_expr {
                    self.validate_cte_identifiers(columns, else_expr)?;
                }
                Ok(())
            }
            Expr::Call { args, .. } => {
                for arg in args {
                    self.validate_cte_identifiers(columns, arg)?;
                }
                Ok(())
            }
            Expr::RowNumberOver { order_by }
            | Expr::RankOver { order_by }
            | Expr::DenseRankOver { order_by } => {
                for order_by in order_by {
                    self.validate_cte_identifiers(columns, &order_by.expr)?;
                }
                Ok(())
            }
            Expr::Range { lower, upper, .. } => {
                self.validate_cte_identifiers(columns, lower)?;
                self.validate_cte_identifiers(columns, upper)
            }
            Expr::Integer(_)
            | Expr::Float64(_)
            | Expr::String(_)
            | Expr::Bool(_)
            | Expr::Null
            | Expr::CountStar
            | Expr::HStore(_) => Ok(()),
        }
    }

    fn bind_lateral_equality(
        &self,
        outer_table: &Table,
        outer_name: &ObjectName,
        inner_table: &Table,
        inner_name: &ObjectName,
        expr: &Expr,
    ) -> Result<(String, String)> {
        let Expr::Binary { left, op, right } = expr else {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "JOIN LATERAL requires an equality ON predicate",
            ));
        };
        if op != "=" {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "JOIN LATERAL requires an equality ON predicate",
            ));
        }
        let left =
            self.lateral_column_ref(outer_table, outer_name, inner_table, inner_name, left)?;
        let right =
            self.lateral_column_ref(outer_table, outer_name, inner_table, inner_name, right)?;
        match (left.side, right.side) {
            (LateralSide::Inner, LateralSide::Outer) => {
                self.ensure_lateral_column_types_match(&left.column, &right.column)?;
                Ok((left.column.name, right.column.name))
            }
            (LateralSide::Outer, LateralSide::Inner) => {
                self.ensure_lateral_column_types_match(&right.column, &left.column)?;
                Ok((right.column.name, left.column.name))
            }
            _ => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "JOIN LATERAL ON must compare one inner column with one outer column",
            )),
        }
    }

    fn lateral_column_ref(
        &self,
        outer_table: &Table,
        outer_name: &ObjectName,
        inner_table: &Table,
        inner_name: &ObjectName,
        expr: &Expr,
    ) -> Result<LateralColumnRef> {
        let Expr::QualifiedIdentifier { qualifier, name } = expr else {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "JOIN LATERAL ON must use qualified column references",
            ));
        };
        if self.object_matches_qualifier(inner_table, inner_name, qualifier) {
            let column = self.resolve_column(inner_table, name.as_str())?;
            return Ok(LateralColumnRef {
                side: LateralSide::Inner,
                column,
            });
        }
        if self.object_matches_qualifier(outer_table, outer_name, qualifier) {
            let column = self.resolve_column(outer_table, name.as_str())?;
            return Ok(LateralColumnRef {
                side: LateralSide::Outer,
                column,
            });
        }
        Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("JOIN LATERAL ON references unknown table qualifier {qualifier}"),
        ))
    }

    fn object_matches_qualifier(
        &self,
        table: &Table,
        object_name: &ObjectName,
        qualifier: &Ident,
    ) -> bool {
        qualifier.as_str().eq_ignore_ascii_case(table.name())
            || qualifier
                .as_str()
                .eq_ignore_ascii_case(object_name.object())
    }

    fn ensure_lateral_column_types_match(
        &self,
        inner_column: &BoundColumn,
        outer_column: &BoundColumn,
    ) -> Result<()> {
        if inner_column.data_type == outer_column.data_type {
            return Ok(());
        }
        Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "JOIN LATERAL column types must match, got {:?} and {:?}",
                inner_column.data_type, outer_column.data_type
            ),
        ))
    }

    fn require_table_privilege(
        &self,
        role_id: RoleId,
        relation_id: RelationId,
        privilege: Privilege,
    ) -> Result<()> {
        if self
            .catalog
            .has_table_privilege(role_id, relation_id, privilege)
        {
            Ok(())
        } else {
            Err(RnovError::new(
                ErrorKind::Security,
                format!("missing {privilege:?} privilege on relation {relation_id}"),
            ))
        }
    }

    fn require_procedure_privilege(
        &self,
        role_id: RoleId,
        procedure_id: rnmdb_common::ids::FunctionId,
        privilege: Privilege,
    ) -> Result<()> {
        if self
            .catalog
            .has_procedure_privilege(role_id, procedure_id, privilege)
        {
            Ok(())
        } else {
            let procedure_name = self
                .catalog
                .procedure_by_id(procedure_id)
                .map(format_procedure_name)
                .unwrap_or_else(|| format!("procedure {procedure_id}"));
            Err(RnovError::new(
                ErrorKind::Security,
                format!("missing {privilege} privilege on {procedure_name}"),
            ))
        }
    }

    fn applied_row_policy_names(&self, role_id: RoleId, relation_id: RelationId) -> Vec<String> {
        if self.bypasses_row_security(role_id, relation_id) {
            return Vec::new();
        }
        let mut names: Vec<String> = self
            .catalog
            .row_policies(relation_id)
            .iter()
            .map(|policy| policy.name().to_string())
            .collect();
        if names.is_empty() && self.catalog.row_security_deny_by_default(relation_id) {
            names.push(RLS_DENY_DEFAULT_POLICY.to_string());
        }
        names
    }

    fn bind_row_policies(&self, role_id: RoleId, table: &Table) -> Result<Vec<BoundRowPolicy>> {
        if self.bypasses_row_security(role_id, table.relation_id()) {
            return Ok(Vec::new());
        }
        let mut policies: Vec<BoundRowPolicy> = self
            .catalog
            .row_policies(table.relation_id())
            .iter()
            .map(|policy| {
                let predicate = parse_expr(policy.predicate())?;
                self.validate_policy_predicate(table, &predicate)?;
                Ok(BoundRowPolicy {
                    name: policy.name().to_string(),
                    predicate,
                })
            })
            .collect::<Result<_>>()?;
        if policies.is_empty()
            && self
                .catalog
                .row_security_deny_by_default(table.relation_id())
        {
            policies.push(BoundRowPolicy {
                name: RLS_DENY_DEFAULT_POLICY.to_string(),
                predicate: deny_default_row_policy_predicate(),
            });
        }
        Ok(policies)
    }

    fn bypasses_row_security(&self, role_id: RoleId, relation_id: RelationId) -> bool {
        self.catalog.role_is_superuser(role_id)
            || self.catalog.role_owns_relation(role_id, relation_id)
    }

    fn validate_policy_predicate(&self, table: &Table, expr: &Expr) -> Result<()> {
        match self.infer_policy_expr_type(table, expr)? {
            Some(SqlType::Bool | SqlType::Null) | None => Ok(()),
            Some(other) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("row policy predicate must be bool, got {other:?}"),
            )),
        }
    }

    fn infer_policy_expr_type(&self, table: &Table, expr: &Expr) -> Result<Option<SqlType>> {
        match expr {
            Expr::Identifier(identifier) => {
                let column = self.resolve_column(table, identifier.as_str())?;
                Ok(Some(column.data_type))
            }
            Expr::QualifiedIdentifier { qualifier, name } => {
                self.ensure_table_qualifier(table, qualifier)?;
                let column = self.resolve_column(table, name.as_str())?;
                Ok(Some(column.data_type))
            }
            Expr::Integer(_) => Ok(Some(SqlType::Int64)),
            Expr::Float64(_) => Ok(Some(SqlType::Float64)),
            Expr::String(_) => Ok(Some(SqlType::Text)),
            Expr::Bool(_) => Ok(Some(SqlType::Bool)),
            Expr::Null => Ok(Some(SqlType::Null)),
            Expr::RuntimeValue(value) => Ok(Some(value.data_type())),
            Expr::ScalarSubquery { query } => self.infer_bound_scalar_subquery_type(query),
            Expr::CountStar => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "COUNT(*) is only supported as a SELECT projection",
            )),
            Expr::Count(_) | Expr::CountDistinct(_) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "COUNT(expr) is only supported as a SELECT projection",
            )),
            Expr::Sum(_) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "SUM(expr) is only supported as a SELECT projection",
            )),
            Expr::Min(_) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "MIN(expr) is only supported as a SELECT projection",
            )),
            Expr::Max(_) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "MAX(expr) is only supported as a SELECT projection",
            )),
            Expr::RowNumberOver { .. } | Expr::RankOver { .. } | Expr::DenseRankOver { .. } => {
                Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "window expressions are only supported as SELECT projections",
                ))
            }
            Expr::Array(values) => self
                .infer_array_expr_type(values, |value| self.infer_policy_expr_type(table, value)),
            Expr::HStore(_) => Ok(Some(SqlType::HStore)),
            Expr::Range { lower, upper, .. } => {
                self.infer_range_expr_type(lower, upper, false, |expr| {
                    self.infer_policy_expr_type(table, expr)
                })
            }
            Expr::Binary { left, right, .. } => {
                let left_type = self.infer_policy_expr_type(table, left)?;
                let right_type = self.infer_policy_expr_type(table, right)?;
                match (left_type, right_type) {
                    (Some(left_type), Some(right_type)) => {
                        self.infer_operator_result_type(expr, &left_type, &right_type)
                    }
                    _ => Ok(policy_unknown_side_operator_type(expr)),
                }
            }
            Expr::Unary { op, expr } => {
                let Some(data_type) = self.infer_policy_expr_type(table, expr)? else {
                    return Ok(Some(SqlType::Int64));
                };
                self.infer_unary_arithmetic_result_type(op, &data_type)
            }
            Expr::Not(expr) => {
                let Some(data_type) = self.infer_policy_expr_type(table, expr)? else {
                    return Ok(Some(SqlType::Bool));
                };
                self.infer_not_result_type(&data_type)
            }
            Expr::IsNull { expr, .. } => {
                let _ = self.infer_policy_expr_type(table, expr)?;
                Ok(Some(SqlType::Bool))
            }
            Expr::IsTruth { expr, value, .. } => {
                let Some(data_type) = self.infer_policy_expr_type(table, expr)? else {
                    return Ok(Some(SqlType::Bool));
                };
                self.infer_truth_test_result_type(truth_test_name(*value), &data_type)
            }
            Expr::IsUnknown { expr, .. } => {
                let Some(data_type) = self.infer_policy_expr_type(table, expr)? else {
                    return Ok(Some(SqlType::Bool));
                };
                self.infer_truth_test_result_type("IS UNKNOWN", &data_type)
            }
            Expr::IsDistinctFrom { left, right, .. } => {
                let Some(left_type) = self.infer_policy_expr_type(table, left)? else {
                    return Ok(Some(SqlType::Bool));
                };
                let Some(right_type) = self.infer_policy_expr_type(table, right)? else {
                    return Ok(Some(SqlType::Bool));
                };
                self.infer_null_safe_comparison_result_type(
                    "IS DISTINCT FROM",
                    &left_type,
                    &right_type,
                )
            }
            Expr::Between {
                expr, low, high, ..
            } => {
                let Some(expr_type) = self.infer_policy_expr_type(table, expr)? else {
                    return Ok(Some(SqlType::Bool));
                };
                let Some(low_type) = self.infer_policy_expr_type(table, low)? else {
                    return Ok(Some(SqlType::Bool));
                };
                let Some(high_type) = self.infer_policy_expr_type(table, high)? else {
                    return Ok(Some(SqlType::Bool));
                };
                self.infer_between_result_type(&expr_type, &low_type, &high_type)
            }
            Expr::InList { expr, values, .. } => {
                let Some(expr_type) = self.infer_policy_expr_type(table, expr)? else {
                    return Ok(Some(SqlType::Bool));
                };
                let Some(value_types) = self.infer_expr_type_list(values, |value| {
                    self.infer_policy_expr_type(table, value)
                })?
                else {
                    return Ok(Some(SqlType::Bool));
                };
                self.infer_in_list_result_type(&expr_type, &value_types)
            }
            Expr::InSubquery { .. } => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "row policy predicates do not support subqueries",
            )),
            Expr::ExistsSubquery { .. } => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "row policy predicates do not support subqueries",
            )),
            Expr::Like { expr, pattern, .. } => {
                let Some(expr_type) = self.infer_policy_expr_type(table, expr)? else {
                    return Ok(Some(SqlType::Bool));
                };
                let Some(pattern_type) = self.infer_policy_expr_type(table, pattern)? else {
                    return Ok(Some(SqlType::Bool));
                };
                self.infer_like_result_type(&expr_type, &pattern_type)
            }
            Expr::Coalesce(values) => {
                let Some(value_types) = self.infer_expr_type_list(values, |value| {
                    self.infer_policy_expr_type(table, value)
                })?
                else {
                    return Ok(None);
                };
                self.infer_coalesce_result_type(&value_types)
            }
            Expr::NullIf { left, right } => {
                let Some(left_type) = self.infer_policy_expr_type(table, left)? else {
                    return Ok(None);
                };
                let Some(right_type) = self.infer_policy_expr_type(table, right)? else {
                    return Ok(None);
                };
                self.infer_nullif_result_type(&left_type, &right_type)
            }
            Expr::Case {
                operand,
                whens,
                else_expr,
            } => {
                let operand_type = match operand {
                    Some(operand) => match self.infer_policy_expr_type(table, operand)? {
                        Some(data_type) => Some(data_type),
                        None => return Ok(None),
                    },
                    None => None,
                };
                let mut result_types = Vec::with_capacity(whens.len());
                for arm in whens {
                    let Some(condition_type) =
                        self.infer_policy_expr_type(table, &arm.condition)?
                    else {
                        return Ok(None);
                    };
                    self.infer_case_condition_type(operand_type.as_ref(), &condition_type)?;
                    let Some(result_type) = self.infer_policy_expr_type(table, &arm.result)? else {
                        return Ok(None);
                    };
                    result_types.push(result_type);
                }
                let else_type = match else_expr {
                    Some(else_expr) => self.infer_policy_expr_type(table, else_expr)?,
                    None => Some(SqlType::Null),
                };
                let Some(else_type) = else_type else {
                    return Ok(None);
                };
                self.infer_case_result_type(&result_types, &else_type)
            }
            Expr::Cast { expr, data_type } => {
                let Some(source_type) = self.infer_policy_expr_type(table, expr)? else {
                    return Ok(Some(data_type.clone()));
                };
                self.infer_cast_result_type(&source_type, data_type)
            }
            Expr::Call { name, args, .. } => {
                let Some(argument_types) =
                    self.infer_expr_type_list(args, |arg| self.infer_policy_expr_type(table, arg))?
                else {
                    return Ok(None);
                };

                Ok(self
                    .catalog
                    .functions()
                    .iter()
                    .find(|function| {
                        function.name() == name.object()
                            && function.argument_types() == argument_types
                    })
                    .map(|function| function.return_type().clone()))
            }
        }
    }

    fn ensure_expr_assignable(
        &self,
        table: &Table,
        column: &BoundColumn,
        expr: &Expr,
    ) -> Result<()> {
        let Some(expr_type) = self.infer_expr_type(table, expr)? else {
            return Ok(());
        };

        if expr_type == SqlType::Null {
            if column.nullable {
                return Ok(());
            }
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "null value cannot be assigned to not-null column {}",
                    column.name
                ),
            ));
        }

        if expr_type == column.data_type {
            Ok(())
        } else {
            Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "type mismatch for column {}: expected {:?}, got {:?}",
                    column.name, column.data_type, expr_type
                ),
            ))
        }
    }

    fn infer_expr_type(&self, table: &Table, expr: &Expr) -> Result<Option<SqlType>> {
        match expr {
            Expr::Identifier(identifier) => {
                let column = self.resolve_column(table, identifier.as_str())?;
                Ok(Some(column.data_type))
            }
            Expr::QualifiedIdentifier { qualifier, name } => {
                self.ensure_table_qualifier(table, qualifier)?;
                let column = self.resolve_column(table, name.as_str())?;
                Ok(Some(column.data_type))
            }
            Expr::Integer(_) => Ok(Some(SqlType::Int64)),
            Expr::Float64(_) => Ok(Some(SqlType::Float64)),
            Expr::String(_) => Ok(Some(SqlType::Text)),
            Expr::Bool(_) => Ok(Some(SqlType::Bool)),
            Expr::Null => Ok(Some(SqlType::Null)),
            Expr::RuntimeValue(value) => Ok(Some(value.data_type())),
            Expr::ScalarSubquery { query } => self.infer_bound_scalar_subquery_type(query),
            Expr::CountStar => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "COUNT(*) is only supported as a SELECT projection",
            )),
            Expr::Count(_) | Expr::CountDistinct(_) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "COUNT(expr) is only supported as a SELECT projection",
            )),
            Expr::Sum(_) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "SUM(expr) is only supported as a SELECT projection",
            )),
            Expr::Min(_) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "MIN(expr) is only supported as a SELECT projection",
            )),
            Expr::Max(_) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "MAX(expr) is only supported as a SELECT projection",
            )),
            Expr::RowNumberOver { .. } | Expr::RankOver { .. } | Expr::DenseRankOver { .. } => {
                Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "window expressions are only supported as SELECT projections",
                ))
            }
            Expr::Array(values) => {
                self.infer_array_expr_type(values, |value| self.infer_expr_type(table, value))
            }
            Expr::HStore(_) => Ok(Some(SqlType::HStore)),
            Expr::Range { lower, upper, .. } => {
                self.infer_range_expr_type(lower, upper, true, |expr| {
                    self.infer_expr_type(table, expr)
                })
            }
            Expr::Binary { left, right, .. } => {
                let Some(left_type) = self.infer_expr_type(table, left)? else {
                    return Ok(None);
                };
                let Some(right_type) = self.infer_expr_type(table, right)? else {
                    return Ok(None);
                };
                self.infer_operator_result_type(expr, &left_type, &right_type)
            }
            Expr::Unary { op, expr } => {
                let Some(data_type) = self.infer_expr_type(table, expr)? else {
                    return Ok(None);
                };
                self.infer_unary_arithmetic_result_type(op, &data_type)
            }
            Expr::Not(expr) => {
                let Some(data_type) = self.infer_expr_type(table, expr)? else {
                    return Ok(None);
                };
                self.infer_not_result_type(&data_type)
            }
            Expr::IsNull { expr, .. } => {
                let _ = self.infer_expr_type(table, expr)?;
                Ok(Some(SqlType::Bool))
            }
            Expr::IsTruth { expr, value, .. } => {
                let Some(data_type) = self.infer_expr_type(table, expr)? else {
                    return Ok(None);
                };
                self.infer_truth_test_result_type(truth_test_name(*value), &data_type)
            }
            Expr::IsUnknown { expr, .. } => {
                let Some(data_type) = self.infer_expr_type(table, expr)? else {
                    return Ok(None);
                };
                self.infer_truth_test_result_type("IS UNKNOWN", &data_type)
            }
            Expr::IsDistinctFrom { left, right, .. } => {
                let Some(left_type) = self.infer_expr_type(table, left)? else {
                    return Ok(None);
                };
                let Some(right_type) = self.infer_expr_type(table, right)? else {
                    return Ok(None);
                };
                self.infer_null_safe_comparison_result_type(
                    "IS DISTINCT FROM",
                    &left_type,
                    &right_type,
                )
            }
            Expr::Between {
                expr, low, high, ..
            } => {
                let Some(expr_type) = self.infer_expr_type(table, expr)? else {
                    return Ok(None);
                };
                let Some(low_type) = self.infer_expr_type(table, low)? else {
                    return Ok(None);
                };
                let Some(high_type) = self.infer_expr_type(table, high)? else {
                    return Ok(None);
                };
                self.infer_between_result_type(&expr_type, &low_type, &high_type)
            }
            Expr::InList { expr, values, .. } => {
                let Some(expr_type) = self.infer_expr_type(table, expr)? else {
                    return Ok(None);
                };
                let Some(value_types) =
                    self.infer_expr_type_list(values, |value| self.infer_expr_type(table, value))?
                else {
                    return Ok(None);
                };
                self.infer_in_list_result_type(&expr_type, &value_types)
            }
            Expr::InSubquery { query, .. } => {
                self.infer_bound_predicate_subquery_type(query, "IN subquery")
            }
            Expr::ExistsSubquery { query } => {
                self.infer_bound_predicate_subquery_type(query, "EXISTS subquery")
            }
            Expr::Like { expr, pattern, .. } => {
                let Some(expr_type) = self.infer_expr_type(table, expr)? else {
                    return Ok(None);
                };
                let Some(pattern_type) = self.infer_expr_type(table, pattern)? else {
                    return Ok(None);
                };
                self.infer_like_result_type(&expr_type, &pattern_type)
            }
            Expr::Coalesce(values) => {
                let Some(value_types) =
                    self.infer_expr_type_list(values, |value| self.infer_expr_type(table, value))?
                else {
                    return Ok(None);
                };
                self.infer_coalesce_result_type(&value_types)
            }
            Expr::NullIf { left, right } => {
                let Some(left_type) = self.infer_expr_type(table, left)? else {
                    return Ok(None);
                };
                let Some(right_type) = self.infer_expr_type(table, right)? else {
                    return Ok(None);
                };
                self.infer_nullif_result_type(&left_type, &right_type)
            }
            Expr::Case {
                operand,
                whens,
                else_expr,
            } => {
                let operand_type = match operand {
                    Some(operand) => match self.infer_expr_type(table, operand)? {
                        Some(data_type) => Some(data_type),
                        None => return Ok(None),
                    },
                    None => None,
                };
                let mut result_types = Vec::with_capacity(whens.len());
                for arm in whens {
                    let Some(condition_type) = self.infer_expr_type(table, &arm.condition)? else {
                        return Ok(None);
                    };
                    self.infer_case_condition_type(operand_type.as_ref(), &condition_type)?;
                    let Some(result_type) = self.infer_expr_type(table, &arm.result)? else {
                        return Ok(None);
                    };
                    result_types.push(result_type);
                }
                let else_type = match else_expr {
                    Some(else_expr) => self.infer_expr_type(table, else_expr)?,
                    None => Some(SqlType::Null),
                };
                let Some(else_type) = else_type else {
                    return Ok(None);
                };
                self.infer_case_result_type(&result_types, &else_type)
            }
            Expr::Cast { expr, data_type } => {
                let Some(source_type) = self.infer_expr_type(table, expr)? else {
                    return Ok(None);
                };
                self.infer_cast_result_type(&source_type, data_type)
            }
            Expr::Call { name, args, .. } => {
                let Some(argument_types) =
                    self.infer_expr_type_list(args, |arg| self.infer_expr_type(table, arg))?
                else {
                    return Ok(None);
                };

                let function = self
                    .catalog
                    .functions()
                    .iter()
                    .find(|function| {
                        function.name() == name.object()
                            && function.argument_types() == argument_types
                    })
                    .ok_or_else(|| {
                        RnovError::new(
                            ErrorKind::NotFound,
                            format!("function does not exist: {name}"),
                        )
                    })?;
                Ok(Some(function.return_type().clone()))
            }
        }
    }

    fn infer_array_expr_type<F>(&self, values: &[Expr], mut infer: F) -> Result<Option<SqlType>>
    where
        F: FnMut(&Expr) -> Result<Option<SqlType>>,
    {
        let mut element_type = None;
        for value in values {
            let Some(value_type) = infer(value)? else {
                return Ok(None);
            };
            if value_type == SqlType::Null {
                continue;
            }
            match &element_type {
                Some(existing) if *existing != value_type => {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        "array literal contains mixed element types",
                    ));
                }
                Some(_) => {}
                None => element_type = Some(value_type),
            }
        }
        Ok(Some(SqlType::Array(Box::new(
            element_type.unwrap_or(SqlType::Null),
        ))))
    }

    fn infer_range_expr_type<F>(
        &self,
        lower: &Expr,
        upper: &Expr,
        unknown_as_null: bool,
        mut infer: F,
    ) -> Result<Option<SqlType>>
    where
        F: FnMut(&Expr) -> Result<Option<SqlType>>,
    {
        let lower_type = match infer(lower)? {
            Some(data_type) => data_type,
            None if unknown_as_null => SqlType::Null,
            None => return Ok(None),
        };
        let upper_type = match infer(upper)? {
            Some(data_type) => data_type,
            None if unknown_as_null => SqlType::Null,
            None => return Ok(None),
        };
        let element_type = match (lower_type, upper_type) {
            (SqlType::Null, SqlType::Null) => SqlType::Null,
            (SqlType::Null, upper_type) => upper_type,
            (lower_type, SqlType::Null) => lower_type,
            (lower_type, upper_type) if lower_type == upper_type => lower_type,
            _ => {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "range literal bounds have different types",
                ));
            }
        };
        Ok(Some(SqlType::Range(Box::new(element_type))))
    }

    fn infer_expr_type_list<F>(&self, values: &[Expr], mut infer: F) -> Result<Option<Vec<SqlType>>>
    where
        F: FnMut(&Expr) -> Result<Option<SqlType>>,
    {
        let mut value_types = Vec::with_capacity(values.len());
        for value in values {
            let Some(value_type) = infer(value)? else {
                return Ok(None);
            };
            value_types.push(value_type);
        }
        Ok(Some(value_types))
    }

    fn infer_expr_type_from_columns(
        &self,
        columns: &[BoundColumn],
        expr: &Expr,
    ) -> Result<Option<SqlType>> {
        match expr {
            Expr::Identifier(_) | Expr::QualifiedIdentifier { .. } => {
                self.infer_column_reference_type(columns, expr)
            }
            Expr::Integer(_)
            | Expr::Float64(_)
            | Expr::String(_)
            | Expr::Bool(_)
            | Expr::Null
            | Expr::RuntimeValue(_) => Self::infer_bound_literal_type(expr),
            Expr::ScalarSubquery { .. } | Expr::InSubquery { .. } | Expr::ExistsSubquery { .. } => {
                self.infer_column_subquery_type(expr)
            }
            Expr::CountStar
            | Expr::Count(_)
            | Expr::CountDistinct(_)
            | Expr::Sum(_)
            | Expr::Min(_)
            | Expr::Max(_)
            | Expr::RowNumberOver { .. }
            | Expr::RankOver { .. }
            | Expr::DenseRankOver { .. } => Self::reject_column_special_expression(expr),
            Expr::Binary { .. } | Expr::Unary { .. } | Expr::Cast { .. } => {
                self.infer_column_operator_type(columns, expr)
            }
            Expr::Coalesce(_) | Expr::NullIf { .. } => {
                self.infer_column_null_function_type(columns, expr)
            }
            Expr::Call { .. } => self.infer_column_call_type(columns, expr),
            other => Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("unsupported generated column expression: {other}"),
            )),
        }
    }

    fn infer_column_reference_type(
        &self,
        columns: &[BoundColumn],
        expr: &Expr,
    ) -> Result<Option<SqlType>> {
        match expr {
            Expr::Identifier(identifier) => columns
                .iter()
                .find(|column| column.name.eq_ignore_ascii_case(identifier.as_str()))
                .map(|column| Some(column.data_type.clone()))
                .ok_or_else(|| {
                    RnovError::new(
                        ErrorKind::NotFound,
                        format!("column does not exist: {}", identifier.as_str()),
                    )
                }),
            Expr::QualifiedIdentifier { .. } => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "bound expressions must not contain qualified column references",
            )),
            _ => Err(column_type_inference_error("column reference")),
        }
    }

    fn infer_bound_literal_type(expr: &Expr) -> Result<Option<SqlType>> {
        match expr {
            Expr::Integer(_) => Ok(Some(SqlType::Int64)),
            Expr::Float64(_) => Ok(Some(SqlType::Float64)),
            Expr::String(_) => Ok(Some(SqlType::Text)),
            Expr::Bool(_) => Ok(Some(SqlType::Bool)),
            Expr::Null => Ok(Some(SqlType::Null)),
            Expr::RuntimeValue(value) => Ok(Some(value.data_type())),
            _ => Err(column_type_inference_error("literal")),
        }
    }

    fn infer_column_subquery_type(&self, expr: &Expr) -> Result<Option<SqlType>> {
        match expr {
            Expr::ScalarSubquery { query } => self.infer_bound_scalar_subquery_type(query),
            Expr::InSubquery { query, .. } => {
                self.infer_bound_predicate_subquery_type(query, "IN subquery")
            }
            Expr::ExistsSubquery { query } => {
                self.infer_bound_predicate_subquery_type(query, "EXISTS subquery")
            }
            _ => Err(column_type_inference_error("subquery")),
        }
    }

    fn reject_column_special_expression(expr: &Expr) -> Result<Option<SqlType>> {
        let message = match expr {
            Expr::CountStar
            | Expr::Count(_)
            | Expr::CountDistinct(_)
            | Expr::Sum(_)
            | Expr::Min(_)
            | Expr::Max(_) => "aggregate expressions are only supported as SELECT projections",
            Expr::RowNumberOver { .. } | Expr::RankOver { .. } | Expr::DenseRankOver { .. } => {
                "window expressions are only supported as SELECT projections"
            }
            _ => {
                return Err(column_type_inference_error(
                    "aggregate or window expression",
                ));
            }
        };
        Err(RnovError::new(ErrorKind::InvalidInput, message))
    }

    fn infer_column_operator_type(
        &self,
        columns: &[BoundColumn],
        expr: &Expr,
    ) -> Result<Option<SqlType>> {
        match expr {
            Expr::Binary { left, right, .. } => {
                self.infer_column_binary_type(columns, expr, left, right)
            }
            Expr::Unary { op, expr } => self.infer_column_unary_type(columns, op, expr),
            Expr::Cast { expr, data_type } => self.infer_column_cast_type(columns, expr, data_type),
            _ => Err(column_type_inference_error("operator")),
        }
    }

    fn infer_column_binary_type(
        &self,
        columns: &[BoundColumn],
        binary: &Expr,
        left: &Expr,
        right: &Expr,
    ) -> Result<Option<SqlType>> {
        let Some(left_type) = self.infer_expr_type_from_columns(columns, left)? else {
            return Ok(None);
        };
        let Some(right_type) = self.infer_expr_type_from_columns(columns, right)? else {
            return Ok(None);
        };
        self.infer_operator_result_type(binary, &left_type, &right_type)
    }

    fn infer_column_unary_type(
        &self,
        columns: &[BoundColumn],
        op: &str,
        expr: &Expr,
    ) -> Result<Option<SqlType>> {
        let Some(data_type) = self.infer_expr_type_from_columns(columns, expr)? else {
            return Ok(None);
        };
        self.infer_unary_arithmetic_result_type(op, &data_type)
    }

    fn infer_column_cast_type(
        &self,
        columns: &[BoundColumn],
        expr: &Expr,
        data_type: &SqlType,
    ) -> Result<Option<SqlType>> {
        let Some(source_type) = self.infer_expr_type_from_columns(columns, expr)? else {
            return Ok(None);
        };
        self.infer_cast_result_type(&source_type, data_type)
    }

    fn infer_column_null_function_type(
        &self,
        columns: &[BoundColumn],
        expr: &Expr,
    ) -> Result<Option<SqlType>> {
        match expr {
            Expr::Coalesce(values) => self.infer_column_coalesce_type(columns, values),
            Expr::NullIf { left, right } => self.infer_column_nullif_type(columns, left, right),
            _ => Err(column_type_inference_error("null-handling function")),
        }
    }

    fn infer_column_coalesce_type(
        &self,
        columns: &[BoundColumn],
        values: &[Expr],
    ) -> Result<Option<SqlType>> {
        let Some(value_types) = self.infer_expr_type_list(values, |value| {
            self.infer_expr_type_from_columns(columns, value)
        })?
        else {
            return Ok(None);
        };
        self.infer_coalesce_result_type(&value_types)
    }

    fn infer_column_nullif_type(
        &self,
        columns: &[BoundColumn],
        left: &Expr,
        right: &Expr,
    ) -> Result<Option<SqlType>> {
        let Some(left_type) = self.infer_expr_type_from_columns(columns, left)? else {
            return Ok(None);
        };
        let Some(right_type) = self.infer_expr_type_from_columns(columns, right)? else {
            return Ok(None);
        };
        self.infer_nullif_result_type(&left_type, &right_type)
    }

    fn infer_column_call_type(
        &self,
        columns: &[BoundColumn],
        expr: &Expr,
    ) -> Result<Option<SqlType>> {
        let Expr::Call { name, args, .. } = expr else {
            return Err(column_type_inference_error("function call"));
        };
        let Some(argument_types) =
            self.infer_expr_type_list(args, |arg| self.infer_expr_type_from_columns(columns, arg))?
        else {
            return Ok(None);
        };
        let function = self
            .catalog
            .functions()
            .iter()
            .find(|function| {
                function.name() == name.object() && function.argument_types() == argument_types
            })
            .ok_or_else(|| {
                RnovError::new(
                    ErrorKind::NotFound,
                    format!("function does not exist: {name}"),
                )
            })?;
        Ok(Some(function.return_type().clone()))
    }

    fn infer_operator_result_type(
        &self,
        expr: &Expr,
        left_type: &SqlType,
        right_type: &SqlType,
    ) -> Result<Option<SqlType>> {
        let Expr::Binary { op, .. } = expr else {
            return Err(RnovError::new(
                ErrorKind::Internal,
                "operator inference requires binary expression",
            ));
        };

        if matches!(op.as_str(), "=" | "<>" | "!=" | "<" | "<=" | ">" | ">=") {
            return Ok(Some(SqlType::Bool));
        }
        if is_arithmetic_operator(op) {
            return self.infer_arithmetic_result_type(op, left_type, right_type);
        }
        if is_text_concat_operator(op) {
            return self.infer_text_concat_result_type(op, left_type, right_type);
        }
        if op == "&&" {
            return self.infer_range_overlap_result_type(left_type, right_type);
        }
        if op == "@>" {
            return self.infer_contains_result_type(left_type, right_type);
        }
        if op == "?" {
            return self.infer_hstore_key_result_type(left_type, right_type);
        }
        if is_boolean_connector(op) {
            if matches!(left_type, SqlType::Bool | SqlType::Null)
                && matches!(right_type, SqlType::Bool | SqlType::Null)
            {
                return Ok(Some(SqlType::Bool));
            }
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("boolean operator {op} requires BOOL operands"),
            ));
        }

        let operator = self
            .catalog
            .operators()
            .iter()
            .find(|operator| {
                let signature = operator.signature();
                signature.symbol() == op
                    && signature.left_type() == left_type
                    && signature.right_type() == right_type
            })
            .ok_or_else(|| {
                RnovError::new(
                    ErrorKind::NotFound,
                    format!("operator does not exist: {left_type:?} {op} {right_type:?}"),
                )
            })?;

        Ok(Some(operator.signature().result_type().clone()))
    }

    fn infer_not_result_type(&self, data_type: &SqlType) -> Result<Option<SqlType>> {
        if matches!(data_type, SqlType::Bool | SqlType::Null) {
            Ok(Some(SqlType::Bool))
        } else {
            Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("NOT requires BOOL operand, got {data_type:?}"),
            ))
        }
    }

    fn infer_truth_test_result_type(
        &self,
        name: &str,
        data_type: &SqlType,
    ) -> Result<Option<SqlType>> {
        if matches!(data_type, SqlType::Bool | SqlType::Null) {
            Ok(Some(SqlType::Bool))
        } else {
            Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("{name} requires BOOL operand, got {data_type:?}"),
            ))
        }
    }

    fn infer_arithmetic_result_type(
        &self,
        op: &str,
        left_type: &SqlType,
        right_type: &SqlType,
    ) -> Result<Option<SqlType>> {
        if !is_numeric_or_null(left_type) || !is_numeric_or_null(right_type) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("arithmetic operator {op} requires numeric operands"),
            ));
        }
        if op == "%" && (left_type == &SqlType::Float64 || right_type == &SqlType::Float64) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "modulo operator requires INT64 operands",
            ));
        }
        if left_type == &SqlType::Float64 || right_type == &SqlType::Float64 {
            Ok(Some(SqlType::Float64))
        } else {
            Ok(Some(SqlType::Int64))
        }
    }

    fn infer_text_concat_result_type(
        &self,
        op: &str,
        left_type: &SqlType,
        right_type: &SqlType,
    ) -> Result<Option<SqlType>> {
        if matches!(left_type, SqlType::Text | SqlType::Null)
            && matches!(right_type, SqlType::Text | SqlType::Null)
        {
            Ok(Some(SqlType::Text))
        } else {
            Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("text operator {op} requires TEXT operands"),
            ))
        }
    }

    fn infer_range_overlap_result_type(
        &self,
        left_type: &SqlType,
        right_type: &SqlType,
    ) -> Result<Option<SqlType>> {
        match (left_type, right_type) {
            (SqlType::Range(left), SqlType::Range(right)) if left == right => {
                Ok(Some(SqlType::Bool))
            }
            (SqlType::Array(left), SqlType::Array(right))
                if left == right && matches!(left.as_ref(), SqlType::Range(_)) =>
            {
                Ok(Some(SqlType::Bool))
            }
            (SqlType::Null, SqlType::Range(_))
            | (SqlType::Range(_), SqlType::Null)
            | (SqlType::Null, SqlType::Array(_))
            | (SqlType::Array(_), SqlType::Null)
            | (SqlType::Null, SqlType::Null) => Ok(Some(SqlType::Bool)),
            _ => Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "range overlap operator && requires matching RANGE operands, got {left_type:?} and {right_type:?}"
                ),
            )),
        }
    }

    fn infer_contains_result_type(
        &self,
        left_type: &SqlType,
        right_type: &SqlType,
    ) -> Result<Option<SqlType>> {
        match (left_type, right_type) {
            (SqlType::Array(left), SqlType::Array(right)) if left == right => {
                Ok(Some(SqlType::Bool))
            }
            (SqlType::HStore, SqlType::HStore) => Ok(Some(SqlType::Bool)),
            (SqlType::Null, SqlType::Array(_))
            | (SqlType::Array(_), SqlType::Null)
            | (SqlType::Null, SqlType::HStore)
            | (SqlType::HStore, SqlType::Null)
            | (SqlType::Null, SqlType::Null) => Ok(Some(SqlType::Bool)),
            _ => Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "contains operator @> requires matching ARRAY or HSTORE operands, got {left_type:?} and {right_type:?}"
                ),
            )),
        }
    }

    fn infer_hstore_key_result_type(
        &self,
        left_type: &SqlType,
        right_type: &SqlType,
    ) -> Result<Option<SqlType>> {
        if matches!(left_type, SqlType::HStore | SqlType::Null)
            && matches!(right_type, SqlType::Text | SqlType::Null)
        {
            Ok(Some(SqlType::Bool))
        } else {
            Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "hstore key operator ? requires HSTORE and TEXT operands, got {left_type:?} and {right_type:?}"
                ),
            ))
        }
    }

    fn infer_unary_arithmetic_result_type(
        &self,
        op: &str,
        data_type: &SqlType,
    ) -> Result<Option<SqlType>> {
        if !matches!(op, "+" | "-") {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("unsupported unary operator {op}"),
            ));
        }
        if matches!(data_type, SqlType::Int64 | SqlType::Null) {
            Ok(Some(SqlType::Int64))
        } else if matches!(data_type, SqlType::Float64) {
            Ok(Some(SqlType::Float64))
        } else {
            Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("unary operator {op} requires numeric operand"),
            ))
        }
    }

    fn infer_coalesce_result_type(&self, value_types: &[SqlType]) -> Result<Option<SqlType>> {
        let mut result_type = None;
        for value_type in value_types {
            if value_type == &SqlType::Null {
                continue;
            }
            match &result_type {
                Some(existing) if existing != value_type => {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        "COALESCE arguments must have matching types",
                    ));
                }
                Some(_) => {}
                None => result_type = Some(value_type.clone()),
            }
        }
        Ok(Some(result_type.unwrap_or(SqlType::Null)))
    }

    fn infer_nullif_result_type(
        &self,
        left_type: &SqlType,
        right_type: &SqlType,
    ) -> Result<Option<SqlType>> {
        if matches!(left_type, SqlType::Null)
            || matches!(right_type, SqlType::Null)
            || left_type == right_type
        {
            Ok(Some(left_type.clone()))
        } else {
            Err(RnovError::new(
                ErrorKind::InvalidInput,
                "NULLIF arguments must have matching types",
            ))
        }
    }

    fn infer_null_safe_comparison_result_type(
        &self,
        name: &str,
        left_type: &SqlType,
        right_type: &SqlType,
    ) -> Result<Option<SqlType>> {
        if matches!(left_type, SqlType::Null)
            || matches!(right_type, SqlType::Null)
            || left_type == right_type
        {
            Ok(Some(SqlType::Bool))
        } else {
            Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("{name} requires matching operand types"),
            ))
        }
    }

    fn infer_case_condition_type(
        &self,
        operand_type: Option<&SqlType>,
        condition_type: &SqlType,
    ) -> Result<()> {
        match operand_type {
            Some(operand_type) => {
                if matches!(operand_type, SqlType::Null)
                    || matches!(condition_type, SqlType::Null)
                    || operand_type == condition_type
                {
                    Ok(())
                } else {
                    Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        "CASE operand and WHEN expressions must have matching types",
                    ))
                }
            }
            None => {
                if matches!(condition_type, SqlType::Bool | SqlType::Null) {
                    Ok(())
                } else {
                    Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        format!("CASE WHEN condition must be BOOL, got {condition_type:?}"),
                    ))
                }
            }
        }
    }

    fn infer_case_result_type(
        &self,
        result_types: &[SqlType],
        else_type: &SqlType,
    ) -> Result<Option<SqlType>> {
        if result_types.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "CASE requires at least one WHEN arm",
            ));
        }

        let mut result_type = None;
        for value_type in result_types.iter().chain(std::iter::once(else_type)) {
            if value_type == &SqlType::Null {
                continue;
            }
            match &result_type {
                Some(existing) if existing != value_type => {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        "CASE result expressions must have matching types",
                    ));
                }
                Some(_) => {}
                None => result_type = Some(value_type.clone()),
            }
        }
        Ok(Some(result_type.unwrap_or(SqlType::Null)))
    }

    fn infer_between_result_type(
        &self,
        expr_type: &SqlType,
        low_type: &SqlType,
        high_type: &SqlType,
    ) -> Result<Option<SqlType>> {
        let mut expected: Option<&SqlType> = None;
        for data_type in [expr_type, low_type, high_type] {
            if matches!(data_type, SqlType::Null) {
                continue;
            }
            self.ensure_ordered_aggregate_type("BETWEEN", data_type)?;
            match &expected {
                Some(expected) if *expected != data_type => {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "BETWEEN requires matching expression and bound types, got {expr_type:?}, {low_type:?}, {high_type:?}"
                        ),
                    ));
                }
                Some(_) => {}
                None => expected = Some(data_type),
            }
        }
        Ok(Some(SqlType::Bool))
    }

    fn infer_in_list_result_type(
        &self,
        expr_type: &SqlType,
        value_types: &[SqlType],
    ) -> Result<Option<SqlType>> {
        let mut expected = if matches!(expr_type, SqlType::Null) {
            None
        } else {
            Some(expr_type)
        };
        for value_type in value_types {
            if matches!(value_type, SqlType::Null) {
                continue;
            }
            match expected {
                Some(expected) if expected != value_type => {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "IN requires matching expression and list value types, got {expr_type:?} and {value_type:?}"
                        ),
                    ));
                }
                Some(_) => {}
                None => expected = Some(value_type),
            }
        }
        Ok(Some(SqlType::Bool))
    }

    fn infer_like_result_type(
        &self,
        expr_type: &SqlType,
        pattern_type: &SqlType,
    ) -> Result<Option<SqlType>> {
        if matches!(expr_type, SqlType::Text | SqlType::Null)
            && matches!(pattern_type, SqlType::Text | SqlType::Null)
        {
            Ok(Some(SqlType::Bool))
        } else {
            Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "LIKE requires TEXT expression and pattern, got {expr_type:?} and {pattern_type:?}"
                ),
            ))
        }
    }

    fn infer_cast_result_type(
        &self,
        source_type: &SqlType,
        target_type: &SqlType,
    ) -> Result<Option<SqlType>> {
        if source_type == target_type
            || matches!(source_type, SqlType::Null)
            || matches!(
                (source_type, target_type),
                (SqlType::Int64, SqlType::Text)
                    | (SqlType::Int64, SqlType::Float64)
                    | (SqlType::Text, SqlType::Int64)
                    | (SqlType::Float64, SqlType::Text)
                    | (SqlType::Text, SqlType::Float64)
                    | (SqlType::Uuid, SqlType::Text)
                    | (SqlType::Text, SqlType::Uuid)
                    | (SqlType::Timestamp, SqlType::Text)
                    | (SqlType::Text, SqlType::Timestamp)
                    | (SqlType::Json, SqlType::Text)
                    | (SqlType::Text, SqlType::Json)
                    | (SqlType::Bool, SqlType::Text)
                    | (SqlType::Text, SqlType::Bool)
            )
        {
            Ok(Some(target_type.clone()))
        } else {
            Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("cannot cast {source_type:?} to {target_type:?}"),
            ))
        }
    }
}

fn policy_unknown_side_operator_type(expr: &Expr) -> Option<SqlType> {
    let Expr::Binary { op, .. } = expr else {
        return None;
    };

    if matches!(
        op.as_str(),
        "=" | "<>" | "!=" | "<" | "<=" | ">" | ">=" | "AND" | "OR"
    ) {
        Some(SqlType::Bool)
    } else if is_arithmetic_operator(op) {
        Some(SqlType::Int64)
    } else if is_text_concat_operator(op) {
        Some(SqlType::Text)
    } else {
        None
    }
}

fn deny_default_row_policy_predicate() -> Expr {
    Expr::Bool(false)
}

fn column_type_inference_error(category: &str) -> RnovError {
    RnovError::new(
        ErrorKind::Internal,
        format!("column type inference received a non-{category} expression"),
    )
}

fn operator_signature_with_metadata(
    symbol: &str,
    left_type: SqlType,
    right_type: SqlType,
    result_type: SqlType,
    function_id: rnmdb_common::ids::FunctionId,
    metadata: OperatorSignatureMetadata<'_>,
) -> OperatorSignature {
    let mut signature =
        OperatorSignature::new(symbol, left_type, right_type, result_type, function_id);
    if let Some(precedence) = metadata.precedence {
        signature = signature.with_precedence(precedence);
    }
    if let Some(commutator) = metadata.commutator {
        signature = signature.with_commutator(commutator);
    }
    if let Some(negator) = metadata.negator {
        signature = signature.with_negator(negator);
    }
    if let Some(selectivity_function_id) = metadata.selectivity_function_id {
        signature = signature.with_selectivity_function(selectivity_function_id);
    }
    signature
}

fn is_boolean_connector(op: &str) -> bool {
    matches!(op, "AND" | "OR")
}

fn is_arithmetic_operator(op: &str) -> bool {
    matches!(op, "+" | "-" | "*" | "/" | "%")
}

fn is_numeric_or_null(data_type: &SqlType) -> bool {
    matches!(data_type, SqlType::Int64 | SqlType::Float64 | SqlType::Null)
}

fn is_text_concat_operator(op: &str) -> bool {
    op == "||"
}

fn truth_test_name(value: bool) -> &'static str {
    if value { "IS TRUE" } else { "IS FALSE" }
}

fn grouped_sort_expr_references_outputs(projection: &[BoundSelectItem], expr: &Expr) -> bool {
    let mut valid = true;
    let rewritten = rewrite_expr_tree(expr, &mut |candidate| {
        match candidate {
            Expr::Identifier(identifier) => {
                valid &= projection
                    .iter()
                    .any(|item| item.column.name.eq_ignore_ascii_case(identifier.as_str()));
            }
            Expr::QualifiedIdentifier { .. } => valid = false,
            _ => {}
        }
        Ok(None)
    });
    rewritten.is_ok() && valid
}

fn grouped_sort_reference_error(expr: &Expr) -> RnovError {
    let message = match expr {
        Expr::Identifier(identifier) => format!(
            "ORDER BY for grouped queries must reference a projected column or GROUP BY expression: {}",
            identifier.as_str()
        ),
        _ => {
            "ORDER BY for grouped queries must reference a projected column or GROUP BY expression"
                .to_string()
        }
    };
    RnovError::new(ErrorKind::InvalidInput, message)
}

fn is_aggregate_expr(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::CountStar
            | Expr::Count(_)
            | Expr::CountDistinct(_)
            | Expr::Sum(_)
            | Expr::Min(_)
            | Expr::Max(_)
    )
}

fn hidden_group_key_nullable(table: &Table, expr: &Expr) -> bool {
    match expr {
        Expr::Identifier(identifier) => table
            .columns()
            .iter()
            .find(|column| column.name().eq_ignore_ascii_case(identifier.as_str()))
            .map(|column| column.nullable())
            .unwrap_or(true),
        Expr::Integer(_) | Expr::Float64(_) | Expr::String(_) | Expr::Bool(_) => false,
        Expr::Null => true,
        Expr::RuntimeValue(value) => value.is_null(),
        _ => true,
    }
}

fn mark_grouping_set_projection_columns_nullable(
    projection: &mut [BoundSelectItem],
    columns: &mut [BoundColumn],
    group_by: &[Expr],
) {
    for (item, column) in projection.iter_mut().zip(columns.iter_mut()) {
        if group_by.iter().any(|expr| expr == &item.expr) {
            item.column.nullable = true;
            column.nullable = true;
        }
    }
}

fn validate_create_function_implementation(
    argument_types: &[SqlType],
    return_type: &SqlType,
    implementation: &CreateFunctionImplementation,
) -> Result<()> {
    let CreateFunctionImplementation::Wasm(body) = implementation else {
        return Ok(());
    };
    validate_wasm_function_signature(argument_types, return_type)?;
    validate_wasm_function_body(body)
}

fn validate_wasm_function_signature(
    argument_types: &[SqlType],
    return_type: &SqlType,
) -> Result<()> {
    if argument_types == [SqlType::Int64] && return_type == &SqlType::Int64 {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::InvalidInput,
        "wasm scalar functions currently require an INT64 argument and INT64 return type",
    ))
}

fn validate_wasm_function_body(body: &WasmFunctionBody) -> Result<()> {
    if body.max_memory_bytes == 0 {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "wasm function memory budget must be greater than zero",
        ));
    }
    let _ = usize::try_from(body.max_memory_bytes).map_err(|_| {
        RnovError::new(
            ErrorKind::InvalidInput,
            "wasm function memory budget does not fit this platform",
        )
    })?;
    let _ = WasmFunctionImplementation::new(
        body.module_bytes.clone(),
        0,
        body.max_memory_bytes,
        body.max_instructions,
        body.timeout_millis,
    )?;
    Ok(())
}

fn query_output_columns(statement: &BoundStatement) -> Result<&[BoundColumn]> {
    match statement {
        BoundStatement::Select(select) => Ok(&select.columns),
        BoundStatement::SelectJoin(join_select) => Ok(&join_select.select.columns),
        BoundStatement::Union(union) => Ok(&union.columns),
        BoundStatement::Intersect(intersect) => Ok(&intersect.columns),
        BoundStatement::Except(except) => Ok(&except.columns),
        BoundStatement::RecursiveCte(cte) => Ok(&cte.query.columns),
        BoundStatement::Query(query) => Ok(&query.columns),
        _ => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "set operation operands must be SELECT queries",
        )),
    }
}

fn single_query_output_type(statement: &BoundStatement) -> Result<SqlType> {
    single_query_output_type_for(statement, "IN subquery")
}

fn single_query_output_type_for(statement: &BoundStatement, context: &str) -> Result<SqlType> {
    let columns = query_output_columns(statement)?;
    match columns {
        [column] => Ok(column.data_type.clone()),
        _ => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "{context} must return exactly one column, got {}",
                columns.len()
            ),
        )),
    }
}

fn recursive_cte_select_input<'a>(
    statement: &'a Statement,
    source: &ObjectName,
) -> Result<CteSelectInput<'a>> {
    let Statement::Select {
        distinct,
        projection,
        from,
        selection,
        group_by,
        having,
        order_by,
        limit,
        offset,
    } = statement
    else {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "recursive CTE clauses currently support SELECT queries only",
        ));
    };
    if !object_names_equal(from, source) {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("recursive CTE SELECT must read from {source}, got {from}"),
        ));
    }
    if !group_by.is_empty() || having.is_some() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "recursive CTE SELECT does not support GROUP BY or HAVING yet",
        ));
    }
    Ok(CteSelectInput {
        distinct: *distinct,
        projection,
        from,
        selection,
        order_by,
        limit: *limit,
        offset: *offset,
    })
}

fn bind_cte_wildcard(
    available_columns: &[BoundColumn],
    projection: &mut Vec<BoundSelectItem>,
    columns: &mut Vec<BoundColumn>,
) {
    for column in available_columns {
        push_cte_projection(
            projection,
            columns,
            column.clone(),
            Expr::Identifier(Ident::new(column.name.as_str())),
        );
    }
}

fn push_cte_projection(
    projection: &mut Vec<BoundSelectItem>,
    columns: &mut Vec<BoundColumn>,
    column: BoundColumn,
    expr: Expr,
) {
    projection.push(BoundSelectItem {
        column: column.clone(),
        expr,
    });
    columns.push(column);
}

fn validate_recursive_cte_name(name: &ObjectName) -> Result<()> {
    if name.schema().is_some() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "recursive CTE name must be unqualified",
        ));
    }
    Ok(())
}

fn recursive_cte_columns(
    seed_columns: &[BoundColumn],
    column_names: &[Ident],
) -> Result<Vec<BoundColumn>> {
    if seed_columns.len() != column_names.len() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "recursive CTE column count mismatch: declared {}, seed returns {}",
                column_names.len(),
                seed_columns.len()
            ),
        ));
    }
    Ok(seed_columns
        .iter()
        .zip(column_names.iter())
        .map(|(column, name)| BoundColumn {
            name: name.as_str().to_string(),
            data_type: column.data_type.clone(),
            nullable: column.nullable,
            encrypted: false,
            generated: None,
        })
        .collect())
}

fn validate_recursive_cte_columns(expected: &[BoundColumn], actual: &[BoundColumn]) -> Result<()> {
    if expected.len() != actual.len() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "recursive CTE column count mismatch: seed returns {}, recursive term returns {}",
                expected.len(),
                actual.len()
            ),
        ));
    }
    for (index, (expected, actual)) in expected.iter().zip(actual.iter()).enumerate() {
        if expected.data_type != actual.data_type {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "recursive CTE column {} type mismatch: seed is {:?}, recursive term is {:?}",
                    index + 1,
                    expected.data_type,
                    actual.data_type
                ),
            ));
        }
    }
    Ok(())
}

fn rename_select_output_columns(select: &mut BoundSelect, names: &[BoundColumn]) {
    for (item, name) in select.projection.iter_mut().zip(names.iter()) {
        item.column.name = name.name.clone();
    }
    for (column, name) in select.columns.iter_mut().zip(names.iter()) {
        column.name = name.name.clone();
    }
}

fn recursive_cte_relation_id(name: &ObjectName) -> RelationId {
    let mut value = 0xcbf2_9ce4_8422_2325u64;
    for byte in name.object().bytes() {
        value ^= u64::from(byte);
        value = value.wrapping_mul(0x0000_0100_0000_01b3);
    }
    RelationId::new(value)
}

fn object_names_equal(left: &ObjectName, right: &ObjectName) -> bool {
    left.schema()
        .map(|schema| {
            right
                .schema()
                .is_some_and(|other| schema.eq_ignore_ascii_case(other))
        })
        .unwrap_or_else(|| right.schema().is_none())
        && left.object().eq_ignore_ascii_case(right.object())
}

fn qualified_index_name(name: &ObjectName, table: &ObjectName) -> ObjectName {
    let table_schema = table.schema().unwrap_or("public");
    let index_schema = name.schema().unwrap_or(table_schema);
    ObjectName::qualified(index_schema, name.object())
}

fn bound_columns_for_table(table: &Table) -> Result<Vec<BoundColumn>> {
    table
        .columns()
        .iter()
        .map(|column| {
            let generated = column
                .generated_expr()
                .map(|expr| {
                    parse_expr(expr).map(|expr| crate::ast::GeneratedColumn {
                        expr,
                        stored: column.generated_stored(),
                    })
                })
                .transpose()?;
            Ok(BoundColumn {
                name: column.name().to_string(),
                data_type: column.data_type().clone(),
                nullable: column.nullable(),
                encrypted: column.is_encrypted(),
                generated,
            })
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LateralColumn {
    side: LateralSide,
    table_name: String,
    source_name: String,
    output_name: String,
    column: BoundColumn,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LateralColumnRef {
    side: LateralSide,
    column: BoundColumn,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LateralSide {
    Outer,
    Inner,
}

fn lateral_join_columns(outer: &Table, inner: &Table) -> Result<Vec<LateralColumn>> {
    join_clause_columns(outer, inner, JoinKind::Inner)
}

fn join_clause_columns(outer: &Table, inner: &Table, kind: JoinKind) -> Result<Vec<LateralColumn>> {
    let mut columns = Vec::new();
    for column in bound_columns_for_table(outer)? {
        columns.push(LateralColumn {
            side: LateralSide::Outer,
            table_name: outer.name().to_string(),
            source_name: column.name.clone(),
            output_name: column.name.clone(),
            column,
        });
    }
    for mut column in bound_columns_for_table(inner)? {
        let source_name = column.name.clone();
        let mut output_name = column.name.clone();
        while columns
            .iter()
            .any(|existing| existing.output_name == output_name)
        {
            output_name = format!("inner_{output_name}");
        }
        if kind == JoinKind::Left {
            column.nullable = true;
        }
        column.name = output_name.clone();
        columns.push(LateralColumn {
            side: LateralSide::Inner,
            table_name: inner.name().to_string(),
            source_name,
            output_name,
            column,
        });
    }
    Ok(columns)
}

fn hash_join_keys(columns: &[LateralColumn], expr: &Expr) -> Option<BoundHashJoinKeys> {
    let Expr::Binary { left, op, right } = expr else {
        return None;
    };
    if op != "=" {
        return None;
    }
    let left = hash_join_column(columns, left)?;
    let right = hash_join_column(columns, right)?;
    if left.column.data_type != right.column.data_type {
        return None;
    }
    match (left.side, right.side) {
        (LateralSide::Outer, LateralSide::Inner) => Some(oriented_hash_join_keys(left, right)),
        (LateralSide::Inner, LateralSide::Outer) => Some(oriented_hash_join_keys(right, left)),
        _ => None,
    }
}

fn hash_join_column<'a>(columns: &'a [LateralColumn], expr: &Expr) -> Option<&'a LateralColumn> {
    let matches = columns
        .iter()
        .filter(|column| hash_join_column_matches(column, expr))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [column] => Some(*column),
        _ => None,
    }
}

fn hash_join_column_matches(column: &LateralColumn, expr: &Expr) -> bool {
    match expr {
        Expr::Identifier(name) => column.output_name.eq_ignore_ascii_case(name.as_str()),
        Expr::QualifiedIdentifier { qualifier, name } => {
            column.table_name.eq_ignore_ascii_case(qualifier.as_str())
                && column.source_name.eq_ignore_ascii_case(name.as_str())
        }
        _ => false,
    }
}

fn oriented_hash_join_keys(left: &LateralColumn, right: &LateralColumn) -> BoundHashJoinKeys {
    BoundHashJoinKeys {
        left_column: left.source_name.clone(),
        right_column: right.source_name.clone(),
    }
}

fn push_lateral_wildcard(
    lateral_columns: &[LateralColumn],
    projection: &mut Vec<BoundSelectItem>,
    columns: &mut Vec<BoundColumn>,
) {
    for lateral_column in lateral_columns {
        projection.push(BoundSelectItem {
            column: lateral_column.column.clone(),
            expr: Expr::Identifier(Ident::new(lateral_column.output_name.as_str())),
        });
        columns.push(lateral_column.column.clone());
    }
}

fn lateral_projection_column(
    lateral_columns: &[LateralColumn],
    output_count: usize,
    expr: &Expr,
    data_type: SqlType,
) -> BoundColumn {
    match expr {
        Expr::Identifier(identifier) => lateral_columns
            .iter()
            .find(|column| column.output_name.eq_ignore_ascii_case(identifier.as_str()))
            .map(|column| column.column.clone())
            .unwrap_or_else(|| expression_output_column(output_count, data_type)),
        _ => expression_output_column(output_count, data_type),
    }
}

fn expression_output_column(output_count: usize, data_type: SqlType) -> BoundColumn {
    BoundColumn {
        name: format!("expr{}", output_count + 1),
        data_type,
        nullable: true,
        encrypted: false,
        generated: None,
    }
}

fn lateral_columns_to_bound(columns: &[LateralColumn]) -> Vec<BoundColumn> {
    columns.iter().map(|column| column.column.clone()).collect()
}

fn outer_lateral_column<'a>(
    columns: &'a [LateralColumn],
    qualifier: &Ident,
    name: &Ident,
) -> Result<Option<&'a LateralColumn>> {
    let matches = columns
        .iter()
        .filter(|column| {
            column.table_name.eq_ignore_ascii_case(qualifier.as_str())
                && column.source_name.eq_ignore_ascii_case(name.as_str())
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [column] => Ok(Some(*column)),
        [] => Ok(None),
        _ => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("ambiguous outer column reference: {qualifier}.{name}"),
        )),
    }
}

fn typed_null_expr(data_type: SqlType) -> Expr {
    Expr::Cast {
        expr: Box::new(Expr::Null),
        data_type,
    }
}

fn join_expr_column(
    joined_columns: &[LateralColumn],
    existing_columns: &[BoundColumn],
    expr: &Expr,
    data_type: SqlType,
) -> BoundColumn {
    if let Expr::Identifier(identifier) = expr
        && let Some(column) = joined_columns
            .iter()
            .find(|column| column.output_name.eq_ignore_ascii_case(identifier.as_str()))
    {
        return column.column.clone();
    }
    BoundColumn {
        name: format!("expr{}", existing_columns.len() + 1),
        data_type,
        nullable: true,
        encrypted: false,
        generated: None,
    }
}

fn validate_set_operation_columns(
    operation: &str,
    left: &BoundStatement,
    right: &BoundStatement,
) -> Result<Vec<BoundColumn>> {
    let left_columns = query_output_columns(left)?;
    let right_columns = query_output_columns(right)?;
    if left_columns.len() != right_columns.len() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "{operation} column count mismatch: left has {}, right has {}",
                left_columns.len(),
                right_columns.len()
            ),
        ));
    }
    for (index, (left, right)) in left_columns.iter().zip(right_columns.iter()).enumerate() {
        if left.data_type != right.data_type {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "{operation} column {} type mismatch: left is {:?}, right is {:?}",
                    index + 1,
                    left.data_type,
                    right.data_type
                ),
            ));
        }
    }
    Ok(left_columns.to_vec())
}

fn bind_count_star_projection(
    alias: &Option<Ident>,
    mut outputs: ProjectionOutputs<'_>,
) -> Result<()> {
    let column = aggregate_bound_column(outputs.columns, "count", SqlType::Int64, false);
    let column = aliased_bound_column(column, alias);
    push_select_projection(&mut outputs, column, Expr::CountStar);
    Ok(())
}

fn push_select_projection(outputs: &mut ProjectionOutputs<'_>, column: BoundColumn, expr: Expr) {
    outputs.projection.push(BoundSelectItem {
        column: column.clone(),
        expr,
    });
    outputs.columns.push(column);
}

fn aggregate_bound_column(
    existing_columns: &[BoundColumn],
    base_name: &str,
    data_type: SqlType,
    nullable: bool,
) -> BoundColumn {
    BoundColumn {
        name: unique_column_name(existing_columns, base_name),
        data_type,
        nullable,
        encrypted: false,
        generated: None,
    }
}

fn aliased_bound_column(mut column: BoundColumn, alias: &Option<Ident>) -> BoundColumn {
    if let Some(alias) = alias {
        column.name = alias.as_str().to_string();
    }
    column
}

fn unique_column_name(existing_columns: &[BoundColumn], base_name: &str) -> String {
    if !existing_columns
        .iter()
        .any(|column| column.name == base_name)
    {
        return base_name.to_string();
    }

    for suffix in 2.. {
        let candidate = format!("{base_name}{suffix}");
        if !existing_columns
            .iter()
            .any(|column| column.name == candidate)
        {
            return candidate;
        }
    }
    unreachable!("unbounded suffix search must find a unique aggregate column name")
}

fn validate_sql_procedure_body(body: &str) -> Result<()> {
    if matches!(
        parse_statement(procedure_body_parse_probe(body).as_str())?,
        Statement::Transaction {
            action: TransactionAction::Begin
                | TransactionAction::Commit
                | TransactionAction::Rollback
        }
    ) {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "transaction control is not allowed in SQL procedure bodies",
        ));
    }
    Ok(())
}

fn validate_trigger_sql_body(body: &str) -> Result<()> {
    let statement = parse_statement(body)?;
    if matches!(
        statement,
        Statement::Insert { .. } | Statement::Update { .. } | Statement::Delete { .. }
    ) {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::InvalidInput,
        "trigger SQL body must be INSERT, UPDATE, or DELETE",
    ))
}

fn procedure_argument_type(expr: &Expr) -> Result<SqlType> {
    match expr {
        Expr::Integer(_) => Ok(SqlType::Int64),
        Expr::Float64(_) => Ok(SqlType::Float64),
        Expr::String(_) => Ok(SqlType::Text),
        Expr::Bool(_) => Ok(SqlType::Bool),
        Expr::Null => Ok(SqlType::Null),
        _ => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "procedure arguments must be literal values",
        )),
    }
}

fn procedure_body_parse_probe(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '$' || !chars.peek().is_some_and(|next| next.is_ascii_digit()) {
            out.push(ch);
            continue;
        }
        while chars.peek().is_some_and(|next| next.is_ascii_digit()) {
            let _ = chars.next();
        }
        out.push_str("NULL");
    }
    out
}

fn format_procedure_name(procedure: &rnmdb_catalog::Procedure) -> String {
    let arguments = procedure
        .argument_types()
        .iter()
        .map(format_sql_type)
        .collect::<Vec<_>>()
        .join(", ");
    format!("procedure {}({arguments})", procedure.name())
}

fn format_sql_type(data_type: &SqlType) -> String {
    match data_type {
        SqlType::Null => "NULL".to_string(),
        SqlType::Bool => "BOOL".to_string(),
        SqlType::Int64 => "INT64".to_string(),
        SqlType::UInt64 => "UINT64".to_string(),
        SqlType::Float64 => "FLOAT64".to_string(),
        SqlType::Uuid => "UUID".to_string(),
        SqlType::Timestamp => "TIMESTAMP".to_string(),
        SqlType::Json => "JSON".to_string(),
        SqlType::Text => "TEXT".to_string(),
        SqlType::Bytes => "BYTES".to_string(),
        SqlType::HStore => "HSTORE".to_string(),
        SqlType::TextVector => "TEXTVECTOR".to_string(),
        SqlType::Array(element) => format!("ARRAY<{}>", format_sql_type(element)),
        SqlType::Range(element) => format!("RANGE<{}>", format_sql_type(element)),
    }
}
