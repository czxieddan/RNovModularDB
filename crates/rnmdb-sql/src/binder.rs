use rnmdb_catalog::{Catalog, OperatorSignature, Privilege, Table};
use rnmdb_common::{
    ErrorKind, Result, RnovError,
    ids::{RelationId, RoleId},
};
use rnmdb_types::SqlType;

use crate::ast::{
    Assignment, BoundAssignment, BoundColumn, BoundDelete, BoundRowPolicy, BoundSelect,
    BoundSelectItem, BoundStatement, BoundUpdate, Expr, Ident, ObjectName, SelectItem, Statement,
};
use crate::parser::parse_expr;

pub struct Binder<'a> {
    catalog: &'a Catalog,
}

impl<'a> Binder<'a> {
    pub fn new(catalog: &'a Catalog) -> Self {
        Self { catalog }
    }

    pub fn bind_for_role(&self, statement: &Statement, role_id: RoleId) -> Result<BoundStatement> {
        match statement {
            Statement::CreateTable { name, columns } => Ok(BoundStatement::CreateTable {
                name: name.clone(),
                columns: columns.clone(),
            }),
            Statement::AlterTableAddColumn { table, column } => {
                let resolved = self.resolve_table(table)?;
                Ok(BoundStatement::AlterTableAddColumn {
                    relation_id: resolved.relation_id(),
                    table: table.clone(),
                    column: column.clone(),
                })
            }
            Statement::DropTable { name, if_exists } => self.bind_drop_table(name, *if_exists),
            Statement::CreateFunction {
                name,
                argument_types,
                return_type,
            } => Ok(BoundStatement::CreateFunction {
                name: name.clone(),
                argument_types: argument_types.clone(),
                return_type: return_type.clone(),
            }),
            Statement::CreateOperator {
                symbol,
                left_type,
                right_type,
                result_type,
                function,
            } => self.bind_create_operator(
                symbol,
                left_type,
                right_type,
                result_type,
                function.as_str(),
            ),
            Statement::CreateRole { name } => Ok(BoundStatement::CreateRole { name: name.clone() }),
            Statement::CreatePolicy {
                name,
                table,
                predicate,
            } => {
                let table = self.resolve_table(table)?;
                Ok(BoundStatement::CreatePolicy {
                    name: name.clone(),
                    relation_id: table.relation_id(),
                    predicate: predicate.to_string(),
                })
            }
            Statement::GrantTablePrivilege {
                privilege,
                table,
                role,
            } => {
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
                    privilege: *privilege,
                })
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
                projection,
                from,
                selection,
                limit,
            } => self.bind_select(projection, from, selection, *limit, role_id),
            Statement::Transaction { action } => {
                Ok(BoundStatement::Transaction { action: *action })
            }
            Statement::Explain { analyze, statement } => Ok(BoundStatement::Explain {
                analyze: *analyze,
                statement: Box::new(self.bind_for_role(statement, role_id)?),
            }),
        }
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

    fn bind_create_operator(
        &self,
        symbol: &str,
        left_type: &SqlType,
        right_type: &SqlType,
        result_type: &SqlType,
        function_name: &str,
    ) -> Result<BoundStatement> {
        let argument_types = [left_type.clone(), right_type.clone()];
        let function = self
            .catalog
            .functions()
            .iter()
            .find(|function| {
                function.name() == function_name
                    && function.argument_types() == argument_types
                    && function.return_type() == result_type
            })
            .ok_or_else(|| {
                RnovError::new(
                    ErrorKind::NotFound,
                    format!("function does not exist for operator {symbol}: {function_name}"),
                )
            })?;

        Ok(BoundStatement::CreateOperator {
            signature: OperatorSignature::new(
                symbol,
                left_type.clone(),
                right_type.clone(),
                result_type.clone(),
                function.function_id(),
            ),
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
        for (ident, value) in columns.iter().zip(values) {
            let column = self.resolve_column(table, ident.as_str())?;
            self.ensure_expr_assignable(table, &column, value)?;
            bound_columns.push(column);
        }
        Ok(BoundStatement::Insert {
            table: table_name.clone(),
            columns: bound_columns,
            values: values.to_vec(),
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

        let mut bound_assignments = Vec::with_capacity(assignments.len());
        for assignment in assignments {
            let column = self.resolve_column(table, assignment.column.as_str())?;
            self.ensure_expr_assignable(table, &column, &assignment.value)?;
            bound_assignments.push(BoundAssignment {
                column,
                value: assignment.value.clone(),
            });
        }
        if let Some(selection) = selection {
            self.validate_predicate(table, selection)?;
        }

        Ok(BoundStatement::Update(BoundUpdate {
            relation_id: table.relation_id(),
            table: table_name.clone(),
            assignments: bound_assignments,
            selection: selection.clone(),
            applied_row_policies: self.applied_row_policy_names(table.relation_id()),
            row_policy_predicates: self.bind_row_policies(table)?,
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
        if let Some(selection) = selection {
            self.validate_predicate(table, selection)?;
        }

        Ok(BoundStatement::Delete(BoundDelete {
            relation_id: table.relation_id(),
            table: table_name.clone(),
            selection: selection.clone(),
            applied_row_policies: self.applied_row_policy_names(table.relation_id()),
            row_policy_predicates: self.bind_row_policies(table)?,
        }))
    }

    fn bind_select(
        &self,
        select_items: &[SelectItem],
        from: &ObjectName,
        selection: &Option<Expr>,
        limit: Option<usize>,
        role_id: RoleId,
    ) -> Result<BoundStatement> {
        let table = self.resolve_table(from)?;
        self.require_table_privilege(role_id, table.relation_id(), Privilege::Select)?;

        let mut columns = Vec::new();
        let mut projection = Vec::new();
        for item in select_items {
            match item {
                SelectItem::Wildcard => {
                    for column in table.columns() {
                        let bound_column = BoundColumn {
                            name: column.name().to_string(),
                            data_type: column.data_type().clone(),
                            nullable: column.nullable(),
                            encrypted: column.is_encrypted(),
                        };
                        projection.push(BoundSelectItem {
                            column: bound_column.clone(),
                            expr: Expr::Identifier(Ident::new(column.name())),
                        });
                        columns.push(bound_column);
                    }
                }
                SelectItem::Expr(Expr::Identifier(identifier)) => {
                    let column = self.resolve_column(table, identifier.as_str())?;
                    projection.push(BoundSelectItem {
                        column: column.clone(),
                        expr: Expr::Identifier(identifier.clone()),
                    });
                    columns.push(column);
                }
                SelectItem::Expr(expr) => {
                    let data_type = self.infer_expr_type(table, expr)?.ok_or_else(|| {
                        RnovError::new(
                            ErrorKind::InvalidInput,
                            format!("cannot infer select expression type: {expr}"),
                        )
                    })?;
                    let column = BoundColumn {
                        name: format!("expr{}", columns.len() + 1),
                        data_type,
                        nullable: true,
                        encrypted: false,
                    };
                    projection.push(BoundSelectItem {
                        column: column.clone(),
                        expr: expr.clone(),
                    });
                    columns.push(column);
                }
            }
        }

        if let Some(selection) = selection {
            self.validate_predicate(table, selection)?;
        }

        Ok(BoundStatement::Select(BoundSelect {
            relation_id: table.relation_id(),
            table: from.clone(),
            projection,
            columns,
            selection: selection.clone(),
            limit,
            applied_row_policies: self.applied_row_policy_names(table.relation_id()),
            row_policy_predicates: self.bind_row_policies(table)?,
        }))
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
        let column = table
            .columns()
            .iter()
            .find(|column| column.name() == column_name)
            .ok_or_else(|| {
                RnovError::new(
                    ErrorKind::NotFound,
                    format!("column does not exist: {}.{column_name}", table.name()),
                )
            })?;

        Ok(BoundColumn {
            name: column.name().to_string(),
            data_type: column.data_type().clone(),
            nullable: column.nullable(),
            encrypted: column.is_encrypted(),
        })
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

    fn applied_row_policy_names(&self, relation_id: RelationId) -> Vec<String> {
        self.catalog
            .row_policies(relation_id)
            .iter()
            .map(|policy| policy.name().to_string())
            .collect()
    }

    fn bind_row_policies(&self, table: &Table) -> Result<Vec<BoundRowPolicy>> {
        self.catalog
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
            .collect()
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
            Expr::Integer(_) => Ok(Some(SqlType::Int64)),
            Expr::String(_) => Ok(Some(SqlType::Text)),
            Expr::Null => Ok(Some(SqlType::Null)),
            Expr::Array(values) => {
                let mut element_type = None;
                for value in values {
                    let Some(value_type) = self.infer_policy_expr_type(table, value)? else {
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
            Expr::HStore(_) => Ok(Some(SqlType::HStore)),
            Expr::Range { lower, upper, .. } => {
                let Some(lower_type) = self.infer_policy_expr_type(table, lower)? else {
                    return Ok(None);
                };
                let Some(upper_type) = self.infer_policy_expr_type(table, upper)? else {
                    return Ok(None);
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
            Expr::Call { name, args } => {
                let mut argument_types = Vec::with_capacity(args.len());
                for arg in args {
                    let Some(arg_type) = self.infer_policy_expr_type(table, arg)? else {
                        return Ok(None);
                    };
                    argument_types.push(arg_type);
                }

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
            Expr::Integer(_) => Ok(Some(SqlType::Int64)),
            Expr::String(_) => Ok(Some(SqlType::Text)),
            Expr::Null => Ok(Some(SqlType::Null)),
            Expr::Array(values) => {
                let mut element_type = None;
                for value in values {
                    let Some(value_type) = self.infer_expr_type(table, value)? else {
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
            Expr::HStore(_) => Ok(Some(SqlType::HStore)),
            Expr::Range { lower, upper, .. } => {
                let lower_type = self.infer_expr_type(table, lower)?.unwrap_or(SqlType::Null);
                let upper_type = self.infer_expr_type(table, upper)?.unwrap_or(SqlType::Null);
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
            Expr::Binary { left, right, .. } => {
                let Some(left_type) = self.infer_expr_type(table, left)? else {
                    return Ok(None);
                };
                let Some(right_type) = self.infer_expr_type(table, right)? else {
                    return Ok(None);
                };
                self.infer_operator_result_type(expr, &left_type, &right_type)
            }
            Expr::Call { name, args } => {
                let mut argument_types = Vec::with_capacity(args.len());
                for arg in args {
                    let Some(arg_type) = self.infer_expr_type(table, arg)? else {
                        return Ok(None);
                    };
                    argument_types.push(arg_type);
                }

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
}

fn policy_unknown_side_operator_type(expr: &Expr) -> Option<SqlType> {
    let Expr::Binary { op, .. } = expr else {
        return None;
    };

    if matches!(op.as_str(), "=" | "<>" | "!=" | "<" | "<=" | ">" | ">=") {
        Some(SqlType::Bool)
    } else {
        None
    }
}
