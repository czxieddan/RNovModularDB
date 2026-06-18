use rnovdb_catalog::{Catalog, OperatorSignature, Privilege, Table};
use rnovdb_common::{
    ErrorKind, Result, RnovError,
    ids::{RelationId, RoleId},
};

use crate::ast::{
    BoundColumn, BoundSelect, BoundStatement, Expr, ObjectName, SelectItem, Statement,
};

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
            } => self.bind_insert(table, columns, values),
            Statement::Select {
                projection,
                from,
                selection,
            } => self.bind_select(projection, from, selection, role_id),
        }
    }

    fn bind_create_operator(
        &self,
        symbol: &str,
        left_type: &rnovdb_types::SqlType,
        right_type: &rnovdb_types::SqlType,
        result_type: &rnovdb_types::SqlType,
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
    ) -> Result<BoundStatement> {
        let table = self.resolve_table(table_name)?;
        let mut bound_columns = Vec::with_capacity(columns.len());
        for ident in columns {
            bound_columns.push(self.resolve_column(table, ident.as_str())?);
        }
        Ok(BoundStatement::Insert {
            table: table_name.clone(),
            columns: bound_columns,
            values: values.to_vec(),
        })
    }

    fn bind_select(
        &self,
        projection: &[SelectItem],
        from: &ObjectName,
        selection: &Option<Expr>,
        role_id: RoleId,
    ) -> Result<BoundStatement> {
        let table = self.resolve_table(from)?;
        self.require_table_privilege(role_id, table.relation_id(), Privilege::Select)?;

        let mut columns = Vec::new();
        for item in projection {
            match item {
                SelectItem::Wildcard => {
                    columns.extend(table.columns().iter().map(|column| BoundColumn {
                        name: column.name().to_string(),
                        data_type: column.data_type().clone(),
                        nullable: column.nullable(),
                        encrypted: column.is_encrypted(),
                    }));
                }
                SelectItem::Expr(Expr::Identifier(identifier)) => {
                    columns.push(self.resolve_column(table, identifier.as_str())?);
                }
                SelectItem::Expr(expr) => {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        format!("select expression is not bindable yet: {expr}"),
                    ));
                }
            }
        }

        if let Some(selection) = selection {
            self.validate_expression_columns(table, selection)?;
        }

        let applied_row_policies = self
            .catalog
            .row_policies(table.relation_id())
            .iter()
            .map(|policy| policy.name().to_string())
            .collect();

        Ok(BoundStatement::Select(BoundSelect {
            relation_id: table.relation_id(),
            table: from.clone(),
            columns,
            selection: selection.clone(),
            applied_row_policies,
        }))
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

    fn validate_expression_columns(&self, table: &Table, expr: &Expr) -> Result<()> {
        match expr {
            Expr::Identifier(identifier) => {
                let _ = self.resolve_column(table, identifier.as_str())?;
            }
            Expr::Binary { left, right, .. } => {
                self.validate_expression_columns(table, left)?;
                self.validate_expression_columns(table, right)?;
            }
            Expr::Call { args, .. } => {
                for arg in args {
                    self.validate_expression_columns(table, arg)?;
                }
            }
            Expr::Integer(_) | Expr::String(_) | Expr::Null => {}
        }
        Ok(())
    }
}
