use rnovdb_catalog::{Catalog, Privilege, Table};
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
