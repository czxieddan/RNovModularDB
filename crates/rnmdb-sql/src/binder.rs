use rnmdb_catalog::{Catalog, OperatorSignature, Privilege, Table};
use rnmdb_common::{
    ErrorKind, Result, RnovError,
    ids::{RelationId, RoleId},
};
use rnmdb_types::SqlType;

use crate::ast::{
    Assignment, BoundAssignment, BoundColumn, BoundDelete, BoundExcept, BoundIntersect, BoundQuery,
    BoundRowPolicy, BoundSelect, BoundSelectItem, BoundStatement, BoundUnion, BoundUpdate,
    CaseWhen, Expr, Ident, ObjectName, OrderByExpr, SelectItem, Statement,
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
                *distinct, projection, from, selection, group_by, having, order_by, *limit,
                *offset, role_id,
            ),
            Statement::Union { all, left, right } => self.bind_union(*all, left, right, role_id),
            Statement::Intersect { all, left, right } => {
                self.bind_intersect(*all, left, right, role_id)
            }
            Statement::Except { all, left, right } => self.bind_except(*all, left, right, role_id),
            Statement::Query {
                input,
                order_by,
                limit,
                offset,
            } => self.bind_query(input, order_by, *limit, *offset, role_id),
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

    fn bind_query(
        &self,
        input: &Statement,
        order_by: &[OrderByExpr],
        limit: Option<usize>,
        offset: Option<usize>,
        role_id: RoleId,
    ) -> Result<BoundStatement> {
        let input = self.bind_for_role(input, role_id)?;
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

    fn bind_except(
        &self,
        all: bool,
        left: &Statement,
        right: &Statement,
        role_id: RoleId,
    ) -> Result<BoundStatement> {
        let left = self.bind_for_role(left, role_id)?;
        let right = self.bind_for_role(right, role_id)?;
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

    fn bind_union(
        &self,
        all: bool,
        left: &Statement,
        right: &Statement,
        role_id: RoleId,
    ) -> Result<BoundStatement> {
        let left = self.bind_for_role(left, role_id)?;
        let right = self.bind_for_role(right, role_id)?;
        let columns = validate_set_operation_columns("UNION", &left, &right)?;
        Ok(BoundStatement::Union(BoundUnion {
            all,
            columns,
            left: Box::new(left),
            right: Box::new(right),
        }))
    }

    fn bind_intersect(
        &self,
        all: bool,
        left: &Statement,
        right: &Statement,
        role_id: RoleId,
    ) -> Result<BoundStatement> {
        let left = self.bind_for_role(left, role_id)?;
        let right = self.bind_for_role(right, role_id)?;
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
        distinct: bool,
        select_items: &[SelectItem],
        from: &ObjectName,
        selection: &Option<Expr>,
        group_by: &[Expr],
        having: &Option<Expr>,
        order_by: &[crate::ast::OrderByExpr],
        limit: Option<usize>,
        offset: Option<usize>,
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
                SelectItem::Expr {
                    expr: Expr::Identifier(identifier),
                    alias,
                } => {
                    let column = self.resolve_column(table, identifier.as_str())?;
                    let column = aliased_bound_column(column, alias);
                    projection.push(BoundSelectItem {
                        column: column.clone(),
                        expr: Expr::Identifier(identifier.clone()),
                    });
                    columns.push(column);
                }
                SelectItem::Expr {
                    expr: Expr::CountStar,
                    alias,
                } => {
                    let column = aggregate_bound_column(&columns, "count", SqlType::Int64, false);
                    let column = aliased_bound_column(column, alias);
                    projection.push(BoundSelectItem {
                        column: column.clone(),
                        expr: Expr::CountStar,
                    });
                    columns.push(column);
                }
                SelectItem::Expr {
                    expr: Expr::Count(expr),
                    alias,
                } => {
                    let _ = self.infer_expr_type(table, expr)?.ok_or_else(|| {
                        RnovError::new(
                            ErrorKind::InvalidInput,
                            format!("cannot infer COUNT expression type: {expr}"),
                        )
                    })?;
                    let column = aggregate_bound_column(&columns, "count", SqlType::Int64, false);
                    let column = aliased_bound_column(column, alias);
                    projection.push(BoundSelectItem {
                        column: column.clone(),
                        expr: Expr::Count(expr.clone()),
                    });
                    columns.push(column);
                }
                SelectItem::Expr {
                    expr: Expr::CountDistinct(expr),
                    alias,
                } => {
                    let _ = self.infer_expr_type(table, expr)?.ok_or_else(|| {
                        RnovError::new(
                            ErrorKind::InvalidInput,
                            format!("cannot infer COUNT DISTINCT expression type: {expr}"),
                        )
                    })?;
                    let column = aggregate_bound_column(&columns, "count", SqlType::Int64, false);
                    let column = aliased_bound_column(column, alias);
                    projection.push(BoundSelectItem {
                        column: column.clone(),
                        expr: Expr::CountDistinct(expr.clone()),
                    });
                    columns.push(column);
                }
                SelectItem::Expr {
                    expr: Expr::Sum(expr),
                    alias,
                } => {
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
                    let column = aggregate_bound_column(&columns, "sum", SqlType::Int64, true);
                    let column = aliased_bound_column(column, alias);
                    projection.push(BoundSelectItem {
                        column: column.clone(),
                        expr: Expr::Sum(expr.clone()),
                    });
                    columns.push(column);
                }
                SelectItem::Expr {
                    expr: Expr::Min(expr),
                    alias,
                } => {
                    let expr_type = self.infer_expr_type(table, expr)?.ok_or_else(|| {
                        RnovError::new(
                            ErrorKind::InvalidInput,
                            format!("cannot infer MIN expression type: {expr}"),
                        )
                    })?;
                    self.ensure_ordered_aggregate_type("MIN", &expr_type)?;
                    let column = aggregate_bound_column(&columns, "min", expr_type, true);
                    let column = aliased_bound_column(column, alias);
                    projection.push(BoundSelectItem {
                        column: column.clone(),
                        expr: Expr::Min(expr.clone()),
                    });
                    columns.push(column);
                }
                SelectItem::Expr {
                    expr: Expr::Max(expr),
                    alias,
                } => {
                    let expr_type = self.infer_expr_type(table, expr)?.ok_or_else(|| {
                        RnovError::new(
                            ErrorKind::InvalidInput,
                            format!("cannot infer MAX expression type: {expr}"),
                        )
                    })?;
                    self.ensure_ordered_aggregate_type("MAX", &expr_type)?;
                    let column = aggregate_bound_column(&columns, "max", expr_type, true);
                    let column = aliased_bound_column(column, alias);
                    projection.push(BoundSelectItem {
                        column: column.clone(),
                        expr: Expr::Max(expr.clone()),
                    });
                    columns.push(column);
                }
                SelectItem::Expr { expr, alias } => {
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
                    let column = aliased_bound_column(column, alias);
                    projection.push(BoundSelectItem {
                        column: column.clone(),
                        expr: expr.clone(),
                    });
                    columns.push(column);
                }
            }
        }
        let aggregate_count = projection
            .iter()
            .filter(|item| is_aggregate_expr(&item.expr))
            .count();
        let bound_group_by = self.bind_group_by_exprs(&projection, group_by)?;
        if !bound_group_by.is_empty() {
            self.validate_group_by_exprs(table, &bound_group_by)?;
        }
        if aggregate_count > 0 && aggregate_count != projection.len() {
            self.validate_grouped_projection(&projection, &bound_group_by)?;
        }
        if aggregate_count == 0 && !bound_group_by.is_empty() {
            self.validate_grouped_projection(&projection, &bound_group_by)?;
        }
        let having = if let Some(having) = having {
            if bound_group_by.is_empty() && aggregate_count == 0 {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "HAVING requires GROUP BY or aggregate projection in this SQL slice",
                ));
            }
            let having = self.rewrite_grouped_having_expr(&projection, having)?;
            self.validate_grouped_having_expr(&projection, &having)?;
            Some(having)
        } else {
            None
        };
        if let Some(selection) = selection {
            self.validate_predicate(table, selection)?;
        }
        let mut bound_order_by = Vec::with_capacity(order_by.len());
        for order_by in order_by {
            if group_by.is_empty() {
                if aggregate_count > 0 {
                    bound_order_by.push(self.bind_grouped_sort_expr(
                        table,
                        &projection,
                        &bound_group_by,
                        order_by,
                    )?);
                } else {
                    bound_order_by.push(self.bind_plain_sort_expr(table, &projection, order_by)?);
                }
            } else {
                bound_order_by.push(self.bind_grouped_sort_expr(
                    table,
                    &projection,
                    &bound_group_by,
                    order_by,
                )?);
            }
        }

        Ok(BoundStatement::Select(BoundSelect {
            relation_id: table.relation_id(),
            table: from.clone(),
            distinct,
            projection,
            columns,
            selection: selection.clone(),
            group_by: bound_group_by,
            having,
            order_by: bound_order_by,
            limit,
            offset,
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

    fn validate_sort_expr(&self, table: &Table, expr: &Expr) -> Result<()> {
        match self.infer_expr_type(table, expr)? {
            Some(
                SqlType::Null
                | SqlType::Bool
                | SqlType::Int64
                | SqlType::UInt64
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

    fn bind_plain_sort_expr(
        &self,
        table: &Table,
        projection: &[BoundSelectItem],
        order_by: &OrderByExpr,
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
        group_by: &[Expr],
        order_by: &OrderByExpr,
    ) -> Result<OrderByExpr> {
        let expr = match &order_by.expr {
            Expr::Integer(value) => Expr::Identifier(Ident::new(
                self.projection_ordinal_item(projection, *value, "ORDER BY")?
                    .column
                    .name
                    .as_str(),
            )),
            _ => projection
                .iter()
                .find(|item| item.expr == order_by.expr)
                .map(|item| Expr::Identifier(Ident::new(item.column.name.as_str())))
                .unwrap_or_else(|| order_by.expr.clone()),
        };
        self.validate_grouped_sort_expr(table, projection, group_by, &expr)?;
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
        projection: &[BoundSelectItem],
        group_by: &[Expr],
    ) -> Result<Vec<Expr>> {
        group_by
            .iter()
            .map(|expr| match expr {
                Expr::Integer(value) => Ok(self
                    .projection_ordinal_item(projection, *value, "GROUP BY")?
                    .expr
                    .clone()),
                Expr::Identifier(identifier) => Ok(projection
                    .iter()
                    .find(|item| item.column.name.eq_ignore_ascii_case(identifier.as_str()))
                    .map(|item| item.expr.clone())
                    .unwrap_or_else(|| expr.clone())),
                _ => Ok(expr.clone()),
            })
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
            | Expr::Integer(_)
            | Expr::String(_)
            | Expr::Bool(_)
            | Expr::Null
            | Expr::HStore(_) => Ok(()),
            Expr::Array(values) => values
                .iter()
                .try_for_each(|value| self.validate_group_by_expr_shape(value)),
            Expr::Range { lower, upper, .. } => {
                self.validate_group_by_expr_shape(lower)?;
                self.validate_group_by_expr_shape(upper)
            }
            Expr::Binary { left, op, right } => {
                if !matches!(
                    op.as_str(),
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
                self.validate_group_by_expr_shape(left)?;
                self.validate_group_by_expr_shape(right)
            }
            Expr::Unary { op, expr } => {
                if !matches!(op.as_str(), "+" | "-") {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        format!("GROUP BY does not support unary operator {op} yet"),
                    ));
                }
                self.validate_group_by_expr_shape(expr)
            }
            Expr::Not(expr) => self.validate_group_by_expr_shape(expr),
            Expr::IsNull { expr, .. } => self.validate_group_by_expr_shape(expr),
            Expr::IsTruth { expr, .. } => self.validate_group_by_expr_shape(expr),
            Expr::IsUnknown { expr, .. } => self.validate_group_by_expr_shape(expr),
            Expr::IsDistinctFrom { left, right, .. } => {
                self.validate_group_by_expr_shape(left)?;
                self.validate_group_by_expr_shape(right)
            }
            Expr::Between {
                expr, low, high, ..
            } => {
                self.validate_group_by_expr_shape(expr)?;
                self.validate_group_by_expr_shape(low)?;
                self.validate_group_by_expr_shape(high)
            }
            Expr::InList { expr, values, .. } => {
                self.validate_group_by_expr_shape(expr)?;
                values
                    .iter()
                    .try_for_each(|value| self.validate_group_by_expr_shape(value))
            }
            Expr::Like { expr, pattern, .. } => {
                self.validate_group_by_expr_shape(expr)?;
                self.validate_group_by_expr_shape(pattern)
            }
            Expr::Coalesce(values) => values
                .iter()
                .try_for_each(|value| self.validate_group_by_expr_shape(value)),
            Expr::NullIf { left, right } => {
                self.validate_group_by_expr_shape(left)?;
                self.validate_group_by_expr_shape(right)
            }
            Expr::Case {
                operand,
                whens,
                else_expr,
            } => {
                if let Some(operand) = operand {
                    self.validate_group_by_expr_shape(operand)?;
                }
                for arm in whens {
                    self.validate_group_by_expr_shape(&arm.condition)?;
                    self.validate_group_by_expr_shape(&arm.result)?;
                }
                if let Some(else_expr) = else_expr {
                    self.validate_group_by_expr_shape(else_expr)?;
                }
                Ok(())
            }
            Expr::Cast { expr, .. } => self.validate_group_by_expr_shape(expr),
            Expr::CountStar
            | Expr::Count(_)
            | Expr::CountDistinct(_)
            | Expr::Sum(_)
            | Expr::Min(_)
            | Expr::Max(_) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "GROUP BY does not support aggregate expressions",
            )),
            Expr::Call { .. } => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "GROUP BY does not support function calls yet",
            )),
        }
    }

    fn validate_grouped_sort_expr(
        &self,
        table: &Table,
        projection: &[BoundSelectItem],
        group_by: &[Expr],
        expr: &Expr,
    ) -> Result<()> {
        if let Expr::Identifier(identifier) = expr {
            if let Some(column) = projection
                .iter()
                .find(|item| item.column.name.eq_ignore_ascii_case(identifier.as_str()))
            {
                return self.ensure_sortable_type(&column.column.data_type);
            }
        }
        if group_by.iter().any(|group| group == expr) {
            return match self.infer_expr_type(table, expr)? {
                Some(data_type) => self.ensure_sortable_type(&data_type),
                None => Ok(()),
            };
        }
        Err(RnovError::new(
            ErrorKind::InvalidInput,
            match expr {
                Expr::Identifier(identifier) => format!(
                    "ORDER BY for grouped queries must reference a projected column or GROUP BY expression: {}",
                    identifier.as_str()
                ),
                _ => "ORDER BY for grouped queries must reference a projected column or GROUP BY expression".to_string(),
            },
        ))
    }

    fn ensure_sortable_type(&self, data_type: &SqlType) -> Result<()> {
        match data_type {
            SqlType::Null
            | SqlType::Bool
            | SqlType::Int64
            | SqlType::UInt64
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
        projection: &[BoundSelectItem],
        expr: &Expr,
    ) -> Result<Expr> {
        match expr {
            Expr::CountStar
            | Expr::Count(_)
            | Expr::CountDistinct(_)
            | Expr::Sum(_)
            | Expr::Min(_)
            | Expr::Max(_) => projection
                .iter()
                .find(|item| &item.expr == expr)
                .map(|item| Expr::Identifier(Ident::new(item.column.name.as_str())))
                .ok_or_else(|| {
                    RnovError::new(
                        ErrorKind::InvalidInput,
                        format!(
                            "HAVING aggregate expression must appear in SELECT projection: {expr}"
                        ),
                    )
                }),
            Expr::Binary { left, op, right } => Ok(Expr::Binary {
                left: Box::new(self.rewrite_grouped_having_expr(projection, left)?),
                op: op.clone(),
                right: Box::new(self.rewrite_grouped_having_expr(projection, right)?),
            }),
            Expr::Unary { op, expr } => Ok(Expr::Unary {
                op: op.clone(),
                expr: Box::new(self.rewrite_grouped_having_expr(projection, expr)?),
            }),
            Expr::Not(expr) => Ok(Expr::Not(Box::new(
                self.rewrite_grouped_having_expr(projection, expr)?,
            ))),
            Expr::IsNull { expr, negated } => Ok(Expr::IsNull {
                expr: Box::new(self.rewrite_grouped_having_expr(projection, expr)?),
                negated: *negated,
            }),
            Expr::IsTruth {
                expr,
                value,
                negated,
            } => Ok(Expr::IsTruth {
                expr: Box::new(self.rewrite_grouped_having_expr(projection, expr)?),
                value: *value,
                negated: *negated,
            }),
            Expr::IsUnknown { expr, negated } => Ok(Expr::IsUnknown {
                expr: Box::new(self.rewrite_grouped_having_expr(projection, expr)?),
                negated: *negated,
            }),
            Expr::IsDistinctFrom {
                left,
                right,
                negated,
            } => Ok(Expr::IsDistinctFrom {
                left: Box::new(self.rewrite_grouped_having_expr(projection, left)?),
                right: Box::new(self.rewrite_grouped_having_expr(projection, right)?),
                negated: *negated,
            }),
            Expr::Between {
                expr,
                low,
                high,
                negated,
            } => Ok(Expr::Between {
                expr: Box::new(self.rewrite_grouped_having_expr(projection, expr)?),
                low: Box::new(self.rewrite_grouped_having_expr(projection, low)?),
                high: Box::new(self.rewrite_grouped_having_expr(projection, high)?),
                negated: *negated,
            }),
            Expr::InList {
                expr,
                values,
                negated,
            } => Ok(Expr::InList {
                expr: Box::new(self.rewrite_grouped_having_expr(projection, expr)?),
                values: values
                    .iter()
                    .map(|value| self.rewrite_grouped_having_expr(projection, value))
                    .collect::<Result<Vec<_>>>()?,
                negated: *negated,
            }),
            Expr::Like {
                expr,
                pattern,
                negated,
            } => Ok(Expr::Like {
                expr: Box::new(self.rewrite_grouped_having_expr(projection, expr)?),
                pattern: Box::new(self.rewrite_grouped_having_expr(projection, pattern)?),
                negated: *negated,
            }),
            Expr::Coalesce(values) => values
                .iter()
                .map(|value| self.rewrite_grouped_having_expr(projection, value))
                .collect::<Result<Vec<_>>>()
                .map(Expr::Coalesce),
            Expr::NullIf { left, right } => Ok(Expr::NullIf {
                left: Box::new(self.rewrite_grouped_having_expr(projection, left)?),
                right: Box::new(self.rewrite_grouped_having_expr(projection, right)?),
            }),
            Expr::Case {
                operand,
                whens,
                else_expr,
            } => Ok(Expr::Case {
                operand: operand
                    .as_ref()
                    .map(|operand| self.rewrite_grouped_having_expr(projection, operand))
                    .transpose()?
                    .map(Box::new),
                whens: whens
                    .iter()
                    .map(|arm| {
                        Ok(CaseWhen {
                            condition: self
                                .rewrite_grouped_having_expr(projection, &arm.condition)?,
                            result: self.rewrite_grouped_having_expr(projection, &arm.result)?,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
                else_expr: else_expr
                    .as_ref()
                    .map(|else_expr| self.rewrite_grouped_having_expr(projection, else_expr))
                    .transpose()?
                    .map(Box::new),
            }),
            Expr::Cast { expr, data_type } => Ok(Expr::Cast {
                expr: Box::new(self.rewrite_grouped_having_expr(projection, expr)?),
                data_type: data_type.clone(),
            }),
            Expr::Array(values) => values
                .iter()
                .map(|value| self.rewrite_grouped_having_expr(projection, value))
                .collect::<Result<Vec<_>>>()
                .map(Expr::Array),
            Expr::Range {
                lower,
                upper,
                bounds,
            } => Ok(Expr::Range {
                lower: Box::new(self.rewrite_grouped_having_expr(projection, lower)?),
                upper: Box::new(self.rewrite_grouped_having_expr(projection, upper)?),
                bounds: *bounds,
            }),
            Expr::Call { name, args } => args
                .iter()
                .map(|arg| self.rewrite_grouped_having_expr(projection, arg))
                .collect::<Result<Vec<_>>>()
                .map(|args| Expr::Call {
                    name: name.clone(),
                    args,
                }),
            Expr::Identifier(_)
            | Expr::Integer(_)
            | Expr::String(_)
            | Expr::Bool(_)
            | Expr::Null
            | Expr::HStore(_) => Ok(expr.clone()),
        }
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
            Expr::Integer(_) => Ok(Some(SqlType::Int64)),
            Expr::String(_) => Ok(Some(SqlType::Text)),
            Expr::Bool(_) => Ok(Some(SqlType::Bool)),
            Expr::Null => Ok(Some(SqlType::Null)),
            Expr::CountStar
            | Expr::Count(_)
            | Expr::CountDistinct(_)
            | Expr::Sum(_)
            | Expr::Min(_)
            | Expr::Max(_) => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "HAVING only supports projected aggregate output columns yet",
            )),
            Expr::Array(values) => {
                let mut element_type = None;
                for value in values {
                    let Some(value_type) =
                        self.infer_grouped_output_expr_type(projection, value)?
                    else {
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
                let lower_type = self
                    .infer_grouped_output_expr_type(projection, lower)?
                    .unwrap_or(SqlType::Null);
                let upper_type = self
                    .infer_grouped_output_expr_type(projection, upper)?
                    .unwrap_or(SqlType::Null);
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
            Expr::Bool(_) => Ok(Some(SqlType::Bool)),
            Expr::Null => Ok(Some(SqlType::Null)),
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
                let mut value_types = Vec::with_capacity(values.len());
                for value in values {
                    let Some(value_type) = self.infer_policy_expr_type(table, value)? else {
                        return Ok(Some(SqlType::Bool));
                    };
                    value_types.push(value_type);
                }
                self.infer_in_list_result_type(&expr_type, &value_types)
            }
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
                let mut value_types = Vec::with_capacity(values.len());
                for value in values {
                    let Some(value_type) = self.infer_policy_expr_type(table, value)? else {
                        return Ok(None);
                    };
                    value_types.push(value_type);
                }
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
            Expr::Bool(_) => Ok(Some(SqlType::Bool)),
            Expr::Null => Ok(Some(SqlType::Null)),
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
                let mut value_types = Vec::with_capacity(values.len());
                for value in values {
                    let Some(value_type) = self.infer_expr_type(table, value)? else {
                        return Ok(None);
                    };
                    value_types.push(value_type);
                }
                self.infer_in_list_result_type(&expr_type, &value_types)
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
                let mut value_types = Vec::with_capacity(values.len());
                for value in values {
                    let Some(value_type) = self.infer_expr_type(table, value)? else {
                        return Ok(None);
                    };
                    value_types.push(value_type);
                }
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
        if is_arithmetic_operator(op) {
            return self.infer_arithmetic_result_type(op, left_type, right_type);
        }
        if is_text_concat_operator(op) {
            return self.infer_text_concat_result_type(op, left_type, right_type);
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
        if matches!(left_type, SqlType::Int64 | SqlType::Null)
            && matches!(right_type, SqlType::Int64 | SqlType::Null)
        {
            Ok(Some(SqlType::Int64))
        } else {
            Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("arithmetic operator {op} requires INT64 operands"),
            ))
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
        } else {
            Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("unary operator {op} requires INT64 operand"),
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
                    | (SqlType::Text, SqlType::Int64)
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

fn is_boolean_connector(op: &str) -> bool {
    matches!(op, "AND" | "OR")
}

fn is_arithmetic_operator(op: &str) -> bool {
    matches!(op, "+" | "-" | "*" | "/" | "%")
}

fn is_text_concat_operator(op: &str) -> bool {
    op == "||"
}

fn truth_test_name(value: bool) -> &'static str {
    if value { "IS TRUE" } else { "IS FALSE" }
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

fn query_output_columns(statement: &BoundStatement) -> Result<&[BoundColumn]> {
    match statement {
        BoundStatement::Select(select) => Ok(&select.columns),
        BoundStatement::Union(union) => Ok(&union.columns),
        BoundStatement::Intersect(intersect) => Ok(&intersect.columns),
        BoundStatement::Except(except) => Ok(&except.columns),
        BoundStatement::Query(query) => Ok(&query.columns),
        _ => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "set operation operands must be SELECT queries",
        )),
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
