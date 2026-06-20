use std::{cmp::Ordering, collections::BTreeMap};

use rnovdb_common::Result;
use rnovdb_common::{ErrorKind, RnovError};
use rnovdb_fts::{SimpleTokenizer, TextQuery, TextVectorBuilder};
use rnovdb_planner::logical::LogicalPlan;
use rnovdb_sql::ast::{ColumnDef, Expr};
use rnovdb_types::{
    ArrayDimension, HStore, HStoreValue, RangeBound, SqlArray, SqlRange, SqlType, SqlValue, Truth,
};

use crate::vector::{ColumnSchema, Row, VectorBatch};

#[derive(Clone, Debug)]
pub struct MemoryTable {
    columns: Vec<ColumnSchema>,
    rows: Vec<Row>,
}

impl MemoryTable {
    pub fn new(columns: Vec<ColumnSchema>) -> Result<Self> {
        let _ = VectorBatch::new(columns.clone(), Vec::new())?;
        Ok(Self {
            columns,
            rows: Vec::new(),
        })
    }

    pub fn columns(&self) -> &[ColumnSchema] {
        &self.columns
    }

    pub fn insert(&mut self, row: Row) -> Result<()> {
        let batch = VectorBatch::new(self.columns.clone(), vec![row.clone()])?;
        self.rows
            .push(batch.rows().first().expect("validated row").clone());
        Ok(())
    }

    pub fn scan(&self) -> VectorBatch {
        VectorBatch::new(self.columns.clone(), self.rows.clone())
            .expect("stored rows are validated on insert")
    }

    fn add_column(&mut self, column: ColumnSchema) -> Result<()> {
        let mut columns = self.columns.clone();
        columns.push(column);
        let mut rows = self.rows.clone();
        for row in &mut rows {
            row.push_value(SqlValue::Null);
        }
        let _ = VectorBatch::new(columns.clone(), rows.clone())?;
        self.columns = columns;
        self.rows = rows;
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryExecutor {
    tables: BTreeMap<String, MemoryTable>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionResult {
    Batch(VectorBatch),
    RowsAffected(u64),
    SchemaChanged,
}

impl MemoryExecutor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_table(&mut self, name: impl Into<String>, table: MemoryTable) -> Result<()> {
        let name = name.into();
        if name.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "registered table name cannot be empty",
            ));
        }
        self.tables.insert(name, table);
        Ok(())
    }

    pub fn execute(&self, plan: &LogicalPlan) -> Result<VectorBatch> {
        match plan {
            LogicalPlan::Scan { table, .. } => self
                .tables
                .get(table)
                .map(MemoryTable::scan)
                .ok_or_else(|| {
                    RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                }),
            LogicalPlan::Filter { predicate, input } => {
                let batch = self.execute(input)?;
                apply_filter(batch, predicate)
            }
            LogicalPlan::TextSearch {
                table,
                column,
                query,
                ..
            } => {
                let batch = self
                    .tables
                    .get(table)
                    .map(MemoryTable::scan)
                    .ok_or_else(|| {
                        RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                    })?;
                apply_text_search(batch, column, query)
            }
            LogicalPlan::Project { items, input } => {
                let batch = self.execute(input)?;
                apply_projection(batch, items)
            }
            _ => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "memory executor does not support this logical plan",
            )),
        }
    }

    pub fn execute_mut(&mut self, plan: &LogicalPlan) -> Result<ExecutionResult> {
        match plan {
            LogicalPlan::CreateTable { table, columns } => {
                self.create_table(table, columns)?;
                Ok(ExecutionResult::SchemaChanged)
            }
            LogicalPlan::AlterTableAddColumn { table, column, .. } => {
                let table = self.tables.get_mut(table).ok_or_else(|| {
                    RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                })?;
                table.add_column(column_schema_from_def(column))?;
                Ok(ExecutionResult::SchemaChanged)
            }
            LogicalPlan::DropTable {
                table, if_exists, ..
            } => {
                if self.tables.remove(table).is_some() || *if_exists {
                    Ok(ExecutionResult::SchemaChanged)
                } else {
                    Err(RnovError::new(
                        ErrorKind::NotFound,
                        format!("table not found: {table}"),
                    ))
                }
            }
            LogicalPlan::Insert {
                table,
                columns,
                values,
            } => {
                let table = self.tables.get_mut(table).ok_or_else(|| {
                    RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                })?;
                insert_values(table, columns, values)?;
                Ok(ExecutionResult::RowsAffected(1))
            }
            LogicalPlan::Update {
                table,
                assignments,
                selection,
                ..
            } => {
                let table = self.tables.get_mut(table).ok_or_else(|| {
                    RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                })?;
                update_rows(table, assignments, selection.as_ref())
                    .map(ExecutionResult::RowsAffected)
            }
            LogicalPlan::Delete {
                table, selection, ..
            } => {
                let table = self.tables.get_mut(table).ok_or_else(|| {
                    RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                })?;
                delete_rows(table, selection.as_ref()).map(ExecutionResult::RowsAffected)
            }
            _ => self.execute(plan).map(ExecutionResult::Batch),
        }
    }

    fn create_table(&mut self, name: &str, columns: &[ColumnDef]) -> Result<()> {
        if self.tables.contains_key(name) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("table already exists: {name}"),
            ));
        }
        let columns = columns.iter().map(column_schema_from_def).collect();
        let table = MemoryTable::new(columns)?;
        self.tables.insert(name.to_string(), table);
        Ok(())
    }
}

fn column_schema_from_def(column: &ColumnDef) -> ColumnSchema {
    let mut schema = ColumnSchema::new(column.name.as_str(), column.data_type.clone());
    if !column.nullable {
        schema = schema.not_null();
    }
    if column.encrypted {
        schema = schema.encrypted();
    }
    schema
}

fn update_rows(
    table: &mut MemoryTable,
    assignments: &[(String, Expr)],
    selection: Option<&Expr>,
) -> Result<u64> {
    let columns = table.columns.clone();
    let assignments = compile_assignments(&columns, assignments)?;
    let mut affected = 0;

    for row in &mut table.rows {
        if row_matches(&columns, row, selection)? {
            let mut updated = row.clone();
            for (index, value) in &assignments {
                updated.set_value(*index, value.clone());
            }
            VectorBatch::new(columns.clone(), vec![updated.clone()])?;
            *row = updated;
            affected += 1;
        }
    }

    Ok(affected)
}

fn delete_rows(table: &mut MemoryTable, selection: Option<&Expr>) -> Result<u64> {
    let columns = table.columns.clone();
    let mut kept = Vec::with_capacity(table.rows.len());
    let mut affected = 0;

    for row in table.rows.drain(..) {
        if row_matches(&columns, &row, selection)? {
            affected += 1;
        } else {
            kept.push(row);
        }
    }

    table.rows = kept;
    Ok(affected)
}

fn compile_assignments(
    columns: &[ColumnSchema],
    assignments: &[(String, Expr)],
) -> Result<Vec<(usize, SqlValue)>> {
    let mut compiled = Vec::with_capacity(assignments.len());
    for (index, (column, value)) in assignments.iter().enumerate() {
        if assignments[..index]
            .iter()
            .any(|(existing, _)| existing == column)
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("duplicate update column: {column}"),
            ));
        }
        compiled.push((column_index(columns, column)?, literal_value(value)?));
    }
    Ok(compiled)
}

fn insert_values(table: &mut MemoryTable, columns: &[String], values: &[Expr]) -> Result<()> {
    if columns.len() != values.len() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "insert column count {} does not match value count {}",
                columns.len(),
                values.len()
            ),
        ));
    }

    for (index, column) in columns.iter().enumerate() {
        if columns[..index].iter().any(|existing| existing == column) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("duplicate insert column: {column}"),
            ));
        }
        let _ = column_index(table.columns(), column)?;
    }

    let mut row_values = Vec::with_capacity(table.columns().len());
    for table_column in table.columns() {
        let value = match columns
            .iter()
            .position(|column| column == table_column.name())
        {
            Some(index) => literal_value(&values[index])?,
            None => SqlValue::Null,
        };
        row_values.push(value);
    }

    table.insert(Row::new(row_values))
}

fn apply_filter(batch: VectorBatch, predicate: &Expr) -> Result<VectorBatch> {
    let Expr::Binary { left, op, right } = predicate else {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "memory filter requires a binary predicate",
        ));
    };

    if op != "=" {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("memory filter does not support operator {op}"),
        ));
    }

    if let Some(column) = column_name(left) {
        let expected = literal_value(right)?;
        return batch.filter_eq(column, &expected);
    }
    if let Some(column) = column_name(right) {
        let expected = literal_value(left)?;
        return batch.filter_eq(column, &expected);
    }

    Err(RnovError::new(
        ErrorKind::InvalidInput,
        "memory filter requires one column and one literal",
    ))
}

fn apply_projection(
    batch: VectorBatch,
    items: &[rnovdb_planner::logical::ProjectionItem],
) -> Result<VectorBatch> {
    let columns = items
        .iter()
        .map(|item| {
            projection_type(batch.columns(), &item.expr)
                .map(|data_type| ColumnSchema::new(item.name.as_str(), data_type))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut rows = Vec::with_capacity(batch.rows().len());
    for row in batch.rows() {
        let values = items
            .iter()
            .map(|item| eval_expr(batch.columns(), row, &item.expr))
            .collect::<Result<Vec<_>>>()?;
        rows.push(Row::new(values));
    }

    VectorBatch::new(columns, rows)
}

fn projection_type(columns: &[ColumnSchema], expr: &Expr) -> Result<SqlType> {
    match expr {
        Expr::Identifier(identifier) => {
            let index = column_index(columns, identifier.as_str())?;
            Ok(columns[index].data_type().clone())
        }
        Expr::Integer(_) => Ok(SqlType::Int64),
        Expr::String(_) => Ok(SqlType::Text),
        Expr::Null => Ok(SqlType::Null),
        Expr::Array(values) => Ok(array_literal_value(values)?.data_type()),
        Expr::HStore(entries) => Ok(hstore_literal_value(entries)?.data_type()),
        Expr::Range {
            lower,
            upper,
            bounds,
        } => Ok(
            range_literal_value(lower, upper, bounds.lower_inclusive, bounds.upper_inclusive)?
                .data_type(),
        ),
        Expr::Binary { op, .. } if boolean_operator(op) => Ok(SqlType::Bool),
        Expr::Binary { op, .. } => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("memory projection does not support operator {op}"),
        )),
        Expr::Call { name, .. } => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("memory projection does not support function call {name}"),
        )),
    }
}

fn eval_expr(columns: &[ColumnSchema], row: &Row, expr: &Expr) -> Result<SqlValue> {
    match expr {
        Expr::Identifier(identifier) => {
            let index = column_index(columns, identifier.as_str())?;
            Ok(row.values()[index].clone())
        }
        Expr::Integer(_)
        | Expr::String(_)
        | Expr::Null
        | Expr::Array(_)
        | Expr::HStore(_)
        | Expr::Range { .. } => literal_value(expr),
        Expr::Binary { left, op, right } => eval_binary_expr(columns, row, left, op, right),
        Expr::Call { name, .. } => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("memory projection does not support function call {name}"),
        )),
    }
}

fn eval_binary_expr(
    columns: &[ColumnSchema],
    row: &Row,
    left: &Expr,
    op: &str,
    right: &Expr,
) -> Result<SqlValue> {
    match op {
        "=" | "<>" | "!=" => {
            let left = eval_expr(columns, row, left)?;
            let right = eval_expr(columns, row, right)?;
            let truth = left.sql_eq(&right);
            Ok(SqlValue::Bool(match op {
                "=" => truth == Truth::True,
                "<>" | "!=" => truth == Truth::False,
                _ => unreachable!("matched equality operators"),
            }))
        }
        "<" | "<=" | ">" | ">=" => {
            let left = eval_expr(columns, row, left)?;
            let right = eval_expr(columns, row, right)?;
            let Some(ordering) = left.sql_cmp(&right)? else {
                return Ok(SqlValue::Bool(false));
            };
            Ok(SqlValue::Bool(match op {
                "<" => ordering == Ordering::Less,
                "<=" => matches!(ordering, Ordering::Less | Ordering::Equal),
                ">" => ordering == Ordering::Greater,
                ">=" => matches!(ordering, Ordering::Greater | Ordering::Equal),
                _ => unreachable!("matched ordering operators"),
            }))
        }
        "@@" => {
            let left = eval_expr(columns, row, left)?;
            let SqlValue::Text(query) = eval_expr(columns, row, right)? else {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "text search expression requires a text query",
                ));
            };
            let query = TextQuery::parse(&query)?;
            let builder = TextVectorBuilder::new(SimpleTokenizer::new());
            Ok(SqlValue::Bool(text_value_matches(left, &query, &builder)?))
        }
        other => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("memory projection does not support operator {other}"),
        )),
    }
}

fn boolean_operator(op: &str) -> bool {
    matches!(op, "=" | "<>" | "!=" | "<" | "<=" | ">" | ">=" | "@@")
}

fn apply_text_search(batch: VectorBatch, column: &str, query: &str) -> Result<VectorBatch> {
    let index = column_index(batch.columns(), column)?;
    match batch.columns()[index].data_type() {
        SqlType::Text | SqlType::TextVector => {}
        other => {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("text search requires text or text vector column, got {other:?}"),
            ));
        }
    }

    let query = TextQuery::parse(query)?;
    let builder = TextVectorBuilder::new(SimpleTokenizer::new());
    let mut rows = Vec::new();

    for row in batch.rows() {
        if text_value_matches(row.values()[index].clone(), &query, &builder)? {
            rows.push(row.clone());
        }
    }

    VectorBatch::new(batch.columns().to_vec(), rows)
}

fn text_value_matches(
    value: SqlValue,
    query: &TextQuery,
    builder: &TextVectorBuilder<SimpleTokenizer>,
) -> Result<bool> {
    match value {
        SqlValue::Null => Ok(false),
        SqlValue::Text(text) => Ok(query.matches(&builder.build(&text)?)),
        SqlValue::TextVector(vector) => Ok(query.matches(&vector)),
        other => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "text search cannot evaluate value type {:?}",
                other.data_type()
            ),
        )),
    }
}

fn row_matches(columns: &[ColumnSchema], row: &Row, selection: Option<&Expr>) -> Result<bool> {
    let Some(selection) = selection else {
        return Ok(true);
    };
    let Expr::Binary { left, op, right } = selection else {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "row predicate requires a binary expression",
        ));
    };
    if op != "=" {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("row predicate does not support operator {op}"),
        ));
    }

    if let Some(column) = column_name(left) {
        let value = literal_value(right)?;
        return row_value_equals(columns, row, column, &value);
    }
    if let Some(column) = column_name(right) {
        let value = literal_value(left)?;
        return row_value_equals(columns, row, column, &value);
    }

    Err(RnovError::new(
        ErrorKind::InvalidInput,
        "row predicate requires one column and one literal",
    ))
}

fn row_value_equals(
    columns: &[ColumnSchema],
    row: &Row,
    column: &str,
    expected: &SqlValue,
) -> Result<bool> {
    let index = column_index(columns, column)?;
    Ok(row.values()[index].sql_eq(expected) == Truth::True)
}

fn column_index(columns: &[ColumnSchema], name: &str) -> Result<usize> {
    columns
        .iter()
        .position(|column| column.name() == name)
        .ok_or_else(|| RnovError::new(ErrorKind::NotFound, format!("column not found: {name}")))
}

fn column_name(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Identifier(identifier) => Some(identifier.as_str()),
        _ => None,
    }
}

fn literal_value(expr: &Expr) -> Result<SqlValue> {
    match expr {
        Expr::Integer(value) => Ok(SqlValue::Int64(*value)),
        Expr::String(value) => Ok(SqlValue::Text(value.clone())),
        Expr::Null => Ok(SqlValue::Null),
        Expr::Array(values) => array_literal_value(values),
        Expr::HStore(entries) => hstore_literal_value(entries),
        Expr::Range {
            lower,
            upper,
            bounds,
        } => range_literal_value(lower, upper, bounds.lower_inclusive, bounds.upper_inclusive),
        _ => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("unsupported memory literal: {expr}"),
        )),
    }
}

fn array_literal_value(values: &[Expr]) -> Result<SqlValue> {
    let mut converted = Vec::with_capacity(values.len());
    let mut element_type = None;

    for expr in values {
        let value = literal_value(expr)?;
        if !value.is_null() {
            let value_type = value.data_type();
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
        converted.push(value);
    }

    let dimension = ArrayDimension::new(1, converted.len())?;
    Ok(SqlValue::Array(SqlArray::new(
        element_type.unwrap_or(SqlType::Null),
        vec![dimension],
        converted,
    )?))
}

fn hstore_literal_value(entries: &[(String, Option<String>)]) -> Result<SqlValue> {
    let entries = entries.iter().map(|(key, value)| {
        (
            key.clone(),
            value
                .as_ref()
                .map_or(HStoreValue::Null, |value| HStoreValue::Text(value.clone())),
        )
    });
    Ok(SqlValue::HStore(HStore::from_entries(entries)?))
}

fn range_literal_value(
    lower: &Expr,
    upper: &Expr,
    lower_inclusive: bool,
    upper_inclusive: bool,
) -> Result<SqlValue> {
    let lower = literal_value(lower)?;
    let upper = literal_value(upper)?;
    let element_type = range_element_type(&lower, &upper)?;
    let lower_bound = range_bound(lower, lower_inclusive);
    let upper_bound = range_bound(upper, upper_inclusive);

    Ok(SqlValue::Range(SqlRange::new(
        element_type,
        lower_bound,
        upper_bound,
    )?))
}

fn range_element_type(lower: &SqlValue, upper: &SqlValue) -> Result<SqlType> {
    match (lower, upper) {
        (SqlValue::Null, SqlValue::Null) => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "range literal requires at least one typed bound",
        )),
        (SqlValue::Null, upper) => Ok(upper.data_type()),
        (lower, SqlValue::Null) => Ok(lower.data_type()),
        (lower, upper) if lower.data_type() == upper.data_type() => Ok(lower.data_type()),
        _ => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "range literal bounds have different types",
        )),
    }
}

fn range_bound(value: SqlValue, inclusive: bool) -> RangeBound {
    if value.is_null() {
        RangeBound::Unbounded
    } else if inclusive {
        RangeBound::Included(value)
    } else {
        RangeBound::Excluded(value)
    }
}
