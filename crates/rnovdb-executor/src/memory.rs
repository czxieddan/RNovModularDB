use std::collections::BTreeMap;

use rnovdb_common::Result;
use rnovdb_common::{ErrorKind, RnovError};
use rnovdb_planner::logical::LogicalPlan;
use rnovdb_sql::ast::Expr;
use rnovdb_types::SqlValue;

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
}

#[derive(Clone, Debug, Default)]
pub struct MemoryExecutor {
    tables: BTreeMap<String, MemoryTable>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionResult {
    Batch(VectorBatch),
    RowsAffected(u64),
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
            LogicalPlan::Project { columns, input } => {
                let batch = self.execute(input)?;
                let names = columns.iter().map(String::as_str).collect::<Vec<_>>();
                batch.project(&names)
            }
            _ => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "memory executor does not support this logical plan",
            )),
        }
    }

    pub fn execute_mut(&mut self, plan: &LogicalPlan) -> Result<ExecutionResult> {
        match plan {
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
            _ => self.execute(plan).map(ExecutionResult::Batch),
        }
    }
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
        if !table
            .columns()
            .iter()
            .any(|table_column| table_column.name() == column)
        {
            return Err(RnovError::new(
                ErrorKind::NotFound,
                format!("column not found: {column}"),
            ));
        }
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
        _ => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("unsupported memory filter literal: {expr}"),
        )),
    }
}
