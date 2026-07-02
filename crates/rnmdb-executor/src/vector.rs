use rnmdb_common::{ErrorKind, Result, RnovError};
use rnmdb_sql::ast::GeneratedColumn;
use rnmdb_types::{SqlType, SqlValue};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColumnSchema {
    name: String,
    data_type: SqlType,
    nullable: bool,
    encrypted: bool,
    generated: Option<GeneratedColumn>,
}

impl ColumnSchema {
    pub fn new(name: impl Into<String>, data_type: SqlType) -> Self {
        Self {
            name: name.into(),
            data_type,
            nullable: true,
            encrypted: false,
            generated: None,
        }
    }

    pub fn not_null(mut self) -> Self {
        self.nullable = false;
        self
    }

    pub fn encrypted(mut self) -> Self {
        self.encrypted = true;
        self
    }

    pub fn with_encrypted(mut self, encrypted: bool) -> Self {
        self.encrypted = encrypted;
        self
    }

    pub fn with_generated(mut self, generated: GeneratedColumn) -> Self {
        self.generated = Some(generated);
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn data_type(&self) -> &SqlType {
        &self.data_type
    }

    pub fn nullable(&self) -> bool {
        self.nullable
    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    pub fn generated(&self) -> Option<&GeneratedColumn> {
        self.generated.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Row {
    values: Vec<SqlValue>,
}

impl Row {
    pub fn new(values: Vec<SqlValue>) -> Self {
        Self { values }
    }

    pub fn values(&self) -> &[SqlValue] {
        &self.values
    }

    pub(crate) fn set_value(&mut self, index: usize, value: SqlValue) {
        self.values[index] = value;
    }

    pub(crate) fn push_value(&mut self, value: SqlValue) {
        self.values.push(value);
    }

    fn project(&self, indexes: &[usize]) -> Self {
        Self {
            values: indexes
                .iter()
                .map(|index| self.values[*index].clone())
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VectorBatch {
    columns: Vec<ColumnSchema>,
    rows: Vec<Row>,
}

impl VectorBatch {
    pub fn new(columns: Vec<ColumnSchema>, rows: Vec<Row>) -> Result<Self> {
        validate_columns(&columns)?;
        let batch = Self { columns, rows };
        for row in &batch.rows {
            validate_row_against_columns(&batch.columns, row)?;
        }
        Ok(batch)
    }

    pub fn columns(&self) -> &[ColumnSchema] {
        &self.columns
    }

    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    pub fn project(&self, names: &[&str]) -> Result<Self> {
        let mut indexes = Vec::with_capacity(names.len());
        let mut columns = Vec::with_capacity(names.len());
        for name in names {
            let index = self.column_index(name)?;
            indexes.push(index);
            columns.push(self.columns[index].clone());
        }

        let rows = self.rows.iter().map(|row| row.project(&indexes)).collect();
        Self::new(columns, rows)
    }

    pub fn filter_eq(&self, name: &str, expected: &SqlValue) -> Result<Self> {
        let index = self.column_index(name)?;
        let rows = self
            .rows
            .iter()
            .filter(|row| &row.values[index] == expected)
            .cloned()
            .collect();
        Self::new(self.columns.clone(), rows)
    }

    fn column_index(&self, name: &str) -> Result<usize> {
        self.columns
            .iter()
            .position(|column| column.name() == name)
            .ok_or_else(|| RnovError::new(ErrorKind::NotFound, format!("column not found: {name}")))
    }
}

fn validate_columns(columns: &[ColumnSchema]) -> Result<()> {
    if columns.is_empty() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "vector batch must have at least one column",
        ));
    }

    for (index, column) in columns.iter().enumerate() {
        if column.name().is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "column name cannot be empty",
            ));
        }
        if columns[..index]
            .iter()
            .any(|existing| existing.name() == column.name())
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("duplicate column: {}", column.name()),
            ));
        }
    }

    Ok(())
}

pub(crate) fn validate_row_against_columns(columns: &[ColumnSchema], row: &Row) -> Result<()> {
    if row.values.len() != columns.len() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "row width {} does not match column width {}",
                row.values.len(),
                columns.len()
            ),
        ));
    }

    for (column, value) in columns.iter().zip(row.values()) {
        if value.is_null() {
            if column.nullable() {
                continue;
            }
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("null value for not-null column {}", column.name()),
            ));
        }
        if value.data_type() != *column.data_type() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "type mismatch for column {}: expected {:?}, got {:?}",
                    column.name(),
                    column.data_type(),
                    value.data_type()
                ),
            ));
        }
    }
    Ok(())
}
