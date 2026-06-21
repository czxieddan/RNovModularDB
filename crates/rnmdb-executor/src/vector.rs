use rnmdb_common::{ErrorKind, Result, RnovError};
use rnmdb_types::{SqlType, SqlValue};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColumnSchema {
    name: String,
    data_type: SqlType,
    nullable: bool,
    encrypted: bool,
}

impl ColumnSchema {
    pub fn new(name: impl Into<String>, data_type: SqlType) -> Self {
        Self {
            name: name.into(),
            data_type,
            nullable: true,
            encrypted: false,
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
            batch.validate_row(row)?;
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

    pub(crate) fn validate_row(&self, row: &Row) -> Result<()> {
        if row.values.len() != self.columns.len() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "row width {} does not match column width {}",
                    row.values.len(),
                    self.columns.len()
                ),
            ));
        }

        for (column, value) in self.columns.iter().zip(row.values()) {
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
