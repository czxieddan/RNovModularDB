use std::collections::BTreeMap;

use rnovdb_common::{
    error::{ErrorKind, Result, RnovError},
    ids::{DatabaseId, RelationId},
};
use rnovdb_types::SqlType;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Column {
    name: String,
    data_type: SqlType,
    nullable: bool,
    encrypted: bool,
}

impl Column {
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
pub struct Table {
    relation_id: RelationId,
    schema_name: String,
    name: String,
    columns: Vec<Column>,
    version: u64,
}

impl Table {
    pub fn relation_id(&self) -> RelationId {
        self.relation_id
    }

    pub fn schema_name(&self) -> &str {
        &self.schema_name
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn columns(&self) -> &[Column] {
        &self.columns
    }

    pub fn version(&self) -> u64 {
        self.version
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Schema {
    name: String,
    tables: BTreeMap<String, Table>,
}

impl Schema {
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Catalog {
    database_id: DatabaseId,
    next_relation_id: u64,
    schemas: BTreeMap<String, Schema>,
}

impl Catalog {
    pub fn new(database_id: DatabaseId) -> Self {
        Self {
            database_id,
            next_relation_id: 1,
            schemas: BTreeMap::new(),
        }
    }

    pub fn database_id(&self) -> DatabaseId {
        self.database_id
    }

    pub fn create_schema(&mut self, name: impl Into<String>) -> Result<&Schema> {
        let name = name.into();
        validate_identifier("schema", &name)?;
        if self.schemas.contains_key(&name) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("schema already exists: {name}"),
            ));
        }

        self.schemas.insert(
            name.clone(),
            Schema {
                name: name.clone(),
                tables: BTreeMap::new(),
            },
        );
        Ok(self.schemas.get(&name).expect("schema inserted"))
    }

    pub fn create_table(
        &mut self,
        schema_name: &str,
        table_name: impl Into<String>,
        columns: Vec<Column>,
    ) -> Result<&Table> {
        let table_name = table_name.into();
        validate_identifier("table", &table_name)?;
        validate_columns(&columns)?;

        let schema = self.schemas.get_mut(schema_name).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("schema does not exist: {schema_name}"),
            )
        })?;

        if schema.tables.contains_key(&table_name) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("table already exists: {schema_name}.{table_name}"),
            ));
        }

        let relation_id = RelationId::new(self.next_relation_id);
        self.next_relation_id += 1;
        schema.tables.insert(
            table_name.clone(),
            Table {
                relation_id,
                schema_name: schema_name.to_string(),
                name: table_name.clone(),
                columns,
                version: 1,
            },
        );
        Ok(schema.tables.get(&table_name).expect("table inserted"))
    }

    pub fn get_table(&self, schema_name: &str, table_name: &str) -> Option<&Table> {
        self.schemas.get(schema_name)?.tables.get(table_name)
    }

    pub fn add_column(
        &mut self,
        schema_name: &str,
        table_name: &str,
        column: Column,
    ) -> Result<&Table> {
        validate_columns(std::slice::from_ref(&column))?;
        let table = self
            .schemas
            .get_mut(schema_name)
            .and_then(|schema| schema.tables.get_mut(table_name))
            .ok_or_else(|| {
                RnovError::new(
                    ErrorKind::NotFound,
                    format!("table does not exist: {schema_name}.{table_name}"),
                )
            })?;

        if table
            .columns
            .iter()
            .any(|existing| existing.name == column.name)
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("column already exists: {}", column.name),
            ));
        }

        table.columns.push(column);
        table.version += 1;
        Ok(table)
    }
}

fn validate_identifier(kind: &'static str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("{kind} name cannot be empty"),
        ));
    }
    Ok(())
}

fn validate_columns(columns: &[Column]) -> Result<()> {
    if columns.is_empty() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "table must have at least one column",
        ));
    }

    let mut seen = BTreeMap::new();
    for column in columns {
        validate_identifier("column", column.name())?;
        if seen.insert(column.name(), ()).is_some() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("duplicate column: {}", column.name()),
            ));
        }
    }
    Ok(())
}
