use std::collections::{BTreeMap, BTreeSet};

use rnmdb_common::{
    ErrorKind, Result, RnovError,
    ids::{RelationId, RoleId},
};
use rnmdb_security::{ColumnKeyMaterial, decrypt_column_value, encrypt_column_value};
use rnmdb_types::SqlValue;

use crate::vector::{ColumnSchema, Row, VectorBatch};

#[derive(Clone, Debug, Default)]
pub struct ColumnCryptoState {
    active_role: Option<RoleId>,
    columns: BTreeMap<EncryptedColumnRef, EncryptedColumnKey>,
}

impl ColumnCryptoState {
    pub fn set_active_role(&mut self, role_id: RoleId) {
        self.active_role = Some(role_id);
    }

    pub fn configure_column(
        &mut self,
        relation_id: RelationId,
        column_name: impl Into<String>,
        key: ColumnKeyMaterial,
        decrypt_roles: impl IntoIterator<Item = RoleId>,
    ) -> Result<()> {
        let column = EncryptedColumnRef::new(relation_id, column_name)?;
        self.columns.insert(
            column,
            EncryptedColumnKey {
                key,
                decrypt_roles: decrypt_roles.into_iter().collect(),
            },
        );
        Ok(())
    }

    pub fn grant_decrypt(
        &mut self,
        relation_id: RelationId,
        column_name: impl Into<String>,
        role_id: RoleId,
    ) -> Result<()> {
        let column = EncryptedColumnRef::new(relation_id, column_name)?;
        let key = self.encrypted_column_mut(&column)?;
        key.decrypt_roles.insert(role_id);
        Ok(())
    }

    pub fn encrypt_row(
        &self,
        relation_id: RelationId,
        columns: &[ColumnSchema],
        row: &Row,
    ) -> Result<Row> {
        let values = columns
            .iter()
            .zip(row.values())
            .map(|(column, value)| self.encrypt_value(relation_id, column, value))
            .collect::<Result<Vec<_>>>()?;
        Ok(Row::new(values))
    }

    pub fn encrypt_insert_row(
        &self,
        relation_id: RelationId,
        columns: &[ColumnSchema],
        row: &Row,
    ) -> Result<Row> {
        let values = columns
            .iter()
            .zip(row.values())
            .map(|(column, value)| self.encrypt_value(relation_id, column, value))
            .collect::<Result<Vec<_>>>()?;
        Ok(Row::new(values))
    }

    pub fn decrypt_batch(
        &self,
        relation_id: RelationId,
        batch: VectorBatch,
    ) -> Result<VectorBatch> {
        let rows = batch
            .rows()
            .iter()
            .map(|row| self.decrypt_row(relation_id, batch.columns(), row))
            .collect::<Result<Vec<_>>>()?;
        VectorBatch::new(batch.columns().to_vec(), rows)
    }

    pub fn decrypt_row(
        &self,
        relation_id: RelationId,
        columns: &[ColumnSchema],
        row: &Row,
    ) -> Result<Row> {
        let values = columns
            .iter()
            .zip(row.values())
            .map(|(column, value)| self.decrypt_value(relation_id, column, value))
            .collect::<Result<Vec<_>>>()?;
        Ok(Row::new(values))
    }

    fn encrypt_value(
        &self,
        relation_id: RelationId,
        column: &ColumnSchema,
        value: &SqlValue,
    ) -> Result<SqlValue> {
        if !column.is_encrypted() || value.is_null() {
            return Ok(value.clone());
        }
        ensure_plaintext_type(column, value)?;
        let key = self.encrypted_column(relation_id, column.name())?;
        let encrypted =
            encrypt_column_value(&key.key, relation_id, column.name(), &value.encode())?;
        Ok(SqlValue::Bytes(encrypted))
    }

    fn decrypt_value(
        &self,
        relation_id: RelationId,
        column: &ColumnSchema,
        value: &SqlValue,
    ) -> Result<SqlValue> {
        if !column.is_encrypted() || value.is_null() {
            return Ok(value.clone());
        }
        let SqlValue::Bytes(encrypted) = value else {
            return Ok(value.clone());
        };
        let key = self.encrypted_column(relation_id, column.name())?;
        self.ensure_decrypt_authorized(relation_id, column.name(), key)?;
        let decrypted = decrypt_column_value(&key.key, relation_id, column.name(), encrypted)?;
        let value = SqlValue::decode(&decrypted)?;
        ensure_plaintext_type(column, &value)?;
        Ok(value)
    }

    fn encrypted_column(
        &self,
        relation_id: RelationId,
        column_name: &str,
    ) -> Result<&EncryptedColumnKey> {
        self.maybe_encrypted_column(relation_id, column_name)?
            .ok_or_else(|| {
                RnovError::new(
                    ErrorKind::Security,
                    format!("column encryption key is not configured: {relation_id}.{column_name}"),
                )
            })
    }

    fn maybe_encrypted_column(
        &self,
        relation_id: RelationId,
        column_name: &str,
    ) -> Result<Option<&EncryptedColumnKey>> {
        let column = EncryptedColumnRef::new(relation_id, column_name)?;
        Ok(self.columns.get(&column))
    }

    fn encrypted_column_mut(
        &mut self,
        column: &EncryptedColumnRef,
    ) -> Result<&mut EncryptedColumnKey> {
        self.columns.get_mut(column).ok_or_else(|| {
            RnovError::new(
                ErrorKind::Security,
                format!(
                    "column encryption key is not configured: {}.{}",
                    column.relation_id, column.column_name
                ),
            )
        })
    }

    fn ensure_decrypt_authorized(
        &self,
        relation_id: RelationId,
        column_name: &str,
        key: &EncryptedColumnKey,
    ) -> Result<()> {
        let Some(role_id) = self.active_role else {
            return Err(RnovError::new(
                ErrorKind::Security,
                format!("no active role can decrypt column {relation_id}.{column_name}"),
            ));
        };
        if key.decrypt_roles.contains(&role_id) {
            return Ok(());
        }
        Err(RnovError::new(
            ErrorKind::Security,
            format!(
                "role {role_id} is not authorized to decrypt column {relation_id}.{column_name}"
            ),
        ))
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EncryptedColumnRef {
    relation_id: RelationId,
    column_name: String,
}

impl EncryptedColumnRef {
    fn new(relation_id: RelationId, column_name: impl Into<String>) -> Result<Self> {
        let column_name = column_name.into();
        if column_name.trim().is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "encrypted column name cannot be empty",
            ));
        }
        Ok(Self {
            relation_id,
            column_name,
        })
    }
}

#[derive(Clone, Debug)]
struct EncryptedColumnKey {
    key: ColumnKeyMaterial,
    decrypt_roles: BTreeSet<RoleId>,
}

fn ensure_plaintext_type(column: &ColumnSchema, value: &SqlValue) -> Result<()> {
    if value.data_type() == *column.data_type() {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::InvalidInput,
        format!(
            "type mismatch for encrypted column {}: expected {:?}, got {:?}",
            column.name(),
            column.data_type(),
            value.data_type()
        ),
    ))
}
