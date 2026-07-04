use rnmdb_common::{ErrorKind, Result, RnovError};
use rnmdb_types::SqlValue;
use sha2::{Digest, Sha256};

use crate::vector::{ColumnSchema, Row, VectorBatch};

#[derive(Clone, Debug, Default)]
pub struct RowCodec;

impl RowCodec {
    const VERSION: u8 = 2;
    const CHECKSUM_LEN: usize = 32;

    pub fn encode(columns: &[ColumnSchema], row: &Row) -> Result<Vec<u8>> {
        let _ = VectorBatch::new(columns.to_vec(), vec![row.clone()])?;
        let mut encoded = vec![Self::VERSION];
        encoded.extend_from_slice(&checked_len(row.values().len(), "row value count")?);
        for value in row.values() {
            let value_bytes = value.encode();
            encoded.extend_from_slice(&checked_len(value_bytes.len(), "row value payload")?);
            encoded.extend_from_slice(&value_bytes);
        }
        encoded.extend_from_slice(&checksum(&encoded));
        Ok(encoded)
    }

    pub fn decode(columns: &[ColumnSchema], bytes: &[u8]) -> Result<Row> {
        let version = *bytes.first().ok_or_else(|| {
            RnovError::new(ErrorKind::InvalidInput, "truncated row encoding version")
        })?;
        if version != Self::VERSION {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("unsupported row encoding version {version}"),
            ));
        }
        if bytes.len() < 1 + Self::CHECKSUM_LEN {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                "truncated row checksum",
            ));
        }

        let checksum_offset = bytes.len() - Self::CHECKSUM_LEN;
        let (payload, stored_checksum) = bytes.split_at(checksum_offset);
        if checksum(payload).as_slice() != stored_checksum {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                "row checksum mismatch",
            ));
        }

        let mut cursor = Cursor::new(payload);
        let _ = cursor.read_u8("row encoding version")?;

        let value_count = cursor.read_u32("row value count")? as usize;
        if value_count != columns.len() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "row value count {value_count} does not match schema column count {}",
                    columns.len()
                ),
            ));
        }

        let mut values = Vec::with_capacity(value_count);
        for _ in 0..value_count {
            let len = cursor.read_u32("row value payload length")? as usize;
            values.push(SqlValue::decode(
                cursor.read_exact(len, "row value payload")?,
            )?);
        }
        if !cursor.is_complete() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "row payload has trailing bytes",
            ));
        }

        let row = Row::new(values);
        let _ = VectorBatch::new(columns.to_vec(), vec![row.clone()])?;
        Ok(row)
    }
}

fn checked_len(len: usize, name: &'static str) -> Result<[u8; 4]> {
    let len = u32::try_from(len)
        .map_err(|_| RnovError::new(ErrorKind::InvalidInput, format!("{name} is too large")))?;
    Ok(len.to_be_bytes())
}

fn checksum(bytes: &[u8]) -> [u8; RowCodec::CHECKSUM_LEN] {
    let digest = Sha256::digest(bytes);
    let mut checksum = [0_u8; RowCodec::CHECKSUM_LEN];
    checksum.copy_from_slice(&digest);
    checksum
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_u8(&mut self, name: &'static str) -> Result<u8> {
        Ok(self.read_exact(1, name)?[0])
    }

    fn read_u32(&mut self, name: &'static str) -> Result<u32> {
        let bytes = self.read_exact(4, name)?;
        Ok(u32::from_be_bytes(
            bytes.try_into().expect("exactly four bytes"),
        ))
    }

    fn read_exact(&mut self, len: usize, name: &'static str) -> Result<&'a [u8]> {
        let end = self.position.checked_add(len).ok_or_else(|| {
            RnovError::new(ErrorKind::InvalidInput, format!("{name} length overflow"))
        })?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| RnovError::new(ErrorKind::InvalidInput, format!("truncated {name}")))?;
        self.position = end;
        Ok(bytes)
    }

    fn is_complete(&self) -> bool {
        self.position == self.bytes.len()
    }
}
