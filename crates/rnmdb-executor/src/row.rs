use crc::{CRC_32_ISCSI, Crc};
use rnmdb_common::{ErrorKind, Result, RnovError};
use rnmdb_types::SqlValue;

use crate::vector::{ColumnSchema, Row, VectorBatch};

const ROW_CRC32C: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);

#[derive(Clone, Debug, Default)]
pub struct RowCodec;

impl RowCodec {
    const VERSION: u8 = 2;
    const CHECKSUM_LEN: usize = 4;

    pub fn encode(columns: &[ColumnSchema], row: &Row) -> Result<Vec<u8>> {
        let _ = VectorBatch::new(columns.to_vec(), vec![row.clone()])?;
        let mut encoded = vec![Self::VERSION];
        encoded.extend_from_slice(&checked_len(row.values().len(), "row value count")?);
        for value in row.values() {
            let value_bytes = value.encode();
            encoded.extend_from_slice(&checked_len(value_bytes.len(), "row value payload")?);
            encoded.extend_from_slice(&value_bytes);
        }
        encoded.extend_from_slice(&checksum(&encoded).to_be_bytes());
        Ok(encoded)
    }

    pub fn decode(columns: &[ColumnSchema], bytes: &[u8]) -> Result<Row> {
        validate_row_version(bytes)?;
        let payload = verified_row_payload(bytes)?;
        let mut cursor = Cursor::new(payload);
        let _ = cursor.read_u8("row encoding version")?;
        let value_count = read_row_value_count(&mut cursor, columns.len())?;
        let values = read_row_values(&mut cursor, value_count)?;
        ensure_row_payload_complete(&cursor)?;
        let row = Row::new(values);
        let _ = VectorBatch::new(columns.to_vec(), vec![row.clone()])?;
        Ok(row)
    }
}

fn validate_row_version(bytes: &[u8]) -> Result<()> {
    let version = *bytes
        .first()
        .ok_or_else(|| RnovError::new(ErrorKind::InvalidInput, "truncated row encoding version"))?;
    if version == RowCodec::VERSION {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::InvalidInput,
        format!("unsupported row encoding version {version}"),
    ))
}

fn verified_row_payload(bytes: &[u8]) -> Result<&[u8]> {
    if bytes.len() < 1 + RowCodec::CHECKSUM_LEN {
        return Err(RnovError::new(
            ErrorKind::Corruption,
            "truncated row checksum",
        ));
    }
    let checksum_offset = bytes.len() - RowCodec::CHECKSUM_LEN;
    let (payload, stored_checksum) = bytes.split_at(checksum_offset);
    if checksum(payload).to_be_bytes().as_slice() == stored_checksum {
        return Ok(payload);
    }
    Err(RnovError::new(
        ErrorKind::Corruption,
        "row checksum mismatch",
    ))
}

fn read_row_value_count(cursor: &mut Cursor<'_>, column_count: usize) -> Result<usize> {
    let value_count = cursor.read_u32("row value count")? as usize;
    if value_count == column_count {
        return Ok(value_count);
    }
    Err(RnovError::new(
        ErrorKind::InvalidInput,
        format!("row value count {value_count} does not match schema column count {column_count}"),
    ))
}

fn read_row_values(cursor: &mut Cursor<'_>, value_count: usize) -> Result<Vec<SqlValue>> {
    let mut values = Vec::with_capacity(value_count);
    for _ in 0..value_count {
        values.push(read_row_value(cursor)?);
    }
    Ok(values)
}

fn read_row_value(cursor: &mut Cursor<'_>) -> Result<SqlValue> {
    let len = cursor.read_u32("row value payload length")? as usize;
    let bytes = cursor.read_exact(len, "row value payload")?;
    SqlValue::decode(bytes)
}

fn ensure_row_payload_complete(cursor: &Cursor<'_>) -> Result<()> {
    if cursor.is_complete() {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::InvalidInput,
        "row payload has trailing bytes",
    ))
}

fn checked_len(len: usize, name: &'static str) -> Result<[u8; 4]> {
    let len = u32::try_from(len)
        .map_err(|_| RnovError::new(ErrorKind::InvalidInput, format!("{name} is too large")))?;
    Ok(len.to_be_bytes())
}

fn checksum(bytes: &[u8]) -> u32 {
    ROW_CRC32C.checksum(bytes)
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
