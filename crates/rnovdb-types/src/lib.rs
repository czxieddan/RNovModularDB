use rnovdb_common::error::{ErrorKind, Result, RnovError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Truth {
    True,
    False,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SqlType {
    Null,
    Bool,
    Int64,
    UInt64,
    Text,
    Bytes,
    Array(Box<SqlType>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SqlValue {
    Null,
    Bool(bool),
    Int64(i64),
    UInt64(u64),
    Text(String),
    Bytes(Vec<u8>),
    Array(SqlArray),
}

impl SqlValue {
    pub const ENCODING_VERSION: u8 = 1;

    const TAG_NULL: u8 = 0;
    const TAG_BOOL: u8 = 1;
    const TAG_INT64: u8 = 2;
    const TAG_UINT64: u8 = 3;
    const TAG_TEXT: u8 = 4;
    const TAG_BYTES: u8 = 5;
    const TAG_ARRAY: u8 = 6;

    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    pub fn data_type(&self) -> SqlType {
        match self {
            Self::Null => SqlType::Null,
            Self::Bool(_) => SqlType::Bool,
            Self::Int64(_) => SqlType::Int64,
            Self::UInt64(_) => SqlType::UInt64,
            Self::Text(_) => SqlType::Text,
            Self::Bytes(_) => SqlType::Bytes,
            Self::Array(array) => SqlType::Array(Box::new(array.element_type().clone())),
        }
    }

    pub fn sql_eq(&self, other: &Self) -> Truth {
        if self.is_null() || other.is_null() {
            return Truth::Unknown;
        }

        if self == other {
            Truth::True
        } else {
            Truth::False
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = vec![Self::ENCODING_VERSION, self.tag()];

        match self {
            Self::Null => {}
            Self::Bool(value) => encoded.push(u8::from(*value)),
            Self::Int64(value) => encoded.extend_from_slice(&value.to_be_bytes()),
            Self::UInt64(value) => encoded.extend_from_slice(&value.to_be_bytes()),
            Self::Text(value) => encode_bytes(value.as_bytes(), &mut encoded),
            Self::Bytes(value) => encode_bytes(value, &mut encoded),
            Self::Array(array) => encode_array(array, &mut encoded),
        }

        encoded
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let version = *bytes
            .first()
            .ok_or_else(|| RnovError::new(ErrorKind::InvalidInput, "missing encoding version"))?;

        if version != Self::ENCODING_VERSION {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("unsupported encoding version {version}"),
            ));
        }

        let tag = *bytes
            .get(1)
            .ok_or_else(|| RnovError::new(ErrorKind::InvalidInput, "missing value tag"))?;
        let payload = &bytes[2..];

        match tag {
            Self::TAG_NULL => Ok(Self::Null),
            Self::TAG_BOOL => {
                let raw = *payload.first().ok_or_else(|| {
                    RnovError::new(ErrorKind::InvalidInput, "truncated bool payload")
                })?;
                match raw {
                    0 => Ok(Self::Bool(false)),
                    1 => Ok(Self::Bool(true)),
                    _ => Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        format!("invalid bool payload {raw}"),
                    )),
                }
            }
            Self::TAG_INT64 => Ok(Self::Int64(i64::from_be_bytes(read_array::<8>(
                payload, "int64",
            )?))),
            Self::TAG_UINT64 => Ok(Self::UInt64(u64::from_be_bytes(read_array::<8>(
                payload, "uint64",
            )?))),
            Self::TAG_TEXT => {
                let bytes = decode_bytes(payload, "text")?;
                let text = String::from_utf8(bytes).map_err(|_| {
                    RnovError::new(ErrorKind::InvalidInput, "text payload is not utf-8")
                })?;
                Ok(Self::Text(text))
            }
            Self::TAG_BYTES => Ok(Self::Bytes(decode_bytes(payload, "bytes")?)),
            Self::TAG_ARRAY => Ok(Self::Array(decode_array(payload)?)),
            unknown => Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("unknown value tag {unknown}"),
            )),
        }
    }

    fn tag(&self) -> u8 {
        match self {
            Self::Null => Self::TAG_NULL,
            Self::Bool(_) => Self::TAG_BOOL,
            Self::Int64(_) => Self::TAG_INT64,
            Self::UInt64(_) => Self::TAG_UINT64,
            Self::Text(_) => Self::TAG_TEXT,
            Self::Bytes(_) => Self::TAG_BYTES,
            Self::Array(_) => Self::TAG_ARRAY,
        }
    }
}

impl SqlType {
    const TAG_NULL: u8 = 0;
    const TAG_BOOL: u8 = 1;
    const TAG_INT64: u8 = 2;
    const TAG_UINT64: u8 = 3;
    const TAG_TEXT: u8 = 4;
    const TAG_BYTES: u8 = 5;
    const TAG_ARRAY: u8 = 6;

    fn encode_into(&self, encoded: &mut Vec<u8>) {
        match self {
            Self::Null => encoded.push(Self::TAG_NULL),
            Self::Bool => encoded.push(Self::TAG_BOOL),
            Self::Int64 => encoded.push(Self::TAG_INT64),
            Self::UInt64 => encoded.push(Self::TAG_UINT64),
            Self::Text => encoded.push(Self::TAG_TEXT),
            Self::Bytes => encoded.push(Self::TAG_BYTES),
            Self::Array(element_type) => {
                encoded.push(Self::TAG_ARRAY);
                element_type.encode_into(encoded);
            }
        }
    }

    fn decode_from(cursor: &mut Cursor<'_>) -> Result<Self> {
        match cursor.read_u8("type tag")? {
            Self::TAG_NULL => Ok(Self::Null),
            Self::TAG_BOOL => Ok(Self::Bool),
            Self::TAG_INT64 => Ok(Self::Int64),
            Self::TAG_UINT64 => Ok(Self::UInt64),
            Self::TAG_TEXT => Ok(Self::Text),
            Self::TAG_BYTES => Ok(Self::Bytes),
            Self::TAG_ARRAY => Ok(Self::Array(Box::new(Self::decode_from(cursor)?))),
            unknown => Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("unknown type tag {unknown}"),
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArrayDimension {
    lower_bound: i64,
    len: usize,
}

impl ArrayDimension {
    pub fn new(lower_bound: i64, len: usize) -> Result<Self> {
        if len == 0 {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "array dimension length must be greater than zero",
            ));
        }

        Ok(Self { lower_bound, len })
    }

    pub fn lower_bound(self) -> i64 {
        self.lower_bound
    }

    pub fn len(self) -> usize {
        self.len
    }

    fn contains(self, index: i64) -> bool {
        let offset = index - self.lower_bound;
        offset >= 0 && (offset as usize) < self.len
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SqlArray {
    element_type: SqlType,
    dimensions: Vec<ArrayDimension>,
    values: Vec<SqlValue>,
}

impl SqlArray {
    pub fn new(
        element_type: SqlType,
        dimensions: Vec<ArrayDimension>,
        values: Vec<SqlValue>,
    ) -> Result<Self> {
        if dimensions.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "array must have at least one dimension",
            ));
        }

        let expected_len = dimensions.iter().try_fold(1_usize, |acc, dimension| {
            acc.checked_mul(dimension.len())
                .ok_or_else(|| RnovError::new(ErrorKind::InvalidInput, "array shape is too large"))
        })?;

        if expected_len != values.len() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "array shape expects {expected_len} values but received {}",
                    values.len()
                ),
            ));
        }

        for value in &values {
            if !value.is_null() && value.data_type() != element_type {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "array element type does not match declared element type",
                ));
            }
        }

        Ok(Self {
            element_type,
            dimensions,
            values,
        })
    }

    pub fn element_type(&self) -> &SqlType {
        &self.element_type
    }

    pub fn dimensions(&self) -> &[ArrayDimension] {
        &self.dimensions
    }

    pub fn rank(&self) -> usize {
        self.dimensions.len()
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn values(&self) -> &[SqlValue] {
        &self.values
    }

    pub fn get(&self, indexes: &[i64]) -> Option<&SqlValue> {
        if indexes.len() != self.dimensions.len() {
            return None;
        }

        let mut offset = 0_usize;
        let mut stride = 1_usize;
        for (dimension, index) in self.dimensions.iter().zip(indexes).rev() {
            if !dimension.contains(*index) {
                return None;
            }

            offset += (*index - dimension.lower_bound()) as usize * stride;
            stride *= dimension.len();
        }

        self.values.get(offset)
    }
}

fn encode_bytes(bytes: &[u8], encoded: &mut Vec<u8>) {
    let len = bytes.len() as u32;
    encoded.extend_from_slice(&len.to_be_bytes());
    encoded.extend_from_slice(bytes);
}

fn encode_array(array: &SqlArray, encoded: &mut Vec<u8>) {
    array.element_type().encode_into(encoded);

    encoded.extend_from_slice(&(array.dimensions().len() as u32).to_be_bytes());
    for dimension in array.dimensions() {
        encoded.extend_from_slice(&dimension.lower_bound().to_be_bytes());
        encoded.extend_from_slice(&(dimension.len() as u32).to_be_bytes());
    }

    encoded.extend_from_slice(&(array.values().len() as u32).to_be_bytes());
    for value in array.values() {
        let value_bytes = value.encode();
        encoded.extend_from_slice(&(value_bytes.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&value_bytes);
    }
}

fn decode_array(payload: &[u8]) -> Result<SqlArray> {
    let mut cursor = Cursor::new(payload);
    let element_type = SqlType::decode_from(&mut cursor)?;
    let dimension_count = cursor.read_u32("array dimension count")? as usize;
    let mut dimensions = Vec::with_capacity(dimension_count);

    for _ in 0..dimension_count {
        let lower_bound = cursor.read_i64("array lower bound")?;
        let len = cursor.read_u32("array dimension length")? as usize;
        dimensions.push(ArrayDimension::new(lower_bound, len)?);
    }

    let value_count = cursor.read_u32("array value count")? as usize;
    let mut values = Vec::with_capacity(value_count);
    for _ in 0..value_count {
        let len = cursor.read_u32("array value length")? as usize;
        let bytes = cursor.read_exact(len, "array value payload")?;
        values.push(SqlValue::decode(bytes)?);
    }

    if !cursor.is_complete() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "array payload has trailing bytes",
        ));
    }

    SqlArray::new(element_type, dimensions, values)
}

fn decode_bytes(payload: &[u8], type_name: &'static str) -> Result<Vec<u8>> {
    let len = u32::from_be_bytes(read_array::<4>(payload, type_name)?) as usize;
    let bytes = payload.get(4..).ok_or_else(|| {
        RnovError::new(
            ErrorKind::InvalidInput,
            format!("truncated {type_name} payload"),
        )
    })?;

    if bytes.len() != len {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("truncated {type_name} payload"),
        ));
    }

    Ok(bytes.to_vec())
}

fn read_array<const N: usize>(payload: &[u8], type_name: &'static str) -> Result<[u8; N]> {
    let bytes = payload.get(..N).ok_or_else(|| {
        RnovError::new(
            ErrorKind::InvalidInput,
            format!("truncated {type_name} payload"),
        )
    })?;
    let mut array = [0_u8; N];
    array.copy_from_slice(bytes);
    Ok(array)
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
        Ok(u32::from_be_bytes(self.read_fixed::<4>(name)?))
    }

    fn read_i64(&mut self, name: &'static str) -> Result<i64> {
        Ok(i64::from_be_bytes(self.read_fixed::<8>(name)?))
    }

    fn read_fixed<const N: usize>(&mut self, name: &'static str) -> Result<[u8; N]> {
        let bytes = self.read_exact(N, name)?;
        let mut array = [0_u8; N];
        array.copy_from_slice(bytes);
        Ok(array)
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
