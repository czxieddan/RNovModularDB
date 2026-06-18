use rnovdb_common::error::{ErrorKind, Result, RnovError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Truth {
    True,
    False,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlType {
    Null,
    Bool,
    Int64,
    UInt64,
    Text,
    Bytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SqlValue {
    Null,
    Bool(bool),
    Int64(i64),
    UInt64(u64),
    Text(String),
    Bytes(Vec<u8>),
}

impl SqlValue {
    pub const ENCODING_VERSION: u8 = 1;

    const TAG_NULL: u8 = 0;
    const TAG_BOOL: u8 = 1;
    const TAG_INT64: u8 = 2;
    const TAG_UINT64: u8 = 3;
    const TAG_TEXT: u8 = 4;
    const TAG_BYTES: u8 = 5;

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
        }
    }
}

fn encode_bytes(bytes: &[u8], encoded: &mut Vec<u8>) {
    let len = bytes.len() as u32;
    encoded.extend_from_slice(&len.to_be_bytes());
    encoded.extend_from_slice(bytes);
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
