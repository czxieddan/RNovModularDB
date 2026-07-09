use rnmdb_common::error::{ErrorKind, Result, RnovError};
use std::{cmp::Ordering, collections::BTreeMap};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Truth {
    True,
    False,
    Unknown,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SqlType {
    Null,
    Bool,
    Int64,
    UInt64,
    Float64,
    Uuid,
    Timestamp,
    Json,
    Text,
    Bytes,
    HStore,
    TextVector,
    Array(Box<SqlType>),
    Range(Box<SqlType>),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SqlValue {
    Null,
    Bool(bool),
    Int64(i64),
    UInt64(u64),
    Float64(SqlFloat64),
    Uuid(SqlUuid),
    Timestamp(SqlTimestamp),
    Json(SqlJson),
    Text(String),
    Bytes(Vec<u8>),
    HStore(HStore),
    TextVector(TextVector),
    Array(SqlArray),
    Range(SqlRange),
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SqlUuid([u8; 16]);

impl SqlUuid {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn parse_str(value: &str) -> Result<Self> {
        validate_uuid_shape(value)?;
        let mut bytes = [0_u8; 16];
        let mut byte_index = 0_usize;
        let mut chars = value
            .as_bytes()
            .iter()
            .copied()
            .filter(|byte| *byte != b'-');
        while byte_index < bytes.len() {
            let high = chars.next().expect("uuid shape validated");
            let low = chars.next().expect("uuid shape validated");
            bytes[byte_index] = parse_hex_pair(high, low)?;
            byte_index += 1;
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(self) -> [u8; 16] {
        self.0
    }

    pub fn to_hyphenated_string(self) -> String {
        let mut out = String::with_capacity(36);
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                out.push('-');
            }
            out.push(hex_char(byte >> 4));
            out.push(hex_char(byte & 0x0f));
        }
        out
    }
}

fn validate_uuid_shape(value: &str) -> Result<()> {
    if value.len() != 36 {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "uuid text must use hyphenated 36-character form",
        ));
    }
    for (position, byte) in value.as_bytes().iter().enumerate() {
        let expects_hyphen = matches!(position, 8 | 13 | 18 | 23);
        if (*byte == b'-') != expects_hyphen {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "uuid text has invalid hyphen positions",
            ));
        }
    }
    Ok(())
}

fn parse_hex_pair(high: u8, low: u8) -> Result<u8> {
    let high = hex_value(high)?;
    let low = hex_value(low)?;
    Ok((high << 4) | low)
}

fn hex_value(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "uuid text contains non-hex character",
        )),
    }
}

fn hex_char(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=15 => char::from(b'a' + value - 10),
        _ => unreachable!("uuid nybble is in range"),
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SqlTimestamp(i64);

impl SqlTimestamp {
    pub fn from_epoch_micros(epoch_micros: i64) -> Self {
        Self(epoch_micros)
    }

    pub fn parse_str(value: &str) -> Result<Self> {
        let (date, time) = parse_timestamp_text(value)?;
        let epoch_micros = timestamp_epoch_micros(date, time)?;
        Ok(Self(epoch_micros))
    }

    pub fn epoch_micros(self) -> i64 {
        self.0
    }

    pub fn to_rfc3339_string(self) -> String {
        let days = self.0.div_euclid(MICROS_PER_DAY);
        let day_micros = self.0.rem_euclid(MICROS_PER_DAY);
        let (year, month, day) = civil_from_days(days);
        let (hour, minute, second, micros) = split_day_micros(day_micros);
        let fraction = format_timestamp_fraction(micros);
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{fraction}Z")
    }
}

#[derive(Clone, Copy, Debug)]
struct DateParts {
    year: i32,
    month: u8,
    day: u8,
}

#[derive(Clone, Copy, Debug)]
struct TimeParts {
    hour: u8,
    minute: u8,
    second: u8,
    micros: u32,
}

const MICROS_PER_SECOND: i64 = 1_000_000;
const SECONDS_PER_DAY: i64 = 86_400;
const MICROS_PER_DAY: i64 = SECONDS_PER_DAY * MICROS_PER_SECOND;

fn parse_timestamp_text(value: &str) -> Result<(DateParts, TimeParts)> {
    let value = value.trim();
    let value = value.strip_suffix('Z').unwrap_or(value);
    let (date, time) = split_timestamp_parts(value)?;
    Ok((parse_date_parts(date)?, parse_time_parts(time)?))
}

fn split_timestamp_parts(value: &str) -> Result<(&str, &str)> {
    value
        .split_once('T')
        .or_else(|| value.split_once(' '))
        .ok_or_else(|| {
            RnovError::new(
                ErrorKind::InvalidInput,
                "timestamp text must include date and time",
            )
        })
}

fn parse_date_parts(value: &str) -> Result<DateParts> {
    let (year, month, day) = split_three(value, '-', "timestamp date")?;
    let date = DateParts {
        year: parse_year(year)?,
        month: parse_two_digit_u8(month, "timestamp month")?,
        day: parse_two_digit_u8(day, "timestamp day")?,
    };
    validate_date_parts(date)?;
    Ok(date)
}

fn parse_time_parts(value: &str) -> Result<TimeParts> {
    let (time, fraction) = split_time_fraction(value)?;
    let (hour, minute, second) = split_three(time, ':', "timestamp time")?;
    let time = TimeParts {
        hour: parse_two_digit_u8(hour, "timestamp hour")?,
        minute: parse_two_digit_u8(minute, "timestamp minute")?,
        second: parse_two_digit_u8(second, "timestamp second")?,
        micros: fraction
            .map(parse_fraction_micros)
            .transpose()?
            .unwrap_or(0),
    };
    validate_time_parts(time)?;
    Ok(time)
}

fn split_time_fraction(value: &str) -> Result<(&str, Option<&str>)> {
    let mut parts = value.split('.');
    let Some(time) = parts.next() else {
        return Err(invalid_timestamp("timestamp time is missing"));
    };
    let fraction = parts.next();
    if parts.next().is_some() {
        return Err(invalid_timestamp(
            "timestamp fraction contains multiple dots",
        ));
    }
    Ok((time, fraction))
}

fn split_three<'a>(
    value: &'a str,
    separator: char,
    label: &str,
) -> Result<(&'a str, &'a str, &'a str)> {
    let mut parts = value.split(separator);
    let Some(first) = parts.next() else {
        return Err(invalid_timestamp(label));
    };
    let Some(second) = parts.next() else {
        return Err(invalid_timestamp(label));
    };
    let Some(third) = parts.next() else {
        return Err(invalid_timestamp(label));
    };
    if parts.next().is_some() {
        return Err(invalid_timestamp(label));
    }
    Ok((first, second, third))
}

fn parse_year(value: &str) -> Result<i32> {
    if value.len() != 4 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_timestamp("timestamp year must use four digits"));
    }
    value
        .parse::<i32>()
        .map_err(|_| invalid_timestamp("timestamp year is invalid"))
}

fn parse_two_digit_u8(value: &str, label: &str) -> Result<u8> {
    if value.len() != 2 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_timestamp(label));
    }
    value.parse::<u8>().map_err(|_| invalid_timestamp(label))
}

fn parse_fraction_micros(value: &str) -> Result<u32> {
    if value.is_empty() || value.len() > 6 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_timestamp(
            "timestamp fraction must use one to six digits",
        ));
    }
    let mut micros = value
        .parse::<u32>()
        .map_err(|_| invalid_timestamp("timestamp fraction must use one to six digits"))?;
    for _ in value.len()..6 {
        micros *= 10;
    }
    Ok(micros)
}

fn validate_date_parts(date: DateParts) -> Result<()> {
    if !(1..=9999).contains(&date.year) {
        return Err(invalid_timestamp("timestamp year is out of range"));
    }
    let max_day = days_in_month(date.year, date.month)?;
    if date.day == 0 || date.day > max_day {
        return Err(invalid_timestamp("timestamp day is out of range"));
    }
    Ok(())
}

fn validate_time_parts(time: TimeParts) -> Result<()> {
    if time.hour > 23 || time.minute > 59 || time.second > 59 {
        return Err(invalid_timestamp("timestamp time is out of range"));
    }
    Ok(())
}

fn days_in_month(year: i32, month: u8) -> Result<u8> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Ok(31),
        4 | 6 | 9 | 11 => Ok(30),
        2 if leap_year(year) => Ok(29),
        2 => Ok(28),
        _ => Err(invalid_timestamp("timestamp month is out of range")),
    }
}

fn leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn timestamp_epoch_micros(date: DateParts, time: TimeParts) -> Result<i64> {
    let days = days_from_civil(date.year, date.month, date.day);
    let seconds =
        i64::from(time.hour) * 3_600 + i64::from(time.minute) * 60 + i64::from(time.second);
    checked_timestamp_micros(days, seconds, time.micros)
}

fn checked_timestamp_micros(days: i64, seconds: i64, micros: u32) -> Result<i64> {
    days.checked_mul(MICROS_PER_DAY)
        .and_then(|value| value.checked_add(seconds * MICROS_PER_SECOND))
        .and_then(|value| value.checked_add(i64::from(micros)))
        .ok_or_else(|| invalid_timestamp("timestamp value is out of range"))
}

fn days_from_civil(year: i32, month: u8, day: u8) -> i64 {
    let year = i64::from(year) - if month <= 2 { 1 } else { 0 };
    let era = floor_div(year, 400);
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, u8, u8) {
    let days = days + 719_468;
    let era = floor_div(days, 146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    (
        year + if month <= 2 { 1 } else { 0 },
        month as u8,
        day as u8,
    )
}

fn floor_div(value: i64, divisor: i64) -> i64 {
    value.div_euclid(divisor)
}

fn split_day_micros(day_micros: i64) -> (u8, u8, u8, u32) {
    let total_seconds = day_micros / MICROS_PER_SECOND;
    let micros = (day_micros % MICROS_PER_SECOND) as u32;
    let hour = (total_seconds / 3_600) as u8;
    let minute = ((total_seconds % 3_600) / 60) as u8;
    let second = (total_seconds % 60) as u8;
    (hour, minute, second, micros)
}

fn format_timestamp_fraction(micros: u32) -> String {
    if micros == 0 {
        return String::new();
    }
    let mut fraction = format!("{micros:06}");
    while fraction.ends_with('0') {
        fraction.pop();
    }
    format!(".{fraction}")
}

fn invalid_timestamp(message: &str) -> RnovError {
    RnovError::new(ErrorKind::InvalidInput, message)
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SqlJson(String);

impl SqlJson {
    pub fn parse_str(value: &str) -> Result<Self> {
        let parsed: serde_json::Value = serde_json::from_str(value).map_err(|err| {
            RnovError::new(ErrorKind::InvalidInput, format!("invalid json text: {err}"))
        })?;
        let canonical = serde_json::to_string(&parsed).map_err(|err| {
            RnovError::new(
                ErrorKind::InvalidInput,
                format!("failed to canonicalize json text: {err}"),
            )
        })?;
        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SqlFloat64(u64);

impl SqlFloat64 {
    pub fn new(value: f64) -> Result<Self> {
        if !value.is_finite() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "float64 value must be finite",
            ));
        }

        Ok(Self(Self::canonical_bits(value)))
    }

    pub fn from_bits(bits: u64) -> Result<Self> {
        Self::new(f64::from_bits(bits))
    }

    pub fn get(self) -> f64 {
        f64::from_bits(self.0)
    }

    pub fn to_bits(self) -> u64 {
        self.0
    }

    fn canonical_bits(value: f64) -> u64 {
        if value == 0.0 {
            0.0_f64.to_bits()
        } else {
            value.to_bits()
        }
    }
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
    const TAG_RANGE: u8 = 7;
    const TAG_HSTORE: u8 = 8;
    const TAG_TEXT_VECTOR: u8 = 9;
    const TAG_FLOAT64: u8 = 10;
    const TAG_UUID: u8 = 11;
    const TAG_TIMESTAMP: u8 = 12;
    const TAG_JSON: u8 = 13;

    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    pub fn data_type(&self) -> SqlType {
        match self {
            Self::Null => SqlType::Null,
            Self::Bool(_) => SqlType::Bool,
            Self::Int64(_) => SqlType::Int64,
            Self::UInt64(_) => SqlType::UInt64,
            Self::Float64(_) => SqlType::Float64,
            Self::Uuid(_) => SqlType::Uuid,
            Self::Timestamp(_) => SqlType::Timestamp,
            Self::Json(_) => SqlType::Json,
            Self::Text(_) => SqlType::Text,
            Self::Bytes(_) => SqlType::Bytes,
            Self::HStore(_) => SqlType::HStore,
            Self::TextVector(_) => SqlType::TextVector,
            Self::Array(array) => SqlType::Array(Box::new(array.element_type().clone())),
            Self::Range(range) => SqlType::Range(Box::new(range.element_type().clone())),
        }
    }

    pub fn sql_eq(&self, other: &Self) -> Truth {
        if self.is_null() || other.is_null() {
            return Truth::Unknown;
        }

        if self == other || numeric_values_are_equal(self, other) {
            Truth::True
        } else {
            Truth::False
        }
    }

    pub fn sql_cmp(&self, other: &Self) -> Result<Option<Ordering>> {
        if self.is_null() || other.is_null() {
            return Ok(None);
        }

        compare_scalar_values(self, other).map(Some)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = vec![Self::ENCODING_VERSION, self.tag()];

        match self {
            Self::Null => {}
            Self::Bool(value) => encoded.push(u8::from(*value)),
            Self::Int64(value) => encoded.extend_from_slice(&value.to_be_bytes()),
            Self::UInt64(value) => encoded.extend_from_slice(&value.to_be_bytes()),
            Self::Float64(value) => encoded.extend_from_slice(&value.to_bits().to_be_bytes()),
            Self::Uuid(value) => encoded.extend_from_slice(&value.as_bytes()),
            Self::Timestamp(value) => {
                encoded.extend_from_slice(&value.epoch_micros().to_be_bytes())
            }
            Self::Json(value) => encode_bytes(value.as_str().as_bytes(), &mut encoded),
            Self::Text(value) => encode_bytes(value.as_bytes(), &mut encoded),
            Self::Bytes(value) => encode_bytes(value, &mut encoded),
            Self::HStore(value) => encode_hstore(value, &mut encoded),
            Self::TextVector(value) => encode_text_vector(value, &mut encoded),
            Self::Array(array) => encode_array(array, &mut encoded),
            Self::Range(range) => encode_range(range, &mut encoded),
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
            Self::TAG_FLOAT64 => Ok(Self::Float64(SqlFloat64::from_bits(u64::from_be_bytes(
                read_array::<8>(payload, "float64")?,
            ))?)),
            Self::TAG_UUID => Ok(Self::Uuid(SqlUuid::from_bytes(read_array::<16>(
                payload, "uuid",
            )?))),
            Self::TAG_TIMESTAMP => Ok(Self::Timestamp(SqlTimestamp::from_epoch_micros(
                i64::from_be_bytes(read_array::<8>(payload, "timestamp")?),
            ))),
            Self::TAG_JSON => {
                let bytes = decode_bytes(payload, "json")?;
                let text = String::from_utf8(bytes).map_err(|_| {
                    RnovError::new(ErrorKind::InvalidInput, "json is not valid utf-8")
                })?;
                SqlJson::parse_str(&text).map(Self::Json)
            }
            Self::TAG_TEXT => {
                let bytes = decode_bytes(payload, "text")?;
                let text = String::from_utf8(bytes).map_err(|_| {
                    RnovError::new(ErrorKind::InvalidInput, "text payload is not utf-8")
                })?;
                Ok(Self::Text(text))
            }
            Self::TAG_BYTES => Ok(Self::Bytes(decode_bytes(payload, "bytes")?)),
            Self::TAG_ARRAY => Ok(Self::Array(decode_array(payload)?)),
            Self::TAG_RANGE => Ok(Self::Range(decode_range(payload)?)),
            Self::TAG_HSTORE => Ok(Self::HStore(decode_hstore(payload)?)),
            Self::TAG_TEXT_VECTOR => Ok(Self::TextVector(decode_text_vector(payload)?)),
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
            Self::Float64(_) => Self::TAG_FLOAT64,
            Self::Uuid(_) => Self::TAG_UUID,
            Self::Timestamp(_) => Self::TAG_TIMESTAMP,
            Self::Json(_) => Self::TAG_JSON,
            Self::Text(_) => Self::TAG_TEXT,
            Self::Bytes(_) => Self::TAG_BYTES,
            Self::HStore(_) => Self::TAG_HSTORE,
            Self::TextVector(_) => Self::TAG_TEXT_VECTOR,
            Self::Array(_) => Self::TAG_ARRAY,
            Self::Range(_) => Self::TAG_RANGE,
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
    const TAG_RANGE: u8 = 7;
    const TAG_HSTORE: u8 = 8;
    const TAG_TEXT_VECTOR: u8 = 9;
    const TAG_FLOAT64: u8 = 10;
    const TAG_UUID: u8 = 11;
    const TAG_TIMESTAMP: u8 = 12;
    const TAG_JSON: u8 = 13;

    fn encode_into(&self, encoded: &mut Vec<u8>) {
        match self {
            Self::Null => encoded.push(Self::TAG_NULL),
            Self::Bool => encoded.push(Self::TAG_BOOL),
            Self::Int64 => encoded.push(Self::TAG_INT64),
            Self::UInt64 => encoded.push(Self::TAG_UINT64),
            Self::Float64 => encoded.push(Self::TAG_FLOAT64),
            Self::Uuid => encoded.push(Self::TAG_UUID),
            Self::Timestamp => encoded.push(Self::TAG_TIMESTAMP),
            Self::Json => encoded.push(Self::TAG_JSON),
            Self::Text => encoded.push(Self::TAG_TEXT),
            Self::Bytes => encoded.push(Self::TAG_BYTES),
            Self::HStore => encoded.push(Self::TAG_HSTORE),
            Self::TextVector => encoded.push(Self::TAG_TEXT_VECTOR),
            Self::Array(element_type) => {
                encoded.push(Self::TAG_ARRAY);
                element_type.encode_into(encoded);
            }
            Self::Range(element_type) => {
                encoded.push(Self::TAG_RANGE);
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
            Self::TAG_FLOAT64 => Ok(Self::Float64),
            Self::TAG_UUID => Ok(Self::Uuid),
            Self::TAG_TIMESTAMP => Ok(Self::Timestamp),
            Self::TAG_JSON => Ok(Self::Json),
            Self::TAG_TEXT => Ok(Self::Text),
            Self::TAG_BYTES => Ok(Self::Bytes),
            Self::TAG_HSTORE => Ok(Self::HStore),
            Self::TAG_TEXT_VECTOR => Ok(Self::TextVector),
            Self::TAG_ARRAY => Ok(Self::Array(Box::new(Self::decode_from(cursor)?))),
            Self::TAG_RANGE => Ok(Self::Range(Box::new(Self::decode_from(cursor)?))),
            unknown => Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("unknown type tag {unknown}"),
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum HStoreValue {
    Null,
    Text(String),
}

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct HStore {
    entries: BTreeMap<String, HStoreValue>,
}

impl HStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_entries(entries: impl IntoIterator<Item = (String, HStoreValue)>) -> Result<Self> {
        let mut hstore = Self::new();
        for (key, value) in entries {
            hstore.insert(key, value)?;
        }
        Ok(hstore)
    }

    pub fn insert(&mut self, key: String, value: HStoreValue) -> Result<Option<HStoreValue>> {
        if key.is_empty() {
            return Err(RnovError::new(ErrorKind::InvalidInput, "hstore empty key"));
        }

        Ok(self.entries.insert(key, value))
    }

    pub fn get(&self, key: &str) -> Option<&HStoreValue> {
        self.entries.get(key)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &HStoreValue)> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LexemeWeight {
    A,
    B,
    C,
    D,
}

impl LexemeWeight {
    fn as_u8(self) -> u8 {
        match self {
            Self::A => 0,
            Self::B => 1,
            Self::C => 2,
            Self::D => 3,
        }
    }

    fn from_u8(raw: u8) -> Result<Self> {
        match raw {
            0 => Ok(Self::A),
            1 => Ok(Self::B),
            2 => Ok(Self::C),
            3 => Ok(Self::D),
            unknown => Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("unknown lexeme weight {unknown}"),
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TextLexeme {
    term: String,
    positions: Vec<u32>,
    weight: LexemeWeight,
}

impl TextLexeme {
    pub fn new(
        term: impl Into<String>,
        mut positions: Vec<u32>,
        weight: LexemeWeight,
    ) -> Result<Self> {
        let term = term.into();
        if term.is_empty() {
            return Err(RnovError::new(ErrorKind::InvalidInput, "empty lexeme term"));
        }
        if positions.contains(&0) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "lexeme position must be greater than zero",
            ));
        }

        positions.sort_unstable();
        positions.dedup();

        Ok(Self {
            term,
            positions,
            weight,
        })
    }

    pub fn term(&self) -> &str {
        &self.term
    }

    pub fn positions(&self) -> &[u32] {
        &self.positions
    }

    pub fn weight(&self) -> LexemeWeight {
        self.weight
    }
}

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct TextVector {
    lexemes: BTreeMap<String, TextLexeme>,
}

impl TextVector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_lexemes(lexemes: impl IntoIterator<Item = TextLexeme>) -> Result<Self> {
        let mut vector = Self::new();
        for lexeme in lexemes {
            vector.insert(lexeme)?;
        }
        Ok(vector)
    }

    pub fn insert(&mut self, lexeme: TextLexeme) -> Result<Option<TextLexeme>> {
        Ok(self.lexemes.insert(lexeme.term.clone(), lexeme))
    }

    pub fn find(&self, term: &str) -> Option<&TextLexeme> {
        self.lexemes.get(term)
    }

    pub fn iter(&self) -> impl Iterator<Item = &TextLexeme> {
        self.lexemes.values()
    }

    pub fn len(&self) -> usize {
        self.lexemes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lexemes.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

    pub fn is_empty(self) -> bool {
        self.len == 0
    }

    fn contains(self, index: i64) -> bool {
        let offset = index - self.lower_bound;
        offset >= 0 && (offset as usize) < self.len
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum RangeBound {
    Unbounded,
    Included(SqlValue),
    Excluded(SqlValue),
}

impl RangeBound {
    fn value(&self) -> Option<&SqlValue> {
        match self {
            Self::Unbounded => None,
            Self::Included(value) | Self::Excluded(value) => Some(value),
        }
    }

    fn is_included(&self) -> bool {
        matches!(self, Self::Included(_))
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SqlRange {
    element_type: SqlType,
    lower: Box<RangeBound>,
    upper: Box<RangeBound>,
    empty: bool,
}

impl SqlRange {
    pub fn new(element_type: SqlType, lower: RangeBound, upper: RangeBound) -> Result<Self> {
        validate_range_bound_type(&element_type, &lower)?;
        validate_range_bound_type(&element_type, &upper)?;

        let empty = bounds_are_empty(&lower, &upper)?;
        if empty {
            return Ok(Self::empty(element_type));
        }

        Ok(Self {
            element_type,
            lower: Box::new(lower),
            upper: Box::new(upper),
            empty: false,
        })
    }

    pub fn empty(element_type: SqlType) -> Self {
        Self {
            element_type,
            lower: Box::new(RangeBound::Unbounded),
            upper: Box::new(RangeBound::Unbounded),
            empty: true,
        }
    }

    pub fn element_type(&self) -> &SqlType {
        &self.element_type
    }

    pub fn lower(&self) -> &RangeBound {
        self.lower.as_ref()
    }

    pub fn upper(&self) -> &RangeBound {
        self.upper.as_ref()
    }

    pub fn is_empty(&self) -> bool {
        self.empty
    }

    pub fn contains_value(&self, value: &SqlValue) -> Result<bool> {
        if self.empty {
            return Ok(false);
        }
        if value.is_null() || value.data_type() != self.element_type {
            return Ok(false);
        }

        let above_lower = match self.lower() {
            RangeBound::Unbounded => true,
            RangeBound::Included(bound) => compare_scalar_values(value, bound)? != Ordering::Less,
            RangeBound::Excluded(bound) => {
                compare_scalar_values(value, bound)? == Ordering::Greater
            }
        };
        let below_upper = match self.upper() {
            RangeBound::Unbounded => true,
            RangeBound::Included(bound) => {
                compare_scalar_values(value, bound)? != Ordering::Greater
            }
            RangeBound::Excluded(bound) => compare_scalar_values(value, bound)? == Ordering::Less,
        };

        Ok(above_lower && below_upper)
    }

    pub fn overlaps(&self, other: &Self) -> Result<bool> {
        self.ensure_same_element_type(other)?;
        Ok(!self.intersection(other)?.is_empty())
    }

    pub fn adjacent(&self, other: &Self) -> Result<bool> {
        self.ensure_same_element_type(other)?;
        if self.empty || other.empty || self.overlaps(other)? {
            return Ok(false);
        }

        Ok(bounds_touch_without_gap(self.upper(), other.lower())?
            || bounds_touch_without_gap(other.upper(), self.lower())?)
    }

    pub fn intersection(&self, other: &Self) -> Result<Self> {
        self.ensure_same_element_type(other)?;
        if self.empty || other.empty {
            return Ok(Self::empty(self.element_type.clone()));
        }

        let lower = max_lower_bound(self.lower(), other.lower())?;
        let upper = min_upper_bound(self.upper(), other.upper())?;
        Self::new(self.element_type.clone(), lower, upper)
    }

    pub fn union(&self, other: &Self) -> Result<Self> {
        self.ensure_same_element_type(other)?;
        if self.empty {
            return Ok(other.clone());
        }
        if other.empty {
            return Ok(self.clone());
        }
        if !self.overlaps(other)? && !self.adjacent(other)? {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "ranges are disjoint and cannot be represented as one range",
            ));
        }

        let lower = min_lower_bound(self.lower(), other.lower())?;
        let upper = max_upper_bound(self.upper(), other.upper())?;
        Self::new(self.element_type.clone(), lower, upper)
    }

    fn ensure_same_element_type(&self, other: &Self) -> Result<()> {
        if self.element_type != other.element_type {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "range element type mismatch",
            ));
        }
        Ok(())
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

fn encode_hstore(hstore: &HStore, encoded: &mut Vec<u8>) {
    encoded.extend_from_slice(&(hstore.len() as u32).to_be_bytes());
    for (key, value) in hstore.iter() {
        encode_bytes(key.as_bytes(), encoded);
        match value {
            HStoreValue::Null => encoded.push(0),
            HStoreValue::Text(text) => {
                encoded.push(1);
                encode_bytes(text.as_bytes(), encoded);
            }
        }
    }
}

fn encode_text_vector(vector: &TextVector, encoded: &mut Vec<u8>) {
    encoded.extend_from_slice(&(vector.len() as u32).to_be_bytes());
    for lexeme in vector.iter() {
        encode_bytes(lexeme.term().as_bytes(), encoded);
        encoded.push(lexeme.weight().as_u8());
        encoded.extend_from_slice(&(lexeme.positions().len() as u32).to_be_bytes());
        for position in lexeme.positions() {
            encoded.extend_from_slice(&position.to_be_bytes());
        }
    }
}

fn encode_range(range: &SqlRange, encoded: &mut Vec<u8>) {
    range.element_type().encode_into(encoded);
    encoded.push(u8::from(range.is_empty()));
    encode_range_bound(range.lower(), encoded);
    encode_range_bound(range.upper(), encoded);
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

fn decode_hstore(payload: &[u8]) -> Result<HStore> {
    let mut cursor = Cursor::new(payload);
    let entry_count = cursor.read_u32("hstore entry count")? as usize;
    let mut hstore = HStore::new();

    for _ in 0..entry_count {
        let key_bytes = cursor.read_len_prefixed_bytes("hstore key")?;
        let key = String::from_utf8(key_bytes)
            .map_err(|_| RnovError::new(ErrorKind::InvalidInput, "hstore key is not utf-8"))?;
        let value = match cursor.read_u8("hstore value tag")? {
            0 => HStoreValue::Null,
            1 => {
                let value_bytes = cursor.read_len_prefixed_bytes("hstore value")?;
                HStoreValue::Text(String::from_utf8(value_bytes).map_err(|_| {
                    RnovError::new(ErrorKind::InvalidInput, "hstore value is not utf-8")
                })?)
            }
            unknown => {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("unknown hstore value tag {unknown}"),
                ));
            }
        };
        hstore.insert(key, value)?;
    }

    if !cursor.is_complete() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "hstore payload has trailing bytes",
        ));
    }

    Ok(hstore)
}

fn decode_text_vector(payload: &[u8]) -> Result<TextVector> {
    let mut cursor = Cursor::new(payload);
    let lexeme_count = cursor.read_u32("text vector lexeme count")? as usize;
    let mut lexemes = Vec::with_capacity(lexeme_count);

    for _ in 0..lexeme_count {
        let term_bytes = cursor.read_len_prefixed_bytes("text vector lexeme term")?;
        let term = String::from_utf8(term_bytes).map_err(|_| {
            RnovError::new(ErrorKind::InvalidInput, "text vector term is not utf-8")
        })?;
        let weight = LexemeWeight::from_u8(cursor.read_u8("text vector weight")?)?;
        let position_count = cursor.read_u32("text vector position count")? as usize;
        let mut positions = Vec::with_capacity(position_count);
        for _ in 0..position_count {
            positions.push(cursor.read_u32("text vector position")?);
        }
        lexemes.push(TextLexeme::new(term, positions, weight)?);
    }

    if !cursor.is_complete() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "text vector payload has trailing bytes",
        ));
    }

    TextVector::from_lexemes(lexemes)
}

fn decode_range(payload: &[u8]) -> Result<SqlRange> {
    let mut cursor = Cursor::new(payload);
    let element_type = SqlType::decode_from(&mut cursor)?;
    let empty = cursor.read_u8("range empty flag")? != 0;
    let lower = decode_range_bound(&mut cursor)?;
    let upper = decode_range_bound(&mut cursor)?;
    if !cursor.is_complete() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "range payload has trailing bytes",
        ));
    }

    if empty {
        return Ok(SqlRange::empty(element_type));
    }

    SqlRange::new(element_type, lower, upper)
}

fn encode_range_bound(bound: &RangeBound, encoded: &mut Vec<u8>) {
    match bound {
        RangeBound::Unbounded => encoded.push(0),
        RangeBound::Included(value) => {
            encoded.push(1);
            let value_bytes = value.encode();
            encoded.extend_from_slice(&(value_bytes.len() as u32).to_be_bytes());
            encoded.extend_from_slice(&value_bytes);
        }
        RangeBound::Excluded(value) => {
            encoded.push(2);
            let value_bytes = value.encode();
            encoded.extend_from_slice(&(value_bytes.len() as u32).to_be_bytes());
            encoded.extend_from_slice(&value_bytes);
        }
    }
}

fn decode_range_bound(cursor: &mut Cursor<'_>) -> Result<RangeBound> {
    let tag = cursor.read_u8("range bound tag")?;
    match tag {
        0 => Ok(RangeBound::Unbounded),
        1 | 2 => {
            let len = cursor.read_u32("range bound length")? as usize;
            let bytes = cursor.read_exact(len, "range bound payload")?;
            let value = SqlValue::decode(bytes)?;
            Ok(if tag == 1 {
                RangeBound::Included(value)
            } else {
                RangeBound::Excluded(value)
            })
        }
        unknown => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("unknown range bound tag {unknown}"),
        )),
    }
}

fn compare_scalar_values(left: &SqlValue, right: &SqlValue) -> Result<Ordering> {
    match (left, right) {
        (SqlValue::Bool(a), SqlValue::Bool(b)) => Ok(a.cmp(b)),
        (SqlValue::Int64(a), SqlValue::Int64(b)) => Ok(a.cmp(b)),
        (SqlValue::Int64(a), SqlValue::Float64(b)) => compare_int64_float64(*a, *b),
        (SqlValue::Float64(a), SqlValue::Int64(b)) => {
            compare_int64_float64(*b, *a).map(Ordering::reverse)
        }
        (SqlValue::UInt64(a), SqlValue::UInt64(b)) => Ok(a.cmp(b)),
        (SqlValue::Float64(a), SqlValue::Float64(b)) => compare_float64_values(*a, *b),
        (SqlValue::Uuid(a), SqlValue::Uuid(b)) => Ok(a.cmp(b)),
        (SqlValue::Timestamp(a), SqlValue::Timestamp(b)) => Ok(a.cmp(b)),
        (SqlValue::Text(a), SqlValue::Text(b)) => Ok(a.cmp(b)),
        (SqlValue::Bytes(a), SqlValue::Bytes(b)) => Ok(a.cmp(b)),
        _ => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "range comparison only supports matching scalar types",
        )),
    }
}

fn numeric_values_are_equal(left: &SqlValue, right: &SqlValue) -> bool {
    matches!(compare_numeric_values(left, right), Some(Ordering::Equal))
}

fn compare_numeric_values(left: &SqlValue, right: &SqlValue) -> Option<Ordering> {
    match (left, right) {
        (SqlValue::Int64(a), SqlValue::Float64(b)) => compare_int64_float64(*a, *b).ok(),
        (SqlValue::Float64(a), SqlValue::Int64(b)) => {
            compare_int64_float64(*b, *a).map(Ordering::reverse).ok()
        }
        _ => None,
    }
}

fn compare_int64_float64(left: i64, right: SqlFloat64) -> Result<Ordering> {
    let right = right.get();
    if right >= 9_223_372_036_854_775_808.0 {
        return Ok(Ordering::Less);
    }
    if right < -9_223_372_036_854_775_808.0 {
        return Ok(Ordering::Greater);
    }

    let truncated = right.trunc() as i64;
    match left.cmp(&truncated) {
        Ordering::Equal => compare_int64_to_fractional_float(right),
        other => Ok(other),
    }
}

fn compare_int64_to_fractional_float(value: f64) -> Result<Ordering> {
    match value.partial_cmp(&value.trunc()) {
        Some(Ordering::Greater) => Ok(Ordering::Less),
        Some(Ordering::Less) => Ok(Ordering::Greater),
        Some(Ordering::Equal) => Ok(Ordering::Equal),
        None => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "float64 comparison requires finite values",
        )),
    }
}

fn compare_float64_values(left: SqlFloat64, right: SqlFloat64) -> Result<Ordering> {
    left.get().partial_cmp(&right.get()).ok_or_else(|| {
        RnovError::new(
            ErrorKind::InvalidInput,
            "float64 comparison requires finite values",
        )
    })
}

fn validate_range_bound_type(element_type: &SqlType, bound: &RangeBound) -> Result<()> {
    if let Some(value) = bound.value()
        && (value.is_null() || value.data_type() != *element_type)
    {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "range bound type does not match declared element type",
        ));
    }
    Ok(())
}

fn bounds_are_empty(lower: &RangeBound, upper: &RangeBound) -> Result<bool> {
    let Some(lower_value) = lower.value() else {
        return Ok(false);
    };
    let Some(upper_value) = upper.value() else {
        return Ok(false);
    };

    match compare_scalar_values(lower_value, upper_value)? {
        Ordering::Greater => Ok(true),
        Ordering::Equal => Ok(!(lower.is_included() && upper.is_included())),
        Ordering::Less => Ok(false),
    }
}

fn min_lower_bound(left: &RangeBound, right: &RangeBound) -> Result<RangeBound> {
    compare_lower_bounds(left, right).map(|ordering| match ordering {
        Ordering::Less | Ordering::Equal => left.clone(),
        Ordering::Greater => right.clone(),
    })
}

fn max_lower_bound(left: &RangeBound, right: &RangeBound) -> Result<RangeBound> {
    compare_lower_bounds(left, right).map(|ordering| match ordering {
        Ordering::Greater | Ordering::Equal => left.clone(),
        Ordering::Less => right.clone(),
    })
}

fn min_upper_bound(left: &RangeBound, right: &RangeBound) -> Result<RangeBound> {
    compare_upper_bounds(left, right).map(|ordering| match ordering {
        Ordering::Less | Ordering::Equal => left.clone(),
        Ordering::Greater => right.clone(),
    })
}

fn max_upper_bound(left: &RangeBound, right: &RangeBound) -> Result<RangeBound> {
    compare_upper_bounds(left, right).map(|ordering| match ordering {
        Ordering::Greater | Ordering::Equal => left.clone(),
        Ordering::Less => right.clone(),
    })
}

fn compare_lower_bounds(left: &RangeBound, right: &RangeBound) -> Result<Ordering> {
    match (left.value(), right.value()) {
        (None, None) => Ok(Ordering::Equal),
        (None, Some(_)) => Ok(Ordering::Less),
        (Some(_), None) => Ok(Ordering::Greater),
        (Some(a), Some(b)) => match compare_scalar_values(a, b)? {
            Ordering::Equal => match (left.is_included(), right.is_included()) {
                (true, false) => Ok(Ordering::Less),
                (false, true) => Ok(Ordering::Greater),
                _ => Ok(Ordering::Equal),
            },
            other => Ok(other),
        },
    }
}

fn compare_upper_bounds(left: &RangeBound, right: &RangeBound) -> Result<Ordering> {
    match (left.value(), right.value()) {
        (None, None) => Ok(Ordering::Equal),
        (None, Some(_)) => Ok(Ordering::Greater),
        (Some(_), None) => Ok(Ordering::Less),
        (Some(a), Some(b)) => match compare_scalar_values(a, b)? {
            Ordering::Equal => match (left.is_included(), right.is_included()) {
                (true, false) => Ok(Ordering::Greater),
                (false, true) => Ok(Ordering::Less),
                _ => Ok(Ordering::Equal),
            },
            other => Ok(other),
        },
    }
}

fn bounds_touch_without_gap(left_upper: &RangeBound, right_lower: &RangeBound) -> Result<bool> {
    match (left_upper.value(), right_lower.value()) {
        (Some(left), Some(right)) if compare_scalar_values(left, right)? == Ordering::Equal => {
            Ok(left_upper.is_included() || right_lower.is_included())
        }
        _ => Ok(false),
    }
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

    fn read_len_prefixed_bytes(&mut self, name: &'static str) -> Result<Vec<u8>> {
        let len = self.read_u32(name)? as usize;
        Ok(self.read_exact(len, name)?.to_vec())
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
