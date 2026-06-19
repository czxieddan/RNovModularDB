use std::collections::{BTreeMap, BTreeSet};

use rnovdb_common::{ErrorKind, Result, RnovError, ids::PageId};
use rnovdb_types::{HStore, HStoreValue, SqlArray, SqlRange, SqlType, SqlValue, TextVector};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum IndexKey {
    Int64(i64),
    Text(String),
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IndexPointer {
    page_id: PageId,
    slot_id: u16,
}

impl IndexPointer {
    pub fn new(page_id: PageId, slot_id: u16) -> Self {
        Self { page_id, slot_id }
    }

    pub fn page_id(self) -> PageId {
        self.page_id
    }

    pub fn slot_id(self) -> u16 {
        self.slot_id
    }
}

#[derive(Clone, Debug)]
pub struct MemoryBTreeIndex {
    name: String,
    unique: bool,
    entries: BTreeMap<IndexKey, Vec<IndexPointer>>,
}

impl MemoryBTreeIndex {
    pub fn unique(name: impl Into<String>) -> Self {
        Self::new(name, true)
    }

    pub fn non_unique(name: impl Into<String>) -> Self {
        Self::new(name, false)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_unique(&self) -> bool {
        self.unique
    }

    pub fn insert(&mut self, key: IndexKey, pointer: IndexPointer) -> Result<()> {
        let pointers = self.entries.entry(key).or_default();
        if self.unique && !pointers.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("unique index violation: {}", self.name),
            ));
        }
        if !pointers.contains(&pointer) {
            pointers.push(pointer);
        }
        Ok(())
    }

    pub fn point_lookup(&self, key: &IndexKey) -> Vec<IndexPointer> {
        self.entries.get(key).cloned().unwrap_or_default()
    }

    pub fn range_scan(&self, lower: &IndexKey, upper: &IndexKey) -> Vec<IndexPointer> {
        self.entries
            .range(lower.clone()..=upper.clone())
            .flat_map(|(_, pointers)| pointers.iter().copied())
            .collect()
    }

    fn new(name: impl Into<String>, unique: bool) -> Self {
        Self {
            name: name.into(),
            unique,
            entries: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct InvertedTextIndex {
    name: String,
    terms: BTreeMap<String, BTreeSet<IndexPointer>>,
}

impl InvertedTextIndex {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            terms: BTreeMap::new(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn insert_document(&mut self, pointer: IndexPointer, vector: &TextVector) -> Result<()> {
        if vector.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "cannot index an empty text vector",
            ));
        }
        for lexeme in vector.iter() {
            self.terms
                .entry(lexeme.term().to_string())
                .or_default()
                .insert(pointer);
        }
        Ok(())
    }

    pub fn lookup(&self, term: &str) -> Vec<IndexPointer> {
        self.terms
            .get(term)
            .map(|pointers| pointers.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn lookup_all<'a>(&self, terms: impl IntoIterator<Item = &'a str>) -> Vec<IndexPointer> {
        let mut terms = terms.into_iter();
        let Some(first) = terms.next() else {
            return Vec::new();
        };

        let mut matches = self.terms.get(first).cloned().unwrap_or_else(BTreeSet::new);
        for term in terms {
            let Some(next) = self.terms.get(term) else {
                return Vec::new();
            };
            matches = matches.intersection(next).copied().collect();
            if matches.is_empty() {
                return Vec::new();
            }
        }

        matches.into_iter().collect()
    }
}

#[derive(Clone, Debug)]
pub struct InvertedValueIndex {
    name: String,
    tokens: BTreeMap<ValueToken, BTreeSet<IndexPointer>>,
}

impl InvertedValueIndex {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            tokens: BTreeMap::new(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn insert_array(&mut self, pointer: IndexPointer, array: &SqlArray) -> Result<()> {
        if array.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "cannot index an empty array",
            ));
        }
        for value in array.values() {
            self.insert_token(ValueToken::ArrayValue(value.encode()), pointer);
        }
        Ok(())
    }

    pub fn insert_hstore(&mut self, pointer: IndexPointer, hstore: &HStore) -> Result<()> {
        if hstore.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "cannot index an empty hstore",
            ));
        }
        for (key, value) in hstore.iter() {
            self.insert_token(ValueToken::HStoreKey(key.clone()), pointer);
            self.insert_token(
                ValueToken::HStorePair(key.clone(), hstore_value_token(value)),
                pointer,
            );
        }
        Ok(())
    }

    pub fn lookup_array_value(&self, value: &SqlValue) -> Vec<IndexPointer> {
        self.lookup_token(&ValueToken::ArrayValue(value.encode()))
    }

    pub fn lookup_hstore_key(&self, key: &str) -> Vec<IndexPointer> {
        self.lookup_token(&ValueToken::HStoreKey(key.to_string()))
    }

    pub fn lookup_hstore_pair(&self, key: &str, value: &HStoreValue) -> Vec<IndexPointer> {
        self.lookup_token(&ValueToken::HStorePair(
            key.to_string(),
            hstore_value_token(value),
        ))
    }

    fn insert_token(&mut self, token: ValueToken, pointer: IndexPointer) {
        self.tokens.entry(token).or_default().insert(pointer);
    }

    fn lookup_token(&self, token: &ValueToken) -> Vec<IndexPointer> {
        self.tokens
            .get(token)
            .map(|pointers| pointers.iter().copied().collect())
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ValueToken {
    ArrayValue(Vec<u8>),
    HStoreKey(String),
    HStorePair(String, HStoreValueToken),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum HStoreValueToken {
    Null,
    Text(String),
}

fn hstore_value_token(value: &HStoreValue) -> HStoreValueToken {
    match value {
        HStoreValue::Null => HStoreValueToken::Null,
        HStoreValue::Text(text) => HStoreValueToken::Text(text.clone()),
    }
}

#[derive(Clone, Debug)]
pub struct MemoryRangeIndex {
    name: String,
    element_type: Option<SqlType>,
    entries: Vec<(SqlRange, IndexPointer)>,
}

impl MemoryRangeIndex {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            element_type: None,
            entries: Vec::new(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn insert_range(&mut self, pointer: IndexPointer, range: &SqlRange) -> Result<()> {
        if range.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "cannot index an empty range",
            ));
        }
        self.ensure_range_type(range.element_type())?;
        self.entries.push((range.clone(), pointer));
        Ok(())
    }

    pub fn overlap_scan(&self, query: &SqlRange) -> Result<Vec<IndexPointer>> {
        if query.is_empty() {
            return Ok(Vec::new());
        }
        self.ensure_query_range_type(query.element_type())?;

        let mut matches = Vec::new();
        for (range, pointer) in &self.entries {
            if range.overlaps(query)? {
                matches.push(*pointer);
            }
        }
        Ok(matches)
    }

    fn ensure_range_type(&mut self, element_type: &SqlType) -> Result<()> {
        match &self.element_type {
            Some(existing) if existing != element_type => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "range index element type mismatch",
            )),
            Some(_) => Ok(()),
            None => {
                self.element_type = Some(element_type.clone());
                Ok(())
            }
        }
    }

    fn ensure_query_range_type(&self, element_type: &SqlType) -> Result<()> {
        match &self.element_type {
            Some(existing) if existing != element_type => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "range query type does not match index element type",
            )),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AxisBounds {
    lower: i64,
    upper: i64,
}

impl AxisBounds {
    pub fn new(lower: i64, upper: i64) -> Result<Self> {
        if lower > upper {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "axis lower bound cannot exceed upper bound",
            ));
        }
        Ok(Self { lower, upper })
    }

    pub fn lower(self) -> i64 {
        self.lower
    }

    pub fn upper(self) -> i64 {
        self.upper
    }

    pub fn intersects(self, other: Self) -> bool {
        self.lower <= other.upper && other.lower <= self.upper
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundingBox {
    axes: Vec<AxisBounds>,
}

impl BoundingBox {
    pub fn new(axes: Vec<AxisBounds>) -> Result<Self> {
        if axes.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "bounding box rank must be greater than zero",
            ));
        }
        Ok(Self { axes })
    }

    pub fn axes(&self) -> &[AxisBounds] {
        &self.axes
    }

    pub fn rank(&self) -> usize {
        self.axes.len()
    }

    pub fn intersects(&self, other: &Self) -> Result<bool> {
        if self.rank() != other.rank() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "bounding box rank mismatch",
            ));
        }

        Ok(self
            .axes
            .iter()
            .zip(other.axes.iter())
            .all(|(left, right)| left.intersects(*right)))
    }
}

#[derive(Clone, Debug)]
pub struct MemoryBoundsIndex {
    name: String,
    rank: Option<usize>,
    entries: Vec<(BoundingBox, IndexPointer)>,
}

impl MemoryBoundsIndex {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            rank: None,
            entries: Vec::new(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn insert_box(&mut self, pointer: IndexPointer, bounds: &BoundingBox) -> Result<()> {
        self.ensure_rank(bounds.rank())?;
        self.entries.push((bounds.clone(), pointer));
        Ok(())
    }

    pub fn intersection_scan(&self, query: &BoundingBox) -> Result<Vec<IndexPointer>> {
        self.ensure_query_rank(query.rank())?;

        let mut matches = Vec::new();
        for (bounds, pointer) in &self.entries {
            if bounds.intersects(query)? {
                matches.push(*pointer);
            }
        }
        Ok(matches)
    }

    fn ensure_rank(&mut self, rank: usize) -> Result<()> {
        match self.rank {
            Some(existing) if existing != rank => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "bounding index rank mismatch",
            )),
            Some(_) => Ok(()),
            None => {
                self.rank = Some(rank);
                Ok(())
            }
        }
    }

    fn ensure_query_rank(&self, rank: usize) -> Result<()> {
        match self.rank {
            Some(existing) if existing != rank => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "bounding query rank does not match index rank",
            )),
            _ => Ok(()),
        }
    }
}
