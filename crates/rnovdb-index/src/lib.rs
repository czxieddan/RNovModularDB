use std::collections::{BTreeMap, BTreeSet};

use rnovdb_common::{ErrorKind, Result, RnovError, ids::PageId};
use rnovdb_types::{HStore, HStoreValue, SqlArray, SqlValue, TextVector};

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
