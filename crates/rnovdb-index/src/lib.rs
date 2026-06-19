use std::collections::BTreeMap;

use rnovdb_common::{ErrorKind, Result, RnovError, ids::PageId};

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
