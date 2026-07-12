use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    ops::Bound,
    sync::atomic::{AtomicUsize, Ordering as AtomicOrdering},
};

use rnmdb_common::{ErrorKind, Result, RnovError, ids::PageId};
use rnmdb_types::{
    HStore, HStoreValue, RangeBound, SqlArray, SqlRange, SqlType, SqlValue, TextVector,
};

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

    pub fn merge_from(&mut self, other: Self) -> Result<()> {
        if self.name != other.name || self.unique != other.unique {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "btree index merge requires matching index metadata",
            ));
        }
        for (key, pointers) in other.entries {
            for pointer in pointers {
                self.insert(key.clone(), pointer)?;
            }
        }
        Ok(())
    }

    pub fn point_lookup(&self, key: &IndexKey) -> Vec<IndexPointer> {
        self.entries.get(key).cloned().unwrap_or_default()
    }

    pub fn range_scan(&self, lower: &IndexKey, upper: &IndexKey) -> Vec<IndexPointer> {
        self.range_scan_bounds(Bound::Included(lower), Bound::Included(upper))
    }

    pub fn range_scan_bounds(
        &self,
        lower: Bound<&IndexKey>,
        upper: Bound<&IndexKey>,
    ) -> Vec<IndexPointer> {
        let lower = cloned_bound(lower);
        let upper = cloned_bound(upper);
        if range_bounds_are_empty(&lower, &upper) {
            return Vec::new();
        }
        self.entries
            .range((lower, upper))
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

fn range_bounds_are_empty(lower: &Bound<IndexKey>, upper: &Bound<IndexKey>) -> bool {
    let (Some(lower_key), Some(upper_key)) = (bound_key(lower), bound_key(upper)) else {
        return false;
    };

    match lower_key.cmp(upper_key) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Equal => excludes_equal_value(lower) || excludes_equal_value(upper),
        std::cmp::Ordering::Less => false,
    }
}

fn bound_key(bound: &Bound<IndexKey>) -> Option<&IndexKey> {
    match bound {
        Bound::Included(key) | Bound::Excluded(key) => Some(key),
        Bound::Unbounded => None,
    }
}

fn excludes_equal_value(bound: &Bound<IndexKey>) -> bool {
    matches!(bound, Bound::Excluded(_))
}

fn cloned_bound(bound: Bound<&IndexKey>) -> Bound<IndexKey> {
    match bound {
        Bound::Included(key) => Bound::Included(key.clone()),
        Bound::Excluded(key) => Bound::Excluded(key.clone()),
        Bound::Unbounded => Bound::Unbounded,
    }
}

#[derive(Clone, Debug)]
pub struct MemoryHashIndex {
    name: String,
    unique: bool,
    entries: BTreeMap<IndexKey, Vec<IndexPointer>>,
}

impl MemoryHashIndex {
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
                format!("unique hash index violation: {}", self.name),
            ));
        }
        if !pointers.contains(&pointer) {
            pointers.push(pointer);
        }
        Ok(())
    }

    pub fn merge_from(&mut self, other: Self) -> Result<()> {
        if self.name != other.name || self.unique != other.unique {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "hash index merge requires matching index metadata",
            ));
        }
        for (key, pointers) in other.entries {
            for pointer in pointers {
                self.insert(key.clone(), pointer)?;
            }
        }
        Ok(())
    }

    pub fn point_lookup(&self, key: &IndexKey) -> Vec<IndexPointer> {
        self.entries.get(key).cloned().unwrap_or_default()
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

    pub fn merge_from(&mut self, other: Self) -> Result<()> {
        if self.name != other.name {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "text index merge requires matching index metadata",
            ));
        }
        for (term, pointers) in other.terms {
            self.terms.entry(term).or_default().extend(pointers);
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

    pub fn merge_from(&mut self, other: Self) -> Result<()> {
        if self.name != other.name {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "value index merge requires matching index metadata",
            ));
        }
        for (token, pointers) in other.tokens {
            self.tokens.entry(token).or_default().extend(pointers);
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

#[derive(Debug)]
pub struct MemoryRangeIndex {
    name: String,
    element_type: Option<SqlType>,
    entries: Vec<RangeEntry>,
    lower_index: BTreeMap<RangeEndpointKey, BTreeSet<usize>>,
    upper_index: BTreeMap<RangeEndpointKey, BTreeSet<usize>>,
    last_recheck_count: AtomicUsize,
}

impl Clone for MemoryRangeIndex {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            element_type: self.element_type.clone(),
            entries: self.entries.clone(),
            lower_index: self.lower_index.clone(),
            upper_index: self.upper_index.clone(),
            last_recheck_count: AtomicUsize::new(self.last_recheck_count()),
        }
    }
}

impl MemoryRangeIndex {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            element_type: None,
            entries: Vec::new(),
            lower_index: BTreeMap::new(),
            upper_index: BTreeMap::new(),
            last_recheck_count: AtomicUsize::new(0),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn last_recheck_count(&self) -> usize {
        self.last_recheck_count.load(AtomicOrdering::Relaxed)
    }

    pub fn insert_range(&mut self, pointer: IndexPointer, range: &SqlRange) -> Result<()> {
        if range.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "cannot index an empty range",
            ));
        }
        self.ensure_range_type(range.element_type())?;
        let entry_id = self.entries.len();
        self.index_range_entry(entry_id, range)?;
        self.entries.push(RangeEntry {
            range: range.clone(),
            pointer,
        });
        Ok(())
    }

    pub fn merge_from(&mut self, other: Self) -> Result<()> {
        if self.name != other.name {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "range index merge requires matching index metadata",
            ));
        }
        if let Some(element_type) = other.element_type {
            self.ensure_range_type(&element_type)?;
        }
        for entry in other.entries {
            self.insert_range(entry.pointer, &entry.range)?;
        }
        Ok(())
    }

    pub fn overlap_scan(&self, query: &SqlRange) -> Result<Vec<IndexPointer>> {
        self.store_last_recheck_count(0);
        if query.is_empty() {
            return Ok(Vec::new());
        }
        self.ensure_query_range_type(query.element_type())?;

        let candidate_ids = self.overlap_candidate_ids(query)?;
        self.store_last_recheck_count(candidate_ids.len());
        let mut matches = Vec::new();
        for entry_id in candidate_ids {
            let entry = &self.entries[entry_id];
            if entry.range.overlaps(query)? {
                matches.push(entry.pointer);
            }
        }
        Ok(matches)
    }

    fn index_range_entry(&mut self, entry_id: usize, range: &SqlRange) -> Result<()> {
        let lower_key = lower_index_key(range.lower())?;
        let upper_key = upper_index_key(range.upper())?;
        self.lower_index
            .entry(lower_key)
            .or_default()
            .insert(entry_id);
        self.upper_index
            .entry(upper_key)
            .or_default()
            .insert(entry_id);
        Ok(())
    }

    fn overlap_candidate_ids(&self, query: &SqlRange) -> Result<Vec<usize>> {
        let lower_ids = self.lower_candidate_ids(query.upper())?;
        let upper_ids = self.upper_candidate_ids(query.lower())?;
        Ok(intersect_entry_ids(&lower_ids, &upper_ids))
    }

    fn lower_candidate_ids(&self, query_upper: &RangeBound) -> Result<BTreeSet<usize>> {
        let upper_key = upper_index_key(query_upper)?;
        Ok(self
            .lower_index
            .range(..=upper_key)
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect())
    }

    fn upper_candidate_ids(&self, query_lower: &RangeBound) -> Result<BTreeSet<usize>> {
        let lower_key = lower_index_key(query_lower)?;
        Ok(self
            .upper_index
            .range(lower_key..)
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect())
    }

    fn store_last_recheck_count(&self, value: usize) {
        self.last_recheck_count
            .store(value, AtomicOrdering::Relaxed);
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

#[derive(Clone, Debug)]
struct RangeEntry {
    range: SqlRange,
    pointer: IndexPointer,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RangeEndpointKey {
    NegInfinity,
    Finite(SqlValue),
    PosInfinity,
}

impl Ord for RangeEndpointKey {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::NegInfinity, Self::NegInfinity) | (Self::PosInfinity, Self::PosInfinity) => {
                Ordering::Equal
            }
            (Self::NegInfinity, _) | (_, Self::PosInfinity) => Ordering::Less,
            (Self::PosInfinity, _) | (_, Self::NegInfinity) => Ordering::Greater,
            (Self::Finite(left), Self::Finite(right)) => compare_endpoint_values(left, right),
        }
    }
}

impl PartialOrd for RangeEndpointKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn lower_index_key(bound: &RangeBound) -> Result<RangeEndpointKey> {
    match bound {
        RangeBound::Unbounded => Ok(RangeEndpointKey::NegInfinity),
        RangeBound::Included(value) | RangeBound::Excluded(value) => finite_endpoint_key(value),
    }
}

fn upper_index_key(bound: &RangeBound) -> Result<RangeEndpointKey> {
    match bound {
        RangeBound::Unbounded => Ok(RangeEndpointKey::PosInfinity),
        RangeBound::Included(value) | RangeBound::Excluded(value) => finite_endpoint_key(value),
    }
}

fn finite_endpoint_key(value: &SqlValue) -> Result<RangeEndpointKey> {
    if !is_indexable_range_endpoint(value) {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "range index endpoint must be a comparable scalar value",
        ));
    }
    Ok(RangeEndpointKey::Finite(value.clone()))
}

fn is_indexable_range_endpoint(value: &SqlValue) -> bool {
    matches!(
        value,
        SqlValue::Bool(_)
            | SqlValue::Int64(_)
            | SqlValue::UInt64(_)
            | SqlValue::Float64(_)
            | SqlValue::Uuid(_)
            | SqlValue::Timestamp(_)
            | SqlValue::Text(_)
            | SqlValue::Bytes(_)
    )
}

fn compare_endpoint_values(left: &SqlValue, right: &SqlValue) -> Ordering {
    left.sql_cmp(right)
        .expect("range endpoint comparison is valid")
        .expect("range endpoint values are non-null")
}

fn intersect_entry_ids(left: &BTreeSet<usize>, right: &BTreeSet<usize>) -> Vec<usize> {
    left.intersection(right).copied().collect()
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

    fn union(&self, other: &Self) -> Self {
        let axes = self
            .axes
            .iter()
            .copied()
            .zip(other.axes.iter().copied())
            .map(|(left, right)| AxisBounds {
                lower: left.lower().min(right.lower()),
                upper: left.upper().max(right.upper()),
            })
            .collect();
        Self { axes }
    }

    fn area(&self) -> f64 {
        self.axes
            .iter()
            .map(|axis| axis.upper().saturating_sub(axis.lower()).saturating_add(1) as f64)
            .product()
    }

    fn enlargement_for(&self, other: &Self) -> f64 {
        self.union(other).area() - self.area()
    }

    fn center_on_axis(&self, axis_index: usize) -> i64 {
        let axis = self.axes[axis_index];
        axis.lower().saturating_add(axis.upper()) / 2
    }
}

#[derive(Debug)]
pub struct MemoryBoundsIndex {
    name: String,
    rank: Option<usize>,
    entries: Vec<BoundsEntry>,
    tree: Option<BoundsRTree>,
    last_recheck_count: AtomicUsize,
    last_tree_node_visit_count: AtomicUsize,
}

impl Clone for MemoryBoundsIndex {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            rank: self.rank,
            entries: self.entries.clone(),
            tree: self.tree.clone(),
            last_recheck_count: AtomicUsize::new(self.last_recheck_count()),
            last_tree_node_visit_count: AtomicUsize::new(self.last_tree_node_visit_count()),
        }
    }
}

impl MemoryBoundsIndex {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            rank: None,
            entries: Vec::new(),
            tree: None,
            last_recheck_count: AtomicUsize::new(0),
            last_tree_node_visit_count: AtomicUsize::new(0),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn last_recheck_count(&self) -> usize {
        self.last_recheck_count.load(AtomicOrdering::Relaxed)
    }

    pub fn last_tree_node_visit_count(&self) -> usize {
        self.last_tree_node_visit_count
            .load(AtomicOrdering::Relaxed)
    }

    pub fn insert_box(&mut self, pointer: IndexPointer, bounds: &BoundingBox) -> Result<()> {
        self.ensure_rank(bounds.rank())?;
        let entry_id = self.entries.len();
        self.insert_tree_entry(entry_id, bounds)?;
        self.entries.push(BoundsEntry {
            bounds: bounds.clone(),
            pointer,
        });
        Ok(())
    }

    pub fn merge_from(&mut self, other: Self) -> Result<()> {
        if self.name != other.name {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "bounds index merge requires matching index metadata",
            ));
        }
        if let Some(rank) = other.rank {
            self.ensure_rank(rank)?;
        }
        for entry in other.entries {
            self.insert_box(entry.pointer, &entry.bounds)?;
        }
        Ok(())
    }

    pub fn intersection_scan(&self, query: &BoundingBox) -> Result<Vec<IndexPointer>> {
        self.store_last_recheck_count(0);
        self.store_last_tree_node_visit_count(0);
        self.ensure_query_rank(query.rank())?;
        if self.rank.is_none() {
            return Ok(Vec::new());
        }

        let candidate_ids = self.intersection_candidate_ids(query)?;
        self.store_last_recheck_count(candidate_ids.len());
        let mut matches = Vec::new();
        for entry_id in candidate_ids {
            let entry = &self.entries[entry_id];
            if entry.bounds.intersects(query)? {
                matches.push(entry.pointer);
            }
        }
        Ok(matches)
    }

    fn insert_tree_entry(&mut self, entry_id: usize, bounds: &BoundingBox) -> Result<()> {
        let tree = self.tree.as_mut().ok_or_else(|| {
            RnovError::new(
                ErrorKind::Internal,
                "bounds index rank must be initialized before insert",
            )
        })?;
        tree.insert(BoundsLeaf {
            entry_id,
            bounds: bounds.clone(),
        });
        Ok(())
    }

    fn intersection_candidate_ids(&self, query: &BoundingBox) -> Result<Vec<usize>> {
        let Some(tree) = &self.tree else {
            return Ok(Vec::new());
        };
        let mut stats = BoundsTreeSearchStats::default();
        let ids = tree.intersection_candidate_ids(query, &mut stats)?;
        self.store_last_tree_node_visit_count(stats.node_visits);
        Ok(ids)
    }

    fn store_last_recheck_count(&self, value: usize) {
        self.last_recheck_count
            .store(value, AtomicOrdering::Relaxed);
    }

    fn store_last_tree_node_visit_count(&self, value: usize) {
        self.last_tree_node_visit_count
            .store(value, AtomicOrdering::Relaxed);
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
                self.tree = Some(BoundsRTree::new(rank));
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

#[derive(Clone, Debug)]
struct BoundsEntry {
    bounds: BoundingBox,
    pointer: IndexPointer,
}

const BOUNDS_RTREE_MAX_CHILDREN: usize = 8;

#[derive(Clone, Debug)]
struct BoundsRTree {
    rank: usize,
    root: Option<BoundsTreeNode>,
}

impl BoundsRTree {
    fn new(rank: usize) -> Self {
        Self { rank, root: None }
    }

    fn insert(&mut self, leaf: BoundsLeaf) {
        if self.root.is_none() {
            self.root = Some(BoundsTreeNode::leaf(vec![leaf]));
            return;
        }
        let sibling = self
            .root
            .as_mut()
            .and_then(|root| root.insert_leaf(leaf, self.rank));
        if let Some(sibling) = sibling {
            let root = self.root.take().expect("root checked above");
            self.root = Some(BoundsTreeNode::internal(vec![root, sibling]));
        }
    }

    fn intersection_candidate_ids(
        &self,
        query: &BoundingBox,
        stats: &mut BoundsTreeSearchStats,
    ) -> Result<Vec<usize>> {
        let mut ids = Vec::new();
        if let Some(root) = &self.root {
            root.collect_intersections(query, stats, &mut ids)?;
        }
        Ok(ids)
    }
}

#[derive(Clone, Debug)]
struct BoundsTreeNode {
    bounds: BoundingBox,
    children: BoundsTreeChildren,
}

impl BoundsTreeNode {
    fn leaf(leaves: Vec<BoundsLeaf>) -> Self {
        let bounds = bounds_for_leaves(&leaves);
        Self {
            bounds,
            children: BoundsTreeChildren::Leaf(leaves),
        }
    }

    fn internal(nodes: Vec<Self>) -> Self {
        let bounds = bounds_for_nodes(&nodes);
        Self {
            bounds,
            children: BoundsTreeChildren::Internal(nodes),
        }
    }

    fn insert_leaf(&mut self, leaf: BoundsLeaf, rank: usize) -> Option<Self> {
        let sibling = match &mut self.children {
            BoundsTreeChildren::Leaf(leaves) => insert_leaf_child(leaves, leaf, rank),
            BoundsTreeChildren::Internal(nodes) => insert_internal_child(nodes, leaf, rank),
        };
        self.refresh_bounds();
        sibling
    }

    fn collect_intersections(
        &self,
        query: &BoundingBox,
        stats: &mut BoundsTreeSearchStats,
        ids: &mut Vec<usize>,
    ) -> Result<()> {
        stats.node_visits += 1;
        if !self.bounds.intersects(query)? {
            return Ok(());
        }
        match &self.children {
            BoundsTreeChildren::Leaf(leaves) => collect_leaf_intersections(leaves, query, ids),
            BoundsTreeChildren::Internal(nodes) => {
                collect_node_intersections(nodes, query, stats, ids)
            }
        }
    }

    fn refresh_bounds(&mut self) {
        self.bounds = match &self.children {
            BoundsTreeChildren::Leaf(leaves) => bounds_for_leaves(leaves),
            BoundsTreeChildren::Internal(nodes) => bounds_for_nodes(nodes),
        };
    }
}

#[derive(Clone, Debug)]
enum BoundsTreeChildren {
    Leaf(Vec<BoundsLeaf>),
    Internal(Vec<BoundsTreeNode>),
}

#[derive(Clone, Debug)]
struct BoundsLeaf {
    entry_id: usize,
    bounds: BoundingBox,
}

#[derive(Default)]
struct BoundsTreeSearchStats {
    node_visits: usize,
}

fn insert_leaf_child(
    leaves: &mut Vec<BoundsLeaf>,
    leaf: BoundsLeaf,
    rank: usize,
) -> Option<BoundsTreeNode> {
    leaves.push(leaf);
    (leaves.len() > BOUNDS_RTREE_MAX_CHILDREN).then(|| split_leaf_node(leaves, rank))
}

fn insert_internal_child(
    nodes: &mut Vec<BoundsTreeNode>,
    leaf: BoundsLeaf,
    rank: usize,
) -> Option<BoundsTreeNode> {
    let child_index = choose_bounds_child(nodes, &leaf.bounds);
    if let Some(sibling) = nodes[child_index].insert_leaf(leaf, rank) {
        nodes.push(sibling);
    }
    (nodes.len() > BOUNDS_RTREE_MAX_CHILDREN).then(|| split_internal_node(nodes, rank))
}

fn choose_bounds_child(nodes: &[BoundsTreeNode], bounds: &BoundingBox) -> usize {
    nodes
        .iter()
        .enumerate()
        .min_by(|(_, left), (_, right)| compare_child_enlargement(left, right, bounds))
        .map(|(index, _)| index)
        .expect("internal node has at least one child")
}

fn compare_child_enlargement(
    left: &BoundsTreeNode,
    right: &BoundsTreeNode,
    bounds: &BoundingBox,
) -> Ordering {
    left.bounds
        .enlargement_for(bounds)
        .total_cmp(&right.bounds.enlargement_for(bounds))
        .then_with(|| left.bounds.area().total_cmp(&right.bounds.area()))
}

fn split_leaf_node(leaves: &mut Vec<BoundsLeaf>, rank: usize) -> BoundsTreeNode {
    let axis = widest_leaf_axis(leaves, rank);
    leaves.sort_by(|left, right| compare_leaf_on_axis(left, right, axis));
    let right = leaves.split_off(leaves.len() / 2);
    BoundsTreeNode::leaf(right)
}

fn split_internal_node(nodes: &mut Vec<BoundsTreeNode>, rank: usize) -> BoundsTreeNode {
    let axis = widest_node_axis(nodes, rank);
    nodes.sort_by(|left, right| compare_node_on_axis(left, right, axis));
    let right = nodes.split_off(nodes.len() / 2);
    BoundsTreeNode::internal(right)
}

fn widest_leaf_axis(leaves: &[BoundsLeaf], rank: usize) -> usize {
    (0..rank)
        .max_by_key(|axis| leaf_axis_spread(leaves, *axis))
        .unwrap_or(0)
}

fn widest_node_axis(nodes: &[BoundsTreeNode], rank: usize) -> usize {
    (0..rank)
        .max_by_key(|axis| node_axis_spread(nodes, *axis))
        .unwrap_or(0)
}

fn leaf_axis_spread(leaves: &[BoundsLeaf], axis: usize) -> i64 {
    axis_center_spread(leaves.iter().map(|leaf| leaf.bounds.center_on_axis(axis)))
}

fn node_axis_spread(nodes: &[BoundsTreeNode], axis: usize) -> i64 {
    axis_center_spread(nodes.iter().map(|node| node.bounds.center_on_axis(axis)))
}

fn axis_center_spread(centers: impl Iterator<Item = i64>) -> i64 {
    let mut min = i64::MAX;
    let mut max = i64::MIN;
    for center in centers {
        min = min.min(center);
        max = max.max(center);
    }
    max.saturating_sub(min)
}

fn compare_leaf_on_axis(left: &BoundsLeaf, right: &BoundsLeaf, axis: usize) -> Ordering {
    left.bounds
        .center_on_axis(axis)
        .cmp(&right.bounds.center_on_axis(axis))
        .then_with(|| left.entry_id.cmp(&right.entry_id))
}

fn compare_node_on_axis(left: &BoundsTreeNode, right: &BoundsTreeNode, axis: usize) -> Ordering {
    left.bounds
        .center_on_axis(axis)
        .cmp(&right.bounds.center_on_axis(axis))
        .then_with(|| left.bounds.area().total_cmp(&right.bounds.area()))
}

fn collect_leaf_intersections(
    leaves: &[BoundsLeaf],
    query: &BoundingBox,
    ids: &mut Vec<usize>,
) -> Result<()> {
    for leaf in leaves {
        if leaf.bounds.intersects(query)? {
            ids.push(leaf.entry_id);
        }
    }
    Ok(())
}

fn collect_node_intersections(
    nodes: &[BoundsTreeNode],
    query: &BoundingBox,
    stats: &mut BoundsTreeSearchStats,
    ids: &mut Vec<usize>,
) -> Result<()> {
    for node in nodes {
        node.collect_intersections(query, stats, ids)?;
    }
    Ok(())
}

fn bounds_for_leaves(leaves: &[BoundsLeaf]) -> BoundingBox {
    union_bounds(leaves.iter().map(|leaf| &leaf.bounds))
}

fn bounds_for_nodes(nodes: &[BoundsTreeNode]) -> BoundingBox {
    union_bounds(nodes.iter().map(|node| &node.bounds))
}

fn union_bounds<'a>(mut bounds: impl Iterator<Item = &'a BoundingBox>) -> BoundingBox {
    let first = bounds
        .next()
        .expect("R-tree nodes are never built from empty children")
        .clone();
    bounds.fold(first, |combined, next| combined.union(next))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockRange {
    start_page: PageId,
    end_page: PageId,
}

impl BlockRange {
    pub fn new(start_page: PageId, end_page: PageId) -> Result<Self> {
        if start_page > end_page {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "page range start cannot exceed end",
            ));
        }
        Ok(Self {
            start_page,
            end_page,
        })
    }

    pub fn start_page(self) -> PageId {
        self.start_page
    }

    pub fn end_page(self) -> PageId {
        self.end_page
    }
}

#[derive(Clone, Debug)]
pub struct BlockSummaryIndex {
    name: String,
    key_family: Option<IndexKeyFamily>,
    summaries: Vec<BlockSummary>,
}

impl BlockSummaryIndex {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            key_family: None,
            summaries: Vec::new(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn insert_summary(
        &mut self,
        pages: BlockRange,
        min_key: IndexKey,
        max_key: IndexKey,
    ) -> Result<()> {
        let family = ensure_same_key_family(&min_key, &max_key)?;
        if min_key > max_key {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "summary lower key cannot exceed upper key",
            ));
        }
        self.ensure_family(family)?;
        self.summaries.push(BlockSummary {
            pages,
            min_key,
            max_key,
        });
        Ok(())
    }

    pub fn range_candidates(&self, lower: &IndexKey, upper: &IndexKey) -> Result<Vec<BlockRange>> {
        let family = ensure_same_key_family(lower, upper)?;
        if lower > upper {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "query lower key cannot exceed upper key",
            ));
        }
        self.ensure_query_family(family)?;

        Ok(self
            .summaries
            .iter()
            .filter(|summary| summary.max_key >= *lower && summary.min_key <= *upper)
            .map(|summary| summary.pages)
            .collect())
    }

    fn ensure_family(&mut self, family: IndexKeyFamily) -> Result<()> {
        match self.key_family {
            Some(existing) if existing != family => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "summary key family does not match index",
            )),
            Some(_) => Ok(()),
            None => {
                self.key_family = Some(family);
                Ok(())
            }
        }
    }

    fn ensure_query_family(&self, family: IndexKeyFamily) -> Result<()> {
        match self.key_family {
            Some(existing) if existing != family => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "summary query key family does not match index",
            )),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug)]
struct BlockSummary {
    pages: BlockRange,
    min_key: IndexKey,
    max_key: IndexKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IndexKeyFamily {
    Int64,
    Text,
}

fn ensure_same_key_family(left: &IndexKey, right: &IndexKey) -> Result<IndexKeyFamily> {
    let left_family = index_key_family(left);
    let right_family = index_key_family(right);
    if left_family != right_family {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "index key family mismatch",
        ));
    }
    Ok(left_family)
}

fn index_key_family(key: &IndexKey) -> IndexKeyFamily {
    match key {
        IndexKey::Int64(_) => IndexKeyFamily::Int64,
        IndexKey::Text(_) => IndexKeyFamily::Text,
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CompositeIndexKey {
    parts: Vec<IndexKey>,
}

impl CompositeIndexKey {
    pub fn new(parts: Vec<IndexKey>) -> Result<Self> {
        if parts.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "composite index key must have at least one part",
            ));
        }
        Ok(Self { parts })
    }

    pub fn parts(&self) -> &[IndexKey] {
        &self.parts
    }

    pub fn rank(&self) -> usize {
        self.parts.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompositeKeyPattern {
    parts: Vec<Option<IndexKey>>,
}

impl CompositeKeyPattern {
    pub fn new(parts: Vec<Option<IndexKey>>) -> Result<Self> {
        if parts.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "composite key pattern must have at least one part",
            ));
        }
        Ok(Self { parts })
    }

    pub fn parts(&self) -> &[Option<IndexKey>] {
        &self.parts
    }

    pub fn rank(&self) -> usize {
        self.parts.len()
    }

    pub fn has_bound_part(&self) -> bool {
        self.parts.iter().any(Option::is_some)
    }

    fn matches(&self, key: &CompositeIndexKey) -> bool {
        self.parts
            .iter()
            .zip(key.parts.iter())
            .all(|(pattern_part, key_part)| match pattern_part {
                Some(pattern_key) => pattern_key == key_part,
                None => true,
            })
    }
}

#[derive(Clone, Debug)]
pub struct MemoryCompositeIndex {
    name: String,
    unique: bool,
    rank: Option<usize>,
    entries: BTreeMap<CompositeIndexKey, Vec<IndexPointer>>,
}

impl MemoryCompositeIndex {
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

    pub fn insert(&mut self, key: CompositeIndexKey, pointer: IndexPointer) -> Result<()> {
        self.ensure_rank(key.rank())?;
        let pointers = self.entries.entry(key).or_default();
        if self.unique && !pointers.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("unique composite index violation: {}", self.name),
            ));
        }
        if !pointers.contains(&pointer) {
            pointers.push(pointer);
        }
        Ok(())
    }

    pub fn merge_from(&mut self, other: Self) -> Result<()> {
        if self.name != other.name || self.unique != other.unique {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "composite index merge requires matching index metadata",
            ));
        }
        for (key, pointers) in other.entries {
            for pointer in pointers {
                self.insert(key.clone(), pointer)?;
            }
        }
        Ok(())
    }

    pub fn point_lookup(&self, key: &CompositeIndexKey) -> Vec<IndexPointer> {
        self.entries.get(key).cloned().unwrap_or_default()
    }

    pub fn skip_scan(&self, pattern: &CompositeKeyPattern) -> Result<Vec<IndexPointer>> {
        if !pattern.has_bound_part() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "skip scan requires at least one bound key part",
            ));
        }
        self.ensure_query_rank(pattern.rank())?;

        Ok(self
            .entries
            .iter()
            .filter(|(key, _)| pattern.matches(key))
            .flat_map(|(_, pointers)| pointers.iter().copied())
            .collect())
    }

    fn new(name: impl Into<String>, unique: bool) -> Self {
        Self {
            name: name.into(),
            unique,
            rank: None,
            entries: BTreeMap::new(),
        }
    }

    fn ensure_rank(&mut self, rank: usize) -> Result<()> {
        match self.rank {
            Some(existing) if existing != rank => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "composite index rank mismatch",
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
                "composite query rank does not match index rank",
            )),
            _ => Ok(()),
        }
    }
}
