use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    future::Future,
    ops::Bound,
    sync::{
        Arc, RwLock, RwLockReadGuard, RwLockWriteGuard,
        atomic::{AtomicBool, Ordering as AtomicOrdering},
    },
    thread,
};

use rnmdb_catalog::{
    Catalog, Column as CatalogColumn, Index as CatalogIndex, IndexKey as CatalogIndexKey,
    IndexMethod, Table as CatalogTable,
};
use rnmdb_common::Result;
use rnmdb_common::{
    ErrorKind, RnovError,
    ids::{PageId, RelationId, RoleId},
};
use rnmdb_fts::{SimpleTokenizer, TextPhraseQuery, TextQuery, TextVectorBuilder};
use rnmdb_index::{
    AxisBounds, BlockRange, BlockSummaryIndex, BoundingBox, CompositeIndexKey, CompositeKeyPattern,
    IndexKey, IndexPointer, InvertedTextIndex, InvertedValueIndex, MemoryBTreeIndex,
    MemoryBoundsIndex, MemoryCompositeIndex, MemoryHashIndex, MemoryRangeIndex,
};
use rnmdb_planner::{
    cost::{TableStatistics, TextLexemeStatistics},
    logical::{
        AggregateFunction, AggregateItem, GroupedAggregateItem, GroupedAggregateItemKind,
        LogicalPlan, LogicalPlanner, ProjectionItem, WindowFunction, WindowItem,
    },
    physical::{InvertedValueQuery, PhysicalPlan, SetOperationKind},
};
use rnmdb_security::ColumnKeyMaterial;
use rnmdb_sql::{
    ast::{
        CaseWhen, ColumnDef, Expr, GeneratedColumn, Ident, IndexKeyDef, JoinKind, OrderByExpr,
        SelectSubquery,
    },
    parser::parse_expr,
    rewrite_expr_tree,
};
use rnmdb_types::{
    ArrayDimension, HStore, HStoreValue, RangeBound, SqlArray, SqlFloat64, SqlJson, SqlRange,
    SqlTimestamp, SqlType, SqlUuid, SqlValue, TextVector, Truth,
};

use crate::{
    column_crypto::ColumnCryptoState,
    durable::DurableTableRows,
    row::RowCodec,
    vector::{ColumnSchema, Row, VectorBatch, validate_row_against_columns},
};

mod async_task;
mod set_ops;
mod sort;

use async_task::{BlockingMutationTask, BlockingResultTask};
use set_ops::{
    apply_distinct_cancellable, apply_except_cancellable, apply_intersect_cancellable,
    apply_union_cancellable,
};
use sort::{
    apply_sort_cancellable, apply_sort_with_key_values_cancellable, compare_sort_row_keys,
    compare_sort_rows, sort_rows,
};

const MEMORY_INDEX_PAGE_ID: PageId = PageId::new(0);
const MEMORY_SUMMARY_BLOCK_ROWS: usize = 2;
const RECURSIVE_CTE_MAX_ITERATIONS: usize = 1000;

#[derive(Clone, Debug)]
pub struct MemoryTable {
    columns: Vec<ColumnSchema>,
    rows: Vec<Row>,
    indexes: BTreeMap<String, MemoryTableIndex>,
}

impl MemoryTable {
    pub fn new(columns: Vec<ColumnSchema>) -> Result<Self> {
        let _ = VectorBatch::new(columns.clone(), Vec::new())?;
        Ok(Self {
            columns,
            rows: Vec::new(),
            indexes: BTreeMap::new(),
        })
    }

    pub fn columns(&self) -> &[ColumnSchema] {
        &self.columns
    }

    pub fn insert(&mut self, row: Row) -> Result<()> {
        validate_row_against_columns(&self.columns, &row)?;
        let pointer = pointer_for_slot(self.rows.len())?;
        for index in self.indexes.values_mut() {
            if let Err(err) = index.insert_row(&self.columns, &row, pointer) {
                self.rebuild_indexes()?;
                return Err(err);
            }
        }
        self.rows.push(row);
        Ok(())
    }

    pub fn scan(&self) -> VectorBatch {
        VectorBatch::new(self.columns.clone(), self.rows.clone())
            .expect("stored rows are validated on insert")
    }

    fn snapshot_rows(&self, name: &str) -> Result<DurableTableRows> {
        let rows = self
            .rows
            .iter()
            .map(|row| RowCodec::encode(&self.columns, row))
            .collect::<Result<Vec<_>>>()?;
        Ok(DurableTableRows::new(name, rows))
    }

    fn index_scan(&self, index_name: &str, column: &str, value: &Expr) -> Result<VectorBatch> {
        let index = self.indexes.get(index_name).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("index not found: {index_name}"),
            )
        })?;
        let column_index = column_index(&self.columns, column)?;
        let key = index_key_from_literal_expr(value)?;
        let pointers = index.point_lookup(column_index, &key)?;
        self.rows_for_pointers(&pointers)
    }

    fn expression_index_scan(
        &self,
        index_name: &str,
        expr: &Expr,
        value: &Expr,
    ) -> Result<VectorBatch> {
        let index = self.indexes.get(index_name).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("index not found: {index_name}"),
            )
        })?;
        let key = index_key_from_literal_expr(value)?;
        let pointers = index.expression_lookup(expr, &key)?;
        self.rows_for_pointers(&pointers)
    }

    fn index_range_scan(
        &self,
        index_name: &str,
        column: &str,
        lower: Option<&Expr>,
        lower_inclusive: bool,
        upper: Option<&Expr>,
        upper_inclusive: bool,
    ) -> Result<VectorBatch> {
        let index = self.indexes.get(index_name).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("index not found: {index_name}"),
            )
        })?;
        let column_index = column_index(&self.columns, column)?;
        let lower = maybe_bound_key_from_expr(lower)?;
        let upper = maybe_bound_key_from_expr(upper)?;
        let pointers = index.range_lookup(
            column_index,
            bound_ref(lower.as_ref(), lower_inclusive),
            bound_ref(upper.as_ref(), upper_inclusive),
        )?;
        self.rows_for_pointers(&pointers)
    }

    fn index_skip_scan(&self, index_name: &str, column: &str, value: &Expr) -> Result<VectorBatch> {
        let index = self.indexes.get(index_name).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("index not found: {index_name}"),
            )
        })?;
        let column_index = column_index(&self.columns, column)?;
        let key = index_key_from_literal_expr(value)?;
        let pointers = index.skip_lookup(column_index, &key)?;
        self.rows_for_pointers(&pointers)
    }

    fn index_point_lookup_value(
        &self,
        index_name: &str,
        column: &str,
        value: &SqlValue,
    ) -> Result<VectorBatch> {
        let index = self.lookup_index(index_name).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("index not found: {index_name}"),
            )
        })?;
        let column_index = column_index(&self.columns, column)?;
        let Some(key) = index_key_from_value(value)? else {
            return VectorBatch::new(self.columns.clone(), Vec::new());
        };
        let pointers = index.point_lookup(column_index, &key)?;
        self.rows_for_pointers(&pointers)
    }

    fn point_lookup_index_for_column(&self, column: usize) -> Option<&str> {
        self.indexes
            .iter()
            .find(|(_, index)| index.supports_point_lookup_column(column))
            .map(|(name, _)| name.as_str())
    }

    fn lookup_index(&self, name: &str) -> Option<&MemoryTableIndex> {
        self.indexes.get(name).or_else(|| {
            name.rsplit_once('.')
                .and_then(|(_, unqualified)| self.indexes.get(unqualified))
        })
    }

    fn text_index_scan(
        &self,
        index_name: &str,
        column: &str,
        query: &str,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        let index = self.indexes.get(index_name).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("index not found: {index_name}"),
            )
        })?;
        let column_index = column_index(&self.columns, column)?;
        let required_terms = required_text_query_terms(query)?;
        if required_terms.is_empty() {
            return apply_text_search_cancellable(self.scan(), column, query, cancellation);
        }
        let pointers = index.text_lookup(column_index, &required_terms)?;
        let batch = self.rows_for_pointers(&pointers)?;
        apply_text_search_cancellable(batch, column, query, cancellation)
    }

    fn inverted_value_scan(
        &self,
        index_name: &str,
        column: &str,
        query: &InvertedValueQuery,
    ) -> Result<VectorBatch> {
        let index = self.indexes.get(index_name).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("index not found: {index_name}"),
            )
        })?;
        let column_index = column_index(&self.columns, column)?;
        let pointers = index.inverted_value_lookup(column_index, query)?;
        self.rows_for_pointers(&pointers)
    }

    fn block_summary_scan(
        &self,
        index_name: &str,
        column: &str,
        lower: &Expr,
        lower_inclusive: bool,
        upper: &Expr,
        upper_inclusive: bool,
    ) -> Result<VectorBatch> {
        let index = self.indexes.get(index_name).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("index not found: {index_name}"),
            )
        })?;
        let column_index = column_index(&self.columns, column)?;
        let lower_key = index_key_from_literal_expr(lower)?;
        let upper_key = index_key_from_literal_expr(upper)?;
        let pointers = index.block_summary_lookup(column_index, &lower_key, &upper_key)?;
        let batch = self.rows_for_pointers(&pointers)?;
        apply_filter_cancellable(
            batch,
            &between_predicate(column, lower, lower_inclusive, upper, upper_inclusive),
            &CancellationToken::default(),
        )
    }

    fn range_overlap_scan(
        &self,
        index_name: &str,
        column: &str,
        range: &Expr,
    ) -> Result<VectorBatch> {
        let index = self.indexes.get(index_name).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("index not found: {index_name}"),
            )
        })?;
        let column_index = column_index(&self.columns, column)?;
        let range = range_from_literal_expr(range)?;
        let pointers = index.range_overlap_lookup(column_index, &range)?;
        self.rows_for_pointers(&pointers)
    }

    fn bounds_overlap_scan(
        &self,
        index_name: &str,
        column: &str,
        bounds: &Expr,
    ) -> Result<VectorBatch> {
        let index = self.indexes.get(index_name).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("index not found: {index_name}"),
            )
        })?;
        let column_index = column_index(&self.columns, column)?;
        let bounds = bounding_box_from_expr(bounds)?;
        let pointers = index.bounds_overlap_lookup(column_index, &bounds)?;
        self.rows_for_pointers(&pointers)
    }

    fn try_index_scan(&self, column: &str, value: &Expr) -> Result<Option<VectorBatch>> {
        let column_index = column_index(&self.columns, column)?;
        let Some(key) = maybe_index_key_from_literal_expr(value)? else {
            return Ok(None);
        };
        let Some(index) = self
            .indexes
            .values()
            .find(|index| index.supports_leading_column(column_index))
        else {
            return Ok(None);
        };
        let pointers = index.point_lookup(column_index, &key)?;
        self.rows_for_pointers(&pointers).map(Some)
    }

    fn try_expression_index_scan(&self, expr: &Expr, value: &Expr) -> Result<Option<VectorBatch>> {
        let Some(key) = maybe_index_key_from_literal_expr(value)? else {
            return Ok(None);
        };
        for index in self.indexes.values() {
            let pointers = index.expression_lookup(expr, &key)?;
            if !pointers.is_empty() {
                return self.rows_for_pointers(&pointers).map(Some);
            }
        }
        Ok(None)
    }

    fn try_index_skip_scan(&self, column: &str, value: &Expr) -> Result<Option<VectorBatch>> {
        let column_index = column_index(&self.columns, column)?;
        let Some(key) = maybe_index_key_from_literal_expr(value)? else {
            return Ok(None);
        };
        let Some(index) = self
            .indexes
            .values()
            .find(|index| index.supports_skip_column(column_index))
        else {
            return Ok(None);
        };
        let pointers = index.skip_lookup(column_index, &key)?;
        self.rows_for_pointers(&pointers).map(Some)
    }

    fn try_text_index_scan(
        &self,
        column: &str,
        query: &str,
        cancellation: &CancellationToken,
    ) -> Result<Option<VectorBatch>> {
        let column_index = column_index(&self.columns, column)?;
        let required_terms = required_text_query_terms(query)?;
        if required_terms.is_empty() {
            return Ok(None);
        }
        let Some(index) = self
            .indexes
            .values()
            .find(|index| index.supports_text_column(column_index))
        else {
            return Ok(None);
        };
        let pointers = index.text_lookup(column_index, &required_terms)?;
        let batch = self.rows_for_pointers(&pointers)?;
        apply_text_search_cancellable(batch, column, query, cancellation).map(Some)
    }

    fn try_inverted_value_scan(
        &self,
        column: &str,
        query: &InvertedValueQuery,
    ) -> Result<Option<VectorBatch>> {
        let column_index = column_index(&self.columns, column)?;
        let Some(index) = self
            .indexes
            .values()
            .find(|index| index.supports_inverted_value_column(column_index))
        else {
            return Ok(None);
        };
        let pointers = index.inverted_value_lookup(column_index, query)?;
        self.rows_for_pointers(&pointers).map(Some)
    }

    fn try_block_summary_scan(
        &self,
        column: &str,
        lower: Option<&Expr>,
        lower_inclusive: bool,
        upper: Option<&Expr>,
        upper_inclusive: bool,
    ) -> Result<Option<VectorBatch>> {
        let (Some(lower), Some(upper)) = (lower, upper) else {
            return Ok(None);
        };
        let column_index = column_index(&self.columns, column)?;
        let lower_key = index_key_from_literal_expr(lower)?;
        let upper_key = index_key_from_literal_expr(upper)?;
        let Some(index) = self
            .indexes
            .values()
            .find(|index| index.supports_block_summary_column(column_index))
        else {
            return Ok(None);
        };
        let pointers = index.block_summary_lookup(column_index, &lower_key, &upper_key)?;
        let batch = self.rows_for_pointers(&pointers)?;
        apply_filter_cancellable(
            batch,
            &between_predicate(column, lower, lower_inclusive, upper, upper_inclusive),
            &CancellationToken::default(),
        )
        .map(Some)
    }

    fn try_range_overlap_scan(&self, column: &str, range: &Expr) -> Result<Option<VectorBatch>> {
        let column_index = column_index(&self.columns, column)?;
        let range = range_from_literal_expr(range)?;
        let Some(index) = self
            .indexes
            .values()
            .find(|index| index.supports_range_overlap_column(column_index))
        else {
            return Ok(None);
        };
        let pointers = index.range_overlap_lookup(column_index, &range)?;
        self.rows_for_pointers(&pointers).map(Some)
    }

    fn try_bounds_overlap_scan(&self, column: &str, bounds: &Expr) -> Result<Option<VectorBatch>> {
        let column_index = column_index(&self.columns, column)?;
        let bounds = bounding_box_from_expr(bounds)?;
        let Some(index) = self
            .indexes
            .values()
            .find(|index| index.supports_bounds_overlap_column(column_index))
        else {
            return Ok(None);
        };
        let pointers = index.bounds_overlap_lookup(column_index, &bounds)?;
        self.rows_for_pointers(&pointers).map(Some)
    }

    fn try_index_range_scan(
        &self,
        column: &str,
        lower: Option<&Expr>,
        lower_inclusive: bool,
        upper: Option<&Expr>,
        upper_inclusive: bool,
    ) -> Result<Option<VectorBatch>> {
        let column_index = column_index(&self.columns, column)?;
        let lower = maybe_bound_key_from_expr(lower)?;
        let upper = maybe_bound_key_from_expr(upper)?;
        if lower.is_none() && upper.is_none() {
            return Ok(None);
        }
        let Some(index) = self
            .indexes
            .values()
            .find(|index| index.supports_single_column(column_index))
        else {
            return Ok(None);
        };
        let pointers = index.range_lookup(
            column_index,
            bound_ref(lower.as_ref(), lower_inclusive),
            bound_ref(upper.as_ref(), upper_inclusive),
        )?;
        self.rows_for_pointers(&pointers).map(Some)
    }

    fn rows_for_pointers(&self, pointers: &[IndexPointer]) -> Result<VectorBatch> {
        let mut rows = Vec::with_capacity(pointers.len());
        for pointer in pointers {
            if pointer.page_id() != MEMORY_INDEX_PAGE_ID {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "memory index pointer references an unexpected page",
                ));
            }
            let row = self.rows.get(pointer.slot_id() as usize).ok_or_else(|| {
                RnovError::new(ErrorKind::InvalidInput, "memory index pointer is stale")
            })?;
            rows.push(row.clone());
        }
        VectorBatch::new(self.columns.clone(), rows)
    }

    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    fn has_encrypted_columns(&self) -> bool {
        self.columns.iter().any(ColumnSchema::is_encrypted)
    }

    pub fn statistics(&self) -> TableStatistics {
        TableStatistics::new(self.row_count() as f64, self.estimated_row_width_bytes())
    }

    pub fn text_lexeme_statistics(
        &self,
        column: &str,
        term: &str,
    ) -> Result<Option<TextLexemeStatistics>> {
        let column_index = column_index(&self.columns, column)?;
        match self.columns[column_index].data_type() {
            SqlType::Text | SqlType::TextVector => {}
            other => {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "text lexeme statistics require TEXT or TEXTVECTOR column, got {other:?}"
                    ),
                ));
            }
        }

        let mut document_count = 0.0;
        let mut occurrence_count = 0.0;
        for row in &self.rows {
            let Some(vector) = text_vector_from_value(&row.values()[column_index])? else {
                continue;
            };
            let Some(lexeme) = vector.find(term) else {
                continue;
            };
            document_count += 1.0;
            occurrence_count += lexeme.positions().len() as f64;
        }

        if document_count == 0.0 {
            Ok(None)
        } else {
            Ok(Some(TextLexemeStatistics::new(
                document_count,
                occurrence_count,
            )))
        }
    }

    pub fn scan_parallel(&self, config: ParallelQueryConfig) -> Result<VectorBatch> {
        self.scan_parallel_cancellable(config, &CancellationToken::default())
    }

    pub fn scan_parallel_cancellable(
        &self,
        config: ParallelQueryConfig,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        config.validate()?;
        cancellation.check()?;
        // A plain memory scan only clones rows; later operators decide whether real
        // per-row work is worth parallelizing.
        let batch = self.scan();
        cancellation.check()?;
        Ok(batch)
    }

    fn add_column(&mut self, column: ColumnSchema) -> Result<()> {
        let mut columns = self.columns.clone();
        columns.push(column);
        let mut rows = self.rows.clone();
        for row in &mut rows {
            row.push_value(SqlValue::Null);
        }
        let _ = VectorBatch::new(columns.clone(), rows.clone())?;
        self.columns = columns;
        self.rows = rows;
        Ok(())
    }

    fn set_column_encrypted(&mut self, column: &str, encrypted: bool) -> Result<()> {
        let mut columns = self.columns.clone();
        let column_index = column_index(&columns, column)?;
        columns[column_index] = columns[column_index].clone().with_encrypted(encrypted);
        let _ = VectorBatch::new(columns.clone(), self.rows.clone())?;
        self.columns = columns;
        Ok(())
    }

    fn create_index(
        &mut self,
        name: &str,
        keys: &[IndexKeyDef],
        method: IndexMethod,
        unique: bool,
    ) -> Result<()> {
        let cancellation = CancellationToken::default();
        self.create_index_with_config(
            name,
            keys,
            method,
            unique,
            ParallelQueryConfig::default(),
            &cancellation,
        )
    }

    fn create_index_parallel(
        &mut self,
        name: &str,
        keys: &[IndexKeyDef],
        method: IndexMethod,
        unique: bool,
        config: ParallelQueryConfig,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        self.create_index_with_config(name, keys, method, unique, config, cancellation)
    }

    fn create_index_with_config(
        &mut self,
        name: &str,
        keys: &[IndexKeyDef],
        method: IndexMethod,
        unique: bool,
        config: ParallelQueryConfig,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        config.validate()?;
        cancellation.check()?;
        if self.indexes.contains_key(name) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("index already exists: {name}"),
            ));
        }
        let mut index = MemoryTableIndex::new(name, &self.columns, keys, method, unique)?;
        if self.rows.is_empty()
            || config.worker_threads() == 1
            || self.rows.len() < config.min_parallel_rows()
        {
            for (slot, row) in self.rows.iter().enumerate() {
                cancellation.check()?;
                index.insert_row(&self.columns, row, pointer_for_slot(slot)?)?;
            }
        } else {
            index = self.build_index_parallel(index, config, cancellation)?;
        }
        cancellation.check()?;
        self.indexes.insert(name.to_string(), index);
        Ok(())
    }

    fn build_index_parallel(
        &self,
        mut index: MemoryTableIndex,
        config: ParallelQueryConfig,
        cancellation: &CancellationToken,
    ) -> Result<MemoryTableIndex> {
        let worker_count = config.worker_threads().min(self.rows.len());
        if worker_count == 0 {
            return Ok(index);
        }
        let chunk_size = self.rows.len().div_ceil(worker_count);

        thread::scope(|scope| {
            let mut handles = Vec::with_capacity(worker_count);
            for (chunk_index, chunk) in self.rows.chunks(chunk_size).enumerate() {
                let columns = &self.columns;
                let mut local_index = index.empty_clone();
                let cancellation = cancellation.clone();
                let start_slot = chunk_index * chunk_size;
                handles.push(scope.spawn(move || {
                    for (offset, row) in chunk.iter().enumerate() {
                        cancellation.check()?;
                        let pointer = pointer_for_slot(start_slot + offset)?;
                        local_index.insert_row(columns, row, pointer)?;
                    }
                    cancellation.check()?;
                    Ok::<MemoryTableIndex, RnovError>(local_index)
                }));
            }

            for handle in handles {
                let local_index = handle.join().map_err(|_| {
                    RnovError::new(ErrorKind::Internal, "parallel index build worker panicked")
                })??;
                index.merge_from(local_index)?;
            }
            Ok::<(), RnovError>(())
        })?;

        Ok(index)
    }

    fn drop_index(&mut self, name: &str) -> bool {
        self.indexes.remove(name).is_some()
    }

    fn rebuild_indexes(&mut self) -> Result<()> {
        let mut indexes = self.indexes.clone();
        for index in indexes.values_mut() {
            index.clear();
            for (slot, row) in self.rows.iter().enumerate() {
                index.insert_row(&self.columns, row, pointer_for_slot(slot)?)?;
            }
        }
        self.indexes = indexes;
        Ok(())
    }

    fn estimated_row_width_bytes(&self) -> f64 {
        if self.rows.is_empty() {
            return schema_row_width_bytes(&self.columns);
        }

        let total_bytes = self
            .rows
            .iter()
            .map(|row| {
                row.values()
                    .iter()
                    .map(|value| value.encode().len())
                    .sum::<usize>()
            })
            .sum::<usize>();
        (total_bytes as f64 / self.rows.len() as f64).max(1.0)
    }
}

#[derive(Clone, Debug)]
enum MemoryTableIndex {
    BTree {
        column_index: usize,
        index: MemoryBTreeIndex,
    },
    ExpressionBTree {
        expr: Expr,
        index: MemoryBTreeIndex,
    },
    Hash {
        column_index: usize,
        index: MemoryHashIndex,
    },
    ExpressionHash {
        expr: Expr,
        index: MemoryHashIndex,
    },
    GinText {
        column_index: usize,
        index: InvertedTextIndex,
    },
    GinValue {
        column_index: usize,
        index: InvertedValueIndex,
    },
    GistRange {
        column_index: usize,
        index: MemoryRangeIndex,
    },
    GistBounds {
        column_index: usize,
        index: MemoryBoundsIndex,
    },
    BrinSummary {
        column_index: usize,
        index: BlockSummaryIndex,
        entries: Vec<(IndexKey, IndexPointer)>,
    },
    Composite {
        column_indexes: Vec<usize>,
        index: MemoryCompositeIndex,
    },
}

impl MemoryTableIndex {
    fn new(
        name: &str,
        table_columns: &[ColumnSchema],
        keys: &[IndexKeyDef],
        method: IndexMethod,
        unique: bool,
    ) -> Result<Self> {
        if keys.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "index must have at least one column",
            ));
        }
        if let [IndexKeyDef::Expression(expr)] = keys {
            return match method {
                IndexMethod::BTree => {
                    let _ = projection_type(table_columns, expr)?;
                    let index = if unique {
                        MemoryBTreeIndex::unique(name)
                    } else {
                        MemoryBTreeIndex::non_unique(name)
                    };
                    Ok(Self::ExpressionBTree {
                        expr: expr.clone(),
                        index,
                    })
                }
                IndexMethod::Hash => {
                    let _ = projection_type(table_columns, expr)?;
                    let index = if unique {
                        MemoryHashIndex::unique(name)
                    } else {
                        MemoryHashIndex::non_unique(name)
                    };
                    Ok(Self::ExpressionHash {
                        expr: expr.clone(),
                        index,
                    })
                }
                _ => Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "expression indexes support only btree and hash methods",
                )),
            };
        }
        if keys
            .iter()
            .any(|key| matches!(key, IndexKeyDef::Expression(_)))
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "expression indexes support exactly one expression",
            ));
        }
        let column_indexes = keys
            .iter()
            .map(|key| match key {
                IndexKeyDef::Column(column) => column_index(table_columns, column.as_str()),
                IndexKeyDef::Expression(_) => unreachable!("handled above"),
            })
            .collect::<Result<Vec<_>>>()?;
        if column_indexes.len() == 1 {
            return match method {
                IndexMethod::BTree => {
                    let index = if unique {
                        MemoryBTreeIndex::unique(name)
                    } else {
                        MemoryBTreeIndex::non_unique(name)
                    };
                    Ok(Self::BTree {
                        column_index: column_indexes[0],
                        index,
                    })
                }
                IndexMethod::Hash => {
                    let index = if unique {
                        MemoryHashIndex::unique(name)
                    } else {
                        MemoryHashIndex::non_unique(name)
                    };
                    Ok(Self::Hash {
                        column_index: column_indexes[0],
                        index,
                    })
                }
                IndexMethod::Gin => {
                    if unique {
                        return Err(RnovError::new(
                            ErrorKind::InvalidInput,
                            "gin indexes do not support uniqueness",
                        ));
                    }
                    let column_index = column_indexes[0];
                    match table_columns[column_index].data_type() {
                        SqlType::Text | SqlType::TextVector => Ok(Self::GinText {
                            column_index,
                            index: InvertedTextIndex::new(name),
                        }),
                        SqlType::Array(_) | SqlType::HStore => Ok(Self::GinValue {
                            column_index,
                            index: InvertedValueIndex::new(name),
                        }),
                        other => Err(RnovError::new(
                            ErrorKind::InvalidInput,
                            format!(
                                "gin index requires TEXT, TEXTVECTOR, ARRAY, or HSTORE column, got {other:?}"
                            ),
                        )),
                    }
                }
                IndexMethod::Gist => {
                    if unique {
                        return Err(RnovError::new(
                            ErrorKind::InvalidInput,
                            "gist indexes do not support uniqueness",
                        ));
                    }
                    let column_index = column_indexes[0];
                    match table_columns[column_index].data_type() {
                        SqlType::Range(_) => Ok(Self::GistRange {
                            column_index,
                            index: MemoryRangeIndex::new(name),
                        }),
                        SqlType::Array(element) if matches!(element.as_ref(), SqlType::Range(inner) if matches!(inner.as_ref(), SqlType::Int64)) => {
                            Ok(Self::GistBounds {
                                column_index,
                                index: MemoryBoundsIndex::new(name),
                            })
                        }
                        other => Err(RnovError::new(
                            ErrorKind::InvalidInput,
                            format!(
                                "gist index requires RANGE or RANGE<INT64>[] column, got {other:?}"
                            ),
                        )),
                    }
                }
                IndexMethod::Brin => {
                    if unique {
                        return Err(RnovError::new(
                            ErrorKind::InvalidInput,
                            "brin indexes do not support uniqueness",
                        ));
                    }
                    let column_index = column_indexes[0];
                    match table_columns[column_index].data_type() {
                        SqlType::Int64 | SqlType::Text => Ok(Self::BrinSummary {
                            column_index,
                            index: BlockSummaryIndex::new(name),
                            entries: Vec::new(),
                        }),
                        other => Err(RnovError::new(
                            ErrorKind::InvalidInput,
                            format!(
                                "brin summary index requires INT64 or TEXT column, got {other:?}"
                            ),
                        )),
                    }
                }
            };
        }
        match method {
            IndexMethod::Hash => {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "hash indexes support exactly one column",
                ));
            }
            IndexMethod::Gin => {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "gin indexes support exactly one column",
                ));
            }
            IndexMethod::Gist => {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "gist indexes support exactly one column",
                ));
            }
            IndexMethod::Brin => {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "brin indexes support exactly one column",
                ));
            }
            IndexMethod::BTree => {}
        }

        let index = if unique {
            MemoryCompositeIndex::unique(name)
        } else {
            MemoryCompositeIndex::non_unique(name)
        };
        Ok(Self::Composite {
            column_indexes,
            index,
        })
    }

    fn clear(&mut self) {
        match self {
            Self::BTree { index, .. } => {
                let name = index.name().to_string();
                let unique = index.is_unique();
                *index = if unique {
                    MemoryBTreeIndex::unique(name)
                } else {
                    MemoryBTreeIndex::non_unique(name)
                };
            }
            Self::ExpressionBTree { index, .. } => {
                let name = index.name().to_string();
                let unique = index.is_unique();
                *index = if unique {
                    MemoryBTreeIndex::unique(name)
                } else {
                    MemoryBTreeIndex::non_unique(name)
                };
            }
            Self::Hash { index, .. } => {
                let name = index.name().to_string();
                let unique = index.is_unique();
                *index = if unique {
                    MemoryHashIndex::unique(name)
                } else {
                    MemoryHashIndex::non_unique(name)
                };
            }
            Self::ExpressionHash { index, .. } => {
                let name = index.name().to_string();
                let unique = index.is_unique();
                *index = if unique {
                    MemoryHashIndex::unique(name)
                } else {
                    MemoryHashIndex::non_unique(name)
                };
            }
            Self::GinText { index, .. } => {
                let name = index.name().to_string();
                *index = InvertedTextIndex::new(name);
            }
            Self::GinValue { index, .. } => {
                let name = index.name().to_string();
                *index = InvertedValueIndex::new(name);
            }
            Self::GistRange { index, .. } => {
                let name = index.name().to_string();
                *index = MemoryRangeIndex::new(name);
            }
            Self::GistBounds { index, .. } => {
                let name = index.name().to_string();
                *index = MemoryBoundsIndex::new(name);
            }
            Self::BrinSummary { index, entries, .. } => {
                let name = index.name().to_string();
                *index = BlockSummaryIndex::new(name);
                entries.clear();
            }
            Self::Composite { index, .. } => {
                let name = index.name().to_string();
                let unique = index.is_unique();
                *index = if unique {
                    MemoryCompositeIndex::unique(name)
                } else {
                    MemoryCompositeIndex::non_unique(name)
                };
            }
        }
    }

    fn empty_clone(&self) -> Self {
        let mut index = self.clone();
        index.clear();
        index
    }

    fn merge_from(&mut self, other: Self) -> Result<()> {
        match (self, other) {
            (
                Self::BTree {
                    column_index,
                    index,
                },
                Self::BTree {
                    column_index: other_column_index,
                    index: other_index,
                },
            ) if *column_index == other_column_index => index.merge_from(other_index),
            (
                Self::ExpressionBTree { expr, index },
                Self::ExpressionBTree {
                    expr: other_expr,
                    index: other_index,
                },
            ) if *expr == other_expr => index.merge_from(other_index),
            (
                Self::Hash {
                    column_index,
                    index,
                },
                Self::Hash {
                    column_index: other_column_index,
                    index: other_index,
                },
            ) if *column_index == other_column_index => index.merge_from(other_index),
            (
                Self::ExpressionHash { expr, index },
                Self::ExpressionHash {
                    expr: other_expr,
                    index: other_index,
                },
            ) if *expr == other_expr => index.merge_from(other_index),
            (
                Self::GinText {
                    column_index,
                    index,
                },
                Self::GinText {
                    column_index: other_column_index,
                    index: other_index,
                },
            ) if *column_index == other_column_index => index.merge_from(other_index),
            (
                Self::GinValue {
                    column_index,
                    index,
                },
                Self::GinValue {
                    column_index: other_column_index,
                    index: other_index,
                },
            ) if *column_index == other_column_index => index.merge_from(other_index),
            (
                Self::GistRange {
                    column_index,
                    index,
                },
                Self::GistRange {
                    column_index: other_column_index,
                    index: other_index,
                },
            ) if *column_index == other_column_index => index.merge_from(other_index),
            (
                Self::GistBounds {
                    column_index,
                    index,
                },
                Self::GistBounds {
                    column_index: other_column_index,
                    index: other_index,
                },
            ) if *column_index == other_column_index => index.merge_from(other_index),
            (
                Self::BrinSummary {
                    column_index,
                    index,
                    entries,
                },
                Self::BrinSummary {
                    column_index: other_column_index,
                    entries: other_entries,
                    ..
                },
            ) if *column_index == other_column_index => {
                entries.extend(other_entries);
                rebuild_block_summary_index(index, entries)
            }
            (
                Self::Composite {
                    column_indexes,
                    index,
                },
                Self::Composite {
                    column_indexes: other_column_indexes,
                    index: other_index,
                },
            ) if *column_indexes == other_column_indexes => index.merge_from(other_index),
            _ => Err(RnovError::new(
                ErrorKind::Internal,
                "cannot merge incompatible memory table indexes",
            )),
        }
    }

    fn insert_row(
        &mut self,
        columns: &[ColumnSchema],
        row: &Row,
        pointer: IndexPointer,
    ) -> Result<()> {
        match self {
            Self::BTree {
                column_index,
                index,
                ..
            } => {
                let Some(key) = index_key_from_value(&row.values()[*column_index])? else {
                    return Ok(());
                };
                index.insert(key, pointer)
            }
            Self::ExpressionBTree { expr, index } => {
                let Some(key) = index_key_from_value(&eval_expr(columns, row, expr)?)? else {
                    return Ok(());
                };
                index.insert(key, pointer)
            }
            Self::Hash {
                column_index,
                index,
                ..
            } => {
                let Some(key) = index_key_from_value(&row.values()[*column_index])? else {
                    return Ok(());
                };
                index.insert(key, pointer)
            }
            Self::ExpressionHash { expr, index } => {
                let Some(key) = index_key_from_value(&eval_expr(columns, row, expr)?)? else {
                    return Ok(());
                };
                index.insert(key, pointer)
            }
            Self::GinText {
                column_index,
                index,
                ..
            } => {
                let Some(vector) = text_vector_from_value(&row.values()[*column_index])? else {
                    return Ok(());
                };
                index.insert_document(pointer, &vector)
            }
            Self::GinValue {
                column_index,
                index,
                ..
            } => match &row.values()[*column_index] {
                SqlValue::Null => Ok(()),
                SqlValue::Array(array) if array.is_empty() => Ok(()),
                SqlValue::Array(array) => index.insert_array(pointer, array),
                SqlValue::HStore(hstore) if hstore.is_empty() => Ok(()),
                SqlValue::HStore(hstore) => index.insert_hstore(pointer, hstore),
                other => Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "gin value index cannot index value type {:?}",
                        other.data_type()
                    ),
                )),
            },
            Self::GistRange {
                column_index,
                index,
                ..
            } => {
                let SqlValue::Range(range) = &row.values()[*column_index] else {
                    if row.values()[*column_index].is_null() {
                        return Ok(());
                    }
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        "gist range index cannot index a non-range value",
                    ));
                };
                index.insert_range(pointer, range)
            }
            Self::GistBounds {
                column_index,
                index,
                ..
            } => {
                let Some(bounds) = bounding_box_from_value(&row.values()[*column_index])? else {
                    return Ok(());
                };
                index.insert_box(pointer, &bounds)
            }
            Self::BrinSummary {
                column_index,
                index,
                entries,
                ..
            } => {
                let Some(key) = index_key_from_value(&row.values()[*column_index])? else {
                    return Ok(());
                };
                entries.push((key, pointer));
                rebuild_block_summary_index(index, entries)
            }
            Self::Composite {
                column_indexes,
                index,
                ..
            } => {
                let Some(key) = composite_key_from_row(row, column_indexes)? else {
                    return Ok(());
                };
                index.insert(key, pointer)
            }
        }
    }

    fn supports_leading_column(&self, column: usize) -> bool {
        match self {
            Self::BTree { column_index, .. } => *column_index == column,
            Self::ExpressionBTree { .. } => false,
            Self::Hash { column_index, .. } => *column_index == column,
            Self::ExpressionHash { .. } => false,
            Self::GinText { .. } => false,
            Self::GinValue { .. } => false,
            Self::GistRange { .. } => false,
            Self::GistBounds { .. } => false,
            Self::BrinSummary { .. } => false,
            Self::Composite { column_indexes, .. } => column_indexes.first() == Some(&column),
        }
    }

    fn supports_single_column(&self, column: usize) -> bool {
        matches!(self, Self::BTree { column_index, .. } if *column_index == column)
    }

    fn supports_skip_column(&self, column: usize) -> bool {
        matches!(self, Self::Composite { column_indexes, .. } if column_indexes.contains(&column))
    }

    fn supports_point_lookup_column(&self, column: usize) -> bool {
        match self {
            Self::BTree { column_index, .. } | Self::Hash { column_index, .. } => {
                *column_index == column
            }
            Self::Composite { column_indexes, .. } => column_indexes.first() == Some(&column),
            _ => false,
        }
    }

    fn supports_text_column(&self, column: usize) -> bool {
        matches!(self, Self::GinText { column_index, .. } if *column_index == column)
    }

    fn supports_inverted_value_column(&self, column: usize) -> bool {
        matches!(self, Self::GinValue { column_index, .. } if *column_index == column)
    }

    fn supports_range_overlap_column(&self, column: usize) -> bool {
        matches!(self, Self::GistRange { column_index, .. } if *column_index == column)
    }

    fn supports_bounds_overlap_column(&self, column: usize) -> bool {
        matches!(self, Self::GistBounds { column_index, .. } if *column_index == column)
    }

    fn supports_block_summary_column(&self, column: usize) -> bool {
        matches!(self, Self::BrinSummary { column_index, .. } if *column_index == column)
    }

    fn point_lookup(&self, column: usize, key: &IndexKey) -> Result<Vec<IndexPointer>> {
        match self {
            Self::BTree {
                column_index,
                index,
                ..
            } if *column_index == column => Ok(index.point_lookup(key)),
            Self::Hash {
                column_index,
                index,
                ..
            } if *column_index == column => Ok(index.point_lookup(key)),
            Self::Composite {
                column_indexes,
                index,
            } if column_indexes.first() == Some(&column) => {
                let mut parts = Vec::with_capacity(column_indexes.len());
                parts.push(Some(key.clone()));
                parts.extend((1..column_indexes.len()).map(|_| None));
                index.skip_scan(&CompositeKeyPattern::new(parts)?)
            }
            _ => Ok(Vec::new()),
        }
    }

    fn expression_lookup(&self, expr: &Expr, key: &IndexKey) -> Result<Vec<IndexPointer>> {
        match self {
            Self::ExpressionBTree {
                expr: indexed,
                index,
            } if indexed == expr => Ok(index.point_lookup(key)),
            Self::ExpressionHash {
                expr: indexed,
                index,
            } if indexed == expr => Ok(index.point_lookup(key)),
            _ => Ok(Vec::new()),
        }
    }

    fn text_lookup(&self, column: usize, required_terms: &[String]) -> Result<Vec<IndexPointer>> {
        match self {
            Self::GinText {
                column_index,
                index,
                ..
            } if *column_index == column => {
                Ok(index.lookup_all(required_terms.iter().map(String::as_str)))
            }
            _ => Ok(Vec::new()),
        }
    }

    fn inverted_value_lookup(
        &self,
        column: usize,
        query: &InvertedValueQuery,
    ) -> Result<Vec<IndexPointer>> {
        match self {
            Self::GinValue {
                column_index,
                index,
                ..
            } if *column_index == column => match query {
                InvertedValueQuery::ArrayContains { values } => {
                    if values.is_empty() {
                        return Ok(Vec::new());
                    }
                    let mut lists = Vec::with_capacity(values.len());
                    for value in values {
                        lists.push(index.lookup_array_value(&literal_value(value)?));
                    }
                    Ok(intersect_pointer_lists(lists))
                }
                InvertedValueQuery::HStoreKey { key } => Ok(index.lookup_hstore_key(key)),
                InvertedValueQuery::HStoreContains { entries } => {
                    if entries.is_empty() {
                        return Ok(Vec::new());
                    }
                    let lists = entries
                        .iter()
                        .map(|(key, value)| {
                            index.lookup_hstore_pair(
                                key,
                                &value.as_ref().map_or(HStoreValue::Null, |value| {
                                    HStoreValue::Text(value.clone())
                                }),
                            )
                        })
                        .collect();
                    Ok(intersect_pointer_lists(lists))
                }
            },
            _ => Ok(Vec::new()),
        }
    }

    fn range_overlap_lookup(&self, column: usize, range: &SqlRange) -> Result<Vec<IndexPointer>> {
        match self {
            Self::GistRange {
                column_index,
                index,
                ..
            } if *column_index == column => index.overlap_scan(range),
            _ => Ok(Vec::new()),
        }
    }

    fn bounds_overlap_lookup(
        &self,
        column: usize,
        bounds: &BoundingBox,
    ) -> Result<Vec<IndexPointer>> {
        match self {
            Self::GistBounds {
                column_index,
                index,
                ..
            } if *column_index == column => index.intersection_scan(bounds),
            _ => Ok(Vec::new()),
        }
    }

    fn block_summary_lookup(
        &self,
        column: usize,
        lower: &IndexKey,
        upper: &IndexKey,
    ) -> Result<Vec<IndexPointer>> {
        match self {
            Self::BrinSummary {
                column_index,
                index,
                entries,
                ..
            } if *column_index == column => {
                let ranges = index.range_candidates(lower, upper)?;
                block_ranges_to_pointers(&ranges, entries.len())
            }
            _ => Ok(Vec::new()),
        }
    }

    fn skip_lookup(&self, column: usize, key: &IndexKey) -> Result<Vec<IndexPointer>> {
        match self {
            Self::Composite {
                column_indexes,
                index,
            } => {
                let Some(part_index) = column_indexes.iter().position(|indexed| *indexed == column)
                else {
                    return Ok(Vec::new());
                };
                let mut parts = vec![None; column_indexes.len()];
                parts[part_index] = Some(key.clone());
                index.skip_scan(&CompositeKeyPattern::new(parts)?)
            }
            _ => Ok(Vec::new()),
        }
    }

    fn range_lookup(
        &self,
        column: usize,
        lower: Bound<&IndexKey>,
        upper: Bound<&IndexKey>,
    ) -> Result<Vec<IndexPointer>> {
        match self {
            Self::BTree {
                column_index,
                index,
                ..
            } if *column_index == column => Ok(index.range_scan_bounds(lower, upper)),
            _ => Ok(Vec::new()),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    canceled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.canceled.store(true, AtomicOrdering::Release);
    }

    pub fn is_canceled(&self) -> bool {
        self.canceled.load(AtomicOrdering::Acquire)
    }

    pub fn check(&self) -> Result<()> {
        if self.is_canceled() {
            return Err(RnovError::new(
                ErrorKind::Canceled,
                "query execution canceled",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParallelQueryConfig {
    worker_threads: usize,
    min_parallel_rows: usize,
}

impl ParallelQueryConfig {
    pub fn new(worker_threads: usize, min_parallel_rows: usize) -> Self {
        Self {
            worker_threads,
            min_parallel_rows,
        }
    }

    pub fn worker_threads(self) -> usize {
        self.worker_threads
    }

    pub fn min_parallel_rows(self) -> usize {
        self.min_parallel_rows
    }

    fn validate(self) -> Result<()> {
        if self.worker_threads == 0 {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "parallel query worker count must be greater than zero",
            ));
        }
        Ok(())
    }
}

impl Default for ParallelQueryConfig {
    fn default() -> Self {
        Self {
            worker_threads: 1,
            min_parallel_rows: 1024,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MemoryExecutor {
    tables: Arc<RwLock<BTreeMap<String, MemoryTable>>>,
    column_crypto: ColumnCryptoState,
}

impl Default for MemoryExecutor {
    fn default() -> Self {
        Self {
            tables: Arc::new(RwLock::new(BTreeMap::new())),
            column_crypto: ColumnCryptoState::default(),
        }
    }
}

struct SidewaysIndexLookupInput<'a> {
    outer: &'a PhysicalPlan,
    inner_table: &'a str,
    inner_index: &'a str,
    inner_column: &'a str,
    outer_column: &'a str,
}

struct CreateIndexInput<'a> {
    name: &'a str,
    table: &'a str,
    keys: &'a [IndexKeyDef],
    method: IndexMethod,
    unique: bool,
    if_not_exists: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionResult {
    Batch(VectorBatch),
    RowsAffected(u64),
    SchemaChanged,
}

impl MemoryExecutor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_active_role(&mut self, role_id: RoleId) {
        self.column_crypto.set_active_role(role_id);
    }

    pub fn configure_column_encryption(
        &mut self,
        relation_id: RelationId,
        column_name: impl Into<String>,
        key: ColumnKeyMaterial,
        decrypt_roles: impl IntoIterator<Item = RoleId>,
    ) -> Result<()> {
        self.column_crypto
            .configure_column(relation_id, column_name, key, decrypt_roles)
    }

    pub fn grant_column_decrypt(
        &mut self,
        relation_id: RelationId,
        column_name: impl Into<String>,
        role_id: RoleId,
    ) -> Result<()> {
        self.column_crypto
            .grant_decrypt(relation_id, column_name, role_id)
    }

    fn read_tables(&self) -> Result<RwLockReadGuard<'_, BTreeMap<String, MemoryTable>>> {
        self.tables
            .read()
            .map_err(|_| RnovError::new(ErrorKind::Internal, "memory executor table lock poisoned"))
    }

    fn write_tables(&self) -> Result<RwLockWriteGuard<'_, BTreeMap<String, MemoryTable>>> {
        self.tables
            .write()
            .map_err(|_| RnovError::new(ErrorKind::Internal, "memory executor table lock poisoned"))
    }

    pub fn snapshot(&self) -> Result<Self> {
        Ok(Self {
            tables: Arc::new(RwLock::new(self.read_tables()?.clone())),
            column_crypto: self.column_crypto.clone(),
        })
    }

    fn with_table<T>(&self, name: &str, f: impl FnOnce(&MemoryTable) -> Result<T>) -> Result<T> {
        let tables = self.read_tables()?;
        let table = tables.get(name).ok_or_else(|| {
            RnovError::new(ErrorKind::NotFound, format!("table not found: {name}"))
        })?;
        f(table)
    }

    fn scan_table(&self, relation_id: RelationId, name: &str) -> Result<VectorBatch> {
        let batch = self.with_table(name, |table| Ok(table.scan()))?;
        self.column_crypto.decrypt_batch(relation_id, batch)
    }

    pub fn scan_catalog_table(&self, table: &CatalogTable) -> Result<VectorBatch> {
        let table_key = {
            let tables = self.read_tables()?;
            executor_table_key_for_catalog_name(&tables, table.schema_name(), table.name())?
        };
        self.scan_table(table.relation_id(), &table_key)
    }

    fn decrypt_physical_scan(
        &self,
        relation_id: RelationId,
        batch: VectorBatch,
    ) -> Result<VectorBatch> {
        self.column_crypto.decrypt_batch(relation_id, batch)
    }

    pub fn register_table(&mut self, name: impl Into<String>, table: MemoryTable) -> Result<()> {
        let name = name.into();
        if name.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "registered table name cannot be empty",
            ));
        }
        self.write_tables()?.insert(name, table);
        Ok(())
    }

    pub fn snapshot_tables(&self) -> Result<Vec<DurableTableRows>> {
        let tables = self.read_tables()?;
        tables
            .iter()
            .map(|(name, table)| table.snapshot_rows(name))
            .collect()
    }

    pub fn restore_tables(&mut self, catalog: &Catalog, tables: &[DurableTableRows]) -> Result<()> {
        let mut restored = BTreeMap::new();
        for table in tables {
            restore_durable_table(catalog, table, &mut restored)?;
        }
        restore_empty_catalog_tables(catalog, &mut restored)?;
        *self.write_tables()? = restored;
        self.rebuild_indexes_from_catalog(catalog)
    }

    pub fn rebuild_indexes_from_catalog(&mut self, catalog: &Catalog) -> Result<()> {
        for index in catalog.indexes() {
            self.rebuild_catalog_index(index)?;
        }
        Ok(())
    }

    fn rebuild_catalog_index(&mut self, index: &CatalogIndex) -> Result<()> {
        let table_key = self.catalog_index_table_key(index)?;
        let keys = catalog_index_key_defs(index.keys())?;
        let mut tables = self.write_tables()?;
        let table = tables.get_mut(&table_key).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("table not found for index: {table_key}"),
            )
        })?;
        table.drop_index(index.name());
        table.create_index(index.name(), &keys, index.method(), index.unique())
    }

    fn catalog_index_table_key(&self, index: &CatalogIndex) -> Result<String> {
        let tables = self.read_tables()?;
        executor_table_key_for_catalog_name(&tables, index.schema_name(), index.table_name())
    }

    pub fn table_statistics(&self, name: &str) -> Option<TableStatistics> {
        self.read_tables()
            .ok()
            .and_then(|tables| tables.get(name).map(MemoryTable::statistics))
    }

    pub fn text_lexeme_statistics(
        &self,
        table: &str,
        column: &str,
        term: &str,
    ) -> Result<Option<TextLexemeStatistics>> {
        let tables = self.read_tables()?;
        let Some(table) = tables.get(table) else {
            return Ok(None);
        };
        table.text_lexeme_statistics(column, term)
    }

    pub fn execute(&self, plan: &LogicalPlan) -> Result<VectorBatch> {
        self.execute_cancellable(plan, &CancellationToken::default())
    }

    pub fn execute_cancellable(
        &self,
        plan: &LogicalPlan,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        cancellation.check()?;
        match plan {
            LogicalPlan::Scan { relation_id, table } => self.scan_table(*relation_id, table),
            LogicalPlan::RecursiveScan { name, .. } => {
                let tables = self.read_tables()?;
                tables.get(name).map(MemoryTable::scan).ok_or_else(|| {
                    RnovError::new(
                        ErrorKind::NotFound,
                        format!("recursive CTE is not active: {name}"),
                    )
                })
            }
            LogicalPlan::Filter { predicate, input } => {
                if self.expr_needs_row_subquery_resolution(predicate)? {
                    let batch = self.execute_cancellable(input, cancellation)?;
                    return self.apply_row_subquery_filter(batch, predicate, cancellation);
                }
                let predicate = self.resolve_scalar_subqueries(predicate, cancellation)?;
                if let Some(batch) =
                    self.execute_indexed_filter_scan(&predicate, input, cancellation)?
                {
                    return Ok(batch);
                }
                let batch = self.execute_cancellable(input, cancellation)?;
                apply_filter_cancellable(batch, &predicate, cancellation)
            }
            LogicalPlan::InSubqueryFilter {
                expr,
                subquery,
                negated,
                input,
            } => {
                let input = self.execute_cancellable(input, cancellation)?;
                self.apply_logical_in_subquery_filter(input, subquery, expr, *negated, cancellation)
            }
            LogicalPlan::ExistsSubqueryFilter {
                subquery,
                negated,
                input,
            } => {
                let input = self.execute_cancellable(input, cancellation)?;
                self.apply_logical_exists_subquery_filter(input, subquery, *negated, cancellation)
            }
            LogicalPlan::TextSearch {
                relation_id,
                table,
                column,
                query,
                ..
            } => {
                let batch = {
                    let tables = self.read_tables()?;
                    let table = tables.get(table).ok_or_else(|| {
                        RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                    })?;
                    if let Some(batch) = table.try_text_index_scan(column, query, cancellation)? {
                        return self.column_crypto.decrypt_batch(*relation_id, batch);
                    }
                    table.scan()
                };
                let batch = self.column_crypto.decrypt_batch(*relation_id, batch)?;
                apply_text_search_cancellable(batch, column, query, cancellation)
            }
            LogicalPlan::SidewaysLookup {
                outer,
                inner_table,
                inner_column,
                outer_column,
                ..
            } => self.execute_logical_sideways_lookup(
                outer,
                inner_table,
                inner_column,
                outer_column,
                cancellation,
            ),
            LogicalPlan::NestedLoopJoin {
                kind,
                left,
                right,
                predicate,
            } => {
                let left = self.execute_cancellable(left, cancellation)?;
                let right = self.execute_cancellable(right, cancellation)?;
                if self.expr_needs_row_subquery_resolution(predicate)? {
                    return self.apply_nested_loop_join_with_subqueries(
                        left,
                        right,
                        *kind,
                        predicate,
                        cancellation,
                    );
                }
                let predicate = self.resolve_scalar_subqueries(predicate, cancellation)?;
                apply_nested_loop_join_cancellable(left, right, *kind, &predicate, cancellation)
            }
            LogicalPlan::Project { items, input } => {
                let batch = self.execute_cancellable(input, cancellation)?;
                self.apply_projection_with_subqueries(batch, items, cancellation)
            }
            LogicalPlan::Window { items, input } => {
                let batch = self.execute_cancellable(input, cancellation)?;
                apply_window_cancellable(batch, items, cancellation)
            }
            LogicalPlan::Aggregate { items, input } => {
                let batch = self.execute_cancellable(input, cancellation)?;
                apply_aggregate_cancellable(batch, items, cancellation)
            }
            LogicalPlan::GroupedAggregate {
                group_by,
                items,
                input,
            } => {
                let batch = self.execute_cancellable(input, cancellation)?;
                apply_grouped_aggregate_cancellable(batch, group_by, items, cancellation)
            }
            LogicalPlan::GroupingSetsAggregate {
                group_by,
                grouping_sets,
                items,
                input,
            } => {
                let batch = self.execute_cancellable(input, cancellation)?;
                apply_grouping_sets_aggregate_cancellable(
                    batch,
                    group_by,
                    grouping_sets,
                    items,
                    cancellation,
                )
            }
            LogicalPlan::Distinct { input } => {
                let batch = self.execute_cancellable(input, cancellation)?;
                apply_distinct_cancellable(batch, cancellation)
            }
            LogicalPlan::Union { all, left, right } => {
                let left = self.execute_cancellable(left, cancellation)?;
                let right = self.execute_cancellable(right, cancellation)?;
                apply_union_cancellable(left, right, *all, cancellation)
            }
            LogicalPlan::Intersect { all, left, right } => {
                let left = self.execute_cancellable(left, cancellation)?;
                let right = self.execute_cancellable(right, cancellation)?;
                apply_intersect_cancellable(left, right, *all, cancellation)
            }
            LogicalPlan::Except { all, left, right } => {
                let left = self.execute_cancellable(left, cancellation)?;
                let right = self.execute_cancellable(right, cancellation)?;
                apply_except_cancellable(left, right, *all, cancellation)
            }
            LogicalPlan::RecursiveCte {
                name,
                columns,
                seed,
                recursive,
                query,
            } => self.execute_recursive_cte_cancellable(
                name,
                columns,
                seed,
                recursive,
                query,
                cancellation,
            ),
            LogicalPlan::Sort { keys, input } => {
                let batch = self.execute_cancellable(input, cancellation)?;
                self.apply_sort_with_scalar_subqueries(batch, keys, cancellation)
            }
            LogicalPlan::Limit { count, input } => {
                let batch = self.execute_cancellable(input, cancellation)?;
                apply_limit_cancellable(batch, *count, cancellation)
            }
            LogicalPlan::Offset { count, input } => {
                let batch = self.execute_cancellable(input, cancellation)?;
                apply_offset_cancellable(batch, *count, cancellation)
            }
            LogicalPlan::Parallel { input, .. } => self.execute_cancellable(input, cancellation),
            _ => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "memory executor does not support this logical plan",
            )),
        }
    }

    fn execute_recursive_cte_cancellable(
        &self,
        name: &str,
        columns: &[String],
        seed: &LogicalPlan,
        recursive: &LogicalPlan,
        query: &LogicalPlan,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        let seed = self.execute_cancellable(seed, cancellation)?;
        let mut accumulated = rename_batch_columns(seed, columns)?;
        let mut working = accumulated.clone();

        for iteration in 0..RECURSIVE_CTE_MAX_ITERATIONS {
            cancellation.check()?;
            if working.rows().is_empty() {
                break;
            }
            let executor = self.with_recursive_table(name, &working)?;
            let next = executor.execute_cancellable(recursive, cancellation)?;
            let next = rename_batch_columns(next, columns)?;
            if next.rows().is_empty() {
                break;
            }
            accumulated = append_batches(accumulated, &next, cancellation)?;
            working = next;
            if iteration + 1 == RECURSIVE_CTE_MAX_ITERATIONS {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "recursive CTE {name} exceeded {RECURSIVE_CTE_MAX_ITERATIONS} iterations"
                    ),
                ));
            }
        }

        let executor = self.with_recursive_table(name, &accumulated)?;
        executor.execute_cancellable(query, cancellation)
    }

    fn apply_logical_exists_subquery_filter(
        &self,
        input: VectorBatch,
        subquery: &LogicalPlan,
        negated: bool,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        if logical_plan_has_qualified_identifier(subquery) {
            return self.apply_correlated_logical_exists_filter(
                input,
                subquery,
                negated,
                cancellation,
            );
        }
        let subquery = self.execute_cancellable(subquery, cancellation)?;
        apply_exists_subquery_filter(input, &subquery, negated, cancellation)
    }

    fn apply_logical_in_subquery_filter(
        &self,
        input: VectorBatch,
        subquery: &LogicalPlan,
        expr: &Expr,
        negated: bool,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        if logical_plan_has_qualified_identifier(subquery) {
            return self.apply_correlated_logical_in_filter(
                input,
                subquery,
                expr,
                negated,
                cancellation,
            );
        }
        let subquery = self.execute_cancellable(subquery, cancellation)?;
        apply_in_subquery_filter_cancellable(input, subquery, expr, negated, cancellation)
    }

    fn apply_correlated_logical_in_filter(
        &self,
        input: VectorBatch,
        subquery: &LogicalPlan,
        expr: &Expr,
        negated: bool,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        let mut rows = Vec::new();
        for row in input.rows() {
            cancellation.check()?;
            let subquery = replace_logical_outer_refs(subquery, input.columns(), row)?;
            let subquery = self.execute_cancellable(&subquery, cancellation)?;
            let values = collect_in_subquery_values(&subquery, cancellation)?;
            if in_subquery_keeps_row(input.columns(), row, expr, &values, negated)? {
                rows.push(row.clone());
            }
        }
        VectorBatch::new(input.columns().to_vec(), rows)
    }

    fn apply_correlated_logical_exists_filter(
        &self,
        input: VectorBatch,
        subquery: &LogicalPlan,
        negated: bool,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        let mut rows = Vec::new();
        for row in input.rows() {
            cancellation.check()?;
            let subquery = replace_logical_outer_refs(subquery, input.columns(), row)?;
            let subquery = self.execute_cancellable(&subquery, cancellation)?;
            if exists_subquery_keeps_row(&subquery, negated) {
                rows.push(row.clone());
            }
        }
        VectorBatch::new(input.columns().to_vec(), rows)
    }

    fn apply_physical_exists_subquery_filter(
        &self,
        input: VectorBatch,
        subquery: &PhysicalPlan,
        negated: bool,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        if physical_plan_has_qualified_identifier(subquery) {
            return self.apply_correlated_physical_exists_filter(
                input,
                subquery,
                negated,
                None,
                cancellation,
            );
        }
        let subquery = self.execute_physical_cancellable(subquery, cancellation)?;
        apply_exists_subquery_filter(input, &subquery, negated, cancellation)
    }

    fn apply_physical_exists_subquery_filter_parallel(
        &self,
        input: VectorBatch,
        subquery: &PhysicalPlan,
        negated: bool,
        config: ParallelQueryConfig,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        if physical_plan_has_qualified_identifier(subquery) {
            return self.apply_correlated_physical_exists_filter(
                input,
                subquery,
                negated,
                Some(config),
                cancellation,
            );
        }
        let subquery =
            self.execute_physical_parallel_cancellable(subquery, config, cancellation)?;
        apply_exists_subquery_filter(input, &subquery, negated, cancellation)
    }

    fn apply_physical_in_subquery_filter(
        &self,
        input: VectorBatch,
        subquery: &PhysicalPlan,
        expr: &Expr,
        negated: bool,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        if physical_plan_has_qualified_identifier(subquery) {
            return self.apply_correlated_physical_in_filter(
                input,
                subquery,
                expr,
                negated,
                None,
                cancellation,
            );
        }
        let subquery = self.execute_physical_cancellable(subquery, cancellation)?;
        apply_in_subquery_filter_cancellable(input, subquery, expr, negated, cancellation)
    }

    fn apply_physical_in_subquery_filter_parallel(
        &self,
        input: VectorBatch,
        subquery: &PhysicalPlan,
        expr: &Expr,
        negated: bool,
        config: ParallelQueryConfig,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        if physical_plan_has_qualified_identifier(subquery) {
            return self.apply_correlated_physical_in_filter(
                input,
                subquery,
                expr,
                negated,
                Some(config),
                cancellation,
            );
        }
        let subquery =
            self.execute_physical_parallel_cancellable(subquery, config, cancellation)?;
        apply_in_subquery_filter_cancellable(input, subquery, expr, negated, cancellation)
    }

    fn apply_correlated_physical_in_filter(
        &self,
        input: VectorBatch,
        subquery: &PhysicalPlan,
        expr: &Expr,
        negated: bool,
        config: Option<ParallelQueryConfig>,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        let mut rows = Vec::new();
        for row in input.rows() {
            cancellation.check()?;
            let subquery = self.execute_physical_subquery_for_row(
                subquery,
                input.columns(),
                row,
                config,
                cancellation,
            )?;
            let values = collect_in_subquery_values(&subquery, cancellation)?;
            if in_subquery_keeps_row(input.columns(), row, expr, &values, negated)? {
                rows.push(row.clone());
            }
        }
        VectorBatch::new(input.columns().to_vec(), rows)
    }

    fn apply_correlated_physical_exists_filter(
        &self,
        input: VectorBatch,
        subquery: &PhysicalPlan,
        negated: bool,
        config: Option<ParallelQueryConfig>,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        let mut rows = Vec::new();
        for row in input.rows() {
            cancellation.check()?;
            let subquery = self.execute_physical_subquery_for_row(
                subquery,
                input.columns(),
                row,
                config,
                cancellation,
            )?;
            if exists_subquery_keeps_row(&subquery, negated) {
                rows.push(row.clone());
            }
        }
        VectorBatch::new(input.columns().to_vec(), rows)
    }

    fn execute_physical_subquery_for_row(
        &self,
        subquery: &PhysicalPlan,
        columns: &[ColumnSchema],
        row: &Row,
        config: Option<ParallelQueryConfig>,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        let subquery = replace_physical_outer_refs(subquery, columns, row)?;
        match config {
            Some(config) => {
                self.execute_physical_parallel_cancellable(&subquery, config, cancellation)
            }
            None => self.execute_physical_cancellable(&subquery, cancellation),
        }
    }

    fn with_recursive_table(&self, name: &str, batch: &VectorBatch) -> Result<Self> {
        let executor = self.snapshot()?;
        executor
            .write_tables()?
            .insert(name.to_string(), memory_table_from_batch(batch)?);
        Ok(executor)
    }

    fn resolve_projection_scalar_subqueries(
        &self,
        items: &[ProjectionItem],
        cancellation: &CancellationToken,
    ) -> Result<Vec<ProjectionItem>> {
        items
            .iter()
            .map(|item| {
                Ok(ProjectionItem {
                    name: item.name.clone(),
                    expr: self.resolve_scalar_subqueries(&item.expr, cancellation)?,
                })
            })
            .collect()
    }

    fn apply_projection_with_subqueries(
        &self,
        batch: VectorBatch,
        items: &[ProjectionItem],
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        if self.projection_needs_row_subquery_resolution(items)? {
            return self.apply_projection_with_row_subqueries(batch, items, cancellation);
        }
        let items = self.resolve_projection_scalar_subqueries(items, cancellation)?;
        apply_projection_cancellable(batch, &items, cancellation)
    }

    fn apply_projection_with_row_subqueries(
        &self,
        batch: VectorBatch,
        items: &[ProjectionItem],
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        let columns = projection_columns(batch.columns(), items)?;
        let mut rows = Vec::with_capacity(batch.rows().len());
        for row in batch.rows() {
            cancellation.check()?;
            rows.push(self.row_subquery_projection_row(&batch, items, row, cancellation)?);
        }
        cancellation.check()?;
        VectorBatch::new(columns, rows)
    }

    fn apply_row_subquery_filter(
        &self,
        batch: VectorBatch,
        predicate: &Expr,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        let mut rows = Vec::new();
        for row in batch.rows() {
            cancellation.check()?;
            let predicate =
                self.resolve_subqueries_for_row(predicate, batch.columns(), row, cancellation)?;
            if eval_predicate(batch.columns(), row, &predicate)? {
                rows.push(row.clone());
            }
        }
        cancellation.check()?;
        VectorBatch::new(batch.columns().to_vec(), rows)
    }

    fn apply_nested_loop_join_with_subqueries(
        &self,
        left: VectorBatch,
        right: VectorBatch,
        kind: JoinKind,
        predicate: &Expr,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        let columns = joined_columns_for_join(left.columns(), right.columns(), kind)?;
        let null_right = null_row(right.columns());
        let mut rows = Vec::new();
        for left_row in left.rows() {
            cancellation.check()?;
            let matched = self.push_matching_join_rows_with_subqueries(
                &columns,
                left_row,
                &right,
                predicate,
                &mut rows,
                cancellation,
            )?;
            if kind == JoinKind::Left && !matched {
                rows.push(join_rows(left_row, &null_right));
            }
        }
        VectorBatch::new(columns, rows)
    }

    fn push_matching_join_rows_with_subqueries(
        &self,
        columns: &[ColumnSchema],
        left_row: &Row,
        right: &VectorBatch,
        predicate: &Expr,
        rows: &mut Vec<Row>,
        cancellation: &CancellationToken,
    ) -> Result<bool> {
        let mut matched = false;
        for right_row in right.rows() {
            cancellation.check()?;
            let row = join_rows(left_row, right_row);
            let predicate =
                self.resolve_subqueries_for_row(predicate, columns, &row, cancellation)?;
            if eval_predicate(columns, &row, &predicate)? {
                rows.push(row);
                matched = true;
            }
        }
        Ok(matched)
    }

    fn row_subquery_projection_row(
        &self,
        batch: &VectorBatch,
        items: &[ProjectionItem],
        row: &Row,
        cancellation: &CancellationToken,
    ) -> Result<Row> {
        let values = items
            .iter()
            .map(|item| {
                let expr = self.resolve_subqueries_for_row(
                    &item.expr,
                    batch.columns(),
                    row,
                    cancellation,
                )?;
                eval_expr(batch.columns(), row, &expr)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Row::new(values))
    }

    fn projection_needs_row_subquery_resolution(&self, items: &[ProjectionItem]) -> Result<bool> {
        for item in items {
            if self.expr_needs_row_subquery_resolution(&item.expr)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn expr_needs_row_subquery_resolution(&self, expr: &Expr) -> Result<bool> {
        Ok(self.expr_has_subquery_predicate(expr)?
            || self.expr_has_correlated_scalar_subquery(expr)?)
    }

    fn expr_has_subquery_predicate(&self, expr: &Expr) -> Result<bool> {
        let mut found = false;
        rewrite_expr_tree(expr, &mut |candidate| {
            if found {
                return Ok(Some(candidate.clone()));
            }
            match candidate {
                Expr::InSubquery { .. } | Expr::ExistsSubquery { .. } => {
                    found = true;
                    Ok(Some(candidate.clone()))
                }
                _ => Ok(None),
            }
        })?;
        Ok(found)
    }

    fn expr_has_correlated_scalar_subquery(&self, expr: &Expr) -> Result<bool> {
        let mut found = false;
        rewrite_expr_tree(expr, &mut |candidate| {
            if found {
                return Ok(Some(candidate.clone()));
            }
            let Expr::ScalarSubquery { query } = candidate else {
                return Ok(None);
            };
            found = self.scalar_subquery_has_outer_refs(query)?;
            Ok(Some(candidate.clone()))
        })?;
        Ok(found)
    }

    fn scalar_subquery_has_outer_refs(&self, query: &SelectSubquery) -> Result<bool> {
        let bound = query.bound().ok_or_else(|| {
            RnovError::new(
                ErrorKind::Internal,
                "scalar subquery was not bound before execution",
            )
        })?;
        let plan = LogicalPlanner::new().plan(bound)?;
        Ok(logical_plan_has_qualified_identifier(&plan))
    }

    fn resolve_scalar_subqueries(
        &self,
        expr: &Expr,
        cancellation: &CancellationToken,
    ) -> Result<Expr> {
        rewrite_expr_tree(expr, &mut |candidate| match candidate {
            Expr::ScalarSubquery { query } => self
                .execute_scalar_subquery(query, cancellation)
                .map(Expr::RuntimeValue)
                .map(Some),
            _ => Ok(None),
        })
    }

    fn apply_sort_with_scalar_subqueries(
        &self,
        batch: VectorBatch,
        keys: &[OrderByExpr],
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        if self.order_by_needs_row_subquery_resolution(keys)? {
            return self.apply_sort_with_row_subqueries(batch, keys, cancellation);
        }
        let keys = self.resolve_order_by_scalar_subqueries(keys, cancellation)?;
        apply_sort_cancellable(batch, &keys, cancellation)
    }

    fn order_by_needs_row_subquery_resolution(&self, keys: &[OrderByExpr]) -> Result<bool> {
        for key in keys {
            if self.expr_needs_row_subquery_resolution(&key.expr)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn apply_sort_with_row_subqueries(
        &self,
        batch: VectorBatch,
        keys: &[OrderByExpr],
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        let key_values = self.resolve_order_by_row_subquery_values(&batch, keys, cancellation)?;
        apply_sort_with_key_values_cancellable(batch, keys, key_values, cancellation)
    }

    fn resolve_order_by_row_subquery_values(
        &self,
        batch: &VectorBatch,
        keys: &[OrderByExpr],
        cancellation: &CancellationToken,
    ) -> Result<Vec<Vec<SqlValue>>> {
        batch
            .rows()
            .iter()
            .map(|row| {
                self.resolve_order_by_row_subquery_values_for_row(
                    batch.columns(),
                    row,
                    keys,
                    cancellation,
                )
            })
            .collect()
    }

    fn resolve_order_by_row_subquery_values_for_row(
        &self,
        columns: &[ColumnSchema],
        row: &Row,
        keys: &[OrderByExpr],
        cancellation: &CancellationToken,
    ) -> Result<Vec<SqlValue>> {
        keys.iter()
            .map(|key| {
                let expr =
                    self.resolve_subqueries_for_row(&key.expr, columns, row, cancellation)?;
                eval_expr(columns, row, &expr)
            })
            .collect()
    }

    fn resolve_order_by_scalar_subqueries(
        &self,
        keys: &[OrderByExpr],
        cancellation: &CancellationToken,
    ) -> Result<Vec<OrderByExpr>> {
        keys.iter()
            .map(|key| {
                Ok(OrderByExpr {
                    expr: self.resolve_scalar_subqueries(&key.expr, cancellation)?,
                    direction: key.direction,
                })
            })
            .collect()
    }

    fn resolve_subqueries_for_row(
        &self,
        expr: &Expr,
        columns: &[ColumnSchema],
        row: &Row,
        cancellation: &CancellationToken,
    ) -> Result<Expr> {
        rewrite_expr_tree(expr, &mut |candidate| match candidate {
            Expr::ScalarSubquery { query } => self
                .execute_scalar_subquery_for_row(query, columns, row, cancellation)
                .map(Expr::RuntimeValue)
                .map(Some),
            Expr::InSubquery {
                expr,
                query,
                negated,
            } => self
                .resolve_in_subquery_for_row(expr, query, *negated, columns, row, cancellation)
                .map(Expr::RuntimeValue)
                .map(Some),
            Expr::ExistsSubquery { query } => self
                .resolve_exists_subquery_for_row(query, columns, row, cancellation)
                .map(Expr::RuntimeValue)
                .map(Some),
            _ => Ok(None),
        })
    }

    fn resolve_in_subquery_for_row(
        &self,
        expr: &Expr,
        query: &SelectSubquery,
        negated: bool,
        columns: &[ColumnSchema],
        row: &Row,
        cancellation: &CancellationToken,
    ) -> Result<SqlValue> {
        let expr = self.resolve_subqueries_for_row(expr, columns, row, cancellation)?;
        let batch = self.execute_select_subquery_for_row(query, columns, row, cancellation)?;
        let values = collect_in_subquery_values(&batch, cancellation)?;
        in_subquery_value(columns, row, &expr, &values, negated)
    }

    fn resolve_exists_subquery_for_row(
        &self,
        query: &SelectSubquery,
        columns: &[ColumnSchema],
        row: &Row,
        cancellation: &CancellationToken,
    ) -> Result<SqlValue> {
        let batch = self.execute_select_subquery_for_row(query, columns, row, cancellation)?;
        Ok(SqlValue::Bool(exists_subquery_keeps_row(&batch, false)))
    }

    fn execute_scalar_subquery(
        &self,
        query: &SelectSubquery,
        cancellation: &CancellationToken,
    ) -> Result<SqlValue> {
        let bound = query.bound().ok_or_else(|| {
            RnovError::new(
                ErrorKind::Internal,
                "scalar subquery was not bound before execution",
            )
        })?;
        let plan = LogicalPlanner::new().plan(bound)?;
        let batch = self.execute_cancellable(&plan, cancellation)?;
        scalar_subquery_value(&batch)
    }

    fn execute_scalar_subquery_for_row(
        &self,
        query: &SelectSubquery,
        columns: &[ColumnSchema],
        row: &Row,
        cancellation: &CancellationToken,
    ) -> Result<SqlValue> {
        let batch = self.execute_select_subquery_for_row(query, columns, row, cancellation)?;
        scalar_subquery_value(&batch)
    }

    fn execute_select_subquery_for_row(
        &self,
        query: &SelectSubquery,
        columns: &[ColumnSchema],
        row: &Row,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        let bound = query.bound().ok_or_else(|| {
            RnovError::new(
                ErrorKind::Internal,
                "subquery was not bound before execution",
            )
        })?;
        let plan = LogicalPlanner::new().plan(bound)?;
        let plan = replace_logical_outer_refs(&plan, columns, row)?;
        self.execute_cancellable(&plan, cancellation)
    }

    pub fn execute_physical(&self, plan: &PhysicalPlan) -> Result<VectorBatch> {
        self.execute_physical_cancellable(plan, &CancellationToken::default())
    }

    pub fn execute_physical_parallel(
        &self,
        plan: &PhysicalPlan,
        config: ParallelQueryConfig,
    ) -> Result<VectorBatch> {
        self.execute_physical_parallel_cancellable(plan, config, &CancellationToken::default())
    }

    pub fn execute_physical_cancellable(
        &self,
        plan: &PhysicalPlan,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        cancellation.check()?;
        match plan {
            PhysicalPlan::SeqScan {
                relation_id, table, ..
            } => self.scan_table(*relation_id, table),
            PhysicalPlan::IndexScan {
                relation_id,
                table,
                index,
                column,
                value,
                ..
            } => self.decrypt_physical_scan(
                *relation_id,
                self.with_table(table, |table| table.index_scan(index, column, value))?,
            ),
            PhysicalPlan::ExpressionIndexScan {
                relation_id,
                table,
                index,
                expr,
                value,
                ..
            } => self.decrypt_physical_scan(
                *relation_id,
                self.with_table(table, |table| {
                    table.expression_index_scan(index, expr, value)
                })?,
            ),
            PhysicalPlan::IndexRangeScan {
                relation_id,
                table,
                index,
                column,
                lower,
                lower_inclusive,
                upper,
                upper_inclusive,
                ..
            } => self.decrypt_physical_scan(
                *relation_id,
                self.with_table(table, |table| {
                    table.index_range_scan(
                        index,
                        column,
                        lower.as_ref(),
                        *lower_inclusive,
                        upper.as_ref(),
                        *upper_inclusive,
                    )
                })?,
            ),
            PhysicalPlan::IndexSkipScan {
                relation_id,
                table,
                index,
                column,
                value,
                ..
            } => self.decrypt_physical_scan(
                *relation_id,
                self.with_table(table, |table| table.index_skip_scan(index, column, value))?,
            ),
            PhysicalPlan::TextSearchScan {
                relation_id,
                table,
                column,
                query,
                ..
            } => {
                let batch = self.with_table(table, |table| Ok(table.scan()))?;
                let batch = self.decrypt_physical_scan(*relation_id, batch)?;
                apply_text_search_cancellable(batch, column, query, cancellation)
            }
            PhysicalPlan::InvertedTextScan {
                relation_id,
                table,
                index,
                column,
                query,
                ..
            } => self.decrypt_physical_scan(
                *relation_id,
                self.with_table(table, |table| {
                    table.text_index_scan(index, column, query, cancellation)
                })?,
            ),
            PhysicalPlan::InvertedValueScan {
                relation_id,
                table,
                index,
                column,
                query,
                ..
            } => self.decrypt_physical_scan(
                *relation_id,
                self.with_table(table, |table| {
                    table.inverted_value_scan(index, column, query)
                })?,
            ),
            PhysicalPlan::BlockSummaryScan {
                relation_id,
                table,
                index,
                column,
                lower,
                lower_inclusive,
                upper,
                upper_inclusive,
                ..
            } => self.decrypt_physical_scan(
                *relation_id,
                self.with_table(table, |table| {
                    table.block_summary_scan(
                        index,
                        column,
                        lower,
                        *lower_inclusive,
                        upper,
                        *upper_inclusive,
                    )
                })?,
            ),
            PhysicalPlan::RangeOverlapScan {
                relation_id,
                table,
                index,
                column,
                range,
                ..
            } => self.decrypt_physical_scan(
                *relation_id,
                self.with_table(table, |table| {
                    table.range_overlap_scan(index, column, range)
                })?,
            ),
            PhysicalPlan::BoundsOverlapScan {
                relation_id,
                table,
                index,
                column,
                bounds,
                ..
            } => self.decrypt_physical_scan(
                *relation_id,
                self.with_table(table, |table| {
                    table.bounds_overlap_scan(index, column, bounds)
                })?,
            ),
            PhysicalPlan::SidewaysIndexLookup {
                outer,
                inner_table,
                inner_index,
                inner_column,
                outer_column,
                ..
            } => self.execute_sideways_index_lookup(
                outer,
                inner_table,
                inner_index,
                inner_column,
                outer_column,
                cancellation,
            ),
            PhysicalPlan::NestedLoopJoin {
                kind,
                left,
                right,
                predicate,
                ..
            } => {
                let left = self.execute_physical_cancellable(left, cancellation)?;
                let right = self.execute_physical_cancellable(right, cancellation)?;
                if self.expr_needs_row_subquery_resolution(predicate)? {
                    return self.apply_nested_loop_join_with_subqueries(
                        left,
                        right,
                        *kind,
                        predicate,
                        cancellation,
                    );
                }
                let predicate = self.resolve_scalar_subqueries(predicate, cancellation)?;
                apply_nested_loop_join_cancellable(left, right, *kind, &predicate, cancellation)
            }
            PhysicalPlan::Filter {
                predicate, input, ..
            } => {
                if self.expr_needs_row_subquery_resolution(predicate)? {
                    let batch = self.execute_physical_cancellable(input, cancellation)?;
                    return self.apply_row_subquery_filter(batch, predicate, cancellation);
                }
                let predicate = self.resolve_scalar_subqueries(predicate, cancellation)?;
                let batch = self.execute_physical_cancellable(input, cancellation)?;
                apply_filter_cancellable(batch, &predicate, cancellation)
            }
            PhysicalPlan::InSubqueryFilter {
                expr,
                subquery,
                negated,
                input,
                ..
            } => {
                let input = self.execute_physical_cancellable(input, cancellation)?;
                self.apply_physical_in_subquery_filter(
                    input,
                    subquery,
                    expr,
                    *negated,
                    cancellation,
                )
            }
            PhysicalPlan::ExistsSubqueryFilter {
                subquery,
                negated,
                input,
                ..
            } => {
                let input = self.execute_physical_cancellable(input, cancellation)?;
                self.apply_physical_exists_subquery_filter(input, subquery, *negated, cancellation)
            }
            PhysicalPlan::Projection { items, input, .. } => {
                let batch = self.execute_physical_cancellable(input, cancellation)?;
                self.apply_projection_with_subqueries(batch, items, cancellation)
            }
            PhysicalPlan::Window { items, input, .. } => {
                let batch = self.execute_physical_cancellable(input, cancellation)?;
                apply_window_cancellable(batch, items, cancellation)
            }
            PhysicalPlan::Aggregate { items, input, .. } => {
                let batch = self.execute_physical_cancellable(input, cancellation)?;
                apply_aggregate_cancellable(batch, items, cancellation)
            }
            PhysicalPlan::GroupedAggregate {
                group_by,
                items,
                input,
                ..
            } => {
                let batch = self.execute_physical_cancellable(input, cancellation)?;
                apply_grouped_aggregate_cancellable(batch, group_by, items, cancellation)
            }
            PhysicalPlan::GroupingSetsAggregate {
                group_by,
                grouping_sets,
                items,
                input,
                ..
            } => {
                let batch = self.execute_physical_cancellable(input, cancellation)?;
                apply_grouping_sets_aggregate_cancellable(
                    batch,
                    group_by,
                    grouping_sets,
                    items,
                    cancellation,
                )
            }
            PhysicalPlan::Distinct { input, .. } => {
                let batch = self.execute_physical_cancellable(input, cancellation)?;
                apply_distinct_cancellable(batch, cancellation)
            }
            PhysicalPlan::Sort { keys, input, .. } => {
                let batch = self.execute_physical_cancellable(input, cancellation)?;
                self.apply_sort_with_scalar_subqueries(batch, keys, cancellation)
            }
            PhysicalPlan::Limit { count, input, .. } => {
                let batch = self.execute_physical_cancellable(input, cancellation)?;
                apply_limit_cancellable(batch, *count, cancellation)
            }
            PhysicalPlan::Offset { count, input, .. } => {
                let batch = self.execute_physical_cancellable(input, cancellation)?;
                apply_offset_cancellable(batch, *count, cancellation)
            }
            PhysicalPlan::SetOperation {
                kind,
                all,
                left,
                right,
                ..
            } => {
                let left = self.execute_physical_cancellable(left, cancellation)?;
                let right = self.execute_physical_cancellable(right, cancellation)?;
                match kind {
                    SetOperationKind::Union => {
                        apply_union_cancellable(left, right, *all, cancellation)
                    }
                    SetOperationKind::Intersect => {
                        apply_intersect_cancellable(left, right, *all, cancellation)
                    }
                    SetOperationKind::Except => {
                        apply_except_cancellable(left, right, *all, cancellation)
                    }
                }
            }
            PhysicalPlan::Parallel { input, .. } => {
                self.execute_physical_cancellable(input, cancellation)
            }
            PhysicalPlan::Unsupported { reason, .. } => {
                Err(RnovError::new(ErrorKind::InvalidInput, reason.clone()))
            }
            _ => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "memory executor cannot execute this physical plan",
            )),
        }
    }

    pub fn execute_physical_parallel_cancellable(
        &self,
        plan: &PhysicalPlan,
        config: ParallelQueryConfig,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        config.validate()?;
        cancellation.check()?;
        match plan {
            PhysicalPlan::SeqScan {
                relation_id, table, ..
            } => self.decrypt_physical_scan(
                *relation_id,
                self.with_table(table, |table| {
                    table.scan_parallel_cancellable(config, cancellation)
                })?,
            ),
            PhysicalPlan::TextSearchScan {
                relation_id,
                table,
                column,
                query,
                ..
            } => {
                let batch = self.with_table(table, |table| {
                    table.scan_parallel_cancellable(config, cancellation)
                })?;
                let batch = self.decrypt_physical_scan(*relation_id, batch)?;
                apply_text_search_cancellable(batch, column, query, cancellation)
            }
            PhysicalPlan::SidewaysIndexLookup {
                outer,
                inner_table,
                inner_index,
                inner_column,
                outer_column,
                ..
            } => self.execute_sideways_index_lookup_parallel(
                SidewaysIndexLookupInput {
                    outer,
                    inner_table,
                    inner_index,
                    inner_column,
                    outer_column,
                },
                config,
                cancellation,
            ),
            PhysicalPlan::Filter {
                predicate, input, ..
            } => {
                if self.expr_needs_row_subquery_resolution(predicate)? {
                    let batch =
                        self.execute_physical_parallel_cancellable(input, config, cancellation)?;
                    return self.apply_row_subquery_filter(batch, predicate, cancellation);
                }
                let predicate = self.resolve_scalar_subqueries(predicate, cancellation)?;
                let batch =
                    self.execute_physical_parallel_cancellable(input, config, cancellation)?;
                apply_filter_cancellable(batch, &predicate, cancellation)
            }
            PhysicalPlan::InSubqueryFilter {
                expr,
                subquery,
                negated,
                input,
                ..
            } => {
                let input =
                    self.execute_physical_parallel_cancellable(input, config, cancellation)?;
                self.apply_physical_in_subquery_filter_parallel(
                    input,
                    subquery,
                    expr,
                    *negated,
                    config,
                    cancellation,
                )
            }
            PhysicalPlan::ExistsSubqueryFilter {
                subquery,
                negated,
                input,
                ..
            } => {
                let input =
                    self.execute_physical_parallel_cancellable(input, config, cancellation)?;
                self.apply_physical_exists_subquery_filter_parallel(
                    input,
                    subquery,
                    *negated,
                    config,
                    cancellation,
                )
            }
            PhysicalPlan::Projection { items, input, .. } => {
                let batch =
                    self.execute_physical_parallel_cancellable(input, config, cancellation)?;
                self.apply_projection_with_subqueries(batch, items, cancellation)
            }
            PhysicalPlan::Window { items, input, .. } => {
                let batch =
                    self.execute_physical_parallel_cancellable(input, config, cancellation)?;
                apply_window_cancellable(batch, items, cancellation)
            }
            PhysicalPlan::Aggregate { items, input, .. } => {
                let batch =
                    self.execute_physical_parallel_cancellable(input, config, cancellation)?;
                apply_aggregate_cancellable(batch, items, cancellation)
            }
            PhysicalPlan::GroupedAggregate {
                group_by,
                items,
                input,
                ..
            } => {
                let batch =
                    self.execute_physical_parallel_cancellable(input, config, cancellation)?;
                apply_grouped_aggregate_parallel_cancellable(
                    batch,
                    group_by,
                    items,
                    config,
                    cancellation,
                )
            }
            PhysicalPlan::GroupingSetsAggregate {
                group_by,
                grouping_sets,
                items,
                input,
                ..
            } => {
                let batch =
                    self.execute_physical_parallel_cancellable(input, config, cancellation)?;
                apply_grouping_sets_aggregate_cancellable(
                    batch,
                    group_by,
                    grouping_sets,
                    items,
                    cancellation,
                )
            }
            PhysicalPlan::Distinct { input, .. } => {
                let batch =
                    self.execute_physical_parallel_cancellable(input, config, cancellation)?;
                apply_distinct_cancellable(batch, cancellation)
            }
            PhysicalPlan::Sort { keys, input, .. } => {
                let batch =
                    self.execute_physical_parallel_cancellable(input, config, cancellation)?;
                self.apply_sort_with_scalar_subqueries(batch, keys, cancellation)
            }
            PhysicalPlan::Limit { count, input, .. } => {
                let batch =
                    self.execute_physical_parallel_cancellable(input, config, cancellation)?;
                apply_limit_cancellable(batch, *count, cancellation)
            }
            PhysicalPlan::Offset { count, input, .. } => {
                let batch =
                    self.execute_physical_parallel_cancellable(input, config, cancellation)?;
                apply_offset_cancellable(batch, *count, cancellation)
            }
            PhysicalPlan::SetOperation {
                kind,
                all,
                left,
                right,
                ..
            } => {
                let left =
                    self.execute_physical_parallel_cancellable(left, config, cancellation)?;
                let right =
                    self.execute_physical_parallel_cancellable(right, config, cancellation)?;
                match kind {
                    SetOperationKind::Union => {
                        apply_union_cancellable(left, right, *all, cancellation)
                    }
                    SetOperationKind::Intersect => {
                        apply_intersect_cancellable(left, right, *all, cancellation)
                    }
                    SetOperationKind::Except => {
                        apply_except_cancellable(left, right, *all, cancellation)
                    }
                }
            }
            PhysicalPlan::Parallel { input, .. } => {
                self.execute_physical_parallel_cancellable(input, config, cancellation)
            }
            _ => self.execute_physical_cancellable(plan, cancellation),
        }
    }

    pub fn execute_async(
        &self,
        plan: &LogicalPlan,
    ) -> impl Future<Output = Result<VectorBatch>> + Send + 'static {
        let executor = self.clone();
        let plan = plan.clone();
        BlockingResultTask::new(move || executor.execute(&plan))
    }

    pub fn execute_cancellable_async(
        &self,
        plan: &LogicalPlan,
        cancellation: &CancellationToken,
    ) -> impl Future<Output = Result<VectorBatch>> + Send + 'static {
        let executor = self.clone();
        let plan = plan.clone();
        let cancellation = cancellation.clone();
        BlockingResultTask::new(move || executor.execute_cancellable(&plan, &cancellation))
    }

    fn execute_sideways_index_lookup(
        &self,
        outer: &PhysicalPlan,
        inner_table: &str,
        inner_index: &str,
        inner_column: &str,
        outer_column: &str,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        let outer_batch = self.execute_physical_cancellable(outer, cancellation)?;
        let outer_column_index = column_index(outer_batch.columns(), outer_column)?;
        let tables = self.read_tables()?;
        let inner = tables.get(inner_table).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("table not found: {inner_table}"),
            )
        })?;
        let columns = joined_columns(outer_batch.columns(), inner.columns())?;
        let mut rows = Vec::new();

        for outer_row in outer_batch.rows() {
            cancellation.check()?;
            let lookup_value = &outer_row.values()[outer_column_index];
            let inner_batch =
                inner.index_point_lookup_value(inner_index, inner_column, lookup_value)?;
            for inner_row in inner_batch.rows() {
                cancellation.check()?;
                let mut values =
                    Vec::with_capacity(outer_row.values().len() + inner_row.values().len());
                values.extend_from_slice(outer_row.values());
                values.extend_from_slice(inner_row.values());
                rows.push(Row::new(values));
            }
        }

        cancellation.check()?;
        VectorBatch::new(columns, rows)
    }

    fn execute_sideways_index_lookup_parallel(
        &self,
        input: SidewaysIndexLookupInput<'_>,
        config: ParallelQueryConfig,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        let outer_batch =
            self.execute_physical_parallel_cancellable(input.outer, config, cancellation)?;
        let outer_column_index = column_index(outer_batch.columns(), input.outer_column)?;
        let tables = self.read_tables()?;
        let inner = tables.get(input.inner_table).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("table not found: {}", input.inner_table),
            )
        })?;
        let columns = joined_columns(outer_batch.columns(), inner.columns())?;
        if outer_batch.rows().is_empty()
            || config.worker_threads() == 1
            || outer_batch.rows().len() < config.min_parallel_rows()
        {
            return join_sideways_lookup_rows(
                outer_batch.rows(),
                outer_column_index,
                inner,
                input.inner_index,
                input.inner_column,
                columns,
                cancellation,
            );
        }

        let worker_count = config.worker_threads().min(outer_batch.rows().len());
        let chunk_size = outer_batch.rows().len().div_ceil(worker_count);
        let mut rows = Vec::new();
        thread::scope(|scope| {
            let mut handles = Vec::with_capacity(worker_count);
            for chunk in outer_batch.rows().chunks(chunk_size) {
                let cancellation = cancellation.clone();
                handles.push(scope.spawn(move || {
                    join_sideways_lookup_chunk(
                        chunk,
                        outer_column_index,
                        inner,
                        input.inner_index,
                        input.inner_column,
                        &cancellation,
                    )
                }));
            }

            for handle in handles {
                let mut chunk_rows = handle.join().map_err(|_| {
                    RnovError::new(
                        ErrorKind::Internal,
                        "parallel sideways lookup worker panicked",
                    )
                })??;
                rows.append(&mut chunk_rows);
            }
            Ok::<(), RnovError>(())
        })?;

        cancellation.check()?;
        VectorBatch::new(columns, rows)
    }

    fn execute_logical_sideways_lookup(
        &self,
        outer: &LogicalPlan,
        inner_table: &str,
        inner_column: &str,
        outer_column: &str,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        let outer_batch = self.execute_cancellable(outer, cancellation)?;
        let outer_column_index = column_index(outer_batch.columns(), outer_column)?;
        let tables = self.read_tables()?;
        let inner = tables.get(inner_table).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("table not found: {inner_table}"),
            )
        })?;
        let inner_column_index = column_index(inner.columns(), inner_column)?;
        let inner_index = inner
            .point_lookup_index_for_column(inner_column_index)
            .ok_or_else(|| {
                RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("JOIN LATERAL requires an index on {inner_table}.{inner_column}"),
                )
            })?;
        let columns = joined_columns(outer_batch.columns(), inner.columns())?;
        let mut rows = Vec::new();

        for outer_row in outer_batch.rows() {
            cancellation.check()?;
            let lookup_value = &outer_row.values()[outer_column_index];
            let inner_batch =
                inner.index_point_lookup_value(inner_index, inner_column, lookup_value)?;
            for inner_row in inner_batch.rows() {
                cancellation.check()?;
                let mut values =
                    Vec::with_capacity(outer_row.values().len() + inner_row.values().len());
                values.extend_from_slice(outer_row.values());
                values.extend_from_slice(inner_row.values());
                rows.push(Row::new(values));
            }
        }

        cancellation.check()?;
        VectorBatch::new(columns, rows)
    }

    pub fn execute_parallel(
        &self,
        plan: &LogicalPlan,
        config: ParallelQueryConfig,
    ) -> Result<VectorBatch> {
        self.execute_parallel_cancellable(plan, config, &CancellationToken::default())
    }

    pub fn execute_parallel_cancellable(
        &self,
        plan: &LogicalPlan,
        config: ParallelQueryConfig,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        config.validate()?;
        cancellation.check()?;
        match plan {
            LogicalPlan::Scan { relation_id, table } => self.decrypt_physical_scan(
                *relation_id,
                self.with_table(table, |table| {
                    table.scan_parallel_cancellable(config, cancellation)
                })?,
            ),
            LogicalPlan::RecursiveScan { name, .. } => {
                let tables = self.read_tables()?;
                tables
                    .get(name)
                    .ok_or_else(|| {
                        RnovError::new(
                            ErrorKind::NotFound,
                            format!("recursive CTE is not active: {name}"),
                        )
                    })?
                    .scan_parallel_cancellable(config, cancellation)
            }
            LogicalPlan::Filter { predicate, input } => {
                if self.expr_needs_row_subquery_resolution(predicate)? {
                    let batch = self.execute_parallel_cancellable(input, config, cancellation)?;
                    return self.apply_row_subquery_filter(batch, predicate, cancellation);
                }
                let predicate = self.resolve_scalar_subqueries(predicate, cancellation)?;
                if let Some(batch) =
                    self.execute_indexed_filter_scan(&predicate, input, cancellation)?
                {
                    return Ok(batch);
                }
                let batch = self.execute_parallel_cancellable(input, config, cancellation)?;
                apply_filter_cancellable(batch, &predicate, cancellation)
            }
            LogicalPlan::InSubqueryFilter {
                expr,
                subquery,
                negated,
                input,
            } => {
                let input = self.execute_parallel_cancellable(input, config, cancellation)?;
                self.apply_logical_in_subquery_filter(input, subquery, expr, *negated, cancellation)
            }
            LogicalPlan::ExistsSubqueryFilter {
                subquery,
                negated,
                input,
            } => {
                let input = self.execute_parallel_cancellable(input, config, cancellation)?;
                self.apply_logical_exists_subquery_filter(input, subquery, *negated, cancellation)
            }
            LogicalPlan::TextSearch {
                relation_id,
                table,
                column,
                query,
                ..
            } => {
                let batch = {
                    let tables = self.read_tables()?;
                    let table = tables.get(table).ok_or_else(|| {
                        RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                    })?;
                    if let Some(batch) = table.try_text_index_scan(column, query, cancellation)? {
                        return self.column_crypto.decrypt_batch(*relation_id, batch);
                    }
                    table.scan_parallel_cancellable(config, cancellation)?
                };
                let batch = self.column_crypto.decrypt_batch(*relation_id, batch)?;
                apply_text_search_cancellable(batch, column, query, cancellation)
            }
            LogicalPlan::SidewaysLookup {
                outer,
                inner_table,
                inner_column,
                outer_column,
                ..
            } => self.execute_logical_sideways_lookup(
                outer,
                inner_table,
                inner_column,
                outer_column,
                cancellation,
            ),
            LogicalPlan::NestedLoopJoin {
                kind,
                left,
                right,
                predicate,
            } => {
                let left = self.execute_parallel_cancellable(left, config, cancellation)?;
                let right = self.execute_parallel_cancellable(right, config, cancellation)?;
                if self.expr_needs_row_subquery_resolution(predicate)? {
                    return self.apply_nested_loop_join_with_subqueries(
                        left,
                        right,
                        *kind,
                        predicate,
                        cancellation,
                    );
                }
                let predicate = self.resolve_scalar_subqueries(predicate, cancellation)?;
                apply_nested_loop_join_cancellable(left, right, *kind, &predicate, cancellation)
            }
            LogicalPlan::Project { items, input } => {
                let batch = self.execute_parallel_cancellable(input, config, cancellation)?;
                self.apply_projection_with_subqueries(batch, items, cancellation)
            }
            LogicalPlan::Window { items, input } => {
                let batch = self.execute_parallel_cancellable(input, config, cancellation)?;
                apply_window_cancellable(batch, items, cancellation)
            }
            LogicalPlan::Aggregate { items, input } => {
                let batch = self.execute_parallel_cancellable(input, config, cancellation)?;
                apply_aggregate_cancellable(batch, items, cancellation)
            }
            LogicalPlan::GroupedAggregate {
                group_by,
                items,
                input,
            } => {
                let batch = self.execute_parallel_cancellable(input, config, cancellation)?;
                apply_grouped_aggregate_parallel_cancellable(
                    batch,
                    group_by,
                    items,
                    config,
                    cancellation,
                )
            }
            LogicalPlan::GroupingSetsAggregate {
                group_by,
                grouping_sets,
                items,
                input,
            } => {
                let batch = self.execute_parallel_cancellable(input, config, cancellation)?;
                apply_grouping_sets_aggregate_cancellable(
                    batch,
                    group_by,
                    grouping_sets,
                    items,
                    cancellation,
                )
            }
            LogicalPlan::Distinct { input } => {
                let batch = self.execute_parallel_cancellable(input, config, cancellation)?;
                apply_distinct_cancellable(batch, cancellation)
            }
            LogicalPlan::Union { all, left, right } => {
                let left = self.execute_parallel_cancellable(left, config, cancellation)?;
                let right = self.execute_parallel_cancellable(right, config, cancellation)?;
                apply_union_cancellable(left, right, *all, cancellation)
            }
            LogicalPlan::Intersect { all, left, right } => {
                let left = self.execute_parallel_cancellable(left, config, cancellation)?;
                let right = self.execute_parallel_cancellable(right, config, cancellation)?;
                apply_intersect_cancellable(left, right, *all, cancellation)
            }
            LogicalPlan::Except { all, left, right } => {
                let left = self.execute_parallel_cancellable(left, config, cancellation)?;
                let right = self.execute_parallel_cancellable(right, config, cancellation)?;
                apply_except_cancellable(left, right, *all, cancellation)
            }
            LogicalPlan::RecursiveCte {
                name,
                columns,
                seed,
                recursive,
                query,
            } => self.execute_recursive_cte_cancellable(
                name,
                columns,
                seed,
                recursive,
                query,
                cancellation,
            ),
            LogicalPlan::Sort { keys, input } => {
                let batch = self.execute_parallel_cancellable(input, config, cancellation)?;
                self.apply_sort_with_scalar_subqueries(batch, keys, cancellation)
            }
            LogicalPlan::Limit { count, input } => {
                let batch = self.execute_parallel_cancellable(input, config, cancellation)?;
                apply_limit_cancellable(batch, *count, cancellation)
            }
            LogicalPlan::Offset { count, input } => {
                let batch = self.execute_parallel_cancellable(input, config, cancellation)?;
                apply_offset_cancellable(batch, *count, cancellation)
            }
            LogicalPlan::Parallel { hint, input } => {
                let hinted_config =
                    ParallelQueryConfig::new(hint.workers, config.min_parallel_rows());
                self.execute_parallel_cancellable(input, hinted_config, cancellation)
            }
            _ => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "memory executor does not support this logical plan",
            )),
        }
    }

    pub fn execute_parallel_async(
        &self,
        plan: &LogicalPlan,
        config: ParallelQueryConfig,
    ) -> impl Future<Output = Result<VectorBatch>> + Send + 'static {
        let executor = self.clone();
        let plan = plan.clone();
        BlockingResultTask::new(move || executor.execute_parallel(&plan, config))
    }

    pub fn execute_parallel_cancellable_async(
        &self,
        plan: &LogicalPlan,
        config: ParallelQueryConfig,
        cancellation: &CancellationToken,
    ) -> impl Future<Output = Result<VectorBatch>> + Send + 'static {
        let executor = self.clone();
        let plan = plan.clone();
        let cancellation = cancellation.clone();
        BlockingResultTask::new(move || {
            executor.execute_parallel_cancellable(&plan, config, &cancellation)
        })
    }

    pub fn execute_mut(&mut self, plan: &LogicalPlan) -> Result<ExecutionResult> {
        match plan {
            LogicalPlan::CreateTable {
                table,
                columns,
                if_not_exists,
            } => {
                self.create_table(table, columns, *if_not_exists)?;
                Ok(ExecutionResult::SchemaChanged)
            }
            LogicalPlan::CreateIndex {
                name,
                table,
                keys,
                method,
                unique,
                if_not_exists,
                ..
            } => {
                self.create_index(CreateIndexInput {
                    name,
                    table,
                    keys,
                    method: *method,
                    unique: *unique,
                    if_not_exists: *if_not_exists,
                })?;
                Ok(ExecutionResult::SchemaChanged)
            }
            LogicalPlan::CreateTrigger { .. } => Ok(ExecutionResult::SchemaChanged),
            LogicalPlan::DropIndex { name, if_exists } => {
                if self.drop_index(name)? || *if_exists {
                    Ok(ExecutionResult::SchemaChanged)
                } else {
                    Err(RnovError::new(
                        ErrorKind::NotFound,
                        format!("index not found: {name}"),
                    ))
                }
            }
            LogicalPlan::DropTrigger { .. } => Ok(ExecutionResult::SchemaChanged),
            LogicalPlan::AlterTableAddColumn {
                table,
                column,
                if_not_exists,
                ..
            } => {
                let mut tables = self.write_tables()?;
                let table = tables.get_mut(table).ok_or_else(|| {
                    RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                })?;
                if table
                    .columns()
                    .iter()
                    .any(|existing| existing.name().eq_ignore_ascii_case(column.name.as_str()))
                    && *if_not_exists
                {
                    return Ok(ExecutionResult::SchemaChanged);
                }
                table.add_column(column_schema_from_def(column))?;
                Ok(ExecutionResult::SchemaChanged)
            }
            LogicalPlan::AlterColumnEncryption {
                table,
                column,
                encrypted,
                ..
            } => {
                let mut tables = self.write_tables()?;
                let table = tables.get_mut(table).ok_or_else(|| {
                    RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                })?;
                table.set_column_encrypted(column, *encrypted)?;
                Ok(ExecutionResult::SchemaChanged)
            }
            LogicalPlan::DropTable {
                table, if_exists, ..
            } => {
                if self.write_tables()?.remove(table).is_some() || *if_exists {
                    Ok(ExecutionResult::SchemaChanged)
                } else {
                    Err(RnovError::new(
                        ErrorKind::NotFound,
                        format!("table not found: {table}"),
                    ))
                }
            }
            LogicalPlan::Insert {
                table,
                columns,
                values,
            } => {
                let column_crypto = self.column_crypto.clone();
                let mut tables = self.write_tables()?;
                let table = tables.get_mut(table).ok_or_else(|| {
                    RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                })?;
                insert_values(table, columns, values, &column_crypto)?;
                Ok(ExecutionResult::RowsAffected(1))
            }
            LogicalPlan::Update {
                relation_id,
                table,
                assignments,
                selection,
                ..
            } => {
                let column_crypto = self.column_crypto.clone();
                let mut tables = self.write_tables()?;
                let table = tables.get_mut(table).ok_or_else(|| {
                    RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                })?;
                update_rows(
                    table,
                    *relation_id,
                    assignments,
                    selection.as_ref(),
                    &column_crypto,
                )
                .map(ExecutionResult::RowsAffected)
            }
            LogicalPlan::Delete {
                relation_id,
                table,
                selection,
                ..
            } => {
                let column_crypto = self.column_crypto.clone();
                let mut tables = self.write_tables()?;
                let table = tables.get_mut(table).ok_or_else(|| {
                    RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                })?;
                delete_rows(table, *relation_id, selection.as_ref(), &column_crypto)
                    .map(ExecutionResult::RowsAffected)
            }
            _ => self.execute(plan).map(ExecutionResult::Batch),
        }
    }

    pub fn execute_mut_async<'a>(
        &'a mut self,
        plan: &LogicalPlan,
    ) -> impl Future<Output = Result<ExecutionResult>> + 'a {
        let executor = self.snapshot();
        let plan = plan.clone();
        BlockingMutationTask {
            executor: self,
            inner: BlockingResultTask::new(move || {
                let mut executor = executor?;
                let result = executor.execute_mut(&plan);
                Ok((executor, result))
            }),
        }
    }

    pub fn execute_mut_parallel(
        &mut self,
        plan: &LogicalPlan,
        config: ParallelQueryConfig,
    ) -> Result<ExecutionResult> {
        self.execute_mut_parallel_cancellable(plan, config, &CancellationToken::default())
    }

    pub fn execute_mut_parallel_cancellable(
        &mut self,
        plan: &LogicalPlan,
        config: ParallelQueryConfig,
        cancellation: &CancellationToken,
    ) -> Result<ExecutionResult> {
        config.validate()?;
        cancellation.check()?;
        match plan {
            LogicalPlan::CreateIndex {
                name,
                table,
                keys,
                method,
                unique,
                if_not_exists,
                ..
            } => {
                self.create_index_parallel(
                    CreateIndexInput {
                        name,
                        table,
                        keys,
                        method: *method,
                        unique: *unique,
                        if_not_exists: *if_not_exists,
                    },
                    config,
                    cancellation,
                )?;
                Ok(ExecutionResult::SchemaChanged)
            }
            _ => self.execute_mut(plan),
        }
    }

    pub fn execute_mut_parallel_async<'a>(
        &'a mut self,
        plan: &LogicalPlan,
        config: ParallelQueryConfig,
    ) -> impl Future<Output = Result<ExecutionResult>> + 'a {
        let executor = self.snapshot();
        let plan = plan.clone();
        BlockingMutationTask {
            executor: self,
            inner: BlockingResultTask::new(move || {
                let mut executor = executor?;
                let result = executor.execute_mut_parallel(&plan, config);
                Ok((executor, result))
            }),
        }
    }

    fn create_table(
        &mut self,
        name: &str,
        columns: &[ColumnDef],
        if_not_exists: bool,
    ) -> Result<()> {
        let mut tables = self.write_tables()?;
        if tables.contains_key(name) {
            if if_not_exists {
                return Ok(());
            }
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("table already exists: {name}"),
            ));
        }
        let columns = columns.iter().map(column_schema_from_def).collect();
        let table = MemoryTable::new(columns)?;
        tables.insert(name.to_string(), table);
        Ok(())
    }

    fn create_index(&mut self, input: CreateIndexInput<'_>) -> Result<()> {
        let mut tables = self.write_tables()?;
        let table = tables.get_mut(input.table).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("table not found: {}", input.table),
            )
        })?;
        if table.indexes.contains_key(input.name) && input.if_not_exists {
            return Ok(());
        }
        table.create_index(input.name, input.keys, input.method, input.unique)
    }

    fn create_index_parallel(
        &mut self,
        input: CreateIndexInput<'_>,
        config: ParallelQueryConfig,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        let mut tables = self.write_tables()?;
        let table = tables.get_mut(input.table).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("table not found: {}", input.table),
            )
        })?;
        if table.indexes.contains_key(input.name) && input.if_not_exists {
            return Ok(());
        }
        table.create_index_parallel(
            input.name,
            input.keys,
            input.method,
            input.unique,
            config,
            cancellation,
        )
    }

    fn drop_index(&mut self, name: &str) -> Result<bool> {
        Ok(self
            .write_tables()?
            .values_mut()
            .any(|table| table.drop_index(name)))
    }

    fn execute_indexed_filter_scan(
        &self,
        predicate: &Expr,
        input: &LogicalPlan,
        cancellation: &CancellationToken,
    ) -> Result<Option<VectorBatch>> {
        let LogicalPlan::Scan { table, .. } = input else {
            return Ok(None);
        };
        let tables = self.read_tables()?;
        let table = tables.get(table).ok_or_else(|| {
            RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
        })?;
        if table.has_encrypted_columns() {
            return Ok(None);
        }
        if let Some((expr, value)) = indexable_expression_equality(predicate)
            && let Some(batch) = table.try_expression_index_scan(expr, value)?
        {
            return apply_filter_cancellable(batch, predicate, cancellation).map(Some);
        }
        if let Some((column, value)) = indexable_equality(predicate) {
            if let Some(batch) = table.try_index_scan(column, value)? {
                return apply_filter_cancellable(batch, predicate, cancellation).map(Some);
            }
            if let Some(batch) = table.try_index_skip_scan(column, value)? {
                return apply_filter_cancellable(batch, predicate, cancellation).map(Some);
            }
        }
        if let Some((column, range)) = indexable_range_overlap(predicate)
            && let Some(batch) = table.try_range_overlap_scan(column, range)?
        {
            return apply_filter_cancellable(batch, predicate, cancellation).map(Some);
        }
        if let Some((column, bounds)) = indexable_bounds_overlap(predicate)
            && let Some(batch) = table.try_bounds_overlap_scan(column, bounds)?
        {
            return apply_filter_cancellable(batch, predicate, cancellation).map(Some);
        }
        if let Some((column, query)) = indexable_inverted_value(predicate)
            && let Some(batch) = table.try_inverted_value_scan(column, &query)?
        {
            return apply_filter_cancellable(batch, predicate, cancellation).map(Some);
        }
        if let Some(range) = indexable_range(predicate) {
            if let Some(batch) = table.try_block_summary_scan(
                range.column,
                range.lower,
                range.lower_inclusive,
                range.upper,
                range.upper_inclusive,
            )? {
                return apply_filter_cancellable(batch, predicate, cancellation).map(Some);
            }
            if let Some(batch) = table.try_index_range_scan(
                range.column,
                range.lower,
                range.lower_inclusive,
                range.upper,
                range.upper_inclusive,
            )? {
                return apply_filter_cancellable(batch, predicate, cancellation).map(Some);
            }
        }
        Ok(None)
    }
}

fn column_schema_from_def(column: &ColumnDef) -> ColumnSchema {
    let mut schema = ColumnSchema::new(column.name.as_str(), column.data_type.clone());
    if !column.nullable {
        schema = schema.not_null();
    }
    if column.encrypted {
        schema = schema.encrypted();
    }
    if let Some(generated) = &column.generated {
        schema = schema.with_generated(generated.clone());
    }
    schema
}

fn column_schema_from_catalog_column(column: &CatalogColumn) -> Result<ColumnSchema> {
    let mut schema = ColumnSchema::new(column.name(), column.data_type().clone());
    if !column.nullable() {
        schema = schema.not_null();
    }
    if column.is_encrypted() {
        schema = schema.encrypted();
    }
    if let Some(generated) = catalog_generated_column(column)? {
        schema = schema.with_generated(generated);
    }
    Ok(schema)
}

fn catalog_generated_column(column: &CatalogColumn) -> Result<Option<GeneratedColumn>> {
    let Some(expr) = column.generated_expr() else {
        return Ok(None);
    };
    Ok(Some(GeneratedColumn {
        expr: parse_expr(expr)?,
        stored: column.generated_stored(),
    }))
}

fn catalog_table_columns(table: &CatalogTable) -> Result<Vec<ColumnSchema>> {
    table
        .columns()
        .iter()
        .map(column_schema_from_catalog_column)
        .collect()
}

fn restore_durable_table(
    catalog: &Catalog,
    table: &DurableTableRows,
    restored: &mut BTreeMap<String, MemoryTable>,
) -> Result<()> {
    let catalog_table = catalog_table_for_executor_name(catalog, table.name())?;
    let memory_table = memory_table_from_durable_rows(catalog_table, table.rows())?;
    restored.insert(table.name().to_string(), memory_table);
    Ok(())
}

fn restore_empty_catalog_tables(
    catalog: &Catalog,
    restored: &mut BTreeMap<String, MemoryTable>,
) -> Result<()> {
    for table in catalog.tables() {
        if restored_table_contains(restored, table) {
            continue;
        }
        let name = default_executor_table_name(table);
        restored.insert(name, MemoryTable::new(catalog_table_columns(table)?)?);
    }
    Ok(())
}

fn restored_table_contains(restored: &BTreeMap<String, MemoryTable>, table: &CatalogTable) -> bool {
    restored
        .keys()
        .any(|name| catalog_table_matches_executor_name(table, name))
}

fn memory_table_from_durable_rows(table: &CatalogTable, rows: &[Vec<u8>]) -> Result<MemoryTable> {
    let mut memory_table = MemoryTable::new(catalog_table_columns(table)?)?;
    for row in rows {
        let decoded = RowCodec::decode(memory_table.columns(), row)?;
        memory_table.insert(decoded)?;
    }
    Ok(memory_table)
}

fn catalog_table_for_executor_name<'a>(
    catalog: &'a Catalog,
    name: &str,
) -> Result<&'a CatalogTable> {
    let matches = catalog
        .tables()
        .into_iter()
        .filter(|table| catalog_table_matches_executor_name(table, name))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [table] => Ok(*table),
        [] => Err(RnovError::new(
            ErrorKind::Corruption,
            format!("durable table has no catalog entry: {name}"),
        )),
        _ => Err(RnovError::new(
            ErrorKind::Corruption,
            format!("durable table name is ambiguous: {name}"),
        )),
    }
}

fn catalog_table_matches_executor_name(table: &CatalogTable, name: &str) -> bool {
    name == table.name() || name == qualified_catalog_table_name(table)
}

fn default_executor_table_name(table: &CatalogTable) -> String {
    if table.schema_name() == "public" {
        table.name().to_string()
    } else {
        qualified_catalog_table_name(table)
    }
}

fn qualified_catalog_table_name(table: &CatalogTable) -> String {
    format!("{}.{}", table.schema_name(), table.name())
}

fn catalog_index_key_defs(keys: &[CatalogIndexKey]) -> Result<Vec<IndexKeyDef>> {
    keys.iter().map(catalog_index_key_def).collect()
}

fn catalog_index_key_def(key: &CatalogIndexKey) -> Result<IndexKeyDef> {
    match key {
        CatalogIndexKey::Column(name) => Ok(IndexKeyDef::Column(Ident::new(name))),
        CatalogIndexKey::Expression(expr) => Ok(IndexKeyDef::Expression(parse_expr(expr)?)),
    }
}

fn executor_table_key_for_catalog_name(
    tables: &BTreeMap<String, MemoryTable>,
    schema: &str,
    table: &str,
) -> Result<String> {
    let qualified = format!("{schema}.{table}");
    if tables.contains_key(&qualified) {
        return Ok(qualified);
    }
    if tables.contains_key(table) {
        return Ok(table.to_string());
    }
    Err(RnovError::new(
        ErrorKind::NotFound,
        format!("table not found for catalog relation: {schema}.{table}"),
    ))
}

fn schema_row_width_bytes(columns: &[ColumnSchema]) -> f64 {
    columns
        .iter()
        .map(|column| sql_type_width_bytes(column.data_type()))
        .sum::<f64>()
        .max(1.0)
}

fn sql_type_width_bytes(data_type: &SqlType) -> f64 {
    match data_type {
        SqlType::Null => 1.0,
        SqlType::Bool => 1.0,
        SqlType::Int64 | SqlType::UInt64 | SqlType::Float64 | SqlType::Timestamp => 8.0,
        SqlType::Uuid => 16.0,
        SqlType::Text | SqlType::Bytes => 32.0,
        SqlType::Json | SqlType::HStore | SqlType::TextVector => 64.0,
        SqlType::Array(_) => 32.0,
        SqlType::Range(_) => 16.0,
    }
}

fn pointer_for_slot(slot: usize) -> Result<IndexPointer> {
    let slot_id = u16::try_from(slot).map_err(|_| {
        RnovError::new(
            ErrorKind::InvalidInput,
            "memory table has too many rows for in-memory index pointers",
        )
    })?;
    Ok(IndexPointer::new(MEMORY_INDEX_PAGE_ID, slot_id))
}

fn index_key_from_literal_expr(expr: &Expr) -> Result<IndexKey> {
    maybe_index_key_from_literal_expr(expr)?.ok_or_else(|| {
        RnovError::new(
            ErrorKind::InvalidInput,
            format!("unsupported index scan value: {expr}"),
        )
    })
}

fn maybe_index_key_from_literal_expr(expr: &Expr) -> Result<Option<IndexKey>> {
    match expr {
        Expr::Integer(value) => Ok(Some(IndexKey::Int64(*value))),
        Expr::String(value) => Ok(Some(IndexKey::Text(value.clone()))),
        _ => Ok(None),
    }
}

fn maybe_bound_key_from_expr(expr: Option<&Expr>) -> Result<Option<IndexKey>> {
    expr.map(maybe_index_key_from_literal_expr)
        .transpose()
        .map(Option::flatten)
}

fn bound_ref(key: Option<&IndexKey>, inclusive: bool) -> Bound<&IndexKey> {
    match (key, inclusive) {
        (Some(key), true) => Bound::Included(key),
        (Some(key), false) => Bound::Excluded(key),
        (None, _) => Bound::Unbounded,
    }
}

fn required_text_query_terms(query: &str) -> Result<Vec<String>> {
    Ok(TextQuery::parse(query)?
        .required_terms()
        .into_iter()
        .map(str::to_string)
        .collect())
}

fn intersect_pointer_lists(lists: Vec<Vec<IndexPointer>>) -> Vec<IndexPointer> {
    let mut lists = lists.into_iter();
    let Some(first) = lists.next() else {
        return Vec::new();
    };
    let mut intersection = first.into_iter().collect::<BTreeSet<_>>();
    for list in lists {
        let set = list.into_iter().collect::<BTreeSet<_>>();
        intersection = intersection.intersection(&set).copied().collect();
        if intersection.is_empty() {
            break;
        }
    }
    intersection.into_iter().collect()
}

fn rebuild_block_summary_index(
    index: &mut BlockSummaryIndex,
    entries: &[(IndexKey, IndexPointer)],
) -> Result<()> {
    let name = index.name().to_string();
    *index = BlockSummaryIndex::new(name);
    for (block_index, chunk) in entries.chunks(MEMORY_SUMMARY_BLOCK_ROWS).enumerate() {
        let first_slot = block_index
            .checked_mul(MEMORY_SUMMARY_BLOCK_ROWS)
            .ok_or_else(|| RnovError::new(ErrorKind::InvalidInput, "summary block overflow"))?;
        let last_slot = first_slot + chunk.len() - 1;
        let mut min_key = chunk[0].0.clone();
        let mut max_key = chunk[0].0.clone();
        for (key, _) in &chunk[1..] {
            if *key < min_key {
                min_key = key.clone();
            }
            if *key > max_key {
                max_key = key.clone();
            }
        }
        index.insert_summary(
            BlockRange::new(
                PageId::new(first_slot as u64),
                PageId::new(last_slot as u64),
            )?,
            min_key,
            max_key,
        )?;
    }
    Ok(())
}

fn block_ranges_to_pointers(ranges: &[BlockRange], row_count: usize) -> Result<Vec<IndexPointer>> {
    let mut pointers = BTreeSet::new();
    for range in ranges {
        let start = usize::try_from(range.start_page().get()).map_err(|_| {
            RnovError::new(ErrorKind::InvalidInput, "summary block start exceeds usize")
        })?;
        let end = usize::try_from(range.end_page().get()).map_err(|_| {
            RnovError::new(ErrorKind::InvalidInput, "summary block end exceeds usize")
        })?;
        for slot in start..=end.min(row_count.saturating_sub(1)) {
            pointers.insert(pointer_for_slot(slot)?);
        }
    }
    Ok(pointers.into_iter().collect())
}

fn between_predicate(
    column: &str,
    lower: &Expr,
    lower_inclusive: bool,
    upper: &Expr,
    upper_inclusive: bool,
) -> Expr {
    if lower_inclusive && upper_inclusive {
        Expr::Between {
            expr: Box::new(Expr::Identifier(Ident::new(column))),
            low: Box::new(lower.clone()),
            high: Box::new(upper.clone()),
            negated: false,
        }
    } else {
        let lower_op = if lower_inclusive { ">=" } else { ">" };
        let upper_op = if upper_inclusive { "<=" } else { "<" };
        Expr::Binary {
            left: Box::new(Expr::Binary {
                left: Box::new(Expr::Identifier(Ident::new(column))),
                op: lower_op.to_string(),
                right: Box::new(lower.clone()),
            }),
            op: "AND".to_string(),
            right: Box::new(Expr::Binary {
                left: Box::new(Expr::Identifier(Ident::new(column))),
                op: upper_op.to_string(),
                right: Box::new(upper.clone()),
            }),
        }
    }
}

fn text_vector_from_value(value: &SqlValue) -> Result<Option<TextVector>> {
    let vector = match value {
        SqlValue::Null => return Ok(None),
        SqlValue::Text(text) => TextVectorBuilder::new(SimpleTokenizer::new()).build(text)?,
        SqlValue::TextVector(vector) => vector.clone(),
        other => {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "gin text index cannot index value type {:?}",
                    other.data_type()
                ),
            ));
        }
    };
    if vector.is_empty() {
        Ok(None)
    } else {
        Ok(Some(vector))
    }
}

fn index_key_from_value(value: &SqlValue) -> Result<Option<IndexKey>> {
    match value {
        SqlValue::Null => Ok(None),
        SqlValue::Int64(value) => Ok(Some(IndexKey::Int64(*value))),
        SqlValue::Text(value) => Ok(Some(IndexKey::Text(value.clone()))),
        other => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("unsupported indexed value type: {:?}", other.data_type()),
        )),
    }
}

fn composite_key_from_row(
    row: &Row,
    column_indexes: &[usize],
) -> Result<Option<CompositeIndexKey>> {
    let mut keys = Vec::with_capacity(column_indexes.len());
    for index in column_indexes {
        let Some(key) = index_key_from_value(&row.values()[*index])? else {
            return Ok(None);
        };
        keys.push(key);
    }
    CompositeIndexKey::new(keys).map(Some)
}

#[derive(Clone, Copy, Debug)]
struct IndexableRange<'a> {
    column: &'a str,
    lower: Option<&'a Expr>,
    lower_inclusive: bool,
    upper: Option<&'a Expr>,
    upper_inclusive: bool,
}

fn indexable_equality(predicate: &Expr) -> Option<(&str, &Expr)> {
    let Expr::Binary { left, op, right } = predicate else {
        return None;
    };
    if op != "=" {
        return None;
    }
    match (left.as_ref(), right.as_ref()) {
        (Expr::Identifier(column), value) if is_index_literal(value) => {
            Some((column.as_str(), value))
        }
        (value, Expr::Identifier(column)) if is_index_literal(value) => {
            Some((column.as_str(), value))
        }
        _ => None,
    }
}

fn indexable_expression_equality(predicate: &Expr) -> Option<(&Expr, &Expr)> {
    let Expr::Binary { left, op, right } = predicate else {
        return None;
    };
    if op != "=" {
        return None;
    }
    match (left.as_ref(), right.as_ref()) {
        (Expr::Identifier(_), _) | (_, Expr::Identifier(_)) => None,
        (expr, value) if is_indexable_expression(expr) && is_index_literal(value) => {
            Some((expr, value))
        }
        (value, expr) if is_index_literal(value) && is_indexable_expression(expr) => {
            Some((expr, value))
        }
        _ => None,
    }
}

fn is_indexable_expression(expr: &Expr) -> bool {
    !matches!(
        expr,
        Expr::Integer(_) | Expr::Float64(_) | Expr::String(_) | Expr::Bool(_) | Expr::Null
    )
}

fn indexable_range(predicate: &Expr) -> Option<IndexableRange<'_>> {
    if let Expr::Between {
        expr,
        low,
        high,
        negated: false,
    } = predicate
        && let (Expr::Identifier(column), low, high) = (expr.as_ref(), low.as_ref(), high.as_ref())
        && is_index_literal(low)
        && is_index_literal(high)
    {
        return Some(IndexableRange {
            column: column.as_str(),
            lower: Some(low),
            lower_inclusive: true,
            upper: Some(high),
            upper_inclusive: true,
        });
    }
    let Expr::Binary { left, op, right } = predicate else {
        return None;
    };
    match (left.as_ref(), op.as_str(), right.as_ref()) {
        (Expr::Identifier(column), ">", value) if is_index_literal(value) => Some(IndexableRange {
            column: column.as_str(),
            lower: Some(value),
            lower_inclusive: false,
            upper: None,
            upper_inclusive: true,
        }),
        (Expr::Identifier(column), ">=", value) if is_index_literal(value) => {
            Some(IndexableRange {
                column: column.as_str(),
                lower: Some(value),
                lower_inclusive: true,
                upper: None,
                upper_inclusive: true,
            })
        }
        (Expr::Identifier(column), "<", value) if is_index_literal(value) => Some(IndexableRange {
            column: column.as_str(),
            lower: None,
            lower_inclusive: true,
            upper: Some(value),
            upper_inclusive: false,
        }),
        (Expr::Identifier(column), "<=", value) if is_index_literal(value) => {
            Some(IndexableRange {
                column: column.as_str(),
                lower: None,
                lower_inclusive: true,
                upper: Some(value),
                upper_inclusive: true,
            })
        }
        (value, "<", Expr::Identifier(column)) if is_index_literal(value) => Some(IndexableRange {
            column: column.as_str(),
            lower: Some(value),
            lower_inclusive: false,
            upper: None,
            upper_inclusive: true,
        }),
        (value, "<=", Expr::Identifier(column)) if is_index_literal(value) => {
            Some(IndexableRange {
                column: column.as_str(),
                lower: Some(value),
                lower_inclusive: true,
                upper: None,
                upper_inclusive: true,
            })
        }
        (value, ">", Expr::Identifier(column)) if is_index_literal(value) => Some(IndexableRange {
            column: column.as_str(),
            lower: None,
            lower_inclusive: true,
            upper: Some(value),
            upper_inclusive: false,
        }),
        (value, ">=", Expr::Identifier(column)) if is_index_literal(value) => {
            Some(IndexableRange {
                column: column.as_str(),
                lower: None,
                lower_inclusive: true,
                upper: Some(value),
                upper_inclusive: true,
            })
        }
        _ => None,
    }
}

fn indexable_range_overlap(predicate: &Expr) -> Option<(&str, &Expr)> {
    let Expr::Binary { left, op, right } = predicate else {
        return None;
    };
    if op != "&&" {
        return None;
    }
    match (left.as_ref(), right.as_ref()) {
        (Expr::Identifier(column), range @ Expr::Range { .. }) => Some((column.as_str(), range)),
        (range @ Expr::Range { .. }, Expr::Identifier(column)) => Some((column.as_str(), range)),
        _ => None,
    }
}

fn indexable_bounds_overlap(predicate: &Expr) -> Option<(&str, &Expr)> {
    let Expr::Binary { left, op, right } = predicate else {
        return None;
    };
    if op != "&&" {
        return None;
    }
    match (left.as_ref(), right.as_ref()) {
        (Expr::Identifier(column), bounds @ Expr::Array(values))
            if values
                .iter()
                .all(|value| matches!(value, Expr::Range { .. })) =>
        {
            Some((column.as_str(), bounds))
        }
        (bounds @ Expr::Array(values), Expr::Identifier(column))
            if values
                .iter()
                .all(|value| matches!(value, Expr::Range { .. })) =>
        {
            Some((column.as_str(), bounds))
        }
        _ => None,
    }
}

fn indexable_inverted_value(predicate: &Expr) -> Option<(&str, InvertedValueQuery)> {
    let Expr::Binary { left, op, right } = predicate else {
        return None;
    };
    match (left.as_ref(), op.as_str(), right.as_ref()) {
        (Expr::Identifier(column), "@>", Expr::Array(values)) => Some((
            column.as_str(),
            InvertedValueQuery::ArrayContains {
                values: values.clone(),
            },
        )),
        (Expr::Identifier(column), "@>", Expr::HStore(entries)) => Some((
            column.as_str(),
            InvertedValueQuery::HStoreContains {
                entries: entries.clone(),
            },
        )),
        (Expr::Identifier(column), "?", Expr::String(key)) => Some((
            column.as_str(),
            InvertedValueQuery::HStoreKey { key: key.clone() },
        )),
        _ => None,
    }
}

fn is_index_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::Integer(_) | Expr::String(_))
}

fn range_from_literal_expr(expr: &Expr) -> Result<SqlRange> {
    let Expr::Range {
        lower,
        upper,
        bounds,
    } = expr
    else {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("unsupported range index query: {expr}"),
        ));
    };
    let SqlValue::Range(range) =
        range_literal_value(lower, upper, bounds.lower_inclusive, bounds.upper_inclusive)?
    else {
        unreachable!("range literal conversion returns a range value")
    };
    Ok(range)
}

fn bounding_box_from_expr(expr: &Expr) -> Result<BoundingBox> {
    let value = literal_value(expr)?;
    let Some(bounds) = bounding_box_from_value(&value)? else {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("unsupported bounds index query: {expr}"),
        ));
    };
    Ok(bounds)
}

fn bounding_box_from_value(value: &SqlValue) -> Result<Option<BoundingBox>> {
    let SqlValue::Array(array) = value else {
        if value.is_null() {
            return Ok(None);
        }
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "bounds index requires RANGE<INT64>[] value, got {:?}",
                value.data_type()
            ),
        ));
    };
    if array.is_empty() {
        return Ok(None);
    }
    let axes = array
        .values()
        .iter()
        .map(axis_bounds_from_value)
        .collect::<Result<Vec<_>>>()?;
    BoundingBox::new(axes).map(Some)
}

fn axis_bounds_from_value(value: &SqlValue) -> Result<AxisBounds> {
    let SqlValue::Range(range) = value else {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "bounds index array must contain RANGE values",
        ));
    };
    if range.element_type() != &SqlType::Int64 {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "bounds index ranges must use INT64 bounds",
        ));
    }
    let lower = axis_bound_value(range.lower(), "lower")?;
    let upper = axis_bound_value(range.upper(), "upper")?;
    AxisBounds::new(lower, upper)
}

fn axis_bound_value(bound: &RangeBound, label: &str) -> Result<i64> {
    match bound {
        RangeBound::Included(SqlValue::Int64(value))
        | RangeBound::Excluded(SqlValue::Int64(value)) => Ok(*value),
        RangeBound::Unbounded => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("bounds index requires finite {label} bounds"),
        )),
        other => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("bounds index requires INT64 {label} bounds, got {other:?}"),
        )),
    }
}

fn update_rows(
    table: &mut MemoryTable,
    relation_id: RelationId,
    assignments: &[(String, Expr)],
    selection: Option<&Expr>,
    column_crypto: &ColumnCryptoState,
) -> Result<u64> {
    let columns = table.columns.clone();
    let assignments = compile_assignments(&columns, assignments)?;
    let original_rows = table.rows.clone();
    let original_indexes = table.indexes.clone();
    let mut rows = original_rows.clone();
    let mut affected = 0;

    for row in &mut rows {
        let logical_row = column_crypto.decrypt_row(relation_id, &columns, row)?;
        if row_matches(&columns, &logical_row, selection)? {
            let mut updated = logical_row.clone();
            for (index, expr) in &assignments {
                updated.set_value(*index, eval_expr(&columns, &logical_row, expr)?);
            }
            recompute_generated_values(&columns, &mut updated)?;
            let encrypted = column_crypto.encrypt_row(relation_id, &columns, &updated)?;
            validate_row_against_columns(&columns, &encrypted)?;
            *row = encrypted;
            affected += 1;
        }
    }

    table.rows = rows;
    if let Err(err) = table.rebuild_indexes() {
        table.rows = original_rows;
        table.indexes = original_indexes;
        return Err(err);
    }
    Ok(affected)
}

fn delete_rows(
    table: &mut MemoryTable,
    relation_id: RelationId,
    selection: Option<&Expr>,
    column_crypto: &ColumnCryptoState,
) -> Result<u64> {
    let columns = table.columns.clone();
    let original_rows = table.rows.clone();
    let original_indexes = table.indexes.clone();
    let mut kept = Vec::with_capacity(original_rows.len());
    let mut affected = 0;

    for row in original_rows.iter().cloned() {
        let logical_row = column_crypto.decrypt_row(relation_id, &columns, &row)?;
        if row_matches(&columns, &logical_row, selection)? {
            affected += 1;
        } else {
            kept.push(row);
        }
    }

    table.rows = kept;
    if let Err(err) = table.rebuild_indexes() {
        table.rows = original_rows;
        table.indexes = original_indexes;
        return Err(err);
    }
    Ok(affected)
}

fn compile_assignments(
    columns: &[ColumnSchema],
    assignments: &[(String, Expr)],
) -> Result<Vec<(usize, Expr)>> {
    let mut compiled = Vec::with_capacity(assignments.len());
    for (index, (column, expr)) in assignments.iter().enumerate() {
        if assignments[..index]
            .iter()
            .any(|(existing, _)| existing == column)
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("duplicate update column: {column}"),
            ));
        }
        let column_index = column_index(columns, column)?;
        if columns[column_index].generated().is_some() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("cannot update generated column {column}"),
            ));
        }
        compiled.push((column_index, expr.clone()));
    }
    Ok(compiled)
}

fn insert_values(
    table: &mut MemoryTable,
    columns: &[String],
    values: &[Expr],
    column_crypto: &ColumnCryptoState,
) -> Result<()> {
    if columns.len() != values.len() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "insert column count {} does not match value count {}",
                columns.len(),
                values.len()
            ),
        ));
    }

    for (index, column) in columns.iter().enumerate() {
        if columns[..index].iter().any(|existing| existing == column) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("duplicate insert column: {column}"),
            ));
        }
        let column_index = column_index(table.columns(), column)?;
        if table.columns()[column_index].generated().is_some() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("cannot insert explicit value for generated column {column}"),
            ));
        }
    }

    let mut row_values = Vec::with_capacity(table.columns().len());
    for table_column in table.columns() {
        let value = match columns
            .iter()
            .position(|column| column == table_column.name())
        {
            Some(index) => literal_value(&values[index])?,
            None => SqlValue::Null,
        };
        row_values.push(value);
    }

    let mut row = Row::new(row_values);
    recompute_generated_values(table.columns(), &mut row)?;
    let row = column_crypto.encrypt_insert_row(table.columns(), &row)?;
    table.insert(row)
}

fn join_sideways_lookup_rows(
    outer_rows: &[Row],
    outer_column_index: usize,
    inner: &MemoryTable,
    inner_index: &str,
    inner_column: &str,
    columns: Vec<ColumnSchema>,
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    let rows = join_sideways_lookup_chunk(
        outer_rows,
        outer_column_index,
        inner,
        inner_index,
        inner_column,
        cancellation,
    )?;
    VectorBatch::new(columns, rows)
}

fn join_sideways_lookup_chunk(
    outer_rows: &[Row],
    outer_column_index: usize,
    inner: &MemoryTable,
    inner_index: &str,
    inner_column: &str,
    cancellation: &CancellationToken,
) -> Result<Vec<Row>> {
    let mut rows = Vec::new();
    for outer_row in outer_rows {
        cancellation.check()?;
        let lookup_value = &outer_row.values()[outer_column_index];
        let inner_batch =
            inner.index_point_lookup_value(inner_index, inner_column, lookup_value)?;
        for inner_row in inner_batch.rows() {
            cancellation.check()?;
            let mut values =
                Vec::with_capacity(outer_row.values().len() + inner_row.values().len());
            values.extend_from_slice(outer_row.values());
            values.extend_from_slice(inner_row.values());
            rows.push(Row::new(values));
        }
    }
    cancellation.check()?;
    Ok(rows)
}

fn recompute_generated_values(columns: &[ColumnSchema], row: &mut Row) -> Result<()> {
    for (index, column) in columns.iter().enumerate() {
        let Some(generated) = column.generated() else {
            continue;
        };
        if !generated.stored {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "only stored generated columns are supported",
            ));
        }
        let value = eval_expr(columns, row, &generated.expr)?;
        row.set_value(index, value);
    }
    Ok(())
}

fn apply_filter_cancellable(
    batch: VectorBatch,
    predicate: &Expr,
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    let mut rows = Vec::new();
    for row in batch.rows() {
        cancellation.check()?;
        if eval_predicate(batch.columns(), row, predicate)? {
            rows.push(row.clone());
        }
    }

    cancellation.check()?;
    VectorBatch::new(batch.columns().to_vec(), rows)
}

struct InSubqueryValues {
    values: HashSet<SqlValue>,
    has_null: bool,
}

fn scalar_subquery_value(batch: &VectorBatch) -> Result<SqlValue> {
    if batch.columns().len() != 1 {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "scalar subquery expected one column, got {}",
                batch.columns().len()
            ),
        ));
    }
    match batch.rows() {
        [] => Ok(SqlValue::Null),
        [row] => Ok(row.values()[0].clone()),
        rows => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("scalar subquery returned more than one row: {}", rows.len()),
        )),
    }
}

fn apply_in_subquery_filter_cancellable(
    batch: VectorBatch,
    subquery: VectorBatch,
    expr: &Expr,
    negated: bool,
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    let values = collect_in_subquery_values(&subquery, cancellation)?;
    let mut rows = Vec::new();
    for row in batch.rows() {
        cancellation.check()?;
        if in_subquery_keeps_row(batch.columns(), row, expr, &values, negated)? {
            rows.push(row.clone());
        }
    }
    VectorBatch::new(batch.columns().to_vec(), rows)
}

fn collect_in_subquery_values(
    batch: &VectorBatch,
    cancellation: &CancellationToken,
) -> Result<InSubqueryValues> {
    if batch.columns().len() != 1 {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "IN subquery execution expected one column, got {}",
                batch.columns().len()
            ),
        ));
    }
    let mut values = HashSet::with_capacity(batch.rows().len());
    let mut has_null = false;
    for row in batch.rows() {
        cancellation.check()?;
        let value = row.values()[0].clone();
        if value.is_null() {
            has_null = true;
        } else {
            values.insert(value);
        }
    }
    Ok(InSubqueryValues { values, has_null })
}

fn in_subquery_keeps_row(
    columns: &[ColumnSchema],
    row: &Row,
    expr: &Expr,
    values: &InSubqueryValues,
    negated: bool,
) -> Result<bool> {
    Ok(matches!(
        in_subquery_value(columns, row, expr, values, negated)?,
        SqlValue::Bool(true)
    ))
}

fn in_subquery_value(
    columns: &[ColumnSchema],
    row: &Row,
    expr: &Expr,
    values: &InSubqueryValues,
    negated: bool,
) -> Result<SqlValue> {
    let value = eval_expr(columns, row, expr)?;
    if value.is_null() {
        return Ok(SqlValue::Null);
    }
    let matched = values.values.contains(&value);
    Ok(match (matched, values.has_null, negated) {
        (true, _, false) => SqlValue::Bool(true),
        (true, _, true) => SqlValue::Bool(false),
        (false, true, _) => SqlValue::Null,
        (false, false, false) => SqlValue::Bool(false),
        (false, false, true) => SqlValue::Bool(true),
    })
}

fn apply_exists_subquery_filter(
    batch: VectorBatch,
    subquery: &VectorBatch,
    negated: bool,
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    cancellation.check()?;
    if exists_subquery_keeps_row(subquery, negated) {
        Ok(batch)
    } else {
        VectorBatch::new(batch.columns().to_vec(), Vec::new())
    }
}

fn exists_subquery_keeps_row(subquery: &VectorBatch, negated: bool) -> bool {
    subquery.rows().is_empty() == negated
}

fn logical_plan_has_qualified_identifier(plan: &LogicalPlan) -> bool {
    match plan {
        LogicalPlan::Filter { predicate, input } => {
            expr_contains_qualified_identifier(predicate)
                || logical_plan_has_qualified_identifier(input)
        }
        LogicalPlan::Project { items, input } => {
            items
                .iter()
                .any(|item| expr_contains_qualified_identifier(&item.expr))
                || logical_plan_has_qualified_identifier(input)
        }
        LogicalPlan::Sort { keys, input } => {
            keys.iter()
                .any(|key| expr_contains_qualified_identifier(&key.expr))
                || logical_plan_has_qualified_identifier(input)
        }
        LogicalPlan::Limit { input, .. }
        | LogicalPlan::Offset { input, .. }
        | LogicalPlan::Distinct { input }
        | LogicalPlan::Parallel { input, .. }
        | LogicalPlan::Explain { input, .. } => logical_plan_has_qualified_identifier(input),
        _ => false,
    }
}

fn physical_plan_has_qualified_identifier(plan: &PhysicalPlan) -> bool {
    physical_local_expr_has_qualified_identifier(plan)
        || physical_child_has_qualified_identifier(plan)
}

fn physical_local_expr_has_qualified_identifier(plan: &PhysicalPlan) -> bool {
    match plan {
        PhysicalPlan::IndexScan { value, .. }
        | PhysicalPlan::IndexSkipScan { value, .. }
        | PhysicalPlan::RangeOverlapScan { range: value, .. }
        | PhysicalPlan::BoundsOverlapScan { bounds: value, .. } => {
            expr_contains_qualified_identifier(value)
        }
        PhysicalPlan::ExpressionIndexScan { expr, value, .. } => {
            expr_contains_qualified_identifier(expr) || expr_contains_qualified_identifier(value)
        }
        PhysicalPlan::IndexRangeScan { lower, upper, .. } => {
            optional_expr_contains_qualified_identifier(lower)
                || optional_expr_contains_qualified_identifier(upper)
        }
        PhysicalPlan::BlockSummaryScan { lower, upper, .. } => {
            expr_contains_qualified_identifier(lower) || expr_contains_qualified_identifier(upper)
        }
        PhysicalPlan::NestedLoopJoin { predicate, .. }
        | PhysicalPlan::Filter { predicate, .. }
        | PhysicalPlan::InSubqueryFilter {
            expr: predicate, ..
        } => expr_contains_qualified_identifier(predicate),
        PhysicalPlan::Projection { items, .. } => projection_has_qualified_identifier(items),
        PhysicalPlan::Sort { keys, .. } => order_by_has_qualified_identifier(keys),
        _ => false,
    }
}

fn physical_child_has_qualified_identifier(plan: &PhysicalPlan) -> bool {
    match plan {
        PhysicalPlan::SidewaysIndexLookup { outer, .. }
        | PhysicalPlan::Filter { input: outer, .. }
        | PhysicalPlan::Projection { input: outer, .. }
        | PhysicalPlan::Sort { input: outer, .. }
        | PhysicalPlan::Limit { input: outer, .. }
        | PhysicalPlan::Offset { input: outer, .. }
        | PhysicalPlan::Distinct { input: outer, .. }
        | PhysicalPlan::Parallel { input: outer, .. }
        | PhysicalPlan::Explain { input: outer, .. } => {
            physical_plan_has_qualified_identifier(outer)
        }
        PhysicalPlan::NestedLoopJoin { left, right, .. }
        | PhysicalPlan::SetOperation { left, right, .. } => {
            physical_plan_has_qualified_identifier(left)
                || physical_plan_has_qualified_identifier(right)
        }
        PhysicalPlan::InSubqueryFilter {
            input, subquery, ..
        }
        | PhysicalPlan::ExistsSubqueryFilter {
            input, subquery, ..
        } => {
            physical_plan_has_qualified_identifier(input)
                || physical_plan_has_qualified_identifier(subquery)
        }
        _ => false,
    }
}

fn optional_expr_contains_qualified_identifier(expr: &Option<Expr>) -> bool {
    expr.as_ref()
        .is_some_and(expr_contains_qualified_identifier)
}

fn projection_has_qualified_identifier(items: &[ProjectionItem]) -> bool {
    items
        .iter()
        .any(|item| expr_contains_qualified_identifier(&item.expr))
}

fn order_by_has_qualified_identifier(keys: &[OrderByExpr]) -> bool {
    keys.iter()
        .any(|key| expr_contains_qualified_identifier(&key.expr))
}

fn replace_logical_outer_refs(
    plan: &LogicalPlan,
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<LogicalPlan> {
    match plan {
        LogicalPlan::Filter { .. } => replace_filter_outer_refs(plan, columns, row),
        LogicalPlan::Project { .. } => replace_project_outer_refs(plan, columns, row),
        LogicalPlan::Sort { .. } => replace_sort_outer_refs(plan, columns, row),
        _ => replace_input_only_outer_refs(plan, columns, row),
    }
}

fn replace_filter_outer_refs(
    plan: &LogicalPlan,
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<LogicalPlan> {
    let LogicalPlan::Filter { predicate, input } = plan else {
        unreachable!("replace_filter_outer_refs only accepts filter plans")
    };
    Ok(LogicalPlan::Filter {
        predicate: replace_outer_refs_expr(predicate, columns, row)?,
        input: Box::new(replace_logical_outer_refs(input, columns, row)?),
    })
}

fn replace_project_outer_refs(
    plan: &LogicalPlan,
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<LogicalPlan> {
    let LogicalPlan::Project { items, input } = plan else {
        unreachable!("replace_project_outer_refs only accepts project plans")
    };
    Ok(LogicalPlan::Project {
        items: replace_projection_outer_refs(items, columns, row)?,
        input: Box::new(replace_logical_outer_refs(input, columns, row)?),
    })
}

fn replace_sort_outer_refs(
    plan: &LogicalPlan,
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<LogicalPlan> {
    let LogicalPlan::Sort { keys, input } = plan else {
        unreachable!("replace_sort_outer_refs only accepts sort plans")
    };
    Ok(LogicalPlan::Sort {
        keys: replace_order_by_outer_refs(keys, columns, row)?,
        input: Box::new(replace_logical_outer_refs(input, columns, row)?),
    })
}

fn replace_input_only_outer_refs(
    plan: &LogicalPlan,
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<LogicalPlan> {
    match plan {
        LogicalPlan::Limit { count, input } => Ok(LogicalPlan::Limit {
            count: *count,
            input: Box::new(replace_logical_outer_refs(input, columns, row)?),
        }),
        LogicalPlan::Offset { count, input } => Ok(LogicalPlan::Offset {
            count: *count,
            input: Box::new(replace_logical_outer_refs(input, columns, row)?),
        }),
        LogicalPlan::Distinct { input } => Ok(LogicalPlan::Distinct {
            input: Box::new(replace_logical_outer_refs(input, columns, row)?),
        }),
        LogicalPlan::Parallel { hint, input } => Ok(LogicalPlan::Parallel {
            hint: hint.clone(),
            input: Box::new(replace_logical_outer_refs(input, columns, row)?),
        }),
        LogicalPlan::Explain {
            analyze,
            format,
            input,
        } => Ok(LogicalPlan::Explain {
            analyze: *analyze,
            format: *format,
            input: Box::new(replace_logical_outer_refs(input, columns, row)?),
        }),
        _ => Ok(plan.clone()),
    }
}

fn replace_physical_outer_refs(
    plan: &PhysicalPlan,
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<PhysicalPlan> {
    match plan {
        PhysicalPlan::Filter { .. } => replace_physical_filter_outer_refs(plan, columns, row),
        PhysicalPlan::Projection { .. } => {
            replace_physical_projection_outer_refs(plan, columns, row)
        }
        PhysicalPlan::Sort { .. } => replace_physical_sort_outer_refs(plan, columns, row),
        PhysicalPlan::NestedLoopJoin { .. } => {
            replace_physical_nested_join_outer_refs(plan, columns, row)
        }
        PhysicalPlan::InSubqueryFilter { .. } => {
            replace_physical_in_filter_outer_refs(plan, columns, row)
        }
        PhysicalPlan::ExistsSubqueryFilter { .. } => {
            replace_physical_exists_filter_outer_refs(plan, columns, row)
        }
        PhysicalPlan::SetOperation { .. } => {
            replace_physical_set_operation_outer_refs(plan, columns, row)
        }
        _ => replace_physical_unary_or_leaf_outer_refs(plan, columns, row),
    }
}

fn replace_physical_filter_outer_refs(
    plan: &PhysicalPlan,
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<PhysicalPlan> {
    let PhysicalPlan::Filter {
        predicate,
        input,
        cost,
    } = plan
    else {
        unreachable!("replace_physical_filter_outer_refs only accepts filter plans")
    };
    Ok(PhysicalPlan::Filter {
        predicate: replace_outer_refs_expr(predicate, columns, row)?,
        input: Box::new(replace_physical_outer_refs(input, columns, row)?),
        cost: *cost,
    })
}

fn replace_physical_projection_outer_refs(
    plan: &PhysicalPlan,
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<PhysicalPlan> {
    let PhysicalPlan::Projection { items, input, cost } = plan else {
        unreachable!("replace_physical_projection_outer_refs only accepts projection plans")
    };
    Ok(PhysicalPlan::Projection {
        items: replace_projection_outer_refs(items, columns, row)?,
        input: Box::new(replace_physical_outer_refs(input, columns, row)?),
        cost: *cost,
    })
}

fn replace_physical_sort_outer_refs(
    plan: &PhysicalPlan,
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<PhysicalPlan> {
    let PhysicalPlan::Sort { keys, input, cost } = plan else {
        unreachable!("replace_physical_sort_outer_refs only accepts sort plans")
    };
    Ok(PhysicalPlan::Sort {
        keys: replace_order_by_outer_refs(keys, columns, row)?,
        input: Box::new(replace_physical_outer_refs(input, columns, row)?),
        cost: *cost,
    })
}

fn replace_physical_nested_join_outer_refs(
    plan: &PhysicalPlan,
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<PhysicalPlan> {
    let PhysicalPlan::NestedLoopJoin {
        kind,
        left,
        right,
        predicate,
        cost,
    } = plan
    else {
        unreachable!("replace_physical_nested_join_outer_refs only accepts nested join plans")
    };
    Ok(PhysicalPlan::NestedLoopJoin {
        kind: *kind,
        left: Box::new(replace_physical_outer_refs(left, columns, row)?),
        right: Box::new(replace_physical_outer_refs(right, columns, row)?),
        predicate: replace_outer_refs_expr(predicate, columns, row)?,
        cost: *cost,
    })
}

fn replace_physical_in_filter_outer_refs(
    plan: &PhysicalPlan,
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<PhysicalPlan> {
    let PhysicalPlan::InSubqueryFilter {
        expr,
        subquery,
        negated,
        input,
        cost,
    } = plan
    else {
        unreachable!("replace_physical_in_filter_outer_refs only accepts IN filters")
    };
    Ok(PhysicalPlan::InSubqueryFilter {
        expr: replace_outer_refs_expr(expr, columns, row)?,
        subquery: Box::new(replace_physical_outer_refs(subquery, columns, row)?),
        negated: *negated,
        input: Box::new(replace_physical_outer_refs(input, columns, row)?),
        cost: *cost,
    })
}

fn replace_physical_exists_filter_outer_refs(
    plan: &PhysicalPlan,
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<PhysicalPlan> {
    let PhysicalPlan::ExistsSubqueryFilter {
        subquery,
        negated,
        input,
        cost,
    } = plan
    else {
        unreachable!("replace_physical_exists_filter_outer_refs only accepts EXISTS filters")
    };
    Ok(PhysicalPlan::ExistsSubqueryFilter {
        subquery: Box::new(replace_physical_outer_refs(subquery, columns, row)?),
        negated: *negated,
        input: Box::new(replace_physical_outer_refs(input, columns, row)?),
        cost: *cost,
    })
}

fn replace_physical_set_operation_outer_refs(
    plan: &PhysicalPlan,
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<PhysicalPlan> {
    let PhysicalPlan::SetOperation {
        kind,
        all,
        left,
        right,
        cost,
    } = plan
    else {
        unreachable!("replace_physical_set_operation_outer_refs only accepts set operations")
    };
    Ok(PhysicalPlan::SetOperation {
        kind: *kind,
        all: *all,
        left: Box::new(replace_physical_outer_refs(left, columns, row)?),
        right: Box::new(replace_physical_outer_refs(right, columns, row)?),
        cost: *cost,
    })
}

fn replace_physical_unary_or_leaf_outer_refs(
    plan: &PhysicalPlan,
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<PhysicalPlan> {
    match plan {
        PhysicalPlan::Limit { count, input, cost } => Ok(PhysicalPlan::Limit {
            count: *count,
            input: Box::new(replace_physical_outer_refs(input, columns, row)?),
            cost: *cost,
        }),
        PhysicalPlan::Offset { count, input, cost } => Ok(PhysicalPlan::Offset {
            count: *count,
            input: Box::new(replace_physical_outer_refs(input, columns, row)?),
            cost: *cost,
        }),
        PhysicalPlan::Distinct { input, cost } => Ok(PhysicalPlan::Distinct {
            input: Box::new(replace_physical_outer_refs(input, columns, row)?),
            cost: *cost,
        }),
        PhysicalPlan::Parallel { hint, input, cost } => Ok(PhysicalPlan::Parallel {
            hint: hint.clone(),
            input: Box::new(replace_physical_outer_refs(input, columns, row)?),
            cost: *cost,
        }),
        PhysicalPlan::Explain {
            analyze,
            format,
            input,
            cost,
        } => Ok(PhysicalPlan::Explain {
            analyze: *analyze,
            format: *format,
            input: Box::new(replace_physical_outer_refs(input, columns, row)?),
            cost: *cost,
        }),
        _ => replace_physical_leaf_outer_refs(plan, columns, row),
    }
}

fn replace_physical_leaf_outer_refs(
    plan: &PhysicalPlan,
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<PhysicalPlan> {
    match plan {
        PhysicalPlan::IndexScan { .. }
        | PhysicalPlan::ExpressionIndexScan { .. }
        | PhysicalPlan::IndexRangeScan { .. }
        | PhysicalPlan::IndexSkipScan { .. }
        | PhysicalPlan::BlockSummaryScan { .. }
        | PhysicalPlan::RangeOverlapScan { .. }
        | PhysicalPlan::BoundsOverlapScan { .. } => {
            replace_physical_scan_expr_outer_refs(plan, columns, row)
        }
        _ => Ok(plan.clone()),
    }
}

fn replace_physical_scan_expr_outer_refs(
    plan: &PhysicalPlan,
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<PhysicalPlan> {
    match plan {
        PhysicalPlan::IndexScan {
            relation_id,
            table,
            index,
            column,
            value,
            cost,
        } => Ok(PhysicalPlan::IndexScan {
            relation_id: *relation_id,
            table: table.clone(),
            index: index.clone(),
            column: column.clone(),
            value: replace_outer_refs_expr(value, columns, row)?,
            cost: *cost,
        }),
        PhysicalPlan::ExpressionIndexScan {
            relation_id,
            table,
            index,
            expr,
            value,
            cost,
        } => Ok(PhysicalPlan::ExpressionIndexScan {
            relation_id: *relation_id,
            table: table.clone(),
            index: index.clone(),
            expr: replace_outer_refs_expr(expr, columns, row)?,
            value: replace_outer_refs_expr(value, columns, row)?,
            cost: *cost,
        }),
        _ => replace_physical_range_scan_outer_refs(plan, columns, row),
    }
}

fn replace_physical_range_scan_outer_refs(
    plan: &PhysicalPlan,
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<PhysicalPlan> {
    match plan {
        PhysicalPlan::IndexRangeScan {
            relation_id,
            table,
            index,
            column,
            lower,
            lower_inclusive,
            upper,
            upper_inclusive,
            cost,
        } => Ok(PhysicalPlan::IndexRangeScan {
            relation_id: *relation_id,
            table: table.clone(),
            index: index.clone(),
            column: column.clone(),
            lower: replace_optional_outer_refs(lower, columns, row)?,
            lower_inclusive: *lower_inclusive,
            upper: replace_optional_outer_refs(upper, columns, row)?,
            upper_inclusive: *upper_inclusive,
            cost: *cost,
        }),
        PhysicalPlan::IndexSkipScan {
            relation_id,
            table,
            index,
            column,
            value,
            cost,
        } => Ok(PhysicalPlan::IndexSkipScan {
            relation_id: *relation_id,
            table: table.clone(),
            index: index.clone(),
            column: column.clone(),
            value: replace_outer_refs_expr(value, columns, row)?,
            cost: *cost,
        }),
        _ => replace_physical_overlap_scan_outer_refs(plan, columns, row),
    }
}

fn replace_physical_overlap_scan_outer_refs(
    plan: &PhysicalPlan,
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<PhysicalPlan> {
    match plan {
        PhysicalPlan::BlockSummaryScan {
            relation_id,
            table,
            index,
            column,
            lower,
            lower_inclusive,
            upper,
            upper_inclusive,
            cost,
        } => Ok(PhysicalPlan::BlockSummaryScan {
            relation_id: *relation_id,
            table: table.clone(),
            index: index.clone(),
            column: column.clone(),
            lower: replace_outer_refs_expr(lower, columns, row)?,
            lower_inclusive: *lower_inclusive,
            upper: replace_outer_refs_expr(upper, columns, row)?,
            upper_inclusive: *upper_inclusive,
            cost: *cost,
        }),
        PhysicalPlan::RangeOverlapScan {
            relation_id,
            table,
            index,
            column,
            range,
            cost,
        } => Ok(PhysicalPlan::RangeOverlapScan {
            relation_id: *relation_id,
            table: table.clone(),
            index: index.clone(),
            column: column.clone(),
            range: replace_outer_refs_expr(range, columns, row)?,
            cost: *cost,
        }),
        PhysicalPlan::BoundsOverlapScan {
            relation_id,
            table,
            index,
            column,
            bounds,
            cost,
        } => Ok(PhysicalPlan::BoundsOverlapScan {
            relation_id: *relation_id,
            table: table.clone(),
            index: index.clone(),
            column: column.clone(),
            bounds: replace_outer_refs_expr(bounds, columns, row)?,
            cost: *cost,
        }),
        _ => Ok(plan.clone()),
    }
}

fn replace_optional_outer_refs(
    expr: &Option<Expr>,
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<Option<Expr>> {
    expr.as_ref()
        .map(|expr| replace_outer_refs_expr(expr, columns, row))
        .transpose()
}

fn replace_projection_outer_refs(
    items: &[ProjectionItem],
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<Vec<ProjectionItem>> {
    items
        .iter()
        .map(|item| {
            Ok(ProjectionItem {
                name: item.name.clone(),
                expr: replace_outer_refs_expr(&item.expr, columns, row)?,
            })
        })
        .collect()
}

fn replace_order_by_outer_refs(
    keys: &[OrderByExpr],
    columns: &[ColumnSchema],
    row: &Row,
) -> Result<Vec<OrderByExpr>> {
    keys.iter()
        .map(|key| {
            Ok(OrderByExpr {
                expr: replace_outer_refs_expr(&key.expr, columns, row)?,
                direction: key.direction,
            })
        })
        .collect()
}

fn expr_contains_qualified_identifier(expr: &Expr) -> bool {
    match expr {
        Expr::QualifiedIdentifier { .. } => true,
        Expr::Binary { left, right, .. } => {
            expr_contains_qualified_identifier(left) || expr_contains_qualified_identifier(right)
        }
        Expr::Unary { expr, .. } | Expr::Not(expr) | Expr::Cast { expr, .. } => {
            expr_contains_qualified_identifier(expr)
        }
        _ => false,
    }
}

fn replace_outer_refs_expr(expr: &Expr, columns: &[ColumnSchema], row: &Row) -> Result<Expr> {
    match expr {
        Expr::QualifiedIdentifier { name, .. } => {
            outer_runtime_value(columns, row, name.as_str()).map(Expr::RuntimeValue)
        }
        Expr::Binary { left, op, right } => Ok(Expr::Binary {
            left: Box::new(replace_outer_refs_expr(left, columns, row)?),
            op: op.clone(),
            right: Box::new(replace_outer_refs_expr(right, columns, row)?),
        }),
        Expr::Unary { op, expr } => Ok(Expr::Unary {
            op: op.clone(),
            expr: Box::new(replace_outer_refs_expr(expr, columns, row)?),
        }),
        Expr::Not(expr) => Ok(Expr::Not(Box::new(replace_outer_refs_expr(
            expr, columns, row,
        )?))),
        Expr::Cast { expr, data_type } => Ok(Expr::Cast {
            expr: Box::new(replace_outer_refs_expr(expr, columns, row)?),
            data_type: data_type.clone(),
        }),
        _ => Ok(expr.clone()),
    }
}

fn outer_runtime_value(columns: &[ColumnSchema], row: &Row, name: &str) -> Result<SqlValue> {
    let index = column_index(columns, name)?;
    Ok(row.values()[index].clone())
}

fn apply_nested_loop_join_cancellable(
    left: VectorBatch,
    right: VectorBatch,
    kind: JoinKind,
    predicate: &Expr,
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    let columns = joined_columns_for_join(left.columns(), right.columns(), kind)?;
    let null_right = null_row(right.columns());
    let mut rows = Vec::new();
    for left_row in left.rows() {
        cancellation.check()?;
        let matched = push_matching_join_rows(
            &columns,
            left_row,
            &right,
            predicate,
            &mut rows,
            cancellation,
        )?;
        if kind == JoinKind::Left && !matched {
            rows.push(join_rows(left_row, &null_right));
        }
    }
    VectorBatch::new(columns, rows)
}

fn push_matching_join_rows(
    columns: &[ColumnSchema],
    left_row: &Row,
    right: &VectorBatch,
    predicate: &Expr,
    rows: &mut Vec<Row>,
    cancellation: &CancellationToken,
) -> Result<bool> {
    let mut matched = false;
    for right_row in right.rows() {
        cancellation.check()?;
        let row = join_rows(left_row, right_row);
        if eval_predicate(columns, &row, predicate)? {
            rows.push(row);
            matched = true;
        }
    }
    Ok(matched)
}

fn join_rows(left: &Row, right: &Row) -> Row {
    let mut values = Vec::with_capacity(left.values().len() + right.values().len());
    values.extend_from_slice(left.values());
    values.extend_from_slice(right.values());
    Row::new(values)
}

fn null_row(columns: &[ColumnSchema]) -> Row {
    Row::new(vec![SqlValue::Null; columns.len()])
}

fn apply_projection_cancellable(
    batch: VectorBatch,
    items: &[rnmdb_planner::logical::ProjectionItem],
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    let columns = projection_columns(batch.columns(), items)?;
    let mut rows = Vec::with_capacity(batch.rows().len());
    for row in batch.rows() {
        cancellation.check()?;
        let values = items
            .iter()
            .map(|item| eval_expr(batch.columns(), row, &item.expr))
            .collect::<Result<Vec<_>>>()?;
        rows.push(Row::new(values));
    }

    cancellation.check()?;
    VectorBatch::new(columns, rows)
}

fn projection_columns(
    columns: &[ColumnSchema],
    items: &[ProjectionItem],
) -> Result<Vec<ColumnSchema>> {
    items
        .iter()
        .map(|item| {
            projection_type(columns, &item.expr)
                .map(|data_type| ColumnSchema::new(item.name.as_str(), data_type))
        })
        .collect()
}

fn apply_window_cancellable(
    batch: VectorBatch,
    items: &[WindowItem],
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    if items.is_empty() {
        return Ok(batch);
    }

    let mut columns = batch.columns().to_vec();
    let mut item_values = Vec::with_capacity(items.len());
    for item in items {
        cancellation.check()?;
        columns.push(window_column_schema(item));
        item_values.push(window_values(&batch, &item.function, cancellation)?);
    }

    let mut rows = Vec::with_capacity(batch.rows().len());
    for row_index in 0..batch.rows().len() {
        cancellation.check()?;
        let mut values = batch.rows()[row_index].values().to_vec();
        for values_by_item in &item_values {
            values.push(values_by_item[row_index].clone());
        }
        rows.push(Row::new(values));
    }

    cancellation.check()?;
    VectorBatch::new(columns, rows)
}

fn window_column_schema(item: &WindowItem) -> ColumnSchema {
    match item.function {
        WindowFunction::RowNumber { .. }
        | WindowFunction::Rank { .. }
        | WindowFunction::DenseRank { .. } => {
            ColumnSchema::new(item.name.as_str(), SqlType::Int64).not_null()
        }
    }
}

fn window_values(
    batch: &VectorBatch,
    function: &WindowFunction,
    cancellation: &CancellationToken,
) -> Result<Vec<SqlValue>> {
    match function {
        WindowFunction::RowNumber { order_by } => {
            row_number_window_values(batch, order_by, cancellation)
        }
        WindowFunction::Rank { order_by } => {
            ranking_window_values(batch, order_by, RankingMode::Rank, cancellation)
        }
        WindowFunction::DenseRank { order_by } => {
            ranking_window_values(batch, order_by, RankingMode::DenseRank, cancellation)
        }
    }
}

fn row_number_window_values(
    batch: &VectorBatch,
    order_by: &[OrderByExpr],
    cancellation: &CancellationToken,
) -> Result<Vec<SqlValue>> {
    if order_by.is_empty() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "row_number() OVER requires ORDER BY",
        ));
    }

    let mut rows = sort_rows(batch, order_by, cancellation)?;
    rows.sort_by(|left, right| compare_sort_rows(left, right, order_by));

    let mut values = vec![SqlValue::Null; batch.rows().len()];
    for (ordinal, row) in rows.iter().enumerate() {
        cancellation.check()?;
        let row_number = i64::try_from(ordinal + 1).map_err(|_| {
            RnovError::new(ErrorKind::InvalidInput, "row_number() result exceeds int64")
        })?;
        values[row.original_index] = SqlValue::Int64(row_number);
    }
    Ok(values)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RankingMode {
    Rank,
    DenseRank,
}

fn ranking_window_values(
    batch: &VectorBatch,
    order_by: &[OrderByExpr],
    mode: RankingMode,
    cancellation: &CancellationToken,
) -> Result<Vec<SqlValue>> {
    if order_by.is_empty() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "ranking window functions require ORDER BY",
        ));
    }

    let mut rows = sort_rows(batch, order_by, cancellation)?;
    rows.sort_by(|left, right| compare_sort_rows(left, right, order_by));

    let mut values = vec![SqlValue::Null; batch.rows().len()];
    let mut current_rank = 0_i64;
    let mut dense_rank = 0_i64;
    for index in 0..rows.len() {
        cancellation.check()?;
        if index == 0
            || compare_sort_row_keys(&rows[index - 1], &rows[index], order_by) != Ordering::Equal
        {
            current_rank = i64::try_from(index + 1).map_err(|_| {
                RnovError::new(ErrorKind::InvalidInput, "rank() result exceeds int64")
            })?;
            dense_rank = dense_rank.checked_add(1).ok_or_else(|| {
                RnovError::new(ErrorKind::InvalidInput, "dense_rank() result exceeds int64")
            })?;
        }
        let value = match mode {
            RankingMode::Rank => current_rank,
            RankingMode::DenseRank => dense_rank,
        };
        values[rows[index].original_index] = SqlValue::Int64(value);
    }
    Ok(values)
}

fn joined_columns(outer: &[ColumnSchema], inner: &[ColumnSchema]) -> Result<Vec<ColumnSchema>> {
    joined_columns_with_inner_nullable(outer, inner, false)
}

fn joined_columns_for_join(
    outer: &[ColumnSchema],
    inner: &[ColumnSchema],
    kind: JoinKind,
) -> Result<Vec<ColumnSchema>> {
    joined_columns_with_inner_nullable(outer, inner, kind == JoinKind::Left)
}

fn joined_columns_with_inner_nullable(
    outer: &[ColumnSchema],
    inner: &[ColumnSchema],
    force_inner_nullable: bool,
) -> Result<Vec<ColumnSchema>> {
    let mut columns = outer.to_vec();
    for column in inner {
        let mut name = column.name().to_string();
        while columns.iter().any(|existing| existing.name() == name) {
            name = format!("inner_{name}");
        }
        columns.push(column_schema_like(
            column,
            name,
            force_inner_nullable || column.nullable(),
        ));
    }
    let _ = VectorBatch::new(columns.clone(), Vec::new())?;
    Ok(columns)
}

fn column_schema_like(column: &ColumnSchema, name: String, nullable: bool) -> ColumnSchema {
    let mut schema = ColumnSchema::new(name, column.data_type().clone());
    if !nullable {
        schema = schema.not_null();
    }
    if column.is_encrypted() {
        schema = schema.encrypted();
    }
    if let Some(generated) = column.generated() {
        schema = schema.with_generated(generated.clone());
    }
    schema
}

fn apply_aggregate_cancellable(
    batch: VectorBatch,
    items: &[AggregateItem],
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    cancellation.check()?;
    let columns = items
        .iter()
        .map(|item| aggregate_column_schema(&batch, item))
        .collect::<Result<Vec<_>>>()?;
    let values = items
        .iter()
        .map(|item| aggregate_value(&batch, &item.function))
        .collect::<Result<Vec<_>>>()?;
    cancellation.check()?;
    VectorBatch::new(columns, vec![Row::new(values)])
}

fn apply_grouped_aggregate_cancellable(
    batch: VectorBatch,
    group_by: &[Expr],
    items: &[GroupedAggregateItem],
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    cancellation.check()?;
    let columns = items
        .iter()
        .map(|item| grouped_aggregate_column_schema(&batch, item))
        .collect::<Result<Vec<_>>>()?;
    let groups = group_states_from_rows(batch.columns(), batch.rows(), group_by, cancellation)?;
    grouped_aggregate_batch(batch.columns(), columns, groups, items, cancellation)
}

fn apply_grouped_aggregate_parallel_cancellable(
    batch: VectorBatch,
    group_by: &[Expr],
    items: &[GroupedAggregateItem],
    config: ParallelQueryConfig,
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    config.validate()?;
    cancellation.check()?;
    if batch.rows().is_empty()
        || config.worker_threads() == 1
        || batch.rows().len() < config.min_parallel_rows()
    {
        return apply_grouped_aggregate_cancellable(batch, group_by, items, cancellation);
    }

    let output_columns = items
        .iter()
        .map(|item| grouped_aggregate_column_schema(&batch, item))
        .collect::<Result<Vec<_>>>()?;
    let input_columns = batch.columns();
    let input_rows = batch.rows();
    let worker_count = config.worker_threads().min(input_rows.len());
    let chunk_size = input_rows.len().div_ceil(worker_count);
    let mut groups: Vec<GroupState> = Vec::new();

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        for chunk in input_rows.chunks(chunk_size) {
            let cancellation = cancellation.clone();
            handles.push(scope.spawn(move || {
                group_states_from_rows(input_columns, chunk, group_by, &cancellation)
            }));
        }

        for handle in handles {
            let local_groups = handle.join().map_err(|_| {
                RnovError::new(
                    ErrorKind::Internal,
                    "parallel grouped aggregate worker panicked",
                )
            })??;
            merge_group_states(&mut groups, local_groups);
        }
        Ok::<(), RnovError>(())
    })?;

    grouped_aggregate_batch(input_columns, output_columns, groups, items, cancellation)
}

fn group_states_from_rows(
    columns: &[ColumnSchema],
    rows: &[Row],
    group_by: &[Expr],
    cancellation: &CancellationToken,
) -> Result<Vec<GroupState>> {
    let mut groups: Vec<GroupState> = Vec::new();
    let mut group_indexes: HashMap<Vec<SqlValue>, usize> = HashMap::new();
    for row in rows {
        cancellation.check()?;
        let key = group_by
            .iter()
            .map(|expr| eval_expr(columns, row, expr))
            .collect::<Result<Vec<_>>>()?;
        if let Some(index) = group_indexes.get(&key).copied() {
            groups[index].rows.push(row.clone());
        } else {
            let index = groups.len();
            group_indexes.insert(key.clone(), index);
            groups.push(GroupState {
                key,
                rows: vec![row.clone()],
            });
        }
    }
    Ok(groups)
}

fn merge_group_states(groups: &mut Vec<GroupState>, local_groups: Vec<GroupState>) {
    let mut group_indexes = groups
        .iter()
        .enumerate()
        .map(|(index, group)| (group.key.clone(), index))
        .collect::<HashMap<_, _>>();
    for local_group in local_groups {
        if let Some(index) = group_indexes.get(&local_group.key).copied() {
            groups[index].rows.extend(local_group.rows);
        } else {
            group_indexes.insert(local_group.key.clone(), groups.len());
            groups.push(local_group);
        }
    }
}

fn grouped_aggregate_batch(
    input_columns: &[ColumnSchema],
    output_columns: Vec<ColumnSchema>,
    groups: Vec<GroupState>,
    items: &[GroupedAggregateItem],
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    let mut rows = Vec::with_capacity(groups.len());
    for group in groups {
        cancellation.check()?;
        let group_batch = VectorBatch::new(input_columns.to_vec(), group.rows)?;
        let values = items
            .iter()
            .map(|item| grouped_aggregate_value(&group_batch, item))
            .collect::<Result<Vec<_>>>()?;
        rows.push(Row::new(values));
    }
    cancellation.check()?;
    VectorBatch::new(output_columns, rows)
}

fn apply_grouping_sets_aggregate_cancellable(
    batch: VectorBatch,
    group_by: &[Expr],
    grouping_sets: &[Vec<Expr>],
    items: &[GroupedAggregateItem],
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    cancellation.check()?;
    let columns = items
        .iter()
        .map(|item| grouped_aggregate_column_schema(&batch, item))
        .collect::<Result<Vec<_>>>()?;
    let mut rows = Vec::new();
    for grouping_set in grouping_sets {
        cancellation.check()?;
        let groups = grouping_set_states(&batch, grouping_set, cancellation)?;
        for group in groups {
            cancellation.check()?;
            let group_batch = VectorBatch::new(batch.columns().to_vec(), group.rows)?;
            let values = items
                .iter()
                .map(|item| {
                    grouping_set_aggregate_value(&group_batch, group_by, grouping_set, item)
                })
                .collect::<Result<Vec<_>>>()?;
            rows.push(Row::new(values));
        }
    }
    cancellation.check()?;
    VectorBatch::new(columns, rows)
}

fn grouping_set_states(
    batch: &VectorBatch,
    grouping_set: &[Expr],
    cancellation: &CancellationToken,
) -> Result<Vec<GroupState>> {
    let mut groups: Vec<GroupState> = Vec::new();
    let mut group_indexes: HashMap<Vec<SqlValue>, usize> = HashMap::new();
    for row in batch.rows() {
        cancellation.check()?;
        let key = grouping_set
            .iter()
            .map(|expr| eval_expr(batch.columns(), row, expr))
            .collect::<Result<Vec<_>>>()?;
        if let Some(index) = group_indexes.get(&key).copied() {
            groups[index].rows.push(row.clone());
        } else {
            let index = groups.len();
            group_indexes.insert(key.clone(), index);
            groups.push(GroupState {
                key,
                rows: vec![row.clone()],
            });
        }
    }
    if groups.is_empty() && grouping_set.is_empty() {
        groups.push(GroupState {
            key: Vec::new(),
            rows: Vec::new(),
        });
    }
    Ok(groups)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GroupState {
    key: Vec<SqlValue>,
    rows: Vec<Row>,
}

fn grouped_aggregate_column_schema(
    batch: &VectorBatch,
    item: &GroupedAggregateItem,
) -> Result<ColumnSchema> {
    match &item.kind {
        GroupedAggregateItemKind::GroupKey(expr) => Ok(ColumnSchema::new(
            item.name.as_str(),
            projection_type(batch.columns(), expr)?,
        )),
        GroupedAggregateItemKind::Aggregate(function) => aggregate_column_schema(
            batch,
            &AggregateItem {
                name: item.name.clone(),
                function: function.clone(),
            },
        ),
    }
}

fn grouped_aggregate_value(batch: &VectorBatch, item: &GroupedAggregateItem) -> Result<SqlValue> {
    match &item.kind {
        GroupedAggregateItemKind::GroupKey(expr) => {
            let Some(row) = batch.rows().first() else {
                return Ok(SqlValue::Null);
            };
            eval_expr(batch.columns(), row, expr)
        }
        GroupedAggregateItemKind::Aggregate(function) => aggregate_value(batch, function),
    }
}

fn grouping_set_aggregate_value(
    batch: &VectorBatch,
    group_by: &[Expr],
    grouping_set: &[Expr],
    item: &GroupedAggregateItem,
) -> Result<SqlValue> {
    match &item.kind {
        GroupedAggregateItemKind::GroupKey(expr)
            if group_by.iter().any(|group_expr| group_expr == expr)
                && !grouping_set.iter().any(|group_expr| group_expr == expr) =>
        {
            Ok(SqlValue::Null)
        }
        _ => grouped_aggregate_value(batch, item),
    }
}

fn aggregate_column_schema(batch: &VectorBatch, item: &AggregateItem) -> Result<ColumnSchema> {
    match &item.function {
        AggregateFunction::CountStar
        | AggregateFunction::Count(_)
        | AggregateFunction::CountDistinct(_) => {
            Ok(ColumnSchema::new(item.name.as_str(), SqlType::Int64).not_null())
        }
        AggregateFunction::Sum(_) => Ok(ColumnSchema::new(item.name.as_str(), SqlType::Int64)),
        AggregateFunction::Min(expr) | AggregateFunction::Max(expr) => Ok(ColumnSchema::new(
            item.name.as_str(),
            projection_type(batch.columns(), expr)?,
        )),
    }
}

fn aggregate_value(batch: &VectorBatch, function: &AggregateFunction) -> Result<SqlValue> {
    match function {
        AggregateFunction::CountStar => {
            Ok(SqlValue::Int64(i64::try_from(batch.rows().len()).map_err(
                |_| RnovError::new(ErrorKind::InvalidInput, "COUNT(*) result exceeds int64"),
            )?))
        }
        AggregateFunction::Count(expr) => {
            let mut count = 0_i64;
            for row in batch.rows() {
                if !eval_expr(batch.columns(), row, expr)?.is_null() {
                    count = count.checked_add(1).ok_or_else(|| {
                        RnovError::new(ErrorKind::InvalidInput, "COUNT(expr) result exceeds int64")
                    })?;
                }
            }
            Ok(SqlValue::Int64(count))
        }
        AggregateFunction::CountDistinct(expr) => {
            let mut values = Vec::new();
            for row in batch.rows() {
                let value = eval_expr(batch.columns(), row, expr)?;
                if !value.is_null() && !values.contains(&value) {
                    values.push(value);
                }
            }
            Ok(SqlValue::Int64(i64::try_from(values.len()).map_err(
                |_| {
                    RnovError::new(
                        ErrorKind::InvalidInput,
                        "COUNT(DISTINCT expr) result exceeds int64",
                    )
                },
            )?))
        }
        AggregateFunction::Sum(expr) => {
            let mut sum: Option<i64> = None;
            for row in batch.rows() {
                match eval_expr(batch.columns(), row, expr)? {
                    SqlValue::Null => {}
                    SqlValue::Int64(value) => {
                        sum = Some(match sum {
                            Some(current) => current.checked_add(value).ok_or_else(|| {
                                RnovError::new(
                                    ErrorKind::InvalidInput,
                                    "SUM(expr) result exceeds int64",
                                )
                            })?,
                            None => value,
                        });
                    }
                    other => {
                        return Err(RnovError::new(
                            ErrorKind::InvalidInput,
                            format!(
                                "SUM(expr) requires INT64 values, got {:?}",
                                other.data_type()
                            ),
                        ));
                    }
                }
            }
            Ok(sum.map_or(SqlValue::Null, SqlValue::Int64))
        }
        AggregateFunction::Min(expr) => aggregate_ordered_value(batch, expr, OrderedAggregate::Min),
        AggregateFunction::Max(expr) => aggregate_ordered_value(batch, expr, OrderedAggregate::Max),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OrderedAggregate {
    Min,
    Max,
}

fn aggregate_ordered_value(
    batch: &VectorBatch,
    expr: &Expr,
    aggregate: OrderedAggregate,
) -> Result<SqlValue> {
    let mut selected: Option<SqlValue> = None;
    for row in batch.rows() {
        let value = eval_expr(batch.columns(), row, expr)?;
        if value.is_null() {
            continue;
        }
        let data_type = value.data_type();
        if !sortable_type(&data_type) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("ordered aggregate expression type is not sortable: {data_type:?}"),
            ));
        }
        if let Some(current) = &selected {
            let ordering = value.sql_cmp(current)?.ok_or_else(|| {
                RnovError::new(
                    ErrorKind::InvalidInput,
                    "ordered aggregate comparison produced unknown result",
                )
            })?;
            let replace = match aggregate {
                OrderedAggregate::Min => ordering == Ordering::Less,
                OrderedAggregate::Max => ordering == Ordering::Greater,
            };
            if replace {
                selected = Some(value);
            }
        } else {
            selected = Some(value);
        }
    }
    Ok(selected.unwrap_or(SqlValue::Null))
}

fn apply_limit_cancellable(
    batch: VectorBatch,
    count: usize,
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    cancellation.check()?;
    let rows = batch.rows().iter().take(count).cloned().collect();
    cancellation.check()?;
    VectorBatch::new(batch.columns().to_vec(), rows)
}

fn apply_offset_cancellable(
    batch: VectorBatch,
    count: usize,
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    cancellation.check()?;
    let rows = batch.rows().iter().skip(count).cloned().collect();
    cancellation.check()?;
    VectorBatch::new(batch.columns().to_vec(), rows)
}

fn rename_batch_columns(batch: VectorBatch, names: &[String]) -> Result<VectorBatch> {
    if batch.columns().len() != names.len() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "recursive CTE column count mismatch: expected {}, got {}",
                names.len(),
                batch.columns().len()
            ),
        ));
    }
    let columns = batch
        .columns()
        .iter()
        .zip(names.iter())
        .map(|(column, name)| renamed_column_schema(column, name))
        .collect::<Vec<_>>();
    VectorBatch::new(columns, batch.rows().to_vec())
}

fn renamed_column_schema(column: &ColumnSchema, name: &str) -> ColumnSchema {
    let mut renamed = ColumnSchema::new(name, column.data_type().clone());
    if !column.nullable() {
        renamed = renamed.not_null();
    }
    if column.is_encrypted() {
        renamed = renamed.encrypted();
    }
    if let Some(generated) = column.generated() {
        renamed = renamed.with_generated(generated.clone());
    }
    renamed
}

fn append_batches(
    left: VectorBatch,
    right: &VectorBatch,
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    ensure_same_batch_schema(&left, right)?;
    let mut rows = left.rows().to_vec();
    rows.reserve(right.rows().len());
    for row in right.rows() {
        cancellation.check()?;
        rows.push(row.clone());
    }
    cancellation.check()?;
    VectorBatch::new(left.columns().to_vec(), rows)
}

fn ensure_same_batch_schema(left: &VectorBatch, right: &VectorBatch) -> Result<()> {
    if left.columns().len() != right.columns().len() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "recursive CTE batch width changed between iterations",
        ));
    }
    for (left, right) in left.columns().iter().zip(right.columns().iter()) {
        if left.name() != right.name() || left.data_type() != right.data_type() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "recursive CTE batch schema changed between iterations",
            ));
        }
    }
    Ok(())
}

fn memory_table_from_batch(batch: &VectorBatch) -> Result<MemoryTable> {
    let mut table = MemoryTable::new(batch.columns().to_vec())?;
    for row in batch.rows() {
        table.insert(row.clone())?;
    }
    Ok(table)
}

fn projection_type(columns: &[ColumnSchema], expr: &Expr) -> Result<SqlType> {
    match expr {
        Expr::Identifier(identifier) => {
            let index = column_index(columns, identifier.as_str())?;
            Ok(columns[index].data_type().clone())
        }
        Expr::QualifiedIdentifier { .. } => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "bound memory projection must not contain qualified column references",
        )),
        Expr::Integer(_) => Ok(SqlType::Int64),
        Expr::Float64(_) => Ok(SqlType::Float64),
        Expr::String(_) => Ok(SqlType::Text),
        Expr::Bool(_) => Ok(SqlType::Bool),
        Expr::Null => Ok(SqlType::Null),
        Expr::RuntimeValue(value) => Ok(value.data_type()),
        Expr::CountStar => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "COUNT(*) requires aggregate execution",
        )),
        Expr::Count(_) | Expr::CountDistinct(_) => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "COUNT(expr) requires aggregate execution",
        )),
        Expr::Sum(_) => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "SUM(expr) requires aggregate execution",
        )),
        Expr::Min(_) => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "MIN(expr) requires aggregate execution",
        )),
        Expr::Max(_) => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "MAX(expr) requires aggregate execution",
        )),
        Expr::RowNumberOver { .. } | Expr::RankOver { .. } | Expr::DenseRankOver { .. } => {
            Err(RnovError::new(
                ErrorKind::InvalidInput,
                "window expressions require window execution",
            ))
        }
        Expr::Array(values) => Ok(array_literal_value(values)?.data_type()),
        Expr::HStore(entries) => Ok(hstore_literal_value(entries)?.data_type()),
        Expr::Range {
            lower,
            upper,
            bounds,
        } => Ok(
            range_literal_value(lower, upper, bounds.lower_inclusive, bounds.upper_inclusive)?
                .data_type(),
        ),
        Expr::Binary { op, .. } if boolean_operator(op) => Ok(SqlType::Bool),
        Expr::Binary { left, op, right } if arithmetic_operator(op) => {
            projection_arithmetic_type(columns, left, op, right)
        }
        Expr::Binary { op, .. } if text_concat_operator(op) => Ok(SqlType::Text),
        Expr::Binary { op, .. } => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("memory projection does not support operator {op}"),
        )),
        Expr::Unary { op, expr } if unary_arithmetic_operator(op) => {
            projection_unary_arithmetic_type(columns, op, expr)
        }
        Expr::Unary { op, .. } => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("memory projection does not support unary operator {op}"),
        )),
        Expr::Not(_) => Ok(SqlType::Bool),
        Expr::IsNull { .. } => Ok(SqlType::Bool),
        Expr::IsTruth { .. } => Ok(SqlType::Bool),
        Expr::IsUnknown { .. } => Ok(SqlType::Bool),
        Expr::IsDistinctFrom { left, right, .. } => {
            projection_null_safe_comparison_type(columns, left, right)
        }
        Expr::Between { .. } => Ok(SqlType::Bool),
        Expr::InList { .. } => Ok(SqlType::Bool),
        Expr::InSubquery { .. } | Expr::ExistsSubquery { .. } => Ok(SqlType::Bool),
        Expr::ScalarSubquery { .. } => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "scalar subquery must be resolved before projection",
        )),
        Expr::Like { .. } => Ok(SqlType::Bool),
        Expr::Coalesce(values) => projection_coalesce_type(columns, values),
        Expr::NullIf { left, right } => projection_nullif_type(columns, left, right),
        Expr::Case {
            operand,
            whens,
            else_expr,
        } => projection_case_type(columns, operand.as_deref(), whens, else_expr.as_deref()),
        Expr::Cast { data_type, .. } => Ok(data_type.clone()),
        Expr::Call { name, args } => projection_call_type(columns, name.object(), args),
    }
}

fn projection_arithmetic_type(
    columns: &[ColumnSchema],
    left: &Expr,
    op: &str,
    right: &Expr,
) -> Result<SqlType> {
    let left_type = projection_type(columns, left)?;
    let right_type = projection_type(columns, right)?;
    if !numeric_or_null_type(&left_type) || !numeric_or_null_type(&right_type) {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("arithmetic operator {op} requires numeric operands"),
        ));
    }
    if op == "%" && (left_type == SqlType::Float64 || right_type == SqlType::Float64) {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "modulo operator requires INT64 operands",
        ));
    }
    if left_type == SqlType::Float64 || right_type == SqlType::Float64 {
        Ok(SqlType::Float64)
    } else {
        Ok(SqlType::Int64)
    }
}

fn projection_unary_arithmetic_type(
    columns: &[ColumnSchema],
    op: &str,
    expr: &Expr,
) -> Result<SqlType> {
    let data_type = projection_type(columns, expr)?;
    match data_type {
        SqlType::Int64 | SqlType::Null => Ok(SqlType::Int64),
        SqlType::Float64 => Ok(SqlType::Float64),
        other => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("unary operator {op} requires numeric operand, got {other:?}"),
        )),
    }
}

fn numeric_or_null_type(data_type: &SqlType) -> bool {
    matches!(data_type, SqlType::Int64 | SqlType::Float64 | SqlType::Null)
}

fn projection_call_type(columns: &[ColumnSchema], name: &str, args: &[Expr]) -> Result<SqlType> {
    match name {
        "text_rank" => {
            ensure_function_arity(name, args, 2)?;
            let value_type = projection_type(columns, &args[0])?;
            if !matches!(
                value_type,
                SqlType::Text | SqlType::TextVector | SqlType::Null
            ) {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "text_rank value argument requires TEXT or TEXTVECTOR, got {value_type:?}"
                    ),
                ));
            }

            let query_type = projection_type(columns, &args[1])?;
            if !matches!(query_type, SqlType::Text | SqlType::Null) {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("text_rank query argument requires TEXT, got {query_type:?}"),
                ));
            }
            Ok(SqlType::Int64)
        }
        "text_phrase_match" => {
            ensure_function_arity(name, args, 3)?;
            let value_type = projection_type(columns, &args[0])?;
            if !matches!(
                value_type,
                SqlType::Text | SqlType::TextVector | SqlType::Null
            ) {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "text_phrase_match value argument requires TEXT or TEXTVECTOR, got {value_type:?}"
                    ),
                ));
            }

            let phrase_type = projection_type(columns, &args[1])?;
            if !matches!(phrase_type, SqlType::Text | SqlType::Null) {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("text_phrase_match phrase argument requires TEXT, got {phrase_type:?}"),
                ));
            }

            let gap_type = projection_type(columns, &args[2])?;
            if !matches!(gap_type, SqlType::Int64 | SqlType::Null) {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("text_phrase_match gap argument requires INT64, got {gap_type:?}"),
                ));
            }
            Ok(SqlType::Bool)
        }
        other => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("memory projection does not support function call {other}"),
        )),
    }
}

fn ensure_function_arity(name: &str, args: &[Expr], expected: usize) -> Result<()> {
    if args.len() == expected {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::InvalidInput,
        format!("{name} expects {expected} arguments, got {}", args.len()),
    ))
}

fn projection_coalesce_type(columns: &[ColumnSchema], values: &[Expr]) -> Result<SqlType> {
    if values.is_empty() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "COALESCE requires at least one expression",
        ));
    }
    let value_types = values
        .iter()
        .map(|value| projection_type(columns, value))
        .collect::<Result<Vec<_>>>()?;
    coalesce_result_type(&value_types)
}

fn coalesce_result_type(value_types: &[SqlType]) -> Result<SqlType> {
    let mut result_type = None;
    for value_type in value_types {
        if value_type == &SqlType::Null {
            continue;
        }
        match &result_type {
            Some(existing) if existing != value_type => {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "COALESCE arguments must have matching types",
                ));
            }
            Some(_) => {}
            None => result_type = Some(value_type.clone()),
        }
    }
    Ok(result_type.unwrap_or(SqlType::Null))
}

fn projection_nullif_type(columns: &[ColumnSchema], left: &Expr, right: &Expr) -> Result<SqlType> {
    let left_type = projection_type(columns, left)?;
    let right_type = projection_type(columns, right)?;
    nullif_result_type(&left_type, &right_type)
}

fn nullif_result_type(left_type: &SqlType, right_type: &SqlType) -> Result<SqlType> {
    if matches!(left_type, SqlType::Null)
        || matches!(right_type, SqlType::Null)
        || left_type == right_type
    {
        Ok(left_type.clone())
    } else {
        Err(RnovError::new(
            ErrorKind::InvalidInput,
            "NULLIF arguments must have matching types",
        ))
    }
}

fn projection_null_safe_comparison_type(
    columns: &[ColumnSchema],
    left: &Expr,
    right: &Expr,
) -> Result<SqlType> {
    let left_type = projection_type(columns, left)?;
    let right_type = projection_type(columns, right)?;
    if matches!(left_type, SqlType::Null)
        || matches!(right_type, SqlType::Null)
        || left_type == right_type
    {
        Ok(SqlType::Bool)
    } else {
        Err(RnovError::new(
            ErrorKind::InvalidInput,
            "IS DISTINCT FROM requires matching operand types",
        ))
    }
}

fn projection_case_type(
    columns: &[ColumnSchema],
    operand: Option<&Expr>,
    whens: &[CaseWhen],
    else_expr: Option<&Expr>,
) -> Result<SqlType> {
    if whens.is_empty() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "CASE requires at least one WHEN arm",
        ));
    }

    let operand_type = operand
        .map(|operand| projection_type(columns, operand))
        .transpose()?;
    let mut result_types = Vec::with_capacity(whens.len());
    for arm in whens {
        let condition_type = projection_type(columns, &arm.condition)?;
        case_condition_type(operand_type.as_ref(), &condition_type)?;
        result_types.push(projection_type(columns, &arm.result)?);
    }
    let else_type = else_expr
        .map(|else_expr| projection_type(columns, else_expr))
        .transpose()?
        .unwrap_or(SqlType::Null);
    case_result_type(&result_types, &else_type)
}

fn case_condition_type(operand_type: Option<&SqlType>, condition_type: &SqlType) -> Result<()> {
    match operand_type {
        Some(operand_type) => {
            if matches!(operand_type, SqlType::Null)
                || matches!(condition_type, SqlType::Null)
                || operand_type == condition_type
            {
                Ok(())
            } else {
                Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "CASE operand and WHEN expressions must have matching types",
                ))
            }
        }
        None => {
            if matches!(condition_type, SqlType::Bool | SqlType::Null) {
                Ok(())
            } else {
                Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("CASE WHEN condition must be BOOL, got {condition_type:?}"),
                ))
            }
        }
    }
}

fn case_result_type(result_types: &[SqlType], else_type: &SqlType) -> Result<SqlType> {
    let mut result_type = None;
    for value_type in result_types.iter().chain(std::iter::once(else_type)) {
        if value_type == &SqlType::Null {
            continue;
        }
        match &result_type {
            Some(existing) if existing != value_type => {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "CASE result expressions must have matching types",
                ));
            }
            Some(_) => {}
            None => result_type = Some(value_type.clone()),
        }
    }
    Ok(result_type.unwrap_or(SqlType::Null))
}

fn sortable_type(data_type: &SqlType) -> bool {
    matches!(
        data_type,
        SqlType::Bool
            | SqlType::Int64
            | SqlType::UInt64
            | SqlType::Float64
            | SqlType::Uuid
            | SqlType::Timestamp
            | SqlType::Text
            | SqlType::Bytes
    )
}

fn eval_expr(columns: &[ColumnSchema], row: &Row, expr: &Expr) -> Result<SqlValue> {
    match expr {
        Expr::Identifier(identifier) => {
            let index = column_index(columns, identifier.as_str())?;
            Ok(row.values()[index].clone())
        }
        Expr::QualifiedIdentifier { .. } => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "bound memory expression must not contain qualified column references",
        )),
        Expr::Integer(_)
        | Expr::Float64(_)
        | Expr::String(_)
        | Expr::Bool(_)
        | Expr::Null
        | Expr::RuntimeValue(_)
        | Expr::Array(_)
        | Expr::HStore(_)
        | Expr::Range { .. } => literal_value(expr),
        Expr::CountStar => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "COUNT(*) requires aggregate execution",
        )),
        Expr::Count(_) | Expr::CountDistinct(_) => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "COUNT(expr) requires aggregate execution",
        )),
        Expr::Sum(_) => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "SUM(expr) requires aggregate execution",
        )),
        Expr::Min(_) => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "MIN(expr) requires aggregate execution",
        )),
        Expr::Max(_) => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "MAX(expr) requires aggregate execution",
        )),
        Expr::RowNumberOver { .. } | Expr::RankOver { .. } | Expr::DenseRankOver { .. } => {
            Err(RnovError::new(
                ErrorKind::InvalidInput,
                "window expressions require window execution",
            ))
        }
        Expr::Binary { left, op, right } => eval_binary_expr(columns, row, left, op, right),
        Expr::Unary { op, expr } => eval_unary_arithmetic_expr(columns, row, op, expr),
        Expr::Not(expr) => eval_not_expr(columns, row, expr),
        Expr::IsNull { expr, negated } => eval_is_null_expr(columns, row, expr, *negated),
        Expr::IsTruth {
            expr,
            value,
            negated,
        } => eval_is_truth_expr(columns, row, expr, *value, *negated),
        Expr::IsUnknown { expr, negated } => eval_is_unknown_expr(columns, row, expr, *negated),
        Expr::IsDistinctFrom {
            left,
            right,
            negated,
        } => eval_is_distinct_from_expr(columns, row, left, right, *negated),
        Expr::Between {
            expr,
            low,
            high,
            negated,
        } => eval_between_expr(columns, row, expr, low, high, *negated),
        Expr::InList {
            expr,
            values,
            negated,
        } => eval_in_list_expr(columns, row, expr, values, *negated),
        Expr::InSubquery { .. } => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "IN subquery must be executed by an InSubqueryFilter plan",
        )),
        Expr::ExistsSubquery { .. } => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "EXISTS subquery must be executed by an ExistsSubqueryFilter plan",
        )),
        Expr::ScalarSubquery { .. } => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "scalar subquery must be resolved before expression evaluation",
        )),
        Expr::Like {
            expr,
            pattern,
            negated,
        } => eval_like_expr(columns, row, expr, pattern, *negated),
        Expr::Coalesce(values) => eval_coalesce_expr(columns, row, values),
        Expr::NullIf { left, right } => eval_nullif_expr(columns, row, left, right),
        Expr::Case {
            operand,
            whens,
            else_expr,
        } => eval_case_expr(
            columns,
            row,
            operand.as_deref(),
            whens,
            else_expr.as_deref(),
        ),
        Expr::Cast { expr, data_type } => eval_cast_expr(columns, row, expr, data_type),
        Expr::Call { name, args } => eval_call_expr(columns, row, name.object(), args),
    }
}

fn eval_call_expr(
    columns: &[ColumnSchema],
    row: &Row,
    name: &str,
    args: &[Expr],
) -> Result<SqlValue> {
    match name {
        "text_rank" => eval_text_rank(columns, row, args),
        "text_phrase_match" => eval_text_phrase_match(columns, row, args),
        other => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("memory projection does not support function call {other}"),
        )),
    }
}

fn eval_text_rank(columns: &[ColumnSchema], row: &Row, args: &[Expr]) -> Result<SqlValue> {
    ensure_function_arity("text_rank", args, 2)?;
    let Some(vector) =
        text_vector_from_search_value(eval_expr(columns, row, &args[0])?, "text_rank")?
    else {
        return Ok(SqlValue::Null);
    };

    let query = match eval_expr(columns, row, &args[1])? {
        SqlValue::Null => return Ok(SqlValue::Null),
        SqlValue::Text(query) => TextQuery::parse(&query)?,
        other => {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "text_rank query argument requires TEXT, got {:?}",
                    other.data_type()
                ),
            ));
        }
    };

    Ok(query
        .rank(&vector)
        .map(|rank| SqlValue::Int64(i64::from(rank.score())))
        .unwrap_or(SqlValue::Null))
}

fn eval_text_phrase_match(columns: &[ColumnSchema], row: &Row, args: &[Expr]) -> Result<SqlValue> {
    ensure_function_arity("text_phrase_match", args, 3)?;
    let Some(vector) =
        text_vector_from_search_value(eval_expr(columns, row, &args[0])?, "text_phrase_match")?
    else {
        return Ok(SqlValue::Bool(false));
    };

    let phrase_text = match eval_expr(columns, row, &args[1])? {
        SqlValue::Null => return Ok(SqlValue::Bool(false)),
        SqlValue::Text(phrase) => phrase,
        other => {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "text_phrase_match phrase argument requires TEXT, got {:?}",
                    other.data_type()
                ),
            ));
        }
    };
    let max_gap = match eval_expr(columns, row, &args[2])? {
        SqlValue::Null => return Ok(SqlValue::Bool(false)),
        SqlValue::Int64(max_gap) if max_gap > 0 => u32::try_from(max_gap).map_err(|_| {
            RnovError::new(
                ErrorKind::InvalidInput,
                "text_phrase_match gap argument exceeds UINT32",
            )
        })?,
        SqlValue::Int64(_) => {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "text_phrase_match gap argument must be greater than zero",
            ));
        }
        other => {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "text_phrase_match gap argument requires INT64, got {:?}",
                    other.data_type()
                ),
            ));
        }
    };

    let phrase = TextPhraseQuery::within(phrase_text.split_whitespace(), max_gap)?;
    Ok(SqlValue::Bool(phrase.matches(&vector)))
}

fn eval_binary_expr(
    columns: &[ColumnSchema],
    row: &Row,
    left: &Expr,
    op: &str,
    right: &Expr,
) -> Result<SqlValue> {
    match op {
        "AND" | "OR" => eval_boolean_connector(columns, row, left, op, right),
        "+" | "-" | "*" | "/" | "%" => eval_arithmetic_expr(columns, row, left, op, right),
        "||" => eval_text_concat_expr(columns, row, left, right),
        "&&" => eval_range_overlap_expr(columns, row, left, right),
        "@>" => eval_contains_expr(columns, row, left, right),
        "?" => eval_hstore_key_expr(columns, row, left, right),
        "=" | "<>" | "!=" => {
            let left = eval_expr(columns, row, left)?;
            let right = eval_expr(columns, row, right)?;
            let truth = left.sql_eq(&right);
            Ok(SqlValue::Bool(match op {
                "=" => truth == Truth::True,
                "<>" | "!=" => truth == Truth::False,
                _ => unreachable!("matched equality operators"),
            }))
        }
        "<" | "<=" | ">" | ">=" => {
            let left = eval_expr(columns, row, left)?;
            let right = eval_expr(columns, row, right)?;
            let Some(ordering) = left.sql_cmp(&right)? else {
                return Ok(SqlValue::Bool(false));
            };
            Ok(SqlValue::Bool(match op {
                "<" => ordering == Ordering::Less,
                "<=" => matches!(ordering, Ordering::Less | Ordering::Equal),
                ">" => ordering == Ordering::Greater,
                ">=" => matches!(ordering, Ordering::Greater | Ordering::Equal),
                _ => unreachable!("matched ordering operators"),
            }))
        }
        "@@" => {
            let left = eval_expr(columns, row, left)?;
            let SqlValue::Text(query) = eval_expr(columns, row, right)? else {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "text search expression requires a text query",
                ));
            };
            let query = TextQuery::parse(&query)?;
            let builder = TextVectorBuilder::new(SimpleTokenizer::new());
            Ok(SqlValue::Bool(text_value_matches(&left, &query, &builder)?))
        }
        other => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("memory projection does not support operator {other}"),
        )),
    }
}

fn eval_contains_expr(
    columns: &[ColumnSchema],
    row: &Row,
    left: &Expr,
    right: &Expr,
) -> Result<SqlValue> {
    match (
        eval_expr(columns, row, left)?,
        eval_expr(columns, row, right)?,
    ) {
        (SqlValue::Null, _) | (_, SqlValue::Null) => Ok(SqlValue::Bool(false)),
        (SqlValue::Array(left), SqlValue::Array(right)) => Ok(SqlValue::Bool(
            right
                .values()
                .iter()
                .all(|value| left.values().contains(value)),
        )),
        (SqlValue::HStore(left), SqlValue::HStore(right)) => {
            Ok(SqlValue::Bool(right.iter().all(|(key, value)| {
                left.get(key).is_some_and(|left| left == value)
            })))
        }
        (left, right) => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "contains operator @> requires ARRAY or HSTORE operands, got {:?} and {:?}",
                left.data_type(),
                right.data_type()
            ),
        )),
    }
}

fn eval_hstore_key_expr(
    columns: &[ColumnSchema],
    row: &Row,
    left: &Expr,
    right: &Expr,
) -> Result<SqlValue> {
    match (
        eval_expr(columns, row, left)?,
        eval_expr(columns, row, right)?,
    ) {
        (SqlValue::Null, _) | (_, SqlValue::Null) => Ok(SqlValue::Bool(false)),
        (SqlValue::HStore(hstore), SqlValue::Text(key)) => {
            Ok(SqlValue::Bool(hstore.contains_key(&key)))
        }
        (left, right) => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "hstore key operator ? requires HSTORE and TEXT operands, got {:?} and {:?}",
                left.data_type(),
                right.data_type()
            ),
        )),
    }
}

fn eval_range_overlap_expr(
    columns: &[ColumnSchema],
    row: &Row,
    left: &Expr,
    right: &Expr,
) -> Result<SqlValue> {
    match (
        eval_expr(columns, row, left)?,
        eval_expr(columns, row, right)?,
    ) {
        (SqlValue::Null, _) | (_, SqlValue::Null) => Ok(SqlValue::Bool(false)),
        (SqlValue::Range(left), SqlValue::Range(right)) => {
            Ok(SqlValue::Bool(left.overlaps(&right)?))
        }
        (SqlValue::Array(left), SqlValue::Array(right))
            if matches!(left.element_type(), SqlType::Range(_))
                && matches!(right.element_type(), SqlType::Range(_)) =>
        {
            let Some(left) = bounding_box_from_value(&SqlValue::Array(left))? else {
                return Ok(SqlValue::Bool(false));
            };
            let Some(right) = bounding_box_from_value(&SqlValue::Array(right))? else {
                return Ok(SqlValue::Bool(false));
            };
            Ok(SqlValue::Bool(left.intersects(&right)?))
        }
        (left, right) => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "range overlap operator && requires RANGE or RANGE[] operands, got {:?} and {:?}",
                left.data_type(),
                right.data_type()
            ),
        )),
    }
}

fn eval_arithmetic_expr(
    columns: &[ColumnSchema],
    row: &Row,
    left: &Expr,
    op: &str,
    right: &Expr,
) -> Result<SqlValue> {
    let left = eval_expr(columns, row, left)?;
    let right = eval_expr(columns, row, right)?;
    if left.is_null() || right.is_null() {
        return Ok(SqlValue::Null);
    }
    if let (SqlValue::Int64(left), SqlValue::Int64(right)) = (&left, &right) {
        return eval_int64_arithmetic(*left, op, *right).map(SqlValue::Int64);
    }
    if op == "%" {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "modulo operator requires INT64 operands",
        ));
    }
    eval_float64_arithmetic(left, op, right).map(SqlValue::Float64)
}

fn eval_int64_arithmetic(left: i64, op: &str, right: i64) -> Result<i64> {
    let value = match op {
        "+" => left.checked_add(right),
        "-" => left.checked_sub(right),
        "*" => left.checked_mul(right),
        "/" => {
            if right == 0 {
                return Err(RnovError::new(ErrorKind::InvalidInput, "division by zero"));
            }
            left.checked_div(right)
        }
        "%" => {
            if right == 0 {
                return Err(RnovError::new(ErrorKind::InvalidInput, "modulo by zero"));
            }
            left.checked_rem(right)
        }
        _ => unreachable!("matched arithmetic operator"),
    }
    .ok_or_else(|| RnovError::new(ErrorKind::InvalidInput, "arithmetic overflow"))?;
    Ok(value)
}

fn eval_float64_arithmetic(left: SqlValue, op: &str, right: SqlValue) -> Result<SqlFloat64> {
    let left = numeric_value_as_float(left, op)?;
    let right = numeric_value_as_float(right, op)?;
    let value = match op {
        "+" => left + right,
        "-" => left - right,
        "*" => left * right,
        "/" => {
            if right == 0.0 {
                return Err(RnovError::new(ErrorKind::InvalidInput, "division by zero"));
            }
            left / right
        }
        _ => unreachable!("matched arithmetic operator"),
    };
    SqlFloat64::new(value)
}

fn numeric_value_as_float(value: SqlValue, op: &str) -> Result<f64> {
    match value {
        SqlValue::Int64(value) => Ok(value as f64),
        SqlValue::Float64(value) => Ok(value.get()),
        other => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "arithmetic operator {op} requires numeric operands, got {:?}",
                other.data_type()
            ),
        )),
    }
}

fn eval_text_concat_expr(
    columns: &[ColumnSchema],
    row: &Row,
    left: &Expr,
    right: &Expr,
) -> Result<SqlValue> {
    let left = eval_expr(columns, row, left)?;
    let right = eval_expr(columns, row, right)?;
    match (left, right) {
        (SqlValue::Null, _) | (_, SqlValue::Null) => Ok(SqlValue::Null),
        (SqlValue::Text(mut left), SqlValue::Text(right)) => {
            left.push_str(&right);
            Ok(SqlValue::Text(left))
        }
        (left, right) => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "text operator || requires TEXT operands, got {:?} and {:?}",
                left.data_type(),
                right.data_type()
            ),
        )),
    }
}

fn eval_unary_arithmetic_expr(
    columns: &[ColumnSchema],
    row: &Row,
    op: &str,
    expr: &Expr,
) -> Result<SqlValue> {
    let value = eval_expr(columns, row, expr)?;
    match (op, value) {
        (_, SqlValue::Null) => Ok(SqlValue::Null),
        ("+", SqlValue::Int64(value)) => Ok(SqlValue::Int64(value)),
        ("-", SqlValue::Int64(value)) => value
            .checked_neg()
            .map(SqlValue::Int64)
            .ok_or_else(|| RnovError::new(ErrorKind::InvalidInput, "arithmetic overflow")),
        ("+", SqlValue::Float64(value)) => Ok(SqlValue::Float64(value)),
        ("-", SqlValue::Float64(value)) => SqlFloat64::new(-value.get()).map(SqlValue::Float64),
        ("+" | "-", other) => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "unary operator {op} requires numeric operand, got {:?}",
                other.data_type()
            ),
        )),
        _ => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("unsupported unary operator {op}"),
        )),
    }
}

fn eval_not_expr(columns: &[ColumnSchema], row: &Row, expr: &Expr) -> Result<SqlValue> {
    Ok(match bool_truth(eval_expr(columns, row, expr)?)? {
        Truth::True => SqlValue::Bool(false),
        Truth::False => SqlValue::Bool(true),
        Truth::Unknown => SqlValue::Null,
    })
}

fn eval_is_null_expr(
    columns: &[ColumnSchema],
    row: &Row,
    expr: &Expr,
    negated: bool,
) -> Result<SqlValue> {
    let is_null = matches!(eval_expr(columns, row, expr)?, SqlValue::Null);
    Ok(SqlValue::Bool(if negated { !is_null } else { is_null }))
}

fn eval_is_truth_expr(
    columns: &[ColumnSchema],
    row: &Row,
    expr: &Expr,
    value: bool,
    negated: bool,
) -> Result<SqlValue> {
    let truth = match eval_expr(columns, row, expr)? {
        SqlValue::Bool(actual) => actual == value,
        SqlValue::Null => false,
        other => {
            let name = if value { "IS TRUE" } else { "IS FALSE" };
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("{name} requires BOOL operand, got {:?}", other.data_type()),
            ));
        }
    };
    Ok(SqlValue::Bool(if negated { !truth } else { truth }))
}

fn eval_is_unknown_expr(
    columns: &[ColumnSchema],
    row: &Row,
    expr: &Expr,
    negated: bool,
) -> Result<SqlValue> {
    let unknown = match eval_expr(columns, row, expr)? {
        SqlValue::Bool(_) => false,
        SqlValue::Null => true,
        other => {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "IS UNKNOWN requires BOOL operand, got {:?}",
                    other.data_type()
                ),
            ));
        }
    };
    Ok(SqlValue::Bool(if negated { !unknown } else { unknown }))
}

fn eval_is_distinct_from_expr(
    columns: &[ColumnSchema],
    row: &Row,
    left: &Expr,
    right: &Expr,
    negated: bool,
) -> Result<SqlValue> {
    let left = eval_expr(columns, row, left)?;
    let right = eval_expr(columns, row, right)?;
    let distinct = match (left.is_null(), right.is_null()) {
        (true, true) => false,
        (true, false) | (false, true) => true,
        (false, false) => {
            if left.data_type() != right.data_type() {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "IS DISTINCT FROM requires matching operand types",
                ));
            }
            left.sql_eq(&right) == Truth::False
        }
    };
    Ok(SqlValue::Bool(if negated { !distinct } else { distinct }))
}

fn eval_between_expr(
    columns: &[ColumnSchema],
    row: &Row,
    expr: &Expr,
    low: &Expr,
    high: &Expr,
    negated: bool,
) -> Result<SqlValue> {
    let value = eval_expr(columns, row, expr)?;
    let low = eval_expr(columns, row, low)?;
    let high = eval_expr(columns, row, high)?;
    let (Some(low_order), Some(high_order)) = (value.sql_cmp(&low)?, value.sql_cmp(&high)?) else {
        return Ok(SqlValue::Null);
    };
    let contains = !matches!(low_order, Ordering::Less) && !matches!(high_order, Ordering::Greater);
    Ok(SqlValue::Bool(if negated { !contains } else { contains }))
}

fn eval_in_list_expr(
    columns: &[ColumnSchema],
    row: &Row,
    expr: &Expr,
    values: &[Expr],
    negated: bool,
) -> Result<SqlValue> {
    let left = eval_expr(columns, row, expr)?;
    let mut saw_unknown = false;
    for value in values {
        match left.sql_eq(&eval_expr(columns, row, value)?) {
            Truth::True => return Ok(SqlValue::Bool(!negated)),
            Truth::False => {}
            Truth::Unknown => saw_unknown = true,
        }
    }
    if saw_unknown {
        Ok(SqlValue::Null)
    } else {
        Ok(SqlValue::Bool(negated))
    }
}

fn eval_like_expr(
    columns: &[ColumnSchema],
    row: &Row,
    expr: &Expr,
    pattern: &Expr,
    negated: bool,
) -> Result<SqlValue> {
    let value = eval_expr(columns, row, expr)?;
    let pattern = eval_expr(columns, row, pattern)?;
    match (value, pattern) {
        (SqlValue::Null, _) | (_, SqlValue::Null) => Ok(SqlValue::Null),
        (SqlValue::Text(value), SqlValue::Text(pattern)) => {
            let matched = like_pattern_matches(&value, &pattern);
            Ok(SqlValue::Bool(if negated { !matched } else { matched }))
        }
        _ => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "LIKE requires TEXT expression and pattern",
        )),
    }
}

fn like_pattern_matches(value: &str, pattern: &str) -> bool {
    let value: Vec<char> = value.chars().collect();
    let pattern: Vec<char> = pattern.chars().collect();
    let mut previous = vec![false; pattern.len() + 1];
    let mut current = vec![false; pattern.len() + 1];
    previous[0] = true;

    for pattern_index in 0..pattern.len() {
        if pattern[pattern_index] == '%' {
            previous[pattern_index + 1] = previous[pattern_index];
        }
    }

    for value_char in value {
        current[0] = false;
        for pattern_index in 0..pattern.len() {
            current[pattern_index + 1] = match pattern[pattern_index] {
                '%' => current[pattern_index] || previous[pattern_index + 1],
                '_' => previous[pattern_index],
                literal => previous[pattern_index] && value_char == literal,
            };
        }
        std::mem::swap(&mut previous, &mut current);
        current.fill(false);
    }

    previous[pattern.len()]
}

fn eval_coalesce_expr(columns: &[ColumnSchema], row: &Row, values: &[Expr]) -> Result<SqlValue> {
    if values.is_empty() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "COALESCE requires at least one expression",
        ));
    }
    for expr in values {
        let value = eval_expr(columns, row, expr)?;
        if !value.is_null() {
            return Ok(value);
        }
    }
    Ok(SqlValue::Null)
}

fn eval_case_expr(
    columns: &[ColumnSchema],
    row: &Row,
    operand: Option<&Expr>,
    whens: &[CaseWhen],
    else_expr: Option<&Expr>,
) -> Result<SqlValue> {
    if whens.is_empty() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "CASE requires at least one WHEN arm",
        ));
    }

    let operand_value = operand
        .map(|operand| eval_expr(columns, row, operand))
        .transpose()?;
    for arm in whens {
        let matched = if let Some(operand_value) = &operand_value {
            let condition = eval_expr(columns, row, &arm.condition)?;
            if !operand_value.is_null()
                && !condition.is_null()
                && operand_value.data_type() != condition.data_type()
            {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "CASE operand and WHEN expressions must have matching types",
                ));
            }
            operand_value.sql_eq(&condition) == Truth::True
        } else {
            bool_truth(eval_expr(columns, row, &arm.condition)?)? == Truth::True
        };

        if matched {
            return eval_expr(columns, row, &arm.result);
        }
    }

    if let Some(else_expr) = else_expr {
        eval_expr(columns, row, else_expr)
    } else {
        Ok(SqlValue::Null)
    }
}

fn eval_nullif_expr(
    columns: &[ColumnSchema],
    row: &Row,
    left: &Expr,
    right: &Expr,
) -> Result<SqlValue> {
    let left = eval_expr(columns, row, left)?;
    let right = eval_expr(columns, row, right)?;
    if left.sql_eq(&right) == Truth::True {
        Ok(SqlValue::Null)
    } else {
        Ok(left)
    }
}

fn eval_cast_expr(
    columns: &[ColumnSchema],
    row: &Row,
    expr: &Expr,
    data_type: &SqlType,
) -> Result<SqlValue> {
    let value = eval_expr(columns, row, expr)?;
    cast_value(value, data_type)
}

fn cast_literal_value(expr: &Expr, data_type: &SqlType) -> Result<SqlValue> {
    let value = literal_value(expr)?;
    cast_value(value, data_type)
}

fn cast_value(value: SqlValue, data_type: &SqlType) -> Result<SqlValue> {
    if value.is_null() {
        return Ok(SqlValue::Null);
    }
    let value_type = value.data_type();
    if &value_type == data_type {
        return Ok(value);
    }
    match (value, data_type) {
        (SqlValue::Int64(value), SqlType::Text) => Ok(SqlValue::Text(value.to_string())),
        (SqlValue::Int64(value), SqlType::Float64) => {
            SqlFloat64::new(value as f64).map(SqlValue::Float64)
        }
        (SqlValue::Text(value), SqlType::Int64) => {
            let parsed = value.parse::<i64>().map_err(|_| {
                RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("cannot cast TEXT value '{value}' to INT64"),
                )
            })?;
            Ok(SqlValue::Int64(parsed))
        }
        (SqlValue::Float64(value), SqlType::Text) => Ok(SqlValue::Text(value.get().to_string())),
        (SqlValue::Text(value), SqlType::Float64) => {
            let parsed = value.parse::<f64>().map_err(|_| {
                RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("cannot cast TEXT value '{value}' to FLOAT64"),
                )
            })?;
            SqlFloat64::new(parsed).map(SqlValue::Float64)
        }
        (SqlValue::Uuid(value), SqlType::Text) => Ok(SqlValue::Text(value.to_hyphenated_string())),
        (SqlValue::Text(value), SqlType::Uuid) => SqlUuid::parse_str(&value).map(SqlValue::Uuid),
        (SqlValue::Timestamp(value), SqlType::Text) => {
            Ok(SqlValue::Text(value.to_rfc3339_string()))
        }
        (SqlValue::Text(value), SqlType::Timestamp) => {
            SqlTimestamp::parse_str(&value).map(SqlValue::Timestamp)
        }
        (SqlValue::Json(value), SqlType::Text) => Ok(SqlValue::Text(value.as_str().to_string())),
        (SqlValue::Text(value), SqlType::Json) => SqlJson::parse_str(&value).map(SqlValue::Json),
        (SqlValue::Bool(value), SqlType::Text) => Ok(SqlValue::Text(value.to_string())),
        (SqlValue::Text(value), SqlType::Bool) => match value.to_ascii_lowercase().as_str() {
            "true" => Ok(SqlValue::Bool(true)),
            "false" => Ok(SqlValue::Bool(false)),
            _ => Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("cannot cast TEXT value '{value}' to BOOL"),
            )),
        },
        (value, target_type) => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("cannot cast {:?} to {target_type:?}", value.data_type()),
        )),
    }
}

fn eval_boolean_connector(
    columns: &[ColumnSchema],
    row: &Row,
    left: &Expr,
    op: &str,
    right: &Expr,
) -> Result<SqlValue> {
    let left = bool_truth(eval_expr(columns, row, left)?)?;
    let right = bool_truth(eval_expr(columns, row, right)?)?;
    let truth = match op {
        "AND" => match (left, right) {
            (Truth::False, _) | (_, Truth::False) => Truth::False,
            (Truth::Unknown, _) | (_, Truth::Unknown) => Truth::Unknown,
            (Truth::True, Truth::True) => Truth::True,
        },
        "OR" => match (left, right) {
            (Truth::True, _) | (_, Truth::True) => Truth::True,
            (Truth::Unknown, _) | (_, Truth::Unknown) => Truth::Unknown,
            (Truth::False, Truth::False) => Truth::False,
        },
        _ => unreachable!("matched boolean connectors"),
    };
    Ok(match truth {
        Truth::True => SqlValue::Bool(true),
        Truth::False => SqlValue::Bool(false),
        Truth::Unknown => SqlValue::Null,
    })
}

fn bool_truth(value: SqlValue) -> Result<Truth> {
    match value {
        SqlValue::Bool(true) => Ok(Truth::True),
        SqlValue::Bool(false) => Ok(Truth::False),
        SqlValue::Null => Ok(Truth::Unknown),
        other => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "boolean expression requires BOOL, got {:?}",
                other.data_type()
            ),
        )),
    }
}

fn eval_predicate(columns: &[ColumnSchema], row: &Row, expr: &Expr) -> Result<bool> {
    match eval_expr(columns, row, expr)? {
        SqlValue::Bool(value) => Ok(value),
        SqlValue::Null => Ok(false),
        other => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "predicate expression must be bool, got {:?}",
                other.data_type()
            ),
        )),
    }
}

fn boolean_operator(op: &str) -> bool {
    matches!(
        op,
        "=" | "<>" | "!=" | "<" | "<=" | ">" | ">=" | "@@" | "&&" | "@>" | "?" | "AND" | "OR"
    )
}

fn arithmetic_operator(op: &str) -> bool {
    matches!(op, "+" | "-" | "*" | "/" | "%")
}

fn text_concat_operator(op: &str) -> bool {
    op == "||"
}

fn unary_arithmetic_operator(op: &str) -> bool {
    matches!(op, "+" | "-")
}

fn apply_text_search_cancellable(
    batch: VectorBatch,
    column: &str,
    query: &str,
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    let index = column_index(batch.columns(), column)?;
    match batch.columns()[index].data_type() {
        SqlType::Text | SqlType::TextVector => {}
        other => {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("text search requires text or text vector column, got {other:?}"),
            ));
        }
    }

    let query = TextQuery::parse(query)?;
    let builder = TextVectorBuilder::new(SimpleTokenizer::new());
    let mut rows = Vec::new();

    for row in batch.rows() {
        cancellation.check()?;
        if text_value_matches(&row.values()[index], &query, &builder)? {
            rows.push(row.clone());
        }
    }

    cancellation.check()?;
    VectorBatch::new(batch.columns().to_vec(), rows)
}

fn text_value_matches(
    value: &SqlValue,
    query: &TextQuery,
    builder: &TextVectorBuilder<SimpleTokenizer>,
) -> Result<bool> {
    match value {
        SqlValue::Null => Ok(false),
        SqlValue::Text(text) => Ok(query.matches(&builder.build(text)?)),
        SqlValue::TextVector(vector) => Ok(query.matches(vector)),
        other => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "text search cannot evaluate value type {:?}",
                other.data_type()
            ),
        )),
    }
}

fn text_vector_from_search_value(value: SqlValue, function: &str) -> Result<Option<TextVector>> {
    match value {
        SqlValue::Null => Ok(None),
        SqlValue::Text(text) => Ok(Some(
            TextVectorBuilder::new(SimpleTokenizer::new()).build(&text)?,
        )),
        SqlValue::TextVector(vector) => Ok(Some(vector)),
        other => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "{function} value argument requires TEXT or TEXTVECTOR, got {:?}",
                other.data_type()
            ),
        )),
    }
}

fn row_matches(columns: &[ColumnSchema], row: &Row, selection: Option<&Expr>) -> Result<bool> {
    let Some(selection) = selection else {
        return Ok(true);
    };
    eval_predicate(columns, row, selection)
}

fn column_index(columns: &[ColumnSchema], name: &str) -> Result<usize> {
    columns
        .iter()
        .position(|column| column.name() == name)
        .ok_or_else(|| RnovError::new(ErrorKind::NotFound, format!("column not found: {name}")))
}

fn literal_value(expr: &Expr) -> Result<SqlValue> {
    match expr {
        Expr::Integer(value) => Ok(SqlValue::Int64(*value)),
        Expr::Float64(value) => Ok(SqlValue::Float64(*value)),
        Expr::String(value) => Ok(SqlValue::Text(value.clone())),
        Expr::Bool(value) => Ok(SqlValue::Bool(*value)),
        Expr::Null => Ok(SqlValue::Null),
        Expr::RuntimeValue(value) => Ok(value.clone()),
        Expr::Array(values) => array_literal_value(values),
        Expr::HStore(entries) => hstore_literal_value(entries),
        Expr::Range {
            lower,
            upper,
            bounds,
        } => range_literal_value(lower, upper, bounds.lower_inclusive, bounds.upper_inclusive),
        Expr::Unary { op, expr } if unary_arithmetic_operator(op) => unary_literal_value(op, expr),
        Expr::Cast { expr, data_type } => cast_literal_value(expr, data_type),
        _ => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("unsupported memory literal: {expr}"),
        )),
    }
}

fn unary_literal_value(op: &str, expr: &Expr) -> Result<SqlValue> {
    let value = literal_value(expr)?;
    match (op, value) {
        (_, SqlValue::Null) => Ok(SqlValue::Null),
        ("+", SqlValue::Int64(value)) => Ok(SqlValue::Int64(value)),
        ("-", SqlValue::Int64(value)) => value
            .checked_neg()
            .map(SqlValue::Int64)
            .ok_or_else(|| RnovError::new(ErrorKind::InvalidInput, "arithmetic overflow")),
        ("+", SqlValue::Float64(value)) => Ok(SqlValue::Float64(value)),
        ("-", SqlValue::Float64(value)) => SqlFloat64::new(-value.get()).map(SqlValue::Float64),
        ("+" | "-", other) => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "unary operator {op} requires numeric literal, got {:?}",
                other.data_type()
            ),
        )),
        _ => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("unsupported unary operator {op}"),
        )),
    }
}

fn array_literal_value(values: &[Expr]) -> Result<SqlValue> {
    let mut converted = Vec::with_capacity(values.len());
    let mut element_type = None;

    for expr in values {
        let value = literal_value(expr)?;
        if !value.is_null() {
            let value_type = value.data_type();
            match &element_type {
                Some(existing) if *existing != value_type => {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        "array literal contains mixed element types",
                    ));
                }
                Some(_) => {}
                None => element_type = Some(value_type),
            }
        }
        converted.push(value);
    }

    let dimension = ArrayDimension::new(1, converted.len())?;
    Ok(SqlValue::Array(SqlArray::new(
        element_type.unwrap_or(SqlType::Null),
        vec![dimension],
        converted,
    )?))
}

fn hstore_literal_value(entries: &[(String, Option<String>)]) -> Result<SqlValue> {
    let entries = entries.iter().map(|(key, value)| {
        (
            key.clone(),
            value
                .as_ref()
                .map_or(HStoreValue::Null, |value| HStoreValue::Text(value.clone())),
        )
    });
    Ok(SqlValue::HStore(HStore::from_entries(entries)?))
}

fn range_literal_value(
    lower: &Expr,
    upper: &Expr,
    lower_inclusive: bool,
    upper_inclusive: bool,
) -> Result<SqlValue> {
    let lower = literal_value(lower)?;
    let upper = literal_value(upper)?;
    let element_type = range_element_type(&lower, &upper)?;
    let lower_bound = range_bound(lower, lower_inclusive);
    let upper_bound = range_bound(upper, upper_inclusive);

    Ok(SqlValue::Range(SqlRange::new(
        element_type,
        lower_bound,
        upper_bound,
    )?))
}

fn range_element_type(lower: &SqlValue, upper: &SqlValue) -> Result<SqlType> {
    match (lower, upper) {
        (SqlValue::Null, SqlValue::Null) => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "range literal requires at least one typed bound",
        )),
        (SqlValue::Null, upper) => Ok(upper.data_type()),
        (lower, SqlValue::Null) => Ok(lower.data_type()),
        (lower, upper) if lower.data_type() == upper.data_type() => Ok(lower.data_type()),
        _ => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "range literal bounds have different types",
        )),
    }
}

fn range_bound(value: SqlValue, inclusive: bool) -> RangeBound {
    if value.is_null() {
        RangeBound::Unbounded
    } else if inclusive {
        RangeBound::Included(value)
    } else {
        RangeBound::Excluded(value)
    }
}
