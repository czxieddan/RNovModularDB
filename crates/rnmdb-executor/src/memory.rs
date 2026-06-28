use std::{
    cmp::Ordering,
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering as AtomicOrdering},
    },
    thread,
};

use rnmdb_common::Result;
use rnmdb_common::{ErrorKind, RnovError};
use rnmdb_fts::{SimpleTokenizer, TextQuery, TextVectorBuilder};
use rnmdb_planner::logical::{
    AggregateFunction, AggregateItem, GroupedAggregateItem, GroupedAggregateItemKind, LogicalPlan,
};
use rnmdb_sql::ast::{CaseWhen, ColumnDef, Expr, OrderByExpr, SortDirection};
use rnmdb_types::{
    ArrayDimension, HStore, HStoreValue, RangeBound, SqlArray, SqlRange, SqlType, SqlValue, Truth,
};

use crate::vector::{ColumnSchema, Row, VectorBatch};

#[derive(Clone, Debug)]
pub struct MemoryTable {
    columns: Vec<ColumnSchema>,
    rows: Vec<Row>,
}

impl MemoryTable {
    pub fn new(columns: Vec<ColumnSchema>) -> Result<Self> {
        let _ = VectorBatch::new(columns.clone(), Vec::new())?;
        Ok(Self {
            columns,
            rows: Vec::new(),
        })
    }

    pub fn columns(&self) -> &[ColumnSchema] {
        &self.columns
    }

    pub fn insert(&mut self, row: Row) -> Result<()> {
        let batch = VectorBatch::new(self.columns.clone(), vec![row.clone()])?;
        self.rows
            .push(batch.rows().first().expect("validated row").clone());
        Ok(())
    }

    pub fn scan(&self) -> VectorBatch {
        VectorBatch::new(self.columns.clone(), self.rows.clone())
            .expect("stored rows are validated on insert")
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
        if self.rows.is_empty()
            || config.worker_threads() == 1
            || self.rows.len() < config.min_parallel_rows()
        {
            cancellation.check()?;
            return Ok(self.scan());
        }

        let worker_count = config.worker_threads().min(self.rows.len());
        let chunk_size = self.rows.len().div_ceil(worker_count);
        let mut rows = Vec::with_capacity(self.rows.len());
        thread::scope(|scope| {
            let mut handles = Vec::with_capacity(worker_count);
            for chunk in self.rows.chunks(chunk_size) {
                let cancellation = cancellation.clone();
                handles.push(scope.spawn(move || {
                    cancellation.check()?;
                    let rows = chunk.to_vec();
                    cancellation.check()?;
                    Ok::<Vec<Row>, RnovError>(rows)
                }));
            }

            for handle in handles {
                let mut chunk = handle.join().map_err(|_| {
                    RnovError::new(ErrorKind::Internal, "parallel memory scan worker panicked")
                })??;
                rows.append(&mut chunk);
            }
            Ok::<(), RnovError>(())
        })?;

        cancellation.check()?;
        VectorBatch::new(self.columns.clone(), rows)
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

#[derive(Clone, Debug, Default)]
pub struct MemoryExecutor {
    tables: BTreeMap<String, MemoryTable>,
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

    pub fn register_table(&mut self, name: impl Into<String>, table: MemoryTable) -> Result<()> {
        let name = name.into();
        if name.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "registered table name cannot be empty",
            ));
        }
        self.tables.insert(name, table);
        Ok(())
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
            LogicalPlan::Scan { table, .. } => self
                .tables
                .get(table)
                .map(MemoryTable::scan)
                .ok_or_else(|| {
                    RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                }),
            LogicalPlan::Filter { predicate, input } => {
                let batch = self.execute_cancellable(input, cancellation)?;
                apply_filter_cancellable(batch, predicate, cancellation)
            }
            LogicalPlan::TextSearch {
                table,
                column,
                query,
                ..
            } => {
                let batch = self
                    .tables
                    .get(table)
                    .map(MemoryTable::scan)
                    .ok_or_else(|| {
                        RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                    })?;
                apply_text_search_cancellable(batch, column, query, cancellation)
            }
            LogicalPlan::Project { items, input } => {
                let batch = self.execute_cancellable(input, cancellation)?;
                apply_projection_cancellable(batch, items, cancellation)
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
            LogicalPlan::Distinct { input } => {
                let batch = self.execute_cancellable(input, cancellation)?;
                apply_distinct_cancellable(batch, cancellation)
            }
            LogicalPlan::Sort { keys, input } => {
                let batch = self.execute_cancellable(input, cancellation)?;
                apply_sort_cancellable(batch, keys, cancellation)
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

    pub async fn execute_async(&self, plan: &LogicalPlan) -> Result<VectorBatch> {
        self.execute(plan)
    }

    pub async fn execute_cancellable_async(
        &self,
        plan: &LogicalPlan,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        self.execute_cancellable(plan, cancellation)
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
            LogicalPlan::Scan { table, .. } => self
                .tables
                .get(table)
                .ok_or_else(|| {
                    RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                })?
                .scan_parallel_cancellable(config, cancellation),
            LogicalPlan::Filter { predicate, input } => {
                let batch = self.execute_parallel_cancellable(input, config, cancellation)?;
                apply_filter_cancellable(batch, predicate, cancellation)
            }
            LogicalPlan::TextSearch {
                table,
                column,
                query,
                ..
            } => {
                let batch = self
                    .tables
                    .get(table)
                    .ok_or_else(|| {
                        RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                    })?
                    .scan_parallel_cancellable(config, cancellation)?;
                apply_text_search_cancellable(batch, column, query, cancellation)
            }
            LogicalPlan::Project { items, input } => {
                let batch = self.execute_parallel_cancellable(input, config, cancellation)?;
                apply_projection_cancellable(batch, items, cancellation)
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
                apply_grouped_aggregate_cancellable(batch, group_by, items, cancellation)
            }
            LogicalPlan::Distinct { input } => {
                let batch = self.execute_parallel_cancellable(input, config, cancellation)?;
                apply_distinct_cancellable(batch, cancellation)
            }
            LogicalPlan::Sort { keys, input } => {
                let batch = self.execute_parallel_cancellable(input, config, cancellation)?;
                apply_sort_cancellable(batch, keys, cancellation)
            }
            LogicalPlan::Limit { count, input } => {
                let batch = self.execute_parallel_cancellable(input, config, cancellation)?;
                apply_limit_cancellable(batch, *count, cancellation)
            }
            LogicalPlan::Offset { count, input } => {
                let batch = self.execute_parallel_cancellable(input, config, cancellation)?;
                apply_offset_cancellable(batch, *count, cancellation)
            }
            LogicalPlan::Parallel { input, .. } => {
                self.execute_parallel_cancellable(input, config, cancellation)
            }
            _ => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "memory executor does not support this logical plan",
            )),
        }
    }

    pub async fn execute_parallel_async(
        &self,
        plan: &LogicalPlan,
        config: ParallelQueryConfig,
    ) -> Result<VectorBatch> {
        self.execute_parallel(plan, config)
    }

    pub async fn execute_parallel_cancellable_async(
        &self,
        plan: &LogicalPlan,
        config: ParallelQueryConfig,
        cancellation: &CancellationToken,
    ) -> Result<VectorBatch> {
        self.execute_parallel_cancellable(plan, config, cancellation)
    }

    pub fn execute_mut(&mut self, plan: &LogicalPlan) -> Result<ExecutionResult> {
        match plan {
            LogicalPlan::CreateTable { table, columns } => {
                self.create_table(table, columns)?;
                Ok(ExecutionResult::SchemaChanged)
            }
            LogicalPlan::AlterTableAddColumn { table, column, .. } => {
                let table = self.tables.get_mut(table).ok_or_else(|| {
                    RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                })?;
                table.add_column(column_schema_from_def(column))?;
                Ok(ExecutionResult::SchemaChanged)
            }
            LogicalPlan::DropTable {
                table, if_exists, ..
            } => {
                if self.tables.remove(table).is_some() || *if_exists {
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
                let table = self.tables.get_mut(table).ok_or_else(|| {
                    RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                })?;
                insert_values(table, columns, values)?;
                Ok(ExecutionResult::RowsAffected(1))
            }
            LogicalPlan::Update {
                table,
                assignments,
                selection,
                ..
            } => {
                let table = self.tables.get_mut(table).ok_or_else(|| {
                    RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                })?;
                update_rows(table, assignments, selection.as_ref())
                    .map(ExecutionResult::RowsAffected)
            }
            LogicalPlan::Delete {
                table, selection, ..
            } => {
                let table = self.tables.get_mut(table).ok_or_else(|| {
                    RnovError::new(ErrorKind::NotFound, format!("table not found: {table}"))
                })?;
                delete_rows(table, selection.as_ref()).map(ExecutionResult::RowsAffected)
            }
            _ => self.execute(plan).map(ExecutionResult::Batch),
        }
    }

    pub async fn execute_mut_async(&mut self, plan: &LogicalPlan) -> Result<ExecutionResult> {
        self.execute_mut(plan)
    }

    fn create_table(&mut self, name: &str, columns: &[ColumnDef]) -> Result<()> {
        if self.tables.contains_key(name) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("table already exists: {name}"),
            ));
        }
        let columns = columns.iter().map(column_schema_from_def).collect();
        let table = MemoryTable::new(columns)?;
        self.tables.insert(name.to_string(), table);
        Ok(())
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
    schema
}

fn update_rows(
    table: &mut MemoryTable,
    assignments: &[(String, Expr)],
    selection: Option<&Expr>,
) -> Result<u64> {
    let columns = table.columns.clone();
    let assignments = compile_assignments(&columns, assignments)?;
    let mut affected = 0;

    for row in &mut table.rows {
        if row_matches(&columns, row, selection)? {
            let mut updated = row.clone();
            for (index, expr) in &assignments {
                updated.set_value(*index, eval_expr(&columns, row, expr)?);
            }
            VectorBatch::new(columns.clone(), vec![updated.clone()])?;
            *row = updated;
            affected += 1;
        }
    }

    Ok(affected)
}

fn delete_rows(table: &mut MemoryTable, selection: Option<&Expr>) -> Result<u64> {
    let columns = table.columns.clone();
    let mut kept = Vec::with_capacity(table.rows.len());
    let mut affected = 0;

    for row in table.rows.drain(..) {
        if row_matches(&columns, &row, selection)? {
            affected += 1;
        } else {
            kept.push(row);
        }
    }

    table.rows = kept;
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
        compiled.push((column_index(columns, column)?, expr.clone()));
    }
    Ok(compiled)
}

fn insert_values(table: &mut MemoryTable, columns: &[String], values: &[Expr]) -> Result<()> {
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
        let _ = column_index(table.columns(), column)?;
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

    table.insert(Row::new(row_values))
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

fn apply_projection_cancellable(
    batch: VectorBatch,
    items: &[rnmdb_planner::logical::ProjectionItem],
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    let columns = items
        .iter()
        .map(|item| {
            projection_type(batch.columns(), &item.expr)
                .map(|data_type| ColumnSchema::new(item.name.as_str(), data_type))
        })
        .collect::<Result<Vec<_>>>()?;

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
    let mut groups: Vec<GroupState> = Vec::new();
    for row in batch.rows() {
        cancellation.check()?;
        let key = group_by
            .iter()
            .map(|expr| eval_expr(batch.columns(), row, expr))
            .collect::<Result<Vec<_>>>()?;
        if let Some(group) = groups.iter_mut().find(|group| group.key == key) {
            group.rows.push(row.clone());
        } else {
            groups.push(GroupState {
                key,
                rows: vec![row.clone()],
            });
        }
    }

    let mut rows = Vec::with_capacity(groups.len());
    for group in groups {
        cancellation.check()?;
        let group_batch = VectorBatch::new(batch.columns().to_vec(), group.rows)?;
        let values = items
            .iter()
            .map(|item| grouped_aggregate_value(&group_batch, item))
            .collect::<Result<Vec<_>>>()?;
        rows.push(Row::new(values));
    }
    cancellation.check()?;
    VectorBatch::new(columns, rows)
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

fn aggregate_column_schema(batch: &VectorBatch, item: &AggregateItem) -> Result<ColumnSchema> {
    match &item.function {
        AggregateFunction::CountStar | AggregateFunction::Count(_) => {
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

fn apply_distinct_cancellable(
    batch: VectorBatch,
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    let mut rows = Vec::new();
    for row in batch.rows() {
        cancellation.check()?;
        if !rows.contains(row) {
            rows.push(row.clone());
        }
    }
    cancellation.check()?;
    VectorBatch::new(batch.columns().to_vec(), rows)
}

#[derive(Clone, Debug)]
struct SortRow {
    keys: Vec<SqlValue>,
    original_index: usize,
    row: Row,
}

fn apply_sort_cancellable(
    batch: VectorBatch,
    keys: &[OrderByExpr],
    cancellation: &CancellationToken,
) -> Result<VectorBatch> {
    if keys.is_empty() {
        return Ok(batch);
    }

    let mut rows = Vec::with_capacity(batch.rows().len());
    for (original_index, row) in batch.rows().iter().enumerate() {
        cancellation.check()?;
        let sort_keys = keys
            .iter()
            .map(|key| eval_expr(batch.columns(), row, &key.expr))
            .collect::<Result<Vec<_>>>()?;
        rows.push(SortRow {
            keys: sort_keys,
            original_index,
            row: row.clone(),
        });
    }
    validate_sort_key_types(&rows, keys.len())?;

    rows.sort_by(|left, right| compare_sort_rows(left, right, keys));
    cancellation.check()?;
    VectorBatch::new(
        batch.columns().to_vec(),
        rows.into_iter().map(|row| row.row).collect(),
    )
}

fn validate_sort_key_types(rows: &[SortRow], key_count: usize) -> Result<()> {
    let mut key_types = vec![None; key_count];
    for row in rows {
        for (index, value) in row.keys.iter().enumerate() {
            if value.is_null() {
                continue;
            }
            let data_type = value.data_type();
            if !sortable_type(&data_type) {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("ORDER BY expression type is not sortable: {data_type:?}"),
                ));
            }
            match &key_types[index] {
                Some(existing) if *existing != data_type => {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        "ORDER BY expression produced mixed value types",
                    ));
                }
                Some(_) => {}
                None => key_types[index] = Some(data_type),
            }
        }
    }
    Ok(())
}

fn compare_sort_rows(left: &SortRow, right: &SortRow, keys: &[OrderByExpr]) -> Ordering {
    for (index, key) in keys.iter().enumerate() {
        let ordering = compare_sort_values(&left.keys[index], &right.keys[index]);
        let ordering = match key.direction {
            SortDirection::Asc => ordering,
            SortDirection::Desc => ordering.reverse(),
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.original_index.cmp(&right.original_index)
}

fn compare_sort_values(left: &SqlValue, right: &SqlValue) -> Ordering {
    match (left, right) {
        (SqlValue::Null, SqlValue::Null) => Ordering::Equal,
        (SqlValue::Null, _) => Ordering::Greater,
        (_, SqlValue::Null) => Ordering::Less,
        (SqlValue::Bool(left), SqlValue::Bool(right)) => left.cmp(right),
        (SqlValue::Int64(left), SqlValue::Int64(right)) => left.cmp(right),
        (SqlValue::UInt64(left), SqlValue::UInt64(right)) => left.cmp(right),
        (SqlValue::Text(left), SqlValue::Text(right)) => left.cmp(right),
        (SqlValue::Bytes(left), SqlValue::Bytes(right)) => left.cmp(right),
        _ => Ordering::Equal,
    }
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

fn projection_type(columns: &[ColumnSchema], expr: &Expr) -> Result<SqlType> {
    match expr {
        Expr::Identifier(identifier) => {
            let index = column_index(columns, identifier.as_str())?;
            Ok(columns[index].data_type().clone())
        }
        Expr::Integer(_) => Ok(SqlType::Int64),
        Expr::String(_) => Ok(SqlType::Text),
        Expr::Bool(_) => Ok(SqlType::Bool),
        Expr::Null => Ok(SqlType::Null),
        Expr::CountStar => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "COUNT(*) requires aggregate execution",
        )),
        Expr::Count(_) => Err(RnovError::new(
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
        Expr::Binary { op, .. } if arithmetic_operator(op) => Ok(SqlType::Int64),
        Expr::Binary { op, .. } if text_concat_operator(op) => Ok(SqlType::Text),
        Expr::Binary { op, .. } => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("memory projection does not support operator {op}"),
        )),
        Expr::Unary { op, .. } if unary_arithmetic_operator(op) => Ok(SqlType::Int64),
        Expr::Unary { op, .. } => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("memory projection does not support unary operator {op}"),
        )),
        Expr::Not(_) => Ok(SqlType::Bool),
        Expr::IsNull { .. } => Ok(SqlType::Bool),
        Expr::IsTruth { .. } => Ok(SqlType::Bool),
        Expr::IsDistinctFrom { left, right, .. } => {
            projection_null_safe_comparison_type(columns, left, right)
        }
        Expr::Between { .. } => Ok(SqlType::Bool),
        Expr::InList { .. } => Ok(SqlType::Bool),
        Expr::Like { .. } => Ok(SqlType::Bool),
        Expr::Coalesce(values) => projection_coalesce_type(columns, values),
        Expr::NullIf { left, right } => projection_nullif_type(columns, left, right),
        Expr::Case {
            operand,
            whens,
            else_expr,
        } => projection_case_type(columns, operand.as_deref(), whens, else_expr.as_deref()),
        Expr::Cast { data_type, .. } => Ok(data_type.clone()),
        Expr::Call { name, .. } => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("memory projection does not support function call {name}"),
        )),
    }
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
        SqlType::Bool | SqlType::Int64 | SqlType::UInt64 | SqlType::Text | SqlType::Bytes
    )
}

fn eval_expr(columns: &[ColumnSchema], row: &Row, expr: &Expr) -> Result<SqlValue> {
    match expr {
        Expr::Identifier(identifier) => {
            let index = column_index(columns, identifier.as_str())?;
            Ok(row.values()[index].clone())
        }
        Expr::Integer(_)
        | Expr::String(_)
        | Expr::Bool(_)
        | Expr::Null
        | Expr::Array(_)
        | Expr::HStore(_)
        | Expr::Range { .. } => literal_value(expr),
        Expr::CountStar => Err(RnovError::new(
            ErrorKind::InvalidInput,
            "COUNT(*) requires aggregate execution",
        )),
        Expr::Count(_) => Err(RnovError::new(
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
        Expr::Binary { left, op, right } => eval_binary_expr(columns, row, left, op, right),
        Expr::Unary { op, expr } => eval_unary_arithmetic_expr(columns, row, op, expr),
        Expr::Not(expr) => eval_not_expr(columns, row, expr),
        Expr::IsNull { expr, negated } => eval_is_null_expr(columns, row, expr, *negated),
        Expr::IsTruth {
            expr,
            value,
            negated,
        } => eval_is_truth_expr(columns, row, expr, *value, *negated),
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
        Expr::Call { name, .. } => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("memory projection does not support function call {name}"),
        )),
    }
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
        "+" | "-" | "*" | "/" => eval_arithmetic_expr(columns, row, left, op, right),
        "||" => eval_text_concat_expr(columns, row, left, right),
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
            Ok(SqlValue::Bool(text_value_matches(left, &query, &builder)?))
        }
        other => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("memory projection does not support operator {other}"),
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
    let (left, right) = match (left, right) {
        (SqlValue::Null, _) | (_, SqlValue::Null) => return Ok(SqlValue::Null),
        (SqlValue::Int64(left), SqlValue::Int64(right)) => (left, right),
        _ => {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("arithmetic operator {op} requires INT64 operands"),
            ));
        }
    };
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
        _ => unreachable!("matched arithmetic operator"),
    }
    .ok_or_else(|| RnovError::new(ErrorKind::InvalidInput, "arithmetic overflow"))?;
    Ok(SqlValue::Int64(value))
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
    let SqlValue::Int64(value) = value else {
        if value.is_null() {
            return Ok(SqlValue::Null);
        }
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("unary operator {op} requires INT64 operand"),
        ));
    };
    match op {
        "+" => Ok(SqlValue::Int64(value)),
        "-" => value
            .checked_neg()
            .map(SqlValue::Int64)
            .ok_or_else(|| RnovError::new(ErrorKind::InvalidInput, "arithmetic overflow")),
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
    let mut matched = vec![vec![false; pattern.len() + 1]; value.len() + 1];
    matched[0][0] = true;

    for pattern_index in 0..pattern.len() {
        if pattern[pattern_index] == '%' {
            matched[0][pattern_index + 1] = matched[0][pattern_index];
        }
    }

    for value_index in 0..value.len() {
        for pattern_index in 0..pattern.len() {
            matched[value_index + 1][pattern_index + 1] = match pattern[pattern_index] {
                '%' => {
                    matched[value_index + 1][pattern_index]
                        || matched[value_index][pattern_index + 1]
                }
                '_' => matched[value_index][pattern_index],
                literal => matched[value_index][pattern_index] && value[value_index] == literal,
            };
        }
    }

    matched[value.len()][pattern.len()]
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
    if value.is_null() {
        return Ok(SqlValue::Null);
    }
    let value_type = value.data_type();
    if &value_type == data_type {
        return Ok(value);
    }
    match (value, data_type) {
        (SqlValue::Int64(value), SqlType::Text) => Ok(SqlValue::Text(value.to_string())),
        (SqlValue::Text(value), SqlType::Int64) => {
            let parsed = value.parse::<i64>().map_err(|_| {
                RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("cannot cast TEXT value '{value}' to INT64"),
                )
            })?;
            Ok(SqlValue::Int64(parsed))
        }
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
        "=" | "<>" | "!=" | "<" | "<=" | ">" | ">=" | "@@" | "AND" | "OR"
    )
}

fn arithmetic_operator(op: &str) -> bool {
    matches!(op, "+" | "-" | "*" | "/")
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
        if text_value_matches(row.values()[index].clone(), &query, &builder)? {
            rows.push(row.clone());
        }
    }

    cancellation.check()?;
    VectorBatch::new(batch.columns().to_vec(), rows)
}

fn text_value_matches(
    value: SqlValue,
    query: &TextQuery,
    builder: &TextVectorBuilder<SimpleTokenizer>,
) -> Result<bool> {
    match value {
        SqlValue::Null => Ok(false),
        SqlValue::Text(text) => Ok(query.matches(&builder.build(&text)?)),
        SqlValue::TextVector(vector) => Ok(query.matches(&vector)),
        other => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!(
                "text search cannot evaluate value type {:?}",
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
        Expr::String(value) => Ok(SqlValue::Text(value.clone())),
        Expr::Bool(value) => Ok(SqlValue::Bool(*value)),
        Expr::Null => Ok(SqlValue::Null),
        Expr::Array(values) => array_literal_value(values),
        Expr::HStore(entries) => hstore_literal_value(entries),
        Expr::Range {
            lower,
            upper,
            bounds,
        } => range_literal_value(lower, upper, bounds.lower_inclusive, bounds.upper_inclusive),
        _ => Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("unsupported memory literal: {expr}"),
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
