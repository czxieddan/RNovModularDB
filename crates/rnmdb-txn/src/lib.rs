use std::collections::{BTreeMap, BTreeSet};

use rnmdb_common::{
    ErrorKind, Result, RnovError,
    ids::{RelationId, SnapshotId, TransactionId},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IsolationLevel {
    ReadCommitted,
    RepeatableRead,
    Serializable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionState {
    Active,
    Committed,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transaction {
    id: TransactionId,
    isolation_level: IsolationLevel,
}

impl Transaction {
    pub fn id(self) -> TransactionId {
        self.id
    }

    pub fn isolation_level(self) -> IsolationLevel {
        self.isolation_level
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    snapshot_id: SnapshotId,
    isolation_level: IsolationLevel,
    committed: BTreeSet<TransactionId>,
    active: BTreeSet<TransactionId>,
}

impl Snapshot {
    pub fn snapshot_id(&self) -> SnapshotId {
        self.snapshot_id
    }

    pub fn isolation_level(&self) -> IsolationLevel {
        self.isolation_level
    }

    pub fn is_committed(&self, transaction_id: TransactionId) -> bool {
        self.committed.contains(&transaction_id)
    }

    pub fn is_active(&self, transaction_id: TransactionId) -> bool {
        self.active.contains(&transaction_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionChain<T> {
    versions: Vec<Version<T>>,
}

impl<T> Default for VersionChain<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> VersionChain<T> {
    pub fn new() -> Self {
        Self {
            versions: Vec::new(),
        }
    }

    pub fn push_insert(&mut self, created_by: TransactionId, value: T) -> Result<()> {
        if created_by == TransactionId::new(0) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "version creator transaction cannot be zero",
            ));
        }
        self.versions.push(Version {
            created_by,
            deleted_by: None,
            value,
        });
        Ok(())
    }

    pub fn mark_deleted(&mut self, deleted_by: TransactionId) -> Result<()> {
        let version = self.versions.last_mut().ok_or_else(|| {
            RnovError::new(ErrorKind::NotFound, "cannot delete an empty version chain")
        })?;
        if version.deleted_by.is_some() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "latest version is already marked deleted",
            ));
        }
        version.deleted_by = Some(deleted_by);
        Ok(())
    }

    pub fn visible(&self, snapshot: &Snapshot) -> Option<&T> {
        self.versions
            .iter()
            .rev()
            .find(|version| version.is_visible(snapshot))
            .map(|version| &version.value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Version<T> {
    created_by: TransactionId,
    deleted_by: Option<TransactionId>,
    value: T,
}

impl<T> Version<T> {
    fn is_visible(&self, snapshot: &Snapshot) -> bool {
        snapshot.is_committed(self.created_by)
            && self
                .deleted_by
                .is_none_or(|deleted_by| !snapshot.is_committed(deleted_by))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LockTarget {
    Row {
        relation_id: RelationId,
        row_id: u64,
    },
}

impl LockTarget {
    pub fn row(relation_id: RelationId, row_id: u64) -> Self {
        Self::Row {
            relation_id,
            row_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockResult {
    Acquired,
    Waiting { blocking: TransactionId },
}

#[derive(Clone, Debug, Default)]
pub struct LockManager {
    exclusive: BTreeMap<LockTarget, TransactionId>,
    waits_for: BTreeMap<TransactionId, BTreeSet<TransactionId>>,
}

impl LockManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn acquire_exclusive(
        &mut self,
        transaction_id: TransactionId,
        target: LockTarget,
    ) -> Result<LockResult> {
        match self.exclusive.get(&target).copied() {
            None => {
                self.exclusive.insert(target, transaction_id);
                self.clear_wait(transaction_id);
                Ok(LockResult::Acquired)
            }
            Some(holder) if holder == transaction_id => Ok(LockResult::Acquired),
            Some(holder) => {
                self.waits_for
                    .entry(transaction_id)
                    .or_default()
                    .insert(holder);
                if self.has_wait_path(holder, transaction_id) {
                    self.remove_wait_edge(transaction_id, holder);
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        format!("deadlock detected between {transaction_id} and {holder}"),
                    ));
                }
                Ok(LockResult::Waiting { blocking: holder })
            }
        }
    }

    pub fn release_all(&mut self, transaction_id: TransactionId) {
        self.exclusive.retain(|_, holder| *holder != transaction_id);
        self.waits_for.remove(&transaction_id);
        for blockers in self.waits_for.values_mut() {
            blockers.remove(&transaction_id);
        }
    }

    fn clear_wait(&mut self, transaction_id: TransactionId) {
        self.waits_for.remove(&transaction_id);
    }

    fn remove_wait_edge(&mut self, waiter: TransactionId, blocker: TransactionId) {
        if let Some(blockers) = self.waits_for.get_mut(&waiter) {
            blockers.remove(&blocker);
            if blockers.is_empty() {
                self.waits_for.remove(&waiter);
            }
        }
    }

    fn has_wait_path(&self, start: TransactionId, target: TransactionId) -> bool {
        let mut stack = vec![start];
        let mut seen = BTreeSet::new();

        while let Some(current) = stack.pop() {
            if current == target {
                return true;
            }
            if !seen.insert(current) {
                continue;
            }
            if let Some(next) = self.waits_for.get(&current) {
                stack.extend(next.iter().copied());
            }
        }

        false
    }
}

#[derive(Clone, Debug)]
pub struct TransactionManager {
    next_transaction_id: u64,
    next_snapshot_id: u64,
    transactions: BTreeMap<TransactionId, TransactionEntry>,
}

impl Default for TransactionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionManager {
    pub fn new() -> Self {
        Self {
            next_transaction_id: 1,
            next_snapshot_id: 1,
            transactions: BTreeMap::new(),
        }
    }

    pub fn begin(&mut self, isolation_level: IsolationLevel) -> Result<Transaction> {
        let id = TransactionId::new(self.next_transaction_id);
        self.next_transaction_id += 1;
        self.transactions.insert(
            id,
            TransactionEntry {
                state: TransactionState::Active,
                isolation_level,
                pinned_snapshot: None,
            },
        );
        Ok(Transaction {
            id,
            isolation_level,
        })
    }

    pub fn state(&self, transaction_id: TransactionId) -> Option<TransactionState> {
        self.transactions
            .get(&transaction_id)
            .map(|entry| entry.state)
    }

    pub fn commit(&mut self, transaction_id: TransactionId) -> Result<()> {
        self.finish(transaction_id, TransactionState::Committed)
    }

    pub fn abort(&mut self, transaction_id: TransactionId) -> Result<()> {
        self.finish(transaction_id, TransactionState::Aborted)
    }

    pub fn snapshot(&mut self, isolation_level: IsolationLevel) -> Result<Snapshot> {
        let snapshot_id = SnapshotId::new(self.next_snapshot_id);
        self.next_snapshot_id += 1;

        let committed = self
            .transactions
            .iter()
            .filter_map(|(id, entry)| (entry.state == TransactionState::Committed).then_some(*id))
            .collect();
        let active = self
            .transactions
            .iter()
            .filter_map(|(id, entry)| (entry.state == TransactionState::Active).then_some(*id))
            .collect();

        Ok(Snapshot {
            snapshot_id,
            isolation_level,
            committed,
            active,
        })
    }

    pub fn snapshot_for(&mut self, transaction_id: TransactionId) -> Result<Snapshot> {
        let (state, isolation_level, pinned_snapshot) = {
            let entry = self.transactions.get(&transaction_id).ok_or_else(|| {
                RnovError::new(
                    ErrorKind::NotFound,
                    format!("transaction not found: {transaction_id}"),
                )
            })?;
            (
                entry.state,
                entry.isolation_level,
                entry.pinned_snapshot.clone(),
            )
        };
        if state != TransactionState::Active {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("transaction is not active: {transaction_id}"),
            ));
        }

        match isolation_level {
            IsolationLevel::ReadCommitted => self.snapshot(isolation_level),
            IsolationLevel::RepeatableRead | IsolationLevel::Serializable => {
                if let Some(snapshot) = pinned_snapshot {
                    return Ok(snapshot);
                }
                let snapshot = self.snapshot(isolation_level)?;
                self.transactions
                    .get_mut(&transaction_id)
                    .expect("transaction was verified")
                    .pinned_snapshot = Some(snapshot.clone());
                Ok(snapshot)
            }
        }
    }

    fn finish(&mut self, transaction_id: TransactionId, new_state: TransactionState) -> Result<()> {
        let entry = self.transactions.get_mut(&transaction_id).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("transaction not found: {transaction_id}"),
            )
        })?;
        if entry.state != TransactionState::Active {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("transaction is not active: {transaction_id}"),
            ));
        }
        entry.state = new_state;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct TransactionEntry {
    state: TransactionState,
    isolation_level: IsolationLevel,
    pinned_snapshot: Option<Snapshot>,
}
