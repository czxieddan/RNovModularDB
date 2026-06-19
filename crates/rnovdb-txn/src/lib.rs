use std::collections::{BTreeMap, BTreeSet};

use rnovdb_common::{
    ErrorKind, Result, RnovError,
    ids::{SnapshotId, TransactionId},
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

#[derive(Clone, Debug)]
pub struct TransactionManager {
    next_transaction_id: u64,
    next_snapshot_id: u64,
    states: BTreeMap<TransactionId, TransactionState>,
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
            states: BTreeMap::new(),
        }
    }

    pub fn begin(&mut self, isolation_level: IsolationLevel) -> Result<Transaction> {
        let id = TransactionId::new(self.next_transaction_id);
        self.next_transaction_id += 1;
        self.states.insert(id, TransactionState::Active);
        Ok(Transaction {
            id,
            isolation_level,
        })
    }

    pub fn state(&self, transaction_id: TransactionId) -> Option<TransactionState> {
        self.states.get(&transaction_id).copied()
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
            .states
            .iter()
            .filter_map(|(id, state)| (*state == TransactionState::Committed).then_some(*id))
            .collect();
        let active = self
            .states
            .iter()
            .filter_map(|(id, state)| (*state == TransactionState::Active).then_some(*id))
            .collect();

        Ok(Snapshot {
            snapshot_id,
            isolation_level,
            committed,
            active,
        })
    }

    fn finish(&mut self, transaction_id: TransactionId, new_state: TransactionState) -> Result<()> {
        let state = self.states.get_mut(&transaction_id).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("transaction not found: {transaction_id}"),
            )
        })?;
        if *state != TransactionState::Active {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("transaction is not active: {transaction_id}"),
            ));
        }
        *state = new_state;
        Ok(())
    }
}
