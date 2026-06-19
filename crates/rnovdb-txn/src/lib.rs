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
