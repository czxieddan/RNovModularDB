use std::{
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_common::{ErrorKind, Result, RnovError, ids::RoleId};
use rnmdb_sql::{
    ast::{Statement, TransactionAction},
    parser::parse_statement,
};
use rnmdb_storage::{CatalogCommitFailure, CatalogCommitFailureKind};

pub(super) struct SharedDatabase {
    state: Mutex<SharedDatabaseState>,
    durable: bool,
}

struct SharedDatabaseState {
    session: LocalSession,
    generation: u64,
    poisoned: bool,
}

struct ConnectionTransaction {
    session: LocalSession,
    base_generation: u64,
    dirty: bool,
}

pub(super) struct SharedConnection {
    database: Arc<SharedDatabase>,
    role_id: Option<RoleId>,
    transaction: Option<ConnectionTransaction>,
    close_after_response: bool,
}

impl fmt::Debug for SharedDatabase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedDatabase")
            .field("durable", &self.durable)
            .finish_non_exhaustive()
    }
}

impl SharedDatabase {
    pub(super) fn new(session: LocalSession, durable: bool) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(SharedDatabaseState {
                session,
                generation: 0,
                poisoned: false,
            }),
            durable,
        })
    }

    pub(super) fn connect(self: &Arc<Self>, role_id: Option<RoleId>) -> SharedConnection {
        SharedConnection {
            database: Arc::clone(self),
            role_id,
            transaction: None,
            close_after_response: false,
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, SharedDatabaseState>> {
        self.state.lock().map_err(|_| {
            RnovError::new(
                ErrorKind::Internal,
                "shared database state lock is poisoned",
            )
        })
    }
}

impl SharedConnection {
    pub(super) fn execute(&mut self, sql: &str) -> Result<CommandOutput> {
        let action = transaction_action(sql)?;
        match (self.transaction.is_some(), action) {
            (false, Some(TransactionAction::Begin)) => self.begin_transaction(sql),
            (true, Some(TransactionAction::Commit)) => self.commit_transaction(sql),
            (true, Some(TransactionAction::Rollback)) => self.rollback_transaction(sql),
            (true, _) => self.execute_transaction_command(sql),
            (false, _) => self.execute_autocommit(sql),
        }
    }

    pub(super) fn close(&mut self) -> Result<()> {
        let Some(mut transaction) = self.transaction.take() else {
            return Ok(());
        };
        transaction.session.execute("ROLLBACK;").map(|_| ())
    }

    pub(super) fn close_after_response(&self) -> bool {
        self.close_after_response
    }

    fn begin_transaction(&mut self, sql: &str) -> Result<CommandOutput> {
        let state = self.database.lock()?;
        ensure_database_available(&state)?;
        let snapshot = state.session.committed_snapshot()?;
        let generation = state.generation;
        drop(state);

        let mut session = LocalSession::from_committed_snapshot(snapshot)?;
        set_connection_role(&mut session, self.role_id)?;
        let output = session.execute(sql)?;
        self.transaction = Some(ConnectionTransaction {
            session,
            base_generation: generation,
            dirty: false,
        });
        Ok(output)
    }

    fn execute_transaction_command(&mut self, sql: &str) -> Result<CommandOutput> {
        let transaction = self
            .transaction
            .as_mut()
            .expect("active transaction must exist");
        let output = transaction.session.execute(sql)?;
        transaction.dirty |= output_changes_state(&output);
        Ok(output)
    }

    fn execute_autocommit(&mut self, sql: &str) -> Result<CommandOutput> {
        let mut state = self.database.lock()?;
        ensure_database_available(&state)?;
        let snapshot = state.session.committed_snapshot()?;
        let mut candidate = LocalSession::from_committed_snapshot(snapshot)?;
        set_connection_role(&mut candidate, self.role_id)?;
        let output = candidate.execute(sql)?;
        if !output_changes_state(&output) {
            return Ok(output);
        }
        let next_generation = next_generation(state.generation)?;
        let snapshot = candidate.committed_snapshot()?;
        persist_and_publish_snapshot(&mut state, self.database.durable, snapshot)?;
        state.generation = next_generation;
        Ok(output)
    }

    fn commit_transaction(&mut self, sql: &str) -> Result<CommandOutput> {
        let dirty = self
            .transaction
            .as_ref()
            .expect("active transaction must exist")
            .dirty;
        if !dirty {
            let mut transaction = self
                .transaction
                .take()
                .expect("active transaction must exist");
            return match transaction.session.execute(sql) {
                Ok(output) => Ok(output),
                Err(error) => {
                    self.transaction = Some(transaction);
                    Err(error)
                }
            };
        }

        let base_generation = self
            .transaction
            .as_ref()
            .expect("active transaction must exist")
            .base_generation;
        let mut state = self.database.lock()?;
        ensure_database_available(&state)?;
        if state.generation != base_generation {
            return Err(RnovError::new(
                ErrorKind::Storage,
                "transaction conflict: committed database state changed; rollback and retry",
            ));
        }
        let next_generation = next_generation(state.generation)?;

        let mut transaction = self
            .transaction
            .take()
            .expect("active transaction must exist");
        let output = match transaction.session.execute(sql) {
            Ok(output) => output,
            Err(error) => {
                self.transaction = Some(transaction);
                return Err(error);
            }
        };
        let snapshot = match transaction.session.committed_snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.close_after_response = true;
                return Err(error);
            }
        };
        if let Err(error) =
            persist_and_publish_snapshot(&mut state, self.database.durable, snapshot)
        {
            self.close_after_response = true;
            return Err(error);
        }
        state.generation = next_generation;
        Ok(output)
    }

    fn rollback_transaction(&mut self, sql: &str) -> Result<CommandOutput> {
        let mut transaction = self
            .transaction
            .take()
            .expect("active transaction must exist");
        match transaction.session.execute(sql) {
            Ok(output) => Ok(output),
            Err(error) => {
                self.transaction = Some(transaction);
                Err(error)
            }
        }
    }
}

fn transaction_action(sql: &str) -> Result<Option<TransactionAction>> {
    match parse_statement(sql)? {
        Statement::Transaction { action } => Ok(Some(action)),
        _ => Ok(None),
    }
}

fn set_connection_role(session: &mut LocalSession, role_id: Option<RoleId>) -> Result<()> {
    if let Some(role_id) = role_id {
        session.set_active_role(role_id)?;
    }
    Ok(())
}

fn output_changes_state(output: &CommandOutput) -> bool {
    matches!(
        output,
        CommandOutput::RowsAffected(affected) if *affected != 0
    ) || matches!(output, CommandOutput::SchemaChanged)
}

fn ensure_database_available(state: &SharedDatabaseState) -> Result<()> {
    if state.poisoned {
        return Err(RnovError::new(
            ErrorKind::Storage,
            "database is unavailable after an indeterminate durable commit; restart required",
        ));
    }
    Ok(())
}

fn persist_and_publish_snapshot(
    state: &mut SharedDatabaseState,
    durable: bool,
    snapshot: rnmdb_cli::CommittedSessionSnapshot,
) -> Result<()> {
    if durable
        && let Err(failure) = state
            .session
            .checkpoint_committed_snapshot_with_outcome(&snapshot)
    {
        return handle_checkpoint_failure(state, failure);
    }
    if let Err(error) = state.session.replace_committed_state(snapshot) {
        if durable {
            state.poisoned = true;
            return Err(RnovError::new(
                ErrorKind::Internal,
                "durable commit succeeded but shared state publication failed; restart required",
            )
            .with_private_context(error.to_string()));
        }
        return Err(error);
    }
    Ok(())
}

fn handle_checkpoint_failure(
    state: &mut SharedDatabaseState,
    failure: CatalogCommitFailure,
) -> Result<()> {
    let kind = failure.kind();
    let error = failure.into_error();
    if kind == CatalogCommitFailureKind::OutcomeUnknown {
        state.poisoned = true;
        return Err(RnovError::new(
            ErrorKind::Storage,
            "durable commit outcome is indeterminate; database requires restart",
        )
        .with_private_context(error.to_string()));
    }
    Err(error)
}

fn next_generation(generation: u64) -> Result<u64> {
    generation.checked_add(1).ok_or_else(|| {
        RnovError::new(
            ErrorKind::Internal,
            "shared database generation counter overflowed",
        )
    })
}
