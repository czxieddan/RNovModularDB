// crates/rnmdb-server/src/lib.rs - RNovModularDB source module.
// Copyright (C) 2026 czxieddan
//
// The AHCL-covered material identified below forms part of
// RNovModularDB and is provided under version 1.2 of the
// Aperip Heimdall Commons License (AHCL). The applicable version is also subject
// to the AHCL provisions concerning Continuous AHCL Licensing Segments and
// migration to later official versions.
//
// AHCL-covered portions: the whole file
//
// Subject to Section 3.1 of AHCL, after having a reasonable opportunity to
// read AHCL, all applicable Additional Restrictions, and all version notices,
// a person accepts the corresponding terms by engaging in Use of the
// AHCL-covered material identified above. Any separate or affirmative assent
// required by applicable mandatory law must still be obtained.
//
// License notice updated: October 15, 2026.
// Official AHCL text and public notices: https://ahcl.aperip.com
// Applicable LICENSE: LICENSE
// Paths below are relative to the directory containing that LICENSE.
// AHCL Materials Directory: .ahcl/
// Repository official or recognized AHCL copy: .ahcl/AHCL-1.2.md
// Canonical repository: https://github.com/czxieddan/RNovModularDB
// Project notice: .ahcl/AHCL-PROJECT-NOTICE.md
// Version records: .ahcl/AHCL-VERSION-ADOPTION.md
// Source and history: .ahcl/AHCL-SOURCE.md
// Dependencies and licenses: .ahcl/AHCL-DEPENDENCIES.md
// Additional Restrictions: None.
// SPDX-License-Identifier: LicenseRef-AHCL-1.2
use std::{
    collections::BTreeMap,
    fmt,
    net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use rnmdb_cli::LocalSession;
use rnmdb_common::ids::{DatabaseId, InstanceId};
use rnmdb_common::{ErrorKind, Result, RnovError};
use rnmdb_instance::{InstanceConfig, InstanceManager, ResourceLimits, ResourceUsage};
use rnmdb_security::LocalCredentialStore;
use rnmdb_storage::PageCryptoKey;

mod shared;
mod sql_protocol;

use shared::{SharedConnection, SharedDatabase};
use sql_protocol::{handle_sql_client, reject_busy_client, spawn_client_thread};

const SQL_LINE_PROTOCOL_VERSION: u16 = 1;
const MAX_ACTIVE_CLIENTS: usize = 64;
const MAX_SQL_COMMAND_BYTES: usize = 65_536;
const SERVER_ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(50);
const CLIENT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const FORCED_CLIENT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Whether the shared database can safely execute more commands.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SqlDatabaseHealth {
    /// The shared committed state is available.
    Available,
    /// A durable commit had an indeterminate outcome and the process must be restarted.
    RestartRequired,
}

/// Stable limits and feature flags for the built-in SQL line protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqlProtocolCapabilities {
    protocol_version: u16,
    max_active_clients: usize,
    max_command_bytes: usize,
}

impl SqlProtocolCapabilities {
    /// Returns the management-visible protocol revision.
    ///
    /// The line protocol does not currently negotiate this value on the wire.
    pub fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub fn max_active_clients(&self) -> usize {
        self.max_active_clients
    }

    pub fn max_command_bytes(&self) -> usize {
        self.max_command_bytes
    }

    pub fn supports_authentication(&self) -> bool {
        true
    }

    pub fn supports_health_check(&self) -> bool {
        true
    }

    pub fn supports_explicit_transactions(&self) -> bool {
        true
    }

    pub fn supports_transport_security(&self) -> bool {
        false
    }
}

/// A best-effort, read-only view of one SQL server runtime.
///
/// Collecting the database fields acquires internal synchronization and may
/// briefly block. Individual fields are sampled separately, so callers should
/// not treat the value as an atomic point-in-time snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqlServerStatus {
    runtime_mode: EmbeddedRuntimeMode,
    authentication_required: bool,
    active_clients: usize,
    committed_generation: u64,
    database_health: SqlDatabaseHealth,
    shutdown_requested: bool,
}

impl SqlServerStatus {
    pub fn runtime_mode(&self) -> EmbeddedRuntimeMode {
        self.runtime_mode
    }

    pub fn authentication_required(&self) -> bool {
        self.authentication_required
    }

    pub fn active_clients(&self) -> usize {
        self.active_clients
    }

    /// Returns a process-local generation that advances after each published
    /// state change. It is not a durable database format revision.
    pub fn committed_generation(&self) -> u64 {
        self.committed_generation
    }

    pub fn database_health(&self) -> SqlDatabaseHealth {
        self.database_health
    }

    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_requested
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmbeddedRuntimeMode {
    TemporaryMemory,
    SingleFile,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SingleFileRuntimeConfig {
    path: PathBuf,
    page_key: PageCryptoKey,
}

impl SingleFileRuntimeConfig {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn page_key(&self) -> PageCryptoKey {
        self.page_key
    }
}

impl fmt::Debug for SingleFileRuntimeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SingleFileRuntimeConfig")
            .field("path", &self.path)
            .field("page_key", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct EmbeddedRuntimeConfig {
    instance: InstanceConfig,
    mode: EmbeddedRuntimeMode,
    temporary: bool,
    single_file: Option<SingleFileRuntimeConfig>,
    credentials: Option<LocalCredentialStore>,
}

impl fmt::Debug for EmbeddedRuntimeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmbeddedRuntimeConfig")
            .field("instance", &self.instance)
            .field("mode", &self.mode)
            .field("temporary", &self.temporary)
            .field("single_file", &self.single_file)
            .field("authentication_required", &self.authentication_required())
            .finish()
    }
}

impl EmbeddedRuntimeConfig {
    pub fn temporary_memory(instance_id: InstanceId, database_id: DatabaseId) -> Self {
        Self::temporary_memory_with_limits(instance_id, database_id, ResourceLimits::default())
    }

    pub fn temporary_memory_with_limits(
        instance_id: InstanceId,
        database_id: DatabaseId,
        limits: ResourceLimits,
    ) -> Self {
        Self {
            instance: InstanceConfig::isolated(instance_id, database_id, limits),
            mode: EmbeddedRuntimeMode::TemporaryMemory,
            temporary: true,
            single_file: None,
            credentials: None,
        }
    }

    pub fn single_file_with_key(
        instance_id: InstanceId,
        database_id: DatabaseId,
        path: impl AsRef<Path>,
        page_key: PageCryptoKey,
    ) -> Self {
        Self::single_file_with_key_and_limits(
            instance_id,
            database_id,
            path,
            page_key,
            ResourceLimits::default(),
        )
    }

    pub fn single_file_with_key_and_limits(
        instance_id: InstanceId,
        database_id: DatabaseId,
        path: impl AsRef<Path>,
        page_key: PageCryptoKey,
        limits: ResourceLimits,
    ) -> Self {
        Self {
            instance: InstanceConfig::isolated(instance_id, database_id, limits),
            mode: EmbeddedRuntimeMode::SingleFile,
            temporary: false,
            single_file: Some(SingleFileRuntimeConfig {
                path: path.as_ref().to_path_buf(),
                page_key,
            }),
            credentials: None,
        }
    }

    pub fn with_credentials(mut self, credentials: LocalCredentialStore) -> Self {
        self.credentials = Some(credentials);
        self
    }

    pub fn instance(&self) -> &InstanceConfig {
        &self.instance
    }

    pub fn mode(&self) -> EmbeddedRuntimeMode {
        self.mode
    }

    pub fn is_temporary(&self) -> bool {
        self.temporary
    }

    pub fn is_memory_only(&self) -> bool {
        matches!(self.mode, EmbeddedRuntimeMode::TemporaryMemory)
    }

    pub fn disk_writes_allowed(&self) -> bool {
        matches!(self.mode, EmbeddedRuntimeMode::SingleFile)
    }

    pub fn authentication_required(&self) -> bool {
        self.credentials.is_some()
    }

    pub fn credentials(&self) -> Option<&LocalCredentialStore> {
        self.credentials.as_ref()
    }

    pub fn single_file(&self) -> Option<&SingleFileRuntimeConfig> {
        self.single_file.as_ref()
    }
}

#[derive(Debug)]
pub struct SqlTcpServer {
    listener: TcpListener,
    runtime: SqlServerRuntime,
    clients: Arc<ClientRegistry>,
    serving: AtomicBool,
}

/// A cloneable control-plane handle that does not expose mutable database state.
#[derive(Clone, Debug)]
pub struct SqlServerHandle {
    runtime: SqlServerRuntime,
    clients: Arc<ClientRegistry>,
}

impl SqlServerHandle {
    /// Requests shutdown of a server running through [`SqlTcpServer::serve`] or
    /// [`SqlTcpServer::serve_until`].
    pub fn request_shutdown(&self) {
        self.runtime.request_shutdown();
    }

    pub fn status(&self) -> Result<SqlServerStatus> {
        let database = self.runtime.database.status()?;
        Ok(SqlServerStatus {
            runtime_mode: self.runtime.config().mode(),
            authentication_required: self.runtime.config().authentication_required(),
            active_clients: self.clients.active_count(),
            committed_generation: database.committed_generation,
            database_health: if database.restart_required {
                SqlDatabaseHealth::RestartRequired
            } else {
                SqlDatabaseHealth::Available
            },
            shutdown_requested: self.runtime.shutdown_requested(),
        })
    }

    pub fn protocol_capabilities(&self) -> SqlProtocolCapabilities {
        SqlProtocolCapabilities {
            protocol_version: SQL_LINE_PROTOCOL_VERSION,
            max_active_clients: MAX_ACTIVE_CLIENTS,
            max_command_bytes: MAX_SQL_COMMAND_BYTES,
        }
    }
}

impl SqlTcpServer {
    pub fn bind(address: impl ToSocketAddrs, config: EmbeddedRuntimeConfig) -> Result<Self> {
        let listener = TcpListener::bind(address)
            .map_err(|err| io_error("failed to bind SQL TCP listener", err))?;
        let embedded = EmbeddedRuntime::new(config)?;
        let database = SharedDatabase::new(
            embedded.open_session()?,
            embedded.config().disk_writes_allowed(),
        );
        let shutdown = Arc::new(AtomicBool::new(false));
        Ok(Self {
            listener,
            runtime: SqlServerRuntime {
                embedded,
                database,
                shutdown,
            },
            clients: Arc::new(ClientRegistry::new()),
            serving: AtomicBool::new(false),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|err| io_error("failed to read SQL TCP listener address", err))
    }

    pub fn management_handle(&self) -> SqlServerHandle {
        SqlServerHandle {
            runtime: self.runtime.clone(),
            clients: Arc::clone(&self.clients),
        }
    }

    pub fn status(&self) -> Result<SqlServerStatus> {
        self.management_handle().status()
    }

    pub fn protocol_capabilities(&self) -> SqlProtocolCapabilities {
        self.management_handle().protocol_capabilities()
    }

    pub fn accept_one(&self) -> Result<()> {
        let _permit = ServerLoopPermit::acquire(self)?;
        let stream = self.accept_client()?;
        handle_sql_client(stream, &self.runtime)
    }

    /// Serves clients until a management handle requests shutdown, then drains
    /// active clients for a bounded period.
    pub fn serve(&self) -> Result<()> {
        self.serve_until_requested(None)
    }

    /// Serves clients until `shutdown` is set, then stops client I/O and waits
    /// for a bounded drain period.
    pub fn serve_until(&self, shutdown: &AtomicBool) -> Result<()> {
        self.serve_until_requested(Some(shutdown))
    }

    fn serve_until_requested(&self, shutdown: Option<&AtomicBool>) -> Result<()> {
        let _permit = ServerLoopPermit::acquire(self)?;
        self.listener
            .set_nonblocking(true)
            .map_err(|err| io_error("failed to enable nonblocking SQL listener", err))?;
        let serve_result = self.serve_nonblocking_until(shutdown);
        self.runtime.request_shutdown();
        let blocking_result = self
            .listener
            .set_nonblocking(false)
            .map_err(|err| io_error("failed to restore blocking SQL listener", err));
        let shutdown_result = self.drain_clients_with_forced_shutdown();
        let result = combine_phase_results(
            serve_result,
            blocking_result,
            "restoring the blocking listener failed",
        );
        combine_phase_results(result, shutdown_result, "client shutdown cleanup failed")
    }

    fn drain_clients_with_forced_shutdown(&self) -> Result<()> {
        let graceful_result = self.drain_clients(CLIENT_DRAIN_TIMEOUT);
        if graceful_result.is_ok() {
            return graceful_result;
        }
        let forced_result = self
            .clients
            .shutdown_all()
            .and_then(|()| self.drain_clients(FORCED_CLIENT_DRAIN_TIMEOUT));
        combine_phase_results(
            graceful_result,
            forced_result,
            "forced SQL client shutdown failed",
        )
    }

    fn drain_clients(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        while self.active_client_count() != 0 && Instant::now() < deadline {
            thread::sleep(SERVER_ACCEPT_RETRY_DELAY);
        }
        let remaining = self.active_client_count();
        if remaining == 0 {
            return Ok(());
        }
        Err(RnovError::new(
            ErrorKind::Canceled,
            format!("shutdown timed out with {remaining} active SQL client(s)"),
        ))
    }

    pub fn active_client_count(&self) -> usize {
        self.clients.active_count()
    }

    fn serve_nonblocking_until(&self, shutdown: Option<&AtomicBool>) -> Result<()> {
        while !self.runtime.shutdown_requested()
            && !shutdown.is_some_and(|shutdown| shutdown.load(Ordering::Acquire))
        {
            match self.listener.accept() {
                Ok((stream, _)) => self.dispatch_client(stream)?,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(SERVER_ACCEPT_RETRY_DELAY);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(io_error("failed to accept SQL TCP client", error)),
            }
        }
        Ok(())
    }

    fn accept_client(&self) -> Result<TcpStream> {
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => return Ok(stream),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(io_error("failed to accept SQL TCP client", error)),
            }
        }
    }

    fn dispatch_client(&self, stream: TcpStream) -> Result<()> {
        stream
            .set_nonblocking(false)
            .map_err(|err| io_error("failed to configure accepted SQL client", err))?;
        let Some(permit) = ClientPermit::acquire(&self.clients, &stream)? else {
            reject_busy_client(stream);
            return Ok(());
        };
        spawn_client_thread(stream, self.runtime.clone(), permit)
    }
}

struct ServerLoopPermit<'a> {
    serving: &'a AtomicBool,
}

impl<'a> ServerLoopPermit<'a> {
    fn acquire(server: &'a SqlTcpServer) -> Result<Self> {
        if server.runtime.shutdown_requested() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "SQL TCP server cannot start after shutdown has been requested",
            ));
        }
        server
            .serving
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                RnovError::new(
                    ErrorKind::InvalidInput,
                    "SQL TCP server is already serving clients",
                )
            })?;
        if server.runtime.shutdown_requested() {
            server.serving.store(false, Ordering::Release);
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "SQL TCP server cannot start after shutdown has been requested",
            ));
        }
        Ok(Self {
            serving: &server.serving,
        })
    }
}

impl Drop for ServerLoopPermit<'_> {
    fn drop(&mut self) {
        self.serving.store(false, Ordering::Release);
    }
}

#[derive(Clone, Debug)]
struct SqlServerRuntime {
    embedded: EmbeddedRuntime,
    database: Arc<SharedDatabase>,
    shutdown: Arc<AtomicBool>,
}

impl SqlServerRuntime {
    fn config(&self) -> &EmbeddedRuntimeConfig {
        self.embedded.config()
    }

    fn open_connection(&self, role_id: Option<rnmdb_common::ids::RoleId>) -> SharedConnection {
        self.database.connect(role_id)
    }

    fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    fn shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
struct ClientRegistry {
    active: AtomicUsize,
    next_id: AtomicU64,
    streams: Mutex<BTreeMap<u64, TcpStream>>,
}

impl ClientRegistry {
    fn new() -> Self {
        Self {
            active: AtomicUsize::new(0),
            next_id: AtomicU64::new(1),
            streams: Mutex::new(BTreeMap::new()),
        }
    }

    fn active_count(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    fn shutdown_all(&self) -> Result<()> {
        let streams = self.streams.lock().map_err(|_| {
            RnovError::new(ErrorKind::Internal, "SQL client registry lock is poisoned")
        })?;
        for stream in streams.values() {
            let _ = stream.set_nonblocking(true);
            let _ = stream.shutdown(Shutdown::Both);
        }
        Ok(())
    }
}

struct ClientPermit {
    clients: Arc<ClientRegistry>,
    id: u64,
}

impl ClientPermit {
    fn acquire(clients: &Arc<ClientRegistry>, stream: &TcpStream) -> Result<Option<Self>> {
        if clients
            .active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_ACTIVE_CLIENTS).then_some(active + 1)
            })
            .is_err()
        {
            return Ok(None);
        }
        let id = clients.next_id.fetch_add(1, Ordering::AcqRel);
        let tracked = match stream.try_clone() {
            Ok(tracked) => tracked,
            Err(error) => {
                clients.active.fetch_sub(1, Ordering::AcqRel);
                return Err(io_error("failed to track SQL TCP client", error));
            }
        };
        let mut streams = match clients.streams.lock() {
            Ok(streams) => streams,
            Err(_) => {
                clients.active.fetch_sub(1, Ordering::AcqRel);
                return Err(RnovError::new(
                    ErrorKind::Internal,
                    "SQL client registry lock is poisoned",
                ));
            }
        };
        streams.insert(id, tracked);
        drop(streams);
        Ok(Some(Self {
            clients: Arc::clone(clients),
            id,
        }))
    }
}

impl Drop for ClientPermit {
    fn drop(&mut self) {
        if let Ok(mut streams) = self.clients.streams.lock() {
            streams.remove(&self.id);
        }
        self.clients.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(feature = "tokio-runtime")]
#[derive(Debug)]
pub struct TokioEmbeddedRuntime {
    runtime: tokio::runtime::Runtime,
    embedded: EmbeddedRuntime,
}

#[cfg(feature = "tokio-runtime")]
impl TokioEmbeddedRuntime {
    pub fn temporary_memory(instance_id: InstanceId, database_id: DatabaseId) -> Result<Self> {
        Self::new(EmbeddedRuntimeConfig::temporary_memory(
            instance_id,
            database_id,
        ))
    }

    pub fn temporary_memory_with_limits(
        instance_id: InstanceId,
        database_id: DatabaseId,
        limits: ResourceLimits,
    ) -> Result<Self> {
        Self::new(EmbeddedRuntimeConfig::temporary_memory_with_limits(
            instance_id,
            database_id,
            limits,
        ))
    }

    pub fn new(config: EmbeddedRuntimeConfig) -> Result<Self> {
        Ok(Self {
            runtime: build_tokio_runtime()?,
            embedded: EmbeddedRuntime::new(config)?,
        })
    }

    pub fn embedded(&self) -> &EmbeddedRuntime {
        &self.embedded
    }

    pub fn runtime(&self) -> &tokio::runtime::Runtime {
        &self.runtime
    }

    pub fn open_session(&self) -> Result<LocalSession> {
        self.runtime.block_on(self.embedded.open_session_async())
    }

    pub fn open_session_with_usage(&self, usage: ResourceUsage) -> Result<LocalSession> {
        self.runtime
            .block_on(self.embedded.open_session_with_usage_async(usage))
    }
}

fn io_error(context: &'static str, err: std::io::Error) -> RnovError {
    RnovError::new(ErrorKind::Io, format!("{context}: {err}"))
}

fn combine_phase_results(
    primary: Result<()>,
    secondary: Result<()>,
    secondary_context: &'static str,
) -> Result<()> {
    match (primary, secondary) {
        (Ok(()), result) | (result, Ok(())) => result,
        (Err(primary), Err(secondary)) => {
            let kind = secondary.kind();
            Err(RnovError::new(
                kind,
                format!("{primary}; {secondary_context}: {secondary}"),
            ))
        }
    }
}

#[cfg(feature = "tokio-runtime")]
fn build_tokio_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .map_err(|err| {
            RnovError::new(
                ErrorKind::Internal,
                format!("failed to build Tokio runtime: {err}"),
            )
        })
}

#[derive(Clone, Debug)]
pub struct EmbeddedRuntime {
    config: EmbeddedRuntimeConfig,
    instances: InstanceManager,
}

impl EmbeddedRuntime {
    pub fn temporary_memory(instance_id: InstanceId, database_id: DatabaseId) -> Self {
        Self::new(EmbeddedRuntimeConfig::temporary_memory(
            instance_id,
            database_id,
        ))
        .expect("temporary memory runtime config is valid")
    }

    pub fn temporary_memory_with_limits(
        instance_id: InstanceId,
        database_id: DatabaseId,
        limits: ResourceLimits,
    ) -> Result<Self> {
        Self::new(EmbeddedRuntimeConfig::temporary_memory_with_limits(
            instance_id,
            database_id,
            limits,
        ))
    }

    pub fn new(config: EmbeddedRuntimeConfig) -> Result<Self> {
        let mut instances = InstanceManager::new();
        instances.register(config.instance().clone())?;
        Ok(Self { config, instances })
    }

    pub fn config(&self) -> &EmbeddedRuntimeConfig {
        &self.config
    }

    pub fn instances(&self) -> &InstanceManager {
        &self.instances
    }

    pub fn open_session(&self) -> Result<LocalSession> {
        self.open_session_with_usage(ResourceUsage::new(0, 0, 1))
    }

    pub async fn open_session_async(&self) -> Result<LocalSession> {
        self.open_session()
    }

    pub fn open_session_with_usage(&self, usage: ResourceUsage) -> Result<LocalSession> {
        self.config.instance().check_resource_usage(&usage)?;
        match self.config.mode() {
            EmbeddedRuntimeMode::TemporaryMemory => LocalSession::memory(),
            EmbeddedRuntimeMode::SingleFile => self.open_single_file_session(),
        }
    }

    fn open_single_file_session(&self) -> Result<LocalSession> {
        let config = self.config.single_file().ok_or_else(|| {
            RnovError::new(
                ErrorKind::Internal,
                "single-file runtime mode is missing storage config",
            )
        })?;
        LocalSession::single_file_with_key(config.path(), config.page_key())
    }

    pub async fn open_session_with_usage_async(
        &self,
        usage: ResourceUsage,
    ) -> Result<LocalSession> {
        self.open_session_with_usage(usage)
    }
}
