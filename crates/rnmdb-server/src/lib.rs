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

const MAX_ACTIVE_CLIENTS: usize = 64;
const SERVER_ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(50);
const CLIENT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const FORCED_CLIENT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmbeddedRuntimeConfig {
    instance: InstanceConfig,
    mode: EmbeddedRuntimeMode,
    temporary: bool,
    single_file: Option<SingleFileRuntimeConfig>,
    credentials: Option<LocalCredentialStore>,
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
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|err| io_error("failed to read SQL TCP listener address", err))
    }

    pub fn accept_one(&self) -> Result<()> {
        let stream = self.accept_client()?;
        handle_sql_client(stream, &self.runtime)
    }

    pub fn serve(&self) -> Result<()> {
        loop {
            self.serve_next()?;
        }
    }

    /// Serves clients until `shutdown` is set, then stops client I/O and waits
    /// for a bounded drain period.
    pub fn serve_until(&self, shutdown: &AtomicBool) -> Result<()> {
        self.listener
            .set_nonblocking(true)
            .map_err(|err| io_error("failed to enable nonblocking SQL listener", err))?;
        let serve_result = self.serve_nonblocking_until(shutdown);
        self.runtime.request_shutdown();
        let blocking_result = self
            .listener
            .set_nonblocking(false)
            .map_err(|err| io_error("failed to restore blocking SQL listener", err));
        let drain_result = self.drain_clients(CLIENT_DRAIN_TIMEOUT);
        let forced_shutdown_result = if drain_result.is_err() {
            self.clients
                .shutdown_all()
                .and_then(|()| self.drain_clients(FORCED_CLIENT_DRAIN_TIMEOUT))
        } else {
            Ok(())
        };
        serve_result
            .and(blocking_result)
            .and(drain_result)
            .and(forced_shutdown_result)
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

    fn serve_nonblocking_until(&self, shutdown: &AtomicBool) -> Result<()> {
        while !shutdown.load(Ordering::Acquire) {
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

    fn serve_next(&self) -> Result<()> {
        self.dispatch_client(self.accept_client()?)
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
