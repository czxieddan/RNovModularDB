use std::{
    fmt,
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use rnmdb_cli::LocalSession;
use rnmdb_common::ids::{DatabaseId, InstanceId};
use rnmdb_common::{ErrorKind, Result, RnovError};
use rnmdb_instance::{InstanceConfig, InstanceManager, ResourceLimits, ResourceUsage};
use rnmdb_security::LocalCredentialStore;
use rnmdb_storage::PageCryptoKey;

mod sql_protocol;

use sql_protocol::{handle_sql_client, reject_busy_client, spawn_client_thread};

const MAX_ACTIVE_CLIENTS: usize = 64;
const SERVER_ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(50);

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
    runtime: EmbeddedRuntime,
    active_clients: Arc<AtomicUsize>,
}

impl SqlTcpServer {
    pub fn bind(address: impl ToSocketAddrs, config: EmbeddedRuntimeConfig) -> Result<Self> {
        let listener = TcpListener::bind(address)
            .map_err(|err| io_error("failed to bind SQL TCP listener", err))?;
        Ok(Self {
            listener,
            runtime: EmbeddedRuntime::new(config)?,
            active_clients: Arc::new(AtomicUsize::new(0)),
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
            if self.serve_next().is_err() {
                thread::sleep(SERVER_ACCEPT_RETRY_DELAY);
            }
        }
    }

    fn serve_next(&self) -> Result<()> {
        self.dispatch_client(self.accept_client()?)
    }

    fn accept_client(&self) -> Result<TcpStream> {
        self.listener
            .accept()
            .map(|(stream, _)| stream)
            .map_err(|err| io_error("failed to accept SQL TCP client", err))
    }

    fn dispatch_client(&self, stream: TcpStream) -> Result<()> {
        let Some(permit) = ClientPermit::acquire(&self.active_clients) else {
            reject_busy_client(stream);
            return Ok(());
        };
        spawn_client_thread(stream, self.runtime.clone(), permit)
    }
}

struct ClientPermit {
    active_clients: Arc<AtomicUsize>,
}

impl ClientPermit {
    fn acquire(active_clients: &Arc<AtomicUsize>) -> Option<Self> {
        active_clients
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_ACTIVE_CLIENTS).then_some(active + 1)
            })
            .ok()?;
        Some(Self {
            active_clients: Arc::clone(active_clients),
        })
    }
}

impl Drop for ClientPermit {
    fn drop(&mut self) {
        self.active_clients.fetch_sub(1, Ordering::AcqRel);
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
