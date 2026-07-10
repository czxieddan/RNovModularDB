use std::{
    fmt,
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
};

use rnmdb_cli::CommandOutput;
use rnmdb_cli::LocalSession;
use rnmdb_common::ids::{DatabaseId, InstanceId};
use rnmdb_common::{ErrorKind, Result, RnovError};
use rnmdb_instance::{InstanceConfig, InstanceManager, ResourceLimits, ResourceUsage};
use rnmdb_security::{AuthenticationProvider, LocalCredentialStore};
use rnmdb_storage::PageCryptoKey;

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
}

impl SqlTcpServer {
    pub fn bind(address: impl ToSocketAddrs, config: EmbeddedRuntimeConfig) -> Result<Self> {
        let listener = TcpListener::bind(address)
            .map_err(|err| io_error("failed to bind SQL TCP listener", err))?;
        Ok(Self {
            listener,
            runtime: EmbeddedRuntime::new(config)?,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|err| io_error("failed to read SQL TCP listener address", err))
    }

    pub fn accept_one(&self) -> Result<()> {
        let (stream, _) = self
            .listener
            .accept()
            .map_err(|err| io_error("failed to accept SQL TCP client", err))?;
        handle_sql_client(stream, &self.runtime)
    }

    pub fn serve(&self) -> Result<()> {
        loop {
            self.accept_one()?;
        }
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

fn handle_sql_client(stream: TcpStream, runtime: &EmbeddedRuntime) -> Result<()> {
    let reader_stream = stream
        .try_clone()
        .map_err(|err| io_error("failed to clone SQL TCP client stream", err))?;
    let mut reader = BufReader::new(reader_stream);
    let mut writer = stream;
    let mut session = initial_client_session(runtime)?;
    let mut command = String::new();
    loop {
        command.clear();
        if read_sql_command(&mut reader, &mut command)? == 0 {
            close_client_session(runtime, &mut session)?;
            return Ok(());
        }
        if execute_sql_command_line(runtime, &mut session, &mut writer, command.trim())? {
            return Ok(());
        }
    }
}

fn initial_client_session(runtime: &EmbeddedRuntime) -> Result<Option<LocalSession>> {
    if runtime.config().authentication_required() {
        Ok(None)
    } else {
        runtime.open_session().map(Some)
    }
}

fn read_sql_command(reader: &mut BufReader<TcpStream>, command: &mut String) -> Result<usize> {
    reader
        .read_line(command)
        .map_err(|err| io_error("failed to read SQL TCP command", err))
}

fn execute_sql_command_line(
    runtime: &EmbeddedRuntime,
    session: &mut Option<LocalSession>,
    writer: &mut TcpStream,
    command: &str,
) -> Result<bool> {
    match classify_client_command(command) {
        ClientCommandKind::Quit => execute_quit_command(runtime, session, writer),
        ClientCommandKind::Empty => execute_empty_command(writer),
        ClientCommandKind::Auth => execute_auth_command(runtime, session, writer, command),
        ClientCommandKind::Sql => execute_session_sql(runtime, session, writer, command),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientCommandKind {
    Quit,
    Empty,
    Auth,
    Sql,
}

fn classify_client_command(command: &str) -> ClientCommandKind {
    if command.eq_ignore_ascii_case("quit") {
        return ClientCommandKind::Quit;
    }
    if command.is_empty() {
        return ClientCommandKind::Empty;
    }
    if auth_command_tail(command).is_some() {
        return ClientCommandKind::Auth;
    }
    ClientCommandKind::Sql
}

fn execute_quit_command(
    runtime: &EmbeddedRuntime,
    session: &mut Option<LocalSession>,
    writer: &mut TcpStream,
) -> Result<bool> {
    close_client_session(runtime, session)?;
    write_protocol_line(writer, "OK bye")?;
    Ok(true)
}

fn execute_empty_command(writer: &mut TcpStream) -> Result<bool> {
    write_protocol_line(writer, "ERR empty command")?;
    Ok(false)
}

fn execute_session_sql(
    runtime: &EmbeddedRuntime,
    session: &mut Option<LocalSession>,
    writer: &mut TcpStream,
    command: &str,
) -> Result<bool> {
    let Some(session) = session.as_mut() else {
        write_protocol_line(writer, "ERR authentication required")?;
        return Ok(false);
    };
    let line = execute_session_command(runtime, session, command)?;
    write_protocol_line(writer, &line)?;
    Ok(false)
}

fn execute_session_command(
    runtime: &EmbeddedRuntime,
    session: &mut LocalSession,
    command: &str,
) -> Result<String> {
    match session.execute(command) {
        Ok(output) => successful_command_line(runtime, session, output),
        Err(err) => Ok(format!("ERR {}", protocol_text(&err.to_string()))),
    }
}

fn successful_command_line(
    runtime: &EmbeddedRuntime,
    session: &mut LocalSession,
    output: CommandOutput,
) -> Result<String> {
    let should_checkpoint = command_output_needs_checkpoint(&output);
    let line = protocol_output_line(output);
    if should_checkpoint {
        checkpoint_local_session(runtime, session)?;
    }
    Ok(line)
}

fn execute_auth_command(
    runtime: &EmbeddedRuntime,
    session: &mut Option<LocalSession>,
    writer: &mut TcpStream,
    command: &str,
) -> Result<bool> {
    let response = auth_command_response(runtime, session, command)?;
    write_protocol_line(writer, response)?;
    Ok(false)
}

fn auth_command_response(
    runtime: &EmbeddedRuntime,
    session: &mut Option<LocalSession>,
    command: &str,
) -> Result<&'static str> {
    if session.is_some() {
        return Ok("OK authenticated");
    }
    let Some((username, password)) = parse_auth_command(command) else {
        return Ok("ERR usage: AUTH <username> <password>");
    };
    if authenticate_client(runtime, username, password)? {
        *session = Some(runtime.open_session()?);
        return Ok("OK authenticated");
    }
    Ok("ERR authentication failed")
}

fn authenticate_client(runtime: &EmbeddedRuntime, username: &str, password: &str) -> Result<bool> {
    let Some(credentials) = runtime.config().credentials() else {
        return Ok(true);
    };
    credentials
        .authenticate(username, password)
        .map(|principal| principal.is_some())
}

fn command_output_needs_checkpoint(output: &CommandOutput) -> bool {
    matches!(
        output,
        CommandOutput::RowsAffected(_) | CommandOutput::SchemaChanged
    )
}

fn close_client_session(
    runtime: &EmbeddedRuntime,
    session: &mut Option<LocalSession>,
) -> Result<()> {
    let Some(session) = session.as_mut() else {
        return Ok(());
    };
    rollback_client_transaction(session)?;
    checkpoint_local_session(runtime, session)
}

fn rollback_client_transaction(session: &mut LocalSession) -> Result<()> {
    if !session.in_transaction() {
        return Ok(());
    }
    session.execute("ROLLBACK;").map(|_| ())
}

fn checkpoint_local_session(runtime: &EmbeddedRuntime, session: &mut LocalSession) -> Result<()> {
    if runtime.config().disk_writes_allowed() && !session.in_transaction() {
        session.checkpoint()?;
    }
    Ok(())
}

fn parse_auth_command(command: &str) -> Option<(&str, &str)> {
    let tail = auth_command_tail(command)?.trim_start();
    let (username, password) = tail.split_once(char::is_whitespace)?;
    let password = password.trim_start();
    if username.is_empty() || password.is_empty() {
        None
    } else {
        Some((username, password))
    }
}

fn auth_command_tail(command: &str) -> Option<&str> {
    if command.eq_ignore_ascii_case("auth") {
        return Some("");
    }
    let (head, tail) = command.split_once(char::is_whitespace)?;
    if head.eq_ignore_ascii_case("auth") {
        Some(tail)
    } else {
        None
    }
}

fn protocol_output_line(output: CommandOutput) -> String {
    match output {
        CommandOutput::Rows(batch) => format!("ROWS {:?}", batch.rows()),
        CommandOutput::RowsAffected(rows) => format!("OK {rows} rows affected"),
        CommandOutput::SchemaChanged => "OK schema changed".to_string(),
        CommandOutput::Text(text) => format!("TEXT {}", protocol_text(&text)),
    }
}

fn protocol_text(text: &str) -> String {
    text.replace(['\r', '\n'], " ")
}

fn write_protocol_line(writer: &mut TcpStream, line: &str) -> Result<()> {
    writer
        .write_all(line.as_bytes())
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.flush())
        .map_err(|err| io_error("failed to write SQL TCP response", err))
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
