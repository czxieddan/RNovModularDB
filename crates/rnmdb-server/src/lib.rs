use std::{
    io::{BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
};

use rnmdb_cli::CommandOutput;
use rnmdb_cli::LocalSession;
use rnmdb_common::ids::{DatabaseId, InstanceId};
use rnmdb_common::{ErrorKind, Result, RnovError};
use rnmdb_instance::{InstanceConfig, InstanceManager, ResourceLimits, ResourceUsage};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmbeddedRuntimeMode {
    TemporaryMemory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmbeddedRuntimeConfig {
    instance: InstanceConfig,
    mode: EmbeddedRuntimeMode,
    temporary: bool,
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
        }
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
        false
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
        handle_sql_client(stream, self.runtime.open_session()?)
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

fn handle_sql_client(stream: TcpStream, mut session: LocalSession) -> Result<()> {
    let reader_stream = stream
        .try_clone()
        .map_err(|err| io_error("failed to clone SQL TCP client stream", err))?;
    let mut reader = BufReader::new(reader_stream);
    let mut writer = stream;
    let mut command = String::new();
    loop {
        command.clear();
        if read_sql_command(&mut reader, &mut command)? == 0 {
            return Ok(());
        }
        if execute_sql_command_line(&mut session, &mut writer, command.trim())? {
            return Ok(());
        }
    }
}

fn read_sql_command(reader: &mut BufReader<TcpStream>, command: &mut String) -> Result<usize> {
    reader
        .read_line(command)
        .map_err(|err| io_error("failed to read SQL TCP command", err))
}

fn execute_sql_command_line(
    session: &mut LocalSession,
    writer: &mut TcpStream,
    command: &str,
) -> Result<bool> {
    if command.eq_ignore_ascii_case("quit") {
        write_protocol_line(writer, "OK bye")?;
        return Ok(true);
    }
    if command.is_empty() {
        write_protocol_line(writer, "ERR empty command")?;
        return Ok(false);
    }
    let line = match session.execute(command) {
        Ok(output) => protocol_output_line(output),
        Err(err) => format!("ERR {}", protocol_text(&err.to_string())),
    };
    write_protocol_line(writer, &line)?;
    Ok(false)
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
        if !self.config.is_memory_only() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "embedded runtime only supports memory sessions",
            ));
        }
        self.config.instance().check_resource_usage(&usage)?;
        LocalSession::memory()
    }

    pub async fn open_session_with_usage_async(
        &self,
        usage: ResourceUsage,
    ) -> Result<LocalSession> {
        self.open_session_with_usage(usage)
    }
}
