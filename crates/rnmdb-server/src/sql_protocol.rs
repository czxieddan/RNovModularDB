// crates/rnmdb-server/src/sql_protocol.rs - RNovModularDB source module.
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
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    thread,
    time::{Duration, Instant},
};

use rnmdb_cli::CommandOutput;
use rnmdb_common::{ErrorKind, Result, RnovError};
use rnmdb_security::{AuthenticatedPrincipal, AuthenticationProvider};

use super::{ClientPermit, SqlServerRuntime, io_error, shared::SharedConnection};

const CLIENT_SHUTDOWN_POLL_INTERVAL: Duration = Duration::from_millis(250);

pub(super) fn spawn_client_thread(
    stream: TcpStream,
    runtime: SqlServerRuntime,
    permit: ClientPermit,
) -> Result<()> {
    thread::Builder::new()
        .name("rnmdb-sql-client".to_string())
        .spawn(move || {
            let _permit = permit;
            if let Err(error) = handle_sql_client(stream, &runtime) {
                eprintln!("rnmdbd client session error: {error}");
            }
        })
        .map(|_| ())
        .map_err(|err| io_error("failed to spawn SQL TCP client worker", err))
}

pub(super) fn reject_busy_client(mut stream: TcpStream, runtime: &SqlServerRuntime) {
    let _ = configure_client_stream(&stream, runtime.options().client_io_timeout());
    let _ = write_protocol_line(&mut stream, "ERR server busy");
}

pub(super) fn handle_sql_client(stream: TcpStream, runtime: &SqlServerRuntime) -> Result<()> {
    let result = handle_sql_client_inner(stream, runtime);
    if result.is_err() {
        runtime.metrics().record_failed_client_session();
    }
    result
}

fn handle_sql_client_inner(stream: TcpStream, runtime: &SqlServerRuntime) -> Result<()> {
    let reader_stream = configured_reader_stream(&stream, runtime)?;
    let mut reader = BufReader::new(reader_stream);
    let mut writer = stream;
    let mut session = initial_client_session(runtime)?;
    let mut command = String::new();
    loop {
        if runtime.shutdown_requested() {
            close_client_session(runtime, &mut session)?;
            return Ok(());
        }
        command.clear();
        let bytes_read = match read_sql_command(&mut reader, &mut command, runtime) {
            Ok(bytes_read) => bytes_read,
            Err(_) if runtime.shutdown_requested() => {
                close_client_session(runtime, &mut session)?;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if bytes_read == 0 {
            close_client_session(runtime, &mut session)?;
            return Ok(());
        }
        if runtime.shutdown_requested() {
            close_client_session(runtime, &mut session)?;
            return Ok(());
        }
        runtime.metrics().record_command();
        if execute_sql_command_line(runtime, &mut session, &mut writer, command.trim())? {
            return Ok(());
        }
    }
}

fn configured_reader_stream(stream: &TcpStream, runtime: &SqlServerRuntime) -> Result<TcpStream> {
    configure_client_stream(stream, runtime.options().client_io_timeout())?;
    stream
        .try_clone()
        .map_err(|err| io_error("failed to clone SQL TCP client stream", err))
}

fn initial_client_session(runtime: &SqlServerRuntime) -> Result<ClientSession> {
    let connection = if runtime.config().authentication_required() {
        None
    } else {
        Some(runtime.open_connection(None))
    };
    Ok(ClientSession {
        connection,
        protocol_version: runtime.protocol_capabilities().protocol_version(),
    })
}

struct ClientSession {
    connection: Option<SharedConnection>,
    protocol_version: u16,
}

fn read_sql_command(
    reader: &mut BufReader<TcpStream>,
    command: &mut String,
    runtime: &SqlServerRuntime,
) -> Result<usize> {
    let max_command_bytes = runtime.options().max_command_bytes();
    let max_read_bytes = max_command_bytes + 2;
    let client_io_timeout = runtime.options().client_io_timeout();
    let mut bytes = Vec::new();
    let mut last_progress = Instant::now();
    let bytes_read = loop {
        if runtime.shutdown_requested() {
            return Ok(0);
        }
        let remaining = max_read_bytes.saturating_sub(bytes.len());
        if remaining == 0 {
            ensure_command_size(&bytes, max_command_bytes)?;
        }
        let mut limited = reader.by_ref().take(remaining as u64);
        match limited.read_until(b'\n', &mut bytes) {
            Ok(0) => break bytes.len(),
            Ok(_) if bytes.ends_with(b"\n") => break bytes.len(),
            Ok(_) => {
                last_progress = Instant::now();
                ensure_command_size(&bytes, max_command_bytes)?;
            }
            Err(error) if is_transient_read_error(&error) => {
                if last_progress.elapsed() >= client_io_timeout {
                    return Err(io_error(
                        "failed to read SQL TCP command",
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "SQL client read timed out",
                        ),
                    ));
                }
            }
            Err(error) => return Err(io_error("failed to read SQL TCP command", error)),
        }
    };
    ensure_command_size(&bytes, max_command_bytes)?;
    append_utf8_command(command, &bytes)?;
    Ok(bytes_read)
}

fn is_transient_read_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

fn ensure_command_size(bytes: &[u8], max_command_bytes: usize) -> Result<()> {
    if command_payload_len(bytes) <= max_command_bytes {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::InvalidInput,
        format!("SQL command exceeds {max_command_bytes} bytes"),
    ))
}

fn command_payload_len(bytes: &[u8]) -> usize {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    bytes.strip_suffix(b"\r").unwrap_or(bytes).len()
}

fn append_utf8_command(command: &mut String, bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| RnovError::new(ErrorKind::InvalidInput, "SQL command is not valid UTF-8"))?;
    command.push_str(text);
    Ok(())
}

fn configure_client_stream(stream: &TcpStream, client_io_timeout: Duration) -> Result<()> {
    let read_poll_interval = client_io_timeout.min(CLIENT_SHUTDOWN_POLL_INTERVAL);
    stream
        .set_read_timeout(Some(read_poll_interval))
        .map_err(|err| io_error("failed to set SQL TCP client read timeout", err))?;
    stream
        .set_write_timeout(Some(client_io_timeout))
        .map_err(|err| io_error("failed to set SQL TCP client write timeout", err))
}

fn execute_sql_command_line(
    runtime: &SqlServerRuntime,
    session: &mut ClientSession,
    writer: &mut TcpStream,
    command: &str,
) -> Result<bool> {
    match classify_client_command(command) {
        ClientCommandKind::Quit => execute_quit_command(runtime, session, writer),
        ClientCommandKind::Ping => execute_ping_command(writer),
        ClientCommandKind::Hello => execute_hello_command(runtime, session, writer, command),
        ClientCommandKind::Status => execute_status_command(runtime, session, writer),
        ClientCommandKind::Empty => execute_empty_command(writer),
        ClientCommandKind::Auth => execute_auth_command(runtime, session, writer, command),
        ClientCommandKind::Sql => execute_session_sql(runtime, session, writer, command),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientCommandKind {
    Quit,
    Ping,
    Hello,
    Status,
    Empty,
    Auth,
    Sql,
}

fn classify_client_command(command: &str) -> ClientCommandKind {
    if command.eq_ignore_ascii_case("quit") {
        return ClientCommandKind::Quit;
    }
    if command.eq_ignore_ascii_case("ping") {
        return ClientCommandKind::Ping;
    }
    if hello_command_tail(command).is_some() {
        return ClientCommandKind::Hello;
    }
    if command.eq_ignore_ascii_case("status") {
        return ClientCommandKind::Status;
    }
    if command.is_empty() {
        return ClientCommandKind::Empty;
    }
    if auth_command_tail(command).is_some() {
        return ClientCommandKind::Auth;
    }
    ClientCommandKind::Sql
}

fn execute_ping_command(writer: &mut TcpStream) -> Result<bool> {
    write_protocol_line(writer, "OK pong")?;
    Ok(false)
}

fn execute_hello_command(
    runtime: &SqlServerRuntime,
    session: &mut ClientSession,
    writer: &mut TcpStream,
    command: &str,
) -> Result<bool> {
    let capabilities = runtime.protocol_capabilities();
    let requested = match parse_hello_request(command) {
        Ok(requested) => requested,
        Err(()) => {
            write_protocol_line(
                writer,
                "ERR usage: HELLO [<minimum-version> <maximum-version>]",
            )?;
            return Ok(false);
        }
    };
    let selected = match requested {
        Some((minimum, maximum)) => {
            match capabilities.negotiate_protocol_version(minimum, maximum) {
                Ok(selected) => selected,
                Err(error) => {
                    write_protocol_line(
                        writer,
                        &format!("ERR {}", protocol_text(&error.to_string())),
                    )?;
                    return Ok(false);
                }
            }
        }
        None => capabilities.protocol_version(),
    };
    session.protocol_version = selected;
    write_protocol_line(
        writer,
        &format!(
            "HELLO protocol_version={} server_min_protocol_version={} server_max_protocol_version={} authentication_required={} max_active_clients={} max_command_bytes={} authentication={} health_check={} explicit_transactions={} runtime_status={} protocol_negotiation={} transport_security={}",
            selected,
            capabilities.minimum_protocol_version(),
            capabilities.protocol_version(),
            runtime.config().authentication_required(),
            capabilities.max_active_clients(),
            capabilities.max_command_bytes(),
            capabilities.supports_authentication(),
            capabilities.supports_health_check(),
            capabilities.supports_explicit_transactions(),
            capabilities.supports_runtime_status_at(selected),
            capabilities.supports_protocol_negotiation(),
            capabilities.supports_transport_security(),
        ),
    )?;
    Ok(false)
}

fn execute_status_command(
    runtime: &SqlServerRuntime,
    session: &ClientSession,
    writer: &mut TcpStream,
) -> Result<bool> {
    if !runtime
        .protocol_capabilities()
        .supports_runtime_status_at(session.protocol_version)
    {
        write_protocol_line(writer, "ERR STATUS requires protocol version 2 or newer")?;
        return Ok(false);
    }
    if session.connection.is_none() {
        write_protocol_line(writer, "ERR authentication required")?;
        return Ok(false);
    }
    let status = match runtime.status() {
        Ok(status) => status,
        Err(error) => {
            write_protocol_line(
                writer,
                &format!("ERR {}", protocol_text(&error.to_string())),
            )?;
            return Ok(false);
        }
    };
    let metrics = runtime.metrics().snapshot();
    let line = format!(
        "STATUS lifecycle={} health={} mode={} authentication_required={} active_clients={} committed_generation={} accepted_clients={} rejected_clients={} completed_clients={} commands_received={} failed_client_sessions={}",
        lifecycle_text(status.lifecycle()),
        database_health_text(status.database_health()),
        runtime_mode_text(status.runtime_mode()),
        status.authentication_required(),
        metrics.active_clients(),
        status.committed_generation(),
        metrics.accepted_clients(),
        metrics.rejected_clients(),
        metrics.completed_clients(),
        metrics.commands_received(),
        metrics.failed_client_sessions(),
    );
    write_protocol_line(writer, &line)?;
    Ok(false)
}

fn execute_quit_command(
    runtime: &SqlServerRuntime,
    session: &mut ClientSession,
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
    runtime: &SqlServerRuntime,
    session: &mut ClientSession,
    writer: &mut TcpStream,
    command: &str,
) -> Result<bool> {
    let Some(connection) = session.connection.as_mut() else {
        write_protocol_line(writer, "ERR authentication required")?;
        return Ok(false);
    };
    let line = execute_session_command(connection, command)?;
    let close_after_response = connection.close_after_response();
    write_protocol_line(writer, &line)?;
    if close_after_response {
        close_client_session(runtime, session)?;
        return Ok(true);
    }
    Ok(false)
}

fn execute_session_command(session: &mut SharedConnection, command: &str) -> Result<String> {
    match session.execute(command) {
        Ok(output) => Ok(protocol_output_line(output)),
        Err(err) if session.close_after_response() => Ok(format!(
            "ERR {}; connection closing",
            protocol_text(&err.to_string())
        )),
        Err(err) => Ok(format!("ERR {}", protocol_text(&err.to_string()))),
    }
}

fn execute_auth_command(
    runtime: &SqlServerRuntime,
    session: &mut ClientSession,
    writer: &mut TcpStream,
    command: &str,
) -> Result<bool> {
    let response = auth_command_response(runtime, session, command)?;
    write_protocol_line(writer, response)?;
    Ok(false)
}

fn auth_command_response(
    runtime: &SqlServerRuntime,
    session: &mut ClientSession,
    command: &str,
) -> Result<&'static str> {
    if session.connection.is_some() {
        return Ok("OK authenticated");
    }
    let Some((username, password)) = parse_auth_command(command) else {
        return Ok("ERR usage: AUTH <username> <password>");
    };
    let Some(principal) = authenticate_client(runtime, username, password)? else {
        return Ok("ERR authentication failed");
    };
    session.connection = Some(open_authenticated_session(runtime, &principal)?);
    Ok("OK authenticated")
}

fn authenticate_client(
    runtime: &SqlServerRuntime,
    username: &str,
    password: &str,
) -> Result<Option<AuthenticatedPrincipal>> {
    let Some(credentials) = runtime.config().credentials() else {
        return Ok(None);
    };
    credentials.authenticate(username, password)
}

fn open_authenticated_session(
    runtime: &SqlServerRuntime,
    principal: &AuthenticatedPrincipal,
) -> Result<SharedConnection> {
    Ok(runtime.open_connection(principal.role_id()))
}

fn close_client_session(_runtime: &SqlServerRuntime, session: &mut ClientSession) -> Result<()> {
    let Some(mut connection) = session.connection.take() else {
        return Ok(());
    };
    connection.close()
}

fn parse_hello_request(command: &str) -> std::result::Result<Option<(u16, u16)>, ()> {
    let tail = hello_command_tail(command).ok_or(())?.trim();
    if tail.is_empty() {
        return Ok(None);
    }
    let mut parts = tail.split_whitespace();
    let minimum = parts.next().ok_or(())?.parse().map_err(|_| ())?;
    let maximum = parts.next().ok_or(())?.parse().map_err(|_| ())?;
    if parts.next().is_some() {
        return Err(());
    }
    Ok(Some((minimum, maximum)))
}

fn hello_command_tail(command: &str) -> Option<&str> {
    if command.eq_ignore_ascii_case("hello") {
        return Some("");
    }
    let (head, tail) = command.split_once(char::is_whitespace)?;
    if head.eq_ignore_ascii_case("hello") {
        Some(tail)
    } else {
        None
    }
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

fn lifecycle_text(lifecycle: super::SqlServerLifecycle) -> &'static str {
    match lifecycle {
        super::SqlServerLifecycle::Idle => "idle",
        super::SqlServerLifecycle::Serving => "serving",
        super::SqlServerLifecycle::ShuttingDown => "shutting_down",
        super::SqlServerLifecycle::Stopped => "stopped",
    }
}

fn database_health_text(health: super::SqlDatabaseHealth) -> &'static str {
    match health {
        super::SqlDatabaseHealth::Available => "available",
        super::SqlDatabaseHealth::RestartRequired => "restart_required",
    }
}

fn runtime_mode_text(mode: super::EmbeddedRuntimeMode) -> &'static str {
    match mode {
        super::EmbeddedRuntimeMode::TemporaryMemory => "temporary_memory",
        super::EmbeddedRuntimeMode::SingleFile => "single_file",
    }
}

fn write_protocol_line(writer: &mut TcpStream, line: &str) -> Result<()> {
    writer
        .write_all(line.as_bytes())
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.flush())
        .map_err(|err| io_error("failed to write SQL TCP response", err))
}
