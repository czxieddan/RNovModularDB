use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    thread,
    time::Duration,
};

use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_common::{ErrorKind, Result, RnovError};
use rnmdb_security::{AuthenticatedPrincipal, AuthenticationProvider};

use super::{ClientPermit, EmbeddedRuntime, io_error};

const MAX_SQL_COMMAND_BYTES: usize = 65_536;
const MAX_SQL_COMMAND_READ_BYTES: usize = MAX_SQL_COMMAND_BYTES + 2;
const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) fn spawn_client_thread(
    stream: TcpStream,
    runtime: EmbeddedRuntime,
    permit: ClientPermit,
) -> Result<()> {
    thread::Builder::new()
        .name("rnmdb-sql-client".to_string())
        .spawn(move || {
            let _permit = permit;
            let _ = handle_sql_client(stream, &runtime);
        })
        .map(|_| ())
        .map_err(|err| io_error("failed to spawn SQL TCP client worker", err))
}

pub(super) fn reject_busy_client(mut stream: TcpStream) {
    let _ = configure_client_stream(&stream);
    let _ = write_protocol_line(&mut stream, "ERR server busy");
}

pub(super) fn handle_sql_client(stream: TcpStream, runtime: &EmbeddedRuntime) -> Result<()> {
    let reader_stream = configured_reader_stream(&stream)?;
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

fn configured_reader_stream(stream: &TcpStream) -> Result<TcpStream> {
    configure_client_stream(stream)?;
    stream
        .try_clone()
        .map_err(|err| io_error("failed to clone SQL TCP client stream", err))
}

fn initial_client_session(runtime: &EmbeddedRuntime) -> Result<Option<LocalSession>> {
    if runtime.config().authentication_required() {
        Ok(None)
    } else {
        runtime.open_session().map(Some)
    }
}

fn read_sql_command(reader: &mut BufReader<TcpStream>, command: &mut String) -> Result<usize> {
    let mut bytes = Vec::new();
    let mut limited = reader.by_ref().take(MAX_SQL_COMMAND_READ_BYTES as u64);
    let bytes_read = limited
        .read_until(b'\n', &mut bytes)
        .map_err(|err| io_error("failed to read SQL TCP command", err))?;
    ensure_command_size(&bytes)?;
    append_utf8_command(command, &bytes)?;
    Ok(bytes_read)
}

fn ensure_command_size(bytes: &[u8]) -> Result<()> {
    if command_payload_len(bytes) <= MAX_SQL_COMMAND_BYTES {
        return Ok(());
    }
    Err(RnovError::new(
        ErrorKind::InvalidInput,
        format!("SQL command exceeds {MAX_SQL_COMMAND_BYTES} bytes"),
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

fn configure_client_stream(stream: &TcpStream) -> Result<()> {
    stream
        .set_read_timeout(Some(CLIENT_IO_TIMEOUT))
        .map_err(|err| io_error("failed to set SQL TCP client read timeout", err))?;
    stream
        .set_write_timeout(Some(CLIENT_IO_TIMEOUT))
        .map_err(|err| io_error("failed to set SQL TCP client write timeout", err))
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
    let Some(principal) = authenticate_client(runtime, username, password)? else {
        return Ok("ERR authentication failed");
    };
    *session = Some(open_authenticated_session(runtime, &principal)?);
    Ok("OK authenticated")
}

fn authenticate_client(
    runtime: &EmbeddedRuntime,
    username: &str,
    password: &str,
) -> Result<Option<AuthenticatedPrincipal>> {
    let Some(credentials) = runtime.config().credentials() else {
        return Ok(None);
    };
    credentials.authenticate(username, password)
}

fn open_authenticated_session(
    runtime: &EmbeddedRuntime,
    principal: &AuthenticatedPrincipal,
) -> Result<LocalSession> {
    let mut session = runtime.open_session()?;
    if let Some(role_id) = principal.role_id() {
        session.set_active_role(role_id)?;
    }
    Ok(session)
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
