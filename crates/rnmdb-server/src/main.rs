use std::{
    env,
    fs::File,
    io::{self, BufRead, Read},
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use rnmdb_common::{
    ErrorKind, Result, RnovError,
    ids::{DatabaseId, InstanceId, RoleId},
};
use rnmdb_security::LocalCredentialStore;
use rnmdb_server::{EmbeddedRuntimeConfig, SqlServerOptions, SqlTcpServer};
use rnmdb_storage::PageCryptoKey;

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:7432";
const PAGE_KEY_ENVIRONMENT_VARIABLE: &str = "RNMDB_PAGE_KEY_HEX";
const MAX_SECRET_BYTES: usize = 4096;

enum ServerMode {
    Memory,
    SingleFile {
        path: PathBuf,
        key_source: PageKeySource,
    },
}

enum PageKeySource {
    Environment,
    File(PathBuf),
}

struct AuthenticationOptions {
    username: String,
    password_file: PathBuf,
    role_id: Option<RoleId>,
}

struct ServeOptions {
    bind: Vec<SocketAddr>,
    mode: ServerMode,
    instance_id: InstanceId,
    database_id: DatabaseId,
    authentication: Option<AuthenticationOptions>,
    allow_unauthenticated: bool,
    allow_remote_plaintext: bool,
    accept_once: bool,
    shutdown_on_stdin: bool,
    server_options: SqlServerOptions,
}

struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let Some((command, rest)) = args.split_first() else {
        return print_help();
    };
    match command.as_str() {
        "serve" => run_server(parse_serve_options(rest)?),
        "help" | "--help" | "-h" => print_help(),
        "version" | "--version" | "-V" => print_version(),
        _ => Err(invalid_arguments(format!(
            "unsupported command '{command}'"
        ))),
    }
}

fn parse_serve_options(args: &[String]) -> Result<ServeOptions> {
    let mut bind = DEFAULT_BIND_ADDRESS.to_string();
    let mut memory = false;
    let mut database = None;
    let mut key_source = None;
    let mut instance_id = InstanceId::new(1);
    let mut database_id = DatabaseId::new(1);
    let mut auth_user = None;
    let mut auth_password_file = None;
    let mut auth_role_id = None;
    let mut allow_unauthenticated = false;
    let mut allow_remote_plaintext = false;
    let mut accept_once = false;
    let mut shutdown_on_stdin = false;
    let mut server_options = SqlServerOptions::default();
    let mut position = 0;

    while position < args.len() {
        match args[position].as_str() {
            "--bind" => {
                bind = option_value(args, position, "--bind")?.to_string();
                position += 2;
            }
            "--memory" => {
                require_once(!memory, "--memory")?;
                memory = true;
                position += 1;
            }
            "--database" => {
                require_once(database.is_none(), "--database")?;
                database = Some(PathBuf::from(option_value(args, position, "--database")?));
                position += 2;
            }
            "--page-key-env" => {
                require_once(key_source.is_none(), "page key source")?;
                key_source = Some(PageKeySource::Environment);
                position += 1;
            }
            "--page-key-file" => {
                require_once(key_source.is_none(), "page key source")?;
                key_source = Some(PageKeySource::File(PathBuf::from(option_value(
                    args,
                    position,
                    "--page-key-file",
                )?)));
                position += 2;
            }
            "--instance-id" => {
                instance_id = InstanceId::new(parse_u64_option(args, position, "--instance-id")?);
                position += 2;
            }
            "--database-id" => {
                database_id = DatabaseId::new(parse_u64_option(args, position, "--database-id")?);
                position += 2;
            }
            "--auth-user" => {
                require_once(auth_user.is_none(), "--auth-user")?;
                auth_user = Some(option_value(args, position, "--auth-user")?.to_string());
                position += 2;
            }
            "--auth-password-file" => {
                require_once(auth_password_file.is_none(), "--auth-password-file")?;
                auth_password_file = Some(PathBuf::from(option_value(
                    args,
                    position,
                    "--auth-password-file",
                )?));
                position += 2;
            }
            "--auth-role-id" => {
                auth_role_id = Some(RoleId::new(parse_u64_option(
                    args,
                    position,
                    "--auth-role-id",
                )?));
                position += 2;
            }
            "--allow-unauthenticated" => {
                allow_unauthenticated = true;
                position += 1;
            }
            "--allow-remote-plaintext" => {
                allow_remote_plaintext = true;
                position += 1;
            }
            "--once" => {
                accept_once = true;
                position += 1;
            }
            "--shutdown-on-stdin" => {
                shutdown_on_stdin = true;
                position += 1;
            }
            "--max-clients" => {
                server_options = server_options.with_max_active_clients(parse_usize_option(
                    args,
                    position,
                    "--max-clients",
                )?)?;
                position += 2;
            }
            "--max-command-bytes" => {
                server_options = server_options.with_max_command_bytes(parse_usize_option(
                    args,
                    position,
                    "--max-command-bytes",
                )?)?;
                position += 2;
            }
            "--client-io-timeout-ms" => {
                server_options = server_options.with_client_io_timeout(Duration::from_millis(
                    parse_u64_option(args, position, "--client-io-timeout-ms")?,
                ))?;
                position += 2;
            }
            "--graceful-drain-timeout-ms" => {
                let graceful = Duration::from_millis(parse_u64_option(
                    args,
                    position,
                    "--graceful-drain-timeout-ms",
                )?);
                server_options = server_options
                    .with_drain_timeouts(graceful, server_options.forced_client_drain_timeout())?;
                position += 2;
            }
            "--forced-drain-timeout-ms" => {
                let forced = Duration::from_millis(parse_u64_option(
                    args,
                    position,
                    "--forced-drain-timeout-ms",
                )?);
                server_options = server_options
                    .with_drain_timeouts(server_options.client_drain_timeout(), forced)?;
                position += 2;
            }
            unknown => {
                return Err(invalid_arguments(format!(
                    "unsupported serve option '{unknown}'"
                )));
            }
        }
    }

    let mode = match (memory, database, key_source) {
        (true, None, None) => ServerMode::Memory,
        (false, Some(path), Some(key_source)) => ServerMode::SingleFile { path, key_source },
        (false, None, None) => {
            return Err(invalid_arguments(
                "serve requires --memory or --database with a page key source",
            ));
        }
        (true, Some(_), _) => {
            return Err(invalid_arguments(
                "--memory and --database are mutually exclusive",
            ));
        }
        (_, Some(_), None) => {
            return Err(invalid_arguments(
                "--database requires --page-key-env or --page-key-file",
            ));
        }
        (_, None, Some(_)) => {
            return Err(invalid_arguments("a page key source requires --database"));
        }
    };

    let authentication = match (auth_user, auth_password_file, auth_role_id) {
        (Some(username), Some(password_file), role_id) => Some(AuthenticationOptions {
            username,
            password_file,
            role_id,
        }),
        (None, None, None) => None,
        _ => {
            return Err(invalid_arguments(
                "authentication requires --auth-user and --auth-password-file; --auth-role-id is optional",
            ));
        }
    };
    if authentication.is_some() && allow_unauthenticated {
        return Err(invalid_arguments(
            "--allow-unauthenticated cannot be combined with authentication options",
        ));
    }
    if authentication.is_none() && !allow_unauthenticated {
        return Err(invalid_arguments(
            "serve requires authentication or explicit --allow-unauthenticated",
        ));
    }
    let bind = resolve_bind_addresses(&bind, allow_remote_plaintext)?;

    Ok(ServeOptions {
        bind,
        mode,
        instance_id,
        database_id,
        authentication,
        allow_unauthenticated,
        allow_remote_plaintext,
        accept_once,
        shutdown_on_stdin,
        server_options,
    })
}

fn run_server(options: ServeOptions) -> Result<()> {
    let mut config = match options.mode {
        ServerMode::Memory => {
            EmbeddedRuntimeConfig::temporary_memory(options.instance_id, options.database_id)
        }
        ServerMode::SingleFile { path, key_source } => EmbeddedRuntimeConfig::single_file_with_key(
            options.instance_id,
            options.database_id,
            path,
            page_key_from_source(key_source)?,
        ),
    };
    if let Some(authentication) = options.authentication {
        let password = read_password_file(&authentication.password_file)?;
        let mut credentials = LocalCredentialStore::new();
        credentials.register_user(
            authentication.username,
            password.as_str()?,
            authentication.role_id,
        )?;
        config = config.with_credentials(credentials);
    }

    let server =
        SqlTcpServer::bind_with_options(options.bind.as_slice(), config, options.server_options)?;
    let address = server.local_addr()?;
    println!(
        "rnmdbd {} listening on {address} (authentication={}, remote_plaintext={}, max_clients={}, max_command_bytes={})",
        env!("CARGO_PKG_VERSION"),
        !options.allow_unauthenticated,
        options.allow_remote_plaintext,
        options.server_options.max_active_clients(),
        options.server_options.max_command_bytes()
    );
    if options.accept_once {
        return server.accept_one();
    }
    if options.shutdown_on_stdin {
        return serve_until_stdin(server);
    }
    server.serve()
}

impl SecretBytes {
    fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(self.as_slice())
            .map_err(|_| RnovError::new(ErrorKind::InvalidInput, "secret file is not valid UTF-8"))
    }
}

fn page_key_from_source(source: PageKeySource) -> Result<PageCryptoKey> {
    let secret = match source {
        PageKeySource::Environment => env::var(PAGE_KEY_ENVIRONMENT_VARIABLE)
            .map(String::into_bytes)
            .map(SecretBytes)
            .map_err(|_| {
                RnovError::new(
                    ErrorKind::InvalidInput,
                    format!("{PAGE_KEY_ENVIRONMENT_VARIABLE} is not set or not valid UTF-8"),
                )
            })?,
        PageKeySource::File(path) => read_secret_file(&path, "page key")?,
    };
    let hex = strip_one_line_ending(secret.as_slice());
    let hex = std::str::from_utf8(hex)
        .map_err(|_| RnovError::new(ErrorKind::InvalidInput, "page key is not valid UTF-8"))?;
    rnmdb_cli::page_key_from_hex(hex)
}

fn read_password_file(path: &Path) -> Result<SecretBytes> {
    let secret = read_secret_file(path, "password")?;
    let stripped = strip_one_line_ending(secret.as_slice());
    if stripped.is_empty()
        || stripped
            .iter()
            .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "password file must contain one non-empty line without NUL bytes",
        ));
    }
    Ok(SecretBytes(stripped.to_vec()))
}

fn read_secret_file(path: &Path, kind: &str) -> Result<SecretBytes> {
    let file = File::open(path).map_err(|error| {
        RnovError::new(
            ErrorKind::Io,
            format!("failed to open {kind} file '{}': {error}", path.display()),
        )
    })?;
    read_bounded_secret(file, kind)
}

fn read_bounded_secret(reader: impl Read, kind: &str) -> Result<SecretBytes> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_SECRET_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            RnovError::new(ErrorKind::Io, format!("failed to read {kind}: {error}"))
        })?;
    if bytes.len() > MAX_SECRET_BYTES {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("{kind} exceeds the {MAX_SECRET_BYTES}-byte limit"),
        ));
    }
    Ok(SecretBytes(bytes))
}

fn strip_one_line_ending(bytes: &[u8]) -> &[u8] {
    if let Some(bytes) = bytes.strip_suffix(b"\r\n") {
        return bytes;
    }
    bytes.strip_suffix(b"\n").unwrap_or(bytes)
}

fn serve_until_stdin(server: SqlTcpServer) -> Result<()> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&shutdown);
    thread::Builder::new()
        .name("rnmdb-shutdown-stdin".to_string())
        .spawn(move || {
            let mut line = String::new();
            let _ = io::stdin().lock().read_line(&mut line);
            signal.store(true, Ordering::Release);
        })
        .map_err(|error| {
            RnovError::new(
                ErrorKind::Internal,
                format!("failed to start shutdown listener: {error}"),
            )
        })?;
    server.serve_until(&shutdown)
}

fn resolve_bind_addresses(address: &str, allow_remote_plaintext: bool) -> Result<Vec<SocketAddr>> {
    let addresses = address.to_socket_addrs().map_err(|error| {
        RnovError::new(
            ErrorKind::InvalidInput,
            format!("failed to resolve bind address '{address}': {error}"),
        )
    })?;
    let addresses = addresses.collect::<Vec<_>>();
    if !allow_remote_plaintext && addresses.iter().any(|address| !address.ip().is_loopback()) {
        return Err(RnovError::new(
            ErrorKind::Security,
            "non-loopback listeners require --allow-remote-plaintext because the line protocol does not provide TLS",
        ));
    }
    if addresses.is_empty() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "bind address did not resolve to a socket address",
        ));
    }
    Ok(addresses)
}

fn parse_u64_option(args: &[String], position: usize, option: &str) -> Result<u64> {
    option_value(args, position, option)?
        .parse()
        .map_err(|_| invalid_arguments(format!("{option} requires an unsigned 64-bit integer")))
}

fn parse_usize_option(args: &[String], position: usize, option: &str) -> Result<usize> {
    option_value(args, position, option)?
        .parse()
        .map_err(|_| invalid_arguments(format!("{option} requires a positive integer")))
}

fn option_value<'a>(args: &'a [String], position: usize, option: &str) -> Result<&'a str> {
    args.get(position + 1)
        .map(String::as_str)
        .ok_or_else(|| invalid_arguments(format!("{option} requires a value")))
}

fn require_once(condition: bool, option: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid_arguments(format!(
            "{option} may be specified only once"
        )))
    }
}

fn invalid_arguments(message: impl Into<String>) -> RnovError {
    RnovError::new(
        ErrorKind::InvalidInput,
        format!("{}; run 'rnmdbd help' for usage", message.into()),
    )
}

fn print_help() -> Result<()> {
    let defaults = SqlServerOptions::default();
    println!(
        "RNovModularDB server {}\n\nUSAGE:\n  rnmdbd serve (--memory | --database <PATH> (--page-key-env | --page-key-file <KEY_PATH>)) [OPTIONS]\n  rnmdbd help\n  rnmdbd version\n\nSECURITY OPTIONS:\n  --auth-user <USER> --auth-password-file <PATH> [--auth-role-id <ID>]\n  --allow-unauthenticated\n  --allow-remote-plaintext\n\nSERVER OPTIONS:\n  --bind <ADDRESS>                     default: {DEFAULT_BIND_ADDRESS}\n  --instance-id <ID>                   default: 1\n  --database-id <ID>                   default: 1\n  --max-clients <COUNT>                default: {}\n  --max-command-bytes <BYTES>          range: 256..=16777216, default: {}\n  --client-io-timeout-ms <MILLISECONDS> default: {}\n  --graceful-drain-timeout-ms <MS>     default: {}\n  --forced-drain-timeout-ms <MS>       default: {}\n  --once                               accept one client and exit\n  --shutdown-on-stdin                  stop accepting after one stdin line or EOF\n\nThe line protocol has no TLS. Non-loopback listeners are rejected unless --allow-remote-plaintext is explicit.",
        env!("CARGO_PKG_VERSION"),
        defaults.max_active_clients(),
        defaults.max_command_bytes(),
        defaults.client_io_timeout().as_millis(),
        defaults.client_drain_timeout().as_millis(),
        defaults.forced_client_drain_timeout().as_millis(),
    );
    Ok(())
}

fn print_version() -> Result<()> {
    println!("rnmdbd {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
