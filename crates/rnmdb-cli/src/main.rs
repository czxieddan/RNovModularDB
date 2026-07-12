use std::{
    env,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
};

use rnmdb_cli::{
    CommandOutput, LocalSession, backup_storage, inspect_storage, inspect_storage_with_key,
    page_key_from_hex, restore_storage, restore_storage_dry_run, upgrade_storage,
    upgrade_storage_with_key, verify_storage, verify_storage_with_key,
};
use rnmdb_storage::{
    PageCryptoKey, SingleFileBackupReport, SingleFileInspection, SingleFileRestoreDryRun,
    SingleFileRestoreReport, SingleFileUpgradeReport, SingleFileVerificationReport,
};

const PAGE_KEY_ENVIRONMENT_VARIABLE: &str = "RNMDB_PAGE_KEY_HEX";
const MAX_PAGE_KEY_INPUT_BYTES: usize = 68;

enum PageKeySource {
    Stdin,
    Environment,
    File(PathBuf),
}

enum SinglePathCommand<'a> {
    Plain(&'a str),
    Keyed {
        source: PageKeySource,
        path: &'a str,
    },
}

enum UpgradeCommand<'a> {
    Plain {
        source: &'a str,
        target: &'a str,
    },
    Keyed {
        key_source: PageKeySource,
        source: &'a str,
        target: &'a str,
    },
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
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> rnmdb_common::Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if !args.is_empty() {
        return run_command(&args);
    }

    run_sql_stdin()
}

fn run_command(args: &[String]) -> rnmdb_common::Result<()> {
    let Some((command, rest)) = args.split_first() else {
        return run_sql_stdin();
    };
    match command.as_str() {
        "inspect" => run_inspect_command(rest),
        "verify" => run_verify_command(rest),
        "backup" => run_backup_command(rest),
        "restore" => run_restore_command(rest),
        "upgrade" => run_upgrade_command(rest),
        _ => unsupported_command(command),
    }
}

fn run_inspect_command(args: &[String]) -> rnmdb_common::Result<()> {
    match parse_single_path_command("inspect", args)? {
        SinglePathCommand::Plain(path) => {
            println!("{}", format_inspection(&inspect_storage(path)?));
            Ok(())
        }
        SinglePathCommand::Keyed { source, path } => {
            let key = page_key_from_source(source)?;
            println!(
                "{}",
                format_inspection(&inspect_storage_with_key(path, key)?)
            );
            Ok(())
        }
    }
}

fn run_verify_command(args: &[String]) -> rnmdb_common::Result<()> {
    match parse_single_path_command("verify", args)? {
        SinglePathCommand::Plain(path) => {
            println!("{}", format_verification(&verify_storage(path)?));
            Ok(())
        }
        SinglePathCommand::Keyed { source, path } => {
            let key = page_key_from_source(source)?;
            println!(
                "{}",
                format_verification(&verify_storage_with_key(path, key)?)
            );
            Ok(())
        }
    }
}

fn run_backup_command(args: &[String]) -> rnmdb_common::Result<()> {
    match args {
        [source, destination] => {
            println!(
                "{}",
                format_backup_report(&backup_storage(source, destination)?)
            );
            Ok(())
        }
        _ => invalid_command_arguments("backup", &["rnmdb backup <SOURCE> <DESTINATION>"]),
    }
}

fn run_restore_command(args: &[String]) -> rnmdb_common::Result<()> {
    match args {
        [dry_run, backup, target] if dry_run == "--dry-run" => {
            println!(
                "{}",
                format_restore_dry_run(&restore_storage_dry_run(backup, target)?)
            );
            Ok(())
        }
        [backup, target] => {
            println!(
                "{}",
                format_restore_report(&restore_storage(backup, target)?)
            );
            Ok(())
        }
        _ => invalid_command_arguments(
            "restore",
            &[
                "rnmdb restore <BACKUP> <TARGET>",
                "rnmdb restore --dry-run <BACKUP> <TARGET>",
            ],
        ),
    }
}

fn run_upgrade_command(args: &[String]) -> rnmdb_common::Result<()> {
    match parse_upgrade_command(args)? {
        UpgradeCommand::Plain { source, target } => {
            println!(
                "{}",
                format_upgrade_report(&upgrade_storage(source, target)?)
            );
            Ok(())
        }
        UpgradeCommand::Keyed {
            key_source,
            source,
            target,
        } => {
            let key = page_key_from_source(key_source)?;
            println!(
                "{}",
                format_upgrade_report(&upgrade_storage_with_key(source, target, key)?)
            );
            Ok(())
        }
    }
}

fn parse_single_path_command<'a>(
    command: &str,
    args: &'a [String],
) -> rnmdb_common::Result<SinglePathCommand<'a>> {
    match args {
        [path] => Ok(SinglePathCommand::Plain(path)),
        [flag, path] if flag == "--page-key-stdin" => Ok(SinglePathCommand::Keyed {
            source: PageKeySource::Stdin,
            path,
        }),
        [flag, path] if flag == "--page-key-env" => Ok(SinglePathCommand::Keyed {
            source: PageKeySource::Environment,
            path,
        }),
        [flag, key_path, path] if flag == "--page-key-file" => Ok(SinglePathCommand::Keyed {
            source: PageKeySource::File(PathBuf::from(key_path)),
            path,
        }),
        [flag, ..] if flag == "--page-key-hex" => reject_argv_page_key(),
        _ => invalid_command_arguments(command, &single_path_usage(command)),
    }
}

fn parse_upgrade_command(args: &[String]) -> rnmdb_common::Result<UpgradeCommand<'_>> {
    match args {
        [source, target] => Ok(UpgradeCommand::Plain { source, target }),
        [flag, source, target] if flag == "--page-key-stdin" => Ok(UpgradeCommand::Keyed {
            key_source: PageKeySource::Stdin,
            source,
            target,
        }),
        [flag, source, target] if flag == "--page-key-env" => Ok(UpgradeCommand::Keyed {
            key_source: PageKeySource::Environment,
            source,
            target,
        }),
        [flag, key_path, source, target] if flag == "--page-key-file" => {
            Ok(UpgradeCommand::Keyed {
                key_source: PageKeySource::File(PathBuf::from(key_path)),
                source,
                target,
            })
        }
        [flag, ..] if flag == "--page-key-hex" => reject_argv_page_key(),
        _ => invalid_command_arguments("upgrade", &upgrade_usage()),
    }
}

fn single_path_usage(command: &str) -> [String; 4] {
    [
        format!("rnmdb {command} <PATH>"),
        format!("rnmdb {command} --page-key-stdin <PATH>"),
        format!("rnmdb {command} --page-key-env <PATH>"),
        format!("rnmdb {command} --page-key-file <KEY_PATH> <PATH>"),
    ]
}

fn upgrade_usage() -> [&'static str; 4] {
    [
        "rnmdb upgrade <SOURCE> <TARGET>",
        "rnmdb upgrade --page-key-stdin <SOURCE> <TARGET>",
        "rnmdb upgrade --page-key-env <SOURCE> <TARGET>",
        "rnmdb upgrade --page-key-file <KEY_PATH> <SOURCE> <TARGET>",
    ]
}

fn reject_argv_page_key<T>() -> rnmdb_common::Result<T> {
    Err(rnmdb_common::RnovError::new(
        rnmdb_common::ErrorKind::InvalidInput,
        "--page-key-hex is disabled because command-line arguments can expose secrets; use --page-key-stdin, --page-key-env, or --page-key-file",
    ))
}

fn page_key_from_source(source: PageKeySource) -> rnmdb_common::Result<PageCryptoKey> {
    let secret = match source {
        PageKeySource::Stdin => read_page_key_stdin(),
        PageKeySource::Environment => read_page_key_environment(),
        PageKeySource::File(path) => read_page_key_file(&path),
    }?;
    parse_page_key_secret(&secret)
}

fn read_page_key_stdin() -> rnmdb_common::Result<SecretBytes> {
    let stdin = io::stdin();
    read_bounded_page_key(stdin.lock(), "standard input")
}

fn read_page_key_environment() -> rnmdb_common::Result<SecretBytes> {
    match env::var(PAGE_KEY_ENVIRONMENT_VARIABLE) {
        Ok(value) => bounded_page_key(value.into_bytes(), PAGE_KEY_ENVIRONMENT_VARIABLE),
        Err(env::VarError::NotPresent) => Err(rnmdb_common::RnovError::new(
            rnmdb_common::ErrorKind::InvalidInput,
            format!("{PAGE_KEY_ENVIRONMENT_VARIABLE} is not set"),
        )),
        Err(env::VarError::NotUnicode(_)) => Err(rnmdb_common::RnovError::new(
            rnmdb_common::ErrorKind::InvalidInput,
            format!("{PAGE_KEY_ENVIRONMENT_VARIABLE} is not valid UTF-8"),
        )),
    }
}

fn read_page_key_file(path: &Path) -> rnmdb_common::Result<SecretBytes> {
    let file = File::open(path).map_err(|err| {
        rnmdb_common::RnovError::new(
            rnmdb_common::ErrorKind::Io,
            format!("failed to open page key file '{}': {err}", path.display()),
        )
    })?;
    read_bounded_page_key(file, "page key file")
}

fn read_bounded_page_key(reader: impl Read, source: &str) -> rnmdb_common::Result<SecretBytes> {
    let mut bytes = Vec::with_capacity(MAX_PAGE_KEY_INPUT_BYTES + 1);
    reader
        .take((MAX_PAGE_KEY_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|err| {
            rnmdb_common::RnovError::new(
                rnmdb_common::ErrorKind::Io,
                format!("failed to read page key from {source}: {err}"),
            )
        })?;
    bounded_page_key(bytes, source)
}

fn bounded_page_key(bytes: Vec<u8>, source: &str) -> rnmdb_common::Result<SecretBytes> {
    let secret = SecretBytes(bytes);
    if secret.as_slice().len() <= MAX_PAGE_KEY_INPUT_BYTES {
        return Ok(secret);
    }
    Err(rnmdb_common::RnovError::new(
        rnmdb_common::ErrorKind::InvalidInput,
        format!("page key from {source} exceeds the maximum supported length"),
    ))
}

fn parse_page_key_secret(secret: &SecretBytes) -> rnmdb_common::Result<PageCryptoKey> {
    let bytes = strip_one_line_ending(secret.as_slice());
    let hex = std::str::from_utf8(bytes).map_err(|_| {
        rnmdb_common::RnovError::new(
            rnmdb_common::ErrorKind::InvalidInput,
            "page key input is not valid UTF-8",
        )
    })?;
    page_key_from_hex(hex)
}

fn strip_one_line_ending(bytes: &[u8]) -> &[u8] {
    if let Some(bytes) = bytes.strip_suffix(b"\r\n") {
        return bytes;
    }
    bytes.strip_suffix(b"\n").unwrap_or(bytes)
}

fn unsupported_command(command: &str) -> rnmdb_common::Result<()> {
    Err(rnmdb_common::RnovError::new(
        rnmdb_common::ErrorKind::InvalidInput,
        format!("unsupported command '{command}'"),
    ))
}

fn invalid_command_arguments<R, T: AsRef<str>>(
    command: &str,
    usage: &[T],
) -> rnmdb_common::Result<R> {
    let usage = usage
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<_>>()
        .join("; ");
    Err(rnmdb_common::RnovError::new(
        rnmdb_common::ErrorKind::InvalidInput,
        format!("invalid arguments for '{command}'; usage: {usage}"),
    ))
}

fn run_sql_stdin() -> rnmdb_common::Result<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).map_err(|err| {
        rnmdb_common::RnovError::new(
            rnmdb_common::ErrorKind::Io,
            format!("failed to read stdin: {err}"),
        )
    })?;

    let mut session = LocalSession::memory()?;
    for statement in input
        .split(';')
        .map(str::trim)
        .filter(|sql| !sql.is_empty())
    {
        let sql = format!("{statement};");
        println!("{}", format_output(session.execute(&sql)?));
    }

    Ok(())
}

fn format_inspection(inspection: &SingleFileInspection) -> String {
    [
        format!("path: {}", inspection.path().display()),
        format!("mode: {:?}", inspection.mode()),
        format!("page_size_bytes: {}", inspection.page_size().bytes()),
        format!("format_version: {}", inspection.format_version()),
        format!(
            "superblock_generation: {}",
            inspection.superblock_generation()
        ),
        format!("file_len_bytes: {}", inspection.file_len_bytes()),
        format!("data_start_bytes: {}", inspection.data_start_bytes()),
        format!(
            "page_record_size_bytes: {}",
            inspection.page_record_size_bytes()
        ),
        format!("page_record_slots: {}", inspection.page_record_slots()),
        format!(
            "present_page_records: {}",
            inspection.present_page_records()
        ),
        format!("empty_page_slots: {}", inspection.empty_page_slots()),
        format!(
            "authenticated_page_records: {}",
            inspection.authenticated_page_records()
        ),
        format!(
            "checksum_verified_page_records: {}",
            inspection.checksum_verified_page_records()
        ),
        format!(
            "superblock_checksum_verified: {}",
            inspection.superblock_checksum_verified()
        ),
        format!("free_space_bytes: {}", inspection.free_space_bytes()),
        format!("encrypted_pages: {}", inspection.encrypted_pages()),
        format!(
            "capabilities: {}",
            inspection.capabilities().names().join(",")
        ),
    ]
    .into_iter()
    .chain(inspection.page_records().iter().map(|record| {
        format!(
            "page_record[{}]: page_id={} offset_bytes={} present={} encrypted={} authenticated={} checksum_verified={} counter={} encrypted_payload_bytes={}",
            record.slot_index(),
            record.page_id().get(),
            record.offset_bytes(),
            record.is_present(),
            record.encrypted_payload_bytes().is_some(),
            record.encryption_authenticated(),
            record.page_checksum_verified(),
            optional_u32(record.encryption_counter()),
            optional_u64(record.encrypted_payload_bytes()),
        )
    }))
    .collect::<Vec<_>>()
    .join("\n")
}

fn optional_u32(value: Option<u32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_string())
}

fn optional_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_string())
}

fn format_verification(report: &SingleFileVerificationReport) -> String {
    [
        format!("path: {}", report.path().display()),
        format!("valid: {}", report.is_valid()),
        format!("format_version: {}", report.format_version()),
        format!(
            "format_compatibility: {}",
            report.format_compatibility().as_str()
        ),
        format!(
            "supported_format_versions: {}..={}",
            report.min_supported_format_version(),
            report.max_supported_format_version()
        ),
        format!("file_len_bytes: {}", report.file_len_bytes()),
        format!("page_record_slots: {}", report.page_record_slots()),
        format!("present_page_records: {}", report.present_page_records()),
        format!("empty_page_slots: {}", report.empty_page_slots()),
        format!(
            "authenticated_page_records: {}",
            report.authenticated_page_records()
        ),
        format!(
            "encryption_authenticated: {}",
            report.encryption_authenticated()
        ),
    ]
    .join("\n")
}

fn format_restore_dry_run(report: &SingleFileRestoreDryRun) -> String {
    [
        format!("backup: {}", report.backup_path().display()),
        format!("target: {}", report.target_path().display()),
        format!("target_exists: {}", report.target_exists()),
        format!("backup_valid: {}", report.backup_valid()),
        format!("bytes_to_restore: {}", report.bytes_to_restore()),
        format!("page_record_slots: {}", report.page_record_slots()),
        format!("present_page_records: {}", report.present_page_records()),
    ]
    .join("\n")
}

fn format_restore_report(report: &SingleFileRestoreReport) -> String {
    [
        format!("backup: {}", report.backup_path().display()),
        format!("target: {}", report.target_path().display()),
        format!("bytes_restored: {}", report.bytes_restored()),
        format!("page_record_slots: {}", report.page_record_slots()),
        format!("present_page_records: {}", report.present_page_records()),
    ]
    .join("\n")
}

fn format_backup_report(report: &SingleFileBackupReport) -> String {
    [
        format!("source: {}", report.source_path().display()),
        format!("destination: {}", report.destination_path().display()),
        format!("bytes_copied: {}", report.bytes_copied()),
        format!("page_size_bytes: {}", report.page_size().bytes()),
        format!("superblock_generation: {}", report.superblock_generation()),
        format!("page_record_slots: {}", report.page_record_slots()),
        format!("present_page_records: {}", report.present_page_records()),
    ]
    .join("\n")
}

fn format_upgrade_report(report: &SingleFileUpgradeReport) -> String {
    [
        format!("source: {}", report.source_path().display()),
        format!("target: {}", report.target_path().display()),
        format!("source_format_version: {}", report.source_format_version()),
        format!("target_format_version: {}", report.target_format_version()),
        format!("bytes_written: {}", report.bytes_written()),
        format!("page_size_bytes: {}", report.page_size().bytes()),
        format!("superblock_generation: {}", report.superblock_generation()),
        format!("page_record_slots: {}", report.page_record_slots()),
        format!("pages_upgraded: {}", report.pages_upgraded()),
        format!("key_rotated: {}", report.key_rotated()),
    ]
    .into_iter()
    .chain(report.page_reports().iter().map(|page| {
        format!(
            "upgraded_page: page_id={} source_counter={} target_counter={}",
            page.page_id().get(),
            page.source_counter(),
            page.target_counter()
        )
    }))
    .collect::<Vec<_>>()
    .join("\n")
}

fn format_output(output: CommandOutput) -> String {
    match output {
        CommandOutput::Rows(batch) => format!("{:?}", batch.rows()),
        CommandOutput::RowsAffected(rows) => format!("{rows} rows affected"),
        CommandOutput::SchemaChanged => "schema changed".to_string(),
        CommandOutput::Text(text) => text,
    }
}
