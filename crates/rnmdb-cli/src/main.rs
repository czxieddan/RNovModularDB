use std::io::{self, Read};

use rnmdb_cli::{
    CommandOutput, LocalSession, backup_storage, inspect_storage, page_key_from_hex,
    restore_storage_dry_run, verify_storage, verify_storage_with_key,
};
use rnmdb_storage::{
    SingleFileBackupReport, SingleFileInspection, SingleFileRestoreDryRun,
    SingleFileVerificationReport,
};

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
    match args {
        [command, path] if command == "inspect" => {
            println!("{}", format_inspection(&inspect_storage(path)?));
            Ok(())
        }
        [command, path] if command == "verify" => {
            println!("{}", format_verification(&verify_storage(path)?));
            Ok(())
        }
        [command, key_flag, key_hex, path]
            if command == "verify" && key_flag == "--page-key-hex" =>
        {
            let key = page_key_from_hex(key_hex)?;
            println!(
                "{}",
                format_verification(&verify_storage_with_key(path, key)?)
            );
            Ok(())
        }
        [command, source, destination] if command == "backup" => {
            println!(
                "{}",
                format_backup_report(&backup_storage(source, destination)?)
            );
            Ok(())
        }
        [command, dry_run, backup, target] if command == "restore" && dry_run == "--dry-run" => {
            println!(
                "{}",
                format_restore_dry_run(&restore_storage_dry_run(backup, target)?)
            );
            Ok(())
        }
        [command, ..] => Err(rnmdb_common::RnovError::new(
            rnmdb_common::ErrorKind::InvalidInput,
            format!("unsupported command '{command}'"),
        )),
        [] => run_sql_stdin(),
    }
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
        format!("free_space_bytes: {}", inspection.free_space_bytes()),
        format!("encrypted_pages: {}", inspection.encrypted_pages()),
        format!(
            "capabilities: {}",
            inspection.capabilities().names().join(",")
        ),
    ]
    .join("\n")
}

fn format_verification(report: &SingleFileVerificationReport) -> String {
    [
        format!("path: {}", report.path().display()),
        format!("valid: {}", report.is_valid()),
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

fn format_output(output: CommandOutput) -> String {
    match output {
        CommandOutput::Rows(batch) => format!("{:?}", batch.rows()),
        CommandOutput::RowsAffected(rows) => format!("{rows} rows affected"),
        CommandOutput::SchemaChanged => "schema changed".to_string(),
        CommandOutput::Text(text) => text,
    }
}
