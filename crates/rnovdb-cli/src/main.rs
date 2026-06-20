use std::io::{self, Read};

use rnovdb_cli::{CommandOutput, LocalSession, inspect_storage};
use rnovdb_storage::SingleFileInspection;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> rnovdb_common::Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if !args.is_empty() {
        return run_command(&args);
    }

    run_sql_stdin()
}

fn run_command(args: &[String]) -> rnovdb_common::Result<()> {
    match args {
        [command, path] if command == "inspect" => {
            println!("{}", format_inspection(&inspect_storage(path)?));
            Ok(())
        }
        [command, ..] => Err(rnovdb_common::RnovError::new(
            rnovdb_common::ErrorKind::InvalidInput,
            format!("unsupported command '{command}'"),
        )),
        [] => run_sql_stdin(),
    }
}

fn run_sql_stdin() -> rnovdb_common::Result<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).map_err(|err| {
        rnovdb_common::RnovError::new(
            rnovdb_common::ErrorKind::Io,
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

fn format_output(output: CommandOutput) -> String {
    match output {
        CommandOutput::Rows(batch) => format!("{:?}", batch.rows()),
        CommandOutput::RowsAffected(rows) => format!("{rows} rows affected"),
        CommandOutput::SchemaChanged => "schema changed".to_string(),
        CommandOutput::Text(text) => text,
    }
}
