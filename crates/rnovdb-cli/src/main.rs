use std::io::{self, Read};

use rnovdb_cli::{CommandOutput, LocalSession};

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> rnovdb_common::Result<()> {
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

fn format_output(output: CommandOutput) -> String {
    match output {
        CommandOutput::Rows(batch) => format!("{:?}", batch.rows()),
        CommandOutput::RowsAffected(rows) => format!("{rows} rows affected"),
        CommandOutput::SchemaChanged => "schema changed".to_string(),
    }
}
