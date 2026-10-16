use std::{
    fs::File,
    io::{self, Read},
    path::PathBuf,
};

use rnmdb_cli::{CommandOutput, LocalSession};
use rnmdb_common::{ErrorKind, Result, RnovError};
use rnmdb_sql::{
    ast::{Statement, TransactionAction},
    parser::{parse_statement, split_statements},
};

use crate::{
    key_input::{PageKeySource, page_key_from_source},
    output::format_output,
};

const MAX_SQL_SCRIPT_BYTES: usize = 16 * 1024 * 1024;

enum ScriptSource {
    Stdin,
    File(PathBuf),
}

enum SessionMode {
    Memory,
    SingleFile {
        path: PathBuf,
        key_source: PageKeySource,
    },
}

struct RunOptions {
    mode: SessionMode,
    source: ScriptSource,
}

pub(super) fn run_default_stdin() -> Result<()> {
    execute_run(RunOptions {
        mode: SessionMode::Memory,
        source: ScriptSource::Stdin,
    })
}

pub(super) fn run_command(args: &[String]) -> Result<()> {
    execute_run(parse_run_options(args)?)
}

fn parse_run_options(args: &[String]) -> Result<RunOptions> {
    let mut memory = false;
    let mut database = None;
    let mut key_source = None;
    let mut source = None;
    let mut position = 0;

    while position < args.len() {
        match args[position].as_str() {
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
            "--page-key-stdin" => {
                require_once(key_source.is_none(), "page key source")?;
                key_source = Some(PageKeySource::Stdin);
                position += 1;
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
            "--file" => {
                require_once(source.is_none(), "--file")?;
                source = Some(ScriptSource::File(PathBuf::from(option_value(
                    args, position, "--file",
                )?)));
                position += 2;
            }
            unknown => {
                return Err(invalid_run_arguments(format!(
                    "unsupported run option '{unknown}'"
                )));
            }
        }
    }

    let mode = match (memory, database, key_source) {
        (false, None, None) | (true, None, None) => SessionMode::Memory,
        (false, Some(path), Some(key_source)) => SessionMode::SingleFile { path, key_source },
        (true, Some(_), _) => {
            return Err(invalid_run_arguments(
                "--memory and --database are mutually exclusive",
            ));
        }
        (_, Some(_), None) => {
            return Err(invalid_run_arguments(
                "--database requires one page key source",
            ));
        }
        (_, None, Some(_)) => {
            return Err(invalid_run_arguments(
                "a page key source requires --database",
            ));
        }
    };

    if matches!(
        mode,
        SessionMode::SingleFile {
            key_source: PageKeySource::Stdin,
            ..
        }
    ) && source.is_none()
    {
        return Err(invalid_run_arguments(
            "--page-key-stdin requires --file so standard input is not shared with SQL input",
        ));
    }

    Ok(RunOptions {
        mode,
        source: source.unwrap_or(ScriptSource::Stdin),
    })
}

fn execute_run(options: RunOptions) -> Result<()> {
    let script = read_script(options.source)?;
    let statements = split_statements(&script)?;
    let (mut session, durable) = match options.mode {
        SessionMode::Memory => (LocalSession::memory()?, false),
        SessionMode::SingleFile { path, key_source } => (
            LocalSession::single_file_with_key(path, page_key_from_source(key_source)?)?,
            true,
        ),
    };

    for statement in statements {
        let parsed = parse_statement(statement)?;
        let output = match session.execute(statement) {
            Ok(output) => output,
            Err(error) => {
                rollback_open_transaction(&mut session);
                return Err(error);
            }
        };
        let checkpoint = durable
            && !session.in_transaction()
            && output_changes_state(&output)
            && !is_transaction_control(&parsed);
        if checkpoint {
            session.checkpoint()?;
        }
        println!("{}", format_output(output));
    }

    if session.in_transaction() {
        rollback_open_transaction(&mut session);
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "SQL script ended with an active transaction; the transaction was rolled back",
        ));
    }
    Ok(())
}

fn rollback_open_transaction(session: &mut LocalSession) {
    if session.in_transaction() {
        let _ = session.execute("ROLLBACK;");
    }
}

fn output_changes_state(output: &CommandOutput) -> bool {
    matches!(
        output,
        CommandOutput::RowsAffected(_) | CommandOutput::SchemaChanged
    )
}

fn is_transaction_control(statement: &Statement) -> bool {
    matches!(
        statement,
        Statement::Transaction {
            action: TransactionAction::Begin
                | TransactionAction::Commit
                | TransactionAction::Rollback
        }
    )
}

fn read_script(source: ScriptSource) -> Result<String> {
    match source {
        ScriptSource::Stdin => {
            let stdin = io::stdin();
            read_bounded_script(stdin.lock(), "standard input")
        }
        ScriptSource::File(path) => {
            let file = File::open(&path).map_err(|error| {
                RnovError::new(
                    ErrorKind::Io,
                    format!("failed to open SQL file '{}': {error}", path.display()),
                )
            })?;
            read_bounded_script(file, &format!("SQL file '{}'", path.display()))
        }
    }
}

fn read_bounded_script(reader: impl Read, source: &str) -> Result<String> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_SQL_SCRIPT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            RnovError::new(ErrorKind::Io, format!("failed to read {source}: {error}"))
        })?;
    if bytes.len() > MAX_SQL_SCRIPT_BYTES {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("{source} exceeds the {MAX_SQL_SCRIPT_BYTES}-byte limit"),
        ));
    }
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes);
    String::from_utf8(bytes.to_vec()).map_err(|_| {
        RnovError::new(
            ErrorKind::InvalidInput,
            format!("{source} is not valid UTF-8"),
        )
    })
}

fn option_value<'a>(args: &'a [String], position: usize, option: &str) -> Result<&'a str> {
    args.get(position + 1)
        .map(String::as_str)
        .ok_or_else(|| invalid_run_arguments(format!("{option} requires a value")))
}

fn require_once(condition: bool, option: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid_run_arguments(format!(
            "{option} may be specified only once"
        )))
    }
}

fn invalid_run_arguments(message: impl Into<String>) -> RnovError {
    RnovError::new(
        ErrorKind::InvalidInput,
        format!(
            "{}; usage: rnmdb run [--memory | --database <PATH> (--page-key-stdin | --page-key-env | --page-key-file <KEY_PATH>)] [--file <SQL_PATH>]",
            message.into()
        ),
    )
}
