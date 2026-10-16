// crates/rnmdb-cli/src/main.rs - RNovModularDB source module.
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
use std::path::PathBuf;

use rnmdb_cli::{
    backup_storage, inspect_storage, inspect_storage_with_key, restore_storage,
    restore_storage_dry_run, upgrade_storage, upgrade_storage_with_key, verify_storage,
    verify_storage_with_key,
};
mod key_input;
mod output;
mod script;

use key_input::{PageKeySource, page_key_from_source};

use output::{
    format_backup_report, format_inspection, format_restore_dry_run, format_restore_report,
    format_upgrade_report, format_verification,
};

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

    script::run_default_stdin()
}

fn run_command(args: &[String]) -> rnmdb_common::Result<()> {
    let Some((command, rest)) = args.split_first() else {
        return script::run_default_stdin();
    };
    match command.as_str() {
        "run" => script::run_command(rest),
        "inspect" => run_inspect_command(rest),
        "verify" => run_verify_command(rest),
        "backup" => run_backup_command(rest),
        "restore" => run_restore_command(rest),
        "upgrade" => run_upgrade_command(rest),
        "help" | "--help" | "-h" => print_help(),
        "version" | "--version" | "-V" => print_version(),
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

fn print_help() -> rnmdb_common::Result<()> {
    println!(
        "RNovModularDB {}\n\nUSAGE:\n  rnmdb\n  rnmdb run [--memory | --database <PATH> (--page-key-stdin | --page-key-env | --page-key-file <KEY_PATH>)] [--file <SQL_PATH>]\n  rnmdb inspect [KEY OPTION] <PATH>\n  rnmdb verify [KEY OPTION] <PATH>\n  rnmdb backup <SOURCE> <DESTINATION>\n  rnmdb restore [--dry-run] <BACKUP> <TARGET>\n  rnmdb upgrade [KEY OPTION] <SOURCE> <TARGET>\n  rnmdb help\n  rnmdb version\n\nKEY OPTIONS:\n  --page-key-stdin\n  --page-key-env\n  --page-key-file <KEY_PATH>\n\nWith no arguments, rnmdb runs a bounded SQL script from stdin in memory.",
        env!("CARGO_PKG_VERSION")
    );
    Ok(())
}

fn print_version() -> rnmdb_common::Result<()> {
    println!("rnmdb {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
