//! `aios`: the one way to change an AIOS system (spec §4.2).
//!
//! Exit codes: 0 success, 1 operational error (including usage errors), 2 invalid manifest.

mod cli;
mod commands;
mod context;
mod failure;
mod lock;

use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = match cli::Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // Help and version go to stdout and exit 0; usage errors exit 1, because 2
            // means "invalid manifest".
            let _ = e.print();
            return if e.use_stderr() {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            };
        }
    };
    match commands::run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("{failure}");
            ExitCode::from(failure.code)
        }
    }
}
