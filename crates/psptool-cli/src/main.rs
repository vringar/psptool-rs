//! `psptool` — command-line entry point.
//!
//! Subcommand wiring is fleshed out in issue #15 (drop-in flag compat with the
//! upstream Python `psptool`). This skeleton handles only `--version` and
//! `--help` so the binary is invokable end-to-end and downstream tests can
//! exec it as soon as they need to.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;

/// Top-level argv parser. Subcommands land in #15.
#[derive(Debug, Parser)]
#[command(
    name = "psptool",
    version,
    about = "Inspect and modify AMD PSP firmware images.",
    long_about = None,
)]
struct Cli {}

fn main() -> ExitCode {
    let _cli = Cli::parse();

    eprintln!(
        "psptool {} (psptool-core {}, psptool-ops {})",
        env!("CARGO_PKG_VERSION"),
        psptool_core::VERSION,
        psptool_ops::CORE_VERSION,
    );
    eprintln!("note: subcommands are not implemented yet (tracked in issue #15).");
    ExitCode::from(2)
}
