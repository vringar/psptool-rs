//! `psptool` — command-line entry point.
//!
//! Subcommand dispatcher built with `clap` (derive). Drop-in flag
//! compatibility with the upstream Python tool is the gating constraint —
//! see `cli.rs` for the surface and `docs/cli-surface.md` §1 for the spec.
//!
//! When no subcommand is supplied, the upstream action flags
//! (`-V`/`-E`/`-X`/`-R`) are honoured: `-V` prints version, `-E` (or no flag
//! with a positional `file`) falls through to `list`, `-X` to `extract`, and
//! `-R` to `replace`. The mapping makes existing scripts that pass the
//! single-letter flags continue working unchanged.

#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::process::ExitCode;

use anyhow::{Result, anyhow};
use clap::Parser;

mod cli;
mod cmds;
mod load;

use cli::{Cli, Command, ExtractArgs, ListArgs, ReplaceArgs};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    match dispatch(&cli, &mut out) {
        Ok(()) => ExitCode::from(0),
        Err(err) => {
            // Anyhow renders the cause chain with `{:#}`; mirrors how
            // `eyre`/anyhow CLIs surface user-facing failures (the upstream
            // Python tool also exits non-zero with a one-line error).
            let _ = writeln!(io::stderr(), "psptool: {err:#}");
            ExitCode::from(1)
        }
    }
}

fn dispatch(cli: &Cli, out: &mut dyn Write) -> Result<()> {
    if cli.version {
        writeln!(
            out,
            "psptool {} (psptool-core {}, psptool-ops {})",
            env!("CARGO_PKG_VERSION"),
            psptool_core::VERSION,
            psptool_ops::CORE_VERSION,
        )?;
        return Ok(());
    }

    if let Some(command) = &cli.command {
        return run_command(command, out);
    }

    // No subcommand and no file → mirror the upstream Python tool: print
    // help and exit 0.
    let Some(file) = cli.file.clone() else {
        use clap::CommandFactory;
        let mut cmd = Cli::command();
        let help = cmd.render_help();
        writeln!(out, "{help}")?;
        return Ok(());
    };

    if cli.extract_file {
        let args = ExtractArgs {
            rom_index: cli.rom_index,
            directory_index: cli.directory_index,
            file_index: cli.file_index,
            type_regex: cli.type_regex.clone(),
            outfile: cli.outfile.clone(),
            decompress: cli.decompress,
            decrypt: cli.decrypt,
            pem_key: cli.pem_key,
            no_duplicates: cli.no_duplicates,
            file,
        };
        return cmds::extract::run(&args, out);
    }

    if cli.replace_file {
        let outfile = cli
            .outfile
            .clone()
            .ok_or_else(|| anyhow!("-R/--replace-file requires -o/--outfile"))?;
        let dir = cli
            .directory_index
            .ok_or_else(|| anyhow!("-R/--replace-file requires -d/--directory-index"))?;
        let entry = cli
            .file_index
            .ok_or_else(|| anyhow!("-R/--replace-file requires -e/--file-index"))?;
        let args = ReplaceArgs {
            rom_index: cli.rom_index,
            directory_index: dir,
            file_index: entry,
            outfile,
            subfile: cli.subfile.clone(),
            privkey: cli.privkey.clone(),
            privkey_pass: cli.privkey_pass.clone(),
            file,
        };
        return cmds::replace::run(&args, out);
    }

    // Default action — `-E` / no flag.
    let args = ListArgs {
        rom_index: cli.rom_index,
        json: cli.json,
        no_duplicates: cli.no_duplicates,
        key_tree: cli.key_tree,
        metrics: cli.metrics,
        verbose: cli.verbose,
        file,
    };
    cmds::list::run(&args, out)
}

fn run_command(command: &Command, out: &mut dyn Write) -> Result<()> {
    match command {
        Command::List(args) => cmds::list::run(args, out),
        Command::Extract(args) => cmds::extract::run(args, out),
        Command::Replace(args) => cmds::replace::run(args, out),
        Command::Sign(args) => cmds::sign::run(args, out),
        Command::Verify(args) => cmds::verify::run(args, out),
        Command::SearchKeys(args) => cmds::search_keys::run(args, out),
    }
}
