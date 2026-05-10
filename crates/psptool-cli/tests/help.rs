//! Snapshot tests for the CLI help output.
//!
//! Guards drop-in flag compatibility (`docs/cli-surface.md` §1) against
//! drift: every flag from the upstream reference must appear in the
//! top-level help, and each subcommand's help must keep its short letters
//! and long names.
//!
//! Snapshots live in `tests/snapshots/` and are reviewed via
//! `cargo insta review` — when a flag *intentionally* changes, the
//! reviewer accepts the new snapshot; an *unintended* flag rename or
//! removal fails the test.

use clap::CommandFactory;

#[path = "../src/cli.rs"]
mod cli;

fn render_help(args: &[&str]) -> String {
    let mut cmd = cli::Cli::command();
    let matches =
        cmd.try_get_matches_from_mut(std::iter::once("psptool").chain(args.iter().copied()));
    // For --help, clap returns Err with kind == DisplayHelp.
    if let Err(e) = matches {
        return e.render().to_string();
    }
    String::new()
}

#[test]
fn top_level_help() {
    insta::assert_snapshot!("top_level_help", render_help(&["--help"]));
}

#[test]
fn list_help() {
    insta::assert_snapshot!("list_help", render_help(&["list", "--help"]));
}

#[test]
fn extract_help() {
    insta::assert_snapshot!("extract_help", render_help(&["extract", "--help"]));
}

#[test]
fn replace_help() {
    insta::assert_snapshot!("replace_help", render_help(&["replace", "--help"]));
}

#[test]
fn sign_help() {
    insta::assert_snapshot!("sign_help", render_help(&["sign", "--help"]));
}

#[test]
fn verify_help() {
    insta::assert_snapshot!("verify_help", render_help(&["verify", "--help"]));
}

#[test]
fn search_keys_help() {
    insta::assert_snapshot!("search_keys_help", render_help(&["search-keys", "--help"]));
}
