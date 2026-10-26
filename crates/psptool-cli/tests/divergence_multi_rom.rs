//! Divergence: the default `-E` / `-E -j` listing of a multi-ROM blob.
//!
//! Upstream (PSPTool `241629b`) `__main__.py:267` / `:275` call
//! `psp.ls_json()` / `psp.ls()`, which iterate every ROM regardless of `-r`
//! (`psptool.py:67-68` `for rom_index, rom in enumerate(self.blob.roms)`,
//! `psptool.py:205` `for rom in self.blob.roms`). Our `-E` lists only the
//! `--rom-index` ROM (default 0), so the upper ROM's directories — and their
//! Generation cells — are missing from the default listing. The expected
//! values come from running the reference (`PSPTOOL_REFERENCE`) on the same
//! corpus ROM; the tests skip (note on stderr) when it or
//! `PSPTOOL_TEST_CORPUS` is unset. Tracking #132.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Output};

/// Two ROMs (`0x1000` and `0x1001000`), four directories in the upper one.
const MULTI_ROM: &str = "ASUS_PRIME-X470-PRO-ASUS-4804.CAP";

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// `(reference interpreter, corpus ROM)`, or `None` to skip.
fn setup() -> Option<(PathBuf, PathBuf)> {
    let (Some(reference), Some(corpus)) = (
        env_path("PSPTOOL_REFERENCE"),
        env_path("PSPTOOL_TEST_CORPUS"),
    ) else {
        eprintln!("PSPTOOL_REFERENCE or PSPTOOL_TEST_CORPUS unset: skipping");
        return None;
    };
    let rom = corpus.join("test_files").join(MULTI_ROM);
    assert!(rom.is_file(), "corpus ROM {} missing", rom.display());
    Some((reference, rom))
}

fn stdout(out: Output, what: &str) -> String {
    assert!(
        out.status.success(),
        "{what} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap_or_else(|e| panic!("{what}: non-UTF-8 stdout: {e}"))
}

/// `python3 -m psptool <args> <rom>`, upstream's CLI.
fn reference_run(reference: &PathBuf, rom: &PathBuf, args: &[&str]) -> String {
    let out = Command::new(reference)
        .args(["-m", "psptool"])
        .args(args)
        .arg(rom)
        .env_remove("PYTHONPATH")
        .current_dir(env!("CARGO_TARGET_TMPDIR"))
        .output()
        .unwrap_or_else(|e| panic!("spawning {}: {e}", reference.display()));
    stdout(out, "reference psptool")
}

fn our_run(rom: &PathBuf, args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_psptool"))
        .arg(rom)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawning our psptool: {e}"));
    stdout(out, "our psptool")
}

/// Leaf directory addresses of an `-E -j` listing (combo nodes, which only
/// we surface, are the documented equivalent divergence of
/// `differential.rs` and are dropped).
fn directory_addresses(json: &str) -> BTreeSet<u64> {
    let value: serde_json::Value =
        serde_json::from_str(json).unwrap_or_else(|e| panic!("parsing -E -j output: {e}"));
    value
        .as_array()
        .unwrap_or_else(|| panic!("-E -j output is not a list"))
        .iter()
        .filter(|d| !matches!(d["magic"].as_str(), Some("2PSP" | "2BHD")))
        .map(|d| {
            d["address"]
                .as_u64()
                .unwrap_or_else(|| panic!("directory without an address: {d}"))
        })
        .collect()
}

/// Divergence: default `-E -j` omits the upper ROM's directories
/// (`psptool.py:205`).
#[test]
fn json_listing_covers_every_rom() {
    let Some((reference, rom)) = setup() else {
        return;
    };
    let theirs = directory_addresses(&reference_run(&reference, &rom, &["-E", "-j"]));
    let ours = directory_addresses(&our_run(&rom, &["-E", "-j"]));
    assert!(
        theirs.iter().any(|&a| a >= 0x100_0000),
        "the reference lists no upper-ROM directory; wrong fixture"
    );
    let fmt = |s: &BTreeSet<u64>| s.iter().map(|a| format!("{a:#x}")).collect::<Vec<_>>();
    assert_eq!(
        fmt(&ours),
        fmt(&theirs),
        "-E -j directories: ours (left) vs reference (right)"
    );
}

/// Divergence: default `-E` prints one ROM table; upstream prints one per
/// ROM (`psptool.py:67-76`).
#[test]
fn table_listing_covers_every_rom() {
    let Some((reference, rom)) = setup() else {
        return;
    };
    let rom_tables = |text: &str| text.lines().filter(|l| l.starts_with("| ROM |")).count();
    let theirs = rom_tables(&reference_run(&reference, &rom, &["-E"]));
    let ours = rom_tables(&our_run(&rom, &["-E"]));
    assert!(
        theirs > 1,
        "the reference prints a single ROM table; wrong fixture"
    );
    assert_eq!(ours, theirs, "ROM tables: ours (left) vs reference (right)");
}
