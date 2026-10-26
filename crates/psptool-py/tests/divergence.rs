//! Pinned divergences of the Python bindings from the reference PSPTool
//! (vringar/PSPTool `241629b`), found by auditing the psptool-py surface
//! beyond the `(rom, directory, file)` walk `corpus_parity.rs` compares.
//!
//! Each test runs one case of `tests/oracle_divergence.py` under the
//! reference interpreter (`PSPTOOL_REFERENCE`) twice — importing upstream
//! PSPTool, then with this build's bindings staged first on `PYTHONPATH` — and
//! requires identical output after the implementation banner. The reference
//! run is the expected value (live oracle); nothing is copied from the
//! bindings side. Corpus-gated cases also need `PSPTOOL_TEST_CORPUS`. Like
//! `python_api.rs`, a test skips (with a note on stderr) when a variable it
//! needs is unset; the nix dev shell sets both.
//!
//! Every test is `#[ignore]`d with its tracking issue until the divergence is
//! fixed: `cargo test -p psptool-py --test divergence -- --ignored` shows
//! them failing.

mod common;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// `<corpus>/test_files/<name>`, or `None` (skip) without a corpus.
fn corpus_rom(name: &str) -> Option<PathBuf> {
    let Some(root) = env_path("PSPTOOL_TEST_CORPUS") else {
        eprintln!("PSPTOOL_TEST_CORPUS unset: skipping");
        return None;
    };
    let rom = root.join("test_files").join(name);
    assert!(rom.is_file(), "corpus ROM {} missing", rom.display());
    Some(rom)
}

/// Run `case` (optionally on `rom`) under the reference and under the
/// bindings; every output line after the banner must match.
fn assert_matches_reference(case: &str, rom: Option<&Path>) {
    let Some(reference) = env_path("PSPTOOL_REFERENCE") else {
        eprintln!("PSPTOOL_REFERENCE unset: skipping the reference comparison");
        return;
    };
    let stage = common::stage(&format!("psptool-py-divergence-{case}"))
        .unwrap_or_else(|e| panic!("staging the package: {e}"));
    let script = common::scripts().join("oracle_divergence.py");
    let mut args: Vec<&OsStr> = vec![case.as_ref()];
    if let Some(rom) = rom {
        args.push(rom.as_os_str());
    }
    let run = |pythonpath: Option<&Path>, what: &str| {
        common::python(&reference, pythonpath, &script, &args)
            .and_then(|out| common::stdout_of(out, what))
            .unwrap_or_else(|e| panic!("{e}"))
    };
    let theirs = run(None, "reference run");
    let ours = run(Some(&stage), "bindings run");
    let (mut theirs, mut ours) = (theirs.lines(), ours.lines());
    let (their_impl, our_impl) = (theirs.next(), ours.next());
    assert!(
        their_impl.is_some_and(|l| l.contains("\"reference\""))
            && our_impl.is_some_and(|l| l.contains("\"psptool-rs\"")),
        "wrong implementations under test: {their_impl:?} / {our_impl:?}"
    );
    let (theirs, ours): (Vec<&str>, Vec<&str>) = (theirs.collect(), ours.collect());
    assert!(!theirs.is_empty(), "the reference printed no records");
    assert_eq!(
        ours, theirs,
        "case {case}: bindings (left) vs reference (right)"
    );
}

/// Divergence: `PSPTool(rom_bytes)` of fewer than 8 MiB parses to an empty
/// blob; upstream `blob.py:53-54`
/// (`max(value for value in possible_rom_sizes if value * 1024 * 1024 <=
/// self.buffer_size)`) raises `ValueError`, which PSP-DB's `analyze.py`
/// relies on to skip non-firmware files.
#[test]
fn small_input_raises_value_error() {
    assert_matches_reference("small_input", None);
}

/// Divergence: a BIOS entry destination `>= 2**63` (0xffffffffffffffff on
/// 2523 corpus records) is extracted as `i64`, so `repr()` and
/// `get_readable_destination_address()` raise `OverflowError`; upstream
/// `entry.py:139-140`, `file.py:365-366`, `file.py:412-413` render
/// `0xffffffffffffffff`.
#[test]
fn destination_renders_as_unsigned_hex() {
    let Some(rom) = corpus_rom("H12SSW9.719") else {
        return;
    };
    assert_matches_reference("destination_text", Some(&rom));
}

/// Divergence: with a BIOS (0x62) destination of 0xffffffffffffffff,
/// upstream `ls()` (`psptool.py:149-158`) and `ls_json()`
/// (`psptool.py:257-258`) list it; the bindings raise `OverflowError`.
#[test]
fn destination_listing_survives_u64_max() {
    let Some(rom) = corpus_rom("ASRock-A520M-HSV-1.31.ROM") else {
        return;
    };
    assert_matches_reference("destination_listing", Some(&rom));
}

/// Divergence: only `BiosFile.__init__` stores `destination`
/// (`file.py:396-399`); the bindings also set it on HeaderFile / PubkeyFile
/// objects parsed from a BIOS directory.
#[test]
#[ignore = "divergence: destination attribute on non-BiosFile classes of a BIOS directory (file.py:396-399); tracking #127"]
fn destination_only_on_bios_file() {
    let Some(rom) = corpus_rom("H12SSW9.719") else {
        return;
    };
    assert_matches_reference("destination_attribute", Some(&rom));
}

/// Divergence: `ls()` renders `soft_fuse(hex(offset + (rsv0 << 32)))`
/// (`psptool.py:164-165`) on Python ints; the bindings wrap an rsv0 with bit
/// 31 set to a negative `i64`.
#[test]
#[ignore = "divergence: ls() soft_fuse() wraps rsv0 >= 0x80000000 to a negative i64 (psptool.py:164-165); tracking #128"]
fn soft_fuse_listing_is_unsigned() {
    let Some(rom) = corpus_rom("ASRock-A520M-HSV-1.31.ROM") else {
        return;
    };
    assert_matches_reference("soft_fuse_listing", Some(&rom));
}

/// Divergence: a magic holding `\t` / `\x0b` (kept by
/// `header_file.py:155-159`) is padded by prettytable as a width -1 cell
/// (`psptool.py:200`); the bindings' renderer pads by character count.
#[test]
#[ignore = "divergence: ls() pads tab/CR/VT/FF cells by char count, prettytable by wcswidth -1 (psptool.py:200); tracking #129"]
fn listing_pads_control_whitespace_like_prettytable() {
    let Some(rom) = corpus_rom("ASRock-A520M-HSV-1.31.ROM") else {
        return;
    };
    assert_matches_reference("listing_control_whitespace", Some(&rom));
}

/// Divergence: upstream `__init__.py:17` imports `.psptool`, which loads
/// every submodule, so `import psptool; psptool.header_file.HeaderFile`
/// works; the bindings' `__init__.py` imports only `_native`.
#[test]
fn import_psptool_loads_submodules() {
    assert_matches_reference("import_surface", None);
}

/// Divergence: the instance setters mask any int (`entry.py:100-102`,
/// `:178-180`) and the `struct.pack` setters raise `struct.error`
/// (`entry.py:76-164`, `directory.py:174-180`); the bindings raise
/// `OverflowError` for both.
#[test]
#[ignore = "divergence: entry/directory setters raise OverflowError where upstream masks or raises struct.error (entry.py:100-102,178-180); tracking #131"]
fn entry_setters_match_upstream() {
    let Some(rom) = corpus_rom("ASRock-A520M-HSV-1.31.ROM") else {
        return;
    };
    assert_matches_reference("entry_setters", Some(&rom));
}
