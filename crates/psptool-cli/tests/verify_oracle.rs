//! `psptool verify` vs the reference's certificate tree (#93).
//!
//! Upstream has no `verify` subcommand; its notion of "this signed file
//! verifies" is `SignedEntity.is_verified()` (`cert_tree.py:72-95`) over the
//! one `CertificateTree` built from the whole blob (`cert_tree.py:385-397`:
//! every ROM, every `PubkeyFile`, every `KeyStoreFile` `$KDB` key). For every
//! corpus image and ROM index, every entry `psptool verify -j` reports at a
//! flash address where the reference holds a signed `HeaderFile` (or
//! `KeyStoreFile`) must carry the reference's outcome:
//!
//! | reference                                   | `psptool verify` |
//! | ------------------------------------------- | ---------------- |
//! | `is_verified()` is `True`                   | `verified`       |
//! | `is_verified()` is `False`                  | `bad-signature`  |
//! | raises `NoCertifyingKey` (`cert_tree.py:80`) | `unknown-key`    |
//! | raises anything else                        | `error: ...`     |
//!
//! Skips (with a note on stderr) when `PSPTOOL_REFERENCE` or
//! `PSPTOOL_TEST_CORPUS` is unset, like `differential.rs`; the nix dev shell
//! sets both.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

/// Reference side: `path address outcome` per signed HeaderFile-class file of
/// every directory of every ROM (`blob.roms -> rom.directories ->
/// directory.files`, as `CertificateTree.from_blob` walks them).
const ORACLE: &str = r#"
import sys
from psptool import PSPTool
from psptool.errors import NoCertifyingKey
from psptool.header_file import HeaderFile
for path in sys.argv[1:]:
    psp = PSPTool.from_file(path)
    for rom in psp.blob.roms:
        for directory in rom.directories:
            for f in directory.files:
                entity = f.signed_entity if isinstance(f, HeaderFile) else None
                if entity is None:
                    continue
                try:
                    outcome = 'verified' if entity.is_verified() else 'bad-signature'
                except NoCertifyingKey:
                    outcome = 'unknown-key'
                except Exception:
                    outcome = 'error'
                print(path, f.get_address(), outcome)
"#;

/// ROM indices probed per image; the corpus tops out at 2 ROMs.
const MAX_ROM_INDEX: usize = 8;

type Outcomes = BTreeMap<(String, u64), BTreeSet<String>>;

fn reference_outcomes(reference: &Path, roms: &[PathBuf]) -> Outcomes {
    let out = Command::new(reference)
        .arg("-c")
        .arg(ORACLE)
        .args(roms)
        .output()
        .unwrap_or_else(|e| panic!("spawning {}: {e}", reference.display()));
    assert!(
        out.status.success(),
        "reference oracle failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut outcomes = Outcomes::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut fields = line.rsplitn(3, ' ');
        let (Some(outcome), Some(address), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            panic!("malformed oracle line {line:?}");
        };
        outcomes
            .entry((path.to_string(), address.parse().expect("oracle address")))
            .or_default()
            .insert(outcome.to_string());
    }
    outcomes
}

/// `psptool verify -j -r N` over every ROM of `rom`, keyed like the oracle.
/// `error: <detail>` statuses collapse to `error`.
fn our_outcomes(rom: &Path, into: &Mutex<Outcomes>) {
    for rom_index in 0..MAX_ROM_INDEX {
        let out = Command::new(env!("CARGO_BIN_EXE_psptool"))
            .args(["verify", "-j", "-r", &rom_index.to_string()])
            .arg(rom)
            .output()
            .expect("spawning our psptool");
        // `verify` exits non-zero when any entry fails, after printing the
        // report; no report means the ROM index is past the last ROM.
        let Some(line) = String::from_utf8_lossy(&out.stdout)
            .lines()
            .find(|l| l.starts_with('['))
            .map(str::to_owned)
        else {
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains("out of range"),
                "{} -r {rom_index}: {stderr}",
                rom.display()
            );
            return;
        };
        let rows: serde_json::Value = serde_json::from_str(&line).expect("verify JSON");
        let mut outcomes = into.lock().expect("outcome map");
        for row in rows.as_array().expect("verify JSON array") {
            let status = row["status"].as_str().expect("status");
            let status = if status.starts_with("error") {
                "error"
            } else {
                status
            };
            let address = row["body"].as_u64().expect("body offset");
            outcomes
                .entry((rom.display().to_string(), address))
                .or_default()
                .insert(status.to_string());
        }
    }
}

#[test]
fn corpus_verify_matches_reference_certificate_tree() {
    let reference = match std::env::var_os("PSPTOOL_REFERENCE") {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => {
            eprintln!("PSPTOOL_REFERENCE unset — skipping the reference differential");
            return;
        }
    };
    let roms = psptool_fixtures::corpus_rom_paths();
    if roms.is_empty() {
        eprintln!("PSPTOOL_TEST_CORPUS unset or empty — skipping the corpus differential");
        return;
    }

    let ours = Mutex::new(Outcomes::new());
    let theirs = std::thread::scope(|scope| {
        let oracle = scope.spawn(|| reference_outcomes(&reference, &roms));
        let workers = std::thread::available_parallelism().map_or(4, |n| n.get());
        for chunk in roms.chunks(roms.len().div_ceil(workers)) {
            let ours = &ours;
            scope.spawn(move || chunk.iter().for_each(|rom| our_outcomes(rom, ours)));
        }
        oracle.join().expect("reference oracle thread")
    });
    let ours = ours.into_inner().expect("outcome map");

    let mut compared = 0usize;
    let mut mismatches = Vec::new();
    for (key, expected) in &theirs {
        let Some(got) = ours.get(key) else { continue };
        compared += 1;
        if got != expected {
            mismatches.push(format!(
                "{} @{:#x}: ours {got:?}, reference {expected:?}",
                key.0, key.1
            ));
        }
    }
    eprintln!(
        "compared {compared} of {} reference signed-file addresses",
        theirs.len()
    );
    assert!(compared > 0, "no signed-file address in common");
    assert!(
        mismatches.is_empty(),
        "{} of {compared} differ:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
