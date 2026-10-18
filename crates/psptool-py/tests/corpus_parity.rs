//! Corpus parity of the Python bindings against the reference PSPTool
//! (`.design/psptool-py/bindings.md` AC-1..AC-3).
//!
//! For every ROM under `<corpus>/test_files/` two trials run:
//!
//! * `dump::<rom>` — `tests/oracle_dump.py` runs under the reference
//!   interpreter (`PSPTOOL_REFERENCE`) twice: importing upstream PSPTool, and
//!   with the bindings staged first on `PYTHONPATH`. Every line after the
//!   implementation banner must be identical: the `(rom, directory, file)`
//!   walk with each file's class, address, size, type, readable strings,
//!   md5, entropy, flags, `sha256(get_bytes())`,
//!   `sha256(get_decrypted_body())`, `sha256(get_decrypted_decompressed_body())`,
//!   `sha256(header + body)`, signed bytes and decode-verification verdict.
//!   This is the psp-db / psp-etl cutover gate (board #388, #484).
//! * `edit::<rom>` — `tests/oracle_edit.py`: the bindings round-trip the
//!   unmodified image through `to_file`, a same-place `move_buffer` of every
//!   unambiguous file leaves it byte-identical, and the upstream replace +
//!   re-sign flow (flip a body byte, `resign_and_replace` with PEM keys the
//!   *reference* generated) produces an image whose re-signed file the
//!   reference's certificate tree verifies under the replaced key.
//!
//! Gating mirrors `psptool-cli/tests/differential.rs`: the `corpus` feature,
//! `PSPTOOL_TEST_CORPUS` and `PSPTOOL_REFERENCE` (the nix dev shell exports
//! both). When both are set but no trials materialise, the test fails loudly.

#[cfg_attr(
    not(feature = "corpus"),
    allow(dead_code, reason = "the helpers only drive corpus trials")
)]
mod common;

use libtest_mimic::{Arguments, Trial};

#[cfg(feature = "corpus")]
use libtest_mimic::Failed;
#[cfg(feature = "corpus")]
use std::path::{Path, PathBuf};

fn reference_available() -> bool {
    std::env::var_os("PSPTOOL_REFERENCE").is_some_and(|v| !v.is_empty())
}

fn main() {
    let args = Arguments::from_args();
    let trials = collect_trials();
    if reference_available()
        && std::env::var_os("PSPTOOL_TEST_CORPUS").is_some()
        && trials.is_empty()
    {
        eprintln!(
            "PSPTOOL_TEST_CORPUS and PSPTOOL_REFERENCE are both set but corpus_parity \
             collected zero trials (wrong corpus path, or the `corpus` feature is off). \
             Refusing to silently pass."
        );
        std::process::exit(1);
    }
    libtest_mimic::run(&args, trials).exit();
}

#[cfg(not(feature = "corpus"))]
fn collect_trials() -> Vec<Trial> {
    Vec::new()
}

#[cfg(feature = "corpus")]
fn collect_trials() -> Vec<Trial> {
    let reference = match std::env::var_os("PSPTOOL_REFERENCE") {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => return Vec::new(),
    };
    let roms = psptool_fixtures::corpus_rom_paths();
    if roms.is_empty() {
        return Vec::new();
    }
    let setup = common::stage("psptool-py-corpus-stage").and_then(|stage| {
        let keys = Path::new(env!("CARGO_TARGET_TMPDIR")).join("psptool-py-corpus-keys");
        if keys.exists() {
            std::fs::remove_dir_all(&keys).map_err(|e| e.to_string())?;
        }
        std::fs::create_dir_all(&keys).map_err(|e| e.to_string())?;
        let stub = keys.join("id");
        // Keys come from the reference (`cryptography`): the bindings must
        // load PEM files they did not write themselves.
        let out = common::python(
            &reference,
            None,
            &common::scripts().join("oracle_edit.py"),
            &["keys".as_ref(), stub.as_os_str()],
        )?;
        common::stdout_of(out, "reference key generation")?;
        Ok((stage, stub))
    });
    let (stage, stub) = match setup {
        Ok(s) => s,
        Err(e) => {
            return vec![Trial::test("corpus_parity::setup", move || {
                Err(Failed::from(e.clone()))
            })];
        }
    };

    let mut trials = Vec::new();
    for rom in roms {
        let name = rom
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unnamed>")
            .to_owned();
        let (r, s, p) = (reference.clone(), stage.clone(), rom.clone());
        trials.push(Trial::test(format!("dump::{name}"), move || {
            dump(&r, &s, &p)
        }));
        let (r, s, k) = (reference.clone(), stage.clone(), stub.clone());
        trials.push(Trial::test(format!("edit::{name}"), move || {
            edit(&r, &s, &k, &rom, &name)
        }));
    }
    trials
}

/// AC-1: identical walk dumps.
#[cfg(feature = "corpus")]
fn dump(reference: &Path, stage: &Path, rom: &Path) -> Result<(), Failed> {
    let script = common::scripts().join("oracle_dump.py");
    let theirs = common::stdout_of(
        common::python(reference, None, &script, &[rom.as_os_str()])?,
        "reference dump",
    )?;
    let ours = common::stdout_of(
        common::python(reference, Some(stage), &script, &[rom.as_os_str()])?,
        "bindings dump",
    )?;
    let (mut theirs, mut ours) = (theirs.lines(), ours.lines());
    let banner = |line: Option<&str>| line.unwrap_or_default().to_owned();
    let (their_impl, our_impl) = (banner(theirs.next()), banner(ours.next()));
    if !their_impl.contains("\"reference\"") || !our_impl.contains("\"psptool-rs\"") {
        return Err(format!("wrong implementations under test: {their_impl} / {our_impl}").into());
    }
    let mut count = 0usize;
    loop {
        match (theirs.next(), ours.next()) {
            (None, None) => break,
            (t, o) if t == o => count += 1,
            (t, o) => {
                return Err(format!(
                    "walk diverges after {count} identical records\n  reference: {}\n  bindings:  {}",
                    t.unwrap_or("<end>"),
                    o.unwrap_or("<end>")
                )
                .into());
            }
        }
    }
    if count == 0 {
        return Err("empty walk".into());
    }
    Ok(())
}

/// AC-2 + AC-3: round trip, no-op moves, and a re-sign the reference verifies.
#[cfg(feature = "corpus")]
fn edit(reference: &Path, stage: &Path, stub: &Path, rom: &Path, name: &str) -> Result<(), Failed> {
    let script = common::scripts().join("oracle_edit.py");
    let out = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("psptool-py-edit-{name}"));
    let summary = common::stdout_of(
        common::python(
            reference,
            Some(stage),
            &script,
            &[
                "edit".as_ref(),
                rom.as_os_str(),
                stub.as_os_str(),
                out.as_os_str(),
            ],
        )?,
        "bindings edit",
    )?;
    let summary = summary.trim().to_owned();
    let value: serde_json::Value =
        serde_json::from_str(&summary).map_err(|e| format!("summary {summary:?}: {e}"))?;
    if value["roundtrip"] != true {
        return Err(format!("unmodified to_file differs from the input: {summary}").into());
    }
    if value["move_noop"] != true || value["moved"].as_u64().unwrap_or(0) == 0 {
        return Err(format!("no-op move_buffer changed the image: {summary}").into());
    }
    if value["target"].is_null() {
        // Every corpus ROM carries a verified plain signed HeaderFile; a
        // missing target means the selection broke, not a legitimate skip.
        return Err(format!("no re-sign target selected: {summary}").into());
    }
    if value["ours_verified"] != true || value["ours_decode"][0] != true {
        return Err(format!("bindings do not verify their own re-sign: {summary}").into());
    }
    common::stdout_of(
        common::python(
            reference,
            None,
            &script,
            &[
                "verify".as_ref(),
                out.as_os_str(),
                stub.as_os_str(),
                summary.as_ref(),
            ],
        )?,
        "reference verification of the re-signed image",
    )?;
    let _ = std::fs::remove_file(&out);
    Ok(())
}
