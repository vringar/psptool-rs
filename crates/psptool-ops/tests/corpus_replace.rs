//! Mutation-locality property test for `replace_entry_body`, exercised across
//! the full `vendor/test-corpus` (issue #12 — companion to the
//! `corpus_roundtrip` test in `psptool-core`).
//!
//! For every ROM under `<corpus>/test_files/`, the test:
//!
//! 1. Parses the FET and walks every reachable directory.
//! 2. Picks the first non-soft-fuse-chain entry with a non-empty body.
//! 3. Calls `replace_psp_entry_body` / `replace_bios_entry_body` with a
//!    same-length sentinel buffer.
//! 4. Asserts the serialised ROM differs from the source ONLY inside the
//!    entry's body byte range — sibling entries, padding, and every other
//!    structural byte must be byte-identical to the input.
//!
//! Same-length is the headline case the issue calls out (locality property)
//! and matches what the existing `corpus_roundtrip` test already validates
//! for the lower-level `BlobEditor` API. Length-changing replacements are
//! exercised by the in-crate unit tests; doing it across every corpus ROM
//! would require knowing each ROM's per-entry slack, which #12 does not
//! attempt.
//!
//! Gating mirrors `corpus_roundtrip`:
//!
//! * Cargo feature `corpus` (declared in `psptool-ops/Cargo.toml`) opts the
//!   test binary into corpus iteration. With the feature off the trial
//!   collector returns an empty list and the binary exits clean.
//! * Runtime: `PSPTOOL_TEST_CORPUS` env var must point at a populated
//!   `test_files/` directory. Unset / missing → empty trial set; SET but
//!   collector found nothing → fail loudly (matches the headline test's
//!   "refuse to silently pass" stance).

use libtest_mimic::{Arguments, Trial};

#[cfg(feature = "corpus")]
use libtest_mimic::Failed;
#[cfg(feature = "corpus")]
use psptool_core::{
    BlobEditor, Directory, DirectoryRef, Entry, EntryClass, Fet, FlashOffset, RomSize, SourceBytes,
    directory::walk_directories,
    fet::{detect_rom_layout, scan_fet_candidates},
};
#[cfg(feature = "corpus")]
use psptool_fixtures::{CorpusRom, corpus_roms};
#[cfg(feature = "corpus")]
use psptool_ops::{replace_bios_entry_body, replace_psp_entry_body};

fn main() {
    let args = Arguments::from_args();
    let trials = collect_trials();

    if std::env::var_os("PSPTOOL_TEST_CORPUS").is_some() && trials.is_empty() {
        eprintln!(
            "PSPTOOL_TEST_CORPUS is set but corpus_replace collected zero \
             trials. Either the path is wrong, `test_files/` is missing, or \
             the `corpus` cargo feature is disabled."
        );
        std::process::exit(1);
    }

    libtest_mimic::run(&args, trials).exit();
}

/// ROMs whose FET candidate is found but the directory parse refuses it.
/// Same set as `corpus_roundtrip::SKIP_LIST` — these fail at the parser level
/// before this test ever gets a chance to mutate them. Tracked as L10.
#[cfg(feature = "corpus")]
const SKIP_LIST: &[&str] = &[];

#[cfg(feature = "corpus")]
fn collect_trials() -> Vec<Trial> {
    let mut trials = Vec::new();
    for (idx, rom_result) in corpus_roms().enumerate() {
        match rom_result {
            Ok(rom) => {
                let name = format!("corpus_replace::{}", rom.name());
                if SKIP_LIST.iter().any(|s| *s == rom.name()) {
                    trials.push(
                        Trial::test(name, move || {
                            Err(Failed::from(
                                "known-broken corpus ROM (FET/directory parser bug, tracked in L10)",
                            ))
                        })
                        .with_ignored_flag(true),
                    );
                    continue;
                }
                trials.push(Trial::test(name, move || run_one(rom)));
            }
            Err(err) => {
                let msg = err.to_string();
                let name = format!("corpus_io_error::entry_{idx}");
                trials.push(Trial::test(name, move || {
                    Err(Failed::from(format!("corpus IO error: {msg}")))
                }));
            }
        }
    }
    trials
}

#[cfg(not(feature = "corpus"))]
fn collect_trials() -> Vec<Trial> {
    Vec::new()
}

#[cfg(feature = "corpus")]
fn run_one(rom: CorpusRom) -> Result<(), Failed> {
    let name = rom.name().to_owned();
    let bytes = rom.into_bytes();
    let blob = SourceBytes::from_blob(bytes.clone());

    let (fet, dirs, rom_size, rom_origin) = match find_fet(&blob) {
        Some(found) => found,
        None => {
            return Err(Failed::from(format!(
                "[{name}] no FET candidate yielded a parseable directory \
                 ({} candidates scanned, file size {} bytes)",
                scan_fet_candidates(&blob).len(),
                bytes.len(),
            )));
        }
    };

    // Pick the first replacement target: a (directory, entry_index) pair whose
    // body is mutable (non-empty, not aliasing the record). We hand the
    // directory to the family-specific helper so the production code path —
    // re-parse the entry, validate, patch — runs end to end.
    let (target, body_off, body_len) =
        match first_replaceable(&blob, &fet, &dirs, rom_size, rom_origin) {
            Some(t) => t,
            // Empty / soft-fuse-only ROMs are legitimate; the headline locality
            // assertion has nothing to chew on but the substrate roundtrip is
            // already covered by `corpus_roundtrip`.
            None => return Ok(()),
        };

    let blob_start = blob.offset().get() as usize;
    let local_off = body_off
        .checked_sub(blob_start)
        .ok_or_else(|| Failed::from(format!("[{name}] entry body offset before blob start")))?;
    let local_end = local_off
        .checked_add(body_len)
        .ok_or_else(|| Failed::from(format!("[{name}] entry body length overflows usize")))?;

    let sentinel = vec![0xCDu8; body_len];

    let mut editor = BlobEditor::from_blob(blob);
    match target {
        Target::Psp { dir, index } => {
            replace_psp_entry_body(&mut editor, &dir, index, rom_size, rom_origin, &sentinel)
                .map_err(|e| {
                    Failed::from(format!(
                        "[{name}] replace_psp_entry_body(idx={index}, len={body_len}) failed: {e}"
                    ))
                })?;
        }
        Target::Bios { dir, index } => {
            replace_bios_entry_body(&mut editor, &dir, index, rom_size, rom_origin, &sentinel)
                .map_err(|e| {
                    Failed::from(format!(
                        "[{name}] replace_bios_entry_body(idx={index}, len={body_len}) failed: {e}"
                    ))
                })?;
        }
    }
    let mutated = editor.serialize();

    if mutated.len() != bytes.len() {
        return Err(Failed::from(format!(
            "[{name}] mutated serialise length drifted: {} -> {}",
            bytes.len(),
            mutated.len(),
        )));
    }
    if mutated[..local_off] != bytes[..local_off] {
        return Err(Failed::from(format!(
            "[{name}] bytes BEFORE patched body changed (body range [{body_off:#x}, \
             {:#x})): {} bytes differ",
            body_off + body_len,
            count_diff(&mutated[..local_off], &bytes[..local_off]),
        )));
    }
    if mutated[local_end..] != bytes[local_end..] {
        return Err(Failed::from(format!(
            "[{name}] bytes AFTER patched body changed (body range [{body_off:#x}, \
             {:#x})): {} bytes differ",
            body_off + body_len,
            count_diff(&mutated[local_end..], &bytes[local_end..]),
        )));
    }
    if mutated[local_off..local_end] != sentinel[..] {
        return Err(Failed::from(format!(
            "[{name}] patched body bytes did not match sentinel (range [{body_off:#x}, \
             {:#x}))",
            body_off + body_len,
        )));
    }

    Ok(())
}

#[cfg(feature = "corpus")]
enum Target {
    Psp {
        dir: psptool_core::PspDirectory,
        index: usize,
    },
    Bios {
        dir: psptool_core::BiosDirectory,
        index: usize,
    },
}

#[cfg(feature = "corpus")]
fn first_replaceable(
    blob: &SourceBytes,
    _fet: &Fet,
    dirs: &[DirectoryRef],
    rom_size: RomSize,
    rom_origin: FlashOffset,
) -> Option<(Target, usize, usize)> {
    for dir_ref in dirs {
        match &dir_ref.directory {
            Directory::Psp(psp) => {
                for idx in 0..psp.entries.len() {
                    if let Ok(entry) = Entry::parse_psp(blob, psp, idx, rom_size, rom_origin)
                        && is_replaceable(&entry)
                    {
                        return Some((
                            Target::Psp {
                                dir: psp.clone(),
                                index: idx,
                            },
                            entry.body.offset().get() as usize,
                            entry.body.len(),
                        ));
                    }
                }
            }
            Directory::Bios(bios) => {
                for idx in 0..bios.entries.len() {
                    if let Ok(entry) = Entry::parse_bios(blob, bios, idx, rom_size, rom_origin)
                        && is_replaceable(&entry)
                    {
                        return Some((
                            Target::Bios {
                                dir: bios.clone(),
                                index: idx,
                            },
                            entry.body.offset().get() as usize,
                            entry.body.len(),
                        ));
                    }
                }
            }
            Directory::Combo(_) => {
                // Combo entries point at child directories, not data bodies.
            }
        }
    }
    None
}

#[cfg(feature = "corpus")]
fn is_replaceable(entry: &Entry) -> bool {
    if entry.body.is_empty() {
        return false;
    }
    !matches!(entry.class, EntryClass::SoftFuseChain)
}

#[cfg(feature = "corpus")]
fn find_fet(blob: &SourceBytes) -> Option<(Fet, Vec<DirectoryRef>, RomSize, FlashOffset)> {
    // §1.1 discovery — same shape as the `corpus_roundtrip` companion test:
    // each FET candidate's (rom_origin, rom_size) is derived via
    // `detect_rom_layout` so capsule-wrapped images resolve correctly.
    for cand in scan_fet_candidates(blob) {
        let Some(layout) = detect_rom_layout(blob, cand) else {
            continue;
        };
        let dirs = walk_directories(blob, &layout.fet, layout.rom_size, layout.rom_origin);
        if !dirs.is_empty() {
            return Some((layout.fet, dirs, layout.rom_size, layout.rom_origin));
        }
    }
    None
}

#[cfg(feature = "corpus")]
fn count_diff(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).filter(|(x, y)| x != y).count()
}
