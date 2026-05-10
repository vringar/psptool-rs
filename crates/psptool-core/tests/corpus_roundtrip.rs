//! Byte-exact roundtrip across the full `vendor/test-corpus` (issue #17).
//!
//! For every ROM under `<corpus>/test_files/`, this test asserts:
//!
//! 1. **Parse never panics.** Implicit — the parser surface returns
//!    `Result`s; a panic from `psptool-core` would surface as a libtest_mimic
//!    failure with the offending file's path.
//! 2. **Serialise-without-mutation is byte-identical.** `BlobEditor` with no
//!    patches must reproduce the input verbatim. This is the substrate
//!    guarantee the project rests on (see `.crosslink/rules/project.md` and
//!    `docs/firmware-layout.md` §8).
//! 3. **Mutation locality.** Pick one parsed entry, replace its body bytes
//!    with a sentinel of identical length via the diff-and-patch writer, and
//!    verify that *only* that byte range differs from the source — every byte
//!    outside the entry body must be byte-identical.
//!
//! ## Gating
//!
//! * Cargo feature `corpus` (declared in `psptool-core/Cargo.toml`) opts the
//!   test binary into corpus iteration. With the feature off, the trial
//!   collector returns an empty list and the test binary exits clean — useful
//!   for CI lanes that should never depend on the private corpus.
//! * Runtime: even with the feature on, iteration is keyed off the
//!   `PSPTOOL_TEST_CORPUS` environment variable via
//!   `psptool_fixtures::corpus_roms`. When the variable is unset (or set but
//!   the `test_files/` directory is missing/empty) the loader yields no items
//!   and the test exits clean. This matches the optional-submodule design.
//!
//! ## Out of scope
//!
//! * Differential test against the reference Python implementation (issue #18).
//! * Property-test fuzzing (issues #21–#24).
//! * Cryptographic correctness — the writer is deliberately dumb, so the test
//!   does not re-sign or re-fletcher anything.

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

fn main() {
    let args = Arguments::from_args();
    let trials = collect_trials();

    // If the user pointed the test at a corpus (PSPTOOL_TEST_CORPUS set) but no
    // trials materialised, this is the headline test silently lying — fail
    // loudly instead of exiting clean. The unset case is a legitimate skip
    // (no submodule hydrated).
    if std::env::var_os("PSPTOOL_TEST_CORPUS").is_some() && trials.is_empty() {
        eprintln!(
            "PSPTOOL_TEST_CORPUS is set but corpus_roundtrip collected zero \
             trials. Either the path is wrong, `test_files/` is missing, or \
             the `corpus` cargo feature is disabled. This is the headline \
             roundtrip test — refusing to silently pass."
        );
        std::process::exit(1);
    }

    libtest_mimic::run(&args, trials).exit();
}

/// ROMs whose FET candidate is found but the directory parse refuses it.
/// Tracked as a parser-coverage gap in the follow-up issue (see L10).
/// Each entry is registered as a libtest_mimic Trial that returns
/// `Trial::test(...).with_ignored_flag(true)`, so the failure surfaces in
/// `cargo test` reports as "ignored" — visible (not silent) but non-fatal.
#[cfg(feature = "corpus")]
const SKIP_LIST: &[&str] = &[];

/// When the `corpus` feature is on, build one trial per ROM file so the
/// libtest report identifies which file failed. When the feature is off, or
/// `PSPTOOL_TEST_CORPUS` is unset / `test_files/` is missing, an empty list
/// is returned and the test binary exits clean (no skipped-test noise).
#[cfg(feature = "corpus")]
fn collect_trials() -> Vec<Trial> {
    let mut trials = Vec::new();
    for (idx, rom_result) in corpus_roms().enumerate() {
        match rom_result {
            Ok(rom) => {
                let name = format!("corpus_roundtrip::{}", rom.name());
                if SKIP_LIST.iter().any(|s| *s == rom.name()) {
                    // Closure returns Err so `cargo test -- --include-ignored`
                    // surfaces the known-broken ROMs as failing-known-broken
                    // rather than passing-when-actually-ignored. Without this,
                    // --include-ignored would re-introduce the silent-pass bug
                    // round-1 was supposed to kill.
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
                // Surface read failures as named failing trials rather than
                // silently skipping — `corpus_roms` only errors on filesystem
                // I/O, which is worth flagging loudly.
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

    // (2) Serialise-without-mutation must round-trip byte-exact. Run this
    // first so it's the failure reported even when no FET parses — the
    // substrate guarantee is independent of any structural parse.
    {
        let editor = BlobEditor::from_blob(blob.clone());
        let out = editor.serialize();
        if out != bytes {
            return Err(Failed::from(format!(
                "[{name}] unmutated serialise drifted: out_len={} vs in_len={}, {} bytes differ",
                out.len(),
                bytes.len(),
                count_diff(&out, &bytes),
            )));
        }
    }

    // (1) Parse: scan FET candidates and use the first that yields a
    // parseable directory (the §1.2 discovery rule). A ROM with no parseable
    // FET candidate is unexpected enough to fail the trial — the corpus is
    // real-world AMD firmware and every image should have one.
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

    // (3) Mutation locality: pick one entry, replace its body with a sentinel
    // of identical length, serialise, and verify only that byte range moves.
    let entry = match first_mutable_entry(&blob, &fet, &dirs, rom_size, rom_origin) {
        Some(e) => e,
        // No entries to mutate is allowed (some directories may be empty);
        // (2) already verified the substrate roundtrip on this ROM.
        None => return Ok(()),
    };

    let body_off = entry.body.offset().get() as usize;
    let body_len = entry.body.len();
    let blob_start = blob.offset().get() as usize;
    let local_off = body_off
        .checked_sub(blob_start)
        .ok_or_else(|| Failed::from(format!("[{name}] entry body offset before blob start")))?;
    let local_end = local_off
        .checked_add(body_len)
        .ok_or_else(|| Failed::from(format!("[{name}] entry body length overflows usize")))?;

    // Sentinel chosen for two reasons:
    //   * 0xAB is uncommon enough in real firmware bodies that the mutation
    //     is observable post-hoc.
    //   * The check below verifies bytes inside the range *equal the
    //     sentinel*, so we don't depend on the original bytes differing from
    //     it — the locality proof is "outside unchanged, inside == sentinel".
    let sentinel = vec![0xABu8; body_len];

    let mut editor = BlobEditor::from_blob(blob);
    editor
        .entry(&entry)
        .set_body(sentinel.clone())
        .map_err(|e| {
            Failed::from(format!(
                "[{name}] set_body on entry type {:?} (body offset {body_off:#010x}, \
                 length {body_len}) failed: {e}",
                entry.entry_type(),
            ))
        })?;
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
fn find_fet(blob: &SourceBytes) -> Option<(Fet, Vec<DirectoryRef>, RomSize, FlashOffset)> {
    // §1.1 discovery: scan every byte-aligned FET candidate, derive the
    // (rom_origin, rom_size) for each via `detect_rom_layout`, then walk the
    // directory graph. The first candidate whose layout yields ≥1 parseable
    // directory wins — capsule-wrapped images (e.g. ASUS .CAP) need this so
    // FET pointers resolve relative to the ROM origin, not the file start.
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

/// Pick the first entry whose body lives in a distinct byte range from any
/// directory record (i.e. *not* a `SoftFuseChain` whose body aliases the
/// record bytes). This keeps the mutation-locality assertion easy to reason
/// about: the patched range covers ordinary entry-body bytes, not the
/// surrounding directory header.
#[cfg(feature = "corpus")]
fn first_mutable_entry(
    blob: &SourceBytes,
    _fet: &Fet,
    dirs: &[DirectoryRef],
    rom_size: RomSize,
    rom_origin: FlashOffset,
) -> Option<Entry> {
    for dir_ref in dirs {
        match &dir_ref.directory {
            Directory::Psp(psp) => {
                for idx in 0..psp.entries.len() {
                    if let Ok(entry) = Entry::parse_psp(blob, psp, idx, rom_size, rom_origin)
                        && is_mutable(&entry)
                    {
                        return Some(entry);
                    }
                }
            }
            Directory::Bios(bios) => {
                for idx in 0..bios.entries.len() {
                    if let Ok(entry) = Entry::parse_bios(blob, bios, idx, rom_size, rom_origin)
                        && is_mutable(&entry)
                    {
                        return Some(entry);
                    }
                }
            }
            Directory::Combo(_) => {
                // Combo entries point at child directories, not data bodies;
                // they're enumerated separately by `walk_directories`.
            }
        }
    }
    None
}

#[cfg(feature = "corpus")]
fn is_mutable(entry: &Entry) -> bool {
    if entry.body.is_empty() {
        return false;
    }
    // SoftFuseChain bodies alias the directory record (see
    // `entry::resolve_body`); skip so the locality assertion's "outside body
    // unchanged" wording matches a clean entry-body window, not a record.
    !matches!(entry.class, EntryClass::SoftFuseChain)
}

#[cfg(feature = "corpus")]
fn count_diff(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).filter(|(x, y)| x != y).count()
}
