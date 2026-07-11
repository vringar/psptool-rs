//! Differential integration test vs the reference Python PSPTool (issue #18).
//!
//! For every ROM under `<corpus>/test_files/`, this test runs **both** our
//! `psptool` binary and the upstream Python `psptool` and asserts the two
//! agree on the firmware's *structure*:
//!
//!   * the set of directories, keyed by flash address, and
//!   * within each directory, every entry's `index`, `address`, `size` and
//!     `sectionType`.
//!
//! Those are exactly the facts a parser can get *wrong* — a missing
//! directory, a mis-sized entry, a misclassified type. Agreement here is the
//! differential guarantee issue #18 asks for.
//!
//! ## Equivalent divergences — compared loosely or not at all
//!
//! The issue calls for sorting divergences into "equivalent" and "bug". The
//! following are *equivalent* — both tools are internally consistent, they
//! just model the same bytes differently — so the comparison accommodates
//! them rather than failing:
//!
//! * **JSON shape.** Ours omits the directory `magic` / `secondaryAddresses`
//!   keys and the per-entry `magic` / `version` / `info` / `md5` / `sizes`
//!   keys upstream emits, and formats shared values differently (full vs
//!   4-char-truncated magic, dotted vs zero-padded versions). Only the
//!   structural keys both tools agree on are read.
//!
//! * **Combo directories.** A combo directory is a routing node — it points
//!   at child directories via `secondaryAddresses`, it holds no firmware
//!   files. Upstream flattens combos away and lists only leaf directories;
//!   our tool additionally surfaces the combo node. Combos are dropped from
//!   the projection (see [`COMBO_MAGICS`]) so leaf directories line up.
//!
//! * **`size` of HeaderFile entries.** Ours is the directory table's
//!   allocation size; upstream's is the file `buffer_size`, which for a
//!   *HeaderFile* (signed/compressed firmware) is the size encoded in the
//!   file's own header — a different quantity that can legitimately disagree.
//!   `size` is compared strictly only for non-HeaderFile entries.
//!
//! * **Entries sharing a flash offset.** Upstream caches `File` objects by
//!   flash offset and reuses the first parse everywhere that offset is
//!   referenced — masking the real type and size of any *later* directory
//!   record at the same offset. Our tool reads each directory record
//!   faithfully (the records genuinely differ — verified against on-disk
//!   bytes; see crosslink issue #40). Two accommodations follow: (a) when
//!   upstream repeats an entry at consecutive positions within a directory
//!   (`address[N] == address[N-1]`), position N is a dedup echo carrying no
//!   independent information and is not compared; (b) a `size` mismatch is
//!   tolerated when our own per-record value matches upstream's for that
//!   offset in *some* directory — the signature of a cross-directory dedup
//!   echo rather than a parser disagreement.
//!
//! * **`address` of empty entries.** A zero-size entry (e.g. an APOB
//!   destination record) has no bytes on flash; upstream normalises its
//!   `address` to 0 while we report the raw directory field. `address` is not
//!   compared when both tools report `size == 0`.
//!
//! Raw per-entry `extract` is not differentially tested: `get_bytes()` is
//! `buffer[address .. address+size]` in both tools, so it is fully determined
//! by the `address`/`size` already compared here — and the `-X -d` directory
//! index space differs between the tools (ours numbers combo directories,
//! upstream's does not), so a naive `-d N` extract comparison is ill-defined.
//! The `-X` argv path itself is covered by `synthetic.rs`.
//!
//! ## Gating
//!
//! * Cargo feature `corpus` opts the test binary into corpus iteration. With
//!   the feature off the trial collector returns an empty list and the binary
//!   exits clean.
//! * `PSPTOOL_TEST_CORPUS` must point at a populated `test_files/` directory.
//! * `PSPTOOL_REFERENCE` must point at a `python3` that can `import psptool`
//!   (the dev shell exports it — see `default.nix`). When it is unset the
//!   test skips cleanly: the reference tool is optional, exactly like the
//!   corpus submodule. When it *and* the corpus are both present but no
//!   trials materialise, the test fails loudly rather than silently passing.
//! * `SKIP_LIST` carries ROMs whose differential is a known *bug* (as opposed
//!   to the equivalent divergences above). Each is registered as an
//!   ignored-but-failing trial so `cargo test -- --include-ignored` surfaces
//!   it instead of silently passing.

use libtest_mimic::{Arguments, Trial};

#[cfg(feature = "corpus")]
use libtest_mimic::Failed;
#[cfg(feature = "corpus")]
use std::collections::{BTreeMap, HashMap, HashSet};
#[cfg(feature = "corpus")]
use std::path::Path;
#[cfg(feature = "corpus")]
use std::process::Command;

/// Environment variable naming a `python3` interpreter that can run the
/// reference tool as `python3 -m psptool`. Set by the nix dev shell.
#[cfg(feature = "corpus")]
const REFERENCE_ENV: &str = "PSPTOOL_REFERENCE";

/// Upper bound on `-r` (ROM index) probing. Real corpus blobs top out at 2
/// ROMs; the cap only guards against a hypothetical runaway loop.
#[cfg(feature = "corpus")]
const MAX_ROM_PROBE: usize = 8;

/// Magics of *combo* directories — routing nodes that point at child
/// directories via `secondaryAddresses` rather than holding firmware files.
/// The reference tool flattens combos away and lists only leaf directories;
/// our tool additionally surfaces the combo node itself. Excluding combos
/// from the projection is a documented "equivalent" divergence (see the
/// module doc): it lets the differential compare the leaf directories both
/// tools agree to list. A combo magic outside this set still surfaces — it
/// would land in the "only we report" bucket and fail the trial.
#[cfg(feature = "corpus")]
const COMBO_MAGICS: &[&str] = &["2PSP", "2BHD"];

/// ROMs whose differential is a known *bug* — paired with the reason and its
/// tracking issue. Each is registered as an ignored trial that *fails* when
/// un-ignored, so `--include-ignored` reports it as known-broken rather than
/// silently passing.
#[cfg(feature = "corpus")]
const SKIP_LIST: &[(&str, &str)] = &[
    // After the #40 compressed-entry fix (zlib-header sizing) this ROM no
    // longer errors on the overrun; it now surfaces a distinct, previously
    // masked divergence at directory @0x670000 entry 26 — our type-0x5c name
    // "SPI_ROM_CONFIG" vs upstream "WMOS" (HeaderFile). Tracked separately.
    (
        "AORUS_X570_X57AOXT2.FCd",
        "entry-26 type-0x5c classification divergence: ours SPI_ROM_CONFIG, \
         reference WMOS/HeaderFile (crosslink issue #60)",
    ),
    // Multi-ROM blobs: the ROM-1 BIOS directory diverges — our tool applies
    // the ROM-1 base to BIOS-region entry addresses where upstream does not,
    // and one record (entry 3) is read as a different type. Multi-ROM
    // address-base handling needs its own investigation.
    (
        "ASUS_PRIME-X470-PRO-ASUS-4804.CAP",
        "multi-ROM BIOS directory address-base divergence (crosslink issue #41)",
    ),
    (
        "ASUS_ROG-STRIX-X470-F-GAMING-ASUS-4804.CAP",
        "multi-ROM BIOS directory address-base divergence (crosslink issue #41)",
    ),
    (
        "H12SSW9.719",
        "multi-ROM BIOS directory address-base divergence (crosslink issue #41)",
    ),
];

fn main() {
    let args = Arguments::from_args();
    let trials = collect_trials();

    // If both the corpus and the reference tool are available but no trials
    // materialised, the test is silently lying — fail loudly. The
    // reference-unset and corpus-unset cases are legitimate skips.
    if reference_available()
        && std::env::var_os("PSPTOOL_TEST_CORPUS").is_some()
        && trials.is_empty()
    {
        eprintln!(
            "PSPTOOL_TEST_CORPUS and PSPTOOL_REFERENCE are both set but the \
             differential test collected zero trials. Either the corpus path \
             is wrong, `test_files/` is missing, or the `corpus` cargo \
             feature is disabled. Refusing to silently pass."
        );
        std::process::exit(1);
    }

    libtest_mimic::run(&args, trials).exit();
}

/// True when `PSPTOOL_REFERENCE` names a non-empty path. Compiles in both
/// feature states so `main` can reference it unconditionally.
fn reference_available() -> bool {
    std::env::var_os("PSPTOOL_REFERENCE").is_some_and(|v| !v.is_empty())
}

/// With the `corpus` feature on, build one trial per ROM. With it off — or
/// when the corpus / reference tool is absent — return an empty list so the
/// binary exits clean with no skipped-test noise.
#[cfg(feature = "corpus")]
fn collect_trials() -> Vec<Trial> {
    // The reference tool is optional. Unset → clean skip (empty trial set).
    let reference = match std::env::var_os(REFERENCE_ENV) {
        Some(v) if !v.is_empty() => std::path::PathBuf::from(v),
        _ => return Vec::new(),
    };

    let mut trials = Vec::new();
    for path in psptool_fixtures::corpus_rom_paths() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unnamed>")
            .to_owned();
        let trial_name = format!("differential::{name}");

        if let Some((_, reason)) = SKIP_LIST.iter().find(|(rom, _)| *rom == name) {
            // Err so `--include-ignored` reports known-broken ROMs as
            // failing-known-broken, not passing-when-actually-ignored.
            let reason = (*reason).to_owned();
            trials.push(
                Trial::test(trial_name, move || {
                    Err(Failed::from(format!("known-broken: {reason}")))
                })
                .with_ignored_flag(true),
            );
            continue;
        }

        let reference = reference.clone();
        trials.push(Trial::test(trial_name, move || run_one(&path, &reference)));
    }
    trials
}

#[cfg(not(feature = "corpus"))]
fn collect_trials() -> Vec<Trial> {
    Vec::new()
}

/// One parsed directory: the entry list, in on-disk table order.
#[cfg(feature = "corpus")]
struct DirModel {
    entries: Vec<EntryModel>,
}

/// The structural projection of one entry. `index`, `address` and
/// `section_type` are compared strictly (with documented exceptions); `size`
/// is compared by [`compare_structure`], which has the cross-directory
/// context the dedup-echo tolerance needs.
#[cfg(feature = "corpus")]
#[derive(Debug)]
struct EntryModel {
    index: u64,
    address: u64,
    size: u64,
    section_type: String,
    /// True when the reference classified the entry as a HeaderFile — it
    /// emitted a `sizes` object. For such entries the two tools source the
    /// `size` field from different structures, so it is not compared. Always
    /// `false` on our side (our `-E -j` emits no `sizes` object).
    is_header_file: bool,
}

/// Compare the identity fields of two entry projections — `index`, `address`,
/// `section_type`. Returns `Some(reason)` for the first divergence, `None` on
/// agreement. `size` is handled separately by [`compare_structure`].
#[cfg(feature = "corpus")]
fn entry_diff(ours: &EntryModel, theirs: &EntryModel) -> Option<String> {
    if ours.index != theirs.index {
        return Some(format!(
            "index: ours {}, reference {}",
            ours.index, theirs.index
        ));
    }
    // `address` of a zero-size entry is not a real flash location — nothing
    // lives there. Upstream normalises it to 0; we report the raw directory
    // field. Skip the comparison when both tools agree the entry is empty.
    let both_empty = ours.size == 0 && theirs.size == 0;
    if !both_empty && ours.address != theirs.address {
        return Some(format!(
            "address: ours {:#x}, reference {:#x}",
            ours.address, theirs.address
        ));
    }
    if ours.section_type != theirs.section_type {
        return Some(format!(
            "sectionType: ours {:?}, reference {:?}",
            ours.section_type, theirs.section_type
        ));
    }
    None
}

#[cfg(feature = "corpus")]
fn run_one(rom: &Path, reference: &Path) -> Result<(), Failed> {
    let ours = collect_ours(rom)?;
    let theirs = collect_reference(rom, reference)?;
    compare_structure(&ours, &theirs)
}

/// Run our `psptool -E -j` once per ROM index (`-r 0`, `-r 1`, …) until the
/// index runs past the last ROM, merging every directory into one
/// address-keyed map. Upstream's `-E -j` dumps every ROM's directories in one
/// pass; iterating `-r` is how we cover the same ground.
#[cfg(feature = "corpus")]
fn collect_ours(rom: &Path) -> Result<BTreeMap<u64, DirModel>, Failed> {
    let mut dirs = BTreeMap::new();
    for rom_index in 0..MAX_ROM_PROBE {
        let out = Command::new(env!("CARGO_BIN_EXE_psptool"))
            .arg(rom)
            .args(["-E", "-j", "-r"])
            .arg(rom_index.to_string())
            .output()
            .map_err(|e| Failed::from(format!("spawning our psptool: {e}")))?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // A `-r` past the last ROM is the expected loop terminator.
            if rom_index > 0 && stderr.contains("out of range") {
                break;
            }
            return Err(Failed::from(format!(
                "our psptool failed on `-r {rom_index}`: {}",
                stderr.trim()
            )));
        }
        parse_json_dirs(&out.stdout, &mut dirs)
            .map_err(|e| Failed::from(format!("parsing our `-r {rom_index}` JSON: {e}")))?;
    }
    Ok(dirs)
}

/// Run the reference `python3 -m psptool -E -j` once — upstream lists every
/// ROM's directories in a single invocation.
#[cfg(feature = "corpus")]
fn collect_reference(rom: &Path, reference: &Path) -> Result<BTreeMap<u64, DirModel>, Failed> {
    let out = Command::new(reference)
        .args(["-m", "psptool"])
        .arg(rom)
        .args(["-E", "-j"])
        .output()
        .map_err(|e| Failed::from(format!("spawning reference psptool: {e}")))?;

    if !out.status.success() {
        return Err(Failed::from(format!(
            "reference psptool failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let mut dirs = BTreeMap::new();
    parse_json_dirs(&out.stdout, &mut dirs)
        .map_err(|e| Failed::from(format!("parsing reference JSON: {e}")))?;
    Ok(dirs)
}

/// Parse a `-E -j` JSON document — an array of directory objects — into the
/// address-keyed map. Both tools emit this shape; only the structural keys
/// (`address`, `entries[].index/address/size/sectionType`) are read.
#[cfg(feature = "corpus")]
fn parse_json_dirs(stdout: &[u8], out: &mut BTreeMap<u64, DirModel>) -> Result<(), String> {
    let text = std::str::from_utf8(stdout)
        .map_err(|e| format!("output is not UTF-8: {e}"))?
        .trim();
    let value: serde_json::Value = serde_json::from_str(text).map_err(|e| {
        format!(
            "invalid JSON ({e}); first 200 bytes: {:?}",
            &text[..text.len().min(200)]
        )
    })?;
    let arr = value.as_array().ok_or("top-level JSON is not an array")?;

    for dir in arr {
        let address = json_u64(dir, "address")?;

        // Drop combo directories — see `COMBO_MAGICS`. Both tools emit the
        // `magic` key; default to "" so a missing key simply isn't a combo.
        let magic = dir.get("magic").and_then(|v| v.as_str()).unwrap_or("");
        if COMBO_MAGICS.contains(&magic) {
            continue;
        }

        let entries_val = dir
            .get("entries")
            .and_then(|v| v.as_array())
            .ok_or("directory object missing `entries` array")?;
        let mut entries = Vec::with_capacity(entries_val.len());
        for entry in entries_val {
            // Our `-E -j` emits `{"error": ..., "index": N}` for an entry it
            // could not parse. Surface it as a clear failure rather than the
            // opaque "missing `address`" the structural read would hit.
            if let Some(err) = entry.get("error").and_then(|v| v.as_str()) {
                let idx = entry.get("index").and_then(|v| v.as_u64());
                return Err(format!(
                    "our psptool flagged a parse error on entry {}: {err}",
                    idx.map_or_else(|| "?".to_owned(), |i| i.to_string()),
                ));
            }
            entries.push(EntryModel {
                index: json_u64(entry, "index")?,
                address: json_u64(entry, "address")?,
                size: json_u64(entry, "size")?,
                section_type: entry
                    .get("sectionType")
                    .and_then(|v| v.as_str())
                    .ok_or("entry missing string `sectionType`")?
                    .to_owned(),
                // The reference emits `sizes` exactly for HeaderFile entries;
                // our side never does, so this stays false there.
                is_header_file: entry.get("sizes").is_some(),
            });
        }
        // A directory shared across ROMs lands at the same address with
        // identical bytes; overwriting is harmless.
        out.insert(address, DirModel { entries });
    }
    Ok(())
}

#[cfg(feature = "corpus")]
fn json_u64(value: &serde_json::Value, key: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| format!("missing or non-integer `{key}`"))
}

/// Assert the two address-keyed directory maps describe the same firmware:
/// identical directory address sets, and identical entry projections within
/// each directory (compared positionally — both tools iterate the directory's
/// on-disk entry table, so index *i* must mean the same entry).
#[cfg(feature = "corpus")]
fn compare_structure(
    ours: &BTreeMap<u64, DirModel>,
    theirs: &BTreeMap<u64, DirModel>,
) -> Result<(), Failed> {
    let our_only: Vec<u64> = ours
        .keys()
        .filter(|a| !theirs.contains_key(a))
        .copied()
        .collect();
    let ref_only: Vec<u64> = theirs
        .keys()
        .filter(|a| !ours.contains_key(a))
        .copied()
        .collect();
    if !our_only.is_empty() || !ref_only.is_empty() {
        return Err(Failed::from(format!(
            "directory sets differ: {} only we report ({}); {} only the \
             reference reports ({})",
            our_only.len(),
            fmt_addrs(&our_only),
            ref_only.len(),
            fmt_addrs(&ref_only),
        )));
    }

    // Every `size` our tool reports for a given flash offset, across all
    // directories. Upstream caches `File` objects by offset and echoes one
    // size everywhere; a `size` mismatch is the dedup echo (not a bug) when
    // our own per-record value matches upstream's somewhere — see the module
    // doc's "entries shared across directories" note.
    let mut our_sizes_by_offset: HashMap<u64, HashSet<u64>> = HashMap::new();
    for dir in ours.values() {
        for entry in &dir.entries {
            our_sizes_by_offset
                .entry(entry.address)
                .or_default()
                .insert(entry.size);
        }
    }

    for (addr, our_dir) in ours {
        let ref_dir = &theirs[addr];
        if our_dir.entries.len() != ref_dir.entries.len() {
            return Err(Failed::from(format!(
                "directory @{addr:#x}: entry count differs — ours {}, reference {}",
                our_dir.entries.len(),
                ref_dir.entries.len(),
            )));
        }
        for (n, (oe, re)) in our_dir.entries.iter().zip(&ref_dir.entries).enumerate() {
            // Upstream caches `File` objects by flash offset: two consecutive
            // directory records sharing an offset are collapsed into one
            // repeated `File`, masking the second record's real type/size.
            // Position N is then a dedup echo of N-1 — skip it (see the
            // module doc's "entries sharing a flash offset" note).
            if n > 0 && re.address == ref_dir.entries[n - 1].address {
                continue;
            }
            if let Some(reason) = entry_diff(oe, re) {
                return Err(Failed::from(format!(
                    "directory @{addr:#x}: entry {} differs — {reason}\n  \
                     ours:      {oe:?}\n  reference: {re:?}",
                    oe.index,
                )));
            }
            // `size`: skipped for HeaderFile entries (different provenance);
            // a mismatch elsewhere is tolerated only as upstream's dedup echo.
            if !re.is_header_file && oe.size != re.size {
                let dedup_echo = our_sizes_by_offset
                    .get(&re.address)
                    .is_some_and(|sizes| sizes.contains(&re.size));
                if !dedup_echo {
                    return Err(Failed::from(format!(
                        "directory @{addr:#x}: entry {} differs — size: ours {}, \
                         reference {}\n  ours:      {oe:?}\n  reference: {re:?}",
                        oe.index, oe.size, re.size,
                    )));
                }
            }
        }
    }
    Ok(())
}

#[cfg(feature = "corpus")]
fn fmt_addrs(addrs: &[u64]) -> String {
    if addrs.is_empty() {
        return "none".to_owned();
    }
    addrs
        .iter()
        .map(|a| format!("{a:#x}"))
        .collect::<Vec<_>>()
        .join(", ")
}
