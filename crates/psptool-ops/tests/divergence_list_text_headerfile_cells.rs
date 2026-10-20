//! ACToR critic divergence pins: `ls` / `ls -v` TEXT cells of HeaderFile-class
//! rows that upstream's `PSPTool.ls_files` renders differently.
//!
//! ## #120 — File Info carries two tokens upstream's text listing never emits
//!
//! Upstream `ls_files` (`/tmp/psptool-ref/psptool/psptool.py:113-140`) builds
//! the text `File Info` from OUTCOME tags only:
//!
//! ```python
//! if file.compressed:  info.append('compressed')
//! if file.is_signed:
//!     try:
//!         if file.signed_entity.is_verified(): info.append(f'verified({...})')
//!         else:                                info.append(f'veri-failed({...})')
//!     except errors.NoCertifyingKey:
//!         info.append(f'key_missing({file.signed_entity.certifying_id.as_string()[:4]})')
//! ...
//! if file.encrypted: info.append('encrypted')
//! if issubclass(type(file), HeaderFile):
//!     if file.has_sha256_checksum:
//!         if file.verify_sha256(): info.append(f'sha256_ok')
//!         else:                    info.append(f'sha256_inconsistent')
//! ```
//!
//! There is no bare `signed` token and no bare `sha256` / `sha384` token (the
//! JSON `ls_files_dict`, `psptool.py:232-244`, has `signed(..)` and no sha tag
//! at all). psptool-rs `info_list` (`psptool-ops/src/list.rs:571-619`) pushes
//! `"signed"` before the signature tag (`:589`) and `"sha256"` / `"sha384"`
//! before the checksum tag (`:596`, `:602`). Corpus: every signed HeaderFile row
//! of every image — e.g. `AORUS_X570_X57AOXT2.FCd` PSP_FW_TRUSTED_OS @0x801200
//! upstream `verified(24C6), sha256_ok`, ours `signed, verified(24C6), sha256,
//! sha256_ok`. With both tokens removed every HeaderFile row's File Info agrees
//! with upstream on the 54-image corpus.
//!
//! ## #121 — `ls -v` size columns of a KeyStoreFile
//!
//! Upstream fills `size_signed / size_full / size_packed / load_addr` only for
//! `type(file) is HeaderFile` (`psptool.py:183-191`, else `4 * ['']`): a
//! `KeyStoreFile` (0x50 / 0x51, `file.py:244`, `key_store_file.py:23`) row has
//! four empty cells. psptool-rs's `build_entry_row` (`list.rs:350-359`) fills
//! them for every `EntryClass::header()` — including `KeyStore`.
//!
//! Expected values are derived from the quoted upstream rules over named
//! fixture constants, or read from the live reference's own `ls -v` table for
//! the corpus pins (R-CHAR-3).

use std::collections::BTreeMap;

use psptool_core::fet::{FET_MAGIC_SIZE, FET_SLOT_SIZE, FET_TERMINATOR_SIZE};
use psptool_core::magic::FET_MAGIC;
use psptool_core::{
    Fet, FlashOffset, RomSize, SourceBytes, detect_rom_layout, scan_fet_candidates,
    walk_directories,
};
use psptool_ops::{RomListing, list_verbose};
use sha2::{Digest, Sha256};

const ROM_BYTES: usize = 0x100_0000;
const FET_OFF: usize = 0x2_0000;
const DIR_OFF: usize = 0xA_0000;
const BODY_OFF: usize = 0x10_0000;
const MODE_FLASH_OFFSET: u32 = 0x2000_0000; // v2, mode 1 (directory.py:186-193)

const ENTRY_SIZE: u32 = 0x8000;
const HEADER_LEN: usize = 0x100; // header_file.py:29
const SIG_LEN_RSA2048: usize = 0x100; // header_file.py:84-85
const SHA256_OFF: usize = 0xd0; // header_file.py:46
const PSP_FW_BOOT_LOADER: u8 = 0x01;
const BL_PUBLIC_KEY: u8 = 0x50; // KEY_STORE_TYPES, file.py:244

/// FET → `$PSP` → one `entry_type` entry (`ENTRY_SIZE` @ `BODY_OFF`) whose body
/// is a signed (`signature_type` 0) `$PS1` header with `rom_size = ENTRY_SIZE`;
/// with `sha256` the big-endian bitfield's bit 0 is set (`header_file.py:55,66`)
/// and +0xd0 holds `sha256(body[0x100 : rom_size - 0x100])` — the decoded body
/// of an unencrypted, uncompressed file (`header_file.py:109-113`).
fn image(entry_type: u8, sha256: bool) -> Vec<u8> {
    let mut buf = vec![0u8; ROM_BYTES];
    buf[FET_OFF..FET_OFF + FET_MAGIC_SIZE].copy_from_slice(FET_MAGIC.as_bytes());
    buf[FET_OFF + FET_MAGIC_SIZE..FET_OFF + FET_MAGIC_SIZE + FET_SLOT_SIZE]
        .copy_from_slice(&(DIR_OFF as u32).to_le_bytes());
    let term = FET_OFF + FET_MAGIC_SIZE + FET_SLOT_SIZE;
    buf[term..term + FET_TERMINATOR_SIZE].copy_from_slice(&[0xFF; FET_TERMINATOR_SIZE]);

    buf[DIR_OFF..DIR_OFF + 4].copy_from_slice(b"$PSP");
    buf[DIR_OFF + 8..DIR_OFF + 12].copy_from_slice(&1u32.to_le_bytes());
    buf[DIR_OFF + 12..DIR_OFF + 16].copy_from_slice(&MODE_FLASH_OFFSET.to_le_bytes());
    let e = DIR_OFF + 0x10;
    buf[e] = entry_type;
    buf[e + 4..e + 8].copy_from_slice(&ENTRY_SIZE.to_le_bytes());
    buf[e + 8..e + 12].copy_from_slice(&(BODY_OFF as u32).to_le_bytes());

    let h = BODY_OFF;
    buf[h + 0x10..h + 0x14].copy_from_slice(b"$PS1");
    buf[h + 0x14..h + 0x18].copy_from_slice(&0x10u32.to_le_bytes()); // size_signed
    buf[h + 0x30..h + 0x34].copy_from_slice(&1u32.to_le_bytes()); // signed
    buf[h + 0x6c..h + 0x70].copy_from_slice(&ENTRY_SIZE.to_le_bytes()); // rom_size
    for (i, b) in buf[h + HEADER_LEN..h + ENTRY_SIZE as usize]
        .iter_mut()
        .enumerate()
    {
        *b = (i as u8).wrapping_mul(13).wrapping_add(1);
    }
    if sha256 {
        buf[h + 0x5b] = 0b01; // bitfield (BE u32 @0x58) bit 0
        let digest =
            Sha256::digest(&buf[h + HEADER_LEN..h + ENTRY_SIZE as usize - SIG_LEN_RSA2048]);
        buf[h + SHA256_OFF..h + SHA256_OFF + 0x20].copy_from_slice(&digest);
    }
    buf
}

fn render_verbose(buf: Vec<u8>) -> String {
    let blob = SourceBytes::from_blob(buf);
    let fet = Fet::parse_at(&blob, FlashOffset(FET_OFF as u64)).expect("parse FET");
    let dirs = walk_directories(&blob, &fet, RomSize::MIB_16, FlashOffset::ZERO);
    list_verbose(&RomListing {
        index: 0,
        blob: &blob,
        rom_size: RomSize::MIB_16,
        rom_origin: FlashOffset::ZERO,
        fet: &fet,
        directories: &dirs,
        sparse: true,
    })
}

type RowKey = (u64, String, String); // (dir address, entry Address cell, type suffix)
type Row = BTreeMap<String, String>;

/// Entry rows of a PrettyTable-style `ls -v` rendering (ours or upstream's),
/// keyed by the enclosing directory's address, the row's `Address` cell and
/// the `0x..` suffix of its `Type` cell. First row per key wins.
fn entry_rows(text: &str) -> BTreeMap<RowKey, Row> {
    let split = |l: &str| -> Vec<String> { l.split('|').map(|c| c.trim().to_string()).collect() };
    let lines: Vec<&str> = text.lines().collect();
    let mut out = BTreeMap::new();
    let mut dir: Option<u64> = None;
    let mut header: Option<Vec<String>> = None;
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i];
        if l.starts_with('|') && l.contains("Directory") && l.contains("Generation") {
            dir = lines.get(i + 2).and_then(|row| {
                split(row)
                    .get(3)
                    .and_then(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).ok())
            });
            header = None;
            i += 3;
            continue;
        }
        if l.starts_with('|') && l.contains("Entry") && l.contains("Address") {
            header = Some(split(l));
        } else if let (Some(h), Some(d)) = (&header, dir)
            && l.starts_with('|')
        {
            let cells = split(l);
            if cells.len() == h.len() {
                let row: Row = h.iter().cloned().zip(cells).collect();
                if row.get("Entry").is_some_and(|e| e.parse::<u64>().is_ok()) {
                    let ty = row["Type"].rsplit('~').next().unwrap_or("").to_string();
                    out.entry((d, row["Address"].clone(), ty)).or_insert(row);
                }
            }
        }
        i += 1;
    }
    out
}

fn single_row(text: &str, type_suffix: &str) -> Row {
    entry_rows(text)
        .into_iter()
        .find(|((_, _, t), _)| t == type_suffix)
        .map(|(_, r)| r)
        .unwrap_or_else(|| panic!("no {type_suffix} row:\n{text}"))
}

/// #120: a signed HeaderFile whose certifying key (fingerprint all zero) is not
/// in the image and whose sha256 checksum matches renders upstream File Info
/// `key_missing(0000), sha256_ok` (`psptool.py:116-123`, `:131-135`;
/// `KeyId.as_string()` is upper-case hex, `crypto.py:373-374`). Ours adds
/// `signed` and `sha256`.
///
/// Tracking: #120
#[test]
#[ignore = "divergence: ls File Info adds 'signed' and 'sha256'/'sha384' tokens upstream ls_files never emits (psptool.py:113-140); tracking #120"]
fn divergence_file_info_has_only_upstream_outcome_tokens() {
    let row = single_row(&render_verbose(image(PSP_FW_BOOT_LOADER, true)), "0x1");
    assert_eq!(
        row.get("File Info").map(String::as_str),
        Some("key_missing(0000), sha256_ok"),
        "divergence #120: File Info must be the psptool.py:113-140 token list; row = {row:?}"
    );
}

/// CONTROL (passes today): the outcome tags themselves are right — removing
/// the two extra tokens yields upstream's string. Isolates #120 to the extra
/// tokens.
#[test]
fn control_file_info_outcome_tags_present() {
    let row = single_row(&render_verbose(image(PSP_FW_BOOT_LOADER, true)), "0x1");
    let info = row["File Info"]
        .split(", ")
        .filter(|t| !matches!(*t, "signed" | "sha256" | "sha384"))
        .collect::<Vec<_>>()
        .join(", ");
    assert_eq!(info, "key_missing(0000), sha256_ok");
}

/// #121: a KeyStoreFile row (0x50 BL_PUBLIC_KEY) has empty
/// `size_signed / size_full / size_packed / load_addr` cells
/// (`psptool.py:183-191`: `type(file) is HeaderFile` excludes the subclass).
///
/// Tracking: #121
#[test]
#[ignore = "divergence: ls -v fills size_signed/size_full/size_packed/load_addr for a KeyStoreFile; upstream only for type(file) is HeaderFile (psptool.py:183-191); tracking #121"]
fn divergence_keystore_row_has_empty_size_columns() {
    let row = single_row(&render_verbose(image(BL_PUBLIC_KEY, false)), "0x50");
    for col in ["size_signed", "size_full", "size_packed", "load_addr"] {
        assert_eq!(
            row.get(col).map(String::as_str),
            Some(""),
            "divergence #121: KeyStoreFile `{col}` must be '' per psptool.py:183-191; row = {row:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Corpus-gated differential against the live reference's `ls -v` table
// ---------------------------------------------------------------------------

/// `(key, upstream row, our rows)` for every upstream row with a same-keyed row
/// of ours, all corpus images; `None` when corpus or reference is unset.
fn corpus_row_pairs() -> Option<Vec<(String, RowKey, Row, Row)>> {
    let reference = std::env::var_os("PSPTOOL_REFERENCE").filter(|v| !v.is_empty())?;
    let roms = psptool_fixtures::corpus_rom_paths();
    if roms.is_empty() {
        return None;
    }
    let mut pairs = Vec::new();
    for rom in roms {
        let out = std::process::Command::new(&reference)
            .args(["-I", "-m", "psptool"])
            .arg(&rom)
            .args(["-E", "-v"])
            .output()
            .expect("spawn reference psptool");
        assert!(
            out.status.success(),
            "reference failed on {}",
            rom.display()
        );
        let theirs = entry_rows(&String::from_utf8_lossy(&out.stdout));

        let blob = SourceBytes::from_blob(std::fs::read(&rom).expect("read ROM"));
        let mut ours: BTreeMap<RowKey, Row> = BTreeMap::new();
        let layouts: Vec<_> = scan_fet_candidates(&blob)
            .into_iter()
            .filter_map(|p| detect_rom_layout(&blob, p))
            .collect();
        for (index, layout) in layouts.iter().enumerate() {
            let dirs = walk_directories(&blob, &layout.fet, layout.rom_size, layout.rom_origin);
            let text = list_verbose(&RomListing {
                index,
                blob: &blob,
                rom_size: layout.rom_size,
                rom_origin: layout.rom_origin,
                fet: &layout.fet,
                directories: &dirs,
                sparse: true,
            });
            for (k, r) in entry_rows(&text) {
                ours.entry(k).or_insert(r);
            }
        }
        let name = rom.file_name().unwrap().to_string_lossy().into_owned();
        for (k, ur) in theirs {
            if let Some(or) = ours.get(&k) {
                pairs.push((name.clone(), k, ur, or.clone()));
            }
        }
    }
    Some(pairs)
}

/// #120 corpus pin: the File Info of every upstream HeaderFile row (non-empty
/// `size_signed`, `psptool.py:183`) equals ours. 4000+ rows differ today, all
/// by the extra `signed` / `sha256` / `sha384` tokens.
///
/// Tracking: #120
#[test]
#[ignore = "divergence: ls File Info adds 'signed' and 'sha256'/'sha384' tokens upstream ls_files never emits (psptool.py:113-140); tracking #120"]
fn divergence_corpus_headerfile_file_info_matches_reference() {
    let Some(pairs) = corpus_row_pairs() else {
        eprintln!("skipped: PSPTOOL_TEST_CORPUS / PSPTOOL_REFERENCE unset");
        return;
    };
    let bad: Vec<String> = pairs
        .iter()
        .filter(|(_, _, ur, _)| ur.get("size_signed").is_some_and(|s| !s.is_empty()))
        .filter(|(_, _, ur, or)| ur.get("File Info") != or.get("File Info"))
        .map(|(n, k, ur, or)| {
            format!(
                "{n} dir {:#x} {} {}: reference {:?}, ours {:?}",
                k.0,
                k.1,
                k.2,
                ur.get("File Info"),
                or.get("File Info")
            )
        })
        .collect();
    assert!(
        bad.is_empty(),
        "divergence #120: {} HeaderFile rows' File Info differs (psptool.py:113-140):\n{}",
        bad.len(),
        bad.join("\n")
    );
}

/// #121 corpus pin: every upstream KeyStoreFile row (0x50 / 0x51) has the four
/// size cells empty, and so must ours.
///
/// Tracking: #121
#[test]
#[ignore = "divergence: ls -v fills size_signed/size_full/size_packed/load_addr for a KeyStoreFile; upstream only for type(file) is HeaderFile (psptool.py:183-191); tracking #121"]
fn divergence_corpus_keystore_size_columns_match_reference() {
    let Some(pairs) = corpus_row_pairs() else {
        eprintln!("skipped: PSPTOOL_TEST_CORPUS / PSPTOOL_REFERENCE unset");
        return;
    };
    let cols = ["size_signed", "size_full", "size_packed", "load_addr"];
    let bad: Vec<String> = pairs
        .iter()
        .filter(|(_, k, _, _)| k.2 == "0x50" || k.2 == "0x51")
        .filter(|(_, _, ur, or)| cols.iter().any(|c| ur.get(*c) != or.get(*c)))
        .map(|(n, k, ur, or)| {
            let pick = |r: &Row| cols.map(|c| r.get(c).cloned().unwrap_or_default());
            format!(
                "{n} dir {:#x} {} {}: reference {:?}, ours {:?}",
                k.0,
                k.1,
                k.2,
                pick(ur),
                pick(or)
            )
        })
        .collect();
    assert!(
        bad.is_empty(),
        "divergence #121: {} KeyStoreFile rows differ (psptool.py:183-191):\n{}",
        bad.len(),
        bad.join("\n")
    );
}
