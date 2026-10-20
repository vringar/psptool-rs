//! ACToR critic divergence pins: two `ls -v` / `ls -j -v` VALUES of a
//! HeaderFile-class entry (every PSP_FW_BOOT_LOADER 0x1, TRUSTED_OS 0x2,
//! SMU_OFFCHIP_FW 0x8, SEC_GASKET 0x24, DRIVER_ENTRIES 0x28, SEV_CODE 0x39 …)
//! are computed from different bytes / fields than upstream.
//!
//! ## #118 — `size_packed` / `sizes.packed` of a header with `rom_size == 0`
//!
//! Upstream `HeaderFile._parse` (`/tmp/psptool-ref/psptool/header_file.py:72-73`):
//!
//! ```python
//! if self.rom_size == 0:
//!     self.rom_size = self.buffer_size
//! ```
//!
//! and both listings print that normalised attribute: `ls -v`
//! `hex(file.rom_size)` (`psptool.py:183-189`, column `size_packed`) and
//! `ls -j` `'packed': file.rom_size` (`psptool.py:261-265`). `buffer_size` is
//! the directory-declared `entry.size` (`file.py:297-299`; grown to 0x100 at
//! `header_file.py:32-33`, irrelevant here). psptool-rs rendered the RAW header
//! field `h.rom_size` → `0x0`; fixed by #118 (`list.rs` `packed_size`).
//! Corpus: every Summit-Ridge combo part, e.g. `AORUS_X370G5.23d`
//! PSP_FW_BOOT_LOADER @0x268000 (upstream `0x8000`, ours `0x0`) and
//! SMU_OFFCHIP_FW @0x270000 (`0x14000` vs `0x0`); 0x2e on `AORUS_X570`.
//!
//! ## #119 — sparse `MD5` of a HeaderFile hashes the wrong bytes
//!
//! Upstream `HeaderFile.md5` (`header_file.py:312-315`) overrides `File.md5`
//! (`file.py:380-383`):
//!
//! ```python
//! def md5(self):
//!     m = md5()
//!     try:
//!         m.update(self.body.get_bytes())
//! ```
//!
//! `self.body` is the data region `NestedBuffer(self, len(self) - 0x100 -
//! signature_len, 0x100)` (`header_file.py:106`) — NOT the whole entry. Both
//! `ls -v` (`psptool.py:180`) and `ls -j` (`psptool.py:254`) print
//! `file.md5()[:4].upper()`. psptool-rs's sparse ("upstream-exact") MD5 cell
//! hashed the whole directory-declared entry. Corpus: every HeaderFile of
//! every image, e.g. `AORUS_X370G5.23d` @0x268000 upstream `C985`, ours
//! `93B4`. The #87 pin (`divergence_list_columns.rs`) only checked length/case
//! on a non-HeaderFile. Fixed by #119 (`list.rs` `entry_md5`).
//!
//! ## #111 / #115 — `Size` / `size` of a HeaderFile is its buffer size
//!
//! `ls` prints `hex(file.buffer_size)` (`psptool.py:172`) and `ls -j`
//! `'size': file.buffer_size` (`psptool.py:249`). `HeaderFile._parse` re-sizes
//! the buffer to the normalised header `rom_size` (`header_file.py:72-75`,
//! `:104-105` `self.buffer_size = self.rom_size`), shorter or longer than the
//! directory-declared entry. psptool-rs printed the directory-declared size.
//! Milan KRPA-U16 0.13.0.50 / .72 ABL0: header `rom_size` `0x3a0`, directory
//! `0x864f0` / `0x8c370` (#115); corpus: 16 grown + 144 shrunk HeaderFiles,
//! which `differential.rs` tolerated until #111.
//!
//! Expected values come from the fixture's named constants through the quoted
//! upstream rules, or from the live reference for the corpus pins (R-CHAR-3).

use std::collections::BTreeMap;

use md5::{Digest, Md5};
use psptool_core::fet::{FET_MAGIC_SIZE, FET_SLOT_SIZE, FET_TERMINATOR_SIZE};
use psptool_core::magic::FET_MAGIC;
use psptool_core::{
    Fet, FlashOffset, RomSize, SourceBytes, detect_rom_layout, scan_fet_candidates,
    walk_directories,
};
use psptool_ops::{RomListing, list_json, list_verbose};

const ROM_BYTES: usize = 0x100_0000;
const FET_OFF: usize = 0x2_0000;
const DIR_OFF: usize = 0xA_0000;
const BODY_OFF: usize = 0x10_0000;
/// `additional_info` v2, bits[30:29] = 01 → mode 1 flash offset
/// (`directory.py:186-193`).
const MODE_FLASH_OFFSET: u32 = 0x2000_0000;

/// Directory-declared entry size → upstream `buffer_size` (`file.py:297-299`).
const ENTRY_SIZE: u32 = 0x8000;
const PSP_FW_BOOT_LOADER: u8 = 0x01;
const HEADER_LEN: usize = 0x100; // `HeaderFile.HEADER_LEN`, header_file.py:29
/// `signature_type == 0` → `signature_len = 0x100` (`header_file.py:84-85`).
const SIG_LEN_RSA2048: usize = 0x100;
const SIZE_SIGNED: u32 = 0x10;

/// FET → `$PSP` (one 0x01 entry, `ENTRY_SIZE` @ `BODY_OFF`) → signed `$PS1`
/// HeaderFile whose header `rom_size` (+0x6c) is `rom_size`.
fn image(rom_size: u32) -> Vec<u8> {
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
    buf[e] = PSP_FW_BOOT_LOADER;
    buf[e + 4..e + 8].copy_from_slice(&ENTRY_SIZE.to_le_bytes());
    buf[e + 8..e + 12].copy_from_slice(&(BODY_OFF as u32).to_le_bytes());

    let h = BODY_OFF;
    buf[h + 0x10..h + 0x14].copy_from_slice(b"$PS1");
    buf[h + 0x14..h + 0x18].copy_from_slice(&SIZE_SIGNED.to_le_bytes());
    buf[h + 0x30..h + 0x34].copy_from_slice(&1u32.to_le_bytes()); // signed
    buf[h + 0x34..h + 0x38].copy_from_slice(&0u32.to_le_bytes()); // RSA-2048
    buf[h + 0x6c..h + 0x70].copy_from_slice(&rom_size.to_le_bytes());
    for (i, b) in buf[h + HEADER_LEN..h + ENTRY_SIZE as usize]
        .iter_mut()
        .enumerate()
    {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    buf
}

fn with_listing<T>(buf: Vec<u8>, f: impl FnOnce(&RomListing<'_>) -> T) -> T {
    let blob = SourceBytes::from_blob(buf);
    let fet = Fet::parse_at(&blob, FlashOffset(FET_OFF as u64)).expect("parse FET");
    let dirs = walk_directories(&blob, &fet, RomSize::MIB_16, FlashOffset::ZERO);
    let rom = RomListing {
        index: 0,
        blob: &blob,
        rom_size: RomSize::MIB_16,
        rom_origin: FlashOffset::ZERO,
        fet: &fet,
        directories: &dirs,
        sparse: true,
    };
    f(&rom)
}

/// Cells of the PSP_FW_BOOT_LOADER row of the sparse `ls -v` table, by header.
fn verbose_row(buf: Vec<u8>) -> BTreeMap<String, String> {
    let table = with_listing(buf, list_verbose);
    let split = |l: &str| -> Vec<String> { l.split('|').map(|c| c.trim().to_string()).collect() };
    let header = table
        .lines()
        .find(|l| l.contains("Subprogram"))
        .expect("entry table header");
    let row = table
        .lines()
        .find(|l| l.contains("PSP_FW_BOOT_LOADER"))
        .unwrap_or_else(|| panic!("no PSP_FW_BOOT_LOADER row:\n{table}"));
    split(header).into_iter().zip(split(row)).collect()
}

fn json_entry(buf: Vec<u8>) -> serde_json::Value {
    let v = with_listing(buf, |rom| list_json(rom, true));
    v.as_array()
        .and_then(|dirs| {
            dirs.iter()
                .find(|d| d["address"].as_u64() == Some(DIR_OFF as u64))
        })
        .and_then(|d| d["entries"].get(0))
        .cloned()
        .unwrap_or_else(|| panic!("no entry for $PSP @{DIR_OFF:#x} in {v}"))
}

/// #118: header `rom_size == 0` → upstream `rom_size := buffer_size =
/// ENTRY_SIZE` (`header_file.py:72-73`, `file.py:297-299`) → `ls -v`
/// `size_packed` is `hex(0x8000)` (`psptool.py:187`). Ours prints `0x0`.
///
/// Tracking: #118
#[test]
fn divergence_size_packed_normalises_zero_rom_size() {
    let row = verbose_row(image(0));
    let expected = format!("{ENTRY_SIZE:#x}");
    assert_eq!(
        row.get("size_packed").map(String::as_str),
        Some(expected.as_str()),
        "divergence #118: size_packed must be hex(rom_size) after \
         header_file.py:72-73 sets rom_size = buffer_size ({expected}); row = {row:?}"
    );
}

/// #118, JSON form: `ls -j` `sizes.packed` = `file.rom_size`
/// (`psptool.py:264`) = `ENTRY_SIZE` after normalisation.
///
/// Tracking: #118
#[test]
fn divergence_json_sizes_packed_normalises_zero_rom_size() {
    let entry = json_entry(image(0));
    assert_eq!(
        entry["sizes"]["packed"].as_u64(),
        Some(u64::from(ENTRY_SIZE)),
        "divergence #118: sizes.packed must be the normalised rom_size \
         (header_file.py:72-73 → buffer_size {ENTRY_SIZE:#x}); entry = {entry}"
    );
}

/// CONTROL (passes today): a non-zero header `rom_size` is printed as is —
/// isolates #118 to the `== 0` normalisation.
#[test]
fn control_size_packed_nonzero_rom_size() {
    let row = verbose_row(image(ENTRY_SIZE));
    let expected = format!("{ENTRY_SIZE:#x}");
    assert_eq!(
        row.get("size_packed").map(String::as_str),
        Some(expected.as_str())
    );
}

/// Header `rom_size` below the directory-declared `ENTRY_SIZE`, the Milan
/// KRPA-U16 ABL0 value (#115).
const SHRUNK_ROM_SIZE: u32 = 0x3a0;
/// Header `rom_size` past the directory-declared `ENTRY_SIZE`.
const GROWN_ROM_SIZE: u32 = ENTRY_SIZE + 0x1000;

/// #111 / #115: the `Size` cell and JSON `size` of a HeaderFile are
/// `file.buffer_size` (`psptool.py:172`, `:249`) = the normalised header
/// `rom_size` (`header_file.py:72-75`, `:104-105`), whether it is below or
/// past the directory-declared `ENTRY_SIZE`, and `ENTRY_SIZE` when the header
/// field is 0. Ours printed `ENTRY_SIZE` throughout.
///
/// Tracking: #111, #115
#[test]
fn divergence_headerfile_size_is_its_buffer_size() {
    for (rom_size, expected) in [
        (SHRUNK_ROM_SIZE, SHRUNK_ROM_SIZE),
        (GROWN_ROM_SIZE, GROWN_ROM_SIZE),
        (0, ENTRY_SIZE),
    ] {
        let row = verbose_row(image(rom_size));
        let want = format!("{expected:#x}");
        assert_eq!(
            row.get("Size").map(String::as_str),
            Some(want.as_str()),
            "divergence #111: ls Size of a HeaderFile with header rom_size {rom_size:#x} \
             must be hex(buffer_size) = {want} (header_file.py:104-105); row = {row:?}"
        );
        let entry = json_entry(image(rom_size));
        assert_eq!(
            entry["size"].as_u64(),
            Some(u64::from(expected)),
            "divergence #111: ls -j size of a HeaderFile with header rom_size \
             {rom_size:#x} must be buffer_size {want}; entry = {entry}"
        );
    }
}

/// #119: the sparse `MD5` cell of a HeaderFile is `md5(self.body)[:4].upper()`
/// (`header_file.py:312-315`, `psptool.py:180`) where `self.body` is
/// `[HEADER_LEN, rom_size - signature_len)` (`header_file.py:106`; signed,
/// RSA-2048 → `signature_len = 0x100`). Ours hashes the whole entry.
///
/// Tracking: #119
#[test]
fn divergence_sparse_md5_hashes_headerfile_body() {
    let buf = image(ENTRY_SIZE);
    let body = &buf[BODY_OFF + HEADER_LEN..BODY_OFF + ENTRY_SIZE as usize - SIG_LEN_RSA2048];
    let digest = Md5::digest(body);
    let expected = format!("{:02X}{:02X}", digest[0], digest[1]);
    let row = verbose_row(buf);
    assert_eq!(
        row.get("MD5").map(String::as_str),
        Some(expected.as_str()),
        "divergence #119: HeaderFile MD5 must be md5(body[0x100:rom_size-0x100])[:4].upper() \
         per header_file.py:106,312-315 / psptool.py:180; row = {row:?}"
    );
}

// ---------------------------------------------------------------------------
// Corpus-gated differential against the live reference (PSPTOOL_REFERENCE)
// ---------------------------------------------------------------------------

/// One JSON line per HeaderFile: directory address, file address, readable
/// type, normalised `rom_size`, `md5()[:4].upper()`.
const REFERENCE_SCRIPT: &str = r#"
import sys, json, io, contextlib
from psptool import PSPTool
from psptool.header_file import HeaderFile
with contextlib.redirect_stderr(io.StringIO()):
    pt = PSPTool.from_file(sys.argv[1])
    out = []
    for rom in pt.blob.roms:
        for d in rom.directories:
            for f in d.files:
                if isinstance(f, HeaderFile):
                    out.append([d.get_address(), f.get_address(), f.get_readable_type(),
                                f.rom_size, f.md5()[:4].upper()])
print(json.dumps(out))
"#;

type Key = (u64, u64, String);

/// `(dir address, entry address, sectionType)` → `(sizes.packed, md5[:4].upper())`
/// for every HeaderFile-class entry of our `ls -j -v`, all ROMs.
fn ours(rom: &std::path::Path) -> BTreeMap<Key, Vec<(u64, String)>> {
    let blob = SourceBytes::from_blob(std::fs::read(rom).expect("read ROM"));
    let mut out: BTreeMap<Key, Vec<(u64, String)>> = BTreeMap::new();
    let layouts: Vec<_> = scan_fet_candidates(&blob)
        .into_iter()
        .filter_map(|p| detect_rom_layout(&blob, p))
        .collect();
    for (index, layout) in layouts.iter().enumerate() {
        let dirs = walk_directories(&blob, &layout.fet, layout.rom_size, layout.rom_origin);
        let listing = RomListing {
            index,
            blob: &blob,
            rom_size: layout.rom_size,
            rom_origin: layout.rom_origin,
            fet: &layout.fet,
            directories: &dirs,
            sparse: true,
        };
        let v = list_json(&listing, true);
        for d in v.as_array().into_iter().flatten() {
            let dir = d["address"].as_u64().unwrap_or(u64::MAX);
            for e in d["entries"].as_array().into_iter().flatten() {
                let (Some(addr), Some(ty), Some(packed), Some(md5)) = (
                    e["address"].as_u64(),
                    e["sectionType"].as_str(),
                    e["sizes"]["packed"].as_u64(),
                    e["md5"].as_str(),
                ) else {
                    continue;
                };
                out.entry((dir, addr, ty.to_string()))
                    .or_default()
                    .push((packed, md5[..4].to_uppercase()));
            }
        }
    }
    out
}

/// Every reference HeaderFile with a same-keyed HeaderFile-class entry of ours;
/// `field` picks the compared value (0 = packed, 1 = md5).
fn corpus_mismatches(field: usize) -> Option<Vec<String>> {
    let reference = std::env::var_os("PSPTOOL_REFERENCE").filter(|v| !v.is_empty())?;
    let roms = psptool_fixtures::corpus_rom_paths();
    if roms.is_empty() {
        return None;
    }
    let mut bad = Vec::new();
    for rom in roms {
        let out = std::process::Command::new(&reference)
            .args(["-I", "-c", REFERENCE_SCRIPT])
            .arg(&rom)
            .output()
            .expect("spawn reference python");
        assert!(
            out.status.success(),
            "reference failed on {}: {}",
            rom.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        let theirs: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON");
        let mine = ours(&rom);
        for r in theirs.as_array().into_iter().flatten() {
            let key = (
                r[0].as_u64().unwrap(),
                r[1].as_u64().unwrap(),
                r[2].as_str().unwrap().to_string(),
            );
            // Cross-ROM / dedup echoes (upstream reports an address we resolve
            // elsewhere) are the differential's business — skip unmatched keys.
            let Some(cands) = mine.get(&key) else {
                continue;
            };
            let (want, got): (String, Vec<String>) = if field == 0 {
                let want = r[3].as_u64().unwrap();
                (
                    format!("{want:#x}"),
                    cands.iter().map(|c| format!("{:#x}", c.0)).collect(),
                )
            } else {
                (
                    r[4].as_str().unwrap().to_string(),
                    cands.iter().map(|c| c.1.clone()).collect(),
                )
            };
            if !got.contains(&want) {
                bad.push(format!(
                    "{} dir {:#x} @{:#x} {}: reference {want}, ours {got:?}",
                    rom.file_name().unwrap().to_string_lossy(),
                    key.0,
                    key.1,
                    key.2
                ));
            }
        }
    }
    Some(bad)
}

/// #118 corpus pin: `sizes.packed` of every HeaderFile equals the reference's
/// normalised `rom_size`. Fails on 39 0x1/0x8 entries (Summit-Ridge combo
/// parts) plus 0xc/0x3/0x10/0x12/0x14/0x2e entries.
///
/// Tracking: #118
#[test]
fn divergence_corpus_sizes_packed_matches_reference() {
    let Some(bad) = corpus_mismatches(0) else {
        eprintln!("skipped: PSPTOOL_TEST_CORPUS / PSPTOOL_REFERENCE unset");
        return;
    };
    assert!(
        bad.is_empty(),
        "divergence #118: {} HeaderFiles' packed size differs (header_file.py:72-73):\n{}",
        bad.len(),
        bad.join("\n")
    );
}

/// #119 corpus pin: `md5()[:4].upper()` of every HeaderFile equals the
/// reference's (`header_file.py:312-315`).
///
/// Tracking: #119
#[test]
fn divergence_corpus_headerfile_md5_matches_reference() {
    let Some(bad) = corpus_mismatches(1) else {
        eprintln!("skipped: PSPTOOL_TEST_CORPUS / PSPTOOL_REFERENCE unset");
        return;
    };
    assert!(
        bad.is_empty(),
        "divergence #119: {} HeaderFiles' MD5 differs (header_file.py:312-315):\n{}",
        bad.len(),
        bad.join("\n")
    );
}
