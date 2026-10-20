//! ACToR critic divergence pins: the `ls` ROM row and the `Secondary
//! Directory` column of a ROM that does not start at file offset 0 — a
//! capsule-wrapped image (`0x800` header on ASUS `.CAP` files and the Milan
//! KRPA-U16 BIOS images, `0x220` on HP, a few MiB on Lenovo `.iso`) or the
//! upper ROM of a 32 MiB dual-ROM image.
//!
//! ## Upstream oracle (`/tmp/psptool-ref/psptool`, PSPTool `241629b`)
//!
//! `psptool.py:69-75` prints one row per `Rom`:
//!
//! ```python
//! t.add_row([rom_index, hex(rom.get_address()), hex(rom.buffer_size),
//!            hex(rom.fet.get_address()), rom.agesa_version])
//! ```
//!
//! A `Rom` is `NestedBuffer(parent_blob, rom_size, rom_offset)` (`rom.py:8-9`)
//! cut by `Blob` at `rom_offset = fet_location - fet_offset` with the
//! image-wide `rom_size` (largest of 32/16/8 MiB that fits, `blob.py:53-55`)
//! when the FET lies in page 0, else `min(rom_size, 16 MiB)`
//! (`blob.py:65`, `:72-75`). So `Addr` is where the ROM starts in the file and
//! `Size` the ROM window, not the file length.
//!
//! `psptool.py:86` prints `directory.secondary_directory_offsets`, filled with
//! `entry.file_offset()` (`directory.py:156-161`) — an offset into the ROM
//! (`entry.py:38-70`; mode 2/3 add the directory's ROM-relative
//! `buffer_offset`), whereas the directory `Addr` column is
//! `directory.get_address()`, an offset into the file.
//!
//! ## Target divergence (fixed by #113)
//!
//! `list.rs` printed `Addr 0x0` and `Size` = the file length, and resolved
//! secondary pointers to file offsets. Milan 0.13.0.50 / .72 (`0x1000800`
//! bytes): upstream `0x800` / `0x1000000`, `$PSP` secondary `0x272000`, `$BHD`
//! `0x582000`; ours `0x0` / `0x1000800`, `0x272800`, `0x582800`. Directory and
//! entry addresses already agreed with upstream and are unchanged.
//!
//! Expected values derive from the fixture's named constants through the
//! quoted upstream rules, or from the live reference for the corpus pin
//! (R-CHAR-3).

use std::collections::BTreeMap;

use psptool_core::fet::{FET_MAGIC_SIZE, FET_SLOT_SIZE, FET_TERMINATOR_SIZE};
use psptool_core::magic::FET_MAGIC;
use psptool_core::{
    FlashOffset, SourceBytes, detect_rom_layout, scan_fet_candidates, walk_directories,
};
use psptool_ops::{RomListing, list_default, list_json};

const MIB_16: usize = 0x100_0000;
/// Capsule header in front of the ROM (ASUS `.CAP`, Milan KRPA-U16).
const PREFIX: usize = 0x800;
/// FET-relative ROM offset `Blob` tries first (`blob.py:42-44`).
const FET_IN_ROM: usize = 0x2_0000;
/// ROM-relative directory offsets (the Milan layout).
const L1_IN_ROM: usize = 0x12_2000;
const L2_IN_ROM: usize = 0x27_2000;
const LEAF_IN_ROM: usize = 0x30_0000;

/// `additional_info` v2, bits[30:29] = 01 → mode 1, a flash offset into the
/// ROM (`directory.py:186-193`, `entry.py:61-63`).
const MODE_FLASH_OFFSET: u32 = 0x2000_0000;
const PSP_L2_PTR: u8 = 0x40; // secondary (`file.py:34`)
const WRAPPED_IKEK: u8 = 0x21; // NO_HDR leaf (`file.py:239`)

fn write_fet(buf: &mut [u8], at: usize, target: u32) {
    buf[at..at + FET_MAGIC_SIZE].copy_from_slice(FET_MAGIC.as_bytes());
    buf[at + FET_MAGIC_SIZE..at + FET_MAGIC_SIZE + FET_SLOT_SIZE]
        .copy_from_slice(&target.to_le_bytes());
    let term = at + FET_MAGIC_SIZE + FET_SLOT_SIZE;
    buf[term..term + FET_TERMINATOR_SIZE].copy_from_slice(&[0xFF; FET_TERMINATOR_SIZE]);
}

/// One-entry mode-1 directory at file offset `at` whose entry (`entry_type`)
/// points at ROM offset `target`.
fn write_dir(buf: &mut [u8], at: usize, magic: &[u8; 4], entry_type: u8, target: usize) {
    buf[at..at + 4].copy_from_slice(magic);
    buf[at + 8..at + 12].copy_from_slice(&1u32.to_le_bytes());
    buf[at + 12..at + 16].copy_from_slice(&MODE_FLASH_OFFSET.to_le_bytes());
    let e = at + 0x10;
    buf[e] = entry_type;
    buf[e + 4..e + 8].copy_from_slice(&0x400u32.to_le_bytes());
    buf[e + 8..e + 12].copy_from_slice(&(target as u32).to_le_bytes());
}

/// A ROM at file offset `origin`: FET → `$PSP` → `0x40` → `$PL2` → leaf, the
/// FET slot and the `0x40` pointer holding ROM-relative offsets.
fn write_rom(buf: &mut [u8], origin: usize) {
    write_fet(buf, origin + FET_IN_ROM, L1_IN_ROM as u32);
    write_dir(buf, origin + L1_IN_ROM, b"$PSP", PSP_L2_PTR, L2_IN_ROM);
    write_dir(buf, origin + L2_IN_ROM, b"$PL2", WRAPPED_IKEK, LEAF_IN_ROM);
}

/// `ls` of every ROM of `buf`, in `Blob` order.
fn render_all(buf: Vec<u8>) -> Vec<String> {
    let blob = SourceBytes::from_blob(buf);
    scan_fet_candidates(&blob)
        .into_iter()
        .filter_map(|p| detect_rom_layout(&blob, p))
        .enumerate()
        .map(|(index, layout)| {
            let dirs = walk_directories(&blob, &layout.fet, layout.rom_size, layout.rom_origin);
            list_default(&RomListing {
                index,
                blob: &blob,
                rom_size: layout.rom_size,
                rom_origin: layout.rom_origin,
                fet: &layout.fet,
                directories: &dirs,
                sparse: false,
            })
        })
        .collect()
}

fn cells(line: &str) -> Vec<String> {
    line.split('|').map(|c| c.trim().to_string()).collect()
}

/// `(Addr, Size, FET)` of the ROM-summary row of one `ls` rendering.
fn rom_row(rendered: &str) -> (String, String, String) {
    let lines: Vec<&str> = rendered.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.contains("AGESA") && l.contains("ROM"))
        .unwrap_or_else(|| panic!("no ROM table:\n{rendered}"));
    let c = cells(lines[at + 2]);
    (c[2].clone(), c[3].clone(), c[4].clone())
}

/// Directory `Addr` → its `Secondary Directory` cell, for every directory
/// table of one `ls` rendering (combo directories, which upstream does not
/// list, excluded).
fn secondary_cells(rendered: &str) -> BTreeMap<u64, String> {
    let lines: Vec<&str> = rendered.lines().collect();
    let mut out = BTreeMap::new();
    for (i, l) in lines.iter().enumerate() {
        if !(l.contains("Directory") && l.contains("Generation")) {
            continue;
        }
        let c = cells(lines[i + 2]);
        if c[5] == "2PSP" || c[5] == "2BHD" {
            continue;
        }
        let addr = u64::from_str_radix(c[3].trim_start_matches("0x"), 16).expect("Addr");
        out.insert(addr, c[6].clone());
    }
    out
}

/// #113: a ROM behind a `PREFIX`-byte capsule header. `Blob` cuts it at
/// `rom_offset = (PREFIX + FET_IN_ROM) - FET_IN_ROM = PREFIX` with
/// `rom_size = 16 MiB` (the largest size not above the `PREFIX + 16 MiB`
/// file, `blob.py:53-55`), so the ROM row reads `Addr PREFIX`, `Size
/// 0x1000000` (`psptool.py:71-72`). The `$PSP`'s `0x40` pointer is
/// `file_offset() = L2_IN_ROM` (`entry.py:61-63`), printed as is
/// (`psptool.py:86`), while the `$PL2` itself is listed at `PREFIX +
/// L2_IN_ROM` (`get_address()`).
///
/// Tracking: #113
#[test]
fn divergence_capsule_rom_row_and_secondary_are_rom_relative() {
    let mut buf = vec![0u8; PREFIX + MIB_16];
    write_rom(&mut buf, PREFIX);
    let out = render_all(buf);
    assert_eq!(out.len(), 1, "one ROM expected");
    let rendered = &out[0];

    assert_eq!(
        rom_row(rendered),
        (
            format!("{PREFIX:#x}"),
            format!("{MIB_16:#x}"),
            format!("{:#x}", PREFIX + FET_IN_ROM)
        ),
        "divergence #113: ROM row must be hex(rom.get_address()) / hex(rom.buffer_size) \
         (psptool.py:71-72, blob.py:70-73)\n{rendered}"
    );
    let secondary = secondary_cells(rendered);
    assert_eq!(
        secondary
            .get(&((PREFIX + L1_IN_ROM) as u64))
            .map(String::as_str),
        Some(format!("{L2_IN_ROM:#x}").as_str()),
        "divergence #113: the $PSP's secondary directory is its ROM-relative \
         file_offset() (entry.py:61-63, psptool.py:86)\n{rendered}"
    );
    assert!(
        secondary.contains_key(&((PREFIX + L2_IN_ROM) as u64)),
        "control: the $PL2 is still listed at its file offset\n{rendered}"
    );
}

/// #113, JSON form: `ls -j` `secondaryAddresses` is the same
/// `directory.secondary_directory_offsets` (`psptool.py:212`), while the
/// directory `address` stays `get_address()` (`psptool.py:210`).
///
/// Tracking: #113
#[test]
fn divergence_capsule_json_secondary_addresses_are_rom_relative() {
    let mut buf = vec![0u8; PREFIX + MIB_16];
    write_rom(&mut buf, PREFIX);
    let blob = SourceBytes::from_blob(buf);
    let fet_at = FlashOffset((PREFIX + FET_IN_ROM) as u64);
    let layout = detect_rom_layout(&blob, fet_at).expect("ROM layout");
    let dirs = walk_directories(&blob, &layout.fet, layout.rom_size, layout.rom_origin);
    let json = list_json(
        &RomListing {
            index: 0,
            blob: &blob,
            rom_size: layout.rom_size,
            rom_origin: layout.rom_origin,
            fet: &layout.fet,
            directories: &dirs,
            sparse: false,
        },
        false,
    );
    let psp = json
        .as_array()
        .and_then(|d| {
            d.iter()
                .find(|d| d["address"].as_u64() == Some((PREFIX + L1_IN_ROM) as u64))
        })
        .unwrap_or_else(|| panic!("$PSP @{:#x} not in {json}", PREFIX + L1_IN_ROM));
    assert_eq!(
        psp["secondaryAddresses"],
        serde_json::json!([L2_IN_ROM]),
        "divergence #113: secondaryAddresses must be ROM-relative (psptool.py:212); {psp}"
    );
}

/// #113, dual-ROM image: the upper ROM's FET sits in page 1, so `Blob` cuts
/// it at `MIB_16` with `min(rom_size, 16 MiB)` (`blob.py:65`, `:74-75`); its
/// secondary pointers are offsets into that ROM. The lower ROM keeps the
/// image-wide 32 MiB window (`blob.py:72-73`).
///
/// Tracking: #113
#[test]
fn divergence_upper_rom_row_and_secondary_are_rom_relative() {
    let mut buf = vec![0u8; 2 * MIB_16];
    write_rom(&mut buf, 0);
    write_rom(&mut buf, MIB_16);
    let out = render_all(buf);
    assert_eq!(out.len(), 2, "two ROMs expected");

    assert_eq!(
        rom_row(&out[0]),
        (
            "0x0".to_string(),
            format!("{:#x}", 2 * MIB_16),
            format!("{FET_IN_ROM:#x}")
        ),
        "control: the page-0 ROM spans the 32 MiB image\n{}",
        out[0]
    );
    assert_eq!(
        rom_row(&out[1]),
        (
            format!("{MIB_16:#x}"),
            format!("{MIB_16:#x}"),
            format!("{:#x}", MIB_16 + FET_IN_ROM)
        ),
        "divergence #113: the upper ROM row must be its 16 MiB window (blob.py:74-75)\n{}",
        out[1]
    );
    let secondary = secondary_cells(&out[1]);
    assert_eq!(
        secondary
            .get(&((MIB_16 + L1_IN_ROM) as u64))
            .map(String::as_str),
        Some(format!("{L2_IN_ROM:#x}").as_str()),
        "divergence #113: the upper ROM's secondary directory is ROM-relative\n{}",
        out[1]
    );
}

// ---------------------------------------------------------------------------
// Corpus-gated differential against the live reference (PSPTOOL_REFERENCE)
// ---------------------------------------------------------------------------

/// `{"roms": [[addr, size, fet], …], "dirs": {"<addr>": [secondary, …]}}`.
const REFERENCE_SCRIPT: &str = r#"
import sys, json, io, contextlib
from psptool import PSPTool
with contextlib.redirect_stderr(io.StringIO()):
    pt = PSPTool.from_file(sys.argv[1])
roms = [[r.get_address(), r.buffer_size, r.fet.get_address()] for r in pt.blob.roms]
dirs = {}
for r in pt.blob.roms:
    for d in r.directories:
        dirs.setdefault(str(d.get_address()), d.secondary_directory_offsets)
print(json.dumps({'roms': roms, 'dirs': dirs}))
"#;

/// Every corpus image's ROM rows and every directory's secondary-directory
/// cell equal the reference's (`psptool.py:71-73`, `:86`). Before #113, 21 of
/// the 54 corpus images differed: every ASUS `.CAP`, both HP and all three
/// Lenovo images, and the upper ROM of `H12SSW9.719`.
///
/// Tracking: #113
#[test]
fn divergence_corpus_rom_rows_and_secondaries_match_reference() {
    let Some(reference) = std::env::var_os("PSPTOOL_REFERENCE").filter(|v| !v.is_empty()) else {
        eprintln!("skipped: PSPTOOL_REFERENCE unset");
        return;
    };
    let roms = psptool_fixtures::corpus_rom_paths();
    if roms.is_empty() {
        eprintln!("skipped: PSPTOOL_TEST_CORPUS unset");
        return;
    }
    let hex = |v: &serde_json::Value| format!("{:#x}", v.as_u64().expect("int"));
    let mut bad = Vec::new();
    for rom in roms {
        let name = rom.file_name().unwrap().to_string_lossy().into_owned();
        let out = std::process::Command::new(&reference)
            .args(["-I", "-c", REFERENCE_SCRIPT])
            .arg(&rom)
            .output()
            .expect("spawn reference python");
        assert!(
            out.status.success(),
            "reference failed on {name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let theirs: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON");
        let ours = render_all(std::fs::read(&rom).expect("read ROM"));

        let their_roms: Vec<(String, String, String)> = theirs["roms"]
            .as_array()
            .expect("roms")
            .iter()
            .map(|r| (hex(&r[0]), hex(&r[1]), hex(&r[2])))
            .collect();
        let our_roms: Vec<_> = ours.iter().map(|r| rom_row(r)).collect();
        if our_roms != their_roms {
            bad.push(format!(
                "{name}: ROM rows reference {their_roms:?}, ours {our_roms:?}"
            ));
        }

        let mut our_secondary = BTreeMap::new();
        for r in &ours {
            for (addr, cell) in secondary_cells(r) {
                our_secondary.entry(addr).or_insert(cell);
            }
        }
        for (addr, list) in theirs["dirs"].as_object().expect("dirs") {
            let addr: u64 = addr.parse().expect("address");
            let want = list
                .as_array()
                .expect("list")
                .iter()
                .map(hex)
                .collect::<Vec<_>>()
                .join(", ");
            // A directory only the reference lists is the differential's
            // business, not this pin's.
            let Some(got) = our_secondary.get(&addr) else {
                continue;
            };
            if *got != want {
                bad.push(format!(
                    "{name} dir {addr:#x}: secondary reference [{want}], ours [{got}]"
                ));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "divergence #113: {} ROM rows / secondary cells differ from the reference \
         (psptool.py:71-73, :86):\n{}",
        bad.len(),
        bad.join("\n")
    );
}
