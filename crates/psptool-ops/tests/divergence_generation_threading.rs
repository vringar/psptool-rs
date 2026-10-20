//! ACToR critic divergence pins: the `ls` Generation column drops the Zen
//! generation upstream threads through the directory graph.
//!
//! ## Upstream oracle (`/tmp/psptool-ref/psptool`, PSPTool `241629b`)
//!
//! `directory.py:58-83` (`Directory.create_directories_if_not_exist`):
//!
//! ```python
//! if offset in fet.psptool.directories_by_offset:                         # :61
//!     fet.psptool.directories_by_offset[offset].update_zen_generation(fet, zen_generation)  # :62
//!     return [fet.psptool.directories_by_offset[offset]]
//! ...
//!     directory = cls.from_offset(fet, offset, zen_generation)            # :68
//! ...
//! for secondary_directory_offset in directory.secondary_directory_offsets:   # :81
//!     secondary_directories = cls.create_directories_if_not_exist(secondary_directory_offset, fet, zen_generation)  # :82
//! ```
//!
//! `directory.py:243-249` (`update_zen_generation`):
//!
//! ```python
//! if zen_generation is not None:
//!     if zen_generation not in self.zen_generation:
//!         self.zen_generation += '\n' + zen_generation                     # :246
//!         for offset in self.secondary_directory_offsets:
//!             dir = fet.psptool.directories_by_offset[offset]
//!             dir.update_zen_generation(fet, zen_generation)               # :249
//! ```
//!
//! The label comes from the combo entry (`fet.py:117-123`):
//! `get_possible_zen_generation(combo_dir[i*16+5:i*16+8])` + `' (PSP ID 0x…)'`,
//! matched against `ZEN_GENERATION_IDS` (`directory.py:34-39`), and is printed
//! verbatim in the `ls` Generation column (`psptool.py:84`,
//! `directory.zen_generation`).
//!
//! So upstream:
//!
//! 1. stamps every L2 directory (`$PL2` / `$BL2`, reached through a
//!    `0x40`/`0x70` secondary pointer, `file.py:34`) with its L1 parent's
//!    generation (`:82`), and
//! 2. accumulates EVERY generation of a directory that several combo entries
//!    point at (`:61-62` → `:246`), cascading the addition to its L2 children
//!    (`:247-249`).
//!
//! ## Target divergence (fixed by #116 / #117 / #57)
//!
//! `psptool_core::walk_directories` (`directory.rs`) recorded one provenance per
//! directory (first visit wins) and `psptool_ops::list::directory_generation`
//! derived a label only for `ComboEntry` / `Tertiary` provenance; an
//! `L2Pointer` directory fell to `_ => String::new()`. The walk now threads
//! `DirectoryRef::generations` the way upstream threads `zen_generation`, and
//! the label is upstream's. Before the fix:
//!
//! * #116 (D1): every combo-reached L1's `$PL2`/`$BL2` child renders a BLANK
//!   Generation cell. Corpus: the Zen 3 `$PL2`/`$BL2` of
//!   `AORUS_X570_X57AOXT2.FCd` (0x7f0000, 0x670000, 0x950000, 0x7d0000) and
//!   `ASRock-A520M-HSV-1.31.ROM`, the Zen 2 `$PL2` (PSP ID 0xbc0b0500) of every
//!   B450/X470 image — the L2 directories that carry the 0x2 / 0x28 / 0x24 /
//!   0x39 HeaderFiles on those parts.
//! * #117 (D2): a directory two combo entries point at (Zen 1 0xbc0a0000 +
//!   Zen 2 0xbc0a0100 on every Pinnacle/Picasso desktop image, e.g.
//!   `AORUS_X570` 0x2c0000) renders only the first generation, and its `$PL2`
//!   child none.
//!
//! The pins compare generation TOKENS (`Zen <n>` digits, format-agnostic: the
//! project renders `Zen3`, upstream `Zen 3 (PSP ID 0xbc0c0140)` — that label
//! format is pinned separately against #57). Expected tokens are derived from
//! `ZEN_GENERATION_IDS` (`directory.py:34-39`) for the fixture's combo ids, or
//! from the live reference for the corpus pins (R-CHAR-3) — never read back
//! from the code under test.

use std::collections::{BTreeMap, BTreeSet};

use psptool_core::fet::{FET_MAGIC_SIZE, FET_SLOT_SIZE, FET_TERMINATOR_SIZE};
use psptool_core::magic::FET_MAGIC;
use psptool_core::{
    Fet, FlashOffset, RomSize, SourceBytes, detect_rom_layout, scan_fet_candidates,
    walk_directories,
};
use psptool_ops::{RomListing, list_default};

const ROM_BYTES: usize = 0x100_0000; // 16 MiB → addr_mask = 0x00FF_FFFF
const FET_OFF: usize = 0x2_0000;
const COMBO_OFF: usize = 0x6_0000;
const L1_OFF: usize = 0x7_0000;
const L2_OFF: usize = 0x8_0000;
const LEAF_BODY_OFF: usize = 0x9_0000;

/// `additional_info` v2 with bits[30:29] = 01 → address mode 1, a plain flash
/// offset (`directory.py:186-193`, `entry.py:61-63`).
const MODE_FLASH_OFFSET: u32 = 0x2000_0000;

/// Combo generation ids (LE u32 at combo entry +4; upstream matches bytes
/// `[5:8]`, `fet.py:117`) and the `ZEN_GENERATION_IDS` key each maps to
/// (`directory.py:34-36`).
const ZEN1_ID: u32 = 0xBC0A_0000; // [5:8] = 00 0A BC → 'Zen 1'
const ZEN2_ID: u32 = 0xBC0A_0100; // [5:8] = 01 0A BC → 'Zen 2'
const ZEN3_ID: u32 = 0xBC0C_0140; // [5:8] = 01 0C BC → 'Zen 3'

/// Entry types (`file.py:34`, `file.py:100-161`).
const PSP_L2_PTR: u8 = 0x40; // PSP_FW_L2_PTR (secondary)
const BIOS_L2_PTR: u8 = 0x70; // BIOS_L2_PTR (secondary)
const WRAPPED_IKEK: u8 = 0x21; // NO_HDR leaf
const APCB: u8 = 0x60; // NO_HDR BIOS leaf

const PSP_ENTRY: usize = 0x10;
const BIOS_ENTRY: usize = 0x18;

fn write_fet(buf: &mut [u8], target: usize) {
    buf[FET_OFF..FET_OFF + FET_MAGIC_SIZE].copy_from_slice(FET_MAGIC.as_bytes());
    buf[FET_OFF + FET_MAGIC_SIZE..FET_OFF + FET_MAGIC_SIZE + FET_SLOT_SIZE]
        .copy_from_slice(&(target as u32).to_le_bytes());
    let term = FET_OFF + FET_MAGIC_SIZE + FET_SLOT_SIZE;
    buf[term..term + FET_TERMINATOR_SIZE].copy_from_slice(&[0xFF; FET_TERMINATOR_SIZE]);
}

/// Combo directory (`2PSP`/`2BHD`): 16-byte header, 16 reserved zero bytes,
/// then one 16-byte entry `[flags | gen id | pointer | rsv]` per `(id, ptr)`
/// (`fet.py:94-127`).
fn write_combo(buf: &mut [u8], magic: &[u8; 4], entries: &[(u32, usize)]) {
    buf[COMBO_OFF..COMBO_OFF + 4].copy_from_slice(magic);
    buf[COMBO_OFF + 8..COMBO_OFF + 12].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    for (i, (gen_id, ptr)) in entries.iter().enumerate() {
        let e = COMBO_OFF + 0x20 + i * 0x10;
        buf[e + 4..e + 8].copy_from_slice(&gen_id.to_le_bytes());
        buf[e + 8..e + 12].copy_from_slice(&(*ptr as u32).to_le_bytes());
    }
}

/// One-entry directory at `off` (`magic`, mode-1 addressing) whose entry has
/// `entry_type` and points at `target` (`size` bytes). `entry_size` is 0x10
/// for PSP and 0x18 for BIOS directories (`entry.py:27`, `:137`).
fn write_dir(
    buf: &mut [u8],
    off: usize,
    magic: &[u8; 4],
    entry_size: usize,
    entry_type: u8,
    target: usize,
    size: u32,
) {
    buf[off..off + 4].copy_from_slice(magic);
    buf[off + 8..off + 12].copy_from_slice(&1u32.to_le_bytes()); // count
    buf[off + 12..off + 16].copy_from_slice(&MODE_FLASH_OFFSET.to_le_bytes());
    let e = off + 0x10;
    buf[e] = entry_type;
    buf[e + 4..e + 8].copy_from_slice(&size.to_le_bytes());
    buf[e + 8..e + 12].copy_from_slice(&(target as u32).to_le_bytes());
    if entry_size == BIOS_ENTRY {
        buf[e + 16..e + 24].copy_from_slice(&u64::MAX.to_le_bytes()); // destination unused
    }
}

/// FET → `2PSP` combo (`ids`, every entry → L1) → L1 `$PSP` → `0x40` → L2 `$PL2`.
fn psp_chain(ids: &[u32]) -> Vec<u8> {
    let mut buf = vec![0u8; ROM_BYTES];
    write_fet(&mut buf, COMBO_OFF);
    let entries: Vec<(u32, usize)> = ids.iter().map(|&id| (id, L1_OFF)).collect();
    write_combo(&mut buf, b"2PSP", &entries);
    write_dir(
        &mut buf, L1_OFF, b"$PSP", PSP_ENTRY, PSP_L2_PTR, L2_OFF, 0x400,
    );
    write_dir(
        &mut buf,
        L2_OFF,
        b"$PL2",
        PSP_ENTRY,
        WRAPPED_IKEK,
        LEAF_BODY_OFF,
        0x10,
    );
    buf
}

/// FET slot → L1 `$PSP` (no combo) → `0x40` → L2 `$PL2`.
fn fet_direct_psp_chain() -> Vec<u8> {
    let mut buf = vec![0u8; ROM_BYTES];
    write_fet(&mut buf, L1_OFF);
    write_dir(
        &mut buf, L1_OFF, b"$PSP", PSP_ENTRY, PSP_L2_PTR, L2_OFF, 0x400,
    );
    write_dir(
        &mut buf,
        L2_OFF,
        b"$PL2",
        PSP_ENTRY,
        WRAPPED_IKEK,
        LEAF_BODY_OFF,
        0x10,
    );
    buf
}

/// FET → `2BHD` combo → L1 `$BHD` → `0x70` → L2 `$BL2`.
fn bios_chain(id: u32) -> Vec<u8> {
    let mut buf = vec![0u8; ROM_BYTES];
    write_fet(&mut buf, COMBO_OFF);
    write_combo(&mut buf, b"2BHD", &[(id, L1_OFF)]);
    write_dir(
        &mut buf,
        L1_OFF,
        b"$BHD",
        BIOS_ENTRY,
        BIOS_L2_PTR,
        L2_OFF,
        0x400,
    );
    write_dir(
        &mut buf,
        L2_OFF,
        b"$BL2",
        BIOS_ENTRY,
        APCB,
        LEAF_BODY_OFF,
        0x10,
    );
    buf
}

fn render_synthetic(buf: Vec<u8>) -> String {
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
        sparse: false,
    };
    list_default(&rom)
}

/// Every directory-header table of an `ls` rendering: absolute address → the
/// table's body text (all body lines, so a multi-line Generation cell is kept).
fn directory_blocks(rendered: &str) -> BTreeMap<u64, String> {
    let lines: Vec<&str> = rendered.lines().collect();
    let mut out = BTreeMap::new();
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i];
        if l.starts_with('|') && l.contains("Directory") && l.contains("Generation") {
            // header, separator, body…, separator
            let mut j = i + 2;
            let mut body = Vec::new();
            while j < lines.len() && lines[j].starts_with('|') {
                body.push(lines[j]);
                j += 1;
            }
            if let Some(first) = body.first() {
                let cells: Vec<&str> = first.split('|').map(str::trim).collect();
                if let Some(addr) = cells
                    .get(3)
                    .and_then(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).ok())
                {
                    out.entry(addr).or_insert_with(|| body.join("\n"));
                }
            }
            i = j;
            continue;
        }
        i += 1;
    }
    out
}

/// Generation tokens of a cell / block: the digit of every `Zen <n>` /
/// `Zen<n>` (with `4/5` / `4Or5` folded to `4/5`). Address, magic and
/// secondary-directory cells never contain `Zen`, so scanning the whole block
/// is safe.
fn zen_tokens(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let b = text.as_bytes();
    let mut i = 0;
    while let Some(pos) = text[i..].find("Zen") {
        let mut k = i + pos + 3;
        if k < b.len() && b[k] == b' ' {
            k += 1;
        }
        if k < b.len() && b[k].is_ascii_digit() {
            let mut tok = (b[k] as char).to_string();
            let rest = &text[k + 1..];
            if rest.starts_with("/5") || rest.starts_with("Or5") {
                tok.push_str("/5");
            }
            out.insert(tok);
        }
        i = k.min(text.len());
    }
    out
}

/// The exact Generation cell of a directory block: column 4 of its first body
/// line plus that column of every further line that has one (a multi-line
/// cell), `'\n'`-joined like upstream's accumulated `zen_generation`.
fn generation_cell(block: &str) -> String {
    let mut lines = Vec::new();
    for (i, line) in block.lines().enumerate() {
        let cell = line.split('|').nth(4).map(str::trim).unwrap_or_default();
        if i == 0 || !cell.is_empty() {
            lines.push(cell.to_string());
        }
    }
    lines.join("\n")
}

fn tokens_of(rendered: &str, addr: usize) -> BTreeSet<String> {
    let blocks = directory_blocks(rendered);
    let block = blocks
        .get(&(addr as u64))
        .unwrap_or_else(|| panic!("directory @{addr:#x} not rendered:\n{rendered}"));
    zen_tokens(block)
}

fn set(tokens: &[&str]) -> BTreeSet<String> {
    tokens.iter().map(|t| (*t).to_string()).collect()
}

/// CONTROL (passes today): a combo-reached `$PSP` carries the combo entry's
/// generation (`fet.py:117-123` → `directory.py:68`). Proves the fixture, the
/// block parser and the token extraction are sound.
#[test]
fn control_combo_reached_l1_carries_generation() {
    let out = render_synthetic(psp_chain(&[ZEN3_ID]));
    assert_eq!(
        tokens_of(&out, L1_OFF),
        set(&["3"]),
        "control: combo-reached $PSP must carry Zen 3\n{out}"
    );
}

/// D1: an L2 `$PL2` reached through a `0x40` pointer of a combo-reached `$PSP`
/// inherits the parent's generation (`directory.py:81-82` passes
/// `zen_generation` into the recursion; `:124` stores it). Upstream renders
/// `Zen 3 (PSP ID 0xbc0c0140)` for both; ours renders the `$PL2` cell blank.
///
/// Tracking: #116
#[test]
fn divergence_psp_l2_inherits_combo_generation() {
    let out = render_synthetic(psp_chain(&[ZEN3_ID]));
    let parent = tokens_of(&out, L1_OFF);
    let child = tokens_of(&out, L2_OFF);
    assert_eq!(
        child,
        set(&["3"]),
        "divergence #116: $PL2 @{L2_OFF:#x} must inherit its $PSP parent's \
         generation (parent tokens {parent:?}), directory.py:81-82; got {child:?}\n{out}"
    );
}

/// D1 (BIOS family): `2BHD` → `$BHD` → `0x70` → `$BL2`. Upstream stamps the
/// `$BL2` with the `$BHD`'s generation (`directory.py:81-82`); e.g.
/// `AORUS_X570_X57AOXT2.FCd` `$BL2` 0x950000 = `Zen 3 (PSP ID 0xbc0c0140)`.
///
/// Tracking: #116
#[test]
fn divergence_bios_l2_inherits_combo_generation() {
    let out = render_synthetic(bios_chain(ZEN3_ID));
    assert_eq!(
        tokens_of(&out, L1_OFF),
        set(&["3"]),
        "control within pin: combo-reached $BHD must carry Zen 3\n{out}"
    );
    let child = tokens_of(&out, L2_OFF);
    assert_eq!(
        child,
        set(&["3"]),
        "divergence #116: $BL2 @{L2_OFF:#x} must inherit the $BHD generation \
         (directory.py:81-82); got {child:?}\n{out}"
    );
}

/// D2: two combo entries — Zen 1 (`0xBC0A0000`) and Zen 2 (`0xBC0A0100`) —
/// point at the SAME `$PSP`. Upstream creates it with `Zen 1 (…)` and the
/// second visit appends `\nZen 2 (…)` (`directory.py:61-62`, `:243-246`), so
/// the Generation cell lists both. Ours keeps the first provenance only.
///
/// Tracking: #117
#[test]
fn divergence_shared_l1_accumulates_every_combo_generation() {
    let out = render_synthetic(psp_chain(&[ZEN1_ID, ZEN2_ID]));
    let got = tokens_of(&out, L1_OFF);
    assert_eq!(
        got,
        set(&["1", "2"]),
        "divergence #117: $PSP @{L1_OFF:#x} is pointed at by a Zen 1 and a Zen 2 \
         combo entry; upstream update_zen_generation (directory.py:243-246) lists \
         both; got {got:?}\n{out}"
    );
}

/// D2 cascade: the shared `$PSP`'s `$PL2` child receives the appended
/// generation too (`update_zen_generation` recurses into
/// `secondary_directory_offsets`, `directory.py:247-249`) — upstream renders
/// `Zen 1 (PSP ID 0xbc0a0000)\nZen 2 (PSP ID 0xbc0a0100)` for it, e.g.
/// `ASRock_B450_B45P4_3.31` `$PL2` 0x520000.
///
/// Tracking: #117
#[test]
fn divergence_shared_l1_generation_cascades_to_l2() {
    let out = render_synthetic(psp_chain(&[ZEN1_ID, ZEN2_ID]));
    let got = tokens_of(&out, L2_OFF);
    assert_eq!(
        got,
        set(&["1", "2"]),
        "divergence #117: $PL2 @{L2_OFF:#x} under a Zen 1 + Zen 2 $PSP must carry \
         both generations (directory.py:82, :247-249); got {got:?}\n{out}"
    );
}

/// Label format: upstream renders `get_possible_zen_generation(id[1:4])` +
/// `' (PSP ID ' + hex(id) + ')'` (`fet.py:117-123`); for `0xBC0C0140` that is
/// `Zen 3 (PSP ID 0xbc0c0140)` (`'Zen 3'` key, `directory.py:36`; Python
/// `hex()` is lower-case). Ours renders `Zen3`. #57 frames this as a future
/// upstream feature, but the pinned oracle `241629b` already prints it.
///
/// Tracking: #57
#[test]
fn divergence_generation_label_includes_psp_id() {
    let out = render_synthetic(psp_chain(&[ZEN3_ID]));
    let blocks = directory_blocks(&out);
    let block = &blocks[&(L1_OFF as u64)];
    let cells: Vec<&str> = block
        .lines()
        .next()
        .unwrap()
        .split('|')
        .map(str::trim)
        .collect();
    let expected = format!("Zen 3 (PSP ID {ZEN3_ID:#x})");
    assert_eq!(
        cells.get(4).copied(),
        Some(expected.as_str()),
        "divergence #57: Generation cell must be upstream's `{expected}` \
         (fet.py:117-123)\n{out}"
    );
}

/// A directory only a FET slot reaches has no generation: `fet.py:89` calls
/// `create_directories_if_not_exist(rom_addr, self)` without one, so
/// `zen_generation` keeps its `None` default (`directory.py:58`, stored at
/// `:124`) and its L2 child inherits that `None` (`:82`). `psptool.py:84`
/// hands it to PrettyTable, which prints `str(None)`: `None`.
///
/// Tracking: #122
#[test]
fn divergence_fet_only_directory_generation_is_none() {
    let out = render_synthetic(fet_direct_psp_chain());
    let blocks = directory_blocks(&out);
    for addr in [L1_OFF, L2_OFF] {
        let block = blocks
            .get(&(addr as u64))
            .unwrap_or_else(|| panic!("directory @{addr:#x} not rendered:\n{out}"));
        assert_eq!(
            generation_cell(block),
            "None",
            "divergence #122: directory @{addr:#x} is reached without a generation; \
             upstream prints str(None) (psptool.py:84)\n{out}"
        );
    }
}

// ---------------------------------------------------------------------------
// Corpus-gated differential against the live reference (PSPTOOL_REFERENCE)
// ---------------------------------------------------------------------------

/// Prints `{"<dir address>": str(zen_generation), …}` for every ROM — the
/// exact text PrettyTable renders in the Generation column (`psptool.py:84`).
const REFERENCE_SCRIPT: &str = r#"
import sys, json, io, contextlib
from psptool import PSPTool
with contextlib.redirect_stderr(io.StringIO()):
    pt = PSPTool.from_file(sys.argv[1])
out = {}
for rom in pt.blob.roms:
    for d in rom.directories:
        out.setdefault(str(d.get_address()), str(d.zen_generation))
print(json.dumps(out))
"#;

/// One corpus image: its file name, the reference's Generation cell text per
/// directory address and ours.
type CorpusGenerations = (String, BTreeMap<u64, String>, BTreeMap<u64, String>);

/// Both tools' Generation cells over the corpus, computed once for every
/// corpus pin; `None` when the corpus or the reference is not wired up.
fn corpus_generations() -> Option<&'static [CorpusGenerations]> {
    static CELLS: std::sync::OnceLock<Option<Vec<CorpusGenerations>>> = std::sync::OnceLock::new();
    CELLS
        .get_or_init(|| {
            let reference = std::env::var_os("PSPTOOL_REFERENCE").filter(|v| !v.is_empty())?;
            let reference = std::path::PathBuf::from(reference);
            let roms = psptool_fixtures::corpus_rom_paths();
            if roms.is_empty() {
                return None;
            }
            Some(
                roms.iter()
                    .map(|rom| {
                        (
                            rom.file_name().unwrap().to_string_lossy().into_owned(),
                            reference_generations(&reference, rom),
                            our_generations(rom),
                        )
                    })
                    .collect(),
            )
        })
        .as_deref()
}

fn reference_generations(
    reference: &std::path::Path,
    rom: &std::path::Path,
) -> BTreeMap<u64, String> {
    let out = std::process::Command::new(reference)
        .args(["-I", "-c", REFERENCE_SCRIPT])
        .arg(rom)
        .output()
        .expect("spawn reference python");
    assert!(
        out.status.success(),
        "reference failed on {}: {}",
        rom.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("reference JSON");
    v.as_object()
        .expect("object")
        .iter()
        .map(|(k, g)| {
            (
                k.parse::<u64>().expect("address"),
                g.as_str().expect("str(zen_generation)").to_string(),
            )
        })
        .collect()
}

fn our_generations(rom: &std::path::Path) -> BTreeMap<u64, String> {
    let blob = SourceBytes::from_blob(std::fs::read(rom).expect("read ROM"));
    let mut out = BTreeMap::new();
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
            sparse: false,
        };
        for (addr, block) in directory_blocks(&list_default(&listing)) {
            out.entry(addr).or_insert_with(|| generation_cell(&block));
        }
    }
    out
}

/// Compare every corpus directory whose upstream generation tokens satisfy
/// `select`, by `project` of both cells; returns the mismatch report lines.
fn corpus_generation_mismatches<T: PartialEq + std::fmt::Debug>(
    select: fn(&BTreeSet<String>) -> bool,
    project: fn(&str) -> T,
) -> Option<Vec<String>> {
    let mut bad = Vec::new();
    for (name, theirs, ours) in corpus_generations()? {
        for (addr, up) in theirs {
            if !select(&zen_tokens(up)) {
                continue;
            }
            // Directories only one tool surfaces are the differential's
            // business, not this pin's.
            let Some(mine) = ours.get(addr) else { continue };
            let (up, mine) = (project(up), project(mine));
            if mine != up {
                bad.push(format!(
                    "{name} dir {addr:#x}: reference {up:?}, ours {mine:?}"
                ));
            }
        }
    }
    Some(bad)
}

/// D1 corpus pin: every directory the reference labels with exactly one (or
/// no) generation must carry the same generation in our `ls`. Fails on the
/// L2 directories of 30+ corpus images (all inherit-only cases).
///
/// Tracking: #116
#[test]
fn divergence_corpus_single_generation_matches_reference() {
    let Some(bad) = corpus_generation_mismatches(|g| g.len() <= 1, zen_tokens) else {
        eprintln!("skipped: PSPTOOL_TEST_CORPUS / PSPTOOL_REFERENCE unset");
        return;
    };
    assert!(
        bad.is_empty(),
        "divergence #116: {} directories' Generation differs from the reference \
         (directory.py:81-82):\n{}",
        bad.len(),
        bad.join("\n")
    );
}

/// D2 corpus pin: every directory the reference labels with several
/// generations (accumulated by `update_zen_generation`) must list all of them.
///
/// Tracking: #117
#[test]
fn divergence_corpus_multi_generation_matches_reference() {
    let Some(bad) = corpus_generation_mismatches(|g| g.len() > 1, zen_tokens) else {
        eprintln!("skipped: PSPTOOL_TEST_CORPUS / PSPTOOL_REFERENCE unset");
        return;
    };
    assert!(
        bad.is_empty(),
        "divergence #117: {} multi-generation directories differ from the \
         reference (directory.py:61-62, 243-249):\n{}",
        bad.len(),
        bad.join("\n")
    );
}

/// Exact-text corpus pin: every directory's Generation cell is the reference's
/// `str(zen_generation)` (`psptool.py:84`) — label, PSP id, line order, and
/// `None` for the FET-only directories of most Zen 1/2 images (e.g.
/// `Tesla_zen-recovery.bin` `$PSP` 0x30000 / `$BHD` 0x152000).
///
/// Tracking: #122
#[test]
fn divergence_corpus_generation_cell_text_matches_reference() {
    let Some(bad) = corpus_generation_mismatches(|_| true, str::to_string) else {
        eprintln!("skipped: PSPTOOL_TEST_CORPUS / PSPTOOL_REFERENCE unset");
        return;
    };
    assert!(
        bad.is_empty(),
        "divergence #122: {} directories' Generation cell text differs from the \
         reference's str(zen_generation) (psptool.py:84):\n{}",
        bad.len(),
        bad.join("\n")
    );
}
