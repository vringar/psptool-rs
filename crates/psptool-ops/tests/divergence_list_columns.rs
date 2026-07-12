//! Adversarial divergence pins for the `ls` (text) column rendering of
//! [`psptool_ops::list_verbose`] / [`list_default`].
//!
//! The differential oracle (`psptool-cli/tests/differential.rs`) only reads
//! the JSON structural keys `index`/`address`/`size`/`sectionType`; it never
//! reads the *text* table's `Subprogram`, `Instance`, `flags`, or `MD5`
//! columns. Those columns are pinned only by the Rust-to-Rust `list_micro`
//! insta snapshot, which froze the current (divergent) values rather than
//! comparing them to upstream `PSPTool.ls_files` (`psptool.py:98-200`).
//!
//! Each test below asserts the value upstream `ls_files` *actually* renders,
//! derived from a quoted upstream `psptool.py` line (never copied from the
//! Rust side). They FAIL against the current `list.rs` renderer and are
//! `#[ignore]`d pending the tracked fix — per goal.md R-DEFER-3 they move to
//! `#[test]` when the fix lands.

use psptool_core::{Fet, FlashOffset, RomSize, SourceBytes, walk_directories};
use psptool_fixtures::micro;
use psptool_ops::{RomListing, list_verbose};

const ROM_SIZE_BYTES: u64 = 0x100_0000; // 16 MiB

/// Same synthetic PSP blob the `list_micro` snapshot suite uses: an FET at
/// flash offset 0x20000 pointing at one PSP directory at 0xA7000. The single
/// entry is `WRAPPED_IKEK~0x21` with `subprogram == 0` and `instance == 0`.
fn build_psp_blob() -> Vec<u8> {
    use psptool_core::fet::{FET_MAGIC_SIZE, FET_SLOT_SIZE, FET_TERMINATOR_SIZE};
    use psptool_core::magic::FET_MAGIC;

    let mut buf = vec![0u8; ROM_SIZE_BYTES as usize];

    let fet_off = 0x20_000usize;
    buf[fet_off..fet_off + FET_MAGIC_SIZE].copy_from_slice(FET_MAGIC.as_bytes());
    buf[fet_off + FET_MAGIC_SIZE..fet_off + FET_MAGIC_SIZE + FET_SLOT_SIZE]
        .copy_from_slice(&0x000A_7000u32.to_le_bytes());
    let term_off = fet_off + FET_MAGIC_SIZE + FET_SLOT_SIZE;
    buf[term_off..term_off + FET_TERMINATOR_SIZE].copy_from_slice(&[0xFF; FET_TERMINATOR_SIZE]);

    let dir_off = 0xA_7000usize;
    let dir_bytes = micro::psp_directory();
    buf[dir_off..dir_off + dir_bytes.len()].copy_from_slice(dir_bytes);

    buf
}

/// Render `list_verbose` over the PSP micro-fixture and return the cells of
/// the entry data row keyed by column header (both the header row and the
/// data row are split on `|` identically by PrettyTable-style layout).
fn verbose_entry_cells() -> std::collections::HashMap<String, String> {
    let buf = build_psp_blob();
    let blob = SourceBytes::from_blob(buf);
    let fet = Fet::parse_at(&blob, FlashOffset(0x20_000)).expect("parse FET");
    let dirs = walk_directories(&blob, &fet, RomSize::MIB_16, FlashOffset::ZERO);
    let rom = RomListing {
        index: 0,
        blob: &blob,
        rom_size: RomSize::MIB_16,
        rom_origin: FlashOffset::ZERO,
        fet: &fet,
        directories: &dirs,
    };
    let table = list_verbose(&rom);

    let split =
        |line: &str| -> Vec<String> { line.split('|').map(|c| c.trim().to_string()).collect() };

    let header = table
        .lines()
        .find(|l| l.contains("Subprogram"))
        .expect("entry table has a Subprogram header");
    let data = table
        .lines()
        .find(|l| l.contains("WRAPPED_IKEK"))
        .expect("entry table has the WRAPPED_IKEK data row");

    let headers = split(header);
    let cells = split(data);
    assert_eq!(
        headers.len(),
        cells.len(),
        "header and data row must have identical column count"
    );

    headers.into_iter().zip(cells).collect()
}

/// Divergence: `list.rs` renders the `Subprogram` / `Instance` columns as
/// DECIMAL (`u8::to_string`, `list.rs:249`/`:250`) but upstream renders them
/// as HEX.
///
/// Upstream `psptool.py:174` — `hex(file.entry.subprogram)`
/// Upstream `psptool.py:175` — `hex(file.entry.instance)`
/// For this fixture both bytes are 0, so upstream renders `"0x0"`; `list.rs`
/// renders `"0"`.
/// Tracking: #85 (fixed — pin now live)
#[test]
fn divergence_subprogram_instance_rendered_decimal_not_hex() {
    let cells = verbose_entry_cells();
    // Upstream `hex(0)` == "0x0" (psptool.py:174/:175).
    assert_eq!(
        cells.get("Subprogram").map(String::as_str),
        Some("0x0"),
        "Subprogram column must render hex(subprogram) per psptool.py:174"
    );
    assert_eq!(
        cells.get("Instance").map(String::as_str),
        Some("0x0"),
        "Instance column must render hex(instance) per psptool.py:175"
    );
}

/// Divergence: `list.rs` fills the verbose `flags` column with
/// `format_hex_u64(flags)` (`list.rs:270`) but upstream renders it as an
/// EMPTY string.
///
/// Upstream `psptool.py:179` — the `flags` slot of `all_values` is the literal
/// `''` (the `hex(file.entry.flags)` form is commented out). Upstream's
/// `flags` column is therefore always empty; `list.rs` shows `"0x0"`.
/// Tracking: #86
#[test]
#[ignore = "divergence: verbose flags column populated, upstream renders '' (psptool.py:179); tracking #86"]
fn divergence_verbose_flags_column_is_empty_upstream() {
    let cells = verbose_entry_cells();
    assert_eq!(
        cells.get("flags").map(String::as_str),
        Some(""),
        "flags column must be empty per psptool.py:179 (value is a literal '')"
    );
}

/// Divergence: `list.rs` renders the verbose `MD5` column as the FULL 32-char
/// lowercase digest (`body_md5_hex`, `list.rs:271`/`:514`) but upstream
/// renders only the first 4 hex chars, UPPERCASED.
///
/// Upstream `psptool.py:180` — `file.md5()[:4].upper()`. So upstream's MD5
/// cell is exactly 4 characters and all-uppercase; `list.rs` produces 32
/// lowercase characters.
/// Tracking: #87
#[test]
#[ignore = "divergence: verbose MD5 column full-32-lowercase, upstream md5()[:4].upper() (psptool.py:180); tracking #87"]
fn divergence_verbose_md5_column_truncated_and_uppercased() {
    let cells = verbose_entry_cells();
    let md5 = cells
        .get("MD5")
        .expect("verbose table has an MD5 column")
        .clone();
    // Upstream `md5()[:4]` — exactly 4 hex chars (psptool.py:180).
    assert_eq!(
        md5.len(),
        4,
        "MD5 column must be truncated to 4 chars per psptool.py:180 `md5()[:4]`, got {md5:?}"
    );
    // Upstream `.upper()` — all-uppercase (psptool.py:180).
    assert_eq!(
        md5,
        md5.to_uppercase(),
        "MD5 column must be uppercased per psptool.py:180 `.upper()`, got {md5:?}"
    );
}
