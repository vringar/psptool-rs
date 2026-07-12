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
//! Rust side). The #86 (`flags`) and #87 (`MD5`) pins now render upstream-exact
//! in SPARSE mode ([`RomListing::sparse`]) — they invoke the renderer with
//! `sparse=true` and are live `#[test]`s (per goal.md R-DEFER-3, un-ignored
//! when the fix landed). `default_mode_flags_populated_and_md5_full_lowercase`
//! pins that the richer rendering remains the default (`sparse=false`).

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
///
/// `sparse` selects the upstream-exact `flags`/`MD5` rendering
/// ([`RomListing::sparse`]); `false` is the richer default.
fn verbose_entry_cells(sparse: bool) -> std::collections::HashMap<String, String> {
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
        sparse,
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
    // Subprogram/Instance are basic columns, unaffected by sparse mode.
    let cells = verbose_entry_cells(false);
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
/// `flags` column is therefore always empty; the richer default shows `"0x0"`.
/// SPARSE mode ([`RomListing::sparse`]) reproduces the upstream `''`.
/// Tracking: #86 (fixed — pin now live in sparse mode)
#[test]
fn divergence_verbose_flags_column_is_empty_upstream() {
    let cells = verbose_entry_cells(true);
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
/// cell is exactly 4 characters and all-uppercase; the richer default produces
/// 32 lowercase characters. SPARSE mode ([`RomListing::sparse`]) reproduces the
/// upstream 4-char uppercase cell.
/// Tracking: #87 (fixed — pin now live in sparse mode)
#[test]
fn divergence_verbose_md5_column_truncated_and_uppercased() {
    let cells = verbose_entry_cells(true);
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

/// The DEFAULT (non-sparse) rendering keeps the richer PSPTool-rs columns: a
/// populated `flags` cell (`format_hex_u64`) and the full 32-char lowercase
/// `MD5`. This pins that `sparse=false` is the default and does NOT narrow the
/// two cells — the opt-in sparse mode above is strictly additive.
#[test]
fn default_mode_flags_populated_and_md5_full_lowercase() {
    let cells = verbose_entry_cells(false);

    // Richer default: `flags` is `hex(flags)`; this fixture's entry flags are 0
    // → "0x0" (populated, not the upstream empty string).
    assert_eq!(
        cells.get("flags").map(String::as_str),
        Some("0x0"),
        "default flags column must be populated (hex(flags)); sparse mode empties it"
    );

    // Richer default: full 32-char lowercase MD5 digest (not md5()[:4].upper()).
    let md5 = cells
        .get("MD5")
        .expect("verbose table has an MD5 column")
        .clone();
    assert_eq!(
        md5.len(),
        32,
        "default MD5 column must be the full 32-char digest, got {md5:?}"
    );
    assert_eq!(
        md5,
        md5.to_lowercase(),
        "default MD5 column must be lowercase, got {md5:?}"
    );
}
