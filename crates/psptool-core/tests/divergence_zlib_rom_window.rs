//! ACToR critic divergence pin (#72): the #59 compressed-BIOS zlib-recovery
//! overrun check is bounded by the **whole input file**, not the **ROM window**
//! the containing `Rom` buffer defines. On a multi-ROM / capsule image (several
//! ROMs concatenated, or trailing envelope bytes) the two boundaries differ, and
//! a compressed entry whose declared (uncompressed) `size` overruns its ROM
//! window — but not the whole file — is sized DIFFERENTLY by the two tools.
//!
//! ## Upstream oracle (all sites Read this iteration)
//!
//! `psptool/file.py:297` (`File.__init__`):
//! ```python
//! elif parent_buffer.buffer_size >= entry.file_offset() + entry.size:
//!     super().__init__(parent_buffer, entry.size, buffer_offset=offset)   # normal path
//! else:
//!     if self.compressed:                                                 # zlib recovery
//!         zlib_hdr = zlib_find_header(self.blob[offset:])
//!         ...
//!         super().__init__(parent_buffer, zlib_hdr + zlib_size, ...)
//! ```
//! The recovery trigger is overrun of `parent_buffer.buffer_size` — the size of
//! the **containing ROM window** (`parent_buffer` is the `Rom`) — evaluated in
//! ROM-relative space (`entry.file_offset()` is ROM-relative; see
//! `entry.py:38-70`, mode 1 → `self.offset`). It is NOT the whole-file length.
//!
//! ## Target divergence
//!
//! `crates/psptool-core/src/entry.rs::resolve_body`:
//! ```rust
//! let blob_end = blob_start.saturating_add(blob.len() as u64);   // entry.rs:517 — WHOLE FILE
//! let body_end = body_offset.get().saturating_add(size);
//! let body_len = if body_end > blob_end {                        // entry.rs:537 — wrong bound
//!     ... zlib recovery ...
//! } else {
//!     entry_size as usize                                        // normal path
//! };
//! ```
//! `blob` is the entire input image (passed whole from `load.rs`/`list.rs`), so
//! `blob_end` is the whole-file end. `rom_size` / `rom_origin` are parameters of
//! `resolve_body` (`entry.rs:500-501`) — the correct bound
//! `rom_origin + rom_size` (the ROM window end) is IN SCOPE but UNUSED at the
//! `:537` check; they feed only the `ResolveContext` body-offset arithmetic.
//!
//! ## The construction
//!
//! Two fixtures identical in every entry/directory byte, differing ONLY in how
//! much data trails the ROM (and the `rom_size` argument):
//!
//! * `control_rom_window_equals_blob_recovers` — single 8 MiB ROM, `blob` == ROM
//!   window. `body_end > blob_end` == `body_end > rom_window_end`, so BOTH tools
//!   take the zlib-recovery path. Passes today (proves the fixture machinery is
//!   sound: the compressed body IS recoverable to `zlib_hdr + zlib_size`).
//!
//! * `divergence_rom_window_smaller_than_blob` — the SAME 8 MiB ROM with a
//!   second 8 MiB ROM concatenated after it (16 MiB blob; the #41 multi-ROM
//!   family). `rom_size` stays 8 MiB. Now the entry's compressed body overruns
//!   the 8 MiB ROM window but NOT the 16 MiB whole file. Upstream still recovers
//!   from the zlib header (ROM window unchanged); our `resolve_body` takes the
//!   NORMAL path (`body_end <= blob_end`) and hands back the raw uncompressed
//!   `size` bytes, spilling across the ROM boundary into ROM#1's data. Divergent
//!   body length → divergent `ls` size → parity broken.
//!
//! The expected body length is a symbolic constant of the fixture
//! (`ZLIB_HDR_POS + ZLIB_SIZE`), derived from the upstream sizing rule
//! `file.py:303-311` — never copied from our parser's output (R-CHAR-3).
//!
//! Tracking: #72

use psptool_core::{Directory, Entry, FlashOffset, ParseError, RomSize, SourceBytes};

const DIR_HDR: usize = 0x10; // directory header size
const BIOS_ENTRY: usize = 0x18; // 24-byte BiosDirectoryEntry

// ROM window is 8 MiB. The body sits near the top so `offset + size` overruns it.
const ROM_WINDOW: usize = 0x80_0000; // RomSize::MIB_8
const BODY_OFF: usize = 0x7F_F000; // flash offset of the entry body (mode 1), ROM-relative

// Record fields, mirroring the empirical AM5 $BL2 compressed-BIOS shape used by
// the #59 pin, chosen so `BODY_OFF + UNCOMPRESSED_SIZE` overruns the 8 MiB ROM
// window but fits inside a 16 MiB two-ROM blob.
const UNCOMPRESSED_SIZE: u32 = 0x0050_0020; // record `size` (uncompressed) — overruns ROM window
const ENTRY_RSV0: u32 = 0x4000_0000; // rsv0>>30 = 1 → FlashOffset (mode 1)
const DEST: u64 = 0x09af_ffe0;
// v2 header, dir mode bits → DirectoryRelative, deferring to entry-level FlashOffset.
const ADDITIONAL_INFO: u32 = 0x4000_0440;

// Compressed-body layout (upstream `file.py:303-311` + `utils.zlib_find_header`).
const ZLIB_HDR_POS: usize = 0x100; // zlib magic sits at body[0x100]
const ZLIB_SIZE: u32 = 0x40; // le_u32 at body[0x14..0x18]
/// Upstream-correct on-flash body length = `zlib_hdr + zlib_size` (`file.py:310`).
const EXPECTED_BODY_LEN: usize = ZLIB_HDR_POS + ZLIB_SIZE as usize;

// Two-ROM blob: ROM#0 = [0, 8 MiB), ROM#1 = [8 MiB, 16 MiB). Body at BODY_OFF in
// ROM#0 spills into ROM#1's bytes.
const TWO_ROM_BLOB: usize = 0x100_0000; // 16 MiB

// Sanity of the construction: body overruns the ROM window but fits the 16 MiB blob.
const _: () = {
    assert!(BODY_OFF + (UNCOMPRESSED_SIZE as usize) > ROM_WINDOW); // overruns ROM window
    assert!(BODY_OFF + (UNCOMPRESSED_SIZE as usize) < TWO_ROM_BLOB); // fits whole file
};

/// Build a `total_len`-byte blob holding one `$BL2` directory (at offset 0) with
/// a single compressed BIOS entry whose body sits near the top of ROM#0.
fn build(total_len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; total_len];

    // --- $BL2 directory header (16 bytes) ---
    buf[0..4].copy_from_slice(b"$BL2");
    buf[4..8].copy_from_slice(&0u32.to_le_bytes()); // checksum (not verified here)
    buf[8..12].copy_from_slice(&1u32.to_le_bytes()); // count = 1
    buf[12..16].copy_from_slice(&ADDITIONAL_INFO.to_le_bytes());

    // --- one BiosDirectoryEntry (24 bytes) at 0x10 ---
    let e = DIR_HDR;
    debug_assert_eq!(BIOS_ENTRY, 0x18);
    buf[e] = 0x62; // type = BIOS
    buf[e + 1] = 0; // region_type
    let flags: u16 = 0x0008; // bit3 = compressed
    buf[e + 2..e + 4].copy_from_slice(&flags.to_le_bytes());
    buf[e + 4..e + 8].copy_from_slice(&UNCOMPRESSED_SIZE.to_le_bytes());
    buf[e + 8..e + 12].copy_from_slice(&(BODY_OFF as u32).to_le_bytes()); // offset (mode 1)
    buf[e + 12..e + 16].copy_from_slice(&ENTRY_RSV0.to_le_bytes());
    buf[e + 16..e + 24].copy_from_slice(&DEST.to_le_bytes());

    // --- compressed body @ BODY_OFF: 0x100-byte header + zlib stream ---
    // header[0x14:0x18] = compressed size; zlib magic at +0x100.
    buf[BODY_OFF + 0x14..BODY_OFF + 0x18].copy_from_slice(&ZLIB_SIZE.to_le_bytes());
    buf[BODY_OFF + ZLIB_HDR_POS] = 0x78; // zlib magic
    buf[BODY_OFF + ZLIB_HDR_POS + 1] = 0xDA;

    buf
}

fn parse_first_bios(buf: Vec<u8>, rom_size: RomSize) -> Result<Entry, ParseError> {
    let blob = SourceBytes::from_blob(buf);
    let dir = match Directory::parse_at(&blob, FlashOffset(0)).expect("directory parses") {
        Directory::Bios(b) => b,
        other => panic!("expected $BL2 BIOS directory, got {other:?}"),
    };
    Entry::parse_bios(&blob, &dir, 0, rom_size, FlashOffset::ZERO)
}

/// Control (fixture soundness + coincidence case): when the ROM window equals the
/// whole blob (single 8 MiB ROM), the whole-file bound and the ROM-window bound
/// COINCIDE, so both upstream and our parser take the zlib-recovery path and
/// size the body to `zlib_hdr + zlib_size`. Passes today — this proves the body
/// IS recoverable and isolates the multi-ROM window as the sole discriminator.
#[test]
fn control_rom_window_equals_blob_recovers() {
    let entry =
        parse_first_bios(build(ROM_WINDOW), RomSize::MIB_8).expect("single-ROM overrun recovers");
    assert_eq!(
        entry.get_bytes().offset(),
        FlashOffset(BODY_OFF as u64),
        "resolved body address must be the mode-1 flash offset"
    );
    assert_eq!(
        entry.get_bytes().len(),
        EXPECTED_BODY_LEN,
        "single-ROM: whole-file bound == ROM-window bound, so both recover to \
         zlib_hdr + zlib_size (0x{EXPECTED_BODY_LEN:x})"
    );
}

/// Divergence pin (#72): the SAME entry, but with a second 8 MiB ROM concatenated
/// after ROM#0 (16 MiB two-ROM blob). `rom_size` is still 8 MiB, so the ROM
/// window is unchanged — upstream's recovery trigger
/// (`parent_buffer.buffer_size >= file_offset + size`, `file.py:297`) still
/// fires and sizes the body to `zlib_hdr + zlib_size = 0x{EXPECTED_BODY_LEN:x}`.
///
/// Our `resolve_body` bounds the overrun against the WHOLE FILE
/// (`body_end > blob_end`, `entry.rs:537`, `blob_end = blob_start + blob.len()`
/// at `entry.rs:517`). With a 16 MiB blob the compressed body no longer overruns
/// `blob_end`, so we take the NORMAL path and return the raw uncompressed
/// `size = 0x{UNCOMPRESSED_SIZE:x}` bytes — spilling across the ROM boundary into
/// ROM#1's data. `rom_size`/`rom_origin` (params at `entry.rs:500-501`) carry the
/// correct bound `rom_origin + rom_size` but are unused at the `:537` check.
///
/// Expected body length is derived from the upstream ROM-window recovery rule
/// (`file.py:303-311`), NOT from our parser (R-CHAR-3).
///
/// Tracking: #72
#[test]
#[ignore = "divergence: zlib-recovery overrun uses whole-file blob_end, not the ROM window rom_origin+rom_size; tracking #72"]
fn divergence_rom_window_smaller_than_blob() {
    let entry = parse_first_bios(build(TWO_ROM_BLOB), RomSize::MIB_8).unwrap_or_else(|e| {
        panic!(
            "divergence #72: compressed entry overrunning the 8 MiB ROM window was \
             rejected with {e:?}; upstream (file.py:297,303-311) recovers it to \
             0x{EXPECTED_BODY_LEN:x} bytes because the ROM window — not the 16 MiB \
             whole file — is the recovery boundary."
        )
    });

    // Address arithmetic is already correct — proves the divergence is purely the
    // body SIZE / boundary, not the address mode.
    assert_eq!(
        entry.get_bytes().offset(),
        FlashOffset(BODY_OFF as u64),
        "resolved body address must be the mode-1 flash offset"
    );

    // The pin: upstream bounds the overrun by the ROM window (8 MiB), so the
    // compressed body is recovered to zlib_hdr + zlib_size. We bound by the whole
    // 16 MiB file and return the raw uncompressed size instead.
    assert_eq!(
        entry.get_bytes().len(),
        EXPECTED_BODY_LEN,
        "compressed body overrunning the ROM window must be sized to \
         zlib_hdr + zlib_size (0x{EXPECTED_BODY_LEN:x}) per file.py:297,303-311; \
         got the raw uncompressed record size instead because the overrun check \
         uses the whole-file blob_end (entry.rs:537) rather than rom_origin+rom_size"
    );
}
