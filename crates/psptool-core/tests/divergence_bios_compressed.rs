//! ACToR critic divergence pin for compressed BIOS ($BHD/$BL2) entries whose
//! directory-record `size` (the *uncompressed* size) overruns the ROM window
//! (crosslink #59; broadens the #52 "entry address-mode" report — see below).
//!
//! ## What #52 actually is, per the upstream oracle
//!
//! #52 filed this as an *address-mode* bug. Running the reference PSPTool
//! (`PSPTOOL_REFERENCE`) against the live corpus image
//! `ASRock_B650_PG_Lightning_1.14.AS06[Beta].bin` shows otherwise. For its
//! `$BL2 @0x2ed000` entry 4:
//!
//! ```text
//!   raw record: type=0x62 flags=0x000b(bit3=compressed) size=0x500020
//!               offset=0x01e02000 rsv0=0x40000000 dest=0x9afffe0
//!   reference (python -m psptool -E -j):  address=0x1e02000  size=0x8ab51  BIOS~0x62
//!   ours       (psptool -E -j):           {"error":"truncated entry body at
//!                0x01e02000: expected 5242912 bytes, only 2088960 available"}
//! ```
//!
//! The resolved *address* (`0x1e02000`) is IDENTICAL in both tools — the
//! address-mode arithmetic (entry `rsv0>>30 = 1` → FlashOffset) is already
//! correct. The divergence is the *body size*: the directory record's
//! `size = 0x500020` is the **uncompressed** size, and using it as the
//! on-flash body length overruns the 32 MiB ROM. Upstream detects the overrun,
//! sees the compressed flag, and re-sizes the body from the zlib header
//! (`file.py:293-311`, `utils.zlib_find_header`): body length =
//! `zlib_hdr_pos + le_u32(blob[offset+0x14 .. offset+0x18])` = `0x100 + 0x8aa51
//! = 0x8ab51`, which fits. We instead treat `size` literally and return
//! `ParseError::Truncated`, DROPPING the entry (`entry.rs::resolve_body`,
//! the `body_end > blob_end` guard).
//!
//! Upstream contract (all cited sites Read this iteration):
//! * `entry.py:38-70`  `file_offset()` — mode selection; mode 1 → `self.offset`.
//! * `file.py:293-319` — when `parent_buffer.buffer_size < file_offset + size`
//!   AND the entry is compressed, size the File from the zlib header rather
//!   than raising `Entry size exceed parent buffer bounds`.
//! * `file.py:303-311` — `zlib_hdr = zlib_find_header(blob[offset:])`,
//!   `zlib_size = le_u32(blob[offset+0x14:+4])`, body = `zlib_hdr + zlib_size`.
//! * `utils.py:209-234` — `ZLIB_TYPES` (magic `78 da / 78 9c / 78 5e / 78 01`),
//!   `zlib_find_header` returns `0x100` when the magic sits at `blob[offset+0x100]`.
//!
//! The expected body length below is a symbolic constant of the fixture
//! (`ZLIB_HDR_POS + ZLIB_SIZE`), derived from the upstream sizing rule — never
//! copied from our parser's output (R-CHAR-3).
//!
//! Tracking: #59 (root cause of the #52 AM5 BIOS manifestation).

use psptool_core::{Directory, Entry, FlashOffset, ParseError, RomSize, SourceBytes};

const DIR_HDR: usize = 0x10; // directory header size
const BIOS_ENTRY: usize = 0x18; // 24-byte BiosDirectoryEntry

// 8 MiB ROM; body sits near the top so `offset + uncompressed_size` overruns it.
const ROM_BYTES: usize = 0x80_0000; // RomSize::MIB_8
const BODY_OFF: usize = 0x7F_F000; // flash offset of the entry body (mode 1)

// Directory record fields, mirroring the empirical B650 $BL2 entry 4 shape.
const UNCOMPRESSED_SIZE: u32 = 0x0050_0020; // record `size` — overruns the ROM
const ENTRY_RSV0: u32 = 0x4000_0000; // rsv0>>30 = 1 → FlashOffset
const DEST: u64 = 0x09af_ffe0;
// additional_info 0x40000440: v2 (bit31=0), mode bits[30:29]=10 → DirectoryRelative,
// which defers to the entry-level rsv0 mode (== FlashOffset). Matches the image.
const ADDITIONAL_INFO: u32 = 0x4000_0440;

// Compressed-body layout (upstream `file.py:303-311` + `utils.zlib_find_header`).
const ZLIB_HDR_POS: usize = 0x100; // zlib magic sits at body[0x100]
const ZLIB_SIZE: u32 = 0x40; // le_u32 at body[0x14..0x18]
/// Upstream-correct on-flash body length = `zlib_hdr + zlib_size`.
const EXPECTED_BODY_LEN: usize = ZLIB_HDR_POS + ZLIB_SIZE as usize;

/// Build an 8 MiB blob holding a single `$BL2` directory (at offset 0) with one
/// BIOS entry, plus the entry's compressed body near the top of the ROM.
///
/// `compressed` toggles the flags bit-3; `body_size` is written into the record
/// `size` field. Everything else mirrors the on-disk B650 record.
fn build(compressed: bool, body_size: u32) -> Vec<u8> {
    let mut buf = vec![0u8; ROM_BYTES];

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
    let flags: u16 = if compressed { 0x0008 } else { 0x0000 }; // bit3 = compressed
    buf[e + 2..e + 4].copy_from_slice(&flags.to_le_bytes());
    buf[e + 4..e + 8].copy_from_slice(&body_size.to_le_bytes());
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

fn parse_first_bios(buf: Vec<u8>) -> Result<Entry, ParseError> {
    let blob = SourceBytes::from_blob(buf);
    let dir = match Directory::parse_at(&blob, FlashOffset(0)).expect("directory parses") {
        Directory::Bios(b) => b,
        other => panic!("expected $BL2 BIOS directory, got {other:?}"),
    };
    Entry::parse_bios(&blob, &dir, 0, RomSize::MIB_8, FlashOffset::ZERO)
}

/// Control 1 (fixture soundness): a compressed BIOS entry whose record `size`
/// stays *within* the ROM parses fine today — so the fixture builder and the
/// `parse_bios` path are sound, and the failure below is specifically the
/// oversize-compressed handling.
#[test]
fn control_compressed_in_bounds_parses() {
    // body_size within bounds: BODY_OFF + size <= ROM_BYTES.
    let in_bounds = (ROM_BYTES - BODY_OFF) as u32; // 0x1000
    let entry = parse_first_bios(build(true, in_bounds)).expect("in-bounds entry parses");
    assert_eq!(entry.entry_type().0, 0x62);
    // Body starts at the mode-1 flash offset (address arithmetic already correct).
    assert_eq!(entry.get_bytes().offset(), FlashOffset(BODY_OFF as u64));
}

/// Control 2 (isolates compression as the discriminator): a NON-compressed
/// entry with the same oversize `size` is rejected by BOTH tools — upstream
/// raises "Entry size exceed parent buffer bounds" (`file.py:317`) and we
/// return `Truncated`. So our bounds check is CORRECT for the non-compressed
/// case; the divergence is specifically the compressed path.
#[test]
fn control_uncompressed_oversize_is_rejected_by_both() {
    let err = parse_first_bios(build(false, UNCOMPRESSED_SIZE))
        .expect_err("uncompressed oversize must be rejected (matches upstream drop)");
    assert!(
        matches!(
            err,
            ParseError::Truncated {
                what: "entry body",
                ..
            }
        ),
        "expected Truncated for uncompressed oversize, got {err:?}"
    );
}

/// Divergence pin (#59): a COMPRESSED BIOS entry whose record `size`
/// (0x500020, the uncompressed size) overruns the ROM must be sized from its
/// zlib header (`0x100 + le_u32@+0x14 = 0x140`), NOT dropped.
///
/// Reference PSPTool parses B650 `$BL2 @0x2ed000` entry 4 as
/// `address=0x1e02000 size=0x8ab51` via exactly this path
/// (`file.py:303-311`). Our `resolve_body` returns
/// `ParseError::Truncated` because it uses the record `size` literally and the
/// `body_end > blob_end` guard fires — dropping the BIOS body.
///
/// This test is now active (R-DEFER-3): `resolve_body` sizes compressed
/// over-ROM entries from the zlib header, so #59 is fixed.
///
/// Tracking: #59
#[test]
fn divergence_compressed_oversize_bios_entry_sized_from_zlib_header() {
    let result = parse_first_bios(build(true, UNCOMPRESSED_SIZE));

    // The pin: upstream does NOT error here — it re-sizes from the zlib header.
    let entry = result.unwrap_or_else(|e| {
        panic!(
            "divergence #59: compressed oversize BIOS entry was dropped with {e:?}; \
             upstream (file.py:303-311) sizes it from the zlib header to \
             0x{EXPECTED_BODY_LEN:x} bytes and keeps it. \
             (Reference parses B650 $BL2@0x2ed000 e4 as address=0x1e02000 size=0x8ab51.)"
        )
    });

    // Address arithmetic is already correct — assert it to prove the divergence
    // is purely the body SIZE, not the mode.
    assert_eq!(
        entry.get_bytes().offset(),
        FlashOffset(BODY_OFF as u64),
        "resolved body address must be the mode-1 flash offset"
    );
    // Body length must be the upstream zlib-derived length, not the record size.
    assert_eq!(
        entry.get_bytes().len(),
        EXPECTED_BODY_LEN,
        "compressed body must be sized to zlib_hdr + zlib_size (0x{EXPECTED_BODY_LEN:x}), \
         not the uncompressed record size 0x{UNCOMPRESSED_SIZE:x}"
    );
}
