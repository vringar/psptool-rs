//! Divergence pins for `psptool-core/src/body.rs` body-region bounds vs the
//! reference PSPTool (`/tmp/psptool-ref/psptool`).
//!
//! Two independent divergences from upstream's *observable* body semantics are
//! pinned here. Both expected values are derived from upstream's own logic
//! (`header_file.py` / `utils.py`, cited per test), NOT copied from the target
//! side (R-CHAR-3). Both are `#[ignore]`d with their tracking blocker; per
//! R-DEFER-3 the fixer flips them to plain `#[test]` when the fix lands.

use psptool_core::body::Ikek;
use psptool_core::{BodyError, HeaderEntry, SourceBytes};

const HEADER_FILE_LEN: usize = 0x100;

/// Divergence: `HeaderEntry::data_region` (`body.rs:190`) subtracts
/// `signature_len()` unconditionally, ignoring `is_signed`. Upstream only
/// reserves signature bytes when the file is signed:
///
///   `header_file.py:77-84`:
///     ```
///     if self.is_signed:
///         if self.signature_type == 0x0: self.signature_len = 0x100
///         elif self.signature_type == 0x2: self.signature_len = 0x200
///         ...
///     else:
///         self.signature_len = 0
///     ```
///   `header_file.py:100`:
///     `self.body = NestedBuffer(self, len(self) - len(self.header)
///                               - self.signature_len, len(self.header))`
///
/// For an UNSIGNED HeaderFile (`signed_raw == 0`) upstream's data region is
/// `body[0x100 : rom_size]` (signature_len == 0); the target instead returns
/// `body[0x100 : rom_size - signature_len(signature_type)]`, dropping the last
/// `signature_len` bytes of a valid unsigned entry.
///
/// Reachable in production: `psptool-ops/src/extract.rs:59`
/// (`header.data_region(entry.body.as_bytes())`) is called for every
/// extracted HeaderFile, signed or not.
///
/// Tracking: #81 (fixed — pin now live)
#[test]
fn data_region_of_unsigned_headerfile_keeps_full_body() {
    // Unsigned HeaderFile: signed_raw (0x30) == 0, signature_type (0x34) == 0,
    // rom_size (0x6c) == 0x300 (header 0x100 + 0x200 data, NO signature).
    let mut h = [0u8; HEADER_FILE_LEN];
    h[0x10..0x14].copy_from_slice(b"$PS1");
    // 0x30 (is_signed) left zero => unsigned.
    h[0x34..0x38].copy_from_slice(&0u32.to_le_bytes()); // signature_type == 0
    h[0x6C..0x70].copy_from_slice(&0x300u32.to_le_bytes()); // rom_size

    let mut blob = Vec::new();
    blob.extend_from_slice(&h);
    blob.extend(std::iter::repeat_n(0xAAu8, 0x100)); // first half of data region
    blob.extend(std::iter::repeat_n(0xBBu8, 0x100)); // second half (upstream keeps this)

    let src = SourceBytes::from_blob(blob);
    let entry = HeaderEntry::parse(&src).expect("header parses");
    assert!(
        !entry.is_signed(),
        "fixture must be unsigned to exercise the bug"
    );

    // Upstream (header_file.py:83-84,100): signature_len == 0 for unsigned files,
    // so the data region is the ENTIRE post-header region: rom_size - 0x100 = 0x200.
    let dr = entry
        .data_region(src.as_bytes())
        .expect("upstream returns the full unsigned data region");
    assert_eq!(
        dr.len(),
        0x200,
        "unsigned data region must be rom_size - 0x100 (0x200), not \
         rom_size - 0x100 - signature_len"
    );
    // The trailing 0x100 bytes (0xBB) belong to the data region upstream, and
    // the target wrongly discards them.
    assert!(
        dr[0x100..0x200].iter().all(|&b| b == 0xBB),
        "trailing data-region bytes must be preserved for an unsigned file"
    );
}

/// Divergence: `HeaderEntry::signature_bytes` (`body.rs:222`) calls
/// `signature_len()` **unconditionally**, without consulting `is_signed()`.
/// This is the exact sibling of the #81 defect that was fixed in
/// `data_region` (`body.rs:200`, which now gates `sig_len` on `is_signed()`),
/// but left un-fixed here.
///
/// Upstream only materializes a signature for a signed file, and gives an
/// unsigned file `signature_len == 0`:
///
///   `header_file.py:77-84`:
///     ```
///     if self.is_signed:
///         if self.signature_type == 0x0: self.signature_len = 0x100
///         elif self.signature_type == 0x2: self.signature_len = 0x200
///         self.signature = NestedBuffer(self, self.signature_len,
///                                       self.rom_size - self.signature_len)
///     else:
///         self.signature_len = 0        # and self.signature is never created
///     ```
///   `header_file.py:181` (the only site that materializes a signature value):
///     `signature = self.signature.get_bytes() if self.is_signed else b''`
///
/// So for an UNSIGNED HeaderFile the observable trailing signature is **empty**
/// (`b''`, `signature_len == 0`). The target instead returns the last
/// `signature_len(signature_type)` bytes of the (rom-size-bounded) body — for
/// `signature_type == 0` that is the last `0x100` bytes.
///
/// Worse, this now contradicts the #81 `data_region` fix on the *same* unsigned
/// entry: `data_region` returns `body[0x100 .. rom_size]` (full, sig_len == 0)
/// while `signature_bytes` returns `body[rom_size - 0x100 .. rom_size]` — the
/// two OVERLAP on the last 0x100 bytes, which upstream never does.
///
/// Not currently reached for unsigned files by the two in-tree callers
/// (`sign.rs:123` and `verify.rs:256` both gate on `is_signed()` first;
/// `extract.rs:59` calls only `data_region`), but `signature_bytes` is a `pub`
/// library API surface (a downstream Rust consumer can call it directly), so
/// the divergence is observable at the public boundary.
///
/// Expected value derived from upstream (`header_file.py:83-84`): an unsigned
/// file has `signature_len == 0`, so `signature_bytes` must be empty.
///
/// Tracking: #83 (fixed — pin now live)
#[test]
fn signature_bytes_of_unsigned_headerfile_is_empty() {
    // Same unsigned fixture as the data_region pin above: signed_raw == 0,
    // signature_type == 0, rom_size == 0x300 (header 0x100 + 0x200 data, NO
    // signature region). The last 0x100 body bytes are 0xBB — they belong to
    // the DATA region upstream, not to any signature.
    let mut h = [0u8; HEADER_FILE_LEN];
    h[0x10..0x14].copy_from_slice(b"$PS1");
    // 0x30 (is_signed) left zero => unsigned.
    h[0x34..0x38].copy_from_slice(&0u32.to_le_bytes()); // signature_type == 0
    h[0x6C..0x70].copy_from_slice(&0x300u32.to_le_bytes()); // rom_size

    let mut blob = Vec::new();
    blob.extend_from_slice(&h);
    blob.extend(std::iter::repeat_n(0xAAu8, 0x100));
    blob.extend(std::iter::repeat_n(0xBBu8, 0x100)); // upstream: part of DATA region

    let src = SourceBytes::from_blob(blob);
    let entry = HeaderEntry::parse(&src).expect("header parses");
    assert!(
        !entry.is_signed(),
        "fixture must be unsigned to exercise the bug"
    );

    // Upstream: signature_len == 0 for an unsigned file (header_file.py:83-84),
    // so the trailing signature region is EMPTY.
    let sig = entry
        .signature_bytes(src.as_bytes())
        .expect("unsigned signature region is a valid (empty) slice");
    assert_eq!(
        sig.len(),
        0,
        "unsigned HeaderFile has signature_len == 0 (header_file.py:83-84); \
         got {} bytes — target is treating the tail of the DATA region as a \
         signature",
        sig.len()
    );
    // Guard against the specific wrong region: the last 0x100 bytes (0xBB) are
    // data-region bytes upstream, and must NOT surface as a signature.
    assert!(
        !sig.contains(&0xBB),
        "trailing 0xBB bytes belong to the data region, not the signature"
    );
}

/// Divergence: `HeaderEntry::get_decompressed_body` (`body.rs:275`) reads
/// `plaintext[stream_start .. stream_start + zlib_size]` — i.e. it treats
/// `zlib_size` as a length measured FROM the zlib magic. Upstream measures
/// `zlib_size` from offset 0 of the data region and decompresses everything up
/// to that absolute offset:
///
///   `header_file.py:171`:
///     `return zlib_decompress(output[:self.zlib_size])`
///   `utils.py:245-252` (`zlib_decompress`):
///     ```
///     zlib_start = zlib_find_header(s)      # searches s == output[:zlib_size]
///     uncompressed = s[:zlib_start]
///     compressed   = s[zlib_start:]         # == output[zlib_start : zlib_size]
///     decompressed = zlib.decompress(compressed)
///     return uncompressed + decompressed
///     ```
///
/// So upstream's compressed slice is `output[zlib_start : zlib_size]`
/// (length `zlib_size - zlib_start`), while the target's is
/// `plaintext[zlib_start : zlib_start + zlib_size]` (length `zlib_size`).
/// When a pre-magic prefix is present (`zlib_start > 0`, exactly the case
/// REQ-3 says it handles) and the data region is `zlib_size` bytes long, the
/// target over-reads by `zlib_start` bytes and raises `ZlibSizeOutOfRange`
/// where upstream decompresses successfully.
///
/// Expected value derived from a live upstream oracle
/// (`zlib_decompress(output[:zlib_size])` over the same bytes):
///   `output = (0x55 * 16) || zlib.compress(b"hello, psptool-rs", 9)` (41 bytes,
///   zlib_start == 16, zlib_size == 41) yields
///   `b"UUUUUUUUUUUUUUUUhello, psptool-rs"`.
///
/// Tracking: #82 (fixed — pin now live)
#[test]
fn get_decompressed_body_zlib_size_is_absolute_offset_not_length() {
    // A valid zlib stream for b"hello, psptool-rs" (Python zlib.compress(.,9)),
    // embedded so the test needs no compression dependency. flate2's ZlibDecoder
    // inside body.rs decompresses it.
    const ZLIB_STREAM: &[u8] = &[
        0x78, 0xDA, 0xCB, 0x48, 0xCD, 0xC9, 0xC9, 0xD7, 0x51, 0x28, 0x28, 0x2E, 0x28, 0xC9, 0xCF,
        0xCF, 0xD1, 0x2D, 0x2A, 0x06, 0x00, 0x3A, 0x02, 0x06, 0x84,
    ];
    const PREFIX_LEN: usize = 16;

    // Data region = 16-byte non-magic prefix (0x55) followed by the stream.
    let mut plaintext = vec![0x55u8; PREFIX_LEN];
    plaintext.extend_from_slice(ZLIB_STREAM);
    // Upstream convention: zlib_size reaches the end of the compressed data,
    // measured from offset 0 of the data region -> includes the prefix.
    let zlib_size = plaintext.len() as u32; // 41

    // Build a compressed HeaderFile header carrying that zlib_size.
    let mut h = [0u8; HEADER_FILE_LEN];
    h[0x10..0x14].copy_from_slice(b"$PS1");
    h[0x48..0x4C].copy_from_slice(&1u32.to_le_bytes()); // is_compressed == 1
    h[0x54..0x58].copy_from_slice(&zlib_size.to_le_bytes());
    let src = SourceBytes::from_blob(h.to_vec());
    let entry = HeaderEntry::parse(&src).expect("header parses");
    assert!(entry.is_compressed);
    let _ = Ikek::ZenPlus; // keep the import meaningful across refactors

    // Upstream oracle result (zlib_decompress(output[:zlib_size])):
    let mut expected = vec![0x55u8; PREFIX_LEN];
    expected.extend_from_slice(b"hello, psptool-rs");

    let out = entry
        .get_decompressed_body(&plaintext)
        .expect("upstream decompresses output[:zlib_size] successfully");
    assert_eq!(
        out, expected,
        "get_decompressed_body must mirror upstream zlib_decompress(output[:zlib_size]): \
         prefix + decompressed payload"
    );
}

/// Divergence: `find_zlib_start` (`body.rs:486`) scans the *whole* `plaintext`
/// (bounded only by the 0x500 window), whereas upstream searches only
/// `output[:zlib_size]`:
///
///   `header_file.py:171`:
///     `return zlib_decompress(output[:self.zlib_size])`
///   `utils.py:245` (`zlib_decompress`):
///     `zlib_start = zlib_find_header(s)`    where `s == output[:zlib_size]`
///   `utils.py:218-234` (`zlib_find_header`):
///     `s = s[:0x500]; for magic in ZLIB_TYPES: ... s.find(magic) ...`
///
/// Upstream therefore NEVER inspects a byte at or beyond `zlib_size`. The
/// target's `get_decompressed_body` (`body.rs:287`) calls
/// `find_zlib_start(plaintext)` on the *entire* data region and only bounds to
/// `zlib_size` AFTER locating a magic (`body.rs:296-304`). A pathological entry
/// with a zlib magic at an offset `> zlib_size` (but within the 0x500 window)
/// and NO magic within `[0, zlib_size)` diverges: the target locates the
/// out-of-bounds magic and (because `zlib_size < stream_start`) raises
/// `ZlibSizeOutOfRange`, whereas upstream's `zlib_find_header(output[:zlib_size])`
/// returns -1 — there is no zlib magic in the region it actually searches.
///
/// Expected value derived from upstream: `output[:zlib_size]` here is 0x40
/// bytes of 0x00, so `zlib_find_header(output[:zlib_size])` finds NO magic. The
/// target must reach the same conclusion (no magic within `[0, zlib_size)`),
/// surfaced in its own error taxonomy as `ZlibMagicMissing` — and must NOT
/// locate the magic that lives at offset 0x50 (past `zlib_size`). The current
/// `ZlibSizeOutOfRange` is direct evidence the scan over-read past `zlib_size`.
///
/// Tracking: #84 (fixed — pin now live)
#[test]
fn find_zlib_start_ignores_magic_beyond_zlib_size() {
    // Data region: 0x50 non-magic bytes, then a zlib magic (0x78 0xDA) at
    // offset 0x50. zlib_size == 0x40, so upstream searches only output[:0x40]
    // (all 0x00 — no magic). The magic at 0x50 is strictly past zlib_size.
    let mut plaintext = vec![0x00u8; 0x50];
    plaintext.extend_from_slice(&[0x78, 0xDA, 0x01, 0x02]); // fake magic past zlib_size
    let zlib_size: u32 = 0x40;

    // Sanity: no zlib magic byte appears within the region upstream searches
    // (output[:zlib_size]); the only 0x78 sits at 0x50, past zlib_size.
    assert!(
        !plaintext[..zlib_size as usize].contains(&0x78),
        "the region upstream searches (output[:zlib_size]) must be magic-free"
    );

    let mut h = [0u8; HEADER_FILE_LEN];
    h[0x10..0x14].copy_from_slice(b"$PS1");
    h[0x48..0x4C].copy_from_slice(&1u32.to_le_bytes()); // is_compressed == 1
    h[0x54..0x58].copy_from_slice(&zlib_size.to_le_bytes());
    let src = SourceBytes::from_blob(h.to_vec());
    let entry = HeaderEntry::parse(&src).expect("header parses");
    assert!(entry.is_compressed);

    let err = entry
        .get_decompressed_body(&plaintext)
        .expect_err("no zlib magic within output[:zlib_size], so decompression cannot succeed");
    // Upstream searches output[:zlib_size] and finds NO magic. The target must
    // agree — it must NOT locate the magic at 0x50 (past zlib_size). A
    // `ZlibSizeOutOfRange` is proof the scan looked past zlib_size and found
    // the out-of-bounds magic; the upstream-faithful outcome is "no magic in
    // the searched region" (`ZlibMagicMissing`).
    assert!(
        matches!(err, BodyError::ZlibMagicMissing { .. }),
        "expected ZlibMagicMissing (no magic within output[:zlib_size]); got {err:?} — \
         the scan located a magic beyond zlib_size, which upstream never inspects"
    );
}

/// Control: with NO pre-magic prefix (`zlib_start == 0`) the two interpretations
/// coincide, so this must pass under BOTH upstream and the target. Guards
/// against a future "fix" that breaks the common case. Left un-ignored on
/// purpose — it is a passing regression guard, not a divergence pin.
#[test]
fn get_decompressed_body_no_prefix_control_passes() {
    const ZLIB_STREAM: &[u8] = &[
        0x78, 0xDA, 0xCB, 0x48, 0xCD, 0xC9, 0xC9, 0xD7, 0x51, 0x28, 0x28, 0x2E, 0x28, 0xC9, 0xCF,
        0xCF, 0xD1, 0x2D, 0x2A, 0x06, 0x00, 0x3A, 0x02, 0x06, 0x84,
    ];
    let plaintext = ZLIB_STREAM.to_vec();
    let zlib_size = plaintext.len() as u32;

    let mut h = [0u8; HEADER_FILE_LEN];
    h[0x10..0x14].copy_from_slice(b"$PS1");
    h[0x48..0x4C].copy_from_slice(&1u32.to_le_bytes());
    h[0x54..0x58].copy_from_slice(&zlib_size.to_le_bytes());
    let src = SourceBytes::from_blob(h.to_vec());
    let entry = HeaderEntry::parse(&src).expect("header parses");

    match entry.get_decompressed_body(&plaintext) {
        Ok(out) => assert_eq!(out, b"hello, psptool-rs"),
        Err(BodyError::ZlibSizeOutOfRange { .. }) => {
            panic!("control (no prefix) must not over-read")
        }
        Err(e) => panic!("unexpected error in no-prefix control: {e}"),
    }
}
