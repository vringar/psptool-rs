//! ACToR critic divergence pin for `psptool_core::scan_fet_candidates`.
//!
//! Oracle: upstream `psptool/blob.py:124-131` (`Blob._find_fets`), executed
//! verbatim in CPython 3 against the fixture below. `_find_fets` runs TWO
//! sequential `re.finditer` passes:
//!
//! ```python
//! def _find_fets(self):
//!     for m in re.finditer(b'\xff\xff\xff\xff' + self._FIRMWARE_ENTRY_MAGIC, self.get_buffer()):
//!         yield m.start() + 4          # blob.py:126-128 — ALL 0xFF-padded first
//!     for m in re.finditer(b'\x00\x00\x00\x00' + self._FIRMWARE_ENTRY_MAGIC, self.get_buffer()):
//!         yield m.start() + 4          # blob.py:129-131 — THEN all 0x00-padded
//! ```
//!
//! It therefore yields every `0xFFFFFFFF`-padded FET (in file order) BEFORE any
//! `0x00000000`-padded FET, regardless of file position. The Rust
//! `scan_fet_candidates` (`fet.rs:299-318`) is a single byte-position pass that
//! interleaves the two pad kinds, so for a blob whose zero-padded FET precedes
//! its FF-padded FET the emitted ORDER differs.
//!
//! The consumer `psptool-cli/src/load.rs:38-41` selects a ROM by
//! `.nth(rom_index)` over this exact ordering, so the divergence is observable:
//! upstream's "ROM 0" and the Rust "ROM 0" are different ROMs for such a blob.
//!
//! Expected values below come from the upstream `_find_fets` regex oracle
//! (order `[0x204, 0x104]`), never copied from the Rust side (R-CHAR-3).
//!
//! Tracking: #63 (scan-ordering divergence, already filed).

use psptool_core::{FET_MAGIC, FlashOffset, SourceBytes, scan_fet_candidates};

/// Build a blob with a zero-padded FET at a LOWER file offset than an
/// FF-padded FET:
///   * `[0x100 .. 0x108]` = `00 00 00 00` + FET magic -> magic at `0x104`
///   * `[0x200 .. 0x208]` = `FF FF FF FF` + FET magic -> magic at `0x204`
fn mixed_pad_blob() -> SourceBytes {
    let mut buf = vec![0u8; 0x300];
    // zero-padded FET (lower offset)
    buf[0x100..0x104].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    buf[0x104..0x108].copy_from_slice(FET_MAGIC.as_bytes());
    // FF-padded FET (higher offset)
    buf[0x200..0x204].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
    buf[0x204..0x208].copy_from_slice(FET_MAGIC.as_bytes());
    SourceBytes::from_blob(buf)
}

/// Control (NOT a pin): the fixture contains exactly two FET candidates and
/// each reported offset genuinely points at the FET magic. This passes today
/// and proves the fixture is sound (the divergence below is about ORDER, not
/// about which offsets are found). Order-independent on purpose.
#[test]
fn control_both_fets_found_at_magic_offsets() {
    let blob = mixed_pad_blob();
    let cands = scan_fet_candidates(&blob);

    let mut sorted = cands.clone();
    sorted.sort();
    assert_eq!(
        sorted,
        vec![FlashOffset(0x104), FlashOffset(0x204)],
        "fixture must expose exactly the two FET magic offsets"
    );

    // Each reported offset really is the FET magic (fixture soundness).
    let bytes = blob.as_bytes();
    for off in &cands {
        let o = off.get() as usize;
        assert_eq!(
            &bytes[o..o + 4],
            FET_MAGIC.as_bytes(),
            "candidate {off:?} must land on FET magic"
        );
    }
}

/// Divergence: `psptool_core::scan_fet_candidates` diverges from
/// `psptool/blob.py:124-131` (`Blob._find_fets`) in candidate ORDER when a
/// blob mixes pad kinds.
///
/// Upstream `_find_fets` yields the FF-padded FET (magic `0x204`) FIRST because
/// its whole `\xff\xff\xff\xff`+magic pass (`blob.py:126`) completes before the
/// `\x00\x00\x00\x00`+magic pass (`blob.py:129`) begins. The zero-padded FET
/// (magic `0x104`) is yielded SECOND even though it sits earlier in the file.
///
/// Upstream oracle order (from the `_find_fets` regexes): `[0x204, 0x104]`.
/// Rust returns file-position order `[0x104, 0x204]` (`fet.rs:310-316`, single
/// pass), so `load.rs`'s `.nth(rom_index)` picks the wrong ROM for such a blob.
///
/// Tracking: #63
#[test]
fn divergence_scan_order_ff_pass_before_zero_pass() {
    let blob = mixed_pad_blob();
    let cands = scan_fet_candidates(&blob);
    // Upstream _find_fets order: all 0xFF-padded first, then all 0x00-padded.
    assert_eq!(
        cands,
        vec![FlashOffset(0x204), FlashOffset(0x104)],
        "scan_fet_candidates must mirror blob.py:124-131 two-pass order \
         (0xFF-padded FET at 0x204 before 0x00-padded FET at 0x104)"
    );
}
