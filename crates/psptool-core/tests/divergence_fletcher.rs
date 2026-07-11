//! ACToR critic divergence pins for `psptool_core::fletcher32`.
//!
//! Oracle: a verbatim transcription of upstream `psptool/utils.py:286-307`
//! (`fletcher32`) executed in CPython 3. The upstream package does not import
//! (missing `prettytable`), but `fletcher32` depends only on `struct` and the
//! `chunker` helper (`utils.py:175-177`), so the standalone transcription is
//! faithful. All expected values below were produced by that oracle, never
//! copied from the Rust side (R-CHAR-3).
//!
//! Even-length parity is intact (seed, 360-word fold, u32-vs-bignum, double
//! final fold all agree). The pinned divergence was ODD-LENGTH input; it is
//! now CLOSED (#45): `fletcher32` returns `Err(FletcherError::OddLength)` on
//! odd input, mirroring upstream's `struct.error` raise (goal.md R-DEV-4).

use psptool_core::fletcher::FletcherError;
use psptool_core::fletcher32;

/// Control (NOT a pin): even-length input crossing the fold boundaries at
/// word indices 0/360/720. 1600 bytes = 800 words, `data[i] = i & 0xFF`.
///
/// Oracle (`utils.py:286` transcription):
///   `fletcher32(bytes((i & 0xFF) for i in range(1600)))` -> `0x8CDB8265`.
/// This passes today and demonstrates the oracle harness is not tautological:
/// it agrees with Rust on every even-length case probed.
#[test]
fn control_even_length_fold_crossing_matches_oracle() {
    let buf: Vec<u8> = (0..1600).map(|i| (i & 0xFF) as u8).collect();
    // Independent oracle value from utils.py transcription, NOT the Rust output.
    // 1600 is even, so the checksum is produced; unwrap the fallible boundary.
    assert_eq!(fletcher32(&buf).unwrap(), 0x8CDB_8265);
}

/// Divergence: `psptool_core::fletcher32` diverges from
/// `psptool/utils.py:291` (`byte_pair_int = struct.unpack('<H', byte_pair)[0]`)
/// for ODD-length input.
///
/// `chunker(s, 2)` (`utils.py:177`) yields a 1-byte final slice for odd-length
/// `s`; `struct.unpack('<H', <1 byte>)` then raises
/// `struct.error: unpack requires a buffer of 2 bytes`. Upstream therefore
/// produces NO checksum for odd-length input — the call aborts.
///
/// The Rust boundary previously (`fletcher.rs:34-39`, pre-#45) silently folded
/// the trailing byte in as a single-byte word and RETURNED a value
/// (`fletcher32(&[0x12,0x34,0x56])` == `0x687A3468`). A public `pub fn`
/// boundary that invents a checksum for input upstream rejects was a semantic
/// divergence.
///
/// CLOSED (#45): the boundary is now fallible. Upstream aborts on odd input,
/// so the Rust boundary returns `Err(FletcherError::OddLength)` (goal.md
/// R-DEV-4: Python exception → Rust `Result::Err`, not a `panic!`). This test
/// asserts the typed error rather than `#[should_panic]`, matching the chosen
/// Rust contract.
///
/// Tracking: #45
#[test]
fn divergence_odd_length_three_bytes_upstream_raises() {
    // Upstream RAISES struct.error here; the Rust boundary returns a typed Err.
    assert_eq!(
        fletcher32(&[0x12, 0x34, 0x56]),
        Err(FletcherError::OddLength { len: 3 })
    );
}

/// Divergence: single odd byte. `chunker(&[0x00], 2)` yields one 1-byte slice;
/// `struct.unpack('<H', b'\x00')` raises (`utils.py:291`). Rust previously
/// returned `0xFFFFFFFF` (`fletcher.rs:34-39`, pre-#45) — a value where
/// upstream aborts.
///
/// CLOSED (#45): the boundary now returns `Err(FletcherError::OddLength)`.
///
/// Tracking: #45
#[test]
fn divergence_single_odd_byte_upstream_raises() {
    assert_eq!(
        fletcher32(&[0x00]),
        Err(FletcherError::OddLength { len: 1 })
    );
}
