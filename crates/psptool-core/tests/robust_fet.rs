//! Robustness pins for FET discovery (`fet.rs`) on crafted, untrusted
//! images. Synthetic bytes only.

use std::sync::mpsc;
use std::time::Duration;

use psptool_core::body::{CertifyingKeys, Ikek};
use psptool_core::{SourceBytes, detect_rom_layout, scan_fet_candidates};

/// Generous for anything near-linear in a 16 MiB image, even in debug.
const BUDGET: Duration = Duration::from_secs(10);

/// One byte short of 16 MiB: `assumed_rom_size` picks 8 MiB, so every FET
/// magic in `[0x20000, 0x820000)` yields a ROM layout (`fet.rs:95-127`).
const IMAGE_LEN: usize = (16 << 20) - 1;

/// Candidate region: `00000000 AA55AA55` repeated, i.e. a zero-padded FET
/// candidate every 8 bytes (`scan_fet_candidates`, `fet.rs:312-340`).
const REGION_AT: usize = 0x70_0000;

fn image_with_candidates(region_len: usize, terminated: bool) -> SourceBytes {
    let mut buf = vec![0u8; IMAGE_LEN];
    for at in (REGION_AT..REGION_AT + region_len).step_by(8) {
        buf[at + 4..at + 8].copy_from_slice(&[0xAA, 0x55, 0xAA, 0x55]);
    }
    if terminated {
        let end = REGION_AT + region_len;
        buf[end..end + 16].fill(0xFF);
    }
    SourceBytes::from_blob(buf)
}

/// Run `f` on a detached thread; `None` when it misses [`BUDGET`]. A miss
/// fails the test and the process exits without waiting for the thread.
fn within_budget<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(BUDGET).ok()
}

/// Severity: hang (quadratic time in image size) on the default `ls` path.
///
/// `Fet::parse_at` (`fet.rs:214-291`) scans forward from the magic to the
/// first 16-byte `0xFF` terminator, and `CertifyingKeys::from_blob`
/// (`body.rs:731-753`, built by every `ls` listing, `list.rs:115`) parses and
/// walks the FET of *every* candidate that yields a layout. Candidates are
/// 8 bytes apart and their tables overlap, so `C` candidates ahead of one
/// terminator cost `O(C^2)` slot records plus a `Directory::parse_at` per
/// pointer slot. 256 KiB of `00000000 AA55AA55` is ~10^9 slot records; a
/// full 8 MiB window of it is ~10^12.
///
/// Expected: candidates inside an already-parsed FET's span (or past a sane
/// ROM count) are not re-parsed, keeping discovery near-linear.
#[test]
#[ignore = "crosslink #143"]
fn robust_fet_overlapping_candidates_certifying_keys_near_linear() {
    let blob = image_with_candidates(0x4_0000, true);
    let done = within_budget(move || {
        let _ = CertifyingKeys::from_blob(&blob, Ikek::ZenPlus);
    });
    assert!(
        done.is_some(),
        "CertifyingKeys::from_blob did not finish within {BUDGET:?} on 32k overlapping \
         FET candidates (each candidate's table is re-parsed and re-walked)"
    );
}

/// Severity: hang on every CLI command (`open_rom`, `psptool-cli/src/load.rs:38-41`).
///
/// With no terminator anywhere, every candidate's `Fet::parse_at` scans to the
/// end of the image, pushing a 48-byte `FetSlotRecord` per dword (~2.3M records
/// = ~110 MB here) before failing with `FetUnterminated`, and
/// `detect_rom_layout` repeats that failing parse once per fitting
/// `KNOWN_FET_OFFSETS` entry (`fet.rs:95-127`). `open_rom` tries candidates
/// until one parses, so an image of nothing but unterminated candidates costs
/// `O(C * image_len)`: a few KiB of candidates already take minutes, a full
/// window of them never finishes.
///
/// Expected: a FET that cannot terminate is rejected without rescanning the
/// image per candidate and per offset (e.g. locate terminators once).
#[test]
fn robust_fet_unterminated_candidates_rejected_near_linear() {
    let blob = image_with_candidates(0x800, false);
    let done = within_budget(move || {
        scan_fet_candidates(&blob)
            .iter()
            .filter_map(|pos| detect_rom_layout(&blob, *pos))
            .next()
            .is_none()
    });
    assert_eq!(
        done,
        Some(true),
        "rejecting 256 unterminated FET candidates (open_rom's discovery loop) did not \
         finish within {BUDGET:?}"
    );
}
