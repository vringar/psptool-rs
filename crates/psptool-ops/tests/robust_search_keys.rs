//! Robustness pin for `search_keys` (`search_keys.rs`) on a crafted,
//! untrusted image. Synthetic bytes only.

use std::sync::mpsc;
use std::time::Duration;

use psptool_core::fet::Fet;
use psptool_core::magic::FET_MAGIC;
use psptool_core::{FlashOffset, RomSize, SourceBytes};
use psptool_ops::search_keys;

fn put_u32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// Severity: hang (`O(image_len * pubkey_entries)`), `psptool search-keys`.
///
/// The heuristic pass (`search_keys.rs:121-132`) tests every byte offset of
/// the image against *every* structured pubkey range with a linear
/// `structured_ranges.iter().any(..)`. Directory entries may alias one body,
/// so an attacker gets one range per 16-byte record for free: 20k type-0x00
/// records pointing at the same pubkey in a 1 MiB image is 2*10^10 range
/// checks; a 16 MiB image with ~1M records is ~10^13.
///
/// Expected: overlapping ranges are merged (or searched by offset), keeping
/// the scan near-linear in the image size.
#[test]
fn robust_search_keys_aliased_pubkey_entries_near_linear() {
    const IMAGE_LEN: usize = 1 << 20;
    const ENTRIES: usize = 20_000;
    const BUDGET: Duration = Duration::from_secs(10);
    let (fet_at, dir_at, key_at) = (0x100usize, 0x1000usize, 0xC_0000usize);
    let mut buf = vec![0u8; IMAGE_LEN];

    buf[fet_at..fet_at + 4].copy_from_slice(FET_MAGIC.as_bytes());
    put_u32(&mut buf, fet_at + 4, dir_at as u32);
    buf[fet_at + 8..fet_at + 24].fill(0xFF);

    // `$PSP`, mode 01 (flash offset), ENTRIES pubkey records aliasing one body.
    buf[dir_at..dir_at + 4].copy_from_slice(b"$PSP");
    put_u32(&mut buf, dir_at + 8, ENTRIES as u32);
    put_u32(&mut buf, dir_at + 12, 0x2000_0000);
    for i in 0..ENTRIES {
        let rec = dir_at + 0x10 + 0x10 * i;
        buf[rec] = 0x00; // AMD_PUBLIC_KEY
        put_u32(&mut buf, rec + 4, 0x240);
        put_u32(&mut buf, rec + 8, key_at as u32);
    }
    // Minimal PubkeyFile header (RSA-2048 widths); contents are irrelevant.
    put_u32(&mut buf, key_at, 1);
    put_u32(&mut buf, key_at + 0x38, 2048);
    put_u32(&mut buf, key_at + 0x3C, 2048);

    let blob = SourceBytes::from_blob(buf);
    let fet = Fet::parse_at(&blob, FlashOffset(fet_at as u64)).expect("FET parses");
    let (tx, rx) = mpsc::channel();
    // Detached: a miss fails the test and the process exits without it.
    std::thread::spawn(move || {
        let _ = tx.send(search_keys(&blob, &fet, RomSize::MIB_8, FlashOffset::ZERO).len());
    });
    match rx.recv_timeout(BUDGET) {
        Ok(hits) => assert!(hits >= ENTRIES, "fixture: {hits} structured hits"),
        Err(_) => panic!(
            "search_keys did not scan a {IMAGE_LEN}-byte image with {ENTRIES} aliased \
             pubkey entries within {BUDGET:?}"
        ),
    }
}
