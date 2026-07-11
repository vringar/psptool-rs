//! Divergence pin: length-changing `replace` leaves the parent directory's
//! Fletcher-32 checksum STALE, where upstream PSPTool recomputes it.
//!
//! Upstream `--replace-file` flow (all cites in `/tmp/psptool-ref/psptool`):
//!   * `__main__.py:247` `file.move_buffer(file.get_address(), len(sub_binary))`
//!   * `file.py:393` `directory.update_entry_fields(self, self.type, self.buffer_size, self.buffer_offset)`
//!   * `directory.py:241` `self.update_checksum()`  (called UNCONDITIONALLY on every replace)
//!   * `directory.py:203-205`:
//!         `data = self[0x8:]`
//!         `self.checksum.set_bytes(0, 4, fletcher32(data))`
//! So a length-changing replace mutates the entry record's `size` field
//! (`entry.py:109-110` `entry.size` setter → `set_bytes(4,4,...)`), which lands
//! inside the checksummed region `self[0x8:]` (directory header[8:] ++ entry
//! table — `directory.py:132-134`), and upstream then writes a FRESH
//! Fletcher-32 into the header's checksum field at `[0x04..0x08]`.
//!
//! Our target (`crates/psptool-ops/src/replace.rs`) never recomputes the
//! checksum: `replace.rs:34-39` explicitly defers it ("belongs alongside the
//! re-sign work in #13") — but #13 (`psptool-ops: sign + verify`) is CLOSED,
//! so the deferral is dangling (goal.md R-DEFER-3: a divergence may not sit
//! behind a closed tracking issue). The result is an output ROM whose directory
//! checksum no longer matches its own bytes; upstream's own
//! `verify_checksum` (`directory.py:195-201`) would warn on it, and a strict
//! Fletcher-verifying reader (the AMD PSP bootrom) would reject it.
//!
//! The expected value is derived from the UPSTREAM ALGORITHM
//! (`psptool_core::fletcher32`, itself pinned byte-for-byte against
//! `utils.fletcher32` in `crates/psptool-core/src/fletcher.rs`) applied to the
//! target's OWN post-replace bytes — never literal-copied from either side
//! (goal.md R-CHAR-3). It is therefore independent of the deliberate PR#77
//! deviation (we write the exact size, upstream rounds to 0x10): whatever size
//! bytes end up in the record, a correct implementation's stored checksum must
//! equal `fletcher32` over the record as written.

use psptool_core::directory::{DIRECTORY_HEADER_SIZE, Directory, PSP_ENTRY_SIZE};
use psptool_core::{FlashOffset, RomSize, SourceBytes, fletcher32};
use psptool_ops::replace_psp_entry_body;

/// Absolute byte range the directory Fletcher-32 is computed over:
/// header bytes `[0x08 .. 0x10]` (count + additional_info) plus the single
/// 16-byte entry record — i.e. `[0x08 .. 0x20]` for a 1-entry `$PSP` dir.
const CKSUM_REGION: std::ops::Range<usize> = 0x08..(DIRECTORY_HEADER_SIZE + PSP_ENTRY_SIZE);

/// Build a single-entry `$PSP` directory whose stored Fletcher-32 checksum is
/// VALID for the initial bytes (recomputed via the upstream algorithm, so the
/// source is a faithful stand-in for a real ROM directory).
fn valid_psp_dir_with_entry(entry_type: u8, body: &[u8]) -> Vec<u8> {
    let body_off = (DIRECTORY_HEADER_SIZE + PSP_ENTRY_SIZE) as u32;
    let size = body.len() as u32;
    let additional_info = (1u32 << 31) | (0b10u32 << 24);
    let entry_rsv0: u32 = 0b10u32 << 30;

    let mut entry = [0u8; PSP_ENTRY_SIZE];
    entry[0x00] = entry_type;
    entry[0x04..0x08].copy_from_slice(&size.to_le_bytes());
    entry[0x08..0x0C].copy_from_slice(&body_off.to_le_bytes());
    entry[0x0C..0x10].copy_from_slice(&entry_rsv0.to_le_bytes());

    let mut out = Vec::new();
    out.extend_from_slice(b"$PSP");
    out.extend_from_slice(&0u32.to_le_bytes()); // checksum placeholder
    out.extend_from_slice(&1u32.to_le_bytes()); // count = 1
    out.extend_from_slice(&additional_info.to_le_bytes());
    out.extend_from_slice(&entry);
    out.extend_from_slice(body);

    // Stamp a VALID checksum over the region upstream checksums (`self[0x8:]`).
    let cksum = fletcher32(&out[CKSUM_REGION]).expect("even-length region");
    out[0x04..0x08].copy_from_slice(&cksum.to_le_bytes());
    out
}

fn parse_psp(blob_bytes: Vec<u8>) -> (SourceBytes, psptool_core::directory::PspDirectory) {
    let blob = SourceBytes::from_blob(blob_bytes);
    let dir = match Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
        Directory::Psp(p) => p,
        _ => unreachable!("$PSP magic"),
    };
    (blob, dir)
}

/// PIN (currently FAILS): a length-changing replace produces a directory whose
/// stored checksum no longer matches its bytes, unlike upstream which
/// recomputes it via `update_checksum` (`directory.py:241` / `:203-205`).
#[test]
#[ignore = "divergence: replace path leaves directory fletcher32 stale; upstream recomputes (directory.py:241); tracking #66"]
fn length_changing_replace_recomputes_directory_checksum() {
    // Original body 0x40; shrink to a deliberately non-0x10-aligned 0x33 so the
    // size field genuinely changes (0x40 -> 0x33) inside the checksummed region.
    let body = vec![0xAAu8; 0x40];
    let bytes = valid_psp_dir_with_entry(0x21, &body);
    let (blob, dir) = parse_psp(bytes);

    let replacement = vec![0xCCu8; 0x33];
    let mut editor = psptool_core::BlobEditor::from_blob(blob);
    replace_psp_entry_body(
        &mut editor,
        &dir,
        0,
        RomSize::MIB_16,
        FlashOffset::ZERO,
        &replacement,
    )
    .unwrap();
    let out = editor.serialize();

    let stored = u32::from_le_bytes(out[0x04..0x08].try_into().unwrap());
    // Oracle: the upstream algorithm over the target's OWN post-replace record.
    let expected = fletcher32(&out[CKSUM_REGION]).expect("even-length region");

    assert_eq!(
        stored, expected,
        "directory checksum is stale after a length-changing replace: stored \
         {stored:#010x} but the post-replace region checksums to {expected:#010x}. \
         Upstream recomputes it (directory.py:241 update_checksum → :203-205 \
         set_bytes(0,4,fletcher32(self[0x8:]))); replace.rs never does.",
    );
}

/// CONTROL (PASSES today): an EQUAL-length replace does not touch the entry
/// record, so the source's valid checksum stays valid — proving the pin above
/// fails for the RIGHT reason (the changed `size` field), not because the
/// fixture or the fletcher region is wrong.
#[test]
fn equal_length_replace_keeps_directory_checksum_valid() {
    let body = vec![0xAAu8; 0x40];
    let bytes = valid_psp_dir_with_entry(0x21, &body);
    let (blob, dir) = parse_psp(bytes);

    let replacement = vec![0xCCu8; 0x40]; // same length → record untouched
    let mut editor = psptool_core::BlobEditor::from_blob(blob);
    replace_psp_entry_body(
        &mut editor,
        &dir,
        0,
        RomSize::MIB_16,
        FlashOffset::ZERO,
        &replacement,
    )
    .unwrap();
    let out = editor.serialize();

    let stored = u32::from_le_bytes(out[0x04..0x08].try_into().unwrap());
    let expected = fletcher32(&out[CKSUM_REGION]).expect("even-length region");
    assert_eq!(
        stored, expected,
        "equal-length replace must leave the (valid) directory checksum intact",
    );
}
