//! `search-keys` — discover RSA pubkeys embedded in a parsed [`Blob`].
//!
//! Two discovery paths run side-by-side:
//!
//! * **Structured** — every directory reachable from the FET is walked; each
//!   entry is parsed via [`Entry::parse_psp`] / [`Entry::parse_bios`] and
//!   anything classified as [`EntryClass::Pubkey`] becomes a [`KeyHit`] with
//!   a [`KeyHitLocation::Structured`] back-reference.
//! * **Heuristic** — the raw blob bytes are scanned for [`PubkeyEntry`]-shaped
//!   regions that the structured walk did not surface (e.g. pubkeys embedded
//!   inline inside another file's body — what PSPTool calls
//!   `InlinePubkeyFile`, populated via `Blob._find_inline_pubkeys`). A region
//!   qualifies when:
//!     - `version` u32 LE at +0x00 ∈ `{1, 2}` (`PubkeyFile` versions
//!       documented in §7.1).
//!     - `pubexp_bits` u32 LE at +0x38 ∈ `{2048, 4096}`.
//!     - `modulus_bits` u32 LE at +0x3C equals `pubexp_bits`.
//!     - The first four bytes of `pubexp` at +0x40 are `01 00 01 00` —
//!       PSP pubkeys universally use exponent `0x10001` little-endian.
//!     - The remaining bytes (`0x40 + 2·(bits/8)`) all fit inside the blob.
//!
//! Heuristic hits whose body region overlaps any structured hit are dropped
//! to avoid double-counting. Output ordering is structured hits first (in
//! directory walk order) followed by heuristic hits in ascending offset.
//!
//! No I/O. The CLI binding for this lives in #15.

use psptool_core::{
    Directory, DirectoryRef, Entry, EntryClass, FlashOffset, RomSize, SourceBytes, walk_directories,
};

/// 16-byte fingerprint of a discovered pubkey — same shape as the
/// `key_id` stamped in [`psptool_core::PubkeyEntry`].
pub type KeyId = [u8; 16];

/// Reference back to the directory walk position that produced a structured
/// hit. Indices are into the [`walk_directories`] result for the structured
/// path; for the heuristic path, see [`KeyHitLocation::Heuristic`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EntryRef {
    /// Index of the directory in the [`walk_directories`] traversal.
    pub directory_index: usize,
    /// Index of the entry within its parent directory.
    pub entry_index: usize,
}

/// How a [`KeyHit`] was discovered.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyHitLocation {
    /// Found via the directory walk + entry-parser pipeline.
    Structured(EntryRef),
    /// Found by heuristic byte-scan outside any structured directory entry.
    Heuristic,
}

/// A single discovered pubkey.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct KeyHit {
    /// Absolute flash offset of byte zero of the pubkey blob (its
    /// [`PubkeyEntry::source`] start, equivalently the version dword).
    pub offset: FlashOffset,
    /// 16-byte `key_id` fingerprint (offset +0x04 of the pubkey blob).
    pub key_id: KeyId,
    /// `modulus_size` in bytes (= `modulus_bits / 8`). Always 256 or 512.
    pub modulus_size: u32,
    pub location: KeyHitLocation,
}

/// Walk every directory reachable from `fet`, then byte-scan for embedded
/// pubkeys outside the structured tree. See module docs for details.
///
/// `rom_origin` is the file offset of ROM-flash-offset 0 inside `blob`
/// (matches [`walk_directories`] / [`Entry::parse_psp`]).
pub fn search_keys(
    blob: &SourceBytes,
    fet: &psptool_core::Fet,
    rom_size: RomSize,
    rom_origin: FlashOffset,
) -> Vec<KeyHit> {
    let directories = walk_directories(blob, fet, rom_size, rom_origin);
    search_keys_with_directories(blob, &directories, rom_size, rom_origin)
}

/// Variant of [`search_keys`] that accepts an already-walked directory list.
/// Useful when the caller is also rendering `list` or running `verify` and
/// wants to share the walk.
pub fn search_keys_with_directories(
    blob: &SourceBytes,
    directories: &[DirectoryRef],
    rom_size: RomSize,
    rom_origin: FlashOffset,
) -> Vec<KeyHit> {
    let mut out = Vec::new();
    let mut structured_ranges: Vec<core::ops::Range<u64>> = Vec::new();

    for (dir_idx, dir_ref) in directories.iter().enumerate() {
        match &dir_ref.directory {
            Directory::Psp(p) => {
                for i in 0..p.entries.len() {
                    if let Ok(entry) = Entry::parse_psp(blob, p, i, rom_size, rom_origin) {
                        push_if_pubkey(&entry, dir_idx, i, &mut out, &mut structured_ranges);
                    }
                }
            }
            Directory::Bios(b) => {
                for i in 0..b.entries.len() {
                    if let Ok(entry) = Entry::parse_bios(blob, b, i, rom_size, rom_origin) {
                        push_if_pubkey(&entry, dir_idx, i, &mut out, &mut structured_ranges);
                    }
                }
            }
            Directory::Combo(_) => {}
        }
    }

    // Heuristic pass: scan the entire blob window for PubkeyFile-shaped
    // regions. Skip any whose start falls inside a structured pubkey body
    // — those are already in `out` with full directory provenance.
    let bytes = blob.as_bytes();
    let blob_start = blob.offset().get();
    for local in 0..bytes.len() {
        let abs = blob_start + local as u64;
        if structured_ranges
            .iter()
            .any(|r| r.start <= abs && abs < r.end)
        {
            continue;
        }
        if let Some(hit) = try_heuristic_at(bytes, local, blob_start) {
            out.push(hit);
        }
    }

    out
}

fn push_if_pubkey(
    entry: &Entry,
    dir_idx: usize,
    entry_idx: usize,
    out: &mut Vec<KeyHit>,
    ranges: &mut Vec<core::ops::Range<u64>>,
) {
    let EntryClass::Pubkey(pk) = &entry.class else {
        return;
    };
    let offset = pk.source.offset();
    let modulus_size = pk.modulus_bits / 8;
    out.push(KeyHit {
        offset,
        key_id: pk.key_id,
        modulus_size,
        location: KeyHitLocation::Structured(EntryRef {
            directory_index: dir_idx,
            entry_index: entry_idx,
        }),
    });
    let start = offset.get();
    let end = start + pk.source.len() as u64;
    ranges.push(start..end);
}

/// Header constants for the `PubkeyFile` shape (§7.1).
const PUBKEY_HEADER_LEN: usize = 0x40;
const PUBKEY_VERSION_OFF: usize = 0x00;
const PUBKEY_KEY_ID_OFF: usize = 0x04;
const PUBKEY_PUBEXP_BITS_OFF: usize = 0x38;
const PUBKEY_MODULUS_BITS_OFF: usize = 0x3C;
const PUBKEY_PUBEXP_OFF: usize = 0x40;
/// PSP pubkeys universally encode `0x10001` as the public exponent, stored
/// little-endian. The first four bytes of `pubexp` therefore look exactly
/// like this on every well-formed pubkey blob.
const RSA_F4_LE_PREFIX: [u8; 4] = [0x01, 0x00, 0x01, 0x00];

fn try_heuristic_at(bytes: &[u8], local: usize, blob_start: u64) -> Option<KeyHit> {
    if local + PUBKEY_HEADER_LEN > bytes.len() {
        return None;
    }
    let h = &bytes[local..];

    // version ∈ {1, 2}
    let version = u32::from_le_bytes(
        h[PUBKEY_VERSION_OFF..PUBKEY_VERSION_OFF + 4]
            .try_into()
            .ok()?,
    );
    if !matches!(version, 1 | 2) {
        return None;
    }

    // pubexp_bits ∈ {2048, 4096}
    let pubexp_bits = u32::from_le_bytes(
        h[PUBKEY_PUBEXP_BITS_OFF..PUBKEY_PUBEXP_BITS_OFF + 4]
            .try_into()
            .ok()?,
    );
    if !matches!(pubexp_bits, 2048 | 4096) {
        return None;
    }

    // modulus_bits == pubexp_bits
    let modulus_bits = u32::from_le_bytes(
        h[PUBKEY_MODULUS_BITS_OFF..PUBKEY_MODULUS_BITS_OFF + 4]
            .try_into()
            .ok()?,
    );
    if modulus_bits != pubexp_bits {
        return None;
    }

    // Length covers header + pubexp + modulus.
    let pubexp_size = (pubexp_bits / 8) as usize;
    let modulus_size = (modulus_bits / 8) as usize;
    let total = PUBKEY_HEADER_LEN + pubexp_size + modulus_size;
    if local + total > bytes.len() {
        return None;
    }

    // pubexp prefix == 01 00 01 00 (RSA F4, little-endian).
    if h[PUBKEY_PUBEXP_OFF..PUBKEY_PUBEXP_OFF + 4] != RSA_F4_LE_PREFIX {
        return None;
    }

    let mut key_id = [0u8; 16];
    key_id.copy_from_slice(&h[PUBKEY_KEY_ID_OFF..PUBKEY_KEY_ID_OFF + 16]);

    Some(KeyHit {
        offset: FlashOffset(blob_start + local as u64),
        key_id,
        modulus_size: modulus_size as u32,
        location: KeyHitLocation::Heuristic,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use psptool_core::{Fet, FlashOffset, RomSize, SourceBytes};

    use crate::tests_support::{
        SyntheticPubkey, build_synthetic_rom_with_signed_entry, generate_test_keypair,
    };

    fn parse_fet_at_zero(blob: &SourceBytes) -> Fet {
        Fet::parse_at(blob, FlashOffset(0)).expect("FET parse")
    }

    #[test]
    fn structured_walk_finds_pubkey_entry() {
        let (priv_key, pub_key) = generate_test_keypair();
        let pk = SyntheticPubkey::from_key(&pub_key, [0xA1; 16], [0xA1; 16]);
        let (rom_bytes, _, _, _) =
            build_synthetic_rom_with_signed_entry(&priv_key, &pk, b"structured-only");
        let blob = SourceBytes::from_blob(rom_bytes);
        let fet = parse_fet_at_zero(&blob);
        let hits = search_keys(&blob, &fet, RomSize::MIB_16, FlashOffset::ZERO);

        // The synthetic ROM has exactly one directory pubkey at offset 0x80.
        let structured: Vec<&KeyHit> = hits
            .iter()
            .filter(|h| matches!(h.location, KeyHitLocation::Structured(_)))
            .collect();
        assert_eq!(
            structured.len(),
            1,
            "expected exactly 1 structured hit, got {hits:#?}",
        );
        let hit = structured[0];
        assert_eq!(hit.offset, FlashOffset(0x080));
        assert_eq!(hit.key_id, [0xA1; 16]);
        assert_eq!(hit.modulus_size, 256);
        assert!(matches!(
            hit.location,
            KeyHitLocation::Structured(EntryRef {
                directory_index: 0,
                entry_index: 0,
            })
        ));

        // No heuristic hit at the same place — the structured-range filter
        // must drop the duplicate even though the bytes match the heuristic.
        let heuristic_at_structured = hits.iter().any(|h| {
            matches!(h.location, KeyHitLocation::Heuristic) && h.offset == FlashOffset(0x080)
        });
        assert!(
            !heuristic_at_structured,
            "structured pubkey must not be re-reported as heuristic, got {hits:#?}",
        );
    }

    /// Place a syntactically-valid PubkeyFile blob into the unused tail of a
    /// synthetic ROM (well past every directory body) so the heuristic
    /// scanner can find it but the directory walk cannot.
    fn rom_with_inline_pubkey() -> (Vec<u8>, usize, [u8; 16], SyntheticPubkey, [u8; 16]) {
        let (priv_key, pub_key) = generate_test_keypair();
        // Structured pubkey lives in the directory.
        let dir_pk = SyntheticPubkey::from_key(&pub_key, [0xB2; 16], [0xB2; 16]);
        let dir_pk_id = dir_pk.key_id;
        let (mut rom_bytes, _, _, _) =
            build_synthetic_rom_with_signed_entry(&priv_key, &dir_pk, b"heuristic-test");

        // Build a second, syntactically-valid pubkey blob with a different
        // key_id and embed it in unused space well past the existing layout.
        let inline_pk = SyntheticPubkey::from_key(&pub_key, [0xCD; 16], [0xEF; 16]);
        let inline_pk_id = inline_pk.key_id;
        let inline_off = 0xC00usize;
        // Sanity: the synthetic ROM is at least 0x1000 bytes and 0xC00 is
        // beyond the directory body region (which ends well below 0x800
        // since the pubkey lives at 0x080..0x320 and the header at 0x300+).
        // Re-confirm by checking we're not overwriting the signature region.
        let pk_len = inline_pk.bytes.len();
        assert!(inline_off + pk_len <= rom_bytes.len());
        rom_bytes[inline_off..inline_off + pk_len].copy_from_slice(&inline_pk.bytes);

        (rom_bytes, inline_off, inline_pk_id, inline_pk, dir_pk_id)
    }

    #[test]
    fn heuristic_scan_finds_inline_pubkey() {
        let (rom_bytes, inline_off, inline_pk_id, _inline_pk, _dir_pk_id) =
            rom_with_inline_pubkey();
        let blob = SourceBytes::from_blob(rom_bytes);
        let fet = parse_fet_at_zero(&blob);
        let hits = search_keys(&blob, &fet, RomSize::MIB_16, FlashOffset::ZERO);

        let heuristic: Vec<&KeyHit> = hits
            .iter()
            .filter(|h| matches!(h.location, KeyHitLocation::Heuristic))
            .collect();

        let inline_hit = heuristic
            .iter()
            .find(|h| h.offset == FlashOffset(inline_off as u64))
            .unwrap_or_else(|| panic!("no heuristic hit at 0x{inline_off:x}; got {hits:#?}"));
        assert_eq!(inline_hit.key_id, inline_pk_id);
        assert_eq!(inline_hit.modulus_size, 256);
    }

    #[test]
    fn structured_and_heuristic_coexist_distinct_offsets() {
        let (rom_bytes, inline_off, inline_pk_id, _inline_pk, dir_pk_id) = rom_with_inline_pubkey();
        let blob = SourceBytes::from_blob(rom_bytes);
        let fet = parse_fet_at_zero(&blob);
        let hits = search_keys(&blob, &fet, RomSize::MIB_16, FlashOffset::ZERO);

        // Exactly one Structured + one Heuristic hit (the rest of the ROM
        // is zeros, which can't satisfy version ∈ {1,2}).
        let structured = hits
            .iter()
            .filter(|h| matches!(h.location, KeyHitLocation::Structured(_)))
            .count();
        let heuristic = hits
            .iter()
            .filter(|h| matches!(h.location, KeyHitLocation::Heuristic))
            .count();
        assert_eq!(structured, 1, "want 1 structured, got {hits:#?}");
        assert_eq!(heuristic, 1, "want 1 heuristic, got {hits:#?}");

        // The structured hit reports the directory pubkey at 0x080.
        let s = hits
            .iter()
            .find(|h| matches!(h.location, KeyHitLocation::Structured(_)))
            .unwrap();
        assert_eq!(s.offset, FlashOffset(0x080));
        assert_eq!(s.key_id, dir_pk_id);

        // The heuristic hit reports the inline pubkey at the planted offset.
        let h = hits
            .iter()
            .find(|h| matches!(h.location, KeyHitLocation::Heuristic))
            .unwrap();
        assert_eq!(h.offset, FlashOffset(inline_off as u64));
        assert_eq!(h.key_id, inline_pk_id);
    }

    #[test]
    fn heuristic_rejects_non_pubkey_bytes() {
        // A blob full of zeros should yield no hits — version is 0 ∉ {1,2}.
        let blob = SourceBytes::from_blob(vec![0u8; 0x1000]);
        let h = (0..0x1000usize)
            .filter_map(|local| try_heuristic_at(blob.as_bytes(), local, 0))
            .count();
        assert_eq!(h, 0);
    }

    #[test]
    fn heuristic_rejects_bad_pubexp_bits() {
        // Build a blob that satisfies all conditions except pubexp_bits.
        let mut buf = vec![0u8; 0x40 + 256 + 256];
        buf[0..4].copy_from_slice(&1u32.to_le_bytes()); // version = 1
        buf[0x38..0x3C].copy_from_slice(&1024u32.to_le_bytes()); // not in {2048, 4096}
        buf[0x3C..0x40].copy_from_slice(&1024u32.to_le_bytes());
        buf[0x40..0x44].copy_from_slice(&[0x01, 0x00, 0x01, 0x00]);
        let blob = SourceBytes::from_blob(buf);
        assert!(try_heuristic_at(blob.as_bytes(), 0, 0).is_none());
    }

    #[test]
    fn heuristic_rejects_pubexp_modulus_mismatch() {
        let mut buf = vec![0u8; 0x40 + 256 + 256];
        buf[0..4].copy_from_slice(&1u32.to_le_bytes());
        buf[0x38..0x3C].copy_from_slice(&2048u32.to_le_bytes());
        buf[0x3C..0x40].copy_from_slice(&4096u32.to_le_bytes()); // mismatched
        buf[0x40..0x44].copy_from_slice(&[0x01, 0x00, 0x01, 0x00]);
        let blob = SourceBytes::from_blob(buf);
        assert!(try_heuristic_at(blob.as_bytes(), 0, 0).is_none());
    }

    #[test]
    fn heuristic_rejects_wrong_pubexp_value() {
        let mut buf = vec![0u8; 0x40 + 256 + 256];
        buf[0..4].copy_from_slice(&1u32.to_le_bytes());
        buf[0x38..0x3C].copy_from_slice(&2048u32.to_le_bytes());
        buf[0x3C..0x40].copy_from_slice(&2048u32.to_le_bytes());
        // exponent != 0x10001
        buf[0x40..0x44].copy_from_slice(&[0x03, 0x00, 0x00, 0x00]);
        let blob = SourceBytes::from_blob(buf);
        assert!(try_heuristic_at(blob.as_bytes(), 0, 0).is_none());
    }

    #[test]
    fn heuristic_offset_carries_blob_root() {
        // Heuristic hits must report absolute flash offsets, not local ones.
        let pad = 0x100usize;
        let pk = SyntheticPubkey::from_key(&generate_test_keypair().1, [0x77; 16], [0x77; 16]);
        let mut buf = vec![0u8; pad + pk.bytes.len() + 0x40];
        buf[pad..pad + pk.bytes.len()].copy_from_slice(&pk.bytes);
        let blob = SourceBytes::with_offset(buf, FlashOffset(0xA000_0000));
        let hit = (0..blob.len())
            .find_map(|local| try_heuristic_at(blob.as_bytes(), local, blob.offset().get()))
            .expect("heuristic must find the planted pubkey");
        assert_eq!(hit.offset, FlashOffset(0xA000_0000 + pad as u64));
        assert_eq!(hit.key_id, [0x77; 16]);
    }
}
