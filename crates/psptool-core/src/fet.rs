//! Firmware Entry Table (FET) parser.
//!
//! See `docs/firmware-layout.md` §1.1 (discovery) and §1.2 (table layout). A
//! FET is the root of one ROM: a 4-byte magic followed by a flat array of
//! 4-byte little-endian dwords, terminated by 16 bytes of `0xFF`. Each dword
//! is either a *sentinel* (preserved verbatim on roundtrip but not followed)
//! or a *pointer* (a raw [`Address`] whose dereferenced location may begin
//! with a known directory magic).
//!
//! Multi-FET support is provided by [`scan_fet_candidates`], which finds
//! every byte-aligned occurrence of the 8-byte signature
//! `[pad ; FET_MAGIC]` where `pad ∈ {0x00000000, 0xFFFFFFFF}` (§1.1).
//! Callers iterate the candidates, attempting [`Fet::parse_at`] on each — the
//! discovery rule is "first candidate that yields a parseable directory
//! wins"; this module exposes the candidates and the parser separately so the
//! caller can decide.

use crate::address::{Address, FlashOffset};
use crate::error::ParseError;
use crate::magic::{FET_MAGIC, Magic};
use crate::source::SourceBytes;

/// Size of the magic at the start of a FET.
pub const FET_MAGIC_SIZE: usize = 4;
/// Size of each FET slot dword.
pub const FET_SLOT_SIZE: usize = 4;
/// Size of the trailing terminator: 4 consecutive `0xFFFFFFFF` dwords (§1.2).
pub const FET_TERMINATOR_SIZE: usize = 16;

/// A single FET slot.
///
/// Sentinel slots (`0x00000000`, `0xFFFFFFFE`, `0xFFFFFFFF`) are preserved by
/// position so the writer can roundtrip them byte-for-byte. Pointer slots
/// carry a raw [`Address`] — interpretation (PhysicalX86 vs. flash offset)
/// happens at traversal time via [`crate::address::AddressMode`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetSlot {
    /// Skip-but-record: §1.2 calls these out as `0x00000000`, `0xFFFFFFFE`,
    /// or `0xFFFFFFFF`. We do not follow them, but we keep their dword value
    /// so the writer can put them back exactly.
    Sentinel(Address),
    /// A real pointer. Whether it actually dereferences to a directory is
    /// resolved during traversal — §1.2 says "only dwords whose dereferenced
    /// location starts with a known directory magic are followed".
    Pointer(Address),
}

impl FetSlot {
    /// Classify a raw dword according to §1.2.
    #[inline]
    pub const fn classify(addr: Address) -> Self {
        if addr.is_fet_sentinel() {
            Self::Sentinel(addr)
        } else {
            Self::Pointer(addr)
        }
    }

    /// The raw [`Address`] of this slot, regardless of classification.
    #[inline]
    pub const fn address(&self) -> Address {
        match self {
            Self::Sentinel(a) | Self::Pointer(a) => *a,
        }
    }
}

/// One FET slot together with the source bytes it was parsed from.
///
/// Holding the [`SourceBytes`] per slot is what lets the writer mutate a
/// single slot in-place when an upstream caller swaps a directory out (per
/// the diff-and-patch rule, `docs/firmware-layout.md` §8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetSlotRecord {
    pub slot: FetSlot,
    /// 4-byte source slice covering this slot.
    pub source: SourceBytes,
}

/// A parsed Firmware Entry Table.
///
/// The [`source`](Self::source) field covers `[magic .. end-of-terminator]`
/// inclusive, so re-serialising the FET means writing `source.as_bytes()`
/// back into the original blob at `source.offset()`. Mutated slots are
/// patched on top via their per-slot [`FetSlotRecord::source`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fet {
    /// Bytes of the entire FET — magic + every slot + the 16-byte terminator.
    pub source: SourceBytes,
    /// Slots in the order they appear on disk. Sentinels are preserved by
    /// position so `slots[i]` corresponds to slot index `i` from the spec
    /// (`Acer ...` images use slot 1 = `$PSP`, slot 2 = `$BHD`, etc.).
    pub slots: Vec<FetSlotRecord>,
}

impl Fet {
    /// Parse a FET whose magic begins at `magic_offset` inside `blob`.
    ///
    /// `blob` is the substrate the caller wants to root the FET in — usually
    /// the entire input (`SourceBytes::from_blob(...)`), but a subset works
    /// too as long as `magic_offset` lies within `blob.flash_range()`.
    ///
    /// The parser stops at the first run of four consecutive `0xFFFFFFFF`
    /// dwords (§1.2). Single sentinel `0xFFFFFFFF` dwords are preserved as
    /// [`FetSlot::Sentinel`].
    pub fn parse_at(blob: &SourceBytes, magic_offset: FlashOffset) -> Result<Self, ParseError> {
        let blob_start = blob.offset().get();
        let magic_abs = magic_offset.get();
        if magic_abs < blob_start {
            return Err(ParseError::Truncated {
                what: "FET magic",
                offset: magic_offset,
                expected: FET_MAGIC_SIZE,
                available: 0,
            });
        }
        let local_start = (magic_abs - blob_start) as usize;
        let bytes = blob.as_bytes();

        if local_start + FET_MAGIC_SIZE > bytes.len() {
            return Err(ParseError::Truncated {
                what: "FET magic",
                offset: magic_offset,
                expected: FET_MAGIC_SIZE,
                available: bytes.len().saturating_sub(local_start),
            });
        }

        let mut buf = [0u8; FET_MAGIC_SIZE];
        buf.copy_from_slice(&bytes[local_start..local_start + FET_MAGIC_SIZE]);
        let magic = Magic::new(buf);
        if magic != FET_MAGIC {
            return Err(ParseError::BadMagic {
                what: "FET",
                offset: magic_offset,
                got: magic,
                expected: &[FET_MAGIC],
            });
        }

        let mut slots = Vec::new();
        let mut cursor = local_start + FET_MAGIC_SIZE;

        loop {
            // Look ahead for the 16-byte terminator. If the remaining bytes
            // start with four consecutive 0xFFFFFFFF dwords, we're done.
            if cursor + FET_TERMINATOR_SIZE <= bytes.len()
                && bytes[cursor..cursor + FET_TERMINATOR_SIZE]
                    .iter()
                    .all(|&b| b == 0xFF)
            {
                break;
            }

            // Otherwise we need at least one more dword.
            if cursor + FET_SLOT_SIZE > bytes.len() {
                return Err(ParseError::FetUnterminated {
                    offset: magic_offset,
                });
            }
            let raw = u32::from_le_bytes(
                bytes[cursor..cursor + FET_SLOT_SIZE]
                    .try_into()
                    .expect("FET_SLOT_SIZE == 4"),
            );
            let addr = Address(raw);
            let source = blob
                .slice(cursor, FET_SLOT_SIZE)
                .expect("cursor verified in-bounds above");
            slots.push(FetSlotRecord {
                slot: FetSlot::classify(addr),
                source,
            });
            cursor += FET_SLOT_SIZE;
        }

        let total_len = cursor + FET_TERMINATOR_SIZE - local_start;
        let source = blob
            .slice(local_start, total_len)
            .expect("total_len verified in-bounds above");

        Ok(Self { source, slots })
    }

    /// Iterate just the pointer slots (skipping sentinels). Convenient for
    /// directory traversal: `for ptr in fet.pointers() { ... }`.
    pub fn pointers(&self) -> impl Iterator<Item = &FetSlotRecord> {
        self.slots
            .iter()
            .filter(|r| matches!(r.slot, FetSlot::Pointer(_)))
    }
}

/// Scan `blob` for byte-aligned FET candidates.
///
/// Implements §1.1's discovery rule: every byte-aligned occurrence of
/// `\x00\x00\x00\x00\xAA\x55\xAA\x55` or `\xFF\xFF\xFF\xFF\xAA\x55\xAA\x55`
/// is recorded; the returned offset points at the **start of the FET magic**
/// (i.e. the byte after the 4-byte pad).
///
/// Returns absolute [`FlashOffset`]s, derived from `blob.offset()` so the
/// result composes with `Fet::parse_at` regardless of whether `blob` is the
/// entire input or a subset.
pub fn scan_fet_candidates(blob: &SourceBytes) -> Vec<FlashOffset> {
    const SIG_LEN: usize = 8;
    const ZERO_PAD: [u8; SIG_LEN] = [0x00, 0x00, 0x00, 0x00, 0xAA, 0x55, 0xAA, 0x55];
    const FF_PAD: [u8; SIG_LEN] = [0xFF, 0xFF, 0xFF, 0xFF, 0xAA, 0x55, 0xAA, 0x55];

    let bytes = blob.as_bytes();
    if bytes.len() < SIG_LEN {
        return Vec::new();
    }
    let blob_start = blob.offset().get();
    let mut out = Vec::new();
    for i in 0..=bytes.len() - SIG_LEN {
        let win = &bytes[i..i + SIG_LEN];
        if win == ZERO_PAD || win == FF_PAD {
            // Magic begins at i+4 (the byte after the 4-byte pad).
            out.push(FlashOffset(blob_start + (i + 4) as u64));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_blob() -> SourceBytes {
        SourceBytes::from_blob(Vec::<u8>::new())
    }

    #[test]
    fn parse_micro_fixture_fet() {
        // The committed fixture is: magic + slot 0 (0x00000000) + slot 1
        // (0xFFFFFFFE) + 16-byte terminator. Total 28 bytes.
        let bytes = psptool_fixtures::micro::fet().to_vec();
        assert_eq!(
            bytes.len(),
            FET_MAGIC_SIZE + 2 * FET_SLOT_SIZE + FET_TERMINATOR_SIZE
        );
        let blob = SourceBytes::from_blob(bytes);
        let fet = Fet::parse_at(&blob, FlashOffset(0)).expect("parse fixture FET");

        assert_eq!(fet.source.offset(), FlashOffset(0));
        assert_eq!(fet.source.len(), 28);
        assert_eq!(fet.slots.len(), 2);

        // Slot 0: 0x00000000 → sentinel
        assert!(matches!(fet.slots[0].slot, FetSlot::Sentinel(a) if a == Address(0)));
        assert_eq!(fet.slots[0].source.offset(), FlashOffset(4));
        assert_eq!(fet.slots[0].source.len(), 4);

        // Slot 1: 0xFFFFFFFE → sentinel
        assert!(matches!(fet.slots[1].slot, FetSlot::Sentinel(a) if a == Address(0xFFFF_FFFE)));
        assert_eq!(fet.slots[1].source.offset(), FlashOffset(8));

        // No pointers in this fixture.
        assert_eq!(fet.pointers().count(), 0);
    }

    #[test]
    fn parse_at_with_offset_root() {
        // Place the fixture at flash offset 0xFA0000 (a real Zen 2 FET site
        // per docs §1.1) and parse from a `SourceBytes::with_offset` blob.
        let bytes = psptool_fixtures::micro::fet().to_vec();
        let blob = SourceBytes::with_offset(bytes, FlashOffset(0xFA_0000));
        let fet = Fet::parse_at(&blob, FlashOffset(0xFA_0000)).expect("parse offset FET");
        assert_eq!(fet.source.offset(), FlashOffset(0xFA_0000));
        assert_eq!(fet.slots[0].source.offset(), FlashOffset(0xFA_0004));
    }

    #[test]
    fn parse_synthetic_fet_with_pointer_and_single_ff_sentinel() {
        // magic | 0xAABBCCDD (pointer) | 0xFFFFFFFF (single sentinel — NOT
        // the terminator) | 0x12345678 (pointer) | 16-byte terminator
        let mut buf = Vec::new();
        buf.extend_from_slice(FET_MAGIC.as_bytes());
        buf.extend_from_slice(&0xAABB_CCDDu32.to_le_bytes());
        buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // sentinel mid-FET
        buf.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        buf.extend_from_slice(&[0xFF; FET_TERMINATOR_SIZE]);

        let blob = SourceBytes::from_blob(buf);
        let fet = Fet::parse_at(&blob, FlashOffset(0)).expect("parse synthetic FET");

        assert_eq!(fet.slots.len(), 3);
        assert!(matches!(fet.slots[0].slot, FetSlot::Pointer(a) if a == Address(0xAABB_CCDD)));
        assert!(matches!(fet.slots[1].slot, FetSlot::Sentinel(a) if a == Address(0xFFFF_FFFF)));
        assert!(matches!(fet.slots[2].slot, FetSlot::Pointer(a) if a == Address(0x1234_5678)));

        // Pointers iterator skips the sentinel.
        let ptrs: Vec<Address> = fet.pointers().map(|r| r.slot.address()).collect();
        assert_eq!(ptrs, vec![Address(0xAABB_CCDD), Address(0x1234_5678)]);
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"NOPE");
        buf.extend_from_slice(&[0xFF; FET_TERMINATOR_SIZE]);
        let blob = SourceBytes::from_blob(buf);
        let err = Fet::parse_at(&blob, FlashOffset(0)).unwrap_err();
        assert!(matches!(err, ParseError::BadMagic { what: "FET", .. }));
    }

    #[test]
    fn unterminated_fet_is_rejected() {
        // Magic + 1 dword pointer + EOF (no terminator).
        let mut buf = Vec::new();
        buf.extend_from_slice(FET_MAGIC.as_bytes());
        buf.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        let blob = SourceBytes::from_blob(buf);
        let err = Fet::parse_at(&blob, FlashOffset(0)).unwrap_err();
        assert!(matches!(err, ParseError::FetUnterminated { .. }));
    }

    #[test]
    fn truncated_at_magic_is_rejected() {
        let blob = SourceBytes::from_blob(vec![0xAA, 0x55]);
        let err = Fet::parse_at(&blob, FlashOffset(0)).unwrap_err();
        assert!(matches!(
            err,
            ParseError::Truncated {
                what: "FET magic",
                ..
            }
        ));
    }

    #[test]
    fn magic_offset_outside_blob_is_truncated() {
        let blob = SourceBytes::with_offset(vec![0u8; 4], FlashOffset(0x100));
        let err = Fet::parse_at(&blob, FlashOffset(0x80)).unwrap_err();
        assert!(matches!(err, ParseError::Truncated { .. }));
    }

    #[test]
    fn scan_finds_zero_padded_candidate() {
        // pad (0x00000000) | FET magic | trailing junk
        let mut buf = vec![0xDEu8, 0xAD, 0xBE, 0xEF]; // unrelated prefix
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        buf.extend_from_slice(FET_MAGIC.as_bytes());
        buf.extend_from_slice(&[0x99u8; 32]);

        let blob = SourceBytes::from_blob(buf);
        let cands = scan_fet_candidates(&blob);
        assert_eq!(cands, vec![FlashOffset(8)]);
    }

    #[test]
    fn scan_finds_ff_padded_candidate() {
        let mut buf = vec![0u8; 0x100];
        // pad of 0xFF dwords + FET magic at flash offset 0x100.
        buf.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        buf.extend_from_slice(FET_MAGIC.as_bytes());

        let blob = SourceBytes::from_blob(buf);
        let cands = scan_fet_candidates(&blob);
        assert_eq!(cands, vec![FlashOffset(0x104)]);
    }

    #[test]
    fn scan_finds_multiple_candidates() {
        // Multi-FET case: two FETs in the same blob.
        let mut buf = Vec::new();
        // ROM A
        buf.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        buf.extend_from_slice(FET_MAGIC.as_bytes());
        buf.extend_from_slice(&[0u8; 0x100]);
        // ROM B
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        buf.extend_from_slice(FET_MAGIC.as_bytes());
        buf.extend_from_slice(&[0u8; 0x100]);

        let blob = SourceBytes::from_blob(buf);
        let cands = scan_fet_candidates(&blob);
        assert_eq!(cands.len(), 2);
        // First candidate magic is at offset 4 (after the 4-byte FF pad).
        assert_eq!(cands[0], FlashOffset(4));
        // ROM A occupies bytes [0..0x108] (4 pad + 4 magic + 0x100 trailing).
        // ROM B starts at 0x108: 4 zero pad, then magic at 0x10C.
        assert_eq!(cands[1], FlashOffset(0x10C));
    }

    #[test]
    fn scan_ignores_unpadded_magic() {
        // FET magic at offset 0 with no pad before it → not a valid candidate.
        let mut buf = Vec::new();
        buf.extend_from_slice(FET_MAGIC.as_bytes());
        buf.extend_from_slice(&[0u8; 16]);
        let blob = SourceBytes::from_blob(buf);
        assert!(scan_fet_candidates(&blob).is_empty());
    }

    #[test]
    fn scan_respects_blob_root_offset() {
        // Blob rooted at 0x20_0000 (capsule envelope offset) — candidates
        // must be reported in absolute flash space.
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        buf.extend_from_slice(FET_MAGIC.as_bytes());
        let blob = SourceBytes::with_offset(buf, FlashOffset(0x20_0000));
        let cands = scan_fet_candidates(&blob);
        assert_eq!(cands, vec![FlashOffset(0x20_0004)]);
    }

    #[test]
    fn scan_empty_blob() {
        assert!(scan_fet_candidates(&empty_blob()).is_empty());
    }
}
