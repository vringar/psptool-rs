//! Byte-exact diff-and-patch writer.
//!
//! Every parsed structure in `psptool-core` carries a [`SourceBytes`] window
//! pinned to the original blob (see `docs/firmware-layout.md` §8). The writer
//! exploits that to roundtrip mutated ROMs:
//!
//! * Start from the original blob bytes.
//! * For every field the caller mutated, record a *patch*: an absolute flash
//!   offset plus the replacement bytes.
//! * On [`BlobEditor::serialize`], walk the original blob and splice each
//!   patch in at its recorded offset. Bytes not covered by any patch (padding,
//!   reserved fields, sibling entries, even unparsed regions) come through
//!   verbatim.
//!
//! The writer is deliberately dumb — it does not recompute fletcher/sha
//! digests, re-sign signed entries, or shift sibling entries when an entry is
//! replaced with a longer body. Those are higher-level operations that belong
//! to crypto-aware mutation paths (issues #12, #13). What this module
//! guarantees is the substrate: if you don't patch anything, the output is
//! byte-identical to the input; if you do patch something, only the bytes you
//! patched (and nothing else) change in the output.
//!
//! ## Comparison to PSPTool
//!
//! PSPTool's serialiser rebuilds directories from typed structures and
//! re-aligns entries on a hardcoded `0x10` boundary, which corrupts ROMs that
//! used different alignment (see PSPReverse/PSPTool#77). The diff-and-patch
//! model sidesteps that class of bugs entirely: alignment, padding, and any
//! per-image quirks are inherited from the source bytes.

use std::collections::BTreeMap;

use bytes::Bytes;
use thiserror::Error;

use crate::address::FlashOffset;
use crate::entry::Entry;
use crate::source::SourceBytes;

/// Reasons a patch may be rejected.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PatchError {
    /// The patch does not lie entirely within the editor's blob.
    #[error(
        "patch at {offset} length {len} extends past end of blob ({blob_end}) \
         (blob starts at {blob_start})"
    )]
    OutOfBounds {
        offset: FlashOffset,
        len: usize,
        blob_start: FlashOffset,
        blob_end: FlashOffset,
    },

    /// The patch overlaps an already-recorded patch. Overlapping patches are
    /// rejected because the resulting bytes would depend on application order.
    #[error("patch at {start}..{end} overlaps existing patch at {existing_start}..{existing_end}")]
    Overlap {
        start: FlashOffset,
        end: FlashOffset,
        existing_start: FlashOffset,
        existing_end: FlashOffset,
    },

    /// `EntryEditor::set_body` was called with a replacement of a different
    /// length than the original body. Length-changing replacement requires
    /// adjusting the parent directory entry's `size` (and possibly `offset`)
    /// fields and re-laying-out neighbours; that lives in the `psptool-ops`
    /// `replace-entry-body` path (#12), not here.
    #[error("entry-body replacement length {got} != original {expected}")]
    BodyLengthMismatch { expected: usize, got: usize },
}

/// A diff-and-patch editor over a parsed blob.
///
/// The editor borrows the original blob (via a cheap [`SourceBytes`] clone)
/// and accumulates an ordered, non-overlapping set of patches. Call
/// [`Self::serialize`] to render the final byte image.
#[derive(Debug, Clone)]
pub struct BlobEditor {
    original: SourceBytes,
    /// Map of absolute flash offset → replacement bytes. Keys are unique and
    /// the byte ranges `[k, k + v.len())` are non-overlapping by construction
    /// (enforced in [`Self::patch`]).
    patches: BTreeMap<u64, Bytes>,
}

impl BlobEditor {
    /// Wrap a parsed blob. The caller usually passes the same `SourceBytes`
    /// that was handed to the parser (`SourceBytes::from_blob(...)`); a
    /// rooted-at-offset blob also works as long as every patch lies within
    /// its [`SourceBytes::flash_range`].
    pub fn from_blob(blob: SourceBytes) -> Self {
        Self {
            original: blob,
            patches: BTreeMap::new(),
        }
    }

    /// The original blob this editor was constructed from.
    #[inline]
    pub fn original(&self) -> &SourceBytes {
        &self.original
    }

    /// `true` iff no patches have been recorded — `serialize()` would emit the
    /// original bytes verbatim.
    #[inline]
    pub fn is_clean(&self) -> bool {
        self.patches.is_empty()
    }

    /// Number of recorded patches.
    #[inline]
    pub fn patch_count(&self) -> usize {
        self.patches.len()
    }

    /// Iterate recorded patches in ascending offset order.
    pub fn patches(&self) -> impl Iterator<Item = (FlashOffset, &[u8])> + '_ {
        self.patches
            .iter()
            .map(|(&off, bytes)| (FlashOffset(off), bytes.as_ref()))
    }

    /// Record a patch at absolute flash `offset`.
    ///
    /// Validates that the replacement lies within the blob and does not
    /// overlap any previously-recorded patch. Empty replacements are accepted
    /// as a no-op (no patch is stored).
    pub fn patch(
        &mut self,
        offset: FlashOffset,
        bytes: impl Into<Bytes>,
    ) -> Result<(), PatchError> {
        let bytes: Bytes = bytes.into();
        let len = bytes.len();
        if len == 0 {
            return Ok(());
        }
        let start = offset.get();
        let blob = self.original.flash_range();
        let end = start
            .checked_add(len as u64)
            .filter(|&e| e <= blob.end)
            .ok_or(PatchError::OutOfBounds {
                offset,
                len,
                blob_start: FlashOffset(blob.start),
                blob_end: FlashOffset(blob.end),
            })?;
        if start < blob.start {
            return Err(PatchError::OutOfBounds {
                offset,
                len,
                blob_start: FlashOffset(blob.start),
                blob_end: FlashOffset(blob.end),
            });
        }

        // Reject overlap with any patch whose start lies within [start, end).
        if let Some((&existing_start, existing_bytes)) = self.patches.range(start..end).next() {
            let existing_end = existing_start + existing_bytes.len() as u64;
            return Err(PatchError::Overlap {
                start: FlashOffset(start),
                end: FlashOffset(end),
                existing_start: FlashOffset(existing_start),
                existing_end: FlashOffset(existing_end),
            });
        }
        // Reject overlap with the immediately-preceding patch when its tail
        // crosses our start.
        if let Some((&existing_start, existing_bytes)) = self.patches.range(..start).next_back() {
            let existing_end = existing_start + existing_bytes.len() as u64;
            if existing_end > start {
                return Err(PatchError::Overlap {
                    start: FlashOffset(start),
                    end: FlashOffset(end),
                    existing_start: FlashOffset(existing_start),
                    existing_end: FlashOffset(existing_end),
                });
            }
        }

        self.patches.insert(start, bytes);
        Ok(())
    }

    /// Replace the bytes covered by `target` with `replacement`. Length must
    /// match `target.len()`; mismatched lengths are surfaced as
    /// [`PatchError::BodyLengthMismatch`] so callers can either resize the
    /// surrounding structure first or drop down to [`Self::patch`] with a
    /// different range.
    pub fn patch_source(
        &mut self,
        target: &SourceBytes,
        replacement: impl Into<Bytes>,
    ) -> Result<(), PatchError> {
        let replacement: Bytes = replacement.into();
        if replacement.len() != target.len() {
            return Err(PatchError::BodyLengthMismatch {
                expected: target.len(),
                got: replacement.len(),
            });
        }
        self.patch(target.offset(), replacement)
    }

    /// Convenience editor for a single parsed [`Entry`]. The returned helper
    /// holds a borrow of `self`; finish the mutation (e.g. via `set_body`) to
    /// release it.
    pub fn entry<'a>(&'a mut self, entry: &'a Entry) -> EntryEditor<'a> {
        EntryEditor {
            editor: self,
            entry,
        }
    }

    /// Render the final byte image: a fresh `Vec<u8>` of `original.len()`
    /// bytes, with every patch spliced in at its recorded offset.
    ///
    /// Bytes not covered by any patch are byte-identical to
    /// `self.original().as_bytes()`.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = self.original.as_bytes().to_vec();
        let base = self.original.offset().get();
        for (&abs_off, bytes) in &self.patches {
            // `patch()` validated bounds at insertion; this subtraction and
            // slice are guaranteed in-range.
            let local = (abs_off - base) as usize;
            out[local..local + bytes.len()].copy_from_slice(bytes);
        }
        out
    }
}

/// Per-entry mutation helper returned by [`BlobEditor::entry`].
pub struct EntryEditor<'a> {
    editor: &'a mut BlobEditor,
    entry: &'a Entry,
}

impl<'a> EntryEditor<'a> {
    /// Replace the entry body bytes. Length must equal the original body
    /// length — replacing with a different size is the responsibility of the
    /// `psptool-ops` `replace-entry-body` path (#12), which adjusts the
    /// parent directory entry's `size`/`offset` fields and re-lays-out
    /// siblings.
    pub fn set_body(self, new_body: impl Into<Bytes>) -> Result<(), PatchError> {
        let new_body: Bytes = new_body.into();
        if new_body.len() != self.entry.body.len() {
            return Err(PatchError::BodyLengthMismatch {
                expected: self.entry.body.len(),
                got: new_body.len(),
            });
        }
        self.editor.patch(self.entry.body.offset(), new_body)
    }

    /// The entry being edited. Useful when the caller needs to inspect the
    /// directory record to compute the replacement.
    #[inline]
    pub fn entry(&self) -> &Entry {
        self.entry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::directory::{DIRECTORY_HEADER_SIZE, Directory};
    use crate::entry::{Entry, EntryClass, HEADER_FILE_LEN};
    use crate::fet::{FET_TERMINATOR_SIZE, Fet};
    use crate::magic::FET_MAGIC;
    use crate::{FlashOffset, RomSize};

    fn sample_blob() -> Vec<u8> {
        (0u8..=255).cycle().take(0x400).collect()
    }

    // ------------------------------------------------------------------
    // Patch primitive: bounds, overlap, no-op empty, ordering.
    // ------------------------------------------------------------------

    #[test]
    fn unchanged_blob_serialises_byte_exact() {
        let bytes = sample_blob();
        let editor = BlobEditor::from_blob(SourceBytes::from_blob(bytes.clone()));
        assert!(editor.is_clean());
        assert_eq!(editor.patch_count(), 0);
        assert_eq!(editor.serialize(), bytes);
    }

    #[test]
    fn single_patch_changes_only_that_range() {
        let bytes = sample_blob();
        let original = bytes.clone();
        let mut editor = BlobEditor::from_blob(SourceBytes::from_blob(bytes));
        editor
            .patch(FlashOffset(0x100), vec![0xAAu8; 4])
            .expect("patch");
        let out = editor.serialize();

        // The patched range is exactly [0x100, 0x104).
        assert_eq!(&out[0x100..0x104], &[0xAA; 4]);
        assert_eq!(&out[..0x100], &original[..0x100]);
        assert_eq!(&out[0x104..], &original[0x104..]);

        // Mutation locality: count differing bytes — must equal patch length.
        let diff: usize = out.iter().zip(&original).filter(|(a, b)| a != b).count();
        assert_eq!(diff, 4);
    }

    #[test]
    fn multiple_disjoint_patches_apply_independently() {
        let bytes = sample_blob();
        let original = bytes.clone();
        let mut editor = BlobEditor::from_blob(SourceBytes::from_blob(bytes));
        editor.patch(FlashOffset(0x010), vec![0x11u8; 3]).unwrap();
        editor.patch(FlashOffset(0x200), vec![0x22u8; 8]).unwrap();
        editor.patch(FlashOffset(0x100), vec![0x33u8; 2]).unwrap();
        assert_eq!(editor.patch_count(), 3);

        let out = editor.serialize();
        // Inside patches: bytes match what we wrote.
        assert_eq!(&out[0x010..0x013], &[0x11, 0x11, 0x11]);
        assert_eq!(&out[0x100..0x102], &[0x33, 0x33]);
        assert_eq!(&out[0x200..0x208], &[0x22; 8]);

        // Outside patches: bytes are byte-identical to the original.
        let patched: &[core::ops::Range<usize>] = &[0x010..0x013, 0x100..0x102, 0x200..0x208];
        let in_patched = |i: usize| patched.iter().any(|r| r.contains(&i));
        for (i, (a, b)) in out.iter().zip(&original).enumerate() {
            if !in_patched(i) {
                assert_eq!(a, b, "byte {i:#06x} unexpectedly differs");
            }
        }
    }

    #[test]
    fn empty_patch_is_a_noop() {
        let bytes = sample_blob();
        let mut editor = BlobEditor::from_blob(SourceBytes::from_blob(bytes.clone()));
        editor.patch(FlashOffset(0x100), Vec::<u8>::new()).unwrap();
        assert!(editor.is_clean());
        assert_eq!(editor.serialize(), bytes);
    }

    #[test]
    fn out_of_bounds_patches_rejected() {
        let bytes = sample_blob();
        let mut editor = BlobEditor::from_blob(SourceBytes::from_blob(bytes));
        // Past the end.
        let err = editor.patch(FlashOffset(0x3FE), vec![0u8; 4]).unwrap_err();
        assert!(matches!(err, PatchError::OutOfBounds { .. }));

        // Length overflows u64.
        let err = editor
            .patch(FlashOffset(u64::MAX - 1), vec![0u8; 4])
            .unwrap_err();
        assert!(matches!(err, PatchError::OutOfBounds { .. }));
    }

    #[test]
    fn out_of_bounds_before_blob_root_rejected() {
        let bytes = vec![0u8; 0x100];
        let blob = SourceBytes::with_offset(bytes, FlashOffset(0x1000));
        let mut editor = BlobEditor::from_blob(blob);
        // Before the rooted blob start.
        let err = editor.patch(FlashOffset(0x0FF8), vec![0u8; 4]).unwrap_err();
        assert!(matches!(err, PatchError::OutOfBounds { .. }));

        // Inside is fine.
        editor.patch(FlashOffset(0x1010), vec![0xAA; 4]).unwrap();
        let out = editor.serialize();
        assert_eq!(&out[0x10..0x14], &[0xAA; 4]);
    }

    #[test]
    fn overlapping_patches_rejected() {
        let bytes = sample_blob();
        let mut editor = BlobEditor::from_blob(SourceBytes::from_blob(bytes));
        editor.patch(FlashOffset(0x100), vec![0u8; 8]).unwrap();

        // Same offset.
        let err = editor.patch(FlashOffset(0x100), vec![0u8; 1]).unwrap_err();
        assert!(matches!(err, PatchError::Overlap { .. }));
        // Tail overlap — second patch starts inside the first.
        let err = editor.patch(FlashOffset(0x104), vec![0u8; 4]).unwrap_err();
        assert!(matches!(err, PatchError::Overlap { .. }));
        // Head overlap — second patch ends inside the first.
        let err = editor.patch(FlashOffset(0x0FE), vec![0u8; 4]).unwrap_err();
        assert!(matches!(err, PatchError::Overlap { .. }));

        // Adjacent patches (touching but not overlapping) are fine.
        editor.patch(FlashOffset(0x108), vec![0u8; 4]).unwrap();
        editor.patch(FlashOffset(0x0FC), vec![0u8; 4]).unwrap();
        assert_eq!(editor.patch_count(), 3);
    }

    #[test]
    fn patches_iterator_is_sorted_by_offset() {
        let bytes = sample_blob();
        let mut editor = BlobEditor::from_blob(SourceBytes::from_blob(bytes));
        editor.patch(FlashOffset(0x200), vec![0u8; 1]).unwrap();
        editor.patch(FlashOffset(0x010), vec![0u8; 1]).unwrap();
        editor.patch(FlashOffset(0x100), vec![0u8; 1]).unwrap();

        let offsets: Vec<u64> = editor.patches().map(|(off, _)| off.get()).collect();
        assert_eq!(offsets, vec![0x010, 0x100, 0x200]);
    }

    // ------------------------------------------------------------------
    // patch_source: length match required.
    // ------------------------------------------------------------------

    #[test]
    fn patch_source_requires_length_match() {
        let bytes = sample_blob();
        let blob = SourceBytes::from_blob(bytes);
        let target = blob.subslice(0x100..0x110).unwrap();
        let mut editor = BlobEditor::from_blob(blob);

        // Wrong length → BodyLengthMismatch.
        let err = editor.patch_source(&target, vec![0u8; 4]).unwrap_err();
        assert!(matches!(
            err,
            PatchError::BodyLengthMismatch {
                expected: 0x10,
                got: 4
            }
        ));

        // Right length succeeds.
        editor
            .patch_source(&target, vec![0xCDu8; 0x10])
            .expect("patch");
        let out = editor.serialize();
        assert_eq!(&out[0x100..0x110], &[0xCD; 0x10]);
    }

    // ------------------------------------------------------------------
    // Mutation locality across a multi-layer handcrafted ROM:
    //   FET → directory → entry record → entry body → HeaderFile field.
    // ------------------------------------------------------------------

    /// Build a 0x400-byte ROM containing:
    ///   - FET at 0x000 with one pointer slot to the PSP directory at 0x040.
    ///   - PSP directory at 0x040 with one entry of type 0x01 (BOOT_LOADER →
    ///     HeaderEntry classification) whose body lives at 0x100.
    ///   - HeaderFile body at 0x100..0x300 (0x100 header + 0x100 body).
    fn handcrafted_layered_rom() -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];
        // ---- FET at 0x000 ----
        buf[0..4].copy_from_slice(FET_MAGIC.as_bytes());
        // Pointer slot → 0x040 (the PSP directory). FET pointers use
        // PhysicalX86 mode; for a 16 MiB ROM, masking is the identity for
        // small offsets so 0x040 is fine.
        buf[4..8].copy_from_slice(&0x0000_0040u32.to_le_bytes());
        // 16-byte terminator at 0x008..0x018.
        buf[8..0x18].copy_from_slice(&[0xFFu8; FET_TERMINATOR_SIZE]);
        // The remainder up to 0x040 is unparsed padding (stays 0x00).

        // ---- $PSP directory at 0x040 ----
        let dir_off = 0x040usize;
        buf[dir_off..dir_off + 4].copy_from_slice(b"$PSP");
        // checksum (irrelevant — parser does not verify here).
        buf[dir_off + 4..dir_off + 8].copy_from_slice(&0u32.to_le_bytes());
        buf[dir_off + 8..dir_off + 0xC].copy_from_slice(&1u32.to_le_bytes()); // count = 1
        // additional_info: v1 layout (bit 31 set), mode bits[25:24] = 10
        // (DirectoryRelative). Entry-level rsv0 high bits will also be 10
        // so resolve_with_entry uses dir_base + offset.
        let additional_info: u32 = (1u32 << 31) | (0b10u32 << 24);
        buf[dir_off + 0xC..dir_off + 0x10].copy_from_slice(&additional_info.to_le_bytes());

        // Entry record at dir_off + 0x10. Type 0x01, size 0x200, offset
        // 0x100 - 0x040 = 0xC0 (directory-relative), rsv0 mode bits = 10.
        let entry_off = dir_off + DIRECTORY_HEADER_SIZE;
        buf[entry_off] = 0x01; // entry_type = PSP_FW_BOOT_LOADER (HeaderFile)
        buf[entry_off + 1] = 0; // subprogram
        buf[entry_off + 2..entry_off + 4].copy_from_slice(&0u16.to_le_bytes()); // flags
        buf[entry_off + 4..entry_off + 8].copy_from_slice(&0x200u32.to_le_bytes()); // size
        buf[entry_off + 8..entry_off + 0xC].copy_from_slice(&0x0C0u32.to_le_bytes()); // offset
        let entry_rsv0: u32 = 0b10u32 << 30;
        buf[entry_off + 0xC..entry_off + 0x10].copy_from_slice(&entry_rsv0.to_le_bytes()); // rsv0

        // ---- HeaderFile body at 0x100 (0x100 header + 0x100 trailing body) ----
        let body_off = 0x100usize;
        // 0x10 leading reserved (PSPTool: certifying-key ID etc.). Leave 0.
        // Magic at +0x10..+0x14 — `$PS1`.
        buf[body_off + 0x10..body_off + 0x14].copy_from_slice(b"$PS1");
        // size_signed at +0x14: HEADER + body covered = 0x110.
        buf[body_off + 0x14..body_off + 0x18].copy_from_slice(&0x110u32.to_le_bytes());
        // is_encrypted = 0 at +0x18..+0x1C, signed = 1 at +0x30..+0x34.
        buf[body_off + 0x30..body_off + 0x34].copy_from_slice(&1u32.to_le_bytes());
        // signature_type = 0 (RSA-2048) at +0x34..+0x38. Leave 0.
        // rom_size at +0x6c = 0x200.
        buf[body_off + 0x6C..body_off + 0x70].copy_from_slice(&0x200u32.to_le_bytes());
        // The remainder of the body is 0x00 — that's the "rest" PSPTool
        // treats as encrypted/compressed/sig payload. Not parsed here.

        buf
    }

    fn parse_layered(blob: &SourceBytes) -> (Fet, Directory, Entry) {
        let fet = Fet::parse_at(blob, FlashOffset(0)).expect("parse FET");
        let dir = Directory::parse_at(blob, FlashOffset(0x040)).expect("parse $PSP");
        let psp = match &dir {
            Directory::Psp(p) => p.clone(),
            _ => unreachable!("$PSP magic"),
        };
        let entry = Entry::parse_psp(blob, &psp, 0, RomSize::MIB_16).expect("parse entry");
        (fet, dir, entry)
    }

    #[test]
    fn layered_rom_unchanged_serialise_roundtrip() {
        // Sanity: the handcrafted ROM parses cleanly and serialises back to
        // the same bytes when no patches are recorded.
        let bytes = handcrafted_layered_rom();
        let blob = SourceBytes::from_blob(bytes.clone());
        let (fet, dir, entry) = parse_layered(&blob);
        // Quick structural sanity to make sure we exercise the full layering.
        assert_eq!(fet.slots.len(), 1);
        assert_eq!(dir.header().count, 1);
        assert!(matches!(entry.class, EntryClass::Header(_)));
        assert_eq!(entry.body.len(), 0x200);

        let editor = BlobEditor::from_blob(blob);
        assert_eq!(editor.serialize(), bytes);
    }

    #[test]
    fn mutation_locality_at_each_layer() {
        // Patch one field at every layer and assert that the diff vs. the
        // original blob is exactly the union of the patched ranges.
        let original = handcrafted_layered_rom();
        let blob = SourceBytes::from_blob(original.clone());
        let (fet, dir, entry) = parse_layered(&blob);

        let mut editor = BlobEditor::from_blob(blob);

        // (a) FET slot 0: rewrite to a different pointer (not actually used by
        // this test — just exercises a 4-byte patch at the FET layer).
        let fet_slot_src = &fet.slots[0].source;
        let fet_slot_off = fet_slot_src.offset().get();
        editor
            .patch_source(fet_slot_src, 0xDEAD_BEEFu32.to_le_bytes().to_vec())
            .unwrap();

        // (b) Directory header: tweak `additional_info` (the 4 bytes at
        // dir+0x0C). Choose a value that preserves the v1+mode10 decoding so
        // re-parsing would still work.
        let dir_src = dir.source();
        let dir_off = dir_src.offset().get();
        let dir_addinfo_off = dir_off + 0x0C;
        let new_addinfo: u32 = (1u32 << 31) | (0b10u32 << 24) | 0x42; // low byte changed
        editor
            .patch(
                FlashOffset(dir_addinfo_off),
                new_addinfo.to_le_bytes().to_vec(),
            )
            .unwrap();

        // (c) Entry record: tweak the `subprogram` byte at +0x01 of the entry
        // record (a 1-byte patch).
        let rec_src = entry.record.source();
        let rec_off = rec_src.offset().get();
        let subprogram_off = rec_off + 0x01;
        editor
            .patch(FlashOffset(subprogram_off), vec![0x77u8])
            .unwrap();

        // (d) Entry body: replace the *trailing* 0x100 body bytes (i.e. the
        // bytes after the 0x100 HeaderFile prefix) with all-0xAB.
        let body_src = &entry.body;
        let trailing_off = body_src.offset().get() + HEADER_FILE_LEN as u64;
        editor
            .patch(FlashOffset(trailing_off), vec![0xABu8; 0x100])
            .unwrap();

        // (e) HeaderFile field: rewrite the `version` 4 bytes at
        // body+0x60..body+0x64 inside the entry body.
        let hdr = match &entry.class {
            EntryClass::Header(h) => h,
            _ => unreachable!(),
        };
        let version_off = hdr.source.offset().get() + 0x60;
        editor
            .patch(FlashOffset(version_off), vec![0x01u8, 0x02, 0x03, 0x04])
            .unwrap();

        assert_eq!(editor.patch_count(), 5);

        let out = editor.serialize();
        assert_eq!(out.len(), original.len());

        // Mutation-locality invariant: every byte outside the patched ranges
        // is byte-identical to the original. Bytes *inside* a patched range
        // may or may not differ (a patch that happens to write the same byte
        // at an offset is a no-op there) but they must match the value we
        // wrote.
        let patched: Vec<core::ops::Range<u64>> = vec![
            fet_slot_off..fet_slot_off + 4,
            dir_addinfo_off..dir_addinfo_off + 4,
            subprogram_off..subprogram_off + 1,
            trailing_off..trailing_off + 0x100,
            version_off..version_off + 4,
        ];
        let in_patched = |i: u64| patched.iter().any(|r| r.contains(&i));
        for (i, (a, b)) in out.iter().zip(&original).enumerate() {
            if !in_patched(i as u64) {
                assert_eq!(
                    a, b,
                    "byte {i:#06x} differs but was outside any patch range",
                );
            }
        }

        // Each patch landed correctly inside its range.
        assert_eq!(
            &out[fet_slot_off as usize..fet_slot_off as usize + 4],
            &0xDEAD_BEEFu32.to_le_bytes()
        );
        assert_eq!(
            &out[dir_addinfo_off as usize..dir_addinfo_off as usize + 4],
            &new_addinfo.to_le_bytes()
        );
        assert_eq!(out[subprogram_off as usize], 0x77);
        assert_eq!(
            &out[trailing_off as usize..trailing_off as usize + 0x100],
            &vec![0xABu8; 0x100][..]
        );
        assert_eq!(
            &out[version_off as usize..version_off as usize + 4],
            &[0x01u8, 0x02, 0x03, 0x04]
        );
    }

    // ------------------------------------------------------------------
    // EntryEditor convenience.
    // ------------------------------------------------------------------

    #[test]
    fn entry_editor_set_body_replaces_only_body_bytes() {
        let original = handcrafted_layered_rom();
        let blob = SourceBytes::from_blob(original.clone());
        let (_fet, _dir, entry) = parse_layered(&blob);
        let body_off = entry.body.offset().get() as usize;
        let body_len = entry.body.len();

        let mut editor = BlobEditor::from_blob(blob);
        editor
            .entry(&entry)
            .set_body(vec![0x5Au8; body_len])
            .expect("set_body");
        let out = editor.serialize();
        assert_eq!(
            &out[body_off..body_off + body_len],
            &vec![0x5A; body_len][..]
        );
        // Bytes outside the body are untouched.
        assert_eq!(&out[..body_off], &original[..body_off]);
        assert_eq!(
            &out[body_off + body_len..],
            &original[body_off + body_len..]
        );
    }

    #[test]
    fn entry_editor_set_body_rejects_length_mismatch() {
        let original = handcrafted_layered_rom();
        let blob = SourceBytes::from_blob(original);
        let (_fet, _dir, entry) = parse_layered(&blob);
        let mut editor = BlobEditor::from_blob(blob);

        let err = editor.entry(&entry).set_body(vec![0u8; 4]).unwrap_err();
        assert!(matches!(
            err,
            PatchError::BodyLengthMismatch {
                expected,
                got: 4,
            }
            if expected == entry.body.len()
        ));
        assert!(
            editor.is_clean(),
            "rejected mutation must not record a patch"
        );
    }

    // ------------------------------------------------------------------
    // Sanity: rooted blobs (capsule envelopes) still roundtrip.
    // ------------------------------------------------------------------

    #[test]
    fn rooted_blob_serialises_to_window_only() {
        // Editor only owns the bytes covered by `original` — `serialize()`
        // returns a Vec of `original.len()` bytes, not the full host file.
        let bytes = vec![0xCDu8; 0x40];
        let blob = SourceBytes::with_offset(bytes.clone(), FlashOffset(0xA7000));
        let mut editor = BlobEditor::from_blob(blob);
        editor.patch(FlashOffset(0xA7008), vec![0x01u8; 4]).unwrap();
        let out = editor.serialize();
        assert_eq!(out.len(), 0x40);
        assert_eq!(&out[..8], &[0xCD; 8]);
        assert_eq!(&out[8..0xC], &[0x01; 4]);
        assert_eq!(&out[0xC..], &vec![0xCD; 0x34][..]);
    }
}
