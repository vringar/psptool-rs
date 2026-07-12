//! `replace` operation — port of the reference `--replace-file` command (issue
//! #12), without the upstream PR-#77 alignment-corruption bug class.
//!
//! API:
//!
//! ```ignore
//! let mut editor = BlobEditor::from_blob(blob);
//! replace_entry_body(&mut editor, &parent_dir, entry_index, &new_body)?;
//! let new_rom = editor.serialize();
//! ```
//!
//! ## Guarantees
//!
//! * **Sibling entries** — byte-identical to source. The writer only patches
//!   the entry body slot and (when the length changed) the 4-byte `size` field
//!   of the entry's directory record plus the parent directory's 4-byte
//!   Fletcher-32 checksum field.
//! * **Directory checksum** — a length-changing replace rewrites the `size`
//!   field inside the directory's checksummed region (`self[0x8:]`,
//!   `directory.py:204`), so the parent directory's Fletcher-32 header field is
//!   recomputed over the post-replace region and patched at directory `+0x04`,
//!   mirroring upstream `Directory.update_checksum` (`directory.py:203-205`,
//!   called unconditionally on every replace via `directory.py:241`). The
//!   entry-only [`replace_entry_body`] path has no parent-directory handle and
//!   therefore leaves the checksum untouched.
//! * **Padding bytes** — byte-identical to source. When the new body is
//!   *shorter* than the original slot, the trailing bytes of the slot stay
//!   verbatim (we do not zero them and we do not round up).
//! * **`size` rewrite** — exact, no `0x10`-alignment rounding. PSPTool's
//!   `File.move_buffer` rounds the new size up to a 16-byte boundary
//!   (`File.ENTRY_ALIGNMENT`); the upstream PR
//!   <https://github.com/PSPReverse/PSPTool/pull/77> demonstrated that this
//!   silently corrupts neighbours when the actual entry layout was finer than
//!   `0x10`. We rewrite `size` with the caller's exact byte count.
//! * **Overflow detection** — replacing with a body strictly larger than the
//!   original slot is rejected with [`ReplaceError::BodyTooLarge`] rather than
//!   clobbering the next entry.
//!
//! ## Out of scope (deferred)
//!
//! * Re-signing / chain-of-trust (#13).
//! * CLI surface (#15).

use psptool_core::directory::{BiosDirectory, PspDirectory};
use psptool_core::entry::{Entry, EntryClass};
use psptool_core::error::ParseError;
use psptool_core::fletcher::FletcherError;
use psptool_core::source::SourceBytes;
use psptool_core::writer::{BlobEditor, PatchError};
use psptool_core::{FlashOffset, RomSize, fletcher32};
use thiserror::Error;

/// Byte offset of the `size` field within a 16/24-byte directory entry
/// record (PSP-family §3.1, BIOS-family §3.2 — both put `size` at +0x04).
const ENTRY_RECORD_SIZE_OFFSET: usize = 0x04;
/// Length of the `size` field (a little-endian u32).
const ENTRY_RECORD_SIZE_LEN: usize = 4;
/// Byte offset of the directory header's 4-byte Fletcher-32 checksum field
/// (`directory.py:135`; upstream writes it via `set_bytes(0, 4, ...)`).
const DIRECTORY_CHECKSUM_OFFSET: usize = 0x04;
/// First byte of the directory region the Fletcher-32 is computed over —
/// `self[0x8:]` (`directory.py:204`): count + additional_info + entry table,
/// excluding the magic and the checksum field itself.
const DIRECTORY_CHECKSUM_REGION_START: usize = 0x08;

/// Errors returned by [`replace_entry_body`].
#[derive(Debug, Error)]
pub enum ReplaceError {
    /// Re-parsing the parent directory's entry to read the original body slot
    /// failed. Returned when the parent directory is inconsistent with the
    /// blob the [`BlobEditor`] wraps (e.g. wrong directory passed in).
    #[error(transparent)]
    Parse(#[from] ParseError),

    /// The new body would extend past the entry's original slot. Per the
    /// scope rule for #12 we never silently clobber a neighbour: the caller
    /// must shrink the replacement (most replace-with-resign flows do — the
    /// signature trailer length is fixed) or perform a higher-level
    /// re-layout that lives in #13.
    #[error(
        "new body length {requested} exceeds original entry slot {available} \
         (growing entries is not supported by replace_entry_body)"
    )]
    BodyTooLarge { available: usize, requested: usize },

    /// Soft-fuse-chain entries (type `0x0B`) encode their payload in the
    /// directory record itself (§3.4) — there is no separate body to replace.
    /// PSPTool models this with `NO_SIZE_ENTRY_TYPES`; we surface a typed
    /// rejection instead of silently overwriting the record.
    #[error("entry is a soft-fuse-chain — replace_entry_body has no slot to write")]
    SoftFuseChainEntry,

    /// Plumbed from the underlying writer when the patches would land out of
    /// bounds or overlap an already-recorded patch on the same editor.
    #[error(transparent)]
    Patch(#[from] PatchError),

    /// Recomputing the parent directory's Fletcher-32 checksum failed because
    /// its checksummed region (`self[0x8:]`) is not a whole number of 16-bit
    /// words. Upstream aborts identically (`utils.py:291` `struct.error`); a
    /// well-formed directory (16-byte header + fixed-width records) always
    /// yields an even-length region, so this surfaces only a malformed input.
    #[error(transparent)]
    Checksum(#[from] FletcherError),
}

/// Replace a PSP-family entry's body via the diff-and-patch [`BlobEditor`].
///
/// `parent` is the parsed `$PSP` / `$PL2` directory the entry belongs to;
/// `entry_index` is the entry's position in `parent.entries`. `rom_size` is
/// the same value used when the directory was parsed — it threads through to
/// re-resolve the entry's body offset.
///
/// On success the editor has accumulated the patches needed to materialise
/// the new ROM; the caller must still call [`BlobEditor::serialize`].
pub fn replace_psp_entry_body(
    editor: &mut BlobEditor,
    parent: &PspDirectory,
    entry_index: usize,
    rom_size: RomSize,
    rom_origin: FlashOffset,
    new_body: &[u8],
) -> Result<(), ReplaceError> {
    let entry = Entry::parse_psp(editor.original(), parent, entry_index, rom_size, rom_origin)?;
    apply(editor, &entry, Some(&parent.source), new_body)
}

/// Replace a BIOS-family entry's body via the diff-and-patch [`BlobEditor`].
///
/// Mirrors [`replace_psp_entry_body`] for `$BHD` / `$BL2` directories.
pub fn replace_bios_entry_body(
    editor: &mut BlobEditor,
    parent: &BiosDirectory,
    entry_index: usize,
    rom_size: RomSize,
    rom_origin: FlashOffset,
    new_body: &[u8],
) -> Result<(), ReplaceError> {
    let entry = Entry::parse_bios(editor.original(), parent, entry_index, rom_size, rom_origin)?;
    apply(editor, &entry, Some(&parent.source), new_body)
}

/// Replace the body of a pre-parsed [`Entry`].
///
/// The two family-specific helpers exist for callers that already have a
/// `&PspDirectory` / `&BiosDirectory` in hand. Callers who hold an [`Entry`]
/// directly (e.g. iterating over `walk_directories`) can use this entry-point
/// to skip the re-parse.
///
/// `entry` must have been parsed from the *same* blob the editor wraps,
/// otherwise the recorded patches will land at offsets that do not exist in
/// the editor's source bytes (and are rejected as
/// [`PatchError::OutOfBounds`]).
pub fn replace_entry_body(
    editor: &mut BlobEditor,
    entry: &Entry,
    new_body: &[u8],
) -> Result<(), ReplaceError> {
    apply(editor, entry, None, new_body)
}

/// Shared core for the three entry points. `dir_source`, when present, is the
/// parent directory's header+entry-table window; a length-changing replace
/// recomputes its Fletcher-32 checksum. The entry-only [`replace_entry_body`]
/// path has no parent handle and passes `None`, leaving the checksum untouched.
fn apply(
    editor: &mut BlobEditor,
    entry: &Entry,
    dir_source: Option<&SourceBytes>,
    new_body: &[u8],
) -> Result<(), ReplaceError> {
    if matches!(entry.class, EntryClass::SoftFuseChain) {
        return Err(ReplaceError::SoftFuseChainEntry);
    }

    let original_len = entry.body.len();
    if new_body.len() > original_len {
        return Err(ReplaceError::BodyTooLarge {
            available: original_len,
            requested: new_body.len(),
        });
    }

    // If the length changed, rewrite the directory record's `size` field
    // first. Doing this before the body patch keeps the editor's recorded
    // patches consistent even if the body patch fails downstream — but in
    // practice both calls validate up-front against `BlobEditor::original`,
    // so either both succeed or neither commits.
    if new_body.len() != original_len {
        let new_size_bytes = rewrite_size_field(editor, entry, new_body.len())?;
        // The `size` field lands inside the directory's checksummed region
        // (`self[0x8:]`), so upstream recomputes the header Fletcher-32 on
        // every replace (`directory.py:241` → `:203-205`). Mirror that when we
        // hold the parent directory; the entry-only path (`dir_source == None`)
        // has no directory to re-checksum.
        if let Some(dir_source) = dir_source {
            recompute_directory_checksum(editor, dir_source, entry, new_size_bytes)?;
        }
    }

    // Patch only the bytes the caller supplied. Trailing bytes of the
    // original slot stay verbatim from the source — they are now
    // unreferenced data (the parent directory entry's `size` shrank) but
    // we deliberately do not zero them, because doing so would touch bytes
    // beyond the entry-body window that the caller did not ask us to
    // overwrite.
    if !new_body.is_empty() {
        editor.patch(entry.body.offset(), new_body.to_vec())?;
    }

    Ok(())
}

/// Patch the 4-byte little-endian `size` field at `record + 0x04`. `new_size`
/// is guaranteed to fit in `u32` by the caller (it is bounded by the original
/// entry's `size`, which is parsed from a wire `u32`).
fn rewrite_size_field(
    editor: &mut BlobEditor,
    entry: &Entry,
    new_size: usize,
) -> Result<[u8; ENTRY_RECORD_SIZE_LEN], ReplaceError> {
    let new_size_u32 = u32::try_from(new_size).expect("new_size <= original entry.size (a u32)");
    let record = entry.record.source();
    let size_offset = record
        .offset()
        .checked_add(ENTRY_RECORD_SIZE_OFFSET as u64)
        .expect("record offset + 4 fits in u64");
    debug_assert!(record.len() >= ENTRY_RECORD_SIZE_OFFSET + ENTRY_RECORD_SIZE_LEN);
    let size_bytes = new_size_u32.to_le_bytes();
    editor.patch(size_offset, size_bytes.to_vec())?;
    Ok(size_bytes)
}

/// Recompute the parent directory's Fletcher-32 checksum after a length-changing
/// replace and patch it at directory `+0x04`.
///
/// Mirrors upstream `Directory.update_checksum` (`directory.py:203-205`):
/// `data = self[0x8:]; self.checksum.set_bytes(0, 4, fletcher32(data))`. The
/// only mutation inside the checksummed region `self[0x8:]` is the entry's
/// `size` field (`entry.py:109-110`), so we reconstruct the post-replace region
/// from the source directory bytes with `new_size_bytes` spliced in, then write
/// the fresh checksum. `dir_source` covers exactly header + entry table, so the
/// region is `dir_source[0x08 ..]`; for any well-formed directory it is an even
/// byte count and `fletcher32` accepts it.
fn recompute_directory_checksum(
    editor: &mut BlobEditor,
    dir_source: &SourceBytes,
    entry: &Entry,
    new_size_bytes: [u8; ENTRY_RECORD_SIZE_LEN],
) -> Result<(), ReplaceError> {
    let dir_base = dir_source.offset().get();
    let record_base = entry.record.source().offset().get();

    // Position of the 4-byte `size` field within the checksummed region. The
    // record starts at `dir_base + header (>= 0x10)` and the size field sits at
    // `record + 0x04`, so it lies strictly inside `self[0x8:]` for any
    // directory/entry pair the family entry points produce (asserted below).
    debug_assert!(record_base >= dir_base + DIRECTORY_CHECKSUM_REGION_START as u64);
    let size_in_region = (record_base - dir_base) as usize + ENTRY_RECORD_SIZE_OFFSET
        - DIRECTORY_CHECKSUM_REGION_START;

    // Post-replace checksummed region: `dir[0x08 ..]` with the size field
    // spliced to its new value (the sole in-region change). `dir_source` is a
    // parsed directory, hence at least a 16-byte header, so `[0x08..]` holds.
    let mut region = dir_source.as_bytes()[DIRECTORY_CHECKSUM_REGION_START..].to_vec();
    region[size_in_region..size_in_region + ENTRY_RECORD_SIZE_LEN].copy_from_slice(&new_size_bytes);

    let checksum = fletcher32(&region)?;

    let checksum_offset = FlashOffset(dir_base + DIRECTORY_CHECKSUM_OFFSET as u64);
    editor.patch(checksum_offset, checksum.to_le_bytes().to_vec())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use psptool_core::directory::{
        BIOS_ENTRY_SIZE, DIRECTORY_HEADER_SIZE, Directory, PSP_ENTRY_SIZE,
    };
    use psptool_core::{FlashOffset, RomSize, SourceBytes};

    // ------------------------------------------------------------------
    // Helpers — handcrafted single-entry directories.
    // ------------------------------------------------------------------

    /// Build a `$PSP` directory containing one entry of `entry_type` with
    /// `body` placed immediately after the entry record.
    fn psp_dir_with_entry(entry_type: u8, body: &[u8]) -> Vec<u8> {
        let body_off = (DIRECTORY_HEADER_SIZE + PSP_ENTRY_SIZE) as u32;
        let size = body.len() as u32;
        let additional_info = (1u32 << 31) | (0b10u32 << 24);
        let mut entry = [0u8; PSP_ENTRY_SIZE];
        entry[0x00] = entry_type;
        entry[0x04..0x08].copy_from_slice(&size.to_le_bytes());
        entry[0x08..0x0C].copy_from_slice(&body_off.to_le_bytes());
        let entry_rsv0: u32 = 0b10u32 << 30;
        entry[0x0C..0x10].copy_from_slice(&entry_rsv0.to_le_bytes());

        let mut out = Vec::new();
        out.extend_from_slice(b"$PSP");
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&additional_info.to_le_bytes());
        out.extend_from_slice(&entry);
        out.extend_from_slice(body);
        out
    }

    /// Build a `$PSP` directory containing two entries placed back-to-back.
    /// Both bodies live after the (1 header + 2 records) prologue.
    fn psp_dir_with_two_entries(types: [u8; 2], bodies: [&[u8]; 2]) -> (Vec<u8>, [usize; 2]) {
        let prologue = DIRECTORY_HEADER_SIZE + 2 * PSP_ENTRY_SIZE;
        let body0_off = prologue as u32;
        let body1_off = (prologue + bodies[0].len()) as u32;
        let additional_info = (1u32 << 31) | (0b10u32 << 24);
        let entry_rsv0: u32 = 0b10u32 << 30;

        let mut e0 = [0u8; PSP_ENTRY_SIZE];
        e0[0] = types[0];
        e0[4..8].copy_from_slice(&(bodies[0].len() as u32).to_le_bytes());
        e0[8..12].copy_from_slice(&body0_off.to_le_bytes());
        e0[12..16].copy_from_slice(&entry_rsv0.to_le_bytes());

        let mut e1 = [0u8; PSP_ENTRY_SIZE];
        e1[0] = types[1];
        e1[4..8].copy_from_slice(&(bodies[1].len() as u32).to_le_bytes());
        e1[8..12].copy_from_slice(&body1_off.to_le_bytes());
        e1[12..16].copy_from_slice(&entry_rsv0.to_le_bytes());

        let mut out = Vec::new();
        out.extend_from_slice(b"$PSP");
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&2u32.to_le_bytes());
        out.extend_from_slice(&additional_info.to_le_bytes());
        out.extend_from_slice(&e0);
        out.extend_from_slice(&e1);
        out.extend_from_slice(bodies[0]);
        out.extend_from_slice(bodies[1]);

        let abs0 = body0_off as usize;
        let abs1 = body1_off as usize;
        (out, [abs0, abs1])
    }

    fn parse_psp(blob_bytes: Vec<u8>) -> (SourceBytes, PspDirectory) {
        let blob = SourceBytes::from_blob(blob_bytes);
        let dir = match Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
            Directory::Psp(p) => p,
            _ => unreachable!(),
        };
        (blob, dir)
    }

    // ------------------------------------------------------------------
    // Equal-length replacement (the locality property's headline case).
    // ------------------------------------------------------------------

    #[test]
    fn equal_length_replacement_locality() {
        // Two adjacent entries; replace the first; sibling and surrounding
        // bytes must be byte-identical to the source.
        let body0 = vec![0xAAu8; 0x20];
        let body1 = vec![0xBBu8; 0x10];
        let (bytes, [abs0, abs1]) = psp_dir_with_two_entries([0x21, 0x21], [&body0, &body1]);
        let original = bytes.clone();
        let (blob, dir) = parse_psp(bytes);

        let replacement = vec![0xCCu8; 0x20];
        let mut editor = BlobEditor::from_blob(blob);
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

        assert_eq!(out.len(), original.len());
        // First body is overwritten.
        assert_eq!(&out[abs0..abs0 + 0x20], &replacement[..]);
        // Sibling body untouched.
        assert_eq!(&out[abs1..abs1 + 0x10], &body1[..]);
        // Everything outside the patched body matches the source byte-for-byte.
        assert_eq!(&out[..abs0], &original[..abs0]);
        assert_eq!(&out[abs0 + 0x20..], &original[abs0 + 0x20..]);
    }

    #[test]
    fn equal_length_replacement_does_not_touch_record_size_field() {
        // When the replacement length matches the original, the entry record
        // bytes (including the `size` field) stay verbatim.
        let body = vec![0xAAu8; 0x10];
        let bytes = psp_dir_with_entry(0x21, &body);
        let original = bytes.clone();
        let (blob, dir) = parse_psp(bytes);

        let mut editor = BlobEditor::from_blob(blob);
        replace_psp_entry_body(
            &mut editor,
            &dir,
            0,
            RomSize::MIB_16,
            FlashOffset::ZERO,
            &[0xCC; 0x10],
        )
        .unwrap();
        // Exactly one patch — only the body. The record was untouched.
        assert_eq!(editor.patch_count(), 1);

        let out = editor.serialize();
        let record_offset = DIRECTORY_HEADER_SIZE;
        assert_eq!(
            &out[record_offset..record_offset + PSP_ENTRY_SIZE],
            &original[record_offset..record_offset + PSP_ENTRY_SIZE]
        );
    }

    // ------------------------------------------------------------------
    // Shrinking — record.size rewritten with exact length, NO 0x10 rounding.
    // ------------------------------------------------------------------

    #[test]
    fn shrinking_rewrites_size_field_to_exact_length() {
        // Original body 0x40 long. Shrink to 0x33 — a deliberately
        // non-`0x10`-aligned length so a buggy "round to ENTRY_ALIGNMENT"
        // implementation (the PR-#77 class) would fail this test.
        let body = vec![0xAAu8; 0x40];
        let bytes = psp_dir_with_entry(0x21, &body);
        let original = bytes.clone();
        let (blob, dir) = parse_psp(bytes);

        let replacement = vec![0xCCu8; 0x33];
        let mut editor = BlobEditor::from_blob(blob);
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

        // 1) The record's `size` field is now exactly 0x33 (NOT 0x40, NOT
        //    rounded up to 0x10).
        let record_off = DIRECTORY_HEADER_SIZE;
        let size_field_off = record_off + ENTRY_RECORD_SIZE_OFFSET;
        let written_size = u32::from_le_bytes(
            out[size_field_off..size_field_off + ENTRY_RECORD_SIZE_LEN]
                .try_into()
                .unwrap(),
        );
        assert_eq!(written_size, 0x33);

        // 2) The first 0x33 bytes of the body slot are the replacement.
        let body_off = DIRECTORY_HEADER_SIZE + PSP_ENTRY_SIZE;
        assert_eq!(&out[body_off..body_off + 0x33], &replacement[..]);

        // 3) The trailing 0x40 - 0x33 = 0xD bytes of the original slot are
        //    unchanged from the source. We deliberately do NOT zero them.
        assert_eq!(
            &out[body_off + 0x33..body_off + 0x40],
            &original[body_off + 0x33..body_off + 0x40]
        );

        // 4) The record bytes other than the `size` field are unchanged.
        // type byte
        assert_eq!(out[record_off], original[record_off]);
        // offset field at +0x08..+0x0C
        assert_eq!(
            &out[record_off + 8..record_off + 12],
            &original[record_off + 8..record_off + 12]
        );
        // rsv0 at +0x0C..+0x10
        assert_eq!(
            &out[record_off + 12..record_off + 16],
            &original[record_off + 12..record_off + 16]
        );
    }

    // ------------------------------------------------------------------
    // Rejection cases.
    // ------------------------------------------------------------------

    #[test]
    fn rejects_growth_with_typed_error() {
        let body = vec![0xAAu8; 0x10];
        let bytes = psp_dir_with_entry(0x21, &body);
        let (blob, dir) = parse_psp(bytes);

        let mut editor = BlobEditor::from_blob(blob);
        let err = replace_psp_entry_body(
            &mut editor,
            &dir,
            0,
            RomSize::MIB_16,
            FlashOffset::ZERO,
            &[0; 0x11],
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ReplaceError::BodyTooLarge {
                available: 0x10,
                requested: 0x11,
            }
        ));
        // Failed validation must not leave dangling patches.
        assert!(editor.is_clean());
    }

    #[test]
    fn rejects_soft_fuse_chain_entry() {
        // Type 0x0B with the §3.4 sentinel size — the parser returns an
        // `Entry` whose body aliases the record bytes.
        let mut entry = [0u8; PSP_ENTRY_SIZE];
        entry[0x00] = 0x0B;
        entry[0x04..0x08].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        entry[0x08..0x0C].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        entry[0x0C..0x10].copy_from_slice(&0xCAFE_BABEu32.to_le_bytes());

        let additional_info: u32 = (1u32 << 31) | (0b10u32 << 24);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"$PSP");
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&additional_info.to_le_bytes());
        bytes.extend_from_slice(&entry);
        let (blob, dir) = parse_psp(bytes);

        let mut editor = BlobEditor::from_blob(blob);
        let err = replace_psp_entry_body(
            &mut editor,
            &dir,
            0,
            RomSize::MIB_16,
            FlashOffset::ZERO,
            &[0u8; PSP_ENTRY_SIZE],
        )
        .unwrap_err();
        assert!(matches!(err, ReplaceError::SoftFuseChainEntry));
        assert!(editor.is_clean());
    }

    #[test]
    fn empty_replacement_still_rewrites_size_to_zero() {
        // Edge case: replacing with an empty body. The size field becomes 0
        // and no body bytes are patched (writer rejects empty patches as a
        // no-op so this exercises that path).
        let body = vec![0xAAu8; 0x10];
        let bytes = psp_dir_with_entry(0x21, &body);
        let original = bytes.clone();
        let (blob, dir) = parse_psp(bytes);

        let mut editor = BlobEditor::from_blob(blob);
        replace_psp_entry_body(
            &mut editor,
            &dir,
            0,
            RomSize::MIB_16,
            FlashOffset::ZERO,
            &[],
        )
        .unwrap();
        let out = editor.serialize();

        // Size field is 0.
        let size_off = DIRECTORY_HEADER_SIZE + ENTRY_RECORD_SIZE_OFFSET;
        let written = u32::from_le_bytes(out[size_off..size_off + 4].try_into().unwrap());
        assert_eq!(written, 0);
        // Original body bytes still present (we only touched the size field).
        let body_off = DIRECTORY_HEADER_SIZE + PSP_ENTRY_SIZE;
        assert_eq!(
            &out[body_off..body_off + 0x10],
            &original[body_off..body_off + 0x10]
        );
    }

    // ------------------------------------------------------------------
    // BIOS-family parity check.
    // ------------------------------------------------------------------

    fn bios_dir_with_entry(entry_type: u8, body: &[u8]) -> Vec<u8> {
        let body_off = (DIRECTORY_HEADER_SIZE + BIOS_ENTRY_SIZE) as u32;
        let size = body.len() as u32;
        let additional_info = (1u32 << 31) | (0b10u32 << 24);
        let mut entry = [0u8; BIOS_ENTRY_SIZE];
        entry[0x00] = entry_type;
        entry[0x04..0x08].copy_from_slice(&size.to_le_bytes());
        entry[0x08..0x0C].copy_from_slice(&body_off.to_le_bytes());
        let entry_rsv0: u32 = 0b10u32 << 30;
        entry[0x0C..0x10].copy_from_slice(&entry_rsv0.to_le_bytes());
        entry[0x10..0x18].copy_from_slice(&[0xFFu8; 8]); // destination = unused

        let mut out = Vec::new();
        out.extend_from_slice(b"$BHD");
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&additional_info.to_le_bytes());
        out.extend_from_slice(&entry);
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn bios_replace_works_and_size_field_at_same_offset() {
        let body = vec![0x55u8; 0x20];
        let bytes = bios_dir_with_entry(0x62, &body);
        let original = bytes.clone();
        let blob = SourceBytes::from_blob(bytes);
        let dir = match Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
            Directory::Bios(b) => b,
            _ => unreachable!(),
        };

        let replacement = vec![0xEEu8; 0x15]; // shrink to 0x15 — non-aligned
        let mut editor = BlobEditor::from_blob(blob);
        replace_bios_entry_body(
            &mut editor,
            &dir,
            0,
            RomSize::MIB_16,
            FlashOffset::ZERO,
            &replacement,
        )
        .unwrap();
        let out = editor.serialize();

        // BIOS records ALSO put `size` at +0x04 — the same constant we use.
        let size_off = DIRECTORY_HEADER_SIZE + ENTRY_RECORD_SIZE_OFFSET;
        let written = u32::from_le_bytes(out[size_off..size_off + 4].try_into().unwrap());
        assert_eq!(written, 0x15);
        // Tail of slot unchanged.
        let body_off = DIRECTORY_HEADER_SIZE + BIOS_ENTRY_SIZE;
        assert_eq!(
            &out[body_off + 0x15..body_off + 0x20],
            &original[body_off + 0x15..body_off + 0x20]
        );
    }

    // ------------------------------------------------------------------
    // Locality across a layered ROM (FET → directory → entry → body).
    // ------------------------------------------------------------------

    #[test]
    fn replace_via_entry_handle_preserves_everything_else() {
        let body0 = vec![0x11u8; 0x40];
        let body1 = vec![0x22u8; 0x30];
        let (bytes, [abs0, abs1]) = psp_dir_with_two_entries([0x21, 0x21], [&body0, &body1]);
        let original = bytes.clone();
        let (blob, dir) = parse_psp(bytes);
        let entry = Entry::parse_psp(&blob, &dir, 1, RomSize::MIB_16, FlashOffset::ZERO).unwrap();

        let mut editor = BlobEditor::from_blob(blob);
        let replacement = vec![0x33u8; 0x30];
        replace_entry_body(&mut editor, &entry, &replacement).unwrap();
        let out = editor.serialize();

        assert_eq!(&out[abs0..abs0 + body0.len()], &body0[..]);
        assert_eq!(&out[abs1..abs1 + 0x30], &replacement[..]);
        // First record + first body untouched.
        assert_eq!(&out[..abs1], &original[..abs1]);
    }
}
