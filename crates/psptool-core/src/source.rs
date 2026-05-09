//! `SourceBytes` — the substrate for byte-exact roundtripping.
//!
//! Every parsed structure (FET slot, directory header, directory entry,
//! HeaderFile, etc.) carries a [`SourceBytes`] that points at the exact byte
//! range of the original input it was parsed from. Serialisation is
//! diff-and-patch (see `docs/firmware-layout.md` §8): the writer walks the
//! source bytes and only overwrites bytes the user has explicitly mutated.
//!
//! This module is the only place that knows how to keep that byte range alive
//! cheaply (via [`bytes::Bytes`] reference-counting) and how to map between
//! "offset within this slice" and "offset within the original blob".

use core::ops::Range;

use bytes::Bytes;

use crate::address::FlashOffset;

/// A reference-counted byte slice plus the absolute flash offset where the
/// slice begins in the original input.
///
/// `SourceBytes` is `Clone`-cheap (it just bumps the [`Bytes`] atomic refcount)
/// so every parsed structure can hold its own. The (slice, absolute offset)
/// pair is what makes diff-and-patch sound: a mutation to a parsed structure
/// is recorded as `(absolute offset, replacement bytes)`, and the writer
/// patches the original blob at that exact location.
///
/// Internally, [`Bytes`] already does sub-range refcounting — `bytes.slice(..)`
/// returns a new `Bytes` that shares the underlying allocation. So `bytes`
/// here is **already** the precise window we cover; `flash_offset` is a
/// separate absolute annotation.
#[derive(Clone)]
pub struct SourceBytes {
    /// The byte window this `SourceBytes` covers (already trimmed by any
    /// parent `subslice` calls).
    bytes: Bytes,
    /// Absolute flash offset of byte zero of `bytes`.
    flash_offset: u64,
}

impl SourceBytes {
    /// Wrap an entire input blob as a `SourceBytes` rooted at flash offset 0.
    pub fn from_blob(blob: impl Into<Bytes>) -> Self {
        Self {
            bytes: blob.into(),
            flash_offset: 0,
        }
    }

    /// Construct a `SourceBytes` rooted at an explicit absolute flash offset.
    /// Used by tests and corpus-mock helpers; production code should derive
    /// child slices via [`Self::subslice`] instead.
    pub fn with_offset(blob: impl Into<Bytes>, offset: FlashOffset) -> Self {
        Self {
            bytes: blob.into(),
            flash_offset: offset.get(),
        }
    }

    /// Absolute flash offset of byte zero of this slice (i.e. where `as_bytes()[0]`
    /// lives in the original input).
    #[inline]
    pub const fn offset(&self) -> FlashOffset {
        FlashOffset(self.flash_offset)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The absolute flash-offset range covered by this slice
    /// (`[offset, offset+len)`).
    #[inline]
    pub fn flash_range(&self) -> Range<u64> {
        self.flash_offset..(self.flash_offset + self.len() as u64)
    }

    /// View the slice as raw bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrow access to the underlying refcounted [`Bytes`]. Cheap to clone if
    /// the caller needs an owned handle.
    #[inline]
    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Construct a child `SourceBytes` covering `range` *within this slice*
    /// (i.e. `range` is relative to byte 0 of `self`, not absolute).
    ///
    /// Returns `None` if the range is out of bounds.
    pub fn subslice(&self, range: Range<usize>) -> Option<Self> {
        if range.start > range.end || range.end > self.len() {
            return None;
        }
        let start = range.start;
        Some(Self {
            bytes: self.bytes.slice(range),
            flash_offset: self.flash_offset + start as u64,
        })
    }

    /// Like [`Self::subslice`] but takes an absolute flash-offset range.
    /// Returns `None` if the range falls outside `self`'s flash range.
    pub fn subslice_at(&self, abs: Range<u64>) -> Option<Self> {
        let our = self.flash_range();
        if abs.start < our.start || abs.end > our.end || abs.start > abs.end {
            return None;
        }
        let local_start = (abs.start - our.start) as usize;
        let local_end = (abs.end - our.start) as usize;
        self.subslice(local_start..local_end)
    }

    /// Convenience: subslice of length `len` starting at relative offset
    /// `start`.
    #[inline]
    pub fn slice(&self, start: usize, len: usize) -> Option<Self> {
        let end = start.checked_add(len)?;
        self.subslice(start..end)
    }
}

impl core::fmt::Debug for SourceBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SourceBytes")
            .field("offset", &FlashOffset(self.flash_offset))
            .field("len", &self.len())
            .finish()
    }
}

impl PartialEq for SourceBytes {
    /// Two `SourceBytes` are equal iff they cover the same absolute range and
    /// the underlying bytes match. We deliberately do *not* compare `Bytes`
    /// pointer identity — two slices into different copies of identical input
    /// should compare equal.
    fn eq(&self, other: &Self) -> bool {
        self.flash_offset == other.flash_offset && self.bytes == other.bytes
    }
}

impl Eq for SourceBytes {}

impl AsRef<[u8]> for SourceBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SourceBytes {
        SourceBytes::from_blob(vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
    }

    #[test]
    fn from_blob_covers_input() {
        let s = sample();
        assert_eq!(s.offset(), FlashOffset(0));
        assert_eq!(s.len(), 16);
        assert!(!s.is_empty());
        assert_eq!(s.as_bytes(), (0u8..16).collect::<Vec<_>>());
        assert_eq!(s.flash_range(), 0..16);
    }

    #[test]
    fn with_offset_root() {
        let s = SourceBytes::with_offset(vec![0xAAu8; 4], FlashOffset(0xA7000));
        assert_eq!(s.offset(), FlashOffset(0xA7000));
        assert_eq!(s.len(), 4);
        assert_eq!(s.flash_range(), 0xA7000..0xA7004);
        assert_eq!(s.as_bytes(), &[0xAA, 0xAA, 0xAA, 0xAA]);
    }

    #[test]
    fn subslice_relative() {
        let s = sample();
        let sub = s.subslice(4..10).unwrap();
        assert_eq!(sub.offset(), FlashOffset(4));
        assert_eq!(sub.len(), 6);
        assert_eq!(sub.as_bytes(), &[4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn subslice_propagates_root_offset() {
        let root = SourceBytes::with_offset(
            vec![0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            FlashOffset(0xA7000),
        );
        let sub = root.subslice(4..10).unwrap();
        assert_eq!(sub.offset(), FlashOffset(0xA7004));
        assert_eq!(sub.flash_range(), 0xA7004..0xA700A);
        assert_eq!(sub.as_bytes(), &[4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn subslice_out_of_bounds() {
        let s = sample();
        assert!(s.subslice(0..17).is_none());
        let inverted: Range<usize> = Range { start: 10, end: 5 };
        assert!(s.subslice(inverted).is_none()); // start > end
        assert!(s.subslice(20..30).is_none());
    }

    #[test]
    fn nested_subslice_offset_arithmetic() {
        let root = SourceBytes::with_offset((0u8..16).collect::<Vec<_>>(), FlashOffset(0x100));
        let outer = root.subslice(2..14).unwrap();
        assert_eq!(outer.offset(), FlashOffset(0x102));
        let inner = outer.subslice(3..7).unwrap();
        assert_eq!(inner.offset(), FlashOffset(0x105));
        assert_eq!(inner.len(), 4);
        assert_eq!(inner.as_bytes(), &[5, 6, 7, 8]);
    }

    #[test]
    fn subslice_at_absolute_range() {
        let root = SourceBytes::with_offset((0u8..16).collect::<Vec<_>>(), FlashOffset(0x100));
        let sub = root.subslice_at(0x104..0x10A).unwrap();
        assert_eq!(sub.offset(), FlashOffset(0x104));
        assert_eq!(sub.as_bytes(), &[4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn subslice_at_out_of_bounds() {
        let root = SourceBytes::with_offset((0u8..16).collect::<Vec<_>>(), FlashOffset(0x100));
        assert!(root.subslice_at(0x0FF..0x101).is_none()); // before
        assert!(root.subslice_at(0x110..0x120).is_none()); // after
        let inverted: Range<u64> = Range {
            start: 0x108,
            end: 0x104,
        };
        assert!(root.subslice_at(inverted).is_none()); // inverted
    }

    #[test]
    fn slice_helper() {
        let s = sample();
        let chunk = s.slice(2, 4).unwrap();
        assert_eq!(chunk.as_bytes(), &[2, 3, 4, 5]);
        assert_eq!(chunk.offset(), FlashOffset(2));

        // Past end
        assert!(s.slice(14, 4).is_none());
    }

    #[test]
    fn clone_is_cheap_and_preserves_view() {
        // We can't directly assert refcount semantics in a unit test, but we
        // can at least confirm that cloning yields an identical view.
        let s = sample();
        let t = s.clone();
        assert_eq!(s, t);
        assert_eq!(s.as_bytes(), t.as_bytes());
    }

    #[test]
    fn empty_subslice_allowed() {
        let s = sample();
        let empty = s.subslice(4..4).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.offset(), FlashOffset(4));
        assert_eq!(empty.as_bytes(), b"");
    }

    #[test]
    fn equality_compares_offset_and_bytes() {
        let a = SourceBytes::with_offset(vec![1u8, 2, 3], FlashOffset(0x10));
        let b = SourceBytes::with_offset(vec![1u8, 2, 3], FlashOffset(0x10));
        let c = SourceBytes::with_offset(vec![1u8, 2, 3], FlashOffset(0x20));
        let d = SourceBytes::with_offset(vec![9u8, 9, 9], FlashOffset(0x10));

        assert_eq!(a, b); // same offset, same bytes, different blob
        assert_ne!(a, c); // different offset
        assert_ne!(a, d); // different bytes
    }

    #[test]
    fn debug_format_includes_offset_and_len() {
        let s = SourceBytes::with_offset(vec![0u8; 32], FlashOffset(0xA7000));
        let dbg = format!("{s:?}");
        assert!(dbg.contains("SourceBytes"));
        assert!(dbg.contains("0x000a7000"), "{dbg}");
        assert!(dbg.contains("32"), "{dbg}");
    }

    #[test]
    fn bytes_accessor_returns_owned_handle_to_window() {
        // bytes() returns a refcounted handle to the *window* this SourceBytes
        // covers (parents and children share the same allocation, but
        // `bytes()` reflects only the slice).
        let root = SourceBytes::from_blob((0u8..16).collect::<Vec<_>>());
        let sub = root.subslice(4..8).unwrap();
        assert_eq!(sub.bytes().len(), 4);
        assert_eq!(&sub.bytes()[..], &[4u8, 5, 6, 7]);

        // Cloning the handle is cheap and yields the same content.
        let owned = sub.bytes().clone();
        assert_eq!(&owned[..], sub.as_bytes());
    }
}
