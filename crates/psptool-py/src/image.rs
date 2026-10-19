//! The one mutable byte buffer every Python view of an image shares.
//!
//! Upstream builds its whole object graph as `NestedBuffer` views over a single
//! `bytearray` (`utils.py:40-114`): a `set_bytes` through any view is visible
//! through every other view and in `PSPTool.to_file`. [`Image`] is that
//! buffer. It is shared by many Python-owned objects (pyo3 requires their
//! fields to be `Send + Sync`), so the bytes sit behind an [`RwLock`]; the
//! invariant the lock protects is only "a read never observes a half-applied
//! write", and every access goes through the bounded [`Image::read`] /
//! [`Image::write`] methods below. The buffer never changes length (see
//! `DEVIATIONS.md`: upstream's `bytearray` slice assignment may resize).
//!
//! A write bumps [`Image::generation`], which invalidates the cached
//! [`Snapshot`] — an immutable [`SourceBytes`] copy plus the image-wide
//! [`CertifyingKeys`] the decode-verification ladder needs. Rebuilding that key
//! map walks the whole image, so it is built at most once per generation.
//!
//! Both buffers register a [`Footprint`]: they are what a dropped parse
//! leaves behind until the cycle collector runs ([`crate::memory`]).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, PoisonError, RwLock};

use psptool_core::body::CertifyingKeys;
use psptool_core::{Ikek, SourceBytes};

use crate::memory::Footprint;

/// IKEK every decryption uses: upstream always unwraps with the Zen+ key
/// (`get_unwrapped_ikek`, `header_file.py:294-307`).
pub const IKEK: Ikek = Ikek::ZenPlus;

/// A shared, fixed-length, mutable image buffer.
#[derive(Debug)]
pub struct Image {
    bytes: RwLock<Vec<u8>>,
    generation: AtomicU64,
    snapshot: RwLock<Option<Arc<Snapshot>>>,
    _footprint: Footprint,
}

/// Immutable view of one generation of an [`Image`].
#[derive(Debug)]
pub struct Snapshot {
    generation: u64,
    source: SourceBytes,
    keys: OnceLock<CertifyingKeys>,
    _footprint: Footprint,
}

impl Snapshot {
    /// The whole image as core-parser input.
    pub fn source(&self) -> &SourceBytes {
        &self.source
    }

    /// The image's certifying keys (`CertificateTree.from_blob`'s key map,
    /// `cert_tree.py:385-406`), built on first use.
    pub fn keys(&self) -> &CertifyingKeys {
        self.keys
            .get_or_init(|| CertifyingKeys::from_blob(&self.source, IKEK))
    }
}

impl Image {
    pub fn new(bytes: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            _footprint: Footprint::new(bytes.len()),
            bytes: RwLock::new(bytes),
            generation: AtomicU64::new(0),
            snapshot: RwLock::new(None),
        })
    }

    /// Bumped by every successful write; keys derived-data caches.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn len(&self) -> usize {
        self.bytes
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copy of `[start, end)`, or `None` when it is not inside the buffer.
    pub fn read(&self, start: usize, end: usize) -> Option<Vec<u8>> {
        let bytes = self.bytes.read().unwrap_or_else(PoisonError::into_inner);
        bytes.get(start..end).map(<[u8]>::to_vec)
    }

    /// Copy of the bytes at `indices` (already normalised by the caller), or
    /// `None` when one is outside the buffer.
    pub fn gather(&self, indices: impl Iterator<Item = usize>) -> Option<Vec<u8>> {
        let bytes = self.bytes.read().unwrap_or_else(PoisonError::into_inner);
        indices.map(|i| bytes.get(i).copied()).collect()
    }

    /// The whole buffer.
    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Overwrite the bytes at `indices` with `data` (same length). Returns
    /// `false`, writing nothing, when an index is outside the buffer.
    pub fn scatter(&self, indices: &[usize], data: &[u8]) -> bool {
        let mut bytes = self.bytes.write().unwrap_or_else(PoisonError::into_inner);
        if indices.len() != data.len() || indices.iter().any(|&i| i >= bytes.len()) {
            return false;
        }
        for (&i, &b) in indices.iter().zip(data) {
            bytes[i] = b;
        }
        drop(bytes);
        self.generation.fetch_add(1, Ordering::AcqRel);
        true
    }

    /// Overwrite `[start, start + data.len())`. Returns `false`, writing
    /// nothing, when the range is outside the buffer.
    pub fn write(&self, start: usize, data: &[u8]) -> bool {
        let mut bytes = self.bytes.write().unwrap_or_else(PoisonError::into_inner);
        let Some(end) = start.checked_add(data.len()) else {
            return false;
        };
        let Some(dst) = bytes.get_mut(start..end) else {
            return false;
        };
        dst.copy_from_slice(data);
        drop(bytes);
        self.generation.fetch_add(1, Ordering::AcqRel);
        true
    }

    /// The current generation's snapshot, rebuilt after a write.
    pub fn snapshot(&self) -> Arc<Snapshot> {
        let generation = self.generation.load(Ordering::Acquire);
        if let Some(snap) = self
            .snapshot
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|s| s.generation == generation)
        {
            return Arc::clone(snap);
        }
        let bytes = self.to_vec();
        let snap = Arc::new(Snapshot {
            generation,
            _footprint: Footprint::new(bytes.len()),
            source: SourceBytes::from_blob(bytes),
            keys: OnceLock::new(),
        });
        *self
            .snapshot
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&snap));
        snap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_invalidates_snapshot() {
        let image = Image::new(vec![0u8; 8]);
        let first = image.snapshot();
        assert!(Arc::ptr_eq(&first, &image.snapshot()));
        assert!(image.write(2, &[1, 2]));
        let second = image.snapshot();
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(second.source().as_bytes(), &[0, 0, 1, 2, 0, 0, 0, 0]);
    }

    #[test]
    fn out_of_bounds_writes_are_rejected_whole() {
        let image = Image::new(vec![0u8; 4]);
        assert!(!image.write(3, &[9, 9]));
        assert!(!image.scatter(&[0, 4], &[9, 9]));
        assert_eq!(image.to_vec(), vec![0; 4]);
        assert_eq!(image.read(1, 5), None);
        assert_eq!(image.gather([3, 0].into_iter()), Some(vec![0, 0]));
    }
}
