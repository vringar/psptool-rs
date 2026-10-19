//! Native memory the cycle collector cannot see, and the collection it
//! warrants.
//!
//! Upstream's object graph is cyclic (`psptool.blob.psptool is psptool`,
//! `rom.fet.rom is rom`, a view and its `parent_buffer`), so a dropped
//! `PSPTool` is reclaimed by Python's cycle collector, not by reference
//! counting — upstream's and ours alike. The collector schedules itself by
//! *object counts*. A parse here allocates a few thousand Python objects but
//! keeps the image and every decoded body in native buffers the collector
//! never sees, so between two automatic full collections tens of dead parses
//! (each the size of its image or more) pile up: on Python 3.13 a
//! parse-and-drop loop over 16 MiB ROMs settles above 1.3 GiB, where upstream
//! stays near 600 MiB (#98).
//!
//! [`Footprint`] counts those native bytes; [`relieve_pressure`] runs a full
//! collection before a new image is built once they have grown past twice
//! what survived the previous one (and past [`MIN_TRIGGER`]), so the
//! garbage a loop leaves behind is bounded by bytes rather than by object
//! counts.

use std::sync::atomic::{AtomicUsize, Ordering};

use pyo3::prelude::*;

/// Native bytes held by live [`Footprint`]s.
static EXTERNAL_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Native bytes at which [`relieve_pressure`] next collects.
static NEXT_TRIGGER: AtomicUsize = AtomicUsize::new(MIN_TRIGGER);

/// Floor of the collection trigger: up to this many native bytes may be
/// awaiting the collector before a construction forces a full collection.
pub const MIN_TRIGGER: usize = 128 << 20;

/// Registration of `bytes` of native memory owned by a Python-visible object
/// (an image buffer, a snapshot, a decode cache), released on drop.
#[derive(Debug)]
pub struct Footprint(usize);

impl Footprint {
    pub fn new(bytes: usize) -> Self {
        EXTERNAL_BYTES.fetch_add(bytes, Ordering::Relaxed);
        Self(bytes)
    }
}

impl Drop for Footprint {
    fn drop(&mut self) {
        EXTERNAL_BYTES.fetch_sub(self.0, Ordering::Relaxed);
    }
}

/// Native bytes currently registered.
pub fn external_bytes() -> usize {
    EXTERNAL_BYTES.load(Ordering::Relaxed)
}

/// Before building an image of `incoming` bytes: run `gc.collect()` when the
/// registered native bytes would cross the trigger, then re-arm the trigger at
/// twice what survived (at least [`MIN_TRIGGER`]), so collections stay
/// amortised however much the caller keeps alive. Does not collect while the
/// caller has disabled automatic collection (`gc.disable()`).
pub fn relieve_pressure(py: Python<'_>, incoming: usize) -> PyResult<()> {
    if external_bytes().saturating_add(incoming) < NEXT_TRIGGER.load(Ordering::Relaxed) {
        return Ok(());
    }
    let gc = py.import("gc")?;
    if gc.call_method0("isenabled")?.is_truthy()? {
        gc.call_method0("collect")?;
    }
    let survived = external_bytes();
    NEXT_TRIGGER.store(
        MIN_TRIGGER.max(survived.saturating_mul(2)),
        Ordering::Relaxed,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn footprints_are_counted_until_dropped() {
        // Other tests register small images concurrently, so the counter is
        // only bounded, through a size far above anything they hold.
        const SIZE: usize = usize::MAX / 2;
        let token = Footprint::new(SIZE);
        assert!(external_bytes() >= SIZE);
        drop(token);
        assert!(external_bytes() < SIZE);
    }
}
