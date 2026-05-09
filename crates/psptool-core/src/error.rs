//! Shared parser error type for `psptool-core`.
//!
//! Parsers in this crate return `Result<_, ParseError>`. The variants are kept
//! deliberately coarse — granular diagnostics live in subsequent issues
//! (entry-kind dispatch, header-file decode) where richer context is
//! available.

use thiserror::Error;

use crate::address::FlashOffset;
use crate::magic::Magic;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// A fixed-size structure expected `expected` bytes but only `available`
    /// were left in the source slice.
    #[error("truncated {what} at {offset}: expected {expected} bytes, only {available} available")]
    Truncated {
        what: &'static str,
        offset: FlashOffset,
        expected: usize,
        available: usize,
    },

    /// A magic-tagged structure carried a tag this parser does not recognise.
    /// `expected` lists the magics the parser was willing to accept.
    #[error("bad magic at {offset}: got {got:?}, expected one of {expected:?}")]
    BadMagic {
        what: &'static str,
        offset: FlashOffset,
        got: Magic,
        expected: &'static [Magic],
    },

    /// The Firmware Entry Table at this offset has no terminator within the
    /// remaining source bytes (§1.2 expects 4 consecutive `0xFFFFFFFF`).
    #[error("FET at {offset} has no terminator within the remaining bytes")]
    FetUnterminated { offset: FlashOffset },

    /// A combo directory's reserved 16-byte block at +0x10..+0x20 was not
    /// all-zero (§2.3 — PSPTool asserts).
    #[error("combo directory at {offset} has non-zero reserved bytes at +0x10..+0x20")]
    ComboReservedNonZero { offset: FlashOffset },
}
