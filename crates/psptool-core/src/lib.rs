//! `psptool-core` — wire-format types, parser, typed domain model, and the
//! byte-exact diff-and-patch writer for AMD PSP firmware images.
//!
//! This crate is built up issue-by-issue. Issue #5 lays the **substrate**:
//!
//! * [`address`] — `AddressMode` enum, address-mode arithmetic per
//!   `docs/firmware-layout.md` §1.3 / §2.2, plus `FlashOffset` / `RomSize` /
//!   `Address` newtypes.
//! * [`magic`] — 4-byte magic constants for FET, directories, HeaderFile, and
//!   KeyStoreFile, plus a [`magic::DirectoryFamily`] dispatch helper.
//! * [`id`] — `EntryType`, `DirectoryId`, and `PspGenerationId` newtypes that
//!   prevent unit confusion at API boundaries.
//! * [`source`] — `SourceBytes`, the refcounted, offset-tracking byte slice
//!   that every parsed structure retains so the writer can do diff-and-patch
//!   roundtripping (`docs/firmware-layout.md` §8).
//!
//! Subsequent issues (#6–#9) build the parser/serializer on top of these.

#![forbid(unsafe_code)]

pub mod address;
pub mod id;
pub mod magic;
pub mod source;

pub use address::{Address, AddressMode, FlashOffset, ResolveContext, ResolveError, RomSize};
pub use id::{DirectoryId, DirectoryKind, EntryType, PspGenerationId, ZenGeneration};
pub use magic::{
    BHD_MAGIC, BL2_MAGIC, COMBO_BHD_MAGIC, COMBO_PSP_MAGIC, DirectoryFamily, FET_MAGIC, KDB_MAGIC,
    Magic, PL2_MAGIC, PS1_MAGIC, PSP_MAGIC, directory_family,
};
pub use source::SourceBytes;

/// Crate version, sourced from Cargo at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_matches_cargo_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert!(!VERSION.is_empty());
    }
}
