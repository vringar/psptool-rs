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
//! Issue #6 layers the **wire-format parsers** on top of that substrate:
//!
//! * [`fletcher`] — Fletcher-32 checksum used by directory headers (§2.4).
//! * [`fet`] — `Fet` + `FetSlot`, multi-FET candidate scanner (§1.1, §1.2).
//! * [`directory`] — `$PSP`/`$PL2`/`$BHD`/`$BL2` and combo (`2PSP`/`2BHD`)
//!   directory parsers, plus the FET → directory traversal walk (§2, §3).
//! * [`error`] — shared `ParseError` enum.
//!
//! Subsequent issues (#7–#9) layer entry-kind dispatch, `HeaderFile` decode,
//! and the byte-exact writer on top.
//!
//! Issue #9 adds the **byte-exact diff-and-patch writer** — see [`writer`]:
//!
//! * [`writer::BlobEditor`] — wraps a [`SourceBytes`] blob and accumulates
//!   non-overlapping patches (absolute flash offset → replacement bytes).
//! * [`writer::EntryEditor`] — convenience helper for setting an [`Entry`]
//!   body without touching the surrounding directory record.

#![forbid(unsafe_code)]

pub mod address;
pub mod body;
pub mod directory;
pub mod entry;
pub mod error;
pub mod fet;
pub mod fletcher;
pub mod id;
pub mod magic;
pub mod source;
pub mod writer;

pub use address::{Address, AddressMode, FlashOffset, ResolveContext, ResolveError, RomSize};
pub use body::{BodyError, Ikek, VerifyError};
pub use directory::{
    BiosDirectory, BiosEntry, ComboDirectory, ComboEntry, Directory, DirectoryHeader,
    DirectoryProvenance, DirectoryRef, PspDirectory, PspEntry, walk_directories,
};
pub use entry::{Entry, EntryClass, EntryRecord, HeaderEntry, PubkeyEntry};
pub use error::ParseError;
pub use fet::{
    Fet, FetSlot, FetSlotRecord, KNOWN_FET_OFFSETS, RomLayout, detect_rom_layout,
    scan_fet_candidates,
};
pub use fletcher::fletcher32;
pub use id::{DirectoryId, DirectoryKind, EntryType, PspGenerationId, ZenGeneration};
pub use magic::{
    BHD_MAGIC, BL2_MAGIC, COMBO_BHD_MAGIC, COMBO_PSP_MAGIC, DirectoryFamily, FET_MAGIC, KDB_MAGIC,
    Magic, PL2_MAGIC, PS1_MAGIC, PSP_MAGIC, directory_family,
};
pub use source::SourceBytes;
pub use writer::{BlobEditor, EntryEditor, PatchError};

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
