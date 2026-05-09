//! Newtype wrappers for primitive IDs used in the PSP wire format.
//!
//! These exist purely to prevent unit confusion at API boundaries (e.g. an
//! `EntryType` should never be silently coerced from a `u8` representing
//! something else). They are deliberately light: `Copy`, `Eq`, `Hash`, and a
//! transparent `repr(transparent)` so they can be read with `binrw` without
//! ceremony.

use core::fmt;

use crate::magic::Magic;

/// PSP-directory-entry `type` byte (§3.1, §3.2). Used to dispatch parsing of
/// the entry body — see `docs/firmware-layout.md` §3.3 / §3.4.
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct EntryType(pub u8);

impl EntryType {
    pub const fn new(b: u8) -> Self {
        Self(b)
    }

    pub const fn get(self) -> u8 {
        self.0
    }

    /// Sub-directory pointer types (§3.3): an entry whose body is another
    /// directory rather than a file. `SECONDARY_DIRECTORY_ENTRY_TYPES` from
    /// `file.py:34`.
    #[inline]
    pub const fn is_secondary_directory_pointer(self) -> bool {
        matches!(self.0, 0x40 | 0x49 | 0x70)
    }

    /// "Tertiary" sub-directory pointer types (Zen 4) — see §3.3.
    /// `TERTIARY_DIRECTORY_ENTRY_TYPES`.
    #[inline]
    pub const fn is_tertiary_directory_pointer(self) -> bool {
        matches!(self.0, 0x48 | 0x4A)
    }

    /// "Soft fuse chain" — `0x0B`. See §3.4.
    #[inline]
    pub const fn is_soft_fuse_chain(self) -> bool {
        self.0 == 0x0B
    }

    /// Pubkey entry types (§3.5, `PUBKEY_ENTRY_TYPES`).
    #[inline]
    pub const fn is_pubkey(self) -> bool {
        matches!(
            self.0,
            0x00 | 0x05 | 0x09 | 0x0A | 0x0D | 0x43 | 0x4E | 0x53 | 0x81 | 0x97 | 0xAD
        )
    }

    /// Key store types (§3.5, `KEY_STORE_TYPES`).
    #[inline]
    pub const fn is_key_store(self) -> bool {
        matches!(self.0, 0x50 | 0x51)
    }

    /// "No size" entry types (`NO_SIZE_ENTRY_TYPES = {0x0B}`). See §3.4: when
    /// `type == 0x0B`, the entry's `size` field is `0xFFFFFFFF` and the body
    /// data lives inline in the entry struct itself.
    #[inline]
    pub const fn has_no_size(self) -> bool {
        self.0 == 0x0B
    }

    /// "No header" entry types — these do **not** carry a HeaderFile prefix
    /// (§3.5, `NO_HDR_ENTRY_TYPES`).
    #[inline]
    pub const fn has_no_header(self) -> bool {
        matches!(
            self.0,
            0x04 | 0x06
                | 0x07
                | 0x0B
                | 0x1A
                | 0x21
                | 0x22
                | 0x38
                | 0x40
                | 0x46
                | 0x48
                | 0x49
                | 0x4A
                | 0x54
                | 0x5F
                | 0x60
                | 0x61
                | 0x62
                | 0x63
                | 0x66
                | 0x67
                | 0x68
                | 0x69
                | 0x6D
                | 0x70
                | 0x7C
                | 0x82
                | 0x84
                | 0x8D
                | 0x98
        )
    }

    /// `WRAPPED_IKEK` (§5).
    #[inline]
    pub const fn is_wrapped_ikek(self) -> bool {
        self.0 == 0x21
    }

    /// BIOS-directory entry type for APOB (§3.4): the entry's address is
    /// always treated as `0` for de-duplication.
    #[inline]
    pub const fn is_bios_apob(self) -> bool {
        self.0 == 0x61
    }
}

impl fmt::Debug for EntryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EntryType({:#04x})", self.0)
    }
}

impl fmt::Display for EntryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#04x}", self.0)
    }
}

/// Identifier for a parsed directory inside a ROM. The wire format does not
/// number directories; this is an internal handle the parser assigns in walk
/// order so downstream code can refer to a directory without keeping a borrow.
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[repr(transparent)]
pub struct DirectoryId(pub u32);

impl DirectoryId {
    pub const fn new(n: u32) -> Self {
        Self(n)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for DirectoryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DirectoryId({})", self.0)
    }
}

/// Directory-header `magic` paired with the family classification (§2). The
/// pair is small enough to copy and survives roundtrip without loss.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct DirectoryKind {
    pub magic: Magic,
    pub family: crate::magic::DirectoryFamily,
}

/// PSP "generation" identifier — a 4-byte tag the PSP exposes via a hardware
/// register, used inside combo directory entries (§2.3). PSPTool only matches
/// the high three bytes; the low byte is a sub-revision.
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct PspGenerationId(pub u32);

impl PspGenerationId {
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn get(self) -> u32 {
        self.0
    }

    /// The high three bytes that PSPTool keys generation matching off.
    #[inline]
    pub const fn high24(self) -> u32 {
        self.0 >> 8
    }

    /// Look up the human-readable Zen generation for this ID.
    /// See §2.3, `directory.py:Directory.ZEN_GENERATION_IDS`.
    pub fn zen_generation(self) -> Option<ZenGeneration> {
        match self.high24() {
            0xBC_09_00 | 0xBC_0A_00 => Some(ZenGeneration::Zen1),
            0xBC_0B_05 | 0xBC_0A_01 => Some(ZenGeneration::Zen2),
            0xBC_0C_01 | 0xBC_0C_00 => Some(ZenGeneration::Zen3),
            0xBC_0D_04 | 0xBC_0D_0B => Some(ZenGeneration::Zen4),
            0xBC_0D_03 => Some(ZenGeneration::Zen4Or5),
            _ => None,
        }
    }
}

impl fmt::Debug for PspGenerationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PspGenerationId({:#010x})", self.0)
    }
}

/// AMD Zen generation labels for combo-directory entries (§2.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ZenGeneration {
    Zen1,
    Zen2,
    Zen3,
    Zen4,
    Zen4Or5,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_type_secondary_directory_pointer() {
        for t in [0x40u8, 0x49, 0x70] {
            assert!(EntryType(t).is_secondary_directory_pointer());
        }
        assert!(!EntryType(0x00).is_secondary_directory_pointer());
        assert!(!EntryType(0x48).is_secondary_directory_pointer());
        assert!(!EntryType(0x4A).is_secondary_directory_pointer());
    }

    #[test]
    fn entry_type_tertiary_directory_pointer() {
        assert!(EntryType(0x48).is_tertiary_directory_pointer());
        assert!(EntryType(0x4A).is_tertiary_directory_pointer());
        assert!(!EntryType(0x40).is_tertiary_directory_pointer());
    }

    #[test]
    fn entry_type_pubkey_set() {
        for t in [
            0x00u8, 0x05, 0x09, 0x0A, 0x0D, 0x43, 0x4E, 0x53, 0x81, 0x97, 0xAD,
        ] {
            assert!(EntryType(t).is_pubkey(), "0x{t:02x} should be pubkey");
        }
        assert!(!EntryType(0x01).is_pubkey());
        assert!(!EntryType(0x44).is_pubkey());
    }

    #[test]
    fn entry_type_key_store() {
        assert!(EntryType(0x50).is_key_store());
        assert!(EntryType(0x51).is_key_store());
        assert!(!EntryType(0x52).is_key_store());
    }

    #[test]
    fn entry_type_no_header_set() {
        for t in [
            0x04u8, 0x06, 0x07, 0x0B, 0x1A, 0x21, 0x22, 0x38, 0x40, 0x46, 0x48, 0x49, 0x4A, 0x54,
            0x5F, 0x60, 0x61, 0x62, 0x63, 0x66, 0x67, 0x68, 0x69, 0x6D, 0x70, 0x7C, 0x82, 0x84,
            0x8D, 0x98,
        ] {
            assert!(
                EntryType(t).has_no_header(),
                "0x{t:02x} should be no-header"
            );
        }
        assert!(!EntryType(0x05).has_no_header());
        assert!(!EntryType(0x50).has_no_header());
    }

    #[test]
    fn entry_type_soft_fuse_chain() {
        assert!(EntryType(0x0B).is_soft_fuse_chain());
        assert!(EntryType(0x0B).has_no_size());
        assert!(!EntryType(0x0C).is_soft_fuse_chain());
    }

    #[test]
    fn entry_type_wrapped_ikek_and_apob() {
        assert!(EntryType(0x21).is_wrapped_ikek());
        assert!(EntryType(0x61).is_bios_apob());
        assert!(!EntryType(0x60).is_wrapped_ikek());
        assert!(!EntryType(0x21).is_bios_apob());
    }

    #[test]
    fn psp_generation_zen2_match() {
        // From corpus example in §2.3
        assert_eq!(
            PspGenerationId(0xBC0B_0500).zen_generation(),
            Some(ZenGeneration::Zen2)
        );
        // §2.3 explicitly notes `BC 0A 01` is also Zen 2.
        assert_eq!(
            PspGenerationId(0xBC0A_0100).zen_generation(),
            Some(ZenGeneration::Zen2)
        );
    }

    #[test]
    fn psp_generation_zen1_match() {
        assert_eq!(
            PspGenerationId(0xBC09_0000).zen_generation(),
            Some(ZenGeneration::Zen1)
        );
        assert_eq!(
            PspGenerationId(0xBC0A_0000).zen_generation(),
            Some(ZenGeneration::Zen1)
        );
    }

    #[test]
    fn psp_generation_low_byte_ignored() {
        // PSPTool only matches the high three bytes — sub-revision in the low
        // byte must not change the generation.
        assert_eq!(
            PspGenerationId(0xBC0B_0500).zen_generation(),
            PspGenerationId(0xBC0B_05FF).zen_generation(),
        );
    }

    #[test]
    fn psp_generation_unknown() {
        assert_eq!(PspGenerationId(0x0000_0000).zen_generation(), None);
        assert_eq!(PspGenerationId(0xDEAD_BEEF).zen_generation(), None);
    }

    #[test]
    fn psp_generation_high24_extracts_top_three_bytes() {
        assert_eq!(PspGenerationId(0xBC0B_05FF).high24(), 0x00BC_0B05);
    }

    #[test]
    fn directory_id_roundtrip() {
        let id = DirectoryId::new(7);
        assert_eq!(id.get(), 7);
        let s = format!("{id:?}");
        assert!(s.contains('7'), "{s}");
    }
}
