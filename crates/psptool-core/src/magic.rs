//! Magic constants for the AMD PSP firmware on-disk format.
//!
//! These are the raw 4-byte tags that mark Firmware Entry Tables, directories,
//! and certain HeaderFile / KeyStoreFile bodies. See `docs/firmware-layout.md`
//! §1.2 (FET), §2 (directories), §4 (HeaderFile), §7.2 (KeyStoreFile).

/// 4-byte tag, little-endian on disk. Stored as the bytes literally appear in
/// the file so that comparisons are byte-order-free.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Magic(pub [u8; 4]);

impl Magic {
    #[inline]
    pub const fn new(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }

    /// Construct from a 4-byte ASCII tag (e.g. `b"$PSP"`).
    #[inline]
    pub const fn from_ascii(tag: &[u8; 4]) -> Self {
        Self(*tag)
    }

    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Read the on-disk u32 representation (little-endian).
    #[inline]
    pub const fn as_u32_le(self) -> u32 {
        u32::from_le_bytes(self.0)
    }
}

impl core::fmt::Debug for Magic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // ASCII-printable when possible, otherwise hex.
        if self.0.iter().all(|b| b.is_ascii_graphic()) {
            write!(
                f,
                "Magic({:?})",
                core::str::from_utf8(&self.0).unwrap_or(""),
            )
        } else {
            write!(
                f,
                "Magic([{:#04x}, {:#04x}, {:#04x}, {:#04x}])",
                self.0[0], self.0[1], self.0[2], self.0[3]
            )
        }
    }
}

/// FET magic (§1.2). The 4-byte word *before* this magic must be `0x00000000`
/// or `0xFFFFFFFF` — see §1.1 — but that pad lives outside the FET itself.
pub const FET_MAGIC: Magic = Magic::new([0x55, 0xAA, 0x55, 0xAA]);

/// Primary PSP directory (§2).
pub const PSP_MAGIC: Magic = Magic::from_ascii(b"$PSP");

/// Secondary ("level 2") PSP directory.
pub const PL2_MAGIC: Magic = Magic::from_ascii(b"$PL2");

/// Primary BIOS directory.
pub const BHD_MAGIC: Magic = Magic::from_ascii(b"$BHD");

/// Secondary BIOS directory.
pub const BL2_MAGIC: Magic = Magic::from_ascii(b"$BL2");

/// Combo PSP directory (§2.3).
pub const COMBO_PSP_MAGIC: Magic = Magic::from_ascii(b"2PSP");

/// Combo BIOS directory.
pub const COMBO_BHD_MAGIC: Magic = Magic::from_ascii(b"2BHD");

/// HeaderFile body magic seen on signed entries (§4, offset `0x10`). PSPTool
/// also accepts a four-byte `0x05000000` and other vendor-specific tags here,
/// so this is informational rather than a strict gate.
pub const PS1_MAGIC: Magic = Magic::from_ascii(b"$PS1");

/// KeyStoreFile body magic (§7.2).
pub const KDB_MAGIC: Magic = Magic::from_ascii(b"$KDB");

/// Family classification for the directory magics. Used by callers that need
/// to dispatch on directory shape (PSP vs BIOS vs Combo) without re-hashing
/// the magic.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum DirectoryFamily {
    /// `$PSP` / `$PL2` — 16-byte entries (§3.1).
    Psp,
    /// `$BHD` / `$BL2` — 24-byte entries (§3.2).
    Bios,
    /// `2PSP` / `2BHD` — combo header (§2.3).
    Combo,
}

/// Look up the family of a directory magic. Returns `None` for unrecognised
/// magics — callers must treat unrecognised dwords as non-directories per
/// §1.2 ("Only dwords whose dereferenced location starts with a known
/// directory magic … are followed").
pub fn directory_family(magic: Magic) -> Option<DirectoryFamily> {
    if magic == PSP_MAGIC || magic == PL2_MAGIC {
        Some(DirectoryFamily::Psp)
    } else if magic == BHD_MAGIC || magic == BL2_MAGIC {
        Some(DirectoryFamily::Bios)
    } else if magic == COMBO_PSP_MAGIC || magic == COMBO_BHD_MAGIC {
        Some(DirectoryFamily::Combo)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_magics_match_disk_layout() {
        // PSP-family magics are stored ASCII bytes-as-written.
        assert_eq!(PSP_MAGIC.as_bytes(), b"$PSP");
        assert_eq!(PL2_MAGIC.as_bytes(), b"$PL2");
        assert_eq!(BHD_MAGIC.as_bytes(), b"$BHD");
        assert_eq!(BL2_MAGIC.as_bytes(), b"$BL2");
        assert_eq!(COMBO_PSP_MAGIC.as_bytes(), b"2PSP");
        assert_eq!(COMBO_BHD_MAGIC.as_bytes(), b"2BHD");
        assert_eq!(PS1_MAGIC.as_bytes(), b"$PS1");
        assert_eq!(KDB_MAGIC.as_bytes(), b"$KDB");
    }

    #[test]
    fn fet_magic_byte_order() {
        // §1.2 sample dump shows `55 AA 55 AA` at the start of the FET on
        // disk. The u32 little-endian read is therefore 0xAA55_AA55.
        assert_eq!(FET_MAGIC.as_bytes(), &[0x55, 0xAA, 0x55, 0xAA]);
        assert_eq!(FET_MAGIC.as_u32_le(), 0xAA55_AA55);
    }

    #[test]
    fn psp_magic_u32() {
        // `$PSP` little-endian = 0x50_53_50_24 (P S P $).
        assert_eq!(PSP_MAGIC.as_u32_le(), 0x5053_5024);
    }

    #[test]
    fn directory_family_dispatch() {
        assert_eq!(directory_family(PSP_MAGIC), Some(DirectoryFamily::Psp));
        assert_eq!(directory_family(PL2_MAGIC), Some(DirectoryFamily::Psp));
        assert_eq!(directory_family(BHD_MAGIC), Some(DirectoryFamily::Bios));
        assert_eq!(directory_family(BL2_MAGIC), Some(DirectoryFamily::Bios));
        assert_eq!(
            directory_family(COMBO_PSP_MAGIC),
            Some(DirectoryFamily::Combo)
        );
        assert_eq!(
            directory_family(COMBO_BHD_MAGIC),
            Some(DirectoryFamily::Combo)
        );

        // Unknown magic
        assert_eq!(directory_family(Magic::new([0, 0, 0, 0])), None);
        assert_eq!(directory_family(Magic::from_ascii(b"$KDB")), None);
        assert_eq!(directory_family(FET_MAGIC), None);
    }

    #[test]
    fn debug_format_ascii() {
        let s = format!("{:?}", PSP_MAGIC);
        assert!(s.contains("$PSP"), "{s}");
    }

    #[test]
    fn debug_format_binary() {
        let s = format!("{:?}", FET_MAGIC);
        assert!(s.contains("0x55"), "{s}");
        assert!(s.contains("0xaa"), "{s}");
    }
}
