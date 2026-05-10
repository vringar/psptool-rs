//! Directory parser for `$PSP`/`$PL2`, `$BHD`/`$BL2`, and `2PSP`/`2BHD`.
//!
//! See `docs/firmware-layout.md` §2 (directory headers) and §3 (entries).
//! Three families share a 16-byte header layout but diverge on what comes
//! after:
//!
//! * **PSP** (`$PSP` / `$PL2`) — `count` entries of 16 bytes each (§3.1).
//! * **BIOS** (`$BHD` / `$BL2`) — `count` entries of 24 bytes each (§3.2).
//! * **Combo** (`2PSP` / `2BHD`) — 16 bytes of reserved zeroes, then
//!   `count` combo entries of 16 bytes (§2.3).
//!
//! Each parsed structure (header, entry, directory body) retains a
//! [`SourceBytes`] window over its on-disk record, so the byte-exact writer
//! can patch a single entry without rebuilding the surrounding directory
//! (`docs/firmware-layout.md` §8).

use crate::address::{Address, AddressMode, FlashOffset, ResolveContext, RomSize};
use crate::error::ParseError;
use crate::fet::Fet;
use crate::id::{EntryType, PspGenerationId};
use crate::magic::{
    BHD_MAGIC, BL2_MAGIC, COMBO_BHD_MAGIC, COMBO_PSP_MAGIC, DirectoryFamily, Magic, PL2_MAGIC,
    PSP_MAGIC, directory_family,
};
use crate::source::SourceBytes;

/// Size of every directory header (§2.1, §2.3).
pub const DIRECTORY_HEADER_SIZE: usize = 0x10;
/// Per-entry record size for `$PSP`/`$PL2` directories (§3.1).
pub const PSP_ENTRY_SIZE: usize = 0x10;
/// Per-entry record size for `$BHD`/`$BL2` directories (§3.2).
pub const BIOS_ENTRY_SIZE: usize = 0x18;
/// Reserved 16-byte block at +0x10..+0x20 inside a combo header (§2.3).
pub const COMBO_RESERVED_SIZE: usize = 0x10;
/// Combo entry record size (§2.3).
pub const COMBO_ENTRY_SIZE: usize = 0x10;

const PSP_MAGICS: &[Magic] = &[PSP_MAGIC, PL2_MAGIC];
const BIOS_MAGICS: &[Magic] = &[BHD_MAGIC, BL2_MAGIC];
const COMBO_MAGICS: &[Magic] = &[COMBO_PSP_MAGIC, COMBO_BHD_MAGIC];
const ANY_DIRECTORY_MAGICS: &[Magic] = &[
    PSP_MAGIC,
    PL2_MAGIC,
    BHD_MAGIC,
    BL2_MAGIC,
    COMBO_PSP_MAGIC,
    COMBO_BHD_MAGIC,
];

/// 16-byte directory header common to all three families (§2.1).
///
/// The 4-byte `additional_info` field at +0x0c carries the
/// address-mode/version-flag bits in PSP and BIOS directories, and the
/// `lookup_mode` in combo directories. The raw u32 is stored as-is and the
/// caller picks the interpretation appropriate to the family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryHeader {
    /// Bytes covering the 16-byte header.
    pub source: SourceBytes,
    pub magic: Magic,
    pub fletcher: u32,
    pub count: u32,
    pub additional_info: u32,
}

impl DirectoryHeader {
    /// Parse a 16-byte header from the start of `source`.
    fn parse(source: &SourceBytes) -> Result<Self, ParseError> {
        if source.len() < DIRECTORY_HEADER_SIZE {
            return Err(ParseError::Truncated {
                what: "directory header",
                offset: source.offset(),
                expected: DIRECTORY_HEADER_SIZE,
                available: source.len(),
            });
        }
        let bytes = source.as_bytes();
        let magic = Magic::new([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let fletcher = u32::from_le_bytes(bytes[0x04..0x08].try_into().unwrap());
        let count = u32::from_le_bytes(bytes[0x08..0x0C].try_into().unwrap());
        let additional_info = u32::from_le_bytes(bytes[0x0C..0x10].try_into().unwrap());
        let header_source = source
            .slice(0, DIRECTORY_HEADER_SIZE)
            .expect("len checked above");
        Ok(Self {
            source: header_source,
            magic,
            fletcher,
            count,
            additional_info,
        })
    }

    /// Address-mode for PSP/BIOS directories (§2.2). Combo directories ignore
    /// this — `additional_info` is the `lookup_mode` for them.
    #[inline]
    pub fn address_mode(&self) -> AddressMode {
        AddressMode::from_additional_info(self.additional_info)
    }

    /// `lookup_mode` for combo directories (§2.3) — alias for the raw
    /// `additional_info` dword. PSPTool does not model the meaning beyond
    /// 0/1, so we just hand it back.
    #[inline]
    pub fn lookup_mode(&self) -> u32 {
        self.additional_info
    }

    /// Whether the header's version flag is "v1" (§2.1: bit 31 of
    /// `additional_info`). PSP/BIOS only; combo headers always read v1==false.
    #[inline]
    pub fn is_v1(&self) -> bool {
        (self.additional_info >> 31) & 1 == 1
    }
}

/// PSP-family entry (16 bytes, §3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PspEntry {
    /// 16-byte source slice for this entry.
    pub source: SourceBytes,
    pub entry_type: EntryType,
    pub subprogram: u8,
    pub flags: u16,
    pub size: u32,
    pub offset: Address,
    pub rsv0: u32,
}

impl PspEntry {
    fn parse(source: SourceBytes) -> Self {
        let b = source.as_bytes();
        debug_assert!(b.len() >= PSP_ENTRY_SIZE);
        let entry_type = EntryType(b[0]);
        let subprogram = b[1];
        let flags = u16::from_le_bytes([b[2], b[3]]);
        let size = u32::from_le_bytes(b[0x04..0x08].try_into().unwrap());
        let offset = Address(u32::from_le_bytes(b[0x08..0x0C].try_into().unwrap()));
        let rsv0 = u32::from_le_bytes(b[0x0C..0x10].try_into().unwrap());
        Self {
            source,
            entry_type,
            subprogram,
            flags,
            size,
            offset,
            rsv0,
        }
    }

    /// Bits `[31:30]` of `rsv0` — the entry-level address mode override
    /// honoured when the parent directory's mode is `10`/`11` (§2.2 last
    /// paragraph, §3.1).
    #[inline]
    pub fn entry_address_mode(&self) -> AddressMode {
        AddressMode::from_entry_rsv0(self.rsv0)
    }

    /// `(flags >> 3) & 0xF` per §3.1 — the "instance" sub-field.
    #[inline]
    pub fn instance(&self) -> u8 {
        ((self.flags >> 3) & 0xF) as u8
    }
}

/// BIOS-family entry (24 bytes, §3.2). Adds an 8-byte `destination` field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BiosEntry {
    /// 24-byte source slice for this entry.
    pub source: SourceBytes,
    pub entry_type: EntryType,
    pub region_type: u8,
    pub flags: u16,
    pub size: u32,
    pub offset: Address,
    pub rsv0: u32,
    /// 64-bit memory address the BIOS loader copies the body to.
    /// `0xFFFFFFFFFFFFFFFF` is the "unused" sentinel (§3.2).
    pub destination: u64,
}

impl BiosEntry {
    fn parse(source: SourceBytes) -> Self {
        let b = source.as_bytes();
        debug_assert!(b.len() >= BIOS_ENTRY_SIZE);
        let entry_type = EntryType(b[0]);
        let region_type = b[1];
        let flags = u16::from_le_bytes([b[2], b[3]]);
        let size = u32::from_le_bytes(b[0x04..0x08].try_into().unwrap());
        let offset = Address(u32::from_le_bytes(b[0x08..0x0C].try_into().unwrap()));
        let rsv0 = u32::from_le_bytes(b[0x0C..0x10].try_into().unwrap());
        let destination = u64::from_le_bytes(b[0x10..0x18].try_into().unwrap());
        Self {
            source,
            entry_type,
            region_type,
            flags,
            size,
            offset,
            rsv0,
            destination,
        }
    }

    #[inline]
    pub fn entry_address_mode(&self) -> AddressMode {
        AddressMode::from_entry_rsv0(self.rsv0)
    }

    /// `(flags >> 3) & 1` per §3.2 — the "compressed" bit lives in the
    /// directory entry, not in the file body.
    #[inline]
    pub fn is_compressed(&self) -> bool {
        ((self.flags >> 3) & 1) == 1
    }

    /// `(flags >> 4) & 0xF` per §3.2.
    #[inline]
    pub fn instance(&self) -> u8 {
        ((self.flags >> 4) & 0xF) as u8
    }

    /// `(flags >> 8) & 0x7` per §3.2.
    #[inline]
    pub fn subprogram(&self) -> u8 {
        ((self.flags >> 8) & 0x7) as u8
    }

    /// `destination == 0xFFFFFFFFFFFFFFFF` is the "unused" sentinel (§3.2).
    #[inline]
    pub fn destination_is_unused(&self) -> bool {
        self.destination == u64::MAX
    }
}

/// Combo-directory entry (16 bytes, §2.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComboEntry {
    /// 16-byte source slice for this combo entry.
    pub source: SourceBytes,
    pub entry_flags: u32,
    pub psp_generation: PspGenerationId,
    pub pointer: Address,
    pub reserved: u32,
}

impl ComboEntry {
    fn parse(source: SourceBytes) -> Self {
        let b = source.as_bytes();
        debug_assert!(b.len() >= COMBO_ENTRY_SIZE);
        let entry_flags = u32::from_le_bytes(b[0x00..0x04].try_into().unwrap());
        let psp_generation = PspGenerationId(u32::from_le_bytes(b[0x04..0x08].try_into().unwrap()));
        let pointer = Address(u32::from_le_bytes(b[0x08..0x0C].try_into().unwrap()));
        let reserved = u32::from_le_bytes(b[0x0C..0x10].try_into().unwrap());
        Self {
            source,
            entry_flags,
            psp_generation,
            pointer,
            reserved,
        }
    }
}

/// Parsed `$PSP` / `$PL2` directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PspDirectory {
    /// Bytes covering header + entries (the body the checksum is computed over).
    pub source: SourceBytes,
    pub header: DirectoryHeader,
    pub entries: Vec<PspEntry>,
}

/// Parsed `$BHD` / `$BL2` directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BiosDirectory {
    pub source: SourceBytes,
    pub header: DirectoryHeader,
    pub entries: Vec<BiosEntry>,
}

/// Parsed `2PSP` / `2BHD` combo directory (§2.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComboDirectory {
    /// Bytes covering header + 16-byte reserved + combo entries.
    pub source: SourceBytes,
    pub header: DirectoryHeader,
    /// 16 bytes at +0x10..+0x20 — PSPTool asserts these are zero, but we
    /// preserve them verbatim so byte-exact roundtrip survives (§8).
    pub reserved: SourceBytes,
    pub entries: Vec<ComboEntry>,
}

/// Parsed directory of any family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Directory {
    Psp(PspDirectory),
    Bios(BiosDirectory),
    Combo(ComboDirectory),
}

impl Directory {
    /// Parse a directory whose header begins at `dir_offset` inside `blob`.
    ///
    /// Dispatches on magic — `$PSP`/`$PL2` → [`PspDirectory`],
    /// `$BHD`/`$BL2` → [`BiosDirectory`], `2PSP`/`2BHD` →
    /// [`ComboDirectory`]. Returns [`ParseError::BadMagic`] for anything
    /// else. Callers walking ambiguous pointers (e.g. raw FET slots) should
    /// match on the error and skip silently per §1.2.
    pub fn parse_at(blob: &SourceBytes, dir_offset: FlashOffset) -> Result<Self, ParseError> {
        let local = local_offset(blob, dir_offset, "directory header", DIRECTORY_HEADER_SIZE)?;
        let header_window = blob
            .slice(local, blob.len() - local)
            .expect("local in-bounds");
        let header = DirectoryHeader::parse(&header_window)?;
        match directory_family(header.magic) {
            Some(DirectoryFamily::Psp) => Ok(Self::Psp(PspDirectory::parse_with_header(
                blob, local, header,
            )?)),
            Some(DirectoryFamily::Bios) => Ok(Self::Bios(BiosDirectory::parse_with_header(
                blob, local, header,
            )?)),
            Some(DirectoryFamily::Combo) => Ok(Self::Combo(ComboDirectory::parse_with_header(
                blob, local, header,
            )?)),
            None => Err(ParseError::BadMagic {
                what: "directory",
                offset: dir_offset,
                got: header.magic,
                expected: ANY_DIRECTORY_MAGICS,
            }),
        }
    }

    /// Header common to all three families.
    pub fn header(&self) -> &DirectoryHeader {
        match self {
            Self::Psp(d) => &d.header,
            Self::Bios(d) => &d.header,
            Self::Combo(d) => &d.header,
        }
    }

    /// Source bytes of the entire directory record.
    pub fn source(&self) -> &SourceBytes {
        match self {
            Self::Psp(d) => &d.source,
            Self::Bios(d) => &d.source,
            Self::Combo(d) => &d.source,
        }
    }

    /// Family classification (PSP / BIOS / Combo).
    pub fn family(&self) -> DirectoryFamily {
        match self {
            Self::Psp(_) => DirectoryFamily::Psp,
            Self::Bios(_) => DirectoryFamily::Bios,
            Self::Combo(_) => DirectoryFamily::Combo,
        }
    }
}

impl PspDirectory {
    fn parse_with_header(
        blob: &SourceBytes,
        local: usize,
        header: DirectoryHeader,
    ) -> Result<Self, ParseError> {
        if !PSP_MAGICS.contains(&header.magic) {
            return Err(ParseError::BadMagic {
                what: "PSP directory",
                offset: header.source.offset(),
                got: header.magic,
                expected: PSP_MAGICS,
            });
        }
        let count = header.count as usize;
        let body_size = count
            .checked_mul(PSP_ENTRY_SIZE)
            .ok_or(ParseError::Truncated {
                what: "PSP directory body",
                offset: header.source.offset(),
                expected: usize::MAX,
                available: 0,
            })?;
        let total = DIRECTORY_HEADER_SIZE + body_size;
        ensure_in_bounds(
            blob,
            local,
            total,
            "PSP directory body",
            header.source.offset(),
        )?;

        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let entry_local = local + DIRECTORY_HEADER_SIZE + i * PSP_ENTRY_SIZE;
            let entry_source = blob
                .slice(entry_local, PSP_ENTRY_SIZE)
                .expect("bounds checked above");
            entries.push(PspEntry::parse(entry_source));
        }
        let source = blob.slice(local, total).expect("bounds checked above");

        Ok(Self {
            source,
            header,
            entries,
        })
    }
}

impl BiosDirectory {
    fn parse_with_header(
        blob: &SourceBytes,
        local: usize,
        header: DirectoryHeader,
    ) -> Result<Self, ParseError> {
        if !BIOS_MAGICS.contains(&header.magic) {
            return Err(ParseError::BadMagic {
                what: "BIOS directory",
                offset: header.source.offset(),
                got: header.magic,
                expected: BIOS_MAGICS,
            });
        }
        let count = header.count as usize;
        let body_size = count
            .checked_mul(BIOS_ENTRY_SIZE)
            .ok_or(ParseError::Truncated {
                what: "BIOS directory body",
                offset: header.source.offset(),
                expected: usize::MAX,
                available: 0,
            })?;
        let total = DIRECTORY_HEADER_SIZE + body_size;
        ensure_in_bounds(
            blob,
            local,
            total,
            "BIOS directory body",
            header.source.offset(),
        )?;

        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let entry_local = local + DIRECTORY_HEADER_SIZE + i * BIOS_ENTRY_SIZE;
            let entry_source = blob
                .slice(entry_local, BIOS_ENTRY_SIZE)
                .expect("bounds checked above");
            entries.push(BiosEntry::parse(entry_source));
        }
        let source = blob.slice(local, total).expect("bounds checked above");

        Ok(Self {
            source,
            header,
            entries,
        })
    }
}

impl ComboDirectory {
    fn parse_with_header(
        blob: &SourceBytes,
        local: usize,
        header: DirectoryHeader,
    ) -> Result<Self, ParseError> {
        if !COMBO_MAGICS.contains(&header.magic) {
            return Err(ParseError::BadMagic {
                what: "combo directory",
                offset: header.source.offset(),
                got: header.magic,
                expected: COMBO_MAGICS,
            });
        }
        let count = header.count as usize;
        let body_size = count
            .checked_mul(COMBO_ENTRY_SIZE)
            .ok_or(ParseError::Truncated {
                what: "combo directory body",
                offset: header.source.offset(),
                expected: usize::MAX,
                available: 0,
            })?;
        let total = DIRECTORY_HEADER_SIZE + COMBO_RESERVED_SIZE + body_size;
        ensure_in_bounds(
            blob,
            local,
            total,
            "combo directory body",
            header.source.offset(),
        )?;

        let reserved = blob
            .slice(local + DIRECTORY_HEADER_SIZE, COMBO_RESERVED_SIZE)
            .expect("bounds checked above");

        let entry_base = local + DIRECTORY_HEADER_SIZE + COMBO_RESERVED_SIZE;
        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let entry_local = entry_base + i * COMBO_ENTRY_SIZE;
            let entry_source = blob
                .slice(entry_local, COMBO_ENTRY_SIZE)
                .expect("bounds checked above");
            entries.push(ComboEntry::parse(entry_source));
        }
        let source = blob.slice(local, total).expect("bounds checked above");

        Ok(Self {
            source,
            header,
            reserved,
            entries,
        })
    }
}

/// How a directory was reached during a [`walk_directories`] traversal.
///
/// Returned alongside the parsed [`Directory`] so callers (e.g. CLI `ls`)
/// can group sub-directories under their parents without re-deriving the
/// pointer graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirectoryProvenance {
    /// The directory was pointed at by FET slot `index` (§1.2 — the slot's
    /// positional index within the FET).
    FetSlot { index: usize },
    /// The directory was pointed at by combo entry `index` of the combo at
    /// `combo_offset`.
    ComboEntry {
        combo_offset: FlashOffset,
        index: usize,
    },
    /// The directory was pointed at by entry `index` of the parent directory
    /// at `parent_offset` (an L2 pointer per §3.3 — types 0x40/0x49/0x70).
    L2Pointer {
        parent_offset: FlashOffset,
        index: usize,
    },
}

/// A parsed [`Directory`] together with the link that led to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryRef {
    pub directory: Directory,
    pub provenance: DirectoryProvenance,
}

/// Walk every directory reachable from `fet`, following combo dispatch and
/// L2 sub-directory pointers (§2.3, §3.3).
///
/// Returns directories in walk order, deduplicated by the absolute flash
/// offset of the directory's header so cycles and multi-pointed directories
/// each appear once. Pointers that do not dereference to a recognisable
/// directory magic are skipped silently per §1.2 ("only dwords whose
/// dereferenced location starts with a known directory magic are followed").
///
/// Tertiary pointers (entry types 0x48 / 0x4A — §3.3) are *not* followed:
/// they require reading the entry body, which lives in the entry-parser
/// issue (#7).
///
/// `rom_origin` is the file offset of the ROM's first byte within `blob`.
/// For a bare flash dump pass [`FlashOffset::ZERO`]; for a capsule-wrapped
/// image (§1.1) pass the byte offset of the envelope end. See
/// [`crate::fet::detect_rom_layout`].
pub fn walk_directories(
    blob: &SourceBytes,
    fet: &Fet,
    rom_size: RomSize,
    rom_origin: FlashOffset,
) -> Vec<DirectoryRef> {
    let mut out = Vec::new();
    let mut visited: Vec<u64> = Vec::new();

    let visit = |out: &mut Vec<DirectoryRef>,
                 visited: &mut Vec<u64>,
                 dir: Directory,
                 provenance: DirectoryProvenance|
     -> Option<usize> {
        let off = dir.source().offset().get();
        if visited.contains(&off) {
            return None;
        }
        visited.push(off);
        out.push(DirectoryRef {
            directory: dir,
            provenance,
        });
        Some(out.len() - 1)
    };

    let mut work: Vec<DirectoryRef> = Vec::new();

    for (index, slot) in fet.slots.iter().enumerate() {
        let raw = match slot.slot {
            crate::fet::FetSlot::Pointer(a) => a,
            crate::fet::FetSlot::Sentinel(_) => continue,
        };
        // FET pointers are normalised as PhysicalX86 (§1.3).
        let ctx = ResolveContext {
            rom_size,
            directory_base: FlashOffset(0),
            rom_origin,
        };
        let target = match AddressMode::PhysicalX86.resolve(raw, ctx) {
            Ok(o) => o,
            Err(_) => continue,
        };
        if let Ok(dir) = Directory::parse_at(blob, target) {
            let provenance = DirectoryProvenance::FetSlot { index };
            if visit(&mut out, &mut visited, dir.clone(), provenance.clone()).is_some() {
                work.push(DirectoryRef {
                    directory: dir,
                    provenance,
                });
            }
        }
    }

    while let Some(node) = work.pop() {
        match node.directory {
            Directory::Combo(combo) => {
                let combo_offset = combo.source.offset();
                for (idx, entry) in combo.entries.iter().enumerate() {
                    // Combo pointers are §1.3-normalised raw pointers.
                    let ctx = ResolveContext {
                        rom_size,
                        directory_base: FlashOffset(0),
                        rom_origin,
                    };
                    let target = match AddressMode::PhysicalX86.resolve(entry.pointer, ctx) {
                        Ok(o) => o,
                        Err(_) => continue,
                    };
                    if let Ok(child) = Directory::parse_at(blob, target) {
                        let provenance = DirectoryProvenance::ComboEntry {
                            combo_offset,
                            index: idx,
                        };
                        if visit(&mut out, &mut visited, child.clone(), provenance.clone())
                            .is_some()
                        {
                            work.push(DirectoryRef {
                                directory: child,
                                provenance,
                            });
                        }
                    }
                }
            }
            Directory::Psp(psp) => {
                let parent_offset = psp.source.offset();
                let dir_mode = psp.header.address_mode();
                let dir_base = psp.source.offset();
                for (idx, entry) in psp.entries.iter().enumerate() {
                    if !entry.entry_type.is_secondary_directory_pointer() {
                        // Tertiary (0x48/0x4a) requires reading the entry body
                        // and is deferred to issue #7.
                        continue;
                    }
                    let ctx = ResolveContext {
                        rom_size,
                        directory_base: dir_base,
                        rom_origin,
                    };
                    let target =
                        dir_mode.resolve_with_entry(entry.entry_address_mode(), entry.offset, ctx);
                    if let Ok(child) = Directory::parse_at(blob, target) {
                        let provenance = DirectoryProvenance::L2Pointer {
                            parent_offset,
                            index: idx,
                        };
                        if visit(&mut out, &mut visited, child.clone(), provenance.clone())
                            .is_some()
                        {
                            work.push(DirectoryRef {
                                directory: child,
                                provenance,
                            });
                        }
                    }
                }
            }
            Directory::Bios(bios) => {
                let parent_offset = bios.source.offset();
                let dir_mode = bios.header.address_mode();
                let dir_base = bios.source.offset();
                for (idx, entry) in bios.entries.iter().enumerate() {
                    if !entry.entry_type.is_secondary_directory_pointer() {
                        continue;
                    }
                    let ctx = ResolveContext {
                        rom_size,
                        directory_base: dir_base,
                        rom_origin,
                    };
                    let target =
                        dir_mode.resolve_with_entry(entry.entry_address_mode(), entry.offset, ctx);
                    if let Ok(child) = Directory::parse_at(blob, target) {
                        let provenance = DirectoryProvenance::L2Pointer {
                            parent_offset,
                            index: idx,
                        };
                        if visit(&mut out, &mut visited, child.clone(), provenance.clone())
                            .is_some()
                        {
                            work.push(DirectoryRef {
                                directory: child,
                                provenance,
                            });
                        }
                    }
                }
            }
        }
    }

    out
}

fn local_offset(
    blob: &SourceBytes,
    abs: FlashOffset,
    what: &'static str,
    expected: usize,
) -> Result<usize, ParseError> {
    let blob_start = blob.offset().get();
    if abs.get() < blob_start {
        return Err(ParseError::Truncated {
            what,
            offset: abs,
            expected,
            available: 0,
        });
    }
    let local = (abs.get() - blob_start) as usize;
    if local + expected > blob.len() {
        return Err(ParseError::Truncated {
            what,
            offset: abs,
            expected,
            available: blob.len().saturating_sub(local),
        });
    }
    Ok(local)
}

fn ensure_in_bounds(
    blob: &SourceBytes,
    local: usize,
    expected: usize,
    what: &'static str,
    offset: FlashOffset,
) -> Result<(), ParseError> {
    if local + expected > blob.len() {
        return Err(ParseError::Truncated {
            what,
            offset,
            expected,
            available: blob.len().saturating_sub(local),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fet::{FET_MAGIC_SIZE, FET_SLOT_SIZE, FET_TERMINATOR_SIZE};
    use crate::magic::{COMBO_PSP_MAGIC, FET_MAGIC};

    // ------------------------------------------------------------------
    // Standalone parse tests using the committed micro-fixtures.
    // ------------------------------------------------------------------

    #[test]
    fn parse_psp_directory_fixture() {
        let bytes = psptool_fixtures::micro::psp_directory().to_vec();
        let blob = SourceBytes::from_blob(bytes);
        let dir = Directory::parse_at(&blob, FlashOffset(0)).expect("parse $PSP");
        let psp = match dir {
            Directory::Psp(p) => p,
            other => panic!("expected PSP, got {other:?}"),
        };

        assert_eq!(psp.header.magic, PSP_MAGIC);
        assert_eq!(psp.header.count, 1);
        // The fixture sets `additional_info = 0x02000000` (bit 31 = 0 → v2),
        // so address_mode reads bits[30:29] = 00 → PhysicalX86. The bits at
        // [25:24] = 10 are dormant in v2 mode.
        assert!(!psp.header.is_v1());
        assert_eq!(psp.header.address_mode(), AddressMode::PhysicalX86);
        assert_eq!(psp.entries.len(), 1);

        let entry = &psp.entries[0];
        assert_eq!(entry.entry_type, EntryType(0x21)); // WRAPPED_IKEK
        assert_eq!(entry.subprogram, 0);
        assert_eq!(entry.size, 0x10);
        assert_eq!(entry.offset, Address(0x20));
        assert_eq!(entry.rsv0, 0);
        assert_eq!(entry.source.len(), PSP_ENTRY_SIZE);

        // Entry source comes right after the header.
        assert_eq!(
            entry.source.offset(),
            FlashOffset(DIRECTORY_HEADER_SIZE as u64)
        );

        // Source covers header + entry table only — not the trailing 16-byte
        // entry body (which is *not* covered by the directory fletcher per §2.4).
        assert_eq!(psp.source.len(), DIRECTORY_HEADER_SIZE + PSP_ENTRY_SIZE);
    }

    #[test]
    fn parse_bhd_directory_fixture() {
        let bytes = psptool_fixtures::micro::bhd_directory().to_vec();
        let blob = SourceBytes::from_blob(bytes);
        let dir = Directory::parse_at(&blob, FlashOffset(0)).expect("parse $BHD");
        let bhd = match dir {
            Directory::Bios(b) => b,
            other => panic!("expected BIOS, got {other:?}"),
        };

        assert_eq!(bhd.header.magic, BHD_MAGIC);
        assert_eq!(bhd.entries.len(), 1);

        let entry = &bhd.entries[0];
        assert_eq!(entry.entry_type, EntryType(0x62));
        assert_eq!(entry.region_type, 0);
        assert_eq!(entry.size, 0x10);
        assert_eq!(entry.offset, Address(0x28));
        // Fixture sets the destination sentinel.
        assert!(entry.destination_is_unused());
        assert_eq!(entry.source.len(), BIOS_ENTRY_SIZE);
        assert_eq!(
            entry.source.offset(),
            FlashOffset(DIRECTORY_HEADER_SIZE as u64)
        );

        assert_eq!(bhd.source.len(), DIRECTORY_HEADER_SIZE + BIOS_ENTRY_SIZE);
    }

    #[test]
    fn parse_combo_psp_fixture() {
        let bytes = psptool_fixtures::micro::combo_psp().to_vec();
        let blob = SourceBytes::from_blob(bytes);
        let dir = Directory::parse_at(&blob, FlashOffset(0)).expect("parse 2PSP");
        let combo = match dir {
            Directory::Combo(c) => c,
            other => panic!("expected combo, got {other:?}"),
        };

        assert_eq!(combo.header.magic, COMBO_PSP_MAGIC);
        assert_eq!(combo.header.count, 1);
        assert_eq!(combo.header.lookup_mode(), 0);
        assert_eq!(combo.reserved.len(), COMBO_RESERVED_SIZE);
        assert!(combo.reserved.as_bytes().iter().all(|&b| b == 0));
        assert_eq!(combo.entries.len(), 1);

        let entry = &combo.entries[0];
        assert_eq!(entry.entry_flags, 0);
        assert_eq!(entry.psp_generation, PspGenerationId(0xBC0B_0500));
        assert_eq!(
            entry.psp_generation.zen_generation(),
            Some(crate::ZenGeneration::Zen2)
        );
        assert_eq!(entry.pointer, Address(0x0000_1000));
        assert_eq!(entry.reserved, 0);
        assert_eq!(entry.source.len(), COMBO_ENTRY_SIZE);

        assert_eq!(
            combo.source.len(),
            DIRECTORY_HEADER_SIZE + COMBO_RESERVED_SIZE + COMBO_ENTRY_SIZE
        );
    }

    #[test]
    fn parse_at_with_blob_root_offset() {
        // Place the PSP fixture inside a larger buffer rooted at flash offset
        // 0xA7000 — the parser must use absolute offsets correctly.
        let mut buf = vec![0u8; 0xA7000];
        buf.extend_from_slice(psptool_fixtures::micro::psp_directory());
        let blob = SourceBytes::from_blob(buf);
        let dir = Directory::parse_at(&blob, FlashOffset(0xA7000)).expect("parse offset PSP");
        let psp = match dir {
            Directory::Psp(p) => p,
            other => panic!("{other:?}"),
        };
        assert_eq!(psp.source.offset(), FlashOffset(0xA7000));
        assert_eq!(
            psp.entries[0].source.offset(),
            FlashOffset(0xA7000 + DIRECTORY_HEADER_SIZE as u64),
        );
    }

    #[test]
    fn parse_at_unknown_magic_is_bad_magic() {
        // Random 16 bytes not starting with a directory magic.
        let mut buf = vec![0u8; 0x100];
        buf[0..4].copy_from_slice(b"NOPE");
        let blob = SourceBytes::from_blob(buf);
        let err = Directory::parse_at(&blob, FlashOffset(0)).unwrap_err();
        assert!(matches!(
            err,
            ParseError::BadMagic {
                what: "directory",
                ..
            }
        ));
    }

    #[test]
    fn parse_at_truncated_returns_truncated() {
        // 8 bytes — half a header.
        let blob = SourceBytes::from_blob(vec![0u8; 8]);
        let err = Directory::parse_at(&blob, FlashOffset(0)).unwrap_err();
        assert!(matches!(
            err,
            ParseError::Truncated {
                what: "directory header",
                ..
            }
        ));
    }

    #[test]
    fn parse_at_truncated_body_returns_truncated() {
        // Header claims 5 entries but the buffer only holds 1.
        let mut buf = Vec::new();
        buf.extend_from_slice(b"$PSP");
        buf.extend_from_slice(&0u32.to_le_bytes()); // checksum
        buf.extend_from_slice(&5u32.to_le_bytes()); // count = 5
        buf.extend_from_slice(&0u32.to_le_bytes()); // additional_info
        buf.extend_from_slice(&[0u8; PSP_ENTRY_SIZE]); // 1 entry only
        let blob = SourceBytes::from_blob(buf);
        let err = Directory::parse_at(&blob, FlashOffset(0)).unwrap_err();
        assert!(
            matches!(
                err,
                ParseError::Truncated {
                    what: "PSP directory body",
                    ..
                }
            ),
            "got {err:?}",
        );
    }

    // ------------------------------------------------------------------
    // Address-mode field decoding sanity check
    // ------------------------------------------------------------------

    #[test]
    fn psp_entry_address_mode_uses_rsv0_high_bits() {
        let bytes = psptool_fixtures::micro::psp_directory().to_vec();
        let blob = SourceBytes::from_blob(bytes);
        let psp = match Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
            Directory::Psp(p) => p,
            _ => unreachable!(),
        };
        // Fixture uses rsv0 = 0 → entry-mode bits[31:30] = 00 → PhysicalX86.
        assert_eq!(
            psp.entries[0].entry_address_mode(),
            AddressMode::PhysicalX86
        );
    }

    // ------------------------------------------------------------------
    // FET → directory traversal (the issue's "sub-directory traversal").
    // ------------------------------------------------------------------

    /// Build a synthetic 16 MiB-ish blob with a FET at flash offset 0x20000
    /// pointing at the committed PSP directory fixture placed at flash offset
    /// 0xA7000. Used to drive the traversal walk end-to-end without depending
    /// on the corpus.
    fn synthetic_blob_with_psp_at(rom_size: usize) -> SourceBytes {
        let mut buf = vec![0u8; rom_size];

        // FET magic + 1 pointer slot (flash offset 0xA7000) + terminator.
        let fet_off = 0x20_000usize;
        buf[fet_off..fet_off + FET_MAGIC_SIZE].copy_from_slice(FET_MAGIC.as_bytes());
        buf[fet_off + FET_MAGIC_SIZE..fet_off + FET_MAGIC_SIZE + FET_SLOT_SIZE]
            .copy_from_slice(&0x000A_7000u32.to_le_bytes());
        let term_off = fet_off + FET_MAGIC_SIZE + FET_SLOT_SIZE;
        buf[term_off..term_off + FET_TERMINATOR_SIZE].copy_from_slice(&[0xFF; FET_TERMINATOR_SIZE]);

        // PSP directory at 0xA7000.
        let dir_off = 0xA_7000usize;
        let dir_bytes = psptool_fixtures::micro::psp_directory();
        buf[dir_off..dir_off + dir_bytes.len()].copy_from_slice(dir_bytes);

        SourceBytes::from_blob(buf)
    }

    #[test]
    fn walk_directories_via_single_fet_pointer() {
        let blob = synthetic_blob_with_psp_at(0x100_0000); // 16 MiB
        let fet = Fet::parse_at(&blob, FlashOffset(0x20_000)).expect("parse FET");
        let dirs = walk_directories(&blob, &fet, RomSize::MIB_16, FlashOffset::ZERO);
        assert_eq!(dirs.len(), 1);
        let DirectoryRef {
            directory,
            provenance,
        } = &dirs[0];
        assert!(matches!(directory, Directory::Psp(_)));
        assert_eq!(*provenance, DirectoryProvenance::FetSlot { index: 0 });
    }

    #[test]
    fn walk_directories_skips_non_directory_pointers() {
        // FET pointer to a region that does NOT contain a directory magic →
        // walk silently skips per §1.2.
        let mut buf = vec![0u8; 0x100_0000];
        let fet_off = 0x20_000usize;
        buf[fet_off..fet_off + 4].copy_from_slice(FET_MAGIC.as_bytes());
        buf[fet_off + 4..fet_off + 8].copy_from_slice(&0x000A_7000u32.to_le_bytes());
        buf[fet_off + 8..fet_off + 24].copy_from_slice(&[0xFF; 16]);
        // Leave 0xA7000 zeroed — no directory there.
        let blob = SourceBytes::from_blob(buf);
        let fet = Fet::parse_at(&blob, FlashOffset(0x20_000)).expect("parse FET");
        let dirs = walk_directories(&blob, &fet, RomSize::MIB_16, FlashOffset::ZERO);
        assert!(dirs.is_empty());
    }

    #[test]
    fn walk_directories_via_combo_to_psp() {
        // FET → 2PSP combo → $PSP directory (one combo entry pointing at the
        // PSP fixture at flash offset 0x10000).
        let mut buf = vec![0u8; 0x100_0000];

        // FET at 0x20000 with one pointer to 0xA7000 (the combo header).
        let fet_off = 0x20_000usize;
        buf[fet_off..fet_off + 4].copy_from_slice(FET_MAGIC.as_bytes());
        buf[fet_off + 4..fet_off + 8].copy_from_slice(&0x000A_7000u32.to_le_bytes());
        buf[fet_off + 8..fet_off + 24].copy_from_slice(&[0xFF; 16]);

        // Build a combo header with one entry pointing at flash offset 0x1_0000.
        // The fixture combo points to 0x1000 — overwrite to 0x1_0000 so we
        // place the PSP fixture there.
        let mut combo_bytes = psptool_fixtures::micro::combo_psp().to_vec();
        // Combo header is 0x20; first combo entry's pointer lives at +0x28.
        combo_bytes[0x28..0x2C].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        // Note: we don't recompute fletcher because traversal doesn't verify it.

        let combo_off = 0xA_7000usize;
        buf[combo_off..combo_off + combo_bytes.len()].copy_from_slice(&combo_bytes);

        // Drop the PSP fixture at 0x1_0000.
        let psp_bytes = psptool_fixtures::micro::psp_directory();
        let psp_off = 0x1_0000usize;
        buf[psp_off..psp_off + psp_bytes.len()].copy_from_slice(psp_bytes);

        let blob = SourceBytes::from_blob(buf);
        let fet = Fet::parse_at(&blob, FlashOffset(0x20_000)).unwrap();
        let dirs = walk_directories(&blob, &fet, RomSize::MIB_16, FlashOffset::ZERO);

        assert_eq!(dirs.len(), 2, "combo + child PSP");
        assert!(matches!(dirs[0].directory, Directory::Combo(_)));
        assert_eq!(
            dirs[0].provenance,
            DirectoryProvenance::FetSlot { index: 0 }
        );
        assert!(matches!(dirs[1].directory, Directory::Psp(_)));
        assert_eq!(
            dirs[1].provenance,
            DirectoryProvenance::ComboEntry {
                combo_offset: FlashOffset(combo_off as u64),
                index: 0,
            }
        );
    }

    #[test]
    fn walk_directories_dedups_repeat_pointers() {
        // Two FET pointers, both to the same PSP directory. The walker
        // visits each absolute offset at most once.
        let mut buf = vec![0u8; 0x100_0000];
        let fet_off = 0x20_000usize;
        buf[fet_off..fet_off + 4].copy_from_slice(FET_MAGIC.as_bytes());
        buf[fet_off + 4..fet_off + 8].copy_from_slice(&0x000A_7000u32.to_le_bytes());
        buf[fet_off + 8..fet_off + 12].copy_from_slice(&0x000A_7000u32.to_le_bytes());
        buf[fet_off + 12..fet_off + 28].copy_from_slice(&[0xFF; 16]);

        let psp_bytes = psptool_fixtures::micro::psp_directory();
        let psp_off = 0xA_7000usize;
        buf[psp_off..psp_off + psp_bytes.len()].copy_from_slice(psp_bytes);

        let blob = SourceBytes::from_blob(buf);
        let fet = Fet::parse_at(&blob, FlashOffset(0x20_000)).unwrap();
        let dirs = walk_directories(&blob, &fet, RomSize::MIB_16, FlashOffset::ZERO);
        assert_eq!(dirs.len(), 1);
        // First pointer wins — provenance records slot 0.
        assert_eq!(
            dirs[0].provenance,
            DirectoryProvenance::FetSlot { index: 0 }
        );
    }

    #[test]
    fn walk_directories_follows_l2_pointer() {
        // PSP directory whose only entry is type 0x40 (PSP_FW_L2_PTR), pointing
        // (mode 10 = directory-relative) at a $PL2 directory placed
        // immediately after the parent header.
        let mut buf = vec![0u8; 0x100_0000];

        // FET at 0x20000 → parent PSP at 0xA7000.
        let fet_off = 0x20_000usize;
        buf[fet_off..fet_off + 4].copy_from_slice(FET_MAGIC.as_bytes());
        buf[fet_off + 4..fet_off + 8].copy_from_slice(&0x000A_7000u32.to_le_bytes());
        buf[fet_off + 8..fet_off + 24].copy_from_slice(&[0xFF; 16]);

        // Parent PSP header: count=1, address_mode=10 (directory-relative).
        // Set bit 31 (v1 layout) so `from_additional_info` reads bits[25:24].
        let parent_off = 0xA_7000usize;
        let additional_info: u32 = (1u32 << 31) | (0b10u32 << 24); // v1, mode 10
        buf[parent_off..parent_off + 4].copy_from_slice(b"$PSP");
        buf[parent_off + 4..parent_off + 8].copy_from_slice(&0u32.to_le_bytes()); // checksum
        buf[parent_off + 8..parent_off + 12].copy_from_slice(&1u32.to_le_bytes()); // count=1
        buf[parent_off + 12..parent_off + 16].copy_from_slice(&additional_info.to_le_bytes());

        // Single PSP entry: type 0x40, offset 0x100 (directory-relative).
        // Directory mode 10/11 defers to entry-level mode (rsv0[31:30]); set
        // those bits to 10 so resolve_with_entry adds directory_base + 0x100.
        let entry_off = parent_off + 0x10;
        let entry_rsv0: u32 = 0b10u32 << 30;
        buf[entry_off] = 0x40;
        buf[entry_off + 1] = 0x00;
        buf[entry_off + 2..entry_off + 4].copy_from_slice(&0u16.to_le_bytes()); // flags
        buf[entry_off + 4..entry_off + 8].copy_from_slice(&0x100u32.to_le_bytes()); // size
        buf[entry_off + 8..entry_off + 12].copy_from_slice(&0x100u32.to_le_bytes()); // offset
        buf[entry_off + 12..entry_off + 16].copy_from_slice(&entry_rsv0.to_le_bytes()); // rsv0

        // Child $PL2 at parent_off + 0x100. Use a 0-entry PL2 — bookkeeping only.
        let child_off = parent_off + 0x100;
        buf[child_off..child_off + 4].copy_from_slice(b"$PL2");
        buf[child_off + 4..child_off + 8].copy_from_slice(&0u32.to_le_bytes()); // checksum
        buf[child_off + 8..child_off + 12].copy_from_slice(&0u32.to_le_bytes()); // count = 0
        buf[child_off + 12..child_off + 16].copy_from_slice(&((0b10u32) << 24).to_le_bytes());

        let blob = SourceBytes::from_blob(buf);
        let fet = Fet::parse_at(&blob, FlashOffset(0x20_000)).unwrap();
        let dirs = walk_directories(&blob, &fet, RomSize::MIB_16, FlashOffset::ZERO);

        assert_eq!(dirs.len(), 2, "parent + L2 child");
        assert!(matches!(&dirs[0].directory, Directory::Psp(p) if p.header.magic == PSP_MAGIC));
        assert!(matches!(&dirs[1].directory, Directory::Psp(p) if p.header.magic == PL2_MAGIC));
        assert_eq!(
            dirs[1].provenance,
            DirectoryProvenance::L2Pointer {
                parent_offset: FlashOffset(parent_off as u64),
                index: 0,
            }
        );
    }

    /// Regression for L10 (capsule-wrapped images, e.g. ASUS_PRIME-X470-PRO):
    /// the ROM origin is `0x800` inside the file. The FET pointer
    /// `0xFF158000` must resolve to file offset `0x800 + 0x158000 = 0x158800`,
    /// not `0x158000`. Without the fix, the directory parse reads from the
    /// capsule envelope and returns BadMagic, so `walk_directories` yields
    /// zero directories.
    #[test]
    fn walk_directories_traverses_capsule_wrapped_image() {
        // 16 MiB ROM + 0x800 capsule envelope. Total file size 16 MiB + 0x800
        // mirrors the corpus failure mode (16779264 bytes).
        let envelope: usize = 0x800;
        let rom_size_bytes: usize = 0x100_0000;
        let mut buf = vec![0u8; envelope + rom_size_bytes];

        // FET in the ROM at ROM-relative offset 0x20000 → file offset 0x20800.
        let fet_off_in_rom = 0x20_000usize;
        let fet_file_off = envelope + fet_off_in_rom;
        buf[fet_file_off..fet_file_off + 4].copy_from_slice(FET_MAGIC.as_bytes());
        // FET slot 0: x86 physical pointer 0xFF158000 → ROM-flash 0x158000
        // → file offset envelope + 0x158000.
        buf[fet_file_off + 4..fet_file_off + 8].copy_from_slice(&0xFF15_8000u32.to_le_bytes());
        // 16-byte terminator.
        buf[fet_file_off + 8..fet_file_off + 24].copy_from_slice(&[0xFF; 16]);

        // Place a $PSP directory at ROM-relative 0x158000 → file 0x158800.
        let dir_file_off = envelope + 0x158_000;
        let dir_bytes = psptool_fixtures::micro::psp_directory();
        buf[dir_file_off..dir_file_off + dir_bytes.len()].copy_from_slice(dir_bytes);

        let blob = SourceBytes::from_blob(buf);
        let fet = Fet::parse_at(&blob, FlashOffset(fet_file_off as u64)).expect("parse FET");

        // Without the rom_origin fix, walk_directories reads the directory at
        // file offset 0x158000 (envelope bytes — zeros) and yields nothing.
        let dirs_without_origin = walk_directories(&blob, &fet, RomSize::MIB_16, FlashOffset::ZERO);
        assert!(
            dirs_without_origin.is_empty(),
            "control: walk without rom_origin must miss the directory"
        );

        // With the correct rom_origin = 0x800, the directory is found.
        let dirs = walk_directories(&blob, &fet, RomSize::MIB_16, FlashOffset(envelope as u64));
        assert_eq!(
            dirs.len(),
            1,
            "capsule-wrapped image must yield 1 directory"
        );
        assert!(matches!(&dirs[0].directory, Directory::Psp(p) if p.header.magic == PSP_MAGIC));
        assert_eq!(
            dirs[0].directory.source().offset(),
            FlashOffset(dir_file_off as u64)
        );
    }
}
