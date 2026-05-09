//! Address-mode arithmetic for AMD PSP firmware images.
//!
//! See `docs/firmware-layout.md` §1.3 (ROM-physical address normalisation) and
//! §2.2 (directory-scoped address-mode lookup table).

use core::fmt;

/// Newtype for byte offsets into the loaded firmware image (the input blob).
///
/// `FlashOffset(0)` is the first byte of the input the user handed us; this is
/// not necessarily the start of a ROM (capsule/UEFI envelopes can prepend
/// bytes — see §1).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FlashOffset(pub u64);

impl FlashOffset {
    pub const ZERO: Self = Self(0);

    #[inline]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[inline]
    pub const fn checked_add(self, rhs: u64) -> Option<Self> {
        match self.0.checked_add(rhs) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }
}

impl fmt::Debug for FlashOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FlashOffset({:#010x})", self.0)
    }
}

impl fmt::Display for FlashOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}", self.0)
    }
}

/// Newtype for the 16/32 MiB-aligned ROM size.
///
/// PSP ROMs are 8/16/32 MiB SPI-flash images. The address mask used by §1.3 is
/// `rom_size - 1`.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RomSize(u64);

impl RomSize {
    pub const MIB_8: Self = Self(8 * 1024 * 1024);
    pub const MIB_16: Self = Self(16 * 1024 * 1024);
    pub const MIB_32: Self = Self(32 * 1024 * 1024);

    /// Construct a `RomSize`. Returns `None` unless `bytes` is a power of two
    /// in the inclusive range `[8 MiB, 32 MiB]`.
    #[inline]
    pub const fn new(bytes: u64) -> Option<Self> {
        if !bytes.is_power_of_two() {
            return None;
        }
        if bytes < Self::MIB_8.0 || bytes > Self::MIB_32.0 {
            return None;
        }
        Some(Self(bytes))
    }

    #[inline]
    pub const fn bytes(self) -> u64 {
        self.0
    }

    /// Mask used by §1.3 (`rom_size - 1`).
    #[inline]
    pub const fn addr_mask(self) -> u64 {
        self.0 - 1
    }
}

impl fmt::Debug for RomSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RomSize({} MiB)", self.0 / (1024 * 1024))
    }
}

/// A raw 32-bit pointer as it appears in a FET slot, directory entry, or combo
/// entry. Interpreting it requires an [`AddressMode`] (and, for mode `00`, a
/// [`RomSize`]).
#[derive(Copy, Clone, PartialEq, Eq, Hash, Default)]
pub struct Address(pub u32);

impl Address {
    pub const ZERO: Self = Self(0);

    #[inline]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// FET sentinels (§1.2). Slots equal to any of these are skipped — but
    /// their position is preserved on roundtrip.
    #[inline]
    pub const fn is_fet_sentinel(self) -> bool {
        matches!(self.0, 0x0000_0000 | 0xFFFF_FFFE | 0xFFFF_FFFF)
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({:#010x})", self.0)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}", self.0)
    }
}

/// Two-bit address-mode field stored in a directory's `additional_info`
/// (or, when the directory mode is `10`/`11`, in entry-level `rsv0`).
///
/// See `docs/firmware-layout.md` §2.2.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AddressMode {
    /// `00` — Pointer is an x86 physical address in `[0xFF00_0000, 0xFFFF_FFFF]`.
    /// Normalize via §1.3. Some images store flash offsets here too — both
    /// work after masking.
    PhysicalX86 = 0b00,
    /// `01` — Pointer is a flash offset from the start of the BIOS image.
    FlashOffset = 0b01,
    /// `10` — Pointer is an offset from the directory header
    /// (`directory_base + offset`).
    DirectoryRelative = 0b10,
    /// `11` — Pointer is an offset from the partition / slot. Treated
    /// identically to `DirectoryRelative` in PSPTool today.
    PartitionRelative = 0b11,
}

impl AddressMode {
    /// Map a 2-bit value to the enum. The bits are extracted from the
    /// directory's `additional_info` field (or from entry-level `rsv0`) by the
    /// caller — see §2.1 / §2.2 for the bit layout. Only the low two bits are
    /// inspected.
    #[inline]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b00 => Self::PhysicalX86,
            0b01 => Self::FlashOffset,
            0b10 => Self::DirectoryRelative,
            0b11 => Self::PartitionRelative,
            _ => unreachable!(),
        }
    }

    /// Inverse of [`from_bits`]: the canonical 2-bit encoding for this mode.
    #[inline]
    pub const fn bits(self) -> u8 {
        self as u8
    }

    /// Extract the 2-bit address-mode field from a directory's
    /// `additional_info` u32. See §2.1:
    ///
    /// * `bit 31` is the version flag (1 = "v2").
    /// * If version == 1 → `bits[25:24]`.
    /// * If version == 0 ("v2") → `bits[30:29]`.
    #[inline]
    pub const fn from_additional_info(additional_info: u32) -> Self {
        let v1 = (additional_info >> 31) & 1 == 1;
        let bits = if v1 {
            ((additional_info >> 24) & 0b11) as u8
        } else {
            ((additional_info >> 29) & 0b11) as u8
        };
        Self::from_bits(bits)
    }

    /// Whether this directory-scoped mode defers to entry-level
    /// `rsv0[31:30]` for actual address resolution. §2.2 last paragraph.
    #[inline]
    pub const fn defers_to_entry(self) -> bool {
        matches!(self, Self::DirectoryRelative | Self::PartitionRelative)
    }
}

/// Resolution context: information the caller threads into address-mode
/// arithmetic. The directory header offset is needed for
/// [`AddressMode::DirectoryRelative`] and
/// [`AddressMode::PartitionRelative`].
#[derive(Copy, Clone, Debug)]
pub struct ResolveContext {
    pub rom_size: RomSize,
    pub directory_base: FlashOffset,
}

/// Errors returned by [`AddressMode::resolve`] when a raw pointer cannot be
/// converted to a flash offset.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResolveError {
    /// The directory-scoped mode is `10`/`11`, which requires an entry-level
    /// override but [`AddressMode::resolve`] was called without one.
    NeedsEntryMode,
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NeedsEntryMode => f.write_str(
                "directory-scoped address mode is 10/11; an entry-level \
                 address mode override is required",
            ),
        }
    }
}

impl core::error::Error for ResolveError {}

impl AddressMode {
    /// Convert a raw [`Address`] to a [`FlashOffset`] using `self` as the
    /// directory-scoped mode. Implements §1.3 + §2.2.
    ///
    /// For directory modes `10`/`11`, callers must use
    /// [`AddressMode::resolve_with_entry`] — this method returns
    /// [`ResolveError::NeedsEntryMode`] in that case.
    pub fn resolve(self, raw: Address, ctx: ResolveContext) -> Result<FlashOffset, ResolveError> {
        match self {
            Self::PhysicalX86 => Ok(normalise_physical(raw, ctx.rom_size)),
            Self::FlashOffset => Ok(FlashOffset(raw.0 as u64)),
            Self::DirectoryRelative | Self::PartitionRelative => Err(ResolveError::NeedsEntryMode),
        }
    }

    /// Resolve, honouring an entry-level override when the directory mode is
    /// `10`/`11`. Implements §2.2.
    pub fn resolve_with_entry(
        self,
        entry_mode: AddressMode,
        raw: Address,
        ctx: ResolveContext,
    ) -> FlashOffset {
        match self {
            Self::PhysicalX86 => normalise_physical(raw, ctx.rom_size),
            Self::FlashOffset => FlashOffset(raw.0 as u64),
            Self::DirectoryRelative | Self::PartitionRelative => match entry_mode {
                Self::PhysicalX86 => normalise_physical(raw, ctx.rom_size),
                Self::FlashOffset => FlashOffset(raw.0 as u64),
                Self::DirectoryRelative | Self::PartitionRelative => {
                    FlashOffset(ctx.directory_base.0.wrapping_add(raw.0 as u64))
                }
            },
        }
    }

    /// Extract the entry-level address-mode override from the high two bits
    /// (`[31:30]`) of an entry's `rsv0` field. §3.1 / §3.2.
    #[inline]
    pub const fn from_entry_rsv0(rsv0: u32) -> Self {
        Self::from_bits((rsv0 >> 30) as u8)
    }
}

/// §1.3 normalisation. Forces the 16 MiB window for >16 MiB ROMs when the
/// pointer looks like an x86 physical address, otherwise masks with
/// `rom_size - 1`.
#[inline]
fn normalise_physical(raw: Address, rom_size: RomSize) -> FlashOffset {
    let raw = raw.0 as u64;
    if raw > 0xFF00_0000 && rom_size.bytes() > RomSize::MIB_16.bytes() {
        FlashOffset(raw & 0x00FF_FFFF)
    } else {
        FlashOffset(raw & rom_size.addr_mask())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rom_size_constructors() {
        assert_eq!(RomSize::new(8 * 1024 * 1024), Some(RomSize::MIB_8));
        assert_eq!(RomSize::new(16 * 1024 * 1024), Some(RomSize::MIB_16));
        assert_eq!(RomSize::new(32 * 1024 * 1024), Some(RomSize::MIB_32));

        assert_eq!(RomSize::new(0), None);
        assert_eq!(RomSize::new(4 * 1024 * 1024), None); // too small
        assert_eq!(RomSize::new(64 * 1024 * 1024), None); // too large
        assert_eq!(RomSize::new(12 * 1024 * 1024), None); // not power-of-two
    }

    #[test]
    fn rom_size_addr_mask() {
        assert_eq!(RomSize::MIB_16.addr_mask(), 0x00FF_FFFF);
        assert_eq!(RomSize::MIB_8.addr_mask(), 0x007F_FFFF);
        assert_eq!(RomSize::MIB_32.addr_mask(), 0x01FF_FFFF);
    }

    #[test]
    fn fet_sentinels() {
        assert!(Address(0).is_fet_sentinel());
        assert!(Address(0xFFFF_FFFE).is_fet_sentinel());
        assert!(Address(0xFFFF_FFFF).is_fet_sentinel());
        assert!(!Address(0x000A_7000).is_fet_sentinel());
        assert!(!Address(0xFF15_8000).is_fet_sentinel());
    }

    #[test]
    fn address_mode_bits_roundtrip() {
        for bits in 0u8..=3 {
            let mode = AddressMode::from_bits(bits);
            assert_eq!(mode.bits(), bits);
        }
    }

    #[test]
    fn address_mode_ignores_high_bits() {
        // Only low two bits matter.
        assert_eq!(
            AddressMode::from_bits(0b1111_1100),
            AddressMode::PhysicalX86
        );
        assert_eq!(
            AddressMode::from_bits(0b1111_1101),
            AddressMode::FlashOffset
        );
    }

    #[test]
    fn additional_info_v1_decode() {
        // Version flag (bit 31) set => mode in bits [25:24].
        let info = 0b1000_0000_0000_0000_0000_0000_0000_0000u32 | (0b10u32 << 24);
        assert_eq!(
            AddressMode::from_additional_info(info),
            AddressMode::DirectoryRelative
        );

        // version 1, mode 01
        let info = (1u32 << 31) | (0b01u32 << 24);
        assert_eq!(
            AddressMode::from_additional_info(info),
            AddressMode::FlashOffset
        );
    }

    #[test]
    fn additional_info_v2_decode() {
        // Version flag clear => mode in bits [30:29].
        let info = 0b01u32 << 29;
        assert_eq!(
            AddressMode::from_additional_info(info),
            AddressMode::FlashOffset
        );

        let info = 0b11u32 << 29;
        assert_eq!(
            AddressMode::from_additional_info(info),
            AddressMode::PartitionRelative,
        );
    }

    #[test]
    fn additional_info_decode_ignores_unused_bits() {
        // `from_additional_info` consults only the version flag (bit 31) and
        // the mode bits ([25:24] for v1, [30:29] for v2). All other bits are
        // unused by mode decoding. Two corpus-derived values exercise this:
        //   0x0000_0500 = 0b...0_0101_0000_0000  -> v2, bits[30:29]=00 -> PhysicalX86
        //   0x0000_0420 = 0b...0_0100_0010_0000  -> v2, bits[30:29]=00 -> PhysicalX86
        // The non-mode bits (0x500, 0x420) must be preserved on a roundtrip,
        // but that is a serializer concern (#9) and not asserted here.
        assert_eq!(
            AddressMode::from_additional_info(0x0000_0500),
            AddressMode::PhysicalX86
        );
        assert_eq!(
            AddressMode::from_additional_info(0x0000_0420),
            AddressMode::PhysicalX86
        );
    }

    #[test]
    fn defers_to_entry() {
        assert!(!AddressMode::PhysicalX86.defers_to_entry());
        assert!(!AddressMode::FlashOffset.defers_to_entry());
        assert!(AddressMode::DirectoryRelative.defers_to_entry());
        assert!(AddressMode::PartitionRelative.defers_to_entry());
    }

    #[test]
    fn entry_rsv0_high_bits() {
        assert_eq!(
            AddressMode::from_entry_rsv0(0b00 << 30),
            AddressMode::PhysicalX86
        );
        assert_eq!(
            AddressMode::from_entry_rsv0(0b01 << 30),
            AddressMode::FlashOffset
        );
        assert_eq!(
            AddressMode::from_entry_rsv0(0b10 << 30),
            AddressMode::DirectoryRelative
        );
        assert_eq!(
            AddressMode::from_entry_rsv0(0b11 << 30),
            AddressMode::PartitionRelative
        );
        // Low bits are ignored.
        assert_eq!(
            AddressMode::from_entry_rsv0((0b01 << 30) | 0x00FF_FFFF),
            AddressMode::FlashOffset
        );
    }

    fn ctx_16mib() -> ResolveContext {
        ResolveContext {
            rom_size: RomSize::MIB_16,
            directory_base: FlashOffset(0xA7000),
        }
    }

    #[test]
    fn resolve_physical_x86_16mib() {
        // FET examples from docs/firmware-layout.md §1.2
        // 0xFF158000 -> 0x00158000 inside a 16 MiB ROM
        let mode = AddressMode::PhysicalX86;
        assert_eq!(
            mode.resolve(Address(0xFF15_8000), ctx_16mib()).unwrap(),
            FlashOffset(0x0015_8000),
        );
        // 0xFF258000 -> 0x00258000
        assert_eq!(
            mode.resolve(Address(0xFF25_8000), ctx_16mib()).unwrap(),
            FlashOffset(0x0025_8000),
        );
        // Already-flash-offset values also work after masking.
        assert_eq!(
            mode.resolve(Address(0x000A_7000), ctx_16mib()).unwrap(),
            FlashOffset(0x000A_7000),
        );
    }

    #[test]
    fn resolve_physical_x86_32mib_window() {
        // For >16 MiB ROMs an x86 physical address is forced into the 16 MiB
        // window (§1.3 special case).
        let ctx = ResolveContext {
            rom_size: RomSize::MIB_32,
            directory_base: FlashOffset(0),
        };
        assert_eq!(
            AddressMode::PhysicalX86
                .resolve(Address(0xFF15_8000), ctx)
                .unwrap(),
            FlashOffset(0x0015_8000),
        );

        // A pointer that *isn't* in the high x86 region still gets masked by
        // the full ROM size.
        assert_eq!(
            AddressMode::PhysicalX86
                .resolve(Address(0x0123_4567), ctx)
                .unwrap(),
            FlashOffset(0x0123_4567),
        );
    }

    #[test]
    fn resolve_flash_offset() {
        let mode = AddressMode::FlashOffset;
        assert_eq!(
            mode.resolve(Address(0x0038_8000), ctx_16mib()).unwrap(),
            FlashOffset(0x0038_8000),
        );
    }

    #[test]
    fn resolve_directory_modes_require_entry_override() {
        let ctx = ctx_16mib();
        assert_eq!(
            AddressMode::DirectoryRelative.resolve(Address(0x10), ctx),
            Err(ResolveError::NeedsEntryMode),
        );
        assert_eq!(
            AddressMode::PartitionRelative.resolve(Address(0x10), ctx),
            Err(ResolveError::NeedsEntryMode),
        );
    }

    #[test]
    fn resolve_with_entry_directory_relative() {
        let ctx = ctx_16mib(); // directory_base = 0xA7000

        // Directory mode 10 + entry mode 10 → directory_base + offset
        let dir_mode = AddressMode::DirectoryRelative;
        assert_eq!(
            dir_mode.resolve_with_entry(AddressMode::DirectoryRelative, Address(0x100), ctx,),
            FlashOffset(0xA7100),
        );

        // Directory mode 10 + entry mode 01 → flash offset
        assert_eq!(
            dir_mode.resolve_with_entry(AddressMode::FlashOffset, Address(0x0038_8000), ctx,),
            FlashOffset(0x0038_8000),
        );

        // Directory mode 10 + entry mode 00 → physical-x86 normalisation
        assert_eq!(
            dir_mode.resolve_with_entry(AddressMode::PhysicalX86, Address(0xFF15_8000), ctx,),
            FlashOffset(0x0015_8000),
        );
    }

    #[test]
    fn resolve_with_entry_partition_relative_treated_like_directory_relative() {
        // §2.2 says PSPTool treats mode 11 identically to mode 10 today.
        let ctx = ctx_16mib();
        let dir_mode = AddressMode::PartitionRelative;
        assert_eq!(
            dir_mode.resolve_with_entry(AddressMode::PartitionRelative, Address(0x100), ctx,),
            FlashOffset(0xA7100),
        );
    }

    #[test]
    fn resolve_with_entry_when_dir_mode_does_not_defer() {
        // When directory mode is 00/01, the entry-level field is ignored.
        // §2.2 last paragraph.
        let ctx = ctx_16mib();
        // Directory says "flash offset", entry says "directory-relative" —
        // entry-level override is ignored.
        assert_eq!(
            AddressMode::FlashOffset.resolve_with_entry(
                AddressMode::DirectoryRelative,
                Address(0x0038_8000),
                ctx,
            ),
            FlashOffset(0x0038_8000),
        );
        assert_eq!(
            AddressMode::PhysicalX86.resolve_with_entry(
                AddressMode::DirectoryRelative,
                Address(0xFF15_8000),
                ctx,
            ),
            FlashOffset(0x0015_8000),
        );
    }
}
