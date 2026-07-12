//! ACToR critic divergence pin: directory-offset masking for tertiary
//! (0x48/0x4A) L2 targets uses the wrong mask flavour in >16 MiB ROMs.
//!
//! Upstream applies a PLAIN `addr_mask` to every directory offset before
//! parsing (`directory.py:104-105`):
//!
//! ```python
//! def from_offset(cls, fet, rom_offset, zen_generation=None):
//!     rom_offset &= fet.rom.addr_mask
//! ```
//!
//! There is NO `> 0xFF000000` 16 MiB-window override on this path — that
//! override exists only in `entry.py:50-60` (`DirectoryEntry.file_offset()`,
//! mode 0) and `fet.py:66-71` (FET slots). A tertiary block's `[16:20]` value
//! (`directory.py:88`, `actual_tertiary_offset = int.from_bytes(
//! directory_body[16:20], 'little')`) goes STRAIGHT to
//! `create_directories_if_not_exist` → `from_offset` (`directory.py:98`,
//! `directory.py:105`) and is therefore masked with `addr_mask` alone.
//!
//! Target `tertiary_actual_offset` (`directory.rs`) instead resolves the
//! block value via `AddressMode::PhysicalX86.resolve`, i.e. `entry.py` mode-0
//! semantics INCLUDING the window override (`address.rs::normalise_physical`:
//! `raw > 0xFF00_0000 && rom_size > 16 MiB → raw & 0x00FF_FFFF`).
//!
//! The two disagree exactly when the ROM is > 16 MiB and the block value is
//! `> 0xFF000000`:
//!
//! * upstream: `0xFF05_0000 & 0x01FF_FFFF = 0x0105_0000` → parses the `$PL2`
//!   there (live-oracle verified: both `/tmp/psptool-ref` HEAD and the
//!   PSPTOOL_REFERENCE 3.4 install surface `$PL2 @ 0x1050000` for this exact
//!   fixture — no #61 skew),
//! * target:   `0xFF05_0000 & 0x00FF_FFFF = 0x0005_0000` → BadMagic → the L2
//!   directory is silently missed.
//!
//! The two control tests prove the fixture is sound and localise the
//! divergence to the mask flavour: a plain flash-offset block value in the
//! same 32 MiB ROM and the same physical-style value in a 16 MiB ROM (where
//! both maskings coincide) must both surface the L2.
//!
//! Expected values are fixture constants derived from upstream's arithmetic
//! (`block_val & (rom_size - 1)`, `directory.py:105`) and confirmed by
//! live-calling upstream (R-CHAR-3(a)); nothing is copied from target output.
//!
//! Tracking: #68

use psptool_core::fet::{FET_MAGIC_SIZE, FET_SLOT_SIZE, FET_TERMINATOR_SIZE};
use psptool_core::magic::FET_MAGIC;
use psptool_core::{
    Directory, DirectoryRef, Fet, FlashOffset, PL2_MAGIC, PSP_MAGIC, RomSize, SourceBytes,
    walk_directories,
};

const FET_OFF: usize = 0x2_0000;
const L1_PSP_OFF: usize = 0x3_0000; // L1 `$PSP` directory header
const TERTIARY_BLOCK_OFF: usize = 0x4_0000; // 32-byte double-indirection block
/// Zen 4/5 generation tag (`directory.py:38`, `b'\x03\x0D\xBC'` at block[21:24]).
const GEN_ID_LE: u32 = 0xBC0D_0300;

/// Build the FET → L1 `$PSP` → tertiary block → L2 `$PL2` chain.
///
/// `block_val` is written verbatim to `block[16:20]`; the L2 `$PL2` is placed
/// at `l2_off`, which the caller computes as `block_val & (rom_bytes - 1)` —
/// upstream's `from_offset` masking (`directory.py:105`).
fn build_chain(rom_bytes: usize, block_val: u32, l2_off: usize) -> Vec<u8> {
    let mut buf = vec![0u8; rom_bytes];

    // --- FET: magic + one pointer slot → L1 $PSP + terminator. ---
    buf[FET_OFF..FET_OFF + FET_MAGIC_SIZE].copy_from_slice(FET_MAGIC.as_bytes());
    buf[FET_OFF + FET_MAGIC_SIZE..FET_OFF + FET_MAGIC_SIZE + FET_SLOT_SIZE]
        .copy_from_slice(&(L1_PSP_OFF as u32).to_le_bytes());
    let term = FET_OFF + FET_MAGIC_SIZE + FET_SLOT_SIZE;
    buf[term..term + FET_TERMINATOR_SIZE].copy_from_slice(&[0xFF; FET_TERMINATOR_SIZE]);

    // --- L1 $PSP: count=1, additional_info 0x2000_0000 (v2, mode 01 =
    //     FlashOffset), one tertiary (0x48) entry → the 32-byte block. ---
    buf[L1_PSP_OFF..L1_PSP_OFF + 4].copy_from_slice(b"$PSP");
    buf[L1_PSP_OFF + 8..L1_PSP_OFF + 12].copy_from_slice(&1u32.to_le_bytes()); // count
    buf[L1_PSP_OFF + 12..L1_PSP_OFF + 16].copy_from_slice(&0x2000_0000u32.to_le_bytes());
    let e = L1_PSP_OFF + 0x10;
    buf[e] = 0x48; // PSP_FW_L2A_PTR (tertiary)
    buf[e + 4..e + 8].copy_from_slice(&0x20u32.to_le_bytes()); // size = 32
    buf[e + 8..e + 12].copy_from_slice(&(TERTIARY_BLOCK_OFF as u32).to_le_bytes());

    // --- Tertiary block: actual L2 offset at [16:20], gen id at [20:24]. ---
    let b = TERTIARY_BLOCK_OFF;
    buf[b + 16..b + 20].copy_from_slice(&block_val.to_le_bytes());
    buf[b + 20..b + 24].copy_from_slice(&GEN_ID_LE.to_le_bytes());
    buf[b + 24..b + 32].copy_from_slice(&[0xFF; 8]);

    // --- L2 $PL2 at the upstream-masked location: count=1, benign entry. ---
    buf[l2_off..l2_off + 4].copy_from_slice(b"$PL2");
    buf[l2_off + 8..l2_off + 12].copy_from_slice(&1u32.to_le_bytes()); // count
    buf[l2_off + 12..l2_off + 16].copy_from_slice(&0x2000_0000u32.to_le_bytes());
    let l2e = l2_off + 0x10;
    buf[l2e] = 0x21; // WRAPPED_IKEK (NO_HDR) — no further recursion
    buf[l2e + 4..l2e + 8].copy_from_slice(&0x10u32.to_le_bytes()); // size

    buf
}

fn walk(rom_bytes: usize, rom_size: RomSize, block_val: u32, l2_off: usize) -> Vec<DirectoryRef> {
    let buf = build_chain(rom_bytes, block_val, l2_off);
    let blob = SourceBytes::from_blob(buf);
    let fet = Fet::parse_at(&blob, FlashOffset(FET_OFF as u64)).expect("parse FET");
    walk_directories(&blob, &fet, rom_size, FlashOffset::ZERO)
}

/// Control assertion (L1 reachable) + the pin (L2 at the upstream-masked
/// offset surfaced).
fn assert_l2_surfaced(dirs: &[DirectoryRef], l2_off: usize) {
    let l1_found = dirs.iter().any(|d| {
        matches!(&d.directory, Directory::Psp(p) if p.header.magic == PSP_MAGIC)
            && d.directory.source().offset() == FlashOffset(L1_PSP_OFF as u64)
    });
    assert!(
        l1_found,
        "control failed: L1 $PSP @0x{L1_PSP_OFF:x} not surfaced — fixture/FET broken"
    );

    let l2_found = dirs.iter().any(|d| {
        matches!(&d.directory, Directory::Psp(p) if p.header.magic == PL2_MAGIC)
            && d.directory.source().offset() == FlashOffset(l2_off as u64)
    });
    let seen: Vec<(String, u64)> = dirs
        .iter()
        .map(|d| {
            (
                String::from_utf8_lossy(d.directory.header().magic.as_bytes()).into_owned(),
                d.directory.source().offset().get(),
            )
        })
        .collect();
    assert!(
        l2_found,
        "divergence: tertiary L2 target $PL2 @0x{l2_off:x} was NOT surfaced. \
         Upstream masks the block[16:20] value with the plain addr_mask \
         (directory.py:105) and parses the $PL2 there; \
         tertiary_actual_offset applies the entry.py mode-0 >16MiB window \
         override instead. Surfaced dirs = {seen:?}"
    );
}

const MIB: usize = 1024 * 1024;

/// Divergence: in a 32 MiB ROM, a tertiary block value of `0xFF05_0000` must
/// resolve via upstream's plain `addr_mask` (`directory.py:105`):
/// `0xFF05_0000 & 0x01FF_FFFF = 0x0105_0000`. Target masks it to
/// `0x0005_0000` (`address.rs::normalise_physical` >16 MiB window override,
/// reached from `directory.rs::tertiary_actual_offset`) and misses the L2.
///
/// Live oracle: upstream HEAD and PSPTOOL_REFERENCE 3.4 both surface
/// `$PL2 @ 0x1050000` for this byte-identical fixture.
///
/// Tracking: #68
#[test]
#[ignore = "divergence: tertiary dir-offset masking uses PhysicalX86 window override instead of plain addr_mask (directory.py:105); tracking #68"]
fn divergence_tertiary_physical_style_block_val_32mib_plain_addr_mask() {
    let dirs = walk(32 * MIB, RomSize::MIB_32, 0xFF05_0000, 0x0105_0000);
    assert_l2_surfaced(&dirs, 0x0105_0000);
}

/// Control: same 32 MiB chain with a plain flash-offset block value
/// (`0x0105_0000`, below `0xFF00_0000`). Both maskings are the identity here,
/// so this must pass — proving the fixture and the tertiary walk are sound
/// and the failure above is specifically the mask flavour.
#[test]
fn control_tertiary_flash_style_block_val_32mib_surfaces_l2() {
    let dirs = walk(32 * MIB, RomSize::MIB_32, 0x0105_0000, 0x0105_0000);
    assert_l2_surfaced(&dirs, 0x0105_0000);
}

/// Control: the same physical-style value (`0xFF05_0000`) in a 16 MiB ROM.
/// Plain `addr_mask` (`& 0x00FF_FFFF`) and the window override coincide at
/// `0x0005_0000`, so this must pass — localising the divergence to the
/// >16 MiB interplay.
#[test]
fn control_tertiary_physical_style_block_val_16mib_surfaces_l2() {
    let dirs = walk(16 * MIB, RomSize::MIB_16, 0xFF05_0000, 0x0005_0000);
    assert_l2_surfaced(&dirs, 0x0005_0000);
}
