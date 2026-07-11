//! ACToR critic divergence pin for the tertiary (0x48/0x4A) L2 directory
//! pointer double-indirection (crosslink #51).
//!
//! Oracle: upstream `psptool/directory.py:80-101`
//! (`create_directories_if_not_exist`) and the type tables at
//! `psptool/file.py:34-35`:
//!
//! ```text
//! SECONDARY_DIRECTORY_ENTRY_TYPES = [0x40, 0x49, 0x70]   # followed by us
//! TERTIARY_DIRECTORY_ENTRY_TYPES  = [0x48, 0x4a]         # NOT followed by us
//! ```
//!
//! For a tertiary entry, upstream does a **double indirection** introduced in
//! Zen 4 (`directory.py:85-99`):
//!
//! ```python
//! for tertiary_directory_offset in directory.tertiary_directory_offsets:
//!     directory_body = fet.rom.get_bytes(tertiary_directory_offset, 32)
//!     actual_tertiary_offset = int.from_bytes(directory_body[16:20], 'little')
//!     zen_generation_id = directory_body[21:24]
//!     zen_generation = cls.get_possible_zen_generation(zen_generation_id)
//!     if zen_generation == 'unknown':
//!         fet.psptool.ph.print_warning(f"Unknown {zen_generation_id=}")
//!     ...
//!     tertiary_directories = cls.create_directories_if_not_exist(
//!         actual_tertiary_offset, fet, zen_generation)
//! ```
//!
//! i.e. the tertiary entry points at a 32-byte block; the REAL L2 directory
//! address lives at `block[16:20]`, and the generation id at `block[20:24]`;
//! upstream then recurses into that address and parses the `$PL2` there —
//! even when the generation id is unknown (it only prints a warning).
//!
//! `psptool-core`'s `walk_directories` originally STOPPED at tertiary entries
//! ("Tertiary (0x48/0x4a) requires reading the entry body and is deferred to
//! issue #7"), so on modern AM5 (Zen 4/5) firmware it surfaced only the L1
//! `$PSP` stub and none of the real L2 directories. It now follows the
//! double-indirection (see `tertiary_actual_offset`); these tests are the
//! regression pin.
//!
//! Both tests below build a minimal L1 `$PSP` → tertiary block → L2 `$PL2`
//! chain and assert the L2 directory is surfaced. They FAIL against current
//! code (which never follows the tertiary pointer). The expected L2 address
//! is a symbolic constant of the fixture layout, never copied from the
//! parser's output (R-CHAR-3).
//!
//! Tracking: #51

use psptool_core::fet::{FET_MAGIC_SIZE, FET_SLOT_SIZE, FET_TERMINATOR_SIZE};
use psptool_core::magic::FET_MAGIC;
use psptool_core::{
    Directory, DirectoryRef, FlashOffset, PL2_MAGIC, PSP_MAGIC, RomSize, SourceBytes,
    walk_directories,
};

// Fixed flash offsets of the synthetic chain (§ mirrors ASRock_B650 layout).
const ROM_BYTES: usize = 0x100_0000; // 16 MiB → addr_mask = 0x00FF_FFFF
const FET_OFF: usize = 0x2_0000;
const L1_PSP_OFF: usize = 0x3_0000; // L1 `$PSP` directory header
const TERTIARY_BLOCK_OFF: usize = 0x4_0000; // 32-byte double-indirection block
const L2_PL2_OFF: usize = 0x5_0000; // the REAL L2 `$PL2` directory

/// Build the shared L1→tertiary→L2 chain into a 16 MiB blob.
///
/// `gen_id_le` is written verbatim into `block[20:24]`; `block[21:24]` is the
/// three high bytes upstream matches against `ZEN_GENERATION_IDS`.
/// `tertiary_type` is the L1 entry type (0x48 `PSP_FW_L2A_PTR` or 0x4A
/// `PSP_FW_L2B_PTR`).
fn build_chain(tertiary_type: u8, gen_id_le: u32) -> Vec<u8> {
    let mut buf = vec![0u8; ROM_BYTES];

    // --- FET at 0x20000: magic + one pointer slot → L1 $PSP + terminator. ---
    buf[FET_OFF..FET_OFF + FET_MAGIC_SIZE].copy_from_slice(FET_MAGIC.as_bytes());
    // FET pointers normalise as PhysicalX86; 0x30000 & 0xFFFFFF = 0x30000.
    buf[FET_OFF + FET_MAGIC_SIZE..FET_OFF + FET_MAGIC_SIZE + FET_SLOT_SIZE]
        .copy_from_slice(&(L1_PSP_OFF as u32).to_le_bytes());
    let term = FET_OFF + FET_MAGIC_SIZE + FET_SLOT_SIZE;
    buf[term..term + FET_TERMINATOR_SIZE].copy_from_slice(&[0xFF; FET_TERMINATOR_SIZE]);

    // --- L1 $PSP directory: count=1, address_mode = FlashOffset (v2, bits
    //     [30:29] = 01 → additional_info 0x2000_0000), so entry.offset is a
    //     direct flash offset. Single entry = the tertiary pointer. ---
    buf[L1_PSP_OFF..L1_PSP_OFF + 4].copy_from_slice(b"$PSP");
    buf[L1_PSP_OFF + 4..L1_PSP_OFF + 8].copy_from_slice(&0u32.to_le_bytes()); // checksum (unverified by walk)
    buf[L1_PSP_OFF + 8..L1_PSP_OFF + 12].copy_from_slice(&1u32.to_le_bytes()); // count = 1
    buf[L1_PSP_OFF + 12..L1_PSP_OFF + 16].copy_from_slice(&0x2000_0000u32.to_le_bytes()); // FlashOffset

    let e = L1_PSP_OFF + 0x10; // first PSP entry (16 bytes)
    buf[e] = tertiary_type; // type 0x48 / 0x4A
    buf[e + 1] = 0; // subprogram
    buf[e + 2..e + 4].copy_from_slice(&0u16.to_le_bytes()); // flags
    buf[e + 4..e + 8].copy_from_slice(&0x20u32.to_le_bytes()); // size = 32 (the tertiary block)
    buf[e + 8..e + 12].copy_from_slice(&(TERTIARY_BLOCK_OFF as u32).to_le_bytes()); // offset → block
    buf[e + 12..e + 16].copy_from_slice(&0u32.to_le_bytes()); // rsv0

    // --- 32-byte tertiary block @ 0x40000 (mirrors the empirical B650 block).
    //     actual_offset = le_u32(block[16:20]); gen_id = le_u32(block[20:24]). ---
    let b = TERTIARY_BLOCK_OFF;
    buf[b..b + 4].copy_from_slice(&0x37_6a_8e_75u32.to_le_bytes()); // arbitrary (upstream ignores [0:16])
    buf[b + 4..b + 8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    buf[b + 8..b + 12].copy_from_slice(&0x0000_000Fu32.to_le_bytes());
    buf[b + 12..b + 16].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
    buf[b + 16..b + 20].copy_from_slice(&(L2_PL2_OFF as u32).to_le_bytes()); // actual_offset
    buf[b + 20..b + 24].copy_from_slice(&gen_id_le.to_le_bytes()); // gen id
    buf[b + 24..b + 28].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    buf[b + 28..b + 32].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    // --- L2 $PL2 directory @ actual_offset: count=1, one benign NO_HDR entry.
    //     Must be a well-formed directory so parse_at succeeds. ---
    buf[L2_PL2_OFF..L2_PL2_OFF + 4].copy_from_slice(b"$PL2");
    buf[L2_PL2_OFF + 4..L2_PL2_OFF + 8].copy_from_slice(&0u32.to_le_bytes()); // checksum
    buf[L2_PL2_OFF + 8..L2_PL2_OFF + 12].copy_from_slice(&1u32.to_le_bytes()); // count = 1
    buf[L2_PL2_OFF + 12..L2_PL2_OFF + 16].copy_from_slice(&0x2000_0000u32.to_le_bytes());
    let l2e = L2_PL2_OFF + 0x10;
    buf[l2e] = 0x21; // WRAPPED_IKEK (NO_HDR) — no further recursion
    buf[l2e + 4..l2e + 8].copy_from_slice(&0x10u32.to_le_bytes()); // size
    buf[l2e + 8..l2e + 12].copy_from_slice(&0u32.to_le_bytes()); // offset

    buf
}

/// Assert `dirs` contains the L1 `$PSP` (control: the walk works) but MISSES
/// the L2 `$PL2` at `actual_offset` (the pinned divergence). The L2 address is
/// the fixture constant `L2_PL2_OFF`, not a value read back from the parser.
fn assert_l2_surfaced(dirs: &[DirectoryRef]) {
    // Control: the L1 $PSP stub IS reachable, proving the fixture + FET walk
    // are sound and the failure below is specifically the tertiary miss.
    let l1_found = dirs.iter().any(|d| {
        matches!(&d.directory, Directory::Psp(p) if p.header.magic == PSP_MAGIC)
            && d.directory.source().offset() == FlashOffset(L1_PSP_OFF as u64)
    });
    assert!(
        l1_found,
        "control failed: L1 $PSP @0x{L1_PSP_OFF:x} not surfaced — fixture/FET broken"
    );

    // The pin: upstream (directory.py:85-99) follows the tertiary block's
    // [16:20] pointer and parses the $PL2 at actual_offset. We must too.
    let l2_found = dirs.iter().any(|d| {
        matches!(&d.directory, Directory::Psp(p) if p.header.magic == PL2_MAGIC)
            && d.directory.source().offset() == FlashOffset(L2_PL2_OFF as u64)
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
        "divergence #51: tertiary L2 target $PL2 @0x{L2_PL2_OFF:x} was NOT \
         surfaced; walk_directories stops at the 0x48/0x4A entry instead of \
         following block[16:20]. Upstream directory.py:85-99 parses it. \
         Surfaced dirs = {seen:?}"
    );
}

/// Divergence: `walk_directories` does not follow a tertiary `0x48`
/// (`PSP_FW_L2A_PTR`) pointer's double-indirection to the real L2 directory.
///
/// Upstream `directory.py:86-99` reads 32 bytes at the entry offset, takes
/// `actual_offset = le_u32(block[16:20])`, and recurses into the `$PL2` there.
/// Gen id `0xBC0D0300` (bytes `00 03 0D BC`; `block[21:24] = 03 0D BC`) is the
/// known Zen 4/5 tag (`directory.py:38`).
///
/// Tracking: #51
#[test]
fn divergence_tertiary_0x48_known_gen_surfaces_l2() {
    let buf = build_chain(0x48, 0xBC0D_0300);
    let blob = SourceBytes::from_blob(buf);
    let fet = psptool_core::Fet::parse_at(&blob, FlashOffset(FET_OFF as u64)).expect("parse FET");
    let dirs = walk_directories(&blob, &fet, RomSize::MIB_16, FlashOffset::ZERO);
    assert_l2_surfaced(&dirs);
}

/// Divergence: same double-indirection via a `0x4A` (`PSP_FW_L2B_PTR`) entry
/// carrying an UNKNOWN generation id (`0xBC0E0B00`; `block[21:24] = 0B 0E BC`,
/// not in `ZEN_GENERATION_IDS`). Upstream only prints
/// `Unknown zen_generation_id=...` and STILL recurses (`directory.py:91-98`),
/// so the L2 directory must still be surfaced — an unknown generation is not
/// an error. This is the X870E/B850 4.43 case from #51.
///
/// Tracking: #51
#[test]
fn divergence_tertiary_0x4a_unknown_gen_still_surfaces_l2() {
    let buf = build_chain(0x4A, 0xBC0E_0B00);
    let blob = SourceBytes::from_blob(buf);
    let fet = psptool_core::Fet::parse_at(&blob, FlashOffset(FET_OFF as u64)).expect("parse FET");
    let dirs = walk_directories(&blob, &fet, RomSize::MIB_16, FlashOffset::ZERO);
    assert_l2_surfaced(&dirs);
}
