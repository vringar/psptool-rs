//! ACToR critic divergence pin: tertiary-reached directories DROP the Zen
//! generation label that upstream stamps from `block[20:24]` (crosslink #70).
//!
//! Oracle: upstream `psptool/directory.py:85-99`
//! (`create_directories_if_not_exist`, tertiary branch) and the `ls`
//! Generation column at `psptool/psptool.py:79-84`.
//!
//! Upstream, after resolving the tertiary double-indirection, does NOT just
//! take the real L2 offset — it also derives a generation label from the
//! 32-byte block and threads it into the created directory:
//!
//! ```python
//! for tertiary_directory_offset in directory.tertiary_directory_offsets:
//!     directory_body = fet.rom.get_bytes(tertiary_directory_offset, 32)
//!     actual_tertiary_offset = int.from_bytes(directory_body[16:20], 'little')
//!     zen_generation_id = directory_body[21:24]                       # :89
//!     zen_generation = cls.get_possible_zen_generation(zen_generation_id)  # :90
//!     if zen_generation == 'unknown':
//!         fet.psptool.ph.print_warning(f"Unknown {zen_generation_id=}")
//!     zen_generation_id = hex(int.from_bytes(directory_body[20:24], 'little'))  # :94
//!     zen_generation += f' (PSP ID {zen_generation_id})'                        # :95
//!     tertiary_directories = cls.create_directories_if_not_exist(
//!         actual_tertiary_offset, fet, zen_generation)                # :98  <-- LABELLED
//! ```
//!
//! The created `Directory.zen_generation` (`directory.py:124`) is then printed
//! verbatim in the `ls` Generation column (`psptool.py:84`,
//! `directory.zen_generation`). So on Zen 4/5 (AM5) firmware, the L2 `$PL2`
//! reached through a `0x48`/`0x4A` tertiary block shows e.g.
//! `Zen 4/5 (PSP ID 0x30dbc)` — NOT a blank cell.
//!
//! psptool-rs mirrors the #51 offset double-indirection
//! (`directory.rs::tertiary_actual_offset`) but that function returns ONLY the
//! offset — it discards `block[20:24]`. The tertiary walk therefore yields a
//! `DirectoryProvenance::L2Pointer`, and `psptool_ops::list::directory_generation`
//! only stamps a generation for `DirectoryProvenance::ComboEntry`. Result: a
//! tertiary-reached directory renders a BLANK Generation column, diverging from
//! upstream which labels it with the block's generation.
//!
//! The generation id `0xBC0D0300` (`block[20:24] = 00 03 0D BC`;
//! `block[21:24] = 03 0D BC`) is the known Zen 4/5 tag
//! (`ZEN_GENERATION_IDS['Zen 4/5'] = [b'\x03\x0D\xBC']`, `directory.py:38`),
//! which the project's own `PspGenerationId::zen_generation()` maps to
//! `ZenGeneration::Zen4Or5` (label `"Zen4Or5"`). The expected label is NOT
//! copied from the tertiary parser output (which produces nothing) — it is the
//! label the working combo path renders for the SAME generation-id bytes, as
//! proved by the passing `control_combo_reached_directory_carries_generation`
//! test below (R-CHAR-3: expected value cross-validated, not tautological).
//!
//! Tracking: #70

use psptool_core::fet::{FET_MAGIC_SIZE, FET_SLOT_SIZE, FET_TERMINATOR_SIZE};
use psptool_core::magic::FET_MAGIC;
use psptool_core::{Fet, FlashOffset, RomSize, SourceBytes, walk_directories};
use psptool_ops::{RomListing, list_default};

const ROM_BYTES: usize = 0x100_0000; // 16 MiB → addr_mask = 0x00FF_FFFF
const FET_OFF: usize = 0x2_0000;

// --- Tertiary chain offsets (mirror the #51 divergence_tertiary fixture). ---
const L1_PSP_OFF: usize = 0x3_0000; // L1 `$PSP` directory header
const TERTIARY_BLOCK_OFF: usize = 0x4_0000; // 32-byte double-indirection block
const L2_PL2_OFF: usize = 0x5_0000; // the REAL L2 `$PL2` directory

// --- Combo control offsets. ---
const COMBO_OFF: usize = 0x6_0000;
const COMBO_CHILD_PSP_OFF: usize = 0x7_0000;

/// The known Zen 4/5 generation id (`block[21:24] = 03 0D BC`,
/// `directory.py:38`). Same bytes for the tertiary block and the combo entry so
/// both paths map to `ZenGeneration::Zen4Or5`.
const ZEN45_GEN_ID: u32 = 0xBC0D_0300;

/// The `zen_label(ZenGeneration::Zen4Or5)` string the project renders for
/// `ZEN45_GEN_ID`. Traceable to upstream `ZEN_GENERATION_IDS['Zen 4/5']`
/// (`directory.py:38`); its correctness for this gen id is proved by the combo
/// control test, not asserted by fiat.
const ZEN45_LABEL: &str = "Zen4Or5";

fn parse_rom(buf: Vec<u8>) -> (SourceBytes, Fet, Vec<psptool_core::DirectoryRef>) {
    let blob = SourceBytes::from_blob(buf);
    let fet = Fet::parse_at(&blob, FlashOffset(FET_OFF as u64)).expect("parse FET");
    let dirs = walk_directories(&blob, &fet, RomSize::MIB_16, FlashOffset::ZERO);
    (blob, fet, dirs)
}

fn render(buf: Vec<u8>) -> String {
    let (blob, fet, dirs) = parse_rom(buf);
    let rom = RomListing {
        index: 0,
        blob: &blob,
        rom_size: RomSize::MIB_16,
        rom_origin: FlashOffset::ZERO,
        fet: &fet,
        directories: &dirs,
    };
    list_default(&rom)
}

/// FET + 1 pointer slot (→ `target`) + terminator into `buf`.
fn write_fet(buf: &mut [u8], target: usize) {
    buf[FET_OFF..FET_OFF + FET_MAGIC_SIZE].copy_from_slice(FET_MAGIC.as_bytes());
    buf[FET_OFF + FET_MAGIC_SIZE..FET_OFF + FET_MAGIC_SIZE + FET_SLOT_SIZE]
        .copy_from_slice(&(target as u32).to_le_bytes());
    let term = FET_OFF + FET_MAGIC_SIZE + FET_SLOT_SIZE;
    buf[term..term + FET_TERMINATOR_SIZE].copy_from_slice(&[0xFF; FET_TERMINATOR_SIZE]);
}

/// Build the L1 `$PSP` → tertiary block → L2 `$PL2` chain.
/// `block[20:24]` carries `gen_id_le`.
fn build_tertiary_chain(tertiary_type: u8, gen_id_le: u32) -> Vec<u8> {
    let mut buf = vec![0u8; ROM_BYTES];
    write_fet(&mut buf, L1_PSP_OFF);

    // L1 $PSP: count=1, address_mode = FlashOffset (v2 bits[30:29]=01 →
    // additional_info 0x2000_0000), single tertiary entry.
    buf[L1_PSP_OFF..L1_PSP_OFF + 4].copy_from_slice(b"$PSP");
    buf[L1_PSP_OFF + 8..L1_PSP_OFF + 12].copy_from_slice(&1u32.to_le_bytes());
    buf[L1_PSP_OFF + 12..L1_PSP_OFF + 16].copy_from_slice(&0x2000_0000u32.to_le_bytes());

    let e = L1_PSP_OFF + 0x10;
    buf[e] = tertiary_type; // 0x48 / 0x4A
    buf[e + 4..e + 8].copy_from_slice(&0x20u32.to_le_bytes()); // size = 32
    buf[e + 8..e + 12].copy_from_slice(&(TERTIARY_BLOCK_OFF as u32).to_le_bytes()); // → block

    // 32-byte tertiary block: [16:20]=actual offset, [20:24]=generation id.
    let b = TERTIARY_BLOCK_OFF;
    buf[b + 16..b + 20].copy_from_slice(&(L2_PL2_OFF as u32).to_le_bytes());
    buf[b + 20..b + 24].copy_from_slice(&gen_id_le.to_le_bytes());

    // L2 $PL2: count=1, one benign NO_HDR entry (no further recursion).
    buf[L2_PL2_OFF..L2_PL2_OFF + 4].copy_from_slice(b"$PL2");
    buf[L2_PL2_OFF + 8..L2_PL2_OFF + 12].copy_from_slice(&1u32.to_le_bytes());
    buf[L2_PL2_OFF + 12..L2_PL2_OFF + 16].copy_from_slice(&0x2000_0000u32.to_le_bytes());
    let l2e = L2_PL2_OFF + 0x10;
    buf[l2e] = 0x21; // WRAPPED_IKEK (NO_HDR)
    buf[l2e + 4..l2e + 8].copy_from_slice(&0x10u32.to_le_bytes());

    buf
}

/// Build a FET → `2PSP` combo → `$PSP` chain whose combo entry carries
/// `gen_id_le`. This is the path that ALREADY threads the generation into the
/// Generation column, so it is the control proving the render machinery works.
fn build_combo_chain(gen_id_le: u32) -> Vec<u8> {
    let mut buf = vec![0u8; ROM_BYTES];
    write_fet(&mut buf, COMBO_OFF);

    // Combo header (16) + reserved (16) + one 16-byte combo entry.
    buf[COMBO_OFF..COMBO_OFF + 4].copy_from_slice(b"2PSP");
    buf[COMBO_OFF + 8..COMBO_OFF + 12].copy_from_slice(&1u32.to_le_bytes()); // count = 1
    // reserved block @ +0x10 stays zero.
    let ce = COMBO_OFF + 0x20; // first combo entry
    // entry_flags @+0x00 = 0; psp_generation @+0x04; pointer @+0x08; reserved @+0x0C.
    buf[ce + 4..ce + 8].copy_from_slice(&gen_id_le.to_le_bytes());
    buf[ce + 8..ce + 12].copy_from_slice(&(COMBO_CHILD_PSP_OFF as u32).to_le_bytes());

    // Child $PSP reached via the combo entry: count=0 (no entries needed).
    buf[COMBO_CHILD_PSP_OFF..COMBO_CHILD_PSP_OFF + 4].copy_from_slice(b"$PSP");
    buf[COMBO_CHILD_PSP_OFF + 8..COMBO_CHILD_PSP_OFF + 12].copy_from_slice(&0u32.to_le_bytes());
    buf[COMBO_CHILD_PSP_OFF + 12..COMBO_CHILD_PSP_OFF + 16]
        .copy_from_slice(&0x2000_0000u32.to_le_bytes());

    buf
}

/// CONTROL (must PASS): a combo-reached `$PSP` renders the `Zen4Or5` label in
/// the `ls` Generation column for gen id `0xBC0D0300`. This proves (a) the
/// render path surfaces the generation, and (b) `ZEN45_LABEL` is the correct
/// expected string for these gen-id bytes — so the pin below is not
/// tautological.
#[test]
fn control_combo_reached_directory_carries_generation() {
    let out = render(build_combo_chain(ZEN45_GEN_ID));
    assert!(
        out.contains("2PSP") && out.contains("$PSP"),
        "control fixture broken: combo + child $PSP not surfaced.\n{out}"
    );
    assert!(
        out.contains(ZEN45_LABEL),
        "control failed: combo path did not render generation `{ZEN45_LABEL}` \
         for gen id 0x{ZEN45_GEN_ID:08X}; render machinery is broken.\n{out}"
    );
}

/// PIN (must FAIL against current code): a tertiary-reached `$PL2` must carry
/// the generation label derived from `block[20:24]` (upstream
/// `directory.py:88-98` → `ls` Generation column `psptool.py:84`).
///
/// The 0x48 tertiary block's `block[20:24] = 0xBC0D0300` (Zen 4/5). Upstream
/// stamps the `$PL2` with `Zen 4/5 (PSP ID 0x30dbc)`; the project's own mapping
/// for these bytes is `Zen4Or5` (proved by the combo control). Current code
/// discards `block[20:24]` in `tertiary_actual_offset`, so the `$PL2`'s
/// Generation column is BLANK → this assertion fails.
///
/// Tracking: #70
#[test]
fn divergence_tertiary_0x48_directory_carries_generation() {
    let out = render(build_tertiary_chain(0x48, ZEN45_GEN_ID));

    // Control within the pin: the L2 $PL2 IS surfaced (the #51 offset walk
    // works), so the failure below is specifically the missing generation.
    assert!(
        out.contains("$PL2"),
        "fixture/#51 regression: tertiary L2 $PL2 not surfaced at all.\n{out}"
    );

    // The pin: the tertiary-reached $PL2 must show the Zen 4/5 generation.
    // No combo exists in this fixture, so `Zen4Or5` can only come from the
    // tertiary block[20:24]. Current code renders a blank cell → FAILS.
    assert!(
        out.contains(ZEN45_LABEL),
        "divergence #70: tertiary-reached $PL2 @0x{L2_PL2_OFF:x} carries NO \
         generation label. Upstream (directory.py:88-98) derives `{ZEN45_LABEL}` \
         (Zen 4/5) from block[20:24]=0x{ZEN45_GEN_ID:08X} and prints it in the \
         ls Generation column (psptool.py:84); psptool-rs discards block[20:24] \
         in tertiary_actual_offset.\n{out}"
    );
}

/// PIN variant (0x4A `PSP_FW_L2B_PTR`), same divergence.
///
/// Tracking: #70
#[test]
fn divergence_tertiary_0x4a_directory_carries_generation() {
    let out = render(build_tertiary_chain(0x4A, ZEN45_GEN_ID));
    assert!(
        out.contains("$PL2"),
        "fixture/#51 regression: tertiary L2 $PL2 not surfaced at all.\n{out}"
    );
    assert!(
        out.contains(ZEN45_LABEL),
        "divergence #70: tertiary-reached $PL2 @0x{L2_PL2_OFF:x} carries NO \
         generation label via 0x4A. Upstream directory.py:88-98 labels it \
         `{ZEN45_LABEL}` from block[20:24]=0x{ZEN45_GEN_ID:08X}.\n{out}"
    );
}
