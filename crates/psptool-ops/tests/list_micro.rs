//! Snapshot tests for [`psptool_ops::list_default`] / [`list_verbose`] /
//! [`list_json`] driven by the handcrafted micro-fixtures from
//! `psptool-fixtures`. The corpus path is intentionally out of scope here —
//! issue #18 covers differential testing against the reference Python tool.

use psptool_core::{Address, Fet, FetSlot, FlashOffset, RomSize, SourceBytes, walk_directories};
use psptool_fixtures::micro;
use psptool_ops::{RomListing, list_default, list_json, list_verbose};

const ROM_SIZE_BYTES: u64 = 0x100_0000; // 16 MiB

/// Build a synthetic 16 MiB rom with an FET at flash offset 0x20000 that
/// points at a single PSP directory placed at flash offset 0xA7000. This
/// mirrors the fixture in `psptool_core::directory::tests::synthetic_blob_with_psp_at`.
fn build_psp_blob() -> Vec<u8> {
    use psptool_core::fet::{FET_MAGIC_SIZE, FET_SLOT_SIZE, FET_TERMINATOR_SIZE};
    use psptool_core::magic::FET_MAGIC;

    let mut buf = vec![0u8; ROM_SIZE_BYTES as usize];

    let fet_off = 0x20_000usize;
    buf[fet_off..fet_off + FET_MAGIC_SIZE].copy_from_slice(FET_MAGIC.as_bytes());
    buf[fet_off + FET_MAGIC_SIZE..fet_off + FET_MAGIC_SIZE + FET_SLOT_SIZE]
        .copy_from_slice(&0x000A_7000u32.to_le_bytes());
    let term_off = fet_off + FET_MAGIC_SIZE + FET_SLOT_SIZE;
    buf[term_off..term_off + FET_TERMINATOR_SIZE].copy_from_slice(&[0xFF; FET_TERMINATOR_SIZE]);

    let dir_off = 0xA_7000usize;
    let dir_bytes = micro::psp_directory();
    buf[dir_off..dir_off + dir_bytes.len()].copy_from_slice(dir_bytes);

    buf
}

/// Same shape as `build_psp_blob` but the directory is a `$BHD`.
fn build_bhd_blob() -> Vec<u8> {
    use psptool_core::fet::{FET_MAGIC_SIZE, FET_SLOT_SIZE, FET_TERMINATOR_SIZE};
    use psptool_core::magic::FET_MAGIC;

    let mut buf = vec![0u8; ROM_SIZE_BYTES as usize];

    let fet_off = 0x20_000usize;
    buf[fet_off..fet_off + FET_MAGIC_SIZE].copy_from_slice(FET_MAGIC.as_bytes());
    buf[fet_off + FET_MAGIC_SIZE..fet_off + FET_MAGIC_SIZE + FET_SLOT_SIZE]
        .copy_from_slice(&0x000A_7000u32.to_le_bytes());
    let term_off = fet_off + FET_MAGIC_SIZE + FET_SLOT_SIZE;
    buf[term_off..term_off + FET_TERMINATOR_SIZE].copy_from_slice(&[0xFF; FET_TERMINATOR_SIZE]);

    let dir_off = 0xA_7000usize;
    let dir_bytes = micro::bhd_directory();
    buf[dir_off..dir_off + dir_bytes.len()].copy_from_slice(dir_bytes);

    buf
}

/// FET-only blob (no directories) — exercises the empty-listing path.
fn build_empty_directories_blob() -> Vec<u8> {
    use psptool_core::fet::{FET_MAGIC_SIZE, FET_SLOT_SIZE, FET_TERMINATOR_SIZE};
    use psptool_core::magic::FET_MAGIC;

    let mut buf = vec![0u8; ROM_SIZE_BYTES as usize];
    let fet_off = 0x20_000usize;
    buf[fet_off..fet_off + FET_MAGIC_SIZE].copy_from_slice(FET_MAGIC.as_bytes());
    // One sentinel slot so the FET is parseable but resolves to nothing.
    buf[fet_off + FET_MAGIC_SIZE..fet_off + FET_MAGIC_SIZE + FET_SLOT_SIZE]
        .copy_from_slice(&0u32.to_le_bytes());
    let term_off = fet_off + FET_MAGIC_SIZE + FET_SLOT_SIZE;
    buf[term_off..term_off + FET_TERMINATOR_SIZE].copy_from_slice(&[0xFF; FET_TERMINATOR_SIZE]);
    buf
}

fn parse_rom(buf: Vec<u8>) -> (SourceBytes, Fet, Vec<psptool_core::DirectoryRef>) {
    let blob = SourceBytes::from_blob(buf);
    let fet = Fet::parse_at(&blob, FlashOffset(0x20_000)).expect("parse FET");
    let directories = walk_directories(&blob, &fet, RomSize::MIB_16, FlashOffset::ZERO);
    (blob, fet, directories)
}

#[test]
fn list_default_psp_micro() {
    let buf = build_psp_blob();
    let (blob, fet, dirs) = parse_rom(buf);
    let rom = RomListing {
        index: 0,
        blob: &blob,
        rom_size: RomSize::MIB_16,
        rom_origin: FlashOffset::ZERO,
        fet: &fet,
        directories: &dirs,
    };
    insta::assert_snapshot!(list_default(&rom));
}

#[test]
fn list_verbose_psp_micro() {
    let buf = build_psp_blob();
    let (blob, fet, dirs) = parse_rom(buf);
    let rom = RomListing {
        index: 0,
        blob: &blob,
        rom_size: RomSize::MIB_16,
        rom_origin: FlashOffset::ZERO,
        fet: &fet,
        directories: &dirs,
    };
    insta::assert_snapshot!(list_verbose(&rom));
}

#[test]
fn list_json_psp_micro() {
    let buf = build_psp_blob();
    let (blob, fet, dirs) = parse_rom(buf);
    let rom = RomListing {
        index: 0,
        blob: &blob,
        rom_size: RomSize::MIB_16,
        rom_origin: FlashOffset::ZERO,
        fet: &fet,
        directories: &dirs,
    };
    insta::assert_json_snapshot!(list_json(&rom, false));
}

#[test]
fn list_json_verbose_psp_micro() {
    let buf = build_psp_blob();
    let (blob, fet, dirs) = parse_rom(buf);
    let rom = RomListing {
        index: 0,
        blob: &blob,
        rom_size: RomSize::MIB_16,
        rom_origin: FlashOffset::ZERO,
        fet: &fet,
        directories: &dirs,
    };
    insta::assert_json_snapshot!(list_json(&rom, true));
}

#[test]
fn list_default_bhd_micro() {
    let buf = build_bhd_blob();
    let (blob, fet, dirs) = parse_rom(buf);
    let rom = RomListing {
        index: 0,
        blob: &blob,
        rom_size: RomSize::MIB_16,
        rom_origin: FlashOffset::ZERO,
        fet: &fet,
        directories: &dirs,
    };
    insta::assert_snapshot!(list_default(&rom));
}

#[test]
fn list_json_bhd_micro() {
    let buf = build_bhd_blob();
    let (blob, fet, dirs) = parse_rom(buf);
    let rom = RomListing {
        index: 0,
        blob: &blob,
        rom_size: RomSize::MIB_16,
        rom_origin: FlashOffset::ZERO,
        fet: &fet,
        directories: &dirs,
    };
    insta::assert_json_snapshot!(list_json(&rom, false));
}

#[test]
fn list_default_empty_directories() {
    let buf = build_empty_directories_blob();
    let (blob, fet, dirs) = parse_rom(buf);
    assert!(dirs.is_empty(), "FET sentinel resolves to no directories");
    let rom = RomListing {
        index: 0,
        blob: &blob,
        rom_size: RomSize::MIB_16,
        rom_origin: FlashOffset::ZERO,
        fet: &fet,
        directories: &dirs,
    };
    insta::assert_snapshot!(list_default(&rom));
}

#[test]
fn list_json_empty_directories_is_empty_array() {
    let buf = build_empty_directories_blob();
    let (blob, fet, dirs) = parse_rom(buf);
    let rom = RomListing {
        index: 0,
        blob: &blob,
        rom_size: RomSize::MIB_16,
        rom_origin: FlashOffset::ZERO,
        fet: &fet,
        directories: &dirs,
    };
    let v = list_json(&rom, false);
    assert_eq!(v, serde_json::Value::Array(Vec::new()));
}

#[test]
fn fet_pointer_addresses_are_byte_stable() {
    // Sanity: confirm the FET pointer slot really is a Pointer, so the
    // walk_directories path under test is exercised by the snapshot tests.
    let buf = build_psp_blob();
    let (_blob, fet, _) = parse_rom(buf);
    let pointer_count = fet
        .slots
        .iter()
        .filter(|s| matches!(s.slot, FetSlot::Pointer(Address(0x000A_7000))))
        .count();
    assert_eq!(pointer_count, 1);
}
