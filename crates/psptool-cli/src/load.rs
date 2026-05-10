//! Load a firmware image, detect FET / ROM layout, walk directories.
//!
//! All subcommands share the same prologue: read the file, scan for FET
//! candidates, pick the requested ROM, materialise its directory list. The
//! helpers in this module factor that prologue out so each command file can
//! stay focused on its own output formatting.

use std::path::Path;

use anyhow::{Context, Result, anyhow};
use psptool_core::{
    DirectoryRef, Fet, FlashOffset, RomLayout, RomSize, SourceBytes, detect_rom_layout,
    scan_fet_candidates, walk_directories,
};

/// One ROM inside a (possibly multi-ROM) blob, plus its already-walked
/// directory list. Returned by [`open_rom`].
pub struct OpenedRom {
    pub blob: SourceBytes,
    pub fet: Fet,
    pub rom_size: RomSize,
    pub rom_origin: FlashOffset,
    pub directories: Vec<DirectoryRef>,
}

/// Read `path` into memory and locate the requested ROM by index.
pub fn open_rom(path: &Path, rom_index: usize) -> Result<OpenedRom> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading firmware image {}", path.display()))?;
    let blob = SourceBytes::from_blob(bytes);
    let candidates = scan_fet_candidates(&blob);
    if candidates.is_empty() {
        return Err(anyhow!(
            "{}: no FET (Firmware Entry Table) found",
            path.display()
        ));
    }
    let layout = candidates
        .iter()
        .filter_map(|pos| detect_rom_layout(&blob, *pos))
        .nth(rom_index)
        .ok_or_else(|| {
            anyhow!(
                "ROM index {rom_index} out of range (found {} ROM(s))",
                candidates.len()
            )
        })?;
    Ok(opened_from_layout(blob, layout))
}

fn opened_from_layout(blob: SourceBytes, layout: RomLayout) -> OpenedRom {
    let RomLayout {
        rom_origin,
        rom_size,
        fet,
    } = layout;
    let directories = walk_directories(&blob, &fet, rom_size, rom_origin);
    OpenedRom {
        blob,
        fet,
        rom_size,
        rom_origin,
        directories,
    }
}
