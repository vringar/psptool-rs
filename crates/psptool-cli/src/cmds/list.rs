//! `list` subcommand — binds to `psptool_ops::list_default` /
//! `list_verbose` / `list_json`.

use std::io::Write;

use anyhow::Result;
use psptool_ops::{RomListing, list_default, list_json, list_verbose};

use crate::cli::ListArgs;
use crate::load::{OpenedRom, open_rom};

/// Run the `list` subcommand.
pub fn run(args: &ListArgs, out: &mut dyn Write) -> Result<()> {
    let opened = open_rom(&args.file, args.rom_index)?;
    if args.key_tree {
        // Cert-tree key tree is not yet wired through `psptool-ops`; mirror
        // the upstream flag with a clear placeholder so existing scripts get
        // a well-defined exit instead of a silent no-op.
        writeln!(
            out,
            "key-tree printing is not yet implemented (psptool-ops cert-tree wiring is a follow-up)"
        )?;
        return Ok(());
    }
    if args.metrics {
        write_metrics(&opened, out)?;
        return Ok(());
    }
    let listing = build_listing(&opened, args.rom_index);
    if args.json {
        let value = list_json(&listing, args.verbose);
        let s = serde_json::to_string(&value)?;
        writeln!(out, "{s}")?;
    } else if args.verbose {
        out.write_all(list_verbose(&listing).as_bytes())?;
    } else {
        out.write_all(list_default(&listing).as_bytes())?;
    }
    let _ = args.no_duplicates; // upstream `-n` filter — accepted for compat;
    // unique-file dedup is a directory-walk concern that lives one layer
    // deeper than the current `list_default` rendering. Existing callers
    // that pass `-n` get the standard listing, never an error.
    Ok(())
}

fn build_listing<'a>(opened: &'a OpenedRom, rom_index: usize) -> RomListing<'a> {
    RomListing {
        index: rom_index,
        blob: &opened.blob,
        rom_size: opened.rom_size,
        rom_origin: opened.rom_origin,
        fet: &opened.fet,
        directories: &opened.directories,
    }
}

fn write_metrics(opened: &OpenedRom, out: &mut dyn Write) -> Result<()> {
    writeln!(out, "directories: {}", opened.directories.len())?;
    let total_entries: usize = opened
        .directories
        .iter()
        .map(|d| match &d.directory {
            psptool_core::Directory::Psp(p) => p.entries.len(),
            psptool_core::Directory::Bios(b) => b.entries.len(),
            psptool_core::Directory::Combo(c) => c.entries.len(),
        })
        .sum();
    writeln!(out, "entries: {total_entries}")?;
    writeln!(out, "rom_size: {:#x}", opened.rom_size.bytes())?;
    Ok(())
}
