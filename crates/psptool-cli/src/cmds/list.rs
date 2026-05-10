//! `list` subcommand — binds to `psptool_ops::list_default` /
//! `list_verbose` / `list_json`.

use std::io::Write;
use std::path::Path;

use anyhow::{Result, bail};
use psptool_core::{Directory, Entry, FlashOffset, RomSize, SourceBytes, scan_fet_candidates};
use psptool_ops::{RomListing, list_default, list_json, list_verbose};

use crate::cli::ListArgs;
use crate::load::{OpenedRom, open_rom};

/// Run the `list` subcommand.
pub fn run(args: &ListArgs, out: &mut dyn Write) -> Result<()> {
    if args.key_tree {
        // Cert-tree key tree is upstream's `psp.cert_tree.print_key_tree()`;
        // wiring it requires a core API that has not yet been ported. Bail
        // with a clear, non-zero exit rather than silently lying with a
        // placeholder. Tracked as a follow-up.
        bail!(
            "-t/--key-tree is not yet implemented (cert-tree wiring is a follow-up; tracked separately)"
        );
    }
    if args.no_duplicates {
        // Upstream `-E -n` calls `psp.ls_files()` which lists `unique_files`
        // (deduped by body bytes) ordered by offset. The required core API
        // is not yet ported. Same rationale as `-t`: fail loudly rather than
        // silently dropping the flag.
        bail!(
            "-n/--no-duplicates is not yet implemented for list (requires unique_files core API; tracked separately)"
        );
    }
    let opened = open_rom(&args.file, args.rom_index)?;
    if args.metrics {
        write_metrics(&args.file, &opened, out)?;
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

/// Mirror upstream `PSPTool.print_metrics()` (psptool/psptool.py:272-284).
///
/// Output format is a verbatim port of the Python f-string self-documenting
/// debug lines (`f'{var=}'`). The PrintHelper counters are not tracked by
/// psptool-rs and are emitted as zeros — they exist so the line set matches
/// upstream byte-for-byte. `unique_files_count` is computed by deduping
/// entry body bytes across every reachable PSP/BIOS entry in every ROM.
fn write_metrics(file: &Path, opened: &OpenedRom, out: &mut dyn Write) -> Result<()> {
    let filename = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| file.display().to_string());
    writeln!(out, "{filename}")?;
    writeln!(out, "self.ph.error_count=0")?;
    writeln!(out, "self.ph.warning_count=0")?;
    writeln!(out, "self.ph.info_count=0")?;

    // Walk every ROM in the blob to compute the same metrics upstream does
    // (`len(self.blob.roms)`, `sum(... rom.directories ...)`,
    // `len(self.blob.unique_files())`). Re-scan from `opened.blob` rather
    // than re-reading the file.
    let blob: &SourceBytes = &opened.blob;
    let layouts: Vec<_> = scan_fet_candidates(blob)
        .iter()
        .filter_map(|pos| psptool_core::detect_rom_layout(blob, *pos))
        .collect();
    let rom_count = layouts.len();
    let mut directory_count = 0usize;
    let mut unique_bodies: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    for layout in &layouts {
        let dirs =
            psptool_core::walk_directories(blob, &layout.fet, layout.rom_size, layout.rom_origin);
        directory_count += dirs.len();
        for dr in &dirs {
            collect_unique_bodies(
                blob,
                &dr.directory,
                layout.rom_size,
                layout.rom_origin,
                &mut unique_bodies,
            );
        }
    }
    let unique_files_count = unique_bodies.len();

    writeln!(out, "rom_count={rom_count}")?;
    writeln!(out, "directory_count={directory_count}")?;
    writeln!(out, "unique_files_count={unique_files_count}")?;
    Ok(())
}

fn collect_unique_bodies(
    blob: &SourceBytes,
    dir: &Directory,
    rom_size: RomSize,
    rom_origin: FlashOffset,
    out: &mut std::collections::HashSet<Vec<u8>>,
) {
    match dir {
        Directory::Psp(p) => {
            for ei in 0..p.entries.len() {
                if let Ok(entry) = Entry::parse_psp(blob, p, ei, rom_size, rom_origin) {
                    out.insert(entry.body.as_bytes().to_vec());
                }
            }
        }
        Directory::Bios(b) => {
            for ei in 0..b.entries.len() {
                if let Ok(entry) = Entry::parse_bios(blob, b, ei, rom_size, rom_origin) {
                    out.insert(entry.body.as_bytes().to_vec());
                }
            }
        }
        Directory::Combo(_) => {}
    }
}
