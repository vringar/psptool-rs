//! `replace` subcommand — binds to `psptool_ops::replace_psp_entry_body` /
//! `replace_bios_entry_body`, optionally followed by `sign_entry`.

use std::fs;
use std::io::Write;

use anyhow::{Context, Result, anyhow, bail};
use psptool_core::{BlobEditor, Directory, Entry, EntryClass};
use psptool_ops::{replace_bios_entry_body, replace_psp_entry_body, sign_entry};

use crate::cli::ReplaceArgs;
use crate::load::{OpenedRom, open_rom};

/// Run the `replace` subcommand.
pub fn run(args: &ReplaceArgs, out: &mut dyn Write) -> Result<()> {
    let opened = open_rom(&args.file, args.rom_index)?;
    let dir_ref = opened
        .directories
        .get(args.directory_index)
        .ok_or_else(|| anyhow!("directory index {} out of range", args.directory_index))?;

    let mut editor = BlobEditor::from_blob(opened.blob.clone());

    if let Some(subfile_path) = &args.subfile {
        let new_body = fs::read(subfile_path)
            .with_context(|| format!("reading subfile {}", subfile_path.display()))?;
        match &dir_ref.directory {
            Directory::Psp(p) => replace_psp_entry_body(
                &mut editor,
                p,
                args.file_index,
                opened.rom_size,
                opened.rom_origin,
                &new_body,
            )?,
            Directory::Bios(b) => replace_bios_entry_body(
                &mut editor,
                b,
                args.file_index,
                opened.rom_size,
                opened.rom_origin,
                &new_body,
            )?,
            Directory::Combo(_) => bail!("cannot replace entries in a combo directory"),
        }
    }

    if let Some(privkey_path) = &args.privkey {
        let priv_key = load_priv_key(privkey_path)?;
        // Re-parse the entry against the *post-replacement* body so the
        // signature region we patch matches the new layout.
        let serialized = editor.serialize();
        let blob = psptool_core::SourceBytes::from_blob(serialized);
        let entry = parse_entry(&blob, &opened, args.directory_index, args.file_index)?;
        if matches!(entry.class, EntryClass::Header(_) | EntryClass::KeyStore(_)) {
            // Build a fresh editor over the post-replacement bytes so the
            // sign patch coordinates are correct.
            let mut sign_editor = BlobEditor::from_blob(blob);
            sign_entry(&mut sign_editor, &entry, &priv_key, None)?;
            let final_bytes = sign_editor.serialize();
            fs::write(&args.outfile, &final_bytes)
                .with_context(|| format!("writing {}", args.outfile.display()))?;
            writeln!(
                out,
                "wrote {} bytes to {}",
                final_bytes.len(),
                args.outfile.display()
            )?;
            return Ok(());
        } else {
            writeln!(
                out,
                "warning: target entry is not signed; -p ignored (no signature region to rewrite)"
            )?;
        }
    }

    let final_bytes = editor.serialize();
    fs::write(&args.outfile, &final_bytes)
        .with_context(|| format!("writing {}", args.outfile.display()))?;
    writeln!(
        out,
        "wrote {} bytes to {}",
        final_bytes.len(),
        args.outfile.display()
    )?;
    Ok(())
}

fn load_priv_key(path: &std::path::Path) -> Result<rsa::RsaPrivateKey> {
    use rsa::pkcs8::DecodePrivateKey;
    let pem = fs::read_to_string(path)
        .with_context(|| format!("reading private key {}", path.display()))?;
    let key = rsa::RsaPrivateKey::from_pkcs8_pem(&pem)
        .with_context(|| format!("parsing PKCS#8 PEM private key {}", path.display()))?;
    Ok(key)
}

fn parse_entry(
    blob: &psptool_core::SourceBytes,
    opened: &OpenedRom,
    dir_idx: usize,
    entry_idx: usize,
) -> Result<Entry> {
    // Re-walk against the new bytes to keep directory layout pointers fresh.
    let dirs =
        psptool_core::walk_directories(blob, &opened.fet, opened.rom_size, opened.rom_origin);
    let dir_ref = dirs
        .get(dir_idx)
        .ok_or_else(|| anyhow!("directory index {dir_idx} out of range after replace"))?;
    match &dir_ref.directory {
        Directory::Psp(p) => {
            Entry::parse_psp(blob, p, entry_idx, opened.rom_size, opened.rom_origin)
                .map_err(Into::into)
        }
        Directory::Bios(b) => {
            Entry::parse_bios(blob, b, entry_idx, opened.rom_size, opened.rom_origin)
                .map_err(Into::into)
        }
        Directory::Combo(_) => bail!("combo directory cannot host replace target"),
    }
}
