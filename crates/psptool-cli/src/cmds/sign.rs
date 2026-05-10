//! `sign` subcommand — binds to `psptool_ops::sign_entry`.

use std::fs;
use std::io::Write;

use anyhow::{Context, Result, anyhow, bail};
use psptool_core::{BlobEditor, Directory, Entry, EntryClass};
use psptool_ops::sign_entry;

use crate::cli::SignArgs;
use crate::load::{OpenedRom, open_rom};

pub fn run(args: &SignArgs, out: &mut dyn Write) -> Result<()> {
    let opened = open_rom(&args.file, args.rom_index)?;
    let entry = parse_entry(&opened, args.directory_index, args.file_index)?;
    if !matches!(entry.class, EntryClass::Header(_) | EntryClass::KeyStore(_)) {
        bail!("target entry is not a HeaderFile-class signed entry");
    }
    let priv_key = load_priv_key(&args.privkey)?;
    let mut editor = BlobEditor::from_blob(opened.blob.clone());
    sign_entry(&mut editor, &entry, &priv_key, None)?;
    let bytes = editor.serialize();
    fs::write(&args.outfile, &bytes)
        .with_context(|| format!("writing {}", args.outfile.display()))?;
    writeln!(
        out,
        "wrote {} bytes to {}",
        bytes.len(),
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

fn parse_entry(opened: &OpenedRom, dir_idx: usize, entry_idx: usize) -> Result<Entry> {
    let dir_ref = opened
        .directories
        .get(dir_idx)
        .ok_or_else(|| anyhow!("directory index {dir_idx} out of range"))?;
    match &dir_ref.directory {
        Directory::Psp(p) => Entry::parse_psp(
            &opened.blob,
            p,
            entry_idx,
            opened.rom_size,
            opened.rom_origin,
        )
        .map_err(Into::into),
        Directory::Bios(b) => Entry::parse_bios(
            &opened.blob,
            b,
            entry_idx,
            opened.rom_size,
            opened.rom_origin,
        )
        .map_err(Into::into),
        Directory::Combo(_) => bail!("cannot sign entries in a combo directory"),
    }
}
