//! `extract` subcommand — binds to `psptool_ops::extract_raw` /
//! `extract_decompressed` / `extract_decrypted`.
//!
//! Selectors:
//!   * `-d` + `-e` → exactly one entry (single-file mode).
//!   * `-T regex` → match against `readable_type`. 0 → error; 1 → extract
//!     that entry; N identical → warn + first; N differing → error (mirrors
//!     upstream `find_files_by_type_regex`).
//!   * none → multi-file mode: every entry under the chosen ROM is written
//!     to `outdir/d{NN}_e{NN}_{TYPE}` (upstream `__main__.py` filename rules).
//!
//! Transforms (`-u`/`-c`/`-k`) modify the output bytes per entry. In
//! single-file mode, an unsuitable entry is rejected with a typed error
//! (matching upstream's "errors if file is not compressed in single-file
//! mode"). In multi-file mode, unsuitable entries fall back to the raw body
//! (matches upstream's "silently ignored for non-pubkey files in `-k`" /
//! "`get_decrypted_body()` for `-c` multi-file" behaviour).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use psptool_core::{Directory, Entry, EntryClass, EntryRecord, Ikek, walk_directories};
use psptool_ops::{extract_decompressed, extract_decrypted, extract_raw, readable_type};
use regex::RegexBuilder;

use crate::cli::ExtractArgs;
use crate::load::{OpenedRom, open_rom};

/// Run the `extract` subcommand.
pub fn run(args: &ExtractArgs, out: &mut dyn Write) -> Result<()> {
    let opened = open_rom(&args.file, args.rom_index)?;
    let mode = ExtractMode::from_args(args)?;
    match mode {
        ExtractMode::Single(selector) => {
            let entry = resolve_single(&opened, &selector)?;
            let bytes = transform_single(&entry, args)?;
            write_single_output(&bytes, args.outfile.as_deref(), out)?;
        }
        ExtractMode::Multi => {
            let outdir = args
                .outfile
                .clone()
                .unwrap_or_else(|| default_outdir(&args.file, args.no_duplicates));
            fs::create_dir_all(&outdir)
                .with_context(|| format!("creating output directory {}", outdir.display()))?;
            extract_all(&opened, &outdir, args)?;
            writeln!(out, "wrote entries to {}", outdir.display())?;
        }
    }
    Ok(())
}

enum ExtractMode {
    Single(EntrySelector),
    Multi,
}

enum EntrySelector {
    Indices { dir: usize, file: usize },
    Regex(String),
}

impl ExtractMode {
    fn from_args(args: &ExtractArgs) -> Result<Self> {
        match (args.directory_index, args.file_index, &args.type_regex) {
            (Some(_), None, _) | (None, Some(_), _) => {
                bail!("-d and -e must be supplied together");
            }
            (Some(d), Some(e), None) => Ok(ExtractMode::Single(EntrySelector::Indices {
                dir: d,
                file: e,
            })),
            (None, None, Some(re)) => Ok(ExtractMode::Single(EntrySelector::Regex(re.clone()))),
            (Some(_), Some(_), Some(_)) => {
                bail!("-T cannot be combined with -d/-e selectors");
            }
            (None, None, None) => Ok(ExtractMode::Multi),
        }
    }
}

fn resolve_single(opened: &OpenedRom, selector: &EntrySelector) -> Result<Entry> {
    match selector {
        EntrySelector::Indices { dir, file } => parse_entry_at(opened, *dir, *file),
        EntrySelector::Regex(re_src) => {
            let re = RegexBuilder::new(re_src)
                .case_insensitive(true)
                .build()
                .with_context(|| format!("compiling type regex {re_src:?}"))?;
            let mut matches: Vec<Entry> = Vec::new();
            for_each_entry(opened, |entry, _, _, is_bios| {
                let name = readable_type(entry.entry_type(), is_bios);
                if re.is_match(&name) {
                    matches.push(entry.clone());
                }
            });
            match matches.len() {
                0 => bail!("no entry matches type regex {re_src:?}"),
                1 => Ok(matches.remove(0)),
                _ => {
                    let first_bytes = matches[0].body.as_bytes();
                    let all_same = matches[1..]
                        .iter()
                        .all(|e| e.body.as_bytes() == first_bytes);
                    if all_same {
                        eprintln!(
                            "warning: regex {re_src:?} matched {} entries with identical bytes; extracting the first",
                            matches.len()
                        );
                        Ok(matches.remove(0))
                    } else {
                        bail!(
                            "regex {re_src:?} matched {} entries with differing bytes; not extracting any",
                            matches.len()
                        );
                    }
                }
            }
        }
    }
}

fn transform_single(entry: &Entry, args: &ExtractArgs) -> Result<Vec<u8>> {
    if args.decompress {
        Ok(extract_decompressed(entry).context("decompressing entry")?)
    } else if args.decrypt {
        Ok(extract_decrypted(entry, Ikek::ZenPlus).context("decrypting entry")?)
    } else if args.pem_key {
        let pk = match &entry.class {
            EntryClass::Pubkey(p) => p,
            _ => bail!("-k specified but entry is not a pubkey"),
        };
        Ok(pem_for_pubkey(pk)?)
    } else {
        Ok(extract_raw(entry))
    }
}

fn write_single_output(bytes: &[u8], outfile: Option<&Path>, out: &mut dyn Write) -> Result<()> {
    match outfile {
        Some(path) => {
            fs::write(path, bytes).with_context(|| format!("writing output {}", path.display()))?;
            writeln!(out, "wrote {} bytes to {}", bytes.len(), path.display())?;
        }
        None => {
            // Match upstream `to_stdout()`: raw bytes to stdout. Because our
            // `out` is `&mut dyn Write`, the binary path works for both the
            // real stdout (`std::io::stdout().lock()`) and snapshot-test
            // sinks.
            out.write_all(bytes)?;
        }
    }
    Ok(())
}

fn extract_all(opened: &OpenedRom, outdir: &Path, args: &ExtractArgs) -> Result<()> {
    let mut written = 0usize;
    for_each_entry(opened, |entry, dir_idx, entry_idx, is_bios| {
        let bytes = if args.decompress {
            extract_decompressed(entry).unwrap_or_else(|_| extract_raw(entry))
        } else if args.decrypt {
            extract_decrypted(entry, Ikek::ZenPlus).unwrap_or_else(|_| extract_raw(entry))
        } else if args.pem_key {
            match &entry.class {
                EntryClass::Pubkey(p) => pem_for_pubkey(p).unwrap_or_else(|_| extract_raw(entry)),
                _ => extract_raw(entry),
            }
        } else {
            extract_raw(entry)
        };
        let name = readable_type(entry.entry_type(), is_bios);
        // Mirrors `psptool/__main__.py:202-209`. The bare type name collides
        // for entries that share a (type, dir, file) but differ in
        // subprogram/instance or HeaderFile version — without the suffixes
        // multi-file extract silently overwrites earlier outputs.
        let stem = if args.no_duplicates {
            // Upstream `unique_files` path (line 226): `'%s' % readable_type`,
            // optionally with `_{readable_version}` for HeaderFile entries.
            let mut s = name.clone();
            if let Some(ver) = header_version_suffix(entry) {
                s.push_str(&ver);
            }
            s
        } else {
            let mut s = format!("d{:02}_e{:02}_{}", dir_idx, entry_idx, name);
            if let Some(suffix) = sub_ins_suffix(entry) {
                s.push_str(&suffix);
            }
            if let Some(ver) = header_version_suffix(entry) {
                s.push_str(&ver);
            }
            s
        };
        let path = outdir.join(sanitize_for_path(&stem));
        if let Err(err) = fs::write(&path, &bytes) {
            eprintln!("warning: writing {}: {}", path.display(), err);
        } else {
            written += 1;
        }
    });
    if written == 0 {
        return Err(anyhow!("no entries extracted"));
    }
    Ok(())
}

/// `_SUB_{hex}_INS_{hex}` when either field is non-zero, mirroring upstream's
/// `if file.entry.subprogram != 0 or file.entry.instance != 0:` branch.
/// Format matches Python's `hex()` output (`0x0` not `0x00`).
fn sub_ins_suffix(entry: &Entry) -> Option<String> {
    let (subprogram, instance) = match &entry.record {
        EntryRecord::Psp(p) => (p.subprogram, p.instance()),
        EntryRecord::Bios(b) => (b.subprogram(), b.instance()),
    };
    if subprogram == 0 && instance == 0 {
        return None;
    }
    Some(format!("_SUB_{:#x}_INS_{:#x}", subprogram, instance))
}

/// `_X.Y.Z.W` for HeaderEntry-class entries, mirroring
/// `HeaderFile.get_readable_version()` (psptool/header_file.py:131-132):
/// the four `version` bytes, reversed, each rendered as upper-case hex
/// without a `0x` prefix, joined by `.`.
fn header_version_suffix(entry: &Entry) -> Option<String> {
    let header = match &entry.class {
        EntryClass::Header(h) => h,
        _ => return None,
    };
    let parts: Vec<String> = header
        .version
        .iter()
        .rev()
        .map(|b| format!("{:X}", b))
        .collect();
    Some(format!("_{}", parts.join(".")))
}

fn parse_entry_at(opened: &OpenedRom, dir: usize, file: usize) -> Result<Entry> {
    let dir_ref = opened
        .directories
        .get(dir)
        .ok_or_else(|| anyhow!("directory index {dir} out of range"))?;
    match &dir_ref.directory {
        Directory::Psp(p) => {
            Entry::parse_psp(&opened.blob, p, file, opened.rom_size, opened.rom_origin)
                .with_context(|| format!("parsing PSP entry {dir}.{file}"))
        }
        Directory::Bios(b) => {
            Entry::parse_bios(&opened.blob, b, file, opened.rom_size, opened.rom_origin)
                .with_context(|| format!("parsing BIOS entry {dir}.{file}"))
        }
        Directory::Combo(_) => Err(anyhow!(
            "directory {dir} is a combo directory; entries cannot be extracted directly"
        )),
    }
}

fn for_each_entry(opened: &OpenedRom, mut f: impl FnMut(&Entry, usize, usize, bool)) {
    let dirs = walk_directories(
        &opened.blob,
        &opened.fet,
        opened.rom_size,
        opened.rom_origin,
    );
    for (di, dr) in dirs.iter().enumerate() {
        match &dr.directory {
            Directory::Psp(p) => {
                for ei in 0..p.entries.len() {
                    if let Ok(entry) =
                        Entry::parse_psp(&opened.blob, p, ei, opened.rom_size, opened.rom_origin)
                    {
                        f(&entry, di, ei, false);
                    }
                }
            }
            Directory::Bios(b) => {
                for ei in 0..b.entries.len() {
                    if let Ok(entry) =
                        Entry::parse_bios(&opened.blob, b, ei, opened.rom_size, opened.rom_origin)
                    {
                        f(&entry, di, ei, true);
                    }
                }
            }
            Directory::Combo(_) => {}
        }
    }
}

fn default_outdir(file: &Path, unique: bool) -> PathBuf {
    let stem = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "rom".to_string());
    let suffix = if unique {
        "_unique_extracted"
    } else {
        "_extracted"
    };
    PathBuf::from(format!("{stem}{suffix}"))
}

fn sanitize_for_path(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c == '/' || c == '\\' || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect()
}

/// Render a parsed `PubkeyEntry` as a PEM-encoded RSA public key.
///
/// Mirrors `PubkeyFile.get_pem_encoded()`. Only RSA `e=65537` is supported in
/// the upstream tool — anything else returns an error.
fn pem_for_pubkey(pk: &psptool_core::PubkeyEntry) -> Result<Vec<u8>> {
    use rsa::pkcs8::{EncodePublicKey, LineEnding};
    use rsa::{BigUint, RsaPublicKey};

    // Pubkey blob layout: header (0x40) | pubexp (pubexp_size) | modulus (modulus_size).
    let bytes = pk.source.as_bytes();
    let pubexp_size = pk.pubexp_size();
    let modulus_size = pk.modulus_size();
    let pubexp_off = 0x40usize;
    let modulus_off = pubexp_off + pubexp_size;
    if bytes.len() < modulus_off + modulus_size {
        bail!("pubkey body too short to contain modulus");
    }
    let n = BigUint::from_bytes_le(&bytes[modulus_off..modulus_off + modulus_size]);
    let e = BigUint::from(65537u32);
    let key = RsaPublicKey::new(n, e).context("constructing RSA public key")?;
    let pem = key
        .to_public_key_pem(LineEnding::LF)
        .context("PEM-encoding public key")?;
    Ok(pem.into_bytes())
}
