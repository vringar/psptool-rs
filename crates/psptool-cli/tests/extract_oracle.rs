//! `-X -u` differential vs the reference Python PSPTool (#91).
//!
//! Single-file `-X -d D -e E -u` is `file.get_signed_bytes()` in both tools
//! (`__main__.py:169-172`), so the same argv must print the same bytes. The
//! zlib step behind it — `_decrypted_decompressed_body` (`header_file.py:
//! 172-189`) over `utils.zlib_decompress` (`utils.py:218-254`) — has edge cases
//! the corpus barely reaches, so [`synthetic_rom_matches_reference`] builds an
//! image with one entry per edge case and runs both binaries on it;
//! [`corpus_get_signed_bytes_matches_reference`] compares every compressed
//! HeaderFile of the corpus against the reference's `get_signed_bytes()`,
//! except the ones whose header `rom_size` outgrows their directory entry:
//! [`corpus_grown_headerfile_window_matches_reference`] pins those (#99).
//!
//! Gating mirrors `differential.rs`: both tests skip (with a note on stderr)
//! when `PSPTOOL_REFERENCE` is unset, the corpus test also when
//! `PSPTOOL_TEST_CORPUS` is. The nix dev shell sets both.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use psptool_core::{
    Directory, Entry, EntryClass, SourceBytes, detect_rom_layout, scan_fet_candidates,
    walk_directories,
};
use psptool_ops::extract_decompressed;
use sha2::{Digest, Sha256};

const HEADER_LEN: usize = 0x100;
/// What the committed `header_compressed` stream inflates to
/// (`build_fixtures.rs:352`).
const FIXTURE_PLAINTEXT: &[u8] = b"hello, psptool-rs";
/// Upstream's warning for a failed inflate (`header_file.py:184`).
const ZLIB_WARNING: &str = "ZLIB decompression failed on file";

fn reference() -> Option<PathBuf> {
    match std::env::var_os("PSPTOOL_REFERENCE") {
        Some(v) if !v.is_empty() => Some(PathBuf::from(v)),
        _ => {
            eprintln!("PSPTOOL_REFERENCE unset — skipping the reference differential");
            None
        }
    }
}

fn run(program: &Path, args: &[&str]) -> Output {
    Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawning {}: {e}", program.display()))
}

// ---------------------------------------------------------------------------
// Synthetic image
// ---------------------------------------------------------------------------

/// The committed `header_compressed` zlib stream (magic `78 9C`).
fn fixture_stream() -> &'static [u8] {
    let fixture = psptool_fixtures::micro::header_compressed();
    let zlib_size =
        u32::from_le_bytes([fixture[0x54], fixture[0x55], fixture[0x56], fixture[0x57]]);
    &fixture[HEADER_LEN..HEADER_LEN + zlib_size as usize]
}

/// Bytes free of `0x78`, so no zlib magic appears by accident.
fn filler(len: usize) -> Vec<u8> {
    (0..len).map(|i| 0x20 + (i % 0x50) as u8).collect()
}

/// An unsigned, unencrypted, compressed HeaderFile around `region`.
fn compressed_header_file(region: &[u8], zlib_size: usize, size_signed: usize) -> Vec<u8> {
    let mut h = [0u8; HEADER_LEN];
    h[0x10..0x14].copy_from_slice(b"$PS1");
    h[0x14..0x18].copy_from_slice(&(size_signed as u32).to_le_bytes());
    h[0x48..0x4C].copy_from_slice(&1u32.to_le_bytes());
    h[0x50..0x54].copy_from_slice(&(FIXTURE_PLAINTEXT.len() as u32).to_le_bytes());
    h[0x54..0x58].copy_from_slice(&(zlib_size as u32).to_le_bytes());
    h[0x6C..0x70].copy_from_slice(&((HEADER_LEN + region.len()) as u32).to_le_bytes());
    let mut file = h.to_vec();
    file.extend_from_slice(region);
    file
}

/// `(case, file)` — one HeaderFile per zlib edge case of `utils.zlib_decompress`.
fn cases() -> Vec<(&'static str, Vec<u8>)> {
    let stream = fixture_stream();
    let plain = FIXTURE_PLAINTEXT.len();

    // `78 5E` at 0x10 precedes the `78 9C` stream at 0x40; `78 9C` is tried
    // first (`utils.py:224-232`).
    let mut priority = filler(0x40);
    priority[0x10..0x12].copy_from_slice(&[0x78, 0x5E]);
    priority.extend_from_slice(stream);

    let mut corrupt = stream.to_vec();
    corrupt[2] = 0x07; // BTYPE = 11: invalid deflate block

    let mut prefixed = filler(0x30);
    prefixed.extend_from_slice(stream);

    let mut trailing = stream.to_vec();
    trailing.extend_from_slice(&[0xEE; 7]);

    vec![
        (
            "priority",
            compressed_header_file(&priority, priority.len(), 0x40 + plain),
        ),
        // `zlib_size` cuts the adler32 trailer: `zlib.decompress` raises.
        (
            "truncated",
            compressed_header_file(stream, stream.len() - 2, plain),
        ),
        (
            "truncated-long-size-signed",
            compressed_header_file(stream, stream.len() - 2, 0x1000),
        ),
        (
            "corrupt",
            compressed_header_file(&corrupt, corrupt.len(), 0x10),
        ),
        // No magic in `output[:zlib_size]`: returned unchanged (`utils.py:254`).
        (
            "no-magic",
            compressed_header_file(&filler(0x40), 0x20, 0x30),
        ),
        // `zlib_size` past the body: the slice clamps, the tail is ignored.
        (
            "zlib-size-past-body",
            compressed_header_file(&trailing, 0x1000, plain),
        ),
        (
            "prefixed-control",
            compressed_header_file(&prefixed, prefixed.len(), 0x30 + plain),
        ),
    ]
}

/// 8 MiB image (the smallest `detect_rom_layout` accepts): FET at 0x20000,
/// one `$PSP` directory (flash-offset addressing) of `PSP_FW_BOOT_LOADER`
/// entries, bodies 4 KiB-aligned from 0x30000.
fn image(files: &[Vec<u8>]) -> Vec<u8> {
    const FET: usize = 0x2_0000;
    const DIR: usize = 0x2_1000;
    let mut rom = vec![0u8; 0x80_0000];
    rom[FET..FET + 4].copy_from_slice(&[0xAA, 0x55, 0xAA, 0x55]);
    rom[FET + 4..FET + 8].copy_from_slice(&(DIR as u32).to_le_bytes());
    rom[FET + 8..FET + 24].fill(0xFF);
    rom[DIR..DIR + 4].copy_from_slice(b"$PSP");
    rom[DIR + 8..DIR + 0xC].copy_from_slice(&(files.len() as u32).to_le_bytes());
    rom[DIR + 0xC..DIR + 0x10].copy_from_slice(&((1u32 << 31) | (0b01u32 << 24)).to_le_bytes());
    let mut cursor = 0x3_0000;
    for (i, file) in files.iter().enumerate() {
        let rec = DIR + 0x10 + i * 0x10;
        rom[rec] = 0x01;
        rom[rec + 4..rec + 8].copy_from_slice(&(file.len() as u32).to_le_bytes());
        rom[rec + 8..rec + 0xC].copy_from_slice(&(cursor as u32).to_le_bytes());
        rom[cursor..cursor + file.len()].copy_from_slice(file);
        cursor = (cursor + file.len()).next_multiple_of(0x1000);
    }
    rom
}

/// Temp file removed on drop.
struct TempRom(PathBuf);

impl Drop for TempRom {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn synthetic_rom_matches_reference() {
    let Some(reference) = reference() else { return };
    let cases = cases();
    let files: Vec<Vec<u8>> = cases.iter().map(|(_, f)| f.clone()).collect();
    let rom = TempRom(
        std::env::temp_dir().join(format!("psptool_extract_oracle_{}.bin", std::process::id())),
    );
    std::fs::write(&rom.0, image(&files)).expect("write synthetic image");
    let rom_path = rom.0.to_str().expect("utf-8 temp path");
    let ours = Path::new(env!("CARGO_BIN_EXE_psptool"));

    let mut failures = Vec::new();
    for (index, (case, _)) in cases.iter().enumerate() {
        let e = index.to_string();
        let argv = ["-X", "-d", "0", "-e", &e, "-u", rom_path];
        let theirs = run(&reference, &[&["-m", "psptool"], &argv[..]].concat());
        let mine = run(ours, &argv);
        assert!(
            theirs.status.success(),
            "[{case}] reference failed: {}",
            String::from_utf8_lossy(&theirs.stderr)
        );
        if !mine.status.success() || mine.stdout != theirs.stdout {
            failures.push(format!(
                "[{case}] ours exit={:?} {} bytes, reference {} bytes; stderr: {}",
                mine.status.code(),
                mine.stdout.len(),
                theirs.stdout.len(),
                String::from_utf8_lossy(&mine.stderr).trim()
            ));
        }
        let warned = |o: &Output| String::from_utf8_lossy(&o.stderr).contains(ZLIB_WARNING);
        if warned(&mine) != warned(&theirs) {
            failures.push(format!(
                "[{case}] ZLIB warning: ours {}, reference {}",
                warned(&mine),
                warned(&theirs)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

/// Reference side: `address sha256(get_signed_bytes())` for every compressed
/// `HeaderFile` (exact type, as the multi-file `-u` path tests it,
/// `__main__.py:193`) of every directory of every ROM.
const ORACLE: &str = r#"
import hashlib, sys
from psptool import PSPTool
from psptool.header_file import HeaderFile
for path in sys.argv[1:]:
    psp = PSPTool.from_file(path)
    for rom in psp.blob.roms:
        for directory in rom.directories:
            for f in directory.files:
                if type(f) is HeaderFile and f.compressed:
                    digest = hashlib.sha256(f.get_signed_bytes()).hexdigest()
                    print(path, f.get_address(), digest)
"#;

type Digests = BTreeMap<(String, u64), BTreeSet<String>>;

fn reference_digests(reference: &Path, roms: &[PathBuf]) -> Digests {
    let out = Command::new(reference)
        .arg("-c")
        .arg(ORACLE)
        .args(roms)
        .output()
        .unwrap_or_else(|e| panic!("spawning {}: {e}", reference.display()));
    assert!(
        out.status.success(),
        "reference oracle failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut digests = Digests::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let mut fields = line.rsplitn(3, ' ');
        let (Some(digest), Some(address), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            panic!("malformed oracle line {line:?}");
        };
        let address = address.parse().expect("oracle address");
        digests
            .entry((path.to_string(), address))
            .or_default()
            .insert(digest.to_string());
    }
    digests
}

/// Our `-u` bytes for every compressed HeaderFile-class entry whose header
/// `rom_size` exceeds its directory size (`grown`) or does not (`!grown`).
/// Upstream reads a grown HeaderFile on into the image (`header_file.py:
/// 72-75`); extract does not yet (#99).
fn our_digests(roms: &[PathBuf], grown: bool) -> Digests {
    let mut digests = Digests::new();
    for path in roms {
        let blob = SourceBytes::from_blob(std::fs::read(path).expect("read corpus ROM"));
        for position in scan_fet_candidates(&blob) {
            let Some(layout) = detect_rom_layout(&blob, position) else {
                continue;
            };
            for dir in walk_directories(&blob, &layout.fet, layout.rom_size, layout.rom_origin) {
                let entries: Vec<_> = match &dir.directory {
                    Directory::Psp(d) => (0..d.entries.len())
                        .map(|i| Entry::parse_psp(&blob, d, i, layout.rom_size, layout.rom_origin))
                        .collect(),
                    Directory::Bios(d) => (0..d.entries.len())
                        .map(|i| Entry::parse_bios(&blob, d, i, layout.rom_size, layout.rom_origin))
                        .collect(),
                    Directory::Combo(_) => Vec::new(),
                };
                for entry in entries.iter().flatten() {
                    let EntryClass::Header(h) = &entry.class else {
                        continue;
                    };
                    if !h.is_compressed || (h.rom_size as usize > entry.body.len()) != grown {
                        continue;
                    }
                    let digest = match extract_decompressed(entry) {
                        Ok(bytes) => format!("{:x}", Sha256::digest(&bytes)),
                        Err(e) => format!("error: {e}"),
                    };
                    digests
                        .entry((path.display().to_string(), entry.body.offset().get()))
                        .or_default()
                        .insert(digest);
                }
            }
        }
    }
    digests
}

/// Compare our `-u` bytes with the reference's for every compressed
/// HeaderFile address both tools list (`grown` as in [`our_digests`]).
/// Skips when the reference or the corpus is absent.
fn compare_corpus(grown: bool) {
    let Some(reference) = reference() else { return };
    let roms = psptool_fixtures::corpus_rom_paths();
    if roms.is_empty() {
        eprintln!("PSPTOOL_TEST_CORPUS unset or empty — skipping the corpus differential");
        return;
    }
    let oracle = {
        let roms = roms.clone();
        std::thread::spawn(move || reference_digests(&reference, &roms))
    };
    let ours = our_digests(&roms, grown);
    let theirs = oracle.join().expect("reference oracle thread");

    let mut compared = 0usize;
    let mut mismatches = Vec::new();
    for (key, got) in &ours {
        let Some(expected) = theirs.get(key) else {
            continue;
        };
        compared += 1;
        if got != expected {
            mismatches.push(format!(
                "{} @{:#x}: ours {got:?}, reference {expected:?}",
                key.0, key.1
            ));
        }
    }
    eprintln!(
        "compared {compared} of {} compressed HeaderFile addresses ({} reference)",
        ours.len(),
        theirs.len()
    );
    assert!(compared > 0, "no compressed HeaderFile address in common");
    assert!(
        mismatches.is_empty(),
        "{} of {compared} differ:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

#[test]
fn corpus_get_signed_bytes_matches_reference() {
    compare_corpus(false);
}

#[test]
#[ignore = "#99: extract reads the directory-sized entry, upstream grows a HeaderFile to rom_size"]
fn corpus_grown_headerfile_window_matches_reference() {
    compare_corpus(true);
}
