//! `-X -u` / `-X -c` differential vs the reference Python PSPTool (#91, #99).
//!
//! Single-file `-X -d D -e E -u` is `file.get_signed_bytes()` and `-c` is
//! `file.to_decrypted_file_bytes()` in both tools (`__main__.py:169-176`);
//! multi-file `-X -u` / `-c` writes `get_signed_bytes()` /
//! `get_decrypted_body()` for every HeaderFile and `get_bytes()` for every
//! other file (`__main__.py:191-213`). The same argv must produce the same
//! bytes.
//!
//! Two shapes the corpus barely reaches get a synthetic image with one entry
//! per edge case, run through both binaries in single-file
//! ([`synthetic_rom_matches_reference`]) and multi-file
//! ([`synthetic_rom_multi_file_matches_reference`]) mode: the zlib step behind
//! `-u` — `_decrypted_decompressed_body` (`header_file.py:172-189`) over
//! `utils.zlib_decompress` (`utils.py:218-254`) — and HeaderFiles whose header
//! `rom_size` outgrows their directory entry, which upstream reads on into the
//! image (`header_file.py:72-75`).
//! [`corpus_get_signed_bytes_matches_reference`] compares the `-u` and `-c`
//! bytes of every corpus HeaderFile against the reference's
//! `get_signed_bytes()` / `to_decrypted_file_bytes()`;
//! [`corpus_grown_headerfile_window_matches_reference`] does the same for the
//! ones whose `rom_size` outgrows their directory entry (#99).
//!
//! Gating mirrors `differential.rs`: every test skips (with a note on stderr)
//! when `PSPTOOL_REFERENCE` is unset, the corpus tests also when
//! `PSPTOOL_TEST_CORPUS` is. The nix dev shell sets both.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use psptool_core::{
    Directory, Entry, EntryClass, Ikek, SourceBytes, detect_rom_layout, scan_fet_candidates,
    walk_directories,
};
use psptool_ops::{extract_decompressed, extract_decrypted};
use sha2::{Digest, Sha256};

const HEADER_LEN: usize = 0x100;
/// RSA-2048 signature length (`signature_type == 0`, `header_file.py:84-85`).
const SIG_LEN: usize = 0x100;
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

fn ours() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_psptool"))
}

// ---------------------------------------------------------------------------
// Synthetic images
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

/// `file` signed: `signed = 1`, `signature_type = 0` and a 0x100-byte
/// signature at `rom_size - 0x100` (`header_file.py:83-88`), `rom_size`
/// re-stamped to cover it.
fn signed(mut file: Vec<u8>) -> Vec<u8> {
    file[0x30..0x34].copy_from_slice(&1u32.to_le_bytes());
    file[0x34..0x38].fill(0);
    file.extend(std::iter::repeat_n(0xBB, SIG_LEN));
    let rom_size = file.len() as u32;
    file[0x6C..0x70].copy_from_slice(&rom_size.to_le_bytes());
    file
}

/// One directory entry of a synthetic image: `file` placed in the image, of
/// which the directory record declares `size` bytes.
#[derive(Clone)]
struct Placed {
    entry_type: u8,
    file: Vec<u8>,
    size: usize,
}

impl Placed {
    /// A `PSP_FW_BOOT_LOADER` entry — a `HeaderFile` (`file.py:264-265`) —
    /// declaring all of `file`.
    fn header_file(file: Vec<u8>) -> Self {
        Self {
            entry_type: 0x01,
            size: file.len(),
            file,
        }
    }

    /// A `WRAPPED_IKEK` entry — no header (`file.py:239`), so multi-file
    /// `-u` / `-c` write its `get_bytes()` (`__main__.py:200`).
    fn plain(file: Vec<u8>) -> Self {
        Self {
            entry_type: 0x21,
            size: file.len(),
            file,
        }
    }

    /// The directory declares only `size` bytes of the file; its header
    /// `rom_size` still spans all of it, so upstream grows the HeaderFile past
    /// the directory entry into the image (`header_file.py:74-75`).
    fn declaring(mut self, size: usize) -> Self {
        self.size = size;
        self
    }
}

/// `-u` cases: one HeaderFile per zlib edge case of `utils.zlib_decompress`,
/// and HeaderFiles grown past their directory entry (#99).
fn decompress_cases() -> Vec<(&'static str, Placed)> {
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

    let file = |region: &[u8], zlib_size: usize, size_signed: usize| {
        Placed::header_file(compressed_header_file(region, zlib_size, size_signed))
    };
    vec![
        ("priority", file(&priority, priority.len(), 0x40 + plain)),
        // `zlib_size` cuts the adler32 trailer: `zlib.decompress` raises.
        ("truncated", file(stream, stream.len() - 2, plain)),
        (
            "truncated-long-size-signed",
            file(stream, stream.len() - 2, 0x1000),
        ),
        ("corrupt", file(&corrupt, corrupt.len(), 0x10)),
        // No magic in `output[:zlib_size]`: returned unchanged (`utils.py:254`).
        ("no-magic", file(&filler(0x40), 0x20, 0x30)),
        // `zlib_size` past the body: the slice clamps, the tail is ignored.
        ("zlib-size-past-body", file(&trailing, 0x1000, plain)),
        (
            "prefixed-control",
            file(&prefixed, prefixed.len(), 0x30 + plain),
        ),
        // The directory stops 0x10 bytes into the stream; the rest of it and
        // the signature lie past the entry (`header_file.py:74-75`).
        (
            "grown-signed",
            Placed::header_file(signed(compressed_header_file(stream, stream.len(), plain)))
                .declaring(HEADER_LEN + 0x10),
        ),
        (
            "grown-unsigned",
            file(&prefixed, prefixed.len(), 0x30 + plain).declaring(HEADER_LEN + 0x10),
        ),
    ]
}

/// `-c` cases: the committed `header_encrypted` fixture (signed RSA-2048,
/// 0x10 cipher bytes, `rom_size` 0x210), whole and grown past its directory
/// entry (#99). Only encrypted HeaderFiles: multi-file `-c` of an unencrypted
/// one still writes the raw entry instead of the bare data region (#102).
fn decrypt_cases() -> Vec<(&'static str, Placed)> {
    let encrypted = psptool_fixtures::micro::header_encrypted().to_vec();
    vec![
        ("encrypted", Placed::header_file(encrypted.clone())),
        // The signature lies past the directory entry.
        (
            "grown-signature",
            Placed::header_file(encrypted.clone()).declaring(HEADER_LEN + 0x10),
        ),
        // The directory covers the header only.
        (
            "grown-body",
            Placed::header_file(encrypted).declaring(HEADER_LEN),
        ),
    ]
}

/// The extract flag and its cases.
fn flags() -> [(&'static str, Vec<(&'static str, Placed)>); 2] {
    [("-u", decompress_cases()), ("-c", decrypt_cases())]
}

/// The image of `cases` plus a trailing plain entry (multi-file only: a
/// single-file `-u`/`-c` of it is an error in both tools, `__main__.py:170`).
fn image_of(cases: &[(&str, Placed)]) -> Vec<u8> {
    let mut entries: Vec<Placed> = cases.iter().map(|(_, p)| p.clone()).collect();
    entries.push(Placed::plain(filler(0x40)));
    image(&entries)
}

/// 8 MiB image (the smallest `detect_rom_layout` accepts): FET at 0x20000,
/// one `$PSP` directory (flash-offset addressing) of `entries`, files 4 KiB-
/// aligned from 0x30000.
fn image(entries: &[Placed]) -> Vec<u8> {
    const FET: usize = 0x2_0000;
    const DIR: usize = 0x2_1000;
    let mut rom = vec![0u8; 0x80_0000];
    rom[FET..FET + 4].copy_from_slice(&[0xAA, 0x55, 0xAA, 0x55]);
    rom[FET + 4..FET + 8].copy_from_slice(&(DIR as u32).to_le_bytes());
    rom[FET + 8..FET + 24].fill(0xFF);
    rom[DIR..DIR + 4].copy_from_slice(b"$PSP");
    rom[DIR + 8..DIR + 0xC].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    rom[DIR + 0xC..DIR + 0x10].copy_from_slice(&((1u32 << 31) | (0b01u32 << 24)).to_le_bytes());
    let mut cursor = 0x3_0000;
    for (i, entry) in entries.iter().enumerate() {
        let rec = DIR + 0x10 + i * 0x10;
        rom[rec] = entry.entry_type;
        rom[rec + 4..rec + 8].copy_from_slice(&(entry.size as u32).to_le_bytes());
        rom[rec + 8..rec + 0xC].copy_from_slice(&(cursor as u32).to_le_bytes());
        rom[cursor..cursor + entry.file.len()].copy_from_slice(&entry.file);
        cursor = (cursor + entry.file.len()).next_multiple_of(0x1000);
    }
    rom
}

/// Temp file or directory, removed on drop.
struct Temp(PathBuf);

impl Temp {
    fn new(tag: &str) -> Self {
        Self(std::env::temp_dir().join(format!(
            "psptool_extract_oracle_{}_{tag}",
            std::process::id()
        )))
    }

    fn path(&self) -> &str {
        self.0.to_str().expect("utf-8 temp path")
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Write `rom` to a temp file tagged `tag`.
fn temp_rom(tag: &str, rom: &[u8]) -> Temp {
    let path = Temp::new(tag);
    std::fs::write(&path.0, rom).expect("write synthetic image");
    path
}

fn warned(output: &Output) -> bool {
    String::from_utf8_lossy(&output.stderr).contains(ZLIB_WARNING)
}

#[test]
fn synthetic_rom_matches_reference() {
    let Some(reference) = reference() else { return };
    let mut failures = Vec::new();
    for (flag, cases) in flags() {
        let rom = temp_rom(&format!("single{flag}.bin"), &image_of(&cases));
        for (index, (case, _)) in cases.iter().enumerate() {
            let e = index.to_string();
            let argv = ["-X", "-d", "0", "-e", &e, flag, rom.path()];
            let theirs = run(&reference, &[&["-m", "psptool"], &argv[..]].concat());
            let mine = run(ours(), &argv);
            assert!(
                theirs.status.success(),
                "[{flag} {case}] reference failed: {}",
                String::from_utf8_lossy(&theirs.stderr)
            );
            if !mine.status.success() || mine.stdout != theirs.stdout {
                failures.push(format!(
                    "[{flag} {case}] ours exit={:?} {} bytes, reference {} bytes; stderr: {}",
                    mine.status.code(),
                    mine.stdout.len(),
                    theirs.stdout.len(),
                    String::from_utf8_lossy(&mine.stderr).trim()
                ));
            }
            if warned(&mine) != warned(&theirs) {
                failures.push(format!(
                    "[{flag} {case}] ZLIB warning: ours {}, reference {}",
                    warned(&mine),
                    warned(&theirs)
                ));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Every file under `dir`, by name.
fn files_in(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("listing {}: {e}", dir.display()))
        .map(|f| {
            let f = f.expect("directory entry");
            let name = f.file_name().to_string_lossy().into_owned();
            (name, std::fs::read(f.path()).expect("read extracted file"))
        })
        .collect()
}

#[test]
fn synthetic_rom_multi_file_matches_reference() {
    let Some(reference) = reference() else { return };
    let mut failures = Vec::new();
    for (flag, cases) in flags() {
        let rom = temp_rom(&format!("multi{flag}.bin"), &image_of(&cases));
        let (mine_dir, theirs_dir) = (
            Temp::new(&format!("ours{flag}")),
            Temp::new(&format!("theirs{flag}")),
        );
        let mine = run(ours(), &["-X", flag, "-o", mine_dir.path(), rom.path()]);
        let theirs = run(
            &reference,
            &[
                "-m",
                "psptool",
                "-X",
                flag,
                "-o",
                theirs_dir.path(),
                rom.path(),
            ],
        );
        assert!(
            theirs.status.success(),
            "[{flag}] reference failed: {}",
            String::from_utf8_lossy(&theirs.stderr)
        );
        assert!(
            mine.status.success(),
            "[{flag}] ours failed: {}",
            String::from_utf8_lossy(&mine.stderr)
        );
        let (mine, theirs) = (files_in(&mine_dir.0), files_in(&theirs_dir.0));
        let names: BTreeSet<&String> = mine.keys().chain(theirs.keys()).collect();
        for name in names {
            match (mine.get(name), theirs.get(name)) {
                (Some(a), Some(b)) if a == b => {}
                (a, b) => failures.push(format!(
                    "[{flag}] {name}: ours {:?} bytes, reference {:?} bytes",
                    a.map(Vec::len),
                    b.map(Vec::len)
                )),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

/// Reference side, for every `HeaderFile` (exact type, as the multi-file
/// `-u`/`-c` path tests it, `__main__.py:193-196`) of every directory of every
/// ROM: `path address u sha256(get_signed_bytes())` — the `-u` output
/// (`__main__.py:172`, `:194`) — and, when encrypted, `path address c
/// sha256(to_decrypted_file_bytes())` — the single-file `-c` output
/// (`__main__.py:176`).
const ORACLE: &str = r#"
import hashlib, sys
from psptool import PSPTool
from psptool.header_file import HeaderFile
for path in sys.argv[1:]:
    psp = PSPTool.from_file(path)
    for rom in psp.blob.roms:
        for directory in rom.directories:
            for f in directory.files:
                if type(f) is not HeaderFile:
                    continue
                digest = hashlib.sha256(f.get_signed_bytes()).hexdigest()
                print(path, f.get_address(), 'u', digest)
                if f.encrypted:
                    digest = hashlib.sha256(f.to_decrypted_file_bytes()).hexdigest()
                    print(path, f.get_address(), 'c', digest)
"#;

/// `(path, address, flag)` -> digests (a set: several directories may list
/// one address).
type Digests = BTreeMap<(String, u64, String), BTreeSet<String>>;

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
        let mut fields = line.rsplitn(4, ' ');
        let (Some(digest), Some(flag), Some(address), Some(path)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            panic!("malformed oracle line {line:?}");
        };
        let address = address.parse().expect("oracle address");
        digests
            .entry((path.to_string(), address, flag.to_string()))
            .or_default()
            .insert(digest.to_string());
    }
    digests
}

fn digest(bytes: Result<Vec<u8>, psptool_ops::ExtractError>) -> String {
    match bytes {
        Ok(bytes) => format!("{:x}", Sha256::digest(&bytes)),
        Err(e) => format!("error: {e}"),
    }
}

/// Our `-u` (and, when encrypted, `-c`) bytes for every HeaderFile-class entry
/// whose header `rom_size` exceeds its directory size (`grown`) or does not
/// (`!grown`). Upstream reads a grown HeaderFile on into the image
/// (`header_file.py:72-75`).
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
                    if (h.rom_size as usize > entry.body.len()) != grown {
                        continue;
                    }
                    let mut record = |flag: &str, value: String| {
                        let key = (
                            path.display().to_string(),
                            entry.body.offset().get(),
                            flag.to_string(),
                        );
                        digests.entry(key).or_default().insert(value);
                    };
                    record("u", digest(extract_decompressed(entry, &blob)));
                    if h.is_encrypted {
                        record("c", digest(extract_decrypted(entry, &blob, Ikek::ZenPlus)));
                    }
                }
            }
        }
    }
    digests
}

/// Compare our `-u`/`-c` bytes with the reference's for every HeaderFile
/// address both tools list (`grown` as in [`our_digests`]). Skips when the
/// reference or the corpus is absent.
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

    let mut compared = BTreeMap::<&str, usize>::new();
    let mut mismatches = Vec::new();
    for (key, got) in &ours {
        let Some(expected) = theirs.get(key) else {
            continue;
        };
        *compared.entry(key.2.as_str()).or_default() += 1;
        if got != expected {
            mismatches.push(format!(
                "{} @{:#x} {}: ours {got:?}, reference {expected:?}",
                key.0, key.1, key.2
            ));
        }
    }
    eprintln!(
        "compared {compared:?} of {} HeaderFile extracts ({} reference)",
        ours.len(),
        theirs.len()
    );
    assert!(!compared.is_empty(), "no HeaderFile address in common");
    assert!(
        mismatches.is_empty(),
        "{} of {} differ:\n{}",
        mismatches.len(),
        compared.values().sum::<usize>(),
        mismatches.join("\n")
    );
}

#[test]
fn corpus_get_signed_bytes_matches_reference() {
    compare_corpus(false);
}

#[test]
fn corpus_grown_headerfile_window_matches_reference() {
    compare_corpus(true);
}
