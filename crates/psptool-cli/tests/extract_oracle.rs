//! `-X`, `-X -u` / `-X -c` differential vs the reference Python PSPTool (#91,
//! #99, #100, #101).
//!
//! Single-file `-X -d D -e E -u` is `file.get_signed_bytes()` and `-c` is
//! `file.to_decrypted_file_bytes()` in both tools (`__main__.py:169-176`) —
//! for a `KeyStoreFile`, its own `get_signed_bytes()` (`key_store_file.py:
//! 50-51`); multi-file `-X -u` / `-c` writes `get_signed_bytes()` /
//! `get_decrypted_body()` only when `type(file) is HeaderFile`, and
//! `get_bytes()` for every other file, `KeyStoreFile` included
//! (`__main__.py:191-213`). Plain `-X` is `get_bytes()` throughout
//! (`__main__.py:180`, `:200`) — for a HeaderFile-class file its buffer
//! re-sized to `rom_size` (`header_file.py:104-105`), and `-T` compares those
//! (`__main__.py:52-56`, [`synthetic_type_regex_compares_the_rom_size_buffers`]).
//! The same argv must produce the same bytes.
//!
//! Shapes the corpus barely reaches get a synthetic image with one entry per
//! edge case, run through both binaries in single-file
//! ([`synthetic_rom_matches_reference`]) and multi-file
//! ([`synthetic_rom_multi_file_matches_reference`]) mode: the zlib step behind
//! `-u` — `_decrypted_decompressed_body` (`header_file.py:172-189`) over
//! `utils.zlib_decompress` (`utils.py:218-254`) — HeaderFiles whose header
//! `rom_size` outgrows their directory entry, which upstream reads on into the
//! image (`header_file.py:72-75`), and `KeyStoreFile`s (plain, compressed,
//! encrypted), and for raw `-X` HeaderFiles whose directory entry declares
//! more or less than `rom_size` (#101).
//! [`corpus_get_signed_bytes_matches_reference`] compares the raw, `-u` and
//! `-c` bytes of every corpus HeaderFile against the reference's
//! `get_bytes()` / `get_signed_bytes()` / `to_decrypted_file_bytes()`;
//! [`corpus_grown_headerfile_window_matches_reference`] does the same for the
//! ones whose `rom_size` outgrows their directory entry (#99, #101);
//! [`corpus_multi_file_key_store_matches_reference`] compares both CLIs'
//! multi-file `-u` key-store files (#100).
//!
//! Gating mirrors `differential.rs`: every test skips (with a note on stderr)
//! when `PSPTOOL_REFERENCE` is unset, the corpus tests also when
//! `PSPTOOL_TEST_CORPUS` is. The nix dev shell sets both.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use psptool_core::body::decrypt;
use psptool_core::{
    Directory, Entry, EntryClass, Ikek, SourceBytes, detect_rom_layout, scan_fet_candidates,
    walk_directories,
};
use psptool_ops::{extract_decompressed, extract_decrypted, extract_raw};
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

    /// A `BL_PUBLIC_KEY` entry — a `KeyStoreFile` (`file.py:244`, `:262-263`).
    fn key_store(file: Vec<u8>) -> Self {
        Self {
            entry_type: 0x50,
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

/// `KeyStoreFile` signature length: `KeyStoreFileHeader` asserts the
/// `(1, 2)` constants at 0x30/0x34 (`key_store_file.py:84-86`), i.e. signed
/// with `signature_type` 2, RSA-4096 (`header_file.py:86-87`).
const KEY_STORE_SIG_LEN: usize = 0x200;

/// A `$KDB` key store (`key_store_file.py:140-231`): the 0x50-byte store
/// header, then one RSA-2048 key — a 0x50-byte key header and a 0x100-byte
/// modulus. No byte is `0x78`, so no zlib magic hides in it.
fn kdb() -> Vec<u8> {
    let key_len = 0x50 + 0x100;
    let mut store = vec![0u8; 0x50 + key_len];
    let total = store.len() as u32;
    store[0x00..0x04].copy_from_slice(&total.to_le_bytes()); // `:151`
    store[0x04..0x08].copy_from_slice(&1u32.to_le_bytes()); // `:154`
    store[0x08..0x0C].copy_from_slice(b"$KDB"); // `:157`
    let k = 0x50;
    store[k..k + 4].copy_from_slice(&(key_len as u32).to_le_bytes()); // `:209`
    store[k + 0x04..k + 0x08].copy_from_slice(&1u32.to_le_bytes()); // `:212`
    store[k + 0x0C..k + 0x10].copy_from_slice(&0x10001u32.to_le_bytes()); // `:218`
    store[k + 0x10..k + 0x20].fill(0x4B); // key id, `:220`
    store[k + 0x20..k + 0x24].copy_from_slice(&2048u32.to_le_bytes()); // `:223`
    store[k + 0x50..].copy_from_slice(&filler(0x100));
    store
}

/// A `KeyStoreFile` around `body` (the store, or a zlib stream of it): the
/// header fields `KeyStoreFileHeader` reads (`key_store_file.py:71-89`) —
/// `body_size` (0x14), the `(1, 2)` constants, packed size (0x6c, also
/// `rom_size`), key-store type 0x50 (0x7c) — then a 0x200-byte signature at
/// `0x100 + body_size` (`signature_size = packed - 0x100 - body_size`,
/// `:126-130`).
fn key_store_file(body: &[u8]) -> Vec<u8> {
    let mut h = [0u8; HEADER_LEN];
    h[0x10..0x14].copy_from_slice(b"$PS1");
    h[0x14..0x18].copy_from_slice(&(body.len() as u32).to_le_bytes());
    h[0x30..0x34].copy_from_slice(&1u32.to_le_bytes());
    h[0x34..0x38].copy_from_slice(&2u32.to_le_bytes());
    let packed = (HEADER_LEN + body.len() + KEY_STORE_SIG_LEN) as u32;
    h[0x6C..0x70].copy_from_slice(&packed.to_le_bytes());
    h[0x7C..0x80].copy_from_slice(&0x50u32.to_le_bytes());
    let mut file = h.to_vec();
    file.extend_from_slice(body);
    file.extend(std::iter::repeat_n(0xCC, KEY_STORE_SIG_LEN));
    file
}

/// One stored (uncompressed) deflate block in a zlib wrapper — RFC 1950/1951,
/// magic `78 01` (`utils.py:213`).
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let len = u16::try_from(data.len()).expect("stored block <= 0xFFFF");
    let mut s = vec![0x78, 0x01, 0x01];
    s.extend_from_slice(&len.to_le_bytes());
    s.extend_from_slice(&(!len).to_le_bytes());
    s.extend_from_slice(data);
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + u32::from(x)) % 65521;
        b = (b + a) % 65521;
    }
    s.extend_from_slice(&((b << 16) | a).to_be_bytes());
    s
}

/// Wrapped entry key of the encrypted key store (non-zero, as
/// `header_file.py:102` asserts).
const WRAPPED_KEY: [u8; 16] = [0x3C; 16];

/// AES-128-CBC encryption of the block-aligned `plain` under the key the Zen+
/// IKEK unwraps from [`WRAPPED_KEY`]: `(iv, ciphertext)`. This crate has no
/// AES dependency, so it is solved from `body::decrypt` alone: CBC decryption
/// is `P[i] = D(C[i]) ^ C[i-1]` with `C[-1] = IV`, so fixing the last cipher
/// block and solving backwards, `C[i-1] = D(C[i]) ^ P[i]`, yields a ciphertext
/// that decrypts to `plain`. The reference parsing the result as a
/// `KeyStoreFile` checks the construction.
fn cbc_encrypt(plain: &[u8]) -> ([u8; 16], Vec<u8>) {
    let mut cipher = vec![0u8; plain.len()];
    let mut block = [0xA7u8; 16];
    for (i, p) in plain.chunks_exact(16).enumerate().rev() {
        cipher[i * 16..i * 16 + 16].copy_from_slice(&block);
        // One block under a zero IV decrypts to `D(C[i])`.
        let d = decrypt(&block, &WRAPPED_KEY, Ikek::ZenPlus, &[0; 16]).expect("one AES block");
        for (b, (d, p)) in block.iter_mut().zip(d.iter().zip(p)) {
            *b = d ^ p;
        }
    }
    (block, cipher)
}

/// A compressed `KeyStoreFile` (`key_store_file.py:39-40`) whose zlib stream
/// inflates to the [`kdb`] store followed by 0x20 more bytes: upstream's
/// `get_signed_bytes()` is `header ++ key_store` (`:50-51`), the store cut to
/// `size_uncompressed` — not the HeaderFile envelope, which keeps the tail.
/// Encrypted under [`WRAPPED_KEY`] when `encrypted` (decrypted, then inflated,
/// `header_file.py:177-181`).
fn compressed_key_store_file(encrypted: bool) -> Vec<u8> {
    let store = kdb();
    let mut inflated = store.clone();
    inflated.extend_from_slice(&filler(0x20));
    let stream = zlib_stored(&inflated);
    let mut body = stream.clone();
    body.resize(stream.len().next_multiple_of(16), 0);
    let mut file = key_store_file(&body);
    file[0x48..0x4C].copy_from_slice(&1u32.to_le_bytes());
    file[0x50..0x54].copy_from_slice(&(store.len() as u32).to_le_bytes());
    file[0x54..0x58].copy_from_slice(&(stream.len() as u32).to_le_bytes());
    if encrypted {
        let (iv, cipher) = cbc_encrypt(&body);
        file[0x18..0x1C].copy_from_slice(&1u32.to_le_bytes());
        file[0x20..0x30].copy_from_slice(&iv);
        file[0x80..0x90].copy_from_slice(&WRAPPED_KEY);
        file[HEADER_LEN..HEADER_LEN + cipher.len()].copy_from_slice(&cipher);
    }
    file
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
        // `KeyStoreFile.get_signed_bytes()` (#100).
        (
            "key-store-compressed",
            Placed::key_store(compressed_key_store_file(false)),
        ),
        (
            "key-store-encrypted",
            Placed::key_store(compressed_key_store_file(true)),
        ),
    ]
}

/// `-c` cases: the committed `header_encrypted` fixture (signed RSA-2048,
/// 0x10 cipher bytes, `rom_size` 0x210), whole and grown past its directory
/// entry (#99). Unencrypted HeaderFiles are in `image_of`'s trailing entries
/// (single-file `-c` rejects them, #102).
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
        // `to_decrypted_file_bytes()` of a `KeyStoreFile` (#100).
        (
            "key-store-encrypted",
            Placed::key_store(compressed_key_store_file(true)),
        ),
    ]
}

/// The committed `header_signed` fixture (signed RSA-2048, `rom_size` 0x210).
fn signed_fixture() -> Vec<u8> {
    psptool_fixtures::micro::header_signed().to_vec()
}

/// Raw `-X` cases (no transform flag): `file.get_bytes()` (`__main__.py:180`,
/// `:200`), which for a HeaderFile-class file is its buffer — grown to the
/// header (`header_file.py:32-33`), then re-sized to `rom_size` (`:72-75`,
/// `:104-105`) — not the directory-declared entry (#101).
fn raw_cases() -> Vec<(&'static str, Placed)> {
    let file = signed_fixture();
    // An unsigned header with `rom_size == 0` on a record shorter than the
    // header: the buffer grows to 0x100 and `rom_size` becomes 0x100.
    let mut short = file[..HEADER_LEN].to_vec();
    short[0x30..0x34].fill(0);
    short[0x6C..0x70].fill(0);
    short.extend_from_slice(&filler(0x40));
    vec![
        ("whole", Placed::header_file(file.clone())),
        (
            "grown",
            Placed::header_file(file.clone()).declaring(HEADER_LEN + 0x10),
        ),
        (
            "shrunk",
            Placed::header_file(file.clone()).declaring(file.len() + 0x30),
        ),
        ("zero-size", Placed::header_file(file).declaring(0)),
        ("rom-size-zero", Placed::header_file(short).declaring(0x80)),
        (
            "key-store-grown",
            Placed::key_store(key_store_file(&kdb())).declaring(HEADER_LEN + 0x10),
        ),
    ]
}

/// The extract flag and its cases; `""` is the raw `-X`.
fn flags() -> [(&'static str, Vec<(&'static str, Placed)>); 3] {
    [
        ("-u", decompress_cases()),
        ("-c", decrypt_cases()),
        ("", raw_cases()),
    ]
}

/// `args` without the empty raw-`-X` flag.
fn argv<'a>(args: &[&'a str]) -> Vec<&'a str> {
    args.iter().copied().filter(|a| !a.is_empty()).collect()
}

/// The image of `cases` plus trailing entries a single-file `-u`/`-c` rejects
/// in both tools (`__main__.py:170`, `:174`), so only multi-file reaches them:
/// a plain file, an uncompressed, unencrypted `KeyStoreFile` — the corpus'
/// shape (#100) — and an uncompressed, unencrypted `HeaderFile`, unsigned and
/// signed, whose multi-file `-c` is the bare data region (`header_file.py:286-288`,
/// #102).
fn image_of(cases: &[(&str, Placed)]) -> Vec<u8> {
    let mut entries: Vec<Placed> = cases.iter().map(|(_, p)| p.clone()).collect();
    entries.push(Placed::plain(filler(0x40)));
    entries.push(Placed::key_store(key_store_file(&kdb())));
    let mut plain_header = compressed_header_file(&filler(0x40), 0x40, 0x40);
    plain_header[0x48..0x4C].fill(0);
    entries.push(Placed::header_file(plain_header.clone()));
    entries.push(Placed::header_file(signed(plain_header)));
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
            let args = argv(&["-X", "-d", "0", "-e", &e, flag, rom.path()]);
            let theirs = run(&reference, &[&["-m", "psptool"], &args[..]].concat());
            let mine = run(ours(), &args);
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
        let mine = run(
            ours(),
            &argv(&["-X", flag, "-o", mine_dir.path(), rom.path()]),
        );
        let theirs = run(
            &reference,
            &argv(&[
                "-m",
                "psptool",
                "-X",
                flag,
                "-o",
                theirs_dir.path(),
                rom.path(),
            ]),
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

/// `-T` extracts the first match when every match has the same
/// `get_bytes()` (`__main__.py:49-56`, `:155-157`): four `PSP_FW_BOOT_LOADER`
/// records of one file, declaring its `rom_size`, less, more and nothing,
/// hold the same `rom_size` buffer, so both tools warn and extract the first
/// (#101).
#[test]
fn synthetic_type_regex_compares_the_rom_size_buffers() {
    let Some(reference) = reference() else { return };
    let file = signed_fixture();
    let rom = temp_rom(
        "type_regex.bin",
        &image(&[
            Placed::header_file(file.clone()),
            Placed::header_file(file.clone()).declaring(HEADER_LEN + 0x10),
            Placed::header_file(file.clone()).declaring(file.len() + 0x30),
            Placed::header_file(file.clone()).declaring(0),
        ]),
    );
    let args = ["-X", "-T", "PSP_FW_BOOT_LOADER", rom.path()];
    // Without `-e`, upstream also runs the multi-file extraction into
    // `./{filename}_extracted` (`__main__.py:183-190`): keep it in a scratch
    // working directory.
    let cwd = Temp::new("type_regex_cwd");
    std::fs::create_dir_all(&cwd.0).expect("scratch working directory");
    let theirs = Command::new(&reference)
        .current_dir(&cwd.0)
        .args(["-m", "psptool"])
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawning {}: {e}", reference.display()));
    let mine = run(ours(), &args);
    assert!(
        theirs.status.success() && theirs.stdout == file,
        "reference: {}",
        String::from_utf8_lossy(&theirs.stderr)
    );
    assert!(
        mine.status.success() && mine.stdout == theirs.stdout,
        "ours exit={:?} {} bytes, reference {} bytes; stderr: {}",
        mine.status.code(),
        mine.stdout.len(),
        theirs.stdout.len(),
        String::from_utf8_lossy(&mine.stderr).trim()
    );
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

/// Corpus ROMs whose ROM 0 — what multi-file extract walks by default
/// (`__main__.py:187`) — holds a `KeyStoreFile`, per the reference.
const KEY_STORE_ROMS: &str = r#"
import sys
from psptool import PSPTool
from psptool.key_store_file import KeyStoreFile
for path in sys.argv[1:]:
    rom = PSPTool.from_file(path).blob.roms[0]
    if any(type(f) is KeyStoreFile for d in rom.directories for f in d.files):
        print(path)
"#;

/// Multi-file `-u` writes a `KeyStoreFile`'s `get_bytes()`, not an envelope:
/// it applies `get_signed_bytes()` only when `type(file) is HeaderFile`
/// (`__main__.py:193`, #100). Runs both CLIs on every corpus ROM holding one
/// and compares the key-store files (`BL_PUBLIC_KEY~0x50`,
/// `TOS_PUBLIC_KEY~0x51`, `file.py:244`) by name without the `dNN_` prefix —
/// the directory index differs (#104) — and content.
#[test]
fn corpus_multi_file_key_store_matches_reference() {
    let Some(reference) = reference() else { return };
    let roms = psptool_fixtures::corpus_rom_paths();
    if roms.is_empty() {
        eprintln!("PSPTOOL_TEST_CORPUS unset or empty — skipping the corpus differential");
        return;
    }
    let listed = Command::new(&reference)
        .arg("-c")
        .arg(KEY_STORE_ROMS)
        .args(&roms)
        .output()
        .unwrap_or_else(|e| panic!("spawning {}: {e}", reference.display()));
    assert!(
        listed.status.success(),
        "reference oracle failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let with_key_store: Vec<String> = String::from_utf8_lossy(&listed.stdout)
        .lines()
        .map(str::to_string)
        .collect();
    assert!(
        !with_key_store.is_empty(),
        "no corpus ROM holds a KeyStoreFile"
    );

    let key_store_files = |dir: &Path| {
        let mut files = BTreeMap::<(String, String), usize>::new();
        for (name, bytes) in files_in(dir) {
            if !(name.contains("~0x50") || name.contains("~0x51")) {
                continue;
            }
            let name = name.split_once('_').map_or(name.clone(), |(_, n)| n.into());
            *files
                .entry((name, format!("{:x}", Sha256::digest(&bytes))))
                .or_default() += 1;
        }
        files
    };
    let mut failures = Vec::new();
    let mut compared = 0;
    for (i, rom) in with_key_store.iter().enumerate() {
        let (mine_dir, theirs_dir) = (
            Temp::new(&format!("key_store_ours_{i}")),
            Temp::new(&format!("key_store_theirs_{i}")),
        );
        let mine = run(ours(), &["-X", "-u", "-o", mine_dir.path(), rom]);
        let theirs = run(
            &reference,
            &["-m", "psptool", "-X", "-u", "-o", theirs_dir.path(), rom],
        );
        assert!(theirs.status.success(), "[{rom}] reference failed");
        assert!(mine.status.success(), "[{rom}] ours failed");
        let (mine, theirs) = (key_store_files(&mine_dir.0), key_store_files(&theirs_dir.0));
        compared += theirs.values().sum::<usize>();
        if mine != theirs {
            failures.push(format!(
                "{rom}:\n  ours      {mine:?}\n  reference {theirs:?}"
            ));
        }
    }
    eprintln!(
        "compared {compared} key-store files over {} ROMs",
        with_key_store.len()
    );
    assert!(compared > 0, "the reference extracted no key-store file");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Reference side, for every HeaderFile-class file (`KeyStoreFile` included)
/// of every directory of every ROM: `path address r sha256(get_bytes())` —
/// the raw `-X` output (`__main__.py:180`, `:200`, #101); and for every
/// `HeaderFile` (exact type, as the multi-file `-u`/`-c` path tests it,
/// `__main__.py:193-196`): `path address u sha256(get_signed_bytes())` — the
/// `-u` output (`__main__.py:172`, `:194`) — and, when encrypted, `path
/// address c sha256(to_decrypted_file_bytes())` — the single-file `-c` output
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
                if not isinstance(f, HeaderFile):
                    continue
                digest = hashlib.sha256(f.get_bytes()).hexdigest()
                print(path, f.get_address(), 'r', digest)
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

/// Our raw `-X` bytes for every HeaderFile-class entry, and the `-u` (and,
/// when encrypted, `-c`) bytes of every `HeaderFile`, whose header `rom_size`
/// exceeds its directory size (`grown`) or does not (`!grown`). Upstream reads
/// a grown HeaderFile on into the image (`header_file.py:72-75`) and cuts a
/// shrunk one at `rom_size` (`:104-105`).
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
                    let Some(h) = entry.class.header() else {
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
                    record("r", digest(Ok(extract_raw(entry, &blob))));
                    if !matches!(entry.class, EntryClass::Header(_)) {
                        continue;
                    }
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
