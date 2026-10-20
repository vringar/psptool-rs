//! `sign_entry` vs the reference's re-sign path (#105).
//!
//! Upstream re-signs a file with `SignedEntity.resign_only`
//! (`cert_tree.py:101-117`): it signs `file.get_signed_bytes()` and writes
//! the signature into `self.signature` — for a `HeaderFile` the
//! `signature_len` bytes before `rom_size` of the buffer grown to the header
//! and then to `rom_size` (`header_file.py:32-33`, `:72-75`, `:88`), which
//! reads on past the directory entry into the image.
//!
//! For every corpus HeaderFile whose buffer outgrows its directory entry
//! (13 past a non-zero size, 3 zero-size records), plus one ordinary signed
//! HeaderFile of the same image as a control, we re-sign the image with keys
//! the reference generates and ask the reference's own
//! `SignedEntity.verify_with_pubkey` (`cert_tree.py:97-98`) whether the
//! re-signed file verifies under that key. It does only if we signed
//! upstream's bytes and wrote the signature where upstream reads it.
//!
//! Skips (with a note on stderr) when `PSPTOOL_REFERENCE` or
//! `PSPTOOL_TEST_CORPUS` is unset, like `differential.rs`; the nix dev shell
//! sets both.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use psptool_core::{
    BlobEditor, Directory, Entry, EntryClass, Ikek, SourceBytes, detect_rom_layout,
    scan_fet_candidates, walk_directories,
};
use psptool_ops::sign_entry;
use rsa::RsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;

/// Generate an RSA-2048 and an RSA-4096 key and save them PKCS#8 PEM, as
/// upstream's own key handling does (`crypto.py:286-297`).
const KEYGEN: &str = r#"
import sys
from psptool.crypto import Rsa2048PrivateKey, Rsa4096PrivateKey
Rsa2048PrivateKey.generate_new().save_to_file(sys.argv[1])
Rsa4096PrivateKey.generate_new().save_to_file(sys.argv[2])
"#;

/// `path address outcome` for every signed HeaderFile-class file of the
/// re-signed images: `SignedEntity.verify_with_pubkey` (`cert_tree.py:97-98`)
/// with the generated key matching its signature size.
const VERIFY: &str = r#"
import sys
from psptool import PSPTool
from psptool.crypto import Rsa2048PrivateKey, Rsa4096PrivateKey
from psptool.header_file import HeaderFile
keys = {0x100: Rsa2048PrivateKey.load_from_file(sys.argv[1]).get_public_key(),
        0x200: Rsa4096PrivateKey.load_from_file(sys.argv[2]).get_public_key()}
for path in sys.argv[3:]:
    psp = PSPTool.from_file(path)
    for rom in psp.blob.roms:
        for directory in rom.directories:
            for f in directory.files:
                entity = f.signed_entity if isinstance(f, HeaderFile) else None
                if entity is None:
                    continue
                try:
                    key = keys[entity.signature.buffer_size]
                    outcome = 'verified' if entity.verify_with_pubkey(key) else 'bad-signature'
                except Exception as e:
                    outcome = 'error'
                print(path, f.get_address(), outcome)
"#;

fn reference() -> Option<PathBuf> {
    match std::env::var_os("PSPTOOL_REFERENCE") {
        Some(v) if !v.is_empty() => Some(PathBuf::from(v)),
        _ => {
            eprintln!("PSPTOOL_REFERENCE unset — skipping the reference differential");
            None
        }
    }
}

fn python(reference: &Path, script: &str, args: &[&Path]) -> String {
    let out = Command::new(reference)
        .arg("-c")
        .arg(script)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawning {}: {e}", reference.display()));
    assert!(
        out.status.success(),
        "reference oracle failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A scratch directory removed on drop.
struct Temp(PathBuf);

impl Temp {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("psptool_sign_oracle_{}_{tag}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create scratch directory");
        Self(path)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Every parsed entry of every directory of every ROM of `blob`.
fn entries(blob: &SourceBytes) -> Vec<Entry> {
    let mut out = Vec::new();
    for position in scan_fet_candidates(blob) {
        let Some(layout) = detect_rom_layout(blob, position) else {
            continue;
        };
        for dir in walk_directories(blob, &layout.fet, layout.rom_size, layout.rom_origin) {
            let parsed: Vec<_> = match &dir.directory {
                Directory::Psp(d) => (0..d.entries.len())
                    .map(|i| Entry::parse_psp(blob, d, i, layout.rom_size, layout.rom_origin))
                    .collect(),
                Directory::Bios(d) => (0..d.entries.len())
                    .map(|i| Entry::parse_bios(blob, d, i, layout.rom_size, layout.rom_origin))
                    .collect(),
                Directory::Combo(_) => Vec::new(),
            };
            out.extend(parsed.into_iter().flatten());
        }
    }
    out
}

/// Re-sign, in one image, every signed HeaderFile whose buffer outgrows its
/// directory entry plus the first ordinary one (the control). Returns the
/// re-signed image and the re-signed addresses, `(address, grown)`; `None`
/// when the image holds no grown signed HeaderFile.
fn resign(
    blob: &SourceBytes,
    keys: &BTreeMap<u32, RsaPrivateKey>,
) -> Option<(Vec<u8>, BTreeMap<u64, bool>)> {
    let mut targets = BTreeMap::<u64, (Entry, bool)>::new();
    let mut control = None;
    for entry in entries(blob) {
        let EntryClass::Header(h) = &entry.class else {
            continue;
        };
        if !h.is_signed() || !keys.contains_key(&h.signature_type) {
            continue;
        }
        let Some(window) = entry.header_file_window(blob) else {
            continue;
        };
        let address = entry.body.offset().get();
        if window.len() > entry.body.len() {
            targets.insert(address, (entry, true));
        } else if control.is_none() {
            control = Some((address, entry));
        }
    }
    if targets.is_empty() {
        return None;
    }
    if let Some((address, entry)) = control {
        targets.entry(address).or_insert((entry, false));
    }

    let mut editor = BlobEditor::from_blob(blob.clone());
    let mut resigned = BTreeMap::new();
    for (address, (entry, grown)) in targets {
        let Some(h) = entry.class.header() else {
            continue;
        };
        let key = &keys[&h.signature_type];
        // Upstream decrypts with the Zen+ IKEK (`header_file.py:294-307`).
        if let Err(e) = sign_entry(&mut editor, &entry, key, Some(Ikek::ZenPlus)) {
            panic!("sign_entry @{address:#x}: {e}");
        }
        resigned.insert(address, grown);
    }
    Some((editor.serialize(), resigned))
}

#[test]
fn corpus_resigned_grown_headerfiles_verify_under_reference() {
    let Some(reference) = reference() else { return };
    let roms = psptool_fixtures::corpus_rom_paths();
    if roms.is_empty() {
        eprintln!("PSPTOOL_TEST_CORPUS unset or empty — skipping the corpus differential");
        return;
    }
    let scratch = Temp::new("keys");
    let (key_2048, key_4096) = (scratch.0.join("rsa2048.pem"), scratch.0.join("rsa4096.pem"));
    python(&reference, KEYGEN, &[&key_2048, &key_4096]);
    let load = |path: &Path| {
        let pem = std::fs::read_to_string(path).expect("read generated key");
        RsaPrivateKey::from_pkcs8_pem(&pem).expect("PKCS#8 PEM key")
    };
    // `signature_type` 0 → RSA-2048, 2 → RSA-4096 (`crypto.py:189-196`).
    let keys = BTreeMap::from([(0, load(&key_2048)), (2, load(&key_4096))]);

    let mut images = Vec::new();
    let mut expected = BTreeMap::<(String, u64), bool>::new();
    for (i, rom) in roms.iter().enumerate() {
        let blob = SourceBytes::from_blob(std::fs::read(rom).expect("read corpus ROM"));
        let Some((bytes, resigned)) = resign(&blob, &keys) else {
            continue;
        };
        let image = scratch.0.join(format!("resigned_{i}.bin"));
        std::fs::write(&image, bytes).expect("write re-signed image");
        for (address, grown) in resigned {
            expected.insert((image.display().to_string(), address), grown);
        }
        images.push(image);
    }
    let grown = expected.values().filter(|&&g| g).count();
    assert!(
        grown > 0,
        "no corpus HeaderFile outgrows its directory entry"
    );

    let mut args: Vec<&Path> = vec![&key_2048, &key_4096];
    args.extend(images.iter().map(PathBuf::as_path));
    let mut outcomes = BTreeMap::<(String, u64), BTreeSet<String>>::new();
    for line in python(&reference, VERIFY, &args).lines() {
        let mut fields = line.rsplitn(3, ' ');
        let (Some(outcome), Some(address), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            panic!("malformed oracle line {line:?}");
        };
        outcomes
            .entry((path.to_string(), address.parse().expect("oracle address")))
            .or_default()
            .insert(outcome.to_string());
    }

    let mut failures = Vec::new();
    for (key, grown) in &expected {
        let verdict = outcomes.get(key);
        if verdict != Some(&BTreeSet::from(["verified".to_string()])) {
            let kind = if *grown { "grown" } else { "control" };
            failures.push(format!("{} @{:#x} ({kind}): {verdict:?}", key.0, key.1));
        }
    }
    eprintln!(
        "re-signed {} HeaderFiles ({grown} grown) over {} images",
        expected.len(),
        images.len()
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// CLI coordinates `(rom index, directory index, entry index)` — the `-r` /
/// `-d` / `-e` the `sign` and `-R` commands resolve through
/// `psptool-cli/src/load.rs` — plus address and `signature_type` of the first
/// encrypted signed HeaderFile of `blob`.
fn first_encrypted_signed(blob: &SourceBytes) -> Option<(usize, usize, usize, u64, u32)> {
    let layouts = scan_fet_candidates(blob)
        .into_iter()
        .filter_map(|p| detect_rom_layout(blob, p));
    for (r, layout) in layouts.enumerate() {
        let dirs = walk_directories(blob, &layout.fet, layout.rom_size, layout.rom_origin);
        for (d, dir) in dirs.iter().enumerate() {
            let parsed: Vec<_> = match &dir.directory {
                Directory::Psp(p) => (0..p.entries.len())
                    .map(|i| Entry::parse_psp(blob, p, i, layout.rom_size, layout.rom_origin))
                    .collect(),
                Directory::Bios(b) => (0..b.entries.len())
                    .map(|i| Entry::parse_bios(blob, b, i, layout.rom_size, layout.rom_origin))
                    .collect(),
                Directory::Combo(_) => Vec::new(),
            };
            for (e, entry) in parsed.into_iter().enumerate() {
                if let Ok(entry) = entry
                    && let EntryClass::Header(h) = &entry.class
                    && h.is_signed()
                    && h.is_encrypted
                    && matches!(h.signature_type, 0 | 2)
                {
                    return Some((r, d, e, entry.body.offset().get(), h.signature_type));
                }
            }
        }
    }
    None
}

/// #108: `psptool sign` and `psptool -R -p` (`cmds/sign.rs`, `cmds/replace.rs`)
/// re-sign an encrypted HeaderFile. The signed bytes are `header ||
/// get_decrypted_decompressed_body()[..size_signed]` (`header_file.py:168-170`),
/// which upstream decrypts with `get_unwrapped_ikek()` — the Zen+ IKEK,
/// unconditionally (`header_file.py:286-307`); both CLI callers passed no
/// IKEK, so `sign_entry` failed `NotEncrypted` on all 256 encrypted signed
/// corpus HeaderFiles. The reference's own `verify_with_pubkey`
/// (`cert_tree.py:97-98`) must accept the CLI's output.
#[test]
fn cli_resigns_an_encrypted_headerfile_under_reference() {
    let Some(reference) = reference() else { return };
    let roms = psptool_fixtures::corpus_rom_paths();
    if roms.is_empty() {
        eprintln!("PSPTOOL_TEST_CORPUS unset or empty — skipping the corpus differential");
        return;
    }
    let (rom, (r, d, e, address, signature_type)) = roms
        .iter()
        .find_map(|rom| {
            let blob = SourceBytes::from_blob(std::fs::read(rom).expect("read corpus ROM"));
            first_encrypted_signed(&blob).map(|target| (rom, target))
        })
        .expect("the corpus holds an encrypted signed HeaderFile");

    let scratch = Temp::new("cli");
    let (key_2048, key_4096) = (scratch.0.join("rsa2048.pem"), scratch.0.join("rsa4096.pem"));
    python(&reference, KEYGEN, &[&key_2048, &key_4096]);
    // `signature_type` 0 → RSA-2048, 2 → RSA-4096 (`crypto.py:189-196`).
    let key = if signature_type == 0 {
        &key_2048
    } else {
        &key_4096
    };

    let (r, d, e) = (r.to_string(), d.to_string(), e.to_string());
    let signed = scratch.0.join("signed.bin");
    let replaced = scratch.0.join("replaced.bin");
    let runs: [(&Path, Vec<&std::ffi::OsStr>); 2] = [
        (
            &signed,
            [
                "sign",
                "-r",
                r.as_str(),
                "-d",
                d.as_str(),
                "-e",
                e.as_str(),
                "-o",
            ]
            .map(std::ffi::OsStr::new)
            .into_iter()
            .chain([signed.as_os_str(), "-p".as_ref(), key.as_os_str()])
            .chain([rom.as_os_str()])
            .collect(),
        ),
        (
            &replaced,
            [rom.as_os_str()]
                .into_iter()
                .chain(
                    [
                        "-R",
                        "-r",
                        r.as_str(),
                        "-d",
                        d.as_str(),
                        "-e",
                        e.as_str(),
                        "-o",
                    ]
                    .map(std::ffi::OsStr::new),
                )
                .chain([replaced.as_os_str(), "-p".as_ref(), key.as_os_str()])
                .collect(),
        ),
    ];
    for (outfile, args) in &runs {
        let out = Command::new(env!("CARGO_BIN_EXE_psptool"))
            .args(args)
            .output()
            .expect("spawn psptool");
        assert!(
            out.status.success(),
            "divergence #108: `psptool {}` failed on the encrypted HeaderFile @{address:#x} \
             of {}: {}",
            args.iter()
                .map(|a| a.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" "),
            rom.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        assert!(outfile.exists(), "no output written");
    }

    let verdicts = python(
        &reference,
        VERIFY,
        &[&key_2048, &key_4096, &signed, &replaced],
    );
    for outfile in [&signed, &replaced] {
        let line = format!("{} {address} verified", outfile.display());
        assert!(
            verdicts.lines().any(|l| l == line),
            "divergence #108: the reference does not verify the re-signed encrypted \
             HeaderFile @{address:#x} in {}:\n{verdicts}",
            outfile.display()
        );
    }
}
