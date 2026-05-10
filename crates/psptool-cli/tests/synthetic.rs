//! End-to-end snapshot tests for each subcommand on synthetic blobs.
//!
//! Each test builds a small ROM in a temp dir, invokes the binary via
//! `cargo run`, and asserts the output text against a committed insta
//! snapshot. The snapshots intentionally exclude noisy bits (timestamps,
//! random RSA outputs) — every byte the test pins down is deterministic.

use std::path::PathBuf;
use std::process::Command;

fn target_binary() -> PathBuf {
    // Cargo sets `CARGO_BIN_EXE_<name>` for integration tests of the crate
    // that owns the binary — the canonical, no-flake way to find it.
    PathBuf::from(env!("CARGO_BIN_EXE_psptool"))
}

fn run(args: &[&str]) -> (String, String, i32) {
    let out = Command::new(target_binary())
        .args(args)
        .output()
        .expect("running psptool");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

/// RAII handle to a synthetic ROM written to a temp file. Drops cleanly so
/// 8 MiB scratch files don't accumulate across runs.
struct RomFile(PathBuf);

impl RomFile {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for RomFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Build a minimal one-FET-one-directory-one-pubkey-one-signed-entry ROM and
/// write it to a temp file. `tag` makes the path unique so parallel tests
/// don't race on the same file.
fn write_synthetic_rom(tag: &str) -> RomFile {
    let bytes = build_synthetic_rom();
    let mut path = std::env::temp_dir();
    path.push(format!(
        "psptool_cli_test_rom_{}_{}.bin",
        std::process::id(),
        tag
    ));
    std::fs::write(&path, &bytes).expect("write synthetic ROM");
    RomFile(path)
}

/// Tiny in-memory ROM the snapshot tests parse. Layout matches the
/// `tests_support::build_synthetic_rom_with_signed_entry` helper inside
/// `psptool-ops` (a single FET → `$PSP` directory → pubkey + HeaderFile),
/// reproduced inline so the test doesn't depend on the ops crate's
/// `cfg(test)`-only helpers.
fn build_synthetic_rom() -> Vec<u8> {
    use rsa::pss::SigningKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use sha2::Sha256;

    use rand::SeedableRng;
    use rand::rngs::StdRng;

    const HEADER_FILE_LEN: usize = 0x100;

    let mut rng = StdRng::seed_from_u64(0xCAFE_F00D_DEAD_BEEF);
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("test RSA key");
    let pub_key: RsaPublicKey = priv_key.to_public_key();

    // PubkeyFile body
    let mut pk_bytes = vec![0u8; 0x40 + 256 + 256];
    pk_bytes[0x00..0x04].copy_from_slice(&1u32.to_le_bytes());
    pk_bytes[0x04..0x14].copy_from_slice(&[0xA1u8; 16]); // key_id
    pk_bytes[0x14..0x24].copy_from_slice(&[0xA1u8; 16]); // certifying_id
    pk_bytes[0x38..0x3C].copy_from_slice(&2048u32.to_le_bytes());
    pk_bytes[0x3C..0x40].copy_from_slice(&2048u32.to_le_bytes());
    let mut e_le = pub_key.e().to_bytes_le();
    e_le.resize(256, 0);
    pk_bytes[0x40..0x40 + 256].copy_from_slice(&e_le);
    let mut n_le = pub_key.n().to_bytes_le();
    n_le.resize(256, 0);
    pk_bytes[0x140..0x140 + 256].copy_from_slice(&n_le);

    let payload = b"hello-cli";
    let payload_padded_len = payload.len().div_ceil(16) * 16;
    let mut payload_padded = vec![0u8; payload_padded_len];
    payload_padded[..payload.len()].copy_from_slice(payload);

    // 8 MiB ROM with FET at offset 0x20000 — the smallest layout
    // `detect_rom_layout` accepts (`KNOWN_FET_OFFSETS[0]` paired with
    // `RomSize::MIB_8`).
    let fet_off = 0x0002_0000usize;
    let dir_off = fet_off + 0x40;
    let pubkey_off = fet_off + 0x80;
    let pubkey_len = pk_bytes.len();
    let header_body_off = fet_off + 0x300;
    let header_total_len = HEADER_FILE_LEN + payload_padded.len() + 0x100;
    let rom_len = 8 * 1024 * 1024;
    let mut rom = vec![0u8; rom_len];

    // 4-byte zero pad + FET magic (so `scan_fet_candidates` finds it).
    rom[fet_off - 4..fet_off].copy_from_slice(&0u32.to_le_bytes());
    rom[fet_off..fet_off + 4].copy_from_slice(b"\xAA\x55\xAA\x55");
    // Pointer slot 0 → directory at `dir_off`, then 16-byte 0xFF terminator.
    rom[fet_off + 4..fet_off + 8].copy_from_slice(&(dir_off as u32).to_le_bytes());
    rom[fet_off + 8..fet_off + 24].copy_from_slice(&[0xFFu8; 16]);

    rom[dir_off..dir_off + 4].copy_from_slice(b"$PSP");
    rom[dir_off + 4..dir_off + 8].copy_from_slice(&0u32.to_le_bytes());
    rom[dir_off + 8..dir_off + 0xC].copy_from_slice(&2u32.to_le_bytes());
    // additional_info: v1 (bit 31), addr_mode = 01 (FlashOffset).
    let additional_info: u32 = (1u32 << 31) | (0b01u32 << 24);
    rom[dir_off + 0xC..dir_off + 0x10].copy_from_slice(&additional_info.to_le_bytes());

    let entry0 = dir_off + 0x10;
    rom[entry0] = 0x00;
    rom[entry0 + 4..entry0 + 8].copy_from_slice(&(pubkey_len as u32).to_le_bytes());
    rom[entry0 + 8..entry0 + 0xC].copy_from_slice(&(pubkey_off as u32).to_le_bytes());

    let entry1 = dir_off + 0x20;
    rom[entry1] = 0x01;
    rom[entry1 + 4..entry1 + 8].copy_from_slice(&(header_total_len as u32).to_le_bytes());
    rom[entry1 + 8..entry1 + 0xC].copy_from_slice(&(header_body_off as u32).to_le_bytes());

    rom[pubkey_off..pubkey_off + pubkey_len].copy_from_slice(&pk_bytes);

    let h_off = header_body_off;
    rom[h_off + 0x10..h_off + 0x14].copy_from_slice(b"$PS1");
    let size_signed = (HEADER_FILE_LEN + payload_padded.len()) as u32;
    rom[h_off + 0x14..h_off + 0x18].copy_from_slice(&size_signed.to_le_bytes());
    rom[h_off + 0x30..h_off + 0x34].copy_from_slice(&1u32.to_le_bytes());
    rom[h_off + 0x34..h_off + 0x38].copy_from_slice(&0u32.to_le_bytes());
    rom[h_off + 0x38..h_off + 0x48].copy_from_slice(&[0xA1u8; 16]);
    rom[h_off + 0x6C..h_off + 0x70].copy_from_slice(&(header_total_len as u32).to_le_bytes());

    let payload_start = h_off + HEADER_FILE_LEN;
    rom[payload_start..payload_start + payload_padded.len()].copy_from_slice(&payload_padded);

    let mut signed = Vec::with_capacity(HEADER_FILE_LEN + payload_padded.len());
    signed.extend_from_slice(&rom[h_off..h_off + HEADER_FILE_LEN]);
    signed.extend_from_slice(&payload_padded);

    let mut sig_rng = StdRng::seed_from_u64(0xDEADC0DE);
    let signing_key = SigningKey::<Sha256>::new(priv_key.clone());
    let sig = signing_key.sign_with_rng(&mut sig_rng, &signed);
    let sig_be = sig.to_bytes();
    let mut sig_disk = sig_be.to_vec();
    sig_disk.reverse();
    let sig_region_off = h_off + HEADER_FILE_LEN + payload_padded.len();
    rom[sig_region_off..sig_region_off + 0x100].copy_from_slice(&sig_disk);

    rom
}

#[test]
fn list_default_on_synthetic_rom() {
    let rom = write_synthetic_rom("list_default");
    let (stdout, stderr, code) = run(&["list", rom.path().to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    insta::assert_snapshot!("list_default_synthetic", stdout);
}

#[test]
fn list_verbose_on_synthetic_rom() {
    let rom = write_synthetic_rom("list_verbose");
    let (stdout, stderr, code) = run(&["list", "-v", rom.path().to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    // Verbose output includes MD5 — pin the column structure, not the bytes.
    // The MD5 of the synthetic ROM's pubkey/header bodies is stable because
    // the rng seed is fixed.
    insta::assert_snapshot!("list_verbose_synthetic", stdout);
}

#[test]
fn list_json_on_synthetic_rom() {
    let rom = write_synthetic_rom("list_json");
    let (stdout, stderr, code) = run(&["list", "--json", rom.path().to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    insta::assert_json_snapshot!("list_json_synthetic", value);
}

#[test]
fn search_keys_on_synthetic_rom() {
    let rom = write_synthetic_rom("search_keys");
    let (stdout, stderr, code) = run(&["search-keys", rom.path().to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    insta::assert_snapshot!("search_keys_synthetic", stdout);
}

#[test]
fn verify_on_synthetic_rom() {
    let rom = write_synthetic_rom("verify");
    let (stdout, stderr, code) = run(&["verify", rom.path().to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    insta::assert_snapshot!("verify_synthetic", stdout);
}

#[test]
fn extract_raw_to_outfile_on_synthetic_rom() {
    let rom = write_synthetic_rom("extract");
    let mut outfile = std::env::temp_dir();
    outfile.push(format!(
        "psptool_cli_test_extract_{}.bin",
        std::process::id()
    ));
    let (_, stderr, code) = run(&[
        "extract",
        "-d",
        "0",
        "-e",
        "1",
        "-o",
        outfile.to_str().unwrap(),
        rom.path().to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let bytes = std::fs::read(&outfile).expect("read extracted file");
    // Should be the HeaderFile body — 0x100 header + 0x10 payload + 0x100 sig.
    assert_eq!(bytes.len(), 0x100 + 0x10 + 0x100);
    // First 4 bytes of the header (after the leading nonce zeros at +0x00) is
    // the magic at +0x10.
    assert_eq!(&bytes[0x10..0x14], b"$PS1");
    let _ = std::fs::remove_file(&outfile);
}
