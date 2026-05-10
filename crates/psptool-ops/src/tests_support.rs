//! Test-only helpers for sign/verify integration tests.
//!
//! Builds in-memory synthetic ROMs that exercise the full chain-of-trust
//! path (FET → `$PSP` directory → entries) without depending on the
//! private corpus. Returned tuples include the byte offsets the caller
//! needs to introspect or mutate (e.g. signature region, body region) so
//! tests can flip individual bytes without re-deriving the layout.

#![cfg(test)]

use rand::SeedableRng;
use rand::rngs::StdRng;
use rsa::pss::SigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

use psptool_core::entry::HEADER_FILE_LEN;

/// On-disk PubkeyFile-shape blob suitable for placement as a `type 0x00`
/// entry body. RSA-2048, no embedded signature.
pub struct SyntheticPubkey {
    pub bytes: Vec<u8>,
    pub key_id: [u8; 16],
}

impl SyntheticPubkey {
    /// Build a `[0x40 header | pubexp(256) | modulus(256)]` PubkeyFile blob
    /// from `pub_key`. The 16-byte `key_id` and `certifying_id` fields are
    /// caller-supplied — set them to whatever a test wants the
    /// chain-of-trust map keyed by.
    pub fn from_key(pub_key: &RsaPublicKey, key_id: [u8; 16], certifying_id: [u8; 16]) -> Self {
        let mut buf = vec![0u8; 0x40 + 256 + 256];
        buf[0x00..0x04].copy_from_slice(&1u32.to_le_bytes()); // version
        buf[0x04..0x14].copy_from_slice(&key_id);
        buf[0x14..0x24].copy_from_slice(&certifying_id);
        // key_usage = 0 (AMD_CODE_SIGN), security_features = 0
        buf[0x38..0x3C].copy_from_slice(&2048u32.to_le_bytes()); // pubexp_bits
        buf[0x3C..0x40].copy_from_slice(&2048u32.to_le_bytes()); // modulus_bits

        // Pad pubexp / modulus to 256-byte slots, little-endian.
        let mut e_le = pub_key.e().to_bytes_le();
        e_le.resize(256, 0);
        buf[0x40..0x40 + 256].copy_from_slice(&e_le);
        let mut n_le = pub_key.n().to_bytes_le();
        n_le.resize(256, 0);
        buf[0x140..0x140 + 256].copy_from_slice(&n_le);

        Self { bytes: buf, key_id }
    }
}

/// Generate a deterministic RSA-2048 keypair for tests.
///
/// Seed is fixed so test runs are reproducible. The keypair is *only* for
/// tests — never ship a hardcoded seed in production code.
pub fn generate_test_keypair() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_C0DE_F00D);
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate test 2048-bit RSA key");
    let pub_key = priv_key.to_public_key();
    (priv_key, pub_key)
}

/// Build a complete synthetic ROM containing:
///
/// * FET at offset `0x000` with one pointer to a `$PSP` directory.
/// * `$PSP` directory with two entries: a Pubkey (`type 0x00`) carrying
///   `pubkey`, and a HeaderFile (`type 0x01`) carrying `payload`.
/// * The HeaderFile is signed with `priv_key` over `header || payload`,
///   `signature_fingerprint == pubkey.key_id`.
///
/// `payload` length is padded with zeros to make the body sane (must be
/// non-empty). The HeaderFile uses RSA-2048 (`signature_type = 0`,
/// `sig_len = 0x100`).
///
/// Returns `(rom_bytes, sig_fingerprint_off, header_body_off, sig_region_off)`:
///
/// * `sig_fingerprint_off` — absolute offset of the 16-byte
///   `signature_fingerprint` field inside the HeaderFile (so tests can
///   point it at a different / unknown key).
/// * `header_body_off` — absolute offset of the start of the HeaderFile
///   entry body (its 0x100 header).
/// * `sig_region_off` — absolute offset of the trailing signature region
///   inside the HeaderFile body.
pub fn build_synthetic_rom_with_signed_entry(
    priv_key: &RsaPrivateKey,
    pubkey: &SyntheticPubkey,
    payload: &[u8],
) -> (Vec<u8>, usize, usize, usize) {
    // Layout (16 MiB ROM, low offsets — masking is identity here):
    //   0x000  FET           (magic + 1 pointer slot + 16-byte terminator = 24 bytes)
    //   0x040  $PSP directory header (0x10) + 2 entries (0x10 each) = 0x30 bytes
    //   0x080  Pubkey body (0x40 + 256 + 256 = 0x240 bytes)
    //   0x300  HeaderFile body (0x100 header + payload_padded + 0x100 sig)
    //
    // We pad payload up to a 16-aligned length so future encryption tests
    // could plug in here too.
    let payload_len = payload.len().div_ceil(16) * 16;
    let mut payload_padded = vec![0u8; payload_len];
    payload_padded[..payload.len()].copy_from_slice(payload);

    let pubkey_off = 0x080usize;
    let pubkey_len = pubkey.bytes.len();
    let header_body_off = 0x300usize;
    let header_total_len = HEADER_FILE_LEN + payload_padded.len() + 0x100;

    // Total ROM length — round up to 0x1000 so we have generous headroom.
    let rom_len = ((header_body_off + header_total_len + 0xFFF) & !0xFFF).max(0x1000);
    let mut rom = vec![0u8; rom_len];

    // ---- FET at 0x000 -----------------------------------------------------
    rom[0..4].copy_from_slice(b"\xAA\x55\xAA\x55"); // FET_MAGIC
    // Pointer slot 0 → $PSP directory at 0x040 (PhysicalX86 mode; identity for low offsets).
    rom[4..8].copy_from_slice(&0x0000_0040u32.to_le_bytes());
    // 16-byte terminator at 0x008..0x018.
    rom[8..24].copy_from_slice(&[0xFFu8; 16]);

    // ---- $PSP directory at 0x040 -----------------------------------------
    let dir_off = 0x040usize;
    rom[dir_off..dir_off + 4].copy_from_slice(b"$PSP");
    rom[dir_off + 4..dir_off + 8].copy_from_slice(&0u32.to_le_bytes()); // checksum
    rom[dir_off + 8..dir_off + 0xC].copy_from_slice(&2u32.to_le_bytes()); // count = 2
    // additional_info: v1 (bit 31 = 1), mode bits[25:24] = 01 (FlashOffset)
    // — entry `offset` fields are treated as absolute flash offsets, which
    // matches our hand-laid pubkey/header positions below. FlashOffset does
    // not defer to entry-level mode bits, so `rsv0[31:30]` is ignored here.
    let additional_info: u32 = (1u32 << 31) | (0b01u32 << 24);
    rom[dir_off + 0xC..dir_off + 0x10].copy_from_slice(&additional_info.to_le_bytes());

    // Entry 0: Pubkey (type 0x00).
    let entry0 = dir_off + 0x10;
    rom[entry0] = 0x00; // entry_type = AMD_PUBLIC_KEY
    rom[entry0 + 4..entry0 + 8].copy_from_slice(&(pubkey_len as u32).to_le_bytes());
    rom[entry0 + 8..entry0 + 0xC].copy_from_slice(&(pubkey_off as u32).to_le_bytes());

    // Entry 1: HeaderFile (type 0x01).
    let entry1 = dir_off + 0x20;
    rom[entry1] = 0x01; // entry_type = PSP_FW_BOOT_LOADER
    rom[entry1 + 4..entry1 + 8].copy_from_slice(&(header_total_len as u32).to_le_bytes());
    rom[entry1 + 8..entry1 + 0xC].copy_from_slice(&(header_body_off as u32).to_le_bytes());

    // ---- Pubkey body ------------------------------------------------------
    rom[pubkey_off..pubkey_off + pubkey_len].copy_from_slice(&pubkey.bytes);

    // ---- HeaderFile body --------------------------------------------------
    // Build a 0x100-byte header in-place, then sign over (header || payload).
    let h_off = header_body_off;
    rom[h_off + 0x10..h_off + 0x14].copy_from_slice(b"$PS1");
    let size_signed = (HEADER_FILE_LEN + payload_padded.len()) as u32;
    rom[h_off + 0x14..h_off + 0x18].copy_from_slice(&size_signed.to_le_bytes());
    // is_encrypted = 0
    rom[h_off + 0x30..h_off + 0x34].copy_from_slice(&1u32.to_le_bytes()); // is_signed = 1
    rom[h_off + 0x34..h_off + 0x38].copy_from_slice(&0u32.to_le_bytes()); // signature_type = 0
    // signature_fingerprint: certifying-key id — points at our pubkey.
    rom[h_off + 0x38..h_off + 0x48].copy_from_slice(&pubkey.key_id);
    // is_compressed = 0 (already zero)
    // rom_size = HEADER + payload + sig
    rom[h_off + 0x6C..h_off + 0x70].copy_from_slice(&(header_total_len as u32).to_le_bytes());

    // Place the payload after the header.
    let payload_start = h_off + HEADER_FILE_LEN;
    rom[payload_start..payload_start + payload_padded.len()].copy_from_slice(&payload_padded);

    // Sign (header || payload) with PSS-SHA256.
    let mut signed = Vec::with_capacity(HEADER_FILE_LEN + payload_padded.len());
    signed.extend_from_slice(&rom[h_off..h_off + HEADER_FILE_LEN]);
    signed.extend_from_slice(&payload_padded);

    let mut rng = StdRng::seed_from_u64(0xC0FF_EE00_BABE_FACE);
    let signing_key = SigningKey::<Sha256>::new(priv_key.clone());
    let sig = signing_key.sign_with_rng(&mut rng, &signed);
    let sig_be = sig.to_bytes(); // wire-order, big-endian
    let mut sig_disk = sig_be.to_vec();
    sig_disk.reverse();
    assert_eq!(sig_disk.len(), 0x100);

    let sig_region_off = h_off + HEADER_FILE_LEN + payload_padded.len();
    rom[sig_region_off..sig_region_off + 0x100].copy_from_slice(&sig_disk);

    let sig_fingerprint_off = h_off + 0x38;
    (rom, sig_fingerprint_off, header_body_off, sig_region_off)
}
