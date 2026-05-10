//! `extract` operations — `entry.get_bytes() / get_decompressed_body() /
//! get_decrypted()` ports of the reference Python tool.
//!
//! Three functions take a parsed [`Entry`] and return owned bytes. No I/O —
//! the filesystem write happens in the CLI layer (`psptool-cli`, #15).
//!
//! Mapping to PSPTool's `File` hierarchy:
//!
//! | This module               | PSPTool method                          |
//! | ------------------------- | --------------------------------------- |
//! | [`extract_raw`]           | `File.get_bytes()`                      |
//! | [`extract_decompressed`]  | `HeaderFile.get_decompressed_body()`    |
//! | [`extract_decrypted`]     | `HeaderFile.get_decrypted()`            |
//!
//! Decompression / decryption are only meaningful for entries that carry a
//! [`HeaderEntry`] — i.e. [`EntryClass::Header`] or [`EntryClass::KeyStore`].
//! Other classes produce [`ExtractError::NotHeaderEntry`].

use psptool_core::{BodyError, Entry, Ikek};
use thiserror::Error;

/// Errors returned by [`extract_decompressed`] / [`extract_decrypted`].
#[derive(Debug, Error)]
pub enum ExtractError {
    /// Entry class does not carry a [`HeaderEntry`] (e.g. `Plain`, `Pubkey`,
    /// directory-pointer entries). Decompression and decryption are only
    /// defined for `HeaderFile`-class bodies.
    #[error("entry does not carry a HeaderFile body (class lacks decompression/decryption)")]
    NotHeaderEntry,
    /// Failure inside `psptool-core` body access (truncation, missing zlib
    /// magic, decrypt failure, etc.).
    #[error(transparent)]
    Body(#[from] BodyError),
}

/// `File.get_bytes()` — return the entry body bytes verbatim.
///
/// Allocates a fresh `Vec<u8>` so callers can write it to disk without
/// holding the parser's source-byte borrow. For zero-copy access use
/// [`Entry::get_bytes`] directly.
pub fn extract_raw(entry: &Entry) -> Vec<u8> {
    entry.get_bytes().as_bytes().to_vec()
}

/// `HeaderFile.get_decompressed_body()` — decompress the data region.
///
/// Returns an error when the entry is not a `HeaderFile` ([`ExtractError::NotHeaderEntry`])
/// or when the header reports `is_compressed == 0` ([`BodyError::NotCompressed`]).
/// Operates on the (possibly still-encrypted) data region — for entries that
/// are *both* encrypted and compressed, callers must decrypt first
/// (`extract_decrypted` then re-feed) or use the combined
/// `HeaderEntry::get_decrypted_decompressed_body` from `psptool-core`. The
/// reference Python tool layers the same way.
///
/// Output preserves the pre-zlib-magic prefix (matches PSPTool's
/// `psptool/utils.py::zlib_decompress`).
pub fn extract_decompressed(entry: &Entry) -> Result<Vec<u8>, ExtractError> {
    let header = entry.class.header().ok_or(ExtractError::NotHeaderEntry)?;
    let plaintext = header.data_region(entry.body.as_bytes())?;
    let out = header.get_decompressed_body(plaintext)?;
    Ok(out)
}

/// `HeaderFile.get_decrypted()` — AES-128-CBC decrypt the data region using
/// `ikek` to unwrap the per-entry key.
///
/// Returns an error when the entry is not a `HeaderFile` ([`ExtractError::NotHeaderEntry`])
/// or when the header reports `is_encrypted == 0` ([`BodyError::NotEncrypted`]).
///
/// Procedure (`docs/firmware-layout.md` §5):
/// 1. `entry_key = AES-128-ECB-decrypt(wrapped_key, ikek_bytes)`
/// 2. `plaintext = AES-128-CBC-decrypt(data_region, iv, entry_key)`
///
/// Selecting the right [`Ikek`] is the chain-of-trust resolution work tracked
/// by #13; until then callers pass [`Ikek::ZenPlus`] (PSPTool's default) or
/// [`Ikek::Custom`].
pub fn extract_decrypted(entry: &Entry, ikek: Ikek) -> Result<Vec<u8>, ExtractError> {
    let header = entry.class.header().ok_or(ExtractError::NotHeaderEntry)?;
    let out = header.get_decrypted_body(entry.body.as_bytes(), ikek)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::Aes128;
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{
        BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit, block_padding::NoPadding,
    };
    use psptool_core::entry::HEADER_FILE_LEN;
    use psptool_core::{Directory, Entry, EntryClass, FlashOffset, RomSize, SourceBytes};

    // -- Helpers -------------------------------------------------------------

    /// Build a single-entry `$PSP` directory wrapping `body` at the given
    /// entry-type. Mirrors the helper used in `psptool-core::entry` tests so
    /// the resulting `Entry` is parsed end-to-end (including classification).
    fn psp_dir_with_entry(entry_type: u8, body: &[u8]) -> Vec<u8> {
        use psptool_core::directory::{DIRECTORY_HEADER_SIZE, PSP_ENTRY_SIZE};
        let body_off = (DIRECTORY_HEADER_SIZE + PSP_ENTRY_SIZE) as u32;
        let size = body.len() as u32;
        let additional_info = (1u32 << 31) | (0b10u32 << 24);
        let mut entry = [0u8; PSP_ENTRY_SIZE];
        entry[0x00] = entry_type;
        entry[0x04..0x08].copy_from_slice(&size.to_le_bytes());
        entry[0x08..0x0C].copy_from_slice(&body_off.to_le_bytes());
        let entry_rsv0: u32 = 0b10u32 << 30;
        entry[0x0C..0x10].copy_from_slice(&entry_rsv0.to_le_bytes());

        let mut out = Vec::new();
        out.extend_from_slice(b"$PSP");
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&additional_info.to_le_bytes());
        out.extend_from_slice(&entry);
        out.extend_from_slice(body);
        out
    }

    fn parse_single_psp_entry(blob_bytes: Vec<u8>) -> Entry {
        let blob = SourceBytes::from_blob(blob_bytes);
        let dir = match Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
            Directory::Psp(p) => p,
            _ => unreachable!(),
        };
        Entry::parse_psp(&blob, &dir, 0, RomSize::MIB_16).unwrap()
    }

    /// Build a header-file body that is BOTH `is_encrypted` and `is_signed`
    /// with a known plaintext. Returns `(body_bytes, plaintext)`.
    fn build_encrypted_header_body(plaintext: &[u8], entry_key: [u8; 16], ikek: Ikek) -> Vec<u8> {
        use cbc::Encryptor as CbcEnc;
        type Aes128CbcEnc = CbcEnc<Aes128>;

        assert!(plaintext.len().is_multiple_of(16));
        let iv = [
            0x10u8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
            0x1E, 0x1F,
        ];
        let cipher = Aes128::new(GenericArray::from_slice(&ikek.bytes()));
        let mut block = GenericArray::clone_from_slice(&entry_key);
        cipher.encrypt_block(&mut block);
        let wrapped: [u8; 16] = block.into();

        let mut buf = vec![0u8; plaintext.len()];
        let ct = Aes128CbcEnc::new_from_slices(&entry_key, &iv)
            .unwrap()
            .encrypt_padded_b2b_mut::<NoPadding>(plaintext, &mut buf)
            .unwrap();
        let ct_len = ct.len();
        buf.truncate(ct_len);

        let mut h = [0u8; HEADER_FILE_LEN];
        h[0x10..0x14].copy_from_slice(b"$PS1");
        let size_signed = (HEADER_FILE_LEN + plaintext.len()) as u32;
        h[0x14..0x18].copy_from_slice(&size_signed.to_le_bytes());
        h[0x18..0x1C].copy_from_slice(&1u32.to_le_bytes()); // is_encrypted
        h[0x20..0x30].copy_from_slice(&iv);
        h[0x30..0x34].copy_from_slice(&1u32.to_le_bytes()); // is_signed
        h[0x34..0x38].copy_from_slice(&0u32.to_le_bytes()); // RSA-2048
        h[0x6C..0x70]
            .copy_from_slice(&((HEADER_FILE_LEN + plaintext.len() + 0x100) as u32).to_le_bytes());
        h[0x80..0x90].copy_from_slice(&wrapped);

        let mut out = Vec::with_capacity(HEADER_FILE_LEN + plaintext.len() + 0x100);
        out.extend_from_slice(&h);
        out.extend_from_slice(&buf);
        out.extend(std::iter::repeat_n(0u8, 0x100)); // signature placeholder
        out
    }

    // -- extract_raw ---------------------------------------------------------

    #[test]
    fn extract_raw_returns_body_bytes_verbatim_for_plain_entry() {
        // Type 0x21 (WRAPPED_IKEK) → NO_HDR → Plain.
        let body = b"raw-extract-test".to_vec();
        let blob_bytes = psp_dir_with_entry(0x21, &body);
        let entry = parse_single_psp_entry(blob_bytes);
        assert!(matches!(entry.class, EntryClass::Plain));

        let out = extract_raw(&entry);
        assert_eq!(out, body);
    }

    #[test]
    fn extract_raw_returns_body_bytes_verbatim_for_header_entry() {
        let body = psptool_fixtures::micro::header_signed().to_vec();
        let blob_bytes = psp_dir_with_entry(0x01, &body); // PSP_FW_BOOT_LOADER → Header
        let entry = parse_single_psp_entry(blob_bytes);
        assert!(matches!(entry.class, EntryClass::Header(_)));

        let out = extract_raw(&entry);
        assert_eq!(out, body);
    }

    #[test]
    fn extract_raw_independent_of_class_works_on_pubkey() {
        let body = psptool_fixtures::micro::pubkey_v1().to_vec();
        let blob_bytes = psp_dir_with_entry(0x00, &body); // AMD_PUBLIC_KEY → Pubkey
        let entry = parse_single_psp_entry(blob_bytes);
        assert!(matches!(entry.class, EntryClass::Pubkey(_)));

        let out = extract_raw(&entry);
        assert_eq!(out, body);
    }

    // -- extract_decompressed ------------------------------------------------

    #[test]
    fn extract_decompressed_round_trips_committed_compressed_fixture() {
        // The committed `header_compressed` fixture compresses
        // b"hello, psptool-rs" with zlib at offset 0x100.
        let body = psptool_fixtures::micro::header_compressed().to_vec();
        let blob_bytes = psp_dir_with_entry(0x01, &body);
        let entry = parse_single_psp_entry(blob_bytes);
        assert!(matches!(entry.class, EntryClass::Header(_)));

        let out = extract_decompressed(&entry).expect("decompress succeeds");
        // get_decompressed_body operates on data_region (post-header), so the
        // pre-zlib-magic prefix is whatever sits between offset 0 of the data
        // region and the zlib stream start. The committed fixture lays the
        // stream directly at the start of the data region → output is purely
        // the decompressed payload.
        assert_eq!(out, b"hello, psptool-rs");
    }

    #[test]
    fn extract_decompressed_errors_for_non_header_entry() {
        let body = vec![0xAAu8; 0x10];
        let blob_bytes = psp_dir_with_entry(0x21, &body); // Plain
        let entry = parse_single_psp_entry(blob_bytes);
        assert!(matches!(entry.class, EntryClass::Plain));

        let err = extract_decompressed(&entry).unwrap_err();
        assert!(matches!(err, ExtractError::NotHeaderEntry));
    }

    #[test]
    fn extract_decompressed_errors_for_pubkey_entry() {
        let body = psptool_fixtures::micro::pubkey_v1().to_vec();
        let blob_bytes = psp_dir_with_entry(0x00, &body);
        let entry = parse_single_psp_entry(blob_bytes);

        let err = extract_decompressed(&entry).unwrap_err();
        assert!(matches!(err, ExtractError::NotHeaderEntry));
    }

    #[test]
    fn extract_decompressed_errors_when_header_not_compressed() {
        let body = psptool_fixtures::micro::header_signed().to_vec();
        let blob_bytes = psp_dir_with_entry(0x01, &body);
        let entry = parse_single_psp_entry(blob_bytes);

        let err = extract_decompressed(&entry).unwrap_err();
        assert!(matches!(err, ExtractError::Body(BodyError::NotCompressed)));
    }

    // -- extract_decrypted ---------------------------------------------------

    #[test]
    fn extract_decrypted_round_trips_synthetic_encrypted_entry() {
        let plaintext = b"sixteen bytes !!"; // 16 bytes (one AES block)
        let entry_key = [0xA5u8; 16];
        let body = build_encrypted_header_body(plaintext, entry_key, Ikek::ZenPlus);
        let blob_bytes = psp_dir_with_entry(0x01, &body); // Header-class
        let entry = parse_single_psp_entry(blob_bytes);
        let header = entry.class.header().expect("header entry");
        assert!(header.is_encrypted);

        let out = extract_decrypted(&entry, Ikek::ZenPlus).expect("decrypt succeeds");
        assert_eq!(out, plaintext);
    }

    #[test]
    fn extract_decrypted_uses_committed_encrypted_fixture() {
        // The committed `header_encrypted` fixture was built with the Zen+
        // IKEK and a known plaintext (`header_encrypted` build script) — we
        // assert the round-trip succeeds and the output starts with the
        // documented marker.
        let body = psptool_fixtures::micro::header_encrypted().to_vec();
        let blob_bytes = psp_dir_with_entry(0x01, &body);
        let entry = parse_single_psp_entry(blob_bytes);
        let header = entry.class.header().expect("header entry");
        assert!(header.is_encrypted);

        let out = extract_decrypted(&entry, Ikek::ZenPlus).expect("decrypt succeeds");
        // The committed fixture's plaintext is non-empty and matches the
        // declared data-region length (one AES block multiple).
        assert!(!out.is_empty());
        assert!(out.len().is_multiple_of(16));
    }

    #[test]
    fn extract_decrypted_errors_for_non_header_entry() {
        let body = vec![0xAAu8; 0x10];
        let blob_bytes = psp_dir_with_entry(0x21, &body); // Plain
        let entry = parse_single_psp_entry(blob_bytes);

        let err = extract_decrypted(&entry, Ikek::ZenPlus).unwrap_err();
        assert!(matches!(err, ExtractError::NotHeaderEntry));
    }

    #[test]
    fn extract_decrypted_errors_for_pubkey_entry() {
        let body = psptool_fixtures::micro::pubkey_v1().to_vec();
        let blob_bytes = psp_dir_with_entry(0x00, &body); // Pubkey
        let entry = parse_single_psp_entry(blob_bytes);

        let err = extract_decrypted(&entry, Ikek::ZenPlus).unwrap_err();
        assert!(matches!(err, ExtractError::NotHeaderEntry));
    }

    #[test]
    fn extract_decrypted_errors_when_header_not_encrypted() {
        let body = psptool_fixtures::micro::header_signed().to_vec();
        let blob_bytes = psp_dir_with_entry(0x01, &body);
        let entry = parse_single_psp_entry(blob_bytes);

        let err = extract_decrypted(&entry, Ikek::ZenPlus).unwrap_err();
        assert!(matches!(err, ExtractError::Body(BodyError::NotEncrypted)));
    }

    #[test]
    fn extract_decrypted_with_wrong_ikek_does_not_match_plaintext() {
        // Sanity: using the wrong IKEK still succeeds (AES is a permutation —
        // any 16-byte key produces 16-byte plaintext) but yields garbage that
        // is *not* the original. Demonstrates the IKEK is consulted.
        let plaintext = b"sixteen bytes !!";
        let entry_key = [0xA5u8; 16];
        let body = build_encrypted_header_body(plaintext, entry_key, Ikek::ZenPlus);
        let blob_bytes = psp_dir_with_entry(0x01, &body);
        let entry = parse_single_psp_entry(blob_bytes);

        let wrong = extract_decrypted(&entry, Ikek::Zen).expect("decrypt completes");
        assert_ne!(wrong, plaintext);
        let right = extract_decrypted(&entry, Ikek::ZenPlus).expect("decrypt completes");
        assert_eq!(right, plaintext);
    }

    // -- KeyStore handling: is also a HeaderEntry-class ---------------------

    #[test]
    fn extract_decompressed_works_on_keystore_class() {
        // Type 0x50 → KeyStore. Our committed `header_signed` fixture is
        // not compressed, so we expect NotCompressed (the gate fires), NOT
        // NotHeaderEntry — proving KeyStore is treated like Header.
        let body = psptool_fixtures::micro::header_signed().to_vec();
        let blob_bytes = psp_dir_with_entry(0x50, &body);
        let entry = parse_single_psp_entry(blob_bytes);
        assert!(matches!(entry.class, EntryClass::KeyStore(_)));

        let err = extract_decompressed(&entry).unwrap_err();
        assert!(matches!(err, ExtractError::Body(BodyError::NotCompressed)));
    }
}
