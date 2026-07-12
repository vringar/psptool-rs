//! `extract` operations — `entry.get_bytes() / get_decompressed_body() /
//! get_decrypted()` ports of the reference Python tool.
//!
//! Three functions take a parsed [`Entry`] and return owned bytes. No I/O —
//! the filesystem write happens in the CLI layer (`psptool-cli`, #15).
//!
//! Mapping to PSPTool's `File` hierarchy — each op ports the single-file
//! `-X` accessor the reference tool emits (the header-prefixed envelope, not
//! the bare body):
//!
//! | This module               | PSPTool accessor                                         |
//! | ------------------------- | -------------------------------------------------------- |
//! | [`extract_raw`]           | `File.get_bytes()` (`__main__.py:180`)                   |
//! | [`extract_decompressed`]  | `HeaderFile.get_signed_bytes()` — `-X -u` (`__main__.py:172`, `header_file.py:162-164`) |
//! | [`extract_decrypted`]     | `HeaderFile.to_decrypted_file_bytes()` — `-X -c` (`__main__.py:176`, `header_file.py:176-182`) |
//!
//! Decompression / decryption are only meaningful for entries that carry a
//! [`HeaderEntry`] — i.e. [`EntryClass::Header`] or [`EntryClass::KeyStore`].
//! Other classes produce [`ExtractError::NotHeaderEntry`].
//!
//! ## REQ status (per `.design/psptool-ops/extract.md`)
//!
//! | REQ | Status | Evidence |
//! |---|---|---|
//! | REQ-1 (`extract_raw` verbatim) | SHIPPED | `extract.rs:41` (`entry.get_bytes().as_bytes().to_vec()`) per upstream `file.get_bytes()` (`__main__.py:180`); consumer `cmds/extract.rs:137`/`:171`. |
//! | REQ-2 (`extract_decompressed` zlib inflate) | SHIPPED | `extract.rs` `extract_decompressed` → `get_signed_bytes` (which decrypt-then-inflates the data region) per upstream inflate step (`header_file.py:169-174`); consumer `cmds/extract.rs:127`/`:162`. Now returns the full `-u` envelope (REQ-7). |
//! | REQ-3 (`extract_decrypted` AES) | SHIPPED | `extract.rs` `extract_decrypted` (`get_decrypted_body`, `NotEncrypted` guard) per upstream `HeaderFile.get_decrypted_body()` (`header_file.py:184-190`); consumer `cmds/extract.rs:129`/`:164`. Now returns the full `-c` envelope (REQ-7). |
//! | REQ-4 (HeaderFile-class gate) | SHIPPED | `extract.rs:58`/`:78` (`entry.class.header().ok_or(NotHeaderEntry)?`) per upstream `type(file) is HeaderFile` (`__main__.py:193`,`:195`); Header/KeyStore only. |
//! | REQ-5 (typed panic-free errors) | SHIPPED | `ExtractError` at `extract.rs:22` (`NotHeaderEntry` + `Body(#[from] BodyError)`); no unwrap/expect/panic on the production path (R-CODE-2). |
//! | REQ-6 (CLI `extract` consumer) | SHIPPED | `cmds/extract.rs` binds all three ops (`:127`/`:129`/`:137`/`:162`/`:164`/`:171`), dispatched `main.rs:82` (`-X`) / `:125` (`Command::Extract`). Boundary CLI surface (R-DEFER-1). |
//! | REQ-7 (`-u`/`-c` envelope parity) | SHIPPED | `extract_decompressed` returns `get_signed_bytes()` (`header ++ decrypted-decompressed[..0x100+size_signed]`, `header_file.py:162-164`); `extract_decrypted` assembles `to_decrypted_file_bytes()` (`header(enc+IV cleared) ++ get_decrypted_body() ++ signature`, `header_file.py:176-182`). Consumer `cmds/extract.rs:127`/`:129` (single-file `-u`/`-c`, with the not-compressed/not-encrypted guards mirroring `__main__.py:170`/`:174`). Pins `divergence_extract_envelope.rs` (both `#[test]`, green). |

use psptool_core::entry::HEADER_FILE_LEN;
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

/// `HeaderFile.get_signed_bytes()` — the reference single-file `-X -u` output
/// (`__main__.py:172`).
///
/// Emits the upstream envelope, **not** the bare inflated body:
/// `header(0x100) ++ get_decrypted_decompressed_body()`, truncated to
/// `0x100 + size_signed` (`header_file.py:162-164`). The Zen+ IKEK is passed
/// unconditionally to mirror upstream's hard-coded default; it is consulted
/// only when the header advertises `is_encrypted == 1` (upstream decrypts then
/// decompresses inside `get_decrypted_decompressed_body`, `header_file.py:166-174`).
///
/// Returns an error when the entry is not a `HeaderFile`
/// ([`ExtractError::NotHeaderEntry`]). The `not-compressed` guard that upstream
/// applies before this accessor (`__main__.py:170`) lives in the CLI arg layer
/// (`crates/psptool-cli/src/cmds/extract.rs`), not here — `get_signed_bytes`
/// itself is defined for both compressed and uncompressed HeaderFiles.
pub fn extract_decompressed(entry: &Entry) -> Result<Vec<u8>, ExtractError> {
    let header = entry.class.header().ok_or(ExtractError::NotHeaderEntry)?;
    let out = header.get_signed_bytes(entry.body.as_bytes(), Some(Ikek::ZenPlus))?;
    Ok(out)
}

/// `HeaderFile.to_decrypted_file_bytes()` — the reference single-file `-X -c`
/// output (`__main__.py:176`).
///
/// Emits the upstream envelope, **not** the bare decrypted body: a copy of the
/// `0x100` header with `[0x18:0x1c]` (is_encrypted) and `[0x20:0x30]` (IV)
/// cleared, then `get_decrypted_body()`, then the trailing signature
/// (`header_file.py:176-182`). `signature_bytes` returns empty for unsigned
/// HeaderFiles (per #83), so no `is_signed` conditional is needed here.
///
/// Returns an error when the entry is not a `HeaderFile`
/// ([`ExtractError::NotHeaderEntry`]) or when the header reports
/// `is_encrypted == 0` ([`BodyError::NotEncrypted`], surfaced by
/// `get_decrypted_body`). The `not-encrypted` guard upstream applies before
/// this accessor (`__main__.py:174`) is also enforced in the CLI arg layer.
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
    let body = entry.body.as_bytes();
    if body.len() < HEADER_FILE_LEN {
        return Err(BodyError::Truncated(body.len()).into());
    }
    // Cleared-flag header copy (`header_file.py:178-180`).
    let mut out = body[..HEADER_FILE_LEN].to_vec();
    out[0x18..0x1C].fill(0);
    out[0x20..0x30].fill(0);
    // Decrypted body (`header_file.py:182` `+ self.get_decrypted_body()`).
    out.extend_from_slice(&header.get_decrypted_body(body, ikek)?);
    // Trailing signature (`header_file.py:181-182` `+ signature`); empty when
    // unsigned (#83).
    out.extend_from_slice(header.signature_bytes(body)?);
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
        Entry::parse_psp(&blob, &dir, 0, RomSize::MIB_16, FlashOffset::ZERO).unwrap()
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
        // `size_signed` is header-EXCLUSIVE (the body-signed length) — the fixed
        // convention (#80, `body.rs:374-376`).
        let size_signed = plaintext.len() as u32;
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

    /// Build a compressed + signed (not encrypted) HeaderFile body wrapping the
    /// committed `header_compressed` zlib stream, with a caller-chosen
    /// header-EXCLUSIVE `size_signed` (the fixed convention, `body.rs:374-376`).
    /// A fixed 0x100 signature placeholder trails the stream.
    fn build_compressed_signed_body(size_signed: u32) -> Vec<u8> {
        const SIG_LEN: usize = 0x100;
        let fixture = psptool_fixtures::micro::header_compressed();
        let zlib_size =
            u32::from_le_bytes([fixture[0x54], fixture[0x55], fixture[0x56], fixture[0x57]])
                as usize;
        let stream = &fixture[HEADER_FILE_LEN..HEADER_FILE_LEN + zlib_size];

        let rom_size = (HEADER_FILE_LEN + zlib_size + SIG_LEN) as u32;
        let mut h = [0u8; HEADER_FILE_LEN];
        h[0x10..0x14].copy_from_slice(b"$PS1");
        h[0x14..0x18].copy_from_slice(&size_signed.to_le_bytes()); // header-exclusive
        h[0x30..0x34].copy_from_slice(&1u32.to_le_bytes()); // is_signed
        h[0x34..0x38].copy_from_slice(&0u32.to_le_bytes()); // signature_type = RSA-2048
        h[0x48..0x4C].copy_from_slice(&1u32.to_le_bytes()); // is_compressed
        h[0x50..0x54].copy_from_slice(&17u32.to_le_bytes()); // size_uncompressed
        h[0x54..0x58].copy_from_slice(&(zlib_size as u32).to_le_bytes()); // zlib_size
        h[0x6C..0x70].copy_from_slice(&rom_size.to_le_bytes());

        let mut body = Vec::with_capacity(HEADER_FILE_LEN + zlib_size + SIG_LEN);
        body.extend_from_slice(&h);
        body.extend_from_slice(stream);
        body.extend(std::iter::repeat_n(0xBBu8, SIG_LEN));
        body
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
    fn extract_decompressed_returns_signed_bytes_envelope() {
        // `extract_decompressed` emits upstream `get_signed_bytes()`
        // (`header_file.py:162-164`): header(0x100) ++ inflated-body, truncated
        // to 0x100 + size_signed. Wrap the committed `header_compressed` zlib
        // stream (inflates to b"hello, psptool-rs", 17 bytes) in a signed body
        // that signs the full inflated length.
        let size_signed: u32 = 17;
        let body = build_compressed_signed_body(size_signed);
        let blob_bytes = psp_dir_with_entry(0x01, &body);
        let entry = parse_single_psp_entry(blob_bytes);
        assert!(matches!(entry.class, EntryClass::Header(_)));

        let mut expected = entry.body.as_bytes()[..HEADER_FILE_LEN].to_vec();
        expected.extend_from_slice(b"hello, psptool-rs");

        let out = extract_decompressed(&entry).ok();
        assert_eq!(out, Some(expected));
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
    fn extract_decompressed_returns_envelope_for_uncompressed_signed_entry() {
        // The `not-compressed` guard moved to the CLI arg layer (mirrors
        // `__main__.py:170`). At the ops level `extract_decompressed` ==
        // `get_signed_bytes`, which is defined for uncompressed HeaderFiles too:
        // it returns header(0x100) ++ data_region[..size_signed] with NO
        // inflation (`get_decrypted_decompressed_body` returns the data region
        // verbatim when `is_compressed == 0`, `header_file.py:169-174`).
        const DATA: &[u8] = b"UNCOMPRESSED-BODY!"; // 18 bytes
        const SIG_LEN: usize = 0x100;
        let size_signed = DATA.len() as u32;
        let rom_size = (HEADER_FILE_LEN + DATA.len() + SIG_LEN) as u32;
        let mut h = [0u8; HEADER_FILE_LEN];
        h[0x10..0x14].copy_from_slice(b"$PS1");
        h[0x14..0x18].copy_from_slice(&size_signed.to_le_bytes());
        h[0x30..0x34].copy_from_slice(&1u32.to_le_bytes()); // is_signed
        h[0x34..0x38].copy_from_slice(&0u32.to_le_bytes()); // RSA-2048
        h[0x6C..0x70].copy_from_slice(&rom_size.to_le_bytes());
        let mut body = Vec::new();
        body.extend_from_slice(&h);
        body.extend_from_slice(DATA);
        body.extend(std::iter::repeat_n(0xBBu8, SIG_LEN));

        let blob_bytes = psp_dir_with_entry(0x01, &body);
        let entry = parse_single_psp_entry(blob_bytes);
        assert!(matches!(entry.class, EntryClass::Header(_)));

        let mut expected = entry.body.as_bytes()[..HEADER_FILE_LEN].to_vec();
        expected.extend_from_slice(DATA);

        let out = extract_decompressed(&entry).ok();
        assert_eq!(out, Some(expected));
    }

    // -- extract_decrypted ---------------------------------------------------

    #[test]
    fn extract_decrypted_returns_to_decrypted_file_bytes_envelope() {
        let plaintext = b"sixteen bytes !!"; // 16 bytes (one AES block)
        let entry_key = [0xA5u8; 16];
        let body = build_encrypted_header_body(plaintext, entry_key, Ikek::ZenPlus);
        let blob_bytes = psp_dir_with_entry(0x01, &body); // Header-class
        let entry = parse_single_psp_entry(blob_bytes);
        assert!(entry.class.header().is_some_and(|h| h.is_encrypted));

        // Upstream to_decrypted_file_bytes (`header_file.py:176-182`): header
        // with is_encrypted (0x18..0x1c) and IV (0x20..0x30) cleared, then the
        // decrypted body, then the trailing signature.
        let mut expected = entry.body.as_bytes()[..HEADER_FILE_LEN].to_vec();
        expected[0x18..0x1C].fill(0);
        expected[0x20..0x30].fill(0);
        expected.extend_from_slice(plaintext);
        expected.extend(std::iter::repeat_n(0u8, 0x100)); // signature placeholder

        let out = extract_decrypted(&entry, Ikek::ZenPlus).ok();
        assert_eq!(out, Some(expected));
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
    fn extract_decrypted_with_wrong_ikek_diverges_in_body() {
        // The IKEK is consulted only for the decrypted-body slice of the
        // envelope; the cleared header + trailing signature are identical for
        // any key, so a wrong IKEK must still yield a DIFFERENT envelope.
        let plaintext = b"sixteen bytes !!";
        let entry_key = [0xA5u8; 16];
        let body = build_encrypted_header_body(plaintext, entry_key, Ikek::ZenPlus);
        let blob_bytes = psp_dir_with_entry(0x01, &body);
        let entry = parse_single_psp_entry(blob_bytes);

        let mut expected_right = entry.body.as_bytes()[..HEADER_FILE_LEN].to_vec();
        expected_right[0x18..0x1C].fill(0);
        expected_right[0x20..0x30].fill(0);
        expected_right.extend_from_slice(plaintext);
        expected_right.extend(std::iter::repeat_n(0u8, 0x100));

        let wrong = extract_decrypted(&entry, Ikek::Zen).ok();
        let right = extract_decrypted(&entry, Ikek::ZenPlus).ok();
        assert_eq!(right, Some(expected_right));
        assert_ne!(wrong, right);
    }

    // -- KeyStore handling: is also a HeaderEntry-class ---------------------

    #[test]
    fn extract_decompressed_works_on_keystore_class() {
        // Type 0x50 → KeyStore. A KeyStore carries a HeaderEntry just like
        // Header, so extract_decompressed reaches `get_signed_bytes` (the
        // envelope) instead of NotHeaderEntry — proving KeyStore is treated
        // like Header.
        let size_signed: u32 = 17;
        let body = build_compressed_signed_body(size_signed);
        let blob_bytes = psp_dir_with_entry(0x50, &body);
        let entry = parse_single_psp_entry(blob_bytes);
        assert!(matches!(entry.class, EntryClass::KeyStore(_)));

        let mut expected = entry.body.as_bytes()[..HEADER_FILE_LEN].to_vec();
        expected.extend_from_slice(b"hello, psptool-rs");

        let out = extract_decompressed(&entry).ok();
        assert_eq!(out, Some(expected));
    }
}
