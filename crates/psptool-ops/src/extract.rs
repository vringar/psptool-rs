//! `extract` operations — `entry.get_bytes() / get_decompressed_body() /
//! get_decrypted()` ports of the reference Python tool.
//!
//! Three functions take a parsed [`Entry`] and return owned bytes. No I/O —
//! the filesystem write happens in the CLI layer (`psptool-cli`, #15). All
//! three also take the image the entry was parsed from: they read the
//! HeaderFile buffer re-sized to the header's `rom_size`
//! ([`Entry::header_file_window`], [`Entry::file_bytes`],
//! `header_file.py:72-75`, `:104-105`), which can extend past the directory
//! entry or stop short of it.
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
//! [`HeaderEntry`] — i.e. [`EntryClass::Header`] or [`EntryClass::KeyStore`]
//! (upstream's `HeaderFile` and its `KeyStoreFile` subclass, which overrides
//! `get_signed_bytes()`). Other classes produce [`ExtractError::NotHeaderEntry`].
//! Multi-file `-u`/`-c` transform only exact `HeaderFile`s
//! (`type(file) is HeaderFile`, `__main__.py:193-196`); that gate lives in the
//! CLI.
//!
//! ## REQ status (per `.design/psptool-ops/extract.md`)
//!
//! | REQ | Status | Evidence |
//! |---|---|---|
//! | REQ-1 (`extract_raw` = `File.get_bytes()`) | SHIPPED | `extract.rs:69` (`entry.file_bytes(blob).as_bytes().to_vec()`; core `Entry::file_bytes`: a HeaderFile-class entry's buffer re-sized to `rom_size`, `header_file.py:72-75`, `:104-105`, else the body; #101) per upstream `file.get_bytes()` (`__main__.py:180`, `:200`); consumer `cmds/extract.rs:162`/`:251` (and the `-T` identical-bytes check, `cmds/extract.rs:108-111`, `__main__.py:52-56`). |
//! | REQ-2 (`extract_decompressed` zlib inflate) | SHIPPED | `extract.rs:98` `extract_decompressed(entry, blob)` → `get_signed_bytes` (core `body.rs:384`) over the `rom_size` HeaderFile buffer `Entry::header_file_window` (core `body.rs:867`, `header_file.py:72-75`, #99), which decrypts then inflates through the decode-verification ladder's `_decrypted_decompressed_body` decode (`zlib_find_header` priority search, strict inflate, still-compressed fallback; #91) per upstream `header_file.py:179-186`, `utils.py:218-254`; a `KeyStoreFile` takes its override `get_key_store_signed_bytes` (core `body.rs:1011`, `key_store_file.py:50-51`, #100); consumer `cmds/extract.rs:143`/`:221`. Returns the full `-u` envelope (REQ-7). |
//! | REQ-3 (`extract_decrypted` AES) | SHIPPED | `extract.rs:148` `extract_decrypted(entry, blob, ikek)` (`get_decrypted_body` over the same `rom_size` buffer, `NotEncrypted` guard) per upstream `HeaderFile.get_decrypted_body()` (`header_file.py:286-292`); consumer `cmds/extract.rs:154`. Returns the full `-c` envelope (REQ-7). |
//! | REQ-4 (HeaderFile-class gate) | SHIPPED | `extract.rs:117` (`entry.class.header().ok_or(NotHeaderEntry)?`): the accessors exist on `HeaderFile` and its `KeyStoreFile` subclass only; the multi-file `type(file) is HeaderFile` gate (`__main__.py:193`,`:195`) is `cmds/extract.rs:219` (#100). |
//! | REQ-5 (typed panic-free errors) | SHIPPED | `ExtractError` at `extract.rs:48` (`NotHeaderEntry` + `Body(#[from] BodyError)`); no unwrap/expect/panic on the production path (R-CODE-2). |
//! | REQ-6 (CLI `extract` consumer) | SHIPPED | `cmds/extract.rs` binds all three ops (`:143`/`:154`/`:162`/`:221`/`:251`) with the image `opened.blob`, dispatched `main.rs:82` (`-X`) / `:129` (`Command::Extract`). Boundary CLI surface (R-DEFER-1). |
//! | REQ-7 (`-u`/`-c` envelope parity) | SHIPPED | `extract_decompressed` returns `get_signed_bytes()` (`header ++ decrypted-decompressed[..0x100+size_signed]`, `header_file.py:168-170`; a `KeyStoreFile`'s `header ++ key_store`, `key_store_file.py:50-51`); `extract_decrypted` assembles `to_decrypted_file_bytes()` (`header(enc+IV cleared) ++ get_decrypted_body() ++ signature`, `header_file.py:278-284`). Consumer `cmds/extract.rs:143`/`:154` (single-file `-u`/`-c`, with the not-compressed/not-encrypted guards mirroring `__main__.py:170`/`:174`). Pins `divergence_extract_envelope.rs` (both `#[test]`, green); live byte parity with the reference CLI in `psptool-cli/tests/extract_oracle.rs`. |

use psptool_core::entry::HEADER_FILE_LEN;
use psptool_core::{BodyError, Entry, EntryClass, HeaderEntry, Ikek, SourceBytes};
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

/// `File.get_bytes()` — the reference raw `-X` output (`__main__.py:180`,
/// `:200`).
///
/// For a HeaderFile-class entry that is its buffer re-sized to the header's
/// `rom_size` (`header_file.py:72-75`, `:104-105`), which can run past the
/// directory entry into `blob` — the image `entry` was parsed from — or stop
/// short of it; every other entry is its body verbatim
/// ([`Entry::file_bytes`]). Allocates a fresh `Vec<u8>` so callers can write
/// it to disk without holding the parser's source-byte borrow.
pub fn extract_raw(entry: &Entry, blob: &SourceBytes) -> Vec<u8> {
    entry.file_bytes(blob).as_bytes().to_vec()
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
/// A zlib stream that fails to inflate leaves the still-compressed body in the
/// envelope, as upstream's does (`header_file.py:182-185`). A `KeyStoreFile`
/// ([`EntryClass::KeyStore`]) overrides the envelope: its `get_signed_bytes()`
/// is `header(0x100) ++ key_store` (`key_store_file.py:50-51`,
/// [`HeaderEntry::get_key_store_signed_bytes`]).
///
/// `blob` is the image `entry` was parsed from: the accessor reads the
/// HeaderFile buffer, re-sized to the header's `rom_size`, which reads on into
/// the image when `rom_size` outgrows the directory size
/// ([`Entry::header_file_window`], `header_file.py:72-75`).
///
/// Returns an error when the entry is not a `HeaderFile`
/// ([`ExtractError::NotHeaderEntry`]). The `not-compressed` guard that upstream
/// applies before this accessor (`__main__.py:170`) lives in the CLI arg layer
/// (`crates/psptool-cli/src/cmds/extract.rs`), not here — `get_signed_bytes`
/// itself is defined for both compressed and uncompressed HeaderFiles.
pub fn extract_decompressed(entry: &Entry, blob: &SourceBytes) -> Result<Vec<u8>, ExtractError> {
    let (header, file) = header_file(entry, blob)?;
    let out = match &entry.class {
        // `KeyStoreFile` overrides `get_signed_bytes()` with `header ++
        // key_store` (`key_store_file.py:50-51`).
        EntryClass::KeyStore(_) => {
            header.get_key_store_signed_bytes(file.as_bytes(), Ikek::ZenPlus)?
        }
        _ => header.get_signed_bytes(file.as_bytes(), Some(Ikek::ZenPlus))?,
    };
    Ok(out)
}

/// The [`HeaderEntry`] of `entry` and the HeaderFile buffer it describes
/// ([`Entry::header_file_window`]).
fn header_file<'a>(
    entry: &'a Entry,
    blob: &SourceBytes,
) -> Result<(&'a HeaderEntry, SourceBytes), ExtractError> {
    let header = entry.class.header().ok_or(ExtractError::NotHeaderEntry)?;
    let file = entry
        .header_file_window(blob)
        .ok_or(ExtractError::NotHeaderEntry)?;
    Ok((header, file))
}

/// `HeaderFile.to_decrypted_file_bytes()` — the reference single-file `-X -c`
/// output (`__main__.py:176`).
///
/// Emits the upstream envelope, **not** the bare decrypted body: a copy of the
/// `0x100` header with `[0x18:0x1c]` (is_encrypted) and `[0x20:0x30]` (IV)
/// cleared, then `get_decrypted_body()`, then the trailing signature
/// (`header_file.py:176-182`). `signature_bytes` returns empty for unsigned
/// HeaderFiles (per #83), so no `is_signed` conditional is needed here. Like
/// [`extract_decompressed`], it reads the `rom_size` HeaderFile buffer of
/// `blob`, the image `entry` was parsed from.
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
pub fn extract_decrypted(
    entry: &Entry,
    blob: &SourceBytes,
    ikek: Ikek,
) -> Result<Vec<u8>, ExtractError> {
    let (header, file) = header_file(entry, blob)?;
    let body = file.as_bytes();
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
        psp_dir_with_sized_entry(entry_type, body.len() as u32, body)
    }

    /// [`psp_dir_with_entry`] with a directory-declared `size` that may stop
    /// short of `file`: the bytes past `size` lie in the image, outside the
    /// entry.
    fn psp_dir_with_sized_entry(entry_type: u8, size: u32, file: &[u8]) -> Vec<u8> {
        use psptool_core::directory::{DIRECTORY_HEADER_SIZE, PSP_ENTRY_SIZE};
        let body_off = (DIRECTORY_HEADER_SIZE + PSP_ENTRY_SIZE) as u32;
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
        out.extend_from_slice(file);
        out
    }

    /// The image and its single parsed entry.
    fn parse_single_psp_entry(blob_bytes: Vec<u8>) -> (SourceBytes, Entry) {
        let blob = SourceBytes::from_blob(blob_bytes);
        let dir = match Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
            Directory::Psp(p) => p,
            _ => unreachable!(),
        };
        let entry = Entry::parse_psp(&blob, &dir, 0, RomSize::MIB_16, FlashOffset::ZERO).unwrap();
        (blob, entry)
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
        let (blob, entry) = parse_single_psp_entry(blob_bytes);
        assert!(matches!(entry.class, EntryClass::Plain));

        let out = extract_raw(&entry, &blob);
        assert_eq!(out, body);
    }

    #[test]
    fn extract_raw_returns_body_bytes_verbatim_for_header_entry() {
        let body = psptool_fixtures::micro::header_signed().to_vec();
        let blob_bytes = psp_dir_with_entry(0x01, &body); // PSP_FW_BOOT_LOADER → Header
        let (blob, entry) = parse_single_psp_entry(blob_bytes);
        assert!(matches!(entry.class, EntryClass::Header(_)));

        let out = extract_raw(&entry, &blob);
        assert_eq!(out, body);
    }

    #[test]
    fn extract_raw_of_a_header_entry_is_its_rom_size_buffer() {
        // `File.get_bytes()` of a HeaderFile is its buffer re-sized to
        // `rom_size` (`header_file.py:72-75`, `:104-105`), not the directory
        // entry: a directory size short of `rom_size` reads on into the image,
        // one past it stops at `rom_size` (#101).
        let file = psptool_fixtures::micro::header_signed().to_vec(); // rom_size 0x210
        let mut image = file.clone();
        image.extend_from_slice(&[0xEE; 0x40]);
        for size in [0, 0x110, 0x250] {
            let (blob, entry) =
                parse_single_psp_entry(psp_dir_with_sized_entry(0x01, size, &image));
            assert_eq!(entry.body.len(), size as usize);
            assert_eq!(extract_raw(&entry, &blob), file, "directory size {size:#x}");
        }
    }

    #[test]
    fn extract_raw_independent_of_class_works_on_pubkey() {
        let body = psptool_fixtures::micro::pubkey_v1().to_vec();
        let blob_bytes = psp_dir_with_entry(0x00, &body); // AMD_PUBLIC_KEY → Pubkey
        let (blob, entry) = parse_single_psp_entry(blob_bytes);
        assert!(matches!(entry.class, EntryClass::Pubkey(_)));

        let out = extract_raw(&entry, &blob);
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
        let (blob, entry) = parse_single_psp_entry(blob_bytes);
        assert!(matches!(entry.class, EntryClass::Header(_)));

        let mut expected = entry.body.as_bytes()[..HEADER_FILE_LEN].to_vec();
        expected.extend_from_slice(b"hello, psptool-rs");

        let out = extract_decompressed(&entry, &blob).ok();
        assert_eq!(out, Some(expected));
    }

    #[test]
    fn extract_decompressed_errors_for_non_header_entry() {
        let body = vec![0xAAu8; 0x10];
        let blob_bytes = psp_dir_with_entry(0x21, &body); // Plain
        let (blob, entry) = parse_single_psp_entry(blob_bytes);
        assert!(matches!(entry.class, EntryClass::Plain));

        let err = extract_decompressed(&entry, &blob).unwrap_err();
        assert!(matches!(err, ExtractError::NotHeaderEntry));
    }

    #[test]
    fn extract_decompressed_errors_for_pubkey_entry() {
        let body = psptool_fixtures::micro::pubkey_v1().to_vec();
        let blob_bytes = psp_dir_with_entry(0x00, &body);
        let (blob, entry) = parse_single_psp_entry(blob_bytes);

        let err = extract_decompressed(&entry, &blob).unwrap_err();
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
        let (blob, entry) = parse_single_psp_entry(blob_bytes);
        assert!(matches!(entry.class, EntryClass::Header(_)));

        let mut expected = entry.body.as_bytes()[..HEADER_FILE_LEN].to_vec();
        expected.extend_from_slice(DATA);

        let out = extract_decompressed(&entry, &blob).ok();
        assert_eq!(out, Some(expected));
    }

    #[test]
    fn extract_decompressed_reads_the_rom_size_buffer_past_the_directory_size() {
        // `header_file.py:74-75`: a header `rom_size` past the directory size
        // grows the HeaderFile buffer, reading on into the image (#99). The
        // directory covers the header and 0x10 stream bytes; the rest of the
        // stream and the signature follow in the image.
        let size_signed: u32 = 17;
        let file = build_compressed_signed_body(size_signed);
        let blob_bytes = psp_dir_with_sized_entry(0x01, 0x110, &file);
        let (blob, entry) = parse_single_psp_entry(blob_bytes);
        assert_eq!(entry.body.len(), 0x110);
        assert!(
            entry
                .class
                .header()
                .is_some_and(|h| h.rom_size as usize == file.len())
        );

        let mut expected = file[..HEADER_FILE_LEN].to_vec();
        expected.extend_from_slice(b"hello, psptool-rs");
        assert_eq!(extract_decompressed(&entry, &blob).ok(), Some(expected));
    }

    // -- extract_decrypted ---------------------------------------------------

    #[test]
    fn extract_decrypted_reads_the_rom_size_buffer_past_the_directory_size() {
        // As above for `-c` (#99): the decrypted body and the signature come
        // from the `rom_size` buffer, past the directory size.
        let plaintext = b"sixteen bytes !!";
        let file = build_encrypted_header_body(plaintext, [0xA5u8; 16], Ikek::ZenPlus);
        let blob_bytes = psp_dir_with_sized_entry(0x01, 0x110, &file);
        let (blob, entry) = parse_single_psp_entry(blob_bytes);
        assert_eq!(entry.body.len(), 0x110);

        let mut expected = file[..HEADER_FILE_LEN].to_vec();
        expected[0x18..0x1C].fill(0);
        expected[0x20..0x30].fill(0);
        expected.extend_from_slice(plaintext);
        expected.extend_from_slice(&file[file.len() - 0x100..]);
        assert_eq!(
            extract_decrypted(&entry, &blob, Ikek::ZenPlus).ok(),
            Some(expected)
        );
    }

    #[test]
    fn extract_decrypted_returns_to_decrypted_file_bytes_envelope() {
        let plaintext = b"sixteen bytes !!"; // 16 bytes (one AES block)
        let entry_key = [0xA5u8; 16];
        let body = build_encrypted_header_body(plaintext, entry_key, Ikek::ZenPlus);
        let blob_bytes = psp_dir_with_entry(0x01, &body); // Header-class
        let (blob, entry) = parse_single_psp_entry(blob_bytes);
        assert!(entry.class.header().is_some_and(|h| h.is_encrypted));

        // Upstream to_decrypted_file_bytes (`header_file.py:176-182`): header
        // with is_encrypted (0x18..0x1c) and IV (0x20..0x30) cleared, then the
        // decrypted body, then the trailing signature.
        let mut expected = entry.body.as_bytes()[..HEADER_FILE_LEN].to_vec();
        expected[0x18..0x1C].fill(0);
        expected[0x20..0x30].fill(0);
        expected.extend_from_slice(plaintext);
        expected.extend(std::iter::repeat_n(0u8, 0x100)); // signature placeholder

        let out = extract_decrypted(&entry, &blob, Ikek::ZenPlus).ok();
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
        let (blob, entry) = parse_single_psp_entry(blob_bytes);
        let header = entry.class.header().expect("header entry");
        assert!(header.is_encrypted);

        let out = extract_decrypted(&entry, &blob, Ikek::ZenPlus).expect("decrypt succeeds");
        // The committed fixture's plaintext is non-empty and matches the
        // declared data-region length (one AES block multiple).
        assert!(!out.is_empty());
        assert!(out.len().is_multiple_of(16));
    }

    #[test]
    fn extract_decrypted_errors_for_non_header_entry() {
        let body = vec![0xAAu8; 0x10];
        let blob_bytes = psp_dir_with_entry(0x21, &body); // Plain
        let (blob, entry) = parse_single_psp_entry(blob_bytes);

        let err = extract_decrypted(&entry, &blob, Ikek::ZenPlus).unwrap_err();
        assert!(matches!(err, ExtractError::NotHeaderEntry));
    }

    #[test]
    fn extract_decrypted_errors_for_pubkey_entry() {
        let body = psptool_fixtures::micro::pubkey_v1().to_vec();
        let blob_bytes = psp_dir_with_entry(0x00, &body); // Pubkey
        let (blob, entry) = parse_single_psp_entry(blob_bytes);

        let err = extract_decrypted(&entry, &blob, Ikek::ZenPlus).unwrap_err();
        assert!(matches!(err, ExtractError::NotHeaderEntry));
    }

    #[test]
    fn extract_decrypted_errors_when_header_not_encrypted() {
        let body = psptool_fixtures::micro::header_signed().to_vec();
        let blob_bytes = psp_dir_with_entry(0x01, &body);
        let (blob, entry) = parse_single_psp_entry(blob_bytes);

        let err = extract_decrypted(&entry, &blob, Ikek::ZenPlus).unwrap_err();
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
        let (blob, entry) = parse_single_psp_entry(blob_bytes);

        let mut expected_right = entry.body.as_bytes()[..HEADER_FILE_LEN].to_vec();
        expected_right[0x18..0x1C].fill(0);
        expected_right[0x20..0x30].fill(0);
        expected_right.extend_from_slice(plaintext);
        expected_right.extend(std::iter::repeat_n(0u8, 0x100));

        let wrong = extract_decrypted(&entry, &blob, Ikek::Zen).ok();
        let right = extract_decrypted(&entry, &blob, Ikek::ZenPlus).ok();
        assert_eq!(right, Some(expected_right));
        assert_ne!(wrong, right);
    }

    // -- KeyStore: `KeyStoreFile.get_signed_bytes()` -------------------------

    #[test]
    fn extract_decompressed_of_a_compressed_key_store_is_header_plus_key_store() {
        // Type 0x50 → KeyStore. `KeyStoreFile.get_signed_bytes()` is
        // `header ++ key_store` (`key_store_file.py:50-51`), the store being
        // the inflated body cut to `size_uncompressed` (`:39-40`) — 5 bytes
        // here — not the HeaderFile envelope cut to `size_signed` (17).
        let mut body = build_compressed_signed_body(17);
        body[0x50..0x54].copy_from_slice(&5u32.to_le_bytes()); // size_uncompressed
        let blob_bytes = psp_dir_with_entry(0x50, &body);
        let (blob, entry) = parse_single_psp_entry(blob_bytes);
        assert!(matches!(entry.class, EntryClass::KeyStore(_)));

        let mut expected = body[..HEADER_FILE_LEN].to_vec();
        expected.extend_from_slice(b"hello");
        assert_eq!(extract_decompressed(&entry, &blob).ok(), Some(expected));
    }

    #[test]
    fn extract_decompressed_of_a_raw_key_store_is_header_plus_body_size_bytes() {
        // Uncompressed: the key store is the `body_size` (`0x14`) bytes after
        // the header (`key_store_file.py:41-42`), whatever `rom_size` says.
        let mut h = [0u8; HEADER_FILE_LEN];
        h[0x10..0x14].copy_from_slice(b"$PS1");
        h[0x14..0x18].copy_from_slice(&0x20u32.to_le_bytes()); // body_size
        h[0x30..0x34].copy_from_slice(&1u32.to_le_bytes());
        h[0x34..0x38].copy_from_slice(&2u32.to_le_bytes()); // RSA-4096
        h[0x6C..0x70].copy_from_slice(&((HEADER_FILE_LEN + 0x20 + 0x200) as u32).to_le_bytes());
        let mut file = h.to_vec();
        file.extend((0..0x20).map(|i| i as u8));
        file.extend(std::iter::repeat_n(0xCCu8, 0x200));
        let (blob, entry) = parse_single_psp_entry(psp_dir_with_entry(0x50, &file));
        assert!(matches!(entry.class, EntryClass::KeyStore(_)));

        let expected = file[..HEADER_FILE_LEN + 0x20].to_vec();
        assert_eq!(extract_decompressed(&entry, &blob).ok(), Some(expected));

        // A `body_size` past the file: upstream's `KeyStore` buffer cannot be
        // cut (`utils.py:46-47`); a typed error here.
        let mut overlong = file.clone();
        overlong[0x14..0x18].copy_from_slice(&0x1000u32.to_le_bytes());
        let (blob, entry) = parse_single_psp_entry(psp_dir_with_entry(0x50, &overlong));
        assert!(matches!(
            extract_decompressed(&entry, &blob),
            Err(ExtractError::Body(BodyError::KeyStoreTruncated {
                available: 0x320,
                needed: 0x1100
            }))
        ));
    }
}
