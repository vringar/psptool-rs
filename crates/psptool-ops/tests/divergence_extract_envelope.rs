//! Divergence pins for the single-file `-X -u` / `-X -c` output ENVELOPE
//! (blocker #88, design REQ-7 of `.design/psptool-ops/extract.md`).
//!
//! The `psptool-ops` extract ops return only the BARE inflated / decrypted
//! body. The reference tool's single-file extract path
//! (`/tmp/psptool-ref/psptool/__main__.py:167-180`) wraps those bytes in a
//! header-prefixed (and, for `-u`, `size_signed`-truncated) envelope:
//!
//! `-X -u` (`__main__.py:169-172`) is `output = file.get_signed_bytes()`
//! (`get_signed_bytes`, `header_file.py:162-164`): the `0x100` header
//! concatenated with `get_decrypted_decompressed_body()`, truncated to
//! `0x100 + size_signed`.
//!
//! Single-file `-X -c` (`__main__.py:173-176`) is `output =
//! file.to_decrypted_file_bytes()` (`to_decrypted_file_bytes`,
//! `header_file.py:176-182`): a copy of the `0x100` header with `[0x18:0x1c]`
//! (is_encrypted) and `[0x20:0x30]` (IV) cleared, then `get_decrypted_body()`,
//! then `signature` when `is_signed`.
//!
//! Upstream inconsistency captured for the eventual fixer: the MULTI-file
//! path uses a DIFFERENT `-c` accessor — `file.get_decrypted_body()`
//! (`__main__.py:195-196`, `:218-219`), i.e. the bare body with NO header
//! and NO signature. Our extract ops back the SINGLE-file CLI path
//! (`crates/psptool-cli/src/cmds/extract.rs:127-129`), so the contract to
//! match is: `-u` -> `get_signed_bytes()`, `-c` -> `to_decrypted_file_bytes()`.
//!
//! Both tests are `#[ignore]`d pending #88; run with `--ignored` to observe
//! the pinned failure. The expected values are constructed from the upstream
//! algorithm above (header slice + a plaintext constant traceable to
//! `crates/psptool-fixtures/examples/build_fixtures.rs:352` + a caller-chosen
//! `size_signed`) — never copied from the `psptool-ops` side (R-CHAR-3).

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit, block_padding::NoPadding};
use psptool_core::directory::{DIRECTORY_HEADER_SIZE, PSP_ENTRY_SIZE};
use psptool_core::entry::HEADER_FILE_LEN;
use psptool_core::{Directory, Entry, EntryClass, FlashOffset, Ikek, RomSize, SourceBytes};
use psptool_ops::{extract_decompressed, extract_decrypted};

/// The plaintext the committed `header_compressed` micro-fixture inflates to,
/// declared as `PLAINTEXT` in `build_fixtures.rs:352`. Symbolic constant, NOT
/// derived from the target side.
const FIXTURE_PLAINTEXT: &[u8] = b"hello, psptool-rs";

/// RSA-2048 signature length (`signature_type == 0`) — `header_file.py:78-79`.
const SIG_LEN: usize = 0x100;

// -- Entry-construction plumbing (mirrors extract.rs unit-test helpers) ------

/// Wrap `body` as the single entry of a `$PSP` directory addressed via mode
/// `10` (offset from directory header), then parse it end-to-end.
fn psp_dir_with_entry(entry_type: u8, body: &[u8]) -> Vec<u8> {
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
        _ => unreachable!("fixture is a $PSP directory"),
    };
    Entry::parse_psp(&blob, &dir, 0, RomSize::MIB_16, FlashOffset::ZERO).unwrap()
}

/// Build a compressed + signed (not encrypted) HeaderFile body wrapping the
/// committed `header_compressed` zlib stream, with a caller-chosen
/// header-EXCLUSIVE `size_signed` (the fixed convention, `body.rs:374-376`).
/// Returns `(body_bytes, size_signed)`.
fn build_compressed_signed_body(size_signed: u32) -> (Vec<u8>, u32) {
    let fixture = psptool_fixtures::micro::header_compressed();
    // `zlib_size` (header +0x54) is the stream length; the stream sits right
    // after the 0x100 header in the committed fixture.
    let zlib_size = u32::from_le_bytes(fixture[0x54..0x58].try_into().unwrap()) as usize;
    let stream = &fixture[HEADER_FILE_LEN..HEADER_FILE_LEN + zlib_size];

    let rom_size = (HEADER_FILE_LEN + zlib_size + SIG_LEN) as u32;
    let mut h = [0u8; HEADER_FILE_LEN];
    h[0x10..0x14].copy_from_slice(b"$PS1");
    h[0x14..0x18].copy_from_slice(&size_signed.to_le_bytes()); // header-exclusive
    // is_encrypted (0x18) stays 0.
    h[0x30..0x34].copy_from_slice(&1u32.to_le_bytes()); // is_signed
    h[0x34..0x38].copy_from_slice(&0u32.to_le_bytes()); // signature_type = RSA-2048
    h[0x48..0x4C].copy_from_slice(&1u32.to_le_bytes()); // is_compressed
    h[0x50..0x54].copy_from_slice(&(FIXTURE_PLAINTEXT.len() as u32).to_le_bytes()); // size_uncompressed
    h[0x54..0x58].copy_from_slice(&(zlib_size as u32).to_le_bytes()); // zlib_size
    h[0x6C..0x70].copy_from_slice(&rom_size.to_le_bytes());

    let mut body = Vec::with_capacity(HEADER_FILE_LEN + zlib_size + SIG_LEN);
    body.extend_from_slice(&h);
    body.extend_from_slice(stream);
    body.extend(std::iter::repeat_n(0xBBu8, SIG_LEN)); // signature placeholder
    (body, size_signed)
}

/// Build an encrypted + signed (not compressed) HeaderFile body with a known
/// plaintext, entry key, and a recognizable signature placeholder. Returns
/// `(body_bytes, plaintext, iv, signature_placeholder)`.
fn build_encrypted_signed_body(
    plaintext: &[u8],
    entry_key: [u8; 16],
    ikek: Ikek,
) -> (Vec<u8>, [u8; 16], [u8; SIG_LEN]) {
    use cbc::Encryptor as CbcEnc;
    type Aes128CbcEnc = CbcEnc<Aes128>;
    assert!(plaintext.len().is_multiple_of(16));

    let iv = [
        0x10u8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F,
    ];
    // wrapped_key = AES-128-ECB-encrypt(entry_key, ikek).
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

    let rom_size = (HEADER_FILE_LEN + plaintext.len() + SIG_LEN) as u32;
    let mut h = [0u8; HEADER_FILE_LEN];
    h[0x10..0x14].copy_from_slice(b"$PS1");
    h[0x14..0x18].copy_from_slice(&(plaintext.len() as u32).to_le_bytes()); // size_signed (header-exclusive)
    h[0x18..0x1C].copy_from_slice(&1u32.to_le_bytes()); // is_encrypted
    h[0x20..0x30].copy_from_slice(&iv);
    h[0x30..0x34].copy_from_slice(&1u32.to_le_bytes()); // is_signed
    h[0x34..0x38].copy_from_slice(&0u32.to_le_bytes()); // signature_type = RSA-2048
    h[0x6C..0x70].copy_from_slice(&rom_size.to_le_bytes());
    h[0x80..0x90].copy_from_slice(&wrapped);

    let mut sig = [0u8; SIG_LEN];
    for (i, b) in sig.iter_mut().enumerate() {
        *b = 0x77u8.wrapping_add(i as u8);
    }

    let mut body = Vec::with_capacity(HEADER_FILE_LEN + plaintext.len() + SIG_LEN);
    body.extend_from_slice(&h);
    body.extend_from_slice(&buf);
    body.extend_from_slice(&sig);
    (body, iv, sig)
}

// ---------------------------------------------------------------------------

/// Divergence: `psptool_ops::extract_decompressed` diverges from the reference
/// single-file `-X -u` accessor `file.get_signed_bytes()`
/// (`/tmp/psptool-ref/psptool/__main__.py:172`,
/// `/tmp/psptool-ref/psptool/header_file.py:162-164`).
///
/// Input: a compressed+signed HeaderFile whose data region inflates to
/// `b"hello, psptool-rs"`, with `size_signed = 10`.
/// Upstream returns `header(0x100) ++ inflated[..10]` (length 0x10A).
/// Target returns the bare inflated body `b"hello, psptool-rs"` (length 17,
/// no header prefix, no `size_signed` truncation).
///
/// Tracking: #88.
#[test]
#[ignore = "divergence: extract_decompressed returns bare inflated body, not get_signed_bytes envelope; tracking #88"]
fn divergence_decompress_envelope_matches_get_signed_bytes() {
    let size_signed: u32 = 10;
    let (body, _ss) = build_compressed_signed_body(size_signed);
    let blob = psp_dir_with_entry(0x01, &body); // PSP_FW_BOOT_LOADER -> Header
    let entry = parse_single_psp_entry(blob);
    assert!(matches!(entry.class, EntryClass::Header(_)));

    // Upstream get_signed_bytes: header(0x100) ++ decrypted-decompressed-body,
    // truncated to 0x100 + size_signed. Not encrypted => decrypted-decompressed
    // body == inflated == FIXTURE_PLAINTEXT.
    let header = &entry.body.as_bytes()[..HEADER_FILE_LEN];
    let mut expected = Vec::with_capacity(HEADER_FILE_LEN + size_signed as usize);
    expected.extend_from_slice(header);
    expected.extend_from_slice(&FIXTURE_PLAINTEXT[..size_signed as usize]);

    let got = extract_decompressed(&entry).expect("decompress succeeds");
    assert_eq!(
        got, expected,
        "extract_decompressed must equal upstream get_signed_bytes() \
         (header-prefixed, size_signed-truncated); it returns the bare body"
    );
}

/// Divergence: `psptool_ops::extract_decrypted` diverges from the reference
/// single-file `-X -c` accessor `file.to_decrypted_file_bytes()`
/// (`/tmp/psptool-ref/psptool/__main__.py:176`,
/// `/tmp/psptool-ref/psptool/header_file.py:176-182`).
///
/// Input: an encrypted+signed HeaderFile with a 16-byte known plaintext.
/// Upstream returns `header(is_encrypted+IV cleared) ++ decrypted-body ++
/// signature` (length 0x210). Target returns the bare decrypted body (length
/// 16, no header prefix, no cleared flags, no signature).
///
/// Tracking: #88.
#[test]
#[ignore = "divergence: extract_decrypted returns bare decrypted body, not to_decrypted_file_bytes envelope; tracking #88"]
fn divergence_decrypt_envelope_matches_to_decrypted_file_bytes() {
    let plaintext = b"sixteen bytes !!"; // 16 bytes (one AES block)
    let entry_key = [0xA5u8; 16];
    let (body, _iv, sig) = build_encrypted_signed_body(plaintext, entry_key, Ikek::ZenPlus);
    let blob = psp_dir_with_entry(0x01, &body); // Header-class
    let entry = parse_single_psp_entry(blob);
    let hdr = entry.class.header().expect("header entry");
    assert!(hdr.is_encrypted);

    // Upstream to_decrypted_file_bytes: header with is_encrypted (0x18..0x1c)
    // and IV (0x20..0x30) zeroed, then decrypted body, then signature.
    let mut expected_header = entry.body.as_bytes()[..HEADER_FILE_LEN].to_vec();
    expected_header[0x18..0x1C].fill(0); // clear is_encrypted (header_file.py:179)
    expected_header[0x20..0x30].fill(0); // clear IV (header_file.py:180)
    let mut expected = Vec::with_capacity(HEADER_FILE_LEN + plaintext.len() + SIG_LEN);
    expected.extend_from_slice(&expected_header);
    expected.extend_from_slice(plaintext); // get_decrypted_body()
    expected.extend_from_slice(&sig); // self.signature.get_bytes()

    let got = extract_decrypted(&entry, Ikek::ZenPlus).expect("decrypt succeeds");
    assert_eq!(
        got, expected,
        "extract_decrypted must equal upstream to_decrypted_file_bytes() \
         (cleared-header prefix + decrypted body + signature); it returns the bare body"
    );
}
