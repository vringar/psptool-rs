//! Decode verification: the `HeaderFile._verify_decode` ladder port
//! (`psptool_core::body`, upstream PSPTool `241629b`, `header_file.py:191-276`)
//! and its `ls` wiring (`psptool_ops::list_json` / `list_default`,
//! `psptool.py:116-140` File-Info tags and `:267-271` JSON keys).
//!
//! The synthetic tests build an 8 MiB image (the smallest layout
//! `detect_rom_layout` accepts) whose `$PSP` directory holds real RSA-PSS
//! signed entries, so every ladder rung is reached through the same
//! `CertifyingKeys::from_blob` -> `Entry::decode_verification` path `ls` uses.
//! Expected labels and tags are upstream's string literals
//! (`header_file.py:226-243`, `psptool.py:119-139`), never read back from the
//! Rust side.
//!
//! The corpus test pins the per-basis tally over `vendor/test-corpus` against
//! an oracle run of upstream `241629b` (see [`UPSTREAM_TALLY`]).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use aes::Aes128;
use aes::cipher::block_padding::NoPadding;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit};
use psptool_core::body::{
    CertifyingKeys, ChecksumCheck, DecodeBasis, DecodeVerification, SignatureCheck,
};
use psptool_core::fet::{FET_MAGIC_SIZE, FET_SLOT_SIZE, FET_TERMINATOR_SIZE};
use psptool_core::magic::FET_MAGIC;
use psptool_core::{
    Directory, Entry, FlashOffset, Ikek, RomLayout, SourceBytes, detect_rom_layout,
    scan_fet_candidates, walk_directories,
};
use psptool_fixtures::corpus_rom_paths;
use psptool_ops::{RomListing, list_default, list_json};
use rand::SeedableRng;
use rand::rngs::StdRng;
use rsa::RsaPrivateKey;
use rsa::pss::SigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Synthetic image builder
// ---------------------------------------------------------------------------

/// Smallest ROM `detect_rom_layout` accepts (8 MiB).
const ROM_LEN: usize = 0x80_0000;
/// FET at the first `KNOWN_FET_OFFSETS` slot, preceded by zero padding so
/// `scan_fet_candidates` finds it.
const FET_OFF: usize = 0x2_0000;
const DIR_OFF: usize = 0x2_1000;
const FIRST_BODY: usize = 0x3_0000;
const HEADER_LEN: usize = 0x100;
/// RSA-2048 signature length (`signature_type == 0`, `header_file.py:84-85`).
const SIG_LEN: usize = 0x100;

/// Certifying key id of the directory `PubkeyFile`.
const KEY_A: [u8; 16] = [0xA1; 16];
/// Certifying key id present only inside a `$KDB` key store.
const KEY_B: [u8; 16] = [0xB2; 16];
/// Certifying key id no key carries.
const KEY_UNKNOWN: [u8; 16] = [0xDE; 16];

const ENTRY_KEY: [u8; 16] = [0x5A; 16];
const IV: [u8; 16] = [0x1F; 16];

fn signing_key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut rng = StdRng::seed_from_u64(0x5EED_0089_DEC0_DE00);
        RsaPrivateKey::new(&mut rng, 2048).expect("generate 2048-bit test key")
    })
}

/// RSA-PSS/SHA-256 over `message`, on-disk (plain big-endian) form.
fn sign(message: &[u8]) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(0x0089_0076);
    SigningKey::<Sha256>::new(signing_key().clone())
        .sign_with_rng(&mut rng, message)
        .to_bytes()
        .to_vec()
}

/// Little-endian 256-byte modulus of the test key.
fn modulus_le() -> Vec<u8> {
    let mut n = signing_key().to_public_key().n().to_bytes_le();
    n.resize(0x100, 0);
    n
}

/// `[0x40 header | pubexp(0x100) | modulus(0x100)]` PubkeyFile, self-certified.
fn pubkey_file(key_id: [u8; 16]) -> Vec<u8> {
    let mut buf = vec![0u8; 0x40 + 0x200];
    buf[0x00..0x04].copy_from_slice(&1u32.to_le_bytes());
    buf[0x04..0x14].copy_from_slice(&key_id);
    buf[0x14..0x24].copy_from_slice(&key_id);
    buf[0x38..0x3C].copy_from_slice(&2048u32.to_le_bytes());
    buf[0x3C..0x40].copy_from_slice(&2048u32.to_le_bytes());
    let mut e = signing_key().to_public_key().e().to_bytes_le();
    e.resize(0x100, 0);
    buf[0x40..0x140].copy_from_slice(&e);
    buf[0x140..0x240].copy_from_slice(&modulus_le());
    buf
}

/// A `$KDB` key store holding the test key under `key_id`
/// (`key_store_file.py:144-231` layout: 0x50-byte store header, then one
/// 0x50-byte key header + 0x100-byte little-endian modulus).
fn kdb(key_id: [u8; 16]) -> Vec<u8> {
    let key_len = 0x50 + 0x100;
    let mut store = vec![0u8; 0x50 + key_len];
    let total = store.len() as u32;
    store[0x00..0x04].copy_from_slice(&total.to_le_bytes());
    store[0x04..0x08].copy_from_slice(&1u32.to_le_bytes());
    store[0x08..0x0C].copy_from_slice(b"$KDB");
    let k = 0x50;
    store[k..k + 4].copy_from_slice(&(key_len as u32).to_le_bytes());
    store[k + 0x04..k + 0x08].copy_from_slice(&1u32.to_le_bytes());
    store[k + 0x0C..k + 0x10].copy_from_slice(&0x10001u32.to_le_bytes());
    store[k + 0x10..k + 0x20].copy_from_slice(&key_id);
    store[k + 0x20..k + 0x24].copy_from_slice(&2048u32.to_le_bytes());
    store[k + 0x50..].copy_from_slice(&modulus_le());
    store
}

/// A KeyStoreFile (`type 0x50`) wrapping `store`: header `body_size` (`0x14`),
/// the `(1, 2)` constants (`key_store_file.py:84-86`), certifying id
/// `KEY_UNKNOWN`, packed size (`0x6c`), and a zero 0x200-byte signature.
fn key_store_file(store: &[u8]) -> Vec<u8> {
    let mut h = [0u8; HEADER_LEN];
    h[0x10..0x14].copy_from_slice(b"$PS1");
    h[0x14..0x18].copy_from_slice(&(store.len() as u32).to_le_bytes());
    h[0x30..0x34].copy_from_slice(&1u32.to_le_bytes());
    h[0x34..0x38].copy_from_slice(&2u32.to_le_bytes());
    h[0x38..0x48].copy_from_slice(&KEY_UNKNOWN);
    let packed = (HEADER_LEN + store.len() + 0x200) as u32;
    h[0x6C..0x70].copy_from_slice(&packed.to_le_bytes());
    h[0x7C..0x80].copy_from_slice(&0x50u32.to_le_bytes());
    let mut out = h.to_vec();
    out.extend_from_slice(store);
    out.extend(std::iter::repeat_n(0u8, 0x200));
    out
}

/// One stored (uncompressed) deflate block in a zlib wrapper — RFC 1950/1951,
/// magic `78 01` (`utils.py:213`, "Zlib header, no compression").
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

/// A 16-aligned payload free of `0x78` so no zlib magic appears by accident.
fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| 0x20 + (i % 0x50) as u8).collect()
}

/// A HeaderFile body: `region` is the on-disk data region before encryption,
/// `decoded` the body the ladder decodes it to.
#[derive(Clone)]
struct HeaderFile {
    region: Vec<u8>,
    decoded: Vec<u8>,
    certifying_id: Option<[u8; 16]>,
    size_signed: u32,
    sha256: Option<[u8; 32]>,
    compressed: bool,
    zlib_size: u32,
    encrypted: bool,
}

impl HeaderFile {
    /// Unsigned, untransformed `data`.
    fn plain(data: &[u8]) -> Self {
        Self {
            region: data.to_vec(),
            decoded: data.to_vec(),
            certifying_id: None,
            size_signed: data.len() as u32,
            sha256: None,
            compressed: false,
            zlib_size: 0,
            encrypted: false,
        }
    }

    fn signed_by(mut self, id: [u8; 16]) -> Self {
        self.certifying_id = Some(id);
        self
    }

    fn size_signed(mut self, size: u32) -> Self {
        self.size_signed = size;
        self
    }

    /// Stamp the sha256 of the decoded body (or of `over`).
    fn sha256_of(mut self, over: &[u8]) -> Self {
        self.sha256 = Some(Sha256::digest(over).into());
        self
    }

    /// Compressed: `stream` is the zlib region, `decoded` what it inflates to.
    fn compressed(stream: &[u8], zlib_size: usize, decoded: &[u8]) -> Self {
        let mut region = stream.to_vec();
        region.resize(stream.len().div_ceil(16) * 16, 0);
        Self {
            region,
            decoded: decoded.to_vec(),
            certifying_id: None,
            size_signed: decoded.len() as u32,
            sha256: None,
            compressed: true,
            zlib_size: zlib_size as u32,
            encrypted: false,
        }
    }

    /// Encrypted under the Zen+ IKEK when `region` is block-aligned; an
    /// unaligned region is stored raw (it cannot be AES-CBC encrypted).
    fn encrypted(mut self) -> Self {
        self.encrypted = true;
        self
    }

    fn build(&self) -> Vec<u8> {
        let mut h = [0u8; HEADER_LEN];
        h[0x10..0x14].copy_from_slice(b"$PS1");
        h[0x14..0x18].copy_from_slice(&self.size_signed.to_le_bytes());
        let mut region = self.region.clone();
        if self.encrypted {
            h[0x18..0x1C].copy_from_slice(&1u32.to_le_bytes());
            h[0x20..0x30].copy_from_slice(&IV);
            let ikek = Aes128::new(GenericArray::from_slice(&Ikek::ZenPlus.bytes()));
            let mut wrapped = GenericArray::clone_from_slice(&ENTRY_KEY);
            ikek.encrypt_block(&mut wrapped);
            h[0x80..0x90].copy_from_slice(&wrapped);
            if region.len().is_multiple_of(16) {
                let len = region.len();
                cbc::Encryptor::<Aes128>::new_from_slices(&ENTRY_KEY, &IV)
                    .expect("AES-128 key + IV")
                    .encrypt_padded_mut::<NoPadding>(&mut region, len)
                    .expect("block-aligned");
            }
        }
        if let Some(id) = self.certifying_id {
            h[0x30..0x34].copy_from_slice(&1u32.to_le_bytes());
            h[0x38..0x48].copy_from_slice(&id);
        }
        if self.compressed {
            h[0x48..0x4C].copy_from_slice(&1u32.to_le_bytes());
            h[0x54..0x58].copy_from_slice(&self.zlib_size.to_le_bytes());
        }
        if let Some(digest) = self.sha256 {
            // Bitfield at 0x58 is big-endian; bit 0 = sha256 (`header_file.py:55,66`).
            h[0x58..0x5C].copy_from_slice(&1u32.to_be_bytes());
            h[0xD0..0xF0].copy_from_slice(&digest);
        }
        let sig_len = if self.certifying_id.is_some() {
            SIG_LEN
        } else {
            0
        };
        let rom_size = (HEADER_LEN + region.len() + sig_len) as u32;
        h[0x6C..0x70].copy_from_slice(&rom_size.to_le_bytes());

        let mut out = h.to_vec();
        out.extend_from_slice(&region);
        if self.certifying_id.is_some() {
            // `header_file.py:168-170`: (header || decoded)[:0x100 + size_signed].
            let covered = (self.size_signed as usize).min(self.decoded.len());
            let mut message = h.to_vec();
            message.extend_from_slice(&self.decoded[..covered]);
            out.extend_from_slice(&sign(&message));
        }
        out
    }
}

/// An 8 MiB image: FET -> one `$PSP` directory (flash-offset mode) whose
/// entries are the given `(type, body)` pairs.
fn image(entries: &[(u8, Vec<u8>)]) -> SourceBytes {
    let mut rom = vec![0u8; ROM_LEN];
    rom[FET_OFF..FET_OFF + FET_MAGIC_SIZE].copy_from_slice(FET_MAGIC.as_bytes());
    let slot = FET_OFF + FET_MAGIC_SIZE;
    rom[slot..slot + FET_SLOT_SIZE].copy_from_slice(&(DIR_OFF as u32).to_le_bytes());
    let term = slot + FET_SLOT_SIZE;
    rom[term..term + FET_TERMINATOR_SIZE].fill(0xFF);

    rom[DIR_OFF..DIR_OFF + 4].copy_from_slice(b"$PSP");
    rom[DIR_OFF + 8..DIR_OFF + 0xC].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    // v1 additional_info, address mode 01 (flash offset): entry offsets are
    // absolute flash offsets.
    let additional_info = (1u32 << 31) | (0b01u32 << 24);
    rom[DIR_OFF + 0xC..DIR_OFF + 0x10].copy_from_slice(&additional_info.to_le_bytes());

    let mut cursor = FIRST_BODY;
    for (i, (entry_type, body)) in entries.iter().enumerate() {
        let rec = DIR_OFF + 0x10 + i * 0x10;
        rom[rec] = *entry_type;
        rom[rec + 4..rec + 8].copy_from_slice(&(body.len() as u32).to_le_bytes());
        rom[rec + 8..rec + 0xC].copy_from_slice(&(cursor as u32).to_le_bytes());
        rom[cursor..cursor + body.len()].copy_from_slice(body);
        cursor = (cursor + body.len()).next_multiple_of(0x1000);
    }
    SourceBytes::from_blob(rom)
}

fn layout(blob: &SourceBytes) -> RomLayout {
    detect_rom_layout(blob, FlashOffset(FET_OFF as u64)).expect("synthetic layout")
}

/// Every entry's verdict, through the production `from_blob` key map.
fn verdicts(entries: &[(u8, Vec<u8>)]) -> Vec<Option<DecodeVerification>> {
    let blob = image(entries);
    let keys = CertifyingKeys::from_blob(&blob, Ikek::ZenPlus);
    let layout = layout(&blob);
    let dirs = walk_directories(&blob, &layout.fet, layout.rom_size, layout.rom_origin);
    let Directory::Psp(dir) = &dirs[0].directory else {
        panic!("synthetic image must walk to a $PSP directory");
    };
    (0..dir.entries.len())
        .map(|i| {
            Entry::parse_psp(&blob, dir, i, layout.rom_size, layout.rom_origin)
                .expect("synthetic entry parses")
                .decode_verification(&blob, &keys, Ikek::ZenPlus)
        })
        .collect()
}

/// Verdict of the last entry (the subject; earlier entries supply keys).
fn verdict(entries: &[(u8, Vec<u8>)]) -> DecodeVerification {
    verdicts(entries)
        .pop()
        .flatten()
        .expect("subject is a HeaderFile-class entry")
}

fn with_key_a(subject: HeaderFile) -> Vec<(u8, Vec<u8>)> {
    vec![(0x00, pubkey_file(KEY_A)), (0x01, subject.build())]
}

// ---------------------------------------------------------------------------
// Ladder rungs (`header_file.py:198-243`)
// ---------------------------------------------------------------------------

#[test]
fn basis_labels_are_upstreams_strings() {
    // `header_file.py:259-265` (the documented set) + `decode-error`.
    let expected = [
        (DecodeBasis::Signature, "signature", true),
        (DecodeBasis::SignatureSha256, "signature+sha256", true),
        (DecodeBasis::SignatureSha384, "signature+sha384", true),
        (DecodeBasis::Sha256, "sha256", true),
        (DecodeBasis::Sha384, "sha384", true),
        (DecodeBasis::Plain, "plain", true),
        (DecodeBasis::SignatureFailed, "signature-failed", false),
        (
            DecodeBasis::SignatureUnresolved,
            "signature-unresolved",
            false,
        ),
        (DecodeBasis::SignatureError, "signature-error", false),
        (DecodeBasis::SignaturePartial, "signature-partial", false),
        (DecodeBasis::Sha256Failed, "sha256-failed", false),
        (DecodeBasis::Sha384Failed, "sha384-failed", false),
        (DecodeBasis::DecompressFailed, "decompress-failed", false),
        (DecodeBasis::Unverifiable, "unverifiable", false),
        (DecodeBasis::DecodeError, "decode-error", false),
    ];
    for (basis, label, verified) in expected {
        assert_eq!(basis.as_str(), label);
        assert_eq!(basis.to_string(), label);
        assert_eq!(basis.is_verified(), verified, "{label}");
    }
}

#[test]
fn signature_spanning_the_whole_body_is_verified() {
    let data = payload(0x40);
    let v = verdict(&with_key_a(HeaderFile::plain(&data).signed_by(KEY_A)));
    assert_eq!(v.decode_verification_method().as_str(), "signature");
    assert!(v.decode_verified());
    assert!(v.plaintext_identity_ok());
    assert_eq!(v.signature(), Some(SignatureCheck::Verified));
    assert_eq!(v.checksum(), None);
}

#[test]
fn signature_over_a_prefix_only_is_partial() {
    // `header_file.py:220-231`: the tail past size_signed is unsigned.
    let data = payload(0x40);
    let subject = HeaderFile::plain(&data).signed_by(KEY_A).size_signed(0x30);
    let v = verdict(&with_key_a(subject));
    assert_eq!(v.decode_verification_method().as_str(), "signature-partial");
    assert!(!v.decode_verified());
    // Unencrypted: the bytes are the plaintext verbatim (`header_file.py:270-273`).
    assert!(v.plaintext_identity_ok());
    assert_eq!(v.signature(), Some(SignatureCheck::Verified));
}

#[test]
fn partial_signature_plus_matching_header_sha256_is_verified() {
    // `header_file.py:227-228`: the header (always signed) vouches for the body.
    let data = payload(0x40);
    let subject = HeaderFile::plain(&data)
        .signed_by(KEY_A)
        .size_signed(0x30)
        .sha256_of(&data);
    let v = verdict(&with_key_a(subject));
    assert_eq!(v.decode_verification_method().as_str(), "signature+sha256");
    assert!(v.decode_verified());
    assert_eq!(v.checksum(), Some(ChecksumCheck::Sha256 { ok: true }));
}

#[test]
fn tampered_body_fails_the_signature() {
    let data = payload(0x40);
    let mut entries = with_key_a(HeaderFile::plain(&data).signed_by(KEY_A));
    entries[1].1[HEADER_LEN + 3] ^= 0x01;
    let v = verdict(&entries);
    assert_eq!(v.decode_verification_method().as_str(), "signature-failed");
    assert!(!v.decode_verified());
    assert!(v.plaintext_identity_ok());
    assert_eq!(v.signature(), Some(SignatureCheck::Failed));
}

#[test]
fn unknown_certifying_key_is_unresolved() {
    // `cert_tree.py:79-80` NoCertifyingKey -> `header_file.py:206-209`.
    let data = payload(0x40);
    let v = verdict(&with_key_a(HeaderFile::plain(&data).signed_by(KEY_UNKNOWN)));
    assert_eq!(
        v.decode_verification_method().as_str(),
        "signature-unresolved"
    );
    assert_eq!(v.signature(), Some(SignatureCheck::NoCertifyingKey));
}

#[test]
fn key_store_kdb_key_certifies_an_entry() {
    // `cert_tree.py:368-383`: every `$KDB` key joins the key map. No
    // PubkeyFile carries KEY_B — only the key store does.
    let data = payload(0x40);
    let entries = vec![
        (0x50, key_store_file(&kdb(KEY_B))),
        (0x01, HeaderFile::plain(&data).signed_by(KEY_B).build()),
    ];
    let all = verdicts(&entries);
    let subject = all[1].expect("HeaderFile verdict");
    assert_eq!(subject.decode_verification_method().as_str(), "signature");
    // The key store itself is a (signed) HeaderFile-class entry
    // (`key_store_file.py:62-64`); nothing certifies KEY_UNKNOWN.
    let store = all[0].expect("KeyStoreFile verdict");
    assert_eq!(store.signature(), Some(SignatureCheck::NoCertifyingKey));
    assert_eq!(
        store.decode_verification_method().as_str(),
        "signature-unresolved"
    );
}

#[test]
fn malformed_kdb_contributes_no_keys() {
    // Control for the test above: break the `$KDB` magic
    // (`key_store_file.py:156-157` asserts it) and KEY_B is unknown again.
    let data = payload(0x40);
    let mut store = kdb(KEY_B);
    store[0x08] = b'X';
    let entries = vec![
        (0x50, key_store_file(&store)),
        (0x01, HeaderFile::plain(&data).signed_by(KEY_B).build()),
    ];
    let v = verdict(&entries);
    assert_eq!(
        v.decode_verification_method().as_str(),
        "signature-unresolved"
    );
}

#[test]
fn unsigned_header_sha256_decides_alone() {
    // `header_file.py:234-235`.
    let data = payload(0x40);
    let ok = verdict(&[(0x01, HeaderFile::plain(&data).sha256_of(&data).build())]);
    assert_eq!(ok.decode_verification_method().as_str(), "sha256");
    assert!(ok.decode_verified());
    assert_eq!(ok.signature(), None);
    assert_eq!(ok.checksum(), Some(ChecksumCheck::Sha256 { ok: true }));

    let bad = verdict(&[(0x01, HeaderFile::plain(&data).sha256_of(b"other").build())]);
    assert_eq!(bad.decode_verification_method().as_str(), "sha256-failed");
    assert!(!bad.decode_verified());
    assert_eq!(bad.checksum(), Some(ChecksumCheck::Sha256 { ok: false }));
}

#[test]
fn unsigned_untransformed_body_is_plain() {
    // `header_file.py:241-242`.
    let v = verdict(&[(0x01, HeaderFile::plain(&payload(0x40)).build())]);
    assert_eq!(v.decode_verification_method().as_str(), "plain");
    assert!(v.decode_verified());
    assert!(v.plaintext_identity_ok());
}

#[test]
fn compressed_body_without_integrity_data_is_unverifiable() {
    // `header_file.py:243`; it still decompresses, so it is a plaintext
    // identity when unencrypted.
    let data = payload(0x40);
    let stream = zlib_stored(&data);
    let subject = HeaderFile::compressed(&stream, stream.len(), &data);
    let v = verdict(&[(0x01, subject.build())]);
    assert_eq!(v.decode_verification_method().as_str(), "unverifiable");
    assert!(!v.decode_verified());
    assert!(v.plaintext_identity_ok());
}

#[test]
fn compressed_body_signature_is_over_the_inflated_bytes() {
    // `header_file.py:168-170` signs header || get_decrypted_decompressed_body().
    let data = payload(0x40);
    let stream = zlib_stored(&data);
    let subject = HeaderFile::compressed(&stream, stream.len(), &data).signed_by(KEY_A);
    let v = verdict(&with_key_a(subject));
    assert_eq!(v.decode_verification_method().as_str(), "signature");
}

#[test]
fn corrupt_zlib_stream_is_decompress_failed() {
    // `header_file.py:179-185` + `:201-202`.
    let mut stream = zlib_stored(&payload(0x40));
    stream[2] = 0x07; // BTYPE = 11, reserved: invalid deflate block
    let subject = HeaderFile::compressed(&stream, stream.len(), &payload(0x40));
    let v = verdict(&[(0x01, subject.build())]);
    assert_eq!(v.decode_verification_method().as_str(), "decompress-failed");
    assert!(!v.decode_verified());
    assert!(!v.plaintext_identity_ok());
}

#[test]
fn truncated_zlib_stream_is_decompress_failed() {
    // `zlib.decompress` raises "incomplete or truncated stream"; `zlib_size`
    // cuts the stream short of its end (`header_file.py:181`).
    let data = payload(0x40);
    let stream = zlib_stored(&data);
    let subject = HeaderFile::compressed(&stream, stream.len() - 8, &data);
    let v = verdict(&[(0x01, subject.build())]);
    assert_eq!(v.decode_verification_method().as_str(), "decompress-failed");
}

#[test]
fn encrypted_signed_body_verifies_after_decryption() {
    let data = payload(0x40);
    let subject = HeaderFile::plain(&data).signed_by(KEY_A).encrypted();
    let v = verdict(&with_key_a(subject));
    assert_eq!(v.decode_verification_method().as_str(), "signature");
    assert!(v.plaintext_identity_ok());
}

#[test]
fn encrypted_unconfirmed_body_is_not_a_plaintext_identity() {
    // `header_file.py:276`: (not encrypted or verified) — an unconfirmed
    // decryption is never a plaintext identity.
    let data = payload(0x40);
    let unsigned = verdict(&[(0x01, HeaderFile::plain(&data).encrypted().build())]);
    assert_eq!(
        unsigned.decode_verification_method().as_str(),
        "unverifiable"
    );
    assert!(!unsigned.plaintext_identity_ok());

    let unresolved = verdict(&with_key_a(
        HeaderFile::plain(&data).signed_by(KEY_UNKNOWN).encrypted(),
    ));
    assert_eq!(
        unresolved.decode_verification_method().as_str(),
        "signature-unresolved"
    );
    assert!(!unresolved.plaintext_identity_ok());
}

#[test]
fn undecryptable_body_is_decode_error() {
    // A cipher text that is not block-aligned cannot be decrypted; upstream's
    // `_decrypted_decompressed_body` raises there (`header_file.py:200`), the
    // Rust ladder reports `decode-error`.
    let v = verdict(&[(0x01, HeaderFile::plain(&payload(0x41)).encrypted().build())]);
    assert_eq!(v.decode_verification_method().as_str(), "decode-error");
    assert!(!v.decode_verified());
    assert!(!v.plaintext_identity_ok());
}

#[test]
fn only_header_file_classes_have_a_verdict() {
    let all = verdicts(&with_key_a(HeaderFile::plain(&payload(0x40))));
    assert!(all[0].is_none(), "a PubkeyFile has no decode verdict");
    assert!(all[1].is_some());
}

// ---------------------------------------------------------------------------
// `ls` wiring (`psptool.py:116-140`, `:267-271`)
// ---------------------------------------------------------------------------

#[test]
fn ls_renders_verdicts_in_json_and_file_info() {
    let data = payload(0x40);
    let entries = vec![
        (0x00, pubkey_file(KEY_A)),
        (0x01, HeaderFile::plain(&data).signed_by(KEY_A).build()),
        (
            0x01,
            HeaderFile::plain(&data).signed_by(KEY_UNKNOWN).build(),
        ),
        (0x01, HeaderFile::plain(&data).sha256_of(&data).build()),
    ];
    let blob = image(&entries);
    let layout = layout(&blob);
    let dirs = walk_directories(&blob, &layout.fet, layout.rom_size, layout.rom_origin);
    let rom = RomListing {
        index: 0,
        blob: &blob,
        rom_size: layout.rom_size,
        rom_origin: layout.rom_origin,
        fet: &layout.fet,
        directories: &dirs,
        sparse: false,
    };

    let json = list_json(&rom, false);
    let rows = json[0]["entries"].as_array().expect("entries array");
    // `psptool.py:260`: only HeaderFile-class entries carry the keys.
    assert!(rows[0].get("decodeVerified").is_none());
    // (verified, method, File-Info tag): `KeyId.magic` = first two id bytes,
    // upper-case hex (`crypto.py:369-371`).
    let expected = [
        (true, "signature", "verified(A1A1)"),
        (false, "signature-unresolved", "key_missing(DEDE)"),
        (true, "sha256", "sha256_ok"),
    ];
    for (row, (verified, method, tag)) in rows[1..].iter().zip(expected) {
        assert_eq!(row["decodeVerified"], verified, "{row}");
        assert_eq!(row["decodeVerificationMethod"], method, "{row}");
        let info = row["info"].as_array().expect("info array");
        assert!(info.iter().any(|t| t == tag), "{tag} missing from {row}");
    }

    let text = list_default(&rom);
    for tag in ["verified(A1A1)", "key_missing(DEDE)", "sha256_ok"] {
        assert!(text.contains(tag), "{tag} missing from:\n{text}");
    }
}

// ---------------------------------------------------------------------------
// Corpus parity
// ---------------------------------------------------------------------------

/// Upstream oracle: PSPTool `241629b` `HeaderFile.decode_verification()` over
/// every `HeaderFile` (incl. `KeyStoreFile`) of every directory of every ROM
/// of the 54 `vendor/test-corpus/test_files` images, iterated
/// `blob.roms -> rom.directories -> directory.files` as upstream's own
/// `tests/integration/test_decode_verified.py:40-47` does: 4147 entries,
/// True 3159 / False 988.
const UPSTREAM_TALLY: [(&str, usize); 6] = [
    ("signature", 3117),
    ("plain", 42),
    ("signature-partial", 295),
    ("signature-unresolved", 251),
    ("signature-failed", 376),
    ("unverifiable", 66),
];

/// Of those, `plaintext_identity_ok()` is False for 5 (all encrypted
/// `signature-unresolved` entries).
const UPSTREAM_IDENTITY_FALSE: usize = 5;

/// The entry SET differs from upstream in four documented places; every
/// shared entry's verdict agrees.
///
/// * Upstream parses a zero-size directory record as a HeaderFile by growing
///   its buffer to 0x100 (`header_file.py:32-33`) and then echoes it for the
///   next record at the same offset (`files_by_offset`, `file.py:47-50`). We
///   classify the zero-size record as a plain file and parse the next record
///   fresh: ASUS_Notebook_TUF_FX505DY-AS.309 (one `signature` fewer) and the
///   Lenovo A285/A485 images (one `signature-partial` fewer each).
/// * Upstream's global `files_by_offset` echoes a lower-ROM non-HeaderFile for
///   H12SSW9.719's upper-ROM record at `0x1249000` (`file.py:47-54`; the
///   differential's cross-ROM-echo accommodation); we parse that record as
///   the HeaderFile it is (one `signature-failed` more).
const ENTRY_SET_DELTA: [(&str, isize); 3] = [
    ("signature", -1),
    ("signature-partial", -2),
    ("signature-failed", 1),
];

/// Every HeaderFile-class verdict of one image, walked the way `ls` lists it:
/// every ROM (FET candidate resolving to a layout), every directory, every
/// entry, against the image-wide key map.
fn image_verdicts(bytes: Vec<u8>) -> Vec<DecodeVerification> {
    let blob = SourceBytes::from_blob(bytes);
    let keys = CertifyingKeys::from_blob(&blob, Ikek::ZenPlus);
    let mut out = Vec::new();
    for position in scan_fet_candidates(&blob) {
        let Some(layout) = detect_rom_layout(&blob, position) else {
            continue;
        };
        let (size, origin) = (layout.rom_size, layout.rom_origin);
        for dir_ref in walk_directories(&blob, &layout.fet, size, origin) {
            let entries: Vec<_> = match &dir_ref.directory {
                Directory::Psp(p) => (0..p.entries.len())
                    .map(|i| Entry::parse_psp(&blob, p, i, size, origin))
                    .collect(),
                Directory::Bios(b) => (0..b.entries.len())
                    .map(|i| Entry::parse_bios(&blob, b, i, size, origin))
                    .collect(),
                Directory::Combo(_) => Vec::new(),
            };
            out.extend(
                entries
                    .iter()
                    .flatten()
                    .filter_map(|e| e.decode_verification(&blob, &keys, Ikek::ZenPlus)),
            );
        }
    }
    out
}

#[test]
fn corpus_tally_matches_upstream_oracle() {
    let paths = corpus_rom_paths();
    if paths.is_empty() {
        // PSPTOOL_TEST_CORPUS unset: nothing to compare (the nix dev shell
        // sets it; the gauntlet treats this skip as red).
        return;
    }
    // One worker per core; images are independent (each has its own tree).
    let workers = std::thread::available_parallelism().map_or(1, usize::from);
    let verdicts: Vec<DecodeVerification> = std::thread::scope(|scope| {
        let handles: Vec<_> = paths
            .chunks(paths.len().div_ceil(workers))
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .flat_map(|p| image_verdicts(std::fs::read(p).expect("read corpus image")))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("corpus worker"))
            .collect()
    });

    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    for v in &verdicts {
        *tally
            .entry(v.decode_verification_method().to_string())
            .or_default() += 1;
    }
    let identity_false = verdicts
        .iter()
        .filter(|v| !v.plaintext_identity_ok())
        .count();

    let mut expected: BTreeMap<String, usize> = UPSTREAM_TALLY
        .iter()
        .map(|&(label, count)| (label.to_owned(), count))
        .collect();
    for (label, delta) in ENTRY_SET_DELTA {
        let slot = expected.entry(label.to_owned()).or_default();
        *slot = slot.checked_add_signed(delta).expect("delta within tally");
    }
    assert_eq!(tally, expected);
    assert_eq!(identity_false, UPSTREAM_IDENTITY_FALSE);
}
