//! Body access for `HeaderFile`-class entries: zlib decompression, AES-128
//! decryption (via IKEK-wrapped key), and RSA-PSS signature verification.
//!
//! The byte-exact roundtrip rule (`docs/firmware-layout.md` §8) is preserved
//! by treating decrypted/decompressed bodies as **derived views**: the parser
//! never mutates the entry's source bytes; everything in this module returns
//! freshly allocated `Vec<u8>` (or borrows the source slice unchanged).
//!
//! Mapping to PSPTool's `header_file.HeaderFile`:
//!
//! | This module                           | PSPTool method                              |
//! | ------------------------------------- | ------------------------------------------- |
//! | [`HeaderEntry::data_region`]          | `body[0x100:-signature_len]`                |
//! | [`HeaderEntry::signature_bytes`]      | `body[-signature_len:]`                     |
//! | [`HeaderEntry::get_decrypted_body`]   | `get_decrypted`                             |
//! | [`HeaderEntry::get_decompressed_body`]| `get_decompressed_body`                     |
//! | [`HeaderEntry::get_decrypted_decompressed_body`] | `get_decrypted_decompressed_body` |
//! | [`HeaderEntry::get_signed_bytes`]     | `get_signed_bytes`                          |
//! | [`HeaderEntry::verify_signature`]     | `HeaderFile.verify_signature`               |
//! | [`PubkeyEntry::rsa_public_key`]       | `PubkeyFile.get_public_key`                 |
//! | [`Entry::decode_verification`]        | `HeaderFile.decode_verification`            |
//! | [`DecodeVerification`]                | `decode_verified` / `decode_verification_method` / `plaintext_identity_ok` |
//! | [`CertifyingKeys::from_blob`]         | `CertificateTree.from_blob` (pubkeys by id) |
//!
//! The `body` argument is always the entry's full body slice
//! (`[header(0x100) | data | signature]`). Nothing here mutates it.
//!
//! ## Decode verification
//!
//! [`Entry::decode_verification`] ports the tiered `(verified, basis)` ladder
//! of `HeaderFile._verify_decode` (PSPTool `header_file.py:198-243`, introduced
//! by the decode-verified commit `241629b` on top of master `edae097`). It
//! answers whether the decrypted/decompressed body is positively confirmed:
//! a signature spanning the whole body, a signature plus a matching header
//! checksum, a standalone checksum, or an untransformed unsigned body. The
//! signature rung resolves certifying keys through [`CertifyingKeys`], the
//! port of the `CertificateTree` key map (`cert_tree.py:255-406`): every
//! `PubkeyFile` key plus every key of every `KeyStoreFile` `$KDB` store
//! (`key_store_file.py:140-253`). The governing requirement is
//! `.design/psptool-ops/list.md` REQ-13/REQ-14 (its production consumer is the
//! `ls` renderer in `psptool-ops/src/list.rs`).
//!
//! ## REQ status (per `.design/psptool-core/body.md`)
//!
//! | REQ | Status | Evidence |
//! |---|---|---|
//! | REQ-1 (rom_size-bounded slicing) | SHIPPED | `data_region` at `body.rs:190` + `signature_bytes` at `body.rs:222`, both gated on `is_signed()` per upstream `header_file.py:77-84,100`; consumer `psptool-ops/src/extract.rs:59` + `psptool-ops/src/sign.rs:147`. Pins #81/#83 (unsigned slicing) live in `tests/divergence_body_bounds.rs`. |
//! | REQ-2 (AES-128 decryption) | SHIPPED | `get_decrypted_body` at `body.rs:255` (ECB-unwrap key then CBC-decrypt) per upstream `utils.py:281,283`, `header_file.py:184-190`; consumer `psptool-ops/src/extract.rs:79` → CLI `extract -d`. |
//! | REQ-3 (zlib decompression) | SHIPPED | `get_decompressed_body` at `body.rs:292` + `find_zlib_start` (0x500 window, bounded to `plaintext[..zlib_size]`) per upstream `utils.py:218-234,241-254`, `header_file.py:171`; consumer `psptool-ops/src/extract.rs:60`. Pins #82 (absolute zlib_size) / #84 (scan bound) live. |
//! | REQ-4 (combined decrypt+decompress) | SHIPPED | `get_decrypted_decompressed_body` at `body.rs:340` (decrypt iff encrypted, decompress iff compressed) per upstream `header_file.py:166-174`; production consumer `get_signed_bytes` at `body.rs:365`. |
//! | REQ-5 (signed-region = 0x100+size_signed) | SHIPPED | `get_signed_bytes` at `body.rs:365` emits `header(0x100) || plaintext[..size_signed]` per upstream `header_file.py:162-164`; consumer `psptool-ops/src/sign.rs:143` + `verify_signature` at `body.rs:392`. Closes #79. |
//! | REQ-6 (verify a real signed HeaderFile) | SHIPPED | `verify_signature` at `body.rs:392` uses the on-disk signature **plain** (not the PubkeyFile-reversed convention) per upstream `cert_tree.py:63,98`, `crypto.py:247-258`; consumer `psptool-ops/src/verify.rs:264` → CLI `verify`. Corpus-proven: 2993 real signatures verify (was 0). Closes #78. |
//! | REQ-7 (PubkeyEntry RSA extraction) | SHIPPED | `rsa_public_key` at `body.rs:481` with LE exponent/modulus per upstream `crypto.py:219-229`; production consumer `verify_signature` at `body.rs:392` (`pubkey.rsa_public_key()`). |

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockDecryptMut, KeyInit, KeyIvInit, block_padding::NoPadding};
use flate2::read::ZlibDecoder;
use flate2::{Decompress, FlushDecompress, Status};
use rsa::pss::{Signature as PssSignature, VerifyingKey as PssVerifyingKey};
use rsa::signature::Verifier;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384};
use std::collections::HashMap;
use std::fmt;
use std::io::Read as _;
use thiserror::Error;

use crate::directory::{Directory, walk_directories};
use crate::entry::{
    Entry, EntryClass, HEADER_FILE_LEN, HeaderEntry, PUBKEY_HEADER_LEN, PubkeyEntry,
    zlib_find_header,
};
use crate::fet::{detect_rom_layout, scan_fet_candidates};
use crate::magic::KDB_MAGIC;
use crate::source::SourceBytes;

/// AES-128-CBC decryptor type alias used throughout this module.
type Aes128CbcDec = cbc::Decryptor<Aes128>;

/// Length of the search window PSPTool scans for the zlib magic when an entry
/// declares `is_compressed` (`docs/firmware-layout.md` §6).
pub const ZLIB_SEARCH_WINDOW: usize = 0x500;

/// Zlib magic bytes PSPTool searches for (in order of preference).
pub const ZLIB_MAGICS: &[[u8; 2]] = &[[0x78, 0xDA], [0x78, 0x9C], [0x78, 0x5E], [0x78, 0x01]];

/// 16-byte Initial Key-Encryption Keys hard-wired in the PSP boot ROM. PSPTool
/// ships exactly the two below (`docs/firmware-layout.md` §5). The right one
/// is selected by hashing the `WRAPPED_IKEK` (`type 0x21`) directory entry —
/// chain-of-trust resolution lives in `psptool-ops` (#13). Callers that
/// already know which IKEK applies pass [`Ikek::ZenPlus`] (PSPTool's current
/// default) or [`Ikek::Custom`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ikek {
    /// Zen 1 IKEK.
    Zen,
    /// Zen+ and later default IKEK (PSPTool's `HeaderFile.get_unwrapped_ikek`
    /// always returns this; auto-detection is deferred to chain-of-trust work).
    ZenPlus,
    /// Caller-supplied 16-byte IKEK (e.g. recovered from a non-default chip).
    Custom([u8; 16]),
}

impl Ikek {
    /// 16 IKEK bytes.
    pub const fn bytes(&self) -> [u8; 16] {
        match self {
            Ikek::Zen => [
                0x49, 0x1E, 0x40, 0x1A, 0x40, 0x1E, 0xC1, 0xB2, 0x28, 0x46, 0x00, 0xF0, 0x99, 0xFD,
                0xE8, 0x68,
            ],
            Ikek::ZenPlus => [
                0x4C, 0x77, 0x63, 0x65, 0x32, 0xFE, 0x4C, 0x6F, 0xD6, 0xB9, 0xD6, 0xD7, 0xB5, 0x1E,
                0xDE, 0x59,
            ],
            Ikek::Custom(b) => *b,
        }
    }
}

/// Errors returned by the body-access helpers in this module.
#[derive(Debug, Error)]
pub enum BodyError {
    /// `body.len() < 0x100` so the leading HeaderFile header is incomplete.
    #[error("entry body shorter than HeaderFile header (got {0}, expected ≥ 0x100)")]
    Truncated(usize),
    /// `signature_type` is not one of the documented `{0, 2}`.
    #[error("unsupported signature_type {0} (expected 0 = RSA-2048 or 2 = RSA-4096)")]
    UnsupportedSignatureType(u32),
    /// Body is shorter than `0x100 + signature_len` so there is no room for
    /// the data region between header and signature.
    #[error("body too small ({body} bytes) for header + signature ({needed} bytes)")]
    BodyTooSmall { body: usize, needed: usize },
    /// `is_encrypted == 0` but the caller asked for decryption.
    #[error("entry is not encrypted (is_encrypted == 0)")]
    NotEncrypted,
    /// `is_compressed == 0` but the caller asked for decompression.
    #[error("entry is not compressed (is_compressed == 0)")]
    NotCompressed,
    /// Encrypted data region length is not a multiple of the AES block size.
    #[error("encrypted data length {0} is not a multiple of 16")]
    InvalidCipherLength(usize),
    /// No zlib magic found within the §6 search window.
    #[error("no zlib magic in first {window:#x} bytes of compressed body")]
    ZlibMagicMissing { window: usize },
    /// `zlib_size` from the header would extend past the data region.
    #[error("zlib_size {size} extends past data region of {available} bytes (start={start})")]
    ZlibSizeOutOfRange {
        size: u64,
        start: usize,
        available: usize,
    },
    /// zlib-decompressing the stream failed.
    #[error("zlib decompression failed: {0}")]
    Zlib(String),
    /// `size_signed` from the header is larger than the
    /// decrypted-decompressed body length.
    #[error("size_signed {0} exceeds available signed body length {1}")]
    SignedRegionOutOfRange(usize, usize),
}

/// Errors returned by [`HeaderEntry::verify_signature`].
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Failure preparing the signed region (decrypt / decompress / slice).
    #[error(transparent)]
    Body(#[from] BodyError),
    /// PubkeyEntry is too short to contain the declared modulus / exponent.
    #[error("pubkey body too short: have {have}, need ≥ {need}")]
    PubkeyTruncated { have: usize, need: usize },
    /// `pubexp_bits` or `modulus_bits` is not 2048 / 4096 (the only two values
    /// PSPTool supports).
    #[error("unsupported pubkey bit-width: pubexp={pubexp}, modulus={modulus}")]
    UnsupportedKeyWidth { pubexp: u32, modulus: u32 },
    /// `header.signature_type` and `pubkey.modulus_bits` disagree (e.g.
    /// signature claims RSA-4096 but the candidate key is 2048-bit).
    #[error(
        "signature_type {sig_type} requires modulus {needed} bits, but pubkey has {modulus} bits"
    )]
    KeySizeMismatch {
        sig_type: u32,
        modulus: u32,
        needed: u32,
    },
    /// `rsa::RsaPublicKey::new` rejected the (modulus, exponent) pair.
    #[error("invalid RSA public key: {0}")]
    InvalidPublicKey(String),
    /// `rsa::pss::Signature::try_from` rejected the trailing signature bytes
    /// (almost always: wrong length).
    #[error("invalid signature bytes")]
    InvalidSignature,
    /// PSS verification failed — the signature does not match the signed bytes
    /// under this pubkey.
    #[error("signature verification failed")]
    BadSignature,
}

// ---------------------------------------------------------------------------
// HeaderEntry — body access methods
// ---------------------------------------------------------------------------

impl HeaderEntry {
    /// Effective end-of-entry offset within `body`, honoring `header.rom_size`
    /// per docs §4.2 / reference `header_file._parse`: when `rom_size != 0`
    /// the entry is logically truncated (or zero-extended) to `rom_size`; when
    /// `rom_size == 0` the caller's body length is authoritative. We cannot
    /// zero-extend a borrowed slice, so `rom_size > body.len()` is rejected
    /// as `BodyTooSmall`.
    fn effective_end(&self, body: &[u8]) -> Result<usize, BodyError> {
        let end = if self.rom_size == 0 {
            body.len()
        } else {
            self.rom_size as usize
        };
        if end > body.len() {
            return Err(BodyError::BodyTooSmall {
                body: body.len(),
                needed: end,
            });
        }
        Ok(end)
    }

    /// Range, **within the entry body**, of the (post-header, possibly
    /// encrypted/compressed) data region. Equivalent to PSPTool's
    /// `body[0x100:-signature_len]` after truncating to `rom_size`. Returns
    /// `Err` when `signature_type` is not one of `{0, 2}` or when the
    /// rom-size-bounded buffer is shorter than header + signature.
    pub fn data_region<'a>(&self, body: &'a [u8]) -> Result<&'a [u8], BodyError> {
        if body.len() < HEADER_FILE_LEN {
            return Err(BodyError::Truncated(body.len()));
        }
        let end = self.effective_end(body)?;
        // Upstream reserves signature bytes only for signed files: an unsigned
        // HeaderFile has `signature_len = 0` (`header_file.py:83-84`), so its
        // data region spans the whole post-header region. Mirror the
        // `if self.is_signed` gate before `body = len - header - signature_len`
        // (`header_file.py:77-84,100`).
        let sig_len = if self.is_signed() {
            self.signature_len()
                .ok_or(BodyError::UnsupportedSignatureType(self.signature_type))?
        } else {
            0
        };
        let needed = HEADER_FILE_LEN
            .checked_add(sig_len)
            .ok_or(BodyError::UnsupportedSignatureType(self.signature_type))?;
        if end < needed {
            return Err(BodyError::BodyTooSmall { body: end, needed });
        }
        Ok(&body[HEADER_FILE_LEN..end - sig_len])
    }

    /// Trailing RSA signature bytes. Equivalent to PSPTool's
    /// `body[-signature_len:]` after truncating to `rom_size`. For a
    /// HeaderFile these are the RSA-PSS signature in standard big-endian
    /// (I2OSP) order — stored **plain**, matching upstream's plain `Signature`
    /// wrapper (`cert_tree.py:63`). [`Self::verify_signature`] passes them to
    /// RSA-PSS verification unchanged. (The reversed `ReversedSignature`
    /// convention, `crypto.py:386-409`, applies only to PubkeyFile signatures.)
    pub fn signature_bytes<'a>(&self, body: &'a [u8]) -> Result<&'a [u8], BodyError> {
        if body.len() < HEADER_FILE_LEN {
            return Err(BodyError::Truncated(body.len()));
        }
        let end = self.effective_end(body)?;
        // Upstream materializes a signature only for signed files: an unsigned
        // HeaderFile has `signature_len = 0` (`header_file.py:83-84`) and the
        // only site that yields a signature value returns `b''` for it
        // (`header_file.py:181`: `signature = ... if self.is_signed else b''`).
        // Mirror the `if self.is_signed` gate — the exact sibling of the #81
        // `data_region` fix above.
        let sig_len = if self.is_signed() {
            self.signature_len()
                .ok_or(BodyError::UnsupportedSignatureType(self.signature_type))?
        } else {
            0
        };
        let needed = HEADER_FILE_LEN
            .checked_add(sig_len)
            .ok_or(BodyError::UnsupportedSignatureType(self.signature_type))?;
        if end < needed {
            return Err(BodyError::BodyTooSmall { body: end, needed });
        }
        Ok(&body[end - sig_len..end])
    }

    /// Apply AES-128-CBC decryption to the data region using `ikek`. Returns
    /// the plaintext bytes as a fresh `Vec<u8>`. Panics never — all errors
    /// are surfaced via [`BodyError`].
    ///
    /// Procedure (§5):
    ///   1. `entry_key = AES-128-ECB-decrypt(wrapped_key, ikek_bytes)`
    ///   2. `plaintext = AES-128-CBC-decrypt(data_region, iv, entry_key)`
    pub fn get_decrypted_body(&self, body: &[u8], ikek: Ikek) -> Result<Vec<u8>, BodyError> {
        if !self.is_encrypted {
            return Err(BodyError::NotEncrypted);
        }
        let ciphertext = self.data_region(body)?;
        if !ciphertext.len().is_multiple_of(16) {
            return Err(BodyError::InvalidCipherLength(ciphertext.len()));
        }

        // Step 1: unwrap the entry key under the IKEK (single AES-128 ECB
        // block; the wrapped key is exactly 16 bytes per the §4 layout).
        let ikek_bytes = ikek.bytes();
        let cipher = Aes128::new(GenericArray::from_slice(&ikek_bytes));
        let mut entry_key = GenericArray::clone_from_slice(&self.wrapped_key);
        cipher.decrypt_block(&mut entry_key);

        // Step 2: CBC decrypt the data region with NoPadding (PSPTool stores
        // already-padded data, so callers see the raw plaintext bytes).
        let mut buf = ciphertext.to_vec();
        let pt = Aes128CbcDec::new_from_slices(&entry_key, &self.iv)
            .expect("AES-128 key + 16-byte IV are always accepted")
            .decrypt_padded_mut::<NoPadding>(&mut buf)
            .map_err(|_| BodyError::InvalidCipherLength(ciphertext.len()))?;
        let len = pt.len();
        buf.truncate(len);
        Ok(buf)
    }

    /// Apply zlib decompression to a candidate plaintext data region.
    ///
    /// `plaintext` is the data region — either [`Self::data_region`] directly
    /// (when `!is_encrypted`) or the output of [`Self::get_decrypted_body`].
    /// PSPTool searches the first `0x500` bytes for one of the four documented
    /// zlib magics (78 DA / 78 9C / 78 5E / 78 01) and decompresses
    /// `zlib_size` bytes starting at the matched offset, then **prepends the
    /// pre-magic prefix** to the decompressed output (matches reference
    /// `psptool/utils.py::zlib_decompress`).
    pub fn get_decompressed_body(&self, plaintext: &[u8]) -> Result<Vec<u8>, BodyError> {
        if !self.is_compressed {
            return Err(BodyError::NotCompressed);
        }
        // `zlib_size` is an ABSOLUTE end offset into the data region, not a
        // length measured from the zlib magic. Upstream feeds
        // `zlib_decompress(output[:self.zlib_size])` (`header_file.py:171`),
        // and `zlib_decompress` (`utils.py:245-252`) slices the compressed
        // stream as `s[zlib_start:]` where `s == output[:zlib_size]` — i.e.
        // `output[zlib_start .. zlib_size]`. So the stream ends at the absolute
        // offset `zlib_size`, and any pre-magic prefix (`output[..zlib_start]`)
        // is prepended to the decompressed output.
        let zlib_size = self.zlib_size as usize;
        // Search for the zlib magic ONLY within `output[:zlib_size]`, exactly
        // like upstream: `zlib_find_header(s)` is called with `s ==
        // output[:zlib_size]` (`utils.py:245`), so upstream never inspects a
        // byte at or beyond `zlib_size`. Bounding the scan here (instead of
        // scanning the whole data region and clamping afterwards) ensures a
        // spurious magic living past `zlib_size` is not located — upstream
        // would return -1 (no magic), which surfaces as `ZlibMagicMissing`.
        let search_end = zlib_size.min(plaintext.len());
        let stream_start = find_zlib_start(&plaintext[..search_end])?;
        if zlib_size > plaintext.len() || zlib_size < stream_start {
            return Err(BodyError::ZlibSizeOutOfRange {
                size: self.zlib_size as u64,
                start: stream_start,
                available: plaintext.len(),
            });
        }
        let stream = &plaintext[stream_start..zlib_size];
        // Don't pre-size from header.size_uncompressed — it is attacker-
        // controlled (up to ~4 GiB) and would let a malformed entry trigger
        // an OOM via Vec::with_capacity. Let `read_to_end` grow on demand.
        let mut out = Vec::new();
        out.extend_from_slice(&plaintext[..stream_start]);
        let mut decoder = ZlibDecoder::new(stream);
        decoder
            .read_to_end(&mut out)
            .map_err(|e| BodyError::Zlib(e.to_string()))?;
        Ok(out)
    }

    /// Combined `get_decrypted` then `get_decompressed_body` — the same view
    /// PSPTool's `get_decrypted_decompressed_body` exposes.
    ///
    /// `ikek` is required iff `is_encrypted == 1`. When neither flag is set
    /// the data region is returned verbatim (as a copy) so all callers see
    /// a uniform `Vec<u8>` shape.
    pub fn get_decrypted_decompressed_body(
        &self,
        body: &[u8],
        ikek: Option<Ikek>,
    ) -> Result<Vec<u8>, BodyError> {
        let decrypted = if self.is_encrypted {
            let key = ikek.ok_or(BodyError::NotEncrypted)?;
            self.get_decrypted_body(body, key)?
        } else {
            self.data_region(body)?.to_vec()
        };
        if self.is_compressed {
            self.get_decompressed_body(&decrypted)
        } else {
            Ok(decrypted)
        }
    }

    /// Best-effort decode mirroring upstream `_decrypted_decompressed_body`
    /// (`header_file.py:172-186`). Unlike [`Self::get_decrypted_decompressed_body`]
    /// a failed zlib stream does not discard the body.
    ///
    /// Returns `(bytes, decompress_ok)`. `decompress_ok` is `false` only when the
    /// entry is compressed and its zlib stream fails to inflate; `bytes` is then
    /// the still-compressed decrypted data region (upstream returns `output`, not
    /// the `zlib_size`-truncated slice, `header_file.py:185`). A missing zlib
    /// magic is not a failure: upstream `zlib_decompress` returns its input
    /// unchanged then (`utils.py:254`), so `decompress_ok` stays `true`.
    ///
    /// The magic search is upstream's per-magic priority order
    /// ([`zlib_find_header`], `utils.py:218-234`) and the inflate is strict
    /// ([`zlib_decompress_strict`]), so a truncated stream is a failure exactly
    /// as `zlib.decompress` raises on it.
    ///
    /// Public because it *is* upstream's `get_decrypted_decompressed_body()`
    /// (`header_file.py:188-189` returns `_decrypted_decompressed_body()[0]`):
    /// the `psptool-py` binding's `HeaderFile.get_decrypted_decompressed_body`
    /// returns its bytes, which consumers hash as a content identity.
    pub fn decode_best_effort(
        &self,
        file: &[u8],
        ikek: Ikek,
    ) -> Result<(Vec<u8>, bool), BodyError> {
        let output = if self.is_encrypted {
            self.get_decrypted_body(file, ikek)?
        } else {
            self.data_region(file)?.to_vec()
        };
        if !self.is_compressed {
            return Ok((output, true));
        }
        // `header_file.py:181`: `zlib_decompress(output[:self.zlib_size])`.
        let stream = &output[..(self.zlib_size as usize).min(output.len())];
        let Some(start) = zlib_find_header(stream) else {
            // `utils.py:254`: no magic → the (truncated) input, unchanged.
            return Ok((stream.to_vec(), true));
        };
        match zlib_decompress_strict(&stream[start..]) {
            Some(inflated) => {
                // `utils.py:248-252`: `uncompressed + decompressed`.
                let mut out = stream[..start].to_vec();
                out.extend_from_slice(&inflated);
                Ok((out, true))
            }
            None => Ok((output, false)),
        }
    }

    /// Bytes covered by the RSA signature: `header(0x100) ||
    /// decrypted_decompressed_body`, truncated to `0x100 + size_signed`
    /// (`header_file.py:162-164`: `file_bytes[:len(self.header) +
    /// self.size_signed]`, `len(header) == 0x100`). `size_signed` is the
    /// length of the *body* region covered by the signature, added on top of
    /// the full `0x100` header — the on-disk field is header-EXCLUSIVE
    /// (`entry.rs:177` reads `h[0x14..0x18]` raw, no adjustment).
    pub fn get_signed_bytes(&self, body: &[u8], ikek: Option<Ikek>) -> Result<Vec<u8>, BodyError> {
        if body.len() < HEADER_FILE_LEN {
            return Err(BodyError::Truncated(body.len()));
        }
        let header_bytes = &body[..HEADER_FILE_LEN];
        let plaintext = self.get_decrypted_decompressed_body(body, ikek)?;
        let size_signed = self.size_signed as usize;
        if size_signed > plaintext.len() {
            return Err(BodyError::SignedRegionOutOfRange(
                size_signed,
                plaintext.len(),
            ));
        }
        let mut out = Vec::with_capacity(HEADER_FILE_LEN + size_signed);
        out.extend_from_slice(header_bytes);
        out.extend_from_slice(&plaintext[..size_signed]);
        Ok(out)
    }

    /// Verify the trailing RSA-PSS signature against `pubkey`. Mirrors
    /// PSPTool's HeaderFile verify path (`cert_tree.py:63` wraps the on-disk
    /// signature in a plain `Signature`; `cert_tree.py:98` + `crypto.py:247-258`
    /// pass it straight to RSA verify). The hash function is selected per
    /// `signature_type` (RSA-2048 → SHA-256, RSA-4096 → SHA-384), and the
    /// on-disk signature bytes are used **plain** (standard big-endian I2OSP) —
    /// a HeaderFile signature is NOT reversed (the `ReversedSignature`
    /// convention, `crypto.py:386-409`, applies only to PubkeyFile signatures).
    pub fn verify_signature(
        &self,
        body: &[u8],
        pubkey: &PubkeyEntry,
        ikek: Option<Ikek>,
    ) -> Result<(), VerifyError> {
        self.check_key_width(pubkey)?;
        // Signed region (decrypted, decompressed if applicable, header + body).
        let signed = self.get_signed_bytes(body, ikek)?;
        self.verify_signed_region(body, &signed, pubkey)
    }

    /// Cross-check `signature_type` (sig length) against the declared modulus
    /// width BEFORE building the RSA key — otherwise a mismatch would be
    /// reported as InvalidPublicKey, which doesn't match the error taxonomy.
    /// PSPTool conflates signature_type with hash + modulus width:
    ///   signature_type = 0 → 2048-bit modulus → SHA-256
    ///   signature_type = 2 → 4096-bit modulus → SHA-384
    fn check_key_width(&self, pubkey: &PubkeyEntry) -> Result<(), VerifyError> {
        let needed = match self.signature_type {
            0 => 2048,
            2 => 4096,
            other => {
                return Err(VerifyError::Body(BodyError::UnsupportedSignatureType(
                    other,
                )));
            }
        };
        if pubkey.modulus_bits != needed {
            return Err(VerifyError::KeySizeMismatch {
                sig_type: self.signature_type,
                modulus: pubkey.modulus_bits,
                needed,
            });
        }
        Ok(())
    }

    /// RSA-PSS verification of `signed` against this entry's trailing signature.
    fn verify_signed_region(
        &self,
        body: &[u8],
        signed: &[u8],
        pubkey: &PubkeyEntry,
    ) -> Result<(), VerifyError> {
        // Trailing signature — used PLAIN (standard big-endian I2OSP). A
        // HeaderFile signature is a plain `Signature` (`cert_tree.py:63`), NOT
        // the reversed PubkeyFile convention (`crypto.py:386-409`).
        let signature = self.signature_bytes(body).map_err(VerifyError::Body)?;

        let public_key = pubkey.rsa_public_key()?;

        match self.signature_type {
            0 => verify_pss::<Sha256>(&public_key, signed, signature),
            2 => verify_pss::<Sha384>(&public_key, signed, signature),
            other => Err(VerifyError::Body(BodyError::UnsupportedSignatureType(
                other,
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// PubkeyEntry — RSA public-key extraction
// ---------------------------------------------------------------------------

impl PubkeyEntry {
    /// Range within the pubkey blob of the `pubexp` bytes (little-endian).
    fn pubexp_range(&self) -> core::ops::Range<usize> {
        PUBKEY_HEADER_LEN..PUBKEY_HEADER_LEN + self.pubexp_size()
    }

    /// Range within the pubkey blob of the modulus bytes (little-endian).
    fn modulus_range(&self) -> core::ops::Range<usize> {
        let start = PUBKEY_HEADER_LEN + self.pubexp_size();
        start..start + self.modulus_size()
    }

    /// Public-exponent bytes as stored on disk (little-endian, high bytes
    /// zero per §7.1).
    pub fn pubexp_bytes(&self) -> Result<&[u8], VerifyError> {
        let r = self.pubexp_range();
        self.source
            .as_bytes()
            .get(r.clone())
            .ok_or(VerifyError::PubkeyTruncated {
                have: self.source.len(),
                need: r.end,
            })
    }

    /// Modulus bytes as stored on disk (little-endian).
    pub fn modulus_bytes(&self) -> Result<&[u8], VerifyError> {
        let r = self.modulus_range();
        self.source
            .as_bytes()
            .get(r.clone())
            .ok_or(VerifyError::PubkeyTruncated {
                have: self.source.len(),
                need: r.end,
            })
    }

    /// Build an [`rsa::RsaPublicKey`] from the on-disk exponent and modulus.
    pub fn rsa_public_key(&self) -> Result<RsaPublicKey, VerifyError> {
        if self.modulus_bits != 2048 && self.modulus_bits != 4096 {
            return Err(VerifyError::UnsupportedKeyWidth {
                pubexp: self.pubexp_bits,
                modulus: self.modulus_bits,
            });
        }
        let e = BigUint::from_bytes_le(self.pubexp_bytes()?);
        let n = BigUint::from_bytes_le(self.modulus_bytes()?);
        RsaPublicKey::new(n, e).map_err(|err| VerifyError::InvalidPublicKey(err.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Decode verification — `HeaderFile._verify_decode` (header_file.py:191-276)
// ---------------------------------------------------------------------------

/// Outcome of the certificate-tree signature check `SignedEntity.is_verified()`
/// (`cert_tree.py:72-95`) for a signed HeaderFile / KeyStoreFile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureCheck {
    /// At least one certifying key verifies the signature (`verified_once`,
    /// `cert_tree.py:84-95`).
    Verified,
    /// Certifying keys exist but none verifies (`cert_tree.py:90-91`).
    Failed,
    /// No key with the entry's certifying id is known: upstream raises
    /// `NoCertifyingKey` (`cert_tree.py:79-80`).
    NoCertifyingKey,
    /// The check could not run: a candidate key's crypto material is not an
    /// RSA-2048/4096 key (upstream `_make_public_key` raises,
    /// `cert_tree.py:204-208`), or the signed region / signature could not be
    /// cut from the file. Upstream's unexpected-exception path
    /// (`header_file.py:210-217`).
    Error,
}

/// Outcome of the stored content checksum check `verify_sha256` /
/// `verify_sha384` (`header_file.py:112-128`) over the checksummed bytes.
/// sha256 wins when both bits are set, as in `psptool.py:131-140`
/// (`if … elif`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumCheck {
    /// `has_sha256_checksum`; `ok` = the stored 32 bytes match.
    Sha256 { ok: bool },
    /// `has_sha384_checksum`; `ok` = the stored 48 bytes match.
    Sha384 { ok: bool },
}

/// Basis of a decode verdict: the `decode_verification_method()` label set
/// (`header_file.py:259-265`) plus [`DecodeBasis::DecodeError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DecodeBasis {
    /// `signature`: verified, and `size_signed` spans the whole decoded body
    /// (`header_file.py:225-226`).
    Signature,
    /// `signature+sha256`: verified signature, partial span, matching sha256
    /// (`header_file.py:227-228`).
    SignatureSha256,
    /// `signature+sha384` (`header_file.py:229-230`).
    SignatureSha384,
    /// `sha256`: unsigned, matching stored sha256 (`header_file.py:234-235`).
    Sha256,
    /// `sha384`: unsigned, matching stored sha384 (`header_file.py:236-237`).
    Sha384,
    /// `plain`: unsigned, unencrypted, uncompressed (`header_file.py:241-242`).
    Plain,
    /// `signature-failed` (`header_file.py:218-219`).
    SignatureFailed,
    /// `signature-unresolved`: no certifying key (`header_file.py:206-209`).
    SignatureUnresolved,
    /// `signature-error` (`header_file.py:210-217`).
    SignatureError,
    /// `signature-partial`: verified, but the tail past `size_signed` is
    /// unauthenticated (`header_file.py:231`).
    SignaturePartial,
    /// `sha256-failed` (`header_file.py:235`).
    Sha256Failed,
    /// `sha384-failed` (`header_file.py:237`).
    Sha384Failed,
    /// `decompress-failed`: the zlib stream does not inflate
    /// (`header_file.py:201-202`).
    DecompressFailed,
    /// `unverifiable`: transformed body with no integrity data
    /// (`header_file.py:243`).
    Unverifiable,
    /// `decode-error`: the body cannot be decrypted or sliced at all (an
    /// undocumented `signature_type` on a signed entry, a header-declared size
    /// past the file, a cipher text that is not block-aligned). Upstream has no
    /// label for this because `_decrypted_decompressed_body` runs outside every
    /// `try` in `_verify_decode` (`header_file.py:200`): the exception escapes
    /// `decode_verification()`. The Rust API is total and reports it instead;
    /// it is never verified and never a plaintext identity.
    DecodeError,
}

impl DecodeBasis {
    /// The upstream label (`header_file.py:259-265`), e.g. `"signature-partial"`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::SignatureSha256 => "signature+sha256",
            Self::SignatureSha384 => "signature+sha384",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Plain => "plain",
            Self::SignatureFailed => "signature-failed",
            Self::SignatureUnresolved => "signature-unresolved",
            Self::SignatureError => "signature-error",
            Self::SignaturePartial => "signature-partial",
            Self::Sha256Failed => "sha256-failed",
            Self::Sha384Failed => "sha384-failed",
            Self::DecompressFailed => "decompress-failed",
            Self::Unverifiable => "unverifiable",
            Self::DecodeError => "decode-error",
        }
    }

    /// Whether this basis confirms the full decoded body — the six verified
    /// labels of `header_file.py:260-261`.
    pub const fn is_verified(self) -> bool {
        matches!(
            self,
            Self::Signature
                | Self::SignatureSha256
                | Self::SignatureSha384
                | Self::Sha256
                | Self::Sha384
                | Self::Plain
        )
    }
}

impl fmt::Display for DecodeBasis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Single-pass decode verification of one HeaderFile-class entry — upstream
/// `decode_verification()` (`header_file.py:191-196`), carrying the
/// signature and checksum sub-results the `ls` File-Info tags render
/// (`psptool.py:116-140`) so a caller never verifies twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeVerification {
    method: DecodeBasis,
    encrypted: bool,
    signature: Option<SignatureCheck>,
    checksum: Option<ChecksumCheck>,
}

impl DecodeVerification {
    /// Whether the decoded body is positively confirmed authentic
    /// (`decode_verified()`, `header_file.py:245-257`).
    pub const fn decode_verified(&self) -> bool {
        self.method.is_verified()
    }

    /// The basis of [`Self::decode_verified`]
    /// (`decode_verification_method()`, `header_file.py:259-265`).
    pub const fn decode_verification_method(&self) -> DecodeBasis {
        self.method
    }

    /// Whether the decoded body is the true plaintext, i.e. its hash is a
    /// valid content identity (`plaintext_identity_ok()`,
    /// `header_file.py:267-276`): `(not encrypted or verified) and method !=
    /// 'decompress-failed'`. Weaker than [`Self::decode_verified`]: an
    /// unencrypted body is the plaintext verbatim whatever its signature
    /// status. A [`DecodeBasis::DecodeError`] body does not exist, so it is
    /// never an identity either (upstream raises there).
    pub const fn plaintext_identity_ok(&self) -> bool {
        (!self.encrypted || self.decode_verified())
            && !matches!(
                self.method,
                DecodeBasis::DecompressFailed | DecodeBasis::DecodeError
            )
    }

    /// The certificate-tree signature check, `None` when the entry is not
    /// signed (a KeyStoreFile always is, `key_store_file.py:62-64`).
    pub const fn signature(&self) -> Option<SignatureCheck> {
        self.signature
    }

    /// The stored content checksum check, `None` when neither sha bit is set.
    pub const fn checksum(&self) -> Option<ChecksumCheck> {
        self.checksum
    }
}

/// Certifying public keys by 16-byte key id: the key map of upstream's
/// `CertificateTree` (`cert_tree.py:255-336`), consulted by
/// [`Entry::decode_verification`] for its signature rung.
#[derive(Clone, Debug, Default)]
pub struct CertifyingKeys {
    by_id: HashMap<[u8; 16], KeyCandidates>,
}

/// Every key known under one key id (`CertificateTree.pubkeys[key_id]`).
#[derive(Clone, Debug, Default)]
struct KeyCandidates {
    /// Distinct usable keys. Upstream dedups key entities by address; equal
    /// key material verifies identically, so dedup by value is equivalent.
    keys: Vec<RsaPublicKey>,
    /// Some candidate's crypto material is not an RSA-2048/4096 key; upstream
    /// raises when it reaches that key (`cert_tree.py:204-208`).
    unusable: bool,
}

impl CertifyingKeys {
    /// Collect the certifying keys of a whole image, as
    /// `CertificateTree.from_blob` does (`cert_tree.py:385-397`): every ROM
    /// (every FET candidate that resolves to a layout), every directory, every
    /// entry — `PubkeyFile` keys (`:392-393`, `add_pubkey_file` `:349-366`) and
    /// every key of every `KeyStoreFile` `$KDB` store (`:396-397`,
    /// `add_key_store_file` `:368-383`). Keys from one ROM certify entries of
    /// another, exactly like upstream's single tree. `ikek` decrypts a
    /// compressed key store (`key_store_file.py:39-40`).
    ///
    /// Upstream additionally scans file bodies for inline pubkeys
    /// (`cert_tree.py:399-404`, `blob.py:133-181`); that heuristic finds none
    /// in the test corpus and is not ported here.
    pub fn from_blob(blob: &SourceBytes, ikek: Ikek) -> Self {
        let mut keys = Self::default();
        for position in scan_fet_candidates(blob) {
            let Some(layout) = detect_rom_layout(blob, position) else {
                continue;
            };
            for dir_ref in walk_directories(blob, &layout.fet, layout.rom_size, layout.rom_origin) {
                let parsed: Vec<_> = match &dir_ref.directory {
                    Directory::Psp(p) => (0..p.entries.len())
                        .map(|i| Entry::parse_psp(blob, p, i, layout.rom_size, layout.rom_origin))
                        .collect(),
                    Directory::Bios(b) => (0..b.entries.len())
                        .map(|i| Entry::parse_bios(blob, b, i, layout.rom_size, layout.rom_origin))
                        .collect(),
                    Directory::Combo(_) => Vec::new(),
                };
                for entry in parsed.iter().flatten() {
                    keys.add_entry(entry, blob, ikek);
                }
            }
        }
        keys
    }

    fn add_entry(&mut self, entry: &Entry, blob: &SourceBytes, ikek: Ikek) {
        match &entry.class {
            // `PublicKeyEntity._from_pubkey_file` (`cert_tree.py:161-170`).
            EntryClass::Pubkey(pk) => self.insert(pk.key_id, pk.rsa_public_key().ok()),
            // `KeyStoreFile.key_store.keys` (`cert_tree.py:377-383`).
            EntryClass::KeyStore(h) => {
                let window = entry.header_file_window(h, blob);
                let file = window.as_bytes();
                let decoded = if h.is_compressed {
                    h.decode_best_effort(file, ikek).ok().map(|(body, _)| body)
                } else {
                    None
                };
                let Some(store) = h.key_store_slice(file, decoded.as_deref()) else {
                    return;
                };
                for (key_id, key) in kdb_keys(store) {
                    self.insert(key_id, key);
                }
            }
            _ => {}
        }
    }

    fn insert(&mut self, key_id: [u8; 16], key: Option<RsaPublicKey>) {
        let slot = self.by_id.entry(key_id).or_default();
        match key {
            Some(key) if !slot.keys.contains(&key) => slot.keys.push(key),
            Some(_) => {}
            None => slot.unusable = true,
        }
    }

    /// `SignedEntity.verify_with_tree` (`cert_tree.py:78-95`) over the signed
    /// bytes and signature, when both could be cut from the file.
    fn check(
        &self,
        certifying_id: &[u8; 16],
        signed: Option<&[u8]>,
        signature: Option<&[u8]>,
    ) -> SignatureCheck {
        // `cert_tree.py:79-80`: an empty key set raises NoCertifyingKey.
        let Some(candidates) = self.by_id.get(certifying_id) else {
            return SignatureCheck::NoCertifyingKey;
        };
        if candidates.unusable {
            return SignatureCheck::Error;
        }
        let (Some(signed), Some(signature)) = (signed, signature) else {
            return SignatureCheck::Error;
        };
        if candidates
            .keys
            .iter()
            .any(|key| verify_blob(key, signed, signature))
        {
            SignatureCheck::Verified
        } else {
            SignatureCheck::Failed
        }
    }
}

impl Entry {
    /// Decode verification of a HeaderFile-class entry (upstream
    /// `decode_verification()`, `header_file.py:191-243`); `None` for every
    /// other entry class (the method exists only on `HeaderFile` and its
    /// `KeyStoreFile` subclass — `psptool.py:260` gates the JSON keys the same
    /// way).
    ///
    /// `blob` is the image the entry was parsed from (a header whose
    /// `rom_size` exceeds the directory size reads on into it), `keys` the
    /// image's [`CertifyingKeys`], `ikek` the decryption IKEK — upstream always
    /// uses [`Ikek::ZenPlus`] (`header_file.py:294-307`).
    pub fn decode_verification(
        &self,
        blob: &SourceBytes,
        keys: &CertifyingKeys,
        ikek: Ikek,
    ) -> Option<DecodeVerification> {
        let (header, key_store) = match &self.class {
            EntryClass::Header(h) => (h, false),
            EntryClass::KeyStore(h) => (h, true),
            _ => return None,
        };
        let window = self.header_file_window(header, blob);
        Some(header.verify_decode(window.as_bytes(), key_store, keys, ikek))
    }

    /// The HeaderFile buffer upstream reads: the entry re-sized to the header's
    /// `rom_size` (`header_file.py:72-75` grows it, `:104-105` pins it). A
    /// shrink is applied by [`HeaderEntry::data_region`]'s `effective_end`; a
    /// grow past the directory-declared size reads on into `blob`, as
    /// upstream's `NestedBuffer` reads on into its parent. Falls back to the
    /// entry body when `blob` does not cover the grown window.
    fn header_file_window(&self, header: &HeaderEntry, blob: &SourceBytes) -> SourceBytes {
        let rom_size = header.rom_size as usize;
        if rom_size > self.body.len() {
            let start = self.body.offset().get();
            if let Some(grown) = blob.subslice_at(start..start.saturating_add(rom_size as u64)) {
                return grown;
            }
        }
        self.body.clone()
    }
}

impl HeaderEntry {
    /// The `_verify_decode` ladder (`header_file.py:198-243`) over the
    /// HeaderFile buffer `file`. `key_store` selects the `KeyStoreFile`
    /// overrides of the signed bytes, signature location and checksummed bytes
    /// (`key_store_file.py:25-26`, `:44-51`).
    fn verify_decode(
        &self,
        file: &[u8],
        key_store: bool,
        keys: &CertifyingKeys,
        ikek: Ikek,
    ) -> DecodeVerification {
        // `header_file.py:200`: the decode runs first.
        let decoded = self.decode_best_effort(file, ikek);
        let body = decoded.as_ref().ok().map(|(bytes, _)| bytes.as_slice());

        // (bytes signed after the header, signature, checksummed bytes)
        let (payload, signature, checksummed) = if key_store {
            // `key_store_file.py:50-51`: header || key_store; `:25-26`.
            let store = self.key_store_slice(file, body);
            (store, self.key_store_signature(file), store)
        } else {
            // `header_file.py:168-170`: (header || body)[:0x100 + size_signed];
            // `:109-110`: the checksummed bytes are the decoded body.
            let covered = body.map(|b| &b[..(self.size_signed as usize).min(b.len())]);
            (covered, self.signature_bytes(file).ok(), body)
        };

        // A KeyStoreFile is always signed (`key_store_file.py:62-64`).
        let signature_check = (key_store || self.is_signed()).then(|| {
            let signed = file
                .get(..HEADER_FILE_LEN)
                .zip(payload)
                .map(|(header, payload)| [header, payload].concat());
            keys.check(&self.signature_fingerprint, signed.as_deref(), signature)
        });

        let sha256_ok = self.has_sha256_checksum()
            && checksummed.is_some_and(|c| Sha256::digest(c).as_slice() == self.sha256_checksum());
        let sha384_ok = self.has_sha384_checksum()
            && checksummed.is_some_and(|c| Sha384::digest(c).as_slice() == self.sha384_checksum());
        let checksum = if self.has_sha256_checksum() {
            Some(ChecksumCheck::Sha256 { ok: sha256_ok })
        } else if self.has_sha384_checksum() {
            Some(ChecksumCheck::Sha384 { ok: sha384_ok })
        } else {
            None
        };

        let method = match &decoded {
            Err(_) => DecodeBasis::DecodeError,
            // `header_file.py:201-202`.
            Ok((_, false)) => DecodeBasis::DecompressFailed,
            Ok((body, true)) => match signature_check {
                // `header_file.py:203-231`: the signed branch.
                Some(SignatureCheck::NoCertifyingKey) => DecodeBasis::SignatureUnresolved,
                Some(SignatureCheck::Error) => DecodeBasis::SignatureError,
                Some(SignatureCheck::Failed) => DecodeBasis::SignatureFailed,
                Some(SignatureCheck::Verified) => {
                    if self.size_signed as usize >= body.len() {
                        DecodeBasis::Signature
                    } else if sha256_ok {
                        DecodeBasis::SignatureSha256
                    } else if sha384_ok {
                        DecodeBasis::SignatureSha384
                    } else {
                        DecodeBasis::SignaturePartial
                    }
                }
                // `header_file.py:232-243`: unsigned.
                None if self.has_sha256_checksum() => {
                    if sha256_ok {
                        DecodeBasis::Sha256
                    } else {
                        DecodeBasis::Sha256Failed
                    }
                }
                None if self.has_sha384_checksum() => {
                    if sha384_ok {
                        DecodeBasis::Sha384
                    } else {
                        DecodeBasis::Sha384Failed
                    }
                }
                None if !self.is_encrypted && !self.is_compressed => DecodeBasis::Plain,
                None => DecodeBasis::Unverifiable,
            },
        };

        DecodeVerification {
            method,
            encrypted: self.is_encrypted,
            signature: signature_check,
            checksum,
        }
    }

    /// `KeyStoreFile.key_store` (`key_store_file.py:36-42`): the decoded body
    /// cut to `size_uncompressed` when compressed, else the raw `body_size`
    /// bytes (header `0x14`, our `size_signed`) after the 0x100-byte header.
    fn key_store_slice<'a>(&self, file: &'a [u8], decoded: Option<&'a [u8]>) -> Option<&'a [u8]> {
        if self.is_compressed {
            decoded?.get(..self.size_uncompressed as usize)
        } else {
            file.get(HEADER_FILE_LEN..HEADER_FILE_LEN.checked_add(self.size_signed as usize)?)
        }
    }

    /// `KeyStoreFile.signature` (`key_store_file.py:44-47`): the bytes from the
    /// end of the key store (`0x100 + body_size`) to the packed size —
    /// `signature_size = packed_size - 0x100 - body_size`, falling back to the
    /// buffer size when `packed_size == 0` (`key_store_file.py:126-130`).
    fn key_store_signature<'a>(&self, file: &'a [u8]) -> Option<&'a [u8]> {
        let start = HEADER_FILE_LEN.checked_add(self.size_signed as usize)?;
        let end = self.effective_end(file).ok()?;
        file.get(start..end)
    }
}

/// Length of the `$KDB` key-store header and of each key-store key header
/// (`key_store_file.py:142`, `:187`).
const KDB_HEADER_LEN: usize = 0x50;

/// RSA public exponent every key-store key carries (`key_store_file.py:218`).
const KDB_RSA_EXPONENT: u32 = 0x10001;

/// `(key_id, key)` of every key in a `$KDB` key store
/// (`KeyStore.__init__`, `key_store_file.py:144-172`); the key is `None` when
/// its crypto material is not an RSA-2048/4096 modulus
/// (`PublicKeyEntity._from_key_store_key`, `cert_tree.py:172-182`). A store
/// violating one of upstream's structural assertions yields no keys — upstream
/// aborts the whole parse there.
fn kdb_keys(store: &[u8]) -> Vec<([u8; 16], Option<RsaPublicKey>)> {
    parse_kdb(store).unwrap_or_default()
}

fn parse_kdb(store: &[u8]) -> Option<Vec<([u8; 16], Option<RsaPublicKey>)>> {
    let header = store.get(..KDB_HEADER_LEN)?;
    // `key_store_file.py:150-159`: size == buffer size, flag == 1, `$KDB`,
    // zero padding.
    if le_u32(header, 0)? as usize != store.len()
        || le_u32(header, 0x4)? != 1
        || header.get(0x8..0xc)? != KDB_MAGIC.as_bytes()
        || header[0xc..].iter().any(|&b| b != 0)
    {
        return None;
    }
    let body = &store[KDB_HEADER_LEN..];
    // `key_store_file.py:164`: `assert body_size > 0`.
    if body.is_empty() {
        return None;
    }
    let mut keys = Vec::new();
    let mut next = 0usize;
    // `key_store_file.py:167-172`.
    while next < body.len() {
        let (size, key) = parse_kdb_key(body, next)?;
        keys.push(key);
        next = next.checked_add(size)?;
    }
    Some(keys)
}

/// One `KeyStoreKey` (`key_store_file.py:189-231`) at `offset` of the store
/// body: its total size and `(key_id, key)`.
type KdbKey = (usize, ([u8; 16], Option<RsaPublicKey>));

fn parse_kdb_key(body: &[u8], offset: usize) -> Option<KdbKey> {
    let size = le_u32(body, offset)? as usize;
    let key = body.get(offset..offset.checked_add(size)?)?;
    let header = key.get(..KDB_HEADER_LEN)?;
    let modulus = &key[KDB_HEADER_LEN..];
    // `:204` non-empty crypto material; `:212`/`:240` flag == 1; `:215` id <
    // 0x100; `:218` exponent 0x10001; `:223` key_size == crypto bits;
    // `:226-231` zero padding whose last byte is 0, 1 or 2.
    if modulus.is_empty()
        || le_u32(header, 0x4)? != 1
        || le_u32(header, 0x8)? >= 0x100
        || le_u32(header, 0xc)? != KDB_RSA_EXPONENT
        || le_u32(header, 0x20)? as usize != modulus.len().checked_mul(8)?
        || header[0x24..0x4f].iter().any(|&b| b != 0)
        || header[0x4f] > 2
    {
        return None;
    }
    let mut key_id = [0u8; 16];
    key_id.copy_from_slice(&header[0x10..0x20]);
    // `cert_tree.py:175-180`: only 2048/4096-bit keys; `crypto.py:223-225`:
    // modulus-only material, little-endian, exponent 0x10001.
    let rsa = matches!(modulus.len(), 0x100 | 0x200)
        .then(|| {
            RsaPublicKey::new(
                BigUint::from_bytes_le(modulus),
                BigUint::from(KDB_RSA_EXPONENT),
            )
            .ok()
        })
        .flatten();
    Some((size, (key_id, rsa)))
}

/// Little-endian `u32` at `offset`, `None` past the end.
fn le_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset.checked_add(4)?)?;
    raw.try_into().ok().map(u32::from_le_bytes)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Find the offset of the first zlib stream within `plaintext`, scanning
/// either the §6 search window (first 0x500 bytes) or the entire plaintext
/// if it is shorter than the window. PSPTool short-circuits at offset 0x100
/// (the most common location for HeaderFiles); we mirror that to preserve
/// behaviour on corpus images that have padding before the stream.
fn find_zlib_start(plaintext: &[u8]) -> Result<usize, BodyError> {
    let window = ZLIB_SEARCH_WINDOW.min(plaintext.len());
    if window < 2 {
        return Err(BodyError::ZlibMagicMissing {
            window: ZLIB_SEARCH_WINDOW,
        });
    }
    // PSPTool's `zlib_find_header` short-circuits when one of the magics sits
    // at exactly 0x100 (the BIOS-microcode glue case). We honor the same
    // shortcut, but only as an optimisation — the linear scan would find it
    // anyway.
    if plaintext.len() >= 0x102 {
        let m = &plaintext[0x100..0x102];
        if ZLIB_MAGICS.iter().any(|expected| m == expected) {
            return Ok(0x100);
        }
    }
    for i in 0..window - 1 {
        let m = &plaintext[i..i + 2];
        if ZLIB_MAGICS.iter().any(|expected| m == expected) {
            return Ok(i);
        }
    }
    Err(BodyError::ZlibMagicMissing {
        window: ZLIB_SEARCH_WINDOW,
    })
}

/// `zlib.decompress(s)` (`utils.py:250`): inflate one complete zlib stream,
/// ignoring any bytes after its end, and fail (`None`) on a corrupt OR
/// truncated stream — Python raises `incomplete or truncated stream` there.
/// `flate2`'s `Read` adapter returns the partial output of a truncated stream
/// as success, so drive [`Decompress`] directly and demand `StreamEnd`.
fn zlib_decompress_strict(stream: &[u8]) -> Option<Vec<u8>> {
    let mut inflater = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    loop {
        if out.len() == out.capacity() {
            out.reserve(out.capacity().max(0x1000));
        }
        let (in_before, out_before) = (inflater.total_in(), inflater.total_out());
        let rest = stream.get(usize::try_from(in_before).ok()?..)?;
        match inflater.decompress_vec(rest, &mut out, FlushDecompress::None) {
            Ok(Status::StreamEnd) => return Some(out),
            Ok(Status::Ok | Status::BufError) => {
                let stalled =
                    inflater.total_in() == in_before && inflater.total_out() == out_before;
                // No progress with output room left: the input ran out before
                // the stream ended.
                if stalled && out.len() < out.capacity() {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
}

/// `RsaPublicKey.verify_blob` (`crypto.py:247-258`): RSA-PSS under the KEY's
/// hash — SHA-256 for a 2048-bit key, SHA-384 for 4096 (`crypto.py:189-194`)
/// — and `false` for any mismatch (`except InvalidSignature: return False`),
/// including a signature whose length is not the key's.
fn verify_blob(key: &RsaPublicKey, signed: &[u8], signature: &[u8]) -> bool {
    match key.size() {
        0x100 => verify_pss::<Sha256>(key, signed, signature).is_ok(),
        0x200 => verify_pss::<Sha384>(key, signed, signature).is_ok(),
        _ => false,
    }
}

fn verify_pss<D>(
    public_key: &RsaPublicKey,
    signed: &[u8],
    signature_be: &[u8],
) -> Result<(), VerifyError>
where
    D: sha2::Digest + Clone + sha2::digest::FixedOutputReset + 'static,
    D: rsa::signature::digest::const_oid::AssociatedOid,
{
    let key: PssVerifyingKey<D> = PssVerifyingKey::new(public_key.clone());
    let sig = PssSignature::try_from(signature_be).map_err(|_| VerifyError::InvalidSignature)?;
    Verifier::verify(&key, signed, &sig).map_err(|_| VerifyError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::SourceBytes;

    // -- IKEK constants ------------------------------------------------------
    #[test]
    fn ikek_zen_plus_matches_spec() {
        // Sanity: the §5 table gives the bytes verbatim.
        assert_eq!(
            Ikek::ZenPlus.bytes(),
            [
                0x4C, 0x77, 0x63, 0x65, 0x32, 0xFE, 0x4C, 0x6F, 0xD6, 0xB9, 0xD6, 0xD7, 0xB5, 0x1E,
                0xDE, 0x59
            ]
        );
        assert_eq!(
            Ikek::Zen.bytes(),
            [
                0x49, 0x1E, 0x40, 0x1A, 0x40, 0x1E, 0xC1, 0xB2, 0x28, 0x46, 0x00, 0xF0, 0x99, 0xFD,
                0xE8, 0x68
            ]
        );
    }

    // -- find_zlib_start -----------------------------------------------------
    #[test]
    fn find_zlib_start_at_zero() {
        assert_eq!(find_zlib_start(&[0x78, 0x9C, 0xAA, 0xBB]).unwrap(), 0);
        assert_eq!(find_zlib_start(&[0x78, 0xDA, 0xAA]).unwrap(), 0);
        assert_eq!(find_zlib_start(&[0x78, 0x5E, 0xAA]).unwrap(), 0);
        assert_eq!(find_zlib_start(&[0x78, 0x01, 0xAA]).unwrap(), 0);
    }

    #[test]
    fn find_zlib_start_in_middle() {
        let mut buf = vec![0u8; 0x40];
        buf[0x20] = 0x78;
        buf[0x21] = 0x9C;
        assert_eq!(find_zlib_start(&buf).unwrap(), 0x20);
    }

    #[test]
    fn find_zlib_start_short_circuit_at_0x100() {
        let mut buf = vec![0xFFu8; 0x110];
        // Put a *different* (also valid) magic earlier so we can prove the
        // 0x100 short-circuit returns 0x100 — but actually a linear scan would
        // also find an earlier match. So instead place magic ONLY at 0x100.
        buf[0x100] = 0x78;
        buf[0x101] = 0x9C;
        // Replace the FF spam with non-magic bytes.
        for b in &mut buf[..0x100] {
            *b = 0x00;
        }
        assert_eq!(find_zlib_start(&buf).unwrap(), 0x100);
    }

    #[test]
    fn find_zlib_start_misses_outside_window() {
        let mut buf = vec![0u8; 0x600];
        buf[0x550] = 0x78;
        buf[0x551] = 0x9C;
        // Outside the 0x500 window → not found.
        assert!(matches!(
            find_zlib_start(&buf).unwrap_err(),
            BodyError::ZlibMagicMissing { .. }
        ));
    }

    // -- decompressed body ---------------------------------------------------
    #[test]
    fn get_decompressed_body_round_trips_micro_fixture() {
        let bytes = psptool_fixtures::micro::header_compressed().to_vec();
        let body = SourceBytes::from_blob(bytes);
        let h = HeaderEntry::parse(&body).unwrap();
        // The data region of `header_compressed` is exactly the zlib stream
        // produced by `flate2::ZlibEncoder` over b"hello, psptool-rs".
        let plaintext = h
            .data_region(body.as_bytes())
            .expect("data region available");
        let out = h.get_decompressed_body(plaintext).unwrap();
        assert_eq!(out, b"hello, psptool-rs");
        assert_eq!(out.len() as u32, h.size_uncompressed);
    }

    #[test]
    fn get_decompressed_body_errors_when_not_compressed() {
        let bytes = psptool_fixtures::micro::header_signed().to_vec();
        let body = SourceBytes::from_blob(bytes);
        let h = HeaderEntry::parse(&body).unwrap();
        let plaintext = h.data_region(body.as_bytes()).unwrap();
        assert!(matches!(
            h.get_decompressed_body(plaintext).unwrap_err(),
            BodyError::NotCompressed
        ));
    }

    #[test]
    fn get_decompressed_body_preserves_pre_zlib_prefix() -> Result<(), Box<dyn std::error::Error>> {
        // Reference (`psptool/utils.py::zlib_decompress`) returns
        // `s[:zlib_start] + zlib.decompress(...)` where `s == output[:zlib_size]`
        // — the pre-magic bytes are part of the output and `zlib_size` is an
        // ABSOLUTE end offset into the data region (`header_file.py:171`).
        // Reuse the committed zlib stream from `header_compressed`, prepend a
        // non-magic prefix, and carry a `zlib_size` that reaches the stream end
        // (`prefix.len() + stream.len()`).
        let bytes = psptool_fixtures::micro::header_compressed().to_vec();
        let fixture = SourceBytes::from_blob(bytes.clone());
        let stream_len = HeaderEntry::parse(&fixture)?.zlib_size as usize;
        // The fixture lays the zlib stream right after the 0x100 header.
        let stream = &bytes[HEADER_FILE_LEN..HEADER_FILE_LEN + stream_len];
        // 32 bytes of non-magic prefix (no 0x78 byte to confuse find_zlib_start).
        let prefix: [u8; 32] = [0x55; 32];
        let mut plaintext = Vec::with_capacity(prefix.len() + stream.len());
        plaintext.extend_from_slice(&prefix);
        plaintext.extend_from_slice(stream);

        // Header carrying `zlib_size` = the absolute end offset of the stream
        // within `plaintext` (prefix included), mirroring `output[:zlib_size]`.
        let mut h = [0u8; HEADER_FILE_LEN];
        h[0x10..0x14].copy_from_slice(b"$PS1");
        h[0x48..0x4C].copy_from_slice(&1u32.to_le_bytes()); // is_compressed
        h[0x54..0x58].copy_from_slice(&(plaintext.len() as u32).to_le_bytes());
        let hdr_src = SourceBytes::from_blob(h.to_vec());
        let hdr = HeaderEntry::parse(&hdr_src)?;

        let out = hdr.get_decompressed_body(&plaintext)?;
        assert_eq!(&out[..prefix.len()], &prefix);
        assert_eq!(&out[prefix.len()..], b"hello, psptool-rs");
        Ok(())
    }

    // -- rom_size truncation -------------------------------------------------
    #[test]
    fn data_region_and_signature_bytes_honor_rom_size_truncation() {
        // Reference (`psptool/header_file.py::_parse`) truncates the entry
        // buffer to `header.rom_size` when it is non-zero. Append trailing
        // garbage past the fixture's `rom_size` and confirm the trailing
        // bytes are NOT treated as part of the data region or signature.
        let bytes = psptool_fixtures::micro::header_signed().to_vec();
        let body = SourceBytes::from_blob(bytes.clone());
        let h = HeaderEntry::parse(&body).unwrap();
        // The committed fixture has rom_size = 0x210 (header + body + sig).
        assert_eq!(h.rom_size, 0x210);
        let mut extended = bytes.clone();
        extended.extend_from_slice(&[0xEE; 0x40]);

        // data_region must stop at rom_size - sig_len = 0x110, not stretch
        // to extended.len() - sig_len = 0x150.
        let dr = h.data_region(&extended).unwrap();
        assert_eq!(dr.len(), 0x10);
        assert_eq!(dr, b"SIGNED-FIXTURE\x00\x00");

        // signature_bytes must live at [rom_size - sig_len, rom_size), not at
        // [extended.len() - sig_len, extended.len()).
        let sig = h.signature_bytes(&extended).unwrap();
        assert_eq!(sig.len(), 0x100);
        assert!(
            sig.iter().all(|&b| b == 0xBB),
            "expected the fixture's 0xBB sig filler, got trailing-garbage region"
        );
    }

    #[test]
    fn rom_size_zero_falls_back_to_body_length() {
        // Build a synthetic header with rom_size explicitly zero and confirm
        // data_region falls back to body.len() (matches docs §4.2: "rom_size
        // == 0 means use the parent entry's size", which here is body.len()).
        let mut h = [0u8; HEADER_FILE_LEN];
        h[0x10..0x14].copy_from_slice(b"$PS1");
        h[0x30..0x34].copy_from_slice(&1u32.to_le_bytes()); // is_signed
        h[0x34..0x38].copy_from_slice(&0u32.to_le_bytes()); // RSA-2048
        // h[0x6C..0x70] left as zero — rom_size == 0 → fallback path.
        let mut out = Vec::new();
        out.extend_from_slice(&h);
        out.extend_from_slice(b"PAYLOAD-DATA-OK_"); // 16-byte body
        out.extend(std::iter::repeat_n(0xCC, 0x100));
        let body = SourceBytes::from_blob(out);
        let parsed = HeaderEntry::parse(&body).unwrap();
        assert_eq!(parsed.rom_size, 0);
        let dr = parsed.data_region(body.as_bytes()).unwrap();
        assert_eq!(dr, b"PAYLOAD-DATA-OK_");
        let sig = parsed.signature_bytes(body.as_bytes()).unwrap();
        assert!(sig.iter().all(|&b| b == 0xCC));
    }

    #[test]
    fn rom_size_larger_than_body_is_rejected() {
        // We cannot zero-extend a borrowed slice, so rom_size > body.len()
        // surfaces as BodyTooSmall (rather than panicking).
        let mut h = [0u8; HEADER_FILE_LEN];
        h[0x10..0x14].copy_from_slice(b"$PS1");
        h[0x30..0x34].copy_from_slice(&1u32.to_le_bytes());
        h[0x34..0x38].copy_from_slice(&0u32.to_le_bytes());
        // rom_size claims a much larger entry than what we actually pass in.
        h[0x6C..0x70].copy_from_slice(&0x1000u32.to_le_bytes());
        let mut out = Vec::new();
        out.extend_from_slice(&h);
        out.extend(std::iter::repeat_n(0u8, 0x110));
        let body = SourceBytes::from_blob(out);
        let parsed = HeaderEntry::parse(&body).unwrap();
        let err = parsed.data_region(body.as_bytes()).unwrap_err();
        assert!(matches!(err, BodyError::BodyTooSmall { .. }));
    }

    // -- decrypted body ------------------------------------------------------
    /// Build a fully-functional encrypted HeaderFile fixture in-memory:
    /// `[header(0x100) | aes_cbc_encrypted(plaintext, entry_key, iv) | sig(0x100)]`,
    /// with `wrapped_key = AES-128-ECB-encrypt(entry_key, ikek)`.
    fn build_encrypted_fixture(
        plaintext: &[u8],
        entry_key: [u8; 16],
        ikek: Ikek,
    ) -> (Vec<u8>, [u8; 16]) {
        use aes::cipher::BlockEncrypt as _;
        use aes::cipher::BlockEncryptMut as _;
        use cbc::Encryptor as CbcEnc;
        type Aes128CbcEnc = CbcEnc<Aes128>;

        assert!(plaintext.len().is_multiple_of(16));
        let iv = [
            0x10u8, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
            0x1E, 0x1F,
        ];
        // Wrap entry_key under the IKEK.
        let cipher = Aes128::new(GenericArray::from_slice(&ikek.bytes()));
        let mut block = GenericArray::clone_from_slice(&entry_key);
        cipher.encrypt_block(&mut block);
        let wrapped: [u8; 16] = block.into();
        // CBC encrypt the plaintext.
        let mut buf = vec![0u8; plaintext.len()];
        let ct = Aes128CbcEnc::new_from_slices(&entry_key, &iv)
            .unwrap()
            .encrypt_padded_b2b_mut::<NoPadding>(plaintext, &mut buf)
            .unwrap();
        let ct_len = ct.len();
        buf.truncate(ct_len);

        // Build the header.
        let mut h = [0u8; HEADER_FILE_LEN];
        h[0x10..0x14].copy_from_slice(b"$PS1");
        // size_signed is the body-signed length (header-EXCLUSIVE); the signed
        // region is header(0x100) || plaintext (signature does not need to match).
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
        (out, wrapped)
    }

    #[test]
    fn get_decrypted_body_round_trips_synthetic_fixture() {
        let plaintext = b"the quick brown fox jumps over !"; // 32 bytes, two AES blocks
        let entry_key = [0xA5u8; 16];
        let (body_bytes, _wrapped) = build_encrypted_fixture(plaintext, entry_key, Ikek::ZenPlus);
        let body = SourceBytes::from_blob(body_bytes);
        let h = HeaderEntry::parse(&body).unwrap();
        assert!(h.is_encrypted);
        let pt = h
            .get_decrypted_body(body.as_bytes(), Ikek::ZenPlus)
            .unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn get_decrypted_body_errors_when_not_encrypted() {
        let bytes = psptool_fixtures::micro::header_signed().to_vec();
        let body = SourceBytes::from_blob(bytes);
        let h = HeaderEntry::parse(&body).unwrap();
        assert!(matches!(
            h.get_decrypted_body(body.as_bytes(), Ikek::ZenPlus)
                .unwrap_err(),
            BodyError::NotEncrypted
        ));
    }

    #[test]
    fn get_decrypted_body_rejects_non_block_aligned_ciphertext() {
        // Build a header that claims is_encrypted with an odd-length data region.
        let plaintext = b"shorter"; // 7 bytes
        let entry_key = [0u8; 16];
        // Don't use build_encrypted_fixture — it asserts block alignment. Hand-craft.
        let mut h = [0u8; HEADER_FILE_LEN];
        h[0x10..0x14].copy_from_slice(b"$PS1");
        h[0x18..0x1C].copy_from_slice(&1u32.to_le_bytes());
        h[0x20..0x30].copy_from_slice(&[1u8; 16]);
        h[0x30..0x34].copy_from_slice(&1u32.to_le_bytes());
        h[0x34..0x38].copy_from_slice(&0u32.to_le_bytes());
        let _ = entry_key;
        let mut out = Vec::new();
        out.extend_from_slice(&h);
        out.extend_from_slice(plaintext);
        out.extend(std::iter::repeat_n(0u8, 0x100));
        let body = SourceBytes::from_blob(out);
        let parsed = HeaderEntry::parse(&body).unwrap();
        let err = parsed
            .get_decrypted_body(body.as_bytes(), Ikek::ZenPlus)
            .unwrap_err();
        assert!(matches!(err, BodyError::InvalidCipherLength(7)));
    }

    // -- signed bytes --------------------------------------------------------
    #[test]
    fn get_signed_bytes_returns_header_plus_plaintext() -> Result<(), Box<dyn std::error::Error>> {
        // size_signed is the BODY-signed length added on top of the full 0x100
        // header (header_file.py:162-164: `file_bytes[:len(header) +
        // size_signed]`). Build an in-memory unencrypted/uncompressed
        // HeaderFile with a 0x10-byte body and size_signed = 0x10; the signed
        // region must be exactly 0x100 (header) + 0x10 (body).
        let mut h = [0u8; HEADER_FILE_LEN];
        h[0x10..0x14].copy_from_slice(b"$PS1");
        h[0x14..0x18].copy_from_slice(&0x10u32.to_le_bytes()); // size_signed = body length
        h[0x30..0x34].copy_from_slice(&1u32.to_le_bytes()); // is_signed
        h[0x34..0x38].copy_from_slice(&0u32.to_le_bytes()); // RSA-2048
        // rom_size = header(0x100) + body(0x10) + sig(0x100).
        h[0x6C..0x70].copy_from_slice(&0x210u32.to_le_bytes());
        let mut blob = Vec::new();
        blob.extend_from_slice(&h);
        blob.extend_from_slice(b"SIGNED-FIXTURE\x00\x00"); // 0x10-byte body
        blob.extend(std::iter::repeat_n(0u8, 0x100)); // signature placeholder
        let body = SourceBytes::from_blob(blob);
        let hdr = HeaderEntry::parse(&body)?;
        let signed = hdr.get_signed_bytes(body.as_bytes(), None)?;
        // 0x100 header + 0x10 signed body.
        assert_eq!(signed.len(), 0x110);
        // First 0x100 bytes are the header verbatim.
        assert_eq!(
            &signed[..HEADER_FILE_LEN],
            &body.as_bytes()[..HEADER_FILE_LEN]
        );
        // The next 0x10 bytes are the (uncompressed, unencrypted) body.
        assert_eq!(&signed[HEADER_FILE_LEN..], b"SIGNED-FIXTURE\x00\x00");
        Ok(())
    }

    // -- pubkey extraction ---------------------------------------------------
    #[test]
    fn pubkey_entry_modulus_and_pubexp_extracted_from_micro_fixture() {
        // The committed `pubkey_v1` micro-fixture has a deterministic byte
        // pattern as its modulus — `(i & 0xFF) for i in 0..256`. That value
        // is even (lowest byte = 0), so it is not a valid RSA modulus and
        // `RsaPublicKey::new` will reject it. We verify byte-level extraction
        // here; the round-trip in `verify_signature_round_trip_rsa2048` covers
        // a real RSA construction.
        let bytes = psptool_fixtures::micro::pubkey_v1().to_vec();
        let body = SourceBytes::from_blob(bytes);
        let p = PubkeyEntry::parse(&body).unwrap();
        // pubexp is little-endian 0x00010001, padded to 256 bytes (high zeros).
        let exp = p.pubexp_bytes().unwrap();
        assert_eq!(exp.len(), 256);
        assert_eq!(&exp[..4], &[0x01, 0x00, 0x01, 0x00]);
        assert!(exp[4..].iter().all(|&b| b == 0));
        // Modulus is 256 bytes, the deterministic `(i & 0xFF)` pattern.
        let modulus = p.modulus_bytes().unwrap();
        assert_eq!(modulus.len(), 256);
        for (i, &b) in modulus.iter().enumerate() {
            assert_eq!(b, (i & 0xFF) as u8);
        }
    }

    // -- verify_signature: RSA-PSS round-trip --------------------------------
    /// Build a signed HeaderFile-shape entry plus a matching PubkeyEntry, with
    /// a freshly generated RSA-2048 key. Returns `(entry_body, pubkey_body)`.
    fn build_signed_rsa2048_fixture() -> (Vec<u8>, Vec<u8>) {
        use rand::SeedableRng;
        use rand::rngs::StdRng;
        use rsa::pss::SigningKey;
        use rsa::signature::{RandomizedSigner, SignatureEncoding};
        use rsa::traits::PublicKeyParts;
        use rsa::{RsaPrivateKey, RsaPublicKey};

        let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_C0DE_F00D);
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate test 2048-bit RSA key");
        let pub_key: RsaPublicKey = priv_key.to_public_key();

        // Build the HeaderFile body (header + 32-byte plaintext + 256-byte sig).
        let plaintext = b"sign me, AMD PSP! 0123456789ABCD"; // 32 bytes
        let header_len = HEADER_FILE_LEN;
        let body_len = plaintext.len();
        let sig_len = 0x100;
        let mut h = [0u8; HEADER_FILE_LEN];
        h[0x10..0x14].copy_from_slice(b"$PS1");
        // size_signed is the body-signed length (header-EXCLUSIVE per
        // header_file.py:162-164 / entry.rs:177).
        h[0x14..0x18].copy_from_slice(&(body_len as u32).to_le_bytes());
        // is_encrypted = 0, is_compressed = 0, is_signed = 1, signature_type = 0.
        h[0x30..0x34].copy_from_slice(&1u32.to_le_bytes());
        h[0x34..0x38].copy_from_slice(&0u32.to_le_bytes());
        h[0x6C..0x70].copy_from_slice(&((header_len + body_len + sig_len) as u32).to_le_bytes());

        // Compose the message we will sign: header || plaintext.
        let mut message = Vec::with_capacity(header_len + body_len);
        message.extend_from_slice(&h);
        message.extend_from_slice(plaintext);

        // RSA-PSS sign with SHA-256, salt_len = 32 (digest length).
        let signing_key = SigningKey::<Sha256>::new(priv_key);
        let sig = signing_key.sign_with_rng(&mut rng, &message);
        // On-disk HeaderFile signature is PLAIN big-endian (I2OSP), not
        // reversed (cert_tree.py:63 plain Signature).
        let sig_disk = sig.to_bytes().to_vec();
        assert_eq!(sig_disk.len(), sig_len);

        let mut entry_body = Vec::with_capacity(header_len + body_len + sig_len);
        entry_body.extend_from_slice(&message);
        entry_body.extend_from_slice(&sig_disk);

        // Build a PubkeyEntry blob: [0x40 header | pubexp(256) | modulus(256)].
        let mut pubkey_body = vec![0u8; 0x40 + 256 + 256];
        pubkey_body[0x00..0x04].copy_from_slice(&1u32.to_le_bytes()); // version
        // key_id / certifying_id: deterministic patterns are fine.
        for (i, b) in pubkey_body[0x04..0x14].iter_mut().enumerate() {
            *b = 0xAA + i as u8;
        }
        for (i, b) in pubkey_body[0x14..0x24].iter_mut().enumerate() {
            *b = 0xBB + i as u8;
        }
        pubkey_body[0x38..0x3C].copy_from_slice(&2048u32.to_le_bytes()); // pubexp_bits
        pubkey_body[0x3C..0x40].copy_from_slice(&2048u32.to_le_bytes()); // modulus_bits

        // pubexp at +0x40 (little-endian, 256-byte slot).
        let e_le = {
            let mut v = pub_key.e().to_bytes_le();
            v.resize(256, 0);
            v
        };
        pubkey_body[0x40..0x40 + 256].copy_from_slice(&e_le);
        // Modulus at +0x40 + 256 (little-endian, 256-byte slot).
        let n_le = {
            let mut v = pub_key.n().to_bytes_le();
            v.resize(256, 0);
            v
        };
        pubkey_body[0x140..0x140 + 256].copy_from_slice(&n_le);

        (entry_body, pubkey_body)
    }

    #[test]
    fn verify_signature_round_trip_rsa2048() {
        let (entry_body, pubkey_body) = build_signed_rsa2048_fixture();
        let entry_src = SourceBytes::from_blob(entry_body.clone());
        let pubkey_src = SourceBytes::from_blob(pubkey_body);
        let header = HeaderEntry::parse(&entry_src).unwrap();
        let pubkey = PubkeyEntry::parse(&pubkey_src).unwrap();
        header
            .verify_signature(entry_src.as_bytes(), &pubkey, None)
            .expect("signature must verify");
    }

    #[test]
    fn verify_signature_rejects_tampered_body() {
        let (mut entry_body, pubkey_body) = build_signed_rsa2048_fixture();
        // Flip a bit in the signed body region.
        entry_body[HEADER_FILE_LEN] ^= 0x01;
        let entry_src = SourceBytes::from_blob(entry_body);
        let pubkey_src = SourceBytes::from_blob(pubkey_body);
        let header = HeaderEntry::parse(&entry_src).unwrap();
        let pubkey = PubkeyEntry::parse(&pubkey_src).unwrap();
        let err = header
            .verify_signature(entry_src.as_bytes(), &pubkey, None)
            .unwrap_err();
        assert!(matches!(err, VerifyError::BadSignature));
    }

    #[test]
    fn verify_signature_rejects_wrong_key_size() {
        // Take a real signed entry (signature_type = 0 = 2048-bit) but feed
        // a pubkey that claims modulus_bits = 4096.
        let (entry_body, mut pubkey_body) = build_signed_rsa2048_fixture();
        pubkey_body[0x3C..0x40].copy_from_slice(&4096u32.to_le_bytes());
        // Resize the buffer so it CAN parse — but values won't match.
        pubkey_body.resize(0x40 + 4096 / 8 + 4096 / 8, 0);
        let entry_src = SourceBytes::from_blob(entry_body);
        let pubkey_src = SourceBytes::from_blob(pubkey_body);
        let header = HeaderEntry::parse(&entry_src).unwrap();
        let pubkey = PubkeyEntry::parse(&pubkey_src).unwrap();
        let err = header
            .verify_signature(entry_src.as_bytes(), &pubkey, None)
            .unwrap_err();
        assert!(matches!(err, VerifyError::KeySizeMismatch { .. }));
    }

    // -- corpus tests (gated) -----------------------------------------------
    /// Resolved corpus root, or `None` if corpus tests should be skipped.
    /// Skips when `PSPTOOL_TEST_CORPUS` is unset, empty, "0", or points at
    /// a path that doesn't exist (the latter happens when the dev shell sets
    /// the env var but the submodule has not been initialised — see
    /// `shell.nix`).
    fn corpus_root() -> Option<std::path::PathBuf> {
        let v = std::env::var("PSPTOOL_TEST_CORPUS").ok()?;
        if v.is_empty() || v == "0" {
            return None;
        }
        let p = std::path::PathBuf::from(v);
        if p.join("test_files").is_dir() {
            Some(p)
        } else {
            None
        }
    }

    #[test]
    fn corpus_aorus_image_present_when_corpus_enabled() {
        let Some(root) = corpus_root() else { return };
        // Cross-check that the env-var-pointed corpus exposes the canonical
        // image we cite throughout `docs/firmware-layout.md` for §1.x and §2.x
        // validation. Real header-decompress / decrypt / verify runs against
        // this corpus are owned by integration tests in #18 — the byte-exact
        // roundtrip + per-class tests above already exercise every code path
        // in this module on synthetic + committed micro-fixtures.
        let aorus = root.join("test_files/AORUS_B450AE.F40");
        assert!(aorus.exists(), "expected AORUS_B450AE.F40 in {root:?}");
    }
}
