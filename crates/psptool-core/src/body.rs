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
//!
//! The `body` argument is always the entry's full body slice
//! (`[header(0x100) | data | signature]`). Nothing here mutates it.

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockDecryptMut, KeyInit, KeyIvInit, block_padding::NoPadding};
use flate2::read::ZlibDecoder;
use rsa::pss::{Signature as PssSignature, VerifyingKey as PssVerifyingKey};
use rsa::signature::Verifier;
use rsa::{BigUint, RsaPublicKey};
use sha2::{Sha256, Sha384};
use std::io::Read as _;
use thiserror::Error;

use crate::entry::{HEADER_FILE_LEN, HeaderEntry, PUBKEY_HEADER_LEN, PubkeyEntry};

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
        let sig_len = self
            .signature_len()
            .ok_or(BodyError::UnsupportedSignatureType(self.signature_type))?;
        let needed = HEADER_FILE_LEN
            .checked_add(sig_len)
            .ok_or(BodyError::UnsupportedSignatureType(self.signature_type))?;
        if end < needed {
            return Err(BodyError::BodyTooSmall { body: end, needed });
        }
        Ok(&body[HEADER_FILE_LEN..end - sig_len])
    }

    /// Trailing RSA signature bytes. Equivalent to PSPTool's
    /// `body[-signature_len:]` after truncating to `rom_size`. Stored
    /// byte-reversed on disk vs. the wire RSA-PSS encoding (§7.1) —
    /// [`Self::verify_signature`] handles the reversal internally; consumers
    /// that need the wire-order bytes should reverse this slice themselves.
    pub fn signature_bytes<'a>(&self, body: &'a [u8]) -> Result<&'a [u8], BodyError> {
        if body.len() < HEADER_FILE_LEN {
            return Err(BodyError::Truncated(body.len()));
        }
        let end = self.effective_end(body)?;
        let sig_len = self
            .signature_len()
            .ok_or(BodyError::UnsupportedSignatureType(self.signature_type))?;
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
        let stream_start = find_zlib_start(plaintext)?;
        let zlib_size = self.zlib_size as usize;
        let available = plaintext.len() - stream_start;
        if zlib_size > available {
            return Err(BodyError::ZlibSizeOutOfRange {
                size: self.zlib_size as u64,
                start: stream_start,
                available,
            });
        }
        let stream = &plaintext[stream_start..stream_start + zlib_size];
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

    /// Bytes covered by the RSA signature (§4.1): `header || decrypted_decompressed_body[..size_signed]`.
    pub fn get_signed_bytes(&self, body: &[u8], ikek: Option<Ikek>) -> Result<Vec<u8>, BodyError> {
        if body.len() < HEADER_FILE_LEN {
            return Err(BodyError::Truncated(body.len()));
        }
        let header_bytes = &body[..HEADER_FILE_LEN];
        let plaintext = self.get_decrypted_decompressed_body(body, ikek)?;
        // size_signed is "header || decrypted_decompressed_body[..N]" — but
        // the header is already 0x100 bytes, so the body portion is N - 0x100.
        let size_signed = self.size_signed as usize;
        let body_signed =
            size_signed
                .checked_sub(HEADER_FILE_LEN)
                .ok_or(BodyError::SignedRegionOutOfRange(
                    size_signed,
                    plaintext.len() + HEADER_FILE_LEN,
                ))?;
        if body_signed > plaintext.len() {
            return Err(BodyError::SignedRegionOutOfRange(
                size_signed,
                plaintext.len() + HEADER_FILE_LEN,
            ));
        }
        let mut out = Vec::with_capacity(size_signed);
        out.extend_from_slice(header_bytes);
        out.extend_from_slice(&plaintext[..body_signed]);
        Ok(out)
    }

    /// Verify the trailing RSA-PSS signature against `pubkey`. Mirrors
    /// PSPTool's `HeaderFile.verify_signature`. The hash function is selected
    /// per `signature_type` (RSA-2048 → SHA-256, RSA-4096 → SHA-384), and the
    /// on-disk signature bytes are reversed before verification (PSPTool's
    /// `ReversedSignature` adapter — see `docs/firmware-layout.md` §7.1).
    pub fn verify_signature(
        &self,
        body: &[u8],
        pubkey: &PubkeyEntry,
        ikek: Option<Ikek>,
    ) -> Result<(), VerifyError> {
        // Cross-check signature_type (sig length) against the declared modulus
        // width BEFORE building the RSA key — otherwise a mismatch would be
        // reported as InvalidPublicKey, which doesn't match the error taxonomy.
        // PSPTool conflates signature_type with hash + modulus width:
        //   signature_type = 0 → 2048-bit modulus → SHA-256
        //   signature_type = 2 → 4096-bit modulus → SHA-384
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

        // Signed region (decrypted, decompressed if applicable, header + body).
        let signed = self.get_signed_bytes(body, ikek)?;

        // Trailing signature, reversed for wire-order RSA-PSS.
        let sig_on_disk = self.signature_bytes(body).map_err(VerifyError::Body)?;
        let mut sig_be = sig_on_disk.to_vec();
        sig_be.reverse();

        let public_key = pubkey.rsa_public_key()?;

        match self.signature_type {
            0 => verify_pss::<Sha256>(&public_key, &signed, &sig_be),
            2 => verify_pss::<Sha384>(&public_key, &signed, &sig_be),
            _ => unreachable!("checked above"),
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
    fn get_decompressed_body_preserves_pre_zlib_prefix() {
        // Reference (`psptool/utils.py::zlib_decompress`) returns
        // `s[:zlib_start] + zlib.decompress(...)` — the pre-magic bytes are
        // part of the output. Synthesize a plaintext with a non-zero stream
        // start by reusing the committed zlib stream from `header_compressed`
        // and prepending a non-magic prefix.
        let bytes = psptool_fixtures::micro::header_compressed().to_vec();
        let body = SourceBytes::from_blob(bytes.clone());
        let h = HeaderEntry::parse(&body).unwrap();
        let zlib_size = h.zlib_size as usize;
        // The fixture lays the zlib stream right after the 0x100 header.
        let stream = &bytes[HEADER_FILE_LEN..HEADER_FILE_LEN + zlib_size];
        // 32 bytes of non-magic prefix (no 0x78 byte to confuse find_zlib_start).
        let prefix: [u8; 32] = [0x55; 32];
        let mut plaintext = Vec::with_capacity(prefix.len() + stream.len());
        plaintext.extend_from_slice(&prefix);
        plaintext.extend_from_slice(stream);

        let out = h.get_decompressed_body(&plaintext).unwrap();
        assert_eq!(&out[..prefix.len()], &prefix);
        assert_eq!(&out[prefix.len()..], b"hello, psptool-rs");
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
        // size_signed = header || plaintext (signature does not need to match)
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
    fn get_signed_bytes_returns_header_plus_plaintext() {
        let bytes = psptool_fixtures::micro::header_signed().to_vec();
        let body = SourceBytes::from_blob(bytes);
        let h = HeaderEntry::parse(&body).unwrap();
        let signed = h.get_signed_bytes(body.as_bytes(), None).unwrap();
        // size_signed = HEADER_LEN + BODY_LEN = 0x110 (per the fixture builder).
        assert_eq!(signed.len(), 0x110);
        // First 0x100 bytes are the header verbatim.
        assert_eq!(
            &signed[..HEADER_FILE_LEN],
            &body.as_bytes()[..HEADER_FILE_LEN]
        );
        // The next 0x10 bytes are the (uncompressed, unencrypted) body.
        assert_eq!(&signed[HEADER_FILE_LEN..], b"SIGNED-FIXTURE\x00\x00");
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
        h[0x14..0x18].copy_from_slice(&((header_len + body_len) as u32).to_le_bytes());
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
        let sig_be = sig.to_bytes(); // wire-order, big-endian
        // Reverse for on-disk storage (PSPTool's ReversedSignature adapter).
        let mut sig_disk = sig_be.to_vec();
        sig_disk.reverse();
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
