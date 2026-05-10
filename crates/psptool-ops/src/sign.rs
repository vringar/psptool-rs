//! Re-sign a mutated [`Entry`] into a [`BlobEditor`].
//!
//! [`sign_entry`] takes a parsed signed entry, computes the canonical signed
//! region (`HeaderEntry::get_signed_bytes`), produces a fresh RSA-PSS
//! signature with a caller-supplied [`RsaPrivateKey`], reverses the
//! signature for on-disk byte-order (`docs/firmware-layout.md` §7.1), and
//! patches the trailing signature region through the diff-and-patch writer.
//!
//! The hash function is selected by `signature_type`:
//!
//! | `signature_type` | Modulus    | Hash    | Sig length |
//! | ---------------- | ---------- | ------- | ---------- |
//! | `0`              | RSA-2048   | SHA-256 | 0x100      |
//! | `2`              | RSA-4096   | SHA-384 | 0x200      |
//!
//! Out of scope (deferred to higher layers):
//! * On-disk private-key formats — callers pass an in-memory [`RsaPrivateKey`].
//! * Chain-of-trust mutation: signing a child does not re-sign its
//!   certifying pubkey. Re-signing every link of the chain is a separate
//!   `psptool-ops` workflow.
//! * Recomputing fletcher / sha checksums elsewhere in the directory: this
//!   module only writes the entry's own trailing signature region.

use rsa::RsaPrivateKey;
use rsa::pss::SigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use sha2::{Sha256, Sha384};
use thiserror::Error;

use psptool_core::{BlobEditor, BodyError, Entry, EntryClass, HeaderEntry, Ikek, PatchError};

/// Errors returned by [`sign_entry`].
#[derive(Debug, Error)]
pub enum SignError {
    /// The entry is not a HeaderFile-class entry — only those carry a
    /// signed-region layout.
    #[error("entry is not a HeaderFile-class signed entry")]
    NotSignedEntry,
    /// `is_signed == 0` — the entry header does not advertise a signature.
    /// Mutating an unsigned entry into a signed one is out of scope: the
    /// caller would need to flip `is_signed` and reserve trailing bytes
    /// first.
    #[error("entry header has is_signed == 0; refusing to write a signature region")]
    NotSignedFlag,
    /// `signature_type` is not 0 (RSA-2048) or 2 (RSA-4096), so we cannot
    /// pick a hash / signature length.
    #[error("unsupported signature_type {0} (expected 0 or 2)")]
    UnsupportedSignatureType(u32),
    /// `RsaPrivateKey` modulus does not match `signature_type`'s required
    /// width (2048 or 4096 bits).
    #[error(
        "private-key modulus is {got_bits} bits, but signature_type {sig_type} requires {needed_bits}"
    )]
    KeySizeMismatch {
        sig_type: u32,
        got_bits: usize,
        needed_bits: usize,
    },
    /// Signing produced a byte string of unexpected length — should never
    /// happen with a correctly-sized RSA key, but we surface it explicitly
    /// rather than panic.
    #[error("signature length mismatch: produced {got} bytes, expected {expected}")]
    SignatureLengthMismatch { expected: usize, got: usize },
    /// Body / signed-region preparation failed (truncated, encrypted entry
    /// without an IKEK, malformed compressed stream, etc.).
    #[error(transparent)]
    Body(#[from] BodyError),
    /// Patch into the [`BlobEditor`] failed (out-of-bounds, overlap with a
    /// previous patch).
    #[error(transparent)]
    Patch(#[from] PatchError),
}

/// Re-sign `entry` and patch the new signature into `editor`.
///
/// Behaviour:
///   1. The entry's class must be [`EntryClass::Header`] or
///      [`EntryClass::KeyStore`] and its header must already advertise
///      `is_signed != 0`. Both predicates exist in PSPTool's reference flow
///      too — we don't synthesise a signature for an unsigned entry.
///   2. The canonical signed bytes (`header || decrypted_decompressed_body[..size_signed]`)
///      are computed via [`HeaderEntry::get_signed_bytes`]. `ikek` is
///      forwarded — required iff the entry is encrypted.
///   3. We build a [`SigningKey`] over SHA-256 (sig type 0) or SHA-384
///      (sig type 2) and produce a fresh PSS signature with `rng`. Salt
///      length defaults to the digest length, matching PSPTool's
///      `cryptography.hazmat`-based path.
///   4. The signature is reversed for on-disk wire order (§7.1) and patched
///      into the entry body's trailing `signature_len()` bytes via
///      [`BlobEditor::patch`]. Bytes outside the signature region are
///      untouched — a `serialize()` call after this function changes only
///      the signature region.
///
/// Determinism note: PSS is randomised, so calling `sign_entry` twice on
/// the same input produces different signature bytes. Both verify against
/// the same pubkey.
pub fn sign_entry(
    editor: &mut BlobEditor,
    entry: &Entry,
    priv_key: &RsaPrivateKey,
    ikek: Option<Ikek>,
) -> Result<(), SignError> {
    sign_entry_with_rng(editor, entry, priv_key, ikek, &mut rand::thread_rng())
}

/// As [`sign_entry`], but with a caller-controlled RNG. Useful in tests
/// (deterministic seed) and in environments that want a non-`thread_rng`
/// CSPRNG.
pub fn sign_entry_with_rng<R: rand::CryptoRng + rand::RngCore>(
    editor: &mut BlobEditor,
    entry: &Entry,
    priv_key: &RsaPrivateKey,
    ikek: Option<Ikek>,
    rng: &mut R,
) -> Result<(), SignError> {
    let header: &HeaderEntry = match &entry.class {
        EntryClass::Header(h) | EntryClass::KeyStore(h) => h,
        _ => return Err(SignError::NotSignedEntry),
    };
    if !header.is_signed() {
        return Err(SignError::NotSignedFlag);
    }

    let needed_bits = match header.signature_type {
        0 => 2048,
        2 => 4096,
        other => return Err(SignError::UnsupportedSignatureType(other)),
    };
    // `n().bits()` is the modulus bit width.
    let got_bits = priv_key.n().bits();
    if got_bits != needed_bits {
        return Err(SignError::KeySizeMismatch {
            sig_type: header.signature_type,
            got_bits,
            needed_bits,
        });
    }

    let signed = header.get_signed_bytes(entry.body.as_bytes(), ikek)?;
    let sig_len = header
        .signature_len()
        .ok_or(SignError::UnsupportedSignatureType(header.signature_type))?;

    let sig_be: Vec<u8> = match header.signature_type {
        0 => {
            let signing_key = SigningKey::<Sha256>::new(priv_key.clone());
            signing_key
                .sign_with_rng(rng, &signed)
                .to_bytes()
                .into_vec()
        }
        2 => {
            let signing_key = SigningKey::<Sha384>::new(priv_key.clone());
            signing_key
                .sign_with_rng(rng, &signed)
                .to_bytes()
                .into_vec()
        }
        _ => unreachable!("signature_type validated above"),
    };
    if sig_be.len() != sig_len {
        return Err(SignError::SignatureLengthMismatch {
            expected: sig_len,
            got: sig_be.len(),
        });
    }
    let mut sig_disk = sig_be;
    sig_disk.reverse();

    // Locate the trailing signature region. `header.signature_bytes` returns
    // a borrowed slice within the entry body; we want the absolute flash
    // offset to feed into the diff-and-patch writer.
    let body_offset = entry.body.offset().get();
    // Effective end honours `rom_size`. If `rom_size == 0`, end == body.len().
    let end = if header.rom_size == 0 {
        entry.body.len() as u64
    } else {
        header.rom_size as u64
    };
    let sig_start = body_offset + (end - sig_len as u64);
    editor.patch(psptool_core::FlashOffset(sig_start), sig_disk)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use psptool_core::{BlobEditor, FlashOffset, RomSize, SourceBytes, walk_directories};

    use crate::tests_support::{
        SyntheticPubkey, build_synthetic_rom_with_signed_entry, generate_test_keypair,
    };

    fn parse_fet(blob: &SourceBytes) -> psptool_core::Fet {
        psptool_core::Fet::parse_at(blob, FlashOffset(0)).expect("FET parse")
    }

    fn signed_entry_in(blob: &SourceBytes) -> Entry {
        let fet = parse_fet(blob);
        let dirs = walk_directories(blob, &fet, RomSize::MIB_16);
        for dir_ref in dirs {
            if let psptool_core::Directory::Psp(p) = &dir_ref.directory {
                for i in 0..p.entries.len() {
                    if let Ok(entry) = Entry::parse_psp(blob, p, i, RomSize::MIB_16)
                        && let EntryClass::Header(h) = &entry.class
                        && h.is_signed()
                    {
                        return entry;
                    }
                }
            }
        }
        panic!("no signed entry in synthetic ROM");
    }

    #[test]
    fn sign_entry_rejects_plain_entry() {
        // Build a synthetic blob with a single Plain entry (no HeaderFile).
        // Reuse the layered ROM from the writer tests — the Type 0x21
        // (WRAPPED_IKEK) entry is Plain.
        let body = vec![0u8; 0x10];
        // Minimal $PSP directory: 1 entry of type 0x21 (Plain), body inside dir.
        let mut buf = vec![0u8; 0x40];
        buf[0..4].copy_from_slice(b"$PSP");
        buf[8..0xC].copy_from_slice(&1u32.to_le_bytes());
        let additional_info: u32 = (1u32 << 31) | (0b10u32 << 24);
        buf[0xC..0x10].copy_from_slice(&additional_info.to_le_bytes());
        // Entry record at +0x10
        buf[0x10] = 0x21; // WRAPPED_IKEK → Plain
        buf[0x14..0x18].copy_from_slice(&(body.len() as u32).to_le_bytes());
        buf[0x18..0x1C].copy_from_slice(&0x20u32.to_le_bytes()); // offset
        let entry_rsv0: u32 = 0b10u32 << 30;
        buf[0x1C..0x20].copy_from_slice(&entry_rsv0.to_le_bytes());
        buf[0x20..0x30].copy_from_slice(&body);
        let blob = SourceBytes::from_blob(buf);
        let dir = match psptool_core::Directory::parse_at(&blob, FlashOffset(0)).unwrap() {
            psptool_core::Directory::Psp(p) => p,
            _ => unreachable!(),
        };
        let entry = Entry::parse_psp(&blob, &dir, 0, RomSize::MIB_16).unwrap();
        assert!(matches!(entry.class, EntryClass::Plain));

        let (priv_key, _) = generate_test_keypair();
        let mut editor = BlobEditor::from_blob(blob);
        let err = sign_entry(&mut editor, &entry, &priv_key, None).unwrap_err();
        assert!(matches!(err, SignError::NotSignedEntry));
        assert!(editor.is_clean(), "rejected sign must record no patch");
    }

    #[test]
    fn sign_entry_patches_only_signature_region() {
        // Build a synthetic ROM, sign it, then assert the only diff vs. the
        // original blob is the trailing signature region.
        let (priv_key, pub_key) = generate_test_keypair();
        let pk = SyntheticPubkey::from_key(&pub_key, [0xD4; 16], [0xD4; 16]);
        let (rom_bytes, _, _, sig_off) =
            build_synthetic_rom_with_signed_entry(&priv_key, &pk, b"locality-test");
        let original = rom_bytes.clone();
        let blob = SourceBytes::from_blob(rom_bytes);
        let entry = signed_entry_in(&blob);
        let mut editor = BlobEditor::from_blob(blob.clone());
        sign_entry(&mut editor, &entry, &priv_key, None).expect("sign");
        let out = editor.serialize();

        // Only bytes in [sig_off, sig_off + 0x100) may differ from the original.
        for (i, (a, b)) in out.iter().zip(&original).enumerate() {
            if !(sig_off..sig_off + 0x100).contains(&i) {
                assert_eq!(a, b, "byte {i:#06x} differs but is outside sig region");
            }
        }
        // And at least one byte inside the sig region differs (the original
        // was zero-filled above; a fresh PSS signature is overwhelmingly
        // unlikely to be all zeros).
        let any_changed = out[sig_off..sig_off + 0x100]
            .iter()
            .zip(&original[sig_off..sig_off + 0x100])
            .any(|(a, b)| a != b);
        assert!(any_changed, "signing did not change the signature region");
    }

    #[test]
    fn sign_entry_rejects_wrong_key_size() {
        // Sign a 2048-bit-typed entry with a 4096-bit key — KeySizeMismatch.
        use rand::SeedableRng;
        let (_priv_2048, pub_key) = generate_test_keypair();
        let pk = SyntheticPubkey::from_key(&pub_key, [0xE5; 16], [0xE5; 16]);
        let (rom_bytes, _, _, _) =
            build_synthetic_rom_with_signed_entry(&_priv_2048, &pk, b"wrong-key-size");
        let blob = SourceBytes::from_blob(rom_bytes);
        let entry = signed_entry_in(&blob);

        let mut rng = rand::rngs::StdRng::seed_from_u64(0xBADF00D);
        let priv_4096 = RsaPrivateKey::new(&mut rng, 4096).expect("4096-bit RSA");
        let mut editor = BlobEditor::from_blob(blob);
        let err = sign_entry(&mut editor, &entry, &priv_4096, None).unwrap_err();
        assert!(
            matches!(err, SignError::KeySizeMismatch { .. }),
            "got {err:?}"
        );
        assert!(editor.is_clean());
    }
}
