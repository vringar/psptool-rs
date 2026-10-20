//! Re-sign a mutated [`Entry`] into a [`BlobEditor`].
//!
//! [`sign_entry`] takes a parsed signed entry, computes the canonical signed
//! region (`HeaderEntry::get_signed_bytes`), produces a fresh RSA-PSS
//! signature with a caller-supplied [`RsaPrivateKey`], and patches the
//! trailing signature region — stored **plain** (big-endian I2OSP), matching
//! upstream's plain HeaderFile `Signature` (`cert_tree.py:63`) — through the
//! diff-and-patch writer.
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
//!   module only writes the entry's own trailing signature region and, when
//!   stale, the entry header's own sha256 (REQ-10).
//!
//! ## REQ status (per `.design/psptool-ops/sign.md`)
//!
//! | REQ | Status | Evidence |
//! |---|---|---|
//! | REQ-1 (signed-region computation) | SHIPPED | `sign.rs:173-188` (`entry.header_file_window(editor.original())`, then `header.get_signed_bytes(file, ikek)?`) delegates to `HeaderEntry::get_signed_bytes` (`header(0x100) || plaintext[..size_signed]`) over the HeaderFile buffer grown to the header and to `rom_size` (`header_file.py:32-33`, `:72-75`; #105), per upstream `header_file.py:168-170`, `cert_tree.py:113`; consumer `psptool-cli/src/cmds/sign.rs:21`. |
//! | REQ-2 (PSS params per signature_type) | SHIPPED | `sign.rs:198-213`: type 0 → `SigningKey::<Sha256>` (salt 32), type 2 → `SigningKey::<Sha384>` (salt 48) per upstream `crypto.py:183-203`; consumer `psptool-cli/src/cmds/sign.rs:21`. |
//! | REQ-3 (fresh valid PSS signature) | SHIPPED | `sign.rs:202-209` (`sign_with_rng`), `sign_entry` seeds `thread_rng` at `sign.rs:132` per upstream `crypto.py:302-307`, `cert_tree.py:113`; verified by `verify::tests::sign_then_verify_round_trip_via_blob_editor`. |
//! | REQ-4 (key-size / type validation) | SHIPPED | `sign.rs:153-166`: `UnsupportedSignatureType` (`sign.rs:156`, `:213`), `KeySizeMismatch` (`sign.rs:161`) per upstream `crypto.py:265`, `cert_tree.py:111-112`; verified by `sign_entry_rejects_wrong_key_size`. |
//! | REQ-5 (reject non-signed entries) | SHIPPED | `sign.rs:147` (`NotSignedEntry`) + `sign.rs:150` (`NotSignedFlag`) per upstream `__main__.py:254-257`, `header_file.py:130-135`; consumer `psptool-cli/src/cmds/sign.rs:16-18`; verified by `sign_entry_rejects_plain_entry`. |
//! | REQ-6 (signature-region locality) | SHIPPED | `sign.rs:224` `editor.patch(FlashOffset(sig_start), ..)` writes only the trailing `sig_len` bytes per upstream `cert_tree.py:117`, plus the 32-byte header checksum at `sign.rs:227` when REQ-10 refreshes it; verified by `sign_entry_patches_only_signature_region`, `sign_entry_keeps_a_valid_sha256` and, for grown buffers, `sign_entry_signs_the_buffer_grown_to_rom_size` / `sign_entry_signs_a_zero_size_record`. |
//! | REQ-7 (bounds-safe trailing region) | SHIPPED | `sign.rs:194-196` uses `HeaderEntry::signature_bytes` over the HeaderFile buffer (`rom_size`-normalised, `BodyTooSmall` when `rom_size` runs past the image) per upstream `header_file.py:88`, `:72-75`; verified by `sign_entry_rejects_rom_size_past_the_image`. |
//! | REQ-8 (on-disk byte-order / upstream verify fidelity) | SHIPPED | The signature is written **plain** (big-endian I2OSP), NOT reversed, matching upstream's plain HeaderFile `Signature` (`cert_tree.py:63,98`); the reversed `ReversedSignature` (`crypto.py:386-409`) is PubkeyFile-only. Corpus-proven by `tests/divergence_signature_byte_order.rs` (real signatures verify plain + full-length; reversed/short controls fail) and by the live reference: `psptool-cli/tests/sign_oracle.rs` re-signs the 16 corpus HeaderFiles whose buffer outgrows their directory entry plus 16 controls, and upstream's `SignedEntity.verify_with_pubkey` (`cert_tree.py:97-98`) accepts all 32. Closes #78, #105. |
//! | REQ-9 (CLI `sign` subcommand consumer) | SHIPPED | `psptool-cli/src/cmds/sign.rs:13-32` parses the entry, loads a PKCS#8 PEM key, drives `sign_entry` through a `BlobEditor`, writes the ROM; dispatched from `main.rs:131` per upstream `__main__.py:238-262`. Boundary CLI surface (R-DEFER-1). |
//! | REQ-10 (stale sha256 refreshed before signing) | SHIPPED | `stale_sha256` `sign.rs:240` — when the header's sha256 bit is set and the stored digest (`CHECKSUM_OFFSET` 0xd0) no longer matches the checksummed bytes (decoded body; a KeyStoreFile's key store), the fresh digest goes into the signed header copy (`sign.rs:178-185`) and is patched at `sign.rs:227`, per upstream `resign_only` (`cert_tree.py:103-110`) → `update_sha256` (`header_file.py:119-121`); consumers `psptool-cli/src/cmds/sign.rs:21`, `psptool-cli/src/cmds/replace.rs:59`; verified by `sign_entry_refreshes_a_stale_sha256_after_replace` (replace then sign, #109) and `sign_entry_keeps_a_valid_sha256`. |

use rsa::RsaPrivateKey;
use rsa::pss::SigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256, Sha384};
use thiserror::Error;

use psptool_core::entry::{CHECKSUM_OFFSET, HEADER_FILE_LEN};
use psptool_core::{
    BlobEditor, BodyError, Entry, EntryClass, FlashOffset, HeaderEntry, Ikek, PatchError,
};

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
///   2. A header whose sha256 checksum bit is set but whose stored digest no
///      longer matches its checksummed bytes — a body replaced since — gets
///      the fresh digest first, like upstream's `resign_only`
///      (`cert_tree.py:103-110` → `update_sha256`, `header_file.py:119-121`).
///      The canonical signed bytes (`header || decrypted_decompressed_body[..size_signed]`)
///      are then computed via [`HeaderEntry::get_signed_bytes`] over the
///      HeaderFile buffer, [`Entry::header_file_window`] — the entry grown to
///      its header and to `rom_size`, read from the image `editor` wraps,
///      which must be the one `entry` was parsed from. `ikek` is forwarded —
///      required iff the entry is encrypted.
///   3. We build a [`SigningKey`] over SHA-256 (sig type 0) or SHA-384
///      (sig type 2) and produce a fresh PSS signature with `rng`. Salt
///      length defaults to the digest length, matching PSPTool's
///      `cryptography.hazmat`-based path.
///   4. The signature is patched **plain** (big-endian I2OSP, matching
///      upstream's plain HeaderFile `Signature`, `cert_tree.py:63`) into the
///      buffer's trailing `signature_len()` bytes before `rom_size` via
///      [`BlobEditor::patch`]. Bytes outside the signature region are
///      untouched — a `serialize()` call after this function changes only
///      the signature region and, when step 2 refreshed it, the checksum.
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

    // Upstream signs and patches the HeaderFile buffer, which is grown to the
    // header (`header_file.py:32-33`) and then to `rom_size` (`:74-75`), so it
    // reads on past the directory entry into the image (`cert_tree.py:113`,
    // `:117` over `header_file.py:88`). Cut that window from the image the
    // editor wraps.
    let window = entry
        .header_file_window(editor.original())
        .ok_or(SignError::NotSignedEntry)?;
    let mut file = window.as_bytes().to_vec();
    let key_store = matches!(entry.class, EntryClass::KeyStore(_));
    let checksum = stale_sha256(header, key_store, &file, ikek)?;
    if let Some(digest) = &checksum {
        let len = file.len();
        file.get_mut(CHECKSUM_OFFSET..CHECKSUM_OFFSET + digest.len())
            .ok_or(BodyError::Truncated(len))?
            .copy_from_slice(digest);
    }
    let file = file.as_slice();
    // The signed header carries the refreshed checksum (`cert_tree.py:109`
    // runs before `:113`).
    let signed = header.get_signed_bytes(file, ikek)?;
    // Locate (and validate) the trailing signature region via the vetted
    // core helper. signature_bytes() honours `rom_size`: it falls back to
    // the window length when rom_size==0, and rejects a rom_size past the
    // image as BodyTooSmall — handling the truncation/extension corner cases
    // that an ad-hoc offset computation would have to re-derive.
    let sig_slice = header.signature_bytes(file)?;
    let sig_len = sig_slice.len();
    let offset_in_file = sig_slice.as_ptr() as usize - file.as_ptr() as usize;

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
        other => return Err(SignError::UnsupportedSignatureType(other)),
    };
    if sig_be.len() != sig_len {
        return Err(SignError::SignatureLengthMismatch {
            expected: sig_len,
            got: sig_be.len(),
        });
    }
    // On-disk HeaderFile signature is PLAIN big-endian (I2OSP), not reversed —
    // matches upstream's plain `Signature` (cert_tree.py:63).
    let sig_start = window.offset().get() + offset_in_file as u64;
    editor.patch(FlashOffset(sig_start), sig_be)?;
    if let Some(digest) = checksum {
        let at = window.offset().get() + CHECKSUM_OFFSET as u64;
        editor.patch(FlashOffset(at), digest.to_vec())?;
    }
    Ok(())
}

/// The sha256 `resign_only` writes before signing (`cert_tree.py:103-110`):
/// `None` unless the header has the sha256 checksum bit (`header_file.py:66`)
/// and its stored digest (`:46`, [`CHECKSUM_OFFSET`]) no longer matches the
/// checksummed bytes, else `update_sha256`'s `sha256(get_checksummed_bytes())`
/// (`header_file.py:119-121`). Those bytes are the decrypted, inflated body of
/// a HeaderFile (`:109-110`) and the key store of a KeyStoreFile
/// (`key_store_file.py:25-26`). A sha384 checksum is left as is, as upstream
/// does.
fn stale_sha256(
    header: &HeaderEntry,
    key_store: bool,
    file: &[u8],
    ikek: Option<Ikek>,
) -> Result<Option<[u8; 32]>, SignError> {
    if !header.has_sha256_checksum() {
        return Ok(None);
    }
    let digest: [u8; 32] = if key_store {
        // The key store is decrypted only when it is inflated
        // (`key_store_file.py:39-42`); an unencrypted one needs no IKEK.
        let ikek = match ikek {
            Some(ikek) => ikek,
            None if header.is_encrypted => return Err(BodyError::NotEncrypted.into()),
            None => Ikek::ZenPlus,
        };
        let signed = header.get_key_store_signed_bytes(file, ikek)?;
        Sha256::digest(signed.get(HEADER_FILE_LEN..).unwrap_or_default()).into()
    } else {
        Sha256::digest(header.get_decrypted_decompressed_body(file, ikek)?).into()
    };
    Ok((digest.as_slice() != header.sha256_checksum()).then_some(digest))
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
        let dirs = walk_directories(blob, &fet, RomSize::MIB_16, FlashOffset(0));
        for dir_ref in dirs {
            if let psptool_core::Directory::Psp(p) = &dir_ref.directory {
                for i in 0..p.entries.len() {
                    if let Ok(entry) = Entry::parse_psp(blob, p, i, RomSize::MIB_16, FlashOffset(0))
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
        let entry = Entry::parse_psp(&blob, &dir, 0, RomSize::MIB_16, FlashOffset(0)).unwrap();
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

    /// Shrink the signed HeaderFile's directory record to `record_size` bytes
    /// (its header `rom_size` still covers header + payload + signature),
    /// zero the signature, re-sign, and check the signature lands where
    /// upstream's lives — `rom_size - signature_len` into the buffer grown to
    /// `rom_size` (`header_file.py:32-33`, `:74-75`, `:88`) — and verifies.
    fn resign_record_declaring(record_size: u32) {
        use crate::verify::{VerificationStatus, verify_chain_of_trust};

        let (priv_key, pub_key) = generate_test_keypair();
        let pk = SyntheticPubkey::from_key(&pub_key, [0x9A; 16], [0x9A; 16]);
        let (mut rom, _, header_off, sig_off) =
            build_synthetic_rom_with_signed_entry(&priv_key, &pk, b"grown-buffer");
        let record = {
            let blob = SourceBytes::from_blob(rom.clone());
            let fet = parse_fet(&blob);
            let dirs = walk_directories(&blob, &fet, RomSize::MIB_16, FlashOffset(0));
            let psptool_core::Directory::Psp(dir) = &dirs[0].directory else {
                panic!("synthetic ROM starts with a $PSP directory");
            };
            let record = dir
                .entries
                .iter()
                .find(|r| r.offset.get() as usize == header_off)
                .expect("record of the signed HeaderFile");
            record.source.offset().get() as usize
        };
        rom[record + 4..record + 8].copy_from_slice(&record_size.to_le_bytes());
        rom[sig_off..sig_off + 0x100].fill(0);
        let original = rom.clone();

        let blob = SourceBytes::from_blob(rom);
        let entry = signed_entry_in(&blob);
        assert_eq!(entry.body.len(), record_size as usize);
        let fet = parse_fet(&blob);
        let status = |blob: &SourceBytes| {
            verify_chain_of_trust(blob, &fet, RomSize::MIB_16, FlashOffset(0), Ikek::ZenPlus)
                .into_iter()
                .find(|row| row.body_offset == FlashOffset(header_off as u64))
                .expect("verify row of the signed HeaderFile")
                .status
        };
        assert_eq!(status(&blob), VerificationStatus::BadSignature);

        let mut editor = BlobEditor::from_blob(blob.clone());
        sign_entry(&mut editor, &entry, &priv_key, None).expect("sign the grown buffer");
        let out = editor.serialize();
        for (i, (a, b)) in out.iter().zip(&original).enumerate() {
            if !(sig_off..sig_off + 0x100).contains(&i) {
                assert_eq!(a, b, "byte {i:#06x} differs but is outside sig region");
            }
        }
        assert_eq!(
            status(&SourceBytes::from_blob(out)),
            VerificationStatus::Verified,
            "re-signed HeaderFile does not verify"
        );
    }

    #[test]
    fn sign_entry_signs_the_buffer_grown_to_rom_size() {
        // `header_file.py:74-75`: a `rom_size` past the directory size grows
        // the buffer; the 13 such corpus HeaderFiles failed `BodyTooSmall`
        // (#105).
        resign_record_declaring(0x100);
    }

    #[test]
    fn sign_entry_signs_a_zero_size_record() {
        // `header_file.py:32-33` grows a zero-size record to the header, then
        // `:74-75` to `rom_size`; the 3 such corpus KVM_IMAGE records failed
        // `Truncated` (#105).
        resign_record_declaring(0);
    }

    /// Set the header's sha256-checksum bit — bit 0 of the big-endian
    /// bitfield at `0x58` (`header_file.py:55`, `:66`) — and store `digest`
    /// at `CHECKSUM_OFFSET` (`:46`).
    fn set_sha256(rom: &mut [u8], header_off: usize, digest: &[u8]) {
        rom[header_off + 0x5B] |= 0b01;
        let at = header_off + CHECKSUM_OFFSET;
        rom[at..at + digest.len()].copy_from_slice(digest);
    }

    /// #109, the `replace -s -p` flow (`psptool-cli/src/cmds/replace.rs`):
    /// replace a HeaderFile whose header carries a valid sha256 with the same
    /// header over a new payload, then re-sign. Upstream's `resign_only`
    /// finds `verify_sha256()` false and calls `update_sha256()` before
    /// signing (`cert_tree.py:103-110`, `header_file.py:119-121`), so the
    /// header holds `sha256(new payload)` and the new signature covers that
    /// header. Before #109 the stale digest stayed.
    #[test]
    fn sign_entry_refreshes_a_stale_sha256_after_replace() {
        use crate::verify::{VerificationStatus, verify_chain_of_trust};
        use psptool_core::body::{CertifyingKeys, ChecksumCheck};

        let (priv_key, pub_key) = generate_test_keypair();
        let pk = SyntheticPubkey::from_key(&pub_key, [0x5A; 16], [0x5A; 16]);
        let (mut rom, _, h, sig_off) =
            build_synthetic_rom_with_signed_entry(&priv_key, &pk, b"sha256-then-replace");
        // The data region `[0x100, rom_size - 0x100)` is the checksummed body
        // of this unencrypted, uncompressed HeaderFile (`header_file.py:106`,
        // `:109-110`).
        let payload = h + HEADER_FILE_LEN..sig_off;
        let digest = Sha256::digest(&rom[payload.clone()]);
        set_sha256(&mut rom, h, &digest);
        let checksum = h + CHECKSUM_OFFSET..h + CHECKSUM_OFFSET + 0x20;

        let mut replacement = rom[h..sig_off + 0x100].to_vec();
        for b in &mut replacement[HEADER_FILE_LEN..sig_off - h] {
            *b ^= 0xA5;
        }
        let blob = SourceBytes::from_blob(rom);
        let fet = parse_fet(&blob);
        let dirs = walk_directories(&blob, &fet, RomSize::MIB_16, FlashOffset(0));
        let psptool_core::Directory::Psp(dir) = &dirs[0].directory else {
            panic!("synthetic ROM starts with a $PSP directory");
        };
        let mut editor = BlobEditor::from_blob(blob.clone());
        // Entry 1 is the HeaderFile (`build_synthetic_rom_with_signed_entry`).
        crate::replace_psp_entry_body(
            &mut editor,
            dir,
            1,
            RomSize::MIB_16,
            FlashOffset(0),
            &replacement,
        )
        .expect("replace");
        let replaced = editor.serialize();
        let fresh = Sha256::digest(&replaced[payload]);
        assert_ne!(
            &replaced[checksum.clone()],
            fresh.as_slice(),
            "digest is stale"
        );

        let blob = SourceBytes::from_blob(replaced.clone());
        let entry = signed_entry_in(&blob);
        let mut editor = BlobEditor::from_blob(blob);
        sign_entry(&mut editor, &entry, &priv_key, None).expect("sign");
        let out = editor.serialize();

        assert_eq!(
            &out[checksum.clone()],
            fresh.as_slice(),
            "divergence #109: re-signing must store sha256(new body) like update_sha256"
        );
        for (i, (a, b)) in out.iter().zip(&replaced).enumerate() {
            if !checksum.contains(&i) && !(sig_off..sig_off + 0x100).contains(&i) {
                assert_eq!(a, b, "byte {i:#06x} differs outside checksum and signature");
            }
        }
        let blob = SourceBytes::from_blob(out);
        let entry = signed_entry_in(&blob);
        let checksum_check = entry
            .decode_verification(&blob, &CertifyingKeys::default(), Ikek::ZenPlus)
            .and_then(|v| v.checksum());
        assert_eq!(checksum_check, Some(ChecksumCheck::Sha256 { ok: true }));
        let fet = parse_fet(&blob);
        let status =
            verify_chain_of_trust(&blob, &fet, RomSize::MIB_16, FlashOffset(0), Ikek::ZenPlus)
                .into_iter()
                .find(|row| row.body_offset == FlashOffset(h as u64))
                .expect("verify row of the HeaderFile")
                .status;
        assert_eq!(
            status,
            VerificationStatus::Verified,
            "the new signature must cover the refreshed header"
        );
    }

    /// Control: a sha256 that still matches is left alone (`cert_tree.py:105-106`
    /// `sha256 still valid!`); only the signature changes.
    #[test]
    fn sign_entry_keeps_a_valid_sha256() {
        let (priv_key, pub_key) = generate_test_keypair();
        let pk = SyntheticPubkey::from_key(&pub_key, [0x6B; 16], [0x6B; 16]);
        let (mut rom, _, h, sig_off) =
            build_synthetic_rom_with_signed_entry(&priv_key, &pk, b"sha256-still-valid");
        let digest = Sha256::digest(&rom[h + HEADER_FILE_LEN..sig_off]);
        set_sha256(&mut rom, h, &digest);
        let original = rom.clone();
        let blob = SourceBytes::from_blob(rom);
        let entry = signed_entry_in(&blob);
        let mut editor = BlobEditor::from_blob(blob);
        sign_entry(&mut editor, &entry, &priv_key, None).expect("sign");
        let out = editor.serialize();
        for (i, (a, b)) in out.iter().zip(&original).enumerate() {
            if !(sig_off..sig_off + 0x100).contains(&i) {
                assert_eq!(a, b, "byte {i:#06x} differs outside the signature");
            }
        }
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

    #[test]
    fn sign_entry_rejects_rom_size_past_the_image() {
        // sign_entry must delegate to HeaderEntry::signature_bytes for the
        // trailing-region offset, so a rom_size the image cannot cover is
        // rejected as BodyTooSmall (not silently patched out-of-bounds).
        // Mutate rom_size in the synthetic ROM to run past the image,
        // re-parse, and assert the error surfaces as
        // SignError::Body(BodyError::BodyTooSmall { .. }).
        use psptool_core::BodyError;
        let (priv_key, pub_key) = generate_test_keypair();
        let pk = SyntheticPubkey::from_key(&pub_key, [0xF6; 16], [0xF6; 16]);
        let (mut rom_bytes, _, header_body_off, _) =
            build_synthetic_rom_with_signed_entry(&priv_key, &pk, b"oversized-rom");
        // rom_size lives at header[0x6C..0x70]. Set it far past the 0x1000-byte
        // image; the directory record is unchanged, so the entry still parses.
        let rom_size_off = header_body_off + 0x6C;
        let oversized = u32::MAX / 2;
        rom_bytes[rom_size_off..rom_size_off + 4].copy_from_slice(&oversized.to_le_bytes());

        let blob = SourceBytes::from_blob(rom_bytes);
        let entry = signed_entry_in(&blob);
        let mut editor = BlobEditor::from_blob(blob);
        let err = sign_entry(&mut editor, &entry, &priv_key, None).unwrap_err();
        assert!(
            matches!(err, SignError::Body(BodyError::BodyTooSmall { .. })),
            "expected BodyTooSmall for a rom_size past the image, got {err:?}"
        );
        assert!(editor.is_clean(), "rejected sign must record no patch");
    }
}
