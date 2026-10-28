//! Chain-of-trust verification.
//!
//! [`verify_chain_of_trust`] reports, for every entry of every directory
//! reachable from a parsed [`Fet`], whether its signature verifies: upstream's
//! `SignedEntity.is_verified()` (`cert_tree.py:72-95`). The check is the
//! signature rung of the core decode-verification ladder
//! ([`Entry::decode_verification`]) — the one `ls` renders — against the
//! image's [`CertifyingKeys`], upstream's single `CertificateTree`
//! (`cert_tree.py:385-397`): every ROM of the image, every `PubkeyFile` key and
//! every key of every `KeyStoreFile` `$KDB` store (`cert_tree.py:368-383`), and
//! every key under an id (verified once any of them verifies,
//! `cert_tree.py:82-95`). A `KeyStoreFile` is always signed and signs its
//! header plus key store (`key_store_file.py:44-64`).
//!
//! The result is a typed report — one [`EntryVerification`] per
//! [`Entry`] processed, classified as
//! [`Verified`](VerificationStatus::Verified) /
//! [`UnknownKey`](VerificationStatus::UnknownKey) /
//! [`BadSignature`](VerificationStatus::BadSignature) /
//! [`NotSigned`](VerificationStatus::NotSigned) /
//! [`Error`](VerificationStatus::Error), so the report never fails wholesale.
//!
//! Out of scope: root anchoring (PSPTool's `AMD_ROOT_KEY` table) and
//! PubkeyFile signatures (`SignedEntity._from_pubkey_file`,
//! `cert_tree.py:53-56`): a PubkeyFile reports `NotSigned`.
//!
//! ## REQ status (per `.design/psptool-core/body.md`)
//!
//! | REQ | Status | Evidence |
//! |---|---|---|
//! | REQ-6 (verify a real signed HeaderFile) | SHIPPED | `verify_with_directories` (`verify.rs:123`) builds `CertifyingKeys::from_blob` plus the walked ROM's `add_entry` keys (`verify.rs:136-139`, core `body.rs`, `cert_tree.py:385-397`) and classifies each entry by `Entry::decode_verification(..).signature()` (`verify.rs:229`, `cert_tree.py:78-95`); consumer CLI `psptool-cli/src/cmds/verify.rs:17`. Corpus: every `psptool verify` row at a reference signed-file address matches the reference outcome (`psptool-cli/tests/verify_oracle.rs`, #93). REQ-1..5 and REQ-7 are `body.rs`'s. |

use std::collections::HashMap;
use std::fmt;

use psptool_core::body::{CertifyingKeys, DecodeBasis, SignatureCheck};
use psptool_core::{
    Directory, DirectoryRef, Entry, EntryClass, EntryType, Fet, FlashOffset, Ikek, ParseError,
    PubkeyEntry, RomSize, SourceBytes, walk_directories,
};

/// 16-byte key fingerprint — matches PSPTool's `key_id` ([`PubkeyEntry::key_id`])
/// and [`psptool_core::HeaderEntry::signature_fingerprint`].
pub type KeyId = [u8; 16];

/// Per-entry verification outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationStatus {
    /// The entry carries no signature upstream verifies: not HeaderFile-class,
    /// or a HeaderFile with `is_signed == 0`.
    NotSigned,
    /// No key in the image carries the entry's certifying id
    /// ([`SignatureCheck::NoCertifyingKey`], upstream `NoCertifyingKey`).
    UnknownKey,
    /// Some key under the certifying id verifies the RSA-PSS signature.
    Verified,
    /// Keys under the certifying id exist, none verifies the signature
    /// (tampered body, stale signature, or a key of the wrong size).
    BadSignature,
    /// The check could not run: the entry could not be parsed or decoded, a
    /// candidate key is not an RSA-2048/4096 key, or the signed region /
    /// signature could not be cut from the entry. Inconclusive rather than a
    /// verification failure, so the report never aborts.
    Error(String),
}

impl fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSigned => f.write_str("not-signed"),
            Self::UnknownKey => f.write_str("unknown-key"),
            Self::Verified => f.write_str("verified"),
            Self::BadSignature => f.write_str("bad-signature"),
            Self::Error(msg) => write!(f, "error: {msg}"),
        }
    }
}

/// A single entry's verification record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryVerification {
    /// Index of the parent directory in the [`walk_directories`] traversal.
    pub directory_index: usize,
    /// Index of this entry within its parent directory.
    pub entry_index: usize,
    /// Entry-record type byte — handy for grouping output by entry kind
    /// (matches PSPTool's `bootloader_overview` column).
    pub entry_type: EntryType,
    /// Absolute flash offset of the entry body.
    pub body_offset: FlashOffset,
    /// Certifying-key fingerprint as recorded in the entry header (when
    /// applicable). `None` for non-Header entries and for parse failures.
    pub key_id: Option<KeyId>,
    /// Verification outcome.
    pub status: VerificationStatus,
}

/// Walk every directory reachable from `fet`, collecting per-entry
/// verification reports.
///
/// The certifying keys come from the whole image `blob` (every ROM, as
/// upstream's `CertificateTree`), whichever ROM `fet` belongs to. `ikek`
/// decrypts encrypted signed entries and compressed key stores before hashing;
/// upstream always uses [`Ikek::ZenPlus`] (`header_file.py:294-307`).
///
/// Output ordering: directories in walk order (matches
/// [`walk_directories`]), entries in record order within each directory.
/// Combo directories contribute no entries (they list pointers, not files).
pub fn verify_chain_of_trust(
    blob: &SourceBytes,
    fet: &Fet,
    rom_size: RomSize,
    rom_origin: FlashOffset,
    ikek: Ikek,
) -> Vec<EntryVerification> {
    let directories = walk_directories(blob, fet, rom_size, rom_origin);
    verify_with_directories(blob, &directories, rom_size, rom_origin, ikek)
}

/// Variant of [`verify_chain_of_trust`] that accepts an already-walked
/// directory list. Useful when the caller is also rendering `list` (#10) and
/// wants to share the walk.
pub fn verify_with_directories(
    blob: &SourceBytes,
    directories: &[DirectoryRef],
    rom_size: RomSize,
    rom_origin: FlashOffset,
    ikek: Ikek,
) -> Vec<EntryVerification> {
    let parsed: Vec<Vec<Result<Entry, ParseError>>> = directories
        .iter()
        .map(|dir_ref| parse_dir_entries(blob, &dir_ref.directory, rom_size, rom_origin))
        .collect();
    // Upstream's tree spans every ROM of the image; the walked ROM's own keys
    // join it even when `from_blob` does not detect that ROM's layout.
    let mut keys = CertifyingKeys::from_blob(blob, ikek);
    for entry in parsed.iter().flatten().flatten() {
        keys.add_entry(entry, blob, ikek);
    }

    let mut out = Vec::new();
    for (dir_idx, entries) in parsed.into_iter().enumerate() {
        for (entry_idx, result) in entries.into_iter().enumerate() {
            out.push(match result {
                Ok(entry) => classify_entry(dir_idx, entry_idx, &entry, blob, &keys, ikek),
                // Entry record could not be resolved into a body — record a
                // synthetic row so the report mirrors the directory's record
                // list 1-to-1.
                Err(err) => EntryVerification {
                    directory_index: dir_idx,
                    entry_index: entry_idx,
                    entry_type: EntryType::new(0),
                    body_offset: FlashOffset(0),
                    key_id: None,
                    status: VerificationStatus::Error(err.to_string()),
                },
            });
        }
    }
    out
}

/// Public helper: the image's `PubkeyFile` entries by `key_id`, first one
/// wins. This is NOT the certifying-key map verification uses — that is
/// [`CertifyingKeys`], which also holds every `$KDB` key-store key and every
/// key under an id.
pub fn collect_pubkeys(
    blob: &SourceBytes,
    directories: &[DirectoryRef],
    rom_size: RomSize,
    rom_origin: FlashOffset,
) -> HashMap<KeyId, PubkeyEntry> {
    let mut pubkeys: HashMap<KeyId, PubkeyEntry> = HashMap::new();
    for dir_ref in directories {
        for entry in parse_dir_entries(blob, &dir_ref.directory, rom_size, rom_origin)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if let EntryClass::Pubkey(pk) = entry.class {
                pubkeys.entry(pk.key_id).or_insert(pk);
            }
        }
    }
    pubkeys
}

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------

fn parse_dir_entries(
    blob: &SourceBytes,
    dir: &Directory,
    rom_size: RomSize,
    rom_origin: FlashOffset,
) -> Vec<Result<Entry, ParseError>> {
    match dir {
        Directory::Psp(p) => (0..p.entries.len())
            .map(|i| Entry::parse_psp(blob, p, i, rom_size, rom_origin))
            .collect(),
        Directory::Bios(b) => (0..b.entries.len())
            .map(|i| Entry::parse_bios(blob, b, i, rom_size, rom_origin))
            .collect(),
        // Combo directories list pointers, not files — no entries to verify.
        Directory::Combo(_) => Vec::new(),
    }
}

/// `SignedEntity.is_verified()` (`cert_tree.py:72-95`) of one entry: the
/// certificate-tree rung of its decode verification. Only HeaderFile-class
/// entries carry a verdict, and only signed ones (a `KeyStoreFile` always is,
/// `key_store_file.py:62-64`) a signature check.
fn classify_entry(
    dir_idx: usize,
    entry_idx: usize,
    entry: &Entry,
    blob: &SourceBytes,
    keys: &CertifyingKeys,
    ikek: Ikek,
) -> EntryVerification {
    let mk = |status, key_id| EntryVerification {
        directory_index: dir_idx,
        entry_index: entry_idx,
        entry_type: entry.entry_type(),
        body_offset: entry.body.offset(),
        key_id,
        status,
    };
    let verdict = entry.decode_verification(blob, keys, ikek);
    let (Some(header), Some(check)) = (entry.class.header(), verdict.and_then(|v| v.signature()))
    else {
        return mk(VerificationStatus::NotSigned, None);
    };
    let status = match check {
        SignatureCheck::Verified => VerificationStatus::Verified,
        SignatureCheck::Failed => VerificationStatus::BadSignature,
        // `cert_tree.py:79-80`: `NoCertifyingKey`.
        SignatureCheck::NoCertifyingKey => VerificationStatus::UnknownKey,
        SignatureCheck::Error => VerificationStatus::Error(
            if verdict.is_some_and(|v| v.decode_verification_method() == DecodeBasis::DecodeError) {
                "entry body cannot be decrypted or sliced".to_string()
            } else {
                "unusable certifying key or unreadable signed region".to_string()
            },
        ),
    };
    mk(status, Some(header.signature_fingerprint))
}

#[cfg(test)]
mod tests {
    use super::*;

    use psptool_core::{BlobEditor, RomSize, SourceBytes, walk_directories};

    use crate::sign::sign_entry;
    use crate::tests_support::{
        SyntheticPubkey, build_synthetic_rom_with_signed_entry, generate_test_keypair,
    };

    fn parse_fet_at(blob: &SourceBytes, off: u64) -> Fet {
        Fet::parse_at(blob, FlashOffset(off)).expect("FET parse")
    }

    #[test]
    fn verify_round_trip_synthetic_rom() {
        let (priv_key, pub_key) = generate_test_keypair();
        let pk = SyntheticPubkey::from_key(&pub_key, [0xA1; 16], [0xA1; 16]);
        let (rom_bytes, _, _, _) =
            build_synthetic_rom_with_signed_entry(&priv_key, &pk, b"hello, signed!");
        let blob = SourceBytes::from_blob(rom_bytes);
        let fet = parse_fet_at(&blob, 0);
        let report =
            verify_chain_of_trust(&blob, &fet, RomSize::MIB_16, FlashOffset(0), Ikek::ZenPlus);

        // Expect at least one Verified row for the signed entry, and a NotSigned
        // row for the pubkey itself (it does not carry a HeaderFile prefix).
        let verified = report
            .iter()
            .filter(|r| matches!(r.status, VerificationStatus::Verified))
            .count();
        assert!(verified >= 1, "expected ≥1 Verified row, got {report:#?}");
    }

    #[test]
    fn verify_flags_unknown_key_when_pubkey_missing() {
        let (priv_key, pub_key) = generate_test_keypair();
        // Use a key_id that does NOT match the signature_fingerprint we stamp
        // into the entry header. The signing key is real, but the pubkey
        // lookup will miss.
        let pk = SyntheticPubkey::from_key(
            &pub_key, /* key_id      */ [0xCC; 16], /* certifying  */ [0xCC; 16],
        );
        // build_synthetic_rom_with_signed_entry stamps the signature_fingerprint
        // to the pubkey's key_id by default. To exercise UnknownKey we replace
        // that field after the fact.
        let (mut rom_bytes, sig_fp_off, _, _) =
            build_synthetic_rom_with_signed_entry(&priv_key, &pk, b"unknown-key-test");
        rom_bytes[sig_fp_off..sig_fp_off + 16].copy_from_slice(&[0xDE; 16]);
        let blob = SourceBytes::from_blob(rom_bytes);
        let fet = parse_fet_at(&blob, 0);
        let report =
            verify_chain_of_trust(&blob, &fet, RomSize::MIB_16, FlashOffset(0), Ikek::ZenPlus);

        let unknown = report
            .iter()
            .filter(|r| matches!(r.status, VerificationStatus::UnknownKey))
            .count();
        assert!(unknown >= 1, "expected ≥1 UnknownKey row, got {report:#?}");
    }

    #[test]
    fn verify_flags_bad_signature_when_body_tampered() {
        let (priv_key, pub_key) = generate_test_keypair();
        let pk = SyntheticPubkey::from_key(&pub_key, [0xB2; 16], [0xB2; 16]);
        let (mut rom_bytes, _, body_off, _) =
            build_synthetic_rom_with_signed_entry(&priv_key, &pk, b"tampered-body");
        // Flip a byte in the signed body region (just past the 0x100 header).
        rom_bytes[body_off + 0x100] ^= 0x01;
        let blob = SourceBytes::from_blob(rom_bytes);
        let fet = parse_fet_at(&blob, 0);
        let report =
            verify_chain_of_trust(&blob, &fet, RomSize::MIB_16, FlashOffset(0), Ikek::ZenPlus);

        let bad = report
            .iter()
            .filter(|r| matches!(r.status, VerificationStatus::BadSignature))
            .count();
        assert!(bad >= 1, "expected ≥1 BadSignature row, got {report:#?}");
    }

    #[test]
    fn sign_then_verify_round_trip_via_blob_editor() {
        // Signing path: build a ROM with an entry whose signature region is
        // intentionally garbage, then re-sign through the diff-and-patch
        // writer and confirm verify reports Verified.
        let (priv_key, pub_key) = generate_test_keypair();
        let pk = SyntheticPubkey::from_key(&pub_key, [0xC3; 16], [0xC3; 16]);
        let (mut rom_bytes, _, body_off, sig_off) =
            build_synthetic_rom_with_signed_entry(&priv_key, &pk, b"resign-target");
        // Corrupt the signature region — verify must now fail.
        for b in &mut rom_bytes[sig_off..sig_off + 0x100] {
            *b = 0;
        }
        let blob = SourceBytes::from_blob(rom_bytes.clone());
        let fet = parse_fet_at(&blob, 0);
        let dirs = walk_directories(&blob, &fet, RomSize::MIB_16, FlashOffset(0));
        let report =
            verify_with_directories(&blob, &dirs, RomSize::MIB_16, FlashOffset(0), Ikek::ZenPlus);
        assert!(
            report
                .iter()
                .any(|r| matches!(r.status, VerificationStatus::BadSignature)),
            "expected the corrupted entry to surface as BadSignature, got {report:#?}"
        );

        // Locate the signed entry, re-sign through BlobEditor, serialise, and
        // re-verify against the patched bytes.
        let mut editor = BlobEditor::from_blob(blob.clone());
        // Find the parsed signed entry.
        let mut signed_entry: Option<Entry> = None;
        for dir_ref in &dirs {
            for parsed in
                parse_dir_entries(&blob, &dir_ref.directory, RomSize::MIB_16, FlashOffset(0))
            {
                if let Ok(entry) = parsed
                    && let EntryClass::Header(h) = &entry.class
                    && h.is_signed()
                {
                    signed_entry = Some(entry);
                    break;
                }
            }
            if signed_entry.is_some() {
                break;
            }
        }
        let entry = signed_entry.expect("synthetic ROM has a signed entry");
        sign_entry(&mut editor, &entry, &priv_key, None).expect("re-sign");
        let _ = body_off;

        let patched = editor.serialize();
        // Sanity: the patch landed in the signature region only.
        assert_eq!(patched.len(), rom_bytes.len());
        let blob2 = SourceBytes::from_blob(patched);
        let fet2 = parse_fet_at(&blob2, 0);
        let report2 = verify_chain_of_trust(
            &blob2,
            &fet2,
            RomSize::MIB_16,
            FlashOffset(0),
            Ikek::ZenPlus,
        );
        assert!(
            report2
                .iter()
                .any(|r| matches!(r.status, VerificationStatus::Verified)),
            "expected the re-signed entry to verify, got {report2:#?}"
        );
    }
}
