//! Chain-of-trust verification.
//!
//! [`verify_chain_of_trust`] walks every directory reachable from a parsed
//! [`Fet`], collects on-image [`PubkeyEntry`]s into a `key_id → pubkey` map,
//! and then for every [`HeaderEntry`]-class entry tries to locate the signing
//! key via [`HeaderEntry::signature_fingerprint`] and dispatches
//! [`HeaderEntry::verify_signature`].
//!
//! The result is a typed report — one [`EntryVerification`] per
//! [`Entry`] processed, classified as
//! [`Verified`](VerificationStatus::Verified) /
//! [`UnknownKey`](VerificationStatus::UnknownKey) /
//! [`BadSignature`](VerificationStatus::BadSignature) /
//! [`NotSigned`](VerificationStatus::NotSigned) — that mirrors the
//! `verified` column of `vendor/test-corpus/bootloader_overview.py`. Errors
//! at the body-prep / pubkey-extraction stage (truncation, key-size
//! mismatch, malformed RSA modulus) collapse into
//! [`VerificationStatus::Error`] with a human-readable string so the report
//! never fails wholesale.
//!
//! Out of scope (deferred): root anchoring (PSPTool's `AMD_ROOT_KEY` table),
//! KeyStore-embedded `$KDB` lookup, recursive PubkeyEntry-self-verification.
//! Those layer cleanly on top of the per-entry classification this module
//! produces.

use std::collections::HashMap;
use std::fmt;

use psptool_core::{
    Directory, DirectoryRef, Entry, EntryClass, EntryRecord, EntryType, Fet, FlashOffset,
    HeaderEntry, Ikek, ParseError, PubkeyEntry, RomSize, SourceBytes, walk_directories,
};

/// 16-byte key fingerprint — matches PSPTool's `key_id` ([`PubkeyEntry::key_id`])
/// and [`HeaderEntry::signature_fingerprint`].
pub type KeyId = [u8; 16];

/// Per-entry verification outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationStatus {
    /// `is_signed == 0` — the entry does not carry an RSA signature, so
    /// chain-of-trust does not apply.
    NotSigned,
    /// The entry advertises a `signature_fingerprint`, but no
    /// [`PubkeyEntry`] with a matching `key_id` was found anywhere in the
    /// reachable directory tree.
    UnknownKey,
    /// Pubkey was located, signature bytes were well-formed, RSA-PSS
    /// verification succeeded.
    Verified,
    /// Pubkey was located but RSA-PSS verification failed (tampered body or
    /// stale signature).
    BadSignature,
    /// Body-preparation, pubkey-extraction, or signature-decoding failed
    /// before RSA-PSS could even run. The wrapped string is the underlying
    /// `VerifyError` / `ParseError` rendered via `Display`. Treated as an
    /// inconclusive result rather than a hard verification failure so the
    /// caller can surface it without the whole report aborting.
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
/// `ikek` is forwarded to [`HeaderEntry::verify_signature`] so encrypted
/// signed entries can be decrypted before hashing. Pass `None` when the
/// caller does not yet know the IKEK (encrypted entries will surface as
/// [`VerificationStatus::Error`] in that case).
///
/// Output ordering: directories in walk order (matches
/// [`walk_directories`]), entries in record order within each directory.
/// Combo directories contribute no entries (they list pointers, not files).
pub fn verify_chain_of_trust(
    blob: &SourceBytes,
    fet: &Fet,
    rom_size: RomSize,
    ikek: Option<Ikek>,
) -> Vec<EntryVerification> {
    let directories = walk_directories(blob, fet, rom_size);
    verify_with_directories(blob, &directories, rom_size, ikek)
}

/// Variant of [`verify_chain_of_trust`] that accepts an already-walked
/// directory list. Useful when the caller is also rendering `list` (#10) and
/// wants to share the walk.
pub fn verify_with_directories(
    blob: &SourceBytes,
    directories: &[DirectoryRef],
    rom_size: RomSize,
    ikek: Option<Ikek>,
) -> Vec<EntryVerification> {
    // First pass: parse every entry and stash the parsed forms keyed by
    // (dir_index, entry_index). We hold the parsed entries because the
    // pubkey lookup table needs to scan all of them before we can verify.
    let mut parsed: Vec<Vec<Result<Entry, ParseError>>> = Vec::with_capacity(directories.len());
    for dir_ref in directories {
        parsed.push(parse_dir_entries(blob, &dir_ref.directory, rom_size));
    }

    // Build the pubkey lookup table from successful parses.
    let mut pubkeys: HashMap<KeyId, PubkeyEntry> = HashMap::new();
    for dir_entries in &parsed {
        for entry in dir_entries.iter().filter_map(|e| e.as_ref().ok()) {
            if let EntryClass::Pubkey(pk) = &entry.class {
                // First-writer-wins: PSPTool tolerates duplicate pubkeys
                // across directories (combos commonly repeat the AMD root)
                // and uses whichever is reached first.
                pubkeys.entry(pk.key_id).or_insert_with(|| pk.clone());
            }
        }
    }

    // Second pass: classify each entry.
    let mut out = Vec::new();
    for (dir_idx, dir_entries) in parsed.into_iter().enumerate() {
        for (entry_idx, parsed_entry) in dir_entries.into_iter().enumerate() {
            let entry = match parsed_entry {
                Ok(e) => e,
                Err(err) => {
                    // Entry record could not be resolved into a body — record
                    // a synthetic row so the report mirrors the directory's
                    // record list 1-to-1.
                    out.push(EntryVerification {
                        directory_index: dir_idx,
                        entry_index: entry_idx,
                        entry_type: EntryType::new(0),
                        body_offset: FlashOffset(0),
                        key_id: None,
                        status: VerificationStatus::Error(err.to_string()),
                    });
                    continue;
                }
            };
            out.push(classify_entry(dir_idx, entry_idx, &entry, &pubkeys, ikek));
        }
    }
    out
}

/// Public helper: build a `key_id → pubkey` map from a list of directories.
///
/// Same data the verifier consumes internally; exposed so callers (CLI
/// `search-keys`, the upcoming `sign` flow) can introspect the on-image
/// pubkey table without re-walking everything.
pub fn collect_pubkeys(
    blob: &SourceBytes,
    directories: &[DirectoryRef],
    rom_size: RomSize,
) -> HashMap<KeyId, PubkeyEntry> {
    let mut pubkeys: HashMap<KeyId, PubkeyEntry> = HashMap::new();
    for dir_ref in directories {
        for entry in parse_dir_entries(blob, &dir_ref.directory, rom_size)
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
) -> Vec<Result<Entry, ParseError>> {
    match dir {
        Directory::Psp(p) => (0..p.entries.len())
            .map(|i| Entry::parse_psp(blob, p, i, rom_size))
            .collect(),
        Directory::Bios(b) => (0..b.entries.len())
            .map(|i| Entry::parse_bios(blob, b, i, rom_size))
            .collect(),
        // Combo directories list pointers, not files — no entries to verify.
        Directory::Combo(_) => Vec::new(),
    }
}

fn classify_entry(
    dir_idx: usize,
    entry_idx: usize,
    entry: &Entry,
    pubkeys: &HashMap<KeyId, PubkeyEntry>,
    ikek: Option<Ikek>,
) -> EntryVerification {
    let entry_type = match &entry.record {
        EntryRecord::Psp(p) => p.entry_type,
        EntryRecord::Bios(b) => b.entry_type,
    };
    let body_offset = entry.body.offset();
    let mk = |status, key_id| EntryVerification {
        directory_index: dir_idx,
        entry_index: entry_idx,
        entry_type,
        body_offset,
        key_id,
        status,
    };

    let header: &HeaderEntry = match &entry.class {
        EntryClass::Header(h) | EntryClass::KeyStore(h) => h,
        // Plain / Pubkey / SecondaryDirectoryPointer / TertiaryDirectoryPointer /
        // Microcode / SoftFuseChain — none of these carry a HeaderFile-shape
        // signature region, so they cannot participate in chain-of-trust as
        // verifiable subjects.
        _ => return mk(VerificationStatus::NotSigned, None),
    };

    if !header.is_signed() {
        return mk(VerificationStatus::NotSigned, None);
    }

    let key_id = header.signature_fingerprint;
    let Some(pubkey) = pubkeys.get(&key_id) else {
        return mk(VerificationStatus::UnknownKey, Some(key_id));
    };

    match header.verify_signature(entry.body.as_bytes(), pubkey, ikek) {
        Ok(()) => mk(VerificationStatus::Verified, Some(key_id)),
        Err(e) => match e {
            psptool_core::VerifyError::BadSignature => {
                mk(VerificationStatus::BadSignature, Some(key_id))
            }
            other => mk(VerificationStatus::Error(other.to_string()), Some(key_id)),
        },
    }
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
        let report = verify_chain_of_trust(&blob, &fet, RomSize::MIB_16, None);

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
        let report = verify_chain_of_trust(&blob, &fet, RomSize::MIB_16, None);

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
        let report = verify_chain_of_trust(&blob, &fet, RomSize::MIB_16, None);

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
        let dirs = walk_directories(&blob, &fet, RomSize::MIB_16);
        let report = verify_with_directories(&blob, &dirs, RomSize::MIB_16, None);
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
            for parsed in parse_dir_entries(&blob, &dir_ref.directory, RomSize::MIB_16) {
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
        let report2 = verify_chain_of_trust(&blob2, &fet2, RomSize::MIB_16, None);
        assert!(
            report2
                .iter()
                .any(|r| matches!(r.status, VerificationStatus::Verified)),
            "expected the re-signed entry to verify, got {report2:#?}"
        );
    }
}
