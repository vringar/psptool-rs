//! Regression pin: real-firmware HeaderFile signature verification.
//!
//! Guards two divergences (both fixed by #78/#79), each of which alone made a
//! re-signed HeaderFile fail to verify on real AMD hardware. Anchored against
//! `vendor/test-corpus` with RSA-PSS applied to the on-disk bytes as the
//! oracle:
//!
//! ## Divergence A — signed-region length (`HeaderEntry::get_signed_bytes`, #79)
//! Upstream signs `header || get_decrypted_decompressed_body()`, truncated to
//! `len(header) + size_signed` = `0x100 + size_signed` bytes
//! (`header_file.py:162-164`: `file_bytes[:len(self.header) + self.size_signed]`).
//! A prior port truncated the TOTAL to `size_signed` (`0x100` bytes short);
//! `size_signed` is the body-signed length added on top of the full `0x100`
//! header. `get_signed_bytes` now emits `header(0x100) || plaintext[..size_signed]`
//! (total `0x100 + size_signed`), matching upstream. The control's
//! `short_len_plain_ok` guard proves the old short region does NOT verify.
//!
//! ## Divergence B — signature byte-order (verify + `sign_entry`, #78)
//! Upstream wraps a HeaderFile signature in a **plain** `Signature`, NOT
//! `ReversedSignature` (`cert_tree.py:63`
//! `Signature.from_nested_buffer(hf.signature)`), and passes the on-disk bytes
//! straight to RSA verify (`cert_tree.py:98` + `crypto.py:247-258`). A prior
//! port reversed the on-disk bytes in both `verify_signature` and `sign_entry`;
//! both now use the signature PLAIN (standard big-endian I2OSP). The control's
//! `correct_reversed_ok` guard proves the reversed bytes do NOT verify.
//!
//! ## Oracle result (e.g. AORUS_X399AOXT.F5g PSP_FW_BOOT_LOADER, sig_type=0,
//! size_signed=0xa380): with the CORRECT signed length (`0x100+size_signed`)
//! and PLAIN (non-reversed) on-disk signature, RSA-PSS verify = True. Every
//! other combination (reversed, or length==size_signed) = False.
//!
//! Tracking: #78/#79 (REQ-5/REQ-6 of `.design/psptool-core/body.md`, REQ-8 of
//! `.design/psptool-ops/sign.md`). The pin
//! `real_corpus_headerfile_verifies_under_verify_chain_of_trust` (now a plain
//! `#[test]`) is the SHIPPED gate for those REQs.

use psptool_core::{
    Directory, DirectoryRef, Entry, EntryClass, Fet, FlashOffset, HeaderEntry, Ikek, PubkeyEntry,
    RomSize, SourceBytes,
    directory::walk_directories,
    fet::{detect_rom_layout, scan_fet_candidates},
};
use psptool_fixtures::corpus_roms;
use psptool_ops::{VerificationStatus, collect_pubkeys, verify_with_directories};
use rsa::RsaPublicKey;
use rsa::pss::{Signature as PssSignature, VerifyingKey as PssVerifyingKey};
use rsa::signature::Verifier;
use sha2::{Sha256, Sha384};

const HEADER_LEN: usize = 0x100;

fn find_fet(blob: &SourceBytes) -> Option<(Fet, Vec<DirectoryRef>, RomSize, FlashOffset)> {
    for cand in scan_fet_candidates(blob) {
        let Some(layout) = detect_rom_layout(blob, cand) else {
            continue;
        };
        let dirs = walk_directories(blob, &layout.fet, layout.rom_size, layout.rom_origin);
        if !dirs.is_empty() {
            return Some((layout.fet, dirs, layout.rom_size, layout.rom_origin));
        }
    }
    None
}

/// Standard RSA-PSS verify over `signed` with `sig` in big-endian (I2OSP)
/// order — exactly `cryptography.hazmat`'s `public_key.verify(...)` upstream
/// (`crypto.py:247-258`). The oracle is the RSA-PSS algorithm applied to the
/// on-disk bytes, not a value copied from the target.
fn pss_ok(sig_type: u32, pubkey: &RsaPublicKey, signed: &[u8], sig: &[u8]) -> bool {
    match sig_type {
        0 => {
            let key: PssVerifyingKey<Sha256> = PssVerifyingKey::new(pubkey.clone());
            PssSignature::try_from(sig).is_ok_and(|s| Verifier::verify(&key, signed, &s).is_ok())
        }
        2 => {
            let key: PssVerifyingKey<Sha384> = PssVerifyingKey::new(pubkey.clone());
            PssSignature::try_from(sig).is_ok_and(|s| Verifier::verify(&key, signed, &s).is_ok())
        }
        _ => false,
    }
}

struct Located {
    rom_name: String,
    size_signed: u32,
    /// CORRECT (upstream) signed length `0x100+size_signed`, PLAIN signature.
    correct_plain_ok: bool,
    /// CORRECT length, REVERSED signature (must fail — proves the signature is
    /// used PLAIN, not the reversed PubkeyFile convention).
    correct_reversed_ok: bool,
    /// OLD-BUG signed region (total == `size_signed`, i.e. `0x100` bytes
    /// short), PLAIN sig (must fail — proves the full `0x100+size_signed`
    /// length is required; independent regression guard for Divergence A).
    short_len_plain_ok: bool,
    /// Production `get_signed_bytes` (post-fix) length, PLAIN on-disk sig —
    /// exactly what `HeaderEntry::verify_signature` now does internally
    /// (must VERIFY once #78/#79 land).
    prod_plain_ok: bool,
}

/// Compute the upstream signed bytes from PUBLIC core APIs, independent of the
/// (buggy) production `get_signed_bytes`: `header[0x100] || ddb`, truncated to
/// `0x100 + size_signed` (`header_file.py:162-164`).
fn upstream_signed(header: &HeaderEntry, body: &[u8]) -> Option<Vec<u8>> {
    let ddb = header.get_decrypted_decompressed_body(body, None).ok()?;
    let mut full = Vec::with_capacity(HEADER_LEN + ddb.len());
    full.extend_from_slice(&body[..HEADER_LEN]);
    full.extend_from_slice(&ddb);
    let want = HEADER_LEN.checked_add(header.size_signed as usize)?;
    if want > full.len() {
        return None;
    }
    full.truncate(want);
    Some(full)
}

/// The OLD (buggy, pre-#79) signed region: `header[0x100] || ddb` truncated to
/// `size_signed` TOTAL — `0x100` fewer bytes than upstream. Computed here from
/// public core APIs (independent of the now-fixed production `get_signed_bytes`)
/// so the control can keep proving this convention does NOT verify real
/// signatures (Divergence A regression guard).
fn short_len_signed(header: &HeaderEntry, body: &[u8]) -> Option<Vec<u8>> {
    let ddb = header.get_decrypted_decompressed_body(body, None).ok()?;
    let mut full = Vec::with_capacity(HEADER_LEN + ddb.len());
    full.extend_from_slice(&body[..HEADER_LEN]);
    full.extend_from_slice(&ddb);
    let want = header.size_signed as usize; // TOTAL == size_signed (the old bug)
    if want > full.len() {
        return None;
    }
    full.truncate(want);
    Some(full)
}

fn locate_real_headerfile() -> Option<Located> {
    for rom_result in corpus_roms() {
        let Ok(rom) = rom_result else { continue };
        let rom_name = rom.name().to_owned();
        let blob = SourceBytes::from_blob(rom.into_bytes());
        let Some((_fet, dirs, rom_size, rom_origin)) = find_fet(&blob) else {
            continue;
        };
        let pubkeys = collect_pubkeys(&blob, &dirs, rom_size, rom_origin);

        for dir_ref in &dirs {
            let Directory::Psp(psp) = &dir_ref.directory else {
                continue;
            };
            for idx in 0..psp.entries.len() {
                let Ok(entry) = Entry::parse_psp(&blob, psp, idx, rom_size, rom_origin) else {
                    continue;
                };
                let header: &HeaderEntry = match &entry.class {
                    EntryClass::Header(h) | EntryClass::KeyStore(h) => h,
                    _ => continue,
                };
                if !header.is_signed() || (header.signature_type != 0 && header.signature_type != 2)
                {
                    continue;
                }
                let Some(pubkey): Option<&PubkeyEntry> = pubkeys.get(&header.signature_fingerprint)
                else {
                    continue;
                };
                let body = entry.body.as_bytes();
                let Some(correct) = upstream_signed(header, body) else {
                    continue;
                };
                let Some(short) = short_len_signed(header, body) else {
                    continue;
                };
                let Ok(prod) = header.get_signed_bytes(body, None) else {
                    continue;
                };
                let Ok(sig_on_disk) = header.signature_bytes(body) else {
                    continue;
                };
                let Ok(rsa_key) = pubkey.rsa_public_key() else {
                    continue;
                };
                let mut reversed = sig_on_disk.to_vec();
                reversed.reverse();
                let st = header.signature_type;
                let correct_plain_ok = pss_ok(st, &rsa_key, &correct, sig_on_disk);
                if !correct_plain_ok {
                    // Not the right key / encrypted-body mismatch — keep scanning
                    // for an entry we can positively anchor the oracle on.
                    continue;
                }
                return Some(Located {
                    rom_name,
                    size_signed: header.size_signed,
                    correct_plain_ok,
                    correct_reversed_ok: pss_ok(st, &rsa_key, &correct, &reversed),
                    short_len_plain_ok: pss_ok(st, &rsa_key, &short, sig_on_disk),
                    prod_plain_ok: pss_ok(st, &rsa_key, &prod, sig_on_disk),
                });
            }
        }
    }
    None
}

/// CONTROL (must PASS): establishes the real-firmware convention from the
/// on-disk bytes alone. A genuine signed HeaderFile verifies iff the signed
/// region is `0x100 + size_signed` bytes AND the signature is used PLAIN
/// (non-reversed). The two wrong conventions — the `0x100`-short region and
/// the byte reversal — fail, and the now-fixed production `get_signed_bytes`
/// produces bytes that verify. Self-skips when the corpus is absent.
#[test]
fn real_corpus_headerfile_convention_is_nonreversed_and_full_length() {
    let Some(loc) = locate_real_headerfile() else {
        if std::env::var_os("PSPTOOL_TEST_CORPUS").is_some() {
            panic!(
                "PSPTOOL_TEST_CORPUS set but no real signed HeaderFile with an on-image \
                 key verified under ANY combination — cannot anchor the oracle"
            );
        }
        eprintln!("corpus absent — skipping convention control");
        return;
    };
    // The truth: full length + non-reversed verifies.
    assert!(
        loc.correct_plain_ok,
        "[{}] size_signed={:#x}: full-length (0x100+size_signed) NON-reversed must verify \
         (upstream cert_tree.py:63 plain Signature, header_file.py:162-164 length)",
        loc.rom_name, loc.size_signed
    );
    // Axis B: reversing the signature breaks it — proves the HeaderFile
    // signature is used PLAIN (the fixed body.rs verify path drops the reversal).
    assert!(
        !loc.correct_reversed_ok,
        "[{}] reversed signature must NOT verify (plain-signature convention)",
        loc.rom_name
    );
    // Axis A: the OLD `size_signed`-total length (0x100 short) breaks it, even
    // without reversal — proves the full 0x100+size_signed region is required.
    assert!(
        !loc.short_len_plain_ok,
        "[{}] short signed region (total==size_signed) must NOT verify even \
         non-reversed (full 0x100+size_signed length is required)",
        loc.rom_name
    );
    // The fix: the production get_signed_bytes length + PLAIN on-disk signature
    // (exactly what HeaderEntry::verify_signature now does) VERIFIES the real
    // on-disk signature — this is why verify_chain_of_trust now reports Verified.
    assert!(
        loc.prod_plain_ok,
        "[{}] production get_signed_bytes + plain on-disk signature must verify \
         after #78/#79 (body.rs get_signed_bytes = 0x100+size_signed, plain sig)",
        loc.rom_name
    );
}

/// PIN (currently FAILS — divergence #78 + REQ-1): our production
/// `verify_chain_of_trust` verifies ZERO real firmware HeaderFile signatures
/// across the corpus (upstream verifies hundreds). It carries BOTH the
/// shortened signed region (`body.rs:333-349`) and the byte reversal
/// (`body.rs:390-393`) — the same two defects `sign_entry` applies, so
/// re-signed firmware would not verify on real AMD hardware. A correct port
/// must verify at least one real HeaderFile. The companion control proves the
/// on-disk signatures ARE valid under the upstream convention, so this failure
/// is those two divergences, nothing else.
#[test]
fn real_corpus_headerfile_verifies_under_verify_chain_of_trust() {
    let Some(loc) = locate_real_headerfile() else {
        if std::env::var_os("PSPTOOL_TEST_CORPUS").is_some() {
            panic!("PSPTOOL_TEST_CORPUS set but located no real signed HeaderFile");
        }
        eprintln!("corpus absent — skipping");
        return;
    };
    assert!(
        loc.correct_plain_ok,
        "control precondition failed for {}",
        loc.rom_name
    );

    let mut verified_total = 0usize;
    let mut bad_total = 0usize;
    for rom_result in corpus_roms() {
        let Ok(rom) = rom_result else { continue };
        let blob = SourceBytes::from_blob(rom.into_bytes());
        let Some((_fet, dirs, rom_size, rom_origin)) = find_fet(&blob) else {
            continue;
        };
        for r in verify_with_directories(&blob, &dirs, rom_size, rom_origin, Ikek::ZenPlus) {
            match r.status {
                VerificationStatus::Verified => verified_total += 1,
                VerificationStatus::BadSignature => bad_total += 1,
                _ => {}
            }
        }
    }
    eprintln!(
        "verify_chain_of_trust across corpus: {verified_total} Verified, \
         {bad_total} BadSignature"
    );
    assert!(
        verified_total >= 1,
        "verify_chain_of_trust verified {verified_total} real HeaderFile signatures \
         (bad-signature={bad_total}); upstream verifies these. Fix the signed-region \
         length (get_signed_bytes → 0x100+size_signed) AND drop the HeaderFile signature \
         reversal (verify_signature, sign_entry)."
    );
}
