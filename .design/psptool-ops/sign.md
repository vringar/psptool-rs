# Entry re-signing (RSA-PSS) path (`sign_entry` / `sign` subcommand)

<!--
tier: 3-component
status: draft
baseline-commit: 1c30c53dbaf8a3facc95d5f1202810ef30992c3e
upstream-paths:
  - /tmp/psptool-ref/psptool/crypto.py
  - /tmp/psptool-ref/psptool/header_file.py
  - /tmp/psptool-ref/psptool/cert_tree.py
  - /tmp/psptool-ref/psptool/__main__.py
-->

## Summary

`crates/psptool-ops/src/sign.rs` is the entry re-signing unit — the Rust port of
the reference tool's re-sign flow (`__main__.py:238-262` → `SignedEntity.resign_only`
`cert_tree.py:101-117`). Given a parsed signed [`Entry`], a caller-supplied
[`RsaPrivateKey`], and an optional [`Ikek`], `sign_entry` recomputes the canonical
signed byte region (`HeaderEntry::get_signed_bytes`, the port of
`header_file.py:162-164`), produces a fresh RSA-PSS signature under the hash/salt
selected by `signature_type`, reverses it for on-disk wire order, and patches the
entry's trailing signature region through the byte-exact [`BlobEditor`]. Its
production consumer is the CLI `sign` subcommand (`psptool-cli/src/cmds/sign.rs:13`,
dispatched from `main.rs:127`).

Because RSA-PSS is randomised (`RandomizedSigner`), re-signing is not byte-identical
to upstream — the correctness contract per goal.md R-DEV-7 is preserved-behaviour:
the signature must verify under the same key over the same byte region upstream
signs. The unit's oracle is therefore a **sign→verify roundtrip**, not a
byte-for-byte corpus comparison; its `parity_ops` is `[]` (neither `corpus_roundtrip`
nor the `ls`/`ls_json` `differential` exercises the signing path, both being
read-only). The load-bearing self-oracle is the `psptool-ops` crate lib suite —
`sign::tests::*` (locality + reject guards) and
`verify::tests::sign_then_verify_round_trip_via_blob_editor` (`verify.rs:360`), which
corrupts an entry's signature, re-signs through the editor, and asserts the
serialised ROM verifies.

## Requirements

- REQ-1: **Signed-region computation mirrors upstream.** The bytes fed to the RSA
  signer are `header || get_decrypted_decompressed_body[..size_signed - 0x100]`,
  computed via [`HeaderEntry::get_signed_bytes`], mirroring
  `HeaderFile.get_signed_bytes` (`header_file.py:162-164`
  `file_bytes = header + get_decrypted_decompressed_body(); return
  file_bytes[:len(header) + size_signed]`), the exact blob upstream passes to
  `sign_blob` (`cert_tree.py:113`). `ikek` is forwarded, required iff the entry is
  encrypted.
- REQ-2: **PSS parameters selected by `signature_type` match upstream.** `signature_type
  == 0` → RSA-2048 / SHA-256 / salt = 32 bytes; `signature_type == 2` → RSA-4096 /
  SHA-384 / salt = 48 bytes. Mirrors `RsaKey.__init_subclass__`
  (`crypto.py:189-196`, `key_bits == 2048 → SHA256, salt_length = 32`; `4096 →
  SHA384, salt_length = 48`) and `RsaKey.padding` (`crypto.py:199-203`, `PSS(MGF1(hash),
  salt_length)`). The `rsa::pss::SigningKey::<H>::new` default salt length equals the
  digest length, matching upstream's salt = digest length.
- REQ-3: **A fresh, valid PSS signature is produced.** `sign_entry` builds a
  [`SigningKey`] over the selected hash and signs with a CSPRNG
  (`RandomizedSigner::sign_with_rng`), mirroring `PrivateKey.sign_blob`
  (`crypto.py:302-307` `self._private_key.sign(blob, self.padding(), self.hash_algorithm)`)
  as invoked by `resign_only` (`cert_tree.py:113`). The signature must verify under
  the signing key's public half.
- REQ-4: **Key-size / `signature_type` validation.** An unsupported `signature_type`
  (not 0 or 2) yields `UnsupportedSignatureType`; a private key whose modulus width
  does not match the type's required width yields `KeySizeMismatch`. Mirrors upstream's
  key-size asserts (`crypto.py:265` `assert private_key.key_size == self.key_bits`)
  and the signature-size assert in `resign_only` (`cert_tree.py:111-112`
  `assert self.signature.buffer_size == privkey.signature_size`).
- REQ-5: **Non-signed entries are rejected, not synthesised.** A non-HeaderFile-class
  entry yields `NotSignedEntry`; a HeaderFile-class entry whose header advertises
  `is_signed == 0` yields `NotSignedFlag`. Mirrors upstream refusing to resign an
  unsigned target (`__main__.py:254-257` `if ... file.signed_entity: resign... else:
  print_warning("Did not resign anything since target file is not signed")`) and the
  `is_signed` predicate (`header_file.py:124-129`).
- REQ-6: **Signature-region locality (diff-and-patch).** Re-signing patches *only* the
  entry's trailing `signature_len()` bytes through [`BlobEditor::patch`]; every other
  byte — header, body, sibling entries, directory records — serialises byte-identical
  to the source. Mirrors upstream writing solely into the signature buffer
  (`cert_tree.py:117` `self.signature.set_bytes(0, len(signature), signature)`), a
  `NestedBuffer` view over the trailing `signature_len` bytes (`header_file.py:82`).
- REQ-7: **Trailing region located via the vetted core helper (bounds-safe).** The
  signature offset/length is taken from [`HeaderEntry::signature_bytes`], which honours
  `rom_size` and rejects `rom_size > body.len()` as `BodyTooSmall` rather than patching
  out of bounds. Mirrors the upstream signature `NestedBuffer(self, signature_len,
  rom_size - signature_len)` (`header_file.py:82`) and its `rom_size` normalisation
  (`header_file.py:66-69`).
- REQ-8: **Re-signed output verifies under upstream / real firmware (on-disk byte-order
  fidelity).** A re-signed HeaderFile entry, when read back by the reference PSPTool or
  the AMD bootrom, must verify. The on-disk signature is stored byte-reversed vs. the
  wire RSA-PSS encoding for PubkeyFiles (`docs/firmware-layout.md` §7.1,
  `ReversedSignature` `crypto.py:386-409`); `sign_entry` applies the same reversal to
  HeaderFile signatures. This must be cross-validated against a real signed corpus
  entry.
- REQ-9: **CLI `sign` subcommand production consumer.** The tool exposes re-signing:
  the `sign` subcommand parses the target entry, loads a PKCS#8 PEM private key, drives
  `sign_entry` through a [`BlobEditor`], and writes the serialised ROM to `--outfile`.
  Mirrors the reference re-sign CLI path (`__main__.py:238-262`, `-p/--privkeystub`
  `__main__.py:82`).

## Acceptance criteria

- AC-1 (REQ-3, REQ-1, REQ-2, REQ-6, REQ-7): `verify::tests::sign_then_verify_round_trip_via_blob_editor`
  (`verify.rs:360`) — zero the signature region so verify reports `BadSignature`,
  re-sign via `sign_entry` + `BlobEditor::serialize`, re-parse the patched ROM, and
  assert `verify_chain_of_trust` now reports `Verified`. This is the end-to-end
  sign→verify oracle.
- AC-2 (REQ-6): `sign::tests::sign_entry_patches_only_signature_region` (`sign.rs:248`)
  — after signing, every byte outside `[sig_off, sig_off + 0x100)` equals the original
  and at least one byte inside the region changed.
- AC-3 (REQ-4): `sign::tests::sign_entry_rejects_wrong_key_size` (`sign.rs:279`) —
  signing a `signature_type == 0` entry with a 4096-bit key yields `KeySizeMismatch`
  and `editor.is_clean()`.
- AC-4 (REQ-5): `sign::tests::sign_entry_rejects_plain_entry` (`sign.rs:214`) — a Plain
  entry yields `NotSignedEntry` and records no patch.
- AC-5 (REQ-7): `sign::tests::sign_entry_rejects_rom_size_larger_than_body`
  (`sign.rs:301`) — an inflated `rom_size` surfaces as
  `SignError::Body(BodyError::BodyTooSmall { .. })` with `editor.is_clean()`.
- AC-6 (REQ-9): the `sign` subcommand round-trips a ROM to disk
  (`psptool-cli/src/cmds/sign.rs:13-32`), reachable via `main.rs:127`
  (`Command::Sign(args) => cmds::sign::run(args, out)`).
- AC-7 (REQ-8): open — no green test re-signs a real corpus entry and confirms it
  verifies under the reference PSPTool (blocker #78). The synthetic roundtrip (AC-1)
  proves target-internal sign/verify consistency only, since both apply the same
  reversal.

## REQ status table

| REQ | Status | Evidence |
|---|---|---|
| REQ-1 (signed-region computation) | SHIPPED | Impl `sign.rs:140-141` (`let signed = header.get_signed_bytes(body_bytes, ikek)?`) delegates to `HeaderEntry::get_signed_bytes` (`body.rs:325-351`, `out = header_bytes ++ plaintext[..size_signed - 0x100]`); mirrors `HeaderFile.get_signed_bytes` (`header_file.py:162-164`) — the blob upstream signs at `cert_tree.py:113` (`privkey.sign_blob(self.file.get_signed_bytes())`). Non-test consumer: `psptool-cli/src/cmds/sign.rs:21` → `main.rs:127`. Verification: `sign_then_verify_round_trip_via_blob_editor` (`verify.rs:360`, re-sign then `Verified`). |
| REQ-2 (PSS params per signature_type) | SHIPPED | Impl `sign.rs:151-167`: `signature_type == 0` → `SigningKey::<Sha256>::new` (`sign.rs:153`), `== 2` → `SigningKey::<Sha384>::new` (`sign.rs:160`); the `rsa::pss::SigningKey` default salt = digest length (32 / 48). Mirrors `RsaKey.__init_subclass__` (`crypto.py:189-196` `2048 → SHA256, salt_length = 32`; `4096 → SHA384, salt_length = 48`) and `RsaKey.padding` (`crypto.py:199-203` `PSS(MGF1(hash), salt_length)`). Needed-bits gate `sign.rs:125-129`. Non-test consumer: `psptool-cli/src/cmds/sign.rs:21`. Verification: `sign_then_verify_round_trip_via_blob_editor` (a wrong hash/salt would fail PSS verify). |
| REQ-3 (fresh valid PSS signature) | SHIPPED | Impl `sign.rs:155-157`/`:161-163` (`signing_key.sign_with_rng(rng, &signed).to_bytes()`), `sign_entry` seeds `rand::thread_rng()` (`sign.rs:104`); mirrors `PrivateKey.sign_blob` (`crypto.py:302-307`) invoked by `resign_only` (`cert_tree.py:113`). Non-test consumer: `psptool-cli/src/cmds/sign.rs:21`. Verification: `sign_then_verify_round_trip_via_blob_editor` (`verify.rs:405` re-sign → `verify.rs:414-418` asserts `Verified`). |
| REQ-4 (key-size / type validation) | SHIPPED | Impl `sign.rs:125-138`: `UnsupportedSignatureType` for type ∉ {0,2} (`sign.rs:128`); `KeySizeMismatch` when `priv_key.n().bits() != needed_bits` (`sign.rs:131-138`); plus `SignatureLengthMismatch` guard (`sign.rs:168-173`). Mirrors upstream key-size assert (`crypto.py:265`) and signature-size assert (`cert_tree.py:111-112`). Non-test consumer: `psptool-cli/src/cmds/sign.rs:21` propagates via `?`. Verification: `sign_entry_rejects_wrong_key_size` (`sign.rs:279`, `KeySizeMismatch` + `is_clean`). |
| REQ-5 (reject non-signed entries) | SHIPPED | Impl `sign.rs:117-123`: non-`Header`/`KeyStore` class → `NotSignedEntry` (`sign.rs:119`); `!header.is_signed()` → `NotSignedFlag` (`sign.rs:121-123`). Mirrors upstream refusal (`__main__.py:254-257`) and `is_signed` (`header_file.py:124-129`). Non-test consumer: `psptool-cli/src/cmds/sign.rs:16-18` pre-checks the class and bails, then `:21` propagates. Verification: `sign_entry_rejects_plain_entry` (`sign.rs:214`, `NotSignedEntry` + no patch). |
| REQ-6 (signature-region locality) | SHIPPED | Impl `sign.rs:177-178` (`editor.patch(FlashOffset(sig_start), sig_disk)?`) writes only the trailing `sig_len` bytes; no other byte is patched. Mirrors upstream `self.signature.set_bytes(0, len(signature), signature)` (`cert_tree.py:117`) over the trailing signature `NestedBuffer` (`header_file.py:82`). Non-test consumer: `psptool-cli/src/cmds/sign.rs:21-22` (`sign_entry` then `editor.serialize()`). Verification: `sign_entry_patches_only_signature_region` (`sign.rs:248-276`, only `[sig_off, sig_off+0x100)` differs). |
| REQ-7 (bounds-safe trailing region) | SHIPPED | Impl `sign.rs:147-149` (`let sig_slice = header.signature_bytes(body_bytes)?`) uses `HeaderEntry::signature_bytes` (`body.rs:212-227`), which normalises `rom_size` and returns `BodyTooSmall` when `rom_size > body.len()`; offset derived `sign.rs:149`. Mirrors upstream signature `NestedBuffer(self, signature_len, rom_size - signature_len)` (`header_file.py:82`, `rom_size` normalised `header_file.py:66-69`). Non-test consumer: `psptool-cli/src/cmds/sign.rs:21`. Verification: `sign_entry_rejects_rom_size_larger_than_body` (`sign.rs:301`, `BodyTooSmall` + `is_clean`). |
| REQ-8 (on-disk byte-order / upstream verify fidelity) | NOT-STARTED | open prereq blocker #78. Impl reverses the signature for on-disk order (`sign.rs:174-175` `sig_disk.reverse()`) per `docs/firmware-layout.md` §7.1 (`ReversedSignature`, `crypto.py:386-409`), and target verify reverses to match (`body.rs:390-393`), so the synthetic sign→verify roundtrip is self-consistent — but upstream HeaderFile verifies via a **plain, non-reversed** `Signature` (`cert_tree.py:63` wraps `hf.signature` as `Signature`, not `ReversedSignature`), so a re-signed HeaderFile may not verify under reference PSPTool. No `psptool-ops` test re-signs a real corpus entry and cross-checks it against the reference tool; the claim is unproven end-to-end. |
| REQ-9 (CLI `sign` subcommand consumer) | SHIPPED | Impl `psptool-cli/src/cmds/sign.rs:13-32`: parses the target entry (`:15`), class-guards (`:16-18`), loads a PKCS#8 PEM key (`:19`, `load_priv_key` `:34-41`), drives `sign_entry` through a `BlobEditor` (`:20-21`), and writes the serialised ROM (`:22-24`). Dispatched from `main.rs:127` (`Command::Sign(args) => cmds::sign::run(args, out)`); args in `cli.rs` (`SignArgs`, `cli.rs:256`+). Mirrors the reference re-sign CLI (`__main__.py:238-262`; `-p/--privkeystub` `__main__.py:82`). This IS the boundary CLI surface (goal.md R-DEFER-1). Verification: `cargo test -p psptool-ops --lib` 51 passed; CLI builds and dispatches. |

## Architecture

**Diff-and-patch, driven from the consumer.** `sign.rs` owns no byte buffer; it
records a single patch into a [`BlobEditor`] (`.design/psptool-core/writer.md`). The
only mutation primitive it calls is `BlobEditor::patch` (`sign.rs:178`);
materialisation is the caller's later `editor.serialize()`
(`psptool-cli/src/cmds/sign.rs:22`). This is why REQ-6 locality is structural: the
writer only echoes the caller's absolute coordinates, and `sign_entry` supplies the
exact trailing-region offset (`entry.body.offset() + offset_in_body`, `sign.rs:177`)
and exact length (`signature_bytes(..).len()`, `sign.rs:147-148`).

**Two entry points, one core.** `sign_entry` (`sign.rs:98-105`) is the ergonomic
surface seeding `rand::thread_rng()`; `sign_entry_with_rng` (`sign.rs:110-180`) takes a
caller-controlled `R: CryptoRng + RngCore` for deterministic-seed tests and non-default
CSPRNGs. Both funnel the same invariant order: class guard (`:117-120`) → `is_signed`
guard (`:121-123`) → `signature_type`/key-width validation (`:125-138`) → signed-region
computation (`:140-141`) → trailing-region location (`:147-149`) → PSS sign
(`:151-167`) → length check (`:168-173`) → reverse (`:174-175`) → patch (`:177-178`).

**Signed region vs. signature region are distinct core helpers.**
`HeaderEntry::get_signed_bytes` (`body.rs:325-351`) reconstructs the *input* to the
signer (`header || decrypted_decompressed_body[..size_signed - 0x100]`), while
`HeaderEntry::signature_bytes` (`body.rs:212-227`) locates the *output* region (the
trailing `signature_len` bytes, `rom_size`-normalised). `sign.rs` composes both rather
than re-deriving offsets, so the bounds/truncation corner cases (`rom_size == 0` →
fall back to `body.len()`; `rom_size > body.len()` → `BodyTooSmall`) are handled once
in the vetted core, not duplicated here.

**Hash selection is a compile-time match, not runtime dispatch.** The `signature_type`
match (`sign.rs:151-167`) monomorphises `SigningKey::<Sha256>` vs `SigningKey::<Sha384>`;
the `_ => unreachable!` arm (`sign.rs:166`) is dominated by the earlier
`UnsupportedSignatureType` guard (`sign.rs:128`), so no unvalidated type reaches it.

**Typed error surface.** `SignError` (`sign.rs:35-73`) enumerates `NotSignedEntry`,
`NotSignedFlag`, `UnsupportedSignatureType`, `KeySizeMismatch`,
`SignatureLengthMismatch`, `Body` (`#[from] BodyError`), and `Patch` (`#[from]
PatchError`). No `unwrap`/`expect`/`panic` on the production path (R-CODE-2); the one
`unreachable!` (`sign.rs:166`) is guarded as above. Every reject path returns before any
patch, so a rejected sign leaves `editor.is_clean()` (asserted in the reject tests).

**Crypto via the target ecosystem analog (R-DEV-7).** Upstream uses
`cryptography.hazmat`; the target uses the `rsa` + `sha2` crates. The observable
contract — RSA-PSS with `MGF1(SHAxxx)`, salt = digest length, over the same signed byte
region — is preserved; the implementation differs. The on-disk key format is out of
scope for this unit (callers pass an in-memory [`RsaPrivateKey`]; the CLI loads PKCS#8
PEM at `psptool-cli/src/cmds/sign.rs:34-41`).

## Version-skew note (blocker #61)

The differential oracle is PSPTool 3.4 while the translation source `/tmp/psptool-ref`
is git HEAD. Signing is algorithmic and version-stable: the signed-region definition
(`HeaderFile.get_signed_bytes` `header_file.py:162-164`), the PSS parameter selection
(`crypto.py:189-203`), and the re-sign flow (`cert_tree.py:101-117`) are long-standing
and identical across 3.4/HEAD. No SHIPPED row above depends on a HEAD-only value.
`parity_ops` is `[]` — the signing path is not reached by `corpus_roundtrip` (a
read-parse-reserialize identity check) nor by the `ls`/`ls_json` `differential`; the
unit's oracle is the crate lib suite's sign→verify roundtrip.

The one open item (REQ-8) is **not** a version-skew artifact but an
upstream-convention discrepancy: the target reverses HeaderFile signature bytes on-disk
(applying the §7.1 PubkeyFile `ReversedSignature` convention), whereas upstream wraps a
HeaderFile signature in a plain `Signature` (`cert_tree.py:63`) for both parse and
verify. Target sign and target verify are mutually consistent (both reverse), so the
synthetic roundtrip is green regardless of which convention is physically correct — the
gap is that no real corpus signed HeaderFile has been re-signed and re-verified under
the reference tool to settle it. Tracked by blocker #78.

## Verification

The list below IS the gauntlet for this module; run inside `nix-shell` so
`PSPTOOL_REFERENCE` + `PSPTOOL_TEST_CORPUS` are set (a skipped suite is a red gate, not
a pass).

- `cargo test -p psptool-ops --lib` — **51 passed, 0 failed, 0 ignored**. Covers the
  sign→verify oracle (`verify::tests::sign_then_verify_round_trip_via_blob_editor`,
  REQ-1/REQ-2/REQ-3/REQ-6/REQ-7 end-to-end) and the `sign::tests::*` reject/locality
  pins: `sign_entry_patches_only_signature_region` (REQ-6),
  `sign_entry_rejects_plain_entry` (REQ-5), `sign_entry_rejects_wrong_key_size`
  (REQ-4), `sign_entry_rejects_rom_size_larger_than_body` (REQ-7). This is the module's
  self-oracle; `parity_ops` is `[]`.
- `cargo test -p psptool-core --test corpus_roundtrip` — byte-exact roundtrip on the
  supported corpus (establishes the [`BlobEditor`] the sign path drives is byte-exact).
  Does **not** exercise signing (read-parse-reserialize identity, no mutation).
- `cargo test -p psptool-cli --test differential` — `ls`/`ls_json` structural parity vs
  reference PSPTool. Does **not** exercise the `sign` subcommand (read-only surface).
- Blocker **#78** open (REQ-8 — real-corpus / upstream cross-validation of the
  re-signed HeaderFile on-disk signature byte-order). No re-sign-then-verify-under-
  reference test exists; the synthetic roundtrip proves target-internal consistency
  only.
