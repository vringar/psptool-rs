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
`header_file.py:168-170`) over the HeaderFile buffer grown to `rom_size`, produces a
fresh RSA-PSS signature under the hash/salt selected by `signature_type`, and patches
that buffer's trailing signature region
— stored **plain** (big-endian I2OSP, matching upstream's plain HeaderFile
`Signature`, `cert_tree.py:63`) — through the byte-exact [`BlobEditor`]. Its
production consumer is the CLI `sign` subcommand (`psptool-cli/src/cmds/sign.rs:13`,
dispatched from `main.rs:131`).

Because RSA-PSS is randomised (`RandomizedSigner`), re-signing is not byte-identical
to upstream — the correctness contract per goal.md R-DEV-7 is preserved-behaviour:
the signature must verify under the same key over the same byte region upstream
signs. The unit's oracle is therefore a **sign→verify roundtrip**, not a
byte-for-byte corpus comparison; its `parity_ops` is `[]` (neither `corpus_roundtrip`
nor the `ls`/`ls_json` `differential` exercises the signing path, both being
read-only). The load-bearing self-oracle is the `psptool-ops` crate lib suite —
`sign::tests::*` (locality + reject guards) and
`verify::tests::sign_then_verify_round_trip_via_blob_editor`, which
corrupts an entry's signature, re-signs through the editor, and asserts the
serialised ROM verifies — and the live-reference
`psptool-cli/tests/sign_oracle.rs`, in which upstream verifies corpus files we
re-signed.

## Requirements

- REQ-1: **Signed-region computation mirrors upstream.** The bytes fed to the RSA
  signer are `header(0x100) || get_decrypted_decompressed_body[..size_signed]`
  (total `0x100 + size_signed`), computed via [`HeaderEntry::get_signed_bytes`]
  over the HeaderFile buffer — the entry grown to the `0x100` header and then to
  its `rom_size`, reading on into the image past the directory entry
  (`header_file.py:32-33`, `:72-75`; `Entry::header_file_window`) — mirroring
  `HeaderFile.get_signed_bytes` (`header_file.py:168-170`
  `file_bytes = header + get_decrypted_decompressed_body(); return
  file_bytes[:len(header) + size_signed]`), the exact blob upstream passes to
  `sign_blob` (`cert_tree.py:113`). `ikek` is forwarded, required iff the entry is
  encrypted.
- REQ-2: **PSS parameters selected by `signature_type` match upstream.** `signature_type
  == 0` → RSA-2048 / SHA-256 / salt = 32 bytes; `signature_type == 2` → RSA-4096 /
  SHA-384 / salt = 48 bytes. Mirrors `RsaKey.__init_subclass__`
  (`crypto.py:183-196`, `key_bits == 2048 → SHA256, salt_length = 32`; `4096 →
  SHA384, salt_length = 48`) and `RsaKey.padding` (`crypto.py:198-203`, `PSS(MGF1(hash),
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
  `is_signed` predicate (`header_file.py:130-135`).
- REQ-6: **Signature-region locality (diff-and-patch).** Re-signing patches *only* the
  entry's trailing `signature_len()` bytes through [`BlobEditor::patch`]; every other
  byte — header, body, sibling entries, directory records — serialises byte-identical
  to the source. Mirrors upstream writing solely into the signature buffer
  (`cert_tree.py:117` `self.signature.set_bytes(0, len(signature), signature)`), a
  `NestedBuffer` view over the trailing `signature_len` bytes (`header_file.py:88`).
- REQ-7: **Trailing region located via the vetted core helper (bounds-safe).** The
  signature offset/length is taken from [`HeaderEntry::signature_bytes`] over the
  HeaderFile buffer of REQ-1, which honours `rom_size` and rejects a `rom_size` the
  image cannot cover as `BodyTooSmall` rather than patching out of bounds. Mirrors
  the upstream signature `NestedBuffer(self, signature_len, rom_size -
  signature_len)` (`header_file.py:88`) over the buffer re-sized to `rom_size`
  (`header_file.py:72-75`, `:104-105`).
- REQ-8: **Re-signed output verifies under upstream / real firmware (on-disk byte-order
  fidelity).** A re-signed HeaderFile entry, when read back by the reference PSPTool or
  the AMD bootrom, must verify. A HeaderFile signature is stored **plain** (big-endian
  I2OSP, the wire RSA-PSS encoding) — matching upstream's plain HeaderFile `Signature`
  (`cert_tree.py:63`, verified plain at `cert_tree.py:98`); `sign_entry` writes it plain
  and does **not** reverse it. The byte-reversed `ReversedSignature` convention
  (`docs/firmware-layout.md` §7.1, `crypto.py:386-409`) is PubkeyFile-only and is not
  applied here. This must be cross-validated against a real signed corpus entry (#78,
  now closed).
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
- AC-2 (REQ-6): `sign::tests::sign_entry_patches_only_signature_region` (`sign.rs:274`)
  — after signing, every byte outside `[sig_off, sig_off + 0x100)` equals the original
  and at least one byte inside the region changed.
- AC-3 (REQ-4): `sign::tests::sign_entry_rejects_wrong_key_size` (`sign.rs:379`) —
  signing a `signature_type == 0` entry with a 4096-bit key yields `KeySizeMismatch`
  and `editor.is_clean()`.
- AC-4 (REQ-5): `sign::tests::sign_entry_rejects_plain_entry` (`sign.rs:240`) — a Plain
  entry yields `NotSignedEntry` and records no patch.
- AC-5 (REQ-7): `sign::tests::sign_entry_rejects_rom_size_past_the_image` — a
  `rom_size` past the image surfaces as
  `SignError::Body(BodyError::BodyTooSmall { .. })` with `editor.is_clean()`.
- AC-8 (REQ-1, REQ-6, REQ-7; #105): `sign::tests::sign_entry_signs_the_buffer_grown_to_rom_size`
  and `sign::tests::sign_entry_signs_a_zero_size_record` — a directory record
  declaring fewer bytes than the header's `rom_size` (`0x100`, `0`) re-signs over
  the grown buffer, patches only `[rom_size - 0x100, rom_size)` and verifies; and
  `psptool-cli/tests/sign_oracle.rs` — the reference's own
  `SignedEntity.verify_with_pubkey` (`cert_tree.py:97-98`) accepts every corpus
  HeaderFile whose buffer outgrows its directory entry (16) plus one control per
  image (16), re-signed with keys the reference generated.
- AC-6 (REQ-9): the `sign` subcommand round-trips a ROM to disk
  (`psptool-cli/src/cmds/sign.rs:13-32`), reachable via `main.rs:131`
  (`Command::Sign(args) => cmds::sign::run(args, out)`).
- AC-7 (REQ-8): **Met** — the sign path writes the signature plain (`sign.rs:204`)
  over the full `0x100 + size_signed` region (`body.rs:384`), which is the
  real-firmware on-disk convention proven by
  `divergence_signature_byte_order.rs` (the pin verifies 2993 real corpus
  HeaderFile signatures under exactly that plain/full-length convention; the
  control asserts reversed and short-length both fail). Blocker #78 closed.

## REQ status table

| REQ | Status | Evidence |
|---|---|---|
| REQ-1 (signed-region computation) | SHIPPED | Impl `sign.rs:164-168`: `entry.header_file_window(editor.original())` (`body.rs:867`, the buffer grown to `max(body, 0x100, rom_size)` — `header_file.py:32-33` `if self.buffer_size < 0x100: self.buffer_size = 0x100`, `:74-75` `elif self.rom_size > self.buffer_size: self.buffer_size = self.rom_size`), then `header.get_signed_bytes(file, ikek)?` (`body.rs:384`, `header_bytes ++ plaintext[..size_signed]`, total `0x100 + size_signed`); mirrors `HeaderFile.get_signed_bytes` (`header_file.py:168-170`) — the blob upstream signs at `cert_tree.py:113` (`privkey.sign_blob(self.file.get_signed_bytes())`). Non-test consumer: `psptool-cli/src/cmds/sign.rs:21` → `main.rs:131`. Verification: `sign_then_verify_round_trip_via_blob_editor` (re-sign then `Verified`); `sign_entry_signs_the_buffer_grown_to_rom_size` / `sign_entry_signs_a_zero_size_record` (#105); live reference `psptool-cli/tests/sign_oracle.rs` (32 corpus re-signs, 16 grown, verified by upstream). |
| REQ-2 (PSS params per signature_type) | SHIPPED | Impl `sign.rs:178-194`: `signature_type == 0` → `SigningKey::<Sha256>::new` (`sign.rs:180`), `== 2` → `SigningKey::<Sha384>::new` (`sign.rs:187`); the `rsa::pss::SigningKey` default salt = digest length (32 / 48). Mirrors `RsaKey.__init_subclass__` (`crypto.py:183-196` `2048 → SHA256, salt_length = 32`; `4096 → SHA384, salt_length = 48`) and `RsaKey.padding` (`crypto.py:198-203` `PSS(MGF1(hash), salt_length)`). Needed-bits gate `sign.rs:144-148`. Non-test consumer: `psptool-cli/src/cmds/sign.rs:21`. Verification: `sign_then_verify_round_trip_via_blob_editor` (a wrong hash/salt would fail PSS verify). |
| REQ-3 (fresh valid PSS signature) | SHIPPED | Impl `sign.rs:181-184`/`:188-191` (`signing_key.sign_with_rng(rng, &signed).to_bytes()`), `sign_entry` seeds `rand::thread_rng()` (`sign.rs:123`); mirrors `PrivateKey.sign_blob` (`crypto.py:302-307`) invoked by `resign_only` (`cert_tree.py:113`). Non-test consumer: `psptool-cli/src/cmds/sign.rs:21`. Verification: `sign_then_verify_round_trip_via_blob_editor` (re-sign → asserts `Verified`). |
| REQ-4 (key-size / type validation) | SHIPPED | Impl `sign.rs:144-157`: `UnsupportedSignatureType` for type ∉ {0,2} (`sign.rs:147`, again at `:193` in the hash match instead of an `unreachable!` arm); `KeySizeMismatch` when `priv_key.n().bits() != needed_bits` (`sign.rs:150-157`); plus `SignatureLengthMismatch` guard (`sign.rs:195-200`). Mirrors upstream key-size assert (`crypto.py:265`) and signature-size assert (`cert_tree.py:111-112`). Non-test consumer: `psptool-cli/src/cmds/sign.rs:21` propagates via `?`. Verification: `sign_entry_rejects_wrong_key_size` (`KeySizeMismatch` + `is_clean`). |
| REQ-5 (reject non-signed entries) | SHIPPED | Impl `sign.rs:136-142`: non-`Header`/`KeyStore` class → `NotSignedEntry` (`sign.rs:138`); `!header.is_signed()` → `NotSignedFlag` (`sign.rs:140-142`). Mirrors upstream refusal (`__main__.py:254-257`) and `is_signed` (`header_file.py:130-135`). Non-test consumer: `psptool-cli/src/cmds/sign.rs:16-18` pre-checks the class and bails, then `:21` propagates. Verification: `sign_entry_rejects_plain_entry` (`NotSignedEntry` + no patch). |
| REQ-6 (signature-region locality) | SHIPPED | Impl `sign.rs:203-204` (`editor.patch(FlashOffset(sig_start), sig_be)?`, `sig_start` = window offset + signature offset in the window) writes only the trailing `sig_len` bytes; no other byte is patched. Mirrors upstream `self.signature.set_bytes(0, len(signature), signature)` (`cert_tree.py:117`) over the trailing signature `NestedBuffer` (`header_file.py:88`). Non-test consumer: `psptool-cli/src/cmds/sign.rs:21-22` (`sign_entry` then `editor.serialize()`). Verification: `sign_entry_patches_only_signature_region` (only `[sig_off, sig_off+0x100)` differs), and the same locality for a buffer grown past its directory entry in `sign_entry_signs_the_buffer_grown_to_rom_size` / `sign_entry_signs_a_zero_size_record`. |
| REQ-7 (bounds-safe trailing region) | SHIPPED | Impl `sign.rs:174-176` (`let sig_slice = header.signature_bytes(file)?` over the REQ-1 window) uses `HeaderEntry::signature_bytes` (`body.rs:260`), which normalises `rom_size` and returns `BodyTooSmall` when the image does not cover `rom_size` (`header_file_window` then falls back to the entry body); offset derived `sign.rs:176`. Mirrors upstream signature `NestedBuffer(self, signature_len, rom_size - signature_len)` (`header_file.py:88`) over the buffer re-sized to `rom_size` (`header_file.py:72-75`, `:104-105`). Non-test consumer: `psptool-cli/src/cmds/sign.rs:21`. Verification: `sign_entry_rejects_rom_size_past_the_image` (`BodyTooSmall` + `is_clean`). |
| REQ-8 (on-disk byte-order / upstream verify fidelity) | SHIPPED | Impl `sign.rs:204` (`editor.patch(FlashOffset(sig_start), sig_be)`) writes the RSA-PSS signature **plain** (big-endian I2OSP), NOT reversed — matching upstream's plain HeaderFile `Signature` (`cert_tree.py:63`; verified plain at `cert_tree.py:98` + `crypto.py:247-258`). Combined with the fixed signed region (`get_signed_bytes` = `0x100 + size_signed`, `body.rs:384`) over the grown HeaderFile buffer (REQ-1), a re-signed HeaderFile matches the real-firmware convention. Non-test consumer: `psptool-cli/src/cmds/sign.rs:21`. Corpus-proven twice: `crates/psptool-ops/tests/divergence_signature_byte_order.rs` establishes that plain + full-length IS the on-disk convention real signed HeaderFiles use (its pin verifies the real corpus signatures under exactly the verify path the plain/full-length sign path targets; the control asserts reversed and short-length both FAIL), and `crates/psptool-cli/tests/sign_oracle.rs` re-signs 32 corpus HeaderFiles (the 16 whose buffer outgrows the directory entry, #105, plus one control per image) with keys the live reference generated, and the reference's `SignedEntity.verify_with_pubkey` (`cert_tree.py:97-98`) verifies all 32. The `ReversedSignature` convention (`crypto.py:386-409`) remains PubkeyFile-only and untouched. |
| REQ-9 (CLI `sign` subcommand consumer) | SHIPPED | Impl `psptool-cli/src/cmds/sign.rs:13-32`: parses the target entry (`:15`), class-guards (`:16-18`), loads a PKCS#8 PEM key (`:19`, `load_priv_key` `:34-41`), drives `sign_entry` through a `BlobEditor` over the parsed image (`:20-21`), and writes the serialised ROM (`:22-24`). Dispatched from `main.rs:131` (`Command::Sign(args) => cmds::sign::run(args, out)`); args in `cli.rs` (`SignArgs`). Mirrors the reference re-sign CLI (`__main__.py:238-262`; `-p/--privkeystub` `__main__.py:82`). This IS the boundary CLI surface (goal.md R-DEFER-1). Verification: `cargo test -p psptool-ops --lib`; CLI builds and dispatches. |

## Architecture

**Diff-and-patch, driven from the consumer.** `sign.rs` owns no byte buffer; it
records a single patch into a [`BlobEditor`] (`.design/psptool-core/writer.md`). The
only mutation primitive it calls is `BlobEditor::patch` (`sign.rs:204`);
materialisation is the caller's later `editor.serialize()`
(`psptool-cli/src/cmds/sign.rs:22`). This is why REQ-6 locality is structural: the
writer only echoes the caller's absolute coordinates, and `sign_entry` supplies the
exact trailing-region offset (`window.offset() + offset_in_file`, `sign.rs:203`)
and exact length (`signature_bytes(..).len()`, `sign.rs:174-175`).

**The HeaderFile buffer comes from the editor's image (#105).** Upstream signs and
patches the HeaderFile buffer, not the directory entry: `HeaderFile._parse` grows a
buffer shorter than the header to `0x100` (`header_file.py:32-33`) and one shorter than
`rom_size` to `rom_size` (`:74-75`), reading on into the image. `sign_entry` cuts the
same window with `Entry::header_file_window(editor.original())` (`sign.rs:164-166`):
the editor wraps the image the entry was parsed from, so the signature needs no extra
parameter and the CLI callers are unchanged. 13 corpus HeaderFiles grown past a
non-zero directory size (`BodyTooSmall` before) and 3 zero-size records (`Truncated`
before) now re-sign.

**Two entry points, one core.** `sign_entry` (`sign.rs:117-124`) is the ergonomic
surface seeding `rand::thread_rng()`; `sign_entry_with_rng` (`sign.rs:129-206`) takes a
caller-controlled `R: CryptoRng + RngCore` for deterministic-seed tests and non-default
CSPRNGs. Both funnel the same invariant order: class guard (`:136-139`) → `is_signed`
guard (`:140-142`) → `signature_type`/key-width validation (`:144-157`) → HeaderFile
buffer and signed-region computation (`:164-168`) → trailing-region location
(`:174-176`) → PSS sign (`:178-194`) → length check (`:195-200`) → patch (`:204`) with
the signature PLAIN (big-endian I2OSP, `cert_tree.py:63`).

**Signed region vs. signature region are distinct core helpers.**
`HeaderEntry::get_signed_bytes` (`body.rs:384`) reconstructs the *input* to the
signer (`header(0x100) || decrypted_decompressed_body[..size_signed]`, total
`0x100 + size_signed`), while
`HeaderEntry::signature_bytes` (`body.rs:260`) locates the *output* region (the
trailing `signature_len` bytes, `rom_size`-normalised). `sign.rs` composes both rather
than re-deriving offsets, so the bounds/truncation corner cases (`rom_size == 0` →
fall back to the buffer length; a `rom_size` the image cannot cover → `BodyTooSmall`)
are handled once in the vetted core, not duplicated here.

**Hash selection is a compile-time match, not runtime dispatch.** The `signature_type`
match (`sign.rs:178-194`) monomorphises `SigningKey::<Sha256>` vs `SigningKey::<Sha384>`;
any other type returns `UnsupportedSignatureType` there too (`sign.rs:193`), though the
earlier guard (`sign.rs:147`) already rejects it.

**Typed error surface.** `SignError` (`sign.rs:49-88`) enumerates `NotSignedEntry`,
`NotSignedFlag`, `UnsupportedSignatureType`, `KeySizeMismatch`,
`SignatureLengthMismatch`, `Body` (`#[from] BodyError`), and `Patch` (`#[from]
PatchError`). No `unwrap`/`expect`/`panic`/`unreachable!` on the production path
(R-CODE-2). Every reject path returns before any patch, so a rejected sign leaves
`editor.is_clean()` (asserted in the reject tests).

**Crypto via the target ecosystem analog (R-DEV-7).** Upstream uses
`cryptography.hazmat`; the target uses the `rsa` + `sha2` crates. The observable
contract — RSA-PSS with `MGF1(SHAxxx)`, salt = digest length, over the same signed byte
region — is preserved; the implementation differs. The on-disk key format is out of
scope for this unit (callers pass an in-memory [`RsaPrivateKey`]; the CLI loads PKCS#8
PEM at `psptool-cli/src/cmds/sign.rs:34-41`).

## Version-skew note (blocker #61)

The differential oracle is PSPTool 3.4 while the translation source `/tmp/psptool-ref`
is git HEAD. Signing is algorithmic and version-stable: the signed-region definition
(`HeaderFile.get_signed_bytes` `header_file.py:168-170`), the PSS parameter selection
(`crypto.py:183-203`), and the re-sign flow (`cert_tree.py:101-117`) are long-standing
and identical across 3.4/HEAD. No SHIPPED row above depends on a HEAD-only value.
`parity_ops` is `[]` — the signing path is not reached by `corpus_roundtrip` (a
read-parse-reserialize identity check) nor by the `ls`/`ls_json` `differential`; the
unit's oracle is the crate lib suite's sign→verify roundtrip.

REQ-8 (previously the one open item) is now SHIPPED: the target no longer reverses
HeaderFile signature bytes. Both sign (`sign.rs:204`) and verify (`body.rs:404`) use the
signature PLAIN (big-endian I2OSP), matching upstream's plain `Signature`
(`cert_tree.py:63`) for both parse and verify. This is the convention real firmware
uses: the corpus oracle `divergence_signature_byte_order.rs` verifies 2993 real
HeaderFile signatures under exactly the plain/full-length convention the sign path
targets, and its control asserts reversed and short-length both fail. Blocker #78 closed.

## Verification

The list below IS the gauntlet for this module; run inside `nix-shell` so
`PSPTOOL_REFERENCE` + `PSPTOOL_TEST_CORPUS` are set (a skipped suite is a red gate, not
a pass).

- `cargo test -p psptool-ops --lib` — **56 passed, 0 failed, 0 ignored**. Covers the
  sign→verify oracle (`verify::tests::sign_then_verify_round_trip_via_blob_editor`,
  REQ-1/REQ-2/REQ-3/REQ-6/REQ-7 end-to-end) and the `sign::tests::*` reject/locality
  pins: `sign_entry_patches_only_signature_region` (REQ-6),
  `sign_entry_rejects_plain_entry` (REQ-5), `sign_entry_rejects_wrong_key_size`
  (REQ-4), `sign_entry_rejects_rom_size_past_the_image` (REQ-7), and
  `sign_entry_signs_the_buffer_grown_to_rom_size` /
  `sign_entry_signs_a_zero_size_record` (REQ-1/REQ-6/REQ-7 over a buffer grown past
  its directory entry, #105). This is the module's self-oracle; `parity_ops` is `[]`.
- `cargo test -p psptool-cli --test sign_oracle` — **1 passed** (live reference +
  corpus): 32 corpus HeaderFiles re-signed — the 16 whose buffer outgrows their
  directory entry and one control per image — all verify under the reference's
  `SignedEntity.verify_with_pubkey` (`cert_tree.py:97-98`) with the keys it generated
  (REQ-1, REQ-6, REQ-7, REQ-8).
- `cargo test -p psptool-core --test corpus_roundtrip` — byte-exact roundtrip on the
  supported corpus (establishes the [`BlobEditor`] the sign path drives is byte-exact).
  Does **not** exercise signing (read-parse-reserialize identity, no mutation).
- `cargo test -p psptool-cli --test differential` — `ls`/`ls_json` structural parity vs
  reference PSPTool. Does **not** exercise the `sign` subcommand (read-only surface).
- `cargo test -p psptool-ops --test divergence_signature_byte_order` — **2 passed, 0
  failed, 0 ignored** (run inside `nix-shell` with the corpus): the control proves the
  plain/full-length on-disk convention and the pin verifies 2993 real corpus HeaderFile
  signatures. This is the real-corpus cross-validation that REQ-8 (blocker #78, now
  closed) required — the plain signature byte-order and `0x100 + size_signed` region the
  sign path writes are the convention real firmware verifies under.
