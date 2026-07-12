# HeaderFile body access: decompression, decryption, signed-region, and signature verification (§4–§7)

<!--
tier: 3-component
status: draft
baseline-commit: 0ceb4e45a474c160ddfb6603fc324625f4a0ebc6
upstream-paths:
  - /tmp/psptool-ref/psptool/header_file.py
  - /tmp/psptool-ref/psptool/file.py
  - /tmp/psptool-ref/psptool/crypto.py
  - /tmp/psptool-ref/psptool/utils.py
  - /tmp/psptool-ref/psptool/cert_tree.py
-->

## Summary

`crates/psptool-core/src/body.rs` is the entry-body surface for
`HeaderFile`-class entries: it slices the post-header data region and trailing
signature (`data_region` / `signature_bytes`), AES-128 decrypts an encrypted
data region (`get_decrypted_body`), zlib-decompresses it
(`get_decompressed_body`), composes the two (`get_decrypted_decompressed_body`),
computes the RSA-signed region (`get_signed_bytes`), and verifies the trailing
RSA-PSS signature against a `PubkeyEntry` (`verify_signature`). It mirrors
PSPTool's `HeaderFile` body methods (`header_file.py:162-190`), the AES/zlib
primitives in `utils.py:218-283`, the RSA-PSS parameters in `crypto.py:189-258`,
and the HeaderFile signed-entity convention in `cert_tree.py:59-98`.

The byte-exact roundtrip rule is preserved because every method here returns a
freshly allocated `Vec<u8>` or borrows the entry's source slice unchanged — none
mutate the carried source bytes.

**Two shipped-in-a-prior-pass defects make real-firmware signature verification
NOT-STARTED** (REQ-5, REQ-6): the signed region is `0x100` bytes too short
(#79) and HeaderFile signatures are wrongly byte-reversed (#78). Together they
make `verify_chain_of_trust` verify **0** real corpus HeaderFile signatures
where upstream verifies all of them; the pin is
`crates/psptool-ops/tests/divergence_signature_byte_order.rs`.

## Requirements

- REQ-1: **Body-region slicing bounded by `rom_size`.** Given the full entry
  body `[header(0x100) | data | signature]`, expose the data region
  `body[0x100 .. rom_size - signature_len]` and the trailing signature
  `body[rom_size - signature_len .. rom_size]`, with `rom_size == 0` falling
  back to `body.len()`. Signature length is `0x100` for `signature_type == 0`
  (RSA-2048) and `0x200` for `signature_type == 2` (RSA-4096). Mirrors
  `header_file.py:100` (`self.body = NestedBuffer(self, len(self) - len(header)
  - signature_len, len(header))`), `header_file.py:82`
  (`signature = NestedBuffer(self, signature_len, self.rom_size -
  signature_len)`), `header_file.py:66-69` (rom_size fallback/extend), and
  `header_file.py:77-84` (signature_len 0x100/0x200).
- REQ-2: **AES-128 data-region decryption with IKEK-wrapped key.** When
  `is_encrypted`, unwrap the per-entry key with AES-128-ECB under the IKEK, then
  AES-128-CBC-decrypt the data region with the header IV. The default IKEK is
  the Zen+ constant (auto-detection deferred, exactly as upstream). Mirrors
  `utils.py:277-283` (`decrypt`: `decrypt_ecb(entry_key, ikek)` then
  `decrypt_cbd(data, iv, key)`), `utils.py:257-264`/`utils.py:267-274`
  (ECB/CBC primitives), `header_file.py:184-190` (`get_decrypted_body`), and
  the IKEK constants `file.py:60` (`UNWRAPPED_IKEK_ZEN_PLUS`) / `file.py:63`
  (`UNWRAPPED_IKEK_ZEN`) selected by `header_file.py:192-203`
  (`get_unwrapped_ikek` returns the Zen+ IKEK unconditionally).
- REQ-3: **zlib decompression with magic search and pre-magic prefix.** Scan the
  first `0x500` bytes of the plaintext data region for one of the four zlib
  magics (`78 DA`/`78 9C`/`78 5E`/`78 01`), short-circuiting at offset `0x100`,
  then decompress `zlib_size` bytes and **prepend the pre-magic prefix** to the
  output. Mirrors `utils.py:218-234` (`zlib_find_header`, 0x500 window + 0x100
  short-circuit) and `utils.py:241-254` (`zlib_decompress`,
  `uncompressed + decompressed`), invoked from `header_file.py:166-174`
  (`zlib_decompress(output[:self.zlib_size])`).
- REQ-4: **Combined decrypted-then-decompressed body.** Produce the same
  "checksummed / signable body" view PSPTool exposes: decrypt (iff encrypted),
  then decompress (iff compressed), else return the data region verbatim.
  Mirrors `header_file.py:166-174` (`get_decrypted_decompressed_body`).
- REQ-5: **Signed-region computation = `header || ddb` truncated to
  `0x100 + size_signed`.** The RSA signature covers the header concatenated with
  the decrypted-decompressed body, truncated to `len(header) + size_signed`
  bytes — i.e. `size_signed` is a **body-signed** length added on top of the
  full `0x100` header. Mirrors `header_file.py:162-164`
  (`file_bytes = self.header.get_bytes() + self.get_decrypted_decompressed_body();
  return file_bytes[:len(self.header) + self.size_signed]`) and the field read
  at `header_file.py:43`.
- REQ-6: **RSA-PSS verification of a real signed HeaderFile.** Verify the
  trailing signature against a `PubkeyEntry`: select SHA-256/RSA-2048 or
  SHA-384/RSA-4096 by `signature_type`, hash the REQ-5 signed region under
  RSA-PSS (MGF1, salt = digest length), and pass the on-disk signature bytes
  **plain** (a HeaderFile signature is a plain `Signature`, not the reversed
  PubkeyFile convention). Must verify at least one real corpus HeaderFile.
  Mirrors `cert_tree.py:63`
  (`Signature.from_nested_buffer(hf.signature)` — plain), `cert_tree.py:98`
  (`pubkey.verify_blob(self.file.get_signed_bytes(), self.signature.get_bytes())`),
  and `crypto.py:247-258` / `crypto.py:189-203` (PSS params).
- REQ-7: **PubkeyEntry → `RsaPublicKey` extraction.** Read the little-endian
  public exponent and modulus from a `PubkeyFile` blob and build an
  `rsa::RsaPublicKey`, rejecting bit-widths other than 2048/4096. Mirrors
  `crypto.py:219-229`
  (`pubexp = int.from_bytes(crypto_material[:size], 'little')`,
  `modulus = int.from_bytes(crypto_material[size:], 'little')`).

## Acceptance criteria

- AC-1 (REQ-1): `data_region` / `signature_bytes` return the correct slices and
  stop at `rom_size` (not `body.len()`) when `rom_size != 0`, falling back to
  `body.len()` when `rom_size == 0`, and reject `rom_size > body.len()` as
  `BodyTooSmall`. Pinned by
  `data_region_and_signature_bytes_honor_rom_size_truncation`,
  `rom_size_zero_falls_back_to_body_length`,
  `rom_size_larger_than_body_is_rejected`.
- AC-2 (REQ-2): `get_decrypted_body` round-trips an AES-CBC-encrypted fixture
  whose per-entry key was wrapped under `Ikek::ZenPlus`, rejects a
  non-block-aligned ciphertext, and errors `NotEncrypted` on an unencrypted
  entry. Pinned by `get_decrypted_body_round_trips_synthetic_fixture`,
  `get_decrypted_body_rejects_non_block_aligned_ciphertext`,
  `get_decrypted_body_errors_when_not_encrypted`, and the IKEK constants by
  `ikek_zen_plus_matches_spec`.
- AC-3 (REQ-3): `find_zlib_start` matches at 0, mid-window, and the 0x100
  short-circuit, and misses beyond the 0x500 window; `get_decompressed_body`
  decompresses a committed micro-fixture and preserves the pre-magic prefix.
  Pinned by `find_zlib_start_*` and `get_decompressed_body_*`.
- AC-4 (REQ-4): `get_decrypted_decompressed_body` returns the data region
  verbatim for a plain entry and the decompressed bytes for a compressed one.
  Exercised transitively by `get_signed_bytes_returns_header_plus_plaintext`
  and by the corpus control in
  `divergence_signature_byte_order.rs::upstream_signed`.
- AC-5 (REQ-5): `get_signed_bytes` returns `header || ddb[..0x100 +
  size_signed]`. **NOT met today** — the impl truncates the total to
  `size_signed` (`0x100` bytes short); see the REQ status table (#79).
- AC-6 (REQ-6): `verify_chain_of_trust` verifies ≥1 real corpus HeaderFile
  signature. **NOT met today** — the impl reverses the signature and uses the
  short region; the control
  `real_corpus_headerfile_convention_is_nonreversed_and_full_length` passes
  while the pin `real_corpus_headerfile_verifies_under_verify_chain_of_trust`
  is `#[ignore]`d (#78/#79).
- AC-7 (REQ-7): `rsa_public_key` builds a key that verifies real corpus
  signatures under the correct convention (the control test's `correct_plain_ok`
  is asserted `true`), and `pubexp_bytes`/`modulus_bytes` extract the documented
  little-endian slots. Pinned by
  `pubkey_entry_modulus_and_pubexp_extracted_from_micro_fixture` and the
  passing corpus control.

## REQ status table

| REQ | Status | Evidence |
|---|---|---|
| REQ-1 (rom_size-bounded slicing) | SHIPPED | Impl `body.rs:190` (`pub fn data_region`) + `body.rs:212` (`pub fn signature_bytes`) via `body.rs:170` (`effective_end`: `rom_size == 0 → body.len()`), sig length from `entry.rs:242` (`signature_len` → `0x100`/`0x200`). Mirrors `header_file.py:100` (`body = NestedBuffer(self, len(self) - len(self.header) - self.signature_len, len(self.header))`), `header_file.py:82` (`signature = NestedBuffer(self, self.signature_len, self.rom_size - self.signature_len)`), `header_file.py:66-69`. Non-test consumer: `psptool-ops/src/extract.rs:59` (`header.data_region(entry.body.as_bytes())`) and `psptool-ops/src/sign.rs:147` (`header.signature_bytes(body_bytes)`). Verification: `cargo test -p psptool-core --lib` (146 passed) incl. `data_region_and_signature_bytes_honor_rom_size_truncation`. |
| REQ-2 (AES-128 decryption) | SHIPPED | Impl `body.rs:236` (`pub fn get_decrypted_body`): ECB-unwrap the key under the IKEK (`body.rs:248-250`) then CBC-decrypt (`body.rs:255-258`); IKEK bytes at `body.rs:67`. Mirrors `utils.py:281` (`unwrapped_entry_key = decrypt_ecb(entry_key, unwrapped_ikek)`) + `utils.py:283` (`decrypt_cbd(data, iv, unwrapped_entry_key)`), `header_file.py:184-190`; constants `file.py:60`/`file.py:63` with the Zen+-default limitation faithfully mirrored from `header_file.py:203` (`return self.UNWRAPPED_IKEK_ZEN_PLUS`). Non-test consumer: `psptool-ops/src/extract.rs:79` (`header.get_decrypted_body(entry.body.as_bytes(), ikek)`) → CLI `psptool extract -d`. Verification: `cargo test -p psptool-core --lib` (146 passed) incl. `get_decrypted_body_round_trips_synthetic_fixture`, `..._rejects_non_block_aligned_ciphertext`. |
| REQ-3 (zlib decompression) | SHIPPED | Impl `body.rs:273` (`pub fn get_decompressed_body`) + `body.rs:469` (`find_zlib_start`, 0x500 window + 0x100 short-circuit) prepending the pre-magic prefix (`body.rs:292` `out.extend_from_slice(&plaintext[..stream_start])`). Mirrors `utils.py:218-234` (`zlib_find_header`) and `utils.py:248-252` (`uncompressed + decompressed`), invoked at `header_file.py:171` (`zlib_decompress(output[:self.zlib_size])`); uses the `flate2` crate per R-DEV-7. Non-test consumer: `psptool-ops/src/extract.rs:60` (`header.get_decompressed_body(plaintext)`) → CLI `psptool extract`. Verification: `cargo test -p psptool-core --lib` (146 passed) incl. `get_decompressed_body_round_trips_micro_fixture`, `..._preserves_pre_zlib_prefix`, `find_zlib_start_*`. |
| REQ-4 (combined decrypt+decompress) | SHIPPED | Impl `body.rs:306` (`pub fn get_decrypted_decompressed_body`): decrypt iff `is_encrypted`, decompress iff `is_compressed`, else data region verbatim — mirrors `header_file.py:166-174`. Non-test consumer: `body.rs:330` (`get_signed_bytes` calls it in production). Corpus-anchored: `divergence_signature_byte_order.rs:101` (`upstream_signed`) feeds its output to RSA-PSS and the control asserts the result verifies real signatures (`correct_plain_ok == true`), proving the composition is byte-correct on real firmware. Verification: `cargo test -p psptool-core --lib` (146 passed); `cargo test -p psptool-ops --test divergence_signature_byte_order` (control passes). |
| REQ-5 (signed-region = 0x100+size_signed) | NOT-STARTED | Open prereq blocker **#79**. Impl `body.rs:325` (`get_signed_bytes`) truncates the TOTAL to `size_signed` — `body.rs:333-349` computes `body_signed = size_signed - 0x100` and emits `header(0x100) || plaintext[..size_signed - 0x100]`, signing **0x100 fewer bytes** than upstream `header_file.py:162-164` (`file_bytes[:len(self.header) + self.size_signed]` = `0x100 + size_signed`). Root cause: `entry.rs:126` documents `size_signed` as header-INCLUSIVE, but the raw on-disk field is header-EXCLUSIVE. Falsified by the corpus control `real_corpus_headerfile_convention_is_nonreversed_and_full_length` (`prod_len_plain_ok` asserted `false`). |
| REQ-6 (verify a real signed HeaderFile) | NOT-STARTED | Open prereq blocker **#78** (also depends on #79). Impl `body.rs:358` (`verify_signature`) reverses HeaderFile signature bytes — `body.rs:392-393` (`sig_be.reverse()`) — applying the PubkeyFile-only `ReversedSignature` convention (`crypto.py:386-408`) to HeaderFiles, whereas upstream wraps them in a **plain** `Signature` (`cert_tree.py:63` `Signature.from_nested_buffer(hf.signature)`; verified plain at `cert_tree.py:98` + `crypto.py:247-258`). Combined with REQ-5, `verify_chain_of_trust` (`psptool-ops/src/verify.rs:264`) verifies **0** real corpus HeaderFile signatures; pin `real_corpus_headerfile_verifies_under_verify_chain_of_trust` is `#[ignore]`d against #78. The synthetic sign→verify round-trip (`verify_signature_round_trip_rsa2048`, `verify.rs::sign_then_verify_round_trip_via_blob_editor`) passes only because `sign_entry` applies the SAME two defects — it is circular and does NOT establish SHIPPED (R-HONEST-3). |
| REQ-7 (PubkeyEntry RSA extraction) | SHIPPED | Impl `body.rs:447` (`pub fn rsa_public_key`) with LE exponent/modulus (`body.rs:454-455` `BigUint::from_bytes_le`) + `body.rs:423`/`body.rs:435` (`pubexp_bytes`/`modulus_bytes`). Mirrors `crypto.py:219` (`pubexp = int.from_bytes(crypto_material[:cls.signature_size], 'little')`) + `crypto.py:222` (`modulus = int.from_bytes(crypto_material[cls.signature_size:], 'little')`). Non-test consumer: `body.rs:395` (`pubkey.rsa_public_key()` in production `verify_signature`). Corpus-anchored independently of the verify defects: the control test builds the key via `pubkey.rsa_public_key()` and RSA-PSS verifies real corpus signatures with it (`correct_plain_ok` asserted `true`), so the extraction itself is proven correct on real firmware keys. Verification: `cargo test -p psptool-core --lib` (146 passed) incl. `pubkey_entry_modulus_and_pubexp_extracted_from_micro_fixture`; `cargo test -p psptool-ops --test divergence_signature_byte_order` control. |

## Architecture

**Derived-view discipline (roundtrip rule).** Every method takes the entry's
full body slice `[header(0x100) | data | signature]` and returns either a fresh
`Vec<u8>` (`get_decrypted_body` `body.rs:261`, `get_decompressed_body`
`body.rs:297`, `get_signed_bytes` `body.rs:350`) or a borrow of the source
(`data_region`/`signature_bytes` return `&'a [u8]`). Nothing mutates the carried
bytes, so the diff-and-patch roundtrip (R-CODE-4) is untouched. This is a
deliberate divergence from upstream's in-place `NestedBuffer` mutation
(`utils.py:62-68`) per R-DEV-4.

**`rom_size` truncation seam.** `effective_end` (`body.rs:170`) reproduces
`header_file.py:66-69`/`header_file.py:98`: a non-zero `rom_size` bounds the
logical entry; `rom_size == 0` falls back to the caller's body length. Because a
borrowed slice cannot be zero-extended, `rom_size > body.len()` returns
`BodyTooSmall` rather than the upstream buffer-grow (`header_file.py:69`) — the
only observable difference is an error instead of trailing zeros, which the
corpus roundtrip never exercises.

**Signature length taxonomy.** `signature_type` conflates three facts, matching
upstream `crypto.py:189-196`: `0` → RSA-2048 → SHA-256 → `0x100`-byte signature;
`2` → RSA-4096 → SHA-384 → `0x200`-byte signature. `signature_len`
(`entry.rs:242`) and the hash dispatch in `verify_signature` (`body.rs:397-401`)
both switch on it. RSA-PSS salt length defaults to the digest length via
`PssVerifyingKey::new` (`body.rs:506`), matching `crypto.py:191-194`
(salt 32 for 2048, 48 for 4096).

**Signed-region defect (#79) — critic watch-item.** Upstream
(`header_file.py:162-164`) signs `header.get_bytes() +
get_decrypted_decompressed_body()` truncated to `len(header) + size_signed`.
The on-disk `size_signed` (read at `header_file.py:43`, mirrored at
`entry.rs:177`) is the length of the *body* covered by the signature, added on
top of the full `0x100` header. Our `get_signed_bytes` (`body.rs:333-349`)
instead treats `size_signed` as the header-inclusive total and slices
`plaintext[..size_signed - 0x100]`, signing `0x100` fewer bytes. On the corpus
this is provably wrong: the control `upstream_signed` (which uses the correct
`0x100 + size_signed` length) verifies real signatures while
`prod_len_plain_ok` (the production length) does not.

**Signature byte-order defect (#78) — critic watch-item.** PSPTool stores
PubkeyFile signatures reversed (the `ReversedSignature` adapter,
`crypto.py:386-408`) but HeaderFile signatures **plain**: `cert_tree.py:63`
builds the HeaderFile signed-entity with `Signature.from_nested_buffer(...)`
(base `Signature`, non-reversed), and `cert_tree.py:98` passes those on-disk
bytes straight to `verify_blob` (`crypto.py:247-258`). Our `verify_signature`
reverses them (`body.rs:392-393`), and the module doc-comment
(`body.rs:207-211`, `body.rs:353-357`) and `sign_entry` (`sign.rs:174-175`)
carry the same wrong assumption. A real firmware HeaderFile RSA-PSS signature is
standard big-endian (I2OSP); reversing it makes verification fail for every real
entry.

**Why the synthetic tests are green but the REQs are NOT-STARTED.**
`verify_signature_round_trip_rsa2048` (`body.rs:930`) and the
`sign_then_verify_round_trip_via_blob_editor` path both build the signature with
the *same* reversal and *same* `size_signed`-as-total convention the verifier
consumes, so they are internally consistent and pass. They do not touch a real
signature, so they cannot detect either divergence. The oracle that does is
`crates/psptool-ops/tests/divergence_signature_byte_order.rs`, whose control
anchors the true on-disk convention from real corpus bytes and whose `#[ignore]`d
pin fails until #78/#79 land (R-DEFER-3: the pin flips to `#[test]` only when the
fix lands).

**PubkeyEntry extraction is correct and independent.** `rsa_public_key`
(`body.rs:447`) is not implicated in #78/#79: the control test builds the key
with it and RSA-PSS verifies real corpus signatures under the correct
convention, so REQ-7 is genuinely SHIPPED. The two defects are entirely in the
signed-region length and the signature byte order, not in key extraction.

## Verification

The verification list below IS the gauntlet for this module. Run inside
`nix-shell` so `PSPTOOL_REFERENCE` + `PSPTOOL_TEST_CORPUS` are set (a skipped
corpus suite is a red gate, not a pass).

- `cargo test -p psptool-core --lib` — 146 passed, 0 failed, 0 ignored. Covers
  REQ-1..REQ-4 and REQ-7 on synthetic + committed micro-fixtures (`body::tests`,
  27 of which are the body module: `data_region_*`, `get_decrypted_body_*`,
  `get_decompressed_body_*`, `find_zlib_start_*`, `get_signed_bytes_*`,
  `pubkey_entry_modulus_and_pubexp_extracted_from_micro_fixture`,
  `verify_signature_round_trip_rsa2048`).
- `cargo test -p psptool-ops --test divergence_signature_byte_order` — 1 passed
  (control `real_corpus_headerfile_convention_is_nonreversed_and_full_length`),
  1 ignored (pin `real_corpus_headerfile_verifies_under_verify_chain_of_trust`,
  tracking #78/#79). This crate-side verify-against-corpus test IS the module's
  oracle — the one that was missing, and the one whose pin the #78/#79 fix must
  flip to `#[test]`. It is why REQ-5 and REQ-6 are NOT-STARTED, not SHIPPED.
- Route note: this unit's declared `parity_ops` should be `[]`. Neither
  `corpus_roundtrip` (no mutation on the read path) nor the `list` `differential`
  (read-only `ls`/`ls_json`, and `differential.rs:73` explicitly excludes
  per-entry `extract`) exercises the body ops; the psptool-ops crate suite
  (`divergence_signature_byte_order` + the sign/verify round-trips) is the
  oracle.

## Open blockers

- **#79** — signed-region length: `get_signed_bytes` (`body.rs:333-349`) signs
  `size_signed` total bytes; upstream (`header_file.py:162-164`) signs
  `0x100 + size_signed`. Blocks REQ-5, contributes to REQ-6.
- **#78** — signature byte-order: `verify_signature` (`body.rs:392-393`) and
  `sign_entry` (`sign.rs:174-175`) reverse HeaderFile signature bytes; upstream
  (`cert_tree.py:63`) uses them plain. Blocks REQ-6. Fixing both #78 and #79 and
  flipping `real_corpus_headerfile_verifies_under_verify_chain_of_trust` from
  `#[ignore]` to `#[test]` (0 failed, 0 ignored) is the SHIPPED gate for REQ-5
  and REQ-6.
