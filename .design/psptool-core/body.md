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

**Two prior-pass defects that made real-firmware signature verification fail
are now fixed** (REQ-5, REQ-6): the signed region was `0x100` bytes too short
(#79, fixed to `0x100 + size_signed`) and HeaderFile signatures were wrongly
byte-reversed (#78, now used plain). `verify_chain_of_trust` now verifies
**2993** real corpus HeaderFile signatures (was 0); the regression pin is
`crates/psptool-ops/tests/divergence_signature_byte_order.rs`
(`real_corpus_headerfile_verifies_under_verify_chain_of_trust`, now a plain
`#[test]`).

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
  `header_file.py:77-84` (signature_len 0x100/0x200). The slices are cut
  from the HeaderFile buffer re-sized to `rom_size`: a `rom_size` past the
  directory-declared size reads on into the image, as upstream's grown
  `NestedBuffer` reads on into its parent (`header_file.py:74-75`).
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
- REQ-3: **zlib decompression with magic search and pre-magic prefix.** Over
  `output[:zlib_size]` (a Python slice of the plaintext data region), search the
  first `0x500` bytes for each zlib magic in turn (`78 DA`, then `78 9C`, `78 5E`,
  `78 01`), checking offset `0x100` first for each, inflate the stream at the
  first hit and **prepend the pre-magic prefix**; without a magic, return the
  slice unchanged. Inflating fails exactly where `zlib.decompress` raises — a
  corrupt or a truncated stream. Mirrors `utils.py:209-234` (`ZLIB_TYPES`,
  `zlib_find_header`) and `utils.py:241-254` (`zlib_decompress`,
  `uncompressed + decompressed`, `return s`), invoked from `header_file.py:181`
  (`zlib_decompress(output[:self.zlib_size])`).
- REQ-4: **Combined decrypted-then-decompressed body.** Produce the same
  "checksummed / signable body" view PSPTool exposes: decrypt (iff encrypted),
  then decompress (iff compressed), else return the data region verbatim; a
  stream that fails to inflate leaves the still-compressed decrypted region.
  Mirrors `header_file.py:172-189` (`_decrypted_decompressed_body`,
  `get_decrypted_decompressed_body`, PSPTool `241629b`).
- REQ-5: **Signed-region computation = `header || ddb` truncated to
  `0x100 + size_signed`.** The RSA signature covers the header concatenated with
  the decrypted-decompressed body, truncated to `len(header) + size_signed`
  bytes — i.e. `size_signed` is a **body-signed** length added on top of the
  full `0x100` header; a shorter body is covered whole (a Python slice). Mirrors
  `header_file.py:168-170`
  (`file_bytes = self.header.get_bytes() + self.get_decrypted_decompressed_body();
  return file_bytes[:len(self.header) + self.size_signed]`) and the field read
  at `header_file.py:44`.
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
- AC-3 (REQ-3): `zlib_find_header` matches at 0 and mid-window, tries the
  magics in `ZLIB_TYPES` order (a later `78 DA` beats an earlier `78 9C`),
  checks 0x100 first per magic, and misses beyond the 0x500 window;
  `get_decompressed_body` decompresses a committed micro-fixture, preserves the
  pre-magic prefix, rejects a truncated stream and returns a magic-free slice
  unchanged. Pinned by `zlib_find_header_*`, `get_decompressed_body_*`,
  `truncated_stream_fails_to_inflate_and_decodes_to_the_compressed_region`,
  `divergence_body_bounds.rs`, and on the `-X -u` path by
  `psptool-ops/tests/divergence_extract_zlib.rs` and the live reference
  differential `psptool-cli/tests/extract_oracle.rs` (#91).
- AC-4 (REQ-4): `get_decrypted_decompressed_body` returns the data region
  verbatim for a plain entry and the decompressed bytes for a compressed one.
  Exercised transitively by `get_signed_bytes_returns_header_plus_plaintext`
  and by the corpus control in
  `divergence_signature_byte_order.rs::upstream_signed`.
- AC-5 (REQ-5): `get_signed_bytes` returns `header(0x100) ||
  ddb[..size_signed]` (total `0x100 + size_signed`). **Met** — pinned by
  `get_signed_bytes_returns_header_plus_plaintext` (in-memory `size_signed =
  0x10` → `0x110` region) and the corpus control's `short_len_plain_ok ==
  false` / `prod_plain_ok == true` (#79).
- AC-6 (REQ-6): `verify_chain_of_trust` verifies ≥1 real corpus HeaderFile
  signature. **Met** — 2993 real signatures verify; the control
  `real_corpus_headerfile_convention_is_nonreversed_and_full_length` and the
  pin `real_corpus_headerfile_verifies_under_verify_chain_of_trust` both pass
  (0 ignored) (#78/#79).
- AC-7 (REQ-7): `rsa_public_key` builds a key that verifies real corpus
  signatures under the correct convention (the control test's `correct_plain_ok`
  is asserted `true`), and `pubexp_bytes`/`modulus_bytes` extract the documented
  little-endian slots. Pinned by
  `pubkey_entry_modulus_and_pubexp_extracted_from_micro_fixture` and the
  passing corpus control.

## REQ status table

| REQ | Status | Evidence |
|---|---|---|
| REQ-1 (rom_size-bounded slicing) | SHIPPED | Impl `body.rs:190` (`pub fn data_region`) + `body.rs:212` (`pub fn signature_bytes`) via `body.rs:170` (`effective_end`: `rom_size == 0 → body.len()`), sig length from `entry.rs:242` (`signature_len` → `0x100`/`0x200`). Mirrors `header_file.py:100` (`body = NestedBuffer(self, len(self) - len(self.header) - self.signature_len, len(self.header))`), `header_file.py:82` (`signature = NestedBuffer(self, self.signature_len, self.rom_size - self.signature_len)`), `header_file.py:66-69`. The grow (`header_file.py:72-75`) is `body.rs:859` (`pub fn Entry::header_file_window(blob)`: `rom_size` past the directory size → `blob.subslice_at(start..start + rom_size)`), the buffer every accessor is handed. Non-test consumers: `psptool-ops/src/extract.rs:86`/`:129` (`extract_decompressed` / `extract_decrypted` over `entry.header_file_window(blob)`, #99) → CLI `cmds/extract.rs`; `body.rs:832` (`decode_verification`) and `body.rs:756` (`CertifyingKeys::add_entry`); `psptool-ops/src/sign.rs:147` (`header.signature_bytes(body_bytes)`). Verification: `cargo test -p psptool-core --lib` (150 passed) incl. `data_region_and_signature_bytes_honor_rom_size_truncation`, `header_file_window_grows_to_rom_size_into_the_image`; live `psptool-cli --test extract_oracle` `corpus_grown_headerfile_window_matches_reference` (13 grown corpus HeaderFiles byte-identical to the reference's `get_signed_bytes()`). |
| REQ-2 (AES-128 decryption) | SHIPPED | Impl `body.rs:236` (`pub fn get_decrypted_body`): ECB-unwrap the key under the IKEK (`body.rs:248-250`) then CBC-decrypt (`body.rs:255-258`); IKEK bytes at `body.rs:67`. Mirrors `utils.py:281` (`unwrapped_entry_key = decrypt_ecb(entry_key, unwrapped_ikek)`) + `utils.py:283` (`decrypt_cbd(data, iv, unwrapped_entry_key)`), `header_file.py:184-190`; constants `file.py:60`/`file.py:63` with the Zen+-default limitation faithfully mirrored from `header_file.py:203` (`return self.UNWRAPPED_IKEK_ZEN_PLUS`). Non-test consumer: `psptool-ops/src/extract.rs:79` (`header.get_decrypted_body(entry.body.as_bytes(), ikek)`) → CLI `psptool extract -d`. Verification: `cargo test -p psptool-core --lib` (146 passed) incl. `get_decrypted_body_round_trips_synthetic_fixture`, `..._rejects_non_block_aligned_ciphertext`. |
| REQ-3 (zlib decompression) | SHIPPED | Impl `body.rs:303` (`pub fn get_decompressed_body`) = `zlib_decompress(output[:zlib_size])` via `body.rs:1100` (`pub fn zlib_decompress`: magic from `entry.rs:613` `zlib_find_header`, per-magic priority over `body.rs` `ZLIB_MAGICS`; strict inflate `body.rs:1118` `zlib_decompress_strict`, `None` on a corrupt or truncated stream; no magic → `s.to_vec()`). Mirrors `utils.py:224-232` (`for zlib_magic in ZLIB_TYPES.keys(): ... s.find(zlib_magic)`), `utils.py:248-254` (`uncompressed + decompressed` / `return s`), invoked at `header_file.py:181` (`zlib_decompress(output[:self.zlib_size])`); `flate2` per R-DEV-7. Non-test consumer: `body.rs:317` (`decode`) → `get_signed_bytes` → `psptool-ops/src/extract.rs:77` → CLI `psptool -X -u`; and the decode-verification ladder (`decode_best_effort` → `ls`). Verification: `cargo test -p psptool-core --lib` (149 passed) incl. `zlib_find_header_*`, `get_decompressed_body_*`, `truncated_stream_fails_to_inflate_and_decodes_to_the_compressed_region`; `psptool-ops --test divergence_extract_zlib` (7 passed); `psptool-cli --test extract_oracle` (live reference: 7 synthetic edge cases + 3225 corpus compressed HeaderFiles byte-identical; #91). |
| REQ-4 (combined decrypt+decompress) | SHIPPED | Impl `body.rs:340` (`pub fn get_decrypted_decompressed_body`) over `body.rs:317` (`decode`): decrypt iff `is_encrypted`, inflate iff `is_compressed` (a failed inflate keeps the still-compressed decrypted region), else data region verbatim — mirrors `header_file.py:172-189` (`return output, False` / `_decrypted_decompressed_body()[0]`). `decode_best_effort` (`body.rs:357`) is the same decode with the `decompress_ok` flag. Non-test consumer: `body.rs:375` (`get_signed_bytes` calls it in production). Corpus-anchored: `divergence_signature_byte_order.rs:101` (`upstream_signed`) feeds its output to RSA-PSS and the control asserts the result verifies real signatures (`correct_plain_ok == true`), proving the composition is byte-correct on real firmware. Verification: `cargo test -p psptool-core --lib` (149 passed); `cargo test -p psptool-ops --test divergence_signature_byte_order` (control passes). |
| REQ-5 (signed-region = 0x100+size_signed) | SHIPPED | Impl `body.rs:375` (`get_signed_bytes`) emits `header(0x100) || plaintext[..size_signed]`, a Python slice (a shorter body is covered whole), mirroring upstream `header_file.py:168-170` (`file_bytes[:len(self.header) + self.size_signed]`); `size_signed` is read raw/header-EXCLUSIVE at `entry.rs:177`. Non-test consumers: `psptool-ops/src/sign.rs:157` (`header.get_signed_bytes(body_bytes, ikek)`) → CLI `psptool-cli/src/cmds/sign.rs:21`; `psptool-ops/src/extract.rs:77` → CLI `psptool -X -u`; and `body.rs:395` (`verify_signature`). Corpus-proven: the control `real_corpus_headerfile_convention_is_nonreversed_and_full_length` asserts `short_len_plain_ok == false` (the old short region fails) and `prod_plain_ok == true` (production length verifies real signatures). Closes **#79**. |
| REQ-6 (verify a real signed HeaderFile) | SHIPPED | Impl, two entry points over one convention: `body.rs:395` (`verify_signature`, library API against one `PubkeyEntry`) and the certificate-tree rung of decode verification, `body.rs:788` (`CertifyingKeys::check`: no key under the id → `NoCertifyingKey`, else verified once any key verifies) → `body.rs:1154` (`verify_blob`, RSA-PSS under the key's hash). Both pass the on-disk HeaderFile signature **plain**, matching upstream's plain `Signature` (`cert_tree.py:63`; verified at `cert_tree.py:78-98` + `crypto.py:247-258`) — the reversed `ReversedSignature` convention (`crypto.py:386-409`) is PubkeyFile-only. Non-test consumers: `psptool-ops/src/verify.rs:229` (`entry.decode_verification(..)` → `.signature()`, over `CertifyingKeys::from_blob` + the walked ROM's `add_entry`) → CLI `psptool-cli/src/cmds/verify.rs:17`; `psptool-ops/src/list.rs` (`ls` File-Info tags). Corpus-proven: `psptool verify` agrees with the reference `SignedEntity.is_verified()` at all 3927 signed-file addresses of the corpus (`psptool-cli/tests/verify_oracle.rs`, live 241629b oracle; #93) — 3409 verified, 377 bad-signature, 251 unknown-key, 0 errors over every ROM, where the PubkeyFile-only map with no IKEK (3df62fe8) left 380 unknown-key and 638 errors; the pin `real_corpus_headerfile_verifies_under_verify_chain_of_trust` stays a plain `#[test]`. Closes **#78** (with #79). |
| REQ-7 (PubkeyEntry RSA extraction) | SHIPPED | Impl `body.rs:499` (`pub fn rsa_public_key`) with LE exponent/modulus (`BigUint::from_bytes_le`) + `pubexp_bytes`/`modulus_bytes`. Mirrors `crypto.py:219` (`pubexp = int.from_bytes(crypto_material[:cls.signature_size], 'little')`) + `crypto.py:222` (`modulus = int.from_bytes(crypto_material[cls.signature_size:], 'little')`). Non-test consumers: `body.rs:756` (`CertifyingKeys::add_entry`, the key map of `ls` and `verify`) and `body.rs:395` (`verify_signature`). Corpus-anchored independently of the verify defects: the control test builds the key via `pubkey.rsa_public_key()` and RSA-PSS verifies real corpus signatures with it (`correct_plain_ok` asserted `true`), so the extraction itself is proven correct on real firmware keys. Verification: `cargo test -p psptool-core --lib` (146 passed) incl. `pubkey_entry_modulus_and_pubexp_extracted_from_micro_fixture`; `cargo test -p psptool-ops --test divergence_signature_byte_order` control. |

## Architecture

**Derived-view discipline (roundtrip rule).** Every method takes the entry's
full body slice `[header(0x100) | data | signature]` and returns either a fresh
`Vec<u8>` (`get_decrypted_body` `body.rs:261`, `get_decompressed_body`
`body.rs:297`, `get_signed_bytes` `body.rs:350`) or a borrow of the source
(`data_region`/`signature_bytes` return `&'a [u8]`). Nothing mutates the carried
bytes, so the diff-and-patch roundtrip (R-CODE-4) is untouched. This is a
deliberate divergence from upstream's in-place `NestedBuffer` mutation
(`utils.py:62-68`) per R-DEV-4.

**`rom_size` seam.** `effective_end` (`body.rs:202`) reproduces
`header_file.py:72-73`/`:104-105`: a non-zero `rom_size` bounds the logical
entry; `rom_size == 0` falls back to the caller's buffer length. The grow
(`header_file.py:74-75`) is not zero-extension: upstream sets `buffer_size =
rom_size` and the `NestedBuffer` reads on into its parent, i.e. the image bytes
past the directory entry. `Entry::header_file_window(blob)` (`body.rs:859`)
cuts that window from the image, and every consumer (extract, decode
verification, the key-store keys) hands it to the accessors. A buffer shorter
than `rom_size` — an image that ends inside it — still returns
`BodyTooSmall`.

**Signature length taxonomy.** `signature_type` conflates three facts, matching
upstream `crypto.py:189-196`: `0` → RSA-2048 → SHA-256 → `0x100`-byte signature;
`2` → RSA-4096 → SHA-384 → `0x200`-byte signature. `signature_len`
(`entry.rs:242`) and the hash dispatch in `verify_signature` (`body.rs:397-401`)
both switch on it. RSA-PSS salt length defaults to the digest length via
`PssVerifyingKey::new` (`body.rs:506`), matching `crypto.py:191-194`
(salt 32 for 2048, 48 for 4096).

**Signed-region computation (#79, FIXED).** Upstream
(`header_file.py:162-164`) signs `header.get_bytes() +
get_decrypted_decompressed_body()` truncated to `len(header) + size_signed`.
The on-disk `size_signed` (read at `header_file.py:43`, mirrored raw at
`entry.rs:177`) is the length of the *body* covered by the signature, added on
top of the full `0x100` header. `get_signed_bytes` (`body.rs:333`) now emits
`header(0x100) || plaintext[..size_signed]` (total `0x100 + size_signed`),
matching upstream. On the corpus this is proven correct: the control asserts
the old short region (`short_len_plain_ok`) does NOT verify while the fixed
production region (`prod_plain_ok`) does.

**Signature byte-order (#78, FIXED).** PSPTool stores PubkeyFile signatures
reversed (the `ReversedSignature` adapter, `crypto.py:386-409`) but HeaderFile
signatures **plain**: `cert_tree.py:63` builds the HeaderFile signed-entity
with `Signature.from_nested_buffer(...)` (base `Signature`, non-reversed), and
`cert_tree.py:98` passes those on-disk bytes straight to `verify_blob`
(`crypto.py:247-258`). `verify_signature` (`body.rs:395`) now uses the on-disk
bytes plain, and `sign_entry` (`sign.rs:179`) writes them plain; the PubkeyFile
LE modulus/exponent extraction (`body.rs:454-455`) and the `ReversedSignature`
path are untouched. A real firmware HeaderFile RSA-PSS signature is standard
big-endian (I2OSP); using it plain makes verification succeed for real entries.

**The corpus oracle.** `verify_signature_round_trip_rsa2048` (`body.rs`) and the
`sign_then_verify_round_trip_via_blob_editor` path are internally consistent
synthetic sign→verify checks; they now build fixtures with the CORRECT
convention (header-exclusive `size_signed`, plain signature). The oracle that
anchors the true on-disk convention from real corpus bytes is
`crates/psptool-ops/tests/divergence_signature_byte_order.rs`: its control
proves plain + full-length verifies (and reversed / short-length do not), and
its now-plain-`#[test]` pin
`real_corpus_headerfile_verifies_under_verify_chain_of_trust` verifies 2993 real
signatures (R-DEFER-3: the pin flipped from `#[ignore]` to `#[test]` when the
fix landed).

**PubkeyEntry extraction is correct and independent.** `rsa_public_key`
(`body.rs:447`) is not implicated in #78/#79: the control test builds the key
with it and RSA-PSS verifies real corpus signatures under the correct
convention, so REQ-7 is genuinely SHIPPED. The two defects are entirely in the
signed-region length and the signature byte order, not in key extraction.

## Verification

The verification list below IS the gauntlet for this module. Run inside
`nix-shell` so `PSPTOOL_REFERENCE` + `PSPTOOL_TEST_CORPUS` are set (a skipped
corpus suite is a red gate, not a pass).

- `cargo test -p psptool-core --lib` — 149 passed, 0 failed, 0 ignored. Covers
  REQ-1..REQ-4 and REQ-7 on synthetic + committed micro-fixtures (`body::tests`:
  `data_region_*`, `get_decrypted_body_*`, `get_decompressed_body_*`,
  `zlib_find_header_*`, `zlib_decompress_follows_utils_zlib_decompress`,
  `truncated_stream_fails_to_inflate_and_decodes_to_the_compressed_region`,
  `get_signed_bytes_*`,
  `pubkey_entry_modulus_and_pubexp_extracted_from_micro_fixture`,
  `verify_signature_round_trip_rsa2048`).
- `cargo test -p psptool-ops --test divergence_extract_zlib` (7 passed) and
  `cargo test -p psptool-cli --test extract_oracle` (4 passed, 0 ignored):
  the REQ-3/REQ-4/REQ-5 zlib edge cases on the `-X -u` path — magic priority,
  truncated and corrupt streams, no magic, `zlib_size` past the region, a
  fallback body shorter than `size_signed` — against expectations built from
  `utils.py`/`header_file.py`, and byte-for-byte against the live reference
  (`PSPTOOL_REFERENCE`) on synthetic images, single- and multi-file, and on
  every corpus HeaderFile's `-u` and `-c` output (4019 `get_signed_bytes()` +
  256 `to_decrypted_file_bytes()`, #91/#99) — including the HeaderFiles grown
  past their directory entry (REQ-1).
- `cargo test -p psptool-ops --test divergence_signature_byte_order` — **2
  passed, 0 failed, 0 ignored**: control
  `real_corpus_headerfile_convention_is_nonreversed_and_full_length` (plain +
  full-length verifies; reversed / short-length do not) and the pin
  `real_corpus_headerfile_verifies_under_verify_chain_of_trust` (3409 real
  corpus HeaderFile signatures verify, 310 BadSignature, since #93). This
  crate-side verify-against-corpus test IS the module's oracle; its
  now-plain-`#[test]` pin is the SHIPPED gate REQ-5 and REQ-6 now pass.
- `cargo test -p psptool-cli --test verify_oracle` — 1 passed: every
  `psptool verify -j -r N` row at an address where the live reference holds a
  signed HeaderFile/KeyStoreFile carries the reference's
  `SignedEntity.is_verified()` outcome (3927 addresses; the three #90
  zero-size-record echoes tolerate one extra `not-signed` row).
  `cargo test -p psptool-ops --test decode_verification` `verify_*` (3) pin the
  `$KDB` key, every-key-under-an-id, and ls/verify agreement on synthetic
  images (#93).
- Route note: this unit's declared `parity_ops` should be `[]`. Neither
  `corpus_roundtrip` (no mutation on the read path) nor the `list` `differential`
  (read-only `ls`/`ls_json`, and `differential.rs:73` explicitly excludes
  per-entry `extract`) exercises the body ops; the psptool-ops crate suite
  (`divergence_signature_byte_order` + the sign/verify round-trips) is the
  oracle.

## Open blockers

- **#79** (CLOSED) — signed-region length: `get_signed_bytes` (`body.rs:333`)
  now signs `0x100 + size_signed` bytes, matching upstream
  (`header_file.py:162-164`). REQ-5 SHIPPED.
- **#78** (CLOSED) — signature byte-order: `verify_signature` (`body.rs:395`)
  and `sign_entry` (`sign.rs:179`) now use HeaderFile signature bytes plain,
  matching upstream (`cert_tree.py:63`). REQ-6 SHIPPED. The pin
  `real_corpus_headerfile_verifies_under_verify_chain_of_trust` is a plain
  `#[test]` (0 failed, 0 ignored), verifying 2993 real corpus signatures.
- **#91** (CLOSED) — the `-X -u` zlib step took the earliest of any magic,
  accepted a truncated stream, and errored on a magic-free slice and on a body
  shorter than `size_signed`. `get_decompressed_body` is now
  `zlib_decompress(output[:zlib_size])` and `get_decrypted_decompressed_body` /
  `decode_best_effort` share one `_decrypted_decompressed_body` decode, so the
  extract path and the decode-verification ladder decode identically.
- **#99** (CLOSED) — extract handed `HeaderEntry` the directory-sized entry
  body; upstream grows a HeaderFile to its header `rom_size`
  (`header_file.py:72-75`), so 13 corpus `-X -u` extracts failed
  `BodyTooSmall`. `Entry::header_file_window` is public and the extract ops read
  it; `extract_oracle.rs::corpus_grown_headerfile_window_matches_reference` is a
  plain `#[test]` (13/13).
- **#93** (CLOSED) — the `verify` report checked signatures against a
  PubkeyFile-only, first-writer-wins map of one ROM with no IKEK. It now takes
  the certificate-tree rung of decode verification over
  `CertifyingKeys::from_blob` (every ROM, every `$KDB` key, every key under an
  id) with the Zen+ IKEK, exactly what `ls` shows.

Remaining follow-up (not a blocker for REQ-5/REQ-6):

- **extract.rs spillover** — `psptool-ops/src/extract.rs:156-157`
  (`build_encrypted_header_body`, a `#[cfg(test)]` helper) still stamps a
  header-inclusive `size_signed`; harmless (that test exercises decryption, not
  the signed region) but tracked for when `extract.rs` is routed.
