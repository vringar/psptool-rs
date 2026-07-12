# Extract byte-producing ops (`extract_raw` / `extract_decompressed` / `extract_decrypted`)

<!--
tier: 3-component
status: draft
baseline-commit: 146b5fd32d21ce5e8e19f848bc58ba07804b8e62
upstream-paths:
  - /tmp/psptool-ref/psptool/__main__.py
  - /tmp/psptool-ref/psptool/file.py
  - /tmp/psptool-ref/psptool/header_file.py
-->

## Summary

`crates/psptool-ops/src/extract.rs` is the extract-payload unit — three thin,
I/O-free functions that take a parsed [`Entry`] and return owned `Vec<u8>` bytes,
each a port of one reference-tool payload accessor:

| This module                | PSPTool accessor (`__main__.py` `-X` path)                                    |
| -------------------------- | ----------------------------------------------------------------------------- |
| `extract_raw`              | `file.get_bytes()` (`__main__.py:180`, `NestedBuffer.get_bytes`)              |
| `extract_decompressed`     | zlib-inflate step of `get_decrypted_decompressed_body` (`header_file.py:169-174`) |
| `extract_decrypted`        | `HeaderFile.get_decrypted_body()` (`header_file.py:184-190`)                  |

Each op delegates to an already-audited `psptool-core` primitive
([`Entry::get_bytes`], [`HeaderEntry::data_region`],
[`HeaderEntry::get_decompressed_body`], [`HeaderEntry::get_decrypted_body`]) and
performs no filesystem I/O — the write happens in the CLI layer. The unit's
production consumer is the CLI `extract` subcommand
(`crates/psptool-cli/src/cmds/extract.rs`), dispatched from `main.rs:82` (the
`-X` fast-path) and `main.rs:125` (`Command::Extract`).

**Scope boundary.** This unit owns only the three byte-producing primitives and
their typed error surface. Everything the reference `-X` command layers *around*
those bytes is owned by the CLI arg layer (`cmds/extract.rs`), not here:
selector modes (`-d`/`-e` indices, `-T` type-regex, multi-file default),
duplicate skipping (`-n`), PEM conversion (`-k`), outfile/stdout handling
(`-o`), and the multi-file filename rules. Those are cited where relevant but
are not REQs of this unit.

`parity_ops` is `[]`: the extract path is not exercised by `corpus_roundtrip`
(read-parse-reserialize identity, no mutation) nor by the `ls`/`ls_json`
`differential` (read-only listing surface). The unit's oracle is therefore the
`psptool-ops` crate lib suite — `extract::tests::*` (14 tests, round-trip +
class-gate + error-surface pins).

## Requirements

- REQ-1: **`extract_raw` returns the entry body bytes verbatim.** Port of
  `file.get_bytes()` — the default `-X` output (`__main__.py:180`
  `output = file.get_bytes()`), which for a `NestedBuffer` returns the raw
  backing bytes. Class-independent: works for `Plain`, `Pubkey`, `Header`,
  `KeyStore`. Allocates a fresh `Vec<u8>` so the caller can write to disk without
  holding the parser's source-byte borrow.
- REQ-2: **`extract_decompressed` zlib-inflates the data region.** Ports the
  decompress step of upstream's `get_decrypted_decompressed_body`
  (`header_file.py:169-174` `zlib_decompress(output[:self.zlib_size])`), including
  the pre-magic-prefix preservation of `utils.zlib_decompress`. Operates on the
  header's data region (post-0x100-header body). Returns
  [`BodyError::NotCompressed`] when the header advertises `is_compressed == 0`.
- REQ-3: **`extract_decrypted` AES-unwrap + CBC-decrypts the data region.** Port
  of `HeaderFile.get_decrypted_body()` encrypted branch (`header_file.py:184-190`):
  unwrap the per-entry key with the caller-supplied [`Ikek`]
  (AES-128-ECB), then AES-128-CBC-decrypt the body under that key and the header
  IV. Returns [`BodyError::NotEncrypted`] when the header advertises
  `is_encrypted == 0` (mirroring the single-file `-c` guard
  `__main__.py:174-175`).
- REQ-4: **Decompress/decrypt are gated to HeaderFile-class entries.** Both ops
  first resolve `entry.class.header()`; a non-`Header`/`KeyStore` class yields
  [`ExtractError::NotHeaderEntry`]. Mirrors upstream's `type(file) is HeaderFile`
  guards (`__main__.py:193`, `:195`) — decompression/decryption are only defined
  for `HeaderFile` bodies. `KeyStore` is treated like `Header` (both carry a
  [`HeaderEntry`]).
- REQ-5: **Typed, panic-free error surface.** [`ExtractError`] enumerates
  `NotHeaderEntry` and `Body(#[from] BodyError)`; all core failures (truncation,
  missing zlib magic, `NotCompressed`, `NotEncrypted`, decrypt failure) surface as
  typed `Err` — no `unwrap`/`expect`/`panic` on the production path (R-CODE-2).
- REQ-6: **CLI `extract` subcommand production consumer.** The tool exposes all
  three ops: `cmds/extract.rs` calls `extract_decompressed` (`:127` single,
  `:162` multi), `extract_decrypted` (`:129` single, `:164` multi), and
  `extract_raw` (`:137`/`:171` default, `:162-168` multi fallback), dispatched
  from `main.rs:82` (`-X` fast-path) and `main.rs:125` (`Command::Extract`).
- REQ-7: **`-u`/`-c` single-file output matches the upstream envelope.**
  Upstream `-X -u` returns `file.get_signed_bytes()`
  (`__main__.py:172`, `:194`) = `header(0x100) ++
  get_decrypted_decompressed_body()[:0x100+size_signed]` (`header_file.py:162-164`)
  — decrypt-then-decompress, header-prefixed, truncated to `size_signed`; and
  upstream single-file `-X -c` returns `file.to_decrypted_file_bytes()`
  (`__main__.py:176`) = `header(enc-flags cleared) ++ get_decrypted_body() ++
  signature` (`header_file.py:176-182`). The Rust extract ops return only the
  bare inflated / decrypted body (no header prefix, no `size_signed` truncation,
  no decrypt-first for encrypted+compressed entries, no signature). This
  observable-byte parity is not yet delivered.

## Acceptance criteria

- AC-1 (REQ-1): `extract::tests::extract_raw_returns_body_bytes_verbatim_for_plain_entry`
  (`extract.rs:175-185`), `..._for_header_entry` (`extract.rs:187-196`), and
  `extract_raw_independent_of_class_works_on_pubkey` (`extract.rs:198-207`) —
  identical bytes returned across `Plain`, `Header`, `Pubkey` classes.
- AC-2 (REQ-2): `extract::tests::extract_decompressed_round_trips_committed_compressed_fixture`
  (`extract.rs:211-227`) — the committed `header_compressed` fixture inflates back
  to `b"hello, psptool-rs"`.
- AC-3 (REQ-2): `extract::tests::extract_decompressed_errors_when_header_not_compressed`
  (`extract.rs:250-258`) — an `is_compressed == 0` header yields
  `ExtractError::Body(BodyError::NotCompressed)`.
- AC-4 (REQ-3): `extract::tests::extract_decrypted_round_trips_synthetic_encrypted_entry`
  (`extract.rs:262-274`) and `..._uses_committed_encrypted_fixture`
  (`extract.rs:276-293`) — a Zen+-IKEK-wrapped entry decrypts back to its known
  plaintext; `extract_decrypted_with_wrong_ikek_does_not_match_plaintext`
  (`extract.rs:325-340`) proves the IKEK is consulted.
- AC-5 (REQ-3): `extract::tests::extract_decrypted_errors_when_header_not_encrypted`
  (`extract.rs:315-323`) — an `is_encrypted == 0` header yields
  `ExtractError::Body(BodyError::NotEncrypted)`.
- AC-6 (REQ-4): `extract::tests::extract_decompressed_errors_for_non_header_entry`
  (`extract.rs:229-238`), `..._for_pubkey_entry` (`extract.rs:240-248`),
  `extract_decrypted_errors_for_non_header_entry` (`extract.rs:295-303`),
  `..._for_pubkey_entry` (`extract.rs:305-313`) all yield
  `ExtractError::NotHeaderEntry`; `extract_decompressed_works_on_keystore_class`
  (`extract.rs:344-356`) proves `KeyStore` is treated like `Header` (it reaches
  the `NotCompressed` gate, not `NotHeaderEntry`).
- AC-7 (REQ-6): the `extract` subcommand round-trips a synthetic ROM's raw entry
  to an outfile (`psptool-cli/tests/synthetic.rs:213`
  `extract_raw_to_outfile_on_synthetic_rom`), reachable via `main.rs:125`
  (`Command::Extract`) and `main.rs:82` (`-X` fast-path).
- AC-8 (REQ-7): **Not met.** No test asserts extract output equals upstream
  `get_signed_bytes` / `to_decrypted_file_bytes`; the extract ops return the bare
  body. Tracked by blocker #88 — the AC lands when the `-u`/`-c` path is wired to
  the envelope primitives and a byte-parity test moves from absent to green.

## REQ status table

| REQ | Status | Evidence |
|---|---|---|
| REQ-1 (`extract_raw` verbatim) | SHIPPED | Impl `extract.rs:41-43` (`pub fn extract_raw`, `entry.get_bytes().as_bytes().to_vec()`) delegates to `Entry::get_bytes` (`entry.rs:381`, returns `&self.body`); mirrors `file.get_bytes()` — the default `-X` output (`__main__.py:180` `output = file.get_bytes()`). Non-test consumer: `psptool-cli/src/cmds/extract.rs:137` (single default) and `:171`/`:162-168` (multi default + fallback), dispatched `main.rs:82`/`:125`. Verification: `extract_raw_returns_body_bytes_verbatim_for_{plain,header}_entry` + `..._works_on_pubkey` (`extract.rs:175-207`) — 3 passed. |
| REQ-2 (`extract_decompressed` zlib inflate) | SHIPPED | Impl `extract.rs:57-62` (`pub fn extract_decompressed`): `header.data_region(..)` (`body.rs:202`) then `header.get_decompressed_body(..)` (`body.rs:304`, `NotCompressed` guard `:305-307`); mirrors upstream zlib-inflate step (`header_file.py:169-174` `zlib_decompress(output[:self.zlib_size])`, prefix-preserving per `utils.zlib_decompress`). Non-test consumer: `cmds/extract.rs:127` (single) / `:162` (multi). Verification: `extract_decompressed_round_trips_committed_compressed_fixture` (`extract.rs:211`) + `..._errors_when_header_not_compressed` (`extract.rs:250`) — 2 passed. NOTE: bare inflated body only; full `-u` envelope parity is REQ-7. |
| REQ-3 (`extract_decrypted` AES) | SHIPPED | Impl `extract.rs:77-81` (`pub fn extract_decrypted`): `header.get_decrypted_body(entry.body.as_bytes(), ikek)` (`body.rs:267`, `NotEncrypted` guard `:269`, key unwrap + CBC decrypt `:352-373`); mirrors `HeaderFile.get_decrypted_body()` encrypted branch (`header_file.py:184-190` `decrypt(self.body.get_bytes(), self.key, unwrapped_ikek, self.iv)`), not-encrypted case surfaced as `NotEncrypted` per the single-file `-c` guard (`__main__.py:174-175`). Non-test consumer: `cmds/extract.rs:129` (single) / `:164` (multi). Verification: `extract_decrypted_round_trips_synthetic_encrypted_entry` (`extract.rs:262`), `..._uses_committed_encrypted_fixture` (`extract.rs:276`), `..._with_wrong_ikek_does_not_match_plaintext` (`extract.rs:325`), `..._errors_when_header_not_encrypted` (`extract.rs:315`) — 4 passed. NOTE: bare decrypted body only; full single-file `-c` envelope parity is REQ-7. |
| REQ-4 (HeaderFile-class gate) | SHIPPED | Impl `extract.rs:58` / `:78` (`entry.class.header().ok_or(ExtractError::NotHeaderEntry)?`) via `EntryClass::header` (`entry.rs:348-353`, returns `Some` only for `Header`/`KeyStore`); mirrors upstream `type(file) is HeaderFile` guards (`__main__.py:193`, `:195`). Non-test consumer: `cmds/extract.rs:127`/`:129` propagate the error via `?`/`context`. Verification: `extract_{decompressed,decrypted}_errors_for_{non_header,pubkey}_entry` (`extract.rs:229-248`, `:295-313`) + `extract_decompressed_works_on_keystore_class` (`extract.rs:344-356`) — 5 passed. |
| REQ-5 (typed panic-free errors) | SHIPPED | Impl `extract.rs:22-34` (`enum ExtractError { NotHeaderEntry, Body(#[from] BodyError) }`); every failure returns typed `Err`, no `unwrap`/`expect`/`panic` on the production path. Mirrors upstream's typed `NotCompressed`/`NotEncrypted` gates (`header_file.py:185`, `header_file.py` compressed field). Non-test consumer: `cmds/extract.rs:127-129` wrap with `.context(..)`, `:162-164` `unwrap_or_else(|_| extract_raw(entry))` fallback. Verification: covered by the `..._errors_*` tests (AC-3/AC-5/AC-6); `cargo test -p psptool-ops --lib extract` 14 passed. |
| REQ-6 (CLI `extract` consumer) | SHIPPED | Consumer `psptool-cli/src/cmds/extract.rs`: `extract_decompressed` (`:127` single, `:162` multi), `extract_decrypted` (`:129` single, `:164` multi), `extract_raw` (`:137`/`:171` default, `:162-168` multi fallback); imported `:25`. Dispatched from `main.rs:82` (`cmds::extract::run` `-X` fast-path) and `main.rs:125` (`Command::Extract(args) => cmds::extract::run(args, out)`). This IS the boundary CLI surface (goal.md R-DEFER-1). Verification: `psptool-cli/tests/synthetic.rs:213` (`extract_raw_to_outfile_on_synthetic_rom`); CLI builds and dispatches. |
| REQ-7 (`-u`/`-c` envelope parity) | NOT-STARTED | Open prereq blocker #88. `extract_decompressed` (`extract.rs:57-62`) returns bare `zlib_inflate(data_region)` — upstream `-u` returns `file.get_signed_bytes()` = `header ++ decrypted-decompressed[:0x100+size_signed]` (`__main__.py:172`, `header_file.py:162-164`); `extract_decrypted` (`extract.rs:77-81`) returns bare `get_decrypted_body()` — upstream single-file `-c` returns `file.to_decrypted_file_bytes()` = `header(enc-cleared) ++ body ++ signature` (`__main__.py:176`, `header_file.py:176-182`). The envelope primitive already exists in core (`get_signed_bytes` `body.rs:377`, used by `sign.rs`) but the extract path uses the wrong primitive; no header prefix, no `size_signed` truncation, no decrypt-first, no signature. Not caught by any suite (`parity_ops=[]`; extract absent from the `ls`/`ls_json` differential). |

## Architecture

**Three thin delegators, no owned buffer.** `extract.rs` holds no state and does
no I/O. Each function resolves a `psptool-core` primitive and copies the result
into a fresh `Vec<u8>`:

- `extract_raw` (`extract.rs:41-43`) → `Entry::get_bytes` (`entry.rs:381`) →
  `SourceBytes::as_bytes().to_vec()`. Class-independent (the raw body is defined
  for every entry class).
- `extract_decompressed` (`extract.rs:57-62`) → `EntryClass::header`
  (`entry.rs:348`) → `HeaderEntry::data_region` (`body.rs:202`) →
  `HeaderEntry::get_decompressed_body` (`body.rs:304`). The two-step
  (`data_region` then inflate) is why the module's inline note (`extract.rs:50-53`)
  flags that for entries that are *both* encrypted and compressed the caller must
  decrypt first — `extract_decompressed` feeds the still-encrypted data region to
  zlib and will fail. Upstream layers the same way inside
  `get_decrypted_decompressed_body` (`header_file.py:166-174`, decrypt then
  decompress) — the divergence is that the Rust op stops at the inflate step
  (REQ-7 / #88).
- `extract_decrypted` (`extract.rs:77-81`) → `EntryClass::header` →
  `HeaderEntry::get_decrypted_body` (`body.rs:267`). The key-unwrap
  (AES-128-ECB with the [`Ikek`]) + CBC-decrypt live entirely in the vetted core
  (`body.rs:352-373`); the op is a pure delegate.

**IKEK selection is caller-supplied, not resolved here.** `extract_decrypted`
takes an [`Ikek`] parameter; the CLI passes `Ikek::ZenPlus` (`cmds/extract.rs:129`,
`:164`), mirroring upstream's hard-coded Zen+ default (`get_unwrapped_ikek`
`header_file.py:192-203`, which returns `UNWRAPPED_IKEK_ZEN_PLUS` with the
per-file MD5 discrimination commented out). Chain-of-trust IKEK resolution is
out of scope for this unit (tracked separately by #13, referenced in the module
doc-comment `extract.rs:74-76`).

**Class gate vs. flag gate.** The `NotHeaderEntry` gate (REQ-4) is structural —
`EntryClass::header` returns `None` for `Plain`/`Pubkey`/pointer classes, so
decompress/decrypt reject them before touching the body. The `NotCompressed` /
`NotEncrypted` gates are content-driven (the header's `is_compressed` /
`is_encrypted` fields). The CLI distinguishes single-file mode (propagate the
typed error, `cmds/extract.rs:127-129`) from multi-file mode (fall back to the
raw body, `cmds/extract.rs:162-168`), matching upstream's "error in single-file
mode, silently raw in multi-file mode" split (`__main__.py:169-180` vs
`:193-200`).

**What lives in the CLI, not here.** The `-T` type-regex selector
(`cmds/extract.rs:87-122`, port of `find_files_by_type_regex`
`__main__.py:31-58`), the `-n` duplicate-skip and multi-file filename rules
(`cmds/extract.rs:178-195`, port of `__main__.py:201-233`), the `-k` PEM
conversion (`cmds/extract.rs:130-135`, `pem_for_pubkey` `:322-342`, port of
`get_pem_encoded`), and outfile/stdout handling (`cmds/extract.rs:141-156`, port
of `__main__.py:277-283`) are all CLI-arg-layer concerns. They are documented in
the CLI surface, not as REQs of this ops unit.

## Known issues

**Blocker #80 — test-helper `size_signed` convention (harmless, not a REQ
regression).** The `#[cfg(test)]` helper `build_encrypted_header_body`
(`extract.rs:132-171`) stamps `size_signed = (HEADER_FILE_LEN + plaintext.len())`
at `extract.rs:156-157` — the *header-inclusive* pre-#79 convention. The fixed
`get_signed_bytes` and real firmware treat `size_signed` as *header-exclusive*
(the body-signed length). This is harmless today: the helper's tests exercise the
decryption path (`data_region` / `get_decrypted_body`), never the signed region,
so the gauntlet stays green. It does **not** make any REQ NOT-STARTED — it is
test-helper hygiene, to be corrected when `extract.rs` gets its fix pass. Tracked
by #80 (low priority).

## Verification

The list below IS the gauntlet for this module; run inside `nix-shell` so
`PSPTOOL_REFERENCE` + `PSPTOOL_TEST_CORPUS` are set (a skipped suite is a red
gate, not a pass).

- `cargo test -p psptool-ops --lib extract` — **14 passed, 0 failed, 0 ignored**.
  This is the module's self-oracle (`parity_ops = []`): `extract_raw_*` (REQ-1, 3
  tests), `extract_decompressed_*` (REQ-2/REQ-4, 4 tests), `extract_decrypted_*`
  (REQ-3/REQ-4, 6 tests), `extract_decompressed_works_on_keystore_class` (REQ-4,
  1 test).
- `cargo test -p psptool-ops --lib` — full crate lib suite (the extract ops share
  the crate with `sign`/`verify`/`list`/`replace`).
- `cargo test -p psptool-cli --test synthetic` — exercises the CLI consumer
  (`extract_raw_to_outfile_on_synthetic_rom`, `synthetic.rs:213`), the end-to-end
  `-X` → `extract_raw` → outfile path (REQ-6).
- `cargo test -p psptool-core --test corpus_roundtrip` — byte-exact roundtrip;
  does **not** exercise the extract path (read-parse-reserialize identity, no
  payload extraction). `parity_ops` for this route is `[]`.
- `cargo test -p psptool-cli --test differential` — `ls`/`ls_json` structural
  parity vs reference PSPTool; does **not** exercise the `-X` extract surface
  (read-only listing). `parity_ops` for this route is `[]`.

REQ-7 has no green verification (it is NOT-STARTED); the `-u`/`-c` envelope
byte-parity test lands with the blocker #88 fix.
