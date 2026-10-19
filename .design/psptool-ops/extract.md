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
| `extract_decompressed`     | `HeaderFile.get_signed_bytes()` — `-u` (`__main__.py:172`, `header_file.py:168-170`) |
| `extract_decrypted`        | `HeaderFile.to_decrypted_file_bytes()` — `-c` (`__main__.py:176`, `header_file.py:278-284`) |

Each op delegates to an already-audited `psptool-core` primitive
([`Entry::file_bytes`], [`Entry::header_file_window`],
[`HeaderEntry::get_signed_bytes`], [`HeaderEntry::get_decrypted_body`],
[`HeaderEntry::signature_bytes`]) and
performs no filesystem I/O — the write happens in the CLI layer. The unit's
production consumer is the CLI `extract` subcommand
(`crates/psptool-cli/src/cmds/extract.rs`), dispatched from `main.rs:82` (the
`-X` fast-path) and `main.rs:129` (`Command::Extract`).

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
`psptool-ops` crate lib suite — `extract::tests::*` (16 tests, round-trip +
class-gate + error-surface pins) — plus the live reference differential
`psptool-cli/tests/extract_oracle.rs` (see Verification).

## Requirements

- REQ-1: **`extract_raw` returns `file.get_bytes()`.** Port of the default
  `-X` output (`__main__.py:180` `output = file.get_bytes()`, multi-file
  `:200`), which for a `NestedBuffer` returns the raw backing bytes of the
  file's buffer. For a `Plain` / `Pubkey` / other file that buffer is the
  directory-declared entry; for a `HeaderFile` (and its `KeyStoreFile`
  subclass) it is grown to the `0x100` header (`header_file.py:32-33`) and
  then re-sized to the header's `rom_size` (`:72-75` grow, `:104-105`
  `self.buffer_size = self.rom_size`; `rom_size == 0` keeps the buffer so
  far) — reading on into the image past a short directory entry, or stopping
  at `rom_size` inside a long one (#101). `extract_raw` therefore takes the
  image `blob` (`Entry::file_bytes`). The CLI `-T` identical-bytes check
  compares the same bytes (`__main__.py:52-56`). Allocates a fresh `Vec<u8>`
  so the caller can write to disk without holding the parser's source-byte
  borrow.
- REQ-2: **`extract_decompressed` zlib-inflates the data region.** Ports the
  decompress step of upstream's `get_decrypted_decompressed_body`
  (`header_file.py:179-186` `zlib_decompress(output[:self.zlib_size])`, PSPTool
  `241629b`), including the pre-magic-prefix preservation of
  `utils.zlib_decompress`, its per-magic priority search (`utils.py:224-232`),
  its magic-free passthrough (`utils.py:254`), and the failure fallback: a
  corrupt or truncated stream yields the still-compressed decrypted region
  (`header_file.py:182-185`), which the CLI flags with upstream's
  `ZLIB decompression failed on file ...` warning. Operates on the header's data
  region (post-0x100-header body) of the HeaderFile buffer re-sized to the
  header's `rom_size`, which reads on into the image when `rom_size` outgrows
  the directory size (`header_file.py:72-75`, `Entry::header_file_window`; the
  ops take the image `blob` for it, #99); the `-u` precondition on
  `is_compressed` lives in the CLI (`__main__.py:170`).
- REQ-3: **`extract_decrypted` AES-unwrap + CBC-decrypts the data region.** Port
  of `HeaderFile.get_decrypted_body()` encrypted branch (`header_file.py:184-190`):
  unwrap the per-entry key with the caller-supplied [`Ikek`]
  (AES-128-ECB), then AES-128-CBC-decrypt the body under that key and the header
  IV. Returns [`BodyError::NotEncrypted`] when the header advertises
  `is_encrypted == 0` (mirroring the single-file `-c` guard
  `__main__.py:174-175`). Like REQ-2, it reads the `rom_size` HeaderFile buffer
  (#99).
- REQ-4: **Decompress/decrypt are gated to HeaderFile-class entries.** Both ops
  first resolve `entry.class.header()`; a non-`Header`/`KeyStore` class yields
  [`ExtractError::NotHeaderEntry`] — the accessors exist on `HeaderFile` and its
  `KeyStoreFile` subclass only, and single-file `-u` of a `KeyStoreFile` is its
  own `get_signed_bytes()`, `header ++ key_store` (`key_store_file.py:50-51`).
  Multi-file `-u`/`-c` transform only exact HeaderFiles (`type(file) is
  HeaderFile`, `__main__.py:193`, `:195`) and write a `KeyStoreFile` raw; that
  gate lives in the CLI (#100).
- REQ-5: **Typed, panic-free error surface.** [`ExtractError`] enumerates
  `NotHeaderEntry` and `Body(#[from] BodyError)`; all core failures (truncation,
  missing zlib magic, `NotCompressed`, `NotEncrypted`, decrypt failure) surface as
  typed `Err` — no `unwrap`/`expect`/`panic` on the production path (R-CODE-2).
- REQ-6: **CLI `extract` subcommand production consumer.** The tool exposes all
  three ops: `cmds/extract.rs` calls `extract_decompressed` (`:143` single,
  `:221` multi), `extract_decrypted` (`:154` single), and `extract_raw`
  (`:162`/`:251` default, `:227`/`:241`/`:245`/`:247` multi fallbacks), all with
  the image `opened.blob`, dispatched from `main.rs:82` (`-X` fast-path) and
  `main.rs:129` (`Command::Extract`).
- REQ-7: **`-u`/`-c` single-file output matches the upstream envelope.**
  Upstream `-X -u` returns `file.get_signed_bytes()`
  (`__main__.py:172`, `:194`) = `header(0x100) ++
  get_decrypted_decompressed_body()[:0x100+size_signed]` (`header_file.py:162-164`)
  — decrypt-then-decompress, header-prefixed, truncated to `size_signed`; and
  upstream single-file `-X -c` returns `file.to_decrypted_file_bytes()`
  (`__main__.py:176`) = `header(enc-flags cleared) ++ get_decrypted_body() ++
  signature` (`header_file.py:176-182`). `extract_decompressed` now delegates to
  `HeaderEntry::get_signed_bytes` and `extract_decrypted` assembles the
  cleared-header + decrypted-body + signature envelope inline; the CLI single-file
  path (`cmds/extract.rs`) applies the not-compressed / not-encrypted guards
  (`__main__.py:170`,`:174`) around them.

## Acceptance criteria

- AC-1 (REQ-1): `extract::tests::extract_raw_returns_body_bytes_verbatim_for_plain_entry`,
  `..._for_header_entry`, and `extract_raw_independent_of_class_works_on_pubkey`
  — the whole file across `Plain`, `Header`, `Pubkey` classes;
  `extract_raw_of_a_header_entry_is_its_rom_size_buffer` and core
  `body::tests::file_bytes_is_the_header_file_buffer_resized_to_rom_size` — a
  HeaderFile's `rom_size` buffer for directory sizes of `0`, short of and past
  `rom_size` (#101); live, `extract_oracle.rs` raw `-X` single- and multi-file
  (grown, shrunk, zero-size, `rom_size == 0`, grown `KeyStoreFile`), `-T`
  over four directory sizes of one file, and `get_bytes()` of every corpus
  HeaderFile-class file.
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
  `ExtractError::NotHeaderEntry`;
  `extract_decompressed_of_a_{compressed,raw}_key_store_*` pin a `KeyStore`'s
  own `get_signed_bytes()`, `header ++ key_store` (#100); `extract_oracle.rs`
  pins the multi-file exact-`HeaderFile` gate against the reference CLI.
- AC-7 (REQ-6): the `extract` subcommand round-trips a synthetic ROM's raw entry
  to an outfile (`psptool-cli/tests/synthetic.rs:213`
  `extract_raw_to_outfile_on_synthetic_rom`), reachable via `main.rs:129`
  (`Command::Extract`) and `main.rs:82` (`-X` fast-path).
- AC-8 (REQ-7): **Met.** `divergence_extract_envelope.rs`
  (`divergence_decompress_envelope_matches_get_signed_bytes`,
  `divergence_decrypt_envelope_matches_to_decrypted_file_bytes`) assert extract
  output equals upstream `get_signed_bytes` / `to_decrypted_file_bytes`
  (envelope constructed from the upstream algorithm, not copied from the target
  side). Both moved from `#[ignore]` to `#[test]` — 2 passed. Closes #88.

## REQ status table

| REQ | Status | Evidence |
|---|---|---|
| REQ-1 (`extract_raw` = `file.get_bytes()`) | SHIPPED | Impl `extract.rs:69` (`pub fn extract_raw(entry, blob)`, `entry.file_bytes(blob).as_bytes().to_vec()`) delegates to `Entry::file_bytes` (`body.rs:891`): a HeaderFile-class entry's `Entry::header_file_window` (`body.rs:867`, grown to the header and to `rom_size`, `header_file.py:32-33`, `:74-75`) cut to the normalised `rom_size` (`header_file.py:104-105` `self.buffer_size = self.rom_size`; `rom_size == 0` keeps the buffer, `:72-73`), any other entry its body (`Entry::get_bytes`, `entry.rs:407`); mirrors `file.get_bytes()` — the default `-X` output (`__main__.py:180` `output = file.get_bytes()`, multi-file `:200` `out_bytes = file.get_bytes()`) (#101). Non-test consumer: `psptool-cli/src/cmds/extract.rs:162` (single default) and `:251` (multi default; `:227`/`:241`/`:245`/`:247` fallbacks), the `-T` identical-bytes check `cmds/extract.rs:108-111` (`Entry::file_bytes`, `__main__.py:52-56`), dispatched `main.rs:82`/`:129`. Verification: `extract_raw_returns_body_bytes_verbatim_for_{plain,header}_entry`, `..._works_on_pubkey`, `extract_raw_of_a_header_entry_is_its_rom_size_buffer` (`extract.rs` unit tests); core `file_bytes_is_the_header_file_buffer_resized_to_rom_size`; live `extract_oracle.rs`: raw single- and multi-file `-X` (whole, grown, shrunk, zero-size, `rom_size == 0`, grown `KeyStoreFile`), `-T` over one file at four directory sizes, and `get_bytes()` of every corpus HeaderFile-class file byte-identical (4018 + 16 grown). |
| REQ-2 (`extract_decompressed` zlib inflate) | SHIPPED | Impl `extract.rs:98` (`pub fn extract_decompressed(entry, blob)`) over the `rom_size` HeaderFile buffer `Entry::header_file_window` (`body.rs:867`, `header_file.py:72-75`, #99) → `HeaderEntry::get_signed_bytes` (`body.rs:384`) → `get_decrypted_decompressed_body` → the shared `_decrypted_decompressed_body` decode (`body.rs:326`) → `get_decompressed_body` (`zlib_decompress(output[:zlib_size])`: `zlib_find_header` priority search, strict inflate, magic-free passthrough; still-compressed fallback on failure) — the decode the decode-verification ladder uses (#91). Mirrors `header_file.py:179-186`, `utils.py:218-254`. A `KeyStoreFile` takes its own `get_signed_bytes()`, `header ++ key_store` (`key_store_file.py:50-51`): `HeaderEntry::get_key_store_signed_bytes` (`body.rs:1011`, #100). Non-test consumer: `cmds/extract.rs:143` (single, + `warn_if_inflate_failed` `cmds/extract.rs:186` per `header_file.py:184`) / `:221` (multi, exact HeaderFiles only). Verification: `psptool-ops --test divergence_extract_zlib` (7 passed: priority, truncated, corrupt, no magic, `zlib_size` past the region, short fallback, control); `extract_decompressed_of_a_{compressed,raw}_key_store_*` (`extract.rs` unit tests); and `psptool-cli --test extract_oracle` (live reference, 6 passed: 11 single-file `-u` synthetic cases incl. the warning, two HeaderFiles grown past their directory entry and two compressed `KeyStoreFile`s, the same image in multi-file `-u`, `get_signed_bytes()` of all 4019 corpus HeaderFiles byte-identical — 13 of them grown, #99 — and the 12 corpus key-store files of multi-file `-u`, #100). |
| REQ-3 (`extract_decrypted` AES) | SHIPPED | Impl `extract.rs:148` (`pub fn extract_decrypted(entry, blob, ikek)`): `header.get_decrypted_body(file, ikek)` over the `rom_size` HeaderFile buffer `Entry::header_file_window` (#99; `get_decrypted_body` `body.rs:293`, `NotEncrypted` guard, key unwrap + CBC decrypt `body::decrypt`); mirrors `HeaderFile.get_decrypted_body()` encrypted branch (`header_file.py:286-292` `decrypt(self.body.get_bytes(), self.key, unwrapped_ikek, self.iv)`), not-encrypted case surfaced as `NotEncrypted` per the single-file `-c` guard (`__main__.py:174-175`). Non-test consumer: `cmds/extract.rs:154` (single-file `-c`); multi-file `-c` calls `get_decrypted_body` over the same window directly, for exact HeaderFiles only (`cmds/extract.rs:235-241`, the bare body of `__main__.py:196`). Verification: `extract_decrypted_returns_to_decrypted_file_bytes_envelope`, `..._uses_committed_encrypted_fixture`, `..._with_wrong_ikek_diverges_in_body`, `..._errors_when_header_not_encrypted`, `..._reads_the_rom_size_buffer_past_the_directory_size` (#99) — `extract.rs` unit tests; live: `extract_oracle.rs` single- and multi-file `-c` on the `header_encrypted` fixture whole and grown and on an encrypted `KeyStoreFile`, and `to_decrypted_file_bytes()` of all 256 encrypted corpus HeaderFiles byte-identical. |
| REQ-4 (HeaderFile-class gate) | SHIPPED | Impl `extract.rs:117` (`entry.class.header().ok_or(ExtractError::NotHeaderEntry)?`) via `EntryClass::header` (`entry.rs:371`, returns `Some` only for `Header`/`KeyStore`): the accessors exist on `HeaderFile` and its `KeyStoreFile` subclass only. The multi-file `type(file) is HeaderFile` gate (`__main__.py:193`, `:195`) is `cmds/extract.rs:219` (`matches!(entry.class, EntryClass::Header(_))`, #100): a `KeyStoreFile` is written raw. Non-test consumer: `cmds/extract.rs:143`/`:154` propagate the error via `?`/`context`. Verification: `extract_{decompressed,decrypted}_errors_for_{non_header,pubkey}_entry` (`extract.rs` unit tests) — 4 passed; the multi-file gate by `extract_oracle.rs` (synthetic plain / compressed / encrypted `KeyStoreFile`s under `-u` and `-c`, and the 12 corpus key-store files). |
| REQ-5 (typed panic-free errors) | SHIPPED | Impl `extract.rs:48` (`enum ExtractError { NotHeaderEntry, Body(#[from] BodyError) }`); every failure returns typed `Err` (a key store past its source: `BodyError::KeyStoreTruncated`, #100), no `unwrap`/`expect`/`panic` on the production path. Mirrors upstream's typed `NotCompressed`/`NotEncrypted` gates (`__main__.py:170`, `:174`). Non-test consumer: `cmds/extract.rs:143`/`:154` wrap with `.context(..)`, `:227` falls back to `extract_raw(entry, blob)`. Verification: covered by the `..._errors_*` tests (AC-3/AC-5/AC-6) and `extract_decompressed_of_a_raw_key_store_is_header_plus_body_size_bytes`; `cargo test -p psptool-ops --lib extract` 18 passed. |
| REQ-6 (CLI `extract` consumer) | SHIPPED | Consumer `psptool-cli/src/cmds/extract.rs`: `extract_decompressed` (`:143` single, `:221` multi), `extract_decrypted` (`:154` single), `extract_raw` (`:162` default, `:227`/`:241`/`:245`/`:247`/`:251` multi); imported `:28`; all pass the image `opened.blob` for the `rom_size` HeaderFile buffer (#99, #101). Dispatched from `main.rs:82` (`cmds::extract::run` `-X` fast-path) and `main.rs:129` (`Command::Extract(args) => cmds::extract::run(args, out)`). This IS the boundary CLI surface (goal.md R-DEFER-1). Verification: `psptool-cli/tests/synthetic.rs:213` (`extract_raw_to_outfile_on_synthetic_rom`); `psptool-cli/tests/extract_oracle.rs` runs both CLIs single- and multi-file. |
| REQ-7 (`-u`/`-c` envelope parity) | SHIPPED | `extract_decompressed` returns `header.get_signed_bytes(file, Some(Ikek::ZenPlus))` (`extract.rs:106`, `get_signed_bytes` `body.rs:384`) = `header ++ decrypted-decompressed[:0x100+size_signed]` per upstream `-u` (`__main__.py:172`, `header_file.py:168-170`), and for a `KeyStoreFile` `header ++ key_store` (`extract.rs:104`, `key_store_file.py:50-51`, #100); `extract_decrypted` assembles `header(is_encrypted+IV cleared) ++ get_decrypted_body() ++ signature_bytes()` (`extract.rs`, `header_file.py:176-182`) per single-file `-c` (`__main__.py:176`). Non-test consumer: `cmds/extract.rs:143` (`-u`) / `:154` (`-c`) single-file path, with the not-compressed/not-encrypted guards mirroring `__main__.py:170`/`:174`. Verification: `divergence_extract_envelope.rs` — both pins `#[test]`, 2 passed; live, byte-for-byte vs the reference CLI: `extract_oracle.rs` (synthetic single-file `-u`/`-c` incl. `KeyStoreFile`s + every corpus HeaderFile's `get_signed_bytes()` / `to_decrypted_file_bytes()`). |

## Architecture

**Three thin delegators, no owned buffer.** `extract.rs` holds no state and does
no I/O. Each function resolves a `psptool-core` primitive and copies the result
into a fresh `Vec<u8>`:

- `extract_raw(entry, blob)` (`extract.rs:69`) → `Entry::file_bytes`
  (`body.rs:891`) → `SourceBytes::as_bytes().to_vec()`: the `rom_size`
  HeaderFile buffer for a HeaderFile-class entry, else `Entry::get_bytes`
  (`entry.rs:407`, the body). Defined for every entry class.
- `extract_decompressed(entry, blob)` (`extract.rs:98`) →
  `Entry::header_file_window` (`body.rs:867`) → `HeaderEntry::get_signed_bytes`
  (`body.rs:384`), which decrypts then inflates
  (`get_decrypted_decompressed_body`, `header_file.py:172-189`) and slices the
  envelope (`header_file.py:168-170`) — or, for a `KeyStoreFile`,
  `HeaderEntry::get_key_store_signed_bytes` (`body.rs:1011`), `header ++
  key_store` (`key_store_file.py:50-51`).
- `extract_decrypted(entry, blob, ikek)` (`extract.rs:148`) →
  `Entry::header_file_window` → the cleared header, `HeaderEntry::get_decrypted_body`
  (`body.rs:293`) and `signature_bytes` (`header_file.py:278-284`). The
  key-unwrap (AES-128-ECB with the [`Ikek`]) + CBC-decrypt live entirely in the
  vetted core (`body::decrypt`).

**The HeaderFile buffer, not the directory entry (#99, #101).** Upstream
re-sizes a `HeaderFile` to its header's `rom_size` (`header_file.py:72-75` grows
it, `:104-105` pins it); a grow reads on into the parent buffer. All three ops
therefore take the image `blob` the entry was parsed from and read
`Entry::header_file_window(blob)` — the same window the decode-verification
ladder reads — instead of `Entry::body`, which stops at the directory-declared
size; `extract_raw` cuts it to `rom_size` (`Entry::file_bytes`), since
`get_bytes()` is the whole buffer, so a directory entry longer than `rom_size`
yields `rom_size` bytes. The CLI passes `opened.blob`.

**IKEK selection is caller-supplied, not resolved here.** `extract_decrypted`
takes an [`Ikek`] parameter; the CLI passes `Ikek::ZenPlus` (`cmds/extract.rs:154`,
`:239`), mirroring upstream's hard-coded Zen+ default (`get_unwrapped_ikek`
`header_file.py:192-203`, which returns `UNWRAPPED_IKEK_ZEN_PLUS` with the
per-file MD5 discrimination commented out). Chain-of-trust IKEK resolution is
out of scope for this unit (tracked separately by #13, referenced in the module
doc-comment `extract.rs:74-76`).

**Class gate vs. flag gate.** The `NotHeaderEntry` gate (REQ-4) is structural —
`EntryClass::header` returns `None` for `Plain`/`Pubkey`/pointer classes, so
decompress/decrypt reject them before touching the body. The `NotCompressed` /
`NotEncrypted` gates are content-driven (the header's `is_compressed` /
`is_encrypted` fields). The CLI distinguishes single-file mode (propagate the
typed error, `cmds/extract.rs:143`/`:154`) from multi-file mode, which
transforms only exact HeaderFiles (`type(file) is HeaderFile`,
`cmds/extract.rs:219`) and writes everything else — a `KeyStoreFile` included —
raw, matching upstream's split (`__main__.py:169-180` vs `:193-200`).

**What lives in the CLI, not here.** The `-T` type-regex selector
(`cmds/extract.rs:87-128`, port of `find_files_by_type_regex`
`__main__.py:31-58`), the `-n` duplicate-skip and multi-file filename rules
(`cmds/extract.rs:178-195`, port of `__main__.py:201-233`), the `-k` PEM
conversion (`cmds/extract.rs:130-135`, `pem_for_pubkey` `:322-342`, port of
`get_pem_encoded`), and outfile/stdout handling (`cmds/extract.rs:141-156`, port
of `__main__.py:277-283`) are all CLI-arg-layer concerns. They are documented in
the CLI surface, not as REQs of this ops unit.

## Known issues

**Blocker #80 — test-helper `size_signed` convention — RESOLVED.** The
`#[cfg(test)]` helper `build_encrypted_header_body` now stamps `size_signed =
plaintext.len()` (header-EXCLUSIVE, matching the fixed `get_signed_bytes` and
real firmware — `body.rs:374-376`), replacing the pre-#79 header-inclusive
convention. Closed with the #88 fix pass.

**#99 — HeaderFile grown past its directory entry — RESOLVED.** `-u`/`-c` read
the directory-sized `Entry::body`, so the 13 corpus HeaderFiles whose header
`rom_size` exceeds their directory size failed `BodyTooSmall` where upstream
returns bytes. The ops now read `Entry::header_file_window(blob)`; pinned live by
`extract_oracle.rs::corpus_grown_headerfile_window_matches_reference` (13/13) and
the `grown-*` synthetic cases.

**#101 — raw `-X` of a HeaderFile wrote the directory entry — RESOLVED.**
`extract_raw` returned `Entry::body`; upstream's `get_bytes()` is the buffer
re-sized to `rom_size` (`header_file.py:104-105`), so 16 corpus HeaderFiles
(grown past their directory size) came out short and 144 (shrunk inside it)
long, and `-T` compared the wrong bytes (`__main__.py:52-56`). `extract_raw`
now takes the image and returns `Entry::file_bytes`; pinned live by
`extract_oracle.rs` (raw synthetic cases, the `-T` case, and `get_bytes()` of
every corpus HeaderFile-class file). The `ls` `size` column, upstream's
`buffer_size` (`psptool.py:249`), still shows the directory size; it is
tolerated in `differential.rs` and tracked separately.

**#100 — `KeyStoreFile` extracted like a `HeaderFile` — RESOLVED.** Multi-file
`-u`/`-c` applied the HeaderFile transforms to every `HeaderEntry` class, so the
12 corpus `KeyStoreFile`s were written as `header ++ store` instead of their raw
bytes; single-file `-u` of a compressed one used the HeaderFile envelope instead
of `KeyStoreFile.get_signed_bytes()`. The CLI gates multi-file on
`EntryClass::Header`, and `extract_decompressed` takes
`HeaderEntry::get_key_store_signed_bytes` for a `KeyStore`; pinned live by
`extract_oracle.rs::corpus_multi_file_key_store_matches_reference` (12/12) and
the `key-store-*` synthetic cases.

## Verification

The list below IS the gauntlet for this module; run inside `nix-shell` so
`PSPTOOL_REFERENCE` + `PSPTOOL_TEST_CORPUS` are set (a skipped suite is a red
gate, not a pass).

- `cargo test -p psptool-ops --lib extract` — **18 passed, 0 failed, 0 ignored**.
  This is the module's self-oracle (`parity_ops = []`): `extract_raw_*` (REQ-1, 4
  tests), `extract_decompressed_*` (REQ-2/REQ-4, 4 tests), `extract_decrypted_*`
  (REQ-3/REQ-4, 6 tests), the two `..._reads_the_rom_size_buffer_past_the_directory_size`
  pins (REQ-2/REQ-3, #99) and the two `extract_decompressed_of_a_*_key_store_*`
  pins (REQ-2/REQ-4, #100).
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

- `cargo test -p psptool-cli --test extract_oracle` — **6 passed, 0 ignored**
  (needs `PSPTOOL_REFERENCE`; the corpus tests also `PSPTOOL_TEST_CORPUS`):
  both CLIs single- and multi-file on synthetic `-u`/`-c`/raw images (zlib edge
  cases, HeaderFiles grown past or shrunk inside their directory entry,
  zero-size records, plain / compressed / encrypted `KeyStoreFile`s), `-T`
  over one file behind four directory sizes
  (`synthetic_type_regex_compares_the_rom_size_buffers`, #101), every corpus
  HeaderFile-class file's raw bytes and every HeaderFile's `-u`/`-c` bytes vs
  the reference's `get_bytes()` / `get_signed_bytes()` /
  `to_decrypted_file_bytes()` — 4034 raw, 4022 `-u`, 256 `-c`; the 16 grown
  ones separately (`corpus_grown_headerfile_window_matches_reference`, #99,
  #101) —
  and both CLIs' multi-file `-u` key-store files on the corpus ROMs holding
  `KeyStoreFile`s (`corpus_multi_file_key_store_matches_reference`, 12 files,
  #100).
