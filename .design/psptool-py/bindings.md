# Python bindings: drop-in `psptool` module (`crates/psptool-py`)

<!--
tier: 3-component
status: draft
baseline-commit: ff8a6d0c
upstream-paths:
  - /tmp/psptool-ref/psptool/psptool.py
  - /tmp/psptool-ref/psptool/blob.py
  - /tmp/psptool-ref/psptool/rom.py
  - /tmp/psptool-ref/psptool/fet.py
  - /tmp/psptool-ref/psptool/directory.py
  - /tmp/psptool-ref/psptool/entry.py
  - /tmp/psptool-ref/psptool/file.py
  - /tmp/psptool-ref/psptool/header_file.py
  - /tmp/psptool-ref/psptool/pubkey_file.py
  - /tmp/psptool-ref/psptool/key_store_file.py
  - /tmp/psptool-ref/psptool/microcode_file.py
  - /tmp/psptool-ref/psptool/cert_tree.py
  - /tmp/psptool-ref/psptool/crypto.py
  - /tmp/psptool-ref/psptool/utils.py
upstream-rev: PSPTool 241629b (vringar/PSPTool claude-main; decode-verified signal)
-->

## Summary

`crates/psptool-py` builds a CPython extension (pyo3, stable ABI `abi3-py39`,
packaged by maturin) that is importable as **`psptool`** — the reference tool's
own package name — so downstream code (`from psptool import PSPTool`,
`isinstance(f, psptool.header_file.HeaderFile)`) keeps working with only the
dependency swapped. The native module is `psptool._native`; the pure-Python
files under `python/psptool/` only re-export its classes at the upstream module
paths (`psptool.psptool`, `psptool.header_file`, `psptool.file`, ...). All
parsing, decoding, verification and signing logic is Rust.

Consumers (board #384 psp-etl, #388/#484 psp-db) key content identities on
`sha256(get_decrypted_decompressed_body())` and store `(rom, directory, file)`
indices, so the binding must reproduce upstream's **object graph**, not just
its bytes: the same ROM list, the same directory order (FET order, depth-first
over secondary/tertiary pointers, combo directories flattened away), the same
per-directory `files` lists (parse failures dropped, one `File` object shared by
every directory that references the same ROM-relative offset), and the same
class per file. That graph is built by `model.rs` (pure Rust, a translation of
`blob.py` / `rom.py` / `fet.py` / `directory.py` / `entry.py` / `file.py`
construction order) on top of the `psptool-core` parsers; `psptool-core`'s own
`walk_directories` is deliberately not reused for ordering because it is
LIFO-ordered and keeps combo nodes (both fine for `ls`, wrong for positional
indices).

The Python objects are views over **one shared image buffer** (`image.rs`):
every class derives from the native `NestedBuffer`, which resolves reads and
writes through its parent chain to the root exactly like `utils.NestedBuffer`
(`utils.py:40-114`). Parse-time attributes that upstream stores by value
(`size_signed`, `encrypted`, `zlib_size`, ...) are instance attributes set at
construction; methods read the live buffer. Writes go through the shared buffer
(bumping a generation counter that invalidates the cached decode-verification
key map), so edits are visible to every view and `to_file` emits the mutated
image; an unmutated image round-trips byte-exactly.

## Requirements

- REQ-1: **Import surface.** `import psptool` exposes `PSPTool` and
  `__version__`; the upstream submodules (`psptool.psptool`, `.blob`, `.rom`,
  `.fet`, `.directory`, `.entry`, `.file`, `.header_file`, `.pubkey_file`,
  `.key_store_file`, `.microcode_file`, `.cert_tree`, `.crypto`, `.errors`,
  `.utils`) re-export the matching native classes (`__init__.py:17-20`).
- REQ-2: **Construction.** `PSPTool.from_file(filename, verbose=False)` reads a
  file; `PSPTool(rom_bytes, verbose=False, filename=None)` parses an in-memory
  bytes-like object (`psptool.py:34-51`). The class is mutable so
  `unittest.mock.patch("...PSPTool.from_file")` works (psp-etl's test suite).
- REQ-3: **Upstream object order.** `psp.blob.roms[r].directories[d].files[f]`
  resolves to the same entry as upstream for every `(r, d, f)`: ROMs per FET
  candidate (`blob.py:58-84`), directories per FET slot with combo expansion and
  depth-first secondary/tertiary recursion deduplicated by a global
  ROM-relative-offset cache (`fet.py:59-92`, `directory.py:57-101`), files per
  entry with the global `files_by_offset` cache, the APOB exception and
  `ParseError` drops (`file.py:39-56`, `:249-272`).
- REQ-4: **File classes and buffer sizing.** Each file is a `File`, `BiosFile`,
  `HeaderFile`, `KeyStoreFile`, `PubkeyFile` or `MicrocodeFile` chosen as
  `File.from_entry` does (`file.py:259-269`), sized as `File.__init__` /
  `HeaderFile._parse` size it (`file.py:285-319`, `header_file.py:31-106`).
- REQ-5: **Read attributes.** `type`, `entry.subprogram`/`instance`,
  `get_address()`, `buffer_size`, `get_readable_type/version/magic()`,
  `md5()`, `shannon_entropy()`, `compressed`, `encrypted`, `is_signed`,
  `size_uncompressed`, `load_addr`, `zlib_size`, `header`, `body`,
  `directory.magic`/`zen_generation`, `rom.agesa_version` match upstream
  values (`file.py:352-383`, `header_file.py:137-166,309-318`,
  `pubkey_file.py:142-171`, `rom.py:24-52`).
- REQ-6: **HeaderFile decode.** `get_decrypted_body()`,
  `get_decrypted_decompressed_body()` and `get_signed_bytes()` are
  byte-identical to upstream (`header_file.py:168-189,286-292`); the
  `decode_verification()` / `decode_verified()` /
  `decode_verification_method()` / `plaintext_identity_ok()` quartet reports the
  upstream ladder (`header_file.py:191-276`).
- REQ-7: **NestedBuffer semantics.** `get_bytes`, `set_bytes`, `__getitem__`,
  `__setitem__`, `__len__`, `get_address`, `get_chunks` behave as
  `utils.NestedBuffer` (`utils.py:40-114`) over the shared image, including the
  reversed `ReversedSignature` view (`crypto.py:386-409`).
- REQ-8: **Edit / rebuild.** `File.move_buffer` + `Directory.update_entry_fields`
  rewrite the directory record (address-mode preserving) and the Fletcher-32
  checksum (`file.py:385-393`, `directory.py:195-241`);
  `HeaderFile.update_sha256` rewrites the header checksum
  (`header_file.py:119-121`); `PSPTool.to_file` / `to_stdout` emit the image
  (`psptool.py:59-64`). Unmutated `to_file` output equals the input bytes.
- REQ-9: **Certificate tree and re-signing.** `psp.cert_tree`,
  `file.signed_entity`, `SignedEntity.is_verified()` / `resign_only()` /
  `resign_and_replace()`, `PublicKeyEntity.replace_and_resign()`, and
  `crypto.PrivateKeyDict` (generate / PEM load / PEM save) mirror
  `cert_tree.py:28-406` and `crypto.py:104-175` so the `-R` replace + re-sign
  flow (`__main__.py:238-262`) runs on the bindings.
- REQ-10: **Listing.** `ls_json()` / `ls_dir_dict()` / `ls_files_dict()` emit
  the upstream dictionaries (`psptool.py:202-275`); `ls()` / `ls_files()` print
  tables (`psptool.py:66-200`).
- REQ-11: **Packaging.** maturin builds an abi3 wheel; `default.nix` exports a
  `python` attribute (buildPythonPackage + maturin hook) whose
  `pythonImportsCheck` is `psptool`, usable from a fetched checkout.

## Acceptance

- AC-1: Corpus parity (`tests/corpus_parity.rs`, gated on
  `PSPTOOL_TEST_CORPUS` + `PSPTOOL_REFERENCE`): for every corpus ROM, the
  bindings and the reference interpreter dump the same `(rom, dir, file)` walk —
  class, address, size, type, readable strings, md5, entropy, flags,
  `sha256(get_bytes())`, `sha256(get_decrypted_body())`,
  `sha256(get_decrypted_decompressed_body())`, `sha256(header + body)`, and the
  decode-verification verdict.
- AC-2: Unmutated `to_file` equals the input for every corpus ROM.
- AC-3: A replace + re-sign done through the bindings is accepted by the
  reference tool (its certificate tree verifies the re-signed entity).
- AC-4: Without the corpus, `tests/test_api.py` (synthetic image: parse,
  decode, NestedBuffer semantics, `move_buffer`, re-sign, PEM keys,
  `mock.patch` of `PSPTool.from_file`) passes under `cargo test`
  (`tests/python_api.rs`) and in the nix `python` check phase.

The oracle is `PSPTOOL_REFERENCE` from the dev shell: `default.nix` pins the
reference interpreter to vringar/PSPTool `241629b`, the translation source of
the decode-verified ladder (`header_file.py:191-276`), which upstream master
`edae097` lacks.

## Packaging

`default.nix` exports `python` (the package for `pkgs.python3Packages`) and
`pythonFor <pythonPackages>` for other interpreter versions. Both build from
the workspace fileset with `maturinBuildHook` and the pinned Rust toolchain;
`pythonImportsCheck` covers `psptool` and `psptool.header_file`. The `package`
(CLI) attribute excludes `psptool-py` from its sandboxed `cargo test`, whose
binaries would need libpython.

## Deviations

Documented in `crates/psptool-py/DEVIATIONS.md` (one line each, with the
reason). Where upstream raises during construction on malformed input
(`AssertionError`, `TypeError` on a `zen_generation` merge, unknown directory
magic) the bindings drop the offending node instead of aborting the whole
parse.
