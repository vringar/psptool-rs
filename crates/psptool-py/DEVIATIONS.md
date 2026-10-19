# `psptool` bindings: deviations from PSPTool (Python)

The bindings mirror PSPTool's Python API as of vringar/PSPTool `241629b`
(master `edae097` plus the decode-verified signal). Same import name
(`psptool`), same classes, methods and attributes, same object graph and
`(rom, directory, file)` order. Verified on the 54-ROM corpus by
`tests/corpus_parity.rs` (walk, hashes, decode verdicts, edit + re-sign
accepted by the reference), for ROM-less Python subclasses by
`tests/oracle_subclass.py` (identical output under the reference), and by
the reference tool's own integration suite (9 of 10 pass; the exception is
item 13).

Everything else differs only as listed here.

## Buffer model

1. **The image is a copy.** `PSPTool(rom_bytes)` copies `rom_bytes`;
   upstream aliases a passed `bytearray`. Root views' `parent_buffer` /
   `blob.get_buffer()` return a `bytearray` copy of the current image. Edits
   made through the API are visible through every view and in `to_file`, but
   not in the caller's original buffer. *Why:* one Rust-owned buffer shared by
   all views; aliasing a Python `bytearray` would need `unsafe` reads.
2. **Fixed image length.** A slice assignment whose value has a different
   length raises `ValueError`; upstream's `bytearray` silently resizes,
   shifting every later byte.
3. **Decode methods read the live header.** `get_decrypted_body()`,
   `get_decrypted_decompressed_body()` and `decode_verification()` take
   `encrypted` / `compressed` / `zlib_size` / key / IV from the header bytes
   at the file's current window, not from the attributes snapshotted at
   parse time. Identical unless the header bytes are edited.
4. **`get_chunks()` returns a list** (upstream: a generator).

## Malformed input

5. **No aborts on malformed firmware.** Where upstream's constructor raises
   (`AssertionError` from an out-of-bounds `NestedBuffer`, `TypeError` when a
   combo generation is merged into a directory without one,
   `UnknownPubkeyFileVersion` / key-store assertions, an unknown directory
   magic), the bindings drop that directory or file and continue. No corpus
   ROM triggers any of these in either tool.
6. **`decode_verification()` is total.** A body that cannot be decrypted or
   sliced at all reports `(False, 'decode-error')`; upstream lets the
   exception escape `_verify_decode`.
7. **Short microcode bodies** read `date` / `patch_level` as 0 (upstream:
   `struct.error`).

## Edit path

8. **`File.move_buffer` keeps the exact size.** Upstream rounds the new size
   up to `ENTRY_ALIGNMENT` (0x10), the PR #77 class of bug; this matches
   psptool-rs `replace` (`.design/psptool-ops/replace.md` REQ-2).
9. **`Directory.update_entry_fields` writes the exact inverse of
   `file_offset()`** for x86-physical pointers: a `> 0xFF000000` pointer in a
   > 16 MiB ROM keeps its top byte. Upstream masks with `addr_mask` and
   clears bit 24, which re-reads to the same address but changes the bytes.

## Determinism and reporting

10. **Dual-ROM AGESA order.** With two distinct AGESA strings upstream picks
    `agesa_version` / `agesa_version_second` in `set` iteration order (hash
    seed dependent); the bindings use first-seen order.
11. **Quiet construction.** Parsing prints no warnings (upstream prints parse
    and checksum warnings to stderr). Explicit checks (`verify_sha256`,
    `verify_sha384`, `Directory.verify_checksum`, a failed decompression) still
    print upstream's `Warning: ...` lines. `verbose=` is accepted and ignored.
12. **Decode-verification keys** come from psptool-core's image-wide key map
    (every `PubkeyFile` and `$KDB` key of every ROM) instead of
    `psp.cert_tree`. The verdict of every corpus `HeaderFile` equals
    upstream's.

## Not provided

13. **Internal helper seams.** zlib, AES and RSA run in Rust, so module-level
    helpers such as `psptool.header_file.zlib_decompress` do not exist and
    cannot be `mock.patch`ed (upstream test
    `test_failed_decompression_is_not_verified` relies on that).
14. **Inline public keys.** The scan of file bodies for embedded public keys
    (`blob.py:133-181`, run by `CertificateTree.from_blob`) is not ported:
    `inline_keys` is always empty and `Blob.find_inline_pubkey_entries` /
    `InlinePubkeyFile` do not exist. The corpus contains none.
15. **Diagnostics and helpers:** `PSPTool.ph` / `print_metrics`,
    `Blob.range_dict` / `_find_fets`, `CertificateTree.print_key_tree`,
    `HeaderFile.get_ikek_md5sum` (broken upstream: `rom` has no
    `get_files_by_type`), `fet.EmptyFet`, the class-level type tables
    (`File.DIRECTORY_ENTRY_TYPES`, ...), the `psptool.utils` helper functions
    (`zlib_decompress`, `decrypt`, `fletcher32`, `RangeDict`, `PrintHelper`,
    ...), and `python -m psptool` (the CLI is the Rust `psptool` binary).
16. **Construction from Python** is supported for `PSPTool`, `NestedBuffer`,
    `KeyId`, `Signature`, `ReversedSignature`, `PrivateKeyDict`,
    `CertificateTree`, `SignedEntity` and `PublicKeyEntity`; the parsed object
    classes (`Blob`, `Rom`, `Fet`, `Directory`, `DirectoryEntry`, `File`,
    `HeaderFile`, `KeyStore*`, `PubkeyFile`, `MicrocodeFile` and their `Bios*`
    variants) only come from a parse, and calling one directly raises
    `TypeError`. A **Python subclass** of a parsed class can be instantiated
    with any arguments and an `__init__` of its own that assigns plain
    attributes (PSP-DB's ROM-less `FakeHeaderFile`). Its native base is an
    empty buffer without a parent (`buffer_size == 0`, `get_bytes() == b''`,
    `get_address() == 0`) where upstream has no `buffer_size` /
    `parent_buffer` attributes until assigned; every other attribute is
    exactly what the subclass sets, and a missing one raises
    `AttributeError` as upstream. On such an instance the `HeaderFile` decode
    methods (`get_decrypted_body`, `_decrypted_decompressed_body`,
    `get_decrypted_decompressed_body`, `get_checksummed_bytes`,
    `_verify_decode`, `decode_verification` / `decode_verified` /
    `decode_verification_method`, `plaintext_identity_ok`, `is_signed`) run
    upstream's call structure through attribute lookup, so the subclass's
    overrides and attributes feed the ladder (warnings still go to stderr,
    item 11). Parsed objects keep the core path: replacing a method on a
    parsed *instance* (`f.get_decrypted_body = ...`) is not seen by its
    ladder. `cls(...)` on a Python subclass of `PSPTool` returns a `PSPTool`;
    the certificate-tree and crypto classes cannot be subclassed.

## Small API differences

17. `PublicKey` / `PrivateKey` (upstream ABCs) are aliases of the RSA
    classes; public keys compare by value.
18. `PrivateKeyDict()` starts from a fresh dict (upstream's default argument
    is one dict shared by every instance).
19. `ls_files_dict(files=None)` lists the sorted unique files (upstream raises
    `AttributeError` on `self.rom`).
20. `psptool.__version__` is the psptool-rs version; the distribution is
    named `psptool`.
