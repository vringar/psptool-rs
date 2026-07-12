# Entry-body replacement / mutation path (`--replace-file`)

<!--
tier: 3-component
status: draft
baseline-commit: e5071d7226f3d5acc0be648af8d7829f6cf63b71
upstream-paths:
  - /tmp/psptool-ref/psptool/__main__.py
  - /tmp/psptool-ref/psptool/file.py
  - /tmp/psptool-ref/psptool/directory.py
  - /tmp/psptool-ref/psptool/entry.py
-->

## Summary

`crates/psptool-ops/src/replace.rs` is the entry-body mutation path — the Rust
port of the reference `--replace-file` command (`__main__.py:238-248`). It
drives the byte-exact [`BlobEditor`] (`.design/psptool-core/writer.md`) to
overwrite one entry's body slot and, on a length change, rewrite that entry's
directory-record `size` field. It ships the *correct* size-rewrite where
upstream's `File.move_buffer` rounds up to `0x10` (`file.py:389`), a known bug
class (PSPReverse/PSPTool#77, goal.md R-DEV-6). On a length change it also
recomputes the parent directory's Fletcher-32 checksum that upstream rewrites
unconditionally on every replace (`directory.py:241`), so a strict
Fletcher-verifying reader accepts the output (closed blocker #66).

## Requirements

- REQ-1: **Body-slot locality.** Replacing an entry's body patches *only* the
  body byte range; sibling entries, directory records, padding, and every other
  structural byte serialize byte-identical to the source. Mirrors the observable
  effect of upstream `file.set_bytes(0, len, sub_binary)` (`__main__.py:248`),
  which writes through the entry's `NestedBuffer` view without touching
  neighbours.
- REQ-2: **Exact-size record rewrite, no `0x10` realign (PR#77 deviation).** A
  length-changing replace rewrites the 4-byte little-endian `size` field at
  record `+0x04` with the caller's *exact* body length — never rounded up to a
  `0x10` boundary. Mirrors the entry `size` setter (`entry.py:108-110`
  `set_bytes(4, 4, struct.pack('<I', value))`) but deviates from
  `File.move_buffer` (`file.py:389` `int(ceil(size / self.ENTRY_ALIGNMENT)) *
  self.ENTRY_ALIGNMENT`), which PSPReverse/PSPTool#77 shows corrupts
  finer-aligned neighbours (goal.md R-DEV-6).
- REQ-3: **Shrink leaves the tail verbatim.** When the new body is shorter than
  the original slot, the trailing `original_len - new_len` bytes of the slot are
  left exactly as in the source (no zero-fill, no truncation). The bytes become
  unreferenced (`size` shrank) but are not touched — the R-CODE-4 no-blind-re-emit
  contract from the mutation side.
- REQ-4: **Growth is rejected, not silently relaid-out.** A body strictly larger
  than the original slot returns a typed [`ReplaceError::BodyTooLarge`] and
  records no patches, rather than clobbering the next entry. This is a deliberate
  scope limit vs upstream `File.move_buffer` (`file.py:385-389`), which relocates
  the buffer to grow; re-layout is out of scope for #12.
- REQ-5: **Soft-fuse-chain entries are rejected.** A type-`0x0B` entry
  (`File.NO_SIZE_ENTRY_TYPES`, `directory.py:219`) encodes its payload in the
  directory record itself and has no separate body slot; replace returns a typed
  [`ReplaceError::SoftFuseChainEntry`] instead of overwriting the record.
- REQ-6: **PSP- and BIOS-family entry points over the shared `apply`.**
  `replace_psp_entry_body` / `replace_bios_entry_body` re-parse the entry from
  the editor's source blob and drive the shared `apply`; the `size` field lives
  at record `+0x04` for both the 16-byte PSP record and the 24-byte BIOS record.
  Mirrors the family-agnostic upstream flow (`__main__.py:240` resolves
  `directories[...].files[...]` regardless of family).
- REQ-7: **Length-changing replace recomputes the parent directory Fletcher-32
  checksum.** Because the rewritten `size` field lands inside the directory's
  checksummed region (`self[0x8:]`, `directory.py:204`), upstream recomputes a
  fresh Fletcher-32 into the header checksum field on every replace
  (`directory.py:241` `self.update_checksum()` → `directory.py:203-205`
  `self.checksum.set_bytes(0, 4, fletcher32(data))`). Our replace path must do
  the same so a strict Fletcher-verifying reader (the AMD PSP bootrom) accepts
  the output.

## Acceptance criteria

- AC-1 (REQ-1): across `vendor/test-corpus`, an equal-length replace of the
  first non-soft-fuse entry differs from the source ROM only inside that entry's
  body range; every other byte is identical. Pinned corpus-wide by
  `corpus_replace` (54 passed, 0 failed, 0 ignored) and by the unit tests
  `equal_length_replacement_locality` (`replace.rs:280`) and
  `equal_length_replacement_does_not_touch_record_size_field` (`replace.rs:313`,
  asserts `patch_count() == 1`).
- AC-2 (REQ-2): shrinking a `0x40` body to a non-aligned `0x33` writes exactly
  `0x33` into the record `size` field (not `0x40`, not a `0x10`-rounded value).
  Pinned by `shrinking_rewrites_size_field_to_exact_length` (`replace.rs:347`)
  and, for the 24-byte BIOS record, `bios_replace_works_and_size_field_at_same_offset`
  (`replace.rs:531`).
- AC-3 (REQ-3): after a `0x40`→`0x33` shrink the trailing `0xD` bytes of the
  slot equal the source; the record bytes other than `size` are unchanged.
  Pinned by assertions (3) and (4) of `shrinking_rewrites_size_field_to_exact_length`
  (`replace.rs:387-405`).
- AC-4 (REQ-4): a `0x10`-slot entry replaced with `0x11` bytes yields
  `BodyTooLarge { available: 0x10, requested: 0x11 }` and `editor.is_clean()`.
  Pinned by `rejects_growth_with_typed_error` (`replace.rs:411`).
- AC-5 (REQ-5): a type-`0x0B` entry yields `SoftFuseChainEntry` with no
  recorded patches. Pinned by `rejects_soft_fuse_chain_entry` (`replace.rs:438`).
- AC-6 (REQ-6): the entry-handle path (`replace_entry_body`) and both family
  entry points produce identical locality; BIOS records honour the same `+0x04`
  size offset. Pinned by `replace_via_entry_handle_preserves_everything_else`
  (`replace.rs:571`) and `bios_replace_works_and_size_field_at_same_offset`
  (`replace.rs:531`).
- AC-7 (REQ-7): after a length-changing replace, the stored directory checksum
  at `[0x04..0x08]` equals `fletcher32` over the post-replace region
  `[0x08 .. header+entry-table]`. Pinned GREEN by the divergence test
  `length_changing_replace_recomputes_directory_checksum`
  (`tests/divergence_fletcher.rs`, now a plain `#[test]` — blocker #66 closed).
  The control `equal_length_replace_keeps_directory_checksum_valid` passes too,
  isolating the changed `size` field as the recompute trigger.

## REQ status table

| REQ | Status | Evidence |
|---|---|---|
| REQ-1 (body-slot locality) | SHIPPED | Impl `replace.rs:170-172` (`editor.patch(entry.body.offset(), new_body.to_vec())?`) writes only the body slot through the diff-and-patch writer; the equal-length path records exactly one patch (`replace.rs:333` asserts `patch_count() == 1`). Mirrors upstream `file.set_bytes(0, len(sub_binary), sub_binary)` (`__main__.py:248`). Non-test consumer: `psptool-cli/src/cmds/replace.rs:28` (`replace_psp_entry_body`) / `:36` (`replace_bios_entry_body`), then `:78` `editor.serialize()` → `:79` `fs::write`. Verification: `corpus_replace` (54 passed, 0 failed, 0 ignored) + `equal_length_replacement_locality`. |
| REQ-2 (exact-size rewrite, no 0x10 realign) | SHIPPED | Impl `rewrite_size_field` `replace.rs:180-193` writes `new_size_u32.to_le_bytes()` (`replace.rs:192`) at record `+0x04` (`ENTRY_RECORD_SIZE_OFFSET`, `replace.rs:50`) — the caller's exact count. Mirrors upstream size setter `entry.py:108-110` (`self.set_bytes(4, 4, struct.pack('<I', value))`) but deviates (R-DEV-6) from `file.py:389` (`int(ceil(size / self.ENTRY_ALIGNMENT)) * self.ENTRY_ALIGNMENT`) per PSPReverse/PSPTool#77. Non-test consumer: `psptool-cli/src/cmds/replace.rs:28`/`:36`. Verification: `shrinking_rewrites_size_field_to_exact_length` (`replace.rs:347`, asserts `0x33` not `0x40`/rounded). |
| REQ-3 (shrink tail verbatim) | SHIPPED | Impl `replace.rs:164-172` patches only `new_body.len()` bytes and never touches the trailing slot bytes (documented `replace.rs:164-169`: "we deliberately do not zero them"). Non-test consumer: `psptool-cli/src/cmds/replace.rs:28`/`:36`. Verification: `shrinking_rewrites_size_field_to_exact_length` assertion (3) (`replace.rs:387-390`, trailing `0xD` bytes equal source). |
| REQ-4 (growth rejected) | SHIPPED | Impl `replace.rs:148-153` returns `ReplaceError::BodyTooLarge { available, requested }` when `new_body.len() > original_len`; validation runs before any patch so `editor.is_clean()` holds. Deliberate scope limit vs upstream `File.move_buffer` relocation (`file.py:385-389`). Non-test consumer: `psptool-cli/src/cmds/replace.rs:35`/`:43` propagate via `?`. Verification: `rejects_growth_with_typed_error` (`replace.rs:411`). |
| REQ-5 (soft-fuse-chain rejected) | SHIPPED | Impl `replace.rs:143-145` returns `ReplaceError::SoftFuseChainEntry` for `EntryClass::SoftFuseChain`. Mirrors upstream `File.NO_SIZE_ENTRY_TYPES` guard (`directory.py:219` `if entry.type not in File.NO_SIZE_ENTRY_TYPES`). Non-test consumer: `psptool-cli/src/cmds/replace.rs:28`/`:36` propagate via `?`. Verification: `rejects_soft_fuse_chain_entry` (`replace.rs:438`). |
| REQ-6 (PSP/BIOS family entry points) | SHIPPED | Impl `replace_psp_entry_body` `replace.rs:96` and `replace_bios_entry_body` `replace.rs:111` re-parse the entry from `editor.original()` and call the shared `apply` (`replace.rs:142`); both families put `size` at `+0x04` (`replace.rs:48-50`). Mirrors the family-agnostic upstream resolution `psp.blob.roms[...].directories[...].files[...]` (`__main__.py:240`). Non-test consumer: `psptool-cli/src/cmds/replace.rs:28`/`:36` (matched on `Directory::Psp`/`Directory::Bios`). Verification: `bios_replace_works_and_size_field_at_same_offset` (`replace.rs:531`), `replace_via_entry_handle_preserves_everything_else` (`replace.rs:571`). |
| REQ-7 (directory Fletcher-32 recompute) | SHIPPED | Impl `recompute_directory_checksum` in `replace.rs` reconstructs the post-replace checksummed region (`dir_source[0x08 ..]` with the new 4-byte `size` spliced in — the sole in-region change) and patches `fletcher32(region)` at directory `+0x04`, gated on a length change and only when the parent-directory handle is present (`apply`'s `dir_source: Option<&SourceBytes>`; `Some(&parent.source)` from the two family entry points, `None` from the entry-only `replace_entry_body`). Mirrors upstream `Directory.update_checksum` (`directory.py:203-205` `data = self[0x8:]; self.checksum.set_bytes(0, 4, fletcher32(data))`), called unconditionally on every replace (`directory.py:241`); the in-region `size` mutation is `entry.py:109-110`. This is `psptool_core::fletcher32`'s first production consumer (closes linkage to #43). Non-test consumer: `psptool-cli/src/cmds/replace.rs` (`replace_psp_entry_body`/`replace_bios_entry_body`, signatures unchanged). Verification: `length_changing_replace_recomputes_directory_checksum` GREEN + control `equal_length_replace_keeps_directory_checksum_valid` GREEN (`divergence_fletcher` 2 passed, 0 ignored); `corpus_replace` 54 passed. Blocker #66 closed. |

## Architecture

**Diff-and-patch, driven from the consumer.** `replace.rs` owns no byte buffer;
it records patches into a [`BlobEditor`] (`.design/psptool-core/writer.md`).
The primitive it calls is `BlobEditor::patch` (`replace.rs:171`, `replace.rs:192`);
materialisation is the caller's later `editor.serialize()`
(`psptool-cli/src/cmds/replace.rs:78`). This is the mechanism by which the PR#77
bug class is structurally impossible here: the writer only echoes the caller's
absolute coordinates, and `apply` supplies the exact body offset
(`entry.body.offset()`) and exact size (`new_body.len()`), so there is no code
path that could round an offset or length to `0x10`.

**Three public entry points, one `apply` core.** `replace_psp_entry_body`
(`replace.rs:96`) and `replace_bios_entry_body` (`replace.rs:111`) re-parse the
entry via `Entry::parse_psp` / `Entry::parse_bios` against `editor.original()`,
so the patch coordinates are guaranteed to exist in the editor's source bytes;
`replace_entry_body` (`replace.rs:134`) takes an already-parsed [`Entry`] for
callers iterating `walk_directories`. All three funnel into `apply`
(`replace.rs:142`), which enforces the invariant order: soft-fuse guard
(`:143-145`) → growth guard (`:148-153`) → conditional `rewrite_size_field`
(`:160-162`, only on a length change) → body patch (`:170-172`). Equal-length
replaces skip `rewrite_size_field`, leaving the record — and therefore any valid
source checksum — byte-identical (this is exactly why the REQ-7 control test
passes while the pin fails).

**The `size`-field offset is a shared constant.** `ENTRY_RECORD_SIZE_OFFSET =
0x04` / `ENTRY_RECORD_SIZE_LEN = 4` (`replace.rs:48-52`) hold for both the
16-byte PSP directory record and the 24-byte BIOS record; `rewrite_size_field`
derives the absolute offset from `entry.record.source().offset() + 0x04`
(`replace.rs:186-190`), matching the upstream layout where `entry.size` reads
`self[4:8]` (`entry.py:105-106`) for every entry family.

**Typed error surface.** `ReplaceError` (`replace.rs:55-85`) enumerates the four
failure modes — `Parse` (`#[from] ParseError`), `BodyTooLarge`,
`SoftFuseChainEntry`, and `Patch` (`#[from] PatchError`, plumbed from the
writer's bounds/overlap rejection). No `unwrap`/`expect`/`panic` on the
production path (R-CODE-2); the two `expect`s in `rewrite_size_field`
(`replace.rs:185`, `:189`) are dominated by the growth guard (`new_size <=
original entry.size`, a wire `u32`) and the record-length invariant, and are
documented as such.

**The REQ-7 checksum recompute.** The `size` field the replace rewrites lands
inside the checksummed region — for a 1-entry `$PSP` directory that region is
`[0x08 .. header + entry-table]` (`divergence_fletcher.rs`
`CKSUM_REGION = 0x08..(DIRECTORY_HEADER_SIZE + PSP_ENTRY_SIZE)`), and upstream
writes a fresh Fletcher-32 into the header checksum field at `[0x04..0x08]`
(`self.checksum`, `directory.py:135`). `apply` threads the parent directory's
source in as `dir_source: Option<&SourceBytes>` and, after the size/body patches
on a length change, `recompute_directory_checksum` patches
`fletcher32(post-replace region)` at `dir_base + 0x04` using the fallible
`psptool_core::fletcher32` (`crates/psptool-core/src/fletcher.rs`, the same
primitive the pin's oracle uses). The region is rebuilt from the source directory
bytes with only the 4-byte `size` field spliced to its new value, so the sole
observable delta versus source is the `size` field and the recomputed checksum.
The entry-only `replace_entry_body` structurally lacks the parent directory and
passes `None`, remaining checksum-agnostic (a shrink through that path leaves the
checksum stale by design — the caller opted out of directory context).

## Version-skew note (blocker #61)

The differential oracle is PSPTool 3.4 while the translation source
`/tmp/psptool-ref` is git HEAD. The upstream write surface this module mirrors —
`File.move_buffer` (`file.py:385-393`), the entry `size` setter
(`entry.py:108-110`), and `Directory.update_entry_fields` / `update_checksum`
(`directory.py:207-241`) — is the HEAD form. This route's assigned parity is the
`corpus_replace` mutation-locality gauntlet, a *self-oracle* (byte-in vs
byte-out inside a known range) that is independent of the reference-tool version.
No SHIPPED row above depends on a HEAD-vs-3.4 value: the exact-size rewrite
(REQ-2) is a strictly-more-correct deviation from *both* versions' `ceil`
rounding, and the growth/soft-fuse rejections (REQ-4/REQ-5) are typed scope
limits, not observable-output claims. REQ-7's checksum recompute is likewise
version-safe — `update_checksum` is long-standing and stable across 3.4/HEAD, so
#66's fix does not risk a skew mismatch. A full `differential` replace-vs-Python
comparison is still deliberately not asserted here: it would now agree on the
directory checksum but diverge on the intentional PR#77 exact-size deviation
(REQ-2), where upstream rounds the `size` up to `0x10` and we do not.

## Verification

The list below IS the gauntlet for this module; run inside `nix-shell` so
`PSPTOOL_REFERENCE` + `PSPTOOL_TEST_CORPUS` are set (a skipped suite is a red
gate, not a pass).

- `cargo test -p psptool-ops --lib` — 50 passed, 0 failed, 0 ignored. The
  `replace::tests::*` cover REQ-1 (`equal_length_replacement_locality`,
  `equal_length_replacement_does_not_touch_record_size_field`), REQ-2/REQ-3
  (`shrinking_rewrites_size_field_to_exact_length`,
  `empty_replacement_still_rewrites_size_to_zero`), REQ-4
  (`rejects_growth_with_typed_error`), REQ-5 (`rejects_soft_fuse_chain_entry`),
  and REQ-6 (`bios_replace_works_and_size_field_at_same_offset`,
  `replace_via_entry_handle_preserves_everything_else`).
- `cargo test -p psptool-ops --test corpus_replace` — 54 passed, 0 failed,
  0 ignored (the mutation-locality companion to `corpus_roundtrip`; every corpus
  ROM's first non-soft-fuse entry is replaced same-length and the output differs
  only inside that body range). This is the SHIPPED-REQ corpus-wide gauntlet.
- `cargo test -p psptool-ops --test divergence_fletcher` — 2 passed, 0 failed,
  0 ignored. The former REQ-7 pin
  (`length_changing_replace_recomputes_directory_checksum`) is now a plain
  `#[test]` and GREEN (blocker #66 closed); the control
  (`equal_length_replace_keeps_directory_checksum_valid`) stays GREEN, proving
  the recompute triggers only on a length change.
- `cargo test -p psptool-core --test corpus_roundtrip` — 54 passed, 0 failed,
  0 ignored: establishes that the underlying [`BlobEditor`] the replace path
  drives is byte-exact on the supported corpus.
- `cargo test -p psptool-cli --test differential` — 50 passed, 0 failed,
  4 ignored: exercises the CLI `list`/`ls_json` surface, not replace mutation
  (a differential replace-vs-Python comparison is not asserted — see the
  version-skew note; it would fail today for the #66 reason).
- Blocker **#66** closed (REQ-7 — length-changing replace now recomputes the
  parent directory Fletcher-32 checksum, mirroring `directory.py:241`). This
  wires `psptool_core::fletcher32`'s first production consumer (#43 closed).
