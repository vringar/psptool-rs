# Byte-exact diff-and-patch writer (§8)

<!--
tier: 3-component
status: draft
baseline-commit: 3800d397f31ad85c1b3023f27659f9c06ecd06e0
upstream-paths:
  - /tmp/psptool-ref/psptool/utils.py
  - /tmp/psptool-ref/psptool/blob.py
-->

## Summary

`crates/psptool-core/src/writer.rs` is the write side of the roundtrip contract:
it renders a mutated ROM image by *splicing* caller-supplied byte patches into
the original blob, never by re-encoding parsed structures. It exposes
[`BlobEditor`] — a diff-and-patch editor holding the source [`SourceBytes`] plus
an ordered, non-overlapping `BTreeMap<offset, replacement>` — with
[`BlobEditor::patch`] / [`BlobEditor::serialize`] as the primitive, and the
[`BlobEditor::patch_source`] / [`EntryEditor::set_body`] equal-length
convenience layer on top.

There is no diff-and-patch writer *in* upstream to mirror method-for-method.
Upstream mutates one shared `bytearray` in place through `NestedBuffer` views
(`utils.py:40`): `NestedBuffer.__setitem__` (`utils.py:62-68`) writes bytes back
into `parent_buffer` at an absolute offset, `NestedBuffer.set_bytes`
(`utils.py:109-111`) asserts a length-preserving write, and the final image is
just that shared buffer written out. `BlobEditor` reproduces the *observable
contract* of that model — unedited bytes survive verbatim, edited bytes land at
their absolute offset — with an immutable-source / accumulated-patch design
(goal.md R-DEV-4: the Rust analog replaces `NestedBuffer`'s aliased-mutation
bookkeeping). It deliberately does **not** reproduce upstream's
`File.move_buffer` `0x10`-realignment on replace, which corrupts finer-aligned
neighbours (PSPReverse/PSPTool#77) — that is a goal.md R-DEV-6 deviation
(REQ-5).

The writer is intentionally dumb about semantics: it does not recompute
fletcher/sha digests, re-sign entries, or relayout siblings. Those are
higher-level `psptool-ops` operations (`replace.rs`, `sign.rs`) that *drive*
the editor by recording their own patches; the editor only guarantees the
substrate.

## Requirements

- REQ-1: **Byte-exact identity serialization.** An editor with no recorded
  patches must serialize to the *exact* source bytes it was constructed from —
  no normalization, no re-emit, no dropped padding/reserved/unparsed regions.
  This is the goal.md R-CODE-4 contract from the write side. Mirrors upstream's
  in-place model: an unmutated `NestedBuffer` tree is the original `bytearray`
  verbatim (`utils.py:54-60` / `utils.py:105-107` read straight from
  `parent_buffer`).
- REQ-2: **Absolute-offset patch primitive with localized splice.**
  `patch(offset, bytes)` records a replacement at an absolute flash offset;
  `serialize()` copies the source, then overwrites exactly `[offset, offset+len)`
  for each patch, leaving every other byte identical to the source. Mutation is
  local: the diff between input and output equals the union of patched ranges.
  Mirrors `NestedBuffer.__setitem__` (`utils.py:62-68`,
  `self.parent_buffer[new_slice] = value`) and the address translation in
  `_offset_slice` (`utils.py:74-94`).
- REQ-3: **Bounds + overlap validation returns typed errors, never panics.**
  A patch that extends past the blob window, starts before its root, or overlaps
  an already-recorded patch is rejected with a typed [`PatchError`]
  (`OutOfBounds` / `Overlap`), not a panic — the goal.md R-CODE-2 rule for
  untrusted mutation. Mirrors the upstream `NestedBuffer` bounds asserts
  (`utils.py:46-48` overflow-of-parent, `utils.py:78`/`utils.py:86` slice-bound
  asserts), promoted from Python `assert` to a recoverable `Result`.
- REQ-4: **Equal-length replacement API (`set_bytes` analog).** A
  length-preserving replace helper — [`BlobEditor::patch_source`] over a
  [`SourceBytes`] window and [`EntryEditor::set_body`] over a parsed [`Entry`] —
  that rejects a size change with [`PatchError::BodyLengthMismatch`]. Mirrors
  `NestedBuffer.set_bytes` (`utils.py:109-111`,
  `assert len(value) == size, "set_bytes: value length does not match size"`).
- REQ-5: **No `0x10`-realign / no blind re-emit (PR#77 deviation).** Replacing
  an entry's bytes must not round any offset/size to a `0x10` boundary and must
  not rebuild directories from typed fields; alignment, padding, and per-image
  quirks are inherited from the source bytes. This ships the *correct* behavior
  where upstream's `File.move_buffer` `0x10`-rounding is known-buggy
  (PSPReverse/PSPTool#77), a goal.md R-DEV-6 deviation. There is no upstream
  file:line to match here — the deviation is documented in the module
  doc-comment (`writer.rs:23-29`).

## Acceptance criteria

- AC-1 (REQ-1): a `BlobEditor::from_blob(SourceBytes::from_blob(bytes))` with
  zero patches has `is_clean() == true`, `patch_count() == 0`, and
  `serialize() == bytes`. Pinned by `unchanged_blob_serialises_byte_exact`
  (`writer.rs:286`) and `layered_rom_unchanged_serialise_roundtrip`
  (`writer.rs:518`); corpus-wide by `corpus_roundtrip` (54 passed, 0 failed,
  0 ignored — the whole supported corpus serializes byte-for-byte).
- AC-2 (REQ-2): a single patch changes exactly its range and nothing else
  (differing-byte count equals patch length); multiple disjoint patches apply
  independently in any insertion order and `serialize()` is order-independent;
  an empty replacement is a no-op. Pinned by
  `single_patch_changes_only_that_range` (`writer.rs:295`),
  `multiple_disjoint_patches_apply_independently` (`writer.rs:315`),
  `mutation_locality_at_each_layer` (`writer.rs:535`, FET→dir→record→body→header
  five-layer locality), `empty_patch_is_a_noop` (`writer.rs:341`),
  `patches_iterator_is_sorted_by_offset` (`writer.rs:402`).
- AC-3 (REQ-3): a past-the-end patch, a length-overflows-`u64` patch, a
  before-root patch on a rooted blob, and same-offset / head / tail overlaps all
  return the matching `PatchError` variant; adjacent (touching, non-overlapping)
  patches are accepted. Pinned by `out_of_bounds_patches_rejected`
  (`writer.rs:350`), `out_of_bounds_before_blob_root_rejected` (`writer.rs:365`),
  `overlapping_patches_rejected` (`writer.rs:380`).
- AC-4 (REQ-4): `patch_source` with a wrong-length replacement yields
  `BodyLengthMismatch { expected, got }` and records no patch; a correct-length
  replacement lands. `EntryEditor::set_body` behaves the same over a parsed
  entry body. Pinned by `patch_source_requires_length_match` (`writer.rs:418`),
  `entry_editor_set_body_replaces_only_body_bytes` (`writer.rs:646`),
  `entry_editor_set_body_rejects_length_mismatch` (`writer.rs:672`). **The
  BINARY REQ-status below still marks REQ-4 NOT-STARTED** — the API is exercised
  only by tests, with no non-test production consumer (blocker #64).
- AC-5 (REQ-5): the `psptool-ops` replace path rewrites the entry-record `size`
  field with the caller's *exact* byte count (no `0x10` rounding) and patches
  only the body slot; shrink leaves trailing bytes verbatim; grow is rejected
  rather than clobbering a neighbour. Pinned by the `psptool-ops` replace suite
  (`replace.rs` tests, 50 passed) and, corpus-wide, by `corpus_roundtrip`
  staying byte-exact. No `differential` op is assigned to this route.
- AC-6 (all SHIPPED REQs): `cargo test -p psptool-core --test corpus_roundtrip`
  is byte-exact with 0 failures / 0 ignored — the roundtrip suite IS the write
  contract's gauntlet (parity_ops "roundtrip"). This route declares no
  `differential` op.

## REQ status table

| REQ | Status | Evidence |
|---|---|---|
| REQ-1 (byte-exact identity) | SHIPPED | Impl `writer.rs:224` (`pub fn serialize`) starts from `self.original.as_bytes().to_vec()` (`writer.rs:225`) and only overwrites patched ranges; with no patches the output is the source verbatim, and `is_clean()` (`writer.rs:109`) reports it. Mirrors upstream's read-through-to-`parent_buffer` model (`utils.py:54-60`) where an unmutated tree equals the original `bytearray`. Non-test consumer: `psptool-cli/src/cmds/replace.rs:80` (`let final_bytes = editor.serialize();` on the no-mutation path) writes the ROM back out; `psptool-cli/src/cmds/sign.rs:25`. Verification: `cargo test -p psptool-core --test corpus_roundtrip` (54 passed, 0 failed, 0 ignored). |
| REQ-2 (offset patch + splice) | SHIPPED | Impl `writer.rs:131` (`pub fn patch`) inserts `offset → bytes` into the `BTreeMap`; `serialize` (`writer.rs:227-232`) computes `local = abs_off - base` and `out[local..local+len].copy_from_slice(bytes)`, leaving all other bytes identical — mirroring `NestedBuffer.__setitem__` (`utils.py:65` `self.parent_buffer[new_slice] = value`) and `_offset_slice` (`utils.py:74-94`). Non-test consumer: `psptool-ops/src/replace.rs:171` (`editor.patch(entry.body.offset(), new_body.to_vec())?`) and `psptool-ops/src/sign.rs:178` (`editor.patch(psptool_core::FlashOffset(sig_start), sig_disk)?`), both reached from the CLI `replace`/`sign` subcommands. Verification: `single_patch_changes_only_that_range` / `mutation_locality_at_each_layer` (in the 146-test core-lib pass) + `corpus_roundtrip` (54 passed). |
| REQ-3 (bounds/overlap → typed err) | SHIPPED | Impl `writer.rs:143-159` bounds-checks against `self.original.flash_range()` returning `PatchError::OutOfBounds`, and `writer.rs:162-183` rejects range- and predecessor-overlap with `PatchError::Overlap`; no `unwrap`/`panic` in the production path (R-CODE-2). Promotes the upstream Python `assert`s (`utils.py:46-48`/`utils.py:78`/`utils.py:86`) to a recoverable `Result`. Non-test consumer: `psptool-ops/src/replace.rs:84` plumbs `PatchError` via `#[from]` into `ReplaceError::Patch` and `replace.rs:171`/`:192` propagate it; `psptool-ops/src/sign.rs:72`/`:178` likewise. Verification: `out_of_bounds_patches_rejected` / `overlapping_patches_rejected` / `out_of_bounds_before_blob_root_rejected` (in the 146-test pass). |
| REQ-4 (equal-length replace API) | NOT-STARTED | Impl exists — `writer.rs:194` (`pub fn patch_source`) and `writer.rs:249` (`EntryEditor::set_body`) enforce `replacement.len() == target.len()` via `PatchError::BodyLengthMismatch` (`writer.rs:71`), mirroring `NestedBuffer.set_bytes` (`utils.py:110` `assert len(value) == size`) — but there is **no non-test production consumer**. The only callers are tests: `writer.rs` unit tests and `psptool-core/tests/corpus_roundtrip.rs:194-195` (`.entry(&entry).set_body(...)`, a test-side consumer that does not count per R-DEFER-1). The production replace path deliberately uses raw `BlobEditor::patch` with its own shrink-allowing length policy (`replace.rs:148` `BodyTooLarge` guard, `replace.rs:171` body patch, `replace.rs:192` exact-size rewrite) rather than the strict equal-length API. Open prerequisite blocker #64: wire the equal-length API into a production caller or retire it. |
| REQ-5 (no 0x10-realign / no re-emit — PR#77) | SHIPPED | The diff-and-patch model carries alignment/padding from the source bytes; nowhere does the writer round to `0x10` or rebuild a directory from typed fields (documented `writer.rs:23-29`, citing PSPReverse/PSPTool#77). The consuming replace path proves the deviation: `psptool-ops/src/replace.rs:180` (`rewrite_size_field`) writes `new_size_u32.to_le_bytes()` — the caller's *exact* count with no `File.ENTRY_ALIGNMENT` rounding — and `replace.rs:164-172` leaves the shrunk slot's trailing bytes verbatim. Non-test consumer: `psptool-cli/src/cmds/replace.rs:22-52` drives `replace_psp_entry_body`/`replace_bios_entry_body` then `editor.serialize()`. Verification: `corpus_roundtrip` (54 passed, 0 failed) proves no spurious realignment on the supported corpus; `mutation_locality_at_each_layer` proves byte-locality. |

## Architecture

**Immutable source + accumulated patches (the R-DEV-4 shape).** Upstream
`NestedBuffer` (`utils.py:40-115`) is a *view* over a mutable shared
`parent_buffer`; writing through any view aliases the one backing `bytearray`,
and the "save" is that buffer written to disk. `BlobEditor` (`writer.rs:80-86`)
inverts this: it holds an immutable [`SourceBytes`] clone plus a
`BTreeMap<u64, Bytes>` of patches, and materializes the mutated image only in
`serialize` (`writer.rs:224`). This eliminates the aliased-mutation bookkeeping
(and the ordering hazards it carries) while preserving the observable contract:
unedited bytes are the source verbatim (REQ-1), edited bytes land at their
absolute offset (REQ-2). The `BTreeMap` gives deterministic, order-independent
serialization and a cheap ascending `patches()` iterator (`writer.rs:120`).

**Absolute-offset addressing and rooted blobs.** Patches key on absolute flash
offset; `serialize` rebases to `local = abs_off - self.original.offset().get()`
(`writer.rs:226-230`). A blob rooted at a non-zero offset (a capsule envelope,
`rom_origin > 0`) therefore serializes to *only its window* — pinned by
`rooted_blob_serialises_to_window_only` (`writer.rs:698`). This mirrors the
upstream `NestedBuffer.get_address` chain (`utils.py:96-100`) that resolves a
view's absolute address before indexing `parent_buffer`. Bounds are validated
against `SourceBytes::flash_range` so an out-of-window patch (before root or
past end) is rejected up front (REQ-3), the same window invariant upstream's
`utils.py:46-48` asserts against the parent buffer.

**Overlap rejection is two-sided (critic watch-item).** `patch` checks both the
first existing patch whose start lies in `[start, end)` (`writer.rs:162`) *and*
the immediately-preceding patch whose tail crosses `start` (`writer.rs:173-183`).
Overlapping patches are rejected because the resulting bytes would depend on
application order — the editor's determinism guarantee (REQ-2) requires
disjointness. Adjacent (touching) patches are legal, pinned in
`overlapping_patches_rejected` (`writer.rs:396-399`). Empty replacements are a
no-op and never stored (`writer.rs:138-140`), so `is_clean()` stays accurate.

**Two mutation layers (REQ-2 primitive vs REQ-4 convenience).** The primitive
is `patch(offset, bytes)` — arbitrary offset, arbitrary length within the
window. On top sit two equal-length helpers: `patch_source` (`writer.rs:194`),
which enforces `replacement.len() == target.len()` for a [`SourceBytes`]
window, and the `EntryEditor` returned by `BlobEditor::entry` (`writer.rs:212`)
whose `set_body` (`writer.rs:249`) does the same against a parsed [`Entry`]'s
`body`. These mirror `NestedBuffer.set_bytes`'s length assert
(`utils.py:110`). **The production `psptool-ops` replace path does not use
them**: `replace.rs::apply` (`replace.rs:142`) allows a *shrink* (new body
shorter than the slot) — which the strict equal-length helpers forbid — so it
calls `rewrite_size_field` + raw `patch` directly. That is why REQ-4 is
NOT-STARTED (blocker #64) while REQ-2 is SHIPPED: the primitive has production
consumers; the equal-length convenience layer has only test consumers.

**Semantic dumbness is deliberate (context for REQ-5).** The writer never
recomputes fletcher (`directory.rs` does not verify it either), never re-signs
(`psptool-ops/src/sign.rs` records its own signature patch and calls
`editor.patch`), and never shifts siblings on a length change. The
size-field rewrite that a shrink requires lives in the *consumer*
(`replace.rs:180`), not the writer, so the writer has exactly one job: splice
bytes. This is the concrete mechanism by which the PR#77 bug class is avoided —
there is no code path that could round an offset to `0x10` because the writer
never computes offsets from fields at all; it only echoes the caller's absolute
coordinates.

**PR#77 deviation, verified (REQ-5, goal.md R-DEV-6).** Upstream's
`File.move_buffer` rounds a replaced entry's new size up to
`File.ENTRY_ALIGNMENT` (`0x10`), which PSPReverse/PSPTool#77 shows silently
corrupts neighbours when the real layout was finer than `0x10`. The Rust
consumer writes the exact size (`replace.rs:185`
`u32::try_from(new_size)` → `replace.rs:192` `to_le_bytes()`) and the writer
splices only the caller's bytes, so no realignment can occur. Confirmed by
`corpus_roundtrip` remaining byte-exact (a realign would perturb padding and
fail the roundtrip) and by the `replace.rs` doc-comment (`replace.rs:20-28`).
This route declares no `differential` op, so there is no reference-tool
"equivalent divergence" entry to reconcile — the deviation is a strictly-more-
correct write path, not an observable structural difference in `list`/`ls_json`.

## Version-skew note (blocker #61)

The differential oracle is PSPTool 3.4 while the translation source
`/tmp/psptool-ref` is git HEAD. The upstream surface this module mirrors — the
`NestedBuffer` write primitives (`utils.py:62-68` `__setitem__`,
`utils.py:109-111` `set_bytes`) and the shared-buffer save model (`blob.py`) —
is long-standing and version-stable; nothing read this iteration shows a
HEAD-only write behavior that the 3.4 oracle would disagree with. This route
carries only `parity_ops = ["roundtrip"]`, which is a self-oracle
(byte-in == byte-out) and independent of the reference-tool version entirely, so
no SHIPPED row above depends on a HEAD-vs-3.4 value. The one HEAD-side upstream
detail worth flagging is that the write path we *deliberately do not* mirror —
`File.move_buffer`'s `0x10`-realign (PR#77) — may differ in exact form between
3.4 and HEAD; REQ-5 sidesteps that whole class regardless of which upstream
version is the reference.

## Verification

The list below IS the gauntlet for this module; every SHIPPED row is backed by
one of these returning green, run inside `nix-shell -A shell` so
`PSPTOOL_REFERENCE` + `PSPTOOL_TEST_CORPUS` are set (a skipped suite is a red
gate, not a pass).

- `cargo test -p psptool-core --lib` — 146 passed, 0 failed, 0 ignored. The 14
  `writer::tests::*` cover REQ-1 (`unchanged_blob_serialises_byte_exact`,
  `layered_rom_unchanged_serialise_roundtrip`), REQ-2
  (`single_patch_changes_only_that_range`,
  `multiple_disjoint_patches_apply_independently`,
  `mutation_locality_at_each_layer`, `empty_patch_is_a_noop`,
  `patches_iterator_is_sorted_by_offset`, `rooted_blob_serialises_to_window_only`),
  REQ-3 (`out_of_bounds_patches_rejected`,
  `out_of_bounds_before_blob_root_rejected`, `overlapping_patches_rejected`),
  and REQ-4's *impl* (`patch_source_requires_length_match`,
  `entry_editor_set_body_replaces_only_body_bytes`,
  `entry_editor_set_body_rejects_length_mismatch` — test-only; REQ-4 is
  NOT-STARTED for lack of a production consumer).
- `cargo test -p psptool-core --test corpus_roundtrip` — 54 passed, 0 failed,
  0 ignored (parity_ops "roundtrip"). This is the write contract's primary
  gauntlet: every supported ROM parses and serializes back byte-for-byte,
  establishing REQ-1/REQ-2/REQ-5 corpus-wide.
- `cargo test -p psptool-ops` — 50 + 54 + 9 passed, 0 failed, 0 ignored. The
  `replace.rs` and `sign.rs` suites exercise the production consumers cited in
  the REQ table (`editor.patch`, `editor.serialize`, `editor.original`,
  `rewrite_size_field`'s no-realign write for REQ-5).
- This route declares no `differential` op (`tooling/translate-routes.toml`
  writer.rs `parity_ops = ["roundtrip"]`); the byte-exact roundtrip is the
  complete oracle for the write side.
- Open prerequisite blocker: #64 (REQ-4 — the equal-length replacement API
  `patch_source`/`set_body` has no non-test production consumer; the ops replace
  path uses raw `patch` with a shrink-allowing policy instead).
