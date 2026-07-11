# Directory header, entry-table, and combo/L2 traversal (§2)

<!--
tier: 3-component
status: draft
baseline-commit: 272bd328551911636f4599a28c2f7a74a934a4a3
upstream-paths:
  - /tmp/psptool-ref/psptool/directory.py
-->

## Summary

`crates/psptool-core/src/directory.rs` parses the 16-byte directory header
shared by the `$PSP`/`$PL2`, `$BHD`/`$BL2`, and `2PSP`/`2BHD` families, slices
the per-family entry table (16-byte PSP records, 24-byte BIOS records, 16-byte
combo records after a reserved block), and walks the directory graph from the
FET through combo dispatch and L2 sub-directory pointers. It mirrors upstream
`psptool/directory.py` — the `Directory` / `BiosDirectory` classes
(`directory.py:26`, `directory.py:252`), the header field reads
(`directory.py:128-135`), the `address_mode` property (`directory.py:186-193`),
the fletcher checksum region (`directory.py:195-205`), the `ZEN_GENERATION_IDS`
table (`directory.py:34-39`), and the recursive directory discovery in
`create_directories_if_not_exist` (`directory.py:57-101`). The byte-level entry
*field* decode (`PspEntry`/`BiosEntry`) and its address-mode *application* are
scoped by the sibling doc `.design/psptool-core/entry.md`; this doc scopes the
header, the table slicing, and the traversal.

## Requirements

- REQ-1: **16-byte directory header parse.** Decode the four header fields —
  `magic` (4 bytes @0x00), `fletcher` (u32 @0x04), `count` (u32 @0x08),
  `additional_info` (u32 @0x0C) — as little-endian values, and retain a
  [`SourceBytes`] window over the 16 bytes so the byte-exact writer can patch a
  single entry without rebuilding the directory. The header layout is common to
  all three families. Mirrors `directory.py:28` (`HEADER_SIZE = 4 * 4`),
  `directory.py:128` (`self._count = int.from_bytes(...[+8:+12], 'little')`),
  `directory.py:129` (`self.magic = ...get_bytes(offset, 4)`), `directory.py:131`
  (`self.additional_info = ...get_bytes(offset + 12, 4)`), and `directory.py:135`
  (`self.checksum = NestedBuffer(self, 4, 4)` — the checksum field at +0x04).
- REQ-2: **Magic-family discrimination and dispatch.** Recognise the six
  directory magics and dispatch on family: `$PSP`/`$PL2` → PSP directory
  (16-byte entries), `$BHD`/`$BL2` → BIOS directory (24-byte entries),
  `2PSP`/`2BHD` → combo directory. Any other 4-byte tag is a non-directory and
  yields a typed `BadMagic` error the FET walker treats as "skip silently".
  Mirrors upstream's magic gate at `directory.py:111` (`if magic in
  cls.DIRECTORY_MAGICS`), `directory.py:113` (`elif magic in
  BiosDirectory.DIRECTORY_MAGICS`), and `directory.py:116-117` (unknown magic →
  `Directory.ParseError`), with `DIRECTORY_MAGICS = [b'$PSP', b'$PL2']`
  (`directory.py:27`) and `[b'$BHD', b'$BL2']` (`directory.py:253`).
- REQ-3: **Entry-count + entry-table slice.** Read `count` entries of the
  family-appropriate stride (`PSP_ENTRY_SIZE = 0x10`, `BIOS_ENTRY_SIZE = 0x18`,
  `COMBO_ENTRY_SIZE = 0x10`) immediately after the 16-byte header (after an
  additional 16-byte reserved block for combos), bounds-checking each record
  against the input blob and returning `Truncated` on overrun. Each entry
  record retains its own `SourceBytes` window. Mirrors `directory.py:133`
  (`self.body = NestedBuffer(self, self.ENTRY_SIZE * self.count, ...)`),
  `directory.py:144-147` (the entry loop over `range(0, len(self.body),
  entry_size)`), and the `ENTRY_SIZE` class attributes at `directory.py:31` /
  `directory.py:255`. Field decode of each record is delegated to the sibling
  `entry.md` (REQ-1/REQ-2).
- REQ-4: **`address_mode` extraction governs entry offset resolution.** Extract
  the 2-bit directory address mode from `additional_info`: bit 31 is the version
  flag; version 1 → bits `[25:24]`, version 0 ("v2") → bits `[30:29]`. This mode
  is what the entry resolver threads into offset arithmetic (modes `10`/`11`
  defer to the entry-level `rsv0[31:30]` override). Mirrors the `address_mode`
  property at `directory.py:186-193` (`version = (info >> 31) & 1`;
  `(info >> 24) & 3` if v1 else `(info >> 29) & 3`).
- REQ-5: **Fletcher checksum field parse.** Read the stored fletcher-32 dword
  from header bytes `[0x04..0x08]` into `DirectoryHeader::fletcher`. Mirrors
  `directory.py:135` (`self.checksum = NestedBuffer(self, 4, 4)`) and
  `directory.py:197` (`checksum = self.checksum.get_bytes()`). The checksum is
  computed over the body `self[0x8:]` (`directory.py:196`); the checksum
  *algorithm* is the sibling `fletcher.md`.
- REQ-6: **Fletcher checksum verify / recompute.** On parse, verify the stored
  checksum against `fletcher32(body[0x08..])` and warn on mismatch; on a mutated
  reserialization, recompute and write the new dword LE into header
  `[0x04..0x08]`. Mirrors `verify_checksum` (`directory.py:195-201`) and
  `update_checksum` (`directory.py:203-205`, `self.checksum.set_bytes(0, 4,
  fletcher32(data))`). No production code path does this today — see the REQ
  status table (blocker #43).
- REQ-7: **Combo directory: reserved-block preservation + `secondaryAddresses`
  traversal.** Parse the `2PSP`/`2BHD` combo as a 16-byte header, a 16-byte
  reserved block (preserved verbatim for byte-exact roundtrip, not asserted-zero
  and dropped), and `count` 16-byte combo entries (`entry_flags`,
  `psp_generation`, `pointer`, `reserved`), then follow each combo entry's
  `pointer` (the "secondary address") to its child directory. Combo dispatch
  mirrors the recursive discovery of secondary directories in
  `create_directories_if_not_exist` (`directory.py:80-83`) and the
  double-reference/generation read for Zen-4 combos (`directory.py:85-99`).
- REQ-8: **Zen-generation id mapping.** Map a combo entry's `psp_generation`
  id (matched on its high three bytes) to a Zen generation label. Mirrors
  `ZEN_GENERATION_IDS` (`directory.py:34-39`) and `get_possible_zen_generation`
  (`directory.py:41-48`).
- REQ-9: **FET → directory graph walk.** Starting from the FET slots, resolve
  each pointer, parse the directory it references, and recursively follow combo
  entries and L2 secondary-directory pointers (entry types `0x40`/`0x49`/`0x70`),
  deduplicating by absolute header offset and silently skipping any pointer that
  does not dereference to a known directory magic. Mirrors the recursive
  `create_directories_if_not_exist` (`directory.py:57-101`) driven by
  `directory.py:159-163` (`entry.type in SECONDARY_DIRECTORY_ENTRY_TYPES` →
  `secondary_directory_offsets`) and the empty/unknown-magic skip
  (`directory.py:108-117`). Tertiary pointers (`0x48`/`0x4A`, the Zen 4+ double
  indirection) are followed by reading the 32-byte block they point at and
  walking the real L2 offset from `block[16:20]` (`directory.py:85-99`).

## Acceptance criteria

- AC-1 (REQ-1): `DirectoryHeader::parse` reads `magic`/`fletcher`/`count`/
  `additional_info` LE at 0x00/0x04/0x08/0x0C and retains a 16-byte source
  window; pinned by `parse_psp_directory_fixture` and `parse_combo_psp_fixture`.
- AC-2 (REQ-2): `Directory::parse_at` returns `Psp`/`Bios`/`Combo` for the six
  magics and `BadMagic` for an unknown tag; pinned by the three `parse_*_fixture`
  tests plus `parse_at_unknown_magic_is_bad_magic`.
- AC-3 (REQ-3): a header whose `count` overruns the blob returns
  `ParseError::Truncated`; pinned by `parse_at_truncated_body_returns_truncated`.
  Each entry's source window starts right after the header/reserved region.
- AC-4 (REQ-4): `DirectoryHeader::address_mode()` returns `PhysicalX86` for the
  v2 fixture (`additional_info = 0x02000000`) and `DirectoryRelative` for a v1
  header with `bits[25:24] = 10`; pinned by `parse_psp_directory_fixture` and
  `walk_directories_follows_l2_pointer`.
- AC-5 (REQ-5): the stored dword at `[0x04..0x08]` is decoded into
  `header.fletcher`; the fixture checksum tests in `fletcher.rs`
  (`matches_fixture_*_directory_checksum`) cross-validate that this stored value
  equals `fletcher32(body)`.
- AC-6 (REQ-6): a no-mutation roundtrip preserves the source checksum bytes
  byte-for-byte (diff-and-patch, `corpus_roundtrip`). A verify-on-parse warning
  and a recompute-on-mutation path do NOT exist — see the REQ status table.
- AC-7 (REQ-7): `parse_combo_psp_fixture` pins the 16/16/16 layout, the
  all-zero-but-preserved reserved block, and combo-entry decode;
  `walk_directories_via_combo_to_psp` pins that the combo `pointer` is followed
  to its child PSP directory.
- AC-8 (REQ-8): `PspGenerationId(0xBC0B_0500).zen_generation()` is `Some(Zen2)`;
  pinned by `parse_combo_psp_fixture` and the `id.rs` `zen_generation_*` tests.
- AC-9 (REQ-9): `walk_directories` yields directories in walk order,
  deduplicated by absolute offset, skipping non-directory pointers and following
  L2 pointers; pinned by `walk_directories_via_single_fet_pointer`,
  `walk_directories_skips_non_directory_pointers`,
  `walk_directories_dedups_repeat_pointers`,
  `walk_directories_follows_l2_pointer`, and
  `walk_directories_traverses_capsule_wrapped_image`.

## REQ status table

| REQ | Status | Evidence |
|---|---|---|
| REQ-1 (16B header parse) | SHIPPED | impl `directory.rs:68` (`DirectoryHeader::parse`) reads `magic`@0x00, `fletcher`@0x04 (`directory.rs:79`), `count`@0x08 (`directory.rs:80`), `additional_info`@0x0C (`directory.rs:81`) LE and slices a 16-byte source window (`directory.rs:82`) — mirrors upstream `directory.py:28`/`128`/`129`/`131`/`135`. Non-test consumer: `psptool-ops/src/list.rs:583` (`dir.header().address_mode()`) via `Directory::header()` (`directory.rs:336`), and the FET walker `walk_directories` (`directory.rs:610`, `Directory::parse_at`). Verification: `cargo test -p psptool-core` (146 passed, 0 failed). |
| REQ-2 (magic-family dispatch) | SHIPPED | impl `directory.rs:310` (`Directory::parse_at`) dispatches on `directory_family(header.magic)` (`magic.rs:107`) at `directory.rs:316-332`: `Psp`/`Bios`/`Combo` build the matching directory, `None` → `ParseError::BadMagic` (`directory.rs:326`). Mirrors upstream `directory.py:111`/`113`/`116` and the `DIRECTORY_MAGICS` tables (`directory.py:27`/`253`). Non-test consumer: `psptool-cli/src/cmds/list.rs:136`, `psptool-ops/src/list.rs:359`, `psptool-cli/src/cmds/replace.rs:44` all `match … Directory::Combo(_)`; the walker `directory.rs:610`/`636`/`669`/`700` calls `parse_at` on every FET/combo/L2 pointer. Verification: `parse_at_unknown_magic_is_bad_magic` + the three `parse_*_fixture` tests (in the 146-test pass). |
| REQ-3 (entry-table slice) | SHIPPED | impl `directory.rs:364` (`PspDirectory::parse_with_header`), `directory.rs:414` (`BiosDirectory::parse_with_header`), `directory.rs:464` (`ComboDirectory::parse_with_header`) loop `count` records at stride `PSP_ENTRY_SIZE`/`BIOS_ENTRY_SIZE`/`COMBO_ENTRY_SIZE` (`directory.rs:30-36`) after the header, bounds-checked by `ensure_in_bounds` (`directory.rs:749`) — mirrors `directory.py:133`/`144-147`/`31`/`255`. Non-test consumer: `entry.rs:402`/`442` (`parse_psp`/`parse_bios` iterate `parent.entries`), reached from `psptool-ops/src/list.rs:366`/`380` and `psptool-cli/src/cmds/list.rs`. Verification: `parse_at_truncated_body_returns_truncated` + `parse_*_fixture` (in the 146-test pass). |
| REQ-4 (address_mode extraction) | SHIPPED | impl `directory.rs:97` (`DirectoryHeader::address_mode`) → `AddressMode::from_additional_info` (`address.rs:172`): `v1 = (info >> 31) & 1`; `(info >> 24) & 3` if v1 else `(info >> 29) & 3` — byte-exact mirror of `directory.py:186-193`. Non-test consumer: `psptool-ops/src/list.rs:583` (`dir.header().address_mode()` → `resolve_with_entry` at `list.rs:617`/`631`), `entry.rs:402`/`442`, and the walker at `directory.rs:654`/`687`. Verification: `parse_psp_directory_fixture` + `walk_directories_follows_l2_pointer` + `cargo test -p psptool-core --test corpus_roundtrip` (54 passed, 0 failed, 0 ignored). |
| REQ-5 (checksum field parse) | SHIPPED | impl `directory.rs:79` (`let fletcher = u32::from_le_bytes(bytes[0x04..0x08]...)`) stores the field into `DirectoryHeader::fletcher` (`directory.rs:61`) — mirrors upstream `directory.py:135` (`self.checksum = NestedBuffer(self, 4, 4)`) / `directory.py:197`. Non-test consumer: the parsed field survives the diff-and-patch writer (`writer.rs:15` — source bytes preserved), pinned end-to-end by `corpus_roundtrip` (54 passed). The field is also cross-validated against `fletcher32(body)` by `fletcher.rs` `matches_fixture_*_directory_checksum`. Verification: `cargo test -p psptool-core --test corpus_roundtrip` (54 passed, 0 failed, 0 ignored). |
| REQ-6 (checksum verify / recompute) | NOT-STARTED | open prereq blocker #43. No production code recomputes or verifies the directory checksum: the writer is diff-and-patch only (`writer.rs:15` — "does not recompute fletcher/sha") and no non-test caller invokes `psptool_core::fletcher32` (grep of `crates/*/src` outside `#[cfg(test)]` finds only the `fletcher.rs` definition). Upstream's `verify_checksum` (`directory.py:195-201`) warns on mismatch and `update_checksum` (`directory.py:203-205`) recomputes; neither is mirrored by a production path. |
| REQ-7 (combo reserved + secondaryAddresses) | SHIPPED | impl `directory.rs:464` (`ComboDirectory::parse_with_header`) parses header + 16-byte reserved (`directory.rs:495`, preserved verbatim per `directory.rs:288-290`) + 16-byte combo entries (`ComboEntry::parse`, `directory.rs:248`: `entry_flags`/`psp_generation`/`pointer`/`reserved`), and `walk_directories` follows each combo `pointer` at `directory.rs:623-651`. Mirrors upstream secondary discovery `directory.py:80-83` + combo generation read `directory.py:85-99`. Non-test consumer: `psptool-ops/src/list.rs:533`/`592-600` (`Directory::Combo(c)` iterates `c.entries` and resolves `entry.pointer`), `psptool-cli/src/cmds/extract.rs:255`. Verification: `parse_combo_psp_fixture` + `walk_directories_via_combo_to_psp` (in the 146-test pass). |
| REQ-8 (Zen-generation id map) | SHIPPED | impl `id.rs:191` (`PspGenerationId::zen_generation`) maps `high24()` (`id.rs:185`, `raw >> 8`) to `Zen1..Zen4Or5` — byte-exact transcription of `ZEN_GENERATION_IDS` (`directory.py:34-39`): `b'\x05\x0B\xBC'` → `0xBC_0B_05` → Zen2, etc. (`get_possible_zen_generation`, `directory.py:41-48`). Non-test consumer: `psptool-ops/src/list.rs:536`/`559` (`e.psp_generation.zen_generation()` in `directory_generation`). Verification: `parse_combo_psp_fixture` (asserts `Zen2`) + the `id.rs` `zen_generation_*` tests (in the 146-test pass). |
| REQ-9 (FET → directory walk) | SHIPPED | impl `directory.rs:567` (`walk_directories`): resolves FET slots (`directory.rs:595-619`), follows combo entries (`directory.rs:623-651`) and L2 secondary pointers `is_secondary_directory_pointer` = `0x40`/`0x49`/`0x70` (`id.rs`, `directory.rs:657`/`690`), dedups by absolute offset (`directory.rs:581-585`), skips non-directory pointers (`directory.rs:610` `if let Ok(dir)`) — mirrors `directory.py:57-101`/`159-163`/`108-117`. Tertiary (`0x48`/`0x4A`) double-indirection is followed via `tertiary_actual_offset` (`directory.rs:750`), reading `block[16:20]` and applying the ROM addr_mask (`directory.py:85-99`/`105`), pinned by `crates/psptool-core/tests/divergence_tertiary.rs` (#51). Non-test consumer: `psptool-cli/src/load.rs:57`, `psptool-ops/src/search_keys.rs:80`, `psptool-ops/src/verify.rs:111`, `psptool-cli/src/cmds/list.rs:94`. Verification: `cargo test -p psptool-cli --test differential` (49 passed, 0 failed, 5 ignored — #40/#41, no directory REQ) + the five `walk_directories_*` unit tests. |

## Architecture

**Header is family-agnostic; the body is not.** `DirectoryHeader`
(`directory.rs:57`) models only the 16 bytes every family shares — `magic`,
`fletcher`, `count`, `additional_info`. The `additional_info` dword is stored
raw and *interpreted per family*: `address_mode()` (`directory.rs:97`) reads it
as the PSP/BIOS version+mode word, while `lookup_mode()` (`directory.rs:105`)
hands it back untouched for combos, matching upstream's comment that combo
directories carry a `lookup_mode` there rather than an address mode. This is the
R-DEV-4 Rust analog of upstream's stringly-typed `self.additional_info` bytes
(`directory.py:131`) — one raw dword, two typed accessors, no runtime
`isinstance` branch.

**Magic discrimination decides entry width (critic watch-item).** There is no
in-record flag selecting 16-vs-24-byte entries; the choice is made solely by the
directory magic at `directory.rs:316-325`. `$PSP`/`$PL2` → `PspEntry` (16 B,
`PSP_ENTRY_SIZE`), `$BHD`/`$BL2` → `BiosEntry` (24 B, `BIOS_ENTRY_SIZE`),
`2PSP`/`2BHD` → `ComboEntry` (16 B, after a 16 B reserved block). This mirrors
upstream selecting the subclass by *which class constructs the entry*
(`Directory.ENTRY_CLASS = DirectoryEntry` at `directory.py:30` vs
`BiosDirectory.ENTRY_CLASS = BiosDirectoryEntry` at `directory.py:255`). Each
family's `parse_with_header` re-checks the magic is in its own set
(`directory.rs:369`/`419`/`469`) so a mis-dispatch is a typed error, not a silent
mis-slice. This is the seam a wrong-width bug would hide behind; it is
cross-checked by the byte-exact roundtrip (a 24-byte BIOS entry parsed as 16
bytes would corrupt every subsequent record and fail `corpus_roundtrip`).

**Address-mode word extraction (critic watch-item).** `address_mode()`
(`directory.rs:97`) forwards to `AddressMode::from_additional_info`
(`address.rs:172`), whose branch is the exact mirror of `directory.py:186-193`:
the version bit (`info >> 31`) selects the field position — v1 reads
`bits[25:24]`, v2 reads `bits[30:29]`. The extracted mode then governs entry
offset resolution: `walk_directories` threads it into
`dir_mode.resolve_with_entry(entry.entry_address_mode(), entry.offset, ctx)`
(`directory.rs:668`/`699`), and `entry.rs` does the same for body resolution
(`entry.rs:402`/`442`). Modes `10`/`11` defer to the entry-level `rsv0[31:30]`
override (`address.rs:257-263`); modes `00`/`01` ignore it. A version-bit or
shift-width slip here would mis-resolve every entry offset in a directory — the
field-extraction contract is pinned by `address.rs`'s
`from_additional_info` tests and end-to-end by `walk_directories_follows_l2_pointer`
(which builds a v1 directory-relative header and asserts the L2 child is
reached).

**Fletcher checksum: parse yes, verify/recompute no (critic watch-item).** The
stored dword is read at `directory.rs:79` from `[0x04..0x08]` into
`header.fletcher`. Upstream additionally *verifies* it on construction
(`verify_checksum`, `directory.py:165`/`195-201`, over `data = self[0x8:]`) and
*recomputes* it on mutation (`update_checksum`, `directory.py:203-205`). Neither
is mirrored in production: the writer is deliberately diff-and-patch and
preserves the source checksum bytes rather than recomputing (`writer.rs:15`),
and no production caller invokes `fletcher32`. That gap is REQ-6 / blocker #43,
shared with `.design/psptool-core/fletcher.md` REQ-6. The checksummed region
(`self[0x8:]` = `count` + `additional_info` + all entries; magic and checksum
field excluded) is documented on the fletcher fixture tests, which slice
`bytes[0x08..]`.

**Combo directories are a Rust-side first-class model (critic watch-item).**
Upstream `directory.py` does **not** parse `2PSP`/`2BHD` as a `Directory` at all:
`from_offset` only recognises `$PSP`/`$PL2` and `$BHD`/`$BL2`
(`directory.py:111`/`113`) and raises `ParseError` on any other magic
(`directory.py:116-117`). Upstream reaches combo-pointed children through the
recursive secondary/tertiary indirection in `create_directories_if_not_exist`
(`directory.py:80-99`), where a Zen-4 "double reference" reads a 32-byte block
and pulls the child offset from `block[16:20]` and the generation from
`block[20:24]` (`directory.py:88-89`). The Rust instead models the combo as a
first-class `ComboDirectory` (`directory.rs:284`) with a
header/reserved/entry-table layout and a `ComboEntry` whose `pointer` lives at
+0x08 within a 16-byte record after a 16-byte header + 16-byte reserved block
(absolute +0x28 for the first entry). The two framings therefore locate the
child pointer at *different byte offsets*, which is why the differential harness
treats combos as an **equivalent divergence**, not a bug: it drops combo
directories from the projection entirely (`crates/psptool-cli/tests/differential.rs:28-31`,
`differential.rs:102-111`, `COMBO_MAGICS = ["2PSP", "2BHD"]`), and both tools
still reach the same *leaf* directories. The `ComboEntry` byte layout cannot be
cross-validated against `directory.py` (which never parses it); it is validated
only by the committed micro-fixture (`parse_combo_psp_fixture`) and by the
roundtrip (the reserved block is preserved verbatim, `directory.rs:288-290`).
**Do not "fix" the combo projection divergence** — see R-DEV-2 and the
differential test's tolerance layer.

**Zen-generation table (critic watch-item).** `PspGenerationId::zen_generation`
(`id.rs:191`) keys off `high24() = raw >> 8` (`id.rs:185`). Each upstream
3-byte little-endian tag maps to the Rust 24-bit constant by reversing the bytes:
`b'\x00\x09\xBC'` → `0xBC_09_00` (Zen1), `b'\x00\x0A\xBC'` → `0xBC_0A_00` (Zen1),
`b'\x05\x0B\xBC'` → `0xBC_0B_05` and `b'\x01\x0A\xBC'` → `0xBC_0A_01` (Zen2),
`b'\x01\x0C\xBC'`/`b'\x00\x0C\xBC'` → `0xBC_0C_01`/`0xBC_0C_00` (Zen3),
`b'\x04\x0D\xBC'`/`b'\x0B\x0D\xBC'` → `0xBC_0D_04`/`0xBC_0D_0B` (Zen4),
`b'\x03\x0D\xBC'` → `0xBC_0D_03` (Zen4Or5). All ten entries of
`ZEN_GENERATION_IDS` (`directory.py:34-39`) are present and none is invented.
The combo entry stores the generation at record +0x04 as a u32 LE
(`directory.rs:252`), so a `psp_generation` of `0xBC0B0500` yields
`high24() = 0xBC0B05` → Zen2 (`parse_combo_psp_fixture`). The low byte
(sub-revision) is discarded exactly as upstream matches only the high three bytes
(`directory.py` `zen_generation_id in cls.ZEN_GENERATION_IDS[...]`).

**Traversal graph (critic watch-item).** `walk_directories` (`directory.rs:567`)
is a worklist walk seeded from the FET slots. FET pointers are resolved as
`PhysicalX86` (`directory.rs:606`), combo `pointer`s likewise
(`directory.rs:632`), and L2 secondary pointers via
`resolve_with_entry` honouring the directory + entry address modes
(`directory.rs:668`/`699`). Dedup is by the absolute flash offset of the
directory header (`directory.rs:581-585`), so a directory reached by two
pointers appears once (first pointer wins the provenance,
`walk_directories_dedups_repeat_pointers`). Any pointer whose target is not a
recognisable directory magic is skipped silently (`if let Ok(dir)`,
`directory.rs:610`), matching upstream's empty/unknown-magic skip
(`directory.py:108-117`). The `rom_origin` addend (`directory.rs:563-566`,
`ResolveContext.rom_origin`) handles capsule-wrapped images (§1.1) that carry an
envelope before the ROM; it is `0` for bare flash dumps, so parity on non-wrapped
images is unaffected. Regression `walk_directories_traverses_capsule_wrapped_image`
pins the `0x800`-envelope case. Tertiary pointers (`0x48`/`0x4A`, Zen 4+) are
followed via `tertiary_actual_offset` (`directory.rs:750`): the entry points at a
32-byte block, the real L2 offset is `block[16:20]` masked by the ROM `addr_mask`
(`directory.py:85-99`/`105`), and an unknown generation id only warns upstream so
it does not gate the recursion. Pinned by `divergence_tertiary.rs` (#51).

## Verification

The list below is the gauntlet for this module; every SHIPPED row is backed by
one of these commands returning green (run inside `nix-shell` so
`PSPTOOL_REFERENCE` + `PSPTOOL_TEST_CORPUS` are set — a skipped suite is a red
gate). Route `parity_ops = ["roundtrip", "differential"]`.

- `cargo test -p psptool-core` — 146 lib tests passed, 0 failed, 0 ignored.
  Covers header parse, family dispatch, entry-table slicing, `address_mode`
  extraction, combo parse, and the FET/combo/L2 walk (REQ-1..REQ-5, REQ-7..REQ-9).
  The pinning tests are `parse_psp_directory_fixture`,
  `parse_bhd_directory_fixture`, `parse_combo_psp_fixture`,
  `parse_at_with_blob_root_offset`, `parse_at_unknown_magic_is_bad_magic`,
  `parse_at_truncated_returns_truncated`,
  `parse_at_truncated_body_returns_truncated`,
  `psp_entry_address_mode_uses_rsv0_high_bits`,
  `walk_directories_via_single_fet_pointer`,
  `walk_directories_skips_non_directory_pointers`,
  `walk_directories_via_combo_to_psp`,
  `walk_directories_dedups_repeat_pointers`,
  `walk_directories_follows_l2_pointer`,
  `walk_directories_traverses_capsule_wrapped_image` (in `directory.rs`), plus
  the `id.rs` `zen_generation_*` tests (REQ-8) and the `address.rs`
  `from_additional_info` tests (REQ-4).
- `cargo test -p psptool-core --test corpus_roundtrip` — 54 passed, 0 failed,
  0 ignored (parity_ops "roundtrip"). Byte-exact roundtrip proves the header +
  entry-table + combo reserved-block source windows are preserved verbatim
  (REQ-1, REQ-3, REQ-5, REQ-7) and that the wrong-entry-width failure mode of
  REQ-2 cannot be hiding on the supported corpus.
- `cargo test -p psptool-cli --test differential` — 49 passed, 0 failed,
  5 ignored (parity_ops "differential"). Establishes structural agreement with
  the reference Python tool on the leaf directory graph (REQ-9). The 5 ignored
  trials are the `SKIP_LIST` known-bug ROMs
  (`crates/psptool-cli/tests/differential.rs:118-148`): two for blocker #40
  (compressed-entry size recovery, `entry.md` REQ-6) and three for blocker #41
  (multi-ROM BIOS address base). None pins a directory REQ marked SHIPPED above.
  Combo directories are excluded from the projection as a documented equivalent
  divergence (`differential.rs:28-31`, `102-111`), not via a skipped ROM.
- `cargo test -p psptool-core --lib fletcher` — the fixture-checksum tests
  (`matches_fixture_{psp,bhd,combo}_directory_checksum`) cross-validate that the
  dword parsed at `directory.rs:79` equals `fletcher32(body)` for each family
  (evidence for REQ-5). The recompute/verify path (REQ-6) is NOT covered by any
  green suite — it does not exist (blocker #43).
