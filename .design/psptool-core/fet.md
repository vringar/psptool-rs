# Firmware Entry Table discovery, ROM layout, and slot parsing (§1.1–§1.3)

<!--
tier: 3-component
status: draft
baseline-commit: 28cc06fe5a256fad32349d068c520c1a089914db
upstream-paths:
  - /tmp/psptool-ref/psptool/fet.py
  - /tmp/psptool-ref/psptool/blob.py
  - /tmp/psptool-ref/psptool/rom.py
-->

## Summary

`crates/psptool-core/src/fet.rs` is the root of firmware parsing: it finds every
Firmware Entry Table (the `0xAA55AA55` magic region), selects the ROM window that
contains each one, and decodes the FET's flat dword array into classified slots.
It mirrors three upstream files, splitting their responsibilities differently
from Python (goal.md R-DEV-4 — the Rust types replace `NestedBuffer`
bookkeeping):

- **`blob.py`** — `Blob._find_fets` (`blob.py:124`) becomes
  [`scan_fet_candidates`]; the ROM-size / FET-offset selection loop
  (`blob.py:53-84`) becomes [`detect_rom_layout`] + [`KNOWN_FET_OFFSETS`].
- **`fet.py`** — `Fet._determine_size` (`fet.py:44`) + `Fet._parse_entry_table`
  (`fet.py:59`) become [`Fet::parse_at`]; the sentinel-skip rule
  (`fet.py:64`) becomes [`FetSlot::classify`]; the combo (`2PSP`/`2BHD`)
  expansion `_parse_combo_dir` (`fet.py:94`) is realised in the sibling
  `directory.rs` walk loop.
- **`rom.py`** — `Rom.addr_mask = rom_size - 1` (`rom.py:14`) is carried by the
  [`RomSize`] type from `address.rs`; `Rom._find_agesa_version` (`rom.py:24`) is
  **not implemented** (REQ-7, NOT-STARTED).

The deliberate structural difference from upstream: `fet.py._parse_entry_table`
both parses the slot array *and* dereferences each pointer (masking the address
and following it only when the target begins with a known directory magic). The
Rust `Fet::parse_at` stops after classifying slots as `Sentinel`/`Pointer`; the
address masking (`address.rs`) and the directory-magic follow gate (`Directory::
parse_at` inside `directory.rs::walk_directories`) run in the consumer. `fet.rs`
therefore owns *discovery + slot decode + ROM windowing*; traversal is `directory.rs`.

Blob-level concerns that also live in `blob.py` but are out of this route's
scope — the `RangeDict` (`blob.py:93`), `unique_files` (`blob.py:115`), and
inline-pubkey scan (`blob.py:133`) — are realised in `psptool-ops`
(`search_keys.rs`) and are not part of the FET contract documented here.

## Requirements

- REQ-1: **FET discovery scan.** Report every byte-aligned occurrence of an
  8-byte signature `[pad ; 0xAA55AA55]` where `pad ∈ {0x00000000, 0xFFFFFFFF}`,
  returning the offset of the FET magic (the byte after the 4-byte pad). Mirrors
  `blob.py:124-131` (`_find_fets`: `re.finditer(b'\xff\xff\xff\xff' +
  _FIRMWARE_ENTRY_MAGIC, ...)` then the `\x00\x00\x00\x00` variant, each yielding
  `m.start() + 4`).
- REQ-2: **FET table decode (size + slot array + terminator).** From the magic,
  read 4-byte little-endian dwords until a run of four consecutive `0xFFFFFFFF`
  dwords (16 bytes) terminates the table; validate the leading magic; retain the
  full `[magic .. end-of-terminator]` source slice and a per-slot 4-byte source
  slice. Mirrors `fet.py:44-57` (`_determine_size`: grow by `step_size = 4` until
  `end_sequence = 4 * b'\xff\xff\xff\xff'`) and `fet.py:60`
  (`entries = self.get_chunks(4, 4)`).
- REQ-3: **Sentinel vs. pointer classification.** A dword equal to `0x00000000`,
  `0xFFFFFFFE`, or `0xFFFFFFFF` is a sentinel — preserved by position but never
  followed; every other dword is a pointer. Mirrors `fet.py:64`
  (`if rom_addr in [0x0, 0xFFFFFFFF, 0xFFFFFFFe]: continue`).
- REQ-4: **ROM window selection (size + offset table + origin + addr_mask).**
  Choose the largest power-of-two ROM size in `{32, 16, 8} MiB` that fits the
  input; for a FET at file offset `p`, try each known FET-relative offset in turn
  and accept the first `rom_origin = p - offset` where the ROM fits, honouring
  the page-0 single-ROM 16 MiB-boundary workaround. Expose `rom_size` so the
  `addr_mask = rom_size - 1` is available to consumers. Mirrors `blob.py:42-84`
  (offset table, `possible_rom_sizes = [32, 16, 8]`, the underflow/overflow
  guards, and the `rom_page == 0` W/A) and `rom.py:14`
  (`self.addr_mask = rom_size - 1`).
- REQ-5: **Pointer slots drive directory traversal.** The classified pointer
  slots must be consumable so a traversal can mask each address and follow only
  those whose dereferenced target begins with a known directory magic. Mirrors
  `fet.py:68-92` (the `rom_addr &= addr_mask` / `>0xFF000000 && >16 MiB →
  &0x00FFFFFF` masking and the `dir_magic in (b'$PSP', b'$BHD', ...)` follow
  gate). The masking impl is `address.rs` and the follow gate is
  `directory.rs::walk_directories`; `fet.rs` owns the `Pointer`/`Sentinel` split
  and the `pointers()` iterator they consume.
- REQ-6: **Combo (`2PSP`/`2BHD`) directories reachable from FET slots are
  expanded.** A FET pointer to a combo directory must lead to each combo entry's
  sub-directory being walked. Mirrors `fet.py:78-92`
  (`if dir_magic == b'2PSP' or dir_magic == b'2BHD': ... _parse_combo_dir`) and
  `fet.py:94-127` (`_parse_combo_dir`: read `no_of_entries` at `dir+8`, entries
  from offset `0x20`, mask each `entry_addr`). The combo record decode and the
  expansion loop live in `directory.rs` (`ComboDirectory`, `walk_directories`
  combo arm); see `.design/psptool-core/directory.md`.
- REQ-7: **AGESA version + dual-ROM detection.** Surface the ROM's AGESA
  version string (and the two-image `dual_rom` case) as `rom.py` does. Mirrors
  `rom.py:24-52` (`_find_agesa_version`: `re.compile(b"AGESA!..\x00.*?\x00")`,
  the `len(res) == 2 → dual_rom` branch, else `AGESA_UNKNOWN`).

## Acceptance criteria

- AC-1 (REQ-1): `scan_fet_candidates` returns the magic offsets for both a
  zero-padded and an `0xFF`-padded FET, in absolute flash space when the blob is
  rooted at a non-zero offset, and ignores an unpadded magic. Pinned by
  `scan_finds_zero_padded_candidate`, `scan_finds_ff_padded_candidate`,
  `scan_finds_multiple_candidates`, `scan_respects_blob_root_offset`,
  `scan_ignores_unpadded_magic`, `scan_empty_blob`.
- AC-2 (REQ-2): `Fet::parse_at` on the micro fixture yields a 28-byte `source`,
  two slots, and rejects bad magic / an unterminated table / a truncated magic
  with typed `ParseError`s. Pinned by `parse_micro_fixture_fet`,
  `parse_at_with_offset_root`, `bad_magic_is_rejected`,
  `unterminated_fet_is_rejected`, `truncated_at_magic_is_rejected`,
  `magic_offset_outside_blob_is_truncated`.
- AC-3 (REQ-3): `0x00000000` and `0xFFFFFFFE` classify as `Sentinel`, a
  mid-table single `0xFFFFFFFF` classifies as `Sentinel` (not the terminator),
  and `pointers()` skips them. Pinned by
  `parse_synthetic_fet_with_pointer_and_single_ff_sentinel`,
  `parse_micro_fixture_fet`.
- AC-4 (REQ-4): `detect_rom_layout` yields `rom_origin = 0` for a bare 16 MiB
  ROM (FET at `0x20000` and at `0xFA0000`), `rom_origin = 0x800` for a
  capsule-wrapped image, and `None` when no offset fits or the FET underflows the
  offset table. Pinned by `detect_rom_layout_bare_16mib`,
  `detect_rom_layout_zen_plus_fa0000`, `detect_rom_layout_capsule_wrapped_16mib`,
  `detect_rom_layout_returns_none_when_no_offset_fits`,
  `detect_rom_layout_underflow_when_fet_below_offset_table`.
- AC-5 (REQ-5 / REQ-6, corpus parity): `corpus_roundtrip` is byte-exact and
  `differential` structurally agrees with reference PSPTool on every supported
  ROM — the traversal driven by FET pointer slots and combo expansion reaches
  the same directory set upstream does. The 4 ignored `differential` trials
  (blockers #41 multi-ROM base, #60 type-`0x5c` naming) pin distinct downstream
  divergences, not the FET-slot or combo classification here.
- AC-6 (REQ-7): the CLI `list` metadata row shows the real AGESA version rather
  than the `AGESA_UNKNOWN` placeholder. This is NOT met today (see the REQ status
  table, blocker #62).

## REQ status table

| REQ | Status | Evidence |
|---|---|---|
| REQ-1 (FET discovery scan) | SHIPPED | Impl `fet.rs:299` (`pub fn scan_fet_candidates`) scans for `[0x00000000 ; FET_MAGIC]` / `[0xFFFFFFFF ; FET_MAGIC]` and pushes `blob_start + (i + 4)` (`fet.rs:310-316`), mirroring `blob.py:126` (`for m in re.finditer(b'\xff\xff\xff\xff' + self._FIRMWARE_ENTRY_MAGIC, ...)`) and `blob.py:127` (`fet_offset = m.start() + 4`). Non-test consumer: `psptool-cli/src/load.rs:31` (`let candidates = scan_fet_candidates(&blob);`) and `psptool-cli/src/cmds/list.rs:85`. Verification: `cargo test -p psptool-core --lib` (146 passed) covers the `scan_*` suite. |
| REQ-2 (FET table decode) | SHIPPED | Impl `fet.rs:201` (`pub fn parse_at`) validates the magic (`fet.rs:227`), grows the slot array until the 16-byte terminator (`fet.rs:242-248`, mirrors `fet.py:49-53` `while self.rom[...] != end_sequence: size += step_size`), reads each dword LE (`fet.rs:256`) — mirroring `fet.py:60` `entries = self.get_chunks(4, 4)` — and retains the whole-FET `source` (`fet.rs:272-277`) plus per-slot `FetSlotRecord::source` (`fet.rs:262-268`) for the R-CODE-4 roundtrip. Non-test consumer: `psptool-cli/src/load.rs:20`/`src/cmds/list.rs:94` hold the parsed `Fet`; `directory.rs:597` iterates `fet.slots`; `psptool-ops/src/list.rs:48` holds `fet: &'a Fet`. Verification: `cargo test -p psptool-core --test corpus_roundtrip` (54 passed, 0 failed, 0 ignored) proves the retained source roundtrips byte-exact. |
| REQ-3 (sentinel classification) | SHIPPED | Impl `fet.rs:146` (`FetSlot::classify`) routes `addr.is_fet_sentinel()` to `Sentinel`, else `Pointer`; `is_fet_sentinel` (`address.rs:105`) matches `{0x0, 0xFFFFFFFE, 0xFFFFFFFF}` — mirroring `fet.py:64` (`if rom_addr in [0x0, 0xFFFFFFFF, 0xFFFFFFFe]: continue`). `Fet::pointers` (`fet.rs:282`) filters out sentinels. Non-test consumer: `directory.rs:600` (`crate::fet::FetSlot::Sentinel(_) => continue`) skips them during the walk. Verification: `parse_synthetic_fet_with_pointer_and_single_ff_sentinel` (in the 146-test pass). |
| REQ-4 (ROM window selection) | SHIPPED | Impl `fet.rs:62` (`pub fn detect_rom_layout`) picks the largest power-of-two ROM size that fits (`fet.rs:72-80`, mirrors `blob.py:53-54` `possible_rom_sizes = [32, 16, 8]`), iterates `KNOWN_FET_OFFSETS` (`fet.rs:29`, mirrors `blob.py:42-51`), guards underflow (`fet.rs:85-90`, `blob.py:62-64`) and overflow with the `rom_page == 0` W/A (`fet.rs:95-104`, mirrors `blob.py:65-75`), and returns `rom_origin`/`rom_size` (`fet.rs:108-112`). `RomSize::addr_mask` (`address.rs:77`) supplies `rom_size - 1` per `rom.py:14`. Non-test consumer: `psptool-cli/src/load.rs:40` (`.filter_map(\|pos\| detect_rom_layout(&blob, *pos))`) and `cmds/list.rs:87`. Verification: `detect_rom_layout_*` suite (in the 146-test pass); multi-ROM base application diverges downstream — blocker #41. |
| REQ-5 (pointer slots drive traversal) | SHIPPED | `fet.rs:140`/`fet.rs:282` expose the `Pointer` variant and `pointers()`; the consumer `directory.rs:597-621` (`walk_directories`) reads `fet.slots`, resolves each pointer via `AddressMode::PhysicalX86.resolve` (`directory.rs:608`) — the masking that mirrors `fet.py:68-71` (`rom_addr &= addr_mask` / `&= 0x00FFFFFF`) lives in `address.rs:283` (`normalise_physical`) — and follows only pointers `Directory::parse_at` accepts (`directory.rs:612`), mirroring `fet.py:74-92`'s `dir_magic in (b'$PSP', b'$BHD', ...)` follow gate. Non-test consumer: `directory.rs::walk_directories`, itself called from `psptool-cli/src/load.rs:57`. Verification: `cargo test -p psptool-cli --test differential` (50 passed, 0 failed) confirms the followed-directory set matches reference on supported ROMs. |
| REQ-6 (combo expansion) | SHIPPED | A FET pointer to a `2PSP`/`2BHD` combo resolves to `Directory::Combo` (`directory.rs:307`, magic dispatch), and the walk loop's combo arm (`directory.rs:625-652`) masks each combo entry pointer and walks its sub-directory — mirroring `fet.py:78-92` (combo-magic branch) and `fet.py:94-127` (`_parse_combo_dir`: `no_of_entries` at `dir+8` per `fet.py:96`, entries from offset `0x20`, `entry_addr &= addr_mask`). Combo record decode is `directory.rs:238` (`ComboEntry`) / `directory.rs:284` (`ComboDirectory`). Non-test consumer: `walk_directories` via `load.rs:57`; `psptool-cli/src/cmds/extract.rs:255` and `replace.rs:44` branch on `Directory::Combo`. Verification: `differential` (50 passed) exercises combo-bearing corpus ROMs (e.g. `Tyan_*`). Detailed contract: `.design/psptool-core/directory.md`. |
| REQ-7 (AGESA version / dual_rom) | NOT-STARTED | No implementation of `rom.py:24-52` (`_find_agesa_version`). The CLI metadata row emits the placeholder `AGESA_UNKNOWN` (`psptool-ops/src/list.rs:61` `const AGESA_UNKNOWN: &str = "AGESA_UNKNOWN"`, rendered at `list.rs:128`), never scanning `re.compile(b"AGESA!..\x00.*?\x00")`. Open prerequisite blocker #62. Not covered by roundtrip (display-only field); the differential tolerance layer ignores the AGESA column, so this gap does not fail parity. |

## Architecture

**Discovery → windowing → decode split.** Upstream folds all three into
`Blob.__init__` (`blob.py:59-84`) driving `Rom.__init__` (`rom.py:8`) driving
`Fet.__init__` (`fet.py:27`). The Rust mirror keeps three free functions so the
CLI can compose them explicitly: `scan_fet_candidates` (discovery) →
`detect_rom_layout` (windowing, which internally calls `Fet::parse_at`) →
`walk_directories` (traversal). `psptool-cli/src/load.rs:31-57` is the composition
site, exactly `Blob.__init__`'s loop written out.

**`Fet::parse_at` deliberately does less than `_parse_entry_table`.** Upstream's
`_parse_entry_table` (`fet.py:59-92`) parses slots *and* masks *and*
dereferences *and* recurses into directories. The Rust `parse_at` (`fet.rs:201`)
stops at slot classification, because masking depends on `rom_size`/`addr_mask`
(an `address.rs` concern) and following depends on the directory magic (a
`directory.rs` concern). This is the R-DEV-4/R-DEV-5 split: the FET parser has no
opinion about which pointers are real; `walk_directories` (`directory.rs:569`)
applies `addr_mask` via `AddressMode::PhysicalX86` and uses `Directory::parse_at`
success as the "starts with a known magic" gate (`fet.py:74-88`). REQ-5/REQ-6 are
therefore SHIPPED by the *consumer*, with `fet.rs` supplying the `Pointer` slots.

**ROM-size selection and the page-0 workaround (critic watch-item).**
`detect_rom_layout` (`fet.rs:95-104`) reproduces `blob.py:65-75`: `rom_page = (p -
blob_start) / 16 MiB`; when `rom_page == 0` the full `rom_size` may cross the
16 MiB boundary, otherwise the effective size is clamped to 16 MiB. The overflow
guard uses `blob_end` (absolute), so capsule-wrapped images (`rom_origin > 0`,
e.g. the ASUS `.CAP` `0x800` envelope) still pass — pinned by
`detect_rom_layout_capsule_wrapped_16mib`. `KNOWN_FET_OFFSETS` (`fet.rs:29`) is in
`blob.py:42-51` order so the common Zen sites match on the first try.

**Scan ordering divergence (resolved, blocker #63).** Upstream
`_find_fets` (`blob.py:124-131`) runs two separate `re.finditer` passes and
yields **all** `0xFFFFFFFF`-padded FETs first, then **all** `0x00000000`-padded
ones. `scan_fet_candidates` (`fet.rs:310-321`) now mirrors this with two
sequential ascending passes (`for pad in [FF_PAD, ZERO_PAD]`), so every
FF-padded FET precedes every zero-padded one regardless of file position — the
order `load.rs:41`'s `.nth(rom_index)` selects. Pinned by
`crates/psptool-core/tests/divergence_fet_scan_order.rs::divergence_scan_order_ff_pass_before_zero_pass`
(oracle order `[0x204, 0x104]`).

**Address masking is `address.rs`, not `fet.rs` (field-width watch-item).**
`fet.py:68-71`'s `rom_addr &= self.rom.addr_mask` with the `>0xFF000000 &&
rom > 16 MiB → &0x00FFFFFF` override is realised once in
`address.rs:283` (`normalise_physical`) and reused for FET pointers, combo
pointers, and directory entries alike (`directory.rs:608`/`634`). This is the
`RomSize::addr_mask = rom_size - 1` (`address.rs:77`) inverse of
`rom.py:14`'s `addr_mask = rom_size - 1`. Keeping it in one place avoids the
three-way copy upstream carries (`fet.py:68`, `fet.py:111`, `entry.py`).

**Combo `no_of_entries` and the `+0x20` assumption.** Upstream `_parse_combo_dir`
(`fet.py:96-101`) reads `no_of_entries` at `dir+8`, sizes the block as
`16 * (no_of_entries + 2)`, and asserts the reserved block `[0x10:0x20]` is
zero, i.e. entries begin at `0x20`. The Rust `ComboDirectory`
(`directory.rs:284`, `COMBO_RESERVED` at `directory.rs:33`) mirrors this; the FET
doc scopes only "a FET slot pointing at a combo is expanded", the record layout
is `directory.md`'s contract. Note the upstream `zen_generation` label attached
per combo entry (`fet.py:117-125`) is a display string this pipeline does not yet
surface; it is not a structural/roundtrip concern and the differential tolerance
layer does not compare it.

**Multi-ROM base application (context for #41).** `detect_rom_layout` correctly
finds each ROM window (multi-FET blobs parse without error), but the second ROM's
non-zero `rom_origin` is applied to BIOS-region entry addresses where upstream
does not — the divergence tracked by blocker #41 for
`ASUS_PRIME-X470-PRO`, `ASUS_ROG-STRIX-X470-F-GAMING`, `H12SSW9.719`. That
divergence is in the `rom_origin` addend of the `address.rs` resolver, downstream
of the FET window selection this module owns; REQ-4 is SHIPPED for the window
detection itself.

## Version-skew note (blocker #61)

The differential oracle is PSPTool 3.4 while the translation source
`/tmp/psptool-ref` is git HEAD. FET/ROM parsing is on-disk-format-structural and
version-stable; nothing in `fet.py`/`blob.py`/`rom.py` read this iteration shows
a HEAD-only behaviour that the 3.4 oracle would disagree with on the supported
corpus (the discovery signatures, the sentinel set `{0x0, 0xFFFFFFFE,
0xFFFFFFFF}`, the offset table, and `addr_mask = rom_size - 1` are all
long-standing). The one HEAD-side elaboration worth flagging is `_parse_combo_dir`
(`fet.py:94-127`): its `zen_generation` labelling and the exact combo-entry
stride may have evolved between 3.4 and HEAD, but the *structural* expansion
(follow each combo entry's masked pointer) is what the differential checks and it
is green. No REQ above is asserted on a HEAD-only value.

## Verification

The list below IS the gauntlet for this module; every SHIPPED row is backed by
one of these returning green, run inside `nix-shell` so `PSPTOOL_REFERENCE` +
`PSPTOOL_TEST_CORPUS` are set (a skip is a red gate, not a pass).

- `cargo test -p psptool-core --lib` — 146 passed, 0 failed, 0 ignored. Covers
  REQ-1 (`scan_*`), REQ-2 (`parse_*`/`bad_magic`/`unterminated`/`truncated`),
  REQ-3 (`parse_synthetic_fet_with_pointer_and_single_ff_sentinel`), REQ-4
  (`detect_rom_layout_*`).
- `cargo test -p psptool-core --test corpus_roundtrip` — 54 passed, 0 failed,
  0 ignored (parity_ops "roundtrip"). Establishes that the FET `source` and
  per-slot source slices roundtrip byte-for-byte (REQ-2).
- `cargo test -p psptool-cli --test differential` — 50 passed, 0 failed,
  4 ignored (parity_ops "differential"). The 4 ignored trials are pinned in
  `crates/psptool-cli/tests/differential.rs:118-144`: one for #60 (type-`0x5c`
  naming, `AORUS_X570`), three for #41 (multi-ROM BIOS address base). No ignored
  trial pins a REQ marked SHIPPED above; REQ-5/REQ-6 (FET-slot traversal + combo
  expansion) pass on every non-ignored ROM.
- Open prerequisite blockers: #62 (REQ-7 AGESA/dual_rom), #41 (multi-ROM base
  application, downstream of REQ-4), #60 (type-`0x5c` naming, downstream), #61
  (differential oracle version skew). #63 (REQ-1 scan ordering) is resolved —
  two-pass FF-then-zero order pinned by `divergence_fet_scan_order`.
