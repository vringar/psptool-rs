# Directory entry record, body resolution, and file-class taxonomy (§3)

<!--
tier: 3-component
status: draft
baseline-commit: 6e6b6db1088c13407728afd54256f60f51fbb8de
upstream-paths:
  - /tmp/psptool-ref/psptool/entry.py
  - /tmp/psptool-ref/psptool/file.py
-->

## Summary

`crates/psptool-core/src/entry.rs` turns a directory *record* (the 16-byte
`$PSP`/`$PL2` entry or the 24-byte `$BHD`/`$BL2` entry) into a resolved
[`Entry`] = (record, body bytes, class). It mirrors two upstream files: the
record field layout and address-mode application from
`psptool/entry.py` (`DirectoryEntry` / `BiosDirectoryEntry`, and
`DirectoryEntry.file_offset()` at `entry.py:38`), and the entry-type → file-kind
dispatch from `psptool/file.py` (`File.from_entry` at `file.py:249`, driven by
the type tables at `file.py:34`, `file.py:235`, `file.py:239`, `file.py:243`,
`file.py:244`). The byte-level record decode itself lives in the sibling
`directory.rs` (`PspEntry::parse` / `BiosEntry::parse`); `entry.rs` consumes it
through the [`EntryRecord`] enum and adds body-offset resolution and
classification.

## Requirements

- REQ-1: **16-byte PSP `DirectoryEntry` field layout.** Decode the six fields of
  the 16-byte record — `type` (u8 @0x00), `subprogram` (u8 @0x01), `flags`
  (u16 @0x02), `size` (u32 @0x04), `offset` (u32 @0x08), `rsv0` (u32 @0x0C) — as
  little-endian unsigned values, and expose the entry-level address-mode
  override `rsv0[31:30]`. Mirrors `entry.py:27` (`ENTRY_SIZE = 4*4`) and the
  property accessors `entry.py:72/81/88/104/112/120/132`.
- REQ-2: **24-byte BIOS `BiosDirectoryEntry` extra fields.** The BIOS record is
  24 bytes: the shared 16-byte prefix plus an 8-byte `destination` (u64 @0x10,
  `'<Q'`). BIOS also re-slices the flag sub-fields: `region_type` (u8 @0x01),
  `compressed = flags[3]`, `instance = flags[4:8]`, `subprogram = flags[8:11]`.
  `destination == 0xFFFF_FFFF_FFFF_FFFF` is the "unused" sentinel. Mirrors
  `entry.py:137` (`ENTRY_SIZE = 4*6`), `entry.py:142/150/158/166/174`. The
  16-vs-24 discrimination is by directory family (`$PSP`/`$PL2` → 16,
  `$BHD`/`$BL2` → 24), decided in `directory.rs`, not by any in-record flag.
- REQ-3: **Address-mode application (`file_offset()`).** Resolve an entry's body
  flash offset from its raw `offset` using the parent directory's address mode,
  with the entry-level `rsv0[31:30]` override consulted only when the directory
  mode is `10`/`11` (relative-to-dir / relative-to-partition). Mode `00` masks
  with `addr_mask = rom_size - 1` and applies the `>0xFF000000 && rom>16 MiB`
  x86-window special case; mode `01` is a flash offset; modes `10`/`11` add the
  directory base. Mirrors `entry.py:38-70`.
- REQ-4: **Soft-fuse-chain (`0x0B`) has no separate body.** For `type == 0x0B`
  (`NO_SIZE_ENTRY_TYPES`), the record carries the fuse mask inline; the "body" is
  the entry record itself and no `offset`/`size` resolution is performed (the
  `size` field is the `0xFFFFFFFF` sentinel). Mirrors the `type == 0xb`
  special-case in `entry.py:40-42` and the `NO_SIZE_ENTRY_TYPES` buffer
  construction in `file.py:287-292` / `file.py:243`.
- REQ-5: **Entry-type classification (`File.from_entry`).** Classify the body by
  `type` in the upstream dispatch order: `PUBKEY_ENTRY_TYPES` → pubkey,
  `KEY_STORE_TYPES` → key-store, types not in
  `NO_HDR_ENTRY_TYPES + SECONDARY_DIRECTORY_ENTRY_TYPES` → signed header,
  BIOS-directory `0x66` → microcode, otherwise plain. In addition, label the
  sub-directory-pointer families the walker follows — secondary
  (`0x40/0x49/0x70`) and tertiary (`0x48/0x4A`) — and soft-fuse (`0x0B`) with
  richer variants than upstream's base `File`. Mirrors `file.py:249-272`,
  `file.py:34/35/235/239/243/244`.
- REQ-6: **Compressed-entry size recovery when the declared size overruns the
  ROM.** When a BIOS entry's `compressed` flag is set and
  `entry.file_offset() + entry.size` exceeds the parent buffer, upstream recovers
  the real on-disk length from the embedded zlib stream
  (`zlib_hdr + zlib_size`, reading `zlib_size` at `offset+0x14`) instead of
  erroring. Mirrors `file.py:297-311`.

## Acceptance criteria

- AC-1 (REQ-1): `EntryRecord::Psp` exposes `entry_type`, `size`, `offset`,
  `entry_address_mode` reading the little-endian fields at their documented
  offsets; unit test `psp_entry_address_mode_uses_rsv0_high_bits` and
  `parse_psp_directory_fixture` pin the decode.
- AC-2 (REQ-2): `EntryRecord::Bios` exposes `destination`,
  `destination_is_unused`, `is_compressed`, `instance`, `subprogram`; the 24-byte
  size constant is `BIOS_ENTRY_SIZE = 0x18`. Unit test
  `parse_bhd_directory_fixture` pins the decode and the destination sentinel.
- AC-3 (REQ-3): `resolve_body` produces the same flash offset as
  `entry.py:file_offset()` across all four modes; the `address.rs` resolve
  suite (`resolve_physical_x86_16mib`, `resolve_with_entry_directory_relative`,
  …) and `entry_subwindows_roundtrip_to_original_bytes` establish parity.
- AC-4 (REQ-4): a `type == 0x0B` record with `size == 0xFFFFFFFF` yields
  `EntryClass::SoftFuseChain` and a body equal to the 16-byte record, not a
  slice of `0xFFFFFFFF` bytes. Pinned by
  `classifies_soft_fuse_chain_uses_record_as_body`.
- AC-5 (REQ-5): each of pubkey / key-store / header / microcode / secondary /
  tertiary / plain types routes to its `EntryClass` variant; BIOS-only `0x66`
  is microcode while PSP `0x66` is plain. Pinned by the `classifies_*` tests.
- AC-6 (REQ-6): a compressed BIOS entry whose directory-declared size overruns
  the ROM parses to the zlib-recovered length rather than erroring. This is NOT
  met today (see the REQ status table).
- AC-7 (all REQs): `corpus_roundtrip` and `differential` remain green on the
  supported corpus with 0 failures (the 5 known-broken ROMs are pinned to
  blockers #40 / #41, not to any REQ below marked SHIPPED).

## REQ status table

| REQ | Status | Evidence |
|---|---|---|
| REQ-1 (16B PSP record) | SHIPPED | Decode impl `directory.rs:131` (`PspEntry::parse`) reads `type`/`subprogram`/`flags`/`size`/`offset`/`rsv0` LE at 0x00/0x01/0x02/0x04/0x08/0x0C, and `directory.rs:155` (`entry_address_mode`) exposes `rsv0[31:30]` — mirrors `entry.py:72`/`81`/`88`/`104`/`112`/`120`/`132` (`return (self.rsv0 >> 30) & 3`). Wrapped by `EntryRecord` at `entry.rs:60-101` (`entry_type`/`size`/`offset`/`entry_address_mode`). Non-test consumer: `psptool-ops/src/list.rs:391` (`subprogram_and_instance` reads `EntryRecord::Psp` fields) and `list.rs:366` (`Entry::parse_psp`). Verification: `cargo test -p psptool-core` (146 passed). |
| REQ-2 (24B BIOS record) | SHIPPED | Decode impl `directory.rs:183` (`BiosEntry::parse`) reads the 8-byte `destination` u64 LE at 0x10 (`entry.py:142`, `'<Q'`), with `is_compressed` (`directory.rs:213`, `flags[3]`), `instance` (`directory.rs:219`, `flags[4:8]`), `subprogram` (`directory.rs:225`, `flags[8:11]`), `destination_is_unused` (`directory.rs:231`) mirroring `entry.py:158/166/174` and `entry.py:137` (`ENTRY_SIZE = 4*6`); `BIOS_ENTRY_SIZE = 0x18` at `directory.rs:32`. 16-vs-24 discrimination is by magic family at `directory.rs:316-325`. Wrapped by `EntryRecord::Bios` (`entry.rs:56`). Non-test consumer: `psptool-ops/src/list.rs:392` (`b.subprogram(), b.instance()`) and `list.rs:380` (`Entry::parse_bios`). Verification: `parse_bhd_directory_fixture` (in the 146-test pass). |
| REQ-3 (address-mode `file_offset`) | SHIPPED | Impl `entry.rs:473` (`resolve_body`) computes the body offset via `entry.rs:496` `dir_mode.resolve_with_entry(entry_mode, entry_offset, ctx)` (`address.rs:248`), which applies mode `00` masking + the `>0xFF000000 && >16 MiB` window at `address.rs:281` (`normalise_physical`, mirrors `entry.py:50-60`), mode `01` flash offset (`entry.py:61-63`), and modes `10`/`11` directory-base add with the entry-level `rsv0[31:30]` override (`entry.py:44-48`, `entry.py:64-70`). Non-test consumer: `entry.rs:404`/`444` (`parse_psp`/`parse_bios`), themselves called from `psptool-ops/src/list.rs:366`/`380` and `psptool-cli/src/cmds/list.rs:124`. Verification: `cargo test -p psptool-core --test corpus_roundtrip` (54 passed, 0 failed, 0 ignored). |
| REQ-4 (soft-fuse no body) | SHIPPED | Impl `entry.rs:485-490` (`resolve_body`): `if entry_type.is_soft_fuse_chain() { return Ok(record_source.clone()); }` (`id.rs:45`, `0x0B`) — returns the 16-byte record as the body, matching `entry.py:40-42` and `file.py:287-292` (`NO_SIZE_ENTRY_TYPES`, buffer of `entry.ENTRY_SIZE` at `dir_start + entry_offset`). Classified `SoftFuseChain` at `entry.rs:531`. Non-test consumer: `psptool-ops/src/replace.rs:143` (`matches!(entry.class, EntryClass::SoftFuseChain)` guards a replace). Verification: `classifies_soft_fuse_chain_uses_record_as_body` (in the 146-test pass). |
| REQ-5 (type classification) | SHIPPED | Impl `entry.rs:524` (`classify`) dispatches secondary (`id.rs:32`, `0x40/0x49/0x70` — `file.py:34`), tertiary (`id.rs:39`, `0x48/0x4A` — `file.py:35`), soft-fuse, pubkey (`id.rs:51` — `file.py:235`), key-store (`id.rs:60` — `file.py:244`), BIOS-`0x66` microcode (`file.py:266`), then `!has_no_header` → signed header (`id.rs:75` — `file.py:239/264`), else plain — mirroring `file.py:249-272`. Non-test consumer: `psptool-ops/src/list.rs:405` (`magic_id_string(class: &EntryClass)`) and `list.rs:474` (`EntryClass::Pubkey`), plus `psptool-ops/src/verify.rs:246` (`EntryClass::Header \| EntryClass::KeyStore`). Verification: the `classifies_*` suite (pubkey/header/keystore/secondary/tertiary/microcode/plain) in the 146-test pass, plus `differential` (49 passed, 0 failed). |
| REQ-6 (compressed size recovery) | SHIPPED | `resolve_body` (`entry.rs`) threads the BIOS `compressed` flag (`record.is_compressed()`, `flags[3]` — `file.py:280-281`) and, when `body_end > blob_end` AND the entry is compressed, sizes the on-flash body to `zlib_hdr + zlib_size` via `zlib_find_header` (mirrors `utils.py:218-234`) reading `zlib_size = le_u32(blob[offset+0x14:+4])` (`file.py:302-311`); a non-compressed overrun still returns `Truncated` (`file.py:316-318`). Non-test consumer: `parse_bios` (`entry.rs`), called from `psptool-ops/src/list.rs:380` and `psptool-cli/src/cmds/list.rs`. Verification: `divergence_bios_compressed` (3 passed, incl. the now-active pin) + `ASRock-A520M-HSV-1.31.ROM` passes the real `differential`. `AORUS_X570_X57AOXT2.FCd` no longer errors on the overrun but has a distinct type-0x5c naming divergence tracked as #60. Tracking issues #40/#59 closed. |

## Architecture

**Record vs. body split.** The byte-level record decode lives in `directory.rs`
(`PspEntry` / `BiosEntry`, `directory.rs:119` / `directory.rs:168`), because the
directory parser must slice the entry table before any body is reachable.
`entry.rs` starts from an already-decoded record and adds two things upstream's
`File.from_entry` does inline: body-offset resolution and file-kind
classification. The [`EntryRecord`] enum (`entry.rs:55`) is the seam — it
type-erases the PSP/BIOS record split behind `entry_type()`/`size()`/`offset()`/
`entry_address_mode()`/`source()` so the resolver and classifier stay
family-agnostic.

**16-vs-24 discrimination (critic watch-item).** There is no in-record flag that
says "I am a BIOS entry". Upstream selects the subclass by *which directory
constructed it* (`entry.py:26` vs `entry.py:136`; `file.py:280` branches on
`type(entry) == BiosDirectoryEntry`). The Rust mirror decides at
`directory.rs:316-325` on the directory magic: `$PSP`/`$PL2` build `PspEntry`
(16 B, `PSP_ENTRY_SIZE = 0x10`), `$BHD`/`$BL2` build `BiosEntry` (24 B,
`BIOS_ENTRY_SIZE = 0x18`). `EntryClass::Microcode` (`entry.rs:546`) is likewise
gated on `is_bios`, matching upstream's `type(entry) == BiosDirectoryEntry and
entry.type == 0x66` (`file.py:266`); a PSP directory carrying `0x66` falls to
`Plain` (pinned by `psp_directory_type_0x66_is_not_microcode`).

**Field width / sign (critic watch-item).** Every multi-byte field is unsigned
little-endian: `size`/`offset`/`rsv0` are `u32` (`entry.py` `'<I'`), the BIOS
`destination` is `u64` (`entry.py:144` `'<Q'`), `type`/`subprogram`/`region_type`
are `u8`. `offset` is carried as `Address(u32)` (`directory.rs:126`,
`address.rs:92`); no sign extension or narrowing happens before resolution. The
mask is `addr_mask = rom_size - 1` (`address.rs:77`), i.e. `entry.py:56`'s
`self.parent_directory.rom.addr_mask + 1` inverted.

**Address-mode override precedence (critic watch-item).** `entry.py:44-48`: the
directory mode is taken first, and only when it is `2`/`3` is the entry-level
`address_mode` substituted. The Rust `resolve_with_entry` (`address.rs:248-265`)
encodes the same precedence — modes `00`/`01` ignore the entry field entirely;
modes `10`/`11` switch on the entry mode. `from_entry_rsv0` (`address.rs:270`)
extracts `rsv0[31:30]` exactly as `entry.py:132-134`. The `rom_origin` addend in
the Rust resolver is a deliberate addition for capsule-wrapped images (§1.1) with
no upstream analog — it is `0` for bare flash dumps, so parity holds on those;
its full contract is documented in `.design/psptool-core/address.md`.

**Classification order (critic watch-item).** Rust special-cases
secondary/tertiary/soft-fuse pointers *before* the pubkey/keystore/header cascade
(`entry.rs:525-533`), where upstream would fold them into the base `File`
(`Plain`) via the `NO_HDR + SECONDARY` exclusion (`file.py:264`). This is a
richer-label deviation, not a behavioral one: the pubkey/keystore/soft-fuse type
sets are disjoint from the secondary/tertiary sets (`0x40/0x49/0x70` and
`0x48/0x4A` appear in neither `PUBKEY_ENTRY_TYPES` nor `KEY_STORE_TYPES` nor
`NO_SIZE_ENTRY_TYPES`), so reordering cannot change which non-directory type
lands where. The module doc-comment (`entry.rs:19-28`) records this and the
deferral of tertiary-pointer *following* to a later issue.

**`HeaderEntry` / `PubkeyEntry` sub-parsers.** `classify` invokes
`HeaderEntry::parse` (`entry.rs:153`) and `PubkeyEntry::parse` (`entry.rs:263`)
to attach the fixed-header view when a body is a signed header, key-store, or
pubkey; both retain their own [`SourceBytes`] sub-window so the roundtrip rule
survives, and both fall back to `Plain` on a parse error (`entry.rs:538`/`544`)
so a malformed corpus body never breaks the byte-exact roundtrip. The
*field-level* decode contract for these fixed headers derives from upstream
`header_file.py` / `pubkey_file.py`, which are outside this route's upstream
set; the downstream body-access methods (`get_decrypted_body`,
`verify_signature`, …) live in `body.rs`. This doc scopes only the classification
dispatch that produces the `Header`/`Pubkey`/`KeyStore` variants.

**Bounds check vs. upstream (context for REQ-6).** `resolve_body` bounds-checks
the body window against the whole input `blob` (`entry.rs:498-508`) and returns
`ParseError::Truncated` on overrun, which the `if let Ok(..)` consumers
(`list.rs:366`, `search_keys.rs:100`) treat as "skip this entry" — matching the
`File.ParseError → return None` skip in `file.py:270-272` for the *uncompressed*
overrun case (`file.py:316-318`). The *compressed* overrun case, where upstream
recovers the length from the zlib stream (`file.py:302-311`), is now handled by
`resolve_body` (REQ-6 SHIPPED): a compressed entry whose declared size overruns
the ROM is sized to `zlib_hdr + zlib_size` instead of erroring (blockers
#40/#59 closed).

## Verification

The verification list below IS the gauntlet for this module; every SHIPPED row
above is backed by one of these commands returning green (run inside
`nix-shell` so `PSPTOOL_REFERENCE` + `PSPTOOL_TEST_CORPUS` are set).

- `cargo test -p psptool-core` — 146 unit tests passed, 0 failed, 0 ignored.
  Covers the record decode, `resolve_body`, and every `classifies_*` branch
  (REQ-1..REQ-5).
- `cargo test -p psptool-core --test corpus_roundtrip` — 54 passed, 0 failed,
  0 ignored (parity_ops "roundtrip"). Establishes that entry sub-window
  resolution preserves the source bytes byte-for-byte across the supported
  corpus (REQ-3, REQ-4).
- `cargo test -p psptool-cli --test differential` — 49 passed, 0 failed,
  5 ignored (parity_ops "differential"). The 5 ignored trials are the pinned
  known-broken ROMs in `crates/psptool-cli/tests/differential.rs:118-148`:
  two for blocker #40 (compressed-entry size recovery — REQ-6, NOT-STARTED) and
  three for blocker #41 (multi-ROM BIOS address base). No ignored trial pins a
  REQ marked SHIPPED above.
- Specific `#[test]`s that pin REQ rows: `parse_psp_directory_fixture` /
  `psp_entry_address_mode_uses_rsv0_high_bits` (REQ-1),
  `parse_bhd_directory_fixture` (REQ-2),
  `entry_subwindows_roundtrip_to_original_bytes` (REQ-3),
  `classifies_soft_fuse_chain_uses_record_as_body` (REQ-4),
  `classifies_pubkey_entry_type` / `classifies_header_entry_type` /
  `classifies_keystore_entry_type` / `classifies_secondary_directory_pointer` /
  `classifies_tertiary_directory_pointer` /
  `classifies_microcode_only_for_bios_directory` /
  `psp_directory_type_0x66_is_not_microcode` (REQ-5).
