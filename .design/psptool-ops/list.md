# `ls` / `ls_json` rendering (`list_default` / `list_verbose` / `list_json`)

<!--
tier: 3-component
status: draft
baseline-commit: 115eb4a82d8f0c9a125a61081b286ba3baff7f52
upstream-paths:
  - /tmp/psptool-ref/psptool/psptool.py
  - /tmp/psptool-ref/psptool/directory.py
-->

## Summary

`crates/psptool-ops/src/list.rs` is the read-only rendering unit — the Rust port
of the reference tool's `PSPTool.ls` (`psptool.py:66-92`), `ls_dir` / `ls_files`
(`psptool.py:94-200`), and `ls_json` / `ls_files_dict` (`psptool.py:202-270`). It
turns a [`RomListing`] (the primitives the parser already produces —
`SourceBytes`, `RomSize`, [`Fet`], the [`DirectoryRef`] walk result, a ROM index)
into owned output: the three-table human layout for `list_default` /
`list_verbose` and a [`serde_json::Value`] array for `list_json`. It performs no
I/O. Its production consumer is the CLI `list` subcommand
(`psptool-cli/src/cmds/list.rs:41`/`:45`/`:47`); its differential oracle is
`psptool-cli/tests/differential.rs`, which parses this unit's `-E -j` JSON and
asserts structural agreement (directory address set; per-entry
`index`/`address`/`size`/`sectionType`) against reference PSPTool.

This route's `parity_ops` is `["differential"]`: the load-bearing contract is the
JSON structural projection the differential reads. Text-table columns the
differential does not read (`Generation`, `AGESA`, `Magic/ID`, `File Version`,
`File Info`, the verbose extension) are pinned by the self-oracle snapshot suite
`tests/list_micro.rs`, not by an upstream comparison — this is called out per row
below so no SHIPPED claim over-reaches its actual oracle.

## Requirements

- REQ-1: **Three-table text layout.** `list_default` / `list_verbose` render a
  ROM-summary table (`ROM/Addr/Size/FET/AGESA`), then per directory a header
  table (`''/Directory/Addr/Generation/Magic/Secondary Directory`) and an entry
  table with the fixed basic column set, mirroring `PSPTool.ls`
  (`psptool.py:68`, `:79`, `psptool.py:103`).
- REQ-2: **JSON directory object shape.** `list_json` emits an array of
  `{directory, address, magic, secondaryAddresses, entries[]}` objects, mirroring
  `ls_json`'s per-directory dict (`psptool.py:208-213`).
- REQ-3: **Entry structural projection (the differential contract).** Each entry
  JSON object carries `index`, `address`, `size`, `sectionType` — exactly the
  fields `differential.rs` compares against reference PSPTool
  (`ls_files_dict` `psptool.py:246-250`).
- REQ-4: **Readable type name (`sectionType` / `Type` column).** Entry types
  render as `"<NAME>~0x<hh>"` for known PSP types, BIOS-directory overrides
  (`0x61`→`APOB`, `0x62`→`BIOS`, others `<NAME>~0x<hh>`), and bare `"0x<hh>"` for
  unknown types, mirroring `File.get_readable_type` as consumed at
  `psptool.py:173`/`:250`.
- REQ-5: **Combo directories list no files.** A combo (`2PSP`/`2BHD`) directory
  is a routing node; its entry list is empty, matching the reference tool, which
  lists only leaf directories' files (`ls_dir` → `directory.files`,
  `psptool.py:95-96`). The combo node the walk surfaces is excluded from the
  differential projection (`differential.rs` `COMBO_MAGICS`).
- REQ-6: **Magic/ID and File Version columns.** The `Magic/ID`/`magic` and
  `File Version`/`version` values are rendered from the entry header / pubkey
  certifying-id, mirroring `get_readable_magic` / `get_readable_version`
  (`psptool.py:176-177`/`:251-252`). *Self-oracle only:* the differential
  tolerates value-format divergence on these keys (`differential.rs` module doc).
- REQ-7: **File Info tokens.** The `File Info`/`info` field emits
  `compressed`/`signed`/`encrypted`/`sha256`/`sha384`/pubkey-usage/`destination(..)`
  tokens derived from the parsed header flags and BIOS entry, mirroring the
  attribute assembly in `ls_files`/`ls_files_dict` (`psptool.py:114-165`/`:232-244`).
  *Self-oracle only.* The signature-verify and sha-verify **result** tags
  (`verified`/`veri-failed`/`sha256_ok`/`sha256_inconsistent`, `psptool.py:117-140`)
  are NOT yet computed — see REQ-13.
- REQ-8: **Verbose extension columns.** `list_verbose` and `list_json(verbose)`
  add `flags`, `MD5`, `size_signed`, `size_full`, `size_packed`, `load_addr`
  (JSON: `md5`, `flags`, `sizes{signed,uncompressed,packed}`, `load_addr`),
  mirroring the `verbose_fields` + HeaderFile size block
  (`psptool.py:104`/`:183-189`, `:260-266`).
- REQ-9: **Secondary-directory address resolution.** The `Secondary Directory`
  column and JSON `secondaryAddresses` list the flash offsets of
  secondary-directory-pointer entries, resolved through the directory's address
  mode, mirroring `directory.secondary_directory_offsets`
  (`directory.py:156-163`, printed at `psptool.py:86`/`:212`).
- REQ-10: **Generation column for combo-reached directories.** The `Generation`
  column shows the distinct Zen generations of a combo directory's entries, and a
  `$PSP`/`$BHD` directory reached *via a combo entry* inherits that entry's
  generation, mirroring `directory.zen_generation` (`psptool.py:84`, combo
  threading `directory.py:57-63`).
- REQ-11: **Generation column for tertiary-reached (`$PL2`) directories.** A
  directory reached through the Zen 4+ tertiary double-indirection (entry types
  `0x48`/`0x4A`) must show the Zen generation stamped in the tertiary block's
  `block[20:24]` PSP-ID, mirroring `directory.py:86-98` (which sets
  `zen_generation='Zen 4/5 (PSP ID 0x..)'`) as printed at `psptool.py:84`.
- REQ-12: **AGESA version in the ROM summary.** The `AGESA` column of the ROM
  table shows the parsed AGESA version string, mirroring `rom.agesa_version`
  (`psptool.py:74`).
- REQ-13: **Signature / sha verification result in File Info.** The `info` field
  shows the signature-verify and sha-checksum-verify *outcomes*
  (`verified`/`veri-failed(..)` and `sha256_ok`/`sha256_inconsistent`), mirroring
  `psptool.py:117-140`.

## Acceptance criteria

- AC-1 (REQ-1..5,8,9): `cargo test -p psptool-ops --test list_micro` — 9 passed,
  0 failed, 0 ignored. Pins `list_default`/`list_verbose`/`list_json` text and
  JSON output over the PSP, BHD, and empty-directory micro-fixtures.
- AC-2 (REQ-2,3,4,5,9): `cargo test -p psptool-cli --test differential` — 50
  passed, 0 failed, 4 ignored. Every corpus ROM's directory address set and each
  entry's `index`/`address`/`size`/`sectionType` agree with reference PSPTool via
  this unit's `-E -j` JSON. The 4 ignored are tracked bugs (#41 multi-ROM address
  base ×3; #60 type-`0x5c` name ×1), not gaps in this unit.
- AC-3 (REQ-10): `cargo test -p psptool-ops --test divergence_tertiary_generation`
  — `control_combo_reached_directory_carries_generation` passes, proving the
  render path stamps `Zen4Or5` for a combo-reached directory.
- AC-4 (REQ-11): the same suite's
  `divergence_tertiary_0x48_directory_carries_generation` and `_0x4a_` are
  `#[ignore]` and fail when un-ignored — the committed pin for blocker #70.
- AC-5 (REQ-12, REQ-13): open — no green test exists; the placeholder strings
  `AGESA_UNKNOWN` / `SIG_UNKNOWN` / `SHA_UNKNOWN` are emitted verbatim.

## REQ status table

| REQ | Status | Evidence |
|---|---|---|
| REQ-1 (three-table text layout) | SHIPPED | `render_text` `list.rs:108-119` composes `render_rom_table` (`list.rs:121-131`, cols `["ROM","Addr","Size","FET","AGESA"]`), `render_directory_header_table` (`list.rs:133-167`, cols `["","Directory","Addr","Generation","Magic","Secondary Directory"]`) and `render_entries_table` (`list.rs:169-213`, `basic_fields` `list.rs:170-182`); mirrors `PSPTool.ls` (`psptool.py:68` `PrettyTable(['ROM','Addr','Size','FET','AGESA'])`, `:79`, `:103`). Consumer: `psptool-cli/src/cmds/list.rs:45` (`list_verbose`) / `:47` (`list_default`). Verification: `list_micro` `list_default_psp_micro`/`list_verbose_psp_micro`/`list_default_bhd_micro` (9 passed). |
| REQ-2 (JSON directory object) | SHIPPED | `list_json` `list.rs:80-102` pushes `json!({"directory","address","magic","secondaryAddresses","entries"})` per directory; mirrors `ls_json` (`psptool.py:208-213` `{'directory','address','magic','secondaryAddresses'}`). Consumer: `psptool-cli/src/cmds/list.rs:41` (`list_json`). Verification: `differential.rs:351-393` reads `address`/`entries`; `list_micro` `list_json_psp_micro`. |
| REQ-3 (entry structural projection) | SHIPPED | `entry_to_json` `list.rs:306-347` inserts `index`/`address`/`size`/`sectionType` (`list.rs:309-315`); mirrors `ls_files_dict` (`psptool.py:246-250`). Consumer: `psptool-cli/src/cmds/list.rs:41`. Verification: `differential.rs:377-389` (`entry_diff` `:247-271`) — `cargo test -p psptool-cli --test differential` 50 passed, 0 failed. |
| REQ-4 (readable type name) | SHIPPED | `readable_type` `types.rs:196-213` (`"<NAME>~0x<hh>"`; BIOS `0x61`→`APOB`, `0x62`→`BIOS`; unknown `"0x<hh>"`), called `list.rs:218`/`:314`; mirrors `File.get_readable_type` as consumed at `psptool.py:173`/`:250`. Consumer: `psptool-cli/src/cmds/list.rs:41`. Verification: `differential.rs:264-269` compares `sectionType` (50 passed). Upstream-parity map-coverage gap tracked #39; one corpus ROM's `0x5c` name is a version-skew ignore (#60, §Version-skew). |
| REQ-5 (combo lists no files) | SHIPPED | `entries_for_directory` `list.rs:353-361` returns `Vec::new()` for `Directory::Combo`; mirrors the reference listing only `directory.files` for leaf dirs (`psptool.py:95-96`). Consumer: `psptool-cli/src/cmds/list.rs:41`/`:47`. Verification: `differential.rs:354-359` drops `COMBO_MAGICS` (`2PSP`/`2BHD`) so combos line up; 50 passed. |
| REQ-6 (magic/ID + version) | SHIPPED (self-oracle) | `magic_id_string` `list.rs:405-422` (header magic or pubkey certifying-id, `ascii_or_hex_4` `list.rs:508-518`) and `version_string` `list.rs:424-432`; mirror `get_readable_magic`/`get_readable_version` (`psptool.py:176-177`/`:251-252`). Consumer: `psptool-cli/src/cmds/list.rs:41`/`:47`. Verification: `list_micro` snapshots — NOT differentially compared (`differential.rs` module doc: `magic`/`version` are tolerated JSON-shape divergences). |
| REQ-7 (file info tokens) | SHIPPED (self-oracle) | `info_list` `list.rs:447-485` emits `compressed`/`signed`/`encrypted`/`sha256`/`sha384`/`pubkey_usage`/`destination(..)` from parsed header + BIOS entry; mirrors `psptool.py:114-165`/`:232-244`. Consumer: `psptool-cli/src/cmds/list.rs:41`/`:47`. Verification: `list_micro` snapshots — `info` is a differential-tolerated key. Verify-result tags are a separate gap (REQ-13). |
| REQ-8 (verbose extension columns) | SHIPPED | `build_entry_row` verbose branch `list.rs:238-259` (`flags`/`MD5`/`size_signed`/`size_full`/`size_packed`/`load_addr`, `body_md5_hex` `list.rs:496-506`) and `entry_to_json` verbose branch `list.rs:330-343` (`md5`/`flags`/`sizes`/`load_addr`); mirror `verbose_fields` + HeaderFile block (`psptool.py:104`/`:183-189`/`:260-266`). Consumer: `psptool-cli/src/cmds/list.rs:45` (`list_verbose`) / `:41` (`list_json` with `args.verbose`). Verification: `list_micro` `list_verbose_psp_micro`/`list_json_verbose_psp_micro`. |
| REQ-9 (secondary-directory resolution) | SHIPPED | `secondary_addresses` `list.rs:580-607` resolves secondary-directory-pointer entries through the directory address mode (`collect_secondary_psp`/`_bios` `list.rs:609-635`); mirrors `directory.secondary_directory_offsets` (`directory.py:156-163`), printed `psptool.py:86`/`:212`. Consumer: `psptool-cli/src/cmds/list.rs:41`/`:47`. Verification: `list_micro` `fet_pointer_addresses_are_byte_stable`; differential combo-drop keys on it. |
| REQ-10 (generation, combo-reached) | SHIPPED | `directory_generation` `list.rs:531-567`: combo branch (`:533-544`) joins distinct `zen_label`s; PSP/BIOS branch resolves `DirectoryProvenance::ComboEntry` back to the combo entry's generation (`:545-564`, `zen_label` `list.rs:569-577`); mirrors `directory.zen_generation` (`psptool.py:84`) combo threading (`directory.py:57-63`). Consumer: `psptool-cli/src/cmds/list.rs:47`. Verification: `divergence_tertiary_generation.rs::control_combo_reached_directory_carries_generation` (passes — renders `Zen4Or5`). |
| REQ-11 (generation, tertiary-reached `$PL2`) | NOT-STARTED | open blocker #70. `directory_generation` `list.rs:545-552` returns `String::new()` for any non-`ComboEntry` provenance — tertiary-reached dirs carry `DirectoryProvenance::L2Pointer` (`directory.rs:551-554`), so their `block[20:24]` Zen ID (`directory.py:86-98`) is dropped and the `Generation` cell is blank vs the reference. Fix spans core `directory.rs` (surface `block[20:24]`) + this unit. Pinned by `divergence_tertiary_generation.rs::divergence_tertiary_0x48/0x4a_directory_carries_generation` (`#[ignore]`, tracking #70). |
| REQ-12 (AGESA version) | NOT-STARTED | open blocker #75. `render_rom_table` `list.rs:128` emits the `AGESA_UNKNOWN` placeholder (const `list.rs:61`) where `psptool.py:74` prints `rom.agesa_version`; the core parse for the AGESA string is not exposed on `RomListing`. Text-only column, not gated by the differential JSON oracle. |
| REQ-13 (sig/sha verify result) | NOT-STARTED | open blocker #76. `info_list` `list.rs:460`/`:467`/`:471` emits `SIG_UNKNOWN`/`SHA_UNKNOWN` placeholders (consts `list.rs:62-63`) where `psptool.py:117-140` renders `verified`/`veri-failed(..)`/`sha256_ok`/`sha256_inconsistent`. `psptool-ops`'s `verify.rs` holds the signature machinery but is not wired into `info_list`. `info` is a differential-tolerated key, so this is not gated by the differential. |

## Architecture

**Inputs, no I/O.** [`RomListing`] (`list.rs:39-50`) bundles the parser outputs —
`blob: &SourceBytes`, `rom_size`, `rom_origin`, `fet`, and the
`directories: &[DirectoryRef]` from `walk_directories` — plus a ROM `index` for
the summary table's leading column. The three public functions
(`list_default` `list.rs:66`, `list_verbose` `list.rs:72`, `list_json`
`list.rs:80`) are the boundary library surface; the CLI `list` subcommand
constructs a `RomListing` (`psptool-cli/src/cmds/list.rs:52-61`) and calls exactly
one of them (`:41`/`:45`/`:47`). Per goal.md R-DEFER-1 these boundary renderers
are the public surface — the CLI is their production consumer.

**Text path.** `render_text` (`list.rs:108`) emits the ROM table then, per
`DirectoryRef`, a header table and an entries table. `render_entries_table`
(`list.rs:169`) parses every record via `entries_for_directory` (`list.rs:353`,
dispatching `Entry::parse_psp`/`parse_bios`) into `EntryRow = Result<Entry,
ParseError>` (`list.rs:56`); a parse error becomes a `<parse error: ..>` row
(`build_error_row` `list.rs:264`) rather than a dropped entry — mirroring the
reference tool's `PrintHelper` warning path rather than silently truncating.

**JSON path.** `list_json` (`list.rs:80`) builds the directory-object array;
`entry_to_json` (`list.rs:306`) emits the structural keys plus, in verbose mode,
`md5`/`flags`/`sizes`/`load_addr`. A parse error becomes `{"index","error"}`
(`entry_row_to_json` `list.rs:296-304`) — `differential.rs:370-376` surfaces that
as an explicit failure rather than an opaque missing-`address`. The BIOS
`destinationAddress` key is added only for a used-destination BIOS entry
(`list.rs:320-328`), mirroring `psptool.py:257-258`.

**Generation resolution.** `directory_generation` (`list.rs:531`) is the one place
the `Generation` column value is computed. For a combo directory it enumerates
each combo entry's `psp_generation.zen_generation()`; for a `$PSP`/`$BHD`
directory it back-resolves a `DirectoryProvenance::ComboEntry`
(`directory.rs:545-548`) to the combo entry's generation. The gap is structural:
tertiary-reached (`0x48`/`0x4A`) directories arrive as
`DirectoryProvenance::L2Pointer` (`directory.rs:551-554`), which the function does
not handle, so their generation is blank (REQ-11 / #70). The fix requires core
`directory.rs` to thread `block[20:24]` into a provenance variant this function
can read — the same routing wall #66 hit for `replace.rs`, which is why list.rs is
being routed now.

**Address-mode reuse.** Secondary-pointer resolution builds a `ResolveContext`
from `rom_size`/`directory_base`/`rom_origin` (`list.rs:583-588`) and defers to the
core `AddressMode` resolver, so the rendering unit never re-implements address
arithmetic — it reuses the `.design/psptool-core/address.md` primitive.

## Version-skew note (blocker #61)

The differential oracle is PSPTool 3.4 while the translation source
`/tmp/psptool-ref` is git HEAD. Two rendering strings this unit produces can differ
across that skew and are handled as tolerated ignores rather than asserted REQs:

- **Type name for `0x5c`** — one corpus ROM
  (`AORUS_X570_X57AOXT2.FCd`) surfaces our `SPI_ROM_CONFIG` (`types.rs:96`) vs the
  3.4 reference's `WMOS`/HeaderFile classification; registered as an ignored
  differential trial (`differential.rs:123-127`, crosslink #60). This is a #61
  version-skew artifact (the HEAD type-name map differs from 3.4), not a code bug,
  so REQ-4 does not assert a HEAD-only `0x5c` string.
- **Generation labels** — `zen_label` (`list.rs:569-577`) renders HEAD-style tags
  (`Zen1`..`Zen4Or5`); the 3.4 reference prints `Zen 1`..`Zen 4/5 (PSP ID 0x..)`
  (`directory.py:34-48`). The `Generation` column is a text-only column the
  differential does not read, so no REQ asserts label equality with the 3.4
  oracle; REQ-10/REQ-11 are pinned by the self-oracle
  `divergence_tertiary_generation.rs` control instead.

The upstream-parity divergences #57 (full PSP-ID hex in the generation label), #55
(zen back-fill to secondary dirs), and #39 (type-name-map coverage) are HEAD-vs-3.4
/ completeness follow-ups on the same rendering surface; they are referenced here,
not re-filed.

## Verification

The list below IS the gauntlet for this module; run inside `nix-shell` so
`PSPTOOL_REFERENCE` + `PSPTOOL_TEST_CORPUS` are set (a skipped suite is a red gate,
not a pass).

- `cargo test -p psptool-cli --test differential` — **50 passed, 0 failed, 4
  ignored**. The route's declared `parity_ops` oracle: directory address sets and
  per-entry `index`/`address`/`size`/`sectionType` agree with reference PSPTool via
  this unit's `-E -j` JSON. The 4 ignored are tracked bugs registered as
  ignored-but-failing trials (#41 multi-ROM address base ×3; #60 type-`0x5c` name
  ×1), not gaps in the rendering unit.
- `cargo test -p psptool-ops --test list_micro` — **9 passed, 0 failed, 0
  ignored**. Self-oracle snapshots of `list_default`/`list_verbose`/`list_json`
  over PSP, BHD, and empty-directory micro-fixtures; the pin for the text-table
  and JSON-shape REQs the differential does not read (REQ-1, REQ-6, REQ-7, REQ-8).
- `cargo test -p psptool-ops --test divergence_tertiary_generation` — **1 passed,
  2 ignored**. `control_combo_reached_directory_carries_generation` passes
  (REQ-10). `divergence_tertiary_0x48/0x4a_directory_carries_generation` are
  `#[ignore]` and fail when un-ignored — the committed pin for REQ-11 / blocker
  #70 (per goal.md R-DEFER-3, they move to `#[test]` only when the fix lands).
- `cargo test -p psptool-ops --lib` — 50 passed, 0 failed, 0 ignored (the crate's
  own suite is green; `list.rs` itself carries no in-file unit tests — its oracles
  are the integration suites above).

Open prerequisite blockers for the NOT-STARTED REQs: **#70** (REQ-11, tertiary
generation column), **#75** (REQ-12, AGESA version), **#76** (REQ-13, sig/sha
verify result).
