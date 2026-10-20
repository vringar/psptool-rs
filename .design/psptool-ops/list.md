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
`tests/list_micro.rs`; where a corpus pin compares a column against the live
reference's `ls` instead (`File Info` of HeaderFile rows, REQ-7) the row says
so — this is called out per row below so no SHIPPED claim over-reaches its
actual oracle.

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
- REQ-7: **File Info tokens.** The `File Info`/`info` field emits, in
  `ls_files` order (`psptool.py:113-165`), `compressed`, the signature outcome
  tag, `encrypted`, the checksum outcome tag, the pubkey usage and
  `destination(..)` — derived from the parsed header flags, the decode
  verification and the BIOS entry. Upstream's text listing has **no** bare
  `signed`, `sha256` or `sha384` token (`psptool.py:116-140` appends only the
  outcome of each check), so neither does this unit (#120). The outcome tags
  themselves (`verified`/`veri-failed`/`key_missing`/`sha256_ok`/
  `sha256_inconsistent`/`sha384_*`, `psptool.py:117-140`) are REQ-13. The JSON
  `info` list shares these tokens; upstream's `ls_files_dict` builds a different
  list (`signed(..)`, `verified`/`no_key`, no checksum tag, `psptool.py:231-244`)
  and `info` is a differential-tolerated key.
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
- REQ-14: **Decode-verified bit in JSON.** Every HeaderFile-class entry
  (`HeaderFile` and its `KeyStoreFile` subclass) in `list_json` carries
  `decodeVerified` (bool) and `decodeVerificationMethod` (basis label), regardless
  of `verbose`, computed by the tiered `HeaderFile._verify_decode` ladder
  (`header_file.py:191-276`) against the image-wide certificate tree
  (`cert_tree.py:385-406`), mirroring `ls_files_dict` `psptool.py:267-271`. Upstream
  for this REQ is PSPTool `241629b` (vringar/PSPTool `claude-main`, = master
  `edae097` + the decode-verified commit). This is the parity contract downstream
  content-addressing keys `sha256_plain` on.

## Acceptance criteria

- AC-1 (REQ-1..5,8,9): `cargo test -p psptool-ops --test list_micro` — 9 passed,
  0 failed, 0 ignored. Pins `list_default`/`list_verbose`/`list_json` text and
  JSON output over the PSP, BHD, and empty-directory micro-fixtures.
- AC-2 (REQ-2,3,4,5,9): `cargo test -p psptool-cli --test differential` — 54
  passed, 0 failed, 0 ignored. Every corpus ROM's directory address set and each
  entry's `index`/`address`/`size`/`sectionType` agree with reference PSPTool via
  this unit's `-E -j` JSON (the former #41/#60 ignores were cleared by the
  cross-ROM-echo accommodation and the master repin).
- AC-3 (REQ-10): `cargo test -p psptool-ops --test divergence_tertiary_generation`
  — `control_combo_reached_directory_carries_generation` passes, proving the
  render path stamps `Zen4Or5` for a combo-reached directory.
- AC-4 (REQ-11): the same suite's
  `divergence_tertiary_0x48_directory_carries_generation` and `_0x4a_` are now
  `#[test]` (un-ignored) and PASS — the tertiary-reached `$PL2` renders
  `Zen4Or5` from the block's `[20:24]` id, closing blocker #70.
- AC-5 (REQ-12): open — no green test exists; the placeholder string
  `AGESA_UNKNOWN` is emitted verbatim.
- AC-6 (REQ-13, REQ-14): `cargo test -p psptool-ops --test decode_verification`
  — 20 passed, 0 failed, 0 ignored. Synthetic RSA-signed images reach every
  ladder rung through `CertifyingKeys::from_blob` → `Entry::decode_verification`
  (incl. a `$KDB`-only certifying key, strict zlib, encrypted entries) and
  `ls_renders_verdicts_in_json_and_file_info` pins the JSON keys and the
  `verified(A1A1)`/`key_missing(DEDE)`/`sha256_ok` tags.
  `corpus_tally_matches_upstream_oracle` pins the per-basis tally over the 54
  corpus images against an oracle run of upstream `241629b` (4147 HeaderFiles →
  True 3159 = signature 3117 + plain 42; False 988 = signature-partial 295 +
  signature-unresolved 251 + signature-failed 376 + unverifiable 66), adjusted
  by the one documented entry-set delta (H12SSW9 cross-ROM echo): this unit
  lists 4148 → signature 3117, plain 42, signature-partial 295,
  signature-unresolved 251, signature-failed 377, unverifiable 66; every
  shared entry's verdict and File-Info tag agrees with upstream. The three
  zero-size records upstream parses as HeaderFiles (`header_file.py:32-33`)
  are HeaderFiles here too (#90).

## REQ status table

| REQ | Status | Evidence |
|---|---|---|
| REQ-1 (three-table text layout) | SHIPPED | `render_text` `list.rs:108-119` composes `render_rom_table` (`list.rs:121-131`, cols `["ROM","Addr","Size","FET","AGESA"]`), `render_directory_header_table` (`list.rs:133-167`, cols `["","Directory","Addr","Generation","Magic","Secondary Directory"]`) and `render_entries_table` (`list.rs:169-213`, `basic_fields` `list.rs:170-182`); mirrors `PSPTool.ls` (`psptool.py:68` `PrettyTable(['ROM','Addr','Size','FET','AGESA'])`, `:79`, `:103`). Consumer: `psptool-cli/src/cmds/list.rs:45` (`list_verbose`) / `:47` (`list_default`). Verification: `list_micro` `list_default_psp_micro`/`list_verbose_psp_micro`/`list_default_bhd_micro` (9 passed). |
| REQ-2 (JSON directory object) | SHIPPED | `list_json` `list.rs:80-102` pushes `json!({"directory","address","magic","secondaryAddresses","entries"})` per directory; mirrors `ls_json` (`psptool.py:208-213` `{'directory','address','magic','secondaryAddresses'}`). Consumer: `psptool-cli/src/cmds/list.rs:41` (`list_json`). Verification: `differential.rs:351-393` reads `address`/`entries`; `list_micro` `list_json_psp_micro`. |
| REQ-3 (entry structural projection) | SHIPPED | `entry_to_json` `list.rs:306-347` inserts `index`/`address`/`size`/`sectionType` (`list.rs:309-315`); mirrors `ls_files_dict` (`psptool.py:246-250`). Consumer: `psptool-cli/src/cmds/list.rs:41`. Verification: `differential.rs:377-389` (`entry_diff` `:247-271`) — `cargo test -p psptool-cli --test differential` 50 passed, 0 failed. |
| REQ-4 (readable type name) | SHIPPED | `readable_type` `types.rs:196-213` (`"<NAME>~0x<hh>"`; BIOS `0x61`→`APOB`, `0x62`→`BIOS`; unknown `"0x<hh>"`), called `list.rs:218`/`:314`; mirrors `File.get_readable_type` as consumed at `psptool.py:173`/`:250`. Consumer: `psptool-cli/src/cmds/list.rs:41`. Verification: `differential.rs:264-269` compares `sectionType` (50 passed). Upstream-parity map-coverage gap tracked #39; one corpus ROM's `0x5c` name is a version-skew ignore (#60, §Version-skew). |
| REQ-5 (combo lists no files) | SHIPPED | `entries_for_directory` `list.rs:353-361` returns `Vec::new()` for `Directory::Combo`; mirrors the reference listing only `directory.files` for leaf dirs (`psptool.py:95-96`). Consumer: `psptool-cli/src/cmds/list.rs:41`/`:47`. Verification: `differential.rs:354-359` drops `COMBO_MAGICS` (`2PSP`/`2BHD`) so combos line up; 50 passed. |
| REQ-6 (magic/ID + version) | SHIPPED (self-oracle) | `magic_id_string` `list.rs:405-422` (header magic or pubkey certifying-id, `ascii_or_hex_4` `list.rs:508-518`) and `version_string` `list.rs:424-432`; mirror `get_readable_magic`/`get_readable_version` (`psptool.py:176-177`/`:251-252`). Consumer: `psptool-cli/src/cmds/list.rs:41`/`:47`. Verification: `list_micro` snapshots — NOT differentially compared (`differential.rs` module doc: `magic`/`version` are tolerated JSON-shape divergences). |
| REQ-7 (file info tokens) | SHIPPED | `info_list` `list.rs:572-613` emits `compressed`, `signature_tag`, `encrypted`, `checksum_tag` (sha256 else sha384, from the `ChecksumCheck` the decode verification picked), `pubkey_usage`, `destination(..)` — no bare `signed`/`sha256`/`sha384` token — mirroring `ls_files` (`psptool.py:113-140`: `info.append(f'verified(...)')`, `info.append(f'sha256_ok')`, …). Consumer: `psptool-cli/src/cmds/list.rs:55`/`:53`/`:49`. Verification: `divergence_list_text_headerfile_cells.rs::divergence_file_info_has_only_upstream_outcome_tokens` (synthetic, `key_missing(0000), sha256_ok`) and `::divergence_corpus_headerfile_file_info_matches_reference` (every HeaderFile row of the reference `ls -E -v` table over the 54-image corpus) — both un-ignored by #120; `list_micro` + `psptool-cli` `synthetic__list_*` snapshots. JSON `info` is a differential-tolerated key (upstream `ls_files_dict` tokens differ, `psptool.py:231-244`). Non-HeaderFile tokens upstream adds (`soft_fuse`, `patch_level`, …) are #114. |
| REQ-8 (verbose extension columns) | SHIPPED | `build_entry_row` verbose branch `list.rs:238-259` (`flags`/`MD5`/`size_signed`/`size_full`/`size_packed`/`load_addr`, `body_md5_hex` `list.rs:496-506`) and `entry_to_json` verbose branch `list.rs:330-343` (`md5`/`flags`/`sizes`/`load_addr`); mirror `verbose_fields` + HeaderFile block (`psptool.py:104`/`:183-189`/`:260-266`). `size_packed` / `sizes.packed` is `packed_size` (`list.rs:520`): upstream's normalised `HeaderFile.rom_size` — a header `rom_size` of 0 reads as the buffer size, the directory-declared entry grown to the 0x100 header (`header_file.py:72-73`, `:32-33`; #118). Consumer: `psptool-cli/src/cmds/list.rs:45` (`list_verbose`) / `:41` (`list_json` with `args.verbose`). Verification: `list_micro` `list_verbose_psp_micro`/`list_json_verbose_psp_micro`; `divergence_headerfile_list_values.rs` `divergence_size_packed_normalises_zero_rom_size` / `divergence_json_sizes_packed_normalises_zero_rom_size` (synthetic) and `divergence_corpus_sizes_packed_matches_reference` (every corpus HeaderFile's packed size equals the reference's `rom_size`; 147 differed before #118). |
| #86/#87 (sparse `flags`/`MD5`) | SHIPPED | The richer default (populated `flags` + full 32-char lowercase `MD5`) is the default. Opt-in `RomListing::sparse` (`list.rs`) drives the `build_entry_row` sparse branch: `flags` → `''` (`psptool.py:179`), `MD5` → `body_md5_short_upper` = `md5()[:4].upper()` (`psptool.py:180`). Consumer: the CLI `list` subcommand sets `sparse` from the `--sparse` flag (`psptool-cli/src/cli.rs`, `ListArgs::sparse`) OR the `PSPTOOL_LS_SPARSE` env var (`psptool-cli/src/cmds/list.rs`). Verification: `divergence_list_columns.rs::divergence_verbose_flags_column_is_empty_upstream` + `::divergence_verbose_md5_column_truncated_and_uppercased` (un-ignored, sparse mode) + `::default_mode_flags_populated_and_md5_full_lowercase` (richer default). |
| REQ-9 (secondary-directory resolution) | SHIPPED | `secondary_addresses` `list.rs:580-607` resolves secondary-directory-pointer entries through the directory address mode (`collect_secondary_psp`/`_bios` `list.rs:609-635`); mirrors `directory.secondary_directory_offsets` (`directory.py:156-163`), printed `psptool.py:86`/`:212`. Consumer: `psptool-cli/src/cmds/list.rs:41`/`:47`. Verification: `list_micro` `fet_pointer_addresses_are_byte_stable`; differential combo-drop keys on it. |
| REQ-10 (generation, combo-reached) | SHIPPED | `directory_generation` `list.rs:531-567`: combo branch (`:533-544`) joins distinct `zen_label`s; PSP/BIOS branch resolves `DirectoryProvenance::ComboEntry` back to the combo entry's generation (`:545-564`, `zen_label` `list.rs:569-577`); mirrors `directory.zen_generation` (`psptool.py:84`) combo threading (`directory.py:57-63`). Consumer: `psptool-cli/src/cmds/list.rs:47`. Verification: `divergence_tertiary_generation.rs::control_combo_reached_directory_carries_generation` (passes — renders `Zen4Or5`). |
| REQ-11 (generation, tertiary-reached `$PL2`) | SHIPPED | `directory_generation` `list.rs:545-580` handles `DirectoryProvenance::Tertiary { generation, .. }` by rendering `generation.zen_generation()` via `zen_label` (`list.rs:571-576`); the id is read from `block[20:24]` in core `tertiary_actual_offset` (`directory.rs:864-869`) and attached to the walk result at `directory.rs:727-731`/`788-792` — mirrors upstream `directory.py:89`/`94`/`98`/`124` (block[20:24] → created dir's `zen_generation`) printed at `psptool.py:84`. Consumer: `psptool-cli/src/cmds/list.rs:47` (`list_default`). Verification: `divergence_tertiary_generation.rs::divergence_tertiary_0x48/0x4a_directory_carries_generation` (both now `#[test]`, pass — render `Zen4Or5`) + control still green. |
| REQ-12 (AGESA version) | NOT-STARTED | open blocker #75. `render_rom_table` `list.rs:128` emits the `AGESA_UNKNOWN` placeholder (const `list.rs:61`) where `psptool.py:74` prints `rom.agesa_version`; the core parse for the AGESA string is not exposed on `RomListing`. Text-only column, not gated by the differential JSON oracle. |
| REQ-13 (sig/sha verify result) | SHIPPED | `info_list` (`list.rs:571`) pushes `signature_tag` (`list.rs:625`: `verified(XXXX)`/`veri-failed(XXXX)`/`key_missing(XXXX)`, `XXXX` = first two certifying-id bytes upper-case hex per `KeyId.magic` `crypto.py:369-371`) and `checksum_tag` (`list.rs:639`: `sha256_ok`/`sha256_inconsistent`/`sha384_ok`/`sha384_inconsistent`) from one `Entry::decode_verification` pass (core `body.rs:899`) per `psptool.py:116-140`. A verification that cannot run renders `invalid_sig(XXXX)` (`psptool.py:124-125`; upstream's `ls` would propagate the exception). Consumer: `psptool-cli/src/cmds/list.rs:55`/`:53`/`:49`. Verification: `decode_verification.rs::ls_renders_verdicts_in_json_and_file_info`; corpus File-Info tags agree with upstream `ls_files` logic on every shared entry (3409 verified, 377 veri-failed, 251 key_missing, 141 sha256_ok, 3 sha256_inconsistent). `info` stays a differential-tolerated key. Closes #76. |
| REQ-14 (decode-verified JSON bit) | SHIPPED | `entry_to_json` (`list.rs:447`) inserts `decodeVerified`/`decodeVerificationMethod` for every HeaderFile-class entry, non-verbose included, per `psptool.py:267-271` (`241629b`). The ladder is core `HeaderEntry::verify_decode` (`body.rs:937`, `header_file.py:198-243`) behind `Entry::decode_verification` (`body.rs:899`), resolving keys through `CertifyingKeys::from_blob` (`body.rs:801`, `cert_tree.py:385-397`: PubkeyFile keys + every `$KDB` key-store key, `key_store_file.py:140-253`) built once per listing by `Verifier::new` (`list.rs:111`). `DecodeVerification` exposes `decode_verified()`/`decode_verification_method()`/`plaintext_identity_ok()` (`header_file.py:245-276`) to library consumers. Consumer: `psptool-cli/src/cmds/list.rs:49`. Verification: AC-6. Closes #89. |

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
(`directory.rs:545-548`) to the combo entry's generation. Tertiary-reached
(`0x48`/`0x4A`) directories arrive as `DirectoryProvenance::Tertiary { generation
}` (`directory.rs:555-570`) — core `tertiary_actual_offset` reads the block's
`[20:24]` PSP-ID (`directory.rs:864-869`, upstream `directory.py:89`/`94`) and the
walk attaches it (`directory.rs:727-731`/`788-792`), so the function renders the
same `zen_label` the combo path does (REQ-11 / #70, closed). This is the same
routing wall #66 hit for `replace.rs`, which is why list.rs was routed.

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

- `cargo test -p psptool-cli --test differential` — **54 passed, 0 failed, 0
  ignored**. The route's declared `parity_ops` oracle: directory address sets and
  per-entry `index`/`address`/`size`/`sectionType` agree with reference PSPTool via
  this unit's `-E -j` JSON.
- `cargo test -p psptool-ops --test decode_verification` — **20 passed, 0 failed,
  0 ignored** (AC-6): the REQ-13/REQ-14 ladder, File-Info and JSON pins plus the
  corpus tally against upstream `241629b`.
- `cargo test -p psptool-ops --test list_micro` — **9 passed, 0 failed, 0
  ignored**. Self-oracle snapshots of `list_default`/`list_verbose`/`list_json`
  over PSP, BHD, and empty-directory micro-fixtures; the pin for the text-table
  and JSON-shape REQs the differential does not read (REQ-1, REQ-6, REQ-7, REQ-8).
- `cargo test -p psptool-ops --test divergence_tertiary_generation` — **3 passed,
  0 ignored**. `control_combo_reached_directory_carries_generation` passes
  (REQ-10). `divergence_tertiary_0x48/0x4a_directory_carries_generation` now pass
  (REQ-11 fix landed — per goal.md R-DEFER-3 they moved from `#[ignore]` to
  `#[test]` when the fix landed, and now serve as permanent regression coverage).
- `cargo test -p psptool-ops --test divergence_list_columns` — all `#[test]`s
  pass, 0 ignored. The #86 (`flags` empty) and #87 (`MD5` `md5()[:4].upper()`)
  pins render upstream-exact in SPARSE mode (`RomListing::sparse`); the richer
  default is pinned by `default_mode_flags_populated_and_md5_full_lowercase`.
  Sparse is opt-in via the CLI `--sparse` flag / `PSPTOOL_LS_SPARSE` env var, so
  the differential (default richer mode) is unaffected.
- `cargo test -p psptool-ops --test divergence_list_text_headerfile_cells` —
  the #120 pins (REQ-7) pass: the synthetic HeaderFile row and every
  HeaderFile row of the reference `ls -E -v` table over the corpus have
  upstream's File Info. The #121 KeyStoreFile size-column pins stay ignored.
- `cargo test -p psptool-ops --lib` — 50 passed, 0 failed, 0 ignored (the crate's
  own suite is green; `list.rs` itself carries no in-file unit tests — its oracles
  are the integration suites above).

Open prerequisite blocker for the NOT-STARTED REQ: **#75** (REQ-12, AGESA
version). (#70 and #76 are closed: REQ-11 and REQ-13 are SHIPPED.)
