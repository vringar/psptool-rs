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
  (`ls_files_dict` `psptool.py:246-250`). `size` (and the text `Size` column,
  `psptool.py:172`) is upstream's `file.buffer_size`: for a HeaderFile /
  KeyStoreFile the buffer re-sized to the normalised header `rom_size`
  (`header_file.py:72-75`, `:104-105`), which may be shorter or longer than the
  directory-declared entry; for every other file the entry itself.
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
  (`psptool.py:104`/`:183-189`, `:260-266`). The four text size cells are filled
  only for an exact `HeaderFile` (`type(file) is HeaderFile`, `psptool.py:183`),
  not its `KeyStoreFile` subclass; the JSON `sizes` include both (`issubclass`,
  `psptool.py:260`).
- REQ-9: **Secondary-directory address resolution.** The `Secondary Directory`
  column and JSON `secondaryAddresses` list the flash offsets of
  secondary-directory-pointer entries, resolved through the directory's address
  mode, mirroring `directory.secondary_directory_offsets`
  (`directory.py:156-163`, printed at `psptool.py:86`/`:212`).
- REQ-10: **Generation column (combo threading).** The `Generation` column of a
  `$PSP`/`$BHD`/`$PL2`/`$BL2` directory shows upstream's `directory.zen_generation`
  (`psptool.py:84`): the generation of every combo entry pointing at it
  (`fet.py:79-84`), inherited by the L2 directories its `0x40`/`0x49`/`0x70`
  pointers reach (`directory.py:81-82`), accumulated when several combo entries
  or parents reach one directory and cascaded to its L2 directories
  (`directory.py:61-62`, `:243-249`). Each generation is upstream's label
  `'<Zen 1|Zen 2|Zen 3|Zen 4|Zen 4/5|unknown> (PSP ID 0x..)'` (`fet.py:117-123`,
  `directory.py:34-48`), one per line as upstream's `'\n'`-joined string prints
  in PrettyTable. A directory only FET slots reach has no generation: upstream
  keeps `zen_generation = None` (`fet.py:89`, `directory.py:58`/`:124`), its L2
  directories inherit it, and PrettyTable prints `None`. A combo directory
  (which upstream does not list) shows the distinct labels of its entries.
- REQ-11: **Generation column for tertiary-reached (`$PL2`) directories.** A
  directory reached through the Zen 4+ tertiary double-indirection (entry types
  `0x48`/`0x4A`) must show the Zen generation stamped in the tertiary block's
  `block[20:24]` PSP-ID, mirroring `directory.py:86-98` (which sets
  `zen_generation='Zen 4/5 (PSP ID 0x..)'`) as printed at `psptool.py:84`, in the
  REQ-10 label format; the directory's own L2 directories inherit it.
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
- AC-3 (REQ-10): `cargo test -p psptool-ops --test divergence_generation_threading`
  — 10 passed, 0 ignored: a combo-reached `$PSP` carries its entry's generation,
  `$PL2`/`$BL2` inherit it (#116), a `$PSP` two combo entries share lists both
  and cascades both to its `$PL2` (#117), the label is `Zen 3 (PSP ID
  0xbc0c0140)` (#57), a FET-only `$PSP` and its `$PL2` render `None` (#122), and
  the three corpus pins compare every directory's generation tokens and exact
  cell text with the live reference.
- AC-4 (REQ-11): `cargo test -p psptool-ops --test divergence_tertiary_generation`
  — 3 passed: the tertiary-reached `$PL2` renders `Zen 4/5 (PSP ID 0xbc0d0300)`
  from the block's `[20:24]` id via `0x48` and `0x4A` (#70), and the combo control
  renders the same label.
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
| REQ-3 (entry structural projection) | SHIPPED | `entry_to_json` `list.rs:426` inserts `index`/`address`/`size`/`sectionType`; mirrors `ls_files_dict` (`psptool.py:246-250`). `size` (JSON `list.rs:438`, text `Size` `list.rs:315`) is `file_size` (`list.rs:544`), upstream's `file.buffer_size` (`psptool.py:172`/`:249`): `packed_size`, the normalised header `rom_size`, for a HeaderFile / KeyStoreFile (`header_file.py:104-105`; #111, Milan ABL0 `0x3a0` of a `0x864f0` entry #115), the entry body otherwise. Consumer: `psptool-cli/src/cmds/list.rs:49`. Verification: `differential.rs` `entry_diff` (`:246`) + the `size` check in `compare_structure` (`:504`) — strict for every entry since #111 (the HeaderFile tolerance is gone; only the dedup-echo accommodation remains) — `cargo test -p psptool-cli --test differential` 54 passed, 0 failed; `divergence_headerfile_list_values.rs::divergence_headerfile_size_is_its_buffer_size` (shrunk, grown, zero `rom_size`, text + JSON). |
| REQ-4 (readable type name) | SHIPPED | `readable_type` `types.rs:196-213` (`"<NAME>~0x<hh>"`; BIOS `0x61`→`APOB`, `0x62`→`BIOS`; unknown `"0x<hh>"`), called `list.rs:218`/`:314`; mirrors `File.get_readable_type` as consumed at `psptool.py:173`/`:250`. Consumer: `psptool-cli/src/cmds/list.rs:41`. Verification: `differential.rs:264-269` compares `sectionType` (50 passed). Upstream-parity map-coverage gap tracked #39; one corpus ROM's `0x5c` name is a version-skew ignore (#60, §Version-skew). |
| REQ-5 (combo lists no files) | SHIPPED | `entries_for_directory` `list.rs:353-361` returns `Vec::new()` for `Directory::Combo`; mirrors the reference listing only `directory.files` for leaf dirs (`psptool.py:95-96`). Consumer: `psptool-cli/src/cmds/list.rs:41`/`:47`. Verification: `differential.rs:354-359` drops `COMBO_MAGICS` (`2PSP`/`2BHD`) so combos line up; 50 passed. |
| REQ-6 (magic/ID + version) | SHIPPED (self-oracle) | `magic_id_string` `list.rs:405-422` (header magic or pubkey certifying-id, `ascii_or_hex_4` `list.rs:508-518`) and `version_string` `list.rs:424-432`; mirror `get_readable_magic`/`get_readable_version` (`psptool.py:176-177`/`:251-252`). Consumer: `psptool-cli/src/cmds/list.rs:41`/`:47`. Verification: `list_micro` snapshots — NOT differentially compared (`differential.rs` module doc: `magic`/`version` are tolerated JSON-shape divergences). |
| REQ-7 (file info tokens) | SHIPPED | `info_list` `list.rs:608-649` emits `compressed`, `signature_tag`, `encrypted`, `checksum_tag` (sha256 else sha384, from the `ChecksumCheck` the decode verification picked), `pubkey_usage`, `destination(..)` — no bare `signed`/`sha256`/`sha384` token — mirroring `ls_files` (`psptool.py:113-140`: `info.append(f'verified(...)')`, `info.append(f'sha256_ok')`, …). Consumer: `psptool-cli/src/cmds/list.rs:55`/`:53`/`:49`. Verification: `divergence_list_text_headerfile_cells.rs::divergence_file_info_has_only_upstream_outcome_tokens` (synthetic, `key_missing(0000), sha256_ok`) and `::divergence_corpus_headerfile_file_info_matches_reference` (every HeaderFile row of the reference `ls -E -v` table over the 54-image corpus) — both un-ignored by #120; `list_micro` + `psptool-cli` `synthetic__list_*` snapshots. JSON `info` is a differential-tolerated key (upstream `ls_files_dict` tokens differ, `psptool.py:231-244`). Non-HeaderFile tokens upstream adds (`soft_fuse`, `patch_level`, …) are #114. |
| REQ-8 (verbose extension columns) | SHIPPED | `build_entry_row` verbose branch `list.rs:336-366` (`flags`/`MD5`/`size_signed`/`size_full`/`size_packed`/`load_addr`) and `entry_to_json` verbose branch `list.rs:467-481` (`md5`/`flags`/`sizes`/`load_addr`); mirror `verbose_fields` + HeaderFile block (`psptool.py:104`/`:180`/`:183-189`/`:260-266`). `MD5` / `md5` is `entry_md5` (`list.rs:695`), the digest of upstream's `file.md5()`: the file buffer for a plain/pubkey/microcode entry (`file.py:380-383`), and for a HeaderFile / KeyStoreFile its data region `self.body` = `[0x100, rom_size - signature_len)` of the HeaderFile buffer (`header_file.py:106`, `:312-315`; the signature is reserved when signed, a KeyStoreFile always is, `key_store_file.py:62-64`; #119). `size_packed` / `sizes.packed` is `packed_size` (`list.rs:532`): upstream's normalised `HeaderFile.rom_size` — a header `rom_size` of 0 reads as the buffer size, the directory-declared entry grown to the 0x100 header (`header_file.py:72-73`, `:32-33`; #118). The four text size cells are filled only for `EntryClass::Header` — `type(file) is HeaderFile` (`psptool.py:183-191`) excludes a KeyStoreFile, whose JSON `sizes` stay (`issubclass`, `psptool.py:260`; #121). Consumer: `psptool-cli/src/cmds/list.rs:53` (`list_verbose`) / `:49` (`list_json` with `args.verbose`). Verification: `list_micro` `list_verbose_psp_micro`/`list_json_verbose_psp_micro`; `divergence_headerfile_list_values.rs` — `divergence_size_packed_normalises_zero_rom_size` / `divergence_json_sizes_packed_normalises_zero_rom_size` / `divergence_sparse_md5_hashes_headerfile_body` (synthetic) and `divergence_corpus_sizes_packed_matches_reference` / `divergence_corpus_headerfile_md5_matches_reference` (every corpus HeaderFile's packed size and `md5()[:4].upper()` equal the reference's; 147 and 4147 differed before #118 / #119). |
| #86/#87 (sparse `flags`/`MD5`) | SHIPPED | The richer default (populated `flags` + full 32-char lowercase `MD5`) is the default. Opt-in `RomListing::sparse` (`list.rs`) drives the `build_entry_row` sparse branch: `flags` → `''` (`psptool.py:179`), `MD5` → the first four characters of `entry_md5`, upper-cased = `md5()[:4].upper()` (`psptool.py:180`); the richer default prints all 32 characters of the same digest. Consumer: the CLI `list` subcommand sets `sparse` from the `--sparse` flag (`psptool-cli/src/cli.rs`, `ListArgs::sparse`) OR the `PSPTOOL_LS_SPARSE` env var (`psptool-cli/src/cmds/list.rs`). Verification: `divergence_list_columns.rs::divergence_verbose_flags_column_is_empty_upstream` + `::divergence_verbose_md5_column_truncated_and_uppercased` (un-ignored, sparse mode) + `::default_mode_flags_populated_and_md5_full_lowercase` (richer default). |
| REQ-9 (secondary-directory resolution) | SHIPPED | `secondary_addresses` `list.rs:580-607` resolves secondary-directory-pointer entries through the directory address mode (`collect_secondary_psp`/`_bios` `list.rs:609-635`); mirrors `directory.secondary_directory_offsets` (`directory.py:156-163`), printed `psptool.py:86`/`:212`. Consumer: `psptool-cli/src/cmds/list.rs:41`/`:47`. Verification: `list_micro` `fet_pointer_addresses_are_byte_stable`; differential combo-drop keys on it. |
| REQ-10 (generation, combo threading) | SHIPPED | core `walk_directories` threads `DirectoryRef::generations` (`psptool-core/src/directory.rs:580`) like `create_directories_if_not_exist` / `update_zen_generation`: `Walk::visit` (`directory.rs:604`) records a combo entry's `psp_generation` on the directory it reaches (`fet.py:79-84`) and merges ids into a directory reached again (`directory.py:61-62`), `Walk::merge` (`directory.rs:634`) cascades new ids along the recorded L2 edges (`directory.py:243-249`), `Walk::visit_l2` (`directory.rs:649`) gives an L2 directory its parent's ids (`directory.py:81-82`). `directory_generation` (`list.rs:758`) renders them with `generation_label` (`list.rs:784`, `fet.py:117-123` / `directory.py:34-48`), one per line through the multi-line cells of `table.rs` (PrettyTable `valign` top). Consumer: `psptool-cli/src/cmds/list.rs:55`/`:53`. Verification: `divergence_generation_threading.rs` (10 tests: the 7 #116/#117/#57 pins un-ignored, incl. two live-reference corpus pins over every corpus directory, and the two #122 pins) + core `walk_directories_threads_combo_generations_to_l2` / `walk_directories_via_combo_to_psp` + `table::tests::multi_line_cells_span_one_text_row_per_line`. A directory only FET slots reach renders `None` (`NO_GENERATION`, upstream `str(None)`; #122), pinned by `divergence_fet_only_directory_generation_is_none` (synthetic FET-slot `$PSP` + its `$PL2`) and `divergence_corpus_generation_cell_text_matches_reference` (exact cell text = the reference's `str(zen_generation)` for every directory of the corpus). |
| REQ-11 (generation, tertiary-reached `$PL2`) | SHIPPED | the walk's tertiary branch (`psptool-core/src/directory.rs:777-797`) records the `block[20:24]` id read by `tertiary_actual_offset` (`directory.rs:829`, `directory.py:89`/`94`) on the reached directory (`directory.py:98`/`124`); `directory_generation` (`list.rs:758`) renders it as `Zen 4/5 (PSP ID 0x..)`, printed at `psptool.py:84`. Consumer: `psptool-cli/src/cmds/list.rs:55` (`list_default`). Verification: `divergence_tertiary_generation.rs` (3 passed: `0x48`/`0x4a` pins + combo control, label `Zen 4/5 (PSP ID 0xbc0d0300)`). |
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

**Generation resolution.** The ids come from the core walk: `walk_directories`
threads them through the directory graph into `DirectoryRef::generations`
(`directory.rs:580`) the way upstream's `create_directories_if_not_exist` /
`update_zen_generation` thread `zen_generation` (`directory.py:58-101`,
`:243-249`) — a combo entry's id, a tertiary block's `[20:24]` id
(`tertiary_actual_offset`, `directory.rs:829`), an L2 parent's ids, merged on
every further visit and cascaded along L2 edges. `directory_generation`
(`list.rs:758`) is the one place the `Generation` cell is rendered: one
`generation_label` (`list.rs:784`) per id and line. The set of ids equals
upstream's; their order is the walk's, which is upstream's depth-first order
unless one directory is reached from two different parents (no corpus image
has such a directory: the exact cell text matches the reference for all 433
directories of the vendor corpus and the five local Zen 4/5 images).

**Address-mode reuse.** Secondary-pointer resolution builds a `ResolveContext`
from `rom_size`/`directory_base`/`rom_origin` (`list.rs:583-588`) and defers to the
core `AddressMode` resolver, so the rendering unit never re-implements address
arithmetic — it reuses the `.design/psptool-core/address.md` primitive.

## Version-skew note (blocker #61, resolved)

The differential oracle and the translation source are the same PSPTool
revision (`241629b`, `default.nix`), so no rendering string of this unit is a
version-skew artifact any more. The `Generation` labels follow that revision
(`Zen 3 (PSP ID 0xbc0c0140)`, #57) and are compared with the live reference by
the `divergence_generation_threading.rs` corpus pins. #55 (bootloader-version
back-fill for single-FET EPYC images, upstream PR #85) and #39 (type-name-map
coverage) remain open on the same rendering surface.

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
- `cargo test -p psptool-ops --test divergence_generation_threading` — **10
  passed, 0 ignored** (REQ-10): L2 inheritance (#116), accumulation + cascade
  (#117), upstream label format (#57), `None` for a FET-only directory (#122),
  and the three live-reference corpus pins (tokens, exact cell text).
- `cargo test -p psptool-ops --test divergence_headerfile_list_values` — 7
  passed, 0 ignored (REQ-8: #118 packed size, #119 HeaderFile MD5, incl. two
  live-reference corpus pins; REQ-3: #111/#115 HeaderFile `Size`/`size`).
- `cargo test -p psptool-ops --test divergence_list_columns` — all `#[test]`s
  pass, 0 ignored. The #86 (`flags` empty) and #87 (`MD5` `md5()[:4].upper()`)
  pins render upstream-exact in SPARSE mode (`RomListing::sparse`); the richer
  default is pinned by `default_mode_flags_populated_and_md5_full_lowercase`.
  Sparse is opt-in via the CLI `--sparse` flag / `PSPTOOL_LS_SPARSE` env var, so
  the differential (default richer mode) is unaffected.
- `cargo test -p psptool-ops --test divergence_list_text_headerfile_cells` —
  the #120 pins (REQ-7) pass: the synthetic HeaderFile row and every
  HeaderFile row of the reference `ls -E -v` table over the corpus have
  upstream's File Info; the #121 pins (REQ-8) leave a KeyStoreFile row's four
  size cells empty, synthetic and against every corpus key store.
- `cargo test -p psptool-ops --lib` — 50 passed, 0 failed, 0 ignored (the crate's
  own suite is green; `list.rs` itself carries no in-file unit tests — its oracles
  are the integration suites above).

Open prerequisite blocker for the NOT-STARTED REQ: **#75** (REQ-12, AGESA
version). (#70 and #76 are closed: REQ-11 and REQ-13 are SHIPPED.)
