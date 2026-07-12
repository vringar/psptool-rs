# Address-mode arithmetic and ROM masking (§1.1 / §1.3 / §2.1 / §2.2)

<!--
tier: 3-component
status: draft
baseline-commit: 50da831be696c2dba8c9d05df2e21ccd18111324
upstream-paths:
  - /tmp/psptool-ref/psptool/entry.py
  - /tmp/psptool-ref/psptool/directory.py
-->

## Summary

`crates/psptool-core/src/address.rs` is the arithmetic core shared by every
pointer in a PSP firmware image: it converts a raw on-disk pointer (a directory
entry's `offset`, a FET slot, or a combo-entry pointer) into a byte offset into
the loaded blob. It mirrors the two upstream address-resolution surfaces:
`DirectoryEntry.file_offset()` (`entry.py:38-70`) with its entry-level
`address_mode` property (`entry.py:132-134`, `(self.rsv0 >> 30) & 3`), and the
directory-scoped `Directory.address_mode` property (`directory.py:186-193`). The
`addr_mask = rom_size - 1` masking that upstream keeps on the `Rom` object
(`rom.py:14`, out of this route) is carried here by the [`RomSize`] type and
exercised at its usage sites `entry.py:56` (`rom_size = ...rom.addr_mask + 1`)
and `entry.py:60` (`self.offset & ...rom.addr_mask`).

Upstream folds address resolution into `DirectoryEntry` / `Directory` methods
that reach out to `self.parent_directory.rom` (Python's ambient object graph).
The Rust mirror follows R-DEV-4: it lifts the arithmetic into a pure, dependency-
free module of newtypes (`FlashOffset`, `Address`, `RomSize`) and an
[`AddressMode`] enum, and threads the ROM parameters explicitly through a
[`ResolveContext`]. The soft-fuse-chain special case (`entry.py:40-42`,
`type == 0xb`) is NOT modelled here — it is an entry-record concern handled by
`entry.rs::resolve_body` (`.design/psptool-core/entry.md` REQ-4).

## Requirements

- REQ-1: **Pointer/offset/ROM-size vocabulary.** Provide distinct newtypes so a
  raw 32-bit on-disk pointer (`Address`), a 64-bit byte offset into the loaded
  blob (`FlashOffset`), and a validated ROM size (`RomSize`) cannot be confused
  by a widening/narrowing slip (R-CODE-5). The raw pointer field upstream is a
  32-bit `struct.unpack('<I', self[8:12])` (`entry.py:113-114`) and byte offsets
  index a flat buffer; `RomSize` encodes the `{8, 16, 32} MiB` power-of-two ROMs
  that `rom.py`/`blob.py` select.
- REQ-2: **`addr_mask = rom_size - 1`.** `RomSize` exposes the mask upstream
  computes as `rom_size - 1`. Mirrors the usage `entry.py:56`
  (`rom_size = self.parent_directory.rom.addr_mask + 1`) and `entry.py:60`
  (`return self.offset & self.parent_directory.rom.addr_mask`); the defining
  assignment is `rom.py:14` (`self.addr_mask = rom_size - 1`, cited by the
  sibling FET route `.design/psptool-core/fet.md`).
- REQ-3: **Entry-level 2-bit address mode `rsv0[31:30]`.** Decode an entry's
  address-mode override from the top two bits of its `rsv0` field into a
  four-valued enum (`00` x86-physical, `01` flash-offset, `10` directory-
  relative, `11` partition-relative), ignoring the low 30 bits, with a canonical
  round-trip encoding. Mirrors `entry.py:132-134`
  (`def address_mode: return (self.rsv0 >> 30) & 3`) and the mode-legend comment
  `entry.py:128-131`.
- REQ-4: **Directory-scoped address mode from `additional_info`.** Decode the
  directory's address mode from its `additional_info` u32: bit 31 is a version
  flag; version 1 reads bits `[25:24]`, version 0 ("v2") reads bits `[30:29]`.
  Mirrors `directory.py:186-193` (`version = (info >> 31) & 1; if version == 1:
  return (info >> 24) & 3 else: return (info >> 29) & 3`).
- REQ-5: **Address-mode resolution (`file_offset()`).** Convert a raw `Address`
  to a `FlashOffset` under the directory-scoped mode, consulting the entry-level
  override only when the directory mode is `10`/`11`:
  mode `00` masks with `addr_mask` and forces the low-16 MiB window
  (`& 0x00FF_FFFF`) when the pointer is `> 0xFF00_0000` and the ROM is `> 16 MiB`;
  mode `01` is a ROM-relative flash offset; modes `10`/`11` add the directory
  base. Mirrors `entry.py:44` (`addr_mode = self.parent_directory.address_mode`),
  `entry.py:47-48` (`if addr_mode == 2 or addr_mode == 3: addr_mode =
  self.address_mode`), `entry.py:50-60` (mode-0 masking + >16 MiB window),
  `entry.py:61-63` (mode 1), and `entry.py:64-70` (modes 2/3
  `return self.parent_directory.buffer_offset + self.offset`).
- REQ-6: **ROM-origin (capsule-envelope) shift.** Resolution returns a *file*
  offset into the input blob, not a ROM-flash offset: a `rom_origin` addend is
  applied so capsule-wrapped images (envelope bytes before the ROM, §1.1) resolve
  their directories to the correct file position. Upstream's `Rom` object stores
  the ROM at `rom_offset = fet_position - fet_offset` (`blob.py`, FET route) so
  its `file_offset()` arithmetic is already ROM-local; the Rust mirror threads
  `rom_origin` explicitly because the resolver operates on the whole-blob buffer.
- REQ-7: **FET sentinel set.** Recognise the reserved slot values that are
  preserved by position but never dereferenced. The directory-discovery empty
  markers are `entry.py`-adjacent: `directory.py:108`
  (`if magic == b'\xff\xff\xff\xff' or magic == b'\x00\x00\x00\x00'`) treats the
  all-ones and all-zeros pointers as empty. The full three-element FET set
  (`{0x0, 0xFFFF_FFFE, 0xFFFF_FFFF}`) is the FET-slot contract documented by
  `.design/psptool-core/fet.md` (`fet.py:64`, read under that route).
- REQ-8: **Unified 32-bit address handling for PSP (16B) and BIOS (24B)
  entries.** Both entry families resolve their body from the *same* 32-bit
  `offset` field (`self[8:12]`) and the *same* `rsv0[31:30]` mode selector; the
  BIOS-only 8-byte `destination` (`self[16:24]`) is a memory load-target, not a
  flash-offset source, and is never fed into `file_offset()`. Mirrors
  `entry.py:136-137` (`class BiosDirectoryEntry(DirectoryEntry): ENTRY_SIZE =
  4 * 6`) inheriting `file_offset()`/`address_mode` unchanged, and
  `entry.py:142-144` (`def destination: struct.unpack('<Q', self[16:24])`) which
  `file_offset()` does not read. There is no 64-bit (`>>62`) address-mode path.

## Acceptance criteria

- AC-1 (REQ-1/REQ-2): `RomSize::new` accepts exactly `{8, 16, 32} MiB` and
  rejects non-power-of-two / out-of-range sizes; `addr_mask()` yields
  `0x007F_FFFF` / `0x00FF_FFFF` / `0x01FF_FFFF`. Pinned by
  `rom_size_constructors`, `rom_size_addr_mask`.
- AC-2 (REQ-3): `from_entry_rsv0` maps `rsv0[31:30] ∈ {00,01,10,11}` to the four
  modes and ignores the low bits; `from_bits`/`bits` round-trip. Pinned by
  `entry_rsv0_high_bits`, `address_mode_bits_roundtrip`,
  `address_mode_ignores_high_bits`.
- AC-3 (REQ-4): `from_additional_info` decodes v1 (`bits[25:24]`) and v2
  (`bits[30:29]`) and is insensitive to unused bits. Pinned by
  `additional_info_v1_decode`, `additional_info_v2_decode`,
  `additional_info_decode_ignores_unused_bits`.
- AC-4 (REQ-5): mode `00` resolves `0xFF15_8000 → 0x0015_8000` in a 16 MiB ROM
  and forces the low-16 MiB window in a 32 MiB ROM; mode `01` returns the raw
  offset; modes `10`/`11` add `directory_base`, and `resolve` (no entry override)
  returns `ResolveError::NeedsEntryMode` for a `10`/`11` directory mode; a `00`/
  `01` directory mode ignores any entry override. Pinned by
  `resolve_physical_x86_16mib`, `resolve_physical_x86_32mib_window`,
  `resolve_flash_offset`, `resolve_directory_modes_require_entry_override`,
  `resolve_with_entry_directory_relative`,
  `resolve_with_entry_partition_relative_treated_like_directory_relative`,
  `resolve_with_entry_when_dir_mode_does_not_defer`.
- AC-5 (REQ-6): with `rom_origin = 0x800`, mode `00` (`0xFF15_8000`) resolves to
  `0x0015_8800` and mode `01` (`0x0038_8000`) to `0x0038_8800`. Pinned by
  `resolve_physical_x86_with_capsule_envelope`,
  `resolve_flash_offset_with_capsule_envelope`.
- AC-6 (REQ-7): `is_fet_sentinel` is true for `{0x0, 0xFFFF_FFFE, 0xFFFF_FFFF}`
  and false for real pointers. Pinned by `fet_sentinels`.
- AC-7 (REQ-5/REQ-8, corpus parity): `corpus_roundtrip` is byte-exact on all 54
  supported ROMs. Byte-exact roundtrip requires that every directory and entry
  be located within its ROM window — i.e. that this resolver mapped each FET
  slot, PSP entry, and BIOS entry to the correct file offset for both the 16-byte
  and 24-byte entry families. A wrong mask, window, or `rom_origin` addend would
  land a directory/entry parse outside its bytes and break the model before the
  writer could reproduce the source.

## REQ status table

| REQ | Status | Evidence |
|---|---|---|
| REQ-1 (pointer/offset/ROM-size vocabulary) | SHIPPED | `FlashOffset(pub u64)` (`address.rs:14`), `Address(pub u32)` (`address.rs:92`), `RomSize` (`address.rs:50`) mirror upstream's 32-bit pointer `entry.py:113` (`struct.unpack('<I', self[8:12])`) and flat-buffer byte offsets. Non-test consumers: `fet.rs:72-77` (`detect_rom_layout` selects `RomSize::MIB_32/16/8`), `directory.rs:138` (`Address(u32::from_le_bytes(b[0x08..0x0C]…))`), `entry.rs:485` (`entry_offset: Address`), and `source.rs:63` (`FlashOffset(self.flash_offset)`). Verification: `rom_size_constructors` in the 146-test lib pass. |
| REQ-2 (`addr_mask = rom_size - 1`) | SHIPPED | `RomSize::addr_mask` (`address.rs:77`, `self.0 - 1`) mirrors `entry.py:56` (`rom_size = …rom.addr_mask + 1`) / `entry.py:60` (`self.offset & …rom.addr_mask`) and the defining `rom.py:14`. Non-test consumer: `normalise_physical` (`address.rs:286`, `raw & rom_size.addr_mask()`) reached from `directory.rs:608` and `entry.rs:503`. Verification: `rom_size_addr_mask` (16/8/32 MiB masks) in the 146-test pass. |
| REQ-3 (entry-level `rsv0[31:30]`) | SHIPPED | `AddressMode::from_entry_rsv0` (`address.rs:270`, `from_bits((rsv0 >> 30) as u8)`) with the 4-mode enum (`address.rs:128-141`) mirrors `entry.py:132-134` (`(self.rsv0 >> 30) & 3`). Non-test consumers: `directory.rs:156` and `directory.rs:207` (`PspEntry`/`BiosEntry::entry_address_mode`), threaded into `entry.rs:455` (`record.entry_address_mode()`) → `resolve_body`. Verification: `entry_rsv0_high_bits`, `address_mode_bits_roundtrip` in the 146-test pass. |
| REQ-4 (directory `additional_info` mode) | SHIPPED | `AddressMode::from_additional_info` (`address.rs:172-180`, version flag `>>31`, v1 `>>24`, v2 `>>29`) mirrors `directory.py:186-193`. Non-test consumer: `directory.rs:98` (`PspDirectoryHeader::address_mode` → `AddressMode::from_additional_info(self.additional_info)`), consumed by `entry.rs:402/446` (`parent.header.address_mode()`) and `list.rs`. Verification: `additional_info_v1_decode`, `additional_info_v2_decode` in the 146-test pass. |
| REQ-5 (address-mode resolution) | SHIPPED | `AddressMode::resolve` (`address.rs:238`) and `resolve_with_entry` (`address.rs:248`) implement the mode-0 masking + >16 MiB window (`normalise_physical`, `address.rs:281-289`), mode-1 flash offset (`rom_relative_to_file`, `address.rs:294`), and mode-2/3 `directory_base + offset` (`address.rs:261`) with the `10`/`11`-defers-to-entry rule (`address.rs:257`), mirroring `entry.py:47-70`. Non-test consumers: `directory.rs:608`/`directory.rs:634` (`AddressMode::PhysicalX86.resolve` for FET + combo pointers), `entry.rs:503` (`dir_mode.resolve_with_entry(entry_mode, entry_offset, ctx)`), and `psptool-ops/src/list.rs:600/617/631`. Verification: the `resolve_*` suite (in the 146-test pass) plus `corpus_roundtrip` (54 passed, 0 failed, 0 ignored). |
| REQ-6 (ROM-origin shift) | SHIPPED | `ResolveContext::rom_origin` (`address.rs:206`) is added in both `normalise_physical` (`address.rs:288`, `rom_origin.0.wrapping_add(rom_flash)`) and `rom_relative_to_file` (`address.rs:295`) so results are file offsets (§1.1). Non-test consumer: `directory.rs:606` and `entry.rs:501` build the `ResolveContext` with the real `rom_origin` from `detect_rom_layout` (`fet.rs:109`), plumbed through `psptool-cli/src/load.rs:22`. Verification: `resolve_physical_x86_with_capsule_envelope`, `resolve_flash_offset_with_capsule_envelope` in the 146-test pass; capsule ROMs (e.g. `Tyan_*.CAP`) roundtrip in the 54-test corpus pass. |
| REQ-7 (FET sentinel set) | SHIPPED | `Address::is_fet_sentinel` (`address.rs:105`, `matches!(self.0, 0x0 \| 0xFFFF_FFFE \| 0xFFFF_FFFF)`) covers the directory empty-marker check `directory.py:108` (`b'\xff\xff\xff\xff'` / `b'\x00\x00\x00\x00'`) plus the FET-only `0xFFFF_FFFE` (`fet.py:64`, sibling FET route). Non-test consumer: `fet.rs:147` (`FetSlot::classify` → `if addr.is_fet_sentinel()`), consumed by `directory.rs:600` (`FetSlot::Sentinel(_) => continue`). Verification: `fet_sentinels` in the 146-test pass. |
| REQ-8 (unified 32-bit PSP+BIOS width) | SHIPPED | Both `PspEntry` (`directory.rs:138`, `offset` @0x08 u32) and `BiosEntry` (`directory.rs:190`, `offset` @0x08 u32; `rsv0` @0x0C u32 at `directory.rs:191`) resolve via the same `Address`/`from_entry_rsv0` path; the BIOS `destination` (`directory.rs:192`, u64 @0x10) is stored but never passed to `resolve*`. Mirrors `entry.py:136-137` (BIOS inherits `file_offset()`) and `entry.py:142-144` (`destination` read separately, not by `file_offset`). Non-test consumer: `entry.rs::parse_bios` (`entry.rs:429`) calls the same `resolve_body`/`resolve_with_entry` as `parse_psp`. Verification: `corpus_roundtrip` (54 passed) covers BIOS-directory-bearing ROMs; `resolve_*` unit tests exercise the shared path. |

## Architecture

**Pure arithmetic module, explicit context (R-DEV-4).** Upstream resolves an
address by walking the live object graph — `self.parent_directory.address_mode`,
`self.parent_directory.rom.addr_mask`, `self.parent_directory.buffer_offset`
(`entry.py:44-70`). `address.rs` has no references to directories or ROMs; every
input is a value threaded through [`ResolveContext`] (`address.rs:196-207`):
`rom_size`, `directory_base`, `rom_origin`. This makes the resolver unit-testable
in isolation (the `resolve_*` tests, `address.rs:436-608`) and lets the same code
serve FET slots (`directory.rs:608`), combo pointers (`directory.rs:634`), and
directory entries (`entry.rs:503`) without three copies of the masking upstream
carries (`entry.py:60`, plus `fet.py`).

**Two entry points encode the `10`/`11` defer rule as types.** Upstream's
`file_offset()` re-reads `self.address_mode` mid-function only when the directory
mode is `2`/`3` (`entry.py:47-48`). The Rust split makes this explicit:
[`AddressMode::resolve`] (`address.rs:238`) is total for modes `00`/`01` and
returns `ResolveError::NeedsEntryMode` (`address.rs:214`) for `10`/`11`, forcing
a caller that has a directory-relative mode to supply the entry-level override via
[`AddressMode::resolve_with_entry`] (`address.rs:248`). `defers_to_entry`
(`address.rs:185`) names the predicate. This is the R-DEV-5 typestate flavour:
the arithmetic that needs an extra input cannot be reached without providing it.

**Mode-0 masking and the >16 MiB x86 window.** `normalise_physical`
(`address.rs:281-289`) is a line-for-line mirror of `entry.py:50-60`: if the raw
pointer is `> 0xFF00_0000` and the ROM is larger than 16 MiB, mask with
`0x00FF_FFFF` (force the top 16 MiB window), otherwise mask with
`rom_size - 1`. The masked ROM-flash offset then has `rom_origin` added to become
a file offset (REQ-6). The critic audit for #52 (commit `9001c659`) verified this
arithmetic reproduces reference entry addresses exactly; the two apparent
divergences it examined were an upstream cache echo (EPYC entry-11) and a
compressed-sizing bug in `entry.rs` (AM5 truncated body), not address math.

**Address width: 32 bits for both entry families (REQ-8).** The task premise of a
64-bit (`>>62`) BIOS address path does not exist in upstream: `BiosDirectoryEntry`
(`entry.py:136`) inherits `DirectoryEntry.file_offset()` and `address_mode`
unchanged, both of which read the 32-bit `offset` (`self[8:12]`) and the 32-bit
`rsv0` (`self[12:16]`). The 8-byte `destination` (`entry.py:142-144`, `self[16:24]`,
`'<Q'`) is the memory address the BIOS loader copies the body *to*, not the flash
location it is read *from*; `file_offset()` never touches it. `address.rs` matches
this exactly — its single `Address(u32)` + `from_entry_rsv0(rsv0 >> 30)` path is
used verbatim by `BiosEntry` (`directory.rs:190-207`) and `PspEntry`
(`directory.rs:138-156`), and `BiosEntry.destination` (`directory.rs:192`) is
carried for display/roundtrip but never passed to a resolver.

**Soft-fuse chain is out of scope here.** `entry.py:40-42` short-circuits
`file_offset()` for `type == 0xb` (returning the record's own position). That
special case is not in `address.rs`; it is handled one layer up in
`entry.rs::resolve_body` (`entry.rs:492-497`, `if entry_type.is_soft_fuse_chain()`)
per `.design/psptool-core/entry.md` REQ-4. `address.rs` is purely the mask/offset
arithmetic; the type-conditional dispatch belongs to the entry layer.

## Version-skew note (blocker #61)

The differential oracle is PSPTool 3.4 while the translation source
`/tmp/psptool-ref` is git HEAD. Every behaviour in this module is on-disk-format-
structural and version-stable: the four address modes and their bit encodings
(`entry.py:128-134`, `directory.py:182-193`), the `additional_info` version-flag
split (`directory.py:189-193`), the mode-0 mask + >16 MiB window
(`entry.py:50-60`), and `addr_mask = rom_size - 1` (`rom.py:14`) are all
long-standing. Nothing read this iteration in `entry.py` / `directory.py` shows a
HEAD-only address-mode behaviour the 3.4 oracle would disagree with, and no REQ
above is asserted on a HEAD-only value. The one HEAD-side nuance is the
`entry.py:69` `TODO: How to calculate the offset from slot?` on mode `11`, which
upstream itself resolves identically to mode `10` — `address.rs:260-262` mirrors
that (partition-relative treated as directory-relative), so there is no skew.

## Verification

The list below IS the gauntlet for this module (parity_ops = `["roundtrip"]`).
Run inside `nix-shell` so `PSPTOOL_REFERENCE` + `PSPTOOL_TEST_CORPUS` are set (a
skip is a red gate, not a pass).

- `cargo test -p psptool-core --lib` — 146 passed, 0 failed, 0 ignored. Covers
  REQ-1/REQ-2 (`rom_size_constructors`, `rom_size_addr_mask`), REQ-3
  (`entry_rsv0_high_bits`, `address_mode_bits_roundtrip`,
  `address_mode_ignores_high_bits`), REQ-4 (`additional_info_v1_decode`,
  `additional_info_v2_decode`, `additional_info_decode_ignores_unused_bits`),
  REQ-5 (`resolve_physical_x86_16mib`, `resolve_physical_x86_32mib_window`,
  `resolve_flash_offset`, `resolve_directory_modes_require_entry_override`,
  `resolve_with_entry_directory_relative`,
  `resolve_with_entry_partition_relative_treated_like_directory_relative`,
  `resolve_with_entry_when_dir_mode_does_not_defer`), REQ-6
  (`resolve_physical_x86_with_capsule_envelope`,
  `resolve_flash_offset_with_capsule_envelope`), REQ-7 (`fet_sentinels`).
- `cargo test -p psptool-core --test corpus_roundtrip` — 54 passed, 0 failed,
  0 ignored (parity_ops "roundtrip"). Byte-exact roundtrip on every supported ROM
  is the end-to-end oracle for REQ-5/REQ-6/REQ-8: each directory and entry (both
  16-byte PSP and 24-byte BIOS) must have been located within its window by this
  resolver for the model to carry the exact source bytes.
- The address arithmetic is additionally exercised, downstream of this route, by
  `cargo test -p psptool-cli --test differential` (owned by the entry/directory/
  fet routes), which structurally compares resolved entry addresses against
  reference PSPTool. This route declares only `roundtrip`; the differential result
  is cited there as corroboration, not as this module's gate.
- No open prerequisite blockers: all eight REQs are SHIPPED. The multi-ROM base
  application divergence (#41) lives in how a *second* ROM's `rom_origin` addend
  is chosen upstream vs here (a `fet.rs`/`load.rs` window-selection concern), not
  in the `address.rs` masking arithmetic; the resolver applies whatever
  `rom_origin` it is handed correctly.
