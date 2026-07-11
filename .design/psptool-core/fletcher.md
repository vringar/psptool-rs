# Fletcher-32 checksum (directory headers, §2.4)

<!--
tier: 3-component
status: draft
baseline-commit: 40fbf2f85eaa847153da729670b9822bab970490
upstream-paths:
  - /tmp/psptool-ref/psptool/utils.py
-->

## Summary

`crates/psptool-core/src/fletcher.rs` implements the PSPTool variant of the
Fletcher-32 checksum carried in every directory header at bytes `[0x04..0x08]`
(§2.4). It mirrors upstream `psptool/utils.py:fletcher32`
(`/tmp/psptool-ref/psptool/utils.py:286`): accumulators seeded with `0xFFFF`,
iteration over 16-bit little-endian words, a periodic carry-fold every 360
words, and a double carry-fold at finalisation, returning `(c1 << 16) | c0`.
The module exposes one pure function, `pub fn fletcher32(data: &[u8]) -> u32`,
re-exported at the crate root (`crates/psptool-core/src/lib.rs:61`).

## Requirements

- REQ-1 (seed): Both accumulators `c0`, `c1` are seeded with `0xFFFF` before any
  word is consumed (upstream seeds `c0 = c1 = 0xFFFF`).
- REQ-2 (360-word carry fold): After accumulating each word at loop index `i`,
  when `i % 360 == 0` both accumulators fold their high 16 bits into their low
  16 bits: `c = (c & 0xFFFF) + (c >> 16)`.
- REQ-3 (double final fold): At finalisation each accumulator is carry-folded
  exactly twice, matching upstream's two consecutive fold blocks.
- REQ-4 (16-bit little-endian word iteration): Input is consumed as 16-bit
  little-endian words (`struct.unpack('<H', ...)` upstream); `c0 += w`,
  `c1 += c0` per word.
- REQ-5 (output value): The function returns the 32-bit checksum
  `(c1 << 16) | c0`. Upstream additionally little-endian-packs this value with
  `struct.pack('<I', checksum)`; the Rust boundary hands back the `u32` and the
  caller performs the LE byte conversion.
- REQ-6 (production writer recompute → header `[0x04..0x08]`): On production
  (re)serialization of a *mutated* directory, the checksum is recomputed via
  `fletcher32` and written little-endian into header bytes `[0x04..0x08]`.

## Acceptance criteria

- AC-1 (REQ-1): `fletcher32(&[])` returns `0xFFFF_FFFF` (empty input leaves the
  seeds untouched).
- AC-2 (REQ-2/3/4/5): For the micro-fixtures whose stored checksum was produced
  by an independent reference implementation, `fletcher32` over the directory
  body `[0x08..end]` equals the stored `u32` at `[0x04..0x08]`.
- AC-3 (REQ-4/5): A single word `[0x01, 0x02]` produces the hand-computed
  `(0x0201 << 16) | 0x0201`.
- AC-4 (REQ-2): A ≥360-word input exercising the periodic fold path is stable
  and reproducible.
- AC-5 (REQ-6): A production mutation path (writer / ops) recomputes the
  directory checksum after a body edit and emits the new LE dword at
  `[0x04..0x08]`. Not currently satisfiable — see the REQ status table.

## REQ status table

| REQ | Status | Evidence |
|---|---|---|
| REQ-1 (seed 0xFFFF) | SHIPPED | impl `crates/psptool-core/src/fletcher.rs:21-22` (`let mut c0: u32 = 0xFFFF; let mut c1: u32 = 0xFFFF;`) mirrors upstream `/tmp/psptool-ref/psptool/utils.py:287-288` (`c0 = 0xFFFF` / `c1 = 0xFFFF`). Public boundary API re-exported at `crates/psptool-core/src/lib.rs:61` (`pub use fletcher::fletcher32;`); consumers are external library users of `psptool-core`. Pinned by `empty_input_returns_seed` (`fletcher.rs:52-56`). Verification: `cargo test -p psptool-core --lib fletcher` → 8 passed / 0 failed. |
| REQ-2 (360-word carry fold) | SHIPPED | impl `crates/psptool-core/src/fletcher.rs:29-32` (`if i % 360 == 0 { c0 = (c0 & 0xFFFF) + (c0 >> 16); c1 = (c1 & 0xFFFF) + (c1 >> 16); }`) mirrors upstream `/tmp/psptool-ref/psptool/utils.py:296-298` (`if index % 360 == 0:`). Public boundary API at `lib.rs:61`. Pinned by `carry_fold_at_360_word_boundary` (`fletcher.rs:121-135`). Verification: `cargo test -p psptool-core --lib fletcher` → 8 passed / 0 failed. |
| REQ-3 (double final fold) | SHIPPED | impl `crates/psptool-core/src/fletcher.rs:41-44` (four fold statements: `c0` twice, `c1` twice) mirrors upstream `/tmp/psptool-ref/psptool/utils.py:300-304` (two consecutive fold blocks). Public boundary API at `lib.rs:61`. Pinned by `single_word_matches_hand_calc` (`fletcher.rs:58-74`), which walks the finalisation by hand. Verification: `cargo test -p psptool-core --lib fletcher` → 8 passed / 0 failed. |
| REQ-4 (16-bit LE word iteration) | SHIPPED | impl `crates/psptool-core/src/fletcher.rs:24-33` (`data.chunks_exact(2)` → `u16::from_le_bytes([chunk[0], chunk[1]])`, `c0 += w`, `c1 += c0`) mirrors upstream `/tmp/psptool-ref/psptool/utils.py:290-294` (`chunker(s, 2)` → `struct.unpack('<H', byte_pair)`). Public boundary API at `lib.rs:61`. Pinned by the fixture-checksum tests `matches_fixture_{psp,bhd,combo}_directory_checksum` (`fletcher.rs:88-119`), which cross-validate against the independent reference impl in `crates/psptool-fixtures/examples/build_fixtures.rs:81-105`. Verification: `cargo test -p psptool-core --lib fletcher` → 8 passed / 0 failed. |
| REQ-5 (output `(c1<<16)\|c0`) | SHIPPED | impl `crates/psptool-core/src/fletcher.rs:45` (`(c1 << 16) \| c0`) mirrors upstream `/tmp/psptool-ref/psptool/utils.py:306` (`checksum = (c1 << 16) \| c0`). LE placement of the returned value is verified against the stored header dword read at `crates/psptool-core/src/directory.rs:79` (`u32::from_le_bytes(bytes[0x04..0x08]...)`) via the fixture tests `fletcher.rs:95,100` (`stored = u32::from_le_bytes(bytes[0x04..0x08]...)`; `assert_eq!(fletcher32(body), stored)`). Public boundary API at `lib.rs:61`. Verification: `cargo test -p psptool-core --lib fletcher` → 8 passed / 0 failed. |
| REQ-6 (production writer recompute) | NOT-STARTED | open prereq blocker #43. No non-test production code calls `psptool_core::fletcher32`: the writer is diff-and-patch only (`crates/psptool-core/src/writer.rs:15` — "The writer is deliberately dumb — it does not recompute fletcher/sha") and `psptool-ops` (`replace.rs:37-38`, `sign.rs:21`) explicitly defers checksum recomputation. The only production-shaped caller, `crates/psptool-fixtures/examples/build_fixtures.rs:142`, uses its *own* private copy of the algorithm (`build_fixtures.rs:81`), not the library function. A mutation path that recomputes and writes the checksum LE into header `[0x04..0x08]` does not exist. |

## Architecture

The module is a single pure function with no state and no I/O
(`crates/psptool-core/src/fletcher.rs:20-46`). It is re-exported at the crate
root (`crates/psptool-core/src/lib.rs:61`, `pub use fletcher::fletcher32;`) and
is therefore part of the public `psptool-core` library surface.

Structure of `fletcher32` and the upstream lines it mirrors:

1. Seed (`fletcher.rs:21-22` ↔ `utils.py:287-288`): `c0 = c1 = 0xFFFF`.
2. Main loop (`fletcher.rs:24-33` ↔ `utils.py:290-298`): `chunks_exact(2)`
   yields 16-bit LE words; `c0 = c0.wrapping_add(w)`, `c1 = c1.wrapping_add(c0)`;
   every 360th word (`i % 360 == 0`) both accumulators carry-fold.
3. Remainder (`fletcher.rs:34-39`): a trailing odd byte, if present, is
   accumulated as a single word. This is a benign Rust extension: upstream
   `struct.unpack('<H', byte_pair)` raises on a 1-byte final chunk (odd input),
   so upstream cannot process odd-length input at all. Directory bodies are
   always word/4-byte-aligned (the header is 0x10 and every entry record is
   0x10/0x18/0x10 bytes), so this branch never fires for real directory bodies;
   it does not change observable behaviour for any valid input.
4. Finalisation (`fletcher.rs:41-44` ↔ `utils.py:300-304`): each accumulator
   carry-folds exactly twice.
5. Output (`fletcher.rs:45` ↔ `utils.py:306`): `(c1 << 16) | c0`. Upstream
   returns this LE-packed (`struct.pack('<I', checksum)`, `utils.py:307`); the
   Rust boundary returns the `u32` and leaves the `to_le_bytes()` conversion to
   the caller.

Key invariant (input scope): the checksummed region is the directory *body*,
bytes `[0x08 .. end-of-directory]` — the 4-byte magic and the 4-byte checksum
field itself are excluded. This is documented on the function
(`fletcher.rs:17-19`) and exercised by the fixture tests, which slice
`bytes[0x08..0x20]` (PSP), `[0x08..0x28]` (BHD), `[0x08..0x30]` (combo)
(`fletcher.rs:99,108,117`).

Consumer status: the parse side reads the stored checksum into
`DirectoryHeader::fletcher` (`crates/psptool-core/src/directory.rs:61,79`) but
does **not** recompute or verify it (`directory.rs:1044` notes traversal does
not verify the checksum). The write side is diff-and-patch and deliberately
preserves the source checksum bytes rather than recomputing
(`crates/psptool-core/src/writer.rs:15`). Consequently REQ-6 (a production
recompute path) is NOT-STARTED and tracked by blocker #43; the algorithm-exactness
REQs (1–5) are SHIPPED as the public library boundary function, cross-validated
against an independent reference implementation via the fixture-checksum tests.

## Verification

The verification list below is the gauntlet for this module. Run inside the nix
dev shell (`nix-shell`) so the parity environment is set.

- `cargo test -p psptool-core --lib fletcher` — the eight unit tests that pin
  REQ-1..REQ-5 (seed, 360-fold, double final fold, LE word iteration, output
  value, fixture cross-checks). Result at baseline: 8 passed / 0 failed.
- `cargo test -p psptool-core` — full crate suite. Result at baseline:
  146 passed / 0 failed (lib) and 54 passed / 0 failed / 0 skipped
  (`corpus_roundtrip`).
- `cargo test -p psptool-core --test corpus_roundtrip` — the route's
  `parity_ops = ["roundtrip"]` gate. Result at baseline: 54 passed / 0 failed /
  0 skipped. Note: the roundtrip harness is diff-and-patch and does **not**
  itself call `fletcher32` (`corpus_roundtrip.rs:34` — "does not re-sign or
  re-fletcher anything"); it establishes that the source checksum bytes survive
  a no-mutation roundtrip untouched. The fletcher REQs are pinned by the lib
  unit tests above, not by this suite.

The fixture-checksum tests (`fletcher.rs:88-119`) are the strongest evidence for
REQ-2..REQ-5: the micro-fixtures' stored checksums were produced by the
independent reference implementation in `build_fixtures.rs:81-105`, so agreement
proves the two implementations compute byte-identical results over real
directory bodies.
