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
The module exposes one pure function,
`pub fn fletcher32(data: &[u8]) -> Result<u32, FletcherError>`, re-exported at
the crate root (`crates/psptool-core/src/lib.rs:61`). The function is
**fallible**: odd-length input is rejected with
`Err(FletcherError::OddLength)`, mirroring upstream's `struct.error` raise on a
trailing half-word (`/tmp/psptool-ref/psptool/utils.py:291`; goal.md R-DEV-4 —
a Python exception maps to a Rust `Result::Err`, not a `panic!`).

The odd-length error lives as a dedicated `#[derive(thiserror::Error)]` enum
`FletcherError` in `fletcher.rs` (rather than a `ParseError` variant): under the
translate-discipline route gate, `error.rs` is routeless and cannot be edited
without an out-of-scope design-doc + route addition, so the checksum's single
error condition is expressed as a minimal local enum reachable via
`psptool_core::fletcher::FletcherError`.

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
- REQ-7 (reject odd-length input): The function is defined over whole 16-bit
  words. Odd-length input has no valid final word; upstream
  `struct.unpack('<H', <1 byte>)` (`/tmp/psptool-ref/psptool/utils.py:291`)
  raises `struct.error` and produces no checksum. The Rust boundary must not
  fabricate a value: it returns `Err(FletcherError::OddLength { len })`
  (goal.md R-DEV-4 — Python exception → Rust `Result::Err`, not a `panic!`).

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
- AC-6 (REQ-7): `fletcher32(&[0x00])` and `fletcher32(&[0x12, 0x34, 0x56])`
  return `Err(FletcherError::OddLength { len: 1 })` / `{ len: 3 }`; an
  even-length prefix (`&[0x12, 0x34]`) still returns `Ok(_)`. Pinned by the
  divergence tests `divergence_single_odd_byte_upstream_raises` /
  `divergence_odd_length_three_bytes_upstream_raises`
  (`crates/psptool-core/tests/divergence_fletcher.rs`), whose expected "raise"
  behaviour is the verbatim `utils.py:286-307` oracle.

## REQ status table

| REQ | Status | Evidence |
|---|---|---|
| REQ-1 (seed 0xFFFF) | SHIPPED | impl `crates/psptool-core/src/fletcher.rs:60-61` (`let mut c0: u32 = 0xFFFF; let mut c1: u32 = 0xFFFF;`) mirrors upstream `/tmp/psptool-ref/psptool/utils.py:287-288` (`c0 = 0xFFFF` / `c1 = 0xFFFF`). Public boundary API re-exported at `crates/psptool-core/src/lib.rs:61` (`pub use fletcher::fletcher32;`); consumers are external library users of `psptool-core`. Pinned by `empty_input_returns_seed`. Verification: `cargo test -p psptool-core --lib fletcher` → 8 passed / 0 failed. |
| REQ-2 (360-word carry fold) | SHIPPED | impl `crates/psptool-core/src/fletcher.rs:69-72` (`if i % 360 == 0 { c0 = (c0 & 0xFFFF) + (c0 >> 16); c1 = (c1 & 0xFFFF) + (c1 >> 16); }`) mirrors upstream `/tmp/psptool-ref/psptool/utils.py:296-298` (`if index % 360 == 0:`). Public boundary API at `lib.rs:61`. Pinned by `carry_fold_at_360_word_boundary`. Verification: `cargo test -p psptool-core --lib fletcher` → 8 passed / 0 failed. |
| REQ-3 (double final fold) | SHIPPED | impl `crates/psptool-core/src/fletcher.rs:75-78` (four fold statements: `c0` twice, `c1` twice) mirrors upstream `/tmp/psptool-ref/psptool/utils.py:300-304` (two consecutive fold blocks). Public boundary API at `lib.rs:61`. Pinned by `single_word_matches_hand_calc`, which walks the finalisation by hand. Verification: `cargo test -p psptool-core --lib fletcher` → 8 passed / 0 failed. |
| REQ-4 (16-bit LE word iteration) | SHIPPED | impl `crates/psptool-core/src/fletcher.rs:65-73` (`data.chunks_exact(2)` → `u16::from_le_bytes([chunk[0], chunk[1]])`, `c0 += w`, `c1 += c0`) mirrors upstream `/tmp/psptool-ref/psptool/utils.py:290-294` (`chunker(s, 2)` → `struct.unpack('<H', byte_pair)`). Public boundary API at `lib.rs:61`. Pinned by the fixture-checksum tests `matches_fixture_{psp,bhd,combo}_directory_checksum`, which cross-validate against the independent reference impl in `crates/psptool-fixtures/examples/build_fixtures.rs:81-105`. Verification: `cargo test -p psptool-core --lib fletcher` → 8 passed / 0 failed. |
| REQ-5 (output `(c1<<16)\|c0`) | SHIPPED | impl `crates/psptool-core/src/fletcher.rs:79` (`Ok((c1 << 16) \| c0)`) mirrors upstream `/tmp/psptool-ref/psptool/utils.py:306` (`checksum = (c1 << 16) \| c0`). LE placement of the returned value is verified against the stored header dword read at `crates/psptool-core/src/directory.rs:79` (`u32::from_le_bytes(bytes[0x04..0x08]...)`) via the fixture tests (`stored = u32::from_le_bytes(bytes[0x04..0x08]...)`; `assert_eq!(fletcher32(body).unwrap(), stored)`). Public boundary API at `lib.rs:61`. Verification: `cargo test -p psptool-core --lib fletcher` → 8 passed / 0 failed. |
| REQ-6 (production writer recompute) | NOT-STARTED | open prereq blocker #43. No non-test production code calls `psptool_core::fletcher32`: the writer is diff-and-patch only (`crates/psptool-core/src/writer.rs:15` — "The writer is deliberately dumb — it does not recompute fletcher/sha") and `psptool-ops` (`replace.rs:37-38`, `sign.rs:21`) explicitly defers checksum recomputation. The only production-shaped caller, `crates/psptool-fixtures/examples/build_fixtures.rs:142`, uses its *own* private copy of the algorithm (`build_fixtures.rs:81`), not the library function. A mutation path that recomputes and writes the checksum LE into header `[0x04..0x08]` does not exist. |
| REQ-7 (reject odd-length input) | SHIPPED | impl `crates/psptool-core/src/fletcher.rs:56-58` (`if !data.len().is_multiple_of(2) { return Err(FletcherError::OddLength { len: data.len() }); }`) mirrors upstream `/tmp/psptool-ref/psptool/utils.py:291` (`struct.unpack('<H', byte_pair)` raises `struct.error` on the 1-byte final `chunker` slice, `utils.py:177`). Error type `FletcherError` at `crates/psptool-core/src/fletcher.rs:27-36`. Public boundary API re-exported at `lib.rs:61` (`pub use fletcher::fletcher32;`); the error is reachable via `psptool_core::fletcher::FletcherError`. Pinned (un-`#[ignore]`'d, R-DEFER-3) by `divergence_single_odd_byte_upstream_raises` + `divergence_odd_length_three_bytes_upstream_raises` (`crates/psptool-core/tests/divergence_fletcher.rs`), whose "raise" expectation is the verbatim `utils.py:286-307` oracle, plus `odd_length_input_is_rejected` (`fletcher.rs` test module). Verification: `cargo test -p psptool-core --lib fletcher` → 8 passed / 0 failed; `cargo test -p psptool-core --test divergence_fletcher` → 3 passed / 0 failed / 0 ignored. |

## Architecture

The module is a single pure, fallible function with no state and no I/O
(`crates/psptool-core/src/fletcher.rs:55-80`) plus its error enum
`FletcherError` (`fletcher.rs:27-36`). The function is re-exported at the crate
root (`crates/psptool-core/src/lib.rs:61`, `pub use fletcher::fletcher32;`) and
is therefore part of the public `psptool-core` library surface; the error type
is reachable via the `pub mod fletcher` path as
`psptool_core::fletcher::FletcherError`.

Structure of `fletcher32` and the upstream lines it mirrors:

1. Odd-length guard (`fletcher.rs:56-58`): `if !data.len().is_multiple_of(2) {
   return Err(FletcherError::OddLength { len: data.len() }); }`. Upstream consumes the
   buffer via `chunker(s, 2)` (`utils.py:177`), whose final slice is 1 byte for
   odd-length input; `struct.unpack('<H', <1 byte>)` (`utils.py:291`) then
   raises `struct.error`, producing no checksum. The Rust boundary mirrors that
   observable abort as `Err` rather than fabricating a value (goal.md R-DEV-4).
2. Seed (`fletcher.rs:60-61` ↔ `utils.py:287-288`): `c0 = c1 = 0xFFFF`.
3. Main loop (`fletcher.rs:65-73` ↔ `utils.py:290-298`): `chunks_exact(2)`
   yields 16-bit LE words; `c0 = c0.wrapping_add(w)`, `c1 = c1.wrapping_add(c0)`;
   every 360th word (`i % 360 == 0`) both accumulators carry-fold. Because the
   odd-length guard rejected odd input, `chunks_exact(2)` never leaves a
   remainder — every byte is consumed as a whole 16-bit word.
4. Finalisation (`fletcher.rs:75-78` ↔ `utils.py:300-304`): each accumulator
   carry-folds exactly twice.
5. Output (`fletcher.rs:79` ↔ `utils.py:306`): `Ok((c1 << 16) | c0)`. Upstream
   returns this LE-packed (`struct.pack('<I', checksum)`, `utils.py:307`); the
   Rust boundary returns the `u32` and leaves the `to_le_bytes()` conversion to
   the caller.

Odd-length is an OBSERVABLE divergence on a public boundary, not a benign
extension: a `pub fn` that invents a checksum (e.g.
`fletcher32(&[0x12,0x34,0x56])` == `0x687A3468`, `fletcher32(&[0x00])` ==
`0xFFFFFFFF` in the pre-#45 impl) for input upstream *rejects* is a semantic
mismatch. Real directory bodies are always word-aligned (the header is 0x10 and
every entry record is 0x10/0x18/0x10 bytes), so valid callers never hit the
guard; but the public surface must still refuse odd input the way upstream does
(cite `utils.py:291`, goal.md R-DEV-4). This closes #45.

Key invariant (input scope): the checksummed region is the directory *body*,
bytes `[0x08 .. end-of-directory]` — the 4-byte magic and the 4-byte checksum
field itself are excluded. This is documented on the function and exercised by
the fixture tests, which slice `bytes[0x08..0x20]` (PSP), `[0x08..0x28]` (BHD),
`[0x08..0x30]` (combo).

Consumer status: the parse side reads the stored checksum into
`DirectoryHeader::fletcher` (`crates/psptool-core/src/directory.rs:61,79`) but
does **not** recompute or verify it (`directory.rs:1044` notes traversal does
not verify the checksum). The write side is diff-and-patch and deliberately
preserves the source checksum bytes rather than recomputing
(`crates/psptool-core/src/writer.rs:15`). Consequently REQ-6 (a production
recompute path) is NOT-STARTED and tracked by blocker #43; the algorithm-exactness
REQs (1–5) and the odd-length rejection REQ-7 are SHIPPED as the public library
boundary function, cross-validated against an independent reference
implementation via the fixture-checksum tests and against the verbatim
`utils.py:286-307` oracle via the divergence tests.

## Verification

The verification list below is the gauntlet for this module. Run inside the nix
dev shell (`nix-shell`) so the parity environment is set.

- `cargo test -p psptool-core --lib fletcher` — the eight unit tests that pin
  REQ-1..REQ-5 + REQ-7 (seed, 360-fold, double final fold, LE word iteration,
  output value, fixture cross-checks, and `odd_length_input_is_rejected`).
  Result: 8 passed / 0 failed.
- `cargo test -p psptool-core --test divergence_fletcher` — the ACToR pins for
  REQ-7, now un-`#[ignore]`'d (R-DEFER-3): the even-length control plus the two
  odd-length `Err(FletcherError::OddLength)` assertions. Result: 3 passed /
  0 failed / 0 ignored.
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

The fixture-checksum tests (`matches_fixture_{psp,bhd,combo}_directory_checksum`)
are the strongest evidence for
REQ-2..REQ-5: the micro-fixtures' stored checksums were produced by the
independent reference implementation in `build_fixtures.rs:81-105`, so agreement
proves the two implementations compute byte-identical results over real
directory bodies.
