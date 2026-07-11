# psptool-rs — Locked /goal Statement

This file is the binding contract for autonomous work on psptool-rs. When the user issues `/goal $(cat goal.md)` (or otherwise references this file), the contents below override the LARP's pull toward caution and the model's instinct to narrow scope. The goal is in force until the user issues `/goal-clear` or rewrites this file.

The substrate of this project is sequential **translation** of a known-working system. Upstream is **PSPTool (Python)** (working tree at `/tmp/psptool-ref/psptool`; clone with `git clone --depth 1 https://github.com/PSPReverse/PSPTool /tmp/psptool-ref`). Target is the workspace (`crates/psptool-*/src/**/*.rs`). Most apparent divergence between target and upstream is a bug a prior translation pass introduced — a mis-sized entry, a wrong offset/address-mode application, a dropped padding or zero-fill byte, a misclassified file type, an endianness slip, parsing that compiled but doesn't read the right bytes. Every one of those is real work to do, not "out of scope."

The project's non-negotiable correctness contract: **byte-exact roundtripping when nothing was mutated** (every `Entry`/`Directory` carries its source bytes; serialization is diff-and-patch, never blind re-emit) and **structural agreement with the reference Python PSPTool** on the differential test. These two are the oracle. See `.crosslink/rules/project.md` and `CLAUDE.md`.

---

## The goal

Work the strict **read → write → verify → commit** loop over every translation unit (source file) under `crates/psptool-*/src/**/`, in dependency order from leaf crates outward. The goal is complete only when every routed source file has:

1. A closing commit citing the upstream file(s) actually opened that iteration, AND
2. The corresponding verification suite(s) the route declares (roundtrip / differential) returning **0 failures, 0 skipped**, AND
3. A `## REQ status` table at the top-of-file doc-comment classifying every REQ as **SHIPPED** or **NOT-STARTED** with quoted-code evidence. Only two states exist: end-to-end satisfied by production code with a consumer (SHIPPED), or work hasn't begun / has a concrete open prerequisite blocker (NOT-STARTED). "Type exists but no consumer" is NOT-STARTED — the consumer is the open work item.

Verifiable mechanically:

```bash
# Count routed translation units:
python3 -c "import tomllib; print(len(tomllib.load(open('tooling/translate-routes.toml','rb'))['route']))"

# Count routed files with `## REQ status` doc-comment:
grep -l "## REQ status" $(python3 -c "import tomllib; [print(r['crate_pattern']) for r in tomllib.load(open('tooling/translate-routes.toml','rb'))['route']]") | wc -l

# When all counts agree AND every routed file's verification suites pass
# with 0 failures / 0 skipped (in the nix dev shell), the goal is complete.
```

---

## The eight-step loop (one iteration = one translation unit)

### Step 1 — Read the routed source unit
Read `crates/psptool-*/src/<path>` end-to-end via the Read tool. Capture: the public surface, the `## REQ status` table if present, the existing tests.

### Step 2 — Read every upstream file in the route
**Mandatory.** Open every file in the route's `upstream` list at `/tmp/psptool-ref/psptool/<path>` via the Read tool. For each, capture at minimum one `file:line — content` quote that the commit message will cite. **No commit may cite an upstream path that has not been opened this iteration.** If a cited file is missing from `/tmp/psptool-ref/psptool/`, document the discrepancy and either (a) re-clone the upstream (`git clone --depth 1 https://github.com/PSPReverse/PSPTool /tmp/psptool-ref`) or (b) fall back to a github URL with an explicit pinned commit.

### Step 3 — Read the design doc
**Mandatory.** Open `.design/<area>/<doc>.md` via the Read tool. Capture the REQ list and AC list. If the design doc does NOT exist on disk, the translate-discipline hook will block the edit — dispatch `acto-doc-author` first to author it, grounded in the existing code + the upstream source.

### Step 4 — File a crosslink issue
```bash
crosslink quick "Translation unit: <crate>/<file>.rs" -p high -l feature
```
Post a `--kind plan` comment listing the upstream files (file:line), the verification suites this file owns (from the route's `parity_ops` field — `roundtrip` and/or `differential`), and the design-doc REQs the implementation will cite.

### Step 5 — Write the implementation
Write or extend the target crate to satisfy:
- Every REQ-N — either fully (**SHIPPED** — end-to-end functional with non-test production consumer + tests + verification verified) or **NOT-STARTED** (work hasn't begun OR has a concrete open prerequisite blocker).
- Every AC-N that can be mechanically discharged now.
- Every verification suite named in the route's `parity_ops` field, with the Step 7 gate returning 0 failures / 0 skipped.

**No stubs.** No `todo!()` / `unimplemented!()` / `unreachable!()` in production. No `unwrap()` / `expect()` outside `#[cfg(test)]`. **No vocabulary-only shipping** — every public API surface added in a commit MUST have a non-test production consumer in the same commit, or the API isn't ready to ship.

The translation pipeline is sequential: we are translating a known-working system. There is no valid "ship the type, defer the consumer" path. If a REQ needs prerequisite work, the prerequisite IS the active blocker — file it concretely (`crosslink quick "Blocker for REQ-N of <area>: needs <prereq>" -p high -l blocker`) and work it. Do NOT mark the dependent REQ as a separate "deferred" status; it is simply NOT-STARTED until the prereq blocker closes and the consumer wiring lands.

### Step 6 — Add `## REQ status` table to module doc-comment
The module's top-level `//!` doc-comment must include a section like:

```rust
//! ## REQ status (per `.design/<area>/<doc>.md`)
//!
//! | REQ | Status | Evidence |
//! |---|---|---|
//! | REQ-1 | SHIPPED | fn `<name>` at `<file>:<L>` per upstream `<upstream-file>:<L>` (consumer at `<caller-file>:<L>`) |
//! | REQ-2 | NOT-STARTED | work hasn't begun |
//! | REQ-3 | NOT-STARTED | blocked on #NNN (file a concrete prereq blocker, not a deferral) |
```

Two states only. **No VOCAB-ONLY. No DEFERRED. No verified_with_deferred. No phase-N+.** SHIPPED means end-to-end with a production consumer; anything else is NOT-STARTED with the open prerequisite tracked as its own active blocker.

### Step 7 — Verify the gauntlet
Before commit, ALL of these MUST pass. Run inside the nix dev shell (`nix-shell -A shell`) so `PSPTOOL_REFERENCE` and `PSPTOOL_TEST_CORPUS` are set — the parity suites auto-skip when those env vars are unset, and **a skip is NOT a pass**.

```bash
# Per-crate test pass
cargo test -p <crate>

# Parity gate — run the suites the route's parity_ops declares. BOTH the
# roundtrip and differential suites must report 0 failed AND 0 skipped.
cargo test -p psptool-core --test corpus_roundtrip   # byte-exact roundtrip (parity_ops: "roundtrip")
cargo test -p psptool-cli  --test differential        # vs reference Python PSPTool (parity_ops: "differential")

# A skipped suite means the corpus / reference tool is not wired up — that
# is a RED gate, not a pass. Fix the environment and re-run.

# Lint
cargo clippy -p <crate> --all-targets --all-features -- -D warnings

# Format
cargo fmt --all --check
```

**No `--no-verify`. No commenting-out failing tests. No `#![allow(..)]` at module or crate root.** Per-item `#[allow(<lint>, reason = "...")]` is the bar.

### Step 8 — Commit + close
Commit message structure:

```
<crate>: <area> — <one-line summary> (closes #<N>)

UPSTREAM FILES OPENED THIS ITERATION:
  - <upstream-path>:<line> — <content quote>
  - ...

DESIGN DOC READ: .design/<area>/<doc>.md (<line count>, <REQ count> REQs).

REQ STATUS (per .design/<area>/<doc>.md):
  - REQ-1 SHIPPED — fn `<name>` at <file>:<L>; production consumer at <caller-file>:<L>
  - REQ-2 NOT-STARTED — open prerequisite blocker #<NN>

VERIFICATION:
  cargo test -p <crate>: <X passed, 0 failed>
  cargo test -p psptool-core --test corpus_roundtrip: <X passed, 0 failed, 0 skipped>
  cargo test -p psptool-cli --test differential: <X passed, 0 failed, 0 skipped>
  cargo clippy -p <crate> --all-targets --all-features -- -D warnings: PASS
  cargo fmt --all --check: PASS

Reference: PSPTool (Python) <commit-or-branch> <each:line cited above>
Reference: .design/<area>/<doc>.md REQ classifications above
```

Close the crosslink issue with `crosslink issue close <N>` (`--kind result` comment posted first).

### Step 9 — Pick the next unit
Pick the next routed source file in dependency order — leaf crates first (psptool-core), then crates that depend on them (psptool-ops, then psptool-cli). **Do not ask which.** The dependency DAG is the answer. Smallest-first within a layer is acceptable when dependency order is ambiguous.

---

## Anti-drift rules (override convenience)

These rules are non-negotiable. If they conflict with a tool-call shortcut, the rule wins.

### Citation rules
- **R-CITE-1**: Never cite an upstream file in a commit message without having Read it THIS iteration.
- **R-CITE-2**: Every upstream citation must carry a line number, not just a filename.
- **R-CITE-3**: When citing a Python/scripting upstream override, prefer citing the registration site (e.g. the `DIRECTORY_ENTRY_TYPES` table, a class field-layout, the `_ENTRY_FIELDS` struct) or the docstring block over a free-floating function definition — those are the actual contract surfaces.

### Honesty rules
- **R-HONEST-1**: Never reframe integration work as "vocabulary + decoders" when the design doc does not defer it. The doc's own deferrals are the only valid deferrals.
- **R-HONEST-2**: Every REQ in the commit message and module `## REQ status` table must carry SHIPPED or NOT-STARTED with quoted evidence. No bare "satisfied" claims. SHIPPED requires both implementation AND a non-test production consumer cited.
- **R-HONEST-3**: Honest underclaim beats unverified overclaim. If you cannot verify a REQ is SHIPPED end-to-end (impl + consumer + tests + verification fires), classify it NOT-STARTED with the open prerequisite blocker named. There is no middle classification.
- **R-HONEST-4**: If the audit reveals the original commit was wrong (citation theater, REQ-overclaim, wrong upstream value), correct the code AND document the correction in a supplemental commit's body.

### Code-quality rules
- **R-CODE-1**: No `unsafe` blocks outside leaf primitives. Leaf primitives are: FFI shims, raw byte-buffer accessors where a safe slice API genuinely cannot express the access. Every `unsafe` block requires a `// SAFETY:` comment documenting the invariants the caller and callee both rely on. A pure-Rust byte-format parser should need approximately none.
- **R-CODE-2**: No `unwrap()` / `expect()` / `panic!()` in production code outside `#[cfg(test)]`. Tests may use them. Parsing untrusted firmware bytes: every malformed-input path returns a typed `Err`, never panics.
- **R-CODE-3**: No `#![allow(..)]` at module or crate root. Per-item `#[allow(<lint>, reason = "...")]` with documented rationale is required.
- **R-CODE-4**: No silent byte round trips. The roundtrip contract means an unmodified `Entry`/`Directory` must serialize back to its *exact* source bytes via diff-and-patch. Forbidden: a decode→re-encode path that discards the carried source bytes and blindly re-emits from parsed fields (drops unknown/padding/reserved bytes); a "normalizing" write that silently rewrites bytes the parse didn't model. The anti-pattern-gate hook flags stub/escape-hatch patterns; agents must either preserve the source bytes or document (with an upstream cite) why a rewrite is correct.
- **R-CODE-5**: No type-cast hiding. A widening or narrowing cast in production code (e.g. truncating a `u32` flash address to `usize`/`u16`, sign-confusing an offset) that doesn't match the upstream contract is a bug unless the upstream explicitly does the same cast (cite the upstream `file:line`).

### Upstream-mirror rules (default = match upstream; deviate only for these reasons)

When translating, the **default answer is "do what upstream does"** with a cite. Most parsing choices have an obvious upstream answer. Only the conditions below justify deviation.

- **R-DEV-1 (MATCH — structural/format contract)**: When the choice is set by the on-disk PSP firmware format — entry sizes (16B DirectoryEntry vs 24B BiosDirectoryEntry), address-mode application, the `0xFFFFFFFE` combo-skip rule, fletcher32 checksum, `addr_mask = rom_size - 1`, zero-fill/padding semantics — always match upstream byte-for-byte.
- **R-DEV-2 (MATCH — user-facing surface)**: When the choice is set by the public surface a user calls (CLI flags, JSON keys the differential test reads, `ls`/`ls_json` output structure, `get_bytes`/`get_decompressed_body`/`get_decrypted` semantics), match upstream. Cite the upstream `__main__.py` / method definition. (Genuinely-equivalent JSON-shape differences the differential test already tolerates are documented in `crates/psptool-cli/tests/differential.rs` — do not "fix" those.)
- **R-DEV-3 (MATCH — on-disk format)**: The PSP firmware layout is an external specification. Match upstream. Deviation is only acceptable when upstream itself misreads the spec (file a separate blocker, cite the upstream `file:line` and the spec).
- **R-DEV-4 (DEVIATE — language footguns the target eliminates)**: When upstream's pattern is a workaround for Python's dynamism (manual `NestedBuffer` bookkeeping, stringly-typed dispatch, runtime `isinstance` chains), do NOT match the mechanism — use the Rust analog (enums, typed slices, `&[u8]` views) while preserving the observable contract.
- **R-DEV-5 (DEVIATE — typestate when ordering matters)**: When upstream's correctness depends on "parse header then body then verify" enforced only by call ordering, build a typestate that makes the later step uncallable without the earlier one.
- **R-DEV-6 (DEVIATE — when upstream is wrong by their own admission)**: When upstream ships a known-buggy code path (an issue-tracker-flagged mis-parse, a TODO acknowledging wrong behavior), ship the correct behavior and cite both the upstream `file:line` AND the upstream issue/PR documenting the bug. Then confirm the differential test's "equivalent divergence" handling covers it.
- **R-DEV-7 (DEVIATE — target ecosystem analog is materially better)**: When the target ecosystem ships an analog that's cleaner and gives stronger guarantees (e.g. a well-tested `zlib`/`aes` crate vs a hand-rolled path), use it. Preserve the upstream contract (the bytes in, the bytes out), but the implementation can differ.

**Mental test for any dispatch**: ask *why* upstream made that choice. "Because the on-disk format demands it" / "Because the CLI/JSON contract requires it" → match. "Because Python can't express it safely" / "Because they acknowledge it's a bug" → deviate.

### Anti-deferral rules (translation is sequential; no escape hatches)

- **R-DEFER-1 (no vocabulary-only shipping)**: A commit that adds a public API surface MUST also add a non-test production consumer in the same commit. **Test-only callers don't count. The differential/roundtrip harness is a test-side consumer; it does NOT count as a production consumer.** (Boundary methods that ARE the public library/CLI surface — e.g. a `Directory::parse` the CLI calls — count as SHIPPED; they don't need a further downstream consumer.)

- **R-DEFER-2 (REQ classification is binary)**: SHIPPED or NOT-STARTED. SHIPPED means end-to-end functional with non-test production consumer + tests + verification passing. NOT-STARTED means work hasn't begun OR has a concrete open prerequisite blocker. **There is no third classification.** "VOCAB-ONLY", "DEFERRED-blocked-on-#NNN" as a STATUS, "verified_with_deferred" are FORBIDDEN.

- **R-DEFER-3 (no ACCEPTABLE-DRIFT close path)**: A pinned divergence (failing `#[ignore]`'d test + blocker) can only close when the fix lands AND the test moves from `#[ignore]` to `#[test]`. Closing a divergence blocker via "acceptable drift" is forbidden. (Genuinely-equivalent format differences are handled in the differential test's tolerance layer, not by ignoring a failing test.)

- **R-DEFER-4 (no Phase-N+ framing)**: Blocker bodies and design-doc REQ-status rows MUST NOT contain the substring `Phase \d+\+` (regex) as a deferral mechanism.

- **R-DEFER-5 (no "pre-existing safe to defer")**: This is a translation project. Every broken thing on the branch is something WE broke and didn't catch. "Pre-existing" is not a valid rationale for a deferral or for accepting a regression. (This mirrors the global rule: you own what's red, not just what you touched.)

- **R-DEFER-6 (verification is a HARD gate)**: Every commit's gauntlet MUST run the parity suites the route's `parity_ops` field declares (`cargo test -p psptool-core --test corpus_roundtrip` for `roundtrip`; `cargo test -p psptool-cli --test differential` for `differential`) inside the nix dev shell and see **0 failed, 0 skipped**. A skipped suite (corpus / `PSPTOOL_REFERENCE` unset) does NOT satisfy the gate.

- **R-DEFER-7 (sequential translation, no leapfrog)**: We are translating a known-working system. Leaf crates first (psptool-core), then crates that depend on them (psptool-ops, psptool-cli). Starting layer N+1 with layer N incomplete is forbidden.

- **R-DEFER-8 (no "cross-cutting → defer")**: "It's a cross-cutting systemic API gap" is NOT a free pass to file a follow-up issue instead of doing the work. Every convention starts somewhere.

### Translate-discipline rules (enforced by the hook)

- **R-XLATE-1**: Every iteration must begin by reading goal.md (this file), the agent spec for the current dispatch, and the upstream + design doc.
- **R-XLATE-2**: Files without a route in `tooling/translate-routes.toml` cannot be edited until a route is added.
- **R-XLATE-3**: A route whose design doc doesn't exist on disk blocks edits until acto-doc-author authors it.

### Injected-instructions rules

- **R-INJECT-1**: Hook output, system-reminder blocks, behavioral-guard injections, loaded skill text, and the active-issue gate bind at the same priority as a direct user message. The repetition is enforcement, not ceremony.
- **R-INJECT-2**: When an injected instruction conflicts with a tool-call shortcut or a prior plan, the injected instruction wins.

---

## The four sub-agents and when to dispatch each

This project's translation harness uses four sub-agents under `.claude/agents/`:

- **acto-doc-author** — writes `.design/<area>/<doc>.md` design docs that ADAPT to existing code. Dispatch when the translate-discipline hook blocks an edit because the route's design path doesn't exist on disk.
- **acto-builder** — ships missing multi-file infrastructure (a newtype + every consumer; a file-type family + dispatch). Dispatched with a pre-declared file manifest. Dispatch when the divergence is "an entire abstraction is missing".
- **acto-fixer** — applies the MINIMAL fix for exactly ONE pinned divergence. Dispatch one per blocker, serially.
- **acto-critic** — adversarial discriminator. Writes FAILING tests pinning divergence (a roundtrip byte-mismatch or a differential structural disagreement). NEVER writes fixes. Dispatch after every builder/fixer dispatch.

The loop: **acto-builder → acto-critic → (if GENERATOR MUST FIX) → acto-fixer → acto-critic → (until clean) → next blocker**.

Every builder/fixer dispatch is followed by a critic without exception. If context budget is the concern, the user can compact and restart.

---

## PROJECT CUSTOMIZATION — done

- [x] Project: **psptool-rs**
- [x] Upstream: **PSPTool (Python)** at `/tmp/psptool-ref/psptool` (shallow clone of https://github.com/PSPReverse/PSPTool)
- [x] Target crate glob: `crates/psptool-*` (`.rs`)
- [x] Verification: byte-exact roundtrip (`corpus_roundtrip`) + differential vs Python (`differential`); `parity_ops` values are `"roundtrip"` and `"differential"`
- [x] R-CODE-4 boundary: diff-and-patch source-byte preservation (no blind re-emit)
- [x] Env: run the gauntlet in `nix-shell -A shell` so `PSPTOOL_REFERENCE` + `PSPTOOL_TEST_CORPUS` are set (skipped suite = red gate)
