# Upstream (PSPReverse/PSPTool) issue & PR review

Research pass over **all** upstream issues (46) and pull requests (40), classifying each
for relevance to psptool-rs. Goal: find correctness/robustness/coverage work worth adopting,
especially things upstream declined or left open but that are still valid.

Pulled via `gh ... --state all` on 2026-07-11. Upstream source read at `/tmp/psptool-ref/psptool/`.
psptool-rs code cross-checked under `crates/`.

Buckets:
- **IMPLEMENT** — a bug/gap/feature we should adopt.
- **COVERED** — upstream already fixed it (we inherit by translating) OR psptool-rs already handles it.
- **N/A** — packaging/CI/docs/discussion, or out of the parser+roundtripper scope.

## Summary — Issues

| # | Title | State | Bucket | Rationale |
|---|-------|-------|--------|-----------|
| 1 | How to calculate Version from EntryHeader | closed | COVERED | Version parse lives in `body.rs`/`entry.rs`. |
| 2 | VPS providers who have used this? | closed | N/A | Discussion. |
| 3 | Implement a psp_cleaner method | closed | N/A | Destructive "zero the PSP" tool; out of parser scope (dup of #56). |
| 4 | Rewrite the parsers in Kaitai | closed | N/A | Implementation-approach opinion. |
| 5 | rename main.py to __main__.py | closed | N/A | Python packaging. |
| 6 | Move metadata to setup.cfg | closed | N/A | Python packaging. |
| 7 | Comparing TR vs EPYC | closed | N/A | Discussion. |
| 8 | zlib incomplete/truncated stream | closed | COVERED | Upstream added decompress-fallback + zlib-length-from-stream; compressed-overrun path tracked by crosslink #40. |
| 9 | Distribute using pip | closed | N/A | Packaging. |
| 10 | Linux on PSP | closed | N/A | Discussion. |
| 11 | Backtrace on LVFS 8MB ROM | closed | COVERED | 8MB mask handled: `RomSize::MIB_8`, `address.rs::normalise_physical`. |
| 12 | Install on WSL Ubuntu | closed | N/A | Install support. |
| 13 | Use microcode repositories? | open | N/A | External microcode-DB matching; out of scope. |
| 18 | OverflowError on TRX40/EPYC Rome | closed | COVERED | Bounds-checked in Rust; multi-ROM/EPYC divergence tracked by crosslink #40/#41. |
| 19 | Rework rom-size detection | open | **IMPLEMENT** | ROM embedded in larger file (ISO/capsule) → wrong power-of-two mask → misparse. No manual override. |
| 20 | Replacing a whole PSP | open | N/A | Boot-behavior research; no parser change. |
| 21 | Multi-FET support and inline FETs | closed | COVERED | `fet.rs::scan_fet_candidates` (multi-FET). |
| 22 | APCB Parse | open | N/A | APCB/APOB internal format; upstream never did it → no parity value; large separate format. |
| 23 | JSON output support | closed | COVERED | `list` has JSON output (`list.rs`, snapshot tests). |
| 26 | Assertion on ASRock 4x4 (FET offset guess) | closed | COVERED/→19 | 8MB & multi-ROM added; residual "embedded in ISO, unknown mask" is #19. |
| 27 | AMD's SEV & SME | closed | N/A | Discussion. |
| 28 | error parsing T14 Gen 1 (2BHD magic) | closed | COVERED | 2BHD/combo handled (`fet.rs`, `magic.rs`). |
| 29 | 'Blob' has no attribute dual_rom | closed | COVERED | Python-only bug; not reproducible in Rust model. |
| 30 | Unable to parse Gigabyte X570 | closed | COVERED | Fixed upstream 2.4; corpus roundtrips. |
| 34 | Release recent fixes to PyPi | closed | N/A | Release request. |
| 35 | info loss with commit e963896 | closed | N/A | Reporter error (self-closed). |
| 37 | Improve deduplication of Entry objects | open | **IMPLEMENT** | Same physical region referenced by ≥2 directory entries; mutation must update all refs. |
| 38 | Introduce strict mode / be lenient | open | **IMPLEMENT** | We skip bad entries *silently*; upstream warns. Surface warnings + optional `--strict`. |
| 39 | Add more known entry types | open | COVERED | Name map in `psptool-ops/types.rs` (169 names). Keep in sync w/ upstream `file.py`. |
| 40 | Gigabyte WRX80 32MB crashes | open | COVERED | 32MB + `$PL2` upper-half handled; addressing tracked by crosslink #52. |
| 45 | Z13 bios can't be parsed (+Pluton) | open | COVERED | Zen4 AM5 tertiary tracked by crosslink #51; new entry types inherit. |
| 46 | question about ZEN_GENERATION_IDS | open | N/A | Q&A; actionable feature is #55. |
| 47 | PSPTool does not describe Coreboot images | open | COVERED* | FET-first discovery (`detect_rom_layout`) needs no UEFI/AGESA wrapper; verify w/ coreboot fixture. |
| 50 | extract/replace type 0x62 BIOS Binary | open | COVERED/→40 | `0x62` known (`id.rs`); compressed-0x62 extraction is the crosslink #40 path. |
| 51 | inline_keys not picked up (same-ID) | open | **IMPLEMENT** | Confirmed upstream bug: inline key whose ID == file's own ID shows `key_missing`. |
| 55 | print ZEN_GENERATION_IDS hex + codename | open | **IMPLEMENT** | Show full PSP ID hex + CPU codename in table; disambiguates directories. |
| 56 | me_cleaner for AMD PSP? | closed | N/A | Destructive; out of scope (dup #3). |
| 57 | Failing parse MSI X670E (0x48/0x4a) | closed | COVERED | Tertiary 0x48/0x4A + new magics tracked by crosslink #51. |
| 58 | PSPTool should require setuptools | closed | N/A | Packaging. |
| 59 | Limited APU support (verify + replace) | open | COVERED/→PR85 | Larger-blob replace is a general limitation; verify false-neg unpinnable w/o fixture. |
| 60 | 7840u parse error (0x48/0x4a, sha256+sha384) | closed | COVERED | Zen4/5 tracked by crosslink #51/#52; both-checksum abort = #38 strict/lenient. |
| 63 | Dragon Range unsupported | open | COVERED | Zen4 mobile tracked by crosslink #51/#52; 0x62 overrun = crosslink #40. |
| 66 | Key store file assertion error | open | COVERED/→38 | Assertion crash on misidentified zen5 key store = #38 robustness; key-store parsing is future. |

## Summary — Pull requests

Merged PRs are inherited by translation → COVERED. Non-merged (CLOSED/OPEN) PRs encode
declined-or-pending behavior and are examined individually.

| PR | Title | State | Bucket | Rationale |
|----|-------|-------|--------|-----------|
| 14 | fix update_entry_type | merged | COVERED | Inherited. |
| 15 | Don't choke on AGESA version parse | merged | COVERED | `rom.py` AGESA is optional in our model. |
| 16/17 | decryption capabilities / fix | merged | COVERED | `psptool-ops` decrypt/verify. |
| 24 | Json support | merged | COVERED | `list.rs` JSON. |
| 25/49/76/78 | add entry types (0x10062, 0x7c, ...) | merged | COVERED | `types.rs` name map. |
| 31 | Warn if a directory can't be parsed | **closed** | **IMPLEMENT (→38)** | Exactly the warn-and-continue behavior; author closed only because other crashes remained. |
| 32 | Fix some bugs | merged | COVERED | Inherited. |
| 33 | BIOS destination address | merged | COVERED | `destination`/address handling. |
| 36 | replace+resign SEV app [WIP] | **closed** | N/A | Re-signing needs AMD private keys; became a branch. `sign.rs` exists for self-signed. |
| 41 | handle 2BHD magic same as 2PSP | merged | COVERED | `magic.rs`. |
| 42/79 | Zen generation from combo dir | merged | COVERED | `directory.rs` generation. |
| 43/48 | signed_entry / hasattr signed_entity | merged | COVERED | `entry.rs` signature model. |
| 52 | errors.py spelling | merged | N/A | Docs. |
| 53 | multiple secondary dirs / new tertiary / rel addr | merged | COVERED | Tertiary tracked by crosslink #51; addr modes `address.rs`. |
| 61 | more info during json dumping | **closed** | N/A | Empty/superseded. |
| 62 | separate parsers for stricter subargs | **closed** | COVERED | clap subcommands already scope flags per-command. |
| 64/67/68/70 | Zen5 / parsing improvements | merged | COVERED | Zen5 tracked by crosslink #51/#52. |
| 65 | Fix pem issue | merged | COVERED | Pubkey/PEM path. |
| 69 | inconsistent results opening multiple files | merged | COVERED | Rust has no shared mutable global state. |
| 71 | Handle address mode | merged | COVERED | `address.rs`. |
| 72/75/80/73/74 | GH metrics workflow / tests | merged/closed | N/A | CI. |
| 77 | Fix replace | open | COVERED | `writer.rs` diff-and-patch *by design* avoids the 0x10-realign corruption (cites #77). |
| 78 | CPU_FEAT_CONFIG_TBL no-header | merged | COVERED | Header/no-header dispatch. |
| 82 | fix bad call during extract+decrypt | merged | COVERED | `extract.rs`. |
| 83 | entry offset addr mode + NO_SIZE sentinel | merged | COVERED | `address.rs` NO_SIZE handling. |
| 84 | AMD 4800S Desktop Kit | merged | COVERED | Corpus. |
| 85 | zen_generation for single-gen EPYC | open | **IMPLEMENT** | EPYC server BIOS returns `generation=None` silently on every dir. |
| 86 | repoint test-fixtures + EPYC scaffolding | open | N/A | Upstream test infra (the generation logic is #85). |

**Totals:** 46 issues (5 IMPLEMENT, 20 COVERED, 21 N/A) + 40 PRs (1 IMPLEMENT, 30 COVERED, 9 N/A).

---

## IMPLEMENT details

### #19 — Rework ROM-size detection (manual override) — MEDIUM
<https://github.com/PSPReverse/PSPTool/issues/19> (also #26)

**What:** The AMD bootloader masks flash addresses by ROM size (`0x7FFFFF` for 8MB,
`0xFFFFFF` for 16MB, etc.). When the PSP ROM is embedded inside a *larger* container
(a bootable-CD ISO, a UEFI capsule, a memory dump spanning two mmap windows — see #26's
64MB-vs-32MB HP Probook case), the input file size no longer equals the ROM size, so the
"largest power-of-two ≤ file length" heuristic picks the wrong mask and every address
mis-resolves.

**Why it matters:** Wrong mask → wrong offsets → total misparse (correctness). Upstream
left this **open** and endorsed "assume a default and provide an option to manually specify
the UEFI image size" — never shipped.

**psptool-rs today:** `crates/psptool-core/src/fet.rs::detect_rom_layout` picks
`MIB_32/16/8` as the largest power-of-two ≤ `blob_len`; no override.

**Impl note:** Add a caller-supplied `rom_size`/`rom_origin` override threaded into
`detect_rom_layout` (skip the heuristic when set), plus `--rom-size`/`--rom-offset` CLI flags
in `crates/psptool-cli/src/cli.rs`. Keeps byte-exact roundtrip (origin/size only affect masking).

### #37 — Deduplicate Entry objects referenced by multiple directories — LOW
<https://github.com/PSPReverse/PSPTool/issues/37>

**What:** One physical region (start+size) can be pointed at by multiple directory entries
across different directories. Upstream keeps a `Rom.unique_entries` set; the open issue asks
to deduplicate at the factory so the object model is consistent.

**Why it matters:** For psptool-rs the mutation path is the risk: `replace` patches by flash
offset, but each *directory record's* size field is a separate location. If two directory
records reference the same region, replacing must update **both** records (and both checksums),
or the second directory silently keeps a stale size → corrupt roundtrip. A parse-time
cross-reference index makes this correct and detectable.

**Impl note:** Build a `flash_offset → Vec<EntryRef>` index during the directory walk
(`crates/psptool-core/src/directory.rs`), consumed by
`crates/psptool-ops/src/replace.rs` so a size change fans out to every referencing record.

### #38 — Surface parse warnings + optional strict mode — LOW
<https://github.com/PSPReverse/PSPTool/issues/38> (reinforced by closed PR#31
<https://github.com/PSPReverse/PSPTool/pull/31>)

**What:** Upstream prints a `Warning: ...` for every entry/directory it can't parse and keeps
going; #38 additionally wants a *strict* mode (assert instead of warn) for scientific work,
and a *very lenient* mode to parse reconstructed/partial ROMs (sniffROM output).

**Why it matters:** psptool-rs already continues past unparseable records
(`directory.rs` `Err(_) => continue` at lines ~608/634/660/691) — but **silently**. That is a
differential-parity gap (upstream emits those warnings to stderr, we don't) and hurts
diagnosability of the exact issues in this list (#57/#60/#63/#66 are all "warned then crashed"
upstream). A collected warning list also lets `--strict` turn skips into hard errors.

**Impl note:** Thread a warning sink through the directory/entry walk
(`crates/psptool-core/src/directory.rs`, `entry.rs`) returning `(parsed, Vec<ParseWarning>)`;
render to stderr in the CLI; add `--strict` to escalate. No change to the happy-path roundtrip.

### #51 (upstream) — Inline pubkeys with same ID as the file are not resolved — MEDIUM
<https://github.com/PSPReverse/PSPTool/issues/51>

**What:** A signing pubkey can be *inline* inside another file's body. Upstream regression
(bisected to `0bda1bd`): inline keys are missed and their signed entries show `key_missing`
instead of `verified`. Maintainer memo confirms: "inline keys that happen to have the same ID
as the file itself are not shown."

**Why it matters:** Correctness of the verify/key column. If we translate upstream as-is we
inherit the bug. In psptool-rs, `crates/psptool-ops/src/verify.rs` builds its `key_id → pubkey`
map from **structured directory pubkey entries only** (the `pubkeys.entry(pk.key_id)` loop),
while inline keys are discovered separately by the heuristic scan in `search_keys.rs`
(`try_heuristic_at`). So a signature signed by an inline-only key can already surface as
`key_missing` — the same failure class.

**Impl note:** Feed heuristic/inline pubkey hits into the verify key map (or reuse
`search_keys_with_directories` as the single source of keys), and explicitly ensure a key whose
`key_id` equals the containing file's own ID is not filtered out. Add a fixture where the only
signer is an inline key. Files: `crates/psptool-ops/src/verify.rs`, `search_keys.rs`.

### #55 — Print full PSP ID hex + CPU codename in the generation column — LOW
<https://github.com/PSPReverse/PSPTool/issues/55>

**What:** The table shows a coarse "Zen N"; the reporter wants the full PSP/zen-generation ID
hex (e.g. `0xBC0C0140`) and ideally the codename (`Zen 3 (Cezanne)`), since the low bytes pin
the exact SoC. Upstream open, maintainer receptive but unsure of a clean single-table mapping.

**Why it matters:** Coverage/UX of the directory table and a concrete disambiguator for
combo/multi-generation images (directly answers #46). coreboot publishes many full IDs, so a
`PSP_ID → codename` map is tractable.

**Impl note:** The full ID is already read during combo/tertiary parsing
(`directory.rs`, cf. crosslink #51 step 3); carry it onto the directory and render hex + optional
codename lookup in `crates/psptool-ops/src/table.rs`. Guard the differential snapshots (this is
an additive column).

### PR#85 — Detect zen_generation for single-generation EPYC BIOSes — MEDIUM
<https://github.com/PSPReverse/PSPTool/pull/85>

**What:** EPYC server BIOSes (Naples–Turin) use a single FET → single `$PSP` + `$BHD` layout.
Neither existing detection path (combo_dir, tertiary self-tag) fires, so every directory/entry
comes back `zen_generation = None` — **silently**. The PR adds a third path: when a ROM's
directories are *uniformly* unclassified, read `PSP_FW_BOOT_LOADER` (entry type `0x01`) version
major and map it (`BOOTLOADER_VERSION_TO_ZEN`, Naples→Turin), applying to all directories
including the `$BHD` ones that carry no bootloader.

**Why it matters:** Correctness/coverage of generation labeling for the entire server line;
downstream tooling that bins by generation currently drops these rows. Distinct from crosslink
#52 (which is entry *address-mode* on upper-half dirs, not generation labeling). The PR is
conservative (only fires when every dir is `None`; warns on unknown bootloader version).

**Impl note:** In `crates/psptool-core/src/directory.rs` generation detection, add the
"all-`None` → read type `0x01` bootloader version major → map to generation" back-fill, and
warn when a bootloader exists but its version isn't in the table. Version major is at
`version[1]` for a Rome bootloader (per PR note) — verify byte order against `body.rs` version
slicing.

---

*Not filed (COVERED-with-caveat) but worth a verification pass:*
- **#47 coreboot `amdfw.rom`** — our FET-first `detect_rom_layout` doesn't require a UEFI/AGESA
  wrapper (unlike Python, whose `blob.roms` came up empty), so it likely already parses bare
  coreboot flash. Confirm with a coreboot fixture before claiming parity.
- **#39 entry-type table** — `psptool-ops/types.rs` should be diffed against the current
  `file.py` `DIRECTORY_ENTRY_TYPES`/`BIOS_DIRECTORY_ENTRY_TYPES` (~162 names) to catch any
  labels we're missing.
</content>
</invoke>
