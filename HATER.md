# The Hater's Code Review

**Change**: `272bd32..@` — session landing tertiary (0x48/0x4A) L2 walking (#51, #68), compressed-BIOS zlib sizing (#40/#59), FET scan ordering (#63), and replace-path Fletcher-32 recompute (#66)
**Date**: 2026-07-12
**Verdict**: Mediocre

The workflow discipline — divergence pinned in a failing test *before* the fix, upstream line citations on every branch, deviations named — is how this is supposed to be done, and it visibly pains me to say so. Which makes it worse that three of the four features ship with the same disease: a "SHIPPED" stamp in the module-doc REQ table over a parity hole the missing Zen4/multi-ROM corpus can't catch. A parity project that claims parity it doesn't have is lying with better formatting.

## Issues

### 1. Checksum recomputed from pristine source bytes, not editor state — silent wrong output
**Severity**: Major
**File**: `crates/psptool-ops/src/replace.rs`
**Lines**: 257–285 (esp. 277–278)

`recompute_directory_checksum` rebuilds the checksummed region from `dir_source.as_bytes()` — the *original* blob — and splices in exactly one change: this entry's new `size` field. The comment even asserts it's "the sole in-region change." That's an invariant about the *whole editor session*, enforced nowhere.

Concrete failure: `replace_entry_body(editor, &entry_a, shorter_a)` (the `dir_source: None` path — patches A's size field, no checksum), then `replace_bios_entry_body(editor, &parent, idx_b, shorter_b)` on the *same directory*. The recompute reconstructs the region with only B's new size; A's already-patched size field enters the Fletcher sum at its stale original value. `serialize()` emits an image whose directory checksum is **silently wrong** — in a firmware image someone may flash. Upstream can't have this bug because `update_checksum` (`directory.py:203-205`) reads the live buffer.

Second-order casualty: two length-changing family replaces in the same directory → the second `editor.patch(checksum_offset, …)` hits the first checksum patch → `PatchError` overlap. Upstream handles this sequence fine. So the design manages to be both silently wrong in one composition and loudly broken in another.

Root cause is that `BlobEditor` has no "read post-patch bytes" view, so the author reached for reconstruction-from-source and hoped. Either add that view, or at minimum reject/detect pre-existing patches inside `dir_source`'s range before computing.

### 2. `rewrite_size_field`'s "panic-proof" `.expect()` rests on an invariant this same session destroyed
**Severity**: Major
**File**: `crates/psptool-ops/src/replace.rs`
**Lines**: 226–228, 234

The doc comment: "`new_size` is guaranteed to fit in `u32` by the caller (it is bounded by the original entry's `size`, which is parsed from a wire `u32`)." That was true at baseline. Then this session's own `entry.rs` change made `entry.body.len()` for a zlib-recovered entry equal `zlib_hdr + zlib_size` (`entry.rs:558`) — bounded by `blob.len()`, **not** by the wire `u32`. `zlib_size` is an attacker-controlled LE u32 read straight off flash; `zlib_hdr` adds up to 0x4FF more.

Adversarial input: a ≥4 GiB crafted image with a compressed over-ROM BIOS entry, `zlib_size = 0xFFFF_FFFF`, blob big enough that `blob.slice(local, body_len)` succeeds → `body.len() > u32::MAX` → caller passes a `new_body` of length `u32::MAX + 1 ≤ original_len` → `u32::try_from(new_size).expect(...)` **panics** at `replace.rs:234`. R-CODE-2 says malformed input yields typed `Err`, not panic. Yes, a 4 GiB firmware image is absurd. The rule doesn't have an absurdity exemption, and the expect message is now documentation that lies. Return `ReplaceError` and move on.

### 3. Zlib-recovery trigger uses the whole-file boundary, not the ROM window
**Severity**: Major
**File**: `crates/psptool-core/src/entry.rs`
**Lines**: 517, 537

Upstream's recovery condition is overrun of the **parent ROM buffer**: `parent_buffer.buffer_size >= entry.file_offset() + entry.size` (`file.py:297`), where `parent_buffer` is the 8/16 MiB `Rom` window. Rust compares `body_end > blob_end` where `blob_end` is the end of the **entire input file** (`load.rs` passes the whole blob). For a bare single-ROM dump these coincide, which is why the corpus differential is green. For a dual-ROM 32 MiB image or a capsule with trailing bytes, they don't: a compressed entry near the end of ROM#0 whose declared size spills into ROM#1's bytes takes the *normal* path here (body happily crosses the ROM boundary into another ROM's data) while upstream takes the recovery path. Different body length → different `ls` size → parity broken. The zlib magic scan and `zlib_size` read (`entry.rs:547–557`) similarly range over file bytes upstream cannot see (`self.blob[offset:]` is ROM-windowed, `file.py:304`).

The insulting part: `rom_size` and `rom_origin` are *parameters of this function*. The correct bound — `rom_origin + rom_size` clamped to `blob_end` — was in scope and unused. The existing multi-ROM SKIP entry in `differential.rs` will keep masking this until someone wonders why dual-ROM parity never converges.

### 4. Tertiary walk discards the generation id upstream displays — the new feature ships pre-diverged
**Severity**: Major
**File**: `crates/psptool-core/src/directory.rs`
**Lines**: 782–806 (`tertiary_actual_offset`), vs `psptool-ops/src/list.rs:531`

Upstream doesn't just resolve `block[16:20]`; it derives `zen_generation = get_possible_zen_generation(block[21:24]) + f' (PSP ID {hex(block[20:24])})'` and stamps it on the created directory (`directory.py:88–98`), and `ls` prints it in the Generation column (`psptool.py:84`). The Rust walk reads the 32-byte block, extracts the offset, and throws the other 28 bytes away; `directory_generation` returns `""` for any `L2Pointer`-provenance directory. So the very Zen 4+ images this feature exists to handle will diverge in `ls` output on the very first directory the double-indirection surfaces. The doc comment pre-emptively rationalizes: the generation "is not needed to resolve the target." Correct, and irrelevant — this is a *parity* project, and the display string is part of the surface. No Zen4 corpus exists yet (hence the PSP-DB harness landed this session), so nothing red exists to force the issue — which is exactly when "SHIPPED" stamps get dangerous.

Related, same walk: upstream emits all secondaries, then all tertiaries, depth-first per directory (`directory.py:83–99`); the Rust worklist interleaves by entry order and pops LIFO. Directory *ordering* in `ls` is unpinned for any image where those differ. Partly pre-existing structure, but the tertiary branch doubled the exposure.

### 5. Replace updates one referencing directory; upstream updates all of them
**Severity**: Major
**File**: `crates/psptool-ops/src/replace.rs`
**Lines**: 128–153, 201–211

Upstream `move_buffer` iterates `for directory in self.references: directory.update_entry_fields(...)` (`file.py:385–393`) — and `references` accrues every directory that points at the same body (`file.py:49`), which is routine (the same blob referenced from `$PSP` and `$PL2`, L1 and L2 BIOS dirs, multi-ROM sharing). A length-changing replace upstream rewrites the size field *and* checksum in **every** referencing directory. The Rust path patches exactly the one `parent` handed in; sibling directories keep the stale size and stale checksum. Output bytes diverge from upstream, and the resulting image is internally inconsistent (two records for one body disagreeing about its size). The module's "What this module does NOT do" section — which dutifully lists re-signing and CLI — doesn't mention this. Scope-limiting is fine; *undocumented* scope-limiting in a file whose REQ table reads SHIPPED×7 is not.

### 6. Secondary pointers never get the plain `addr_mask` the tertiary fix so proudly cites
**Severity**: Minor
**File**: `crates/psptool-core/src/directory.rs`
**Lines**: 678–679, 725–726 vs 799–805

Upstream `from_offset` masks **every** directory offset it's handed — secondary or tertiary — with the plain mask (`rom_offset &= fet.rom.addr_mask`, `directory.py:105`). The #68 fix applied that mask to the tertiary inner target, with a long, correct comment about why plain-mask, not the PhysicalX86 window. Three lines up, the secondary branch resolves through `resolve_with_entry` and applies **no** final mask: a mode-1 offset ≥ rom_size that upstream wraps into a valid directory is passed through unmasked here, `parse_at` fails, pointer silently skipped — a directory upstream finds, we don't. Pre-existing for secondaries, so I'm grading it Minor, but landing a mask-parity fix while enshrining the asymmetry in the adjacent `if` branch takes a special kind of tunnel vision.

## What is — regrettably — correct

- `scan_fet_candidates` two-pass rewrite: ordering matches `_find_fets` exactly; I checked the 8-byte signatures for self-overlap (there is none), so the naive scan is equivalent to `re.finditer`. Short-blob guard present. Fine. The double O(n) scan with per-position slice compare is lazy but harmless at 32 MiB.
- `zlib_find_header` is a faithful mirror down to the per-magic 0x100-first heuristic and 0x500 cap, with every slice access fallible. No complaints, which annoys me.
- The tertiary plain-mask-vs-window reasoning (#68) is right, and the `local_offset`-guarded 32-byte block read cannot panic on truncated input.
- `recompute_directory_checksum`'s even-length argument is structurally sound (16-byte header + 16/24-byte records ⇒ region length always even), so the `FletcherError` arm is genuinely unreachable for parsed directories — a correct claim, for once.
- `is_compressed` = `(flags >> 3) & 1` matches `file.py:281`; PSP entries hardwired uncompressed matches `file.py:282-283`.
- Fletcher output endianness (`to_le_bytes`) matches `struct.pack('<I', …)`.
- Commit messages are specific, issue-linked, and honest. 403 tests + 50 corpus-differential tests green, verified myself.

## Closing Remarks

The craft here is above the median — pinned divergences, cited deviations, fallible parsing throughout. But four of five Major findings are the same sin wearing different hats: declaring parity ("SHIPPED", "panic-proof", "sole in-region change") on the strength of a corpus that cannot falsify the claim. The tertiary feature diverges on the Generation column of every image it was built for; the zlib fix guards the wrong boundary; the checksum recompute is correct only for editor histories nobody promised to have. Fix the checksum reconstruction and the ROM-window bound before anyone builds on them, and downgrade the REQ stamps to match reality. Reality doesn't read your module docs.
