//! Robustness pins for `walk_directories` (`directory.rs`) on crafted,
//! untrusted images. Each test builds a small synthetic image in memory; no
//! firmware bytes are involved.
//!
//! These are not upstream-parity pins: they assert resource bounds a parser of
//! untrusted input must keep regardless of what the reference tool does.

use std::process::Command;

use psptool_core::{
    Directory, FlashOffset, RomSize, SourceBytes, fet::Fet, magic::FET_MAGIC, walk_directories,
};

/// Set in the re-executed child of a test that may crash the process.
const CHILD_ENV: &str = "PSPTOOL_ROBUST_WALK_CHILD";

/// Re-run the single test `name` in a child process and report how it ended.
/// A stack overflow aborts the whole process (it is not a panic), so the only
/// way to turn it into an ordinary test failure is to observe it from outside.
fn run_in_child(name: &str) -> std::process::ExitStatus {
    Command::new(std::env::current_exe().expect("current test binary"))
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, "1")
        .status()
        .expect("spawn child test process")
}

fn put_u32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// FET at `fet_off` with one pointer slot per entry of `ptrs`, then the
/// 16-byte `0xFF` terminator.
fn put_fet(buf: &mut [u8], fet_off: usize, ptrs: &[u32]) {
    buf[fet_off..fet_off + 4].copy_from_slice(FET_MAGIC.as_bytes());
    for (i, &p) in ptrs.iter().enumerate() {
        put_u32(buf, fet_off + 4 + 4 * i, p);
    }
    let term = fet_off + 4 + 4 * ptrs.len();
    buf[term..term + 16].fill(0xFF);
}

/// `$PSP` header, mode 01 (flash offset: v2 `additional_info` bits[30:29]).
fn put_psp_header(buf: &mut [u8], at: usize, count: u32) {
    buf[at..at + 4].copy_from_slice(b"$PSP");
    put_u32(buf, at + 8, count);
    put_u32(buf, at + 12, 0x2000_0000);
}

/// One 16-byte PSP entry record.
fn put_psp_entry(buf: &mut [u8], at: usize, entry_type: u8, size: u32, offset: u32) {
    buf[at] = entry_type;
    put_u32(buf, at + 4, size);
    put_u32(buf, at + 8, offset);
}

/// Number of `$PSP` directories chained by L2 (0x40) pointers. Each needs one
/// `Walk::merge` frame when a late generation id cascades down the chain.
const CHAIN_LEN: usize = 30_000;

/// Stack the walk runs on. Deliberately below the CLI main thread's 8 MiB so
/// the test stays fast: the recursion depth is attacker-controlled (a 16 MiB
/// image holds ~500k 32-byte links), so every fixed stack is exhaustible.
/// Measured on 8 MiB: debug overflows between 30k and 40k links, release
/// between 80k and 160k.
const WALK_STACK: usize = 1 << 20;

/// Severity: crash (process abort) on crafted input.
///
/// `Walk::merge` (`directory.rs:634-644`) cascades a newly-seen generation id
/// down the L2 graph by plain recursion, one stack frame per L2 hop.
/// `walk_directories` builds a chain `A1 -0x40-> A2 -0x40-> ... -> AN` (every
/// directory inheriting `A1`'s empty generation set), and only then meets a
/// tertiary (0x48) entry in `AN` whose block points back at `A1` with a new
/// generation id. `visit(A1, [g])` merges into the existing `A1`, which
/// recurses `merge(A2)`, `merge(A3)`, ... `merge(AN)`: recursion depth equals
/// the chain length an attacker controls (32 bytes per link, so a 16 MiB image
/// holds ~500k links). The thread overflows its stack and the process aborts
/// — not a catchable panic, so `psptool ls`, `verify`, `extract` and the Python
/// binding all die on such an image. Without the tertiary back-edge the same
/// chain walks fine, so the cascade is the culprit.
///
/// Expected: the cascade is iterative (or depth-bounded) and the walk
/// returns.
#[test]
fn robust_walk_generation_cascade_does_not_overflow_stack() {
    if std::env::var_os(CHILD_ENV).is_none() {
        let status = run_in_child("robust_walk_generation_cascade_does_not_overflow_stack");
        assert!(
            status.success(),
            "walk_directories crashed on a {CHAIN_LEN}-deep L2 chain with a late \
             generation id (stack overflow in Walk::merge recursion): {status}"
        );
        return;
    }

    let chain_base = 0x10_0000usize;
    let link = 0x20usize; // header + one entry
    let block_off = chain_base + CHAIN_LEN * link;
    let mut buf = vec![0u8; block_off + 0x40];

    put_fet(&mut buf, 0x2_0000, &[chain_base as u32]);
    for i in 0..CHAIN_LEN {
        let at = chain_base + i * link;
        put_psp_header(&mut buf, at, 1);
        if i + 1 < CHAIN_LEN {
            // 0x40 = PSP_FW_L2_PTR -> next link.
            put_psp_entry(&mut buf, at + 0x10, 0x40, 0x20, (at + link) as u32);
        } else {
            // 0x48 tertiary -> 32-byte block whose [16:20] points back at A1
            // and whose [20:24] carries a fresh generation id.
            put_psp_entry(&mut buf, at + 0x10, 0x48, 0x20, block_off as u32);
        }
    }
    put_u32(&mut buf, block_off + 16, chain_base as u32);
    put_u32(&mut buf, block_off + 20, 0xBC0B_0500);

    let blob = SourceBytes::from_blob(buf);
    let fet = Fet::parse_at(&blob, FlashOffset(0x2_0000)).expect("FET parses");
    let dirs = std::thread::Builder::new()
        .stack_size(WALK_STACK)
        .spawn(move || walk_directories(&blob, &fet, RomSize::MIB_8, FlashOffset::ZERO).len())
        .expect("spawn walker")
        .join()
        .expect("walker thread");
    assert_eq!(dirs, CHAIN_LEN);
}

/// Severity: memory exhaustion (quadratic in image size).
///
/// `walk_directories` dedups directories by header offset only
/// (`directory.rs:611-618`), and every parsed directory owns a
/// `Vec<PspEntry>` of `count` records (`directory.rs:409-416`, ~56 bytes per
/// 16-byte record). Directories whose entry tables overlap are therefore all
/// materialised in full: `D` FET slots pointing at `D` headers spaced 16 bytes
/// apart, each claiming every remaining record up to the end of the image,
/// cost `O(D * image_len)` memory. On a 16 MiB image with a few thousand FET
/// slots that is tens of GiB before `ls` prints anything.
///
/// A well-formed image never has overlapping directory tables, so the total
/// number of records the walk materialises is bounded by `image_len / 16`.
/// Expected: the walk keeps that bound (reject or share overlapping tables,
/// or budget the total).
#[test]
#[ignore = "crosslink #141"]
fn robust_walk_overlapping_directories_bounded_entries() {
    const IMAGE_LEN: usize = 0x4_0000; // 256 KiB keeps the failing case at ~70 MB
    const DIRS: usize = 64;
    let dir_base = 0x1_0000usize;
    let mut buf = vec![0u8; IMAGE_LEN];

    let ptrs: Vec<u32> = (0..DIRS).map(|i| (dir_base + 0x10 * i) as u32).collect();
    put_fet(&mut buf, 0x100, &ptrs);
    for i in 0..DIRS {
        let at = dir_base + 0x10 * i;
        let count = (IMAGE_LEN - at - 0x10) / 0x10;
        put_psp_header(&mut buf, at, count as u32);
    }

    let blob = SourceBytes::from_blob(buf);
    let fet = Fet::parse_at(&blob, FlashOffset(0x100)).expect("FET parses");
    let dirs = walk_directories(&blob, &fet, RomSize::MIB_8, FlashOffset::ZERO);
    let total: usize = dirs
        .iter()
        .map(|d| match &d.directory {
            Directory::Psp(p) => p.entries.len(),
            Directory::Bios(b) => b.entries.len(),
            Directory::Combo(c) => c.entries.len(),
        })
        .sum();
    assert!(
        total <= IMAGE_LEN / 0x10,
        "walk materialised {total} directory records from a {IMAGE_LEN}-byte image \
         ({} directories with overlapping tables); bound is {}",
        dirs.len(),
        IMAGE_LEN / 0x10
    );
}

/// Severity: hang (quadratic time in image size).
///
/// `Walk::visit` dedups by a linear scan over every directory recorded so far
/// (`directory.rs:611-614`) and `Walk::visit_l2` dedups child edges with
/// `Vec::contains` (`directory.rs:652`), so `D` distinct directories cost
/// `O(D^2)`. One `$PSP` with `D` L2 (0x40) entries, each pointing at its own
/// empty `$PL2`, needs 32 bytes per directory: a 16 MiB image holds ~500k, i.e.
/// ~10^11 comparisons before `ls` prints a line (measured: 160k chained
/// directories take ~150 s in a release build).
///
/// Expected: dedup by a hash/ordered set keyed on the header offset, so the
/// walk is near-linear. The budget below is generous for 100k directories.
#[test]
#[ignore = "crosslink #144"]
fn robust_walk_many_directories_near_linear_time() {
    const CHILDREN: usize = 100_000;
    const BUDGET: std::time::Duration = std::time::Duration::from_secs(10);
    let parent = 0x1_0000usize;
    let child_base = parent + 0x10 + 0x10 * CHILDREN;
    let mut buf = vec![0u8; child_base + 0x10 * CHILDREN];

    put_fet(&mut buf, 0x100, &[parent as u32]);
    put_psp_header(&mut buf, parent, CHILDREN as u32);
    for i in 0..CHILDREN {
        let child = child_base + 0x10 * i;
        put_psp_entry(&mut buf, parent + 0x10 + 0x10 * i, 0x40, 0x10, child as u32);
        buf[child..child + 4].copy_from_slice(b"$PL2");
        put_u32(&mut buf, child + 12, 0x2000_0000);
    }

    let blob = SourceBytes::from_blob(buf);
    let fet = Fet::parse_at(&blob, FlashOffset(0x100)).expect("FET parses");
    let (tx, rx) = std::sync::mpsc::channel();
    // Detached: if the walk blows the budget the test fails and the process
    // exits without waiting for it.
    std::thread::spawn(move || {
        let _ = tx.send(walk_directories(&blob, &fet, RomSize::MIB_8, FlashOffset::ZERO).len());
    });
    match rx.recv_timeout(BUDGET) {
        Ok(n) => assert_eq!(n, CHILDREN + 1),
        Err(_) => panic!(
            "walk_directories did not finish {} directories within {BUDGET:?} \
             (quadratic dedup in Walk::visit / visit_l2)",
            CHILDREN + 1
        ),
    }
}
