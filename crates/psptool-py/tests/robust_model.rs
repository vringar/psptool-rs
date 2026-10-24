//! Robustness pin for the bindings' object-graph builder (`model.rs`) on a
//! crafted, untrusted image. Synthetic bytes only; no interpreter needed.

use std::process::Command;

use psptool_core::SourceBytes;
use psptool_core::magic::FET_MAGIC;

/// Set in the re-executed child of a test that may crash the process.
const CHILD_ENV: &str = "PSPTOOL_ROBUST_MODEL_CHILD";

/// `$PSP` directories chained by L2 (0x40) pointers.
const CHAIN_LEN: usize = 30_000;

/// Stack the build runs on. Below the 8 MiB of a Python main thread so the
/// test stays fast; the chain length is attacker-controlled (32 bytes per
/// link, ~250k links in an 8 MiB ROM), so every fixed stack is exhaustible.
const BUILD_STACK: usize = 1 << 20;

fn put_u32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// Severity: crash (process abort) on crafted input, `PSPTool.from_file`.
///
/// `Builder::create_directories` (`model.rs:295-326`) recurses into every L2
/// (0x40/0x49/0x70) and tertiary target of a freshly parsed directory, so a
/// chain `A1 -0x40-> A2 -0x40-> ... -> AN` costs one Rust stack frame per
/// link. Unlike the core walk (which needs a late generation id to recurse),
/// a plain chain suffices. The overflow aborts the interpreter that loaded the
/// extension — Python cannot catch it. `update_zen_generation`
/// (`model.rs:331-349`) recurses the same way.
///
/// Expected: the directory graph is built with an explicit worklist.
#[test]
fn robust_model_deep_l2_chain_does_not_overflow_stack() {
    if std::env::var_os(CHILD_ENV).is_none() {
        let status = Command::new(std::env::current_exe().expect("current test binary"))
            .args([
                "--exact",
                "robust_model_deep_l2_chain_does_not_overflow_stack",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_ENV, "1")
            .status()
            .expect("spawn child test process");
        assert!(
            status.success(),
            "model::build crashed on a {CHAIN_LEN}-deep L2 chain (stack overflow in \
             Builder::create_directories recursion): {status}"
        );
        return;
    }

    // 8 MiB image, FET at 0x20000 (rom_origin 0), chain of `$PSP` (mode 01,
    // flash offset) each holding one 0x40 record to the next link.
    let base = 0x10_0000usize;
    let mut buf = vec![0u8; 8 << 20];
    buf[0x2_0000..0x2_0004].copy_from_slice(FET_MAGIC.as_bytes());
    put_u32(&mut buf, 0x2_0004, base as u32);
    buf[0x2_0008..0x2_0018].fill(0xFF);
    for i in 0..CHAIN_LEN {
        let at = base + 0x20 * i;
        buf[at..at + 4].copy_from_slice(b"$PSP");
        put_u32(&mut buf, at + 8, 1);
        put_u32(&mut buf, at + 12, 0x2000_0000);
        if i + 1 < CHAIN_LEN {
            buf[at + 0x10] = 0x40;
            put_u32(&mut buf, at + 0x14, 0x20);
            put_u32(&mut buf, at + 0x18, (at + 0x20) as u32);
        }
    }

    let image = SourceBytes::from_blob(buf);
    let dirs = std::thread::Builder::new()
        .stack_size(BUILD_STACK)
        .spawn(move || _native::model::build(&image).dirs.len())
        .expect("spawn builder")
        .join()
        .expect("builder thread");
    assert_eq!(dirs, CHAIN_LEN);
}
