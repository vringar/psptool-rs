//! Divergence: `-E` / `-E -j` on an input without any FET.
//!
//! Upstream (PSPTool `241629b`) `blob.py:94` only warns "Could not find any
//! Firmware Entry Table!" on stderr; `ls()` then prints nothing and
//! `ls_json()` prints `[]`, exit 0. We used to exit 1. Tracking #133. The
//! comparison against the reference runs only when `PSPTOOL_REFERENCE` is set.

use std::path::{Path, PathBuf};
use std::process::Command;

fn fixtures() -> Vec<(&'static str, PathBuf)> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("no_fet");
    std::fs::create_dir_all(&dir).unwrap();
    [("8m", 8usize << 20), ("64m_plus", (64usize << 20) + 264)]
        .into_iter()
        .map(|(name, len)| {
            let p = dir.join(format!("{name}.bin"));
            std::fs::write(&p, vec![0u8; len]).unwrap();
            (name, p)
        })
        .collect()
}

fn run(cmd: &mut Command, file: &Path) -> (Option<i32>, String) {
    let out = cmd.arg(file).output().expect("spawn");
    (
        out.status.code(),
        String::from_utf8(out.stdout).expect("utf8 stdout"),
    )
}

#[test]
fn no_fet_listing_succeeds_and_matches_reference() {
    let reference = std::env::var_os("PSPTOOL_REFERENCE").filter(|v| !v.is_empty());
    if reference.is_none() {
        eprintln!("PSPTOOL_REFERENCE unset: skipping the oracle comparison");
    }
    for (name, file) in fixtures() {
        for (flags, expected) in [(&["-E"][..], ""), (&["-E", "-j"][..], "[]\n")] {
            let ours = run(
                Command::new(env!("CARGO_BIN_EXE_psptool")).args(flags),
                &file,
            );
            assert_eq!(ours, (Some(0), expected.to_string()), "{name} {flags:?}");
            if let Some(py) = &reference {
                let theirs = run(
                    Command::new(py)
                        .args(["-m", "psptool"])
                        .args(flags)
                        .env_remove("PYTHONPATH")
                        .current_dir(env!("CARGO_TARGET_TMPDIR")),
                    &file,
                );
                assert_eq!(ours, theirs, "{name} {flags:?}: ours vs reference");
            }
        }
    }
}
