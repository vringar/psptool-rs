//! Runs `tests/test_api.py` (corpus-free `unittest` suite on a synthetic
//! image) against the extension module of this build.
//!
//! The interpreter is `PYO3_PYTHON` when set, else `python3` — the one the
//! extension was built against (pyo3 links its libpython). A missing
//! interpreter fails the test: it cannot be absent where this crate builds.

mod common;

use std::path::PathBuf;

#[test]
fn python_api_suite() {
    let python = std::env::var_os("PYO3_PYTHON")
        .filter(|v| !v.is_empty())
        .map_or_else(|| PathBuf::from("python3"), PathBuf::from);
    let stage = match common::stage("psptool-py-api-stage") {
        Ok(s) => s,
        Err(e) => panic!("staging the package: {e}"),
    };
    let script = common::scripts().join("test_api.py");
    let output = match common::python(&python, Some(&stage), &script, &["-v".as_ref()]) {
        Ok(o) => o,
        Err(e) => panic!("{e}"),
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "test_api.py failed:\n{stderr}");
    assert!(
        stderr.contains("\nOK"),
        "unexpected unittest report:\n{stderr}"
    );
}
