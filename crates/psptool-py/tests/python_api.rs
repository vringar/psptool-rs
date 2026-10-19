//! Corpus-free Python suites against the extension module of this build.
//!
//! * `python_api_suite` runs `tests/test_api.py` (`unittest` on a synthetic
//!   image). The interpreter is `PYO3_PYTHON` when set, else `python3` — the
//!   one the extension was built against (pyo3 links its libpython). A
//!   missing interpreter fails the test: it cannot be absent where this crate
//!   builds.
//! * `subclass_parity_with_reference` runs `tests/oracle_subclass.py`
//!   (ROM-less Python subclasses of the model classes, PSP-DB's
//!   `FakeHeaderFile` pattern) under the reference interpreter
//!   (`PSPTOOL_REFERENCE`, vringar/PSPTool `241629b`) twice — importing
//!   upstream PSPTool, then with the bindings first on `PYTHONPATH` — and
//!   requires identical output after the implementation banner. Like the
//!   corpus suites it self-skips when `PSPTOOL_REFERENCE` is unset; the nix
//!   dev shell always sets it.

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

#[test]
fn subclass_parity_with_reference() {
    let Some(reference) = std::env::var_os("PSPTOOL_REFERENCE").filter(|v| !v.is_empty()) else {
        eprintln!("PSPTOOL_REFERENCE unset: skipping the reference comparison");
        return;
    };
    let reference = PathBuf::from(reference);
    let stage = match common::stage("psptool-py-subclass-stage") {
        Ok(s) => s,
        Err(e) => panic!("staging the package: {e}"),
    };
    let script = common::scripts().join("oracle_subclass.py");
    let run = |pythonpath: Option<&std::path::Path>, what: &str| {
        let out = common::python(&reference, pythonpath, &script, &[]);
        match out.and_then(|out| common::stdout_of(out, what)) {
            Ok(stdout) => stdout,
            Err(e) => panic!("{e}"),
        }
    };
    let theirs = run(None, "reference run");
    let ours = run(Some(&stage), "bindings run");
    let (mut theirs, mut ours) = (theirs.lines(), ours.lines());
    let (their_impl, our_impl) = (theirs.next(), ours.next());
    assert!(
        their_impl.is_some_and(|l| l.contains("\"reference\""))
            && our_impl.is_some_and(|l| l.contains("\"psptool-rs\"")),
        "wrong implementations under test: {their_impl:?} / {our_impl:?}"
    );
    let mut count = 0usize;
    loop {
        match (theirs.next(), ours.next()) {
            (None, None) => break,
            (t, o) => assert_eq!(
                o, t,
                "subclass behaviour diverges after {count} identical cases"
            ),
        }
        count += 1;
    }
    assert!(count > 0, "the oracle printed no cases");
}
