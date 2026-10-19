//! Shared helpers for the Python-driven integration tests: stage an
//! importable `psptool` package from this build and run interpreters on it.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Directory of this crate's test scripts.
pub fn scripts() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")
}

/// The extension module cargo built for this test run. `cargo test` writes
/// the cdylib into `deps/` next to the test executable and does not uplift
/// it to the profile directory, whose copy may be stale (from an earlier
/// `cargo build`), so only `deps/` is consulted.
fn built_extension() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let deps = exe.parent().ok_or("test executable has no directory")?;
    let name = if cfg!(target_os = "macos") {
        "lib_native.dylib"
    } else {
        "lib_native.so"
    };
    let path = deps.join(name);
    if path.is_file() {
        Ok(path)
    } else {
        Err(format!("extension module {} not built", path.display()))
    }
}

/// Copy `python/psptool/*.py` and the freshly built extension into
/// `<target tmp>/<label>/psptool/`; returns the directory to put on
/// `PYTHONPATH`.
pub fn stage(label: &str) -> Result<PathBuf, String> {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(label);
    let package = root.join("psptool");
    if root.exists() {
        std::fs::remove_dir_all(&root).map_err(|e| format!("clearing {}: {e}", root.display()))?;
    }
    std::fs::create_dir_all(&package)
        .map_err(|e| format!("creating {}: {e}", package.display()))?;
    let sources = Path::new(env!("CARGO_MANIFEST_DIR")).join("python/psptool");
    let entries =
        std::fs::read_dir(&sources).map_err(|e| format!("reading {}: {e}", sources.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().is_some_and(|x| x == "py")
            && let Some(name) = path.file_name()
        {
            std::fs::copy(&path, package.join(name))
                .map_err(|e| format!("copying {}: {e}", path.display()))?;
        }
    }
    let extension = built_extension()?;
    std::fs::copy(&extension, package.join("_native.abi3.so"))
        .map_err(|e| format!("copying {}: {e}", extension.display()))?;
    Ok(root)
}

/// Run `python script args...`, with `pythonpath` (if any) as the only
/// `PYTHONPATH` entry, from a neutral working directory.
pub fn python(
    python: &Path,
    pythonpath: Option<&Path>,
    script: &Path,
    args: &[&std::ffi::OsStr],
) -> Result<Output, String> {
    let mut cmd = Command::new(python);
    cmd.arg(script)
        .args(args)
        .env_remove("PYTHONPATH")
        .current_dir(env!("CARGO_TARGET_TMPDIR"));
    if let Some(path) = pythonpath {
        cmd.env("PYTHONPATH", path);
    }
    cmd.output()
        .map_err(|e| format!("spawning {}: {e}", python.display()))
}

/// Stdout of a successful run, or the failure with its stderr.
pub fn stdout_of(output: Output, what: &str) -> Result<String, String> {
    if !output.status.success() {
        return Err(format!(
            "{what} failed ({}):\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("{what}: non-UTF-8 output: {e}"))
}
