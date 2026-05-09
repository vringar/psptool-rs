//! Corpus loader keyed off the `PSPTOOL_TEST_CORPUS` environment variable.
//!
//! The corpus is a private git submodule (~315 MB) at `vendor/test-corpus`.
//! The dev shell exports `PSPTOOL_TEST_CORPUS` whenever the submodule is
//! populated; otherwise the variable is unset and corpus-gated tests skip.
//!
//! ROM files live under `<corpus_root>/test_files/`. The iterator yields
//! every regular file in that directory (sorted by name for determinism),
//! reading bytes lazily. A reader-side error is surfaced as the iterator
//! item type so a single unreadable file does not abort the run.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Environment variable that points at the `vendor/test-corpus` checkout.
///
/// Set by `shell.nix` whenever the submodule is populated; absent otherwise so
/// corpus-gated integration tests can skip cleanly.
pub const CORPUS_ENV: &str = "PSPTOOL_TEST_CORPUS";

/// Subdirectory under the corpus root that holds the firmware images.
const TEST_FILES_DIR: &str = "test_files";

/// Returns the corpus root if `PSPTOOL_TEST_CORPUS` is set and non-empty.
///
/// Returns `None` when the variable is unset or empty — callers should treat
/// this as "skip the corpus-gated test", not as an error. This matches the
/// `vendor/test-corpus` submodule being optional.
pub fn corpus() -> Option<PathBuf> {
    match std::env::var_os(CORPUS_ENV) {
        Some(value) if !value.is_empty() => Some(PathBuf::from(value)),
        _ => None,
    }
}

/// One ROM image loaded from the corpus.
///
/// `name` is the file name as it appears in `test_files/` (no path components),
/// and `bytes` is the full file contents read into memory. Tests typically
/// destructure with [`CorpusRom::name`] and [`CorpusRom::bytes`].
#[derive(Clone, Debug)]
pub struct CorpusRom {
    name: String,
    bytes: Vec<u8>,
}

impl CorpusRom {
    /// File name as it appears under `test_files/`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Full file contents as a byte slice.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Move out the owned byte buffer, e.g. when the consumer wants to mutate
    /// the bytes for a roundtrip test without cloning.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Iterator over corpus ROM files under an explicit root.
///
/// Yields each regular file in `<root>/test_files/` in lexicographic order,
/// reading the contents on demand. The iterator is empty when the directory
/// does not exist (the directory entry case used by hermetic unit tests
/// that point at a temp dir, and the "submodule not populated" case where the
/// corpus root exists but `test_files/` is missing).
pub fn corpus_roms_in(root: &Path) -> CorpusRoms {
    let test_files = root.join(TEST_FILES_DIR);
    let entries = match fs::read_dir(&test_files) {
        Ok(reader) => {
            let mut paths: Vec<PathBuf> = reader
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.file_type().map(|ft| ft.is_file()).unwrap_or(false))
                .map(|entry| entry.path())
                .collect();
            paths.sort();
            paths
        }
        Err(_) => Vec::new(),
    };
    CorpusRoms {
        paths: entries.into_iter(),
    }
}

/// Iterator over corpus ROM files keyed off the `PSPTOOL_TEST_CORPUS`
/// environment variable.
///
/// Returns an empty iterator when the variable is unset or empty. This is the
/// expected behaviour when the optional `vendor/test-corpus` submodule has
/// not been initialised — corpus-gated tests skip cleanly.
pub fn corpus_roms() -> CorpusRoms {
    match corpus() {
        Some(root) => corpus_roms_in(&root),
        None => CorpusRoms {
            paths: Vec::new().into_iter(),
        },
    }
}

/// Iterator returned by [`corpus_roms`] / [`corpus_roms_in`].
pub struct CorpusRoms {
    paths: std::vec::IntoIter<PathBuf>,
}

impl Iterator for CorpusRoms {
    type Item = io::Result<CorpusRom>;

    fn next(&mut self) -> Option<Self::Item> {
        let path = self.paths.next()?;
        let name = path
            .file_name()
            .and_then(OsStr::to_str)
            .map(str::to_owned)
            .unwrap_or_default();
        match fs::read(&path) {
            Ok(bytes) => Some(Ok(CorpusRom { name, bytes })),
            Err(err) => Some(Err(io::Error::new(
                err.kind(),
                format!("reading {}: {err}", path.display()),
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_env_var_name_is_stable() {
        // The shell.nix and downstream tooling key off this exact name; if it
        // changes, both sides need to move together.
        assert_eq!(CORPUS_ENV, "PSPTOOL_TEST_CORPUS");
    }

    #[test]
    fn corpus_roms_in_missing_dir_is_empty() {
        let tmp = tempdir_unique("psptool-fixtures-empty");
        let count = corpus_roms_in(&tmp).count();
        assert_eq!(count, 0);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn corpus_roms_in_yields_files_sorted_with_bytes() {
        let tmp = tempdir_unique("psptool-fixtures-yields");
        let test_files = tmp.join(TEST_FILES_DIR);
        fs::create_dir_all(&test_files).unwrap();
        // Create out-of-order so we can verify sorted iteration.
        fs::write(test_files.join("zzz.bin"), b"ZZ").unwrap();
        fs::write(test_files.join("aaa.bin"), b"A").unwrap();
        fs::write(test_files.join("mmm.bin"), b"MID").unwrap();
        // A subdirectory should be skipped (we only yield regular files).
        fs::create_dir_all(test_files.join("subdir")).unwrap();

        let roms: Vec<CorpusRom> = corpus_roms_in(&tmp).map(|r| r.expect("read")).collect();
        let names: Vec<&str> = roms.iter().map(CorpusRom::name).collect();
        assert_eq!(names, ["aaa.bin", "mmm.bin", "zzz.bin"]);
        assert_eq!(roms[0].bytes(), b"A");
        assert_eq!(roms[1].bytes(), b"MID");
        assert_eq!(roms[2].bytes(), b"ZZ");

        let _ = fs::remove_dir_all(&tmp);
    }

    /// Cheap unique-per-test temp dir without pulling in a `tempfile` dep.
    /// Uses the test thread name (`tests::<name>`) plus the process id so
    /// concurrent test runs don't collide.
    fn tempdir_unique(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let pid = std::process::id();
        let thread = std::thread::current();
        let suffix = thread.name().unwrap_or("anon").replace("::", "_");
        p.push(format!("{tag}-{pid}-{suffix}"));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }
}
