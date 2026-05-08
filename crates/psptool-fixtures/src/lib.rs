//! `psptool-fixtures` — shared test-corpus discovery and micro-fixtures.
//!
//! This skeleton ships only the corpus-root lookup (the env var is already
//! exported by `shell.nix` when the submodule is present). Issue #16 layers
//! the real corpus loader and micro-fixtures on top.

#![forbid(unsafe_code)]

use std::path::PathBuf;

/// Environment variable that points at the `vendor/test-corpus` checkout.
///
/// Set by `shell.nix` whenever the submodule is populated; absent otherwise so
/// corpus-gated integration tests can skip cleanly.
pub const CORPUS_ENV: &str = "PSPTOOL_TEST_CORPUS";

/// Returns the corpus root if `PSPTOOL_TEST_CORPUS` is set in the environment.
///
/// Returns `None` when the variable is unset or empty — callers should treat
/// this as "skip the corpus-gated test", not as an error.
pub fn corpus_root() -> Option<PathBuf> {
    match std::env::var_os(CORPUS_ENV) {
        Some(value) if !value.is_empty() => Some(PathBuf::from(value)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::CORPUS_ENV;

    #[test]
    fn corpus_env_var_name_is_stable() {
        // The shell.nix and downstream tooling key off this exact name; if it
        // changes, both sides need to move together.
        assert_eq!(CORPUS_ENV, "PSPTOOL_TEST_CORPUS");
    }
}
