//! `psptool-ops` — high-level operations layered over `psptool-core`:
//! `list`, `extract`, `replace`, `sign`, `verify`, `search-keys`.
//!
//! Subsequent issues (#10–#14) populate this crate. This skeleton wires the
//! `psptool-core` dependency so downstream crates can already link against it.

#![forbid(unsafe_code)]

/// Re-export of the core crate version, exposed for diagnostic / `--version` use.
pub const CORE_VERSION: &str = psptool_core::VERSION;

#[cfg(test)]
mod tests {
    #[test]
    fn core_version_is_linked() {
        assert!(!super::CORE_VERSION.is_empty());
    }
}
