//! `psptool-ops` — high-level operations layered over `psptool-core`:
//! `list`, `extract`, `replace`, `sign`, `verify`, `search-keys`.
//!
//! Issue #10 lands the `list` operations: [`list_default`] / [`list_verbose`]
//! / [`list_json`]. Subsequent issues (#11–#14) populate the rest. The CLI
//! subcommand bindings live in #15 and call into this crate.

#![forbid(unsafe_code)]

mod list;
mod table;
mod types;

pub use list::{RomListing, list_default, list_json, list_verbose};
pub use types::readable_type;

/// Re-export of the core crate version, exposed for diagnostic / `--version` use.
pub const CORE_VERSION: &str = psptool_core::VERSION;

#[cfg(test)]
mod tests {
    #[test]
    fn core_version_is_linked() {
        assert!(!super::CORE_VERSION.is_empty());
    }
}
