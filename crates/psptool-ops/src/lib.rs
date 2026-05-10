//! `psptool-ops` — high-level operations layered over `psptool-core`:
//! `list`, `extract`, `replace`, `sign`, `verify`, `search-keys`.
//!
//! Issue #10 lands the `list` operations: [`list_default`] / [`list_verbose`]
//! / [`list_json`]. Issue #11 lands [`extract_raw`] / [`extract_decompressed`]
//! / [`extract_decrypted`]. Issue #12 lands [`replace_entry_body`] (and the
//! family-specific helpers). Subsequent issues (#13–#14) populate the rest.
//! The CLI subcommand bindings live in #15 and call into this crate.

#![forbid(unsafe_code)]

mod extract;
mod list;
mod replace;
mod table;
mod types;

pub use extract::{ExtractError, extract_decompressed, extract_decrypted, extract_raw};
pub use list::{RomListing, list_default, list_json, list_verbose};
pub use replace::{
    ReplaceError, replace_bios_entry_body, replace_entry_body, replace_psp_entry_body,
};
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
