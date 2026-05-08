//! `psptool-core` — wire-format types, parser, typed domain model, and the
//! byte-exact diff-and-patch writer for AMD PSP firmware images.
//!
//! Subsequent issues (#5–#9) populate this crate. This skeleton only fixes the
//! crate's identity and forbids `unsafe` to anchor the safety policy.

#![forbid(unsafe_code)]

/// Crate version, sourced from Cargo at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_matches_cargo_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert!(!VERSION.is_empty());
    }
}
