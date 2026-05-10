//! Subcommand handlers — one module per `psptool-ops` entry-point.
//!
//! Each handler takes the parsed clap struct, opens the requested ROM via
//! [`crate::load::open_rom`], dispatches into `psptool-ops`, and writes the
//! result to the supplied [`std::io::Write`] (stdout for textual / JSON
//! output) or to disk (for `extract` / `replace` / `sign`).

pub mod extract;
pub mod list;
pub mod replace;
pub mod search_keys;
pub mod sign;
pub mod verify;
