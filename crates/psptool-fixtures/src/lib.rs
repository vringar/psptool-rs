//! `psptool-fixtures` — shared test-corpus discovery and micro-fixtures for
//! `psptool-core`, `psptool-ops`, `psptool-cli`, and downstream consumers.
//!
//! Two flavours of fixture are exposed:
//!
//! * [`micro`] — handcrafted, byte-stable fixtures committed under
//!   `crates/psptool-fixtures/data/`. They cover every parser branch (FET,
//!   directory, entry kinds, signed entry, encrypted body, compressed body,
//!   pubkey) without requiring the private corpus.
//! * [`corpus`] — a loader for the optional `vendor/test-corpus` submodule,
//!   keyed off the `PSPTOOL_TEST_CORPUS` environment variable. When the
//!   variable is unset, [`corpus()`] returns `None` and corpus-gated tests
//!   skip cleanly — by design, not a stub.
//!
//! Tests that want to opt into the corpus path can use the `corpus`
//! cargo feature as a build-time switch (see `Cargo.toml`).

#![forbid(unsafe_code)]

pub mod corpus;
pub mod micro;

pub use corpus::{CORPUS_ENV, CorpusRom, corpus, corpus_roms, corpus_roms_in};
