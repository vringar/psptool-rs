//! `psptool-py` — a drop-in `psptool` Python module backed by psptool-rs.
//!
//! The native extension `psptool._native` mirrors the reference PSPTool
//! object model (`PSPTool` → `blob.roms` → `rom.directories` →
//! `directory.files`, with the upstream classes, methods and attributes); the
//! `python/psptool/` package re-exports its classes at the upstream module
//! paths so `from psptool import PSPTool` and
//! `isinstance(f, psptool.header_file.HeaderFile)` keep working. Governing
//! design: `.design/psptool-py/bindings.md`; deviations:
//! `crates/psptool-py/DEVIATIONS.md`.
//!
//! * [`model`] — the upstream construction order (ROM / directory / file
//!   graph, classes, buffer sizes), pure Rust over the `psptool-core` parsers.
//! * [`image`] — the one mutable buffer every view shares.
//! * [`buffer`] — `NestedBuffer` and its small subclasses.
//! * [`tool`], [`directory`], [`file`] — the object model.
//! * [`cert_tree`], [`crypto`] — certificate tree, keys, re-signing.
//! * [`listing`] — `ls` / `ls_json`.
//! * [`memory`] — native buffers the cycle collector cannot see, and the
//!   collection they warrant at construction (#98).
//!
//! ## REQ status (per `.design/psptool-py/bindings.md`)
//!
//! | REQ | Status | Evidence |
//! |---|---|---|
//! The Python module is itself the public surface (a boundary, goal.md
//! R-DEFER-1); its consumers are the downstream importers (psp-etl, psp-db)
//! and the nix `python` attribute (`pythonImportsCheck`). Every row is
//! exercised by `tests/corpus_parity.rs` against the reference interpreter
//! and/or `tests/test_api.py`.
//!
//! | REQ | Status | Evidence |
//! |---|---|---|
//! | REQ-1 (import surface) | SHIPPED | `_native` at `lib.rs:58` + `python/psptool/*.py` re-exports per `__init__.py:17-20`. |
//! | REQ-2 (construction) | SHIPPED | `PSPTool::py_new` `tool.rs:102`, `from_file` `tool.rs:124` per `psptool.py:34-51`. ROM-less Python subclasses of every parsed class: `buffer::detached` `buffer.rs:656` (each class's `py_new`); consumer PSP-DB `tests/test_identity.py` `FakeHeaderFile`, pinned by `tests/oracle_subclass.py`. |
//! | REQ-3 (upstream object order) | SHIPPED | `model::build` `model.rs:175` per `blob.py:58-84`, `fet.py:59-127`, `directory.py:57-165`, `file.py:39-56`; consumer `tool::build` `tool.rs:235`. |
//! | REQ-4 (classes and sizing) | SHIPPED | `Builder::parse_file` `model.rs:449`, `header_sizing` `model.rs:533` per `file.py:249-319`, `header_file.py:31-106`; consumer `tool::build_files` `tool.rs:395`. |
//! | REQ-5 (read attributes) | SHIPPED | `file::header_file` attributes and the `file.rs` getters per `file.py:352-383`, `header_file.py:31-166`, `pubkey_file.py:93-171`. |
//! | REQ-6 (HeaderFile decode) | SHIPPED | `HeaderFile::decode` `file.rs:416` → core `HeaderEntry::decode_best_effort`; `HeaderFile::verification` `file.rs:434` → core `Entry::decode_verification`; per `header_file.py:168-292`. Python-subclass instances (`is_native` `file.rs:342`): `decrypted_decompressed_py` `file.rs:505` → core `body::zlib_decompress`, `verify_decode_py` `file.rs:534`, attribute-driven `get_decrypted_body` → core `body::decrypt`, per `header_file.py:172-243,286-292`. |
//! | REQ-7 (NestedBuffer semantics) | SHIPPED | `NestedBuffer::resolve` `buffer.rs:109`, `__getitem__` `buffer.rs:385`, `set_bytes` `buffer.rs:469` per `utils.py:40-114`, `crypto.py:386-409`. |
//! | REQ-8 (edit / rebuild) | SHIPPED | `File::move_buffer` `file.rs:196`, `Directory::update_entry_fields` `directory.rs:144`, `update_checksum` `directory.rs:135`, `HeaderFile::update_sha256` `file.rs:426`, `PSPTool::to_file` `tool.rs:155` per `file.py:385-393`, `directory.py:195-241`, `header_file.py:119-121`, `psptool.py:59-64`. |
//! | REQ-9 (certificate tree, re-signing) | SHIPPED | `CertificateTree::from_blob_impl` `cert_tree.rs:485` (built at `tool.rs:235`), `SignedEntity::resign_and_replace` `cert_tree.rs:191`, `PublicKeyEntity::replace_and_resign` `cert_tree.rs:419`, `PrivateKeyDict` `crypto.rs:476` per `cert_tree.py:28-406`, `crypto.py:104-307`. |
//! | REQ-10 (listing) | SHIPPED | `listing::ls` `listing.rs:126`, `ls_json` `listing.rs:372`, `ls_files_dict` `listing.rs:402` per `psptool.py:66-275`. |
//! | REQ-11 (packaging) | SHIPPED | `pyproject.toml` (maturin, abi3) + `default.nix` `python` / `pythonFor`. |

pub mod buffer;
pub mod cert_tree;
pub mod crypto;
pub mod directory;
pub mod errors;
pub mod file;
pub mod image;
pub mod listing;
pub mod memory;
pub mod model;
pub mod tool;

use pyo3::prelude::*;

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<buffer::NestedBuffer>()?;
    m.add_class::<buffer::KeyId>()?;
    m.add_class::<buffer::Signature>()?;
    m.add_class::<buffer::ReversedSignature>()?;
    m.add_class::<tool::PSPTool>()?;
    m.add_class::<tool::Blob>()?;
    m.add_class::<tool::Rom>()?;
    m.add_class::<tool::Fet>()?;
    m.add_class::<directory::Directory>()?;
    m.add_class::<directory::BiosDirectory>()?;
    m.add_class::<directory::DirectoryEntry>()?;
    m.add_class::<directory::BiosDirectoryEntry>()?;
    m.add_class::<file::File>()?;
    m.add_class::<file::BiosFile>()?;
    m.add_class::<file::HeaderFile>()?;
    m.add_class::<file::KeyStoreFile>()?;
    m.add_class::<file::KeyStoreFileHeader>()?;
    m.add_class::<file::KeyStore>()?;
    m.add_class::<file::KeyStoreKey>()?;
    m.add_class::<file::PubkeyFile>()?;
    m.add_class::<file::MicrocodeFile>()?;
    m.add_class::<cert_tree::CertificateTree>()?;
    m.add_class::<cert_tree::SignedEntity>()?;
    m.add_class::<cert_tree::PublicKeyEntity>()?;
    m.add_class::<crypto::KeyType>()?;
    m.add_class::<crypto::RsaPublicKey>()?;
    m.add_class::<crypto::Rsa2048PublicKey>()?;
    m.add_class::<crypto::Rsa4096PublicKey>()?;
    m.add_class::<crypto::RsaPrivateKey>()?;
    m.add_class::<crypto::Rsa2048PrivateKey>()?;
    m.add_class::<crypto::Rsa4096PrivateKey>()?;
    m.add_class::<crypto::PrivateKeyDict>()?;
    errors::register(m)?;
    Ok(())
}
