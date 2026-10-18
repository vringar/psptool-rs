//! `psptool.cert_tree` (`cert_tree.py:28-406`): the certificate tree linking
//! signed entities (signed `HeaderFile`s, `PubkeyFile`s, `KeyStoreFile`s) to
//! the public keys that certify them, and the re-signing operations built on
//! it.
//!
//! The graph is kept in Python containers exactly as upstream keeps it (the
//! `certifying_keys` set of a signed entity is *shared* with the tree's
//! `pubkeys[cert_id]` set, `cert_tree.py:297-299`; a key's
//! `certified_entities` is the tree's `signed_entities[key_id]` set,
//! `cert_tree.py:333`), so edges added later are visible through every
//! reference. Signatures are checked and produced by the native key classes
//! (`crypto.rs`); every byte read and write goes through the shared image.

use pyo3::exceptions::{PyAssertionError, PyException};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PySet, PyType};

use crate::buffer::{self, py_hex};
use crate::crypto::{PrivateKeyDict, key_type};
use crate::errors::{self, NonUniquePublicKeyEntity, NonUniqueSignedEntity};
use crate::file::{HeaderFile, KeyStoreFile, PubkeyFile};

fn print(py: Python<'_>, message: String) -> PyResult<()> {
    py.import("builtins")?.call_method1("print", (message,))?;
    Ok(())
}

fn range<'py>(py: Python<'py>, start: i64, stop: i64) -> PyResult<Bound<'py, PyAny>> {
    py.import("builtins")?
        .getattr("range")?
        .call1((start, stop))
}

/// `SignedEntity` (`cert_tree.py:28-124`).
#[pyclass(dict, module = "psptool.cert_tree")]
pub struct SignedEntity;

#[pymethods]
impl SignedEntity {
    #[new]
    fn py_new<'py>(
        file: &Bound<'py, PyAny>,
        certifying_id: &Bound<'py, PyAny>,
        signature: &Bound<'py, PyAny>,
        psptool: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, Self>> {
        let py = file.py();
        let obj = Bound::new(py, SignedEntity)?;
        obj.setattr("psptool", psptool)?;
        obj.setattr("file", file)?;
        obj.setattr("certifying_id", certifying_id)?;
        obj.setattr("signature", signature)?;
        obj.setattr("certifying_keys", py.None())?;
        obj.setattr("contained_keys", PySet::empty(py)?)?;
        Ok(obj)
    }

    fn get_address(slf: &Bound<'_, Self>) -> PyResult<PyObject> {
        Ok(slf.getattr("file")?.call_method0("get_address")?.unbind())
    }

    fn get_length(slf: &Bound<'_, Self>) -> PyResult<PyObject> {
        Ok(slf.getattr("file")?.getattr("buffer_size")?.unbind())
    }

    fn get_range<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyAny>> {
        let start: i64 = slf.call_method0("get_address")?.extract()?;
        let length: i64 = slf.call_method0("get_length")?.extract()?;
        range(slf.py(), start, start + length)
    }

    fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
        let start: i64 = slf.call_method0("get_address")?.extract()?;
        let length: i64 = slf.call_method0("get_length")?.extract()?;
        Ok(format!("SignedEntity(@{start:x}:{length:x})"))
    }

    #[staticmethod]
    fn _from_pubkey_file<'py>(
        pkf: &Bound<'py, PyAny>,
        psptool: &Bound<'py, PyAny>,
    ) -> PyResult<Option<Bound<'py, Self>>> {
        if !pkf.getattr("is_signed")?.is_truthy()? {
            return Ok(None);
        }
        Self::py_new(
            pkf,
            &pkf.getattr("certifying_id")?,
            &pkf.getattr("signature")?,
            psptool,
        )
        .map(Some)
    }

    /// `_from_header_file` (`cert_tree.py:58-66`): the signature as a plain
    /// `Signature`, the certifying id at header `0x38`.
    #[staticmethod]
    fn _from_header_file<'py>(
        hf: &Bound<'py, PyAny>,
        psptool: &Bound<'py, PyAny>,
    ) -> PyResult<Option<Bound<'py, Self>>> {
        if !hf.getattr("is_signed")?.is_truthy()? {
            return Ok(None);
        }
        let signature = buffer::signature(&hf.getattr("signature")?, false)?;
        let certifying_id = buffer::key_id(hf, 0x10, 0x38)?;
        Self::py_new(hf, certifying_id.as_any(), signature.as_any(), psptool).map(Some)
    }

    #[staticmethod]
    fn _from_key_store_file<'py>(
        ksf: &Bound<'py, PyAny>,
        psptool: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, Self>> {
        let certifying_id = ksf.getattr("header")?.getattr("certifying_id")?;
        Self::py_new(ksf, &certifying_id, &ksf.getattr("signature")?, psptool)
    }

    fn is_verified(slf: &Bound<'_, Self>) -> PyResult<bool> {
        Self::verify_with_tree(slf)
    }

    fn is_verified_by(slf: &Bound<'_, Self>, pubkey: &Bound<'_, PyAny>) -> PyResult<bool> {
        Self::verify_with_pubkey(slf, &pubkey.call_method0("get_public_key")?)
    }

    /// `verify_with_tree` (`cert_tree.py:78-95`): verified by at least one
    /// certifying key; `NoCertifyingKey` without any.
    fn verify_with_tree(slf: &Bound<'_, Self>) -> PyResult<bool> {
        let keys = slf.getattr("certifying_keys")?;
        if keys.is_none() || !keys.is_truthy()? {
            return Err(errors::no_certifying_key(slf.as_any())?);
        }
        let mut verified_once = false;
        for key in keys.try_iter()? {
            let public = key?.call_method0("get_public_key")?;
            verified_once |= Self::verify_with_pubkey(slf, &public)?;
        }
        Ok(verified_once)
    }

    fn verify_with_pubkey(slf: &Bound<'_, Self>, pubkey: &Bound<'_, PyAny>) -> PyResult<bool> {
        let signed = slf.getattr("file")?.call_method0("get_signed_bytes")?;
        let signature = slf.getattr("signature")?.call_method0("get_bytes")?;
        pubkey
            .call_method1("verify_blob", (signed, signature))?
            .extract()
    }

    /// `resign_only(privkey)` (`cert_tree.py:100-117`): refresh the sha256
    /// checksum if stale, then sign the signed bytes into the signature.
    fn resign_only(slf: &Bound<'_, Self>, privkey: &Bound<'_, PyAny>) -> PyResult<()> {
        let py = slf.py();
        let file = slf.getattr("file")?;
        print(py, format!("Resigning {} ({})", slf.repr()?, file.repr()?))?;
        if file.getattr("has_sha256_checksum")?.is_truthy()? {
            print(
                py,
                format!("    Checking sha256 checksum of {}", file.repr()?),
            )?;
            if file.call_method1("verify_sha256", (false,))?.is_truthy()? {
                print(py, "        sha256 still valid!".to_owned())?;
            } else {
                print(py, "        Need to rehash".to_owned())?;
                file.call_method0("update_sha256")?;
                print(py, "        Done".to_owned())?;
            }
        }
        let signature = slf.getattr("signature")?;
        let size: i64 = signature.getattr("buffer_size")?.extract()?;
        let key_size: i64 = privkey.getattr("signature_size")?.extract()?;
        if size != key_size {
            return Err(PyAssertionError::new_err(format!(
                "self.signature.buffer_size={size}, privkey.signature_size={key_size}"
            )));
        }
        let signed = file.call_method0("get_signed_bytes")?;
        let new_signature = privkey.call_method1("sign_blob", (signed,))?;
        if new_signature.len()? as i64 != size {
            return Err(PyAssertionError::new_err(format!(
                "Could not resign {}: the new signature has the wrong length",
                slf.repr()?
            )));
        }
        signature.call_method1("set_bytes", (0, size, new_signature))?;
        Ok(())
    }

    /// `resign_and_replace` (`cert_tree.py:119-124`).
    #[pyo3(signature = (privkeys = None, recursive = false))]
    fn resign_and_replace(
        slf: &Bound<'_, Self>,
        privkeys: Option<Bound<'_, PyAny>>,
        recursive: bool,
    ) -> PyResult<()> {
        let contained = slf.getattr("contained_keys")?;
        let keys: Vec<Bound<'_, PyAny>> = slf
            .getattr("certifying_keys")?
            .try_iter()?
            .collect::<PyResult<_>>()?;
        for key in keys {
            if contained.contains(&key)? {
                continue;
            }
            key.call_method1("replace_and_resign", (privkeys.clone(), recursive))?;
        }
        Ok(())
    }
}

/// `PublicKeyEntity` (`cert_tree.py:127-252`).
#[pyclass(dict, module = "psptool.cert_tree")]
pub struct PublicKeyEntity;

#[pymethods]
impl PublicKeyEntity {
    #[new]
    fn py_new<'py>(
        key_type: &Bound<'py, PyAny>,
        key_id: &Bound<'py, PyAny>,
        crypto_material: &Bound<'py, PyAny>,
        psptool: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, Self>> {
        let py = key_type.py();
        let obj = Bound::new(py, PublicKeyEntity)?;
        obj.setattr("psptool", psptool)?;
        obj.setattr("key_type", key_type)?;
        obj.setattr("key_id", key_id)?;
        obj.setattr("_crypto_material", crypto_material)?;
        obj.setattr("wrapping_entities", py.None())?;
        obj.setattr("certified_entities", py.None())?;
        obj.setattr("_public_key", py.None())?;
        Ok(obj)
    }

    fn get_address(slf: &Bound<'_, Self>) -> PyResult<PyObject> {
        Ok(slf.getattr("key_id")?.call_method0("get_address")?.unbind())
    }

    fn get_magic(slf: &Bound<'_, Self>) -> PyResult<String> {
        let id: String = slf
            .getattr("key_id")?
            .call_method0("as_string")?
            .extract()?;
        Ok(id.chars().take(4).collect())
    }

    fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
        let magic = Self::get_magic(slf)?;
        let address: i64 = slf.call_method0("get_address")?.extract()?;
        let size = slf.getattr("key_type")?.getattr("signature_size")?;
        Ok(format!(
            "PubkeyEntity({magic}, @{address:x}, self.key_type.signature_size={size})"
        ))
    }

    /// `is_same` (`cert_tree.py:150-159`).
    fn is_same(slf: &Bound<'_, Self>, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        let bytes = |o: &Bound<'_, PyAny>, n: &str| -> PyResult<Vec<u8>> {
            buffer::to_bytes(&o.getattr(n)?.call_method0("get_bytes")?)
        };
        Ok(bytes(slf.as_any(), "key_id")? == bytes(other, "key_id")?
            && slf.getattr("key_type")?.is(&other.getattr("key_type")?)
            && bytes(slf.as_any(), "_crypto_material")? == bytes(other, "_crypto_material")?)
    }

    #[classmethod]
    fn _from_pubkey_file<'py>(
        _cls: &Bound<'py, PyType>,
        pkf: &Bound<'py, PyAny>,
        psptool: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, Self>> {
        let py = pkf.py();
        let name = match pkf.getattr("modulus_size")?.extract::<i64>()? {
            0x100 => "rsa2048",
            0x200 => "rsa4096",
            other => {
                return Err(PyException::new_err(format!(
                    "Unknown PubkeyFile modulus size ({}) for {}",
                    py_hex(other),
                    pkf.repr()?
                )));
            }
        };
        Self::py_new(
            key_type(py, name)?.as_any(),
            &pkf.getattr("key_id")?,
            &pkf.getattr("crypto_material")?,
            psptool,
        )
    }

    #[classmethod]
    fn _from_key_store_key<'py>(
        _cls: &Bound<'py, PyType>,
        ksk: &Bound<'py, PyAny>,
        psptool: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, Self>> {
        let py = ksk.py();
        let name = match ksk.getattr("key_size")?.extract::<i64>()? {
            2048 => "rsa2048",
            4096 => "rsa4096",
            other => {
                return Err(PyException::new_err(format!(
                    "Unknown key_size ({other:x}) for {}",
                    ksk.repr()?
                )));
            }
        };
        Self::py_new(
            key_type(py, name)?.as_any(),
            &ksk.getattr("key_id")?,
            &ksk.getattr("crypto_material")?,
            psptool,
        )
    }

    fn is_root(slf: &Bound<'_, Self>) -> PyResult<bool> {
        let keys = Self::get_certifying_keys(slf)?;
        Ok(keys.is_empty() || keys.contains(slf)?)
    }

    fn get_certifying_ids<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PySet>> {
        let out = PySet::empty(slf.py())?;
        for entity in slf.getattr("wrapping_entities")?.try_iter()? {
            out.add(entity?.getattr("certifying_id")?)?;
        }
        Ok(out)
    }

    fn get_certifying_keys<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PySet>> {
        let out = PySet::empty(slf.py())?;
        for entity in slf.getattr("wrapping_entities")?.try_iter()? {
            for key in entity?.getattr("certifying_keys")?.try_iter()? {
                out.add(key?)?;
            }
        }
        Ok(out)
    }

    fn get_certified_keys<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PySet>> {
        let out = PySet::empty(slf.py())?;
        for entity in slf.getattr("certified_entities")?.try_iter()? {
            for key in entity?.getattr("contained_keys")?.try_iter()? {
                out.add(key?)?;
            }
        }
        Ok(out)
    }

    fn _make_public_key<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyAny>> {
        let material = slf.getattr("_crypto_material")?.call_method0("get_bytes")?;
        slf.getattr("key_type")?
            .call_method1("make_public_key", (material,))
            .map_err(|_| {
                PyException::new_err(format!(
                    "Cannot create crypto key for {}.",
                    slf.repr().map(|r| r.to_string()).unwrap_or_default()
                ))
            })
    }

    /// Lazily cached (`cert_tree.py:210-213`).
    fn get_public_key<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyAny>> {
        let cached = slf.getattr("_public_key")?;
        if !cached.is_none() {
            return Ok(cached);
        }
        let key = Self::_make_public_key(slf)?;
        slf.setattr("_public_key", &key)?;
        Ok(key)
    }

    fn replace_crypto_material(
        slf: &Bound<'_, Self>,
        crypto_material: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let py = slf.py();
        let material = slf.getattr("_crypto_material")?;
        let size: i64 = material.getattr("buffer_size")?.extract()?;
        let new = buffer::to_bytes(crypto_material)?;
        if new.len() as i64 != size {
            return Err(PyAssertionError::new_err(format!(
                "Crypto material has wrong size: {} != {size}",
                new.len()
            )));
        }
        slf.setattr("_public_key", py.None())?;
        material.call_method1("set_bytes", (0, size, crypto_material))?;
        Ok(())
    }

    /// `replace_only(pubkey)` (`cert_tree.py:220-225`).
    fn replace_only(slf: &Bound<'_, Self>, pubkey: &Bound<'_, PyAny>) -> PyResult<()> {
        let py = slf.py();
        print(py, format!("Replacing {}", slf.repr()?))?;
        let ours: i64 = slf
            .getattr("key_type")?
            .getattr("signature_size")?
            .extract()?;
        let theirs: i64 = pubkey.getattr("signature_size")?.extract()?;
        if ours != theirs {
            return Err(PyAssertionError::new_err("key size mismatch"));
        }
        let size: i64 = slf
            .getattr("_crypto_material")?
            .getattr("buffer_size")?
            .extract()?;
        let material = pubkey.call_method1("get_crypto_material", (size,))?;
        Self::replace_crypto_material(slf, &material)?;
        if !pubkey.eq(Self::get_public_key(slf)?)? {
            return Err(PyAssertionError::new_err("replaced key does not read back"));
        }
        Ok(())
    }

    /// `replace_and_resign` (`cert_tree.py:227-252`).
    #[pyo3(signature = (privkeys = None, recursive = false))]
    fn replace_and_resign(
        slf: &Bound<'_, Self>,
        privkeys: Option<Bound<'_, PyAny>>,
        recursive: bool,
    ) -> PyResult<()> {
        let py = slf.py();
        let privkeys = match privkeys {
            Some(p) if !p.is_none() => p,
            _ => py.get_type::<PrivateKeyDict>().call0()?,
        };
        let name = slf.getattr("key_type")?.getattr("name")?;
        let privkey = privkeys.get_item(name)?;
        let ours: i64 = slf
            .getattr("key_type")?
            .getattr("signature_size")?
            .extract()?;
        let theirs: i64 = privkey.getattr("signature_size")?.extract()?;
        if ours != theirs {
            return Err(PyAssertionError::new_err("private key size mismatch"));
        }
        Self::replace_only(slf, &privkey.call_method0("get_public_key")?)?;
        let certified: Vec<Bound<'_, PyAny>> = slf
            .getattr("certified_entities")?
            .try_iter()?
            .collect::<PyResult<_>>()?;
        for entity in &certified {
            entity.call_method1("resign_only", (&privkey,))?;
        }
        for entity in &certified {
            if !entity.call_method1("is_verified_by", (slf,))?.is_truthy()? {
                return Err(PyAssertionError::new_err(format!(
                    "Resigning {} with {} failed!",
                    entity.repr()?,
                    slf.repr()?
                )));
            }
        }
        if recursive {
            let wrapping: Vec<Bound<'_, PyAny>> = slf
                .getattr("wrapping_entities")?
                .try_iter()?
                .collect::<PyResult<_>>()?;
            if wrapping.len() > 1 {
                py.import("sys")?.getattr("stderr")?.call_method1(
                    "write",
                    (format!(
                        "Warning: Resigning could be in wrong order for {wrapping:?}!\n"
                    ),),
                )?;
            }
            for entity in wrapping {
                entity.call_method1("resign_and_replace", (&privkeys, true))?;
            }
        }
        Ok(())
    }
}

/// `CertificateTree` (`cert_tree.py:255-462`).
#[pyclass(dict, module = "psptool.cert_tree")]
pub struct CertificateTree;

impl CertificateTree {
    /// `CertificateTree.from_blob` (`cert_tree.py:385-406`). Upstream's
    /// follow-up scan for inline public keys inside file bodies
    /// (`blob.py:133-181`) is not ported (`DEVIATIONS.md`).
    pub(crate) fn from_blob_impl<'py>(
        blob: &Bound<'py, PyAny>,
        psptool: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, Self>> {
        let tree = Self::py_new(psptool)?;
        for rom in blob.getattr("roms")?.try_iter()? {
            for directory in rom?.getattr("directories")?.try_iter()? {
                for file in directory?.getattr("files")?.try_iter()? {
                    let file = file?;
                    if file.is_exact_instance_of::<PubkeyFile>() {
                        Self::add_pubkey_file(&tree, &file)?;
                    }
                    if file.is_exact_instance_of::<HeaderFile>() {
                        Self::add_header_file(&tree, &file)?;
                    }
                    if file.is_exact_instance_of::<KeyStoreFile>() {
                        Self::add_key_store_file(&tree, &file)?;
                    }
                }
            }
        }
        Ok(tree)
    }

    /// Run `add` and fall back to the `existing` entity of a `NonUnique*`
    /// error (`cert_tree.py:341-344`).
    fn or_existing<'py, E: pyo3::PyTypeInfo>(
        py: Python<'py>,
        entity: Bound<'py, PyAny>,
        add: PyResult<()>,
    ) -> PyResult<Bound<'py, PyAny>> {
        match add {
            Ok(()) => Ok(entity),
            Err(e) if e.is_instance_of::<E>(py) => e.value(py).getattr("existing"),
            Err(e) => Err(e),
        }
    }
}

#[pymethods]
impl CertificateTree {
    #[new]
    fn py_new<'py>(psptool: &Bound<'py, PyAny>) -> PyResult<Bound<'py, Self>> {
        let py = psptool.py();
        let obj = Bound::new(py, CertificateTree)?;
        obj.setattr("psptool", psptool)?;
        obj.setattr("ids", PySet::empty(py)?)?;
        obj.setattr("pubkeys", PyDict::new(py))?;
        obj.setattr("pubkeys_address", PyDict::new(py))?;
        obj.setattr("signed_entities", PyDict::new(py))?;
        obj.setattr("signed_ranges", PyDict::new(py))?;
        obj.setattr("verification_failed", PySet::empty(py)?)?;
        Ok(obj)
    }

    #[staticmethod]
    fn from_blob<'py>(
        blob: &Bound<'py, PyAny>,
        psptool: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, Self>> {
        Self::from_blob_impl(blob, psptool)
    }

    /// `add_signed_entity` (`cert_tree.py:271-302`).
    fn add_signed_entity(slf: &Bound<'_, Self>, signed_entity: &Bound<'_, PyAny>) -> PyResult<()> {
        let py = slf.py();
        let address_range = signed_entity.call_method0("get_range")?;
        let ranges = slf.getattr("signed_ranges")?;
        let existing = ranges.call_method1("get", (&address_range,))?;
        if existing.is_truthy()? {
            return Err(errors::non_unique::<NonUniqueSignedEntity>(
                &existing,
                signed_entity,
            )?);
        }
        ranges.set_item(&address_range, signed_entity)?;
        let cert_id = signed_entity
            .getattr("certifying_id")?
            .call_method0("as_string")?;
        slf.getattr("ids")?.call_method1("add", (&cert_id,))?;
        let signed = slf.getattr("signed_entities")?;
        if !signed.call_method1("get", (&cert_id,))?.is_truthy()? {
            signed.set_item(&cert_id, PySet::empty(py)?)?;
        }
        signed
            .get_item(&cert_id)?
            .call_method1("add", (signed_entity,))?;
        for item in slf
            .getattr("pubkeys_address")?
            .call_method0("items")?
            .try_iter()?
        {
            let (address, pubkey): (Bound<'_, PyAny>, Bound<'_, PyAny>) = item?.extract()?;
            if address_range.contains(address)? {
                signed_entity
                    .getattr("contained_keys")?
                    .call_method1("add", (&pubkey,))?;
                pubkey
                    .getattr("wrapping_entities")?
                    .call_method1("add", (signed_entity,))?;
            }
        }
        let certifying = slf
            .getattr("pubkeys")?
            .call_method1("get", (&cert_id, PySet::empty(py)?))?;
        if !signed_entity.getattr("certifying_keys")?.is_none() {
            return Err(PyAssertionError::new_err("certifying_keys already set"));
        }
        signed_entity.setattr("certifying_keys", &certifying)?;
        for pubkey in certifying.try_iter()? {
            pubkey?
                .getattr("certified_entities")?
                .call_method1("add", (signed_entity,))?;
        }
        Ok(())
    }

    /// `add_pubkey_entity` (`cert_tree.py:304-336`).
    fn add_pubkey_entity(slf: &Bound<'_, Self>, pubkey: &Bound<'_, PyAny>) -> PyResult<()> {
        let py = slf.py();
        let start = pubkey.call_method0("get_address")?;
        let by_address = slf.getattr("pubkeys_address")?;
        let existing = by_address.call_method1("get", (&start,))?;
        if existing.is_truthy()? {
            return Err(errors::non_unique::<NonUniquePublicKeyEntity>(
                &existing, pubkey,
            )?);
        }
        by_address.set_item(&start, pubkey)?;
        let key_id = pubkey.getattr("key_id")?.call_method0("as_string")?;
        slf.getattr("ids")?.call_method1("add", (&key_id,))?;
        let pubkeys = slf.getattr("pubkeys")?;
        if !pubkeys.call_method1("get", (&key_id,))?.is_truthy()? {
            pubkeys.set_item(&key_id, PySet::empty(py)?)?;
        }
        pubkeys.get_item(&key_id)?.call_method1("add", (pubkey,))?;
        if !pubkey.getattr("wrapping_entities")?.is_none() {
            return Err(PyAssertionError::new_err("wrapping_entities already set"));
        }
        let wrapping = PySet::empty(py)?;
        for item in slf
            .getattr("signed_ranges")?
            .call_method0("items")?
            .try_iter()?
        {
            let (r, entity): (Bound<'_, PyAny>, Bound<'_, PyAny>) = item?.extract()?;
            if r.contains(&start)? {
                wrapping.add(&entity)?;
                entity
                    .getattr("contained_keys")?
                    .call_method1("add", (pubkey,))?;
            }
        }
        pubkey.setattr("wrapping_entities", wrapping)?;
        if !pubkey.getattr("certified_entities")?.is_none() {
            return Err(PyAssertionError::new_err("certified_entities already set"));
        }
        let certified = slf
            .getattr("signed_entities")?
            .call_method1("get", (&key_id, PySet::empty(py)?))?;
        pubkey.setattr("certified_entities", &certified)?;
        for entity in certified.try_iter()? {
            entity?
                .getattr("certifying_keys")?
                .call_method1("add", (pubkey,))?;
        }
        Ok(())
    }

    /// `add_header_file` (`cert_tree.py:338-347`).
    fn add_header_file<'py>(
        slf: &Bound<'py, Self>,
        header_file: &Bound<'py, PyAny>,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        let py = slf.py();
        let Some(entity) = SignedEntity::_from_header_file(header_file, &slf.getattr("psptool")?)?
        else {
            return Ok(None);
        };
        let entity = entity.into_any();
        let added = Self::add_signed_entity(slf, &entity);
        let entity = Self::or_existing::<NonUniqueSignedEntity>(py, entity, added)?;
        header_file.setattr("signed_entity", &entity)?;
        Ok(Some(entity))
    }

    /// `add_pubkey_file` (`cert_tree.py:349-366`).
    fn add_pubkey_file<'py>(
        slf: &Bound<'py, Self>,
        pubkey_file: &Bound<'py, PyAny>,
    ) -> PyResult<(Bound<'py, PyAny>, Option<Bound<'py, PyAny>>)> {
        let py = slf.py();
        let psptool = slf.getattr("psptool")?;
        let mut signed = None;
        if let Some(entity) = SignedEntity::_from_pubkey_file(pubkey_file, &psptool)? {
            let entity = entity.into_any();
            let added = Self::add_signed_entity(slf, &entity);
            let entity = Self::or_existing::<NonUniqueSignedEntity>(py, entity, added)?;
            pubkey_file.setattr("signed_entity", &entity)?;
            signed = Some(entity);
        }
        let key = PublicKeyEntity::_from_pubkey_file(
            &py.get_type::<PublicKeyEntity>(),
            pubkey_file,
            &psptool,
        )?
        .into_any();
        let added = Self::add_pubkey_entity(slf, &key);
        let key = Self::or_existing::<NonUniquePublicKeyEntity>(py, key, added)?;
        pubkey_file.setattr("pubkey_entity", &key)?;
        Ok((key, signed))
    }

    /// `add_key_store_file` (`cert_tree.py:368-383`).
    fn add_key_store_file(
        slf: &Bound<'_, Self>,
        key_store_file: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let py = slf.py();
        let psptool = slf.getattr("psptool")?;
        let entity = SignedEntity::_from_key_store_file(key_store_file, &psptool)?.into_any();
        let added = Self::add_signed_entity(slf, &entity);
        let entity = Self::or_existing::<NonUniqueSignedEntity>(py, entity, added)?;
        key_store_file.setattr("signed_entity", entity)?;
        for key_store_key in key_store_file
            .getattr("key_store")?
            .getattr("keys")?
            .try_iter()?
        {
            let key_store_key = key_store_key?;
            let key = PublicKeyEntity::_from_key_store_key(
                &py.get_type::<PublicKeyEntity>(),
                &key_store_key,
                &psptool,
            )?
            .into_any();
            let added = Self::add_pubkey_entity(slf, &key);
            let key = Self::or_existing::<NonUniquePublicKeyEntity>(py, key, added)?;
            key_store_key.setattr("pubkey_entity", key)?;
        }
        Ok(())
    }

    /// `unique_pubkeys(key_id)` (`cert_tree.py:408-419`).
    fn unique_pubkeys<'py>(
        slf: &Bound<'py, Self>,
        key_id: &Bound<'py, PyAny>,
    ) -> PyResult<Vec<Vec<Bound<'py, PyAny>>>> {
        let mut unique: Vec<Vec<Bound<'py, PyAny>>> = Vec::new();
        for key in slf.getattr("pubkeys")?.get_item(key_id)?.try_iter()? {
            let key = key?;
            let mut inserted = false;
            for group in &mut unique {
                if key.call_method1("is_same", (&group[0],))?.is_truthy()? {
                    group.push(key.clone());
                    inserted = true;
                    break;
                }
            }
            if !inserted {
                unique.push(vec![key]);
            }
        }
        Ok(unique)
    }
}
