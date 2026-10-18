//! `psptool.crypto` key classes (`crypto.py:104-364`): `KeyType`, the
//! RSA-2048/4096 public and private keys, and `PrivateKeyDict`.
//!
//! RSA-PSS parameters follow `RsaKey.__init_subclass__` (`crypto.py:184-203`):
//! 2048-bit keys sign with SHA-256 (salt 32), 4096-bit keys with SHA-384
//! (salt 48) — the digest length, which is the `rsa` crate's default salt.
//! Crypto material is the little-endian `pubexp || modulus` layout
//! (`crypto.py:215-243`). Private keys are PKCS#8 PEM files, optionally
//! password-encrypted (`crypto.py:275-294`).

use pyo3::exceptions::{PyAssertionError, PyException, PyKeyError, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::GILOnceCell;
use pyo3::types::{PyBytes, PyDict, PyType};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::pss::{Signature as PssSignature, SigningKey, VerifyingKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey as RsaPriv, RsaPublicKey as RsaPub};
use sha2::{Sha256, Sha384};

use crate::buffer::to_bytes;

/// The only public exponent upstream accepts (`crypto.py:220`).
const EXPONENT: u32 = 0x10001;

fn bits_of(signature_size: usize) -> usize {
    signature_size << 3
}

/// `verify_blob` (`crypto.py:247-258`): RSA-PSS, hash by key size.
fn verify(key: &RsaPub, blob: &[u8], signature: &[u8]) -> bool {
    let Ok(sig) = PssSignature::try_from(signature) else {
        return false;
    };
    match key.size() {
        0x100 => VerifyingKey::<Sha256>::new(key.clone())
            .verify(blob, &sig)
            .is_ok(),
        0x200 => VerifyingKey::<Sha384>::new(key.clone())
            .verify(blob, &sig)
            .is_ok(),
        _ => false,
    }
}

/// `RsaPublicKey` (`crypto.py:206-258`).
#[pyclass(subclass, module = "psptool.crypto")]
pub struct RsaPublicKey {
    pub(crate) key: RsaPub,
}

/// `Rsa2048PublicKey` (`crypto.py:310-318`).
#[pyclass(extends = RsaPublicKey, module = "psptool.crypto")]
pub struct Rsa2048PublicKey;

/// `Rsa4096PublicKey` (`crypto.py:339-347`).
#[pyclass(extends = RsaPublicKey, module = "psptool.crypto")]
pub struct Rsa4096PublicKey;

#[pymethods]
impl Rsa2048PublicKey {
    #[classattr]
    #[pyo3(name = "signature_size")]
    fn signature_size() -> usize {
        0x100
    }

    #[classattr]
    #[pyo3(name = "key_bits")]
    fn key_bits() -> usize {
        2048
    }
}

#[pymethods]
impl Rsa4096PublicKey {
    #[classattr]
    #[pyo3(name = "signature_size")]
    fn signature_size() -> usize {
        0x200
    }

    #[classattr]
    #[pyo3(name = "key_bits")]
    fn key_bits() -> usize {
        4096
    }
}

/// A public-key object of the class matching `key`'s size.
pub(crate) fn public_key(py: Python<'_>, key: RsaPub) -> PyResult<Bound<'_, RsaPublicKey>> {
    match key.size() {
        0x100 => Ok(Bound::new(
            py,
            PyClassInitializer::from(RsaPublicKey { key }).add_subclass(Rsa2048PublicKey),
        )?
        .into_super()),
        0x200 => Ok(Bound::new(
            py,
            PyClassInitializer::from(RsaPublicKey { key }).add_subclass(Rsa4096PublicKey),
        )?
        .into_super()),
        other => Err(PyException::new_err(format!(
            "Unknown rsa key size: {} bits!",
            other * 8
        ))),
    }
}

#[pymethods]
impl RsaPublicKey {
    /// `from_crypto_material` (`crypto.py:215-229`).
    #[classmethod]
    fn from_crypto_material<'py>(
        cls: &Bound<'py, PyType>,
        crypto_material: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, RsaPublicKey>> {
        let size: usize = cls.getattr("signature_size")?.extract()?;
        let material = to_bytes(crypto_material)?;
        let (exponent, modulus) = if material.len() == 2 * size {
            (
                BigUint::from_bytes_le(&material[..size]),
                BigUint::from_bytes_le(&material[size..]),
            )
        } else if material.len() == size {
            (BigUint::from(EXPONENT), BigUint::from_bytes_le(&material))
        } else {
            return Err(PyException::new_err(format!(
                "Crypto material has unknown size: 0x{:x}!",
                material.len()
            )));
        };
        if exponent != BigUint::from(EXPONENT) {
            return Err(PyAssertionError::new_err(format!(
                "The public exponent should always be 65537 (0x10001) not {exponent}"
            )));
        }
        let key =
            RsaPub::new(modulus, exponent).map_err(|e| PyValueError::new_err(e.to_string()))?;
        if key.size() != size {
            return Err(PyAssertionError::new_err(format!(
                "Key has the wrong size: expected {} but got {}!",
                bits_of(size),
                bits_of(key.size())
            )));
        }
        public_key(cls.py(), key)
    }

    /// `get_crypto_material(size)` (`crypto.py:231-243`).
    fn get_crypto_material<'py>(
        &self,
        py: Python<'py>,
        size: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let sig = self.key.size();
        let modulus = le_padded(&self.key.n().to_bytes_le(), sig);
        if size == sig {
            return Ok(PyBytes::new(py, &modulus));
        }
        if size == 2 * sig {
            let mut out = le_padded(&self.key.e().to_bytes_le(), sig);
            out.extend_from_slice(&modulus);
            return Ok(PyBytes::new(py, &out));
        }
        Err(PyException::new_err(format!(
            "Unknown crypto_material size: 0x{size:x} (expected 0x{sig:x} or 0x{:x})!",
            2 * sig
        )))
    }

    fn verify_blob(&self, blob: &Bound<'_, PyAny>, signature: &Bound<'_, PyAny>) -> PyResult<bool> {
        Ok(verify(&self.key, &to_bytes(blob)?, &to_bytes(signature)?))
    }

    fn __eq__(&self, other: &Bound<'_, PyAny>) -> bool {
        other
            .downcast::<RsaPublicKey>()
            .is_ok_and(|o| o.borrow().key == self.key)
    }

    fn __hash__(&self) -> u64 {
        // Keys are compared by value; hash the low modulus bytes.
        let n = self.key.n().to_bytes_le();
        n.iter()
            .take(8)
            .fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
    }
}

fn le_padded(bytes: &[u8], len: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out.resize(len, 0);
    out
}

/// `RsaPrivateKey` (`crypto.py:261-307`).
#[pyclass(subclass, module = "psptool.crypto")]
pub struct RsaPrivateKey {
    pub(crate) key: RsaPriv,
}

/// `Rsa2048PrivateKey` (`crypto.py:320-333`).
#[pyclass(extends = RsaPrivateKey, module = "psptool.crypto")]
pub struct Rsa2048PrivateKey;

/// `Rsa4096PrivateKey` (`crypto.py:349-362`).
#[pyclass(extends = RsaPrivateKey, module = "psptool.crypto")]
pub struct Rsa4096PrivateKey;

#[pymethods]
impl Rsa2048PrivateKey {
    #[classattr]
    #[pyo3(name = "signature_size")]
    fn signature_size() -> usize {
        0x100
    }

    #[classattr]
    #[pyo3(name = "key_bits")]
    fn key_bits() -> usize {
        2048
    }
    #[classattr]
    #[allow(
        non_snake_case,
        reason = "upstream class attribute name (crypto.py:71)"
    )]
    fn PublicKey(py: Python<'_>) -> Py<PyType> {
        py.get_type::<Rsa2048PublicKey>().unbind()
    }
}

#[pymethods]
impl Rsa4096PrivateKey {
    #[classattr]
    #[pyo3(name = "signature_size")]
    fn signature_size() -> usize {
        0x200
    }

    #[classattr]
    #[pyo3(name = "key_bits")]
    fn key_bits() -> usize {
        4096
    }
    #[classattr]
    #[allow(
        non_snake_case,
        reason = "upstream class attribute name (crypto.py:71)"
    )]
    fn PublicKey(py: Python<'_>) -> Py<PyType> {
        py.get_type::<Rsa4096PublicKey>().unbind()
    }
}

/// A private-key object of the class matching `key`'s size.
fn private_key(py: Python<'_>, key: RsaPriv) -> PyResult<Bound<'_, RsaPrivateKey>> {
    match key.size() {
        0x100 => Ok(Bound::new(
            py,
            PyClassInitializer::from(RsaPrivateKey { key }).add_subclass(Rsa2048PrivateKey),
        )?
        .into_super()),
        0x200 => Ok(Bound::new(
            py,
            PyClassInitializer::from(RsaPrivateKey { key }).add_subclass(Rsa4096PrivateKey),
        )?
        .into_super()),
        other => Err(PyException::new_err(format!(
            "Unknown rsa key size: {} bits!",
            other * 8
        ))),
    }
}

#[pymethods]
impl RsaPrivateKey {
    /// `generate_new` (`crypto.py:270-273`).
    #[classmethod]
    fn generate_new<'py>(cls: &Bound<'py, PyType>) -> PyResult<Bound<'py, RsaPrivateKey>> {
        let size: usize = cls.getattr("signature_size")?.extract()?;
        let key = RsaPriv::new(&mut rand::thread_rng(), bits_of(size))
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        private_key(cls.py(), key)
    }

    /// `load_from_file` (`crypto.py:276-282`): PKCS#8 (optionally encrypted)
    /// or PKCS#1 PEM.
    #[classmethod]
    #[pyo3(signature = (filename, password = None))]
    fn load_from_file<'py>(
        cls: &Bound<'py, PyType>,
        filename: &Bound<'py, PyAny>,
        password: Option<String>,
    ) -> PyResult<Bound<'py, RsaPrivateKey>> {
        let py = cls.py();
        let size: usize = cls.getattr("signature_size")?.extract()?;
        let path: std::path::PathBuf = py
            .import("os")?
            .call_method1("fspath", (filename,))?
            .extract()?;
        let pem = std::fs::read_to_string(&path)?;
        let key = match password.filter(|p| !p.is_empty()) {
            Some(p) => RsaPriv::from_pkcs8_encrypted_pem(&pem, p.as_bytes())
                .map_err(|e| PyValueError::new_err(e.to_string()))?,
            None => RsaPriv::from_pkcs8_pem(&pem)
                .or_else(|_| RsaPriv::from_pkcs1_pem(&pem))
                .map_err(|e| PyValueError::new_err(e.to_string()))?,
        };
        if key.size() != size {
            return Err(PyAssertionError::new_err(format!(
                "Key has the wrong size: expected {} but got {}!",
                bits_of(size),
                bits_of(key.size())
            )));
        }
        private_key(py, key)
    }

    /// `save_to_file` (`crypto.py:284-294`): PKCS#8 PEM.
    #[pyo3(signature = (filename, password = None))]
    fn save_to_file(
        &self,
        py: Python<'_>,
        filename: &Bound<'_, PyAny>,
        password: Option<String>,
    ) -> PyResult<()> {
        let path: std::path::PathBuf = py
            .import("os")?
            .call_method1("fspath", (filename,))?
            .extract()?;
        let pem = match password.filter(|p| !p.is_empty()) {
            Some(p) => self.key.to_pkcs8_encrypted_pem(
                &mut rand::thread_rng(),
                p.as_bytes(),
                LineEnding::LF,
            ),
            None => self.key.to_pkcs8_pem(LineEnding::LF),
        }
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
        std::fs::write(path, pem.as_bytes())?;
        Ok(())
    }

    fn get_public_key<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, RsaPublicKey>> {
        public_key(py, self.key.to_public_key())
    }

    /// `sign_blob` (`crypto.py:301-307`): RSA-PSS with a fresh salt.
    fn sign_blob<'py>(
        &self,
        py: Python<'py>,
        blob: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let blob = to_bytes(blob)?;
        let mut rng = rand::thread_rng();
        let sig = match self.key.size() {
            0x100 => SigningKey::<Sha256>::new(self.key.clone())
                .sign_with_rng(&mut rng, &blob)
                .to_vec(),
            0x200 => SigningKey::<Sha384>::new(self.key.clone())
                .sign_with_rng(&mut rng, &blob)
                .to_vec(),
            other => {
                return Err(PyException::new_err(format!(
                    "Unknown rsa key size: {} bits!",
                    other * 8
                )));
            }
        };
        Ok(PyBytes::new(py, &sig))
    }
}

/// `KeyType` (`crypto.py:104-136`): `rsa2048` / `rsa4096` singletons.
#[pyclass(module = "psptool.crypto")]
pub struct KeyType {
    #[pyo3(get)]
    name: &'static str,
    #[pyo3(get)]
    signature_size: usize,
}

static RSA2048: GILOnceCell<Py<KeyType>> = GILOnceCell::new();
static RSA4096: GILOnceCell<Py<KeyType>> = GILOnceCell::new();

/// `KeyType.from_name(name)`.
pub(crate) fn key_type<'py>(py: Python<'py>, name: &str) -> PyResult<Bound<'py, KeyType>> {
    let (cell, name, signature_size) = match name {
        "rsa2048" => (&RSA2048, "rsa2048", 0x100),
        "rsa4096" => (&RSA4096, "rsa4096", 0x200),
        other => return Err(PyKeyError::new_err(other.to_owned())),
    };
    let ty = cell.get_or_try_init(py, || {
        Py::new(
            py,
            KeyType {
                name,
                signature_size,
            },
        )
    })?;
    Ok(ty.bind(py).clone())
}

#[pymethods]
impl KeyType {
    #[staticmethod]
    fn from_name<'py>(py: Python<'py>, name: &str) -> PyResult<Bound<'py, KeyType>> {
        key_type(py, name)
    }

    #[getter]
    #[allow(non_snake_case, reason = "upstream attribute name (crypto.py:124)")]
    fn PublicKey(&self, py: Python<'_>) -> Py<PyType> {
        if self.signature_size == 0x100 {
            py.get_type::<Rsa2048PublicKey>().unbind()
        } else {
            py.get_type::<Rsa4096PublicKey>().unbind()
        }
    }

    #[getter]
    #[allow(non_snake_case, reason = "upstream attribute name (crypto.py:125)")]
    fn PrivateKey(&self, py: Python<'_>) -> Py<PyType> {
        if self.signature_size == 0x100 {
            py.get_type::<Rsa2048PrivateKey>().unbind()
        } else {
            py.get_type::<Rsa4096PrivateKey>().unbind()
        }
    }

    #[pyo3(signature = (filename, password = None))]
    fn load_private_key<'py>(
        &self,
        py: Python<'py>,
        filename: &Bound<'py, PyAny>,
        password: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.PrivateKey(py)
            .bind(py)
            .call_method1("load_from_file", (filename, password))
    }

    fn generate_private_key<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.PrivateKey(py).bind(py).call_method0("generate_new")
    }

    fn make_public_key<'py>(
        &self,
        py: Python<'py>,
        crypto_material: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.PublicKey(py)
            .bind(py)
            .call_method1("from_crypto_material", (crypto_material,))
    }

    fn __repr__(&self) -> String {
        format!("KeyType({})", self.name)
    }
}

/// `PrivateKeyDict` (`crypto.py:150-175`): key-type name → private key,
/// generating missing keys on lookup.
#[pyclass(dict, module = "psptool.crypto")]
pub struct PrivateKeyDict;

#[pymethods]
impl PrivateKeyDict {
    #[new]
    #[pyo3(signature = (keys = None))]
    fn py_new<'py>(
        py: Python<'py>,
        keys: Option<Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, Self>> {
        let obj = Bound::new(py, PrivateKeyDict)?;
        obj.setattr("keys", keys.unwrap_or_else(|| PyDict::new(py)))?;
        Ok(obj)
    }

    fn __getitem__<'py>(slf: &Bound<'py, Self>, name: &str) -> PyResult<Bound<'py, PyAny>> {
        let py = slf.py();
        let keys = slf.getattr("keys")?;
        if let Ok(key) = keys.get_item(name)
            && key.is_truthy()?
        {
            return Ok(key);
        }
        let key = key_type(py, name)?.call_method0("generate_private_key")?;
        keys.set_item(name, &key)?;
        Ok(key)
    }

    /// `save_to_files(filestub, password=None)` (`crypto.py:160-163`).
    #[pyo3(signature = (filestub, password = None))]
    fn save_to_files(
        slf: &Bound<'_, Self>,
        filestub: &str,
        password: Option<String>,
    ) -> PyResult<()> {
        create_parent_dir(slf.py(), filestub)?;
        let keys = slf.getattr("keys")?;
        for item in keys.call_method0("items")?.try_iter()? {
            let (name, key): (String, Bound<'_, PyAny>) = item?.extract()?;
            key.call_method1(
                "save_to_file",
                (format!("{filestub}.{name}"), password.clone()),
            )?;
        }
        Ok(())
    }

    /// `read_from_files(filestub, password=None)` (`crypto.py:165-175`).
    #[staticmethod]
    #[pyo3(signature = (filestub, password = None))]
    fn read_from_files<'py>(
        py: Python<'py>,
        filestub: &str,
        password: Option<String>,
    ) -> PyResult<Bound<'py, Self>> {
        create_parent_dir(py, filestub)?;
        let os = py.import("os")?;
        let dirname: String = os
            .getattr("path")?
            .call_method1("dirname", (filestub,))?
            .extract()?;
        let stub: String = os
            .getattr("path")?
            .call_method1("relpath", (filestub, &dirname))?
            .extract()?;
        let keys = PyDict::new(py);
        for name in os.call_method1("listdir", (&dirname,))?.try_iter()? {
            let filename: String = name?.extract()?;
            if !filename.starts_with(&stub) {
                continue;
            }
            let Some(kind) = filename.rsplit('.').next() else {
                continue;
            };
            let key = key_type(py, kind)?.call_method1(
                "load_private_key",
                (format!("{dirname}/{filename}"), password.clone()),
            )?;
            keys.set_item(kind, key)?;
        }
        Self::py_new(py, Some(keys))
    }
}

/// `create_parent_dir` (`crypto.py:139-147`).
fn create_parent_dir(py: Python<'_>, filestub: &str) -> PyResult<()> {
    let os = py.import("os")?;
    let real = os.getattr("path")?.call_method1("realpath", (filestub,))?;
    let parent = os.getattr("path")?.call_method1("dirname", (real,))?;
    let kwargs = PyDict::new(py);
    kwargs.set_item("exist_ok", true)?;
    os.call_method("makedirs", (parent,), Some(&kwargs))?;
    Ok(())
}
