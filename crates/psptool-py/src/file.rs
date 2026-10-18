//! The file class hierarchy: `File` / `BiosFile` (`file.py:37-413`),
//! `HeaderFile` (`header_file.py:27-318`), `KeyStoreFile` and its key-store
//! views (`key_store_file.py:23-253`), `PubkeyFile` (`pubkey_file.py:27-171`)
//! and `MicrocodeFile` (`microcode_file.py:24-60`).
//!
//! Each object is a [`NestedBuffer`] over the shared image. Attributes that
//! upstream's constructors store by value (`type`, `compressed`,
//! `size_signed`, ...) are set as instance attributes when the object is
//! built (`tool.rs`); methods read the live buffer. Decoding and decode
//! verification delegate to `psptool-core` (`HeaderEntry::decode_best_effort`,
//! `HeaderEntry::get_decrypted_body`, `Entry::decode_verification`).

use md5::{Digest as _, Md5};
use pyo3::exceptions::{PyNotImplementedError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PyList, PySet, PyTuple, PyType};
use sha2::{Sha256, Sha384};

use psptool_core::body::DecodeVerification;
use psptool_core::{Entry, EntryClass, EntryRecord, EntryType, HeaderEntry, SourceBytes};

use crate::buffer::{self, NestedBuffer, hex_lower, py_hex, to_bytes};
use crate::directory::BiosDirectoryEntry;
use crate::errors;
use crate::image::IKEK;
use crate::model::{HEADER_LEN, PUBKEY_HEADER_LEN};

/// `File.ENTRY_ALIGNMENT` (`file.py:58`).
const ENTRY_ALIGNMENT: i64 = 0x10;
/// `KeyStore.HEADER_SIZE` / `KeyStoreKey.HEADER_SIZE` (`key_store_file.py:142,187`).
const KDB_HEADER_LEN: i64 = 0x50;

/// The view of `obj` as a [`NestedBuffer`].
pub(crate) fn view<'py>(obj: &Bound<'py, PyAny>) -> PyResult<PyRef<'py, NestedBuffer>> {
    Ok(obj.downcast::<NestedBuffer>()?.borrow())
}

/// `obj.get_bytes()` of an attribute holding a buffer, through Python.
fn attr_bytes(obj: &Bound<'_, PyAny>, name: &str) -> PyResult<Vec<u8>> {
    to_bytes(&obj.getattr(name)?.call_method0("get_bytes")?)
}

fn warn(py: Python<'_>, message: &str) -> PyResult<()> {
    py.import("sys")?
        .getattr("stderr")?
        .call_method1("write", (format!("Warning: {message}\n"),))?;
    Ok(())
}

fn md5_hex(data: &[u8]) -> String {
    hex_lower(&Md5::digest(data))
}

/// `utils.shannon` (`utils.py:188-206`): byte entropy / 8, computed with the
/// same operations (`math.log(p, 2)` is `log(p) / log(2)`) and order.
fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut seen = [0u64; 256];
    for &b in data {
        seen[b as usize] += 1;
    }
    let length = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &seen {
        let p = count as f64 / length;
        if p > 0.0 {
            entropy -= p * (p.ln() / 2f64.ln());
        }
    }
    entropy / 8.0
}

fn body_error(e: psptool_core::BodyError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

/// The core header of the file buffer `window`.
fn parse_header(window: &[u8]) -> PyResult<HeaderEntry> {
    HeaderEntry::parse(&SourceBytes::from_blob(window.to_vec()))
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

/// `File` (`file.py:37-393`).
#[pyclass(extends = NestedBuffer, subclass, module = "psptool.file")]
pub struct File;

#[pymethods]
impl File {
    #[classattr]
    const ENTRY_ALIGNMENT: i64 = ENTRY_ALIGNMENT;

    #[classattr]
    #[pyo3(name = "ParseError")]
    fn parse_error(py: Python<'_>) -> Py<PyType> {
        py.get_type::<errors::ParseError>().unbind()
    }

    #[classattr]
    #[pyo3(name = "UNWRAPPED_IKEK_ZEN_PLUS")]
    fn unwrapped_ikek_zen_plus(py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &psptool_core::Ikek::ZenPlus.bytes()).unbind()
    }

    #[classattr]
    #[pyo3(name = "UNWRAPPED_IKEK_ZEN")]
    fn unwrapped_ikek_zen(py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &psptool_core::Ikek::Zen.bytes()).unbind()
    }

    #[classattr]
    const NO_SIZE_ENTRY_TYPES: [i64; 1] = [0x0B];

    #[classattr]
    const KEY_STORE_TYPES: [i64; 2] = [0x50, 0x51];

    /// `File.is_signed` (`file.py:331-333`).
    #[getter]
    fn is_signed(&self) -> bool {
        false
    }

    fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
        file_repr(slf.as_any())
    }

    fn __eq__(slf: &Bound<'_, Self>, other: &Bound<'_, PyAny>) -> PyResult<PyObject> {
        let py = slf.py();
        let key = |o: &Bound<'_, PyAny>| -> PyResult<(i64, i64, i64)> {
            Ok((
                o.getattr("type")?.extract()?,
                o.call_method0("get_address")?.extract()?,
                o.getattr("buffer_size")?.extract()?,
            ))
        };
        match (key(slf.as_any()), key(other)) {
            (Ok(a), Ok(b)) => Ok((a == b).into_pyobject(py)?.to_owned().into_any().unbind()),
            _ => Ok(py.NotImplemented()),
        }
    }

    fn __hash__(slf: &Bound<'_, Self>) -> PyResult<isize> {
        let key = PyTuple::new(
            slf.py(),
            [
                slf.getattr("type")?,
                slf.call_method0("get_address")?,
                slf.getattr("buffer_size")?,
            ],
        )?;
        key.hash()
    }

    fn __lt__(slf: &Bound<'_, Self>, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        let a: i64 = slf.call_method0("get_address")?.extract()?;
        let b: i64 = other.call_method0("get_address")?.extract()?;
        Ok(a < b)
    }

    /// `get_readable_type` (`file.py:352-363`).
    fn get_readable_type(slf: &Bound<'_, Self>) -> PyResult<String> {
        readable_type(slf.as_any())
    }

    fn get_readable_destination_address(slf: &Bound<'_, Self>) -> PyResult<String> {
        let destination: i64 = slf.getattr("entry")?.getattr("destination")?.extract()?;
        Ok(py_hex(destination))
    }

    fn get_readable_version(&self) -> &'static str {
        ""
    }

    fn get_readable_magic(&self) -> &'static str {
        ""
    }

    fn get_readable_signed_by(&self) -> &'static str {
        ""
    }

    /// `shannon(self[:])` (`file.py:377-378`).
    fn shannon_entropy(slf: &Bound<'_, Self>) -> PyResult<f64> {
        Ok(shannon(&view(slf.as_any())?.read_all(slf.py())?))
    }

    /// `md5(self.get_bytes()).hexdigest()` (`file.py:380-383`).
    fn md5(slf: &Bound<'_, Self>) -> PyResult<String> {
        Ok(md5_hex(&view(slf.as_any())?.read_all(slf.py())?))
    }

    /// `move_buffer` (`file.py:385-393`): move/resize the buffer and rewrite
    /// every referencing directory record. The new size is kept exact (no
    /// `ENTRY_ALIGNMENT` round-up, PSPTool PR #77; see `DEVIATIONS.md`).
    fn move_buffer(slf: &Bound<'_, Self>, new_address: i64, size: i64) -> PyResult<()> {
        let current: i64 = slf.call_method0("get_address")?.extract()?;
        {
            let mut nb = slf.downcast::<NestedBuffer>()?.borrow_mut();
            nb.offset += new_address - current;
            nb.size = size;
        }
        let (offset, size) = {
            let nb = view(slf.as_any())?;
            (nb.offset, nb.size)
        };
        let file_type = slf.getattr("type")?;
        for directory in slf.getattr("references")?.try_iter()? {
            directory?.call_method1("update_entry_fields", (slf, &file_type, size, offset))?;
        }
        Ok(())
    }
}

/// `File.__repr__` (`file.py:335-337`).
fn file_repr(slf: &Bound<'_, PyAny>) -> PyResult<String> {
    let name = slf.get_type().name()?;
    let file_type: i64 = slf.getattr("type")?.extract()?;
    let address: i64 = slf.call_method0("get_address")?.extract()?;
    let size: i64 = slf.getattr("buffer_size")?.extract()?;
    let references = slf.getattr("references")?.len()?;
    Ok(format!(
        "{name}(type={}, address={}, size={}, len(references)={references})",
        py_hex(file_type),
        py_hex(address),
        py_hex(size)
    ))
}

/// `File.get_readable_type` (`file.py:352-363`): the BIOS overrides apply
/// when the entry is exactly a `BiosDirectoryEntry`.
pub(crate) fn readable_type(slf: &Bound<'_, PyAny>) -> PyResult<String> {
    let file_type: u8 = slf.getattr("type")?.extract()?;
    let is_bios = slf
        .getattr("entry")?
        .is_exact_instance_of::<BiosDirectoryEntry>();
    Ok(psptool_ops::readable_type(EntryType(file_type), is_bios))
}

/// `BiosFile` (`file.py:396-413`).
#[pyclass(extends = File, subclass, module = "psptool.file")]
pub struct BiosFile;

#[pymethods]
impl BiosFile {
    /// APOBs have no address (`file.py:401-407`).
    fn get_address(slf: &Bound<'_, Self>) -> PyResult<i64> {
        if readable_type(slf.as_any())? == "APOB" {
            return Ok(0);
        }
        let (offset, parent) = {
            let nb = view(slf.as_any())?;
            (nb.offset, nb.parent.as_ref().map(|p| p.clone_ref(slf.py())))
        };
        match parent {
            Some(p) => Ok(offset
                + p.bind(slf.py())
                    .call_method0("get_address")?
                    .extract::<i64>()?),
            None => Ok(offset),
        }
    }

    fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
        let base = file_repr(slf.as_any())?;
        let destination: i64 = slf.getattr("destination")?.extract()?;
        Ok(format!(
            "{}, destination={})",
            &base[..base.len() - 1],
            py_hex(destination)
        ))
    }

    fn get_readable_destination_address(slf: &Bound<'_, Self>) -> PyResult<String> {
        Ok(py_hex(slf.getattr("destination")?.extract()?))
    }
}

/// `HeaderFile` (`header_file.py:27-318`). `record` is the directory record
/// the file was created from; decode verification needs it to rebuild the
/// core [`Entry`]. The decode and verification results are cached per image
/// generation and buffer window, so the upstream call pattern
/// (`decode_verified()`, then `decode_verification_method()`, then
/// `plaintext_identity_ok()`) verifies once; any write invalidates them.
#[pyclass(extends = File, subclass, module = "psptool.header_file")]
pub struct HeaderFile {
    pub(crate) record: EntryRecord,
    decoded: Option<(CacheKey, Vec<u8>, bool)>,
    verified: Option<(CacheKey, DecodeVerification)>,
}

impl HeaderFile {
    pub(crate) fn new(record: EntryRecord) -> Self {
        Self {
            record,
            decoded: None,
            verified: None,
        }
    }
}

/// What a cached decode depends on: the image generation and the window.
#[derive(Clone, Copy, PartialEq, Eq)]
struct CacheKey {
    generation: u64,
    start: i64,
    size: i64,
}

fn cache_key(slf: &Bound<'_, PyAny>) -> PyResult<CacheKey> {
    let nb = view(slf)?;
    Ok(CacheKey {
        generation: nb.image.generation(),
        start: nb.absolute(slf.py())?,
        size: nb.size,
    })
}

impl HeaderFile {
    /// The live file buffer and its parsed header.
    fn window(slf: &Bound<'_, PyAny>) -> PyResult<(Vec<u8>, HeaderEntry)> {
        let window = view(slf)?.read_all(slf.py())?;
        let header = parse_header(&window)?;
        Ok((window, header))
    }

    /// `_decrypted_decompressed_body` (`header_file.py:172-186`).
    pub(crate) fn decode(slf: &Bound<'_, PyAny>) -> PyResult<(Vec<u8>, bool)> {
        let key = cache_key(slf)?;
        let this = slf.downcast::<HeaderFile>()?;
        if let Some((k, body, ok)) = &this.borrow().decoded
            && *k == key
        {
            return Ok((body.clone(), *ok));
        }
        let (window, header) = Self::window(slf)?;
        let (body, ok) = header
            .decode_best_effort(&window, IKEK)
            .map_err(body_error)?;
        this.borrow_mut().decoded = Some((key, body.clone(), ok));
        Ok((body, ok))
    }

    /// `decode_verification()` (`header_file.py:191-243`) through the core
    /// ladder, over the image-wide certifying keys.
    fn verification(slf: &Bound<'_, PyAny>) -> PyResult<DecodeVerification> {
        let key = cache_key(slf)?;
        let this = slf.downcast::<HeaderFile>()?;
        if let Some((k, v)) = &this.borrow().verified
            && *k == key
        {
            return Ok(*v);
        }
        let v = Self::verify_uncached(slf)?;
        this.borrow_mut().verified = Some((key, v));
        Ok(v)
    }

    fn verify_uncached(slf: &Bound<'_, PyAny>) -> PyResult<DecodeVerification> {
        let py = slf.py();
        let record = slf.downcast::<HeaderFile>()?.borrow().record.clone();
        let (image, start, len) = {
            let nb = view(slf)?;
            (std::sync::Arc::clone(&nb.image), nb.absolute(py)?, nb.size)
        };
        let snapshot = image.snapshot();
        let start =
            u64::try_from(start).map_err(|_| PyValueError::new_err("negative file address"))?;
        let len = u64::try_from(len).map_err(|_| PyValueError::new_err("negative file size"))?;
        let window = snapshot
            .source()
            .subslice_at(start..start + len)
            .ok_or_else(|| PyValueError::new_err("file buffer lies outside the image"))?;
        let header =
            HeaderEntry::parse(&window).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let class = if slf.is_instance_of::<KeyStoreFile>() {
            EntryClass::KeyStore(header)
        } else {
            EntryClass::Header(header)
        };
        let entry = Entry {
            record,
            body: window,
            class,
        };
        entry
            .decode_verification(snapshot.source(), snapshot.keys(), IKEK)
            .ok_or_else(|| PyValueError::new_err("not a HeaderFile-class entry"))
    }

    fn checksum_matches(slf: &Bound<'_, PyAny>, field: &str, sha384: bool) -> PyResult<bool> {
        let stored = attr_bytes(slf, field)?;
        let data = to_bytes(&slf.call_method0("get_checksummed_bytes")?)?;
        let digest = if sha384 {
            Sha384::digest(&data).to_vec()
        } else {
            Sha256::digest(&data).to_vec()
        };
        Ok(stored == digest)
    }
}

#[pymethods]
impl HeaderFile {
    #[classattr]
    const HEADER_LEN: u64 = HEADER_LEN;

    /// `get_checksummed_bytes` (`header_file.py:109-110`).
    fn get_checksummed_bytes<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(slf.py(), &Self::decode(slf.as_any())?.0))
    }

    #[pyo3(signature = (print_warning = true))]
    fn verify_sha256(slf: &Bound<'_, Self>, print_warning: bool) -> PyResult<bool> {
        let ok = Self::checksum_matches(slf.as_any(), "_sha256_checksum", false)?;
        if !ok && print_warning {
            warn(
                slf.py(),
                &format!("Could not verify sha256 checksum for {}", slf.repr()?),
            )?;
        }
        Ok(ok)
    }

    /// `update_sha256` (`header_file.py:119-121`).
    fn update_sha256(slf: &Bound<'_, Self>) -> PyResult<()> {
        let data = to_bytes(&slf.call_method0("get_checksummed_bytes")?)?;
        let digest = Sha256::digest(&data);
        let field = slf.getattr("_sha256_checksum")?;
        view(&field)?.write(slf.py(), None, None, None, &digest)?;
        slf.call_method0("verify_sha256")?;
        Ok(())
    }

    #[pyo3(signature = (print_warning = true))]
    fn verify_sha384(slf: &Bound<'_, Self>, print_warning: bool) -> PyResult<bool> {
        let ok = Self::checksum_matches(slf.as_any(), "_sha384_checksum", true)?;
        if !ok && print_warning {
            warn(
                slf.py(),
                &format!("Could not verify sha384 checksum for {}", slf.repr()?),
            )?;
        }
        Ok(ok)
    }

    /// `is_signed` (`header_file.py:130-135`), read live from header `0x30`.
    #[getter]
    fn is_signed(slf: &Bound<'_, Self>) -> PyResult<bool> {
        let signed = u32::from_le_bytes(word(&view(slf.as_any())?.read(slf.py(), 0x30, 4)?));
        if !matches!(signed, 0 | 1 | 0xFFFF_0000) {
            return Err(errors::ParseError::new_err(format!(
                "Did not expect signed to be 0x{signed:x}"
            )));
        }
        Ok(signed != 0)
    }

    /// `'.'.join(hex(b)[2:].upper() ...)` over `version` (`header_file.py:137-138`).
    fn get_readable_version(slf: &Bound<'_, Self>) -> PyResult<String> {
        let version = to_bytes(&slf.getattr("version")?)?;
        Ok(version
            .iter()
            .map(|b| format!("{b:X}"))
            .collect::<Vec<_>>()
            .join("."))
    }

    /// `get_readable_magic` (`header_file.py:146-163`).
    fn get_readable_magic(slf: &Bound<'_, Self>) -> PyResult<String> {
        let magic = to_bytes(&slf.getattr("magic")?)?;
        Ok(readable_magic(&magic))
    }

    fn get_readable_signed_by(slf: &Bound<'_, Self>) -> PyResult<PyObject> {
        Ok(slf
            .getattr("signed_entity")?
            .getattr("certifying_id")?
            .getattr("magic")?
            .unbind())
    }

    /// `(header + decrypted/decompressed body)[:0x100 + size_signed]`
    /// (`header_file.py:168-170`).
    fn get_signed_bytes<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyBytes>> {
        let mut out = attr_bytes(slf.as_any(), "header")?;
        let header_len = out.len();
        out.extend_from_slice(&to_bytes(
            &slf.call_method0("get_decrypted_decompressed_body")?,
        )?);
        let size_signed: usize = slf.getattr("size_signed")?.extract()?;
        out.truncate(header_len + size_signed);
        Ok(PyBytes::new(slf.py(), &out))
    }

    #[pyo3(signature = (print_warning = true))]
    fn _decrypted_decompressed_body<'py>(
        slf: &Bound<'py, Self>,
        print_warning: bool,
    ) -> PyResult<(Bound<'py, PyBytes>, bool)> {
        let (body, ok) = Self::decode(slf.as_any())?;
        if !ok && print_warning {
            let kind = readable_type(slf.as_any())?;
            warn(
                slf.py(),
                &format!("ZLIB decompression failed on file {kind}"),
            )?;
        }
        Ok((PyBytes::new(slf.py(), &body), ok))
    }

    /// `get_decrypted_decompressed_body` (`header_file.py:188-189`).
    fn get_decrypted_decompressed_body<'py>(
        slf: &Bound<'py, Self>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        Ok(Self::_decrypted_decompressed_body(slf, true)?.0)
    }

    /// `(decode_verified, basis)` (`header_file.py:191-196`).
    #[pyo3(signature = (print_warning = false))]
    fn decode_verification(
        slf: &Bound<'_, Self>,
        print_warning: bool,
    ) -> PyResult<(bool, &'static str)> {
        let _ = print_warning;
        let v = Self::verification(slf.as_any())?;
        Ok((v.decode_verified(), v.decode_verification_method().as_str()))
    }

    #[pyo3(signature = (print_warning = false))]
    fn decode_verified(slf: &Bound<'_, Self>, print_warning: bool) -> PyResult<bool> {
        Ok(Self::decode_verification(slf, print_warning)?.0)
    }

    fn decode_verification_method(slf: &Bound<'_, Self>) -> PyResult<&'static str> {
        Ok(Self::decode_verification(slf, false)?.1)
    }

    /// `plaintext_identity_ok` (`header_file.py:267-276`).
    fn plaintext_identity_ok(slf: &Bound<'_, Self>) -> PyResult<bool> {
        Ok(Self::verification(slf.as_any())?.plaintext_identity_ok())
    }

    /// `to_decrypted_file_bytes` (`header_file.py:278-284`).
    fn to_decrypted_file_bytes<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyBytes>> {
        let mut out = attr_bytes(slf.as_any(), "header")?;
        if out.len() < 0x30 {
            return Err(PyValueError::new_err("header shorter than 0x30 bytes"));
        }
        out[0x18..0x1C].fill(0);
        out[0x20..0x30].fill(0);
        out.extend_from_slice(&to_bytes(&slf.call_method0("get_decrypted_body")?)?);
        if slf.getattr("is_signed")?.is_truthy()? {
            out.extend_from_slice(&attr_bytes(slf.as_any(), "signature")?);
        }
        Ok(PyBytes::new(slf.py(), &out))
    }

    /// `get_decrypted_body` (`header_file.py:286-292`).
    fn get_decrypted_body<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyBytes>> {
        let py = slf.py();
        if !slf.getattr("encrypted")?.is_truthy()? {
            return Ok(PyBytes::new(py, &attr_bytes(slf.as_any(), "body")?));
        }
        let (window, header) = Self::window(slf.as_any())?;
        let plain = header
            .get_decrypted_body(&window, IKEK)
            .map_err(body_error)?;
        Ok(PyBytes::new(py, &plain))
    }

    fn get_unwrapped_ikek<'py>(slf: &Bound<'py, Self>) -> Bound<'py, PyBytes> {
        PyBytes::new(slf.py(), &IKEK.bytes())
    }

    /// `shannon(self.body[:])` (`header_file.py:309-310`).
    fn shannon_entropy(slf: &Bound<'_, Self>) -> PyResult<f64> {
        Ok(shannon(&attr_bytes(slf.as_any(), "body")?))
    }

    /// `md5(self.body.get_bytes())`; a read failure hashes nothing, as the
    /// upstream `except` does (`header_file.py:312-318`).
    fn md5(slf: &Bound<'_, Self>) -> PyResult<String> {
        Ok(md5_hex(
            &attr_bytes(slf.as_any(), "body").unwrap_or_default(),
        ))
    }
}

/// `HeaderFile.get_readable_magic` (`header_file.py:146-163`): `\x05\0\0\0`
/// reads as `0x05`; otherwise ASCII with unprintables dropped, `''` when
/// not ASCII.
fn readable_magic(magic: &[u8]) -> String {
    let magic: &[u8] = if magic == b"\x05\x00\x00\x00" {
        b"0x05"
    } else {
        magic
    };
    if !magic.is_ascii() {
        return String::new();
    }
    // `string.printable`: digits, letters, punctuation and whitespace.
    magic
        .iter()
        .filter(|b| b.is_ascii_graphic() || matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C))
        .map(|&b| b as char)
        .collect()
}

fn word(b: &[u8]) -> [u8; 4] {
    let mut w = [0u8; 4];
    w.copy_from_slice(&b[..4]);
    w
}

/// `KeyStoreFile` (`key_store_file.py:23-64`).
#[pyclass(extends = HeaderFile, module = "psptool.key_store_file")]
pub struct KeyStoreFile;

#[pymethods]
impl KeyStoreFile {
    fn get_checksummed_bytes(slf: &Bound<'_, Self>) -> PyResult<PyObject> {
        Ok(slf
            .getattr("key_store")?
            .call_method0("get_bytes")?
            .unbind())
    }

    /// `header || key_store` (`key_store_file.py:50-51`).
    fn get_signed_bytes<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyBytes>> {
        let mut out = attr_bytes(slf.as_any(), "header")?;
        out.extend_from_slice(&attr_bytes(slf.as_any(), "key_store")?);
        Ok(PyBytes::new(slf.py(), &out))
    }

    fn get_readable_version(&self) -> &'static str {
        "1"
    }

    /// `f'{self.header.magic}'[2:-1]` (`key_store_file.py:56-57`).
    fn get_readable_magic(slf: &Bound<'_, Self>) -> PyResult<String> {
        let magic = slf.getattr("header")?.getattr("magic")?;
        let text = magic.str()?.to_string();
        Ok(text
            .get(2..text.len().saturating_sub(1))
            .unwrap_or_default()
            .to_owned())
    }

    fn get_readable_signed_by(slf: &Bound<'_, Self>) -> PyResult<PyObject> {
        Ok(slf
            .getattr("header")?
            .getattr("certifying_id")?
            .getattr("magic")?
            .unbind())
    }

    #[getter]
    fn is_signed(&self) -> bool {
        true
    }
}

/// `KeyStoreFileHeader` (`key_store_file.py:67-137`).
#[pyclass(extends = NestedBuffer, module = "psptool.key_store_file")]
pub struct KeyStoreFileHeader;

impl KeyStoreFileHeader {
    fn u32_at(slf: &Bound<'_, Self>, offset: i64) -> PyResult<u32> {
        Ok(u32::from_le_bytes(word(&view(slf.as_any())?.read(
            slf.py(),
            offset,
            4,
        )?)))
    }
}

#[pymethods]
impl KeyStoreFileHeader {
    #[classattr]
    const HEADER_SIZE: i64 = 0x100;

    #[getter]
    fn magic<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(
            slf.py(),
            &view(slf.as_any())?.read(slf.py(), 0x10, 4)?,
        ))
    }

    #[setter]
    fn set_magic(slf: &Bound<'_, Self>, value: &Bound<'_, PyAny>) -> PyResult<()> {
        let value = to_bytes(value)?;
        view(slf.as_any())?.write(slf.py(), Some(0x10), Some(0x14), None, &value)
    }

    #[getter]
    fn body_size(slf: &Bound<'_, Self>) -> PyResult<u32> {
        Self::u32_at(slf, 0x14)
    }

    #[getter]
    fn packed_size(slf: &Bound<'_, Self>) -> PyResult<u32> {
        Self::u32_at(slf, 0x6C)
    }

    #[getter]
    fn keystore_type(slf: &Bound<'_, Self>) -> PyResult<u32> {
        Self::u32_at(slf, 0x7C)
    }

    /// `signature_size` (`key_store_file.py:125-130`).
    #[getter]
    fn signature_size(slf: &Bound<'_, Self>) -> PyResult<i64> {
        let packed = i64::from(Self::u32_at(slf, 0x6C)?);
        let body = i64::from(Self::u32_at(slf, 0x14)?);
        if packed != 0 {
            return Ok(packed - 0x100 - body);
        }
        let parent: i64 = slf
            .getattr("parent_buffer")?
            .getattr("buffer_size")?
            .extract()?;
        Ok(parent - body - 0x100)
    }

    #[getter]
    fn unknown_constants<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyTuple>> {
        let nb = view(slf.as_any())?;
        let a = PyBytes::new(slf.py(), &nb.read(slf.py(), 0x30, 4)?);
        let b = PyBytes::new(slf.py(), &nb.read(slf.py(), 0x34, 4)?);
        PyTuple::new(slf.py(), [a, b])
    }
}

/// `KeyStore` (`key_store_file.py:140-182`).
#[pyclass(extends = NestedBuffer, module = "psptool.key_store_file")]
pub struct KeyStore;

#[pymethods]
impl KeyStore {
    #[classattr]
    const HEADER_SIZE: i64 = KDB_HEADER_LEN;

    #[getter]
    fn size(slf: &Bound<'_, Self>) -> PyResult<u32> {
        Ok(u32::from_le_bytes(word(&view(slf.as_any())?.read(
            slf.py(),
            0,
            4,
        )?)))
    }

    #[getter]
    fn unknown_flag(slf: &Bound<'_, Self>) -> PyResult<bool> {
        Ok(u32::from_le_bytes(word(&view(slf.as_any())?.read(slf.py(), 4, 4)?)) == 1)
    }
}

/// `KeyStoreKey` (`key_store_file.py:185-253`).
#[pyclass(extends = NestedBuffer, module = "psptool.key_store_file")]
pub struct KeyStoreKey;

impl KeyStoreKey {
    fn header_u32(slf: &Bound<'_, Self>, offset: i64) -> PyResult<u32> {
        let header = slf.getattr("header")?;
        Ok(u32::from_le_bytes(word(&view(&header)?.read(
            slf.py(),
            offset,
            4,
        )?)))
    }
}

#[pymethods]
impl KeyStoreKey {
    #[classattr]
    const HEADER_SIZE: i64 = KDB_HEADER_LEN;

    #[getter]
    fn size(slf: &Bound<'_, Self>) -> PyResult<u32> {
        Self::header_u32(slf, 0)
    }

    #[getter]
    fn unknown_flag(slf: &Bound<'_, Self>) -> PyResult<bool> {
        Ok(Self::header_u32(slf, 4)? == 1)
    }

    #[getter]
    fn unknown_id(slf: &Bound<'_, Self>) -> PyResult<u32> {
        Self::header_u32(slf, 8)
    }

    #[getter]
    fn rsa_exponent(slf: &Bound<'_, Self>) -> PyResult<u32> {
        Self::header_u32(slf, 0xC)
    }

    #[getter]
    fn key_size(slf: &Bound<'_, Self>) -> PyResult<u32> {
        Self::header_u32(slf, 0x20)
    }
}

/// `PubkeyFile` (`pubkey_file.py:27-171`).
#[pyclass(extends = File, subclass, module = "psptool.pubkey_file")]
pub struct PubkeyFile;

impl PubkeyFile {
    fn u32_at(slf: &Bound<'_, Self>, offset: i64) -> PyResult<u32> {
        Ok(u32::from_le_bytes(word(&view(slf.as_any())?.read(
            slf.py(),
            offset,
            4,
        )?)))
    }

    fn sizes(slf: &Bound<'_, Self>) -> PyResult<(i64, i64)> {
        let pubexp_bits = i64::from(Self::u32_at(slf, 0x38)?);
        let modulus_bits = i64::from(Self::u32_at(slf, 0x3C)?);
        Ok((pubexp_bits >> 3, modulus_bits >> 3))
    }

    fn int_from_le<'py>(py: Python<'py>, bytes: &[u8]) -> PyResult<Bound<'py, PyAny>> {
        py.get_type::<pyo3::types::PyInt>()
            .call_method1("from_bytes", (PyBytes::new(py, bytes), "little"))
    }
}

#[pymethods]
impl PubkeyFile {
    #[classattr]
    const HEADER_LEN: u64 = PUBKEY_HEADER_LEN;

    #[classattr]
    #[pyo3(name = "KNOWN_VERSIONS")]
    fn known_versions(py: Python<'_>) -> PyResult<Py<PySet>> {
        Ok(PySet::new(py, [1, 2])?.unbind())
    }

    #[getter]
    fn version(slf: &Bound<'_, Self>) -> PyResult<u32> {
        Self::u32_at(slf, 0)
    }

    #[getter]
    fn key_usage(slf: &Bound<'_, Self>) -> PyResult<u32> {
        Self::u32_at(slf, 0x24)
    }

    #[getter]
    fn pubexp_bits(slf: &Bound<'_, Self>) -> PyResult<u32> {
        Self::u32_at(slf, 0x38)
    }

    #[getter]
    fn modulus_bits(slf: &Bound<'_, Self>) -> PyResult<u32> {
        Self::u32_at(slf, 0x3C)
    }

    #[getter]
    fn pubexp_size(slf: &Bound<'_, Self>) -> PyResult<i64> {
        Ok(Self::sizes(slf)?.0)
    }

    #[getter]
    fn modulus_size(slf: &Bound<'_, Self>) -> PyResult<i64> {
        Ok(Self::sizes(slf)?.1)
    }

    /// `buffer_size - HEADER_LEN - pubexp_size - modulus_size`.
    #[getter]
    fn signature_size(slf: &Bound<'_, Self>) -> PyResult<i64> {
        let (pe, m) = Self::sizes(slf)?;
        Ok(view(slf.as_any())?.size - PUBKEY_HEADER_LEN as i64 - pe - m)
    }

    #[getter]
    fn is_signed(slf: &Bound<'_, Self>) -> PyResult<bool> {
        Ok(Self::signature_size(slf)? != 0)
    }

    #[getter]
    fn pubexp<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyAny>> {
        let bytes = attr_bytes(slf.as_any(), "_pubexp")?;
        Self::int_from_le(slf.py(), &bytes)
    }

    #[getter]
    fn modulus<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyAny>> {
        let bytes = attr_bytes(slf.as_any(), "_modulus")?;
        Self::int_from_le(slf.py(), &bytes)
    }

    #[getter]
    fn security_features(slf: &Bound<'_, Self>) -> PyResult<u16> {
        let b = view(slf.as_any())?.read(slf.py(), 0x2A, 2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn get_modulus_bytes<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyBytes>> {
        Ok(PyBytes::new(
            slf.py(),
            &attr_bytes(slf.as_any(), "_modulus")?,
        ))
    }

    /// `get_der_encoded` (`pubkey_file.py:32-43`), modulus bytes as stored.
    fn get_der_encoded<'py>(slf: &Bound<'py, Self>) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let pubexp = attr_bytes(slf.as_any(), "_pubexp")?;
        if Self::int_from_le(slf.py(), &pubexp)?.extract::<u64>().ok() != Some(65537) {
            return Err(PyNotImplementedError::new_err(
                "Only an exponent of 65537 is supported.",
            ));
        }
        let modulus = attr_bytes(slf.as_any(), "_modulus")?;
        let prefix: &[u8] = match modulus.len() {
            0x100 => b"\x30\x82\x01\x22\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x01\x0F\x00\x30\x82\x01\x0A\x02\x82\x01\x01\x00",
            0x200 => b"\x30\x82\x02\x22\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00\x03\x82\x02\x0F\x00\x30\x82\x02\x0A\x02\x82\x02\x01\x00",
            _ => return Ok(None),
        };
        let mut der = prefix.to_vec();
        der.extend_from_slice(&modulus);
        der.extend_from_slice(b"\x02\x03\x01\x00\x01");
        Ok(Some(PyBytes::new(slf.py(), &der)))
    }

    /// `get_pem_encoded` (`pubkey_file.py:45-48`).
    fn get_pem_encoded<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyBytes>> {
        let py = slf.py();
        let der = slf.call_method0("get_der_encoded")?;
        let b64 = to_bytes(&py.import("base64")?.call_method1("b64encode", (der,))?)?;
        let mut pem = b"-----BEGIN PUBLIC KEY-----\n".to_vec();
        pem.extend_from_slice(&b64.chunks(64).collect::<Vec<_>>().join(&b'\n'));
        pem.extend_from_slice(b"\n-----END PUBLIC KEY-----\n");
        Ok(PyBytes::new(py, &pem))
    }

    /// `get_bytes(0, buffer_size - signature_size)` (`pubkey_file.py:139-140`).
    fn get_signed_bytes<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyBytes>> {
        let signature = Self::signature_size(slf)?;
        let nb = view(slf.as_any())?;
        Ok(PyBytes::new(
            slf.py(),
            &nb.read(slf.py(), 0, nb.size - signature)?,
        ))
    }

    fn get_readable_signed_by(slf: &Bound<'_, Self>) -> PyResult<Option<PyObject>> {
        if !Self::is_signed(slf)? {
            return Ok(None);
        }
        Ok(Some(
            slf.getattr("certifying_id")?.getattr("magic")?.unbind(),
        ))
    }

    fn get_readable_magic(slf: &Bound<'_, Self>) -> PyResult<PyObject> {
        Ok(slf.getattr("key_id")?.getattr("magic")?.unbind())
    }

    fn get_readable_version(slf: &Bound<'_, Self>) -> PyResult<String> {
        Ok(Self::u32_at(slf, 0)?.to_string())
    }

    /// `get_readable_key_usage` (`pubkey_file.py:152-161`).
    fn get_readable_key_usage(slf: &Bound<'_, Self>) -> PyResult<String> {
        Ok(match Self::u32_at(slf, 0x24)? {
            0 => "AMD_CODE_SIGN".to_owned(),
            1 => "BIOS_CODE_SIGN".to_owned(),
            2 => "AMD_AND_BIOS_CODE_SIGN".to_owned(),
            8 => "PLATFORM_SECURE_BOOT".to_owned(),
            other => format!("unknown_key_usage({other})"),
        })
    }

    /// `get_readable_security_features` (`pubkey_file.py:163-171`).
    fn get_readable_security_features(slf: &Bound<'_, Self>) -> PyResult<String> {
        let features = Self::security_features(slf)?;
        let mut out = Vec::new();
        if features & 0b001 != 0 {
            out.push("DISABLE_BIOS_KEY_ANTI_ROLLBACK");
        }
        if features & 0b010 != 0 {
            out.push("DISABLE_AMD_BIOS_KEY_USE");
        }
        if features & 0b100 != 0 {
            out.push("DISABLE_SECURE_DEBUG_UNLOCK");
        }
        Ok(out.join(", "))
    }
}

/// `MicrocodeFile` (`microcode_file.py:24-60`).
#[pyclass(extends = BiosFile, module = "psptool.microcode_file")]
pub struct MicrocodeFile;

#[pymethods]
impl MicrocodeFile {
    fn get_readable_version(slf: &Bound<'_, Self>) -> PyResult<PyObject> {
        let header = slf.getattr("header")?;
        if !header.is_none() {
            return Ok(header.call_method0("get_readable_version")?.unbind());
        }
        let level: i64 = slf.getattr("patch_level")?.extract()?;
        Ok(py_hex(level).into_pyobject(slf.py())?.into_any().unbind())
    }

    fn get_readable_magic(slf: &Bound<'_, Self>) -> PyResult<PyObject> {
        let header = slf.getattr("header")?;
        if !header.is_none() {
            return Ok(header.call_method0("get_readable_magic")?.unbind());
        }
        Ok("".into_pyobject(slf.py())?.into_any().unbind())
    }

    /// `'%.2d/%.2d/%.4d' % (day, month, year)` (`microcode_file.py:56-57`).
    fn get_readable_date(slf: &Bound<'_, Self>) -> PyResult<String> {
        let day: i64 = slf.getattr("day")?.extract()?;
        let month: i64 = slf.getattr("month")?.extract()?;
        let year: i64 = slf.getattr("year")?.extract()?;
        Ok(format!("{day:02}/{month:02}/{year:04}"))
    }

    /// Upstream's repr (`microcode_file.py:59-60`), unclosed parenthesis
    /// included.
    fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
        let base = file_repr(slf.as_any())?;
        let destination: i64 = slf.getattr("destination")?.extract()?;
        let bios = format!(
            "{}, destination={})",
            &base[..base.len() - 1],
            py_hex(destination)
        );
        let version: String = slf.call_method0("get_readable_version")?.extract()?;
        let date: String = slf.call_method0("get_readable_date")?.extract()?;
        Ok(format!("{}{version}{date}", &bios[..bios.len() - 1]))
    }
}

/// Everything `tool.rs` needs to instantiate one file object.
pub(crate) struct FileArgs<'a, 'py> {
    pub psptool: &'a Bound<'py, PyAny>,
    pub rom: &'a Bound<'py, PyAny>,
    pub directory: &'a Bound<'py, PyAny>,
    pub entry: &'a Bound<'py, PyAny>,
    pub record: &'a EntryRecord,
    pub offset: i64,
    pub size: i64,
}

/// Instance attributes `File.__init__` sets (`file.py:274-327`).
fn init_file(obj: &Bound<'_, PyAny>, a: &FileArgs<'_, '_>) -> PyResult<()> {
    let py = obj.py();
    let compressed: PyObject = match a.record {
        EntryRecord::Bios(b) => i64::from((b.flags >> 3) & 1)
            .into_pyobject(py)?
            .into_any()
            .unbind(),
        EntryRecord::Psp(_) => false.into_pyobject(py)?.to_owned().into_any().unbind(),
    };
    obj.setattr("blob", a.rom)?;
    obj.setattr("psptool", a.psptool)?;
    obj.setattr("entry", a.entry)?;
    obj.setattr("type", a.record.entry_type().get())?;
    obj.setattr("compressed", compressed)?;
    obj.setattr("encrypted", false)?;
    obj.setattr("is_legacy", false)?;
    obj.setattr("size_uncompressed", 0)?;
    obj.setattr("references", PyList::new(py, [a.directory])?)?;
    obj.setattr("parent_directory", a.directory)?;
    if let EntryRecord::Bios(b) = a.record {
        obj.setattr("destination", b.destination)?;
    }
    Ok(())
}

fn base(a: &FileArgs<'_, '_>) -> PyResult<NestedBuffer> {
    NestedBuffer::child(a.rom, a.size, a.offset, false, false)
}

pub(crate) fn plain_file<'py>(a: &FileArgs<'_, 'py>, bios: bool) -> PyResult<Bound<'py, PyAny>> {
    let py = a.rom.py();
    let init = PyClassInitializer::from(base(a)?).add_subclass(File);
    let obj = if bios {
        Bound::new(py, init.add_subclass(BiosFile))?.into_any()
    } else {
        Bound::new(py, init)?.into_any()
    };
    init_file(&obj, a)?;
    Ok(obj)
}

/// A `HeaderFile` (or `KeyStoreFile`) with the `_parse` attributes
/// (`header_file.py:31-107`).
pub(crate) fn header_file<'py>(
    a: &FileArgs<'_, 'py>,
    signature_len: i64,
    key_store: bool,
) -> PyResult<Bound<'py, PyAny>> {
    let py = a.rom.py();
    let init = PyClassInitializer::from(base(a)?)
        .add_subclass(File)
        .add_subclass(HeaderFile::new(a.record.clone()));
    let obj = if key_store {
        Bound::new(py, init.add_subclass(KeyStoreFile))?.into_any()
    } else {
        Bound::new(py, init)?.into_any()
    };
    init_file(&obj, a)?;
    let h = view(&obj)?.read(py, 0, HEADER_LEN as i64)?;
    let u32_at = |o: usize| u32::from_le_bytes(word(&h[o..o + 4]));
    let header = buffer::nested(&obj, HEADER_LEN as i64, 0)?;
    obj.setattr("header", &header)?;
    obj.setattr("signed_entity", py.None())?;
    obj.setattr("inline_keys", PySet::empty(py)?)?;
    obj.setattr("magic", PyByteArray::new(py, &h[0x10..0x14]))?;
    obj.setattr("size_signed", u32_at(0x14))?;
    obj.setattr("encrypted", u32_at(0x18) == 1)?;
    obj.setattr("_sha256_checksum", buffer::nested(&obj, 0x20, 0xD0)?)?;
    obj.setattr("_sha384_checksum", buffer::nested(&obj, 0x30, 0xD0)?)?;
    obj.setattr("_signed", buffer::nested(&obj, 4, 0x30)?)?;
    obj.setattr("signature_type", u32_at(0x34))?;
    obj.setattr(
        "signature_fingerprint",
        PyBytes::new(py, hex_lower(&h[0x38..0x48]).as_bytes()),
    )?;
    obj.setattr("compressed", u32_at(0x48) == 1)?;
    obj.setattr("unknown_field_2", u32_at(0x4C))?;
    obj.setattr("size_uncompressed", u32_at(0x50))?;
    obj.setattr("zlib_size", u32_at(0x54))?;
    let bitfield = u32::from_be_bytes(word(&h[0x58..0x5C]));
    obj.setattr("bitfield", bitfield)?;
    obj.setattr(
        "version",
        PyByteArray::new(py, &[h[0x63], h[0x62], h[0x61], h[0x60]]),
    )?;
    obj.setattr("load_addr", u32_at(0x68))?;
    obj.setattr("rom_size", a.size)?;
    obj.setattr("unknown_field_3", u32_at(0x7C))?;
    obj.setattr("has_sha256_checksum", bitfield & 0b01)?;
    obj.setattr("has_sha384_checksum", bitfield & 0b10)?;
    obj.setattr("signature_len", signature_len)?;
    if signature_len != 0 {
        obj.setattr(
            "signature",
            buffer::nested(&obj, signature_len, a.size - signature_len)?,
        )?;
    }
    if u32_at(0x18) == 1 {
        obj.setattr("iv", PyByteArray::new(py, &h[0x20..0x30]))?;
        obj.setattr("key", PyByteArray::new(py, &h[0x80..0x90]))?;
    }
    let body_len = (a.size - HEADER_LEN as i64 - signature_len).max(0);
    obj.setattr("body", buffer::nested(&obj, body_len, HEADER_LEN as i64)?)?;
    obj.setattr("is_legacy", false)?;
    if key_store {
        init_key_store(&obj)?;
    }
    Ok(obj)
}

/// `KeyStoreFile._parse` after `HeaderFile._parse` (`key_store_file.py:28-48`).
fn init_key_store(obj: &Bound<'_, PyAny>) -> PyResult<()> {
    let py = obj.py();
    obj.setattr("signed_entity", py.None())?;
    let header_base = NestedBuffer::child(obj, 0x100, 0, false, false)?;
    let header = Bound::new(
        py,
        PyClassInitializer::from(header_base).add_subclass(KeyStoreFileHeader),
    )?;
    for (name, size, offset) in [
        ("_magic", 4, 0x10),
        ("_body_size", 4, 0x14),
        ("_packed_size", 4, 0x6C),
        ("_unknown_constant_1", 4, 0x30),
        ("_unknown_constant_2", 4, 0x34),
        ("_keystore_type", 4, 0x7C),
    ] {
        header.setattr(name, buffer::nested(header.as_any(), size, offset)?)?;
    }
    header.setattr(
        "certifying_id",
        buffer::key_id(header.as_any(), 0x10, 0x38)?,
    )?;
    obj.setattr("header", &header)?;

    let body_size: i64 = header.getattr("body_size")?.extract()?;
    let compressed = obj.getattr("compressed")?.is_truthy()?;
    let key_store = if compressed {
        // `key_store_file.py:39-40`: a store over the decoded body.
        let decoded = HeaderFile::decode(obj)?.0;
        let size: i64 = obj.getattr("size_uncompressed")?.extract()?;
        let mut root = NestedBuffer::root(crate::image::Image::new(decoded));
        root.size = size;
        Bound::new(py, PyClassInitializer::from(root).add_subclass(KeyStore))?
    } else {
        let base = NestedBuffer::child(obj, body_size, 0x100, false, false)?;
        Bound::new(py, PyClassInitializer::from(base).add_subclass(KeyStore))?
    };
    init_key_store_keys(&key_store)?;
    obj.setattr("key_store", &key_store)?;

    let signature_size: i64 = header.getattr("signature_size")?.extract()?;
    let signature_base = NestedBuffer::child(obj, signature_size, 0x100 + body_size, false, false)?;
    let signature = Bound::new(
        py,
        PyClassInitializer::from(signature_base).add_subclass(buffer::Signature),
    )?;
    obj.setattr("signature", signature)?;
    Ok(())
}

/// `KeyStore.__init__` (`key_store_file.py:144-172`): header views and the
/// key list. A malformed key size ends the list (upstream asserts).
fn init_key_store_keys(store: &Bound<'_, KeyStore>) -> PyResult<()> {
    let py = store.py();
    let size = view(store.as_any())?.size;
    let header = buffer::nested(store.as_any(), KDB_HEADER_LEN, 0)?;
    store.setattr("_size", buffer::nested(header.as_any(), 4, 0)?)?;
    store.setattr("_unknown_flag", buffer::nested(header.as_any(), 4, 4)?)?;
    store.setattr("magic", buffer::nested(header.as_any(), 4, 8)?)?;
    store.setattr("header", &header)?;
    let body_size = (size - KDB_HEADER_LEN).max(0);
    let body = buffer::nested(store.as_any(), body_size, KDB_HEADER_LEN)?;
    store.setattr("body", &body)?;
    let keys = PyList::empty(py);
    let mut next = 0i64;
    while next < body_size {
        let raw = view(body.as_any())?.read(py, next, 4)?;
        let key_size = i64::from(u32::from_le_bytes(word(&raw)));
        if key_size <= KDB_HEADER_LEN || next + key_size > body_size {
            break;
        }
        let key_base = NestedBuffer::child(body.as_any(), key_size, next, false, false)?;
        let key = Bound::new(
            py,
            PyClassInitializer::from(key_base).add_subclass(KeyStoreKey),
        )?;
        let key_header = buffer::nested(body.as_any(), KDB_HEADER_LEN, next)?;
        key.setattr("pubkey_entity", py.None())?;
        key.setattr("header", &key_header)?;
        key.setattr(
            "crypto_material",
            buffer::nested(
                body.as_any(),
                key_size - KDB_HEADER_LEN,
                next + KDB_HEADER_LEN,
            )?,
        )?;
        key.setattr("key_id", buffer::key_id(key_header.as_any(), 0x10, 0x10)?)?;
        keys.append(key)?;
        next += key_size;
    }
    store.setattr("keys", keys)?;
    Ok(())
}

/// A `PubkeyFile` with its `_parse` attributes (`pubkey_file.py:53-91`).
pub(crate) fn pubkey_file<'py>(a: &FileArgs<'_, 'py>) -> PyResult<Bound<'py, PyAny>> {
    let py = a.rom.py();
    let init = PyClassInitializer::from(base(a)?)
        .add_subclass(File)
        .add_subclass(PubkeyFile);
    let obj = Bound::new(py, init)?;
    init_file(obj.as_any(), a)?;
    obj.setattr("signed_entity", py.None())?;
    obj.setattr("pubkey_entity", py.None())?;
    obj.setattr("_version", buffer::nested(obj.as_any(), 4, 0)?)?;
    obj.setattr("_key_usage", buffer::nested(obj.as_any(), 4, 0x24)?)?;
    obj.setattr("key_id", buffer::key_id(obj.as_any(), 0x10, 0x4)?)?;
    obj.setattr("certifying_id", buffer::key_id(obj.as_any(), 0x10, 0x14)?)?;
    obj.setattr("_security_features", buffer::nested(obj.as_any(), 2, 0x2A)?)?;
    obj.setattr("_pubexp_bits", buffer::nested(obj.as_any(), 4, 0x38)?)?;
    obj.setattr("_modulus_bits", buffer::nested(obj.as_any(), 4, 0x3C)?)?;
    let (pe, m) = PubkeyFile::sizes(&obj)?;
    let material = buffer::nested(obj.as_any(), pe + m, PUBKEY_HEADER_LEN as i64)?;
    obj.setattr("_pubexp", buffer::nested(material.as_any(), pe, 0)?)?;
    obj.setattr("_modulus", buffer::nested(material.as_any(), m, pe)?)?;
    obj.setattr("crypto_material", material)?;
    obj.setattr("has_sha256_checksum", false)?;
    obj.setattr("has_sha384_checksum", false)?;
    let signature = PubkeyFile::signature_size(&obj)?;
    if signature != 0 {
        let base = NestedBuffer::child(
            obj.as_any(),
            signature,
            PUBKEY_HEADER_LEN as i64 + pe + m,
            true,
            false,
        )?;
        let sig = PyClassInitializer::from(base)
            .add_subclass(buffer::Signature)
            .add_subclass(buffer::ReversedSignature);
        obj.setattr("signature", Bound::new(py, sig)?)?;
    }
    Ok(obj.into_any())
}

/// A `MicrocodeFile` (`microcode_file.py:25-42`). `header` is the wrapping
/// `HeaderFile` object when its parse succeeded.
pub(crate) fn microcode_file<'py>(
    a: &FileArgs<'_, 'py>,
    header: Option<Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    let py = a.rom.py();
    let init = PyClassInitializer::from(base(a)?)
        .add_subclass(File)
        .add_subclass(BiosFile)
        .add_subclass(MicrocodeFile);
    let obj = Bound::new(py, init)?.into_any();
    init_file(&obj, a)?;
    let (date, patch_level) = match &header {
        Some(h) => {
            let body = HeaderFile::decode(h)?.0;
            obj.setattr("body", PyBytes::new(py, &body))?;
            leading_words(&body)
        }
        None => leading_words(&view(&obj)?.read(py, 0, 8).unwrap_or_default()),
    };
    obj.setattr("header", header.map_or_else(|| py.None(), |h| h.unbind()))?;
    obj.setattr("date", date)?;
    obj.setattr("patch_level", patch_level)?;
    // `microcode_file.py:39-42`: BCD date fields.
    let digit = |shift: u32| i64::from((date >> shift) & 0xF);
    obj.setattr(
        "year",
        digit(0) + digit(4) * 10 + digit(8) * 100 + digit(12) * 1000,
    )?;
    obj.setattr("month", digit(16) + digit(20) * 10)?;
    obj.setattr("day", digit(24) + digit(28) * 10)?;
    Ok(obj)
}

/// `struct.unpack('<I', b[0:4])`, `struct.unpack('<I', b[4:8])`; zero when
/// short (upstream raises `struct.error`).
fn leading_words(b: &[u8]) -> (u32, u32) {
    if b.len() < 8 {
        return (0, 0);
    }
    (
        u32::from_le_bytes(word(&b[0..4])),
        u32::from_le_bytes(word(&b[4..8])),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shannon_of_uniform_and_constant_data() {
        assert_eq!(shannon(&[]), 0.0);
        assert_eq!(shannon(&[7u8; 64]), 0.0);
        let all: Vec<u8> = (0..=255).collect();
        assert!((shannon(&all) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn readable_magic_rules() {
        assert_eq!(readable_magic(b"$PS1"), "$PS1");
        assert_eq!(readable_magic(b"\x05\x00\x00\x00"), "0x05");
        assert_eq!(readable_magic(b"AB\x00\x01"), "AB");
        assert_eq!(readable_magic(b"\xff\x00AB"), "");
    }
}
