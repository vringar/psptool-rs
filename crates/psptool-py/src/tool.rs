//! `PSPTool` (`psptool.py:33-64`), `Blob` (`blob.py:29-185`), `Rom`
//! (`rom.py:7-56`) and `Fet` (`fet.py:26-42`), plus the materialisation of the
//! [`model`] graph as Python objects.
//!
//! The constructor builds the whole graph eagerly, like upstream: every ROM,
//! directory, directory entry and file object exists (with its instance
//! attributes) when `PSPTool(...)` returns, a file shared by several
//! directories is one object, and `psp.cert_tree` is built last
//! (`psptool.py:50-51`).

use std::sync::Arc;

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PySet, PyTuple, PyType};

use psptool_core::{SourceBytes, fet::assumed_rom_size};

use crate::buffer::{self, NestedBuffer, to_bytes};
use crate::cert_tree::CertificateTree;
use crate::directory::{BiosDirectory, BiosDirectoryEntry, Directory, DirectoryEntry};
use crate::file::{self, FileArgs};
use crate::image::Image;
use crate::listing;
use crate::memory;
use crate::model::{self, FileKind, Model};

/// `Blob` (`blob.py:29-185`): the root view over the whole input.
#[pyclass(extends = NestedBuffer, subclass, module = "psptool.blob")]
pub struct Blob;

#[pymethods]
impl Blob {
    /// A detached instance of a Python subclass ([`buffer::detached`]).
    #[new]
    #[classmethod]
    #[pyo3(signature = (*_args, **_kwargs))]
    fn py_new(
        cls: &Bound<'_, PyType>,
        _args: &Bound<'_, PyTuple>,
        _kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<PyClassInitializer<Self>> {
        Ok(buffer::detached::<Self>(cls)?.add_subclass(Self))
    }

    fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
        Ok(format!("Blob(self.roms={})", slf.getattr("roms")?.repr()?))
    }

    /// `unique_files` (`blob.py:115-122`): every directory's files, as a set.
    fn unique_files<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PySet>> {
        let out = PySet::empty(slf.py())?;
        for rom in slf.getattr("roms")?.try_iter()? {
            for directory in rom?.getattr("directories")?.try_iter()? {
                for file in directory?.getattr("files")?.try_iter()? {
                    out.add(file?)?;
                }
            }
        }
        Ok(out)
    }

    /// `get_files_by_type` (`blob.py:183-185`).
    fn get_files_by_type<'py>(slf: &Bound<'py, Self>, type_: i64) -> PyResult<Bound<'py, PyList>> {
        let out = PyList::empty(slf.py());
        for file in Self::unique_files(slf)?.iter() {
            if file.getattr("type")?.extract::<i64>()? == type_ {
                out.append(file)?;
            }
        }
        Ok(out)
    }
}

/// `Rom` (`rom.py:7-56`).
#[pyclass(extends = NestedBuffer, subclass, module = "psptool.rom")]
pub struct Rom;

#[pymethods]
impl Rom {
    #[new]
    #[classmethod]
    #[pyo3(signature = (*_args, **_kwargs))]
    fn py_new(
        cls: &Bound<'_, PyType>,
        _args: &Bound<'_, PyTuple>,
        _kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<PyClassInitializer<Self>> {
        Ok(buffer::detached::<Self>(cls)?.add_subclass(Self))
    }

    fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
        Ok(format!(
            "Rom(self.agesa_version={})",
            slf.getattr("agesa_version")?.repr()?
        ))
    }
}

/// `Fet` (`fet.py:26-42`).
#[pyclass(extends = NestedBuffer, subclass, module = "psptool.fet")]
pub struct Fet;

#[pymethods]
impl Fet {
    #[new]
    #[classmethod]
    #[pyo3(signature = (*_args, **_kwargs))]
    fn py_new(
        cls: &Bound<'_, PyType>,
        _args: &Bound<'_, PyTuple>,
        _kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<PyClassInitializer<Self>> {
        Ok(buffer::detached::<Self>(cls)?.add_subclass(Self))
    }

    fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
        Ok(format!(
            "Fet(len(directories)={})",
            slf.getattr("directories")?.len()?
        ))
    }
}

/// `PSPTool` (`psptool.py:33-290`).
#[pyclass(dict, weakref, subclass, module = "psptool.psptool")]
pub struct PSPTool {
    pub(crate) image: Arc<Image>,
}

#[pymethods]
impl PSPTool {
    /// `PSPTool(rom_bytes, verbose=False, filename=None)`
    /// (`psptool.py:43-51`). `rom_bytes` is any bytes-like object; the image
    /// is a copy of it.
    #[new]
    #[pyo3(signature = (rom_bytes, verbose = false, filename = None))]
    fn py_new<'py>(
        rom_bytes: &Bound<'py, PyAny>,
        verbose: bool,
        filename: Option<Py<PyAny>>,
    ) -> PyResult<Bound<'py, Self>> {
        let _ = verbose;
        let py = rom_bytes.py();
        let bytes = to_bytes(rom_bytes)?;
        memory::relieve_pressure(py, bytes.len())?;
        let image = Image::new(bytes);
        let obj = Bound::new(
            py,
            PSPTool {
                image: Arc::clone(&image),
            },
        )?;
        obj.setattr("filename", filename)?;
        build(&obj, &image)?;
        Ok(obj)
    }

    /// `PSPTool.from_file(filename, verbose=False)` (`psptool.py:34-41`).
    #[classmethod]
    #[pyo3(signature = (filename, verbose = false))]
    fn from_file<'py>(
        cls: &Bound<'py, PyType>,
        filename: &Bound<'py, PyAny>,
        verbose: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let py = cls.py();
        let data = py
            .import("builtins")?
            .call_method1("open", (filename, "rb"))?
            .call_method0("__enter__")?;
        let bytes = data.call_method0("read");
        data.call_method1("__exit__", (py.None(), py.None(), py.None()))?;
        let kwargs = PyDict::new(py);
        kwargs.set_item("verbose", verbose)?;
        kwargs.set_item("filename", filename)?;
        cls.call((bytes?,), Some(&kwargs))
    }

    fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
        let filename = slf.getattr("filename")?;
        if !filename.is_none() {
            return Ok(format!("PSPTool(filename={})", filename.str()?));
        }
        // Upstream's repr lacks the closing parenthesis (`psptool.py:57`).
        Ok(format!(
            "PSPTool(len(rom_bytes)={}",
            slf.borrow().image.len()
        ))
    }

    /// `to_file` (`psptool.py:59-61`): the (possibly edited) image.
    fn to_file(slf: &Bound<'_, Self>, filename: &Bound<'_, PyAny>) -> PyResult<()> {
        let py = slf.py();
        let bytes = PyBytes::new(py, &slf.borrow().image.to_vec());
        let f = py
            .import("builtins")?
            .call_method1("open", (filename, "wb"))?;
        let written = f.call_method1("write", (bytes,));
        f.call_method0("close")?;
        written.map(|_| ())
    }

    /// `to_stdout` (`psptool.py:63-64`).
    fn to_stdout(slf: &Bound<'_, Self>) -> PyResult<()> {
        let py = slf.py();
        let bytes = PyBytes::new(py, &slf.borrow().image.to_vec());
        py.import("sys")?
            .getattr("stdout")?
            .getattr("buffer")?
            .call_method1("write", (bytes,))?;
        Ok(())
    }

    #[pyo3(signature = (verbose = false))]
    fn ls(slf: &Bound<'_, Self>, verbose: bool) -> PyResult<()> {
        listing::ls(slf.as_any(), verbose)
    }

    #[pyo3(signature = (fet, directory_index, verbose = false))]
    fn ls_dir(
        slf: &Bound<'_, Self>,
        fet: &Bound<'_, PyAny>,
        directory_index: usize,
        verbose: bool,
    ) -> PyResult<()> {
        let files = fet
            .getattr("directories")?
            .get_item(directory_index)?
            .getattr("files")?;
        listing::ls_files(slf.as_any(), Some(&files), verbose)
    }

    #[pyo3(signature = (files = None, verbose = false))]
    fn ls_files(
        slf: &Bound<'_, Self>,
        files: Option<&Bound<'_, PyAny>>,
        verbose: bool,
    ) -> PyResult<()> {
        listing::ls_files(slf.as_any(), files, verbose)
    }

    #[pyo3(signature = (verbose = false))]
    fn ls_json(slf: &Bound<'_, Self>, verbose: bool) -> PyResult<()> {
        listing::ls_json(slf.as_any(), verbose)
    }

    #[pyo3(signature = (fet, directory_index, verbose = false))]
    fn ls_dir_dict<'py>(
        slf: &Bound<'py, Self>,
        fet: &Bound<'py, PyAny>,
        directory_index: usize,
        verbose: bool,
    ) -> PyResult<Bound<'py, PyList>> {
        let _ = verbose;
        let files = fet
            .getattr("directories")?
            .get_item(directory_index)?
            .getattr("files")?;
        listing::ls_files_dict(slf.as_any(), Some(&files))
    }

    #[pyo3(signature = (files = None))]
    fn ls_files_dict<'py>(
        slf: &Bound<'py, Self>,
        files: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyList>> {
        listing::ls_files_dict(slf.as_any(), files)
    }
}

/// Materialise the [`Model`] of `image` under `psptool`.
fn build(psptool: &Bound<'_, PSPTool>, image: &Arc<Image>) -> PyResult<()> {
    let py = psptool.py();
    // `blob.py:53-54`: `max()` over the empty candidate list raises before
    // any FET is looked at.
    if assumed_rom_size(image.len() as u64).is_none() {
        return Err(PyValueError::new_err("max() iterable argument is empty"));
    }
    let source = SourceBytes::from_blob(image.to_vec());
    let m = model::build(&source);

    let blob = Bound::new(
        py,
        PyClassInitializer::from(NestedBuffer::root(Arc::clone(image))).add_subclass(Blob),
    )?;
    blob.setattr("psptool", psptool)?;

    let roms = build_roms(psptool.as_any(), blob.as_any(), &m)?;
    let (dirs, entries) = build_directories(psptool.as_any(), &roms, &m)?;
    let files = build_files(psptool.as_any(), &roms, &dirs, &entries, &m)?;

    for (node, dir) in m.dirs.iter().zip(&dirs) {
        let list = PyList::new(py, node.files.iter().map(|&f| &files[f]))?;
        dir.setattr("files", list)?;
    }
    for (node, rom) in m.roms.iter().zip(&roms) {
        let list = rom.getattr("directories")?;
        for &d in &node.directories {
            list.call_method1("append", (&dirs[d],))?;
        }
    }
    blob.setattr("roms", PyList::new(py, &roms)?)?;

    let by_offset = PyDict::new(py);
    for &(offset, d) in &m.directories_by_offset {
        by_offset.set_item(offset, &dirs[d])?;
    }
    psptool.setattr("directories_by_offset", by_offset)?;
    let by_offset = PyDict::new(py);
    for &(offset, f) in &m.files_by_offset {
        by_offset.set_item(offset, &files[f])?;
    }
    psptool.setattr("files_by_offset", by_offset)?;
    psptool.setattr("blob", &blob)?;
    let tree = CertificateTree::from_blob_impl(blob.as_any(), psptool.as_any())?;
    psptool.setattr("cert_tree", tree)?;
    Ok(())
}

/// `Rom` + `Fet` objects (`blob.py:72-76`, `rom.py:8-22`).
fn build_roms<'py>(
    psptool: &Bound<'py, PyAny>,
    blob: &Bound<'py, PyAny>,
    m: &Model,
) -> PyResult<Vec<Bound<'py, PyAny>>> {
    let py = blob.py();
    let mut out = Vec::with_capacity(m.roms.len());
    for node in &m.roms {
        let base = NestedBuffer::child(blob, node.size as i64, node.offset as i64, false, false)?;
        let rom = Bound::new(py, PyClassInitializer::from(base).add_subclass(Rom))?.into_any();
        rom.setattr("addr_mask", node.size - 1)?;
        rom.setattr("unique_entries", PySet::empty(py)?)?;
        rom.setattr("pubkeys", PyDict::new(py))?;
        // `rom.py:43-52`: two distinct strings mark a dual ROM; none or more
        // than two read as unknown. Python iterates a `set` there, so the
        // pair's order is hash-seed dependent; ours is first-seen.
        match node.agesa.as_slice() {
            [one] => rom.setattr("agesa_version", one)?,
            [first, second] => {
                rom.setattr("dual_rom", true)?;
                rom.setattr("agesa_version_second", second)?;
                rom.setattr("agesa_version", first)?;
            }
            _ => rom.setattr("agesa_version", "AGESA_UNKNOWN")?,
        }
        let fet_base = NestedBuffer::child(
            &rom,
            node.fet_size as i64,
            node.fet_offset as i64,
            false,
            false,
        )?;
        let fet = Bound::new(py, PyClassInitializer::from(fet_base).add_subclass(Fet))?;
        let directories = PyList::empty(py);
        fet.setattr("rom", &rom)?;
        fet.setattr("psptool", psptool)?;
        fet.setattr("directories", &directories)?;
        rom.setattr("fet", fet)?;
        rom.setattr("directories", directories)?;
        out.push(rom);
    }
    Ok(out)
}

type DirObjects<'py> = (Vec<Bound<'py, PyAny>>, Vec<Vec<Bound<'py, PyAny>>>);

/// `Directory` objects and their `DirectoryEntry` lists
/// (`directory.py:119-163`).
fn build_directories<'py>(
    psptool: &Bound<'py, PyAny>,
    roms: &[Bound<'py, PyAny>],
    m: &Model,
) -> PyResult<DirObjects<'py>> {
    let py = psptool.py();
    let mut dirs = Vec::with_capacity(m.dirs.len());
    let mut all_entries = Vec::with_capacity(m.dirs.len());
    for node in &m.dirs {
        let rom = &roms[node.rom];
        let entry_size = node.entry_size() as i64;
        let count = node.count as i64;
        let size = 0x10 + entry_size * count;
        let base = NestedBuffer::child(rom, size, node.offset as i64, false, false)?;
        let init = PyClassInitializer::from(base).add_subclass(Directory);
        let dir = if node.bios {
            Bound::new(py, init.add_subclass(BiosDirectory))?.into_any()
        } else {
            Bound::new(py, init)?.into_any()
        };
        let raw = file::view(&dir)?.read(py, 0, 0x10)?;
        dir.setattr("rom", rom)?;
        dir.setattr("psptool", psptool)?;
        dir.setattr("zen_generation", node.zen_generation.as_deref())?;
        dir.setattr("bios_directory_type", py.get_type::<BiosDirectory>())?;
        dir.setattr("_count", node.count)?;
        dir.setattr("magic", PyBytes::new(py, &raw[0..4]))?;
        dir.setattr("additional_info", PyBytes::new(py, &raw[12..16]))?;
        dir.setattr("header", buffer::nested(&dir, 0x10, 0)?)?;
        let body = buffer::nested(&dir, entry_size * count, 0x10)?;
        dir.setattr("checksum", buffer::nested(&dir, 4, 4)?)?;
        let mut entries = Vec::with_capacity(node.records.len());
        for index in 0..node.records.len() {
            let base = NestedBuffer::child(
                body.as_any(),
                entry_size,
                index as i64 * entry_size,
                false,
                false,
            )?;
            let init = PyClassInitializer::from(base).add_subclass(DirectoryEntry);
            let entry = if node.bios {
                Bound::new(py, init.add_subclass(BiosDirectoryEntry))?.into_any()
            } else {
                Bound::new(py, init)?.into_any()
            };
            entry.setattr("parent_directory", &dir)?;
            entry.setattr("entry_offset", index as i64 * entry_size)?;
            entries.push(entry);
        }
        dir.setattr("body", body)?;
        dir.setattr("entries", PyList::new(py, &entries)?)?;
        dir.setattr("files", PyList::empty(py))?;
        dir.setattr(
            "secondary_directory_offsets",
            PyList::new(py, &node.secondary)?,
        )?;
        dir.setattr(
            "tertiary_directory_offsets",
            PyList::new(py, &node.tertiary)?,
        )?;
        dirs.push(dir);
        all_entries.push(entries);
    }
    Ok((dirs, all_entries))
}

/// File objects (`file.py:249-329`), one per model file.
fn build_files<'py>(
    psptool: &Bound<'py, PyAny>,
    roms: &[Bound<'py, PyAny>],
    dirs: &[Bound<'py, PyAny>],
    entries: &[Vec<Bound<'py, PyAny>>],
    m: &Model,
) -> PyResult<Vec<Bound<'py, PyAny>>> {
    let py = psptool.py();
    let mut out = Vec::with_capacity(m.files.len());
    for node in &m.files {
        let args = FileArgs {
            psptool,
            rom: &roms[node.rom],
            directory: &dirs[node.dir],
            entry: &entries[node.dir][node.entry],
            record: &m.dirs[node.dir].records[node.entry],
            offset: node.offset as i64,
            size: node.size as i64,
        };
        let obj = match node.kind {
            FileKind::Plain => file::plain_file(&args, false)?,
            FileKind::Bios => file::plain_file(&args, true)?,
            FileKind::Header { signature_len } => {
                file::header_file(&args, signature_len as i64, false)?
            }
            FileKind::KeyStore { signature_len } => {
                file::header_file(&args, signature_len as i64, true)?
            }
            FileKind::Pubkey => file::pubkey_file(&args)?,
            FileKind::Microcode { header } => {
                let header = match header {
                    Some(sizing) => {
                        let wrapped = FileArgs {
                            size: sizing.buffer_size as i64,
                            ..args
                        };
                        Some(file::header_file(
                            &wrapped,
                            sizing.signature_len as i64,
                            false,
                        )?)
                    }
                    None => None,
                };
                file::microcode_file(&args, header)?
            }
        };
        let references = PyList::new(py, node.references.iter().map(|&d| &dirs[d]))?;
        obj.setattr("references", references)?;
        out.push(obj);
    }
    Ok(out)
}
