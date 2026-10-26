//! `Directory` / `BiosDirectory` (`directory.py:26-257`) and
//! `DirectoryEntry` / `BiosDirectoryEntry` (`entry.py:26-180`).
//!
//! Entry fields are properties over the live 16/24-byte record, so a setter
//! rewrites the image exactly like upstream's `set_bytes`. The directory's
//! edit path (`update_entry_fields`, `update_checksum`, the `count` setter)
//! recomputes the Fletcher-32 header checksum with `psptool_core::fletcher32`.

use pyo3::exceptions::{PyAssertionError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple, PyType};

use psptool_core::{EntryType, fletcher32};

use crate::buffer::{self, NestedBuffer, py_hex, py_hex_wide, to_bytes};
use crate::file::{File, view};
use crate::model;

/// `Directory.HEADER_SIZE` (`directory.py:28`).
const HEADER_SIZE: i64 = 0x10;

fn le(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .rev()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
}

fn read_le(slf: &Bound<'_, PyAny>, offset: i64, len: i64) -> PyResult<u64> {
    Ok(le(&view(slf)?.read(slf.py(), offset, len)?))
}

fn write_le(slf: &Bound<'_, PyAny>, offset: i64, len: usize, value: u64) -> PyResult<()> {
    let bytes = value.to_le_bytes();
    view(slf)?.set(slf.py(), offset, &bytes[..len])
}

fn warn(py: Python<'_>, message: &str) -> PyResult<()> {
    py.import("sys")?
        .getattr("stderr")?
        .call_method1("write", (format!("Warning: {message}\n"),))?;
    Ok(())
}

/// `(info >> 24) & 3` for v1 headers, `(info >> 29) & 3` otherwise
/// (`directory.py:186-193`).
fn address_mode_of(additional_info: u32) -> u8 {
    psptool_core::AddressMode::from_additional_info(additional_info).bits()
}

fn additional_info(slf: &Bound<'_, PyAny>) -> PyResult<u32> {
    let info = to_bytes(&slf.getattr("additional_info")?)?;
    Ok(le(&info) as u32)
}

/// `Directory` (`directory.py:26-249`).
#[pyclass(extends = NestedBuffer, subclass, module = "psptool.directory")]
pub struct Directory;

#[pymethods]
impl Directory {
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

    #[classattr]
    const HEADER_SIZE: i64 = HEADER_SIZE;

    #[classattr]
    const ENTRY_SIZE: i64 = 0x10;

    #[classattr]
    #[pyo3(name = "DIRECTORY_MAGICS")]
    fn directory_magics(py: Python<'_>) -> PyResult<Py<PyList>> {
        Ok(PyList::new(py, [PyBytes::new(py, b"$PSP"), PyBytes::new(py, b"$PL2")])?.unbind())
    }

    #[classattr]
    #[pyo3(name = "ENTRY_CLASS")]
    fn entry_class(py: Python<'_>) -> Py<PyType> {
        py.get_type::<DirectoryEntry>().unbind()
    }

    #[classattr]
    #[pyo3(name = "FILE_CLASS")]
    fn file_class(py: Python<'_>) -> Py<PyType> {
        py.get_type::<File>().unbind()
    }

    fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
        let name = slf.get_type().name()?;
        let address: i64 = slf.call_method0("get_address")?.extract()?;
        let magic = slf.getattr("magic")?.repr()?;
        let count = slf.getattr("count")?;
        Ok(format!(
            "{name}(address={}, magic={magic}, count={count})",
            py_hex(address)
        ))
    }

    #[getter]
    fn count(slf: &Bound<'_, Self>) -> PyResult<Py<PyAny>> {
        Ok(slf.getattr("_count")?.unbind())
    }

    /// `count.setter` (`directory.py:174-180`): rewrite header `[8:12]` and
    /// the checksum.
    #[setter]
    fn set_count(slf: &Bound<'_, Self>, value: u32) -> PyResult<()> {
        slf.setattr("_count", value)?;
        let header = slf.getattr("header")?;
        write_le(&header, 8, 4, u64::from(value))?;
        slf.call_method0("update_checksum")?;
        Ok(())
    }

    #[getter]
    fn address_mode(slf: &Bound<'_, Self>) -> PyResult<u8> {
        Ok(address_mode_of(additional_info(slf.as_any())?))
    }

    /// `verify_checksum` (`directory.py:195-201`): warn on a mismatch.
    fn verify_checksum(slf: &Bound<'_, Self>) -> PyResult<()> {
        let py = slf.py();
        let stored = to_bytes(&slf.getattr("checksum")?.call_method0("get_bytes")?)?;
        if stored != directory_checksum(slf.as_any())?.to_le_bytes() {
            warn(
                py,
                &format!(
                    "Could not verify fletcher checksum for directory {}",
                    slf.repr()?
                ),
            )?;
        }
        Ok(())
    }

    /// `update_checksum` (`directory.py:203-205`).
    fn update_checksum(slf: &Bound<'_, Self>) -> PyResult<()> {
        let sum = directory_checksum(slf.as_any())?;
        let checksum = slf.getattr("checksum")?;
        view(&checksum)?.set(slf.py(), 0, &sum.to_le_bytes())
    }

    /// `update_entry_fields` (`directory.py:207-241`): point the first entry of
    /// `file.type` at `(offset, size)`, preserving its address mode, then
    /// re-checksum.
    fn update_entry_fields(
        slf: &Bound<'_, Self>,
        file: &Bound<'_, PyAny>,
        type_: u8,
        size: u32,
        offset: i64,
    ) -> PyResult<()> {
        let file_type: u8 = file.getattr("type")?.extract()?;
        let mut target = None;
        for entry in slf.getattr("entries")?.try_iter()? {
            let entry = entry?;
            if entry.getattr("type")?.extract::<u8>()? == file_type {
                target = Some(entry);
                break;
            }
        }
        let entry =
            target.ok_or_else(|| PyAssertionError::new_err("no entry of the file's type"))?;
        entry.setattr("type", type_)?;
        if !EntryType(type_).is_soft_fuse_chain() {
            entry.setattr("size", size)?;
        }
        let mut mode: u8 = slf.getattr("address_mode")?.extract()?;
        if mode >= 2 {
            mode = entry.getattr("address_mode")?.extract()?;
        }
        let old: i64 = entry.getattr("offset")?.extract()?;
        let new = match mode {
            0 => {
                // The exact inverse of `file_offset()` (`entry.py:56-60`): keep
                // the bits the read masked away. Upstream keeps the bits
                // outside `addr_mask` (`directory.py:228-232`), which drops
                // bit 24 of a `> 0xFF000000` pointer in a > 16 MiB ROM that the
                // read decoded through the 24-bit window (DEVIATIONS.md).
                let addr_mask: i64 = slf.getattr("rom")?.getattr("addr_mask")?.extract()?;
                let window = if old > 0xFF00_0000 && addr_mask + 1 > model::PAGE_SIZE as i64 {
                    0x00FF_FFFF
                } else {
                    addr_mask
                };
                (old & (0xFFFF_FFFF ^ window)) | (offset & window)
            }
            2 | 3 => offset - view(slf.as_any())?.offset,
            _ => offset,
        };
        let new = u32::try_from(new).map_err(|_| {
            PyValueError::new_err(format!("entry offset {new:#x} does not fit 32 bits"))
        })?;
        entry.setattr("offset", new)?;
        slf.call_method0("update_checksum")?;
        Ok(())
    }

    /// `update_zen_generation` (`directory.py:243-249`).
    fn update_zen_generation(
        slf: &Bound<'_, Self>,
        fet: &Bound<'_, PyAny>,
        zen_generation: Option<String>,
    ) -> PyResult<()> {
        let Some(generation) = zen_generation else {
            return Ok(());
        };
        let current: Option<String> = slf.getattr("zen_generation")?.extract()?;
        let merged = match current {
            Some(existing) if existing.contains(&generation) => return Ok(()),
            Some(existing) => format!("{existing}\n{generation}"),
            None => generation.clone(),
        };
        slf.setattr("zen_generation", merged)?;
        let by_offset = fet.getattr("psptool")?.getattr("directories_by_offset")?;
        for offset in slf.getattr("secondary_directory_offsets")?.try_iter()? {
            if let Ok(child) = by_offset.get_item(offset?) {
                child.call_method1("update_zen_generation", (fet, &generation))?;
            }
        }
        Ok(())
    }
}

/// Fletcher-32 of `self[0x8:]` (`directory.py:197-198,204`).
fn directory_checksum(slf: &Bound<'_, PyAny>) -> PyResult<u32> {
    let nb = view(slf)?;
    let data = nb.read(slf.py(), 8, nb.size - 8)?;
    fletcher32(&data).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// `BiosDirectory` (`directory.py:252-257`).
#[pyclass(extends = Directory, subclass, module = "psptool.directory")]
pub struct BiosDirectory;

#[pymethods]
impl BiosDirectory {
    #[new]
    #[classmethod]
    #[pyo3(signature = (*_args, **_kwargs))]
    fn py_new(
        cls: &Bound<'_, PyType>,
        _args: &Bound<'_, PyTuple>,
        _kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<PyClassInitializer<Self>> {
        Ok(buffer::detached::<Self>(cls)?
            .add_subclass(Directory)
            .add_subclass(Self))
    }

    #[classattr]
    const ENTRY_SIZE: i64 = 0x18;

    #[classattr]
    #[pyo3(name = "DIRECTORY_MAGICS")]
    fn directory_magics(py: Python<'_>) -> PyResult<Py<PyList>> {
        Ok(PyList::new(py, [PyBytes::new(py, b"$BHD"), PyBytes::new(py, b"$BL2")])?.unbind())
    }

    #[classattr]
    #[pyo3(name = "ENTRY_CLASS")]
    fn entry_class(py: Python<'_>) -> Py<PyType> {
        py.get_type::<BiosDirectoryEntry>().unbind()
    }

    #[classattr]
    #[pyo3(name = "FILE_CLASS")]
    fn file_class(py: Python<'_>) -> Py<PyType> {
        py.get_type::<crate::file::BiosFile>().unbind()
    }
}

/// `DirectoryEntry` (`entry.py:26-134`).
#[pyclass(extends = NestedBuffer, subclass, module = "psptool.entry")]
pub struct DirectoryEntry;

impl DirectoryEntry {
    fn repr_fields(slf: &Bound<'_, PyAny>) -> PyResult<String> {
        let name = slf.get_type().name()?;
        let field = |n: &str| -> PyResult<String> { Ok(py_hex(slf.getattr(n)?.extract()?)) };
        Ok(format!(
            "{name}(self.type={}, self.flags={}, self.size={}, self.offset={}, self.entry_offset={}, self.rsv0={})",
            field("type")?,
            field("flags")?,
            field("size")?,
            field("offset")?,
            field("entry_offset")?,
            field("rsv0")?,
        ))
    }
}

#[pymethods]
impl DirectoryEntry {
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

    #[classattr]
    const ENTRY_SIZE: i64 = 0x10;

    fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
        Self::repr_fields(slf.as_any())
    }

    /// `file_offset()` (`entry.py:38-70`) over the live record.
    fn file_offset(slf: &Bound<'_, Self>) -> PyResult<u64> {
        let directory = slf.getattr("parent_directory")?;
        let rom_size = directory
            .getattr("rom")?
            .getattr("addr_mask")?
            .extract::<u64>()?
            + 1;
        model::resolve_file_offset(
            EntryType(read_le(slf.as_any(), 0, 1)? as u8),
            additional_info(&directory)?,
            read_le(slf.as_any(), 12, 4)? as u32,
            read_le(slf.as_any(), 8, 4)? as u32,
            view(&directory)?.offset as u64,
            slf.getattr("entry_offset")?.extract()?,
            rom_size,
        )
        .ok_or_else(|| PyValueError::new_err(format!("unsupported ROM size {rom_size:#x}")))
    }

    /// `type` (`entry.py:72-78`); pyo3 strips the `get_`/`set_` prefixes.
    #[getter]
    fn get_type(slf: &Bound<'_, Self>) -> PyResult<u64> {
        read_le(slf.as_any(), 0, 1)
    }

    #[setter]
    fn set_type(slf: &Bound<'_, Self>, value: u8) -> PyResult<()> {
        write_le(slf.as_any(), 0, 1, u64::from(value))
    }

    #[getter]
    fn subprogram(slf: &Bound<'_, Self>) -> PyResult<u64> {
        read_le(slf.as_any(), 1, 1)
    }

    #[setter]
    fn set_subprogram(slf: &Bound<'_, Self>, value: u8) -> PyResult<()> {
        write_le(slf.as_any(), 1, 1, u64::from(value))
    }

    #[getter]
    fn flags(slf: &Bound<'_, Self>) -> PyResult<u64> {
        read_le(slf.as_any(), 2, 2)
    }

    #[setter]
    fn set_flags(slf: &Bound<'_, Self>, value: u16) -> PyResult<()> {
        write_le(slf.as_any(), 2, 2, u64::from(value))
    }

    /// `(flags >> 3) & 0xF` (`entry.py:96-98`).
    #[getter]
    fn instance(slf: &Bound<'_, Self>) -> PyResult<u64> {
        Ok((read_le(slf.as_any(), 2, 2)? >> 3) & 0xF)
    }

    /// Upstream ORs the field in without clearing it (`entry.py:100-102`).
    #[setter]
    fn set_instance(slf: &Bound<'_, Self>, value: u16) -> PyResult<()> {
        let flags = read_le(slf.as_any(), 2, 2)? | (u64::from(value & 0xF) << 3);
        write_le(slf.as_any(), 2, 2, flags)
    }

    #[getter]
    fn size(slf: &Bound<'_, Self>) -> PyResult<u64> {
        read_le(slf.as_any(), 4, 4)
    }

    #[setter]
    fn set_size(slf: &Bound<'_, Self>, value: u32) -> PyResult<()> {
        write_le(slf.as_any(), 4, 4, u64::from(value))
    }

    #[getter]
    fn offset(slf: &Bound<'_, Self>) -> PyResult<u64> {
        read_le(slf.as_any(), 8, 4)
    }

    #[setter]
    fn set_offset(slf: &Bound<'_, Self>, value: u32) -> PyResult<()> {
        write_le(slf.as_any(), 8, 4, u64::from(value))
    }

    #[getter]
    fn rsv0(slf: &Bound<'_, Self>) -> PyResult<u64> {
        read_le(slf.as_any(), 12, 4)
    }

    #[setter]
    fn set_rsv0(slf: &Bound<'_, Self>, value: u32) -> PyResult<()> {
        write_le(slf.as_any(), 12, 4, u64::from(value))
    }

    /// `(rsv0 >> 30) & 3` (`entry.py:132-134`).
    #[getter]
    fn address_mode(slf: &Bound<'_, Self>) -> PyResult<u64> {
        Ok((read_le(slf.as_any(), 12, 4)? >> 30) & 3)
    }
}

/// `BiosDirectoryEntry` (`entry.py:136-180`).
#[pyclass(extends = DirectoryEntry, subclass, module = "psptool.entry")]
pub struct BiosDirectoryEntry;

#[pymethods]
impl BiosDirectoryEntry {
    #[new]
    #[classmethod]
    #[pyo3(signature = (*_args, **_kwargs))]
    fn py_new(
        cls: &Bound<'_, PyType>,
        _args: &Bound<'_, PyTuple>,
        _kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<PyClassInitializer<Self>> {
        Ok(buffer::detached::<Self>(cls)?
            .add_subclass(DirectoryEntry)
            .add_subclass(Self))
    }

    #[classattr]
    const ENTRY_SIZE: i64 = 0x18;

    fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
        let base = DirectoryEntry::repr_fields(slf.as_any())?;
        let destination: i128 = slf.getattr("destination")?.extract()?;
        Ok(format!(
            "{}, self.destination={})",
            &base[..base.len() - 1],
            py_hex_wide(destination)
        ))
    }

    #[getter]
    fn destination(slf: &Bound<'_, Self>) -> PyResult<u64> {
        read_le(slf.as_any(), 16, 8)
    }

    #[setter]
    fn set_destination(slf: &Bound<'_, Self>, value: u64) -> PyResult<()> {
        write_le(slf.as_any(), 16, 8, value)
    }

    #[getter]
    fn region_type(slf: &Bound<'_, Self>) -> PyResult<u64> {
        read_le(slf.as_any(), 1, 1)
    }

    #[setter]
    fn set_region_type(slf: &Bound<'_, Self>, value: u8) -> PyResult<()> {
        write_le(slf.as_any(), 1, 1, u64::from(value))
    }

    /// `(flags >> 8) & 0x7` (`entry.py:166-168`).
    #[getter]
    fn subprogram(slf: &Bound<'_, Self>) -> PyResult<u64> {
        Ok((read_le(slf.as_any(), 2, 2)? >> 8) & 0x7)
    }

    #[setter]
    fn set_subprogram(slf: &Bound<'_, Self>, value: u16) -> PyResult<()> {
        let flags = read_le(slf.as_any(), 2, 2)? | (u64::from(value & 0x7) << 8);
        write_le(slf.as_any(), 2, 2, flags)
    }

    /// `(flags >> 4) & 0xF` (`entry.py:174-176`).
    #[getter]
    fn instance(slf: &Bound<'_, Self>) -> PyResult<u64> {
        Ok((read_le(slf.as_any(), 2, 2)? >> 4) & 0xF)
    }

    #[setter]
    fn set_instance(slf: &Bound<'_, Self>, value: u16) -> PyResult<()> {
        let flags = read_le(slf.as_any(), 2, 2)? | (u64::from(value & 0xF) << 4);
        write_le(slf.as_any(), 2, 2, flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn little_endian_fold() {
        assert_eq!(le(&[0x78, 0x56, 0x34, 0x12]), 0x1234_5678);
        assert_eq!(le(&[]), 0);
    }

    #[test]
    fn address_mode_bits_follow_header_version() {
        // `directory.py:186-193`: v1 → bits[25:24], v2 → bits[30:29].
        assert_eq!(address_mode_of((1 << 31) | (0b10 << 24)), 2);
        assert_eq!(address_mode_of(0b01 << 29), 1);
    }
}
