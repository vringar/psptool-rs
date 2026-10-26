//! `NestedBuffer` and the small buffer classes built on it.
//!
//! Translation of `utils.NestedBuffer` (`utils.py:40-114`) and
//! `crypto.KeyId` / `Signature` / `ReversedSignature` (`crypto.py:367-409`).
//! A view is `(parent, buffer_offset, buffer_size)`; reads and writes are
//! resolved by walking the parent chain, applying each level's
//! `_offset_slice` (with its bounds assertions), down to the shared
//! [`Image`] root, where Python slice semantics apply. Every other class of
//! the module derives from [`NestedBuffer`].

use std::sync::Arc;

use pyo3::exceptions::{PyAssertionError, PyIndexError, PyTypeError, PyValueError};
use pyo3::gc::{PyTraverseError, PyVisit};
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PyInt, PyList, PySlice, PyType};

use crate::image::Image;

/// `utils.NestedBuffer`.
#[pyclass(subclass, dict, weakref, module = "psptool.utils")]
pub struct NestedBuffer {
    pub(crate) image: Arc<Image>,
    /// `None` for a root view (upstream: a `bytearray` parent).
    pub(crate) parent: Option<Py<PyAny>>,
    pub(crate) offset: i64,
    pub(crate) size: i64,
    /// `ReversedSignature` indexing (`crypto.py:386-409`).
    pub(crate) reversed: bool,
}

/// One level of a view chain.
#[derive(Clone, Copy)]
struct Level {
    offset: i64,
    size: i64,
    reversed: bool,
}

impl NestedBuffer {
    /// A root view over a fresh image.
    pub(crate) fn root(image: Arc<Image>) -> Self {
        let size = image.len() as i64;
        Self {
            image,
            parent: None,
            offset: 0,
            size,
            reversed: false,
        }
    }

    /// An empty view without a parent: the native state of a model object
    /// built by a Python subclass's own `__init__` instead of a parse (see
    /// [`detached`]).
    pub(crate) fn detached() -> Self {
        Self::root(Image::new(Vec::new()))
    }

    /// A child view of `parent` (`NestedBuffer.__init__`, `utils.py:41-49`).
    /// `checked` applies upstream's two constructor assertions.
    pub(crate) fn child(
        parent: &Bound<'_, PyAny>,
        size: i64,
        offset: i64,
        reversed: bool,
        checked: bool,
    ) -> PyResult<Self> {
        let base = parent.cast::<NestedBuffer>()?.borrow();
        if checked {
            if offset + size > base.size {
                return Err(PyAssertionError::new_err(
                    "Cannot create child buffer: overflows parent buffer's bounds!",
                ));
            }
            if size > offset + size {
                return Err(PyAssertionError::new_err(format!(
                    "sz=0x{size:x},off=0x{offset:x}"
                )));
            }
        }
        Ok(Self {
            image: Arc::clone(&base.image),
            parent: Some(parent.clone().unbind()),
            offset,
            size,
            reversed,
        })
    }

    /// Levels from `self` up to (and including) the root view.
    fn levels(&self, py: Python<'_>) -> PyResult<Vec<Level>> {
        let mut levels = vec![Level {
            offset: self.offset,
            size: self.size,
            reversed: self.reversed,
        }];
        let mut next = self.parent.as_ref().map(|p| p.clone_ref(py));
        while let Some(parent) = next {
            let bound = parent.bind(py);
            let nb = bound
                .cast::<NestedBuffer>()
                .map_err(|_| PyTypeError::new_err("parent buffer is not a NestedBuffer"))?
                .borrow();
            levels.push(Level {
                offset: nb.offset,
                size: nb.size,
                reversed: nb.reversed,
            });
            next = nb.parent.as_ref().map(|p| p.clone_ref(py));
        }
        Ok(levels)
    }

    /// The image range addressed by `self[start:stop:step]`: every level's
    /// `_offset_slice`, then Python slice semantics on the root `bytearray`.
    fn resolve(
        &self,
        py: Python<'_>,
        start: Option<i64>,
        stop: Option<i64>,
        step: Option<i64>,
    ) -> PyResult<RootSlice> {
        let (mut start, mut stop, mut step) = (start, stop, step);
        for level in self.levels(py)? {
            (start, stop, step) = offset_slice(level, start, stop, step)?;
        }
        // Every level yields concrete bounds, so `start`/`stop` are set here.
        let bound = |v: Option<i64>| v.unwrap_or(0) as isize;
        let slice = PySlice::new(py, bound(start), bound(stop), step.unwrap_or(1) as isize);
        let ind = slice.indices(self.image.len() as isize)?;
        Ok(RootSlice {
            start: ind.start,
            step: ind.step,
            len: ind.slicelength,
        })
    }

    /// Bytes of a resolved range.
    fn fetch(&self, r: RootSlice) -> PyResult<Vec<u8>> {
        let out = if r.step == 1 {
            let start = r.start.max(0) as usize;
            self.image.read(start, start + r.len)
        } else {
            self.image.gather(r.indices())
        };
        out.ok_or_else(|| PyIndexError::new_err("buffer range outside the image"))
    }

    /// Absolute image index addressed by `self[index]`.
    fn index(&self, py: Python<'_>, index: i64) -> PyResult<usize> {
        let mut i = index;
        for level in self.levels(py)? {
            if level.reversed {
                if i < 0 {
                    return Err(PyAssertionError::new_err(
                        "Negative index not supported for ReversedSignature",
                    ));
                }
                i = level.offset + level.size - i - 1;
            } else {
                i += level.offset;
            }
        }
        let len = self.image.len() as i64;
        let abs = if i < 0 { i + len } else { i };
        if !(0..len).contains(&abs) {
            return Err(PyIndexError::new_err("bytearray index out of range"));
        }
        Ok(abs as usize)
    }

    /// `bytes(self[offset:offset + size])` — `get_bytes` (`utils.py:105-107`).
    pub(crate) fn read(&self, py: Python<'_>, offset: i64, size: i64) -> PyResult<Vec<u8>> {
        let r = self.resolve(py, Some(offset), Some(offset + size), None)?;
        self.fetch(r)
    }

    /// All bytes of the view.
    pub(crate) fn read_all(&self, py: Python<'_>) -> PyResult<Vec<u8>> {
        self.read(py, 0, self.size)
    }

    /// `self[start:stop] = data` with the length preserved.
    pub(crate) fn write(
        &self,
        py: Python<'_>,
        start: Option<i64>,
        stop: Option<i64>,
        step: Option<i64>,
        data: &[u8],
    ) -> PyResult<()> {
        let r = self.resolve(py, start, stop, step)?;
        if r.len != data.len() {
            return Err(PyValueError::new_err(format!(
                "assignment of {} bytes to a {}-byte slice would resize the image \
                 (psptool-rs keeps the image length fixed)",
                data.len(),
                r.len
            )));
        }
        let ok = if r.step == 1 {
            self.image.write(r.start.max(0) as usize, data)
        } else {
            self.image.scatter(&r.indices().collect::<Vec<_>>(), data)
        };
        if ok {
            Ok(())
        } else {
            Err(PyIndexError::new_err("buffer range outside the image"))
        }
    }

    /// `set_bytes(address, size, value)` (`utils.py:109-111`).
    pub(crate) fn set(&self, py: Python<'_>, address: i64, value: &[u8]) -> PyResult<()> {
        self.write(
            py,
            Some(address),
            Some(address + value.len() as i64),
            None,
            value,
        )
    }

    /// `get_address()` without Python dispatch (sum of the offset chain).
    pub(crate) fn absolute(&self, py: Python<'_>) -> PyResult<i64> {
        Ok(self.levels(py)?.iter().map(|l| l.offset).sum())
    }
}

/// A normalised `slice.indices(len(root))` triple.
#[derive(Clone, Copy)]
struct RootSlice {
    start: isize,
    step: isize,
    len: usize,
}

impl RootSlice {
    fn indices(self) -> impl Iterator<Item = usize> {
        (0..self.len).map(move |i| (self.start + i as isize * self.step) as usize)
    }
}

/// One level of `_offset_slice` (`utils.py:74-94`), or the reversed variant
/// (`crypto.py:404-409`).
type SliceBounds = (Option<i64>, Option<i64>, Option<i64>);

fn offset_slice(
    level: Level,
    start: Option<i64>,
    stop: Option<i64>,
    step: Option<i64>,
) -> PyResult<SliceBounds> {
    let Level {
        offset,
        size,
        reversed,
    } = level;
    if reversed {
        // `(item.start or 0)` / `(item.stop or self.buffer_size)`.
        let s = start.filter(|&s| s != 0).unwrap_or(0);
        let e = stop.filter(|&e| e != 0).unwrap_or(size);
        return Ok((
            Some(offset + size - s - 1),
            Some(offset + size - e - 1),
            Some(-1),
        ));
    }
    let start = match start {
        None => offset,
        Some(s) => {
            if s > size {
                return Err(PyAssertionError::new_err("Slice offset out of bounds"));
            }
            if s < 0 {
                offset + py_mod(s, size)?
            } else {
                offset + s
            }
        }
    };
    let stop = match stop {
        None => offset + size,
        Some(e) => {
            if e > size {
                return Err(PyAssertionError::new_err(format!(
                    "old_slice.stop={e},self.buffer_size={size}"
                )));
            }
            if e < 0 {
                offset + py_mod(e, size)?
            } else {
                offset + e
            }
        }
    };
    Ok((Some(start), Some(stop), step))
}

/// Python's `a % b` (sign of the divisor).
fn py_mod(a: i64, b: i64) -> PyResult<i64> {
    if b == 0 {
        return Err(pyo3::exceptions::PyZeroDivisionError::new_err(
            "integer modulo by zero",
        ));
    }
    Ok(a.rem_euclid(b) + if b < 0 && a.rem_euclid(b) != 0 { b } else { 0 })
}

/// `bytes(value)` for anything bytes-like.
pub(crate) fn to_bytes(value: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(b) = value.cast::<PyBytes>() {
        return Ok(b.as_bytes().to_vec());
    }
    if let Ok(b) = value.cast::<PyByteArray>() {
        return Ok(b.to_vec());
    }
    let b = value.py().get_type::<PyBytes>().call1((value,))?;
    Ok(b.cast::<PyBytes>()?.as_bytes().to_vec())
}

/// Upper-case hex (`hexlify(...).upper()`).
pub(crate) fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

/// Lower-case hex (`hexlify(...)`).
pub(crate) fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[pymethods]
impl NestedBuffer {
    /// GC support. Upstream's object graph is cyclic by design: a view holds
    /// its `parent_buffer` while the parent holds the view in an attribute
    /// (`directory.header`, `rom.fet`, `directory.entries`, ...), so a parse
    /// is reclaimed by the cycle collector, as upstream's is. pyo3 visits and
    /// clears the instance `__dict__`; the Rust-held parent link is the one
    /// edge it cannot see.
    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        visit.call(&self.parent)
    }

    fn __clear__(&mut self) {
        self.parent = None;
    }

    #[new]
    #[pyo3(signature = (parent_buffer, buffer_size, buffer_offset = 0))]
    fn py_new(
        parent_buffer: &Bound<'_, PyAny>,
        buffer_size: i64,
        buffer_offset: i64,
    ) -> PyResult<Self> {
        if parent_buffer.is_instance_of::<NestedBuffer>() {
            return Self::child(parent_buffer, buffer_size, buffer_offset, false, true);
        }
        // A bytes-like parent: the view owns a copy (see DEVIATIONS.md).
        if size_exceeds(buffer_size, buffer_offset) {
            return Err(PyAssertionError::new_err(format!(
                "sz=0x{buffer_size:x},off=0x{buffer_offset:x}"
            )));
        }
        let mut root = Self::root(Image::new(to_bytes(parent_buffer)?));
        root.offset = buffer_offset;
        root.size = buffer_size;
        Ok(root)
    }

    #[getter]
    fn get_buffer_offset(&self) -> i64 {
        self.offset
    }

    #[setter]
    fn set_buffer_offset(&mut self, value: i64) {
        self.offset = value;
    }

    #[getter]
    fn get_buffer_size(&self) -> i64 {
        self.size
    }

    #[setter]
    fn set_buffer_size(&mut self, value: i64) {
        self.size = value;
    }

    /// The parent view, or a `bytearray` copy of the image for a root view.
    #[getter]
    fn parent_buffer(&self, py: Python<'_>) -> Py<PyAny> {
        match &self.parent {
            Some(p) => p.clone_ref(py),
            None => PyByteArray::new(py, &self.image.to_vec())
                .into_any()
                .unbind(),
        }
    }

    fn __len__(&self) -> PyResult<usize> {
        usize::try_from(self.size)
            .map_err(|_| PyValueError::new_err("__len__() should return >= 0"))
    }

    fn __getitem__(&self, py: Python<'_>, item: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        if let Ok(slice) = item.cast::<PySlice>() {
            let (start, stop, step) = slice_parts(slice)?;
            let bytes = self.fetch(self.resolve(py, start, stop, step)?)?;
            return Ok(PyByteArray::new(py, &bytes).into_any().unbind());
        }
        let index: i64 = item
            .cast::<PyInt>()
            .map_err(|_| PyAssertionError::new_err(""))?
            .extract()?;
        let abs = self.index(py, index)?;
        let byte = self
            .image
            .read(abs, abs + 1)
            .ok_or_else(|| PyIndexError::new_err("bytearray index out of range"))?;
        Ok(byte[0].into_pyobject(py)?.into_any().unbind())
    }

    fn __setitem__(
        &self,
        py: Python<'_>,
        key: &Bound<'_, PyAny>,
        value: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        if let Ok(slice) = key.cast::<PySlice>() {
            let (start, stop, step) = slice_parts(slice)?;
            return self.write(py, start, stop, step, &to_bytes(value)?);
        }
        let index: i64 = key
            .cast::<PyInt>()
            .map_err(|_| PyAssertionError::new_err(""))?
            .extract()?;
        let byte: i64 = value.extract()?;
        let byte = u8::try_from(byte)
            .map_err(|_| PyValueError::new_err("byte must be in range(0, 256)"))?;
        let abs = self.index(py, index)?;
        if self.image.write(abs, &[byte]) {
            Ok(())
        } else {
            Err(PyIndexError::new_err("bytearray index out of range"))
        }
    }

    fn __repr__(slf: &Bound<'_, Self>) -> PyResult<String> {
        let py = slf.py();
        let name = slf.get_type().name()?;
        let address: i64 = slf.call_method0("get_address")?.extract()?;
        let this = slf.borrow();
        let parent_address: i64 = match &this.parent {
            Some(p) => p.bind(py).call_method0("get_address")?.extract()?,
            None => 0,
        };
        Ok(format!(
            "{name}(address={}, buffer_size={}, buffer_offset={}, self.parent_buffer=0x{parent_address:x})",
            py_hex(address),
            py_hex(this.size),
            py_hex(this.offset),
        ))
    }

    /// `get_address()` (`utils.py:96-100`): dispatches to the parent's
    /// (possibly overridden) `get_address`.
    fn get_address(&self, py: Python<'_>) -> PyResult<i64> {
        match &self.parent {
            Some(p) => Ok(self.offset + p.bind(py).call_method0("get_address")?.extract::<i64>()?),
            None => Ok(self.offset),
        }
    }

    fn get_buffer(&self, py: Python<'_>) -> Py<PyAny> {
        self.parent_buffer(py)
    }

    #[pyo3(signature = (offset = 0, size = None))]
    fn get_bytes<'py>(
        &self,
        py: Python<'py>,
        offset: i64,
        size: Option<i64>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.read(py, offset, size.unwrap_or(self.size))?;
        Ok(PyBytes::new(py, &bytes))
    }

    fn set_bytes(
        &self,
        py: Python<'_>,
        address: i64,
        size: i64,
        value: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let value = to_bytes(value)?;
        if value.len() as i64 != size {
            return Err(PyAssertionError::new_err(
                "set_bytes: value length does not match size argument",
            ));
        }
        self.set(py, address, &value)
    }

    /// `get_chunks` (`utils.py:113-114`); a list rather than a generator.
    #[pyo3(signature = (size, offset = 0))]
    fn get_chunks<'py>(
        &self,
        py: Python<'py>,
        size: usize,
        offset: i64,
    ) -> PyResult<Bound<'py, PyList>> {
        if size == 0 {
            return Err(PyValueError::new_err("chunk size must be positive"));
        }
        let bytes = self.fetch(self.resolve(py, Some(offset), None, None)?)?;
        PyList::new(py, bytes.chunks(size).map(|c| PyByteArray::new(py, c)))
    }
}

fn size_exceeds(size: i64, offset: i64) -> bool {
    size > offset + size
}

/// `hex()` of an `int`.
pub(crate) fn py_hex(v: i64) -> String {
    py_hex_wide(v.into())
}

/// `hex()` of an `int` wide enough for any unsigned 64-bit value.
pub(crate) fn py_hex_wide(v: i128) -> String {
    if v < 0 {
        format!("-0x{:x}", v.unsigned_abs())
    } else {
        format!("0x{v:x}")
    }
}

fn slice_parts(slice: &Bound<'_, PySlice>) -> PyResult<SliceBounds> {
    let part = |name: &str| -> PyResult<Option<i64>> {
        let v = slice.getattr(name)?;
        if v.is_none() {
            Ok(None)
        } else {
            Ok(Some(v.extract()?))
        }
    };
    Ok((part("start")?, part("stop")?, part("step")?))
}

/// `crypto.KeyId` (`crypto.py:367-377`).
#[pyclass(extends = NestedBuffer, module = "psptool.crypto")]
pub struct KeyId;

#[pymethods]
impl KeyId {
    #[new]
    #[pyo3(signature = (parent_buffer, buffer_size, buffer_offset = 0))]
    fn py_new(
        parent_buffer: &Bound<'_, PyAny>,
        buffer_size: i64,
        buffer_offset: i64,
    ) -> PyResult<PyClassInitializer<Self>> {
        let base = NestedBuffer::child(parent_buffer, buffer_size, buffer_offset, false, true)?;
        Ok(PyClassInitializer::from(base).add_subclass(Self))
    }

    /// `hexlify(self.get_bytes(0, 2)).upper()`.
    #[getter]
    fn magic(slf: PyRef<'_, Self>) -> PyResult<String> {
        Ok(hex_upper(&slf.as_super().read(slf.py(), 0, 2)?))
    }

    fn as_string(slf: PyRef<'_, Self>) -> PyResult<String> {
        Ok(hex_upper(&slf.as_super().read_all(slf.py())?))
    }

    fn __repr__(slf: PyRef<'_, Self>) -> PyResult<String> {
        Ok(format!(
            "KeyId({})",
            hex_upper(&slf.as_super().read_all(slf.py())?)
        ))
    }
}

/// `crypto.Signature` (`crypto.py:380-383`).
#[pyclass(extends = NestedBuffer, subclass, module = "psptool.crypto")]
pub struct Signature;

#[pymethods]
impl Signature {
    #[new]
    #[pyo3(signature = (parent_buffer, buffer_size, buffer_offset = 0))]
    fn py_new(
        parent_buffer: &Bound<'_, PyAny>,
        buffer_size: i64,
        buffer_offset: i64,
    ) -> PyResult<PyClassInitializer<Self>> {
        let base = NestedBuffer::child(parent_buffer, buffer_size, buffer_offset, false, true)?;
        Ok(PyClassInitializer::from(base).add_subclass(Self))
    }

    /// `Signature.from_nested_buffer(nb)`: the same window, as a `Signature`.
    #[classmethod]
    fn from_nested_buffer<'py>(
        _cls: &Bound<'py, PyType>,
        nb: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, Signature>> {
        signature(nb, false)
    }
}

/// `crypto.ReversedSignature` (`crypto.py:386-409`): byte order reversed.
#[pyclass(extends = Signature, module = "psptool.crypto")]
pub struct ReversedSignature;

#[pymethods]
impl ReversedSignature {
    #[new]
    #[pyo3(signature = (parent_buffer, buffer_size, buffer_offset = 0))]
    fn py_new(
        parent_buffer: &Bound<'_, PyAny>,
        buffer_size: i64,
        buffer_offset: i64,
    ) -> PyResult<PyClassInitializer<Self>> {
        let base = NestedBuffer::child(parent_buffer, buffer_size, buffer_offset, true, true)?;
        Ok(PyClassInitializer::from(base)
            .add_subclass(Signature)
            .add_subclass(Self))
    }
}

/// A `Signature` (or `ReversedSignature`) over the same window as `nb`.
pub(crate) fn signature<'py>(
    nb: &Bound<'py, PyAny>,
    reversed: bool,
) -> PyResult<Bound<'py, Signature>> {
    let py = nb.py();
    let (parent, size, offset) = {
        let view = nb.cast::<NestedBuffer>()?.borrow();
        let parent = view
            .parent
            .as_ref()
            .ok_or_else(|| PyTypeError::new_err("a signature needs a parent buffer"))?
            .clone_ref(py);
        (parent, view.size, view.offset)
    };
    let base = NestedBuffer::child(parent.bind(py), size, offset, reversed, false)?;
    if reversed {
        let init = PyClassInitializer::from(base)
            .add_subclass(Signature)
            .add_subclass(ReversedSignature);
        Ok(Bound::new(py, init)?.into_super())
    } else {
        Bound::new(py, PyClassInitializer::from(base).add_subclass(Signature))
    }
}

/// The base of `cls.__new__(cls, *args, **kwargs)` for a parsed model class
/// `T` (`File`, `HeaderFile`, `Directory`, ...).
///
/// Upstream's classes are plain Python classes, so downstream test suites
/// subclass them with an `__init__` of their own that never calls the
/// parent's and only assigns the attributes it needs (PSP-DB's
/// `FakeHeaderFile(HeaderFile)`). The native `__new__` therefore accepts and
/// ignores any arguments and gives a Python subclass a [`NestedBuffer::detached`]
/// base; attributes the subclass assigns land in the instance `__dict__`.
/// `T` itself still only comes from a parse: its objects need the image
/// window and directory record a parse attaches.
pub(crate) fn detached<T: pyo3::PyTypeInfo>(
    cls: &Bound<'_, PyType>,
) -> PyResult<PyClassInitializer<NestedBuffer>> {
    let native = T::type_object(cls.py());
    if cls.is(&native) {
        return Err(PyTypeError::new_err(format!(
            "{} objects come from parsing an image (PSPTool(...)); only a Python \
             subclass can be instantiated directly",
            native.name()?
        )));
    }
    Ok(PyClassInitializer::from(NestedBuffer::detached()))
}

/// A plain `NestedBuffer` child of `parent`.
pub(crate) fn nested<'py>(
    parent: &Bound<'py, PyAny>,
    size: i64,
    offset: i64,
) -> PyResult<Bound<'py, NestedBuffer>> {
    Bound::new(
        parent.py(),
        NestedBuffer::child(parent, size, offset, false, false)?,
    )
}

/// A `KeyId` child of `parent`.
pub(crate) fn key_id<'py>(
    parent: &Bound<'py, PyAny>,
    size: i64,
    offset: i64,
) -> PyResult<Bound<'py, KeyId>> {
    let base = NestedBuffer::child(parent, size, offset, false, false)?;
    Bound::new(
        parent.py(),
        PyClassInitializer::from(base).add_subclass(KeyId),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_modulo_matches_python() {
        assert_eq!(py_mod(-1, 16).ok(), Some(15));
        assert_eq!(py_mod(17, 16).ok(), Some(1));
        assert_eq!(py_mod(-17, 16).ok(), Some(15));
    }

    #[test]
    fn reversed_offset_slice_maps_to_descending_range() {
        // `crypto.py:404-409`: [0:4] of a 4-byte reversed view at 8 walks
        // 11, 10, 9, 8.
        let level = Level {
            offset: 8,
            size: 4,
            reversed: true,
        };
        let r = offset_slice(level, Some(0), Some(4), None).ok();
        assert_eq!(r, Some((Some(11), Some(7), Some(-1))));
    }
}
