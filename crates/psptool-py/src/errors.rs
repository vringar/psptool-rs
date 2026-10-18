//! Exception classes of `psptool.errors` (`errors.py:20-71`) plus the two
//! parse errors upstream nests in classes (`File.ParseError`, `file.py:246`;
//! `UnknownPubkeyFileVersion`, `pubkey_file.py:23`).

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

create_exception!(psptool.errors, NoCertifyingKey, PyException);
create_exception!(psptool.errors, SignatureInvalid, PyException);
create_exception!(psptool.errors, SignatureInconsistent, SignatureInvalid);
create_exception!(psptool.errors, NonUniqueSignedEntity, PyException);
create_exception!(psptool.errors, NonUniquePublicKeyEntity, PyException);
create_exception!(psptool.file, ParseError, PyException);
create_exception!(psptool.pubkey_file, UnknownPubkeyFileVersion, PyException);

/// `NoCertifyingKey(signed_entity)` with the entity attached as
/// `.signed_entity` (`errors.py:20-26`).
pub fn no_certifying_key(signed_entity: &Bound<'_, PyAny>) -> PyResult<PyErr> {
    let py = signed_entity.py();
    let err = NoCertifyingKey::new_err(format!(
        "There is no key with the certifying id of {}, so it could not be verified!",
        signed_entity.repr()?
    ));
    err.value(py).setattr("signed_entity", signed_entity)?;
    Ok(err)
}

/// `NonUnique*(existing, new)` with both attached (`errors.py:46-71`).
pub fn non_unique<E: pyo3::PyTypeInfo>(
    existing: &Bound<'_, PyAny>,
    new: &Bound<'_, PyAny>,
) -> PyResult<PyErr> {
    let py = existing.py();
    let err = PyErr::from_type(
        E::type_object(py),
        format!(
            "duplicate entity (existing={}, new={})",
            existing.repr()?,
            new.repr()?
        ),
    );
    err.value(py).setattr("existing", existing)?;
    err.value(py).setattr("new", new)?;
    Ok(err)
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add("NoCertifyingKey", py.get_type::<NoCertifyingKey>())?;
    m.add("SignatureInvalid", py.get_type::<SignatureInvalid>())?;
    m.add(
        "SignatureInconsistent",
        py.get_type::<SignatureInconsistent>(),
    )?;
    m.add(
        "NonUniqueSignedEntity",
        py.get_type::<NonUniqueSignedEntity>(),
    )?;
    m.add(
        "NonUniquePublicKeyEntity",
        py.get_type::<NonUniquePublicKeyEntity>(),
    )?;
    m.add("ParseError", py.get_type::<ParseError>())?;
    m.add(
        "UnknownPubkeyFileVersion",
        py.get_type::<UnknownPubkeyFileVersion>(),
    )?;
    Ok(())
}
