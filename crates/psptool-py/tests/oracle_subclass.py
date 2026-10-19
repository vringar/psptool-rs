"""Python subclasses of the model classes, built without a ROM.

Downstream suites fake PSPTool objects by subclassing them with an
``__init__`` of their own that never calls the parent's (PSP-DB
``tests/test_identity.py``: ``class FakeHeaderFile(HeaderFile)`` overriding
``get_decrypted_body``). Run under the reference interpreter twice by
``python_api.rs``: once importing upstream PSPTool, once with the psptool-rs
bindings first on ``PYTHONPATH``. Every line after the first (which names the
implementation) must be identical: the decode ladder
(``header_file.py:109-292``) has to see the subclass's attributes and
overrides exactly as upstream's pure-Python methods do, including which
attribute it trips over when one is missing.

Usage: python3 oracle_subclass.py
"""

import contextlib
import hashlib
import io
import json
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import psptool
from psptool import errors
from psptool.directory import BiosDirectory, Directory
from psptool.entry import BiosDirectoryEntry, DirectoryEntry
from psptool.file import BiosFile, File
from psptool.header_file import HeaderFile
from psptool.key_store_file import KeyStoreFile
from psptool.microcode_file import MicrocodeFile
from psptool.pubkey_file import PubkeyFile

PLAIN = b"PSP firmware body " * 64
COMPRESSED = zlib.compress(PLAIN)
# header_file.py:294-307: the Zen+ IKEK every decryption uses by default.
IKEK = File.UNWRAPPED_IKEK_ZEN_PLUS
ENTRY_KEY = bytes(range(0x40, 0x50))
IV = bytes(range(0x20, 0x30))


def sha(data):
    return hashlib.sha256(bytes(data)).hexdigest()


def jsonable(value):
    if isinstance(value, (bytes, bytearray)):
        return "sha:" + sha(value)
    if isinstance(value, (tuple, list)):
        return [jsonable(v) for v in value]
    return value


def attempt(fn):
    """The value, or the exception class name (both tools must agree)."""
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            return jsonable(fn())
    except Exception as exc:  # noqa: BLE001 - the class name is the datum
        return f"EXC:{type(exc).__name__}"


def aes(mode, key, data):
    encryptor = Cipher(algorithms.AES(key), mode).encryptor()
    return encryptor.update(data) + encryptor.finalize()


# utils.py:277-283 inverted: the stored key is ECB(ENTRY_KEY) under the IKEK.
WRAPPED_KEY = aes(modes.ECB(), IKEK, ENTRY_KEY)
CIPHERTEXT = aes(modes.CBC(IV), ENTRY_KEY, PLAIN)


class FakeBuffer:
    def __init__(self, data):
        self.data = data

    def get_bytes(self):
        return self.data


class SizedBuffer(FakeBuffer):
    def __len__(self):
        return len(self.data)

    def __getitem__(self, item):
        return self.data[item]

    def __setitem__(self, item, value):
        data = bytearray(self.data)
        data[item] = value
        self.data = bytes(data)


class FakeHeaderFile(HeaderFile):
    """PSP-DB's fake (vringar/PSP-DB tests/test_identity.py), verbatim."""

    def __init__(self, body, compressed=False, encrypted=False, zlib_size=0, decrypted=None, load_addr=0, type=0x1):
        self.body = FakeBuffer(body)
        self.compressed = compressed
        self.encrypted = encrypted
        self.zlib_size = zlib_size
        self.decrypted = body if decrypted is None else decrypted
        self.load_addr = load_addr
        self.type = type

    def get_decrypted_body(self):
        return self.decrypted


def compute_identity(file):
    """PSP-DB pspdb/identity.py (claude-main), which reads the fake's
    attributes and calls its overrides directly."""
    try:
        raw = file.body.get_bytes() if isinstance(file, HeaderFile) else file.get_bytes()
    except Exception:  # noqa: BLE001
        raw = None
    plain = None
    if isinstance(file, HeaderFile) and raw is not None:
        if not file.compressed:
            plain = None if file.encrypted else file.body.get_bytes()
        else:
            decompressor = zlib.decompressobj()
            try:
                out = decompressor.decompress(file.get_decrypted_body()[: file.zlib_size])
                plain = out if decompressor.eof else None
            except (zlib.error, ValueError):
                plain = None
    return {
        "raw": sha(raw) if raw is not None else None,
        "plain": sha(plain) if plain is not None else None,
        "load": file.load_addr,
        "type": file.type,
    }


class Entity:
    """A `signed_entity` stand-in: `is_verified()` returns or raises `outcome`."""

    def __init__(self, outcome):
        self.outcome = outcome

    def is_verified(self):
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


class LadderFile(FakeHeaderFile):
    """Sets every attribute `_verify_decode` reads (header_file.py:198-243)
    and overrides both checksum checks, as a fake for the ladder would."""

    def __init__(self, body, signed=None, size_signed=0, sha256=None, sha384=None, signed_word=0, **kwargs):
        super().__init__(body, **kwargs)
        self.signed_entity = signed
        self.size_signed = size_signed
        self.has_sha256_checksum = int(sha256 is not None)
        self.has_sha384_checksum = int(sha384 is not None) << 1
        self.sha256_ok, self.sha384_ok = sha256, sha384
        self._signed = FakeBuffer(signed_word.to_bytes(4, "little"))
        self.calls = []

    def verify_sha256(self, print_warning=True):
        self.calls.append(("verify_sha256", print_warning))
        return self.sha256_ok

    def verify_sha384(self, print_warning=True):
        self.calls.append(("verify_sha384", print_warning))
        return self.sha384_ok


class ChecksumFile(FakeHeaderFile):
    """Keeps the native `verify_sha256`: it must checksum this fake's
    `get_checksummed_bytes()` against its `_sha256_checksum`."""

    def __init__(self, body, stored, **kwargs):
        super().__init__(body, **kwargs)
        self.signed_entity = None
        self.has_sha256_checksum = 1
        self.has_sha384_checksum = 0
        self._sha256_checksum = FakeBuffer(stored)


class EncryptedFile(HeaderFile):
    """No overrides: `get_decrypted_body` must decrypt the attributes
    (header_file.py:286-292, utils.py:277-283)."""

    def __init__(self, key=WRAPPED_KEY, iv=IV):
        self.body = FakeBuffer(CIPHERTEXT)
        self.encrypted = True
        self.compressed = False
        self.key = key
        self.iv = iv
        self.signed_entity = None
        self.has_sha256_checksum = 0
        self.has_sha384_checksum = 0


class OwnLadder(LadderFile):
    def _verify_decode(self, print_warning=False):
        return True, "overridden"


class OwnDecode(LadderFile):
    def _decrypted_decompressed_body(self, print_warning=True):
        return b"decoded", False


class FakeEntry:
    def __init__(self, destination=0):
        self.destination = destination


class FakeFile(File):
    def __init__(self, type, entry):
        self.type = type
        self.entry = entry


class FakeBios(BiosFile):
    def __init__(self, destination):
        self.destination = destination


def ladder(f):
    return {
        "dv": attempt(f.decode_verification),
        "dvd": attempt(f.decode_verified),
        "dvm": attempt(f.decode_verification_method),
        "pio": attempt(f.plaintext_identity_ok),
        "ddb": attempt(f.get_decrypted_decompressed_body),
        "ddb_quiet": attempt(lambda: f._decrypted_decompressed_body(print_warning=False)),
        "calls": getattr(f, "calls", None),
    }


def cases():
    yield "isinstance", [isinstance(FakeHeaderFile(PLAIN), c) for c in (HeaderFile, File)]
    # PSP-DB tests/test_identity.py, through their compute_identity.
    yield "pspdb_plain", attempt(lambda: compute_identity(FakeHeaderFile(PLAIN)))
    yield "pspdb_compressed", attempt(
        lambda: compute_identity(FakeHeaderFile(COMPRESSED + b"\xff" * 32, compressed=True, zlib_size=len(COMPRESSED)))
    )
    yield "pspdb_encrypted_wrong_key", attempt(
        lambda: compute_identity(
            FakeHeaderFile(b"\x00" * 1024, compressed=True, encrypted=True, zlib_size=1024, decrypted=bytes(range(256)) * 4)
        )
    )
    yield "pspdb_encrypted_right_key", attempt(
        lambda: compute_identity(
            FakeHeaderFile(bytes(len(COMPRESSED)), compressed=True, encrypted=True, zlib_size=len(COMPRESSED), decrypted=COMPRESSED)
        )
    )
    yield "pspdb_load_type", attempt(lambda: compute_identity(FakeHeaderFile(PLAIN, load_addr=0xFFFF0100, type=0x8)))
    # The bare fake on the ladder: upstream trips over `signed_entity`.
    yield "bare_ladder", ladder(FakeHeaderFile(PLAIN))
    yield "bare_is_signed", attempt(lambda: FakeHeaderFile(PLAIN).is_signed)
    # Every rung of header_file.py:198-243.
    corrupt = bytearray(COMPRESSED)
    corrupt[-1] ^= 0xFF
    rungs = {
        "plain": dict(),
        "plain_signed_word": dict(signed_word=1),
        "bad_signed_word": dict(signed_word=2),
        "unverifiable_encrypted": dict(encrypted=True, decrypted=PLAIN),
        "compressed_ok": dict(compressed=True, zlib_size=len(COMPRESSED), decrypted=COMPRESSED),
        "compressed_corrupt": dict(compressed=True, zlib_size=len(corrupt), decrypted=bytes(corrupt)),
        "compressed_truncated": dict(compressed=True, zlib_size=len(COMPRESSED) // 2, decrypted=COMPRESSED),
        "compressed_no_magic": dict(compressed=True, zlib_size=100, decrypted=PLAIN),
        "compressed_prefix": dict(compressed=True, zlib_size=0x20 + len(COMPRESSED), decrypted=b"\x55" * 0x20 + COMPRESSED),
        "sha256_ok": dict(sha256=True),
        "sha256_failed": dict(sha256=False),
        "sha384_ok": dict(sha384=True),
        "sha384_failed": dict(sha384=False),
        "signature": dict(signed=Entity(True), size_signed=len(PLAIN)),
        "signature_failed": dict(signed=Entity(False), size_signed=len(PLAIN)),
        "signature_unresolved": dict(signed=Entity(errors.NoCertifyingKey(None))),
        "signature_error": dict(signed=Entity(RuntimeError("boom"))),
        "signature_sha256": dict(signed=Entity(True), size_signed=4, sha256=True),
        "signature_sha384": dict(signed=Entity(True), size_signed=4, sha256=False, sha384=True),
        "signature_partial": dict(signed=Entity(True), size_signed=4, sha256=False, sha384=False),
        "encrypted_signature": dict(signed=Entity(True), size_signed=len(PLAIN), encrypted=True, decrypted=PLAIN),
        "encrypted_signature_failed": dict(signed=Entity(False), encrypted=True, decrypted=PLAIN),
    }
    for name, kwargs in rungs.items():
        yield f"rung_{name}", ladder(LadderFile(PLAIN, **kwargs))
    yield "rung_verbose", attempt(lambda: LadderFile(PLAIN, sha256=False).decode_verification(print_warning=True))
    yield "own_verify_decode", ladder(OwnLadder(PLAIN))
    yield "own_decode", ladder(OwnDecode(PLAIN))
    # The native checksum check over the fake's decoded body.
    yield "checksum_match", ladder(ChecksumFile(PLAIN, hashlib.sha256(PLAIN).digest()))
    yield "checksum_mismatch", ladder(ChecksumFile(PLAIN, bytes(32)))
    yield "checksum_compressed", ladder(
        ChecksumFile(COMPRESSED, hashlib.sha256(PLAIN).digest(), compressed=True, zlib_size=len(COMPRESSED))
    )
    # update_sha256 (header_file.py:119-121): `self._sha256_checksum[:] = ...`.
    updated = ChecksumFile(PLAIN, bytes(32))
    updated._sha256_checksum = SizedBuffer(bytes(32))
    yield "update_sha256", [attempt(updated.update_sha256), attempt(updated._sha256_checksum.get_bytes)]
    yield "update_sha256_readonly", attempt(ChecksumFile(PLAIN, bytes(32)).update_sha256)
    # Attribute-driven decryption.
    yield "decrypt", ladder(EncryptedFile())
    yield "decrypt_short_iv", attempt(lambda: EncryptedFile(iv=IV[:8]).get_decrypted_body())
    # Methods over assigned attributes; `len(self.header)` and
    # `self.body[:]` need a sized, sliceable buffer upstream.
    signed = LadderFile(PLAIN, size_signed=0x10)
    signed.header = FakeBuffer(bytes(range(0x100)))
    yield "signed_bytes_unsized_header", attempt(signed.get_signed_bytes)
    signed.header = SizedBuffer(bytes(range(0x100)))
    yield "signed_bytes", attempt(signed.get_signed_bytes)
    yield "md5", attempt(FakeHeaderFile(PLAIN).md5)
    yield "entropy_unsliceable_body", attempt(lambda: repr(FakeHeaderFile(PLAIN).shannon_entropy()))
    sliceable = FakeHeaderFile(PLAIN)
    sliceable.body = SizedBuffer(PLAIN)
    yield "entropy", attempt(lambda: repr(sliceable.shannon_entropy()))
    # The other model classes.
    yield "file_readable_type", attempt(FakeFile(0x62, FakeEntry()).get_readable_type)
    yield "bios_destination", attempt(FakeBios(0x1234).get_readable_destination_address)
    yield "subclass_isinstance", [
        isinstance(type(f"Fake{c.__name__}", (c,), {"__init__": lambda self: None})(), c)
        for c in (
            File,
            BiosFile,
            HeaderFile,
            KeyStoreFile,
            PubkeyFile,
            MicrocodeFile,
            Directory,
            BiosDirectory,
            DirectoryEntry,
            BiosDirectoryEntry,
        )
    ]


def main():
    native = hasattr(psptool, "_native")
    print(json.dumps({"impl": "psptool-rs" if native else "reference", "module": psptool.__file__}))
    for name, out in cases():
        print(json.dumps({"case": name, "out": out}, sort_keys=True))


if __name__ == "__main__":
    main()
