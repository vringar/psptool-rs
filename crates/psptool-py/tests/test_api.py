"""Corpus-free tests of the psptool-rs Python API on a synthetic image.

The image is built here byte by byte (FET -> one $PSP directory -> an
unsigned RSA-2048 PubkeyFile, a HeaderFile it signs, a raw WRAPPED_IKEK
entry), so the expectations are layout facts, not values read back from the
implementation. Run by ``python_api.rs`` (``cargo test``) and by the nix
``python`` attribute's check phase.
"""

import contextlib
import hashlib
import io
import json
import os
import struct
import tempfile
import unittest
from unittest import mock

import psptool
from psptool import PSPTool
from psptool.crypto import PrivateKeyDict, ReversedSignature
from psptool.directory import Directory
from psptool.entry import DirectoryEntry
from psptool.file import File
from psptool.header_file import HeaderFile
from psptool.pubkey_file import PubkeyFile
from psptool.utils import NestedBuffer

ROM_SIZE = 8 * 1024 * 1024  # smallest ROM upstream accepts (blob.py:53-54)
FET = 0x20000  # first known FET offset (blob.py:43)
DIRECTORY = 0x21000
PUBKEY = 0x30000
HEADER = 0x31000
IKEK = 0x32000
KEY_ID = bytes(range(0x10, 0x20))
BODY = bytes((i * 7) & 0xFF for i in range(0x200))
VERSION = bytes([0x21, 0x00, 0x0D, 0x00])  # displayed reversed: 0.D.0.21


def pubkey_file():
    # pubkey_file.py:53-91: version, key/certifying ids, 2048-bit exponent
    # and modulus widths, then pubexp || modulus (little-endian); unsigned.
    out = bytearray(0x240)
    out[0:4] = struct.pack("<I", 1)
    out[4:0x14] = KEY_ID
    out[0x14:0x24] = KEY_ID
    out[0x38:0x40] = struct.pack("<II", 2048, 2048)
    out[0x40:0x44] = struct.pack("<I", 0x10001)
    out[0x140:0x240] = b"\x01" * 0x100  # placeholder modulus, replaced by re-signing
    return bytes(out)


def header_file():
    # header_file.py:31-106: signed (0x30 = 1), RSA-2048 (0x34 = 0),
    # certifying id at 0x38, size_signed spanning the whole body.
    header = bytearray(0x100)
    header[0x10:0x14] = b"$PS1"
    header[0x14:0x18] = struct.pack("<I", len(BODY))
    header[0x30:0x34] = struct.pack("<I", 1)
    header[0x38:0x48] = KEY_ID
    header[0x60:0x64] = VERSION
    header[0x68:0x6C] = struct.pack("<I", 0x100)
    header[0x6C:0x70] = struct.pack("<I", 0x100 + len(BODY) + 0x100)
    return bytes(header) + BODY + bytes(0x100)


def image():
    rom = bytearray(b"\xff" * ROM_SIZE)
    # blob.py:124-131: FET magic preceded by a 0xFFFFFFFF word; one pointer.
    rom[FET : FET + 4] = b"\xaa\x55\xaa\x55"
    rom[FET + 4 : FET + 8] = struct.pack("<I", DIRECTORY)
    entries = [(0x00, pubkey_file(), PUBKEY), (0x01, header_file(), HEADER), (0x21, bytes(range(16)), IKEK)]
    # directory.py:119-147: $PSP, checksum (fixed below), count, additional
    # info 0 (x86-physical address mode), then 16-byte entry records.
    table = bytearray(b"$PSP" + bytes(4) + struct.pack("<II", len(entries), 0))
    for entry_type, body, offset in entries:
        table += struct.pack("<BBHIII", entry_type, 0, 0, len(body), offset, 0)
        rom[offset : offset + len(body)] = body
    rom[DIRECTORY : DIRECTORY + len(table)] = table
    return bytes(rom)


def parse(data):
    with contextlib.redirect_stderr(io.StringIO()):
        return PSPTool(data)


def files(pt):
    return pt.blob.roms[0].directories[0].files


class TestReadSurface(unittest.TestCase):
    def setUp(self):
        self.data = image()
        self.pt = parse(self.data)

    def test_object_walk(self):
        self.assertTrue(hasattr(psptool, "_native"))
        self.assertEqual(len(self.pt.blob.roms), 1)
        rom = self.pt.blob.roms[0]
        self.assertEqual((rom.buffer_offset, rom.buffer_size, rom.fet.buffer_offset), (0, ROM_SIZE, FET))
        self.assertIs(rom.directories, rom.fet.directories)
        directory = rom.directories[0]
        self.assertIsInstance(directory, Directory)
        self.assertEqual(directory.get_address(), DIRECTORY)
        self.assertEqual(directory.magic, b"$PSP")
        self.assertEqual(len(directory.entries), 3)
        self.assertIsInstance(directory.entries[0], DirectoryEntry)
        pubkey, header, ikek = directory.files
        self.assertIs(type(pubkey), PubkeyFile)
        self.assertIs(type(header), HeaderFile)
        self.assertIs(type(ikek), File)
        self.assertEqual([f.get_address() for f in directory.files], [PUBKEY, HEADER, IKEK])
        self.assertIs(self.pt.files_by_offset[HEADER], header)
        self.assertIs(self.pt.directories_by_offset[DIRECTORY], directory)

    def test_header_file_attributes(self):
        header = files(self.pt)[1]
        self.assertEqual(header.buffer_size, 0x100 + len(BODY) + 0x100)
        self.assertEqual(header.size_signed, len(BODY))
        self.assertFalse(header.encrypted)
        self.assertFalse(header.compressed)
        self.assertTrue(header.is_signed)
        self.assertEqual(header.load_addr, 0x100)
        self.assertEqual(header.get_readable_version(), "0.D.0.21")
        self.assertEqual(header.get_readable_magic(), "$PS1")
        self.assertEqual(header.get_readable_type(), "PSP_FW_BOOT_LOADER~0x1")
        self.assertEqual(header.entry.subprogram, 0)
        self.assertEqual(header.header.get_bytes(), header_file()[:0x100])
        self.assertEqual(header.get_decrypted_body(), BODY)
        self.assertEqual(header.get_decrypted_decompressed_body(), BODY)
        self.assertEqual(header.get_signed_bytes(), header_file()[: 0x100 + len(BODY)])

    def test_unverified_before_signing(self):
        # The placeholder modulus is a well-formed key that did not sign the
        # file (header_file.py:218-219); an unencrypted body is still its own
        # plaintext identity (header_file.py:267-276).
        header = files(self.pt)[1]
        self.assertEqual(header.decode_verification(), (False, "signature-failed"))
        self.assertFalse(header.decode_verified())
        self.assertEqual(header.decode_verification_method(), "signature-failed")
        self.assertTrue(header.plaintext_identity_ok())
        self.assertFalse(header.signed_entity.is_verified())

    def test_pubkey_file(self):
        pubkey = files(self.pt)[0]
        self.assertEqual(pubkey.key_id.as_string(), KEY_ID.hex().upper())
        self.assertEqual(pubkey.get_readable_magic(), KEY_ID[:2].hex().upper())
        self.assertEqual((pubkey.modulus_size, pubkey.signature_size), (0x100, 0))
        self.assertFalse(pubkey.is_signed)
        self.assertEqual(pubkey.pubexp, 0x10001)

    def test_unmodified_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.bin")
            self.pt.to_file(path)
            with open(path, "rb") as f:
                self.assertEqual(f.read(), self.data)
            again = PSPTool.from_file(path)
            self.assertEqual(again.filename, path)
            self.assertEqual(len(files(again)), 3)

    def test_nested_buffer_semantics(self):
        header = files(self.pt)[1]
        self.assertEqual(header[0x10:0x14], bytearray(b"$PS1"))
        self.assertEqual(header[0x10], ord("$"))
        self.assertEqual(header.body[0:4], bytearray(BODY[:4]))
        self.assertEqual(header.body.get_address(), HEADER + 0x100)
        with self.assertRaises(AssertionError):
            header.body[0 : header.body.buffer_size + 1]
        with self.assertRaises(AssertionError):
            header.set_bytes(0, 2, b"\x00")
        nb = NestedBuffer(header, 4, 0x10)
        self.assertEqual(nb.get_bytes(), b"$PS1")
        reversed_view = ReversedSignature(header, 4, 0x10)
        self.assertEqual(reversed_view.get_bytes(), b"1SP$")
        reversed_view.set_bytes(0, 4, b"ABCD")
        self.assertEqual(header[0x10:0x14], bytearray(b"DCBA"))

    def test_ls_json_shape(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.pt.ls_json()
        (directory,) = json.loads(out.getvalue())
        self.assertEqual(directory["address"], DIRECTORY)
        self.assertEqual([e["address"] for e in directory["entries"]], [PUBKEY, HEADER, IKEK])
        self.assertEqual(directory["entries"][1]["decodeVerificationMethod"], "signature-failed")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.pt.ls(verbose=True)
            self.pt.ls_files()
        self.assertIn("PSP_FW_BOOT_LOADER~0x1", out.getvalue())

    def test_from_file_is_patchable(self):
        # psp-etl's suite patches the classmethod (tests/test_ingest.py).
        with mock.patch("psptool.PSPTool.from_file", return_value="patched"):
            self.assertEqual(PSPTool.from_file("x"), "patched")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "rom.bin")
            with open(path, "wb") as f:
                f.write(self.data)
            self.assertEqual(len(files(PSPTool.from_file(path))), 3)


class TestEditSurface(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # One generated key for the class: RSA key generation dominates.
        cls.privkeys = PrivateKeyDict()
        cls.privkeys["rsa2048"]

    def setUp(self):
        self.pt = parse(image())

    def resign(self, pt):
        header = files(pt)[1]
        with contextlib.redirect_stdout(io.StringIO()):
            header.signed_entity.resign_and_replace(privkeys=self.privkeys, recursive=False)
        return header, self.privkeys

    def test_resign_verifies_and_persists(self):
        header, privkeys = self.resign(self.pt)
        self.assertTrue(header.signed_entity.is_verified())
        self.assertEqual(header.decode_verification(), (True, "signature"))
        self.assertTrue(header.plaintext_identity_ok())
        material = privkeys["rsa2048"].get_public_key().get_crypto_material(0x200)
        self.assertEqual(files(self.pt)[0].crypto_material.get_bytes(), material)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "signed.bin")
            self.pt.to_file(path)
            again = PSPTool.from_file(path)
            self.assertEqual(files(again)[1].decode_verification(), (True, "signature"))

    def test_replace_body_and_resign(self):
        # __main__.py:238-262: move_buffer + set_bytes, then re-sign.
        header = files(self.pt)[1]
        new_body = bytes(reversed(BODY))
        header.body.set_bytes(0, len(new_body), new_body)
        self.assertEqual(header.decode_verification()[1], "signature-failed")
        header.move_buffer(header.get_address(), header.buffer_size)
        self.resign(self.pt)
        self.assertEqual(header.get_decrypted_decompressed_body(), new_body)
        self.assertEqual(header.decode_verification(), (True, "signature"))

    def test_move_buffer_rewrites_record_and_checksum(self):
        ikek = files(self.pt)[2]
        directory = self.pt.blob.roms[0].directories[0]
        ikek.move_buffer(IKEK + 0x100, 8)
        record = directory.entries[2]
        self.assertEqual((record.offset, record.size), (IKEK + 0x100, 8))
        self.assertEqual(ikek.get_address(), IKEK + 0x100)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            directory.verify_checksum()
        self.assertEqual(err.getvalue(), "")
        reparsed = parse(self.pt.blob.get_buffer())
        self.assertEqual(files(reparsed)[2].get_address(), IKEK + 0x100)

    def test_private_keys_round_trip_through_pem(self):
        privkeys = self.privkeys
        material = privkeys["rsa2048"].get_public_key().get_crypto_material(0x100)
        for password in (None, "secret"):
            with tempfile.TemporaryDirectory() as tmp:
                stub = os.path.join(tmp, "keys", "id")
                privkeys.save_to_files(stub, password)
                loaded = PrivateKeyDict.read_from_files(stub, password)
                self.assertEqual(loaded["rsa2048"].get_public_key().get_crypto_material(0x100), material)

    def test_update_sha256(self):
        header = files(self.pt)[1]
        header.update_sha256()
        self.assertTrue(header.verify_sha256(print_warning=False))
        self.assertEqual(header._sha256_checksum.get_bytes(), hashlib.sha256(BODY).digest())


if __name__ == "__main__":
    unittest.main()
