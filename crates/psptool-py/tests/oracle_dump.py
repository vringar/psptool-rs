"""Dump the PSPTool object walk of one ROM as JSON lines.

Run under the reference interpreter twice by ``corpus_parity.rs``: once
importing upstream PSPTool, once with the psptool-rs bindings first on
``PYTHONPATH``. Both runs must print identical lines (after the first,
which names the implementation).

Usage: python3 oracle_dump.py <rom>
"""

import contextlib
import hashlib
import io
import json
import sys

import psptool
from psptool import PSPTool


def sha(data):
    return hashlib.sha256(bytes(data)).hexdigest()


def attempt(fn):
    """The value, or the exception class name (both tools must agree)."""
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            return fn()
    except Exception as exc:  # noqa: BLE001 - the class name is the datum
        return f"EXC:{type(exc).__name__}"


def agesa(rom):
    # rom.py:43-48 iterates a set: the order of a dual ROM's two strings is
    # hash-seed dependent upstream, so compare them as a sorted pair.
    if getattr(rom, "dual_rom", False):
        return sorted([rom.agesa_version, rom.agesa_version_second])
    return rom.agesa_version


def file_record(key, f):
    rec = {
        "k": key,
        "cls": type(f).__name__,
        "addr": f.get_address(),
        "size": f.buffer_size,
        "type": f.type,
        "rtype": attempt(f.get_readable_type),
        "rver": attempt(f.get_readable_version),
        "rmagic": attempt(f.get_readable_magic),
        "md5": attempt(f.md5),
        "raw": attempt(lambda: sha(f.get_bytes())),
        "enc": bool(getattr(f, "encrypted", False)),
        "comp": bool(getattr(f, "compressed", False)),
        "signed": attempt(lambda: bool(getattr(f, "is_signed", False))),
        "load": getattr(f, "load_addr", None),
        "zlib": getattr(f, "zlib_size", None),
        "sizeu": getattr(f, "size_uncompressed", None),
        "sub": f.entry.subprogram,
        "ins": f.entry.instance,
        "ent": attempt(lambda: repr(f.shannon_entropy())),
        "refs": len(f.references),
    }
    if hasattr(f, "get_decrypted_decompressed_body"):
        rec["ddb"] = attempt(lambda: sha(f.get_decrypted_decompressed_body()))
        rec["db"] = attempt(lambda: sha(f.get_decrypted_body()))
        rec["hdr"] = attempt(lambda: sha(f.header.get_bytes()))
        rec["body"] = attempt(lambda: sha(f.body.get_bytes()))
        rec["hdr_ddb"] = attempt(lambda: sha(f.header.get_bytes() + f.get_decrypted_decompressed_body()))
        rec["signed_bytes"] = attempt(lambda: sha(f.get_signed_bytes()))
        rec["dv"] = attempt(lambda: list(f.decode_verification()))
        rec["dvd"] = attempt(f.decode_verified)
        rec["dvm"] = attempt(f.decode_verification_method)
        rec["pio"] = attempt(f.plaintext_identity_ok)
    if getattr(f, "signed_entity", None) is not None:
        rec["se_verified"] = attempt(f.signed_entity.is_verified)
    return rec


def main(path):
    native = hasattr(psptool, "_native")
    print(json.dumps({"impl": "psptool-rs" if native else "reference", "module": psptool.__file__}))
    with contextlib.redirect_stderr(io.StringIO()):
        pt = PSPTool.from_file(path)
    for ri, rom in enumerate(pt.blob.roms):
        rec = {
            "k": [ri],
            "off": rom.buffer_offset,
            "size": rom.buffer_size,
            "fet": rom.fet.buffer_offset,
            "agesa": agesa(rom),
            "ndirs": len(rom.directories),
        }
        print(json.dumps(rec, sort_keys=True))
        for di, d in enumerate(rom.directories):
            rec = {
                "k": [ri, di],
                "cls": type(d).__name__,
                "addr": d.get_address(),
                "magic": d.magic.hex(),
                "gen": d.zen_generation,
                "nfiles": len(d.files),
                "nentries": len(d.entries),
                "secondary": list(d.secondary_directory_offsets),
            }
            print(json.dumps(rec, sort_keys=True))
            for fi, f in enumerate(d.files):
                print(json.dumps(file_record([ri, di, fi], f), sort_keys=True))


if __name__ == "__main__":
    main(sys.argv[1])
