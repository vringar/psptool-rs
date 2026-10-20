"""Divergence probes: one case per pinned bindings-vs-upstream divergence.

Run by ``tests/divergence.rs`` under the reference interpreter twice, once
importing upstream PSPTool and once with the psptool-rs bindings first on
``PYTHONPATH``. Every line after the implementation banner must be identical;
the reference's lines are the expected values (live oracle, R-CHAR-3).

Corpus-gated cases take a ROM path. Cases that mutate the image compute the
byte offsets from a parse of the *unmodified* image (both implementations
agree on it, ``corpus_parity.rs``) and then re-parse a mutated ``bytearray``.

Usage: python3 oracle_divergence.py <case> [<rom>]
"""

import contextlib
import io
import json
import re
import struct
import sys

import psptool
from psptool import PSPTool


def emit(**rec):
    print(json.dumps(rec, sort_keys=True))


def attempt(fn):
    """The value, or the exception's qualified class name."""
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            return fn()
    except Exception as exc:  # noqa: BLE001 - the class is the datum
        return f"EXC:{type(exc).__module__}.{type(exc).__qualname__}"


def stdout_of(fn):
    """What ``fn`` prints, or the exception's qualified class name."""
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            fn()
    except Exception as exc:  # noqa: BLE001
        return f"EXC:{type(exc).__module__}.{type(exc).__qualname__}"
    return buf.getvalue()


def parse(data):
    with contextlib.redirect_stderr(io.StringIO()):
        return PSPTool(data)


def read(path):
    with open(path, "rb") as fh:
        return bytearray(fh.read())


def entries(pt):
    for rom in pt.blob.roms:
        for d in rom.directories:
            for e in d.entries:
                yield d, e


def files(pt):
    for rom in pt.blob.roms:
        for d in rom.directories:
            for f in d.files:
                yield d, f


def first_entry(pt, cls, entry_type):
    for d, e in entries(pt):
        if type(e).__name__ == cls and e.type == entry_type:
            return d, e
    raise LookupError(f"no {cls} of type {entry_type:#x}")


# --- cases -------------------------------------------------------------------


def case_small_input(_rom):
    """blob.py:53-54: ``max(value for value in [32, 16, 8] if value MiB <=
    buffer_size)`` has no candidate below 8 MiB, so ``PSPTool(...)`` raises
    ValueError (psp-db's analyze.py relies on that to skip non-firmware)."""
    for size in (0, 5, 1 << 20, (8 << 20) - 1):
        result = attempt(lambda: len(parse(bytearray(size)).blob.roms))
        emit(case="small_input", size=size, result=result)


def case_destination_text(rom):
    """entry.py:139-144 ``f'{self.destination=:#x}'``, file.py:365-366
    ``hex(self.entry.destination)``, file.py:410-413 (BiosFile): Python ints,
    so a destination of 0xffffffffffffffff renders, it does not overflow."""
    pt = parse(read(rom))
    big = 1 << 63
    for d, e in entries(pt):
        if type(e).__name__ == "BiosDirectoryEntry" and e.destination >= big:
            emit(case="entry_repr", addr=e.get_address(), repr=attempt(lambda: repr(e)))
            break
    seen = set()
    for d, f in files(pt):
        cls = type(f).__name__
        if cls in seen or type(f.entry).__name__ != "BiosDirectoryEntry" or f.entry.destination < big:
            continue
        seen.add(cls)
        emit(case="file", cls=cls, addr=f.get_address(),
             readable=attempt(f.get_readable_destination_address),
             repr=attempt(lambda: repr(f)))


def case_destination_listing(rom):
    """psptool.py:149-158 (ls) and :257-258 (ls_json) call
    get_readable_destination_address() for the BIOS (0x62) entry; with its
    destination set to 0xffffffffffffffff upstream still lists."""
    data = read(rom)
    _, e = first_entry(parse(bytearray(data)), "BiosDirectoryEntry", 0x62)
    at = e.get_address() + 16
    data[at:at + 8] = b"\xff" * 8
    pt = parse(data)
    ls = stdout_of(pt.ls)
    emit(case="ls", destinations=re.findall(r"destination\([^)]*\)", ls) if not ls.startswith("EXC:") else ls)
    out = stdout_of(pt.ls_json)
    if out.startswith("EXC:"):
        emit(case="ls_json", destinations=out)
    else:
        emit(case="ls_json", destinations=[
            e["destinationAddress"] for d in json.loads(out) for e in d["entries"] if "destinationAddress" in e
        ])


def case_destination_attribute(rom):
    """file.py:396-399: only BiosFile.__init__ stores ``self.destination``;
    a HeaderFile / PubkeyFile / KeyStoreFile parsed from a BIOS directory
    (file.py:259-265 picks those classes before BiosFile) has none."""
    pt = parse(read(rom))
    counts = {}
    for d, f in files(pt):
        cls = type(f).__name__
        if type(d).__name__ != "BiosDirectory" or cls not in ("HeaderFile", "PubkeyFile", "KeyStoreFile"):
            continue
        key = f"{cls}:{hasattr(f, 'destination')}"
        counts[key] = counts.get(key, 0) + 1
    emit(case="destination_attribute", counts=counts)


def case_soft_fuse_listing(rom):
    """psptool.py:164-165 ``hex(file.entry.offset + (file.entry.rsv0 << 32))``
    on Python ints: an rsv0 with bit 31 set gives a 64-bit positive value."""
    data = read(rom)
    _, e = first_entry(parse(bytearray(data)), "DirectoryEntry", 0x0B)
    at = e.get_address() + 12
    data[at:at + 4] = struct.pack("<I", 0x80000000 | e.rsv0)
    ls = stdout_of(parse(data).ls)
    emit(case="soft_fuse", tokens=re.findall(r"soft_fuse\([^)]*\)", ls) if not ls.startswith("EXC:") else ls)


def case_listing_control_whitespace(rom):
    """header_file.py:146-163 keeps string.printable characters of the magic,
    which include \\t and \\x0b; psptool.py:200 hands the cell to prettytable,
    whose width of such a cell is wcwidth.wcswidth() == -1, not its length."""
    data = read(rom)
    pt = parse(bytearray(data))
    target = next(f for _, f in files(pt) if type(f).__name__ == "HeaderFile" and f.type == 0x1)
    at = target.get_address() + 0x10
    data[at:at + 4] = b"A\tB\x0b"
    pt = parse(data)
    ls = stdout_of(pt.ls)
    rows = [line for line in ls.split("\n") if "PSP_FW_BOOT_LOADER~0x1" in line]
    emit(case="control_whitespace", magic=attempt(lambda: next(
        f.get_readable_magic() for _, f in files(pt) if f.get_address() == target.get_address())), rows=rows)


def case_import_surface(_rom):
    """__init__.py:17 ``from .psptool import PSPTool`` imports psptool.py, which
    imports every other submodule, so after ``import psptool`` they are all
    attributes of the package (``psptool.header_file.HeaderFile`` works)."""
    for sub in ("psptool", "blob", "rom", "fet", "directory", "entry", "file", "header_file",
                "pubkey_file", "key_store_file", "microcode_file", "cert_tree", "crypto", "errors", "utils"):
        emit(case="import_surface", submodule=sub, attribute=hasattr(psptool, sub))


def case_entry_setters(rom):
    """entry.py:100-102 / 178-180: the instance setters OR in ``value & 0xF``
    (any int); the struct.pack setters (entry.py:76-126, 146-164) raise
    struct.error for an out-of-range value; directory.py:174-180 likewise."""
    raw = read(rom)

    def fresh(cls, entry_type):
        return first_entry(parse(bytearray(raw)), cls, entry_type)

    def apply(name, target, attr, value):
        def go():
            setattr(target, attr, value)
            return target.flags if attr == "instance" else getattr(target, attr)
        emit(case="setter", name=name, result=attempt(go))

    apply("psp_instance_wide", fresh("DirectoryEntry", 0x1)[1], "instance", 0x10013)
    apply("psp_instance_negative", fresh("DirectoryEntry", 0x1)[1], "instance", -1)
    apply("bios_instance_wide", fresh("BiosDirectoryEntry", 0x62)[1], "instance", 0x10001)
    apply("psp_subprogram_overflow", fresh("DirectoryEntry", 0x1)[1], "subprogram", 0x1FF)
    apply("psp_flags_negative", fresh("DirectoryEntry", 0x1)[1], "flags", -1)
    apply("psp_size_overflow", fresh("DirectoryEntry", 0x1)[1], "size", 1 << 32)
    apply("bios_destination_overflow", fresh("BiosDirectoryEntry", 0x62)[1], "destination", 1 << 64)
    apply("directory_count_negative", fresh("DirectoryEntry", 0x1)[0], "count", -1)


CASES = {name[len("case_"):]: fn for name, fn in globals().items() if name.startswith("case_")}


def main(case, rom=None):
    native = hasattr(psptool, "_native")
    print(json.dumps({"impl": "psptool-rs" if native else "reference", "case": case}))
    CASES[case](rom)


if __name__ == "__main__":
    main(*sys.argv[1:])
