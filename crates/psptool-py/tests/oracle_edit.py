"""Edit / rebuild acceptance across implementations (``corpus_parity.rs``).

Three modes, each run under the reference interpreter:

* ``keys <stub>`` — with upstream PSPTool importable: generate an RSA-2048
  and an RSA-4096 key with upstream ``PrivateKeyDict`` and save them as PEM
  files ``<stub>.rsa2048`` / ``<stub>.rsa4096`` (``crypto.py:150-175``).
* ``edit <rom> <stub> <out>`` — with the psptool-rs bindings first on the
  path: (1) the unmodified image round-trips through ``to_file``; (2) a
  same-place, same-size ``move_buffer`` of every file whose records already
  hold that place and size leaves the image byte-identical; (3) the
  ``__main__.py:238-262`` replace flow on the signed ``HeaderFile`` whose
  signature covers its whole decoded body and whose keys certify the fewest
  entities — flip a body byte when it is neither encrypted nor compressed,
  then ``signed_entity.resign_and_replace(privkeys)`` with the PEM keys — and
  ``to_file(out)``. Prints a JSON summary.
* ``verify <out> <stub> <summary-json>`` — with upstream PSPTool: parse
  ``out``, find the edited file at the same ``(rom, dir, file)`` index and
  require upstream's certificate tree to verify it and every sibling the
  replaced key certifies, under the replaced key material.
"""

import contextlib
import io
import json
import sys

import psptool
from psptool import PSPTool
from psptool.crypto import PrivateKeyDict
from psptool.header_file import HeaderFile


def quiet():
    return contextlib.redirect_stderr(io.StringIO())


def keys(stub):
    privkeys = PrivateKeyDict(dict())
    privkeys["rsa2048"]
    privkeys["rsa4096"]
    privkeys.save_to_files(stub)


def walk(pt):
    for ri, rom in enumerate(pt.blob.roms):
        for di, directory in enumerate(rom.directories):
            for fi, f in enumerate(directory.files):
                yield [ri, di, fi], f


def movable(f):
    """Whether a same-place, same-size move is a no-op: every referencing
    directory has exactly one entry of the file's type (``directory.py:207-215``
    rewrites the first one) and that record already holds this offset and size
    (a file shared through the offset cache may be referenced by records of
    another size, which the move would rewrite)."""
    if f.type in (0x0B, 0x61):
        return False
    for directory in f.references:
        same = [e for e in directory.entries if e.type == f.type]
        if len(same) != 1:
            return False
        if same[0].size != f.buffer_size or same[0].file_offset() != f.buffer_offset:
            return False
    return True


def resign_cost(f):
    """``(needs no flip ? 0 : 1, signatures re-created)`` for a signed
    ``HeaderFile`` whose whole decoded body the signature covers, or None.
    Plain (unencrypted, uncompressed) targets get a body byte flipped before
    re-signing; others are re-signed unchanged."""
    if type(f) is not HeaderFile or f.signed_entity is None:
        return None
    try:
        with quiet():
            if not f.signed_entity.is_verified() or f.decode_verification() != (True, "signature"):
                return None
    except Exception:  # noqa: BLE001 - unverifiable entries are not targets
        return None
    plain = not f.encrypted and not f.compressed and f.body.buffer_size >= 16
    cost = sum(len(k.certified_entities) for k in f.signed_entity.certifying_keys)
    return (0 if plain else 1, cost)


def edit(rom, stub, out):
    assert hasattr(psptool, "_native"), psptool.__file__
    original = open(rom, "rb").read()
    with quiet():
        pt = PSPTool.from_file(rom)
    summary = {}

    pt.to_file(out)
    summary["roundtrip"] = open(out, "rb").read() == original

    moved = 0
    for _, f in walk(pt):
        if movable(f):
            f.move_buffer(f.get_address(), f.buffer_size)
            moved += 1
    pt.to_file(out)
    summary["moved"] = moved
    summary["move_noop"] = open(out, "rb").read() == original

    best = None
    for key, f in walk(pt):
        cost = resign_cost(f)
        if cost is not None and (best is None or cost < best[0]):
            best = (cost, key, f)
    if best is None:
        summary["target"] = None
    else:
        (needs_flip, cost), key, f = best
        flipped = None
        if needs_flip == 0:
            flipped = f.body.get_bytes(0, 1)[0] ^ 0xFF
            f.body.set_bytes(0, 1, bytes([flipped]))
        privkeys = PrivateKeyDict.read_from_files(stub)
        with contextlib.redirect_stdout(io.StringIO()), quiet():
            f.signed_entity.resign_and_replace(privkeys=privkeys, recursive=False)
        summary["target"] = key
        summary["address"] = f.get_address()
        summary["byte"] = flipped
        summary["resigned"] = cost
        summary["ours_verified"] = f.signed_entity.is_verified()
        summary["ours_decode"] = list(f.decode_verification())
        pt.to_file(out)
    print(json.dumps(summary, sort_keys=True))


def verify(out, stub, summary):
    assert not hasattr(psptool, "_native"), psptool.__file__
    summary = json.loads(summary)
    with quiet():
        pt = PSPTool.from_file(out)
    r, d, i = summary["target"]
    f = pt.blob.roms[r].directories[d].files[i]
    assert f.get_address() == summary["address"], (f, summary)
    if summary["byte"] is not None:
        assert f.body.get_bytes(0, 1)[0] == summary["byte"], "edited byte not in the output image"
    assert f.signed_entity.is_verified(), "reference does not verify the re-signed file"
    privkeys = PrivateKeyDict.read_from_files(stub)
    for key in f.signed_entity.certifying_keys:
        expected = privkeys[key.key_type.name].get_public_key().get_crypto_material(key._crypto_material.buffer_size)
        assert key._crypto_material.get_bytes() == expected, f"{key} not replaced by the PEM key"
        for entity in key.certified_entities:
            assert entity.is_verified_by(key), f"{entity} does not verify under the replaced {key}"
    print(json.dumps({"verified": True}))


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "keys":
        keys(sys.argv[2])
    elif mode == "edit":
        edit(sys.argv[2], sys.argv[3], sys.argv[4])
    elif mode == "verify":
        verify(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        sys.exit(f"unknown mode {mode}")
