"""The psp-etl ingest loop over corpus ROMs (#98, board #533).

For each ROM given on the command line: ``PSPTool.from_file``, decode every
``HeaderFile`` body, drop the object -- without ``gc.collect()``, so the
automatic collector (and the bindings' native-memory trigger) must reclaim
the dropped parses. Prints one JSON object: the RSS after the first ROM, the
peak RSS sampled after every ROM, and the ROM count. Run by ``memory.rs``.
"""

import contextlib
import io
import json
import os
import sys

from psptool import PSPTool
from psptool.header_file import HeaderFile


def rss():
    with open("/proc/self/statm") as f:
        return int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")


def main(paths):
    first = peak = None
    for path in paths:
        with contextlib.redirect_stderr(io.StringIO()):
            psp = PSPTool.from_file(path)
        for rom in psp.blob.roms:
            for directory in rom.directories:
                for f in directory.files:
                    if isinstance(f, HeaderFile):
                        # Undecodable bodies are the loop's to skip, not ours.
                        with contextlib.suppress(Exception):
                            f.get_decrypted_decompressed_body()
        del psp
        now = rss()
        first = now if first is None else first
        peak = now if peak is None else max(peak, now)
    print(json.dumps({"roms": len(paths), "first": first, "peak": peak}))


if __name__ == "__main__":
    main(sys.argv[1:])
