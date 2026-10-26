"""Drop-in replacement for the PSPTool Python API, backed by psptool-rs.

``from psptool import PSPTool`` and the upstream submodules
(``psptool.header_file.HeaderFile``, ...) resolve to the native classes of
``psptool._native``. Deviations from upstream PSPTool are listed in
``DEVIATIONS.md`` next to the psptool-py crate.
"""

from ._native import PSPTool, __version__

# Upstream's __init__ imports psptool.py, which imports every submodule, so a
# bare ``import psptool`` makes ``psptool.header_file`` etc. resolve.
from . import (  # noqa: F401
    blob,
    cert_tree,
    crypto,
    directory,
    entry,
    errors,
    fet,
    file,
    header_file,
    key_store_file,
    microcode_file,
    psptool,
    pubkey_file,
    rom,
    utils,
)

__all__ = ["PSPTool", "__version__"]
