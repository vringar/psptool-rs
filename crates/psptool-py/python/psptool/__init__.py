"""Drop-in replacement for the PSPTool Python API, backed by psptool-rs.

``from psptool import PSPTool`` and the upstream submodules
(``psptool.header_file.HeaderFile``, ...) resolve to the native classes of
``psptool._native``. Deviations from upstream PSPTool are listed in
``DEVIATIONS.md`` next to the psptool-py crate.
"""

from ._native import PSPTool, __version__

__all__ = ["PSPTool", "__version__"]
