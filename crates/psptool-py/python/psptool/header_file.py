# Re-export of the psptool-rs native implementation at the upstream PSPTool
# module path (see crates/psptool-py/DEVIATIONS.md). No logic lives here.

from ._native import HeaderFile

__all__ = ["HeaderFile"]
