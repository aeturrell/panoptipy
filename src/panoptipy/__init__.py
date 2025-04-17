"""
panoptipy
------------------------------------
A Python Package for Static Code Quality Assessment
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("panoptipy")
except PackageNotFoundError:
    __version__ = "unknown"
