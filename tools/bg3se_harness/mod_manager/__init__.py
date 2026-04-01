"""BG3 mod manager — CLI integration layer.

Delegates to BG3MacModManager (if installed) or uses pure Python fallback.
"""

from .installer import install_local, uninstall, get_mod_info
from .registry import list_mods, get_mod
from .modsettings import (
    read_mod_order,
    add_mod,
    remove_mod,
    enable_mod,
    disable_mod,
    reorder_mod,
    backup_modsettings,
)

__all__ = [
    # installer
    "install_local",
    "uninstall",
    "get_mod_info",
    # registry
    "list_mods",
    "get_mod",
    # modsettings
    "read_mod_order",
    "add_mod",
    "remove_mod",
    "enable_mod",
    "disable_mod",
    "reorder_mod",
    "backup_modsettings",
]
