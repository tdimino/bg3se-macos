"""registry.py — JSON-backed mod registry for bg3se-harness.

Tracks installed mods and their metadata.  The registry is a flat dict
keyed by UUID, persisted at ~/.config/bg3se-harness/mod_registry.json.

Capped at 200 entries; older entries are not auto-evicted — callers
must use unregister_mod() when removing mods.

All public functions return JSON-serialisable dicts or lists.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Resolve config paths via the harness package.
# modsettings.py patches sys.path for the same import; we avoid that
# by using a relative import since registry.py lives inside the package.
try:
    from ..config import MOD_REGISTRY_PATH, HARNESS_CONFIG_DIR
except ImportError:
    # Fallback for direct script execution (rare)
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from config import MOD_REGISTRY_PATH, HARNESS_CONFIG_DIR  # type: ignore

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REGISTRY_MAX_ENTRIES = 200

# ---------------------------------------------------------------------------
# Internal I/O helpers
# ---------------------------------------------------------------------------

def _ensure_config_dir() -> None:
    HARNESS_CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_registry() -> dict:
    """Load the registry from disk.

    Returns an empty dict if the file does not exist or is invalid JSON.
    The registry is keyed by UUID string.
    """
    if not MOD_REGISTRY_PATH.exists():
        return {}
    try:
        raw = MOD_REGISTRY_PATH.read_text(encoding="utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            return {}
        return data
    except (json.JSONDecodeError, OSError):
        return {}


def save_registry(registry: dict) -> None:
    """Persist the registry to disk atomically.

    Writes to a temp file then renames so a crash mid-write doesn't
    corrupt the existing registry.
    """
    _ensure_config_dir()
    tmp = MOD_REGISTRY_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(registry, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(MOD_REGISTRY_PATH)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def register_mod(
    uuid: str,
    name: str,
    folder: str,
    source_path: str,
    pak_path: str | None = None,
    *,
    se_mod: bool = False,
    version: str | None = None,
    author: str | None = None,
    description: str | None = None,
    enabled: bool = True,
    **metadata,
) -> dict:
    """Add or update a mod entry in the registry.

    If a mod with *uuid* already exists, its record is updated in-place
    (new call wins).  Returns the final registry entry dict.

    Extra keyword args in *metadata* are stored verbatim — useful for
    callers that pass additional fields without breaking the contract.

    Raises:
        ValueError: If the registry is already at REGISTRY_MAX_ENTRIES
            and the UUID is not already present.
    """
    registry = load_registry()

    if uuid not in registry and len(registry) >= REGISTRY_MAX_ENTRIES:
        raise ValueError(
            f"Registry full ({REGISTRY_MAX_ENTRIES} entries). "
            f"Unregister a mod before adding a new one."
        )

    now = datetime.now(tz=timezone.utc).isoformat()
    existing = registry.get(uuid, {})

    entry: dict = {
        "uuid": uuid,
        "name": name,
        "folder": folder,
        "source_path": source_path,
        "pak_path": pak_path,
        "installed_at": existing.get("installed_at", now),
        "enabled": enabled,
        "se_mod": se_mod,
        "version": version,
        "author": author,
        "description": description,
        **metadata,
    }

    registry[uuid] = entry
    save_registry(registry)
    return entry


def unregister_mod(uuid: str) -> dict:
    """Remove a mod from the registry by UUID.

    Returns ``{"removed": True, "uuid": uuid}`` on success or
    ``{"removed": False, "uuid": uuid, "reason": "not found"}`` if the
    UUID was not present.
    """
    registry = load_registry()
    if uuid not in registry:
        return {"removed": False, "uuid": uuid, "reason": "not found"}

    del registry[uuid]
    save_registry(registry)
    return {"removed": True, "uuid": uuid}


def get_mod(uuid: str) -> dict | None:
    """Return the registry entry for *uuid*, or None if not found."""
    registry = load_registry()
    return registry.get(uuid)


def list_mods() -> list[dict]:
    """Return all registered mods, augmented with modsettings.lsx state.

    Each entry gains an ``"in_load_order"`` boolean indicating whether
    the mod is currently active in modsettings.lsx.

    Sorted by name (case-insensitive) for stable output.
    """
    # Lazy import to avoid circular dependency and allow the module to be
    # imported even if modsettings.lsx is absent.
    try:
        from .modsettings import read_mod_order
        active_order = read_mod_order()
        # read_mod_order returns [{"error": ...}] on failure
        if active_order and "error" in active_order[0]:
            active_uuids: set[str] = set()
        else:
            active_uuids = {m["uuid"] for m in active_order if m.get("uuid")}
    except Exception:
        active_uuids = set()

    registry = load_registry()
    result: list[dict] = []
    for entry in registry.values():
        augmented = dict(entry)
        augmented["in_load_order"] = entry.get("uuid", "") in active_uuids
        result.append(augmented)

    result.sort(key=lambda e: (e.get("name") or "").lower())
    return result
