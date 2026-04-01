"""
modsettings.py — Read/write BG3 modsettings.lsx

Invariants:
- GustavX (GUSTAVX_UUID) must always remain at position 0 in the mod order.
- Every write is preceded by a timestamped backup capped at 20 files.
- XML attribute order within <attribute> elements is always: id, type, value.
  The C parser (mod_loader.c) uses strstr() and depends on this exact ordering.

Attribute order matters because xml.etree.ElementTree sorts attributes
alphabetically by default (CPython 3.8+ insertion order, but the attribute
kwargs in Element() calls are not positionally ordered). We use a custom
serializer that emits attributes in the canonical LSX order to maintain
C-parser compatibility.
"""

from __future__ import annotations

import re
import shutil
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree as ET

# Import project paths from config
try:
    from ..config import MODSETTINGS_PATH, HARNESS_CONFIG_DIR, GUSTAVX_UUID
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from config import MODSETTINGS_PATH, HARNESS_CONFIG_DIR, GUSTAVX_UUID

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BACKUPS_DIR = HARNESS_CONFIG_DIR / "backups"
MAX_BACKUPS = 20

# Default version for new mods (matches BG3SE Windows reference)
DEFAULT_VERSION = "36028797018963968"

# ---------------------------------------------------------------------------
# Internal: XML serialization with guaranteed attribute order
# ---------------------------------------------------------------------------

def _attr(id_val: str, type_val: str, value_val: str) -> str:
    """
    Produce a single <attribute .../> string with attributes in the order
    id, type, value — the order the C strstr() parser expects.
    """
    # Escape XML special characters in values
    def esc(s: str) -> str:
        return (s.replace("&", "&amp;")
                  .replace('"', "&quot;")
                  .replace("<", "&lt;")
                  .replace(">", "&gt;"))
    return f'<attribute id="{esc(id_val)}" type="{esc(type_val)}" value="{esc(value_val)}"/>'


def _mod_node_xml(mod: dict, indent: str = "          ") -> str:
    """
    Serialise a mod dict to a <node id="ModuleShortDesc"> block with
    attributes in the id-alphabetical order BG3 itself uses, and each
    <attribute> line keeping the id/type/value attribute order.

    BG3 canonical attribute order within the ModuleShortDesc node:
      Folder, MD5, Name, UUID, Version64
    """
    folder  = mod.get("folder",  "")
    md5     = mod.get("md5",     "")
    name    = mod.get("name",    "")
    uuid    = mod.get("uuid",    "")
    version = mod.get("version", DEFAULT_VERSION)

    lines = [
        f'{indent}<node id="ModuleShortDesc">',
        f'{indent}  {_attr("Folder",    "LSString",   folder)}',
        f'{indent}  {_attr("MD5",       "LSString",   md5)}',
        f'{indent}  {_attr("Name",      "LSString",   name)}',
        f'{indent}  {_attr("UUID",      "FixedString", uuid)}',
        f'{indent}  {_attr("Version64", "int64",      version)}',
        f'{indent}</node>',
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Internal: parse modsettings.lsx → list of mod dicts
# ---------------------------------------------------------------------------

def _parse_modsettings(path: Path) -> tuple[ET.ElementTree, list[dict]]:
    """
    Parse modsettings.lsx using ElementTree.  Returns (tree, mods) where
    mods is a list of dicts with keys: folder, md5, name, uuid, version.

    The tree is returned for structural awareness but we do NOT use ET to
    serialise back — we use the custom _serialise_modsettings() instead.
    """
    tree = ET.parse(str(path))
    root = tree.getroot()

    mods: list[dict] = []

    for node in root.iter("node"):
        if node.get("id") != "ModuleShortDesc":
            continue
        entry: dict = {}
        for attr in node:
            if attr.tag != "attribute":
                continue
            attr_id = attr.get("id", "")
            val     = attr.get("value", "")
            if attr_id == "Folder":
                entry["folder"] = val
            elif attr_id == "MD5":
                entry["md5"] = val
            elif attr_id == "Name":
                entry["name"] = val
            elif attr_id == "UUID":
                entry["uuid"] = val
            elif attr_id == "Version64":
                entry["version"] = val
        if "uuid" in entry:
            mods.append(entry)

    return tree, mods


# ---------------------------------------------------------------------------
# Internal: serialise mods list back to modsettings.lsx
# ---------------------------------------------------------------------------

_LSX_HEADER = '<?xml version="1.0" encoding="UTF-8"?>'

# Regexes matching <children>…</children> blocks under ModOrder and Mods nodes.
# Both must be rewritten in sync — BG3 requires matching entries in both blocks.
_MOD_ORDER_CHILDREN_RE = re.compile(
    r'(<node\s+id="ModOrder"[^>]*>\s*<children>)'
    r'(.*?)'
    r'(</children>\s*</node>)',
    re.DOTALL,
)

_MODS_CHILDREN_RE = re.compile(
    r'(<node\s+id="Mods"[^>]*>\s*<children>)'
    r'(.*?)'
    r'(</children>\s*</node>)',
    re.DOTALL,
)


def _serialise_modsettings(original_text: str, mods: list[dict]) -> str:
    """
    Replace both the ModOrder and Mods <children> blocks in the original
    file text with fresh content built from *mods*, preserving all other
    XML verbatim.

    Both blocks must contain identical entries — BG3 reads both at boot.
    We control the exact attribute order within each <attribute> element
    for C-parser compatibility.
    """
    inner = "\n".join(_mod_node_xml(m) for m in mods)

    def replacer(m: re.Match) -> str:
        return m.group(1) + "\n" + inner + "\n          " + m.group(3)

    result, n = _MOD_ORDER_CHILDREN_RE.subn(replacer, original_text)
    if n == 0:
        result = _build_full_lsx(mods)
        return result

    # Also replace the Mods block to keep both in sync
    result, _ = _MODS_CHILDREN_RE.subn(replacer, result)
    return result


def _build_full_lsx(mods: list[dict]) -> str:
    """
    Build a minimal but valid modsettings.lsx from scratch.
    Used when the file does not exist or the regex couldn't find the block.
    """
    mod_nodes = "\n".join(_mod_node_xml(m) for m in mods)
    return f"""{_LSX_HEADER}
<save>
  <version major="4" minor="0" revision="9" build="332"/>
  <region id="ModuleSettings">
    <node id="root">
      <children>
        <node id="ModOrder">
          <children>
{mod_nodes}
          </children>
        </node>
        <node id="Mods">
          <children>
{mod_nodes}
          </children>
        </node>
      </children>
    </node>
  </region>
</save>
"""


# ---------------------------------------------------------------------------
# Backup helpers
# ---------------------------------------------------------------------------

def _ensure_backups_dir() -> None:
    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)


def _prune_backups() -> None:
    """Remove oldest backups, keeping at most MAX_BACKUPS files."""
    backups = sorted(BACKUPS_DIR.glob("modsettings_*.lsx"))
    while len(backups) >= MAX_BACKUPS:
        backups.pop(0).unlink(missing_ok=True)


def backup_modsettings() -> dict:
    """
    Create a timestamped backup of modsettings.lsx.
    Returns {"path": str, "timestamp": str} on success, {"error": str} on failure.
    """
    if not MODSETTINGS_PATH.exists():
        return {"error": f"modsettings.lsx not found at {MODSETTINGS_PATH}"}

    _ensure_backups_dir()
    _prune_backups()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = BACKUPS_DIR / f"modsettings_{ts}.lsx"
    shutil.copy2(str(MODSETTINGS_PATH), str(dest))

    return {"path": str(dest), "timestamp": ts}


def list_backups() -> list[dict]:
    """
    Return a list of available backups, newest first.
    Each entry: {"path": str, "timestamp": str, "size": int}.
    """
    if not BACKUPS_DIR.exists():
        return []
    results = []
    for p in sorted(BACKUPS_DIR.glob("modsettings_*.lsx"), reverse=True):
        ts = p.stem.replace("modsettings_", "")
        results.append({"path": str(p), "timestamp": ts, "size": p.stat().st_size})
    return results


def restore_backup(backup_path: str) -> dict:
    """
    Overwrite modsettings.lsx from a backup file.
    Returns {"restored": str} on success, {"error": str} on failure.
    """
    src = Path(backup_path)
    if not src.exists():
        return {"error": f"Backup not found: {backup_path}"}

    # Back up the current file before restoring
    backup_modsettings()

    MODSETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(src), str(MODSETTINGS_PATH))
    return {"restored": str(src)}


# ---------------------------------------------------------------------------
# Internal: read helpers
# ---------------------------------------------------------------------------

def _load_mods() -> tuple[str, list[dict]] | tuple[None, dict]:
    """
    Load modsettings.lsx, returning (raw_text, mods_list).
    On error returns (None, {"error": str}).
    """
    if not MODSETTINGS_PATH.exists():
        return None, {"error": f"modsettings.lsx not found at {MODSETTINGS_PATH}"}
    try:
        raw = MODSETTINGS_PATH.read_text(encoding="utf-8")
        _, mods = _parse_modsettings(MODSETTINGS_PATH)
        return raw, mods
    except ET.ParseError as exc:
        return None, {"error": f"XML parse error: {exc}"}
    except OSError as exc:
        return None, {"error": f"IO error: {exc}"}


def _save_mods(raw: str, mods: list[dict]) -> dict | None:
    """
    Validate GustavX invariant and write the updated file.
    Returns {"error": str} if validation fails, None on success.
    """
    # Enforce GustavX at position 0
    if not mods or mods[0].get("uuid") != GUSTAVX_UUID:
        return {"error": "GustavX invariant violated: UUID not at position 0"}

    new_text = _serialise_modsettings(raw, mods)
    MODSETTINGS_PATH.write_text(new_text, encoding="utf-8")
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def read_mod_order() -> list[dict]:
    """
    Read the current mod order from modsettings.lsx.
    Returns a list of mod dicts on success, or a single-element list
    containing {"error": str} on failure.
    """
    raw, result = _load_mods()
    if raw is None:
        return [result]
    return result


def add_mod(
    uuid: str,
    name: str,
    folder: str,
    version: str = DEFAULT_VERSION,
    md5: str = "",
) -> dict:
    """
    Add a mod to modsettings.lsx.  If a mod with this UUID already exists,
    returns an informational dict without modifying the file.

    Returns {"added": bool, "uuid": str, "name": str} or {"error": str}.
    """
    raw, mods = _load_mods()
    if raw is None:
        return mods  # error dict

    # Idempotent: already present
    if any(m.get("uuid") == uuid for m in mods):
        return {"added": False, "uuid": uuid, "name": name, "reason": "already present"}

    backup = backup_modsettings()
    if "error" in backup:
        return backup

    new_entry = {"uuid": uuid, "name": name, "folder": folder,
                 "version": version, "md5": md5}
    mods.append(new_entry)

    err = _save_mods(raw, mods)
    if err:
        return err

    return {"added": True, "uuid": uuid, "name": name}


def remove_mod(uuid: str) -> dict:
    """
    Remove a mod from modsettings.lsx by UUID.
    Refuses to remove GustavX.

    Returns {"removed": bool, "uuid": str} or {"error": str}.
    """
    if uuid == GUSTAVX_UUID:
        return {"error": "Cannot remove GustavX — it must remain at position 0"}

    raw, mods = _load_mods()
    if raw is None:
        return mods

    original_count = len(mods)
    mods = [m for m in mods if m.get("uuid") != uuid]

    if len(mods) == original_count:
        return {"removed": False, "uuid": uuid, "reason": "not found"}

    backup = backup_modsettings()
    if "error" in backup:
        return backup

    err = _save_mods(raw, mods)
    if err:
        return err

    return {"removed": True, "uuid": uuid}


def enable_mod(uuid: str) -> dict:
    """
    Alias for add_mod when a uuid is already registered in the mod registry.
    Requires name/folder — here we just check presence; for full enable
    from registry use add_mod() directly with all fields.

    Returns add_mod result or {"error": str}.
    """
    raw, mods = _load_mods()
    if raw is None:
        return mods

    # If already present, nothing to do
    match = next((m for m in mods if m.get("uuid") == uuid), None)
    if match:
        return {"enabled": True, "uuid": uuid, "reason": "already in order"}

    return {"error": f"Mod {uuid} not in current order — use add_mod() with name/folder to add it"}


def disable_mod(uuid: str) -> dict:
    """
    Alias for remove_mod().
    """
    result = remove_mod(uuid)
    if "removed" in result:
        result["disabled"] = result.pop("removed")
    return result


def reorder_mod(uuid: str, before_uuid: str) -> dict:
    """
    Move the mod identified by *uuid* to just before the mod identified by
    *before_uuid* in the load order.  GustavX remains pinned at position 0
    regardless of where it appears in the operation.

    Returns {"reordered": True, "uuid": str} or {"error": str}.
    """
    if uuid == GUSTAVX_UUID:
        return {"error": "Cannot reorder GustavX — it is pinned at position 0"}

    raw, mods = _load_mods()
    if raw is None:
        return mods

    source = next((m for m in mods if m.get("uuid") == uuid), None)
    if source is None:
        return {"error": f"Mod {uuid} not found in load order"}

    if before_uuid != GUSTAVX_UUID:
        target_idx = next(
            (i for i, m in enumerate(mods) if m.get("uuid") == before_uuid), None
        )
        if target_idx is None:
            return {"error": f"Target mod {before_uuid} not found in load order"}
    else:
        # "before GustavX" means position 1 (right after GustavX)
        target_idx = 1

    # Remove source, re-insert at target position
    mods = [m for m in mods if m.get("uuid") != uuid]

    # Recompute target_idx after removal (source may have been before target)
    target_idx = next(
        (i for i, m in enumerate(mods) if m.get("uuid") == before_uuid),
        len(mods),
    ) if before_uuid != GUSTAVX_UUID else 1

    mods.insert(target_idx, source)

    backup = backup_modsettings()
    if "error" in backup:
        return backup

    err = _save_mods(raw, mods)
    if err:
        return err

    return {"reordered": True, "uuid": uuid, "position": target_idx}
