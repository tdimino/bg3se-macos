"""installer.py — Mod installation / removal for bg3se-harness.

Handles the file-system work of adding and removing mods:
  - Copying PAK files into the BG3 Mods directory
  - Reading metadata from PAK archives via PakReader
  - Syncing modsettings.lsx via the modsettings module
  - Registering / unregistering mods in the JSON registry

All public functions return JSON-serialisable dicts.
Progress messages go to stderr; only final result JSON is print()ed.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Internal imports
# ---------------------------------------------------------------------------

try:
    from ..config import MODS_DIR, GUSTAVX_UUID
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from config import MODS_DIR, GUSTAVX_UUID  # type: ignore

from .pak_inspector import PakReader, PakInspectorError
from .modsettings import add_mod, remove_mod, backup_modsettings
from .registry import register_mod, unregister_mod, get_mod, load_registry


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _stderr(msg: str) -> None:
    """Write a progress line to stderr."""
    print(msg, file=sys.stderr)


def _ensure_mods_dir() -> None:
    MODS_DIR.mkdir(parents=True, exist_ok=True)


def _derive_folder(pak_path: Path, info: dict) -> str:
    """Derive the BG3 mod folder name.

    BG3 uses the folder name from meta.lsx when present.  Many mods set
    Folder equal to Name.  If meta.lsx has no useful Folder attribute we
    fall back to the PAK stem (filename without extension).
    """
    # PakReader doesn't parse the Folder attribute — only Name, UUID,
    # Author, Description, Version.  The Folder value lives in meta.lsx
    # under ModuleInfo as well, but _extract_mod_info_from_lsx only captures
    # the five fields listed above.
    #
    # Practical convention: for most well-formed mods Folder == Name.
    # Use the PAK stem as an always-available fallback.
    name = (info.get("name") or "").strip()
    if name:
        return name
    return pak_path.stem


def _read_pak_info(pak_path: Path) -> dict:
    """Open a PAK and return its mod info dict.

    Returns ``{"error": str}`` on failure.  On success the dict has keys:
    uuid, name, author, description, version, meta_path.
    """
    try:
        with PakReader(str(pak_path)) as pak:
            return pak.get_mod_info()
    except (PakInspectorError, OSError) as exc:
        return {"error": str(exc)}


def _pak_has_meta(info: dict) -> bool:
    """Return True if *info* contains a usable UUID (came from meta.lsx)."""
    return bool(info.get("uuid"))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_mod_info(source: str) -> dict:
    """Return metadata from a PAK file or installed mod without installing.

    *source* can be:
    - Path to a ``.pak`` file
    - UUID of an installed mod (looked up in the registry)
    - Name substring matched against installed mods

    Returns a dict with keys matching a registry entry plus ``"meta_path"``.
    On failure returns ``{"error": str}``.
    """
    path = Path(source)

    # Direct PAK path
    if path.suffix.lower() == ".pak" and path.exists():
        info = _read_pak_info(path)
        info.setdefault("source_path", str(path))
        return info

    # Registry lookup by UUID
    entry = get_mod(source)
    if entry:
        result = dict(entry)
        pak_path = entry.get("pak_path")
        if pak_path:
            pak_info = _read_pak_info(Path(pak_path))
            if "error" not in pak_info:
                # Merge live PAK data over stale registry data
                result.update({k: v for k, v in pak_info.items() if v is not None})
        return result

    # Fallback: search installed PAK files by name pattern
    if MODS_DIR.exists():
        lower_source = source.lower()
        for candidate in sorted(MODS_DIR.glob("*.pak")):
            if lower_source in candidate.name.lower():
                info = _read_pak_info(candidate)
                info.setdefault("source_path", str(candidate))
                return info

    return {"error": f"Mod not found: {source!r}"}


def install_local(source_path: str, enable: bool = True) -> dict:
    """Install a local ``.pak`` file or extracted mod directory.

    Steps:
    1. Validate the source exists.
    2. If a ``.pak``, read metadata via PakReader; copy to MODS_DIR.
    3. If a directory, copy the whole tree to MODS_DIR/<dirname>.
    4. If *enable* is True, add to modsettings.lsx via add_mod().
    5. Register in mod_registry.json.
    6. Return a result dict.

    Returns ``{"installed": True, "uuid": str, "name": str, "pak_path": str}``
    on success, or ``{"error": str}`` on failure.
    """
    src = Path(source_path)
    if not src.exists():
        return {"error": f"Source path does not exist: {source_path!r}"}

    _ensure_mods_dir()

    # ------------------------------------------------------------------
    # PAK file installation
    # ------------------------------------------------------------------
    if src.is_file():
        if src.suffix.lower() != ".pak":
            return {"error": f"Expected a .pak file, got: {src.name!r}"}

        _stderr(f"Reading metadata from {src.name} ...")
        info = _read_pak_info(src)
        if "error" in info:
            return {"error": f"Could not read PAK: {info['error']}"}

        if not _pak_has_meta(info):
            return {"error": f"PAK has no meta.lsx — cannot determine mod UUID: {src.name!r}"}

        uuid = info["uuid"]
        name = info.get("name") or src.stem
        folder = _derive_folder(src, info)
        version = info.get("version") or "36028797018963968"

        # Refuse to stomp GustavX
        if uuid == GUSTAVX_UUID:
            return {"error": "Cannot install GustavX as a mod — it is a system entry."}

        dest_pak = MODS_DIR / src.name
        _stderr(f"Copying {src.name} → {dest_pak} ...")
        try:
            shutil.copy2(str(src), str(dest_pak))
        except OSError as exc:
            return {"error": f"Copy failed: {exc}"}

        pak_path_str = str(dest_pak)

        # ------------------------------------------------------------------
        # modsettings.lsx
        # ------------------------------------------------------------------
        ms_result: dict = {"added": False}
        if enable:
            _stderr(f"Adding {name!r} to modsettings.lsx ...")
            ms_result = add_mod(uuid=uuid, name=name, folder=folder, version=version)
            if "error" in ms_result:
                # Clean up the copy — leave the filesystem clean on failure
                try:
                    dest_pak.unlink(missing_ok=True)
                except OSError:
                    pass
                return {"error": f"modsettings update failed: {ms_result['error']}"}

        # ------------------------------------------------------------------
        # Registry
        # ------------------------------------------------------------------
        _stderr(f"Registering {name!r} ({uuid}) ...")
        entry = register_mod(
            uuid=uuid,
            name=name,
            folder=folder,
            source_path=source_path,
            pak_path=pak_path_str,
            version=version,
            author=info.get("author"),
            description=info.get("description"),
            enabled=enable,
        )

        return {
            "installed": True,
            "uuid": uuid,
            "name": name,
            "pak_path": pak_path_str,
            "in_load_order": ms_result.get("added", False) or ms_result.get("reason") == "already present",
            "entry": entry,
        }

    # ------------------------------------------------------------------
    # Directory installation (extracted mod)
    # ------------------------------------------------------------------
    if src.is_dir():
        dest_dir = MODS_DIR / src.name
        _stderr(f"Copying directory {src.name} → {dest_dir} ...")
        try:
            if dest_dir.exists():
                shutil.rmtree(str(dest_dir))
            shutil.copytree(str(src), str(dest_dir))
        except OSError as exc:
            return {"error": f"Directory copy failed: {exc}"}

        # Try to find a meta.lsx inside the copied dir for metadata
        meta_candidates = list(dest_dir.rglob("meta.lsx"))
        uuid = None
        name = src.name
        folder = src.name
        version = "36028797018963968"
        author: str | None = None
        description: str | None = None

        if meta_candidates:
            from .pak_inspector import _extract_mod_info_from_lsx
            try:
                content = meta_candidates[0].read_bytes()
                info = _extract_mod_info_from_lsx(content)
                if info.get("uuid"):
                    uuid = info["uuid"]
                    name = info.get("name") or src.name
                    folder = name
                    version = info.get("version") or version
                    author = info.get("author")
                    description = info.get("description")
            except OSError:
                pass

        if uuid is None:
            # No meta — generate a placeholder UUID from the folder name
            import hashlib
            seed = src.name.encode("utf-8")
            h = hashlib.md5(seed).hexdigest()
            uuid = f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
            _stderr(f"WARNING: No meta.lsx found; generated synthetic UUID {uuid}")

        if uuid == GUSTAVX_UUID:
            return {"error": "Cannot install GustavX as a mod — it is a system entry."}

        ms_result = {"added": False}
        if enable:
            _stderr(f"Adding {name!r} to modsettings.lsx ...")
            ms_result = add_mod(uuid=uuid, name=name, folder=folder, version=version)
            if "error" in ms_result:
                return {"error": f"modsettings update failed: {ms_result['error']}"}

        entry = register_mod(
            uuid=uuid,
            name=name,
            folder=folder,
            source_path=source_path,
            pak_path=None,
            version=version,
            author=author,
            description=description,
            enabled=enable,
        )

        return {
            "installed": True,
            "uuid": uuid,
            "name": name,
            "pak_path": None,
            "in_load_order": ms_result.get("added", False) or ms_result.get("reason") == "already present",
            "entry": entry,
        }

    return {"error": f"Source is neither a file nor a directory: {source_path!r}"}


def uninstall(uuid_or_name: str) -> dict:
    """Remove a mod: disable in modsettings.lsx, optionally delete PAK, unregister.

    *uuid_or_name* can be an exact UUID or a name substring.  If multiple
    registry entries match the name, the first alphabetical match is used.

    Steps:
    1. Resolve UUID from registry.
    2. Backup modsettings.lsx.
    3. Remove from modsettings.lsx via remove_mod().
    4. If ``pak_path`` is set and the file exists, delete it.
    5. Unregister from mod_registry.json.

    Returns ``{"uninstalled": True, "uuid": str, "name": str}`` or
    ``{"error": str}``.
    """
    registry = load_registry()

    # Resolve UUID — try exact match first, then name substring
    uuid: str | None = None
    if uuid_or_name in registry:
        uuid = uuid_or_name
    else:
        lower = uuid_or_name.lower()
        matches = [
            u for u, e in sorted(registry.items(), key=lambda x: (x[1].get("name") or "").lower())
            if lower in (e.get("name") or "").lower()
        ]
        if len(matches) == 1:
            uuid = matches[0]
        elif len(matches) > 1:
            names = [registry[u].get("name", u) for u in matches]
            return {"error": f"Ambiguous name {uuid_or_name!r}: matched {names}. Use UUID."}

    if uuid is None:
        return {"error": f"Mod not found in registry: {uuid_or_name!r}"}

    entry = registry[uuid]
    name = entry.get("name") or uuid

    if uuid == GUSTAVX_UUID:
        return {"error": "Cannot uninstall GustavX — it is a system entry."}

    # Backup modsettings before any write
    _stderr(f"Backing up modsettings.lsx before uninstalling {name!r} ...")
    bk = backup_modsettings()
    if "error" in bk:
        # Non-fatal — modsettings may not exist yet if mod was never enabled
        _stderr(f"  (backup skipped: {bk['error']})")

    # Remove from modsettings
    _stderr(f"Removing {name!r} from modsettings.lsx ...")
    ms_result = remove_mod(uuid)
    if "error" in ms_result:
        return {"error": f"modsettings removal failed: {ms_result['error']}"}

    # Delete PAK from Mods dir if present (validate path stays under MODS_DIR)
    pak_path = entry.get("pak_path")
    pak_deleted = False
    if pak_path:
        pak_file = Path(pak_path).resolve()
        mods_root = MODS_DIR.resolve()
        if pak_file.exists() and str(pak_file).startswith(str(mods_root)) and pak_file.suffix == ".pak":
            _stderr(f"Deleting {pak_file.name} from Mods directory ...")
            try:
                pak_file.unlink()
                pak_deleted = True
            except OSError as exc:
                _stderr(f"  WARNING: Could not delete PAK: {exc}")
        elif pak_file.exists():
            _stderr(f"  WARNING: Refusing to delete {pak_file} — not under {mods_root}")

    # Unregister
    _stderr(f"Unregistering {name!r} ({uuid}) ...")
    unregister_mod(uuid)

    return {
        "uninstalled": True,
        "uuid": uuid,
        "name": name,
        "pak_deleted": pak_deleted,
        "removed_from_load_order": ms_result.get("removed", False),
    }
