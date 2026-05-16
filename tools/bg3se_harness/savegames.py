"""BG3 save game management for deterministic testing.

Provides save listing, snapshot/restore as named fixtures, and cloning.
Fixtures are stored outside the game's save directory to avoid Steam Cloud
interference and BG3's own save management.

Usage:
    bg3se-harness save list
    bg3se-harness save snapshot <name> [--source SAVE_DIR_NAME]
    bg3se-harness save restore <name>
    bg3se-harness save clone <src> <dst>
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

from .config import SAVES_DIR, SAVE_FIXTURES_DIR
from .mod_manager.pak_inspector import PakInspectorError, PakReader


def _ensure_fixtures_dir():
    SAVE_FIXTURES_DIR.mkdir(parents=True, exist_ok=True)


def _safe_name(name, context="name"):
    """Validate a name contains no path separators or traversal."""
    if not name or "/" in name or "\\" in name or ".." in name:
        return None
    return name


def _save_dirs():
    """List save game directories sorted by modification time (newest first)."""
    if not SAVES_DIR.exists():
        return []
    dirs = []
    for entry in SAVES_DIR.iterdir():
        if entry.is_dir() and not entry.name.startswith("."):
            dirs.append(entry)
    dirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
    return dirs


def _save_info(save_dir):
    """Extract info from a save directory."""
    stat = save_dir.stat()
    name = save_dir.name
    # BG3 save names: "CharName-TIMESTAMP__DisplayName" or "CharName-TIMESTAMP__AutoSave_N"
    display_name = name
    if "__" in name:
        display_name = name.split("__", 1)[1]

    # Calculate total size
    total_size = sum(f.stat().st_size for f in save_dir.rglob("*") if f.is_file())

    return {
        "dir_name": name,
        "display_name": display_name,
        "path": str(save_dir),
        "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
        "modified_ts": stat.st_mtime,
        "size_bytes": total_size,
        "size_mb": round(total_size / (1024 * 1024), 1),
    }


def _find_save_dir(name=None, *, continue_latest=False):
    """Resolve a save by directory name/display substring, or latest save."""
    dirs = _save_dirs()
    if continue_latest or not name:
        return dirs[0] if dirs else None

    if _safe_name(name):
        exact = SAVES_DIR / name
        if exact.exists() and exact.is_dir():
            return exact

    needle = name.lower()
    matches = [
        save_dir for save_dir in dirs
        if needle in save_dir.name.lower()
        or needle in _save_info(save_dir)["display_name"].lower()
    ]
    if len(matches) == 1:
        return matches[0]
    return None


def _save_lsv_path(save_dir):
    lsvs = sorted(save_dir.glob("*.lsv"), key=lambda p: p.name.lower())
    return lsvs[0] if lsvs else None


def _ascii_strings(data, min_len=4):
    pattern = rb"[\x20-\x7e]{%d,}" % min_len
    return [
        match.group(0).decode("utf-8", errors="replace")
        for match in re.finditer(pattern, data)
    ]


def _load_known_mods():
    """Return registry mods plus installed scan metadata keyed by UUID."""
    from .mod_manager.inventory import scan_installed_paks
    from .mod_manager.registry import load_registry

    known = {}
    for uuid, entry in load_registry().items():
        if uuid:
            known[uuid] = dict(entry)
    for mod in scan_installed_paks().get("mods", []):
        uuid = mod.get("uuid")
        if not uuid:
            continue
        merged = dict(known.get(uuid, {}))
        merged.update({k: v for k, v in mod.items() if v not in (None, "", [])})
        known[uuid] = merged
    return known


def _scan_archive_for_mod_markers(lsv_path, known_mods):
    """Search decompressed save entries for known mod UUID/name/folder markers."""
    markers = {
        uuid: {
            "uuid": uuid,
            "name": mod.get("name"),
            "folder": mod.get("folder"),
            "version": mod.get("version"),
            "markers": [],
            "sources": [],
            "first_seen": None,
        }
        for uuid, mod in known_mods.items()
    }

    scanned_files = []
    unreadable_files = []

    try:
        with PakReader(str(lsv_path)) as pak:
            files = pak.list_files()
            for file_name in files:
                if file_name.lower().endswith((".webp", ".png", ".jpg", ".jpeg")):
                    continue
                try:
                    data = pak.read_file(file_name)
                except (KeyError, PakInspectorError, RuntimeError) as exc:
                    unreadable_files.append({"file": file_name, "error": str(exc)})
                    continue
                scanned_files.append(file_name)
                lower = data.lower()
                for uuid, mod in known_mods.items():
                    search_terms = []
                    for kind in ("uuid", "folder", "name"):
                        value = mod.get(kind)
                        if value:
                            search_terms.append((kind, str(value)))
                    for kind, term in search_terms:
                        encoded = term.encode("utf-8", errors="ignore").lower()
                        if not encoded or encoded not in lower:
                            continue
                        offset = lower.find(encoded)
                        marker = {
                            "kind": kind,
                            "value": term,
                            "file": file_name,
                            "offset": offset,
                        }
                        if marker not in markers[uuid]["markers"]:
                            markers[uuid]["markers"].append(marker)
                            markers[uuid]["sources"].append(file_name)
                        first_seen = markers[uuid]["first_seen"]
                        order_key = (files.index(file_name), offset)
                        if first_seen is None or order_key < tuple(first_seen):
                            markers[uuid]["first_seen"] = list(order_key)
    except (PakInspectorError, OSError, RuntimeError) as exc:
        return {
            "error": str(exc),
            "scanned_files": scanned_files,
            "unreadable_files": unreadable_files,
            "mods": [],
        }

    found = [
        {
            **entry,
            "sources": sorted(set(entry["sources"])),
            "confidence": (
                "high" if any(m["kind"] in ("uuid", "folder") for m in entry["markers"])
                else "low"
            ),
        }
        for entry in markers.values()
        if entry["markers"]
    ]
    found.sort(key=lambda item: tuple(item["first_seen"] or [999999, 999999]))
    return {
        "scanned_files": scanned_files,
        "unreadable_files": unreadable_files,
        "mods": found,
    }


def _read_save_info_json(lsv_path):
    try:
        with PakReader(str(lsv_path)) as pak:
            data = pak.read_file("SaveInfo.json")
    except (KeyError, PakInspectorError, OSError, RuntimeError) as exc:
        return {"error": str(exc)}
    try:
        return json.loads(data.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        return {"error": f"SaveInfo.json parse error: {exc}"}


def _fixture_dirs():
    """List fixture directories."""
    _ensure_fixtures_dir()
    dirs = []
    for entry in SAVE_FIXTURES_DIR.iterdir():
        if entry.is_dir() and not entry.name.startswith("."):
            dirs.append(entry)
    dirs.sort(key=lambda d: d.name)
    return dirs


# ============================================================================
# Public API
# ============================================================================

def list_saves():
    """List available save games with metadata."""
    if not SAVES_DIR.exists():
        return {"error": f"Save directory not found: {SAVES_DIR}", "saves": []}

    saves = [_save_info(d) for d in _save_dirs()]
    return {"saves": saves, "count": len(saves), "path": str(SAVES_DIR)}


def list_fixtures():
    """List available save fixtures."""
    fixtures = []
    for d in _fixture_dirs():
        stat = d.stat()
        total_size = sum(f.stat().st_size for f in d.rglob("*") if f.is_file())
        fixtures.append({
            "name": d.name,
            "path": str(d),
            "created": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
            "size_mb": round(total_size / (1024 * 1024), 1),
        })
    return {"fixtures": fixtures, "count": len(fixtures), "path": str(SAVE_FIXTURES_DIR)}


def snapshot(fixture_name, source_dir_name=None):
    """Create a named fixture from a save game.

    Args:
        fixture_name: Name for the fixture (e.g., "Harness_Base_Camp")
        source_dir_name: Specific save directory name. If None, uses most recent.
    """
    if not _safe_name(fixture_name):
        return {"error": f"Invalid fixture name (no path separators or ..): {fixture_name}"}
    if source_dir_name and not _safe_name(source_dir_name):
        return {"error": f"Invalid save name (no path separators or ..): {source_dir_name}"}

    _ensure_fixtures_dir()

    # Find source save
    if source_dir_name:
        source = SAVES_DIR / source_dir_name
        if not source.exists():
            return {"error": f"Save not found: {source_dir_name}"}
    else:
        dirs = _save_dirs()
        if not dirs:
            return {"error": "No saves found"}
        source = dirs[0]

    dest = SAVE_FIXTURES_DIR / fixture_name

    # Don't overwrite without backup
    if dest.exists():
        backup_name = f"{fixture_name}.bak.{int(time.time())}"
        backup = SAVE_FIXTURES_DIR / backup_name
        shutil.move(str(dest), str(backup))
        print(f"Existing fixture backed up to {backup_name}", file=sys.stderr)

    shutil.copytree(str(source), str(dest))

    return {
        "success": True,
        "fixture": fixture_name,
        "source": source.name,
        "path": str(dest),
    }


def restore(fixture_name):
    """Restore a fixture into the game's save directory.

    Creates a backup of the current save state before restoring.
    """
    if not _safe_name(fixture_name):
        return {"error": f"Invalid fixture name (no path separators or ..): {fixture_name}"}
    fixture_path = SAVE_FIXTURES_DIR / fixture_name
    if not fixture_path.exists():
        available = [d.name for d in _fixture_dirs()]
        return {
            "error": f"Fixture not found: {fixture_name}",
            "available": available,
        }

    # Determine destination name in saves dir
    dest = SAVES_DIR / f"Harness__{fixture_name}"

    # Backup previous restore before overwriting
    if dest.exists():
        from datetime import datetime
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dest = dest.parent / f"{dest.name}__backup_{ts}"
        shutil.move(str(dest), str(backup_dest))

    shutil.copytree(str(fixture_path), str(dest))

    return {
        "success": True,
        "fixture": fixture_name,
        "restored_to": str(dest),
        "save_name": dest.name,
    }


def clone(src_name, dst_name):
    """Clone a save under a new name."""
    if not _safe_name(src_name):
        return {"error": f"Invalid source name (no path separators or ..): {src_name}"}
    if not _safe_name(dst_name):
        return {"error": f"Invalid destination name (no path separators or ..): {dst_name}"}
    # Check fixtures first, then saves
    src_path = SAVE_FIXTURES_DIR / src_name
    if not src_path.exists():
        src_path = SAVES_DIR / src_name
    if not src_path.exists():
        return {"error": f"Source not found: {src_name}"}

    dst_path = SAVE_FIXTURES_DIR / dst_name
    _ensure_fixtures_dir()

    if dst_path.exists():
        return {"error": f"Destination already exists: {dst_name}"}

    shutil.copytree(str(src_path), str(dst_path))

    return {
        "success": True,
        "source": src_name,
        "destination": dst_name,
        "path": str(dst_path),
    }


def save_mods(save_name=None, *, continue_latest=False):
    """Infer save-required mods from a .lsv archive and compare active state."""
    save_dir = _find_save_dir(save_name, continue_latest=continue_latest)
    if not save_dir:
        return {
            "success": False,
            "error": "Save not found" if save_name else "No saves found",
            "save": save_name,
        }
    lsv_path = _save_lsv_path(save_dir)
    if not lsv_path:
        return {
            "success": False,
            "error": f"No .lsv file found in {save_dir}",
            "save_dir": str(save_dir),
        }

    known_mods = _load_known_mods()
    marker_scan = _scan_archive_for_mod_markers(lsv_path, known_mods)
    save_info = _read_save_info_json(lsv_path)

    detected = marker_scan.get("mods", [])
    required = [mod for mod in detected if mod.get("confidence") == "high"]
    low_confidence = [mod for mod in detected if mod.get("confidence") != "high"]
    required_uuids = {mod["uuid"] for mod in required}

    from .mod_manager.modsettings import read_mod_order
    active_order = read_mod_order()
    if active_order and "error" in active_order[0]:
        active_mods = []
        active_error = active_order[0]
    else:
        active_mods = active_order
        active_error = None
    active_uuids = {mod.get("uuid") for mod in active_mods if mod.get("uuid")}
    base_uuids = {
        mod.get("uuid")
        for mod in active_mods
        if mod.get("name") == "GustavX" or mod.get("folder") == "GustavX"
    }

    installed_uuids = set(known_mods)
    missing_from_active = sorted(required_uuids - active_uuids)
    missing_from_installed = sorted(required_uuids - installed_uuids)
    active_extra = sorted(active_uuids - required_uuids - base_uuids)

    return {
        "success": "error" not in marker_scan,
        "save": _save_info(save_dir),
        "lsv_path": str(lsv_path),
        "method": "archive_marker_scan",
        "order_reliable": False,
        "note": (
            "BG3 save files expose mod markers in binary LSF entries, but this "
            "scanner does not prove load order. Use mod verify --modsettings "
            "to check active state."
        ),
        "save_info": save_info,
        "detected_mods": detected,
        "required_mods": required,
        "low_confidence_candidates": low_confidence,
        "required_count": len(required),
        "active_mods": active_mods,
        "active_error": active_error,
        "comparison": {
            "missing_from_active": missing_from_active,
            "missing_from_installed": missing_from_installed,
            "active_extra": active_extra,
        },
        "scan": {
            "scanned_files": marker_scan.get("scanned_files", []),
            "unreadable_files": marker_scan.get("unreadable_files", []),
            "error": marker_scan.get("error"),
        },
    }


# ============================================================================
# CLI handler
# ============================================================================

def cmd_save(args):
    """CLI handler for save subcommands."""
    subcmd = args.save_command

    if subcmd == "list":
        show_fixtures = getattr(args, "fixtures", False)
        if show_fixtures:
            result = list_fixtures()
        else:
            result = list_saves()
        print(json.dumps(result, indent=2))
        return 0

    elif subcmd == "snapshot":
        source = getattr(args, "source", None)
        result = snapshot(args.name, source_dir_name=source)
        print(json.dumps(result, indent=2))
        return 0 if result.get("success") else 1

    elif subcmd == "restore":
        result = restore(args.name)
        print(json.dumps(result, indent=2))
        return 0 if result.get("success") else 1

    elif subcmd == "clone":
        result = clone(args.src, args.dst)
        print(json.dumps(result, indent=2))
        return 0 if result.get("success") else 1

    elif subcmd == "mods":
        result = save_mods(
            getattr(args, "name", None),
            continue_latest=getattr(args, "continue_latest", False),
        )
        print(json.dumps(result, indent=2))
        return 0 if result.get("success") else 1

    return 1
