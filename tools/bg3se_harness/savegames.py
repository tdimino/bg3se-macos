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
import shutil
import sys
import time
from pathlib import Path

from .config import SAVES_DIR, SAVE_FIXTURES_DIR


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

    # Remove previous restore if it exists
    if dest.exists():
        shutil.rmtree(str(dest))

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

    return 1
