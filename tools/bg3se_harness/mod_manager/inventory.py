"""Installed mod inventory and registry reconciliation helpers."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from ..config import MODS_DIR, MOD_REGISTRY_PATH
from .modsettings import read_mod_order
from .pak_inspector import PakInspectorError, PakReader
from .registry import load_registry, save_registry


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _folder_from_meta_path(meta_path: str | None) -> str | None:
    if not meta_path:
        return None
    parts = meta_path.replace("\\", "/").split("/")
    if len(parts) >= 3 and parts[0].lower() == "mods" and parts[-1].lower() == "meta.lsx":
        return parts[1]
    return None


def _normalise_pak_info(pak_path: Path, info: dict, se_mod: bool) -> dict:
    meta_folder = _folder_from_meta_path(info.get("meta_path"))
    name = info.get("name") or pak_path.stem
    folder = info.get("folder") or meta_folder or name or pak_path.stem
    uuid = info.get("uuid")
    status = "ok" if uuid else "error"
    issues = []
    if not uuid:
        issues.append("missing_uuid")
    if not info.get("meta_path"):
        issues.append("missing_meta_lsx")

    return {
        "pak_path": str(pak_path),
        "pak_name": pak_path.name,
        "status": status,
        "issues": issues,
        "uuid": uuid,
        "name": name,
        "folder": folder,
        "version": info.get("version"),
        "author": info.get("author"),
        "description": info.get("description"),
        "dependencies": info.get("dependencies") or [],
        "se_mod": bool(se_mod),
        "meta_path": info.get("meta_path"),
    }


def scan_installed_paks(mods_dir: Path | None = None) -> dict:
    """Scan BG3's Mods directory and return installed PAK metadata."""
    root = Path(mods_dir) if mods_dir is not None else MODS_DIR
    report = {
        "mods_dir": str(root),
        "exists": root.exists(),
        "mods": [],
        "duplicates": {"uuid": [], "folder": []},
        "summary": {
            "pak_count": 0,
            "ok_count": 0,
            "error_count": 0,
        },
    }
    if not root.exists():
        report["error"] = f"Mods directory not found: {root}"
        return report

    mods = []
    for pak_path in sorted(root.glob("*.pak"), key=lambda p: p.name.lower()):
        try:
            with PakReader(str(pak_path)) as pak:
                info = pak.get_mod_info()
                entry = _normalise_pak_info(
                    pak_path,
                    info,
                    se_mod=pak.contains_script_extender(),
                )
        except (PakInspectorError, OSError, RuntimeError) as exc:
            entry = {
                "pak_path": str(pak_path),
                "pak_name": pak_path.name,
                "status": "error",
                "issues": ["read_error"],
                "error": str(exc),
                "uuid": None,
                "name": pak_path.stem,
                "folder": pak_path.stem,
                "version": None,
                "author": None,
                "description": None,
                "dependencies": [],
                "se_mod": False,
                "meta_path": None,
            }
        mods.append(entry)

    report["mods"] = mods
    report["summary"]["pak_count"] = len(mods)
    report["summary"]["ok_count"] = sum(1 for mod in mods if mod.get("status") == "ok")
    report["summary"]["error_count"] = sum(1 for mod in mods if mod.get("status") != "ok")
    report["duplicates"] = _find_duplicates(mods)
    return report


def _find_duplicates(mods: list[dict]) -> dict:
    by_uuid: dict[str, list[dict]] = defaultdict(list)
    by_folder: dict[str, list[dict]] = defaultdict(list)
    for mod in mods:
        uuid = mod.get("uuid")
        folder = mod.get("folder")
        if uuid:
            by_uuid[uuid].append(mod)
        if folder:
            by_folder[folder.lower()].append(mod)

    def pack(groups: dict[str, list[dict]]) -> list[dict]:
        result = []
        for key, entries in sorted(groups.items()):
            if len(entries) <= 1:
                continue
            result.append({
                "key": key,
                "mods": [
                    {
                        "pak_name": entry.get("pak_name"),
                        "uuid": entry.get("uuid"),
                        "name": entry.get("name"),
                        "folder": entry.get("folder"),
                    }
                    for entry in entries
                ],
            })
        return result

    return {"uuid": pack(by_uuid), "folder": pack(by_folder)}


def _active_mod_order() -> tuple[list[dict], dict | None]:
    order = read_mod_order()
    if order and isinstance(order[0], dict) and "error" in order[0]:
        return [], order[0]
    return order, None


def reconcile_registry(*, write: bool = False, mods_dir: Path | None = None) -> dict:
    """Compare installed PAKs with the JSON registry, optionally writing entries."""
    scan = scan_installed_paks(mods_dir=mods_dir)
    registry = load_registry()
    installed = [mod for mod in scan.get("mods", []) if mod.get("uuid")]
    installed_by_uuid = {mod["uuid"]: mod for mod in installed}

    active_order, active_error = _active_mod_order()
    active_uuids = {mod.get("uuid") for mod in active_order if mod.get("uuid")}

    registered_uuids = set(registry)
    installed_uuids = set(installed_by_uuid)
    missing_registry = sorted(installed_uuids - registered_uuids)
    registry_orphans = sorted(
        uuid for uuid, entry in registry.items()
        if uuid not in installed_uuids and entry.get("pak_path")
    )

    written = []
    if write and missing_registry:
        now = _utc_now()
        updated = dict(registry)
        for uuid in missing_registry:
            mod = installed_by_uuid[uuid]
            existing = updated.get(uuid, {})
            entry = {
                **existing,
                "uuid": uuid,
                "name": mod.get("name") or uuid,
                "folder": mod.get("folder") or mod.get("name") or uuid,
                "source_path": mod.get("pak_path"),
                "pak_path": mod.get("pak_path"),
                "enabled": existing.get("enabled", uuid in active_uuids),
                "se_mod": mod.get("se_mod", False),
                "version": mod.get("version"),
                "author": mod.get("author"),
                "description": mod.get("description"),
                "dependencies": mod.get("dependencies") or [],
                "meta_path": mod.get("meta_path"),
                "installed": True,
                "registry_source": "installed_pak_scan",
                "reconciled_at": now,
            }
            updated[uuid] = entry
            written.append(uuid)
        save_registry(updated)
        registry = updated

    return {
        "registry_path": str(MOD_REGISTRY_PATH),
        "write": write,
        "scan": scan,
        "modsettings": {
            "error": active_error,
            "active_count": len(active_order),
            "active_uuids": sorted(active_uuids),
        },
        "summary": {
            "installed_count": len(installed),
            "registered_count": len(registry),
            "installed_registered_count": len(installed_uuids & set(registry)),
            "installed_unregistered_count": len(missing_registry),
            "registry_orphan_count": len(registry_orphans),
            "written_count": len(written),
        },
        "installed_unregistered": [
            installed_by_uuid[uuid] for uuid in missing_registry
        ],
        "registry_orphans": [
            {"uuid": uuid, **registry.get(uuid, {})}
            for uuid in registry_orphans
        ],
        "written": written,
    }


def preflight_mod_state(
    *,
    accept_mod_verification: bool = False,
    mods_dir: Path | None = None,
) -> dict:
    """Check whether the current mod state is safe enough to launch a save."""
    scan = scan_installed_paks(mods_dir=mods_dir)
    registry = load_registry()
    active_order, active_error = _active_mod_order()

    installed_by_uuid = {
        mod["uuid"]: mod
        for mod in scan.get("mods", [])
        if mod.get("uuid")
    }
    issues = []
    warnings = []

    if active_error:
        issues.append({
            "code": "modsettings_unreadable",
            "message": active_error.get("error", "Could not read modsettings.lsx"),
        })

    for duplicate in scan.get("duplicates", {}).get("uuid", []):
        issues.append({
            "code": "duplicate_installed_uuid",
            "message": f"Duplicate installed mod UUID: {duplicate['key']}",
            "details": duplicate,
        })

    for duplicate in scan.get("duplicates", {}).get("folder", []):
        warnings.append({
            "code": "duplicate_installed_folder",
            "message": f"Duplicate installed mod folder: {duplicate['key']}",
            "details": duplicate,
        })

    for mod in scan.get("mods", []):
        if mod.get("status") != "ok":
            warnings.append({
                "code": "pak_scan_error",
                "message": f"Could not fully inspect {mod.get('pak_name')}",
                "details": mod,
            })

    for mod in active_order:
        uuid = mod.get("uuid")
        name = mod.get("name") or mod.get("folder") or uuid
        if not uuid:
            continue
        if name == "GustavX" or mod.get("folder") == "GustavX":
            continue
        if uuid not in installed_by_uuid:
            issues.append({
                "code": "active_mod_not_installed",
                "message": f"Active mod is not present in installed PAK scan: {name}",
                "uuid": uuid,
                "mod": mod,
            })
        if uuid not in registry:
            issues.append({
                "code": "active_mod_unregistered",
                "message": f"Active mod is not known to the harness registry: {name}",
                "uuid": uuid,
                "mod": mod,
            })

    blocking = bool(issues) and not accept_mod_verification
    return {
        "success": not blocking,
        "blocking": blocking,
        "accept_mod_verification": accept_mod_verification,
        "issues": issues,
        "warnings": warnings,
        "summary": {
            "installed_paks": scan.get("summary", {}).get("pak_count", 0),
            "installed_ok": scan.get("summary", {}).get("ok_count", 0),
            "registered": len(registry),
            "active": len(active_order),
            "issue_count": len(issues),
            "warning_count": len(warnings),
        },
        "remediation": [
            "PYTHONPATH=tools python3 -m bg3se_harness mod scan --installed",
            "PYTHONPATH=tools python3 -m bg3se_harness mod reconcile --installed --write",
            "Re-run launch/test after modsettings.lsx matches the save-required mod list.",
        ],
    }


def verify_modsettings(
    *,
    save_name: str | None = None,
    continue_latest: bool = False,
    expected_order_path: str | None = None,
) -> dict:
    """Verify active modsettings entries against registry/install/save state."""
    registry = load_registry()
    scan = scan_installed_paks()
    installed_by_uuid = {
        mod["uuid"]: mod
        for mod in scan.get("mods", [])
        if mod.get("uuid")
    }
    active_order, active_error = _active_mod_order()
    issues = []
    warnings = []

    if active_error:
        issues.append({
            "code": "modsettings_unreadable",
            "message": active_error.get("error", "Could not read modsettings.lsx"),
        })
        active_order = []

    if active_order:
        first = active_order[0]
        if not (first.get("name") == "GustavX" or first.get("folder") == "GustavX"):
            issues.append({
                "code": "gustavx_not_first",
                "message": "GustavX must be the first modsettings entry",
                "first": first,
            })

    seen = set()
    for index, mod in enumerate(active_order):
        uuid = mod.get("uuid")
        name = mod.get("name") or mod.get("folder") or uuid
        is_base = mod.get("name") == "GustavX" or mod.get("folder") == "GustavX"
        if not uuid:
            issues.append({
                "code": "active_mod_missing_uuid",
                "message": f"Active mod at index {index} has no UUID",
                "mod": mod,
            })
            continue
        if uuid in seen:
            issues.append({
                "code": "duplicate_active_uuid",
                "message": f"Duplicate active mod UUID: {uuid}",
                "uuid": uuid,
                "mod": mod,
            })
        seen.add(uuid)
        if is_base:
            continue
        reg = registry.get(uuid)
        installed = installed_by_uuid.get(uuid)
        if not reg:
            issues.append({
                "code": "active_mod_unregistered",
                "message": f"Active mod is not registered: {name}",
                "uuid": uuid,
                "mod": mod,
            })
            continue
        if not installed:
            issues.append({
                "code": "active_mod_not_installed",
                "message": f"Active mod is not installed as a readable PAK: {name}",
                "uuid": uuid,
                "mod": mod,
            })
        for field in ("folder", "version"):
            expected = reg.get(field) or (installed or {}).get(field)
            actual = mod.get(field)
            if expected and actual and str(expected) != str(actual):
                issues.append({
                    "code": f"active_mod_{field}_mismatch",
                    "message": f"Active mod {field} differs from registry: {name}",
                    "uuid": uuid,
                    "expected": expected,
                    "actual": actual,
                    "mod": mod,
                })

    expected_order = None
    if expected_order_path:
        try:
            data = json.loads(Path(expected_order_path).read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data = data.get("order") or data.get("mods") or data.get("uuids")
            if not isinstance(data, list):
                raise ValueError("expected order file must contain a JSON list")
            expected_order = [str(item) for item in data]
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            issues.append({
                "code": "expected_order_unreadable",
                "message": str(exc),
                "path": expected_order_path,
            })

    if expected_order is not None:
        active_ids = [mod.get("uuid") for mod in active_order]
        if active_ids != expected_order:
            issues.append({
                "code": "modsettings_order_mismatch",
                "message": "Active modsettings UUID order does not match expected order",
                "expected": expected_order,
                "actual": active_ids,
            })

    save_report = None
    if save_name or continue_latest:
        from ..savegames import save_mods
        save_report = save_mods(save_name, continue_latest=continue_latest)
        required_uuids = {
            mod.get("uuid")
            for mod in save_report.get("required_mods", [])
            if mod.get("uuid")
        }
        active_uuids = {mod.get("uuid") for mod in active_order if mod.get("uuid")}
        for uuid in sorted(required_uuids - active_uuids):
            required = next(
                (mod for mod in save_report.get("required_mods", []) if mod.get("uuid") == uuid),
                {"uuid": uuid},
            )
            issues.append({
                "code": "save_required_mod_inactive",
                "message": f"Save-required mod is not active: {required.get('name') or uuid}",
                "uuid": uuid,
                "required": required,
            })
        for uuid in sorted(active_uuids - required_uuids):
            mod = next((m for m in active_order if m.get("uuid") == uuid), {"uuid": uuid})
            if mod.get("name") == "GustavX" or mod.get("folder") == "GustavX":
                continue
            warnings.append({
                "code": "active_mod_not_detected_in_save",
                "message": f"Active mod was not detected in save markers: {mod.get('name') or uuid}",
                "uuid": uuid,
                "mod": mod,
            })

    return {
        "success": not issues,
        "issues": issues,
        "warnings": warnings,
        "summary": {
            "active_count": len(active_order),
            "registered_count": len(registry),
            "installed_count": len(installed_by_uuid),
            "issue_count": len(issues),
            "warning_count": len(warnings),
        },
        "active_order": active_order,
        "expected_order": expected_order,
        "save": save_report,
    }


def dumps(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)
