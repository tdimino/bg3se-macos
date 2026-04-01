"""Prerequisite verifier for bg3se-harness.

Checks that all required paths, permissions, and tools are available.
Reports actionable diagnostics as JSON.

Usage:
    bg3se-harness doctor
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from .config import (
    BG3_APP_BUNDLE, BG3_EXEC, DEPLOYED_DYLIB, HARNESS_CONFIG_DIR,
    INSERT_DYLIB, MODS_DIR, MODSETTINGS_PATH, SAVES_DIR, SOCKET_PATH,
    PROJECT_ROOT,
)
from . import launch as launch_mod
from . import patch as patch_mod


def _check(name, passed, detail=None, fix=None):
    """Build a check result dict."""
    result = {"name": name, "passed": passed}
    if detail:
        result["detail"] = detail
    if fix and not passed:
        result["fix"] = fix
    return result


def run_doctor():
    """Run all diagnostic checks. Returns dict with checks array and summary."""
    checks = []

    # 1. BG3 app bundle
    checks.append(_check(
        "bg3_app_bundle",
        BG3_APP_BUNDLE.exists(),
        detail=str(BG3_APP_BUNDLE),
        fix="Install BG3 via Steam",
    ))

    # 2. BG3 binary
    checks.append(_check(
        "bg3_binary",
        BG3_EXEC.exists(),
        detail=str(BG3_EXEC),
    ))

    # 3. SE dylib built
    dylib_built = (PROJECT_ROOT / "build/lib/libbg3se.dylib").exists()
    checks.append(_check(
        "se_dylib_built",
        dylib_built,
        fix="Run: bg3se-harness build",
    ))

    # 4. SE dylib deployed
    checks.append(_check(
        "se_dylib_deployed",
        DEPLOYED_DYLIB.exists(),
        detail=str(DEPLOYED_DYLIB),
        fix="Run: bg3se-harness build (auto-deploys)",
    ))

    # 5. Binary patched
    patched = False
    try:
        patched = patch_mod.is_patched()
    except Exception:
        pass
    checks.append(_check(
        "binary_patched",
        patched,
        fix="Run: bg3se-harness patch",
    ))

    # 6. insert_dylib available
    checks.append(_check(
        "insert_dylib",
        INSERT_DYLIB.exists(),
        detail=str(INSERT_DYLIB),
        fix="Build insert_dylib from tools/vendor/insert_dylib/",
    ))

    # 7. Mods directory
    checks.append(_check(
        "mods_directory",
        MODS_DIR.exists(),
        detail=str(MODS_DIR),
        fix="Launch BG3 at least once to create Larian directories",
    ))

    # 8. modsettings.lsx
    modsettings_ok = MODSETTINGS_PATH.exists()
    checks.append(_check(
        "modsettings_lsx",
        modsettings_ok,
        detail=str(MODSETTINGS_PATH),
        fix="Launch BG3 at least once",
    ))

    # 9. Save directory
    checks.append(_check(
        "save_directory",
        SAVES_DIR.exists(),
        detail=str(SAVES_DIR),
    ))

    # 10. Harness config dir writable
    try:
        HARNESS_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        test_file = HARNESS_CONFIG_DIR / ".doctor_test"
        test_file.write_text("ok")
        test_file.unlink()
        config_ok = True
    except OSError:
        config_ok = False
    checks.append(_check(
        "harness_config_writable",
        config_ok,
        detail=str(HARNESS_CONFIG_DIR),
    ))

    # 11. Game running?
    game_running = launch_mod.is_running()
    checks.append(_check(
        "game_running",
        game_running,
        detail="BG3 process detected" if game_running else "BG3 not running",
    ))

    # 12. Socket alive?
    socket_alive = launch_mod.socket_alive()
    checks.append(_check(
        "se_socket",
        socket_alive,
        detail=SOCKET_PATH,
    ))

    # 13. Accessibility permission (for menu automation)
    accessibility_ok = False
    try:
        result = subprocess.run(
            ["osascript", "-e",
             'tell application "System Events" to get name of first process'],
            capture_output=True, text=True, timeout=5,
        )
        accessibility_ok = result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        pass
    checks.append(_check(
        "accessibility_permission",
        accessibility_ok,
        fix="System Settings > Privacy & Security > Accessibility > enable terminal app",
    ))

    # 14. BG3MacModManager installed?
    mmgr_installed = False
    mmgr_detail = "Not found"
    for app_dir in [Path.home() / "Applications", Path("/Applications")]:
        mmgr_path = app_dir / "BG3 Mac Mod Manager.app"
        if mmgr_path.exists():
            mmgr_installed = True
            mmgr_detail = str(mmgr_path)
            break
    checks.append(_check(
        "bg3macmodmanager",
        mmgr_installed,
        detail=mmgr_detail,
        fix="Optional: https://github.com/ShaiLaric/BG3MacModManager",
    ))

    # 15. NoLauncher defaults set?
    nolauncher = False
    try:
        result = subprocess.run(
            ["defaults", "read", "com.larian.bg3", "NoLauncher"],
            capture_output=True, text=True,
        )
        nolauncher = result.stdout.strip() == "1"
    except OSError:
        pass
    checks.append(_check(
        "no_launcher_bypass",
        nolauncher,
        fix="Run: defaults write com.larian.bg3 NoLauncher 1",
    ))

    # Summary
    passed = sum(1 for c in checks if c["passed"])
    total = len(checks)

    return {
        "checks": checks,
        "passed": passed,
        "total": total,
        "all_passed": passed == total,
    }


def cmd_doctor(args):
    """CLI handler for doctor command."""
    result = run_doctor()
    print(json.dumps(result, indent=2))

    # Also print human-readable summary to stderr
    for check in result["checks"]:
        icon = "OK" if check["passed"] else "FAIL"
        line = f"  [{icon}] {check['name']}"
        if "detail" in check:
            line += f" — {check['detail']}"
        print(line, file=sys.stderr)
        if not check["passed"] and "fix" in check:
            print(f"         Fix: {check['fix']}", file=sys.stderr)

    print(f"\n  {result['passed']}/{result['total']} checks passed", file=sys.stderr)
    return 0
