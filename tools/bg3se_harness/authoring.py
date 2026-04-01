"""Mod authoring tools for macOS BG3SE development.

Scaffold new mods, lint for macOS-specific issues, and run quick smoke tests.

Usage:
    bg3se-harness author new <name>     # Scaffold mod structure
    bg3se-harness author check <path>   # Lint for issues
    bg3se-harness author smoke <path>   # Quick launch-and-test
"""

from __future__ import annotations

import json
import os
import re
import sys
import uuid
from pathlib import Path

from .config import PROJECT_ROOT


# Windows-only APIs that don't exist on macOS
WINDOWS_ONLY_APIS = [
    "Ext.ClientUI",
    "Ext.ServerUI",
    "Ext.UI.Create",
    "Ext.UI.Destroy",
    "Ext.UI.GetByName",
    "Ext.UI.GetByPath",
    "NativeModLoader",
    "Ext.Utils.LoadString",  # DLL string loading
]

# Common mistakes in SE mods
COMMON_ISSUES = [
    (r'require\s*\(\s*["\']lfs["\']', "lfs (LuaFileSystem) is not available in BG3SE"),
    (r'require\s*\(\s*["\']socket["\']', "LuaSocket is not available in BG3SE"),
    (r'os\.execute', "os.execute is sandboxed in BG3SE"),
    (r'io\.open\s*\(', "Use Ext.IO.LoadFile/SaveFile instead of io.open"),
    (r'dofile\s*\(', "dofile is not available — use Ext.Require"),
    (r'loadfile\s*\(', "loadfile is restricted — use Ext.Require"),
]


def scaffold(name, output_dir=None):
    """Create a new mod skeleton with BG3SE macOS conventions.

    Args:
        name: Mod name (e.g., "MyTestMod")
        output_dir: Where to create the mod. Defaults to PROJECT_ROOT/test-mods/
    """
    if "/" in name or "\\" in name or ".." in name:
        return {"error": f"Invalid mod name (no path separators or ..): {name}"}

    if output_dir is None:
        output_dir = PROJECT_ROOT / "test-mods"

    mod_dir = Path(output_dir) / name
    se_dir = mod_dir / "ScriptExtender"
    lua_dir = se_dir / "Lua"

    if mod_dir.exists():
        return {"error": f"Directory already exists: {mod_dir}"}

    # Create structure
    lua_dir.mkdir(parents=True)

    # Generate a UUID for the mod
    mod_uuid = str(uuid.uuid4())

    # Config.json
    config = {
        "RequiredVersion": 1,
        "ModTable": name,
        "FeatureFlags": ["Lua"],
    }
    (se_dir / "Config.json").write_text(json.dumps(config, indent=4) + "\n")

    # BootstrapServer.lua
    bootstrap = f'''-- {name} — Server-side bootstrap
-- Loaded when the game starts a session (server context)

Ext.Events.SessionLoaded:Add(function()
    Ext.Utils.Print("[{name}] Session loaded — mod is active")
end)

Ext.Events.GameStateChanged:Add(function(e)
    if e.ToState == "Running" then
        Ext.Utils.Print("[{name}] Game state: Running")
    end
end)
'''
    (lua_dir / "BootstrapServer.lua").write_text(bootstrap)

    # BootstrapClient.lua
    client_bootstrap = f'''-- {name} — Client-side bootstrap
-- Loaded on the client (UI context)

Ext.Events.SessionLoaded:Add(function()
    Ext.Utils.Print("[{name}] Client session loaded")
end)
'''
    (lua_dir / "BootstrapClient.lua").write_text(client_bootstrap)

    return {
        "success": True,
        "name": name,
        "uuid": mod_uuid,
        "path": str(mod_dir),
        "files": [
            "ScriptExtender/Config.json",
            "ScriptExtender/Lua/BootstrapServer.lua",
            "ScriptExtender/Lua/BootstrapClient.lua",
        ],
    }


def check(path):
    """Lint a mod directory for macOS-specific issues.

    Checks for:
    - Windows-only API usage
    - Missing Config.json
    - Common Lua mistakes
    - Missing FeatureFlags
    """
    mod_path = Path(path)
    if not mod_path.exists():
        return {"error": f"Path not found: {path}"}

    issues = []

    # Check Config.json
    config_path = mod_path / "ScriptExtender" / "Config.json"
    if not config_path.exists():
        issues.append({
            "severity": "error",
            "file": "ScriptExtender/Config.json",
            "message": "Missing Config.json — mod will not be detected by SE",
        })
    else:
        try:
            config = json.loads(config_path.read_text())
            if "Lua" not in config.get("FeatureFlags", []):
                issues.append({
                    "severity": "warning",
                    "file": "ScriptExtender/Config.json",
                    "message": "Missing 'Lua' in FeatureFlags — Lua scripts won't load",
                })
        except json.JSONDecodeError as e:
            issues.append({
                "severity": "error",
                "file": "ScriptExtender/Config.json",
                "message": f"Invalid JSON: {e}",
            })

    # Scan Lua files
    lua_dir = mod_path / "ScriptExtender" / "Lua"
    if not lua_dir.exists():
        lua_dir = mod_path  # Some mods have flat structure

    lua_files = list(lua_dir.rglob("*.lua"))
    if not lua_files:
        issues.append({
            "severity": "warning",
            "file": "ScriptExtender/Lua/",
            "message": "No Lua files found",
        })

    for lua_file in lua_files:
        rel_path = str(lua_file.relative_to(mod_path))
        try:
            content = lua_file.read_text(errors="replace")
        except OSError:
            continue

        # Check Windows-only APIs
        for api in WINDOWS_ONLY_APIS:
            if api in content:
                issues.append({
                    "severity": "error",
                    "file": rel_path,
                    "message": f"Windows-only API: {api} — not available on macOS",
                    "line": _find_line(content, api),
                })

        # Check common mistakes
        for pattern, message in COMMON_ISSUES:
            match = re.search(pattern, content)
            if match:
                line_num = content[:match.start()].count("\n") + 1
                issues.append({
                    "severity": "warning",
                    "file": rel_path,
                    "message": message,
                    "line": line_num,
                })

    errors = sum(1 for i in issues if i["severity"] == "error")
    warnings = sum(1 for i in issues if i["severity"] == "warning")

    return {
        "path": str(mod_path),
        "issues": issues,
        "error_count": errors,
        "warning_count": warnings,
        "clean": len(issues) == 0,
    }


def _find_line(content, text):
    """Find the line number of text in content."""
    idx = content.find(text)
    if idx < 0:
        return 0
    return content[:idx].count("\n") + 1


# ============================================================================
# CLI handler
# ============================================================================

def cmd_author(args):
    """CLI handler for author subcommands."""
    subcmd = args.author_command

    if subcmd == "new":
        result = scaffold(args.name)
        print(json.dumps(result, indent=2))
        return 0 if result.get("success") else 1

    elif subcmd == "check":
        result = check(args.path)
        print(json.dumps(result, indent=2))
        return 0 if result.get("clean") else 1

    return 1
