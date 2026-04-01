"""Windows BG3SE parity audit.

Compares the live Ext.* API surface against a static Windows baseline,
or performs offline analysis of the baseline to report known gaps.

Usage:
    bg3se-harness parity scan       # Live scan (requires running game)
    bg3se-harness parity missing    # Offline: list known gaps from baseline
    bg3se-harness parity verify <ns> # Deep-verify a namespace via Lua probes
"""

from __future__ import annotations

import json
import sys

from .config import CATALOG_DIR
from .console import Console


def _load_baseline():
    """Load the Windows parity baseline JSON."""
    path = CATALOG_DIR / "windows_parity_baseline.json"
    if not path.exists():
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def scan():
    """Live scan: enumerate Ext table from running game and compare to baseline.

    Requires a running game with SE socket connected.
    """
    baseline = _load_baseline()
    if not baseline:
        return {"error": "Baseline file not found at catalog/windows_parity_baseline.json"}

    # Enumerate live Ext table via console
    lua_code = """
local result = {}
for k, v in pairs(Ext) do
    if type(v) == "table" then
        local funcs = {}
        for fk, fv in pairs(v) do
            if type(fv) == "function" then
                table.insert(funcs, fk)
            end
        end
        table.sort(funcs)
        result[k] = funcs
    elseif type(v) == "function" then
        if not result["_toplevel"] then result["_toplevel"] = {} end
        table.insert(result["_toplevel"], k)
    end
end
Ext.Print(Ext.Json.Stringify(result))
"""
    try:
        with Console() as c:
            raw = c.send(lua_code)
    except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
        return {"error": f"Socket connection failed: {e}. Is the game running with SE?"}

    # Parse live data
    try:
        import re
        cleaned = re.sub(r'\033\[[0-9;]*m', '', raw).strip()
        # Find the JSON in the output (may have prompts around it)
        start = cleaned.find("{")
        end = cleaned.rfind("}") + 1
        if start < 0 or end <= start:
            return {"error": "Could not parse Ext table from game", "raw": cleaned[:500]}
        live_data = json.loads(cleaned[start:end])
    except (json.JSONDecodeError, ValueError) as e:
        return {"error": f"JSON parse error: {e}", "raw": raw[:500]}

    # Compare against baseline
    namespaces = {}
    total_expected = 0
    total_found = 0
    total_missing = 0

    for ns_name, ns_info in baseline.get("namespaces", {}).items():
        # Map baseline namespace to live key
        # Baseline uses "Ext.Stats", live data uses "Stats"
        live_key = ns_name.replace("Ext.", "").replace("Net.", "")

        expected_funcs = set(ns_info.get("functions", []))
        live_funcs = set(live_data.get(live_key, []))

        found = expected_funcs & live_funcs
        missing = expected_funcs - live_funcs
        extra = live_funcs - expected_funcs

        total_expected += len(expected_funcs)
        total_found += len(found)
        total_missing += len(missing)

        status = ns_info.get("status", "unknown")
        namespaces[ns_name] = {
            "status": status,
            "expected": len(expected_funcs),
            "found": len(found),
            "missing": sorted(missing) if missing else [],
            "extra": sorted(extra) if extra else [],
            "owner_file": ns_info.get("owner_file", ""),
        }

    parity_pct = round(total_found / total_expected * 100, 1) if total_expected else 0

    return {
        "parity_percent": parity_pct,
        "total_expected": total_expected,
        "total_found": total_found,
        "total_missing": total_missing,
        "namespaces": namespaces,
        "game_version": baseline.get("known_version", "unknown"),
    }


def missing():
    """Offline: list functions marked as missing or partial in the baseline."""
    baseline = _load_baseline()
    if not baseline:
        return {"error": "Baseline file not found"}

    gaps = []
    for ns_name, ns_info in baseline.get("namespaces", {}).items():
        status = ns_info.get("status", "unknown")
        if status in ("partial", "missing", "stub"):
            gaps.append({
                "namespace": ns_name,
                "status": status,
                "functions": ns_info.get("functions", []),
                "notes": ns_info.get("notes", ""),
                "owner_file": ns_info.get("owner_file", ""),
            })

    # Summary stats
    total_ns = len(baseline.get("namespaces", {}))
    complete = sum(1 for ns in baseline.get("namespaces", {}).values()
                   if ns.get("status") == "complete")

    return {
        "gaps": gaps,
        "gap_count": len(gaps),
        "total_namespaces": total_ns,
        "complete_namespaces": complete,
    }


def verify(namespace):
    """Deep-verify a namespace by running Lua probes.

    Requires running game with SE socket.
    """
    baseline = _load_baseline()
    if not baseline:
        return {"error": "Baseline file not found"}

    ns_key = namespace if namespace.startswith("Ext.") else f"Ext.{namespace}"
    ns_info = baseline.get("namespaces", {}).get(ns_key)
    if not ns_info:
        available = sorted(baseline.get("namespaces", {}).keys())
        return {"error": f"Namespace '{ns_key}' not found in baseline", "available": available}

    # Build probes for each expected function
    functions = ns_info.get("functions", [])
    live_key = ns_key.replace("Ext.", "")

    lua_probes = []
    for func in functions:
        lua_probes.append(
            f'table.insert(results, {{name="{func}", '
            f'exists=type(Ext.{live_key}) == "table" and type(Ext.{live_key}.{func}) == "function"}})'
        )

    lua_code = f"""
local results = {{}}
{chr(10).join(lua_probes)}
Ext.Print(Ext.Json.Stringify(results))
"""

    try:
        with Console() as c:
            raw = c.send(lua_code)
    except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
        return {"error": f"Socket connection failed: {e}"}

    # Parse results
    try:
        import re
        cleaned = re.sub(r'\033\[[0-9;]*m', '', raw).strip()
        start = cleaned.find("[")
        end = cleaned.rfind("]") + 1
        if start < 0 or end <= start:
            return {"error": "Could not parse probe results", "raw": cleaned[:500]}
        probe_results = json.loads(cleaned[start:end])
    except (json.JSONDecodeError, ValueError) as e:
        return {"error": f"JSON parse error: {e}"}

    verified = []
    missing_funcs = []
    for probe in probe_results:
        if probe.get("exists"):
            verified.append(probe["name"])
        else:
            missing_funcs.append(probe["name"])

    return {
        "namespace": ns_key,
        "verified": len(verified),
        "missing": len(missing_funcs),
        "total": len(functions),
        "verified_functions": verified,
        "missing_functions": missing_funcs,
        "owner_file": ns_info.get("owner_file", ""),
    }


# ============================================================================
# CLI handler
# ============================================================================

def cmd_parity(args):
    """CLI handler for parity subcommands."""
    subcmd = args.parity_command

    if subcmd == "scan":
        result = scan()
        print(json.dumps(result, indent=2))
        return 0 if "error" not in result else 1

    elif subcmd == "missing":
        result = missing()
        print(json.dumps(result, indent=2))
        return 0 if "error" not in result else 1

    elif subcmd == "verify":
        result = verify(args.namespace)
        print(json.dumps(result, indent=2))
        return 0 if "error" not in result else 1

    return 1
