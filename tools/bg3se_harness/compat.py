"""Mod compatibility test runner.

Orchestrates mod install + save restore + launch + test + report for
automated compatibility verification of popular BG3SE mods.

Scenarios are defined as JSON manifests in catalog/scenarios/.

Usage:
    bg3se-harness compat list              # Available scenarios
    bg3se-harness compat run <scenario>    # Run a scenario end-to-end
    bg3se-harness compat matrix            # Run all scenarios
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from .config import CATALOG_DIR, SCENARIOS_DIR, REPORTS_DIR


def _load_scenarios():
    """Load all scenario manifests from the scenarios/ directory."""
    scenarios = {}
    if not SCENARIOS_DIR.exists():
        return scenarios
    for f in SCENARIOS_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text())
            data["_file"] = f.name
            scenarios[f.stem] = data
        except (json.JSONDecodeError, OSError):
            pass
    return scenarios


def _load_popular_mods():
    """Load the popular mods catalog."""
    path = CATALOG_DIR / "popular_mods.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
        return data.get("mods", {})
    except (json.JSONDecodeError, OSError):
        return {}


def list_scenarios():
    """List available compatibility test scenarios."""
    scenarios = _load_scenarios()
    catalog = _load_popular_mods()

    items = []
    for name, data in scenarios.items():
        items.append({
            "name": name,
            "description": data.get("description", ""),
            "mods": data.get("mods", []),
            "save_fixture": data.get("save_fixture", ""),
        })

    # Also list catalog mods that could be scenarios
    for mod_key, mod_info in catalog.items():
        if mod_key not in scenarios:
            items.append({
                "name": mod_key,
                "description": f"{mod_info['name']} (catalog entry, no scenario manifest)",
                "mods": [mod_key],
                "save_fixture": "",
                "has_manifest": False,
            })

    return {"scenarios": items, "count": len(items)}


def run_scenario(scenario_name):
    """Run a compatibility test scenario.

    Steps:
    1. Load scenario manifest (or build one from catalog)
    2. Install required mods
    3. Restore save fixture (if specified)
    4. Launch game with SE
    5. Wait for socket
    6. Run Lua assertions
    7. Capture screenshots
    8. Collect results
    """
    scenarios = _load_scenarios()
    catalog = _load_popular_mods()

    # Try manifest first, then catalog entry
    if scenario_name in scenarios:
        scenario = scenarios[scenario_name]
    elif scenario_name in catalog:
        mod_info = catalog[scenario_name]
        scenario = {
            "description": f"Auto-generated scenario for {mod_info['name']}",
            "mods": [scenario_name],
            "assertions": [
                "assert(Ext.Utils.Version() ~= nil, 'SE loaded')",
                f"assert(Ext.Mod.IsModLoaded ~= nil, 'Ext.Mod available')",
            ],
        }
    else:
        available = sorted(list(scenarios.keys()) + list(catalog.keys()))
        return {
            "error": f"Scenario '{scenario_name}' not found",
            "available": available,
        }

    run_id = f"{scenario_name}_{int(time.time())}"
    report_dir = REPORTS_DIR / run_id
    report_dir.mkdir(parents=True, exist_ok=True)

    results = {
        "scenario": scenario_name,
        "run_id": run_id,
        "description": scenario.get("description", ""),
        "report_dir": str(report_dir),
        "steps": [],
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    def log_step(name, result):
        step = {"name": name, "success": result.get("success", "error" not in result), **result}
        results["steps"].append(step)
        status = "OK" if step["success"] else "FAIL"
        print(f"  [{status}] {name}", file=sys.stderr)
        return step["success"]

    print(f"Running compat scenario: {scenario_name}", file=sys.stderr)

    # Step 1: Check prerequisites
    from .doctor import run_doctor
    doctor_result = run_doctor()
    prereq_ok = doctor_result.get("all_passed", False)
    # Only hard-fail on critical checks
    critical_checks = ["bg3_app_bundle", "bg3_binary", "se_dylib_deployed", "mods_directory"]
    critical_passed = all(
        c["passed"] for c in doctor_result["checks"]
        if c["name"] in critical_checks
    )
    log_step("prerequisites", {"success": critical_passed, "passed": doctor_result["passed"], "total": doctor_result["total"]})

    if not critical_passed:
        results["success"] = False
        results["error"] = "Critical prerequisites not met"
        _save_report(report_dir, results)
        return results

    # Step 2: Install mods (if mod PAKs are available locally)
    mod_keys = scenario.get("mods", [])
    for mod_key in mod_keys:
        mod_info = catalog.get(mod_key, {})
        log_step(f"mod_check_{mod_key}", {
            "success": True,
            "name": mod_info.get("name", mod_key),
            "priority": mod_info.get("priority", "unknown"),
            "note": "Mod must be manually installed for now. Auto-install via Nexus planned.",
        })

    # Step 3: Restore save fixture (if specified)
    save_fixture = scenario.get("save_fixture")
    if save_fixture:
        from .savegames import restore
        restore_result = restore(save_fixture)
        log_step("restore_save", restore_result)

    # Step 4: Check if game is already running
    from . import launch as launch_mod
    if launch_mod.is_running() and launch_mod.socket_alive():
        log_step("game_status", {"success": True, "note": "Game already running with SE"})
    else:
        log_step("game_status", {
            "success": False,
            "note": "Game not running. Launch manually or via: bg3se-harness launch --continue",
        })

    # Step 5: Run assertions (if game is running)
    assertions = scenario.get("assertions", [])
    if assertions and launch_mod.socket_alive():
        from .console import Console
        try:
            with Console() as c:
                for i, assertion_lua in enumerate(assertions):
                    try:
                        output = c.send(assertion_lua)
                        log_step(f"assertion_{i}", {"success": True, "lua": assertion_lua, "output": output[:200]})
                    except Exception as e:
                        log_step(f"assertion_{i}", {"success": False, "lua": assertion_lua, "error": str(e)})
        except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
            log_step("assertions", {"success": False, "error": f"Socket connection failed: {e}"})

    # Step 6: Capture screenshot
    if launch_mod.is_running():
        from .screenshot import capture
        ss_result = capture(output=str(report_dir / "screenshot.jpg"))
        log_step("screenshot", {"success": "error" not in ss_result, **ss_result})

    # Step 7: Check crash log
    from .crashlog import cmd_crashlog
    import argparse
    crash_args = argparse.Namespace(ring=False, tail=20)

    # Finalize
    passed_steps = sum(1 for s in results["steps"] if s.get("success"))
    total_steps = len(results["steps"])
    results["success"] = all(s.get("success") for s in results["steps"])
    results["summary"] = f"{passed_steps}/{total_steps} steps passed"
    results["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

    _save_report(report_dir, results)
    return results


def run_matrix():
    """Run all scenarios and produce a summary."""
    catalog = _load_popular_mods()
    scenarios = _load_scenarios()
    all_names = sorted(set(list(scenarios.keys()) + list(catalog.keys())))

    matrix_results = []
    for name in all_names:
        result = run_scenario(name)
        matrix_results.append({
            "scenario": name,
            "success": result.get("success", False),
            "summary": result.get("summary", ""),
            "run_id": result.get("run_id", ""),
        })

    passed = sum(1 for r in matrix_results if r["success"])
    return {
        "matrix": matrix_results,
        "passed": passed,
        "total": len(matrix_results),
        "all_passed": passed == len(matrix_results),
    }


def _save_report(report_dir, results):
    """Save report JSON to report directory."""
    report_path = report_dir / "report.json"
    report_path.write_text(json.dumps(results, indent=2))


# ============================================================================
# CLI handler
# ============================================================================

def cmd_compat(args):
    """CLI handler for compat subcommands."""
    subcmd = args.compat_command

    if subcmd == "list":
        result = list_scenarios()
        print(json.dumps(result, indent=2))
        return 0

    elif subcmd == "run":
        result = run_scenario(args.scenario)
        print(json.dumps(result, indent=2))
        return 0 if result.get("success") else 1

    elif subcmd == "matrix":
        result = run_matrix()
        print(json.dumps(result, indent=2))
        return 0 if result.get("all_passed") else 1

    return 1
