"""Test suite for bg3se-harness CLI.

Run: PYTHONPATH=tools python3 -m bg3se_harness.tests [--live] [--ghidra]

Without flags: runs offline tests only (no game, no socket, no Ghidra).
With --live: also runs tests that require BG3 running with SE socket.
With --ghidra: also runs tests that require Ghidra HTTP bridge.
"""

import json
import os
import subprocess
import sys
import tempfile
import time

HARNESS = [sys.executable, "-m", "bg3se_harness"]
PASS = 0
FAIL = 0
SKIP = 0


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
TOOLS_DIR = os.path.join(PROJECT_ROOT, "tools")


def run(args, expect_rc=0, timeout=10):
    """Run a harness command. Returns (stdout, stderr, returncode)."""
    env = os.environ.copy()
    env["PYTHONPATH"] = TOOLS_DIR
    result = subprocess.run(
        [sys.executable, "-m", "bg3se_harness"] + args,
        capture_output=True, text=True, timeout=timeout,
        cwd=PROJECT_ROOT,
        env=env,
    )
    return result.stdout, result.stderr, result.returncode


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS: {name}")
    else:
        FAIL += 1
        print(f"  FAIL: {name} {detail}")


def skip(name, reason=""):
    global SKIP
    SKIP += 1
    print(f"  SKIP: {name} ({reason})")


# ─── Offline Tests (no game, no socket) ───────────────────────────


def test_help():
    """All 22 commands show --help without error."""
    print("\n=== Help Text ===")
    out, err, rc = run(["--help"])
    check("main --help exits 0", rc == 0)

    commands = [
        "build", "patch", "unpatch", "launch", "test", "run", "eval",
        "status", "entity", "entity-search", "components", "flags",
        "screenshot", "stats", "watch", "dump", "crashlog", "benchmark",
        "events", "diff-test", "probe", "ghidra",
    ]
    for cmd in commands:
        out, err, rc = run([cmd, "--help"])
        check(f"{cmd} --help exits 0", rc == 0, f"rc={rc}")


def test_imports():
    """All modules import without error."""
    print("\n=== Module Imports ===")
    modules = [
        "bg3se_harness.benchmark",
        "bg3se_harness.crashlog",
        "bg3se_harness.diff_test",
        "bg3se_harness.dump",
        "bg3se_harness.entity_inspect",
        "bg3se_harness.eval",
        "bg3se_harness.events",
        "bg3se_harness.flags",
        "bg3se_harness.ghidra",
        "bg3se_harness.launch",
        "bg3se_harness.probe",
        "bg3se_harness.screenshot",
        "bg3se_harness.stats_inspect",
        "bg3se_harness.watch",
    ]
    for mod in modules:
        try:
            __import__(mod)
            check(f"import {mod}", True)
        except Exception as e:
            check(f"import {mod}", False, str(e))


def test_flags():
    """Flags command works offline, lists all flags."""
    print("\n=== Flags ===")
    out, err, rc = run(["flags"])
    check("flags exits 0", rc == 0)
    check("flags lists 40 flags", "40 flags" in err, f"stderr={err[-60:]}")

    # Group filter
    out, err, rc = run(["flags", "--group", "launch"])
    check("flags --group launch exits 0", rc == 0)
    check("flags --group launch shows continueGame", "continueGame" in out)

    # Validation logic
    from bg3se_harness.flags import build_flag_args, FlagError, validate_flags
    check("build_flag_args continue", build_flag_args({"continueGame": True}) == ["-continueGame"])
    check("build_flag_args save", build_flag_args({"loadSaveGame": "X"}) == ["-loadSaveGame", "X"])

    try:
        validate_flags({"continueGame", "loadSaveGame"})
        check("mutual exclusion enforced", False, "should have raised")
    except FlagError:
        check("mutual exclusion enforced", True)

    try:
        build_flag_args({"nonexistent": True})
        check("unknown flag rejected", False, "should have raised")
    except FlagError:
        check("unknown flag rejected", True)


def test_diff_test():
    """diff-test works with mock JSON files."""
    print("\n=== Diff-Test ===")
    baseline = {
        "tests": [
            {"name": "Core.Print", "status": "pass", "ms": 2},
            {"name": "Stats.Get", "status": "pass", "ms": 5},
            {"name": "Entity.Bad", "status": "fail", "ms": 1, "error": "old bug"},
        ],
        "summary": {"passed": 2, "failed": 1, "total": 3},
    }
    current = {
        "tests": [
            {"name": "Core.Print", "status": "pass", "ms": 2},
            {"name": "Stats.Get", "status": "fail", "ms": 50, "error": "new bug"},
            {"name": "NewTest.One", "status": "pass", "ms": 1},
        ],
        "summary": {"passed": 2, "failed": 1, "total": 3},
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as bf:
        json.dump(baseline, bf)
        base_path = bf.name
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as cf:
        json.dump(current, cf)
        curr_path = cf.name

    try:
        out, err, rc = run(["diff-test", base_path, curr_path])
        check("diff-test exits 1 (regression)", rc == 1)
        if not out.strip():
            check("diff-test returns JSON", False, f"empty stdout, stderr={err[:100]}")
            return
        result = json.loads(out)
        check("diff-test verdict REGRESSION", result["verdict"] == "REGRESSION")
        check("diff-test new failure Stats.Get", "Stats.Get" in result["new_failures"])
        # Entity.Bad was in baseline (fail) but absent from current → "missing", not "new_pass"
        check("diff-test Entity.Bad is missing (removed)", "Entity.Bad" in result.get("missing_tests", []))
        check("diff-test new test NewTest.One", "NewTest.One" in result.get("new_tests", []))
        check("diff-test missing test Entity.Bad", "Entity.Bad" in result.get("missing_tests", []))
    finally:
        os.unlink(base_path)
        os.unlink(curr_path)


def test_crashlog():
    """crashlog works (may find no data, but should not crash)."""
    print("\n=== Crashlog ===")
    out, err, rc = run(["crashlog"])
    check("crashlog exits cleanly", rc in (0, 1))
    try:
        result = json.loads(out)
        check("crashlog returns valid JSON", True)
        check("crashlog has expected keys", "error" in result or "signal" in result or "last_log_lines" in result)
    except json.JSONDecodeError:
        check("crashlog returns valid JSON", False, f"out={out[:100]}")


def test_status_offline():
    """status works without game running."""
    print("\n=== Status (Offline) ===")
    out, err, rc = run(["status"])
    check("status exits 0", rc == 0)
    result = json.loads(out)
    check("status has game_running", "game_running" in result)
    check("status has socket_alive", "socket_alive" in result)
    check("status has patched", "patched" in result)


def test_screenshot_safeguards():
    """Screenshot module has correct constants."""
    print("\n=== Screenshot Safeguards ===")
    from bg3se_harness import screenshot
    check("MAX_DIMENSION = 1568", getattr(screenshot, "MAX_DIMENSION", None) == 1568)
    check("JPEG_QUALITY = 80", getattr(screenshot, "JPEG_QUALITY", None) == 80)
    # Check SCREENSHOTS_DIR exists as a Path
    sd = getattr(screenshot, "SCREENSHOTS_DIR", None) or getattr(screenshot, "SCREENSHOT_DIR", None)
    check("SCREENSHOTS_DIR is set", sd is not None)


def test_ghidra_bridge_class():
    """GhidraBridge class instantiates and has expected methods."""
    print("\n=== Ghidra Bridge Class ===")
    from bg3se_harness.ghidra import GhidraBridge
    bridge = GhidraBridge("http://127.0.0.1:99999")  # intentionally wrong port
    check("GhidraBridge instantiates", bridge is not None)
    check("has decompile()", hasattr(bridge, "decompile"))
    check("has search_strings()", hasattr(bridge, "search_strings"))
    check("has search_functions()", hasattr(bridge, "search_functions"))
    check("has xrefs_to()", hasattr(bridge, "xrefs_to"))
    check("has status()", hasattr(bridge, "status"))


# ─── Live Tests (require BG3 running with SE socket) ──────────────


def test_live_run():
    """run command sends Lua to game."""
    print("\n=== Live: run ===")
    out, err, rc = run(["run", "_P('harness_test_ok')"], timeout=15)
    check("run exits 0", rc == 0)
    check("run returns output", "harness_test_ok" in out)


def test_live_eval():
    """eval with stdin pipe."""
    print("\n=== Live: eval ===")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".lua", delete=False) as f:
        f.write("_P('eval_test_ok')\n")
        lua_path = f.name
    try:
        out, err, rc = run(["eval", lua_path], timeout=15)
        check("eval file exits 0", rc == 0)
        check("eval returns output", "eval_test_ok" in out)
    finally:
        os.unlink(lua_path)


def test_live_entity():
    """entity command lists components (needs loaded save)."""
    print("\n=== Live: entity ===")
    # Use a known player GUID pattern
    out, err, rc = run(["run", '_P(Ext.Entity.Get("S_Player_Karlach") ~= nil and "found" or "nil")'], timeout=15)
    if "found" in out:
        out2, err2, rc2 = run(["entity", "S_Player_Karlach"], timeout=15)
        check("entity exits 0", rc2 == 0)
        check("entity returns JSON array or components", "[" in out2 or "component" in out2.lower())
    else:
        skip("entity S_Player_Karlach", "entity not found (no save loaded?)")


def test_live_stats():
    """stats command dumps a stat."""
    print("\n=== Live: stats ===")
    out, err, rc = run(["stats", "WPN_Longsword"], timeout=15)
    check("stats exits 0 or 1", rc in (0, 1))
    if rc == 0:
        check("stats returns data", len(out) > 10)


def test_live_components():
    """components command lists types."""
    print("\n=== Live: components ===")
    out, err, rc = run(["components", "--count"], timeout=15)
    check("components exits 0", rc == 0)


def test_live_screenshot():
    """screenshot captures game window."""
    print("\n=== Live: screenshot ===")
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
        out_path = f.name
    try:
        out, err, rc = run(["screenshot", "--output", out_path], timeout=15)
        check("screenshot exits 0", rc == 0)
        if rc == 0:
            result = json.loads(out)
            check("screenshot returns path", "path" in result)
            check("screenshot file exists", os.path.exists(result.get("path", "")))
            check("screenshot width <= 1568", result.get("width", 9999) <= 1568)
            check("screenshot tokens_est present", "tokens_est" in result)
            check("screenshot token estimate in stderr", "tokens" in err.lower())
    finally:
        if os.path.exists(out_path):
            os.unlink(out_path)


# ─── Ghidra Tests (require Ghidra HTTP bridge) ────────────────────


def test_ghidra_status():
    """ghidra status checks bridge."""
    print("\n=== Ghidra: status ===")
    out, err, rc = run(["ghidra", "status"], timeout=10)
    check("ghidra status exits 0", rc == 0)
    result = json.loads(out)
    check("ghidra status alive", result.get("alive") is True)


def test_ghidra_search():
    """ghidra search-strings finds known strings."""
    print("\n=== Ghidra: search ===")
    out, err, rc = run(["ghidra", "search-strings", "continueGame"], timeout=15)
    check("ghidra search-strings exits 0", rc == 0)
    check("ghidra finds continueGame", "continueGame" in out)


def test_ghidra_decompile():
    """ghidra decompile produces C pseudocode."""
    print("\n=== Ghidra: decompile ===")
    out, err, rc = run(["ghidra", "decompile", "0x100bb53d8"], timeout=15)
    check("ghidra decompile exits 0", rc == 0)
    check("ghidra decompile has code", "void" in out or "function" in out.lower() or "{" in out)


# ─── Main ─────────────────────────────────────────────────────────


def main():
    global PASS, FAIL, SKIP

    live = "--live" in sys.argv
    ghidra = "--ghidra" in sys.argv

    print("bg3se-harness test suite")
    print(f"Mode: offline{' + live' if live else ''}{' + ghidra' if ghidra else ''}")

    # Offline tests (always run)
    test_help()
    test_imports()
    test_flags()
    test_diff_test()
    test_crashlog()
    test_status_offline()
    test_screenshot_safeguards()
    test_ghidra_bridge_class()

    # Live tests (require game running)
    if live:
        test_live_run()
        test_live_eval()
        test_live_entity()
        test_live_stats()
        test_live_components()
        test_live_screenshot()
    else:
        for name in ["run", "eval", "entity", "stats", "components", "screenshot"]:
            skip(f"live:{name}", "use --live with game running")

    # Ghidra tests
    if ghidra:
        test_ghidra_status()
        test_ghidra_search()
        test_ghidra_decompile()
    else:
        for name in ["status", "search", "decompile"]:
            skip(f"ghidra:{name}", "use --ghidra with bridge running")

    # Summary
    total = PASS + FAIL + SKIP
    print(f"\n{'=' * 40}")
    print(f"Results: {PASS} passed, {FAIL} failed, {SKIP} skipped ({total} total)")
    if FAIL > 0:
        print("FAILED")
        return 1
    print("ALL PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
