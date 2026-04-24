import argparse
import json
import sys

from . import build as build_mod
from . import launch as launch_mod
from . import patch as patch_mod
from .authoring import cmd_author
from .console import Console
from .benchmark import cmd_benchmark
from .compat import cmd_compat
from .crashlog import cmd_crashlog
from .doctor import cmd_doctor
from .diff_test import cmd_diff_test
from .dump import cmd_dump, CATEGORIES as DUMP_CATEGORIES
from .entity_inspect import cmd_entity, cmd_entity_search, cmd_components
from .eval import cmd_eval
from .events import cmd_events
from .flags import (
    GAME_FLAGS,
    PRESETS,
    ALL_GROUPS,
    FlagError,
    list_flags,
)
from .probe import cmd_probe
from .menu import cmd_menu
from .mod_cli import cmd_mod
from .parity import cmd_parity
from .wiki import cmd_wiki  # bg3.wiki MediaWiki client
from .savegames import cmd_save
from .screenshot import cmd_screenshot
from .stats_inspect import cmd_stats
from .test_runner import run_tests
from .watch import cmd_watch


def _collect_extra_flags(args):
    """Build extra_flags dict from CLI args."""
    flags = {}
    if getattr(args, "storylog", False):
        flags["storylog"] = True
    if getattr(args, "stats", False):
        flags["stats"] = True
    if getattr(args, "json_mode", False):
        flags["json"] = True
    if getattr(args, "osi_debug", False):
        flags["osi"] = True
    if getattr(args, "syslog", False):
        flags["syslog"] = True
    if getattr(args, "modded", False):
        flags["modded"] = True
    if getattr(args, "controller", False):
        flags["startInControllerMode"] = True
    if getattr(args, "ecb_checker", False):
        for key in PRESETS["ecb"]:
            flags[key] = True
    if getattr(args, "module", None):
        flags["module"] = args.module
    if getattr(args, "detail_level", None):
        flags["detailLevel"] = args.detail_level
    if getattr(args, "log_path", None):
        flags["logPath"] = args.log_path

    # Raw passthrough: parse space-separated flags
    raw = getattr(args, "flags", None)
    if raw:
        parts = raw.split()
        i = 0
        while i < len(parts):
            name = parts[i].lstrip("-")
            flag_def = GAME_FLAGS.get(name)
            if flag_def and flag_def.takes_arg and i + 1 < len(parts):
                flags[name] = parts[i + 1]
                i += 2
            else:
                flags[name] = True
                i += 1

    return flags or None


def _add_launch_flags(parser):
    """Add game flag arguments shared between launch and test."""
    g = parser.add_argument_group("game flags")
    g.add_argument("--continue", dest="continue_game", action="store_true",
                    help="Auto-continue most recent save (-continueGame)")
    g.add_argument("--save", metavar="NAME",
                    help="Load specific save game (-loadSaveGame NAME)")
    g.add_argument("--storylog", action="store_true",
                    help="Enable story logging (-storylog)")
    g.add_argument("--stats", action="store_true",
                    help="Enable stats output (-stats)")
    g.add_argument("--json-mode", action="store_true",
                    help="Enable JSON output mode (-json)")
    g.add_argument("--osi-debug", action="store_true",
                    help="Enable Osiris debug (-osi)")
    g.add_argument("--syslog", action="store_true",
                    help="Enable system logging (-syslog)")
    g.add_argument("--modded", action="store_true",
                    help="Enable modded mode (-modded)")
    g.add_argument("--module", metavar="NAME",
                    help="Specify module (-module NAME)")
    g.add_argument("--controller", action="store_true",
                    help="Start in controller mode (-startInControllerMode)")
    g.add_argument("--detail-level", metavar="N",
                    help="Graphics detail level (-detailLevel N)")
    g.add_argument("--log-path", metavar="PATH",
                    help="Log file path (--logPath PATH)")
    g.add_argument("--ecb-checker", action="store_true",
                    help="Enable save system ECB checker + logging")
    g.add_argument("--no-skip-videos", dest="skip_videos", action="store_false",
                    default=True, help="Don't set video-skip preferences this run")
    g.add_argument("--flags", metavar="'...'",
                    help="Pass arbitrary game flags verbatim")


def cmd_build(args):
    print("Building...", file=sys.stderr)
    result = build_mod.build()
    if not result.get("success"):
        print(json.dumps(result, indent=2))
        return 1

    print("Verifying architecture...", file=sys.stderr)
    verify = build_mod.verify()
    result["arch"] = verify

    print("Deploying...", file=sys.stderr)
    deploy = build_mod.deploy()
    result["deploy"] = deploy

    print(json.dumps(result, indent=2))
    return 0 if verify.get("verified") and deploy.get("deployed") else 1


def cmd_patch(args):
    print("Patching BG3 binary...", file=sys.stderr)
    result = patch_mod.patch()
    print(json.dumps(result, indent=2))
    return 0 if result.get("success") or result.get("already_patched") else 1


def cmd_unpatch(args):
    print("Restoring original binary...", file=sys.stderr)
    result = patch_mod.unpatch()
    print(json.dumps(result, indent=2))
    return 0 if result.get("success") else 1


def cmd_launch(args):
    continue_game = getattr(args, "continue_game", False)
    load_save = getattr(args, "save", None)

    try:
        extra_flags = _collect_extra_flags(args)
    except FlagError as e:
        print(json.dumps({"error": str(e)}))
        return 1

    # Build + deploy
    print("Building...", file=sys.stderr)
    br = build_mod.build()
    if not br.get("success"):
        print(json.dumps({"stage": "build", **br}, indent=2))
        return 1

    verify = build_mod.verify()
    deploy = build_mod.deploy()
    if not verify.get("verified") or not deploy.get("deployed"):
        print(json.dumps({"stage": "deploy", "verify": verify, "deploy": deploy}, indent=2))
        return 1

    # Patch
    print("Patching...", file=sys.stderr)
    pr = patch_mod.patch()
    if not (pr.get("success") or pr.get("already_patched")):
        print(json.dumps({"stage": "patch", **pr}, indent=2))
        return 1

    # Launch with game flags
    skip_videos = getattr(args, "skip_videos", True)
    print("Launching BG3...", file=sys.stderr)
    proc = launch_mod.launch(
        continue_game=continue_game,
        load_save=load_save,
        extra_flags=extra_flags,
        skip_videos=skip_videos,
    )

    # Health check — also dismisses splash screen via CGEvent
    print("Waiting for SE socket...", file=sys.stderr)
    timeout = getattr(args, "timeout", None)
    if timeout is None:
        timeout = launch_mod.default_timeout(continue_game, load_save)
    health = launch_mod.wait_for_socket(timeout=timeout, dismiss_splash=True)
    health["pid"] = proc.pid
    health["patch"] = pr
    health["continue_game"] = continue_game
    if load_save:
        health["load_save"] = load_save

    print(json.dumps(health, indent=2))
    return 0 if health.get("socket_connected") else 1


def cmd_test(args):
    continue_game = getattr(args, "continue_game", True)  # default: auto-continue
    load_save = getattr(args, "save", None)

    try:
        extra_flags = _collect_extra_flags(args)
    except FlagError as e:
        print(json.dumps({"error": str(e)}))
        return 1

    # Build + deploy
    print("Building...", file=sys.stderr)
    br = build_mod.build()
    if not br.get("success"):
        print(json.dumps({"stage": "build", **br}, indent=2))
        return 1

    verify = build_mod.verify()
    deploy = build_mod.deploy()
    if not verify.get("verified") or not deploy.get("deployed"):
        print(json.dumps({"stage": "deploy", "verify": verify, "deploy": deploy}, indent=2))
        return 1

    # Patch
    print("Patching...", file=sys.stderr)
    pr = patch_mod.patch()
    if not (pr.get("success") or pr.get("already_patched")):
        print(json.dumps({"stage": "patch", **pr}, indent=2))
        return 1

    # Launch
    skip_videos = getattr(args, "skip_videos", True)
    print("Launching BG3...", file=sys.stderr)
    proc = launch_mod.launch(
        continue_game=continue_game,
        load_save=load_save,
        extra_flags=extra_flags,
        skip_videos=skip_videos,
    )

    # Wait for socket — also dismisses splash screen via CGEvent
    print("Waiting for SE socket...", file=sys.stderr)
    timeout = launch_mod.default_timeout(continue_game, load_save)
    health = launch_mod.wait_for_socket(timeout=timeout, dismiss_splash=True)
    if not health.get("socket_connected"):
        health["stage"] = "health"
        health["pid"] = proc.pid
        print(json.dumps(health, indent=2))
        return 1

    # Run tests
    print("Running tests...", file=sys.stderr)
    result = run_tests(
        tier=args.tier if hasattr(args, "tier") else 1,
        filter_pattern=args.filter if hasattr(args, "filter") else None,
    )
    output = {k: v for k, v in result.items() if k != "raw_output"}
    output["launch"] = {
        "pid": proc.pid,
        "continue_game": continue_game,
        "socket_elapsed_ms": health.get("elapsed_ms"),
    }
    print(json.dumps(output, indent=2))
    return 0 if result.get("all_passed") else 1


def cmd_run(args):
    try:
        with Console() as c:
            output = c.send(args.lua)
        print(output)
        return 0
    except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
        print(json.dumps({"error": f"Socket connection failed: {e}"}))
        return 1


def cmd_status(args):
    result = {
        "game_running": launch_mod.is_running(),
        "socket_alive": launch_mod.socket_alive(),
        "patched": patch_mod.is_patched(),
        "backup_exists": patch_mod._backup_path().exists(),
    }
    print(json.dumps(result, indent=2))
    return 0


def cmd_quit(args):
    result = launch_mod.quit_game(force=getattr(args, "force", False))
    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


def cmd_flags(args):
    group = getattr(args, "group", None)
    items = list_flags(group=group)

    if getattr(args, "verify", False):
        # Verify flags exist in current binary
        import subprocess
        from .config import BG3_EXEC
        result = subprocess.run(
            ["strings", "-a", str(BG3_EXEC)],
            capture_output=True, text=True,
        )
        binary_strings = set(result.stdout.splitlines())
        verified = {}
        for key, flag in items:
            verified[key] = {
                "flag": flag.name,
                "found": flag.name in binary_strings,
                "group": flag.group,
            }
        print(json.dumps(verified, indent=2))
        return 0

    # Human-readable listing
    current_group = None
    for key, flag in items:
        if flag.group != current_group:
            current_group = flag.group
            print(f"\n  [{current_group}]", file=sys.stderr)
        arg_hint = " <arg>" if flag.takes_arg else ""
        print(f"    {flag.name}{arg_hint:10s}  {flag.description}")
    print(f"\n  {len(items)} flags", file=sys.stderr)
    if not group:
        print(f"  Groups: {', '.join(ALL_GROUPS)}", file=sys.stderr)
        print(f"  Presets: {', '.join(PRESETS.keys())}", file=sys.stderr)
    return 0


def cmd_ghidra(args):
    from .ghidra import GhidraBridge

    bridge = GhidraBridge()
    subcmd = args.ghidra_command

    if subcmd == "status":
        result = bridge.status()
        print(json.dumps(result, indent=2))
        return 0 if result.get("alive") else 1

    elif subcmd == "decompile":
        code = bridge.decompile(args.target)
        if code:
            print(code)
            return 0
        print(json.dumps({"error": "Function not found"}))
        return 1

    elif subcmd == "search-strings":
        results = bridge.search_strings(args.query)
        for addr, s in results:
            print(f"{addr}: {s}")
        return 0

    elif subcmd == "search-functions":
        results = bridge.search_functions(args.query)
        for line in results:
            print(line)
        return 0

    elif subcmd == "xrefs":
        results = bridge.xrefs_to(args.address)
        for line in results:
            print(line)
        return 0

    elif subcmd == "list-functions":
        offset = getattr(args, "offset", 0) or 0
        limit = getattr(args, "limit", 50) or 50
        results = bridge.list_functions(offset=offset, limit=limit)
        for line in results:
            print(line)
        return 0

    elif subcmd == "call-graph":
        depth = getattr(args, "depth", 2) or 2
        result = bridge.call_graph(args.name, depth=depth)
        print(result)
        return 0

    return 1


def main():
    parser = argparse.ArgumentParser(
        prog="bg3se-harness",
        description="BG3 Script Extender autonomous test harness",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # build
    sub.add_parser("build", help="Build and deploy the SE dylib")

    # patch / unpatch
    sub.add_parser("patch", help="Patch BG3 binary with insert_dylib")
    sub.add_parser("unpatch", help="Restore original BG3 binary")

    # launch
    p_launch = sub.add_parser("launch", help="Build, patch, launch, and health-check")
    p_launch.add_argument("--timeout", type=int, help="Socket health check timeout (seconds)")
    _add_launch_flags(p_launch)

    # test
    p_test = sub.add_parser("test", help="Full autonomous pipeline: build+patch+launch+continue+test")
    p_test.add_argument("filter", nargs="?", help="Test name filter pattern")
    p_test.add_argument("--tier", type=int, default=1, choices=[1, 2], help="Test tier (1=console, 2=ingame)")
    p_test.add_argument("--no-continue", dest="continue_game", action="store_false",
                         help="Don't auto-continue (stop at main menu)")
    _add_launch_flags(p_test)

    # run
    p_run = sub.add_parser("run", help="Send arbitrary Lua to running game")
    p_run.add_argument("lua", help="Lua code to execute")

    # eval
    p_eval = sub.add_parser("eval", help="Execute Lua from a file or stdin in the running game")
    p_eval.add_argument("source", help="Path to .lua file, or '-' for stdin")

    # status / quit
    sub.add_parser("status", help="Check game/socket/patch status")
    p_quit = sub.add_parser("quit", help="Quit the running game")
    p_quit.add_argument("--force", action="store_true", help="Skip graceful quit, send SIGTERM immediately")

    # entity
    p_entity = sub.add_parser("entity", help="Inspect a live entity by GUID")
    p_entity.add_argument("guid", help="Entity GUID")
    p_entity.add_argument("--component", metavar="NAME",
                          help="Dump this component's fields (omit to list all)")
    p_entity.add_argument("--depth", type=int, default=3, metavar="N",
                          help="MaxDepth for JSON serialisation (default: 3)")

    # entity-search
    p_esearch = sub.add_parser("entity-search", help="Search entities by component and/or name pattern")
    p_esearch.add_argument("--component", metavar="NAME",
                           help="Filter to entities that have this component")
    p_esearch.add_argument("--name-pattern", metavar="PATTERN", dest="name_pattern",
                           help="Case-insensitive GUID substring filter")
    p_esearch.add_argument("--limit", type=int, default=20, metavar="N",
                           help="Maximum results to return (default: 20)")

    # components
    p_comps = sub.add_parser("components", help="List registered component types")
    p_comps.add_argument("--namespace", metavar="NS",
                         help="Filter to types starting with this prefix (e.g. eoc::)")
    p_comps.add_argument("--search", metavar="PATTERN",
                         help="Case-insensitive substring filter")
    p_comps.add_argument("--count", action="store_true",
                         help="Print only the total count")

    # flags
    p_flags = sub.add_parser("flags", help="List all discovered BG3 CLI flags")
    p_flags.add_argument("--group", choices=ALL_GROUPS, help="Filter by flag group")
    p_flags.add_argument("--verify", action="store_true", help="Verify flags exist in current binary")

    # screenshot
    p_ss = sub.add_parser("screenshot", help="Capture game window screenshot (Claude Code safe)")
    p_ss.add_argument("--output", "-o", metavar="PATH", help="Output file path")
    p_ss.add_argument("--raw", action="store_true", help="Skip resize, keep full resolution PNG")

    # stats
    p_stats = sub.add_parser("stats", help="Inspect RPG stat entries")
    p_stats.add_argument("name", nargs="?", help="Stat name (e.g. WPN_Longsword)")
    p_stats.add_argument("--all", metavar="TYPE", dest="all_type", help="List all stats of TYPE (Weapon, Armor, SpellData, etc.)")
    p_stats.add_argument("--diff", metavar="OTHER", help="Show only differences vs OTHER stat")

    # watch
    p_watch = sub.add_parser("watch", help="Hot-reload Lua file on change")
    p_watch.add_argument("path", help="Path to Lua file to watch")
    p_watch.add_argument("--once", action="store_true", help="Execute once and exit (CI mode)")

    # dump
    p_dump = sub.add_parser("dump", help="Bulk extract game data")
    p_dump.add_argument("category", choices=sorted(list(DUMP_CATEGORIES.keys()) + ["all"]),
                         help="Data category to extract")
    p_dump.add_argument("--output", "-o", metavar="DIR", help="Output directory for JSON files")

    # crashlog
    p_crash = sub.add_parser("crashlog", help="Parse BG3SE crash diagnostics (no socket needed)")
    p_crash.add_argument("--ring", action="store_true", help="Include crash ring buffer")
    p_crash.add_argument("--tail", type=int, default=50, metavar="N", help="Last N log lines (default 50)")

    # benchmark
    p_bench = sub.add_parser("benchmark", help="Benchmark Lua code execution")
    p_bench.add_argument("code", nargs="?", help="Lua code to benchmark")
    p_bench.add_argument("--file", metavar="PATH", help="Lua file to benchmark")
    p_bench.add_argument("--iterations", "-n", type=int, default=100, help="Number of iterations (default 100)")
    p_bench.add_argument("--warmup", type=int, default=5, help="Warmup iterations (default 5)")

    # events
    p_events = sub.add_parser("events", help="Subscribe to game events (JSONL stream)")
    p_events.add_argument("--list", dest="list_events", action="store_true", help="List all known events")
    p_events.add_argument("--subscribe", metavar="EVENT", help="Subscribe to event name")
    p_events.add_argument("--listen", type=int, metavar="SECS", help="Listen duration in seconds")

    # diff-test
    p_diff = sub.add_parser("diff-test", help="Compare test results against baseline")
    p_diff.add_argument("baseline", help="Baseline test results JSON file")
    p_diff.add_argument("current", help="Current test results JSON file")
    p_diff.add_argument("--threshold", type=int, default=50, help="Timing regression threshold %% (default 50)")

    # probe
    p_probe = sub.add_parser("probe", help="Memory inspection via Ext.Debug")
    p_probe.add_argument("address", help="Memory address (0xADDR)")
    p_probe.add_argument("--range", type=int, default=256, help="Range in bytes (default 256)")
    p_probe.add_argument("--stride", type=int, default=8, help="Stride for struct probe (default 8)")
    p_probe.add_argument("--classify", action="store_true", help="Classify pointer type")


    # menu
    p_menu = sub.add_parser("menu", help="Main menu automation (OCR + click)")
    menu_sub = p_menu.add_subparsers(dest="menu_command", required=True)

    menu_sub.add_parser("detect", help="Detect visible menu buttons via Vision OCR")

    p_mc = menu_sub.add_parser("click", help="Click a menu button by name")
    p_mc.add_argument("button", help="Button text (e.g. 'Continue', 'New Game')")

    p_mw = menu_sub.add_parser("wait", help="Poll until main menu is visible")
    p_mw.add_argument("--timeout", type=int, default=60, help="Timeout in seconds (default 60)")

    menu_sub.add_parser("dismiss", help="Dismiss 'Click to Continue' splash screen")

    # compat
    p_compat = sub.add_parser("compat", help="Mod compatibility test runner")
    compat_sub = p_compat.add_subparsers(dest="compat_command", required=True)

    compat_sub.add_parser("list", help="List available test scenarios")

    p_cr = compat_sub.add_parser("run", help="Run a compatibility test scenario")
    p_cr.add_argument("scenario", help="Scenario name (e.g. mcm, community_library)")

    compat_sub.add_parser("matrix", help="Run all scenarios and produce summary")

    # author
    p_author = sub.add_parser("author", help="Mod authoring tools")
    author_sub = p_author.add_subparsers(dest="author_command", required=True)

    p_an = author_sub.add_parser("new", help="Scaffold a new mod with BG3SE conventions")
    p_an.add_argument("name", help="Mod name (e.g. MyTestMod)")

    p_ac = author_sub.add_parser("check", help="Lint mod for macOS-specific issues")
    p_ac.add_argument("path", help="Path to mod directory")

    # mod
    p_mod = sub.add_parser("mod", help="Mod management (install, enable, list, search)")
    mod_sub = p_mod.add_subparsers(dest="mod_command", required=True)

    mod_sub.add_parser("list", help="List installed mods with enabled/SE status")

    p_mi = mod_sub.add_parser("install", help="Install a mod from local file or Nexus")
    p_mi.add_argument("source", help="Local .pak path, directory, or nexus:MOD_ID")
    p_mi.add_argument("--no-enable", action="store_true", help="Install without enabling")

    p_me = mod_sub.add_parser("enable", help="Enable a mod in modsettings.lsx")
    p_me.add_argument("name", help="Mod UUID or name")

    p_md = mod_sub.add_parser("disable", help="Disable a mod in modsettings.lsx")
    p_md.add_argument("name", help="Mod UUID or name")

    p_mr = mod_sub.add_parser("remove", help="Uninstall a mod")
    p_mr.add_argument("name", help="Mod UUID or name")

    p_minfo = mod_sub.add_parser("info", help="Show mod metadata from PAK or registry")
    p_minfo.add_argument("source", help="PAK file path or mod name")

    p_mo = mod_sub.add_parser("order", help="Reorder mod load order")
    p_mo.add_argument("--move", required=True, help="UUID of mod to move")
    p_mo.add_argument("--before", required=True, help="UUID to place before")

    p_ms = mod_sub.add_parser("search", help="Search Nexus Mods")
    p_ms.add_argument("query", help="Search query")

    p_mch = mod_sub.add_parser("changelog", help="Show all version changelogs for a Nexus mod")
    p_mch.add_argument("mod_id", type=int, help="Nexus mod ID")

    p_mver = mod_sub.add_parser("versions", help="List file versions for a Nexus mod")
    p_mver.add_argument("mod_id", type=int, help="Nexus mod ID")

    p_mup = mod_sub.add_parser("updated", help="List recently-updated BG3 mods on Nexus")
    p_mup.add_argument("--period", choices=("1d", "1w", "1m"), default="1w",
                       help="Time window: 1d, 1w (default), or 1m")

    mod_sub.add_parser("backup", help="Backup modsettings.lsx")

    # wiki — bg3.wiki cross-reference
    p_wiki = sub.add_parser("wiki", help="Query bg3.wiki for spell/item data")
    wiki_sub = p_wiki.add_subparsers(dest="wiki_command", required=True)

    p_ws = wiki_sub.add_parser("spell", help="Look up a spell page on bg3.wiki by name")
    p_ws.add_argument("name", help="Spell display name (e.g. Fireball)")
    p_ws.add_argument("--no-cache", action="store_true",
                      help="Bypass the local 24h file cache")

    p_wi = wiki_sub.add_parser("item", help="Look up an item/weapon page on bg3.wiki by name")
    p_wi.add_argument("name", help='Item display name (e.g. "Longsword +1")')
    p_wi.add_argument("--no-cache", action="store_true",
                      help="Bypass the local 24h file cache")

    p_wv = wiki_sub.add_parser("verify", help="Fetch a wiki page and (optionally) cross-check its engine uid")
    p_wv.add_argument("page", help="Exact wiki page title")
    p_wv.add_argument("--expect-uid", dest="expect_uid", default=None,
                      help="Expected engine stat name (e.g. WPN_HUM_Longsword_A_1)")
    p_wv.add_argument("--no-cache", action="store_true",
                      help="Bypass the local 24h file cache")

    wiki_sub.add_parser("clear-cache", help="Wipe the local wiki page cache")

    # parity
    p_parity = sub.add_parser("parity", help="Windows BG3SE parity audit")
    parity_sub = p_parity.add_subparsers(dest="parity_command", required=True)

    parity_sub.add_parser("scan", help="Compare live Ext table vs Windows baseline (requires running game)")
    parity_sub.add_parser("missing", help="List known gaps from baseline (offline)")

    p_pv = parity_sub.add_parser("verify", help="Deep-verify a namespace via Lua probes (requires running game)")
    p_pv.add_argument("namespace", help="Namespace to verify (e.g. Stats, Entity, IMGUI)")

    # doctor
    sub.add_parser("doctor", help="Verify paths, permissions, SE status, and prerequisites")

    # save
    p_save = sub.add_parser("save", help="Save game management for deterministic testing")
    save_sub = p_save.add_subparsers(dest="save_command", required=True)

    p_sl = save_sub.add_parser("list", help="List available save games")
    p_sl.add_argument("--fixtures", action="store_true", help="List fixtures instead of game saves")

    p_ss = save_sub.add_parser("snapshot", help="Create named fixture from a save")
    p_ss.add_argument("name", help="Fixture name (e.g. Harness_Base_Camp)")
    p_ss.add_argument("--source", metavar="SAVE_DIR", help="Specific save directory (default: most recent)")

    p_sr = save_sub.add_parser("restore", help="Restore a fixture into game saves")
    p_sr.add_argument("name", help="Fixture name to restore")

    p_sc = save_sub.add_parser("clone", help="Clone a save or fixture under a new name")
    p_sc.add_argument("src", help="Source save/fixture name")
    p_sc.add_argument("dst", help="Destination fixture name")

    # ghidra
    p_ghidra = sub.add_parser("ghidra", help="Ghidra RE bridge commands")
    ghidra_sub = p_ghidra.add_subparsers(dest="ghidra_command", required=True)

    ghidra_sub.add_parser("status", help="Check Ghidra bridge connectivity")

    p_gd = ghidra_sub.add_parser("decompile", help="Decompile function by name or address")
    p_gd.add_argument("target", help="Function name or 0xADDRESS")

    p_gs = ghidra_sub.add_parser("search-strings", help="Search strings in binary")
    p_gs.add_argument("query", help="String to search for")

    p_gf = ghidra_sub.add_parser("search-functions", help="Search function names")
    p_gf.add_argument("query", help="Function name pattern")

    p_gx = ghidra_sub.add_parser("xrefs", help="Find cross-references to address")
    p_gx.add_argument("address", help="Address (0xADDR)")

    p_gl = ghidra_sub.add_parser("list-functions", help="List functions (paginated)")
    p_gl.add_argument("--offset", type=int, default=0, help="Start offset")
    p_gl.add_argument("--limit", type=int, default=50, help="Max results")

    p_gc = ghidra_sub.add_parser("call-graph", help="Function call graph")
    p_gc.add_argument("name", help="Function name")
    p_gc.add_argument("--depth", type=int, default=2, help="Graph depth")

    args = parser.parse_args()

    handlers = {
        "build": cmd_build,
        "patch": cmd_patch,
        "unpatch": cmd_unpatch,
        "launch": cmd_launch,
        "test": cmd_test,
        "run": cmd_run,
        "eval": cmd_eval,
        "status": cmd_status,
        "quit": cmd_quit,
        "screenshot": cmd_screenshot,
        "entity": cmd_entity,
        "entity-search": cmd_entity_search,
        "components": cmd_components,
        "stats": cmd_stats,
        "watch": cmd_watch,
        "dump": cmd_dump,
        "crashlog": cmd_crashlog,
        "benchmark": cmd_benchmark,
        "events": cmd_events,
        "diff-test": cmd_diff_test,
        "probe": cmd_probe,
        "flags": cmd_flags,
        "menu": cmd_menu,
        "author": cmd_author,
        "compat": cmd_compat,
        "mod": cmd_mod,
        "wiki": cmd_wiki,
        "parity": cmd_parity,
        "doctor": cmd_doctor,
        "save": cmd_save,
        "ghidra": cmd_ghidra,
    }

    sys.exit(handlers[args.command](args))
