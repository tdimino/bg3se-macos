# BG3SE Test Harness

Autonomous test harness for bg3se-macos. Builds, injects, launches, tests, and reports—one command.

## Quick Start

```bash
cd /path/to/bg3se-macos

# Check status
PYTHONPATH=tools python3 -m bg3se_harness status

# Full launch: build + patch + launch + health check
PYTHONPATH=tools python3 -m bg3se_harness launch

# Run regression tests (game must be running)
PYTHONPATH=tools python3 -m bg3se_harness test

# Send arbitrary Lua
PYTHONPATH=tools python3 -m bg3se_harness run "Ext.GetVersion()"
```

## Commands

The harness exposes 36 subcommands grouped by workflow stage.  Every command
emits JSON to stdout so it composes with `jq`, test pipelines, and agent
tooling.

### Core pipeline

| Command | Description |
|---------|-------------|
| `status` | Check if BG3 is running, socket alive, binary patched |
| `build` | Build dylib via cmake, verify universal binary, deploy to Steam folder |
| `patch` | Inject libbg3se.dylib into BG3 binary via insert_dylib |
| `unpatch` | Restore original BG3 binary from backup |
| `launch [--continue\|--save NAME]` | Build + patch + launch + socket health check |
| `test [filter]` | Tier 1 regression tests, output structured JSON |
| `test --tier 2 [filter]` | Tier 2 in-game tests (requires loaded save) |
| `run "<lua>"` | Send inline Lua to the running game via socket |
| `eval script.lua` | Run a Lua file (stdin `-` for piping) |
| `watch script.lua` | Hot-reload on file change |

### Game inspection

| Command | Description |
|---------|-------------|
| `entity <GUID> [--component X]` | Inspect an entity and its components |
| `stats <name> [--diff OTHER]` | RPGStats object fields, optionally diffed against another |
| `components [--namespace eoc]` | List registered component types (1,999+) |
| `probe <0xADDR> [--classify]` | Memory inspection with pointer classification |
| `dump spells\|items\|passives\|...` | Bulk extract game data |
| `events --subscribe SessionLoaded` | Stream engine events as JSONL |
| `screenshot` | Game window capture (Claude-Code-safe JPEG) |

### Diagnostics & performance

| Command | Description |
|---------|-------------|
| `crashlog` | Parse the mmap crash ring buffer (works without a socket) |
| `benchmark "<lua>"` | Measure per-call cost of a Lua fragment |
| `diff-test base.json curr.json` | Compare two `test` JSON outputs |
| `doctor` | Verify every prerequisite (SDK, BG3 install, launcher flag, codesign) |
| `save list` | Available saves with metadata |

### Mod management

| Command | Description |
|---------|-------------|
| `mod list` | Installed mods + enabled/SE status |
| `mod install <path\|nexus:ID>` | Install from a local PAK or Nexus mod id |
| `mod enable <name>` / `mod disable <name>` | Toggle in `modsettings.lsx` |
| `mod remove <name>` | Uninstall by mod name |
| `mod info <source>` | Inspect a PAK file or Nexus mod id |
| `mod order --move X --before Y` | Reorder the load order |
| `mod search <query>` | Nexus Mods search (falls back to updated + client filter) |
| `mod backup` | Snapshot `modsettings.lsx` |

### Web integrations (Nexus + bg3.wiki)

All web commands use stdlib `urllib.request` (no external HTTP deps), return
the canonical harness error envelope on failure, and cache wiki results for
24h in `~/.config/bg3se-harness/wiki_cache/` (0o700).

| Command | Description |
|---------|-------------|
| `mod changelog <id>` | Nexus `/changelogs.json` — HTML stripped, newest version first |
| `mod versions <id>` | Nexus `/files.json` — file_id, version, category, size, timestamps |
| `mod updated --period 1d\|1w\|1m` | Nexus `/updated.json` — recently updated mods |
| `wiki spell "<name>"` | bg3.wiki `{{Feature page}}` / `{{Spell page}}` template fields |
| `wiki item "<name>"` | bg3.wiki `{{WeaponPage}}` / `{{ArmourPage}}` / `{{EquipmentPage}}` fields |
| `wiki verify "<page>" [--expect-uid UID]` | Fetch a page and optionally match its engine `uid` field |
| `wiki clear-cache` | Wipe the 24h wiki cache directory |

Both the Nexus and the wiki clients use a tolerant version sort key that
handles SemVer, ISO dates, and month-name date strings (`2024April-30`), so
`mod changelog` returns entries newest-first regardless of format.  HTTP 403s
on Nexus are classified path-aware: `/users/...` paths are always auth
errors, per-mod detail paths (`/mods/<id>`) default to `content_restricted`
(a hidden or moderated mod), and collection endpoints (`/mods/search.json`,
`/mods/updated.json`) fall through to the auth fallback.

**Wiki verify scope note.**  `wiki verify` is an offline field printer with
an optional `--expect-uid` string match.  The runtime-diff variant that calls
`Ext.Stats.Get(name)` on a live game and compares the two structures
(originally planned at
`~/.claude/plans/2026-04-06-bg3se-harness-opencli-integration.md`) remains a
follow-up.

### Parity, compatibility & build tooling

| Command | Description |
|---------|-------------|
| `parity scan` / `parity missing` | Compare Ext table vs Windows baseline |
| `compat list` / `compat run mcm` | Autonomous mod compat scenarios |
| `author new MyMod` | Scaffold a new mod directory |
| `menu detect` / `menu click "Continue"` | Vision OCR + CGEvent main-menu automation |
| `flags [--group X]` | 40 discovered BG3 CLI flags |
| `ghidra decompile <name\|0xADDR>` | Ghidra HTTP bridge (requires running Ghidra + GhidraMCP) |

## How Injection Works

Traditional `DYLD_INSERT_LIBRARIES` injection is fragile—SIP, Hardened Runtime, and Steam's process chain can silently strip the environment variable. The harness replaces this with **static Mach-O patching** via `insert_dylib`:

1. `insert_dylib` adds an `LC_LOAD_WEAK_DYLIB` load command to the BG3 binary
2. The binary is ad-hoc codesigned after patching
3. On launch, dyld automatically loads libbg3se.dylib—no environment variables needed
4. `--weak` linking means a missing dylib won't crash the game

### Idempotency

- `patch` checks `otool -L` before patching—skips if already done
- A SHA-256 hash of the patched binary is stored alongside it
- Game updates detected by hash mismatch → automatic re-patch from backup

### Reversibility

```bash
PYTHONPATH=tools python3 -m bg3se_harness unpatch
```

Restores the original binary from the `.bg3se-original` backup.

## Test Output

`test` returns structured JSON:

```json
{
  "tier": 1,
  "filter": null,
  "tests": [
    {"name": "Core.Print", "status": "pass", "ms": 2, "error": null, "index": 1, "total": 85},
    {"name": "Stats.Bad", "status": "fail", "ms": 5, "error": "Expected string, got nil", "index": 3, "total": 85}
  ],
  "summary": {"passed": 83, "failed": 2, "skipped": 0, "total": 85, "elapsed_ms": 142},
  "all_passed": false
}
```

Filter by category: `test Stats` runs only tests matching "Stats".

## Architecture

```
tools/bg3se_harness/
├── __init__.py
├── __main__.py         # entry point
├── cli.py              # argparse subcommands + handler dispatch
├── config.py           # paths, timeouts, defaults
├── build.py            # cmake build + verify + deploy
├── patch.py            # insert_dylib + codesign
├── launch.py           # direct launch + socket health check
├── console.py          # Python socket IPC client
├── test_runner.py      # test execution + output parsing
├── menu.py             # vision-based save loading (Claude Computer Use)
├── wiki.py             # bg3.wiki MediaWiki client (opensearch + parse, 24h file cache)
├── ghidra.py           # Ghidra HTTP bridge wrapper
├── mod_cli.py          # mod subcommand dispatcher
└── mod_manager/
    ├── nexus.py        # Nexus Mods API v1 (search, info, files, changelogs, updated)
    ├── installer.py    # Local PAK install/uninstall
    ├── modsettings.py  # modsettings.lsx enable/disable/backup
    ├── registry.py     # Installed-mod registry
    └── pak_inspector.py # PAK metadata extraction
```

### Design conventions

* **Error envelope.**  Every HTTP client returns either a success dict or
  `{"success": False, "error_type": str, "message": str, ...}`.
  `error_type` values: `validation_error`, `auth_error`, `api_error`,
  `content_restricted`, `premium_required`, `not_found`,
  `template_not_found`, `network_error`, `internal_error`, `cache_error`.
* **Stdlib-only web.**  `nexus.py` and `wiki.py` use `urllib.request` rather
  than `requests`/`httpx` so the harness has no optional Python
  dependencies.
* **JSON on stdout.**  Every subcommand prints a single JSON document.
  Exit code 1 on `{"success": False}`, 0 on success or happy-path dicts
  without an explicit success flag.
* **Offline tests.**  `tests_nexus.py` and `tests_wiki.py` monkey-patch
  `urllib.request.urlopen` with canned fixtures — run them with
  `PYTHONPATH=tools python3 -m bg3se_harness.tests_nexus` and
  `tests_wiki`.

## Dependencies

- **insert_dylib** (C, tyilo/insert_dylib): Built from `tools/vendor/insert_dylib/`
- **Python 3.10+**
- **BG3** installed via Steam
- **bg3se-macos** dylib (built by cmake)

## Troubleshooting

**Binary not patched after game update:** Run `patch` again—it detects the hash change and re-patches from the updated binary.

**Socket timeout:** The health check polls `/tmp/bg3se.sock` for 30s. If BG3 is slow to start, use `--timeout 60`.

**Codesign warnings:** Ad-hoc signing may warn about subcomponents (log files in MacOS/). These are harmless—the binary itself is signed correctly.

**Steam re-downloads binary:** If you run "Verify Integrity of Game Files" in Steam, it will replace the patched binary. Run `patch` again afterward.
