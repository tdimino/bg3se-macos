---
title: "feat: BG3SE Harness Modding Toolkit — 12 New Commands"
type: feat
status: active
date: 2026-03-30
origin: docs/plans/2026-03-28-001-feat-bg3se-cli-autonomous-pipeline-expansion-plan.md
---

# feat: BG3SE Harness Modding Toolkit — 12 New Commands

## Overview

Expand bg3se-harness from 9 commands to 21 with a full modding toolkit: entity/stats inspection, game data extraction, hot-reload development, screenshot automation with Claude Code safeguards, crash diagnostics, memory probing, benchmarking, and CI regression comparison. All commands follow the existing JSON-stdout / stderr-narration convention and compose with shell pipelines.

Based on Nomos blueprint (2026-03-29) and Claude Code image limit research (Exa, 2026-03-30).

## Problem Statement / Motivation

The harness handles build/patch/launch/test but offers no help with the actual mod development workflow. Modders currently write ad-hoc multi-line Lua in the console for every inspection, have no hot-reload, can't extract game data in bulk, and can't pass screenshots to Claude Code without manual resizing and token management. 12 new commands close these gaps.

## Proposed Solution

### Architecture

```
tools/bg3se_harness/
  # Existing (unchanged)
  cli.py, config.py, console.py, build.py, patch.py,
  launch.py, test_runner.py, flags.py, ghidra.py, menu.py

  # New modules (12 commands)
  screenshot.py        # P0: Game window capture + Claude Code safeguards
  eval.py              # P0: Execute Lua file/stdin
  entity_inspect.py    # P0: Entity + entity-search + components
  stats_inspect.py     # P0: Stats inspection + diff
  watch.py             # P1: Hot-reload Lua on file change
  dump.py              # P1: Bulk game data extraction
  crashlog.py          # P1: Crash ring buffer + log parser
  benchmark.py         # P2: Lua performance measurement
  events.py            # P2: Game event streaming (JSONL)
  diff_test.py         # P2: Test baseline comparison
  probe.py             # P2: Memory inspection via Ext.Debug

  # Support
  lua_templates/       # Separated Lua code (editable/testable independently)
```

### Implementation Phases

#### Phase 1: P0 Commands (4 commands, ~280 lines)

##### 1.1 `screenshot` — `screenshot.py` (~80 lines)

Captures BG3 game window via `screencapture -l <windowid>`. Auto-resizes for Claude Code safety.

```
bg3se-harness screenshot                     # → game-modding/bg3/bg3se-macos/.screenshots/latest.jpg
bg3se-harness screenshot --output path.png   # specific path
bg3se-harness screenshot --raw               # skip resize (full resolution PNG)
```

**Claude Code Image Safeguards** (from Exa research):

| Constraint | Source | Safeguard |
|-----------|--------|-----------|
| Images >8000px crash sessions permanently | anthropics/claude-code#29969 | Enforce 1568px max on longest edge |
| Each image = `(w×h)/750` tokens, persists after compaction | anthropics/claude-code#27869 | JPEG 80% quality (~5x smaller than PNG for game screenshots) |
| Accumulated screenshots drain context fast | Reddit r/ClaudeCode Jan 2026 | Single rolling file at `.screenshots/latest.jpg` — overwrite, never accumulate |
| No per-conversation image limit in CLI, but context fills | General | Print token estimate to stderr: `[screenshot: ~1,600 tokens, 1568x882]` |

**Implementation:**
```python
def capture(output=None, raw=False):
    # 1. Get BG3 window ID via osascript
    wid = subprocess.check_output([
        "osascript", "-e",
        'tell app "System Events" to get id of window 1 of process "Baldur\'s Gate 3"'
    ]).strip()

    # 2. Capture to temp PNG
    tmp = "/tmp/bg3_screenshot_raw.png"
    subprocess.run(["screencapture", "-l", wid, "-x", "-o", tmp])

    # 3. Resize + compress (unless --raw)
    if not raw:
        # sips: resize longest edge to 1568px, convert to JPEG 80%
        subprocess.run(["sips", "--resampleHeightWidthMax", "1568",
                       "--setProperty", "formatOptions", "80",
                       "-s", "format", "jpeg", tmp, "--out", dest])

    # 4. Print token estimate to stderr
    # 5. Return JSON: {path, width, height, tokens_est, size_bytes}
```

**Files:** `screenshot.py`, `cli.py` (add subcommand)

##### 1.2 `eval` — `eval.py` (~20 lines)

Execute Lua from file or stdin. Thin wrapper enabling piping.

```
bg3se-harness eval script.lua                    # execute file
echo 'return Ext.Stats.GetAll("Weapon")' | bg3se-harness eval -   # stdin
cat gen.py | python3 | bg3se-harness eval -      # pipeline
```

**Implementation:** Read file/stdin → `Console.send_lua()` → print output.

**Files:** `eval.py`, `cli.py`

##### 1.3 `entity` — `entity_inspect.py` (~100 lines)

Inspect game entities by GUID or character name.

```
bg3se-harness entity S_Player_Karlach                    # list all components
bg3se-harness entity S_Player_Karlach --component Stats  # dump one component
bg3se-harness entity S_Player_Karlach --depth 2          # control JSON depth
```

**Lua API:** `Ext.Entity.Get(guid)`, `e:GetAllComponents()`, `Ext.Json.Stringify(component, {MaxDepth=N})`

**Composition:**
```bash
diff <(bg3se-harness entity Karlach --component Stats) \
     <(bg3se-harness entity Shadowheart --component Stats)
```

**Files:** `entity_inspect.py`, `lua_templates/entity_get.lua`, `cli.py`

##### 1.4 `stats` — `stats_inspect.py` (~80 lines)

Dump RPG stat entries with optional diff.

```
bg3se-harness stats WPN_Longsword                        # dump stat
bg3se-harness stats --all Weapon                         # list all weapon stats
bg3se-harness stats WPN_Longsword --diff WPN_Greatsword  # show differences only
```

**Lua API:** `Ext.Stats.Get(name)`, `Ext.Stats.GetAll(type)`, property iteration + diff via Lua pairs.

**Files:** `stats_inspect.py`, `lua_templates/stats_get.lua`, `lua_templates/stats_diff.lua`, `cli.py`

#### Phase 2: P1 Commands (4 commands, ~470 lines)

##### 2.1 `watch` — `watch.py` (~120 lines)

Hot-reload Lua on file change. The mod development loop accelerator.

```
bg3se-harness watch my_mod/test.lua               # watch + execute on change
bg3se-harness watch my_mod/bootstrap.lua --once    # execute once (CI)
bg3se-harness watch my_mod/ --pattern "*.lua"      # watch directory
```

**Implementation:** `os.stat()` polling at 500ms interval. On mtime change: read file → `Console.send_lua()` → print output. Ctrl+C to stop.

**Files:** `watch.py`, `cli.py`

##### 2.2 `dump` — `dump.py` (~150 lines)

Bulk extract game data to JSON files.

```
bg3se-harness dump feats                           # all feat definitions
bg3se-harness dump spells --output ./data/         # to specific directory
bg3se-harness dump all                             # everything
bg3se-harness dump weapons --format csv            # CSV output
```

**Categories (11):**

| Category | Lua API |
|----------|---------|
| `feats` | `Ext.StaticData.GetAll("Feat")` |
| `races` | `Ext.StaticData.GetAll("Race")` |
| `classes` | `Ext.StaticData.GetAll("Class")` |
| `spells` | `Ext.Stats.GetAll("SpellData")` |
| `weapons` | `Ext.Stats.GetAll("Weapon")` |
| `armor` | `Ext.Stats.GetAll("Armor")` |
| `statuses` | `Ext.Stats.GetAll("StatusData")` |
| `passives` | `Ext.Stats.GetAll("PassiveData")` |
| `resources` | `Ext.Resource.GetAll(type)` (34 types) |
| `templates` | `Ext.Template.*` |
| `all` | Everything above |

**Files:** `dump.py`, `lua_templates/dump_category.lua`, `cli.py`

##### 2.3 `crashlog` — `crashlog.py` (~130 lines)

Parse BG3SE crash diagnostics. **No socket needed** — game is crashed.

```
bg3se-harness crashlog                             # latest crash summary (JSON)
bg3se-harness crashlog --ring                      # decode crash ring buffer
bg3se-harness crashlog --tail 50                   # last 50 log lines before crash
```

**Sources:**
- `~/Library/Application Support/BG3SE/crash_ring_<pid>.bin` (mmap'd 16KB ring buffer)
- `~/Library/Application Support/BG3SE/crash.log` (signal handler output)
- `~/Library/Application Support/BG3SE/logs/latest.log` (session log)

**JSON output:**
```json
{
  "signal": "SIGSEGV",
  "fault_address": "0x10",
  "breadcrumbs": [...],
  "backtrace": [...],
  "last_log_lines": [...],
  "crash_time": "2026-03-30T12:34:56"
}
```

**Files:** `crashlog.py`, `cli.py`

##### 2.4 `components` — `entity_inspect.py` (extends, ~70 lines)

List all 1,999 registered component types.

```
bg3se-harness components                           # list all
bg3se-harness components --namespace eoc           # filter by namespace
bg3se-harness components --search "Health"         # search by name
bg3se-harness components --count                   # count per namespace
```

**Lua API:** `Ext.Types.GetAllTypes()` + `Ext.Types.GetTypeInfo(t)` filtered to Kind == "Component".

**Files:** `entity_inspect.py` (shared module), `cli.py`

#### Phase 3: P2 Commands (4 commands, ~390 lines)

##### 3.1 `benchmark` — `benchmark.py` (~100 lines)

Benchmark Lua code execution inside the game engine.

```
bg3se-harness benchmark "Ext.Stats.Get('WPN_Longsword')" --iterations 1000
bg3se-harness benchmark --file perf_suite.lua --warmup 10
```

**Output:** JSON with min/max/mean/p50/p95/p99 in milliseconds. Uses `Ext.Debug.Timestamp()` for timing.

**CI composition:**
```bash
bg3se-harness benchmark --file perf.lua > baseline.json
# ... make changes ...
bg3se-harness benchmark --file perf.lua > current.json
bg3se-harness diff-test baseline.json --threshold 20
```

**Files:** `benchmark.py`, `lua_templates/benchmark_wrapper.lua`, `cli.py`

##### 3.2 `events` — `events.py` (~150 lines)

Subscribe to game events and stream as JSONL.

```
bg3se-harness events --list                        # list all 33 events
bg3se-harness events --subscribe SessionLoaded     # stream occurrences
bg3se-harness events --subscribe SessionLoaded --listen 30  # 30 second window
```

**Requires Console extension:** `Console.stream()` — continuous reading with line callback.

**Files:** `events.py`, `lua_templates/event_subscribe.lua`, `console.py` (add `stream()`), `cli.py`

##### 3.3 `diff-test` — `diff_test.py` (~80 lines)

Compare current test results against a saved baseline. Pure Python — no socket.

```
bg3se-harness test > baseline.json
# ... make changes ...
bg3se-harness test > current.json
bg3se-harness diff-test baseline.json current.json --threshold 50
```

**Output:**
```json
{
  "new_failures": ["Stats.NewBug"],
  "new_passes": ["Entity.WasFlaky"],
  "timing_regressions": [{"name": "...", "baseline_ms": 5, "current_ms": 15}],
  "missing_tests": [],
  "verdict": "REGRESSION"
}
```

**Files:** `diff_test.py`, `cli.py`

##### 3.4 `probe` — `probe.py` (~60 lines)

Memory inspection via Ext.Debug API.

```
bg3se-harness probe 0x10898e8b8                    # hex dump
bg3se-harness probe 0x10898e8b8 --range 256 --stride 8  # struct probe
bg3se-harness probe 0x10898e8b8 --classify         # pointer classification
```

**Lua API:** `Ext.Debug.HexDump()`, `Ext.Debug.ProbeStruct()`, `Ext.Debug.ClassifyPointer()`

**Files:** `probe.py`, `lua_templates/probe_struct.lua`, `cli.py`

## System-Wide Impact

### Interaction Graph
- All inspection commands (`entity`, `stats`, `components`, `probe`, `benchmark`, `events`) → `Console.send_lua()` → socket IPC → SE Lua VM → JSON stdout
- `screenshot` → `osascript` (window ID) → `screencapture` → `sips` (resize) → JPEG file
- `crashlog`, `diff-test` → pure file I/O, no socket needed
- `watch` → `os.stat()` polling → `Console.send_lua()` on change → output loop
- `eval` → file/stdin read → `Console.send_lua()` → output
- `dump` → `Console.send_lua()` per category → file write

### Error Propagation
- Socket not connected: all socket commands return `{"error": "Socket connection failed: ..."}` and exit 1
- BG3 not running: `screenshot` returns `{"error": "BG3 window not found"}`
- Invalid GUID/stat name: Lua error message captured and returned in JSON `error` field
- Crash log missing: `crashlog` returns `{"error": "No crash data found"}`

### State Lifecycle Risks
- `watch` loop must handle socket disconnect gracefully (reconnect on next change)
- `events --subscribe` must unsubscribe on Ctrl+C (send cleanup Lua)
- `dump all` generates many socket requests — add rate limiting to avoid overwhelming the console
- `screenshot` overwrites `latest.jpg` — no accumulation risk

### API Surface Parity
- All new commands are Python-only — no C code changes needed
- Socket IPC protocol unchanged
- Lua templates are sent as strings, not compiled into the SE

## Acceptance Criteria

### Functional Requirements

**P0:**
- [ ] `screenshot` captures BG3 window, resizes to ≤1568px, outputs JPEG, prints token estimate
- [ ] `eval script.lua` executes Lua file in-game, returns output
- [ ] `eval -` reads from stdin
- [ ] `entity <GUID>` lists all components as JSON
- [ ] `entity <GUID> --component X` dumps specific component
- [ ] `stats <name>` dumps stat entry as JSON
- [ ] `stats <name> --diff <other>` shows only differing properties

**P1:**
- [ ] `watch <file>` re-executes on save, outputs results
- [ ] `dump <category>` extracts game data to JSON
- [ ] `crashlog` parses crash ring buffer and log into structured JSON
- [ ] `components` lists all 1,999 types with namespace filtering

**P2:**
- [ ] `benchmark` reports min/max/mean/p50/p95/p99
- [ ] `events --subscribe <name>` streams JSONL to stdout
- [ ] `diff-test` compares two test result files, reports regressions
- [ ] `probe` performs hex dump / struct probe / pointer classification

### Non-Functional Requirements
- [ ] All commands output valid JSON to stdout
- [ ] Screenshot ≤1568px on longest edge, JPEG 80% quality
- [ ] Token estimate printed to stderr for every screenshot
- [ ] No command exceeds 150 lines of Python
- [ ] Lua templates separated into `lua_templates/` directory

### Quality Gates
- [ ] All existing commands still work (no regression)
- [ ] `--help` text for every new subcommand
- [ ] SKILL.md updated with all 21 commands
- [ ] CLAUDE.md updated with new command reference

## Dependencies & Prerequisites

| Dependency | Status | Notes |
|-----------|--------|-------|
| bg3se-harness (Phase 1-3) | **Done** | 9 commands working |
| Console socket IPC | **Done** | `send()` and `send_lua()` working |
| `screencapture` | **Available** | macOS built-in, `-l <windowid>` |
| `sips` | **Available** | macOS built-in, image resize/convert |
| Ext.Entity API | **Available** | 1,999 components, Get/GetComponent |
| Ext.Stats API | **Available** | 52 functions, full parity |
| Ext.Debug API | **Available** | ReadPtr, ProbeStruct, HexDump |
| Ext.Events | **Available** | 33 events with Subscribe |
| Crash ring buffer | **Available** | mmap'd 16KB at `~/Library/Application Support/BG3SE/` |

## Risk Analysis & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Large Lua output exceeds socket buffer | Medium | Chunk large dumps, add `--limit` flag |
| `watch` polling misses rapid saves | Low | 500ms interval is fast enough for manual editing |
| `events --subscribe` leaks subscribers | Medium | Send unsubscribe Lua on Ctrl+C via signal handler |
| `screenshot` window ID changes between launches | Low | Re-query window ID on every capture |
| Game-specific Lua errors in templates | Medium | Wrap all templates in pcall, return structured errors |

## Future Considerations

1. **`entity-search`** (P3): Search entities by component presence or name pattern
2. **`mod` command**: List/inspect loaded mods (Ext.Mod.* is read-only)
3. **`profile`**: CPU profiling via `debug.sethook` (conflicts with SE internals — deferred)
4. **Screenshot diff**: Compare two screenshots for visual regression (ImageMagick `compare`)
5. **CI pipeline**: `test → diff-test → screenshot → benchmark` as a single `ci` meta-command

## Documentation Plan

| File | Update |
|------|--------|
| `CLAUDE.md` | Add all 12 new commands to harness reference |
| `SKILL.md` | Rewrite with 21-command reference + modding workflow examples |
| `docs/harness.md` | Full CLI reference for all commands |
| `docs/plans/` | This plan |

## Sources & References

### Origin
- **Origin document:** [docs/plans/2026-03-28-001-feat-bg3se-cli-autonomous-pipeline-expansion-plan.md](docs/plans/2026-03-28-001-feat-bg3se-cli-autonomous-pipeline-expansion-plan.md) — Built the 9-command harness with flags, ghidra, and autonomous launch.

### Internal References
- Nomos blueprint (2026-03-29): 12 commands designed against existing architecture
- Console IPC: `tools/bg3se_harness/console.py` (send, send_lua, context manager)
- Flags registry: `tools/bg3se_harness/flags.py` (40 flags, validation)
- Ghidra bridge: `tools/bg3se_harness/ghidra.py` (HTTP client)
- Crash diagnostics: `src/core/crashlog.c` (ring buffer format)
- Test runner: `tools/bg3se_harness/test_runner.py` (JSON output format)
- SE Lua APIs: `src/lua/lua_*.c` (all Ext.* implementations)

### External References — Claude Code Image Limits
- anthropics/claude-code#27869: Chrome MCP screenshots accumulate, 17% of Max plan for 5 turns
- anthropics/claude-code#23446: Oversized images (>2000px) break sessions permanently
- anthropics/claude-code#29969: >8000px images cause unrecoverable 400 loop after compaction
- anthropics/claude-code#29259: No recovery path for oversized image in conversation
- Reddit r/ClaudeCode (Jan 2026): Image token formula = (w×h)/750, auto-resize at 1568px
