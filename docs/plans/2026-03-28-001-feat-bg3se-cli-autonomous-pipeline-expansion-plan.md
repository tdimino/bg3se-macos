---
title: "feat: BG3SE CLI Autonomous Pipeline Expansion"
type: feat
status: completed
date: 2026-03-28
origin: docs/plans/2026-03-27-001-feat-bg3se-autonomous-test-harness-plan.md
---

# feat: BG3SE CLI Autonomous Pipeline Expansion

## Context

Yesterday's plan (`2026-03-27-001`) built the bg3se-harness with 7 commands for build/patch/launch/test/run/status/unpatch. Today we discovered **38 command-line flags** embedded in the BG3 macOS binary via Ghidra reverse engineering, including two that eliminate the need for vision-based menu navigation entirely:

- **`-continueGame`** — auto-loads the most recent save, bypasses main menu
- **`-loadSaveGame`** — loads a specific save by name

We also confirmed the Ghidra HTTP bridge is live on `http://127.0.0.1:8080/` with **135+ endpoints** for decompilation, string search, xref analysis, function renaming, struct creation, and more — accessible via `curl` even when the MCP wrapper fails to connect.

This plan expands the harness CLI into a **full autonomous pipeline** (build → patch → launch with auto-save-load → test → report, zero human interaction) and integrates Ghidra RE capabilities for ongoing parity work.

## Problem Statement / Motivation

1. **Menu navigation was the last manual step.** The previous plan used vision-based automation (Claude Computer Use) to click through menus — fragile and non-deterministic. `-continueGame` makes this obsolete.
2. **38 game flags are undocumented.** No public documentation exists for BG3's CLI flags. We discovered them via binary string extraction. They enable debug modes, save system diagnostics, story logging, and more.
3. **Ghidra is underutilized.** The HTTP bridge has 135+ endpoints but no CLI integration. RE sessions currently require manual curl commands.
4. **The skill and docs are stale.** The bg3se-harness SKILL.md still references vision-based menu navigation, and `~/.claude/agent_docs/tools.md` doesn't document the Ghidra HTTP bridge workaround.

## Proposed Solution

Expand bg3se-harness in 5 phases:

```
Phase 0: Doc updates (Ghidra bridge workaround, CLAUDE.md, tools.md)
Phase 1: Autonomous launch with -continueGame/-loadSaveGame
Phase 2: Expose all 38 game CLI flags via harness
Phase 3: Ghidra RE integration (decompile, search, xref commands)
Phase 4: Skill update via skill-optimizer
Phase 5: Verification + end-to-end test
```

## Technical Approach

### Architecture (Post-Expansion)

```
tools/bg3se_harness/
├── __init__.py
├── __main__.py           # entry: python -m bg3se_harness
├── cli.py                # argparse with expanded subcommands
├── config.py             # paths, timeouts, game flags registry
├── build.py              # cmake build + verify + deploy
├── patch.py              # insert_dylib + codesign + backup
├── launch.py             # EXPANDED: game flags, -continueGame, -loadSaveGame
├── console.py            # socket IPC client (reuse as-is)
├── test_runner.py         # test execution + JSON parsing
├── ghidra.py             # NEW: Ghidra HTTP bridge client
├── flags.py              # NEW: game flag registry + validation
└── menu.py               # DEPRECATED: kept for fallback only
```

### Discovered BG3 CLI Flags (Complete Inventory)

**Binary source:** `strings -a "$BG3_EXEC" | grep -E "^-[a-z][a-zA-Z]{3,}" | sort -u`

#### Launch & Save Control
| Flag | Purpose | Arg? | Priority |
|------|---------|------|----------|
| `-continueGame` | Auto-continue most recent save | No | **P0** |
| `-loadSaveGame` | Load specific save game | Yes (name) | **P0** |
| `-load` | Generic load | Unknown | P2 |
| `-testLoadLevel` | Test level loading | Unknown | P1 |

#### Mod & Story
| Flag | Purpose | Arg? | Priority |
|------|---------|------|----------|
| `-module` | Specify module to load | Yes | P1 |
| `-modded` | Enable modded mode | No | P1 |
| `-modEnv` | Mod environment | Yes | P2 |
| `-dynamicStory` | Dynamic story mode | No | P2 |
| `-saveStoryState` | Save story state on exit | No | P2 |
| `-storylog` | Enable story logging | No | P1 |

#### Debug & Developer
| Flag | Purpose | Arg? | Priority |
|------|---------|------|----------|
| `-stats` | Stats output | No | P1 |
| `-json` | JSON output mode | No | P1 |
| `-osi` | Osiris debug | No | P1 |
| `-crash` | Crash reporting mode | No | P2 |
| `-syslog` | System logging | No | P2 |
| `-combatTimelines` | Combat timeline debug | No | P2 |
| `-toggleCrowds` | Toggle NPC crowds | No | P2 |
| `-testAIStart` | Test AI start | No | P2 |
| `-newexposure` | New exposure settings | No | P3 |
| `-dummyValue` | Dummy test value | Yes | P3 |

#### System & Graphics
| Flag | Purpose | Arg? | Priority |
|------|---------|------|----------|
| `-detailLevel` | Graphics detail level | Yes | P2 |
| `-startInControllerMode` | Controller vs KB/M | No | P2 |
| `-mediaPath` | Media/assets path | Yes | P3 |
| `-photoModeScreenshotsPath` | Screenshot path | Yes | P3 |
| `-enableClientNewECSScheduler` | New ECS scheduler | No | P2 |

#### Network
| Flag | Purpose | Arg? | Priority |
|------|---------|------|----------|
| `-lariannetEnv` | Larian network environment | Yes | P2 |

#### Localization
| Flag | Purpose | Arg? | Priority |
|------|---------|------|----------|
| `-locaLanguage` | Language setting | Yes | P2 |
| `-locaCloseOnErrors` | Close on localization errors | No | P3 |
| `-locaupdater` | Localization updater | No | P3 |

#### Save System Debug (ECB Checker)
| Flag | Purpose | Arg? | Priority |
|------|---------|------|----------|
| `-useSaveSystemECBChecker` | Enable ECB checker | No | P2 |
| `-saveSystemECBCheckerEnableLogging` | ECB logging | No | P2 |
| `-saveSystemECBCheckerEnableDetailedLogging` | Detailed ECB logging | No | P3 |
| `-saveSystemECBCheckerAllowSaveOnFailure` | Allow save on ECB fail | No | P3 |
| `-saveSystemECBCheckerLogSuccessfulAttempts` | Log successful saves | No | P3 |
| `-saveSystemECBCheckNumberOfFramesToWait` | Frames before check | Yes | P3 |

#### Double-Dash Flags
| Flag | Purpose | Arg? | Priority |
|------|---------|------|----------|
| `--skip-launcher` | Bypass Larian launcher | No | **P0** (already used) |
| `--logPath` | Log file path | Yes | P1 |
| `--cpuLimit` | CPU usage limit | Yes | P2 |
| `--closeOnErrors` | Close on errors | No | P2 |
| `--nodb` | No database | No | P2 |
| `--noxml` | No XML | No | P3 |

**Critical string context from binary:**
```
-loadSaveGame
-continueGame
GameStateInit: These commands should be mutually exclusive
```
This confirms `-loadSaveGame` and `-continueGame` are **mutually exclusive** — the game validates this at `GameStateInit`.

### Implementation Phases

#### Phase 0: Documentation Updates (files: 3)

**Goal:** Update stale docs before any code changes.

**Tasks:**
- [ ] **`~/.claude/agent_docs/tools.md`** — Add Ghidra HTTP bridge section:
  ```
  ## Ghidra RE (via HTTP Bridge)
  - **Bridge**: GhidraMCP HTTP server at `http://127.0.0.1:8080/`
  - **Workaround**: MCP wrapper may fail to connect; use curl directly
  - **135+ endpoints**: decompile, search, xref, rename, struct, analysis
  - **Key endpoints**: /decompile_function, /search_strings, /get_xrefs_to,
    /list_functions, /batch_decompile, /search_functions
  - **Setup**: Ghidra must be running with GhidraMCP plugin + BG3 binary loaded
  ```

- [ ] **`game-modding/bg3/bg3se-macos/CLAUDE.md`** — Add:
  - Ghidra HTTP bridge section with curl examples
  - Complete CLI flag inventory (the 38 flags table above)
  - Note: `-continueGame` and `-loadSaveGame` for autonomous launch
  - Update harness commands to include new ones from this plan

- [ ] **`game-modding/bg3/bg3se-macos/ghidra/offsets/CLI_FLAGS.md`** — New offset doc:
  - Document all 38 flags with binary string addresses
  - Document the `GameStateInit` mutual exclusion behavior
  - Note the Noesis UI JavaScript bridge (`continueGame: function(args)`)
  - Record the `runGame:arm64` and `continueGame:arm64` entry points

**Success criteria:** All three docs updated and accurate.

#### Phase 1: Autonomous Launch Pipeline (files: 3)

**Goal:** `bg3se-harness launch --continue` starts BG3, auto-loads most recent save, confirms running state via socket. Zero human interaction.

**Tasks:**
- [ ] **`tools/bg3se_harness/flags.py`** — New module: Game flag registry
  ```python
  # Registry of all known BG3 CLI flags with metadata
  GAME_FLAGS = {
      "continueGame": Flag(name="-continueGame", arg=False, group="launch",
          description="Auto-continue most recent save"),
      "loadSaveGame": Flag(name="-loadSaveGame", arg=True, group="launch",
          description="Load specific save game by name"),
      "module": Flag(name="-module", arg=True, group="mod"),
      "modded": Flag(name="-modded", arg=False, group="mod"),
      # ... all 38 flags
  }

  MUTUALLY_EXCLUSIVE = [
      {"continueGame", "loadSaveGame"},  # GameStateInit enforces this
  ]

  def build_flag_args(flags: dict) -> list[str]:
      """Convert flag dict to command-line args list."""
      # Validates mutual exclusivity, returns ["-continueGame"] etc.
  ```

- [ ] **`tools/bg3se_harness/launch.py`** — Expand launch function:
  ```python
  def launch(continue_game=False, load_save=None, extra_flags=None):
      kill_existing()
      clean_socket()

      cmd = ["arch", "-arm64", str(BG3_EXEC), "--skip-launcher"]

      if continue_game:
          cmd.append("-continueGame")
      elif load_save:
          cmd.extend(["-loadSaveGame", load_save])

      if extra_flags:
          cmd.extend(build_flag_args(extra_flags))

      proc = subprocess.Popen(cmd, ...)
  ```

- [ ] **`tools/bg3se_harness/cli.py`** — Expand `launch` subcommand:
  ```
  bg3se-harness launch                        # launch only (main menu)
  bg3se-harness launch --continue             # auto-continue most recent save
  bg3se-harness launch --save "MySave"        # load specific save
  bg3se-harness launch --continue --storylog  # continue + enable story logging
  bg3se-harness launch --flags "-stats -json" # pass arbitrary game flags
  ```

  Also expand `test` to auto-continue:
  ```
  bg3se-harness test                          # build+patch+launch+continue+test
  bg3se-harness test --save "TestSave"        # test with specific save
  bg3se-harness test --tier 2 Stats           # tier 2 tests, Stats filter
  ```

**Success criteria:**
- `bg3se-harness launch --continue` starts BG3, auto-loads save, socket confirms Running state
- `bg3se-harness test` is fully autonomous: build → patch → launch → continue → test → JSON report
- No vision/menu navigation needed

#### Phase 2: Full Game Flag Exposure (files: 2)

**Goal:** All 38 flags accessible as named CLI arguments.

**Tasks:**
- [ ] **`tools/bg3se_harness/cli.py`** — Add flag group arguments:
  ```
  # Launch flags
  --continue          # -continueGame
  --save NAME         # -loadSaveGame NAME
  --module NAME       # -module NAME
  --modded            # -modded
  --storylog          # -storylog
  --detail-level N    # -detailLevel N
  --controller        # -startInControllerMode
  --log-path PATH     # --logPath PATH

  # Debug flags
  --stats             # -stats
  --json-mode         # -json (avoid conflict with JSON output)
  --osi-debug         # -osi
  --syslog            # -syslog
  --ecb-checker       # -useSaveSystemECBChecker + logging flags

  # Raw passthrough
  --flags "..."       # Pass arbitrary flags verbatim
  ```

- [ ] **`tools/bg3se_harness/config.py`** — Add flag-related constants:
  - `GAME_FLAGS_PATH` pointing to flags.py registry
  - `DEFAULT_LAUNCH_FLAGS` (currently just `--skip-launcher`)
  - `DEBUG_LAUNCH_FLAGS` preset (stats + json + storylog + osi)
  - `MODDED_LAUNCH_FLAGS` preset (modded + module)

  Add a new `flags` subcommand:
  ```
  bg3se-harness flags                   # list all known flags
  bg3se-harness flags --group launch    # list launch flags only
  bg3se-harness flags --group debug     # list debug flags only
  bg3se-harness flags --verify          # verify flags exist in current binary
  ```

**Success criteria:** Every discovered flag accessible via named arg or `--flags` passthrough.

#### Phase 3: Ghidra RE Integration (files: 1 new + 1 updated)

**Goal:** RE operations accessible from the harness CLI, enabling Ghidra-assisted offset discovery, function analysis, and documentation without leaving the terminal.

**Tasks:**
- [ ] **`tools/bg3se_harness/ghidra.py`** — New module: Ghidra HTTP bridge client
  ```python
  GHIDRA_URL = "http://127.0.0.1:8080"

  class GhidraBridge:
      """Client for the GhidraMCP HTTP bridge."""

      def __init__(self, base_url=GHIDRA_URL):
          self.base_url = base_url

      def is_alive(self) -> bool:
          """Check if bridge is responding."""

      def decompile(self, name_or_addr: str) -> str:
          """Decompile a function by name or address."""
          # GET /decompile_function?name=X or ?address=X

      def search_strings(self, query: str) -> list[dict]:
          """Search strings in the analyzed binary."""
          # GET /search_strings?query=X

      def search_functions(self, query: str) -> list[dict]:
          """Search function names."""
          # GET /search_functions?query=X

      def get_xrefs_to(self, address: str) -> list[dict]:
          """Get cross-references to an address."""
          # GET /get_xrefs_to?address=X

      def list_functions(self, offset=0, limit=50) -> list[dict]:
          """List functions with pagination."""
          # GET /list_functions?offset=X&limit=Y

      def batch_decompile(self, names: list[str]) -> dict:
          """Decompile multiple functions."""
          # POST /batch_decompile

      def get_function_call_graph(self, name: str, depth=2) -> dict:
          """Get call graph for a function."""
          # GET /get_function_call_graph?name=X&depth=Y
  ```

- [ ] **`tools/bg3se_harness/cli.py`** — Add `ghidra` subcommand group:
  ```
  bg3se-harness ghidra status                      # check bridge alive
  bg3se-harness ghidra decompile <name_or_addr>    # decompile function
  bg3se-harness ghidra search-strings <query>      # search strings in binary
  bg3se-harness ghidra search-functions <query>     # search function names
  bg3se-harness ghidra xrefs <address>             # find cross-references
  bg3se-harness ghidra list-functions [--offset N]  # paginated function list
  bg3se-harness ghidra call-graph <name> [--depth N] # function call graph
  bg3se-harness ghidra batch-decompile <f1> <f2>..  # decompile multiple
  ```

  **Key use cases for the CLI:**
  1. **Flag analysis:** `ghidra search-strings "continueGame"` → find address → `ghidra xrefs 0xADDR` → `ghidra decompile FUN_XXXX` to understand flag parsing
  2. **Offset discovery:** `ghidra search-functions "AddComponent"` → `ghidra batch-decompile` to extract component sizes
  3. **Parity work:** `ghidra decompile FUN_XXXX` to understand unknown functions for porting

**Available Ghidra HTTP Endpoints (135+):**

| Category | Key Endpoints |
|----------|--------------|
| **Decompilation** | `/decompile_function`, `/batch_decompile`, `/force_decompile`, `/disassemble_function` |
| **Search** | `/search_strings`, `/search_functions`, `/search_functions_enhanced`, `/search_byte_patterns`, `/search_data_types` |
| **XRefs** | `/get_xrefs_to`, `/get_xrefs_from`, `/get_function_xrefs`, `/get_bulk_xrefs` |
| **Call Graph** | `/get_function_call_graph`, `/get_full_call_graph`, `/get_function_callers`, `/get_function_callees`, `/analyze_call_graph` |
| **Functions** | `/list_functions`, `/list_functions_enhanced`, `/get_function_by_address`, `/get_function_variables`, `/get_function_count` |
| **Data Types** | `/list_data_types`, `/create_struct`, `/get_struct_layout`, `/add_struct_field`, `/get_type_size` |
| **Analysis** | `/run_analysis`, `/analyze_data_region`, `/detect_array_bounds`, `/find_similar_functions`, `/inspect_memory_content` |
| **Rename/Comment** | `/rename_function`, `/rename_variable`, `/batch_rename_variables`, `/set_decompiler_comment`, `/batch_set_comments` |
| **Labels/Bookmarks** | `/create_label`, `/list_bookmarks`, `/set_bookmark` |
| **Program** | `/list_open_programs`, `/get_current_program_info`, `/get_metadata`, `/save_program` |
| **Documentation** | `/get_function_hash`, `/get_function_documentation`, `/apply_function_documentation`, `/find_undocumented_by_string` |

**Success criteria:** Ghidra RE operations are one command away. No more manual curl.

#### Phase 4: Skill Update (files: 2)

**Goal:** Update `bg3se-harness` SKILL.md to reflect all new capabilities.

**Tasks:**
- [ ] **`~/.claude/skills/bg3se-harness/SKILL.md`** — Full rewrite:
  - Remove vision-based menu navigation section (obsoleted by `-continueGame`)
  - Add all new subcommands (launch --continue, flags, ghidra)
  - Add Ghidra integration section with examples
  - Update trigger keywords to include "ghidra", "decompile", "RE", "reverse engineer"
  - Add "Autonomous Pipeline" quickstart showing zero-interaction test run
  - Document flag presets (debug, modded, ecb-checker)

- [ ] Run **`skill-optimizer`** skill to validate and polish the SKILL.md

**Success criteria:** SKILL.md accurately reflects all CLI capabilities.

#### Phase 5: Verification (files: 0)

**Goal:** End-to-end verification of the full autonomous pipeline.

**End-to-End Test:**
```bash
cd ~/Desktop/Programming/game-modding/bg3/bg3se-macos

# 1. Full autonomous pipeline (the dream)
PYTHONPATH=tools python3 -m bg3se_harness launch --continue
# Expect: BG3 launches, auto-loads save, socket confirms Running state

# 2. Autonomous test run
PYTHONPATH=tools python3 -m bg3se_harness test --tier 1
# Expect: build → patch → launch → continue → test → JSON (85 tests)

# 3. Tier 2 tests (need loaded save — now automatic!)
PYTHONPATH=tools python3 -m bg3se_harness test --tier 2
# Expect: build → patch → launch → continue → wait for save load → test → JSON

# 4. Flag inspection
PYTHONPATH=tools python3 -m bg3se_harness flags
# Expect: All 38 flags listed with descriptions and groups

# 5. Ghidra integration
PYTHONPATH=tools python3 -m bg3se_harness ghidra status
# Expect: {"alive": true, "program": "Baldur's Gate 3", ...}

PYTHONPATH=tools python3 -m bg3se_harness ghidra search-strings "continueGame"
# Expect: string addresses

PYTHONPATH=tools python3 -m bg3se_harness ghidra decompile FUN_XXXXXXXX
# Expect: decompiled C pseudocode

# 6. Debug launch preset
PYTHONPATH=tools python3 -m bg3se_harness launch --continue --stats --storylog --osi-debug
# Expect: BG3 launches with debug flags active
```

## Alternative Approaches Considered

1. **Keep vision-based menu navigation** — Rejected. `-continueGame` is deterministic, faster, and always works. Vision was the weakest link.

2. **Integrate Ghidra via MCP only** — Rejected. MCP wrapper has connection issues (see blocker from 2026-03-27 session). HTTP bridge is reliable and already works. MCP can be a future enhancement when the connection issue is resolved.

3. **Separate CLI for Ghidra** — Rejected. Keeping everything in one harness makes the skill simpler and the workflow cohesive.

4. **Minimal expansion (just -continueGame)** — Rejected by user. The full flag inventory and Ghidra integration provide lasting value for parity work and modding.

## System-Wide Impact

### Interaction Graph
- `launch --continue` → `arch -arm64 "$BG3" --skip-launcher -continueGame` → BG3 auto-loads save → SE injects → socket → health check
- `test` → build → patch → launch --continue → wait for Running state → send `!test` → parse → JSON
- `ghidra *` → `curl http://127.0.0.1:8080/<endpoint>` → parse JSON → display

### Error Propagation
- `-continueGame` with no saves: game shows error dialog → socket never connects → timeout → structured error
- `-loadSaveGame` with invalid name: same pattern
- Ghidra bridge down: `ghidra status` returns `{"alive": false}`, all other ghidra commands fail fast

### State Lifecycle Risks
- **-continueGame + -loadSaveGame together**: BG3 itself validates mutual exclusivity at `GameStateInit`. Our `flags.py` also validates before launch.
- **Game state after -continueGame**: Need to wait longer for socket (save loading takes 10-30s). Increase default timeout for `--continue` from 30s to 90s.
- **Ghidra binary mismatch**: If Ghidra has a different binary version loaded, results are wrong. `ghidra status` should show program name + hash.

### API Surface Parity
- Socket IPC protocol unchanged
- No new C code required — all changes are in the Python harness
- Ghidra integration is read-only (no writes to the Ghidra project)

## Acceptance Criteria

### Functional Requirements
- [ ] `bg3se-harness launch --continue` starts BG3 and auto-loads most recent save
- [ ] `bg3se-harness launch --save "X"` loads a specific save
- [ ] `bg3se-harness test` is fully autonomous (zero human interaction from build to JSON report)
- [ ] `bg3se-harness test --tier 2` works with auto-loaded save
- [ ] `bg3se-harness flags` lists all 38 discovered flags
- [ ] `bg3se-harness ghidra status` confirms bridge connectivity
- [ ] `bg3se-harness ghidra decompile <X>` returns decompiled code
- [ ] `bg3se-harness ghidra search-strings <X>` returns matching strings

### Non-Functional Requirements
- [ ] Auto-continue launch completes socket health check within 90s
- [ ] All output is valid JSON to stdout (machine-parseable)
- [ ] Mutual exclusivity validated before launch (fail fast, don't send invalid flags)
- [ ] Ghidra commands fail gracefully when bridge is down

### Quality Gates
- [ ] CLAUDE.md updated with full flag inventory and Ghidra bridge docs
- [ ] `~/.claude/agent_docs/tools.md` updated with Ghidra HTTP bridge section
- [ ] `ghidra/offsets/CLI_FLAGS.md` documents all discoveries
- [ ] SKILL.md rewritten to reflect autonomous pipeline
- [ ] All existing tests still pass (no regression)

## Dependencies & Prerequisites

| Dependency | Status | Notes |
|-----------|--------|-------|
| bg3se-harness (Phase 1) | **Done** | Yesterday's plan, fully implemented |
| BG3 binary with CLI flags | **Verified** | 38 flags confirmed via `strings` |
| `-continueGame` behavior | **Confirmed** | Embedded JS shows it posts to WebKit message handler |
| Ghidra HTTP bridge | **Running** | Port 8080, 135+ endpoints, tested via curl |
| GhidraMCP plugin | **Installed** | xebyte fork with McpTool annotations |
| Python 3.10+ | **Available** | Via `uv run` |

## Risk Analysis & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| `-continueGame` doesn't work on macOS | High | Test immediately in Phase 1. Fallback: `-loadSaveGame` with most recent save name |
| `-loadSaveGame` needs exact save file path | Medium | RE the flag parsing function via Ghidra to discover expected format |
| Ghidra bridge endpoint changes | Low | Pin to current xebyte GhidraMCP version |
| Save loading takes too long for timeout | Medium | Increase timeout to 90s for `--continue`, add configurable `--timeout` |
| Some flags have unknown argument formats | Low | Phase 2 RE work: use Ghidra to decompile flag parsing for each unknown |

## Future Considerations

1. **CI/CD integration**: The fully autonomous pipeline (`test` with JSON output) can feed into GitHub Actions for automated regression testing on every commit.
2. **Ghidra MCP reconnection**: When the MCP wrapper connection issue is resolved, the `ghidra.py` module can add MCP as an alternative transport alongside HTTP.
3. **Parity acceleration**: `ghidra batch-decompile` enables parallel component size extraction (1,577 Ghidra sizes already, 922 gaps remain).
4. **Cross-binary analysis**: GhidraMCP supports `/diff_functions` and `/bulk_fuzzy_match` for comparing macOS vs Windows binaries.

## Documentation Plan

| File | Update |
|------|--------|
| `~/.claude/agent_docs/tools.md` | Ghidra HTTP bridge section |
| `game-modding/bg3/bg3se-macos/CLAUDE.md` | CLI flags, Ghidra bridge, expanded commands |
| `ghidra/offsets/CLI_FLAGS.md` | New: complete flag inventory with addresses |
| `docs/harness.md` | Expanded commands, autonomous pipeline |
| `~/.claude/skills/bg3se-harness/SKILL.md` | Full rewrite |

## Sources & References

### Origin
- **Origin document:** [docs/plans/2026-03-27-001-feat-bg3se-autonomous-test-harness-plan.md](docs/plans/2026-03-27-001-feat-bg3se-autonomous-test-harness-plan.md) — Built the 7-command harness. Key decisions: insert_dylib over DYLD, direct binary launch, modular Python architecture.

### Internal References
- Launch module: `tools/bg3se_harness/launch.py:26-37` (current launch with --skip-launcher)
- CLI entry: `tools/bg3se_harness/cli.py:114-150` (argparse structure)
- Config: `tools/bg3se_harness/config.py` (all path constants)
- Console IPC: `tools/bg3se_harness/console.py` (socket client, reusable as-is)
- Existing Ghidra scripts: `ghidra/scripts/` (40+ Python scripts for headless analysis)
- Ghidra offsets: `ghidra/offsets/` (16 offset docs, osgrep indexed)
- GhidraMCP plugin: `/Users/tomdimino/ghidra/GhidraMCP/` (135+ HTTP endpoints)
- GhidraMCP bridge: `/Users/tomdimino/ghidra/GhidraMCP/bridge_mcp_ghidra.py` (MCP→HTTP adapter)

### External References
- GhidraMCP (xebyte fork): https://github.com/xebyte/GhidraMCP
- BG3 CLI flags: Discovered via `strings -a` on macOS binary (no public docs)
- Larian Noesis UI: Embedded JavaScript in binary (`continueGame: function(args)`)

### Related Work
- Session `237cad09` (2026-03-28): Evaluated tools for game launch, hit Ghidra MCP blocker
- Session handoff: Ghidra MCP not connected → HTTP bridge workaround discovered
