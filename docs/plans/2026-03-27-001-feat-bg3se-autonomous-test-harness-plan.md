---
title: "feat: BG3SE Autonomous Test Harness CLI"
type: feat
status: active
date: 2026-03-27
origin: ~/.claude/plans/golden-weaving-crab.md
---

# feat: BG3SE Autonomous Test Harness CLI

## Overview

Build `bg3se-harness`—a Python CLI that gives Claude Code (and the developer) a single command to build, inject, launch, test, and report on bg3se-macos. Replaces the fragile DYLD_INSERT_LIBRARIES injection with static Mach-O patching via `insert_dylib`, eliminating the primary failure mode. Exposed as a Claude Code skill with full documentation in the repo and agent_docs.

## Problem Statement / Motivation

Testing bg3se-macos changes requires a manual, multi-step dance where the primary failure mode—silent DYLD variable stripping by SIP, Hardened Runtime, or Steam's process chain—wastes minutes per attempt and provides no error signal. The existing `bg3-steam-launcher` skill uses hardcoded screen coordinates and polling, making it fragile across resolutions and game states. (see origin: `~/.claude/plans/golden-weaving-crab.md`)

## Proposed Solution

An 8-layer deterministic pipeline where vision is used only for the one step that has no API (menu navigation):

```
BUILD → VERIFY → PATCH → SIGN → LAUNCH → HEALTH → MENU → TEST/RUN → REPORT
  cmake   file    insert  codesign  arch    socket  vision  socket     JSON
                  _dylib   -f -s -  -arm64  poll    (CU/    IPC        stdout
                                                     peek)
```

## Technical Approach

### Architecture

```
game-modding/bg3/bg3se-macos/
├── tools/
│   ├── bg3se-console.c          # existing socket client (keep)
│   └── bg3se-harness/           # NEW: Python CLI
│       ├── __init__.py
│       ├── __main__.py          # entry point: python -m bg3se_harness
│       ├── cli.py               # argparse subcommands
│       ├── build.py             # cmake build + verify
│       ├── patch.py             # insert_dylib + codesign
│       ├── launch.py            # direct launch + socket health check
│       ├── console.py           # socket IPC client (Python)
│       ├── test_runner.py       # send !test, parse results
│       ├── menu.py              # vision-based save loading (optional)
│       └── config.py            # paths, timeouts, defaults
├── docs/
│   └── harness.md               # user-facing CLI documentation
└── scripts/
    ├── launch_bg3.sh            # keep as legacy fallback
    └── bg3w.sh                  # keep for Steam usage
```

### Implementation Phases

#### Phase 1: Core CLI + Injection (files: 5)

**Goal:** `bg3se-harness build`, `bg3se-harness patch`, `bg3se-harness launch`

**Tasks:**
- [ ] `tools/bg3se-harness/config.py` — Path constants and configuration
  - BG3 app bundle: `~/Library/Application Support/Steam/steamapps/common/Baldurs Gate 3/Baldur's Gate 3.app`
  - BG3 executable: `Contents/MacOS/Baldur's Gate 3`
  - Dylib output: `build/lib/libbg3se.dylib`
  - Deployed dylib: `Contents/MacOS/libbg3se.dylib`
  - Socket path: `/tmp/bg3se.sock`
  - Sentinel: `/tmp/bg3se_loaded.txt`
  - Default timeout: 30s
  - insert_dylib binary path (built from vendor)

- [ ] `tools/bg3se-harness/build.py` — Build + verify
  - Run `cmake --build build/` from project root
  - Verify output: `file build/lib/libbg3se.dylib` contains both `arm64` and `x86_64`
  - Copy to app bundle's MacOS dir (reuse existing `scripts/deploy.sh` logic)
  - Return structured result: `{success, arch_verified, deploy_path}`

- [ ] `tools/bg3se-harness/patch.py` — insert_dylib + codesign
  - Check if BG3 binary already has `LC_LOAD_WEAK_DYLIB` for `libbg3se.dylib` via `otool -L`
  - If not patched: back up original (`bg3.original`), run insert_dylib
  - Command: `insert-dylib --weak --inplace --strip-codesig --all-yes @rpath/libbg3se.dylib "$BG3_EXEC"`
  - Re-sign: `codesign -f -s - "$BG3_EXEC"`
  - Verify: `codesign -vv "$BG3_EXEC"` and `otool -L "$BG3_EXEC" | grep bg3se`
  - Detect game updates: compare binary hash against stored hash, re-patch if changed
  - Return: `{already_patched, backup_path, signed, verified}`

- [ ] `tools/bg3se-harness/launch.py` — Launch + health check
  - Kill any running BG3 process first (`pkill -f "Baldur's Gate 3"`)
  - Clean stale socket: `rm -f /tmp/bg3se.sock`
  - Launch: `arch -arm64 "$BG3_EXEC" &`
  - Poll `/tmp/bg3se.sock` with `socket.connect()` every 500ms until connected or timeout
  - On connect: send `Ext.GetVersion()` to confirm SE is alive
  - Return: `{pid, socket_connected, se_version, elapsed_ms}`

- [ ] `tools/bg3se-harness/cli.py` + `__main__.py` — argparse entry point
  ```
  bg3se-harness build              # build + deploy dylib
  bg3se-harness patch              # patch BG3 binary with insert_dylib
  bg3se-harness launch             # build + patch + launch + health check
  bg3se-harness test [filter]      # full cycle: launch + load save + run tests
  bg3se-harness run <lua>          # send arbitrary Lua to running game
  bg3se-harness status             # check if game running, socket alive
  bg3se-harness unpatch            # restore original binary from backup
  ```

**Vendor dependency: insert_dylib**
- Clone tyilo/insert_dylib (2K stars, C, proven): `git submodule add https://github.com/tyilo/insert_dylib.git tools/vendor/insert_dylib`
- Build: `clang -o tools/vendor/insert_dylib/insert_dylib tools/vendor/insert_dylib/insert_dylib/main.c -framework Foundation`
- Alternative: YinMo19/insert-dylib (Rust) if Cargo is preferred
- Decision: **Use tyilo's C version**—zero dependencies beyond Foundation framework, compiles in <1s, battle-tested

**Success criteria:** `bg3se-harness launch` starts BG3 with SE injected and confirms via socket, no DYLD variables involved.

#### Phase 2: Socket IPC + Test Runner (files: 2)

**Goal:** `bg3se-harness test`, `bg3se-harness run`

**Tasks:**
- [ ] `tools/bg3se-harness/console.py` — Python socket client
  - Connect to `/tmp/bg3se.sock` (AF_UNIX, SOCK_STREAM)
  - Send command: append `\n`, write to socket
  - Read response: non-blocking read with select/poll, accumulate until prompt `> ` or timeout
  - Strip ANSI escape codes from output: `re.sub(r'\033\[[0-9;]*m', '', text)`
  - Multi-line send: wrap in `--[[` / `]]--` delimiters for Lua blocks
  - Methods: `send(cmd) -> str`, `send_lua(code) -> str`, `is_connected() -> bool`

- [ ] `tools/bg3se-harness/test_runner.py` — Test execution + parsing
  - Send `!test [filter]` or `!test_ingame [filter]` via console client
  - Parse output format (confirmed from source):
    ```
    PASS: Core.Print (2ms) [1/85]      → {name: "Core.Print", status: "pass", ms: 2, index: 1, total: 85}
    FAIL: Stats.Bad (5ms) - error [3/85] → {name: "Stats.Bad", status: "fail", ms: 5, error: "error", ...}
    === Results: 83/85 passed, 2 failed, 0 skipped (142ms) ===
    ```
  - Regex patterns:
    - Per-test: `(PASS|FAIL): (\S+) \((\d+)ms\)(?: - (.+?))? \[(\d+)/(\d+)\]`
    - Summary: `Results: (\d+)/(\d+) passed, (\d+) failed, (\d+) skipped \((\d+)ms\)`
  - Output JSON to stdout:
    ```json
    {
      "tier": 1,
      "filter": "Stats",
      "tests": [...],
      "summary": {"passed": 83, "failed": 2, "skipped": 0, "total": 85, "elapsed_ms": 142},
      "all_passed": false
    }
    ```
  - Support `bg3se-harness run "Ext.Print('hello')"` for arbitrary Lua with raw output

**Success criteria:** `bg3se-harness test` returns parseable JSON that Claude Code can reason about.

#### Phase 3: Vision-Based Menu Navigation (files: 1)

**Goal:** `bg3se-harness test` navigates main menu → load save automatically

**Tasks:**
- [ ] `tools/bg3se-harness/menu.py` — Save loading via Claude Computer Use or peekaboo
  - **Primary: Claude Computer Use** (available in Claude Code CLI since March 23, 2026)
    - When invoked from Claude Code, the harness can delegate menu navigation to the calling Claude instance via structured instructions
    - The skill SKILL.md will include step-by-step instructions for Claude to use its screen control
  - **Fallback: peekaboo MCP** (already configured in bg3-steam-launcher)
    - Screenshot → analyze → click sequence
    - Reuse JXA/CGEvent click pattern from existing skill (not hardcoded coords—use vision to find buttons)
  - **Fallback 2: usecomputer CLI** (`npm i -g usecomputer`)
    - `usecomputer screenshot --path /tmp/bg3_menu.png`
    - Analyze with SmolVLM or Claude
    - `usecomputer click -x N -y N`
  - Menu flow: Wait for main menu → Click "Load Game" → Select most recent save (or by name) → Click "Load"
  - Timeout + retry: if menu not detected within 60s of launch, report failure

**Key insight from origin doc:** Vision is the ONLY non-deterministic layer. All in-game interaction goes through the socket. The menu navigation gap exists because BG3 has no CLI for save loading.

**Success criteria:** `bg3se-harness test` loads a save without manual intervention.

#### Phase 4: Claude Code Skill (files: 1 new, 1 updated)

**Goal:** Replace `bg3-steam-launcher` with `bg3se-harness` skill

**Tasks:**
- [ ] Create `~/.claude/skills/bg3se-harness/SKILL.md`
  - Trigger: "test SE", "launch BG3", "run bg3se tests", "bg3 test", "start BG3 with SE"
  - Subcommands:
    - `bg3 test [filter]` → full cycle
    - `bg3 launch` → build + patch + launch + health check
    - `bg3 run <lua>` → send Lua to running game
    - `bg3 status` → check game/socket status
    - `bg3 unpatch` → restore original binary
  - Include menu navigation instructions for Claude Computer Use
  - Reference: `game-modding/bg3/bg3se-macos/tools/bg3se-harness/`

- [ ] Move `~/.claude/skills/bg3-steam-launcher/` to `~/.claude/skills/disabled/bg3-steam-launcher/`
  - The old skill is superseded but preserved for reference

**Success criteria:** Claude Code can invoke `bg3 test` and get structured results.

#### Phase 5: Documentation (files: 3-4)

**Goal:** Full docs in repo, agent_docs reference, CLAUDE.md update

**Tasks:**
- [ ] `game-modding/bg3/bg3se-macos/docs/harness.md` — User-facing CLI docs
  - Installation (uv, dependencies)
  - Quick start
  - All subcommands with examples
  - Architecture diagram
  - Troubleshooting (game updates, re-patching, socket timeout)
  - How insert_dylib works (brief technical explanation)

- [ ] Update `game-modding/bg3/bg3se-macos/CLAUDE.md`
  - Add Harness CLI section with quick-reference commands
  - Document the `bg3se-harness` tool location and usage
  - Update injection method from DYLD to insert_dylib
  - Use `claude-md-manager` skill for structure/quality

- [ ] `~/.claude/agent_docs/tools.md` — Add bg3se-harness entry
  - Under existing Game Modding section or new section
  - CLI reference, path, key subcommands

- [ ] Update `~/.claude/agent_docs/active-projects.md`
  - Reference the new plan

## System-Wide Impact

### Interaction Graph
- `bg3se-harness build` → CMake → `deploy.sh` → copies dylib to Steam folder
- `bg3se-harness patch` → `insert_dylib` → modifies BG3 binary → `codesign` → re-signs
- `bg3se-harness launch` → `arch -arm64` BG3 → dylib auto-loaded (LC_LOAD_WEAK_DYLIB) → constructor → socket server → health check
- `bg3se-harness test` → socket IPC → Lua test framework → output parsing → JSON report

### Error Propagation
- Build failure: cmake exit code, captured stderr
- Patch failure: insert_dylib exit code, codesign verification
- Launch failure: process exit, socket timeout
- Test failure: structured per-test results, not a harness crash

### State Lifecycle Risks
- **Game update overwrites patched binary**: Detected via binary hash comparison; `patch` re-applies automatically
- **Stale socket from crashed game**: `launch` removes stale socket before starting
- **Backup binary diverges from current game version**: Timestamp + hash stored alongside backup

### API Surface Parity
- Socket IPC protocol unchanged (newline-delimited text, `/tmp/bg3se.sock`)
- Test framework unchanged (Lua `BG3SE_RunTests()`, compiled into binary)
- Only new surface: the Python CLI itself

## Acceptance Criteria

### Functional Requirements
- [ ] `bg3se-harness launch` starts BG3 with SE injected via insert_dylib (no DYLD vars)
- [ ] `bg3se-harness test` runs 125 regression tests and returns structured JSON
- [ ] `bg3se-harness run "Ext.Print('hello')"` sends Lua and returns output
- [ ] `bg3se-harness patch` is idempotent (detects already-patched binary)
- [ ] `bg3se-harness unpatch` restores original binary from backup
- [ ] `bg3se-harness status` reports game/socket state
- [ ] Game updates detected and re-patch triggered automatically

### Non-Functional Requirements
- [ ] Socket health check completes within 30s of launch
- [ ] Test results parseable by Claude Code (valid JSON to stdout)
- [ ] No hardcoded screen coordinates anywhere
- [ ] Works on ARM64 Apple Silicon (M-series)

### Quality Gates
- [ ] Harness itself tested: build, patch, unpatch subcommands verified
- [ ] CLI help text (`--help`) for all subcommands
- [ ] CLAUDE.md updated with harness usage
- [ ] Skill registered and working from Claude Code

## Dependencies & Prerequisites

| Dependency | Status | Notes |
|-----------|--------|-------|
| insert_dylib (tyilo, C) | Available | 2K stars, compiles with clang, Foundation.framework |
| Python 3.10+ | Available | Via `uv run` |
| BG3 installed via Steam | Available | Verified at `~/Library/Application Support/Steam/...` |
| BG3 binary: no Hardened Runtime | **Verified** | flags=0x0, plain arm64, no entitlements |
| Socket IPC (`/tmp/bg3se.sock`) | Available | 500+ lines, 4 client max, well-tested |
| Claude Computer Use | Available | Shipped March 23, 2026; Pro/Max subscription |

## Risk Analysis & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Game update overwrites patched binary | Medium | Hash-based detection + automatic re-patch |
| Steam "Verify Integrity" reverts patch | Low | User education; `unpatch` command; backup stored |
| insert_dylib fails on BG3 binary | Low | Verified: no Hardened Runtime, fat binary support confirmed |
| Socket protocol changes in SE update | Low | We control both sides (SE source + harness) |
| Claude Computer Use not available | Medium | Fallback to peekaboo MCP or usecomputer CLI |

## Verification

### End-to-End Test

```bash
cd ~/Desktop/Programming/game-modding/bg3/bg3se-macos

# 1. Build
uv run python -m bg3se_harness build
# Expect: {success: true, arch_verified: true}

# 2. Patch
uv run python -m bg3se_harness patch
# Expect: {already_patched: false, backup_path: "...", signed: true}

# 3. Launch
uv run python -m bg3se_harness launch
# Expect: {socket_connected: true, se_version: "0.36.45"}

# 4. Run arbitrary Lua
uv run python -m bg3se_harness run "Ext.GetVersion()"
# Expect: version string

# 5. Run tests
uv run python -m bg3se_harness test
# Expect: JSON with pass/fail per test

# 6. Unpatch
uv run python -m bg3se_harness unpatch
# Expect: original binary restored
```

### From Claude Code Skill

```
> bg3 test Stats
# Claude Code runs harness, parses JSON, reports results
```

## Sources & References

### Origin
- **Origin document:** [~/.claude/plans/golden-weaving-crab.md](~/.claude/plans/golden-weaving-crab.md) — BG3SE Autonomous Test Harness requirements. Key decisions: insert_dylib over DYLD, direct launch over Steam, vision only for menus.

### Internal References
- Socket IPC server: `src/console/console.c:157-194` (server init), `console.h:32` (socket path)
- Test framework: `src/lua/lua_ext.c:1130-1796` (test registration + runner)
- Test output format: `src/lua/lua_ext.c:1150-1181` (PASS/FAIL lines)
- Console client: `tools/bg3se-console.c:65-103` (socket connection)
- Build system: `CMakeLists.txt:289-293` (POST_BUILD deploy hook)
- Launch scripts: `scripts/launch_bg3.sh`, `scripts/bg3w.sh`
- Existing skill: `~/.claude/skills/bg3-steam-launcher/SKILL.md`

### External References
- insert_dylib (tyilo): https://github.com/tyilo/insert_dylib (2,046 stars)
- insert_dylib (YinMo19, Rust): https://github.com/YinMo19/insert-dylib (Feb 2026)
- Claude Computer Use: https://thenewstack.io/claude-computer-use/ (March 2026)
- usecomputer CLI: https://github.com/remorses/usecomputer (152 stars, March 2026)
- mac-use-mcp: https://github.com/antbotlab/mac-use-mcp (18 macOS automation tools)
- SIP/DYLD deep dive: https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/
- mirrord SIP bypass: https://metalbear.com/blog/fun-with-macoss-sip/
- macOS code signing patched binaries: https://www.storbeck.dev/posts/macos-code-signing-patched-binaries
