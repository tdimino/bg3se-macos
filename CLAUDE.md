# BG3SE-macOS

macOS port of Norbyte's Script Extender for Baldur's Gate 3. Goal: feature parity with Windows BG3SE.

**Version:** v0.36.50 | **Parity:** ~94% | **Target:** Full Windows BG3SE mod compatibility

## Stack

- C17/C++20, Universal binary (arm64 + x86_64)
- Dobby (inline hooking), Lua 5.4, lz4, zlib
- Injection: `insert_dylib` static Mach-O patching (LC_LOAD_WEAK_DYLIB) — DYLD_INSERT_LIBRARIES is dead (crashes through Steam)
- Launcher bypass: `defaults write com.larian.bg3 NoLauncher 1` (set automatically by harness)

## Structure

- `src/injector/main.c` - Core injection, hooks, Lua state, Osi dispatch
- `src/core/crashlog.c` - Crash-resilient logging (mmap ring buffer, signal handler, breadcrumbs)
- `src/lua/lua_*.c` - Ext.* API implementations
- `src/osiris/` - Osiris types, function cache, handle encoding, pattern scanning
- `src/stats/` - RPGStats system + prototype managers
- `src/entity/` - Entity Component System (GUID lookup, components)
- `ghidra/offsets/` - Reverse-engineered offsets documentation

## Modding Toolkit (29 Commands)

```bash
# Core pipeline
PYTHONPATH=tools python3 -m bg3se_harness status            # Game/socket/patch state
PYTHONPATH=tools python3 -m bg3se_harness launch --continue # Autonomous: auto-loads most recent save
PYTHONPATH=tools python3 -m bg3se_harness test [filter]     # Full pipeline: build+patch+launch+continue+test → JSON

# Game inspection
PYTHONPATH=tools python3 -m bg3se_harness entity <GUID> [--component X]  # Inspect entity
PYTHONPATH=tools python3 -m bg3se_harness stats <name> [--diff OTHER]    # RPG stats + comparison
PYTHONPATH=tools python3 -m bg3se_harness components [--namespace eoc]   # List 1,999+ component types
PYTHONPATH=tools python3 -m bg3se_harness probe <0xADDR> [--classify]    # Memory inspection

# Development
PYTHONPATH=tools python3 -m bg3se_harness run "<lua>"       # Inline Lua
PYTHONPATH=tools python3 -m bg3se_harness eval script.lua   # File/stdin Lua (piping)
PYTHONPATH=tools python3 -m bg3se_harness watch script.lua  # Hot-reload on save
PYTHONPATH=tools python3 -m bg3se_harness screenshot        # Game window (1568px, JPEG, Claude Code safe)
PYTHONPATH=tools python3 -m bg3se_harness dump spells       # Bulk extract game data
PYTHONPATH=tools python3 -m bg3se_harness events --subscribe SessionLoaded  # Stream events (JSONL)

# Diagnostics
PYTHONPATH=tools python3 -m bg3se_harness crashlog          # Parse crash ring buffer (no socket)
PYTHONPATH=tools python3 -m bg3se_harness benchmark "Ext.Stats.Get('WPN_Longsword')"  # Perf measurement
PYTHONPATH=tools python3 -m bg3se_harness diff-test base.json curr.json   # Test regression comparison

# Mod management (delegates to BG3MacModManager or pure Python fallback)
PYTHONPATH=tools python3 -m bg3se_harness mod list          # Installed mods + enabled/SE status
PYTHONPATH=tools python3 -m bg3se_harness mod install <path.pak>  # Install local PAK
PYTHONPATH=tools python3 -m bg3se_harness mod enable <name> # Enable in modsettings.lsx
PYTHONPATH=tools python3 -m bg3se_harness mod search <query>  # Search Nexus Mods API

# Parity + compatibility + diagnostics
PYTHONPATH=tools python3 -m bg3se_harness parity scan       # Compare Ext table vs Windows baseline
PYTHONPATH=tools python3 -m bg3se_harness parity missing    # List gaps (offline)
PYTHONPATH=tools python3 -m bg3se_harness compat list       # Available test scenarios
PYTHONPATH=tools python3 -m bg3se_harness compat run mcm    # Autonomous mod compat test
PYTHONPATH=tools python3 -m bg3se_harness doctor            # Verify all prerequisites
PYTHONPATH=tools python3 -m bg3se_harness save list         # Available saves with metadata
PYTHONPATH=tools python3 -m bg3se_harness author new MyMod  # Scaffold new mod

# Menu automation (Vision OCR + CGEvent click)
PYTHONPATH=tools python3 -m bg3se_harness menu detect       # OCR main menu buttons → JSON
PYTHONPATH=tools python3 -m bg3se_harness menu click "Continue"  # Click button by name

# RE + flags
PYTHONPATH=tools python3 -m bg3se_harness flags             # 40 discovered game CLI flags
PYTHONPATH=tools python3 -m bg3se_harness ghidra decompile <name|0xADDR>  # Ghidra RE bridge
```

Uses `insert_dylib` for injection + `defaults write com.larian.bg3 NoLauncher 1` for launcher bypass. See `docs/harness.md` for full docs.

## Commands (Legacy)

```bash
cd build && cmake .. && cmake --build .    # Build (auto-deploys to Steam folder)
./scripts/launch_bg3.sh                     # Test (launches BG3 via DYLD_INSERT_LIBRARIES)
./build/bin/bg3se-console                   # Live Lua console

# IMPORTANT: Check system time BEFORE checking logs (to filter old entries)
date && tail -f "/Users/tomdimino/Library/Application Support/BG3SE/bg3se.log"
```

**Auto-deploy:** Build automatically copies dylib to Steam folder via `scripts/deploy.sh` (CMake POST_BUILD hook).

## Semantic Search

**PREFER RLAMA over OSGrep** for semantic code search. RLAMA provides locally-indexed RAG with superior context retrieval for large C/C++ codebases.

### RLAMA Buckets (Recommended)

| Bucket | Description | Documents |
|--------|-------------|-----------|
| `bg3se-macos` | This project (macOS port) | 389 |
| `bg3se-windows` | Norbyte's Windows BG3SE (reference) | 294 |

```bash
# Semantic queries - how/why questions, architectural understanding
rlama run bg3se-macos --query "how is the Metal ImGui backend implemented?"
rlama run bg3se-windows --query "how does entity component lookup work?"

# Compare implementations
rlama run bg3se-windows --query "how does the Lua state manager work?"
rlama run bg3se-macos --query "how does the Lua state manager work?"
```

### OSGrep (Fallback)

Use OSGrep for exact symbol/string search and grep-style pattern matching:

```bash
cd /Users/tomdimino/Desktop/Programming/game-modding/bg3/bg3se-macos && osgrep "exact_function_name"
cd /Users/tomdimino/Desktop/Programming/game-modding/bg3/bg3se && osgrep "exact_function_name"
```

### Refreshing RLAMA Indexes

If codebase changes significantly:
```bash
rlama add-docs bg3se-macos /Users/tomdimino/Desktop/Programming/game-modding/bg3/bg3se-macos
```

Use `bg3se-macos-ghidra` skill for Ghidra workflows and ARM64 patterns.

**GhidraMCP installed:** When Ghidra is running with BG3 binary loaded and plugin enabled, Claude has direct access to decompilation via MCP tools. See `plans/unexplored-re-techniques.md` for setup.

## Current API Status

~94% Windows BG3SE parity. Key namespaces: Osi.* (40+ functions), Ext.Stats (100% parity, 52 functions), Ext.Entity (1,999 components), Ext.Events (33 events), Ext.IMGUI (40 widgets), Ext.Net (RakNet backend).

@agent_docs/api-status.md — Full per-namespace breakdown. Read when implementing new APIs or checking parity.

## Conventions

- Modular design: each subsystem is header+source pair with static state
- Prefix public functions with module name (`stats_get_string()`)
- Use `log_message()` for consistent logging
- **Git:** Only commit when user requests. Do NOT push until user confirms

## Testing Workflow

You run console commands via `echo 'cmd' | nc -U /tmp/bg3se.sock`. User launches game.

**Console Access:** You can ALWAYS connect to the BG3SE console when the game is running. Prefer this over log parsing - it's faster and provides real-time feedback. Use `nc -U /tmp/bg3se.sock` for quick one-liners.

**Note:** When user says "run the commands" during in-game testing, Claude should immediately execute test commands via nc - this is faster and more efficient than asking the user to run them manually.

**Important:** After rebuilding, the game must be restarted to load the new dylib. Check build timestamps vs game start time if APIs appear missing.

**Session Logs:** Each game launch creates a new log file:
```bash
# Latest session (symlink)
tail -f "/Users/tomdimino/Library/Application Support/BG3SE/logs/latest.log"

# Specific session (e.g., 2025-12-26_18-05-00)
ls "/Users/tomdimino/Library/Application Support/BG3SE/logs/"
```

Use `!test` to run Tier 1 regression tests (85 tests, always works). Use `!test_ingame` for Tier 2 tests (40 tests, needs loaded save). Use `Debug.*` helpers for memory probing.

## Reverse Engineering

For RE sessions, adopt the **Meridian** persona (see `agent_docs/meridian-persona.md`):
- Hypothesis-driven, document-as-you-go approach
- Runtime probing before static analysis
- ARM64 awareness (const& = pointer, x8 indirect return)

## Key Offsets (Ghidra-verified)

| Offset | Purpose |
|--------|---------|
| `0x348` | RPGSTATS_OFFSET_FIXEDSTRINGS |
| `0x10124f92c` | LEGACY_IsInCombat (EntityWorld capture) |
| `0x10898e8b8` | esv::EocServer::m_ptr (server singleton) |
| `0x10898c968` | ecl::EocClient::m_ptr (client singleton) |
| `0x1089bac80` | SpellPrototypeManager::m_ptr |
| `0x1089bdb30` | StatusPrototypeManager::m_ptr |
| `0x108aeccd8` | PassivePrototypeManager |
| `0x108aecce0` | InterruptPrototypeManager |
| `0x108991528` | BoostPrototypeManager |
| `0x108a8f070` | ResourceManager::m_ptr |
| `0x101f72754` | SpellPrototype::Init (populates from stats) |

## BG3 CLI Flags (Discovered via RE)

Extracted from macOS binary via `strings -a`. No public documentation exists. Full inventory: `ghidra/offsets/CLI_FLAGS.md`.

**Launch & Save (P0):**
- `-continueGame` — auto-continue most recent save (bypasses main menu)
- `-loadSaveGame <name>` — load specific save game
- `defaults write com.larian.bg3 NoLauncher 1` — bypass Larian WebKit launcher (set automatically by harness)

**Note:** `-continueGame` and `-loadSaveGame` are mutually exclusive (enforced at `GameStateInit`).

**Mod & Story:** `-module <name>`, `-modded`, `-storylog`, `-dynamicStory`, `-saveStoryState`, `-modEnv <env>`

**Debug:** `-stats`, `-json`, `-osi`, `-crash`, `-syslog`, `-combatTimelines`, `-toggleCrowds`, `-testAIStart`, `-testLoadLevel`

**System:** `-detailLevel <N>`, `-startInControllerMode`, `-enableClientNewECSScheduler`, `--logPath <path>`, `--cpuLimit <N>`

**Save Debug (ECB):** `-useSaveSystemECBChecker`, `-saveSystemECBCheckerEnableLogging`, `-saveSystemECBCheckerEnableDetailedLogging`

**Harness usage:** `bg3se-harness launch --continue` passes `-continueGame` automatically. `bg3se-harness flags` lists all 40 flags.

## Ghidra HTTP Bridge

When Ghidra is running with GhidraMCP plugin and BG3 binary loaded, 135+ RE endpoints at `http://127.0.0.1:8080/`.

**MCP note:** The MCP wrapper may fail to connect to Claude Code. Use HTTP directly or via `bg3se-harness ghidra <command>`.

```bash
curl -s "http://127.0.0.1:8080/decompile_function?address=0x100bb53d8"   # Decompile
curl -s "http://127.0.0.1:8080/strings?filter=continueGame"              # Search strings
curl -s "http://127.0.0.1:8080/searchFunctions?query=GameStateInit"      # Search functions
curl -s "http://127.0.0.1:8080/xrefs_to?address=0x108502635"            # XREFs
curl -s "http://127.0.0.1:8080/list_functions?offset=0&limit=50"        # List functions
```

**CLI wrapper:** `bg3se-harness ghidra status|decompile|search-strings|search-functions|xrefs|list-functions|call-graph`

## Session Checklist

When completing features, update: `docs/CHANGELOG.md`, `CLAUDE.md`, `README.md`, `ROADMAP.md`
See @agent_docs/development.md for full checklist.

## Detailed Guides

**Always loaded (~3.7k tokens):**
@agent_docs/architecture.md
@agent_docs/development.md
@agent_docs/reference.md

**On-demand (read when needed):**
- `agent_docs/debugging-strategies.md` - Hypothesis-driven RE debugging
- `agent_docs/ghidra.md` - Ghidra workflows and MCP usage
- `agent_docs/acceleration.md` - Parity acceleration strategies
- `agent_docs/meridian-persona.md` - RE persona and approach
- `ghidra/offsets/STATS.md` - RPGStats system offsets
