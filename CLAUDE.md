# BG3SE-macOS

macOS port of Norbyte's Script Extender for Baldur's Gate 3. Goal: scope-corrected 100% parity across the supported macOS surface.

**Version:** v0.44.0 | **Parity:** approximately 94.8% from the ROADMAP.md matrix (behavioral accounting with per-function contract diffs — stubs score zero, macOS-only extras earn no credit) | **Target:** 100% of the supported macOS surface | **Deferral registry:** docs/deferrals.md

## Stack

- C23/C++20, Universal binary (arm64 + x86_64)
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
- `src/lua/lua_gate.c/h` - Recursive mutex serializing all Lua VM entry points (thread safety)
- `src/hooks/arm64_hook.c/h` - ARM64 inline hooks with MAP_JIT trampolines
- `ghidra/offsets/` - Reverse-engineered offsets documentation

## Modding Toolkit

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
PYTHONPATH=tools python3 -m bg3se_harness mod install <path.pak|nexus:ID>  # Install local PAK or Nexus download (--links-only: URLs only)
PYTHONPATH=tools python3 -m bg3se_harness mod enable <name> # Enable in modsettings.lsx
PYTHONPATH=tools python3 -m bg3se_harness mod search <query>  # Search Nexus Mods API

# Web integrations (Nexus + bg3.wiki — stdlib urllib, 24h file cache)
PYTHONPATH=tools python3 -m bg3se_harness mod changelog <id>       # Nexus changelogs (HTML stripped, newest-first)
PYTHONPATH=tools python3 -m bg3se_harness mod versions <id>        # Nexus file list (file_id, version, category, size)
PYTHONPATH=tools python3 -m bg3se_harness mod updated --period 1w  # Recently-updated mods (1d/1w/1m)
PYTHONPATH=tools python3 -m bg3se_harness wiki spell "Fireball"    # Parsed {{Feature page}} template fields
PYTHONPATH=tools python3 -m bg3se_harness wiki item "Longsword +1" # Parsed {{WeaponPage}} / {{ArmourPage}} fields
PYTHONPATH=tools python3 -m bg3se_harness wiki verify "Fireball" --expect-uid Projectile_Fireball  # Offline uid cross-check
PYTHONPATH=tools python3 -m bg3se_harness wiki clear-cache         # Wipe ~/.config/bg3se-harness/wiki_cache/

# Parity + compatibility + diagnostics
PYTHONPATH=tools python3 -m bg3se_harness parity scan       # Compare Ext table vs Windows baseline
PYTHONPATH=tools python3 -m bg3se_harness parity scan --contract  # Score vs Wave 7 contract manifest (offline)
PYTHONPATH=tools python3 -m bg3se_harness parity missing    # List gaps (offline)
PYTHONPATH=tools python3 -m bg3se_harness compat list       # Available test scenarios
PYTHONPATH=tools python3 -m bg3se_harness compat run mcm --launch --auto-install  # Full autonomous vet: install+launch+assert+quit
PYTHONPATH=tools python3 -m bg3se_harness compat matrix [--launch --auto-install]  # All scenarios, summary matrix
PYTHONPATH=tools python3 -m bg3se_harness compat diff mcm   # Compare latest run vs docs/compat-reports/baseline/
PYTHONPATH=tools python3 -m bg3se_harness compat vet mcm    # Vet mod: probe SE, scan logs, JSON report
PYTHONPATH=tools python3 -m bg3se_harness doctor            # Verify all prerequisites
PYTHONPATH=tools python3 -m bg3se_harness save list         # Available saves with metadata
PYTHONPATH=tools python3 -m bg3se_harness save snapshot <name>  # Save → fixture (records source dir in fixture_meta.json)
PYTHONPATH=tools python3 -m bg3se_harness save restore <name>   # Fixture → its recorded source dir (backs up outside save tree)
PYTHONPATH=tools python3 -m bg3se_harness author new MyMod  # Scaffold new mod

# Menu automation (Vision OCR + CGEvent click)
PYTHONPATH=tools python3 -m bg3se_harness menu detect       # OCR main menu buttons → JSON
PYTHONPATH=tools python3 -m bg3se_harness menu click "Continue"  # Click button by name

# RE + flags
PYTHONPATH=tools python3 -m bg3se_harness flags             # 40 discovered game CLI flags
PYTHONPATH=tools python3 -m bg3se_harness ghidra decompile <name|0xADDR>  # Ghidra RE bridge
```

Uses `insert_dylib` for injection + `defaults write com.larian.bg3 NoLauncher 1` for launcher bypass. Intro videos are skipped by default on `launch`/`test` (opt out with `--no-skip-videos`). See `docs/harness.md` for full docs.

## Game Input via osascript

Claude can send keypresses and clicks to BG3 via AppleScript — useful for navigating the "press any key" screen, main menu, and other UI that the socket can't control.

```bash
# Send spacebar (e.g., dismiss "press any key")
osascript -e 'tell application "System Events" to tell process "Baldur'"'"'s Gate 3" to keystroke " "'

# Send Escape
osascript -e 'tell application "System Events" to tell process "Baldur'"'"'s Gate 3" to key code 53'

# Send Return
osascript -e 'tell application "System Events" to tell process "Baldur'"'"'s Gate 3" to keystroke return'
```

Requires Accessibility permission (checked by `doctor`). Works alongside `menu detect`/`menu click` (Vision OCR + CGEvent) for button-level automation.

**Semi-headless mode:** Hide BG3 after launch so it runs in the background while Claude operates via socket:
```bash
# Hide BG3 (still renders, but out of the way)
osascript -e 'tell application "System Events" to set visible of process "Baldur'"'"'s Gate 3" to false'

# Bring it back when needed (e.g., for screenshots)
osascript -e 'tell application "System Events" to set visible of process "Baldur'"'"'s Gate 3" to true'
```

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

Approximately 94.8% parity across the supported macOS surface, sourced from the ROADMAP.md matrix (behavioral accounting with per-function contract diffs: fail-closed stubs score zero; Ext.Entity 73.1% — 19/26 Windows registrations, Ext.Stats 96.2% — 50/52, Ext.Types 76.9% — 10/13). Key namespaces: Osi.* (40+ functions, generic DB_* accessor), Ext.Stats (100% function-count parity, 52 functions)[^stats-stubs], Ext.Entity (1,999 components, CreateComponent via verified ComponentOps registry, GetAllEntities/GetAllEntitiesWithComponent/GetAllComponents archetype walks, GetEntityType/GetSalt/GetIndex/GetNetId; 6 Windows registrations still missing and EnableTracing remains stubbed — see ROADMAP matrix)[^entity-stubs], Ext.Events (33 events + ExecuteFunctor hook; BeforeDealDamage/DealDamage fire live, verified 51/51 on build 7209685), Ext.IMGUI (40 widgets), Ext.Net (RakNet backend), Ext.Level (20/25 engine-backed, 80%; all 8 sweeps incl. cylinders, TestBox/TestSphere, GetEntitiesOnTile, GetHeightsAt real multi-subgrid walk (Wave 7 — replaced the stub the B3 truth pass exposed), pathfinding suite GetPathById/ReleasePath/GetActivePathfindingRequests/FindPath; physics dispatch repaired against the audited macOS vtable; GetTileRawDebugInfo diagnostic surface with confirmed MinHeight +0x0a; 5 deferrals: raycasts quarantined, GetTileDebugInfo, BeginPathfinding — see docs/deferrals.md), Ext.Audio (16/16 Windows-registered, 100%; GetSoundObjectId/IsReady are macOS extras; WWise banks via dlsym'd AK::SoundEngine exports), Ext.Types (10/13, 76.9%; Serialize/Unserialize real; GetHashSetValueAt + AddCustomFunction/AddCustomProperty missing — the latter two are functional on Windows; Construct matches the Windows reference's unimplemented-TODO contract and leaves the denominator), Ext.Math (59/59, 100%), Ext.Localization (GetLanguage, CreateHandle, GetTranslatedString, UpdateTranslatedString — live-verified round trip). Version detection sentinel probes for game update tolerance.

[^stats-stubs]: Remaining gaps behind function-count parity: AddAttribute returns false and ExecuteFunctors is partial. AddEnumerationValue uses engine ValueList::Insert with FixedString interning, but the 2026-08-04 live session found the enum registry resolving NULL for every name (read and write paths) — a live regression under investigation (docs/parity-100/LIVE-VERIFICATION-2026-08-04.md). Passive sync remains false after PARTIAL-GO recon because Boosts still needs an LTO closure ABI; interrupt sync remains false. TreasureTable/TreasureCategory reads, GetStatsLoadedMods, and spell/status prototype sync return real data.
[^entity-stubs]: EnableTracing and DisableTracing are warn-and-nil stubs (`src/injector/main.c`); `entity:Replicate()` is a no-op. `entity:GetReplicationFlags(component[,qword])` is now a real **read-only** proxy method (SyncBuffers chain, `ghidra/offsets/REPLICATION_SYNCBUFFERS.md`), fail-closed and version-gated — it earns no parity credit until the live-probe checklist validates the runtime chain. GetAllEntities, GetAllEntitiesWithComponent, and GetAllComponents are real server-world archetype walks (Wave 3). `entity:CreateComponent` dispatches through the verified ComponentOps registry; `entity:RemoveComponent` returns false (734 per-type templates, no generic entry point — `ghidra/offsets/COMPONENT_OPS_AND_PROTO_INIT.md`). Component property reads work; writes are real for INT32, UINT8, BOOL, FLOAT, and INT32_ARRAY fields and are refused (return false) for unknown-size layouts and unsupported field types (`src/entity/component_property.c`).

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

Use `!test` to run Tier 1 regression tests (114 tests, always works). Use `!test_ingame` for Tier 2 tests (114 tests, needs loaded save). Use `!identity` to verify pid + session readiness before trusting live results. Use `Debug.*` helpers for memory probing. 510 offline tests (142 C + 368 pytest) run via CI; all four tiers total 738 tests.

## Reverse Engineering

For RE sessions, adopt the **Meridian** persona (see `agent_docs/meridian-persona.md`):
- Hypothesis-driven, document-as-you-go approach
- Runtime probing before static analysis
- ARM64 awareness (const& = pointer, x8 indirect return)

## Key Offsets (Ghidra-verified)

**Build 4.1.1.7398727 (current — migrated offline 2026-08-04, arm64 LC_UUID `0C51CAED-6D60-3DCD-9299-8519C92631B0`; Phase 5/6 live verification 2026-09-15 on the v0.44.0 dylib — tier 1 114/114, tier 2 112/114, StaticData banks resolved for all 10 types, `docs/parity-100/LIVE-VERIFICATION-2026-09-14.md`).** All singletons and functions resolve from the per-version table in `src/core/offset_table.c` (rows: 6995620, 7209685, 7398727), audited every run by `tests/harness/test_offset_audit.py` (283+ checks against the installed binary's exact nm symbols). Gates still closed on 7398727: ECS system update (stale system-TypeIds), savegame hook, ValueList Insert (`VALUELIST_INSERT_VERIFIED_BUILD`). Evidence: `ghidra/offsets/ADDRESS_MIGRATION_7398727.md`, `VALUELIST_REGISTRY_7398727.md`, `ABI_REVIEW_7398727.md`.

| Offset (7398727) | Purpose |
|--------|---------|
| `0x348` | RPGSTATS_OFFSET_FIXEDSTRINGS |
| `0x1089c6f58` | esv::EocServer::m_ptr (server singleton) |
| `0x1089c4fc0` | ecl::EocClient::m_ptr (client singleton) |
| `0x1089f3320` | SpellPrototypeManager::m_ptr |
| `0x1089fddd0` | RPGStats::m_ptr (ValueList registry at +0x00) |
| `0x1089f61d0` | StatusPrototypeManager::m_ptr |
| `0x1089ec8c8` | eoc::Passives::m_ptr |
| `0x1089eaf90` | InterruptPrototypeManager::m_ptr |
| `0x1089c9bc8` | BoostPrototypeManager::m_ptr |
| `0x108ac8080` | ResourceManager::m_ptr |
| `0x108b25f40` | EoCGlobalSwitches* slot (Wave 2A metathesis) |
| `0x108ab68f8` | osi::OsirisInterface slot (Wave 2A metathesis) |
| `0x101f543a8` | SpellPrototype::Init (populates from stats) |

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
- `agent_docs/harness.md` - Harness capabilities, command groups, headless mode. Read when running CLI commands or testing.
- `agent_docs/debugging-strategies.md` - Hypothesis-driven RE debugging
- `agent_docs/ghidra.md` - Ghidra workflows and MCP usage
- `agent_docs/acceleration.md` - Parity acceleration strategies
- `agent_docs/meridian-persona.md` - RE persona and approach
- `ghidra/offsets/STATS.md` - RPGStats system offsets
