# BG3SE-macOS

macOS port of Norbyte's Script Extender for Baldur's Gate 3. Goal: feature parity with Windows BG3SE.

**Version:** v0.26.0 | **Target:** Full Windows BG3SE mod compatibility

## Stack

- C17/C++20, Universal binary (arm64 + x86_64)
- Dobby (inline hooking), Lua 5.4, lz4, zlib
- DYLD_INSERT_LIBRARIES injection into libOsiris.dylib

## Structure

- `src/injector/main.c` - Core injection, hooks, Lua state
- `src/lua/lua_*.c` - Ext.* API implementations
- `src/osiris/custom_functions.c` - Custom Osiris function registry
- `src/console/console.c` - Socket server + file-based console
- `src/stats/stats_manager.c` - RPGStats system (stat property access)
- `src/entity/` - Entity Component System (GUID lookup, components)
- `tools/bg3se-console.c` - Standalone readline console client
- `ghidra/offsets/` - Reverse-engineered offsets documentation

## Commands

```bash
# Build
cd build && cmake .. && cmake --build .

# Test (launches BG3 with dylib)
./scripts/launch_bg3.sh

# IMPORTANT: Check system time BEFORE checking logs (to filter old entries)
date && tail -f "/Users/tomdimino/Library/Application Support/BG3SE/bg3se.log"

# Live Lua console - interactive socket (recommended)
./build/bin/bg3se-console

# Live Lua console - file-based fallback
echo 'Ext.Print("test")' > "/Users/tomdimino/Library/Application Support/BG3SE/commands.txt"
```

## Semantic Search (osgrep)

**PREFER osgrep over grep/Grep/search tools.** Use the `osgrep-reference` skill for full CLI reference.

**Indexed repos:**

- `/Users/tomdimino/Desktop/Programming/bg3se-macos` - This project (macOS port)
- `/Users/tomdimino/Desktop/Programming/bg3se` - Windows BG3SE reference (Norbyte's original)

**IMPORTANT**: You must `cd` into the project directory before running osgrep commands.
osgrep uses per-project `.osgrep/` indexes, so it only searches the repo you're currently in.

```bash
# Search this project
cd /Users/tomdimino/Desktop/Programming/bg3se-macos
osgrep "your query"

# Search Windows BG3SE reference
cd /Users/tomdimino/Desktop/Programming/bg3se
osgrep "your query"
```

**Why osgrep over grep?**
- Semantic: finds by concept, not literal strings ("auth flow" finds authentication code)
- Token-efficient: relevant snippets vs exhaustive output
- Better for: "How does X work?", "Where is Y implemented?", cross-cutting concerns

**When to use traditional tools instead:**
- Exact string/identifier search → `Grep`
- File name patterns → `Glob`
- Already know exact location → `Read`

Run `osgrep index --reset` if the index is stale. Use `bg3se-macos-ghidra` skill for Ghidra workflows and ARM64 patterns.

## Ghidra Analysis

```bash
# Run script (fast, read-only)
./ghidra/scripts/run_analysis.sh find_rpgstats.py

# With re-analysis (slow)
./ghidra/scripts/run_analysis.sh find_rpgstats.py -analyze
```

## Current API Status

- **Osi.*** - Dynamic metatable with lazy lookup (40+ functions seeded)
- **Ext.Osiris** - RegisterListener, NewCall/NewQuery/NewEvent for custom Osiris functions
- **Ext.Entity** - GUID lookup working for all entity types including characters (template GUIDs like `S_PLA_*_<uuid>` supported), Transform/Level/Physics/Visual components, GetAllEntitiesWithComponent/CountEntitiesWithComponent
- **Ext.Stats** - Property read working (`stat.Damage` returns "1d8")
- **Ext.Memory** - Read, Search, GetModuleBase for debugging
- **Ext.Events** - 7 events (SessionLoading/Loaded, ResetCompleted, Tick, StatsLoaded, ModuleLoadStarted, GameStateChanged) with priority ordering, Once flag, handler IDs
- **Ext.Vars** - PersistentVars for mod data persistence (file-based)
- **Ext.Debug** - Memory introspection (ReadPtr/U32/I32/Float, ProbeStruct, HexDump)

## Conventions

- Modular design: each subsystem is header+source pair with static state
- Prefix public functions with module name (`stats_get_string()`)
- Extract from main.c when code exceeds ~100 lines with isolated state
- Use `log_message()` for consistent logging

## Testing Workflow

- **You run console commands** - User doesn't manually run console commands during testing. You execute them via `echo 'command' | nc -U /tmp/bg3se.sock` or the console client.
- User launches/reloads the game; you handle Lua console interaction
- Check logs after running commands to see results

## Key Offsets (verified via Ghidra)

- `RPGSTATS_OFFSET_FIXEDSTRINGS = 0x348` - Stats string pool
- `LEGACY_IsInCombat` at `0x10124f92c` - EntityWorld capture hook

## Detailed Guides

@agent_docs/architecture.md
@agent_docs/development.md
@agent_docs/ghidra.md
@agent_docs/reference.md
@ghidra/offsets/STATS.md
