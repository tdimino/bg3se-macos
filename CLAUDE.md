# BG3SE-macOS

macOS port of Norbyte's Script Extender for Baldur's Gate 3. Goal: feature parity with Windows BG3SE.

**Version:** v0.12.0 | **Target:** Full Windows BG3SE mod compatibility

## Stack

- C17/C++20, Universal binary (arm64 + x86_64)
- Dobby (inline hooking), Lua 5.4, lz4, zlib
- DYLD_INSERT_LIBRARIES injection into libOsiris.dylib

## Structure

- `src/injector/main.c` - Core injection, hooks, Lua state
- `src/lua/lua_*.c` - Ext.* API implementations
- `src/stats/stats_manager.c` - RPGStats system (stat property access)
- `src/entity/` - Entity Component System (GUID lookup, components)
- `ghidra/offsets/` - Reverse-engineered offsets documentation

## Commands

```bash
# Build
cd build && cmake .. && cmake --build .

# Test (launches BG3 with dylib)
./scripts/launch_bg3.sh

# IMPORTANT: Check system time BEFORE checking logs (to filter old entries)
date && tail -f "/Users/tomdimino/Library/Application Support/BG3SE/bg3se.log"

# Live Lua console (send commands to running game)
echo 'Ext.Print("test")' > "/Users/tomdimino/Library/Application Support/BG3SE/commands.txt"
```

## Codebase Search (osgrep)

**Semantic search** - use natural language queries, not just keywords:

```bash
# Search this project (bg3se-macos, indexed)
osgrep "how does event dispatch work"
osgrep "where are stats properties resolved"
osgrep "ARM64 indirect return pattern"

# Search Windows BG3SE reference (indexed)
osgrep "entity manager" -p /Users/tomdimino/Desktop/Programming/bg3se
osgrep "how does Lua component binding work" -p /Users/tomdimino/Desktop/Programming/bg3se
osgrep "stats property resolution flow" -p /Users/tomdimino/Desktop/Programming/bg3se
```

**Indexed repositories:**

- `/Users/tomdimino/Desktop/Programming/bg3se-macos` (this project)
- `/Users/tomdimino/Desktop/Programming/bg3se` (Windows reference implementation)

**Tips:** Ask complete questions rather than keywords. osgrep understands context and returns relevant code snippets with surrounding lines.

## Ghidra Analysis

```bash
# Run script (fast, read-only)
./ghidra/scripts/run_analysis.sh find_rpgstats.py

# With re-analysis (slow)
./ghidra/scripts/run_analysis.sh find_rpgstats.py -analyze
```

## Current API Status

- **Osi.*** - Dynamic metatable with lazy lookup (40+ functions seeded)
- **Ext.Entity** - GUID lookup, Transform/Level/Physics/Visual components
- **Ext.Stats** - Property read working (`stat.Damage` returns "1d8")
- **Ext.Memory** - Read, Search, GetModuleBase for debugging
- **Ext.Events** - SessionLoading, SessionLoaded, ResetCompleted (3/10+ events)
- **Ext.Debug** - Memory introspection (ReadPtr/U32/I32/Float, ProbeStruct, HexDump)

## Conventions

- Modular design: each subsystem is header+source pair with static state
- Prefix public functions with module name (`stats_get_string()`)
- Extract from main.c when code exceeds ~100 lines with isolated state
- Use `log_message()` for consistent logging

## Key Offsets (verified via Ghidra)

- `RPGSTATS_OFFSET_FIXEDSTRINGS = 0x348` - Stats string pool
- `LEGACY_IsInCombat` at `0x10124f92c` - EntityWorld capture hook

## Detailed Guides

@agent_docs/architecture.md
@agent_docs/development.md
@agent_docs/ghidra.md
@agent_docs/reference.md
@ghidra/offsets/STATS.md
