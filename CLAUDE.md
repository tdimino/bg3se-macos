# BG3SE-macOS

macOS port of Norbyte's Script Extender for Baldur's Gate 3. Goal: feature parity with Windows BG3SE.

**Version:** v0.32.9 | **Parity:** ~66% | **Target:** Full Windows BG3SE mod compatibility

## Stack

- C17/C++20, Universal binary (arm64 + x86_64)
- Dobby (inline hooking), Lua 5.4, lz4, zlib
- DYLD_INSERT_LIBRARIES injection into libOsiris.dylib

## Structure

- `src/injector/main.c` - Core injection, hooks, Lua state
- `src/lua/lua_*.c` - Ext.* API implementations
- `src/stats/` - RPGStats system + prototype managers
- `src/entity/` - Entity Component System (GUID lookup, components)
- `ghidra/offsets/` - Reverse-engineered offsets documentation

## Commands

```bash
cd build && cmake .. && cmake --build .    # Build (auto-deploys to Steam folder)
./scripts/launch_bg3.sh                     # Test (launches BG3)
./build/bin/bg3se-console                   # Live Lua console

# IMPORTANT: Check system time BEFORE checking logs (to filter old entries)
date && tail -f "/Users/tomdimino/Library/Application Support/BG3SE/bg3se.log"
```

**Auto-deploy:** Build automatically copies dylib to Steam folder via `scripts/deploy.sh` (CMake POST_BUILD hook).

## Semantic Search

**PREFER osgrep** over grep/Grep. Use `osgrep-reference` skill for CLI reference.

**Indexed repos:**
- `/Users/tomdimino/Desktop/Programming/bg3se-macos` - This project (macOS port)
- `/Users/tomdimino/Desktop/Programming/bg3se` - Windows BG3SE reference (Norbyte's original)

```bash
cd /Users/tomdimino/Desktop/Programming/bg3se-macos && osgrep "query"  # This project
cd /Users/tomdimino/Desktop/Programming/bg3se && osgrep "query"        # Windows reference
```

Use `bg3se-macos-ghidra` skill for Ghidra workflows and ARM64 patterns.

**GhidraMCP installed:** When Ghidra is running with BG3 binary loaded and plugin enabled, Claude has direct access to decompilation via MCP tools. See `plans/unexplored-re-techniques.md` for setup.

## Current API Status

- **Osi.*** - Dynamic metatable (40+ functions)
- **Ext.Osiris** - RegisterListener, NewCall/NewQuery/NewEvent
- **Ext.Entity** - GUID lookup, 158 component layouts (including 109 tag components), GetByHandle
- **Ext.Stats** - Property read/write, Create/Sync complete (shadow + game stats, all 5 prototype managers)
- **Ext.Events** - 10 events with priority ordering, Once flag, Prevent pattern
- **Ext.Vars** - PersistentVars, User Variables, Mod Variables
- **Ext.StaticData** - Immutable game data (Feat type via Frida capture: GetAll, Get, LoadFridaCapture)
- **Ext.Template** - Game object templates (via Frida capture: Get, GetRootTemplate, GetAllRootTemplates)
- **Ext.Debug** - Memory introspection (ReadPtr, ProbeStruct, HexDump)

## Conventions

- Modular design: each subsystem is header+source pair with static state
- Prefix public functions with module name (`stats_get_string()`)
- Use `log_message()` for consistent logging
- **Git:** Commit freely, but do NOT push until user confirms

## Testing Workflow

You run console commands via `echo 'cmd' | nc -U /tmp/bg3se.sock`. User launches game.

**Note:** When user says "run the commands" during in-game testing, Claude should immediately execute test commands via nc - this is faster and more efficient than asking the user to run them manually.

**Important:** After rebuilding, the game must be restarted to load the new dylib. Check build timestamps vs game start time if APIs appear missing.

Use `!test` to run automated regression tests. Use `Debug.*` helpers for memory probing.

## Reverse Engineering

For RE sessions, adopt the **Meridian** persona (see @agent_docs/meridian-persona.md):
- Hypothesis-driven, document-as-you-go approach
- Runtime probing before static analysis
- ARM64 awareness (const& = pointer, x8 indirect return)

## Key Offsets (Ghidra-verified)

| Offset | Purpose |
|--------|---------|
| `0x348` | RPGSTATS_OFFSET_FIXEDSTRINGS |
| `0x10124f92c` | LEGACY_IsInCombat (EntityWorld capture) |
| `0x1089bac80` | SpellPrototypeManager::m_ptr |
| `0x1089bdb30` | StatusPrototypeManager::m_ptr |
| `0x108aeccd8` | PassivePrototypeManager |
| `0x108aecce0` | InterruptPrototypeManager |
| `0x108991528` | BoostPrototypeManager |
| `0x101f72754` | SpellPrototype::Init (populates from stats) |

## Session Checklist

When completing features, update: `docs/CHANGELOG.md`, `CLAUDE.md`, `README.md`, `ROADMAP.md`
See @agent_docs/development.md for full checklist.

## Detailed Guides

@agent_docs/architecture.md
@agent_docs/development.md
@agent_docs/ghidra.md
@agent_docs/reference.md
@agent_docs/acceleration.md
@agent_docs/meridian-persona.md
@ghidra/offsets/STATS.md
