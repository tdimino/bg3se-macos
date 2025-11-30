# BG3SE-macOS Development Guide

## Project Overview

BG3SE-macOS is a macOS port of Norbyte's Script Extender for Baldur's Gate 3. The goal is feature parity with the Windows BG3SE, enabling Lua mods to run on macOS.

**Current Version:** v0.10.1
**Target:** Full compatibility with Windows BG3SE mods

## Architecture

### Injection Method
- Uses `DYLD_INSERT_LIBRARIES` to load the dylib before the game starts
- Dobby framework for inline function hooking (ARM64 + x86_64 universal binary)
- Hooks into libOsiris.dylib for Osiris scripting engine integration

### Module Structure
```
src/
├── core/           # Logging, version info
├── entity/         # Entity Component System (Phase 2)
├── hooks/          # Legacy hook stubs (actual hooks in main.c)
├── injector/       # Main injection logic (main.c)
├── lua/            # Lua API modules (lua_ext, lua_json, lua_osiris)
├── mod/            # Mod detection and loading
├── osiris/         # Osiris types, functions, pattern scanning
└── pak/            # LSPK v18 PAK file reading
```

### Key Files
- `src/injector/main.c` - Core injection, Dobby hooks, Osi.* namespace, Lua state
- `src/mod/mod_loader.c` - Mod detection from modsettings.lsx, PAK loading
- `src/lua/lua_*.c` - Ext.* API implementations
- `src/osiris/osiris_functions.c` - Osiris function enumeration
- `src/entity/entity_system.c` - Entity Component System with Lua bindings
- `ghidra/offsets/` - Modular offset documentation (Osiris, Entity, Components, Structures)

## Modular Architecture

**This project follows a strict modular design.** Each subsystem should be self-contained with:
- **Header file** (`.h`) - Public API declarations, constants, type definitions
- **Source file** (`.c`) - Implementation with static (private) helpers
- **Minimal coupling** - Modules communicate through well-defined interfaces

### Module Design Pattern (MUST FOLLOW)

When extracting or creating new modules:

```c
// module.h - Public interface
#ifndef MODULE_H
#define MODULE_H

// Public constants
#define MODULE_MAX_ITEMS 128

// Public functions (prefixed with module name)
void module_init(void);
int module_get_count(void);
const char *module_get_name(int index);

#endif

// module.c - Implementation
#include "module.h"
#include "logging.h"

// Private state (static)
static char items[MODULE_MAX_ITEMS][256];
static int item_count = 0;

// Private helpers (static)
static int validate_item(const char *item) { ... }

// Public implementation
void module_init(void) { ... }
```

### Existing Module Examples

| Module | Purpose | Key Pattern |
|--------|---------|-------------|
| `mod_loader` | Mod detection & PAK loading | State encapsulation via static variables |
| `pak_reader` | LSPK v18 archive parsing | Opaque struct (`PakFile*`) with accessor functions |
| `entity_system` | ECS access & Lua bindings | Singleton capture via hooks |
| `lua_ext` | Ext.* API registration | Registration functions per API group |

### When to Extract Code from main.c

Extract to a new module when:
1. Code exceeds ~100 lines with related functionality
2. State (static variables) can be isolated
3. Multiple source files need the functionality
4. Testing the functionality independently would be valuable

**Goal:** Keep `main.c` focused on initialization, orchestration, and hook dispatch

## Development Workflow

### Building
```bash
cd build && cmake .. && cmake --build .
# Output: build/lib/libbg3se.dylib
```

### Testing
```bash
./scripts/launch_bg3.sh  # Launches BG3 with dylib injected
tail -f /tmp/bg3se_macos.log  # Watch logs in real-time
```

### Debugging
- All logs go to `/tmp/bg3se_macos.log` and syslog
- Use `log_message()` for consistent logging
- Osiris events logged with `[Osiris]` prefix

## Current Status (from ROADMAP.md)

### Phase 1: Core Osiris Integration - COMPLETE
- [x] Dynamic Osi.* metatable with lazy function lookup
- [x] Query output parameters
- [x] Function type detection (Query/Call/Event/Proc/Database dispatch)
- [x] Pre-populated common functions (40+ seeded at startup)
- [ ] Safe enumeration via Ghidra offsets

### Phase 2: Entity/Component System - COMPLETE
- [x] EntityWorld capture via LEGACY_IsInCombat hook
- [x] TryGetSingleton for UuidToHandleMappingComponent
- [x] HashMap<Guid, EntityHandle> reverse engineered & implemented
- [x] Component accessors (Transform, Level, Physics, Visual)
- [x] Lua bindings: `Ext.Entity.Get(guid)`, `entity.Transform`, etc.
- [ ] Additional eoc:: component addresses (Stats, Health, Armor) - pending runtime discovery

### Phase 3-7: See ROADMAP.md for details

## Technical Patterns

### Pattern Scanning
When dlsym fails (symbols stripped), use pattern scanning:
```c
static const FunctionPattern g_osirisPatterns[] = {
    {"InternalQuery", "_Z13InternalQueryjP16COsiArgumentDesc", "FD 43...", 28},
    // ...
};
void *addr = resolve_by_pattern("libOsiris.dylib", &pattern);
```

### Osiris Function Calls
```c
// Query (returns values)
OsiArgumentDesc *args = alloc_args(2);
set_arg_string(&args[0], guid, 1);  // isGuid=1
int result = osiris_query_by_id(funcId, args);

// Call (no return)
osiris_call_by_id(funcId, args);
```

### Lua API Registration
```c
void lua_ext_register_basic(lua_State *L, int ext_table_index) {
    lua_pushcfunction(L, lua_ext_print);
    lua_setfield(L, ext_table_index, "Print");
}
```

### Module Loading
Mods loaded from:
1. `/tmp/<ModName>_extracted/` - Extracted mods for development
2. `~/Documents/Larian Studios/Baldur's Gate 3/Mods/` - User mods
3. PAK files - Compressed mods

## Common Tasks

### Adding a New Ext.* Function
1. Implement in `src/lua/lua_ext.c`
2. Declare in `src/lua/lua_ext.h`
3. Register in `lua_ext_register_*()` function

### Adding a New Osi.* Function
Dynamic Osi.* uses metatable `__index`. For explicit stubs:
1. Add to `register_osi_namespace()` in main.c
2. Implement the Lua C function

### Extracting Code from main.c
See **Modular Architecture** section above for the design pattern. Steps:
1. Create header/source pair in appropriate `src/` subdirectory
2. Follow the module design pattern (static state, prefixed functions)
3. Update CMakeLists.txt to include new source file
4. Update main.c to `#include` header and remove duplicate code
5. Replace direct state access with module accessors

### Ghidra Analysis
```bash
# Run headless analysis with a script
JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
  ~/ghidra/support/analyzeHeadless ~/ghidra_projects BG3Analysis \
  -process BG3_arm64_thin \
  -postScript find_uuid_mapping.py \
  -noanalysis

# Available scripts in ghidra/scripts/:
# - find_entity_offsets.py   - Discover Entity system offsets and component strings
# - find_uuid_mapping.py     - Find UuidToHandleMappingComponent for GUID lookup
# - find_osiris_offsets.py   - Discover Osiris scripting engine offsets
```

## Codebase Search

Use `osgrep` for semantic code search. **Invoke the `osgrep-reference` skill** for full CLI documentation.

```bash
# Search this project
osgrep "how does event dispatch work"
osgrep "entity component access"
osgrep "mod loading bootstrap"

# Search reference implementation
osgrep "entity manager" -p /Users/tomdimino/Desktop/Programming/bg3se
osgrep "Lua component binding" -p /Users/tomdimino/Desktop/Programming/bg3se

# Reindex after changes
osgrep index -p /Users/tomdimino/Desktop/Programming/bg3se-macos
osgrep index -p /Users/tomdimino/Desktop/Programming/bg3se
```

### osgrep Tips
- Use natural language queries ("how does X work" rather than "functionX")
- `-m N` limits results (default 10)
- `--per-file N` limits matches per file
- Index is auto-updated but run `osgrep index` after major changes

## Reference Implementation

**Local clone:** `/Users/tomdimino/Desktop/Programming/bg3se` (Norbyte's Windows BG3SE)
**GitHub:** https://github.com/Norbyte/bg3se
**osgrep indexed:** Yes - use `-p /Users/tomdimino/Desktop/Programming/bg3se` for semantic search

Key directories in the reference:
- `BG3Extender/Osiris/` - Osiris binding patterns, function lookups
- `BG3Extender/Lua/` - Lua API design, Ext.* implementations
- `BG3Extender/Lua/Libs/Entity.inl` - Entity Lua bindings (UuidToHandle, GetComponent)
- `BG3Extender/GameDefinitions/` - Entity/component structures, type definitions
- `BG3Extender/GameDefinitions/EntitySystem.cpp` - EntitySystemHelpers, GetSingleton
- `BG3Extender/GameDefinitions/Components/Components.h` - Component struct definitions
- `CoreLib/` - Core utilities, memory patterns
- `Docs/` - API documentation

Use osgrep to search the reference implementation:
```bash
# The bg3se reference repo is indexed for semantic search
osgrep "entity component access" -p /Users/tomdimino/Desktop/Programming/bg3se
osgrep "GUID to entity handle lookup" -p /Users/tomdimino/Desktop/Programming/bg3se
osgrep "Lua component binding" -p /Users/tomdimino/Desktop/Programming/bg3se
osgrep "Osiris function registration" -p /Users/tomdimino/Desktop/Programming/bg3se
```

## Build Configuration

- Universal binary (arm64 + x86_64)
- C17 / C++20 standards
- Depends on: Dobby, Lua 5.4, lz4, zlib
- Frameworks: Foundation, CoreFoundation

## Entity System Offsets (from Ghidra analysis)

See `ghidra/offsets/` for modular documentation:
- `ENTITY_SYSTEM.md` - ECS architecture, EntityWorld capture, GUID lookup
- `COMPONENTS.md` - GetComponent addresses and discovery status
- `STRUCTURES.md` - C structure definitions

Key findings:

### Capturing EntityWorld Pointer
Hook `eoc::CombatHelpers::LEGACY_IsInCombat` at `0x10124f92c` to capture `EntityWorld&` parameter.

### GUID to EntityHandle Lookup
| Function | Address | Notes |
|----------|---------|-------|
| `TryGetSingleton<UuidToHandleMappingComponent>` | `0x1010dc924` | Returns singleton for GUID mapping |

### GetComponent Template Instances
| Component | Method Address |
|-----------|----------------|
| `ls::TransformComponent` | `0x10010d5b00` |
| `ls::LevelComponent` | `0x10010d588c` |
| `ls::PhysicsComponent` | `0x101ba0898` |
| `ls::VisualComponent` | `0x102e56350` |

### Component Strings
| Component | String Address |
|-----------|----------------|
| `eoc::StatsComponent` | `0x107b7ca22` |
| `eoc::BaseHpComponent` | `0x107b84c63` |
| `ls::TransformComponent` | `0x107b619cc` |
| `eoc::ArmorComponent` | `0x107b7c9e7` |

## Automated Testing

Invoke the **bg3-steam-launcher** skill for autonomous game testing with MCP servers:
```
skill: "bg3-steam-launcher"
```

The skill documents the complete workflow for:
- Launching BG3 via Steam
- Clicking through launcher/menus with JXA CGEvent
- Loading saved games
- Crash report locations

**MCP Servers:** `macos-automator` (AppleScript/JXA), `peekaboo` (screenshots)

## Notes

- Game binary is ARM64 on Apple Silicon, Rosetta for Intel
- libOsiris.dylib contains the Osiris scripting engine
- Symbol names may be mangled C++ (use c++filt to demangle)
- Some symbols stripped - pattern scanning is the fallback
- **EntityWorld/EoCServer singletons not exported** - must capture via hooks
