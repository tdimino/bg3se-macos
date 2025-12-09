---
name: bg3se-macos-ghidra
description: |
  Develop the BG3 Script Extender macOS port using Ghidra for reverse engineering. Use this skill when:
  (1) Working on bg3se-macos port development or debugging
  (2) Using Ghidra to discover offsets, function addresses, or data structures in BG3
  (3) Implementing new Lua APIs (Ext.*, Osi.*) for macOS Script Extender
  (4) Porting Windows BG3SE features to macOS ARM64
  (5) Understanding ECS architecture, Osiris integration, or stats system
  (6) Analyzing ARM64 assembly or calling conventions for game hooks
  (7) Writing or modifying Ghidra Python scripts for BG3 analysis
version: 0.20.0
last_updated: 2025-12-09
allowed-tools: "Bash(cmake:*), Bash(osgrep:*), Bash(./scripts/*), Read"
---

# BG3 Script Extender macOS + Ghidra Development

## Project Locations

| Project | Path | Purpose |
|---------|------|---------|
| **bg3se-macos** | `/Users/tomdimino/Desktop/Programming/bg3se-macos` | Target project (macOS port) |
| **bg3se** (Windows) | `/Users/tomdimino/Desktop/Programming/bg3se` | Reference implementation |

## Quick Reference

### Building
```bash
cd /Users/tomdimino/Desktop/Programming/bg3se-macos/build
cmake .. && cmake --build .
# Output: build/lib/libbg3se.dylib
```

### Testing
```bash
./scripts/launch_bg3.sh  # Launch with injection
tail -f ~/Library/Application\ Support/BG3SE/bg3se.log  # Watch logs
```

### Ghidra Headless (Optimized)
```bash
JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
  ~/ghidra/support/analyzeHeadless ~/ghidra_projects BG3Analysis \
  -process BG3_arm64_thin \
  -scriptPath /Users/tomdimino/Desktop/Programming/bg3se-macos/ghidra/scripts \
  -preScript optimize_analysis.py \
  -postScript <your_script.py>
```

### Semantic Search (osgrep)

osgrep indexes are per-repository (stored in `.osgrep/` in each repo root). Run from the target directory:

```bash
# Search bg3se-macos (run from its directory)
cd /Users/tomdimino/Desktop/Programming/bg3se-macos
osgrep "how does entity lookup work"

# Search Windows reference (run from its directory)
cd /Users/tomdimino/Desktop/Programming/bg3se
osgrep "Lua component binding"

# Index a repository (run from its directory, or use -p)
osgrep index                                    # Current directory
osgrep index -p /path/to/repo                   # Specific path
```

## Architecture Overview

### Injection & Hooking
- **Method**: `DYLD_INSERT_LIBRARIES` via `open --env`
- **Hook Framework**: Dobby (ARM64 + x86_64 universal)
- **Key Constraint**: Can hook `libOsiris.dylib` but NOT main binary `__TEXT` (Hardened Runtime)

### Module Structure
```
src/
├── core/           # Logging, safe_memory, version
├── entity/         # ECS (entity_system, guid_lookup, arm64_call, component_*)
├── lua/            # Lua APIs (lua_ext, lua_json, lua_osiris, lua_stats)
├── osiris/         # Osiris types, functions, pattern scanning
├── stats/          # RPGStats system (stats_manager)
├── mod/            # Mod detection and loading
└── pak/            # LSPK v18 PAK file reading
```

### Key Files
| File | Purpose |
|------|---------|
| `src/injector/main.c` | Core injection, hooks, Osi.* namespace, Lua state |
| `src/entity/entity_system.c` | ECS core, EntityWorld capture, Lua bindings |
| `src/entity/guid_lookup.c` | GUID→EntityHandle HashMap lookup |
| `src/entity/arm64_call.c` | ARM64 ABI wrappers for large struct returns |
| `src/lua/lua_stats.c` | Ext.Stats.* API implementation |
| `src/stats/stats_manager.c` | RPGStats global access |

## Ghidra Workflow

### Script Categories

| Script | Purpose | When to Use |
|--------|---------|-------------|
| `optimize_analysis.py` | Prescript disabling slow analyzers | Always use with `-preScript` |
| `find_rpgstats.py` | Find RPGStats singleton | Stats system work |
| `find_uuid_mapping.py` | Find GUID→Handle mapping | Entity lookup work |
| `find_entity_offsets.py` | Discover ECS offsets | Entity system work |
| `quick_component_search.py` | Fast XREF search for components | Component discovery |

### Analysis Pattern

1. **String Search** → Find type name strings (e.g., `"eoc::RPGStatsComponent"`)
2. **XREF Analysis** → Find code referencing those strings
3. **ADRP+LDR Pattern** → Extract global pointer addresses (ARM64)
4. **Decompile** → Understand data structure layout

### ARM64 Global Pointer Pattern
```python
# Common ARM64 pattern for loading globals
# ADRP x8, #page_address    ; Load page base
# LDR x8, [x8, #offset]     ; Load from page+offset
def find_global_refs(func_addr):
    for inst in listing.getInstructions(func.getBody(), True):
        if inst.getMnemonicString() == "adrp":
            next_inst = listing.getInstructionAfter(inst.getAddress())
            if next_inst.getMnemonicString() in ["ldr", "add"]:
                # Found global access pattern
```

## Critical Patterns

### ARM64 Large Struct Return (x8 Register)
Functions returning structs >16 bytes require x8 to point to result buffer:

```c
// TryGetSingleton returns 64-byte ls::Result
void* call_try_get_singleton(void *fn, void *entityWorld) {
    LsResult result = {0};
    __asm__ volatile (
        "mov x8, %[buf]\n"   // CRITICAL: Set x8 to result buffer
        "mov x0, %[world]\n"
        "blr %[fn]\n"
        : "+m"(result)
        : [buf] "r"(&result), [world] "r"(entityWorld), [fn] "r"(fn)
        : "x0", "x1", "x8", "x9", "x10", "x19", "x20", "x30", "memory"
    );
    return result.has_error ? NULL : result.value;
}
```

### GUID Byte Order (BG3-Specific)
```c
// GUID "a5eaeafe-220d-bc4d-4cc3-b94574d334c7"
// BG3 stores with hi/lo swapped from standard!
out_guid->hi = (a << 32) | (b << 16) | c;  // First 3 parts → hi
out_guid->lo = (d << 48) | e;              // Last 2 parts → lo
```

### EntityWorld Capture (Direct Memory Read)
```c
// Read from global pointer (no hooking required)
#define OFFSET_EOCSERVER_SINGLETON  0x10898e8b8ULL
#define OFFSET_ENTITYWORLD          0x288

void *eocServer = *(void **)runtime_addr(OFFSET_EOCSERVER_SINGLETON);
void *entityWorld = *(void **)((char *)eocServer + OFFSET_ENTITYWORLD);
```

### Module Design Pattern
```c
// module.h - Public interface
#ifndef MODULE_H
#define MODULE_H
void module_init(void);
int module_get_value(void);
#endif

// module.c - Implementation
#include "module.h"
static int s_value = 0;  // Private state (static)
static void internal_helper(void) { }  // Private (static)
void module_init(void) { s_value = 42; }  // Public
int module_get_value(void) { return s_value; }
```

### Lua API Registration
```c
void lua_ext_register_stats(lua_State *L, int ext_table_index) {
    // Create Ext.Stats table
    lua_newtable(L);

    lua_pushcfunction(L, lua_stats_get);
    lua_setfield(L, -2, "Get");

    lua_pushcfunction(L, lua_stats_get_all);
    lua_setfield(L, -2, "GetAll");

    lua_setfield(L, ext_table_index, "Stats");
}
```

## Key Offsets (ARM64, base 0x100000000)

| Symbol | Address | Notes |
|--------|---------|-------|
| `esv::EocServer::m_ptr` | `0x10898e8b8` | Global EoCServer pointer |
| EntityWorld offset | `+0x288` | Within EoCServer |
| `RPGStats::m_ptr` | `0x89c5730` (offset) | Stats manager |
| `TryGetSingleton<UuidMapping>` | `0x1010dc924` | GUID lookup |
| `EntityStorageContainer::TryGet` | `0x10636b27c` | Entity storage |

## Reference Documentation

For detailed information, see:

- **Windows BG3SE Architecture**: `references/bg3se-architecture.md`
- **Ghidra Workflows**: `references/ghidra-workflows.md`
- **Offset Discovery**: `references/offset-discovery.md`
- **ARM64 Patterns**: `references/arm64-patterns.md`

## Common Tasks

### Adding New Ext.* API
1. Create function in `src/lua/lua_*.c`
2. Declare in corresponding `.h` file
3. Register in `lua_*_register()` function
4. Test with EntityTest mod

### Discovering New Offset
1. Search for related string in Ghidra
2. Find XREFs to string
3. Trace ADRP+LDR pattern to global
4. Document in `ghidra/offsets/*.md`
5. Implement in C with runtime address calculation

### Porting Windows Feature

1. Search Windows BG3SE with osgrep (from its directory):
   ```bash
   cd /Users/tomdimino/Desktop/Programming/bg3se && osgrep "feature name"
   ```
2. Understand the Windows implementation pattern
3. Find equivalent ARM64 offsets with Ghidra
4. Adapt for macOS constraints (Hardened Runtime, ARM64 ABI)

## Troubleshooting

**Game crashes on launch with dylib:**
- Check dylib is signed: `codesign -dv build/lib/libbg3se.dylib`
- Verify ARM64: `file build/lib/libbg3se.dylib`
- Check SIP: `csrutil status` (should be enabled, we use DYLD injection)

**Hooks not being called:**
- Verify hooking libOsiris.dylib, not main binary (Hardened Runtime blocks __TEXT)
- Check Dobby hook return value
- Add logging before/after DobbyHook calls

**Entity lookup returns NULL:**
- EoCServer may not be initialized yet (hook later in game startup)
- Verify offset 0x288 for EntityWorld is still valid
- Check g_EntityWorld capture in entity_system.c

**osgrep shows "indexed 0" or no results:**
- Run from project directory: `cd /path/to/bg3se-macos && osgrep "query"`
- Reindex if needed: `osgrep index --reset`
- Check index exists: `osgrep list` (should show `.osgrep/` in repo root)

**Ghidra headless analysis hangs:**
- Always use `optimize_analysis.py` as prescript
- Monitor: `tail -f /tmp/ghidra_progress.log`
- Check Java heap: JAVA_OPTS="-Xmx8g"

## osgrep Search Patterns

**Important:** osgrep uses per-repo indexes stored in `.osgrep/` within each repository root. Always `cd` to the target repo before searching.

```bash
# Search bg3se-macos (from its directory)
cd /Users/tomdimino/Desktop/Programming/bg3se-macos

osgrep "how does entity component lookup work"
osgrep "Lua API registration pattern"
osgrep "ARM64 indirect return via x8"
osgrep "Osiris event dispatch"
osgrep "Ext.Stats property resolution"
osgrep "GUID to EntityHandle mapping"
osgrep "socket console command processing"
osgrep "ADRP LDR global pointer pattern"

# Search Windows reference (from its directory)
cd /Users/tomdimino/Desktop/Programming/bg3se

osgrep "entity component binding"
osgrep "stats property accessor"
osgrep "Lua component binding"
```
