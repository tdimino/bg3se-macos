# Reverse Engineering Guide

Ghidra workflows, offset discovery, and maintenance procedures for BG3SE-macOS.

## Overview

BG3SE-macOS requires reverse-engineering the macOS ARM64 binary to discover memory offsets, function addresses, and data structures. The primary tool is **Ghidra**, used in headless mode for automation.

## Prerequisites

- Ghidra 11.x: `brew install ghidra` or download from [ghidra-sre.org](https://ghidra-sre.org)
- Java 21: `brew install openjdk@21`

## Headless Analysis

For the 1GB+ BG3 binary, **always use the wrapper script**:

```bash
# Run script on already-analyzed project (read-only, fast)
./ghidra/scripts/run_analysis.sh find_modifierlist_offsets.py

# Force re-analysis with optimized settings (slow, only if needed)
./ghidra/scripts/run_analysis.sh find_modifierlist_offsets.py -analyze

# Monitor progress:
tail -f /tmp/ghidra_progress.log
```

### Wrapper Script Behavior

- **Default mode**: Uses `-noanalysis` for fast read-only script execution
- **With `-analyze`**: Applies `optimize_analysis.py` prescript for re-analysis
- Logs to `/tmp/ghidra_progress.log` (progress) and `/tmp/ghidra_output.log` (full output)

## Available Scripts

| Script | Purpose |
|--------|---------|
| `find_modifierlist_offsets.py` | ModifierList structure offsets |
| `find_property_access.py` | Stats property access offsets |
| `find_rpgstats.py` | gRPGStats global pointer |
| `find_getfixedstring.py` | FixedStrings pool offset |
| `find_uuid_mapping.py` | UuidToHandleMappingComponent |
| `find_entity_offsets.py` | Entity system offsets |
| `quick_component_search.py` | XREFs to component strings |

## Offset Documentation

Detailed findings in `ghidra/offsets/`:

| File | Contents |
|------|----------|
| `STATS.md` | RPGStats system, FixedStrings pool (0x348) |
| `ENTITY_SYSTEM.md` | ECS architecture, EntityWorld capture |
| `COMPONENTS.md` | GetComponent addresses |
| `STRUCTURES.md` | C structure definitions |
| `GLOBAL_STRING_TABLE.md` | FixedString resolution |

## Key Discovered Offsets

### Stats System

- `RPGSTATS_OFFSET_FIXEDSTRINGS = 0x348` - FixedStrings pool (verified via Ghidra)
- Property resolution: `stat.Name` → IndexedProperties → FixedStrings[pool_index]

### Entity System

- `LEGACY_IsInCombat` hook at `0x10124f92c` captures EntityWorld&
- `TryGetSingleton<UuidToHandleMappingComponent>` at `0x1010dc924`

## Game Update Maintenance

When BG3 updates:

### 1. Check Exported Symbols

```bash
nm -gU "/Users/$USER/Library/Application Support/Steam/steamapps/common/Baldurs Gate 3/Baldur's Gate 3.app/Contents/Frameworks/libOsiris.dylib"
```

### 2. Re-run Analysis (if offsets changed)

For libOsiris.dylib (smaller binary):

```bash
# Extract ARM64 slice from universal binary
lipo -thin arm64 \
  "/Users/$USER/Library/Application Support/Steam/steamapps/common/Baldurs Gate 3/Baldur's Gate 3.app/Contents/Frameworks/libOsiris.dylib" \
  -output ~/ghidra_projects/libOsiris_arm64_thin.dylib

# Run Ghidra headless analysis
JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
~/ghidra/support/analyzeHeadless \
  ~/ghidra_projects BG3Analysis \
  -import ~/ghidra_projects/libOsiris_arm64_thin.dylib \
  -processor "AARCH64:LE:64:v8A" \
  -postScript ghidra/scripts/find_osiris_offsets.py \
  -analysisTimeoutPerFile 300
```

For the main BG3 binary (large):

```bash
# Use the optimized workflow with prescript
JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
~/ghidra/support/analyzeHeadless ~/ghidra_projects BG3Analysis \
  -process BG3_arm64_thin \
  -scriptPath /path/to/bg3se-macos/ghidra/scripts \
  -preScript optimize_analysis.py \
  -postScript quick_component_search.py
```

The prescript disables slow analyzers (Stack, Decompiler Parameter ID, etc.) that would cause analysis to hang on large binaries.

### 3. Update Offsets in Code

Update offsets in `src/injector/main.c`:
- `OSIFUNCMAN_OFFSET` - `_OsiFunctionMan` global variable
- `PFUNCTIONDATA_OFFSET` - `COsiFunctionMan::pFunctionData()` method
- `COSIRIS_EVENT_OFFSET` - `COsiris::Event()` method
- `COSIRIS_INITGAME_OFFSET` - `COsiris::InitGame()` method

### 4. Rebuild and Test

```bash
./scripts/build.sh
./scripts/launch_bg3.sh
```

## Runtime Probing

Use the Ext.Debug API for live offset discovery:

```lua
-- Read primitives (returns nil on bad address, never crashes)
Ext.Debug.ReadPtr(addr)         -- Read pointer
Ext.Debug.ReadU32(addr)         -- Read uint32
Ext.Debug.ReadU64(addr)         -- Read uint64
Ext.Debug.ReadFloat(addr)       -- Read float
Ext.Debug.ReadString(addr, max) -- Read C string

-- Struct probing (bulk offset discovery)
Ext.Debug.ProbeStruct(base, start, end, stride)
-- Returns: { [offset] = { ptr=..., u32=..., i32=..., float=... } }

-- Find array patterns (ptr, capacity, size)
Ext.Debug.FindArrayPattern(base, range)

-- Hex dump
Ext.Debug.HexDump(addr, size)
```

### Console Commands for Probing

```bash
echo '!probe 0x12345678 256' > ~/Library/Application\ Support/BG3SE/commands.txt
echo '!hexdump 0x12345678 64' > ~/Library/Application\ Support/BG3SE/commands.txt
```

## ARM64 Patterns to Watch For

### ADRP + LDR Pattern

Global variable access on ARM64:
```asm
adrp x8, #0x1234000      ; Load page address
ldr x8, [x8, #0x567]     ; Load from page + offset
```

### x8 Indirect Return

Large struct returns (>16 bytes):
```asm
mov x19, x8              ; Save return buffer address
; ... function body ...
stp x10, xzr, [x19]      ; Store result
strb w8, [x19, #0x30]    ; Store error flag
```

### Virtual Table Calls

```asm
ldr x8, [x0]             ; Load vtable pointer
ldr x8, [x8, #0x10]      ; Load function at vtable + offset
blr x8                   ; Call virtual function
```

## Windows BG3SE Reference

Use the Windows implementation as architectural reference:

```bash
# Search with osgrep
osgrep "entity component access" -p /Users/tomdimino/Desktop/Programming/bg3se
osgrep "GUID to entity handle lookup" -p /Users/tomdimino/Desktop/Programming/bg3se
osgrep "stats property resolution" -p /Users/tomdimino/Desktop/Programming/bg3se
```

Key directories:
- `BG3Extender/Lua/` - Lua API design
- `BG3Extender/GameDefinitions/` - Entity/component structures
- `BG3Extender/Osiris/` - Osiris binding patterns
