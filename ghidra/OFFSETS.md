# BG3SE-macOS: Ghidra-Derived Offsets

**Game Version:** Baldur's Gate 3 (macOS ARM64)
**Analysis Date:** 2025-01-28
**Library:** libOsiris.dylib (ARM64 slice)

## Key Offsets

| Symbol | Offset | Description |
|--------|--------|-------------|
| `_OsiFunctionMan` | `0x0009f348` | Global pointer to OsiFunctionMan instance |
| `pFunctionData` | `0x0002a04c` | `COsiFunctionMan::pFunctionData(uint32_t)` method |
| `COsiris::Event` | `0x000513cc` | Event dispatch method |
| `COsiris::InitGame` | `0x000519b8` | Game initialization method |
| `COsiFunctionDef` ctor | `0x00026bb8` | Function definition constructor |
| `COsiFunctionData` ctor | `0x000273ac` | Function data constructor |

## Usage in main.c

```c
// libOsiris base address for offset-based lookups
static void *g_libOsirisBase = NULL;

// Ghidra-discovered offsets
#define OSIFUNCMAN_OFFSET       0x0009f348
#define PFUNCTIONDATA_OFFSET    0x0002a04c
#define COSIRIS_EVENT_OFFSET    0x000513cc
#define COSIRIS_INITGAME_OFFSET 0x000519b8

// To get OsiFunctionMan at runtime:
// 1. Get libOsiris base address from dyld callback
// 2. Add OSIFUNCMAN_OFFSET to get pointer location
// 3. Dereference to get actual OsiFunctionMan instance
void *funcman_ptr = (char*)g_libOsirisBase + OSIFUNCMAN_OFFSET;
g_pOsiFunctionMan = *(void**)funcman_ptr;
```

## How to Re-run Analysis

If game updates change these offsets:

```bash
# Extract ARM64 slice from universal binary
lipo -thin arm64 \
  "/Users/tomdimino/Library/Application Support/Steam/steamapps/common/Baldurs Gate 3/Baldur's Gate 3.app/Contents/Frameworks/libOsiris.dylib" \
  -output ~/ghidra_projects/libOsiris_arm64_thin.dylib

# Run Ghidra headless analysis
JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
/Users/tomdimino/ghidra/support/analyzeHeadless \
  ~/ghidra_projects BG3Analysis \
  -import ~/ghidra_projects/libOsiris_arm64_thin.dylib \
  -processor "AARCH64:LE:64:v8A" \
  -postScript find_osiris_offsets.py \
  -postScript analyze_funcdef_struct.py \
  -analysisTimeoutPerFile 300
```

## References to _OsiFunctionMan

Functions that read from the global:
- `0x57a94`, `0x57e34`, `0x581d4`
- `0x48318`, `0x484f4`, `0x48884`, `0x492bc`
- `0x21328`, `0x2169c`

## pFunctionData Analysis

The `pFunctionData(uint32_t funcId)` method at `0x2a04c`:
- Takes function ID as parameter (w1 register)
- Uses offset `0x5ff0` into the OsiFunctionMan structure
- Returns pointer to function data or NULL if not found
- Uses red-black tree lookup (cmp, csel pattern)

Key instruction pattern:
```asm
0x2a05c: mov w8,#0x5ff0
0x2a060: add x20,x0,x8
0x2a064: ldr x9,[x20, #0x5ff0]   ; Tree root at offset 0xbfe0
```

This suggests the function registry is at offset `0xbfe0` (0x5ff0 * 2) within OsiFunctionMan.
