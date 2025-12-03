# Osiris Function System Architecture

## Overview

The Osiris scripting engine uses a function manager (`COsiFunctionMan`) to store and look up function definitions. This document describes the structures discovered via Ghidra analysis of macOS ARM64 `libOsiris.dylib`.

## Key Symbols

| Symbol | Address | Description |
|--------|---------|-------------|
| `_OsiFunctionMan` | `0x9f348` | Global pointer to COsiFunctionMan instance |
| `COsiFunctionMan::pFunctionData(uint)` | `0x2a04c` | Look up function by ID |
| `COsiFunctionDef::COsiFunctionDef(char*, COsipParameterList*)` | `0x26dc4` | Function definition constructor |

## OsiFunctionDef Structure (CORRECTED December 2025)

**IMPORTANT:** The previous documentation was INCORRECT. The macOS ARM64 structure
matches the Windows BG3SE structure (with ARM64 alignment), NOT a simplified version.

### Evidence of Bug

The old code read offset +0x08 expecting a name pointer, but got values like `0x4a8` (1192 decimal).
This is a **line number**, not a pointer. The name requires following `Signature->Name` indirection.

### Correct Structure (ARM64 macOS, 8-byte aligned)

Based on Windows BG3SE `Osiris.h` lines 902-918, with ARM64 alignment:

```c
struct OsiFunctionDef {
    void* VMT;                     // 0x00: Virtual method table (8 bytes)
    uint32_t Line;                 // 0x08: Source line number (4 bytes) - NOT A POINTER!
    uint32_t Unknown1;             // 0x0C: Unknown (4 bytes)
    uint32_t Unknown2;             // 0x10: Unknown (4 bytes)
    uint32_t _padding;             // 0x14: Alignment padding (4 bytes)
    FunctionSignature* Signature;  // 0x18: Pointer to signature (8 bytes)
    // ... more fields (NodeRef, Type, Key, OsiFunctionId)
};

struct FunctionSignature {
    void* VMT;                     // 0x00: Virtual method table (8 bytes)
    const char* Name;              // 0x08: Function name string pointer
    FunctionParamList* Params;     // 0x10: Parameter list
    // ... more fields
};
```

### Pointer Chain Diagram

```
OsiFunctionDef @ 0x60002f1d8180
    │
    ├── +0x00: VMT (0x10xxxxxxxx)
    ├── +0x08: Line = 0x4a8 (1192)  ← OLD CODE INCORRECTLY READ THIS!
    ├── +0x0C: Unknown1
    ├── +0x10: Unknown2
    ├── +0x14: (padding)
    └── +0x18: Signature* ─────────────────┐
                                           ▼
                              FunctionSignature @ 0x6000xxxxxxxx
                                  │
                                  ├── +0x00: VMT
                                  └── +0x08: Name* ────────────────┐
                                                                   ▼
                                                    "GetPlayerInfo\0"
```

### To Get Function Name

```c
// CORRECT: Two-level indirection
FunctionSignature* sig = *(FunctionSignature**)(funcDef + 0x18);
const char* name = *(const char**)(sig + 0x08);

// WRONG (old code): Direct read at +0x08
// char* name = *(char**)(funcDef + 0x08);  // This reads Line, not Name!
```

### Why ARM64 Uses Offset 0x18 for Signature

On x86/x64 Windows, the Signature pointer might be at +0x14 (after three uint32_t fields).
On ARM64 macOS, pointers must be 8-byte aligned, so there's 4 bytes of padding at +0x14,
pushing Signature to offset +0x18.

## COsiFunctionMan Hash Table

The function manager uses a hash table with 1023 buckets:

```c
struct COsiFunctionMan {
    // ... other fields
    void* hashBuckets[1024];  // Starting at offset 0x5ff8
    void* functionTree;       // At offset 0xbfe0 - binary search tree for ID lookup
};
```

### pFunctionData Implementation

From Ghidra decompilation:

```c
void* COsiFunctionMan::pFunctionData(uint funcId) {
    // First, search the ID tree at offset 0xbfe0
    void* node = *(this + 0xbfe0);
    if (!node) return NULL;

    // Binary search tree traversal (field at offset 0x1c contains ID)
    while (node) {
        if (funcId <= *(uint*)(node + 0x1c)) {
            // Go left
        } else {
            // Go right (offset 8)
        }
    }

    // Then hash lookup: bucket = (id % 0x3ff) * 0x18 + 0x5ff8
    uint bucket = (funcId % 0x3ff);
    void* entry = *(this + bucket * 0x18 + 0x5ff8);

    // Walk bucket chain, compare ID at offset 0x20
    while (entry) {
        if (*(uint*)(entry + 0x20) == funcId) {
            return *(void**)(entry + 0x28);  // Return COsiFunctionDef*
        }
        entry = *(entry + 8);
    }

    return NULL;
}
```

## Usage

To extract function name from a function ID:

```c
// 1. Get OsiFunctionMan instance
void** ppFuncMan = dlsym(osiris, "_OsiFunctionMan");
void* funcMan = *ppFuncMan;

// 2. Get pFunctionData function
typedef void* (*pFunctionDataFn)(void* funcMan, uint32_t funcId);
pFunctionDataFn pFunctionData = dlsym(osiris, "__ZN15COsiFunctionMan13pFunctionDataEj");

// 3. Look up function definition
void* funcDef = pFunctionData(funcMan, funcId);

// 4. Extract name via Signature indirection (CORRECTED)
if (funcDef) {
    // Read Signature pointer at offset 0x18
    void* signature = *(void**)((uint8_t*)funcDef + 0x18);
    if (signature) {
        // Read Name pointer from Signature at offset 0x08
        char* name = *(char**)((uint8_t*)signature + 0x08);
        // name now points to the function name string
    }
}
```

**Note:** The old documentation incorrectly showed reading name at `funcDef + 0x08`.
That offset contains `uint32_t Line`, not a pointer. Always use the two-level indirection.

## Function Types

Based on Windows BG3SE reference:

| Value | Type | Description |
|-------|------|-------------|
| 0 | Unknown | Not yet determined |
| 1 | Event | Triggered by game events |
| 2 | Query | Returns values, has output parameters |
| 3 | Call | Fire-and-forget function call |
| 4 | Proc | User-defined procedure |
| 5 | Database | Database query/insert |
| 6+ | Reserved | Various internal types |

## Notes

- Function strings (e.g., "AutomatedDialogStarted") are **not** in libOsiris.dylib
- They are loaded at runtime from story/goal files
- The function ID 2147492339 (0x80002E93) for AutomatedDialogStarted has high bit set
- IDs with high bit set (0x80000000) are registered functions, lower IDs are built-in

## Ghidra Analysis Commands

```bash
# Extract ARM64 slice
lipo libOsiris.dylib -thin arm64 -output libOsiris_arm64.dylib

# Run analysis with scripts
JAVA_HOME="/opt/homebrew/opt/openjdk@21/.../Contents/Home" \
  ~/ghidra/support/analyzeHeadless ~/ghidra_projects OsirisAnalysis \
  -import libOsiris_arm64.dylib \
  -processor AARCH64:LE:64:v8A \
  -postScript analyze_osiris_functions.py
```
