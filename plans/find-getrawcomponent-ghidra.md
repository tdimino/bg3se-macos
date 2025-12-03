# Plan: Find GetRawComponent via Ghidra Analysis

## Overview

Locate the `GetRawComponent` function in the BG3 macOS ARM64 binary using Ghidra static analysis. This function is the central dispatcher for all component access in the Entity Component System.

## Problem Statement

The component registry is implemented and pre-registers 50 components, but **cannot access any components** without the `GetRawComponent` address. This function:
- Is not exported (no symbol)
- Cannot be found via string XREFs (RTTI metadata has no references)
- Must be located through behavioral/structural analysis

## Target Function Signature

```c
void* GetRawComponent(
    EntityWorld* world,      // x0: pointer
    EntityHandle handle,     // x1: uint64_t
    ComponentTypeIndex type, // w2: uint16_t
    size_t componentSize,    // x3: size_t
    bool isProxy             // w4: bool
)
```

**Key Behavioral Traits** (from Windows bg3se `EntitySystem.cpp:457-484`):
1. Checks one-frame bit: `type & 0x8000`
2. Calls `GetEntityStorage(handle)`
3. Has three fallback paths: storage → write cache → read cache
4. Returns pointer or NULL

## Proposed Approaches

### Approach 1: ARM64 Instruction Pattern Search (Recommended)

**Rationale:** The one-frame bit check (`0x8000`) is distinctive and searchable.

**ARM64 Instructions to Find:**
```asm
; Check one-frame bit - MUST exist in GetRawComponent
TST W2, #0x8000        ; Test bit 15 of type index
; or
AND W8, W2, #0x8000    ; Isolate bit 15
```

**Ghidra Script Strategy:**
```python
# Pseudocode for find_getrawcomponent.py
from ghidra.program.model.listing import CodeUnit

def find_one_frame_check():
    """Find functions that test bit 0x8000 on a 16-bit parameter"""
    candidates = []

    listing = currentProgram.getListing()
    for func in currentProgram.getFunctionManager().getFunctions(True):
        # Skip small functions (GetRawComponent is 100-300 instructions)
        if func.getBody().getNumAddresses() < 50:
            continue

        # Check for TST or AND with 0x8000
        for instr in listing.getInstructions(func.getBody(), True):
            mnemonic = instr.getMnemonicString()
            if mnemonic in ["TST", "AND", "ANDS"]:
                # Check if operand contains 0x8000
                for i in range(instr.getNumOperands()):
                    op = instr.getDefaultOperandRepresentation(i)
                    if "0x8000" in op or "#32768" in op:
                        candidates.append((func, instr.getAddress()))

    return candidates
```

**Implementation Steps:**
1. Create `ghidra/scripts/find_getrawcomponent.py`
2. Search for `TST W?, #0x8000` or `AND W?, W?, #0x8000`
3. Filter candidates by:
   - Function size: 50-500 instructions
   - Has 5 parameters (check decompiler output)
   - Returns pointer (void*)
   - Contains multiple conditional branches (fallback logic)

---

### Approach 2: Trace from Known Hook

**Rationale:** We already hook `LEGACY_IsInCombat` which receives `EntityWorld&`. Functions called from combat code likely access components.

**Strategy:**
1. In Ghidra, go to `LEGACY_IsInCombat` at `0x10124f92c`
2. Analyze its call graph (callers and callees)
3. Look for functions that:
   - Take EntityWorld as first parameter
   - Take a 16-bit type index
   - Access entity storage structures

**Manual Investigation:**
```
LEGACY_IsInCombat (0x10124f92c)
    └── Calls functions that check combat state
        └── These likely call GetComponent to read character stats
            └── GetComponent internally calls GetRawComponent
```

---

### Approach 3: EntityStorage Structure Analysis

**Rationale:** GetRawComponent accesses `EntityWorld->Storage->EntityStorageData`. Finding storage access patterns leads to the function.

**Key Offsets** (from reference implementation):
- `EntityWorld + 0x???` → Storage pointer
- `Storage + 0x???` → EntityStorageData array
- Storage access uses `handle.ThreadIndex` and `handle.Salt`

**Search Strategy:**
1. Find functions that dereference EntityWorld at consistent offsets
2. Look for array indexing patterns (storage lookup)
3. Verify by checking for cache fallback logic

---

### Approach 4: Frida Dynamic Tracing (Backup)

If static analysis fails, use runtime tracing:

```javascript
// In tools/frida/discover_components.js
// Hook a known component user and trace callers

// 1. Find a function that accesses Transform (we know it works)
// 2. Set breakpoint, examine call stack
// 3. Identify GetRawComponent in the trace
```

---

## Implementation Plan

### Phase 1: Create Ghidra Script

**File:** `ghidra/scripts/find_getrawcomponent.py`

```python
# @category BG3SE
# @description Find GetRawComponent by searching for 0x8000 bit test

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType

def main():
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()

    print("=== Searching for GetRawComponent candidates ===")
    print("Looking for functions with TST/AND #0x8000 pattern...")

    candidates = []

    for func in fm.getFunctions(True):
        body = func.getBody()
        size = body.getNumAddresses()

        # Size filter: 50-500 instructions typical for this function
        if size < 50 or size > 2000:
            continue

        for instr in listing.getInstructions(body, True):
            mnemonic = instr.getMnemonicString()

            if mnemonic in ["tst", "TST", "and", "AND", "ands", "ANDS"]:
                op_str = str(instr)
                if "0x8000" in op_str or "#32768" in op_str:
                    candidates.append({
                        'func': func,
                        'addr': func.getEntryPoint(),
                        'size': size,
                        'instr': instr.getAddress(),
                        'pattern': op_str
                    })
                    break  # One match per function

    print(f"\nFound {len(candidates)} candidates:\n")

    for i, c in enumerate(candidates):
        print(f"[{i}] {c['addr']} - {c['func'].getName()}")
        print(f"    Size: {c['size']} bytes")
        print(f"    Pattern at: {c['instr']}")
        print(f"    Instruction: {c['pattern']}")
        print()

    # Further filtering hints
    print("=== Next Steps ===")
    print("1. Check each candidate's decompiled signature for 5 parameters")
    print("2. Look for EntityHandle (uint64) and ComponentTypeIndex (uint16) params")
    print("3. Verify function has multiple return paths (fallback logic)")
    print("4. Test with Frida: setGetRawComponent('0xADDRESS')")

if __name__ == "__main__":
    main()
```

### Phase 2: Run Analysis

```bash
# Headless analysis with the script
JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
  ~/ghidra/support/analyzeHeadless ~/ghidra_projects BG3Analysis \
  -process BG3_arm64_thin \
  -scriptPath /Users/tomdimino/Desktop/Programming/bg3se-macos/ghidra/scripts \
  -preScript optimize_analysis.py \
  -postScript find_getrawcomponent.py \
  2>&1 | tee /tmp/getrawcomponent_search.log
```

### Phase 3: Verify Candidate

Once candidates are identified:

1. **Decompile in Ghidra GUI** - Check parameter count and types
2. **Verify with Frida:**
   ```javascript
   // In Frida REPL
   setGetRawComponent("0x<candidate_address>")
   // Play game, access a character
   dumpDiscoveries()
   // If components appear with valid indices, address is correct
   ```

### Phase 4: Update Component Registry

Once confirmed:
```lua
-- In game Lua console
Ext.Entity.SetGetRawComponentAddr(0x<confirmed_address>)

-- Test component access
local entity = Ext.Entity.Get("c7c13742-bacd-460a-8f65-f864fe41f255")
local health = entity:GetComponent("eoc::HealthComponent")
```

---

## Acceptance Criteria

- [ ] Ghidra script created at `ghidra/scripts/find_getrawcomponent.py`
- [ ] Script finds candidates with `0x8000` bit test
- [ ] At least one candidate verified via Frida
- [ ] GetRawComponent address documented in `ghidra/offsets/COMPONENTS.md`
- [ ] Component access works in Lua after setting address

## Success Metrics

- GetRawComponent address discovered
- `Ext.Entity.SetGetRawComponentAddr()` enables component access
- At least one component (e.g., `eoc::HealthComponent`) accessible via Lua

## References

### Internal
- `src/entity/component_registry.c` - Uses GetRawComponent address
- `ghidra/offsets/COMPONENTS.md` - Component discovery documentation
- `tools/frida/discover_components.js` - Runtime verification

### External
- Windows bg3se `EntitySystem.cpp:457-484` - Reference implementation
- [Ghidra Wildcard Instruction Search](https://fossies.org/linux/misc/ghidra-Ghidra_11.3.2_build.tar.gz/ghidra-Ghidra_11.3.2_build/Ghidra/Features/WildcardAssembler/ghidra_scripts/FindInstructionWithWildcard.java)
- [ARM64 Bit Masking Patterns](https://computerscience.chemeketa.edu/armTutorial/Bitwise/Masking.html)
