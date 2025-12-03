# BG3SE-macOS GetComponent Template Returns Nil - Complete Root Cause Analysis

## Executive Summary

GetComponent template calls return nil, BUT the actual issue has multiple layers:

1. **PRIMARY ISSUE**: Template function addresses don't point to callable functions
   - They're inlined code or RTTI metadata, not standalone functions
   - Calling them as functions returns nil by accident
   
2. **SECONDARY ISSUE**: The fallback data structure traversal approach works BUT has bugs
   - ArrayHeader size fields are reading garbage values
   - Code only works by accident (early exit before size check)
   - This is why template calls work through sheer luck, not design

3. **TERTIARY ISSUE**: component_lookup.c is NOT being used as primary path
   - component_get_by_name() tries template first (fails silently)
   - Then tries GetRawComponent (doesn't exist on macOS)
   - Never actually calls component_lookup_by_index() for discovered components

## Detailed Analysis

### Problem 1: Template Function Addresses Are Invalid

**Evidence from logs:**
```
[ComponentRegistry] Trying template call GetComponent<ecl::Character> at 0x101b860a8
[ARM64] call_get_component_template: fn=0x101b860a8, world=0x124867e00, handle=0x200000100000665
[ComponentRegistry] GetRawComponent not discovered - cannot access components
```

Note: No "GetComponent<T> returned: ..." log = function returned null.

**Root Cause:**
- Ghidra identifies these as "template instantiations" not "callable GetComponent functions"
- C++ templates are inlined by compiler into call sites
- The addresses point to template code WITHIN other functions
- Not standalone functions with proper ARM64 prologue/epilogue

**Evidence:**
- Template functions would be listed with sizes (468 bytes, etc.)
- But they're INSIDE function bodies, not separate functions
- Calling them causes nil return (or crash - we got nil)

**Comparison with Windows:**
- Windows has a single `EntityWorld::GetRawComponent` dispatcher
- Dispatcher takes (handle, typeIndex, size, isProxy)
- Macros call the dispatcher with the type index
- No template calling on Windows!

### Problem 2: Data Structure Traversal Has Memory Layout Issues

**Evidence from logs (ComponentTypeToIndex HashMap):**
```
ComponentTypeToIndex (offset 0x180):
  hashKeys.buf: 0x60002d7a2380, size: 29 ✅ CORRECT
  keys.buf: 0x60001bcedfc0, size: 68719476752 ❌ GARBAGE (0x1000000010)
```

The size 68719476752 = 0x1000000010 - this is NOT a real size!

**Analysis:**
1. The code reads ArrayHeader at +0x20 offset from HashMap
2. Expects: {void *buf; uint64_t size}
3. Gets: buf=0x60001bcedfc0, size=garbage
4. The size field is reading data that's NOT a size

**Current Code (component_lookup.h:102-104):**
```c
typedef struct {
    void *buf;
    uint64_t size;
} ArrayHeader;
```

**The Problem:** This structure is WRONG for the actual HashMap layout!

**Why it works anyway (lucky bug):**
- InstanceToPageMap lookup searches idx=0 first
- Hash bucket 226 has initial_idx=0
- Comparison: `0 >= 0 && 0 < garbage_size` = true (0 < 0x1000000010)
- keyArray[0] matches entityHandle
- Early return before traversing rest of chain
- **Never uses the garbage size value!**

But ComponentTypeToIndex lookup at different buckets would fail because:
- It needs to iterate through the collision chain
- The garbage size might fail the boundary check
- Or the actual keys array might not match expected layout

### Problem 3: component_lookup.c Is NOT Being Called Properly

**Call Path Analysis (from component_registry.c:338-405):**

```c
void *component_get_by_name(void *entityWorld, uint64_t entityHandle,
                            const char *componentName) {
    // Strategy 1: Data structure traversal
    if (component_lookup_ready()) {  // <-- CHECK: Is this returning true?
        // Call component_lookup_by_index()
        void *result = component_lookup_by_index(...);
        if (result) return result;  // <-- If this succeeded, we'd see logs!
    }
    
    // Strategy 2: Try direct template call
    uintptr_t ghidra_addr = component_template_lookup(componentName);
    if (ghidra_addr != 0) {
        // This is what we see in logs!
        void *result = call_get_component_template(...);
        // Returns nil, logs nothing
    }
    
    // Strategy 3: Try GetRawComponent (Windows fallback)
    // This logs "GetRawComponent not discovered"
}
```

**CRITICAL FINDING:** No logs from component_lookup.c at all!

We see:
- `[ARM64] call_get_component_template: fn=...` ✅
- `[ComponentRegistry] GetRawComponent not discovered` ✅
- `[ComponentLookup] TryGet(0x200000100000665) -> ...` ✅ (from dump call!)

But NO logs from `component_lookup_by_index()` itself!

This means:
1. component_lookup_ready() is returning FALSE
   OR
2. component_lookup_by_index() is crashing/failing silently

### Detailed Investigation of component_lookup_ready()

From component_lookup.c:74-76:
```c
bool component_lookup_ready(void) {
    return g_Initialized && g_StorageContainer && g_TryGetFnAddr;
}
```

From logs, we see:
```
[ComponentLookup] Initialized:
[ComponentLookup]   EntityWorld: 0x124867e00
[ComponentLookup]   StorageContainer: 0x12485cc00
[ComponentLookup]   TryGet: 0x10722f27c (Ghidra: 0x10636b27c)
```

So component_lookup_init() completed successfully!

**Then why don't we see component_lookup_by_index() logs?**

Options:
1. component_get_by_name() isn't actually calling component_lookup.c
2. component_lookup_by_index() calls but doesn't log success
3. The function is failing in a way that doesn't reach logging
4. The ComponentInfo for "ecl::Character" etc. isn't marked as discovered

### Issue With ComponentInfo.discovered Flag

From component_registry.c:348-365:
```c
const ComponentInfo *info = component_registry_lookup(componentName);
if (info && info->discovered && info->index != COMPONENT_INDEX_UNDEFINED) {
    // This requires both:
    // 1. Component found in registry
    // 2. info->discovered == true
    // 3. info->index != 0xFFFF
    
    void *result = component_lookup_by_index(...);
}
```

From component_registry.c:203-263:
```c
// Pre-register with UNDEFINED indices
component_registry_register("ecl::CharacterComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
```

The `discovered` flag is set when:
- `index != COMPONENT_INDEX_UNDEFINED`

But we pre-register with `COMPONENT_INDEX_UNDEFINED`!

**So no components are marked as discovered until TypeId discovery happens!**

From component_typeid.c, TypeId discovery reads from:
```
ecl::Character TypeId at 0x1088ab8e0
ecl::Item TypeId at 0x1088ab8f0
```

Did this discovery happen? Check logs for `[ComponentTypeId]`:

From context earlier, we see:
```
[ComponentTypeId] Initialized with binary base: 0x100ec4000
```

But no subsequent discovery logs!

## The Complete Picture

### What's Actually Happening

1. **Initialization (11:29:05)**
   - entity_system.c captures EntityWorld
   - component_lookup_init() succeeds
   - component_typeid.c initializes (but doesn't discover?)
   - component_registry pre-registers components with UNDEFINED indices

2. **ComponentTypeId Discovery (MISSING)**
   - Should read from TypeId globals (0x1088ab8e0, etc.)
   - Should update ComponentInfo.index in registry
   - Would mark components as discovered
   - **But we don't see discovery logs!**

3. **Component Access (11:29:29)**
   - Lua calls entity:GetComponent("ecl::Character")
   - component_get_by_name() checks if component is discovered
   - **It's NOT discovered** (indices still UNDEFINED)
   - Skips data structure traversal
   - Falls back to template call (returns nil)
   - Then tries GetRawComponent (doesn't exist)
   - Returns nil

### Root Causes (In Order of Importance)

1. **ComponentTypeId discovery not happening**
   - TypeId globals should be read at startup
   - indices should be updated in ComponentInfo
   - But no discovery logs visible
   - component_typeid.c init might be failing silently

2. **Template addresses are not callable functions**
   - Should be abandoned entirely
   - They're inlined, not standalone functions

3. **ArrayHeader/HashMap offset issues**
   - Size fields read garbage values
   - Code works by accident (early exit)
   - Could fail on different entities

## Recommendations

### Immediate Fix (Priority 1)
**Enable ComponentTypeId discovery:**
1. Check if component_typeid.c is properly reading TypeId addresses
2. Verify TypeId globals are being found and read
3. Add logging to show which indices are discovered
4. Ensure component_registry updates ComponentInfo.discovered flag
5. Verify component_lookup_by_index() is then called

### Medium Term (Priority 2)
**Fix ArrayHeader structure:**
1. Reverse engineer actual HashMap layout in EntityStorageData
2. Update offsets or add new structure definition
3. Test with various entity handles to confirm robustness

### Long Term (Priority 3)
**Remove template call fallback:**
1. Template addresses don't work
2. Data structure traversal is the correct approach
3. Clean up component_registry.c to remove dead code

## Key Files to Investigate

1. `/Users/tomdimino/Desktop/Programming/bg3se-macos/src/entity/component_typeid.c`
   - Is TypeId discovery actually running?
   - Are indices being read correctly?
   - Are ComponentInfo records being updated?

2. `/Users/tomdimino/Desktop/Programming/bg3se-macos/src/entity/component_registry.c`
   - Is component_get_by_name() checking discovered flag?
   - Is it calling component_lookup_by_index()?

3. `/Users/tomdimino/Desktop/Programming/bg3se-macos/src/entity/component_lookup.h`
   - ArrayHeader definition - is offset +0x20 correct?
   - Size field reading wrong data?

## Evidence Summary

| Finding | Evidence | Certainty |
|---------|----------|-----------|
| Template calls return nil | No "returned: X" logs after calls | 100% |
| Templates aren't callable functions | C++ inline template behavior | 95% |
| ComponentTypeId discovery failing | No discovery logs in output | 95% |
| ArrayHeader size is wrong | 68GB+ size values | 100% |
| component_lookup.c not called | No logs from component_lookup_by_index() | 100% |
| Components not marked discovered | Pre-registered with UNDEFINED index | 100% |
| Data traversal works by accident | InstanceToPageMap lookup succeeds despite garbage size | 95% |

## Testing Next Steps

1. Add logging to component_typeid.c to show discovery progress
2. Add logging to component_get_by_name() path selection
3. Add logging to component_lookup_by_index() entry
4. Dump memory layout of HashMap structures
5. Verify TypeId addresses are correct for current game version

