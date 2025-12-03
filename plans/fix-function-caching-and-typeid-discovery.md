# fix: Function Caching and TypeId Discovery

**Date:** 2025-12-03
**Type:** Bug Fix
**Priority:** High
**Affects:** Entity Component System, Osiris Function Caching

## Overview

Two critical issues prevent eoc:: component discovery from working properly:

1. **Function caching fails** - `safe_memory_check_address()` incorrectly rejects valid heap addresses (0x6000...)
2. **TypeId discovery shows all zeros** - TypeId globals are read too early, before game initializes them

Both issues have the same root cause: the safety infrastructure works (no crashes), but the functionality doesn't deliver results.

## Problem Statement

### Issue 1: mach_vm_region Validation Bug

**Location:** `src/core/safe_memory.c:46-52`

```c
/* Check if the original address falls within the returned region
 * mach_vm_region returns the region at or AFTER the address,
 * so we need to verify the address is actually inside it */
if (address < region_addr || address >= region_addr + region_size) {
    /* Address is in a gap between regions */
    return info;
}
```

**The Bug:** `mach_vm_region` modifies the `region_addr` parameter to point to the **next** mapped region if the input address is in a gap. The current check correctly handles this case. However, the issue is that `region_addr` is initialized TO the input address before the call:

```c
mach_vm_address_t region_addr = address;  // Set to input address
kern_return_t kr = mach_vm_region(..., &region_addr, ...);  // May modify region_addr
```

When `mach_vm_region` is called with a valid heap address like `0x6000256bf040`, it can:
- Return KERN_SUCCESS
- Set `region_addr` to a value HIGHER than the input (the next region start)
- The check `address < region_addr` then fails

**Evidence from logs:**
```
[FuncCache] Failed to extract name for funcId=0x800022ab, funcDef=0x6000256bf040 (memory inaccessible or invalid)
```

The funcDef pointer `0x6000256bf040` is a valid heap allocation, but validation fails.

### Issue 2: TypeId Discovery Timing

**Location:** `src/entity/entity_system.c:900-903`

```c
// Called from entity_system_init() at injection time
component_typeid_init(binaryBase);
int discovered = component_typeid_discover();
```

**The Bug:** TypeId discovery runs at **dylib injection time**, which is before the game's component registration system initializes. The `TypeId<T>::m_TypeIndex` static variables are -1 or 0 until the game's type registration runs.

**Evidence from logs:**
```
[ComponentTypeId]   TypeIndex=0 at 0x1097238e0 (Ghidra 0x1088ab8e0)
[ComponentTypeId]   ecl::Character: index=0 (from 0x1088ab8e0)
```

All TypeIds read as 0, which is the uninitialized value.

## Proposed Solution

### Fix 1: Correct mach_vm_region Validation

**Approach:** The current logic is actually correct in theory, but we need to add better diagnostics and potentially use `mach_vm_read` as a secondary validation.

**Changes to `src/core/safe_memory.c`:**

```c
SafeMemoryInfo safe_memory_check_address(mach_vm_address_t address) {
    SafeMemoryInfo info = {0};

    if (address == 0 || address < 0x1000) {
        return info;
    }

    mach_port_t task = mach_task_self();
    mach_vm_address_t region_addr = address;
    mach_vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t region_info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name = MACH_PORT_NULL;

    kern_return_t kr = mach_vm_region(
        task,
        &region_addr,
        &region_size,
        VM_REGION_BASIC_INFO_64,
        (vm_region_info_t)&region_info,
        &info_count,
        &object_name
    );

    if (kr != KERN_SUCCESS) {
        return info;
    }

    /* CRITICAL: Verify address is WITHIN the returned region
     * mach_vm_region returns the region AT OR AFTER the queried address */
    if (address < region_addr || address >= region_addr + region_size) {
        /* Address is in a gap - try the PREVIOUS search approach */
        /* This shouldn't happen for valid heap addresses, log for diagnostics */
        return info;
    }

    info.is_valid = true;
    info.is_readable = (region_info.protection & VM_PROT_READ) != 0;
    info.is_writable = (region_info.protection & VM_PROT_WRITE) != 0;
    info.region_start = region_addr;
    info.region_size = region_size;

    return info;
}
```

**Additional Fix:** Skip validation for funcDef pointers and use direct `mach_vm_read` instead:

```c
// In osiris_functions.c - extract_func_name_from_def()
// Instead of validating then reading, just try to read directly

static const char *extract_func_name_from_def(void *funcDef) {
    if (!funcDef) return NULL;

    mach_vm_address_t funcDefAddr = (mach_vm_address_t)funcDef;

    /* Skip GPU region check - these are clearly not GPU addresses */
    if (safe_memory_is_gpu_region(funcDefAddr)) {
        return NULL;
    }

    /* Try direct read without pre-validation - mach_vm_read will fail safely */
    void *namePtr = NULL;
    if (!safe_memory_read_pointer(funcDefAddr + 8, &namePtr)) {
        return NULL;  // Read failed, address invalid
    }

    // ... rest of function
}
```

### Fix 2: Deferred TypeId Discovery

**Approach:**
1. Keep initial discovery attempt (may succeed if game loads fast)
2. Add automatic retry at SessionLoaded event
3. Add manual `Ext.Entity.DiscoverTypeIds()` Lua API for explicit control

**Changes to `src/entity/entity_system.c`:**

```c
/* Add retry state */
static bool g_TypeIdDiscoveryComplete = false;
static int g_TypeIdRetryCount = 0;
#define TYPEID_MAX_RETRIES 10
#define TYPEID_RETRY_DELAY_MS 100

/* Called from SessionLoaded hook */
void entity_retry_typeid_discovery(void) {
    if (g_TypeIdDiscoveryComplete) return;

    int discovered = component_typeid_discover();
    if (discovered > 0) {
        g_TypeIdDiscoveryComplete = true;
        log_message("[Entity] TypeId discovery succeeded: %d components", discovered);
    } else {
        g_TypeIdRetryCount++;
        if (g_TypeIdRetryCount < TYPEID_MAX_RETRIES) {
            log_message("[Entity] TypeId discovery retry %d/%d",
                       g_TypeIdRetryCount, TYPEID_MAX_RETRIES);
            // Schedule another retry (via timer or next event)
        }
    }
}
```

**Lua API Addition:**

```c
// In lua_ext.c or entity_system.c Lua bindings
static int lua_entity_discover_typeids(lua_State *L) {
    int discovered = component_typeid_discover();

    lua_createtable(L, 0, 3);
    lua_pushboolean(L, discovered > 0);
    lua_setfield(L, -2, "success");
    lua_pushinteger(L, discovered);
    lua_setfield(L, -2, "discovered_count");

    if (discovered == 0) {
        lua_pushstring(L, "TypeIds not yet initialized, retry after SessionLoaded");
    } else {
        lua_pushstring(L, "Discovery complete");
    }
    lua_setfield(L, -2, "message");

    return 1;
}
```

## Technical Approach

### Phase 1: Diagnostic Logging (30 min)

Add verbose logging to understand exactly why validation fails:

**File:** `src/core/safe_memory.c`

```c
SafeMemoryInfo safe_memory_check_address(mach_vm_address_t address) {
    // ... existing code ...

    #ifdef BG3SE_VERBOSE_MEMORY
    if (address < region_addr || address >= region_addr + region_size) {
        log_message("[SafeMemory] VALIDATION FAILED:");
        log_message("  Queried:  0x%llx", (unsigned long long)address);
        log_message("  Region:   0x%llx - 0x%llx",
                   (unsigned long long)region_addr,
                   (unsigned long long)(region_addr + region_size));
        log_message("  Gap:      address %s region",
                   address < region_addr ? "BELOW" : "ABOVE");
    }
    #endif

    // ... rest of function ...
}
```

### Phase 2: Fix Memory Validation (1 hour)

**Option A: Trust mach_vm_read**

Remove pre-validation for heap addresses, rely on `mach_vm_read_overwrite` to fail safely:

```c
bool safe_memory_read(mach_vm_address_t source, void *dest, size_t size) {
    if (dest == NULL || size == 0) {
        return false;
    }

    /* Skip GPU region even without full validation */
    if (safe_memory_is_gpu_region(source)) {
        return false;
    }

    /* Direct read - will return error if address invalid */
    mach_vm_size_t bytes_read = size;
    kern_return_t kr = mach_vm_read_overwrite(
        mach_task_self(),
        source,
        size,
        (mach_vm_address_t)dest,
        &bytes_read
    );

    return kr == KERN_SUCCESS && bytes_read == size;
}
```

**Option B: Use mach_vm_read (allocating version)**

Research suggests `mach_vm_read` (not `_overwrite`) is more reliable on ARM64:

```c
bool safe_memory_read(mach_vm_address_t source, void *dest, size_t size) {
    if (dest == NULL || size == 0) return false;
    if (safe_memory_is_gpu_region(source)) return false;

    vm_offset_t read_data;
    mach_msg_type_number_t read_count;

    kern_return_t kr = mach_vm_read(
        mach_task_self(),
        source,
        size,
        &read_data,
        &read_count
    );

    if (kr == KERN_SUCCESS && read_count == size) {
        memcpy(dest, (void*)read_data, size);
        vm_deallocate(mach_task_self(), read_data, read_count);
        return true;
    }

    return false;
}
```

### Phase 3: Deferred TypeId Discovery (1 hour)

**Changes:**

1. **Keep initial attempt** in `entity_system_init()` (may work)
2. **Add retry in SessionLoaded** hook in `main.c`
3. **Add Lua API** for manual control

**File:** `src/entity/entity_system.c`

```c
// Add to header
bool entity_typeid_discovery_complete(void);
int entity_retry_typeid_discovery(void);

// Implementation
static bool g_TypeIdDiscoveryComplete = false;

bool entity_typeid_discovery_complete(void) {
    return g_TypeIdDiscoveryComplete;
}

int entity_retry_typeid_discovery(void) {
    if (g_TypeIdDiscoveryComplete) {
        return component_registry_get_discovered_count();
    }

    int discovered = component_typeid_discover();

    /* Check if any TypeIds were actually found (not all zeros) */
    if (discovered > 0) {
        /* Verify at least one has a non-zero index */
        ComponentInfo *info = component_registry_get_by_name("eoc::StatsComponent");
        if (info && info->typeIndex != COMPONENT_INDEX_UNDEFINED && info->typeIndex != 0) {
            g_TypeIdDiscoveryComplete = true;
            log_message("[Entity] TypeId discovery complete: %d components", discovered);
        }
    }

    return discovered;
}
```

**File:** `main.c` - Add to SessionLoaded handler:

```c
// In fake_StoryLoaded or session load callback
if (!entity_typeid_discovery_complete()) {
    log_message("[Entity] Retrying TypeId discovery after SessionLoaded...");
    entity_retry_typeid_discovery();
}
```

### Phase 4: Lua API (30 min)

**File:** `src/entity/entity_system.c` - Lua bindings section:

```c
static int lua_entity_discover_typeids(lua_State *L) {
    int discovered = entity_retry_typeid_discovery();
    bool complete = entity_typeid_discovery_complete();

    lua_createtable(L, 0, 3);

    lua_pushboolean(L, complete);
    lua_setfield(L, -2, "success");

    lua_pushinteger(L, discovered);
    lua_setfield(L, -2, "count");

    lua_pushboolean(L, complete);
    lua_setfield(L, -2, "complete");

    return 1;
}

// Register in entity_system_register_lua()
lua_pushcfunction(L, lua_entity_discover_typeids);
lua_setfield(L, -2, "DiscoverTypeIds");
```

## Acceptance Criteria

### Functional Requirements

- [ ] `safe_memory_read()` succeeds for valid heap addresses (0x6000...)
- [ ] `osi_func_cache_from_event()` successfully caches function names
- [ ] TypeId discovery returns non-zero values after SessionLoaded
- [ ] At least 4 of 6 core eoc:: components have valid TypeIds discovered
- [ ] `Ext.Entity.GetComponent("StatsComponent")` returns valid data
- [ ] `Ext.Entity.DiscoverTypeIds()` returns accurate status

### Non-Functional Requirements

- [ ] No SIGBUS/SIGSEGV crashes from memory access
- [ ] Discovery completes within 100ms
- [ ] Verbose logging available for debugging
- [ ] Graceful degradation if discovery fails

### Quality Gates

- [ ] Test on fresh game launch
- [ ] Test on save game load
- [ ] Test with EntityTest mod
- [ ] Verify logs show successful caching/discovery

## Implementation Files

| File | Changes |
|------|---------|
| `src/core/safe_memory.c` | Fix validation, add diagnostics |
| `src/core/safe_memory.h` | No changes needed |
| `src/osiris/osiris_functions.c` | Simplify validation in extract_func_name_from_def |
| `src/entity/entity_system.c` | Add retry logic, Lua API |
| `src/entity/entity_system.h` | Export new functions |
| `src/entity/component_typeid.c` | Add validation for zero values |
| `src/injector/main.c` | Add SessionLoaded retry trigger |

## Risk Analysis & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| mach_vm_read fails on some addresses | High | Keep fallback to _overwrite, add logging |
| TypeIds never initialize (game bug) | Medium | Max retry count, clear error message |
| Race condition in concurrent discovery | Medium | Add mutex around discovery |
| Game update changes TypeId addresses | High | Version detection, refuse to run if mismatch |

## Testing Plan

### Manual Test Cases

1. **Fresh Launch Test**
   - Launch game without mods
   - Load a save
   - Check logs for TypeId discovery success
   - Expected: TypeIds discovered after SessionLoaded

2. **EntityTest Mod Test**
   - Enable EntityTest mod
   - Load save with player character
   - Call `Ext.Entity.Get(player_guid):GetComponent("StatsComponent")`
   - Expected: Returns valid component data

3. **Function Caching Test**
   - Play for 1 minute with Osiris events firing
   - Check logs for `[FuncCache] SUCCESS:` messages
   - Expected: Multiple function names cached

4. **Manual Discovery Test**
   - In Lua console: `print(Ext.Entity.DiscoverTypeIds())`
   - Expected: `{success=true, count=N, complete=true}`

## References

### Internal References
- `src/core/safe_memory.c:46-52` - Problematic validation logic
- `src/entity/entity_system.c:900-903` - Early discovery call
- `docs/COMPONENT_NIL_ROOT_CAUSE.md` - Previous analysis
- `ghidra/offsets/COMPONENTS.md` - Component addresses

### External References
- [Julia Evans - Mac Memory Maps](https://jvns.ca/blog/2018/01/26/mac-memory-maps/)
- [MIT vm_region documentation](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/vm_region.html)
- [Stack Overflow - Safely checking pointer validity on macOS](https://stackoverflow.com/questions/56177752/safely-checking-a-pointer-for-validity-in-macos)
- [RevelariOS - vm_region deep dive](https://psychobird.github.io/RevelariOS/RevelariOS.html)

### Related Issues
- Issue #2 - eoc:: component discovery (this plan addresses it)
