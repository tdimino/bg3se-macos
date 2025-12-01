# Issue #2: Component Discovery Implementation Plan

## Overview

Implement a robust component discovery system for BG3SE-macOS that mirrors the Windows bg3se approach: **runtime index-based component lookup** rather than hardcoded function addresses.

**Key Insight from Research:** Component strings are RTTI metadata with NO XREFs - the game uses a ComponentRegistry with uint16_t type indices, not direct function pointers.

## Problem Statement

Current state:
- ✅ EntityWorld captured via `LEGACY_IsInCombat` hook
- ✅ GUID → EntityHandle lookup working (1873 entities)
- ✅ TryGetSingleton working with ARM64 x8 ABI fix
- ❌ GetComponent addresses were INVALID (11-digit hex values)
- ❌ Component string addresses have NO XREFs in Ghidra analysis
- ❌ Direct function pointer approach won't work

The Windows bg3se uses `ComponentTypeIndex` (uint16_t) at runtime, discovered through binary pattern scanning of component registration code.

## Proposed Solution: Index-Based Component Access

### Architecture (Matching bg3se)

```
┌─────────────────────────────────────────────────────────────┐
│                     Component Discovery                      │
├─────────────────────────────────────────────────────────────┤
│  Phase 1: Find GetRawComponent                               │
│    └─ Single function: GetRawComponent(handle, typeIdx,     │
│                                        size, isProxy)        │
├─────────────────────────────────────────────────────────────┤
│  Phase 2: Runtime Index Discovery                            │
│    └─ Hook component registration to capture name→index map  │
│    └─ Or: Iterate ComponentRegistry at runtime               │
├─────────────────────────────────────────────────────────────┤
│  Phase 3: Lua API                                            │
│    └─ entity:GetComponent("HealthComponent") uses index      │
│    └─ Ext.Entity.DumpComponentRegistry() for debugging       │
└─────────────────────────────────────────────────────────────┘
```

## Technical Approach

### Phase 1: Find EntityWorld::GetRawComponent (1-2 days)

**Goal:** Locate the single dispatcher function that all component access goes through.

**From bg3se research** (`BG3Extender/GameDefinitions/EntitySystem.cpp:457-484`):
```cpp
void* EntityWorld::GetRawComponent(EntityHandle entityHandle,
                                   ComponentTypeIndex type,
                                   std::size_t componentSize,
                                   bool isProxy)
{
    auto storage = GetEntityStorage(entityHandle);
    if (IsOneFrame(type)) {
        return storage->GetOneFrameComponent(entityHandle, type);
    } else {
        auto component = storage->GetComponent(entityHandle, type,
                                               componentSize, isProxy);
        // ... cache checks ...
    }
    return nullptr;
}
```

**Discovery Strategy:**
1. **Pattern scan for signature**: Function that takes (EntityHandle, uint16_t, size_t, bool)
2. **Hook EntityStorageData::GetComponent** and trace callers
3. **Use Frida for dynamic discovery** (recommended for ARM64 macOS)

**Files to create:**
- `src/entity/component_registry.h` - ComponentTypeIndex, registry structures
- `src/entity/component_registry.c` - Runtime discovery implementation

### Phase 2: Component Registry Discovery (2-3 days)

**Goal:** Build runtime map of component names → type indices.

**From bg3se research** (`BG3Extender/GameHooks/DataLibrariesBG3Game.cpp:42-88`):

The Windows version uses three callbacks during binary scanning:
- `BindECSContext` - Maps context pointers to type names
- `BindECSIndex` - Maps component indices to names
- `BindECSStaticRegistrant` - Maps static registrants

**macOS Approach Options:**

#### Option A: Frida Dynamic Instrumentation (Recommended)
```javascript
// discovery_components.js
const componentStrings = [
    "eoc::HealthComponent",
    "ls::TransformComponent",
    "eoc::ArmorComponent"
];

Interceptor.attach(ptr("0x...GetRawComponent"), {
    onEnter: function(args) {
        const typeIndex = args[1].toInt32() & 0xFFFF;
        console.log(`GetRawComponent called with typeIndex: ${typeIndex}`);
        // Build name→index map by observing runtime calls
    }
});
```

#### Option B: ComponentRegistry Iteration
If we can find the ComponentRegistry pointer within EntityWorld:
```c
// Offset from EntityWorld to ComponentRegistry
#define ENTITYWORLD_COMPONENT_REGISTRY_OFFSET 0x??? // TBD via Ghidra

typedef struct {
    uint16_t TypeId;
    uint16_t InlineSize;
    uint16_t ComponentSize;
    bool Replicated;
    bool OneFrame;
} ComponentTypeEntry;

void dump_component_registry(void *entityWorld) {
    void *registry = (char*)entityWorld + ENTITYWORLD_COMPONENT_REGISTRY_OFFSET;
    // Iterate Types array...
}
```

#### Option C: Pattern Scan Component Registration
Search for assembly patterns that match component registration:
```
ADRP X?, #component_name_string@PAGE
ADD  X?, X?, #component_name_string@PAGEOFF
MOV  W?, #component_type_index
BL   register_component_func
```

**Files to modify:**
- `src/entity/entity_system.c` - Add registry capture
- `ghidra/scripts/find_component_registry.py` - New Ghidra script

### Phase 3: Implement GetComponent API (1-2 days)

**Goal:** Expose component access through Lua API using discovered indices.

**Lua API Design:**
```lua
-- Get component by name (uses cached index lookup)
local health = entity:GetComponent("eoc::HealthComponent")
local transform = entity:GetComponent("ls::TransformComponent")

-- Dump registry for debugging
local registry = Ext.Entity.DumpComponentRegistry()
for name, info in pairs(registry) do
    print(name, info.typeIndex, info.size)
end
```

**C Implementation:**
```c
// component_registry.h
typedef struct {
    const char *name;
    uint16_t typeIndex;
    uint16_t componentSize;
    bool isProxy;
} ComponentInfo;

// Public API
bool component_registry_init(void *entityWorld);
ComponentInfo *component_registry_lookup(const char *name);
void *component_get_raw(void *entityWorld, uint64_t entityHandle,
                        const char *componentName);

// entity_system.c - Lua binding
static int lua_entity_get_component(lua_State *L) {
    // 1. Get entity handle from userdata
    // 2. Get component name from arg
    // 3. Lookup index from registry
    // 4. Call GetRawComponent
    // 5. Return component data as Lua table
}
```

**Files to create/modify:**
- `src/entity/component_registry.c` - Core implementation
- `src/entity/entity_system.c` - Add GetComponent Lua binding
- `src/lua/lua_entity.c` - Add DumpComponentRegistry

### Phase 4: Frida Discovery Script (1 day)

**Goal:** Create Frida script for ARM64 macOS component discovery.

```javascript
// tools/frida/discover_components.js

const knownComponents = new Map();
const GetRawComponent = ptr("0x..."); // TBD

Interceptor.attach(GetRawComponent, {
    onEnter: function(args) {
        this.entityHandle = args[0].toString();
        this.typeIndex = args[1].toInt32() & 0xFFFF;
        this.size = args[2].toInt32();
        this.isProxy = args[3].toInt32() !== 0;
    },
    onLeave: function(retval) {
        if (retval.isNull()) return;

        // Log discovery
        console.log(JSON.stringify({
            typeIndex: this.typeIndex,
            size: this.size,
            isProxy: this.isProxy,
            address: retval.toString()
        }));
    }
});

// Attach to component registration for name discovery
const RegisterComponent = ptr("0x..."); // TBD
Interceptor.attach(RegisterComponent, {
    onEnter: function(args) {
        const name = args[0].readUtf8String();
        const index = args[1].toInt32() & 0xFFFF;
        knownComponents.set(index, name);
        console.log(`Registered: ${name} = ${index}`);
    }
});
```

**Files to create:**
- `tools/frida/discover_components.js`
- `tools/frida/README.md` - Usage instructions

## Acceptance Criteria

### Functional Requirements

- [ ] `Ext.Entity.DumpComponentRegistry()` returns map of all known components
- [ ] `entity:GetComponent("eoc::HealthComponent")` returns component data
- [ ] `entity:GetComponent("ls::TransformComponent")` returns position/rotation
- [ ] Component access works for at least 10 common component types
- [ ] No hardcoded function addresses - all index-based

### Non-Functional Requirements

- [ ] Component lookup < 1ms per call (cached index)
- [ ] Registry initialization < 100ms at startup
- [ ] Works across game updates (index-based, not address-based)
- [ ] Memory safe - no crashes on invalid component requests

### Quality Gates

- [ ] All existing entity tests pass
- [ ] New component tests added
- [ ] Documentation updated (COMPONENTS.md, README.md)
- [ ] Code follows modular architecture pattern

## Implementation Phases

### Phase 1: Foundation (Days 1-2)
- [ ] Create `component_registry.h/c` module skeleton
- [ ] Research GetRawComponent signature in Ghidra
- [ ] Create Frida discovery script
- [ ] Document findings in COMPONENTS.md

### Phase 2: Core Implementation (Days 3-5)
- [ ] Implement runtime index discovery
- [ ] Add GetRawComponent wrapper with ARM64 ABI handling
- [ ] Build component name → index cache
- [ ] Add `Ext.Entity.DumpComponentRegistry()` Lua function

### Phase 3: Polish & Testing (Days 6-7)
- [ ] Add `entity:GetComponent()` Lua binding
- [ ] Test with real game components (Health, Transform, Stats)
- [ ] Update documentation
- [ ] Clean up Ghidra scripts

## Dependencies & Prerequisites

- [x] EntityWorld capture (completed in Issue #1)
- [x] TryGetSingleton ARM64 ABI fix (completed)
- [x] GUID → EntityHandle lookup (1873 entities working)
- [ ] Frida installed for dynamic analysis
- [ ] Ghidra with BG3 binary analyzed

## Risk Analysis & Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| GetRawComponent signature differs on macOS | High | Use Frida to observe actual function calls |
| Component indices change per game version | Medium | Runtime discovery, not hardcoded |
| ARM64 calling convention issues | Medium | Already solved for TryGetSingleton (x8 ABI) |
| Performance impact of index lookup | Low | Cache indices at initialization |

## References & Research

### Internal References
- `ghidra/offsets/COMPONENTS.md` - Current component status
- `src/entity/entity_system.c:234-289` - Existing entity Lua bindings
- `src/entity/arm64_call.c` - ARM64 x8 ABI wrapper pattern

### External References
- bg3se EntitySystem.cpp: `/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/GameDefinitions/EntitySystem.cpp`
- bg3se DataLibrariesBG3Game.cpp: Component discovery patterns
- bg3se EntitySystemHelpers.h: Index mapping logic

### Related Work
- Issue #1: TryGetSingleton ARM64 ABI fix (COMPLETED)
- GUID → EntityHandle lookup (WORKING)

## Files to Create/Modify

### New Files
```
src/entity/component_registry.h     # ComponentTypeIndex, registry API
src/entity/component_registry.c     # Runtime discovery, caching
tools/frida/discover_components.js  # Dynamic component discovery
tools/frida/README.md               # Frida usage guide
ghidra/scripts/find_component_registry.py  # Ghidra analysis script
```

### Modified Files
```
src/entity/entity_system.c          # Add GetComponent Lua binding
src/entity/entity_system.h          # Expose component registry API
CMakeLists.txt                      # Add new source files
ghidra/offsets/COMPONENTS.md        # Update with findings
README.md                           # Document component API
```

## Success Metrics

1. **Component Coverage**: ≥10 component types accessible via Lua
2. **API Compatibility**: Match Windows bg3se `entity:GetComponent()` interface
3. **Performance**: Component lookup < 1ms
4. **Stability**: No crashes during component access
5. **Maintainability**: Works after game updates (no hardcoded addresses)
