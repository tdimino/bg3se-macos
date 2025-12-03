# Component Discovery System

## Status Summary (Dec 2025)

**Current Approach:** Direct template function calls for known components.

### Key Insight: No GetRawComponent Dispatcher on macOS

Unlike Windows BG3SE which uses a single `GetRawComponent` dispatcher, macOS ARM64 **template-inlines** all component access. Each `GetComponent<T>` is a separate function with hardcoded type indices.

**Solution:** Call the template instantiations directly using discovered Ghidra addresses.

### Implementation Files

| File | Purpose |
|------|---------|
| `src/entity/component_templates.h` | Known template addresses table |
| `src/entity/component_registry.c` | `component_get_by_name()` calls templates |
| `src/entity/arm64_call.c` | `call_get_component_template()` ARM64 wrapper |

## Known GetComponent<T> Template Addresses

From `src/entity/component_templates.h`:

| Component | Ghidra Address | Runtime Calculation |
|-----------|----------------|---------------------|
| `ecl::Item` | `0x100cb1644` | addr - 0x100000000 + binary_base |
| `ecl::Character` | `0x100cc20a8` | addr - 0x100000000 + binary_base |
| `eoc::combat::ParticipantComponent` | `0x100cc1d7c` | |
| `ls::anubis::TreeComponent` | `0x100c8ec50` | |
| `navcloud::PathRequestComponent` | `0x100da66c8` | |
| `eoc::controller::LocomotionComponent` | `0x100e1c66c` | |

### ARM64 Calling Convention for GetComponent<T>

```c
// x0 = EntityWorld*, x1 = EntityHandle, return in x0
void* call_get_component_template(void *fn_addr, void *entityWorld, uint64_t entityHandle) {
    void *result;
    __asm__ volatile (
        "mov x0, %[world]\n"
        "mov x1, %[handle]\n"
        "blr %[fn]\n"
        "mov %[result], x0\n"
        : [result] "=r"(result)
        : [world] "r"(entityWorld), [handle] "r"(entityHandle), [fn] "r"(fn_addr)
        : "x0", "x1", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x30", "memory"
    );
    return result;
}
```

## Implementation Status

| Feature | Status |
|---------|--------|
| GUID→EntityHandle lookup | ✅ Working (byte order fixed) |
| Template-based GetComponent | ✅ Implemented |
| Component Registry module | ✅ Implemented |
| Pre-registered component names | ✅ 45+ common components |
| Lua API: entity:GetComponent(name) | ✅ Uses templates first |
| Lua API: DumpComponentRegistry | ✅ Implemented |
| Runtime template validation | 🔄 In progress |

## New Lua API

```lua
-- Dump all registered components
local registry = Ext.Entity.DumpComponentRegistry()
for name, info in pairs(registry) do
    if info.discovered then
        print(name, "index=" .. info.typeIndex, "size=" .. info.size)
    end
end

-- Initialize component registry
Ext.Entity.InitComponentRegistry()

-- Register a component discovered via Frida
Ext.Entity.RegisterComponent("eoc::HealthComponent", 42, 64)

-- Set GetRawComponent address from Frida discovery
Ext.Entity.SetGetRawComponentAddr(0x1012345678)

-- Look up component info
local info = Ext.Entity.LookupComponent("eoc::HealthComponent")

-- Get component from entity (supports full names)
local health = entity:GetComponent("eoc::HealthComponent")
```

## Discovery Workflow

### Step 1: Run Frida Discovery Script

```bash
frida -n "Baldur's Gate 3" -l tools/frida/discover_components.js
```

In the Frida REPL:
```javascript
// The script will scan for component strings
// Look for GetRawComponent address in the output
// Or manually set it if found via Ghidra
setGetRawComponent("0x1012345678")

// Play the game, observe component accesses
// Then export discoveries
saveDiscoveries()
```

### Step 2: Import Discoveries into BG3SE

From Lua console:
```lua
-- Set GetRawComponent address
Ext.Entity.SetGetRawComponentAddr(0x1012345678)

-- Register discovered components
Ext.Entity.RegisterComponent("eoc::HealthComponent", 42, 64)
Ext.Entity.RegisterComponent("eoc::StatsComponent", 43, 128)
-- etc.
```

### Step 3: Access Components

```lua
local entity = Ext.Entity.Get("c7c13742-bacd-460a-8f65-f864fe41f255")
if entity then
    local health = entity:GetComponent("eoc::HealthComponent")
end
```

## Known Component String Addresses (Nov 30, 2025)

These string addresses were verified via Ghidra analysis:

| Component | String Address | Notes |
|-----------|----------------|-------|
| `ls::TransformComponent` | `0x107b6196c` | ✅ Verified |
| `ls::LevelComponent` | `0x107b4e3bf` | ✅ Verified |
| `eoc::StatsComponent` | `0x107b7c9fc` | ✅ Verified |
| `eoc::BaseHpComponent` | `0x107b84c3d` | ✅ Verified |
| `eoc::HealthComponent` | `0x107bce7b4` | ✅ Verified |
| `eoc::ArmorComponent` | `0x107b7c9c1` | ✅ Verified |
| `ALL_COMPONENTS_META` | `0x107ba7dd3` | Contains all component names |

**Note:** These are string addresses, NOT function addresses. They have no XREFs because they're RTTI metadata.

## Pre-Registered Component Names

The component registry pre-registers these common component names for discovery:

### ls:: namespace (Larian Studios base)
- `ls::TransformComponent`
- `ls::LevelComponent`
- `ls::PhysicsComponent`
- `ls::VisualComponent`
- `ls::AnimationBlueprintComponent`
- `ls::BoundComponent`

### eoc:: namespace (Engine of Combat - BG3 specific)
- `eoc::StatsComponent`
- `eoc::BaseHpComponent`
- `eoc::HealthComponent`
- `eoc::ArmorComponent`
- `eoc::ClassesComponent`
- `eoc::RaceComponent`
- `eoc::PlayerComponent`
- `eoc::CharacterComponent`
- `eoc::ItemComponent`
- `eoc::InventoryComponent`
- `eoc::EquipmentComponent`
- `eoc::SpellBookComponent`
- `eoc::StatusContainerComponent`
- And ~30 more...

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Component Registry                       │
├─────────────────────────────────────────────────────────────┤
│  Pre-registered Names                                        │
│    └─ 45+ common components pre-registered at startup       │
│    └─ Indices set to UNDEFINED until discovered             │
├─────────────────────────────────────────────────────────────┤
│  Runtime Discovery (via Frida)                               │
│    └─ Hook GetRawComponent to observe type indices          │
│    └─ Register discovered name→index mappings               │
├─────────────────────────────────────────────────────────────┤
│  Component Access                                            │
│    └─ Lookup name → ComponentInfo (index, size, proxy)      │
│    └─ Call GetRawComponent(world, handle, index, size)      │
│    └─ Return component pointer                               │
└─────────────────────────────────────────────────────────────┘
```

## Frida Analysis Results (Dec 1, 2025)

### Key Finding: No GetRawComponent Dispatcher on macOS

Frida tracing of `EntityStorageContainer::TryGet` revealed that **there is no single `GetRawComponent` dispatcher function on macOS**. The Windows BG3SE uses a dispatcher pattern, but the macOS binary uses template-inlined component access.

The call pattern observed:
```
Game Logic (CharacterManager, CombatSystem, etc.)
    └─ ecs::WorldView<...> template instantiation
        └─ EntityStorageContainer::TryGet
```

Each `ecs::WorldView` template specialization inlines the component access directly, rather than going through a dispatcher.

### Discovered Core Functions

| Function | Ghidra Address | Purpose |
|----------|----------------|---------|
| `EntityStorageContainer::TryGet` | `0x10636b27c` | Component lookup (non-const) |
| `EntityStorageContainer::TryGet (const)` | `0x10636b310` | Component lookup (const) |
| `EntityStoragePurgeAll` | `0x10636d368` | Storage cleanup |
| `EntityStorageData::~EntityStorageData` | `0x10636c868` | Storage destructor |

### TryGet Signature

```c
// TryGet returns EntityStorageData* for the given handle
EntityStorageData* EntityStorageContainer::TryGet(EntityHandle handle);
```

ARM64 calling convention:
- x0 = this (EntityStorageContainer*)
- x1 = EntityHandle (64-bit packed)
- Return: x0 = EntityStorageData* or null

### Implementation Approach

Since there's no GetRawComponent dispatcher, we implement our own:

1. **Get EntityStorageContainer for component type** from EntityWorld
2. **Call TryGet** with the EntityHandle to get EntityStorageData
3. **Access component data** from EntityStorageData

This matches how the templated WorldView code works, but done at runtime.

## Related Files

| File | Purpose |
|------|---------|
| `src/entity/component_registry.h` | Public API, ComponentInfo struct |
| `src/entity/component_registry.c` | Implementation, pre-registration |
| `src/entity/arm64_call.c` | GetRawComponent ARM64 wrapper |
| `tools/frida/discover_components.js` | Frida discovery script |
| `tools/frida/trace_getrawcomponent.js` | TryGet caller tracer |
| `tools/frida/README.md` | Frida usage guide |

## Technical Details

### ComponentTypeIndex

```c
typedef uint16_t ComponentTypeIndex;

// Special values
#define COMPONENT_INDEX_UNDEFINED ((ComponentTypeIndex)0xFFFF)
#define COMPONENT_INDEX_ONE_FRAME_BIT 0x8000

// Check if component is one-frame
bool component_is_one_frame(ComponentTypeIndex idx) {
    return (idx & COMPONENT_INDEX_ONE_FRAME_BIT) != 0;
}
```

### GetRawComponent Signature

```c
void* GetRawComponent(EntityWorld* world, EntityHandle handle,
                      ComponentTypeIndex type, size_t componentSize,
                      bool isProxy)
```

ARM64 calling convention:
- x0 = entityWorld
- x1 = entityHandle (64-bit)
- w2 = typeIndex (16-bit, zero-extended)
- x3 = componentSize (64-bit)
- w4 = isProxy (bool)
- Return: x0 = component pointer

## Ghidra Decompilation Analysis (Dec 2025)

### EntityWorld Structure (Discovered via GetComponent<T> Decompilation)

```c
struct ecs::EntityWorld {
    // ... other members ...
    EntityStorageContainer* Storage;     // offset 0x2d0
    // ... other members ...
    ImmediateWorldCache* Cache;          // offset 0x3f0
    // ...
};
```

### GetComponent<T> Template Instantiations

Found many template instantiations in the binary:

| Function | Address | Size | Notes |
|----------|---------|------|-------|
| `GetComponent<ecl::Item>` | `0x100cb1644` | 468 bytes | |
| `GetComponent<ecl::Character>` | `0x100cc20a8` | 468 bytes | |
| `GetComponent<ls::anubis::TreeComponent>` | `0x100c8ec50` | 396 bytes | |
| `GetComponent<eoc::combat::ParticipantComponent>` | `0x100cc1d7c` | 476 bytes | |
| `GetComponent<navcloud::PathRequestComponent>` | `0x100da66c8` | 588 bytes | |
| `GetComponent<eoc::controller::LocomotionComponent>` | `0x100e1c66c` | 588 bytes | |

### TypeId<T>::m_TypeIndex Globals (v0.10.5)

Component type indices are stored in global static variables with mangled names.

**Game Version:** 4.1.1.6995620 (macOS ARM64)

**Mangled Name Pattern:**
```
__ZN2ls6TypeIdIN{namespace_len}{namespace}{class_len}{class}EN3ecs22ComponentTypeIdContextEE11m_TypeIndexE
```

**Known TypeId Addresses (Verified Dec 2025):**

| Component | Address | Verified |
|-----------|---------|----------|
| `ecl::Character` | `0x1088ab8e0` | ✅ |
| `ecl::Item` | `0x1088ab8f0` | ✅ |
| `eoc::HealthComponent` | `0x10890a360` | ✅ |
| `eoc::StatsComponent` | `0x10890b058` | ✅ |
| `eoc::ArmorComponent` | `0x108912e40` | ✅ |
| `eoc::BaseHpComponent` | `0x108907888` | ✅ |
| `eoc::DataComponent` | `0x10890b088` | ✅ |
| `ls::TransformComponent` | `0x108940550` | ✅ |
| `ls::LevelComponent` | `0x10893e780` | ✅ |
| `ls::VisualComponent` | `0x108940110` | ✅ |
| `ls::PhysicsComponent` | `0x10893c8e8` | ✅ |

**Discovery Method:**
```bash
nm -gU "Baldur's Gate 3" | c++filt | grep "TypeId.*ecs::ComponentTypeIdContext.*m_TypeIndex"
```

**How to Find More TypeId Addresses:**

1. Run: `nm -gU "Baldur's Gate 3" | c++filt | grep TypeId | grep ComponentTypeIdContext`
2. Look for the actual variable (not guard variable): `ls::TypeId<...>::m_TypeIndex`
3. The value at runtime = address - 0x100000000 + binary_base
4. Add new entries to `src/entity/component_typeid.c` in `g_KnownTypeIds[]`

**Runtime Discovery API:**
```lua
-- Discover indices from known TypeId addresses
local count = Ext.Entity.DiscoverTypeIds()

-- Dump all TypeId addresses and values
Ext.Entity.DumpTypeIds()
```

These globals hold the actual type indices assigned at game startup.

### Next Implementation Steps

1. **Read TypeId globals** - Scan the `__DATA` segment for `ls::TypeId<...>::m_TypeIndex` globals
2. **Map names to indices** - Build runtime mapping of component names → indices
3. **Implement GetRawComponent** - Use TryGet + EntityStorageData offset pattern

## References

- bg3se EntitySystem.cpp: GetRawComponent implementation
- bg3se EntitySystemHelpers.h: ComponentTypeIndex mapping
- bg3se DataLibrariesBG3Game.cpp: Component registration patterns
- `/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/GameDefinitions/EntitySystem.h` - Windows structure definitions
