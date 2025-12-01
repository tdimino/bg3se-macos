# Component Discovery System

## Status Summary

**Current Approach:** Index-based component access matching Windows BG3SE architecture.

The original approach of using direct `GetComponent<T>` function addresses was abandoned because:
1. Component strings are RTTI metadata with **NO XREFs** in static analysis
2. BG3 uses runtime type indices (`uint16_t`) not direct function pointers
3. The discovered addresses were malformed (11 hex digits instead of 10)

## Implementation Status

| Feature | Status |
|---------|--------|
| Component Registry module | ✅ Implemented |
| Pre-registered component names | ✅ 45+ common components |
| Runtime index discovery | ⚠️ Requires Frida |
| GetRawComponent wrapper | ✅ Implemented (ARM64 ABI) |
| Lua API: DumpComponentRegistry | ✅ Implemented |
| Lua API: RegisterComponent | ✅ Implemented |
| Lua API: SetGetRawComponentAddr | ✅ Implemented |

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

## Related Files

| File | Purpose |
|------|---------|
| `src/entity/component_registry.h` | Public API, ComponentInfo struct |
| `src/entity/component_registry.c` | Implementation, pre-registration |
| `src/entity/arm64_call.c` | GetRawComponent ARM64 wrapper |
| `tools/frida/discover_components.js` | Frida discovery script |
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

## References

- bg3se EntitySystem.cpp: GetRawComponent implementation
- bg3se EntitySystemHelpers.h: ComponentTypeIndex mapping
- bg3se DataLibrariesBG3Game.cpp: Component registration patterns
