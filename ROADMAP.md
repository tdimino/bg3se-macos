# BG3SE-macOS Roadmap

This document tracks the development roadmap for achieving feature parity with Windows BG3SE (Norbyte's Script Extender).

## Current Status: v0.10.4

**Working Features:**
- DYLD injection and Dobby hooking infrastructure
- Osiris event observation (2000+ events captured per session)
- Lua runtime with mod loading (BootstrapServer.lua, BootstrapClient.lua)
- Basic Ext.* API (Print, Require, RegisterListener, Json, IO)
- Osiris listener callbacks (before/after event dispatch)
- Dynamic Osi.* metatable with lazy function lookup
- Query output parameters (queries return values, not just bool)
- **Function type detection** - Proper dispatch for Query/Call/Event/Proc/Database types
- **Pre-populated common functions** - 40+ functions seeded at startup
- PAK file extraction and Lua script loading
- Player GUID tracking from observed events
- **Entity Component System** - EntityWorld capture, GUID lookup, component access
- **Ext.Entity API** - Get(guid), IsReady(), entity.Transform, GetComponent()
- **Data Structure Traversal** - TryGet + HashMap traversal for component access (macOS-specific)
- **TypeId Discovery** - Reading TypeId<T>::m_TypeIndex globals for component index discovery

---

## Phase 1: Core Osiris Integration (Current)

### 1.1 Dynamic Osi.* Metatable
**Status:** ✅ Complete (v0.10.0)

Lazy function lookup matching Windows BG3SE's OsirisBinding pattern:
- [x] `__index` metamethod intercepts unknown property accesses
- [x] Creates closures that dispatch via InternalQuery/InternalCall
- [x] Automatic Lua-to-Osiris argument type conversion
- [x] Result caching in Osi table for subsequent accesses
- [x] **Query output parameters** - Return values from queries (v0.10.0)
- [x] **Function type detection** - Distinguish Query vs Call vs Event (v0.10.1)

### 1.2 Function Discovery & Type Detection
**Status:** ✅ Complete (v0.10.1)

- [x] Event observation captures function IDs at runtime
- [x] Function name extraction from event arguments
- [x] Hash table cache for fast ID→name lookup
- [x] **Proper type-based dispatch** - Query/SysQuery/UserQuery use InternalQuery; Call/SysCall use InternalCall; Event/Proc trigger events
- [x] **Pre-populated common functions** - 40+ common functions (queries, calls, events, databases) seeded at startup
- [x] **Type string helper** - `osi_func_type_str()` for debug logging
- [ ] **Safe enumeration via Ghidra offsets** - Use discovered offsets (0x9f348) without crashes

---

## Phase 2: Entity/Component System

### 2.1 Ext.Entity API
**Status:** ✅ Complete (v0.10.0)

The entity system is fundamental to BG3 modding. Entities are game objects (characters, items, projectiles) with attached components.

**Implemented API:**
```lua
-- Get entity by GUID
local entity = Ext.Entity.Get(guid)

-- Check if entity system is ready
if Ext.Entity.IsReady() then
    -- Access components
    local transform = entity.Transform  -- Position, Rotation, Scale
    local component = entity:GetComponent("Transform")

    -- Entity properties
    local handle = entity:GetHandle()
    local alive = entity:IsAlive()
end
```

**Implementation details:**
- [x] Hook `LEGACY_IsInCombat` to capture EntityWorld pointer
- [x] Reverse-engineered HashMap<Guid, EntityHandle> structure
- [x] TryGetSingleton for UuidToHandleMappingComponent
- [x] Lua userdata proxies for entities with `__index` metamethod
- [x] Component accessors via GetComponent template addresses

### 2.2 Component Access
**Status:** 🔄 In Progress (data structure traversal implemented)

**Key Discovery (Dec 2025):** macOS ARM64 has NO `GetRawComponent` dispatcher like Windows. Template functions are **completely inlined** - calling template addresses directly returns NULL.

**Solution: Data Structure Traversal (v0.10.3)**

Since template calls don't work on macOS, we traverse the ECS data structures manually:

```
GetComponent(EntityHandle, ComponentTypeIndex)
    ↓
EntityWorld->Storage (offset 0x2d0)
    ↓
EntityStorageContainer::TryGet(EntityHandle) → EntityStorageData*
    ↓
EntityStorageData->InstanceToPageMap (0x1c0) → EntityStorageIndex
    ↓
EntityStorageData->ComponentTypeToIndex (0x180) → uint8_t slot
    ↓
Components[PageIndex]->Components[slot].ComponentBuffer
    ↓
buffer + (componentSize * EntryIndex) → Component*
```

**Implementation:**
- [x] GUID→EntityHandle lookup (byte order fix: hi/lo swapped)
- [x] EntityStorageContainer::TryGet wrapper (`call_try_get` at 0x10636b27c)
- [x] InstanceToPageMap HashMap traversal
- [x] ComponentTypeToIndex HashMap traversal
- [x] Component buffer access with page/entry indexing
- [x] New module: `component_lookup.c/h` with traversal logic
- [x] `Ext.Entity.DumpStorage(handle)` debug function
- [x] **TypeId global discovery** - Read `TypeId<T>::m_TypeIndex` globals from binary
- [ ] **More TypeId addresses** - Need to find more component TypeId addresses via Ghidra

**Why Template Calls Failed:**

On Windows, `GetRawComponent` is a single dispatcher function. On macOS/ARM64, each `GetComponent<T>` template is **completely inlined** at call sites - there are no callable functions, just inlined code.

**TypeId Discovery (v0.10.4):**

Component type indices are stored in global variables with mangled names like:
```
__ZN2ls6TypeIdIN3ecl9CharacterEN3ecs22ComponentTypeIdContextEE11m_TypeIndexE
```

These globals are at known addresses that can be read at runtime:
- `ecl::Character` @ `0x1083c7818`
- `ecl::Item` @ `0x1083c6910`

New Lua API:
```lua
-- Discover indices from TypeId globals
Ext.Entity.DiscoverTypeIds()

-- Dump all known TypeId addresses
Ext.Entity.DumpTypeIds()
```

**Next Steps:**
- Find more TypeId addresses via Ghidra for ls::, eoc:: components
- Validate TryGet returns valid EntityStorageData
- Test end-to-end GetComponent with discovered indices

---

## Phase 3: Stats System

### 3.1 Ext.Stats API
**Status:** Not Started

Access and modify game statistics, character builds, and item properties.

**Target API:**
```lua
-- Get stat object
local stat = Ext.Stats.Get("Weapon_Longsword")

-- Modify stats
stat.Damage = "1d10"
stat.DamageType = "Slashing"

-- Create new stat
local newStat = Ext.Stats.Create("MyCustomWeapon", "Weapon")
newStat.Damage = "2d6"
```

**Implementation approach:**
- Locate stat manager in game memory via pattern scanning
- Parse stat file formats (.lsx, .lsf)
- Create modification layer that intercepts stat lookups
- Support runtime stat modification

### 3.2 Character Stats
**Status:** Not Started

- Ability scores (STR, DEX, CON, INT, WIS, CHA)
- Skills and proficiencies
- Armor class, saving throws
- Movement speed, initiative

---

## Phase 4: Custom Osiris Functions

### 4.1 Function Registration
**Status:** Not Started

Allow mods to register custom Osiris functions callable from story scripts.

**Target API:**
```lua
-- Register a custom query
Ext.Osiris.RegisterQuery("MyMod_IsPlayerNearby", 2, function(x, y)
    -- Custom logic
    return distance < 10
end)

-- Register a custom call
Ext.Osiris.RegisterCall("MyMod_SpawnEffect", 3, function(effect, x, y)
    -- Spawn visual effect
end)
```

**Implementation approach:**
- Hook Osiris function registration
- Create bridge functions that invoke Lua callbacks
- Handle type marshalling between Osiris and Lua
- Support IN/OUT parameter semantics

### 4.2 Story Script Integration
**Status:** Not Started

- Custom events triggerable from Lua
- Database manipulation (insert/delete/query)
- Goal completion tracking

---

## Phase 5: In-Game Console

### 5.1 Debug Console
**Status:** Not Started

Real-time Lua REPL accessible during gameplay.

**Features:**
- Toggle with hotkey (e.g., ~)
- Command history
- Autocomplete for Ext.* APIs
- Output scrollback
- Variable inspection

**Implementation approach:**
- Hook keyboard input
- Overlay rendering (or redirect to external terminal)
- Sandboxed Lua environment
- Pretty-printing for tables/entities

### 5.2 Debug Tools
**Status:** Not Started

- Entity inspector (click to examine)
- Position display
- Event logger toggle
- Performance profiler

---

## Phase 6: Networking & Co-op Sync

### 6.1 Ext.Net API
**Status:** Not Started

Synchronize mod state between host and clients in multiplayer.

**Target API:**
```lua
-- Host broadcasts to all clients
Ext.Net.BroadcastMessage("MyMod_StateUpdate", Ext.Json.Stringify(state))

-- Register message handler
Ext.Net.RegisterListener("MyMod_StateUpdate", function(channel, payload, userId)
    local state = Ext.Json.Parse(payload)
    -- Apply state
end)
```

**Implementation approach:**
- Hook game's network layer
- Piggyback on existing sync mechanisms
- Message queue with reliable delivery
- User ID tracking for sender identification

### 6.2 State Synchronization
**Status:** Not Started

- Automatic entity state sync
- Conflict resolution
- Bandwidth optimization
- Latency handling

---

## Phase 7: Type System

### 7.1 Full Type Definitions
**Status:** Not Started

Complete Lua type annotations for IDE support and runtime validation.

**Features:**
- LuaLS annotations for all Ext.* APIs
- Entity component type definitions
- Osiris function signatures
- Enum definitions (DamageType, StatusType, etc.)

**Deliverables:**
- `types/` folder with .lua definition files
- Integration with VS Code Lua extension
- Runtime type checking (optional)

### 7.2 IDE Integration
**Status:** Not Started

- Autocomplete for all APIs
- Inline documentation
- Error detection
- Go-to-definition support

---

## Technical Debt & Infrastructure

### Pattern Scanning Improvements
- [ ] Signature database for different game versions
- [ ] Automatic offset recalculation on game updates
- [ ] Fallback mechanisms when patterns fail

### Stability
- [ ] Crash recovery and logging
- [ ] Memory leak detection
- [ ] Thread safety audit
- [ ] Extensive error handling

### Testing
- [ ] Unit tests for Lua bindings
- [ ] Integration tests with mock game state
- [ ] Regression test suite
- [ ] Performance benchmarks

### Documentation
- [ ] API reference (generated from type definitions)
- [ ] Migration guide from Windows BG3SE
- [ ] Mod developer tutorials
- [ ] Architecture documentation

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| v0.10.4 | 2025-12-02 | TypeId<T>::m_TypeIndex discovery, ComponentTypeToIndex enumeration, Lua bindings for runtime discovery |
| v0.10.3 | 2025-12-01 | Data structure traversal for GetComponent (TryGet + HashMap), template calls don't work on macOS |
| v0.10.2 | 2025-12-01 | GUID byte order fix, template-based GetComponent attempt, entity lookup working |
| v0.10.1 | 2025-11-29 | Function type detection - proper Query/Call/Event dispatch, 40+ pre-populated functions |
| v0.10.0 | 2025-11-29 | Entity System complete - EntityWorld capture, GUID lookup, Ext.Entity API |
| v0.9.9 | 2025-11-28 | Dynamic Osi.* metatable, lazy function lookup |
| v0.9.5 | 2025-11-28 | Stable event observation, MRC mod support |
| v0.9.0 | 2025-11-27 | Initial Lua runtime, basic Ext.* API |

---

## Contributing

See [README.md](README.md) for build instructions. Key files:
- `src/injector/main.c` - Core injection and hooking logic
- `ghidra/OFFSETS.md` - Reverse-engineered memory offsets
- `ghidra/*.py` - Ghidra analysis scripts

## References

- [Windows BG3SE](https://github.com/Norbyte/bg3se) - Reference implementation
- [BG3 Modding Wiki](https://bg3.wiki/wiki/Modding) - Game mechanics documentation
- [Lua 5.4 Reference](https://www.lua.org/manual/5.4/) - Lua language reference
