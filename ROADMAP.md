# BG3SE-macOS Roadmap

This document tracks the development roadmap for achieving feature parity with Windows BG3SE (Norbyte's Script Extender).

## Current Status: v0.31.0

**Overall Feature Parity: ~53%** (based on comprehensive API function count analysis)

**Working Features:**
- DYLD injection and Dobby hooking infrastructure
- Osiris event observation (2000+ events captured per session)
- Lua runtime with mod loading (BootstrapServer.lua)
- Basic Ext.* API (Print, Require, RegisterListener, NewCall/NewQuery/NewEvent/RaiseEvent/GetCustomFunctions, Json, IO)
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
- **TypeId Discovery** - 11 component TypeIds discovered at SessionLoaded with deferred retry
- **Safe Memory APIs** - Crash-safe memory reading via mach_vm_read
- **Function Name Caching** - OsiFunctionDef->Signature->Name two-level indirection (v0.10.6)
- **Ext.Stats API** - RPGStats::m_ptr discovery, stats_manager module, Lua bindings (v0.11.0)

---

## Feature Parity Matrix

| Namespace | Windows BG3SE | bg3se-macos | Parity | Phase |
|-----------|---------------|-------------|--------|-------|
| `Osi.*` | ✅ Full | ✅ Dynamic metatable | **95%** | 1 |
| `Ext.Osiris` | ✅ Full | ✅ RegisterListener + NewCall/NewQuery/NewEvent/RaiseEvent/GetCustomFunctions | **100%** | 1 |
| `Ext.Json` | ✅ Full (2) | ✅ Parse, Stringify | **100%** | 1 |
| `Ext.IO` | ✅ Full (4) | ✅ LoadFile, SaveFile | **50%** | 1 |
| `Ext.Entity` | ✅ Full (26) | ⚠️ Get, GetByHandle, components, enumeration (16) | **62%** | 2 |
| `Ext.Stats` | ✅ Full (52) | ⚠️ Get, GetAll, Create, property read/write (15) | **29%** | 3 |
| `Ext.Events` | ✅ Full (~30) | ⚠️ 10 events + Subscribe/Unsubscribe/Prevent | **33%** | 2.5 |
| `Ext.Timer` | ✅ Full (13) | ⚠️ WaitFor, Cancel, Pause, Resume, IsPaused, MonotonicTime (6) | **46%** | 2.3 |
| `Ext.Debug` | ✅ Full (8) | ✅ Memory introspection (11 macOS-specific) | **100%** | 2.3 |
| `Ext.Vars` | ✅ Full (8) | ✅ User + Mod Variables (12) | **100%** | 2.6 |
| `Ext.Types` | ✅ Full (15) | ⚠️ GetAllTypes, GetObjectType, GetTypeInfo, Validate (4) | **27%** | 7 |
| `Ext.Enums` | ✅ Full | ✅ 14 enum/bitfield types | **100%** | 7 |
| `Ext.Math` | ✅ Full (59) | ✅ 35 functions | **59%** | 7.5 |
| `Ext.Input` | ✅ Full | ✅ CGEventTap capture, hotkeys (8 macOS-specific) | **100%** | 9 |
| `Ext.Net` | ✅ Full | ❌ Not impl | **0%** | 6 |
| `Ext.UI` | ✅ Full (9) | ❌ Not impl | **0%** | 8 |
| `Ext.IMGUI` | ✅ Full (7+) | ❌ Not impl | **0%** | 8 |
| `Ext.Level` | ✅ Full (21) | ❌ Not impl | **0%** | 9 |
| `Ext.Audio` | ✅ Full (17) | ❌ Not impl | **0%** | 10 |
| `Ext.Localization` | ✅ Full (2) | ❌ Not impl | **0%** | 10 |
| `Ext.StaticData` | ✅ Full (5) | ❌ Not impl | **0%** | 10 |
| `Ext.Resource` | ✅ Full (2) | ❌ Not impl | **0%** | 10 |
| `Ext.Template` | ✅ Full (9) | ❌ Not impl | **0%** | 10 |
| Console/REPL | ✅ Full | ✅ Socket + file + in-game overlay | **95%** | 5 |
| PersistentVars | ✅ Full | ✅ File-based | **90%** | 2.4 |
| Client Lua State | ✅ Full | ❌ Not impl | **0%** | 2.7 |
| Debugger | ✅ Full | ❌ Not impl | **0%** | 11 |

---

## Phase 1: Core Osiris Integration (Complete)

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
**Status:** ✅ Complete (v0.10.6)

- [x] Event observation captures function IDs at runtime
- [x] Function name extraction from event arguments
- [x] Hash table cache for fast ID→name lookup
- [x] **Proper type-based dispatch** - Query/SysQuery/UserQuery use InternalQuery; Call/SysCall use InternalCall; Event/Proc trigger events
- [x] **Pre-populated common functions** - 40+ common functions (queries, calls, events, databases) seeded at startup
- [x] **Type string helper** - `osi_func_type_str()` for debug logging
- [x] **Function name caching via Signature indirection** - Fixed OsiFunctionDef structure (offset +0x08 is Line, not Name) (v0.10.6)

### 1.3 Database Operations
**Status:** ⚠️ Partial

- [x] `Osi.DB_*:Get(nil)` - Fetch all rows (verified working)
- [x] `Osi.DB_*(values...)` - Insert rows
- [ ] `Osi.DB_*:Get(filter, nil, nil)` - Filtered queries (needs verification)
- [ ] `Osi.DB_*:Delete(...)` - Row deletion (needs verification)

### 1.4 Custom Osiris Function Registration
**Status:** ✅ Complete (v0.22.0)

Allows Lua mods to register custom Osiris functions callable via the `Osi.*` namespace:

**Implemented API:**
```lua
-- Register a custom query (returns values via OUT params)
Ext.Osiris.NewQuery("MyMod_Add", "[in](INTEGER)_A,[in](INTEGER)_B,[out](INTEGER)_Sum",
    function(a, b)
        return a + b
    end)

-- Call it via Osi namespace
local sum = Osi.MyMod_Add(10, 20)  -- Returns 30

-- Register a custom call (no return value)
Ext.Osiris.NewCall("MyMod_Log", "(STRING)_Message",
    function(msg)
        _P("Custom call: " .. msg)
    end)

-- Call it
Osi.MyMod_Log("Hello from Lua!")

-- Register a custom event
Ext.Osiris.NewEvent("MyMod_OnItemUsed", "(GUIDSTRING)_Item,(GUIDSTRING)_User")

-- Register a listener for the custom event
Ext.Osiris.RegisterListener("MyMod_OnItemUsed", 2, "after", function(item, user)
    _P("Item " .. item .. " used by " .. user)
end)

-- Raise the event from Lua (dispatches to all listeners)
local numCalled = Ext.Osiris.RaiseEvent("MyMod_OnItemUsed", itemGuid, userGuid)

-- Debug: List all registered custom functions
for name, info in pairs(Ext.Osiris.GetCustomFunctions()) do
    _P(name .. " (" .. info.Type .. ") - Arity: " .. info.Arity)
end
```

**Implementation details:**
- [x] Signature parsing for Windows BG3SE format: `"[in](TYPE)_Name,[out](TYPE)_Name"`
- [x] Type support: INTEGER, INTEGER64, REAL, STRING, GUIDSTRING
- [x] Custom function IDs start at 0xF0000000 (no collision with game IDs)
- [x] Lua callbacks stored in registry for persistence
- [x] Integration with `Osi.*` metatable dispatch
- [x] Session lifecycle management (cleanup on Lua shutdown)
- [x] **RaiseEvent** - Dispatch custom events to registered listeners (v0.23.0)
- [x] **GetCustomFunctions** - Debug introspection of registered functions (v0.23.0)

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

### 2.2 Component Access & Property System
**Status:** ✅ Complete (v0.24.0+) - 32 component property layouts working

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

**Completed:**
- [x] GUID→EntityHandle lookup (byte order fix: hi/lo swapped)
- [x] EntityStorageContainer::TryGet wrapper (`call_try_get` at 0x10636b27c)
- [x] InstanceToPageMap HashMap traversal
- [x] ComponentTypeToIndex HashMap traversal
- [x] Component buffer access with page/entry indexing
- [x] New module: `component_lookup.c/h` with traversal logic
- [x] `Ext.Entity.DumpStorage(handle)` debug function
- [x] **TypeId global discovery** - Read `TypeId<T>::m_TypeIndex` globals from binary
- [x] **Deferred TypeId retry** - Retry at SessionLoaded when globals are initialized (v0.10.5)
- [x] **Safe memory APIs** - mach_vm_read for crash-safe memory access (v0.10.5)

**Completed (v0.21.0):**
- [x] `entity:GetAllComponents()` - Return all attached components (as light userdata)
- [x] `entity:GetAllComponentNames()` - List all component type names
- [x] `Ext.Entity.GetAllEntitiesWithComponent(name)` - Get all entities with a component
- [x] `Ext.Entity.CountEntitiesWithComponent(name)` - Count entities with a component

**Completed (v0.24.0+) - Component Property Layouts:**

32 components with data-driven property access via proxy userdata:

| Component | Properties |
|-----------|------------|
| Health | Hp, MaxHp, TemporaryHp, MaxTemporaryHp, IsInvulnerable |
| BaseHp | Vitality, VitalityBoost |
| Armor | ArmorType, ArmorClass, AbilityModifierCap, ArmorClassAbility, EquipmentType |
| Stats | InitiativeBonus, Abilities[7], AbilityModifiers[7], Skills[18], ProficiencyBonus, etc. |
| BaseStats | BaseAbilities[7] |
| Transform | Rotation (vec4), Position (vec3), Scale (vec3) |
| Level | LevelHandle, LevelName |
| Data | Weight, StatsId, StepsType |
| Experience | CurrentLevelExperience, NextLevelExperience, TotalExperience |
| AvailableLevel | Level |
| EocLevel | Level (character level, distinct from ls::LevelComponent) |
| Passive | Type, PassiveId, Source, Item, ToggledOn, Disabled |
| Resistances | AC |
| PassiveContainer | PassiveCount |
| Tag | TagCount |
| Race | Race (GUID) |
| Origin | field_18, Origin |
| Classes | ClassCount |
| Movement | Direction, Acceleration, Speed, Speed2 |
| Background | Background (GUID) |
| God | God, HasGodOverride, GodOverride |
| Value | Value, Rarity, Unique |
| TurnBased | IsActiveCombatTurn, Removed, RequestedEndTurn, TurnActionsCompleted, ActedThisRoundInCombat, HadTurnInCombat, CanActInCombat, CombatTeam |
| SpellBook | Entity, SpellCount |
| StatusContainer | StatusCount |
| ActionResources | ResourceTypeCount |
| Weapon | WeaponRange, DamageRange, WeaponProperties, WeaponGroup, Ability |
| InventoryContainer | ItemCount |
| InventoryOwner | InventoryCount, PrimaryInventory (EntityHandle) |
| InventoryMember | Inventory (EntityHandle), EquipmentSlot |
| InventoryIsOwned | Owner (EntityHandle) |
| Equipable | EquipmentTypeID (GUID), Slot |

Features:
- [x] `entity.Health.Hp` - Direct property access via `__index`
- [x] `for k,v in pairs(component)` - Iteration support
- [x] `component.__type` - Full component name
- [x] `component.__shortname` - Short name
- [x] **Hash function fix** - ComponentTypeIndex HashMap uses BG3-specific hash:
  ```c
  h0 = (typeIndex & 0x7FFF) + (typeIndex >> 15) * 0x880
  hash = h0 | (h0 << 16)
  ```

**Pending (from API.md):**
- [ ] `entity:CreateComponent(name)` - Attach new component
- [ ] `entity:RemoveComponent(name)` - Detach component (v22+)
- [ ] `entity:GetEntityType()` - Numeric type ID
- [ ] `entity:GetSalt()`, `entity:GetIndex()` - Handle parts
- [ ] `entity:GetNetId()` - Network ID (v23+)
- [ ] `entity:Replicate(component)` - Network replication
- [ ] `entity:SetReplicationFlags()`, `entity:GetReplicationFlags()` - Replication control
- [ ] **Component property read** via `__index` (IndexedProperties + pools)
- [ ] **Component property write** via `__newindex`

**Discovered TypeIds (at SessionLoaded):**
| Component | Index |
|-----------|-------|
| ecl::Character | 13 |
| ecl::Item | 67 |
| eoc::HealthComponent | 575 |
| eoc::StatsComponent | 650 |
| eoc::ArmorComponent | 484 |
| eoc::BaseHpComponent | 491 |
| eoc::DataComponent | 542 |
| ls::TransformComponent | 1998 |
| ls::LevelComponent | 1923 |
| ls::VisualComponent | 1999 |
| ls::PhysicsComponent | 1947 |

### 2.3 Timer API
**Status:** ✅ Complete (v0.11.0)

Scheduling API for delayed and periodic callbacks.

**Implemented API:**
```lua
-- One-shot timer (delay in milliseconds)
local handle = Ext.Timer.WaitFor(1000, function(h)
    Ext.Print("1 second later!")
end)

-- Repeating timer (third arg = repeat interval)
local handle = Ext.Timer.WaitFor(1000, function(h)
    Ext.Print("Every 1 second")
end, 1000)

-- Timer control
Ext.Timer.Cancel(handle)   -- Cancel timer
Ext.Timer.Pause(handle)    -- Pause timer
Ext.Timer.Resume(handle)   -- Resume paused timer
Ext.Timer.IsPaused(handle) -- Check if paused

-- Utility
local ms = Ext.Timer.MonotonicTime()  -- High-resolution clock
```

**Implementation:**
- Fixed-size timer pool (256 timers max)
- Min-heap priority queue for efficient scheduling
- Callbacks stored via `luaL_ref` to prevent GC
- Polled from `COsiris::Event` hook
- 1-based handles (0 = error sentinel)
- Input validation: delay >= 0, finite, <= 24 hours

### 2.4 PersistentVars (Savegame Persistence)
**Status:** ✅ Complete (v0.12.0)

File-based persistence for mod variables. Data survives game restarts.

**Implemented API:**
```lua
-- In BootstrapServer.lua
Mods[ModTable].PersistentVars = {}

-- Store data during gameplay
Mods[ModTable].PersistentVars['QuestProgress'] = 5
Mods[ModTable].PersistentVars['Inventory'] = { "sword", "shield" }

-- Restored BEFORE SessionLoaded event fires
Ext.Events.SessionLoaded:Subscribe(function()
    local progress = Mods[ModTable].PersistentVars['QuestProgress']
    _P("Restored: " .. tostring(progress))  -- Prints 5
end)

-- Manual save (auto-saves every 30 seconds if dirty)
Ext.Vars.SyncPersistentVars()

-- Query state
Ext.Vars.IsPersistentVarsLoaded() -- true if loaded
Ext.Vars.ReloadPersistentVars()   -- Force reload from disk
```

**Implementation:**
- Storage: `~/Library/Application Support/BG3SE/persistentvars/{ModTable}.json`
- Timing: Restored BEFORE SessionLoaded, auto-saved every 30s if dirty
- Atomic writes: temp file + rename prevents corruption
- Per-mod isolation via ModTable name
- Console commands: `!pv_dump`, `!pv_set`, `!pv_save`, `!pv_reload`

**Note:** macOS uses file-based persistence instead of savegame hooks (which would require extensive reverse engineering).

### 2.5 Ext.Events API (Engine Events)
**Status:** ✅ Complete (v0.30.0) - 10 events including console interception with Prevent pattern

From API.md: "Subscribing to engine events can be done through the `Ext.Events` table."

**Implemented API (v0.30.0):**
```lua
-- Subscribe with options
local handlerId = Ext.Events.SessionLoaded:Subscribe(function(e)
    _P("Session loaded!")
end, {
    Priority = 50,   -- Lower = called first (default: 100)
    Once = true      -- Auto-unsubscribe after first call
})

-- Unsubscribe by handler ID
Ext.Events.SessionLoaded:Unsubscribe(handlerId)

-- Helper for next tick (fires once)
Ext.OnNextTick(function()
    -- Runs on next game loop iteration
end)

-- Tick event with delta time
Ext.Events.Tick:Subscribe(function(e)
    local dt = e.DeltaTime  -- Seconds since last tick
end)

-- GameStateChanged event (v0.14.0)
Ext.Events.GameStateChanged:Subscribe(function(e)
    _P("State: " .. e.FromState .. " -> " .. e.ToState)
    -- States: 2=Init, 7=LoadSession, 13=Running, etc.
end)

-- DoConsoleCommand event with Prevent pattern (v0.30.0)
Ext.Events.DoConsoleCommand:Subscribe(function(e)
    _P("Command: " .. e.Command)
    if e.Command:match("^!secret") then
        e.Prevent = true  -- Block command execution
    end
end)

-- LuaConsoleInput event (v0.30.0)
Ext.Events.LuaConsoleInput:Subscribe(function(e)
    _P("Lua input: " .. #e.Input .. " chars")
end)
```

**Available Events:**
| Event | When | Event Data | Status |
|-------|------|------------|--------|
| `SessionLoading` | Session setup started | {} | ✅ Implemented |
| `SessionLoaded` | Session ready | {} | ✅ Implemented |
| `ResetCompleted` | After `reset` command | {} | ✅ Implemented |
| `Tick` | Every game loop (~30hz) | {DeltaTime} | ✅ Implemented (v0.13.0) |
| `StatsLoaded` | After stats entries loaded | {} | ✅ Implemented (v0.13.0) |
| `ModuleLoadStarted` | Before mod scripts load | {} | ✅ Implemented (v0.13.0) |
| `GameStateChanged` | State transitions | {FromState, ToState} | ✅ Implemented (v0.14.0) |
| `KeyInput` | Keyboard input | {Key, Pressed, Modifiers, Character} | ✅ Implemented |
| `DoConsoleCommand` | Console ! command | {Command, Prevent} | ✅ Implemented (v0.30.0) |
| `LuaConsoleInput` | Raw Lua console input | {Input, Prevent} | ✅ Implemented (v0.30.0) |

**Advanced Features:**
- Priority-based handler ordering (lower = called first)
- Once flag for auto-unsubscription
- Handler ID return for explicit unsubscription
- Deferred modifications during dispatch (prevents iterator corruption)
- Protected calls to prevent cascade failures
- `!events` console command to inspect handler counts
- **Prevent pattern** - handlers can set `e.Prevent = true` to block default execution
- Combat/status events available via `Ext.Osiris.RegisterListener()` (TurnStarted, StatusApplied, etc.)

### 2.6 User & Mod Variables
**Status:** ✅ Complete (v0.28.0) - User variables + Mod variables working

From API.md: "v10 adds support for attaching custom properties to entities."

**User Variables (entity-attached):**
```lua
-- Registration (in BootstrapServer/Client.lua)
Ext.Vars.RegisterUserVariable("MyMod_CustomHP", {
    Server = true,
    Persistent = true,       -- Save to disk
    SyncOnTick = true        -- Batch sync (default)
})

-- Usage
entity.Vars.MyMod_CustomHP = { bonus = 50, temp = 10 }
local data = entity.Vars.MyMod_CustomHP

-- Manual sync
Ext.Vars.SyncUserVariables()

-- Find entities with variable
local entities = Ext.Vars.GetEntitiesWithVariable("MyMod_CustomHP")
```

**Mod Variables (global per-mod, v0.28.0):**
```lua
-- Registration (optional - auto-registered on first use)
Ext.Vars.RegisterModVariable("mod-uuid", "Settings", {
    Server = true,
    Persistent = true
})

-- Get mod variable proxy
local mv = Ext.Vars.GetModVariables("mod-uuid")

-- Read/write (table-like access)
mv.Counter = 42
mv.Settings = { volume = 0.8, difficulty = "Hard" }
_P(mv.Counter)  -- 42

-- Iteration
for key, value in pairs(mv) do
    _P(key, "=", value)
end

-- Manual sync
Ext.Vars.SyncModVariables()
```

**Storage:**
- User vars: `~/Library/Application Support/BG3SE/uservars.json`
- Mod vars: `~/Library/Application Support/BG3SE/modvars.json`

**Not Yet Implemented:**
- Client/server sync (requires NetChannel API)

### 2.7 Client Lua State
**Status:** ❌ Not Started - **HIGH**

From API.md: "The game is split into client and server components... the extender keeps multiple Lua states."

**Current State:** bg3se-macos only runs server-side Lua (BootstrapServer.lua)

**Missing:**
- BootstrapClient.lua loading
- Separate client Lua state
- Client-only APIs (UI, rendering, level scaling)
- Context annotations (C = Client, S = Server, R = Restricted)

**Impact:** Client-side mods (UI modification, visual effects) completely broken.

### 2.8 Object Scopes/Lifetimes
**Status:** ✅ Complete (v0.29.0 - Issue #28)

From API.md: "Most `userdata` types are now bound to their enclosing *extender scope*."

**Implementation:**
- `src/lifetime/lifetime.h` - Lifetime handle types and pool API
- `src/lifetime/lifetime.c` - LifetimePool (4096 entries) + LifetimeStack (64 nested scopes)
- Modified: `EntityUserdata`, `ComponentProxy`, `LuaStatsObject` - all include `LifetimeHandle` field
- Console commands and Lua callbacks wrapped with `lifetime_lua_begin_scope()`/`lifetime_lua_end_scope()`

**Working Behavior:**
```lua
-- BAD: Smuggling objects outside scope
local entity = Ext.Entity.Get(GetHostCharacter())
stored = entity  -- Store for later

-- Next console command...
_P(stored)  -- Shows: Entity(0x...) [EXPIRED]
stored.Health.Hp  -- ERROR: "Lifetime of Entity has expired; re-fetch the object in the current scope"

-- GOOD: Fetch fresh reference in each scope
local entity = Ext.Entity.Get(GetHostCharacter())
_P(entity.Health.Hp)  -- Works!
```

**Features:**
- 12-bit index + 36-bit salt for staleness detection
- All userdata (Entity, Component, StatsObject) validate lifetime on every access
- `__tostring` shows `[EXPIRED]` for debugging
- Proper error messages guide users to re-fetch objects

---

## Phase 3: Stats System

### 3.1 Ext.Stats API
**Status:** ✅ Complete (v0.18.0) - Property read/write working (`stat.Damage = "2d6"`), 15,774 stats accessible

Access and modify game statistics, character builds, and item properties.

**GlobalStringTable & FixedString Resolution (Dec 5, 2025):**
- ✅ Found `ls::gst::Get()` function at `0x1064bb224` via Ghidra analysis
- ✅ GST pointer global variable at offset `0x8aeccd8` from module base
- ✅ Confirmed GST heap address: `0x1501f8000` (runtime verified)
- ✅ Decoded SubTable structure: `0x1200` bytes each, 11 SubTables
- ✅ StringEntry: `+0x00` Hash, `+0x04` RefCount, `+0x08` Length, `+0x18` String
- ✅ **Implemented `fixed_string_resolve()` - 47,326 strings resolved successfully**
- ✅ **Ext.Stats.GetAll() returns 15,774 stat names** (full names, not indices)
- ✅ **Ext.Stats.Get(name) retrieves stats by name**
- [ ] Enable type filtering for GetAll() (ModifierList name resolution pending)

**Implemented API (v0.11.0):**
```lua
-- Check if stats system is ready
if Ext.Stats.IsReady() then
    -- Get stat object by name
    local stat = Ext.Stats.Get("Weapon_Longsword")

    if stat then
        -- Read built-in properties
        local name = stat.Name        -- "Weapon_Longsword"
        local type = stat.Type        -- "Weapon"
        local level = stat.Level      -- Level value
        local using = stat.Using      -- Parent stat name or nil

        -- Dump stat info to log
        stat:Dump()
    end

    -- Get all stats of a type
    local weapons = Ext.Stats.GetAll("Weapon")
    for i, name in ipairs(weapons) do
        Ext.Print("Weapon: " .. name)
    end

    -- Dump available stat types
    Ext.Stats.DumpTypes()
end
```

**Implementation details:**
- [x] Discovered `RPGStats::m_ptr` global at `0x1089c5730` via symbol analysis
- [x] Documented offsets in `ghidra/offsets/STATS.md`
- [x] Created `stats_manager.c/h` module for C-level access
- [x] Created `lua_stats.c/h` for Lua bindings
- [x] StatsObject userdata with `__index`, `__newindex`, `__tostring`
- [x] **GlobalStringTable access** - offset `0x8aeccd8`, 47,326+ strings resolved
- [x] **Ext.Stats.GetAll()** - returns all 15,774 stat names
- [x] **Ext.Stats.Get(name)** - retrieves stats by name with property access
- [x] **stat.Name** - returns resolved string name

**Completed (v0.11.0):**
- [x] **Type filtering** - `Ext.Stats.GetAll("Weapon")` ✅ Working (uses stats_get_type)
- [x] **stat.Type** - ✅ Working via name-based detection (WPN_→Weapon, ARM_→Armor, etc.)
- [x] **Property read** - `stat.Damage` → "1d8" via IndexedProperties + FixedStrings
- [x] **RPGSTATS_OFFSET_FIXEDSTRINGS = 0x348** - Discovered via Ghidra decompilation

**Completed (v0.18.0):**
- [x] **Property write access** via `__newindex` (`stat.Damage = "2d6"`)

**Pending:**
- [ ] `stat:Sync()` - Propagate changes to clients
- [ ] `Ext.Stats.Create(name, type, template)` - Create new stats
- [ ] **Level scaling** - `Ext.Stats.Get(name, level)` parameter

**Supported Stat Types (from API.md):**
- `StatusData`, `SpellData`, `PassiveData`, `Armor`, `Weapon`, `Character`, `Object`
- `SpellSet`, `EquipmentSet`, `TreasureTable`, `TreasureCategory`, `ItemGroup`, `NameGroup`

### 3.2 Stats Functors (v22+)
**Status:** ❌ Not Started

```lua
Ext.Stats.ExecuteFunctors(type, ...)
Ext.Stats.ExecuteFunctor(functor, ...)
Ext.Stats.PrepareFunctorParams(...)

-- Event
Ext.Events.ExecuteFunctor:Subscribe(function(e) ... end)
```

### 3.3 Character Stats
**Status:** ❌ Not Started

- Ability scores (STR, DEX, CON, INT, WIS, CHA)
- Skills and proficiencies
- Armor class, saving throws
- Movement speed, initiative

---

## Phase 4: Custom Osiris Functions

### 4.1 Function Registration
**Status:** ❌ Not Started

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
**Status:** ❌ Not Started

- Custom events triggerable from Lua
- Database manipulation (insert/delete/query)
- Goal completion tracking

---

## Phase 5: In-Game Console

### 5.1 Debug Console
**Status:** ✅ Complete (v0.19.0) - Socket + file + in-game overlay

Three ways to interact with the Lua runtime:

**Implemented Features:**
- ✅ **In-game overlay (v0.19.0)** - NSWindow floating above fullscreen game
- ✅ **Tanit symbol** with warm amber/gold glow (Aldea palette)
- ✅ **Ctrl+` hotkey** toggle via Input API
- ✅ Command history with up/down arrows
- ✅ Socket console with Unix domain socket (`/tmp/bg3se.sock`)
- ✅ Standalone readline client (`build/bin/bg3se-console`)
- ✅ Real-time bidirectional I/O (Ext.Print output to socket + overlay)
- ✅ Up to 4 concurrent socket clients
- ✅ ANSI color output (errors in red)
- ✅ Single-line Lua execution
- ✅ Multi-line mode (`--[[` ... `]]--`)
- ✅ Console commands (`!command arg1 arg2`)
- ✅ Comments (`#` prefix outside multi-line)
- ✅ File-based polling as fallback

**In-Game Overlay (New in v0.19.0):**
```
Press Ctrl+` to toggle the console overlay:
- Floating NSWindow at NSScreenSaverWindowLevel (above fullscreen)
- Tanit symbol in top-left with pulsing amber glow
- Scrollable output area with Menlo font
- Input field with command history
- Commands execute via console backend
- Output from Ext.Print() appears automatically
```

**Socket Console Usage:**
```bash
# Launch game with BG3SE
./scripts/launch_bg3.sh

# Connect with console client (recommended)
./build/bin/bg3se-console

# Or use socat/nc
socat - UNIX-CONNECT:/tmp/bg3se.sock
nc -U /tmp/bg3se.sock
```

**File-Based Usage (fallback):**
```bash
# Single line
echo 'Ext.Print("hello")' > ~/Library/Application\ Support/BG3SE/commands.txt

# Multi-line
cat > ~/Library/Application\ Support/BG3SE/commands.txt << 'EOF'
--[[
for i = 1, 10 do
    Ext.Print(i)
end
]]--
EOF

# Console command
echo '!probe 0x12345678 256' > ~/Library/Application\ Support/BG3SE/commands.txt
```

**Not implemented:**
- Client/server context switching (requires dual Lua states)

### 5.2 Custom Console Commands
**Status:** ✅ Complete (v0.11.0)

```lua
Ext.RegisterConsoleCommand("test", function(cmd, a1, a2, ...)
    _P("Command: " .. cmd .. ", args: ", a1, ", ", a2)
end)
-- Usage: !test arg1 arg2
```

**Built-in Commands:**
- `!help` - List available commands
- `!probe <addr> [range]` - Probe memory structure
- `!dumpstat <name>` - Dump stat object details
- `!findstr <pattern>` - Search memory for string
- `!hexdump <addr> [size]` - Hex dump memory
- `!types` - List registered types

### 5.3 Debug Tools (Ext.Debug)
**Status:** ✅ Complete (v0.11.0)

**Memory Introspection:**
```lua
-- Safe memory reading (returns nil on bad address)
Ext.Debug.ReadPtr(addr)         -- Read pointer
Ext.Debug.ReadU32(addr)         -- Read uint32
Ext.Debug.ReadU64(addr)         -- Read uint64
Ext.Debug.ReadI32(addr)         -- Read int32
Ext.Debug.ReadFloat(addr)       -- Read float
Ext.Debug.ReadString(addr, max) -- Read C string

-- Bulk offset discovery
Ext.Debug.ProbeStruct(base, start, end, stride)
-- Returns: { [offset] = { ptr=..., u32=..., i32=..., float=... } }

-- Pattern finding
Ext.Debug.FindArrayPattern(base, range)

-- Hex dump
Ext.Debug.HexDump(addr, size)
```

**Not implemented:**
- Entity inspector (click to examine)
- Performance profiler

---

## Phase 6: Networking & Co-op Sync

### 6.1 NetChannel API (New - v22+)
**Status:** ❌ Not Started - **CRITICAL for multiplayer**

From API.md: "NetChannel API provides a structured abstraction for request/response and message broadcasting."

**Target API:**
```lua
-- Create channel
local channel = Net.CreateChannel(ModuleUUID, "MyChannel")

-- Fire-and-forget handler
channel:SetHandler(function(data, user)
    Osi.TemplateAddTo(data.Template, data.Target, data.Amount)
end)

-- Request/reply handler
channel:SetRequestHandler(function(data, user)
    return { Result = CheckSomething(data) }
end)

-- Client → Server
channel:SendToServer(data)
channel:RequestToServer(data, function(response) ... end)

-- Server → Client(s)
channel:SendToClient(data, userOrGuid)
channel:Broadcast(data)
channel:RequestToClient(data, user, function(response) ... end)

-- Utility
Ext.Net.IsHost()
```

**Benefits over legacy NetMessage:**
- Structured request/reply semantics
- Per-channel handler attachment
- Faster local client requests (no 1-frame delay)

### 6.2 Legacy NetMessage API (Deprecated)
**Status:** ❌ Not Started

```lua
-- Server → Client
Ext.ServerNet.BroadcastMessage(channel, payload)
Ext.ServerNet.PostMessageToUser(peerId, channel, payload)

-- Client → Server
Ext.ClientNet.PostMessageToServer(channel, payload)

-- Listening
Ext.RegisterNetListener(channel, function(channel, payload, userID) ... end)
```

### 6.3 State Synchronization
**Status:** ❌ Not Started

- Automatic entity state sync
- Conflict resolution
- Bandwidth optimization
- Latency handling

---

## Phase 7: Type System & Enumerations

### 7.1 Enum Objects
**Status:** ✅ Complete (v0.26.0 - Issue #29)

Enum userdata with Label, Value, EnumName properties and flexible comparison.

**Implementation:**
- `src/enum/enum_registry.c/h` - Central enum registry
- `src/enum/enum_lua.c` - Enum metamethods (__index, __eq, __tostring, __lt, __le)
- `src/enum/enum_ext.c` - Ext.Enums table registration
- `src/enum/enum_definitions.c` - 14 enum/bitfield types (DamageType, AbilityId, SkillId, StatusType, SurfaceType, SpellSchoolId, WeaponType, ArmorType, ItemSlot, ItemDataRarity, SpellType, AttributeFlags, WeaponFlags, DamageFlags)

**Working API:**
```lua
local dt = Ext.Enums.DamageType.Fire
dt.Label      -- "Fire"
dt.Value      -- 7
dt.EnumName   -- "DamageType"

-- Comparison
dt == "Fire"  -- true (label)
dt == 7       -- true (value)
dt == Ext.Enums.DamageType.Fire  -- true
```

### 7.2 Bitfield Objects
**Status:** ✅ Complete (v0.26.0 - Issue #29)

Bitfield userdata with __Labels, __Value, __EnumName, flag queries, and bitwise operations.

**Working API:**
```lua
local bf = Ext.Enums.AttributeFlags.Backstab
bf.__Labels   -- {"Backstab"}
bf.__Value    -- 65536
bf.__EnumName -- "AttributeFlags"

-- Query flags
bf.Backstab   -- true
bf.Torch      -- false

-- Bitwise operators
~bf           -- Negate (masked by allowed_flags)
bf | "Torch"  -- OR returns new bitfield
bf & 0xFF     -- AND returns new bitfield
bf ^ other    -- XOR returns new bitfield
#bf           -- Popcount (number of set flags)
tostring(bf)  -- Comma-separated labels
```

### 7.3 Full Type Definitions
**Status:** ❌ Not Started

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

### 7.4 IDE Integration
**Status:** ❌ Not Started

- Autocomplete for all APIs
- Inline documentation
- Error detection
- Go-to-definition support

### 7.5 Ext.Math Library
**Status:** ❌ Not Started

From API.md (complete API surface):

```lua
-- Vector operations
Ext.Math.Add(a, b)           -- vec3, vec4, mat
Ext.Math.Sub(a, b)
Ext.Math.Mul(a, b)
Ext.Math.Div(a, b)
Ext.Math.Normalize(x)
Ext.Math.Cross(x, y)         -- vec3
Ext.Math.Dot(x, y)
Ext.Math.Distance(p0, p1)
Ext.Math.Length(x)
Ext.Math.Angle(a, b)
Ext.Math.Reflect(I, N)
Ext.Math.Project(x, normal)
Ext.Math.Perpendicular(x, normal)

-- Matrix operations
Ext.Math.Inverse(x)
Ext.Math.Transpose(x)
Ext.Math.Determinant(x)
Ext.Math.OuterProduct(c, r)
Ext.Math.Rotate(m, angle, axis)
Ext.Math.Translate(m, translation)
Ext.Math.Scale(m, scale)

-- Matrix construction
Ext.Math.BuildRotation3(v, angle)
Ext.Math.BuildRotation4(v, angle)
Ext.Math.BuildTranslation(v)
Ext.Math.BuildScale(v)
Ext.Math.BuildFromEulerAngles3(angles)
Ext.Math.BuildFromEulerAngles4(angles)
Ext.Math.BuildFromAxisAngle3(axis, angle)
Ext.Math.BuildFromAxisAngle4(axis, angle)

-- Decomposition
Ext.Math.ExtractEulerAngles(m)
Ext.Math.ExtractAxisAngle(m, axis)
Ext.Math.Decompose(m, scale, yawPitchRoll, translation)

-- Scalar functions
Ext.Math.Clamp(val, min, max)
Ext.Math.Lerp(x, y, a)
Ext.Math.Fract(x)
Ext.Math.Trunc(x)
Ext.Math.Sign(x)
Ext.Math.Acos(x), Asin(x), Atan(x), Atan2(x, y)
```

---

## Phase 8: UI Systems

### 8.1 Noesis UI (Custom ViewModels)
**Status:** ❌ Not Started

From API.md: "SE supports the creation and modification of Noesis viewmodels."

**Target API:**
```lua
-- Register ViewModel type
Ext.UI.RegisterType("PREFIX_MyType", {
    MyString = {Type = "String", WriteCallback = func, Notify = true},
    MyCommand = {Type = "Command"},
    MyCollection = {Type = "Collection"}
}, wrappedTypeName)

-- Instantiate
local vm = Ext.UI.Instantiate("PREFIX_MyType")
vm.MyString = "value"
vm.MyCommand:SetHandler(function() ... end)

-- UI access
Ext.UI.GetRoot()
Ext.UI.GetCursorControl()  -- v22+
Ext.UI.GetDragDrop()       -- v22+
```

**Supported Property Types:**
- `Bool`, `Int8`-`Int64`, `UInt8`-`UInt64`
- `Single`, `Double`, `String`
- `Collection`, `Command`, `Object`
- `Color`, `Vector2`, `Vector3`, `Point`, `Rect`

### 8.2 IMGUI Debug Overlay
**Status:** ❌ Not Started

From ReleaseNotes.md v23-27:
- Window management (SetPos, SetSize, SetCollapsed, etc.)
- Table rendering with sorting, freeze rows/cols
- Font loading and scaling
- OnClick/OnRightClick events
- Texture binding

---

## Phase 9: Advanced Features

### 9.1 Input Injection (Ext.Input)
**Status:** ❌ Not Started

```lua
Ext.Input.InjectKeyPress(key)
Ext.Input.InjectKeyDown(key)
Ext.Input.InjectKeyUp(key)
Ext.Input.GetInputManager()  -- v23+
```

### 9.2 Physics Queries (Ext.Level)
**Status:** ❌ Not Started

```lua
-- Raycast
Ext.Level.RaycastClosest(origin, target, [flags])
Ext.Level.RaycastAny(origin, target, [flags])
Ext.Level.RaycastAll(origin, target, [flags])

-- Sweep
Ext.Level.SweepSphereClosest(origin, target, radius, [flags])
Ext.Level.SweepCapsuleClosest(...)
Ext.Level.SweepBoxClosest(...)
Ext.Level.SweepCylinderClosest(...)

-- Overlap tests
Ext.Level.TestBox(pos, halfExtents, rotation, [flags])
Ext.Level.TestSphere(pos, radius, [flags])

-- Pathfinding
Ext.Level.GetActivePathfindingRequests()
```

### 9.3 Virtual Textures
**Status:** ❌ Not Started

Configuration: `Mods/<ModName>/ScriptExtender/VirtualTextures.json`

### 9.4 Debugger Support
**Status:** ❌ Not Started

VS Code integration with breakpoints, stepping, watches.

### 9.5 Mod Info API
**Status:** ⚠️ Partial

```lua
Ext.Mod.IsModLoaded(guid)
Ext.Mod.GetLoadOrder()
Ext.Mod.GetModInfo(guid)
```

---

## Phase 10: Data Access & Audio

### 10.1 Ext.StaticData API
**Status:** ❌ Not Started - [Issue #40](https://github.com/tdimino/bg3se-macos/issues/40)

Access to 200+ static game resource types.

```lua
local resource = Ext.StaticData.Get(guid, resourceType)
local resources = Ext.StaticData.GetAll(resourceType)
```

Resource types: Background, Feat, Spell, Origin, Progression, Race, ClassDescription, etc.

### 10.2 Ext.Resource & Ext.Template API
**Status:** ❌ Not Started - [Issue #41](https://github.com/tdimino/bg3se-macos/issues/41)

```lua
-- Template access
local templates = Ext.Template.GetAllLocalCacheTemplates()
local template = Ext.Template.Get(templateGuid)

-- Resource access
local exists = Ext.Resource.Exists(path)
local resource = Ext.Resource.Load(path, resourceType)
```

### 10.3 Ext.Localization API
**Status:** ❌ Not Started - [Issue #39](https://github.com/tdimino/bg3se-macos/issues/39)

```lua
local text = Ext.Localization.Get(handle)
local lang = Ext.Localization.GetLanguage()
```

### 10.4 Ext.Audio API
**Status:** ❌ Not Started - [Issue #38](https://github.com/tdimino/bg3se-macos/issues/38)

```lua
local soundId = Ext.Audio.PlaySound(eventName, position, entity)
Ext.Audio.PlayMusic(trackName)
Ext.Audio.SetMasterVolume(volume)
```

---

## Phase 11: Developer Tools

### 11.1 VS Code Debugger
**Status:** ❌ Not Started - [Issue #42](https://github.com/tdimino/bg3se-macos/issues/42)

Full debugging experience with breakpoints, stepping, and variable inspection.

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
- [x] Userdata lifetime scoping (v0.29.0)

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

## Implementation Priority

### Priority A: Critical Blockers (Breaks Most Mods)

| ID | Feature | Effort | Status |
|----|---------|--------|--------|
| A1 | Ext.Events API | Medium | ✅ 6 events + Tick (v0.13.0) |
| A2 | PersistentVars | Medium | ✅ Complete |
| A3 | Stats Property Read/Write | High | ✅ Complete (v0.18.0) |
| A4 | Component Property Access | High | ✅ Complete (v0.24.0) |
| A5 | NetChannel API | High | ❌ Not Started |
| A6 | User Variables | High | ✅ Complete |

### Priority B: High Impact (Breaks Many Mods)

| ID | Feature | Effort | Status |
|----|---------|--------|--------|
| B1 | Client Lua State | High | ❌ Not Started |
| B2 | Timer API | Low | ✅ Complete |
| B3 | Console/REPL | Medium | ✅ Complete (socket + file + in-game overlay) |
| B4 | GetAllComponents | Low | ✅ Complete |
| B5 | Stats Create/Sync | Medium | ⚠️ Partial (v0.25.0) - Create works, prototype sync pending |
| B6 | Userdata Lifetime Scoping | Medium | ✅ Complete (v0.29.0) |

### Priority C: Medium Impact (Developer Experience)

| ID | Feature | Effort | Status |
|----|---------|--------|--------|
| C1 | Ext.Math Library | Medium | ✅ Complete |
| C2 | Enum/Bitfield Objects | Medium | ✅ Complete (v0.26.0) |
| C3 | Console Commands | Low | ✅ Complete |
| C6 | Ext.Debug APIs | Low | ✅ Complete |
| C4 | Mod Variables | Medium | ✅ Complete (v0.28.0) |
| C5 | More Component Types | High | 🔄 Ongoing |

### Priority D: Nice-to-Have

| ID | Feature | Effort | Status | Issue |
|----|---------|--------|--------|-------|
| D1 | Noesis UI (Ext.UI) | High | ❌ Not Started | [#35](https://github.com/tdimino/bg3se-macos/issues/35) |
| D2 | IMGUI Debug Overlay | High | ❌ Not Started | [#36](https://github.com/tdimino/bg3se-macos/issues/36) |
| D3 | Physics/Raycasting (Ext.Level) | High | ❌ Not Started | [#37](https://github.com/tdimino/bg3se-macos/issues/37) |
| D4 | Audio (Ext.Audio) | Medium | ❌ Not Started | [#38](https://github.com/tdimino/bg3se-macos/issues/38) |
| D5 | Localization (Ext.Localization) | Low | ❌ Not Started | [#39](https://github.com/tdimino/bg3se-macos/issues/39) |
| D6 | Static Data (Ext.StaticData) | Medium | ❌ Not Started | [#40](https://github.com/tdimino/bg3se-macos/issues/40) |
| D7 | Resource/Template Management | Medium | ❌ Not Started | [#41](https://github.com/tdimino/bg3se-macos/issues/41) |
| D8 | VS Code Debugger | High | ❌ Not Started | [#42](https://github.com/tdimino/bg3se-macos/issues/42) |
| D9 | Input Injection | Medium | ❌ Not Started | - |
| D10 | Virtual Textures | Medium | ❌ Not Started | - |

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| v0.31.0 | 2025-12-11 | Entity Relationship Traversal - Ext.Entity.GetByHandle(), 32 component layouts (was 28), added InventoryOwner, InventoryMember, InventoryIsOwned, Equipable with EntityHandle support for character→inventory→item traversal (Issue #33) |
| v0.30.1 | 2025-12-11 | Component Property Layouts Expansion - 28 components (was 19), added Background, God, Value, TurnBased, SpellBook, StatusContainer, ActionResources, Weapon, InventoryContainer (Issue #33) |
| v0.30.0 | 2025-12-11 | Ext.Events Expansion - 10 events (was 8), DoConsoleCommand and LuaConsoleInput with Prevent pattern, combat/status events documented via Osiris (Issue #34) |
| v0.29.0 | 2025-12-10 | Userdata Lifetime Scoping - Entities, Components, and StatsObjects now validate lifetime on every access, preventing stale object use (Issue #28) |
| v0.28.0 | 2025-12-10 | Mod Variables - Ext.Vars.GetModVariables() for global per-mod data storage with persistence |
| v0.27.0 | 2025-12-10 | User Variables - entity.Vars for attaching custom data to entities with persistence (Issue #13) |
| v0.26.0 | 2025-12-10 | Ext.Enums - Type-safe enum/bitfield userdata with 14 types (DamageType, AbilityId, SkillId, StatusType, SurfaceType, etc.), flexible comparison, bitwise operations (Issue #29) |
| v0.25.0 | 2025-12-10 | Ext.Stats.Create and Sync (Issue #27) |
| v0.24.0 | 2025-12-10 | Expanded component property access - 8 component layouts (Health, BaseHp, Armor, Stats, BaseStats, Transform, Level, Data) with data-driven property definitions |
| v0.23.0 | 2025-12-10 | Health component property access - entity.Health.Hp/MaxHp/TemporaryHp working via data structure traversal + hash fix; Ext.Osiris.RaiseEvent() and GetCustomFunctions() for custom event dispatch |
| v0.22.0 | 2025-12-09 | Custom Osiris function registration - Ext.Osiris.NewCall/NewQuery/NewEvent for Lua-defined Osiris functions |
| v0.21.0 | 2025-12-09 | GetAllEntitiesWithComponent/CountEntitiesWithComponent - entity enumeration by component type |
| v0.20.0 | 2025-12-08 | Structured logging system - 14 modules, 4 log levels, timestamps, consistent formatting |
| v0.19.0 | 2025-12-06 | In-game console overlay with Tanit symbol, Ctrl+` toggle, command history |
| v0.18.0 | 2025-12-06 | Stats property write - `stat.Damage = "2d6"` modifies stats at runtime |
| v0.17.0 | 2025-12-06 | Ext.Math library - vec3/vec4/mat3/mat4 operations, transforms, decomposition |
| v0.16.0 | 2025-12-06 | Ext.Input API - CGEventTap keyboard capture, hotkey registration, key injection |
| v0.15.0 | 2025-12-06 | Socket console with Unix domain socket, readline client, real-time bidirectional I/O |
| v0.14.0 | 2025-12-06 | GameStateChanged event, game state tracking module, event-based state inference for macOS |
| v0.13.0 | 2025-12-06 | Ext.Events expansion (Tick, StatsLoaded, ModuleLoadStarted), priority/Once/handler IDs, Ext.OnNextTick |
| v0.12.0 | 2025-12-06 | PersistentVars (file-based savegame persistence), Ext.Vars.SyncPersistentVars() |
| v0.11.0 | 2025-12-05 | Ext.Timer API, Enhanced Debug Console, Ext.Debug APIs, Ext.Stats property read |
| v0.10.6 | 2025-12-03 | Fixed Osiris function name caching - OsiFunctionDef->Signature->Name two-level indirection |
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
- `plans/bg3se-docs-gap-analysis.md` - Comprehensive gap analysis

## References

- [Windows BG3SE](https://github.com/Norbyte/bg3se) - Reference implementation
- [BG3SE Docs](https://github.com/Norbyte/bg3se/tree/main/Docs) - Official API documentation
- [BG3 Modding Wiki](https://bg3.wiki/wiki/Modding) - Game mechanics documentation
- [Lua 5.4 Reference](https://www.lua.org/manual/5.4/) - Lua language reference
