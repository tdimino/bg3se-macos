# BG3SE-macOS Roadmap

This document tracks the development roadmap for achieving feature parity with Windows BG3SE (Norbyte's Script Extender).

## Current Status: v0.36.40

**Overall Feature Parity: ~92%** (based on comprehensive API function count analysis)

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
| `Ext.IO` | ✅ Full (4) | ✅ LoadFile, SaveFile, AddPathOverride, GetPathOverride (4) | **100%** | 1 |
| `Ext.Entity` | ✅ Full (26) | ⚠️ Get, GetByHandle, **Dual EntityWorld**, components, enumeration (22) | **85%** | 2 |
| `Ext.Stats` | ✅ Full (52) | ✅ **100% parity** — Get, GetAll, Create, Sync, CopyFrom, SetRawAttribute, ExecuteFunctors, TreasureTable stubs (52) | **100%** | 3 |
| `Ext.Events` | ✅ Full (~33) | ✅ 33 events (13 lifecycle + 17 engine + 2 functor + 1 network) + Subscribe/Unsubscribe/Prevent | **100%** | 2.5 |
| `Ext.Timer` | ✅ Full (13) | ✅ WaitFor, WaitForRealtime, Cancel, Pause, Resume, IsPaused, MonotonicTime, MicrosecTime, ClockEpoch, ClockTime, GameTime, DeltaTime, Ticks, IsGamePaused, +6 persistent (20) | **100%** | 2.3 |
| `Ext.Debug` | ✅ Full (8) | ✅ Memory introspection (11 macOS-specific) | **100%** | 2.3 |
| `Ext.Vars` | ✅ Full (8) | ✅ User + Mod Variables (12) | **100%** | 2.6 |
| `Ext.Types` | ✅ Full (15) | ✅ GetAllTypes, GetObjectType, GetTypeInfo, Validate, TypeOf, IsA, GetComponentLayout, GetAllLayouts, GenerateIdeHelpers (9) | **90%** | 7 |
| `Ext.Enums` | ✅ Full | ✅ 14 enum/bitfield types | **100%** | 7 |
| `Ext.Math` | ✅ Full (59) | ✅ 57 functions (vectors, matrices, 16 quaternions, scalars) | **97%** | 7.5 |
| `Ext.Input` | ✅ Full | ✅ CGEventTap capture, hotkeys (8 macOS-specific) | **100%** | 9 |
| `Ext.Net` | ✅ Full | ✅ Phase 4I Complete (handshake, version negotiation, full multiplayer transport) | **95%** | 6 |
| `Ext.UI` | ✅ Full (9) | ❌ Not impl | **0%** | 8 |
| `Ext.IMGUI` | ✅ Full (7+) | ✅ Complete widget system (40 types) - All widgets, events, Metal backend | **100%** | 8 |
| `Ext.Level` | ✅ Full (21) | ⚠️ RaycastClosest, RaycastAny, TestBox, TestSphere, GetHeightsAt, singleton accessors (9) | **43%** | 9 |
| `Ext.Audio` | ✅ Full (17) | ✅ PostEvent, Stop, PauseAll, ResumeAll, SetSwitch, SetState, RTPC (set/get/reset), LoadEvent, UnloadEvent (13) | **76%** | 10 |
| `Ext.Localization` | ✅ Full (2) | ⚠️ GetLanguage + safe stubs (1/2) | **50%** | 10 |
| `Ext.StaticData` | ✅ Full (5) | ✅ **All 9 types** (Feat, Race, Background, Origin, God, Class, Progression, ActionResource, FeatDescription), ForceCapture, HashLookup | **100%** | 10 |
| `Ext.Resource` | ✅ Full (2) | ✅ Get, GetAll, GetTypes, GetCount, IsReady (5) | **100%** | 10 |
| `Ext.Template` | ✅ Full (9) | ✅ 14 functions, **auto-capture**, Cache/LocalCache iteration | **100%** | 10 |
| Console/REPL | ✅ Full | ✅ Socket + file + in-game overlay | **95%** | 5 |
| PersistentVars | ✅ Full | ✅ File-based | **90%** | 2.4 |
| Client Lua State | ✅ Full | ✅ Context awareness, two-phase bootstrap | **90%** | 2.7 |
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
**Status:** ✅ Complete (v0.36.14) - **Dual EntityWorld** (client + server), **1,999 components registered** (534 layouts: 169 verified + 365 generated), **1,577 ARM64 sizes** + **702 Windows estimates** = **1,730 total** (87% coverage)

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
| PassiveContainer | **Passives** (ArrayProxy), PassiveCount |
| Tag | **Tags** (ArrayProxy), TagCount |
| Race | Race (GUID) |
| Origin | field_18, Origin |
| Classes | **Classes** (ArrayProxy with ClassUUID, SubClassUUID, Level), ClassCount |
| Movement | Direction, Acceleration, Speed, Speed2 |
| Background | Background (GUID) |
| God | God, HasGodOverride, GodOverride |
| Value | Value, Rarity, Unique |
| TurnBased | IsActiveCombatTurn, Removed, RequestedEndTurn, TurnActionsCompleted, ActedThisRoundInCombat, HadTurnInCombat, CanActInCombat, CombatTeam |
| SpellBook | **Spells** (ArrayProxy with SpellId), Entity, SpellCount |
| StatusContainer | StatusCount |
| ActionResources | ResourceTypeCount |
| Weapon | WeaponRange, DamageRange, WeaponProperties, WeaponGroup, Ability |
| InventoryContainer | ItemCount |
| InventoryOwner | InventoryCount, PrimaryInventory (EntityHandle) |
| InventoryMember | Inventory (EntityHandle), EquipmentSlot |
| InventoryIsOwned | Owner (EntityHandle) |
| Equipable | EquipmentTypeID (GUID), Slot |
| SpellContainer | **Spells** (ArrayProxy), SpellCount |
| Concentration | Caster (EntityHandle), TargetCount, SpellPrototype |
| BoostsContainer | **Boosts** (ArrayProxy with Type, BoostCount), BoostTypeCount |
| DisplayName | NameHandle, TitleHandle |

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

**Generated Component Registration (v0.36.6):**

All 1,999 components are now auto-registered from the BG3 binary:

| Namespace | Components | Description |
|-----------|------------|-------------|
| `eoc::` | 701 | Engine of Combat - BG3 gameplay |
| `esv::` | 596 | Server-side components |
| `ecl::` | 429 | Client-side components |
| `ls::` | 233 | Larian Studios base |
| `gui::` | 26 | GUI components |
| `navcloud::` | 13 | Navigation/pathfinding |
| `ecs::` | 1 | ECS internals |

Tools:
- `tools/extract_typeids.py` - Generates TypeId addresses header
- `tools/extract_typeids.py --registry` - Generates registration C file
- `docs/components/` - Modular component documentation by namespace

### 2.3 Timer API
**Status:** ✅ Complete (v0.36.5)

Scheduling API for delayed and periodic callbacks with full time utilities.

**Implemented API:**
```lua
-- One-shot timer (delay in milliseconds)
local handle = Ext.Timer.WaitFor(1000, function(h)
    Ext.Print("1 second later!")
end)

-- Wall-clock timer (ignores game pause)
local handle = Ext.Timer.WaitForRealtime(1000, function(h)
    Ext.Print("1 second real time!")
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

-- Time utilities
local ms = Ext.Timer.MonotonicTime()  -- Milliseconds since app start
local us = Ext.Timer.MicrosecTime()   -- Microseconds since app start
local epoch = Ext.Timer.ClockEpoch()  -- Unix timestamp (seconds)
local time = Ext.Timer.ClockTime()    -- "YYYY-MM-DD HH:MM:SS"
local game = Ext.Timer.GameTime()     -- Game time in seconds (pauses with game)
local delta = Ext.Timer.DeltaTime()   -- Last frame delta in seconds
local ticks = Ext.Timer.Ticks()       -- Game tick count
local paused = Ext.Timer.IsGamePaused() -- Check if game time paused

-- Persistent timers (survive save/load)
Ext.Timer.RegisterPersistentHandler("MyHandler", function(handle, argsJson)
    local args = Ext.Json.Parse(argsJson)
    -- Handle timer
end)
local handle = Ext.Timer.WaitForPersistent(5000, "MyHandler", {target = "player"})
Ext.Timer.CancelPersistent(handle)
local json = Ext.Timer.ExportPersistent()  -- For saving
local count = Ext.Timer.ImportPersistent(json)  -- After loading
```

**Implementation:**
- Fixed-size timer pool (256 regular + 64 persistent timers)
- Min-heap priority queue for efficient scheduling
- Callbacks stored via `luaL_ref` to prevent GC
- Polled from `COsiris::Event` hook
- 1-based handles (0 = error sentinel)
- Persistent timers use named handlers with JSON-serializable args
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
**Status:** ⚠️ 60% Parity (v0.36.9) - 18 events (10 lifecycle + 8 engine events via one-frame polling)

From API.md: "Subscribing to engine events can be done through the `Ext.Events` table."

**Implemented API (v0.36.9):**
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

-- Engine events (v0.36.9) - polled from one-frame ECS components
Ext.Events.TurnStarted:Subscribe(function(e)
    _P("Turn started for entity: " .. tostring(e.Entity) .. " round: " .. e.Round)
end)

Ext.Events.StatusApplied:Subscribe(function(e)
    _P("Status " .. e.StatusId .. " applied to " .. tostring(e.Entity))
end)

Ext.Events.CombatStarted:Subscribe(function(e)
    _P("Combat started!")
end)
```

**Lifecycle Events (10):**
| Event | When | Event Data | Status |
|-------|------|------------|--------|
| `SessionLoading` | Session setup started | {} | ✅ Implemented |
| `SessionLoaded` | Session ready | {} | ✅ Implemented |
| `ResetCompleted` | After `reset` command | {} | ✅ Implemented |
| `Tick` | Every game loop (~30hz) | {DeltaTime} | ✅ Implemented |
| `StatsLoaded` | After stats entries loaded | {} | ✅ Implemented |
| `ModuleLoadStarted` | Before mod scripts load | {} | ✅ Implemented |
| `GameStateChanged` | State transitions | {FromState, ToState} | ✅ Implemented |
| `KeyInput` | Keyboard input | {Key, Pressed, Modifiers, Character} | ✅ Implemented |
| `DoConsoleCommand` | Console ! command | {Command, Prevent} | ✅ Implemented |
| `LuaConsoleInput` | Raw Lua console input | {Input, Prevent} | ✅ Implemented |

**Engine Events via One-Frame Polling (8) - v0.36.9:**
| Event | When | Event Data | Component Polled |
|-------|------|------------|------------------|
| `TurnStarted` | Combat turn begins | {Entity, Round} | esv::TurnStartedEventOneFrameComponent |
| `TurnEnded` | Combat turn ends | {Entity} | esv::TurnEndedEventOneFrameComponent |
| `CombatStarted` | Combat initiated | {Entity} | esv::combat::CombatStartedEventOneFrameComponent |
| `CombatEnded` | Combat resolved | {Entity} | esv::combat::LeftEventOneFrameComponent |
| `StatusApplied` | Status effect applied | {Entity, StatusId, Source} | esv::status::ApplyEventOneFrameComponent |
| `StatusRemoved` | Status effect removed | {Entity} | esv::status::RemoveEventOneFrameComponent |
| `EquipmentChanged` | Equipment slot changed | {Entity} | esv::stats::EquipmentSlotChangedEventOneFrameComponent |
| `LevelUp` | Character level increased | {Entity} | esv::stats::LevelChangedOneFrameComponent |

**Missing Events (~12) - See Issue #51:**
| Event | Type | Priority | Notes |
|-------|------|----------|-------|
| `ExecuteFunctor` | Hook | HIGH | Stats functor execution - needed for damage mods |
| `BeforeDealDamage` | Hook | HIGH | Pre-damage modification |
| `DealDamage` | Hook | HIGH | Damage dealt |
| `MouseButton` | Client | LOW | Mouse clicks |
| `MouseWheel` | Client | LOW | Scroll wheel |
| `ControllerButton` | Client | LOW | Gamepad buttons |
| `Shutdown` | Lifecycle | LOW | Game exit |
| `NetMessage` | Network | LOW | Cross-client comms |

**Additional One-Frame Components Available for Future Polling:**
- Death: `DownedEvent`, `DiedEvent`, `ResurrectedEvent`
- Spells: `SpellCastEvent`, `SpellsLearnedEvent`, `ConcentrationChanged`
- Combat: `CombatantKilledEvent`, `HitResultEvent`, `ProjectileImpactEvent`
- Stats: `AbilityCheckEvent`, `SkillCheckEvent`, `SavingThrowRolledEvent`
- Boosts: `BoostChangedEvent`

**Advanced Features:**
- Priority-based handler ordering (lower = called first)
- Once flag for auto-unsubscription
- Handler ID return for explicit unsubscription
- Deferred modifications during dispatch (prevents iterator corruption)
- Protected calls to prevent cascade failures
- `!events` console command to inspect handler counts
- **Prevent pattern** - handlers can set `e.Prevent = true` to block default execution
- **One-frame polling** - only polls when handlers are registered (performance optimization)

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

### 2.7 Client Lua State & Context Separation
**Status:** ✅ Complete (v0.36.4 - Issue #15)

From API.md: "The game is split into client and server components... the extender keeps multiple Lua states."

**Architecture Decision:** Single Lua state with context awareness (not dual states)
- BG3 macOS is single-player where server/client run in same process
- Simpler than dual Lua VMs while matching Windows BG3SE behavior

**Implemented:**
- [x] `Ext.GetContext()` - Returns "Server", "Client", or "None"
- [x] `Ext.IsServer()` / `Ext.IsClient()` - Real context detection (were hardcoded stubs)
- [x] Two-phase bootstrap loading:
  1. Phase 1: All BootstrapServer.lua files load in SERVER context
  2. Phase 2: All BootstrapClient.lua files load in CLIENT context
- [x] Context guards for server-only APIs (Osiris, Stats writes)
- [x] Lifecycle: None → Server → Client

**API:**
```lua
-- Check context
print("Context:", Ext.GetContext())    -- "Server", "Client", or "None"
print("IsServer:", Ext.IsServer())     -- true during BootstrapServer.lua
print("IsClient:", Ext.IsClient())     -- true during BootstrapClient.lua
```

**Not Yet Implemented:**
- True dual Lua state separation (if needed for full isolation)
- Client-only APIs (Ext.UI, Ext.IMGUI, rendering hooks)

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
**Status:** ✅ Phase 4I Complete (v0.36.31) - Full multiplayer transport with handshake: JSON hello exchange, CanSendExtenderMessages gating, Ext.Net.IsReady/PeerVersion, auto-switch timing fix.

From API.md: "NetChannel API provides a structured abstraction for request/response and message broadcasting."

**Implemented API (Phase 1):**
```lua
-- Create channel
local channel = Net.CreateChannel(ModuleUUID, "MyChannel")

-- Fire-and-forget handler (✅ Working)
channel:SetHandler(function(data, user)
    _P("Received: " .. Ext.Json.Stringify(data))
end)

-- Client → Server (✅ Working)
channel:SendToServer(data)

-- Server → Client(s) (✅ Working locally)
channel:SendToClient(data, userOrGuid)
channel:Broadcast(data)

-- Utility (✅ Working)
Ext.Net.IsHost()            -- Returns true in single-player
Ext.Net.Version()           -- Returns 2 (binary support)
Ext.Net.IsReady()           -- Returns true after handshake
Ext.Net.PeerVersion(userId) -- Returns peer's proto version
```

**Phase 1 Implementation (Complete):**
- [x] `Ext.Net` namespace with 8 functions
- [x] `Net.CreateChannel()` high-level API
- [x] `SetHandler()` for fire-and-forget messages
- [x] `SendToServer()`, `SendToClient()`, `Broadcast()`
- [x] In-process message bus for local/single-player
- [x] `NetModMessage` event firing to handlers
- [x] `Ext.Mod` namespace (IsModLoaded, GetLoadOrder, GetMod, GetBaseMod)

**Phase 2 Implementation (Complete - v0.36.24):**
- [x] `SetRequestHandler()` for request/reply pattern
- [x] `RequestToServer()` with callback
- [x] `RequestToClient()` with callback
- [x] Callback registry with request_id/reply_to_id correlation
- [x] `callback_registry_invoke()` - retrieves and calls stored callbacks
- [x] Owner state tracking (`owner_L`) for cross-Lua-state callback safety
- [x] Timeout cleanup (30 second) via `callback_registry_cleanup_expired()`

**Verified Working (Phase 2):**
```lua
-- Request/reply handler (server-side)
channel:SetRequestHandler(function(data, user)
    return { status = "ok", echo = data.message }
end)

-- Request with callback (client-side)
channel:RequestToServer({message = "Hello!"}, function(response)
    _P("*** CALLBACK SUCCESS! ***")
    _P("Response: " .. Ext.Json.Stringify(response))
end)
```

**Phase 4D: Ghidra RE (COMPLETE):**
- [x] Found `GameServer::ActivatePeer` at `0x104abbb2c` (string ref tracing)
- [x] Found `GameServer::DeactivatePeer` at `0x105347910`
- [x] **EocServer+0xA8 = GameServer** (233 accesses, statistical analysis of 2706 loads)
- [x] **GameServer+0x1F8 = NetMessageFactory** (74 accesses, +16 from Windows)
- [x] **GameServer+0x2D0 = ProtocolList** (Larian Array: ptr(8)+cap_u32(4)+size_u32(4) = 16 bytes)
- [x] **GameServer+0x2E0 = ProtocolMap** (HashMap for protocol ID lookup, -1 sentinel buckets)
- [x] Itanium ABI vtable with dual destructor entries implemented
- [x] `net_hooks_capture_peer()` reads GameServer, NetMessageFactory, ProtocolList from live game
- [x] Integrated into main.c after EntityWorld discovery
- [x] Confirmed GameServer struct fields: `+0x650` (peer array), `+0x694/0x698` (peer hash)
- [x] Found `AbstractPeer::Protocols` TypeContext at `0x1010a857c`
- [x] Documented Windows struct layouts from BG3Extender reference
- [x] Created ARM64 binary analysis scripts (`scripts/re/`)
- [x] Full RE documentation in `ghidra/offsets/NETWORKING.md`
- [x] Runtime probe EocServer→GameServer offset — confirmed 0xA8 at runtime
- [x] ProtocolList offset corrected from +0x2E0 to +0x2D0 via live memory probing
- [x] NetMessageFactory offset confirmed at +0x1F8 via runtime
- [x] ProcessMsg dispatch via Protocol VMT[2] (Itanium ABI)

**Phase 4G: BitstreamSerializer + Outbound Send (COMPLETE - v0.36.29):**
- [x] em_serialize uses BitstreamSerializer VMT dispatch (WriteBytes at VMT[3], ReadBytes at VMT[4])
- [x] IsWriting flag at serializer+0x08 determines read vs write mode
- [x] `net_hooks_send_message()` — outbound send via GameServer VMT SendToPeer (index 28)
- [x] Runtime VMT probe validates SendToPeer function pointer before first call
- [x] RakNet backend: JSON wire format, send_to_server, send_to_user implemented
- [x] `network_backend_set_raknet()` switches from Local to RakNet when GameServer captured

**Phase 4H: Peer Resolution + Broadcast + Auto-Detect (COMPLETE - v0.36.30):**
- [x] GUID-to-peer resolution for `send_to_client` via `peer_manager_find_by_guid()`
- [x] Peer iteration for `broadcast` via `peer_manager_iterate()` + `broadcast_visitor`
- [x] Auto-detect multiplayer: `network_backend_set_raknet()` called from `net_hooks_insert_protocol()`
- [x] Implicit peer handshake: unknown peers auto-registered in `extender_process_msg()`
- [x] `net_hooks_sync_active_peers()` reads GameServer ActivePeerIds (+0x650/+0x65c)

**Phase 4I: Handshake + Version Negotiation (COMPLETE - v0.36.31):**
- [x] JSON hello handshake: `{"t":"hello","v":2}` exchange via ExtenderMessage
- [x] `peer_manager_can_send_extender()` gates all RakNet sends on proto_version > 0
- [x] `Ext.Net.IsReady()` and `Ext.Net.PeerVersion(userId)` Lua API
- [x] Hello message parsing in `extender_process_msg()` (intercepts before message bus)
- [x] Server auto-replies to client hello messages (ping-pong prevention: only first hello)
- [x] Fixed auto-switch timing: moved to `net_hooks_insert_protocol()` (was premature in `net_hooks_capture_peer()`)
- [x] Hash container warning in `net_hooks_sync_active_peers()` for invalid peer IDs (log-once guard)
- [x] **ProtocolList offset corrected**: +0x2D0 with packed uint32 cap/size (was +0x2E0 with uint64)
- [x] **Larian Array layout**: `{data_ptr(8), capacity_u32(4), size_u32(4)}` — 16-byte compact struct
- [x] Buffer overread fix: hello parsing copies to NUL-terminated stack buffer before strstr/sscanf
- [x] Race condition fix: backend switch before host peer proto_version assignment
- [x] Added `safe_memory_write_u32()` for compact array field updates

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
**Status:** ✅ Complete (v0.36.17) - GenerateIdeHelpers API

Complete Lua type annotations for IDE support via runtime generation.

**Implemented API:**
```lua
-- Generate LuaLS-compatible type annotations file
Ext.Types.GenerateIdeHelpers("ExtIdeHelpers.lua")  -- Returns content, saves to file

-- Query component property layouts
local layout = Ext.Types.GetComponentLayout("eoc::HealthComponent")
-- Returns: {Name, ShortName, Size, Properties=[{Name, Type, Offset}...]}

-- Get all available layouts
local layouts = Ext.Types.GetAllLayouts()  -- Returns array of all 534 layouts
```

**Generated Output:**
- `---@meta` header with `---@diagnostic disable`
- All 14 enum types as `---@alias` definitions
- All 1,999 component types as `---@class` annotations
- 534 components with property `---@field` annotations
- Ext.* namespace with all functions

**Console command:** `!ide_helpers [filename]`

### 7.4 IDE Integration
**Status:** ✅ Complete (v0.36.17)

- Autocomplete for all APIs via LuaLS
- Type hints for component properties
- Enum value completion

**Setup for VS Code:**
```json
// .luarc.json
{
  "runtime.version": "Lua 5.4",
  "workspace.library": ["./ExtIdeHelpers.lua"],
  "diagnostics.globals": ["Ext", "Osi", "Mods"]
}
```

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
**Status:** ✅ Complete (v0.36.21) - **All 40 Widget Types**

**Implemented (v0.36.21):**
- ✅ Dear ImGui library integration
- ✅ Metal rendering backend (ImGui_ImplMetal)
- ✅ CAMetalLayer hook for render injection
- ✅ CGEventTap input capture with Cocoa coordinate conversion
- ✅ **Mouse input complete** - Hover detection, button clicks, drag all working (v0.36.19)
- ✅ F11 hotkey toggle
- ✅ **Widget object system** - Handle-based (4096 max), generation counters (v0.36.20)
- ✅ **Lua bindings** - NewWindow, AddText, AddButton, AddCheckbox, AddSeparator, AddGroup
- ✅ **Property access** - Metatables with __index/__newindex for Open, Visible, Label, etc.
- ✅ **Event callbacks** - OnClick, OnChange, OnClose, OnExpand, OnCollapse support
- ✅ **Input widgets** - InputText, Combo, RadioButton with Value/SelectedIndex (v0.36.21)
- ✅ **Slider widgets** - SliderFloat, SliderInt, DragFloat, DragInt (v0.36.21)
- ✅ **Color widgets** - ColorEdit, ColorPicker with RGBA (v0.36.21)
- ✅ **Container widgets** - Tree, Table, TabBar, TabItem, MenuBar, Menu, MenuItem (v0.36.21)
- ✅ **Progress widgets** - ProgressBar with overlay text (v0.36.21)
- ✅ **Standalone test app** - tools/imgui_test for testing without BG3 (v0.36.21)

**Platform Note:** BG3 macOS uses native Cocoa/AppKit (NOT SDL like Windows).
Input uses CGEventTap → direct io.MousePos (skips ImGui_ImplOSX_NewFrame which overwrote coords).

**Remaining (low priority):**
- Font loading and scaling
- Texture binding (images)
- Style enums (GuiStyleVar, GuiColor)

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
**Status:** ✅ ~85% Complete - [Issue #40](https://github.com/tdimino/bg3se-macos/issues/40)

Access to static game resource types (Feats, Races, Backgrounds, Origins, Gods, Classes).

```lua
-- Auto-capture at SessionLoaded - no Frida needed!
-- Just use the API directly:
local feats = Ext.StaticData.GetAll("Feat")
for _, f in ipairs(feats) do
    print(f.Name, f.ResourceUUID)  -- "Alert", "f57bd72c-be64-4855-3a9e-7dbb657656e6"
end

-- Get by GUID
local feat = Ext.StaticData.Get("Feat", "d215b9ad-9753-4d74-f98f-bf24ce1dd653")
print(feat.Name)  -- "AbilityScoreIncrease"

-- Get count
local count = Ext.StaticData.GetCount("Feat")  -- Returns 41

-- Manual trigger (if auto-capture missed something)
local captured = Ext.StaticData.TriggerCapture()
print("Captured " .. captured .. " managers")

-- Frida fallback (if auto-capture fails)
Ext.StaticData.LoadFridaCapture()        -- Load Feat manager
Ext.StaticData.LoadFridaCapture("Race")  -- Load specific type

-- Debug helpers
Ext.StaticData.DumpStatus()
Ext.StaticData.DumpFeatMemory()  -- Diagnostic memory dump
```

**Implementation Notes:**
- **Auto-capture at SessionLoaded** - TypeContext traversal + real manager probing
- **FixedString resolution** - Name field at +0x18 resolved via GlobalStringTable
- **Generic config infrastructure** - Per-type offsets for Race, Origin, God, Class
- Safe memory reads prevent crashes when captured pointers become stale
- Offsets verified via Ghidra: count at +0x7C, array at +0x80, FEAT_SIZE=0x128

**What Works (Dec 17, 2025):**
- ✅ **Auto-capture at SessionLoaded** - No Frida needed for basic access
- ✅ `GetAll("Feat")` returns 41 feats with **Names and GUIDs**
- ✅ `Get("Feat", guid)` retrieves single feat by GUID
- ✅ `TriggerCapture()` manual trigger for debugging
- ✅ `LoadFridaCapture([type])` as fallback (type-aware)
- ✅ **FixedString Name resolution** - feat.Name returns actual names
- ✅ Safe memory reads prevent crashes on stale pointers
- ✅ Generic ManagerConfig infrastructure for all resource types

**Auto-Capture Flow:**
1. SessionLoaded event fires
2. `staticdata_post_init_capture()` runs automatically
3. TypeContext traversal finds managers by name
4. Real manager probing validates metadata pointers
5. Frida captures loaded as fallback if available

**Remaining Work:**
- [x] Extract feat names from structure (FixedString resolution) ✅
- [x] Generic config-based infrastructure for multiple types ✅
- [x] Auto-capture without Frida ✅
- [ ] Frida capture scripts for Race, Origin, God, Class types
- [ ] Verify auto-capture works for all resource types

Resource types: Feat (✅ complete with auto-capture), Race (🔶 config ready), Background (🔶 no Name field), Origin (🔶), God (🔶), ClassDescription (🔶)

### 10.2 Ext.Resource & Ext.Template API
**Status:** ✅ Complete - [Issue #41](https://github.com/tdimino/bg3se-macos/issues/41)

**Ext.Resource: ✅ Complete (v0.36.2)** - Full API for non-GUID resources

```lua
-- Resource access (34 types: Visual, Material, Texture, Dialog, etc.)
Ext.Resource.IsReady()           -- true when ResourceManager available
Ext.Resource.GetTypes()          -- Returns all 34 type names
Ext.Resource.GetCount("Visual")  -- Returns count (10000+)
Ext.Resource.GetAll("Dialog")    -- Returns all Dialog resources
Ext.Resource.Get(id, "Material") -- Get specific resource by FixedString ID
```

**Global pointer:** `ls::ResourceManager::m_ptr` at offset `0x08a8f070`
- ResourceBank at manager `+0x28` (primary) and `+0x30` (secondary)
- Hash table traversal for resource iteration

**Ext.Template: ✅ Complete (v0.36.1)** - Full API with auto-capture

```lua
-- Template access (all working!)
Ext.Template.IsReady()                    -- Check if initialized
Ext.Template.GetCount("Cache")            -- 61 templates
Ext.Template.GetCount("LocalCache")       -- 19 templates
Ext.Template.GetAllCacheTemplates()       -- Iterate with GUIDs
Ext.Template.GetAllLocalCacheTemplates()  -- Iterate with GUIDs
Ext.Template.Get(guid)                    -- Cascading lookup
Ext.Template.DumpStatus()                 -- Debug info
```

**Implementation:** Uses direct global pointer reads (no hooks needed) discovered via Ghidra:
- `GlobalTemplateManager::m_ptr` at offset `0x08a88508`
- `CacheTemplateManager::m_ptr` at offset `0x08a309a8`
- `Level::s_CacheTemplateManager` at offset `0x08a735d8`

Key discovery: Template GUID at +0x10 is a FixedString index, resolved via `fixed_string_resolve()`.

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
| A5 | NetChannel API | High | ✅ Phase 4I Complete (v0.36.31) |
| A6 | User Variables | High | ✅ Complete |

### Priority B: High Impact (Breaks Many Mods)

| ID | Feature | Effort | Status |
|----|---------|--------|--------|
| B1 | Client Lua State | High | ✅ Complete (v0.36.4) - Context awareness, two-phase bootstrap |
| B2 | Timer API | Low | ✅ Complete |
| B3 | Console/REPL | Medium | ✅ Complete (socket + file + in-game overlay) |
| B4 | GetAllComponents | Low | ✅ Complete |
| B5 | Stats Create/Sync | Medium | ✅ Complete (v0.32.4) - Full sync for created + existing stats |
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
| D2 | IMGUI Debug Overlay | High | ✅ Complete (v0.36.21) - All 40 widget types | [#36](https://github.com/tdimino/bg3se-macos/issues/36) |
| D3 | Physics/Raycasting (Ext.Level) | High | ⚠️ 9 functions (43%, offsets need runtime verification) | [#37](https://github.com/tdimino/bg3se-macos/issues/37) |
| D4 | Audio (Ext.Audio) | Medium | ⚠️ 13 functions (76%, VMT indices need runtime verification) | [#38](https://github.com/tdimino/bg3se-macos/issues/38) |
| D5 | Localization (Ext.Localization) | Low | ❌ Not Started | [#39](https://github.com/tdimino/bg3se-macos/issues/39) |
| D6 | Static Data (Ext.StaticData) | Medium | 🔶 Blocked by #44 | [#40](https://github.com/tdimino/bg3se-macos/issues/40) |
| D7 | Resource/Template Management | Medium | ✅ Complete (v0.36.2) | [#41](https://github.com/tdimino/bg3se-macos/issues/41) |
| D8 | VS Code Debugger | High | ❌ Not Started | [#42](https://github.com/tdimino/bg3se-macos/issues/42) |
| D9 | Input Injection | Medium | ❌ Not Started | - |
| D10 | Virtual Textures | Medium | ❌ Not Started | - |

---

## Version History

See **[docs/CHANGELOG.md](docs/CHANGELOG.md)** for detailed version history with:
- Version, date, and parity percentage
- Category tags (Core, Entity, Stats, Events, etc.)
- Related GitHub issues
- Added/Changed/Fixed sections per release

**Recent Releases:**

| Version | Date | Highlights |
|---------|------|------------|
| v0.36.39 | 2026-02-07 | **Issue #66: Handle Encoding + Crash Diagnostics** - Read FunctionType from OsiFunctionDef +0x28 (fixes funcType=0 bug), encode OsirisFunctionHandle from Key[0..3], crash-resilient mmap ring buffer + SIGSEGV handler + breadcrumbs, `!probe_osidef` console command |
| v0.36.38 | 2026-02-06 | **Issue #66 Fix: Osiris Call Crash** - Hook RegisterDIVFunctions to capture DivFunctions::Call/Query (correct OsiArgumentDesc* signature). Fixes SIGSEGV on AddGold, TemplateAddTo, and all Osi.* calls on ARM64. |
| v0.36.37 | 2026-02-06 | **Issue #65 Diagnostics + Net Parity** - BG3SE_NO_HOOKS env var, fallback deferred init in fake_InitGame, legacy NetMessage event, PlayerHasExtender (Issue #6) |
| v0.36.36 | 2026-02-06 | **Issue #65 Diagnostics** - Added diagnostic timing and logging for user ShaiLaric's M4/Tahoe crash report |
| v0.36.35 | 2026-02-06 | **Issue #65 Fix + Stats 100% Parity** - Deferred session init (all ~2,800 kernel calls moved to tick loop), state corruption fix in fake_InitGame, diagnostic timing, BG3SE_MINIMAL env var, build system auto-builds Dobby+Lua from source |
| v0.36.34 | 2026-02-06 | **Ext.Stats 100% Parity** - 22 new items: Sync, CopyFrom, SetRawAttribute, ExecuteFunctors/ExecuteFunctor, PrepareFunctorParams, TreasureTable/TreasureCategory stubs, StatsObject methods |
| v0.36.33 | 2026-02-06 | **Deferred Net Init (Issue #65)** - Move ~65 mach_vm_read_overwrite kernel calls from COsiris::Load to tick loop, fixing game startup failure on some machines. State machine with 500ms stability gate and exponential backoff retry. |
| v0.36.40 | 2026-02-07 | **Mach Exception Handler** - Catches EXC_BAD_ACCESS/EXC_BAD_INSTRUCTION before CrashReporter via Mach exception ports + MIG stubs. Fixed `!probe_osidef` crash (safe_memory_read vs safe_memory_read_pointer). Three-tier crash diagnostics (Issue #66) |
| v0.36.32 | 2026-02-06 | **Parity Push to 90%** - Ext.Stats expansion (12 new functions: enum lookup, modifier attributes, prototype cache), Ext.Level (9 functions: raycasting, overlap tests, tile queries), Ext.Audio (13 functions: WWise playback, state/switch, RTPC, event management) |
| v0.36.31 | 2026-02-06 | **NetChannel API Phase 4I** - Handshake + version negotiation: JSON hello exchange, CanSendExtenderMessages gating, Ext.Net.IsReady/PeerVersion, auto-switch timing fix (Issue #6) |
| v0.36.30 | 2026-02-06 | **NetChannel API Phase 4H** - Peer resolution + broadcast + auto-detect: GUID-to-peer lookup, peer iteration broadcast, ActivePeerIds sync, implicit handshake (Issue #6) |
| v0.36.29 | 2026-02-06 | **NetChannel API Phase 4G** - Bidirectional transport: em_serialize via BitstreamSerializer VMT dispatch (WriteBytes/ReadBytes), outbound send via GameServer VMT SendToPeer (index 28), RakNet backend with JSON wire format, network_backend_set_raknet() (Issue #6) |
| v0.36.28 | 2026-02-06 | **NetChannel API Phase 4F** - GetMessage hook via Dobby (ASLR-aware), ExtenderMessage pool (8 slots), full net::Message layout (40 bytes), em_serialize diagnostic, process_msg routes to message_bus (Issue #6) |
| v0.36.27 | 2026-02-05 | **NetChannel API Phase 4E** - Live ProtocolList insertion (swap-to-end pattern), MessageFactory runtime probe, safe_memory write API, cleanup on shutdown (Issue #6, #65) |
| v0.36.26 | 2026-02-05 | **NetChannel API Phase 4D** - All network offsets RE'd via statistical binary analysis: EocServer+0xA8=GameServer, GameServer+0x1F8=NetMessageFactory, +0x2E0=ProtocolList. Itanium ABI vtable, capture pipeline in main.c (Issue #6) |
| v0.36.25 | 2026-02-04 | **NetChannel API Phase 4A** - Protocol VMT matching Windows, ExtenderProtocol stub, NetworkBackend abstraction (Local/RakNet), PeerManager with rate limiting. Reviewed by 4 agents (Issue #6) |
| v0.36.24 | 2026-02-04 | **NetChannel API Phase 2** - Request/reply callbacks, callback registry with Lua state safety, 30s timeout cleanup (Issue #6) |
| v0.36.23 | 2026-02-03 | **NetChannel API Phase 1** - Ext.Net namespace (6 functions), Net.CreateChannel high-level API, Ext.Mod namespace, in-process message bus for local/single-player. Fire-and-forget messaging working (Issue #6) |
| v0.36.22 | 2026-02-02 | **Critical Bug Fix: Reaction Crash** - Fixed game crash on in-combat reactions (AoO, Counterspell, etc.). Root cause: Interrupt functor hook had wrong 3-param signature instead of 4-param with HitResult* first (Issue #60) |
| v0.36.21 | 2026-01-30 | **Complete Ext.IMGUI Widget System** - All 40 widget types (InputText, Combo, Slider, ColorEdit, Tree, Table, Tabs, Menu), event callbacks, standalone test app (Issue #36) |
| v0.36.20 | 2025-12-31 | **ImGui Widget Foundation** - Handle-based objects, Lua userdata, basic widgets (Window, Text, Button, Checkbox) (Issue #36) |
| v0.36.19 | 2025-12-31 | **ImGui OSX Backend Bypass** - Skip ImGui_ImplOSX_NewFrame (overwrote CGEventTap coords), apply cached mouse pos directly (Issue #36) |
| v0.36.18 | 2025-12-30 | **ImGui Mouse Input Fix** - Fixed Cocoa coordinate conversion, 4-step CG→Screen→Window→View, works fullscreen/windowed (Issue #36) |
| v0.36.17 | 2025-12-28 | **IDE Types** - GenerateIdeHelpers for VS Code IntelliSense, GetComponentLayout, GetAllLayouts (Issue #7) |
| v0.36.16 | 2025-12-28 | **Ext.Types Full Reflection** - GetAllTypes (~2050), GetTypeInfo, TypeOf, IsA, Validate (Issue #48) |
| v0.36.15 | 2025-12-27 | **API Context Annotations** - Context column (B/S/C) added to all API tables in api-reference.md (Issue #46) |
| v0.36.14 | 2025-12-27 | **Dual EntityWorld Complete** - Client singleton discovered (`0x10898c968`), both client + server worlds auto-captured |
| v0.36.11 | 2025-12-26 | **30 Events Complete** - 11 new events (death, spell, hit, rest, approval, lifecycle), completes Issue #51 |
| v0.36.10 | 2025-12-26 | **Logging & Debugging** - Ext.Log convenience functions, Ext.Events.Log callback, combat-tested structured logging (#8, #42) |
| v0.36.9 | 2025-12-24 | **534 Component Layouts** - 3.2x increase (169→534), integrated 365 new layouts from Windows headers (#52) |
| v0.36.8 | 2025-12-24 | **Unified Component Database** - 1,730 sizes (87% coverage), 4 new analysis tools, 293 valid generated layouts (#52) |
| v0.36.7 | 2025-12-23 | **1,538 ARM64 Sizes** - Parallel Ghidra extraction workflow, modular namespace documentation (#52) |
| v0.36.6 | 2025-12-23 | **631 Component Layouts** - Two-tier registration (169 verified + 462 generated), Gen_ prefix strategy, 1,999 TypeIds, 504 property defs, 70 Ghidra-verified sizes (#52) |
| v0.36.5 | 2025-12-22 | **Math/Timer/IO APIs Complete** - 16 quaternion ops, **20 timer functions** (persistent timers + GameTime), path overrides (#47, #49, #50 all complete) |
| v0.36.4 | 2025-12-22 | **Context System** - Server/Client context awareness, two-phase bootstrap, API guards (#15) |
| v0.36.3 | 2025-12-22 | **StaticData All 9 Types** - ForceCapture + HashLookup for Race, God, FeatDescription (#45) |
| v0.36.2 | 2025-12-21 | **Ext.Resource API** - 34 resource types (Visual, Material, Texture, etc.) (#41) |
| v0.36.1 | 2025-12-21 | **Template Auto-Capture** - Direct global pointer reads, no hooks needed (#41) |
| v0.35.0 | 2025-12-20 | **Dynamic Array Components** - 6 array-enabled components with ArrayProxy (#33) |
| v0.34.2 | 2025-12-20 | **Issue #40 Fix** - GetAll returns all entries (41 feats), fixed probe logic |
| v0.34.1 | 2025-12-17 | **StaticData Auto-Capture** - Eliminates Frida requirement, TriggerCapture API (#40) |
| v0.34.0 | 2025-12-16 | **ARM64 Safe Hooking** - Complete infrastructure + discovery that FeatManager needs standard Dobby (#44, #40) |
| v0.33.0 | 2025-12-15 | **StaticData Name Resolution** - FixedString names for feats, generic multi-type infrastructure (#40) |
| v0.32.9 | 2025-12-15 | **Ext.Template API** - Template manager with Frida capture, OriginalTemplateComponent, 158 components (#41) |
| v0.32.8 | 2025-12-15 | **Massive Tag Component Expansion** - 105 new tag components, 157 total, ~65% parity (#33) |
| v0.32.7 | 2025-12-14 | **Component Batch Expansion** - 11 new components (2 combat + 9 tag), 52 total, ~60% parity (#33) |
| v0.32.6 | 2025-12-14 | **Component Expansion** - 5 new components (Death, ThreatRange, InventoryWeight, IsInCombat), 41 total (#33) |
| v0.32.5 | 2025-12-14 | Ext.StaticData API - Feat type with hook-based capture (#40) |
| v0.32.4 | 2025-12-13 | **Stats Sync Complete** - Shadow stats + game stats, RefMap insertion, prototype managers (#32) |
| v0.32.3 | 2025-12-12 | Testing Infrastructure - !test suite, Debug.* helpers, Frida scripts (#8) |
| v0.32.2 | 2025-12-12 | Stats Sync Complete - ARM64 const& fix, RefMap linear search, Sync working (#32) |
| v0.32.1 | 2025-12-12 | Stats Sync - SpellPrototype::Init, RefMap lookup, existing spell sync (#32) |
| v0.32.0 | 2025-12-12 | Prototype Managers - All 5 singletons discovered, Sync() integration |
| v0.31.0 | 2025-12-11 | Entity Relationships - GetByHandle() |
| v0.30.0 | 2025-12-11 | Events Expansion - 10 events, Prevent pattern |
| v0.29.0 | 2025-12-10 | Lifetime Scoping - Stale userdata prevention |
| v0.26.0 | 2025-12-10 | Ext.Enums - 14 enum/bitfield types |

---

## Acceleration Strategies

### Component Parity Tools

We've built a **complete automation pipeline** for batch component expansion:

| Tool | Purpose | Output |
|------|---------|--------|
| `tools/extract_typeids.py` | Extract 1,999 TypeId addresses from binary symbols | `generated_typeids.h` |
| `tools/parse_component_headers.py` | Parse 504 property definitions from Windows headers | `generated_property_defs.h` |
| `tools/generate_component_entries.py` | Generate skeleton entries from Ghidra sizes | C struct stubs |
| `ghidra/scripts/batch_extract_component_sizes.py` | Batch ARM64 size extraction via Ghidra | `component_sizes.json` |

**Extraction Pipeline (v0.36.6):**
```
TypeId Extraction → Property Parsing → ARM64 Size Verification → Runtime Registration
     1,999              504                  70                     631 layouts
```

**Coverage Statistics (v0.36.6):**

| Namespace | Available | Generated Layouts | Verified Layouts | Total Layouts |
|-----------|-----------|-------------------|------------------|---------------|
| `eoc::` | 701 | ~350 | ~99 | ~449 |
| `esv::` | 596 | ~50 | ~58 | ~108 |
| `ecl::` | 429 | ~30 | ~19 | ~49 |
| `ls::` | 233 | ~32 | ~60 | ~92 |
| `navcloud::` | 13 | 0 | 9 | 9 |
| **Total** | **1,999** | **462** | **438** | **900** (~45%)

**Ghidra MCP Batch Extraction (Dec 2025):**

438 component sizes verified via Ghidra MCP decompilation using the `ComponentFrameStorageAllocRaw` pattern.
See `agent_docs/acceleration.md` for detailed methodology |

**Batch Expansion Workflow:**
1. **Tag components** (100+ at once): Just need TypeId, no fields
2. **Simple components**: TypeId + Properties from headers, trust Windows sizes
3. **Complex components**: Full Ghidra verification + runtime probing

**Documentation:** See `ghidra/offsets/EXTRACTION_METHODOLOGY.md` for complete workflow

### Issue Acceleration Matrix (Dec 2025 Comprehensive Audit)

**Quick Wins (90%+ acceleration, 1-2 days):**
| Issue | Feature | Acceleration | Key Technique |
|-------|---------|--------------|---------------|
| **#49 Ext.IO** | Path Overrides | ✅ **Complete** | 2 functions, pure C implementation |
| **#47 Ext.Math** | Full Math Library | ✅ **Complete** | 47 functions, pure math, no RE needed |
| **#50 Ext.Timer** | Persistent/Realtime | ✅ **Complete** | 20 functions, full timer system |
| **#46 Context Docs** | API Annotations | ✅ **Complete** | Context column (B/S/C) added to all API tables |

**Core Expansion (60-80% acceleration, 1-2 weeks):**
| Issue | Feature | Acceleration | Key Technique |
|-------|---------|--------------|---------------|
| **#52 Components** | Coverage Expansion | **80%** | Tools ready: `extract_typeids.py` + stubs |
| ~~#48 Ext.Types~~ | Full Reflection | ✅ **DONE** | Port from Windows Types.inl |
| ~~#51 Ext.Events~~ | Engine Events | ✅ **DONE** | Hook game event dispatch |
| ~~#53 Stats Functors~~ | ExecuteFunctors | ✅ **DONE** | Windows code portable |

**Client Features (45-70% acceleration, 2-4 weeks):**
| Issue | Feature | Acceleration | Key Technique |
|-------|---------|--------------|---------------|
| ~~#36~~ | IMGUI | ✅ DONE (v0.36.21) |
| **#42 Debugger** | VS Code DAP | **60%** | DAP reference implementations |
| **#38 Audio** | WWise Audio | **45%** | WWise SDK documented |
| ~~#7 IDE Types~~ | LuaLS Annotations | ✅ **DONE** | GenerateIdeHelpers API |

**Complex Integrations (25-50% acceleration, 4+ weeks):**
| Issue | Feature | Acceleration | Key Technique |
|-------|---------|--------------|---------------|
| **#37 Ext.Level** | Physics/Raycast | **43%** | 9 functions implemented, offsets need runtime verification |
| **#35 Ext.UI** | Noesis UI | **25%** | Deep game UI hooks required |

**Completed:**
| Issue | Feature | Status |
|-------|---------|--------|
| ~~#6~~ | NetChannel API | ✅ DONE (v0.36.31, Phase 4I) |
| ~~#65~~ | Game startup failure | ✅ FIXED (v0.36.33, deferred net init) |
| ~~#66~~ | Osiris call crash + crash diagnostics | ✅ FIXED (v0.36.40, handle encoding + Mach exception handler) |
| ~~#15~~ | Client Lua State | ✅ DONE (v0.36.4) |
| ~~#32~~ | Stats Sync | ✅ DONE |
| ~~#40~~ | StaticData | ✅ DONE (auto-capture) |
| ~~#41~~ | Resource/Template | ✅ DONE |
| ~~#7~~ | IDE Types | ✅ DONE (v0.36.17) |
| ~~#48~~ | Ext.Types | ✅ DONE (v0.36.16) |
| ~~#51~~ | Ext.Events | ✅ DONE (v0.36.11) |
| ~~#53~~ | Stats Functors | ✅ DONE (v0.36.15) |

### ARM64 Hooking Infrastructure (Dec 2025) ✅ RESOLVED

**Issue #44** - [ARM64-Safe Inline Hooking Infrastructure](https://github.com/tdimino/bg3se-macos/issues/44) - **COMPLETE**

Built complete ARM64-safe hooking infrastructure to handle functions with PC-relative instructions:

| Component | Purpose |
|-----------|---------|
| `arm64_decode.h/c` | Full instruction decoder (20+ types, ADRP/LDR/STP/branches) |
| `arm64_hook.h/c` | Skip-and-redirect hooking API |
| `arm64_analyze_prologue()` | Detects ADRP+LDR patterns in function prologues |
| `tools/frida/analyze_prologue.js` | Runtime prologue analyzer for verification |

**Key Discovery (Dec 16, 2025):** FeatManager::GetFeats has **NO ADRP+LDR patterns** - standard Dobby hooks work!

```
FeatManager::GetFeats prologue @ 0x101b752b4:
+00: STP x22, x21, [sp, #-48]!   ← Standard frame setup
+04: STP x20, x19, [sp, #16]     ← No PC-relative instructions
+08: STP x29, x30, [sp, #32]     ← Safe for Dobby
+0C: ADD x29, sp, #32
```

**Result:** Issue #40 (StaticData) is **unblocked** - FeatManager can use standard Dobby hooking.

**Infrastructure Available For:** Future functions that DO have ADRP+LDR patterns will use the skip-and-redirect strategy automatically.

### Prioritized Implementation Order (Dec 2025 Audit)

**Phase 1: Quick Wins (1-2 days each)**

| Order | Issue | Status | Why First |
|-------|-------|--------|-----------|
| 1 | **#49 Ext.IO** | ✅ Complete | 2 functions, pure C implementation |
| 2 | **#47 Ext.Math** | ✅ Complete | 47 functions, pure math, no RE needed |
| 3 | **#50 Ext.Timer** | ✅ Complete | 20 functions, full timer system |
| 4 | **#46 Context Docs** | ✅ Complete | Context annotations added to API docs |

**Phase 2: Core Expansion (1-2 weeks each)**

| Order | Issue | Acceleration | Why This Order |
|-------|-------|--------------|----------------|
| 5 | ~~#48 Ext.Types~~ | ✅ Complete | Unlocks debugger/IDE features |
| 6 | ~~#51 Ext.Events~~ | ✅ Complete | Unlocks stat functors |
| 7 | **#52 Components** | 80% | Accelerated workflow exists |
| 8 | ~~#53 Stats Functors~~ | ✅ Complete | Needs #51 events |

**Phase 3: Client Features (1-3 weeks each)**

| Order | Issue | Acceleration | Why This Order |
|-------|-------|--------------|----------------|
| 9 | ~~#36 Ext.IMGUI~~ | ✅ Complete | All 40 widget types (v0.36.21) |
| 10 | **#38 Ext.Audio** | 76% | 13 functions, VMT indices need verification |
| 11 | **#42 Debugger** | 60% | DAP reference exists |
| 12 | ~~#7 IDE Types~~ | ✅ Complete | GenerateIdeHelpers API |

**Phase 4: Complex Integrations (2-4 weeks each)**

| Order | Issue | Acceleration | Why Last |
|-------|-------|--------------|----------|
| 13 | **#37 Ext.Level** | 43% | 9 functions, needs runtime offset verification |
| 14 | **#35 Ext.UI** | 25% | Deep Noesis hooks |
| 15 | ~~#6 Ext.Net~~ | ⚠️ Phase 1 DONE | Phase 2-3 pending |

**All Quick Wins Complete (as of v0.36.15):**
1. ✅ **#49 Ext.IO** - 4 functions: LoadFile, SaveFile, AddPathOverride, GetPathOverride
2. ✅ **#47 Ext.Math** - 47+ functions including 16 quaternion operations
3. ✅ **#50 Ext.Timer** - 20 functions: core timers, time utilities, persistent timers
4. ✅ **#46 Context Docs** - Context annotations (B/S/C) added to all API tables

**Phase 2 Core Expansion Complete (as of v0.36.16):**
5. ✅ **#48 Ext.Types** - 6 functions: GetAllTypes, GetTypeInfo, GetObjectType, Validate, TypeOf, IsA
6. ✅ **#51 Ext.Events** - 32 engine events with priority/once/prevent patterns
7. ✅ **#53 Stats Functors** - ExecuteFunctor/AfterExecuteFunctor for damage/heal hooks

All Phase 1-2 complete. #36 IMGUI complete (v0.36.21). Next: Component expansion (#52), Debugger (#42).

### Patterns from Windows BG3SE

**Key discoveries from `EntitySystemHelpers.h`:**
- `PerComponentData` struct tracks ComponentIndex, ReplicationIndex, Size, Properties
- `ECSComponentDataMap` provides name→index and index→data mappings
- `GenericPropertyMap` binds component structs to Lua properties
- `BindPropertyMap(ExtComponentType, PropertyMap*)` registers component bindings

**Key pattern from `StaticData.inl`:**
- Template-based `GuidResourceBankHelper<T>` wraps resource banks
- `FOR_EACH_GUID_RESOURCE_TYPE()` macro iterates all resource types
- `GetGuidResource`, `GetAllGuidResources`, `CreateGuidResource` API

### Ghidra MCP Batch Extraction (Dec 2025) ✅ PRODUCTIVE

**Methodology:** Extract ARM64 component sizes from `AddComponent<T>` template functions using Ghidra MCP tools.

**Pattern discovered:**
```c
ComponentFrameStorageAllocRaw((ComponentFrameStorage*)(this_00 + 0x48), SIZE, ...)
                                                                       ^^^^
                                                           Second argument = component size
```

**Tools used:**
- `mcp__ghidra__search_functions_by_name` - Find AddComponent functions with pagination
- `mcp__ghidra__decompile_function` - Extract SIZE parameter from allocation call

**Parallel agent workflow:**
1. Deploy 8-10 Claude subagents processing different offset ranges
2. Each agent searches 50 functions at specified offset (e.g., offset=700, limit=50)
3. Decompile and extract sizes from ComponentFrameStorageAllocRaw calls
4. Consolidate results into modular documentation

**Results:** 1,577 ARM64 components size-verified via Ghidra + 702 Windows estimates = 1,730 total (87% coverage), organized by namespace:
- `COMPONENT_SIZES_EOC_CORE.md` - 52 core eoc:: components
- `COMPONENT_SIZES_EOC_BOOST.md` - 55 boost components
- `COMPONENT_SIZES_EOC_NAMESPACED.md` - 185 sub-namespaced components (56 namespaces)
- `COMPONENT_SIZES_LS.md` - 60 Larian engine components
- `COMPONENT_SIZES_ESV.md` - 58 server components
- `COMPONENT_SIZES_ECL.md` - 19 client components
- `COMPONENT_SIZES_NAVCLOUD.md` - 9 navigation components

**Key discoveries:**
- Largest component: BoostsComponent (832 bytes)
- 28+ OneFrameComponent event types (1-488 bytes)
- Server entities use 8-byte pointers to heap allocations
- Client entities use inline structures

### Ghidra Automation Opportunities

**Scripts to create:**
1. `find_all_component_typeids.py` - Bulk discovery of TypeId addresses
2. `analyze_component_sizes.py` - Detect component struct sizes from allocations
3. `find_resource_managers.py` - Locate `GuidResourceBank` singletons

**Research queries (osgrep on Windows BG3SE):**
```bash
osgrep "how are component properties registered"
osgrep "entity system initialization"
osgrep "prototype manager sync"
```

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
