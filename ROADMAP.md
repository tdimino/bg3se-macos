# BG3SE-macOS Roadmap

This document tracks the development roadmap for achieving feature parity with Windows BG3SE (Norbyte's Script Extender).

## Current Status: v0.19.0

**Overall Feature Parity: ~55%** (based on [comprehensive gap analysis](plans/bg3se-docs-gap-analysis.md))

**Working Features:**
- DYLD injection and Dobby hooking infrastructure
- Osiris event observation (2000+ events captured per session)
- Lua runtime with mod loading (BootstrapServer.lua)
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
- **TypeId Discovery** - 11 component TypeIds discovered at SessionLoaded with deferred retry
- **Safe Memory APIs** - Crash-safe memory reading via mach_vm_read
- **Function Name Caching** - OsiFunctionDef->Signature->Name two-level indirection (v0.10.6)
- **Ext.Stats API** - RPGStats::m_ptr discovery, stats_manager module, Lua bindings (v0.11.0)

---

## Feature Parity Matrix

| Namespace | Windows BG3SE | bg3se-macos | Parity | Phase |
|-----------|---------------|-------------|--------|-------|
| `Osi.*` | ✅ Full | ✅ Dynamic metatable | **95%** | 1 |
| `Ext.Osiris` | ✅ Full | ✅ RegisterListener | **90%** | 1 |
| `Ext.Json` | ✅ Full | ✅ Parse, Stringify | **90%** | 1 |
| `Ext.IO` | ✅ Full | ✅ LoadFile, SaveFile | **80%** | 1 |
| `Ext.Entity` | ✅ Full | ⚠️ Basic access | **40%** | 2 |
| `Ext.Stats` | ✅ Full | ✅ Read/Write complete (`stat.Damage = "2d6"`) | **95%** | 3 |
| `Ext.Events` | ✅ Full | ✅ 7 events + advanced features | **75%** | 2.5 |
| `Ext.Timer` | ✅ Full | ✅ Complete | **100%** | 2.3 |
| `Ext.Debug` | ✅ Full | ✅ Complete | **100%** | 2.3 |
| `Ext.Vars` | ✅ Full | ⚠️ PersistentVars only | **25%** | 2.6 |
| `Ext.Net` | ✅ Full | ❌ Not impl | **0%** | 6 |
| `Ext.UI` | ✅ Full | ❌ Not impl | **0%** | 8 |
| `Ext.Math` | ✅ Full | ✅ Complete | **95%** | 7.5 |
| `Ext.Input` | ✅ Full | ✅ CGEventTap capture, hotkeys | **85%** | 9 |
| `Ext.Level` | ✅ Full | ❌ Not impl | **0%** | 9 |
| Console/REPL | ✅ Full | ✅ Socket + file + in-game overlay | **95%** | 5 |
| PersistentVars | ✅ Full | ✅ File-based | **90%** | 2.4 |
| Client Lua State | ✅ Full | ❌ Not impl | **0%** | 2.7 |

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
**Status:** 🔄 In Progress (TypeId discovery complete, property access needed)

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

**Pending (from API.md):**
- [ ] `entity:GetAllComponents()` - Return all attached components
- [ ] `entity:GetAllComponentNames()` - List all component type names
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
**Status:** ✅ Complete (v0.14.0) - 7 events including GameStateChanged, advanced subscription system

From API.md: "Subscribing to engine events can be done through the `Ext.Events` table."

**Implemented API (v0.14.0):**
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
```

**Available Events (from API.md):**
| Event | When | Status |
|-------|------|--------|
| `SessionLoading` | Session setup started | ✅ Implemented |
| `SessionLoaded` | Session ready | ✅ Implemented |
| `ResetCompleted` | After `reset` command | ✅ Implemented |
| `Tick` | Every game loop (~30hz) | ✅ Implemented (v0.13.0) |
| `StatsLoaded` | After stats entries loaded | ✅ Implemented (v0.13.0) |
| `ModuleLoadStarted` | Before mod scripts load | ✅ Implemented (v0.13.0) |
| `GameStateChanged` | State transitions (load, run, etc.) | ✅ Implemented (v0.14.0) |

**Advanced Features (v0.14.0):**
- Priority-based handler ordering (lower = called first)
- Once flag for auto-unsubscription
- Handler ID return for explicit unsubscription
- Deferred modifications during dispatch (prevents iterator corruption)
- Protected calls to prevent cascade failures
- `!events` console command to inspect handler counts
- GameStateChanged fires on initial load and save reloads

### 2.6 User & Mod Variables
**Status:** ❌ Not Started - **CRITICAL**

From API.md: "v10 adds support for attaching custom properties to entities."

**Target API:**
```lua
-- Registration (in BootstrapServer/Client.lua)
Ext.Vars.RegisterUserVariable("NRD_MyVar", {
    Server = true,
    Client = true,
    SyncToClient = true,
    Persistent = true,       -- Save to savegame
    SyncOnTick = true        -- Batch sync (default)
})

-- Usage
entity.Vars.NRD_MyVar = { health = 100, mana = 50 }
local data = entity.Vars.NRD_MyVar

-- Manual sync
Ext.Vars.SyncUserVariables()

-- Mod-level variables
Ext.Vars.RegisterModVariable(ModuleUUID, "GlobalState", { ... })
local vars = Ext.Vars.GetModVariables(ModuleUUID)
```

**Impact:** Without this, mods cannot attach custom data to entities with automatic sync/persistence.

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
**Status:** ❌ Not Started - **HIGH**

From API.md: "Most `userdata` types are now bound to their enclosing *extender scope*."

**Current State:** Objects live forever (memory leak risk)

**Target Behavior:**
```lua
-- BAD: Smuggling objects outside scope
local spellbook = Ext.Entity.Get(...).SpellBook
Ext.OnNextTick(function()
    -- Should THROW: "lifetime has expired"
    local uuid = spellbook.Spells[2].SpellUUID
end)

-- GOOD: Fetch fresh reference in each scope
Ext.OnNextTick(function()
    local spellbook = Ext.Entity.Get(...).SpellBook
    local uuid = spellbook.Spells[2].SpellUUID
end)
```

**Impact:** Memory leaks, potential crashes from accessing deleted entities.

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
**Status:** ❌ Not Started

From API.md: "Enum values returned from functions are `userdata` values instead of `string`."

**Target API:**
```lua
local bt = entity.CurrentTemplate.BloodSurfaceType
bt.Label      -- "Blood"
bt.Value      -- 16
bt.EnumName   -- "SurfaceType"

-- Comparison
bt == "Blood"  -- true (label)
bt == 16       -- true (value)
bt == Ext.Enums.SurfaceType.Blood  -- true

-- JSON serialization
Ext.Json.Stringify(bt)  -- "Blood"
```

### 7.2 Bitfield Objects
**Status:** ❌ Not Started

```lua
local af = entity.Stats.AttributeFlags
af.__Labels    -- {"SuffocatingImmunity", "BleedingImmunity", ...}
af.__Value     -- 137440004096
af.__EnumName  -- "StatAttributeFlags"

-- Query flags
af.DrunkImmunity  -- true/false

-- Bitwise operators
~af                    -- Negate
af | "FreezeImmunity"  -- OR
af & {"DrunkImmunity"} -- AND

-- Assignment
entity.Stats.AttributeFlags = af | "WebImmunity"
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
- [ ] Userdata lifetime scoping

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
| A4 | Component Property Access | High | 🔄 In Progress |
| A5 | NetChannel API | High | ❌ Not Started |
| A6 | User Variables | High | ❌ Not Started |

### Priority B: High Impact (Breaks Many Mods)

| ID | Feature | Effort | Status |
|----|---------|--------|--------|
| B1 | Client Lua State | High | ❌ Not Started |
| B2 | Timer API | Low | ✅ Complete |
| B3 | Console/REPL | Medium | ✅ Complete (socket + file + in-game overlay) |
| B4 | GetAllComponents | Low | ❌ Not Started |
| B5 | Stats Create/Sync | Medium | ❌ Not Started |
| B6 | Userdata Lifetime Scoping | Medium | ❌ Not Started |

### Priority C: Medium Impact (Developer Experience)

| ID | Feature | Effort | Status |
|----|---------|--------|--------|
| C1 | Ext.Math Library | Medium | ✅ Complete |
| C2 | Enum/Bitfield Objects | Medium | ❌ Not Started |
| C3 | Console Commands | Low | ✅ Complete |
| C6 | Ext.Debug APIs | Low | ✅ Complete |
| C4 | Mod Variables | Medium | ❌ Not Started |
| C5 | More Component Types | High | 🔄 Ongoing |

### Priority D: Nice-to-Have

| ID | Feature | Effort | Status |
|----|---------|--------|--------|
| D1 | Noesis UI | High | ❌ Not Started |
| D2 | IMGUI | High | ❌ Not Started |
| D3 | Input Injection | Medium | ❌ Not Started |
| D4 | Physics Queries | Medium | ❌ Not Started |
| D5 | Virtual Textures | Medium | ❌ Not Started |
| D6 | Debugger Support | High | ❌ Not Started |

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
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
