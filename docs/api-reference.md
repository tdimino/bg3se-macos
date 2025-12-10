# API Reference

Complete documentation for BG3SE-macOS Lua APIs.

## Status Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Fully working |
| ⚠️ | Framework exists, partial implementation |
| ⏳ | Stub only |

---

## Ext Namespace

### Core Functions

| API | Status | Description |
|-----|--------|-------------|
| `Ext.Print(...)` | ✅ | Print to BG3SE log |
| `Ext.GetVersion()` | ✅ | Returns version string |
| `Ext.IsClient()` | ✅ | Returns true |
| `Ext.IsServer()` | ✅ | Returns false |
| `Ext.Require(path)` | ✅ | Load Lua module relative to mod |

### Ext.IO

| API | Status | Description |
|-----|--------|-------------|
| `Ext.IO.LoadFile(path)` | ✅ | Read file contents |
| `Ext.IO.SaveFile(path, content)` | ✅ | Write file contents |

### Ext.Json

| API | Status | Description |
|-----|--------|-------------|
| `Ext.Json.Parse(json)` | ✅ | Parse JSON to Lua table |
| `Ext.Json.Stringify(table)` | ✅ | Convert Lua table to JSON |

---

## Ext.Entity

Entity Component System access for querying game objects.

| API | Status | Description |
|-----|--------|-------------|
| `Ext.Entity.Get(guid)` | ✅ | Look up entity by GUID string |
| `Ext.Entity.IsReady()` | ✅ | Check if entity system ready |
| `entity.Transform` | ✅ | Get transform component (Position, Rotation, Scale) |
| `entity:GetComponent(name)` | ✅ | Get component by name (short or full) |
| `entity:IsAlive()` | ✅ | Check if entity is valid |
| `entity:GetHandle()` | ✅ | Get raw EntityHandle value |

### Debug/Discovery Functions

| API | Status | Description |
|-----|--------|-------------|
| `Ext.Entity.DumpComponentRegistry()` | ✅ | Dump all registered components |
| `Ext.Entity.DumpStorage(handle)` | ✅ | Test TryGet and dump EntityStorageData |
| `Ext.Entity.DiscoverTypeIds()` | ✅ | Discover indices from TypeId globals |
| `Ext.Entity.DumpTypeIds()` | ✅ | Dump all known TypeId addresses |
| `Ext.Entity.RegisterComponent(name, idx, size)` | ✅ | Register discovered component |
| `Ext.Entity.LookupComponent(name)` | ✅ | Look up component info by name |

---

## Ext.Stats

Access to the RPGStats system (weapons, armor, spells, etc.).

| API | Status | Description |
|-----|--------|-------------|
| `Ext.Stats.Get(name)` | ✅ | Get StatsObject by name |
| `Ext.Stats.GetAll(type?)` | ✅ | Get all stat names, optionally by type |
| `Ext.Stats.Create(name, type, template?)` | ✅ | Create new stat object |
| `Ext.Stats.Sync(name)` | ⚠️ | Sync stat changes (framework exists) |
| `Ext.Stats.IsReady()` | ✅ | Check if stats system ready |
| `Ext.Stats.DumpTypes()` | ✅ | Print all stat types to log |

### StatsObject Properties

| Property | Status | Description |
|----------|--------|-------------|
| `stat.Name` | ✅ | Read-only stat name |
| `stat.Type` | ✅ | Read-only stat type |
| `stat.Level` | ✅ | Read-only stat level |
| `stat.Using` | ✅ | Read-only parent stat |
| `stat:GetProperty(name)` | ✅ | Get property value |
| `stat:SetProperty(name, value)` | ✅ | Set property value |
| `stat:Dump()` | ✅ | Print stat contents to log |

**Example:**
```lua
local sword = Ext.Stats.Get("WPN_Longsword")
Ext.Print(sword.Damage)  -- "1d8"
sword.Damage = "2d6"     -- Modify at runtime
```

---

## Ext.Events

Event subscription system for game lifecycle events.

| Event | Status | Description |
|-------|--------|-------------|
| `Ext.Events.SessionLoading` | ✅ | Before save loads |
| `Ext.Events.SessionLoaded` | ✅ | After save loads |
| `Ext.Events.ResetCompleted` | ✅ | After reset command |
| `Ext.Events.Tick` | ✅ | Every game loop (~30hz), provides `e.DeltaTime` |
| `Ext.Events.StatsLoaded` | ✅ | After stats loaded |
| `Ext.Events.ModuleLoadStarted` | ✅ | Before mod scripts load |
| `Ext.Events.GameStateChanged` | ✅ | State transitions (`e.FromState`, `e.ToState`) |
| `Ext.Events.KeyInput` | ✅ | Keyboard input (`e.Key`, `e.Pressed`, `e.Repeat`) |

### Subscribing to Events

```lua
local handlerId = Ext.Events.SessionLoaded:Subscribe(function(e)
    Ext.Print("Save loaded!")
end, {Priority = 100, Once = false})

-- Unsubscribe later
Ext.Events.SessionLoaded:Unsubscribe(handlerId)
```

**Options:**
- `Priority` - Lower numbers run first (default: 100)
- `Once` - Auto-unsubscribe after first call (default: false)

### Convenience Functions

| API | Status | Description |
|-----|--------|-------------|
| `Ext.OnNextTick(callback)` | ✅ | Run callback on next tick (once) |

---

## Ext.Vars (PersistentVars)

File-based persistence for mod data across sessions.

| API | Status | Description |
|-----|--------|-------------|
| `Mods[ModTable].PersistentVars` | ✅ | Per-mod persistent storage table |
| `Ext.Vars.SyncPersistentVars()` | ✅ | Force save all PersistentVars |
| `Ext.Vars.IsPersistentVarsLoaded()` | ✅ | Check if vars loaded |
| `Ext.Vars.ReloadPersistentVars()` | ✅ | Force reload from disk |
| `Ext.Vars.MarkDirty()` | ✅ | Mark for auto-save |

**Storage Location:** `~/Library/Application Support/BG3SE/persistentvars/{ModTable}.json`

**Example:**
```lua
-- In your mod's BootstrapServer.lua
Mods.MyMod.PersistentVars = Mods.MyMod.PersistentVars or {}
Mods.MyMod.PersistentVars.PlayerKills = (Mods.MyMod.PersistentVars.PlayerKills or 0) + 1
Ext.Vars.MarkDirty()  -- Will auto-save
```

---

## Ext.Timer

Timer system for delayed and repeating function calls.

| API | Status | Description |
|-----|--------|-------------|
| `Ext.Timer.WaitFor(delay, callback, [repeat])` | ✅ | Create timer (delay in ms) |
| `Ext.Timer.Cancel(handle)` | ✅ | Cancel a timer |
| `Ext.Timer.Pause(handle)` | ✅ | Pause a timer |
| `Ext.Timer.Resume(handle)` | ✅ | Resume a paused timer |
| `Ext.Timer.IsPaused(handle)` | ✅ | Check if timer is paused |
| `Ext.Timer.MonotonicTime()` | ✅ | Get monotonic clock (ms) |

**Example:**
```lua
-- One-shot timer (5 seconds)
local handle = Ext.Timer.WaitFor(5000, function(h)
    Ext.Print("Timer fired!")
end)

-- Repeating timer (every 1 second)
local repeater = Ext.Timer.WaitFor(1000, function(h)
    Ext.Print("Tick!")
end, 1000)  -- Third arg is repeat interval

-- Cancel it later
Ext.Timer.Cancel(repeater)
```

---

## Ext.Osiris

Interface to the Osiris scripting engine.

| API | Status | Description |
|-----|--------|-------------|
| `Ext.Osiris.RegisterListener(event, arity, timing, callback)` | ✅ | Register Osiris event callback |
| `Ext.Osiris.NewQuery(name, signature, handler)` | ✅ | Register custom query (returns values) |
| `Ext.Osiris.NewCall(name, signature, handler)` | ✅ | Register custom call (no return) |
| `Ext.Osiris.NewEvent(name, signature)` | ✅ | Register custom event |

**Timing values:** `"before"` or `"after"`

**Example - Event Listener:**
```lua
Ext.Osiris.RegisterListener("AutomatedDialogStarted", 2, "after", function(dialog, instanceId)
    Ext.Print("Dialog started: " .. tostring(dialog))
end)
```

**Example - Custom Query:**
```lua
-- Register a custom query with IN and OUT parameters
Ext.Osiris.NewQuery("MyMod_Add", "[in](INTEGER)_A,[in](INTEGER)_B,[out](INTEGER)_Sum",
    function(a, b)
        return a + b
    end)

-- Call via Osi namespace
local result = Osi.MyMod_Add(10, 20)  -- Returns 30
```

**Example - Custom Call:**
```lua
-- Register a custom call (no return value)
Ext.Osiris.NewCall("MyMod_Log", "(STRING)_Message",
    function(msg)
        Ext.Print("Custom: " .. msg)
    end)

-- Call it
Osi.MyMod_Log("Hello from Lua!")
```

**Signature Format:**
- `[in]` - Input parameter (default if omitted)
- `[out]` - Output parameter (for queries)
- Types: `INTEGER`, `INTEGER64`, `REAL`, `STRING`, `GUIDSTRING`
- Example: `"[in](GUIDSTRING)_Target,[out](INTEGER)_Health"`

---

## Ext.Input

Keyboard input capture and injection (macOS CGEventTap).

| API | Status | Description |
|-----|--------|-------------|
| `Ext.Input.RegisterHotkey(key, callback)` | ✅ | Register hotkey handler |
| `Ext.Input.UnregisterHotkey(key)` | ✅ | Remove hotkey handler |
| `Ext.Input.InjectKey(key, pressed)` | ✅ | Simulate key press/release |
| `Ext.Input.IsKeyPressed(key)` | ✅ | Check current key state |

---

## Ext.Math

Vector and matrix operations.

### Vector Types

| Type | Description |
|------|-------------|
| `vec3` | 3D vector (x, y, z) |
| `vec4` | 4D vector (x, y, z, w) |
| `mat3` | 3x3 matrix |
| `mat4` | 4x4 matrix |

### Operations

```lua
local v1 = Ext.Math.vec3(1, 2, 3)
local v2 = Ext.Math.vec3(4, 5, 6)
local sum = v1 + v2
local dot = Ext.Math.Dot(v1, v2)
local cross = Ext.Math.Cross(v1, v2)
local normalized = Ext.Math.Normalize(v1)
```

---

## Ext.Memory (Development)

Low-level memory access for debugging and offset discovery.

| API | Status | Description |
|-----|--------|-------------|
| `Ext.Memory.Read(addr, size)` | ✅ | Read bytes as hex string |
| `Ext.Memory.ReadString(addr, maxLen)` | ✅ | Read null-terminated string |
| `Ext.Memory.Search(pattern, start, size)` | ✅ | Search for byte pattern |
| `Ext.Memory.GetModuleBase(name)` | ✅ | Get base address of loaded module |

---

## Ext.Debug (Development)

Safe memory introspection for offset discovery.

| API | Status | Description |
|-----|--------|-------------|
| `Ext.Debug.ReadPtr(addr)` | ✅ | Read pointer (safe) |
| `Ext.Debug.ReadU32(addr)` | ✅ | Read uint32 |
| `Ext.Debug.ReadI32(addr)` | ✅ | Read int32 |
| `Ext.Debug.ReadU64(addr)` | ✅ | Read uint64 |
| `Ext.Debug.ReadFloat(addr)` | ✅ | Read float |
| `Ext.Debug.ReadString(addr, max)` | ✅ | Read C string |
| `Ext.Debug.ProbeStruct(base, start, end, stride)` | ✅ | Bulk offset discovery |
| `Ext.Debug.HexDump(addr, size)` | ✅ | Hex dump memory |
| `Ext.Debug.FindArrayPattern(base, range)` | ✅ | Find array patterns |

---

## Global Debug Functions

Available in the console for quick debugging:

| Function | Description | Example |
|----------|-------------|---------|
| `_P(...)` | Print (alias for Ext.Print) | `_P("hello")` |
| `_D(obj)` | Dump object as JSON | `_D(Ext.Stats.Get("WPN_Longsword"))` |
| `_DS(obj)` | Dump shallow (depth=1) | `_DS(someTable)` |
| `_H(n)` | Format as hex | `_H(255)` → "0xff" |
| `_PTR(base, off)` | Pointer arithmetic | `_PTR(base, 0x10)` |
| `_PE(...)` | Print error | `_PE("failed!")` |
| `GetHostCharacter()` | Returns main player GUID | |

---

## Osi Namespace

Osiris function bindings. Key functions return real game data discovered by observing Osiris events.

| API | Status | Description |
|-----|--------|-------------|
| `Osi.DB_Players:Get(nil)` | ✅ | Returns real player GUIDs |
| `Osi.IsTagged(char, tag)` | ✅ | Returns true for players in active dialog |
| `Osi.DialogGetNumberOfInvolvedPlayers(id)` | ✅ | Returns 1 (single-player) |
| `Osi.SpeakerGetDialog(char, idx)` | ✅ | Returns current dialog resource |
| `Osi.GetDistanceTo(char1, char2)` | ⏳ | Stub - always returns 0 |
| `Osi.DialogRequestStop(char)` | ⏳ | Stub - no-op |
| `Osi.QRY_StartDialog_Fixed(res, char)` | ⏳ | Stub - returns false |

---

## Console Commands

Register custom console commands (invoked with `!` prefix):

```lua
Ext.RegisterConsoleCommand("mystats", function(cmd, statName)
    local stat = Ext.Stats.Get(statName)
    if stat then
        stat:Dump()
    else
        Ext.Print("Stat not found: " .. tostring(statName))
    end
end)
```

Then use in console:
```
!mystats WPN_Longsword
```

### Built-in Commands

| Command | Description |
|---------|-------------|
| `!help` | List all registered commands |
| `!probe <addr> <range>` | Probe memory structure |
| `!dumpstat <name>` | Dump stat object |
| `!hexdump <addr> <size>` | Hex dump memory |
| `!types` | List registered component types |
