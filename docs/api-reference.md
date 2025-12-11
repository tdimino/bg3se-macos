# API Reference

Complete documentation for BG3SE-macOS Lua APIs.

## Status Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Fully working |
| ⚠️ | Framework exists, partial implementation |
| ⏳ | Stub only |

---

## Userdata Lifetime Scoping

BG3SE-macOS implements lifetime scoping for userdata objects (Entities, Components, StatsObjects). This prevents accessing stale objects that may have been destroyed or modified by the game engine.

### How It Works

Each console command or Lua callback runs in its own **lifetime scope**. Objects created within a scope are valid only for that scope's duration. When the scope ends, all objects created in it become **expired**.

```lua
-- Scope 1: First console command
local entity = Ext.Entity.Get(GetHostCharacter())
stored = entity  -- Store for later (BAD PRACTICE)

-- Scope 2: Second console command
_P(stored)              -- Shows: Entity(0x...) [EXPIRED]
stored.Health.Hp        -- ERROR: "Lifetime of Entity has expired"

-- Correct usage: Re-fetch in each scope
local entity = Ext.Entity.Get(GetHostCharacter())
_P(entity.Health.Hp)    -- Works!
```

### Affected Types

| Type | Description |
|------|-------------|
| Entity | From `Ext.Entity.Get()` |
| Component | From `entity.Health`, `entity:GetComponent()`, etc. |
| StatsObject | From `Ext.Stats.Get()` |

### Detecting Expired Objects

- `tostring(obj)` shows `[EXPIRED]` suffix for expired objects
- Property access on expired objects throws a clear error message
- The error message instructs you to re-fetch the object

### Best Practices

1. **Don't store userdata** in global tables for later use
2. **Re-fetch objects** at the start of each callback or command
3. **Complete work within one scope** when possible

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

### Component Property Access

Components with property layouts return proxy userdata that supports direct property access and iteration with `pairs()`.

#### Health Component

| Property | Type | Description |
|----------|------|-------------|
| `entity.Health.Hp` | int32 | Current HP |
| `entity.Health.MaxHp` | int32 | Maximum HP |
| `entity.Health.TemporaryHp` | int32 | Temporary HP |
| `entity.Health.MaxTemporaryHp` | int32 | Max temporary HP |
| `entity.Health.IsInvulnerable` | bool | Invulnerability flag |

#### BaseHp Component

| Property | Type | Description |
|----------|------|-------------|
| `entity.BaseHp.Vitality` | int32 | Base vitality value |
| `entity.BaseHp.VitalityBoost` | int32 | Vitality boost modifier |

#### Stats Component

| Property | Type | Description |
|----------|------|-------------|
| `entity.Stats.InitiativeBonus` | int32 | Initiative modifier |
| `entity.Stats.Abilities` | int32[7] | Array: STR, DEX, CON, INT, WIS, CHA, unused |
| `entity.Stats.AbilityModifiers` | int32[7] | Computed ability modifiers |
| `entity.Stats.Skills` | int32[18] | All skill values |
| `entity.Stats.ProficiencyBonus` | int32 | Proficiency bonus |
| `entity.Stats.SpellCastingAbility` | uint8 | Primary casting ability |

#### Level Component

| Property | Type | Description |
|----------|------|-------------|
| `entity.Level.LevelHandle` | EntityHandle | Handle to level entity (hex string) |
| `entity.Level.LevelName` | FixedString | Level name index (raw uint32) |

#### Data Component

| Property | Type | Description |
|----------|------|-------------|
| `entity.Data.Weight` | int32 | Entity weight (in game units) |
| `entity.Data.StatsId` | FixedString | Stats ID index (raw uint32) |
| `entity.Data.StepsType` | uint32 | Steps type value |

#### Transform Component

| Property | Type | Description |
|----------|------|-------------|
| `entity.Transform.Position` | table | {x, y, z} world position |
| `entity.Transform.Rotation` | table | {x, y, z, w} quaternion rotation |
| `entity.Transform.Scale` | table | {x, y, z} scale factors |

**Example:**
```lua
local entity = Ext.Entity.Get(GetHostCharacter())
if entity then
    -- Health
    _P("HP: " .. entity.Health.Hp .. "/" .. entity.Health.MaxHp)

    -- Stats
    _P("Proficiency: " .. entity.Stats.ProficiencyBonus)

    -- Level
    _P("Level Handle: " .. entity.Level.LevelHandle)

    -- Data
    _P("Weight: " .. entity.Data.Weight)

    -- Iterate all properties on a component
    for k, v in pairs(entity.Stats) do
        _P(k .. " = " .. tostring(v))
    end
end
```

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
| `Ext.Stats.Create(name, type, template?)` | ✅ | Create new stat object at runtime |
| `Ext.Stats.Sync(name)` | ⚠️ | Mark stat as synced (prototype manager sync pending) |
| `Ext.Stats.IsReady()` | ✅ | Check if stats system ready |
| `Ext.Stats.DumpTypes()` | ✅ | Print all stat types to log |

### Ext.Stats.Create

Creates a new stat object at runtime. The stat is stored in a shadow registry and accessible via `Ext.Stats.Get()`.

**Parameters:**
- `name` (string) - Unique name for the new stat
- `type` (string) - Stat type: "Weapon", "Armor", "SpellData", "StatusData", "PassiveData", etc.
- `template` (string, optional) - Existing stat to copy properties from

**Returns:** StatsObject or nil (if name exists, type invalid, or system not ready)

**Example:**
```lua
-- Create a new weapon from scratch
local sword = Ext.Stats.Create("MyMod_CustomSword", "Weapon")
sword.Damage = "2d8"
sword.DamageType = "Slashing"

-- Create based on existing stat
local betterSword = Ext.Stats.Create("MyMod_BetterSword", "Weapon", "WPN_Longsword")
betterSword.Damage = "3d8"  -- Override template value

-- Call Sync when done modifying
Ext.Stats.Sync("MyMod_CustomSword")
```

**Note:** Created stats exist in memory and support property read/write. Prototype manager sync (for game to use stats in spawning/casting) is pending implementation.

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

## Ext.Enums

Type-safe enum and bitfield access matching Windows BG3SE behavior.

### Enum Access

```lua
-- Access enum values via Ext.Enums.<EnumName>.<Label>
local dt = Ext.Enums.DamageType.Fire
_P(dt.Label)      -- "Fire"
_P(dt.Value)      -- 7
_P(dt.EnumName)   -- "DamageType"

-- Flexible comparison
dt == "Fire"      -- true (label match)
dt == 7           -- true (value match)
dt == Ext.Enums.DamageType.Fire  -- true
```

### Bitfield Access

```lua
-- Access bitfield values
local bf = Ext.Enums.AttributeFlags.Backstab
_P(bf.__Labels)   -- {"Backstab"}
_P(bf.__Value)    -- 65536

-- Query individual flags
bf.Backstab       -- true
bf.Torch          -- false

-- Bitwise operations
local combined = bf | Ext.Enums.AttributeFlags.Torch
_P(#combined)     -- 2 (popcount)
_P(tostring(combined))  -- "Backstab, Torch"
```

### Available Enums

| Enum | Type | Description |
|------|------|-------------|
| `DamageType` | Enum | None, Slashing, Piercing, Bludgeoning, Acid, Thunder, Necrotic, Fire, Lightning, Cold, Psychic, Poison, Radiant, Force |
| `AbilityId` | Enum | None, Strength, Dexterity, Constitution, Intelligence, Wisdom, Charisma |
| `SkillId` | Enum | Deception, Intimidation, Performance, Persuasion, Acrobatics, SleightOfHand, Stealth, Arcana, History, Investigation, Nature, Religion, Athletics, AnimalHandling, Insight, Medicine, Perception, Survival |
| `StatusType` | Enum | DYING, HEAL, KNOCKED_DOWN, BOOST, FEAR, INVISIBLE, INCAPACITATED, POLYMORPHED, DOWNED, etc. |
| `SurfaceType` | Enum | None, Water, WaterElectrified, WaterFrozen, Blood, Poison, Oil, Lava, Fire, Acid, etc. |
| `SpellSchoolId` | Enum | None, Abjuration, Conjuration, Divination, Enchantment, Evocation, Illusion, Necromancy, Transmutation |
| `WeaponType` | Enum | None, Sword, Club, Axe, Staff, Bow, Crossbow, Spear, Knife, Wand, Arrow, Rifle |
| `ArmorType` | Enum | None, Cloth, Padded, Leather, StuddedLeather, Hide, ChainShirt, ScaleMail, BreastPlate, HalfPlate, RingMail, ChainMail, Splint, Plate |
| `ItemSlot` | Enum | Helmet, Breast, Cloak, MeleeMainHand, MeleeOffHand, RangedMainHand, RangedOffHand, Ring, Boots, Gloves, Amulet, etc. |
| `ItemDataRarity` | Enum | Common, Unique, Uncommon, Rare, Epic, Legendary, Divine |
| `SpellType` | Enum | None, Zone, MultiStrike, Projectile, ProjectileStrike, Rush, Shout, Storm, Target, Teleportation, Wall, Throw |
| `AttributeFlags` | Bitfield | SlippingImmunity, Torch, Arrow, Unbreakable, Grounded, Floating, ThrownImmunity, InvisibilityImmunity, Backstab, BackstabImmunity, etc. |
| `WeaponFlags` | Bitfield | Light, Ammunition, Finesse, Heavy, Loading, Range, Reach, Thrown, Twohanded, Versatile, Melee, Magical, etc. |
| `DamageFlags` | Bitfield | Hit, Dodge, Miss, Critical, Backstab, Invisible, Magical, Invulnerable, SavingThrow, KillingBlow, etc. |

---

## Ext.Events

Event subscription system for game lifecycle events.

| Event | Status | Event Data | Description |
|-------|--------|------------|-------------|
| `Ext.Events.SessionLoading` | ✅ | {} | Before save loads |
| `Ext.Events.SessionLoaded` | ✅ | {} | After save loads |
| `Ext.Events.ResetCompleted` | ✅ | {} | After reset command |
| `Ext.Events.Tick` | ✅ | {DeltaTime} | Every game loop (~30hz) |
| `Ext.Events.StatsLoaded` | ✅ | {} | After stats loaded |
| `Ext.Events.ModuleLoadStarted` | ✅ | {} | Before mod scripts load |
| `Ext.Events.GameStateChanged` | ✅ | {FromState, ToState} | State transitions |
| `Ext.Events.KeyInput` | ✅ | {Key, Pressed, Modifiers, Character} | Keyboard input |
| `Ext.Events.DoConsoleCommand` | ✅ | {Command, Prevent} | Console `!` command interception |
| `Ext.Events.LuaConsoleInput` | ✅ | {Input, Prevent} | Raw Lua console input interception |

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

### Preventable Events

Some events support the `Prevent` pattern, allowing handlers to stop the default action:

```lua
-- Intercept console commands
Ext.Events.DoConsoleCommand:Subscribe(function(e)
    Ext.Print("Command: " .. e.Command)
    if e.Command == "!secret" then
        Ext.Print("Access denied!")
        e.Prevent = true  -- Stop command execution
    end
end)

-- Intercept raw Lua input
Ext.Events.LuaConsoleInput:Subscribe(function(e)
    Ext.Print("Lua input received: " .. #e.Input .. " chars")
    -- e.Prevent = true would skip execution
end)
```

### Combat & Status Events via Osiris

Combat and status events are available through `Ext.Osiris.RegisterListener`. These fire from the Osiris scripting engine and provide comprehensive coverage for combat mechanics:

**Combat Events:**
```lua
-- Turn started (fires when a character's turn begins)
Ext.Osiris.RegisterListener("TurnStarted", 1, "after", function(charGuid)
    Ext.Print("Turn started for: " .. charGuid)
end)

-- Turn ended
Ext.Osiris.RegisterListener("TurnEnded", 1, "after", function(charGuid)
    Ext.Print("Turn ended for: " .. charGuid)
end)

-- Combat started/ended
Ext.Osiris.RegisterListener("EnteredCombat", 2, "after", function(charGuid, combatGuid)
    Ext.Print("Entered combat: " .. charGuid)
end)

Ext.Osiris.RegisterListener("LeftCombat", 2, "after", function(charGuid, combatGuid)
    Ext.Print("Left combat: " .. charGuid)
end)

-- Combat round events
Ext.Osiris.RegisterListener("CombatRoundStarted", 2, "after", function(combatGuid, round)
    Ext.Print("Round " .. round .. " started")
end)
```

**Status Events:**
```lua
-- Status applied
Ext.Osiris.RegisterListener("StatusApplied", 4, "after", function(target, status, causee, storyActionID)
    Ext.Print("Status " .. status .. " applied to " .. target)
end)

-- Status removed
Ext.Osiris.RegisterListener("StatusRemoved", 4, "after", function(target, status, causee, storyActionID)
    Ext.Print("Status " .. status .. " removed from " .. target)
end)
```

**Attack Events:**
```lua
-- Attack of opportunity
Ext.Osiris.RegisterListener("AttackedByObject", 3, "after", function(defender, attackerOwner, attacker)
    Ext.Print(defender .. " attacked by " .. attacker)
end)
```

**Rest Events:**
```lua
-- Short rest
Ext.Osiris.RegisterListener("ShortRested", 1, "after", function(charGuid)
    Ext.Print(charGuid .. " short rested")
end)

-- Long rest
Ext.Osiris.RegisterListener("LongRestStarted", 0, "after", function()
    Ext.Print("Long rest started")
end)

Ext.Osiris.RegisterListener("LongRestFinished", 0, "after", function()
    Ext.Print("Long rest finished")
end)
```

### Convenience Functions

| API | Status | Description |
|-----|--------|-------------|
| `Ext.OnNextTick(callback)` | ✅ | Run callback on next tick (once) |

---

## Ext.Vars

Variable persistence system with support for both mod-level storage and entity-attached data.

### PersistentVars (Mod-Level)

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

### User Variables (Entity-Attached)

Attach custom data to game entities with automatic persistence.

| API | Status | Description |
|-----|--------|-------------|
| `Ext.Vars.RegisterUserVariable(name, opts)` | ✅ | Register a variable prototype |
| `Ext.Vars.GetEntitiesWithVariable(name)` | ✅ | Get all entities with a variable |
| `Ext.Vars.SyncUserVariables()` | ✅ | Force save user variables |
| `Ext.Vars.DirtyUserVariables([guid], [key])` | ✅ | Mark variables as dirty |
| `entity.Vars.VarName` | ✅ | Get/set entity variable |

**Registration Options:**
| Option | Default | Description |
|--------|---------|-------------|
| `Server` | true | Available on server |
| `Client` | false | Available on client |
| `Persistent` | true | Save to disk |
| `WriteableOnServer` | true | Can modify on server |
| `WriteableOnClient` | false | Can modify on client |
| `SyncToClient` | false | Sync server→client |
| `SyncToServer` | false | Sync client→server |
| `SyncOnTick` | true | Batch sync per tick |
| `SyncOnWrite` | false | Sync immediately on write |

**Storage Location:** `~/Library/Application Support/BG3SE/uservars.json`

**Example:**
```lua
-- Register variable (in BootstrapServer.lua)
Ext.Vars.RegisterUserVariable("MyMod_CustomHP", {
    Server = true,
    Persistent = true
})

-- Set variable on entity
local entity = Ext.Entity.Get(GetHostCharacter())
entity.Vars.MyMod_CustomHP = { bonus = 50, temp = 10 }

-- Read variable
local hp = entity.Vars.MyMod_CustomHP
if hp then
    Ext.Print("Bonus HP: " .. hp.bonus)
end

-- Find all entities with variable
local entities = Ext.Vars.GetEntitiesWithVariable("MyMod_CustomHP")
for _, guid in ipairs(entities) do
    Ext.Print("Entity: " .. guid)
end
```

### Mod Variables (Global Per-Mod)

Store global mod data not attached to any specific entity. Ideal for settings, counters, and mod state.

| API | Status | Description |
|-----|--------|-------------|
| `Ext.Vars.RegisterModVariable(uuid, name, opts)` | ✅ | Register a mod variable prototype |
| `Ext.Vars.GetModVariables(uuid)` | ✅ | Get mod variable proxy |
| `Ext.Vars.SyncModVariables()` | ✅ | Force save mod variables |
| `Ext.Vars.DirtyModVariables([uuid], [key])` | ✅ | Mark variables as dirty |

**Storage Location:** `~/Library/Application Support/BG3SE/modvars.json`

**Example:**
```lua
-- Get mod variables proxy (auto-creates if needed)
local mv = Ext.Vars.GetModVariables("my-mod-uuid")

-- Set values (table-like access)
mv.Counter = 42
mv.Settings = { volume = 0.8, difficulty = "Hard" }
mv.Active = true

-- Read values
Ext.Print("Counter: " .. mv.Counter)
Ext.Print("Volume: " .. mv.Settings.volume)

-- Iterate all variables
for key, value in pairs(mv) do
    Ext.Print(key .. " = " .. tostring(value))
end

-- Optional: explicit registration with options
Ext.Vars.RegisterModVariable("my-mod-uuid", "Settings", {
    Server = true,
    Persistent = true
})

-- Force save
Ext.Vars.SyncModVariables()
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
| `Ext.Osiris.RaiseEvent(name, ...)` | ✅ | Raise a custom event to dispatch to listeners |
| `Ext.Osiris.GetCustomFunctions()` | ✅ | Get table of all registered custom functions (debug) |

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

**Example - Custom Event with RaiseEvent:**
```lua
-- Register a custom event
Ext.Osiris.NewEvent("MyMod_ItemCollected", "(GUIDSTRING)_Item,(GUIDSTRING)_Collector")

-- Register a listener for the event
Ext.Osiris.RegisterListener("MyMod_ItemCollected", 2, "after", function(item, collector)
    Ext.Print("Item " .. item .. " collected by " .. collector)
end)

-- Raise the event from Lua (dispatches to all listeners)
local itemGuid = "ITEM_Gold_123"
local playerGuid = "S_PLA_Gale_..."
local numListenersCalled = Ext.Osiris.RaiseEvent("MyMod_ItemCollected", itemGuid, playerGuid)
```

**Example - Debug Custom Functions:**
```lua
-- List all registered custom functions
for name, info in pairs(Ext.Osiris.GetCustomFunctions()) do
    Ext.Print(name .. " (" .. info.Type .. ") - " .. info.Arity .. " params")
end
```

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
