# Changelog

All notable changes to BG3SE-macOS are documented here.

## Format

Each entry includes:
- **Version** - Semantic version (MAJOR.MINOR.PATCH)
- **Date** - Release date
- **Parity** - Feature parity % with Windows BG3SE
- **Category** - Primary area of change
- **Issues** - Related GitHub issues

---

## [v0.32.3] - 2025-12-12

**Parity:** ~55% | **Category:** Testing & Tooling | **Issues:** #8

### Added
- **`!test` console command** - Automated regression test suite (8 tests)
- **`Debug.*` helper library** - Preloaded Lua functions for reverse engineering
  - `Debug.ProbeRefMap(mgr, fs)` - Single-call RefMap lookup
  - `Debug.ProbeStructSpec(base, spec)` - Structured memory probing
  - `Debug.ProbeManager(mgr)` - Prototype manager inspection
  - `Debug.Hex(n)`, `Debug.HexMath(base, offset)` - Hex formatting
- **Script library system** - Reusable Lua scripts in `scripts/library/`
  - `probe_spell_refmap.lua` - SpellPrototypeManager probing
  - `dump_managers.lua` - All prototype manager states
  - `find_physics_scene.lua` - PhysicsScene discovery (Issue #37)
  - `test_audio_init.lua` - Wwise audio testing (Issue #38)
- **Frida scripts** for singleton capture
  - `capture_singletons.js` - Multi-target singleton capture
  - `capture_physics.js` - PhysicsScene capture for Issue #37
- **Meridian persona** - Reverse engineering approach documentation

### Changed
- Console command log now includes `!test`
- Global helpers log now includes `Debug.*`

### Documentation
- `agent_docs/meridian-persona.md` - RE persona with prompt template
- `plans/testing-advanced.md` - Full testing optimization plan
- Updated `tools/frida/README.md` with new scripts

---

## [v0.32.2] - 2025-12-12

**Parity:** ~55% | **Category:** Stats System | **Issues:** #32

### Added
- RefMap linear search implementation (hash function is non-trivial)
- ARM64 const& calling convention documentation

### Fixed
- **SpellPrototype::Init crash** - Fixed by passing FixedString as pointer (const& semantics)
- RefMap lookup now uses linear search after discovering hash function is proprietary

### Changed
- **`Ext.Stats.Sync()` fully working for existing spells** - Modify damage, costs, etc. and sync
- Stats modifications propagate to game prototypes without crashes

### Technical
- RefMap hash function is NOT `key % capacity` - FireBolt at FS=512753744 found in bucket 11798, not expected 7508
- ARM64 `const&` parameters must be passed as pointers: `Init(proto, &fs_key)` not `Init(proto, fs_key)`
- Linear search through ~5000 spell prototypes is sub-millisecond

### Verified Working
```lua
local spell = Ext.Stats.Get("Projectile_FireBolt")
spell.Damage = "3d10"
Ext.Stats.Sync("Projectile_FireBolt")  -- No crash, damage updated
```

---

## [v0.32.1] - 2025-12-12

**Parity:** ~54% | **Category:** Stats System | **Issues:** #32

### Added
- `eoc::SpellPrototype::Init` at `0x101f72754` - Populates prototype from stats object
- RefMap lookup implementation for prototype managers
- `sync_spell_prototype()` now calls SpellPrototype::Init on existing prototypes

### Changed
- **`Ext.Stats.Sync()` now functional for SpellData** - Modified spells re-sync with game
- Stats modifications to existing game spells now propagate to prototypes

### Technical
- Discovered SpellPrototype::Init via XREFs from ParseSpellAnimations
- RefMap structure documented: +0x08 buckets, +0x10 capacity, +0x18 next, +0x28 keys, +0x38 values
- Init function reads FixedString from stats object at offset +0x20

### Limitations
- Newly created (shadow) spells need RefMap insertion (not yet implemented)
- Status/Passive/Interrupt Init functions need discovery for those types

---

## [v0.32.0] - 2025-12-12

**Parity:** ~54% | **Category:** Stats System | **Issues:** #32

### Added
- Prototype managers infrastructure (`src/stats/prototype_managers.c/h`)
- **All 5 prototype manager singletons discovered:**
  - SpellPrototypeManager::m_ptr at `0x1089bac80`
  - StatusPrototypeManager::m_ptr at `0x1089bdb30`
  - PassivePrototypeManager at `0x108aeccd8`
  - InterruptPrototypeManager at `0x108aecce0`
  - BoostPrototypeManager at `0x108991528`
- Debug functions: `Ext.Stats.DumpPrototypeManagers()`, `ProbePrototypeManager()`, `GetPrototypeManagerPtrs()`
- Ghidra scripts: `analyze_get_spell_prototype.py`, `find_status_manager.py`

### Changed
- `Ext.Stats.Sync()` now calls all prototype managers
- Verified 16/21 component property layouts working via entity access

### Technical
- Ghidra offset discovery via ADRP+LDR pattern analysis
- GetSpellPrototype decompilation at `0x10346e740` revealed SpellPrototypeManager
- Ghidra symbol search revealed StatusPrototypeManager
- Runtime verification of manager instance pointers

---

## [v0.31.0] - 2025-12-11

**Parity:** ~53% | **Category:** Entity System | **Issues:** #33

### Added
- `Ext.Entity.GetByHandle()` for handle-based entity lookup
- 8 new component layouts: InventoryOwner, InventoryMember, InventoryIsOwned, Equipable, SpellContainer, Concentration, BoostsContainer, DisplayName

### Changed
- Component count: 28 → 36 layouts

---

## [v0.30.1] - 2025-12-11

**Parity:** ~52% | **Category:** Entity System | **Issues:** #33

### Added
- 9 new component layouts: Background, God, Value, TurnBased, SpellBook, StatusContainer, ActionResources, Weapon, InventoryContainer

### Changed
- Component count: 19 → 28 layouts

---

## [v0.30.0] - 2025-12-11

**Parity:** ~51% | **Category:** Events | **Issues:** #34

### Added
- `DoConsoleCommand` event with Prevent pattern
- `LuaConsoleInput` event with Prevent pattern

### Changed
- Event count: 8 → 10 events
- Documented combat/status events via Osiris listeners

---

## [v0.29.0] - 2025-12-10

**Parity:** ~50% | **Category:** Core | **Issues:** #28

### Added
- Userdata lifetime scoping system (`src/lifetime/lifetime.c/h`)
- LifetimePool (4096 entries) + LifetimeStack (64 nested scopes)

### Changed
- Entities, Components, StatsObjects validate lifetime on every access
- Stale objects show `[EXPIRED]` in `__tostring`

### Fixed
- Prevents use of stale userdata across scope boundaries

---

## [v0.28.0] - 2025-12-10

**Parity:** ~49% | **Category:** Variables

### Added
- `Ext.Vars.GetModVariables(uuid)` for global per-mod data
- Mod variable persistence to `modvars.json`
- Table-like access with iteration support

---

## [v0.27.0] - 2025-12-10

**Parity:** ~48% | **Category:** Variables | **Issues:** #13

### Added
- User variables via `entity.Vars`
- `Ext.Vars.RegisterUserVariable()` with Server/Persistent/SyncOnTick options
- `Ext.Vars.GetEntitiesWithVariable()`
- Persistence to `uservars.json`

---

## [v0.26.0] - 2025-12-10

**Parity:** ~47% | **Category:** Type System | **Issues:** #29

### Added
- `Ext.Enums` namespace with 14 enum/bitfield types
- Enum userdata: Label, Value, EnumName properties
- Bitfield userdata: __Labels, __Value, flag queries, bitwise operators
- Types: DamageType, AbilityId, SkillId, StatusType, SurfaceType, SpellSchoolId, WeaponType, ArmorType, ItemSlot, ItemDataRarity, SpellType, AttributeFlags, WeaponFlags, DamageFlags

---

## [v0.25.0] - 2025-12-10

**Parity:** ~45% | **Category:** Stats System | **Issues:** #27

### Added
- `Ext.Stats.Create(name, type, template)` - Create new stats
- `Ext.Stats.Sync(name)` - Mark stats as synced (placeholder)

---

## [v0.24.0] - 2025-12-10

**Parity:** ~43% | **Category:** Entity System

### Added
- Data-driven component property definitions
- 8 component layouts: Health, BaseHp, Armor, Stats, BaseStats, Transform, Level, Data

---

## [v0.23.0] - 2025-12-10

**Parity:** ~40% | **Category:** Entity/Osiris

### Added
- `entity.Health.Hp/MaxHp/TemporaryHp` property access
- `Ext.Osiris.RaiseEvent()` - Dispatch custom events
- `Ext.Osiris.GetCustomFunctions()` - Debug introspection

### Fixed
- ComponentTypeToIndex hash function (BG3-specific algorithm)

---

## [v0.22.0] - 2025-12-09

**Parity:** ~38% | **Category:** Osiris

### Added
- `Ext.Osiris.NewCall()` - Register custom Osiris calls
- `Ext.Osiris.NewQuery()` - Register custom Osiris queries
- `Ext.Osiris.NewEvent()` - Register custom Osiris events
- Signature parsing for Windows BG3SE format

---

## [v0.21.0] - 2025-12-09

**Parity:** ~36% | **Category:** Entity System

### Added
- `Ext.Entity.GetAllEntitiesWithComponent(name)` - Entity enumeration
- `Ext.Entity.CountEntitiesWithComponent(name)` - Entity counting

---

## [v0.20.0] - 2025-12-08

**Parity:** ~35% | **Category:** Core

### Added
- Structured logging system with 14 modules
- 4 log levels: DEBUG, INFO, WARN, ERROR
- Timestamps and consistent formatting

---

## [v0.19.0] - 2025-12-06

**Parity:** ~33% | **Category:** Console

### Added
- In-game console overlay (NSWindow)
- Tanit symbol with amber glow
- Ctrl+` hotkey toggle
- Command history with up/down arrows

---

## [v0.18.0] - 2025-12-06

**Parity:** ~31% | **Category:** Stats System

### Added
- Stats property write via `__newindex`
- `stat.Damage = "2d6"` modifies stats at runtime

---

## [v0.17.0] - 2025-12-06

**Parity:** ~29% | **Category:** Math

### Added
- `Ext.Math` library with 35 functions
- vec3/vec4/mat3/mat4 operations
- Transforms, decomposition, scalar functions

---

## [v0.16.0] - 2025-12-06

**Parity:** ~27% | **Category:** Input

### Added
- `Ext.Input` API with 8 macOS-specific functions
- CGEventTap keyboard capture
- Hotkey registration and key injection

---

## [v0.15.0] - 2025-12-06

**Parity:** ~25% | **Category:** Console

### Added
- Unix domain socket console (`/tmp/bg3se.sock`)
- Standalone readline client (`bg3se-console`)
- Real-time bidirectional I/O
- Up to 4 concurrent clients

---

## [v0.14.0] - 2025-12-06

**Parity:** ~23% | **Category:** Events

### Added
- `GameStateChanged` event with FromState/ToState
- Game state tracking module
- Event-based state inference for macOS

---

## [v0.13.0] - 2025-12-06

**Parity:** ~21% | **Category:** Events

### Added
- `Tick` event with DeltaTime
- `StatsLoaded` event
- `ModuleLoadStarted` event
- Priority ordering, Once flag, handler IDs
- `Ext.OnNextTick()` helper

---

## [v0.12.0] - 2025-12-06

**Parity:** ~19% | **Category:** Variables

### Added
- PersistentVars (file-based persistence)
- `Ext.Vars.SyncPersistentVars()`
- Auto-save every 30 seconds
- Per-mod isolation via ModTable

---

## [v0.11.0] - 2025-12-05

**Parity:** ~17% | **Category:** Timer/Debug/Stats

### Added
- `Ext.Timer` API: WaitFor, Cancel, Pause, Resume
- `Ext.Debug` APIs: ReadPtr, ProbeStruct, HexDump
- Stats property read via IndexedProperties + FixedStrings
- `RPGSTATS_OFFSET_FIXEDSTRINGS = 0x348`

---

## [v0.10.6] - 2025-12-03

**Parity:** ~15% | **Category:** Osiris

### Fixed
- Osiris function name caching via Signature indirection
- OsiFunctionDef structure (+0x08 is Line, not Name)

---

## [v0.10.4] - 2025-12-02

**Parity:** ~14% | **Category:** Entity System

### Added
- TypeId<T>::m_TypeIndex discovery
- ComponentTypeToIndex enumeration
- Lua bindings for runtime TypeId discovery

---

## [v0.10.3] - 2025-12-01

**Parity:** ~13% | **Category:** Entity System

### Added
- Data structure traversal for GetComponent
- TryGet + HashMap traversal (macOS-specific)

### Technical
- Discovered template calls don't work on macOS ARM64

---

## [v0.10.2] - 2025-12-01

**Parity:** ~12% | **Category:** Entity System

### Fixed
- GUID byte order (hi/lo swapped)
- Entity lookup now working

---

## [v0.10.1] - 2025-11-29

**Parity:** ~11% | **Category:** Osiris

### Added
- Function type detection (Query/Call/Event dispatch)
- 40+ pre-populated common functions

---

## [v0.10.0] - 2025-11-29

**Parity:** ~10% | **Category:** Entity System

### Added
- EntityWorld capture via LEGACY_IsInCombat hook
- GUID → EntityHandle lookup
- `Ext.Entity.Get()`, `IsReady()`, `GetHandle()`, `IsAlive()`

---

## [v0.9.9] - 2025-11-28

**Parity:** ~8% | **Category:** Osiris

### Added
- Dynamic `Osi.*` metatable
- Lazy function lookup via `__index`

---

## [v0.9.5] - 2025-11-28

**Parity:** ~6% | **Category:** Core

### Added
- Stable event observation
- MRC (More Reactive Companions) mod support

---

## [v0.9.0] - 2025-11-27

**Parity:** ~5% | **Category:** Core

### Added
- Initial Lua 5.4 runtime
- Basic `Ext.*` API structure
- DYLD injection working

---

## Legend

| Category | Description |
|----------|-------------|
| Core | Injection, logging, memory safety |
| Osiris | Osi.* namespace, event listeners |
| Entity System | Ext.Entity, components |
| Stats System | Ext.Stats, property access |
| Events | Ext.Events subscriptions |
| Variables | PersistentVars, User/Mod variables |
| Timer | Ext.Timer scheduling |
| Console | Debug console (socket/file/overlay) |
| Input | Ext.Input keyboard capture |
| Math | Ext.Math vector/matrix ops |
| Type System | Ext.Enums, type definitions |
