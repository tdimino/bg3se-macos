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

## [v0.34.2] - 2025-12-20

**Parity:** ~68% | **Category:** StaticData | **Issues:** #40

### Fixed
- **Ext.StaticData.GetAll() now returns all entries** - Previously returned only 1 item, now correctly returns all feats (41 entries)
  - Root cause: `probe_for_real_manager()` searched within TypeContext metadata for wrong pattern
  - Fix: Rely on GetFeats hook to capture real FeatManager with correct structure
  - Real FeatManager uses flat array at +0x80 with count at +0x7C

### Technical
- Removed faulty probing logic from `capture_managers_via_typecontext()`
- TypeContext metadata provides type registration, not data access
- Real manager captured via hook when feat window is accessed
- Verified: GetAll, GetCount, and Get by GUID all working correctly

---

## [v0.34.1] - 2025-12-17

**Parity:** ~68% | **Category:** StaticData | **Issues:** #40

### Added
- **Auto-capture for Ext.StaticData** - Eliminates Frida requirement for basic StaticData access
  - `staticdata_post_init_capture()` - Automatic manager discovery at SessionLoaded
  - TypeContext traversal finds managers by name in ImmutableDataHeadmaster linked list
  - Real manager probing validates metadata pointers at multiple offsets
  - Frida capture as fallback if auto-capture fails
- **Ext.StaticData.TriggerCapture()** - Manual capture trigger for debugging

### Changed
- `Ext.StaticData.GetAll("Feat")` now works at main menu without Frida
- Post-init capture runs automatically after SessionLoaded event

### Technical
- Generic `looks_like_real_manager()` validates any manager type using ManagerConfig
- Generic `probe_for_real_manager()` searches metadata at offsets 0x08-0x78
- Safe memory reads via mach_vm_read prevent crashes on invalid pointers
- 3-phase capture: TypeContext → Probe metadata → Frida fallback

---

## [v0.34.0] - 2025-12-16

**Parity:** ~67% | **Category:** Hooks, StaticData | **Issues:** #44, #40

### Added
- **ARM64 Safe Hooking Infrastructure** - Complete skip-and-redirect hooking system for functions with ADRP+LDR prologues
  - `arm64_decode.h/c` - Full ARM64 instruction decoder with 20+ instruction types
  - `arm64_hook.h/c` - Safe hooking API: `arm64_safe_hook()`, `arm64_hook_at_offset()`, `arm64_unhook()`
  - `arm64_analyze_prologue()` - Detects PC-relative instruction patterns
  - Trampoline allocation within ±128MB for relative branches
- **Frida prologue analyzer** - `tools/frida/analyze_prologue.js` for runtime verification
- **ARM64_SAFE_HOOKING.md** - Comprehensive implementation documentation

### Changed
- **FeatManager::GetFeats now uses standard Dobby hook** - Frida analysis confirmed NO ADRP+LDR patterns in prologue
- `staticdata_manager.c` - Falls through to Dobby when prologue is safe (no PC-relative instructions)

### Fixed
- **Issue #40 unblocked** - StaticData can now hook FeatManager without ARM64 corruption
- Build errors: Added missing `#include <stddef.h>` and `#include <unistd.h>`
- Overlay console stability: prevent crashes when clicking overlay tabs by centralizing Lua dispatch on the tick thread (queue key events + overlay commands) and only submitting commands on Enter (not focus loss)

### Technical
- **Key Discovery**: FeatManager::GetFeats prologue is standard frame setup (STP x22,x21; STP x20,x19; STP x29,x30; ADD x29,sp,#32) - no ADRP patterns
- **ARM64 ADRP encoding**: 21-bit immediate encodes ±4GB PC-relative page offset
- **Skip-and-redirect strategy**: Hook AFTER safe instructions, let original prologue run in-place
- **Trampoline structure**: [skipped prologue] + [overwritten insn] + [branch back to target+N]

---

## [v0.33.0] - 2025-12-15

**Parity:** ~66% | **Category:** StaticData | **Issues:** #40

### Added
- **FixedString Name resolution** - Feat entries now include actual names (e.g., "Alert", "Actor", "AbilityScoreIncrease")
- **Type-specific capture loading** - `LoadFridaCapture("Race")`, `LoadFridaCapture("Origin")` etc.
- **Generic ManagerConfig infrastructure** - Per-type offsets for all resource types (Race, Origin, God, Class, Background)

### Changed
- `Ext.StaticData.GetAll("Feat")` now returns Name field in addition to ResourceUUID
- `LoadFridaCapture()` accepts optional type parameter (defaults to "Feat" for backwards compatibility)

### Technical
- **FixedString at offset +0x18** - Name field located after GuidResource base class (VMT + UUID = 24 bytes)
- **ManagerConfig struct** - Stores count_offset, array_offset, entry_size, name_offset, capture_file per type
- **Type-specific name offsets** - Race: +0x18, Origin: +0x1C, God: +0x18, Class: +0x28, Background: none (DisplayName only)

---

## [v0.32.9] - 2025-12-15

**Parity:** ~66% | **Category:** Template System | **Issues:** #41

### Added
- **Ext.Template API** - Game object template access via Frida capture workflow
  - `Ext.Template.Get(guid)` - Cascading template search
  - `Ext.Template.GetRootTemplate(guid)` - GlobalTemplateBank lookup
  - `Ext.Template.GetAllRootTemplates()` - List all root templates
  - `Ext.Template.GetCount([managerType])` - Get template counts
  - `Ext.Template.LoadFridaCapture()` - Load captured manager pointers
- **OriginalTemplateComponent** - ECS component for template GUID tracking (158 total components)
- **Template manager C implementation** - `src/template/template_manager.c` with Frida capture loading
- **Frida discovery script** - `tools/frida/discover_template_managers.js` for runtime template capture

### Technical
- **Same pattern as StaticData** - Frida runtime capture when symbols aren't exported
- **4-level template hierarchy** - GlobalTemplateBank → LocalTemplateManager → CacheTemplateManager → LocalCacheTemplates
- **GameObjectTemplate struct** - VMT, Tags, FixedString IDs, Handle at discovered offsets

---

## [v0.32.8] - 2025-12-15

**Parity:** ~65% | **Category:** Entity Components | **Issues:** #33

### Added
- **105 new tag component layouts** - Expanded from 52 to 157 components (201% increase!)
- **Automated tag component generation** - `tools/generate_tag_components.py` for batch TypeId extraction

**Client Components (ecl::) - 4 components:**
- Camera state tracking (CameraInSelectorMode, CameraSpellTracking)
- Animation flags (DummyIsCopyingFullPose, DummyLoaded)

**Common Components (eoc::) - 69 components:**
- Gameplay state: Player, SimpleCharacter, IsCharacter, IsInTurnBasedMode, IsInFTB, OffStage, PickingState
- Combat indicators: CombatDelayedFanfare, RollInProgress, Ambushing
- Progression: CanLevelUp, FTBPaused
- Environmental: IsFalling, GravityDisabled, CampPresence
- Healing: HealBlock, HealMaxIncoming, HealMaxOutgoing
- Inventory flags: CanBeWielded, CanBeInInventory, CannotBePickpocketed, CannotBeTakenOut, etc.
- Item properties: IsGold, IsDoor, IsItem, ItemInUse, NewInInventory, ItemCanMove, etc.
- Template flags: ClimbOn, Ladder, WalkOn, InteractionDisabled, IsStoryItem
- Tadpole states: Tadpoled, HalfIllithid, FullIllithid
- Character markers: Avatar, HasExclamationDialog, Trader
- Visibility: CanSeeThrough, CanShootThrough, CanWalkThrough

**Server Components (esv::) - 28 components:**
- Combat: ServerCanStartCombat, ServerFleeBlocked, ServerCombatLeaveRequest
- Visibility: ServerIsLightBlocker, ServerIsVisionBlocker, ServerDarknessActive
- Inventory: ServerInventoryIsReplicatedWith, ReadyToBeAddedToInventory
- Status: ServerStatusActive, ServerStatusAddedFromSaveLoad, ServerStatusAura
- Misc: ServerHotbarOrder, EscortHasStragglers, ServerDeathContinue

**Low-level Components (ls::) - 13 components:**
- Engine flags: IsGlobal, SavegameComponent, NetComponent
- Visual: VisualLoaded, AlwaysUpdateEffect, AnimationUpdate
- Level lifecycle: LevelIsOwner, LevelPrepareUnloadBusy, LevelUnloadBusy, LevelInstanceUnloading
- Pause: PauseComponent, PauseExcluded

### Technical
- **Tag components are zero-field** - Presence on entity IS the data (boolean flags)
- **No reverse engineering needed** - componentSize=0, properties=NULL
- **157 total components** - Massive jump from 52 (~8% parity for components)

---

## [v0.32.7] - 2025-12-14

**Parity:** ~60% | **Category:** Entity Components | **Issues:** #33

### Added
- **11 new component layouts** - Expanded from 41 to 52 components (batch acceleration)

**Combat Components:**
- `CombatParticipant` - CombatHandle, CombatGroupId, InitiativeRoll, Flags, AiHint
- `CombatState` - MyGuid (HashMaps skipped)

**Tag Components (presence = data):**
- `Avatar`, `Trader`, `CanLevelUp`, `IsGold`, `IsItem`, `IsDoor`, `IsFalling`, `IsInTurnBasedMode`, `GravityDisabled`

### Technical
- **Batch acceleration** - Tag components require no offset verification
- **52 total components** - Exceeds 50-component goal from Issue #33

---

## [v0.32.6] - 2025-12-14

**Parity:** ~58% | **Category:** Entity Components | **Issues:** #33

### Added
- **5 new component layouts** - Expanded from 36 to 41 components
  - `DeathState`, `DeathType`, `InventoryWeight`, `ThreatRange`, `IsInCombat`

---

## [v0.32.5] - 2025-12-14

**Parity:** ~57% | **Category:** Static Data, Debug API | **Issues:** #40

### Added
- **Ext.StaticData API (Foundation)** - New Lua namespace for immutable game data
- `Ext.StaticData.GetCount(type)` - Get count of entries (works for Feat: returns 37)
- `Ext.StaticData.GetTypes()` - List all supported type names
- `Ext.StaticData.IsReady(type)` - Check if manager is captured
- `Ext.StaticData.TryTypeContext()` - Debug: traverse ImmutableDataHeadmaster TypeInfo list
- Debug helpers: `DumpStatus()`, `DumpEntries()`, `Probe()`

### Added (Debug API)
- **Time utilities for RE sessions** - Correlate console commands with log timestamps
  - `Ext.Debug.Time()` - Current time as "HH:MM:SS"
  - `Ext.Debug.Timestamp()` - Unix timestamp (seconds)
  - `Ext.Debug.SessionStart()` - Time when BG3SE initialized
  - `Ext.Debug.SessionAge()` - Seconds since session started
  - `Ext.Debug.PrintTime(msg)` - Print with timestamp prefix
- **Pointer validation** - Safer memory probing for offset discovery
  - `Ext.Debug.IsValidPointer(addr)` - Check if address is readable
  - `Ext.Debug.ClassifyPointer(addr)` - Classify pointer type

### Known Limitations
- **GetAll() returns invalid GUIDs** - TypeContext gives registration metadata, not real manager data
- **GetFeats hooks disabled** - Hooks broke feat selection UI; root cause under investigation
- **Feat data access incomplete** - Count works (37), but individual feat entries need hook-based capture

### Technical Discoveries
- **TypeContext is metadata, not managers** - ImmutableDataHeadmaster TypeContext provides registration entries, not actual GuidResourceBank data
- **Real FeatManager structure** - count at +0x7C, array at +0x80 (from GetFeats @ `0x101b752b4`)
- **TypeContext structure** - count at +0x00, linked list pointer at +0x80 (NOT feat array)
- **m_State discovered**: ImmutableDataHeadmaster m_State at offset `0x083c4a68`
- **121 TypeInfo entries** scanned via linked list traversal

### Documentation
- Updated `agent_docs/development.md` with Debug API reference
- Updated `ghidra/offsets/STATICDATA.md` with structure findings

---

## [v0.32.4] - 2025-12-13

**Parity:** ~57% | **Category:** Stats System | **Issues:** #32

### Added
- **Full Stats Sync for created stats** - `Ext.Stats.Sync()` now works for both existing game stats AND newly created shadow stats
- **Shadow stat detection** - `stats_is_shadow_stat()` API for checking if a stat was created at runtime
- **FixedString interning** - `fixed_string_intern()` creates new FixedStrings via game's `ls::FixedString::Create`
- **RefMap insertion** - New prototypes can be inserted into prototype manager hash tables

### Fixed
- **SpellPrototype::Init crash** - Shadow stats now use template cloning (memcpy) instead of Init()
- **ARM64 const& calling convention** - Fixed crash by passing pointer (not value) to Init function
- **Prototype registration** - New spells properly registered with SpellPrototypeManager

### Technical
- **Shadow stats architecture**: Stats created via `Ext.Stats.Create()` exist in a separate registry, not in `RPGStats.Objects`. `Init()` can't find them, so we clone the template prototype instead.
- **SpellPrototype::Init** at `0x101f72754` - Populates prototype from stats object in RPGStats
- **FixedString::Create** at `0x1064b9ebc` - Game's function for interning new strings
- **RefMap hash** is `fs_key % capacity` (verified via Ghidra)
- **Two-path sync**: Shadow stats use memcpy clone, game stats use Init()

### Verified Working
```lua
-- Create and sync shadow spell
local spell = Ext.Stats.Create("MyTestSpell", "SpellData", "Projectile_FireBolt")
spell.Damage = "2d6"
Ext.Stats.Sync("MyTestSpell")  -- No crash, prototype registered

-- Create and sync shadow status
local status = Ext.Stats.Create("TestStatus", "StatusData", "BURNING")
Ext.Stats.Sync("TestStatus")   -- No crash, prototype registered

-- Sync existing game spell
Ext.Stats.Sync("Projectile_FireBolt")  -- Works for game stats too
```

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
