# Stats System Offsets (macOS ARM64)

## Overview

The stats system manages game statistics including weapons, armor, spells, statuses, and passives. The central manager is `RPGStats` which contains multiple `CNamedElementManager<T>` instances for different stat types.

## Key Symbols

| Symbol | Address | Description |
|--------|---------|-------------|
| `RPGStats::m_ptr` | `0x1089c5730` | Global pointer to RPGStats instance (static class member) |
| `eoc::IsStatsItem(int)::rpgStats` | `0x1089c55a8` | Local static cached reference |
| `CRPGStats_Object_Manager::~CRPGStats_Object_Manager()` | `0x10211cfa8` | Object manager destructor |

## Mangled Symbol Names

```
__ZN8RPGStats5m_ptrE                                     -> RPGStats::m_ptr
__ZZN3eoc11IsStatsItemEiE8rpgStats                       -> eoc::IsStatsItem(int)::rpgStats
__ZN24CRPGStats_Object_ManagerD1Ev                       -> CRPGStats_Object_Manager::~CRPGStats_Object_Manager()
```

## CNamedElementManager Template Instantiations

These are discovered template instantiations for managing different stat types:

| Type | Key Methods | Notes |
|------|-------------|-------|
| `CRPGStats_Modifier` | Insert @ `0x1021217cc`, GetEntry @ `0x102121b84` | Property modifiers |
| `CRPGStats_Modifier_List` | Insert @ `0x101c5fc74`, GetEntry @ `0x101c5ffac` | Modifier lists (stat types) |
| `CRPGStats_Modifier_ValueList` | Insert @ `0x10211d5d0`, GetEntry @ `0x10211d980` | Enum value lists |
| `CRPGStats_Treasure_Table` | Insert @ `0x10211ed58`, GetEntry @ `0x10211f0dc` | Loot tables |
| `CRPGStats_Treasure_SubTable` | Insert @ `0x10211e54c`, GetEntry @ `0x10211e8d0` | Loot sub-tables |

## RPGStats Structure

Based on Windows BG3SE reference (`BG3Extender/GameDefinitions/Stats/Stats.h`):

```c
struct RPGStats {
    void* VMT;                                                    // 0x00
    CNamedElementManager<RPGEnumeration> ModifierValueLists;      // Type definitions (enums)
    CNamedElementManager<ModifierList> ModifierLists;             // Stat types (Weapon, Armor, etc.)
    CNamedElementManager<Object> Objects;                         // Actual stat objects
    // ... SpellPrototypes, StatusPrototypes, PassivePrototypes
    // ... Property pools (FixedStrings, Floats, Int64s, GUIDs, etc.)
    // ... ExtraData and other managers
};
```

### Runtime-Verified Offsets (macOS ARM64)

**Verified via console probing on Dec 5, 2025:**

| Member | Offset | Verified Values |
|--------|--------|-----------------|
| `ModifierValueLists` | `+0x00` | size=112 (112 RPGEnumeration types - enums, ConstantInt, etc.) |
| `ModifierLists` | `+0x60` | size=9 (9 stat types: Weapon, Armor, Character, etc.) |
| `Objects` | `+0xC0` | size=15,774 (all stat entries in the game) |

**ModifierValueLists (Dec 5, 2025):**
```
RPGStats+0x00: ModifierValueLists (CNamedElementManager<RPGEnumeration>)
  buf  = 0x1231b4e00
  cap  = 128
  size = 112  (112 enum types for property type definitions)
```
These enumerations define property types like ConstantInt, ConstantFloat, FixedString, etc.

**Sample Runtime Values:**
```
RPGStats base:     0x11f08f800
ModifierLists:     +0x60 -> buf=0x600000637c00, cap=16, size=9
Objects:           +0xC0 -> buf=0x1749e8000, cap=16384, size=15774
```

**Console Probe Commands Used:**
```lua
-- Get RPGStats pointer
local rpg = Ext.Memory.Read(Ext.Memory.GetModuleBase("Baldur") + 0x89c5730, 8)

-- Read ModifierLists manager at +0x60
-- CNamedElementManager layout: VMT(8) + buf_(8) + cap_(4) + size_(4) = 24 bytes
local ml_base = rpg_addr + 0x60
local ml_buf = Ext.Memory.Read(ml_base + 0x08, 8)   -- Array.buf_
local ml_cap = Ext.Memory.Read(ml_base + 0x10, 4)   -- Array.cap_ (expect 16)
local ml_size = Ext.Memory.Read(ml_base + 0x14, 4)  -- Array.size_ (expect 9)
```

**Note:** These offsets differ from the Windows version due to ARM64 alignment and potential structure packing differences.

## CNamedElementManager<T> Structure

```c
template<typename T>
struct CNamedElementManager {
    void* VMT;                           // 0x00 (8 bytes)
    Array<T*> Primitives;                // 0x08: Element storage (buf_ + cap_ + size_)
    HashMap<FixedString, int32_t> NameHashMap;  // Name to index lookup
    int32_t HighestIndex;                // Next available index
};

// Array<T> layout (verified via runtime probing):
struct Array {
    T* buf_;      // +0x00: Pointer to element storage
    uint32_t cap_;     // +0x08: Capacity
    uint32_t size_;    // +0x0C: Current size (element count)
};
// Total: 16 bytes (not 24 as in some Windows layouts)
```

### CNamedElementManager Verified Layout

| Field | Offset | Size | Notes |
|-------|--------|------|-------|
| VMT | +0x00 | 8 | Virtual method table |
| Primitives.buf_ | +0x08 | 8 | Pointer to element array |
| Primitives.cap_ | +0x10 | 4 | Array capacity |
| Primitives.size_ | +0x14 | 4 | Element count |
| NameHashMap | +0x18 | ~48 | HashMap for name lookups |
| HighestIndex | varies | 4 | Next allocation index |

**Total CNamedElementManager size:** ~0x60 bytes (96 bytes), which explains the +0x60 stride between managers in RPGStats.

## stats::Object Structure

Based on Windows BG3SE (`BG3Extender/GameDefinitions/Stats/Common.h`):

```c
struct Object {
    void* VMT;                           // 0x00
    Array<int32_t> IndexedProperties;    // Indices into global pools
    FixedString Name;                    // Stat entry name
    // ... AI flags, functors, requirements, HashMaps
    int32_t Using;                       // Parent stat index (-1 if none)
    uint32_t ModifierListIndex;          // Type reference (which ModifierList)
    uint32_t Level;                      // Level value
};
```

### Runtime-Verified Object Offsets (Dec 5, 2025)

**BREAKTHROUGH:** C-level memory dump of WPN_Longsword at `0x60004f97def0`:

| Field | Offset | Size | Verified Value | Notes |
|-------|--------|------|----------------|-------|
| VMT | +0x00 | 8 | 0x010cf54608 | Virtual method table |
| IndexedProperties.begin_ | +0x08 | 8 | 0x60001fb4ad00 | Pointer to int32_t array |
| IndexedProperties.end_ | +0x10 | 8 | 0x60001fb4adf4 | End pointer |
| IndexedProperties.capacity_ | +0x18 | 8 | 0x60001fb4adf4 | Capacity end (same as end) |
| Name | +0x20 | 8 | 0x35a00060 | FixedString index |
| Functors | +0x28 | 8 | 0x600010c961c0 | HashMap pointer |
| (count/field) | +0x30 | 8 | 5 | Some count field |

**Memory dump:**
```
+00: 08 46 f5 0c 01 00 00 00  00 ad b4 1f 00 60 00 00  // VMT + begin_
+10: f4 ad b4 1f 00 60 00 00  f4 ad b4 1f 00 60 00 00  // end_ + capacity_
+20: 60 00 a0 35 00 00 00 00  c0 61 c9 10 00 60 00 00  // Name + Functors
+30: 05 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  // count + padding
```

**IndexedProperties Vector (std::vector layout on ARM64):**
- Uses 3 pointers: begin_, end_, capacity_end_ (24 bytes total)
- Size calculation: (end_ - begin_) / sizeof(int32_t)
- WPN_Longsword has **61 properties** (0xF4 / 4 = 61)

**Sample property indices from WPN_Longsword:**
```
[ 0] = 0       [ 1] = 4251    [ 2] = 0       [ 3] = 0
[ 6] = 2303    [ 8] = 1       [18] = 1       [19] = 3316
```
These are indices into global pools (FixedStrings, enums, etc.)

**Old offset notes (may be incorrect):**

### ModifierListIndex Offset Issue (Dec 5, 2025)

**Problem:** The offset 0xac always reads 0 for all stats, even weapons (which should be index 8).

**Root Cause:** The Object struct on macOS ARM64 has a different layout than Windows x64 due to different sizes of:
- `HashMap<FixedString, Array<FunctorGroup>>` (Functors)
- `HashMap<FixedString, Array<RollCondition>>` (RollConditions)
- `Array<Requirement>` (Requirements)
- `TrackedCompactSet<FixedString>` (ComboProperties, ComboCategories)

These variable-size members between `Name` (+0x20) and `Using` cause offset differences.

**Workaround Implemented:** Name-based type detection in `stats_get_type()`:
- `WPN_*` → "Weapon"
- `ARM_*` → "Armor"
- `Target_*`, `Projectile_*`, `Rush_*`, etc. → "SpellData"
- `Passive_*` → "PassiveData"
- Falls back to ModifierListIndex lookup if no prefix matches

**Future Work:** Use Ghidra to analyze functions that access `Object.ModifierListIndex` to discover the true ARM64 offset.

## ModifierList Structure

```c
struct ModifierList {
    CNamedElementManager<Modifier> Attributes;  // ~0x5c bytes
    FixedString Name;                           // Type name ("Weapon", "Armor", etc.)
};
```

### Runtime-Verified ModifierList Offsets (Dec 5, 2025)

Discovered via debug probe of ModifierList[0] at `0x600009d31800`:

| Field | Offset | Notes |
|-------|--------|-------|
| Attributes (CNamedElementManager) | +0x00 | Contains modifier definitions |
| Name (FixedString) | +0x5c | Type name - verified: resolves to "Armor" |

**Debug probe results:**
```
ML+0x5c: fs_idx=0x46d00030 -> Armor
```

Note: The CNamedElementManager<Modifier> is smaller than expected (~0x5c bytes instead of 0x60).

## Related TypeIds

| Component | TypeId Global | Notes |
|-----------|---------------|-------|
| `eoc::RPGStatsComponent` | `0x1088ec680` | ECS component for entity stats |
| `esv::RPGStatsSystem` | `0x108a1e220` | Server-side stats system |

## Usage Pattern

To access the stats system:

```c
// 1. Resolve RPGStats::m_ptr symbol
void** pRPGStatsPtr = dlsym(handle, "__ZN8RPGStats5m_ptrE");

// 2. Dereference to get RPGStats instance
RPGStats* stats = *pRPGStatsPtr;

// 3. Access Objects manager at appropriate offset
CNamedElementManager<Object>* objects = (void*)stats + OFFSET_OBJECTS;

// 4. Look up stat by name via NameHashMap
int32_t index = hashmap_lookup(objects->NameHashMap, "Weapon_Longsword");

// 5. Get object from Primitives array
Object* stat = objects->Primitives[index];
```

## VTable Addresses

| Class | VTable Address |
|-------|----------------|
| `CNamedElementManager<CRPGStats_Modifier>` | `0x1086c28c0` |
| `CNamedElementManager<CRPGStats_Modifier_List>` | `0x1086c2518` |
| `CNamedElementManager<CRPGStats_Modifier_ValueList>` | `0x1086c2448` |
| `CNamedElementManager<CRPGStats_Treasure_Table>` | `0x1086c2788` |
| `CRPGStats_Modifier_List` | `0x1086c2858` |
| `CRPGStats_Object_Manager` | `0x1086c2580` |
| `CRPGStats_ItemType_Manager` | `0x1086c2378` |
| `CRPGStats_Modifier_List_Manager` | `0x1086c24b0` |

## ModifierList Discovery (Dec 2025)

Results from `find_modifierlist_offsets.py` Ghidra script:

### ModifierList-Related Symbols

| Symbol | Address | Notes |
|--------|---------|-------|
| `GetModifierListByIdAndType` | `0x10114a0d8` | Useful for understanding ModifierList access |
| `gui::VMBoostModifiers::GetFromUIBoostModifierList` | `0x10226e248` | UI boost modifiers |
| `gui::DCActiveRoll::GetFromUISelectedBoostModifierList` | `0x102274374` | Active roll UI |

### Stat Type Name Strings

| Type Name | String Address | DATA XREF | Notes |
|-----------|----------------|-----------|-------|
| `Weapon` | `0x1078481a9` | None | No XREF found |
| `Armor` | `0x10784a2f1` | None | No XREF found |
| `SpellData` | `0x107864734` | None | No XREF found |
| `StatusData` | `0x107b72fbd` | `0x10868a218` | Has DATA reference |
| `PassiveData` | `0x107b73be3` | `0x10868c288` | Has DATA reference |
| `Character` | `0x107847596` | None | No XREF found |

**Observation:** StatusData and PassiveData have DATA references ~8KB apart (`0x10868c288 - 0x10868a218 = 0x2070`). These may be entries in a ModifierList name table or type registry. Investigating these addresses could reveal the ModifierList structure layout.

### RPGStats-Related Symbols (364 total)

Key functions found:
- `eoc::active_roll::ComputeFinalModifiers` @ `0x101149030`, `0x1011492dc`
- `CItemCombinationManager::LoadText(..., RPGStats&)` @ `0x1011bc0cc`
- `eoc::RPGStatsComponent` type registration @ `0x10194da60`

## Ghidra Analysis Notes

### Finding RPGStats::m_ptr

The symbol `__ZN8RPGStats5m_ptrE` is exported and can be resolved via dlsym. This is a `b` (BSS) section symbol, meaning it's an uninitialized global that gets populated at runtime.

### Usage in Functions

Functions that use RPGStats typically take it as a reference parameter:
- `CItemCombinationManager::LoadText(..., RPGStats&)` @ `0x1011bc0cc`
- `CTreasureCategoryGroups::ShouldCategoriesDrop(..., RPGStats*)` @ `0x10211b0ac`

## Implementation Notes

Unlike the Entity system where we had to capture pointers via hooks, `RPGStats::m_ptr` is a static member that can be resolved directly via dlsym once the game loads. However, it will be NULL/0 until the stats system initializes.

**Timing:** The stats system typically initializes early in game startup, before SessionLoaded. Safe to access after main menu appears.

## Modifier Attribute Discovery (Dec 5, 2025)

Results from `find_modifier_attributes.py` Ghidra script:

### Key Finding: Attribute Names NOT in Binary

**Critical discovery:** Property attribute names like "Damage", "DamageType", "WeaponRange" are **NOT compiled into the binary**. They are loaded at runtime from game data files (`Stats/*.txt`). This is why:
- Ghidra string search found 0 matches for these strings
- The Modifier.Name field must resolve through FixedString at runtime
- Property names exist only in data files, not code

### Symbols Found

| Category | Count | Notable Examples |
|----------|-------|------------------|
| Modifier-related symbols | 2,827 | Mostly Noesis UI framework (`NoesisApp::KeyTrigger::GetModifiers`) |
| GetAttribute* functions | 170 | Various error APIs and meta functions |
| RPGStats symbols | 419 | Component registrations, stat accessors |

### Key RPGStats Functions

| Function | Address | Signature |
|----------|---------|-----------|
| `eoc::active_roll::ComputeFinalModifiers` | `0x101149030` | Takes `Modifier[]` and `RPGStats*` |
| `eoc::active_roll::ComputeFinalModifiers` (overload) | `0x1011492dc` | Second overload |
| `CItemCombinationManager::LoadText` | `0x1011bc0cc` | Takes `RPGStats&` parameter |
| `eoc::IsSatisfyItemUseConditions` | `0x1012d49ac` | Uses RPGStats for condition checking |
| `eoc::RPGStatsComponent` type registration | `0x10194da60` | ECS component registration |

### GetAttribute Function Offset Patterns

Common offsets used in GetAttribute* functions (may indicate struct field access):

| Offset | Occurrences | Likely Purpose |
|--------|-------------|----------------|
| `0x08` | Very common | First field after VMT |
| `0x30, 0x38` | Common | HashMap/Array access |
| `0x88` | Multiple | Mid-struct field |
| `0x108, 0x110, 0x118` | Multiple | Larger struct access |

### Modifier Structure Analysis

The `eoc::active_roll::ComputeFinalModifiers` function at `0x101149030` processes `Modifier` arrays. Analyzing this function could reveal:
- Modifier struct layout on ARM64
- How EnumerationIndex is accessed
- How Name (FixedString) is resolved

**Windows BG3SE Modifier struct for reference:**
```c
struct Modifier {
    int32_t EnumerationIndex;  // +0x00: Index into ModifierValueLists
    int32_t LevelMapIndex;     // +0x04: For level scaling
    int32_t UnknownZero;       // +0x08: Always 0
    FixedString Name;          // +0x0C (x86) or +0x10 (ARM64 aligned)
};
```

### Implications for Property Access

Since attribute names are NOT in the binary:
1. The Modifier.Name field contains a FixedString index
2. FixedString must be resolved via GlobalStringTable at runtime
3. Property lookup requires: Name string → FixedString hash → Modifier index → IndexedProperties[index]
4. Cannot use static analysis to find attribute offsets; must probe at runtime

## FixedStrings Pool (CRITICAL - Dec 5, 2025)

**BREAKTHROUGH:** Discovered the correct offset for `RPGStats.FixedStrings` via Ghidra decompilation.

### Discovery Method

Decompiled `StatsObject::GetFixedStringValue` at `0x102006b48`:

```c
/* StatsObject::GetFixedStringValue(ls::FixedString const&) const */
undefined4 * StatsObject::GetFixedStringValue(FixedString *param_1)
{
    // ... validation code ...
    uVar1 = *(uint *)(*(long *)(param_1 + 8) + (long)(int)uVar3 * 4);
    if (-1 < (int)uVar1) {
        return (undefined4 *)(*(long *)(lVar2 + 0x348) + (ulong)uVar1 * 4);
        //                                    ^^^^^ THIS IS THE KEY OFFSET
    }
    return &ls::FixedString::Empty;
}
```

### Key Offset

| Field | Offset | Notes |
|-------|--------|-------|
| `RPGStats.FixedStrings.buf_` | **0x348** | Pointer to FixedString index array |

### Assembly Evidence

```asm
ldr [u'x9', u'[x22, #0x348]']    // x9 = RPGStats + 0x348 (FixedStrings.buf_)
add [u'x0', u'x9', u'x8, LSL #0x2']  // x0 = buf_ + (index * 4)
```

### Property Resolution Flow

```
stat.PropertyName
    ↓ __index metamethod
stats_get_string(obj, "PropertyName")
    ↓ find_property_index_by_name() → attr_index
IndexedProperties[attr_index]
    ↓ pool_index (e.g., 2303 for Damage)
RPGStats.FixedStrings[pool_index]
    ↓ FixedString index → GlobalStringTable
"1d8"
```

### Verified Working

```lua
local stat = Ext.Stats.Get("WPN_Longsword")
Ext.Print(stat.Damage)  -- Output: "1d8"
```

### Next Steps

1. ~~**Runtime probe:** Use `Ext.Stats.DumpAttributes(8)` with debug code to inspect actual Modifier memory~~ ✅ COMPLETE
2. ~~**Analyze ComputeFinalModifiers:** Decompile `0x101149030` to understand ARM64 Modifier layout~~ Used GetFixedStringValue instead
3. ~~**Test multiple offsets:** Try Name at +0x0C, +0x10, +0x18, +0x20 until valid strings appear~~ ✅ COMPLETE - 0x0C is correct

## Related Files in Windows BG3SE

- `BG3Extender/GameDefinitions/Stats/Stats.h` - RPGStats struct definition
- `BG3Extender/GameDefinitions/Stats/Common.h` - Object, ModifierList structs
- `BG3Extender/Lua/Libs/Stats.inl` - Lua bindings
- `BG3Extender/GameDefinitions/Symbols.h` - gRPGStats declaration

---

## Prototype Managers (for Stats Sync)

### Overview

For created stats to be usable by the game (spawning items, casting spells, applying statuses), they must be registered with the appropriate **Prototype Manager**. This is what `Ext.Stats.Sync()` does in Windows BG3SE.

### Architecture (from Windows BG3SE)

```
RPGStats::SyncWithPrototypeManager(Object* object)
    ├── SpellData     → SpellPrototypeManager::SyncStat()
    ├── StatusData    → StatusPrototypeManager::SyncStat()
    ├── PassiveData   → PassivePrototypeManager::SyncStat()
    └── InterruptData → InterruptPrototypeManager::SyncStat()
```

Each prototype manager:
1. Has a singleton instance (double-pointer global)
2. Contains a `HashMap<FixedString, *Prototype>` for prototype lookup
3. Has an `Init` function that parses stat properties into the prototype struct

### Required Components (per prototype type)

| Component | Windows Symbol | Purpose |
|-----------|----------------|---------|
| Singleton | `eoc__SpellPrototypeManager` | Double-pointer to manager instance |
| Init Function | `eoc__SpellPrototype__Init` | Parses Object into Prototype |
| Prototype Struct | `SpellPrototype` | ~300+ bytes, type-specific layout |

### SpellPrototype Structure (Windows x64, partial)

```c
struct SpellPrototype {
    int StatsObjectIndex;           // +0x00
    SpellType SpellTypeId;          // +0x04
    FixedString SpellId;            // +0x08
    uint8_t SpellSchool;            // +0x10
    SpellFlags SpellFlags;          // +0x14
    // ... ~100+ more fields
    Array<ActionResourceCost> UseCosts;
    Array<FixedString> ContainerSpells;
    // Total: ~300-400 bytes
};
```

### macOS Findings (Dec 2025)

**Ghidra script:** `find_prototype_managers.py`, `analyze_get_spell_prototype.py`, `find_status_manager.py`

**Discovered Singleton Addresses (all verified Dec 2025):**
| Manager | Singleton Address | Discovery Method |
|---------|------------------|------------------|
| `SpellPrototypeManager::m_ptr` | `0x1089bac80` | GetSpellPrototype decompilation (ADRP+LDR pattern) |
| `StatusPrototypeManager::m_ptr` | `0x1089bdb30` | Ghidra symbol search |
| `PassivePrototypeManager*` | `0x108aeccd8` | GetPassivePrototype ADRP+LDR pattern |
| `InterruptPrototypeManager*` | `0x108aecce0` | EvaluateInterrupt ADRP patterns |
| `BoostPrototypeManager::m_ptr` | `0x108991528` | Symbol table (not exported via dlsym) |

**Discovered Functions:**
| Function | Address | Notes |
|----------|---------|-------|
| `GetPassivePrototype` | `0x102655c14` | Retrieves passive by name |
| `GetPassivePrototypes` | `0x102014284` | Bulk retrieval |
| `GetSpellPrototype` (SpellCastWrapper) | `0x10346e740` | Loads SpellPrototypeManager singleton |
| `__GLOBAL__sub_I_SpellPrototype.cpp` | `0x1066e389c` | Static initializer |
| `__GLOBAL__sub_I_StatusPrototypeManager.cpp` | `0x106704ad4` | Static initializer |
| `__GLOBAL__sub_I_PassivePrototype.cpp` | `0x106691108` | Static initializer |

**All 5 prototype manager singletons discovered - Issue #32 singleton discovery complete!**

### Implementation Approach

To complete `Ext.Stats.Sync()`:

1. **Find Singleton Pointers**
   - Trace XREFs from functions using managers
   - Look for global pointer loads in register setup
   - Pattern scan for manager VMT addresses

2. **Find Init Functions**
   - Decompile `SyncStat` equivalents
   - Find functions taking `(Prototype*, FixedString const&)`
   - Match against property string accesses

3. **Understand ARM64 Layouts**
   - Prototype structs likely differ from Windows
   - Need to verify field offsets via runtime probing
   - May need to allocate via game allocator

4. **Implementation Steps**
   ```c
   bool sync_spell_prototype(StatsObjectPtr obj) {
       // 1. Get SpellPrototypeManager singleton
       void **mgr_ptr = get_spell_prototype_manager();
       if (!mgr_ptr || !*mgr_ptr) return false;

       // 2. Get or create prototype in manager's HashMap
       SpellPrototype *proto = find_or_create_prototype(*mgr_ptr, obj->Name);

       // 3. Call Init function to parse properties
       spell_prototype_init(proto, obj->Name);

       return true;
   }
   ```

### Current State (v0.32.0)

- `Ext.Stats.Create()` - Works, creates stats in shadow registry
- `Ext.Stats.Sync()` - Calls prototype managers (manager access verified)
- **All 5 singleton addresses discovered** (Spell, Status, Passive, Interrupt, Boost)
- Created stats accessible via `Ext.Stats.Get()`
- Runtime manager pointer resolution implemented in `prototype_managers.c`

### Remaining Work (Medium effort)

- Implement RefMap insertion for each prototype type
- Understand Prototype struct layouts on ARM64
- Call `Prototype::Init()` or manually populate prototype fields
- Test that synced stats are usable by game (Osi.AddSpell, etc.)

### Related Issue

See [GitHub Issue #32](https://github.com/tdimino/bg3se-macos/issues/32) (Stats Sync - Full Prototype Manager Integration)
