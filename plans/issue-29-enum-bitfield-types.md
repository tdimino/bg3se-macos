# Plan: Implement Enum and Bitfield Object Types (Issue #29)

## Overview

Implement proper enum and bitfield userdata types for BG3SE-macOS to match Windows BG3SE behavior. This provides first-class Lua objects for enums with type-safe comparison, label resolution, and bitwise operations for bitfields.

## Target API

```lua
-- Enum Objects
local dt = Ext.Enums.DamageType.Fire
dt.Label      -- "Fire"
dt.Value      -- 5
dt.EnumName   -- "DamageType"
dt == "Fire"  -- true (label comparison)
dt == 5       -- true (value comparison)

-- Bitfield Objects
local af = Ext.Enums.AttributeFlags[3]
af.__Labels   -- {"FreezeImmunity", "DrunkImmunity"}
af.__Value    -- 3
af.DrunkImmunity  -- true (flag query)
af | "WebImmunity"  -- OR operation returns new bitfield

-- Ext.Enums Table
Ext.Enums.DamageType.Fire
Ext.Enums.SurfaceType.Blood
```

## Architecture

### Design: C-Based Enum Registry

Windows BG3SE uses C++ templates and STL containers. For macOS, we'll use:
- C arrays for label/value storage
- Standard Lua userdata with metatables
- Separate metatables for enums vs bitfields

### Key Data Structures

```c
// Enum value entry
typedef struct {
    const char *label;  // "Fire"
    uint64_t value;     // 5
} EnumValueEntry;

// Enum type definition
typedef struct {
    const char *name;                    // "DamageType"
    EnumValueEntry values[256];          // Value mappings
    int value_count;
    int registry_index;
    bool is_bitfield;
    uint64_t allowed_flags;              // For bitfields only
} EnumTypeInfo;

// Lua userdata (16 bytes)
typedef struct {
    uint64_t value;
    int16_t type_index;
    int16_t _padding;
    uint32_t _reserved;
} EnumUserdata;
```

## Implementation Plan

### Phase 1: Core Infrastructure

**New Files:**
- `src/enum/enum_registry.h` - Type definitions, public API
- `src/enum/enum_registry.c` - Registry implementation
- `src/enum/enum_lua.c` - Enum metamethods

**Enum Registry:**
```c
void enum_registry_init(void);
int enum_registry_add_type(const char *name, bool is_bitfield);
bool enum_registry_add_value(int type_idx, const char *label, uint64_t value);
EnumTypeInfo* enum_registry_get(int type_index);
EnumTypeInfo* enum_registry_find_by_name(const char *name);
const char* enum_find_label(int type_index, uint64_t value);
int64_t enum_find_value(int type_index, const char *label);
```

**Enum Metamethods:**
- `__index` - Access Label, Value, EnumName properties
- `__eq` - Compare to string/int/enum (flexible)
- `__tostring` - Return label
- `__lt` - Less-than comparison by value

### Phase 2: Bitfield Support

**New File:**
- `src/enum/bitfield_lua.c` - Bitfield metamethods

**Bitfield Metamethods:**
- `__index` - Access __Labels, __Value, __EnumName, or query flags
- `__eq` - Compare bitfield values
- `__len` - Count of set flags (popcount)
- `__band` - Bitwise AND (returns new bitfield)
- `__bor` - Bitwise OR (returns new bitfield)
- `__bxor` - Bitwise XOR (returns new bitfield)
- `__bnot` - Bitwise NOT (masked by allowed_flags)
- `__pairs` - Iterate over active flag labels
- `__tostring` - Comma-separated labels

### Phase 3: Ext.Enums Table

**New File:**
- `src/enum/enum_ext.c` - Ext.Enums registration

Create `Ext.Enums` table populated with all registered enum types:
```lua
Ext.Enums = {
    DamageType = {
        Fire = <EnumUserdata>,
        Cold = <EnumUserdata>,
        [5] = <EnumUserdata>,  -- Reverse lookup by value
    },
    AttributeFlags = {
        FreezeImmunity = <BitfieldUserdata>,
        DrunkImmunity = <BitfieldUserdata>,
    },
}
```

### Phase 4: Enum Definitions

**New File:**
- `src/enum/enum_definitions.c` - Hardcoded enum values

Essential enums to include:
- **DamageType**: None, Slashing, Piercing, Bludgeoning, Acid, Fire, Cold, Lightning, Necrotic, Poison, Psychic, Radiant, Thunder, Force
- **SurfaceType**: ~100+ values (Water, Fire, Blood, etc.)
- **StatusType**: BURNING, POISONED, BLEEDING, etc.
- **AbilityId**: Strength, Dexterity, Constitution, Intelligence, Wisdom, Charisma
- **SkillId**: Athletics, Acrobatics, etc.
- **AttributeFlags** (bitfield): FreezeImmunity, DrunkImmunity, etc.

Values sourced from Windows BG3SE `Generated/Enumerations.inl`.

## Files to Modify

| File | Changes |
|------|---------|
| `CMakeLists.txt` | Add new src/enum/*.c files |
| `src/injector/main.c` | Call enum_registry_init(), register Ext.Enums |
| `docs/api-reference.md` | Document Ext.Enums and enum/bitfield objects |

## Files to Create

```
src/enum/
  enum_registry.h       # Type definitions, public API
  enum_registry.c       # Registry implementation
  enum_lua.c            # Enum metamethods
  bitfield_lua.c        # Bitfield metamethods
  enum_ext.c            # Ext.Enums registration
  enum_definitions.c    # Hardcoded enum values
```

## Testing Plan

```lua
-- Test 1: Basic enum access
local dt = Ext.Enums.DamageType.Fire
assert(dt.Label == "Fire")
assert(dt.Value == 5)
assert(dt.EnumName == "DamageType")

-- Test 2: Enum comparison
assert(dt == "Fire")
assert(dt == 5)
assert(dt == Ext.Enums.DamageType.Fire)
assert(not (dt == "Cold"))

-- Test 3: Bitfield access
local bf = Ext.Enums.AttributeFlags.FreezeImmunity | Ext.Enums.AttributeFlags.DrunkImmunity
assert(bf.FreezeImmunity == true)
assert(bf.DrunkImmunity == true)
assert(bf.WebImmunity == false)

-- Test 4: Bitfield operations
local bf2 = bf | "WebImmunity"
assert(bf2.WebImmunity == true)
assert(#bf == 2)  -- popcount

-- Test 5: __tostring
_P(tostring(Ext.Enums.DamageType.Fire))  -- "Fire"
```

## Success Criteria

- [ ] `Ext.Enums.DamageType.Fire` returns enum userdata
- [ ] Enum `.Label`, `.Value`, `.EnumName` properties work
- [ ] Enum comparison with string/int/enum works
- [ ] Bitfield `.__Labels`, `.__Value` properties work
- [ ] Bitfield flag queries (`.FlagName`) return boolean
- [ ] Bitfield bitwise ops (`|`, `&`, `~`) work
- [ ] At least 5 essential enums populated (DamageType, SurfaceType, StatusType, AbilityId, AttributeFlags)

## Estimated Changes

- ~600 lines new C code across 6 new files
- ~30 lines modifications to existing files
- ~50 lines documentation
