# Plan: Issue #30 - Expand Component Property Access

## Overview

Comprehensive expansion of component property access beyond Health. Three phases:
1. Verify existing components work (Stats, Armor, BaseHp, BaseStats)
2. Add TransformComponent properties (Position, Rotation, Scale)
3. Add remaining component layouts (Character, Item, Data, Level, Visual, Physics)

## Current State

**Infrastructure Complete:**
- `component_property.c/h` - Full property reading system with type handlers
- `component_offsets.h` - 5 layouts defined (Health, BaseHp, Armor, Stats, BaseStats)
- `component_typeid.c` - 11 TypeId addresses for runtime discovery
- Safe memory reading via `mach_vm_read`

**Components with TypeId addresses (but no property layout):**
- `ls::TransformComponent` (0x108940550)
- `ls::LevelComponent` (0x10893e780)
- `ls::VisualComponent` (0x108940110)
- `ls::PhysicsComponent` (0x10893c8e8)
- `ecl::Character` (0x1088ab8e0)
- `ecl::Item` (0x1088ab8f0)
- `eoc::DataComponent` (0x10890b088)

---

## Phase 1: Verify Existing Components

### 1.1 Test Script
```lua
-- Test each component on a player entity
local entity = Ext.Entity.Get(GetHostCharacter())

-- Health (known working)
_P("Health.Hp: " .. tostring(entity.Health.Hp))

-- Stats (test)
local stats = entity:GetComponent("Stats")
if stats then
    _P("Stats.InitiativeBonus: " .. tostring(stats.InitiativeBonus))
    _P("Stats.Abilities: " .. Ext.Json.Stringify(stats.Abilities))
    _P("Stats.ProficiencyBonus: " .. tostring(stats.ProficiencyBonus))
end

-- Armor (test)
local armor = entity:GetComponent("Armor")
if armor then
    _P("Armor.ArmorClass: " .. tostring(armor.ArmorClass))
end

-- BaseHp (test)
local baseHp = entity:GetComponent("BaseHp")
if baseHp then
    _P("BaseHp.Vitality: " .. tostring(baseHp.Vitality))
end

-- BaseStats (test)
local baseStats = entity:GetComponent("BaseStats")
if baseStats then
    _P("BaseStats.BaseAbilities: " .. Ext.Json.Stringify(baseStats.BaseAbilities))
end
```

### 1.2 Expected Issues
- TypeId not being set on layouts (check `component_property_set_type_index` is called)
- Offset mismatches between Windows x64 and macOS ARM64

### 1.3 Files to Check
- `src/entity/entity_system.c` - `discover_component_type_ids()` function
- Verify it calls `component_property_set_type_index()` for each discovered component

---

## Phase 2: Add TransformComponent

### 2.1 Windows Reference (from BG3Extender)
```cpp
struct Transform {
    glm::quat RotationQuat;  // +0x00 (16 bytes) - quaternion (x,y,z,w)
    glm::vec3 Translate;     // +0x10 (12 bytes) - position
    glm::vec3 Scale;         // +0x1C (12 bytes) - scale
};

struct TransformComponent : public BaseComponent {
    Transform Transform;     // +0x00
};
```

### 2.2 Add to component_offsets.h
```c
// ============================================================================
// TransformComponent (ls::TransformComponent)
// From: BG3Extender/GameDefinitions/Components/Components.h:435-440
// ============================================================================

static const ComponentPropertyDef g_TransformComponent_Properties[] = {
    { "Rotation",  0x00, FIELD_TYPE_VEC4, 0, true },  // Quaternion (x,y,z,w)
    { "Position",  0x10, FIELD_TYPE_VEC3, 0, true },  // Translation
    { "Scale",     0x1C, FIELD_TYPE_VEC3, 0, true },
};

static const ComponentLayoutDef g_TransformComponent_Layout = {
    .componentName = "ls::TransformComponent",
    .shortName = "Transform",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_TransformComponent_Properties,
    .propertyCount = sizeof(g_TransformComponent_Properties) / sizeof(g_TransformComponent_Properties[0]),
};
```

### 2.3 Register in g_AllComponentLayouts
```c
static const ComponentLayoutDef* g_AllComponentLayouts[] = {
    &g_HealthComponent_Layout,
    &g_BaseHpComponent_Layout,
    &g_ArmorComponent_Layout,
    &g_StatsComponent_Layout,
    &g_BaseStatsComponent_Layout,
    &g_TransformComponent_Layout,  // ADD
    NULL
};
```

---

## Phase 3: Add Remaining Components

### 3.1 LevelComponent
```c
// From Windows BG3SE - minimal component
static const ComponentPropertyDef g_LevelComponent_Properties[] = {
    { "LevelName", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_LevelComponent_Layout = {
    .componentName = "ls::LevelComponent",
    .shortName = "Level",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_LevelComponent_Properties,
    .propertyCount = 1,
};
```

### 3.2 DataComponent (eoc::DataComponent)
Research needed - check Windows BG3SE for struct definition.

### 3.3 Character/Item Components
These are complex - may require runtime probing to discover field layouts on ARM64.

---

## Implementation Order

| Step | Task | Effort | Dependencies |
|------|------|--------|--------------|
| 1 | Verify Stats/Armor/BaseHp/BaseStats in-game | Low | Game running |
| 2 | Debug TypeId→Layout linkage if needed | Low | Step 1 results |
| 3 | Add TransformComponent layout | Low | None |
| 4 | Test Transform properties | Low | Step 3 |
| 5 | Add LevelComponent layout | Low | None |
| 6 | Research DataComponent struct | Medium | Windows BG3SE |
| 7 | Add DataComponent layout | Low | Step 6 |
| 8 | Document remaining (Visual, Physics, Character, Item) | Medium | Research |

---

## Files to Modify

| File | Changes |
|------|---------|
| `src/entity/component_offsets.h` | Add Transform, Level, Data layouts |
| `src/entity/entity_system.c` | Verify TypeId discovery integration |
| `docs/api-reference.md` | Document new component properties |
| `ROADMAP.md` | Update component status |

---

## Success Criteria

- [ ] `entity:GetComponent("Stats").Abilities` returns array of 7 integers
- [ ] `entity:GetComponent("Stats").ProficiencyBonus` returns correct value
- [ ] `entity:GetComponent("Armor").ArmorClass` returns integer
- [ ] `entity:GetComponent("BaseHp").Vitality` returns integer
- [ ] `entity:GetComponent("Transform").Position` returns {x, y, z} table
- [ ] `entity:GetComponent("Transform").Rotation` returns {x, y, z, w} quaternion
- [ ] `entity:GetComponent("Level").LevelName` returns FixedString index
- [ ] All new properties documented in api-reference.md
