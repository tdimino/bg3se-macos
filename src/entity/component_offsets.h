/**
 * BG3SE-macOS - Component Offset Definitions
 *
 * Data-driven property layouts for ECS components.
 * Offsets are derived from Windows BG3SE GameDefinitions and verified on ARM64.
 *
 * BaseComponent is empty, so all offsets start from 0.
 */

#ifndef COMPONENT_OFFSETS_H
#define COMPONENT_OFFSETS_H

#include "component_property.h"
#include <stddef.h>  // For NULL

// ============================================================================
// HealthComponent (eoc::HealthComponent)
// From: BG3Extender/GameDefinitions/Components/Data.h:57-67
// ============================================================================

static const ComponentPropertyDef g_HealthComponent_Properties[] = {
    { "Hp",             0x00, FIELD_TYPE_INT32, 0, false },
    { "MaxHp",          0x04, FIELD_TYPE_INT32, 0, false },
    { "TemporaryHp",    0x08, FIELD_TYPE_INT32, 0, false },
    { "MaxTemporaryHp", 0x0C, FIELD_TYPE_INT32, 0, false },
    // field_10 is Guid (16 bytes) at 0x10
    { "IsInvulnerable", 0x20, FIELD_TYPE_BOOL,  0, false },
};

static const ComponentLayoutDef g_HealthComponent_Layout = {
    .componentName = "eoc::HealthComponent",
    .shortName = "Health",
    .componentTypeIndex = 0,  // Set dynamically from TypeId discovery
    .componentSize = 0x24,
    .properties = g_HealthComponent_Properties,
    .propertyCount = sizeof(g_HealthComponent_Properties) / sizeof(g_HealthComponent_Properties[0]),
};

// ============================================================================
// BaseHpComponent (eoc::BaseHpComponent)
// From: BG3Extender/GameDefinitions/Components/Stats.h:33-39
// ============================================================================

static const ComponentPropertyDef g_BaseHpComponent_Properties[] = {
    { "Vitality",      0x00, FIELD_TYPE_INT32, 0, false },
    { "VitalityBoost", 0x04, FIELD_TYPE_INT32, 0, false },
};

static const ComponentLayoutDef g_BaseHpComponent_Layout = {
    .componentName = "eoc::BaseHpComponent",
    .shortName = "BaseHp",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_BaseHpComponent_Properties,
    .propertyCount = sizeof(g_BaseHpComponent_Properties) / sizeof(g_BaseHpComponent_Properties[0]),
};

// ============================================================================
// ArmorComponent (eoc::ArmorComponent)
// From: BG3Extender/GameDefinitions/Components/Stats.h:8-17
// ============================================================================

static const ComponentPropertyDef g_ArmorComponent_Properties[] = {
    { "ArmorType",          0x00, FIELD_TYPE_INT32, 0, true },
    { "ArmorClass",         0x04, FIELD_TYPE_INT32, 0, true },
    { "AbilityModifierCap", 0x08, FIELD_TYPE_INT32, 0, true },
    { "ArmorClassAbility",  0x0C, FIELD_TYPE_UINT8, 0, true },
    { "EquipmentType",      0x0D, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_ArmorComponent_Layout = {
    .componentName = "eoc::ArmorComponent",
    .shortName = "Armor",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ArmorComponent_Properties,
    .propertyCount = sizeof(g_ArmorComponent_Properties) / sizeof(g_ArmorComponent_Properties[0]),
};

// ============================================================================
// StatsComponent (eoc::StatsComponent)
// From: BG3Extender/GameDefinitions/Components/Stats.h:113-129
// ============================================================================

static const ComponentPropertyDef g_StatsComponent_Properties[] = {
    { "InitiativeBonus",     0x00, FIELD_TYPE_INT32,       0, true },
    { "Abilities",           0x04, FIELD_TYPE_INT32_ARRAY, 7, true },
    { "AbilityModifiers",    0x20, FIELD_TYPE_INT32_ARRAY, 7, true },
    { "Skills",              0x3C, FIELD_TYPE_INT32_ARRAY, 18, true },
    { "ProficiencyBonus",    0x84, FIELD_TYPE_INT32,       0, true },
    { "SpellCastingAbility", 0x88, FIELD_TYPE_UINT8,       0, true },
    { "ArmorType",           0x94, FIELD_TYPE_INT32,       0, true },
    { "ArmorType2",          0x98, FIELD_TYPE_INT32,       0, true },
    { "UnarmedAttackAbility",0x9C, FIELD_TYPE_UINT8,       0, true },
    { "RangedAttackAbility", 0x9D, FIELD_TYPE_UINT8,       0, true },
};

static const ComponentLayoutDef g_StatsComponent_Layout = {
    .componentName = "eoc::StatsComponent",
    .shortName = "Stats",
    .componentTypeIndex = 0,
    .componentSize = 0xA0,
    .properties = g_StatsComponent_Properties,
    .propertyCount = sizeof(g_StatsComponent_Properties) / sizeof(g_StatsComponent_Properties[0]),
};

// ============================================================================
// BaseStatsComponent (eoc::BaseStatsComponent)
// From: BG3Extender/GameDefinitions/Components/Data.h:97-102
// ============================================================================

static const ComponentPropertyDef g_BaseStatsComponent_Properties[] = {
    { "BaseAbilities", 0x00, FIELD_TYPE_INT32_ARRAY, 7, true },
};

static const ComponentLayoutDef g_BaseStatsComponent_Layout = {
    .componentName = "eoc::BaseStatsComponent",
    .shortName = "BaseStats",
    .componentTypeIndex = 0,
    .componentSize = 0x1C,
    .properties = g_BaseStatsComponent_Properties,
    .propertyCount = sizeof(g_BaseStatsComponent_Properties) / sizeof(g_BaseStatsComponent_Properties[0]),
};

// ============================================================================
// TransformComponent (ls::TransformComponent)
// From: BG3Extender/GameDefinitions/Components/Components.h:435-440
// Note: Transform struct uses glm::quat (16B) + 2x glm::vec3 (12B each)
// ============================================================================

static const ComponentPropertyDef g_TransformComponent_Properties[] = {
    { "Rotation",  0x00, FIELD_TYPE_VEC4, 0, true },  // glm::quat (x,y,z,w)
    { "Position",  0x10, FIELD_TYPE_VEC3, 0, true },  // glm::vec3 (Translate)
    { "Scale",     0x1C, FIELD_TYPE_VEC3, 0, true },  // glm::vec3
};

static const ComponentLayoutDef g_TransformComponent_Layout = {
    .componentName = "ls::TransformComponent",
    .shortName = "Transform",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_TransformComponent_Properties,
    .propertyCount = sizeof(g_TransformComponent_Properties) / sizeof(g_TransformComponent_Properties[0]),
};

// ============================================================================
// LevelComponent (ls::LevelComponent)
// From: BG3Extender/GameDefinitions/Components/Components.h:328-334
// ============================================================================

static const ComponentPropertyDef g_LevelComponent_Properties[] = {
    { "LevelHandle", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },  // EntityHandle field_0
    { "LevelName",   0x08, FIELD_TYPE_FIXEDSTRING,   0, true },  // FixedString
};

static const ComponentLayoutDef g_LevelComponent_Layout = {
    .componentName = "ls::LevelComponent",
    .shortName = "Level",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_LevelComponent_Properties,
    .propertyCount = sizeof(g_LevelComponent_Properties) / sizeof(g_LevelComponent_Properties[0]),
};

// ============================================================================
// DataComponent (eoc::DataComponent)
// From: BG3Extender/GameDefinitions/Components/Stats.h:55-62
// ============================================================================

static const ComponentPropertyDef g_DataComponent_Properties[] = {
    { "Weight",    0x00, FIELD_TYPE_INT32,       0, true },  // int32_t
    { "StatsId",   0x04, FIELD_TYPE_FIXEDSTRING, 0, true },  // FixedString index
    { "StepsType", 0x08, FIELD_TYPE_UINT32,      0, true },  // uint32_t
};

static const ComponentLayoutDef g_DataComponent_Layout = {
    .componentName = "eoc::DataComponent",
    .shortName = "Data",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_DataComponent_Properties,
    .propertyCount = sizeof(g_DataComponent_Properties) / sizeof(g_DataComponent_Properties[0]),
};

// ============================================================================
// ExperienceComponent (eoc::exp::ExperienceComponent)
// From: BG3Extender/GameDefinitions/Components/Data.h:625-633
// ============================================================================

static const ComponentPropertyDef g_ExperienceComponent_Properties[] = {
    { "CurrentLevelExperience", 0x00, FIELD_TYPE_INT32, 0, true },
    { "NextLevelExperience",    0x04, FIELD_TYPE_INT32, 0, true },
    { "TotalExperience",        0x08, FIELD_TYPE_INT32, 0, true },
    // field_28 is uint8_t at 0x0C (padding suggests 0x0C, not 0x28)
};

static const ComponentLayoutDef g_ExperienceComponent_Layout = {
    .componentName = "eoc::exp::ExperienceComponent",
    .shortName = "Experience",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ExperienceComponent_Properties,
    .propertyCount = sizeof(g_ExperienceComponent_Properties) / sizeof(g_ExperienceComponent_Properties[0]),
};

// ============================================================================
// AvailableLevelComponent (eoc::exp::AvailableLevelComponent)
// From: BG3Extender/GameDefinitions/Components/Data.h:635-640
// ============================================================================

static const ComponentPropertyDef g_AvailableLevelComponent_Properties[] = {
    { "Level", 0x00, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_AvailableLevelComponent_Layout = {
    .componentName = "eoc::exp::AvailableLevelComponent",
    .shortName = "AvailableLevel",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_AvailableLevelComponent_Properties,
    .propertyCount = sizeof(g_AvailableLevelComponent_Properties) / sizeof(g_AvailableLevelComponent_Properties[0]),
};

// ============================================================================
// EocLevelComponent (eoc::LevelComponent) - Character Level
// From: BG3Extender/GameDefinitions/Components/Stats.h:95-100
// Note: Different from ls::LevelComponent (world level name)
// ============================================================================

static const ComponentPropertyDef g_EocLevelComponent_Properties[] = {
    { "Level", 0x00, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_EocLevelComponent_Layout = {
    .componentName = "eoc::LevelComponent",
    .shortName = "EocLevel",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_EocLevelComponent_Properties,
    .propertyCount = sizeof(g_EocLevelComponent_Properties) / sizeof(g_EocLevelComponent_Properties[0]),
};

// ============================================================================
// PassiveComponent (eoc::PassiveComponent)
// From: BG3Extender/GameDefinitions/Components/Passives.h:15-26
// ============================================================================

static const ComponentPropertyDef g_PassiveComponent_Properties[] = {
    { "Type",       0x00, FIELD_TYPE_UINT32,        0, true },  // PassiveSourceType enum
    { "PassiveId",  0x04, FIELD_TYPE_FIXEDSTRING,   0, true },  // FixedString
    { "Source",     0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },  // EntityHandle
    { "Item",       0x10, FIELD_TYPE_ENTITY_HANDLE, 0, true },  // EntityHandle
    { "ToggledOn",  0x18, FIELD_TYPE_BOOL,          0, true },  // bool
    { "Disabled",   0x19, FIELD_TYPE_BOOL,          0, true },  // bool
};

static const ComponentLayoutDef g_PassiveComponent_Layout = {
    .componentName = "eoc::PassiveComponent",
    .shortName = "Passive",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_PassiveComponent_Properties,
    .propertyCount = sizeof(g_PassiveComponent_Properties) / sizeof(g_PassiveComponent_Properties[0]),
};

// ============================================================================
// ResistancesComponent (eoc::ResistancesComponent)
// From: BG3Extender/GameDefinitions/Components/Stats.h:102-111
// Note: Complex arrays - exposing AC and simple fields only for now
// ============================================================================

static const ComponentPropertyDef g_ResistancesComponent_Properties[] = {
    // Resistances array (14 x ResistanceBoostFlags) at 0x00 - needs ENUM_ARRAY
    { "AC",         0x10, FIELD_TYPE_INT32, 0, true },  // After 14 bytes of flags + 1 byte field + padding
    // PerDamageTypeHealthThresholds arrays are complex, skipping for now
};

static const ComponentLayoutDef g_ResistancesComponent_Layout = {
    .componentName = "eoc::ResistancesComponent",
    .shortName = "Resistances",
    .componentTypeIndex = 0,
    .componentSize = 0x70,  // Estimated based on arrays
    .properties = g_ResistancesComponent_Properties,
    .propertyCount = sizeof(g_ResistancesComponent_Properties) / sizeof(g_ResistancesComponent_Properties[0]),
};

// ============================================================================
// PassiveContainerComponent (eoc::PassiveContainerComponent)
// From: BG3Extender/GameDefinitions/Components/Passives.h:8-13
// Note: Contains Array<EntityHandle>, exposed as count only for now
// ============================================================================

static const ComponentPropertyDef g_PassiveContainerComponent_Properties[] = {
    // Array<EntityHandle> Passives at 0x00 - each EntityHandle is 8 bytes
    { "Passives",     0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true, ELEM_TYPE_ENTITY_HANDLE, 8 },
    { "PassiveCount", 0x0C, FIELD_TYPE_UINT32, 0, true, ELEM_TYPE_UNKNOWN, 0 },  // Array.size field
};

static const ComponentLayoutDef g_PassiveContainerComponent_Layout = {
    .componentName = "eoc::PassiveContainerComponent",
    .shortName = "PassiveContainer",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_PassiveContainerComponent_Properties,
    .propertyCount = sizeof(g_PassiveContainerComponent_Properties) / sizeof(g_PassiveContainerComponent_Properties[0]),
};

// ============================================================================
// TagComponent (eoc::TagComponent)
// From: BG3Extender/GameDefinitions/Components/Components.h:40-45
// Note: Contains Array<Guid>, exposed as count only for now
// ============================================================================

static const ComponentPropertyDef g_TagComponent_Properties[] = {
    // Array<Guid> Tags at 0x00 - each Guid is 16 bytes
    { "Tags",     0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true, ELEM_TYPE_GUID, 16 },
    { "TagCount", 0x0C, FIELD_TYPE_UINT32, 0, true, ELEM_TYPE_UNKNOWN, 0 },  // Array.size field
};

static const ComponentLayoutDef g_TagComponent_Layout = {
    .componentName = "eoc::TagComponent",
    .shortName = "Tag",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_TagComponent_Properties,
    .propertyCount = sizeof(g_TagComponent_Properties) / sizeof(g_TagComponent_Properties[0]),
};

// ============================================================================
// RaceComponent (eoc::RaceComponent)
// From: BG3Extender/GameDefinitions/Components/Data.h:492-497
// ============================================================================

static const ComponentPropertyDef g_RaceComponent_Properties[] = {
    { "Race", 0x00, FIELD_TYPE_GUID, 0, true },  // Guid
};

static const ComponentLayoutDef g_RaceComponent_Layout = {
    .componentName = "eoc::RaceComponent",
    .shortName = "Race",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_RaceComponent_Properties,
    .propertyCount = sizeof(g_RaceComponent_Properties) / sizeof(g_RaceComponent_Properties[0]),
};

// ============================================================================
// OriginComponent (eoc::OriginComponent)
// From: BG3Extender/GameDefinitions/Components/Components.h:111-116
// ============================================================================

static const ComponentPropertyDef g_OriginComponent_Properties[] = {
    { "field_18", 0x00, FIELD_TYPE_GUID,        0, true },  // Guid (unknown purpose)
    { "Origin",   0x10, FIELD_TYPE_FIXEDSTRING, 0, true },  // FixedString origin name
};

static const ComponentLayoutDef g_OriginComponent_Layout = {
    .componentName = "eoc::OriginComponent",
    .shortName = "Origin",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_OriginComponent_Properties,
    .propertyCount = sizeof(g_OriginComponent_Properties) / sizeof(g_OriginComponent_Properties[0]),
};

// ============================================================================
// ClassesComponent (eoc::ClassesComponent)
// From: BG3Extender/GameDefinitions/Components/Stats.h:48-53
// Note: Contains Array<ClassInfo>, exposed as count only for now
// ============================================================================

static const ComponentPropertyDef g_ClassesComponent_Properties[] = {
    // Array<ClassInfo> Classes at 0x00 - ClassInfo is 40 bytes (2x Guid + Level + padding)
    { "Classes",    0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true, ELEM_TYPE_CLASS_INFO, 40 },
    { "ClassCount", 0x0C, FIELD_TYPE_UINT32, 0, true, ELEM_TYPE_UNKNOWN, 0 },  // Array.size field
};

static const ComponentLayoutDef g_ClassesComponent_Layout = {
    .componentName = "eoc::ClassesComponent",
    .shortName = "Classes",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ClassesComponent_Properties,
    .propertyCount = sizeof(g_ClassesComponent_Properties) / sizeof(g_ClassesComponent_Properties[0]),
};

// ============================================================================
// MovementComponent (eoc::MovementComponent)
// From: BG3Extender/GameDefinitions/Components/Data.h:508-516
// ============================================================================

static const ComponentPropertyDef g_MovementComponent_Properties[] = {
    { "Direction",    0x00, FIELD_TYPE_VEC3,  0, true },  // glm::vec3
    { "Acceleration", 0x0C, FIELD_TYPE_FLOAT, 0, true },  // float
    { "Speed",        0x10, FIELD_TYPE_FLOAT, 0, true },  // float
    { "Speed2",       0x14, FIELD_TYPE_FLOAT, 0, true },  // float
};

static const ComponentLayoutDef g_MovementComponent_Layout = {
    .componentName = "eoc::MovementComponent",
    .shortName = "Movement",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_MovementComponent_Properties,
    .propertyCount = sizeof(g_MovementComponent_Properties) / sizeof(g_MovementComponent_Properties[0]),
};

// ============================================================================
// BackgroundComponent (eoc::BackgroundComponent)
// From: BG3Extender/GameDefinitions/Components/Data.h:118-123
// ============================================================================

static const ComponentPropertyDef g_BackgroundComponent_Properties[] = {
    { "Background", 0x00, FIELD_TYPE_GUID, 0, true },  // Guid
};

static const ComponentLayoutDef g_BackgroundComponent_Layout = {
    .componentName = "eoc::BackgroundComponent",
    .shortName = "Background",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_BackgroundComponent_Properties,
    .propertyCount = sizeof(g_BackgroundComponent_Properties) / sizeof(g_BackgroundComponent_Properties[0]),
};

// ============================================================================
// GodComponent (eoc::god::GodComponent)
// From: BG3Extender/GameDefinitions/Components/Data.h:125-131
// Note: std::optional<Guid> = 1 byte has_value + 16 bytes Guid = 17 bytes
// ============================================================================

static const ComponentPropertyDef g_GodComponent_Properties[] = {
    { "God",            0x00, FIELD_TYPE_GUID, 0, true },  // Guid
    // GodOverride is std::optional<Guid>: has_value byte at 0x10, then Guid at 0x11
    // Alignment may push Guid to 0x18, check at runtime
    { "HasGodOverride", 0x10, FIELD_TYPE_BOOL, 0, true },  // optional::has_value
    { "GodOverride",    0x18, FIELD_TYPE_GUID, 0, true },  // optional::value (aligned)
};

static const ComponentLayoutDef g_GodComponent_Layout = {
    .componentName = "eoc::god::GodComponent",
    .shortName = "God",
    .componentTypeIndex = 0,
    .componentSize = 0x28,  // 16 (God) + 8 (padding) + 1 (has) + 7 (pad) + 16 (override)
    .properties = g_GodComponent_Properties,
    .propertyCount = sizeof(g_GodComponent_Properties) / sizeof(g_GodComponent_Properties[0]),
};

// ============================================================================
// ValueComponent (eoc::ValueComponent)
// From: BG3Extender/GameDefinitions/Components/Stats.h:147-154
// ============================================================================

static const ComponentPropertyDef g_ValueComponent_Properties[] = {
    { "Value",  0x00, FIELD_TYPE_INT32, 0, true },  // int32_t
    { "Rarity", 0x04, FIELD_TYPE_UINT8, 0, true },  // uint8_t enum
    { "Unique", 0x05, FIELD_TYPE_BOOL,  0, true },  // bool
};

static const ComponentLayoutDef g_ValueComponent_Layout = {
    .componentName = "eoc::ValueComponent",
    .shortName = "Value",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_ValueComponent_Properties,
    .propertyCount = sizeof(g_ValueComponent_Properties) / sizeof(g_ValueComponent_Properties[0]),
};

// ============================================================================
// TurnBasedComponent (eoc::TurnBasedComponent)
// From: BG3Extender/GameDefinitions/Components/Combat.h:54-69
// Note: Multiple bool fields, optional floats (8 bytes each), then Guid
// ============================================================================

static const ComponentPropertyDef g_TurnBasedComponent_Properties[] = {
    { "IsActiveCombatTurn",    0x00, FIELD_TYPE_BOOL, 0, true },
    { "Removed",               0x01, FIELD_TYPE_BOOL, 0, true },
    { "RequestedEndTurn",      0x02, FIELD_TYPE_BOOL, 0, true },
    { "TurnActionsCompleted",  0x03, FIELD_TYPE_BOOL, 0, true },
    { "ActedThisRoundInCombat",0x04, FIELD_TYPE_BOOL, 0, true },
    { "HadTurnInCombat",       0x05, FIELD_TYPE_BOOL, 0, true },
    { "CanActInCombat",        0x06, FIELD_TYPE_BOOL, 0, true },
    // 0x08: std::optional<float> Timeout (8 bytes: has_value + pad + float)
    // 0x10: std::optional<float> PauseTimer
    // 0x18: std::optional<float> EndTurnHoldTimer
    // 0x20: Guid CombatTeam (16 bytes)
    { "CombatTeam",            0x20, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_TurnBasedComponent_Layout = {
    .componentName = "eoc::TurnBasedComponent",
    .shortName = "TurnBased",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_TurnBasedComponent_Properties,
    .propertyCount = sizeof(g_TurnBasedComponent_Properties) / sizeof(g_TurnBasedComponent_Properties[0]),
};

// ============================================================================
// WeaponComponent (eoc::WeaponComponent)
// From: BG3Extender/GameDefinitions/Components/Stats.h:156-171
// Note: Has LegacyRefMap at start, so floats are after those
// ============================================================================

static const ComponentPropertyDef g_WeaponComponent_Properties[] = {
    // LegacyRefMap<AbilityId, Array<RollDefinition>> Rolls at 0x00 (complex, skip)
    // LegacyRefMap<AbilityId, Array<RollDefinition>> Rolls2 at 0x?? (complex, skip)
    // Estimate: 2 RefMaps ~= 0x30 each = 0x60, then floats
    { "WeaponRange",      0x60, FIELD_TYPE_FLOAT,  0, true },
    { "DamageRange",      0x64, FIELD_TYPE_FLOAT,  0, true },
    // WeaponFunctors* at 0x68 (pointer, skip)
    { "WeaponProperties", 0x70, FIELD_TYPE_UINT32, 0, true },  // Flags
    { "WeaponGroup",      0x74, FIELD_TYPE_UINT8,  0, true },
    { "Ability",          0x75, FIELD_TYPE_UINT8,  0, true },  // AbilityId enum
    // Array<StatsExpressionWithMetadata> DamageValues after
    // DiceSizeId at end
};

static const ComponentLayoutDef g_WeaponComponent_Layout = {
    .componentName = "eoc::WeaponComponent",
    .shortName = "Weapon",
    .componentTypeIndex = 0,
    .componentSize = 0x90,  // Estimate
    .properties = g_WeaponComponent_Properties,
    .propertyCount = sizeof(g_WeaponComponent_Properties) / sizeof(g_WeaponComponent_Properties[0]),
};

// ============================================================================
// SpellBookComponent (eoc::spell::BookComponent)
// From: BG3Extender/GameDefinitions/Components/Spell.h:217-223
// Array<SpellData> layout: buf_(0x00), capacity_(0x08), size_(0x0C)
// SpellData estimated size: ~88 bytes (contains SpellId, Guid, etc.)
// ============================================================================

static const ComponentPropertyDef g_SpellBookComponent_Properties[] = {
    { "Entity",     0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true, ELEM_TYPE_UNKNOWN, 0 },
    // Array<SpellData> Spells at 0x08 - dynamic array with iteration support
    { "Spells",     0x08, FIELD_TYPE_DYNAMIC_ARRAY, 0, true, ELEM_TYPE_SPELL_DATA, 88 },
    // Also expose count for convenience
    { "SpellCount", 0x14, FIELD_TYPE_UINT32, 0, true, ELEM_TYPE_UNKNOWN, 0 },  // Array.size_ at 0x08+0x0C
};

static const ComponentLayoutDef g_SpellBookComponent_Layout = {
    .componentName = "eoc::spell::BookComponent",
    .shortName = "SpellBook",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_SpellBookComponent_Properties,
    .propertyCount = sizeof(g_SpellBookComponent_Properties) / sizeof(g_SpellBookComponent_Properties[0]),
};

// ============================================================================
// StatusContainerComponent (eoc::status::ContainerComponent)
// From: BG3Extender/GameDefinitions/Components/Status.h:5-10
// Note: Contains HashMap<EntityHandle, FixedString>, exposed as count
// ============================================================================

static const ComponentPropertyDef g_StatusContainerComponent_Properties[] = {
    // HashMap<EntityHandle, FixedString> Statuses at 0x00
    // HashMap layout: HashSet (0x40) contains count at offset ~0x18
    { "StatusCount", 0x18, FIELD_TYPE_UINT32, 0, true },  // HashMap element count
};

static const ComponentLayoutDef g_StatusContainerComponent_Layout = {
    .componentName = "eoc::status::ContainerComponent",
    .shortName = "StatusContainer",
    .componentTypeIndex = 0,
    .componentSize = 0x48,  // HashMap size estimate
    .properties = g_StatusContainerComponent_Properties,
    .propertyCount = sizeof(g_StatusContainerComponent_Properties) / sizeof(g_StatusContainerComponent_Properties[0]),
};

// ============================================================================
// InventoryContainerComponent (eoc::inventory::ContainerComponent)
// From: BG3Extender/GameDefinitions/Components/Inventory.h:34-39
// Note: Contains HashMap<uint16_t, ContainerSlotData>, exposed as count
// ============================================================================

static const ComponentPropertyDef g_InventoryContainerComponent_Properties[] = {
    // HashMap<uint16_t, ContainerSlotData> Items at 0x00
    { "ItemCount", 0x18, FIELD_TYPE_UINT32, 0, true },  // HashMap element count
};

static const ComponentLayoutDef g_InventoryContainerComponent_Layout = {
    .componentName = "eoc::inventory::ContainerComponent",
    .shortName = "InventoryContainer",
    .componentTypeIndex = 0,
    .componentSize = 0x48,
    .properties = g_InventoryContainerComponent_Properties,
    .propertyCount = sizeof(g_InventoryContainerComponent_Properties) / sizeof(g_InventoryContainerComponent_Properties[0]),
};

// ============================================================================
// ActionResourcesComponent (eoc::ActionResourcesComponent)
// From: BG3Extender/GameDefinitions/Components/ActionResources.h:63-68
// Note: Contains HashMap<Guid, Array<ActionResourceEntry>>, exposed as count
// ============================================================================

static const ComponentPropertyDef g_ActionResourcesComponent_Properties[] = {
    // HashMap<Guid, Array<ActionResourceEntry>> Resources at 0x00
    { "ResourceTypeCount", 0x18, FIELD_TYPE_UINT32, 0, true },  // HashMap element count
};

static const ComponentLayoutDef g_ActionResourcesComponent_Layout = {
    .componentName = "eoc::ActionResourcesComponent",
    .shortName = "ActionResources",
    .componentTypeIndex = 0,
    .componentSize = 0x48,
    .properties = g_ActionResourcesComponent_Properties,
    .propertyCount = sizeof(g_ActionResourcesComponent_Properties) / sizeof(g_ActionResourcesComponent_Properties[0]),
};

// ============================================================================
// InventoryOwnerComponent (eoc::inventory::OwnerComponent)
// From: BG3Extender/GameDefinitions/Components/Inventory.h:15-20
// On characters - links to their inventory entity
// ============================================================================

static const ComponentPropertyDef g_InventoryOwnerComponent_Properties[] = {
    // Array<EntityHandle> Inventories at 0x00 (ptr + size + capacity = 24 bytes)
    { "InventoryCount",    0x08, FIELD_TYPE_UINT32,        0, true },  // Array size
    { "PrimaryInventory",  0x18, FIELD_TYPE_ENTITY_HANDLE, 0, true },  // EntityHandle
};

static const ComponentLayoutDef g_InventoryOwnerComponent_Layout = {
    .componentName = "eoc::inventory::OwnerComponent",
    .shortName = "InventoryOwner",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_InventoryOwnerComponent_Properties,
    .propertyCount = sizeof(g_InventoryOwnerComponent_Properties) / sizeof(g_InventoryOwnerComponent_Properties[0]),
};

// ============================================================================
// InventoryMemberComponent (eoc::inventory::MemberComponent)
// From: BG3Extender/GameDefinitions/Components/Inventory.h:22-27
// On items - links back to containing inventory and equipment slot
// ============================================================================

static const ComponentPropertyDef g_InventoryMemberComponent_Properties[] = {
    { "Inventory",      0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },  // EntityHandle
    { "EquipmentSlot",  0x08, FIELD_TYPE_INT16,         0, true },  // -1 if not equipped
};

static const ComponentLayoutDef g_InventoryMemberComponent_Layout = {
    .componentName = "eoc::inventory::MemberComponent",
    .shortName = "InventoryMember",
    .componentTypeIndex = 0,
    .componentSize = 0x0C,
    .properties = g_InventoryMemberComponent_Properties,
    .propertyCount = sizeof(g_InventoryMemberComponent_Properties) / sizeof(g_InventoryMemberComponent_Properties[0]),
};

// ============================================================================
// InventoryIsOwnedComponent (eoc::inventory::IsOwnedComponent)
// From: BG3Extender/GameDefinitions/Components/Inventory.h:29-33
// On items - links to owning character
// ============================================================================

static const ComponentPropertyDef g_InventoryIsOwnedComponent_Properties[] = {
    { "Owner", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },  // EntityHandle to owner
};

static const ComponentLayoutDef g_InventoryIsOwnedComponent_Layout = {
    .componentName = "eoc::inventory::IsOwnedComponent",
    .shortName = "InventoryIsOwned",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_InventoryIsOwnedComponent_Properties,
    .propertyCount = sizeof(g_InventoryIsOwnedComponent_Properties) / sizeof(g_InventoryIsOwnedComponent_Properties[0]),
};

// ============================================================================
// EquipableComponent (eoc::EquipableComponent)
// From: BG3Extender/GameDefinitions/Components/Stats.h:80-86
// On equippable items - indicates which slot type
// ============================================================================

static const ComponentPropertyDef g_EquipableComponent_Properties[] = {
    { "EquipmentTypeID", 0x00, FIELD_TYPE_GUID,  0, true },  // Guid (16 bytes)
    { "Slot",            0x10, FIELD_TYPE_UINT8, 0, true },  // ItemSlot enum
};

static const ComponentLayoutDef g_EquipableComponent_Layout = {
    .componentName = "eoc::EquipableComponent",
    .shortName = "Equipable",
    .componentTypeIndex = 0,
    .componentSize = 0x14,
    .properties = g_EquipableComponent_Properties,
    .propertyCount = sizeof(g_EquipableComponent_Properties) / sizeof(g_EquipableComponent_Properties[0]),
};

// ============================================================================
// SpellContainerComponent (eoc::spell::ContainerComponent)
// From: BG3Extender/GameDefinitions/Components/Spell.h:117-122
// Note: Contains Array<SpellMeta>, exposed as count for now
// ============================================================================

static const ComponentPropertyDef g_SpellContainerComponent_Properties[] = {
    // Array<SpellMeta> Spells at 0x00 - SpellMeta is 80 bytes
    { "Spells",     0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true, ELEM_TYPE_SPELL_META, 80 },
    { "SpellCount", 0x0C, FIELD_TYPE_UINT32, 0, true, ELEM_TYPE_UNKNOWN, 0 },  // Array.size field
};

static const ComponentLayoutDef g_SpellContainerComponent_Layout = {
    .componentName = "eoc::spell::ContainerComponent",
    .shortName = "SpellContainer",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_SpellContainerComponent_Properties,
    .propertyCount = sizeof(g_SpellContainerComponent_Properties) / sizeof(g_SpellContainerComponent_Properties[0]),
};

// ============================================================================
// ConcentrationComponent (eoc::concentration::ConcentrationComponent)
// From: BG3Extender/GameDefinitions/Components/Data.h:413-420
// ============================================================================

static const ComponentPropertyDef g_ConcentrationComponent_Properties[] = {
    { "Caster",      0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },  // EntityHandle
    // Array<ConcentrationTarget> Targets at 0x08 (complex, expose count only)
    { "TargetCount", 0x10, FIELD_TYPE_UINT32, 0, true },  // Array.size field
    // SpellId at 0x18 is complex (FixedString + padding + enum + 2x Guid = ~0x30 bytes)
    // Just expose the spell prototype FixedString
    { "SpellPrototype", 0x18, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_ConcentrationComponent_Layout = {
    .componentName = "eoc::concentration::ConcentrationComponent",
    .shortName = "Concentration",
    .componentTypeIndex = 0,
    .componentSize = 0x50,  // Estimate based on SpellId size
    .properties = g_ConcentrationComponent_Properties,
    .propertyCount = sizeof(g_ConcentrationComponent_Properties) / sizeof(g_ConcentrationComponent_Properties[0]),
};

// ============================================================================
// BoostsContainerComponent (eoc::BoostsContainerComponent)
// From: BG3Extender/GameDefinitions/Components/Boosts.h:24-29
// Note: Contains Array<BoostEntry>, exposed as count
// ============================================================================

static const ComponentPropertyDef g_BoostsContainerComponent_Properties[] = {
    // Array<BoostEntry> Boosts at 0x00 - BoostEntry is 24 bytes (BoostType + padding + Array)
    { "Boosts",         0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true, ELEM_TYPE_BOOST_ENTRY, 24 },
    { "BoostTypeCount", 0x0C, FIELD_TYPE_UINT32, 0, true, ELEM_TYPE_UNKNOWN, 0 },  // Array.size field
};

static const ComponentLayoutDef g_BoostsContainerComponent_Layout = {
    .componentName = "eoc::BoostsContainerComponent",
    .shortName = "BoostsContainer",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_BoostsContainerComponent_Properties,
    .propertyCount = sizeof(g_BoostsContainerComponent_Properties) / sizeof(g_BoostsContainerComponent_Properties[0]),
};

// ============================================================================
// DisplayNameComponent (eoc::DisplayNameComponent)
// From: BG3Extender/GameDefinitions/Components/Visual.h:64-70
// Note: Contains two TranslatedStrings (complex - handle + version = ~16 bytes each)
// ============================================================================

static const ComponentPropertyDef g_DisplayNameComponent_Properties[] = {
    // TranslatedString Name at 0x00 (Handle + Version = ~16 bytes)
    { "NameHandle",   0x00, FIELD_TYPE_FIXEDSTRING, 0, true },  // TranslatedString.Handle
    // TranslatedString Title at 0x10
    { "TitleHandle",  0x10, FIELD_TYPE_FIXEDSTRING, 0, true },  // TranslatedString.Handle
};

static const ComponentLayoutDef g_DisplayNameComponent_Layout = {
    .componentName = "eoc::DisplayNameComponent",
    .shortName = "DisplayName",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_DisplayNameComponent_Properties,
    .propertyCount = sizeof(g_DisplayNameComponent_Properties) / sizeof(g_DisplayNameComponent_Properties[0]),
};

// ============================================================================
// Phase 2 Batch 6 - Simple Components (Issue #33)
// Quick wins - single-field or simple struct components
// ============================================================================

// DeathStateComponent (eoc::death::StateComponent)
// From: BG3Extender/GameDefinitions/Components/Death.h:60-65
static const ComponentPropertyDef g_DeathStateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_UINT32, 0, true },  // Death state enum
};

static const ComponentLayoutDef g_DeathStateComponent_Layout = {
    .componentName = "eoc::death::StateComponent",
    .shortName = "DeathState",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_DeathStateComponent_Properties,
    .propertyCount = sizeof(g_DeathStateComponent_Properties) / sizeof(g_DeathStateComponent_Properties[0]),
};

// DeathTypeComponent (eoc::death::DeathTypeComponent)
// From: BG3Extender/GameDefinitions/Components/Death.h:67-72
static const ComponentPropertyDef g_DeathTypeComponent_Properties[] = {
    { "DeathType", 0x00, FIELD_TYPE_UINT8, 0, true },  // Death type enum
};

static const ComponentLayoutDef g_DeathTypeComponent_Layout = {
    .componentName = "eoc::death::DeathTypeComponent",
    .shortName = "DeathType",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_DeathTypeComponent_Properties,
    .propertyCount = sizeof(g_DeathTypeComponent_Properties) / sizeof(g_DeathTypeComponent_Properties[0]),
};

// InventoryWeightComponent (eoc::inventory::WeightComponent)
// From: BG3Extender/GameDefinitions/Components/Inventory.h:93-98
static const ComponentPropertyDef g_InventoryWeightComponent_Properties[] = {
    { "Weight", 0x00, FIELD_TYPE_INT32, 0, true },  // Total inventory weight
};

static const ComponentLayoutDef g_InventoryWeightComponent_Layout = {
    .componentName = "eoc::inventory::WeightComponent",
    .shortName = "InventoryWeight",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_InventoryWeightComponent_Properties,
    .propertyCount = sizeof(g_InventoryWeightComponent_Properties) / sizeof(g_InventoryWeightComponent_Properties[0]),
};

// ThreatRangeComponent (eoc::combat::ThreatRangeComponent)
// From: BG3Extender/GameDefinitions/Components/Combat.h:115-122
static const ComponentPropertyDef g_ThreatRangeComponent_Properties[] = {
    { "Range",        0x00, FIELD_TYPE_FLOAT, 0, true },  // Threat range
    { "TargetCeiling", 0x04, FIELD_TYPE_FLOAT, 0, true }, // Target ceiling
    { "TargetFloor",   0x08, FIELD_TYPE_FLOAT, 0, true }, // Target floor
};

static const ComponentLayoutDef g_ThreatRangeComponent_Layout = {
    .componentName = "eoc::combat::ThreatRangeComponent",
    .shortName = "ThreatRange",
    .componentTypeIndex = 0,
    .componentSize = 0x0C,
    .properties = g_ThreatRangeComponent_Properties,
    .propertyCount = sizeof(g_ThreatRangeComponent_Properties) / sizeof(g_ThreatRangeComponent_Properties[0]),
};

// IsInCombatComponent (eoc::combat::IsInCombatComponent)
// From: BG3Extender/GameDefinitions/Components/Combat.h:8
// Tag component - no fields, presence indicates entity is in combat
static const ComponentLayoutDef g_IsInCombatComponent_Layout = {
    .componentName = "eoc::combat::IsInCombatComponent",
    .shortName = "IsInCombat",
    .componentTypeIndex = 0,
    .componentSize = 0x00,  // Tag component - no size
    .properties = NULL,     // No properties
    .propertyCount = 0,
};

// ============================================================================
// Phase 2 Batch 7 - Combat Components (Issue #33)
// ============================================================================

// CombatParticipantComponent (eoc::combat::ParticipantComponent)
// From: BG3Extender/GameDefinitions/Components/Combat.h:18-27
static const ComponentPropertyDef g_CombatParticipantComponent_Properties[] = {
    { "CombatHandle",   0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },  // EntityHandle
    { "CombatGroupId",  0x08, FIELD_TYPE_FIXEDSTRING,   0, true },  // FixedString
    { "InitiativeRoll", 0x0C, FIELD_TYPE_INT32,         0, true },  // int
    { "Flags",          0x10, FIELD_TYPE_UINT32,        0, true },  // CombatParticipantFlags
    { "AiHint",         0x18, FIELD_TYPE_GUID,          0, true },  // Guid (aligned to 8)
};

static const ComponentLayoutDef g_CombatParticipantComponent_Layout = {
    .componentName = "eoc::combat::ParticipantComponent",
    .shortName = "CombatParticipant",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_CombatParticipantComponent_Properties,
    .propertyCount = sizeof(g_CombatParticipantComponent_Properties) / sizeof(g_CombatParticipantComponent_Properties[0]),
};

// CombatStateComponent (eoc::combat::StateComponent)
// From: BG3Extender/GameDefinitions/Components/Combat.h:37-52
// NOTE: Only exposing simple leading fields, skipping HashMaps/Arrays
static const ComponentPropertyDef g_CombatStateComponent_Properties[] = {
    { "MyGuid", 0x00, FIELD_TYPE_GUID, 0, true },  // Guid (16 bytes)
};

static const ComponentLayoutDef g_CombatStateComponent_Layout = {
    .componentName = "eoc::combat::StateComponent",
    .shortName = "CombatState",
    .componentTypeIndex = 0,
    .componentSize = 0xD8,  // Full size but only exposing safe fields
    .properties = g_CombatStateComponent_Properties,
    .propertyCount = sizeof(g_CombatStateComponent_Properties) / sizeof(g_CombatStateComponent_Properties[0]),
};

// ============================================================================
// Tag Components (Issue #33) - Zero-field presence components
// Generated by tools/generate_tag_components.py
// Tag components have no fields - their presence on an entity is the data
// Total: 114 tag components (IsInCombatComponent defined above in Batch 6)
// ============================================================================

// === ecl:: namespace tag components ===

// CameraInSelectorMode (ecl::camera::IsInSelectorModeComponent)
static const ComponentLayoutDef g_CameraInSelectorModeComponent_Layout = {
    .componentName = "ecl::camera::IsInSelectorModeComponent",
    .shortName = "CameraInSelectorMode",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// CameraSpellTracking (ecl::camera::SpellTrackingComponent)
static const ComponentLayoutDef g_CameraSpellTrackingComponent_Layout = {
    .componentName = "ecl::camera::SpellTrackingComponent",
    .shortName = "CameraSpellTracking",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// DummyIsCopyingFullPose (ecl::dummy::IsCopyingFullPoseComponent)
static const ComponentLayoutDef g_DummyIsCopyingFullPoseComponent_Layout = {
    .componentName = "ecl::dummy::IsCopyingFullPoseComponent",
    .shortName = "DummyIsCopyingFullPose",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// DummyLoaded (ecl::dummy::LoadedComponent)
static const ComponentLayoutDef g_DummyLoadedComponent_Layout = {
    .componentName = "ecl::dummy::LoadedComponent",
    .shortName = "DummyLoaded",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// === eoc:: namespace tag components ===

// CanTriggerRandomCasts (eoc::CanTriggerRandomCastsComponent)
static const ComponentLayoutDef g_CanTriggerRandomCastsComponent_Layout = {
    .componentName = "eoc::CanTriggerRandomCastsComponent",
    .shortName = "CanTriggerRandomCasts",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ClientControl (eoc::ClientControlComponent)
static const ComponentLayoutDef g_ClientControlComponent_Layout = {
    .componentName = "eoc::ClientControlComponent",
    .shortName = "ClientControl",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// GravityDisabled (eoc::GravityDisabledComponent)
static const ComponentLayoutDef g_GravityDisabledComponent_Layout = {
    .componentName = "eoc::GravityDisabledComponent",
    .shortName = "GravityDisabled",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// IsInTurnBasedMode (eoc::IsInTurnBasedModeComponent)
static const ComponentLayoutDef g_IsInTurnBasedModeComponent_Layout = {
    .componentName = "eoc::IsInTurnBasedModeComponent",
    .shortName = "IsInTurnBasedMode",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// OffStage (eoc::OffStageComponent)
static const ComponentLayoutDef g_OffStageComponent_Layout = {
    .componentName = "eoc::OffStageComponent",
    .shortName = "OffStage",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// PickingState (eoc::PickingStateComponent)
static const ComponentLayoutDef g_PickingStateComponent_Layout = {
    .componentName = "eoc::PickingStateComponent",
    .shortName = "PickingState",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// Player (eoc::PlayerComponent)
static const ComponentLayoutDef g_PlayerComponent_Layout = {
    .componentName = "eoc::PlayerComponent",
    .shortName = "Player",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// SimpleCharacter (eoc::SimpleCharacterComponent)
static const ComponentLayoutDef g_SimpleCharacterComponent_Layout = {
    .componentName = "eoc::SimpleCharacterComponent",
    .shortName = "SimpleCharacter",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// RollInProgress (eoc::active_roll::InProgressComponent)
static const ComponentLayoutDef g_RollInProgressComponent_Layout = {
    .componentName = "eoc::active_roll::InProgressComponent",
    .shortName = "RollInProgress",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// Ambushing (eoc::ambush::AmbushingComponent)
static const ComponentLayoutDef g_AmbushingComponent_Layout = {
    .componentName = "eoc::ambush::AmbushingComponent",
    .shortName = "Ambushing",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// CampPresence (eoc::camp::PresenceComponent)
static const ComponentLayoutDef g_CampPresenceComponent_Layout = {
    .componentName = "eoc::camp::PresenceComponent",
    .shortName = "CampPresence",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// IsCharacter (eoc::character::CharacterComponent)
static const ComponentLayoutDef g_IsCharacterComponent_Layout = {
    .componentName = "eoc::character::CharacterComponent",
    .shortName = "IsCharacter",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// CombatDelayedFanfare (eoc::combat::DelayedFanfareComponent)
static const ComponentLayoutDef g_CombatDelayedFanfareComponent_Layout = {
    .componentName = "eoc::combat::DelayedFanfareComponent",
    .shortName = "CombatDelayedFanfare",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// NOTE: IsInCombatComponent is defined above in Batch 6

// CanLevelUp (eoc::exp::CanLevelUpComponent)
static const ComponentLayoutDef g_CanLevelUpComponent_Layout = {
    .componentName = "eoc::exp::CanLevelUpComponent",
    .shortName = "CanLevelUp",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// IsFalling (eoc::falling::IsFallingComponent)
static const ComponentLayoutDef g_IsFallingComponent_Layout = {
    .componentName = "eoc::falling::IsFallingComponent",
    .shortName = "IsFalling",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// FTBPaused (eoc::ftb::IsFtbPausedComponent)
static const ComponentLayoutDef g_FTBPausedComponent_Layout = {
    .componentName = "eoc::ftb::IsFtbPausedComponent",
    .shortName = "FTBPaused",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// IsInFTB (eoc::ftb::IsInFtbComponent)
static const ComponentLayoutDef g_IsInFTBComponent_Layout = {
    .componentName = "eoc::ftb::IsInFtbComponent",
    .shortName = "IsInFTB",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// HealBlock (eoc::heal::BlockComponent)
static const ComponentLayoutDef g_HealBlockComponent_Layout = {
    .componentName = "eoc::heal::BlockComponent",
    .shortName = "HealBlock",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// HealMaxIncoming (eoc::heal::MaxIncomingComponent)
static const ComponentLayoutDef g_HealMaxIncomingComponent_Layout = {
    .componentName = "eoc::heal::MaxIncomingComponent",
    .shortName = "HealMaxIncoming",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// HealMaxOutgoing (eoc::heal::MaxOutgoingComponent)
static const ComponentLayoutDef g_HealMaxOutgoingComponent_Layout = {
    .componentName = "eoc::heal::MaxOutgoingComponent",
    .shortName = "HealMaxOutgoing",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// CanBeWielded (eoc::improvised_weapon::CanBeWieldedComponent)
static const ComponentLayoutDef g_CanBeWieldedComponent_Layout = {
    .componentName = "eoc::improvised_weapon::CanBeWieldedComponent",
    .shortName = "CanBeWielded",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// CanBeInInventory (eoc::inventory::CanBeInComponent)
static const ComponentLayoutDef g_CanBeInInventoryComponent_Layout = {
    .componentName = "eoc::inventory::CanBeInComponent",
    .shortName = "CanBeInInventory",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// CannotBePickpocketed (eoc::inventory::CannotBePickpocketedComponent)
static const ComponentLayoutDef g_CannotBePickpocketedComponent_Layout = {
    .componentName = "eoc::inventory::CannotBePickpocketedComponent",
    .shortName = "CannotBePickpocketed",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// CannotBeTakenOut (eoc::inventory::CannotBeTakenOutComponent)
static const ComponentLayoutDef g_CannotBeTakenOutComponent_Layout = {
    .componentName = "eoc::inventory::CannotBeTakenOutComponent",
    .shortName = "CannotBeTakenOut",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// DropOnDeathBlocked (eoc::inventory::DropOnDeathBlockedComponent)
static const ComponentLayoutDef g_DropOnDeathBlockedComponent_Layout = {
    .componentName = "eoc::inventory::DropOnDeathBlockedComponent",
    .shortName = "DropOnDeathBlocked",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// InventoryLocked (eoc::inventory::IsLockedComponent)
static const ComponentLayoutDef g_InventoryLockedComponent_Layout = {
    .componentName = "eoc::inventory::IsLockedComponent",
    .shortName = "InventoryLocked",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// NewItemsInside (eoc::inventory::NewItemsInsideComponent)
static const ComponentLayoutDef g_NewItemsInsideComponent_Layout = {
    .componentName = "eoc::inventory::NewItemsInsideComponent",
    .shortName = "NewItemsInside",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// NonTradable (eoc::inventory::NonTradableComponent)
static const ComponentLayoutDef g_NonTradableComponent_Layout = {
    .componentName = "eoc::inventory::NonTradableComponent",
    .shortName = "NonTradable",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ItemDestroying (eoc::item::DestroyingComponent)
static const ComponentLayoutDef g_ItemDestroyingComponent_Layout = {
    .componentName = "eoc::item::DestroyingComponent",
    .shortName = "ItemDestroying",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// IsDoor (eoc::item::DoorComponent)
static const ComponentLayoutDef g_IsDoorComponent_Layout = {
    .componentName = "eoc::item::DoorComponent",
    .shortName = "IsDoor",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ExamineDisabled (eoc::item::ExamineDisabledComponent)
static const ComponentLayoutDef g_ExamineDisabledComponent_Layout = {
    .componentName = "eoc::item::ExamineDisabledComponent",
    .shortName = "ExamineDisabled",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ItemHasMoved (eoc::item::HasMovedComponent)
static const ComponentLayoutDef g_ItemHasMovedComponent_Layout = {
    .componentName = "eoc::item::HasMovedComponent",
    .shortName = "ItemHasMoved",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// HasOpened (eoc::item::HasOpenedComponent)
static const ComponentLayoutDef g_HasOpenedComponent_Layout = {
    .componentName = "eoc::item::HasOpenedComponent",
    .shortName = "HasOpened",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ItemInUse (eoc::item::InUseComponent)
static const ComponentLayoutDef g_ItemInUseComponent_Layout = {
    .componentName = "eoc::item::InUseComponent",
    .shortName = "ItemInUse",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// IsGold (eoc::item::IsGoldComponent)
static const ComponentLayoutDef g_IsGoldComponent_Layout = {
    .componentName = "eoc::item::IsGoldComponent",
    .shortName = "IsGold",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ItemIsPoisoned (eoc::item::IsPoisonedComponent)
static const ComponentLayoutDef g_ItemIsPoisonedComponent_Layout = {
    .componentName = "eoc::item::IsPoisonedComponent",
    .shortName = "ItemIsPoisoned",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// IsItem (eoc::item::ItemComponent)
static const ComponentLayoutDef g_IsItemComponent_Layout = {
    .componentName = "eoc::item::ItemComponent",
    .shortName = "IsItem",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// NewInInventory (eoc::item::NewInInventoryComponent)
static const ComponentLayoutDef g_NewInInventoryComponent_Layout = {
    .componentName = "eoc::item::NewInInventoryComponent",
    .shortName = "NewInInventory",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ShouldDestroyOnSpellCast (eoc::item::ShouldDestroyOnSpellCastComponent)
static const ComponentLayoutDef g_ShouldDestroyOnSpellCastComponent_Layout = {
    .componentName = "eoc::item::ShouldDestroyOnSpellCastComponent",
    .shortName = "ShouldDestroyOnSpellCast",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ItemCanMove (eoc::item_template::CanMoveComponent)
static const ComponentLayoutDef g_ItemCanMoveComponent_Layout = {
    .componentName = "eoc::item_template::CanMoveComponent",
    .shortName = "ItemCanMove",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ClimbOn (eoc::item_template::ClimbOnComponent)
static const ComponentLayoutDef g_ClimbOnComponent_Layout = {
    .componentName = "eoc::item_template::ClimbOnComponent",
    .shortName = "ClimbOn",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ItemTemplateDestroyed (eoc::item_template::DestroyedComponent)
static const ComponentLayoutDef g_ItemTemplateDestroyedComponent_Layout = {
    .componentName = "eoc::item_template::DestroyedComponent",
    .shortName = "ItemTemplateDestroyed",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// InteractionDisabled (eoc::item_template::InteractionDisabledComponent)
static const ComponentLayoutDef g_InteractionDisabledComponent_Layout = {
    .componentName = "eoc::item_template::InteractionDisabledComponent",
    .shortName = "InteractionDisabled",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// IsStoryItem (eoc::item_template::IsStoryItemComponent)
static const ComponentLayoutDef g_IsStoryItemComponent_Layout = {
    .componentName = "eoc::item_template::IsStoryItemComponent",
    .shortName = "IsStoryItem",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// Ladder (eoc::item_template::LadderComponent)
static const ComponentLayoutDef g_LadderComponent_Layout = {
    .componentName = "eoc::item_template::LadderComponent",
    .shortName = "Ladder",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// WalkOn (eoc::item_template::WalkOnComponent)
static const ComponentLayoutDef g_WalkOnComponent_Layout = {
    .componentName = "eoc::item_template::WalkOnComponent",
    .shortName = "WalkOn",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// MultiplayerHost (eoc::multiplayer::HostComponent)
static const ComponentLayoutDef g_MultiplayerHostComponent_Layout = {
    .componentName = "eoc::multiplayer::HostComponent",
    .shortName = "MultiplayerHost",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// OwnedAsLoot (eoc::ownership::OwnedAsLootComponent)
static const ComponentLayoutDef g_OwnedAsLootComponent_Layout = {
    .componentName = "eoc::ownership::OwnedAsLootComponent",
    .shortName = "OwnedAsLoot",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// BlockFollow (eoc::party::BlockFollowComponent)
static const ComponentLayoutDef g_BlockFollowComponent_Layout = {
    .componentName = "eoc::party::BlockFollowComponent",
    .shortName = "BlockFollow",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// CurrentlyFollowingParty (eoc::party::CurrentlyFollowingPartyComponent)
static const ComponentLayoutDef g_CurrentlyFollowingPartyComponent_Layout = {
    .componentName = "eoc::party::CurrentlyFollowingPartyComponent",
    .shortName = "CurrentlyFollowingParty",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// PickUpExecuting (eoc::pickup::PickUpExecutingComponent)
static const ComponentLayoutDef g_PickUpExecutingComponent_Layout = {
    .componentName = "eoc::pickup::PickUpExecutingComponent",
    .shortName = "PickUpExecuting",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// LongRestInScriptPhase (eoc::rest::LongRestInScriptPhase)
static const ComponentLayoutDef g_LongRestInScriptPhaseComponent_Layout = {
    .componentName = "eoc::rest::LongRestInScriptPhase",
    .shortName = "LongRestInScriptPhase",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ShortRest (eoc::rest::ShortRestComponent)
static const ComponentLayoutDef g_ShortRestComponent_Layout = {
    .componentName = "eoc::rest::ShortRestComponent",
    .shortName = "ShortRest",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// SpellCastCanBeTargeted (eoc::spell_cast::CanBeTargetedComponent)
static const ComponentLayoutDef g_SpellCastCanBeTargetedComponent_Layout = {
    .componentName = "eoc::spell_cast::CanBeTargetedComponent",
    .shortName = "SpellCastCanBeTargeted",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// StatusIndicateDarkness (eoc::status::IndicateDarknessComponent)
static const ComponentLayoutDef g_StatusIndicateDarknessComponent_Layout = {
    .componentName = "eoc::status::IndicateDarknessComponent",
    .shortName = "StatusIndicateDarkness",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// FullIllithid (eoc::tadpole_tree::FullIllithidComponent)
static const ComponentLayoutDef g_FullIllithidComponent_Layout = {
    .componentName = "eoc::tadpole_tree::FullIllithidComponent",
    .shortName = "FullIllithid",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// HalfIllithid (eoc::tadpole_tree::HalfIllithidComponent)
static const ComponentLayoutDef g_HalfIllithidComponent_Layout = {
    .componentName = "eoc::tadpole_tree::HalfIllithidComponent",
    .shortName = "HalfIllithid",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// Tadpoled (eoc::tadpole_tree::TadpoledComponent)
static const ComponentLayoutDef g_TadpoledComponent_Layout = {
    .componentName = "eoc::tadpole_tree::TadpoledComponent",
    .shortName = "Tadpoled",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// Avatar (eoc::tag::AvatarComponent)
static const ComponentLayoutDef g_AvatarComponent_Layout = {
    .componentName = "eoc::tag::AvatarComponent",
    .shortName = "Avatar",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// HasExclamationDialog (eoc::tag::HasExclamationDialogComponent)
static const ComponentLayoutDef g_HasExclamationDialogComponent_Layout = {
    .componentName = "eoc::tag::HasExclamationDialogComponent",
    .shortName = "HasExclamationDialog",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// Trader (eoc::tag::TraderComponent)
static const ComponentLayoutDef g_TraderComponent_Layout = {
    .componentName = "eoc::tag::TraderComponent",
    .shortName = "Trader",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// CanSeeThrough (eoc::through::CanSeeThroughComponent)
static const ComponentLayoutDef g_CanSeeThroughComponent_Layout = {
    .componentName = "eoc::through::CanSeeThroughComponent",
    .shortName = "CanSeeThrough",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// CanShootThrough (eoc::through::CanShootThroughComponent)
static const ComponentLayoutDef g_CanShootThroughComponent_Layout = {
    .componentName = "eoc::through::CanShootThroughComponent",
    .shortName = "CanShootThrough",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// CanWalkThrough (eoc::through::CanWalkThroughComponent)
static const ComponentLayoutDef g_CanWalkThroughComponent_Layout = {
    .componentName = "eoc::through::CanWalkThroughComponent",
    .shortName = "CanWalkThrough",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// CanTrade (eoc::trade::CanTradeComponent)
static const ComponentLayoutDef g_CanTradeComponent_Layout = {
    .componentName = "eoc::trade::CanTradeComponent",
    .shortName = "CanTrade",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// === esv:: namespace tag components ===

// IsMarkedForDeletion (esv::IsMarkedForDeletionComponent)
static const ComponentLayoutDef g_IsMarkedForDeletionComponent_Layout = {
    .componentName = "esv::IsMarkedForDeletionComponent",
    .shortName = "IsMarkedForDeletion",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ============================================================================
// OriginalTemplateComponent (eoc::templates::OriginalTemplateComponent)
// From: BG3Extender/GameDefinitions/Components/Components.h:222-228
// Stores the template ID and type for an entity
// ============================================================================

static const ComponentPropertyDef g_OriginalTemplateComponent_Properties[] = {
    { "OriginalTemplate", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },  // Template ID
    { "TemplateType",     0x04, FIELD_TYPE_UINT8,       0, true },  // Template type enum
};

static const ComponentLayoutDef g_OriginalTemplateComponent_Layout = {
    .componentName = "eoc::templates::OriginalTemplateComponent",
    .shortName = "OriginalTemplate",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_OriginalTemplateComponent_Properties,
    .propertyCount = sizeof(g_OriginalTemplateComponent_Properties) / sizeof(g_OriginalTemplateComponent_Properties[0]),
};

// Net (esv::NetComponent)
static const ComponentLayoutDef g_NetComponent_Layout = {
    .componentName = "esv::NetComponent",
    .shortName = "Net",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ScriptPropertyCanBePickpocketed (esv::ScriptPropertyCanBePickpocketedComponent)
static const ComponentLayoutDef g_ScriptPropertyCanBePickpocketedComponent_Layout = {
    .componentName = "esv::ScriptPropertyCanBePickpocketedComponent",
    .shortName = "ScriptPropertyCanBePickpocketed",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ScriptPropertyIsDroppedOnDeath (esv::ScriptPropertyIsDroppedOnDeathComponent)
static const ComponentLayoutDef g_ScriptPropertyIsDroppedOnDeathComponent_Layout = {
    .componentName = "esv::ScriptPropertyIsDroppedOnDeathComponent",
    .shortName = "ScriptPropertyIsDroppedOnDeath",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ScriptPropertyIsTradable (esv::ScriptPropertyIsTradableComponent)
static const ComponentLayoutDef g_ScriptPropertyIsTradableComponent_Layout = {
    .componentName = "esv::ScriptPropertyIsTradableComponent",
    .shortName = "ScriptPropertyIsTradable",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// TurnOrderSkipped (esv::TurnOrderSkippedComponent)
static const ComponentLayoutDef g_TurnOrderSkippedComponent_Layout = {
    .componentName = "esv::TurnOrderSkippedComponent",
    .shortName = "TurnOrderSkipped",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerVariableManager (esv::VariableManagerComponent)
static const ComponentLayoutDef g_ServerVariableManagerComponent_Layout = {
    .componentName = "esv::VariableManagerComponent",
    .shortName = "ServerVariableManager",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerStatusBoostsProcessed (esv::boost::StatusBoostsProcessedComponent)
static const ComponentLayoutDef g_ServerStatusBoostsProcessedComponent_Layout = {
    .componentName = "esv::boost::StatusBoostsProcessedComponent",
    .shortName = "ServerStatusBoostsProcessed",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerCCIsCustom (esv::character_creation::IsCustomComponent)
static const ComponentLayoutDef g_ServerCCIsCustomComponent_Layout = {
    .componentName = "esv::character_creation::IsCustomComponent",
    .shortName = "ServerCCIsCustom",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerCanStartCombat (esv::combat::CanStartCombatComponent)
static const ComponentLayoutDef g_ServerCanStartCombatComponent_Layout = {
    .componentName = "esv::combat::CanStartCombatComponent",
    .shortName = "ServerCanStartCombat",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerFleeBlocked (esv::combat::FleeBlockedComponent)
static const ComponentLayoutDef g_ServerFleeBlockedComponent_Layout = {
    .componentName = "esv::combat::FleeBlockedComponent",
    .shortName = "ServerFleeBlocked",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerImmediateJoin (esv::combat::ImmediateJoinComponent)
static const ComponentLayoutDef g_ServerImmediateJoinComponent_Layout = {
    .componentName = "esv::combat::ImmediateJoinComponent",
    .shortName = "ServerImmediateJoin",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerCombatLeaveRequest (esv::combat::LeaveRequestComponent)
static const ComponentLayoutDef g_ServerCombatLeaveRequestComponent_Layout = {
    .componentName = "esv::combat::LeaveRequestComponent",
    .shortName = "ServerCombatLeaveRequest",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerIsLightBlocker (esv::cover::IsLightBlockerComponent)
static const ComponentLayoutDef g_ServerIsLightBlockerComponent_Layout = {
    .componentName = "esv::cover::IsLightBlockerComponent",
    .shortName = "ServerIsLightBlocker",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerIsVisionBlocker (esv::cover::IsVisionBlockerComponent)
static const ComponentLayoutDef g_ServerIsVisionBlockerComponent_Layout = {
    .componentName = "esv::cover::IsVisionBlockerComponent",
    .shortName = "ServerIsVisionBlocker",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerDarknessActive (esv::darkness::DarknessActiveComponent)
static const ComponentLayoutDef g_ServerDarknessActiveComponent_Layout = {
    .componentName = "esv::darkness::DarknessActiveComponent",
    .shortName = "ServerDarknessActive",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerDeathContinue (esv::death::DeathContinueComponent)
static const ComponentLayoutDef g_ServerDeathContinueComponent_Layout = {
    .componentName = "esv::death::DeathContinueComponent",
    .shortName = "ServerDeathContinue",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// EscortHasStragglers (esv::escort::HasStragglersComponent)
static const ComponentLayoutDef g_EscortHasStragglersComponent_Layout = {
    .componentName = "esv::escort::HasStragglersComponent",
    .shortName = "EscortHasStragglers",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerHotbarOrder (esv::hotbar::OrderComponent)
static const ComponentLayoutDef g_ServerHotbarOrderComponent_Layout = {
    .componentName = "esv::hotbar::OrderComponent",
    .shortName = "ServerHotbarOrder",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// CharacterHasGeneratedTradeTreasure (esv::inventory::CharacterHasGeneratedTradeTreasureComponent)
static const ComponentLayoutDef g_CharacterHasGeneratedTradeTreasureComponent_Layout = {
    .componentName = "esv::inventory::CharacterHasGeneratedTradeTreasureComponent",
    .shortName = "CharacterHasGeneratedTradeTreasure",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// HasGeneratedTreasure (esv::inventory::EntityHasGeneratedTreasureComponent)
static const ComponentLayoutDef g_HasGeneratedTreasureComponent_Layout = {
    .componentName = "esv::inventory::EntityHasGeneratedTreasureComponent",
    .shortName = "HasGeneratedTreasure",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerInventoryIsReplicatedWith (esv::inventory::IsReplicatedWithComponent)
static const ComponentLayoutDef g_ServerInventoryIsReplicatedWithComponent_Layout = {
    .componentName = "esv::inventory::IsReplicatedWithComponent",
    .shortName = "ServerInventoryIsReplicatedWith",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ReadyToBeAddedToInventory (esv::inventory::ReadyToBeAddedToInventoryComponent)
static const ComponentLayoutDef g_ReadyToBeAddedToInventoryComponent_Layout = {
    .componentName = "esv::inventory::ReadyToBeAddedToInventoryComponent",
    .shortName = "ReadyToBeAddedToInventory",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerInventoryItemDataPopulated (esv::level::InventoryItemDataPopulatedComponent)
static const ComponentLayoutDef g_ServerInventoryItemDataPopulatedComponent_Layout = {
    .componentName = "esv::level::InventoryItemDataPopulatedComponent",
    .shortName = "ServerInventoryItemDataPopulated",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ShortRestConsumeResources (esv::rest::ShortRestConsumeResourcesComponent)
static const ComponentLayoutDef g_ShortRestConsumeResourcesComponent_Layout = {
    .componentName = "esv::rest::ShortRestConsumeResourcesComponent",
    .shortName = "ShortRestConsumeResources",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerSightEventsEnabled (esv::sight::EventsEnabledComponent)
static const ComponentLayoutDef g_ServerSightEventsEnabledComponent_Layout = {
    .componentName = "esv::sight::EventsEnabledComponent",
    .shortName = "ServerSightEventsEnabled",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerSpellClientInitiated (esv::spell_cast::ClientInitiatedComponent)
static const ComponentLayoutDef g_ServerSpellClientInitiatedComponent_Layout = {
    .componentName = "esv::spell_cast::ClientInitiatedComponent",
    .shortName = "ServerSpellClientInitiated",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerStatusActive (esv::status::ActiveComponent)
static const ComponentLayoutDef g_ServerStatusActiveComponent_Layout = {
    .componentName = "esv::status::ActiveComponent",
    .shortName = "ServerStatusActive",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerStatusAddedFromSaveLoad (esv::status::AddedFromSaveLoadComponent)
static const ComponentLayoutDef g_ServerStatusAddedFromSaveLoadComponent_Layout = {
    .componentName = "esv::status::AddedFromSaveLoadComponent",
    .shortName = "ServerStatusAddedFromSaveLoad",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerStatusAura (esv::status::AuraComponent)
static const ComponentLayoutDef g_ServerStatusAuraComponent_Layout = {
    .componentName = "esv::status::AuraComponent",
    .shortName = "ServerStatusAura",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerIsUnsummoning (esv::summon::IsUnsummoningComponent)
static const ComponentLayoutDef g_ServerIsUnsummoningComponent_Layout = {
    .componentName = "esv::summon::IsUnsummoningComponent",
    .shortName = "ServerIsUnsummoning",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerTriggerLoadedHandled (esv::trigger::LoadedHandledComponent)
static const ComponentLayoutDef g_ServerTriggerLoadedHandledComponent_Layout = {
    .componentName = "esv::trigger::LoadedHandledComponent",
    .shortName = "ServerTriggerLoadedHandled",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ServerTriggerWorldAutoTriggered (esv::trigger::TriggerWorldAutoTriggeredComponent)
static const ComponentLayoutDef g_ServerTriggerWorldAutoTriggeredComponent_Layout = {
    .componentName = "esv::trigger::TriggerWorldAutoTriggeredComponent",
    .shortName = "ServerTriggerWorldAutoTriggered",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// === ls:: namespace tag components ===

// AlwaysUpdateEffect (ls::AlwaysUpdateEffectComponent)
static const ComponentLayoutDef g_AlwaysUpdateEffectComponent_Layout = {
    .componentName = "ls::AlwaysUpdateEffectComponent",
    .shortName = "AlwaysUpdateEffect",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// AnimationUpdate (ls::AnimationUpdateComponent)
static const ComponentLayoutDef g_AnimationUpdateComponent_Layout = {
    .componentName = "ls::AnimationUpdateComponent",
    .shortName = "AnimationUpdate",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// IsGlobal (ls::IsGlobalComponent)
static const ComponentLayoutDef g_IsGlobalComponent_Layout = {
    .componentName = "ls::IsGlobalComponent",
    .shortName = "IsGlobal",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// IsSeeThrough (ls::IsSeeThroughComponent)
static const ComponentLayoutDef g_IsSeeThroughComponent_Layout = {
    .componentName = "ls::IsSeeThroughComponent",
    .shortName = "IsSeeThrough",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// LevelIsOwner (ls::LevelIsOwnerComponent)
static const ComponentLayoutDef g_LevelIsOwnerComponent_Layout = {
    .componentName = "ls::LevelIsOwnerComponent",
    .shortName = "LevelIsOwner",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// LevelPrepareUnloadBusy (ls::LevelPrepareUnloadBusyComponent)
static const ComponentLayoutDef g_LevelPrepareUnloadBusyComponent_Layout = {
    .componentName = "ls::LevelPrepareUnloadBusyComponent",
    .shortName = "LevelPrepareUnloadBusy",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// LevelUnloadBusy (ls::LevelUnloadBusyComponent)
static const ComponentLayoutDef g_LevelUnloadBusyComponent_Layout = {
    .componentName = "ls::LevelUnloadBusyComponent",
    .shortName = "LevelUnloadBusy",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// Savegame (ls::SavegameComponent)
static const ComponentLayoutDef g_SavegameComponent_Layout = {
    .componentName = "ls::SavegameComponent",
    .shortName = "Savegame",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// VisualLoaded (ls::VisualLoadedComponent)
static const ComponentLayoutDef g_VisualLoadedComponent_Layout = {
    .componentName = "ls::VisualLoadedComponent",
    .shortName = "VisualLoaded",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// Pause (ls::game::PauseComponent)
static const ComponentLayoutDef g_PauseComponent_Layout = {
    .componentName = "ls::game::PauseComponent",
    .shortName = "Pause",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// PauseExcluded (ls::game::PauseExcludedComponent)
static const ComponentLayoutDef g_PauseExcludedComponent_Layout = {
    .componentName = "ls::game::PauseExcludedComponent",
    .shortName = "PauseExcluded",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// LevelInstanceUnloading (ls::level::LevelInstanceUnloadingComponent)
static const ComponentLayoutDef g_LevelInstanceUnloadingComponent_Layout = {
    .componentName = "ls::level::LevelInstanceUnloadingComponent",
    .shortName = "LevelInstanceUnloading",
    .componentTypeIndex = 0,
    .componentSize = 0x00,
    .properties = NULL,
    .propertyCount = 0,
};

// ============================================================================
// All Component Layouts (for bulk registration)
// ============================================================================

static const ComponentLayoutDef* g_AllComponentLayouts[] = {
    &g_HealthComponent_Layout,
    &g_BaseHpComponent_Layout,
    &g_ArmorComponent_Layout,
    &g_StatsComponent_Layout,
    &g_BaseStatsComponent_Layout,
    &g_TransformComponent_Layout,
    &g_LevelComponent_Layout,
    &g_DataComponent_Layout,
    // Phase 2 components (Issue #33)
    &g_ExperienceComponent_Layout,
    &g_AvailableLevelComponent_Layout,
    &g_EocLevelComponent_Layout,
    &g_PassiveComponent_Layout,
    &g_ResistancesComponent_Layout,
    &g_PassiveContainerComponent_Layout,
    &g_TagComponent_Layout,
    &g_RaceComponent_Layout,
    &g_OriginComponent_Layout,
    &g_ClassesComponent_Layout,
    &g_MovementComponent_Layout,
    // Phase 2 batch 2 (Issue #33)
    &g_BackgroundComponent_Layout,
    &g_GodComponent_Layout,
    &g_ValueComponent_Layout,
    &g_TurnBasedComponent_Layout,
    // Phase 2 batch 3 (Issue #33) - High-priority gameplay components
    &g_WeaponComponent_Layout,
    &g_SpellBookComponent_Layout,
    &g_StatusContainerComponent_Layout,
    &g_InventoryContainerComponent_Layout,
    &g_ActionResourcesComponent_Layout,
    // Phase 2 batch 4 (Issue #33) - Inventory relationship components
    &g_InventoryOwnerComponent_Layout,
    &g_InventoryMemberComponent_Layout,
    &g_InventoryIsOwnedComponent_Layout,
    &g_EquipableComponent_Layout,
    // Phase 2 batch 5 (Issue #33) - Spell and boost components
    &g_SpellContainerComponent_Layout,
    &g_ConcentrationComponent_Layout,
    &g_BoostsContainerComponent_Layout,
    &g_DisplayNameComponent_Layout,
    // Phase 2 batch 6 (Issue #33) - Simple components
    &g_DeathStateComponent_Layout,
    &g_DeathTypeComponent_Layout,
    &g_InventoryWeightComponent_Layout,
    &g_ThreatRangeComponent_Layout,
    &g_IsInCombatComponent_Layout,
    // Phase 2 batch 7 (Issue #33) - Combat components
    &g_CombatParticipantComponent_Layout,
    &g_CombatStateComponent_Layout,
    // Phase 2 batch 8 (Issue #33) - Tag components (109 total, all zero-field presence components)
    // Client namespace (ecl::) - 4 components
    &g_CameraInSelectorModeComponent_Layout,
    &g_CameraSpellTrackingComponent_Layout,
    &g_DummyIsCopyingFullPoseComponent_Layout,
    &g_DummyLoadedComponent_Layout,
    // Common namespace (eoc::) - Core gameplay flags
    &g_CanTriggerRandomCastsComponent_Layout,
    &g_ClientControlComponent_Layout,
    &g_GravityDisabledComponent_Layout,
    &g_IsInTurnBasedModeComponent_Layout,
    &g_OffStageComponent_Layout,
    &g_PickingStateComponent_Layout,
    &g_PlayerComponent_Layout,
    &g_SimpleCharacterComponent_Layout,
    &g_RollInProgressComponent_Layout,
    &g_AmbushingComponent_Layout,
    &g_CampPresenceComponent_Layout,
    &g_IsCharacterComponent_Layout,
    &g_CombatDelayedFanfareComponent_Layout,
    &g_CanLevelUpComponent_Layout,
    &g_IsFallingComponent_Layout,
    &g_FTBPausedComponent_Layout,
    &g_IsInFTBComponent_Layout,
    &g_HealBlockComponent_Layout,
    &g_HealMaxIncomingComponent_Layout,
    &g_HealMaxOutgoingComponent_Layout,
    // eoc:: Inventory and item flags
    &g_CanBeWieldedComponent_Layout,
    &g_CanBeInInventoryComponent_Layout,
    &g_CannotBePickpocketedComponent_Layout,
    &g_CannotBeTakenOutComponent_Layout,
    &g_DropOnDeathBlockedComponent_Layout,
    &g_InventoryLockedComponent_Layout,
    &g_NewItemsInsideComponent_Layout,
    &g_NonTradableComponent_Layout,
    &g_ItemDestroyingComponent_Layout,
    &g_IsDoorComponent_Layout,
    &g_ExamineDisabledComponent_Layout,
    &g_ItemHasMovedComponent_Layout,
    &g_HasOpenedComponent_Layout,
    &g_ItemInUseComponent_Layout,
    &g_IsGoldComponent_Layout,
    &g_ItemIsPoisonedComponent_Layout,
    &g_IsItemComponent_Layout,
    &g_NewInInventoryComponent_Layout,
    &g_ShouldDestroyOnSpellCastComponent_Layout,
    &g_ItemCanMoveComponent_Layout,
    &g_ClimbOnComponent_Layout,
    &g_ItemTemplateDestroyedComponent_Layout,
    &g_InteractionDisabledComponent_Layout,
    &g_IsStoryItemComponent_Layout,
    &g_LadderComponent_Layout,
    &g_WalkOnComponent_Layout,
    // eoc:: Party and character flags
    &g_MultiplayerHostComponent_Layout,
    &g_OwnedAsLootComponent_Layout,
    &g_BlockFollowComponent_Layout,
    &g_CurrentlyFollowingPartyComponent_Layout,
    &g_PickUpExecutingComponent_Layout,
    &g_LongRestInScriptPhaseComponent_Layout,
    &g_ShortRestComponent_Layout,
    &g_SpellCastCanBeTargetedComponent_Layout,
    &g_StatusIndicateDarknessComponent_Layout,
    // eoc:: Tadpole state
    &g_FullIllithidComponent_Layout,
    &g_HalfIllithidComponent_Layout,
    &g_TadpoledComponent_Layout,
    // eoc:: Character markers
    &g_AvatarComponent_Layout,
    &g_HasExclamationDialogComponent_Layout,
    &g_TraderComponent_Layout,
    // eoc:: Visibility flags
    &g_CanSeeThroughComponent_Layout,
    &g_CanShootThroughComponent_Layout,
    &g_CanWalkThroughComponent_Layout,
    &g_CanTradeComponent_Layout,
    // eoc:: Misc flags
    &g_IsMarkedForDeletionComponent_Layout,
    &g_ScriptPropertyCanBePickpocketedComponent_Layout,
    &g_ScriptPropertyIsDroppedOnDeathComponent_Layout,
    &g_ScriptPropertyIsTradableComponent_Layout,
    &g_TurnOrderSkippedComponent_Layout,
    // Server namespace (esv::) - Authoritative state flags
    &g_ServerVariableManagerComponent_Layout,
    &g_ServerStatusBoostsProcessedComponent_Layout,
    &g_ServerCCIsCustomComponent_Layout,
    &g_ServerCanStartCombatComponent_Layout,
    &g_ServerFleeBlockedComponent_Layout,
    &g_ServerImmediateJoinComponent_Layout,
    &g_ServerCombatLeaveRequestComponent_Layout,
    &g_ServerIsLightBlockerComponent_Layout,
    &g_ServerIsVisionBlockerComponent_Layout,
    &g_ServerDarknessActiveComponent_Layout,
    &g_ServerDeathContinueComponent_Layout,
    &g_EscortHasStragglersComponent_Layout,
    &g_ServerHotbarOrderComponent_Layout,
    &g_CharacterHasGeneratedTradeTreasureComponent_Layout,
    &g_HasGeneratedTreasureComponent_Layout,
    &g_ServerInventoryIsReplicatedWithComponent_Layout,
    &g_ReadyToBeAddedToInventoryComponent_Layout,
    &g_ServerInventoryItemDataPopulatedComponent_Layout,
    &g_ShortRestConsumeResourcesComponent_Layout,
    &g_ServerSightEventsEnabledComponent_Layout,
    &g_ServerSpellClientInitiatedComponent_Layout,
    &g_ServerStatusActiveComponent_Layout,
    &g_ServerStatusAddedFromSaveLoadComponent_Layout,
    &g_ServerStatusAuraComponent_Layout,
    &g_ServerIsUnsummoningComponent_Layout,
    &g_ServerTriggerLoadedHandledComponent_Layout,
    &g_ServerTriggerWorldAutoTriggeredComponent_Layout,
    // Low-level namespace (ls::) - Engine flags
    &g_AlwaysUpdateEffectComponent_Layout,
    &g_AnimationUpdateComponent_Layout,
    &g_IsGlobalComponent_Layout,
    &g_IsSeeThroughComponent_Layout,
    &g_LevelIsOwnerComponent_Layout,
    &g_LevelPrepareUnloadBusyComponent_Layout,
    &g_LevelUnloadBusyComponent_Layout,
    &g_SavegameComponent_Layout,
    &g_VisualLoadedComponent_Layout,
    &g_PauseComponent_Layout,
    &g_PauseExcludedComponent_Layout,
    &g_LevelInstanceUnloadingComponent_Layout,
    &g_NetComponent_Layout,
    // Template components (Issue #41 - Ext.Template support)
    &g_OriginalTemplateComponent_Layout,
    NULL  // Sentinel
};

#endif // COMPONENT_OFFSETS_H
