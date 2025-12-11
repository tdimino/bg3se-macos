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
    // Array<EntityHandle> Passives at 0x00 - need to expose as special type
    // For now, just expose the count via the array size field
    // Array layout: buf*(8) + size(4) + capacity(4) = at offset 8 for size
    { "PassiveCount", 0x08, FIELD_TYPE_UINT32, 0, true },  // Array.size field
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
    // Array<Guid> Tags at 0x00
    { "TagCount", 0x08, FIELD_TYPE_UINT32, 0, true },  // Array.size field
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
    // Array<ClassInfo> Classes at 0x00
    { "ClassCount", 0x08, FIELD_TYPE_UINT32, 0, true },  // Array.size field
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
// ============================================================================

static const ComponentPropertyDef g_SpellBookComponent_Properties[] = {
    { "Entity",     0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },  // EntityHandle
    // Array<SpellData> Spells at 0x08
    { "SpellCount", 0x10, FIELD_TYPE_UINT32, 0, true },  // Array.size field
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
    NULL  // Sentinel
};

#endif // COMPONENT_OFFSETS_H
