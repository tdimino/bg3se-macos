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
// ARM64 Verified: Size 0x28 (via Ghidra AddComponent<eoc::HealthComponent>)
// ============================================================================

static const ComponentPropertyDef g_HealthComponent_Properties[] = {
    { "Hp",             0x00, FIELD_TYPE_INT32, 0, false },
    { "MaxHp",          0x04, FIELD_TYPE_INT32, 0, false },
    { "TemporaryHp",    0x08, FIELD_TYPE_INT32, 0, false },
    { "MaxTemporaryHp", 0x0C, FIELD_TYPE_INT32, 0, false },
    // field_10 is Guid (16 bytes) at 0x10
    { "IsInvulnerable", 0x20, FIELD_TYPE_BOOL,  0, false },
    // Padding/alignment to 0x28
};

static const ComponentLayoutDef g_HealthComponent_Layout = {
    .componentName = "eoc::HealthComponent",
    .shortName = "Health",
    .componentTypeIndex = 0,  // Set dynamically from TypeId discovery
    .componentSize = 0x28,    // ARM64 verified via Ghidra
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
// ARM64 Verified: Size 0x10 (via Ghidra AddComponent<eoc::ArmorComponent>)
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
    .componentSize = 0x10,    // ARM64 verified via Ghidra
    .properties = g_ArmorComponent_Properties,
    .propertyCount = sizeof(g_ArmorComponent_Properties) / sizeof(g_ArmorComponent_Properties[0]),
};

// ============================================================================
// StatsComponent (eoc::StatsComponent)
// From: BG3Extender/GameDefinitions/Components/Stats.h:113-129
// ARM64 Verified: Size 0xa0 (via Ghidra AddComponent<eoc::StatsComponent>)
// Runtime Verified: All properties working (Dec 2025)
// Note: Abilities/AbilityModifiers arrays use index [1]=None, [2-7]=STR/DEX/CON/INT/WIS/CHA
// ============================================================================

static const ComponentPropertyDef g_StatsComponent_Properties[] = {
    { "InitiativeBonus",     0x00, FIELD_TYPE_INT32,       0, true },
    { "Abilities",           0x04, FIELD_TYPE_INT32_ARRAY, 7, true },  // [1]=None, [2]=STR...[7]=CHA
    { "AbilityModifiers",    0x20, FIELD_TYPE_INT32_ARRAY, 7, true },  // Matches Abilities indexing
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
    .componentSize = 0xa0,    // ARM64 verified via Ghidra
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
// ARM64 Verified: Size 0x0c (via Ghidra AddComponent<eoc::DataComponent>)
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
    .componentSize = 0x0c,    // ARM64 verified via Ghidra
    .properties = g_DataComponent_Properties,
    .propertyCount = sizeof(g_DataComponent_Properties) / sizeof(g_DataComponent_Properties[0]),
};

// ============================================================================
// ExperienceComponent (eoc::exp::ExperienceComponent)
// From: BG3Extender/GameDefinitions/Components/Data.h:625-633
// ARM64 Verified: Size 0x18 (via Ghidra AddComponent<eoc::exp::ExperienceComponent>)
// ============================================================================

static const ComponentPropertyDef g_ExperienceComponent_Properties[] = {
    { "CurrentLevelExperience", 0x00, FIELD_TYPE_INT32, 0, true },
    { "NextLevelExperience",    0x04, FIELD_TYPE_INT32, 0, true },
    { "TotalExperience",        0x08, FIELD_TYPE_INT32, 0, true },
    // Additional fields at 0x0C-0x17 (total size 0x18)
};

static const ComponentLayoutDef g_ExperienceComponent_Layout = {
    .componentName = "eoc::exp::ExperienceComponent",
    .shortName = "Experience",
    .componentTypeIndex = 0,
    .componentSize = 0x18,    // ARM64 verified via Ghidra
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
// ARM64 Verified: Size 0x68 (via Ghidra AddComponent<eoc::ResistancesComponent>)
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
    .componentSize = 0x68,    // ARM64 verified via Ghidra
    .properties = g_ResistancesComponent_Properties,
    .propertyCount = sizeof(g_ResistancesComponent_Properties) / sizeof(g_ResistancesComponent_Properties[0]),
};

// ============================================================================
// PassiveContainerComponent (eoc::PassiveContainerComponent)
// From: BG3Extender/GameDefinitions/Components/Passives.h:8-13
// ARM64 Verified: Size 0x10 (via Ghidra AddComponent<eoc::PassiveContainerComponent>)
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
// ARM64 Verified: Size 0x10 (via Ghidra AddComponent<eoc::TagComponent>)
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
// ARM64 Verified: Size 0x10 (via Ghidra AddComponent<eoc::RaceComponent>)
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
// ARM64 Verified: Size 0x18 (via Ghidra AddComponent<eoc::OriginComponent>)
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
// ARM64 Verified: Size 0x10 (via Ghidra AddComponent<eoc::BackgroundComponent>)
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
// ARM64 Verified: Size 0x28 (via Ghidra AddComponent<eoc::god::GodComponent>)
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
// ARM64 Verified: Size 0x30 (via Ghidra AddComponent<eoc::TurnBasedComponent>)
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
// ARM64 Verified: Size 0x40 (via Ghidra AddComponent<eoc::ActionResourcesComponent>)
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
    .componentSize = 0x40,    // ARM64 verified via Ghidra
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
// SpellMeta stride is 0x60 (96 bytes) on ARM64, not the 80 the Windows field
// list suggests. Live-verified on 4.1.1.7398727 (2026-09-14): the SpellId
// FixedString of consecutive entries sits at +0x00, +0x60, +0xC0, +0x120 and
// the 0x60-byte record repeats byte-for-byte from +0x00..+0x5F; a read at
// +0x50 lands mid-record (nil). docs/parity-100/LIVE-VERIFICATION-2026-09-14.md
// ============================================================================

static const ComponentPropertyDef g_SpellContainerComponent_Properties[] = {
    // Array<SpellMeta> Spells at 0x00 - SpellMeta is 96 bytes (0x60) on ARM64
    { "Spells",     0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true, ELEM_TYPE_SPELL_META, 96 },
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
// ARM64 Verified: Size 0x10 (via Ghidra AddComponent<eoc::BoostsContainerComponent>)
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
// Boost Type Components (Ghidra-verified sizes, Dec 2025)
// ARM64 sizes extracted from AddComponent<T> decompilations
// ============================================================================

// AbilityBoostComponent (eoc::AbilityBoostComponent)
// ARM64 Verified: Size 0x10 (16 bytes)
static const ComponentPropertyDef g_AbilityBoostComponent_Properties[] = {
    { "Ability", 0x00, FIELD_TYPE_UINT8, 0, true },
    { "Value",   0x04, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_AbilityBoostComponent_Layout = {
    .componentName = "eoc::AbilityBoostComponent",
    .shortName = "AbilityBoost",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_AbilityBoostComponent_Properties,
    .propertyCount = sizeof(g_AbilityBoostComponent_Properties) / sizeof(g_AbilityBoostComponent_Properties[0]),
};

// ArmorClassBoostComponent (eoc::ArmorClassBoostComponent)
// ARM64 Verified: Size 0x04 (4 bytes)
static const ComponentPropertyDef g_ArmorClassBoostComponent_Properties[] = {
    { "AC", 0x00, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_ArmorClassBoostComponent_Layout = {
    .componentName = "eoc::ArmorClassBoostComponent",
    .shortName = "ArmorClassBoost",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_ArmorClassBoostComponent_Properties,
    .propertyCount = sizeof(g_ArmorClassBoostComponent_Properties) / sizeof(g_ArmorClassBoostComponent_Properties[0]),
};

// AdvantageBoostComponent (eoc::AdvantageBoostComponent)
// ARM64 Verified: Size 0x18 (24 bytes)
static const ComponentPropertyDef g_AdvantageBoostComponent_Properties[] = {
    { "Type",      0x00, FIELD_TYPE_UINT8, 0, true },  // Advantage/Disadvantage enum
    { "Ability",   0x04, FIELD_TYPE_UINT8, 0, true },
    { "SkillType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "Tags",      0x10, FIELD_TYPE_UINT64, 0, true },  // Tag bitfield
};

static const ComponentLayoutDef g_AdvantageBoostComponent_Layout = {
    .componentName = "eoc::AdvantageBoostComponent",
    .shortName = "AdvantageBoost",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_AdvantageBoostComponent_Properties,
    .propertyCount = sizeof(g_AdvantageBoostComponent_Properties) / sizeof(g_AdvantageBoostComponent_Properties[0]),
};

// AddTagBoostComponent (eoc::AddTagBoostComponent)
// ARM64 Verified: Size 0x10 (16 bytes)
static const ComponentPropertyDef g_AddTagBoostComponent_Properties[] = {
    { "Tag", 0x00, FIELD_TYPE_GUID, 0, true },  // Guid (16 bytes)
};

static const ComponentLayoutDef g_AddTagBoostComponent_Layout = {
    .componentName = "eoc::AddTagBoostComponent",
    .shortName = "AddTagBoost",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_AddTagBoostComponent_Properties,
    .propertyCount = sizeof(g_AddTagBoostComponent_Properties) / sizeof(g_AddTagBoostComponent_Properties[0]),
};

// AttributeBoostComponent (eoc::AttributeBoostComponent)
// ARM64 Verified: Size 0x04 (4 bytes)
static const ComponentPropertyDef g_AttributeBoostComponent_Properties[] = {
    { "AttributeFlags", 0x00, FIELD_TYPE_UINT32, 0, true },
};

static const ComponentLayoutDef g_AttributeBoostComponent_Layout = {
    .componentName = "eoc::AttributeBoostComponent",
    .shortName = "AttributeBoost",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_AttributeBoostComponent_Properties,
    .propertyCount = sizeof(g_AttributeBoostComponent_Properties) / sizeof(g_AttributeBoostComponent_Properties[0]),
};

// ============================================================================
// DisplayNameComponent (eoc::DisplayNameComponent)
// From: BG3Extender/GameDefinitions/Components/Visual.h:64-70
// ARM64 Verified: Size 0x40 (via Ghidra AddComponent<eoc::DisplayNameComponent>)
// Note: Contains two TranslatedStrings (complex - handle + version = ~32 bytes each)
// ============================================================================

static const ComponentPropertyDef g_DisplayNameComponent_Properties[] = {
    // TranslatedString Name at 0x00 (Handle + Version = ~32 bytes on ARM64)
    { "NameHandle",   0x00, FIELD_TYPE_FIXEDSTRING, 0, true },  // TranslatedString.Handle
    // TranslatedString Title at 0x20
    { "TitleHandle",  0x20, FIELD_TYPE_FIXEDSTRING, 0, true },  // TranslatedString.Handle
};

static const ComponentLayoutDef g_DisplayNameComponent_Layout = {
    .componentName = "eoc::DisplayNameComponent",
    .shortName = "DisplayName",
    .componentTypeIndex = 0,
    .componentSize = 0x40,    // ARM64 verified via Ghidra
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
// Client Components (ecl::) - Ghidra-verified sizes, Dec 2025
// ARM64 sizes extracted from AddComponent<T> and Create/malloc patterns
// Note: Some components use malloc with ptr storage (marked with "malloc" note)
// ============================================================================

// EquipmentVisualsComponent (ecl::EquipmentVisualsComponent)
// ARM64 Verified: Size 0x48 (72 bytes)
static const ComponentPropertyDef g_ClientEquipmentVisualsComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_UINT32, 0, true },
    // Complex visual data follows (meshes, materials, etc.)
};

static const ComponentLayoutDef g_ClientEquipmentVisualsComponent_Layout = {
    .componentName = "ecl::EquipmentVisualsComponent",
    .shortName = "ClientEquipmentVisuals",
    .componentTypeIndex = 0,
    .componentSize = 0x48,
    .properties = g_ClientEquipmentVisualsComponent_Properties,
    .propertyCount = sizeof(g_ClientEquipmentVisualsComponent_Properties) / sizeof(g_ClientEquipmentVisualsComponent_Properties[0]),
};

// Character (ecl::Character)
// ARM64 Verified: Size 0x158 (344 bytes) - allocated via malloc
static const ComponentLayoutDef g_ClientCharacterComponent_Layout = {
    .componentName = "ecl::Character",
    .shortName = "ClientCharacter",
    .componentTypeIndex = 0,
    .componentSize = 0x158,
    .properties = NULL,
    .propertyCount = 0,
};

// Item (ecl::Item)
// ARM64 Verified: Size 0x70 (112 bytes) - allocated via malloc
static const ComponentLayoutDef g_ClientItemComponent_Layout = {
    .componentName = "ecl::Item",
    .shortName = "ClientItem",
    .componentTypeIndex = 0,
    .componentSize = 0x70,
    .properties = NULL,
    .propertyCount = 0,
};

// Projectile (ecl::Projectile)
// ARM64 Verified: Size 0x240 (576 bytes) - LARGEST COMPONENT
static const ComponentLayoutDef g_ClientProjectileComponent_Layout = {
    .componentName = "ecl::Projectile",
    .shortName = "ClientProjectile",
    .componentTypeIndex = 0,
    .componentSize = 0x240,
    .properties = NULL,
    .propertyCount = 0,
};

// Scenery (ecl::Scenery)
// ARM64 Verified: Size 0x40 (64 bytes) - allocated via malloc
static const ComponentLayoutDef g_ClientSceneryComponent_Layout = {
    .componentName = "ecl::Scenery",
    .shortName = "ClientScenery",
    .componentTypeIndex = 0,
    .componentSize = 0x40,
    .properties = NULL,
    .propertyCount = 0,
};

// PaperdollComponent (ecl::PaperdollComponent)
// ARM64 Verified: Size 0x10 (16 bytes)
static const ComponentLayoutDef g_ClientPaperdollComponent_Layout = {
    .componentName = "ecl::PaperdollComponent",
    .shortName = "ClientPaperdoll",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = NULL,
    .propertyCount = 0,
};

// ============================================================================
// All Component Layouts (for bulk registration)
// ============================================================================


// ============================================================================
// AUTO-GENERATED COMPONENT LAYOUTS
// New layouts: 365
// ============================================================================


// === eoc:: namespace (145 layouts) ===

// eoc::ACOverrideFormulaBoostComponent - 24 bytes (0x18)
// Source: ACOverrideFormulaBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ACOverrideFormulaBoostComponent_Properties[] = {
    { "AC", 0x00, FIELD_TYPE_INT32, 0, false },
    { "field_4", 0x04, FIELD_TYPE_BOOL, 0, false },
    { "AddAbilityModifiers", 0x08, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_eoc_ACOverrideFormulaBoostComponent_Layout = {
    .componentName = "eoc::ACOverrideFormulaBoostComponent",
    .shortName = "ACOverrideFormulaBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_eoc_ACOverrideFormulaBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_ACOverrideFormulaBoostComponent_Properties) / sizeof(g_eoc_ACOverrideFormulaBoostComponent_Properties[0]),
};

// eoc::AbilityFailedSavingThrowBoostComponent - 1 bytes (0x1)
// Source: AbilityFailedSavingThrowBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_AbilityFailedSavingThrowBoostComponent_Properties[] = {
    { "Ability", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_AbilityFailedSavingThrowBoostComponent_Layout = {
    .componentName = "eoc::AbilityFailedSavingThrowBoostComponent",
    .shortName = "AbilityFailedSavingThrowBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_eoc_AbilityFailedSavingThrowBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_AbilityFailedSavingThrowBoostComponent_Properties) / sizeof(g_eoc_AbilityFailedSavingThrowBoostComponent_Properties[0]),
};

// eoc::AbilityOverrideMinimumBoostComponent - 12 bytes (0xC)
// Source: AbilityOverrideMinimumBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_AbilityOverrideMinimumBoostComponent_Properties[] = {
    { "Ability", 0x00, FIELD_TYPE_INT32, 0, false },
    { "Amount", 0x04, FIELD_TYPE_INT32, 0, false },
    { "field_8", 0x08, FIELD_TYPE_BOOL, 0, false },
};
static const ComponentLayoutDef g_eoc_AbilityOverrideMinimumBoostComponent_Layout = {
    .componentName = "eoc::AbilityOverrideMinimumBoostComponent",
    .shortName = "AbilityOverrideMinimumBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0xC,
    .properties = g_eoc_AbilityOverrideMinimumBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_AbilityOverrideMinimumBoostComponent_Properties) / sizeof(g_eoc_AbilityOverrideMinimumBoostComponent_Properties[0]),
};

// eoc::ActionResourceBlockBoostComponent - 24 bytes (0x18)
// Source: ActionResourceBlockBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ActionResourceBlockBoostComponent_Properties[] = {
    { "ResourceUUID", 0x00, FIELD_TYPE_GUID, 0, false },
};
static const ComponentLayoutDef g_eoc_ActionResourceBlockBoostComponent_Layout = {
    .componentName = "eoc::ActionResourceBlockBoostComponent",
    .shortName = "ActionResourceBlockBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_eoc_ActionResourceBlockBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_ActionResourceBlockBoostComponent_Properties) / sizeof(g_eoc_ActionResourceBlockBoostComponent_Properties[0]),
};

// eoc::ActionResourceConsumeMultiplierBoostComponent - 32 bytes (0x20)
// Source: ActionResourceConsumeMultiplierBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ActionResourceConsumeMultiplierBoostComponent_Properties[] = {
    { "ResourceUUID", 0x00, FIELD_TYPE_GUID, 0, false },
    { "Level", 0x10, FIELD_TYPE_INT32, 0, false },
    { "Multiplier", 0x14, FIELD_TYPE_FLOAT, 0, false },
};
static const ComponentLayoutDef g_eoc_ActionResourceConsumeMultiplierBoostComponent_Layout = {
    .componentName = "eoc::ActionResourceConsumeMultiplierBoostComponent",
    .shortName = "ActionResourceConsumeMultiplierBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_eoc_ActionResourceConsumeMultiplierBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_ActionResourceConsumeMultiplierBoostComponent_Properties) / sizeof(g_eoc_ActionResourceConsumeMultiplierBoostComponent_Properties[0]),
};

// eoc::ActionResourceMultiplierBoostComponent - 32 bytes (0x20)
// Source: ActionResourceMultiplierBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ActionResourceMultiplierBoostComponent_Properties[] = {
    { "ResourceUUID", 0x00, FIELD_TYPE_GUID, 0, false },
    { "IntParam2", 0x10, FIELD_TYPE_INT32, 0, false },
    { "IntParam", 0x14, FIELD_TYPE_INT32, 0, false },
    { "DiceSize", 0x18, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_ActionResourceMultiplierBoostComponent_Layout = {
    .componentName = "eoc::ActionResourceMultiplierBoostComponent",
    .shortName = "ActionResourceMultiplierBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_eoc_ActionResourceMultiplierBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_ActionResourceMultiplierBoostComponent_Properties) / sizeof(g_eoc_ActionResourceMultiplierBoostComponent_Properties[0]),
};

// eoc::ActionResourcePreventReductionBoostComponent - 24 bytes (0x18)
// Source: ActionResourcePreventReductionBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ActionResourcePreventReductionBoostComponent_Properties[] = {
    { "ActionResource", 0x00, FIELD_TYPE_GUID, 0, false },
    { "Amount", 0x10, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_ActionResourcePreventReductionBoostComponent_Layout = {
    .componentName = "eoc::ActionResourcePreventReductionBoostComponent",
    .shortName = "ActionResourcePreventReductionBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_eoc_ActionResourcePreventReductionBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_ActionResourcePreventReductionBoostComponent_Properties) / sizeof(g_eoc_ActionResourcePreventReductionBoostComponent_Properties[0]),
};

// eoc::ActionResourceReplenishTypeOverrideBoostComponent - 24 bytes (0x18)
// Source: ActionResourceReplenishTypeOverrideBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ActionResourceReplenishTypeOverrideBoostComponent_Properties[] = {
    { "ActionResource", 0x00, FIELD_TYPE_GUID, 0, false },
    { "ReplenishType", 0x10, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_ActionResourceReplenishTypeOverrideBoostComponent_Layout = {
    .componentName = "eoc::ActionResourceReplenishTypeOverrideBoostComponent",
    .shortName = "ActionResourceReplenishTypeOverrideBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_eoc_ActionResourceReplenishTypeOverrideBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_ActionResourceReplenishTypeOverrideBoostComponent_Properties) / sizeof(g_eoc_ActionResourceReplenishTypeOverrideBoostComponent_Properties[0]),
};

// eoc::ActionResourceValueBoostComponent - 40 bytes (0x28)
// Source: ActionResourceValueBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ActionResourceValueBoostComponent_Properties[] = {
    { "ResourceUUID", 0x00, FIELD_TYPE_GUID, 0, false },
    { "Amount2", 0x10, FIELD_TYPE_INT32, 0, false },
    { "Amount", 0x14, FIELD_TYPE_FLOAT, 0, false },
    { "DiceSize", 0x1C, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_ActionResourceValueBoostComponent_Layout = {
    .componentName = "eoc::ActionResourceValueBoostComponent",
    .shortName = "ActionResourceValueBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_eoc_ActionResourceValueBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_ActionResourceValueBoostComponent_Properties) / sizeof(g_eoc_ActionResourceValueBoostComponent_Properties[0]),
};

// eoc::ActiveCharacterLightBoostComponent - 4 bytes (0x4)
// Source: ActiveCharacterLightBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ActiveCharacterLightBoostComponent_Properties[] = {
    { "LightUUID", 0x00, FIELD_TYPE_FIXEDSTRING, 0, false },
};
static const ComponentLayoutDef g_eoc_ActiveCharacterLightBoostComponent_Layout = {
    .componentName = "eoc::ActiveCharacterLightBoostComponent",
    .shortName = "ActiveCharacterLightBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_ActiveCharacterLightBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_ActiveCharacterLightBoostComponent_Properties) / sizeof(g_eoc_ActiveCharacterLightBoostComponent_Properties[0]),
};

// eoc::AiArchetypeOverrideBoostComponent - 8 bytes (0x8)
// Source: AiArchetypeOverrideBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_AiArchetypeOverrideBoostComponent_Properties[] = {
    { "Archetype", 0x00, FIELD_TYPE_FIXEDSTRING, 0, false },
    { "Priority", 0x04, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_AiArchetypeOverrideBoostComponent_Layout = {
    .componentName = "eoc::AiArchetypeOverrideBoostComponent",
    .shortName = "AiArchetypeOverrideBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_eoc_AiArchetypeOverrideBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_AiArchetypeOverrideBoostComponent_Properties) / sizeof(g_eoc_AiArchetypeOverrideBoostComponent_Properties[0]),
};

// eoc::ArmorAbilityModifierCapOverrideBoostComponent - 8 bytes (0x8)
// Source: ArmorAbilityModifierCapOverrideBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ArmorAbilityModifierCapOverrideBoostComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_ArmorAbilityModifierCapOverrideBoostComponent_Layout = {
    .componentName = "eoc::ArmorAbilityModifierCapOverrideBoostComponent",
    .shortName = "ArmorAbilityModifierCapOverrideBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_eoc_ArmorAbilityModifierCapOverrideBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_ArmorAbilityModifierCapOverrideBoostComponent_Properties) / sizeof(g_eoc_ArmorAbilityModifierCapOverrideBoostComponent_Properties[0]),
};

// eoc::AttackSpellOverrideBoostComponent - 8 bytes (0x8)
// Source: AttackSpellOverrideBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_AttackSpellOverrideBoostComponent_Properties[] = {
    { "SpellId", 0x00, FIELD_TYPE_FIXEDSTRING, 0, false },
};
static const ComponentLayoutDef g_eoc_AttackSpellOverrideBoostComponent_Layout = {
    .componentName = "eoc::AttackSpellOverrideBoostComponent",
    .shortName = "AttackSpellOverrideBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_eoc_AttackSpellOverrideBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_AttackSpellOverrideBoostComponent_Properties) / sizeof(g_eoc_AttackSpellOverrideBoostComponent_Properties[0]),
};

// eoc::AttributeFlagsComponent - 4 bytes (0x4)
// Source: AttributeFlagsComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_AttributeFlagsComponent_Properties[] = {
    { "AttributeFlags", 0x00, FIELD_TYPE_UINT32, 0, false },
};
static const ComponentLayoutDef g_eoc_AttributeFlagsComponent_Layout = {
    .componentName = "eoc::AttributeFlagsComponent",
    .shortName = "AttributeFlagsComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_AttributeFlagsComponent_Properties,
    .propertyCount = sizeof(g_eoc_AttributeFlagsComponent_Properties) / sizeof(g_eoc_AttributeFlagsComponent_Properties[0]),
};

// eoc::BodyTypeComponent - 2 bytes (0x2)
// Source: BodyTypeComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_BodyTypeComponent_Properties[] = {
    { "BodyType", 0x00, FIELD_TYPE_UINT8, 0, false },
    { "BodyType2", 0x01, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_BodyTypeComponent_Layout = {
    .componentName = "eoc::BodyTypeComponent",
    .shortName = "BodyTypeComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_eoc_BodyTypeComponent_Properties,
    .propertyCount = sizeof(g_eoc_BodyTypeComponent_Properties) / sizeof(g_eoc_BodyTypeComponent_Properties[0]),
};

// eoc::BoostConditionComponent - 8 bytes (0x8)
// Source: BoostConditionComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_BoostConditionComponent_Properties[] = {
    { "ConditionFlags", 0x00, FIELD_TYPE_INT32, 0, false },
    { "field_1C", 0x04, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_BoostConditionComponent_Layout = {
    .componentName = "eoc::BoostConditionComponent",
    .shortName = "BoostConditionComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_eoc_BoostConditionComponent_Properties,
    .propertyCount = sizeof(g_eoc_BoostConditionComponent_Properties) / sizeof(g_eoc_BoostConditionComponent_Properties[0]),
};

// eoc::BoostInfoComponent - 88 bytes (0x58)
// Source: BoostInfoComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_BoostInfoComponent_Properties[] = {
    { "field_20", 0x00, FIELD_TYPE_BOOL, 0, false },
    { "Owner", 0x04, FIELD_TYPE_ENTITY_HANDLE, 0, false },
};
static const ComponentLayoutDef g_eoc_BoostInfoComponent_Layout = {
    .componentName = "eoc::BoostInfoComponent",
    .shortName = "BoostInfoComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x58,
    .properties = g_eoc_BoostInfoComponent_Properties,
    .propertyCount = sizeof(g_eoc_BoostInfoComponent_Properties) / sizeof(g_eoc_BoostInfoComponent_Properties[0]),
};

// eoc::CanBeDisarmedComponent - 2 bytes (0x2)
// Source: CanBeDisarmedComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_CanBeDisarmedComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT32, 0, false },
};
static const ComponentLayoutDef g_eoc_CanBeDisarmedComponent_Layout = {
    .componentName = "eoc::CanBeDisarmedComponent",
    .shortName = "CanBeDisarmedComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_eoc_CanBeDisarmedComponent_Properties,
    .propertyCount = sizeof(g_eoc_CanBeDisarmedComponent_Properties) / sizeof(g_eoc_CanBeDisarmedComponent_Properties[0]),
};

// eoc::CanBeLootedComponent - 2 bytes (0x2)
// Source: CanBeLootedComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_CanBeLootedComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT32, 0, false },
};
static const ComponentLayoutDef g_eoc_CanBeLootedComponent_Layout = {
    .componentName = "eoc::CanBeLootedComponent",
    .shortName = "CanBeLootedComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_eoc_CanBeLootedComponent_Properties,
    .propertyCount = sizeof(g_eoc_CanBeLootedComponent_Properties) / sizeof(g_eoc_CanBeLootedComponent_Properties[0]),
};

// eoc::CanDeflectProjectilesComponent - 2 bytes (0x2)
// Source: CanDeflectProjectilesComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_CanDeflectProjectilesComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT32, 0, false },
};
static const ComponentLayoutDef g_eoc_CanDeflectProjectilesComponent_Layout = {
    .componentName = "eoc::CanDeflectProjectilesComponent",
    .shortName = "CanDeflectProjectilesComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_eoc_CanDeflectProjectilesComponent_Properties,
    .propertyCount = sizeof(g_eoc_CanDeflectProjectilesComponent_Properties) / sizeof(g_eoc_CanDeflectProjectilesComponent_Properties[0]),
};

// eoc::CanModifyHealthComponent - 2 bytes (0x2)
// Source: CanModifyHealthComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_CanModifyHealthComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT32, 0, false },
};
static const ComponentLayoutDef g_eoc_CanModifyHealthComponent_Layout = {
    .componentName = "eoc::CanModifyHealthComponent",
    .shortName = "CanModifyHealthComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_eoc_CanModifyHealthComponent_Properties,
    .propertyCount = sizeof(g_eoc_CanModifyHealthComponent_Properties) / sizeof(g_eoc_CanModifyHealthComponent_Properties[0]),
};

// eoc::CanMoveComponent - 6 bytes (0x6)
// Source: CanMoveComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_CanMoveComponent_Properties[] = {
    { "field_4", 0x00, FIELD_TYPE_UINT32, 0, false },
    { "field_6", 0x02, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_CanMoveComponent_Layout = {
    .componentName = "eoc::CanMoveComponent",
    .shortName = "CanMoveComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x6,
    .properties = g_eoc_CanMoveComponent_Properties,
    .propertyCount = sizeof(g_eoc_CanMoveComponent_Properties) / sizeof(g_eoc_CanMoveComponent_Properties[0]),
};

// eoc::CanSeeThroughBoostComponent - 1 bytes (0x1)
// Source: CanSeeThroughBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_CanSeeThroughBoostComponent_Properties[] = {
    { "CanSeeThrough", 0x00, FIELD_TYPE_BOOL, 0, false },
};
static const ComponentLayoutDef g_eoc_CanSeeThroughBoostComponent_Layout = {
    .componentName = "eoc::CanSeeThroughBoostComponent",
    .shortName = "CanSeeThroughBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_eoc_CanSeeThroughBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_CanSeeThroughBoostComponent_Properties) / sizeof(g_eoc_CanSeeThroughBoostComponent_Properties[0]),
};

// eoc::CanSenseComponent - 2 bytes (0x2)
// Source: CanSenseComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_CanSenseComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT32, 0, false },
};
static const ComponentLayoutDef g_eoc_CanSenseComponent_Layout = {
    .componentName = "eoc::CanSenseComponent",
    .shortName = "CanSenseComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_eoc_CanSenseComponent_Properties,
    .propertyCount = sizeof(g_eoc_CanSenseComponent_Properties) / sizeof(g_eoc_CanSenseComponent_Properties[0]),
};

// eoc::CanShootThroughBoostComponent - 1 bytes (0x1)
// Source: CanShootThroughBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_CanShootThroughBoostComponent_Properties[] = {
    { "CanShootThrough", 0x00, FIELD_TYPE_BOOL, 0, false },
};
static const ComponentLayoutDef g_eoc_CanShootThroughBoostComponent_Layout = {
    .componentName = "eoc::CanShootThroughBoostComponent",
    .shortName = "CanShootThroughBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_eoc_CanShootThroughBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_CanShootThroughBoostComponent_Properties) / sizeof(g_eoc_CanShootThroughBoostComponent_Properties[0]),
};

// eoc::CanTravelComponent - 6 bytes (0x6)
// Source: CanTravelComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_CanTravelComponent_Properties[] = {
    { "field_2", 0x00, FIELD_TYPE_UINT32, 0, false },
};
static const ComponentLayoutDef g_eoc_CanTravelComponent_Layout = {
    .componentName = "eoc::CanTravelComponent",
    .shortName = "CanTravelComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x6,
    .properties = g_eoc_CanTravelComponent_Properties,
    .propertyCount = sizeof(g_eoc_CanTravelComponent_Properties) / sizeof(g_eoc_CanTravelComponent_Properties[0]),
};

// eoc::CanWalkThroughBoostComponent - 1 bytes (0x1)
// Source: CanWalkThroughBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_CanWalkThroughBoostComponent_Properties[] = {
    { "CanWalkThrough", 0x00, FIELD_TYPE_BOOL, 0, false },
};
static const ComponentLayoutDef g_eoc_CanWalkThroughBoostComponent_Layout = {
    .componentName = "eoc::CanWalkThroughBoostComponent",
    .shortName = "CanWalkThroughBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_eoc_CanWalkThroughBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_CanWalkThroughBoostComponent_Properties) / sizeof(g_eoc_CanWalkThroughBoostComponent_Properties[0]),
};

// eoc::CannotHarmCauseEntityBoostComponent - 4 bytes (0x4)
// Source: CannotHarmCauseEntityBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_CannotHarmCauseEntityBoostComponent_Properties[] = {
    { "Type", 0x00, FIELD_TYPE_FIXEDSTRING, 0, false },
};
static const ComponentLayoutDef g_eoc_CannotHarmCauseEntityBoostComponent_Layout = {
    .componentName = "eoc::CannotHarmCauseEntityBoostComponent",
    .shortName = "CannotHarmCauseEntityBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_CannotHarmCauseEntityBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_CannotHarmCauseEntityBoostComponent_Properties) / sizeof(g_eoc_CannotHarmCauseEntityBoostComponent_Properties[0]),
};

// eoc::CarryCapacityMultiplierBoostComponent - 4 bytes (0x4)
// Source: CarryCapacityMultiplierBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_CarryCapacityMultiplierBoostComponent_Properties[] = {
    { "Multiplier", 0x00, FIELD_TYPE_FLOAT, 0, false },
};
static const ComponentLayoutDef g_eoc_CarryCapacityMultiplierBoostComponent_Layout = {
    .componentName = "eoc::CarryCapacityMultiplierBoostComponent",
    .shortName = "CarryCapacityMultiplierBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_CarryCapacityMultiplierBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_CarryCapacityMultiplierBoostComponent_Properties) / sizeof(g_eoc_CarryCapacityMultiplierBoostComponent_Properties[0]),
};

// eoc::CharacterCreationStatsComponent - 88 bytes (0x58)
// Source: CharacterCreationStatsComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_CharacterCreationStatsComponent_Properties[] = {
    { "Race", 0x00, FIELD_TYPE_GUID, 0, false },
    { "SubRace", 0x10, FIELD_TYPE_GUID, 0, false },
    { "BodyType", 0x20, FIELD_TYPE_UINT8, 0, false },
    { "BodyShape", 0x21, FIELD_TYPE_UINT8, 0, false },
    { "Abilities", 0x24, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
    { "field_5C", 0x34, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_CharacterCreationStatsComponent_Layout = {
    .componentName = "eoc::CharacterCreationStatsComponent",
    .shortName = "CharacterCreationStatsComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x58,
    .properties = g_eoc_CharacterCreationStatsComponent_Properties,
    .propertyCount = sizeof(g_eoc_CharacterCreationStatsComponent_Properties) / sizeof(g_eoc_CharacterCreationStatsComponent_Properties[0]),
};

// eoc::CharacterUnarmedDamageBoostComponent - 40 bytes (0x28)
// Source: CharacterUnarmedDamageBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_CharacterUnarmedDamageBoostComponent_Properties[] = {
    { "DamageType", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_CharacterUnarmedDamageBoostComponent_Layout = {
    .componentName = "eoc::CharacterUnarmedDamageBoostComponent",
    .shortName = "CharacterUnarmedDamageBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_eoc_CharacterUnarmedDamageBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_CharacterUnarmedDamageBoostComponent_Properties) / sizeof(g_eoc_CharacterUnarmedDamageBoostComponent_Properties[0]),
};

// eoc::CharacterWeaponDamageBoostComponent - 40 bytes (0x28)
// Source: CharacterWeaponDamageBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_CharacterWeaponDamageBoostComponent_Properties[] = {
    { "DamageType", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_CharacterWeaponDamageBoostComponent_Layout = {
    .componentName = "eoc::CharacterWeaponDamageBoostComponent",
    .shortName = "CharacterWeaponDamageBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_eoc_CharacterWeaponDamageBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_CharacterWeaponDamageBoostComponent_Properties) / sizeof(g_eoc_CharacterWeaponDamageBoostComponent_Properties[0]),
};

// eoc::ConcentrationIgnoreDamageBoostComponent - 1 bytes (0x1)
// Source: ConcentrationIgnoreDamageBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ConcentrationIgnoreDamageBoostComponent_Properties[] = {
    { "SpellSchool", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_ConcentrationIgnoreDamageBoostComponent_Layout = {
    .componentName = "eoc::ConcentrationIgnoreDamageBoostComponent",
    .shortName = "ConcentrationIgnoreDamageBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_eoc_ConcentrationIgnoreDamageBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_ConcentrationIgnoreDamageBoostComponent_Properties) / sizeof(g_eoc_ConcentrationIgnoreDamageBoostComponent_Properties[0]),
};

// eoc::CriticalHitBoostComponent - 8 bytes (0x8)
// Source: CriticalHitBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_CriticalHitBoostComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_FLOAT, 0, false },
};
static const ComponentLayoutDef g_eoc_CriticalHitBoostComponent_Layout = {
    .componentName = "eoc::CriticalHitBoostComponent",
    .shortName = "CriticalHitBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_eoc_CriticalHitBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_CriticalHitBoostComponent_Properties) / sizeof(g_eoc_CriticalHitBoostComponent_Properties[0]),
};

// eoc::CriticalHitExtraDiceBoostComponent - 2 bytes (0x2)
// Source: CriticalHitExtraDiceBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_CriticalHitExtraDiceBoostComponent_Properties[] = {
    { "Amount", 0x00, FIELD_TYPE_UINT8, 0, false },
    { "AttackType", 0x04, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_CriticalHitExtraDiceBoostComponent_Layout = {
    .componentName = "eoc::CriticalHitExtraDiceBoostComponent",
    .shortName = "CriticalHitExtraDiceBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_eoc_CriticalHitExtraDiceBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_CriticalHitExtraDiceBoostComponent_Properties) / sizeof(g_eoc_CriticalHitExtraDiceBoostComponent_Properties[0]),
};

// eoc::DamageBonusBoostComponent - 40 bytes (0x28)
// Source: DamageBonusBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_DamageBonusBoostComponent_Properties[] = {
    { "DamageType", 0x00, FIELD_TYPE_INT32, 0, false },
    { "field_31", 0x04, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_DamageBonusBoostComponent_Layout = {
    .componentName = "eoc::DamageBonusBoostComponent",
    .shortName = "DamageBonusBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_eoc_DamageBonusBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_DamageBonusBoostComponent_Properties) / sizeof(g_eoc_DamageBonusBoostComponent_Properties[0]),
};

// eoc::DamageReductionBoostComponent - 56 bytes (0x38)
// Source: DamageReductionBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_DamageReductionBoostComponent_Properties[] = {
    { "DamageType", 0x00, FIELD_TYPE_INT32, 0, false },
    { "Flat", 0x04, FIELD_TYPE_BOOL, 0, false },
    { "Half", 0x05, FIELD_TYPE_BOOL, 0, false },
};
static const ComponentLayoutDef g_eoc_DamageReductionBoostComponent_Layout = {
    .componentName = "eoc::DamageReductionBoostComponent",
    .shortName = "DamageReductionBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x38,
    .properties = g_eoc_DamageReductionBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_DamageReductionBoostComponent_Properties) / sizeof(g_eoc_DamageReductionBoostComponent_Properties[0]),
};

// eoc::DamageTakenBonusBoostComponent - 40 bytes (0x28)
// Source: DamageTakenBonusBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_DamageTakenBonusBoostComponent_Properties[] = {
    { "DamageType", 0x00, FIELD_TYPE_INT32, 0, false },
    { "Arg3", 0x04, FIELD_TYPE_BOOL, 0, false },
};
static const ComponentLayoutDef g_eoc_DamageTakenBonusBoostComponent_Layout = {
    .componentName = "eoc::DamageTakenBonusBoostComponent",
    .shortName = "DamageTakenBonusBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_eoc_DamageTakenBonusBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_DamageTakenBonusBoostComponent_Properties) / sizeof(g_eoc_DamageTakenBonusBoostComponent_Properties[0]),
};

// eoc::DarknessComponent - 16 bytes (0x10)
// Source: DarknessComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_DarknessComponent_Properties[] = {
    { "Sneaking", 0x00, FIELD_TYPE_UINT8, 0, false },
    { "Obscurity", 0x01, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_DarknessComponent_Layout = {
    .componentName = "eoc::DarknessComponent",
    .shortName = "DarknessComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_eoc_DarknessComponent_Properties,
    .propertyCount = sizeof(g_eoc_DarknessComponent_Properties) / sizeof(g_eoc_DarknessComponent_Properties[0]),
};

// eoc::DarkvisionRangeBoostComponent - 4 bytes (0x4)
// Source: DarkvisionRangeBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_DarkvisionRangeBoostComponent_Properties[] = {
    { "Range", 0x00, FIELD_TYPE_FLOAT, 0, false },
};
static const ComponentLayoutDef g_eoc_DarkvisionRangeBoostComponent_Layout = {
    .componentName = "eoc::DarkvisionRangeBoostComponent",
    .shortName = "DarkvisionRangeBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_DarkvisionRangeBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_DarkvisionRangeBoostComponent_Properties) / sizeof(g_eoc_DarkvisionRangeBoostComponent_Properties[0]),
};

// eoc::DarkvisionRangeMinBoostComponent - 4 bytes (0x4)
// Source: DarkvisionRangeMinBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_DarkvisionRangeMinBoostComponent_Properties[] = {
    { "Range", 0x00, FIELD_TYPE_FLOAT, 0, false },
};
static const ComponentLayoutDef g_eoc_DarkvisionRangeMinBoostComponent_Layout = {
    .componentName = "eoc::DarkvisionRangeMinBoostComponent",
    .shortName = "DarkvisionRangeMinBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_DarkvisionRangeMinBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_DarkvisionRangeMinBoostComponent_Properties) / sizeof(g_eoc_DarkvisionRangeMinBoostComponent_Properties[0]),
};

// eoc::DarkvisionRangeOverrideBoostComponent - 4 bytes (0x4)
// Source: DarkvisionRangeOverrideBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_DarkvisionRangeOverrideBoostComponent_Properties[] = {
    { "Range", 0x00, FIELD_TYPE_FLOAT, 0, false },
};
static const ComponentLayoutDef g_eoc_DarkvisionRangeOverrideBoostComponent_Layout = {
    .componentName = "eoc::DarkvisionRangeOverrideBoostComponent",
    .shortName = "DarkvisionRangeOverrideBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_DarkvisionRangeOverrideBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_DarkvisionRangeOverrideBoostComponent_Properties) / sizeof(g_eoc_DarkvisionRangeOverrideBoostComponent_Properties[0]),
};

// eoc::DetachedComponent - 4 bytes (0x4)
// Source: DetachedComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_DetachedComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT32, 0, false },
};
static const ComponentLayoutDef g_eoc_DetachedComponent_Layout = {
    .componentName = "eoc::DetachedComponent",
    .shortName = "DetachedComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_DetachedComponent_Properties,
    .propertyCount = sizeof(g_eoc_DetachedComponent_Properties) / sizeof(g_eoc_DetachedComponent_Properties[0]),
};

// eoc::DifficultyCheckComponent - 72 bytes (0x48)
// Source: DifficultyCheckComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_DifficultyCheckComponent_Properties[] = {
    { "Abilities", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
    { "field_30", 0x10, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
    { "field_40", 0x20, FIELD_TYPE_INT32, 0, false },
    { "field_44", 0x24, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_DifficultyCheckComponent_Layout = {
    .componentName = "eoc::DifficultyCheckComponent",
    .shortName = "DifficultyCheckComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x48,
    .properties = g_eoc_DifficultyCheckComponent_Properties,
    .propertyCount = sizeof(g_eoc_DifficultyCheckComponent_Properties) / sizeof(g_eoc_DifficultyCheckComponent_Properties[0]),
};

// eoc::DisabledEquipmentComponent - 1 bytes (0x1)
// Source: DisabledEquipmentComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_DisabledEquipmentComponent_Properties[] = {
    { "ShapeshiftFlag", 0x00, FIELD_TYPE_BOOL, 0, false },
};
static const ComponentLayoutDef g_eoc_DisabledEquipmentComponent_Layout = {
    .componentName = "eoc::DisabledEquipmentComponent",
    .shortName = "DisabledEquipmentComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_eoc_DisabledEquipmentComponent_Properties,
    .propertyCount = sizeof(g_eoc_DisabledEquipmentComponent_Properties) / sizeof(g_eoc_DisabledEquipmentComponent_Properties[0]),
};

// eoc::DisarmableComponent - 24 bytes (0x18)
// Source: DisarmableComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_DisarmableComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_GUID, 0, false },
    { "field_10", 0x10, FIELD_TYPE_UINT8, 0, false },
    { "field_11", 0x11, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_DisarmableComponent_Layout = {
    .componentName = "eoc::DisarmableComponent",
    .shortName = "DisarmableComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_eoc_DisarmableComponent_Properties,
    .propertyCount = sizeof(g_eoc_DisarmableComponent_Properties) / sizeof(g_eoc_DisarmableComponent_Properties[0]),
};

// eoc::DodgeAttackRollBoostComponent - 12 bytes (0xC)
// Source: DodgeAttackRollBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_DodgeAttackRollBoostComponent_Properties[] = {
    { "field_4", 0x00, FIELD_TYPE_INT32, 0, false },
    { "StatusType", 0x04, FIELD_TYPE_FIXEDSTRING, 0, false },
};
static const ComponentLayoutDef g_eoc_DodgeAttackRollBoostComponent_Layout = {
    .componentName = "eoc::DodgeAttackRollBoostComponent",
    .shortName = "DodgeAttackRollBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0xC,
    .properties = g_eoc_DodgeAttackRollBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_DodgeAttackRollBoostComponent_Properties) / sizeof(g_eoc_DodgeAttackRollBoostComponent_Properties[0]),
};

// eoc::DownedStatusBoostComponent - 8 bytes (0x8)
// Source: DownedStatusBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_DownedStatusBoostComponent_Properties[] = {
    { "StatusId", 0x00, FIELD_TYPE_FIXEDSTRING, 0, false },
};
static const ComponentLayoutDef g_eoc_DownedStatusBoostComponent_Layout = {
    .componentName = "eoc::DownedStatusBoostComponent",
    .shortName = "DownedStatusBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_eoc_DownedStatusBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_DownedStatusBoostComponent_Properties) / sizeof(g_eoc_DownedStatusBoostComponent_Properties[0]),
};

// eoc::DualWieldingBoostComponent - 1 bytes (0x1)
// Source: DualWieldingBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_DualWieldingBoostComponent_Properties[] = {
    { "DualWielding", 0x00, FIELD_TYPE_BOOL, 0, false },
};
static const ComponentLayoutDef g_eoc_DualWieldingBoostComponent_Layout = {
    .componentName = "eoc::DualWieldingBoostComponent",
    .shortName = "DualWieldingBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_eoc_DualWieldingBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_DualWieldingBoostComponent_Properties) / sizeof(g_eoc_DualWieldingBoostComponent_Properties[0]),
};

// eoc::DualWieldingComponent - 7 bytes (0x7)
// Source: DualWieldingComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_DualWieldingComponent_Properties[] = {
    { "MeleeUI", 0x00, FIELD_TYPE_BOOL, 0, false },
    { "RangedUI", 0x01, FIELD_TYPE_BOOL, 0, false },
};
static const ComponentLayoutDef g_eoc_DualWieldingComponent_Layout = {
    .componentName = "eoc::DualWieldingComponent",
    .shortName = "DualWieldingComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x7,
    .properties = g_eoc_DualWieldingComponent_Properties,
    .propertyCount = sizeof(g_eoc_DualWieldingComponent_Properties) / sizeof(g_eoc_DualWieldingComponent_Properties[0]),
};

// eoc::EntityThrowDamageBoostComponent - 16 bytes (0x10)
// Source: EntityThrowDamageBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_EntityThrowDamageBoostComponent_Properties[] = {
    { "field_C", 0x00, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_EntityThrowDamageBoostComponent_Layout = {
    .componentName = "eoc::EntityThrowDamageBoostComponent",
    .shortName = "EntityThrowDamageBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_eoc_EntityThrowDamageBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_EntityThrowDamageBoostComponent_Properties) / sizeof(g_eoc_EntityThrowDamageBoostComponent_Properties[0]),
};

// eoc::ExpertiseBonusBoostComponent - 1 bytes (0x1)
// Source: ExpertiseBonusBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ExpertiseBonusBoostComponent_Properties[] = {
    { "Skill", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_ExpertiseBonusBoostComponent_Layout = {
    .componentName = "eoc::ExpertiseBonusBoostComponent",
    .shortName = "ExpertiseBonusBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_eoc_ExpertiseBonusBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_ExpertiseBonusBoostComponent_Properties) / sizeof(g_eoc_ExpertiseBonusBoostComponent_Properties[0]),
};

// eoc::FactionOverrideBoostComponent - 24 bytes (0x18)
// Source: FactionOverrideBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_FactionOverrideBoostComponent_Properties[] = {
    { "Faction", 0x00, FIELD_TYPE_GUID, 0, false },
    { "field_10", 0x10, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_FactionOverrideBoostComponent_Layout = {
    .componentName = "eoc::FactionOverrideBoostComponent",
    .shortName = "FactionOverrideBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_eoc_FactionOverrideBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_FactionOverrideBoostComponent_Properties) / sizeof(g_eoc_FactionOverrideBoostComponent_Properties[0]),
};

// eoc::FallDamageMultiplierBoostComponent - 4 bytes (0x4)
// Source: FallDamageMultiplierBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_FallDamageMultiplierBoostComponent_Properties[] = {
    { "Amount", 0x00, FIELD_TYPE_FLOAT, 0, false },
};
static const ComponentLayoutDef g_eoc_FallDamageMultiplierBoostComponent_Layout = {
    .componentName = "eoc::FallDamageMultiplierBoostComponent",
    .shortName = "FallDamageMultiplierBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_FallDamageMultiplierBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_FallDamageMultiplierBoostComponent_Properties) / sizeof(g_eoc_FallDamageMultiplierBoostComponent_Properties[0]),
};

// eoc::GameplayLightBoostComponent - 16 bytes (0x10)
// Source: GameplayLightBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_GameplayLightBoostComponent_Properties[] = {
    { "LOS", 0x00, FIELD_TYPE_BOOL, 0, false },
    { "Sharpening", 0x04, FIELD_TYPE_FLOAT, 0, false },
};
static const ComponentLayoutDef g_eoc_GameplayLightBoostComponent_Layout = {
    .componentName = "eoc::GameplayLightBoostComponent",
    .shortName = "GameplayLightBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_eoc_GameplayLightBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_GameplayLightBoostComponent_Properties) / sizeof(g_eoc_GameplayLightBoostComponent_Properties[0]),
};

// eoc::GuaranteedChanceRollOutcomeBoostComponent - 1 bytes (0x1)
// Source: GuaranteedChanceRollOutcomeBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_GuaranteedChanceRollOutcomeBoostComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_BOOL, 0, false },
};
static const ComponentLayoutDef g_eoc_GuaranteedChanceRollOutcomeBoostComponent_Layout = {
    .componentName = "eoc::GuaranteedChanceRollOutcomeBoostComponent",
    .shortName = "GuaranteedChanceRollOutcomeBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_eoc_GuaranteedChanceRollOutcomeBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_GuaranteedChanceRollOutcomeBoostComponent_Properties) / sizeof(g_eoc_GuaranteedChanceRollOutcomeBoostComponent_Properties[0]),
};

// eoc::HalveWeaponDamageBoostComponent - 1 bytes (0x1)
// Source: HalveWeaponDamageBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_HalveWeaponDamageBoostComponent_Properties[] = {
    { "Ability", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_HalveWeaponDamageBoostComponent_Layout = {
    .componentName = "eoc::HalveWeaponDamageBoostComponent",
    .shortName = "HalveWeaponDamageBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_eoc_HalveWeaponDamageBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_HalveWeaponDamageBoostComponent_Properties) / sizeof(g_eoc_HalveWeaponDamageBoostComponent_Properties[0]),
};

// eoc::HearingComponent - 4 bytes (0x4)
// Source: HearingComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_HearingComponent_Properties[] = {
    { "Hearing", 0x00, FIELD_TYPE_FLOAT, 0, false },
};
static const ComponentLayoutDef g_eoc_HearingComponent_Layout = {
    .componentName = "eoc::HearingComponent",
    .shortName = "HearingComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_HearingComponent_Properties,
    .propertyCount = sizeof(g_eoc_HearingComponent_Properties) / sizeof(g_eoc_HearingComponent_Properties[0]),
};

// eoc::HorizontalFOVOverrideBoostComponent - 4 bytes (0x4)
// Source: HorizontalFOVOverrideBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_HorizontalFOVOverrideBoostComponent_Properties[] = {
    { "FOV", 0x00, FIELD_TYPE_FLOAT, 0, false },
};
static const ComponentLayoutDef g_eoc_HorizontalFOVOverrideBoostComponent_Layout = {
    .componentName = "eoc::HorizontalFOVOverrideBoostComponent",
    .shortName = "HorizontalFOVOverrideBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_HorizontalFOVOverrideBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_HorizontalFOVOverrideBoostComponent_Properties) / sizeof(g_eoc_HorizontalFOVOverrideBoostComponent_Properties[0]),
};

// eoc::IgnoreDamageThresholdMinBoostComponent - 4 bytes (0x4)
// Source: IgnoreDamageThresholdMinBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_IgnoreDamageThresholdMinBoostComponent_Properties[] = {
    { "DamageType", 0x00, FIELD_TYPE_INT32, 0, false },
    { "All", 0x04, FIELD_TYPE_BOOL, 0, false },
    { "Amount", 0x05, FIELD_TYPE_UINT32, 0, false },
};
static const ComponentLayoutDef g_eoc_IgnoreDamageThresholdMinBoostComponent_Layout = {
    .componentName = "eoc::IgnoreDamageThresholdMinBoostComponent",
    .shortName = "IgnoreDamageThresholdMinBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_IgnoreDamageThresholdMinBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_IgnoreDamageThresholdMinBoostComponent_Properties) / sizeof(g_eoc_IgnoreDamageThresholdMinBoostComponent_Properties[0]),
};

// eoc::IgnorePointBlankDisadvantageBoostComponent - 1 bytes (0x1)
// Source: IgnorePointBlankDisadvantageBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_IgnorePointBlankDisadvantageBoostComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT32, 0, false },
};
static const ComponentLayoutDef g_eoc_IgnorePointBlankDisadvantageBoostComponent_Layout = {
    .componentName = "eoc::IgnorePointBlankDisadvantageBoostComponent",
    .shortName = "IgnorePointBlankDisadvantageBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_eoc_IgnorePointBlankDisadvantageBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_IgnorePointBlankDisadvantageBoostComponent_Properties) / sizeof(g_eoc_IgnorePointBlankDisadvantageBoostComponent_Properties[0]),
};

// eoc::IgnoreResistanceBoostComponent - 24 bytes (0x18)
// Source: IgnoreResistanceBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_IgnoreResistanceBoostComponent_Properties[] = {
    { "DamageType", 0x00, FIELD_TYPE_INT32, 0, false },
    { "Flags", 0x04, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_IgnoreResistanceBoostComponent_Layout = {
    .componentName = "eoc::IgnoreResistanceBoostComponent",
    .shortName = "IgnoreResistanceBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_eoc_IgnoreResistanceBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_IgnoreResistanceBoostComponent_Properties) / sizeof(g_eoc_IgnoreResistanceBoostComponent_Properties[0]),
};

// eoc::IncreaseMaxHPBoostComponent - 48 bytes (0x30)
// Source: IncreaseMaxHPComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_IncreaseMaxHPBoostComponent_Properties[] = {
    { "field_30", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_IncreaseMaxHPBoostComponent_Layout = {
    .componentName = "eoc::IncreaseMaxHPBoostComponent",
    .shortName = "IncreaseMaxHPBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_eoc_IncreaseMaxHPBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_IncreaseMaxHPBoostComponent_Properties) / sizeof(g_eoc_IncreaseMaxHPBoostComponent_Properties[0]),
};

// eoc::InitiativeBoostComponent - 4 bytes (0x4)
// Source: InitiativeBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_InitiativeBoostComponent_Properties[] = {
    { "Amount", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_InitiativeBoostComponent_Layout = {
    .componentName = "eoc::InitiativeBoostComponent",
    .shortName = "InitiativeBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_InitiativeBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_InitiativeBoostComponent_Properties) / sizeof(g_eoc_InitiativeBoostComponent_Properties[0]),
};

// eoc::InvisibilityComponent - 20 bytes (0x14)
// Source: InvisibilityComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_InvisibilityComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false },
    { "field_10", 0x01, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_InvisibilityComponent_Layout = {
    .componentName = "eoc::InvisibilityComponent",
    .shortName = "InvisibilityComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x14,
    .properties = g_eoc_InvisibilityComponent_Properties,
    .propertyCount = sizeof(g_eoc_InvisibilityComponent_Properties) / sizeof(g_eoc_InvisibilityComponent_Properties[0]),
};

// eoc::JumpMaxDistanceBonusBoostComponent - 4 bytes (0x4)
// Source: JumpMaxDistanceBonusBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_JumpMaxDistanceBonusBoostComponent_Properties[] = {
    { "DistanceBonus", 0x00, FIELD_TYPE_FLOAT, 0, false },
};
static const ComponentLayoutDef g_eoc_JumpMaxDistanceBonusBoostComponent_Layout = {
    .componentName = "eoc::JumpMaxDistanceBonusBoostComponent",
    .shortName = "JumpMaxDistanceBonusBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_JumpMaxDistanceBonusBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_JumpMaxDistanceBonusBoostComponent_Properties) / sizeof(g_eoc_JumpMaxDistanceBonusBoostComponent_Properties[0]),
};

// eoc::JumpMaxDistanceMultiplierBoostComponent - 4 bytes (0x4)
// Source: JumpMaxDistanceMultiplierBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_JumpMaxDistanceMultiplierBoostComponent_Properties[] = {
    { "Amount", 0x00, FIELD_TYPE_FLOAT, 0, false },
};
static const ComponentLayoutDef g_eoc_JumpMaxDistanceMultiplierBoostComponent_Layout = {
    .componentName = "eoc::JumpMaxDistanceMultiplierBoostComponent",
    .shortName = "JumpMaxDistanceMultiplierBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_JumpMaxDistanceMultiplierBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_JumpMaxDistanceMultiplierBoostComponent_Properties) / sizeof(g_eoc_JumpMaxDistanceMultiplierBoostComponent_Properties[0]),
};

// eoc::LockBoostComponent - 16 bytes (0x10)
// Source: LockBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_LockBoostComponent_Properties[] = {
    { "Lock", 0x00, FIELD_TYPE_GUID, 0, false },
};
static const ComponentLayoutDef g_eoc_LockBoostComponent_Layout = {
    .componentName = "eoc::LockBoostComponent",
    .shortName = "LockBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_eoc_LockBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_LockBoostComponent_Properties) / sizeof(g_eoc_LockBoostComponent_Properties[0]),
};

// eoc::LootComponent - 2 bytes (0x2)
// Source: LootComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_LootComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT8, 0, false },
    { "InventoryType", 0x01, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_LootComponent_Layout = {
    .componentName = "eoc::LootComponent",
    .shortName = "LootComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_eoc_LootComponent_Properties,
    .propertyCount = sizeof(g_eoc_LootComponent_Properties) / sizeof(g_eoc_LootComponent_Properties[0]),
};

// eoc::LootingStateComponent - 16 bytes (0x10)
// Source: LootingStateComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_LootingStateComponent_Properties[] = {
    { "Looter_M", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false },
    { "State", 0x08, FIELD_TYPE_UINT8, 0, false },
    { "field_24", 0x0C, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_LootingStateComponent_Layout = {
    .componentName = "eoc::LootingStateComponent",
    .shortName = "LootingStateComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_eoc_LootingStateComponent_Properties,
    .propertyCount = sizeof(g_eoc_LootingStateComponent_Properties) / sizeof(g_eoc_LootingStateComponent_Properties[0]),
};

// eoc::MaximumRollResultBoostComponent - 2 bytes (0x2)
// Source: MaximumRollResultBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_MaximumRollResultBoostComponent_Properties[] = {
    { "Result", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_MaximumRollResultBoostComponent_Layout = {
    .componentName = "eoc::MaximumRollResultBoostComponent",
    .shortName = "MaximumRollResultBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_eoc_MaximumRollResultBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_MaximumRollResultBoostComponent_Properties) / sizeof(g_eoc_MaximumRollResultBoostComponent_Properties[0]),
};

// eoc::MinimumRollResultBoostComponent - 2 bytes (0x2)
// Source: MinimumRollResultBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_MinimumRollResultBoostComponent_Properties[] = {
    { "Result", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_MinimumRollResultBoostComponent_Layout = {
    .componentName = "eoc::MinimumRollResultBoostComponent",
    .shortName = "MinimumRollResultBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_eoc_MinimumRollResultBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_MinimumRollResultBoostComponent_Properties) / sizeof(g_eoc_MinimumRollResultBoostComponent_Properties[0]),
};

// eoc::MonkWeaponDamageDiceOverrideBoostComponent - 4 bytes (0x4)
// Source: MonkWeaponDamageDiceOverrideBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_MonkWeaponDamageDiceOverrideBoostComponent_Properties[] = {
    { "DamageDice", 0x00, FIELD_TYPE_FIXEDSTRING, 0, false },
};
static const ComponentLayoutDef g_eoc_MonkWeaponDamageDiceOverrideBoostComponent_Layout = {
    .componentName = "eoc::MonkWeaponDamageDiceOverrideBoostComponent",
    .shortName = "MonkWeaponDamageDiceOverrideBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_MonkWeaponDamageDiceOverrideBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_MonkWeaponDamageDiceOverrideBoostComponent_Properties) / sizeof(g_eoc_MonkWeaponDamageDiceOverrideBoostComponent_Properties[0]),
};

// eoc::MovementSpeedLimitBoostComponent - 1 bytes (0x1)
// Source: MovementSpeedLimitBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_MovementSpeedLimitBoostComponent_Properties[] = {
    { "MovementType", 0x00, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_MovementSpeedLimitBoostComponent_Layout = {
    .componentName = "eoc::MovementSpeedLimitBoostComponent",
    .shortName = "MovementSpeedLimitBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_eoc_MovementSpeedLimitBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_MovementSpeedLimitBoostComponent_Properties) / sizeof(g_eoc_MovementSpeedLimitBoostComponent_Properties[0]),
};

// eoc::NullifyAbilityBoostComponent - 1 bytes (0x1)
// Source: NullifyAbilityBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_NullifyAbilityBoostComponent_Properties[] = {
    { "Ability", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_NullifyAbilityBoostComponent_Layout = {
    .componentName = "eoc::NullifyAbilityBoostComponent",
    .shortName = "NullifyAbilityBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_eoc_NullifyAbilityBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_NullifyAbilityBoostComponent_Properties) / sizeof(g_eoc_NullifyAbilityBoostComponent_Properties[0]),
};

// eoc::ObjectInteractionComponent - 16 bytes (0x10)
// Source: ObjectInteractionComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ObjectInteractionComponent_Properties[] = {
    { "Interactions", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_eoc_ObjectInteractionComponent_Layout = {
    .componentName = "eoc::ObjectInteractionComponent",
    .shortName = "ObjectInteractionComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_eoc_ObjectInteractionComponent_Properties,
    .propertyCount = sizeof(g_eoc_ObjectInteractionComponent_Properties) / sizeof(g_eoc_ObjectInteractionComponent_Properties[0]),
};

// eoc::ObjectSizeBoostComponent - 4 bytes (0x4)
// Source: ObjectSizeBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ObjectSizeBoostComponent_Properties[] = {
    { "SizeCategoryAdjustment", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_ObjectSizeBoostComponent_Layout = {
    .componentName = "eoc::ObjectSizeBoostComponent",
    .shortName = "ObjectSizeBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_ObjectSizeBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_ObjectSizeBoostComponent_Properties) / sizeof(g_eoc_ObjectSizeBoostComponent_Properties[0]),
};

// eoc::ObjectSizeOverrideBoostComponent - 1 bytes (0x1)
// Source: ObjectSizeOverrideBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ObjectSizeOverrideBoostComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_ObjectSizeOverrideBoostComponent_Layout = {
    .componentName = "eoc::ObjectSizeOverrideBoostComponent",
    .shortName = "ObjectSizeOverrideBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_eoc_ObjectSizeOverrideBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_ObjectSizeOverrideBoostComponent_Properties) / sizeof(g_eoc_ObjectSizeOverrideBoostComponent_Properties[0]),
};

// eoc::PhysicalForceRangeBonusBoostComponent - 8 bytes (0x8)
// Source: PhysicalForceRangeBonusBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_PhysicalForceRangeBonusBoostComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_FLOAT, 0, false },
    { "field_4", 0x04, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_PhysicalForceRangeBonusBoostComponent_Layout = {
    .componentName = "eoc::PhysicalForceRangeBonusBoostComponent",
    .shortName = "PhysicalForceRangeBonusBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_eoc_PhysicalForceRangeBonusBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_PhysicalForceRangeBonusBoostComponent_Properties) / sizeof(g_eoc_PhysicalForceRangeBonusBoostComponent_Properties[0]),
};

// eoc::RedirectDamageBoostComponent - 8 bytes (0x8)
// Source: RedirectDamageBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_RedirectDamageBoostComponent_Properties[] = {
    { "Amount", 0x00, FIELD_TYPE_INT32, 0, false },
    { "DamageType1", 0x04, FIELD_TYPE_INT32, 0, false },
    { "DamageType2", 0x08, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_RedirectDamageBoostComponent_Layout = {
    .componentName = "eoc::RedirectDamageBoostComponent",
    .shortName = "RedirectDamageBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_eoc_RedirectDamageBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_RedirectDamageBoostComponent_Properties) / sizeof(g_eoc_RedirectDamageBoostComponent_Properties[0]),
};

// eoc::ReduceCriticalAttackThresholdBoostComponent - 8 bytes (0x8)
// Source: ReduceCriticalAttackThresholdBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ReduceCriticalAttackThresholdBoostComponent_Properties[] = {
    { "Status", 0x00, FIELD_TYPE_FIXEDSTRING, 0, false },
};
static const ComponentLayoutDef g_eoc_ReduceCriticalAttackThresholdBoostComponent_Layout = {
    .componentName = "eoc::ReduceCriticalAttackThresholdBoostComponent",
    .shortName = "ReduceCriticalAttackThresholdBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_eoc_ReduceCriticalAttackThresholdBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_ReduceCriticalAttackThresholdBoostComponent_Properties) / sizeof(g_eoc_ReduceCriticalAttackThresholdBoostComponent_Properties[0]),
};

// eoc::ResistanceBoostComponent - 3 bytes (0x3)
// Source: ResistanceBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ResistanceBoostComponent_Properties[] = {
    { "DamageType", 0x00, FIELD_TYPE_INT32, 0, false },
    { "ResistanceFlags", 0x04, FIELD_TYPE_UINT8, 0, false },
    { "IsResistantToAll", 0x05, FIELD_TYPE_BOOL, 0, false },
};
static const ComponentLayoutDef g_eoc_ResistanceBoostComponent_Layout = {
    .componentName = "eoc::ResistanceBoostComponent",
    .shortName = "ResistanceBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x3,
    .properties = g_eoc_ResistanceBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_ResistanceBoostComponent_Properties) / sizeof(g_eoc_ResistanceBoostComponent_Properties[0]),
};

// eoc::RollBonusBoostComponent - 48 bytes (0x30)
// Source: RollBonusBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_RollBonusBoostComponent_Properties[] = {
    { "Ability", 0x00, FIELD_TYPE_INT32, 0, false },
    { "Skill", 0x04, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_RollBonusBoostComponent_Layout = {
    .componentName = "eoc::RollBonusBoostComponent",
    .shortName = "RollBonusBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_eoc_RollBonusBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_RollBonusBoostComponent_Properties) / sizeof(g_eoc_RollBonusBoostComponent_Properties[0]),
};

// eoc::ScaleMultiplierBoostComponent - 4 bytes (0x4)
// Source: ScaleMultiplierBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ScaleMultiplierBoostComponent_Properties[] = {
    { "Multiplier", 0x00, FIELD_TYPE_FLOAT, 0, false },
};
static const ComponentLayoutDef g_eoc_ScaleMultiplierBoostComponent_Layout = {
    .componentName = "eoc::ScaleMultiplierBoostComponent",
    .shortName = "ScaleMultiplierBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_ScaleMultiplierBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_ScaleMultiplierBoostComponent_Properties) / sizeof(g_eoc_ScaleMultiplierBoostComponent_Properties[0]),
};

// eoc::SightRangeAdditiveBoostComponent - 4 bytes (0x4)
// Source: SightRangeAdditiveBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_SightRangeAdditiveBoostComponent_Properties[] = {
    { "Range", 0x00, FIELD_TYPE_FLOAT, 0, false },
};
static const ComponentLayoutDef g_eoc_SightRangeAdditiveBoostComponent_Layout = {
    .componentName = "eoc::SightRangeAdditiveBoostComponent",
    .shortName = "SightRangeAdditiveBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_SightRangeAdditiveBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_SightRangeAdditiveBoostComponent_Properties) / sizeof(g_eoc_SightRangeAdditiveBoostComponent_Properties[0]),
};

// eoc::SightRangeMaximumBoostComponent - 4 bytes (0x4)
// Source: SightRangeMaximumBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_SightRangeMaximumBoostComponent_Properties[] = {
    { "Range", 0x00, FIELD_TYPE_FLOAT, 0, false },
};
static const ComponentLayoutDef g_eoc_SightRangeMaximumBoostComponent_Layout = {
    .componentName = "eoc::SightRangeMaximumBoostComponent",
    .shortName = "SightRangeMaximumBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_SightRangeMaximumBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_SightRangeMaximumBoostComponent_Properties) / sizeof(g_eoc_SightRangeMaximumBoostComponent_Properties[0]),
};

// eoc::SightRangeMinimumBoostComponent - 4 bytes (0x4)
// Source: SightRangeMinimumBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_SightRangeMinimumBoostComponent_Properties[] = {
    { "Range", 0x00, FIELD_TYPE_FLOAT, 0, false },
};
static const ComponentLayoutDef g_eoc_SightRangeMinimumBoostComponent_Layout = {
    .componentName = "eoc::SightRangeMinimumBoostComponent",
    .shortName = "SightRangeMinimumBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_SightRangeMinimumBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_SightRangeMinimumBoostComponent_Properties) / sizeof(g_eoc_SightRangeMinimumBoostComponent_Properties[0]),
};

// eoc::SightRangeOverrideBoostComponent - 4 bytes (0x4)
// Source: SightRangeOverrideBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_SightRangeOverrideBoostComponent_Properties[] = {
    { "Range", 0x00, FIELD_TYPE_FLOAT, 0, false },
};
static const ComponentLayoutDef g_eoc_SightRangeOverrideBoostComponent_Layout = {
    .componentName = "eoc::SightRangeOverrideBoostComponent",
    .shortName = "SightRangeOverrideBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_SightRangeOverrideBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_SightRangeOverrideBoostComponent_Properties) / sizeof(g_eoc_SightRangeOverrideBoostComponent_Properties[0]),
};

// eoc::SkillBoostComponent - 40 bytes (0x28)
// Source: SkillBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_SkillBoostComponent_Properties[] = {
    { "Skill", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_SkillBoostComponent_Layout = {
    .componentName = "eoc::SkillBoostComponent",
    .shortName = "SkillBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_eoc_SkillBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_SkillBoostComponent_Properties) / sizeof(g_eoc_SkillBoostComponent_Properties[0]),
};

// eoc::SourceAdvantageBoostComponent - 16 bytes (0x10)
// Source: SourceAdvantageBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_SourceAdvantageBoostComponent_Properties[] = {
    { "field_8", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false },
};
static const ComponentLayoutDef g_eoc_SourceAdvantageBoostComponent_Layout = {
    .componentName = "eoc::SourceAdvantageBoostComponent",
    .shortName = "SourceAdvantageBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_eoc_SourceAdvantageBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_SourceAdvantageBoostComponent_Properties) / sizeof(g_eoc_SourceAdvantageBoostComponent_Properties[0]),
};

// eoc::SpellResistanceBoostComponent - 1 bytes (0x1)
// Source: SpellResistanceBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_SpellResistanceBoostComponent_Properties[] = {
    { "Resistance", 0x00, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_SpellResistanceBoostComponent_Layout = {
    .componentName = "eoc::SpellResistanceBoostComponent",
    .shortName = "SpellResistanceBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_eoc_SpellResistanceBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_SpellResistanceBoostComponent_Properties) / sizeof(g_eoc_SpellResistanceBoostComponent_Properties[0]),
};

// eoc::SpellSaveDCBoostComponent - 4 bytes (0x4)
// Source: SpellSaveDCBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_SpellSaveDCBoostComponent_Properties[] = {
    { "DC", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_SpellSaveDCBoostComponent_Layout = {
    .componentName = "eoc::SpellSaveDCBoostComponent",
    .shortName = "SpellSaveDCBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_SpellSaveDCBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_SpellSaveDCBoostComponent_Properties) / sizeof(g_eoc_SpellSaveDCBoostComponent_Properties[0]),
};

// eoc::StatusImmunityBoostComponent - 24 bytes (0x18)
// Source: StatusImmunityBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_StatusImmunityBoostComponent_Properties[] = {
    { "StatusID", 0x00, FIELD_TYPE_FIXEDSTRING, 0, false },
};
static const ComponentLayoutDef g_eoc_StatusImmunityBoostComponent_Layout = {
    .componentName = "eoc::StatusImmunityBoostComponent",
    .shortName = "StatusImmunityBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_eoc_StatusImmunityBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_StatusImmunityBoostComponent_Properties) / sizeof(g_eoc_StatusImmunityBoostComponent_Properties[0]),
};

// eoc::StealthComponent - 36 bytes (0x24)
// Source: StealthComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_StealthComponent_Properties[] = {
    { "SeekHiddenFlag", 0x00, FIELD_TYPE_BOOL, 0, false },
    { "SeekHiddenTimeout", 0x04, FIELD_TYPE_FLOAT, 0, false },
    { "field_14", 0x08, FIELD_TYPE_FLOAT, 0, false },
    { "field_18", 0x0C, FIELD_TYPE_INT32, 0, false },
    { "field_1C", 0x10, FIELD_TYPE_FLOAT, 0, false },
    { "field_20", 0x14, FIELD_TYPE_FLOAT, 0, false },
};
static const ComponentLayoutDef g_eoc_StealthComponent_Layout = {
    .componentName = "eoc::StealthComponent",
    .shortName = "StealthComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x24,
    .properties = g_eoc_StealthComponent_Properties,
    .propertyCount = sizeof(g_eoc_StealthComponent_Properties) / sizeof(g_eoc_StealthComponent_Properties[0]),
};

// eoc::TurnOrderComponent - 80 bytes (0x50)
// Source: TurnOrderComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_TurnOrderComponent_Properties[] = {
    { "TurnOrderIndices", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
    { "TurnOrderIndices2", 0x10, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
    { "field_40", 0x20, FIELD_TYPE_INT32, 0, false },
    { "field_44", 0x24, FIELD_TYPE_INT32, 0, false },
    { "field_48", 0x28, FIELD_TYPE_INT32, 0, false },
    { "field_4C", 0x2C, FIELD_TYPE_FLOAT, 0, false },
};
static const ComponentLayoutDef g_eoc_TurnOrderComponent_Layout = {
    .componentName = "eoc::TurnOrderComponent",
    .shortName = "TurnOrderComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x50,
    .properties = g_eoc_TurnOrderComponent_Properties,
    .propertyCount = sizeof(g_eoc_TurnOrderComponent_Properties) / sizeof(g_eoc_TurnOrderComponent_Properties[0]),
};

// eoc::UnlockInterruptBoostComponent - 4 bytes (0x4)
// Source: UnlockInterruptBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_UnlockInterruptBoostComponent_Properties[] = {
    { "Interrupt", 0x00, FIELD_TYPE_FIXEDSTRING, 0, false },
};
static const ComponentLayoutDef g_eoc_UnlockInterruptBoostComponent_Layout = {
    .componentName = "eoc::UnlockInterruptBoostComponent",
    .shortName = "UnlockInterruptBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_UnlockInterruptBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_UnlockInterruptBoostComponent_Properties) / sizeof(g_eoc_UnlockInterruptBoostComponent_Properties[0]),
};

// eoc::UseBoostsComponent - 16 bytes (0x10)
// Source: UseBoostsComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_UseBoostsComponent_Properties[] = {
    { "Boosts", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_eoc_UseBoostsComponent_Layout = {
    .componentName = "eoc::UseBoostsComponent",
    .shortName = "UseBoostsComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_eoc_UseBoostsComponent_Properties,
    .propertyCount = sizeof(g_eoc_UseBoostsComponent_Properties) / sizeof(g_eoc_UseBoostsComponent_Properties[0]),
};

// eoc::UseComponent - 80 bytes (0x50)
// Source: UseComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_UseComponent_Properties[] = {
    { "Requirements", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
    { "Charges", 0x10, FIELD_TYPE_INT32, 0, false },
    { "MaxCharges", 0x14, FIELD_TYPE_INT32, 0, false },
    { "Boosts", 0x18, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
    { "BoostsOnEquipMainHand", 0x28, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
    { "BoostsOnEquipOffHand", 0x38, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_eoc_UseComponent_Layout = {
    .componentName = "eoc::UseComponent",
    .shortName = "UseComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x50,
    .properties = g_eoc_UseComponent_Properties,
    .propertyCount = sizeof(g_eoc_UseComponent_Properties) / sizeof(g_eoc_UseComponent_Properties[0]),
};

// eoc::VoiceComponent - 16 bytes (0x10)
// Source: VoiceComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_VoiceComponent_Properties[] = {
    { "Voice", 0x00, FIELD_TYPE_GUID, 0, false },
};
static const ComponentLayoutDef g_eoc_VoiceComponent_Layout = {
    .componentName = "eoc::VoiceComponent",
    .shortName = "VoiceComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_eoc_VoiceComponent_Properties,
    .propertyCount = sizeof(g_eoc_VoiceComponent_Properties) / sizeof(g_eoc_VoiceComponent_Properties[0]),
};

// eoc::VoiceTagComponent - 16 bytes (0x10)
// Source: VoiceTagComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_VoiceTagComponent_Properties[] = {
    { "Tags", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_eoc_VoiceTagComponent_Layout = {
    .componentName = "eoc::VoiceTagComponent",
    .shortName = "VoiceTagComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_eoc_VoiceTagComponent_Properties,
    .propertyCount = sizeof(g_eoc_VoiceTagComponent_Properties) / sizeof(g_eoc_VoiceTagComponent_Properties[0]),
};

// eoc::WeaponAttackRollAbilityOverrideBoostComponent - 1 bytes (0x1)
// Source: WeaponAttackRollAbilityOverrideBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_WeaponAttackRollAbilityOverrideBoostComponent_Properties[] = {
    { "Ability", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_WeaponAttackRollAbilityOverrideBoostComponent_Layout = {
    .componentName = "eoc::WeaponAttackRollAbilityOverrideBoostComponent",
    .shortName = "WeaponAttackRollAbilityOverrideBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_eoc_WeaponAttackRollAbilityOverrideBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_WeaponAttackRollAbilityOverrideBoostComponent_Properties) / sizeof(g_eoc_WeaponAttackRollAbilityOverrideBoostComponent_Properties[0]),
};

// eoc::WeaponAttackTypeOverrideBoostComponent - 1 bytes (0x1)
// Source: WeaponAttackTypeOverrideBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_WeaponAttackTypeOverrideBoostComponent_Properties[] = {
    { "AttackType", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_WeaponAttackTypeOverrideBoostComponent_Layout = {
    .componentName = "eoc::WeaponAttackTypeOverrideBoostComponent",
    .shortName = "WeaponAttackTypeOverrideBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_eoc_WeaponAttackTypeOverrideBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_WeaponAttackTypeOverrideBoostComponent_Properties) / sizeof(g_eoc_WeaponAttackTypeOverrideBoostComponent_Properties[0]),
};

// eoc::WeaponDamageBoostComponent - 48 bytes (0x30)
// Source: WeaponDamageBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_WeaponDamageBoostComponent_Properties[] = {
    { "DamageType", 0x00, FIELD_TYPE_INT32, 0, false },
    { "field_30", 0x04, FIELD_TYPE_BOOL, 0, false },
};
static const ComponentLayoutDef g_eoc_WeaponDamageBoostComponent_Layout = {
    .componentName = "eoc::WeaponDamageBoostComponent",
    .shortName = "WeaponDamageBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_eoc_WeaponDamageBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_WeaponDamageBoostComponent_Properties) / sizeof(g_eoc_WeaponDamageBoostComponent_Properties[0]),
};

// eoc::WeaponDamageResistanceBoostComponent - 16 bytes (0x10)
// Source: WeaponDamageResistanceBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_WeaponDamageResistanceBoostComponent_Properties[] = {
    { "DamageTypes", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_eoc_WeaponDamageResistanceBoostComponent_Layout = {
    .componentName = "eoc::WeaponDamageResistanceBoostComponent",
    .shortName = "WeaponDamageResistanceBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_eoc_WeaponDamageResistanceBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_WeaponDamageResistanceBoostComponent_Properties) / sizeof(g_eoc_WeaponDamageResistanceBoostComponent_Properties[0]),
};

// eoc::WeaponDamageTypeOverrideBoostComponent - 1 bytes (0x1)
// Source: WeaponDamageTypeOverrideBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_WeaponDamageTypeOverrideBoostComponent_Properties[] = {
    { "DamageType", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_WeaponDamageTypeOverrideBoostComponent_Layout = {
    .componentName = "eoc::WeaponDamageTypeOverrideBoostComponent",
    .shortName = "WeaponDamageTypeOverrideBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_eoc_WeaponDamageTypeOverrideBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_WeaponDamageTypeOverrideBoostComponent_Properties) / sizeof(g_eoc_WeaponDamageTypeOverrideBoostComponent_Properties[0]),
};

// eoc::WeaponEnchantmentBoostComponent - 4 bytes (0x4)
// Source: WeaponEnchantmentBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_WeaponEnchantmentBoostComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_WeaponEnchantmentBoostComponent_Layout = {
    .componentName = "eoc::WeaponEnchantmentBoostComponent",
    .shortName = "WeaponEnchantmentBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_WeaponEnchantmentBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_WeaponEnchantmentBoostComponent_Properties) / sizeof(g_eoc_WeaponEnchantmentBoostComponent_Properties[0]),
};

// eoc::WeaponPropertyBoostComponent - 4 bytes (0x4)
// Source: WeaponPropertyBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_WeaponPropertyBoostComponent_Properties[] = {
    { "Properties", 0x00, FIELD_TYPE_UINT32, 0, false },
};
static const ComponentLayoutDef g_eoc_WeaponPropertyBoostComponent_Layout = {
    .componentName = "eoc::WeaponPropertyBoostComponent",
    .shortName = "WeaponPropertyBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_WeaponPropertyBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_WeaponPropertyBoostComponent_Properties) / sizeof(g_eoc_WeaponPropertyBoostComponent_Properties[0]),
};

// eoc::WeightBoostComponent - 4 bytes (0x4)
// Source: WeightBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_WeightBoostComponent_Properties[] = {
    { "Amount", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_WeightBoostComponent_Layout = {
    .componentName = "eoc::WeightBoostComponent",
    .shortName = "WeightBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_WeightBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_WeightBoostComponent_Properties) / sizeof(g_eoc_WeightBoostComponent_Properties[0]),
};

// eoc::WeightCategoryBoostComponent - 4 bytes (0x4)
// Source: WeightCategoryBoostComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_WeightCategoryBoostComponent_Properties[] = {
    { "Amount", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_WeightCategoryBoostComponent_Layout = {
    .componentName = "eoc::WeightCategoryBoostComponent",
    .shortName = "WeightCategoryBoostComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_WeightCategoryBoostComponent_Properties,
    .propertyCount = sizeof(g_eoc_WeightCategoryBoostComponent_Properties) / sizeof(g_eoc_WeightCategoryBoostComponent_Properties[0]),
};

// eoc::action::ActionUseConditionsComponent - 16 bytes (0x10)
// Source: ActionUseConditionsComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ActionUseConditionsComponent_Properties[] = {
    { "Conditions", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_eoc_ActionUseConditionsComponent_Layout = {
    .componentName = "eoc::action::ActionUseConditionsComponent",
    .shortName = "ActionUseConditionsComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_eoc_ActionUseConditionsComponent_Properties,
    .propertyCount = sizeof(g_eoc_ActionUseConditionsComponent_Properties) / sizeof(g_eoc_ActionUseConditionsComponent_Properties[0]),
};

// eoc::approval::RatingsComponent - 112 bytes (0x70)
// Source: ApprovalRatingsComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_RatingsComponent_Properties[] = {
    { "Ratings", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false },
    { "field_70", 0x08, FIELD_TYPE_GUID, 0, false },
};
static const ComponentLayoutDef g_eoc_RatingsComponent_Layout = {
    .componentName = "eoc::approval::RatingsComponent",
    .shortName = "RatingsComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x70,
    .properties = g_eoc_RatingsComponent_Properties,
    .propertyCount = sizeof(g_eoc_RatingsComponent_Properties) / sizeof(g_eoc_RatingsComponent_Properties[0]),
};

// eoc::background::GoalsComponent - 64 bytes (0x40)
// Source: GoalsComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_GoalsComponent_Properties[] = {
    { "Goals", 0x00, FIELD_TYPE_GUID, 0, true },
};
static const ComponentLayoutDef g_eoc_GoalsComponent_Layout = {
    .componentName = "eoc::background::GoalsComponent",
    .shortName = "GoalsComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x40,
    .properties = g_eoc_GoalsComponent_Properties,
    .propertyCount = sizeof(g_eoc_GoalsComponent_Properties) / sizeof(g_eoc_GoalsComponent_Properties[0]),
};

// eoc::calendar::DaysPassedComponent - 4 bytes (0x4)
// Source: DaysPassedComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_DaysPassedComponent_Properties[] = {
    { "Days", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_DaysPassedComponent_Layout = {
    .componentName = "eoc::calendar::DaysPassedComponent",
    .shortName = "DaysPassedComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_DaysPassedComponent_Properties,
    .propertyCount = sizeof(g_eoc_DaysPassedComponent_Properties) / sizeof(g_eoc_DaysPassedComponent_Properties[0]),
};

// eoc::calendar::StartingDateComponent - 8 bytes (0x8)
// Source: StartingDateComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_StartingDateComponent_Properties[] = {
    { "Day", 0x00, FIELD_TYPE_INT32, 0, false },
    { "Year", 0x04, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_StartingDateComponent_Layout = {
    .componentName = "eoc::calendar::StartingDateComponent",
    .shortName = "StartingDateComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_eoc_StartingDateComponent_Properties,
    .propertyCount = sizeof(g_eoc_StartingDateComponent_Properties) / sizeof(g_eoc_StartingDateComponent_Properties[0]),
};

// eoc::character_creation::LevelUpComponent - 16 bytes (0x10)
// Source: LevelUpComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_LevelUpComponent_Properties[] = {
    { "LevelUps", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_eoc_LevelUpComponent_Layout = {
    .componentName = "eoc::character_creation::LevelUpComponent",
    .shortName = "LevelUpComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_eoc_LevelUpComponent_Properties,
    .propertyCount = sizeof(g_eoc_LevelUpComponent_Properties) / sizeof(g_eoc_LevelUpComponent_Properties[0]),
};

// eoc::character_creation::SessionCommonComponent - 12 bytes (0xC)
// Source: SessionCommonComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_SessionCommonComponent_Properties[] = {
    { "NetId", 0x00, FIELD_TYPE_INT32, 0, false },
    { "field_4", 0x04, FIELD_TYPE_INT32, 0, false },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_SessionCommonComponent_Layout = {
    .componentName = "eoc::character_creation::SessionCommonComponent",
    .shortName = "SessionCommonComponent",
    .componentTypeIndex = 0,
    .componentSize = 0xC,
    .properties = g_eoc_SessionCommonComponent_Properties,
    .propertyCount = sizeof(g_eoc_SessionCommonComponent_Properties) / sizeof(g_eoc_SessionCommonComponent_Properties[0]),
};

// eoc::character_creation::StateComponent - 3 bytes (0x3)
// Source: StateComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_StateComponent_Properties[] = {
    { "HasDummy", 0x00, FIELD_TYPE_BOOL, 0, false },
    { "Canceled", 0x01, FIELD_TYPE_BOOL, 0, false },
    { "field_2", 0x02, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_StateComponent_Layout = {
    .componentName = "eoc::character_creation::StateComponent",
    .shortName = "StateComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x3,
    .properties = g_eoc_StateComponent_Properties,
    .propertyCount = sizeof(g_eoc_StateComponent_Properties) / sizeof(g_eoc_StateComponent_Properties[0]),
};

// eoc::combat::IsThreatenedComponent - 16 bytes (0x10)
// Source: IsThreatenedComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_IsThreatenedComponent_Properties[] = {
    { "ThreatenedBy", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_eoc_IsThreatenedComponent_Layout = {
    .componentName = "eoc::combat::IsThreatenedComponent",
    .shortName = "IsThreatenedComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_eoc_IsThreatenedComponent_Properties,
    .propertyCount = sizeof(g_eoc_IsThreatenedComponent_Properties) / sizeof(g_eoc_IsThreatenedComponent_Properties[0]),
};

// eoc::encumbrance::StateComponent - 4 bytes (0x4)
// Source: EncumbranceStateComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_EncumbranceStateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_UINT32, 0, false },
};
static const ComponentLayoutDef g_eoc_EncumbranceStateComponent_Layout = {
    .componentName = "eoc::encumbrance::StateComponent",
    .shortName = "EncumbranceStateComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_EncumbranceStateComponent_Properties,
    .propertyCount = sizeof(g_eoc_EncumbranceStateComponent_Properties) / sizeof(g_eoc_EncumbranceStateComponent_Properties[0]),
};

// eoc::ftb::ParticipantComponent - 8 bytes (0x8)
// Source: ParticipantComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ParticipantComponent_Properties[] = {
    { "field_18", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false },
};
static const ComponentLayoutDef g_eoc_ParticipantComponent_Layout = {
    .componentName = "eoc::ftb::ParticipantComponent",
    .shortName = "ParticipantComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_eoc_ParticipantComponent_Properties,
    .propertyCount = sizeof(g_eoc_ParticipantComponent_Properties) / sizeof(g_eoc_ParticipantComponent_Properties[0]),
};

// eoc::ftb::ZoneBlockReasonComponent - 1 bytes (0x1)
// Source: ZoneBlockReasonComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ZoneBlockReasonComponent_Properties[] = {
    { "Reason", 0x00, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_ZoneBlockReasonComponent_Layout = {
    .componentName = "eoc::ftb::ZoneBlockReasonComponent",
    .shortName = "ZoneBlockReasonComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_eoc_ZoneBlockReasonComponent_Properties,
    .propertyCount = sizeof(g_eoc_ZoneBlockReasonComponent_Properties) / sizeof(g_eoc_ZoneBlockReasonComponent_Properties[0]),
};

// eoc::god::TagComponent - 16 bytes (0x10)
// Source: GodTagComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_TagComponent_Properties[] = {
    { "Tags", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_eoc_TagComponent_Layout = {
    .componentName = "eoc::god::TagComponent",
    .shortName = "TagComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_eoc_TagComponent_Properties,
    .propertyCount = sizeof(g_eoc_TagComponent_Properties) / sizeof(g_eoc_TagComponent_Properties[0]),
};

// eoc::hotbar::ContainerComponent - 72 bytes (0x48)
// Source: ContainerComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ContainerComponent_Properties[] = {
    { "ActiveContainer", 0x00, FIELD_TYPE_FIXEDSTRING, 0, false },
};
static const ComponentLayoutDef g_eoc_ContainerComponent_Layout = {
    .componentName = "eoc::hotbar::ContainerComponent",
    .shortName = "ContainerComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x48,
    .properties = g_eoc_ContainerComponent_Properties,
    .propertyCount = sizeof(g_eoc_ContainerComponent_Properties) / sizeof(g_eoc_ContainerComponent_Properties[0]),
};

// eoc::improvised_weapon::WieldedComponent - 16 bytes (0x10)
// Source: WieldedComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_WieldedComponent_Properties[] = {
    { "Wielder", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, false },
    { "field_9", 0x09, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_WieldedComponent_Layout = {
    .componentName = "eoc::improvised_weapon::WieldedComponent",
    .shortName = "WieldedComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_eoc_WieldedComponent_Properties,
    .propertyCount = sizeof(g_eoc_WieldedComponent_Properties) / sizeof(g_eoc_WieldedComponent_Properties[0]),
};

// eoc::improvised_weapon::WieldingComponent - 8 bytes (0x8)
// Source: WieldingComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_WieldingComponent_Properties[] = {
    { "Weapon", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false },
};
static const ComponentLayoutDef g_eoc_WieldingComponent_Layout = {
    .componentName = "eoc::improvised_weapon::WieldingComponent",
    .shortName = "WieldingComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_eoc_WieldingComponent_Properties,
    .propertyCount = sizeof(g_eoc_WieldingComponent_Properties) / sizeof(g_eoc_WieldingComponent_Properties[0]),
};

// eoc::inventory::StackMemberComponent - 8 bytes (0x8)
// Source: StackMemberComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_StackMemberComponent_Properties[] = {
    { "Stack", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false },
};
static const ComponentLayoutDef g_eoc_StackMemberComponent_Layout = {
    .componentName = "eoc::inventory::StackMemberComponent",
    .shortName = "StackMemberComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_eoc_StackMemberComponent_Properties,
    .propertyCount = sizeof(g_eoc_StackMemberComponent_Properties) / sizeof(g_eoc_StackMemberComponent_Properties[0]),
};

// eoc::inventory::TopOwnerComponent - 8 bytes (0x8)
// Source: TopOwnerComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_TopOwnerComponent_Properties[] = {
    { "TopOwner", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false },
};
static const ComponentLayoutDef g_eoc_TopOwnerComponent_Layout = {
    .componentName = "eoc::inventory::TopOwnerComponent",
    .shortName = "TopOwnerComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_eoc_TopOwnerComponent_Properties,
    .propertyCount = sizeof(g_eoc_TopOwnerComponent_Properties) / sizeof(g_eoc_TopOwnerComponent_Properties[0]),
};

// eoc::inventory::TradeBuybackDataComponent - 24 bytes (0x18)
// Source: TradeBuybackDataComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_TradeBuybackDataComponent_Properties[] = {
    { "Amount", 0x00, FIELD_TYPE_UINT32, 0, false },
    { "Trader", 0x04, FIELD_TYPE_ENTITY_HANDLE, 0, false },
    { "Buyer", 0x0C, FIELD_TYPE_ENTITY_HANDLE, 0, false },
};
static const ComponentLayoutDef g_eoc_TradeBuybackDataComponent_Layout = {
    .componentName = "eoc::inventory::TradeBuybackDataComponent",
    .shortName = "TradeBuybackDataComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_eoc_TradeBuybackDataComponent_Properties,
    .propertyCount = sizeof(g_eoc_TradeBuybackDataComponent_Properties) / sizeof(g_eoc_TradeBuybackDataComponent_Properties[0]),
};

// eoc::item::DyeComponent - 16 bytes (0x10)
// Source: DyeComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_DyeComponent_Properties[] = {
    { "Color", 0x00, FIELD_TYPE_GUID, 0, false },
};
static const ComponentLayoutDef g_eoc_DyeComponent_Layout = {
    .componentName = "eoc::item::DyeComponent",
    .shortName = "DyeComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_eoc_DyeComponent_Properties,
    .propertyCount = sizeof(g_eoc_DyeComponent_Properties) / sizeof(g_eoc_DyeComponent_Properties[0]),
};

// eoc::item::MapMarkerStyleComponent - 4 bytes (0x4)
// Source: MapMarkerStyleComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_MapMarkerStyleComponent_Properties[] = {
    { "Style", 0x00, FIELD_TYPE_FIXEDSTRING, 0, false },
};
static const ComponentLayoutDef g_eoc_MapMarkerStyleComponent_Layout = {
    .componentName = "eoc::item::MapMarkerStyleComponent",
    .shortName = "MapMarkerStyleComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_MapMarkerStyleComponent_Properties,
    .propertyCount = sizeof(g_eoc_MapMarkerStyleComponent_Properties) / sizeof(g_eoc_MapMarkerStyleComponent_Properties[0]),
};

// eoc::item::PortalComponent - 2 bytes (0x2)
// Source: PortalComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_PortalComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, false },
    { "field_1", 0x01, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_PortalComponent_Layout = {
    .componentName = "eoc::item::PortalComponent",
    .shortName = "PortalComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_eoc_PortalComponent_Properties,
    .propertyCount = sizeof(g_eoc_PortalComponent_Properties) / sizeof(g_eoc_PortalComponent_Properties[0]),
};

// eoc::lock::KeyComponent - 4 bytes (0x4)
// Source: KeyComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_KeyComponent_Properties[] = {
    { "Key", 0x00, FIELD_TYPE_FIXEDSTRING, 0, false },
};
static const ComponentLayoutDef g_eoc_KeyComponent_Layout = {
    .componentName = "eoc::lock::KeyComponent",
    .shortName = "KeyComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_KeyComponent_Properties,
    .propertyCount = sizeof(g_eoc_KeyComponent_Properties) / sizeof(g_eoc_KeyComponent_Properties[0]),
};

// eoc::lock::LockComponent - 40 bytes (0x28)
// Source: LockComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_LockComponent_Properties[] = {
    { "Key_M", 0x00, FIELD_TYPE_FIXEDSTRING, 0, false },
    { "LockDC", 0x04, FIELD_TYPE_INT32, 0, false },
    { "field_8", 0x08, FIELD_TYPE_GUID, 0, false },
    { "field_18", 0x18, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_eoc_LockComponent_Layout = {
    .componentName = "eoc::lock::LockComponent",
    .shortName = "LockComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_eoc_LockComponent_Properties,
    .propertyCount = sizeof(g_eoc_LockComponent_Properties) / sizeof(g_eoc_LockComponent_Properties[0]),
};

// eoc::pickup::PickUpRequestComponent - 24 bytes (0x18)
// Source: PickUpRequestComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_PickUpRequestComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_GUID, 0, false },
    { "State", 0x10, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_PickUpRequestComponent_Layout = {
    .componentName = "eoc::pickup::PickUpRequestComponent",
    .shortName = "PickUpRequestComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_eoc_PickUpRequestComponent_Properties,
    .propertyCount = sizeof(g_eoc_PickUpRequestComponent_Properties) / sizeof(g_eoc_PickUpRequestComponent_Properties[0]),
};

// eoc::spell::AddedSpellsComponent - 16 bytes (0x10)
// Source: AddedSpellsComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_AddedSpellsComponent_Properties[] = {
    { "Spells", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_eoc_AddedSpellsComponent_Layout = {
    .componentName = "eoc::spell::AddedSpellsComponent",
    .shortName = "AddedSpellsComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_eoc_AddedSpellsComponent_Properties,
    .propertyCount = sizeof(g_eoc_AddedSpellsComponent_Properties) / sizeof(g_eoc_AddedSpellsComponent_Properties[0]),
};

// eoc::spell::BookCooldownsComponent - 16 bytes (0x10)
// Source: SpellBookCooldownsComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_BookCooldownsComponent_Properties[] = {
    { "Cooldowns", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_eoc_BookCooldownsComponent_Layout = {
    .componentName = "eoc::spell::BookCooldownsComponent",
    .shortName = "BookCooldownsComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_eoc_BookCooldownsComponent_Properties,
    .propertyCount = sizeof(g_eoc_BookCooldownsComponent_Properties) / sizeof(g_eoc_BookCooldownsComponent_Properties[0]),
};

// eoc::spell::CCPrepareSpellComponent - 16 bytes (0x10)
// Source: CCPrepareSpellComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_CCPrepareSpellComponent_Properties[] = {
    { "Spells", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_eoc_CCPrepareSpellComponent_Layout = {
    .componentName = "eoc::spell::CCPrepareSpellComponent",
    .shortName = "CCPrepareSpellComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_eoc_CCPrepareSpellComponent_Properties,
    .propertyCount = sizeof(g_eoc_CCPrepareSpellComponent_Properties) / sizeof(g_eoc_CCPrepareSpellComponent_Properties[0]),
};

// eoc::spell::PlayerPrepareSpellComponent - 24 bytes (0x18)
// Source: PlayerPrepareSpellComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_PlayerPrepareSpellComponent_Properties[] = {
    { "Spells", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_eoc_PlayerPrepareSpellComponent_Layout = {
    .componentName = "eoc::spell::PlayerPrepareSpellComponent",
    .shortName = "PlayerPrepareSpellComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_eoc_PlayerPrepareSpellComponent_Properties,
    .propertyCount = sizeof(g_eoc_PlayerPrepareSpellComponent_Properties) / sizeof(g_eoc_PlayerPrepareSpellComponent_Properties[0]),
};

// eoc::spell::ScriptedExplosionComponent - 4 bytes (0x4)
// Source: ScriptedExplosionComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_ScriptedExplosionComponent_Properties[] = {
    { "Projectile", 0x00, FIELD_TYPE_FIXEDSTRING, 0, false },
};
static const ComponentLayoutDef g_eoc_ScriptedExplosionComponent_Layout = {
    .componentName = "eoc::spell::ScriptedExplosionComponent",
    .shortName = "ScriptedExplosionComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_ScriptedExplosionComponent_Properties,
    .propertyCount = sizeof(g_eoc_ScriptedExplosionComponent_Properties) / sizeof(g_eoc_ScriptedExplosionComponent_Properties[0]),
};

// eoc::status::CauseComponent - 8 bytes (0x8)
// Source: CauseComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_CauseComponent_Properties[] = {
    { "Cause", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, false },
};
static const ComponentLayoutDef g_eoc_CauseComponent_Layout = {
    .componentName = "eoc::status::CauseComponent",
    .shortName = "CauseComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_eoc_CauseComponent_Properties,
    .propertyCount = sizeof(g_eoc_CauseComponent_Properties) / sizeof(g_eoc_CauseComponent_Properties[0]),
};

// eoc::status::IDComponent - 4 bytes (0x4)
// Source: IDComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_IDComponent_Properties[] = {
    { "ID", 0x00, FIELD_TYPE_FIXEDSTRING, 0, false },
};
static const ComponentLayoutDef g_eoc_IDComponent_Layout = {
    .componentName = "eoc::status::IDComponent",
    .shortName = "IDComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_eoc_IDComponent_Properties,
    .propertyCount = sizeof(g_eoc_IDComponent_Properties) / sizeof(g_eoc_IDComponent_Properties[0]),
};

// eoc::status::IncapacitatedComponent - 80 bytes (0x50)
// Source: IncapacitatedComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_IncapacitatedComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT32, 0, false },
    { "field_48", 0x04, FIELD_TYPE_UINT8, 0, false },
};
static const ComponentLayoutDef g_eoc_IncapacitatedComponent_Layout = {
    .componentName = "eoc::status::IncapacitatedComponent",
    .shortName = "IncapacitatedComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x50,
    .properties = g_eoc_IncapacitatedComponent_Properties,
    .propertyCount = sizeof(g_eoc_IncapacitatedComponent_Properties) / sizeof(g_eoc_IncapacitatedComponent_Properties[0]),
};

// eoc::status::LifetimeComponent - 8 bytes (0x8)
// Source: LifetimeComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_LifetimeComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, false },
};
static const ComponentLayoutDef g_eoc_LifetimeComponent_Layout = {
    .componentName = "eoc::status::LifetimeComponent",
    .shortName = "LifetimeComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_eoc_LifetimeComponent_Properties,
    .propertyCount = sizeof(g_eoc_LifetimeComponent_Properties) / sizeof(g_eoc_LifetimeComponent_Properties[0]),
};

// eoc::status::LoseControlComponent - 1 bytes (0x1)
// Source: LoseControlComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_LoseControlComponent_Properties[] = {
    { "LoseControl", 0x00, FIELD_TYPE_BOOL, 0, false },
};
static const ComponentLayoutDef g_eoc_LoseControlComponent_Layout = {
    .componentName = "eoc::status::LoseControlComponent",
    .shortName = "LoseControlComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_eoc_LoseControlComponent_Properties,
    .propertyCount = sizeof(g_eoc_LoseControlComponent_Properties) / sizeof(g_eoc_LoseControlComponent_Properties[0]),
};

// eoc::summon::IsSummonComponent - 48 bytes (0x30)
// Source: IsSummonComponent from Windows BG3SE
static const ComponentPropertyDef g_eoc_IsSummonComponent_Properties[] = {
    { "field_10", 0x00, FIELD_TYPE_GUID, 0, false },
    { "field_20", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, false },
    { "field_28", 0x18, FIELD_TYPE_FIXEDSTRING, 0, false },
};
static const ComponentLayoutDef g_eoc_IsSummonComponent_Layout = {
    .componentName = "eoc::summon::IsSummonComponent",
    .shortName = "IsSummonComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_eoc_IsSummonComponent_Properties,
    .propertyCount = sizeof(g_eoc_IsSummonComponent_Properties) / sizeof(g_eoc_IsSummonComponent_Properties[0]),
};


// === esv:: namespace (110 layouts) ===

// esv::AIHintAreaTrigger - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_AIHintAreaTrigger_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT64, 0, true },
};
static const ComponentLayoutDef g_esv_AIHintAreaTrigger_Layout = {
    .componentName = "esv::AIHintAreaTrigger",
    .shortName = "AIHintAreaTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_AIHintAreaTrigger_Properties,
    .propertyCount = sizeof(g_esv_AIHintAreaTrigger_Properties) / sizeof(g_esv_AIHintAreaTrigger_Properties[0]),
};

// esv::ActivationGroupContainerComponent - 16 bytes (0x10)
// Source: ServerData.h
static const ComponentPropertyDef g_esv_ActivationGroupContainerComponent_Properties[] = {
    { "Groups", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },  // Array<ActivationGroupData>
};
static const ComponentLayoutDef g_esv_ActivationGroupContainerComponent_Layout = {
    .componentName = "esv::ActivationGroupContainerComponent",
    .shortName = "ActivationGroupContainer",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_ActivationGroupContainerComponent_Properties,
    .propertyCount = sizeof(g_esv_ActivationGroupContainerComponent_Properties) / sizeof(g_esv_ActivationGroupContainerComponent_Properties[0]),
};

// esv::ActiveCharacterLightComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_ActiveCharacterLightComponent_Properties[] = {
    { "LightUUID", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};
static const ComponentLayoutDef g_esv_ActiveCharacterLightComponent_Layout = {
    .componentName = "esv::ActiveCharacterLightComponent",
    .shortName = "ActiveCharacterLight",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_ActiveCharacterLightComponent_Properties,
    .propertyCount = sizeof(g_esv_ActiveCharacterLightComponent_Properties) / sizeof(g_esv_ActiveCharacterLightComponent_Properties[0]),
};

// esv::ActiveMusicVolumeComponent - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_ActiveMusicVolumeComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT64, 0, true },
};
static const ComponentLayoutDef g_esv_ActiveMusicVolumeComponent_Layout = {
    .componentName = "esv::ActiveMusicVolumeComponent",
    .shortName = "ActiveMusicVolume",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_ActiveMusicVolumeComponent_Properties,
    .propertyCount = sizeof(g_esv_ActiveMusicVolumeComponent_Properties) / sizeof(g_esv_ActiveMusicVolumeComponent_Properties[0]),
};

// esv::AiGridAreaTrigger - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_AiGridAreaTrigger_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT64, 0, true },
};
static const ComponentLayoutDef g_esv_AiGridAreaTrigger_Layout = {
    .componentName = "esv::AiGridAreaTrigger",
    .shortName = "AiGridAreaTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_AiGridAreaTrigger_Properties,
    .propertyCount = sizeof(g_esv_AiGridAreaTrigger_Properties) / sizeof(g_esv_AiGridAreaTrigger_Properties[0]),
};

// esv::ArmorClassComponent - 32 bytes (0x20)
// Source: COMPONENT_SIZES_ESV_CORE.md
static const ComponentPropertyDef g_esv_ArmorClassComponent_Properties[] = {
    { "AC", 0x00, FIELD_TYPE_INT32, 0, true },
    { "ArmorType", 0x04, FIELD_TYPE_INT32, 0, true },
    { "AbilityModifierCap", 0x08, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_ArmorClassComponent_Layout = {
    .componentName = "esv::ArmorClassComponent",
    .shortName = "ArmorClass",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_esv_ArmorClassComponent_Properties,
    .propertyCount = sizeof(g_esv_ArmorClassComponent_Properties) / sizeof(g_esv_ArmorClassComponent_Properties[0]),
};

// esv::AtmosphereTrigger - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_AtmosphereTrigger_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT64, 0, true },
};
static const ComponentLayoutDef g_esv_AtmosphereTrigger_Layout = {
    .componentName = "esv::AtmosphereTrigger",
    .shortName = "AtmosphereTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_AtmosphereTrigger_Properties,
    .propertyCount = sizeof(g_esv_AtmosphereTrigger_Properties) / sizeof(g_esv_AtmosphereTrigger_Properties[0]),
};

// esv::AvailableLevelComponent - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_AvailableLevelComponent_Properties[] = {
    { "Level", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_AvailableLevelComponent_Layout = {
    .componentName = "esv::AvailableLevelComponent",
    .shortName = "AvailableLevel",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_AvailableLevelComponent_Properties,
    .propertyCount = sizeof(g_esv_AvailableLevelComponent_Properties) / sizeof(g_esv_AvailableLevelComponent_Properties[0]),
};

// esv::BaseDataComponent - 24 bytes (0x18)
// Source: ServerData.h
static const ComponentPropertyDef g_esv_BaseDataComponent_Properties[] = {
    { "Resistances", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },  // std::array<std::array<ResistanceBoostFlags, 7>, 2>
    { "Weight", 0x0E, FIELD_TYPE_INT32, 0, true },
    { "Flags", 0x12, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_esv_BaseDataComponent_Layout = {
    .componentName = "esv::BaseDataComponent",
    .shortName = "BaseData",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_BaseDataComponent_Properties,
    .propertyCount = sizeof(g_esv_BaseDataComponent_Properties) / sizeof(g_esv_BaseDataComponent_Properties[0]),
};

// esv::BaseHpComponent - 16 bytes (0x10)
// Source: COMPONENT_SIZES_ESV_CORE.md
static const ComponentPropertyDef g_esv_BaseHpComponent_Properties[] = {
    { "Hp", 0x00, FIELD_TYPE_INT32, 0, true },
    { "MaxHp", 0x04, FIELD_TYPE_INT32, 0, true },
    { "VitalityBoost", 0x08, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_BaseHpComponent_Layout = {
    .componentName = "esv::BaseHpComponent",
    .shortName = "BaseHp",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_BaseHpComponent_Properties,
    .propertyCount = sizeof(g_esv_BaseHpComponent_Properties) / sizeof(g_esv_BaseHpComponent_Properties[0]),
};

// esv::BaseSizeComponent - 2 bytes (0x02)
// Source: ServerData.h
static const ComponentPropertyDef g_esv_BaseSizeComponent_Properties[] = {
    { "GameSize", 0x00, FIELD_TYPE_UINT8, 0, true },
    { "SoundSize", 0x01, FIELD_TYPE_UINT8, 0, true },
};
static const ComponentLayoutDef g_esv_BaseSizeComponent_Layout = {
    .componentName = "esv::BaseSizeComponent",
    .shortName = "BaseSize",
    .componentTypeIndex = 0,
    .componentSize = 0x02,
    .properties = g_esv_BaseSizeComponent_Properties,
    .propertyCount = sizeof(g_esv_BaseSizeComponent_Properties) / sizeof(g_esv_BaseSizeComponent_Properties[0]),
};

// esv::BaseStatsComponent - 4 bytes (0x04)
// Source: ServerData.h
static const ComponentPropertyDef g_esv_BaseStatsComponent_Properties[] = {
    { "Initiative", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_BaseStatsComponent_Layout = {
    .componentName = "esv::BaseStatsComponent",
    .shortName = "BaseStats",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_BaseStatsComponent_Properties,
    .propertyCount = sizeof(g_esv_BaseStatsComponent_Properties) / sizeof(g_esv_BaseStatsComponent_Properties[0]),
};

// esv::BaseWeaponComponent - 16 bytes (0x10)
// Source: ServerData.h
static const ComponentPropertyDef g_esv_BaseWeaponComponent_Properties[] = {
    { "DamageList", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },  // Array<BaseWeaponDamage>
};
static const ComponentLayoutDef g_esv_BaseWeaponComponent_Layout = {
    .componentName = "esv::BaseWeaponComponent",
    .shortName = "BaseWeapon",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_BaseWeaponComponent_Properties,
    .propertyCount = sizeof(g_esv_BaseWeaponComponent_Properties) / sizeof(g_esv_BaseWeaponComponent_Properties[0]),
};

// esv::BlockBronzeTimelinePlacementTrigger - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_BlockBronzeTimelinePlacementTrigger_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT64, 0, true },
};
static const ComponentLayoutDef g_esv_BlockBronzeTimelinePlacementTrigger_Layout = {
    .componentName = "esv::BlockBronzeTimelinePlacementTrigger",
    .shortName = "BlockBronzeTimelinePlacementTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_BlockBronzeTimelinePlacementTrigger_Properties,
    .propertyCount = sizeof(g_esv_BlockBronzeTimelinePlacementTrigger_Properties) / sizeof(g_esv_BlockBronzeTimelinePlacementTrigger_Properties[0]),
};

// esv::CampChestTrigger - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_CampChestTrigger_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT64, 0, true },
};
static const ComponentLayoutDef g_esv_CampChestTrigger_Layout = {
    .componentName = "esv::CampChestTrigger",
    .shortName = "CampChestTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_CampChestTrigger_Properties,
    .propertyCount = sizeof(g_esv_CampChestTrigger_Properties) / sizeof(g_esv_CampChestTrigger_Properties[0]),
};

// esv::CampRegionTrigger - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_CampRegionTrigger_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT64, 0, true },
};
static const ComponentLayoutDef g_esv_CampRegionTrigger_Layout = {
    .componentName = "esv::CampRegionTrigger",
    .shortName = "CampRegionTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_CampRegionTrigger_Properties,
    .propertyCount = sizeof(g_esv_CampRegionTrigger_Properties) / sizeof(g_esv_CampRegionTrigger_Properties[0]),
};

// esv::Character - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_Character_Properties[] = {
    { "CharacterPtr", 0x00, FIELD_TYPE_UINT64, 0, true },  // Ptr to 0x1a8 (424b) malloc
};
static const ComponentLayoutDef g_esv_Character_Layout = {
    .componentName = "esv::Character",
    .shortName = "Character",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_Character_Properties,
    .propertyCount = sizeof(g_esv_Character_Properties) / sizeof(g_esv_Character_Properties[0]),
};

// esv::CharacterComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_CharacterComponent_Properties[] = {
    { "Template", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Flags", 0x04, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_esv_CharacterComponent_Layout = {
    .componentName = "esv::CharacterComponent",
    .shortName = "CharacterComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_CharacterComponent_Properties,
    .propertyCount = sizeof(g_esv_CharacterComponent_Properties) / sizeof(g_esv_CharacterComponent_Properties[0]),
};

// esv::ChasmDataComponent - 48 bytes (0x30)
static const ComponentPropertyDef g_esv_ChasmDataComponent_Properties[] = {
    { "Data", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_ChasmDataComponent_Layout = {
    .componentName = "esv::ChasmDataComponent",
    .shortName = "ChasmData",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_esv_ChasmDataComponent_Properties,
    .propertyCount = sizeof(g_esv_ChasmDataComponent_Properties) / sizeof(g_esv_ChasmDataComponent_Properties[0]),
};

// esv::ChasmSeederTrigger - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_ChasmSeederTrigger_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT64, 0, true },
};
static const ComponentLayoutDef g_esv_ChasmSeederTrigger_Layout = {
    .componentName = "esv::ChasmSeederTrigger",
    .shortName = "ChasmSeederTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_ChasmSeederTrigger_Properties,
    .propertyCount = sizeof(g_esv_ChasmSeederTrigger_Properties) / sizeof(g_esv_ChasmSeederTrigger_Properties[0]),
};

// esv::CombatComponent - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_CombatComponent_Properties[] = {
    { "CombatId", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_CombatComponent_Layout = {
    .componentName = "esv::CombatComponent",
    .shortName = "Combat",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_CombatComponent_Properties,
    .propertyCount = sizeof(g_esv_CombatComponent_Properties) / sizeof(g_esv_CombatComponent_Properties[0]),
};

// esv::CombatGroupMappingComponent - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_CombatGroupMappingComponent_Properties[] = {
    { "CombatGroup", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_CombatGroupMappingComponent_Layout = {
    .componentName = "esv::CombatGroupMappingComponent",
    .shortName = "CombatGroupMapping",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_CombatGroupMappingComponent_Properties,
    .propertyCount = sizeof(g_esv_CombatGroupMappingComponent_Properties) / sizeof(g_esv_CombatGroupMappingComponent_Properties[0]),
};

// esv::CombatParticipantComponent - 48 bytes (0x30)
static const ComponentPropertyDef g_esv_CombatParticipantComponent_Properties[] = {
    { "CombatHandle", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "CombatGroupId", 0x08, FIELD_TYPE_GUID, 0, true },
};
static const ComponentLayoutDef g_esv_CombatParticipantComponent_Layout = {
    .componentName = "esv::CombatParticipantComponent",
    .shortName = "CombatParticipant",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_esv_CombatParticipantComponent_Properties,
    .propertyCount = sizeof(g_esv_CombatParticipantComponent_Properties) / sizeof(g_esv_CombatParticipantComponent_Properties[0]),
};

// esv::ConstellationChildComponent - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_ConstellationChildComponent_Properties[] = {
    { "Parent", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_ConstellationChildComponent_Layout = {
    .componentName = "esv::ConstellationChildComponent",
    .shortName = "ConstellationChild",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_ConstellationChildComponent_Properties,
    .propertyCount = sizeof(g_esv_ConstellationChildComponent_Properties) / sizeof(g_esv_ConstellationChildComponent_Properties[0]),
};

// esv::ConstellationHelperComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_ConstellationHelperComponent_Properties[] = {
    { "Data", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_ConstellationHelperComponent_Layout = {
    .componentName = "esv::ConstellationHelperComponent",
    .shortName = "ConstellationHelper",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_ConstellationHelperComponent_Properties,
    .propertyCount = sizeof(g_esv_ConstellationHelperComponent_Properties) / sizeof(g_esv_ConstellationHelperComponent_Properties[0]),
};

// esv::CrimeAreaTrigger - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_CrimeAreaTrigger_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT64, 0, true },
};
static const ComponentLayoutDef g_esv_CrimeAreaTrigger_Layout = {
    .componentName = "esv::CrimeAreaTrigger",
    .shortName = "CrimeAreaTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_CrimeAreaTrigger_Properties,
    .propertyCount = sizeof(g_esv_CrimeAreaTrigger_Properties) / sizeof(g_esv_CrimeAreaTrigger_Properties[0]),
};

// esv::CustomStatsComponent - 40 bytes (0x28)
static const ComponentPropertyDef g_esv_CustomStatsComponent_Properties[] = {
    { "Stats", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_CustomStatsComponent_Layout = {
    .componentName = "esv::CustomStatsComponent",
    .shortName = "CustomStats",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_esv_CustomStatsComponent_Properties,
    .propertyCount = sizeof(g_esv_CustomStatsComponent_Properties) / sizeof(g_esv_CustomStatsComponent_Properties[0]),
};

// esv::DisplayNameListComponent - 40 bytes (0x28)
static const ComponentPropertyDef g_esv_DisplayNameListComponent_Properties[] = {
    { "Names", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_DisplayNameListComponent_Layout = {
    .componentName = "esv::DisplayNameListComponent",
    .shortName = "DisplayNameList",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_esv_DisplayNameListComponent_Properties,
    .propertyCount = sizeof(g_esv_DisplayNameListComponent_Properties) / sizeof(g_esv_DisplayNameListComponent_Properties[0]),
};

// esv::Effect - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_Effect_Properties[] = {
    { "EffectPtr", 0x00, FIELD_TYPE_UINT64, 0, true },  // Ptr to 0x70 (112b) malloc
};
static const ComponentLayoutDef g_esv_Effect_Layout = {
    .componentName = "esv::Effect",
    .shortName = "Effect",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_Effect_Properties,
    .propertyCount = sizeof(g_esv_Effect_Properties) / sizeof(g_esv_Effect_Properties[0]),
};

// esv::EocLevelComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_EocLevelComponent_Properties[] = {
    { "Level", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_EocLevelComponent_Layout = {
    .componentName = "esv::EocLevelComponent",
    .shortName = "EocLevel",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_EocLevelComponent_Properties,
    .propertyCount = sizeof(g_esv_EocLevelComponent_Properties) / sizeof(g_esv_EocLevelComponent_Properties[0]),
};

// esv::ExperienceComponent - 8 bytes (0x08)
// Source: COMPONENT_SIZES_ESV_CORE.md (no Windows header struct found)
static const ComponentPropertyDef g_esv_ExperienceComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT32, 0, true },  // Estimated field
};
static const ComponentLayoutDef g_esv_ExperienceComponent_Layout = {
    .componentName = "esv::ExperienceComponent",
    .shortName = "Experience",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_ExperienceComponent_Properties,
    .propertyCount = sizeof(g_esv_ExperienceComponent_Properties) / sizeof(g_esv_ExperienceComponent_Properties[0]),
};

// esv::ExperienceGaveOutComponent - 4 bytes (0x04)
// Source: ServerData.h
static const ComponentPropertyDef g_esv_ExperienceGaveOutComponent_Properties[] = {
    { "Experience", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_ExperienceGaveOutComponent_Layout = {
    .componentName = "esv::exp::ExperienceGaveOutComponent",
    .shortName = "ExperienceGaveOut",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_ExperienceGaveOutComponent_Properties,
    .propertyCount = sizeof(g_esv_ExperienceGaveOutComponent_Properties) / sizeof(g_esv_ExperienceGaveOutComponent_Properties[0]),
};

// esv::ExplorationAwardStateComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_ExplorationAwardStateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_ExplorationAwardStateComponent_Layout = {
    .componentName = "esv::ExplorationAwardStateComponent",
    .shortName = "ExplorationAwardState",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_ExplorationAwardStateComponent_Properties,
    .propertyCount = sizeof(g_esv_ExplorationAwardStateComponent_Properties) / sizeof(g_esv_ExplorationAwardStateComponent_Properties[0]),
};

// esv::FollowersComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_FollowersComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_FollowersComponent_Layout = {
    .componentName = "esv::FollowersComponent",
    .shortName = "Followers",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_FollowersComponent_Properties,
    .propertyCount = sizeof(g_esv_FollowersComponent_Properties) / sizeof(g_esv_FollowersComponent_Properties[0]),
};

// esv::GameTimerComponent - 40 bytes (0x28)
// Source: ServerData.h
static const ComponentPropertyDef g_esv_GameTimerComponent_Properties[] = {
    { "field_18", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "field_20", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "field_28", 0x10, FIELD_TYPE_INT32, 0, true },
    { "field_2C", 0x14, FIELD_TYPE_INT32, 0, true },
    { "field_30", 0x18, FIELD_TYPE_INT32, 0, true },
    { "field_34", 0x1C, FIELD_TYPE_INT32, 0, true },
    { "field_38", 0x20, FIELD_TYPE_UINT8, 0, true },
};
static const ComponentLayoutDef g_esv_GameTimerComponent_Layout = {
    .componentName = "esv::GameTimerComponent",
    .shortName = "GameTimer",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_esv_GameTimerComponent_Properties,
    .propertyCount = sizeof(g_esv_GameTimerComponent_Properties) / sizeof(g_esv_GameTimerComponent_Properties[0]),
};

// esv::GravityActiveTimeoutComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_GravityActiveTimeoutComponent_Properties[] = {
    { "Timeout", 0x00, FIELD_TYPE_FLOAT, 0, true },
};
static const ComponentLayoutDef g_esv_GravityActiveTimeoutComponent_Layout = {
    .componentName = "esv::GravityActiveTimeoutComponent",
    .shortName = "GravityActiveTimeout",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_GravityActiveTimeoutComponent_Properties,
    .propertyCount = sizeof(g_esv_GravityActiveTimeoutComponent_Properties) / sizeof(g_esv_GravityActiveTimeoutComponent_Properties[0]),
};

// esv::GravityInstigatorComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_GravityInstigatorComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_GravityInstigatorComponent_Layout = {
    .componentName = "esv::GravityInstigatorComponent",
    .shortName = "GravityInstigator",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_GravityInstigatorComponent_Properties,
    .propertyCount = sizeof(g_esv_GravityInstigatorComponent_Properties) / sizeof(g_esv_GravityInstigatorComponent_Properties[0]),
};

// esv::HealthComponent - 16 bytes (0x10)
// Source: COMPONENT_SIZES_ESV_CORE.md
static const ComponentPropertyDef g_esv_HealthComponent_Properties[] = {
    { "Hp", 0x00, FIELD_TYPE_INT32, 0, true },
    { "MaxHp", 0x04, FIELD_TYPE_INT32, 0, true },
    { "TempHp", 0x08, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_HealthComponent_Layout = {
    .componentName = "esv::HealthComponent",
    .shortName = "Health",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_HealthComponent_Properties,
    .propertyCount = sizeof(g_esv_HealthComponent_Properties) / sizeof(g_esv_HealthComponent_Properties[0]),
};

// esv::IconListComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_IconListComponent_Properties[] = {
    { "Icons", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_IconListComponent_Layout = {
    .componentName = "esv::IconListComponent",
    .shortName = "IconList",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_IconListComponent_Properties,
    .propertyCount = sizeof(g_esv_IconListComponent_Properties) / sizeof(g_esv_IconListComponent_Properties[0]),
};

// esv::IdentifiedComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_IdentifiedComponent_Properties[] = {
    { "Identified", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_IdentifiedComponent_Layout = {
    .componentName = "esv::IdentifiedComponent",
    .shortName = "Identified",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_IdentifiedComponent_Properties,
    .propertyCount = sizeof(g_esv_IdentifiedComponent_Properties) / sizeof(g_esv_IdentifiedComponent_Properties[0]),
};

// esv::InterruptDataComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_InterruptDataComponent_Properties[] = {
    { "Data", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_InterruptDataComponent_Layout = {
    .componentName = "esv::InterruptDataComponent",
    .shortName = "InterruptData",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_InterruptDataComponent_Properties,
    .propertyCount = sizeof(g_esv_InterruptDataComponent_Properties) / sizeof(g_esv_InterruptDataComponent_Properties[0]),
};

// esv::InterruptPreferencesComponent - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_InterruptPreferencesComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_InterruptPreferencesComponent_Layout = {
    .componentName = "esv::InterruptPreferencesComponent",
    .shortName = "InterruptPreferences",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_InterruptPreferencesComponent_Properties,
    .propertyCount = sizeof(g_esv_InterruptPreferencesComponent_Properties) / sizeof(g_esv_InterruptPreferencesComponent_Properties[0]),
};

// esv::InterruptZoneParticipantComponent - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_InterruptZoneParticipantComponent_Properties[] = {
    { "ZoneId", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_InterruptZoneParticipantComponent_Layout = {
    .componentName = "esv::InterruptZoneParticipantComponent",
    .shortName = "InterruptZoneParticipant",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_InterruptZoneParticipantComponent_Properties,
    .propertyCount = sizeof(g_esv_InterruptZoneParticipantComponent_Properties) / sizeof(g_esv_InterruptZoneParticipantComponent_Properties[0]),
};

// esv::InventoryDataComponent - 32 bytes (0x20)
static const ComponentPropertyDef g_esv_InventoryDataComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_esv_InventoryDataComponent_Layout = {
    .componentName = "esv::InventoryDataComponent",
    .shortName = "InventoryData",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_esv_InventoryDataComponent_Properties,
    .propertyCount = sizeof(g_esv_InventoryDataComponent_Properties) / sizeof(g_esv_InventoryDataComponent_Properties[0]),
};

// esv::InventoryMemberComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_InventoryMemberComponent_Properties[] = {
    { "Inventory", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "EquipmentSlot", 0x08, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_InventoryMemberComponent_Layout = {
    .componentName = "esv::InventoryMemberComponent",
    .shortName = "InventoryMember",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_InventoryMemberComponent_Properties,
    .propertyCount = sizeof(g_esv_InventoryMemberComponent_Properties) / sizeof(g_esv_InventoryMemberComponent_Properties[0]),
};

// esv::InventoryOwnerComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_InventoryOwnerComponent_Properties[] = {
    { "Inventories", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_InventoryOwnerComponent_Layout = {
    .componentName = "esv::InventoryOwnerComponent",
    .shortName = "InventoryOwner",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_InventoryOwnerComponent_Properties,
    .propertyCount = sizeof(g_esv_InventoryOwnerComponent_Properties) / sizeof(g_esv_InventoryOwnerComponent_Properties[0]),
};

// esv::InventoryPropertyCanBePickpocketedComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_InventoryPropertyCanBePickpocketedComponent_Properties[] = {
    { "CanBePickpocketed", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_InventoryPropertyCanBePickpocketedComponent_Layout = {
    .componentName = "esv::InventoryPropertyCanBePickpocketedComponent",
    .shortName = "InventoryPropertyCanBePickpocketed",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_InventoryPropertyCanBePickpocketedComponent_Properties,
    .propertyCount = sizeof(g_esv_InventoryPropertyCanBePickpocketedComponent_Properties) / sizeof(g_esv_InventoryPropertyCanBePickpocketedComponent_Properties[0]),
};

// esv::InventoryPropertyIsDroppedOnDeathComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_InventoryPropertyIsDroppedOnDeathComponent_Properties[] = {
    { "IsDroppedOnDeath", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_InventoryPropertyIsDroppedOnDeathComponent_Layout = {
    .componentName = "esv::InventoryPropertyIsDroppedOnDeathComponent",
    .shortName = "InventoryPropertyIsDroppedOnDeath",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_InventoryPropertyIsDroppedOnDeathComponent_Properties,
    .propertyCount = sizeof(g_esv_InventoryPropertyIsDroppedOnDeathComponent_Properties) / sizeof(g_esv_InventoryPropertyIsDroppedOnDeathComponent_Properties[0]),
};

// esv::InventoryPropertyIsTradableComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_InventoryPropertyIsTradableComponent_Properties[] = {
    { "IsTradable", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_InventoryPropertyIsTradableComponent_Layout = {
    .componentName = "esv::InventoryPropertyIsTradableComponent",
    .shortName = "InventoryPropertyIsTradable",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_InventoryPropertyIsTradableComponent_Properties,
    .propertyCount = sizeof(g_esv_InventoryPropertyIsTradableComponent_Properties) / sizeof(g_esv_InventoryPropertyIsTradableComponent_Properties[0]),
};

// esv::IsGlobalComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_IsGlobalComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_IsGlobalComponent_Layout = {
    .componentName = "esv::IsGlobalComponent",
    .shortName = "IsGlobal",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_IsGlobalComponent_Properties,
    .propertyCount = sizeof(g_esv_IsGlobalComponent_Properties) / sizeof(g_esv_IsGlobalComponent_Properties[0]),
};

// esv::Item - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_Item_Properties[] = {
    { "ItemPtr", 0x00, FIELD_TYPE_UINT64, 0, true },  // Ptr to 0xb0 (176b) malloc
};
static const ComponentLayoutDef g_esv_Item_Layout = {
    .componentName = "esv::Item",
    .shortName = "Item",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_Item_Properties,
    .propertyCount = sizeof(g_esv_Item_Properties) / sizeof(g_esv_Item_Properties[0]),
};

// esv::ItemComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_ItemComponent_Properties[] = {
    { "Template", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Flags", 0x04, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_esv_ItemComponent_Layout = {
    .componentName = "esv::ItemComponent",
    .shortName = "ItemComponent",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_ItemComponent_Properties,
    .propertyCount = sizeof(g_esv_ItemComponent_Properties) / sizeof(g_esv_ItemComponent_Properties[0]),
};

// esv::LevelComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_LevelComponent_Properties[] = {
    { "Level", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_LevelComponent_Layout = {
    .componentName = "esv::LevelComponent",
    .shortName = "Level",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_LevelComponent_Properties,
    .propertyCount = sizeof(g_esv_LevelComponent_Properties) / sizeof(g_esv_LevelComponent_Properties[0]),
};

// esv::LockComponent - 40 bytes (0x28)
static const ComponentPropertyDef g_esv_LockComponent_Properties[] = {
    { "Key", 0x00, FIELD_TYPE_GUID, 0, true },
    { "LockDC", 0x10, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_LockComponent_Layout = {
    .componentName = "esv::LockComponent",
    .shortName = "Lock",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_esv_LockComponent_Properties,
    .propertyCount = sizeof(g_esv_LockComponent_Properties) / sizeof(g_esv_LockComponent_Properties[0]),
};

// esv::MusicVolumeTriggerStateComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_MusicVolumeTriggerStateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_MusicVolumeTriggerStateComponent_Layout = {
    .componentName = "esv::MusicVolumeTriggerStateComponent",
    .shortName = "MusicVolumeTriggerState",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_MusicVolumeTriggerStateComponent_Properties,
    .propertyCount = sizeof(g_esv_MusicVolumeTriggerStateComponent_Properties) / sizeof(g_esv_MusicVolumeTriggerStateComponent_Properties[0]),
};

// esv::OriginalTemplateComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_OriginalTemplateComponent_Properties[] = {
    { "TemplateId", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};
static const ComponentLayoutDef g_esv_OriginalTemplateComponent_Layout = {
    .componentName = "esv::OriginalTemplateComponent",
    .shortName = "OriginalTemplate",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_OriginalTemplateComponent_Properties,
    .propertyCount = sizeof(g_esv_OriginalTemplateComponent_Properties) / sizeof(g_esv_OriginalTemplateComponent_Properties[0]),
};

// esv::OsirisPingRequestSingletonComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_OsirisPingRequestSingletonComponent_Properties[] = {
    { "Requests", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_OsirisPingRequestSingletonComponent_Layout = {
    .componentName = "esv::OsirisPingRequestSingletonComponent",
    .shortName = "OsirisPingRequestSingleton",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_OsirisPingRequestSingletonComponent_Properties,
    .propertyCount = sizeof(g_esv_OsirisPingRequestSingletonComponent_Properties) / sizeof(g_esv_OsirisPingRequestSingletonComponent_Properties[0]),
};

// esv::PartyMemberComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_PartyMemberComponent_Properties[] = {
    { "Party", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};
static const ComponentLayoutDef g_esv_PartyMemberComponent_Layout = {
    .componentName = "esv::PartyMemberComponent",
    .shortName = "PartyMember",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_PartyMemberComponent_Properties,
    .propertyCount = sizeof(g_esv_PartyMemberComponent_Properties) / sizeof(g_esv_PartyMemberComponent_Properties[0]),
};

// esv::PingRequestSingletonComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_PingRequestSingletonComponent_Properties[] = {
    { "Requests", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_PingRequestSingletonComponent_Layout = {
    .componentName = "esv::PingRequestSingletonComponent",
    .shortName = "PingRequestSingleton",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_PingRequestSingletonComponent_Properties,
    .propertyCount = sizeof(g_esv_PingRequestSingletonComponent_Properties) / sizeof(g_esv_PingRequestSingletonComponent_Properties[0]),
};

// esv::PlayerComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_PlayerComponent_Properties[] = {
    { "UserId", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_PlayerComponent_Layout = {
    .componentName = "esv::PlayerComponent",
    .shortName = "Player",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_PlayerComponent_Properties,
    .propertyCount = sizeof(g_esv_PlayerComponent_Properties) / sizeof(g_esv_PlayerComponent_Properties[0]),
};

// esv::Projectile - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_Projectile_Properties[] = {
    { "ProjectilePtr", 0x00, FIELD_TYPE_UINT64, 0, true },  // Ptr to 0x5b8 (1464b) malloc
};
static const ComponentLayoutDef g_esv_Projectile_Layout = {
    .componentName = "esv::Projectile",
    .shortName = "Projectile",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_Projectile_Properties,
    .propertyCount = sizeof(g_esv_Projectile_Properties) / sizeof(g_esv_Projectile_Properties[0]),
};

// esv::RecruitedByComponent - 8 bytes (0x08)
// Source: ServerData.h
static const ComponentPropertyDef g_esv_RecruitedByComponent_Properties[] = {
    { "RecruitedBy", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_RecruitedByComponent_Layout = {
    .componentName = "esv::recruit::RecruitedByComponent",
    .shortName = "RecruitedBy",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_RecruitedByComponent_Properties,
    .propertyCount = sizeof(g_esv_RecruitedByComponent_Properties) / sizeof(g_esv_RecruitedByComponent_Properties[0]),
};

// esv::ReplicationDependencyComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_ReplicationDependencyComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_ReplicationDependencyComponent_Layout = {
    .componentName = "esv::ReplicationDependencyComponent",
    .shortName = "ReplicationDependency",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_ReplicationDependencyComponent_Properties,
    .propertyCount = sizeof(g_esv_ReplicationDependencyComponent_Properties) / sizeof(g_esv_ReplicationDependencyComponent_Properties[0]),
};

// esv::SafePositionComponent - 16 bytes (0x10)
// Source: ServerData.h
static const ComponentPropertyDef g_esv_SafePositionComponent_Properties[] = {
    { "Position", 0x00, FIELD_TYPE_VEC3, 0, true },  // glm::vec3 (12 bytes)
    { "field_24", 0x0C, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_SafePositionComponent_Layout = {
    .componentName = "esv::SafePositionComponent",
    .shortName = "SafePosition",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_SafePositionComponent_Properties,
    .propertyCount = sizeof(g_esv_SafePositionComponent_Properties) / sizeof(g_esv_SafePositionComponent_Properties[0]),
};

// esv::SafePositionUpdatedEventOneFrameComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_SafePositionUpdatedEventOneFrameComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_SafePositionUpdatedEventOneFrameComponent_Layout = {
    .componentName = "esv::SafePositionUpdatedEventOneFrameComponent",
    .shortName = "SafePositionUpdatedEventOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_SafePositionUpdatedEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_esv_SafePositionUpdatedEventOneFrameComponent_Properties) / sizeof(g_esv_SafePositionUpdatedEventOneFrameComponent_Properties[0]),
};

// esv::SaveCompletedOneFrameComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_SaveCompletedOneFrameComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_SaveCompletedOneFrameComponent_Layout = {
    .componentName = "esv::SaveCompletedOneFrameComponent",
    .shortName = "SaveCompletedOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_SaveCompletedOneFrameComponent_Properties,
    .propertyCount = sizeof(g_esv_SaveCompletedOneFrameComponent_Properties) / sizeof(g_esv_SaveCompletedOneFrameComponent_Properties[0]),
};

// esv::SaveWorldPrepareEventComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_SaveWorldPrepareEventComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_SaveWorldPrepareEventComponent_Layout = {
    .componentName = "esv::SaveWorldPrepareEventComponent",
    .shortName = "SaveWorldPrepareEvent",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_SaveWorldPrepareEventComponent_Properties,
    .propertyCount = sizeof(g_esv_SaveWorldPrepareEventComponent_Properties) / sizeof(g_esv_SaveWorldPrepareEventComponent_Properties[0]),
};

// esv::ServerDisplayNameListComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_ServerDisplayNameListComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};
static const ComponentLayoutDef g_esv_ServerDisplayNameListComponent_Layout = {
    .componentName = "esv::ServerDisplayNameListComponent",
    .shortName = "ServerDisplayNameList",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_ServerDisplayNameListComponent_Properties,
    .propertyCount = sizeof(g_esv_ServerDisplayNameListComponent_Properties) / sizeof(g_esv_ServerDisplayNameListComponent_Properties[0]),
};

// esv::ServerReplicationDependencyOwnerComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_ServerReplicationDependencyOwnerComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_ServerReplicationDependencyOwnerComponent_Layout = {
    .componentName = "esv::ServerReplicationDependencyOwnerComponent",
    .shortName = "ServerReplicationDependencyOwner",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_ServerReplicationDependencyOwnerComponent_Properties,
    .propertyCount = sizeof(g_esv_ServerReplicationDependencyOwnerComponent_Properties) / sizeof(g_esv_ServerReplicationDependencyOwnerComponent_Properties[0]),
};

// esv::SetGravityActiveRequestOneFrameComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_SetGravityActiveRequestOneFrameComponent_Properties[] = {
    { "Active", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_SetGravityActiveRequestOneFrameComponent_Layout = {
    .componentName = "esv::SetGravityActiveRequestOneFrameComponent",
    .shortName = "SetGravityActiveRequestOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_SetGravityActiveRequestOneFrameComponent_Properties,
    .propertyCount = sizeof(g_esv_SetGravityActiveRequestOneFrameComponent_Properties) / sizeof(g_esv_SetGravityActiveRequestOneFrameComponent_Properties[0]),
};

// esv::StartTrigger - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_StartTrigger_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT64, 0, true },
};
static const ComponentLayoutDef g_esv_StartTrigger_Layout = {
    .componentName = "esv::StartTrigger",
    .shortName = "StartTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_StartTrigger_Properties,
    .propertyCount = sizeof(g_esv_StartTrigger_Properties) / sizeof(g_esv_StartTrigger_Properties[0]),
};

// esv::StatesComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_StatesComponent_Properties[] = {
    { "States", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_StatesComponent_Layout = {
    .componentName = "esv::StatesComponent",
    .shortName = "States",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_StatesComponent_Properties,
    .propertyCount = sizeof(g_esv_StatesComponent_Properties) / sizeof(g_esv_StatesComponent_Properties[0]),
};

// esv::StatusContainerComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_StatusContainerComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_StatusContainerComponent_Layout = {
    .componentName = "esv::StatusContainerComponent",
    .shortName = "StatusContainer",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_StatusContainerComponent_Properties,
    .propertyCount = sizeof(g_esv_StatusContainerComponent_Properties) / sizeof(g_esv_StatusContainerComponent_Properties[0]),
};

// esv::StealthComponent - 40 bytes (0x28)
static const ComponentPropertyDef g_esv_StealthComponent_Properties[] = {
    { "Seeking", 0x00, FIELD_TYPE_BOOL, 0, true },
    { "SeekHiddenFlag", 0x01, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_StealthComponent_Layout = {
    .componentName = "esv::StealthComponent",
    .shortName = "Stealth",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_esv_StealthComponent_Properties,
    .propertyCount = sizeof(g_esv_StealthComponent_Properties) / sizeof(g_esv_StealthComponent_Properties[0]),
};

// esv::SummonContainerComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_SummonContainerComponent_Properties[] = {
    { "Summons", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_SummonContainerComponent_Layout = {
    .componentName = "esv::SummonContainerComponent",
    .shortName = "SummonContainer",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_SummonContainerComponent_Properties,
    .propertyCount = sizeof(g_esv_SummonContainerComponent_Properties) / sizeof(g_esv_SummonContainerComponent_Properties[0]),
};

// esv::SurfacePathInfluencesComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_SurfacePathInfluencesComponent_Properties[] = {
    { "PathInfluences", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_SurfacePathInfluencesComponent_Layout = {
    .componentName = "esv::SurfacePathInfluencesComponent",
    .shortName = "SurfacePathInfluences",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_SurfacePathInfluencesComponent_Properties,
    .propertyCount = sizeof(g_esv_SurfacePathInfluencesComponent_Properties) / sizeof(g_esv_SurfacePathInfluencesComponent_Properties[0]),
};

// esv::TurnStartedEventOneFrameComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_TurnStartedEventOneFrameComponent_Properties[] = {
    { "CombatId", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_TurnStartedEventOneFrameComponent_Layout = {
    .componentName = "esv::TurnStartedEventOneFrameComponent",
    .shortName = "TurnStartedEventOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_TurnStartedEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_esv_TurnStartedEventOneFrameComponent_Properties) / sizeof(g_esv_TurnStartedEventOneFrameComponent_Properties[0]),
};

// esv::UseComponent - 40 bytes (0x28)
static const ComponentPropertyDef g_esv_UseComponent_Properties[] = {
    { "Charges", 0x00, FIELD_TYPE_INT32, 0, true },
    { "MaxCharges", 0x04, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_UseComponent_Layout = {
    .componentName = "esv::UseComponent",
    .shortName = "Use",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_esv_UseComponent_Properties,
    .propertyCount = sizeof(g_esv_UseComponent_Properties) / sizeof(g_esv_UseComponent_Properties[0]),
};

// esv::UseSocketComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_UseSocketComponent_Properties[] = {
    { "Socket", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_UseSocketComponent_Layout = {
    .componentName = "esv::UseSocketComponent",
    .shortName = "UseSocket",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_UseSocketComponent_Properties,
    .propertyCount = sizeof(g_esv_UseSocketComponent_Properties) / sizeof(g_esv_UseSocketComponent_Properties[0]),
};

// esv::UserReservedComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_UserReservedComponent_Properties[] = {
    { "UserID", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_UserReservedComponent_Layout = {
    .componentName = "esv::UserReservedComponent",
    .shortName = "UserReserved",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_UserReservedComponent_Properties,
    .propertyCount = sizeof(g_esv_UserReservedComponent_Properties) / sizeof(g_esv_UserReservedComponent_Properties[0]),
};

// esv::ai::AiComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_ai_AiComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_ai_AiComponent_Layout = {
    .componentName = "esv::ai::AiComponent",
    .shortName = "Ai",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_ai_AiComponent_Properties,
    .propertyCount = sizeof(g_esv_ai_AiComponent_Properties) / sizeof(g_esv_ai_AiComponent_Properties[0]),
};

// esv::combat::CombatStateComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_combat_CombatStateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_INT32, 0, true },
    { "Initiative", 0x04, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_combat_CombatStateComponent_Layout = {
    .componentName = "esv::combat::CombatStateComponent",
    .shortName = "CombatState",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_combat_CombatStateComponent_Properties,
    .propertyCount = sizeof(g_esv_combat_CombatStateComponent_Properties) / sizeof(g_esv_combat_CombatStateComponent_Properties[0]),
};

// esv::combat::CombatSwitchedComponent - 48 bytes (0x30)
static const ComponentPropertyDef g_esv_combat_CombatSwitchedComponent_Properties[] = {
    { "FromCombat", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "ToCombat", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_combat_CombatSwitchedComponent_Layout = {
    .componentName = "esv::combat::CombatSwitchedComponent",
    .shortName = "CombatSwitched",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_esv_combat_CombatSwitchedComponent_Properties,
    .propertyCount = sizeof(g_esv_combat_CombatSwitchedComponent_Properties) / sizeof(g_esv_combat_CombatSwitchedComponent_Properties[0]),
};

// esv::combat::EnterRequestComponent - 48 bytes (0x30)
static const ComponentPropertyDef g_esv_combat_EnterRequestComponent_Properties[] = {
    { "CombatId", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Position", 0x08, FIELD_TYPE_VEC3, 0, true },
};
static const ComponentLayoutDef g_esv_combat_EnterRequestComponent_Layout = {
    .componentName = "esv::combat::EnterRequestComponent",
    .shortName = "EnterRequest",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_esv_combat_EnterRequestComponent_Properties,
    .propertyCount = sizeof(g_esv_combat_EnterRequestComponent_Properties) / sizeof(g_esv_combat_EnterRequestComponent_Properties[0]),
};

// esv::combat::IsInCombatComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_combat_IsInCombatComponent_Properties[] = {
    { "CombatId", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_combat_IsInCombatComponent_Layout = {
    .componentName = "esv::combat::IsInCombatComponent",
    .shortName = "IsInCombat",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_combat_IsInCombatComponent_Properties,
    .propertyCount = sizeof(g_esv_combat_IsInCombatComponent_Properties) / sizeof(g_esv_combat_IsInCombatComponent_Properties[0]),
};

// esv::combat::JoiningComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_combat_JoiningComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_combat_JoiningComponent_Layout = {
    .componentName = "esv::combat::JoiningComponent",
    .shortName = "Joining",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_combat_JoiningComponent_Properties,
    .propertyCount = sizeof(g_esv_combat_JoiningComponent_Properties) / sizeof(g_esv_combat_JoiningComponent_Properties[0]),
};

// esv::combat::LateJoinPenaltyComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_combat_LateJoinPenaltyComponent_Properties[] = {
    { "Penalty", 0x00, FIELD_TYPE_FLOAT, 0, true },
};
static const ComponentLayoutDef g_esv_combat_LateJoinPenaltyComponent_Layout = {
    .componentName = "esv::combat::LateJoinPenaltyComponent",
    .shortName = "LateJoinPenalty",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_combat_LateJoinPenaltyComponent_Properties,
    .propertyCount = sizeof(g_esv_combat_LateJoinPenaltyComponent_Properties) / sizeof(g_esv_combat_LateJoinPenaltyComponent_Properties[0]),
};

// esv::combat::LeftEventOneFrameComponent - 24 bytes (0x18)
static const ComponentPropertyDef g_esv_combat_LeftEventOneFrameComponent_Properties[] = {
    { "CombatId", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_combat_LeftEventOneFrameComponent_Layout = {
    .componentName = "esv::combat::LeftEventOneFrameComponent",
    .shortName = "LeftEventOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_esv_combat_LeftEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_esv_combat_LeftEventOneFrameComponent_Properties) / sizeof(g_esv_combat_LeftEventOneFrameComponent_Properties[0]),
};

// esv::inventory::ContainerDataComponent - 8 bytes (0x08)
// Source: Inventory.h
static const ComponentPropertyDef g_esv_inventory_ContainerDataComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT16, 0, true },
    { "field_4", 0x04, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_ContainerDataComponent_Layout = {
    .componentName = "esv::inventory::ContainerDataComponent",
    .shortName = "ContainerData",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_inventory_ContainerDataComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_ContainerDataComponent_Properties) / sizeof(g_esv_inventory_ContainerDataComponent_Properties[0]),
};

// esv::inventory::GroupCheckComponent - 4 bytes (0x04)
// Source: Inventory.h
static const ComponentPropertyDef g_esv_inventory_GroupCheckComponent_Properties[] = {
    { "Conditions", 0x00, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_GroupCheckComponent_Layout = {
    .componentName = "esv::inventory::GroupCheckComponent",
    .shortName = "GroupCheck",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_inventory_GroupCheckComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_GroupCheckComponent_Properties) / sizeof(g_esv_inventory_GroupCheckComponent_Properties[0]),
};

// esv::inventory::IsReplicatedComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_inventory_IsReplicatedComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_IsReplicatedComponent_Layout = {
    .componentName = "esv::inventory::IsReplicatedComponent",
    .shortName = "IsReplicated",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_inventory_IsReplicatedComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_IsReplicatedComponent_Properties) / sizeof(g_esv_inventory_IsReplicatedComponent_Properties[0]),
};

// esv::inventory::MemberIsReplicatedWithComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_inventory_MemberIsReplicatedWithComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_MemberIsReplicatedWithComponent_Layout = {
    .componentName = "esv::inventory::MemberIsReplicatedWithComponent",
    .shortName = "MemberIsReplicatedWith",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_inventory_MemberIsReplicatedWithComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_MemberIsReplicatedWithComponent_Properties) / sizeof(g_esv_inventory_MemberIsReplicatedWithComponent_Properties[0]),
};

// esv::inventory::MemberRemovedEventOneFrameComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_inventory_MemberRemovedEventOneFrameComponent_Properties[] = {
    { "Member", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_MemberRemovedEventOneFrameComponent_Layout = {
    .componentName = "esv::inventory::MemberRemovedEventOneFrameComponent",
    .shortName = "MemberRemovedEventOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_inventory_MemberRemovedEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_MemberRemovedEventOneFrameComponent_Properties) / sizeof(g_esv_inventory_MemberRemovedEventOneFrameComponent_Properties[0]),
};

// esv::inventory::ReturnToOwnerComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_inventory_ReturnToOwnerComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_ReturnToOwnerComponent_Layout = {
    .componentName = "esv::inventory::ReturnToOwnerComponent",
    .shortName = "ReturnToOwner",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_inventory_ReturnToOwnerComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_ReturnToOwnerComponent_Properties) / sizeof(g_esv_inventory_ReturnToOwnerComponent_Properties[0]),
};

// esv::inventory::ShapeshiftAddedEquipmentComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_inventory_ShapeshiftAddedEquipmentComponent_Properties[] = {
    { "Equipment", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_ShapeshiftAddedEquipmentComponent_Layout = {
    .componentName = "esv::inventory::ShapeshiftAddedEquipmentComponent",
    .shortName = "ShapeshiftAddedEquipment",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_inventory_ShapeshiftAddedEquipmentComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_ShapeshiftAddedEquipmentComponent_Properties) / sizeof(g_esv_inventory_ShapeshiftAddedEquipmentComponent_Properties[0]),
};

// esv::inventory::ShapeshiftEquipmentHistoryComponent - 16 bytes (0x10)
// Source: Inventory.h
static const ComponentPropertyDef g_esv_inventory_ShapeshiftEquipmentHistoryComponent_Properties[] = {
    { "History", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_ShapeshiftEquipmentHistoryComponent_Layout = {
    .componentName = "esv::inventory::ShapeshiftEquipmentHistoryComponent",
    .shortName = "ShapeshiftEquipmentHistory",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_inventory_ShapeshiftEquipmentHistoryComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_ShapeshiftEquipmentHistoryComponent_Properties) / sizeof(g_esv_inventory_ShapeshiftEquipmentHistoryComponent_Properties[0]),
};

// esv::inventory::ShapeshiftUnequippedEquipmentComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_inventory_ShapeshiftUnequippedEquipmentComponent_Properties[] = {
    { "Equipment", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_ShapeshiftUnequippedEquipmentComponent_Layout = {
    .componentName = "esv::inventory::ShapeshiftUnequippedEquipmentComponent",
    .shortName = "ShapeshiftUnequippedEquipment",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_inventory_ShapeshiftUnequippedEquipmentComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_ShapeshiftUnequippedEquipmentComponent_Properties) / sizeof(g_esv_inventory_ShapeshiftUnequippedEquipmentComponent_Properties[0]),
};

// esv::inventory::StackBlockedDuringTradeComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_inventory_StackBlockedDuringTradeComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_inventory_StackBlockedDuringTradeComponent_Layout = {
    .componentName = "esv::inventory::StackBlockedDuringTradeComponent",
    .shortName = "StackBlockedDuringTrade",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_inventory_StackBlockedDuringTradeComponent_Properties,
    .propertyCount = sizeof(g_esv_inventory_StackBlockedDuringTradeComponent_Properties) / sizeof(g_esv_inventory_StackBlockedDuringTradeComponent_Properties[0]),
};

// esv::item::DestroyingEventOneFrameComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_item_DestroyingEventOneFrameComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_item_DestroyingEventOneFrameComponent_Layout = {
    .componentName = "esv::item::DestroyingEventOneFrameComponent",
    .shortName = "DestroyingEventOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_item_DestroyingEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_esv_item_DestroyingEventOneFrameComponent_Properties) / sizeof(g_esv_item_DestroyingEventOneFrameComponent_Properties[0]),
};

// esv::item::DestroyingWaitingForDeactivationComponent - 2 bytes (0x02)
static const ComponentPropertyDef g_esv_item_DestroyingWaitingForDeactivationComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_UINT16, 0, true },
};
static const ComponentLayoutDef g_esv_item_DestroyingWaitingForDeactivationComponent_Layout = {
    .componentName = "esv::item::DestroyingWaitingForDeactivationComponent",
    .shortName = "DestroyingWaitingForDeactivation",
    .componentTypeIndex = 0,
    .componentSize = 0x02,
    .properties = g_esv_item_DestroyingWaitingForDeactivationComponent_Properties,
    .propertyCount = sizeof(g_esv_item_DestroyingWaitingForDeactivationComponent_Properties) / sizeof(g_esv_item_DestroyingWaitingForDeactivationComponent_Properties[0]),
};

// esv::item::DestroyingWaitingForEffectComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_item_DestroyingWaitingForEffectComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_esv_item_DestroyingWaitingForEffectComponent_Layout = {
    .componentName = "esv::item::DestroyingWaitingForEffectComponent",
    .shortName = "DestroyingWaitingForEffect",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_item_DestroyingWaitingForEffectComponent_Properties,
    .propertyCount = sizeof(g_esv_item_DestroyingWaitingForEffectComponent_Properties) / sizeof(g_esv_item_DestroyingWaitingForEffectComponent_Properties[0]),
};

// esv::item::DynamicLayerOwnerComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_item_DynamicLayerOwnerComponent_Properties[] = {
    { "Owner", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};
static const ComponentLayoutDef g_esv_item_DynamicLayerOwnerComponent_Layout = {
    .componentName = "esv::item::DynamicLayerOwnerComponent",
    .shortName = "DynamicLayerOwner",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_item_DynamicLayerOwnerComponent_Properties,
    .propertyCount = sizeof(g_esv_item_DynamicLayerOwnerComponent_Properties) / sizeof(g_esv_item_DynamicLayerOwnerComponent_Properties[0]),
};

// esv::item::EntityMovingComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_item_EntityMovingComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_item_EntityMovingComponent_Layout = {
    .componentName = "esv::item::EntityMovingComponent",
    .shortName = "EntityMoving",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_item_EntityMovingComponent_Properties,
    .propertyCount = sizeof(g_esv_item_EntityMovingComponent_Properties) / sizeof(g_esv_item_EntityMovingComponent_Properties[0]),
};

// esv::item::MarkEntityForDestructionComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_item_MarkEntityForDestructionComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_item_MarkEntityForDestructionComponent_Layout = {
    .componentName = "esv::item::MarkEntityForDestructionComponent",
    .shortName = "MarkEntityForDestruction",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_item_MarkEntityForDestructionComponent_Properties,
    .propertyCount = sizeof(g_esv_item_MarkEntityForDestructionComponent_Properties) / sizeof(g_esv_item_MarkEntityForDestructionComponent_Properties[0]),
};

// esv::item::TransformedOnDestroyEventOneFrameComponent - 1 byte (0x01)
static const ComponentPropertyDef g_esv_item_TransformedOnDestroyEventOneFrameComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_esv_item_TransformedOnDestroyEventOneFrameComponent_Layout = {
    .componentName = "esv::item::TransformedOnDestroyEventOneFrameComponent",
    .shortName = "TransformedOnDestroyEventOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_esv_item_TransformedOnDestroyEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_esv_item_TransformedOnDestroyEventOneFrameComponent_Properties) / sizeof(g_esv_item_TransformedOnDestroyEventOneFrameComponent_Properties[0]),
};

// esv::status::LifeTimeComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_status_LifeTimeComponent_Properties[] = {
    { "Duration", 0x00, FIELD_TYPE_FLOAT, 0, true },
    { "TurnTimer", 0x04, FIELD_TYPE_FLOAT, 0, true },
};
static const ComponentLayoutDef g_esv_status_LifeTimeComponent_Layout = {
    .componentName = "esv::status::LifeTimeComponent",
    .shortName = "LifeTime",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_status_LifeTimeComponent_Properties,
    .propertyCount = sizeof(g_esv_status_LifeTimeComponent_Properties) / sizeof(g_esv_status_LifeTimeComponent_Properties[0]),
};

// esv::status::OwnershipComponent - 8 bytes (0x08)
static const ComponentPropertyDef g_esv_status_OwnershipComponent_Properties[] = {
    { "Owner", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_esv_status_OwnershipComponent_Layout = {
    .componentName = "esv::status::OwnershipComponent",
    .shortName = "Ownership",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_esv_status_OwnershipComponent_Properties,
    .propertyCount = sizeof(g_esv_status_OwnershipComponent_Properties) / sizeof(g_esv_status_OwnershipComponent_Properties[0]),
};

// esv::status::PerformingComponent - 4 bytes (0x04)
static const ComponentPropertyDef g_esv_status_PerformingComponent_Properties[] = {
    { "StatusId", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};
static const ComponentLayoutDef g_esv_status_PerformingComponent_Layout = {
    .componentName = "esv::status::PerformingComponent",
    .shortName = "Performing",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_esv_status_PerformingComponent_Properties,
    .propertyCount = sizeof(g_esv_status_PerformingComponent_Properties) / sizeof(g_esv_status_PerformingComponent_Properties[0]),
};

// esv::status::StatusComponent - 40 bytes (0x28)
static const ComponentPropertyDef g_esv_status_StatusComponent_Properties[] = {
    { "StatusId", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Flags", 0x04, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_esv_status_StatusComponent_Layout = {
    .componentName = "esv::status::StatusComponent",
    .shortName = "Status",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_esv_status_StatusComponent_Properties,
    .propertyCount = sizeof(g_esv_status_StatusComponent_Properties) / sizeof(g_esv_status_StatusComponent_Properties[0]),
};

// esv::status::StatusIDComponent - 16 bytes (0x10)
static const ComponentPropertyDef g_esv_status_StatusIDComponent_Properties[] = {
    { "ID", 0x00, FIELD_TYPE_GUID, 0, true },
};
static const ComponentLayoutDef g_esv_status_StatusIDComponent_Layout = {
    .componentName = "esv::status::StatusIDComponent",
    .shortName = "StatusID",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_esv_status_StatusIDComponent_Properties,
    .propertyCount = sizeof(g_esv_status_StatusIDComponent_Properties) / sizeof(g_esv_status_StatusIDComponent_Properties[0]),
};


// === ecl:: namespace (71 layouts) ===

// ecl::ActiveTurnComponent - 12 bytes (0xc)
// Source: Combat.h (inferred tag component)
static const ComponentPropertyDef g_ecl_ActiveTurnComponent_Properties[] = {
    { "Active", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ecl_ActiveTurnComponent_Layout = {
    .componentName = "ecl::ActiveTurnComponent",
    .shortName = "ActiveTurn",
    .componentTypeIndex = 0,
    .componentSize = 0xc,
    .properties = g_ecl_ActiveTurnComponent_Properties,
    .propertyCount = sizeof(g_ecl_ActiveTurnComponent_Properties) / sizeof(g_ecl_ActiveTurnComponent_Properties[0]),
};

// ecl::CharacterIconResultComponent - 88 bytes (0x58)
// Source: Visual.h (verified from Visual.h:870-875)
static const ComponentPropertyDef g_ecl_CharacterIconResultComponent_Properties[] = {
    { "IconData", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Width", 0x08, FIELD_TYPE_INT32, 0, true },
    { "Height", 0x0C, FIELD_TYPE_INT32, 0, true },
    { "Format", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Flags", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved10", 0x3C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved11", 0x40, FIELD_TYPE_UINT32, 0, true },
    { "Reserved12", 0x44, FIELD_TYPE_UINT32, 0, true },
    { "Reserved13", 0x48, FIELD_TYPE_UINT32, 0, true },
    { "Reserved14", 0x4C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved15", 0x50, FIELD_TYPE_UINT32, 0, true },
    { "Reserved16", 0x54, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_CharacterIconResultComponent_Layout = {
    .componentName = "ecl::CharacterIconResultComponent",
    .shortName = "CharacterIconResult",
    .componentTypeIndex = 0,
    .componentSize = 0x58,
    .properties = g_ecl_CharacterIconResultComponent_Properties,
    .propertyCount = sizeof(g_ecl_CharacterIconResultComponent_Properties) / sizeof(g_ecl_CharacterIconResultComponent_Properties[0]),
};

// ecl::CharacterLightComponent - 24 bytes (0x18)
// Source: Visual.h
static const ComponentPropertyDef g_ecl_CharacterLightComponent_Properties[] = {
    { "LightEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "LightType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "Intensity", 0x0C, FIELD_TYPE_FLOAT, 0, true },
    { "Radius", 0x10, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x14, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_CharacterLightComponent_Layout = {
    .componentName = "ecl::CharacterLightComponent",
    .shortName = "CharacterLight",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_ecl_CharacterLightComponent_Properties,
    .propertyCount = sizeof(g_ecl_CharacterLightComponent_Properties) / sizeof(g_ecl_CharacterLightComponent_Properties[0]),
};

// ecl::ClientTimelineActorControlComponent - 40 bytes (0x28)
// Source: Timeline.h (verified from Camera.h:42)
static const ComponentPropertyDef g_ecl_ClientTimelineActorControlComponent_Properties[] = {
    { "ActorEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "ControlType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "Priority", 0x0C, FIELD_TYPE_INT32, 0, true },
    { "Flags", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x24, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_ClientTimelineActorControlComponent_Layout = {
    .componentName = "ecl::ClientTimelineActorControlComponent",
    .shortName = "ClientTimelineActorControl",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_ecl_ClientTimelineActorControlComponent_Properties,
    .propertyCount = sizeof(g_ecl_ClientTimelineActorControlComponent_Properties) / sizeof(g_ecl_ClientTimelineActorControlComponent_Properties[0]),
};

// ecl::DeathEffectComponent - 8 bytes (0x8)
// Source: Death.h (effect pointer)
static const ComponentPropertyDef g_ecl_DeathEffectComponent_Properties[] = {
    { "Effect", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_DeathEffectComponent_Layout = {
    .componentName = "ecl::DeathEffectComponent",
    .shortName = "DeathEffect",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_DeathEffectComponent_Properties,
    .propertyCount = sizeof(g_ecl_DeathEffectComponent_Properties) / sizeof(g_ecl_DeathEffectComponent_Properties[0]),
};

// ecl::DetachedComponent - 4 bytes (0x4)
// Source: Components.h (simple state flag)
static const ComponentPropertyDef g_ecl_DetachedComponent_Properties[] = {
    { "Detached", 0x00, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_DetachedComponent_Layout = {
    .componentName = "ecl::DetachedComponent",
    .shortName = "Detached",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_ecl_DetachedComponent_Properties,
    .propertyCount = sizeof(g_ecl_DetachedComponent_Properties) / sizeof(g_ecl_DetachedComponent_Properties[0]),
};

// ecl::DifficultyCheckComponent - 72 bytes (0x48)
// Source: Combat.h
static const ComponentPropertyDef g_ecl_DifficultyCheckComponent_Properties[] = {
    { "CheckEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "DifficultyClass", 0x08, FIELD_TYPE_INT32, 0, true },
    { "RollType", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "Ability", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Skill", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "SourceEntity", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "TargetEntity", 0x20, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Flags", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x3C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x40, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x44, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_DifficultyCheckComponent_Layout = {
    .componentName = "ecl::DifficultyCheckComponent",
    .shortName = "DifficultyCheck",
    .componentTypeIndex = 0,
    .componentSize = 0x48,
    .properties = g_ecl_DifficultyCheckComponent_Properties,
    .propertyCount = sizeof(g_ecl_DifficultyCheckComponent_Properties) / sizeof(g_ecl_DifficultyCheckComponent_Properties[0]),
};

// ecl::DisabledEquipmentComponent - 1 byte (0x1)
// Source: Equipment.h (tag component)
static const ComponentPropertyDef g_ecl_DisabledEquipmentComponent_Properties[] = {
    { "Disabled", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ecl_DisabledEquipmentComponent_Layout = {
    .componentName = "ecl::DisabledEquipmentComponent",
    .shortName = "DisabledEquipment",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_ecl_DisabledEquipmentComponent_Properties,
    .propertyCount = sizeof(g_ecl_DisabledEquipmentComponent_Properties) / sizeof(g_ecl_DisabledEquipmentComponent_Properties[0]),
};

// ecl::DisarmableComponent - 24 bytes (0x18)
// Source: Combat.h
static const ComponentPropertyDef g_ecl_DisarmableComponent_Properties[] = {
    { "DisarmerEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "DisarmTime", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "DisarmType", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Reserved", 0x14, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_DisarmableComponent_Layout = {
    .componentName = "ecl::DisarmableComponent",
    .shortName = "Disarmable",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_ecl_DisarmableComponent_Properties,
    .propertyCount = sizeof(g_ecl_DisarmableComponent_Properties) / sizeof(g_ecl_DisarmableComponent_Properties[0]),
};

// ecl::DisplayNameComponent - 32 bytes (0x20)
// Source: Components.h
static const ComponentPropertyDef g_ecl_DisplayNameComponent_Properties[] = {
    { "Name", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "NameKey", 0x04, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "UnknownKey", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Flags", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x1C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_DisplayNameComponent_Layout = {
    .componentName = "ecl::DisplayNameComponent",
    .shortName = "DisplayName",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_ecl_DisplayNameComponent_Properties,
    .propertyCount = sizeof(g_ecl_DisplayNameComponent_Properties) / sizeof(g_ecl_DisplayNameComponent_Properties[0]),
};

// ecl::EocCameraBehavior - 64 bytes (0x40)
// Source: Camera.h
static const ComponentPropertyDef g_ecl_EocCameraBehavior_Properties[] = {
    { "BehaviorType", 0x00, FIELD_TYPE_UINT32, 0, true },
    { "CameraEntity", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "TargetEntity", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "FOV", 0x18, FIELD_TYPE_FLOAT, 0, true },
    { "Distance", 0x1C, FIELD_TYPE_FLOAT, 0, true },
    { "Pitch", 0x20, FIELD_TYPE_FLOAT, 0, true },
    { "Yaw", 0x24, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x3C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_EocCameraBehavior_Layout = {
    .componentName = "ecl::EocCameraBehavior",
    .shortName = "EocCameraBehavior",
    .componentTypeIndex = 0,
    .componentSize = 0x40,
    .properties = g_ecl_EocCameraBehavior_Properties,
    .propertyCount = sizeof(g_ecl_EocCameraBehavior_Properties) / sizeof(g_ecl_EocCameraBehavior_Properties[0]),
};

// ecl::GroundMaterialComponent - 2 bytes (0x2)
// Source: Visual.h (material index)
static const ComponentPropertyDef g_ecl_GroundMaterialComponent_Properties[] = {
    { "MaterialIndex", 0x00, FIELD_TYPE_UINT16, 0, true },
};
static const ComponentLayoutDef g_ecl_GroundMaterialComponent_Layout = {
    .componentName = "ecl::GroundMaterialComponent",
    .shortName = "GroundMaterial",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_ecl_GroundMaterialComponent_Properties,
    .propertyCount = sizeof(g_ecl_GroundMaterialComponent_Properties) / sizeof(g_ecl_GroundMaterialComponent_Properties[0]),
};

// ecl::IgnoredComponent - 1 byte (0x1)
// Source: Components.h (tag)
static const ComponentPropertyDef g_ecl_IgnoredComponent_Properties[] = {
    { "Ignored", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ecl_IgnoredComponent_Layout = {
    .componentName = "ecl::IgnoredComponent",
    .shortName = "Ignored",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_ecl_IgnoredComponent_Properties,
    .propertyCount = sizeof(g_ecl_IgnoredComponent_Properties) / sizeof(g_ecl_IgnoredComponent_Properties[0]),
};

// ecl::InSelectComponent - 1 byte (0x1)
// Source: Components.h (tag)
static const ComponentPropertyDef g_ecl_InSelectComponent_Properties[] = {
    { "InSelect", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ecl_InSelectComponent_Layout = {
    .componentName = "ecl::InSelectComponent",
    .shortName = "InSelect",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_ecl_InSelectComponent_Properties,
    .propertyCount = sizeof(g_ecl_InSelectComponent_Properties) / sizeof(g_ecl_InSelectComponent_Properties[0]),
};

// ecl::InvisibilityAttachmentComponent - 1 byte (0x1)
// Source: Visual.h (tag)
static const ComponentPropertyDef g_ecl_InvisibilityAttachmentComponent_Properties[] = {
    { "HasAttachment", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ecl_InvisibilityAttachmentComponent_Layout = {
    .componentName = "ecl::InvisibilityAttachmentComponent",
    .shortName = "InvisibilityAttachment",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_ecl_InvisibilityAttachmentComponent_Properties,
    .propertyCount = sizeof(g_ecl_InvisibilityAttachmentComponent_Properties) / sizeof(g_ecl_InvisibilityAttachmentComponent_Properties[0]),
};

// ecl::InvisibilityFadingComponent - 12 bytes (0xc)
// Source: Visual.h (fade parameters)
static const ComponentPropertyDef g_ecl_InvisibilityFadingComponent_Properties[] = {
    { "FadeValue", 0x00, FIELD_TYPE_FLOAT, 0, true },
    { "FadeTarget", 0x04, FIELD_TYPE_FLOAT, 0, true },
    { "FadeSpeed", 0x08, FIELD_TYPE_FLOAT, 0, true },
};
static const ComponentLayoutDef g_ecl_InvisibilityFadingComponent_Layout = {
    .componentName = "ecl::InvisibilityFadingComponent",
    .shortName = "InvisibilityFading",
    .componentTypeIndex = 0,
    .componentSize = 0xc,
    .properties = g_ecl_InvisibilityFadingComponent_Properties,
    .propertyCount = sizeof(g_ecl_InvisibilityFadingComponent_Properties) / sizeof(g_ecl_InvisibilityFadingComponent_Properties[0]),
};

// ecl::InvisibilityVisualComponent - 12 bytes (0xc)
// Source: Visual.h (visual state)
static const ComponentPropertyDef g_ecl_InvisibilityVisualComponent_Properties[] = {
    { "Alpha", 0x00, FIELD_TYPE_FLOAT, 0, true },
    { "TargetAlpha", 0x04, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x08, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_InvisibilityVisualComponent_Layout = {
    .componentName = "ecl::InvisibilityVisualComponent",
    .shortName = "InvisibilityVisual",
    .componentTypeIndex = 0,
    .componentSize = 0xc,
    .properties = g_ecl_InvisibilityVisualComponent_Properties,
    .propertyCount = sizeof(g_ecl_InvisibilityVisualComponent_Properties) / sizeof(g_ecl_InvisibilityVisualComponent_Properties[0]),
};

// ecl::IsHoveredOverComponent - 1 byte (0x1)
// Source: Components.h (tag)
static const ComponentPropertyDef g_ecl_IsHoveredOverComponent_Properties[] = {
    { "IsHovered", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ecl_IsHoveredOverComponent_Layout = {
    .componentName = "ecl::IsHoveredOverComponent",
    .shortName = "IsHoveredOver",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_ecl_IsHoveredOverComponent_Properties,
    .propertyCount = sizeof(g_ecl_IsHoveredOverComponent_Properties) / sizeof(g_ecl_IsHoveredOverComponent_Properties[0]),
};

// ecl::MeshPreviewComponent - 88 bytes (0x58)
// Source: Visual.h
static const ComponentPropertyDef g_ecl_MeshPreviewComponent_Properties[] = {
    { "MeshEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "MeshResource", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "MaterialOverride", 0x0C, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "PreviewType", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Flags", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved10", 0x3C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved11", 0x40, FIELD_TYPE_UINT32, 0, true },
    { "Reserved12", 0x44, FIELD_TYPE_UINT32, 0, true },
    { "Reserved13", 0x48, FIELD_TYPE_UINT32, 0, true },
    { "Reserved14", 0x4C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved15", 0x50, FIELD_TYPE_UINT32, 0, true },
    { "Reserved16", 0x54, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_MeshPreviewComponent_Layout = {
    .componentName = "ecl::MeshPreviewComponent",
    .shortName = "MeshPreview",
    .componentTypeIndex = 0,
    .componentSize = 0x58,
    .properties = g_ecl_MeshPreviewComponent_Properties,
    .propertyCount = sizeof(g_ecl_MeshPreviewComponent_Properties) / sizeof(g_ecl_MeshPreviewComponent_Properties[0]),
};

// ecl::MovementComponent - 24 bytes (0x18)
// Source: Movement.h
static const ComponentPropertyDef g_ecl_MovementComponent_Properties[] = {
    { "TargetEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Speed", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "Acceleration", 0x0C, FIELD_TYPE_FLOAT, 0, true },
    { "MovementType", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Flags", 0x14, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_MovementComponent_Layout = {
    .componentName = "ecl::MovementComponent",
    .shortName = "Movement",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_ecl_MovementComponent_Properties,
    .propertyCount = sizeof(g_ecl_MovementComponent_Properties) / sizeof(g_ecl_MovementComponent_Properties[0]),
};

// ecl::ObjectInteractionComponent - 16 bytes (0x10)
// Source: Components.h
static const ComponentPropertyDef g_ecl_ObjectInteractionComponent_Properties[] = {
    { "InteractionEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Flags", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "Type", 0x0C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_ObjectInteractionComponent_Layout = {
    .componentName = "ecl::ObjectInteractionComponent",
    .shortName = "ObjectInteraction",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ecl_ObjectInteractionComponent_Properties,
    .propertyCount = sizeof(g_ecl_ObjectInteractionComponent_Properties) / sizeof(g_ecl_ObjectInteractionComponent_Properties[0]),
};

// ecl::PathingComponent - 80 bytes (0x50)
// Source: Movement.h
static const ComponentPropertyDef g_ecl_PathingComponent_Properties[] = {
    { "PathEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "TargetEntity", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "PathType", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "PathFlags", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "CurrentNode", 0x18, FIELD_TYPE_INT32, 0, true },
    { "TotalNodes", 0x1C, FIELD_TYPE_INT32, 0, true },
    { "Reserved1", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x3C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x40, FIELD_TYPE_UINT32, 0, true },
    { "Reserved10", 0x44, FIELD_TYPE_UINT32, 0, true },
    { "Reserved11", 0x48, FIELD_TYPE_UINT32, 0, true },
    { "Reserved12", 0x4C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_PathingComponent_Layout = {
    .componentName = "ecl::PathingComponent",
    .shortName = "Pathing",
    .componentTypeIndex = 0,
    .componentSize = 0x50,
    .properties = g_ecl_PathingComponent_Properties,
    .propertyCount = sizeof(g_ecl_PathingComponent_Properties) / sizeof(g_ecl_PathingComponent_Properties[0]),
};

// ecl::PickingStateComponent - 1 byte (0x1)
// Source: Components.h (tag)
static const ComponentPropertyDef g_ecl_PickingStateComponent_Properties[] = {
    { "Picking", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ecl_PickingStateComponent_Layout = {
    .componentName = "ecl::PickingStateComponent",
    .shortName = "PickingState",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_ecl_PickingStateComponent_Properties,
    .propertyCount = sizeof(g_ecl_PickingStateComponent_Properties) / sizeof(g_ecl_PickingStateComponent_Properties[0]),
};

// ecl::PlayerComponent - 1 byte (0x1)
// Source: Components.h (tag)
static const ComponentPropertyDef g_ecl_PlayerComponent_Properties[] = {
    { "IsPlayer", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ecl_PlayerComponent_Layout = {
    .componentName = "ecl::PlayerComponent",
    .shortName = "Player",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_ecl_PlayerComponent_Properties,
    .propertyCount = sizeof(g_ecl_PlayerComponent_Properties) / sizeof(g_ecl_PlayerComponent_Properties[0]),
};

// ecl::PointSoundTriggerDummy - 8 bytes (0x8)
// Source: Trigger.h (pointer)
static const ComponentPropertyDef g_ecl_PointSoundTriggerDummy_Properties[] = {
    { "Dummy", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_PointSoundTriggerDummy_Layout = {
    .componentName = "ecl::PointSoundTriggerDummy",
    .shortName = "PointSoundTriggerDummy",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_PointSoundTriggerDummy_Properties,
    .propertyCount = sizeof(g_ecl_PointSoundTriggerDummy_Properties) / sizeof(g_ecl_PointSoundTriggerDummy_Properties[0]),
};

// ecl::PointTrigger - 8 bytes (0x8)
// Source: Trigger.h (pointer)
static const ComponentPropertyDef g_ecl_PointTrigger_Properties[] = {
    { "TriggerEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_PointTrigger_Layout = {
    .componentName = "ecl::PointTrigger",
    .shortName = "PointTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_PointTrigger_Properties,
    .propertyCount = sizeof(g_ecl_PointTrigger_Properties) / sizeof(g_ecl_PointTrigger_Properties[0]),
};

// ecl::PortalTrigger - 8 bytes (0x8)
// Source: Trigger.h (pointer)
static const ComponentPropertyDef g_ecl_PortalTrigger_Properties[] = {
    { "Portal", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_PortalTrigger_Layout = {
    .componentName = "ecl::PortalTrigger",
    .shortName = "PortalTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_PortalTrigger_Properties,
    .propertyCount = sizeof(g_ecl_PortalTrigger_Properties) / sizeof(g_ecl_PortalTrigger_Properties[0]),
};

// ecl::RegionTrigger - 8 bytes (0x8)
// Source: Trigger.h (pointer)
static const ComponentPropertyDef g_ecl_RegionTrigger_Properties[] = {
    { "Region", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_RegionTrigger_Layout = {
    .componentName = "ecl::RegionTrigger",
    .shortName = "RegionTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_RegionTrigger_Properties,
    .propertyCount = sizeof(g_ecl_RegionTrigger_Properties) / sizeof(g_ecl_RegionTrigger_Properties[0]),
};

// ecl::RoomTrigger - 8 bytes (0x8)
// Source: Trigger.h (pointer)
static const ComponentPropertyDef g_ecl_RoomTrigger_Properties[] = {
    { "Room", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_RoomTrigger_Layout = {
    .componentName = "ecl::RoomTrigger",
    .shortName = "RoomTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_RoomTrigger_Properties,
    .propertyCount = sizeof(g_ecl_RoomTrigger_Properties) / sizeof(g_ecl_RoomTrigger_Properties[0]),
};

// ecl::SelectedComponent - 1 byte (0x1)
// Source: Components.h (tag)
static const ComponentPropertyDef g_ecl_SelectedComponent_Properties[] = {
    { "Selected", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ecl_SelectedComponent_Layout = {
    .componentName = "ecl::SelectedComponent",
    .shortName = "Selected",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_ecl_SelectedComponent_Properties,
    .propertyCount = sizeof(g_ecl_SelectedComponent_Properties) / sizeof(g_ecl_SelectedComponent_Properties[0]),
};

// ecl::SoundAttachmentComponent - 16 bytes (0x10)
// Source: Sound.h
static const ComponentPropertyDef g_ecl_SoundAttachmentComponent_Properties[] = {
    { "SoundEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "AttachmentType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "Flags", 0x0C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_SoundAttachmentComponent_Layout = {
    .componentName = "ecl::SoundAttachmentComponent",
    .shortName = "SoundAttachment",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ecl_SoundAttachmentComponent_Properties,
    .propertyCount = sizeof(g_ecl_SoundAttachmentComponent_Properties) / sizeof(g_ecl_SoundAttachmentComponent_Properties[0]),
};

// ecl::SoundVolumeTrigger - 8 bytes (0x8)
// Source: Trigger.h (pointer)
static const ComponentPropertyDef g_ecl_SoundVolumeTrigger_Properties[] = {
    { "Volume", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_SoundVolumeTrigger_Layout = {
    .componentName = "ecl::SoundVolumeTrigger",
    .shortName = "SoundVolumeTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_SoundVolumeTrigger_Properties,
    .propertyCount = sizeof(g_ecl_SoundVolumeTrigger_Properties) / sizeof(g_ecl_SoundVolumeTrigger_Properties[0]),
};

// ecl::SpectatorTrigger - 8 bytes (0x8)
// Source: Trigger.h (pointer)
static const ComponentPropertyDef g_ecl_SpectatorTrigger_Properties[] = {
    { "Spectator", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_SpectatorTrigger_Layout = {
    .componentName = "ecl::SpectatorTrigger",
    .shortName = "SpectatorTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_SpectatorTrigger_Properties,
    .propertyCount = sizeof(g_ecl_SpectatorTrigger_Properties) / sizeof(g_ecl_SpectatorTrigger_Properties[0]),
};

// ecl::TerrainWalkableAreaComponent - 80 bytes (0x50)
// Source: Visual.h
static const ComponentPropertyDef g_ecl_TerrainWalkableAreaComponent_Properties[] = {
    { "TerrainEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "AreaType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "AreaFlags", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "MinHeight", 0x10, FIELD_TYPE_FLOAT, 0, true },
    { "MaxHeight", 0x14, FIELD_TYPE_FLOAT, 0, true },
    { "Reserved1", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved10", 0x3C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved11", 0x40, FIELD_TYPE_UINT32, 0, true },
    { "Reserved12", 0x44, FIELD_TYPE_UINT32, 0, true },
    { "Reserved13", 0x48, FIELD_TYPE_UINT32, 0, true },
    { "Reserved14", 0x4C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_TerrainWalkableAreaComponent_Layout = {
    .componentName = "ecl::TerrainWalkableAreaComponent",
    .shortName = "TerrainWalkableArea",
    .componentTypeIndex = 0,
    .componentSize = 0x50,
    .properties = g_ecl_TerrainWalkableAreaComponent_Properties,
    .propertyCount = sizeof(g_ecl_TerrainWalkableAreaComponent_Properties) / sizeof(g_ecl_TerrainWalkableAreaComponent_Properties[0]),
};

// ecl::TimelineAnimationStateComponent - 8 bytes (0x8)
// Source: Timeline.h (state pointer)
static const ComponentPropertyDef g_ecl_TimelineAnimationStateComponent_Properties[] = {
    { "AnimationState", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelineAnimationStateComponent_Layout = {
    .componentName = "ecl::TimelineAnimationStateComponent",
    .shortName = "TimelineAnimationState",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_TimelineAnimationStateComponent_Properties,
    .propertyCount = sizeof(g_ecl_TimelineAnimationStateComponent_Properties) / sizeof(g_ecl_TimelineAnimationStateComponent_Properties[0]),
};

// ecl::TimelineAutomatedLookatComponent - 32 bytes (0x20)
// Source: Timeline.h
static const ComponentPropertyDef g_ecl_TimelineAutomatedLookatComponent_Properties[] = {
    { "TargetEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "LookAtSpeed", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "BlendTime", 0x0C, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "State", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x1C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelineAutomatedLookatComponent_Layout = {
    .componentName = "ecl::TimelineAutomatedLookatComponent",
    .shortName = "TimelineAutomatedLookat",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_ecl_TimelineAutomatedLookatComponent_Properties,
    .propertyCount = sizeof(g_ecl_TimelineAutomatedLookatComponent_Properties) / sizeof(g_ecl_TimelineAutomatedLookatComponent_Properties[0]),
};

// ecl::TimelineCameraRequestComponent - 32 bytes (0x20)
// Source: Timeline.h
static const ComponentPropertyDef g_ecl_TimelineCameraRequestComponent_Properties[] = {
    { "CameraEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "RequestType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "Priority", 0x0C, FIELD_TYPE_INT32, 0, true },
    { "BlendTime", 0x10, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x1C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelineCameraRequestComponent_Layout = {
    .componentName = "ecl::TimelineCameraRequestComponent",
    .shortName = "TimelineCameraRequest",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_ecl_TimelineCameraRequestComponent_Properties,
    .propertyCount = sizeof(g_ecl_TimelineCameraRequestComponent_Properties) / sizeof(g_ecl_TimelineCameraRequestComponent_Properties[0]),
};

// ecl::TimelineCameraShotComponent - 104 bytes (0x68)
// Source: Timeline.h
static const ComponentPropertyDef g_ecl_TimelineCameraShotComponent_Properties[] = {
    { "CameraEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "ShotType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "ShotFlags", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "TargetEntity", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "FOV", 0x18, FIELD_TYPE_FLOAT, 0, true },
    { "BlendTime", 0x1C, FIELD_TYPE_FLOAT, 0, true },
    { "Duration", 0x20, FIELD_TYPE_FLOAT, 0, true },
    { "Priority", 0x24, FIELD_TYPE_INT32, 0, true },
    { "Reserved1", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x3C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x40, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x44, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x48, FIELD_TYPE_UINT32, 0, true },
    { "Reserved10", 0x4C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved11", 0x50, FIELD_TYPE_UINT32, 0, true },
    { "Reserved12", 0x54, FIELD_TYPE_UINT32, 0, true },
    { "Reserved13", 0x58, FIELD_TYPE_UINT32, 0, true },
    { "Reserved14", 0x5C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved15", 0x60, FIELD_TYPE_UINT32, 0, true },
    { "Reserved16", 0x64, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelineCameraShotComponent_Layout = {
    .componentName = "ecl::TimelineCameraShotComponent",
    .shortName = "TimelineCameraShot",
    .componentTypeIndex = 0,
    .componentSize = 0x68,
    .properties = g_ecl_TimelineCameraShotComponent_Properties,
    .propertyCount = sizeof(g_ecl_TimelineCameraShotComponent_Properties) / sizeof(g_ecl_TimelineCameraShotComponent_Properties[0]),
};

// ecl::TimelineEyeLookAtOverrideComponent - 48 bytes (0x30)
// Source: Timeline.h
static const ComponentPropertyDef g_ecl_TimelineEyeLookAtOverrideComponent_Properties[] = {
    { "TargetEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "OverrideType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "BlendTime", 0x0C, FIELD_TYPE_FLOAT, 0, true },
    { "Weight", 0x10, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x2C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelineEyeLookAtOverrideComponent_Layout = {
    .componentName = "ecl::TimelineEyeLookAtOverrideComponent",
    .shortName = "TimelineEyeLookAtOverride",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_ecl_TimelineEyeLookAtOverrideComponent_Properties,
    .propertyCount = sizeof(g_ecl_TimelineEyeLookAtOverrideComponent_Properties) / sizeof(g_ecl_TimelineEyeLookAtOverrideComponent_Properties[0]),
};

// ecl::TimelinePlayerTransitionEventOneFrameComponent - 64 bytes (0x40)
// Source: Timeline.h
static const ComponentPropertyDef g_ecl_TimelinePlayerTransitionEventOneFrameComponent_Properties[] = {
    { "PlayerEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "TransitionType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "TargetEntity", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "BlendTime", 0x18, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x3C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelinePlayerTransitionEventOneFrameComponent_Layout = {
    .componentName = "ecl::TimelinePlayerTransitionEventOneFrameComponent",
    .shortName = "TimelinePlayerTransitionEvent",
    .componentTypeIndex = 0,
    .componentSize = 0x40,
    .properties = g_ecl_TimelinePlayerTransitionEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_ecl_TimelinePlayerTransitionEventOneFrameComponent_Properties) / sizeof(g_ecl_TimelinePlayerTransitionEventOneFrameComponent_Properties[0]),
};

// ecl::TimelineQuestionHoldAutomationComponent - 28 bytes (0x1c)
// Source: Timeline.h
static const ComponentPropertyDef g_ecl_TimelineQuestionHoldAutomationComponent_Properties[] = {
    { "QuestionEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "HoldDuration", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "CurrentTime", 0x0C, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "State", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved", 0x18, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelineQuestionHoldAutomationComponent_Layout = {
    .componentName = "ecl::TimelineQuestionHoldAutomationComponent",
    .shortName = "TimelineQuestionHoldAutomation",
    .componentTypeIndex = 0,
    .componentSize = 0x1c,
    .properties = g_ecl_TimelineQuestionHoldAutomationComponent_Properties,
    .propertyCount = sizeof(g_ecl_TimelineQuestionHoldAutomationComponent_Properties) / sizeof(g_ecl_TimelineQuestionHoldAutomationComponent_Properties[0]),
};

// ecl::TimelineSceneTrigger - 8 bytes (0x8)
// Source: Timeline.h (trigger pointer)
static const ComponentPropertyDef g_ecl_TimelineSceneTrigger_Properties[] = {
    { "Trigger", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelineSceneTrigger_Layout = {
    .componentName = "ecl::TimelineSceneTrigger",
    .shortName = "TimelineSceneTrigger",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_TimelineSceneTrigger_Properties,
    .propertyCount = sizeof(g_ecl_TimelineSceneTrigger_Properties) / sizeof(g_ecl_TimelineSceneTrigger_Properties[0]),
};

// ecl::TimelineSplatterComponent - 36 bytes (0x24)
// Source: Timeline.h
static const ComponentPropertyDef g_ecl_TimelineSplatterComponent_Properties[] = {
    { "SplatterEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "SplatterType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "Intensity", 0x0C, FIELD_TYPE_FLOAT, 0, true },
    { "Radius", 0x10, FIELD_TYPE_FLOAT, 0, true },
    { "Duration", 0x14, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x20, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelineSplatterComponent_Layout = {
    .componentName = "ecl::TimelineSplatterComponent",
    .shortName = "TimelineSplatter",
    .componentTypeIndex = 0,
    .componentSize = 0x24,
    .properties = g_ecl_TimelineSplatterComponent_Properties,
    .propertyCount = sizeof(g_ecl_TimelineSplatterComponent_Properties) / sizeof(g_ecl_TimelineSplatterComponent_Properties[0]),
};

// ecl::TimelineSpringsComponent - 8 bytes (0x8)
// Source: Timeline.h (springs data pointer)
static const ComponentPropertyDef g_ecl_TimelineSpringsComponent_Properties[] = {
    { "Springs", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelineSpringsComponent_Layout = {
    .componentName = "ecl::TimelineSpringsComponent",
    .shortName = "TimelineSprings",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_TimelineSpringsComponent_Properties,
    .propertyCount = sizeof(g_ecl_TimelineSpringsComponent_Properties) / sizeof(g_ecl_TimelineSpringsComponent_Properties[0]),
};

// ecl::TimelineSteppingFadeComponent - 8 bytes (0x8)
// Source: Timeline.h (fade data pointer)
static const ComponentPropertyDef g_ecl_TimelineSteppingFadeComponent_Properties[] = {
    { "Fade", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_TimelineSteppingFadeComponent_Layout = {
    .componentName = "ecl::TimelineSteppingFadeComponent",
    .shortName = "TimelineSteppingFade",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_TimelineSteppingFadeComponent_Properties,
    .propertyCount = sizeof(g_ecl_TimelineSteppingFadeComponent_Properties) / sizeof(g_ecl_TimelineSteppingFadeComponent_Properties[0]),
};

// ecl::TurnActionsDoneOneFrameComponent - 1 byte (0x1)
// Source: Timeline.h (one-frame tag)
static const ComponentPropertyDef g_ecl_TurnActionsDoneOneFrameComponent_Properties[] = {
    { "Done", 0x00, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ecl_TurnActionsDoneOneFrameComponent_Layout = {
    .componentName = "ecl::TurnActionsDoneOneFrameComponent",
    .shortName = "TurnActionsDoneOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_ecl_TurnActionsDoneOneFrameComponent_Properties,
    .propertyCount = sizeof(g_ecl_TurnActionsDoneOneFrameComponent_Properties) / sizeof(g_ecl_TurnActionsDoneOneFrameComponent_Properties[0]),
};

// ecl::TurnBasedComponent - 48 bytes (0x30)
// Source: Combat.h
static const ComponentPropertyDef g_ecl_TurnBasedComponent_Properties[] = {
    { "TurnOrder", 0x00, FIELD_TYPE_INT32, 0, true },
    { "Initiative", 0x04, FIELD_TYPE_INT32, 0, true },
    { "CurrentTurn", 0x08, FIELD_TYPE_BOOL, 0, true },
    { "CombatId", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "TeamId", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Flags", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x2C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_TurnBasedComponent_Layout = {
    .componentName = "ecl::TurnBasedComponent",
    .shortName = "TurnBased",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_ecl_TurnBasedComponent_Properties,
    .propertyCount = sizeof(g_ecl_TurnBasedComponent_Properties) / sizeof(g_ecl_TurnBasedComponent_Properties[0]),
};

// ecl::UseComponent - 80 bytes (0x50)
// Source: Components.h
static const ComponentPropertyDef g_ecl_UseComponent_Properties[] = {
    { "UseEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "UserEntity", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "UseType", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "UseFlags", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "UseAction", 0x18, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Charges", 0x1C, FIELD_TYPE_INT32, 0, true },
    { "MaxCharges", 0x20, FIELD_TYPE_INT32, 0, true },
    { "Flags", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x3C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x40, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x44, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x48, FIELD_TYPE_UINT32, 0, true },
    { "Reserved10", 0x4C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_UseComponent_Layout = {
    .componentName = "ecl::UseComponent",
    .shortName = "Use",
    .componentTypeIndex = 0,
    .componentSize = 0x50,
    .properties = g_ecl_UseComponent_Properties,
    .propertyCount = sizeof(g_ecl_UseComponent_Properties) / sizeof(g_ecl_UseComponent_Properties[0]),
};

// ecl::VoiceComponent - 24 bytes (0x18)
// Source: Sound.h
static const ComponentPropertyDef g_ecl_VoiceComponent_Properties[] = {
    { "VoiceEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "VoiceType", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Volume", 0x0C, FIELD_TYPE_FLOAT, 0, true },
    { "Pitch", 0x10, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x14, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_VoiceComponent_Layout = {
    .componentName = "ecl::VoiceComponent",
    .shortName = "Voice",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_ecl_VoiceComponent_Properties,
    .propertyCount = sizeof(g_ecl_VoiceComponent_Properties) / sizeof(g_ecl_VoiceComponent_Properties[0]),
};

// ecl::WalkableSurfaceComponent - 16 bytes (0x10)
// Source: Visual.h
static const ComponentPropertyDef g_ecl_WalkableSurfaceComponent_Properties[] = {
    { "SurfaceType", 0x00, FIELD_TYPE_UINT32, 0, true },
    { "Flags", 0x04, FIELD_TYPE_UINT32, 0, true },
    { "Material", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Reserved", 0x0C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_WalkableSurfaceComponent_Layout = {
    .componentName = "ecl::WalkableSurfaceComponent",
    .shortName = "WalkableSurface",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ecl_WalkableSurfaceComponent_Properties,
    .propertyCount = sizeof(g_ecl_WalkableSurfaceComponent_Properties) / sizeof(g_ecl_WalkableSurfaceComponent_Properties[0]),
};

// ecl::WeaponComponent - 80 bytes (0x50)
// Source: Item.h
static const ComponentPropertyDef g_ecl_WeaponComponent_Properties[] = {
    { "WeaponEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "WeaponType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "DamageType", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "MinDamage", 0x10, FIELD_TYPE_INT32, 0, true },
    { "MaxDamage", 0x14, FIELD_TYPE_INT32, 0, true },
    { "AttackBonus", 0x18, FIELD_TYPE_INT32, 0, true },
    { "DamageBonus", 0x1C, FIELD_TYPE_INT32, 0, true },
    { "Flags", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x3C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x40, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x44, FIELD_TYPE_UINT32, 0, true },
    { "Reserved10", 0x48, FIELD_TYPE_UINT32, 0, true },
    { "Reserved11", 0x4C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_WeaponComponent_Layout = {
    .componentName = "ecl::WeaponComponent",
    .shortName = "Weapon",
    .componentTypeIndex = 0,
    .componentSize = 0x50,
    .properties = g_ecl_WeaponComponent_Properties,
    .propertyCount = sizeof(g_ecl_WeaponComponent_Properties) / sizeof(g_ecl_WeaponComponent_Properties[0]),
};

// ecl::camera::CombatTargetComponent - 48 bytes (0x30)
// Source: Camera.h (verified from Camera.h:336-341)
static const ComponentPropertyDef g_ecl_camera_CombatTargetComponent_Properties[] = {
    { "TargetEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Priority", 0x08, FIELD_TYPE_INT32, 0, true },
    { "Flags", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "Position", 0x10, FIELD_TYPE_FLOAT, 0, true },  // vec3 x
    { "PositionY", 0x14, FIELD_TYPE_FLOAT, 0, true },  // vec3 y
    { "PositionZ", 0x18, FIELD_TYPE_FLOAT, 0, true },  // vec3 z
    { "Distance", 0x1C, FIELD_TYPE_FLOAT, 0, true },
    { "Zoom", 0x20, FIELD_TYPE_FLOAT, 0, true },
    { "Reserved1", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x2C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_camera_CombatTargetComponent_Layout = {
    .componentName = "ecl::camera::CombatTargetComponent",
    .shortName = "CameraCombatTarget",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_ecl_camera_CombatTargetComponent_Properties,
    .propertyCount = sizeof(g_ecl_camera_CombatTargetComponent_Properties) / sizeof(g_ecl_camera_CombatTargetComponent_Properties[0]),
};

// ecl::camera::CombatTargetRequestsComponent - 16 bytes (0x10)
// Source: Camera.h
static const ComponentPropertyDef g_ecl_camera_CombatTargetRequestsComponent_Properties[] = {
    { "TargetEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Priority", 0x08, FIELD_TYPE_INT32, 0, true },
    { "Flags", 0x0C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_camera_CombatTargetRequestsComponent_Layout = {
    .componentName = "ecl::camera::CombatTargetRequestsComponent",
    .shortName = "CameraCombatTargetRequests",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ecl_camera_CombatTargetRequestsComponent_Properties,
    .propertyCount = sizeof(g_ecl_camera_CombatTargetRequestsComponent_Properties) / sizeof(g_ecl_camera_CombatTargetRequestsComponent_Properties[0]),
};

// ecl::crowds::SoundVolumeComponent - 56 bytes (0x38)
// Source: Sound.h
static const ComponentPropertyDef g_ecl_crowds_SoundVolumeComponent_Properties[] = {
    { "VolumeEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Volume", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "TargetVolume", 0x0C, FIELD_TYPE_FLOAT, 0, true },
    { "FadeTime", 0x10, FIELD_TYPE_FLOAT, 0, true },
    { "CurrentFadeTime", 0x14, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x34, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_crowds_SoundVolumeComponent_Layout = {
    .componentName = "ecl::crowds::SoundVolumeComponent",
    .shortName = "CrowdsSoundVolume",
    .componentTypeIndex = 0,
    .componentSize = 0x38,
    .properties = g_ecl_crowds_SoundVolumeComponent_Properties,
    .propertyCount = sizeof(g_ecl_crowds_SoundVolumeComponent_Properties) / sizeof(g_ecl_crowds_SoundVolumeComponent_Properties[0]),
};

// ecl::death::DeathImpactComponent - 24 bytes (0x18)
// Source: Death.h
static const ComponentPropertyDef g_ecl_death_DeathImpactComponent_Properties[] = {
    { "ImpactEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "ImpactForce", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "ImpactType", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "DamageType", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Flags", 0x14, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_death_DeathImpactComponent_Layout = {
    .componentName = "ecl::death::DeathImpactComponent",
    .shortName = "DeathImpact",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_ecl_death_DeathImpactComponent_Properties,
    .propertyCount = sizeof(g_ecl_death_DeathImpactComponent_Properties) / sizeof(g_ecl_death_DeathImpactComponent_Properties[0]),
};

// ecl::death::StateComponent - 16 bytes (0x10)
// Source: Death.h
static const ComponentPropertyDef g_ecl_death_StateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_UINT32, 0, true },
    { "DeathTime", 0x04, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "Reserved", 0x0C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_death_StateComponent_Layout = {
    .componentName = "ecl::death::StateComponent",
    .shortName = "DeathState",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ecl_death_StateComponent_Properties,
    .propertyCount = sizeof(g_ecl_death_StateComponent_Properties) / sizeof(g_ecl_death_StateComponent_Properties[0]),
};

// ecl::effect::HandlerComponent - 8 bytes (0x8)
// Source: Effect.h (handler pointer)
static const ComponentPropertyDef g_ecl_effect_HandlerComponent_Properties[] = {
    { "Handler", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_effect_HandlerComponent_Layout = {
    .componentName = "ecl::effect::HandlerComponent",
    .shortName = "EffectHandler",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_effect_HandlerComponent_Properties,
    .propertyCount = sizeof(g_ecl_effect_HandlerComponent_Properties) / sizeof(g_ecl_effect_HandlerComponent_Properties[0]),
};

// ecl::effect::InfluenceTrackerComponent - 96 bytes (0x60)
// Source: Effect.h
static const ComponentPropertyDef g_ecl_effect_InfluenceTrackerComponent_Properties[] = {
    { "TrackerEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "InfluenceType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "InfluenceFlags", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "SourceEntity", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "TargetEntity", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "InfluenceValue", 0x20, FIELD_TYPE_FLOAT, 0, true },
    { "Reserved1", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x3C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x40, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x44, FIELD_TYPE_UINT32, 0, true },
    { "Reserved10", 0x48, FIELD_TYPE_UINT32, 0, true },
    { "Reserved11", 0x4C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved12", 0x50, FIELD_TYPE_UINT32, 0, true },
    { "Reserved13", 0x54, FIELD_TYPE_UINT32, 0, true },
    { "Reserved14", 0x58, FIELD_TYPE_UINT32, 0, true },
    { "Reserved15", 0x5C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_effect_InfluenceTrackerComponent_Layout = {
    .componentName = "ecl::effect::InfluenceTrackerComponent",
    .shortName = "EffectInfluenceTracker",
    .componentTypeIndex = 0,
    .componentSize = 0x60,
    .properties = g_ecl_effect_InfluenceTrackerComponent_Properties,
    .propertyCount = sizeof(g_ecl_effect_InfluenceTrackerComponent_Properties) / sizeof(g_ecl_effect_InfluenceTrackerComponent_Properties[0]),
};

// ecl::effect::InteractionEventOneFrameComponent - 40 bytes (0x28)
// Source: Effect.h
static const ComponentPropertyDef g_ecl_effect_InteractionEventOneFrameComponent_Properties[] = {
    { "InteractionEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "InteractionType", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "TargetEntity", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Flags", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x24, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_effect_InteractionEventOneFrameComponent_Layout = {
    .componentName = "ecl::effect::InteractionEventOneFrameComponent",
    .shortName = "EffectInteractionEvent",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_ecl_effect_InteractionEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_ecl_effect_InteractionEventOneFrameComponent_Properties) / sizeof(g_ecl_effect_InteractionEventOneFrameComponent_Properties[0]),
};

// ecl::effect::SharedTimerComponent - 24 bytes (0x18)
// Source: Effect.h
static const ComponentPropertyDef g_ecl_effect_SharedTimerComponent_Properties[] = {
    { "Timer", 0x00, FIELD_TYPE_FLOAT, 0, true },
    { "Duration", 0x04, FIELD_TYPE_FLOAT, 0, true },
    { "StartTime", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "TimerType", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Reserved", 0x14, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_effect_SharedTimerComponent_Layout = {
    .componentName = "ecl::effect::SharedTimerComponent",
    .shortName = "EffectSharedTimer",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_ecl_effect_SharedTimerComponent_Properties,
    .propertyCount = sizeof(g_ecl_effect_SharedTimerComponent_Properties) / sizeof(g_ecl_effect_SharedTimerComponent_Properties[0]),
};

// ecl::effect::SpawnedComponent - 24 bytes (0x18)
// Source: Effect.h
static const ComponentPropertyDef g_ecl_effect_SpawnedComponent_Properties[] = {
    { "SpawnedEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "SpawnTime", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "SpawnType", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "ParentEntity", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_effect_SpawnedComponent_Layout = {
    .componentName = "ecl::effect::SpawnedComponent",
    .shortName = "EffectSpawned",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_ecl_effect_SpawnedComponent_Properties,
    .propertyCount = sizeof(g_ecl_effect_SpawnedComponent_Properties) / sizeof(g_ecl_effect_SpawnedComponent_Properties[0]),
};

// ecl::multiplayer::UsersComponent - 24 bytes (0x18)
// Source: Multiplayer.h
static const ComponentPropertyDef g_ecl_multiplayer_UsersComponent_Properties[] = {
    { "UserCount", 0x00, FIELD_TYPE_INT32, 0, true },
    { "MaxUsers", 0x04, FIELD_TYPE_INT32, 0, true },
    { "Flags", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x14, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_multiplayer_UsersComponent_Layout = {
    .componentName = "ecl::multiplayer::UsersComponent",
    .shortName = "MultiplayerUsers",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_ecl_multiplayer_UsersComponent_Properties,
    .propertyCount = sizeof(g_ecl_multiplayer_UsersComponent_Properties) / sizeof(g_ecl_multiplayer_UsersComponent_Properties[0]),
};

// ecl::projectile::AttachmentComponent - 8 bytes (0x8)
// Source: Projectile.h (attachment reference)
static const ComponentPropertyDef g_ecl_projectile_AttachmentComponent_Properties[] = {
    { "Attachment", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_projectile_AttachmentComponent_Layout = {
    .componentName = "ecl::projectile::AttachmentComponent",
    .shortName = "ProjectileAttachment",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_projectile_AttachmentComponent_Properties,
    .propertyCount = sizeof(g_ecl_projectile_AttachmentComponent_Properties) / sizeof(g_ecl_projectile_AttachmentComponent_Properties[0]),
};

// ecl::relation::RelationChangedEventOneFrameComponent - 8 bytes (0x8)
// Source: Events.h (relation event)
static const ComponentPropertyDef g_ecl_relation_RelationChangedEventOneFrameComponent_Properties[] = {
    { "RelationEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_ecl_relation_RelationChangedEventOneFrameComponent_Layout = {
    .componentName = "ecl::relation::RelationChangedEventOneFrameComponent",
    .shortName = "RelationChangedEventOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_ecl_relation_RelationChangedEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_ecl_relation_RelationChangedEventOneFrameComponent_Properties) / sizeof(g_ecl_relation_RelationChangedEventOneFrameComponent_Properties[0]),
};

// ecl::sound::CharacterSwitchDataComponent - 120 bytes (0x78)
// Source: Sound.h
static const ComponentPropertyDef g_ecl_sound_CharacterSwitchDataComponent_Properties[] = {
    { "CharacterEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "SwitchGroup1", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "SwitchState1", 0x0C, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "SwitchGroup2", 0x10, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "SwitchState2", 0x14, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "SwitchGroup3", 0x18, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "SwitchState3", 0x1C, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Flags", 0x20, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_sound_CharacterSwitchDataComponent_Layout = {
    .componentName = "ecl::sound::CharacterSwitchDataComponent",
    .shortName = "SoundCharacterSwitchData",
    .componentTypeIndex = 0,
    .componentSize = 0x78,
    .properties = g_ecl_sound_CharacterSwitchDataComponent_Properties,
    .propertyCount = sizeof(g_ecl_sound_CharacterSwitchDataComponent_Properties) / sizeof(g_ecl_sound_CharacterSwitchDataComponent_Properties[0]),
};

// ecl::sound::DecoratorSwitchDataComponent - 48 bytes (0x30)
// Source: Sound.h
static const ComponentPropertyDef g_ecl_sound_DecoratorSwitchDataComponent_Properties[] = {
    { "SwitchGroup", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "SwitchState", 0x04, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Flags", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x2C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_sound_DecoratorSwitchDataComponent_Layout = {
    .componentName = "ecl::sound::DecoratorSwitchDataComponent",
    .shortName = "SoundDecoratorSwitchData",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_ecl_sound_DecoratorSwitchDataComponent_Properties,
    .propertyCount = sizeof(g_ecl_sound_DecoratorSwitchDataComponent_Properties) / sizeof(g_ecl_sound_DecoratorSwitchDataComponent_Properties[0]),
};

// ecl::sound::ItemSwitchDataComponent - 64 bytes (0x40)
// Source: Sound.h
static const ComponentPropertyDef g_ecl_sound_ItemSwitchDataComponent_Properties[] = {
    { "ItemEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "SwitchGroup", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "SwitchState", 0x0C, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Flags", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved10", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved11", 0x3C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_sound_ItemSwitchDataComponent_Layout = {
    .componentName = "ecl::sound::ItemSwitchDataComponent",
    .shortName = "SoundItemSwitchData",
    .componentTypeIndex = 0,
    .componentSize = 0x40,
    .properties = g_ecl_sound_ItemSwitchDataComponent_Properties,
    .propertyCount = sizeof(g_ecl_sound_ItemSwitchDataComponent_Properties) / sizeof(g_ecl_sound_ItemSwitchDataComponent_Properties[0]),
};

// ecl::sound::SoundCacheComponent - 40 bytes (0x28)
// Source: Sound.h
static const ComponentPropertyDef g_ecl_sound_SoundCacheComponent_Properties[] = {
    { "CachedSound", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Volume", 0x04, FIELD_TYPE_FLOAT, 0, true },
    { "Pitch", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "CacheTime", 0x0C, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x14, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x18, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x1C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x20, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x24, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_sound_SoundCacheComponent_Layout = {
    .componentName = "ecl::sound::SoundCacheComponent",
    .shortName = "SoundCache",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_ecl_sound_SoundCacheComponent_Properties,
    .propertyCount = sizeof(g_ecl_sound_SoundCacheComponent_Properties) / sizeof(g_ecl_sound_SoundCacheComponent_Properties[0]),
};

// ecl::spell_cast::PlaySoundRequestOneFrameComponent - 16 bytes (0x10)
// Source: SpellCast.h
static const ComponentPropertyDef g_ecl_spell_cast_PlaySoundRequestOneFrameComponent_Properties[] = {
    { "SoundResource", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Volume", 0x04, FIELD_TYPE_FLOAT, 0, true },
    { "Pitch", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x0C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_spell_cast_PlaySoundRequestOneFrameComponent_Layout = {
    .componentName = "ecl::spell_cast::PlaySoundRequestOneFrameComponent",
    .shortName = "SpellCastPlaySoundRequest",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ecl_spell_cast_PlaySoundRequestOneFrameComponent_Properties,
    .propertyCount = sizeof(g_ecl_spell_cast_PlaySoundRequestOneFrameComponent_Properties) / sizeof(g_ecl_spell_cast_PlaySoundRequestOneFrameComponent_Properties[0]),
};

// ecl::spell_cast::SetSoundSwitchesRequestOneFrameComponent - 16 bytes (0x10)
// Source: SpellCast.h
static const ComponentPropertyDef g_ecl_spell_cast_SetSoundSwitchesRequestOneFrameComponent_Properties[] = {
    { "SwitchGroup", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "SwitchState", 0x04, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Priority", 0x08, FIELD_TYPE_INT32, 0, true },
    { "Flags", 0x0C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_spell_cast_SetSoundSwitchesRequestOneFrameComponent_Layout = {
    .componentName = "ecl::spell_cast::SetSoundSwitchesRequestOneFrameComponent",
    .shortName = "SpellCastSetSoundSwitches",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ecl_spell_cast_SetSoundSwitchesRequestOneFrameComponent_Properties,
    .propertyCount = sizeof(g_ecl_spell_cast_SetSoundSwitchesRequestOneFrameComponent_Properties) / sizeof(g_ecl_spell_cast_SetSoundSwitchesRequestOneFrameComponent_Properties[0]),
};

// ecl::spell_cast::SoundImpactEventOneFrameComponent - 80 bytes (0x50)
// Source: SpellCast.h
static const ComponentPropertyDef g_ecl_spell_cast_SoundImpactEventOneFrameComponent_Properties[] = {
    { "ImpactEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "SoundResource", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "ImpactType", 0x0C, FIELD_TYPE_UINT32, 0, true },
    { "Volume", 0x10, FIELD_TYPE_FLOAT, 0, true },
    { "Pitch", 0x14, FIELD_TYPE_FLOAT, 0, true },
    { "PositionX", 0x18, FIELD_TYPE_FLOAT, 0, true },
    { "PositionY", 0x1C, FIELD_TYPE_FLOAT, 0, true },
    { "PositionZ", 0x20, FIELD_TYPE_FLOAT, 0, true },
    { "Flags", 0x24, FIELD_TYPE_UINT32, 0, true },
    { "Reserved1", 0x28, FIELD_TYPE_UINT32, 0, true },
    { "Reserved2", 0x2C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved3", 0x30, FIELD_TYPE_UINT32, 0, true },
    { "Reserved4", 0x34, FIELD_TYPE_UINT32, 0, true },
    { "Reserved5", 0x38, FIELD_TYPE_UINT32, 0, true },
    { "Reserved6", 0x3C, FIELD_TYPE_UINT32, 0, true },
    { "Reserved7", 0x40, FIELD_TYPE_UINT32, 0, true },
    { "Reserved8", 0x44, FIELD_TYPE_UINT32, 0, true },
    { "Reserved9", 0x48, FIELD_TYPE_UINT32, 0, true },
    { "Reserved10", 0x4C, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ecl_spell_cast_SoundImpactEventOneFrameComponent_Layout = {
    .componentName = "ecl::spell_cast::SoundImpactEventOneFrameComponent",
    .shortName = "SpellCastSoundImpactEvent",
    .componentTypeIndex = 0,
    .componentSize = 0x50,
    .properties = g_ecl_spell_cast_SoundImpactEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_ecl_spell_cast_SoundImpactEventOneFrameComponent_Properties) / sizeof(g_ecl_spell_cast_SoundImpactEventOneFrameComponent_Properties[0]),
};


// === ls:: namespace (39 layouts) ===

// ls::AnimationBlueprintComponent - 8 bytes (0x08)
// Source: Visual.h, COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_AnimationBlueprint_Properties[] = {
    { "Instance", 0x00, FIELD_TYPE_UINT64, 0, true },
};
static const ComponentLayoutDef g_ls_AnimationBlueprint_Layout = {
    .componentName = "ls::AnimationBlueprintComponent",
    .shortName = "AnimationBlueprint",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_ls_AnimationBlueprint_Properties,
    .propertyCount = sizeof(g_ls_AnimationBlueprint_Properties) / sizeof(g_ls_AnimationBlueprint_Properties[0]),
};

// ls::AnimationSetComponent - 8 bytes (0x08)
// Source: Visual.h, COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_AnimationSet_Properties[] = {
    { "Entries", 0x00, FIELD_TYPE_UINT64, 0, true },
};
static const ComponentLayoutDef g_ls_AnimationSet_Layout = {
    .componentName = "ls::AnimationSetComponent",
    .shortName = "AnimationSet",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_ls_AnimationSet_Properties,
    .propertyCount = sizeof(g_ls_AnimationSet_Properties) / sizeof(g_ls_AnimationSet_Properties[0]),
};

// ls::ClusterAttachRequestComponent - 1 bytes (0x01)
// Source: COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_ClusterAttachRequest_Properties[] = {};
static const ComponentLayoutDef g_ls_ClusterAttachRequest_Layout = {
    .componentName = "ls::ClusterAttachRequestComponent",
    .shortName = "ClusterAttachRequest",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_ls_ClusterAttachRequest_Properties,
    .propertyCount = 0,
};

// ls::ClusterBoundMaxComponent - 4 bytes (0x04)
// Source: COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_ClusterBoundMax_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_FLOAT, 0, true },
};
static const ComponentLayoutDef g_ls_ClusterBoundMax_Layout = {
    .componentName = "ls::ClusterBoundMaxComponent",
    .shortName = "ClusterBoundMax",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_ls_ClusterBoundMax_Properties,
    .propertyCount = sizeof(g_ls_ClusterBoundMax_Properties) / sizeof(g_ls_ClusterBoundMax_Properties[0]),
};

// ls::ClusterComponent - 1 bytes (0x01)
// Source: COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_Cluster_Properties[] = {};
static const ComponentLayoutDef g_ls_Cluster_Layout = {
    .componentName = "ls::ClusterComponent",
    .shortName = "Cluster",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_ls_Cluster_Properties,
    .propertyCount = 0,
};

// ls::ClusterDistMaxComponent - 4 bytes (0x04)
// Source: COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_ClusterDistMax_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_FLOAT, 0, true },
};
static const ComponentLayoutDef g_ls_ClusterDistMax_Layout = {
    .componentName = "ls::ClusterDistMaxComponent",
    .shortName = "ClusterDistMax",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_ls_ClusterDistMax_Properties,
    .propertyCount = sizeof(g_ls_ClusterDistMax_Properties) / sizeof(g_ls_ClusterDistMax_Properties[0]),
};

// ls::ClusterDistMinComponent - 4 bytes (0x04)
// Source: COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_ClusterDistMin_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_FLOAT, 0, true },
};
static const ComponentLayoutDef g_ls_ClusterDistMin_Layout = {
    .componentName = "ls::ClusterDistMinComponent",
    .shortName = "ClusterDistMin",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_ls_ClusterDistMin_Properties,
    .propertyCount = sizeof(g_ls_ClusterDistMin_Properties) / sizeof(g_ls_ClusterDistMin_Properties[0]),
};

// ls::ClusterPositionXComponent - 4 bytes (0x04)
// Source: COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_ClusterPositionX_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_FLOAT, 0, true },
};
static const ComponentLayoutDef g_ls_ClusterPositionX_Layout = {
    .componentName = "ls::ClusterPositionXComponent",
    .shortName = "ClusterPositionX",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_ls_ClusterPositionX_Properties,
    .propertyCount = sizeof(g_ls_ClusterPositionX_Properties) / sizeof(g_ls_ClusterPositionX_Properties[0]),
};

// ls::ClusterPositionYComponent - 4 bytes (0x04)
// Source: COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_ClusterPositionY_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_FLOAT, 0, true },
};
static const ComponentLayoutDef g_ls_ClusterPositionY_Layout = {
    .componentName = "ls::ClusterPositionYComponent",
    .shortName = "ClusterPositionY",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_ls_ClusterPositionY_Properties,
    .propertyCount = sizeof(g_ls_ClusterPositionY_Properties) / sizeof(g_ls_ClusterPositionY_Properties[0]),
};

// ls::ClusterPositionZComponent - 4 bytes (0x04)
// Source: COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_ClusterPositionZ_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_FLOAT, 0, true },
};
static const ComponentLayoutDef g_ls_ClusterPositionZ_Layout = {
    .componentName = "ls::ClusterPositionZComponent",
    .shortName = "ClusterPositionZ",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_ls_ClusterPositionZ_Properties,
    .propertyCount = sizeof(g_ls_ClusterPositionZ_Properties) / sizeof(g_ls_ClusterPositionZ_Properties[0]),
};

// ls::ClusterRadiusComponent - 4 bytes (0x04)
// Source: COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_ClusterRadius_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_FLOAT, 0, true },
};
static const ComponentLayoutDef g_ls_ClusterRadius_Layout = {
    .componentName = "ls::ClusterRadiusComponent",
    .shortName = "ClusterRadius",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_ls_ClusterRadius_Properties,
    .propertyCount = sizeof(g_ls_ClusterRadius_Properties) / sizeof(g_ls_ClusterRadius_Properties[0]),
};

// ls::CullComponent - 2 bytes (0x02)
// Source: COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_Cull_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT8, 0, true },
    { "Flags2", 0x01, FIELD_TYPE_UINT8, 0, true },
};
static const ComponentLayoutDef g_ls_Cull_Layout = {
    .componentName = "ls::CullComponent",
    .shortName = "Cull",
    .componentTypeIndex = 0,
    .componentSize = 0x02,
    .properties = g_ls_Cull_Properties,
    .propertyCount = sizeof(g_ls_Cull_Properties) / sizeof(g_ls_Cull_Properties[0]),
};

// ls::EffectCreateOneFrameComponent - 1 bytes (0x01)
// Source: COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_EffectCreateOneFrame_Properties[] = {};
static const ComponentLayoutDef g_ls_EffectCreateOneFrame_Layout = {
    .componentName = "ls::EffectCreateOneFrameComponent",
    .shortName = "EffectCreateOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_ls_EffectCreateOneFrame_Properties,
    .propertyCount = 0,
};

// ls::LevelInstanceComponent - 64 bytes (0x40)
// Source: Components.h, COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_LevelInstance_Properties[] = {
    { "LevelInstanceID", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "LevelName", 0x04, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "LevelInstanceTemplate", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "LevelType", 0x0c, FIELD_TYPE_UINT8, 0, true },
    { "Active", 0x0d, FIELD_TYPE_BOOL, 0, true },
    { "Platform", 0x0e, FIELD_TYPE_BOOL, 0, true },
    { "MovingPlatform", 0x0f, FIELD_TYPE_BOOL, 0, true },
    { "DynamicLayer", 0x10, FIELD_TYPE_BOOL, 0, true },
    { "NeedsPhysics", 0x11, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ls_LevelInstance_Layout = {
    .componentName = "ls::LevelInstanceComponent",
    .shortName = "LevelInstance",
    .componentTypeIndex = 0,
    .componentSize = 0x40,
    .properties = g_ls_LevelInstance_Properties,
    .propertyCount = sizeof(g_ls_LevelInstance_Properties) / sizeof(g_ls_LevelInstance_Properties[0]),
};

// ls::LevelInstanceLoadComponent - 1 bytes (0x01)
// Source: COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_LevelInstanceLoad_Properties[] = {};
static const ComponentLayoutDef g_ls_LevelInstanceLoad_Layout = {
    .componentName = "ls::LevelInstanceLoadComponent",
    .shortName = "LevelInstanceLoad",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_ls_LevelInstanceLoad_Properties,
    .propertyCount = 0,
};

// ls::LevelRootComponent - 4 bytes (0x04)
// Source: Components.h, COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_LevelRoot_Properties[] = {
    { "LevelName", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};
static const ComponentLayoutDef g_ls_LevelRoot_Layout = {
    .componentName = "ls::LevelRootComponent",
    .shortName = "LevelRoot",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_ls_LevelRoot_Properties,
    .propertyCount = sizeof(g_ls_LevelRoot_Properties) / sizeof(g_ls_LevelRoot_Properties[0]),
};

// ls::LevelUnloadedOneFrameComponent - 4 bytes (0x04)
// Source: Components.h, COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_LevelUnloadedOneFrame_Properties[] = {
    { "Level", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};
static const ComponentLayoutDef g_ls_LevelUnloadedOneFrame_Layout = {
    .componentName = "ls::LevelUnloadedOneFrameComponent",
    .shortName = "LevelUnloadedOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_ls_LevelUnloadedOneFrame_Properties,
    .propertyCount = sizeof(g_ls_LevelUnloadedOneFrame_Properties) / sizeof(g_ls_LevelUnloadedOneFrame_Properties[0]),
};

// ls::ParentEntityComponent - 8 bytes (0x8)
// Source: COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_ParentEntity_Properties[] = {
    { "Parent", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_ls_ParentEntity_Layout = {
    .componentName = "ls::ParentEntityComponent",
    .shortName = "ParentEntity",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_ls_ParentEntity_Properties,
    .propertyCount = sizeof(g_ls_ParentEntity_Properties) / sizeof(g_ls_ParentEntity_Properties[0]),
};

// ls::PhysicsComponent - 24 bytes (0x18)
// Source: Visual.h, COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_Physics_Properties[] = {
    { "Physics", 0x00, FIELD_TYPE_UINT64, 0, true },
    { "PhysicsGroup", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "CollidesWith", 0x0c, FIELD_TYPE_UINT32, 0, true },
    { "ExtraFlags", 0x10, FIELD_TYPE_UINT32, 0, true },
    { "HasPhysics", 0x14, FIELD_TYPE_BOOL, 0, true },
    { "field_15", 0x15, FIELD_TYPE_UINT8, 0, true },
    { "IsClustered", 0x16, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ls_Physics_Layout = {
    .componentName = "ls::PhysicsComponent",
    .shortName = "Physics",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_ls_Physics_Properties,
    .propertyCount = sizeof(g_ls_Physics_Properties) / sizeof(g_ls_Physics_Properties[0]),
};

// ls::PhysicsLoadedComponent - 1 bytes (0x01)
// Source: COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_PhysicsLoaded_Properties[] = {};
static const ComponentLayoutDef g_ls_PhysicsLoaded_Layout = {
    .componentName = "ls::PhysicsLoadedComponent",
    .shortName = "PhysicsLoaded",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_ls_PhysicsLoaded_Properties,
    .propertyCount = 0,
};

// ls::PhysicsStreamLoadComponent - 1 bytes (0x01)
// Source: COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_PhysicsStreamLoad_Properties[] = {};
static const ComponentLayoutDef g_ls_PhysicsStreamLoad_Layout = {
    .componentName = "ls::PhysicsStreamLoadComponent",
    .shortName = "PhysicsStreamLoad",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_ls_PhysicsStreamLoad_Properties,
    .propertyCount = 0,
};

// ls::RoomTriggerTagComponent - 1 bytes (0x01)
// Source: COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_RoomTriggerTag_Properties[] = {};
static const ComponentLayoutDef g_ls_RoomTriggerTag_Layout = {
    .componentName = "ls::RoomTriggerTagComponent",
    .shortName = "RoomTriggerTag",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_ls_RoomTriggerTag_Properties,
    .propertyCount = 0,
};

// ls::SaveWithComponent - 8 bytes (0x08)
// Source: COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_SaveWith_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_ls_SaveWith_Layout = {
    .componentName = "ls::SaveWithComponent",
    .shortName = "SaveWith",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_ls_SaveWith_Properties,
    .propertyCount = sizeof(g_ls_SaveWith_Properties) / sizeof(g_ls_SaveWith_Properties[0]),
};

// ls::SoundActivatedComponent - 1 bytes (0x1)
// Source: COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_SoundActivated_Properties[] = {};
static const ComponentLayoutDef g_ls_SoundActivated_Layout = {
    .componentName = "ls::SoundActivatedComponent",
    .shortName = "SoundActivated",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_ls_SoundActivated_Properties,
    .propertyCount = 0,
};

// ls::TimeFactorComponent - 4 bytes (0x04)
// Source: Components.h, COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_TimeFactor_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_FLOAT, 0, true },
};
static const ComponentLayoutDef g_ls_TimeFactor_Layout = {
    .componentName = "ls::TimeFactorComponent",
    .shortName = "TimeFactor",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_ls_TimeFactor_Properties,
    .propertyCount = sizeof(g_ls_TimeFactor_Properties) / sizeof(g_ls_TimeFactor_Properties[0]),
};

// ls::VisualChangedEventOneFrameComponent - 1 bytes (0x01)
// Source: COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_VisualChangedEventOneFrame_Properties[] = {};
static const ComponentLayoutDef g_ls_VisualChangedEventOneFrame_Layout = {
    .componentName = "ls::VisualChangedEventOneFrameComponent",
    .shortName = "VisualChangedEventOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_ls_VisualChangedEventOneFrame_Properties,
    .propertyCount = 0,
};

// ls::VisualComponent - 16 bytes (0x10)
// Source: Visual.h, COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_Visual_Properties[] = {
    { "Visual", 0x00, FIELD_TYPE_UINT64, 0, true },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, true },
    { "field_9", 0x09, FIELD_TYPE_UINT8, 0, true },
    { "NotClustered", 0x0a, FIELD_TYPE_BOOL, 0, true },
};
static const ComponentLayoutDef g_ls_Visual_Layout = {
    .componentName = "ls::VisualComponent",
    .shortName = "Visual",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ls_Visual_Properties,
    .propertyCount = sizeof(g_ls_Visual_Properties) / sizeof(g_ls_Visual_Properties[0]),
};

// ls::VisualStreamHintComponent - 4 bytes (0x04)
// Source: COMPONENT_SIZES_LS_CORE.md
static const ComponentPropertyDef g_ls_VisualStreamHint_Properties[] = {
    { "Hint", 0x00, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ls_VisualStreamHint_Layout = {
    .componentName = "ls::VisualStreamHintComponent",
    .shortName = "VisualStreamHint",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_ls_VisualStreamHint_Properties,
    .propertyCount = sizeof(g_ls_VisualStreamHint_Properties) / sizeof(g_ls_VisualStreamHint_Properties[0]),
};

// ls::animation::AnimationSetUpdateRequestComponent - 1 bytes (0x01)
// Source: Visual.h, COMPONENT_SIZES_LS_ANIMATION.md
static const ComponentPropertyDef g_ls_AnimationSetUpdateRequest_Properties[] = {};
static const ComponentLayoutDef g_ls_AnimationSetUpdateRequest_Layout = {
    .componentName = "ls::animation::AnimationSetUpdateRequestComponent",
    .shortName = "AnimationSetUpdateRequest",
    .componentTypeIndex = 0,
    .componentSize = 0x01,
    .properties = g_ls_AnimationSetUpdateRequest_Properties,
    .propertyCount = 0,
};

// ls::animation::DynamicAnimationTagsComponent - 16 bytes (0x10)
// Source: Visual.h, COMPONENT_SIZES_LS_ANIMATION.md
static const ComponentPropertyDef g_ls_DynamicAnimationTags_Properties[] = {
    { "Tags", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_ls_DynamicAnimationTags_Layout = {
    .componentName = "ls::animation::DynamicAnimationTagsComponent",
    .shortName = "DynamicAnimationTags",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ls_DynamicAnimationTags_Properties,
    .propertyCount = sizeof(g_ls_DynamicAnimationTags_Properties) / sizeof(g_ls_DynamicAnimationTags_Properties[0]),
};

// ls::animation::LoadAnimationSetGameplayRequestOneFrameComponent - 16 bytes (0x10)
// Source: Visual.h, COMPONENT_SIZES_LS_ANIMATION.md
static const ComponentPropertyDef g_ls_LoadAnimationSetGameplayRequestOneFrame_Properties[] = {
    { "Animations", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_ls_LoadAnimationSetGameplayRequestOneFrame_Layout = {
    .componentName = "ls::animation::LoadAnimationSetGameplayRequestOneFrameComponent",
    .shortName = "LoadAnimationSetGameplayRequestOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ls_LoadAnimationSetGameplayRequestOneFrame_Properties,
    .propertyCount = sizeof(g_ls_LoadAnimationSetGameplayRequestOneFrame_Properties) / sizeof(g_ls_LoadAnimationSetGameplayRequestOneFrame_Properties[0]),
};

// ls::animation::RemoveAnimationSetsGameplayRequestOneFrameComponent - 48 bytes (0x30)
// Source: Visual.h, COMPONENT_SIZES_LS_ANIMATION.md
static const ComponentPropertyDef g_ls_RemoveAnimationSetsGameplayRequestOneFrame_Properties[] = {
    { "AnimationSets", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_ls_RemoveAnimationSetsGameplayRequestOneFrame_Layout = {
    .componentName = "ls::animation::RemoveAnimationSetsGameplayRequestOneFrameComponent",
    .shortName = "RemoveAnimationSetsGameplayRequestOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_ls_RemoveAnimationSetsGameplayRequestOneFrame_Properties,
    .propertyCount = sizeof(g_ls_RemoveAnimationSetsGameplayRequestOneFrame_Properties) / sizeof(g_ls_RemoveAnimationSetsGameplayRequestOneFrame_Properties[0]),
};

// ls::animation::TemplateAnimationSetOverrideComponent - 16 bytes (0x10)
// Source: Visual.h, COMPONENT_SIZES_LS_ANIMATION.md
static const ComponentPropertyDef g_ls_TemplateAnimationSetOverride_Properties[] = {
    { "Overrides", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_ls_TemplateAnimationSetOverride_Layout = {
    .componentName = "ls::animation::TemplateAnimationSetOverrideComponent",
    .shortName = "TemplateAnimationSetOverride",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ls_TemplateAnimationSetOverride_Properties,
    .propertyCount = sizeof(g_ls_TemplateAnimationSetOverride_Properties) / sizeof(g_ls_TemplateAnimationSetOverride_Properties[0]),
};

// ls::anubis::LoadRequestOneFrameComponent - 8 bytes (0x8)
// Source: COMPONENT_SIZES_LS_MISC.md
static const ComponentPropertyDef g_ls_LoadRequestOneFrame_Properties[] = {
    { "Request", 0x00, FIELD_TYPE_UINT64, 0, true },
};
static const ComponentLayoutDef g_ls_LoadRequestOneFrame_Layout = {
    .componentName = "ls::anubis::LoadRequestOneFrameComponent",
    .shortName = "LoadRequestOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_ls_LoadRequestOneFrame_Properties,
    .propertyCount = sizeof(g_ls_LoadRequestOneFrame_Properties) / sizeof(g_ls_LoadRequestOneFrame_Properties[0]),
};

// ls::level::LevelInstanceTempDestroyedComponent - 8 bytes (0x8)
// Source: Components.h, COMPONENT_SIZES_LS_MISC.md
static const ComponentPropertyDef g_ls_LevelInstanceTempDestroyed_Properties[] = {
    { "Level", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};
static const ComponentLayoutDef g_ls_LevelInstanceTempDestroyed_Layout = {
    .componentName = "ls::level::LevelInstanceTempDestroyedComponent",
    .shortName = "LevelInstanceTempDestroyed",
    .componentTypeIndex = 0,
    .componentSize = 0x08,
    .properties = g_ls_LevelInstanceTempDestroyed_Properties,
    .propertyCount = sizeof(g_ls_LevelInstanceTempDestroyed_Properties) / sizeof(g_ls_LevelInstanceTempDestroyed_Properties[0]),
};

// ls::scene::SceneStageComponent - 4 bytes (0x04)
// Source: COMPONENT_SIZES_LS_MISC.md
static const ComponentPropertyDef g_ls_SceneStage_Properties[] = {
    { "Stage", 0x00, FIELD_TYPE_UINT32, 0, true },
};
static const ComponentLayoutDef g_ls_SceneStage_Layout = {
    .componentName = "ls::scene::SceneStageComponent",
    .shortName = "SceneStage",
    .componentTypeIndex = 0,
    .componentSize = 0x04,
    .properties = g_ls_SceneStage_Properties,
    .propertyCount = sizeof(g_ls_SceneStage_Properties) / sizeof(g_ls_SceneStage_Properties[0]),
};

// ls::trigger::IsInsideOfComponent - 16 bytes (0x10)
// Source: COMPONENT_SIZES_LS_MISC.md
static const ComponentPropertyDef g_ls_IsInsideOf_Properties[] = {
    { "Triggers", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_ls_IsInsideOf_Layout = {
    .componentName = "ls::trigger::IsInsideOfComponent",
    .shortName = "IsInsideOf",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ls_IsInsideOf_Properties,
    .propertyCount = sizeof(g_ls_IsInsideOf_Properties) / sizeof(g_ls_IsInsideOf_Properties[0]),
};

// ls::uuid::Component - 16 bytes (0x10)
// Source: Components.h, COMPONENT_SIZES_LS_MISC.md
static const ComponentPropertyDef g_ls_Uuid_Properties[] = {
    { "EntityUuid", 0x00, FIELD_TYPE_GUID, 0, true },
};
static const ComponentLayoutDef g_ls_Uuid_Layout = {
    .componentName = "ls::uuid::Component",
    .shortName = "Uuid",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_ls_Uuid_Properties,
    .propertyCount = sizeof(g_ls_Uuid_Properties) / sizeof(g_ls_Uuid_Properties[0]),
};

// ls::uuid::ToHandleMappingComponent - 64 bytes (0x40)
// Source: Components.h, COMPONENT_SIZES_LS_MISC.md
static const ComponentPropertyDef g_ls_UuidToHandleMapping_Properties[] = {
    { "Mappings", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true },
};
static const ComponentLayoutDef g_ls_UuidToHandleMapping_Layout = {
    .componentName = "ls::uuid::ToHandleMappingComponent",
    .shortName = "UuidToHandleMapping",
    .componentTypeIndex = 0,
    .componentSize = 0x40,
    .properties = g_ls_UuidToHandleMapping_Properties,
    .propertyCount = sizeof(g_ls_UuidToHandleMapping_Properties) / sizeof(g_ls_UuidToHandleMapping_Properties[0]),
};

// ============================================================================
// Layouts measured on the ARM64 binary (4.1.1.7209685) and read live on
// 4.1.1.7398727. Sizes come from AddComponent<T> / CreateProgressionEntity
// AllocRaw; array element sizes from the code that fills them.
// ============================================================================

// eoc::encumbrance::StatsComponent - 0x0C (AddComponent AllocRaw 0xc).
static const ComponentPropertyDef g_EncumbranceStatsComponent_Properties[] = {
    { "UnencumberedWeight",      0x00, FIELD_TYPE_INT32, 0, true },
    { "EncumberedWeight",        0x04, FIELD_TYPE_INT32, 0, true },
    { "HeavilyEncumberedWeight", 0x08, FIELD_TYPE_INT32, 0, true },
};
static const ComponentLayoutDef g_EncumbranceStatsComponent_Layout = {
    .componentName = "eoc::encumbrance::StatsComponent", .shortName = "EncumbranceStats",
    .componentTypeIndex = 0, .componentSize = 0x0c,
    .properties = g_EncumbranceStatsComponent_Properties,
    .propertyCount = sizeof(g_EncumbranceStatsComponent_Properties) / sizeof(g_EncumbranceStatsComponent_Properties[0]),
};

// eoc::WeaponSetComponent - 0x01.
static const ComponentPropertyDef g_eoc_WeaponSetComponent_Properties[] = {
    { "WeaponSet", 0x00, FIELD_TYPE_UINT8, 0, true },
};
static const ComponentLayoutDef g_eoc_WeaponSetComponent_Layout = {
    .componentName = "eoc::WeaponSetComponent", .shortName = "WeaponSet",
    .componentTypeIndex = 0, .componentSize = 0x01,
    .properties = g_eoc_WeaponSetComponent_Properties,
    .propertyCount = sizeof(g_eoc_WeaponSetComponent_Properties) / sizeof(g_eoc_WeaponSetComponent_Properties[0]),
};

// eoc::stats::proficiency::ProficiencyComponent - 0x08; one 64-bit flag word.
static const ComponentPropertyDef g_eoc_proficiency_ProficiencyComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT64, 0, true },
};
static const ComponentLayoutDef g_eoc_proficiency_ProficiencyComponent_Layout = {
    .componentName = "eoc::stats::proficiency::ProficiencyComponent", .shortName = "Proficiency",
    .componentTypeIndex = 0, .componentSize = 0x08,
    .properties = g_eoc_proficiency_ProficiencyComponent_Properties,
    .propertyCount = sizeof(g_eoc_proficiency_ProficiencyComponent_Properties) / sizeof(g_eoc_proficiency_ProficiencyComponent_Properties[0]),
};

// eoc::progression::PassivesComponent - 0x20: Array<FixedString> x2.
static const ComponentPropertyDef g_eoc_progression_PassivesComponent_Properties[] = {
    { "AddPassives",    0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true, ELEM_TYPE_FIXED_STRING, 4 },
    { "RemovePassives", 0x10, FIELD_TYPE_DYNAMIC_ARRAY, 0, true, ELEM_TYPE_FIXED_STRING, 4 },
};
static const ComponentLayoutDef g_eoc_progression_PassivesComponent_Layout = {
    .componentName = "eoc::progression::PassivesComponent", .shortName = "ProgressionPassives",
    .componentTypeIndex = 0, .componentSize = 0x20,
    .properties = g_eoc_progression_PassivesComponent_Properties,
    .propertyCount = sizeof(g_eoc_progression_PassivesComponent_Properties) / sizeof(g_eoc_progression_PassivesComponent_Properties[0]),
};

// eoc::progression::SkillsComponent - 0x20: Array<ESkill> x2 (1-byte elements:
// CreateProgressionEntity's staging loops write one byte per element).
static const ComponentPropertyDef g_eoc_progression_SkillsComponent_Properties[] = {
    { "Proficiencies", 0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true, ELEM_TYPE_UNKNOWN, 1 },
    { "Expertise",     0x10, FIELD_TYPE_DYNAMIC_ARRAY, 0, true, ELEM_TYPE_UNKNOWN, 1 },
};
static const ComponentLayoutDef g_eoc_progression_SkillsComponent_Layout = {
    .componentName = "eoc::progression::SkillsComponent", .shortName = "ProgressionSkills",
    .componentTypeIndex = 0, .componentSize = 0x20,
    .properties = g_eoc_progression_SkillsComponent_Properties,
    .propertyCount = sizeof(g_eoc_progression_SkillsComponent_Properties) / sizeof(g_eoc_progression_SkillsComponent_Properties[0]),
};

// eoc::progression::AbilityImprovementsComponent - 0x30 (the Windows 24 is
// wrong here): Array<EAbility> at 0x00, int32[7] at 0x10.
static const ComponentPropertyDef g_eoc_progression_AbilityImprovementsComponent_Properties[] = {
    { "Abilities",           0x00, FIELD_TYPE_DYNAMIC_ARRAY, 0, true, ELEM_TYPE_UNKNOWN, 1 },
    { "AbilityImprovements", 0x10, FIELD_TYPE_INT32_ARRAY,   7, true },
};
static const ComponentLayoutDef g_eoc_progression_AbilityImprovementsComponent_Layout = {
    .componentName = "eoc::progression::AbilityImprovementsComponent", .shortName = "AbilityImprovements",
    .componentTypeIndex = 0, .componentSize = 0x30,
    .properties = g_eoc_progression_AbilityImprovementsComponent_Properties,
    .propertyCount = sizeof(g_eoc_progression_AbilityImprovementsComponent_Properties) / sizeof(g_eoc_progression_AbilityImprovementsComponent_Properties[0]),
};

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
    // Ghidra-verified boost type components (Dec 2025)
    &g_AbilityBoostComponent_Layout,
    &g_ArmorClassBoostComponent_Layout,
    &g_AdvantageBoostComponent_Layout,
    &g_AddTagBoostComponent_Layout,
    &g_AttributeBoostComponent_Layout,
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
    // Ghidra-verified client components (Dec 2025)
    &g_ClientEquipmentVisualsComponent_Layout,
    &g_ClientCharacterComponent_Layout,
    &g_ClientItemComponent_Layout,
    &g_ClientProjectileComponent_Layout,
    &g_ClientSceneryComponent_Layout,
    &g_ClientPaperdollComponent_Layout,
    // === AUTO-GENERATED LAYOUTS (365 new components) ===
&g_eoc_ACOverrideFormulaBoostComponent_Layout,
    &g_eoc_AbilityFailedSavingThrowBoostComponent_Layout,
    &g_eoc_AbilityOverrideMinimumBoostComponent_Layout,
    &g_eoc_ActionResourceBlockBoostComponent_Layout,
    &g_eoc_ActionResourceConsumeMultiplierBoostComponent_Layout,
    &g_eoc_ActionResourceMultiplierBoostComponent_Layout,
    &g_eoc_ActionResourcePreventReductionBoostComponent_Layout,
    &g_eoc_ActionResourceReplenishTypeOverrideBoostComponent_Layout,
    &g_eoc_ActionResourceValueBoostComponent_Layout,
    &g_eoc_ActiveCharacterLightBoostComponent_Layout,
    &g_eoc_AiArchetypeOverrideBoostComponent_Layout,
    &g_eoc_ArmorAbilityModifierCapOverrideBoostComponent_Layout,
    &g_eoc_AttackSpellOverrideBoostComponent_Layout,
    &g_eoc_AttributeFlagsComponent_Layout,
    &g_eoc_BodyTypeComponent_Layout,
    &g_eoc_BoostConditionComponent_Layout,
    &g_eoc_BoostInfoComponent_Layout,
    &g_eoc_CanBeDisarmedComponent_Layout,
    &g_eoc_CanBeLootedComponent_Layout,
    &g_eoc_CanDeflectProjectilesComponent_Layout,
    &g_eoc_CanModifyHealthComponent_Layout,
    &g_eoc_CanMoveComponent_Layout,
    &g_eoc_CanSeeThroughBoostComponent_Layout,
    &g_eoc_CanSenseComponent_Layout,
    &g_eoc_CanShootThroughBoostComponent_Layout,
    &g_eoc_CanTravelComponent_Layout,
    &g_eoc_CanWalkThroughBoostComponent_Layout,
    &g_eoc_CannotHarmCauseEntityBoostComponent_Layout,
    &g_eoc_CarryCapacityMultiplierBoostComponent_Layout,
    &g_eoc_CharacterCreationStatsComponent_Layout,
    &g_eoc_CharacterUnarmedDamageBoostComponent_Layout,
    &g_eoc_CharacterWeaponDamageBoostComponent_Layout,
    &g_eoc_ConcentrationIgnoreDamageBoostComponent_Layout,
    &g_eoc_CriticalHitBoostComponent_Layout,
    &g_eoc_CriticalHitExtraDiceBoostComponent_Layout,
    &g_eoc_DamageBonusBoostComponent_Layout,
    &g_eoc_DamageReductionBoostComponent_Layout,
    &g_eoc_DamageTakenBonusBoostComponent_Layout,
    &g_eoc_DarknessComponent_Layout,
    &g_eoc_DarkvisionRangeBoostComponent_Layout,
    &g_eoc_DarkvisionRangeMinBoostComponent_Layout,
    &g_eoc_DarkvisionRangeOverrideBoostComponent_Layout,
    &g_eoc_DetachedComponent_Layout,
    &g_eoc_DifficultyCheckComponent_Layout,
    &g_eoc_DisabledEquipmentComponent_Layout,
    &g_eoc_DisarmableComponent_Layout,
    &g_eoc_DodgeAttackRollBoostComponent_Layout,
    &g_eoc_DownedStatusBoostComponent_Layout,
    &g_eoc_DualWieldingBoostComponent_Layout,
    &g_eoc_DualWieldingComponent_Layout,
    &g_eoc_EntityThrowDamageBoostComponent_Layout,
    &g_eoc_ExpertiseBonusBoostComponent_Layout,
    &g_eoc_FactionOverrideBoostComponent_Layout,
    &g_eoc_FallDamageMultiplierBoostComponent_Layout,
    &g_eoc_GameplayLightBoostComponent_Layout,
    &g_eoc_GuaranteedChanceRollOutcomeBoostComponent_Layout,
    &g_eoc_HalveWeaponDamageBoostComponent_Layout,
    &g_eoc_HearingComponent_Layout,
    &g_eoc_HorizontalFOVOverrideBoostComponent_Layout,
    &g_eoc_IgnoreDamageThresholdMinBoostComponent_Layout,
    &g_eoc_IgnorePointBlankDisadvantageBoostComponent_Layout,
    &g_eoc_IgnoreResistanceBoostComponent_Layout,
    &g_eoc_IncreaseMaxHPBoostComponent_Layout,
    &g_eoc_InitiativeBoostComponent_Layout,
    &g_eoc_InvisibilityComponent_Layout,
    &g_eoc_JumpMaxDistanceBonusBoostComponent_Layout,
    &g_eoc_JumpMaxDistanceMultiplierBoostComponent_Layout,
    &g_eoc_LockBoostComponent_Layout,
    &g_eoc_LootComponent_Layout,
    &g_eoc_LootingStateComponent_Layout,
    &g_eoc_MaximumRollResultBoostComponent_Layout,
    &g_eoc_MinimumRollResultBoostComponent_Layout,
    &g_eoc_MonkWeaponDamageDiceOverrideBoostComponent_Layout,
    &g_eoc_MovementSpeedLimitBoostComponent_Layout,
    &g_eoc_NullifyAbilityBoostComponent_Layout,
    &g_eoc_ObjectInteractionComponent_Layout,
    &g_eoc_ObjectSizeBoostComponent_Layout,
    &g_eoc_ObjectSizeOverrideBoostComponent_Layout,
    &g_eoc_PhysicalForceRangeBonusBoostComponent_Layout,
    &g_eoc_RedirectDamageBoostComponent_Layout,
    &g_eoc_ReduceCriticalAttackThresholdBoostComponent_Layout,
    &g_eoc_ResistanceBoostComponent_Layout,
    &g_eoc_RollBonusBoostComponent_Layout,
    &g_eoc_ScaleMultiplierBoostComponent_Layout,
    &g_eoc_SightRangeAdditiveBoostComponent_Layout,
    &g_eoc_SightRangeMaximumBoostComponent_Layout,
    &g_eoc_SightRangeMinimumBoostComponent_Layout,
    &g_eoc_SightRangeOverrideBoostComponent_Layout,
    &g_eoc_SkillBoostComponent_Layout,
    &g_eoc_SourceAdvantageBoostComponent_Layout,
    &g_eoc_SpellResistanceBoostComponent_Layout,
    &g_eoc_SpellSaveDCBoostComponent_Layout,
    &g_eoc_StatusImmunityBoostComponent_Layout,
    &g_eoc_StealthComponent_Layout,
    &g_eoc_TurnOrderComponent_Layout,
    &g_eoc_UnlockInterruptBoostComponent_Layout,
    &g_eoc_UseBoostsComponent_Layout,
    &g_eoc_UseComponent_Layout,
    &g_eoc_VoiceComponent_Layout,
    &g_eoc_VoiceTagComponent_Layout,
    &g_eoc_WeaponAttackRollAbilityOverrideBoostComponent_Layout,
    &g_eoc_WeaponAttackTypeOverrideBoostComponent_Layout,
    &g_eoc_WeaponDamageBoostComponent_Layout,
    &g_eoc_WeaponDamageResistanceBoostComponent_Layout,
    &g_eoc_WeaponDamageTypeOverrideBoostComponent_Layout,
    &g_eoc_WeaponEnchantmentBoostComponent_Layout,
    &g_eoc_WeaponPropertyBoostComponent_Layout,
    &g_eoc_WeightBoostComponent_Layout,
    &g_eoc_WeightCategoryBoostComponent_Layout,
    &g_eoc_ActionUseConditionsComponent_Layout,
    &g_eoc_RatingsComponent_Layout,
    &g_eoc_GoalsComponent_Layout,
    &g_eoc_DaysPassedComponent_Layout,
    &g_eoc_StartingDateComponent_Layout,
    &g_eoc_LevelUpComponent_Layout,
    &g_eoc_SessionCommonComponent_Layout,
    &g_eoc_StateComponent_Layout,
    &g_eoc_IsThreatenedComponent_Layout,
    &g_eoc_EncumbranceStateComponent_Layout,
    &g_eoc_ParticipantComponent_Layout,
    &g_eoc_ZoneBlockReasonComponent_Layout,
    &g_eoc_TagComponent_Layout,
    &g_eoc_ContainerComponent_Layout,
    &g_eoc_WieldedComponent_Layout,
    &g_eoc_WieldingComponent_Layout,
    &g_eoc_StackMemberComponent_Layout,
    &g_eoc_TopOwnerComponent_Layout,
    &g_eoc_TradeBuybackDataComponent_Layout,
    &g_eoc_DyeComponent_Layout,
    &g_eoc_MapMarkerStyleComponent_Layout,
    &g_eoc_PortalComponent_Layout,
    &g_eoc_KeyComponent_Layout,
    &g_eoc_LockComponent_Layout,
    &g_eoc_PickUpRequestComponent_Layout,
    &g_eoc_AddedSpellsComponent_Layout,
    &g_eoc_BookCooldownsComponent_Layout,
    &g_eoc_CCPrepareSpellComponent_Layout,
    &g_eoc_PlayerPrepareSpellComponent_Layout,
    &g_eoc_ScriptedExplosionComponent_Layout,
    &g_eoc_CauseComponent_Layout,
    &g_eoc_IDComponent_Layout,
    &g_eoc_IncapacitatedComponent_Layout,
    &g_eoc_LifetimeComponent_Layout,
    &g_eoc_LoseControlComponent_Layout,
    &g_eoc_IsSummonComponent_Layout,
    &g_esv_AIHintAreaTrigger_Layout,
    &g_esv_ActivationGroupContainerComponent_Layout,
    &g_esv_ActiveCharacterLightComponent_Layout,
    &g_esv_ActiveMusicVolumeComponent_Layout,
    &g_esv_AiGridAreaTrigger_Layout,
    &g_esv_ArmorClassComponent_Layout,
    &g_esv_AtmosphereTrigger_Layout,
    &g_esv_AvailableLevelComponent_Layout,
    &g_esv_BaseDataComponent_Layout,
    &g_esv_BaseHpComponent_Layout,
    &g_esv_BaseSizeComponent_Layout,
    &g_esv_BaseStatsComponent_Layout,
    &g_esv_BaseWeaponComponent_Layout,
    &g_esv_BlockBronzeTimelinePlacementTrigger_Layout,
    &g_esv_CampChestTrigger_Layout,
    &g_esv_CampRegionTrigger_Layout,
    &g_esv_Character_Layout,
    &g_esv_CharacterComponent_Layout,
    &g_esv_ChasmDataComponent_Layout,
    &g_esv_ChasmSeederTrigger_Layout,
    &g_esv_CombatComponent_Layout,
    &g_esv_CombatGroupMappingComponent_Layout,
    &g_esv_CombatParticipantComponent_Layout,
    &g_esv_ConstellationChildComponent_Layout,
    &g_esv_ConstellationHelperComponent_Layout,
    &g_esv_CrimeAreaTrigger_Layout,
    &g_esv_CustomStatsComponent_Layout,
    &g_esv_DisplayNameListComponent_Layout,
    &g_esv_Effect_Layout,
    &g_esv_EocLevelComponent_Layout,
    &g_esv_ExperienceComponent_Layout,
    &g_esv_ExperienceGaveOutComponent_Layout,
    &g_esv_ExplorationAwardStateComponent_Layout,
    &g_esv_FollowersComponent_Layout,
    &g_esv_GameTimerComponent_Layout,
    &g_esv_GravityActiveTimeoutComponent_Layout,
    &g_esv_GravityInstigatorComponent_Layout,
    &g_esv_HealthComponent_Layout,
    &g_esv_IconListComponent_Layout,
    &g_esv_IdentifiedComponent_Layout,
    &g_esv_InterruptDataComponent_Layout,
    &g_esv_InterruptPreferencesComponent_Layout,
    &g_esv_InterruptZoneParticipantComponent_Layout,
    &g_esv_InventoryDataComponent_Layout,
    &g_esv_InventoryMemberComponent_Layout,
    &g_esv_InventoryOwnerComponent_Layout,
    &g_esv_InventoryPropertyCanBePickpocketedComponent_Layout,
    &g_esv_InventoryPropertyIsDroppedOnDeathComponent_Layout,
    &g_esv_InventoryPropertyIsTradableComponent_Layout,
    &g_esv_IsGlobalComponent_Layout,
    &g_esv_Item_Layout,
    &g_esv_ItemComponent_Layout,
    &g_esv_LevelComponent_Layout,
    &g_esv_LockComponent_Layout,
    &g_esv_MusicVolumeTriggerStateComponent_Layout,
    &g_esv_OriginalTemplateComponent_Layout,
    &g_esv_OsirisPingRequestSingletonComponent_Layout,
    &g_esv_PartyMemberComponent_Layout,
    &g_esv_PingRequestSingletonComponent_Layout,
    &g_esv_PlayerComponent_Layout,
    &g_esv_Projectile_Layout,
    &g_esv_RecruitedByComponent_Layout,
    &g_esv_ReplicationDependencyComponent_Layout,
    &g_esv_SafePositionComponent_Layout,
    &g_esv_SafePositionUpdatedEventOneFrameComponent_Layout,
    &g_esv_SaveCompletedOneFrameComponent_Layout,
    &g_esv_SaveWorldPrepareEventComponent_Layout,
    &g_esv_ServerDisplayNameListComponent_Layout,
    &g_esv_ServerReplicationDependencyOwnerComponent_Layout,
    &g_esv_SetGravityActiveRequestOneFrameComponent_Layout,
    &g_esv_StartTrigger_Layout,
    &g_esv_StatesComponent_Layout,
    &g_esv_StatusContainerComponent_Layout,
    &g_esv_StealthComponent_Layout,
    &g_esv_SummonContainerComponent_Layout,
    &g_esv_SurfacePathInfluencesComponent_Layout,
    &g_esv_TurnStartedEventOneFrameComponent_Layout,
    &g_esv_UseComponent_Layout,
    &g_esv_UseSocketComponent_Layout,
    &g_esv_UserReservedComponent_Layout,
    &g_esv_ai_AiComponent_Layout,
    &g_esv_combat_CombatStateComponent_Layout,
    &g_esv_combat_CombatSwitchedComponent_Layout,
    &g_esv_combat_EnterRequestComponent_Layout,
    &g_esv_combat_IsInCombatComponent_Layout,
    &g_esv_combat_JoiningComponent_Layout,
    &g_esv_combat_LateJoinPenaltyComponent_Layout,
    &g_esv_combat_LeftEventOneFrameComponent_Layout,
    &g_esv_inventory_ContainerDataComponent_Layout,
    &g_esv_inventory_GroupCheckComponent_Layout,
    &g_esv_inventory_IsReplicatedComponent_Layout,
    &g_esv_inventory_MemberIsReplicatedWithComponent_Layout,
    &g_esv_inventory_MemberRemovedEventOneFrameComponent_Layout,
    &g_esv_inventory_ReturnToOwnerComponent_Layout,
    &g_esv_inventory_ShapeshiftAddedEquipmentComponent_Layout,
    &g_esv_inventory_ShapeshiftEquipmentHistoryComponent_Layout,
    &g_esv_inventory_ShapeshiftUnequippedEquipmentComponent_Layout,
    &g_esv_inventory_StackBlockedDuringTradeComponent_Layout,
    &g_esv_item_DestroyingEventOneFrameComponent_Layout,
    &g_esv_item_DestroyingWaitingForDeactivationComponent_Layout,
    &g_esv_item_DestroyingWaitingForEffectComponent_Layout,
    &g_esv_item_DynamicLayerOwnerComponent_Layout,
    &g_esv_item_EntityMovingComponent_Layout,
    &g_esv_item_MarkEntityForDestructionComponent_Layout,
    &g_esv_item_TransformedOnDestroyEventOneFrameComponent_Layout,
    &g_esv_status_LifeTimeComponent_Layout,
    &g_esv_status_OwnershipComponent_Layout,
    &g_esv_status_PerformingComponent_Layout,
    &g_esv_status_StatusComponent_Layout,
    &g_esv_status_StatusIDComponent_Layout,
    &g_ecl_ActiveTurnComponent_Layout,
    &g_ecl_CharacterIconResultComponent_Layout,
    &g_ecl_CharacterLightComponent_Layout,
    &g_ecl_ClientTimelineActorControlComponent_Layout,
    &g_ecl_DeathEffectComponent_Layout,
    &g_ecl_DetachedComponent_Layout,
    &g_ecl_DifficultyCheckComponent_Layout,
    &g_ecl_DisabledEquipmentComponent_Layout,
    &g_ecl_DisarmableComponent_Layout,
    &g_ecl_DisplayNameComponent_Layout,
    &g_ecl_EocCameraBehavior_Layout,
    &g_ecl_GroundMaterialComponent_Layout,
    &g_ecl_IgnoredComponent_Layout,
    &g_ecl_InSelectComponent_Layout,
    &g_ecl_InvisibilityAttachmentComponent_Layout,
    &g_ecl_InvisibilityFadingComponent_Layout,
    &g_ecl_InvisibilityVisualComponent_Layout,
    &g_ecl_IsHoveredOverComponent_Layout,
    &g_ecl_MeshPreviewComponent_Layout,
    &g_ecl_MovementComponent_Layout,
    &g_ecl_ObjectInteractionComponent_Layout,
    &g_ecl_PathingComponent_Layout,
    &g_ecl_PickingStateComponent_Layout,
    &g_ecl_PlayerComponent_Layout,
    &g_ecl_PointSoundTriggerDummy_Layout,
    &g_ecl_PointTrigger_Layout,
    &g_ecl_PortalTrigger_Layout,
    &g_ecl_RegionTrigger_Layout,
    &g_ecl_RoomTrigger_Layout,
    &g_ecl_SelectedComponent_Layout,
    &g_ecl_SoundAttachmentComponent_Layout,
    &g_ecl_SoundVolumeTrigger_Layout,
    &g_ecl_SpectatorTrigger_Layout,
    &g_ecl_TerrainWalkableAreaComponent_Layout,
    &g_ecl_TimelineAnimationStateComponent_Layout,
    &g_ecl_TimelineAutomatedLookatComponent_Layout,
    &g_ecl_TimelineCameraRequestComponent_Layout,
    &g_ecl_TimelineCameraShotComponent_Layout,
    &g_ecl_TimelineEyeLookAtOverrideComponent_Layout,
    &g_ecl_TimelinePlayerTransitionEventOneFrameComponent_Layout,
    &g_ecl_TimelineQuestionHoldAutomationComponent_Layout,
    &g_ecl_TimelineSceneTrigger_Layout,
    &g_ecl_TimelineSplatterComponent_Layout,
    &g_ecl_TimelineSpringsComponent_Layout,
    &g_ecl_TimelineSteppingFadeComponent_Layout,
    &g_ecl_TurnActionsDoneOneFrameComponent_Layout,
    &g_ecl_TurnBasedComponent_Layout,
    &g_ecl_UseComponent_Layout,
    &g_ecl_VoiceComponent_Layout,
    &g_ecl_WalkableSurfaceComponent_Layout,
    &g_ecl_WeaponComponent_Layout,
    &g_ecl_camera_CombatTargetComponent_Layout,
    &g_ecl_camera_CombatTargetRequestsComponent_Layout,
    &g_ecl_crowds_SoundVolumeComponent_Layout,
    &g_ecl_death_DeathImpactComponent_Layout,
    &g_ecl_death_StateComponent_Layout,
    &g_ecl_effect_HandlerComponent_Layout,
    &g_ecl_effect_InfluenceTrackerComponent_Layout,
    &g_ecl_effect_InteractionEventOneFrameComponent_Layout,
    &g_ecl_effect_SharedTimerComponent_Layout,
    &g_ecl_effect_SpawnedComponent_Layout,
    &g_ecl_multiplayer_UsersComponent_Layout,
    &g_ecl_projectile_AttachmentComponent_Layout,
    &g_ecl_relation_RelationChangedEventOneFrameComponent_Layout,
    &g_ecl_sound_CharacterSwitchDataComponent_Layout,
    &g_ecl_sound_DecoratorSwitchDataComponent_Layout,
    &g_ecl_sound_ItemSwitchDataComponent_Layout,
    &g_ecl_sound_SoundCacheComponent_Layout,
    &g_ecl_spell_cast_PlaySoundRequestOneFrameComponent_Layout,
    &g_ecl_spell_cast_SetSoundSwitchesRequestOneFrameComponent_Layout,
    &g_ecl_spell_cast_SoundImpactEventOneFrameComponent_Layout,
    &g_ls_AnimationBlueprint_Layout,
    &g_ls_AnimationSet_Layout,
    &g_ls_ClusterAttachRequest_Layout,
    &g_ls_ClusterBoundMax_Layout,
    &g_ls_Cluster_Layout,
    &g_ls_ClusterDistMax_Layout,
    &g_ls_ClusterDistMin_Layout,
    &g_ls_ClusterPositionX_Layout,
    &g_ls_ClusterPositionY_Layout,
    &g_ls_ClusterPositionZ_Layout,
    &g_ls_ClusterRadius_Layout,
    &g_ls_Cull_Layout,
    &g_ls_EffectCreateOneFrame_Layout,
    &g_ls_LevelInstance_Layout,
    &g_ls_LevelInstanceLoad_Layout,
    &g_ls_LevelRoot_Layout,
    &g_ls_LevelUnloadedOneFrame_Layout,
    &g_ls_ParentEntity_Layout,
    &g_ls_Physics_Layout,
    &g_ls_PhysicsLoaded_Layout,
    &g_ls_PhysicsStreamLoad_Layout,
    &g_ls_RoomTriggerTag_Layout,
    &g_ls_SaveWith_Layout,
    &g_ls_SoundActivated_Layout,
    &g_ls_TimeFactor_Layout,
    &g_ls_VisualChangedEventOneFrame_Layout,
    &g_ls_Visual_Layout,
    &g_ls_VisualStreamHint_Layout,
    &g_ls_AnimationSetUpdateRequest_Layout,
    &g_ls_DynamicAnimationTags_Layout,
    &g_ls_LoadAnimationSetGameplayRequestOneFrame_Layout,
    &g_ls_RemoveAnimationSetsGameplayRequestOneFrame_Layout,
    &g_ls_TemplateAnimationSetOverride_Layout,
    &g_ls_LoadRequestOneFrame_Layout,
    &g_ls_LevelInstanceTempDestroyed_Layout,
    &g_ls_SceneStage_Layout,
    &g_ls_IsInsideOf_Layout,
    &g_ls_Uuid_Layout,
    &g_ls_UuidToHandleMapping_Layout,
    &g_EncumbranceStatsComponent_Layout,
    &g_eoc_WeaponSetComponent_Layout,
    &g_eoc_proficiency_ProficiencyComponent_Layout,
    &g_eoc_progression_PassivesComponent_Layout,
    &g_eoc_progression_SkillsComponent_Layout,
    &g_eoc_progression_AbilityImprovementsComponent_Layout,
    NULL  // Sentinel
};

#endif // COMPONENT_OFFSETS_H
