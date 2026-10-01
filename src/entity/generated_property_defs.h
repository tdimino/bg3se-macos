/**
 * generated_property_defs.h - Auto-generated component property definitions
 *
 * Generated from Windows BG3SE headers by tools/generate_layouts.py
 * Total components: 519
 * ARM64 verified (Ghidra): 543
 *
 * SIZES: Ghidra-verified ARM64 sizes used where available,
 * otherwise Windows x64 estimates (may differ on ARM64).
 */

#ifndef GENERATED_PROPERTY_DEFS_H
#define GENERATED_PROPERTY_DEFS_H

#include "component_property.h"

// ======================================================================
// ecl::CharacterIconRequestComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1b0 (432 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_CharacterIconRequestComponent_Properties[] = {
    { "Visual", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Template", 0x04, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "field_190", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "field_1B0", 0x10, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_CharacterIconRequestComponent_Layout = {
    .componentName = "ecl::CharacterIconRequestComponent",
    .shortName = "CharacterIconRequest",
    .componentTypeIndex = 0,
    .componentSize = 0x1b0,
    .properties = g_Gen_ecl_CharacterIconRequestComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_CharacterIconRequestComponent_Properties) / sizeof(g_Gen_ecl_CharacterIconRequestComponent_Properties[0]),
};

// ======================================================================
// ecl::CharacterLightComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x18 (24 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_CharacterLightComponent_Properties[] = {
    { "Enabled", 0x00, FIELD_TYPE_BOOL, 0, true },
    { "LightChannel", 0x01, FIELD_TYPE_UINT8, 0, true },
    { "field_2", 0x02, FIELD_TYPE_UINT8, 0, true },
    { "field_3", 0x03, FIELD_TYPE_UINT8, 0, true },
    { "field_4", 0x04, FIELD_TYPE_UINT8, 0, true },
    { "field_5", 0x05, FIELD_TYPE_UINT8, 0, true },
    { "field_6", 0x06, FIELD_TYPE_UINT8, 0, true },
    { "field_7", 0x07, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_CharacterLightComponent_Layout = {
    .componentName = "ecl::CharacterLightComponent",
    .shortName = "CharacterLight",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_ecl_CharacterLightComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_CharacterLightComponent_Properties) / sizeof(g_Gen_ecl_CharacterLightComponent_Properties[0]),
};

// ======================================================================
// ecl::ClientTimelineActorControlComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x28 (40 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_ClientTimelineActorControlComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_GUID, 0, true },
    { "field_10", 0x10, FIELD_TYPE_GUID, 0, true },
    { "field_20", 0x20, FIELD_TYPE_UINT8, 0, true },
    { "field_21", 0x21, FIELD_TYPE_UINT8, 0, true },
    { "field_22", 0x22, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_ClientTimelineActorControlComponent_Layout = {
    .componentName = "ecl::ClientTimelineActorControlComponent",
    .shortName = "ClientTimelineActorControl",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_Gen_ecl_ClientTimelineActorControlComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_ClientTimelineActorControlComponent_Properties) / sizeof(g_Gen_ecl_ClientTimelineActorControlComponent_Properties[0]),
};

// ======================================================================
// ecl::EquipmentVisualsComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x48 (72 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_EquipmentVisualsComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_EquipmentVisualsComponent_Layout = {
    .componentName = "ecl::EquipmentVisualsComponent",
    .shortName = "EquipmentVisuals",
    .componentTypeIndex = 0,
    .componentSize = 0x48,
    .properties = g_Gen_ecl_EquipmentVisualsComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_EquipmentVisualsComponent_Properties) / sizeof(g_Gen_ecl_EquipmentVisualsComponent_Properties[0]),
};

// ======================================================================
// ecl::GameCameraBehavior
// Generated from Windows BG3SE headers
// ARM64 Size: 0x258 (600 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_GameCameraBehavior_Properties[] = {
    { "Trigger", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Target", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "TargetFalling", 0x10, FIELD_TYPE_BOOL, 0, true },
    { "field_11", 0x11, FIELD_TYPE_BOOL, 0, true },
    { "MovingToTarget", 0x12, FIELD_TYPE_BOOL, 0, true },
    { "field_13", 0x13, FIELD_TYPE_BOOL, 0, true },
    { "field_14", 0x14, FIELD_TYPE_FLOAT, 0, true },
    { "TargetPreviousDestination", 0x18, FIELD_TYPE_VEC3, 0, true },
    { "TargetDestination", 0x28, FIELD_TYPE_VEC3, 0, true },
    { "field_30", 0x38, FIELD_TYPE_VEC3, 0, true },
    { "field_3C", 0x48, FIELD_TYPE_VEC3, 0, true },
    { "TargetCurrent", 0x58, FIELD_TYPE_VEC3, 0, true },
    { "Distance", 0x64, FIELD_TYPE_FLOAT, 0, true },
    { "field_58", 0x68, FIELD_TYPE_FLOAT, 0, true },
    { "field_5C", 0x6c, FIELD_TYPE_FLOAT, 0, true },
    { "field_60", 0x70, FIELD_TYPE_FLOAT, 0, true },
    { "field_64", 0x74, FIELD_TYPE_FLOAT, 0, true },
    { "field_68", 0x78, FIELD_TYPE_FLOAT, 0, true },
    { "MovementDistanceMax", 0x7c, FIELD_TYPE_FLOAT, 0, true },
    { "Direction", 0x80, FIELD_TYPE_VEC3, 0, true },
    { "DirectionDestination", 0x90, FIELD_TYPE_VEC3, 0, true },
    { "field_88", 0xa0, FIELD_TYPE_VEC3, 0, true },
    { "XRotationSpeed", 0xac, FIELD_TYPE_FLOAT, 0, true },
    { "XRotationSpeedMouse", 0xb0, FIELD_TYPE_INT32, 0, true },
    { "ZoomSpeed", 0xb4, FIELD_TYPE_FLOAT, 0, true },
    { "CameraMode", 0xb8, FIELD_TYPE_UINT8, 0, true },
    { "field_A9", 0xa9, FIELD_TYPE_UINT8, 0, true },
    { "RotationY", 0xbc, FIELD_TYPE_FLOAT, 0, true },
    { "MouseRotationSpeed", 0xc0, FIELD_TYPE_FLOAT, 0, true },
    { "TargetLastPosition", 0xc8, FIELD_TYPE_VEC3, 0, true },
    { "field_D8", 0xd4, FIELD_TYPE_FLOAT, 0, true },
    { "field_DC", 0xd8, FIELD_TYPE_FLOAT, 0, true },
    { "field_E0", 0xdc, FIELD_TYPE_FLOAT, 0, true },
    { "field_E4", 0xe0, FIELD_TYPE_FLOAT, 0, true },
    { "field_E8", 0xe4, FIELD_TYPE_FLOAT, 0, true },
    { "Trigger1ID", 0xe8, FIELD_TYPE_INT32, 0, true },
    { "Trigger2ID", 0xec, FIELD_TYPE_INT32, 0, true },
    { "Trigger3ID", 0xf0, FIELD_TYPE_INT32, 0, true },
    { "LastPlayerInputTime", 0xf4, FIELD_TYPE_FLOAT, 0, true },
    { "PlayerInControl", 0xf8, FIELD_TYPE_BOOL, 0, true },
    { "field_145", 0x145, FIELD_TYPE_BOOL, 0, true },
    { "IsPaused", 0xfa, FIELD_TYPE_BOOL, 0, true },
    { "TargetMode", 0xfc, FIELD_TYPE_UINT32, 0, true },
    { "SelectMode", 0x100, FIELD_TYPE_BOOL, 0, true },
    { "WasInSelectMode", 0x101, FIELD_TYPE_BOOL, 0, true },
    { "field_150", 0x108, FIELD_TYPE_VEC3, 0, true },
    { "field_15C", 0x114, FIELD_TYPE_FLOAT, 0, true },
    { "Zoom", 0x118, FIELD_TYPE_FLOAT, 0, true },
    { "PitchDegrees", 0x11c, FIELD_TYPE_FLOAT, 0, true },
    { "field_188", 0x120, FIELD_TYPE_BOOL, 0, true },
    { "FreezeHeight", 0x121, FIELD_TYPE_BOOL, 0, true },
    { "field_18A", 0x18a, FIELD_TYPE_BOOL, 0, true },
    { "field_18B", 0x18b, FIELD_TYPE_BOOL, 0, true },
    { "DebugPosition", 0x128, FIELD_TYPE_VEC3, 0, true },
    { "DebugOffset", 0x134, FIELD_TYPE_FLOAT, 0, true },
    { "TrackTarget", 0x138, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "IsMoving", 0x140, FIELD_TYPE_BOOL, 0, true },
    { "IsRotating", 0x141, FIELD_TYPE_BOOL, 0, true },
    { "field_1F2", 0x142, FIELD_TYPE_BOOL, 0, true },
    { "IsSnapping", 0x143, FIELD_TYPE_BOOL, 0, true },
    { "LastPickingTarget", 0x148, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "field_200", 0x200, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_GameCameraBehavior_Layout = {
    .componentName = "ecl::GameCameraBehavior",
    .shortName = "GameCameraBehavior",
    .componentTypeIndex = 0,
    .componentSize = 0x258,
    .properties = g_Gen_ecl_GameCameraBehavior_Properties,
    .propertyCount = sizeof(g_Gen_ecl_GameCameraBehavior_Properties) / sizeof(g_Gen_ecl_GameCameraBehavior_Properties[0]),
};

// ======================================================================
// ecl::PaperdollComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_PaperdollComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_PaperdollComponent_Layout = {
    .componentName = "ecl::PaperdollComponent",
    .shortName = "Paperdoll",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_ecl_PaperdollComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_PaperdollComponent_Properties) / sizeof(g_Gen_ecl_PaperdollComponent_Properties[0]),
};

// ======================================================================
// ecl::Scenery
// Generated from Windows BG3SE headers
// ARM64 Size: 0x40 (64 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_Scenery_Properties[] = {
    { "Entity2", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Uuid", 0x08, FIELD_TYPE_GUID, 0, true },
    { "Visual", 0x18, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "VisualLoadFlags", 0x1c, FIELD_TYPE_UINT16, 0, true },
    { "field_60", 0x20, FIELD_TYPE_UINT64, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_Scenery_Layout = {
    .componentName = "ecl::Scenery",
    .shortName = "Scenery",
    .componentTypeIndex = 0,
    .componentSize = 0x40,
    .properties = g_Gen_ecl_Scenery_Properties,
    .propertyCount = sizeof(g_Gen_ecl_Scenery_Properties) / sizeof(g_Gen_ecl_Scenery_Properties[0]),
};

// ======================================================================
// ecl::TLPreviewDummy
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_TLPreviewDummy_Properties[] = {
    { "TLPreviewDummyPtr", 0x00, FIELD_TYPE_UINT64, 0, true },  // Ptr to 0xc0 (192b) malloc
};

static const ComponentLayoutDef g_Gen_ecl_TLPreviewDummy_Layout = {
    .componentName = "ecl::TLPreviewDummy",
    .shortName = "TLPreviewDummy",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_ecl_TLPreviewDummy_Properties,
    .propertyCount = sizeof(g_Gen_ecl_TLPreviewDummy_Properties) / sizeof(g_Gen_ecl_TLPreviewDummy_Properties[0]),
};

// ======================================================================
// ecl::camera::SelectorModeComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x1 (1 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_camera_SelectorModeComponent_Properties[] = {
    { "Mode", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_camera_SelectorModeComponent_Layout = {
    .componentName = "ecl::camera::SelectorModeComponent",
    .shortName = "SelectorMode",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_ecl_camera_SelectorModeComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_camera_SelectorModeComponent_Properties) / sizeof(g_Gen_ecl_camera_SelectorModeComponent_Properties[0]),
};

// ======================================================================
// ecl::character_creation::CompanionDefinitionComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x68 (104 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_character_creation_CompanionDefinitionComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_GUID, 0, true },
    { "field_10", 0x10, FIELD_TYPE_GUID, 0, true },
    { "field_20", 0x20, FIELD_TYPE_UINT8, 0, true },
    { "field_21", 0x21, FIELD_TYPE_UINT8, 0, true },
    { "field_28", 0x28, FIELD_TYPE_GUID, 0, true },
    { "field_110", 0x38, FIELD_TYPE_GUID, 0, true },
    { "field_120", 0x48, FIELD_TYPE_GUID, 0, true },
    { "field_130", 0x58, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_character_creation_CompanionDefinitionComponent_Layout = {
    .componentName = "ecl::character_creation::CompanionDefinitionComponent",
    .shortName = "CompanionDefinition",
    .componentTypeIndex = 0,
    .componentSize = 0x68,
    .properties = g_Gen_ecl_character_creation_CompanionDefinitionComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_character_creation_CompanionDefinitionComponent_Properties) / sizeof(g_Gen_ecl_character_creation_CompanionDefinitionComponent_Properties[0]),
};

// ======================================================================
// ecl::character_creation::DefinitionStateComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0xc8 (200 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_character_creation_DefinitionStateComponent_Properties[] = {
    { "field_8", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "field_C", 0x0c, FIELD_TYPE_UINT32, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_character_creation_DefinitionStateComponent_Layout = {
    .componentName = "ecl::character_creation::DefinitionStateComponent",
    .shortName = "DefinitionState",
    .componentTypeIndex = 0,
    .componentSize = 0xc8,
    .properties = g_Gen_ecl_character_creation_DefinitionStateComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_character_creation_DefinitionStateComponent_Properties) / sizeof(g_Gen_ecl_character_creation_DefinitionStateComponent_Properties[0]),
};

// ======================================================================
// ecl::character_creation::DefinitionStateExComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x28 (40 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_character_creation_DefinitionStateExComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, true },
    { "field_1", 0x01, FIELD_TYPE_UINT8, 0, true },
    { "field_2", 0x02, FIELD_TYPE_UINT8, 0, true },
    { "field_18", 0x18, FIELD_TYPE_UINT32, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_character_creation_DefinitionStateExComponent_Layout = {
    .componentName = "ecl::character_creation::DefinitionStateExComponent",
    .shortName = "DefinitionStateEx",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_Gen_ecl_character_creation_DefinitionStateExComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_character_creation_DefinitionStateExComponent_Properties) / sizeof(g_Gen_ecl_character_creation_DefinitionStateExComponent_Properties[0]),
};

// ======================================================================
// ecl::character_creation::DummyDefinitionComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1b0 (432 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_character_creation_DummyDefinitionComponent_Properties[] = {
    { "field_10", 0x00, FIELD_TYPE_INT32, 0, true },
    { "field_58", 0x04, FIELD_TYPE_UINT8, 0, true },
    { "field_59", 0x05, FIELD_TYPE_UINT8, 0, true },
    { "field_5A", 0x06, FIELD_TYPE_UINT8, 0, true },
    { "field_5B", 0x07, FIELD_TYPE_UINT8, 0, true },
    { "field_1A0", 0x08, FIELD_TYPE_UINT8, 0, true },
    { "field_1A8", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_character_creation_DummyDefinitionComponent_Layout = {
    .componentName = "ecl::character_creation::DummyDefinitionComponent",
    .shortName = "DummyDefinition",
    .componentTypeIndex = 0,
    .componentSize = 0x1b0,
    .properties = g_Gen_ecl_character_creation_DummyDefinitionComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_character_creation_DummyDefinitionComponent_Properties) / sizeof(g_Gen_ecl_character_creation_DummyDefinitionComponent_Properties[0]),
};

// ======================================================================
// ecl::character_creation::FullRespecDefinitionComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0xa8 (168 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_character_creation_FullRespecDefinitionComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_GUID, 0, true },
    { "field_10", 0x10, FIELD_TYPE_GUID, 0, true },
    { "field_20", 0x20, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_character_creation_FullRespecDefinitionComponent_Layout = {
    .componentName = "ecl::character_creation::FullRespecDefinitionComponent",
    .shortName = "FullRespecDefinition",
    .componentTypeIndex = 0,
    .componentSize = 0xa8,
    .properties = g_Gen_ecl_character_creation_FullRespecDefinitionComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_character_creation_FullRespecDefinitionComponent_Properties) / sizeof(g_Gen_ecl_character_creation_FullRespecDefinitionComponent_Properties[0]),
};

// ======================================================================
// ecl::dummy::DummyComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_dummy_DummyComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_dummy_DummyComponent_Layout = {
    .componentName = "ecl::dummy::DummyComponent",
    .shortName = "Dummy",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_ecl_dummy_DummyComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_dummy_DummyComponent_Properties) / sizeof(g_Gen_ecl_dummy_DummyComponent_Properties[0]),
};

// ======================================================================
// ecl::dummy::EquipmentVisualsStateComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x4 (4 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_dummy_EquipmentVisualsStateComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_dummy_EquipmentVisualsStateComponent_Layout = {
    .componentName = "ecl::dummy::EquipmentVisualsStateComponent",
    .shortName = "EquipmentVisualsState",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_ecl_dummy_EquipmentVisualsStateComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_dummy_EquipmentVisualsStateComponent_Properties) / sizeof(g_Gen_ecl_dummy_EquipmentVisualsStateComponent_Properties[0]),
};

// ======================================================================
// ecl::dummy::FootIKStateComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x10 (16 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_dummy_FootIKStateComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT64, 0, true },
    { "field_8", 0x08, FIELD_TYPE_INT32, 0, true },
    { "field_C", 0x0c, FIELD_TYPE_UINT8, 0, true },
    { "field_D", 0x0d, FIELD_TYPE_UINT8, 0, true },
    { "field_E", 0x0e, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_dummy_FootIKStateComponent_Layout = {
    .componentName = "ecl::dummy::FootIKStateComponent",
    .shortName = "FootIKState",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_ecl_dummy_FootIKStateComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_dummy_FootIKStateComponent_Properties) / sizeof(g_Gen_ecl_dummy_FootIKStateComponent_Properties[0]),
};

// ======================================================================
// ecl::dummy::HasDummyComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_dummy_HasDummyComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_dummy_HasDummyComponent_Layout = {
    .componentName = "ecl::dummy::HasDummyComponent",
    .shortName = "HasDummy",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_ecl_dummy_HasDummyComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_dummy_HasDummyComponent_Properties) / sizeof(g_Gen_ecl_dummy_HasDummyComponent_Properties[0]),
};

// ======================================================================
// ecl::dummy::SplatterComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x14 (20 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_dummy_SplatterComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, true },
    { "field_4", 0x04, FIELD_TYPE_INT32, 0, true },
    { "field_8", 0x08, FIELD_TYPE_INT32, 0, true },
    { "field_C", 0x0c, FIELD_TYPE_INT32, 0, true },
    { "byte10", 0x10, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_dummy_SplatterComponent_Layout = {
    .componentName = "ecl::dummy::SplatterComponent",
    .shortName = "Splatter",
    .componentTypeIndex = 0,
    .componentSize = 0x14,
    .properties = g_Gen_ecl_dummy_SplatterComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_dummy_SplatterComponent_Properties) / sizeof(g_Gen_ecl_dummy_SplatterComponent_Properties[0]),
};

// ======================================================================
// ecl::dummy::UnsheathComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x10 (16 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_dummy_UnsheathComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, true },
    { "field_4", 0x04, FIELD_TYPE_INT32, 0, true },
    { "field_8", 0x08, FIELD_TYPE_INT32, 0, true },
    { "field_C", 0x0c, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_dummy_UnsheathComponent_Layout = {
    .componentName = "ecl::dummy::UnsheathComponent",
    .shortName = "Unsheath",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_ecl_dummy_UnsheathComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_dummy_UnsheathComponent_Properties) / sizeof(g_Gen_ecl_dummy_UnsheathComponent_Properties[0]),
};

// ======================================================================
// ecl::equipment::VisualsVisibilityStateComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x48 (72 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_equipment_VisualsVisibilityStateComponent_Properties[] = {
    { "field_40", 0x40, FIELD_TYPE_UINT8, 0, true },
    { "field_41", 0x41, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_equipment_VisualsVisibilityStateComponent_Layout = {
    .componentName = "ecl::equipment::VisualsVisibilityStateComponent",
    .shortName = "VisualsVisibilityState",
    .componentTypeIndex = 0,
    .componentSize = 0x48,
    .properties = g_Gen_ecl_equipment_VisualsVisibilityStateComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_equipment_VisualsVisibilityStateComponent_Properties) / sizeof(g_Gen_ecl_equipment_VisualsVisibilityStateComponent_Properties[0]),
};

// ======================================================================
// ecl::photo_mode::CameraOffsetComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x20 (32 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_photo_mode_CameraOffsetComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_VEC3, 0, true },
    { "field_C", 0x10, FIELD_TYPE_VEC3, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_photo_mode_CameraOffsetComponent_Layout = {
    .componentName = "ecl::photo_mode::CameraOffsetComponent",
    .shortName = "CameraOffset",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_Gen_ecl_photo_mode_CameraOffsetComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_photo_mode_CameraOffsetComponent_Properties) / sizeof(g_Gen_ecl_photo_mode_CameraOffsetComponent_Properties[0]),
};

// ======================================================================
// ecl::photo_mode::CameraSavedTransformComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x18 (24 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_photo_mode_CameraSavedTransformComponent_Properties[] = {
    { "field_28", 0x00, FIELD_TYPE_INT32, 0, true },
    { "field_2C", 0x04, FIELD_TYPE_INT32, 0, true },
    { "field_30", 0x08, FIELD_TYPE_INT32, 0, true },
    { "field_34", 0x0c, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_photo_mode_CameraSavedTransformComponent_Layout = {
    .componentName = "ecl::photo_mode::CameraSavedTransformComponent",
    .shortName = "CameraSavedTransform",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_ecl_photo_mode_CameraSavedTransformComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_photo_mode_CameraSavedTransformComponent_Properties) / sizeof(g_Gen_ecl_photo_mode_CameraSavedTransformComponent_Properties[0]),
};

// ======================================================================
// ecl::photo_mode::CameraTiltComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x8 (8 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_photo_mode_CameraTiltComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_FLOAT, 0, true },
    { "field_4", 0x04, FIELD_TYPE_FLOAT, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_photo_mode_CameraTiltComponent_Layout = {
    .componentName = "ecl::photo_mode::CameraTiltComponent",
    .shortName = "CameraTilt",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_ecl_photo_mode_CameraTiltComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_photo_mode_CameraTiltComponent_Properties) / sizeof(g_Gen_ecl_photo_mode_CameraTiltComponent_Properties[0]),
};

// ======================================================================
// ecl::photo_mode::CameraTrackingComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x8 (8 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_photo_mode_CameraTrackingComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_photo_mode_CameraTrackingComponent_Layout = {
    .componentName = "ecl::photo_mode::CameraTrackingComponent",
    .shortName = "CameraTracking",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_ecl_photo_mode_CameraTrackingComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_photo_mode_CameraTrackingComponent_Properties) / sizeof(g_Gen_ecl_photo_mode_CameraTrackingComponent_Properties[0]),
};

// ======================================================================
// ecl::photo_mode::DummyEquipmentSetupOneFrameComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x4 (4 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_photo_mode_DummyEquipmentSetupOneFrameComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, true },
    { "field_1", 0x01, FIELD_TYPE_UINT8, 0, true },
    { "field_2", 0x02, FIELD_TYPE_UINT8, 0, true },
    { "field_3", 0x03, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_photo_mode_DummyEquipmentSetupOneFrameComponent_Layout = {
    .componentName = "ecl::photo_mode::DummyEquipmentSetupOneFrameComponent",
    .shortName = "DummyEquipmentSetupOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_ecl_photo_mode_DummyEquipmentSetupOneFrameComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_photo_mode_DummyEquipmentSetupOneFrameComponent_Properties) / sizeof(g_Gen_ecl_photo_mode_DummyEquipmentSetupOneFrameComponent_Properties[0]),
};

// ======================================================================
// ecl::photo_mode::RequestedSingletonComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x1 (1 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_ecl_photo_mode_RequestedSingletonComponent_Properties[] = {
    { "Requested", 0x00, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_ecl_photo_mode_RequestedSingletonComponent_Layout = {
    .componentName = "ecl::photo_mode::RequestedSingletonComponent",
    .shortName = "RequestedSingleton",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_ecl_photo_mode_RequestedSingletonComponent_Properties,
    .propertyCount = sizeof(g_Gen_ecl_photo_mode_RequestedSingletonComponent_Properties) / sizeof(g_Gen_ecl_photo_mode_RequestedSingletonComponent_Properties[0]),
};

// ======================================================================
// eoc::ArmorComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_ArmorComponent_Properties[] = {
    { "ArmorType", 0x00, FIELD_TYPE_INT32, 0, true },
    { "ArmorClass", 0x04, FIELD_TYPE_INT32, 0, true },
    { "AbilityModifierCap", 0x08, FIELD_TYPE_INT32, 0, true },
    { "ArmorClassAbility", 0x0c, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_ArmorComponent_Layout = {
    .componentName = "eoc::ArmorComponent",
    .shortName = "Armor",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_eoc_ArmorComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_ArmorComponent_Properties) / sizeof(g_Gen_eoc_ArmorComponent_Properties[0]),
};

// ======================================================================
// eoc::AttributeFlagsComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_AttributeFlagsComponent_Properties[] = {
    { "AttributeFlags", 0x00, FIELD_TYPE_UINT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_AttributeFlagsComponent_Layout = {
    .componentName = "eoc::AttributeFlagsComponent",
    .shortName = "AttributeFlags",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_AttributeFlagsComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_AttributeFlagsComponent_Properties) / sizeof(g_Gen_eoc_AttributeFlagsComponent_Properties[0]),
};

// ======================================================================
// eoc::BackgroundComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_BackgroundComponent_Properties[] = {
    { "Background", 0x00, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_BackgroundComponent_Layout = {
    .componentName = "eoc::BackgroundComponent",
    .shortName = "Background",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_eoc_BackgroundComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_BackgroundComponent_Properties) / sizeof(g_Gen_eoc_BackgroundComponent_Properties[0]),
};

// ======================================================================
// eoc::BaseHpComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_BaseHpComponent_Properties[] = {
    { "Vitality", 0x00, FIELD_TYPE_INT32, 0, true },
    { "VitalityBoost", 0x04, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_BaseHpComponent_Layout = {
    .componentName = "eoc::BaseHpComponent",
    .shortName = "BaseHp",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_BaseHpComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_BaseHpComponent_Properties) / sizeof(g_Gen_eoc_BaseHpComponent_Properties[0]),
};

// ======================================================================
// eoc::BlockAbilityModifierFromACComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x1 (1 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_BlockAbilityModifierFromACComponent_Properties[] = {
    { "Ability", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_BlockAbilityModifierFromACComponent_Layout = {
    .componentName = "eoc::BlockAbilityModifierFromACComponent",
    .shortName = "BlockAbilityModifierFromAC",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_eoc_BlockAbilityModifierFromACComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_BlockAbilityModifierFromACComponent_Properties) / sizeof(g_Gen_eoc_BlockAbilityModifierFromACComponent_Properties[0]),
};

// ======================================================================
// eoc::BodyTypeComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x2 (2 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_BodyTypeComponent_Properties[] = {
    { "BodyType", 0x00, FIELD_TYPE_UINT8, 0, true },
    { "BodyType2", 0x01, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_BodyTypeComponent_Layout = {
    .componentName = "eoc::BodyTypeComponent",
    .shortName = "BodyType",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_Gen_eoc_BodyTypeComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_BodyTypeComponent_Properties) / sizeof(g_Gen_eoc_BodyTypeComponent_Properties[0]),
};

// ======================================================================
// eoc::BoostConditionComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_BoostConditionComponent_Properties[] = {
    { "ConditionFlags", 0x00, FIELD_TYPE_INT32, 0, true },
    { "field_1C", 0x04, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_BoostConditionComponent_Layout = {
    .componentName = "eoc::BoostConditionComponent",
    .shortName = "BoostCondition",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_BoostConditionComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_BoostConditionComponent_Properties) / sizeof(g_Gen_eoc_BoostConditionComponent_Properties[0]),
};

// ======================================================================
// eoc::BoostInfoComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x58 (88 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_BoostInfoComponent_Properties[] = {
    { "field_20", 0x10, FIELD_TYPE_BOOL, 0, true },
    { "Owner", 0x30, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_BoostInfoComponent_Layout = {
    .componentName = "eoc::BoostInfoComponent",
    .shortName = "BoostInfo",
    .componentTypeIndex = 0,
    .componentSize = 0x58,
    .properties = g_Gen_eoc_BoostInfoComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_BoostInfoComponent_Properties) / sizeof(g_Gen_eoc_BoostInfoComponent_Properties[0]),
};

// ======================================================================
// eoc::CanBeDisarmedComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x2 (2 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_CanBeDisarmedComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT16, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_CanBeDisarmedComponent_Layout = {
    .componentName = "eoc::CanBeDisarmedComponent",
    .shortName = "CanBeDisarmed",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_Gen_eoc_CanBeDisarmedComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_CanBeDisarmedComponent_Properties) / sizeof(g_Gen_eoc_CanBeDisarmedComponent_Properties[0]),
};

// ======================================================================
// eoc::CanBeLootedComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x2 (2 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_CanBeLootedComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT16, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_CanBeLootedComponent_Layout = {
    .componentName = "eoc::CanBeLootedComponent",
    .shortName = "CanBeLooted",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_Gen_eoc_CanBeLootedComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_CanBeLootedComponent_Properties) / sizeof(g_Gen_eoc_CanBeLootedComponent_Properties[0]),
};

// ======================================================================
// eoc::CanDeflectProjectilesComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x2 (2 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_CanDeflectProjectilesComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT16, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_CanDeflectProjectilesComponent_Layout = {
    .componentName = "eoc::CanDeflectProjectilesComponent",
    .shortName = "CanDeflectProjectiles",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_Gen_eoc_CanDeflectProjectilesComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_CanDeflectProjectilesComponent_Properties) / sizeof(g_Gen_eoc_CanDeflectProjectilesComponent_Properties[0]),
};

// ======================================================================
// eoc::CanInteractComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_CanInteractComponent_Properties[] = {
    { "Flags2", 0x00, FIELD_TYPE_UINT16, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_CanInteractComponent_Layout = {
    .componentName = "eoc::CanInteractComponent",
    .shortName = "CanInteract",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_CanInteractComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_CanInteractComponent_Properties) / sizeof(g_Gen_eoc_CanInteractComponent_Properties[0]),
};

// ======================================================================
// eoc::CanModifyHealthComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x2 (2 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_CanModifyHealthComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT16, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_CanModifyHealthComponent_Layout = {
    .componentName = "eoc::CanModifyHealthComponent",
    .shortName = "CanModifyHealth",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_Gen_eoc_CanModifyHealthComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_CanModifyHealthComponent_Properties) / sizeof(g_Gen_eoc_CanModifyHealthComponent_Properties[0]),
};

// ======================================================================
// eoc::CanMoveComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x6 (6 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_CanMoveComponent_Properties[] = {
    { "field_4", 0x00, FIELD_TYPE_UINT16, 0, true },
    { "field_6", 0x02, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_CanMoveComponent_Layout = {
    .componentName = "eoc::CanMoveComponent",
    .shortName = "CanMove",
    .componentTypeIndex = 0,
    .componentSize = 0x6,
    .properties = g_Gen_eoc_CanMoveComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_CanMoveComponent_Properties) / sizeof(g_Gen_eoc_CanMoveComponent_Properties[0]),
};

// ======================================================================
// eoc::CanSenseComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x2 (2 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_CanSenseComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT16, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_CanSenseComponent_Layout = {
    .componentName = "eoc::CanSenseComponent",
    .shortName = "CanSense",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_Gen_eoc_CanSenseComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_CanSenseComponent_Properties) / sizeof(g_Gen_eoc_CanSenseComponent_Properties[0]),
};

// ======================================================================
// eoc::CanSpeakComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x2 (2 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_CanSpeakComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT16, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_CanSpeakComponent_Layout = {
    .componentName = "eoc::CanSpeakComponent",
    .shortName = "CanSpeak",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_Gen_eoc_CanSpeakComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_CanSpeakComponent_Properties) / sizeof(g_Gen_eoc_CanSpeakComponent_Properties[0]),
};

// ======================================================================
// eoc::CanTravelComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x6 (6 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_CanTravelComponent_Properties[] = {
    { "field_2", 0x02, FIELD_TYPE_UINT16, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_CanTravelComponent_Layout = {
    .componentName = "eoc::CanTravelComponent",
    .shortName = "CanTravel",
    .componentTypeIndex = 0,
    .componentSize = 0x6,
    .properties = g_Gen_eoc_CanTravelComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_CanTravelComponent_Properties) / sizeof(g_Gen_eoc_CanTravelComponent_Properties[0]),
};

// ======================================================================
// eoc::CharacterCreationStatsComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x58 (88 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_CharacterCreationStatsComponent_Properties[] = {
    { "Race", 0x00, FIELD_TYPE_GUID, 0, true },
    { "SubRace", 0x10, FIELD_TYPE_GUID, 0, true },
    { "BodyType", 0x20, FIELD_TYPE_UINT8, 0, true },
    { "BodyShape", 0x21, FIELD_TYPE_UINT8, 0, true },
    { "field_5C", 0x54, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_CharacterCreationStatsComponent_Layout = {
    .componentName = "eoc::CharacterCreationStatsComponent",
    .shortName = "CharacterCreationStats",
    .componentTypeIndex = 0,
    .componentSize = 0x58,
    .properties = g_Gen_eoc_CharacterCreationStatsComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_CharacterCreationStatsComponent_Properties) / sizeof(g_Gen_eoc_CharacterCreationStatsComponent_Properties[0]),
};

// ======================================================================
// eoc::CombinedLightComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x40 (64 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_CombinedLightComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Template", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "InstanceGuid", 0x0c, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_CombinedLightComponent_Layout = {
    .componentName = "eoc::CombinedLightComponent",
    .shortName = "CombinedLight",
    .componentTypeIndex = 0,
    .componentSize = 0x40,
    .properties = g_Gen_eoc_CombinedLightComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_CombinedLightComponent_Properties) / sizeof(g_Gen_eoc_CombinedLightComponent_Properties[0]),
};

// ======================================================================
// eoc::CustomIconComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x60 (96 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_CustomIconComponent_Properties[] = {
    { "Source", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_CustomIconComponent_Layout = {
    .componentName = "eoc::CustomIconComponent",
    .shortName = "CustomIcon",
    .componentTypeIndex = 0,
    .componentSize = 0x60,
    .properties = g_Gen_eoc_CustomIconComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_CustomIconComponent_Properties) / sizeof(g_Gen_eoc_CustomIconComponent_Properties[0]),
};

// ======================================================================
// eoc::DamageReductionBoostComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x38 (56 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_DamageReductionBoostComponent_Properties[] = {
    { "Flat", 0x00, FIELD_TYPE_BOOL, 0, true },
    { "Half", 0x01, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_DamageReductionBoostComponent_Layout = {
    .componentName = "eoc::DamageReductionBoostComponent",
    .shortName = "DamageReductionBoost",
    .componentTypeIndex = 0,
    .componentSize = 0x38,
    .properties = g_Gen_eoc_DamageReductionBoostComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_DamageReductionBoostComponent_Properties) / sizeof(g_Gen_eoc_DamageReductionBoostComponent_Properties[0]),
};

// ======================================================================
// eoc::DarknessComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_DarknessComponent_Properties[] = {
    { "Sneaking", 0x00, FIELD_TYPE_UINT8, 0, true },
    { "Obscurity", 0x01, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_DarknessComponent_Layout = {
    .componentName = "eoc::DarknessComponent",
    .shortName = "Darkness",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_eoc_DarknessComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_DarknessComponent_Properties) / sizeof(g_Gen_eoc_DarknessComponent_Properties[0]),
};

// ======================================================================
// eoc::DataComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0xc (12 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_DataComponent_Properties[] = {
    { "Weight", 0x00, FIELD_TYPE_INT32, 0, true },
    { "StatsId", 0x04, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "StepsType", 0x08, FIELD_TYPE_UINT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_DataComponent_Layout = {
    .componentName = "eoc::DataComponent",
    .shortName = "Data",
    .componentTypeIndex = 0,
    .componentSize = 0xc,
    .properties = g_Gen_eoc_DataComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_DataComponent_Properties) / sizeof(g_Gen_eoc_DataComponent_Properties[0]),
};

// ======================================================================
// eoc::DetachedComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_DetachedComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_DetachedComponent_Layout = {
    .componentName = "eoc::DetachedComponent",
    .shortName = "Detached",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_DetachedComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_DetachedComponent_Properties) / sizeof(g_Gen_eoc_DetachedComponent_Properties[0]),
};

// ======================================================================
// eoc::DifficultyCheckComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x48 (72 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_DifficultyCheckComponent_Properties[] = {
    { "field_40", 0x00, FIELD_TYPE_INT32, 0, true },
    { "field_44", 0x04, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_DifficultyCheckComponent_Layout = {
    .componentName = "eoc::DifficultyCheckComponent",
    .shortName = "DifficultyCheck",
    .componentTypeIndex = 0,
    .componentSize = 0x48,
    .properties = g_Gen_eoc_DifficultyCheckComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_DifficultyCheckComponent_Properties) / sizeof(g_Gen_eoc_DifficultyCheckComponent_Properties[0]),
};

// ======================================================================
// eoc::DisabledEquipmentComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1 (1 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_DisabledEquipmentComponent_Properties[] = {
    { "ShapeshiftFlag", 0x00, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_DisabledEquipmentComponent_Layout = {
    .componentName = "eoc::DisabledEquipmentComponent",
    .shortName = "DisabledEquipment",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_eoc_DisabledEquipmentComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_DisabledEquipmentComponent_Properties) / sizeof(g_Gen_eoc_DisabledEquipmentComponent_Properties[0]),
};

// ======================================================================
// eoc::DisarmableComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x18 (24 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_DisarmableComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_GUID, 0, true },
    { "field_10", 0x10, FIELD_TYPE_UINT8, 0, true },
    { "field_11", 0x11, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_DisarmableComponent_Layout = {
    .componentName = "eoc::DisarmableComponent",
    .shortName = "Disarmable",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_eoc_DisarmableComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_DisarmableComponent_Properties) / sizeof(g_Gen_eoc_DisarmableComponent_Properties[0]),
};

// ======================================================================
// eoc::DualWieldingComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x7 (7 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_DualWieldingComponent_Properties[] = {
    { "MeleeUI", 0x00, FIELD_TYPE_BOOL, 0, true },
    { "RangedUI", 0x01, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_DualWieldingComponent_Layout = {
    .componentName = "eoc::DualWieldingComponent",
    .shortName = "DualWielding",
    .componentTypeIndex = 0,
    .componentSize = 0x7,
    .properties = g_Gen_eoc_DualWieldingComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_DualWieldingComponent_Properties) / sizeof(g_Gen_eoc_DualWieldingComponent_Properties[0]),
};

// ======================================================================
// eoc::FloatingComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_FloatingComponent_Properties[] = {
    { "field_18", 0x00, FIELD_TYPE_INT32, 0, true },
    { "field_1C", 0x04, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_FloatingComponent_Layout = {
    .componentName = "eoc::FloatingComponent",
    .shortName = "Floating",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_FloatingComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_FloatingComponent_Properties) / sizeof(g_Gen_eoc_FloatingComponent_Properties[0]),
};

// ======================================================================
// eoc::FogVolumeRequestComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_FogVolumeRequestComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_FogVolumeRequestComponent_Layout = {
    .componentName = "eoc::FogVolumeRequestComponent",
    .shortName = "FogVolumeRequest",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_eoc_FogVolumeRequestComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_FogVolumeRequestComponent_Properties) / sizeof(g_Gen_eoc_FogVolumeRequestComponent_Properties[0]),
};

// ======================================================================
// eoc::GameObjectVisualComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x14 (20 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_GameObjectVisualComponent_Properties[] = {
    { "RootTemplateId", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "RootTemplateType", 0x04, FIELD_TYPE_UINT8, 0, true },
    { "Icon", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Scale", 0x0c, FIELD_TYPE_FLOAT, 0, true },
    { "Type", 0x10, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_GameObjectVisualComponent_Layout = {
    .componentName = "eoc::GameObjectVisualComponent",
    .shortName = "GameObjectVisual",
    .componentTypeIndex = 0,
    .componentSize = 0x14,
    .properties = g_Gen_eoc_GameObjectVisualComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_GameObjectVisualComponent_Properties) / sizeof(g_Gen_eoc_GameObjectVisualComponent_Properties[0]),
};

// ======================================================================
// eoc::GameplayLightComponent
// Generated from Windows BG3SE headers
// Windows Size: 0xc (12 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_GameplayLightComponent_Properties[] = {

};

static const ComponentLayoutDef g_Gen_eoc_GameplayLightComponent_Layout = {
    .componentName = "eoc::GameplayLightComponent",
    .shortName = "GameplayLight",
    .componentTypeIndex = 0,
    .componentSize = 0xc,
    .properties = g_Gen_eoc_GameplayLightComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_GameplayLightComponent_Properties) / sizeof(g_Gen_eoc_GameplayLightComponent_Properties[0]),
};

// ======================================================================
// eoc::HealthComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x28 (40 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_HealthComponent_Properties[] = {
    { "Hp", 0x00, FIELD_TYPE_INT32, 0, true },
    { "MaxHp", 0x04, FIELD_TYPE_INT32, 0, true },
    { "TemporaryHp", 0x08, FIELD_TYPE_INT32, 0, true },
    { "MaxTemporaryHp", 0x0c, FIELD_TYPE_INT32, 0, true },
    { "field_10", 0x10, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_HealthComponent_Layout = {
    .componentName = "eoc::HealthComponent",
    .shortName = "Health",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_Gen_eoc_HealthComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_HealthComponent_Properties) / sizeof(g_Gen_eoc_HealthComponent_Properties[0]),
};

// ======================================================================
// eoc::HearingComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_HearingComponent_Properties[] = {
    { "Hearing", 0x00, FIELD_TYPE_FLOAT, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_HearingComponent_Layout = {
    .componentName = "eoc::HearingComponent",
    .shortName = "Hearing",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_HearingComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_HearingComponent_Properties) / sizeof(g_Gen_eoc_HearingComponent_Properties[0]),
};

// ======================================================================
// eoc::IconComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_IconComponent_Properties[] = {
    { "Icon", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_IconComponent_Layout = {
    .componentName = "eoc::IconComponent",
    .shortName = "Icon",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_IconComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_IconComponent_Properties) / sizeof(g_Gen_eoc_IconComponent_Properties[0]),
};

// ======================================================================
// eoc::IncreaseMaxHPBoostComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x30 (48 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_IncreaseMaxHPBoostComponent_Properties[] = {
    { "field_30", 0x00, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_IncreaseMaxHPBoostComponent_Layout = {
    .componentName = "eoc::IncreaseMaxHPBoostComponent",
    .shortName = "IncreaseMaxHPBoost",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_Gen_eoc_IncreaseMaxHPBoostComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_IncreaseMaxHPBoostComponent_Properties) / sizeof(g_Gen_eoc_IncreaseMaxHPBoostComponent_Properties[0]),
};

// ======================================================================
// eoc::InteractionFilterComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x38 (56 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_InteractionFilterComponent_Properties[] = {
    { "field_30", 0x30, FIELD_TYPE_UINT8, 0, true },
    { "field_31", 0x31, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_InteractionFilterComponent_Layout = {
    .componentName = "eoc::InteractionFilterComponent",
    .shortName = "InteractionFilter",
    .componentTypeIndex = 0,
    .componentSize = 0x38,
    .properties = g_Gen_eoc_InteractionFilterComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_InteractionFilterComponent_Properties) / sizeof(g_Gen_eoc_InteractionFilterComponent_Properties[0]),
};

// ======================================================================
// eoc::InvisibilityComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x14 (20 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_InvisibilityComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, true },
    { "field_4", 0x04, FIELD_TYPE_VEC3, 0, true },
    { "field_10", 0x10, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_InvisibilityComponent_Layout = {
    .componentName = "eoc::InvisibilityComponent",
    .shortName = "Invisibility",
    .componentTypeIndex = 0,
    .componentSize = 0x14,
    .properties = g_Gen_eoc_InvisibilityComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_InvisibilityComponent_Properties) / sizeof(g_Gen_eoc_InvisibilityComponent_Properties[0]),
};

// ======================================================================
// eoc::LevelComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_LevelComponent_Properties[] = {
    { "Level", 0x00, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_LevelComponent_Layout = {
    .componentName = "eoc::LevelComponent",
    .shortName = "Level",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_LevelComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_LevelComponent_Properties) / sizeof(g_Gen_eoc_LevelComponent_Properties[0]),
};

// ======================================================================
// eoc::LootComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x2 (2 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_LootComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT8, 0, true },
    { "InventoryType", 0x01, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_LootComponent_Layout = {
    .componentName = "eoc::LootComponent",
    .shortName = "Loot",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_Gen_eoc_LootComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_LootComponent_Properties) / sizeof(g_Gen_eoc_LootComponent_Properties[0]),
};

// ======================================================================
// eoc::LootingStateComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_LootingStateComponent_Properties[] = {
    { "Looter_M", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "State", 0x08, FIELD_TYPE_UINT8, 0, true },
    { "field_24", 0x0c, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_LootingStateComponent_Layout = {
    .componentName = "eoc::LootingStateComponent",
    .shortName = "LootingState",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_eoc_LootingStateComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_LootingStateComponent_Properties) / sizeof(g_Gen_eoc_LootingStateComponent_Properties[0]),
};

// ======================================================================
// eoc::MovementComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x18 (24 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_MovementComponent_Properties[] = {
    { "Direction", 0x00, FIELD_TYPE_VEC3, 0, true },
    { "Acceleration", 0x0c, FIELD_TYPE_FLOAT, 0, true },
    { "Speed", 0x10, FIELD_TYPE_FLOAT, 0, true },
    { "Speed2", 0x14, FIELD_TYPE_FLOAT, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_MovementComponent_Layout = {
    .componentName = "eoc::MovementComponent",
    .shortName = "Movement",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_eoc_MovementComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_MovementComponent_Properties) / sizeof(g_Gen_eoc_MovementComponent_Properties[0]),
};

// ======================================================================
// eoc::ObjectSizeComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x2 (2 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_ObjectSizeComponent_Properties[] = {
    { "Size", 0x00, FIELD_TYPE_INT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_ObjectSizeComponent_Layout = {
    .componentName = "eoc::ObjectSizeComponent",
    .shortName = "ObjectSize",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_Gen_eoc_ObjectSizeComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_ObjectSizeComponent_Properties) / sizeof(g_Gen_eoc_ObjectSizeComponent_Properties[0]),
};

// ======================================================================
// eoc::OriginComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x18 (24 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_OriginComponent_Properties[] = {
    { "field_18", 0x00, FIELD_TYPE_GUID, 0, true },
    { "Origin", 0x10, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_OriginComponent_Layout = {
    .componentName = "eoc::OriginComponent",
    .shortName = "Origin",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_eoc_OriginComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_OriginComponent_Properties) / sizeof(g_Gen_eoc_OriginComponent_Properties[0]),
};

// ======================================================================
// eoc::PassiveComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x20 (32 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_PassiveComponent_Properties[] = {
    { "PassiveId", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "field_1C", 0x1c, FIELD_TYPE_UINT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_PassiveComponent_Layout = {
    .componentName = "eoc::PassiveComponent",
    .shortName = "Passive",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_Gen_eoc_PassiveComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_PassiveComponent_Properties) / sizeof(g_Gen_eoc_PassiveComponent_Properties[0]),
};

// ======================================================================
// eoc::PathingComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x50 (80 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_PathingComponent_Properties[] = {
    { "field_20", 0x20, FIELD_TYPE_VEC3, 0, true },
    { "MovementTiltToRemap", 0x0c, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "field_30", 0x10, FIELD_TYPE_INT64, 0, true },
    { "field_38", 0x38, FIELD_TYPE_INT32, 0, true },
    { "PathId", 0x1c, FIELD_TYPE_INT32, 0, true },
    { "Flags", 0x20, FIELD_TYPE_UINT8, 0, true },
    { "PathMovementSpeed", 0x24, FIELD_TYPE_FLOAT, 0, true },
    { "field_48", 0x48, FIELD_TYPE_INT32, 0, true },
    { "ServerControl", 0x2c, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_PathingComponent_Layout = {
    .componentName = "eoc::PathingComponent",
    .shortName = "Pathing",
    .componentTypeIndex = 0,
    .componentSize = 0x50,
    .properties = g_Gen_eoc_PathingComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_PathingComponent_Properties) / sizeof(g_Gen_eoc_PathingComponent_Properties[0]),
};

// ======================================================================
// eoc::RaceComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_RaceComponent_Properties[] = {
    { "Race", 0x00, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_RaceComponent_Layout = {
    .componentName = "eoc::RaceComponent",
    .shortName = "Race",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_eoc_RaceComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_RaceComponent_Properties) / sizeof(g_Gen_eoc_RaceComponent_Properties[0]),
};

// ======================================================================
// eoc::RequestedRollComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1e0 (480 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_RequestedRollComponent_Properties[] = {
    { "RollEntity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "RollUuid", 0x08, FIELD_TYPE_GUID, 0, true },
    { "RollComponentType", 0x18, FIELD_TYPE_UINT8, 0, true },
    { "RollType", 0x19, FIELD_TYPE_UINT8, 0, true },
    { "NaturalRoll", 0x1a, FIELD_TYPE_UINT8, 0, true },
    { "DiscardedDiceTotal", 0x1b, FIELD_TYPE_UINT8, 0, true },
    { "DiceAdditionalValue", 0x1c, FIELD_TYPE_UINT8, 0, true },
    { "AdditionalValue", 0x20, FIELD_TYPE_INT32, 0, true },
    { "SpellCheck", 0x24, FIELD_TYPE_UINT8, 0, true },
    { "Finished", 0x25, FIELD_TYPE_BOOL, 0, true },
    { "field_4F", 0x26, FIELD_TYPE_UINT8, 0, true },
    { "PassiveRollDelay", 0x28, FIELD_TYPE_FLOAT, 0, true },
    { "RollContext", 0x2c, FIELD_TYPE_UINT8, 0, true },
    { "field_89", 0x2d, FIELD_TYPE_UINT8, 0, true },
    { "field_8A", 0x2e, FIELD_TYPE_UINT8, 0, true },
    { "Ability", 0x2f, FIELD_TYPE_UINT8, 0, true },
    { "Skill", 0x30, FIELD_TYPE_UINT8, 0, true },
    { "EntityUuid", 0x38, FIELD_TYPE_GUID, 0, true },
    { "Entity2Uuid", 0x48, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_RequestedRollComponent_Layout = {
    .componentName = "eoc::RequestedRollComponent",
    .shortName = "RequestedRoll",
    .componentTypeIndex = 0,
    .componentSize = 0x1e0,
    .properties = g_Gen_eoc_RequestedRollComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_RequestedRollComponent_Properties) / sizeof(g_Gen_eoc_RequestedRollComponent_Properties[0]),
};

// ======================================================================
// eoc::ResistancesComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x20 (32 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_ResistancesComponent_Properties[] = {
    { "Resistances", 0x00, FIELD_TYPE_INT32, 0, true },
    { "field_E", 0x0e, FIELD_TYPE_UINT8, 0, true },
    { "AC", 0x08, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_ResistancesComponent_Layout = {
    .componentName = "eoc::ResistancesComponent",
    .shortName = "Resistances",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_Gen_eoc_ResistancesComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_ResistancesComponent_Properties) / sizeof(g_Gen_eoc_ResistancesComponent_Properties[0]),
};

// ======================================================================
// eoc::StatsComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0xa0 (160 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_StatsComponent_Properties[] = {
    { "InitiativeBonus", 0x00, FIELD_TYPE_INT32, 0, true },
    { "ProficiencyBonus", 0x04, FIELD_TYPE_INT32, 0, true },
    { "SpellCastingAbility", 0x08, FIELD_TYPE_UINT8, 0, true },
    { "field_8C", 0x0c, FIELD_TYPE_INT32, 0, true },
    { "field_90", 0x10, FIELD_TYPE_INT32, 0, true },
    { "ArmorType", 0x14, FIELD_TYPE_INT32, 0, true },
    { "ArmorType2", 0x18, FIELD_TYPE_INT32, 0, true },
    { "UnarmedAttackAbility", 0x1c, FIELD_TYPE_UINT8, 0, true },
    { "RangedAttackAbility", 0x1d, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_StatsComponent_Layout = {
    .componentName = "eoc::StatsComponent",
    .shortName = "Stats",
    .componentTypeIndex = 0,
    .componentSize = 0xa0,
    .properties = g_Gen_eoc_StatsComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_StatsComponent_Properties) / sizeof(g_Gen_eoc_StatsComponent_Properties[0]),
};

// ======================================================================
// eoc::StealthComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x24 (36 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_StealthComponent_Properties[] = {
    { "SeekHiddenFlag", 0x00, FIELD_TYPE_BOOL, 0, true },
    { "Position", 0x08, FIELD_TYPE_VEC3, 0, true },
    { "SeekHiddenTimeout", 0x14, FIELD_TYPE_FLOAT, 0, true },
    { "field_14", 0x14, FIELD_TYPE_FLOAT, 0, true },
    { "field_18", 0x18, FIELD_TYPE_INT32, 0, true },
    { "field_1C", 0x1c, FIELD_TYPE_FLOAT, 0, true },
    { "field_20", 0x20, FIELD_TYPE_FLOAT, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_StealthComponent_Layout = {
    .componentName = "eoc::StealthComponent",
    .shortName = "Stealth",
    .componentTypeIndex = 0,
    .componentSize = 0x24,
    .properties = g_Gen_eoc_StealthComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_StealthComponent_Properties) / sizeof(g_Gen_eoc_StealthComponent_Properties[0]),
};

// ======================================================================
// eoc::SteeringComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x20 (32 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_SteeringComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_VEC3, 0, true },
    { "field_18", 0x18, FIELD_TYPE_FLOAT, 0, true },
    { "field_1C", 0x1c, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_SteeringComponent_Layout = {
    .componentName = "eoc::SteeringComponent",
    .shortName = "Steering",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_Gen_eoc_SteeringComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_SteeringComponent_Properties) / sizeof(g_Gen_eoc_SteeringComponent_Properties[0]),
};

// ======================================================================
// eoc::TimelineActorDataComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x28 (40 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_TimelineActorDataComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_GUID, 0, true },
    { "field_10", 0x10, FIELD_TYPE_GUID, 0, true },
    { "field_20", 0x20, FIELD_TYPE_UINT16, 0, true },
    { "field_22", 0x22, FIELD_TYPE_UINT8, 0, true },
    { "field_23", 0x23, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_TimelineActorDataComponent_Layout = {
    .componentName = "eoc::TimelineActorDataComponent",
    .shortName = "TimelineActorData",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_Gen_eoc_TimelineActorDataComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_TimelineActorDataComponent_Properties) / sizeof(g_Gen_eoc_TimelineActorDataComponent_Properties[0]),
};

// ======================================================================
// eoc::TurnBasedComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x30 (48 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_TurnBasedComponent_Properties[] = {
    { "RequestedEndTurn", 0x00, FIELD_TYPE_BOOL, 0, true },
    { "ActedThisRoundInCombat", 0x01, FIELD_TYPE_BOOL, 0, true },
    { "HadTurnInCombat", 0x02, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_TurnBasedComponent_Layout = {
    .componentName = "eoc::TurnBasedComponent",
    .shortName = "TurnBased",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_Gen_eoc_TurnBasedComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_TurnBasedComponent_Properties) / sizeof(g_Gen_eoc_TurnBasedComponent_Properties[0]),
};

// ======================================================================
// eoc::TurnOrderComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x50 (80 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_TurnOrderComponent_Properties[] = {
    { "field_40", 0x40, FIELD_TYPE_INT32, 0, true },
    { "field_44", 0x44, FIELD_TYPE_INT32, 0, true },
    { "field_48", 0x48, FIELD_TYPE_INT32, 0, true },
    { "field_4C", 0x4c, FIELD_TYPE_FLOAT, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_TurnOrderComponent_Layout = {
    .componentName = "eoc::TurnOrderComponent",
    .shortName = "TurnOrder",
    .componentTypeIndex = 0,
    .componentSize = 0x50,
    .properties = g_Gen_eoc_TurnOrderComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_TurnOrderComponent_Properties) / sizeof(g_Gen_eoc_TurnOrderComponent_Properties[0]),
};

// ======================================================================
// eoc::UseComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x50 (80 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_UseComponent_Properties[] = {
    { "Charges", 0x00, FIELD_TYPE_INT32, 0, true },
    { "MaxCharges", 0x04, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_UseComponent_Layout = {
    .componentName = "eoc::UseComponent",
    .shortName = "Use",
    .componentTypeIndex = 0,
    .componentSize = 0x50,
    .properties = g_Gen_eoc_UseComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_UseComponent_Properties) / sizeof(g_Gen_eoc_UseComponent_Properties[0]),
};

// ======================================================================
// eoc::ValueComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_ValueComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_INT32, 0, true },
    { "Rarity", 0x04, FIELD_TYPE_UINT8, 0, true },
    { "Unique", 0x05, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_ValueComponent_Layout = {
    .componentName = "eoc::ValueComponent",
    .shortName = "Value",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_ValueComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_ValueComponent_Properties) / sizeof(g_Gen_eoc_ValueComponent_Properties[0]),
};

// ======================================================================
// eoc::VoiceComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_VoiceComponent_Properties[] = {
    { "Voice", 0x00, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_VoiceComponent_Layout = {
    .componentName = "eoc::VoiceComponent",
    .shortName = "Voice",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_eoc_VoiceComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_VoiceComponent_Properties) / sizeof(g_Gen_eoc_VoiceComponent_Properties[0]),
};

// ======================================================================
// eoc::WeaponComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x50 (80 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_WeaponComponent_Properties[] = {
    { "WeaponRange", 0x00, FIELD_TYPE_FLOAT, 0, true },
    { "DamageRange", 0x04, FIELD_TYPE_FLOAT, 0, true },
    { "WeaponProperties", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "WeaponGroup", 0x0c, FIELD_TYPE_UINT8, 0, true },
    { "Ability", 0x0d, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_WeaponComponent_Layout = {
    .componentName = "eoc::WeaponComponent",
    .shortName = "Weapon",
    .componentTypeIndex = 0,
    .componentSize = 0x50,
    .properties = g_Gen_eoc_WeaponComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_WeaponComponent_Properties) / sizeof(g_Gen_eoc_WeaponComponent_Properties[0]),
};

// ======================================================================
// eoc::WieldingComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_WieldingComponent_Properties[] = {
    { "Owner", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_WieldingComponent_Layout = {
    .componentName = "eoc::WieldingComponent",
    .shortName = "Wielding",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_WieldingComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_WieldingComponent_Properties) / sizeof(g_Gen_eoc_WieldingComponent_Properties[0]),
};

// ======================================================================
// eoc::active_roll::ModifiersComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x90 (144 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_active_roll_ModifiersComponent_Properties[] = {
    { "field_18", 0x18, FIELD_TYPE_UINT8, 0, true },
    { "field_19", 0x19, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_active_roll_ModifiersComponent_Layout = {
    .componentName = "eoc::active_roll::ModifiersComponent",
    .shortName = "Modifiers",
    .componentTypeIndex = 0,
    .componentSize = 0x90,
    .properties = g_Gen_eoc_active_roll_ModifiersComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_active_roll_ModifiersComponent_Properties) / sizeof(g_Gen_eoc_active_roll_ModifiersComponent_Properties[0]),
};

// ======================================================================
// eoc::calendar::DaysPassedComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_calendar_DaysPassedComponent_Properties[] = {
    { "Days", 0x00, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_calendar_DaysPassedComponent_Layout = {
    .componentName = "eoc::calendar::DaysPassedComponent",
    .shortName = "DaysPassed",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_calendar_DaysPassedComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_calendar_DaysPassedComponent_Properties) / sizeof(g_Gen_eoc_calendar_DaysPassedComponent_Properties[0]),
};

// ======================================================================
// eoc::calendar::StartingDateComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_calendar_StartingDateComponent_Properties[] = {
    { "Day", 0x00, FIELD_TYPE_INT32, 0, true },
    { "Year", 0x04, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_calendar_StartingDateComponent_Layout = {
    .componentName = "eoc::calendar::StartingDateComponent",
    .shortName = "StartingDate",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_calendar_StartingDateComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_calendar_StartingDateComponent_Properties) / sizeof(g_Gen_eoc_calendar_StartingDateComponent_Properties[0]),
};

// ======================================================================
// eoc::camp::ChestComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x28 (40 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_camp_ChestComponent_Properties[] = {
    { "UserID", 0x10, FIELD_TYPE_INT32, 0, true },
    { "field_1C", 0x14, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "field_20", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "field_28", 0x20, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_camp_ChestComponent_Layout = {
    .componentName = "eoc::camp::ChestComponent",
    .shortName = "Chest",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_Gen_eoc_camp_ChestComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_camp_ChestComponent_Properties) / sizeof(g_Gen_eoc_camp_ChestComponent_Properties[0]),
};

// ======================================================================
// eoc::camp::EndTheDayStateComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_camp_EndTheDayStateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_UINT8, 0, true },
    { "field_8", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_camp_EndTheDayStateComponent_Layout = {
    .componentName = "eoc::camp::EndTheDayStateComponent",
    .shortName = "EndTheDayState",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_eoc_camp_EndTheDayStateComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_camp_EndTheDayStateComponent_Properties) / sizeof(g_Gen_eoc_camp_EndTheDayStateComponent_Properties[0]),
};

// ======================================================================
// eoc::camp::QualityComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_camp_QualityComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, true },
    { "field_4", 0x04, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_camp_QualityComponent_Layout = {
    .componentName = "eoc::camp::QualityComponent",
    .shortName = "Quality",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_camp_QualityComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_camp_QualityComponent_Properties) / sizeof(g_Gen_eoc_camp_QualityComponent_Properties[0]),
};

// ======================================================================
// eoc::camp::SettingsComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_camp_SettingsComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, true },
    { "field_1", 0x01, FIELD_TYPE_UINT8, 0, true },
    { "field_4", 0x04, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_camp_SettingsComponent_Layout = {
    .componentName = "eoc::camp::SettingsComponent",
    .shortName = "Settings",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_camp_SettingsComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_camp_SettingsComponent_Properties) / sizeof(g_Gen_eoc_camp_SettingsComponent_Properties[0]),
};

// ======================================================================
// eoc::camp::SupplyComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_camp_SupplyComponent_Properties[] = {
    { "Amount", 0x00, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_camp_SupplyComponent_Layout = {
    .componentName = "eoc::camp::SupplyComponent",
    .shortName = "Supply",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_camp_SupplyComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_camp_SupplyComponent_Properties) / sizeof(g_Gen_eoc_camp_SupplyComponent_Properties[0]),
};

// ======================================================================
// eoc::camp::TotalSuppliesComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_camp_TotalSuppliesComponent_Properties[] = {
    { "Amount", 0x00, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_camp_TotalSuppliesComponent_Layout = {
    .componentName = "eoc::camp::TotalSuppliesComponent",
    .shortName = "TotalSupplies",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_camp_TotalSuppliesComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_camp_TotalSuppliesComponent_Properties) / sizeof(g_Gen_eoc_camp_TotalSuppliesComponent_Properties[0]),
};

// ======================================================================
// eoc::character::EquipmentVisualComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1 (1 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_character_EquipmentVisualComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_character_EquipmentVisualComponent_Layout = {
    .componentName = "eoc::character::EquipmentVisualComponent",
    .shortName = "EquipmentVisual",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_eoc_character_EquipmentVisualComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_character_EquipmentVisualComponent_Properties) / sizeof(g_Gen_eoc_character_EquipmentVisualComponent_Properties[0]),
};

// ======================================================================
// eoc::character_creation::AppearanceComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x70 (112 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_character_creation_AppearanceComponent_Properties[] = {
    { "SkinColor", 0x00, FIELD_TYPE_GUID, 0, true },
    { "EyeColor", 0x10, FIELD_TYPE_GUID, 0, true },
    { "SecondEyeColor", 0x20, FIELD_TYPE_GUID, 0, true },
    { "HairColor", 0x30, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_character_creation_AppearanceComponent_Layout = {
    .componentName = "eoc::character_creation::AppearanceComponent",
    .shortName = "Appearance",
    .componentTypeIndex = 0,
    .componentSize = 0x70,
    .properties = g_Gen_eoc_character_creation_AppearanceComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_character_creation_AppearanceComponent_Properties) / sizeof(g_Gen_eoc_character_creation_AppearanceComponent_Properties[0]),
};

// ======================================================================
// eoc::character_creation::ChangeAppearanceDefinitionComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x2e0 (736 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_character_creation_ChangeAppearanceDefinitionComponent_Properties[] = {
    { "field_2E0", 0x00, FIELD_TYPE_INT32, 0, true },
    { "field_2E4", 0x04, FIELD_TYPE_UINT8, 0, true },
    { "field_2E8", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_character_creation_ChangeAppearanceDefinitionComponent_Layout = {
    .componentName = "eoc::character_creation::ChangeAppearanceDefinitionComponent",
    .shortName = "ChangeAppearanceDefinition",
    .componentTypeIndex = 0,
    .componentSize = 0x2e0,
    .properties = g_Gen_eoc_character_creation_ChangeAppearanceDefinitionComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_character_creation_ChangeAppearanceDefinitionComponent_Properties) / sizeof(g_Gen_eoc_character_creation_ChangeAppearanceDefinitionComponent_Properties[0]),
};

// ======================================================================
// eoc::character_creation::CharacterDefinitionComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x290 (656 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_character_creation_CharacterDefinitionComponent_Properties[] = {
    { "field_288", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_character_creation_CharacterDefinitionComponent_Layout = {
    .componentName = "eoc::character_creation::CharacterDefinitionComponent",
    .shortName = "CharacterDefinition",
    .componentTypeIndex = 0,
    .componentSize = 0x290,
    .properties = g_Gen_eoc_character_creation_CharacterDefinitionComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_character_creation_CharacterDefinitionComponent_Properties) / sizeof(g_Gen_eoc_character_creation_CharacterDefinitionComponent_Properties[0]),
};

// ======================================================================
// eoc::character_creation::CompanionDefinitionComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x140 (320 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_character_creation_CompanionDefinitionComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_GUID, 0, true },
    { "field_10", 0x10, FIELD_TYPE_GUID, 0, true },
    { "field_20", 0x20, FIELD_TYPE_UINT8, 0, true },
    { "field_21", 0x21, FIELD_TYPE_UINT8, 0, true },
    { "field_28", 0x28, FIELD_TYPE_GUID, 0, true },
    { "field_110", 0x38, FIELD_TYPE_GUID, 0, true },
    { "field_120", 0x48, FIELD_TYPE_GUID, 0, true },
    { "field_130", 0x58, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_character_creation_CompanionDefinitionComponent_Layout = {
    .componentName = "eoc::character_creation::CompanionDefinitionComponent",
    .shortName = "CompanionDefinition",
    .componentTypeIndex = 0,
    .componentSize = 0x140,
    .properties = g_Gen_eoc_character_creation_CompanionDefinitionComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_character_creation_CompanionDefinitionComponent_Properties) / sizeof(g_Gen_eoc_character_creation_CompanionDefinitionComponent_Properties[0]),
};

// ======================================================================
// eoc::character_creation::DefinitionCommonComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0xc0 (192 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_character_creation_DefinitionCommonComponent_Properties[] = {
    { "field_8", 0x00, FIELD_TYPE_INT64, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_character_creation_DefinitionCommonComponent_Layout = {
    .componentName = "eoc::character_creation::DefinitionCommonComponent",
    .shortName = "DefinitionCommon",
    .componentTypeIndex = 0,
    .componentSize = 0xc0,
    .properties = g_Gen_eoc_character_creation_DefinitionCommonComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_character_creation_DefinitionCommonComponent_Properties) / sizeof(g_Gen_eoc_character_creation_DefinitionCommonComponent_Properties[0]),
};

// ======================================================================
// eoc::character_creation::FullRespecDefinitionComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x268 (616 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_character_creation_FullRespecDefinitionComponent_Properties[] = {
    { "field_1C0", 0x00, FIELD_TYPE_GUID, 0, true },
    { "field_1D0", 0x10, FIELD_TYPE_GUID, 0, true },
    { "field_1E0", 0x20, FIELD_TYPE_INT32, 0, true },
    { "field_268", 0x24, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_character_creation_FullRespecDefinitionComponent_Layout = {
    .componentName = "eoc::character_creation::FullRespecDefinitionComponent",
    .shortName = "FullRespecDefinition",
    .componentTypeIndex = 0,
    .componentSize = 0x268,
    .properties = g_Gen_eoc_character_creation_FullRespecDefinitionComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_character_creation_FullRespecDefinitionComponent_Properties) / sizeof(g_Gen_eoc_character_creation_FullRespecDefinitionComponent_Properties[0]),
};

// ======================================================================
// eoc::character_creation::LevelUpDefinitionComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x330 (816 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_character_creation_LevelUpDefinitionComponent_Properties[] = {
    { "field_160", 0x00, FIELD_TYPE_UINT8, 0, true },
    { "field_16C", 0x04, FIELD_TYPE_INT32, 0, true },
    { "Character", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_character_creation_LevelUpDefinitionComponent_Layout = {
    .componentName = "eoc::character_creation::LevelUpDefinitionComponent",
    .shortName = "LevelUpDefinition",
    .componentTypeIndex = 0,
    .componentSize = 0x330,
    .properties = g_Gen_eoc_character_creation_LevelUpDefinitionComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_character_creation_LevelUpDefinitionComponent_Properties) / sizeof(g_Gen_eoc_character_creation_LevelUpDefinitionComponent_Properties[0]),
};

// ======================================================================
// eoc::character_creation::RespecDefinitionComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x298 (664 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_character_creation_RespecDefinitionComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_GUID, 0, true },
    { "field_298", 0x10, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_character_creation_RespecDefinitionComponent_Layout = {
    .componentName = "eoc::character_creation::RespecDefinitionComponent",
    .shortName = "RespecDefinition",
    .componentTypeIndex = 0,
    .componentSize = 0x298,
    .properties = g_Gen_eoc_character_creation_RespecDefinitionComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_character_creation_RespecDefinitionComponent_Properties) / sizeof(g_Gen_eoc_character_creation_RespecDefinitionComponent_Properties[0]),
};

// ======================================================================
// eoc::character_creation::SessionCommonComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0xc (12 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_character_creation_SessionCommonComponent_Properties[] = {
    { "NetId", 0x00, FIELD_TYPE_INT32, 0, true },
    { "field_4", 0x04, FIELD_TYPE_INT32, 0, true },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_character_creation_SessionCommonComponent_Layout = {
    .componentName = "eoc::character_creation::SessionCommonComponent",
    .shortName = "SessionCommon",
    .componentTypeIndex = 0,
    .componentSize = 0xc,
    .properties = g_Gen_eoc_character_creation_SessionCommonComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_character_creation_SessionCommonComponent_Properties) / sizeof(g_Gen_eoc_character_creation_SessionCommonComponent_Properties[0]),
};

// ======================================================================
// eoc::character_creation::StateComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x3 (3 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_character_creation_StateComponent_Properties[] = {
    { "HasDummy", 0x00, FIELD_TYPE_BOOL, 0, true },
    { "Canceled", 0x01, FIELD_TYPE_BOOL, 0, true },
    { "field_2", 0x02, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_character_creation_StateComponent_Layout = {
    .componentName = "eoc::character_creation::StateComponent",
    .shortName = "State",
    .componentTypeIndex = 0,
    .componentSize = 0x3,
    .properties = g_Gen_eoc_character_creation_StateComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_character_creation_StateComponent_Properties) / sizeof(g_Gen_eoc_character_creation_StateComponent_Properties[0]),
};

// ======================================================================
// eoc::character_creation::definition::CreationComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x18 (24 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_character_creation_definition_CreationComponent_Properties[] = {
    { "field_10", 0x10, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_character_creation_definition_CreationComponent_Layout = {
    .componentName = "eoc::character_creation::definition::CreationComponent",
    .shortName = "Creation",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_eoc_character_creation_definition_CreationComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_character_creation_definition_CreationComponent_Properties) / sizeof(g_Gen_eoc_character_creation_definition_CreationComponent_Properties[0]),
};

// ======================================================================
// eoc::character_creation::definition::LevelUpComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x18 (24 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_character_creation_definition_LevelUpComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "field_8", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "field_10", 0x10, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_character_creation_definition_LevelUpComponent_Layout = {
    .componentName = "eoc::character_creation::definition::LevelUpComponent",
    .shortName = "LevelUp",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_eoc_character_creation_definition_LevelUpComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_character_creation_definition_LevelUpComponent_Properties) / sizeof(g_Gen_eoc_character_creation_definition_LevelUpComponent_Properties[0]),
};

// ======================================================================
// eoc::chasm::CanEnterChasmComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1 (1 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_chasm_CanEnterChasmComponent_Properties[] = {
    { "CanEnter", 0x00, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_chasm_CanEnterChasmComponent_Layout = {
    .componentName = "eoc::chasm::CanEnterChasmComponent",
    .shortName = "CanEnterChasm",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_eoc_chasm_CanEnterChasmComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_chasm_CanEnterChasmComponent_Properties) / sizeof(g_Gen_eoc_chasm_CanEnterChasmComponent_Properties[0]),
};

// ======================================================================
// eoc::combat::ParticipantComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x28 (40 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_combat_ParticipantComponent_Properties[] = {
    { "CombatHandle", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "CombatGroupId", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "AiHint", 0x10, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_combat_ParticipantComponent_Layout = {
    .componentName = "eoc::combat::ParticipantComponent",
    .shortName = "Participant",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_Gen_eoc_combat_ParticipantComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_combat_ParticipantComponent_Properties) / sizeof(g_Gen_eoc_combat_ParticipantComponent_Properties[0]),
};

// ======================================================================
// eoc::combat::StateComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x98 (152 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_combat_StateComponent_Properties[] = {
    { "MyGuid", 0x00, FIELD_TYPE_GUID, 0, true },
    { "field_98", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "field_A0", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Level", 0x20, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "field_AC", 0x24, FIELD_TYPE_UINT8, 0, true },
    { "IsInNarrativeCombat", 0x25, FIELD_TYPE_BOOL, 0, true },
    { "field_B0", 0x28, FIELD_TYPE_FLOAT, 0, true },
    { "field_D0", 0x2c, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_combat_StateComponent_Layout = {
    .componentName = "eoc::combat::StateComponent",
    .shortName = "State",
    .componentTypeIndex = 0,
    .componentSize = 0x98,
    .properties = g_Gen_eoc_combat_StateComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_combat_StateComponent_Properties) / sizeof(g_Gen_eoc_combat_StateComponent_Properties[0]),
};

// ======================================================================
// eoc::combat::ThreatRangeComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0xc (12 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_combat_ThreatRangeComponent_Properties[] = {
    { "Range", 0x00, FIELD_TYPE_FLOAT, 0, true },
    { "TargetCeiling", 0x04, FIELD_TYPE_FLOAT, 0, true },
    { "TargetFloor", 0x08, FIELD_TYPE_FLOAT, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_combat_ThreatRangeComponent_Layout = {
    .componentName = "eoc::combat::ThreatRangeComponent",
    .shortName = "ThreatRange",
    .componentTypeIndex = 0,
    .componentSize = 0xc,
    .properties = g_Gen_eoc_combat_ThreatRangeComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_combat_ThreatRangeComponent_Properties) / sizeof(g_Gen_eoc_combat_ThreatRangeComponent_Properties[0]),
};

// ======================================================================
// eoc::death::DeadByDefaultComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1 (1 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_death_DeadByDefaultComponent_Properties[] = {
    { "DeadByDefault", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_death_DeadByDefaultComponent_Layout = {
    .componentName = "eoc::death::DeadByDefaultComponent",
    .shortName = "DeadByDefault",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_eoc_death_DeadByDefaultComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_death_DeadByDefaultComponent_Properties) / sizeof(g_Gen_eoc_death_DeadByDefaultComponent_Properties[0]),
};

// ======================================================================
// eoc::death::DeathTypeComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1 (1 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_death_DeathTypeComponent_Properties[] = {
    { "DeathType", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_death_DeathTypeComponent_Layout = {
    .componentName = "eoc::death::DeathTypeComponent",
    .shortName = "DeathType",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_eoc_death_DeathTypeComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_death_DeathTypeComponent_Properties) / sizeof(g_Gen_eoc_death_DeathTypeComponent_Properties[0]),
};

// ======================================================================
// eoc::death::DownedComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x18 (24 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_death_DownedComponent_Properties[] = {
    { "DownedStatus", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Entity", 0x08, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_death_DownedComponent_Layout = {
    .componentName = "eoc::death::DownedComponent",
    .shortName = "Downed",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_eoc_death_DownedComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_death_DownedComponent_Properties) / sizeof(g_Gen_eoc_death_DownedComponent_Properties[0]),
};

// ======================================================================
// eoc::death::StateComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_death_StateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_UINT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_death_StateComponent_Layout = {
    .componentName = "eoc::death::StateComponent",
    .shortName = "State",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_death_StateComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_death_StateComponent_Properties) / sizeof(g_Gen_eoc_death_StateComponent_Properties[0]),
};

// ======================================================================
// eoc::dialog::StateComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0xc (12 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_dialog_StateComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, true },
    { "field_1", 0x01, FIELD_TYPE_UINT8, 0, true },
    { "field_2", 0x02, FIELD_TYPE_UINT8, 0, true },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_dialog_StateComponent_Layout = {
    .componentName = "eoc::dialog::StateComponent",
    .shortName = "State",
    .componentTypeIndex = 0,
    .componentSize = 0xc,
    .properties = g_Gen_eoc_dialog_StateComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_dialog_StateComponent_Properties) / sizeof(g_Gen_eoc_dialog_StateComponent_Properties[0]),
};

// ======================================================================
// eoc::encumbrance::StateComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_encumbrance_StateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_UINT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_encumbrance_StateComponent_Layout = {
    .componentName = "eoc::encumbrance::StateComponent",
    .shortName = "State",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_encumbrance_StateComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_encumbrance_StateComponent_Properties) / sizeof(g_Gen_eoc_encumbrance_StateComponent_Properties[0]),
};

// ======================================================================
// eoc::exp::AvailableLevelComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_exp_AvailableLevelComponent_Properties[] = {
    { "Level", 0x00, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_exp_AvailableLevelComponent_Layout = {
    .componentName = "eoc::exp::AvailableLevelComponent",
    .shortName = "AvailableLevel",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_exp_AvailableLevelComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_exp_AvailableLevelComponent_Properties) / sizeof(g_Gen_eoc_exp_AvailableLevelComponent_Properties[0]),
};

// ======================================================================
// eoc::exp::ExperienceComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_exp_ExperienceComponent_Properties[] = {
    { "CurrentLevelExperience", 0x00, FIELD_TYPE_INT32, 0, true },
    { "NextLevelExperience", 0x04, FIELD_TYPE_INT32, 0, true },
    { "TotalExperience", 0x08, FIELD_TYPE_INT32, 0, true },
    { "field_28", 0x0c, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_exp_ExperienceComponent_Layout = {
    .componentName = "eoc::exp::ExperienceComponent",
    .shortName = "Experience",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_eoc_exp_ExperienceComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_exp_ExperienceComponent_Properties) / sizeof(g_Gen_eoc_exp_ExperienceComponent_Properties[0]),
};

// ======================================================================
// eoc::ftb::ParticipantComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_ftb_ParticipantComponent_Properties[] = {
    { "field_18", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_ftb_ParticipantComponent_Layout = {
    .componentName = "eoc::ftb::ParticipantComponent",
    .shortName = "Participant",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_ftb_ParticipantComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_ftb_ParticipantComponent_Properties) / sizeof(g_Gen_eoc_ftb_ParticipantComponent_Properties[0]),
};

// ======================================================================
// eoc::ftb::ZoneBlockReasonComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1 (1 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_ftb_ZoneBlockReasonComponent_Properties[] = {
    { "Reason", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_ftb_ZoneBlockReasonComponent_Layout = {
    .componentName = "eoc::ftb::ZoneBlockReasonComponent",
    .shortName = "ZoneBlockReason",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_eoc_ftb_ZoneBlockReasonComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_ftb_ZoneBlockReasonComponent_Properties) / sizeof(g_Gen_eoc_ftb_ZoneBlockReasonComponent_Properties[0]),
};

// ======================================================================
// eoc::god::GodComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x28 (40 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_god_GodComponent_Properties[] = {
    { "God", 0x00, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_god_GodComponent_Layout = {
    .componentName = "eoc::god::GodComponent",
    .shortName = "God",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_Gen_eoc_god_GodComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_god_GodComponent_Properties) / sizeof(g_Gen_eoc_god_GodComponent_Properties[0]),
};

// ======================================================================
// eoc::hit::AttackerComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x8 (8 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_hit_AttackerComponent_Properties[] = {
    { "Attacker", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_hit_AttackerComponent_Layout = {
    .componentName = "eoc::hit::AttackerComponent",
    .shortName = "Attacker",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_hit_AttackerComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_hit_AttackerComponent_Properties) / sizeof(g_Gen_eoc_hit_AttackerComponent_Properties[0]),
};

// ======================================================================
// eoc::hit::LifetimeComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_hit_LifetimeComponent_Properties[] = {
    { "Lifetime", 0x00, FIELD_TYPE_FLOAT, 0, true },
    { "field_4", 0x04, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_hit_LifetimeComponent_Layout = {
    .componentName = "eoc::hit::LifetimeComponent",
    .shortName = "Lifetime",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_hit_LifetimeComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_hit_LifetimeComponent_Properties) / sizeof(g_Gen_eoc_hit_LifetimeComponent_Properties[0]),
};

// ======================================================================
// eoc::hit::MetaComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_hit_MetaComponent_Properties[] = {
    { "HitGuid", 0x00, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_hit_MetaComponent_Layout = {
    .componentName = "eoc::hit::MetaComponent",
    .shortName = "Meta",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_eoc_hit_MetaComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_hit_MetaComponent_Properties) / sizeof(g_Gen_eoc_hit_MetaComponent_Properties[0]),
};

// ======================================================================
// eoc::hit::ProxyComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_hit_ProxyComponent_Properties[] = {
    { "Owner", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "field_8", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_hit_ProxyComponent_Layout = {
    .componentName = "eoc::hit::ProxyComponent",
    .shortName = "Proxy",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_eoc_hit_ProxyComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_hit_ProxyComponent_Properties) / sizeof(g_Gen_eoc_hit_ProxyComponent_Properties[0]),
};

// ======================================================================
// eoc::hit::TargetComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x18 (24 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_hit_TargetComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "field_8", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_hit_TargetComponent_Layout = {
    .componentName = "eoc::hit::TargetComponent",
    .shortName = "Target",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_eoc_hit_TargetComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_hit_TargetComponent_Properties) / sizeof(g_Gen_eoc_hit_TargetComponent_Properties[0]),
};

// ======================================================================
// eoc::hit::ThrownObjectComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x8 (8 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_hit_ThrownObjectComponent_Properties[] = {
    { "ThrownObject", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_hit_ThrownObjectComponent_Layout = {
    .componentName = "eoc::hit::ThrownObjectComponent",
    .shortName = "ThrownObject",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_hit_ThrownObjectComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_hit_ThrownObjectComponent_Properties) / sizeof(g_Gen_eoc_hit_ThrownObjectComponent_Properties[0]),
};

// ======================================================================
// eoc::hit::WeaponComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x8 (8 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_hit_WeaponComponent_Properties[] = {
    { "Weapon", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_hit_WeaponComponent_Layout = {
    .componentName = "eoc::hit::WeaponComponent",
    .shortName = "Weapon",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_hit_WeaponComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_hit_WeaponComponent_Properties) / sizeof(g_Gen_eoc_hit_WeaponComponent_Properties[0]),
};

// ======================================================================
// eoc::hotbar::ContainerComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x48 (72 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_hotbar_ContainerComponent_Properties[] = {
    { "ActiveContainer", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_hotbar_ContainerComponent_Layout = {
    .componentName = "eoc::hotbar::ContainerComponent",
    .shortName = "Container",
    .componentTypeIndex = 0,
    .componentSize = 0x48,
    .properties = g_Gen_eoc_hotbar_ContainerComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_hotbar_ContainerComponent_Properties) / sizeof(g_Gen_eoc_hotbar_ContainerComponent_Properties[0]),
};

// ======================================================================
// eoc::identity::IdentityComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1 (1 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_identity_IdentityComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_identity_IdentityComponent_Layout = {
    .componentName = "eoc::identity::IdentityComponent",
    .shortName = "Identity",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_eoc_identity_IdentityComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_identity_IdentityComponent_Properties) / sizeof(g_Gen_eoc_identity_IdentityComponent_Properties[0]),
};

// ======================================================================
// eoc::identity::OriginalIdentityComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1 (1 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_identity_OriginalIdentityComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_identity_OriginalIdentityComponent_Layout = {
    .componentName = "eoc::identity::OriginalIdentityComponent",
    .shortName = "OriginalIdentity",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_eoc_identity_OriginalIdentityComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_identity_OriginalIdentityComponent_Properties) / sizeof(g_Gen_eoc_identity_OriginalIdentityComponent_Properties[0]),
};

// ======================================================================
// eoc::improvised_weapon::WieldedComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_improvised_weapon_WieldedComponent_Properties[] = {
    { "Wielder", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, true },
    { "field_9", 0x09, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_improvised_weapon_WieldedComponent_Layout = {
    .componentName = "eoc::improvised_weapon::WieldedComponent",
    .shortName = "Wielded",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_eoc_improvised_weapon_WieldedComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_improvised_weapon_WieldedComponent_Properties) / sizeof(g_Gen_eoc_improvised_weapon_WieldedComponent_Properties[0]),
};

// ======================================================================
// eoc::improvised_weapon::WieldingComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_improvised_weapon_WieldingComponent_Properties[] = {
    { "Weapon", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_improvised_weapon_WieldingComponent_Layout = {
    .componentName = "eoc::improvised_weapon::WieldingComponent",
    .shortName = "Wielding",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_improvised_weapon_WieldingComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_improvised_weapon_WieldingComponent_Properties) / sizeof(g_Gen_eoc_improvised_weapon_WieldingComponent_Properties[0]),
};

// ======================================================================
// eoc::interrupt::ActionStateComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x128 (296 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_interrupt_ActionStateComponent_Properties[] = {
    { "SpellCastGuid", 0x00, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_interrupt_ActionStateComponent_Layout = {
    .componentName = "eoc::interrupt::ActionStateComponent",
    .shortName = "ActionState",
    .componentTypeIndex = 0,
    .componentSize = 0x128,
    .properties = g_Gen_eoc_interrupt_ActionStateComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_interrupt_ActionStateComponent_Properties) / sizeof(g_Gen_eoc_interrupt_ActionStateComponent_Properties[0]),
};

// ======================================================================
// eoc::interrupt::ConditionallyDisabledComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1 (1 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_interrupt_ConditionallyDisabledComponent_Properties[] = {
    { "Dummy", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_interrupt_ConditionallyDisabledComponent_Layout = {
    .componentName = "eoc::interrupt::ConditionallyDisabledComponent",
    .shortName = "ConditionallyDisabled",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_eoc_interrupt_ConditionallyDisabledComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_interrupt_ConditionallyDisabledComponent_Properties) / sizeof(g_Gen_eoc_interrupt_ConditionallyDisabledComponent_Properties[0]),
};

// ======================================================================
// eoc::interrupt::DataComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x20 (32 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_interrupt_DataComponent_Properties[] = {
    { "Interrupt", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "field_4", 0x04, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_interrupt_DataComponent_Layout = {
    .componentName = "eoc::interrupt::DataComponent",
    .shortName = "Data",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_Gen_eoc_interrupt_DataComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_interrupt_DataComponent_Properties) / sizeof(g_Gen_eoc_interrupt_DataComponent_Properties[0]),
};

// ======================================================================
// eoc::interrupt::PreparedComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1 (1 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_interrupt_PreparedComponent_Properties[] = {
    { "Dummy", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_interrupt_PreparedComponent_Layout = {
    .componentName = "eoc::interrupt::PreparedComponent",
    .shortName = "Prepared",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_eoc_interrupt_PreparedComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_interrupt_PreparedComponent_Properties) / sizeof(g_Gen_eoc_interrupt_PreparedComponent_Properties[0]),
};

// ======================================================================
// eoc::interrupt::ZoneComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_interrupt_ZoneComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_interrupt_ZoneComponent_Layout = {
    .componentName = "eoc::interrupt::ZoneComponent",
    .shortName = "Zone",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_eoc_interrupt_ZoneComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_interrupt_ZoneComponent_Properties) / sizeof(g_Gen_eoc_interrupt_ZoneComponent_Properties[0]),
};

// ======================================================================
// eoc::interrupt::ZoneSourceComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1 (1 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_interrupt_ZoneSourceComponent_Properties[] = {
    { "Dummy", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_interrupt_ZoneSourceComponent_Layout = {
    .componentName = "eoc::interrupt::ZoneSourceComponent",
    .shortName = "ZoneSource",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_eoc_interrupt_ZoneSourceComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_interrupt_ZoneSourceComponent_Properties) / sizeof(g_Gen_eoc_interrupt_ZoneSourceComponent_Properties[0]),
};

// ======================================================================
// eoc::inventory::IsOwnedComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_inventory_IsOwnedComponent_Properties[] = {
    { "Owner", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_inventory_IsOwnedComponent_Layout = {
    .componentName = "eoc::inventory::IsOwnedComponent",
    .shortName = "IsOwned",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_inventory_IsOwnedComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_inventory_IsOwnedComponent_Properties) / sizeof(g_Gen_eoc_inventory_IsOwnedComponent_Properties[0]),
};

// ======================================================================
// eoc::inventory::MemberComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_inventory_MemberComponent_Properties[] = {
    { "Inventory", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "EquipmentSlot", 0x08, FIELD_TYPE_INT16, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_inventory_MemberComponent_Layout = {
    .componentName = "eoc::inventory::MemberComponent",
    .shortName = "Member",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_eoc_inventory_MemberComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_inventory_MemberComponent_Properties) / sizeof(g_Gen_eoc_inventory_MemberComponent_Properties[0]),
};

// ======================================================================
// eoc::inventory::OwnerComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x18 (24 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_inventory_OwnerComponent_Properties[] = {
    { "PrimaryInventory", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_inventory_OwnerComponent_Layout = {
    .componentName = "eoc::inventory::OwnerComponent",
    .shortName = "Owner",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_eoc_inventory_OwnerComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_inventory_OwnerComponent_Properties) / sizeof(g_Gen_eoc_inventory_OwnerComponent_Properties[0]),
};

// ======================================================================
// eoc::inventory::StackMemberComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_inventory_StackMemberComponent_Properties[] = {
    { "Stack", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_inventory_StackMemberComponent_Layout = {
    .componentName = "eoc::inventory::StackMemberComponent",
    .shortName = "StackMember",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_inventory_StackMemberComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_inventory_StackMemberComponent_Properties) / sizeof(g_Gen_eoc_inventory_StackMemberComponent_Properties[0]),
};

// ======================================================================
// eoc::inventory::TopOwnerComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_inventory_TopOwnerComponent_Properties[] = {
    { "TopOwner", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_inventory_TopOwnerComponent_Layout = {
    .componentName = "eoc::inventory::TopOwnerComponent",
    .shortName = "TopOwner",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_inventory_TopOwnerComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_inventory_TopOwnerComponent_Properties) / sizeof(g_Gen_eoc_inventory_TopOwnerComponent_Properties[0]),
};

// ======================================================================
// eoc::inventory::TradeBuybackDataComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x18 (24 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_inventory_TradeBuybackDataComponent_Properties[] = {
    { "Amount", 0x00, FIELD_TYPE_UINT16, 0, true },
    { "Trader", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Buyer", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_inventory_TradeBuybackDataComponent_Layout = {
    .componentName = "eoc::inventory::TradeBuybackDataComponent",
    .shortName = "TradeBuybackData",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_eoc_inventory_TradeBuybackDataComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_inventory_TradeBuybackDataComponent_Properties) / sizeof(g_Gen_eoc_inventory_TradeBuybackDataComponent_Properties[0]),
};

// ======================================================================
// eoc::inventory::WeightComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_inventory_WeightComponent_Properties[] = {
    { "Weight", 0x00, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_inventory_WeightComponent_Layout = {
    .componentName = "eoc::inventory::WeightComponent",
    .shortName = "Weight",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_inventory_WeightComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_inventory_WeightComponent_Properties) / sizeof(g_Gen_eoc_inventory_WeightComponent_Properties[0]),
};

// ======================================================================
// eoc::inventory::WieldedComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x10 (16 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_inventory_WieldedComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_inventory_WieldedComponent_Layout = {
    .componentName = "eoc::inventory::WieldedComponent",
    .shortName = "Wielded",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_eoc_inventory_WieldedComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_inventory_WieldedComponent_Properties) / sizeof(g_Gen_eoc_inventory_WieldedComponent_Properties[0]),
};

// ======================================================================
// eoc::inventory::WieldingHistoryComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x10 (16 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_inventory_WieldingHistoryComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_inventory_WieldingHistoryComponent_Layout = {
    .componentName = "eoc::inventory::WieldingHistoryComponent",
    .shortName = "WieldingHistory",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_eoc_inventory_WieldingHistoryComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_inventory_WieldingHistoryComponent_Properties) / sizeof(g_Gen_eoc_inventory_WieldingHistoryComponent_Properties[0]),
};

// ======================================================================
// eoc::item::DyeComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_item_DyeComponent_Properties[] = {
    { "Color", 0x00, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_item_DyeComponent_Layout = {
    .componentName = "eoc::item::DyeComponent",
    .shortName = "Dye",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_eoc_item_DyeComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_item_DyeComponent_Properties) / sizeof(g_Gen_eoc_item_DyeComponent_Properties[0]),
};

// ======================================================================
// eoc::item::MapMarkerStyleComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_item_MapMarkerStyleComponent_Properties[] = {
    { "Style", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_item_MapMarkerStyleComponent_Layout = {
    .componentName = "eoc::item::MapMarkerStyleComponent",
    .shortName = "MapMarkerStyle",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_item_MapMarkerStyleComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_item_MapMarkerStyleComponent_Properties) / sizeof(g_Gen_eoc_item_MapMarkerStyleComponent_Properties[0]),
};

// ======================================================================
// eoc::item::PortalComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x2 (2 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_item_PortalComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, true },
    { "field_1", 0x01, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_item_PortalComponent_Layout = {
    .componentName = "eoc::item::PortalComponent",
    .shortName = "Portal",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_Gen_eoc_item_PortalComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_item_PortalComponent_Properties) / sizeof(g_Gen_eoc_item_PortalComponent_Properties[0]),
};

// ======================================================================
// eoc::light::ActiveCharacterLightComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_light_ActiveCharacterLightComponent_Properties[] = {
    { "Light", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_light_ActiveCharacterLightComponent_Layout = {
    .componentName = "eoc::light::ActiveCharacterLightComponent",
    .shortName = "ActiveCharacterLight",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_light_ActiveCharacterLightComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_light_ActiveCharacterLightComponent_Properties) / sizeof(g_Gen_eoc_light_ActiveCharacterLightComponent_Properties[0]),
};

// ======================================================================
// eoc::lock::KeyComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_lock_KeyComponent_Properties[] = {
    { "Key", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_lock_KeyComponent_Layout = {
    .componentName = "eoc::lock::KeyComponent",
    .shortName = "Key",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_lock_KeyComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_lock_KeyComponent_Properties) / sizeof(g_Gen_eoc_lock_KeyComponent_Properties[0]),
};

// ======================================================================
// eoc::lock::LockComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x28 (40 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_lock_LockComponent_Properties[] = {
    { "Key_M", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "LockDC", 0x04, FIELD_TYPE_INT32, 0, true },
    { "field_8", 0x08, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_lock_LockComponent_Layout = {
    .componentName = "eoc::lock::LockComponent",
    .shortName = "Lock",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_Gen_eoc_lock_LockComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_lock_LockComponent_Properties) / sizeof(g_Gen_eoc_lock_LockComponent_Properties[0]),
};

// ======================================================================
// eoc::object_visual::CharacterCreationTemplateOverrideComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_object_visual_CharacterCreationTemplateOverrideComponent_Properties[] = {
    { "Template", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_object_visual_CharacterCreationTemplateOverrideComponent_Layout = {
    .componentName = "eoc::object_visual::CharacterCreationTemplateOverrideComponent",
    .shortName = "CharacterCreationTemplateOverride",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_object_visual_CharacterCreationTemplateOverrideComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_object_visual_CharacterCreationTemplateOverrideComponent_Properties) / sizeof(g_Gen_eoc_object_visual_CharacterCreationTemplateOverrideComponent_Properties[0]),
};

// ======================================================================
// eoc::ownership::OwneeCurrentComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_ownership_OwneeCurrentComponent_Properties[] = {
    { "Ownee", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_ownership_OwneeCurrentComponent_Layout = {
    .componentName = "eoc::ownership::OwneeCurrentComponent",
    .shortName = "OwneeCurrent",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_ownership_OwneeCurrentComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_ownership_OwneeCurrentComponent_Properties) / sizeof(g_Gen_eoc_ownership_OwneeCurrentComponent_Properties[0]),
};

// ======================================================================
// eoc::party::CompositionComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x28 (40 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_party_CompositionComponent_Properties[] = {
    { "Party", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_party_CompositionComponent_Layout = {
    .componentName = "eoc::party::CompositionComponent",
    .shortName = "Composition",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_Gen_eoc_party_CompositionComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_party_CompositionComponent_Properties) / sizeof(g_Gen_eoc_party_CompositionComponent_Properties[0]),
};

// ======================================================================
// eoc::party::FollowerComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_party_FollowerComponent_Properties[] = {
    { "Following", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_party_FollowerComponent_Layout = {
    .componentName = "eoc::party::FollowerComponent",
    .shortName = "Follower",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_party_FollowerComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_party_FollowerComponent_Properties) / sizeof(g_Gen_eoc_party_FollowerComponent_Properties[0]),
};

// ======================================================================
// eoc::party::MemberComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x38 (56 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_party_MemberComponent_Properties[] = {
    { "Party", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_party_MemberComponent_Layout = {
    .componentName = "eoc::party::MemberComponent",
    .shortName = "Member",
    .componentTypeIndex = 0,
    .componentSize = 0x38,
    .properties = g_Gen_eoc_party_MemberComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_party_MemberComponent_Properties) / sizeof(g_Gen_eoc_party_MemberComponent_Properties[0]),
};

// ======================================================================
// eoc::photo_mode::DummyAnimationStateComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x18 (24 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_photo_mode_DummyAnimationStateComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "field_4", 0x04, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, true },
    { "qwordC", 0x0c, FIELD_TYPE_INT32, 0, true },
    { "field_10", 0x10, FIELD_TYPE_INT32, 0, true },
    { "word14", 0x14, FIELD_TYPE_UINT8, 0, true },
    { "field_15", 0x15, FIELD_TYPE_UINT8, 0, true },
    { "field_16", 0x16, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_photo_mode_DummyAnimationStateComponent_Layout = {
    .componentName = "eoc::photo_mode::DummyAnimationStateComponent",
    .shortName = "DummyAnimationState",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_eoc_photo_mode_DummyAnimationStateComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_photo_mode_DummyAnimationStateComponent_Properties) / sizeof(g_Gen_eoc_photo_mode_DummyAnimationStateComponent_Properties[0]),
};

// ======================================================================
// eoc::photo_mode::DummyComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_photo_mode_DummyComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_photo_mode_DummyComponent_Layout = {
    .componentName = "eoc::photo_mode::DummyComponent",
    .shortName = "Dummy",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_eoc_photo_mode_DummyComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_photo_mode_DummyComponent_Properties) / sizeof(g_Gen_eoc_photo_mode_DummyComponent_Properties[0]),
};

// ======================================================================
// eoc::photo_mode::DummyEquipmentVisualComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_photo_mode_DummyEquipmentVisualComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_photo_mode_DummyEquipmentVisualComponent_Layout = {
    .componentName = "eoc::photo_mode::DummyEquipmentVisualComponent",
    .shortName = "DummyEquipmentVisual",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_photo_mode_DummyEquipmentVisualComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_photo_mode_DummyEquipmentVisualComponent_Properties) / sizeof(g_Gen_eoc_photo_mode_DummyEquipmentVisualComponent_Properties[0]),
};

// ======================================================================
// eoc::photo_mode::DummyShowSplatterComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1 (1 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_photo_mode_DummyShowSplatterComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_photo_mode_DummyShowSplatterComponent_Layout = {
    .componentName = "eoc::photo_mode::DummyShowSplatterComponent",
    .shortName = "DummyShowSplatter",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_eoc_photo_mode_DummyShowSplatterComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_photo_mode_DummyShowSplatterComponent_Properties) / sizeof(g_Gen_eoc_photo_mode_DummyShowSplatterComponent_Properties[0]),
};

// ======================================================================
// eoc::photo_mode::SessionComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1 (1 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_photo_mode_SessionComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_photo_mode_SessionComponent_Layout = {
    .componentName = "eoc::photo_mode::SessionComponent",
    .shortName = "Session",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_eoc_photo_mode_SessionComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_photo_mode_SessionComponent_Properties) / sizeof(g_Gen_eoc_photo_mode_SessionComponent_Properties[0]),
};

// ======================================================================
// eoc::pickup::PickUpRequestComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x18 (24 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_pickup_PickUpRequestComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_GUID, 0, true },
    { "State", 0x10, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_pickup_PickUpRequestComponent_Layout = {
    .componentName = "eoc::pickup::PickUpRequestComponent",
    .shortName = "PickUpRequest",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_eoc_pickup_PickUpRequestComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_pickup_PickUpRequestComponent_Properties) / sizeof(g_Gen_eoc_pickup_PickUpRequestComponent_Properties[0]),
};

// ======================================================================
// eoc::progression::FeatComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x80 (128 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_progression_FeatComponent_Properties[] = {
    { "Feat", 0x00, FIELD_TYPE_GUID, 0, true },
    { "field_10", 0x10, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_progression_FeatComponent_Layout = {
    .componentName = "eoc::progression::FeatComponent",
    .shortName = "Feat",
    .componentTypeIndex = 0,
    .componentSize = 0x80,
    .properties = g_Gen_eoc_progression_FeatComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_progression_FeatComponent_Properties) / sizeof(g_Gen_eoc_progression_FeatComponent_Properties[0]),
};

// ======================================================================
// eoc::progression::MetaComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x80 (128 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_progression_MetaComponent_Properties[] = {
    { "field_18", 0x00, FIELD_TYPE_UINT8, 0, true },
    { "Progression", 0x08, FIELD_TYPE_GUID, 0, true },
    { "Owner", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_progression_MetaComponent_Layout = {
    .componentName = "eoc::progression::MetaComponent",
    .shortName = "Meta",
    .componentTypeIndex = 0,
    .componentSize = 0x80,
    .properties = g_Gen_eoc_progression_MetaComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_progression_MetaComponent_Properties) / sizeof(g_Gen_eoc_progression_MetaComponent_Properties[0]),
};

// ======================================================================
// eoc::progression::ReplicatedFeatComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x18 (24 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_progression_ReplicatedFeatComponent_Properties[] = {
    { "Feat", 0x00, FIELD_TYPE_GUID, 0, true },
    { "field_10", 0x10, FIELD_TYPE_UINT8, 0, true },
    { "field_14", 0x14, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_progression_ReplicatedFeatComponent_Layout = {
    .componentName = "eoc::progression::ReplicatedFeatComponent",
    .shortName = "ReplicatedFeat",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_eoc_progression_ReplicatedFeatComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_progression_ReplicatedFeatComponent_Properties) / sizeof(g_Gen_eoc_progression_ReplicatedFeatComponent_Properties[0]),
};

// ======================================================================
// eoc::projectile::SourceInfoComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x40 (64 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_projectile_SourceInfoComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_projectile_SourceInfoComponent_Layout = {
    .componentName = "eoc::projectile::SourceInfoComponent",
    .shortName = "SourceInfo",
    .componentTypeIndex = 0,
    .componentSize = 0x40,
    .properties = g_Gen_eoc_projectile_SourceInfoComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_projectile_SourceInfoComponent_Properties) / sizeof(g_Gen_eoc_projectile_SourceInfoComponent_Properties[0]),
};

// ======================================================================
// eoc::relation::FactionComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x30 (48 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_relation_FactionComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "field_8", 0x08, FIELD_TYPE_GUID, 0, true },
    { "field_18", 0x18, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_relation_FactionComponent_Layout = {
    .componentName = "eoc::relation::FactionComponent",
    .shortName = "Faction",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_Gen_eoc_relation_FactionComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_relation_FactionComponent_Properties) / sizeof(g_Gen_eoc_relation_FactionComponent_Properties[0]),
};

// ======================================================================
// eoc::repose::StateComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x30 (48 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_repose_StateComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "field_8", 0x08, FIELD_TYPE_GUID, 0, true },
    { "field_18", 0x18, FIELD_TYPE_INT32, 0, true },
    { "field_1C", 0x1c, FIELD_TYPE_VEC3, 0, true },
    { "field_28", 0x28, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_repose_StateComponent_Layout = {
    .componentName = "eoc::repose::StateComponent",
    .shortName = "State",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_Gen_eoc_repose_StateComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_repose_StateComponent_Properties) / sizeof(g_Gen_eoc_repose_StateComponent_Properties[0]),
};

// ======================================================================
// eoc::rest::LongRestState
// Generated from Windows BG3SE headers
// ARM64 Size: 0x18 (24 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_rest_LongRestState_Properties[] = {
    { "WaitingForOthers", 0x00, FIELD_TYPE_BOOL, 0, true },
    { "FinishConfirmed", 0x01, FIELD_TYPE_BOOL, 0, true },
    { "Finishing", 0x02, FIELD_TYPE_BOOL, 0, true },
    { "field_8", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Requester", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_rest_LongRestState_Layout = {
    .componentName = "eoc::rest::LongRestState",
    .shortName = "LongRestState",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_eoc_rest_LongRestState_Properties,
    .propertyCount = sizeof(g_Gen_eoc_rest_LongRestState_Properties) / sizeof(g_Gen_eoc_rest_LongRestState_Properties[0]),
};

// ======================================================================
// eoc::rest::LongRestTimeline
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_rest_LongRestTimeline_Properties[] = {
    { "Timeline", 0x00, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_rest_LongRestTimeline_Layout = {
    .componentName = "eoc::rest::LongRestTimeline",
    .shortName = "LongRestTimeline",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_eoc_rest_LongRestTimeline_Properties,
    .propertyCount = sizeof(g_Gen_eoc_rest_LongRestTimeline_Properties) / sizeof(g_Gen_eoc_rest_LongRestTimeline_Properties[0]),
};

// ======================================================================
// eoc::rest::LongRestTimers
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_rest_LongRestTimers_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_rest_LongRestTimers_Layout = {
    .componentName = "eoc::rest::LongRestTimers",
    .shortName = "LongRestTimers",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_rest_LongRestTimers_Properties,
    .propertyCount = sizeof(g_Gen_eoc_rest_LongRestTimers_Properties) / sizeof(g_Gen_eoc_rest_LongRestTimers_Properties[0]),
};

// ======================================================================
// eoc::rest::LongRestUsers
// Generated from Windows BG3SE headers
// ARM64 Size: 0x78 (120 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_rest_LongRestUsers_Properties[] = {
    { "RequestRestore", 0x00, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_rest_LongRestUsers_Layout = {
    .componentName = "eoc::rest::LongRestUsers",
    .shortName = "LongRestUsers",
    .componentTypeIndex = 0,
    .componentSize = 0x78,
    .properties = g_Gen_eoc_rest_LongRestUsers_Properties,
    .propertyCount = sizeof(g_Gen_eoc_rest_LongRestUsers_Properties) / sizeof(g_Gen_eoc_rest_LongRestUsers_Properties[0]),
};

// ======================================================================
// eoc::rest::RestingEntities
// Generated from Windows BG3SE headers
// ARM64 Size: 0xc8 (200 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_rest_RestingEntities_Properties[] = {
    { "HasSurfaces", 0x00, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_rest_RestingEntities_Layout = {
    .componentName = "eoc::rest::RestingEntities",
    .shortName = "RestingEntities",
    .componentTypeIndex = 0,
    .componentSize = 0xc8,
    .properties = g_Gen_eoc_rest_RestingEntities_Properties,
    .propertyCount = sizeof(g_Gen_eoc_rest_RestingEntities_Properties) / sizeof(g_Gen_eoc_rest_RestingEntities_Properties[0]),
};

// ======================================================================
// eoc::ruleset::RulesetComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x60 (96 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_ruleset_RulesetComponent_Properties[] = {
    { "field_40", 0x50, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_ruleset_RulesetComponent_Layout = {
    .componentName = "eoc::ruleset::RulesetComponent",
    .shortName = "Ruleset",
    .componentTypeIndex = 0,
    .componentSize = 0x60,
    .properties = g_Gen_eoc_ruleset_RulesetComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_ruleset_RulesetComponent_Properties) / sizeof(g_Gen_eoc_ruleset_RulesetComponent_Properties[0]),
};

// ======================================================================
// eoc::shapeshift::AnimationComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_shapeshift_AnimationComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT32, 0, true },
    { "field_4", 0x04, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_shapeshift_AnimationComponent_Layout = {
    .componentName = "eoc::shapeshift::AnimationComponent",
    .shortName = "Animation",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_shapeshift_AnimationComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_shapeshift_AnimationComponent_Properties) / sizeof(g_Gen_eoc_shapeshift_AnimationComponent_Properties[0]),
};

// ======================================================================
// eoc::shapeshift::RecoveryAnimationComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_shapeshift_RecoveryAnimationComponent_Properties[] = {
    { "Animation", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_shapeshift_RecoveryAnimationComponent_Layout = {
    .componentName = "eoc::shapeshift::RecoveryAnimationComponent",
    .shortName = "RecoveryAnimation",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_shapeshift_RecoveryAnimationComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_shapeshift_RecoveryAnimationComponent_Properties) / sizeof(g_Gen_eoc_shapeshift_RecoveryAnimationComponent_Properties[0]),
};

// ======================================================================
// eoc::shapeshift::ReplicatedChangesComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0xa8 (168 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_shapeshift_ReplicatedChangesComponent_Properties[] = {
    { "VisualChanged", 0x00, FIELD_TYPE_BOOL, 0, true },
    { "ItemTooltipFlags", 0x02, FIELD_TYPE_UINT16, 0, true },
    { "GoldAmount", 0x04, FIELD_TYPE_INT32, 0, true },
    { "ItemWeight", 0x08, FIELD_TYPE_INT32, 0, true },
    { "MuteEquipmentSound", 0x0c, FIELD_TYPE_BOOL, 0, true },
    { "DisableEquipment", 0x0d, FIELD_TYPE_BOOL, 0, true },
    { "HasWildShapeHotBar", 0x0e, FIELD_TYPE_BOOL, 0, true },
    { "HasWeightOverride", 0x0f, FIELD_TYPE_BOOL, 0, true },
    { "AC", 0x10, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_shapeshift_ReplicatedChangesComponent_Layout = {
    .componentName = "eoc::shapeshift::ReplicatedChangesComponent",
    .shortName = "ReplicatedChanges",
    .componentTypeIndex = 0,
    .componentSize = 0xa8,
    .properties = g_Gen_eoc_shapeshift_ReplicatedChangesComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_shapeshift_ReplicatedChangesComponent_Properties) / sizeof(g_Gen_eoc_shapeshift_ReplicatedChangesComponent_Properties[0]),
};

// ======================================================================
// eoc::sight::DataComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x28 (40 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_sight_DataComponent_Properties[] = {
    { "field_20", 0x20, FIELD_TYPE_INT32, 0, true },
    { "field_24", 0x24, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_sight_DataComponent_Layout = {
    .componentName = "eoc::sight::DataComponent",
    .shortName = "Data",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_Gen_eoc_sight_DataComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_sight_DataComponent_Properties) / sizeof(g_Gen_eoc_sight_DataComponent_Properties[0]),
};

// ======================================================================
// eoc::spatial_grid::DataComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x98 (152 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_spatial_grid_DataComponent_Properties[] = {
    { "Level", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "field_94", 0x04, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_spatial_grid_DataComponent_Layout = {
    .componentName = "eoc::spatial_grid::DataComponent",
    .shortName = "Data",
    .componentTypeIndex = 0,
    .componentSize = 0x98,
    .properties = g_Gen_eoc_spatial_grid_DataComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_spatial_grid_DataComponent_Properties) / sizeof(g_Gen_eoc_spatial_grid_DataComponent_Properties[0]),
};

// ======================================================================
// eoc::spell::ScriptedExplosionComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_spell_ScriptedExplosionComponent_Properties[] = {
    { "Projectile", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_spell_ScriptedExplosionComponent_Layout = {
    .componentName = "eoc::spell::ScriptedExplosionComponent",
    .shortName = "ScriptedExplosion",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_spell_ScriptedExplosionComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_spell_ScriptedExplosionComponent_Properties) / sizeof(g_Gen_eoc_spell_ScriptedExplosionComponent_Properties[0]),
};

// ======================================================================
// eoc::spell_cast::AnimationInfoComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x30 (48 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_spell_cast_AnimationInfoComponent_Properties[] = {
    { "TargetPosition", 0x00, FIELD_TYPE_VEC3, 0, true },
    { "Target", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "field_28", 0x28, FIELD_TYPE_UINT8, 0, true },
    { "TargetIsCaster", 0x19, FIELD_TYPE_BOOL, 0, true },
    { "field_2B", 0x2b, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_spell_cast_AnimationInfoComponent_Layout = {
    .componentName = "eoc::spell_cast::AnimationInfoComponent",
    .shortName = "AnimationInfo",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_Gen_eoc_spell_cast_AnimationInfoComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_spell_cast_AnimationInfoComponent_Properties) / sizeof(g_Gen_eoc_spell_cast_AnimationInfoComponent_Properties[0]),
};

// ======================================================================
// eoc::spell_cast::CacheComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_spell_cast_CacheComponent_Properties[] = {
    { "SpellCastingAbility", 0x00, FIELD_TYPE_UINT8, 0, true },
    { "Flags", 0x04, FIELD_TYPE_UINT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_spell_cast_CacheComponent_Layout = {
    .componentName = "eoc::spell_cast::CacheComponent",
    .shortName = "Cache",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_spell_cast_CacheComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_spell_cast_CacheComponent_Properties) / sizeof(g_Gen_eoc_spell_cast_CacheComponent_Properties[0]),
};

// ======================================================================
// eoc::spell_cast::InterruptResultsComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x38 (56 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_spell_cast_InterruptResultsComponent_Properties[] = {
    { "HasReplacement", 0x00, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_spell_cast_InterruptResultsComponent_Layout = {
    .componentName = "eoc::spell_cast::InterruptResultsComponent",
    .shortName = "InterruptResults",
    .componentTypeIndex = 0,
    .componentSize = 0x38,
    .properties = g_Gen_eoc_spell_cast_InterruptResultsComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_spell_cast_InterruptResultsComponent_Properties) / sizeof(g_Gen_eoc_spell_cast_InterruptResultsComponent_Properties[0]),
};

// ======================================================================
// eoc::spell_cast::IsCastingComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_spell_cast_IsCastingComponent_Properties[] = {
    { "Cast", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_spell_cast_IsCastingComponent_Layout = {
    .componentName = "eoc::spell_cast::IsCastingComponent",
    .shortName = "IsCasting",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_spell_cast_IsCastingComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_spell_cast_IsCastingComponent_Properties) / sizeof(g_Gen_eoc_spell_cast_IsCastingComponent_Properties[0]),
};

// ======================================================================
// eoc::spell_cast::MovementComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1c (28 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_spell_cast_MovementComponent_Properties[] = {
    { "Position", 0x00, FIELD_TYPE_VEC3, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_spell_cast_MovementComponent_Layout = {
    .componentName = "eoc::spell_cast::MovementComponent",
    .shortName = "Movement",
    .componentTypeIndex = 0,
    .componentSize = 0x1c,
    .properties = g_Gen_eoc_spell_cast_MovementComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_spell_cast_MovementComponent_Properties) / sizeof(g_Gen_eoc_spell_cast_MovementComponent_Properties[0]),
};

// ======================================================================
// eoc::spell_cast::StateComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0xc0 (192 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_spell_cast_StateComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Caster", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "CasterStartPosition", 0x10, FIELD_TYPE_VEC3, 0, true },
    { "SpellCastGuid", 0x20, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_spell_cast_StateComponent_Layout = {
    .componentName = "eoc::spell_cast::StateComponent",
    .shortName = "State",
    .componentTypeIndex = 0,
    .componentSize = 0xc0,
    .properties = g_Gen_eoc_spell_cast_StateComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_spell_cast_StateComponent_Properties) / sizeof(g_Gen_eoc_spell_cast_StateComponent_Properties[0]),
};

// ======================================================================
// eoc::spell_cast::SyncTargetingComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x98 (152 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_spell_cast_SyncTargetingComponent_Properties[] = {
    { "field_44", 0x00, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_spell_cast_SyncTargetingComponent_Layout = {
    .componentName = "eoc::spell_cast::SyncTargetingComponent",
    .shortName = "SyncTargeting",
    .componentTypeIndex = 0,
    .componentSize = 0x98,
    .properties = g_Gen_eoc_spell_cast_SyncTargetingComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_spell_cast_SyncTargetingComponent_Properties) / sizeof(g_Gen_eoc_spell_cast_SyncTargetingComponent_Properties[0]),
};

// ======================================================================
// eoc::status::CauseComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_status_CauseComponent_Properties[] = {
    { "Cause", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_status_CauseComponent_Layout = {
    .componentName = "eoc::status::CauseComponent",
    .shortName = "Cause",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_status_CauseComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_status_CauseComponent_Properties) / sizeof(g_Gen_eoc_status_CauseComponent_Properties[0]),
};

// ======================================================================
// eoc::status::IDComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_status_IDComponent_Properties[] = {
    { "ID", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_status_IDComponent_Layout = {
    .componentName = "eoc::status::IDComponent",
    .shortName = "ID",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_status_IDComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_status_IDComponent_Properties) / sizeof(g_Gen_eoc_status_IDComponent_Properties[0]),
};

// ======================================================================
// eoc::status::IncapacitatedComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x50 (80 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_status_IncapacitatedComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT32, 0, true },
    { "field_48", 0x48, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_status_IncapacitatedComponent_Layout = {
    .componentName = "eoc::status::IncapacitatedComponent",
    .shortName = "Incapacitated",
    .componentTypeIndex = 0,
    .componentSize = 0x50,
    .properties = g_Gen_eoc_status_IncapacitatedComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_status_IncapacitatedComponent_Properties) / sizeof(g_Gen_eoc_status_IncapacitatedComponent_Properties[0]),
};

// ======================================================================
// eoc::status::LifetimeComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_status_LifetimeComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_status_LifetimeComponent_Layout = {
    .componentName = "eoc::status::LifetimeComponent",
    .shortName = "Lifetime",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_status_LifetimeComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_status_LifetimeComponent_Properties) / sizeof(g_Gen_eoc_status_LifetimeComponent_Properties[0]),
};

// ======================================================================
// eoc::status::LoseControlComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1 (1 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_status_LoseControlComponent_Properties[] = {
    { "LoseControl", 0x00, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_status_LoseControlComponent_Layout = {
    .componentName = "eoc::status::LoseControlComponent",
    .shortName = "LoseControl",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_eoc_status_LoseControlComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_status_LoseControlComponent_Properties) / sizeof(g_Gen_eoc_status_LoseControlComponent_Properties[0]),
};

// ======================================================================
// eoc::summon::IsSummonComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x30 (48 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_summon_IsSummonComponent_Properties[] = {
    { "field_10", 0x10, FIELD_TYPE_GUID, 0, true },
    { "field_20", 0x20, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "field_28", 0x28, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_summon_IsSummonComponent_Layout = {
    .componentName = "eoc::summon::IsSummonComponent",
    .shortName = "IsSummon",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_Gen_eoc_summon_IsSummonComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_summon_IsSummonComponent_Properties) / sizeof(g_Gen_eoc_summon_IsSummonComponent_Properties[0]),
};

// ======================================================================
// eoc::tadpole_tree::TreeStateComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1 (1 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_tadpole_tree_TreeStateComponent_Properties[] = {
    { "State", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_tadpole_tree_TreeStateComponent_Layout = {
    .componentName = "eoc::tadpole_tree::TreeStateComponent",
    .shortName = "TreeState",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_eoc_tadpole_tree_TreeStateComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_tadpole_tree_TreeStateComponent_Properties) / sizeof(g_Gen_eoc_tadpole_tree_TreeStateComponent_Properties[0]),
};

// ======================================================================
// eoc::templates::OriginalTemplateComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_templates_OriginalTemplateComponent_Properties[] = {
    { "OriginalTemplate", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "TemplateType", 0x04, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_templates_OriginalTemplateComponent_Layout = {
    .componentName = "eoc::templates::OriginalTemplateComponent",
    .shortName = "OriginalTemplate",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_eoc_templates_OriginalTemplateComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_templates_OriginalTemplateComponent_Properties) / sizeof(g_Gen_eoc_templates_OriginalTemplateComponent_Properties[0]),
};

// ======================================================================
// eoc::through::ShootThroughTypeComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1 (1 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_through_ShootThroughTypeComponent_Properties[] = {
    { "Type", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_through_ShootThroughTypeComponent_Layout = {
    .componentName = "eoc::through::ShootThroughTypeComponent",
    .shortName = "ShootThroughType",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_eoc_through_ShootThroughTypeComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_through_ShootThroughTypeComponent_Properties) / sizeof(g_Gen_eoc_through_ShootThroughTypeComponent_Properties[0]),
};

// ======================================================================
// eoc::trigger::TypeComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1 (1 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_trigger_TypeComponent_Properties[] = {
    { "Type", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_trigger_TypeComponent_Layout = {
    .componentName = "eoc::trigger::TypeComponent",
    .shortName = "Type",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_eoc_trigger_TypeComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_trigger_TypeComponent_Properties) / sizeof(g_Gen_eoc_trigger_TypeComponent_Properties[0]),
};

// ======================================================================
// eoc::unsheath::StateComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x20 (32 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_unsheath_StateComponent_Properties[] = {
    { "field_10", 0x10, FIELD_TYPE_INT32, 0, true },
    { "field_18", 0x18, FIELD_TYPE_UINT8, 0, true },
    { "field_19", 0x19, FIELD_TYPE_UINT8, 0, true },
    { "field_1A", 0x1a, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_unsheath_StateComponent_Layout = {
    .componentName = "eoc::unsheath::StateComponent",
    .shortName = "State",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_Gen_eoc_unsheath_StateComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_unsheath_StateComponent_Properties) / sizeof(g_Gen_eoc_unsheath_StateComponent_Properties[0]),
};

// ======================================================================
// eoc::user::AvatarComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0xc (12 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_user_AvatarComponent_Properties[] = {
    { "UserID", 0x00, FIELD_TYPE_INT32, 0, true },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_user_AvatarComponent_Layout = {
    .componentName = "eoc::user::AvatarComponent",
    .shortName = "Avatar",
    .componentTypeIndex = 0,
    .componentSize = 0xc,
    .properties = g_Gen_eoc_user_AvatarComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_user_AvatarComponent_Properties) / sizeof(g_Gen_eoc_user_AvatarComponent_Properties[0]),
};

// ======================================================================
// eoc::user::ReservedForComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_eoc_user_ReservedForComponent_Properties[] = {
    { "UserID", 0x00, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_eoc_user_ReservedForComponent_Layout = {
    .componentName = "eoc::user::ReservedForComponent",
    .shortName = "ReservedFor",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_eoc_user_ReservedForComponent_Properties,
    .propertyCount = sizeof(g_Gen_eoc_user_ReservedForComponent_Properties) / sizeof(g_Gen_eoc_user_ReservedForComponent_Properties[0]),
};

// ======================================================================
// esv::AnubisExecutorComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_AnubisExecutorComponent_Properties[] = {
    { "field_10", 0x00, FIELD_TYPE_UINT8, 0, true },
    { "field_11", 0x01, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_AnubisExecutorComponent_Layout = {
    .componentName = "esv::AnubisExecutorComponent",
    .shortName = "AnubisExecutor",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_esv_AnubisExecutorComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_AnubisExecutorComponent_Properties) / sizeof(g_Gen_esv_AnubisExecutorComponent_Properties[0]),
};

// ======================================================================
// esv::BaseDataComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x18 (24 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_BaseDataComponent_Properties[] = {
    { "Resistances", 0x00, FIELD_TYPE_INT32, 0, true },
    { "Weight", 0x04, FIELD_TYPE_INT32, 0, true },
    { "Flags", 0x08, FIELD_TYPE_UINT32, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_BaseDataComponent_Layout = {
    .componentName = "esv::BaseDataComponent",
    .shortName = "BaseData",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_esv_BaseDataComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_BaseDataComponent_Properties) / sizeof(g_Gen_esv_BaseDataComponent_Properties[0]),
};

// ======================================================================
// esv::BaseSizeComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x2 (2 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_BaseSizeComponent_Properties[] = {
    { "GameSize", 0x00, FIELD_TYPE_UINT8, 0, true },
    { "SoundSize", 0x01, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_BaseSizeComponent_Layout = {
    .componentName = "esv::BaseSizeComponent",
    .shortName = "BaseSize",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_Gen_esv_BaseSizeComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_BaseSizeComponent_Properties) / sizeof(g_Gen_esv_BaseSizeComponent_Properties[0]),
};

// ======================================================================
// esv::BaseStatsComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_BaseStatsComponent_Properties[] = {
    { "Initiative", 0x00, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_BaseStatsComponent_Layout = {
    .componentName = "esv::BaseStatsComponent",
    .shortName = "BaseStats",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_esv_BaseStatsComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_BaseStatsComponent_Properties) / sizeof(g_Gen_esv_BaseStatsComponent_Properties[0]),
};

// ======================================================================
// esv::BreadcrumbComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10c (268 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_BreadcrumbComponent_Properties[] = {
    { "field_118", 0x100, FIELD_TYPE_VEC3, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_BreadcrumbComponent_Layout = {
    .componentName = "esv::BreadcrumbComponent",
    .shortName = "Breadcrumb",
    .componentTypeIndex = 0,
    .componentSize = 0x10c,
    .properties = g_Gen_esv_BreadcrumbComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_BreadcrumbComponent_Properties) / sizeof(g_Gen_esv_BreadcrumbComponent_Properties[0]),
};

// ======================================================================
// esv::GameTimerComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x28 (40 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_GameTimerComponent_Properties[] = {
    { "field_18", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "field_20", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "field_28", 0x10, FIELD_TYPE_INT32, 0, true },
    { "field_2C", 0x14, FIELD_TYPE_INT32, 0, true },
    { "field_30", 0x18, FIELD_TYPE_INT32, 0, true },
    { "field_34", 0x1c, FIELD_TYPE_INT32, 0, true },
    { "field_38", 0x20, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_GameTimerComponent_Layout = {
    .componentName = "esv::GameTimerComponent",
    .shortName = "GameTimer",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_Gen_esv_GameTimerComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_GameTimerComponent_Properties) / sizeof(g_Gen_esv_GameTimerComponent_Properties[0]),
};

// ======================================================================
// esv::JumpFollowComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x150 (336 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_JumpFollowComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_VEC3, 0, true },
    { "field_C", 0x10, FIELD_TYPE_VEC3, 0, true },
    { "field_18", 0x1c, FIELD_TYPE_INT32, 0, true },
    { "field_1C", 0x20, FIELD_TYPE_INT32, 0, true },
    { "field_20", 0x24, FIELD_TYPE_INT32, 0, true },
    { "field_24", 0x28, FIELD_TYPE_VEC3, 0, true },
    { "field_30", 0x38, FIELD_TYPE_VEC3, 0, true },
    { "field_3C", 0x44, FIELD_TYPE_FLOAT, 0, true },
    { "field_40", 0x48, FIELD_TYPE_FLOAT, 0, true },
    { "field_44", 0x4c, FIELD_TYPE_FLOAT, 0, true },
    { "field_48", 0x50, FIELD_TYPE_UINT8, 0, true },
    { "field_4C", 0x54, FIELD_TYPE_FLOAT, 0, true },
    { "ProjectileTerrainOffset", 0x58, FIELD_TYPE_FLOAT, 0, true },
    { "field_D0", 0x5c, FIELD_TYPE_UINT8, 0, true },
    { "field_D4", 0x60, FIELD_TYPE_VEC3, 0, true },
    { "field_E0", 0x70, FIELD_TYPE_VEC3, 0, true },
    { "field_EC", 0x7c, FIELD_TYPE_INT32, 0, true },
    { "field_F0", 0x80, FIELD_TYPE_INT64, 0, true },
    { "field_F8", 0x88, FIELD_TYPE_INT32, 0, true },
    { "field_FC", 0x90, FIELD_TYPE_VEC3, 0, true },
    { "field_108", 0xa0, FIELD_TYPE_VEC3, 0, true },
    { "field_114", 0xac, FIELD_TYPE_INT32, 0, true },
    { "field_118", 0xb0, FIELD_TYPE_UINT8, 0, true },
    { "field_11C", 0xb8, FIELD_TYPE_VEC3, 0, true },
    { "field_128", 0xc4, FIELD_TYPE_INT32, 0, true },
    { "field_12C", 0xc8, FIELD_TYPE_INT32, 0, true },
    { "field_130", 0xcc, FIELD_TYPE_UINT32, 0, true },
    { "field_134", 0xd0, FIELD_TYPE_UINT32, 0, true },
    { "field_138", 0xd4, FIELD_TYPE_UINT8, 0, true },
    { "field_139", 0xd5, FIELD_TYPE_UINT8, 0, true },
    { "field_13A", 0xd6, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_JumpFollowComponent_Layout = {
    .componentName = "esv::JumpFollowComponent",
    .shortName = "JumpFollow",
    .componentTypeIndex = 0,
    .componentSize = 0x150,
    .properties = g_Gen_esv_JumpFollowComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_JumpFollowComponent_Properties) / sizeof(g_Gen_esv_JumpFollowComponent_Properties[0]),
};

// ======================================================================
// esv::Projectile
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_Projectile_Properties[] = {
    { "field_8", 0x00, FIELD_TYPE_UINT32, 0, true },
    { "field_C", 0x04, FIELD_TYPE_UINT32, 0, true },
    { "Entity", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Caster", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Source", 0x18, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "TargetObject", 0x20, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "HitObject", 0x28, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "ClientHitObject", 0x30, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "BeamSource", 0x38, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "SourceWeapon", 0x40, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "SourcePos", 0x48, FIELD_TYPE_VEC3, 0, true },
    { "TargetPos", 0x58, FIELD_TYPE_VEC3, 0, true },
    { "TargetObjectPos", 0x68, FIELD_TYPE_VEC3, 0, true },
    { "TextKey", 0x74, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "LifeTime", 0x78, FIELD_TYPE_FLOAT, 0, true },
    { "HitInterpolation", 0x7c, FIELD_TYPE_FLOAT, 0, true },
    { "FallbackTimer", 0x80, FIELD_TYPE_FLOAT, 0, true },
    { "ExplodeRadius", 0x84, FIELD_TYPE_FLOAT, 0, true },
    { "SpellCastingAbility", 0x88, FIELD_TYPE_UINT8, 0, true },
    { "SpellCastUuid", 0x90, FIELD_TYPE_GUID, 0, true },
    { "MovingObject", 0xa0, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "SpawnEffect", 0xa8, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "SpawnFXOverridesImpactFX", 0xac, FIELD_TYPE_BOOL, 0, true },
    { "BeamEffect", 0xb0, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "RequestDelete", 0xb8, FIELD_TYPE_BOOL, 0, true },
    { "Launched", 0xb9, FIELD_TYPE_BOOL, 0, true },
    { "IsOnHold", 0xba, FIELD_TYPE_BOOL, 0, true },
    { "IsTrap", 0xbb, FIELD_TYPE_BOOL, 0, true },
    { "IsThrown", 0xbc, FIELD_TYPE_BOOL, 0, true },
    { "IsFromItem", 0xbd, FIELD_TYPE_BOOL, 0, true },
    { "IgnoreTargetChecks", 0xbe, FIELD_TYPE_BOOL, 0, true },
    { "IgnoreRoof", 0xbf, FIELD_TYPE_BOOL, 0, true },
    { "CanDeflect", 0xc0, FIELD_TYPE_BOOL, 0, true },
    { "IgnoreObjects", 0xc1, FIELD_TYPE_BOOL, 0, true },
    { "IgnoreSurfaces", 0xc2, FIELD_TYPE_BOOL, 0, true },
    { "Used", 0xc3, FIELD_TYPE_BOOL, 0, true },
    { "Success", 0xc4, FIELD_TYPE_BOOL, 0, true },
    { "field_526", 0xc5, FIELD_TYPE_UINT8, 0, true },
    { "DamageMovingObjectOnLand", 0xc6, FIELD_TYPE_BOOL, 0, true },
    { "Reacted", 0xc7, FIELD_TYPE_BOOL, 0, true },
    { "ItemActivated", 0xc8, FIELD_TYPE_BOOL, 0, true },
    { "IsChasmRecovery", 0xc9, FIELD_TYPE_BOOL, 0, true },
    { "StoryActionId", 0xcc, FIELD_TYPE_INT32, 0, true },
    { "Flags", 0xd0, FIELD_TYPE_UINT64, 0, true },
    { "SourcePosition", 0xd8, FIELD_TYPE_VEC3, 0, true },
    { "field_574", 0xe8, FIELD_TYPE_VEC3, 0, true },
    { "Level", 0xf4, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "ShouldFall", 0xf8, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_Projectile_Layout = {
    .componentName = "esv::Projectile",
    .shortName = "Projectile",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_esv_Projectile_Properties,
    .propertyCount = sizeof(g_Gen_esv_Projectile_Properties) / sizeof(g_Gen_esv_Projectile_Properties[0]),
};

// ======================================================================
// esv::SafePositionComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_SafePositionComponent_Properties[] = {
    { "Position", 0x00, FIELD_TYPE_VEC3, 0, true },
    { "field_24", 0x0c, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_SafePositionComponent_Layout = {
    .componentName = "esv::SafePositionComponent",
    .shortName = "SafePosition",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_esv_SafePositionComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_SafePositionComponent_Properties) / sizeof(g_Gen_esv_SafePositionComponent_Properties[0]),
};

// ======================================================================
// esv::active_roll::InProgressComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x18 (24 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_active_roll_InProgressComponent_Properties[] = {
    { "Position", 0x00, FIELD_TYPE_VEC3, 0, true },
    { "Entity", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_active_roll_InProgressComponent_Layout = {
    .componentName = "esv::active_roll::InProgressComponent",
    .shortName = "InProgress",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_esv_active_roll_InProgressComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_active_roll_InProgressComponent_Properties) / sizeof(g_Gen_esv_active_roll_InProgressComponent_Properties[0]),
};

// ======================================================================
// esv::active_roll::StartRequestOneFrameComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x18 (24 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_active_roll_StartRequestOneFrameComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_GUID, 0, true },
    { "field_10", 0x10, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_active_roll_StartRequestOneFrameComponent_Layout = {
    .componentName = "esv::active_roll::StartRequestOneFrameComponent",
    .shortName = "StartRequestOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_esv_active_roll_StartRequestOneFrameComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_active_roll_StartRequestOneFrameComponent_Properties) / sizeof(g_Gen_esv_active_roll_StartRequestOneFrameComponent_Properties[0]),
};

// ======================================================================
// esv::ai::combat::AiModifiersComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x48 (72 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_ai_combat_AiModifiersComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_ai_combat_AiModifiersComponent_Layout = {
    .componentName = "esv::ai::combat::AiModifiersComponent",
    .shortName = "AiModifiers",
    .componentTypeIndex = 0,
    .componentSize = 0x48,
    .properties = g_Gen_esv_ai_combat_AiModifiersComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_ai_combat_AiModifiersComponent_Properties) / sizeof(g_Gen_esv_ai_combat_AiModifiersComponent_Properties[0]),
};

// ======================================================================
// esv::ai::combat::ArchetypeComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_ai_combat_ArchetypeComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "field_4", 0x04, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "field_8", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "field_C", 0x0c, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_ai_combat_ArchetypeComponent_Layout = {
    .componentName = "esv::ai::combat::ArchetypeComponent",
    .shortName = "Archetype",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_esv_ai_combat_ArchetypeComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_ai_combat_ArchetypeComponent_Properties) / sizeof(g_Gen_esv_ai_combat_ArchetypeComponent_Properties[0]),
};

// ======================================================================
// esv::character_creation::GodComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_character_creation_GodComponent_Properties[] = {
    { "God", 0x00, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_character_creation_GodComponent_Layout = {
    .componentName = "esv::character_creation::GodComponent",
    .shortName = "God",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_esv_character_creation_GodComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_character_creation_GodComponent_Properties) / sizeof(g_Gen_esv_character_creation_GodComponent_Properties[0]),
};

// ======================================================================
// esv::combat::CombatGroupMappingComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x48 (72 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_combat_CombatGroupMappingComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_combat_CombatGroupMappingComponent_Layout = {
    .componentName = "esv::combat::CombatGroupMappingComponent",
    .shortName = "CombatGroupMapping",
    .componentTypeIndex = 0,
    .componentSize = 0x48,
    .properties = g_Gen_esv_combat_CombatGroupMappingComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_combat_CombatGroupMappingComponent_Properties) / sizeof(g_Gen_esv_combat_CombatGroupMappingComponent_Properties[0]),
};

// ======================================================================
// esv::combat::CombatSwitchedComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x30 (48 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_combat_CombatSwitchedComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "field_8", 0x08, FIELD_TYPE_GUID, 0, true },
    { "field_18", 0x18, FIELD_TYPE_GUID, 0, true },
    { "field_28", 0x28, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_combat_CombatSwitchedComponent_Layout = {
    .componentName = "esv::combat::CombatSwitchedComponent",
    .shortName = "CombatSwitched",
    .componentTypeIndex = 0,
    .componentSize = 0x30,
    .properties = g_Gen_esv_combat_CombatSwitchedComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_combat_CombatSwitchedComponent_Properties) / sizeof(g_Gen_esv_combat_CombatSwitchedComponent_Properties[0]),
};

// ======================================================================
// esv::combat::FleeRequestComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x18 (24 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_combat_FleeRequestComponent_Properties[] = {
    { "RequestGuid", 0x00, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_combat_FleeRequestComponent_Layout = {
    .componentName = "esv::combat::FleeRequestComponent",
    .shortName = "FleeRequest",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_esv_combat_FleeRequestComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_combat_FleeRequestComponent_Properties) / sizeof(g_Gen_esv_combat_FleeRequestComponent_Properties[0]),
};

// ======================================================================
// esv::combat::JoiningComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_combat_JoiningComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_FLOAT, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_combat_JoiningComponent_Layout = {
    .componentName = "esv::combat::JoiningComponent",
    .shortName = "Joining",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_esv_combat_JoiningComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_combat_JoiningComponent_Properties) / sizeof(g_Gen_esv_combat_JoiningComponent_Properties[0]),
};

// ======================================================================
// esv::combat::LateJoinPenaltyComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_combat_LateJoinPenaltyComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_FLOAT, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_combat_LateJoinPenaltyComponent_Layout = {
    .componentName = "esv::combat::LateJoinPenaltyComponent",
    .shortName = "LateJoinPenalty",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_esv_combat_LateJoinPenaltyComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_combat_LateJoinPenaltyComponent_Properties) / sizeof(g_Gen_esv_combat_LateJoinPenaltyComponent_Properties[0]),
};

// ======================================================================
// esv::combat::MergeComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_combat_MergeComponent_Properties[] = {
    { "Combat1", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Combat2", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_combat_MergeComponent_Layout = {
    .componentName = "esv::combat::MergeComponent",
    .shortName = "Merge",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_esv_combat_MergeComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_combat_MergeComponent_Properties) / sizeof(g_Gen_esv_combat_MergeComponent_Properties[0]),
};

// ======================================================================
// esv::death::DelayDeathCauseComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x18 (24 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_death_DelayDeathCauseComponent_Properties[] = {
    { "DelayCount", 0x00, FIELD_TYPE_INT32, 0, true },
    { "Reason", 0x04, FIELD_TYPE_INT32, 0, true },
    { "field_8", 0x08, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_death_DelayDeathCauseComponent_Layout = {
    .componentName = "esv::death::DelayDeathCauseComponent",
    .shortName = "DelayDeathCause",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_esv_death_DelayDeathCauseComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_death_DelayDeathCauseComponent_Properties) / sizeof(g_Gen_esv_death_DelayDeathCauseComponent_Properties[0]),
};

// ======================================================================
// esv::death::DelayedDeathComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x98 (152 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_death_DelayedDeathComponent_Properties[] = {
    { "Reason", 0x00, FIELD_TYPE_UINT32, 0, true },
    { "field_88", 0x08, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_death_DelayedDeathComponent_Layout = {
    .componentName = "esv::death::DelayedDeathComponent",
    .shortName = "DelayedDeath",
    .componentTypeIndex = 0,
    .componentSize = 0x98,
    .properties = g_Gen_esv_death_DelayedDeathComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_death_DelayedDeathComponent_Properties) / sizeof(g_Gen_esv_death_DelayedDeathComponent_Properties[0]),
};

// ======================================================================
// esv::death::StateComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x4 (4 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_death_StateComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT32, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_death_StateComponent_Layout = {
    .componentName = "esv::death::StateComponent",
    .shortName = "State",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_esv_death_StateComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_death_StateComponent_Properties) / sizeof(g_Gen_esv_death_StateComponent_Properties[0]),
};

// ======================================================================
// esv::escort::FollowerComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_escort_FollowerComponent_Properties[] = {
    { "Following", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_escort_FollowerComponent_Layout = {
    .componentName = "esv::escort::FollowerComponent",
    .shortName = "Follower",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_esv_escort_FollowerComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_escort_FollowerComponent_Properties) / sizeof(g_Gen_esv_escort_FollowerComponent_Properties[0]),
};

// ======================================================================
// esv::escort::LeaderComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_escort_LeaderComponent_Properties[] = {
    { "Group", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_escort_LeaderComponent_Layout = {
    .componentName = "esv::escort::LeaderComponent",
    .shortName = "Leader",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_esv_escort_LeaderComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_escort_LeaderComponent_Properties) / sizeof(g_Gen_esv_escort_LeaderComponent_Properties[0]),
};

// ======================================================================
// esv::escort::MemberComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_escort_MemberComponent_Properties[] = {
    { "Group", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_escort_MemberComponent_Layout = {
    .componentName = "esv::escort::MemberComponent",
    .shortName = "Member",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_esv_escort_MemberComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_escort_MemberComponent_Properties) / sizeof(g_Gen_esv_escort_MemberComponent_Properties[0]),
};

// ======================================================================
// esv::escort::StragglersTrackerComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x20 (32 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_escort_StragglersTrackerComponent_Properties[] = {
    { "field_10", 0x10, FIELD_TYPE_VEC3, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_escort_StragglersTrackerComponent_Layout = {
    .componentName = "esv::escort::StragglersTrackerComponent",
    .shortName = "StragglersTracker",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_Gen_esv_escort_StragglersTrackerComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_escort_StragglersTrackerComponent_Properties) / sizeof(g_Gen_esv_escort_StragglersTrackerComponent_Properties[0]),
};

// ======================================================================
// esv::exp::ExperienceGaveOutComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_exp_ExperienceGaveOutComponent_Properties[] = {
    { "Experience", 0x00, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_exp_ExperienceGaveOutComponent_Layout = {
    .componentName = "esv::exp::ExperienceGaveOutComponent",
    .shortName = "ExperienceGaveOut",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_esv_exp_ExperienceGaveOutComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_exp_ExperienceGaveOutComponent_Properties) / sizeof(g_Gen_esv_exp_ExperienceGaveOutComponent_Properties[0]),
};

// ======================================================================
// esv::ftb::ZoneComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x48 (72 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_ftb_ZoneComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, true },
    { "field_10", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "field_18", 0x18, FIELD_TYPE_UINT8, 0, true },
    { "field_1C", 0x1c, FIELD_TYPE_FLOAT, 0, true },
    { "field_20", 0x20, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "ZoneGuid", 0x28, FIELD_TYPE_GUID, 0, true },
    { "Creator", 0x38, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "ByPlayer", 0x40, FIELD_TYPE_BOOL, 0, true },
    { "Shared", 0x41, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_ftb_ZoneComponent_Layout = {
    .componentName = "esv::ftb::ZoneComponent",
    .shortName = "Zone",
    .componentTypeIndex = 0,
    .componentSize = 0x48,
    .properties = g_Gen_esv_ftb_ZoneComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_ftb_ZoneComponent_Properties) / sizeof(g_Gen_esv_ftb_ZoneComponent_Properties[0]),
};

// ======================================================================
// esv::ftb::ZoneInstigatorComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_ftb_ZoneInstigatorComponent_Properties[] = {
    { "Instigator", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Shared", 0x08, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_ftb_ZoneInstigatorComponent_Layout = {
    .componentName = "esv::ftb::ZoneInstigatorComponent",
    .shortName = "ZoneInstigator",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_esv_ftb_ZoneInstigatorComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_ftb_ZoneInstigatorComponent_Properties) / sizeof(g_Gen_esv_ftb_ZoneInstigatorComponent_Properties[0]),
};

// ======================================================================
// esv::history::TargetUUIDComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_history_TargetUUIDComponent_Properties[] = {
    { "Target", 0x00, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_history_TargetUUIDComponent_Layout = {
    .componentName = "esv::history::TargetUUIDComponent",
    .shortName = "TargetUUID",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_esv_history_TargetUUIDComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_history_TargetUUIDComponent_Properties) / sizeof(g_Gen_esv_history_TargetUUIDComponent_Properties[0]),
};

// ======================================================================
// esv::inventory::ContainerDataComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_inventory_ContainerDataComponent_Properties[] = {
    { "Flags", 0x00, FIELD_TYPE_UINT16, 0, true },
    { "field_4", 0x04, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_inventory_ContainerDataComponent_Layout = {
    .componentName = "esv::inventory::ContainerDataComponent",
    .shortName = "ContainerData",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_esv_inventory_ContainerDataComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_inventory_ContainerDataComponent_Properties) / sizeof(g_Gen_esv_inventory_ContainerDataComponent_Properties[0]),
};

// ======================================================================
// esv::inventory::GroupCheckComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_inventory_GroupCheckComponent_Properties[] = {
    { "Conditions", 0x00, FIELD_TYPE_UINT32, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_inventory_GroupCheckComponent_Layout = {
    .componentName = "esv::inventory::GroupCheckComponent",
    .shortName = "GroupCheck",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_esv_inventory_GroupCheckComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_inventory_GroupCheckComponent_Properties) / sizeof(g_Gen_esv_inventory_GroupCheckComponent_Properties[0]),
};

// ======================================================================
// esv::item::DynamicLayerOwnerComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_item_DynamicLayerOwnerComponent_Properties[] = {
    { "Owner", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_item_DynamicLayerOwnerComponent_Layout = {
    .componentName = "esv::item::DynamicLayerOwnerComponent",
    .shortName = "DynamicLayerOwner",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_esv_item_DynamicLayerOwnerComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_item_DynamicLayerOwnerComponent_Properties) / sizeof(g_Gen_esv_item_DynamicLayerOwnerComponent_Properties[0]),
};

// ======================================================================
// esv::light::GameplayLightChangesComponent
// Generated from Windows BG3SE headers
// Windows Size: 0xc (12 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_light_GameplayLightChangesComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT32, 0, true },
    { "field_4", 0x04, FIELD_TYPE_UINT32, 0, true },
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, true },
    { "field_9", 0x09, FIELD_TYPE_UINT8, 0, true },
    { "field_A", 0x0a, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_light_GameplayLightChangesComponent_Layout = {
    .componentName = "esv::light::GameplayLightChangesComponent",
    .shortName = "GameplayLightChanges",
    .componentTypeIndex = 0,
    .componentSize = 0xc,
    .properties = g_Gen_esv_light_GameplayLightChangesComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_light_GameplayLightChangesComponent_Properties) / sizeof(g_Gen_esv_light_GameplayLightChangesComponent_Properties[0]),
};

// ======================================================================
// esv::ownership::OwneeHistoryComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x18 (24 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_ownership_OwneeHistoryComponent_Properties[] = {
    { "OriginalOwner", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "LatestOwner", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "PreviousOwner", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_ownership_OwneeHistoryComponent_Layout = {
    .componentName = "esv::ownership::OwneeHistoryComponent",
    .shortName = "OwneeHistory",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_esv_ownership_OwneeHistoryComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_ownership_OwneeHistoryComponent_Properties) / sizeof(g_Gen_esv_ownership_OwneeHistoryComponent_Properties[0]),
};

// ======================================================================
// esv::passive::PersistentDataComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_passive_PersistentDataComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_FLOAT, 0, true },
    { "field_4", 0x04, FIELD_TYPE_FLOAT, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_passive_PersistentDataComponent_Layout = {
    .componentName = "esv::passive::PersistentDataComponent",
    .shortName = "PersistentData",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_esv_passive_PersistentDataComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_passive_PersistentDataComponent_Properties) / sizeof(g_Gen_esv_passive_PersistentDataComponent_Properties[0]),
};

// ======================================================================
// esv::photo_mode::CapabilityComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x1 (1 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_photo_mode_CapabilityComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_photo_mode_CapabilityComponent_Layout = {
    .componentName = "esv::photo_mode::CapabilityComponent",
    .shortName = "Capability",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_esv_photo_mode_CapabilityComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_photo_mode_CapabilityComponent_Properties) / sizeof(g_Gen_esv_photo_mode_CapabilityComponent_Properties[0]),
};

// ======================================================================
// esv::projectile::AttachmentComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_projectile_AttachmentComponent_Properties[] = {
    { "Attachment", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_projectile_AttachmentComponent_Layout = {
    .componentName = "esv::projectile::AttachmentComponent",
    .shortName = "Attachment",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_esv_projectile_AttachmentComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_projectile_AttachmentComponent_Properties) / sizeof(g_Gen_esv_projectile_AttachmentComponent_Properties[0]),
};

// ======================================================================
// esv::projectile::SpellComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0xb8 (184 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_projectile_SpellComponent_Properties[] = {
    { "Spell", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Index", 0x08, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_projectile_SpellComponent_Layout = {
    .componentName = "esv::projectile::SpellComponent",
    .shortName = "Spell",
    .componentTypeIndex = 0,
    .componentSize = 0xb8,
    .properties = g_Gen_esv_projectile_SpellComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_projectile_SpellComponent_Properties) / sizeof(g_Gen_esv_projectile_SpellComponent_Properties[0]),
};

// ======================================================================
// esv::recruit::RecruitedByComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_recruit_RecruitedByComponent_Properties[] = {
    { "RecruitedBy", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_recruit_RecruitedByComponent_Layout = {
    .componentName = "esv::recruit::RecruitedByComponent",
    .shortName = "RecruitedBy",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_esv_recruit_RecruitedByComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_recruit_RecruitedByComponent_Properties) / sizeof(g_Gen_esv_recruit_RecruitedByComponent_Properties[0]),
};

// ======================================================================
// esv::replication::ReplicationDependencyComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_replication_ReplicationDependencyComponent_Properties[] = {
    { "Dependency", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_replication_ReplicationDependencyComponent_Layout = {
    .componentName = "esv::replication::ReplicationDependencyComponent",
    .shortName = "ReplicationDependency",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_esv_replication_ReplicationDependencyComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_replication_ReplicationDependencyComponent_Properties) / sizeof(g_Gen_esv_replication_ReplicationDependencyComponent_Properties[0]),
};

// ======================================================================
// esv::roll::stream::StreamsComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x28 (40 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_roll_stream_StreamsComponent_Properties[] = {
    { "LastFrame", 0x00, FIELD_TYPE_UINT64, 0, true },
    { "BaseSeed", 0x08, FIELD_TYPE_UINT64, 0, true },
    { "CustomRollExpectedValue", 0x10, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_roll_stream_StreamsComponent_Layout = {
    .componentName = "esv::roll::stream::StreamsComponent",
    .shortName = "Streams",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_Gen_esv_roll_stream_StreamsComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_roll_stream_StreamsComponent_Properties) / sizeof(g_Gen_esv_roll_stream_StreamsComponent_Properties[0]),
};

// ======================================================================
// esv::shapeshift::StatesComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x18 (24 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_shapeshift_StatesComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_shapeshift_StatesComponent_Layout = {
    .componentName = "esv::shapeshift::StatesComponent",
    .shortName = "States",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_esv_shapeshift_StatesComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_shapeshift_StatesComponent_Properties) / sizeof(g_Gen_esv_shapeshift_StatesComponent_Properties[0]),
};

// ======================================================================
// esv::sight::AggregatedDataComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x168 (360 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_sight_AggregatedDataComponent_Properties[] = {
    { "MaxSightRange", 0x00, FIELD_TYPE_FLOAT, 0, true },
    { "field_144", 0x144, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_sight_AggregatedDataComponent_Layout = {
    .componentName = "esv::sight::AggregatedDataComponent",
    .shortName = "AggregatedData",
    .componentTypeIndex = 0,
    .componentSize = 0x168,
    .properties = g_Gen_esv_sight_AggregatedDataComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_sight_AggregatedDataComponent_Properties) / sizeof(g_Gen_esv_sight_AggregatedDataComponent_Properties[0]),
};

// ======================================================================
// esv::sight::AggregatedGameplayLightDataComponent
// Generated from Windows BG3SE headers
// Windows Size: 0xa0 (160 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_sight_AggregatedGameplayLightDataComponent_Properties[] = {
    { "MaxRange", 0x00, FIELD_TYPE_FLOAT, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_sight_AggregatedGameplayLightDataComponent_Layout = {
    .componentName = "esv::sight::AggregatedGameplayLightDataComponent",
    .shortName = "AggregatedGameplayLightData",
    .componentTypeIndex = 0,
    .componentSize = 0xa0,
    .properties = g_Gen_esv_sight_AggregatedGameplayLightDataComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_sight_AggregatedGameplayLightDataComponent_Properties) / sizeof(g_Gen_esv_sight_AggregatedGameplayLightDataComponent_Properties[0]),
};

// ======================================================================
// esv::sight::AiGridViewshedComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x48 (72 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_sight_AiGridViewshedComponent_Properties[] = {
    { "Count", 0x00, FIELD_TYPE_UINT32, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_sight_AiGridViewshedComponent_Layout = {
    .componentName = "esv::sight::AiGridViewshedComponent",
    .shortName = "AiGridViewshed",
    .componentTypeIndex = 0,
    .componentSize = 0x48,
    .properties = g_Gen_esv_sight_AiGridViewshedComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_sight_AiGridViewshedComponent_Properties) / sizeof(g_Gen_esv_sight_AiGridViewshedComponent_Properties[0]),
};

// ======================================================================
// esv::spell_cast::CacheComponent
// Generated from Windows BG3SE headers
// Windows Size: 0xf0 (240 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_spell_cast_CacheComponent_Properties[] = {
    { "TextKeyIndex", 0x00, FIELD_TYPE_UINT32, 0, true },
    { "field_54", 0x04, FIELD_TYPE_INT32, 0, true },
    { "MovementTransactionId", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "HasPathfindTemplate", 0x0c, FIELD_TYPE_BOOL, 0, true },
    { "PhaseFinished", 0x0d, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_spell_cast_CacheComponent_Layout = {
    .componentName = "esv::spell_cast::CacheComponent",
    .shortName = "Cache",
    .componentTypeIndex = 0,
    .componentSize = 0xf0,
    .properties = g_Gen_esv_spell_cast_CacheComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_spell_cast_CacheComponent_Properties) / sizeof(g_Gen_esv_spell_cast_CacheComponent_Properties[0]),
};

// ======================================================================
// esv::spell_cast::CastHitDelayComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x18 (24 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_spell_cast_CastHitDelayComponent_Properties[] = {
    { "HitDelay", 0x00, FIELD_TYPE_FLOAT, 0, true },
    { "HitDelayRemaining", 0x04, FIELD_TYPE_FLOAT, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_spell_cast_CastHitDelayComponent_Layout = {
    .componentName = "esv::spell_cast::CastHitDelayComponent",
    .shortName = "CastHitDelay",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_esv_spell_cast_CastHitDelayComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_spell_cast_CastHitDelayComponent_Properties) / sizeof(g_Gen_esv_spell_cast_CastHitDelayComponent_Properties[0]),
};

// ======================================================================
// esv::spell_cast::CastResponsibleComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x8 (8 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_spell_cast_CastResponsibleComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_spell_cast_CastResponsibleComponent_Layout = {
    .componentName = "esv::spell_cast::CastResponsibleComponent",
    .shortName = "CastResponsible",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_esv_spell_cast_CastResponsibleComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_spell_cast_CastResponsibleComponent_Properties) / sizeof(g_Gen_esv_spell_cast_CastResponsibleComponent_Properties[0]),
};

// ======================================================================
// esv::spell_cast::InterruptDataComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x48 (72 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_spell_cast_InterruptDataComponent_Properties[] = {
    { "SpellCastGuid", 0x00, FIELD_TYPE_GUID, 0, true },
    { "NextInterruptIndex", 0x10, FIELD_TYPE_INT32, 0, true },
    { "AnimationIndex", 0x14, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_spell_cast_InterruptDataComponent_Layout = {
    .componentName = "esv::spell_cast::InterruptDataComponent",
    .shortName = "InterruptData",
    .componentTypeIndex = 0,
    .componentSize = 0x48,
    .properties = g_Gen_esv_spell_cast_InterruptDataComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_spell_cast_InterruptDataComponent_Properties) / sizeof(g_Gen_esv_spell_cast_InterruptDataComponent_Properties[0]),
};

// ======================================================================
// esv::spell_cast::MovementComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x18 (24 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_spell_cast_MovementComponent_Properties[] = {
    { "IsMoving", 0x00, FIELD_TYPE_BOOL, 0, true },
    { "Duration", 0x04, FIELD_TYPE_FLOAT, 0, true },
    { "Progress", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "TextKey", 0x0c, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_spell_cast_MovementComponent_Layout = {
    .componentName = "esv::spell_cast::MovementComponent",
    .shortName = "Movement",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_esv_spell_cast_MovementComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_spell_cast_MovementComponent_Properties) / sizeof(g_Gen_esv_spell_cast_MovementComponent_Properties[0]),
};

// ======================================================================
// esv::spell_cast::StateComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x40 (64 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_spell_cast_StateComponent_Properties[] = {
    { "field_4", 0x04, FIELD_TYPE_INT32, 0, true },
    { "StoryActionId", 0x04, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_spell_cast_StateComponent_Layout = {
    .componentName = "esv::spell_cast::StateComponent",
    .shortName = "State",
    .componentTypeIndex = 0,
    .componentSize = 0x40,
    .properties = g_Gen_esv_spell_cast_StateComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_spell_cast_StateComponent_Properties) / sizeof(g_Gen_esv_spell_cast_StateComponent_Properties[0]),
};

// ======================================================================
// esv::spell_cast::ZoneRangeComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x10 (16 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_spell_cast_ZoneRangeComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, true },
    { "field_4", 0x04, FIELD_TYPE_INT32, 0, true },
    { "field_8", 0x08, FIELD_TYPE_INT32, 0, true },
    { "field_C", 0x0c, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_spell_cast_ZoneRangeComponent_Layout = {
    .componentName = "esv::spell_cast::ZoneRangeComponent",
    .shortName = "ZoneRange",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_esv_spell_cast_ZoneRangeComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_spell_cast_ZoneRangeComponent_Properties) / sizeof(g_Gen_esv_spell_cast_ZoneRangeComponent_Properties[0]),
};

// ======================================================================
// esv::stats::proficiency::BaseProficiencyComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x10 (16 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_stats_proficiency_BaseProficiencyComponent_Properties[] = {
    { "Proficiency", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_stats_proficiency_BaseProficiencyComponent_Layout = {
    .componentName = "esv::stats::proficiency::BaseProficiencyComponent",
    .shortName = "BaseProficiency",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_esv_stats_proficiency_BaseProficiencyComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_stats_proficiency_BaseProficiencyComponent_Properties) / sizeof(g_Gen_esv_stats_proficiency_BaseProficiencyComponent_Properties[0]),
};

// ======================================================================
// esv::stats::proficiency::ProficiencyGroupStatsComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_stats_proficiency_ProficiencyGroupStatsComponent_Properties[] = {
    { "Stats", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_stats_proficiency_ProficiencyGroupStatsComponent_Layout = {
    .componentName = "esv::stats::proficiency::ProficiencyGroupStatsComponent",
    .shortName = "ProficiencyGroupStats",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_esv_stats_proficiency_ProficiencyGroupStatsComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_stats_proficiency_ProficiencyGroupStatsComponent_Properties) / sizeof(g_Gen_esv_stats_proficiency_ProficiencyGroupStatsComponent_Properties[0]),
};

// ======================================================================
// esv::status::CauseComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x58 (88 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_status_CauseComponent_Properties[] = {
    { "Cause", 0x00, FIELD_TYPE_GUID, 0, true },
    { "StoryActionId", 0x10, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_status_CauseComponent_Layout = {
    .componentName = "esv::status::CauseComponent",
    .shortName = "Cause",
    .componentTypeIndex = 0,
    .componentSize = 0x58,
    .properties = g_Gen_esv_status_CauseComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_status_CauseComponent_Properties) / sizeof(g_Gen_esv_status_CauseComponent_Properties[0]),
};

// ======================================================================
// esv::status::OwnershipComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_status_OwnershipComponent_Properties[] = {
    { "Owner", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_status_OwnershipComponent_Layout = {
    .componentName = "esv::status::OwnershipComponent",
    .shortName = "Ownership",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_esv_status_OwnershipComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_status_OwnershipComponent_Properties) / sizeof(g_Gen_esv_status_OwnershipComponent_Properties[0]),
};

// ======================================================================
// esv::status::PerformingComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_status_PerformingComponent_Properties[] = {
    { "PerformEvent", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_status_PerformingComponent_Layout = {
    .componentName = "esv::status::PerformingComponent",
    .shortName = "Performing",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_esv_status_PerformingComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_status_PerformingComponent_Properties) / sizeof(g_Gen_esv_status_PerformingComponent_Properties[0]),
};

// ======================================================================
// esv::status::StatusComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x28 (40 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_status_StatusComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "StatusHandle", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "StatusId", 0x10, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "SpellCastSourceUuid", 0x18, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_status_StatusComponent_Layout = {
    .componentName = "esv::status::StatusComponent",
    .shortName = "Status",
    .componentTypeIndex = 0,
    .componentSize = 0x28,
    .properties = g_Gen_esv_status_StatusComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_status_StatusComponent_Properties) / sizeof(g_Gen_esv_status_StatusComponent_Properties[0]),
};

// ======================================================================
// esv::status::aura::RemovedStatusAuraEffectEventOneFrameComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x18 (24 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_status_aura_RemovedStatusAuraEffectEventOneFrameComponent_Properties[] = {
    { "StatusId", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "StoryActionId", 0x04, FIELD_TYPE_INT32, 0, true },
    { "Source", 0x08, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Subject", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_status_aura_RemovedStatusAuraEffectEventOneFrameComponent_Layout = {
    .componentName = "esv::status::aura::RemovedStatusAuraEffectEventOneFrameComponent",
    .shortName = "RemovedStatusAuraEffectEventOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_esv_status_aura_RemovedStatusAuraEffectEventOneFrameComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_status_aura_RemovedStatusAuraEffectEventOneFrameComponent_Properties) / sizeof(g_Gen_esv_status_aura_RemovedStatusAuraEffectEventOneFrameComponent_Properties[0]),
};

// ======================================================================
// esv::surface::SurfaceComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x18 (24 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_surface_SurfaceComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_GUID, 0, true },
    { "field_10", 0x10, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_surface_SurfaceComponent_Layout = {
    .componentName = "esv::surface::SurfaceComponent",
    .shortName = "Surface",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_esv_surface_SurfaceComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_surface_SurfaceComponent_Properties) / sizeof(g_Gen_esv_surface_SurfaceComponent_Properties[0]),
};

// ======================================================================
// esv::trigger::EventConfigComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1 (1 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_trigger_EventConfigComponent_Properties[] = {
    { "Config", 0x00, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_trigger_EventConfigComponent_Layout = {
    .componentName = "esv::trigger::EventConfigComponent",
    .shortName = "EventConfig",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_esv_trigger_EventConfigComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_trigger_EventConfigComponent_Properties) / sizeof(g_Gen_esv_trigger_EventConfigComponent_Properties[0]),
};

// ======================================================================
// esv::trigger::RegistrationSettingsComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1 (1 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_trigger_RegistrationSettingsComponent_Properties[] = {
    { "Registered", 0x00, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_trigger_RegistrationSettingsComponent_Layout = {
    .componentName = "esv::trigger::RegistrationSettingsComponent",
    .shortName = "RegistrationSettings",
    .componentTypeIndex = 0,
    .componentSize = 0x1,
    .properties = g_Gen_esv_trigger_RegistrationSettingsComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_trigger_RegistrationSettingsComponent_Properties) / sizeof(g_Gen_esv_trigger_RegistrationSettingsComponent_Properties[0]),
};

// ======================================================================
// esv::unsheath::DefaultComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_esv_unsheath_DefaultComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_INT32, 0, true },
    { "field_4", 0x04, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_esv_unsheath_DefaultComponent_Layout = {
    .componentName = "esv::unsheath::DefaultComponent",
    .shortName = "Default",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_esv_unsheath_DefaultComponent_Properties,
    .propertyCount = sizeof(g_Gen_esv_unsheath_DefaultComponent_Properties) / sizeof(g_Gen_esv_unsheath_DefaultComponent_Properties[0]),
};

// ======================================================================
// ls::AnimationBlueprintComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_AnimationBlueprintComponent_Properties[] = {
    { "InstanceId", 0x00, FIELD_TYPE_INT32, 0, true },
    { "Flags", 0x04, FIELD_TYPE_UINT8, 0, true },
    { "field_40", 0x08, FIELD_TYPE_UINT64, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_AnimationBlueprintComponent_Layout = {
    .componentName = "ls::AnimationBlueprintComponent",
    .shortName = "AnimationBlueprint",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_ls_AnimationBlueprintComponent_Properties,
    .propertyCount = sizeof(g_Gen_ls_AnimationBlueprintComponent_Properties) / sizeof(g_Gen_ls_AnimationBlueprintComponent_Properties[0]),
};

// ======================================================================
// ls::AnimationSetComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_AnimationSetComponent_Properties[] = {
    { "FallbackSubSet", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_AnimationSetComponent_Layout = {
    .componentName = "ls::AnimationSetComponent",
    .shortName = "AnimationSet",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_ls_AnimationSetComponent_Properties,
    .propertyCount = sizeof(g_Gen_ls_AnimationSetComponent_Properties) / sizeof(g_Gen_ls_AnimationSetComponent_Properties[0]),
};

// ======================================================================
// ls::CameraComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0xb0 (176 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_CameraComponent_Properties[] = {
    { "MasterBehaviorType", 0x00, FIELD_TYPE_UINT32, 0, true },
    { "ExposureSettingIndex", 0x04, FIELD_TYPE_INT32, 0, true },
    { "Active", 0x08, FIELD_TYPE_BOOL, 0, true },
    { "AcceptsInput", 0x09, FIELD_TYPE_BOOL, 0, true },
    { "UseCameraPPSettings", 0x0a, FIELD_TYPE_BOOL, 0, true },
    { "UseSplitScreenFov", 0x0b, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_CameraComponent_Layout = {
    .componentName = "ls::CameraComponent",
    .shortName = "Camera",
    .componentTypeIndex = 0,
    .componentSize = 0xb0,
    .properties = g_Gen_ls_CameraComponent_Properties,
    .propertyCount = sizeof(g_Gen_ls_CameraComponent_Properties) / sizeof(g_Gen_ls_CameraComponent_Properties[0]),
};

// ======================================================================
// ls::CullComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x2 (2 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_CullComponent_Properties[] = {
    { "CullFlags", 0x00, FIELD_TYPE_UINT16, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_CullComponent_Layout = {
    .componentName = "ls::CullComponent",
    .shortName = "Cull",
    .componentTypeIndex = 0,
    .componentSize = 0x2,
    .properties = g_Gen_ls_CullComponent_Properties,
    .propertyCount = sizeof(g_Gen_ls_CullComponent_Properties) / sizeof(g_Gen_ls_CullComponent_Properties[0]),
};

// ======================================================================
// ls::DecalComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_DecalComponent_Properties[] = {
    { "field_8", 0x00, FIELD_TYPE_INT64, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_DecalComponent_Layout = {
    .componentName = "ls::DecalComponent",
    .shortName = "Decal",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_ls_DecalComponent_Properties,
    .propertyCount = sizeof(g_Gen_ls_DecalComponent_Properties) / sizeof(g_Gen_ls_DecalComponent_Properties[0]),
};

// ======================================================================
// ls::DefaultCameraBehavior
// Generated from Windows BG3SE headers
// ARM64 Size: 0x1c (28 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_DefaultCameraBehavior_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_FLOAT, 0, true },
    { "Left", 0x04, FIELD_TYPE_FLOAT, 0, true },
    { "Forward", 0x08, FIELD_TYPE_FLOAT, 0, true },
    { "RotationX", 0x0c, FIELD_TYPE_FLOAT, 0, true },
    { "RotationY", 0x10, FIELD_TYPE_FLOAT, 0, true },
    { "Zoom", 0x14, FIELD_TYPE_FLOAT, 0, true },
    { "CaptureInput", 0x18, FIELD_TYPE_BOOL, 0, true },
    { "field_19", 0x19, FIELD_TYPE_BOOL, 0, true },
    { "field_1A", 0x1a, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_DefaultCameraBehavior_Layout = {
    .componentName = "ls::DefaultCameraBehavior",
    .shortName = "DefaultCameraBehavior",
    .componentTypeIndex = 0,
    .componentSize = 0x1c,
    .properties = g_Gen_ls_DefaultCameraBehavior_Properties,
    .propertyCount = sizeof(g_Gen_ls_DefaultCameraBehavior_Properties) / sizeof(g_Gen_ls_DefaultCameraBehavior_Properties[0]),
};

// ======================================================================
// ls::EffectCameraBehavior
// Generated from Windows BG3SE headers
// ARM64 Size: 0xc (12 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_EffectCameraBehavior_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_VEC3, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_EffectCameraBehavior_Layout = {
    .componentName = "ls::EffectCameraBehavior",
    .shortName = "EffectCameraBehavior",
    .componentTypeIndex = 0,
    .componentSize = 0xc,
    .properties = g_Gen_ls_EffectCameraBehavior_Properties,
    .propertyCount = sizeof(g_Gen_ls_EffectCameraBehavior_Properties) / sizeof(g_Gen_ls_EffectCameraBehavior_Properties[0]),
};

// ======================================================================
// ls::EffectComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_EffectComponent_Properties[] = {
    { "EffectPtr", 0x00, FIELD_TYPE_UINT64, 0, true },  // Ptr to 0x68 (104b) malloc
};

static const ComponentLayoutDef g_Gen_ls_EffectComponent_Layout = {
    .componentName = "ls::EffectComponent",
    .shortName = "Effect",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_ls_EffectComponent_Properties,
    .propertyCount = sizeof(g_Gen_ls_EffectComponent_Properties) / sizeof(g_Gen_ls_EffectComponent_Properties[0]),
};

// ======================================================================
// ls::LevelComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_LevelComponent_Properties[] = {
    { "field_0", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "LevelName", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_LevelComponent_Layout = {
    .componentName = "ls::LevelComponent",
    .shortName = "Level",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_ls_LevelComponent_Properties,
    .propertyCount = sizeof(g_Gen_ls_LevelComponent_Properties) / sizeof(g_Gen_ls_LevelComponent_Properties[0]),
};

// ======================================================================
// ls::LevelInstanceComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x40 (64 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_LevelInstanceComponent_Properties[] = {
    { "LevelInstanceID", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "LevelName", 0x04, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "LevelInstanceTemplate", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "LevelType", 0x0c, FIELD_TYPE_UINT8, 0, true },
    { "Active", 0x0d, FIELD_TYPE_BOOL, 0, true },
    { "Platform", 0x0e, FIELD_TYPE_BOOL, 0, true },
    { "MovingPlatform", 0x0f, FIELD_TYPE_BOOL, 0, true },
    { "DynamicLayer", 0x10, FIELD_TYPE_BOOL, 0, true },
    { "NeedsPhysics", 0x11, FIELD_TYPE_BOOL, 0, true },
    { "field_12", 0x12, FIELD_TYPE_UINT8, 0, true },
    { "field_13", 0x13, FIELD_TYPE_UINT8, 0, true },
    { "field_14", 0x14, FIELD_TYPE_UINT8, 0, true },
    { "field_15", 0x15, FIELD_TYPE_UINT8, 0, true },
    { "qword18", 0x18, FIELD_TYPE_UINT64, 0, true },
    { "dword20", 0x20, FIELD_TYPE_INT32, 0, true },
    { "field_24", 0x24, FIELD_TYPE_INT32, 0, true },
    { "field_28", 0x28, FIELD_TYPE_INT32, 0, true },
    { "field_2C", 0x2c, FIELD_TYPE_INT32, 0, true },
    { "field_30", 0x30, FIELD_TYPE_INT32, 0, true },
    { "field_34", 0x34, FIELD_TYPE_FLOAT, 0, true },
    { "field_38", 0x38, FIELD_TYPE_FLOAT, 0, true },
    { "field_3C", 0x3c, FIELD_TYPE_FLOAT, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_LevelInstanceComponent_Layout = {
    .componentName = "ls::LevelInstanceComponent",
    .shortName = "LevelInstance",
    .componentTypeIndex = 0,
    .componentSize = 0x40,
    .properties = g_Gen_ls_LevelInstanceComponent_Properties,
    .propertyCount = sizeof(g_Gen_ls_LevelInstanceComponent_Properties) / sizeof(g_Gen_ls_LevelInstanceComponent_Properties[0]),
};

// ======================================================================
// ls::LevelInstanceStateComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0xd0 (208 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_LevelInstanceStateComponent_Properties[] = {
    { "field_60", 0x00, FIELD_TYPE_INT32, 0, true },
    { "MergedLevelTemplateUUID", 0x04, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "LevelInstanceID", 0x08, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "LevelName", 0x0c, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "LevelName2", 0x10, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "Destroyed", 0x14, FIELD_TYPE_BOOL, 0, true },
    { "MovingPlatform", 0x15, FIELD_TYPE_BOOL, 0, true },
    { "field_A6", 0x16, FIELD_TYPE_UINT8, 0, true },
    { "field_A8", 0x18, FIELD_TYPE_FLOAT, 0, true },
    { "field_AC", 0x1c, FIELD_TYPE_FLOAT, 0, true },
    { "field_B0", 0x20, FIELD_TYPE_FLOAT, 0, true },
    { "field_B4", 0x24, FIELD_TYPE_FLOAT, 0, true },
    { "field_B8", 0x28, FIELD_TYPE_FLOAT, 0, true },
    { "field_BC", 0x2c, FIELD_TYPE_FLOAT, 0, true },
    { "field_C0", 0x30, FIELD_TYPE_FLOAT, 0, true },
    { "field_C4", 0x34, FIELD_TYPE_FLOAT, 0, true },
    { "field_C8", 0x38, FIELD_TYPE_FLOAT, 0, true },
    { "field_CC", 0x3c, FIELD_TYPE_FLOAT, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_LevelInstanceStateComponent_Layout = {
    .componentName = "ls::LevelInstanceStateComponent",
    .shortName = "LevelInstanceState",
    .componentTypeIndex = 0,
    .componentSize = 0xd0,
    .properties = g_Gen_ls_LevelInstanceStateComponent_Properties,
    .propertyCount = sizeof(g_Gen_ls_LevelInstanceStateComponent_Properties) / sizeof(g_Gen_ls_LevelInstanceStateComponent_Properties[0]),
};

// ======================================================================
// ls::LevelRootComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_LevelRootComponent_Properties[] = {
    { "LevelName", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_LevelRootComponent_Layout = {
    .componentName = "ls::LevelRootComponent",
    .shortName = "LevelRoot",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_ls_LevelRootComponent_Properties,
    .propertyCount = sizeof(g_Gen_ls_LevelRootComponent_Properties) / sizeof(g_Gen_ls_LevelRootComponent_Properties[0]),
};

// ======================================================================
// ls::PhysicsComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x18 (24 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_PhysicsComponent_Properties[] = {
    { "PhysicsGroup", 0x00, FIELD_TYPE_UINT32, 0, true },
    { "CollidesWith", 0x04, FIELD_TYPE_UINT32, 0, true },
    { "ExtraFlags", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "field_15", 0x0c, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_PhysicsComponent_Layout = {
    .componentName = "ls::PhysicsComponent",
    .shortName = "Physics",
    .componentTypeIndex = 0,
    .componentSize = 0x18,
    .properties = g_Gen_ls_PhysicsComponent_Properties,
    .propertyCount = sizeof(g_Gen_ls_PhysicsComponent_Properties) / sizeof(g_Gen_ls_PhysicsComponent_Properties[0]),
};

// ======================================================================
// ls::SoundComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x20 (32 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_SoundComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "Flags", 0x08, FIELD_TYPE_UINT32, 0, true },
    { "Duration", 0x0c, FIELD_TYPE_FLOAT, 0, true },
    { "Effect", 0x10, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "field_1C", 0x14, FIELD_TYPE_FLOAT, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_SoundComponent_Layout = {
    .componentName = "ls::SoundComponent",
    .shortName = "Sound",
    .componentTypeIndex = 0,
    .componentSize = 0x20,
    .properties = g_Gen_ls_SoundComponent_Properties,
    .propertyCount = sizeof(g_Gen_ls_SoundComponent_Properties) / sizeof(g_Gen_ls_SoundComponent_Properties[0]),
};

// ======================================================================
// ls::TimeFactorComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x4 (4 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_TimeFactorComponent_Properties[] = {
    { "Value", 0x00, FIELD_TYPE_FLOAT, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_TimeFactorComponent_Layout = {
    .componentName = "ls::TimeFactorComponent",
    .shortName = "TimeFactor",
    .componentTypeIndex = 0,
    .componentSize = 0x4,
    .properties = g_Gen_ls_TimeFactorComponent_Properties,
    .propertyCount = sizeof(g_Gen_ls_TimeFactorComponent_Properties) / sizeof(g_Gen_ls_TimeFactorComponent_Properties[0]),
};

// ======================================================================
// ls::VisualAttachRequestOneFrameComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x10 (16 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_VisualAttachRequestOneFrameComponent_Properties[] = {
    { "Entity", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
    { "field_8", 0x08, FIELD_TYPE_INT32, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_VisualAttachRequestOneFrameComponent_Layout = {
    .componentName = "ls::VisualAttachRequestOneFrameComponent",
    .shortName = "VisualAttachRequestOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_ls_VisualAttachRequestOneFrameComponent_Properties,
    .propertyCount = sizeof(g_Gen_ls_VisualAttachRequestOneFrameComponent_Properties) / sizeof(g_Gen_ls_VisualAttachRequestOneFrameComponent_Properties[0]),
};

// ======================================================================
// ls::VisualChangeRequestOneFrameComponent
// Generated from Windows BG3SE headers
// Windows Size: 0x8 (8 bytes) - Estimated
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_VisualChangeRequestOneFrameComponent_Properties[] = {
    { "VisualTemplate", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "RenderFlags", 0x04, FIELD_TYPE_UINT16, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_VisualChangeRequestOneFrameComponent_Layout = {
    .componentName = "ls::VisualChangeRequestOneFrameComponent",
    .shortName = "VisualChangeRequestOneFrame",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_ls_VisualChangeRequestOneFrameComponent_Properties,
    .propertyCount = sizeof(g_Gen_ls_VisualChangeRequestOneFrameComponent_Properties) / sizeof(g_Gen_ls_VisualChangeRequestOneFrameComponent_Properties[0]),
};

// ======================================================================
// ls::VisualComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_VisualComponent_Properties[] = {
    { "field_8", 0x08, FIELD_TYPE_UINT8, 0, true },
    { "field_9", 0x09, FIELD_TYPE_UINT8, 0, true },
    { "NotClustered", 0x02, FIELD_TYPE_BOOL, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_VisualComponent_Layout = {
    .componentName = "ls::VisualComponent",
    .shortName = "Visual",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_ls_VisualComponent_Properties,
    .propertyCount = sizeof(g_Gen_ls_VisualComponent_Properties) / sizeof(g_Gen_ls_VisualComponent_Properties[0]),
};

// ======================================================================
// ls::VisualLoadDesciptionComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_VisualLoadDesciptionComponent_Properties[] = {
    { "VisualTemplate", 0x00, FIELD_TYPE_FIXEDSTRING, 0, true },
    { "RenderFlags", 0x04, FIELD_TYPE_UINT16, 0, true },
    { "RenderChannel", 0x06, FIELD_TYPE_UINT8, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_VisualLoadDesciptionComponent_Layout = {
    .componentName = "ls::VisualLoadDesciptionComponent",
    .shortName = "VisualLoadDesciption",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_ls_VisualLoadDesciptionComponent_Properties,
    .propertyCount = sizeof(g_Gen_ls_VisualLoadDesciptionComponent_Properties) / sizeof(g_Gen_ls_VisualLoadDesciptionComponent_Properties[0]),
};

// ======================================================================
// ls::level::LevelInstanceTempDestroyedComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x8 (8 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_level_LevelInstanceTempDestroyedComponent_Properties[] = {
    { "Level", 0x00, FIELD_TYPE_ENTITY_HANDLE, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_level_LevelInstanceTempDestroyedComponent_Layout = {
    .componentName = "ls::level::LevelInstanceTempDestroyedComponent",
    .shortName = "LevelInstanceTempDestroyed",
    .componentTypeIndex = 0,
    .componentSize = 0x8,
    .properties = g_Gen_ls_level_LevelInstanceTempDestroyedComponent_Properties,
    .propertyCount = sizeof(g_Gen_ls_level_LevelInstanceTempDestroyedComponent_Properties) / sizeof(g_Gen_ls_level_LevelInstanceTempDestroyedComponent_Properties[0]),
};

// ======================================================================
// ls::trigger::AreaComponent
// Generated from Windows BG3SE headers
// ARM64 Size: 0x88 (136 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_trigger_AreaComponent_Properties[] = {
    { "RotationInv", 0x00, FIELD_TYPE_VEC4, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_trigger_AreaComponent_Layout = {
    .componentName = "ls::trigger::AreaComponent",
    .shortName = "Area",
    .componentTypeIndex = 0,
    .componentSize = 0x88,
    .properties = g_Gen_ls_trigger_AreaComponent_Properties,
    .propertyCount = sizeof(g_Gen_ls_trigger_AreaComponent_Properties) / sizeof(g_Gen_ls_trigger_AreaComponent_Properties[0]),
};

// ======================================================================
// ls::uuid::Component
// Generated from Windows BG3SE headers
// ARM64 Size: 0x10 (16 bytes) - Ghidra verified
// ======================================================================

static const ComponentPropertyDef g_Gen_ls_uuid_Component_Properties[] = {
    { "EntityUuid", 0x00, FIELD_TYPE_GUID, 0, true },
};

static const ComponentLayoutDef g_Gen_ls_uuid_Component_Layout = {
    .componentName = "ls::uuid::Component",
    .shortName = "",
    .componentTypeIndex = 0,
    .componentSize = 0x10,
    .properties = g_Gen_ls_uuid_Component_Properties,
    .propertyCount = sizeof(g_Gen_ls_uuid_Component_Properties) / sizeof(g_Gen_ls_uuid_Component_Properties[0]),
};

#define GENERATED_COMPONENT_COUNT 293

static const ComponentLayoutDef* g_GeneratedComponentLayouts[] = {
    &g_Gen_ecl_CharacterIconRequestComponent_Layout,
    &g_Gen_ecl_CharacterLightComponent_Layout,
    &g_Gen_ecl_ClientTimelineActorControlComponent_Layout,
    &g_Gen_ecl_EquipmentVisualsComponent_Layout,
    &g_Gen_ecl_GameCameraBehavior_Layout,
    &g_Gen_ecl_PaperdollComponent_Layout,
    &g_Gen_ecl_Scenery_Layout,
    &g_Gen_ecl_TLPreviewDummy_Layout,
    &g_Gen_ecl_camera_SelectorModeComponent_Layout,
    &g_Gen_ecl_character_creation_CompanionDefinitionComponent_Layout,
    &g_Gen_ecl_character_creation_DefinitionStateComponent_Layout,
    &g_Gen_ecl_character_creation_DefinitionStateExComponent_Layout,
    &g_Gen_ecl_character_creation_DummyDefinitionComponent_Layout,
    &g_Gen_ecl_character_creation_FullRespecDefinitionComponent_Layout,
    &g_Gen_ecl_dummy_DummyComponent_Layout,
    &g_Gen_ecl_dummy_EquipmentVisualsStateComponent_Layout,
    &g_Gen_ecl_dummy_FootIKStateComponent_Layout,
    &g_Gen_ecl_dummy_HasDummyComponent_Layout,
    &g_Gen_ecl_dummy_SplatterComponent_Layout,
    &g_Gen_ecl_dummy_UnsheathComponent_Layout,
    &g_Gen_ecl_equipment_VisualsVisibilityStateComponent_Layout,
    &g_Gen_ecl_photo_mode_CameraOffsetComponent_Layout,
    &g_Gen_ecl_photo_mode_CameraSavedTransformComponent_Layout,
    &g_Gen_ecl_photo_mode_CameraTiltComponent_Layout,
    &g_Gen_ecl_photo_mode_CameraTrackingComponent_Layout,
    &g_Gen_ecl_photo_mode_DummyEquipmentSetupOneFrameComponent_Layout,
    &g_Gen_ecl_photo_mode_RequestedSingletonComponent_Layout,
    &g_Gen_eoc_ArmorComponent_Layout,
    &g_Gen_eoc_AttributeFlagsComponent_Layout,
    &g_Gen_eoc_BackgroundComponent_Layout,
    &g_Gen_eoc_BaseHpComponent_Layout,
    &g_Gen_eoc_BlockAbilityModifierFromACComponent_Layout,
    &g_Gen_eoc_BodyTypeComponent_Layout,
    &g_Gen_eoc_BoostConditionComponent_Layout,
    &g_Gen_eoc_BoostInfoComponent_Layout,
    &g_Gen_eoc_CanBeDisarmedComponent_Layout,
    &g_Gen_eoc_CanBeLootedComponent_Layout,
    &g_Gen_eoc_CanDeflectProjectilesComponent_Layout,
    &g_Gen_eoc_CanInteractComponent_Layout,
    &g_Gen_eoc_CanModifyHealthComponent_Layout,
    &g_Gen_eoc_CanMoveComponent_Layout,
    &g_Gen_eoc_CanSenseComponent_Layout,
    &g_Gen_eoc_CanSpeakComponent_Layout,
    &g_Gen_eoc_CanTravelComponent_Layout,
    &g_Gen_eoc_CharacterCreationStatsComponent_Layout,
    &g_Gen_eoc_CombinedLightComponent_Layout,
    &g_Gen_eoc_CustomIconComponent_Layout,
    &g_Gen_eoc_DamageReductionBoostComponent_Layout,
    &g_Gen_eoc_DarknessComponent_Layout,
    &g_Gen_eoc_DataComponent_Layout,
    &g_Gen_eoc_DetachedComponent_Layout,
    &g_Gen_eoc_DifficultyCheckComponent_Layout,
    &g_Gen_eoc_DisabledEquipmentComponent_Layout,
    &g_Gen_eoc_DisarmableComponent_Layout,
    &g_Gen_eoc_DualWieldingComponent_Layout,
    &g_Gen_eoc_FloatingComponent_Layout,
    &g_Gen_eoc_FogVolumeRequestComponent_Layout,
    &g_Gen_eoc_GameObjectVisualComponent_Layout,
    &g_Gen_eoc_GameplayLightComponent_Layout,
    &g_Gen_eoc_HealthComponent_Layout,
    &g_Gen_eoc_HearingComponent_Layout,
    &g_Gen_eoc_IconComponent_Layout,
    &g_Gen_eoc_IncreaseMaxHPBoostComponent_Layout,
    &g_Gen_eoc_InteractionFilterComponent_Layout,
    &g_Gen_eoc_InvisibilityComponent_Layout,
    &g_Gen_eoc_LevelComponent_Layout,
    &g_Gen_eoc_LootComponent_Layout,
    &g_Gen_eoc_LootingStateComponent_Layout,
    &g_Gen_eoc_MovementComponent_Layout,
    &g_Gen_eoc_ObjectSizeComponent_Layout,
    &g_Gen_eoc_OriginComponent_Layout,
    &g_Gen_eoc_PassiveComponent_Layout,
    &g_Gen_eoc_PathingComponent_Layout,
    &g_Gen_eoc_RaceComponent_Layout,
    &g_Gen_eoc_RequestedRollComponent_Layout,
    &g_Gen_eoc_ResistancesComponent_Layout,
    &g_Gen_eoc_StatsComponent_Layout,
    &g_Gen_eoc_StealthComponent_Layout,
    &g_Gen_eoc_SteeringComponent_Layout,
    &g_Gen_eoc_TimelineActorDataComponent_Layout,
    &g_Gen_eoc_TurnBasedComponent_Layout,
    &g_Gen_eoc_TurnOrderComponent_Layout,
    &g_Gen_eoc_UseComponent_Layout,
    &g_Gen_eoc_ValueComponent_Layout,
    &g_Gen_eoc_VoiceComponent_Layout,
    &g_Gen_eoc_WeaponComponent_Layout,
    &g_Gen_eoc_WieldingComponent_Layout,
    &g_Gen_eoc_active_roll_ModifiersComponent_Layout,
    &g_Gen_eoc_calendar_DaysPassedComponent_Layout,
    &g_Gen_eoc_calendar_StartingDateComponent_Layout,
    &g_Gen_eoc_camp_ChestComponent_Layout,
    &g_Gen_eoc_camp_EndTheDayStateComponent_Layout,
    &g_Gen_eoc_camp_QualityComponent_Layout,
    &g_Gen_eoc_camp_SettingsComponent_Layout,
    &g_Gen_eoc_camp_SupplyComponent_Layout,
    &g_Gen_eoc_camp_TotalSuppliesComponent_Layout,
    &g_Gen_eoc_character_EquipmentVisualComponent_Layout,
    &g_Gen_eoc_character_creation_AppearanceComponent_Layout,
    &g_Gen_eoc_character_creation_ChangeAppearanceDefinitionComponent_Layout,
    &g_Gen_eoc_character_creation_CharacterDefinitionComponent_Layout,
    &g_Gen_eoc_character_creation_CompanionDefinitionComponent_Layout,
    &g_Gen_eoc_character_creation_DefinitionCommonComponent_Layout,
    &g_Gen_eoc_character_creation_FullRespecDefinitionComponent_Layout,
    &g_Gen_eoc_character_creation_LevelUpDefinitionComponent_Layout,
    &g_Gen_eoc_character_creation_RespecDefinitionComponent_Layout,
    &g_Gen_eoc_character_creation_SessionCommonComponent_Layout,
    &g_Gen_eoc_character_creation_StateComponent_Layout,
    &g_Gen_eoc_character_creation_definition_CreationComponent_Layout,
    &g_Gen_eoc_character_creation_definition_LevelUpComponent_Layout,
    &g_Gen_eoc_chasm_CanEnterChasmComponent_Layout,
    &g_Gen_eoc_combat_ParticipantComponent_Layout,
    &g_Gen_eoc_combat_StateComponent_Layout,
    &g_Gen_eoc_combat_ThreatRangeComponent_Layout,
    &g_Gen_eoc_death_DeadByDefaultComponent_Layout,
    &g_Gen_eoc_death_DeathTypeComponent_Layout,
    &g_Gen_eoc_death_DownedComponent_Layout,
    &g_Gen_eoc_death_StateComponent_Layout,
    &g_Gen_eoc_dialog_StateComponent_Layout,
    &g_Gen_eoc_encumbrance_StateComponent_Layout,
    &g_Gen_eoc_exp_AvailableLevelComponent_Layout,
    &g_Gen_eoc_exp_ExperienceComponent_Layout,
    &g_Gen_eoc_ftb_ParticipantComponent_Layout,
    &g_Gen_eoc_ftb_ZoneBlockReasonComponent_Layout,
    &g_Gen_eoc_god_GodComponent_Layout,
    &g_Gen_eoc_hit_AttackerComponent_Layout,
    &g_Gen_eoc_hit_LifetimeComponent_Layout,
    &g_Gen_eoc_hit_MetaComponent_Layout,
    &g_Gen_eoc_hit_ProxyComponent_Layout,
    &g_Gen_eoc_hit_TargetComponent_Layout,
    &g_Gen_eoc_hit_ThrownObjectComponent_Layout,
    &g_Gen_eoc_hit_WeaponComponent_Layout,
    &g_Gen_eoc_hotbar_ContainerComponent_Layout,
    &g_Gen_eoc_identity_IdentityComponent_Layout,
    &g_Gen_eoc_identity_OriginalIdentityComponent_Layout,
    &g_Gen_eoc_improvised_weapon_WieldedComponent_Layout,
    &g_Gen_eoc_improvised_weapon_WieldingComponent_Layout,
    &g_Gen_eoc_interrupt_ActionStateComponent_Layout,
    &g_Gen_eoc_interrupt_ConditionallyDisabledComponent_Layout,
    &g_Gen_eoc_interrupt_DataComponent_Layout,
    &g_Gen_eoc_interrupt_PreparedComponent_Layout,
    &g_Gen_eoc_interrupt_ZoneComponent_Layout,
    &g_Gen_eoc_interrupt_ZoneSourceComponent_Layout,
    &g_Gen_eoc_inventory_IsOwnedComponent_Layout,
    &g_Gen_eoc_inventory_MemberComponent_Layout,
    &g_Gen_eoc_inventory_OwnerComponent_Layout,
    &g_Gen_eoc_inventory_StackMemberComponent_Layout,
    &g_Gen_eoc_inventory_TopOwnerComponent_Layout,
    &g_Gen_eoc_inventory_TradeBuybackDataComponent_Layout,
    &g_Gen_eoc_inventory_WeightComponent_Layout,
    &g_Gen_eoc_inventory_WieldedComponent_Layout,
    &g_Gen_eoc_inventory_WieldingHistoryComponent_Layout,
    &g_Gen_eoc_item_DyeComponent_Layout,
    &g_Gen_eoc_item_MapMarkerStyleComponent_Layout,
    &g_Gen_eoc_item_PortalComponent_Layout,
    &g_Gen_eoc_light_ActiveCharacterLightComponent_Layout,
    &g_Gen_eoc_lock_KeyComponent_Layout,
    &g_Gen_eoc_lock_LockComponent_Layout,
    &g_Gen_eoc_object_visual_CharacterCreationTemplateOverrideComponent_Layout,
    &g_Gen_eoc_ownership_OwneeCurrentComponent_Layout,
    &g_Gen_eoc_party_CompositionComponent_Layout,
    &g_Gen_eoc_party_FollowerComponent_Layout,
    &g_Gen_eoc_party_MemberComponent_Layout,
    &g_Gen_eoc_photo_mode_DummyAnimationStateComponent_Layout,
    &g_Gen_eoc_photo_mode_DummyComponent_Layout,
    &g_Gen_eoc_photo_mode_DummyEquipmentVisualComponent_Layout,
    &g_Gen_eoc_photo_mode_DummyShowSplatterComponent_Layout,
    &g_Gen_eoc_photo_mode_SessionComponent_Layout,
    &g_Gen_eoc_pickup_PickUpRequestComponent_Layout,
    &g_Gen_eoc_progression_FeatComponent_Layout,
    &g_Gen_eoc_progression_MetaComponent_Layout,
    &g_Gen_eoc_progression_ReplicatedFeatComponent_Layout,
    &g_Gen_eoc_projectile_SourceInfoComponent_Layout,
    &g_Gen_eoc_relation_FactionComponent_Layout,
    &g_Gen_eoc_repose_StateComponent_Layout,
    &g_Gen_eoc_rest_LongRestState_Layout,
    &g_Gen_eoc_rest_LongRestTimeline_Layout,
    &g_Gen_eoc_rest_LongRestTimers_Layout,
    &g_Gen_eoc_rest_LongRestUsers_Layout,
    &g_Gen_eoc_rest_RestingEntities_Layout,
    &g_Gen_eoc_ruleset_RulesetComponent_Layout,
    &g_Gen_eoc_shapeshift_AnimationComponent_Layout,
    &g_Gen_eoc_shapeshift_RecoveryAnimationComponent_Layout,
    &g_Gen_eoc_shapeshift_ReplicatedChangesComponent_Layout,
    &g_Gen_eoc_sight_DataComponent_Layout,
    &g_Gen_eoc_spatial_grid_DataComponent_Layout,
    &g_Gen_eoc_spell_ScriptedExplosionComponent_Layout,
    &g_Gen_eoc_spell_cast_AnimationInfoComponent_Layout,
    &g_Gen_eoc_spell_cast_CacheComponent_Layout,
    &g_Gen_eoc_spell_cast_InterruptResultsComponent_Layout,
    &g_Gen_eoc_spell_cast_IsCastingComponent_Layout,
    &g_Gen_eoc_spell_cast_MovementComponent_Layout,
    &g_Gen_eoc_spell_cast_StateComponent_Layout,
    &g_Gen_eoc_spell_cast_SyncTargetingComponent_Layout,
    &g_Gen_eoc_status_CauseComponent_Layout,
    &g_Gen_eoc_status_IDComponent_Layout,
    &g_Gen_eoc_status_IncapacitatedComponent_Layout,
    &g_Gen_eoc_status_LifetimeComponent_Layout,
    &g_Gen_eoc_status_LoseControlComponent_Layout,
    &g_Gen_eoc_summon_IsSummonComponent_Layout,
    &g_Gen_eoc_tadpole_tree_TreeStateComponent_Layout,
    &g_Gen_eoc_templates_OriginalTemplateComponent_Layout,
    &g_Gen_eoc_through_ShootThroughTypeComponent_Layout,
    &g_Gen_eoc_trigger_TypeComponent_Layout,
    &g_Gen_eoc_unsheath_StateComponent_Layout,
    &g_Gen_eoc_user_AvatarComponent_Layout,
    &g_Gen_eoc_user_ReservedForComponent_Layout,
    &g_Gen_esv_AnubisExecutorComponent_Layout,
    &g_Gen_esv_BaseDataComponent_Layout,
    &g_Gen_esv_BaseSizeComponent_Layout,
    &g_Gen_esv_BaseStatsComponent_Layout,
    &g_Gen_esv_BreadcrumbComponent_Layout,
    &g_Gen_esv_GameTimerComponent_Layout,
    &g_Gen_esv_JumpFollowComponent_Layout,
    &g_Gen_esv_Projectile_Layout,
    &g_Gen_esv_SafePositionComponent_Layout,
    &g_Gen_esv_active_roll_InProgressComponent_Layout,
    &g_Gen_esv_active_roll_StartRequestOneFrameComponent_Layout,
    &g_Gen_esv_ai_combat_AiModifiersComponent_Layout,
    &g_Gen_esv_ai_combat_ArchetypeComponent_Layout,
    &g_Gen_esv_character_creation_GodComponent_Layout,
    &g_Gen_esv_combat_CombatGroupMappingComponent_Layout,
    &g_Gen_esv_combat_CombatSwitchedComponent_Layout,
    &g_Gen_esv_combat_FleeRequestComponent_Layout,
    &g_Gen_esv_combat_JoiningComponent_Layout,
    &g_Gen_esv_combat_LateJoinPenaltyComponent_Layout,
    &g_Gen_esv_combat_MergeComponent_Layout,
    &g_Gen_esv_death_DelayDeathCauseComponent_Layout,
    &g_Gen_esv_death_DelayedDeathComponent_Layout,
    &g_Gen_esv_death_StateComponent_Layout,
    &g_Gen_esv_escort_FollowerComponent_Layout,
    &g_Gen_esv_escort_LeaderComponent_Layout,
    &g_Gen_esv_escort_MemberComponent_Layout,
    &g_Gen_esv_escort_StragglersTrackerComponent_Layout,
    &g_Gen_esv_exp_ExperienceGaveOutComponent_Layout,
    &g_Gen_esv_ftb_ZoneComponent_Layout,
    &g_Gen_esv_ftb_ZoneInstigatorComponent_Layout,
    &g_Gen_esv_history_TargetUUIDComponent_Layout,
    &g_Gen_esv_inventory_ContainerDataComponent_Layout,
    &g_Gen_esv_inventory_GroupCheckComponent_Layout,
    &g_Gen_esv_item_DynamicLayerOwnerComponent_Layout,
    &g_Gen_esv_light_GameplayLightChangesComponent_Layout,
    &g_Gen_esv_ownership_OwneeHistoryComponent_Layout,
    &g_Gen_esv_passive_PersistentDataComponent_Layout,
    &g_Gen_esv_photo_mode_CapabilityComponent_Layout,
    &g_Gen_esv_projectile_AttachmentComponent_Layout,
    &g_Gen_esv_projectile_SpellComponent_Layout,
    &g_Gen_esv_recruit_RecruitedByComponent_Layout,
    &g_Gen_esv_replication_ReplicationDependencyComponent_Layout,
    &g_Gen_esv_roll_stream_StreamsComponent_Layout,
    &g_Gen_esv_shapeshift_StatesComponent_Layout,
    &g_Gen_esv_sight_AggregatedDataComponent_Layout,
    &g_Gen_esv_sight_AggregatedGameplayLightDataComponent_Layout,
    &g_Gen_esv_sight_AiGridViewshedComponent_Layout,
    &g_Gen_esv_spell_cast_CacheComponent_Layout,
    &g_Gen_esv_spell_cast_CastHitDelayComponent_Layout,
    &g_Gen_esv_spell_cast_CastResponsibleComponent_Layout,
    &g_Gen_esv_spell_cast_InterruptDataComponent_Layout,
    &g_Gen_esv_spell_cast_MovementComponent_Layout,
    &g_Gen_esv_spell_cast_StateComponent_Layout,
    &g_Gen_esv_spell_cast_ZoneRangeComponent_Layout,
    &g_Gen_esv_stats_proficiency_BaseProficiencyComponent_Layout,
    &g_Gen_esv_stats_proficiency_ProficiencyGroupStatsComponent_Layout,
    &g_Gen_esv_status_CauseComponent_Layout,
    &g_Gen_esv_status_OwnershipComponent_Layout,
    &g_Gen_esv_status_PerformingComponent_Layout,
    &g_Gen_esv_status_StatusComponent_Layout,
    &g_Gen_esv_status_aura_RemovedStatusAuraEffectEventOneFrameComponent_Layout,
    &g_Gen_esv_surface_SurfaceComponent_Layout,
    &g_Gen_esv_trigger_EventConfigComponent_Layout,
    &g_Gen_esv_trigger_RegistrationSettingsComponent_Layout,
    &g_Gen_esv_unsheath_DefaultComponent_Layout,
    &g_Gen_ls_AnimationBlueprintComponent_Layout,
    &g_Gen_ls_AnimationSetComponent_Layout,
    &g_Gen_ls_CameraComponent_Layout,
    &g_Gen_ls_CullComponent_Layout,
    &g_Gen_ls_DecalComponent_Layout,
    &g_Gen_ls_DefaultCameraBehavior_Layout,
    &g_Gen_ls_EffectCameraBehavior_Layout,
    &g_Gen_ls_EffectComponent_Layout,
    &g_Gen_ls_LevelComponent_Layout,
    &g_Gen_ls_LevelInstanceComponent_Layout,
    &g_Gen_ls_LevelInstanceStateComponent_Layout,
    &g_Gen_ls_LevelRootComponent_Layout,
    &g_Gen_ls_PhysicsComponent_Layout,
    &g_Gen_ls_SoundComponent_Layout,
    &g_Gen_ls_TimeFactorComponent_Layout,
    &g_Gen_ls_VisualAttachRequestOneFrameComponent_Layout,
    &g_Gen_ls_VisualChangeRequestOneFrameComponent_Layout,
    &g_Gen_ls_VisualComponent_Layout,
    &g_Gen_ls_VisualLoadDesciptionComponent_Layout,
    &g_Gen_ls_level_LevelInstanceTempDestroyedComponent_Layout,
    &g_Gen_ls_trigger_AreaComponent_Layout,
    &g_Gen_ls_uuid_Component_Layout,
    NULL
};

#endif // GENERATED_PROPERTY_DEFS_H
