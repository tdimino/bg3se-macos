# BG3SE-macOS: Entity System Offsets

**Game Version:** Baldur's Gate 3 (macOS ARM64)
**Analysis Date:** 2025-11-28
**Status:** Complete - Ghidra analysis finished, key symbols identified

## Overview

The BG3 Entity Component System (ECS) follows the same architecture on macOS as Windows.

### Namespace Structure

| Namespace | Purpose |
|-----------|---------|
| `ecs::` | Core ECS infrastructure (EntityWorld, EntityHandle) |
| `eoc::` | Engine of Creation - shared game components |
| `esv::` | Server-side components and systems |
| `ecl::` | Client-side components and systems |
| `ls::` | Larian Studios core (Transform, Level, etc.) |

## Access Path (Windows Reference)

```
esv::EoCServer** (global pointer-to-pointer)
└── *esv::EoCServer (dereferenced)
    ├── GameStateMachine (offset 0xA0)
    ├── GameServer (offset 0xA8)
    ├── ModManager (offset 0xD0, size 0x1B0)
    └── EntityWorld* (offset 0x288)
        ├── Replication (SyncBuffers*)
        ├── ComponentRegistry_
        ├── HandleGenerator
        ├── Storage (EntityStorageContainer)
        └── Cache (ImmediateWorldCache)

ecl::EoCClient** (global pointer-to-pointer)
└── *ecl::EoCClient (dereferenced)
    ├── GameStateMachine (around offset 0x90)
    └── EntityWorld* (offset ~0x1B0)
```

## EntityHandle Structure

64-bit packed value:
- **Bits 0-31**: Entity Index (within type)
- **Bits 32-47**: Salt (generation counter for reuse detection)
- **Bits 48-63**: Type Index (entity archetype)

## Key Components (from strings analysis)

### Stats/Combat
- `eoc::StatsComponent` - Abilities, skills, proficiency
- `eoc::BaseStatsComponent` - Base stat values
- `eoc::BaseHpComponent` - Base HP (Vitality, VitalityBoost)
- `eoc::HealthComponent` - Current HP/health state
- `eoc::ArmorComponent` - AC, armor type
- `eoc::WeaponComponent` - Weapon data

### Character
- `eoc::ClassesComponent` - Class info (ClassUUID, Level)
- `eoc::LevelComponent` - Character level
- `eoc::BackgroundComponent` - Background
- `eoc::RaceComponent` - Race
- `eoc::OriginComponent` - Origin character data

### Position/Transform
- `ls::TransformComponent` - Position, rotation, scale

### Inventory
- `eoc::inventory::DataComponent` - Inventory data
- `eoc::inventory::ContainerComponent` - Container
- `eoc::inventory::MemberComponent` - Inventory membership

### Status/Effects
- `eoc::StatusContainerComponent` - Active statuses (TBD)
- `eoc::BoostsContainerComponent` - Active boosts

## Windows Reference Offsets

From Windows BG3SE (`BinaryMappings.xml`):
- EoCClient EntityWorld: offset 0x1A8 from EoCClient pointer
- EoCServer EntityWorld: offset ~0xA8 from EoCServer pointer

**Note:** ARM64 may have different offsets due to struct packing differences.

## Ghidra Analysis Targets

1. Find `esv__EoCServer` / `ecl__EoCClient` global pointers
2. Determine EntityWorld offset within these structures
3. Find `EntityWorld::GetRawComponent()` function
4. Map ComponentTypeIndex → component name strings

## Next Steps

1. Wait for Ghidra headless analysis to complete
2. Review `find_entity_offsets.py` output
3. Manually verify offsets in Ghidra GUI if needed
4. Create ARM64-specific pattern signatures

---

## Discovered Offsets

### libOsiris.dylib (Already Analyzed)

| Symbol | Offset | Description |
|--------|--------|-------------|
| `_OsiFunctionMan` | `0x0009f348` | Global pointer to OsiFunctionMan |
| `pFunctionData` | `0x0002a04c` | Function lookup method |
| `COsiris::Event` | `0x000513cc` | Event dispatch |

### Main Game Binary (ARM64)

#### Component String Addresses

| Component | String Address | Description |
|-----------|----------------|-------------|
| `eoc::StatsComponent` | `0x107b7ca22` | Character stats (abilities, skills) |
| `eoc::BaseHpComponent` | `0x107b84c63` | Base HP values |
| `ls::TransformComponent` | `0x107b619cc` | Position, rotation, scale |
| `eoc::ArmorComponent` | `0x107b7c9e7` | AC and armor data |
| `eoc::DataComponent` | `0x107b7c833` | Generic data component |
| `esv::Character` | `0x107b4bf6e` | Server character entity |

#### EntityWorld::GetComponent Template Instances

| Component Type | Method Address | Notes |
|---------------|----------------|-------|
| `ls::TransformComponent` | `0x10010d5b00` | Position access |
| `ls::LevelComponent` | `0x10010d588c` | Level info |
| `ls::PhysicsComponent` | `0x101ba0898` | Physics state |
| `ls::DebugComponent` | `0x101f22d80` | Debug info |
| `ls::CameraComponent` | `0x102f23c1c` | Camera data |
| `ls::EffectComponent` | `0x102ef2018` | Visual effects |
| `ls::VisualComponent` | `0x102e56350` | Visuals |

#### ECS Helper Functions

| Function | Address | Signature |
|----------|---------|-----------|
| `eoc::CombatHelpers::LEGACY_IsInCombat` | `0x10124f92c` | `(EntityHandle, EntityWorld&)` |
| `eoc::CombatHelpers::LEGACY_GetCombatFromGuid` | `0x101250074` | `(Guid&, EntityWorld&)` |
| `eoc::camp::Helpers::LEGACY_GetSettingsComponent` | `0x1011c72bc` | `(EntityWorld&)` |
| `ecl::ProjectileHelpers::TryGetAttachedProjectile` | `0x1031159c8` | `(EntityWorld&, EntityHandle)` |
| `esv::ProjectileHelpers::TryGetAttachedProjectile` | `0x104cc4b3c` | `(EntityWorld&, EntityHandle)` |

#### Key Observations

1. **Singletons Not Exported**: The `esv::EoCServer` and `ecl::EoCClient` singleton pointers are not directly exported symbols - they're likely static locals or accessed via accessors

2. **LEGACY_ Functions**: Many helper functions have `LEGACY_` prefix, suggesting refactoring from older patterns

3. **Same Architecture**: The macOS binary uses identical ECS patterns to Windows - same component names, same EntityWorld structure

4. **GameServer/GameClient**: Build debug paths confirm:
   - `EoCServer/Server/GameServer.cpp`
   - `EoCClient/Client/GameClient.cpp`

#### Next: Finding Singletons at Runtime

Since global singletons aren't exported, we have two options:

1. **Pattern Scan at Runtime**: Search for characteristic instruction sequences that access the singletons

2. **Hook Entry Points**: Hook a known function that receives EntityWorld& as a parameter, capture the pointer

Recommended approach: Hook `eoc::CombatHelpers::LEGACY_IsInCombat` at `0x10124f92c` which receives `EntityWorld&` - this gives us a live EntityWorld pointer during gameplay

---

## Component Registry (from symbol analysis)

### Core Components (`ls::`)

| Component | Symbol Length | Description |
|-----------|---------------|-------------|
| `ls::TransformComponent` | 18 | Position, rotation, scale |
| `ls::LevelComponent` | 14 | Level/map reference |
| `ls::PhysicsComponent` | 16 | Physics state |
| `ls::DebugComponent` | 14 | Debug info |
| `ls::VisualComponent` | 15 | Visual rendering |
| `ls::CameraComponent` | 15 | Camera data |
| `ls::EffectComponent` | 15 | Visual effects |
| `ls::SoundComponent` | 14 | Audio |
| `ls::LightComponent` | 14 | Lighting |
| `ls::AnimationSetComponent` | 21 | Animations |

### Game Components (`eoc::`)

| Component | Description |
|-----------|-------------|
| `eoc::StatsComponent` | Character stats (abilities, skills, proficiency) |
| `eoc::BaseHpComponent` | Base HP (Vitality, VitalityBoost) |
| `eoc::HealthComponent` | Current HP/health state |
| `eoc::ArmorComponent` | AC and armor data |
| `eoc::WeaponComponent` | Weapon properties |
| `eoc::ClassesComponent` | Class info (ClassUUID, Level) |
| `eoc::LevelComponent` | Character level |
| `eoc::RaceComponent` | Race data |
| `eoc::OriginComponent` | Origin character data |
| `eoc::DataComponent` | Generic entity data |
| `eoc::TagComponent` | Entity tags |
| `eoc::PlayerComponent` | Player-controlled flag |
| `eoc::ActiveComponent` | Entity active state |
| `eoc::PassiveComponent` | Passive features |
| `eoc::CanMoveComponent` | Movement capability |
| `eoc::CanSenseComponent` | Sensing capability |
| `eoc::StealthComponent` | Stealth state |
| `eoc::MovementComponent` | Movement data |
| `eoc::BodyTypeComponent` | Body type info |
| `eoc::IconComponent` | UI icon |
| `eoc::ValueComponent` | Item value |
| `eoc::UseComponent` | Usable item |

### Server Components (`esv::`)

| Component | Description |
|-----------|-------------|
| `esv::Character` | Server character entity |
| `esv::Item` | Server item entity |
| `esv::GameServer` | Server singleton (not exported) |

### Client Components (`ecl::`)

| Component | Description |
|-----------|-------------|
| `ecl::Character` | Client character entity |
| `ecl::Item` | Client item entity |
| `ecl::GameClient` | Client singleton (not exported) |

---

## Implementation Strategy for Phase 2

### Step 1: Capture EntityWorld Pointer

Hook a function that receives `EntityWorld&`:

```c
// Target function: eoc::CombatHelpers::LEGACY_IsInCombat
// Address: 0x10124f92c (relative to binary base)
// Signature: bool LEGACY_IsInCombat(EntityHandle, EntityWorld&)

static ecs_EntityWorld *g_EntityWorld = NULL;

bool hook_LEGACY_IsInCombat(uint64_t handle, void *entityWorld) {
    if (!g_EntityWorld) {
        g_EntityWorld = entityWorld;
        printf("[BG3SE] Captured EntityWorld: %p\n", entityWorld);
    }
    return original_LEGACY_IsInCombat(handle, entityWorld);
}
```

### Step 2: GUID to EntityHandle Lookup

Use `ls::uuid::ToHandleMappingComponent` to map GUIDs to handles:

```c
// Lookup entity by GUID string
EntityHandle get_entity_by_guid(const char *guid_str) {
    // Parse GUID string to binary format
    // Query ToHandleMappingComponent in EntityWorld
    // Return EntityHandle or invalid handle
}
```

### Step 3: Component Access

Use discovered GetComponent addresses:

```c
// Get TransformComponent for entity
ls_TransformComponent* get_transform(EntityHandle handle) {
    // Call EntityWorld::GetComponent<ls::TransformComponent>
    // Address: 0x10010d5b00 (relative)
    return call_get_component(g_EntityWorld, handle, COMPONENT_TRANSFORM);
}
```
