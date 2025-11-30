/**
 * BG3SE-macOS - Entity Component System
 *
 * This module provides access to the game's Entity Component System (ECS).
 * It allows looking up entities by GUID and accessing their components.
 *
 * Architecture matches Windows BG3SE:
 * - EntityWorld is the central ECS manager
 * - EntityHandle is a 64-bit packed value (index, salt, type)
 * - Components are accessed via GetComponent<T>(handle)
 */

#ifndef ENTITY_SYSTEM_H
#define ENTITY_SYSTEM_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// EntityHandle - 64-bit packed entity reference
// ============================================================================

typedef uint64_t EntityHandle;

// EntityHandle bit layout (same as Windows):
// - Bits 0-31:  Entity Index (within type)
// - Bits 32-47: Salt (generation counter for reuse detection)
// - Bits 48-63: Type Index (entity archetype)

#define ENTITY_HANDLE_INVALID 0xFFFFFFFFFFFFFFFFULL

static inline uint32_t entity_get_index(EntityHandle h) {
    return (uint32_t)(h & 0xFFFFFFFF);
}

static inline uint16_t entity_get_salt(EntityHandle h) {
    return (uint16_t)((h >> 32) & 0xFFFF);
}

static inline uint16_t entity_get_type(EntityHandle h) {
    return (uint16_t)((h >> 48) & 0xFFFF);
}

static inline bool entity_is_valid(EntityHandle h) {
    return h != ENTITY_HANDLE_INVALID;
}

// ============================================================================
// GUID - 128-bit unique identifier
// ============================================================================

typedef struct {
    uint64_t lo;
    uint64_t hi;
} Guid;

// Parse GUID from string format: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
bool guid_parse(const char *str, Guid *out);

// Format GUID to string (buffer must be at least 37 bytes)
void guid_to_string(const Guid *guid, char *out);

// ============================================================================
// Component Types
// ============================================================================

// Component type indices (discovered from ARM64 binary)
// Note: Only components with discovered GetComponent addresses are fully implemented
typedef enum {
    // Implemented - have GetComponent function addresses
    COMPONENT_TRANSFORM = 0,     // ls::TransformComponent - 0x10010d5b00
    COMPONENT_LEVEL,             // ls::LevelComponent - 0x10010d588c
    COMPONENT_PHYSICS,           // ls::PhysicsComponent - 0x101ba0898
    COMPONENT_VISUAL,            // ls::VisualComponent - 0x102e56350

    // Not yet implemented - need to find GetComponent addresses via Ghidra
    COMPONENT_STATS,             // eoc::StatsComponent
    COMPONENT_BASE_HP,           // eoc::BaseHpComponent
    COMPONENT_HEALTH,            // eoc::HealthComponent
    COMPONENT_ARMOR,             // eoc::ArmorComponent
    COMPONENT_CLASSES,           // eoc::ClassesComponent
    COMPONENT_RACE,              // eoc::RaceComponent
    COMPONENT_PLAYER,            // eoc::PlayerComponent

    COMPONENT_COUNT
} ComponentType;

// ============================================================================
// Transform Component
// ============================================================================

typedef struct {
    float position[3];      // x, y, z
    float rotation[4];      // quaternion (x, y, z, w)
    float scale[3];         // x, y, z
} TransformComponent;

// ============================================================================
// Stats Component (simplified - full version has ~40 fields)
// ============================================================================

typedef struct {
    int32_t initiative_bonus;
    int32_t abilities[7];           // STR, DEX, CON, INT, WIS, CHA, unused
    int32_t ability_modifiers[7];
    int32_t skills[18];
    int32_t proficiency_bonus;
    int32_t spell_casting_ability;
} StatsComponent;

// ============================================================================
// BaseHp Component
// ============================================================================

typedef struct {
    int32_t vitality;
    int32_t vitality_boost;
} BaseHpComponent;

// ============================================================================
// Health Component
// ============================================================================

typedef struct {
    int32_t current_hp;
    int32_t max_hp;
    int32_t temp_hp;
    // Additional fields TBD from reverse engineering
} HealthComponent;

// ============================================================================
// Armor Component
// ============================================================================

typedef struct {
    int32_t armor_type;
    int32_t armor_class;
    int32_t ability_modifier_cap;
    uint8_t armor_class_ability;
    uint8_t equipment_type;
} ArmorComponent;

// ============================================================================
// Classes Component
// ============================================================================

typedef struct {
    uint64_t class_uuid_lo;
    uint64_t class_uuid_hi;
    uint64_t subclass_uuid_lo;
    uint64_t subclass_uuid_hi;
    int32_t level;
} ClassInfo;

typedef struct {
    // Array of ClassInfo - in practice this is a dynamic array
    // For now, support up to 4 multiclass levels
    ClassInfo classes[4];
    int32_t num_classes;
} ClassesComponent;

// ============================================================================
// EntityWorld Interface
// ============================================================================

// Opaque pointer to EntityWorld
typedef void* EntityWorldPtr;

/**
 * Get the current EntityWorld pointer.
 * Returns NULL if not yet captured.
 */
EntityWorldPtr entity_get_world(void);

/**
 * Look up an entity by GUID string.
 * Returns ENTITY_HANDLE_INVALID if not found.
 */
EntityHandle entity_get_by_guid(const char *guid_str);

/**
 * Check if an entity is alive (valid and not destroyed).
 */
bool entity_is_alive(EntityHandle handle);

/**
 * Get a component from an entity.
 * Returns NULL if entity doesn't have the component.
 */
void* entity_get_component(EntityHandle handle, ComponentType type);

/**
 * Get all component names for an entity.
 * Returns array of component name strings (NULL-terminated).
 * Caller must free the array (but not the strings).
 */
const char** entity_get_component_names(EntityHandle handle, int *count);

// ============================================================================
// Initialization
// ============================================================================

/**
 * Initialize the entity system.
 * Installs hooks to capture EntityWorld pointer.
 * Returns 0 on success, non-zero on failure.
 */
int entity_system_init(void *main_binary_base);

/**
 * Check if entity system is ready (EntityWorld captured).
 */
bool entity_system_ready(void);

/**
 * Attempt to discover EntityWorld via memory scanning.
 * Call this after the game server is initialized (e.g., after loading a save).
 * Returns true if EntityWorld was found, false otherwise.
 */
bool entity_discover_world(void);

// ============================================================================
// Lua Bindings
// ============================================================================

struct lua_State;

/**
 * Register Ext.Entity API with Lua state.
 */
void entity_register_lua(struct lua_State *L);

#ifdef __cplusplus
}
#endif

#endif // ENTITY_SYSTEM_H
