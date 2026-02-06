/**
 * stats_manager.h - Stats System Manager for BG3SE-macOS
 *
 * Provides access to the game's RPGStats system for reading and modifying
 * game statistics (weapons, armor, spells, statuses, passives, etc.)
 *
 * Architecture:
 *   RPGStats::m_ptr (global) -> RPGStats instance -> CNamedElementManager<Object>
 *   Objects manager contains stat entries with properties stored as indices
 *   into global property pools (strings, floats, ints, GUIDs).
 */

#ifndef STATS_MANAGER_H
#define STATS_MANAGER_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// Opaque handle for stat objects
typedef void* StatsObjectPtr;

// Forward declaration for internal types
typedef struct RPGStats RPGStats;
typedef struct StatsObject StatsObject;

// ============================================================================
// Initialization
// ============================================================================

/**
 * Initialize the stats manager.
 * Must be called after the game binary is loaded.
 *
 * @param main_binary_base Base address of the main game binary (for offset calculation)
 */
void stats_manager_init(void *main_binary_base);

/**
 * Called at SessionLoaded to verify stats system is ready.
 * Logs diagnostic information about the stats pointer state.
 */
void stats_manager_on_session_loaded(void);

/**
 * Check if the stats system is ready (RPGStats::m_ptr is non-null).
 *
 * @return true if stats system is initialized and accessible
 */
bool stats_manager_ready(void);

/**
 * Get the raw RPGStats pointer (for debugging).
 *
 * @return Pointer to RPGStats instance, or NULL if not ready
 */
void* stats_manager_get_raw(void);

// ============================================================================
// Stat Object Access
// ============================================================================

/**
 * Get a stat object by name.
 *
 * @param name Stat entry name (e.g., "Weapon_Longsword", "Armor_Leather")
 * @return Opaque pointer to stat object, or NULL if not found
 */
StatsObjectPtr stats_get(const char *name);

/**
 * Get the type (ModifierList name) of a stat object.
 *
 * @param obj Stat object pointer from stats_get()
 * @return Type name (e.g., "Weapon", "Armor", "SpellData"), or NULL on error
 */
const char* stats_get_type(StatsObjectPtr obj);

/**
 * Get the name of a stat object.
 *
 * @param obj Stat object pointer from stats_get()
 * @return Stat entry name, or NULL on error
 */
const char* stats_get_name(StatsObjectPtr obj);

/**
 * Get the level of a stat object.
 *
 * @param obj Stat object pointer from stats_get()
 * @return Level value, or -1 on error
 */
int stats_get_level(StatsObjectPtr obj);

/**
 * Get the parent stat name (Using field).
 *
 * @param obj Stat object pointer from stats_get()
 * @return Parent stat name, or NULL if no parent or on error
 */
const char* stats_get_using(StatsObjectPtr obj);

// ============================================================================
// IndexedProperties Access (Low-Level)
// ============================================================================

/**
 * Get the number of indexed properties for a stat object.
 *
 * @param obj Stat object pointer from stats_get()
 * @return Number of properties, or -1 on error
 */
int stats_get_property_count(StatsObjectPtr obj);

/**
 * Get a raw property index value at the given position.
 * The returned value is an index into a global pool (strings, enums, etc.)
 *
 * @param obj Stat object pointer from stats_get()
 * @param property_index Index into the IndexedProperties array
 * @return The int32_t value at that index, or -1 on error
 */
int32_t stats_get_property_raw(StatsObjectPtr obj, int property_index);

// ============================================================================
// Property Access (Read)
// ============================================================================

/**
 * Get a string property value.
 *
 * @param obj Stat object pointer
 * @param prop Property name (e.g., "Damage", "DamageType")
 * @return String value, or NULL if property not found or wrong type
 */
const char* stats_get_string(StatsObjectPtr obj, const char *prop);

/**
 * Get an integer property value.
 *
 * @param obj Stat object pointer
 * @param prop Property name
 * @param out_value Output parameter for the value
 * @return true if successful, false on error
 */
bool stats_get_int(StatsObjectPtr obj, const char *prop, int64_t *out_value);

/**
 * Get a float property value.
 *
 * @param obj Stat object pointer
 * @param prop Property name
 * @param out_value Output parameter for the value
 * @return true if successful, false on error
 */
bool stats_get_float(StatsObjectPtr obj, const char *prop, float *out_value);

// ============================================================================
// Property Access (Write) - Phase 4
// ============================================================================

/**
 * Set a string property value.
 *
 * @param obj Stat object pointer
 * @param prop Property name
 * @param value New string value
 * @return true if successful, false on error
 */
bool stats_set_string(StatsObjectPtr obj, const char *prop, const char *value);

/**
 * Set an integer property value.
 *
 * @param obj Stat object pointer
 * @param prop Property name
 * @param value New integer value
 * @return true if successful, false on error
 */
bool stats_set_int(StatsObjectPtr obj, const char *prop, int64_t value);

/**
 * Set a float property value.
 *
 * @param obj Stat object pointer
 * @param prop Property name
 * @param value New float value
 * @return true if successful, false on error
 */
bool stats_set_float(StatsObjectPtr obj, const char *prop, float value);

// ============================================================================
// Sync and Persistence - Phase 4
// ============================================================================

/**
 * Sync a modified stat to the game engine.
 * This propagates changes to prototypes and recalculates derived values.
 *
 * @param name Stat entry name to sync
 * @return true if successful, false on error
 */
bool stats_sync(const char *name);

// ============================================================================
// Enumeration
// ============================================================================

/**
 * Get the count of stats of a given type.
 *
 * @param type Type name (e.g., "Weapon", "Armor", NULL for all)
 * @return Number of stats, or -1 on error
 */
int stats_get_count(const char *type);

/**
 * Get the name of a stat at a given index.
 *
 * @param type Type name (or NULL for all)
 * @param index Index into the filtered list
 * @return Stat name, or NULL if out of bounds
 */
const char* stats_get_name_at(const char *type, int index);

// ============================================================================
// Stat Creation - Phase 5
// ============================================================================

/**
 * Create a new stat object.
 *
 * @param name Name for the new stat
 * @param type Type (ModifierList name)
 * @param template_name Optional template stat to copy from (NULL for default)
 * @return New stat object pointer, or NULL on error
 */
StatsObjectPtr stats_create(const char *name, const char *type, const char *template_name);

/**
 * Check if a stat object is a shadow stat (created via stats_create).
 * Shadow stats are stored in a local registry, not in the game's RPGStats.Objects.
 *
 * @param obj Stat object pointer
 * @return true if shadow stat, false if game stat
 */
bool stats_is_shadow_stat(StatsObjectPtr obj);

// ============================================================================
// Enum Lookup (ModifierValueLists)
// ============================================================================

/**
 * Convert a stats enum index to its label string.
 *
 * @param enum_name Enum type name (e.g., "DamageType", "WeaponType")
 * @param index Enum index value
 * @return Label string, or NULL if not found
 */
const char* stats_enum_index_to_label(const char *enum_name, int32_t index);

/**
 * Convert a stats enum label to its index.
 *
 * @param enum_name Enum type name (e.g., "DamageType", "WeaponType")
 * @param label Enum label string
 * @return Index value, or -1 if not found
 */
int32_t stats_enum_label_to_index(const char *enum_name, const char *label);

// ============================================================================
// Modifier Attributes
// ============================================================================

/**
 * Get modifier attributes as an iteration.
 *
 * @param modifier_name Modifier list name (e.g., "Weapon", "Armor")
 * @param index Attribute index
 * @param out_attr_name Output: attribute name
 * @param out_type_name Output: attribute type name
 * @return true if attribute exists at index, false if out of range
 */
bool stats_get_modifier_attribute(const char *modifier_name, int index,
                                   const char **out_attr_name, const char **out_type_name);

/**
 * Get number of attributes for a modifier list.
 *
 * @param modifier_name Modifier list name
 * @return Number of attributes, or -1 if not found
 */
int stats_get_modifier_attribute_count_by_name(const char *modifier_name);

// ============================================================================
// StatsObject Methods (for Lua metatable)
// ============================================================================

/**
 * Copy all indexed properties from a source stat to a destination stat.
 * Both stats must have the same ModifierList (type).
 *
 * @param dst Destination stat object
 * @param parent_name Name of the source stat to copy from
 * @return true if copy succeeded, false on error
 */
bool stats_copy_from(StatsObjectPtr dst, const char *parent_name);

/**
 * Set a stat property from a raw string value.
 * This parses the string and sets the appropriate property.
 *
 * @param obj Stat object
 * @param key Property name (e.g., "Damage", "DamageType")
 * @param value Raw string value (e.g., "2d8", "Fire")
 * @return true if set succeeded
 */
bool stats_set_raw_attribute(StatsObjectPtr obj, const char *key, const char *value);

// ============================================================================
// Debugging
// ============================================================================

/**
 * Dump stat object details to log.
 *
 * @param obj Stat object pointer
 */
void stats_dump(StatsObjectPtr obj);

/**
 * Dump all available stat types to log.
 */
void stats_dump_types(void);

/**
 * Dump attributes for a specific ModifierList to log.
 * This enumerates all property names for a stat type (e.g., Weapon attributes).
 *
 * @param ml_index ModifierList index (0-8, use stats_dump_types to see available types)
 */
void stats_dump_modifierlist_attributes(int ml_index);

/**
 * Debug: Probe RPGStats.FixedStrings at various offsets to find correct offset.
 * Logs results showing which offset has a valid array with element[2303] = "1d8".
 */
void stats_probe_fixedstrings_offset(void);

#endif // STATS_MANAGER_H
