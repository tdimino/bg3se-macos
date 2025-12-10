/*
 * BG3SE-macOS Enum Registry
 * Type definitions and public API for enum/bitfield userdata
 */

#ifndef BG3SE_ENUM_REGISTRY_H
#define BG3SE_ENUM_REGISTRY_H

#include <stdint.h>
#include <stdbool.h>
#include <lua.h>

// Limits
#define ENUM_MAX_VALUES 512
#define ENUM_MAX_TYPES 256

// Metatable names
#define ENUM_METATABLE "BG3Enum"
#define BITFIELD_METATABLE "BG3Bitfield"

// Enum value entry (label + value pair)
typedef struct {
    const char *label;   // String label (e.g., "Fire")
    uint64_t value;      // Numeric value
} EnumValueEntry;

// Enum type definition
typedef struct {
    const char *name;                    // Internal name (e.g., "DamageType")
    EnumValueEntry values[ENUM_MAX_VALUES];
    int value_count;
    int registry_index;                  // Index in global registry
    bool is_bitfield;                    // False for enum, true for bitfield
    uint64_t allowed_flags;              // For bitfields: mask of all valid flags
} EnumTypeInfo;

// Lua userdata for enum values (16 bytes)
typedef struct {
    uint64_t value;          // The enum/bitfield numeric value
    int16_t type_index;      // Index into EnumRegistry
    int16_t _padding;        // Alignment padding
    uint32_t _reserved;      // Reserved for future use
} EnumUserdata;

// Same structure for bitfields
typedef EnumUserdata BitfieldUserdata;

// ============================================================================
// Registry API
// ============================================================================

// Initialize the enum registry (call once at startup)
void enum_registry_init(void);

// Add a new enum type, returns type index or -1 on failure
int enum_registry_add_type(const char *name, bool is_bitfield);

// Add a value to an enum type, returns true on success
bool enum_registry_add_value(int type_index, const char *label, uint64_t value);

// Get enum type info by index, returns NULL if invalid
EnumTypeInfo* enum_registry_get(int type_index);

// Find enum type by name, returns NULL if not found
EnumTypeInfo* enum_registry_find_by_name(const char *name);

// Get number of registered types
int enum_registry_get_count(void);

// Look up label for a value, returns NULL if not found
const char* enum_find_label(int type_index, uint64_t value);

// Look up value for a label, returns -1 if not found
int64_t enum_find_value(int type_index, const char *label);

// ============================================================================
// Lua Userdata API
// ============================================================================

// Push an enum userdata onto the Lua stack
void enum_push(lua_State *L, uint64_t value, int type_index);

// Push a bitfield userdata onto the Lua stack
void bitfield_push(lua_State *L, uint64_t value, int type_index);

// Register enum metatables (call once after lua_State creation)
void enum_register_metatables(lua_State *L);

// Register Ext.Enums table (call after metatables are registered)
void enum_register_ext_enums(lua_State *L);

// ============================================================================
// Enum Definitions
// ============================================================================

// Register all hardcoded enum definitions
void enum_register_definitions(void);

#endif // BG3SE_ENUM_REGISTRY_H
