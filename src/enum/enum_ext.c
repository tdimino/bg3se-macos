/*
 * BG3SE-macOS Ext.Enums Registration
 * Creates the Ext.Enums table with all registered enum types
 */

#include "enum_registry.h"
#include <lauxlib.h>
#include <string.h>

// Forward declarations from enum_lua.c and bitfield_lua.c
extern void enum_register_enum_metatable(lua_State *L);
extern void enum_register_bitfield_metatable(lua_State *L);

// ============================================================================
// Enum Type Metatable
// ============================================================================

// __index for enum type tables: Ext.Enums.DamageType.Fire or Ext.Enums.DamageType[5]
static int enum_type_index(lua_State *L) {
    // upvalue 1 = type_index
    int type_index = (int)lua_tointeger(L, lua_upvalueindex(1));
    EnumTypeInfo *info = enum_registry_get(type_index);

    if (!info) {
        lua_pushnil(L);
        return 1;
    }

    // String key: Look up by label
    if (lua_isstring(L, 2)) {
        const char *label = lua_tostring(L, 2);
        int64_t value = enum_find_value(type_index, label);

        if (value >= 0) {
            if (info->is_bitfield) {
                bitfield_push(L, (uint64_t)value, type_index);
            } else {
                enum_push(L, (uint64_t)value, type_index);
            }
            return 1;
        }
    }
    // Integer key: Look up by value
    else if (lua_isinteger(L, 2)) {
        lua_Integer value = lua_tointeger(L, 2);

        // Verify value is valid for this enum type
        const char *label = enum_find_label(type_index, (uint64_t)value);
        if (label || info->is_bitfield) {
            // For bitfields, any combination of valid flags is allowed
            if (info->is_bitfield) {
                bitfield_push(L, (uint64_t)value, type_index);
            } else {
                enum_push(L, (uint64_t)value, type_index);
            }
            return 1;
        }
    }

    lua_pushnil(L);
    return 1;
}

// __pairs for enum type tables: iterate over all values
static int enum_type_pairs_iter(lua_State *L) {
    // upvalue 1 = type_index
    int type_index = (int)lua_tointeger(L, lua_upvalueindex(1));
    int idx = (int)lua_tointeger(L, 2);  // Current iteration index
    EnumTypeInfo *info = enum_registry_get(type_index);

    if (!info || idx >= info->value_count) {
        lua_pushnil(L);
        return 1;
    }

    // Return: next_index, label, userdata
    lua_pushinteger(L, idx + 1);
    lua_pushstring(L, info->values[idx].label);

    if (info->is_bitfield) {
        bitfield_push(L, info->values[idx].value, type_index);
    } else {
        enum_push(L, info->values[idx].value, type_index);
    }

    return 3;
}

static int enum_type_pairs(lua_State *L) {
    // Get type_index from the table's metatable upvalue
    lua_getmetatable(L, 1);
    lua_getfield(L, -1, "__type_index");
    int type_index = (int)lua_tointeger(L, -1);
    lua_pop(L, 2);

    lua_pushinteger(L, type_index);  // upvalue for iterator
    lua_pushcclosure(L, enum_type_pairs_iter, 1);
    lua_pushvalue(L, 1);  // The table itself
    lua_pushinteger(L, 0);  // Starting index
    return 3;
}

// __len for enum type tables: return count of values
static int enum_type_len(lua_State *L) {
    lua_getmetatable(L, 1);
    lua_getfield(L, -1, "__type_index");
    int type_index = (int)lua_tointeger(L, -1);
    lua_pop(L, 2);

    EnumTypeInfo *info = enum_registry_get(type_index);
    lua_pushinteger(L, info ? info->value_count : 0);
    return 1;
}

// Create metatable for an enum type table
static void create_enum_type_metatable(lua_State *L, int type_index) {
    lua_newtable(L);  // metatable

    // __index closure with type_index upvalue
    lua_pushinteger(L, type_index);
    lua_pushcclosure(L, enum_type_index, 1);
    lua_setfield(L, -2, "__index");

    // __pairs
    lua_pushcfunction(L, enum_type_pairs);
    lua_setfield(L, -2, "__pairs");

    // __len
    lua_pushcfunction(L, enum_type_len);
    lua_setfield(L, -2, "__len");

    // Store type_index for __pairs and __len
    lua_pushinteger(L, type_index);
    lua_setfield(L, -2, "__type_index");
}

// ============================================================================
// Ext.Enums Table
// ============================================================================

// __index for Ext.Enums: Returns enum type tables
static int ext_enums_index(lua_State *L) {
    const char *name = luaL_checkstring(L, 2);
    EnumTypeInfo *info = enum_registry_find_by_name(name);

    if (!info) {
        lua_pushnil(L);
        return 1;
    }

    // Create a table for this enum type
    lua_newtable(L);

    // Set metatable with __index for value lookups
    create_enum_type_metatable(L, info->registry_index);
    lua_setmetatable(L, -2);

    return 1;
}

// __pairs for Ext.Enums: Iterate over all registered enum types
static int ext_enums_pairs_iter(lua_State *L) {
    int idx = (int)lua_tointeger(L, 2);  // Current index
    int count = enum_registry_get_count();

    while (idx < count) {
        EnumTypeInfo *info = enum_registry_get(idx);
        if (info) {
            lua_pushinteger(L, idx + 1);  // Next index
            lua_pushstring(L, info->name);  // Key

            // Create table for this enum type
            lua_newtable(L);
            create_enum_type_metatable(L, idx);
            lua_setmetatable(L, -2);

            return 3;
        }
        idx++;
    }

    lua_pushnil(L);
    return 1;
}

static int ext_enums_pairs(lua_State *L) {
    lua_pushcfunction(L, ext_enums_pairs_iter);
    lua_pushvalue(L, 1);  // The Ext.Enums table
    lua_pushinteger(L, 0);  // Starting index
    return 3;
}

// ============================================================================
// Public API
// ============================================================================

void enum_register_metatables(lua_State *L) {
    enum_register_enum_metatable(L);
    enum_register_bitfield_metatable(L);
}

void enum_register_ext_enums(lua_State *L) {
    // Stack: Ext table at top

    // Create Ext.Enums table
    lua_newtable(L);

    // Create metatable for Ext.Enums
    lua_newtable(L);

    lua_pushcfunction(L, ext_enums_index);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, ext_enums_pairs);
    lua_setfield(L, -2, "__pairs");

    lua_setmetatable(L, -2);

    // Set Ext.Enums
    lua_setfield(L, -2, "Enums");
}
