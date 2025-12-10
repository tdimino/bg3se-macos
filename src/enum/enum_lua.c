/*
 * BG3SE-macOS Enum Lua Metamethods
 */

#include "enum_registry.h"
#include <lauxlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// Helper Functions
// ============================================================================

static EnumUserdata* check_enum(lua_State *L, int idx) {
    return (EnumUserdata*)luaL_checkudata(L, idx, ENUM_METATABLE);
}

static EnumUserdata* test_enum(lua_State *L, int idx) {
    return (EnumUserdata*)luaL_testudata(L, idx, ENUM_METATABLE);
}

// ============================================================================
// Enum Metamethods
// ============================================================================

// __index: Access Label, Value, EnumName properties
static int enum_index(lua_State *L) {
    EnumUserdata *ud = check_enum(L, 1);
    const char *key = luaL_checkstring(L, 2);
    EnumTypeInfo *info = enum_registry_get(ud->type_index);

    if (!info) {
        lua_pushnil(L);
        return 1;
    }

    if (strcmp(key, "Label") == 0) {
        const char *label = enum_find_label(ud->type_index, ud->value);
        if (label) {
            lua_pushstring(L, label);
        } else {
            lua_pushfstring(L, "Unknown(%llu)", (unsigned long long)ud->value);
        }
        return 1;
    }

    if (strcmp(key, "Value") == 0) {
        lua_pushinteger(L, (lua_Integer)ud->value);
        return 1;
    }

    if (strcmp(key, "EnumName") == 0) {
        lua_pushstring(L, info->name);
        return 1;
    }

    // Unknown property
    return luaL_error(L, "Enum '%s' has no property '%s'", info->name, key);
}

// __eq: Compare enum == string/int/enum
static int enum_eq(lua_State *L) {
    EnumUserdata *ud = check_enum(L, 1);

    // Compare with string (label)
    if (lua_isstring(L, 2)) {
        const char *other_label = lua_tostring(L, 2);
        int64_t other_value = enum_find_value(ud->type_index, other_label);
        lua_pushboolean(L, other_value >= 0 && (uint64_t)other_value == ud->value);
        return 1;
    }

    // Compare with integer (value)
    if (lua_isinteger(L, 2)) {
        lua_Integer other_value = lua_tointeger(L, 2);
        lua_pushboolean(L, (uint64_t)other_value == ud->value);
        return 1;
    }

    // Compare with another enum
    EnumUserdata *other = test_enum(L, 2);
    if (other) {
        // Same type and value?
        lua_pushboolean(L, other->type_index == ud->type_index &&
                        other->value == ud->value);
        return 1;
    }

    // Not equal to anything else
    lua_pushboolean(L, 0);
    return 1;
}

// __tostring: Return label
static int enum_tostring(lua_State *L) {
    EnumUserdata *ud = check_enum(L, 1);
    const char *label = enum_find_label(ud->type_index, ud->value);

    if (label) {
        lua_pushstring(L, label);
    } else {
        EnumTypeInfo *info = enum_registry_get(ud->type_index);
        if (info) {
            lua_pushfstring(L, "%s(%llu)", info->name, (unsigned long long)ud->value);
        } else {
            lua_pushfstring(L, "Enum(%llu)", (unsigned long long)ud->value);
        }
    }
    return 1;
}

// __lt: Less-than comparison by value
static int enum_lt(lua_State *L) {
    EnumUserdata *ud = check_enum(L, 1);
    uint64_t other_val = 0;

    if (lua_isinteger(L, 2)) {
        other_val = (uint64_t)lua_tointeger(L, 2);
    } else {
        EnumUserdata *other = test_enum(L, 2);
        if (other && other->type_index == ud->type_index) {
            other_val = other->value;
        } else {
            lua_pushboolean(L, 0);
            return 1;
        }
    }

    lua_pushboolean(L, ud->value < other_val);
    return 1;
}

// __le: Less-than-or-equal comparison
static int enum_le(lua_State *L) {
    EnumUserdata *ud = check_enum(L, 1);
    uint64_t other_val = 0;

    if (lua_isinteger(L, 2)) {
        other_val = (uint64_t)lua_tointeger(L, 2);
    } else {
        EnumUserdata *other = test_enum(L, 2);
        if (other && other->type_index == ud->type_index) {
            other_val = other->value;
        } else {
            lua_pushboolean(L, 0);
            return 1;
        }
    }

    lua_pushboolean(L, ud->value <= other_val);
    return 1;
}

// ============================================================================
// Metatable Registration
// ============================================================================

static const luaL_Reg enum_methods[] = {
    {"__index", enum_index},
    {"__eq", enum_eq},
    {"__tostring", enum_tostring},
    {"__lt", enum_lt},
    {"__le", enum_le},
    {NULL, NULL}
};

void enum_register_enum_metatable(lua_State *L) {
    luaL_newmetatable(L, ENUM_METATABLE);
    luaL_setfuncs(L, enum_methods, 0);
    lua_pop(L, 1);
}
