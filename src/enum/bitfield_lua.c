/*
 * BG3SE-macOS Bitfield Lua Metamethods
 */

#include "enum_registry.h"
#include <lauxlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// Helper Functions
// ============================================================================

static BitfieldUserdata* check_bitfield(lua_State *L, int idx) {
    return (BitfieldUserdata*)luaL_checkudata(L, idx, BITFIELD_METATABLE);
}

static BitfieldUserdata* test_bitfield(lua_State *L, int idx) {
    return (BitfieldUserdata*)luaL_testudata(L, idx, BITFIELD_METATABLE);
}

// Count number of set bits (popcount)
static int popcount64(uint64_t value) {
    int count = 0;
    while (value) {
        count += value & 1;
        value >>= 1;
    }
    return count;
}

// Get flag value from string or integer argument
static int64_t get_flag_value(lua_State *L, int idx, int type_index) {
    if (lua_isstring(L, idx)) {
        const char *label = lua_tostring(L, idx);
        return enum_find_value(type_index, label);
    } else if (lua_isinteger(L, idx)) {
        return lua_tointeger(L, idx);
    } else {
        BitfieldUserdata *bf = test_bitfield(L, idx);
        if (bf && bf->type_index == type_index) {
            return (int64_t)bf->value;
        }
    }
    return -1;
}

// ============================================================================
// Bitfield Metamethods
// ============================================================================

// __index: Access __Labels, __Value, __EnumName, or query individual flags
static int bitfield_index(lua_State *L) {
    BitfieldUserdata *ud = check_bitfield(L, 1);
    const char *key = luaL_checkstring(L, 2);
    EnumTypeInfo *info = enum_registry_get(ud->type_index);

    if (!info) {
        lua_pushnil(L);
        return 1;
    }

    // Special properties (prefixed with __)
    if (strcmp(key, "__Labels") == 0) {
        // Return array of active flag labels
        lua_newtable(L);
        int idx = 1;
        for (int i = 0; i < info->value_count; i++) {
            uint64_t flag_value = info->values[i].value;
            // Check if this flag is set (and it's a power of 2, i.e., single flag)
            if (flag_value != 0 && (ud->value & flag_value) == flag_value) {
                lua_pushstring(L, info->values[i].label);
                lua_rawseti(L, -2, idx++);
            }
        }
        return 1;
    }

    if (strcmp(key, "__Value") == 0) {
        lua_pushinteger(L, (lua_Integer)ud->value);
        return 1;
    }

    if (strcmp(key, "__EnumName") == 0) {
        lua_pushstring(L, info->name);
        return 1;
    }

    // Check if key is a flag name and return whether it's set
    int64_t flag_value = enum_find_value(ud->type_index, key);
    if (flag_value >= 0) {
        lua_pushboolean(L, (ud->value & (uint64_t)flag_value) != 0);
        return 1;
    }

    // Unknown property
    return luaL_error(L, "Bitfield '%s' has no flag or property '%s'", info->name, key);
}

// __eq: Compare bitfield values
static int bitfield_eq(lua_State *L) {
    BitfieldUserdata *ud = check_bitfield(L, 1);

    // Compare with integer
    if (lua_isinteger(L, 2)) {
        lua_pushboolean(L, ud->value == (uint64_t)lua_tointeger(L, 2));
        return 1;
    }

    // Compare with another bitfield
    BitfieldUserdata *other = test_bitfield(L, 2);
    if (other) {
        lua_pushboolean(L, ud->type_index == other->type_index &&
                        ud->value == other->value);
        return 1;
    }

    lua_pushboolean(L, 0);
    return 1;
}

// __len: Return count of set flags (popcount)
static int bitfield_len(lua_State *L) {
    BitfieldUserdata *ud = check_bitfield(L, 1);
    lua_pushinteger(L, popcount64(ud->value));
    return 1;
}

// __band: Bitwise AND
static int bitfield_band(lua_State *L) {
    BitfieldUserdata *ud = check_bitfield(L, 1);
    int64_t other_value = get_flag_value(L, 2, ud->type_index);

    if (other_value < 0) {
        return luaL_error(L, "Invalid operand for bitfield AND operation");
    }

    bitfield_push(L, ud->value & (uint64_t)other_value, ud->type_index);
    return 1;
}

// __bor: Bitwise OR
static int bitfield_bor(lua_State *L) {
    BitfieldUserdata *ud = check_bitfield(L, 1);
    int64_t other_value = get_flag_value(L, 2, ud->type_index);

    if (other_value < 0) {
        return luaL_error(L, "Invalid operand for bitfield OR operation");
    }

    bitfield_push(L, ud->value | (uint64_t)other_value, ud->type_index);
    return 1;
}

// __bxor: Bitwise XOR
static int bitfield_bxor(lua_State *L) {
    BitfieldUserdata *ud = check_bitfield(L, 1);
    int64_t other_value = get_flag_value(L, 2, ud->type_index);

    if (other_value < 0) {
        return luaL_error(L, "Invalid operand for bitfield XOR operation");
    }

    bitfield_push(L, ud->value ^ (uint64_t)other_value, ud->type_index);
    return 1;
}

// __bnot: Bitwise NOT (masked by allowed_flags)
static int bitfield_bnot(lua_State *L) {
    BitfieldUserdata *ud = check_bitfield(L, 1);
    EnumTypeInfo *info = enum_registry_get(ud->type_index);

    uint64_t mask = info ? info->allowed_flags : ~0ULL;
    bitfield_push(L, (~ud->value) & mask, ud->type_index);
    return 1;
}

// __tostring: Return comma-separated list of active flag labels
static int bitfield_tostring(lua_State *L) {
    BitfieldUserdata *ud = check_bitfield(L, 1);
    EnumTypeInfo *info = enum_registry_get(ud->type_index);

    if (!info) {
        lua_pushfstring(L, "Bitfield(%llu)", (unsigned long long)ud->value);
        return 1;
    }

    // Build comma-separated list of active flags
    luaL_Buffer b;
    luaL_buffinit(L, &b);

    int first = 1;
    for (int i = 0; i < info->value_count; i++) {
        uint64_t flag_value = info->values[i].value;
        if (flag_value != 0 && (ud->value & flag_value) == flag_value) {
            if (!first) {
                luaL_addstring(&b, ", ");
            }
            luaL_addstring(&b, info->values[i].label);
            first = 0;
        }
    }

    if (first) {
        // No flags set
        luaL_addstring(&b, "(none)");
    }

    luaL_pushresult(&b);
    return 1;
}

// __pairs: Iterate over active flag labels
static int bitfield_pairs_iter(lua_State *L) {
    BitfieldUserdata *ud = check_bitfield(L, 1);
    int idx = (int)lua_tointeger(L, 2);  // Current index
    EnumTypeInfo *info = enum_registry_get(ud->type_index);

    if (!info) {
        lua_pushnil(L);
        return 1;
    }

    // Find next set flag
    while (idx < info->value_count) {
        uint64_t flag_value = info->values[idx].value;
        if (flag_value != 0 && (ud->value & flag_value) == flag_value) {
            lua_pushinteger(L, idx + 1);  // Next index
            lua_pushstring(L, info->values[idx].label);  // Key
            lua_pushboolean(L, 1);  // Value (always true for active flags)
            return 3;
        }
        idx++;
    }

    lua_pushnil(L);
    return 1;
}

static int bitfield_pairs(lua_State *L) {
    lua_pushcfunction(L, bitfield_pairs_iter);
    lua_pushvalue(L, 1);  // The bitfield userdata
    lua_pushinteger(L, 0);  // Starting index
    return 3;
}

// ============================================================================
// Metatable Registration
// ============================================================================

static const luaL_Reg bitfield_methods[] = {
    {"__index", bitfield_index},
    {"__eq", bitfield_eq},
    {"__len", bitfield_len},
    {"__band", bitfield_band},
    {"__bor", bitfield_bor},
    {"__bxor", bitfield_bxor},
    {"__bnot", bitfield_bnot},
    {"__tostring", bitfield_tostring},
    {"__pairs", bitfield_pairs},
    {NULL, NULL}
};

void enum_register_bitfield_metatable(lua_State *L) {
    luaL_newmetatable(L, BITFIELD_METATABLE);
    luaL_setfuncs(L, bitfield_methods, 0);
    lua_pop(L, 1);
}
