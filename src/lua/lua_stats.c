/**
 * lua_stats.c - Lua bindings for Ext.Stats API
 *
 * Implements the Lua interface for accessing and modifying game statistics.
 */

#include "lua_stats.h"
#include "../stats/stats_manager.h"
#include "../strings/fixed_string.h"
#include "../lifetime/lifetime.h"
#include "logging.h"

#include "../../lib/lua/src/lua.h"
#include "../../lib/lua/src/lauxlib.h"
#include "../../lib/lua/src/lualib.h"

#include <string.h>
#include <stdlib.h>

// Forward declarations
static int lua_stats_object_get_property(lua_State *L);
static int lua_stats_object_set_property(lua_State *L);
static int lua_stats_object_dump(lua_State *L);
static int lua_stats_object_get_raw_property(lua_State *L);

// ============================================================================
// StatsObject Userdata
// ============================================================================

#define STATS_OBJECT_METATABLE "bg3se.StatsObject"

typedef struct {
    StatsObjectPtr obj;  // Opaque handle from stats_manager
    LifetimeHandle lifetime;
} LuaStatsObject;

// Push a StatsObject userdata onto the stack
static void push_stats_object(lua_State *L, StatsObjectPtr obj) {
    if (!obj) {
        lua_pushnil(L);
        return;
    }

    LuaStatsObject *ud = (LuaStatsObject*)lua_newuserdata(L, sizeof(LuaStatsObject));
    ud->obj = obj;
    ud->lifetime = lifetime_lua_get_current(L);

    luaL_getmetatable(L, STATS_OBJECT_METATABLE);
    lua_setmetatable(L, -2);
}

// Get StatsObject from userdata at stack index
static LuaStatsObject* check_stats_object(lua_State *L, int idx) {
    return (LuaStatsObject*)luaL_checkudata(L, idx, STATS_OBJECT_METATABLE);
}

// ============================================================================
// StatsObject Metatable Methods
// ============================================================================

// StatsObject.__index - Property access
static int lua_stats_object_index(lua_State *L) {
    LuaStatsObject *ud = check_stats_object(L, 1);
    if (!lifetime_lua_is_valid(L, ud->lifetime)) {
        return lifetime_lua_expired_error(L, "StatsObject");
    }
    const char *key = luaL_checkstring(L, 2);

    if (!ud->obj) {
        lua_pushnil(L);
        return 1;
    }

    // Built-in properties
    if (strcmp(key, "Name") == 0) {
        const char *name = stats_get_name(ud->obj);
        if (name) {
            lua_pushstring(L, name);
        } else {
            lua_pushnil(L);
        }
        return 1;
    }

    if (strcmp(key, "Type") == 0) {
        const char *type = stats_get_type(ud->obj);
        if (type) {
            lua_pushstring(L, type);
        } else {
            lua_pushnil(L);
        }
        return 1;
    }

    if (strcmp(key, "Level") == 0) {
        int level = stats_get_level(ud->obj);
        lua_pushinteger(L, level);
        return 1;
    }

    if (strcmp(key, "Using") == 0) {
        const char *using_stat = stats_get_using(ud->obj);
        if (using_stat) {
            lua_pushstring(L, using_stat);
        } else {
            lua_pushnil(L);
        }
        return 1;
    }

    if (strcmp(key, "PropertyCount") == 0) {
        int count = stats_get_property_count(ud->obj);
        lua_pushinteger(L, count);
        return 1;
    }

    // Methods
    if (strcmp(key, "GetRawProperty") == 0) {
        // Method: stat:GetRawProperty(index) -> int32
        lua_pushcfunction(L, lua_stats_object_get_raw_property);
        return 1;
    }

    if (strcmp(key, "GetProperty") == 0) {
        // Push method closure (handled below)
        lua_pushcfunction(L, lua_stats_object_get_property);
        return 1;
    }

    if (strcmp(key, "SetProperty") == 0) {
        lua_pushcfunction(L, lua_stats_object_set_property);
        return 1;
    }

    if (strcmp(key, "Dump") == 0) {
        lua_pushcfunction(L, lua_stats_object_dump);
        return 1;
    }

    // Try to get as a stat property
    const char *str_val = stats_get_string(ud->obj, key);
    if (str_val) {
        lua_pushstring(L, str_val);
        return 1;
    }

    // Property not found
    lua_pushnil(L);
    return 1;
}

// StatsObject.__newindex - Property modification
static int lua_stats_object_newindex(lua_State *L) {
    LuaStatsObject *ud = check_stats_object(L, 1);
    if (!lifetime_lua_is_valid(L, ud->lifetime)) {
        return lifetime_lua_expired_error(L, "StatsObject");
    }
    const char *key = luaL_checkstring(L, 2);

    if (!ud->obj) {
        return luaL_error(L, "Invalid StatsObject");
    }

    // Built-in properties are read-only
    if (strcmp(key, "Name") == 0 || strcmp(key, "Type") == 0 ||
        strcmp(key, "Level") == 0 || strcmp(key, "Using") == 0) {
        return luaL_error(L, "Property '%s' is read-only", key);
    }

    // Try to set as a stat property
    int value_type = lua_type(L, 3);

    if (value_type == LUA_TSTRING) {
        const char *value = lua_tostring(L, 3);
        bool success = stats_set_string(ud->obj, key, value);
        if (!success) {
            LOG_STATS_DEBUG("Failed to set string property '%s'", key);
        }
    } else if (value_type == LUA_TNUMBER) {
        if (lua_isinteger(L, 3)) {
            int64_t value = lua_tointeger(L, 3);
            bool success = stats_set_int(ud->obj, key, value);
            if (!success) {
                LOG_STATS_DEBUG("Failed to set integer property '%s'", key);
            }
        } else {
            float value = (float)lua_tonumber(L, 3);
            bool success = stats_set_float(ud->obj, key, value);
            if (!success) {
                LOG_STATS_DEBUG("Failed to set float property '%s'", key);
            }
        }
    } else {
        return luaL_error(L, "Unsupported value type for property '%s'", key);
    }

    return 0;
}

// StatsObject.__tostring
static int lua_stats_object_tostring(lua_State *L) {
    LuaStatsObject *ud = check_stats_object(L, 1);
    // tostring works even on expired objects (for debugging)
    bool valid = lifetime_lua_is_valid(L, ud->lifetime);

    if (!ud->obj) {
        lua_pushstring(L, "StatsObject(nil)");
        return 1;
    }

    const char *name = stats_get_name(ud->obj);
    const char *type = stats_get_type(ud->obj);
    const char *expired = valid ? "" : " [EXPIRED]";

    if (name && type) {
        lua_pushfstring(L, "StatsObject(%s [%s])%s", name, type, expired);
    } else if (name) {
        lua_pushfstring(L, "StatsObject(%s)%s", name, expired);
    } else {
        lua_pushfstring(L, "StatsObject(%p)%s", ud->obj, expired);
    }

    return 1;
}

// StatsObject:GetRawProperty(index) -> int32
// Returns the raw property index value at the given position
static int lua_stats_object_get_raw_property(lua_State *L) {
    LuaStatsObject *ud = check_stats_object(L, 1);
    if (!lifetime_lua_is_valid(L, ud->lifetime)) {
        return lifetime_lua_expired_error(L, "StatsObject");
    }
    int index = (int)luaL_checkinteger(L, 2);

    if (!ud->obj) {
        lua_pushnil(L);
        return 1;
    }

    int32_t value = stats_get_property_raw(ud->obj, index);
    lua_pushinteger(L, value);
    return 1;
}

// StatsObject:GetProperty(name) -> value
static int lua_stats_object_get_property(lua_State *L) {
    LuaStatsObject *ud = check_stats_object(L, 1);
    if (!lifetime_lua_is_valid(L, ud->lifetime)) {
        return lifetime_lua_expired_error(L, "StatsObject");
    }
    const char *prop = luaL_checkstring(L, 2);

    if (!ud->obj) {
        lua_pushnil(L);
        return 1;
    }

    // Try string first
    const char *str_val = stats_get_string(ud->obj, prop);
    if (str_val) {
        lua_pushstring(L, str_val);
        return 1;
    }

    // Try integer
    int64_t int_val;
    if (stats_get_int(ud->obj, prop, &int_val)) {
        lua_pushinteger(L, int_val);
        return 1;
    }

    // Try float
    float float_val;
    if (stats_get_float(ud->obj, prop, &float_val)) {
        lua_pushnumber(L, float_val);
        return 1;
    }

    lua_pushnil(L);
    return 1;
}

// StatsObject:SetProperty(name, value) -> bool
static int lua_stats_object_set_property(lua_State *L) {
    LuaStatsObject *ud = check_stats_object(L, 1);
    if (!lifetime_lua_is_valid(L, ud->lifetime)) {
        return lifetime_lua_expired_error(L, "StatsObject");
    }
    const char *prop = luaL_checkstring(L, 2);

    if (!ud->obj) {
        lua_pushboolean(L, 0);
        return 1;
    }

    int value_type = lua_type(L, 3);
    bool success = false;

    if (value_type == LUA_TSTRING) {
        const char *value = lua_tostring(L, 3);
        success = stats_set_string(ud->obj, prop, value);
    } else if (value_type == LUA_TNUMBER) {
        if (lua_isinteger(L, 3)) {
            int64_t value = lua_tointeger(L, 3);
            success = stats_set_int(ud->obj, prop, value);
        } else {
            float value = (float)lua_tonumber(L, 3);
            success = stats_set_float(ud->obj, prop, value);
        }
    }

    lua_pushboolean(L, success);
    return 1;
}

// StatsObject:Dump()
static int lua_stats_object_dump(lua_State *L) {
    LuaStatsObject *ud = check_stats_object(L, 1);
    if (!lifetime_lua_is_valid(L, ud->lifetime)) {
        return lifetime_lua_expired_error(L, "StatsObject");
    }
    if (ud->obj) {
        stats_dump(ud->obj);
    }
    return 0;
}

// ============================================================================
// Ext.Stats Functions
// ============================================================================

// Ext.Stats.Get(name) -> StatsObject or nil
static int lua_stats_get(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);

    if (!stats_manager_ready()) {
        LOG_STATS_DEBUG("Stats system not ready");
        lua_pushnil(L);
        return 1;
    }

    StatsObjectPtr obj = stats_get(name);
    push_stats_object(L, obj);
    return 1;
}

// Ext.Stats.GetAll(type?) -> array of names
static int lua_stats_getall(lua_State *L) {
    const char *type = NULL;
    if (lua_gettop(L) >= 1 && !lua_isnil(L, 1)) {
        type = luaL_checkstring(L, 1);
    }

    if (!stats_manager_ready()) {
        LOG_STATS_DEBUG("Stats system not ready");
        lua_newtable(L);  // Return empty array
        return 1;
    }

    int count = stats_get_count(type);
    if (count < 0) {
        lua_newtable(L);
        return 1;
    }

    lua_createtable(L, count, 0);

    for (int i = 0; i < count; i++) {
        const char *name = stats_get_name_at(type, i);
        if (name) {
            lua_pushstring(L, name);
            lua_rawseti(L, -2, i + 1);  // Lua arrays are 1-indexed
        }
    }

    return 1;
}

// Ext.Stats.Sync(name) -> bool
static int lua_stats_sync(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);

    bool success = stats_sync(name);
    lua_pushboolean(L, success);
    return 1;
}

// Ext.Stats.Create(name, type, template?) -> StatsObject or nil
static int lua_stats_create(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);
    const char *type = luaL_checkstring(L, 2);
    const char *template_name = NULL;

    if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
        template_name = luaL_checkstring(L, 3);
    }

    if (!stats_manager_ready()) {
        LOG_STATS_DEBUG("Stats system not ready");
        lua_pushnil(L);
        return 1;
    }

    StatsObjectPtr obj = stats_create(name, type, template_name);
    push_stats_object(L, obj);
    return 1;
}

// Ext.Stats.IsReady() -> bool
static int lua_stats_isready(lua_State *L) {
    lua_pushboolean(L, stats_manager_ready());
    return 1;
}

// Ext.Stats.DumpTypes()
static int lua_stats_dumptypes(lua_State *L) {
    (void)L;
    stats_dump_types();
    return 0;
}

// Ext.Stats.GetRaw() -> pointer string (for debugging)
static int lua_stats_getraw(lua_State *L) {
    void *raw = stats_manager_get_raw();
    if (raw) {
        lua_pushfstring(L, "%p", raw);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

// Ext.Stats.GetRawPtr() -> pointer as integer (for Ext.Debug probing)
static int lua_stats_getrawptr(lua_State *L) {
    void *raw = stats_manager_get_raw();
    if (raw) {
        lua_pushinteger(L, (lua_Integer)(uintptr_t)raw);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

// Ext.Stats.GetFixedStringByIndex(index) -> string
// Direct access to the FixedStrings pool at RPGStats+0x348
static int lua_stats_get_fixedstring_by_index(lua_State *L) {
    int index = (int)luaL_checkinteger(L, 1);

    if (index < 0) {
        lua_pushnil(L);
        return 1;
    }

    const char *str = fixed_string_resolve((uint32_t)index);
    if (str) {
        lua_pushstring(L, str);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

// Ext.Stats.GetAllStats(type?) -> array of names
// Alias for GetAll, matches Windows BG3SE API naming
static int lua_stats_getallstats(lua_State *L) {
    return lua_stats_getall(L);
}

// Ext.Stats.GetFixedStringStatus() -> table with status info
static int lua_stats_get_fixedstring_status(lua_State *L) {
    lua_newtable(L);

    lua_pushboolean(L, fixed_string_is_ready());
    lua_setfield(L, -2, "ready");

    uint32_t resolved = 0, failed = 0;
    fixed_string_get_stats(&resolved, &failed);

    lua_pushinteger(L, resolved);
    lua_setfield(L, -2, "resolved");

    lua_pushinteger(L, failed);
    lua_setfield(L, -2, "failed");

    return 1;
}

// Ext.Stats.DumpAttributes(ml_index) - Debug: dump ModifierList attributes
static int lua_stats_dumpattributes(lua_State *L) {
    int ml_index = (int)luaL_checkinteger(L, 1);
    stats_dump_modifierlist_attributes(ml_index);
    return 0;
}

// Ext.Stats.ProbeFixedStrings() - Debug: probe for FixedStrings array offset
static int lua_stats_probe_fixedstrings(lua_State *L) {
    (void)L;
    stats_probe_fixedstrings_offset();
    return 0;
}

// Ext.Stats.GetObjectRaw(name) -> table with raw object data
// Returns IndexedProperties array and other raw data for debugging
static int lua_stats_getobjectraw(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);

    if (!stats_manager_ready()) {
        lua_pushnil(L);
        return 1;
    }

    StatsObjectPtr obj = stats_get(name);
    if (!obj) {
        lua_pushnil(L);
        return 1;
    }

    lua_newtable(L);

    // Name
    const char *obj_name = stats_get_name(obj);
    if (obj_name) {
        lua_pushstring(L, obj_name);
        lua_setfield(L, -2, "Name");
    }

    // Type
    const char *obj_type = stats_get_type(obj);
    if (obj_type) {
        lua_pushstring(L, obj_type);
        lua_setfield(L, -2, "Type");
    }

    // Level
    lua_pushinteger(L, stats_get_level(obj));
    lua_setfield(L, -2, "Level");

    // Using (parent)
    const char *using_stat = stats_get_using(obj);
    if (using_stat) {
        lua_pushstring(L, using_stat);
        lua_setfield(L, -2, "Using");
    }

    // Raw pointer address
    lua_pushinteger(L, (lua_Integer)(uintptr_t)obj);
    lua_setfield(L, -2, "Address");

    // Property count
    int prop_count = stats_get_property_count(obj);
    lua_pushinteger(L, prop_count);
    lua_setfield(L, -2, "PropertyCount");

    // IndexedProperties array (raw values)
    lua_newtable(L);
    for (int i = 0; i < prop_count && i < 100; i++) {
        int32_t raw_val = stats_get_property_raw(obj, i);
        lua_pushinteger(L, i);
        lua_pushinteger(L, raw_val);
        lua_settable(L, -3);
    }
    lua_setfield(L, -2, "IndexedProperties");

    return 1;
}

// Ext.Stats.DumpModifierList(typeName) -> table with attribute info
// Returns table of attributes for a modifier list type (e.g., "Weapon")
// Note: Attribute names are loaded from game data at runtime, not compiled into binary
static int lua_stats_dumpmodifierlist(lua_State *L) {
    const char *type_name = luaL_checkstring(L, 1);

    if (!stats_manager_ready()) {
        lua_pushnil(L);
        return 1;
    }

    // Map type name to ModifierList index
    // Based on verified offsets: Armor=0, Character=1, Weapon=8, etc.
    int ml_index = -1;
    if (strcmp(type_name, "Armor") == 0) ml_index = 0;
    else if (strcmp(type_name, "Character") == 0) ml_index = 1;
    else if (strcmp(type_name, "Object") == 0) ml_index = 2;
    else if (strcmp(type_name, "EquipmentSet") == 0) ml_index = 3;
    else if (strcmp(type_name, "PassiveData") == 0) ml_index = 4;
    else if (strcmp(type_name, "SpellData") == 0) ml_index = 5;
    else if (strcmp(type_name, "StatusData") == 0) ml_index = 6;
    else if (strcmp(type_name, "CriticalHitTypeData") == 0) ml_index = 7;
    else if (strcmp(type_name, "Weapon") == 0) ml_index = 8;

    if (ml_index < 0) {
        LOG_STATS_DEBUG("Unknown modifier list type: %s", type_name);
        lua_pushnil(L);
        return 1;
    }

    // Dump to log (the actual data is returned via log for now)
    stats_dump_modifierlist_attributes(ml_index);

    // Return info table
    lua_newtable(L);
    lua_pushstring(L, type_name);
    lua_setfield(L, -2, "Type");
    lua_pushinteger(L, ml_index);
    lua_setfield(L, -2, "Index");
    lua_pushstring(L, "See log for attribute details (names loaded from game data at runtime)");
    lua_setfield(L, -2, "Note");

    return 1;
}

// ============================================================================
// Registration
// ============================================================================

static const luaL_Reg stats_object_methods[] = {
    {"__index", lua_stats_object_index},
    {"__newindex", lua_stats_object_newindex},
    {"__tostring", lua_stats_object_tostring},
    {NULL, NULL}
};

static const luaL_Reg stats_functions[] = {
    {"Get", lua_stats_get},
    {"GetAll", lua_stats_getall},
    {"GetAllStats", lua_stats_getallstats},  // Alias for compatibility
    {"Sync", lua_stats_sync},
    {"Create", lua_stats_create},
    {"IsReady", lua_stats_isready},
    {"DumpTypes", lua_stats_dumptypes},
    {"DumpAttributes", lua_stats_dumpattributes},  // Debug: dump ModifierList attributes
    {"DumpModifierList", lua_stats_dumpmodifierlist},  // Debug: dump modifier list by type name
    {"GetRaw", lua_stats_getraw},
    {"GetRawPtr", lua_stats_getrawptr},  // Debug: returns integer for Ext.Debug probing
    {"GetObjectRaw", lua_stats_getobjectraw},  // Debug: raw object data with IndexedProperties
    {"GetFixedStringByIndex", lua_stats_get_fixedstring_by_index},  // Debug: direct FixedStrings[index] access
    {"GetFixedStringStatus", lua_stats_get_fixedstring_status},
    {"ProbeFixedStrings", lua_stats_probe_fixedstrings},  // Debug: probe for FixedStrings offset
    {NULL, NULL}
};

void lua_stats_register(lua_State *L, int ext_table_index) {
    LOG_STATS_DEBUG("Registering Ext.Stats API");

    // Convert negative index to absolute since we'll be pushing onto stack
    if (ext_table_index < 0) {
        ext_table_index = lua_gettop(L) + ext_table_index + 1;
    }

    // Create StatsObject metatable
    luaL_newmetatable(L, STATS_OBJECT_METATABLE);
    luaL_setfuncs(L, stats_object_methods, 0);
    lua_pop(L, 1);

    // Create Ext.Stats table
    lua_newtable(L);
    luaL_setfuncs(L, stats_functions, 0);

    // Set as Ext.Stats
    lua_setfield(L, ext_table_index, "Stats");

    LOG_STATS_DEBUG("Ext.Stats API registered");
}
