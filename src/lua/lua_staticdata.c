/**
 * lua_staticdata.c - Lua bindings for Ext.StaticData API
 *
 * Provides Lua access to immutable game data like Feats, Races, Backgrounds, etc.
 *
 * API:
 *   Ext.StaticData.GetAll(type) - Get all entries of a type as array of tables
 *   Ext.StaticData.Get(type, guid) - Get single entry by GUID string
 *   Ext.StaticData.GetCount(type) - Get count of entries for a type
 */

#include "lua_staticdata.h"
#include "../staticdata/staticdata_manager.h"
#include "../core/logging.h"
#include <lua.h>
#include <lauxlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Push a static data entry as a Lua table.
 */
static void push_staticdata_entry(lua_State *L, StaticDataType type, StaticDataPtr entry) {
    if (!entry) {
        lua_pushnil(L);
        return;
    }

    lua_newtable(L);

    // Add ResourceUUID (GUID)
    char guid_str[40];
    if (staticdata_get_guid_string(type, entry, guid_str, sizeof(guid_str))) {
        lua_pushstring(L, guid_str);
        lua_setfield(L, -2, "ResourceUUID");
    }

    // Add Name if available
    const char* name = staticdata_get_name(type, entry);
    if (name) {
        lua_pushstring(L, name);
        lua_setfield(L, -2, "Name");
    }

    // Add DisplayName if available
    const char* display_name = staticdata_get_display_name(type, entry);
    if (display_name) {
        lua_pushstring(L, display_name);
        lua_setfield(L, -2, "DisplayName");
    }

    // Add Type
    lua_pushstring(L, staticdata_type_name(type));
    lua_setfield(L, -2, "Type");

    // Add raw pointer for debugging
    lua_pushlightuserdata(L, entry);
    lua_setfield(L, -2, "_ptr");
}

// ============================================================================
// Ext.StaticData.GetAll(type)
// ============================================================================

/**
 * Get all entries of a static data type.
 *
 * @param type Type name string (e.g., "Feat", "Race")
 * @return Array table of entry tables, or nil on error
 */
static int lua_staticdata_getall(lua_State *L) {
    const char* type_name = luaL_checkstring(L, 1);

    int type = staticdata_type_from_name(type_name);
    if (type < 0) {
        return luaL_error(L, "Unknown static data type: %s", type_name);
    }

    if (!staticdata_has_manager((StaticDataType)type)) {
        // Manager not yet captured - return empty table
        // The hook will capture it when game code accesses it
        lua_newtable(L);
        return 1;
    }

    int count = staticdata_get_count((StaticDataType)type);
    if (count < 0) {
        lua_newtable(L);
        return 1;
    }

    lua_createtable(L, count, 0);

    for (int i = 0; i < count; i++) {
        StaticDataPtr entry = staticdata_get_by_index((StaticDataType)type, i);
        if (entry) {
            push_staticdata_entry(L, (StaticDataType)type, entry);
            lua_rawseti(L, -2, i + 1);  // Lua arrays are 1-indexed
        }
    }

    return 1;
}

// ============================================================================
// Ext.StaticData.Get(type, guid)
// ============================================================================

/**
 * Get a single static data entry by GUID.
 *
 * @param type Type name string
 * @param guid GUID string (e.g., "e7ab823e-32b2-49f8-b7b3-7f9c2d4c1f5e")
 * @return Entry table, or nil if not found
 */
static int lua_staticdata_get(lua_State *L) {
    const char* type_name = luaL_checkstring(L, 1);
    const char* guid_str = luaL_checkstring(L, 2);

    int type = staticdata_type_from_name(type_name);
    if (type < 0) {
        return luaL_error(L, "Unknown static data type: %s", type_name);
    }

    if (!staticdata_has_manager((StaticDataType)type)) {
        lua_pushnil(L);
        return 1;
    }

    StaticDataPtr entry = staticdata_get_by_guid_string((StaticDataType)type, guid_str);
    if (!entry) {
        lua_pushnil(L);
        return 1;
    }

    push_staticdata_entry(L, (StaticDataType)type, entry);
    return 1;
}

// ============================================================================
// Ext.StaticData.GetCount(type)
// ============================================================================

/**
 * Get the count of entries for a static data type.
 *
 * @param type Type name string
 * @return Count integer, or -1 if type not available
 */
static int lua_staticdata_getcount(lua_State *L) {
    const char* type_name = luaL_checkstring(L, 1);

    int type = staticdata_type_from_name(type_name);
    if (type < 0) {
        return luaL_error(L, "Unknown static data type: %s", type_name);
    }

    int count = staticdata_get_count((StaticDataType)type);
    lua_pushinteger(L, count);
    return 1;
}

// ============================================================================
// Ext.StaticData.GetTypes()
// ============================================================================

/**
 * Get list of supported static data type names.
 *
 * @return Array table of type name strings
 */
static int lua_staticdata_gettypes(lua_State *L) {
    lua_createtable(L, STATICDATA_COUNT, 0);

    for (int i = 0; i < STATICDATA_COUNT; i++) {
        lua_pushstring(L, staticdata_type_name((StaticDataType)i));
        lua_rawseti(L, -2, i + 1);
    }

    return 1;
}

// ============================================================================
// Ext.StaticData.IsReady(type)
// ============================================================================

/**
 * Check if a static data type is ready (manager captured).
 *
 * @param type Type name string (optional - if omitted, checks any)
 * @return boolean
 */
static int lua_staticdata_isready(lua_State *L) {
    if (lua_gettop(L) == 0) {
        // No argument - check if any manager is ready
        lua_pushboolean(L, staticdata_manager_ready());
        return 1;
    }

    const char* type_name = luaL_checkstring(L, 1);
    int type = staticdata_type_from_name(type_name);
    if (type < 0) {
        lua_pushboolean(L, 0);
        return 1;
    }

    lua_pushboolean(L, staticdata_has_manager((StaticDataType)type));
    return 1;
}

// ============================================================================
// Ext.StaticData.DumpStatus()
// ============================================================================

/**
 * Dump static data manager status to log (debug function).
 */
static int lua_staticdata_dumpstatus(lua_State *L) {
    (void)L;
    staticdata_dump_status();
    return 0;
}

// ============================================================================
// Ext.StaticData.DumpEntries(type, max)
// ============================================================================

/**
 * Dump entries of a type to log (debug function).
 *
 * @param type Type name string
 * @param max Maximum entries to dump (optional, default all)
 */
static int lua_staticdata_dumpentries(lua_State *L) {
    const char* type_name = luaL_checkstring(L, 1);
    int max = (int)luaL_optinteger(L, 2, -1);

    int type = staticdata_type_from_name(type_name);
    if (type < 0) {
        return luaL_error(L, "Unknown static data type: %s", type_name);
    }

    staticdata_dump_entries((StaticDataType)type, max);
    return 0;
}

// ============================================================================
// Ext.StaticData.Probe(type, range)
// ============================================================================

/**
 * Probe a manager for structure discovery (debug function).
 *
 * @param type Type name string
 * @param range Byte range to probe (optional, default 256)
 */
static int lua_staticdata_probe(lua_State *L) {
    const char* type_name = luaL_checkstring(L, 1);
    int range = (int)luaL_optinteger(L, 2, 256);

    int type = staticdata_type_from_name(type_name);
    if (type < 0) {
        return luaL_error(L, "Unknown static data type: %s", type_name);
    }

    staticdata_probe_manager((StaticDataType)type, range);
    return 0;
}

/**
 * Try to capture managers via TypeContext traversal (debug function).
 */
static int lua_staticdata_trytypecontext(lua_State *L) {
    (void)L;
    staticdata_try_typecontext_capture();
    return 0;
}

/**
 * Dump feat array memory for debugging structure layout (debug function).
 */
static int lua_staticdata_dumpfeatmemory(lua_State *L) {
    (void)L;
    staticdata_dump_feat_memory();
    return 0;
}

// ============================================================================
// Ext.StaticData.LoadFridaCapture([type])
// ============================================================================

/**
 * Load captured managers from Frida capture file.
 *
 * Workflow:
 * 1. In terminal: frida -U -n "Baldur's Gate 3" -l tools/frida/capture_featmanager_live.js
 * 2. In game: Open respec or level-up and click on feats
 * 3. In console: Ext.StaticData.LoadFridaCapture()  -- or LoadFridaCapture("Feat")
 * 4. Now GetAll("Feat") will return actual feat data
 *
 * @param type Optional type name string (defaults to "Feat")
 * @return boolean true if capture loaded successfully
 */
static int lua_staticdata_loadfridacapture(lua_State *L) {
    bool success;

    if (lua_gettop(L) == 0 || lua_isnil(L, 1)) {
        // No argument - load Feat (backwards compatible)
        success = staticdata_load_frida_capture();
    } else {
        // Type argument provided
        const char* type_name = luaL_checkstring(L, 1);
        int type = staticdata_type_from_name(type_name);
        if (type < 0) {
            return luaL_error(L, "Unknown static data type: %s", type_name);
        }
        success = staticdata_load_frida_capture_type((StaticDataType)type);
    }

    lua_pushboolean(L, success);
    return 1;
}

/**
 * Check if Frida capture is available.
 *
 * @param type Optional type name string (defaults to "Feat")
 * @return boolean true if capture file exists
 */
static int lua_staticdata_fridacaptureavailable(lua_State *L) {
    bool available;

    if (lua_gettop(L) == 0 || lua_isnil(L, 1)) {
        // No argument - check Feat (backwards compatible)
        available = staticdata_frida_capture_available();
    } else {
        // Type argument provided
        const char* type_name = luaL_checkstring(L, 1);
        int type = staticdata_type_from_name(type_name);
        if (type < 0) {
            lua_pushboolean(L, 0);
            return 1;
        }
        available = staticdata_frida_capture_available_type((StaticDataType)type);
    }

    lua_pushboolean(L, available);
    return 1;
}

/**
 * Manually trigger manager capture attempt.
 * Useful for debugging or if auto-capture at SessionLoaded didn't find managers.
 *
 * Uses TypeContext traversal + real manager probing + Frida capture fallback.
 *
 * @return number of managers captured
 */
static int lua_staticdata_triggercapture(lua_State *L) {
    int captured = staticdata_post_init_capture();
    lua_pushinteger(L, captured);
    return 1;
}

// ============================================================================
// Registration
// ============================================================================

static const luaL_Reg staticdata_funcs[] = {
    {"GetAll", lua_staticdata_getall},
    {"Get", lua_staticdata_get},
    {"GetCount", lua_staticdata_getcount},
    {"GetTypes", lua_staticdata_gettypes},
    {"IsReady", lua_staticdata_isready},
    {"DumpStatus", lua_staticdata_dumpstatus},
    {"DumpEntries", lua_staticdata_dumpentries},
    {"Probe", lua_staticdata_probe},
    {"TryTypeContext", lua_staticdata_trytypecontext},
    {"LoadFridaCapture", lua_staticdata_loadfridacapture},
    {"FridaCaptureAvailable", lua_staticdata_fridacaptureavailable},
    {"DumpFeatMemory", lua_staticdata_dumpfeatmemory},
    {"TriggerCapture", lua_staticdata_triggercapture},
    {NULL, NULL}
};

void lua_staticdata_register(lua_State *L, int ext_table_idx) {
    // Convert to absolute index before pushing new values
    if (ext_table_idx < 0) {
        ext_table_idx = lua_gettop(L) + ext_table_idx + 1;
    }

    // Create Ext.StaticData table
    lua_newtable(L);

    // Register functions
    for (const luaL_Reg* func = staticdata_funcs; func->name; func++) {
        lua_pushcfunction(L, func->func);
        lua_setfield(L, -2, func->name);
    }

    // Set Ext.StaticData
    lua_setfield(L, ext_table_idx, "StaticData");

    log_message("[Lua] Registered Ext.StaticData API");
}
