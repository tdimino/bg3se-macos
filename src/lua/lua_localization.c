/**
 * lua_localization.c - Lua Bindings for Localization API
 */

#include "lua_localization.h"
#include "localization.h"
#include "logging.h"
#include <string.h>

// ============================================================================
// Lua C API Functions
// ============================================================================

int lua_loca_get_translated_string(lua_State *L) {
    // Get handle (required)
    const char *handle = luaL_checkstring(L, 1);

    // Get optional fallback
    const char *fallback = NULL;
    if (lua_gettop(L) >= 2 && !lua_isnil(L, 2)) {
        fallback = lua_tostring(L, 2);
    }

    // Get translated string
    const char *result = localization_get(handle, fallback);

    lua_pushstring(L, result);
    return 1;
}

int lua_loca_update_translated_string(lua_State *L) {
    const char *handle = luaL_checkstring(L, 1);
    const char *value = luaL_checkstring(L, 2);

    bool success = localization_set(handle, value);

    lua_pushboolean(L, success);
    return 1;
}

int lua_loca_get_language(lua_State *L) {
    const char *lang = localization_get_language();
    lua_pushstring(L, lang);
    return 1;
}

int lua_loca_is_ready(lua_State *L) {
    lua_pushboolean(L, localization_ready());
    return 1;
}

int lua_loca_dump_info(lua_State *L) {
    (void)L;
    localization_dump_info();
    return 0;
}

// ============================================================================
// Registration
// ============================================================================

void lua_ext_register_loca(lua_State *L, int ext_table_index) {
    // Convert to absolute index before pushing new values
    if (ext_table_index < 0) {
        ext_table_index = lua_gettop(L) + ext_table_index + 1;
    }

    // Create Ext.Loca table
    lua_newtable(L);

    // Register functions
    lua_pushcfunction(L, lua_loca_get_translated_string);
    lua_setfield(L, -2, "GetTranslatedString");

    lua_pushcfunction(L, lua_loca_update_translated_string);
    lua_setfield(L, -2, "UpdateTranslatedString");

    lua_pushcfunction(L, lua_loca_get_language);
    lua_setfield(L, -2, "GetLanguage");

    lua_pushcfunction(L, lua_loca_is_ready);
    lua_setfield(L, -2, "IsReady");

    lua_pushcfunction(L, lua_loca_dump_info);
    lua_setfield(L, -2, "DumpInfo");

    // Set Ext.Loca = table (use absolute index)
    lua_setfield(L, ext_table_index, "Loca");

    LOG_LUA_INFO("Registered Ext.Loca namespace");
}
