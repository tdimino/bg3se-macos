/**
 * BG3SE-macOS - Lua Ext Namespace Core Implementation
 *
 * Core Ext.* API functions.
 */

#include "lua_ext.h"
#include "version.h"
#include "logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Ext Core Functions
// ============================================================================

int lua_ext_print(lua_State *L) {
    int n = lua_gettop(L);
    luaL_Buffer b;
    luaL_buffinit(L, &b);

    for (int i = 1; i <= n; i++) {
        size_t len;
        const char *s = luaL_tolstring(L, i, &len);
        if (i > 1) luaL_addchar(&b, '\t');
        luaL_addlstring(&b, s, len);
        lua_pop(L, 1);  // pop the string from luaL_tolstring
    }

    luaL_pushresult(&b);
    const char *msg = lua_tostring(L, -1);
    log_message("[Lua] %s", msg);

    return 0;
}

int lua_ext_getversion(lua_State *L) {
    lua_pushstring(L, BG3SE_VERSION);
    return 1;
}

int lua_ext_isserver(lua_State *L) {
    // For now, always return false (client-side)
    lua_pushboolean(L, 0);
    return 1;
}

int lua_ext_isclient(lua_State *L) {
    // For now, always return true (client-side)
    lua_pushboolean(L, 1);
    return 1;
}

// ============================================================================
// Ext.IO Functions
// ============================================================================

int lua_ext_io_loadfile(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    log_message("[Lua] Ext.IO.LoadFile('%s')", path);

    FILE *f = fopen(path, "r");
    if (!f) {
        lua_pushnil(L);
        lua_pushstring(L, "File not found");
        return 2;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *content = (char *)malloc(size + 1);
    if (!content) {
        fclose(f);
        lua_pushnil(L);
        lua_pushstring(L, "Out of memory");
        return 2;
    }

    fread(content, 1, size, f);
    content[size] = '\0';
    fclose(f);

    lua_pushstring(L, content);
    free(content);
    return 1;
}

int lua_ext_io_savefile(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    const char *content = luaL_checkstring(L, 2);
    log_message("[Lua] Ext.IO.SaveFile('%s')", path);

    FILE *f = fopen(path, "w");
    if (!f) {
        lua_pushboolean(L, 0);
        return 1;
    }

    fputs(content, f);
    fclose(f);

    lua_pushboolean(L, 1);
    return 1;
}

// ============================================================================
// Registration
// ============================================================================

void lua_ext_register_basic(lua_State *L, int ext_table_index) {
    // Convert negative index to absolute since we'll be pushing onto stack
    if (ext_table_index < 0) {
        ext_table_index = lua_gettop(L) + ext_table_index + 1;
    }

    lua_pushcfunction(L, lua_ext_print);
    lua_setfield(L, ext_table_index, "Print");

    lua_pushcfunction(L, lua_ext_getversion);
    lua_setfield(L, ext_table_index, "GetVersion");

    lua_pushcfunction(L, lua_ext_isserver);
    lua_setfield(L, ext_table_index, "IsServer");

    lua_pushcfunction(L, lua_ext_isclient);
    lua_setfield(L, ext_table_index, "IsClient");
}

void lua_ext_register_io(lua_State *L, int ext_table_index) {
    // Convert negative index to absolute since we'll be pushing onto stack
    if (ext_table_index < 0) {
        ext_table_index = lua_gettop(L) + ext_table_index + 1;
    }

    // Create Ext.IO table
    lua_newtable(L);
    lua_pushcfunction(L, lua_ext_io_loadfile);
    lua_setfield(L, -2, "LoadFile");
    lua_pushcfunction(L, lua_ext_io_savefile);
    lua_setfield(L, -2, "SaveFile");
    lua_setfield(L, ext_table_index, "IO");
}
