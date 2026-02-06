/**
 * lua_level.h - Lua bindings for Ext.Level API
 *
 * Provides Lua access to level physics and tile queries.
 */

#ifndef LUA_LEVEL_H
#define LUA_LEVEL_H

#include <lua.h>

/**
 * Register Ext.Level API with the Lua state.
 *
 * @param L Lua state
 * @param ext_table_idx Stack index of Ext table
 */
void lua_level_register(lua_State *L, int ext_table_idx);

#endif // LUA_LEVEL_H
