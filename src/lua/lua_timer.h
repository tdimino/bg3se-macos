/**
 * lua_timer.h - Ext.Timer Lua bindings
 */

#ifndef LUA_TIMER_H
#define LUA_TIMER_H

#include <lua.h>

// Register the Ext.Timer namespace
void lua_timer_register(lua_State *L, int ext_table_idx);

#endif // LUA_TIMER_H
