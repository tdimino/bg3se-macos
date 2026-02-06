/**
 * lua_audio.h - Lua bindings for Ext.Audio API
 *
 * Provides Lua access to WWise audio engine control.
 */

#ifndef LUA_AUDIO_H
#define LUA_AUDIO_H

#include <lua.h>

/**
 * Register Ext.Audio API with the Lua state.
 *
 * @param L Lua state
 * @param ext_table_idx Stack index of Ext table
 */
void lua_audio_register(lua_State *L, int ext_table_idx);

#endif // LUA_AUDIO_H
