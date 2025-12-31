/**
 * @file lua_imgui.h
 * @brief Lua bindings for Ext.IMGUI namespace
 *
 * Provides ImGui overlay functionality to Lua mods.
 */

#ifndef LUA_IMGUI_H
#define LUA_IMGUI_H

#include "lua.h"

/**
 * Register Ext.IMGUI namespace with all functions.
 *
 * @param L Lua state
 * @param ext_idx Stack index of the Ext table
 */
void lua_imgui_register(lua_State *L, int ext_idx);

#endif /* LUA_IMGUI_H */
