/**
 * @file lua_imgui.h
 * @brief Lua bindings for Ext.IMGUI namespace
 *
 * Provides ImGui overlay functionality to Lua mods.
 */

#ifndef LUA_IMGUI_H
#define LUA_IMGUI_H

#include "lua.h"
#include "../imgui/imgui_objects.h"

/**
 * Register Ext.IMGUI namespace with all functions.
 *
 * @param L Lua state
 * @param ext_idx Stack index of the Ext table
 */
void lua_imgui_register(lua_State *L, int ext_idx);

/**
 * Set the Lua state for IMGUI event callbacks.
 * Called from console_poll() or other tick functions.
 *
 * @param L Lua state
 */
void lua_imgui_set_lua_state(lua_State *L);

/**
 * Get the Lua state for IMGUI event callbacks.
 *
 * @return Lua state or NULL if not set
 */
lua_State *lua_imgui_get_lua_state(void);

/**
 * Fire an IMGUI event callback.
 *
 * @param handle Object handle
 * @param event Event type
 * @param ... Event-specific arguments (depends on event type)
 */
void lua_imgui_fire_event(ImguiHandle handle, ImguiEventType event, ...);

/**
 * Clean up Lua references for an IMGUI object before destruction.
 * Must be called before imgui_object_destroy() to prevent memory leaks.
 *
 * @param handle Object handle to clean up
 */
void lua_imgui_cleanup_refs(ImguiHandle handle);

#endif /* LUA_IMGUI_H */
