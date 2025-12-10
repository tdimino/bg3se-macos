/**
 * BG3SE-macOS - Lua Osiris Namespace Implementation
 *
 * Handles registration of Osiris event listeners and custom functions.
 */

#include "lua_osiris.h"
#include "custom_functions.h"
#include "logging.h"

#include <string.h>

// ============================================================================
// Internal State
// ============================================================================

static OsirisListener osiris_listeners[MAX_OSIRIS_LISTENERS];
static int osiris_listener_count = 0;

// ============================================================================
// Lua C API Functions
// ============================================================================

int lua_ext_osiris_registerlistener(lua_State *L) {
    const char *event = luaL_checkstring(L, 1);
    int arity = (int)luaL_checkinteger(L, 2);
    const char *timing = luaL_checkstring(L, 3);
    luaL_checktype(L, 4, LUA_TFUNCTION);

    if (osiris_listener_count >= MAX_OSIRIS_LISTENERS) {
        LOG_LUA_DEBUG("Warning: Max Osiris listeners reached");
        return 0;
    }

    // Store the listener
    OsirisListener *listener = &osiris_listeners[osiris_listener_count];
    strncpy(listener->event_name, event, sizeof(listener->event_name) - 1);
    listener->event_name[sizeof(listener->event_name) - 1] = '\0';
    listener->arity = arity;
    strncpy(listener->timing, timing, sizeof(listener->timing) - 1);
    listener->timing[sizeof(listener->timing) - 1] = '\0';

    // Store callback reference in Lua registry
    lua_pushvalue(L, 4);  // Push the function
    listener->callback_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    osiris_listener_count++;

    LOG_LUA_DEBUG("Registered Osiris listener: %s (arity=%d, timing=%s)",
                event, arity, timing);

    return 0;
}

// ============================================================================
// Custom Function Registration
// ============================================================================

int lua_ext_osiris_newcall(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);
    const char *signature = luaL_checkstring(L, 2);
    luaL_checktype(L, 3, LUA_TFUNCTION);

    // Store callback in registry
    lua_pushvalue(L, 3);
    int callback_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // Register the custom call
    uint32_t handle = custom_func_register(name, CUSTOM_FUNC_CALL, callback_ref, signature);
    if (handle == 0) {
        luaL_unref(L, LUA_REGISTRYINDEX, callback_ref);
        return luaL_error(L, "Failed to register custom call '%s'", name);
    }

    LOG_LUA_DEBUG("Ext.Osiris.NewCall: registered '%s' (ID=0x%x)", name, handle);

    lua_pushinteger(L, handle);
    return 1;
}

int lua_ext_osiris_newquery(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);
    const char *signature = luaL_checkstring(L, 2);
    luaL_checktype(L, 3, LUA_TFUNCTION);

    // Store callback in registry
    lua_pushvalue(L, 3);
    int callback_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // Register the custom query
    uint32_t handle = custom_func_register(name, CUSTOM_FUNC_QUERY, callback_ref, signature);
    if (handle == 0) {
        luaL_unref(L, LUA_REGISTRYINDEX, callback_ref);
        return luaL_error(L, "Failed to register custom query '%s'", name);
    }

    LOG_LUA_DEBUG("Ext.Osiris.NewQuery: registered '%s' (ID=0x%x)", name, handle);

    lua_pushinteger(L, handle);
    return 1;
}

int lua_ext_osiris_newevent(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);
    const char *signature = luaL_checkstring(L, 2);

    // Events don't have callbacks - they're raised from Lua
    uint32_t handle = custom_func_register(name, CUSTOM_FUNC_EVENT, LUA_NOREF, signature);
    if (handle == 0) {
        return luaL_error(L, "Failed to register custom event '%s'", name);
    }

    LOG_LUA_DEBUG("Ext.Osiris.NewEvent: registered '%s' (ID=0x%x)", name, handle);

    lua_pushinteger(L, handle);
    return 1;
}

// ============================================================================
// Listener Access Functions
// ============================================================================

int lua_osiris_get_listener_count(void) {
    return osiris_listener_count;
}

OsirisListener *lua_osiris_get_listener(int index) {
    if (index < 0 || index >= osiris_listener_count) {
        return NULL;
    }
    return &osiris_listeners[index];
}

void lua_osiris_reset_listeners(void) {
    osiris_listener_count = 0;
}

void lua_osiris_reset_custom_functions(lua_State *L) {
    custom_func_clear(L);
}

// ============================================================================
// Registration
// ============================================================================

void lua_osiris_register(lua_State *L) {
    // Initialize custom function registry
    custom_func_init();

    // Get Ext table
    lua_getglobal(L, "Ext");

    // Create Ext.Osiris table
    lua_newtable(L);

    lua_pushcfunction(L, lua_ext_osiris_registerlistener);
    lua_setfield(L, -2, "RegisterListener");

    lua_pushcfunction(L, lua_ext_osiris_newcall);
    lua_setfield(L, -2, "NewCall");

    lua_pushcfunction(L, lua_ext_osiris_newquery);
    lua_setfield(L, -2, "NewQuery");

    lua_pushcfunction(L, lua_ext_osiris_newevent);
    lua_setfield(L, -2, "NewEvent");

    lua_setfield(L, -2, "Osiris");

    lua_pop(L, 1);  // Pop Ext table

    LOG_OSIRIS_INFO("Ext.Osiris API registered (with NewCall/NewQuery/NewEvent)");
}
