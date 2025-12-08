/**
 * BG3SE-macOS - Lua Osiris Namespace Implementation
 *
 * Handles registration of Osiris event listeners.
 */

#include "lua_osiris.h"
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

// ============================================================================
// Registration
// ============================================================================

void lua_osiris_register(lua_State *L) {
    // Get Ext table
    lua_getglobal(L, "Ext");

    // Create Ext.Osiris table
    lua_newtable(L);

    lua_pushcfunction(L, lua_ext_osiris_registerlistener);
    lua_setfield(L, -2, "RegisterListener");

    lua_setfield(L, -2, "Osiris");

    lua_pop(L, 1);  // Pop Ext table

    LOG_OSIRIS_INFO("Ext.Osiris API registered");
}
