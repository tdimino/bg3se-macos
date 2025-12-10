/**
 * BG3SE-macOS - Lua Osiris Namespace Module
 *
 * Provides Ext.Osiris API for registering callbacks for Osiris events.
 */

#ifndef BG3SE_LUA_OSIRIS_H
#define BG3SE_LUA_OSIRIS_H

#include <lua.h>
#include <lauxlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Constants
// ============================================================================

#define MAX_OSIRIS_LISTENERS 64

// ============================================================================
// Data Structures
// ============================================================================

/**
 * Registered Osiris event listener
 */
typedef struct {
    char event_name[128];    // Osiris event name to listen for
    int arity;               // Number of arguments the callback expects
    char timing[16];         // "before" or "after"
    int callback_ref;        // Lua registry reference to callback function
} OsirisListener;

// ============================================================================
// Lua C API Functions
// ============================================================================

/**
 * Ext.Osiris.RegisterListener(event, arity, timing, callback)
 * Registers a callback for an Osiris event.
 */
int lua_ext_osiris_registerlistener(lua_State *L);

/**
 * Ext.Osiris.NewCall(name, signature, handler)
 * Registers a custom Osiris call (no return value).
 */
int lua_ext_osiris_newcall(lua_State *L);

/**
 * Ext.Osiris.NewQuery(name, signature, handler)
 * Registers a custom Osiris query (returns values via OUT params).
 */
int lua_ext_osiris_newquery(lua_State *L);

/**
 * Ext.Osiris.NewEvent(name, signature)
 * Registers a custom Osiris event (can be raised from Lua).
 */
int lua_ext_osiris_newevent(lua_State *L);

// ============================================================================
// Listener Access Functions
// ============================================================================

/**
 * Get the total number of registered listeners.
 */
int lua_osiris_get_listener_count(void);

/**
 * Get a listener by index.
 * @return Pointer to listener, or NULL if index out of range
 */
OsirisListener *lua_osiris_get_listener(int index);

/**
 * Reset all listeners (for cleanup).
 */
void lua_osiris_reset_listeners(void);

/**
 * Reset all custom functions (for session cleanup).
 * @param L Lua state (to release callback references)
 */
void lua_osiris_reset_custom_functions(lua_State *L);

// ============================================================================
// Registration
// ============================================================================

/**
 * Register Ext.Osiris namespace functions.
 * @param L Lua state with Ext table on top of stack
 */
void lua_osiris_register(lua_State *L);

#ifdef __cplusplus
}
#endif

#endif // BG3SE_LUA_OSIRIS_H
