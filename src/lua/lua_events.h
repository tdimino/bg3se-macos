/**
 * BG3SE-macOS - Event System Header
 *
 * Advanced event subscription with priority ordering, Once flag, and handler IDs.
 * Replaces the simple event system previously in main.c.
 */

#ifndef LUA_EVENTS_H
#define LUA_EVENTS_H

#include <lua.h>
#include <lauxlib.h>
#include <stdint.h>

// ============================================================================
// Event Types
// ============================================================================

typedef enum {
    EVENT_SESSION_LOADING = 0,
    EVENT_SESSION_LOADED,
    EVENT_RESET_COMPLETED,
    EVENT_TICK,
    EVENT_STATS_LOADED,
    EVENT_MODULE_LOAD_STARTED,
    EVENT_GAME_STATE_CHANGED,  // Phase 3 - deferred
    EVENT_MAX
} EventType;

// ============================================================================
// Public API
// ============================================================================

/**
 * Initialize the event system.
 * Must be called before any other event functions.
 */
void events_init(void);

/**
 * Fire an event to all registered handlers.
 * Handlers receive an empty event data table.
 *
 * @param L     Lua state
 * @param event Event type to fire
 */
void events_fire(lua_State *L, EventType event);

/**
 * Fire the Tick event with delta time data.
 * Handlers receive {DeltaTime = float} table.
 *
 * @param L          Lua state
 * @param delta_time Seconds since last tick
 */
void events_fire_tick(lua_State *L, float delta_time);

/**
 * Fire the GameStateChanged event with state transition data.
 * Handlers receive {FromState = int, ToState = int} table.
 *
 * State values match Windows BG3SE ServerGameState enum:
 *   0=Unknown, 1=Uninitialized, 2=Init, 3=Idle, 4=Exit,
 *   5=LoadLevel, 6=LoadModule, 7=LoadSession, 8=UnloadLevel,
 *   9=UnloadModule, 10=UnloadSession, 11=Sync, 12=Paused,
 *   13=Running, 14=Save, 15=Disconnect, 16=BuildStory, 17=ReloadStory
 *
 * @param L         Lua state
 * @param fromState Previous state value
 * @param toState   New state value
 */
void events_fire_game_state_changed(lua_State *L, int fromState, int toState);

/**
 * Register the Ext.Events namespace and Ext.OnNextTick function.
 *
 * @param L               Lua state
 * @param ext_table_index Stack index of Ext table
 */
void lua_events_register(lua_State *L, int ext_table_index);

/**
 * Get handler count for an event (for debugging).
 *
 * @param event Event type
 * @return Number of registered handlers
 */
int events_get_handler_count(EventType event);

/**
 * Get event name string.
 *
 * @param event Event type
 * @return Static event name string
 */
const char *events_get_name(EventType event);

#endif /* LUA_EVENTS_H */
