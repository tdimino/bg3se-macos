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
    EVENT_GAME_STATE_CHANGED,
    EVENT_KEY_INPUT,           // Keyboard input event
    EVENT_DO_CONSOLE_COMMAND,  // Console command interception
    EVENT_LUA_CONSOLE_INPUT,   // Raw Lua console input
    EVENT_MAX
} BG3SEEventType;

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
void events_fire(lua_State *L, BG3SEEventType event);

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
 * Fire the KeyInput event with key data.
 * Handlers receive {Key = int, Pressed = bool, Modifiers = int, Character = string} table.
 *
 * @param L         Lua state
 * @param keyCode   Virtual key code
 * @param pressed   true for key down, false for key up
 * @param modifiers Modifier bitmask (shift/ctrl/alt/cmd)
 * @param character Character string (if printable)
 */
void events_fire_key_input(lua_State *L, int keyCode, bool pressed, int modifiers, const char *character);

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
int events_get_handler_count(BG3SEEventType event);

/**
 * Get event name string.
 *
 * @param event Event type
 * @return Static event name string
 */
const char *events_get_name(BG3SEEventType event);

/**
 * Fire the DoConsoleCommand event with command data.
 * Handlers receive {Command = string} table.
 * Returns true if any handler requested to prevent default execution.
 *
 * @param L       Lua state
 * @param command The console command (including ! prefix)
 * @return true if command should be prevented (a handler set e.Prevent = true)
 */
bool events_fire_do_console_command(lua_State *L, const char *command);

/**
 * Fire the LuaConsoleInput event with input data.
 * Handlers receive {Input = string} table.
 * Returns true if any handler requested to prevent default execution.
 *
 * @param L     Lua state
 * @param input The Lua code input
 * @return true if execution should be prevented (a handler set e.Prevent = true)
 */
bool events_fire_lua_console_input(lua_State *L, const char *input);

#endif /* LUA_EVENTS_H */
