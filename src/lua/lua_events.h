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
#include <stdbool.h>

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
    EVENT_LOG,                 // Log message event (for mod interception)
    // Engine events (Issue #51) - Polled from one-frame components
    EVENT_TURN_STARTED,        // Combat turn started
    EVENT_TURN_ENDED,          // Combat turn ended
    EVENT_COMBAT_STARTED,      // Combat initiated
    EVENT_COMBAT_ENDED,        // Combat resolved
    EVENT_STATUS_APPLIED,      // Status effect applied
    EVENT_STATUS_REMOVED,      // Status effect removed
    EVENT_EQUIPMENT_CHANGED,   // Equipment slot changed
    EVENT_LEVEL_UP,            // Character level increased
    // Additional engine events (Issue #51 expansion)
    EVENT_DIED,                // Character/entity died
    EVENT_DOWNED,              // Character downed (0 HP)
    EVENT_RESURRECTED,         // Character resurrected
    EVENT_SPELL_CAST,          // Spell cast started
    EVENT_SPELL_CAST_FINISHED, // Spell cast finished
    EVENT_HIT_NOTIFICATION,    // Hit notification
    EVENT_SHORT_REST_STARTED,  // Short rest result
    EVENT_APPROVAL_CHANGED,    // Companion approval changed
    // Lifecycle events (Issue #51 expansion)
    EVENT_STATS_STRUCTURE_LOADED, // Stats structure loaded (before StatsLoaded)
    EVENT_MODULE_RESUME,       // Module resumed from save
    EVENT_SHUTDOWN,            // Game shutdown
    // Functor events (Issue #53)
    EVENT_EXECUTE_FUNCTOR,     // Before functor execution
    EVENT_AFTER_EXECUTE_FUNCTOR, // After functor execution
    EVENT_DEAL_DAMAGE,         // During damage application
    EVENT_DEALT_DAMAGE,        // After damage applied
    EVENT_BEFORE_DEAL_DAMAGE,  // Before damage calculation
    EVENT_NET_MOD_MESSAGE,     // Network mod message (Issue #6)
    EVENT_NET_MESSAGE,         // Legacy network message (no module, Issue #6)
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

/**
 * Poll for one-frame event components and fire corresponding events.
 * Should be called once per tick after the main tick event.
 *
 * This function checks for entities with event marker components like:
 * - esv::TurnStartedEventOneFrameComponent
 * - esv::combat::LeftEventOneFrameComponent
 * - esv::status::ApplyEventOneFrameComponent
 * etc.
 *
 * @param L Lua state
 */
void events_poll_oneframe_components(lua_State *L);

/**
 * Fire the TurnStarted event with combat data.
 * Handlers receive {Entity = handle, Round = int} table.
 *
 * @param L      Lua state
 * @param entity The entity whose turn started (as EntityHandle uint64)
 * @param round  Current combat round
 */
void events_fire_turn_started(lua_State *L, uint64_t entity, int round);

/**
 * Fire the StatusApplied event with status data.
 * Handlers receive {Entity = handle, StatusId = string, Source = handle} table.
 *
 * @param L        Lua state
 * @param entity   The entity receiving the status
 * @param statusId The status ID (FixedString)
 * @param source   The source entity
 */
void events_fire_status_applied(lua_State *L, uint64_t entity, const char *statusId, uint64_t source);

/**
 * Fire ExecuteFunctor event before functor execution.
 * Handlers receive {ContextType = int, FunctorListPtr = int, ContextPtr = int} table.
 *
 * @param L           Lua state
 * @param ctxType     The functor context type (0-8)
 * @param functors    Pointer to functor list
 * @param context     Pointer to context data
 */
void events_fire_execute_functor(lua_State *L, int ctxType, void *functors, void *context);

/**
 * Fire AfterExecuteFunctor event after functor execution.
 * Same parameters as events_fire_execute_functor.
 */
void events_fire_after_execute_functor(lua_State *L, int ctxType, void *functors, void *context);

/**
 * Fire the TurnStarted event from Osiris callback with character GUID.
 * Handlers receive {CharacterGuid = string} table.
 *
 * @param L             Lua state
 * @param characterGuid The character GUID whose turn started
 */
void events_fire_turn_started_from_osiris(lua_State *L, const char *characterGuid);

/**
 * Fire the TurnEnded event from Osiris callback with character GUID.
 * Handlers receive {CharacterGuid = string} table.
 *
 * @param L             Lua state
 * @param characterGuid The character GUID whose turn ended
 */
void events_fire_turn_ended_from_osiris(lua_State *L, const char *characterGuid);

/**
 * Fire the NetModMessage event with network message data.
 * Handlers receive {Channel, Payload, Module, UserID, RequestId, ReplyId, Binary} table.
 *
 * @param L         Lua state
 * @param channel   Channel name
 * @param payload   Message payload (JSON string)
 * @param module    Module UUID
 * @param userId    User ID (0 for server)
 * @param requestId Request ID (for request/reply correlation)
 * @param replyId   Reply ID (if this is a reply)
 * @param binary    Whether payload is binary
 */
void events_fire_net_mod_message(lua_State *L, const char *channel, const char *payload,
                                  const char *module, int userId, uint64_t requestId,
                                  uint64_t replyId, bool binary);

/**
 * Fire the legacy NetMessage event (for mods that don't use module UUIDs).
 * In Windows BG3SE, messages without a module fire NetMessage instead of NetModMessage.
 * Most existing mods still use this legacy event.
 * Handlers receive {Channel, Payload, UserID} table.
 */
void events_fire_net_message(lua_State *L, const char *channel, const char *payload,
                              int userId);

/**
 * Fire the Log event with log message data.
 * Handlers receive {Level = string, Module = string, Message = string} table.
 * Returns true if any handler requested to prevent default logging.
 *
 * This matches Windows BG3SE's Ext.Events.Log pattern, allowing mods to
 * intercept, filter, or redirect log messages.
 *
 * @param L       Lua state
 * @param level   Log level ("DEBUG", "INFO", "WARN", "ERROR")
 * @param module  Module name ("Lua", "Stats", etc.)
 * @param message The log message
 * @return true if logging should be prevented (a handler set e.Prevent = true)
 */
bool events_fire_log(lua_State *L, const char *level, const char *module, const char *message);

/**
 * Initialize the Log event callback with the logging system.
 * Must be called after both event system and logging system are initialized.
 *
 * @param L Lua state to use for firing events
 */
void events_init_log_callback(lua_State *L);

// ============================================================================
// Mod Health API (for crash attribution and !mod_diag)
// ============================================================================

/**
 * Get number of tracked mods.
 */
int events_get_mod_health_count(void);

/**
 * Get mod name by health index.
 */
const char *events_get_mod_health_name(int index);

/**
 * Get mod health statistics.
 */
void events_get_mod_health_stats(int index, uint32_t *handlers, uint32_t *errors,
                                  uint32_t *handled, bool *disabled);

/**
 * Get last error message for a mod.
 */
const char *events_get_mod_last_error(int index);

/**
 * Soft-disable/enable a mod's event handlers.
 * Returns true if mod was found.
 */
bool events_set_mod_disabled(const char *mod_name, bool disabled);

// ============================================================================
// Event Tracing (Debug)
// ============================================================================

/**
 * Enable or disable event tracing.
 * When enabled, all event activity is logged with detailed timing info.
 *
 * @param enabled Whether to enable tracing
 */
void events_set_trace_enabled(bool enabled);

/**
 * Check if event tracing is enabled.
 */
bool events_get_trace_enabled(void);

/**
 * Get the name of an event type.
 */
const char *events_get_name(BG3SEEventType event);

#endif /* LUA_EVENTS_H */
