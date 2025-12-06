/**
 * BG3SE-macOS - Game State Tracker
 *
 * Tracks game state transitions by observing Osiris events and game behavior.
 * Fires EVENT_GAME_STATE_CHANGED when state transitions are detected.
 *
 * Note: macOS binary has stripped debug strings, so we can't directly hook
 * GameStateEventManager. Instead, we infer state from observable events.
 */

#ifndef GAME_STATE_H
#define GAME_STATE_H

#include <lua.h>

// ============================================================================
// Server Game State (matches Windows BG3SE ServerGameState enum)
// ============================================================================

typedef enum {
    SERVER_STATE_UNKNOWN = 0,
    SERVER_STATE_UNINITIALIZED = 1,
    SERVER_STATE_INIT = 2,
    SERVER_STATE_IDLE = 3,
    SERVER_STATE_EXIT = 4,
    SERVER_STATE_LOAD_LEVEL = 5,
    SERVER_STATE_LOAD_MODULE = 6,
    SERVER_STATE_LOAD_SESSION = 7,
    SERVER_STATE_UNLOAD_LEVEL = 8,
    SERVER_STATE_UNLOAD_MODULE = 9,
    SERVER_STATE_UNLOAD_SESSION = 10,
    SERVER_STATE_SYNC = 11,
    SERVER_STATE_PAUSED = 12,
    SERVER_STATE_RUNNING = 13,
    SERVER_STATE_SAVE = 14,
    SERVER_STATE_DISCONNECT = 15,
    SERVER_STATE_BUILD_STORY = 16,
    SERVER_STATE_RELOAD_STORY = 17,
    SERVER_STATE_MAX
} ServerGameState;

// ============================================================================
// Public API
// ============================================================================

/**
 * Initialize the game state tracker.
 * Must be called once during startup.
 */
void game_state_init(void);

/**
 * Get the current game state.
 */
ServerGameState game_state_get_current(void);

/**
 * Get a human-readable name for a game state.
 */
const char *game_state_get_name(ServerGameState state);

/**
 * Notify the state tracker that session is loading.
 * Called when mod scripts start loading.
 */
void game_state_on_session_loading(lua_State *L);

/**
 * Notify the state tracker that session is loaded.
 * Called when LevelGameplayStarted fires.
 */
void game_state_on_session_loaded(lua_State *L);

/**
 * Notify the state tracker of a reset.
 * Called when the game resets (console reset command).
 */
void game_state_on_reset(lua_State *L);

/**
 * Notify the state tracker that a save operation is in progress.
 * Called when save events are detected.
 */
void game_state_on_save_start(lua_State *L);
void game_state_on_save_complete(lua_State *L);

/**
 * Notify the state tracker that combat state changed.
 * Useful for detecting Running vs combat substates.
 */
void game_state_on_combat_started(lua_State *L);
void game_state_on_combat_ended(lua_State *L);

/**
 * Notify the state tracker of pause/unpause.
 * Called when pause state can be detected (e.g., via tick timing).
 */
void game_state_on_pause(lua_State *L);
void game_state_on_unpause(lua_State *L);

/**
 * Check if the game is currently paused.
 * This uses tick timing heuristics.
 */
int game_state_is_paused(void);

/**
 * Update tick timing (called from Tick event).
 * Used to detect pause state.
 *
 * @param delta_time Time since last tick in seconds
 */
void game_state_update_tick(float delta_time);

#endif /* GAME_STATE_H */
