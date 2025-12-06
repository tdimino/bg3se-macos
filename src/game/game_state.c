/**
 * BG3SE-macOS - Game State Tracker Implementation
 *
 * Since macOS binary has stripped debug strings (no "SERVER STATE SWAP" etc.),
 * we infer game state from observable events rather than hooking GameStateEventManager.
 */

#include "game_state.h"
#include "lua_events.h"
#include "logging.h"

#include <string.h>
#include <time.h>

// ============================================================================
// State Names (for logging and Lua)
// ============================================================================

static const char *g_state_names[SERVER_STATE_MAX] = {
    "Unknown",
    "Uninitialized",
    "Init",
    "Idle",
    "Exit",
    "LoadLevel",
    "LoadModule",
    "LoadSession",
    "UnloadLevel",
    "UnloadModule",
    "UnloadSession",
    "Sync",
    "Paused",
    "Running",
    "Save",
    "Disconnect",
    "BuildStory",
    "ReloadStory"
};

// ============================================================================
// Static State
// ============================================================================

static ServerGameState g_current_state = SERVER_STATE_UNKNOWN;
static ServerGameState g_previous_state = SERVER_STATE_UNKNOWN;
static int g_initialized = 0;

// Tick timing for pause detection
static clock_t g_last_tick_time = 0;
static float g_accumulated_pause_time = 0.0f;
static int g_pause_detection_enabled = 0;

// Thresholds
#define PAUSE_THRESHOLD_MS 500  // If no tick for 500ms, likely paused

// ============================================================================
// Internal: Fire State Change Event
// ============================================================================

static void fire_state_change(lua_State *L, ServerGameState from, ServerGameState to) {
    if (from == to) return;  // No change

    g_previous_state = from;
    g_current_state = to;

    log_message("[GameState] State transition: %s (%d) -> %s (%d)",
                game_state_get_name(from), from,
                game_state_get_name(to), to);

    // Fire the Lua event
    events_fire_game_state_changed(L, (int)from, (int)to);
}

// ============================================================================
// Public API: Initialize
// ============================================================================

void game_state_init(void) {
    if (g_initialized) return;

    g_current_state = SERVER_STATE_INIT;
    g_previous_state = SERVER_STATE_UNKNOWN;
    g_last_tick_time = 0;
    g_accumulated_pause_time = 0.0f;
    g_pause_detection_enabled = 0;
    g_initialized = 1;

    log_message("[GameState] Game state tracker initialized");
}

// ============================================================================
// Public API: Getters
// ============================================================================

ServerGameState game_state_get_current(void) {
    return g_current_state;
}

const char *game_state_get_name(ServerGameState state) {
    if (state >= 0 && state < SERVER_STATE_MAX) {
        return g_state_names[state];
    }
    return "Unknown";
}

// ============================================================================
// Public API: State Notifications
// ============================================================================

void game_state_on_session_loading(lua_State *L) {
    if (g_current_state != SERVER_STATE_LOAD_SESSION) {
        fire_state_change(L, g_current_state, SERVER_STATE_LOAD_SESSION);
    }
}

void game_state_on_session_loaded(lua_State *L) {
    // Transition to Running state
    fire_state_change(L, g_current_state, SERVER_STATE_RUNNING);

    // Enable pause detection now that the game is running
    g_pause_detection_enabled = 1;
    g_last_tick_time = clock();
}

void game_state_on_reset(lua_State *L) {
    // Reset typically goes through: Running -> Unload -> Idle
    // We simplify to: Running -> Idle -> (wait for new session)
    if (g_current_state == SERVER_STATE_RUNNING ||
        g_current_state == SERVER_STATE_PAUSED) {
        fire_state_change(L, g_current_state, SERVER_STATE_IDLE);
    }
    g_pause_detection_enabled = 0;
}

void game_state_on_save_start(lua_State *L) {
    if (g_current_state == SERVER_STATE_RUNNING) {
        fire_state_change(L, g_current_state, SERVER_STATE_SAVE);
    }
}

void game_state_on_save_complete(lua_State *L) {
    if (g_current_state == SERVER_STATE_SAVE) {
        fire_state_change(L, g_current_state, SERVER_STATE_RUNNING);
    }
}

void game_state_on_combat_started(lua_State *L) {
    // Combat is a substate of Running, no state change needed
    // But we log it for debugging
    (void)L;
    log_message("[GameState] Combat started (still in Running state)");
}

void game_state_on_combat_ended(lua_State *L) {
    (void)L;
    log_message("[GameState] Combat ended (still in Running state)");
}

void game_state_on_pause(lua_State *L) {
    if (g_current_state == SERVER_STATE_RUNNING) {
        fire_state_change(L, g_current_state, SERVER_STATE_PAUSED);
    }
}

void game_state_on_unpause(lua_State *L) {
    if (g_current_state == SERVER_STATE_PAUSED) {
        fire_state_change(L, g_current_state, SERVER_STATE_RUNNING);
    }
}

// ============================================================================
// Public API: Pause Detection
// ============================================================================

int game_state_is_paused(void) {
    return g_current_state == SERVER_STATE_PAUSED;
}

void game_state_update_tick(float delta_time) {
    if (!g_pause_detection_enabled) return;

    clock_t now = clock();

    // If we're getting ticks with reasonable delta times, we're not paused
    // A paused game stops calling tick entirely

    if (g_last_tick_time != 0) {
        double elapsed_ms = (double)(now - g_last_tick_time) * 1000.0 / CLOCKS_PER_SEC;

        // If real time since last tick is much longer than delta_time suggests,
        // the game was probably paused
        float expected_ms = delta_time * 1000.0f;

        if (elapsed_ms > PAUSE_THRESHOLD_MS && expected_ms < PAUSE_THRESHOLD_MS) {
            // We were paused and just resumed
            // Note: We can't fire the event here because we don't have lua_State
            // The pause/unpause detection would need to be called from the tick handler
            g_accumulated_pause_time += (float)(elapsed_ms - expected_ms) / 1000.0f;
        }
    }

    g_last_tick_time = now;
}
