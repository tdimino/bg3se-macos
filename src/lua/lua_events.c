/**
 * BG3SE-macOS - Event System Implementation
 *
 * Advanced event subscription system with:
 * - Priority-based handler ordering (lower priority = called first)
 * - Once flag for auto-unsubscription after first call
 * - Handler ID return for explicit unsubscription
 * - Deferred modifications during dispatch to prevent iterator corruption
 * - Protected calls to prevent cascade failures
 */

#include "lua_events.h"
#include "logging.h"

#include <string.h>

// ============================================================================
// Constants
// ============================================================================

#define MAX_EVENT_HANDLERS 64
#define MAX_DEFERRED_OPERATIONS 256
#define DEFAULT_PRIORITY 100

// ============================================================================
// Data Structures
// ============================================================================

typedef struct {
    int callback_ref;       // Lua registry reference
    int priority;           // Lower = first (default 100)
    int once;               // Auto-unsubscribe after first call
    uint64_t handler_id;    // Unique ID for unsubscription
} EventHandler;

typedef struct {
    EventType event;
    uint64_t handler_id;
} DeferredUnsubscribe;

// ============================================================================
// Static State
// ============================================================================

static EventHandler g_handlers[EVENT_MAX][MAX_EVENT_HANDLERS];
static int g_handler_counts[EVENT_MAX] = {0};
static uint64_t g_next_handler_id = 1;  // Global counter, never reuse
static int g_dispatch_depth[EVENT_MAX] = {0};  // Reentrancy tracking
static int g_initialized = 0;

// Deferred unsubscriptions (processed after dispatch completes)
static DeferredUnsubscribe g_deferred_unsubs[MAX_DEFERRED_OPERATIONS];
static int g_deferred_unsub_count = 0;

// Event names for logging and Lua
static const char *g_event_names[EVENT_MAX] = {
    "SessionLoading",
    "SessionLoaded",
    "ResetCompleted",
    "Tick",
    "StatsLoaded",
    "ModuleLoadStarted",
    "GameStateChanged"
};

// ============================================================================
// Internal: Priority Sort
// ============================================================================

/**
 * Sort handlers by priority (lower first) using insertion sort.
 * Stable sort preserves registration order for equal priorities.
 */
static void sort_handlers_by_priority(EventType event) {
    int count = g_handler_counts[event];
    if (count <= 1) return;

    for (int i = 1; i < count; i++) {
        EventHandler key = g_handlers[event][i];
        int j = i - 1;

        while (j >= 0 && g_handlers[event][j].priority > key.priority) {
            g_handlers[event][j + 1] = g_handlers[event][j];
            j--;
        }
        g_handlers[event][j + 1] = key;
    }
}

// ============================================================================
// Internal: Remove Handler
// ============================================================================

static int remove_handler_by_id(lua_State *L, EventType event, uint64_t handler_id) {
    for (int i = 0; i < g_handler_counts[event]; i++) {
        if (g_handlers[event][i].handler_id == handler_id) {
            // Release callback reference
            if (g_handlers[event][i].callback_ref != LUA_NOREF &&
                g_handlers[event][i].callback_ref != LUA_REFNIL) {
                luaL_unref(L, LUA_REGISTRYINDEX, g_handlers[event][i].callback_ref);
            }

            // Shift remaining handlers down using memmove (ARM64 SIMD-optimized)
            int remaining = g_handler_counts[event] - i - 1;
            if (remaining > 0) {
                memmove(&g_handlers[event][i],
                        &g_handlers[event][i + 1],
                        remaining * sizeof(EventHandler));
            }
            g_handler_counts[event]--;

            return 1;  // Found and removed
        }
    }
    return 0;  // Not found
}

// ============================================================================
// Internal: Process Deferred Unsubscriptions
// ============================================================================

static void process_deferred_unsubscribes(lua_State *L, EventType event) {
    // Process all deferred unsubscriptions for this event
    // Using swap-and-pop for O(1) removal instead of O(n) shift
    int i = 0;
    while (i < g_deferred_unsub_count) {
        if (g_deferred_unsubs[i].event == event) {
            remove_handler_by_id(L, event, g_deferred_unsubs[i].handler_id);

            // Swap with last element and pop (O(1) removal)
            g_deferred_unsubs[i] = g_deferred_unsubs[--g_deferred_unsub_count];
            // Don't increment i - check same index again (now contains swapped element)
        } else {
            i++;
        }
    }
}

// ============================================================================
// Public API: Initialize
// ============================================================================

void events_init(void) {
    if (g_initialized) return;

    // Initialize handler counts and dispatch depth
    // Note: g_handlers array doesn't need initialization - only slots up to
    // g_handler_counts[e] are ever accessed, and they're properly filled on Subscribe
    memset(g_handler_counts, 0, sizeof(g_handler_counts));
    memset(g_dispatch_depth, 0, sizeof(g_dispatch_depth));

    g_next_handler_id = 1;
    g_deferred_unsub_count = 0;
    g_initialized = 1;

    log_message("[Events] Event system initialized");
}

// ============================================================================
// Public API: Fire Event
// ============================================================================

void events_fire(lua_State *L, EventType event) {
    if (!L || event >= EVENT_MAX) return;

    int count = g_handler_counts[event];
    if (count == 0) return;

    // Log for non-Tick events (Tick is too frequent)
    if (event != EVENT_TICK) {
        log_message("[Events] Firing %s (%d handlers)", g_event_names[event], count);
    }

    g_dispatch_depth[event]++;

    for (int i = 0; i < g_handler_counts[event]; i++) {
        EventHandler *h = &g_handlers[event][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) {
            continue;
        }

        // Get callback from registry
        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (!lua_isfunction(L, -1)) {
            lua_pop(L, 1);
            continue;
        }

        // Create event data table (empty for basic events)
        lua_newtable(L);

        // Protected call to prevent cascade failures
        if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            log_message("[Events] Error in %s handler (id=%llu): %s",
                       g_event_names[event], h->handler_id, err ? err : "unknown");
            lua_pop(L, 1);
        }

        // Handle Once flag - queue for deferred removal
        if (h->once) {
            if (g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
                g_deferred_unsubs[g_deferred_unsub_count++] =
                    (DeferredUnsubscribe){event, h->handler_id};
            }
        }
    }

    g_dispatch_depth[event]--;

    // Process deferred unsubscriptions when dispatch completes
    if (g_dispatch_depth[event] == 0) {
        process_deferred_unsubscribes(L, event);
    }
}

// ============================================================================
// Public API: Fire Tick Event (with DeltaTime)
// ============================================================================

void events_fire_tick(lua_State *L, float delta_time) {
    if (!L) return;

    int count = g_handler_counts[EVENT_TICK];
    if (count == 0) return;

    g_dispatch_depth[EVENT_TICK]++;

    for (int i = 0; i < g_handler_counts[EVENT_TICK]; i++) {
        EventHandler *h = &g_handlers[EVENT_TICK][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) {
            continue;
        }

        // Get callback from registry
        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (!lua_isfunction(L, -1)) {
            lua_pop(L, 1);
            continue;
        }

        // Create event data table with DeltaTime
        lua_newtable(L);
        lua_pushnumber(L, delta_time);
        lua_setfield(L, -2, "DeltaTime");

        // Protected call
        if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            log_message("[Events] Tick handler error (id=%llu): %s",
                       h->handler_id, err ? err : "unknown");
            lua_pop(L, 1);
        }

        // Handle Once flag
        if (h->once) {
            if (g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
                g_deferred_unsubs[g_deferred_unsub_count++] =
                    (DeferredUnsubscribe){EVENT_TICK, h->handler_id};
            }
        }
    }

    g_dispatch_depth[EVENT_TICK]--;

    if (g_dispatch_depth[EVENT_TICK] == 0) {
        process_deferred_unsubscribes(L, EVENT_TICK);
    }
}

// ============================================================================
// Public API: Fire GameStateChanged Event (with FromState and ToState)
// ============================================================================

void events_fire_game_state_changed(lua_State *L, int fromState, int toState) {
    if (!L) return;

    int count = g_handler_counts[EVENT_GAME_STATE_CHANGED];
    if (count == 0) return;

    log_message("[Events] Firing GameStateChanged (from=%d, to=%d, %d handlers)",
                fromState, toState, count);

    g_dispatch_depth[EVENT_GAME_STATE_CHANGED]++;

    for (int i = 0; i < g_handler_counts[EVENT_GAME_STATE_CHANGED]; i++) {
        EventHandler *h = &g_handlers[EVENT_GAME_STATE_CHANGED][i];
        if (h->callback_ref == LUA_NOREF || h->callback_ref == LUA_REFNIL) {
            continue;
        }

        // Get callback from registry
        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (!lua_isfunction(L, -1)) {
            lua_pop(L, 1);
            continue;
        }

        // Create event data table with FromState and ToState
        lua_newtable(L);
        lua_pushinteger(L, fromState);
        lua_setfield(L, -2, "FromState");
        lua_pushinteger(L, toState);
        lua_setfield(L, -2, "ToState");

        // Protected call
        if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            log_message("[Events] GameStateChanged handler error (id=%llu): %s",
                       h->handler_id, err ? err : "unknown");
            lua_pop(L, 1);
        }

        // Handle Once flag
        if (h->once) {
            if (g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
                g_deferred_unsubs[g_deferred_unsub_count++] =
                    (DeferredUnsubscribe){EVENT_GAME_STATE_CHANGED, h->handler_id};
            }
        }
    }

    g_dispatch_depth[EVENT_GAME_STATE_CHANGED]--;

    if (g_dispatch_depth[EVENT_GAME_STATE_CHANGED] == 0) {
        process_deferred_unsubscribes(L, EVENT_GAME_STATE_CHANGED);
    }
}

// ============================================================================
// Public API: Get Handler Count
// ============================================================================

int events_get_handler_count(EventType event) {
    if (event < 0 || event >= EVENT_MAX) return 0;
    return g_handler_counts[event];
}

// ============================================================================
// Public API: Get Event Name
// ============================================================================

const char *events_get_name(EventType event) {
    if (event < 0 || event >= EVENT_MAX) return "Unknown";
    return g_event_names[event];
}

// ============================================================================
// Lua API: Subscribe
// ============================================================================

/**
 * Event:Subscribe(callback, [options])
 *
 * Options table:
 *   Priority: number (default 100, lower = called first)
 *   Once: boolean (default false, auto-unsubscribe after first call)
 *
 * Returns: handler ID (integer) for use with Unsubscribe
 */
static int lua_event_subscribe(lua_State *L) {
    // Event type from closure upvalue
    int event = (int)lua_tointeger(L, lua_upvalueindex(1));
    if (event < 0 || event >= EVENT_MAX) {
        return luaL_error(L, "Invalid event type");
    }

    // Callback is arg 2 (arg 1 is self due to colon syntax)
    luaL_checktype(L, 2, LUA_TFUNCTION);

    // Parse options (arg 3, optional table)
    int priority = DEFAULT_PRIORITY;
    int once = 0;

    if (lua_istable(L, 3)) {
        lua_getfield(L, 3, "Priority");
        if (lua_isnumber(L, -1)) {
            priority = (int)lua_tointeger(L, -1);
        }
        lua_pop(L, 1);

        lua_getfield(L, 3, "Once");
        if (lua_isboolean(L, -1)) {
            once = lua_toboolean(L, -1);
        }
        lua_pop(L, 1);
    }

    // Check handler limit
    if (g_handler_counts[event] >= MAX_EVENT_HANDLERS) {
        return luaL_error(L, "Too many handlers for event %s (max %d)",
                         g_event_names[event], MAX_EVENT_HANDLERS);
    }

    // Store callback in registry
    lua_pushvalue(L, 2);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // Allocate handler
    uint64_t handler_id = g_next_handler_id++;
    int idx = g_handler_counts[event]++;

    g_handlers[event][idx].callback_ref = ref;
    g_handlers[event][idx].priority = priority;
    g_handlers[event][idx].once = once;
    g_handlers[event][idx].handler_id = handler_id;

    // Re-sort by priority
    sort_handlers_by_priority(event);

    // Log subscription (not for Tick - too noisy)
    if (event != EVENT_TICK) {
        log_message("[Events] Subscribed to %s (id=%llu, priority=%d, once=%d)",
                   g_event_names[event], handler_id, priority, once);
    }

    // Return handler ID
    lua_pushinteger(L, (lua_Integer)handler_id);
    return 1;
}

// ============================================================================
// Lua API: Unsubscribe
// ============================================================================

/**
 * Event:Unsubscribe(handlerId)
 *
 * Returns: boolean (true if handler was found and removed)
 */
static int lua_event_unsubscribe(lua_State *L) {
    // Event type from closure upvalue
    int event = (int)lua_tointeger(L, lua_upvalueindex(1));
    if (event < 0 || event >= EVENT_MAX) {
        return luaL_error(L, "Invalid event type");
    }

    // Handler ID is arg 2 (arg 1 is self)
    uint64_t handler_id = (uint64_t)luaL_checkinteger(L, 2);

    // If currently dispatching, defer the removal
    if (g_dispatch_depth[event] > 0) {
        if (g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
            g_deferred_unsubs[g_deferred_unsub_count++] =
                (DeferredUnsubscribe){event, handler_id};
            lua_pushboolean(L, 1);  // Will be removed
        } else {
            log_message("[Events] Deferred unsubscribe queue full");
            lua_pushboolean(L, 0);
        }
        return 1;
    }

    // Immediate removal
    int found = remove_handler_by_id(L, event, handler_id);

    if (found && event != EVENT_TICK) {
        log_message("[Events] Unsubscribed from %s (id=%llu)",
                   g_event_names[event], handler_id);
    }

    lua_pushboolean(L, found);
    return 1;
}

// ============================================================================
// Lua API: OnNextTick
// ============================================================================

/**
 * Ext.OnNextTick(callback)
 *
 * Convenience function to subscribe to Tick with Once=true.
 * Returns: handler ID (can be used to cancel before it fires)
 */
static int lua_on_next_tick(lua_State *L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);

    // Check handler limit
    if (g_handler_counts[EVENT_TICK] >= MAX_EVENT_HANDLERS) {
        return luaL_error(L, "Too many Tick handlers");
    }

    // Store callback in registry
    lua_pushvalue(L, 1);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // Allocate handler with Once=true
    uint64_t handler_id = g_next_handler_id++;
    int idx = g_handler_counts[EVENT_TICK]++;

    g_handlers[EVENT_TICK][idx].callback_ref = ref;
    g_handlers[EVENT_TICK][idx].priority = DEFAULT_PRIORITY;
    g_handlers[EVENT_TICK][idx].once = 1;  // Auto-unsubscribe
    g_handlers[EVENT_TICK][idx].handler_id = handler_id;

    // Re-sort by priority
    sort_handlers_by_priority(EVENT_TICK);

    // Return handler ID
    lua_pushinteger(L, (lua_Integer)handler_id);
    return 1;
}

// ============================================================================
// Internal: Create Event Object
// ============================================================================

static void create_event_object(lua_State *L, EventType event) {
    lua_newtable(L);

    // Subscribe method with event type as upvalue
    lua_pushinteger(L, event);
    lua_pushcclosure(L, lua_event_subscribe, 1);
    lua_setfield(L, -2, "Subscribe");

    // Unsubscribe method with event type as upvalue
    lua_pushinteger(L, event);
    lua_pushcclosure(L, lua_event_unsubscribe, 1);
    lua_setfield(L, -2, "Unsubscribe");
}

// ============================================================================
// Public API: Register Lua API
// ============================================================================

void lua_events_register(lua_State *L, int ext_table_index) {
    // Initialize event system
    events_init();

    // Convert negative index to absolute
    if (ext_table_index < 0) {
        ext_table_index = lua_gettop(L) + ext_table_index + 1;
    }

    // Create Ext.Events table
    lua_newtable(L);

    // Register all events
    for (int i = 0; i < EVENT_MAX; i++) {
        create_event_object(L, i);
        lua_setfield(L, -2, g_event_names[i]);
    }

    lua_setfield(L, ext_table_index, "Events");

    // Register Ext.OnNextTick
    lua_pushcfunction(L, lua_on_next_tick);
    lua_setfield(L, ext_table_index, "OnNextTick");

    log_message("[Events] Ext.Events namespace registered with %d event types", EVENT_MAX);
}
