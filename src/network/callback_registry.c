/**
 * BG3SE-macOS - Callback Registry Implementation
 *
 * Manages request/reply correlation for NetChannel API.
 * Uses Lua registry (luaL_ref) to store callback functions.
 *
 * Issue #6: NetChannel API
 */

#include "callback_registry.h"
#include "../core/logging.h"
#include "../lua/lua_json.h"
#include <lauxlib.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>  // arc4random_buf

// ============================================================================
// Static State
// ============================================================================

static CallbackEntry s_callbacks[MAX_PENDING_CALLBACKS];
static bool s_initialized = false;

// Generate cryptographically random request ID (security fix per review)
static uint64_t generate_random_request_id(void) {
    uint64_t id;
    arc4random_buf(&id, sizeof(id));
    // Ensure non-zero (0 is used as "no callback")
    if (id == 0) id = 1;
    return id;
}

// ============================================================================
// Time Utilities
// ============================================================================

static uint64_t get_current_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

// ============================================================================
// Public API
// ============================================================================

void callback_registry_init(void) {
    if (s_initialized) return;

    memset(s_callbacks, 0, sizeof(s_callbacks));
    s_initialized = true;

    LOG_NET_DEBUG("Callback registry initialized (using crypto-random request IDs)");
}

uint64_t callback_registry_register(lua_State *L) {
    if (!s_initialized) {
        callback_registry_init();
    }

    // Verify there's a function at stack top
    if (!lua_isfunction(L, -1)) {
        LOG_NET_ERROR("callback_registry_register: expected function at stack top");
        lua_pop(L, 1);  // Pop the non-function to maintain stack balance
        return 0;
    }

    // Find free slot
    int slot = -1;
    for (int i = 0; i < MAX_PENDING_CALLBACKS; i++) {
        if (!s_callbacks[i].active) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        LOG_NET_ERROR("Callback registry full (%d callbacks)", MAX_PENDING_CALLBACKS);
        lua_pop(L, 1);  // Pop the function
        return 0;
    }

    // Store function in Lua registry
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);
    if (ref == LUA_REFNIL || ref == LUA_NOREF) {
        LOG_NET_ERROR("Failed to store callback in Lua registry");
        return 0;
    }

    // Assign cryptographically random request ID (prevents spoofing in multiplayer)
    uint64_t request_id = generate_random_request_id();

    s_callbacks[slot].request_id = request_id;
    s_callbacks[slot].lua_ref = ref;
    s_callbacks[slot].owner_L = L;  // Track owning Lua state
    s_callbacks[slot].timestamp = get_current_time_ms();
    s_callbacks[slot].active = true;

    LOG_NET_DEBUG("Registered callback: request_id=%llu, slot=%d, ref=%d, owner=%p",
                (unsigned long long)request_id, slot, ref, (void*)L);

    return request_id;
}

bool callback_registry_retrieve(lua_State *L, uint64_t request_id, lua_State **out_L) {
    for (int i = 0; i < MAX_PENDING_CALLBACKS; i++) {
        if (s_callbacks[i].active && s_callbacks[i].request_id == request_id) {
            // Use the owner state - this is critical for correct stack operations
            lua_State *actual_L = s_callbacks[i].owner_L;
            if (actual_L != L) {
                LOG_NET_WARN("Callback retrieve: state mismatch (registered=%p, requesting=%p), using owner",
                            (void*)actual_L, (void*)L);
            }

            // Return the actual state to caller so they use the correct one
            if (out_L) {
                *out_L = actual_L;
            }

            // Push callback function onto the owner's stack
            lua_rawgeti(actual_L, LUA_REGISTRYINDEX, s_callbacks[i].lua_ref);

            // Release the reference (one-shot callback)
            luaL_unref(actual_L, LUA_REGISTRYINDEX, s_callbacks[i].lua_ref);

            // Clear slot
            s_callbacks[i].active = false;
            s_callbacks[i].request_id = 0;
            s_callbacks[i].lua_ref = LUA_NOREF;
            s_callbacks[i].owner_L = NULL;

            LOG_NET_DEBUG("Retrieved callback: request_id=%llu (actual_L=%p)",
                        (unsigned long long)request_id, (void*)actual_L);

            return true;
        }
    }

    LOG_NET_WARN("Callback not found: request_id=%llu",
                (unsigned long long)request_id);
    return false;
}

bool callback_registry_exists(uint64_t request_id) {
    for (int i = 0; i < MAX_PENDING_CALLBACKS; i++) {
        if (s_callbacks[i].active && s_callbacks[i].request_id == request_id) {
            return true;
        }
    }
    return false;
}

bool callback_registry_cancel(lua_State *L, uint64_t request_id) {
    (void)L;  // L is unused - we use the owner state instead
    for (int i = 0; i < MAX_PENDING_CALLBACKS; i++) {
        if (s_callbacks[i].active && s_callbacks[i].request_id == request_id) {
            // Use the owner Lua state for unref (not the passed-in L)
            lua_State *owner = s_callbacks[i].owner_L;
            if (owner) {
                luaL_unref(owner, LUA_REGISTRYINDEX, s_callbacks[i].lua_ref);
            }

            // Clear slot
            s_callbacks[i].active = false;
            s_callbacks[i].request_id = 0;
            s_callbacks[i].lua_ref = LUA_NOREF;
            s_callbacks[i].owner_L = NULL;

            LOG_NET_DEBUG("Cancelled callback: request_id=%llu",
                        (unsigned long long)request_id);

            return true;
        }
    }
    return false;
}

int callback_registry_cleanup_expired(lua_State *L, uint64_t timeout_ms) {
    (void)L;  // L is unused now - we use the owner state instead
    uint64_t now = get_current_time_ms();
    int cleaned = 0;

    for (int i = 0; i < MAX_PENDING_CALLBACKS; i++) {
        if (s_callbacks[i].active) {
            uint64_t age = now - s_callbacks[i].timestamp;
            if (age > timeout_ms) {
                // Use the owner Lua state for unref (critical for cross-state safety)
                lua_State *owner = s_callbacks[i].owner_L;
                if (owner) {
                    luaL_unref(owner, LUA_REGISTRYINDEX, s_callbacks[i].lua_ref);
                }

                LOG_NET_WARN("Expired callback: request_id=%llu, age=%llums",
                            (unsigned long long)s_callbacks[i].request_id,
                            (unsigned long long)age);

                // Clear slot
                s_callbacks[i].active = false;
                s_callbacks[i].request_id = 0;
                s_callbacks[i].lua_ref = LUA_NOREF;
                s_callbacks[i].owner_L = NULL;

                cleaned++;
            }
        }
    }

    if (cleaned > 0) {
        LOG_NET_DEBUG("Cleaned up %d expired callbacks", cleaned);
    }

    return cleaned;
}

int callback_registry_count(void) {
    int count = 0;
    for (int i = 0; i < MAX_PENDING_CALLBACKS; i++) {
        if (s_callbacks[i].active) {
            count++;
        }
    }
    return count;
}

int callback_registry_cleanup_for_state(lua_State *L) {
    if (!L) return 0;

    int cleaned = 0;
    for (int i = 0; i < MAX_PENDING_CALLBACKS; i++) {
        if (s_callbacks[i].active && s_callbacks[i].owner_L == L) {
            // Release the Lua reference
            luaL_unref(L, LUA_REGISTRYINDEX, s_callbacks[i].lua_ref);

            LOG_NET_DEBUG("Cleaning up callback for destroyed state: request_id=%llu",
                         (unsigned long long)s_callbacks[i].request_id);

            // Clear slot
            s_callbacks[i].active = false;
            s_callbacks[i].request_id = 0;
            s_callbacks[i].lua_ref = LUA_NOREF;
            s_callbacks[i].owner_L = NULL;

            cleaned++;
        }
    }

    if (cleaned > 0) {
        LOG_NET_INFO("Cleaned up %d callbacks for destroyed Lua state %p", cleaned, (void*)L);
    }

    return cleaned;
}

bool callback_registry_invoke(lua_State *L, uint64_t request_id,
                             const char *payload, int32_t user_id) {
    if (!L || request_id == 0) {
        return false;
    }

    // Retrieve pushes the callback function onto stack and returns the actual state used
    lua_State *actual_L = L;
    if (!callback_registry_retrieve(L, request_id, &actual_L)) {
        LOG_NET_DEBUG("No callback found for request_id=%llu",
                     (unsigned long long)request_id);
        return false;
    }

    // CRITICAL: Use actual_L for all subsequent operations
    // The callback function is now on actual_L's stack
    L = actual_L;

    // Record stack top for cleanup on error
    int stack_top = lua_gettop(L);  // Should be N+1 where N was previous top

    // Stack: [callback_function]

    // Push the raw payload string (Lua wrapper handles JSON parsing)
    // This matches Windows BG3SE behavior where callbacks receive raw payloads
    int nargs = 0;
    if (payload && payload[0] != '\0') {
        lua_pushstring(L, payload);
        nargs = 1;
    } else {
        // No payload - push empty string
        lua_pushstring(L, "{}");
        nargs = 1;
    }

    // Stack: [callback_function, payload_string]

    // Push binary flag as second argument (false for JSON payloads)
    lua_pushboolean(L, 0);  // binary = false
    nargs = 2;

    // Call the callback
    int result = lua_pcall(L, nargs, 0, 0);
    if (result != LUA_OK) {
        const char *err = lua_tostring(L, -1);
        LOG_NET_ERROR("Callback invocation failed for request_id=%llu: %s",
                     (unsigned long long)request_id,
                     err ? err : "unknown error");
        lua_pop(L, 1);  // Pop error message
        return false;
    }

    LOG_NET_DEBUG("Invoked callback for request_id=%llu successfully",
                 (unsigned long long)request_id);

    return true;
}
