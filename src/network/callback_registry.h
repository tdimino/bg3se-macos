/**
 * BG3SE-macOS - Callback Registry
 *
 * Manages request/reply correlation for NetChannel API.
 * Stores Lua function references keyed by request ID.
 *
 * Issue #6: NetChannel API
 */

#ifndef CALLBACK_REGISTRY_H
#define CALLBACK_REGISTRY_H

#include <lua.h>
#include <stdint.h>
#include <stdbool.h>

// Maximum pending callbacks (requests waiting for replies)
#define MAX_PENDING_CALLBACKS 256

// Callback entry
typedef struct {
    uint64_t request_id;     // Unique request ID
    int lua_ref;             // Lua registry reference to callback function
    lua_State *owner_L;      // Lua state that owns this callback (for correct unref)
    uint64_t timestamp;      // Creation time (for timeout detection)
    bool active;             // Whether this slot is in use
} CallbackEntry;

/**
 * Initialize the callback registry.
 */
void callback_registry_init(void);

/**
 * Register a callback for a request.
 * Stores the Lua function at stack top and returns a unique request ID.
 *
 * @param L Lua state (function must be at stack top, will be popped)
 * @return Request ID (0 on failure)
 */
uint64_t callback_registry_register(lua_State *L);

/**
 * Retrieve and remove a callback by request ID.
 * Pushes the callback function onto the Lua stack.
 * IMPORTANT: If a state mismatch occurs, uses the owner state and returns it via out_L.
 *
 * @param L Lua state (may differ from owner)
 * @param request_id The request ID
 * @param out_L [out] If not NULL, receives the actual Lua state used (owner_L)
 * @return true if callback found and pushed, false otherwise
 */
bool callback_registry_retrieve(lua_State *L, uint64_t request_id, lua_State **out_L);

/**
 * Check if a callback exists for a request ID.
 *
 * @param request_id The request ID
 * @return true if callback exists
 */
bool callback_registry_exists(uint64_t request_id);

/**
 * Cancel a pending callback by request ID.
 * Releases the Lua reference without calling the callback.
 *
 * @param L Lua state
 * @param request_id The request ID
 * @return true if callback was cancelled, false if not found
 */
bool callback_registry_cancel(lua_State *L, uint64_t request_id);

/**
 * Clean up expired callbacks (older than timeout_ms).
 * Should be called periodically to prevent memory leaks.
 *
 * @param L Lua state
 * @param timeout_ms Timeout in milliseconds
 * @return Number of expired callbacks cleaned up
 */
int callback_registry_cleanup_expired(lua_State *L, uint64_t timeout_ms);

/**
 * Get count of pending callbacks.
 *
 * @return Number of active callbacks
 */
int callback_registry_count(void);

/**
 * Clean up all callbacks registered by a specific Lua state.
 * MUST be called before destroying a Lua state to prevent dangling pointers.
 *
 * @param L Lua state being destroyed
 * @return Number of callbacks cleaned up
 */
int callback_registry_cleanup_for_state(lua_State *L);

/**
 * Invoke a callback with reply payload data.
 * Retrieves the callback, parses the JSON payload, and calls the function.
 * This is a one-shot operation - the callback is removed after invocation.
 *
 * @param L Lua state
 * @param request_id The request ID to invoke callback for
 * @param payload JSON payload string (will be parsed into Lua table)
 * @param user_id Optional user ID to pass to callback (0 if none)
 * @return true if callback was found and invoked successfully
 */
bool callback_registry_invoke(lua_State *L, uint64_t request_id,
                             const char *payload, int32_t user_id);

#endif /* CALLBACK_REGISTRY_H */
