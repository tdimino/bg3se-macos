/**
 * BG3SE-macOS - Lifetime Scoping System
 *
 * Prevents access to stale/destroyed game objects by binding userdata
 * to "lifetime scopes". When a scope ends (callback returns), all
 * userdata created within that scope become invalid.
 *
 * Based on Windows BG3SE's LuaLifetime.h implementation.
 */

#ifndef BG3SE_LIFETIME_H
#define BG3SE_LIFETIME_H

#include <stdint.h>
#include <stdbool.h>
#include <lua.h>

// ============================================================================
// Constants
// ============================================================================

#define LIFETIME_POOL_SIZE 4096      // Max concurrent lifetimes
#define LIFETIME_STACK_SIZE 256      // Max scope nesting depth

// Bit layout for LifetimeHandle (48-bit handle)
#define LIFETIME_INDEX_BITS 12       // 4096 pool entries
#define LIFETIME_SALT_BITS 36        // Salt for reuse detection
#define LIFETIME_INDEX_MASK ((1ULL << LIFETIME_INDEX_BITS) - 1)
#define LIFETIME_SALT_MASK ((1ULL << LIFETIME_SALT_BITS) - 1)

// Special handle value
#define LIFETIME_NULL_HANDLE 0ULL

// ============================================================================
// Types
// ============================================================================

/**
 * Lifetime handle - opaque reference to a lifetime scope.
 * Contains index (for pool lookup) + salt (for staleness detection).
 */
typedef uint64_t LifetimeHandle;

/**
 * Lifetime entry in the pool.
 */
typedef struct {
    uint64_t salt;      // Incremented each time this slot is reused
    bool alive;         // Currently active?
} Lifetime;

/**
 * Pool of lifetime objects with fast alloc/free.
 */
typedef struct {
    Lifetime entries[LIFETIME_POOL_SIZE];
    uint32_t free_list[LIFETIME_POOL_SIZE];
    uint32_t free_count;
} LifetimePool;

/**
 * Stack of active lifetime scopes.
 */
typedef struct {
    LifetimeHandle stack[LIFETIME_STACK_SIZE];
    int top;
} LifetimeStack;

/**
 * Combined lifetime state attached to Lua state.
 */
typedef struct {
    LifetimePool pool;
    LifetimeStack stack;
    LifetimeHandle current;  // Current scope's lifetime
} LifetimeState;

// ============================================================================
// Lifetime Pool API
// ============================================================================

/**
 * Initialize a lifetime pool.
 */
void lifetime_pool_init(LifetimePool *pool);

/**
 * Allocate a new lifetime from the pool.
 * Returns LIFETIME_NULL_HANDLE if pool is exhausted.
 */
LifetimeHandle lifetime_pool_alloc(LifetimePool *pool);

/**
 * Release a lifetime back to the pool.
 * The lifetime handle becomes invalid.
 */
void lifetime_pool_release(LifetimePool *pool, LifetimeHandle handle);

/**
 * Check if a lifetime handle is still valid.
 */
bool lifetime_pool_is_valid(LifetimePool *pool, LifetimeHandle handle);

// ============================================================================
// Lifetime Stack API
// ============================================================================

/**
 * Initialize a lifetime stack.
 */
void lifetime_stack_init(LifetimeStack *stack);

/**
 * Push a lifetime onto the stack.
 * Returns false if stack is full.
 */
bool lifetime_stack_push(LifetimeStack *stack, LifetimeHandle handle);

/**
 * Pop and return the top lifetime from the stack.
 * Returns LIFETIME_NULL_HANDLE if stack is empty.
 */
LifetimeHandle lifetime_stack_pop(LifetimeStack *stack);

/**
 * Get the current (top) lifetime without removing it.
 * Returns LIFETIME_NULL_HANDLE if stack is empty.
 */
LifetimeHandle lifetime_stack_current(LifetimeStack *stack);

/**
 * Check if the stack is empty.
 */
bool lifetime_stack_is_empty(LifetimeStack *stack);

// ============================================================================
// Lifetime State API (combines pool + stack)
// ============================================================================

/**
 * Initialize lifetime state.
 */
void lifetime_state_init(LifetimeState *state);

/**
 * Begin a new lifetime scope.
 * Call before invoking Lua callbacks.
 * Returns the new scope's lifetime handle.
 */
LifetimeHandle lifetime_begin_scope(LifetimeState *state);

/**
 * End the current lifetime scope.
 * All userdata created in this scope become invalid.
 * Call after Lua callback returns.
 */
void lifetime_end_scope(LifetimeState *state);

/**
 * Get the current scope's lifetime handle.
 */
LifetimeHandle lifetime_get_current(LifetimeState *state);

/**
 * Check if a lifetime handle is still valid.
 */
bool lifetime_is_valid(LifetimeState *state, LifetimeHandle handle);

// ============================================================================
// Lua Integration
// ============================================================================

/**
 * Get the lifetime state from a Lua state.
 * Stored in registry.
 */
LifetimeState *lifetime_get_state(lua_State *L);

/**
 * Initialize lifetime system for a Lua state.
 * Call once during Lua state creation.
 */
void lifetime_lua_init(lua_State *L);

/**
 * Begin a lifetime scope for Lua callbacks.
 * Returns the new scope's lifetime handle.
 */
LifetimeHandle lifetime_lua_begin_scope(lua_State *L);

/**
 * End the current lifetime scope.
 */
void lifetime_lua_end_scope(lua_State *L);

/**
 * Get the current lifetime handle for binding to userdata.
 */
LifetimeHandle lifetime_lua_get_current(lua_State *L);

/**
 * Check if a lifetime handle is valid in this Lua state.
 * Use this before accessing userdata.
 */
bool lifetime_lua_is_valid(lua_State *L, LifetimeHandle handle);

/**
 * Raise a Lua error for accessing an expired lifetime.
 * Does not return.
 */
int lifetime_lua_expired_error(lua_State *L, const char *type_name);

// ============================================================================
// Helper Macros
// ============================================================================

/**
 * Create a lifetime handle from index and salt.
 */
#define LIFETIME_MAKE_HANDLE(index, salt) \
    (((uint64_t)(index) & LIFETIME_INDEX_MASK) | \
     (((uint64_t)(salt) & LIFETIME_SALT_MASK) << LIFETIME_INDEX_BITS))

/**
 * Extract index from lifetime handle.
 */
#define LIFETIME_GET_INDEX(handle) \
    ((uint32_t)((handle) & LIFETIME_INDEX_MASK))

/**
 * Extract salt from lifetime handle.
 */
#define LIFETIME_GET_SALT(handle) \
    ((uint64_t)(((handle) >> LIFETIME_INDEX_BITS) & LIFETIME_SALT_MASK))

/**
 * Check if a handle is null.
 */
#define LIFETIME_IS_NULL(handle) \
    ((handle) == LIFETIME_NULL_HANDLE)

#endif // BG3SE_LIFETIME_H
