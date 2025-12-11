/**
 * BG3SE-macOS - Lifetime Scoping System Implementation
 */

#include "lifetime.h"
#include "../core/logging.h"
#include <string.h>
#include <lauxlib.h>

// Registry key for lifetime state
static const char *LIFETIME_REGISTRY_KEY = "BG3SE_LifetimeState";

// ============================================================================
// Lifetime Pool Implementation
// ============================================================================

void lifetime_pool_init(LifetimePool *pool) {
    memset(pool->entries, 0, sizeof(pool->entries));

    // Initialize free list (all entries available except index 0)
    // Index 0 is reserved for null handle
    pool->free_count = LIFETIME_POOL_SIZE - 1;
    for (uint32_t i = 0; i < pool->free_count; i++) {
        pool->free_list[i] = i + 1;  // Skip index 0
    }

    // Mark index 0 as permanently used (null sentinel)
    pool->entries[0].salt = 0;
    pool->entries[0].alive = false;
}

LifetimeHandle lifetime_pool_alloc(LifetimePool *pool) {
    if (pool->free_count == 0) {
        LOG_LUA_ERROR("Lifetime pool exhausted!");
        return LIFETIME_NULL_HANDLE;
    }

    // Pop from free list
    uint32_t index = pool->free_list[--pool->free_count];

    // Increment salt and mark alive
    Lifetime *lt = &pool->entries[index];
    lt->salt = (lt->salt + 1) & LIFETIME_SALT_MASK;
    lt->alive = true;

    return LIFETIME_MAKE_HANDLE(index, lt->salt);
}

void lifetime_pool_release(LifetimePool *pool, LifetimeHandle handle) {
    if (LIFETIME_IS_NULL(handle)) {
        return;
    }

    uint32_t index = LIFETIME_GET_INDEX(handle);
    if (index >= LIFETIME_POOL_SIZE) {
        LOG_LUA_ERROR("Invalid lifetime index: %u", index);
        return;
    }

    Lifetime *lt = &pool->entries[index];

    // Verify salt matches (not already released)
    uint64_t salt = LIFETIME_GET_SALT(handle);
    if (lt->salt != salt) {
        LOG_LUA_WARN("Lifetime salt mismatch on release: expected %llu, got %llu",
                     lt->salt, salt);
        return;
    }

    if (!lt->alive) {
        LOG_LUA_WARN("Attempting to release dead lifetime at index %u", index);
        return;
    }

    // Mark dead and return to free list
    lt->alive = false;
    pool->free_list[pool->free_count++] = index;
}

bool lifetime_pool_is_valid(LifetimePool *pool, LifetimeHandle handle) {
    if (LIFETIME_IS_NULL(handle)) {
        return false;
    }

    uint32_t index = LIFETIME_GET_INDEX(handle);
    if (index >= LIFETIME_POOL_SIZE) {
        return false;
    }

    Lifetime *lt = &pool->entries[index];
    uint64_t salt = LIFETIME_GET_SALT(handle);

    return lt->alive && (lt->salt == salt);
}

// ============================================================================
// Lifetime Stack Implementation
// ============================================================================

void lifetime_stack_init(LifetimeStack *stack) {
    stack->top = 0;
}

bool lifetime_stack_push(LifetimeStack *stack, LifetimeHandle handle) {
    if (stack->top >= LIFETIME_STACK_SIZE) {
        LOG_LUA_ERROR("Lifetime stack overflow! Nested too deep.");
        return false;
    }

    stack->stack[stack->top++] = handle;
    return true;
}

LifetimeHandle lifetime_stack_pop(LifetimeStack *stack) {
    if (stack->top <= 0) {
        LOG_LUA_ERROR("Lifetime stack underflow!");
        return LIFETIME_NULL_HANDLE;
    }

    return stack->stack[--stack->top];
}

LifetimeHandle lifetime_stack_current(LifetimeStack *stack) {
    if (stack->top <= 0) {
        return LIFETIME_NULL_HANDLE;
    }

    return stack->stack[stack->top - 1];
}

bool lifetime_stack_is_empty(LifetimeStack *stack) {
    return stack->top <= 0;
}

// ============================================================================
// Lifetime State Implementation
// ============================================================================

void lifetime_state_init(LifetimeState *state) {
    lifetime_pool_init(&state->pool);
    lifetime_stack_init(&state->stack);
    state->current = LIFETIME_NULL_HANDLE;
}

LifetimeHandle lifetime_begin_scope(LifetimeState *state) {
    // Allocate new lifetime
    LifetimeHandle handle = lifetime_pool_alloc(&state->pool);
    if (LIFETIME_IS_NULL(handle)) {
        return LIFETIME_NULL_HANDLE;
    }

    // Push onto stack and set as current
    if (!lifetime_stack_push(&state->stack, handle)) {
        lifetime_pool_release(&state->pool, handle);
        return LIFETIME_NULL_HANDLE;
    }

    state->current = handle;
    return handle;
}

void lifetime_end_scope(LifetimeState *state) {
    // Pop from stack
    LifetimeHandle handle = lifetime_stack_pop(&state->stack);
    if (LIFETIME_IS_NULL(handle)) {
        LOG_LUA_WARN("lifetime_end_scope called with empty stack");
        return;
    }

    // Release the lifetime (invalidates all userdata bound to it)
    lifetime_pool_release(&state->pool, handle);

    // Update current to new top (or null if empty)
    state->current = lifetime_stack_current(&state->stack);
}

LifetimeHandle lifetime_get_current(LifetimeState *state) {
    return state->current;
}

bool lifetime_is_valid(LifetimeState *state, LifetimeHandle handle) {
    return lifetime_pool_is_valid(&state->pool, handle);
}

// ============================================================================
// Lua Integration
// ============================================================================

LifetimeState *lifetime_get_state(lua_State *L) {
    lua_getfield(L, LUA_REGISTRYINDEX, LIFETIME_REGISTRY_KEY);
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        return NULL;
    }

    LifetimeState *state = (LifetimeState *)lua_touserdata(L, -1);
    lua_pop(L, 1);
    return state;
}

void lifetime_lua_init(lua_State *L) {
    // Allocate lifetime state as userdata in registry
    LifetimeState *state = (LifetimeState *)lua_newuserdata(L, sizeof(LifetimeState));
    lifetime_state_init(state);

    // Store in registry
    lua_setfield(L, LUA_REGISTRYINDEX, LIFETIME_REGISTRY_KEY);

    LOG_LUA_INFO("Lifetime system initialized (pool size: %d)", LIFETIME_POOL_SIZE);
}

LifetimeHandle lifetime_lua_begin_scope(lua_State *L) {
    LifetimeState *state = lifetime_get_state(L);
    if (!state) {
        LOG_LUA_ERROR("Lifetime state not initialized!");
        return LIFETIME_NULL_HANDLE;
    }

    return lifetime_begin_scope(state);
}

void lifetime_lua_end_scope(lua_State *L) {
    LifetimeState *state = lifetime_get_state(L);
    if (!state) {
        LOG_LUA_ERROR("Lifetime state not initialized!");
        return;
    }

    lifetime_end_scope(state);
}

LifetimeHandle lifetime_lua_get_current(lua_State *L) {
    LifetimeState *state = lifetime_get_state(L);
    if (!state) {
        return LIFETIME_NULL_HANDLE;
    }

    return lifetime_get_current(state);
}

bool lifetime_lua_is_valid(lua_State *L, LifetimeHandle handle) {
    LifetimeState *state = lifetime_get_state(L);
    if (!state) {
        return false;
    }

    return lifetime_is_valid(state, handle);
}

int lifetime_lua_expired_error(lua_State *L, const char *type_name) {
    return luaL_error(L, "Lifetime of %s has expired; re-fetch the object in the current scope", type_name);
}
