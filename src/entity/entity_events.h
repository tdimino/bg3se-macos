/**
 * BG3SE-macOS - Entity Component Event System
 *
 * Provides component create/destroy event subscriptions matching
 * the Windows BG3SE Ext.Entity.OnCreate/OnDestroy API.
 *
 * Architecture:
 *   - HookPool: salted pool of ComponentHook subscriptions
 *   - ComponentHooks: per-component-type hook lists (global + per-entity)
 *   - DeferredEvent queue: events delayed to next tick
 *   - Signal integration: hooks into EntityWorld->ComponentCallbacks
 *
 * Windows reference: BG3Extender/Lua/Shared/EntityComponentEvents.h/inl
 */

#ifndef ENTITY_EVENTS_H
#define ENTITY_EVENTS_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lua_State;

// ============================================================================
// Event Types and Flags (match Windows BG3SE)
// ============================================================================

// Component event types (bitmask)
#define ENTITY_EVENT_CREATE   (1 << 0)
#define ENTITY_EVENT_DESTROY  (1 << 1)

// Event subscription flags (bitmask)
#define ENTITY_EVENT_FLAG_DEFERRED  (1 << 0)
#define ENTITY_EVENT_FLAG_ONCE      (1 << 1)

// ============================================================================
// Subscription Handle
// ============================================================================

/**
 * Subscription ID returned to Lua.
 * Upper 32 bits = type tag, lower 32 bits = pool index + salt.
 * Matches Windows BG3SE LuaEntitySubscriptionId layout.
 */
typedef uint64_t EntitySubscriptionId;

// Subscription type tags (upper 32 bits)
#define SUB_TYPE_REPLICATION  1
#define SUB_TYPE_COMPONENT    2
#define SUB_TYPE_SYSTEM       3

// Build subscription ID from type tag and pool index
#define MAKE_SUB_ID(type_tag, index) \
    (((uint64_t)(type_tag) << 32) | (uint32_t)(index))

// Extract type tag from subscription ID
#define SUB_ID_TYPE(id)  ((uint32_t)((id) >> 32))

// Extract pool index from subscription ID
#define SUB_ID_INDEX(id) ((uint32_t)(id))

// Invalid subscription ID
#define ENTITY_SUB_INVALID ((EntitySubscriptionId)0)

// ============================================================================
// Public API
// ============================================================================

/**
 * Initialize the entity event system.
 * Allocates the hook pool and per-type arrays.
 * Call once during startup.
 */
void entity_events_init(void);

/**
 * Bind to an EntityWorld.
 * Attempts to find ComponentCallbackRegistry and install signal hooks.
 * Call when EntityWorld is captured (after session load).
 *
 * @param entity_world Pointer to EntityWorld
 * @param is_server    true for server world, false for client
 */
void entity_events_bind(void *entity_world, bool is_server);

/**
 * Subscribe to component create/destroy events.
 *
 * @param component_type_index ECS ComponentTypeIndex
 * @param entity_handle Specific entity (0 = global, all entities of this type)
 * @param events Bitmask: ENTITY_EVENT_CREATE | ENTITY_EVENT_DESTROY
 * @param flags  Bitmask: ENTITY_EVENT_FLAG_DEFERRED | ENTITY_EVENT_FLAG_ONCE
 * @param lua_callback_ref luaL_ref reference to the Lua callback function
 * @param L Lua state that owns the callback
 * @return Subscription ID, or ENTITY_SUB_INVALID on failure
 */
EntitySubscriptionId entity_events_subscribe(
    uint16_t component_type_index,
    uint64_t entity_handle,
    uint32_t events,
    uint32_t flags,
    int lua_callback_ref,
    struct lua_State *L
);

/**
 * Unsubscribe from component events.
 *
 * @param id Subscription ID returned by entity_events_subscribe
 * @param L Lua state (for releasing the callback reference)
 * @return true if subscription was found and removed
 */
bool entity_events_unsubscribe(EntitySubscriptionId id, struct lua_State *L);

/**
 * Fire deferred events.
 * Processes all queued deferred events and deferred unsubscriptions.
 * Call once per tick from the game loop.
 *
 * @param L Lua state for callback invocation
 */
void entity_events_fire_deferred(struct lua_State *L);

/**
 * Notify the event system of a component creation.
 * Called from Signal hooks or ECB scanning.
 *
 * @param type_index Component type that was created
 * @param entity_handle Entity that received the component
 * @param component Pointer to the created component data (may be NULL for deferred)
 * @param L Lua state
 */
void entity_events_on_create(uint16_t type_index, uint64_t entity_handle,
                              void *component, struct lua_State *L);

/**
 * Notify the event system of a component destruction.
 * Called from Signal hooks or ECB scanning.
 *
 * @param type_index Component type that was destroyed
 * @param entity_handle Entity that lost the component
 * @param component Pointer to the component data being destroyed (may be NULL)
 * @param L Lua state
 */
void entity_events_on_destroy(uint16_t type_index, uint64_t entity_handle,
                               void *component, struct lua_State *L);

/**
 * Cleanup all subscriptions.
 * Releases all Lua callback references and frees memory.
 * Call when Lua state is being shut down or reset.
 *
 * @param L Lua state
 */
void entity_events_cleanup(struct lua_State *L);

/**
 * Get the number of active subscriptions.
 * Useful for diagnostics.
 */
int entity_events_subscription_count(void);

/**
 * Check if the event system is bound to an EntityWorld
 * and has Signal hooks installed.
 */
bool entity_events_is_bound(void);

/**
 * Set/clear the transition guard.
 * When set, signal handlers return immediately without dispatching events.
 * Call with true before game state transitions (new game, load save)
 * and false after transition completes (e.g., in entity_on_session_loaded).
 */
void entity_events_set_transition(bool in_transition);

/**
 * Register Ext.Entity event functions with Lua state.
 * Replaces stub implementations with real C functions.
 */
void entity_events_register_lua(struct lua_State *L);

#ifdef __cplusplus
}
#endif

#endif // ENTITY_EVENTS_H
