/**
 * BG3SE-macOS - Entity Component Event System
 *
 * C implementation of the Windows BG3SE EntityComponentEventHooks system.
 * Manages subscriptions to component create/destroy events and dispatches
 * callbacks to Lua handlers.
 *
 * The event system has two layers:
 * 1. Subscription management (this file) - always works
 * 2. Signal integration (entity_events_bind) - requires RE'd offsets
 *
 * Without Signal integration, events must be pumped manually via
 * entity_events_on_create/on_destroy from hooked game functions.
 */

#include "entity_events.h"
#include "component_registry.h"
#include "../core/logging.h"

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "../core/safe_memory.h"
#include "../core/version_detect.h"

// ============================================================================
// Configuration
// ============================================================================

#define MAX_SUBSCRIPTIONS     256   // Max concurrent subscriptions
#define MAX_DEFERRED_EVENTS   2048  // Max queued deferred events per tick (was 512, increased for heavy combat)
#define MAX_COMPONENT_HOOKS   2048  // Max component types we can hook
#define MAX_ENTITY_HOOKS_PER_TYPE 32 // Max per-entity hooks per component type
#define MAX_GLOBAL_HOOKS_PER_TYPE 64 // Max global hooks per component type

// ============================================================================
// CCR (ComponentCallbackRegistry) Layout — Runtime Verified 2026-02-07
// ============================================================================
//
// EntityWorld + 0x240 = Array<ComponentCallbacks*> (inline)
//   +0x00: buf_      (ptr to array of ComponentCallbacks*)
//   +0x08: capacity_ (uint32)
//   +0x0C: size_     (uint32, ~2709 entries)
//
// ComponentCallbacks (56 bytes):
//   +0x00: VMT              (8B)
//   +0x08: OnConstruct      (Signal<EntityRef, void*>, 24B)
//   +0x20: OnDestroy        (Signal<EntityRef, void*>, 24B)
//
// EntityRef (16 bytes, passed by value on ARM64 in two registers):
//   +0x00: Handle           (EntityHandle, uint64)
//   +0x08: World            (EntityWorld*, ptr)
//
// Signal (24 bytes):
//   +0x00: NextRegistrantId (uint64)
//   +0x08: Connections.buf_ (ptr to Connection[])
//   +0x10: Connections.capacity_ (uint32)
//   +0x14: Connections.size_ (uint32)
//
// Connection (72 bytes):
//   +0x00: Handler.pStorage_        (ptr → self + 0x08)
//   +0x08: Handler.storage_.call_   (fn ptr: call_(storage*, EntityRef, void*))
//          ARM64 ABI: call_(x0=storage*, x1=Handle, x2=World*, x3=component*)
//   +0x10: Handler.storage_.copy_   (fn ptr: copy_(dst_storage*, src_storage*))
//   +0x18: Handler.storage_.move_   (fn ptr: move_(dst_storage*, src_storage*))
//   +0x20: Handler.storage_.data_[0] (uintptr_t — we store type_index here)
//   +0x28: Handler.storage_.data_[1] (uintptr_t)
//   +0x30: Handler.storage_.data_[2] (uintptr_t)
//   +0x38: Handler.storage_.data_[3] (uintptr_t)
//   +0x40: RegistrantIndex          (uint64)

#define ENTITYWORLD_CCR_OFFSET    0x240
#define CCR_BUF_OFFSET            (ENTITYWORLD_CCR_OFFSET + 0x00)
#define CCR_SIZE_OFFSET           (ENTITYWORLD_CCR_OFFSET + 0x0C)

#define CB_ONCONSTRUCT_OFFSET     0x08
#define CB_ONDESTROY_OFFSET       0x20

#define SIGNAL_NEXTID_OFFSET      0x00
#define SIGNAL_BUF_OFFSET         0x08
#define SIGNAL_CAP_OFFSET         0x10
#define SIGNAL_SIZE_OFFSET        0x14

#define CONNECTION_SIZE           72

#define SIGNAL_HOOK_NONE          UINT64_MAX

/**
 * Per-type signal hook tracking.
 */
typedef struct {
    uint64_t construct_registrant;  // SIGNAL_HOOK_NONE = not installed
    uint64_t destroy_registrant;    // SIGNAL_HOOK_NONE = not installed
} SignalHookInfo;

// ============================================================================
// Internal Data Structures
// ============================================================================

/**
 * A single subscription (slot in the pool).
 * Matches Windows BG3SE ComponentHook.
 */
typedef struct {
    uint32_t events;            // ENTITY_EVENT_CREATE | DESTROY
    uint32_t flags;             // DEFERRED | ONCE
    uint16_t type_index;        // ComponentTypeIndex
    uint64_t entity;            // EntityHandle (0 = global)
    int lua_ref;                // luaL_ref registry reference
    uint16_t salt;              // Salt for safe handle reuse (matches packed format)
    bool active;                // false when freed
} ComponentHook;

/**
 * Per-entity hook entry within a ComponentHooks.
 */
typedef struct {
    uint64_t entity;
    uint32_t indices[MAX_ENTITY_HOOKS_PER_TYPE];
    int count;
} EntityHookEntry;

/**
 * Per-component-type hook tracking.
 * Matches Windows BG3SE ComponentHooks.
 */
typedef struct {
    uint32_t events;                                    // Combined event mask
    uint32_t global_hooks[MAX_GLOBAL_HOOKS_PER_TYPE];   // Global subscription indices
    int global_hook_count;
    EntityHookEntry entity_hooks[MAX_ENTITY_HOOKS_PER_TYPE]; // Per-entity subscriptions
    int entity_hook_count;
    bool installed;                                     // Signal hooks installed?
} ComponentHooks;

/**
 * Deferred event (queued for next tick).
 */
typedef struct {
    uint64_t entity;
    uint16_t type_index;
    uint32_t event;             // ENTITY_EVENT_CREATE or DESTROY
    uint32_t sub_index;         // Subscription pool index
} DeferredEvent;

// ============================================================================
// Static State
// ============================================================================

// Subscription pool
static ComponentHook g_hooks[MAX_SUBSCRIPTIONS];
static uint32_t g_hook_salts[MAX_SUBSCRIPTIONS];
static int g_hook_count = 0;
static uint16_t g_next_salt = 1;

// Per-component-type tracking (sparse - indexed by ComponentTypeIndex)
static ComponentHooks *g_component_hooks = NULL;  // Dynamically allocated
static uint8_t *g_hooked_mask = NULL;             // Bitmask: which types have hooks
static int g_hooked_capacity = 0;

// Deferred event queue
static DeferredEvent g_deferred[MAX_DEFERRED_EVENTS];
static int g_deferred_count = 0;

// Deferred unsubscription queue
static uint32_t g_deferred_unsubs[MAX_SUBSCRIPTIONS];
static int g_deferred_unsub_count = 0;

// Bound EntityWorld
static void *g_bound_world = NULL;
static bool g_is_server = false;
static bool g_initialized = false;

// Signal hook tracking (indexed by ComponentTypeIndex)
static SignalHookInfo *g_signal_hooks = NULL;
static int g_signal_hooks_capacity = 0;

// Thread-safe Lua state access — signal handlers fire on ServerWorker thread
// while main thread manages state lifecycle. Use acquire/release ordering.
static _Atomic(lua_State *) g_lua_state = NULL;

// Transition guard — set during game state transitions (new game, load save)
// to prevent signal handlers from dispatching while state is unstable
static _Atomic(bool) g_in_transition = false;

// Deferred free list for old connection buffers. When inject_connection()
// grows a Signal's Connections array, the old buffer can't be freed immediately
// because ServerWorker may be iterating it. Instead, push to this list and
// free on the next main-thread tick.
#define MAX_DEFERRED_FREES 256
static void *g_deferred_frees[MAX_DEFERRED_FREES];
static int g_deferred_free_count = 0;

// ============================================================================
// Pool Management
// ============================================================================

/**
 * Allocate a subscription slot.
 * Returns pool index, or -1 if full.
 */
static int pool_alloc(void) {
    for (int i = 0; i < MAX_SUBSCRIPTIONS; i++) {
        if (!g_hooks[i].active) {
            g_hooks[i].active = true;
            g_hooks[i].salt = g_next_salt++;
            g_hook_salts[i] = g_hooks[i].salt;
            g_hook_count++;
            return i;
        }
    }
    return -1;
}

/**
 * Free a subscription slot.
 */
static void pool_free(int index) {
    if (index < 0 || index >= MAX_SUBSCRIPTIONS) return;
    if (!g_hooks[index].active) return;
    g_hooks[index].active = false;
    g_hook_count--;
}

/**
 * Validate a pool index + salt pair.
 */
static bool pool_validate(uint32_t packed) {
    // packed = salt << 16 | index (for the lower 32 bits of subscription ID)
    uint16_t index = packed & 0xFFFF;
    uint16_t salt = (packed >> 16) & 0xFFFF;
    if (index >= MAX_SUBSCRIPTIONS) return false;
    if (!g_hooks[index].active) return false;
    return g_hooks[index].salt == salt;
}

static uint32_t pool_pack(int index) {
    return ((g_hooks[index].salt & 0xFFFF) << 16) | (index & 0xFFFF);
}

static int pool_unpack_index(uint32_t packed) {
    return packed & 0xFFFF;
}

// ============================================================================
// Component Hooks Management
// ============================================================================

/**
 * Ensure the hooked_mask and component_hooks arrays are large enough.
 */
static bool ensure_hooks_capacity(uint16_t type_index) {
    if (type_index == COMPONENT_INDEX_UNDEFINED) return false;

    int needed = (int)type_index + 1;
    if (needed <= g_hooked_capacity) return true;

    // Grow to next power of 2
    int new_cap = g_hooked_capacity ? g_hooked_capacity : 256;
    while (new_cap < needed) new_cap *= 2;
    if (new_cap > MAX_COMPONENT_HOOKS) new_cap = MAX_COMPONENT_HOOKS;
    if (needed > new_cap) return false;

    ComponentHooks *new_hooks = realloc(g_component_hooks,
                                         new_cap * sizeof(ComponentHooks));
    uint8_t *new_mask = realloc(g_hooked_mask, (new_cap + 7) / 8);
    if (!new_hooks || !new_mask) return false;

    // Zero-initialize new entries
    memset(new_hooks + g_hooked_capacity, 0,
           (new_cap - g_hooked_capacity) * sizeof(ComponentHooks));
    if (g_hooked_capacity == 0) {
        memset(new_mask, 0, (new_cap + 7) / 8);
    } else {
        memset(new_mask + (g_hooked_capacity + 7) / 8, 0,
               (new_cap + 7) / 8 - (g_hooked_capacity + 7) / 8);
    }

    g_component_hooks = new_hooks;
    g_hooked_mask = new_mask;
    g_hooked_capacity = new_cap;
    return true;
}

static bool is_type_hooked(uint16_t type_index) {
    if (type_index >= g_hooked_capacity) return false;
    return (g_hooked_mask[type_index / 8] & (1 << (type_index % 8))) != 0;
}

static void set_type_hooked(uint16_t type_index) {
    g_hooked_mask[type_index / 8] |= (1 << (type_index % 8));
}

/**
 * Get or create the ComponentHooks entry for a type.
 */
static ComponentHooks *get_or_create_component_hooks(uint16_t type_index) {
    if (!ensure_hooks_capacity(type_index)) return NULL;

    if (!is_type_hooked(type_index)) {
        set_type_hooked(type_index);
        memset(&g_component_hooks[type_index], 0, sizeof(ComponentHooks));
    }

    return &g_component_hooks[type_index];
}

// ============================================================================
// Signal Integration — Connection Injection into Game's CCR
// ============================================================================

// Forward declarations for handlers
// EntityRef (16B) is passed by value on ARM64: Handle in x1, World* in x2, component in x3
static void signal_construct_handler(void *self_storage, uint64_t entity_handle, void *entity_world, void *component);
static void signal_destroy_handler(void *self_storage, uint64_t entity_handle, void *entity_world, void *component);

/**
 * Ensure signal hooks array is large enough for type_index.
 */
static bool ensure_signal_hooks_capacity(uint16_t type_index) {
    int needed = (int)type_index + 1;
    if (needed <= g_signal_hooks_capacity) return true;

    int new_cap = g_signal_hooks_capacity ? g_signal_hooks_capacity : 256;
    while (new_cap < needed) new_cap *= 2;
    if (new_cap > MAX_COMPONENT_HOOKS) new_cap = MAX_COMPONENT_HOOKS;
    if (needed > new_cap) return false;

    SignalHookInfo *new_hooks = realloc(g_signal_hooks, new_cap * sizeof(SignalHookInfo));
    if (!new_hooks) return false;

    for (int i = g_signal_hooks_capacity; i < new_cap; i++) {
        new_hooks[i].construct_registrant = SIGNAL_HOOK_NONE;
        new_hooks[i].destroy_registrant = SIGNAL_HOOK_NONE;
    }

    g_signal_hooks = new_hooks;
    g_signal_hooks_capacity = new_cap;
    return true;
}

// --- FunctionStorage copy/move procs ---
// Called by game when reallocating Signal::Connections array.
// The game's Array<Connection> uses C++ move construction during reallocation.
// These procs receive (dst_FunctionStorage*, src_FunctionStorage*) and must
// copy all 56 bytes (call_ + copy_ + move_ + data_[4]).
// The caller (Function::MoveFrom) handles pStorage_ fixup afterward.

static void signal_storage_copy(void *dst, const void *src) {
    memcpy(dst, src, 56);
}

static void signal_storage_move(void *dst, void *src) {
    memcpy(dst, src, 56);
}

// --- Signal handlers ---
// Called by game's Signal::Invoke during AddComponent/RemoveComponent.
//
// The game's signal is Signal<EntityRef, void*> where EntityRef is 16 bytes
// (Handle + World*). On ARM64, EntityRef is passed by value in two registers:
//   X0 = FunctionStorage* (self/pStorage_)
//   X1 = EntityRef.Handle  (uint64 entity handle — NOT a pointer!)
//   X2 = EntityRef.World*  (EntityWorld pointer — we don't need this)
//   X3 = void*             (component data pointer)
//
// Confirmed by game's own handler symbol:
//   OnComponentRemoved(ecs::EntityRef, eoc::HealthComponent&)
// and crash registers: x1=handle_value, x2=world_ptr, x3=component_ptr

static void signal_construct_handler(void *self_storage, uint64_t entity_handle,
                                      void *entity_world, void *component) {
    (void)entity_world;  // EntityRef.World — not needed for dispatch
    // Atomic load with acquire ordering — ensures we see the latest state
    // written by the main thread. Local copy prevents TOCTOU race.
    lua_State *L = atomic_load_explicit(&g_lua_state, memory_order_acquire);
    if (!entity_handle || !L) return;
    if (atomic_load_explicit(&g_in_transition, memory_order_acquire)) return;
    // data_[0] at FunctionStorage + 0x18 contains our type_index
    uint16_t type_index = (uint16_t)(*(uintptr_t*)((char*)self_storage + 0x18));
    entity_events_on_create(type_index, entity_handle, component, L);
}

static void signal_destroy_handler(void *self_storage, uint64_t entity_handle,
                                    void *entity_world, void *component) {
    (void)entity_world;  // EntityRef.World — not needed for dispatch
    lua_State *L = atomic_load_explicit(&g_lua_state, memory_order_acquire);
    if (!entity_handle || !L) return;
    if (atomic_load_explicit(&g_in_transition, memory_order_acquire)) return;
    uint16_t type_index = (uint16_t)(*(uintptr_t*)((char*)self_storage + 0x18));
    entity_events_on_destroy(type_index, entity_handle, component, L);
}

/**
 * Write a 72-byte Connection struct at the given address.
 * Sets up the self-referential pStorage_, our handler as call_,
 * copy/move stubs, type_index in data_[0], and registrant ID.
 */
static void write_connection(void *addr,
                              void (*handler)(void*, uint64_t, void*, void*),
                              uint16_t type_index, uint64_t registrant_id) {
    uint8_t conn[CONNECTION_SIZE];
    memset(conn, 0, CONNECTION_SIZE);

    // pStorage_ at +0x00 → points to storage_ at addr + 0x08
    *(void**)&conn[0x00] = (void*)((uintptr_t)addr + 0x08);
    // storage_.call_ at +0x08
    *(void**)&conn[0x08] = (void*)handler;
    // storage_.copy_ at +0x10
    *(void**)&conn[0x10] = (void*)signal_storage_copy;
    // storage_.move_ at +0x18
    *(void**)&conn[0x18] = (void*)signal_storage_move;
    // storage_.data_[0] at +0x20 = type_index
    *(uintptr_t*)&conn[0x20] = (uintptr_t)type_index;
    // RegistrantIndex at +0x40
    *(uint64_t*)&conn[0x40] = registrant_id;

    memcpy(addr, conn, CONNECTION_SIZE);
}

/**
 * Inject our Connection into a Signal's Connections array.
 *
 * If the array has room (size < capacity), writes directly at buf[size].
 * Otherwise allocates a new buffer, copies existing entries, appends ours.
 * macOS BG3 uses system malloc, so our calloc'd buffers are compatible
 * with the game's realloc/free during later Array growth.
 */
static bool inject_connection(void *callbacks, int signal_offset,
                               uint16_t type_index,
                               void (*handler)(void*, uint64_t, void*, void*),
                               uint64_t *out_registrant) {
    uintptr_t signal_addr = (uintptr_t)callbacks + signal_offset;

    uint64_t next_id = 0;
    void *conn_buf = NULL;
    uint32_t conn_cap = 0, conn_size = 0;

    if (!safe_memory_read_u64((mach_vm_address_t)(signal_addr + SIGNAL_NEXTID_OFFSET), &next_id)) return false;
    if (!safe_memory_read_pointer((mach_vm_address_t)(signal_addr + SIGNAL_BUF_OFFSET), &conn_buf)) return false;
    if (!safe_memory_read_u32((mach_vm_address_t)(signal_addr + SIGNAL_CAP_OFFSET), &conn_cap)) return false;
    if (!safe_memory_read_u32((mach_vm_address_t)(signal_addr + SIGNAL_SIZE_OFFSET), &conn_size)) return false;

    // Sanity check: reject corrupted arrays
    if (conn_size > 10000 || (conn_size > conn_cap && conn_cap > 0)) {
        log_message("[WARN] [EntityEvents] Signal array corrupt: size=%u cap=%u", conn_size, conn_cap);
        return false;
    }

    uint64_t our_registrant = next_id;

    if (conn_size < conn_cap && conn_buf) {
        // Room available — write directly at buf[size]
        void *new_conn = (void*)((uintptr_t)conn_buf + (uintptr_t)conn_size * CONNECTION_SIZE);
        write_connection(new_conn, handler, type_index, our_registrant);
    } else {
        // Need to grow the array
        uint32_t new_cap = conn_cap ? conn_cap * 2 : 2;
        void *new_buf = calloc(new_cap, CONNECTION_SIZE);
        if (!new_buf) return false;

        // Copy existing connections
        if (conn_buf && conn_size > 0) {
            memcpy(new_buf, conn_buf, (size_t)conn_size * CONNECTION_SIZE);
            // Fix pStorage_ for all copied entries (they still point to old buffer)
            for (uint32_t i = 0; i < conn_size; i++) {
                uintptr_t entry = (uintptr_t)new_buf + (uintptr_t)i * CONNECTION_SIZE;
                *(void**)entry = (void*)(entry + 0x08);
            }
        }

        // Write our new Connection at the end
        void *new_conn = (void*)((uintptr_t)new_buf + (uintptr_t)conn_size * CONNECTION_SIZE);
        write_connection(new_conn, handler, type_index, our_registrant);

        // Defer freeing old buffer — ServerWorker may still be iterating it.
        // Buffers are freed on the next main-thread tick in fire_deferred().
        if (conn_buf) {
            if (g_deferred_free_count < MAX_DEFERRED_FREES) {
                g_deferred_frees[g_deferred_free_count++] = conn_buf;
            } else {
                // Overflow: do NOT free — ServerWorker may still be iterating.
                // This leaks the buffer, but that's safer than use-after-free.
                // 256 overflows means 256 replaced connection arrays in one tick —
                // something is very wrong if this fires.
                log_message("[WARN] [EntityEvents] Deferred free list full (%d entries). "
                            "Leaking old buffer %p to avoid use-after-free.",
                            MAX_DEFERRED_FREES, conn_buf);
            }
        }

        // Update Signal buf_ and capacity_ (heap is always writable)
        *(void**)(signal_addr + SIGNAL_BUF_OFFSET) = new_buf;
        *(uint32_t*)(signal_addr + SIGNAL_CAP_OFFSET) = new_cap;
    }

    // Update size and NextRegistrantId
    *(uint32_t*)(signal_addr + SIGNAL_SIZE_OFFSET) = conn_size + 1;
    *(uint64_t*)(signal_addr + SIGNAL_NEXTID_OFFSET) = next_id + 1;

    *out_registrant = our_registrant;
    return true;
}

/**
 * Remove our Connection from a Signal's array by registrant ID.
 * Uses swap-with-last to avoid memmove; fixes pStorage_ on the moved entry.
 */
static bool remove_connection_by_registrant(void *callbacks, int signal_offset,
                                             uint64_t registrant_id) {
    uintptr_t signal_addr = (uintptr_t)callbacks + signal_offset;

    void *conn_buf = NULL;
    uint32_t conn_size = 0;
    if (!safe_memory_read_pointer((mach_vm_address_t)(signal_addr + SIGNAL_BUF_OFFSET), &conn_buf)) return false;
    if (!safe_memory_read_u32((mach_vm_address_t)(signal_addr + SIGNAL_SIZE_OFFSET), &conn_size)) return false;
    if (!conn_buf || conn_size == 0) return false;

    for (uint32_t i = 0; i < conn_size; i++) {
        uintptr_t conn_addr = (uintptr_t)conn_buf + (uintptr_t)i * CONNECTION_SIZE;
        uint64_t reg_idx = 0;
        if (!safe_memory_read_u64((mach_vm_address_t)(conn_addr + 0x40), &reg_idx)) continue;

        if (reg_idx == registrant_id) {
            // Swap with last entry if not already last
            if (i < conn_size - 1) {
                uintptr_t last_addr = (uintptr_t)conn_buf + (uintptr_t)(conn_size - 1) * CONNECTION_SIZE;
                memcpy((void*)conn_addr, (void*)last_addr, CONNECTION_SIZE);
                // Fix pStorage_ of moved entry to be self-referential
                *(void**)conn_addr = (void*)(conn_addr + 0x08);
            }
            *(uint32_t*)(signal_addr + SIGNAL_SIZE_OFFSET) = conn_size - 1;
            return true;
        }
    }
    return false;
}

/**
 * Install signal hooks for a component type into the CCR.
 */
static bool install_signal_hook(uint16_t type_index, uint32_t events) {
    if (!g_bound_world) return false;
    if (!ensure_signal_hooks_capacity(type_index)) return false;

    // Read CCR
    void *ccr_buf = NULL;
    uint32_t ccr_size = 0;
    if (!safe_memory_read_pointer(
            (mach_vm_address_t)((uintptr_t)g_bound_world + CCR_BUF_OFFSET), &ccr_buf)) return false;
    if (!safe_memory_read_u32(
            (mach_vm_address_t)((uintptr_t)g_bound_world + CCR_SIZE_OFFSET), &ccr_size)) return false;
    if (type_index >= ccr_size || !ccr_buf) return false;

    // Read ComponentCallbacks* for this type
    void *callbacks = NULL;
    if (!safe_memory_read_pointer(
            (mach_vm_address_t)((uintptr_t)ccr_buf + (uintptr_t)type_index * 8), &callbacks)) return false;
    if (!callbacks) {
        log_message("[WARN] [EntityEvents] CCR[%u] is NULL — component type may not use callbacks",
                    type_index);
        return false;
    }

    bool ok = true;

    if ((events & ENTITY_EVENT_CREATE) &&
        g_signal_hooks[type_index].construct_registrant == SIGNAL_HOOK_NONE) {
        uint64_t reg = SIGNAL_HOOK_NONE;
        if (inject_connection(callbacks, CB_ONCONSTRUCT_OFFSET, type_index,
                               signal_construct_handler, &reg)) {
            g_signal_hooks[type_index].construct_registrant = reg;
        } else {
            log_message("[WARN] [EntityEvents] Failed to inject OnConstruct for type %u", type_index);
            ok = false;
        }
    }

    if ((events & ENTITY_EVENT_DESTROY) &&
        g_signal_hooks[type_index].destroy_registrant == SIGNAL_HOOK_NONE) {
        uint64_t reg = SIGNAL_HOOK_NONE;
        if (inject_connection(callbacks, CB_ONDESTROY_OFFSET, type_index,
                               signal_destroy_handler, &reg)) {
            g_signal_hooks[type_index].destroy_registrant = reg;
        } else {
            log_message("[WARN] [EntityEvents] Failed to inject OnDestroy for type %u", type_index);
            ok = false;
        }
    }

    return ok;
}

/**
 * Remove all signal hooks for a component type.
 */
static bool remove_signal_hook(uint16_t type_index) {
    if (!g_bound_world || type_index >= g_signal_hooks_capacity) return false;

    void *ccr_buf = NULL;
    uint32_t ccr_size = 0;
    if (!safe_memory_read_pointer(
            (mach_vm_address_t)((uintptr_t)g_bound_world + CCR_BUF_OFFSET), &ccr_buf)) return false;
    if (!safe_memory_read_u32(
            (mach_vm_address_t)((uintptr_t)g_bound_world + CCR_SIZE_OFFSET), &ccr_size)) return false;
    if (type_index >= ccr_size || !ccr_buf) return false;

    void *callbacks = NULL;
    if (!safe_memory_read_pointer(
            (mach_vm_address_t)((uintptr_t)ccr_buf + (uintptr_t)type_index * 8), &callbacks)) return false;
    if (!callbacks) return false;

    if (g_signal_hooks[type_index].construct_registrant != SIGNAL_HOOK_NONE) {
        remove_connection_by_registrant(callbacks, CB_ONCONSTRUCT_OFFSET,
                                         g_signal_hooks[type_index].construct_registrant);
        g_signal_hooks[type_index].construct_registrant = SIGNAL_HOOK_NONE;
    }

    if (g_signal_hooks[type_index].destroy_registrant != SIGNAL_HOOK_NONE) {
        remove_connection_by_registrant(callbacks, CB_ONDESTROY_OFFSET,
                                         g_signal_hooks[type_index].destroy_registrant);
        g_signal_hooks[type_index].destroy_registrant = SIGNAL_HOOK_NONE;
    }

    return true;
}

// ============================================================================
// Callback Dispatch
// ============================================================================

/**
 * Call a single Lua callback for a component event.
 */
static void call_lua_handler(lua_State *L, ComponentHook *hook,
                              uint64_t entity_handle, uint16_t type_index,
                              uint32_t event, void *component) {
    (void)component;  // Reserved for future Signal integration (pass component data to Lua)
    if (!L || !hook->active || hook->lua_ref == LUA_NOREF) return;

    // Push the callback function
    lua_rawgeti(L, LUA_REGISTRYINDEX, hook->lua_ref);
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 1);
        return;
    }

    // Push arguments: entity (as integer handle), component_type (as string), event_name
    lua_pushinteger(L, (lua_Integer)entity_handle);

    // Look up component name
    const ComponentInfo *info = component_registry_lookup_by_index(type_index);
    if (info) {
        lua_pushstring(L, info->name);
    } else {
        lua_pushinteger(L, type_index);
    }

    // Push event type string
    if (event & ENTITY_EVENT_CREATE) {
        lua_pushstring(L, "Create");
    } else {
        lua_pushstring(L, "Destroy");
    }

    // Call with 3 arguments, 0 results
    if (lua_pcall(L, 3, 0, 0) != LUA_OK) {
        const char *err = lua_tostring(L, -1);
        log_message("[ERROR] Entity event callback failed: %s", err ? err : "(unknown)");
        lua_pop(L, 1);
    }
}

/**
 * Dispatch an event to all matching handlers for a component type.
 */
static void dispatch_event(lua_State *L, uint16_t type_index,
                            uint64_t entity_handle, uint32_t event,
                            void *component) {
    if (!is_type_hooked(type_index)) return;

    ComponentHooks *hooks = &g_component_hooks[type_index];
    if ((hooks->events & event) == 0) return;

    // Dispatch to global hooks
    for (int i = 0; i < hooks->global_hook_count; i++) {
        uint32_t packed = hooks->global_hooks[i];
        if (!pool_validate(packed)) continue;

        int idx = pool_unpack_index(packed);
        ComponentHook *hook = &g_hooks[idx];
        if (!hook->active || (hook->events & event) == 0) continue;

        // P0 FIX: Always defer — dispatch may fire from ServerWorker thread,
        // and calling lua_pcall from a non-main thread corrupts the Lua stack.
        if (g_deferred_count < MAX_DEFERRED_EVENTS) {
            g_deferred[g_deferred_count++] = (DeferredEvent){
                .entity = entity_handle,
                .type_index = type_index,
                .event = event,
                .sub_index = packed
            };
        }
    }

    // Dispatch to per-entity hooks
    for (int i = 0; i < hooks->entity_hook_count; i++) {
        EntityHookEntry *entry = &hooks->entity_hooks[i];
        if (entry->entity != entity_handle) continue;

        for (int j = 0; j < entry->count; j++) {
            uint32_t packed = entry->indices[j];
            if (!pool_validate(packed)) continue;

            int idx = pool_unpack_index(packed);
            ComponentHook *hook = &g_hooks[idx];
            if (!hook->active || (hook->events & event) == 0) continue;

            // P0 FIX: Always defer (see above)
            if (g_deferred_count < MAX_DEFERRED_EVENTS) {
                g_deferred[g_deferred_count++] = (DeferredEvent){
                    .entity = entity_handle,
                    .type_index = type_index,
                    .event = event,
                    .sub_index = packed
                };
            }
        }
        break;  // Found the entity entry
    }
}

// ============================================================================
// Internal Unsubscribe (no Lua state needed)
// ============================================================================

static void unsubscribe_by_packed(uint32_t packed, lua_State *L) {
    if (!pool_validate(packed)) return;
    int idx = pool_unpack_index(packed);
    ComponentHook *hook = &g_hooks[idx];

    // Remove from component hooks lists
    if (hook->type_index < g_hooked_capacity && is_type_hooked(hook->type_index)) {
        ComponentHooks *chooks = &g_component_hooks[hook->type_index];

        if (hook->entity == 0) {
            // Remove from global hooks
            for (int i = 0; i < chooks->global_hook_count; i++) {
                if (chooks->global_hooks[i] == packed) {
                    // Shift remaining entries
                    memmove(&chooks->global_hooks[i],
                            &chooks->global_hooks[i + 1],
                            (chooks->global_hook_count - i - 1) * sizeof(uint32_t));
                    chooks->global_hook_count--;
                    break;
                }
            }
        } else {
            // Remove from entity hooks
            for (int i = 0; i < chooks->entity_hook_count; i++) {
                if (chooks->entity_hooks[i].entity == hook->entity) {
                    EntityHookEntry *entry = &chooks->entity_hooks[i];
                    for (int j = 0; j < entry->count; j++) {
                        if (entry->indices[j] == packed) {
                            memmove(&entry->indices[j],
                                    &entry->indices[j + 1],
                                    (entry->count - j - 1) * sizeof(uint32_t));
                            entry->count--;
                            break;
                        }
                    }
                    break;
                }
            }
        }
    }

    // Release Lua callback reference
    if (L && hook->lua_ref != LUA_NOREF && hook->lua_ref != LUA_REFNIL) {
        luaL_unref(L, LUA_REGISTRYINDEX, hook->lua_ref);
    }
    hook->lua_ref = LUA_NOREF;

    pool_free(idx);
}

// ============================================================================
// Public API Implementation
// ============================================================================

void entity_events_init(void) {
    if (g_initialized) return;

    memset(g_hooks, 0, sizeof(g_hooks));
    memset(g_hook_salts, 0, sizeof(g_hook_salts));
    g_hook_count = 0;
    g_next_salt = 1;
    g_deferred_count = 0;
    g_deferred_unsub_count = 0;
    g_bound_world = NULL;
    g_is_server = false;

    // Start with capacity for 256 component types
    g_hooked_capacity = 0;
    g_component_hooks = NULL;
    g_hooked_mask = NULL;
    ensure_hooks_capacity(256);

    g_initialized = true;
    log_message("[INFO] [EntityEvents] Initialized (max %d subscriptions)", MAX_SUBSCRIPTIONS);
}

void entity_events_bind(void *entity_world, bool is_server) {
    if (!entity_world) return;

    // Guard: CCR injection writes Connection structs into game memory at
    // offsets derived from hardcoded addresses. On version mismatch, these
    // offsets are wrong and writing corrupts the game's signal arrays,
    // causing crashes in HotbarSystem::Update and similar ECS systems.
    if (!version_detect_addresses_safe()) {
        log_message("[WARN] [EntityEvents] Skipping CCR bind — game version mismatch. "
                    "Entity event subscriptions (OnCreate/OnDestroy) will not work.");
        return;
    }

    // Validate CCR access BEFORE committing to this world
    void *ccr_buf = NULL;
    uint32_t ccr_size = 0;
    bool ccr_ok = safe_memory_read_pointer(
        (mach_vm_address_t)((uintptr_t)entity_world + CCR_BUF_OFFSET), &ccr_buf);
    ccr_ok = ccr_ok && safe_memory_read_u32(
        (mach_vm_address_t)((uintptr_t)entity_world + CCR_SIZE_OFFSET), &ccr_size);

    if (ccr_ok && ccr_buf && ccr_size > 100 && ccr_size < 65535) {
        log_message("[INFO] [EntityEvents] CCR validated: %u component types at %p",
                    ccr_size, ccr_buf);
    } else {
        log_message("[WARN] [EntityEvents] CCR validation failed for %s EntityWorld at %p "
                    "(buf=%p, size=%u) — signal hooks disabled",
                    is_server ? "server" : "client", entity_world, ccr_buf, ccr_size);
        return;  // Don't overwrite g_bound_world with invalid world
    }

    // CCR valid — commit to this world
    g_bound_world = entity_world;
    g_is_server = is_server;

    // Install signal hooks for any types that already have subscriptions
    int hooks_installed = 0;
    for (int i = 0; i < g_hooked_capacity; i++) {
        if (is_type_hooked((uint16_t)i) && !g_component_hooks[i].installed) {
            if (install_signal_hook((uint16_t)i, g_component_hooks[i].events)) {
                g_component_hooks[i].installed = true;
                hooks_installed++;
            }
        }
    }

    log_message("[INFO] [EntityEvents] Bound to %s EntityWorld at %p (CCR: %u types, %d signal hooks)",
                is_server ? "server" : "client", entity_world, ccr_size, hooks_installed);
}

EntitySubscriptionId entity_events_subscribe(
    uint16_t component_type_index,
    uint64_t entity_handle,
    uint32_t events,
    uint32_t flags,
    int lua_callback_ref,
    lua_State *L
) {
    if (!g_initialized) {
        log_message("[WARN] [EntityEvents] Subscribe called before init");
        return ENTITY_SUB_INVALID;
    }

    if (component_type_index == COMPONENT_INDEX_UNDEFINED) {
        log_message("[WARN] [EntityEvents] Subscribe: undefined component type");
        return ENTITY_SUB_INVALID;
    }

    if (events == 0) {
        log_message("[WARN] [EntityEvents] Subscribe: no events specified");
        return ENTITY_SUB_INVALID;
    }

    // Allocate pool slot
    int slot = pool_alloc();
    if (slot < 0) {
        log_message("[ERROR] [EntityEvents] Subscribe: pool full (%d/%d)",
                    g_hook_count, MAX_SUBSCRIPTIONS);
        return ENTITY_SUB_INVALID;
    }

    // Fill subscription
    ComponentHook *hook = &g_hooks[slot];
    hook->events = events;
    hook->flags = flags;
    hook->type_index = component_type_index;
    hook->entity = entity_handle;
    hook->lua_ref = lua_callback_ref;

    uint32_t packed = pool_pack(slot);

    // Add to component hooks
    ComponentHooks *chooks = get_or_create_component_hooks(component_type_index);
    if (!chooks) {
        pool_free(slot);
        if (L) luaL_unref(L, LUA_REGISTRYINDEX, lua_callback_ref);
        return ENTITY_SUB_INVALID;
    }

    chooks->events |= events;

    if (entity_handle == 0) {
        // Global hook
        if (chooks->global_hook_count < MAX_GLOBAL_HOOKS_PER_TYPE) {
            chooks->global_hooks[chooks->global_hook_count++] = packed;
        } else {
            log_message("[WARN] [EntityEvents] Too many global hooks for type %u",
                        component_type_index);
            pool_free(slot);
            if (L) luaL_unref(L, LUA_REGISTRYINDEX, lua_callback_ref);
            return ENTITY_SUB_INVALID;
        }
    } else {
        // Per-entity hook — find or create entry
        EntityHookEntry *entry = NULL;
        for (int i = 0; i < chooks->entity_hook_count; i++) {
            if (chooks->entity_hooks[i].entity == entity_handle) {
                entry = &chooks->entity_hooks[i];
                break;
            }
        }
        if (!entry) {
            if (chooks->entity_hook_count < MAX_ENTITY_HOOKS_PER_TYPE) {
                entry = &chooks->entity_hooks[chooks->entity_hook_count++];
                entry->entity = entity_handle;
                entry->count = 0;
            } else {
                log_message("[WARN] [EntityEvents] Too many entity hooks for type %u",
                            component_type_index);
                pool_free(slot);
                if (L) luaL_unref(L, LUA_REGISTRYINDEX, lua_callback_ref);
                return ENTITY_SUB_INVALID;
            }
        }
        if (entry->count < MAX_ENTITY_HOOKS_PER_TYPE) {
            entry->indices[entry->count++] = packed;
        } else {
            pool_free(slot);
            if (L) luaL_unref(L, LUA_REGISTRYINDEX, lua_callback_ref);
            return ENTITY_SUB_INVALID;
        }
    }

    // Install signal hooks if bound and not yet installed for this type
    if (g_bound_world && !chooks->installed) {
        if (install_signal_hook(component_type_index, chooks->events)) {
            chooks->installed = true;
            const ComponentInfo *info2 = component_registry_lookup_by_index(component_type_index);
            log_message("[INFO] [EntityEvents] Signal hooks installed for %s (type=%u)",
                        info2 ? info2->name : "?", component_type_index);
        }
    } else if (g_bound_world && chooks->installed) {
        // Already have hooks but may need to add the other signal direction
        // e.g., had OnCreate hooks, now subscribing to OnDestroy
        install_signal_hook(component_type_index, events);
    }

    const ComponentInfo *info = component_registry_lookup_by_index(component_type_index);
    log_message("[DEBUG] [EntityEvents] Subscribed to %s %s (type=%u, entity=%s, flags=0x%x) -> sub=%u",
                (events & ENTITY_EVENT_CREATE) ? "Create" : "",
                (events & ENTITY_EVENT_DESTROY) ? "Destroy" : "",
                component_type_index,
                entity_handle ? "specific" : "global",
                flags,
                packed);
    (void)info;  // Used only in DEBUG logging

    return MAKE_SUB_ID(SUB_TYPE_COMPONENT, packed);
}

bool entity_events_unsubscribe(EntitySubscriptionId id, lua_State *L) {
    if (id == ENTITY_SUB_INVALID) return false;

    uint32_t type_tag = SUB_ID_TYPE(id);
    uint32_t packed = SUB_ID_INDEX(id);

    if (type_tag != SUB_TYPE_COMPONENT) {
        // Replication and System subscriptions not yet implemented
        log_message("[WARN] [EntityEvents] Unsubscribe: unsupported type tag %u", type_tag);
        return false;
    }

    if (!pool_validate(packed)) {
        return false;
    }

    unsubscribe_by_packed(packed, L);
    return true;
}

void entity_events_fire_deferred(lua_State *L) {
    if (!g_initialized || !L) return;

    // Cache Lua state for signal handlers (updated each tick, atomic release)
    atomic_store_explicit(&g_lua_state, L, memory_order_release);

    // Flush deferred connection buffer frees — these are old Signal arrays
    // that were replaced during inject_connection(). By now, any ServerWorker
    // iteration that was using them has completed (at least one tick has passed).
    for (int i = 0; i < g_deferred_free_count; i++) {
        free(g_deferred_frees[i]);
        g_deferred_frees[i] = NULL;
    }
    g_deferred_free_count = 0;

    // Swap deferred events to local copy FIRST (handlers may generate new events)
    DeferredEvent local_events[MAX_DEFERRED_EVENTS];
    int local_count = g_deferred_count;
    if (local_count > 0) {
        memcpy(local_events, g_deferred, local_count * sizeof(DeferredEvent));
        g_deferred_count = 0;
    }

    // Fire deferred events before processing unsubscriptions.
    // This ensures ONCE+DEFERRED subscriptions fire before being cleaned up.
    for (int i = 0; i < local_count; i++) {
        DeferredEvent *ev = &local_events[i];
        if (!pool_validate(ev->sub_index)) continue;

        int idx = pool_unpack_index(ev->sub_index);
        ComponentHook *hook = &g_hooks[idx];
        if (!hook->active) continue;

        call_lua_handler(L, hook, ev->entity, ev->type_index, ev->event, NULL);

        if (hook->flags & ENTITY_EVENT_FLAG_ONCE) {
            unsubscribe_by_packed(ev->sub_index, L);
        }
    }

    // Process deferred unsubscriptions after events have fired
    for (int i = 0; i < g_deferred_unsub_count; i++) {
        unsubscribe_by_packed(g_deferred_unsubs[i], L);
    }
    g_deferred_unsub_count = 0;
}

void entity_events_on_create(uint16_t type_index, uint64_t entity_handle,
                              void *component, lua_State *L) {
    if (!g_initialized || !L) return;
    dispatch_event(L, type_index, entity_handle, ENTITY_EVENT_CREATE, component);
}

void entity_events_on_destroy(uint16_t type_index, uint64_t entity_handle,
                               void *component, lua_State *L) {
    if (!g_initialized || !L) return;
    dispatch_event(L, type_index, entity_handle, ENTITY_EVENT_DESTROY, component);
}

void entity_events_cleanup(lua_State *L) {
    if (!g_initialized) return;

    // Null g_lua_state FIRST so signal handlers exit immediately if they fire
    // during hook removal (handlers check g_lua_state before dispatching)
    atomic_store_explicit(&g_lua_state, NULL, memory_order_release);

    // Remove all signal hooks from the game's CCR
    // (before clearing state, while g_bound_world is still valid)
    int hooks_removed = 0;
    if (g_bound_world) {
        // Validate CCR is still accessible (game may have freed it during shutdown)
        void *ccr_buf = NULL;
        uint32_t ccr_size = 0;
        bool ccr_live = safe_memory_read_pointer(
            (mach_vm_address_t)((uintptr_t)g_bound_world + CCR_BUF_OFFSET), &ccr_buf);
        ccr_live = ccr_live && safe_memory_read_u32(
            (mach_vm_address_t)((uintptr_t)g_bound_world + CCR_SIZE_OFFSET), &ccr_size);
        ccr_live = ccr_live && ccr_buf && ccr_size > 100 && ccr_size < 65535;

        if (ccr_live) {
            for (int i = 0; i < g_signal_hooks_capacity; i++) {
                if (g_signal_hooks[i].construct_registrant != SIGNAL_HOOK_NONE ||
                    g_signal_hooks[i].destroy_registrant != SIGNAL_HOOK_NONE) {
                    remove_signal_hook((uint16_t)i);
                    hooks_removed++;
                }
            }
        } else {
            log_message("[WARN] [EntityEvents] CCR already freed — skipping signal hook removal");
        }
    }

    // Release all active Lua callback references
    for (int i = 0; i < MAX_SUBSCRIPTIONS; i++) {
        if (g_hooks[i].active) {
            if (L && g_hooks[i].lua_ref != LUA_NOREF && g_hooks[i].lua_ref != LUA_REFNIL) {
                luaL_unref(L, LUA_REGISTRYINDEX, g_hooks[i].lua_ref);
            }
            g_hooks[i].active = false;
            g_hooks[i].lua_ref = LUA_NOREF;
        }
    }

    g_hook_count = 0;
    g_deferred_count = 0;
    g_deferred_unsub_count = 0;

    // Reset component hooks
    if (g_component_hooks) {
        memset(g_component_hooks, 0, g_hooked_capacity * sizeof(ComponentHooks));
    }
    if (g_hooked_mask) {
        memset(g_hooked_mask, 0, (g_hooked_capacity + 7) / 8);
    }

    g_bound_world = NULL;
    atomic_store_explicit(&g_lua_state, NULL, memory_order_release);

    // Flush any remaining deferred frees during cleanup
    for (int i = 0; i < g_deferred_free_count; i++) {
        free(g_deferred_frees[i]);
        g_deferred_frees[i] = NULL;
    }
    g_deferred_free_count = 0;

    log_message("[INFO] [EntityEvents] Cleaned up all subscriptions (%d signal hooks removed)",
                hooks_removed);
}

int entity_events_subscription_count(void) {
    return g_hook_count;
}

bool entity_events_is_bound(void) {
    return g_bound_world != NULL;
}

void entity_events_set_transition(bool in_transition) {
    atomic_store_explicit(&g_in_transition, in_transition, memory_order_release);
    if (in_transition) {
        log_message("[INFO] [EntityEvents] Transition guard ON — signal handlers suspended");
    } else {
        log_message("[INFO] [EntityEvents] Transition guard OFF — signal handlers resumed");
    }
}

// ============================================================================
// Lua Bindings
// ============================================================================

/**
 * Resolve a component type name to a ComponentTypeIndex.
 * Supports both full names ("eoc::HealthComponent") and short names ("Health").
 */
static uint16_t resolve_component_type(lua_State *L, int arg_index) {
    const char *name = luaL_checkstring(L, arg_index);

    // Try exact match first
    const ComponentInfo *info = component_registry_lookup(name);
    if (info && info->index != COMPONENT_INDEX_UNDEFINED) {
        return info->index;
    }

    // Guard against names too long for prefix probing (max prefix "eoc::" = 5, suffix "Component" = 9)
    if (strlen(name) > COMPONENT_MAX_NAME_LEN - 15) {
        return COMPONENT_INDEX_UNDEFINED;
    }

    // Try common prefixed variants
    char prefixed[COMPONENT_MAX_NAME_LEN];
    const char *prefixes[] = {
        "eoc::", "esv::", "ecl::", "ls::", NULL
    };
    const char *suffixes[] = {
        "Component", "", NULL
    };

    for (int p = 0; prefixes[p]; p++) {
        for (int s = 0; suffixes[s]; s++) {
            snprintf(prefixed, sizeof(prefixed), "%s%s%s", prefixes[p], name, suffixes[s]);
            info = component_registry_lookup(prefixed);
            if (info && info->index != COMPONENT_INDEX_UNDEFINED) {
                return info->index;
            }
        }
    }

    return COMPONENT_INDEX_UNDEFINED;
}

/**
 * Common subscribe implementation for OnCreate/OnDestroy variants.
 * Stack: (componentType, callback, [entity], [deferred], [once])
 */
static int lua_entity_subscribe_impl(lua_State *L, uint32_t events,
                                      bool force_deferred, bool force_once) {
    uint16_t type_index = resolve_component_type(L, 1);
    if (type_index == COMPONENT_INDEX_UNDEFINED) {
        return luaL_error(L, "Unknown component type: %s", lua_tostring(L, 1));
    }

    luaL_checktype(L, 2, LUA_TFUNCTION);

    // Optional entity handle (arg 3)
    uint64_t entity = 0;
    if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
        entity = (uint64_t)luaL_checkinteger(L, 3);
    }

    // Optional deferred flag (arg 4, unless forced)
    uint32_t flags = 0;
    if (force_deferred) {
        flags |= ENTITY_EVENT_FLAG_DEFERRED;
    } else if (lua_gettop(L) >= 4 && lua_toboolean(L, 4)) {
        flags |= ENTITY_EVENT_FLAG_DEFERRED;
    }

    // Optional once flag (arg 5, unless forced)
    if (force_once) {
        flags |= ENTITY_EVENT_FLAG_ONCE;
    } else if (lua_gettop(L) >= 5 && lua_toboolean(L, 5)) {
        flags |= ENTITY_EVENT_FLAG_ONCE;
    }

    // Create Lua reference for the callback
    lua_pushvalue(L, 2);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);

    EntitySubscriptionId id = entity_events_subscribe(
        type_index, entity, events, flags, ref, L);

    if (id == ENTITY_SUB_INVALID) {
        luaL_unref(L, LUA_REGISTRYINDEX, ref);
        lua_pushnil(L);
        return 1;
    }

    lua_pushinteger(L, (lua_Integer)id);
    return 1;
}

// --- Ext.Entity.OnCreate(type, func, entity?, deferred?, once?) ---
static int lua_entity_on_create(lua_State *L) {
    return lua_entity_subscribe_impl(L, ENTITY_EVENT_CREATE, false, false);
}

// --- Ext.Entity.OnCreateDeferred(type, func, entity?) ---
static int lua_entity_on_create_deferred(lua_State *L) {
    return lua_entity_subscribe_impl(L, ENTITY_EVENT_CREATE, true, false);
}

// --- Ext.Entity.OnCreateOnce(type, func, entity?) ---
static int lua_entity_on_create_once(lua_State *L) {
    return lua_entity_subscribe_impl(L, ENTITY_EVENT_CREATE, false, true);
}

// --- Ext.Entity.OnCreateDeferredOnce(type, func, entity?) ---
static int lua_entity_on_create_deferred_once(lua_State *L) {
    return lua_entity_subscribe_impl(L, ENTITY_EVENT_CREATE, true, true);
}

// --- Ext.Entity.OnDestroy(type, func, entity?, deferred?, once?) ---
static int lua_entity_on_destroy(lua_State *L) {
    return lua_entity_subscribe_impl(L, ENTITY_EVENT_DESTROY, false, false);
}

// --- Ext.Entity.OnDestroyDeferred(type, func, entity?) ---
static int lua_entity_on_destroy_deferred(lua_State *L) {
    return lua_entity_subscribe_impl(L, ENTITY_EVENT_DESTROY, true, false);
}

// --- Ext.Entity.OnDestroyOnce(type, func, entity?) ---
static int lua_entity_on_destroy_once(lua_State *L) {
    return lua_entity_subscribe_impl(L, ENTITY_EVENT_DESTROY, false, true);
}

// --- Ext.Entity.OnDestroyDeferredOnce(type, func, entity?) ---
static int lua_entity_on_destroy_deferred_once(lua_State *L) {
    return lua_entity_subscribe_impl(L, ENTITY_EVENT_DESTROY, true, true);
}

// --- Ext.Entity.Subscribe(type, func, entity?, flags?) ---
// This is the replication subscription variant.
// For now, maps to OnCreate (replication events fire on component changes).
static int lua_entity_subscribe(lua_State *L) {
    // Windows BG3SE Subscribe = replication events, not component events.
    // For compatibility, treat as OnCreate+OnDestroy with deferred flag.
    return lua_entity_subscribe_impl(L,
        ENTITY_EVENT_CREATE | ENTITY_EVENT_DESTROY, true, false);
}

// --- Ext.Entity.Unsubscribe(handle) ---
static int lua_entity_unsubscribe(lua_State *L) {
    lua_Integer id = luaL_checkinteger(L, 1);
    bool ok = entity_events_unsubscribe((EntitySubscriptionId)id, L);
    lua_pushboolean(L, ok);
    return 1;
}

// ============================================================================
// Lua Registration
// ============================================================================

void entity_events_register_lua(lua_State *L) {
    if (!L) return;

    // Get Ext.Entity table
    lua_getglobal(L, "Ext");
    if (!lua_istable(L, -1)) { lua_pop(L, 1); return; }

    lua_getfield(L, -1, "Entity");
    if (!lua_istable(L, -1)) { lua_pop(L, 2); return; }

    int entity_idx = lua_gettop(L);

    // Register functions (overwriting stubs)
    static const struct { const char *name; lua_CFunction func; } funcs[] = {
        { "Subscribe",              lua_entity_subscribe },
        { "OnChange",               lua_entity_subscribe },   // Alias
        { "OnCreate",               lua_entity_on_create },
        { "OnCreateDeferred",       lua_entity_on_create_deferred },
        { "OnCreateOnce",           lua_entity_on_create_once },
        { "OnCreateDeferredOnce",   lua_entity_on_create_deferred_once },
        { "OnDestroy",              lua_entity_on_destroy },
        { "OnDestroyDeferred",      lua_entity_on_destroy_deferred },
        { "OnDestroyOnce",          lua_entity_on_destroy_once },
        { "OnDestroyDeferredOnce",  lua_entity_on_destroy_deferred_once },
        { "Unsubscribe",            lua_entity_unsubscribe },
        { NULL, NULL }
    };

    for (int i = 0; funcs[i].name; i++) {
        lua_pushcfunction(L, funcs[i].func);
        lua_setfield(L, entity_idx, funcs[i].name);
    }

    lua_pop(L, 2);  // Pop Entity table and Ext table

    log_message("[INFO] [EntityEvents] Registered %d Lua functions", 11);
}
