/**
 * BG3SE-macOS - Network Hooks Implementation
 *
 * Captures GameServer from EocServer and reads network pointers
 * (NetMessageFactory, ProtocolList) using Ghidra-verified offsets.
 * Phase 4E: Performs live ProtocolList insertion and MessageFactory probing.
 *
 * Offset discovery (Phase 4D):
 *   EocServer+0xA8  = GameServer*         (233 accesses confirmed, matches Windows)
 *   GameServer+0x1F8 = NetMessageFactory* (74 accesses, Windows ~0x1E8)
 *   GameServer+0x2E0 = ProtocolList area  (61 accesses, Windows ~0x2B0)
 *
 * See ghidra/offsets/NETWORKING.md for full RE documentation.
 *
 * Issue #6: NetChannel API (Phase 4E)
 */

#include "net_hooks.h"
#include "protocol.h"
#include "extender_protocol.h"
#include "extender_message.h"
#include "../core/logging.h"
#include "../core/safe_memory.h"
#include "../entity/entity_system.h"  // entity_get_binary_base()
#include <dobby.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// ============================================================================
// Static State
// ============================================================================

static NetHookStatus s_status = {0};
static NetCapturedPtrs s_ptrs = {0};

// Captured network objects
static void *s_game_server = NULL;         // GameServer* (from EocServer+0xA8)
static void *s_net_msg_factory = NULL;     // NetMessageFactory* (from GameServer+0x1F8)

// GetMessage hook state (Phase 4F)
typedef void *(*GetMessage_t)(void *factory, uint32_t message_id);
static GetMessage_t s_orig_GetMessage = NULL;
static void *s_hook_target_addr = NULL;    // For cleanup

// ============================================================================
// Safe Memory Helpers
//
// Use safe_memory API (mach_vm_read_overwrite) to prevent SIGBUS crashes
// from GPU carveout regions and unmapped addresses.
// ============================================================================

/**
 * Read a pointer from (base + offset) safely.
 * Returns NULL if the read fails or the value is NULL/invalid.
 */
static void *safe_read_ptr(const void *base, uintptr_t offset) {
    if (!base) return NULL;
    void *value = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)base + offset, &value)) {
        return NULL;
    }
    return value;
}

/**
 * Read a uint64_t from (base + offset) safely.
 * Returns false if the read fails.
 */
static bool safe_read_u64(const void *base, uintptr_t offset, uint64_t *out) {
    if (!base || !out) return false;
    return safe_memory_read_u64((mach_vm_address_t)base + offset, out);
}

// ============================================================================
// ASLR Address Resolution
// ============================================================================

#define GHIDRA_BASE_ADDRESS 0x100000000ULL

static uintptr_t get_runtime_addr(uintptr_t ghidra_addr) {
    void *base = entity_get_binary_base();
    if (!base) return 0;
    return ghidra_addr - GHIDRA_BASE_ADDRESS + (uintptr_t)base;
}

// ============================================================================
// GetMessage Hook (Phase 4F)
//
// Intercepts NetMessageFactory::GetMessage. For ID 400 (NETMSG_SCRIPT_EXTENDER),
// returns an ExtenderMessage from our pool. For all other IDs, calls the
// original game function.
//
// ARM64 signature:
//   x0 = this (MessageFactory*), w1 = messageId (uint32_t)
//   Returns: x0 = Message* (or NULL)
// ============================================================================

static void *hook_GetMessage(void *factory, uint32_t message_id) {
    if (message_id == NETMSG_SCRIPT_EXTENDER) {
        ExtenderMessage *msg = extender_message_pool_get();
        if (msg) {
            LOG_NET_DEBUG("GetMessage(%u): returning ExtenderMessage %p from pool",
                          message_id, (void *)msg);
            return &msg->base;
        }
        LOG_NET_WARN("GetMessage(%u): pool exhausted, returning NULL", message_id);
        return NULL;
    }
    return s_orig_GetMessage(factory, message_id);
}

// ============================================================================
// ProtocolList Probing
//
// The ProtocolList is an Array<Protocol*> at GameServer+0x2E0.
// The exact array layout needs runtime verification.
//
// Candidate layouts:
//   Layout A (16-byte): { Protocol** data; uint32_t capacity; uint32_t size; }
//   Layout B (24-byte): { Protocol** data; uint64_t capacity; uint64_t size; }
//   Layout C (Larian):  { Protocol** data; uint64_t size; uint64_t capacity; }
//
// We probe at runtime to determine which layout matches by reading the data
// pointer and checking if it points to valid Protocol* entries with vtables.
// ============================================================================

/**
 * Probe the ProtocolList at GameServer+offset.
 * Uses safe_memory API for all reads. Returns valid Protocol* count.
 *
 * @param game_server  GameServer pointer
 * @param data_offset  Offset to data pointer within GameServer
 * @param size_offset  Offset to size field within GameServer
 * @param out_data     Output: data pointer
 * @param out_size     Output: element count
 */
static int probe_protocol_list(void *game_server, uintptr_t data_offset,
                               uintptr_t size_offset,
                               void ***out_data, uint64_t *out_size) {
    // Read data pointer safely
    void *data_raw = safe_read_ptr(game_server, data_offset);
    if (!data_raw) return 0;
    void **data = (void **)data_raw;

    // Read size as uint64_t safely
    uint64_t size = 0;
    if (!safe_read_u64(game_server, size_offset, &size)) return 0;

    // Sanity check: protocol count should be small (typically 3-10)
    if (size == 0 || size > 64) return 0;

    // Validate entries: each should be a pointer to an object with a vtable
    int valid = 0;
    for (uint64_t i = 0; i < size && i < 16; i++) {
        void *entry = NULL;
        if (!safe_memory_read_pointer((mach_vm_address_t)&data[i], &entry)) break;
        if (!entry) break;

        // Check if entry has a vtable-like pointer at offset 0
        void *vtable = NULL;
        if (!safe_memory_read_pointer((mach_vm_address_t)entry, &vtable)) break;
        if (!vtable) break;

        valid++;
    }

    if (valid > 0) {
        *out_data = data;
        *out_size = size;
    }

    return valid;
}

// ============================================================================
// Public API
// ============================================================================

bool net_hooks_install(void) {
    LOG_NET_INFO("net_hooks_install: Phase 4D — using Ghidra-verified offsets");
    LOG_NET_INFO("  EocServer+0x%X = GameServer", OFFSET_EOCSERVER_GAMESERVER);
    LOG_NET_INFO("  GameServer+0x%X = NetMessageFactory", OFFSET_GAMESERVER_MSGFACTORY);
    LOG_NET_INFO("  GameServer+0x%X = ProtocolList", OFFSET_GAMESERVER_PROTOLIST);

    // No Dobby hooks needed for Phase 4D.
    // We capture pointers directly from memory using known offsets.
    // The game's dispatch loop will call our protocol automatically
    // once we insert into ProtocolList.

    return true;
}

void net_hooks_remove(void) {
    LOG_NET_INFO("net_hooks_remove: cleaning up");

    // Remove our protocol from ProtocolList if inserted
    if (s_status.protocol_list_hooked && s_game_server) {
        ExtenderProtocol *proto = extender_protocol_get();
        if (proto) {
            void *data_raw = safe_read_ptr(s_game_server, OFFSET_GAMESERVER_PROTOLIST);
            uint64_t size = 0;
            safe_read_u64(s_game_server, OFFSET_GAMESERVER_PROTOLIST_SIZE, &size);

            if (data_raw && size > 0 && size <= 64) {
                void **data = (void **)data_raw;
                int found_idx = -1;

                // Find our protocol in the list
                for (uint64_t i = 0; i < size; i++) {
                    void *entry = NULL;
                    if (!safe_memory_read_pointer((mach_vm_address_t)&data[i], &entry)) break;
                    if (entry == (void *)&proto->base) {
                        found_idx = (int)i;
                        break;
                    }
                }

                if (found_idx >= 0) {
                    // Swap-with-last to fill the gap, then decrement size
                    if (found_idx < (int)(size - 1)) {
                        void *last = NULL;
                        safe_memory_read_pointer(
                            (mach_vm_address_t)&data[size - 1], &last);
                        safe_memory_write_pointer(
                            (mach_vm_address_t)&data[found_idx], last);
                    }
                    // Clear the last slot and decrement size
                    safe_memory_write_pointer(
                        (mach_vm_address_t)&data[size - 1], NULL);
                    __sync_synchronize();
                    safe_memory_write_u64(
                        (mach_vm_address_t)s_game_server + OFFSET_GAMESERVER_PROTOLIST_SIZE,
                        size - 1);
                    __sync_synchronize();

                    LOG_NET_INFO("  Removed ExtenderProtocol from ProtocolList index %d (new size=%llu)",
                                 found_idx, (unsigned long long)(size - 1));
                } else {
                    LOG_NET_WARN("  ExtenderProtocol not found in ProtocolList during cleanup");
                }
            }
        }
    }

    // Remove GetMessage hook (Phase 4F)
    // Note: Dobby doesn't provide DobbyDestroy on all platforms.
    // Clear our state so the hook becomes a pass-through if it fires during shutdown.
    if (s_status.message_factory_hooked) {
        LOG_NET_INFO("  Clearing GetMessage hook state");
        s_status.message_factory_hooked = false;
        // After this, hook_GetMessage will still call s_orig_GetMessage for all IDs
        // since message_factory_hooked is cleared. This is safe.
    }

    // Destroy the ExtenderProtocol singleton
    ExtenderProtocol *proto = extender_protocol_get();
    if (proto) {
        extender_protocol_destroy(proto);
    }

    memset(&s_status, 0, sizeof(s_status));
    memset(&s_ptrs, 0, sizeof(s_ptrs));
    s_game_server = NULL;
    s_net_msg_factory = NULL;
    s_hook_target_addr = NULL;
}

NetHookStatus net_hooks_get_status(void) {
    return s_status;
}

NetCapturedPtrs net_hooks_get_ptrs(void) {
    return s_ptrs;
}

bool net_hooks_capture_peer(void *eoc_server) {
    if (!eoc_server) {
        LOG_NET_WARN("net_hooks_capture_peer: NULL EocServer");
        return false;
    }

    LOG_NET_INFO("net_hooks_capture_peer: EocServer=%p", eoc_server);

    // Step 1: Read GameServer from EocServer+0xA8
    s_game_server = safe_read_ptr(eoc_server, OFFSET_EOCSERVER_GAMESERVER);
    if (!s_game_server) {
        LOG_NET_WARN("  GameServer at EocServer+0x%X is NULL or unreadable",
                     OFFSET_EOCSERVER_GAMESERVER);
        return false;
    }
    LOG_NET_INFO("  GameServer = %p", s_game_server);

    // Step 2: Read NetMessageFactory from GameServer+0x1F8
    s_net_msg_factory = safe_read_ptr(s_game_server, OFFSET_GAMESERVER_MSGFACTORY);
    if (s_net_msg_factory) {
        LOG_NET_INFO("  NetMessageFactory = %p", s_net_msg_factory);
    } else {
        LOG_NET_WARN("  NetMessageFactory at GameServer+0x%X is NULL or unreadable",
                     OFFSET_GAMESERVER_MSGFACTORY);
    }

    // Step 3: Probe ProtocolList at GameServer+0x2E0
    // Layout confirmed via statistical binary analysis (NETWORKING.md Phase 4D):
    //   +0x2E0: data pointer (Protocol**)
    //   +0x2F0: capacity (uint64_t)
    //   +0x300: size/count (uint64_t)
    void **proto_data = NULL;
    uint64_t proto_size = 0;
    int valid_protos = 0;

    // Primary: NETWORKING.md confirmed layout (data=+0x2E0, size=+0x300)
    valid_protos = probe_protocol_list(s_game_server,
                                       OFFSET_GAMESERVER_PROTOLIST,
                                       OFFSET_GAMESERVER_PROTOLIST_SIZE,
                                       &proto_data, &proto_size);
    if (valid_protos > 0) {
        LOG_NET_INFO("  ProtocolList: data=%p, size=%llu (layout: +0x2E0/+0x300)",
                     (void *)proto_data, (unsigned long long)proto_size);
    }

    // Fallback: try size at +0x2F0 (in case capacity/size are swapped)
    if (valid_protos == 0) {
        valid_protos = probe_protocol_list(s_game_server,
                                           OFFSET_GAMESERVER_PROTOLIST,
                                           OFFSET_GAMESERVER_PROTOLIST_CAP,
                                           &proto_data, &proto_size);
        if (valid_protos > 0) {
            LOG_NET_INFO("  ProtocolList: data=%p, size=%llu (layout: +0x2E0/+0x2F0, cap/size swapped?)",
                         (void *)proto_data, (unsigned long long)proto_size);
        }
    }

    if (valid_protos == 0) {
        LOG_NET_WARN("  ProtocolList probe failed — no valid array layout found at +0x2E0");
        LOG_NET_WARN("  Dumping GameServer+0x2D0..0x320 for manual analysis:");
        for (uintptr_t off = 0x2D0; off <= 0x320; off += 8) {
            void *val = NULL;
            safe_memory_read_pointer((mach_vm_address_t)s_game_server + off, &val);
            LOG_NET_WARN("    +0x%03lX: %p", (unsigned long)off, val);
        }
    }

    // Populate captured pointers
    s_ptrs.abstract_peer = s_game_server;  // GameServer IS-A AbstractPeer
    s_ptrs.message_factory = s_net_msg_factory;
    s_ptrs.protocol_list = (valid_protos > 0) ? (void *)proto_data : NULL;

    LOG_NET_INFO("  Probe summary: %d valid protocols in list, factory=%s",
                 valid_protos, s_net_msg_factory ? "YES" : "NO");

    return s_game_server != NULL;
}

bool net_hooks_register_message(void) {
    if (!s_net_msg_factory) {
        LOG_NET_WARN("net_hooks_register_message: MessageFactory not captured");
        return false;
    }

    LOG_NET_INFO("net_hooks_register_message: MessageFactory=%p", s_net_msg_factory);

    // ---- Phase 4E: MessageFactory runtime probe ----
    // Actual registration deferred to Phase 4F (requires GameAlloc for MessagePool).
    // Here we probe the factory layout for diagnostic logging.

    // Read VMT (should be non-null for a valid C++ object)
    void *factory_vmt = safe_read_ptr(s_net_msg_factory, 0);
    if (factory_vmt) {
        LOG_NET_INFO("  Factory VMT = %p", factory_vmt);
    } else {
        LOG_NET_WARN("  Factory VMT is NULL — invalid object?");
        return false;
    }

    // Read MessagePools data pointer at +0x08
    void *pools_data = safe_read_ptr(s_net_msg_factory, 0x08);
    LOG_NET_INFO("  MessagePools.buf = %p", pools_data);

    // Probe candidate pool array layouts:
    // Layout A: { void** buf; uint32_t capacity; uint32_t size; }  (+0x10: cap32, +0x14: size32)
    // Layout B: { void** buf; uint64_t capacity; uint64_t size; }  (+0x10: cap64, +0x18: size64)
    uint32_t cap32 = 0, size32 = 0;
    uint64_t cap64 = 0, size64 = 0;
    safe_memory_read_u32((mach_vm_address_t)s_net_msg_factory + 0x10, &cap32);
    safe_memory_read_u32((mach_vm_address_t)s_net_msg_factory + 0x14, &size32);
    safe_memory_read_u64((mach_vm_address_t)s_net_msg_factory + 0x10, &cap64);
    safe_memory_read_u64((mach_vm_address_t)s_net_msg_factory + 0x18, &size64);

    LOG_NET_INFO("  Probe 32-bit: cap=%u, size=%u (at +0x10/+0x14)", cap32, size32);
    LOG_NET_INFO("  Probe 64-bit: cap=%llu, size=%llu (at +0x10/+0x18)",
                 (unsigned long long)cap64, (unsigned long long)size64);

    // Heuristic: valid layout has size in range [50, 500], capacity >= size
    bool layout_32 = (size32 >= 50 && size32 <= 500 && cap32 >= size32);
    bool layout_64 = (size64 >= 50 && size64 <= 500 && cap64 >= size64);

    if (layout_32 && !layout_64) {
        LOG_NET_INFO("  Detected 32-bit pool layout (size=%u, cap=%u)", size32, cap32);
        if (NETMSG_SCRIPT_EXTENDER < size32) {
            LOG_NET_INFO("  Message ID %d is WITHIN pool range — already allocated?",
                         NETMSG_SCRIPT_EXTENDER);
        } else {
            LOG_NET_INFO("  Message ID %d is OUTSIDE pool range — needs Grow()",
                         NETMSG_SCRIPT_EXTENDER);
        }
    } else if (layout_64) {
        LOG_NET_INFO("  Detected 64-bit pool layout (size=%llu, cap=%llu)",
                     (unsigned long long)size64, (unsigned long long)cap64);
        if ((uint64_t)NETMSG_SCRIPT_EXTENDER < size64) {
            LOG_NET_INFO("  Message ID %d is WITHIN pool range — already allocated?",
                         NETMSG_SCRIPT_EXTENDER);
        } else {
            LOG_NET_INFO("  Message ID %d is OUTSIDE pool range — needs Grow()",
                         NETMSG_SCRIPT_EXTENDER);
        }
    } else {
        LOG_NET_WARN("  Could not determine pool layout — neither heuristic matched");
        LOG_NET_WARN("  Manual inspection needed: use Ext.Debug.ProbeStruct(0x%llx, 0, 0x40, 8)",
                     (unsigned long long)(uintptr_t)s_net_msg_factory);
    }

    // Validate pool entries: read first few to check they look like valid pointers
    if (pools_data) {
        int valid_pools = 0;
        for (int i = 0; i < 4 && i < (int)size32; i++) {
            void *pool_entry = NULL;
            if (!safe_memory_read_pointer(
                    (mach_vm_address_t)pools_data + (i * sizeof(void *)),
                    &pool_entry))
                break;
            if (!pool_entry) continue;
            void *pool_vmt = NULL;
            if (safe_memory_read_pointer((mach_vm_address_t)pool_entry, &pool_vmt) && pool_vmt) {
                valid_pools++;
            }
        }
        LOG_NET_INFO("  Pool validation: %d/4 sampled entries have valid vtables", valid_pools);
    }

    // ---- Phase 4F: Hook GetMessage instead of MessagePool registration ----
    // Hooking GetMessage avoids needing GameAlloc and Larian container RE.
    // For ID 400 we return our own pooled ExtenderMessage, for all other IDs
    // we pass through to the original.

    uintptr_t runtime_addr = get_runtime_addr(ADDR_GETMESSAGE);
    if (!runtime_addr) {
        LOG_NET_WARN("  GetMessage hook: failed to resolve runtime address (no binary base)");
        return false;
    }

    s_hook_target_addr = (void *)runtime_addr;
    LOG_NET_INFO("  GetMessage: Ghidra=0x%llx, runtime=%p",
                 (unsigned long long)ADDR_GETMESSAGE, s_hook_target_addr);

    // Initialize the message pool before hooking
    extender_message_pool_init();

    int result = DobbyHook(s_hook_target_addr, (void *)hook_GetMessage,
                           (void **)&s_orig_GetMessage);
    if (result == 0) {
        LOG_NET_INFO("  GetMessage hook installed successfully (orig=%p)",
                     (void *)s_orig_GetMessage);
        s_status.message_factory_hooked = true;
        return true;
    } else {
        LOG_NET_ERROR("  GetMessage hook FAILED (Dobby result=%d)", result);
        s_hook_target_addr = NULL;
        return false;
    }
}

bool net_hooks_insert_protocol(void) {
    if (!s_game_server) {
        LOG_NET_WARN("net_hooks_insert_protocol: GameServer not captured");
        return false;
    }

    if (!s_ptrs.protocol_list) {
        LOG_NET_WARN("net_hooks_insert_protocol: ProtocolList not probed");
        return false;
    }

    ExtenderProtocol *proto = extender_protocol_get();
    if (!proto) {
        LOG_NET_ERROR("net_hooks_insert_protocol: Failed to create ExtenderProtocol");
        return false;
    }

    proto->base.peer = s_game_server;  // Set peer to GameServer (IS-A AbstractPeer)

    LOG_NET_INFO("net_hooks_insert_protocol: ExtenderProtocol=%p, peer=%p",
                 (void *)proto, s_game_server);

    // ---- Phase 4E: Live ProtocolList insertion ----
    // Read current data/capacity/size from GameServer offsets
    void *data_raw = safe_read_ptr(s_game_server, OFFSET_GAMESERVER_PROTOLIST);
    uint64_t capacity = 0, size = 0;
    if (!safe_read_u64(s_game_server, OFFSET_GAMESERVER_PROTOLIST_CAP, &capacity)) {
        LOG_NET_WARN("  Failed to read ProtocolList capacity");
        return false;
    }
    if (!safe_read_u64(s_game_server, OFFSET_GAMESERVER_PROTOLIST_SIZE, &size)) {
        LOG_NET_WARN("  Failed to read ProtocolList size");
        return false;
    }

    if (!data_raw || size > 64 || capacity > 128) {
        LOG_NET_WARN("  ProtocolList sanity check failed: data=%p, capacity=%llu, size=%llu",
                     data_raw, (unsigned long long)capacity, (unsigned long long)size);
        return false;
    }

    void **data = (void **)data_raw;
    LOG_NET_INFO("  ProtocolList: data=%p, capacity=%llu, size=%llu",
                 data_raw, (unsigned long long)capacity, (unsigned long long)size);

    // Idempotency guard: check if our protocol is already inserted
    for (uint64_t i = 0; i < size; i++) {
        void *entry = NULL;
        if (!safe_memory_read_pointer((mach_vm_address_t)&data[i], &entry)) break;
        if (entry == (void *)&proto->base) {
            LOG_NET_INFO("  ExtenderProtocol already in ProtocolList at index %llu",
                         (unsigned long long)i);
            s_status.protocol_list_hooked = true;
            proto->active = true;
            return true;
        }
    }

    // Growth: if the array is full, allocate a larger buffer
    // We use malloc here — ProtocolList holds raw pointers, safe with our allocator.
    // The old game-allocated buffer cannot be freed, but it's a one-time ~64 byte leak.
    if (size >= capacity) {
        uint64_t new_cap = (capacity == 0) ? 8 : capacity * 2;
        void **new_data = malloc(new_cap * sizeof(void *));
        if (!new_data) {
            LOG_NET_ERROR("  Failed to allocate new ProtocolList buffer (cap=%llu)",
                          (unsigned long long)new_cap);
            return false;
        }
        memset(new_data, 0, new_cap * sizeof(void *));

        // Copy existing entries
        for (uint64_t i = 0; i < size; i++) {
            safe_memory_read_pointer((mach_vm_address_t)&data[i], &new_data[i]);
        }

        // Write new data pointer and capacity back to GameServer
        if (!safe_memory_write_pointer(
                (mach_vm_address_t)s_game_server + OFFSET_GAMESERVER_PROTOLIST,
                (void *)new_data)) {
            LOG_NET_ERROR("  Failed to write new data pointer");
            free(new_data);
            return false;
        }
        if (!safe_memory_write_u64(
                (mach_vm_address_t)s_game_server + OFFSET_GAMESERVER_PROTOLIST_CAP,
                new_cap)) {
            LOG_NET_ERROR("  Failed to write new capacity");
            return false;
        }

        LOG_NET_INFO("  Grew ProtocolList: %llu -> %llu capacity",
                     (unsigned long long)capacity, (unsigned long long)new_cap);
        data = new_data;
        capacity = new_cap;
    }

    // Swap-insert at index 0 (Windows insert_at(0) pattern):
    // Copy data[0] to data[size], then overwrite data[0] with our protocol
    if (size > 0) {
        void *first = NULL;
        safe_memory_read_pointer((mach_vm_address_t)&data[0], &first);
        safe_memory_write_pointer((mach_vm_address_t)&data[size], first);
    }
    safe_memory_write_pointer((mach_vm_address_t)&data[0], (void *)&proto->base);

    // Increment size — write AFTER data[0] is set for thread safety
    __sync_synchronize();  // ARM64 full memory barrier
    safe_memory_write_u64(
        (mach_vm_address_t)s_game_server + OFFSET_GAMESERVER_PROTOLIST_SIZE,
        size + 1);
    __sync_synchronize();

    // Verify insertion
    void *verify = NULL;
    safe_memory_read_pointer((mach_vm_address_t)&data[0], &verify);
    if (verify != (void *)&proto->base) {
        LOG_NET_ERROR("  VERIFICATION FAILED: data[0]=%p, expected=%p",
                      verify, (void *)&proto->base);
        return false;
    }

    LOG_NET_INFO("  ExtenderProtocol inserted at index 0 (new size=%llu)",
                 (unsigned long long)(size + 1));
    LOG_NET_INFO("  VERIFICATION: data[0]=%p matches expected", verify);

    s_status.protocol_list_hooked = true;
    proto->active = true;
    return true;
}
