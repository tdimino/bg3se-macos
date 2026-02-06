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
#include "peer_manager.h"
#include "network_backend.h"
#include "../core/logging.h"
#include "../core/safe_memory.h"
#include "../game/game_state.h"        // game_state_get_current()
#include "../entity/entity_system.h"   // entity_get_binary_base(), entity_get_eoc_server()
#include <dobby.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

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

// Outbound send state (Phase 4G)
static bool s_send_vmt_probed = false;
static void *s_send_fn = NULL;  // Resolved SendToPeer function pointer

// Forward declarations (Phase 4I)
static void send_client_hello(void);

// Forward declaration for deferred state reset (Issue #65)
static void deferred_state_reset(void);

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

    // Read size as uint32_t (Larian Array uses packed {ptr, u32 cap, u32 size})
    uint32_t size32 = 0;
    if (!safe_memory_read_u32((mach_vm_address_t)game_server + size_offset, &size32)) return 0;
    uint64_t size = size32;

    // Sanity check: protocol count should be reasonable (typically 3-50)
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
            uint32_t size32 = 0;
            safe_memory_read_u32((mach_vm_address_t)s_game_server + OFFSET_GAMESERVER_PROTOLIST_SIZE, &size32);
            uint64_t size = size32;

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
                    safe_memory_write_u32(
                        (mach_vm_address_t)s_game_server + OFFSET_GAMESERVER_PROTOLIST_SIZE,
                        (uint32_t)(size - 1));
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
    s_send_vmt_probed = false;
    s_send_fn = NULL;

    // Reset deferred state machine (Issue #65)
    deferred_state_reset();
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
    // Idempotency guard: DobbyHook on same address twice is undefined
    if (s_status.message_factory_hooked) {
        LOG_NET_INFO("net_hooks_register_message: already hooked, skipping");
        return true;
    }

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

// ============================================================================
// Outbound Send (Phase 4G)
//
// Sends an ExtenderMessage to a specific peer using the game's transport.
// Uses GameServer VMT dispatch: SendToPeer at Itanium index 28.
//
// ARM64 calling convention:
//   x0 = this (GameServer*/AbstractPeer*)
//   x1 = &peerId (int32_t*, passed by pointer — Windows pattern)
//   x2 = msg (Message*)
// ============================================================================

/**
 * Probe GameServer VMT to discover and validate SendToPeer.
 * One-time operation on first send attempt.
 */
static bool probe_send_vmt(void) {
    if (s_send_vmt_probed) return (s_send_fn != NULL);

    if (!s_game_server) {
        LOG_NET_WARN("probe_send_vmt: GameServer not captured");
        return false;
    }

    void **vmt = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)s_game_server, (void **)&vmt)) {
        LOG_NET_WARN("probe_send_vmt: failed to read GameServer VMT");
        return false;
    }

    LOG_NET_INFO("probe_send_vmt: GameServer=%p, VMT=%p", s_game_server, (void *)vmt);

    // Read SendToPeer at expected index
    void *fn = NULL;
    if (!safe_memory_read_pointer(
            (mach_vm_address_t)&vmt[VMT_IDX_SEND_TO_PEER], &fn)) {
        LOG_NET_WARN("probe_send_vmt: failed to read VMT[%d]", VMT_IDX_SEND_TO_PEER);
        return false;
    }

    if (!fn) {
        LOG_NET_WARN("probe_send_vmt: VMT[%d] is NULL", VMT_IDX_SEND_TO_PEER);
        return false;
    }

    // Log nearby VMT entries for diagnostic verification
    LOG_NET_INFO("  VMT entries around SendToPeer (index %d):", VMT_IDX_SEND_TO_PEER);
    for (int i = VMT_IDX_SEND_TO_PEER - 2; i <= VMT_IDX_SEND_TO_PEER + 2; i++) {
        if (i < 0) continue;
        void *entry = NULL;
        safe_memory_read_pointer((mach_vm_address_t)&vmt[i], &entry);
        LOG_NET_INFO("    VMT[%d] = %p%s", i, entry,
                     (i == VMT_IDX_SEND_TO_PEER) ? " <-- SendToPeer" : "");
    }

    s_send_fn = fn;
    s_send_vmt_probed = true;  // Only mark probed after successful resolution
    LOG_NET_INFO("  SendToPeer resolved: %p", s_send_fn);
    return true;
}

bool net_hooks_send_message(int32_t peer_id, void *msg) {
    if (!s_game_server) {
        LOG_NET_WARN("net_hooks_send_message: GameServer not captured");
        return false;
    }
    if (!msg) {
        LOG_NET_WARN("net_hooks_send_message: NULL message");
        return false;
    }

    if (!probe_send_vmt()) {
        LOG_NET_WARN("net_hooks_send_message: SendToPeer not resolved");
        return false;
    }

    LOG_NET_DEBUG("net_hooks_send_message: peer=%d, msg=%p via SendToPeer=%p",
                  peer_id, msg, s_send_fn);

    // Call SendToPeer(this, &peerId, msg)
    // ARM64: x0=GameServer*, x1=&peerId, x2=Message*
    typedef void (*SendToPeer_t)(void *self, int32_t *peer_id_ptr, void *msg);
    int32_t pid = peer_id;
    ((SendToPeer_t)s_send_fn)(s_game_server, &pid, msg);

    return true;
}

void *net_hooks_get_game_server(void) {
    return s_game_server;
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
    // Read current data/capacity/size from GameServer offsets.
    // Larian Array<T> layout: {data_ptr(8), capacity(u32), size(u32)} = 16 bytes.
    void *data_raw = safe_read_ptr(s_game_server, OFFSET_GAMESERVER_PROTOLIST);
    uint32_t capacity32 = 0, size32 = 0;
    if (!safe_memory_read_u32((mach_vm_address_t)s_game_server + OFFSET_GAMESERVER_PROTOLIST_CAP, &capacity32)) {
        LOG_NET_WARN("  Failed to read ProtocolList capacity");
        return false;
    }
    if (!safe_memory_read_u32((mach_vm_address_t)s_game_server + OFFSET_GAMESERVER_PROTOLIST_SIZE, &size32)) {
        LOG_NET_WARN("  Failed to read ProtocolList size");
        return false;
    }
    uint64_t capacity = capacity32;
    uint64_t size = size32;

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
        if (!safe_memory_write_u32(
                (mach_vm_address_t)s_game_server + OFFSET_GAMESERVER_PROTOLIST_CAP,
                (uint32_t)new_cap)) {
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
    safe_memory_write_u32(
        (mach_vm_address_t)s_game_server + OFFSET_GAMESERVER_PROTOLIST_SIZE,
        (uint32_t)(size + 1));
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

    // Switch to RakNet backend now that protocol is fully inserted (Phase 4I)
    // Moved from net_hooks_capture_peer() — must happen AFTER protocol insertion
    // so incoming messages can be dispatched through our ExtenderProtocol.
    // NOTE: Must switch backend BEFORE marking host peer ready, otherwise
    // messages could be routed through LocalBackend instead of RakNet.
    network_backend_set_raknet();

    // Mark the host peer as handshake-complete (Phase 4I).
    // The host always has the extender (it's us), so set proto_version directly.
    // This ensures raknet_send() gating passes for the local host peer.
    PeerInfo *host = peer_manager_get_host();
    if (host) {
        peer_manager_set_proto_version(host->user_id, PROTO_VERSION_CURRENT);
    }

    // Send hello to server if we're a client (Phase 4I handshake)
    send_client_hello();

    return true;
}

// ============================================================================
// Client Hello (Phase 4I)
//
// Sends a JSON hello message to the server after protocol insertion.
// The server will reply with its own hello, completing the handshake.
// Wire format: {"t":"hello","v":2}
// ============================================================================

static void send_client_hello(void) {
    // Build hello JSON with current protocol version
    char hello[64];
    snprintf(hello, sizeof(hello), "{\"t\":\"hello\",\"v\":%d}", PROTO_VERSION_CURRENT);

    // Create ExtenderMessage with hello payload
    ExtenderMessage *msg = extender_message_pool_get();
    if (!msg) {
        LOG_NET_WARN("send_client_hello: pool exhausted, skipping hello");
        return;
    }

    if (!extender_message_set_payload(msg, hello, (uint32_t)strlen(hello))) {
        LOG_NET_WARN("send_client_hello: failed to set payload");
        extender_message_pool_return(msg);
        return;
    }

    // Send to server (peer 0)
    bool ok = net_hooks_send_message(0, &msg->base);
    if (ok) {
        LOG_NET_INFO("Sent client hello to server (version %d)", PROTO_VERSION_CURRENT);
    } else {
        LOG_NET_WARN("send_client_hello: send failed");
        extender_message_pool_return(msg);
    }
}

// ============================================================================
// ActivePeerIds Sync (Phase 4H)
//
// Reads the GameServer's ActivePeerIds array and registers any unknown
// peers into PeerManager. Called before broadcast to ensure coverage.
//
// GameServer+0x650: peer array data pointer
// GameServer+0x65c: peer count (uint32_t)
//
// NOTE: This may be a hash container, not a flat array. If direct read
// produces invalid peer IDs, the function returns 0 and broadcast falls
// back to implicit peer registration from extender_process_msg.
// ============================================================================

int net_hooks_sync_active_peers(void) {
    if (!s_game_server) return 0;

    // Read peer array data pointer
    void *peer_data = safe_read_ptr(s_game_server, OFFSET_GAMESERVER_ACTIVE_PEERS);
    if (!peer_data) return 0;

    // Read peer count (32-bit)
    uint32_t peer_count = 0;
    if (!safe_memory_read_u32(
            (mach_vm_address_t)s_game_server + OFFSET_GAMESERVER_ACTIVE_PEERS_COUNT,
            &peer_count)) {
        return 0;
    }

    // Sanity: BG3 supports max ~4 players, but allow headroom
    if (peer_count == 0 || peer_count > MAX_PEERS) return 0;

    int synced = 0;
    for (uint32_t i = 0; i < peer_count; i++) {
        int32_t peer_id = 0;
        if (!safe_memory_read_u32(
                (mach_vm_address_t)peer_data + (i * sizeof(int32_t)),
                (uint32_t *)&peer_id)) {
            continue;
        }

        // Sanity: peer IDs should be small non-negative integers
        if (peer_id < 0 || peer_id > 64) continue;

        if (!peer_manager_get_peer(peer_id)) {
            peer_manager_add_peer(peer_id, NULL, (peer_id == 0));
            synced++;
        }
    }

    if (synced > 0) {
        LOG_NET_DEBUG("net_hooks_sync_active_peers: synced %d new peers (total in array: %u)",
                      synced, peer_count);
    } else if (peer_count > 0) {
        // Check if we already knew about all peers, or if the data is garbage
        int known = 0;
        for (uint32_t i = 0; i < peer_count; i++) {
            int32_t pid = 0;
            if (safe_memory_read_u32(
                    (mach_vm_address_t)peer_data + (i * sizeof(int32_t)),
                    (uint32_t *)&pid) && pid >= 0 && pid <= 64) {
                if (peer_manager_get_peer(pid)) known++;
            }
        }
        if (known == 0) {
            static bool s_hash_warning_logged = false;
            if (!s_hash_warning_logged) {
                LOG_NET_WARN("net_hooks_sync_active_peers: 0/%u peer IDs valid — "
                             "OFFSET_GAMESERVER_ACTIVE_PEERS (0x%X) may be wrong",
                             peer_count, OFFSET_GAMESERVER_ACTIVE_PEERS);
                s_hash_warning_logged = true;
            }
        }
    }

    return synced;
}

// ============================================================================
// Deferred Initialization State Machine (Issue #65)
//
// Moves ~65 mach_vm_read_overwrite kernel calls out of the timing-sensitive
// COsiris::Load path into the tick loop. On some machines, performing these
// kernel calls during save load causes the game to abort the session.
//
// The state machine waits for the game to be in Running state for at least
// DEFERRED_STABILITY_MS before attempting capture. On failure, it retries
// with exponential backoff up to MAX_RETRIES times.
// ============================================================================

typedef enum {
    DEFERRED_IDLE = 0,      // No init requested
    DEFERRED_PENDING,       // Init requested, waiting for stability
    DEFERRED_CAPTURING,     // About to perform capture (transient)
    DEFERRED_COMPLETE,      // Successfully initialized
    DEFERRED_FAILED         // All retries exhausted
} DeferredState;

#define DEFERRED_STABILITY_MS  500   // Wait 500ms in Running before capture
#define DEFERRED_MAX_RETRIES   3     // Max retry attempts
#define DEFERRED_BASE_DELAY_MS 1000  // Initial retry delay (doubles each time)

static DeferredState s_deferred_state = DEFERRED_IDLE;
static clock_t       s_deferred_running_since = 0;  // When Running state was first seen
static int           s_deferred_retries = 0;
static clock_t       s_deferred_retry_after = 0;    // Don't retry before this time

static void deferred_state_reset(void) {
    s_deferred_state = DEFERRED_IDLE;
    s_deferred_running_since = 0;
    s_deferred_retries = 0;
    s_deferred_retry_after = 0;
}

/** Calculate backoff delay for a given retry count (0-based). */
static int deferred_backoff_ms(int retry_count) {
    int shift = (retry_count > 0) ? retry_count - 1 : 0;
    return DEFERRED_BASE_DELAY_MS * (1 << shift);
}

void net_hooks_request_deferred_init(void) {
    // Already complete — nothing to do
    if (s_deferred_state == DEFERRED_COMPLETE) {
        LOG_NET_DEBUG("net_hooks_request_deferred_init: already complete, skipping");
        return;
    }
    // In progress — don't restart
    if (s_deferred_state == DEFERRED_PENDING ||
        s_deferred_state == DEFERRED_CAPTURING) {
        LOG_NET_DEBUG("net_hooks_request_deferred_init: already in progress (state %d)",
                      s_deferred_state);
        return;
    }
    // Allow retry from FAILED state on save reload (Issue #65)
    if (s_deferred_state == DEFERRED_FAILED) {
        LOG_NET_INFO("net_hooks_request_deferred_init: retrying after previous failure");
    }

    // Check BG3SE_NO_NET env var
    static int net_disabled = -1;
    if (net_disabled < 0) net_disabled = (getenv("BG3SE_NO_NET") != NULL);
    if (net_disabled) {
        static bool warned = false;
        if (!warned) {
            LOG_NET_INFO("Network hooks DISABLED (BG3SE_NO_NET=1)");
            warned = true;
        }
        s_deferred_state = DEFERRED_FAILED;
        return;
    }

    // Skip if already initialized
    if (s_status.protocol_list_hooked) {
        LOG_NET_DEBUG("net_hooks_request_deferred_init: already hooked, skipping");
        s_deferred_state = DEFERRED_COMPLETE;
        return;
    }

    s_deferred_state = DEFERRED_PENDING;
    s_deferred_running_since = 0;
    s_deferred_retries = 0;
    s_deferred_retry_after = 0;
    LOG_NET_INFO("Network init DEFERRED to tick loop (Issue #65)");
}

bool net_hooks_deferred_tick(void) {
    if (s_deferred_state == DEFERRED_IDLE ||
        s_deferred_state == DEFERRED_COMPLETE ||
        s_deferred_state == DEFERRED_FAILED) {
        return false;
    }

    clock_t now = clock();

    // PENDING: wait for Running state stability
    if (s_deferred_state == DEFERRED_PENDING) {
        ServerGameState state = game_state_get_current();
        if (state != SERVER_STATE_RUNNING) {
            // Not in Running yet — reset stability timer
            s_deferred_running_since = 0;
            return false;
        }

        if (s_deferred_running_since == 0) {
            s_deferred_running_since = now;
            return false;
        }

        double elapsed_ms = (double)(now - s_deferred_running_since) * 1000.0 / CLOCKS_PER_SEC;
        if (elapsed_ms < DEFERRED_STABILITY_MS) {
            return false;  // Keep waiting
        }

        // Check retry backoff
        if (s_deferred_retry_after != 0) {
            double retry_elapsed_ms = (double)(now - s_deferred_retry_after) * 1000.0 / CLOCKS_PER_SEC;
            if (retry_elapsed_ms < deferred_backoff_ms(s_deferred_retries)) {
                return false;  // Still in backoff
            }
        }

        LOG_NET_INFO("Deferred net init: Running stable for %.0fms, attempting capture (attempt %d/%d)",
                     elapsed_ms, s_deferred_retries + 1, DEFERRED_MAX_RETRIES);
        s_deferred_state = DEFERRED_CAPTURING;
    }

    // CAPTURING: perform the actual initialization
    if (s_deferred_state == DEFERRED_CAPTURING) {
        void *eoc_server = entity_get_eoc_server();
        if (!eoc_server) {
            LOG_NET_WARN("Deferred net init: EocServer not available");
            goto retry;
        }

        if (!net_hooks_capture_peer(eoc_server)) {
            LOG_NET_WARN("Deferred net init: capture_peer failed");
            goto retry;
        }

        if (!net_hooks_register_message()) {
            LOG_NET_WARN("Deferred net init: register_message failed");
            goto retry;
        }

        if (!net_hooks_insert_protocol()) {
            LOG_NET_WARN("Deferred net init: insert_protocol failed");
            goto retry;
        }

        LOG_NET_INFO("Deferred net init: COMPLETE (attempt %d)", s_deferred_retries + 1);
        s_deferred_state = DEFERRED_COMPLETE;
        return true;

    retry:
        s_deferred_retries++;
        if (s_deferred_retries >= DEFERRED_MAX_RETRIES) {
            LOG_NET_ERROR("Deferred net init: FAILED after %d attempts", DEFERRED_MAX_RETRIES);
            s_deferred_state = DEFERRED_FAILED;
            return false;
        }

        // Exponential backoff
        s_deferred_retry_after = now;
        s_deferred_running_since = 0;  // Re-check stability
        s_deferred_state = DEFERRED_PENDING;
        LOG_NET_INFO("Deferred net init: retry %d/%d in %dms",
                     s_deferred_retries, DEFERRED_MAX_RETRIES,
                     deferred_backoff_ms(s_deferred_retries));
        return false;
    }

    return false;
}

bool net_hooks_is_ready(void) {
    return s_deferred_state == DEFERRED_COMPLETE ||
           s_status.protocol_list_hooked;
}
