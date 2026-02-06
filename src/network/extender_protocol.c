/**
 * BG3SE-macOS - Extender Protocol Implementation
 *
 * Custom protocol inserted at index 0 of the game's ProtocolList.
 * Intercepts NETMSG_SCRIPT_EXTENDER (ID 400) messages and routes
 * them to the message bus for Lua event dispatch.
 *
 * Uses Itanium C++ ABI vtable layout for macOS ARM64 compatibility.
 * See protocol.h for the vtable structure.
 *
 * Issue #6: NetChannel API (Phase 4D)
 */

#include "extender_protocol.h"
#include "extender_message.h"
#include "message_bus.h"
#include "peer_manager.h"
#include "../core/logging.h"
#include "../core/safe_memory.h"
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Static State
// ============================================================================

static ExtenderProtocol *s_instance = NULL;

// ============================================================================
// VMT Function Implementations
//
// These match the game's net::Protocol virtual function signatures.
// The game will call these through our Itanium-compatible vtable.
// ============================================================================

static void extender_destructor(Protocol *self) {
    LOG_NET_DEBUG("ExtenderProtocol destructor called");

    ExtenderProtocol *ep = (ExtenderProtocol *)self;
    if (ep == s_instance) {
        s_instance = NULL;
    }
}

static void extender_deleting_destructor(Protocol *self) {
    LOG_NET_DEBUG("ExtenderProtocol deleting destructor called");

    ExtenderProtocol *ep = (ExtenderProtocol *)self;
    if (ep == s_instance) {
        s_instance = NULL;
    }
    free(ep);
}

/**
 * Process an incoming network message.
 *
 * Checks if msg->MessageId == NETMSG_SCRIPT_EXTENDER (400).
 * If so, deserializes the payload and routes to message_bus.
 * Otherwise returns Unhandled to pass through the protocol chain.
 */
static ProtocolResult extender_process_msg(Protocol *self, void *unused,
                                           MessageContext *ctx, void *msg) {
    (void)self;
    (void)unused;

    if (!msg) {
        return PROTOCOL_RESULT_UNHANDLED;
    }

    // The game's net::Message has msg_id at offset 8 (after vptr)
    uint32_t msg_id = 0;
    if (!safe_memory_read_u32((mach_vm_address_t)msg + 8, &msg_id)) {
        return PROTOCOL_RESULT_UNHANDLED;
    }

    if (msg_id != NETMSG_SCRIPT_EXTENDER) {
        return PROTOCOL_RESULT_UNHANDLED;
    }

    int32_t sender = ctx ? ctx->user_id : -1;
    LOG_NET_INFO("ExtenderProtocol: received NETMSG_SCRIPT_EXTENDER from user %d", sender);

    // Cast to ExtenderMessage (our GetMessage hook returned this from the pool)
    ExtenderMessage *em = (ExtenderMessage *)msg;

    // At this point, the game has already called em_serialize(deserializer).
    // Once BitstreamSerializer RE is complete (Phase 4G), em->payload will
    // contain the deserialized payload bytes.
    if (!em->payload || em->payload_size == 0) {
        LOG_NET_DEBUG("  ExtenderMessage has no payload (em_serialize is diagnostic-only)");
        extender_message_pool_return(em);
        return PROTOCOL_RESULT_HANDLED;
    }

    // Parse the payload as a JSON-encoded NetMessage.
    // Expected format: {"Channel":"ch","Module":"mod","Payload":"data",...}
    // For now, treat the entire payload as the message payload on a default channel.
    LOG_NET_INFO("  Processing %u-byte payload from user %d", em->payload_size, sender);

    NetMessage net_msg = message_create_to_server("", "", "", 0);
    net_msg.user_id = sender;

    // Copy raw payload as the message content
    net_msg.payload = malloc(em->payload_size + 1);
    if (net_msg.payload) {
        memcpy(net_msg.payload, em->payload, em->payload_size);
        net_msg.payload[em->payload_size] = '\0';
        net_msg.payload_len = em->payload_size;

        if (!message_bus_queue_from_peer(sender, &net_msg)) {
            LOG_NET_WARN("  Failed to queue message from peer %d", sender);
        }
        free(net_msg.payload);
        net_msg.payload = NULL;
    }

    // Return message to pool
    extender_message_pool_return(em);

    return PROTOCOL_RESULT_HANDLED;
}

static ProtocolResult extender_pre_update(Protocol *self, void *game_time) {
    (void)self;
    (void)game_time;
    return PROTOCOL_RESULT_UNHANDLED;
}

static ProtocolResult extender_post_update(Protocol *self, void *game_time) {
    (void)self;
    (void)game_time;
    return PROTOCOL_RESULT_UNHANDLED;
}

static void extender_on_added_to_host(Protocol *self) {
    (void)self;
    LOG_NET_INFO("ExtenderProtocol added to host");

    ExtenderProtocol *ep = (ExtenderProtocol *)self;
    ep->active = true;
}

static void extender_on_removed_from_host(Protocol *self) {
    (void)self;
    LOG_NET_INFO("ExtenderProtocol removed from host");

    ExtenderProtocol *ep = (ExtenderProtocol *)self;
    ep->active = false;
}

static void extender_reset(Protocol *self) {
    (void)self;
    LOG_NET_DEBUG("ExtenderProtocol reset");
}

// ============================================================================
// Itanium C++ ABI Vtable Block
//
// Layout in memory:
//   [offset_to_top = 0]         <- preamble
//   [typeinfo = NULL]            <- preamble
//   [complete_destructor]        <- vmt[0]  (vptr points here)
//   [deleting_destructor]        <- vmt[1]
//   [process_msg]                <- vmt[2]
//   [pre_update]                 <- vmt[3]
//   [post_update]                <- vmt[4]
//   [on_added_to_host]           <- vmt[5]
//   [on_removed_from_host]       <- vmt[6]
//   [reset]                      <- vmt[7]
//
// Protocol.vmt points to &s_vtable_block.vmt (past the preamble).
// ============================================================================

static const ProtocolVtableBlock s_vtable_block = {
    .preamble = {
        .offset_to_top = 0,
        .typeinfo = NULL,
    },
    .vmt = {
        .complete_destructor = extender_destructor,
        .deleting_destructor = extender_deleting_destructor,
        .process_msg         = extender_process_msg,
        .pre_update          = extender_pre_update,
        .post_update         = extender_post_update,
        .on_added_to_host    = extender_on_added_to_host,
        .on_removed_from_host = extender_on_removed_from_host,
        .reset               = extender_reset,
    },
};

// ============================================================================
// Public API
// ============================================================================

ExtenderProtocol *extender_protocol_create(void) {
    ExtenderProtocol *proto = calloc(1, sizeof(ExtenderProtocol));
    if (!proto) {
        LOG_NET_ERROR("Failed to allocate ExtenderProtocol");
        return NULL;
    }

    // Point vmt past the preamble to the actual function table
    proto->base.vmt = &s_vtable_block.vmt;
    proto->base.peer = NULL;  // Set when added to ProtocolList
    proto->active = false;

    LOG_NET_DEBUG("Created ExtenderProtocol at %p (vmt=%p)", (void *)proto, (void *)&s_vtable_block.vmt);
    return proto;
}

void extender_protocol_destroy(ExtenderProtocol *proto) {
    if (!proto) return;

    LOG_NET_DEBUG("Destroying ExtenderProtocol at %p", (void *)proto);

    if (proto == s_instance) {
        s_instance = NULL;
    }

    free(proto);
}

ExtenderProtocol *extender_protocol_get(void) {
    if (!s_instance) {
        s_instance = extender_protocol_create();
    }
    return s_instance;
}

bool extender_protocol_is_active(void) {
    return s_instance && s_instance->active;
}
