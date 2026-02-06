/**
 * BG3SE-macOS - Extender Message Implementation
 *
 * Custom network message (ID 400) with serialization support.
 * Wire format matches Windows BG3SE: [4-byte LE size][payload]
 *
 * Issue #6: NetChannel API (Phase 4B)
 */

#include "extender_message.h"
#include "../core/logging.h"
#include "../core/safe_memory.h"
#include <stdlib.h>
#include <string.h>

// ============================================================================
// VMT Implementations
//
// These match the Windows net::Message virtual function signatures.
// In Phase 4D, the game may call these through the VMT pointer when
// our message is registered with the NetMessageFactory.
// ============================================================================

static void em_complete_destructor(MessageBase *self) {
    LOG_NET_DEBUG("ExtenderMessage complete destructor called");
    ExtenderMessage *em = (ExtenderMessage *)self;
    if (em->payload) {
        free(em->payload);
        em->payload = NULL;
    }
}

static void em_deleting_destructor(MessageBase *self) {
    LOG_NET_DEBUG("ExtenderMessage deleting destructor called");
    ExtenderMessage *em = (ExtenderMessage *)self;
    if (em->payload) {
        free(em->payload);
        em->payload = NULL;
    }
    free(em);
}

static void em_serialize(MessageBase *self, void *serializer) {
    ExtenderMessage *em = (ExtenderMessage *)self;

    LOG_NET_INFO("ExtenderMessage::Serialize called: self=%p, serializer=%p",
                 (void *)self, serializer);

    if (!serializer) {
        LOG_NET_WARN("  Serialize: NULL serializer");
        return;
    }

    // Diagnostic: dump first 64 bytes of serializer for layout discovery.
    // The game calls msg->Serialize(serializer) where serializer is a
    // BitstreamSerializer. We need to discover:
    //   - IsWriting flag (bool/uint8_t at some offset)
    //   - ReadBytes/WriteBytes method pointers or inline functions
    //
    // This diagnostic runs until BitstreamSerializer RE is complete (Phase 4G).
    LOG_NET_INFO("  Serializer dump (first 64 bytes):");
    for (int i = 0; i < 64; i += 8) {
        uint64_t val = 0;
        if (safe_memory_read_u64((mach_vm_address_t)serializer + i, &val)) {
            LOG_NET_INFO("    +0x%02x: 0x%016llx", i, (unsigned long long)val);
        } else {
            LOG_NET_INFO("    +0x%02x: <unreadable>", i);
            break;
        }
    }

    // Heuristic: try common IsWriting offsets (0x08, 0x10, 0x18)
    // If IsWriting==0 (deserializing), we're receiving a message.
    // If IsWriting==1 (serializing), we're sending a message.
    for (int off = 0x08; off <= 0x18; off += 0x08) {
        uint8_t flag = 0xFF;
        if (safe_memory_read_u8((mach_vm_address_t)serializer + off, &flag)) {
            if (flag == 0 || flag == 1) {
                LOG_NET_INFO("  Candidate IsWriting at +0x%02x = %u", off, flag);
            }
        }
    }

    LOG_NET_INFO("  Payload state: valid=%d, size=%u",
                 em->valid, em->payload_size);
}

static void em_unknown(MessageBase *self) {
    (void)self;
}

static MessageBase *em_create_new(MessageBase *self) {
    (void)self;
    ExtenderMessage *msg = extender_message_create();
    return msg ? &msg->base : NULL;
}

static void em_reset(MessageBase *self) {
    ExtenderMessage *em = (ExtenderMessage *)self;
    if (em->payload) {
        free(em->payload);
        em->payload = NULL;
    }
    em->payload_size = 0;
    em->valid = false;
}

// ============================================================================
// Itanium C++ ABI Vtable Block
//
// Layout in memory:
//   [offset_to_top = 0]         <- preamble
//   [typeinfo = NULL]            <- preamble
//   [complete_destructor]        <- vmt[0]  (vptr points here)
//   [deleting_destructor]        <- vmt[1]
//   [serialize]                  <- vmt[2]
//   [unknown]                    <- vmt[3]
//   [create_new]                 <- vmt[4]
//   [reset]                      <- vmt[5]
//
// MessageBase.vmt points to &s_vtable_block.vmt (past the preamble).
// ============================================================================

static const MessageVtableBlock s_vtable_block = {
    .preamble = {
        .offset_to_top = 0,
        .typeinfo = NULL,
    },
    .vmt = {
        .complete_destructor = em_complete_destructor,
        .deleting_destructor = em_deleting_destructor,
        .serialize  = em_serialize,
        .unknown    = em_unknown,
        .create_new = em_create_new,
        .reset      = em_reset,
    },
};

// ============================================================================
// Public API
// ============================================================================

static void init_message_base(MessageBase *base) {
    base->vmt = &s_vtable_block.vmt;
    base->msg_id = NETMSG_SCRIPT_EXTENDER;
    base->reliability = 4;
    base->priority = 1;
    base->ordering_sequence = 0;
    base->timestamped = false;
    base->_pad[0] = 0;
    base->_pad[1] = 0;
    base->timestamp = 0;
    base->original_size = 0;
    base->latency = 0.0f;
}

ExtenderMessage *extender_message_create(void) {
    ExtenderMessage *msg = calloc(1, sizeof(ExtenderMessage));
    if (!msg) {
        LOG_NET_ERROR("Failed to allocate ExtenderMessage");
        return NULL;
    }

    init_message_base(&msg->base);
    msg->payload = NULL;
    msg->payload_size = 0;
    msg->valid = false;

    return msg;
}

void extender_message_destroy(ExtenderMessage *msg) {
    if (!msg) return;

    if (msg->payload) {
        free(msg->payload);
        msg->payload = NULL;
    }

    free(msg);
}

void extender_message_reset(ExtenderMessage *msg) {
    if (!msg) return;

    if (msg->payload) {
        free(msg->payload);
        msg->payload = NULL;
    }
    msg->payload_size = 0;
    msg->valid = false;
}

bool extender_message_set_payload(ExtenderMessage *msg,
                                   const void *data, uint32_t size) {
    if (!msg) return false;

    if (size > MAX_EXTENDER_PAYLOAD) {
        LOG_NET_ERROR("Payload too large: %u bytes (max %u)",
                      size, MAX_EXTENDER_PAYLOAD);
        return false;
    }

    // Free existing payload
    if (msg->payload) {
        free(msg->payload);
        msg->payload = NULL;
    }

    if (data && size > 0) {
        msg->payload = malloc(size);
        if (!msg->payload) {
            LOG_NET_ERROR("Failed to allocate payload (%u bytes)", size);
            msg->payload_size = 0;
            msg->valid = false;
            return false;
        }
        memcpy(msg->payload, data, size);
        msg->payload_size = size;
        msg->valid = true;
    } else {
        msg->payload_size = 0;
        msg->valid = false;
    }

    return true;
}

uint32_t extender_message_serialize(const ExtenderMessage *msg,
                                     void *out, uint32_t out_sz) {
    if (!msg || !out) return 0;

    uint32_t total = extender_message_serialized_size(msg);
    if (total == 0 || out_sz < total) return 0;

    uint8_t *buf = (uint8_t *)out;

    // Write 4-byte LE size prefix
    uint32_t size_le = msg->payload_size;
    memcpy(buf, &size_le, sizeof(uint32_t));
    buf += sizeof(uint32_t);

    // Write payload
    if (msg->payload && msg->payload_size > 0) {
        memcpy(buf, msg->payload, msg->payload_size);
    }

    return total;
}

uint32_t extender_message_deserialize(ExtenderMessage *msg,
                                       const void *data, uint32_t size) {
    if (!msg || !data) return 0;

    // Need at least 4 bytes for the size prefix
    if (size < sizeof(uint32_t)) {
        LOG_NET_ERROR("Buffer too small for size prefix: %u bytes", size);
        return 0;
    }

    // Read 4-byte LE size prefix
    uint32_t payload_size = 0;
    memcpy(&payload_size, data, sizeof(uint32_t));

    if (payload_size > MAX_EXTENDER_PAYLOAD) {
        LOG_NET_ERROR("Payload size too large: %u (max %u)",
                      payload_size, MAX_EXTENDER_PAYLOAD);
        return 0;
    }

    uint32_t total = sizeof(uint32_t) + payload_size;
    if (size < total) {
        LOG_NET_ERROR("Buffer too small: need %u, have %u", total, size);
        return 0;
    }

    // Set payload
    if (payload_size > 0) {
        const uint8_t *payload_data = (const uint8_t *)data + sizeof(uint32_t);
        if (!extender_message_set_payload(msg, payload_data, payload_size)) {
            return 0;
        }
    } else {
        extender_message_reset(msg);
    }

    return total;
}

uint32_t extender_message_serialized_size(const ExtenderMessage *msg) {
    if (!msg) return 0;
    return sizeof(uint32_t) + msg->payload_size;
}

// ============================================================================
// Message Pool
//
// Pre-allocated pool of ExtenderMessages for the GetMessage hook.
// Avoids malloc in the hot path. Falls back to malloc if exhausted.
// ============================================================================

static ExtenderMessage s_msg_pool[EXTMSG_POOL_SIZE];
static bool s_pool_in_use[EXTMSG_POOL_SIZE];
static bool s_pool_initialized = false;

void extender_message_pool_init(void) {
    if (s_pool_initialized) return;

    for (int i = 0; i < EXTMSG_POOL_SIZE; i++) {
        memset(&s_msg_pool[i], 0, sizeof(ExtenderMessage));
        init_message_base(&s_msg_pool[i].base);
        s_pool_in_use[i] = false;
    }
    s_pool_initialized = true;
    LOG_NET_DEBUG("ExtenderMessage pool initialized (%d slots)", EXTMSG_POOL_SIZE);
}

ExtenderMessage *extender_message_pool_get(void) {
    if (!s_pool_initialized) {
        extender_message_pool_init();
    }

    for (int i = 0; i < EXTMSG_POOL_SIZE; i++) {
        if (!s_pool_in_use[i]) {
            s_pool_in_use[i] = true;
            extender_message_reset(&s_msg_pool[i]);
            init_message_base(&s_msg_pool[i].base);
            LOG_NET_DEBUG("Pool: allocated slot %d", i);
            return &s_msg_pool[i];
        }
    }

    // Pool exhausted — fall back to heap allocation
    LOG_NET_WARN("ExtenderMessage pool exhausted, falling back to malloc");
    return extender_message_create();
}

void extender_message_pool_return(ExtenderMessage *msg) {
    if (!msg) return;

    // Check if this message is from our pool
    for (int i = 0; i < EXTMSG_POOL_SIZE; i++) {
        if (msg == &s_msg_pool[i]) {
            extender_message_reset(msg);
            s_pool_in_use[i] = false;
            LOG_NET_DEBUG("Pool: returned slot %d", i);
            return;
        }
    }

    // Not from pool — was malloc'd as fallback, free it
    extender_message_destroy(msg);
}
