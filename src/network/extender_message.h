/**
 * BG3SE-macOS - Extender Message
 *
 * Custom network message (ID 400) for Script Extender communication.
 * Matches the Windows BG3SE ExtenderMessage class layout.
 *
 * Windows reference: BG3Extender/Extender/Shared/ExtenderNet.h
 * Windows net::Message VMT: Dtor, Serialize, Unknown, CreateNew, Reset
 *
 * Wire format: [4-byte LE size][payload bytes]
 * Payload is a serialized Lua message (JSON or binary).
 *
 * Issue #6: NetChannel API (Phase 4B)
 */

#ifndef EXTENDER_MESSAGE_H
#define EXTENDER_MESSAGE_H

#include "protocol.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// ============================================================================
// Message VMT — Itanium C++ ABI Layout (macOS ARM64)
//
// The Itanium ABI places TWO destructor entries in the vtable,
// matching the Protocol_VMT layout in protocol.h:
//   [0] complete_destructor  — destroys object, no deallocation
//   [1] deleting_destructor  — destroys object + calls operator delete
//   [2] Serialize
//   [3] Unknown
//   [4] CreateNew
//   [5] Reset
//
// Entries at negative offsets: RTTI (-8) and offset-to-top (-16).
//
// Windows reference (MSVC ABI, single destructor):
//   virtual ~Message()
//   virtual void Serialize(BitstreamSerializer&)
//   virtual void Unknown()
//   virtual Message* CreateNew()
//   virtual void Reset()
// ============================================================================

typedef struct MessageBase MessageBase;

typedef void         (*Message_Destructor)(MessageBase *self);
typedef void         (*Message_Serialize)(MessageBase *self, void *serializer);
typedef void         (*Message_Unknown)(MessageBase *self);
typedef MessageBase *(*Message_CreateNew)(MessageBase *self);
typedef void         (*Message_Reset)(MessageBase *self);

/**
 * Message virtual function table (Itanium ABI).
 * Two destructor entries, then the virtual methods in declaration order.
 */
typedef struct {
    Message_Destructor  complete_destructor;   // vtable[0]
    Message_Destructor  deleting_destructor;   // vtable[1]
    Message_Serialize   serialize;             // vtable[2]
    Message_Unknown     unknown;               // vtable[3]
    Message_CreateNew   create_new;            // vtable[4]
    Message_Reset       reset;                 // vtable[5]
} Message_VMT;

/**
 * Complete vtable block: Itanium preamble + function table.
 * Allocate one of these and set MessageBase.vmt = &block.vmt.
 */
typedef struct {
    ItaniumVtablePreamble preamble;
    Message_VMT           vmt;
} MessageVtableBlock;

// ============================================================================
// MessageBase (matches Windows net::Message data layout)
// ============================================================================

struct MessageBase {
    const Message_VMT *vmt;        // +0x00
    uint32_t msg_id;               // +0x08  NetMessage enum (400 for NETMSG_SCRIPT_EXTENDER)
    uint32_t reliability;          // +0x0C  Default: 4
    uint32_t priority;             // +0x10  Default: 1
    uint8_t  ordering_sequence;    // +0x14  Default: 0
    bool     timestamped;          // +0x15  Default: false
    uint8_t  _pad[2];              // +0x16  Alignment padding
    uint64_t timestamp;            // +0x18  Default: 0
    uint32_t original_size;        // +0x20  Default: 0
    float    latency;              // +0x24  Default: 0.0
};
// Full layout matches Windows net::Message (Net.h lines 65-72)
// sizeof(MessageBase) == 0x28 (40 bytes)

// ============================================================================
// ExtenderMessage
//
// Extends MessageBase with a payload buffer for Lua mod messages.
// In Phase 4D, this will be registered with the game's NetMessageFactory.
// For now, it provides the serialization format for future network use.
// ============================================================================

typedef struct {
    MessageBase base;        // Must be first (C "inheritance")

    // Payload
    uint8_t *payload;        // Serialized payload (heap allocated)
    uint32_t payload_size;   // Payload size in bytes

    // State
    bool valid;              // Whether payload was successfully parsed
} ExtenderMessage;

// ============================================================================
// Public API
// ============================================================================

/**
 * Create a new ExtenderMessage.
 * Initializes with NETMSG_SCRIPT_EXTENDER ID and empty payload.
 *
 * @return New message, or NULL on allocation failure
 */
ExtenderMessage *extender_message_create(void);

/**
 * Destroy an ExtenderMessage and free its payload.
 *
 * @param msg Message to destroy (NULL-safe)
 */
void extender_message_destroy(ExtenderMessage *msg);

/**
 * Reset an ExtenderMessage for reuse (pool pattern).
 * Frees the payload and resets state.
 *
 * @param msg Message to reset
 */
void extender_message_reset(ExtenderMessage *msg);

/**
 * Set the payload of an ExtenderMessage.
 * Makes a deep copy of the data.
 *
 * @param msg   Message to update
 * @param data  Payload data
 * @param size  Payload size in bytes
 * @return true on success, false if too large or allocation fails
 */
bool extender_message_set_payload(ExtenderMessage *msg,
                                   const void *data, uint32_t size);

/**
 * Serialize an ExtenderMessage to a buffer (for network transmission).
 * Wire format: [4-byte LE size][payload bytes]
 *
 * @param msg    Message to serialize
 * @param out    Output buffer (must be at least extender_message_serialized_size())
 * @param out_sz Output buffer size
 * @return Bytes written, or 0 on failure
 */
uint32_t extender_message_serialize(const ExtenderMessage *msg,
                                     void *out, uint32_t out_sz);

/**
 * Deserialize an ExtenderMessage from a buffer.
 * Reads the 4-byte size prefix, then the payload.
 *
 * @param msg    Message to populate
 * @param data   Input buffer
 * @param size   Input buffer size
 * @return Bytes consumed, or 0 on failure
 */
uint32_t extender_message_deserialize(ExtenderMessage *msg,
                                       const void *data, uint32_t size);

/**
 * Get the serialized size of a message (header + payload).
 *
 * @param msg Message to measure
 * @return Total serialized size in bytes
 */
uint32_t extender_message_serialized_size(const ExtenderMessage *msg);

// ============================================================================
// Message Pool (Phase 4F)
//
// Pre-allocated pool for the GetMessage hook. Avoids malloc in the hot path.
// Pool is tiny (8 messages) — extender messages are rare.
// ============================================================================

#define EXTMSG_POOL_SIZE 8

/**
 * Initialize the message pool. Called once during net_hooks setup.
 */
void extender_message_pool_init(void);

/**
 * Get a free message from the pool.
 * Falls back to malloc if pool is exhausted.
 *
 * @return ExtenderMessage ready for use, or NULL on failure
 */
ExtenderMessage *extender_message_pool_get(void);

/**
 * Return a message to the pool after use.
 * If msg was malloc'd (not from pool), it is freed.
 *
 * @param msg Message to return (NULL-safe)
 */
void extender_message_pool_return(ExtenderMessage *msg);

#endif /* EXTENDER_MESSAGE_H */
