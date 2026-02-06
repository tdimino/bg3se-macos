/**
 * BG3SE-macOS - Message Bus
 *
 * In-process message routing between server and client Lua contexts.
 * Messages are queued and delivered on the next tick.
 *
 * Issue #6: NetChannel API
 */

#ifndef MESSAGE_BUS_H
#define MESSAGE_BUS_H

#include <lua.h>
#include <stdint.h>
#include <stdbool.h>

// Maximum pending messages in queue
#define MAX_PENDING_MESSAGES 1024

// Maximum message payload size
#define MAX_MESSAGE_PAYLOAD 65536

// Message destination types
typedef enum {
    MSG_DEST_SERVER,      // Client -> Server
    MSG_DEST_USER,        // Server -> Specific user (by UserID)
    MSG_DEST_CLIENT,      // Server -> Specific client (by character GUID)
    MSG_DEST_BROADCAST    // Server -> All clients
} MessageDestination;

// Network message structure
typedef struct {
    MessageDestination dest_type;

    // Routing info
    int32_t user_id;                  // Target UserID (for MSG_DEST_USER)
    char character_guid[64];          // Target character GUID (for MSG_DEST_CLIENT)
    char exclude_character[64];       // Exclude from broadcast (for MSG_DEST_BROADCAST)

    // Channel info
    char channel[128];                // Channel name
    char module_uuid[64];             // Module UUID

    // Payload
    char *payload;                    // JSON-encoded payload (heap allocated)
    size_t payload_len;

    // Request/reply correlation
    uint64_t request_id;              // 0 for fire-and-forget
    uint64_t reply_to_id;             // Non-zero if this is a reply

    // Handler info (for replies)
    char handler_name[128];           // Handler name (optional)

    // Flags
    bool binary;                      // Binary payload (future use)
    bool active;                      // Whether this slot is in use
} NetMessage;

/**
 * Initialize the message bus.
 */
void message_bus_init(void);

/**
 * Queue a message for delivery.
 * Validates payload size and channel name.
 *
 * @param msg Message to queue (contents are copied)
 * @return true on success, false if queue full or validation fails
 */
bool message_bus_queue(const NetMessage *msg);

/**
 * Queue a message from a network peer with rate limiting.
 * Checks the peer's rate limit before queueing.
 * Use this for messages received from the network (Phase 4D).
 * For local in-process messages, use message_bus_queue() directly.
 *
 * @param peer_user_id User ID of the sending peer
 * @param msg          Message to queue (contents are copied)
 * @return true on success, false if rate limited, queue full, or validation fails
 */
bool message_bus_queue_from_peer(int32_t peer_user_id, const NetMessage *msg);

/**
 * Process pending messages and fire NetModMessage events.
 * Should be called once per tick.
 *
 * @param server_L Server Lua state (or NULL)
 * @param client_L Client Lua state (or NULL)
 * @return Number of messages processed
 */
int message_bus_process(lua_State *server_L, lua_State *client_L);

/**
 * Get count of pending messages.
 *
 * @return Number of messages in queue
 */
int message_bus_pending_count(void);

/**
 * Clear all pending messages.
 */
void message_bus_clear(void);

/**
 * Check if running as host (for IsHost()).
 * In local mode, always returns true for server context.
 *
 * @param is_server true if checking from server context
 * @return true if host
 */
bool message_bus_is_host(bool is_server);

/**
 * Get protocol version.
 *
 * @return Protocol version (2 for binary support)
 */
int message_bus_version(void);

// ============================================================================
// Helper: Create message structures
// ============================================================================

/**
 * Create a message destined for the server.
 */
NetMessage message_create_to_server(const char *channel, const char *module,
                                    const char *payload, uint64_t request_id);

/**
 * Create a message destined for a specific user.
 */
NetMessage message_create_to_user(int32_t user_id, const char *channel,
                                  const char *module, const char *payload,
                                  uint64_t request_id);

/**
 * Create a message destined for a specific client by character GUID.
 */
NetMessage message_create_to_client(const char *guid, const char *channel,
                                    const char *module, const char *payload,
                                    uint64_t request_id);

/**
 * Create a broadcast message to all clients.
 */
NetMessage message_create_broadcast(const char *channel, const char *module,
                                    const char *payload, const char *exclude_char,
                                    uint64_t request_id);

/**
 * Create a reply message.
 */
NetMessage message_create_reply(const NetMessage *original, const char *payload);

/**
 * Free message payload (if heap allocated).
 */
void message_free(NetMessage *msg);

#endif /* MESSAGE_BUS_H */
