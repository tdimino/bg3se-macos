/**
 * BG3SE-macOS - Network Backend Abstraction
 *
 * Provides a pluggable interface for message transport.
 * LocalBackend routes through the in-process message bus (single-player).
 * RakNetBackend (Phase 4F) will route through the game's network layer.
 *
 * Issue #6: NetChannel API (Phase 4A)
 */

#ifndef NETWORK_BACKEND_H
#define NETWORK_BACKEND_H

#include <stdint.h>
#include <stdbool.h>
#include <lua.h>

// ============================================================================
// Backend Types
// ============================================================================

typedef enum {
    NETWORK_BACKEND_LOCAL,   // In-process message bus (single-player / local)
    NETWORK_BACKEND_RAKNET   // Game's RakNet transport (multiplayer, Phase 4F)
} NetworkBackendType;

// ============================================================================
// Backend Interface (function pointer dispatch)
// ============================================================================

typedef struct NetworkBackend NetworkBackend;

/**
 * Send a message to the server context.
 *
 * @param channel   Channel name
 * @param module    Module UUID
 * @param payload   JSON payload
 * @param request_id Request ID (0 for fire-and-forget)
 * @param binary    Binary payload flag
 * @return true on success
 */
typedef bool (*BackendSendToServer)(const char *channel, const char *module,
                                    const char *payload, uint64_t request_id,
                                    bool binary);

/**
 * Send a message to a specific user.
 *
 * @param user_id   Target user ID
 * @param channel   Channel name
 * @param module    Module UUID
 * @param payload   JSON payload
 * @param request_id Request ID
 * @param binary    Binary payload flag
 * @return true on success
 */
typedef bool (*BackendSendToUser)(int32_t user_id, const char *channel,
                                  const char *module, const char *payload,
                                  uint64_t request_id, bool binary);

/**
 * Send a message to a specific client by character GUID.
 *
 * @param guid      Character GUID
 * @param channel   Channel name
 * @param module    Module UUID
 * @param payload   JSON payload
 * @param request_id Request ID
 * @param binary    Binary payload flag
 * @return true on success
 */
typedef bool (*BackendSendToClient)(const char *guid, const char *channel,
                                    const char *module, const char *payload,
                                    uint64_t request_id, bool binary);

/**
 * Broadcast a message to all clients.
 *
 * @param channel        Channel name
 * @param module         Module UUID
 * @param payload        JSON payload
 * @param exclude_char   Character GUID to exclude (NULL for none)
 * @param request_id     Request ID
 * @param binary         Binary payload flag
 * @return true on success
 */
typedef bool (*BackendBroadcast)(const char *channel, const char *module,
                                 const char *payload, const char *exclude_char,
                                 uint64_t request_id, bool binary);

/**
 * Check if the current peer is the host.
 *
 * @param is_server true if called from server context
 * @return true if host
 */
typedef bool (*BackendIsHost)(bool is_server);

/**
 * Get the network protocol version.
 *
 * @return Protocol version number
 */
typedef int (*BackendGetVersion)(void);

struct NetworkBackend {
    NetworkBackendType type;
    BackendSendToServer   send_to_server;
    BackendSendToUser     send_to_user;
    BackendSendToClient   send_to_client;
    BackendBroadcast      broadcast;
    BackendIsHost         is_host;
    BackendGetVersion     get_version;
};

// ============================================================================
// Public API
// ============================================================================

/**
 * Initialize the network backend system.
 * Starts with LocalBackend by default.
 */
void network_backend_init(void);

/**
 * Get the current active backend.
 *
 * @return Pointer to the current NetworkBackend
 */
NetworkBackend *network_backend_get(void);

/**
 * Get the current backend type.
 *
 * @return NETWORK_BACKEND_LOCAL or NETWORK_BACKEND_RAKNET
 */
NetworkBackendType network_backend_get_type(void);

/**
 * Switch to the RakNet backend (called when multiplayer is detected).
 * Phase 4F: Will be implemented when real network hooks are ready.
 */
void network_backend_set_raknet(void);

/**
 * Switch back to the local backend.
 */
void network_backend_set_local(void);

#endif /* NETWORK_BACKEND_H */
