/**
 * BG3SE-macOS - Peer Manager
 *
 * Tracks connected peers and their state for multiplayer networking.
 * Includes rate limiting support (Phase 4E) and protocol version
 * negotiation tracking.
 *
 * In single-player, one local peer is registered automatically.
 *
 * Issue #6: NetChannel API (Phase 4A)
 */

#ifndef PEER_MANAGER_H
#define PEER_MANAGER_H

#include <stdint.h>
#include <stdbool.h>

// ============================================================================
// Constants
// ============================================================================

/** Maximum number of peers (matches BG3 max players + headroom). */
#define MAX_PEERS 16

/** Default rate limit: messages per window. */
#define PEER_RATE_LIMIT_DEFAULT 100

/** Rate limit window in milliseconds. */
#define PEER_RATE_WINDOW_MS 1000

// ============================================================================
// Peer Info
// ============================================================================

typedef struct {
    int32_t  user_id;              // Game-assigned user ID
    char     character_guid[64];   // Primary character GUID
    bool     is_host;              // Whether this peer is the host
    bool     active;               // Slot in use
    uint32_t proto_version;        // Negotiated protocol version (ProtoVersion)

    // Rate limiting (Phase 4E)
    uint64_t rate_window_start;    // Start of current rate window (ms)
    uint32_t rate_message_count;   // Messages sent in current window
    uint32_t rate_limit;           // Max messages per window (0 = unlimited)
} PeerInfo;

// ============================================================================
// Public API
// ============================================================================

/**
 * Initialize the peer manager.
 * Registers a local host peer (user_id=1) for single-player.
 */
void peer_manager_init(void);

/**
 * Add a peer.
 *
 * @param user_id    Game-assigned user ID
 * @param guid       Character GUID (may be NULL)
 * @param is_host    Whether this peer is the host
 * @return Slot index (>= 0) on success, -1 if full
 */
int peer_manager_add_peer(int32_t user_id, const char *guid, bool is_host);

/**
 * Remove a peer by user ID.
 *
 * @param user_id User ID to remove
 * @return true if found and removed
 */
bool peer_manager_remove_peer(int32_t user_id);

/**
 * Look up a peer by user ID.
 *
 * @param user_id User ID to find
 * @return Pointer to PeerInfo, or NULL if not found
 */
PeerInfo *peer_manager_get_peer(int32_t user_id);

/**
 * Get the host peer.
 *
 * @return Pointer to host PeerInfo, or NULL if no host
 */
PeerInfo *peer_manager_get_host(void);

/**
 * Get the number of active peers.
 *
 * @return Active peer count
 */
int peer_manager_get_peer_count(void);

/**
 * Set the negotiated protocol version for a peer.
 *
 * @param user_id       User ID
 * @param proto_version ProtoVersion value
 * @return true if peer found and updated
 */
bool peer_manager_set_proto_version(int32_t user_id, uint32_t proto_version);

/**
 * Check if a peer is within its rate limit.
 * Increments the message counter if within limit.
 *
 * @param user_id User ID to check
 * @return true if message is allowed (within rate limit)
 */
bool peer_manager_check_rate_limit(int32_t user_id);

/**
 * Set the rate limit for a specific peer.
 *
 * @param user_id    User ID
 * @param max_per_sec Maximum messages per second (0 = unlimited)
 * @return true if peer found and updated
 */
bool peer_manager_set_rate_limit(int32_t user_id, uint32_t max_per_sec);

/**
 * Clear all peers and reset to initial state.
 */
void peer_manager_clear(void);

#endif /* PEER_MANAGER_H */
