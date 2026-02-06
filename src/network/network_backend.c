/**
 * BG3SE-macOS - Network Backend Implementation
 *
 * Provides LocalBackend (in-process message bus) and the interface
 * for switching to RakNetBackend when multiplayer is detected.
 *
 * Issue #6: NetChannel API (Phase 4A)
 */

#include "network_backend.h"
#include "message_bus.h"
#include "../core/logging.h"

// ============================================================================
// Static State
// ============================================================================

static bool s_initialized = false;

// ============================================================================
// LocalBackend Implementation
//
// Routes all messages through the in-process message_bus.
// Used for single-player / local testing.
// ============================================================================

static bool local_send_to_server(const char *channel, const char *module,
                                 const char *payload, uint64_t request_id,
                                 bool binary) {
    NetMessage msg = message_create_to_server(channel, module, payload, request_id);
    msg.binary = binary;
    bool ok = message_bus_queue(&msg);
    message_free(&msg);
    return ok;
}

static bool local_send_to_user(int32_t user_id, const char *channel,
                               const char *module, const char *payload,
                               uint64_t request_id, bool binary) {
    NetMessage msg = message_create_to_user(user_id, channel, module, payload,
                                            request_id);
    msg.binary = binary;
    bool ok = message_bus_queue(&msg);
    message_free(&msg);
    return ok;
}

static bool local_send_to_client(const char *guid, const char *channel,
                                 const char *module, const char *payload,
                                 uint64_t request_id, bool binary) {
    NetMessage msg = message_create_to_client(guid, channel, module, payload,
                                              request_id);
    msg.binary = binary;
    bool ok = message_bus_queue(&msg);
    message_free(&msg);
    return ok;
}

static bool local_broadcast(const char *channel, const char *module,
                            const char *payload, const char *exclude_char,
                            uint64_t request_id, bool binary) {
    NetMessage msg = message_create_broadcast(channel, module, payload,
                                              exclude_char, request_id);
    msg.binary = binary;
    bool ok = message_bus_queue(&msg);
    message_free(&msg);
    return ok;
}

static bool local_is_host(bool is_server) {
    return message_bus_is_host(is_server);
}

static int local_get_version(void) {
    return message_bus_version();
}

// ============================================================================
// Backend Instances
// ============================================================================

static NetworkBackend s_local_backend = {
    .type            = NETWORK_BACKEND_LOCAL,
    .send_to_server  = local_send_to_server,
    .send_to_user    = local_send_to_user,
    .send_to_client  = local_send_to_client,
    .broadcast       = local_broadcast,
    .is_host         = local_is_host,
    .get_version     = local_get_version,
};

static NetworkBackend *s_active_backend = NULL;

// ============================================================================
// Public API
// ============================================================================

void network_backend_init(void) {
    if (s_initialized) return;

    s_active_backend = &s_local_backend;
    s_initialized = true;

    LOG_NET_DEBUG("Network backend initialized (LocalBackend)");
}

NetworkBackend *network_backend_get(void) {
    if (!s_initialized) {
        network_backend_init();
    }
    return s_active_backend;
}

NetworkBackendType network_backend_get_type(void) {
    if (!s_initialized) {
        network_backend_init();
    }
    return s_active_backend->type;
}

void network_backend_set_raknet(void) {
    // Phase 4F: RakNet backend not yet implemented
    LOG_NET_WARN("RakNet backend not yet implemented, staying on LocalBackend");
}

void network_backend_set_local(void) {
    s_active_backend = &s_local_backend;
    LOG_NET_INFO("Switched to LocalBackend");
}
