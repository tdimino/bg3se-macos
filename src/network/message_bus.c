/**
 * BG3SE-macOS - Message Bus Implementation
 *
 * In-process message routing between server and client Lua contexts.
 * For local/single-player mode, messages are delivered directly.
 *
 * Issue #6: NetChannel API
 */

#include "message_bus.h"
#include "callback_registry.h"
#include "../core/logging.h"
#include "../lua/lua_events.h"
#include <lauxlib.h>
#include <string.h>
#include <stdlib.h>

// ============================================================================
// Static State
// ============================================================================

static NetMessage g_message_queue[MAX_PENDING_MESSAGES];
static int g_queue_head = 0;
static int g_queue_tail = 0;
static bool g_initialized = false;

// ============================================================================
// Queue Management
// ============================================================================

static int queue_count(void) {
    if (g_queue_tail >= g_queue_head) {
        return g_queue_tail - g_queue_head;
    }
    return MAX_PENDING_MESSAGES - g_queue_head + g_queue_tail;
}

static bool queue_is_full(void) {
    return queue_count() >= MAX_PENDING_MESSAGES - 1;
}

static bool queue_is_empty(void) {
    return g_queue_head == g_queue_tail;
}

// ============================================================================
// Public API
// ============================================================================

void message_bus_init(void) {
    if (g_initialized) return;

    memset(g_message_queue, 0, sizeof(g_message_queue));
    g_queue_head = 0;
    g_queue_tail = 0;
    g_initialized = true;

    LOG_NET_DEBUG("Message bus initialized");
}

bool message_bus_queue(const NetMessage *msg) {
    if (!g_initialized) {
        message_bus_init();
    }

    if (queue_is_full()) {
        LOG_NET_ERROR("Message queue full, dropping message");
        return false;
    }

    // Initialize queue slot to zero first (prevents stale pointers)
    NetMessage *queued = &g_message_queue[g_queue_tail];
    memset(queued, 0, sizeof(NetMessage));

    // Copy scalar fields
    queued->dest_type = msg->dest_type;
    queued->user_id = msg->user_id;
    queued->request_id = msg->request_id;
    queued->reply_to_id = msg->reply_to_id;
    queued->binary = msg->binary;
    strncpy(queued->channel, msg->channel, sizeof(queued->channel) - 1);
    queued->channel[sizeof(queued->channel) - 1] = '\0';
    strncpy(queued->module_uuid, msg->module_uuid, sizeof(queued->module_uuid) - 1);
    queued->module_uuid[sizeof(queued->module_uuid) - 1] = '\0';
    strncpy(queued->character_guid, msg->character_guid, sizeof(queued->character_guid) - 1);
    queued->character_guid[sizeof(queued->character_guid) - 1] = '\0';
    strncpy(queued->exclude_character, msg->exclude_character, sizeof(queued->exclude_character) - 1);
    queued->exclude_character[sizeof(queued->exclude_character) - 1] = '\0';

    // Deep copy payload if present (even for empty strings)
    if (msg->payload) {
        size_t len = msg->payload_len > 0 ? msg->payload_len : strlen(msg->payload);
        queued->payload = malloc(len + 1);
        if (!queued->payload) {
            LOG_NET_ERROR("Failed to allocate payload");
            // Clear slot on failure (already zeroed, but be explicit)
            queued->active = false;
            queued->payload_len = 0;
            return false;
        }
        memcpy(queued->payload, msg->payload, len);
        queued->payload[len] = '\0';
        queued->payload_len = len;
    } else {
        queued->payload = NULL;
        queued->payload_len = 0;
    }

    queued->active = true;

    // Advance tail
    g_queue_tail = (g_queue_tail + 1) % MAX_PENDING_MESSAGES;

    LOG_NET_DEBUG("Queued message: channel=%s, dest=%d, request_id=%llu",
                msg->channel, msg->dest_type, (unsigned long long)msg->request_id);

    return true;
}

/**
 * Fire NetModMessage event to a Lua state.
 * Uses the events_fire_net_mod_message C API function.
 */
static void fire_net_mod_message(lua_State *L, const NetMessage *msg) {
    if (!L) return;

    events_fire_net_mod_message(
        L,
        msg->channel,
        msg->payload,
        msg->module_uuid,
        msg->user_id,
        msg->request_id,
        msg->reply_to_id,
        msg->binary
    );
}

int message_bus_process(lua_State *server_L, lua_State *client_L) {
    if (!g_initialized || queue_is_empty()) {
        return 0;
    }

    int processed = 0;

    while (!queue_is_empty()) {
        NetMessage *msg = &g_message_queue[g_queue_head];

        if (!msg->active) {
            g_queue_head = (g_queue_head + 1) % MAX_PENDING_MESSAGES;
            continue;
        }

        // Check if this is a reply to a pending request
        // If so, invoke the callback instead of firing an event
        if (msg->reply_to_id != 0) {
            // Determine which Lua state should receive the callback
            // Replies go to the opposite context from where they were sent
            lua_State *callback_L = NULL;
            switch (msg->dest_type) {
                case MSG_DEST_SERVER:
                    // Reply going to server - callback was registered by server
                    callback_L = server_L;
                    break;
                case MSG_DEST_USER:
                case MSG_DEST_CLIENT:
                case MSG_DEST_BROADCAST:
                    // Reply going to client - callback was registered by client
                    callback_L = client_L;
                    break;
            }

            if (callback_L) {
                LOG_NET_DEBUG("Invoking callback for reply_to_id=%llu",
                             (unsigned long long)msg->reply_to_id);

                if (callback_registry_invoke(callback_L, msg->reply_to_id,
                                            msg->payload, msg->user_id)) {
                    // Callback invoked successfully, skip event firing
                    LOG_NET_DEBUG("Callback invoked for reply_to_id=%llu",
                                 (unsigned long long)msg->reply_to_id);
                    goto cleanup;
                }
                // Callback not found - fall through to normal event handling
                LOG_NET_DEBUG("No callback found for reply_to_id=%llu, firing event",
                             (unsigned long long)msg->reply_to_id);
            }
        }

        // Route message based on destination (normal event handling)
        switch (msg->dest_type) {
            case MSG_DEST_SERVER:
                // Client -> Server: deliver to server context
                LOG_NET_DEBUG("Delivering message to server: channel=%s", msg->channel);
                fire_net_mod_message(server_L, msg);
                break;

            case MSG_DEST_USER:
            case MSG_DEST_CLIENT:
                // Server -> Specific client: deliver to client context
                // In local mode, we only have one client
                LOG_NET_DEBUG("Delivering message to client: channel=%s", msg->channel);
                fire_net_mod_message(client_L, msg);
                break;

            case MSG_DEST_BROADCAST:
                // Server -> All clients: deliver to client context
                LOG_NET_DEBUG("Broadcasting message: channel=%s", msg->channel);
                fire_net_mod_message(client_L, msg);
                break;
        }

cleanup:
        // Free payload and mark inactive
        if (msg->payload) {
            free(msg->payload);
            msg->payload = NULL;
        }
        msg->active = false;

        g_queue_head = (g_queue_head + 1) % MAX_PENDING_MESSAGES;
        processed++;
    }

    if (processed > 0) {
        LOG_NET_DEBUG("Processed %d messages", processed);
    }

    return processed;
}

int message_bus_pending_count(void) {
    return queue_count();
}

void message_bus_clear(void) {
    // Free all payloads
    for (int i = 0; i < MAX_PENDING_MESSAGES; i++) {
        if (g_message_queue[i].payload) {
            free(g_message_queue[i].payload);
            g_message_queue[i].payload = NULL;
        }
        g_message_queue[i].active = false;
    }

    g_queue_head = 0;
    g_queue_tail = 0;

    LOG_NET_DEBUG("Message queue cleared");
}

bool message_bus_is_host(bool is_server) {
    // In local/single-player mode, server context is always the host
    return is_server;
}

int message_bus_version(void) {
    // Protocol version 2 supports binary payloads
    return 2;
}

// ============================================================================
// Message Creation Helpers
// ============================================================================

NetMessage message_create_to_server(const char *channel, const char *module,
                                    const char *payload, uint64_t request_id) {
    NetMessage msg = {0};
    msg.dest_type = MSG_DEST_SERVER;

    if (channel) {
        strncpy(msg.channel, channel, sizeof(msg.channel) - 1);
        msg.channel[sizeof(msg.channel) - 1] = '\0';
    }
    if (module) {
        strncpy(msg.module_uuid, module, sizeof(msg.module_uuid) - 1);
        msg.module_uuid[sizeof(msg.module_uuid) - 1] = '\0';
    }

    if (payload) {
        size_t len = strlen(payload);
        msg.payload = malloc(len + 1);
        if (msg.payload) {
            strcpy(msg.payload, payload);
            msg.payload_len = len;
        } else {
            // Allocation failed - ensure consistent state
            msg.payload_len = 0;
        }
    }

    msg.request_id = request_id;
    return msg;
}

NetMessage message_create_to_user(int32_t user_id, const char *channel,
                                  const char *module, const char *payload,
                                  uint64_t request_id) {
    NetMessage msg = message_create_to_server(channel, module, payload, request_id);
    msg.dest_type = MSG_DEST_USER;
    msg.user_id = user_id;
    return msg;
}

NetMessage message_create_to_client(const char *guid, const char *channel,
                                    const char *module, const char *payload,
                                    uint64_t request_id) {
    NetMessage msg = message_create_to_server(channel, module, payload, request_id);
    msg.dest_type = MSG_DEST_CLIENT;
    if (guid) {
        strncpy(msg.character_guid, guid, sizeof(msg.character_guid) - 1);
        msg.character_guid[sizeof(msg.character_guid) - 1] = '\0';
    }
    return msg;
}

NetMessage message_create_broadcast(const char *channel, const char *module,
                                    const char *payload, const char *exclude_char,
                                    uint64_t request_id) {
    NetMessage msg = message_create_to_server(channel, module, payload, request_id);
    msg.dest_type = MSG_DEST_BROADCAST;
    if (exclude_char) {
        strncpy(msg.exclude_character, exclude_char, sizeof(msg.exclude_character) - 1);
        msg.exclude_character[sizeof(msg.exclude_character) - 1] = '\0';
    }
    return msg;
}

NetMessage message_create_reply(const NetMessage *original, const char *payload) {
    NetMessage msg = {0};

    // Reverse the direction
    if (original->dest_type == MSG_DEST_SERVER) {
        // Reply to client
        msg.dest_type = MSG_DEST_USER;
        msg.user_id = original->user_id;
    } else {
        // Reply to server
        msg.dest_type = MSG_DEST_SERVER;
    }

    strncpy(msg.channel, original->channel, sizeof(msg.channel) - 1);
    msg.channel[sizeof(msg.channel) - 1] = '\0';
    strncpy(msg.module_uuid, original->module_uuid, sizeof(msg.module_uuid) - 1);
    msg.module_uuid[sizeof(msg.module_uuid) - 1] = '\0';

    if (payload) {
        size_t len = strlen(payload);
        msg.payload = malloc(len + 1);
        if (msg.payload) {
            strcpy(msg.payload, payload);
            msg.payload_len = len;
        } else {
            // Allocation failed - ensure consistent state
            msg.payload_len = 0;
        }
    }

    msg.reply_to_id = original->request_id;
    return msg;
}

void message_free(NetMessage *msg) {
    if (msg && msg->payload) {
        free(msg->payload);
        msg->payload = NULL;
        msg->payload_len = 0;
    }
}
