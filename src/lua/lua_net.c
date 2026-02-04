/**
 * BG3SE-macOS - Ext.Net Lua Bindings Implementation
 *
 * Network messaging API for multiplayer mod synchronization.
 * Phase 1: Local in-process routing (single-player/local testing).
 *
 * Issue #6: NetChannel API
 */

#include "lua_net.h"
#include "lua_net_scripts.h"
#include "../network/message_bus.h"
#include "../network/callback_registry.h"
#include "../core/logging.h"

#include <lauxlib.h>
#include <string.h>

// ============================================================================
// Static State
// ============================================================================

static bool g_is_server_context = false;
static bool g_initialized = false;

// ============================================================================
// Helper: Get optional string argument
// ============================================================================

static const char *get_opt_string(lua_State *L, int idx, const char *default_val) {
    if (lua_isstring(L, idx)) {
        return lua_tostring(L, idx);
    }
    return default_val;
}

static bool get_opt_bool(lua_State *L, int idx, bool default_val) {
    if (lua_isboolean(L, idx)) {
        return lua_toboolean(L, idx);
    }
    return default_val;
}

static int64_t get_opt_int(lua_State *L, int idx, int64_t default_val) {
    if (lua_isinteger(L, idx)) {
        return lua_tointeger(L, idx);
    }
    return default_val;
}

// ============================================================================
// Lua Functions
// ============================================================================

/**
 * Ext.Net.PostMessageToServer(channel, payload, module, handler, replyId, binary)
 *
 * Send a message from client to server.
 * In local mode, queues for immediate delivery on next tick.
 *
 * handler can be:
 * - nil: fire-and-forget message
 * - function: callback for request/reply pattern (callback stored, request_id assigned)
 * - string: handler name for routing (legacy, currently ignored)
 */
static int lua_net_post_to_server(lua_State *L) {
    const char *channel = luaL_checkstring(L, 1);
    const char *payload = get_opt_string(L, 2, "{}");
    const char *module = get_opt_string(L, 3, "");
    // handler at position 4 - can be function, string, or nil
    int64_t reply_id = get_opt_int(L, 5, 0);
    bool binary = get_opt_bool(L, 6, false);

    (void)binary;   // Binary flag for future use

    uint64_t request_id = 0;

    // Check if handler is a function (request/reply pattern)
    if (lua_isfunction(L, 4)) {
        // Push the function to top of stack for callback_registry_register
        lua_pushvalue(L, 4);
        request_id = callback_registry_register(L);
        if (request_id == 0) {
            return luaL_error(L, "Failed to register callback");
        }
        LOG_NET_DEBUG("Registered callback for request: request_id=%llu",
                     (unsigned long long)request_id);
    }

    NetMessage msg = message_create_to_server(channel, module, payload, request_id);
    msg.reply_to_id = (uint64_t)reply_id;

    if (!message_bus_queue(&msg)) {
        // If we registered a callback but queue failed, cancel it
        if (request_id != 0) {
            callback_registry_cancel(L, request_id);
        }
        message_free(&msg);
        return luaL_error(L, "Failed to queue message");
    }

    message_free(&msg);
    return 0;
}

/**
 * Ext.Net.PostMessageToUser(userId, channel, payload, module, handler, replyId, binary)
 *
 * Send a message from server to a specific user by UserID.
 */
static int lua_net_post_to_user(lua_State *L) {
    int32_t user_id = (int32_t)luaL_checkinteger(L, 1);
    const char *channel = luaL_checkstring(L, 2);
    const char *payload = get_opt_string(L, 3, "{}");
    const char *module = get_opt_string(L, 4, "");
    // handler at position 5 - can be function, string, or nil
    int64_t reply_id = get_opt_int(L, 6, 0);
    bool binary = get_opt_bool(L, 7, false);

    (void)binary;

    uint64_t request_id = 0;

    // Check if handler is a function (request/reply pattern)
    if (lua_isfunction(L, 5)) {
        lua_pushvalue(L, 5);
        request_id = callback_registry_register(L);
        if (request_id == 0) {
            return luaL_error(L, "Failed to register callback");
        }
    }

    NetMessage msg = message_create_to_user(user_id, channel, module, payload, request_id);
    msg.reply_to_id = (uint64_t)reply_id;

    if (!message_bus_queue(&msg)) {
        if (request_id != 0) {
            callback_registry_cancel(L, request_id);
        }
        message_free(&msg);
        return luaL_error(L, "Failed to queue message");
    }

    message_free(&msg);
    return 0;
}

/**
 * Ext.Net.PostMessageToClient(characterGuid, channel, payload, module, handler, replyId, binary)
 *
 * Send a message from server to a specific client by character GUID.
 */
static int lua_net_post_to_client(lua_State *L) {
    const char *guid = luaL_checkstring(L, 1);
    const char *channel = luaL_checkstring(L, 2);
    const char *payload = get_opt_string(L, 3, "{}");
    const char *module = get_opt_string(L, 4, "");
    // handler at position 5 - can be function, string, or nil
    int64_t reply_id = get_opt_int(L, 6, 0);
    bool binary = get_opt_bool(L, 7, false);

    (void)binary;

    uint64_t request_id = 0;

    // Check if handler is a function (request/reply pattern)
    if (lua_isfunction(L, 5)) {
        lua_pushvalue(L, 5);
        request_id = callback_registry_register(L);
        if (request_id == 0) {
            return luaL_error(L, "Failed to register callback");
        }
    }

    NetMessage msg = message_create_to_client(guid, channel, module, payload, request_id);
    msg.reply_to_id = (uint64_t)reply_id;

    if (!message_bus_queue(&msg)) {
        if (request_id != 0) {
            callback_registry_cancel(L, request_id);
        }
        message_free(&msg);
        return luaL_error(L, "Failed to queue message");
    }

    message_free(&msg);
    return 0;
}

/**
 * Ext.Net.BroadcastMessage(channel, payload, excludeCharacterGuid, module, handler, replyId, binary)
 *
 * Broadcast a message from server to all connected clients.
 * Note: Broadcasts typically don't use request/reply pattern, but we support it for consistency.
 */
static int lua_net_broadcast(lua_State *L) {
    const char *channel = luaL_checkstring(L, 1);
    const char *payload = get_opt_string(L, 2, "{}");
    const char *exclude = get_opt_string(L, 3, NULL);
    const char *module = get_opt_string(L, 4, "");
    // handler at position 5 - can be function, string, or nil
    int64_t reply_id = get_opt_int(L, 6, 0);
    bool binary = get_opt_bool(L, 7, false);

    (void)binary;

    uint64_t request_id = 0;

    // Check if handler is a function (request/reply pattern)
    // Note: Broadcast request/reply is unusual but supported
    if (lua_isfunction(L, 5)) {
        lua_pushvalue(L, 5);
        request_id = callback_registry_register(L);
        if (request_id == 0) {
            return luaL_error(L, "Failed to register callback");
        }
    }

    NetMessage msg = message_create_broadcast(channel, module, payload, exclude, request_id);
    msg.reply_to_id = (uint64_t)reply_id;

    if (!message_bus_queue(&msg)) {
        if (request_id != 0) {
            callback_registry_cancel(L, request_id);
        }
        message_free(&msg);
        return luaL_error(L, "Failed to queue message");
    }

    message_free(&msg);
    return 0;
}

/**
 * Ext.Net.Version() -> int
 *
 * Returns the network protocol version.
 * Version 2 indicates binary payload support.
 */
static int lua_net_version(lua_State *L) {
    lua_pushinteger(L, message_bus_version());
    return 1;
}

/**
 * Ext.Net.IsHost() -> boolean
 *
 * Returns true if running as the host (server in multiplayer, always true in single-player).
 */
static int lua_net_is_host(lua_State *L) {
    lua_pushboolean(L, message_bus_is_host(g_is_server_context));
    return 1;
}

// ============================================================================
// Embedded Script Loading
// ============================================================================

static bool g_scripts_loaded = false;

/**
 * Load the embedded Net library scripts (Class, NetChannel, NetworkManager).
 * MUST be called AFTER Ext is set as a global (the scripts use Ext.Net, Ext.Json, etc.)
 */
void lua_net_load_scripts(lua_State *L) {
    if (g_scripts_loaded) return;

    // Load the combined initialization script
    if (luaL_dostring(L, LUA_SCRIPT_NET_INIT) != LUA_OK) {
        const char *err = lua_tostring(L, -1);
        LOG_NET_ERROR("Failed to load Net library: %s", err ? err : "unknown");
        lua_pop(L, 1);
        return;
    }

    g_scripts_loaded = true;
    LOG_NET_INFO("Net library scripts loaded (Class, NetChannel, NetworkManager)");
}

// ============================================================================
// Public API
// ============================================================================

void lua_net_init(void) {
    if (g_initialized) return;

    message_bus_init();
    callback_registry_init();

    g_initialized = true;
    LOG_NET_INFO("Network subsystem initialized");
}

void lua_net_register(lua_State *L, int ext_table_index, bool is_server) {
    g_is_server_context = is_server;

    // Convert to absolute index before pushing new values onto stack
    int abs_ext_index = lua_absindex(L, ext_table_index);

    // Ensure initialization
    lua_net_init();

    // Create Ext.Net table
    lua_newtable(L);

    // Register functions
    lua_pushcfunction(L, lua_net_post_to_server);
    lua_setfield(L, -2, "PostMessageToServer");

    lua_pushcfunction(L, lua_net_post_to_user);
    lua_setfield(L, -2, "PostMessageToUser");

    lua_pushcfunction(L, lua_net_post_to_client);
    lua_setfield(L, -2, "PostMessageToClient");

    lua_pushcfunction(L, lua_net_broadcast);
    lua_setfield(L, -2, "BroadcastMessage");

    lua_pushcfunction(L, lua_net_version);
    lua_setfield(L, -2, "Version");

    lua_pushcfunction(L, lua_net_is_host);
    lua_setfield(L, -2, "IsHost");

    // Set as Ext.Net
    lua_setfield(L, abs_ext_index, "Net");

    LOG_LUA_INFO("Registered Ext.Net namespace (6 functions, context=%s)",
                is_server ? "server" : "client");

    // NOTE: lua_net_load_scripts() must be called separately AFTER Ext is global
}

void lua_net_process_messages(lua_State *server_L, lua_State *client_L) {
    if (!g_initialized) return;

    int processed = message_bus_process(server_L, client_L);
    if (processed > 0) {
        LOG_NET_DEBUG("Processed %d messages this tick", processed);
    }

    // Clean up expired callbacks (30 second timeout)
    if (server_L) {
        callback_registry_cleanup_expired(server_L, 30000);
    }
    if (client_L) {
        callback_registry_cleanup_expired(client_L, 30000);
    }
}
