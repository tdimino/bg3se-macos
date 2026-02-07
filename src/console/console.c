/**
 * console.c - BG3SE Console with file-based and socket interfaces
 *
 * Features:
 * - Unix domain socket server for real-time bidirectional I/O
 * - File-based console as fallback
 * - Multi-line mode: Accumulate lines between --[[ and ]]-- delimiters
 * - Console commands: Lines starting with ! are dispatched to registered handlers
 */

#include "console.h"
#include "../core/logging.h"
#include "../lua/lua_events.h"
#include "../overlay/overlay.h"
#include "../lifetime/lifetime.h"
#include "../entity/component_typeid.h"
#include "../osiris/osiris_functions.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <lauxlib.h>
#include <pthread.h>

// ============================================================================
// Configuration
// ============================================================================

#define MAX_CLIENTS 4
#define RECV_BUFFER_SIZE 4096
#define SEND_BUFFER_SIZE 8192

// ============================================================================
// State
// ============================================================================

// File-based console
static char s_command_file[512] = {0};

// Socket server
static int s_server_fd = -1;
static int s_client_fds[MAX_CLIENTS] = {-1, -1, -1, -1};
static char s_client_buffers[MAX_CLIENTS][RECV_BUFFER_SIZE];
static size_t s_client_buffer_lens[MAX_CLIENTS] = {0};

// Initialization state
static int s_initialized = 0;

// Multi-line buffer (shared between file and socket input)
#define MULTILINE_BUFFER_SIZE 65536
static char s_multiline_buffer[MULTILINE_BUFFER_SIZE];
static size_t s_multiline_len = 0;
static int s_multiline_mode = 0;
static int s_multiline_client = -1;  // Which client started multi-line mode (-1 = file)

// Console command registry
#define MAX_CONSOLE_COMMANDS 32
typedef struct {
    char name[64];
    int lua_callback_ref;
} ConsoleCommand;

static ConsoleCommand s_commands[MAX_CONSOLE_COMMANDS];
static int s_command_count = 0;
static lua_State *s_lua_state = NULL;

// ============================================================================
// Thread-safe Overlay Command Queue (drained from console_poll on Lua thread)
// ============================================================================

#define OVERLAY_COMMAND_QUEUE_CAPACITY 64

static pthread_mutex_t s_overlay_cmd_mutex = PTHREAD_MUTEX_INITIALIZER;
static char *s_overlay_cmd_queue[OVERLAY_COMMAND_QUEUE_CAPACITY];
static uint32_t s_overlay_cmd_head = 0;
static uint32_t s_overlay_cmd_tail = 0;

/**
 * Drain queued overlay commands and execute on the calling thread.
 */
static void drain_overlay_command_queue(void) {
    while (1) {
        char *cmd = NULL;

        pthread_mutex_lock(&s_overlay_cmd_mutex);
        if (s_overlay_cmd_head != s_overlay_cmd_tail) {
            cmd = s_overlay_cmd_queue[s_overlay_cmd_head];
            s_overlay_cmd_queue[s_overlay_cmd_head] = NULL;
            s_overlay_cmd_head = (s_overlay_cmd_head + 1) % OVERLAY_COMMAND_QUEUE_CAPACITY;
        }
        pthread_mutex_unlock(&s_overlay_cmd_mutex);

        if (!cmd) break;

        (void)console_execute_lua(cmd);
        free(cmd);
    }
}

// ============================================================================
// Multi-line Buffer Management
// ============================================================================

static void multiline_buffer_clear(void) {
    s_multiline_buffer[0] = '\0';
    s_multiline_len = 0;
}

static void multiline_buffer_append(const char *text) {
    size_t text_len = strlen(text);
    if (s_multiline_len + text_len < MULTILINE_BUFFER_SIZE - 1) {
        memcpy(s_multiline_buffer + s_multiline_len, text, text_len);
        s_multiline_len += text_len;
        s_multiline_buffer[s_multiline_len] = '\0';
    } else {
        LOG_CONSOLE_WARN("Multi-line buffer overflow, truncating");
    }
}

// ============================================================================
// String Utilities
// ============================================================================

static const char *trim_whitespace(const char *str) {
    while (*str && isspace((unsigned char)*str)) str++;
    return str;
}

static void trim_trailing_newline(char *str) {
    size_t len = strlen(str);
    while (len > 0 && (str[len-1] == '\n' || str[len-1] == '\r')) {
        str[--len] = '\0';
    }
}

// ============================================================================
// Socket Server
// ============================================================================

static void socket_server_init(void) {
    // Remove any existing socket file
    unlink(CONSOLE_SOCKET_PATH);

    // Create socket
    s_server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s_server_fd < 0) {
        LOG_CONSOLE_ERROR("Failed to create socket: %s", strerror(errno));
        return;
    }

    // Set non-blocking
    int flags = fcntl(s_server_fd, F_GETFL, 0);
    fcntl(s_server_fd, F_SETFL, flags | O_NONBLOCK);

    // Bind to socket path
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONSOLE_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(s_server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_CONSOLE_ERROR("Failed to bind socket: %s", strerror(errno));
        close(s_server_fd);
        s_server_fd = -1;
        return;
    }

    // Listen for connections
    if (listen(s_server_fd, MAX_CLIENTS) < 0) {
        LOG_CONSOLE_ERROR("Failed to listen on socket: %s", strerror(errno));
        close(s_server_fd);
        s_server_fd = -1;
        return;
    }

    LOG_CONSOLE_INFO("Socket server listening on %s", CONSOLE_SOCKET_PATH);
}

static void socket_server_shutdown(void) {
    // Close all client connections
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (s_client_fds[i] >= 0) {
            close(s_client_fds[i]);
            s_client_fds[i] = -1;
        }
    }

    // Close server socket
    if (s_server_fd >= 0) {
        close(s_server_fd);
        s_server_fd = -1;
    }

    // Remove socket file
    unlink(CONSOLE_SOCKET_PATH);
}

static void socket_accept_clients(void) {
    if (s_server_fd < 0) return;

    // Try to accept new connections (non-blocking)
    while (1) {
        int client_fd = accept(s_server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;  // No more pending connections
            }
            LOG_CONSOLE_ERROR("Accept failed: %s", strerror(errno));
            break;
        }

        // Set client socket to non-blocking
        int flags = fcntl(client_fd, F_GETFL, 0);
        fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

        // Find a free slot
        int slot = -1;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (s_client_fds[i] < 0) {
                slot = i;
                break;
            }
        }

        if (slot < 0) {
            // No free slots, reject connection
            const char *msg = "ERROR: Too many connections\n";
            write(client_fd, msg, strlen(msg));
            close(client_fd);
            LOG_CONSOLE_WARN("Rejected connection: too many clients");
            continue;
        }

        s_client_fds[slot] = client_fd;
        s_client_buffer_lens[slot] = 0;
        s_client_buffers[slot][0] = '\0';

        LOG_CONSOLE_INFO("Client %d connected", slot);

        // Send welcome message
        const char *welcome =
            "\033[1;36m=== BG3SE Console ===\033[0m\n"
            "Type Lua commands or !help for built-in commands.\n"
            "Multi-line: Start with --[[ and end with ]]--\n"
            "> ";
        write(client_fd, welcome, strlen(welcome));
    }
}

static void socket_close_client(int slot) {
    if (slot < 0 || slot >= MAX_CLIENTS) return;
    if (s_client_fds[slot] < 0) return;

    close(s_client_fds[slot]);
    s_client_fds[slot] = -1;
    s_client_buffer_lens[slot] = 0;

    // If this client was in multi-line mode, reset it
    if (s_multiline_mode && s_multiline_client == slot) {
        s_multiline_mode = 0;
        s_multiline_client = -1;
        multiline_buffer_clear();
    }

    LOG_CONSOLE_INFO("Client %d disconnected", slot);
}

// ============================================================================
// Output Forwarding
// ============================================================================

void console_send_output(const char *message, bool is_error) {
    if (!message) return;

    char buf[SEND_BUFFER_SIZE];
    if (is_error) {
        snprintf(buf, sizeof(buf), "\033[1;31m%s\033[0m\n", message);
    } else {
        snprintf(buf, sizeof(buf), "%s\n", message);
    }

    size_t len = strlen(buf);

    // Send to all connected socket clients
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (s_client_fds[i] >= 0) {
            ssize_t written = write(s_client_fds[i], buf, len);
            if (written < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                socket_close_client(i);
            }
        }
    }

    // Also forward to overlay console (without ANSI codes)
    overlay_append_output(message);
}

void console_printf(const char *format, ...) {
    char buf[SEND_BUFFER_SIZE];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    console_send_output(buf, false);
}

void console_error(const char *format, ...) {
    char buf[SEND_BUFFER_SIZE];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    console_send_output(buf, true);
}

// Send prompt to a specific client
static void socket_send_prompt(int slot) {
    if (slot < 0 || slot >= MAX_CLIENTS) return;
    if (s_client_fds[slot] < 0) return;

    const char *prompt = s_multiline_mode ? "... " : "> ";
    write(s_client_fds[slot], prompt, strlen(prompt));
}

// ============================================================================
// Console Command System
// ============================================================================

int console_register_command(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);

    if (s_command_count >= MAX_CONSOLE_COMMANDS) {
        return luaL_error(L, "Maximum console commands reached (%d)", MAX_CONSOLE_COMMANDS);
    }

    lua_pushvalue(L, 2);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);

    strncpy(s_commands[s_command_count].name, name, sizeof(s_commands[0].name) - 1);
    s_commands[s_command_count].name[sizeof(s_commands[0].name) - 1] = '\0';
    s_commands[s_command_count].lua_callback_ref = ref;
    s_command_count++;

    LOG_CONSOLE_INFO("Registered command: !%s", name);
    return 0;
}

static int dispatch_console_command(lua_State *L, const char *line, int client_slot) {
    char cmd_buffer[256];
    strncpy(cmd_buffer, line + 1, sizeof(cmd_buffer) - 1);
    cmd_buffer[sizeof(cmd_buffer) - 1] = '\0';

    char *cmd_name = strtok(cmd_buffer, " \t");
    if (!cmd_name) return 0;

    // Find the command
    for (int i = 0; i < s_command_count; i++) {
        if (strcmp(s_commands[i].name, cmd_name) == 0) {
            lua_rawgeti(L, LUA_REGISTRYINDEX, s_commands[i].lua_callback_ref);
            lua_pushstring(L, cmd_name);

            int argc = 1;
            char *arg;
            while ((arg = strtok(NULL, " \t")) != NULL && argc < 10) {
                lua_pushstring(L, arg);
                argc++;
            }

            if (lua_pcall(L, argc, 0, 0) != LUA_OK) {
                const char *err = lua_tostring(L, -1);
                if (client_slot >= 0) {
                    console_error("Command error: %s", err ? err : "(unknown)");
                }
                LOG_CONSOLE_ERROR("Command error: %s", err ? err : "(unknown)");
                lua_pop(L, 1);
            }
            return 1;
        }
    }

    // Built-in !help command
    if (strcmp(cmd_name, "help") == 0) {
        console_printf("Available commands:");
        console_printf("  !help - Show this help");
        console_printf("  !events - Show event handler counts");
        console_printf("  !status - Show BG3SE status");
        console_printf("  !typeids - Show TypeId resolution status");
        console_printf("  !probe_osidef [N] - Dump OsiFunctionDef layout for N functions (default 5)");
        for (int i = 0; i < s_command_count; i++) {
            console_printf("  !%s", s_commands[i].name);
        }
        return 1;
    }

    // Built-in !events command
    if (strcmp(cmd_name, "events") == 0) {
        console_printf("Event handler counts:");
        for (int e = 0; e < EVENT_MAX; e++) {
            int count = events_get_handler_count(e);
            const char *name = events_get_name(e);
            console_printf("  %s: %d handler(s)", name, count);
        }
        return 1;
    }

    // Built-in !status command
    if (strcmp(cmd_name, "status") == 0) {
        console_printf("BG3SE Status:");
        console_printf("  Socket: %s", s_server_fd >= 0 ? "listening" : "not available");
        int client_count = 0;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (s_client_fds[i] >= 0) client_count++;
        }
        console_printf("  Connected clients: %d", client_count);
        console_printf("  Registered commands: %d", s_command_count);
        return 1;
    }

    // Built-in !typeids command
    if (strcmp(cmd_name, "typeids") == 0) {
        component_typeid_dump_to_console();
        return 1;
    }

    // Built-in !probe_osidef command (Issue #66: discover OsiFunctionDef layout)
    if (strcmp(cmd_name, "probe_osidef") == 0) {
        int count = 5;  // Default: probe first 5 functions
        char *count_arg = strtok(NULL, " \t");
        if (count_arg && count_arg[0]) {
            count = atoi(count_arg);
            if (count <= 0) count = 5;
            if (count > 50) count = 50;
        }
        console_printf("Probing OsiFunctionDef layout for %d functions (check log)...", count);
        osi_func_probe_layout(count);
        return 1;
    }

    if (client_slot >= 0) {
        console_error("Unknown command: !%s (try !help)", cmd_name);
    }
    LOG_CONSOLE_WARN("Unknown command: !%s (try !help)", cmd_name);
    return 0;
}

// ============================================================================
// Line Processing
// ============================================================================

static void process_line(lua_State *L, char *line, int client_slot) {
    trim_trailing_newline(line);
    size_t len = strlen(line);

    // Skip empty lines (but allow them in multi-line mode)
    if (len == 0 && !s_multiline_mode) return;

    // Skip comments (but allow them in multi-line mode)
    if (line[0] == '#' && !s_multiline_mode) return;

    const char *trimmed = trim_whitespace(line);

    // Check for multi-line start delimiter
    if (strcmp(trimmed, "--[[") == 0) {
        if (s_multiline_mode) {
            if (client_slot >= 0) {
                console_error("Already in multi-line mode, resetting");
            }
            LOG_CONSOLE_WARN("Already in multi-line mode, resetting");
        }
        s_multiline_mode = 1;
        s_multiline_client = client_slot;
        multiline_buffer_clear();
        LOG_CONSOLE_DEBUG("Entering multi-line mode...");
        return;
    }

    // Check for multi-line end delimiter
    if (s_multiline_mode && strcmp(trimmed, "]]--") == 0) {
        // Only the client that started multi-line mode can end it
        if (client_slot != s_multiline_client) {
            if (client_slot >= 0) {
                console_error("Another client is in multi-line mode");
            }
            return;
        }

        s_multiline_mode = 0;
        s_multiline_client = -1;
        LOG_CONSOLE_DEBUG("Executing multi-line block (%zu bytes)", s_multiline_len);

        // Begin lifetime scope for multi-line block
        LifetimeHandle scope = lifetime_lua_begin_scope(L);
        (void)scope;

        int result = luaL_dostring(L, s_multiline_buffer);
        if (result != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            if (client_slot >= 0) {
                console_error("Error: %s", err ? err : "(unknown)");
            }
            LOG_CONSOLE_ERROR("Error: %s", err ? err : "(unknown)");
            lua_pop(L, 1);
        }

        // End lifetime scope
        lifetime_lua_end_scope(L);
        multiline_buffer_clear();
        return;
    }

    // In multi-line mode, accumulate lines
    if (s_multiline_mode) {
        // Only accept input from the client that started multi-line mode
        if (client_slot != s_multiline_client) {
            if (client_slot >= 0) {
                console_error("Another client is in multi-line mode");
            }
            return;
        }
        multiline_buffer_append(line);
        multiline_buffer_append("\n");
        return;
    }

    // Check for console command (! prefix)
    if (line[0] == '!') {
        LOG_CONSOLE_DEBUG("! %s", line + 1);

        // Fire DoConsoleCommand event - handlers can prevent execution
        if (events_fire_do_console_command(L, line)) {
            LOG_CONSOLE_DEBUG("DoConsoleCommand prevented by handler");
            return;
        }

        dispatch_console_command(L, line, client_slot);
        return;
    }

    // Normal single-line execution
    LOG_CONSOLE_DEBUG("> %s", line);

    // Fire LuaConsoleInput event - handlers can prevent execution
    if (events_fire_lua_console_input(L, line)) {
        LOG_CONSOLE_DEBUG("LuaConsoleInput prevented by handler");
        return;
    }

    // Begin lifetime scope for single line
    LifetimeHandle scope = lifetime_lua_begin_scope(L);
    (void)scope;

    int result = luaL_dostring(L, line);
    if (result != LUA_OK) {
        const char *err = lua_tostring(L, -1);
        if (client_slot >= 0) {
            console_error("Error: %s", err ? err : "(unknown)");
        }
        LOG_CONSOLE_ERROR("Error: %s", err ? err : "(unknown)");
        lua_pop(L, 1);
    }

    // End lifetime scope
    lifetime_lua_end_scope(L);
}

// ============================================================================
// Socket Input Processing
// ============================================================================

static void socket_process_client(lua_State *L, int slot) {
    if (slot < 0 || slot >= MAX_CLIENTS) return;
    if (s_client_fds[slot] < 0) return;

    char buf[1024];
    ssize_t n = read(s_client_fds[slot], buf, sizeof(buf) - 1);

    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            socket_close_client(slot);
        }
        return;
    }

    if (n == 0) {
        // Client disconnected
        socket_close_client(slot);
        return;
    }

    buf[n] = '\0';

    // Append to client buffer
    char *client_buf = s_client_buffers[slot];
    size_t *client_len = &s_client_buffer_lens[slot];

    for (ssize_t i = 0; i < n; i++) {
        char c = buf[i];

        if (c == '\n' || c == '\r') {
            if (*client_len > 0) {
                client_buf[*client_len] = '\0';
                process_line(L, client_buf, slot);
                socket_send_prompt(slot);
                *client_len = 0;
            }
        } else if (*client_len < RECV_BUFFER_SIZE - 1) {
            client_buf[(*client_len)++] = c;
        }
    }
}

static void socket_poll_clients(lua_State *L) {
    if (s_server_fd < 0) return;

    // Accept new connections
    socket_accept_clients();

    // Check for data from clients using select with zero timeout
    fd_set read_fds;
    FD_ZERO(&read_fds);

    int max_fd = -1;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (s_client_fds[i] >= 0) {
            FD_SET(s_client_fds[i], &read_fds);
            if (s_client_fds[i] > max_fd) max_fd = s_client_fds[i];
        }
    }

    if (max_fd < 0) return;  // No clients connected

    struct timeval tv = {0, 0};  // Non-blocking
    int ready = select(max_fd + 1, &read_fds, NULL, NULL, &tv);

    if (ready <= 0) return;

    // Process clients with data
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (s_client_fds[i] >= 0 && FD_ISSET(s_client_fds[i], &read_fds)) {
            socket_process_client(L, i);
        }
    }
}

// ============================================================================
// File-based Console
// ============================================================================

static void file_console_poll(lua_State *L) {
    FILE *f = fopen(s_command_file, "r");
    if (!f) return;

    LOG_CONSOLE_DEBUG("Processing commands from %s", s_command_file);

    char line[4096];
    int cmd_count = 0;

    while (fgets(line, sizeof(line), f)) {
        cmd_count++;
        process_line(L, line, -1);  // -1 = file source
    }

    fclose(f);
    unlink(s_command_file);

    // Reset multi-line mode if file ended without closing delimiter
    if (s_multiline_mode && s_multiline_client == -1) {
        LOG_CONSOLE_WARN("Multi-line block not closed, resetting");
        s_multiline_mode = 0;
        multiline_buffer_clear();
    }

    if (cmd_count > 0) {
        LOG_CONSOLE_DEBUG("Executed %d command(s) from file", cmd_count);
    }
}

// ============================================================================
// Public API
// ============================================================================

void console_init(void) {
    if (s_initialized) return;

    // Build file-based console path
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }

    if (home) {
        snprintf(s_command_file, sizeof(s_command_file),
                 "%s/Library/Application Support/BG3SE/commands.txt", home);
    } else {
        snprintf(s_command_file, sizeof(s_command_file),
                 "/tmp/bg3se-commands.txt");
    }

    // Initialize socket server
    socket_server_init();

    multiline_buffer_clear();
    s_initialized = 1;

    LOG_CONSOLE_INFO("Console initialized");
    LOG_CONSOLE_INFO("  Socket: %s", CONSOLE_SOCKET_PATH);
    LOG_CONSOLE_INFO("  File: %s", s_command_file);
}

void console_shutdown(void) {
    socket_server_shutdown();
    s_initialized = 0;
    LOG_CONSOLE_INFO("Console shutdown");
}

const char *console_get_command_file(void) {
    if (!s_initialized) console_init();
    return s_command_file;
}

const char *console_get_socket_path(void) {
    return CONSOLE_SOCKET_PATH;
}

bool console_has_client(void) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (s_client_fds[i] >= 0) return true;
    }
    return false;
}

void console_poll(lua_State *L) {
    if (!L) return;
    if (!s_initialized) console_init();
    s_lua_state = L;

    // Execute any queued overlay commands on this Lua-owning tick thread.
    drain_overlay_command_queue();

    // Poll socket clients (higher priority, real-time)
    socket_poll_clients(L);

    // Poll file-based console (fallback)
    file_console_poll(L);
}

// ============================================================================
// Direct Lua Execution (for overlay console)
// ============================================================================

void console_set_lua_state(lua_State *L) {
    s_lua_state = L;
}

void console_queue_lua_command(const char *command) {
    if (!command) return;

    char *copy = strdup(command);
    if (!copy) {
        LOG_CONSOLE_ERROR("console_queue_lua_command: strdup failed");
        return;
    }

    pthread_mutex_lock(&s_overlay_cmd_mutex);

    uint32_t next_tail = (s_overlay_cmd_tail + 1) % OVERLAY_COMMAND_QUEUE_CAPACITY;
    if (next_tail == s_overlay_cmd_head) {
        // Queue full: drop oldest
        char *old = s_overlay_cmd_queue[s_overlay_cmd_head];
        s_overlay_cmd_queue[s_overlay_cmd_head] = NULL;
        s_overlay_cmd_head = (s_overlay_cmd_head + 1) % OVERLAY_COMMAND_QUEUE_CAPACITY;
        if (old) free(old);
    }

    s_overlay_cmd_queue[s_overlay_cmd_tail] = copy;
    s_overlay_cmd_tail = next_tail;

    pthread_mutex_unlock(&s_overlay_cmd_mutex);
}

bool console_execute_lua(const char *command) {
    if (!command || !s_lua_state) {
        LOG_CONSOLE_WARN("console_execute_lua: no Lua state available");
        return false;
    }

    LOG_CONSOLE_DEBUG("Overlay execute: %s", command);

    // Begin lifetime scope for console command
    LifetimeHandle scope = lifetime_lua_begin_scope(s_lua_state);
    (void)scope;

    int result = luaL_dostring(s_lua_state, command);
    if (result != LUA_OK) {
        const char *err = lua_tostring(s_lua_state, -1);
        console_error("Error: %s", err ? err : "unknown error");
        lua_pop(s_lua_state, 1);
        lifetime_lua_end_scope(s_lua_state);
        return false;
    }

    // End lifetime scope - userdata created during command become invalid
    lifetime_lua_end_scope(s_lua_state);
    return true;
}
