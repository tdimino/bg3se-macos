/**
 * console.c - File-based Lua console with multi-line support
 *
 * Features:
 * - Poll a file, execute each line as Lua, delete file
 * - Multi-line mode: Accumulate lines between --[[ and ]]-- delimiters
 * - Console commands: Lines starting with ! are dispatched to registered handlers
 */

#include "console.h"
#include "../core/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <ctype.h>
#include <lauxlib.h>

// Command file path (resolved at init)
static char s_command_file[512] = {0};
static int s_initialized = 0;

// Multi-line buffer
#define MULTILINE_BUFFER_SIZE 65536
static char s_multiline_buffer[MULTILINE_BUFFER_SIZE];
static size_t s_multiline_len = 0;
static int s_multiline_mode = 0;

// Console command registry
#define MAX_CONSOLE_COMMANDS 32
typedef struct {
    char name[64];
    int lua_callback_ref;  // Reference to Lua callback function
} ConsoleCommand;

static ConsoleCommand s_commands[MAX_CONSOLE_COMMANDS];
static int s_command_count = 0;
static lua_State *s_lua_state = NULL;

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
        log_message("[Console] Warning: Multi-line buffer overflow, truncating");
    }
}

// ============================================================================
// String Utilities
// ============================================================================

static const char *trim_whitespace(const char *str) {
    while (*str && isspace((unsigned char)*str)) str++;
    return str;
}

// Reserved for future use
#if 0
static char *trim_trailing_whitespace(char *str) {
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
    return str;
}
#endif

// ============================================================================
// Console Command System
// ============================================================================

int console_register_command(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);

    if (s_command_count >= MAX_CONSOLE_COMMANDS) {
        return luaL_error(L, "Maximum console commands reached (%d)", MAX_CONSOLE_COMMANDS);
    }

    // Store the callback reference
    lua_pushvalue(L, 2);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);

    strncpy(s_commands[s_command_count].name, name, sizeof(s_commands[0].name) - 1);
    s_commands[s_command_count].name[sizeof(s_commands[0].name) - 1] = '\0';
    s_commands[s_command_count].lua_callback_ref = ref;
    s_command_count++;

    log_message("[Console] Registered command: !%s", name);
    return 0;
}

static int dispatch_console_command(lua_State *L, const char *line) {
    // Parse command name and arguments
    // Format: !command arg1 arg2 ...
    char cmd_buffer[256];
    strncpy(cmd_buffer, line + 1, sizeof(cmd_buffer) - 1);  // Skip the '!'
    cmd_buffer[sizeof(cmd_buffer) - 1] = '\0';

    // Tokenize
    char *cmd_name = strtok(cmd_buffer, " \t");
    if (!cmd_name) return 0;

    // Find the command
    for (int i = 0; i < s_command_count; i++) {
        if (strcmp(s_commands[i].name, cmd_name) == 0) {
            // Get callback from registry
            lua_rawgeti(L, LUA_REGISTRYINDEX, s_commands[i].lua_callback_ref);

            // Push command name as first argument
            lua_pushstring(L, cmd_name);

            // Push remaining arguments
            int argc = 1;
            char *arg;
            while ((arg = strtok(NULL, " \t")) != NULL && argc < 10) {
                lua_pushstring(L, arg);
                argc++;
            }

            // Call the function
            if (lua_pcall(L, argc, 0, 0) != LUA_OK) {
                const char *err = lua_tostring(L, -1);
                log_message("[Console] Command error: %s", err ? err : "(unknown)");
                lua_pop(L, 1);
            }
            return 1;
        }
    }

    // Built-in !help command
    if (strcmp(cmd_name, "help") == 0) {
        log_message("[Console] Available commands:");
        log_message("  !help - Show this help");
        for (int i = 0; i < s_command_count; i++) {
            log_message("  !%s", s_commands[i].name);
        }
        return 1;
    }

    log_message("[Console] Unknown command: !%s (try !help)", cmd_name);
    return 0;
}

// ============================================================================
// Initialization and Polling
// ============================================================================

void console_init(void) {
    if (s_initialized) return;

    // Build path: ~/Library/Application Support/BG3SE/commands.txt
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }

    if (home) {
        snprintf(s_command_file, sizeof(s_command_file),
                 "%s/Library/Application Support/BG3SE/commands.txt", home);
    } else {
        // Fallback to /tmp
        snprintf(s_command_file, sizeof(s_command_file),
                 "/tmp/bg3se-commands.txt");
    }

    multiline_buffer_clear();
    s_initialized = 1;
    log_message("[Console] Command file: %s", s_command_file);
    log_message("[Console] Multi-line mode: Use --[[ to start, ]]-- to end and execute");
}

const char *console_get_command_file(void) {
    if (!s_initialized) console_init();
    return s_command_file;
}

void console_poll(lua_State *L) {
    if (!L) return;
    if (!s_initialized) console_init();
    s_lua_state = L;  // Store for command dispatch

    FILE *f = fopen(s_command_file, "r");
    if (!f) return;

    log_message("[Console] Processing commands from %s", s_command_file);

    char line[4096];
    int cmd_count = 0;

    while (fgets(line, sizeof(line), f)) {
        // Remove trailing newline
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }

        // Skip empty lines (but allow them in multi-line mode)
        if (len == 0 && !s_multiline_mode) continue;

        // Skip comments (but allow them in multi-line mode)
        if (line[0] == '#' && !s_multiline_mode) continue;

        const char *trimmed = trim_whitespace(line);

        // Check for multi-line start delimiter
        if (strcmp(trimmed, "--[[") == 0) {
            if (s_multiline_mode) {
                log_message("[Console] Warning: Already in multi-line mode, resetting");
            }
            s_multiline_mode = 1;
            multiline_buffer_clear();
            log_message("[Console] Entering multi-line mode...");
            continue;
        }

        // Check for multi-line end delimiter
        if (s_multiline_mode && strcmp(trimmed, "]]--") == 0) {
            s_multiline_mode = 0;
            cmd_count++;
            log_message("[Console] Executing multi-line block (%zu bytes)", s_multiline_len);

            int result = luaL_dostring(L, s_multiline_buffer);
            if (result != LUA_OK) {
                const char *err = lua_tostring(L, -1);
                log_message("[Console] Error: %s", err ? err : "(unknown)");
                lua_pop(L, 1);
            }
            multiline_buffer_clear();
            continue;
        }

        // In multi-line mode, accumulate lines
        if (s_multiline_mode) {
            multiline_buffer_append(line);
            multiline_buffer_append("\n");
            continue;
        }

        // Check for console command (! prefix)
        if (line[0] == '!') {
            cmd_count++;
            log_message("[Console] ! %s", line + 1);
            dispatch_console_command(L, line);
            continue;
        }

        // Normal single-line execution
        cmd_count++;
        log_message("[Console] > %s", line);

        int result = luaL_dostring(L, line);
        if (result != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            log_message("[Console] Error: %s", err ? err : "(unknown)");
            lua_pop(L, 1);
        }
    }

    fclose(f);
    unlink(s_command_file);  // Delete after processing

    // Reset multi-line mode if file ended without closing delimiter
    if (s_multiline_mode) {
        log_message("[Console] Warning: Multi-line block not closed, resetting");
        s_multiline_mode = 0;
        multiline_buffer_clear();
    }

    if (cmd_count > 0) {
        log_message("[Console] Executed %d command(s)", cmd_count);
    }
}
