/**
 * console.c - File-based Lua console
 *
 * Simple implementation: poll a file, execute each line as Lua, delete file.
 */

#include "console.h"
#include "../core/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <lauxlib.h>

// Command file path (resolved at init)
static char s_command_file[512] = {0};
static int s_initialized = 0;

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

    s_initialized = 1;
    log_message("[Console] Command file: %s", s_command_file);
}

const char *console_get_command_file(void) {
    if (!s_initialized) console_init();
    return s_command_file;
}

void console_poll(lua_State *L) {
    if (!L) return;
    if (!s_initialized) console_init();

    FILE *f = fopen(s_command_file, "r");
    if (!f) return;

    log_message("[Console] Processing commands from %s", s_command_file);

    char cmd[4096];
    int cmd_count = 0;

    while (fgets(cmd, sizeof(cmd), f)) {
        // Skip empty lines and comments
        if (cmd[0] == '\n' || cmd[0] == '#') continue;

        // Remove trailing newline
        size_t len = strlen(cmd);
        if (len > 0 && cmd[len - 1] == '\n') {
            cmd[len - 1] = '\0';
        }

        cmd_count++;
        log_message("[Console] > %s", cmd);

        int result = luaL_dostring(L, cmd);
        if (result != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            log_message("[Console] Error: %s", err ? err : "(unknown)");
            lua_pop(L, 1);
        }
    }

    fclose(f);
    unlink(s_command_file);  // Delete after processing

    if (cmd_count > 0) {
        log_message("[Console] Executed %d command(s)", cmd_count);
    }
}
