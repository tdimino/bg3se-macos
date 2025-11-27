/**
 * BG3SE-macOS - Osiris Engine Hooks
 *
 * This file implements hooks for the Osiris scripting engine functions.
 * Currently using fishhook for symbol rebinding (works for imported symbols).
 *
 * NOTE: fishhook only works for dynamically imported symbols, not internal
 * library functions. For internal functions, we'd need inline hooking.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <dlfcn.h>
#include "../../lib/fishhook/fishhook.h"

// Log helper
static void hook_log(const char *format, ...) {
    va_list args;
    char buffer[1024];

    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    syslog(LOG_ERR, "[BG3SE-Hooks] %s", buffer);

    FILE *f = fopen("/tmp/bg3se_macos.log", "a");
    if (f) {
        fprintf(f, "[HOOK] %s\n", buffer);
        fclose(f);
    }
}

// Track hook state
static int hooks_installed = 0;

/**
 * Install hooks - currently disabled, just logs
 */
int install_osiris_hooks(void) {
    if (hooks_installed) {
        hook_log("Hooks already installed");
        return 0;
    }

    // Do absolutely nothing for now - just mark as done
    hook_log("Osiris hooks: DISABLED (minimal safe mode)");
    hooks_installed = 1;
    return 0;
}

/**
 * Alternative installation method
 */
int install_osiris_hooks_direct(void *osiris_handle) {
    return install_osiris_hooks();
}

/**
 * Check if hooks are active
 */
int are_hooks_installed(void) {
    return hooks_installed;
}
