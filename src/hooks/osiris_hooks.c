/**
 * BG3SE-macOS - Osiris Engine Hooks
 *
 * This file implements hooks for the Osiris scripting engine functions.
 * We intercept key functions to:
 * 1. Initialize our Lua runtime at the right time
 * 2. Extend scripting capabilities
 * 3. Dispatch events to mods
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

// ============================================
// Original function pointers (filled by fishhook)
// ============================================

// C functions from libOsiris
static void (*orig_DebugHook)(int) = NULL;
static void (*orig_CreateRule)(void) = NULL;
static void (*orig_DefineFunction)(void) = NULL;
static void (*orig_SetInitSection)(void) = NULL;

// Track hook state
static int hooks_installed = 0;
static int osiris_initialized = 0;

// ============================================
// Hook implementations
// ============================================

/**
 * Hook for DebugHook - called during debug operations
 */
static void hooked_DebugHook(int arg) {
    hook_log("DebugHook called with arg: %d", arg);

    if (orig_DebugHook) {
        orig_DebugHook(arg);
    }
}

/**
 * Hook for CreateRule - called when Osiris rules are created
 * This is a key extension point for script mods
 */
static void hooked_CreateRule(void) {
    static int rule_count = 0;
    rule_count++;

    // Only log occasionally to avoid spam
    if (rule_count <= 5 || rule_count % 100 == 0) {
        hook_log("CreateRule called (count: %d)", rule_count);
    }

    if (orig_CreateRule) {
        orig_CreateRule();
    }
}

/**
 * Hook for DefineFunction - called when Osiris functions are registered
 * This lets us see what functions the game defines
 */
static void hooked_DefineFunction(void) {
    static int func_count = 0;
    func_count++;

    // Only log occasionally
    if (func_count <= 5 || func_count % 100 == 0) {
        hook_log("DefineFunction called (count: %d)", func_count);
    }

    if (orig_DefineFunction) {
        orig_DefineFunction();
    }
}

/**
 * Hook for SetInitSection - called during Osiris initialization
 */
static void hooked_SetInitSection(void) {
    hook_log("SetInitSection called - Osiris initializing");

    if (!osiris_initialized) {
        osiris_initialized = 1;
        hook_log(">>> First Osiris init - good place to initialize Lua runtime");
        // TODO: Initialize Lua runtime here
    }

    if (orig_SetInitSection) {
        orig_SetInitSection();
    }
}

// ============================================
// Hook installation
// ============================================

/**
 * Install hooks using fishhook
 * Note: fishhook works on dynamically linked symbols
 */
int install_osiris_hooks(void) {
    if (hooks_installed) {
        hook_log("Hooks already installed");
        return 0;
    }

    hook_log("Installing Osiris hooks via fishhook...");

    // Define rebindings for fishhook
    struct rebinding rebindings[] = {
        {"DebugHook", hooked_DebugHook, (void **)&orig_DebugHook},
        {"CreateRule", hooked_CreateRule, (void **)&orig_CreateRule},
        {"DefineFunction", hooked_DefineFunction, (void **)&orig_DefineFunction},
        {"SetInitSection", hooked_SetInitSection, (void **)&orig_SetInitSection},
    };

    int result = rebind_symbols(rebindings, sizeof(rebindings) / sizeof(rebindings[0]));

    if (result == 0) {
        hook_log("Fishhook rebind_symbols succeeded");
        hook_log("  orig_DebugHook: %p", orig_DebugHook);
        hook_log("  orig_CreateRule: %p", orig_CreateRule);
        hook_log("  orig_DefineFunction: %p", orig_DefineFunction);
        hook_log("  orig_SetInitSection: %p", orig_SetInitSection);
        hooks_installed = 1;
    } else {
        hook_log("Fishhook rebind_symbols failed with code: %d", result);
    }

    return result;
}

/**
 * Alternative: Direct hook installation using dlsym
 * This stores the original pointers for manual calling
 */
int install_osiris_hooks_direct(void *osiris_handle) {
    if (hooks_installed) {
        hook_log("Hooks already installed");
        return 0;
    }

    hook_log("Installing Osiris hooks via direct dlsym...");

    // Get original function pointers
    orig_DebugHook = dlsym(osiris_handle, "DebugHook");
    orig_CreateRule = dlsym(osiris_handle, "CreateRule");
    orig_DefineFunction = dlsym(osiris_handle, "DefineFunction");
    orig_SetInitSection = dlsym(osiris_handle, "SetInitSection");

    hook_log("  orig_DebugHook: %p", orig_DebugHook);
    hook_log("  orig_CreateRule: %p", orig_CreateRule);
    hook_log("  orig_DefineFunction: %p", orig_DefineFunction);
    hook_log("  orig_SetInitSection: %p", orig_SetInitSection);

    // For direct hooking, we would need to patch the GOT/PLT
    // or use inline hooking. Fishhook is preferred.

    hooks_installed = 1;
    return 0;
}

/**
 * Check if hooks are active
 */
int are_hooks_installed(void) {
    return hooks_installed;
}
