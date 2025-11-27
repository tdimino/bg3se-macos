/**
 * BG3SE-macOS - Baldur's Gate 3 Script Extender for macOS
 *
 * Proof of Concept: DYLD injection into BG3
 *
 * This dylib is loaded via DYLD_INSERT_LIBRARIES before the game starts.
 * The constructor runs automatically when the library is loaded.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <dlfcn.h>
#include <time.h>
#include <unistd.h>
#include <mach-o/dyld.h>

#include "../hooks/osiris_hooks.h"

// Version info
#define BG3SE_VERSION "0.2.0"
#define BG3SE_NAME "BG3SE-macOS"

// Log file for debugging
#define LOG_FILE "/tmp/bg3se_macos.log"

// Forward declarations
static void log_message(const char *format, ...);
static void enumerate_loaded_images(void);
static void check_osiris_library(void);

/**
 * Write to both syslog and our log file
 */
static void log_message(const char *format, ...) {
    va_list args;
    char buffer[1024];

    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    // Write to syslog
    syslog(LOG_ERR, "[%s] %s", BG3SE_NAME, buffer);

    // Write to log file
    FILE *f = fopen(LOG_FILE, "a");
    if (f) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
                t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                t->tm_hour, t->tm_min, t->tm_sec, buffer);
        fclose(f);
    }
}

/**
 * Enumerate all loaded dynamic libraries
 * This helps us understand what's loaded and find libOsiris.dylib
 */
static void enumerate_loaded_images(void) {
    uint32_t count = _dyld_image_count();
    log_message("Loaded images: %u", count);

    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name) {
            // Only log interesting ones (not system frameworks)
            if (strstr(name, "Baldur") || strstr(name, "Osiris") ||
                strstr(name, "steam") || strstr(name, "BG3") ||
                strstr(name, "bg3se")) {
                log_message("  [%u] %s", i, name);
            }
        }
    }
}

/**
 * Check if libOsiris.dylib is loaded and examine its exports
 */
static void check_osiris_library(void) {
    // Try to find libOsiris.dylib - use full path since RTLD_NOLOAD needs it
    void *osiris = dlopen("@rpath/libOsiris.dylib", RTLD_NOLOAD);

    if (!osiris) {
        // Try with explicit path
        osiris = dlopen("/Users/tomdimino/Library/Application Support/Steam/steamapps/common/Baldurs Gate 3/Baldur's Gate 3.app/Contents/Frameworks/libOsiris.dylib", RTLD_NOW);
    }

    if (osiris) {
        log_message("libOsiris.dylib handle obtained!");

        // These are the actual exported C symbols (with underscore prefix stripped by dlsym)
        void *debugHook = dlsym(osiris, "DebugHook");
        void *createRule = dlsym(osiris, "CreateRule");
        void *defineFunction = dlsym(osiris, "DefineFunction");
        void *setInitSection = dlsym(osiris, "SetInitSection");

        // Try C++ mangled names for COsiris methods
        void *initGame = dlsym(osiris, "_ZN7COsiris8InitGameEv");
        void *load = dlsym(osiris, "_ZN7COsiris4LoadER12COsiSmartBuf");

        log_message("  DebugHook: %p", debugHook);
        log_message("  CreateRule: %p", createRule);
        log_message("  DefineFunction: %p", defineFunction);
        log_message("  SetInitSection: %p", setInitSection);
        log_message("  COsiris::InitGame: %p", initGame);
        log_message("  COsiris::Load: %p", load);

        // Install hooks now that we have the library loaded
        log_message("Attempting to install Osiris hooks...");
        int hook_result = install_osiris_hooks();
        if (hook_result == 0) {
            log_message("Osiris hooks installed successfully!");
        } else {
            log_message("Failed to install Osiris hooks (code: %d)", hook_result);
        }

        // Don't close - we need these for hooks
        // dlclose(osiris);
    } else {
        log_message("libOsiris.dylib not yet loaded (this is normal at init time)");
        log_message("  dlerror: %s", dlerror());
    }
}

/**
 * Callback for when new images are loaded
 * This lets us know when libOsiris.dylib becomes available
 */
static void image_added_callback(const struct mach_header *mh, intptr_t slide) {
    // Find the name of this image
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        if (_dyld_get_image_header(i) == mh) {
            const char *name = _dyld_get_image_name(i);
            if (name && strstr(name, "libOsiris")) {
                log_message(">>> libOsiris.dylib loaded! Slide: 0x%lx", (long)slide);
                check_osiris_library();
            }
            break;
        }
    }
}

/**
 * Main constructor - runs when dylib is loaded
 */
__attribute__((constructor))
static void bg3se_init(void) {
    // Clear log file
    FILE *f = fopen(LOG_FILE, "w");
    if (f) {
        fprintf(f, "=== %s v%s ===\n", BG3SE_NAME, BG3SE_VERSION);
        fprintf(f, "Injection timestamp: %ld\n", (long)time(NULL));
        fprintf(f, "Process ID: %d\n", getpid());
        fclose(f);
    }

    log_message("=== %s v%s initialized ===", BG3SE_NAME, BG3SE_VERSION);
    log_message("Running in process: %s (PID: %d)", getprogname(), getpid());

    // Get architecture
#if defined(__arm64__)
    log_message("Architecture: ARM64 (Apple Silicon)");
#elif defined(__x86_64__)
    log_message("Architecture: x86_64 (Intel)");
#else
    log_message("Architecture: Unknown");
#endif

    // Enumerate loaded images
    enumerate_loaded_images();

    // Check for Osiris
    check_osiris_library();

    // Register callback for when new images load
    _dyld_register_func_for_add_image(image_added_callback);

    log_message("Image load callback registered");
    log_message("=== Initialization complete ===");

    // Write success marker
    f = fopen("/tmp/bg3se_loaded.txt", "w");
    if (f) {
        fprintf(f, "BG3SE-macOS loaded successfully at %ld\n", (long)time(NULL));
        fprintf(f, "Check %s for detailed logs\n", LOG_FILE);
        fclose(f);
    }
}

/**
 * Destructor - runs when dylib is unloaded (usually at process exit)
 */
__attribute__((destructor))
static void bg3se_cleanup(void) {
    log_message("=== %s shutting down ===", BG3SE_NAME);
}
