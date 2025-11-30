/**
 * arm64_call.c - ARM64 ABI utilities for calling BG3 functions
 *
 * Implementation of ARM64-specific function call wrappers.
 */

#include "arm64_call.h"
#include "../core/logging.h"

#include <string.h>
#include <stdarg.h>
#include <stdio.h>

// Logging helper for ARM64 module
static void log_arm64(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void log_arm64(const char *fmt, ...) {
    char buf[512];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    log_message("[ARM64] %s", buf);
}

// ============================================================================
// ARM64 Function Call Wrappers
// ============================================================================

#if defined(__aarch64__) || defined(__arm64__)

void* call_try_get_singleton_with_x8(void *fn, void *entityWorld) {
    LsResult result;
    memset(&result, 0, sizeof(result));
    result.has_error = 1;  // Assume error until function sets success

    __asm__ volatile (
        "mov x8, %[buf]\n"        // x8 = pointer to result buffer (ARM64 ABI for large struct return)
        "mov x0, %[world]\n"      // x0 = entityWorld parameter
        "blr %[fn]\n"             // Call the function
        : "+m"(result)            // result may be modified
        : [buf] "r"(&result),
          [world] "r"(entityWorld),
          [fn] "r"(fn)
        : "x0", "x1", "x8", "x9", "x10", "x11", "x12", "x13",
          "x14", "x15", "x16", "x17", "x19", "x20",
          "x21", "x22", "x23", "x24", "x25", "x26",
          "x30", "memory"
    );

    // Check result
    if (result.has_error == 0 && result.value != NULL) {
        log_arm64("TryGetSingleton succeeded: value=%p", result.value);
        return result.value;
    } else {
        log_arm64("TryGetSingleton failed: has_error=%d, value=%p",
                  result.has_error, result.value);
        return NULL;
    }
}

bool arm64_call_available(void) {
    return true;
}

#else
// x86_64 fallback - struct returns work differently

void* call_try_get_singleton_with_x8(void *fn, void *entityWorld) {
    (void)fn;
    (void)entityWorld;
    log_arm64("TryGetSingleton not implemented for x86_64");
    return NULL;
}

bool arm64_call_available(void) {
    return false;
}

#endif
