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

void* call_get_raw_component(void *fn, void *entityWorld, uint64_t entityHandle,
                              uint16_t typeIndex, size_t componentSize, bool isProxy) {
    if (!fn || !entityWorld) {
        return NULL;
    }

    // ARM64 calling convention:
    // x0 = entityWorld
    // x1 = entityHandle (64-bit)
    // w2 = typeIndex (16-bit, zero-extended to 32-bit)
    // x3 = componentSize (64-bit)
    // w4 = isProxy (bool, zero-extended to 32-bit)
    // Return: x0 = component pointer
    //
    // This is a standard call - no x8 indirect return needed since
    // GetRawComponent returns a pointer (8 bytes)

    typedef void* (*GetRawComponentFn)(void*, uint64_t, uint32_t, uint64_t, uint32_t);
    GetRawComponentFn func = (GetRawComponentFn)fn;

    void *result = func(entityWorld, entityHandle, (uint32_t)typeIndex,
                        (uint64_t)componentSize, isProxy ? 1 : 0);

    if (result) {
        log_arm64("GetRawComponent returned: %p (typeIndex=%u)", result, typeIndex);
    }

    return result;
}

void* call_get_component_template(void *fn_addr, void *entityWorld, uint64_t entityHandle) {
    if (!fn_addr || !entityWorld) {
        log_arm64("call_get_component_template: NULL fn_addr=%p or entityWorld=%p", fn_addr, entityWorld);
        return NULL;
    }

    log_arm64("call_get_component_template: fn=%p, world=%p, handle=0x%llx",
              fn_addr, entityWorld, (unsigned long long)entityHandle);

    // GetComponent<T> signature: T* (EntityWorld* this, EntityHandle handle)
    // ARM64 calling convention:
    // x0 = this (EntityWorld*)
    // x1 = entityHandle (64-bit)
    // Return: x0 = component pointer (or NULL)
    //
    // This is a standard call - no x8 indirect return needed since
    // GetComponent returns a pointer (8 bytes)

    void *result;
    __asm__ volatile (
        "mov x0, %[world]\n"
        "mov x1, %[handle]\n"
        "blr %[fn]\n"
        "mov %[result], x0\n"
        : [result] "=r"(result)
        : [world] "r"(entityWorld),
          [handle] "r"(entityHandle),
          [fn] "r"(fn_addr)
        : "x0", "x1", "x8", "x9", "x10", "x11", "x12", "x13",
          "x14", "x15", "x16", "x17", "x30", "memory"
    );

    if (result) {
        log_arm64("GetComponent<T> returned: %p", result);
    }

    return result;
}

void* call_try_get(void *fn_addr, void *storageContainer, uint64_t entityHandle) {
    if (!fn_addr || !storageContainer) {
        return NULL;
    }

    // TryGet signature: EntityStorageData* (EntityStorageContainer* this, EntityHandle handle)
    // ARM64 calling convention:
    // x0 = this (EntityStorageContainer*)
    // x1 = entityHandle (64-bit)
    // Return: x0 = EntityStorageData* (or NULL)

    void *result;
    __asm__ volatile (
        "mov x0, %[storage]\n"
        "mov x1, %[handle]\n"
        "blr %[fn]\n"
        "mov %[result], x0\n"
        : [result] "=r"(result)
        : [storage] "r"(storageContainer),
          [handle] "r"(entityHandle),
          [fn] "r"(fn_addr)
        : "x0", "x1", "x8", "x9", "x10", "x11", "x12", "x13",
          "x14", "x15", "x16", "x17", "x30", "memory"
    );

    if (result) {
        log_arm64("TryGet returned: %p", result);
    }

    return result;
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

void* call_get_raw_component(void *fn, void *entityWorld, uint64_t entityHandle,
                              uint16_t typeIndex, size_t componentSize, bool isProxy) {
    (void)fn;
    (void)entityWorld;
    (void)entityHandle;
    (void)typeIndex;
    (void)componentSize;
    (void)isProxy;
    log_arm64("call_get_raw_component not implemented for x86_64");
    return NULL;
}

void* call_get_component_template(void *fn_addr, void *entityWorld, uint64_t entityHandle) {
    (void)fn_addr;
    (void)entityWorld;
    (void)entityHandle;
    log_arm64("call_get_component_template not implemented for x86_64");
    return NULL;
}

void* call_try_get(void *fn_addr, void *storageContainer, uint64_t entityHandle) {
    (void)fn_addr;
    (void)storageContainer;
    (void)entityHandle;
    log_arm64("call_try_get not implemented for x86_64");
    return NULL;
}

#endif
