/**
 * component_typeid.c - TypeId<T>::m_TypeIndex global discovery
 *
 * Reads TypeId globals from the game binary to discover component type indices.
 * These globals are initialized at game startup with the actual indices.
 */

#include "component_typeid.h"
#include "component_registry.h"
#include "entity_storage.h"  // For GHIDRA_BASE_ADDRESS
#include "../core/logging.h"
#include "../core/safe_memory.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

// ============================================================================
// Logging
// ============================================================================

static void log_typeid(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void log_typeid(const char *fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    log_message("[ComponentTypeId] %s", buf);
}

// ============================================================================
// Known TypeId Addresses
// ============================================================================

/**
 * Table of known TypeId<T>::m_TypeIndex global addresses.
 * These were discovered via Ghidra analysis of the macOS ARM64 binary.
 *
 * Mangled name pattern:
 *   __ZN2ls6TypeIdIN3{namespace}{length}{Component}EN3ecs22ComponentTypeIdContextEE11m_TypeIndexE
 */
typedef struct {
    const char *componentName;  // Full component name (e.g., "ecl::Character")
    uint64_t ghidraAddr;        // Ghidra address of m_TypeIndex global
    uint16_t expectedSize;      // Expected component size (0 = unknown)
    bool isProxy;               // Is this a proxy component?
} TypeIdEntry;

static const TypeIdEntry g_KnownTypeIds[] = {
    // =====================================================================
    // ecl:: namespace (client components)
    // Discovered via: nm -gU "Baldur's Gate 3" | c++filt | grep TypeId
    // Game version: 4.1.1.6995620 (macOS ARM64)
    // =====================================================================
    { "ecl::Character", 0x1088ab8e0, 0, false },
    { "ecl::Item",      0x1088ab8f0, 0, false },

    // =====================================================================
    // eoc:: namespace (engine of combat)
    // =====================================================================
    { "eoc::HealthComponent",  0x10890a360, 0, false },
    { "eoc::StatsComponent",   0x10890b058, 0, false },
    { "eoc::ArmorComponent",   0x108912e40, 0, false },
    { "eoc::BaseHpComponent",  0x108907888, 0, false },
    { "eoc::DataComponent",    0x10890b088, 0, false },

    // =====================================================================
    // ls:: namespace (base Larian components)
    // =====================================================================
    { "ls::TransformComponent", 0x108940550, 0, false },
    { "ls::LevelComponent",     0x10893e780, 0, false },
    { "ls::VisualComponent",    0x108940110, 0, false },
    { "ls::PhysicsComponent",   0x10893c8e8, 0, false },

    // Sentinel
    { NULL, 0, 0, false }
};

// ============================================================================
// Global State
// ============================================================================

static void *g_BinaryBase = NULL;
static bool g_Initialized = false;

// ============================================================================
// Initialization
// ============================================================================

bool component_typeid_init(void *binaryBase) {
    if (!binaryBase) {
        log_typeid("ERROR: binaryBase is NULL");
        return false;
    }

    g_BinaryBase = binaryBase;
    g_Initialized = true;

    log_typeid("Initialized with binary base: %p", binaryBase);
    return true;
}

bool component_typeid_ready(void) {
    return g_Initialized && g_BinaryBase != NULL;
}

// ============================================================================
// TypeId Reading
// ============================================================================

bool component_typeid_read(uint64_t ghidraAddr, uint16_t *outIndex) {
    if (!component_typeid_ready() || !outIndex) {
        return false;
    }

    /* Calculate runtime address
     * Formula: runtime = ghidra - 0x100000000 + binary_base */
    uint64_t offset = ghidraAddr - GHIDRA_BASE_ADDRESS;
    mach_vm_address_t runtimeAddr = offset + (mach_vm_address_t)g_BinaryBase;

    /* Validate the runtime address before attempting to read */
    SafeMemoryInfo info = safe_memory_check_address(runtimeAddr);
    if (!info.is_valid || !info.is_readable) {
        log_typeid("  Address 0x%llx (Ghidra 0x%llx) is not readable",
                   (unsigned long long)runtimeAddr, (unsigned long long)ghidraAddr);
        return false;
    }

    /* Check for GPU carveout region */
    if (safe_memory_is_gpu_region(runtimeAddr)) {
        log_typeid("  Address 0x%llx (Ghidra 0x%llx) is in GPU region",
                   (unsigned long long)runtimeAddr, (unsigned long long)ghidraAddr);
        return false;
    }

    /* Safely read the 4-byte type index
     * TypeId<T>::m_TypeIndex is typically a 32-bit integer */
    int32_t rawValue = -1;
    if (!safe_memory_read_i32(runtimeAddr, &rawValue)) {
        log_typeid("  Failed to safely read from 0x%llx (Ghidra 0x%llx)",
                   (unsigned long long)runtimeAddr, (unsigned long long)ghidraAddr);
        return false;
    }

    /* Check for uninitialized (-1 or very large values indicate not yet registered) */
    if (rawValue < 0 || rawValue > 0xFFFF) {
        log_typeid("  Invalid TypeIndex value %d at 0x%llx (expected 0-65535)",
                   rawValue, (unsigned long long)runtimeAddr);
        return false;
    }

    *outIndex = (uint16_t)rawValue;
    log_typeid("  TypeIndex=%u at 0x%llx (Ghidra 0x%llx)",
               *outIndex, (unsigned long long)runtimeAddr, (unsigned long long)ghidraAddr);
    return true;
}

// ============================================================================
// Discovery
// ============================================================================

int component_typeid_discover(void) {
    if (!component_typeid_ready()) {
        log_typeid("ERROR: Not initialized, cannot discover");
        return 0;
    }

    log_typeid("Discovering component type indices from TypeId globals...");

    int discovered = 0;

    for (int i = 0; g_KnownTypeIds[i].componentName != NULL; i++) {
        const TypeIdEntry *entry = &g_KnownTypeIds[i];

        uint16_t typeIndex;
        if (component_typeid_read(entry->ghidraAddr, &typeIndex)) {
            log_typeid("  %s: index=%u (from 0x%llx)",
                       entry->componentName, typeIndex, (unsigned long long)entry->ghidraAddr);

            // Update the component registry with this discovered index
            bool registered = component_registry_register(
                entry->componentName,
                typeIndex,
                entry->expectedSize,
                entry->isProxy
            );

            if (registered) {
                discovered++;
            }
        } else {
            log_typeid("  %s: FAILED to read from 0x%llx",
                       entry->componentName, (unsigned long long)entry->ghidraAddr);
        }
    }

    log_typeid("Discovered %d component type indices", discovered);
    return discovered;
}

// ============================================================================
// Debug
// ============================================================================

void component_typeid_dump(void) {
    if (!component_typeid_ready()) {
        log_typeid("Not initialized");
        return;
    }

    log_typeid("=== TypeId<T>::m_TypeIndex Dump ===");
    log_typeid("Binary base: %p", g_BinaryBase);

    for (int i = 0; g_KnownTypeIds[i].componentName != NULL; i++) {
        const TypeIdEntry *entry = &g_KnownTypeIds[i];

        mach_vm_address_t runtimeAddr = entry->ghidraAddr - GHIDRA_BASE_ADDRESS + (mach_vm_address_t)g_BinaryBase;

        log_typeid("  %s:", entry->componentName);
        log_typeid("    Ghidra addr: 0x%llx", (unsigned long long)entry->ghidraAddr);
        log_typeid("    Runtime addr: 0x%llx", (unsigned long long)runtimeAddr);

        /* Check if address is readable */
        SafeMemoryInfo info = safe_memory_check_address(runtimeAddr);
        if (!info.is_valid || !info.is_readable) {
            log_typeid("    => NOT READABLE");
            continue;
        }

        if (safe_memory_is_gpu_region(runtimeAddr)) {
            log_typeid("    => GPU REGION (unsafe)");
            continue;
        }

        /* Safely read the value */
        int32_t rawValue = -1;
        if (!safe_memory_read_i32(runtimeAddr, &rawValue)) {
            log_typeid("    => READ FAILED");
            continue;
        }

        log_typeid("    Raw value: %d (0x%x)", rawValue, rawValue);

        if (rawValue >= 0 && rawValue <= 0xFFFF) {
            log_typeid("    => TypeIndex: %u", (uint16_t)rawValue);
        } else {
            log_typeid("    => INVALID (uninitialized or error)");
        }
    }
}
