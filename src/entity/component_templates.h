/**
 * component_templates.h - Known GetComponent<T> template addresses
 *
 * On macOS, there's no GetRawComponent dispatcher - each GetComponent<T>
 * is template-inlined. This header contains addresses discovered via Ghidra
 * analysis for direct component access.
 *
 * IMPORTANT: These are Ghidra addresses (base 0x100000000).
 * At runtime, add the ASLR slide to get actual addresses.
 */

#ifndef COMPONENT_TEMPLATES_H
#define COMPONENT_TEMPLATES_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

// ============================================================================
// Ghidra Base Address
// ============================================================================

#define GHIDRA_BASE_ADDRESS 0x100000000ULL

// ============================================================================
// Key Entity System Offsets
// ============================================================================

// EntityWorld structure offsets
#define ENTITYWORLD_STORAGE_OFFSET      0x2d0   // EntityStorageContainer*
#define ENTITYWORLD_CACHE_OFFSET        0x3f0   // ImmediateWorldCache*

// EntityStorageContainer::TryGet function address (Ghidra)
#define ADDR_TRYGET_GHIDRA              0x10636b27c

// ============================================================================
// Known Component Template Entry
// ============================================================================

typedef struct {
    const char* name;           // Full component name (e.g., "ecl::Item")
    uintptr_t ghidra_addr;      // GetComponent<T> address in Ghidra
    size_t component_size;      // Approximate size (0 if unknown)
} ComponentTemplateEntry;

// ============================================================================
// Known Component Templates Table
// ============================================================================
//
// Discovered via Ghidra analysis of ecs::EntityWorld::GetComponent<T> templates.
// See ghidra/offsets/COMPONENTS.md for discovery methodology.

static const ComponentTemplateEntry g_ComponentTemplates[] = {
    // Client-side components (ecl:: namespace)
    {"ecl::Item",                           0x100cb1644, 0},
    {"ecl::Character",                      0x100cc20a8, 0},

    // Combat components (eoc::combat:: namespace)
    {"eoc::combat::ParticipantComponent",   0x100cc1d7c, 0},

    // Anubis/animation components (ls::anubis:: namespace)
    {"ls::anubis::TreeComponent",           0x100c8ec50, 0},

    // Navigation components (navcloud:: namespace)
    {"navcloud::PathRequestComponent",      0x100da66c8, 0},

    // Controller components (eoc::controller:: namespace)
    {"eoc::controller::LocomotionComponent", 0x100e1c66c, 0},

    // Sentinel - must be last
    {NULL, 0, 0}
};

// ============================================================================
// Template Lookup Function
// ============================================================================

/**
 * Look up a GetComponent<T> template address by component name.
 *
 * @param name Component name (e.g., "ecl::Item")
 * @return Ghidra address of GetComponent<T>, or 0 if not found
 */
static inline uintptr_t component_template_lookup(const char* name) {
    if (!name) return 0;

    for (size_t i = 0; g_ComponentTemplates[i].name != NULL; i++) {
        // Exact match
        if (strcmp(g_ComponentTemplates[i].name, name) == 0) {
            return g_ComponentTemplates[i].ghidra_addr;
        }
    }

    return 0;
}

/**
 * Get the number of known component templates.
 */
static inline size_t component_template_count(void) {
    size_t count = 0;
    while (g_ComponentTemplates[count].name != NULL) {
        count++;
    }
    return count;
}

#endif // COMPONENT_TEMPLATES_H
