/**
 * BG3SE-macOS - Component Registry
 *
 * Runtime component discovery and index-based component access.
 *
 * Architecture mirrors Windows bg3se:
 * - ComponentTypeIndex is a uint16_t discovered at runtime
 * - GetRawComponent is a single dispatcher function
 * - Component names map to indices via ComponentRegistry
 *
 * Key insight: Component strings in the binary are RTTI metadata with NO XREFs.
 * The game uses index-based lookup, not direct function pointers.
 */

#ifndef COMPONENT_REGISTRY_H
#define COMPONENT_REGISTRY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// ComponentTypeIndex - matches bg3se definition
// ============================================================================

/**
 * Component type index, registered statically during game startup.
 * The high bit (0x8000) indicates a "one-frame" component.
 */
typedef uint16_t ComponentTypeIndex;

// Special values
#define COMPONENT_INDEX_UNDEFINED ((ComponentTypeIndex)0xFFFF)
#define COMPONENT_INDEX_ONE_FRAME_BIT 0x8000

// Check if component is a one-frame component
static inline bool component_is_one_frame(ComponentTypeIndex idx) {
    return (idx & COMPONENT_INDEX_ONE_FRAME_BIT) != 0;
}

// ============================================================================
// Component Info Structure
// ============================================================================

/**
 * Information about a discovered component type.
 */
typedef struct {
    const char *name;           // Full qualified name (e.g., "eoc::HealthComponent")
    ComponentTypeIndex index;   // Runtime type index
    uint16_t size;              // Component size in bytes
    bool is_proxy;              // Is this a proxy component?
    bool is_one_frame;          // Is this a one-frame component?
    bool discovered;            // Has this been discovered at runtime?
} ComponentInfo;

// ============================================================================
// Registry Configuration
// ============================================================================

// Maximum number of components the registry can track
#define COMPONENT_REGISTRY_MAX_COMPONENTS 2048

// Maximum component name length
#define COMPONENT_MAX_NAME_LEN 128

// ============================================================================
// Public API
// ============================================================================

/**
 * Initialize the component registry.
 * Must be called after EntityWorld is captured.
 *
 * @param entityWorld Pointer to the captured EntityWorld
 * @return true on success, false on failure
 */
bool component_registry_init(void *entityWorld);

/**
 * Check if registry is initialized and ready.
 */
bool component_registry_ready(void);

/**
 * Look up a component by name.
 *
 * @param name Full qualified component name (e.g., "eoc::HealthComponent")
 * @return Pointer to ComponentInfo, or NULL if not found
 */
const ComponentInfo *component_registry_lookup(const char *name);

/**
 * Look up a component by index.
 *
 * @param index Component type index
 * @return Pointer to ComponentInfo, or NULL if not found
 */
const ComponentInfo *component_registry_lookup_by_index(ComponentTypeIndex index);

/**
 * Register a manually discovered component.
 * Used when hooking component registration at runtime.
 *
 * @param name Component name
 * @param index Type index
 * @param size Component size
 * @param is_proxy Is proxy component
 * @return true on success
 */
bool component_registry_register(const char *name, ComponentTypeIndex index,
                                  uint16_t size, bool is_proxy);

/**
 * Get the number of discovered components.
 */
int component_registry_count(void);

/**
 * Iterate all discovered components.
 * Callback receives ComponentInfo pointer, returns true to continue.
 */
typedef bool (*ComponentIteratorFn)(const ComponentInfo *info, void *userdata);
void component_registry_iterate(ComponentIteratorFn callback, void *userdata);

// ============================================================================
// GetRawComponent API
// ============================================================================

/**
 * Get raw component data for an entity.
 * This is the C wrapper around EntityWorld::GetRawComponent.
 *
 * @param entityWorld EntityWorld pointer
 * @param entityHandle Entity handle (64-bit)
 * @param typeIndex Component type index
 * @param componentSize Expected component size (for validation)
 * @param isProxy Is this a proxy component access?
 * @return Pointer to component data, or NULL if not found
 */
void *component_get_raw(void *entityWorld, uint64_t entityHandle,
                        ComponentTypeIndex typeIndex, size_t componentSize,
                        bool isProxy);

/**
 * Get component by name (convenience wrapper).
 * Looks up index from registry, then calls component_get_raw.
 *
 * @param entityWorld EntityWorld pointer
 * @param entityHandle Entity handle
 * @param componentName Full qualified component name
 * @return Pointer to component data, or NULL
 */
void *component_get_by_name(void *entityWorld, uint64_t entityHandle,
                            const char *componentName);

// ============================================================================
// Discovery Functions
// ============================================================================

/**
 * Attempt to discover GetRawComponent function address.
 * Uses pattern scanning and/or Frida injection results.
 *
 * @param binaryBase Base address of main game binary
 * @return true if GetRawComponent was found
 */
bool component_discover_get_raw_component(void *binaryBase);

/**
 * Attempt to discover ComponentRegistry within EntityWorld.
 * Looks for the registry structure containing component metadata.
 *
 * @param entityWorld EntityWorld pointer
 * @return true if registry was found and parsed
 */
bool component_discover_registry(void *entityWorld);

/**
 * Dump known component registry to log for debugging.
 */
void component_registry_dump(void);

// ============================================================================
// Frida Integration
// ============================================================================

/**
 * Set GetRawComponent address discovered via Frida.
 * Called from Frida script via IPC or shared memory.
 */
void component_set_get_raw_component_addr(void *addr);

/**
 * Add component discovered via Frida runtime hooking.
 */
void component_add_frida_discovery(const char *name, ComponentTypeIndex index,
                                    uint16_t size);

#ifdef __cplusplus
}
#endif

#endif // COMPONENT_REGISTRY_H
