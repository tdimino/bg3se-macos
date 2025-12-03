/**
 * component_typeid.h - TypeId<T>::m_TypeIndex global discovery
 *
 * On macOS, component type indices are stored in global variables with mangled names:
 *   __ZN2ls6TypeIdIN3ecl4ItemEN3ecs22ComponentTypeIdContextEE11m_TypeIndexE
 *
 * These variables hold the actual ComponentTypeIndex for each component type.
 * By reading them at runtime, we can discover the name→index mapping.
 */

#ifndef COMPONENT_TYPEID_H
#define COMPONENT_TYPEID_H

#include <stdbool.h>
#include <stdint.h>

// ============================================================================
// Initialization
// ============================================================================

/**
 * Initialize the TypeId discovery system.
 * @param binaryBase Base address of the main executable
 * @return true if initialization succeeded
 */
bool component_typeid_init(void *binaryBase);

/**
 * Check if the TypeId system is ready.
 */
bool component_typeid_ready(void);

// ============================================================================
// Discovery
// ============================================================================

/**
 * Discover component type indices by reading TypeId globals.
 * This reads known TypeId<T>::m_TypeIndex addresses and updates the component registry.
 * @return Number of components discovered
 */
int component_typeid_discover(void);

/**
 * Read a specific TypeId global address.
 * @param ghidraAddr The Ghidra address of the m_TypeIndex global
 * @param outIndex Output: the type index value
 * @return true if read succeeded and index is valid
 */
bool component_typeid_read(uint64_t ghidraAddr, uint16_t *outIndex);

// ============================================================================
// Debug
// ============================================================================

/**
 * Dump all known TypeId addresses and their values.
 */
void component_typeid_dump(void);

#endif // COMPONENT_TYPEID_H
