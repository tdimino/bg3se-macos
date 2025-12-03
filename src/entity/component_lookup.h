/**
 * component_lookup.h - Component lookup via data structure traversal
 *
 * On macOS, GetComponent<T> templates are completely inlined (no GetRawComponent
 * dispatcher like Windows). This module implements component lookup by manually
 * traversing EntityStorageData structures.
 *
 * Data flow:
 *   EntityWorld->Storage (0x2d0)
 *       ↓
 *   EntityStorageContainer::TryGet(EntityHandle) → EntityStorageData*
 *       ↓
 *   EntityStorageData->InstanceToPageMap (0x1c0) → EntityStorageIndex
 *       ↓
 *   EntityStorageData->ComponentTypeToIndex (0x180) → uint8_t componentSlot
 *       ↓
 *   EntityStorageData->Components (0x138) [PageIndex]->Components[slot].ComponentBuffer
 *       ↓
 *   buffer + (componentSize * EntryIndex) → Component*
 */

#ifndef COMPONENT_LOOKUP_H
#define COMPONENT_LOOKUP_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "entity_storage.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// High-Level API
// ============================================================================

/**
 * Initialize component lookup module.
 * Must be called after EntityWorld is captured.
 *
 * @param entityWorld Pointer to EntityWorld
 * @param binaryBase Base address of main binary (for ASLR calculation)
 * @return true on success
 */
bool component_lookup_init(void *entityWorld, void *binaryBase);

/**
 * Check if component lookup is ready.
 */
bool component_lookup_ready(void);

/**
 * Look up a component by type index.
 *
 * @param entityHandle 64-bit entity handle
 * @param typeIndex Component type index (from ComponentRegistry)
 * @param componentSize Size of the component (0 to auto-detect if possible)
 * @param isProxy Whether this is a proxy component (uses pointer indirection)
 * @return Pointer to component data, or NULL if not found
 */
void *component_lookup_by_index(uint64_t entityHandle, uint16_t typeIndex,
                                 size_t componentSize, bool isProxy);

/**
 * Get EntityStorageData for an entity handle.
 * This calls the game's EntityStorageContainer::TryGet function.
 *
 * @param entityHandle 64-bit entity handle
 * @return Pointer to EntityStorageData, or NULL if entity not found
 */
void *component_lookup_get_storage_data(uint64_t entityHandle);

// ============================================================================
// Low-Level HashMap Traversal (for debugging/testing)
// ============================================================================

/**
 * Look up EntityStorageIndex in InstanceToPageMap.
 *
 * @param storageData Pointer to EntityStorageData
 * @param entityHandle Entity handle to look up
 * @param outIndex Output EntityStorageIndex
 * @return true if found
 */
bool storage_data_get_instance_index(void *storageData, uint64_t entityHandle,
                                      EntityStorageIndex *outIndex);

/**
 * Look up component slot in ComponentTypeToIndex.
 *
 * @param storageData Pointer to EntityStorageData
 * @param typeIndex Component type index
 * @param outSlot Output component slot (0-255)
 * @return true if found
 */
bool storage_data_get_component_slot(void *storageData, uint16_t typeIndex,
                                      uint8_t *outSlot);

/**
 * Get component pointer from storage data.
 *
 * @param storageData Pointer to EntityStorageData
 * @param storageIndex Location from InstanceToPageMap
 * @param componentSlot Slot from ComponentTypeToIndex
 * @param componentSize Size of component (for buffer offset calculation)
 * @param isProxy Whether this is a proxy component
 * @return Pointer to component data, or NULL
 */
void *storage_data_get_component(void *storageData, EntityStorageIndex storageIndex,
                                  uint8_t componentSlot, size_t componentSize,
                                  bool isProxy);

// ============================================================================
// Debug Functions
// ============================================================================

/**
 * Dump EntityStorageData structure for debugging.
 *
 * @param storageData Pointer to EntityStorageData
 * @param entityHandle Handle for context in log messages
 */
void component_lookup_dump_storage_data(void *storageData, uint64_t entityHandle);

/**
 * Enumerate all component type indices from ComponentTypeToIndex HashMap.
 * This shows what component types are registered in a storage class.
 *
 * @param storageData Pointer to EntityStorageData
 * @param outIndices Output array for type indices
 * @param outSlots Output array for corresponding slots
 * @param maxEntries Maximum entries to return
 * @return Number of entries found
 */
int storage_data_enumerate_component_types(void *storageData,
                                            uint16_t *outIndices,
                                            uint8_t *outSlots,
                                            int maxEntries);

#ifdef __cplusplus
}
#endif

#endif // COMPONENT_LOOKUP_H
