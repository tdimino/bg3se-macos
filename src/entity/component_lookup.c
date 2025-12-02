/**
 * component_lookup.c - Component lookup via data structure traversal
 *
 * Implements GetComponent functionality for macOS by traversing
 * EntityStorageData structures directly, since template functions are inlined.
 */

#include "component_lookup.h"
#include "arm64_call.h"
#include "../core/logging.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

// ============================================================================
// Logging
// ============================================================================

static void log_lookup(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void log_lookup(const char *fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    log_message("[ComponentLookup] %s", buf);
}

// ============================================================================
// Global State
// ============================================================================

static void *g_EntityWorld = NULL;
static void *g_StorageContainer = NULL;  // EntityWorld + 0x2d0
static void *g_TryGetFnAddr = NULL;      // Runtime address of TryGet
static void *g_BinaryBase = NULL;
static bool g_Initialized = false;

// ============================================================================
// Initialization
// ============================================================================

bool component_lookup_init(void *entityWorld, void *binaryBase) {
    if (!entityWorld || !binaryBase) {
        log_lookup("ERROR: NULL entityWorld=%p or binaryBase=%p", entityWorld, binaryBase);
        return false;
    }

    g_EntityWorld = entityWorld;
    g_BinaryBase = binaryBase;

    // Get StorageContainer from EntityWorld + 0x2d0
    g_StorageContainer = *(void **)((char *)entityWorld + ENTITYWORLD_STORAGE_OFFSET);
    if (!g_StorageContainer) {
        log_lookup("ERROR: StorageContainer is NULL at EntityWorld+0x%x", ENTITYWORLD_STORAGE_OFFSET);
        return false;
    }

    // Calculate runtime address of TryGet function
    uintptr_t runtime_addr = ADDR_STORAGE_CONTAINER_TRYGET - GHIDRA_BASE_ADDRESS + (uintptr_t)binaryBase;
    g_TryGetFnAddr = (void *)runtime_addr;

    log_lookup("Initialized:");
    log_lookup("  EntityWorld: %p", g_EntityWorld);
    log_lookup("  StorageContainer: %p", g_StorageContainer);
    log_lookup("  TryGet: %p (Ghidra: 0x%llx)", g_TryGetFnAddr,
               (unsigned long long)ADDR_STORAGE_CONTAINER_TRYGET);

    g_Initialized = true;
    return true;
}

bool component_lookup_ready(void) {
    return g_Initialized && g_StorageContainer && g_TryGetFnAddr;
}

// ============================================================================
// TryGet - Get EntityStorageData for an entity
// ============================================================================

void *component_lookup_get_storage_data(uint64_t entityHandle) {
    if (!component_lookup_ready()) {
        log_lookup("ERROR: Not initialized");
        return NULL;
    }

    // Call EntityStorageContainer::TryGet(EntityHandle) -> EntityStorageData*
    void *result = call_try_get(g_TryGetFnAddr, g_StorageContainer, entityHandle);

    if (result) {
        log_lookup("TryGet(0x%llx) -> %p", (unsigned long long)entityHandle, result);
    } else {
        log_lookup("TryGet(0x%llx) -> NULL", (unsigned long long)entityHandle);
    }

    return result;
}

// ============================================================================
// HashMap Lookup: InstanceToPageMap
// ============================================================================

// Hash function for EntityHandle (matches game's implementation)
static uint64_t hash_entity_handle(uint64_t handle) {
    // Simple hash based on observed game behavior
    // The game appears to use the handle directly with bucket masking
    return handle;
}

bool storage_data_get_instance_index(void *storageData, uint64_t entityHandle,
                                      EntityStorageIndex *outIndex) {
    if (!storageData || !outIndex) return false;

    // InstanceToPageMap is at offset 0x1c0 from EntityStorageData
    void *map = (char *)storageData + STORAGE_DATA_INSTANCE_TO_PAGE_MAP;

    // Get HashMap components
    ArrayHeader *hashKeys = GET_HASH_KEYS(map);
    ArrayHeader *nextIds = GET_NEXT_IDS(map);
    ArrayHeader *keys = GET_KEYS(map);
    ArrayHeader *values = GET_VALUES(map);

    if (!hashKeys->buf || !keys->buf || !values->buf || hashKeys->size == 0) {
        log_lookup("InstanceToPageMap: Empty or invalid (buckets=%llu)", hashKeys->size);
        return false;
    }

    // Calculate bucket
    uint64_t hash = hash_entity_handle(entityHandle);
    uint32_t bucket = (uint32_t)(hash % hashKeys->size);

    // Get initial index from bucket
    int32_t *bucketArray = (int32_t *)hashKeys->buf;
    int32_t idx = bucketArray[bucket];

    log_lookup("InstanceToPageMap lookup: handle=0x%llx, hash=0x%llx, bucket=%u, initial_idx=%d",
               (unsigned long long)entityHandle, (unsigned long long)hash, bucket, idx);

    // Traverse collision chain
    uint64_t *keyArray = (uint64_t *)keys->buf;
    EntityStorageIndex *valueArray = (EntityStorageIndex *)values->buf;
    int32_t *nextArray = nextIds->buf ? (int32_t *)nextIds->buf : NULL;

    while (idx >= 0 && (uint64_t)idx < keys->size) {
        if (keyArray[idx] == entityHandle) {
            *outIndex = valueArray[idx];
            log_lookup("  Found at idx=%d: PageIndex=%u, EntryIndex=%u",
                       idx, outIndex->PageIndex, outIndex->EntryIndex);
            return true;
        }

        // Move to next in chain
        if (nextArray && (uint64_t)idx < nextIds->size) {
            idx = nextArray[idx];
        } else {
            break;
        }
    }

    log_lookup("  Not found in chain");
    return false;
}

// ============================================================================
// HashMap Lookup: ComponentTypeToIndex
// ============================================================================

bool storage_data_get_component_slot(void *storageData, uint16_t typeIndex,
                                      uint8_t *outSlot) {
    if (!storageData || !outSlot) return false;

    // ComponentTypeToIndex is at offset 0x180 from EntityStorageData
    void *map = (char *)storageData + STORAGE_DATA_COMPONENT_TYPE_TO_INDEX;

    // Get HashMap components
    ArrayHeader *hashKeys = GET_HASH_KEYS(map);
    ArrayHeader *nextIds = GET_NEXT_IDS(map);
    ArrayHeader *keys = GET_KEYS(map);
    ArrayHeader *values = GET_VALUES(map);

    if (!hashKeys->buf || !keys->buf || !values->buf || hashKeys->size == 0) {
        log_lookup("ComponentTypeToIndex: Empty or invalid");
        return false;
    }

    // Calculate bucket (simple hash for uint16_t)
    uint32_t bucket = typeIndex % (uint32_t)hashKeys->size;

    // Get initial index from bucket
    int32_t *bucketArray = (int32_t *)hashKeys->buf;
    int32_t idx = bucketArray[bucket];

    log_lookup("ComponentTypeToIndex lookup: type=%u, bucket=%u, initial_idx=%d",
               typeIndex, bucket, idx);

    // Traverse collision chain
    uint16_t *keyArray = (uint16_t *)keys->buf;
    uint8_t *valueArray = (uint8_t *)values->buf;
    int32_t *nextArray = nextIds->buf ? (int32_t *)nextIds->buf : NULL;

    while (idx >= 0 && (uint64_t)idx < keys->size) {
        if (keyArray[idx] == typeIndex) {
            *outSlot = valueArray[idx];
            log_lookup("  Found at idx=%d: slot=%u", idx, *outSlot);
            return true;
        }

        // Move to next in chain
        if (nextArray && (uint64_t)idx < nextIds->size) {
            idx = nextArray[idx];
        } else {
            break;
        }
    }

    log_lookup("  Type %u not found in this storage class", typeIndex);
    return false;
}

// ============================================================================
// Component Buffer Access
// ============================================================================

void *storage_data_get_component(void *storageData, EntityStorageIndex storageIndex,
                                  uint8_t componentSlot, size_t componentSize,
                                  bool isProxy) {
    if (!storageData || !storage_index_is_valid(storageIndex)) {
        return NULL;
    }

    // Get Components array at offset 0x138
    ArrayHeader *componentsArray = GET_ARRAY_HEADER(storageData, STORAGE_DATA_COMPONENTS_OFFSET);

    if (!componentsArray->buf || storageIndex.PageIndex >= componentsArray->size) {
        log_lookup("Components array: Invalid or PageIndex %u out of range (size=%llu)",
                   storageIndex.PageIndex, componentsArray->size);
        return NULL;
    }

    // Get page pointer (Components is Array<EntityStorageComponentPage*>)
    EntityStorageComponentPage **pageArray = (EntityStorageComponentPage **)componentsArray->buf;
    EntityStorageComponentPage *page = pageArray[storageIndex.PageIndex];

    if (!page) {
        log_lookup("Page %u is NULL", storageIndex.PageIndex);
        return NULL;
    }

    // Get ComponentInfo for this slot
    // Note: componentSlot is uint8_t (0-255) and COMPONENT_PAGE_SLOTS is 256,
    // so all values are valid. This check is kept for documentation purposes.
    (void)componentSlot; // All uint8_t values are valid indices

    EntityStorageComponentInfo *compInfo = &page->Components[componentSlot];
    void *buffer = compInfo->ComponentBuffer;

    if (!buffer) {
        log_lookup("ComponentBuffer is NULL for slot %u", componentSlot);
        return NULL;
    }

    // Calculate final component pointer
    void *result;
    if (isProxy) {
        // Proxy: buffer contains array of pointers
        void **ptrArray = (void **)buffer;
        result = ptrArray[storageIndex.EntryIndex];
        log_lookup("Proxy component: buffer=%p, entry=%u -> %p",
                   buffer, storageIndex.EntryIndex, result);
    } else {
        // Direct: buffer contains array of component data
        result = (char *)buffer + (componentSize * storageIndex.EntryIndex);
        log_lookup("Direct component: buffer=%p + (%zu * %u) -> %p",
                   buffer, componentSize, storageIndex.EntryIndex, result);
    }

    return result;
}

// ============================================================================
// High-Level Lookup
// ============================================================================

void *component_lookup_by_index(uint64_t entityHandle, uint16_t typeIndex,
                                 size_t componentSize, bool isProxy) {
    if (!component_lookup_ready()) {
        log_lookup("ERROR: Not initialized");
        return NULL;
    }

    log_lookup("Looking up component: handle=0x%llx, type=%u, size=%zu, proxy=%d",
               (unsigned long long)entityHandle, typeIndex, componentSize, isProxy);

    // Step 1: Get EntityStorageData
    void *storageData = component_lookup_get_storage_data(entityHandle);
    if (!storageData) {
        log_lookup("  Failed: TryGet returned NULL");
        return NULL;
    }

    // Step 2: Look up storage index (entity location in pages)
    EntityStorageIndex storageIndex;
    if (!storage_data_get_instance_index(storageData, entityHandle, &storageIndex)) {
        log_lookup("  Failed: Entity not in InstanceToPageMap");
        return NULL;
    }

    // Step 3: Look up component slot
    uint8_t componentSlot;
    if (!storage_data_get_component_slot(storageData, typeIndex, &componentSlot)) {
        log_lookup("  Failed: Component type not in this storage class");
        return NULL;
    }

    // Step 4: Get component pointer
    void *component = storage_data_get_component(storageData, storageIndex,
                                                  componentSlot, componentSize, isProxy);

    if (component) {
        log_lookup("  SUCCESS: Component at %p", component);
    } else {
        log_lookup("  Failed: Could not access component buffer");
    }

    return component;
}

// ============================================================================
// Debug Functions
// ============================================================================

void component_lookup_dump_storage_data(void *storageData, uint64_t entityHandle) {
    if (!storageData) {
        log_lookup("StorageData is NULL");
        return;
    }

    log_lookup("=== EntityStorageData Dump ===");
    log_lookup("Address: %p", storageData);
    log_lookup("For EntityHandle: 0x%llx", (unsigned long long)entityHandle);

    // Dump Components array info
    ArrayHeader *components = GET_ARRAY_HEADER(storageData, STORAGE_DATA_COMPONENTS_OFFSET);
    log_lookup("Components (offset 0x%x):", STORAGE_DATA_COMPONENTS_OFFSET);
    log_lookup("  buf: %p", components->buf);
    log_lookup("  size: %llu", components->size);

    // Dump ComponentTypeToIndex HashMap info
    void *typeMap = (char *)storageData + STORAGE_DATA_COMPONENT_TYPE_TO_INDEX;
    ArrayHeader *typeHashKeys = GET_HASH_KEYS(typeMap);
    ArrayHeader *typeKeys = GET_KEYS(typeMap);
    log_lookup("ComponentTypeToIndex (offset 0x%x):", STORAGE_DATA_COMPONENT_TYPE_TO_INDEX);
    log_lookup("  hashKeys.buf: %p, size: %llu", typeHashKeys->buf, typeHashKeys->size);
    log_lookup("  keys.buf: %p, size: %llu", typeKeys->buf, typeKeys->size);

    // Dump InstanceToPageMap HashMap info
    void *instanceMap = (char *)storageData + STORAGE_DATA_INSTANCE_TO_PAGE_MAP;
    ArrayHeader *instanceHashKeys = GET_HASH_KEYS(instanceMap);
    ArrayHeader *instanceKeys = GET_KEYS(instanceMap);
    log_lookup("InstanceToPageMap (offset 0x%x):", STORAGE_DATA_INSTANCE_TO_PAGE_MAP);
    log_lookup("  hashKeys.buf: %p, size: %llu", instanceHashKeys->buf, instanceHashKeys->size);
    log_lookup("  keys.buf: %p, size: %llu", instanceKeys->buf, instanceKeys->size);

    // Try to look up this entity
    EntityStorageIndex idx;
    if (storage_data_get_instance_index(storageData, entityHandle, &idx)) {
        log_lookup("Entity location: PageIndex=%u, EntryIndex=%u", idx.PageIndex, idx.EntryIndex);
    } else {
        log_lookup("Entity not found in InstanceToPageMap");
    }

    // Enumerate and dump all component types in this storage class
    log_lookup("Component types in this storage class:");
    uint16_t indices[256];
    uint8_t slots[256];
    int count = storage_data_enumerate_component_types(storageData, indices, slots, 256);
    for (int i = 0; i < count; i++) {
        log_lookup("  TypeIndex=%u -> Slot=%u", indices[i], slots[i]);
    }
    log_lookup("Total component types: %d", count);
}

int storage_data_enumerate_component_types(void *storageData,
                                            uint16_t *outIndices,
                                            uint8_t *outSlots,
                                            int maxEntries) {
    if (!storageData || !outIndices || !outSlots || maxEntries <= 0) {
        return 0;
    }

    // ComponentTypeToIndex is at offset 0x180 from EntityStorageData
    void *map = (char *)storageData + STORAGE_DATA_COMPONENT_TYPE_TO_INDEX;

    // Get HashMap components
    ArrayHeader *keys = GET_KEYS(map);
    ArrayHeader *values = GET_VALUES(map);

    if (!keys->buf || !values->buf || keys->size == 0) {
        log_lookup("ComponentTypeToIndex: Empty or invalid");
        return 0;
    }

    // Iterate through all keys (not buckets - keys array contains actual entries)
    uint16_t *keyArray = (uint16_t *)keys->buf;
    uint8_t *valueArray = (uint8_t *)values->buf;

    int count = 0;
    uint64_t size = keys->size;
    if (size > (uint64_t)maxEntries) {
        size = (uint64_t)maxEntries;
    }

    for (uint64_t i = 0; i < size && count < maxEntries; i++) {
        // In the game's HashMap, all entries in the keys array are valid
        // (unused slots would have a sentinel key value, but for discovery
        // we'll just read all of them)
        uint16_t typeIndex = keyArray[i];

        // Skip obviously invalid entries (likely uninitialized memory)
        if (typeIndex == 0xFFFF) continue;

        outIndices[count] = typeIndex;
        outSlots[count] = valueArray[i];
        count++;
    }

    return count;
}
