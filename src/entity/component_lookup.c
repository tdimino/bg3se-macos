/**
 * component_lookup.c - Component lookup via data structure traversal
 *
 * Implements GetComponent functionality for macOS by traversing
 * EntityStorageData structures directly, since template functions are inlined.
 */

#include "component_lookup.h"
#include "arm64_call.h"
#include "../core/logging.h"

#include <string.h>

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
        LOG_ENTITY_DEBUG("ERROR: NULL entityWorld=%p or binaryBase=%p", entityWorld, binaryBase);
        return false;
    }

    g_EntityWorld = entityWorld;
    g_BinaryBase = binaryBase;

    // Get StorageContainer from EntityWorld + 0x2d0
    g_StorageContainer = *(void **)((char *)entityWorld + ENTITYWORLD_STORAGE_OFFSET);
    if (!g_StorageContainer) {
        LOG_ENTITY_DEBUG("ERROR: StorageContainer is NULL at EntityWorld+0x%x", ENTITYWORLD_STORAGE_OFFSET);
        return false;
    }

    // Calculate runtime address of TryGet function
    uintptr_t runtime_addr = ADDR_STORAGE_CONTAINER_TRYGET - GHIDRA_BASE_ADDRESS + (uintptr_t)binaryBase;
    g_TryGetFnAddr = (void *)runtime_addr;

    LOG_ENTITY_DEBUG("Initialized:");
    LOG_ENTITY_DEBUG("  EntityWorld: %p", g_EntityWorld);
    LOG_ENTITY_DEBUG("  StorageContainer: %p", g_StorageContainer);
    LOG_ENTITY_DEBUG("  TryGet: %p (Ghidra: 0x%llx)", g_TryGetFnAddr,
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
        LOG_ENTITY_DEBUG("ERROR: Not initialized");
        return NULL;
    }

    // Call EntityStorageContainer::TryGet(EntityHandle) -> EntityStorageData*
    void *result = call_try_get(g_TryGetFnAddr, g_StorageContainer, entityHandle);

    if (result) {
        LOG_ENTITY_DEBUG("TryGet(0x%llx) -> %p", (unsigned long long)entityHandle, result);
    } else {
        LOG_ENTITY_DEBUG("TryGet(0x%llx) -> NULL", (unsigned long long)entityHandle);
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
        LOG_ENTITY_DEBUG("InstanceToPageMap: Empty or invalid (buckets=%llu)", hashKeys->size);
        return false;
    }

    // Calculate bucket
    uint64_t hash = hash_entity_handle(entityHandle);
    uint32_t bucket = (uint32_t)(hash % hashKeys->size);

    // Get initial index from bucket
    int32_t *bucketArray = (int32_t *)hashKeys->buf;
    int32_t idx = bucketArray[bucket];

    LOG_ENTITY_DEBUG("InstanceToPageMap lookup: handle=0x%llx, hash=0x%llx, bucket=%u, initial_idx=%d",
               (unsigned long long)entityHandle, (unsigned long long)hash, bucket, idx);

    // Traverse collision chain
    uint64_t *keyArray = (uint64_t *)keys->buf;
    EntityStorageIndex *valueArray = (EntityStorageIndex *)values->buf;
    int32_t *nextArray = nextIds->buf ? (int32_t *)nextIds->buf : NULL;

    while (idx >= 0 && (uint64_t)idx < keys->size) {
        if (keyArray[idx] == entityHandle) {
            *outIndex = valueArray[idx];
            LOG_ENTITY_DEBUG("  Found at idx=%d: PageIndex=%u, EntryIndex=%u",
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

    LOG_ENTITY_DEBUG("  Not found in chain");
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
        LOG_ENTITY_DEBUG("ComponentTypeToIndex: Empty or invalid");
        return false;
    }

    // Calculate bucket (simple hash for uint16_t)
    uint32_t bucket = typeIndex % (uint32_t)hashKeys->size;

    // Get initial index from bucket
    int32_t *bucketArray = (int32_t *)hashKeys->buf;
    int32_t idx = bucketArray[bucket];

    LOG_ENTITY_DEBUG("ComponentTypeToIndex lookup: type=%u, bucket=%u, initial_idx=%d",
               typeIndex, bucket, idx);

    // Traverse collision chain
    uint16_t *keyArray = (uint16_t *)keys->buf;
    uint8_t *valueArray = (uint8_t *)values->buf;
    int32_t *nextArray = nextIds->buf ? (int32_t *)nextIds->buf : NULL;

    while (idx >= 0 && (uint64_t)idx < keys->size) {
        if (keyArray[idx] == typeIndex) {
            *outSlot = valueArray[idx];
            LOG_ENTITY_DEBUG("  Found at idx=%d: slot=%u", idx, *outSlot);
            return true;
        }

        // Move to next in chain
        if (nextArray && (uint64_t)idx < nextIds->size) {
            idx = nextArray[idx];
        } else {
            break;
        }
    }

    LOG_ENTITY_DEBUG("  Type %u not found in this storage class", typeIndex);
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
        LOG_ENTITY_DEBUG("Components array: Invalid or PageIndex %u out of range (size=%llu)",
                   storageIndex.PageIndex, componentsArray->size);
        return NULL;
    }

    // Get page pointer (Components is Array<EntityStorageComponentPage*>)
    EntityStorageComponentPage **pageArray = (EntityStorageComponentPage **)componentsArray->buf;
    EntityStorageComponentPage *page = pageArray[storageIndex.PageIndex];

    if (!page) {
        LOG_ENTITY_DEBUG("Page %u is NULL", storageIndex.PageIndex);
        return NULL;
    }

    // Get ComponentInfo for this slot
    // Note: componentSlot is uint8_t (0-255) and COMPONENT_PAGE_SLOTS is 256,
    // so all values are valid. This check is kept for documentation purposes.
    (void)componentSlot; // All uint8_t values are valid indices

    EntityStorageComponentInfo *compInfo = &page->Components[componentSlot];
    void *buffer = compInfo->ComponentBuffer;

    if (!buffer) {
        LOG_ENTITY_DEBUG("ComponentBuffer is NULL for slot %u", componentSlot);
        return NULL;
    }

    // Calculate final component pointer
    void *result;
    if (isProxy) {
        // Proxy: buffer contains array of pointers
        void **ptrArray = (void **)buffer;
        result = ptrArray[storageIndex.EntryIndex];
        LOG_ENTITY_DEBUG("Proxy component: buffer=%p, entry=%u -> %p",
                   buffer, storageIndex.EntryIndex, result);
    } else {
        // Direct: buffer contains array of component data
        result = (char *)buffer + (componentSize * storageIndex.EntryIndex);
        LOG_ENTITY_DEBUG("Direct component: buffer=%p + (%zu * %u) -> %p",
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
        LOG_ENTITY_DEBUG("ERROR: Not initialized");
        return NULL;
    }

    LOG_ENTITY_DEBUG("Looking up component: handle=0x%llx, type=%u, size=%zu, proxy=%d",
               (unsigned long long)entityHandle, typeIndex, componentSize, isProxy);

    // Step 1: Get EntityStorageData
    void *storageData = component_lookup_get_storage_data(entityHandle);
    if (!storageData) {
        LOG_ENTITY_DEBUG("  Failed: TryGet returned NULL");
        return NULL;
    }

    // Step 2: Look up storage index (entity location in pages)
    EntityStorageIndex storageIndex;
    if (!storage_data_get_instance_index(storageData, entityHandle, &storageIndex)) {
        LOG_ENTITY_DEBUG("  Failed: Entity not in InstanceToPageMap");
        return NULL;
    }

    // Step 3: Look up component slot
    uint8_t componentSlot;
    if (!storage_data_get_component_slot(storageData, typeIndex, &componentSlot)) {
        LOG_ENTITY_DEBUG("  Failed: Component type not in this storage class");
        return NULL;
    }

    // Step 4: Get component pointer
    void *component = storage_data_get_component(storageData, storageIndex,
                                                  componentSlot, componentSize, isProxy);

    if (component) {
        LOG_ENTITY_DEBUG("  SUCCESS: Component at %p", component);
    } else {
        LOG_ENTITY_DEBUG("  Failed: Could not access component buffer");
    }

    return component;
}

// ============================================================================
// Debug Functions
// ============================================================================

void component_lookup_dump_storage_data(void *storageData, uint64_t entityHandle) {
    if (!storageData) {
        LOG_ENTITY_DEBUG("StorageData is NULL");
        return;
    }

    LOG_ENTITY_DEBUG("=== EntityStorageData Dump ===");
    LOG_ENTITY_DEBUG("Address: %p", storageData);
    LOG_ENTITY_DEBUG("For EntityHandle: 0x%llx", (unsigned long long)entityHandle);

    // Hexdump first 512 bytes of storageData to understand layout
    LOG_ENTITY_DEBUG("=== StorageData Hexdump (first 512 bytes) ===");
    unsigned char *bytes = (unsigned char *)storageData;
    for (int row = 0; row < 32; row++) {
        int offset = row * 16;
        LOG_ENTITY_DEBUG("  +0x%03x: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x",
                   offset,
                   bytes[offset+0], bytes[offset+1], bytes[offset+2], bytes[offset+3],
                   bytes[offset+4], bytes[offset+5], bytes[offset+6], bytes[offset+7],
                   bytes[offset+8], bytes[offset+9], bytes[offset+10], bytes[offset+11],
                   bytes[offset+12], bytes[offset+13], bytes[offset+14], bytes[offset+15]);
    }

    // Also dump the area around ComponentTypeToIndex (0x180)
    LOG_ENTITY_DEBUG("=== ComponentTypeToIndex area (+0x180, 128 bytes) ===");
    bytes = (unsigned char *)storageData + 0x180;
    for (int row = 0; row < 8; row++) {
        int offset = row * 16;
        LOG_ENTITY_DEBUG("  +0x%03x: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x",
                   0x180 + offset,
                   bytes[offset+0], bytes[offset+1], bytes[offset+2], bytes[offset+3],
                   bytes[offset+4], bytes[offset+5], bytes[offset+6], bytes[offset+7],
                   bytes[offset+8], bytes[offset+9], bytes[offset+10], bytes[offset+11],
                   bytes[offset+12], bytes[offset+13], bytes[offset+14], bytes[offset+15]);
    }

    // Dump Components array info
    ArrayHeader *components = GET_ARRAY_HEADER(storageData, STORAGE_DATA_COMPONENTS_OFFSET);
    LOG_ENTITY_DEBUG("Components (offset 0x%x):", STORAGE_DATA_COMPONENTS_OFFSET);
    LOG_ENTITY_DEBUG("  buf: %p", components->buf);
    LOG_ENTITY_DEBUG("  size: %llu", components->size);

    // Dump ComponentTypeToIndex HashMap info
    void *typeMap = (char *)storageData + STORAGE_DATA_COMPONENT_TYPE_TO_INDEX;
    ArrayHeader *typeHashKeys = GET_HASH_KEYS(typeMap);
    ArrayHeader *typeKeys = GET_KEYS(typeMap);
    LOG_ENTITY_DEBUG("ComponentTypeToIndex (offset 0x%x):", STORAGE_DATA_COMPONENT_TYPE_TO_INDEX);
    LOG_ENTITY_DEBUG("  hashKeys.buf: %p, size: %llu", typeHashKeys->buf, typeHashKeys->size);
    LOG_ENTITY_DEBUG("  keys.buf: %p, size: %llu", typeKeys->buf, typeKeys->size);

    // Dump InstanceToPageMap HashMap info
    void *instanceMap = (char *)storageData + STORAGE_DATA_INSTANCE_TO_PAGE_MAP;
    ArrayHeader *instanceHashKeys = GET_HASH_KEYS(instanceMap);
    ArrayHeader *instanceKeys = GET_KEYS(instanceMap);
    LOG_ENTITY_DEBUG("InstanceToPageMap (offset 0x%x):", STORAGE_DATA_INSTANCE_TO_PAGE_MAP);
    LOG_ENTITY_DEBUG("  hashKeys.buf: %p, size: %llu", instanceHashKeys->buf, instanceHashKeys->size);
    LOG_ENTITY_DEBUG("  keys.buf: %p, size: %llu", instanceKeys->buf, instanceKeys->size);

    // Try to look up this entity
    EntityStorageIndex idx;
    if (storage_data_get_instance_index(storageData, entityHandle, &idx)) {
        LOG_ENTITY_DEBUG("Entity location: PageIndex=%u, EntryIndex=%u", idx.PageIndex, idx.EntryIndex);
    } else {
        LOG_ENTITY_DEBUG("Entity not found in InstanceToPageMap");
    }

    // Enumerate and dump all component types in this storage class
    LOG_ENTITY_DEBUG("Component types in this storage class:");
    uint16_t indices[256];
    uint8_t slots[256];
    int count = storage_data_enumerate_component_types(storageData, indices, slots, 256);
    for (int i = 0; i < count; i++) {
        LOG_ENTITY_DEBUG("  TypeIndex=%u -> Slot=%u", indices[i], slots[i]);
    }
    LOG_ENTITY_DEBUG("Total component types: %d", count);
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
        LOG_ENTITY_DEBUG("ComponentTypeToIndex: Empty or invalid");
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
