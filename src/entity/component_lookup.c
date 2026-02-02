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

    // Get HashMap components - hashKeys is StaticArray, others are GenericArray
    StaticArray *hashKeys = GET_HASH_KEYS(map);
    GenericArray *nextIds = GET_NEXT_IDS(map);
    GenericArray *keys = GET_KEYS(map);
    GenericArray *values = GET_VALUES(map);

    if (!hashKeys->buf || !keys->buf || !values->buf || hashKeys->size == 0) {
        LOG_ENTITY_DEBUG("InstanceToPageMap: Empty or invalid (buckets=%llu)", (unsigned long long)hashKeys->size);
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

// BG3 ComponentTypeIndex hash function (from Windows BG3SE)
// ComponentMapSize = 0x880 = 2176
#define COMPONENT_MAP_SIZE 0x880

static uint64_t hash_component_type_index(uint16_t typeIndex) {
    // From BG3Extender/GameDefinitions/EntitySystem.h:82-86
    // HashMapHash<ecs::ComponentTypeIndex>
    uint64_t h0 = ((uint64_t)typeIndex & 0x7FFF) + ((uint64_t)typeIndex >> 15) * COMPONENT_MAP_SIZE;
    return h0 | (h0 << 16);
}

// Generic HashMap find_index for uint16_t keys (proper bucket-based lookup)
// Matches Windows BG3SE CoreLib/Base/BaseMap.h:153-164
static int hashmap_find_index_u16(void *map, uint16_t key) {
    StaticArray *hashKeys = GET_HASH_KEYS(map);   // +0x00: bucket array
    GenericArray *nextIds = GET_NEXT_IDS(map);    // +0x10: collision chains
    GenericArray *keys = GET_KEYS(map);           // +0x20: key array

    if (!hashKeys->buf || hashKeys->size == 0) return -1;
    if (!keys->buf || keys->size == 0) return -1;

    // Hash and get bucket
    uint64_t hash = hash_component_type_index(key);
    uint32_t bucket = (uint32_t)(hash % hashKeys->size);

    // Get initial key index from bucket
    int32_t keyIndex = ((int32_t *)hashKeys->buf)[bucket];

    // Follow collision chain
    uint16_t *keyArray = (uint16_t *)keys->buf;
    int32_t *nextArray = nextIds->buf ? (int32_t *)nextIds->buf : NULL;

    while (keyIndex >= 0 && (uint32_t)keyIndex < keys->size) {
        if (keyArray[keyIndex] == key) return keyIndex;
        keyIndex = (nextArray && (uint32_t)keyIndex < nextIds->size)
                   ? nextArray[keyIndex] : -1;
    }
    return -1;
}

bool storage_data_get_component_slot(void *storageData, uint16_t typeIndex,
                                      uint8_t *outSlot) {
    if (!storageData || !outSlot) return false;

    // Skip lookup for unresolved TypeIds (0xFFFF = COMPONENT_INDEX_UNDEFINED)
    // This avoids log spam when polling for one-frame components that haven't been discovered yet
    if (typeIndex == 0xFFFF) return false;

    // ComponentTypeToIndex is at offset 0x180 from EntityStorageData
    void *map = (char *)storageData + STORAGE_DATA_COMPONENT_TYPE_TO_INDEX;

    // Get HashMap components - hashKeys is StaticArray, others are GenericArray
    StaticArray *hashKeys = GET_HASH_KEYS(map);
    GenericArray *nextIds = GET_NEXT_IDS(map);
    GenericArray *keys = GET_KEYS(map);
    GenericArray *values = GET_VALUES(map);

    if (!hashKeys->buf || !keys->buf || !values->buf || hashKeys->size == 0) {
        LOG_ENTITY_DEBUG("ComponentTypeToIndex: Empty or invalid");
        return false;
    }

    // Calculate bucket using BG3's component type hash function
    uint64_t hash = hash_component_type_index(typeIndex);
    uint32_t bucket = (uint32_t)(hash % hashKeys->size);

    // Get initial index from bucket
    int32_t *bucketArray = (int32_t *)hashKeys->buf;
    int32_t idx = bucketArray[bucket];

    LOG_ENTITY_DEBUG("ComponentTypeToIndex lookup: type=%u, hash=0x%llx, bucket=%u, initial_idx=%d",
               typeIndex, (unsigned long long)hash, bucket, idx);

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
    GenericArray *components = GET_ARRAY(storageData, STORAGE_DATA_COMPONENTS_OFFSET);
    LOG_ENTITY_DEBUG("Components (offset 0x%x):", STORAGE_DATA_COMPONENTS_OFFSET);
    LOG_ENTITY_DEBUG("  buf: %p", components->buf);
    LOG_ENTITY_DEBUG("  size: %u", components->size);

    // Dump ComponentTypeToIndex HashMap info
    void *typeMap = (char *)storageData + STORAGE_DATA_COMPONENT_TYPE_TO_INDEX;
    StaticArray *typeHashKeys = GET_HASH_KEYS(typeMap);
    GenericArray *typeKeys = GET_KEYS(typeMap);
    LOG_ENTITY_DEBUG("ComponentTypeToIndex (offset 0x%x):", STORAGE_DATA_COMPONENT_TYPE_TO_INDEX);
    LOG_ENTITY_DEBUG("  hashKeys.buf: %p, size: %llu", typeHashKeys->buf, (unsigned long long)typeHashKeys->size);
    LOG_ENTITY_DEBUG("  keys.buf: %p, size: %u", typeKeys->buf, typeKeys->size);

    // Dump InstanceToPageMap HashMap info
    void *instanceMap = (char *)storageData + STORAGE_DATA_INSTANCE_TO_PAGE_MAP;
    StaticArray *instanceHashKeys = GET_HASH_KEYS(instanceMap);
    GenericArray *instanceKeys = GET_KEYS(instanceMap);
    LOG_ENTITY_DEBUG("InstanceToPageMap (offset 0x%x):", STORAGE_DATA_INSTANCE_TO_PAGE_MAP);
    LOG_ENTITY_DEBUG("  hashKeys.buf: %p, size: %llu", instanceHashKeys->buf, (unsigned long long)instanceHashKeys->size);
    LOG_ENTITY_DEBUG("  keys.buf: %p, size: %u", instanceKeys->buf, instanceKeys->size);

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
    GenericArray *keys = GET_KEYS(map);
    GenericArray *values = GET_VALUES(map);

    if (!keys->buf || !values->buf || keys->size == 0) {
        LOG_ENTITY_DEBUG("ComponentTypeToIndex: Empty or invalid");
        return 0;
    }

    // Iterate through all keys (not buckets - keys array contains actual entries)
    uint16_t *keyArray = (uint16_t *)keys->buf;
    uint8_t *valueArray = (uint8_t *)values->buf;

    int count = 0;
    uint32_t size = keys->size;
    if (size > (uint32_t)maxEntries) {
        size = (uint32_t)maxEntries;
    }

    for (uint32_t i = 0; i < size && count < maxEntries; i++) {
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

// ============================================================================
// Entity Enumeration
// ============================================================================

// Helper: Get entities from OneFrameComponents pool (HashMap<ComponentTypeIndex, HashMap<EntityHandle, void*>>)
// Uses proper bucket-based HashMap lookup matching Windows BG3SE implementation
static int get_oneframe_entities(void *storageData, uint16_t componentTypeIndex,
                                  uint64_t *outHandles, int maxHandles) {
    // Check if this storage class has one-frame components
    // HasOneFrameComponents flag is at offset 0x2e0
    uint8_t hasOneFrame = *(uint8_t *)((char *)storageData + STORAGE_DATA_HAS_ONEFRAME);
    if (!hasOneFrame) {
        return 0;
    }

    LOG_ENTITY_DEBUG("  OneFrame: storageData=%p has oneFrame components, checking map...", storageData);

    // OneFrameComponents is at offset 0x2A0 (HashMap<ComponentTypeIndex, HashMap<EntityHandle, void*>>)
    void *oneFrameMap = (char *)storageData + STORAGE_DATA_ONEFRAME_COMPONENTS;

    // Outer HashMap lookup: find ComponentTypeIndex in the OneFrameComponents map
    // Keys are stored WITHOUT the 0x8000 bit in the HashMap
    uint16_t searchKey = componentTypeIndex & 0x7FFF;  // Strip one-frame bit for lookup

    LOG_ENTITY_DEBUG("  OneFrame: looking up searchKey=%u (0x%x) in outer map", searchKey, searchKey);

    // Use proper bucket-based HashMap lookup
    int outerIdx = hashmap_find_index_u16(oneFrameMap, searchKey);
    if (outerIdx < 0) {
        LOG_ENTITY_DEBUG("  OneFrame: component type not found in OneFrameComponents map");
        return 0;
    }

    LOG_ENTITY_DEBUG("  OneFrame: found at outerIdx=%d", outerIdx);

    // Get the inner HashMap (EntityHandle → void*) from Values array
    // CRITICAL: Values are INLINE HashMap structures, not pointers!
    // Each inner HashMap is HASHMAP_STRUCT_SIZE (0x40) bytes
    GenericArray *outerValues = GET_VALUES(oneFrameMap);
    if (!outerValues->buf || (uint32_t)outerIdx >= outerValues->size) {
        LOG_ENTITY_DEBUG("  OneFrame: outerValues invalid or outerIdx out of bounds");
        return 0;
    }

    // Values are inline HashMap<EntityHandle, void*> structures (64 bytes each)
    // Access by byte offset, not pointer array indexing
    char *valuesBuf = (char *)outerValues->buf;
    void *innerMap = valuesBuf + (outerIdx * HASHMAP_STRUCT_SIZE);

    LOG_ENTITY_DEBUG("  OneFrame: outerValues.buf=%p, size=%u, idx=%d, innerMap=%p (offset 0x%x)",
                     outerValues->buf, outerValues->size, outerIdx, innerMap,
                     outerIdx * HASHMAP_STRUCT_SIZE);

    // Inner HashMap has EntityHandle keys at +0x20
    // We collect all EntityHandles from the keys array (they all have this component)
    GenericArray *entityKeys = GET_KEYS(innerMap);
    if (!entityKeys->buf || entityKeys->size == 0) {
        LOG_ENTITY_DEBUG("  OneFrame: innerMap has no entities");
        return 0;
    }

    uint64_t *handleArray = (uint64_t *)entityKeys->buf;
    uint32_t entriesToCopy = entityKeys->size;

    if ((int)entriesToCopy > maxHandles) {
        entriesToCopy = (uint32_t)maxHandles;
    }

    for (uint32_t j = 0; j < entriesToCopy; j++) {
        outHandles[j] = handleArray[j];
    }

    LOG_ENTITY_DEBUG("  OneFrame: found %u entities for typeIndex=0x%x", entriesToCopy, componentTypeIndex);
    return (int)entriesToCopy;
}

int component_lookup_get_all_with_component(uint16_t componentTypeIndex,
                                             uint64_t *outHandles,
                                             int maxHandles) {
    if (!component_lookup_ready() || !outHandles || maxHandles <= 0) {
        return 0;
    }

    // Check if this is a one-frame component (bit 15 set)
    bool isOneFrame = is_oneframe_component(componentTypeIndex);

    // Get Entities array from StorageContainer
    GenericArray *entities = storage_container_get_entities(g_StorageContainer);

    // Debug: dump raw bytes to understand layout
    LOG_ENTITY_DEBUG("GetAllWithComponent: StorageContainer=%p (oneFrame=%s)",
               g_StorageContainer, isOneFrame ? "YES" : "no");
    LOG_ENTITY_DEBUG("  Entities.buf=%p, capacity=%u, size=%u",
               entities->buf, entities->capacity, entities->size);

    if (!entities->buf || entities->size == 0) {
        LOG_ENTITY_DEBUG("GetAllWithComponent: Entities array empty or NULL (size=%u)", entities->size);
        return 0;
    }

    LOG_ENTITY_DEBUG("GetAllWithComponent: Searching %u entity classes for typeIndex=0x%x%s",
               entities->size, componentTypeIndex, isOneFrame ? " (one-frame)" : "");

    int totalCount = 0;
    void **entityClasses = (void **)entities->buf;

    // Iterate all entity storage classes (archetypes)
    for (uint32_t classIdx = 0; classIdx < entities->size && totalCount < maxHandles; classIdx++) {
        void *storageData = entityClasses[classIdx];
        if (!storageData) continue;

        if (isOneFrame) {
            // One-frame components are stored in the OneFrameComponents pool
            int count = get_oneframe_entities(storageData, componentTypeIndex,
                                               outHandles + totalCount, maxHandles - totalCount);
            if (count > 0) {
                totalCount += count;
                LOG_ENTITY_DEBUG("  Class %u: found %d one-frame entities (total: %d)",
                           classIdx, count, totalCount);
            }
        } else {
            // Regular components - check ComponentTypeToIndex HashMap
            uint8_t slot;
            if (!storage_data_get_component_slot(storageData, componentTypeIndex, &slot)) {
                continue;  // This class doesn't have this component type
            }

            // This class has the component - collect all entity handles from InstanceToPageMap
            void *instanceMap = (char *)storageData + STORAGE_DATA_INSTANCE_TO_PAGE_MAP;
            GenericArray *keys = GET_KEYS(instanceMap);

            if (!keys->buf || keys->size == 0) {
                continue;
            }

            uint64_t *handleArray = (uint64_t *)keys->buf;
            uint32_t entriesToCopy = keys->size;

            // Limit to remaining space in output buffer
            if (totalCount + (int)entriesToCopy > maxHandles) {
                entriesToCopy = (uint32_t)(maxHandles - totalCount);
            }

            // Copy handles
            for (uint32_t i = 0; i < entriesToCopy; i++) {
                outHandles[totalCount++] = handleArray[i];
            }

            LOG_ENTITY_DEBUG("  Class %u: found %u entities with component (total: %d)",
                       classIdx, keys->size, totalCount);
        }
    }

    LOG_ENTITY_DEBUG("GetAllWithComponent: Found %d total entities%s",
               totalCount, isOneFrame ? " (one-frame)" : "");
    return totalCount;
}

// Helper: Count entities in OneFrameComponents pool
static int count_oneframe_entities(void *storageData, uint16_t componentTypeIndex) {
    uint8_t hasOneFrame = *(uint8_t *)((char *)storageData + STORAGE_DATA_HAS_ONEFRAME);
    if (!hasOneFrame) {
        return 0;
    }

    void *oneFrameMap = (char *)storageData + STORAGE_DATA_ONEFRAME_COMPONENTS;

    // Use proper bucket-based HashMap lookup (same as get_oneframe_entities)
    uint16_t searchKey = componentTypeIndex & 0x7FFF;
    int outerIdx = hashmap_find_index_u16(oneFrameMap, searchKey);
    if (outerIdx < 0) {
        return 0;
    }

    // CRITICAL: Values are INLINE HashMap structures, not pointers!
    GenericArray *outerValues = GET_VALUES(oneFrameMap);
    if (!outerValues->buf || (uint32_t)outerIdx >= outerValues->size) {
        return 0;
    }

    // Access inline HashMap by byte offset
    char *valuesBuf = (char *)outerValues->buf;
    void *innerMap = valuesBuf + (outerIdx * HASHMAP_STRUCT_SIZE);

    GenericArray *entityKeys = GET_KEYS(innerMap);
    if (entityKeys->buf && entityKeys->size > 0) {
        return (int)entityKeys->size;
    }

    return 0;
}

int component_lookup_count_with_component(uint16_t componentTypeIndex) {
    if (!component_lookup_ready()) {
        return 0;
    }

    bool isOneFrame = is_oneframe_component(componentTypeIndex);

    // Get Entities array from StorageContainer
    GenericArray *entities = storage_container_get_entities(g_StorageContainer);

    if (!entities->buf || entities->size == 0) {
        return 0;
    }

    int totalCount = 0;
    void **entityClasses = (void **)entities->buf;

    // Iterate all entity storage classes (archetypes)
    for (uint32_t classIdx = 0; classIdx < entities->size; classIdx++) {
        void *storageData = entityClasses[classIdx];
        if (!storageData) continue;

        if (isOneFrame) {
            // One-frame components are stored in the OneFrameComponents pool
            totalCount += count_oneframe_entities(storageData, componentTypeIndex);
        } else {
            // Regular components - check ComponentTypeToIndex HashMap
            uint8_t slot;
            if (!storage_data_get_component_slot(storageData, componentTypeIndex, &slot)) {
                continue;
            }

            // This class has the component - count entities from InstanceToPageMap
            void *instanceMap = (char *)storageData + STORAGE_DATA_INSTANCE_TO_PAGE_MAP;
            GenericArray *keys = GET_KEYS(instanceMap);

            if (keys->buf && keys->size > 0) {
                totalCount += (int)keys->size;
            }
        }
    }

    return totalCount;
}
