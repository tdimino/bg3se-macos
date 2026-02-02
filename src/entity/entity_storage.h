/**
 * entity_storage.h - Entity Storage data structures
 *
 * Defines structures for accessing EntityStorageData and components.
 * On macOS, GetComponent<T> templates are completely inlined, so we must
 * traverse these data structures manually to get component pointers.
 *
 * Reference: BG3Extender/GameDefinitions/EntitySystem.h
 */

#ifndef ENTITY_STORAGE_H
#define ENTITY_STORAGE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Constants
// ============================================================================

// ASLR base for Ghidra addresses
#define GHIDRA_BASE_ADDRESS             0x100000000ULL

// EntityStorageContainer::TryGet function address (Ghidra)
#define ADDR_STORAGE_CONTAINER_TRYGET   0x10636b27cULL

// EntityWorld offsets
#define ENTITYWORLD_STORAGE_OFFSET      0x2d0   // EntityStorageContainer*
#define ENTITYWORLD_CACHE_OFFSET        0x3f0   // ImmediateWorldCache*

// EntityStorageContainer offsets (discovered via Ghidra Dec 2025)
// TryGet decompilation shows: *(long *)this → Entities.buf at offset 0x00
#define STORAGE_CONTAINER_ENTITIES_OFFSET   0x00   // Array<EntityStorageData*>

// EntityStorageData offsets (from Windows reference + Ghidra decompilation)
#define STORAGE_DATA_COMPONENTS_OFFSET          0x138  // Array<EntityStorageComponentPage*>
#define STORAGE_DATA_COMPONENT_TYPE_TO_INDEX    0x180  // HashMap<ComponentTypeIndex, uint8_t>
#define STORAGE_DATA_INSTANCE_TO_PAGE_MAP       0x1c0  // HashMap<EntityHandle, EntityStorageIndex>

// Page size constants
#define STORAGE_PAGE_SIZE               64   // EntityStorageData::PageSize
#define COMPONENT_PAGE_SLOTS            256  // EntityStorageComponentPage has 256 ComponentInfo slots

// Invalid indices
#define STORAGE_INDEX_INVALID           0xFFFF

// One-frame component detection (bit 15 indicates one-frame component)
// From Windows BG3SE: IsOneFrame(idx) = (idx & 0x8000) == 0x8000
#define ONEFRAME_TYPE_MASK              0x8000

// One-frame component storage offsets (verified from Windows BG3SE EntitySystem.h:520-527)
// EntityStorageData layout after InstanceToPageMap (0x1C0):
//   0x200 = AddedComponentFrameStorageIDs (HashMap<uint64_t, uint16_t>)
//   0x240 = RemovedComponentFrameStorageIDs2 (HashMap<uint64_t, uint16_t>)
//   0x280 = ComponentAddedEntityMap (Array<Array<EntityHandle>>)
//   0x290 = ComponentRemovedEntityMap (Array<Array<EntityHandle>>)
//   0x2A0 = OneFrameComponents (HashMap<ComponentTypeIndex, HashMap<EntityHandle, void*>>)
//   0x2E0 = HasOneFrameComponents (bool)
#define STORAGE_DATA_ONEFRAME_COMPONENTS 0x2A0  // HashMap<ComponentTypeIndex, HashMap<EntityHandle, void*>>
#define STORAGE_DATA_HAS_ONEFRAME        0x2e0  // bool HasOneFrameComponents

// Check if a component type index indicates a one-frame component
static inline bool is_oneframe_component(uint16_t typeIndex) {
    return (typeIndex & ONEFRAME_TYPE_MASK) == ONEFRAME_TYPE_MASK;
}

// ============================================================================
// EntityStorageIndex - Location of an entity in component pages
// ============================================================================

typedef struct {
    uint16_t PageIndex;     // 0xFFFF = invalid
    uint16_t EntryIndex;    // Index within page
} EntityStorageIndex;

static inline bool storage_index_is_valid(EntityStorageIndex idx) {
    return idx.PageIndex != STORAGE_INDEX_INVALID;
}

// ============================================================================
// EntityStorageComponentInfo - Buffer pointers for a component slot
// ============================================================================

typedef struct {
    void *ComponentBuffer;      // Pointer to component data array
    void *ModificationInfo;     // Modification tracking (unused for reads)
} EntityStorageComponentInfo;

// ============================================================================
// EntityStorageComponentPage - 256 component slots per page
// ============================================================================

// Each page has 256 ComponentInfo entries
// Access: Components[PageIndex]->Components[componentSlot]
typedef struct {
    EntityStorageComponentInfo Components[COMPONENT_PAGE_SLOTS];
} EntityStorageComponentPage;

// ============================================================================
// HashMap Layout (from reverse engineering)
// ============================================================================

// Both ComponentTypeToIndex and InstanceToPageMap use similar HashMap layouts:
//   offset +0x00: StaticArray<int32_t> HashKeys (bucket indices, -1 = empty)
//   offset +0x10: Array<int32_t> NextIds (collision chains)
//   offset +0x20: Array<K> Keys
//   offset +0x30: Array<V> Values (StaticArray for some)
//
// For ComponentTypeToIndex:
//   K = uint16_t (ComponentTypeIndex)
//   V = uint8_t (component slot within page)
//
// For InstanceToPageMap:
//   K = uint64_t (EntityHandle)
//   V = EntityStorageIndex (4 bytes)

// StaticArray layout (16 bytes) - used for hash buckets
// offset +0x00: void* buf
// offset +0x08: uint64_t size (single field, no separate capacity)
typedef struct {
    void *buf;
    uint64_t size;
} StaticArray;

// Array<T> layout (from Windows BG3SE CoreLib/Base/BaseArray.h)
// Total size: 16 bytes - used for keys, values, nextIds
typedef struct {
    void *buf;          // +0x00: pointer to element array
    uint32_t capacity;  // +0x08: capacity (uint32_t)
    uint32_t size;      // +0x0C: current size (uint32_t)
} GenericArray;

// Legacy alias
typedef StaticArray ArrayHeader;

// Helper to access EntityStorageContainer::Entities array
// Array<EntityStorageData*> at offset 0x00
static inline GenericArray* storage_container_get_entities(void *storageContainer) {
    return (GenericArray *)((char *)storageContainer + STORAGE_CONTAINER_ENTITIES_OFFSET);
}

// HashMap field offsets within the 64-byte HashMap structure
#define HASHMAP_HASH_KEYS_OFFSET    0x00  // StaticArray<int32_t>
#define HASHMAP_NEXT_IDS_OFFSET     0x10  // Array<int32_t>
#define HASHMAP_KEYS_OFFSET         0x20  // Array<K>
#define HASHMAP_VALUES_OFFSET       0x30  // Array<V> or StaticArray<V>

// Total size of a HashMap<K,V> structure (for inline storage calculations)
// Layout: HashKeys(16) + NextIds(16) + Keys(16) + Values(16) = 64 bytes
#define HASHMAP_STRUCT_SIZE         0x40

// ============================================================================
// Helper Macros for HashMap Access
// ============================================================================

// Get StaticArray at offset (for hash bucket arrays - uses uint64 size)
#define GET_STATIC_ARRAY(base, offset) ((StaticArray*)((char*)(base) + (offset)))

// Get GenericArray at offset (for keys/values/nextIds - uses uint32 cap+size)
#define GET_ARRAY(base, offset) ((GenericArray*)((char*)(base) + (offset)))

// Legacy: Get array header at offset (same as GET_STATIC_ARRAY)
#define GET_ARRAY_HEADER(base, offset) ((StaticArray*)((char*)(base) + (offset)))

// Get hash keys array (bucket indices) - StaticArray<int32_t>
#define GET_HASH_KEYS(map) GET_STATIC_ARRAY(map, HASHMAP_HASH_KEYS_OFFSET)

// Get next IDs array (collision chains) - Array<int32_t>
#define GET_NEXT_IDS(map) GET_ARRAY(map, HASHMAP_NEXT_IDS_OFFSET)

// Get keys array - Array<K>
#define GET_KEYS(map) GET_ARRAY(map, HASHMAP_KEYS_OFFSET)

// Get values array - Array<V> (or StaticArray<V> for some)
#define GET_VALUES(map) GET_ARRAY(map, HASHMAP_VALUES_OFFSET)

// ============================================================================
// EntityHandle Utilities (for thread/bucket extraction)
// ============================================================================

// EntityHandle bit layout (from ENTITY_SYSTEM.md):
// Bits 0-31:  Entity Index
// Bits 32-47: Salt (generation)
// Bits 48-63: Type Index
//
// For TryGet, we also need thread index from bits 54-59:
// Bits 54-59: Thread index (0x3F mask after shifting)

static inline uint32_t storage_get_thread_index(uint64_t handle) {
    return (uint32_t)((handle >> 54) & 0x3F);
}

#ifdef __cplusplus
}
#endif

#endif // ENTITY_STORAGE_H
