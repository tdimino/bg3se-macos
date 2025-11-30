/**
 * guid_lookup.h - GUID to EntityHandle lookup utilities
 *
 * This module provides HashMap structure definitions and GUID lookup
 * functionality for the BG3 Entity Component System.
 */

#ifndef GUID_LOOKUP_H
#define GUID_LOOKUP_H

#include <stdint.h>
#include <stdbool.h>

// ============================================================================
// Basic Types
// ============================================================================

// Entity handle - 64-bit packed value from BG3 ECS
typedef uint64_t EntityHandle;
#define ENTITY_HANDLE_INVALID 0xFFFFFFFFFFFFFFFFULL

// 128-bit GUID structure (matches BG3 internal layout)
typedef struct {
    uint64_t lo;  // Lower 64 bits (bytes 0-7)
    uint64_t hi;  // Upper 64 bits (bytes 8-15)
} Guid;

// ============================================================================
// EntityHandle Helpers
// ============================================================================

static inline bool entity_handle_is_valid(EntityHandle h) {
    return h != ENTITY_HANDLE_INVALID;
}

static inline uint32_t entity_handle_get_index(EntityHandle h) {
    return (uint32_t)(h & 0xFFFFFFFF);
}

static inline uint16_t entity_handle_get_salt(EntityHandle h) {
    return (uint16_t)((h >> 32) & 0xFFFF);
}

static inline uint16_t entity_handle_get_type(EntityHandle h) {
    return (uint16_t)((h >> 48) & 0xFFFF);
}

// ============================================================================
// HashMap Structures (from Windows BG3SE reference)
// ============================================================================

// StaticArray<T> layout (16 bytes on 64-bit):
//   offset 0x00: T* buf_ (8 bytes)
//   offset 0x08: uint32_t size_ (4 bytes)
//   offset 0x0C: padding (4 bytes)
typedef struct {
    int32_t *buf;
    uint32_t size;
    uint32_t _pad;
} StaticArrayInt32;

typedef struct {
    EntityHandle *buf;
    uint32_t size;
    uint32_t _pad;
} StaticArrayEntityHandle;

// Array<T> layout (16 bytes on 64-bit):
//   offset 0x00: T* buf_ (8 bytes)
//   offset 0x08: uint32_t capacity_ (4 bytes)
//   offset 0x0C: uint32_t size_ (4 bytes)
typedef struct {
    int32_t *buf;
    uint32_t capacity;
    uint32_t size;
} ArrayInt32;

typedef struct {
    Guid *buf;
    uint32_t capacity;
    uint32_t size;
} ArrayGuid;

// HashMap<Guid, EntityHandle> layout (64 bytes total):
//   offset 0x00: StaticArray<int32_t> HashKeys   (bucket table)
//   offset 0x10: Array<int32_t> NextIds          (collision chain)
//   offset 0x20: Array<Guid> Keys                (key storage)
//   offset 0x30: UninitializedStaticArray<EntityHandle> Values
typedef struct {
    StaticArrayInt32 HashKeys;         // offset 0x00
    ArrayInt32 NextIds;                // offset 0x10
    ArrayGuid Keys;                    // offset 0x20
    StaticArrayEntityHandle Values;    // offset 0x30
} HashMapGuidEntityHandle;

// UuidToHandleMappingComponent contains HashMap<Guid, EntityHandle> Mappings
// The Mappings field is at offset 0 (first field after vtable if any)
typedef struct {
    HashMapGuidEntityHandle Mappings;
} UuidToHandleMappingComponent;

// ============================================================================
// GUID Parsing and Lookup
// ============================================================================

/**
 * Parse a GUID string into a Guid structure
 * @param guid_str String in format "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
 * @param out_guid Output Guid structure
 * @return true if parsing succeeded
 */
bool guid_parse(const char *guid_str, Guid *out_guid);

/**
 * Convert a Guid to string representation
 * @param guid The Guid to convert
 * @param out_str Output buffer (must be at least 37 bytes)
 */
void guid_to_string(const Guid *guid, char *out_str);

/**
 * Lookup an EntityHandle in a HashMap by GUID
 * @param hashmap The HashMap<Guid, EntityHandle> to search
 * @param guid The GUID to look up
 * @return EntityHandle if found, ENTITY_HANDLE_INVALID otherwise
 */
EntityHandle hashmap_lookup_guid(const HashMapGuidEntityHandle *hashmap, const Guid *guid);

/**
 * Debug: Dump HashMap contents to log
 * @param hashmap The HashMap to dump
 * @param max_entries Maximum number of entries to log (0 = all)
 */
void hashmap_dump(const HashMapGuidEntityHandle *hashmap, int max_entries);

#endif // GUID_LOOKUP_H
