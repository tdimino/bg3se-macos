/**
 * guid_lookup.c - GUID to EntityHandle lookup utilities
 *
 * Implementation of HashMap operations and GUID parsing for BG3 ECS.
 */

#include "guid_lookup.h"
#include "../core/logging.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

// ============================================================================
// GUID Parsing
// ============================================================================

// Helper: Convert hex character to value
static int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Helper: Parse N hex characters into a uint64_t
static bool parse_hex_bytes(const char *str, int num_chars, uint64_t *out) {
    *out = 0;
    for (int i = 0; i < num_chars; i++) {
        int val = hex_char_to_int(str[i]);
        if (val < 0) return false;
        *out = (*out << 4) | val;
    }
    return true;
}

bool guid_parse(const char *guid_str, Guid *out_guid) {
    if (!guid_str || !out_guid) return false;

    // Expected format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 chars)
    size_t len = strlen(guid_str);
    if (len != 36) return false;

    // Validate dashes
    if (guid_str[8] != '-' || guid_str[13] != '-' ||
        guid_str[18] != '-' || guid_str[23] != '-') {
        return false;
    }

    // Parse each section
    // Format: AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE
    // where GUID.lo = swapped(AAAAAAAA BBBB CCCC)
    //       GUID.hi = swapped(DDDD EEEEEEEEEEEE)
    //
    // BG3 stores GUIDs in little-endian byte order within each section

    uint64_t a, b, c, d, e;
    if (!parse_hex_bytes(guid_str + 0, 8, &a)) return false;
    if (!parse_hex_bytes(guid_str + 9, 4, &b)) return false;
    if (!parse_hex_bytes(guid_str + 14, 4, &c)) return false;
    if (!parse_hex_bytes(guid_str + 19, 4, &d)) return false;
    if (!parse_hex_bytes(guid_str + 24, 12, &e)) return false;

    // Pack into 128-bit GUID
    // BG3 stores GUIDs with the last parts (DDDD-EEEEEEEEEEEE) in lo
    // and first parts (AAAAAAAA-BBBB-CCCC) in hi
    // This was discovered by comparing parsed GUIDs to HashMap keys
    out_guid->hi = (a << 32) | (b << 16) | c;  // First 8 bytes go to hi
    out_guid->lo = (d << 48) | e;              // Last 8 bytes go to lo

    return true;
}

void guid_to_string(const Guid *guid, char *out_str) {
    if (!guid || !out_str) return;

    // Unpack from Guid structure
    // Format: AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE
    // hi contains first parts (AAAAAAAA-BBBB-CCCC)
    // lo contains last parts (DDDD-EEEEEEEEEEEE)
    uint32_t a = (uint32_t)(guid->hi >> 32);
    uint16_t b = (uint16_t)((guid->hi >> 16) & 0xFFFF);
    uint16_t c = (uint16_t)(guid->hi & 0xFFFF);
    uint16_t d = (uint16_t)(guid->lo >> 48);
    uint64_t e = guid->lo & 0xFFFFFFFFFFFFULL;

    snprintf(out_str, 37, "%08x-%04hx-%04hx-%04hx-%012llx",
             a, b, c, d, (unsigned long long)e);
}

// ============================================================================
// HashMap Lookup
// ============================================================================

EntityHandle hashmap_lookup_guid(const HashMapGuidEntityHandle *hashmap, const Guid *guid) {
    if (!hashmap || !guid) return ENTITY_HANDLE_INVALID;

    // Validate structure
    if (!hashmap->HashKeys.buf || hashmap->HashKeys.size == 0) {
        return ENTITY_HANDLE_INVALID;
    }

    // Hash the GUID (simple XOR hash matching BG3's implementation)
    uint64_t hash = guid->lo ^ guid->hi;
    uint32_t bucket = (uint32_t)(hash % hashmap->HashKeys.size);

    // Get initial index from bucket
    int32_t keyIndex = hashmap->HashKeys.buf[bucket];

    // Follow collision chain
    while (keyIndex >= 0) {
        // Bounds check
        if ((uint32_t)keyIndex >= hashmap->Keys.size) {
            break;
        }

        // Compare GUID
        const Guid *key = &hashmap->Keys.buf[keyIndex];
        if (key->lo == guid->lo && key->hi == guid->hi) {
            // Found it!
            return hashmap->Values.buf[keyIndex];
        }

        // Follow collision chain
        if ((uint32_t)keyIndex >= hashmap->NextIds.size) {
            break;
        }
        keyIndex = hashmap->NextIds.buf[keyIndex];
    }

    return ENTITY_HANDLE_INVALID;
}

// ============================================================================
// Debug Functions
// ============================================================================

void hashmap_dump(const HashMapGuidEntityHandle *hashmap, int max_entries) {
    if (!hashmap) {
        log_message("[GuidLookup] HashMap is NULL");
        return;
    }

    log_message("[GuidLookup] HashMap dump:");
    log_message("  HashKeys: buf=%p, size=%u",
                (void*)hashmap->HashKeys.buf, hashmap->HashKeys.size);
    log_message("  NextIds: buf=%p, capacity=%u, size=%u",
                (void*)hashmap->NextIds.buf, hashmap->NextIds.capacity, hashmap->NextIds.size);
    log_message("  Keys: buf=%p, capacity=%u, size=%u",
                (void*)hashmap->Keys.buf, hashmap->Keys.capacity, hashmap->Keys.size);
    log_message("  Values: buf=%p, size=%u",
                (void*)hashmap->Values.buf, hashmap->Values.size);

    // Dump some entries
    int count = (max_entries > 0 && (uint32_t)max_entries < hashmap->Keys.size)
                ? max_entries : (int)hashmap->Keys.size;
    if (count > 20) count = 20;  // Safety limit

    for (int i = 0; i < count; i++) {
        Guid *key = &hashmap->Keys.buf[i];
        EntityHandle value = hashmap->Values.buf[i];
        log_message("  [%d] GUID: %016llx-%016llx -> Handle: 0x%llx",
                    i, (unsigned long long)key->lo, (unsigned long long)key->hi,
                    (unsigned long long)value);
    }

    if ((int)hashmap->Keys.size > count) {
        log_message("  ... (%u more entries)", hashmap->Keys.size - count);
    }
}
