/**
 * staticdata_manager.c - StaticData Manager Implementation for BG3SE-macOS
 *
 * Captures static data managers via hooks and provides access for Lua API.
 */

#include "staticdata_manager.h"
#include "../core/logging.h"
#include <dobby.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

// ============================================================================
// Constants and Offsets (Discovered via Ghidra)
// ============================================================================

// Function addresses (relative to base)
#define OFFSET_FEAT_GETFEATS          0x01b752b4  // FeatManager::GetFeats
#define OFFSET_GETALLFEATS            0x0120b3e8  // GetAllFeats (for context capture)

// ImmutableDataHeadmaster m_State pointer address (for TypeContext traversal)
#define OFFSET_MSTATE_PTR             0x083c4a68  // PTR_m_State - pointer to m_State

// FeatManager structure offsets
// NOTE: TypeContext gives us a metadata structure, not the real FeatManager.
// Real FeatManager (from GetFeats) has count at +0x7C, but TypeContext has count at +0x00.
// Using TypeContext layout since hooks are disabled:
#define FEATMANAGER_OFFSET_COUNT      0x00   // int32_t count (TypeContext metadata)
#define FEATMANAGER_OFFSET_ARRAY      0x80   // Feat* array pointer

// Feat structure
#define FEAT_SIZE                     0x128  // 296 bytes per feat

// ============================================================================
// Type Name Table
// ============================================================================

static const char* s_type_names[STATICDATA_COUNT] = {
    "Feat",
    "Race",
    "Background",
    "Origin",
    "God",
    "Class",
    "Progression",
    "ActionResource",
    "FeatDescription"
};

// Manager type names as they appear in TypeContext (for name-based capture)
static const char* s_manager_type_names[STATICDATA_COUNT] = {
    "eoc::FeatManager",
    "eoc::RaceManager",
    "eoc::BackgroundManager",
    "eoc::OriginManager",
    "eoc::GodManager",
    "eoc::ClassManager",
    "eoc::ProgressionManager",
    "eoc::ActionResourceManager",
    "eoc::FeatDescriptionManager"
};

// ============================================================================
// Module State
// ============================================================================

static struct {
    bool initialized;
    void* main_binary_base;

    // Captured manager pointers
    void* managers[STATICDATA_COUNT];

    // Original function pointers (for hooks)
    void* orig_feat_getfeats;
} g_staticdata = {0};

// ============================================================================
// TypeContext Traversal (Alternative capture method)
// ============================================================================

/**
 * TypeInfo structure in ImmutableDataHeadmaster TypeContext
 */
typedef struct TypeInfo {
    void*    manager_ptr;     // +0x00: Pointer to manager instance
    void*    type_name;       // +0x08: FixedString or char* type name
    uint32_t name_length;     // +0x10: Type name length
    uint32_t padding;         // +0x14: Padding
    struct TypeInfo* next;    // +0x18: Next TypeInfo in list
} TypeInfo;

/**
 * Capture all known managers by traversing the ImmutableDataHeadmaster TypeContext.
 * The type_name field is a raw C string pointer (verified at runtime).
 * Returns number of managers captured.
 */
static int capture_managers_via_typecontext(void) {
    if (!g_staticdata.main_binary_base) {
        return 0;
    }

    // Get pointer to m_State
    void** ptr_mstate = (void**)((uint8_t*)g_staticdata.main_binary_base + OFFSET_MSTATE_PTR);
    void* m_state = *ptr_mstate;
    if (!m_state) {
        log_message("[StaticData] m_State is NULL - TypeContext not available yet");
        return 0;
    }

    log_message("[StaticData] TypeContext traversal: m_State at %p", m_state);

    // TypeInfo head is at m_State + 8
    TypeInfo* typeinfo = *(TypeInfo**)((uint8_t*)m_state + 8);

    int captured = 0;
    int count = 0;
    while (typeinfo && count < 200) {  // Safety limit (100+ managers exist)
        // Check if this TypeInfo has a valid manager and name
        if (typeinfo->manager_ptr && typeinfo->type_name) {
            // type_name is a raw C string (verified via runtime probing)
            const char* name = (const char*)typeinfo->type_name;

            // Log first 20 entries and any containing "Feat" or "Manager"
            if (count < 20 || strstr(name, "Feat") || strstr(name, "Manager")) {
                log_message("[StaticData] TypeInfo[%d]: %s @ %p", count, name, typeinfo->manager_ptr);
            }

            // Try to match against known manager names
            for (int i = 0; i < STATICDATA_COUNT; i++) {
                // Only capture if not already captured
                if (!g_staticdata.managers[i] && strcmp(name, s_manager_type_names[i]) == 0) {
                    g_staticdata.managers[i] = typeinfo->manager_ptr;
                    log_message("[StaticData] Captured %s: %p", s_type_names[i], typeinfo->manager_ptr);
                    captured++;
                    break;
                }
            }
        }

        typeinfo = typeinfo->next;
        count++;
    }

    log_message("[StaticData] TypeContext traversal: scanned %d entries, captured %d managers", count, captured);
    return captured;
}

/**
 * Legacy function for debugging - traverses and logs all TypeInfo entries.
 */
static void* find_manager_via_typecontext(const char* type_name) {
    if (!g_staticdata.main_binary_base || !type_name) {
        return NULL;
    }

    // Get pointer to m_State
    void** ptr_mstate = (void**)((uint8_t*)g_staticdata.main_binary_base + OFFSET_MSTATE_PTR);
    void* m_state = *ptr_mstate;
    if (!m_state) {
        log_message("[StaticData] m_State is NULL");
        return NULL;
    }

    log_message("[StaticData] m_State at %p", m_state);

    // TypeInfo head is at m_State + 8
    TypeInfo* typeinfo = *(TypeInfo**)((uint8_t*)m_state + 8);

    int count = 0;
    while (typeinfo && count < 200) {  // Safety limit
        // Check if this TypeInfo has a valid manager
        if (typeinfo->manager_ptr && typeinfo->type_name) {
            // type_name is a raw C string (verified at runtime)
            const char* name = (const char*)typeinfo->type_name;
            log_message("[StaticData] TypeInfo[%d]: mgr=%p, name=%s",
                        count, typeinfo->manager_ptr, name);
        }

        typeinfo = typeinfo->next;
        count++;
    }

    log_message("[StaticData] Traversed %d TypeInfo entries", count);
    return NULL;
}

// ============================================================================
// Hook Functions
// ============================================================================

/**
 * Hook for FeatManager::GetFeats
 * Signature: void GetFeats(OutputArray* out, FeatManager* this)
 * On ARM64: x0 = out, x1 = FeatManager*
 */
typedef void (*FeatGetFeats_t)(void* out, void* feat_manager);
static FeatGetFeats_t g_orig_FeatGetFeats = NULL;

static void hook_FeatGetFeats(void* out, void* feat_manager) {
    // Capture FeatManager pointer
    if (feat_manager && !g_staticdata.managers[STATICDATA_FEAT]) {
        g_staticdata.managers[STATICDATA_FEAT] = feat_manager;
        log_message("[StaticData] Captured FeatManager via GetFeats hook: %p", feat_manager);

        // Log structure info using GetFeats-verified offsets (0x7C, 0x80)
        int32_t count = *(int32_t*)((uint8_t*)feat_manager + FEATMANAGER_OFFSET_COUNT);
        void* array = *(void**)((uint8_t*)feat_manager + FEATMANAGER_OFFSET_ARRAY);
        log_message("[StaticData] FeatManager structure: count@+0x7C=%d, array@+0x80=%p", count, array);

        // Verify by reading first feat entry
        if (array && count > 0) {
            uint8_t* first_feat = (uint8_t*)array;
            log_message("[StaticData] First feat at %p, first 16 bytes: %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X",
                first_feat,
                first_feat[0], first_feat[1], first_feat[2], first_feat[3],
                first_feat[4], first_feat[5], first_feat[6], first_feat[7],
                first_feat[8], first_feat[9], first_feat[10], first_feat[11],
                first_feat[12], first_feat[13], first_feat[14], first_feat[15]);
        }
    }

    // Call original
    if (g_orig_FeatGetFeats) {
        g_orig_FeatGetFeats(out, feat_manager);
    }
}

/**
 * Hook for GetAllFeats (called from character creation UI)
 * Signature: void GetAllFeats(Environment* param_1)
 * The FeatManager is at param_1 + 0x130
 */
typedef void (*GetAllFeats_t)(void* environment);
static GetAllFeats_t g_orig_GetAllFeats = NULL;

static void hook_GetAllFeats(void* environment) {
    log_message("[StaticData] GetAllFeats called with env=%p", environment);

    // Try to capture FeatManager from environment + 0x130
    if (environment && !g_staticdata.managers[STATICDATA_FEAT]) {
        void* feat_manager = *(void**)((uint8_t*)environment + 0x130);
        if (feat_manager) {
            g_staticdata.managers[STATICDATA_FEAT] = feat_manager;
            log_message("[StaticData] Captured FeatManager from env+0x130: %p", feat_manager);

            // Log structure info
            int32_t count = *(int32_t*)((uint8_t*)feat_manager + FEATMANAGER_OFFSET_COUNT);
            void* array = *(void**)((uint8_t*)feat_manager + FEATMANAGER_OFFSET_ARRAY);
            log_message("[StaticData] FeatManager: count=%d, array=%p", count, array);
        }
    }

    // Call original
    if (g_orig_GetAllFeats) {
        g_orig_GetAllFeats(environment);
    }
}

// ============================================================================
// Initialization
// ============================================================================

bool staticdata_manager_init(void *main_binary_base) {
    if (g_staticdata.initialized) {
        return true;
    }

    g_staticdata.main_binary_base = main_binary_base;

    // Clear manager pointers
    memset(g_staticdata.managers, 0, sizeof(g_staticdata.managers));

    // NOTE: GetFeats/GetAllFeats hooks DISABLED - they break feat selection UI
    // The hook intercepts correctly but breaks the original function call.
    // For now, use TypeContext capture for FeatManager instead.
    // TODO: Debug why original function call fails after hook

    log_message("[StaticData] GetFeats hooks DISABLED (broke feat UI) - using TypeContext only");

    g_staticdata.initialized = true;
    log_message("[StaticData] Static data manager initialized");

    return true;
}

bool staticdata_manager_ready(void) {
    if (!g_staticdata.initialized) {
        return false;
    }

    // Check if at least one manager is captured
    for (int i = 0; i < STATICDATA_COUNT; i++) {
        if (g_staticdata.managers[i]) {
            return true;
        }
    }

    return false;
}

const char* staticdata_type_name(StaticDataType type) {
    if (type < 0 || type >= STATICDATA_COUNT) {
        return NULL;
    }
    return s_type_names[type];
}

int staticdata_type_from_name(const char* name) {
    if (!name) return -1;

    for (int i = 0; i < STATICDATA_COUNT; i++) {
        if (strcasecmp(s_type_names[i], name) == 0) {
            return i;
        }
    }

    return -1;
}

// ============================================================================
// Manager Access
// ============================================================================

bool staticdata_has_manager(StaticDataType type) {
    if (type < 0 || type >= STATICDATA_COUNT) {
        return false;
    }

    // If not captured yet, try TypeContext capture (lazy initialization)
    if (!g_staticdata.managers[type] && g_staticdata.initialized) {
        capture_managers_via_typecontext();
    }

    return g_staticdata.managers[type] != NULL;
}

void* staticdata_get_manager(StaticDataType type) {
    if (type < 0 || type >= STATICDATA_COUNT) {
        return NULL;
    }
    return g_staticdata.managers[type];
}

bool staticdata_capture_manager(StaticDataType type) {
    // TODO: Call known accessor functions to trigger hook capture
    // For now, managers are captured lazily when game code calls them
    return staticdata_has_manager(type);
}

// ============================================================================
// Data Access - FeatManager specific
// ============================================================================

static int feat_get_count(void) {
    void* mgr = g_staticdata.managers[STATICDATA_FEAT];
    if (!mgr) return -1;

    return *(int32_t*)((uint8_t*)mgr + FEATMANAGER_OFFSET_COUNT);
}

static void* feat_get_by_index(int index) {
    void* mgr = g_staticdata.managers[STATICDATA_FEAT];
    if (!mgr) return NULL;

    int32_t count = *(int32_t*)((uint8_t*)mgr + FEATMANAGER_OFFSET_COUNT);
    if (index < 0 || index >= count) return NULL;

    void* array = *(void**)((uint8_t*)mgr + FEATMANAGER_OFFSET_ARRAY);
    if (!array) return NULL;

    // Each feat is FEAT_SIZE bytes
    return (uint8_t*)array + (index * FEAT_SIZE);
}

static void* feat_get_by_guid(const StaticDataGuid* guid) {
    void* mgr = g_staticdata.managers[STATICDATA_FEAT];
    if (!mgr || !guid) return NULL;

    int32_t count = *(int32_t*)((uint8_t*)mgr + FEATMANAGER_OFFSET_COUNT);
    void* array = *(void**)((uint8_t*)mgr + FEATMANAGER_OFFSET_ARRAY);
    if (!array) return NULL;

    // Linear search through feats comparing GUIDs
    // GUID is assumed to be at offset 0 of each feat
    for (int i = 0; i < count; i++) {
        void* entry = (uint8_t*)array + (i * FEAT_SIZE);
        if (memcmp(entry, guid, sizeof(StaticDataGuid)) == 0) {
            return entry;
        }
    }

    return NULL;
}

// ============================================================================
// Data Access - Generic
// ============================================================================

int staticdata_get_count(StaticDataType type) {
    switch (type) {
        case STATICDATA_FEAT:
            return feat_get_count();
        // TODO: Add other types as discovered
        default:
            return -1;
    }
}

StaticDataPtr staticdata_get_by_index(StaticDataType type, int index) {
    switch (type) {
        case STATICDATA_FEAT:
            return feat_get_by_index(index);
        default:
            return NULL;
    }
}

StaticDataPtr staticdata_get_by_guid(StaticDataType type, const StaticDataGuid* guid) {
    switch (type) {
        case STATICDATA_FEAT:
            return feat_get_by_guid(guid);
        default:
            return NULL;
    }
}

// ============================================================================
// GUID Parsing
// ============================================================================

static bool parse_guid(const char* str, StaticDataGuid* out) {
    if (!str || !out) return false;

    // Format: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    unsigned int d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11;

    if (sscanf(str, "%8x-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x",
               &d1, &d2, &d3, &d4, &d5, &d6, &d7, &d8, &d9, &d10, &d11) != 11) {
        return false;
    }

    out->data1 = d1;
    out->data2 = (uint16_t)d2;
    out->data3 = (uint16_t)d3;
    out->data4[0] = (uint8_t)d4;
    out->data4[1] = (uint8_t)d5;
    out->data4[2] = (uint8_t)d6;
    out->data4[3] = (uint8_t)d7;
    out->data4[4] = (uint8_t)d8;
    out->data4[5] = (uint8_t)d9;
    out->data4[6] = (uint8_t)d10;
    out->data4[7] = (uint8_t)d11;

    return true;
}

StaticDataPtr staticdata_get_by_guid_string(StaticDataType type, const char* guid_str) {
    StaticDataGuid guid;
    if (!parse_guid(guid_str, &guid)) {
        return NULL;
    }
    return staticdata_get_by_guid(type, &guid);
}

// ============================================================================
// Entry Property Access
// ============================================================================

bool staticdata_get_guid(StaticDataType type, StaticDataPtr entry, StaticDataGuid* out_guid) {
    if (!entry || !out_guid) return false;

    // GUID is assumed to be at offset 0 of entry
    memcpy(out_guid, entry, sizeof(StaticDataGuid));
    return true;
}

bool staticdata_get_guid_string(StaticDataType type, StaticDataPtr entry, char* out_buf, size_t buf_size) {
    if (!entry || !out_buf || buf_size < 37) return false;

    StaticDataGuid guid;
    if (!staticdata_get_guid(type, entry, &guid)) {
        return false;
    }

    snprintf(out_buf, buf_size, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             guid.data1, guid.data2, guid.data3,
             guid.data4[0], guid.data4[1],
             guid.data4[2], guid.data4[3], guid.data4[4],
             guid.data4[5], guid.data4[6], guid.data4[7]);

    return true;
}

const char* staticdata_get_name(StaticDataType type, StaticDataPtr entry) {
    // TODO: Discover name offset in each structure via runtime probing
    // For now, return NULL - names may be FixedStrings that need resolution
    (void)type;
    (void)entry;
    return NULL;
}

const char* staticdata_get_display_name(StaticDataType type, StaticDataPtr entry) {
    // TODO: Implement localized name lookup
    (void)type;
    (void)entry;
    return NULL;
}

// ============================================================================
// Debugging
// ============================================================================

void staticdata_try_typecontext_capture(void) {
    log_message("[StaticData] Attempting TypeContext capture...");
    int captured = capture_managers_via_typecontext();
    log_message("[StaticData] Captured %d managers via TypeContext", captured);
}

void staticdata_dump_status(void) {
    log_message("[StaticData] Manager Status:");
    log_message("  Initialized: %s", g_staticdata.initialized ? "yes" : "no");
    log_message("  Base: %p", g_staticdata.main_binary_base);

    for (int i = 0; i < STATICDATA_COUNT; i++) {
        void* mgr = g_staticdata.managers[i];
        if (mgr) {
            log_message("  %s: %p (count=%d)",
                        s_type_names[i], mgr, staticdata_get_count(i));
        } else {
            log_message("  %s: not captured", s_type_names[i]);
        }
    }
}

void staticdata_dump_entries(StaticDataType type, int max_entries) {
    int count = staticdata_get_count(type);
    if (count < 0) {
        log_message("[StaticData] Type %s not available", staticdata_type_name(type));
        return;
    }

    int to_dump = (max_entries < 0 || max_entries > count) ? count : max_entries;
    log_message("[StaticData] Dumping %d of %d %s entries:", to_dump, count, staticdata_type_name(type));

    for (int i = 0; i < to_dump; i++) {
        void* entry = staticdata_get_by_index(type, i);
        if (!entry) continue;

        char guid_str[40];
        if (staticdata_get_guid_string(type, entry, guid_str, sizeof(guid_str))) {
            log_message("  [%d] GUID=%s", i, guid_str);
        } else {
            log_message("  [%d] ptr=%p", i, entry);
        }
    }
}

void staticdata_probe_manager(StaticDataType type, int probe_range) {
    void* mgr = g_staticdata.managers[type];
    if (!mgr) {
        log_message("[StaticData] Cannot probe %s - manager not captured", staticdata_type_name(type));
        return;
    }

    log_message("[StaticData] Probing %s manager at %p (range: 0x%X):",
                staticdata_type_name(type), mgr, probe_range);

    // Dump hex view of manager structure
    uint8_t* data = (uint8_t*)mgr;
    for (int offset = 0; offset < probe_range; offset += 16) {
        char hex[64] = {0};
        char ascii[20] = {0};

        for (int i = 0; i < 16 && (offset + i) < probe_range; i++) {
            sprintf(hex + strlen(hex), "%02X ", data[offset + i]);
            ascii[i] = isprint(data[offset + i]) ? data[offset + i] : '.';
        }

        log_message("  +0x%02X: %-48s %s", offset, hex, ascii);
    }
}
