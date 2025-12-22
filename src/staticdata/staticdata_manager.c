/**
 * staticdata_manager.c - StaticData Manager Implementation for BG3SE-macOS
 *
 * Captures static data managers via hooks and provides access for Lua API.
 */

#include "staticdata_manager.h"
#include "../core/logging.h"
#include "../core/safe_memory.h"
#include "../strings/fixed_string.h"
#include "../hooks/arm64_hook.h"
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

// Get<T> function addresses (for real manager capture - Dec 22, 2025)
// These functions return the real manager pointers from ImmutableDataHeadmaster
#define OFFSET_GET_BACKGROUND         0x02994834  // Get<eoc::BackgroundManager>
#define OFFSET_GET_ORIGIN             0x0341c42c  // Get<eoc::OriginManager>
#define OFFSET_GET_CLASS              0x0262f184  // Get<eoc::ClassDescriptions>
#define OFFSET_GET_PROGRESSION        0x03697f0c  // Get<eoc::ProgressionManager>
#define OFFSET_GET_ACTIONRESOURCE     0x011a4494  // Get<eoc::ActionResourceTypes>

// FeatManager structure offsets
//
// TypeContext Metadata (GuidResourceBank HashMap - Dec 20, 2025 discovery):
//   +0x7C: Keys.size_ (entry count, e.g., 37)
//   +0x80: Values.buf_ (array of POINTERS to Feat structs)
//   NOTE: This is a HashMap, so +0x80 contains pointers, NOT flat structs!
//
// Session FeatManager (from GetFeats hook - only during character creation):
//   +0x7C: int32_t count
//   +0x80: Feat* array (flat array of Feat structs, each 0x128 bytes)
//
// The key difference: TypeContext Values.buf_ is an array of POINTERS,
// while Session FeatManager has a flat array of structs.
//
#define FEATMANAGER_REAL_COUNT_OFFSET    0x7C   // Real FeatManager count offset
#define FEATMANAGER_REAL_ARRAY_OFFSET    0x80   // Real FeatManager array offset
#define FEATMANAGER_META_COUNT_OFFSET    0x7C   // TypeContext HashMap Keys.size_ offset
#define FEATMANAGER_META_VALUES_OFFSET   0x80   // TypeContext HashMap Values.buf_ offset (pointer array)

// Structure offsets (verified via Windows BG3SE GuidResources.h)
// Base class GuidResource: VMT (8) + ResourceUUID (16) = 24 bytes (0x18)
// Then type-specific fields follow

// Feat structure
#define FEAT_SIZE                     0x128  // 296 bytes per feat
#define FEAT_OFFSET_NAME              0x18   // FixedString Name (after GuidResource base)

// Race structure
#define RACE_SIZE                     0x200  // Estimate - has many arrays
#define RACE_OFFSET_NAME              0x18   // FixedString Name (same as Feat)

// Origin structure
// Has uint8_t AvailableInCharacterCreation at +0x18 before Name
#define ORIGIN_SIZE                   0x180  // Estimate
#define ORIGIN_OFFSET_NAME            0x1C   // FixedString Name (aligned after uint8_t)

// Background structure - NO Name field, only DisplayName (TranslatedString)
#define BACKGROUND_SIZE               0x80   // Estimate
#define BACKGROUND_OFFSET_NAME        0      // No FixedString Name field!

// God structure
#define GOD_SIZE                      0x60   // Small structure
#define GOD_OFFSET_NAME               0x18   // FixedString Name

// ClassDescription structure
// Has Guid ParentGuid (16 bytes) at +0x18 before Name
#define CLASS_SIZE                    0x100  // Estimate
#define CLASS_OFFSET_NAME             0x28   // FixedString Name (after ParentGuid)

// ============================================================================
// Manager Configuration (per-type structure info)
// ============================================================================

typedef struct {
    int count_offset;    // Offset to count field in manager
    int array_offset;    // Offset to array pointer in manager
    int entry_size;      // Size of each entry
    int name_offset;     // Offset to Name FixedString in entry (0 = no name)
    const char* capture_file;  // Path to Frida capture file
} ManagerConfig;

static const ManagerConfig g_manager_configs[STATICDATA_COUNT] = {
    // STATICDATA_FEAT
    { 0x7C, 0x80, FEAT_SIZE, FEAT_OFFSET_NAME, "/tmp/bg3se_featmanager.txt" },
    // STATICDATA_RACE
    { 0x7C, 0x80, RACE_SIZE, RACE_OFFSET_NAME, "/tmp/bg3se_racemanager.txt" },
    // STATICDATA_BACKGROUND
    { 0x7C, 0x80, BACKGROUND_SIZE, 0, "/tmp/bg3se_backgroundmanager.txt" },  // No Name
    // STATICDATA_ORIGIN
    { 0x7C, 0x80, ORIGIN_SIZE, ORIGIN_OFFSET_NAME, "/tmp/bg3se_originmanager.txt" },
    // STATICDATA_GOD
    { 0x7C, 0x80, GOD_SIZE, GOD_OFFSET_NAME, "/tmp/bg3se_godmanager.txt" },
    // STATICDATA_CLASS
    { 0x7C, 0x80, CLASS_SIZE, CLASS_OFFSET_NAME, "/tmp/bg3se_classmanager.txt" },
    // STATICDATA_PROGRESSION
    { 0x7C, 0x80, 0x200, 0x18, "/tmp/bg3se_progressionmanager.txt" },
    // STATICDATA_ACTIONRESOURCE
    { 0x7C, 0x80, 0x80, 0x18, "/tmp/bg3se_actionresourcemanager.txt" },
    // STATICDATA_FEATDESCRIPTION
    { 0x7C, 0x80, 0x80, 0, "/tmp/bg3se_featdescmanager.txt" },  // Has TranslatedString, not FixedString
};

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
// Names sourced from Windows BG3SE GuidResources.h EngineClass definitions
static const char* s_manager_type_names[STATICDATA_COUNT] = {
    "eoc::FeatManager",
    "eoc::RaceManager",
    "eoc::BackgroundManager",
    "eoc::OriginManager",
    "eoc::GodManager",
    "eoc::ClassDescriptions",           // Was ClassManager - corrected per GuidResources.h
    "eoc::ProgressionManager",
    "eoc::ActionResourceTypes",         // Was ActionResourceManager - corrected per GuidResources.h
    "eoc::FeatDescriptionManager"
};

// ============================================================================
// Module State
// ============================================================================

static struct {
    bool initialized;
    void* main_binary_base;

    // Captured manager pointers (from TypeContext - metadata structures)
    void* managers[STATICDATA_COUNT];

    // Real manager pointers (probed from metadata or captured via hooks)
    void* real_managers[STATICDATA_COUNT];

    // Original function pointers (for hooks)
    void* orig_feat_getfeats;

    // ARM64 safe hook handles
    ARM64HookHandle* feat_getfeats_hook;
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

// ============================================================================
// Real Manager Discovery (Probing)
// ============================================================================

/**
 * Check if a pointer looks like a valid manager for a given type.
 * Uses ManagerConfig to validate using type-specific offsets.
 * Valid manager has:
 *   - count at count_offset: reasonable value (1-10000)
 *   - array at array_offset: non-null pointer to heap
 * Uses safe memory reads to prevent crashes.
 */
static bool looks_like_real_manager(StaticDataType type, void* ptr) {
    if (!ptr || type < 0 || type >= STATICDATA_COUNT) return false;

    const ManagerConfig* config = &g_manager_configs[type];

    // Safely read count at type's count_offset
    int32_t count = 0;
    if (!safe_memory_read_i32((mach_vm_address_t)ptr + config->count_offset, &count)) {
        return false;  // Memory not readable
    }

    // Count should be reasonable (allow 1-10000 for all types)
    if (count <= 0 || count > 10000) return false;

    // Safely read array pointer at type's array_offset
    void* array = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)ptr + config->array_offset, &array)) {
        return false;  // Memory not readable
    }

    // Array pointer should be non-null and look like a heap address
    if (!array) return false;
    uintptr_t arr_addr = (uintptr_t)array;

    // Heap addresses on macOS are typically > 0x600000000000
    // But code pointers are ~0x100000000
    // Allow anything that's not obviously wrong
    if (arr_addr < 0x100000000ULL) return false;

    return true;
}

/**
 * Legacy wrapper for Feat-specific validation.
 */
static bool looks_like_real_feat_manager(void* ptr) {
    return looks_like_real_manager(STATICDATA_FEAT, ptr);
}

/**
 * Try to find the real manager by probing the TypeContext metadata structure.
 * The metadata might contain a pointer to the real manager.
 * Uses safe memory reads to prevent crashes.
 *
 * @param type Static data type
 * @param metadata Metadata pointer from TypeContext
 * @return Pointer to real manager, or NULL if not found
 */
static void* probe_for_real_manager(StaticDataType type, void* metadata) {
    if (!metadata || type < 0 || type >= STATICDATA_COUNT) return NULL;

    const ManagerConfig* config = &g_manager_configs[type];
    const char* type_name = s_type_names[type];

    log_message("[StaticData] Probing metadata %p for real %s manager...", metadata, type_name);

    // First check: is the metadata itself the real manager?
    if (looks_like_real_manager(type, metadata)) {
        int32_t count = 0;
        safe_memory_read_i32((mach_vm_address_t)metadata + config->count_offset, &count);
        log_message("[StaticData] Metadata IS the real %s manager (count@+0x%x=%d)",
                    type_name, config->count_offset, count);
        return metadata;
    }

    // Safely read metadata count at +0x00
    int32_t meta_count = 0;
    if (safe_memory_read_i32((mach_vm_address_t)metadata + FEATMANAGER_META_COUNT_OFFSET, &meta_count)) {
        log_message("[StaticData] Metadata count@+0x00=%d", meta_count);
    }

    // Probe for pointers at various offsets that could point to real manager
    // Extended range: 0x08 through 0x100 in steps of 8
    int offsets_to_probe[] = {
        0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40,
        0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80,
        0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8, 0xC0,
        0xC8, 0xD0, 0xD8, 0xE0, 0xE8, 0xF0, 0xF8, 0x100
    };
    int num_offsets = sizeof(offsets_to_probe) / sizeof(offsets_to_probe[0]);

    // For Feat type, dump all pointer candidates for debugging
    if (type == STATICDATA_FEAT) {
        log_message("[StaticData] Dumping Feat metadata structure at %p:", metadata);
        for (int i = 0; i < num_offsets; i++) {
            int offset = offsets_to_probe[i];
            void* ptr = NULL;
            if (safe_memory_read_pointer((mach_vm_address_t)metadata + offset, &ptr)) {
                // Check if this looks like a valid heap pointer
                if (ptr && (uintptr_t)ptr > 0x100000000ULL && (uintptr_t)ptr < 0x800000000000ULL) {
                    // Try to read count at +0x7C from this candidate
                    int32_t maybe_count = 0;
                    void* maybe_array = NULL;
                    if (safe_memory_read_i32((mach_vm_address_t)ptr + 0x7C, &maybe_count) &&
                        safe_memory_read_pointer((mach_vm_address_t)ptr + 0x80, &maybe_array)) {
                        log_message("[StaticData]   +0x%02X: %p -> count@+0x7C=%d, array@+0x80=%p",
                                    offset, ptr, maybe_count, maybe_array);
                    } else {
                        log_message("[StaticData]   +0x%02X: %p (can't read +0x7C/+0x80)", offset, ptr);
                    }
                }
            }
        }
    }

    for (int i = 0; i < num_offsets; i++) {
        int offset = offsets_to_probe[i];
        void* candidate = NULL;

        // Safely read the candidate pointer
        if (!safe_memory_read_pointer((mach_vm_address_t)metadata + offset, &candidate)) {
            continue;  // Memory not readable at this offset
        }

        if (candidate && looks_like_real_manager(type, candidate)) {
            int32_t count = 0;
            void* array = NULL;
            safe_memory_read_i32((mach_vm_address_t)candidate + config->count_offset, &count);
            safe_memory_read_pointer((mach_vm_address_t)candidate + config->array_offset, &array);
            log_message("[StaticData] FOUND real %s manager at metadata+0x%02X: %p (count=%d, array=%p)",
                        type_name, offset, candidate, count, array);
            return candidate;
        }
    }

    log_message("[StaticData] Could not find real %s manager from metadata", type_name);
    return NULL;
}

/**
 * Legacy wrapper for Feat-specific probing.
 */
static void* probe_for_real_feat_manager(void* metadata) {
    return probe_for_real_manager(STATICDATA_FEAT, metadata);
}

/**
 * Capture all known managers by traversing the ImmutableDataHeadmaster TypeContext.
 * The type_name field is a raw C string pointer (verified at runtime).
 * Returns number of managers captured.
 * Uses safe memory reads to prevent crashes.
 */
static int capture_managers_via_typecontext(void) {
    if (!g_staticdata.main_binary_base) {
        return 0;
    }

    // Safely get pointer to m_State
    void* m_state = NULL;
    mach_vm_address_t ptr_mstate_addr = (mach_vm_address_t)g_staticdata.main_binary_base + OFFSET_MSTATE_PTR;
    if (!safe_memory_read_pointer(ptr_mstate_addr, &m_state)) {
        log_message("[StaticData] Could not read m_State pointer at %p", (void*)ptr_mstate_addr);
        return 0;
    }
    if (!m_state) {
        log_message("[StaticData] m_State is NULL - TypeContext not available yet");
        return 0;
    }

    log_message("[StaticData] TypeContext traversal: m_State at %p", m_state);

    // Safely read TypeInfo head at m_State + 8
    TypeInfo* typeinfo = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)m_state + 8, (void**)&typeinfo)) {
        log_message("[StaticData] Could not read TypeInfo head pointer");
        return 0;
    }

    int captured = 0;
    int count = 0;
    while (typeinfo && count < 200) {  // Safety limit (100+ managers exist)
        // Safely read TypeInfo fields
        void* manager_ptr = NULL;
        void* type_name_ptr = NULL;
        TypeInfo* next_ptr = NULL;

        if (!safe_memory_read_pointer((mach_vm_address_t)&typeinfo->manager_ptr, &manager_ptr) ||
            !safe_memory_read_pointer((mach_vm_address_t)&typeinfo->type_name, &type_name_ptr) ||
            !safe_memory_read_pointer((mach_vm_address_t)&typeinfo->next, (void**)&next_ptr)) {
            log_message("[StaticData] Could not read TypeInfo fields at %p, stopping traversal", typeinfo);
            break;
        }

        // Check if this TypeInfo has a valid manager and name
        if (manager_ptr && type_name_ptr) {
            // Safely read type name string (up to 128 chars)
            char name[128] = {0};
            if (safe_memory_read_string((mach_vm_address_t)type_name_ptr, name, sizeof(name))) {
                // Log first 20 entries and any containing "Feat", "Manager", "Class", "Action", or "Descriptions"
                if (count < 20 || strstr(name, "Feat") || strstr(name, "Manager") ||
                    strstr(name, "Class") || strstr(name, "Action") || strstr(name, "Descriptions")) {
                    log_message("[StaticData] TypeInfo[%d]: %s @ %p", count, name, manager_ptr);
                }

                // Try to match against known manager names
                for (int i = 0; i < STATICDATA_COUNT; i++) {
                    // Only capture if not already captured
                    if (!g_staticdata.managers[i] && strcmp(name, s_manager_type_names[i]) == 0) {
                        g_staticdata.managers[i] = manager_ptr;
                        log_message("[StaticData] *** MATCHED *** %s = %s @ %p",
                                    s_type_names[i], s_manager_type_names[i], manager_ptr);

                        // NOTE: We do NOT probe for real managers anymore.
                        // Dec 20, 2025 discovery: TypeContext metadata IS a GuidResourceBank
                        // with HashMap. The metadata itself has:
                        //   +0x7C: Keys.size_ (entry count)
                        //   +0x80: Values.buf_ (pointer array to entries)
                        //
                        // The previous probe_for_real_manager() incorrectly found a
                        // structure at metadata+0xC0 with count=1, causing GetAll to
                        // return only 1 item instead of 37.
                        //
                        // real_managers[] is now only set by hooks (GetFeats hook during
                        // character creation), which capture the Session FeatManager with
                        // flat array structure.

                        captured++;
                        break;
                    }
                }
            }
        }

        typeinfo = next_ptr;
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
    // Capture REAL FeatManager pointer (the one with count@+0x7C, array@+0x80)
    // This goes to real_managers, not managers (which holds TypeContext metadata)
    if (feat_manager && !g_staticdata.real_managers[STATICDATA_FEAT]) {
        g_staticdata.real_managers[STATICDATA_FEAT] = feat_manager;
        log_message("[StaticData] *** HOOK FIRED *** Captured REAL FeatManager: %p", feat_manager);

        // Log structure info using GetFeats-verified offsets (0x7C, 0x80)
        int32_t count = *(int32_t*)((uint8_t*)feat_manager + FEATMANAGER_REAL_COUNT_OFFSET);
        void* array = *(void**)((uint8_t*)feat_manager + FEATMANAGER_REAL_ARRAY_OFFSET);
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
            int32_t count = *(int32_t*)((uint8_t*)feat_manager + FEATMANAGER_REAL_COUNT_OFFSET);
            void* array = *(void**)((uint8_t*)feat_manager + FEATMANAGER_REAL_ARRAY_OFFSET);
            log_message("[StaticData] FeatManager: count=%d, array=%p", count, array);
        }
    }

    // Call original
    if (g_orig_GetAllFeats) {
        g_orig_GetAllFeats(environment);
    }
}

// ============================================================================
// Get<T> Hooks (Dec 22, 2025 - Real Manager Capture)
// ============================================================================

/**
 * Hook typedef for Get<T> functions.
 * Signature: Manager* Get(ImmutableDataHeadmaster* this)
 * ARM64: x0 = this, returns manager in x0
 */
typedef void* (*GetManager_t)(void* headmaster);

// Original function pointers
static GetManager_t g_orig_GetBackground = NULL;
static GetManager_t g_orig_GetOrigin = NULL;
static GetManager_t g_orig_GetClass = NULL;
static GetManager_t g_orig_GetProgression = NULL;
static GetManager_t g_orig_GetActionResource = NULL;

// ImmutableDataHeadmaster pointer (captured from Get<T> hooks)
static void* g_immutable_data_headmaster = NULL;

/**
 * Hook for Get<eoc::BackgroundManager>
 */
static void* hook_GetBackground(void* headmaster) {
    // Capture ImmutableDataHeadmaster pointer
    if (headmaster && !g_immutable_data_headmaster) {
        g_immutable_data_headmaster = headmaster;
        log_message("[StaticData] Captured ImmutableDataHeadmaster: %p", headmaster);
    }

    void* result = g_orig_GetBackground ? g_orig_GetBackground(headmaster) : NULL;

    // Capture real manager
    if (result && !g_staticdata.real_managers[STATICDATA_BACKGROUND]) {
        g_staticdata.real_managers[STATICDATA_BACKGROUND] = result;
        log_message("[StaticData] *** GET<T> HOOK *** Captured real BackgroundManager: %p", result);

        // Verify structure
        int32_t count = 0;
        void* array = NULL;
        if (safe_memory_read_i32((mach_vm_address_t)result + 0x7C, &count) &&
            safe_memory_read_pointer((mach_vm_address_t)result + 0x80, &array)) {
            log_message("[StaticData] BackgroundManager: count@+0x7C=%d, array@+0x80=%p", count, array);
        }
    }

    return result;
}

/**
 * Hook for Get<eoc::OriginManager>
 */
static void* hook_GetOrigin(void* headmaster) {
    if (headmaster && !g_immutable_data_headmaster) {
        g_immutable_data_headmaster = headmaster;
    }

    void* result = g_orig_GetOrigin ? g_orig_GetOrigin(headmaster) : NULL;

    if (result && !g_staticdata.real_managers[STATICDATA_ORIGIN]) {
        g_staticdata.real_managers[STATICDATA_ORIGIN] = result;
        log_message("[StaticData] *** GET<T> HOOK *** Captured real OriginManager: %p", result);

        int32_t count = 0;
        if (safe_memory_read_i32((mach_vm_address_t)result + 0x7C, &count)) {
            log_message("[StaticData] OriginManager: count@+0x7C=%d", count);
        }
    }

    return result;
}

/**
 * Hook for Get<eoc::ClassDescriptions>
 */
static void* hook_GetClass(void* headmaster) {
    if (headmaster && !g_immutable_data_headmaster) {
        g_immutable_data_headmaster = headmaster;
    }

    void* result = g_orig_GetClass ? g_orig_GetClass(headmaster) : NULL;

    if (result && !g_staticdata.real_managers[STATICDATA_CLASS]) {
        g_staticdata.real_managers[STATICDATA_CLASS] = result;
        log_message("[StaticData] *** GET<T> HOOK *** Captured real ClassDescriptions: %p", result);

        int32_t count = 0;
        if (safe_memory_read_i32((mach_vm_address_t)result + 0x7C, &count)) {
            log_message("[StaticData] ClassDescriptions: count@+0x7C=%d", count);
        }
    }

    return result;
}

/**
 * Hook for Get<eoc::ProgressionManager>
 */
static void* hook_GetProgression(void* headmaster) {
    if (headmaster && !g_immutable_data_headmaster) {
        g_immutable_data_headmaster = headmaster;
    }

    void* result = g_orig_GetProgression ? g_orig_GetProgression(headmaster) : NULL;

    if (result && !g_staticdata.real_managers[STATICDATA_PROGRESSION]) {
        g_staticdata.real_managers[STATICDATA_PROGRESSION] = result;
        log_message("[StaticData] *** GET<T> HOOK *** Captured real ProgressionManager: %p", result);

        int32_t count = 0;
        if (safe_memory_read_i32((mach_vm_address_t)result + 0x7C, &count)) {
            log_message("[StaticData] ProgressionManager: count@+0x7C=%d", count);
        }
    }

    return result;
}

/**
 * Hook for Get<eoc::ActionResourceTypes>
 */
static void* hook_GetActionResource(void* headmaster) {
    if (headmaster && !g_immutable_data_headmaster) {
        g_immutable_data_headmaster = headmaster;
    }

    void* result = g_orig_GetActionResource ? g_orig_GetActionResource(headmaster) : NULL;

    if (result && !g_staticdata.real_managers[STATICDATA_ACTION_RESOURCE]) {
        g_staticdata.real_managers[STATICDATA_ACTION_RESOURCE] = result;
        log_message("[StaticData] *** GET<T> HOOK *** Captured real ActionResourceTypes: %p", result);

        int32_t count = 0;
        if (safe_memory_read_i32((mach_vm_address_t)result + 0x7C, &count)) {
            log_message("[StaticData] ActionResourceTypes: count@+0x7C=%d", count);
        }
    }

    return result;
}

/**
 * Install hooks for Get<T> functions.
 * Uses standard Dobby hooks (Get<T> functions are small and typically safe).
 */
static void install_get_manager_hooks(void* main_binary_base) {
    log_message("[StaticData] Installing Get<T> hooks for real manager capture...");

    // Background
    void* target = (uint8_t*)main_binary_base + OFFSET_GET_BACKGROUND;
    if (DobbyHook(target, (void*)hook_GetBackground, (void**)&g_orig_GetBackground) == 0) {
        log_message("[StaticData] Installed Get<BackgroundManager> hook at %p", target);
    } else {
        log_message("[StaticData] WARNING: Failed to hook Get<BackgroundManager>");
    }

    // Origin
    target = (uint8_t*)main_binary_base + OFFSET_GET_ORIGIN;
    if (DobbyHook(target, (void*)hook_GetOrigin, (void**)&g_orig_GetOrigin) == 0) {
        log_message("[StaticData] Installed Get<OriginManager> hook at %p", target);
    } else {
        log_message("[StaticData] WARNING: Failed to hook Get<OriginManager>");
    }

    // Class
    target = (uint8_t*)main_binary_base + OFFSET_GET_CLASS;
    if (DobbyHook(target, (void*)hook_GetClass, (void**)&g_orig_GetClass) == 0) {
        log_message("[StaticData] Installed Get<ClassDescriptions> hook at %p", target);
    } else {
        log_message("[StaticData] WARNING: Failed to hook Get<ClassDescriptions>");
    }

    // Progression
    target = (uint8_t*)main_binary_base + OFFSET_GET_PROGRESSION;
    if (DobbyHook(target, (void*)hook_GetProgression, (void**)&g_orig_GetProgression) == 0) {
        log_message("[StaticData] Installed Get<ProgressionManager> hook at %p", target);
    } else {
        log_message("[StaticData] WARNING: Failed to hook Get<ProgressionManager>");
    }

    // ActionResource
    target = (uint8_t*)main_binary_base + OFFSET_GET_ACTIONRESOURCE;
    if (DobbyHook(target, (void*)hook_GetActionResource, (void**)&g_orig_GetActionResource) == 0) {
        log_message("[StaticData] Installed Get<ActionResourceTypes> hook at %p", target);
    } else {
        log_message("[StaticData] WARNING: Failed to hook Get<ActionResourceTypes>");
    }

    log_message("[StaticData] Get<T> hooks installation complete");
}

/**
 * Force capture managers by calling Get<T> functions directly.
 * Uses captured ImmutableDataHeadmaster to trigger manager capture
 * for types where hooks are installed but haven't fired yet.
 * Returns number of managers newly captured.
 */
int staticdata_force_capture(void) {
    if (!g_immutable_data_headmaster) {
        log_message("[StaticData] Cannot force capture - no ImmutableDataHeadmaster captured yet");
        return 0;
    }

    int captured = 0;
    log_message("[StaticData] Force capturing managers via ImmutableDataHeadmaster %p",
                g_immutable_data_headmaster);

    // Background - call original if not captured
    if (!g_staticdata.real_managers[STATICDATA_BACKGROUND] && g_orig_GetBackground) {
        void* result = g_orig_GetBackground(g_immutable_data_headmaster);
        if (result) {
            g_staticdata.real_managers[STATICDATA_BACKGROUND] = result;
            int32_t count = 0;
            safe_memory_read_i32((mach_vm_address_t)result + 0x7C, &count);
            log_message("[StaticData] Force captured BackgroundManager: %p (count=%d)", result, count);
            captured++;
        }
    }

    // Origin - call original if not captured
    if (!g_staticdata.real_managers[STATICDATA_ORIGIN] && g_orig_GetOrigin) {
        void* result = g_orig_GetOrigin(g_immutable_data_headmaster);
        if (result) {
            g_staticdata.real_managers[STATICDATA_ORIGIN] = result;
            int32_t count = 0;
            safe_memory_read_i32((mach_vm_address_t)result + 0x7C, &count);
            log_message("[StaticData] Force captured OriginManager: %p (count=%d)", result, count);
            captured++;
        }
    }

    // Class - call original if not captured
    if (!g_staticdata.real_managers[STATICDATA_CLASS] && g_orig_GetClass) {
        void* result = g_orig_GetClass(g_immutable_data_headmaster);
        if (result) {
            g_staticdata.real_managers[STATICDATA_CLASS] = result;
            int32_t count = 0;
            safe_memory_read_i32((mach_vm_address_t)result + 0x7C, &count);
            log_message("[StaticData] Force captured ClassDescriptions: %p (count=%d)", result, count);
            captured++;
        }
    }

    // Progression - call original if not captured
    if (!g_staticdata.real_managers[STATICDATA_PROGRESSION] && g_orig_GetProgression) {
        void* result = g_orig_GetProgression(g_immutable_data_headmaster);
        if (result) {
            g_staticdata.real_managers[STATICDATA_PROGRESSION] = result;
            int32_t count = 0;
            safe_memory_read_i32((mach_vm_address_t)result + 0x7C, &count);
            log_message("[StaticData] Force captured ProgressionManager: %p (count=%d)", result, count);
            captured++;
        }
    }

    // ActionResource - call original if not captured
    if (!g_staticdata.real_managers[STATICDATA_ACTION_RESOURCE] && g_orig_GetActionResource) {
        void* result = g_orig_GetActionResource(g_immutable_data_headmaster);
        if (result) {
            g_staticdata.real_managers[STATICDATA_ACTION_RESOURCE] = result;
            int32_t count = 0;
            safe_memory_read_i32((mach_vm_address_t)result + 0x7C, &count);
            log_message("[StaticData] Force captured ActionResourceTypes: %p (count=%d)", result, count);
            captured++;
        }
    }

    log_message("[StaticData] Force capture complete: %d managers newly captured", captured);
    return captured;
}

/**
 * Look up a manager in ImmutableDataHeadmaster using type index from TypeContext.
 *
 * ImmutableDataHeadmaster hash table structure (from Get<T> decompilation):
 *   +0x00: buckets array (uint32_t*) - initial bucket indices
 *   +0x08: bucket_count (int32_t) - number of buckets
 *   +0x10: next array (uint32_t*) - chain for collision resolution
 *   +0x20: keys array (int32_t*) - type indices
 *   +0x2c: size (int32_t) - number of entries
 *   +0x30: values array (void**) - manager pointers
 *
 * TypeContext slot structure (what managers[] contains):
 *   +0x00: type_index (int32_t) - used for hash lookup
 *   +0x08: flags/padding
 *   +0x38: type name string pointer
 *
 * @param type_index The type index to look up
 * @return Manager pointer, or NULL if not found
 */
static void* lookup_manager_by_type_index(int32_t type_index) {
    if (!g_immutable_data_headmaster || type_index < 0) {
        return NULL;
    }

    void* headmaster = g_immutable_data_headmaster;

    // Read hash table structure
    void* buckets = NULL;
    int32_t bucket_count = 0;
    void* next_chain = NULL;
    void* keys = NULL;
    int32_t size = 0;
    void* values = NULL;

    if (!safe_memory_read_pointer((mach_vm_address_t)headmaster + 0x00, &buckets) ||
        !safe_memory_read_i32((mach_vm_address_t)headmaster + 0x08, &bucket_count) ||
        !safe_memory_read_pointer((mach_vm_address_t)headmaster + 0x10, &next_chain) ||
        !safe_memory_read_pointer((mach_vm_address_t)headmaster + 0x20, &keys) ||
        !safe_memory_read_i32((mach_vm_address_t)headmaster + 0x2c, &size) ||
        !safe_memory_read_pointer((mach_vm_address_t)headmaster + 0x30, &values)) {
        log_message("[StaticData] Hash lookup: failed to read headmaster structure");
        return NULL;
    }

    if (!buckets || bucket_count <= 0 || !keys || !values) {
        log_message("[StaticData] Hash lookup: invalid headmaster structure");
        return NULL;
    }

    // Compute bucket index: type_index % bucket_count
    int32_t bucket_idx = type_index % bucket_count;
    if (bucket_idx < 0) bucket_idx += bucket_count;  // Handle negative modulo

    // Read initial index from bucket
    uint32_t idx = 0;
    if (!safe_memory_read_u32((mach_vm_address_t)buckets + bucket_idx * 4, &idx)) {
        return NULL;
    }

    // Walk the chain
    while ((int32_t)idx >= 0) {
        // Read key at this index
        int32_t key = 0;
        if (!safe_memory_read_i32((mach_vm_address_t)keys + idx * 4, &key)) {
            break;
        }

        if (key == type_index) {
            // Found it - read value
            void* manager = NULL;
            if (safe_memory_read_pointer((mach_vm_address_t)values + idx * 8, &manager)) {
                return manager;
            }
            break;
        }

        // Follow next chain
        if (!next_chain) break;
        if (!safe_memory_read_u32((mach_vm_address_t)next_chain + idx * 4, &idx)) {
            break;
        }
    }

    return NULL;
}

/**
 * Force capture managers that don't have Get<T> hooks by using hash lookup.
 * This works for Race, God, FeatDescription which don't have templated Get functions.
 *
 * Prerequisites:
 *   - ImmutableDataHeadmaster must be captured (via any Get<T> hook)
 *   - TypeContext must be captured (provides type indices)
 *
 * @return Number of managers newly captured via hash lookup
 */
int staticdata_hash_lookup_capture(void) {
    if (!g_immutable_data_headmaster) {
        log_message("[StaticData] Hash lookup: no ImmutableDataHeadmaster captured yet");
        return 0;
    }

    int captured = 0;
    log_message("[StaticData] Attempting hash lookup capture for remaining types...");

    // Types without Get<T> hooks: Race, God, FeatDescription, (Feat if hook didn't fire)
    StaticDataType hash_types[] = {
        STATICDATA_RACE,
        STATICDATA_GOD,
        STATICDATA_FEAT_DESCRIPTION,
        STATICDATA_FEAT  // Also try Feat in case hook didn't fire
    };

    for (int i = 0; i < sizeof(hash_types)/sizeof(hash_types[0]); i++) {
        StaticDataType type = hash_types[i];

        // Skip if already captured
        if (g_staticdata.real_managers[type]) {
            continue;
        }

        // Need TypeContext metadata to get type index
        void* slot_ptr = g_staticdata.managers[type];
        if (!slot_ptr) {
            log_message("[StaticData] Hash lookup: no TypeContext for %s", s_type_names[type]);
            continue;
        }

        // Read type index from slot_ptr+0x00
        int32_t type_index = 0;
        if (!safe_memory_read_i32((mach_vm_address_t)slot_ptr, &type_index)) {
            log_message("[StaticData] Hash lookup: failed to read type_index for %s", s_type_names[type]);
            continue;
        }

        log_message("[StaticData] Hash lookup: %s has type_index=%d", s_type_names[type], type_index);

        // Look up in hash table
        void* manager = lookup_manager_by_type_index(type_index);
        if (manager) {
            g_staticdata.real_managers[type] = manager;

            // Verify structure
            int32_t count = 0;
            safe_memory_read_i32((mach_vm_address_t)manager + 0x7C, &count);
            log_message("[StaticData] Hash lookup captured %s: %p (count=%d)",
                        s_type_names[type], manager, count);
            captured++;
        } else {
            log_message("[StaticData] Hash lookup: %s not found in hash table", s_type_names[type]);
        }
    }

    log_message("[StaticData] Hash lookup complete: %d managers newly captured", captured);
    return captured;
}

// ============================================================================
// ARM64 Safe Hook Installation (Issue #44)
// ============================================================================

/**
 * Install ARM64-safe hook for FeatManager::GetFeats.
 * Uses skip-and-redirect strategy to avoid ADRP corruption.
 * Returns true if hook was installed successfully.
 */
static bool install_feat_getfeats_safe_hook(void* main_binary_base) {
    void* target = (uint8_t*)main_binary_base + OFFSET_FEAT_GETFEATS;

    // First, analyze the prologue to understand the ADRP patterns
    log_message("[StaticData] Analyzing FeatManager::GetFeats prologue at %p", target);
    arm64_analyze_and_log(target, "FeatManager::GetFeats");

    // Check if it has ADRP in prologue
    if (arm64_has_prologue_adrp(target)) {
        log_message("[StaticData] ADRP detected in prologue - using ARM64 safe hook");

        // Get recommended hook offset
        int safe_offset = arm64_get_recommended_hook_offset(target);
        if (safe_offset < 0) {
            log_message("[StaticData] WARNING: No safe hook point found, falling back to TypeContext");
            return false;
        }

        log_message("[StaticData] Safe hook point at +%d (0x%x)", safe_offset, safe_offset);

        // Install the safe hook
        void* original = NULL;
        g_staticdata.feat_getfeats_hook = arm64_safe_hook(target, (void*)hook_FeatGetFeats, &original);

        if (g_staticdata.feat_getfeats_hook) {
            g_orig_FeatGetFeats = (FeatGetFeats_t)original;
            log_message("[StaticData] ARM64 safe hook installed successfully!");
            log_message("[StaticData]   Original function trampoline: %p", original);
            return true;
        } else {
            log_message("[StaticData] WARNING: ARM64 safe hook installation failed");
            return false;
        }
    } else {
        // No ADRP in prologue - safe to use standard Dobby hook!
        log_message("[StaticData] No ADRP in prologue - installing standard Dobby hook");

        void* original = NULL;
        int result = DobbyHook(target, (void*)hook_FeatGetFeats, (void**)&original);

        if (result == 0 && original) {
            g_orig_FeatGetFeats = (FeatGetFeats_t)original;
            g_staticdata.feat_getfeats_hook = target;
            log_message("[StaticData] Dobby hook installed successfully!");
            log_message("[StaticData]   Original function trampoline: %p", original);
            return true;
        } else {
            log_message("[StaticData] WARNING: Dobby hook installation failed (result=%d)", result);
            return false;
        }
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
    memset(g_staticdata.real_managers, 0, sizeof(g_staticdata.real_managers));

    // Try to install ARM64-safe hook for FeatManager::GetFeats
    // This uses the skip-and-redirect strategy from Issue #44
    bool hook_installed = install_feat_getfeats_safe_hook(main_binary_base);

    if (hook_installed) {
        log_message("[StaticData] FeatManager hook: ARM64 safe hook active");
    } else {
        log_message("[StaticData] FeatManager hook: Using TypeContext capture (hook not installed)");
    }

    // Install Get<T> hooks for other manager types (Dec 22, 2025)
    // These capture real manager pointers from ImmutableDataHeadmaster
    install_get_manager_hooks(main_binary_base);

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
    // Triggers capture for a specific type via TypeContext traversal
    if (type < 0 || type >= STATICDATA_COUNT) return false;

    // Try TypeContext capture if not already captured
    if (!g_staticdata.managers[type] && g_staticdata.initialized) {
        capture_managers_via_typecontext();
    }

    // NOTE: We no longer probe for real managers.
    // Dec 20, 2025: TypeContext metadata IS a GuidResourceBank with HashMap.
    // Use managers[type] directly with HashMap offsets (+0x7C count, +0x80 values).

    return staticdata_has_manager(type);
}

/**
 * Post-initialization capture attempt.
 * Call this after game data is loaded (e.g., after SessionLoaded event).
 * Attempts to capture all manager types via TypeContext traversal + probing.
 *
 * @return Number of managers successfully captured
 */
int staticdata_post_init_capture(void) {
    if (!g_staticdata.initialized) {
        log_message("[StaticData] Post-init capture skipped - not initialized");
        return 0;
    }

    log_message("[StaticData] Post-init capture starting...");
    int captured = 0;

    // 1. Try TypeContext-based capture for all manager types
    int tc_captured = capture_managers_via_typecontext();
    log_message("[StaticData] TypeContext captured %d managers", tc_captured);

    // 2. NOTE: We no longer probe for real managers from metadata.
    // Dec 20, 2025: TypeContext metadata IS a GuidResourceBank with HashMap.
    // The metadata at managers[i] can be used directly with:
    //   +0x7C = entry count (Keys.size_)
    //   +0x80 = pointer array (Values.buf_)
    //
    // real_managers[] is only set by hooks (e.g., GetFeats during character creation).

    // 3. Load any existing Frida captures as fallback
    for (int i = 0; i < STATICDATA_COUNT; i++) {
        if (!g_staticdata.real_managers[i]) {
            if (staticdata_frida_capture_available_type((StaticDataType)i)) {
                if (staticdata_load_frida_capture_type((StaticDataType)i)) {
                    log_message("[StaticData] Loaded Frida capture for %s", s_type_names[i]);
                }
            }
        }
    }

    // Count total captured managers (either metadata or real)
    for (int i = 0; i < STATICDATA_COUNT; i++) {
        if (g_staticdata.managers[i] || g_staticdata.real_managers[i]) {
            captured++;
        }
    }

    log_message("[StaticData] Post-init capture complete: %d/%d managers ready", captured, STATICDATA_COUNT);
    staticdata_dump_status();

    return captured;
}

// ============================================================================
// Data Access - FeatManager specific
// ============================================================================

/**
 * Get the effective FeatManager pointer and determine which offsets to use.
 * Prefers real_managers (has real data) over managers (metadata only).
 */
static void* get_effective_feat_manager(bool* is_real) {
    // Prefer real manager if available
    if (g_staticdata.real_managers[STATICDATA_FEAT]) {
        if (is_real) *is_real = true;
        return g_staticdata.real_managers[STATICDATA_FEAT];
    }

    // Fall back to metadata
    if (g_staticdata.managers[STATICDATA_FEAT]) {
        if (is_real) *is_real = false;
        return g_staticdata.managers[STATICDATA_FEAT];
    }

    return NULL;
}

static int feat_get_count(void) {
    bool is_real = false;
    void* mgr = get_effective_feat_manager(&is_real);
    if (!mgr) return -1;

    // Both TypeContext HashMap and Session FeatManager have count at +0x7C
    int offset = is_real ? FEATMANAGER_REAL_COUNT_OFFSET : FEATMANAGER_META_COUNT_OFFSET;

    int32_t count = 0;
    if (!safe_memory_read_i32((mach_vm_address_t)mgr + offset, &count)) {
        return -1;
    }
    return count;
}

static void* feat_get_by_index(int index) {
    bool is_real = false;
    void* mgr = get_effective_feat_manager(&is_real);
    if (!mgr) return NULL;

    // Determine offsets based on manager type
    int count_offset = is_real ? FEATMANAGER_REAL_COUNT_OFFSET : FEATMANAGER_META_COUNT_OFFSET;
    int array_offset = is_real ? FEATMANAGER_REAL_ARRAY_OFFSET : FEATMANAGER_META_VALUES_OFFSET;

    // Use safe memory reads to prevent crashes
    int32_t count = 0;
    if (!safe_memory_read_i32((mach_vm_address_t)mgr + count_offset, &count)) {
        log_message("[StaticData] Cannot read feat count at %p+0x%x", mgr, count_offset);
        return NULL;
    }
    if (index < 0 || index >= count) return NULL;

    void* array = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)mgr + array_offset, &array)) {
        log_message("[StaticData] Cannot read feat array at %p+0x%x", mgr, array_offset);
        return NULL;
    }
    if (!array) return NULL;

    void* entry = NULL;

    if (is_real) {
        // Session FeatManager: flat array of Feat structs, each FEAT_SIZE bytes
        entry = (uint8_t*)array + (index * FEAT_SIZE);
    } else {
        // TypeContext HashMap: Values.buf_ is array of POINTERS to Feat structs
        void* entry_ptr = NULL;
        if (!safe_memory_read_pointer((mach_vm_address_t)array + (index * sizeof(void*)), &entry_ptr)) {
            log_message("[StaticData] Cannot read feat pointer at index %d (array=%p)", index, array);
            return NULL;
        }
        entry = entry_ptr;
    }

    if (!entry) return NULL;

    // Verify the entry address is readable before returning
    int32_t test_read = 0;
    if (!safe_memory_read_i32((mach_vm_address_t)entry, &test_read)) {
        log_message("[StaticData] Feat entry %d at %p is not readable (array=%p, is_real=%d)",
                    index, entry, array, is_real);
        return NULL;
    }

    return entry;
}

static void* feat_get_by_guid(const StaticDataGuid* guid) {
    bool is_real = false;
    void* mgr = get_effective_feat_manager(&is_real);
    if (!mgr || !guid) return NULL;

    // Determine offsets based on manager type
    int count_offset = is_real ? FEATMANAGER_REAL_COUNT_OFFSET : FEATMANAGER_META_COUNT_OFFSET;
    int array_offset = is_real ? FEATMANAGER_REAL_ARRAY_OFFSET : FEATMANAGER_META_VALUES_OFFSET;

    int32_t count = 0;
    if (!safe_memory_read_i32((mach_vm_address_t)mgr + count_offset, &count)) {
        return NULL;
    }

    void* array = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)mgr + array_offset, &array)) {
        return NULL;
    }
    if (!array) return NULL;

    // Linear search through feats comparing GUIDs
    // GUID is at offset +0x08 in each feat (after VMT pointer)
    for (int i = 0; i < count; i++) {
        void* entry = NULL;

        if (is_real) {
            // Session FeatManager: flat array of structs
            entry = (uint8_t*)array + (i * FEAT_SIZE);
        } else {
            // TypeContext HashMap: pointer array
            if (!safe_memory_read_pointer((mach_vm_address_t)array + (i * sizeof(void*)), &entry)) {
                continue;
            }
        }

        if (!entry) continue;

        // Read and compare GUID at +0x08
        uint8_t entry_guid[16];
        bool readable = true;
        for (int j = 0; j < 16 && readable; j++) {
            if (!safe_memory_read_u8((mach_vm_address_t)entry + 0x08 + j, &entry_guid[j])) {
                readable = false;
            }
        }

        if (readable && memcmp(entry_guid, guid, sizeof(StaticDataGuid)) == 0) {
            return entry;
        }
    }

    return NULL;
}

// ============================================================================
// Data Access - Generic (config-based)
// ============================================================================

/**
 * Get effective manager pointer for a type.
 * Prefers real_managers over metadata managers.
 */
static void* get_effective_manager(StaticDataType type, bool* is_real) {
    if (type < 0 || type >= STATICDATA_COUNT) return NULL;

    // Prefer real manager if available
    if (g_staticdata.real_managers[type]) {
        if (is_real) *is_real = true;
        return g_staticdata.real_managers[type];
    }

    // Fall back to metadata
    if (g_staticdata.managers[type]) {
        if (is_real) *is_real = false;
        return g_staticdata.managers[type];
    }

    return NULL;
}

/**
 * Generic count getter using config.
 *
 * For TypeContext HashMap: count is at +0x7C (Keys.size_)
 * For Session Manager: count is at config->count_offset (typically +0x7C too)
 */
static int generic_get_count(StaticDataType type) {
    if (type < 0 || type >= STATICDATA_COUNT) return -1;

    bool is_real = false;
    void* mgr = get_effective_manager(type, &is_real);
    if (!mgr) return -1;

    const ManagerConfig* config = &g_manager_configs[type];

    // Both TypeContext and Session managers have count at +0x7C
    int offset = is_real ? config->count_offset : FEATMANAGER_META_COUNT_OFFSET;

    int32_t count = 0;
    if (!safe_memory_read_i32((mach_vm_address_t)mgr + offset, &count)) {
        return -1;
    }
    return count;
}

/**
 * Generic entry getter by index using config.
 *
 * IMPORTANT: TypeContext HashMap (is_real=false) vs Session Manager (is_real=true):
 * - TypeContext: Values.buf_ at +0x80 contains array of POINTERS to entries
 * - Session Manager: +0x80 contains flat array of entry structs
 *
 * For TypeContext, we must dereference: entry = ((void**)array)[index]
 * For Session Manager: entry = array + (index * entry_size)
 */
static void* generic_get_by_index(StaticDataType type, int index) {
    if (type < 0 || type >= STATICDATA_COUNT) return NULL;

    bool is_real = false;
    void* mgr = get_effective_manager(type, &is_real);
    if (!mgr) return NULL;

    const ManagerConfig* config = &g_manager_configs[type];

    // Determine offsets based on manager type
    int count_offset = is_real ? config->count_offset : FEATMANAGER_META_COUNT_OFFSET;
    int array_offset = is_real ? config->array_offset : FEATMANAGER_META_VALUES_OFFSET;

    // Read count
    int32_t count = 0;
    if (!safe_memory_read_i32((mach_vm_address_t)mgr + count_offset, &count)) {
        return NULL;
    }
    if (index < 0 || index >= count) return NULL;

    // Read array pointer
    void* array = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)mgr + array_offset, &array)) {
        return NULL;
    }
    if (!array) return NULL;

    void* entry = NULL;

    if (is_real) {
        // Session Manager: flat array of structs
        entry = (uint8_t*)array + (index * config->entry_size);
    } else {
        // TypeContext HashMap: array of pointers to entries
        // Each element is 8 bytes (pointer size)
        void* entry_ptr = NULL;
        if (!safe_memory_read_pointer((mach_vm_address_t)array + (index * sizeof(void*)), &entry_ptr)) {
            return NULL;
        }
        entry = entry_ptr;
    }

    if (!entry) return NULL;

    // Verify the entry address is readable
    int32_t test_read = 0;
    if (!safe_memory_read_i32((mach_vm_address_t)entry, &test_read)) {
        return NULL;
    }

    return entry;
}

/**
 * Generic GUID lookup using config.
 *
 * Handles both TypeContext HashMap (pointer array) and Session Manager (flat array).
 */
static void* generic_get_by_guid(StaticDataType type, const StaticDataGuid* guid) {
    if (type < 0 || type >= STATICDATA_COUNT || !guid) return NULL;

    bool is_real = false;
    void* mgr = get_effective_manager(type, &is_real);
    if (!mgr) return NULL;

    const ManagerConfig* config = &g_manager_configs[type];

    // Determine offsets based on manager type
    int count_offset = is_real ? config->count_offset : FEATMANAGER_META_COUNT_OFFSET;
    int array_offset = is_real ? config->array_offset : FEATMANAGER_META_VALUES_OFFSET;

    int32_t count = 0;
    if (!safe_memory_read_i32((mach_vm_address_t)mgr + count_offset, &count)) {
        return NULL;
    }

    void* array = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)mgr + array_offset, &array)) {
        return NULL;
    }
    if (!array) return NULL;

    // Linear search through entries comparing GUIDs
    // GUID is at offset +0x08 in each entry (after VMT pointer)
    for (int i = 0; i < count; i++) {
        void* entry = NULL;

        if (is_real) {
            // Session Manager: flat array of structs
            entry = (uint8_t*)array + (i * config->entry_size);
        } else {
            // TypeContext HashMap: pointer array
            if (!safe_memory_read_pointer((mach_vm_address_t)array + (i * sizeof(void*)), &entry)) {
                continue;
            }
        }

        if (!entry) continue;

        // Read and compare GUID at +0x08
        uint8_t guid_bytes[16];
        bool readable = true;
        for (int j = 0; j < 16 && readable; j++) {
            if (!safe_memory_read_u8((mach_vm_address_t)entry + 0x08 + j, &guid_bytes[j])) {
                readable = false;
            }
        }

        if (readable && memcmp(guid_bytes, guid, sizeof(StaticDataGuid)) == 0) {
            return entry;
        }
    }

    return NULL;
}

int staticdata_get_count(StaticDataType type) {
    // Use feat-specific for backwards compatibility, generic for others
    if (type == STATICDATA_FEAT) {
        return feat_get_count();
    }
    return generic_get_count(type);
}

StaticDataPtr staticdata_get_by_index(StaticDataType type, int index) {
    if (type == STATICDATA_FEAT) {
        return feat_get_by_index(index);
    }
    return generic_get_by_index(type, index);
}

StaticDataPtr staticdata_get_by_guid(StaticDataType type, const StaticDataGuid* guid) {
    if (type == STATICDATA_FEAT) {
        return feat_get_by_guid(guid);
    }
    return generic_get_by_guid(type, guid);
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

    // GUID is at +0x08 in the Feat structure (after 8-byte VMT header)
    // Different static data types may have different layouts
    int guid_offset = 0x08;  // Default: after VMT
    switch (type) {
        case STATICDATA_FEAT:
            guid_offset = 0x08;  // Verified via Ghidra
            break;
        default:
            guid_offset = 0x08;  // TODO: Verify for other types
            break;
    }

    // Use safe memory read to prevent crashes
    uint8_t guid_bytes[16];
    mach_vm_address_t guid_addr = (mach_vm_address_t)entry + guid_offset;

    // Read GUID bytes safely (16 bytes = sizeof(StaticDataGuid))
    for (int i = 0; i < 16; i++) {
        uint8_t byte = 0;
        if (!safe_memory_read_u8(guid_addr + i, &byte)) {
            log_message("[StaticData] Cannot read GUID byte %d at %p", i, (void*)(guid_addr + i));
            return false;
        }
        guid_bytes[i] = byte;
    }

    memcpy(out_guid, guid_bytes, sizeof(StaticDataGuid));
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
    if (!entry) return NULL;

    // Name offset depends on type - different layouts per GuidResource subclass
    int name_offset = 0;

    switch (type) {
        case STATICDATA_FEAT:
            name_offset = FEAT_OFFSET_NAME;  // 0x18
            break;
        case STATICDATA_RACE:
            name_offset = RACE_OFFSET_NAME;  // 0x18
            break;
        case STATICDATA_ORIGIN:
            name_offset = ORIGIN_OFFSET_NAME;  // 0x1C (after uint8_t)
            break;
        case STATICDATA_BACKGROUND:
            // Background has no FixedString Name - only TranslatedString DisplayName
            return NULL;
        case STATICDATA_GOD:
            name_offset = GOD_OFFSET_NAME;  // 0x18
            break;
        case STATICDATA_CLASS:
            name_offset = CLASS_OFFSET_NAME;  // 0x28 (after ParentGuid)
            break;
        default:
            name_offset = 0x18;  // Default assumption
            break;
    }

    if (name_offset == 0) {
        return NULL;  // Type has no Name field
    }

    // Read FixedString index safely
    uint32_t fs_index = 0;
    if (!safe_memory_read_u32((mach_vm_address_t)entry + name_offset, &fs_index)) {
        log_message("[StaticData] Cannot read name FixedString at %p+0x%x", entry, name_offset);
        return NULL;
    }

    // Check for null/invalid index
    if (fs_index == 0 || fs_index == 0xFFFFFFFF) {
        return NULL;
    }

    // Resolve via GlobalStringTable
    const char* name = fixed_string_resolve(fs_index);
    if (!name) {
        // Log once per session for debugging
        static int logged_failures = 0;
        if (logged_failures < 5) {
            log_message("[StaticData] Failed to resolve FixedString 0x%08X for %s entry at %p",
                        fs_index, staticdata_type_name(type), entry);
            logged_failures++;
        }
    }

    return name;
}

const char* staticdata_get_display_name(StaticDataType type, StaticDataPtr entry) {
    // TODO: Implement localized name lookup
    (void)type;
    (void)entry;
    return NULL;
}

// ============================================================================
// File-Based Frida Capture Integration
// ============================================================================

/**
 * Generic capture loader for any manager type.
 * File format:
 *   Line 1: Manager pointer (hex)
 *   Line 2: Count
 *   Line 3: Array pointer (hex)
 */
static bool load_captured_manager(StaticDataType type) {
    if (type < 0 || type >= STATICDATA_COUNT) return false;

    const ManagerConfig* config = &g_manager_configs[type];
    const char* capture_file = config->capture_file;

    FILE* f = fopen(capture_file, "r");
    if (!f) {
        return false;
    }

    char line1[64], line2[64], line3[64];
    if (!fgets(line1, sizeof(line1), f) ||
        !fgets(line2, sizeof(line2), f) ||
        !fgets(line3, sizeof(line3), f)) {
        fclose(f);
        return false;
    }
    fclose(f);

    // Parse pointer addresses
    void* mgr = NULL;
    int count = 0;
    void* array = NULL;

    if (sscanf(line1, "%p", &mgr) != 1 && sscanf(line1, "0x%lx", (unsigned long*)&mgr) != 1) {
        log_message("[StaticData] Failed to parse %s pointer from capture file", s_type_names[type]);
        return false;
    }
    count = atoi(line2);
    if (sscanf(line3, "%p", &array) != 1 && sscanf(line3, "0x%lx", (unsigned long*)&array) != 1) {
        log_message("[StaticData] Failed to parse %s array pointer from capture file", s_type_names[type]);
        return false;
    }

    // Validate the captured data
    if (!mgr || count <= 0 || count > 10000 || !array) {
        log_message("[StaticData] Invalid %s captured data: mgr=%p count=%d array=%p",
                    s_type_names[type], mgr, count, array);
        return false;
    }

    // Verify the pointers are still valid using type-specific offsets
    int32_t verify_count = 0;
    void* verify_array = NULL;
    if (!safe_memory_read_i32((mach_vm_address_t)mgr + config->count_offset, &verify_count) ||
        !safe_memory_read_pointer((mach_vm_address_t)mgr + config->array_offset, &verify_array)) {
        log_message("[StaticData] Captured %s pointer no longer valid (game restarted?)", s_type_names[type]);
        return false;
    }

    if (verify_count != count || verify_array != array) {
        log_message("[StaticData] Captured %s data mismatch (count=%d vs %d, array=%p vs %p)",
                    s_type_names[type], verify_count, count, verify_array, array);
        // Use the verified values instead
        count = verify_count;
        array = verify_array;
    }

    // Store as real manager
    g_staticdata.real_managers[type] = mgr;
    log_message("[StaticData] Loaded REAL %s from capture file: %p (count=%d, array=%p)",
                s_type_names[type], mgr, count, array);

    return true;
}

// Legacy wrapper for FeatManager
static bool load_captured_featmanager(void) {
    return load_captured_manager(STATICDATA_FEAT);
}

/**
 * Lua-callable function to load captured managers from Frida.
 * Call this after running the Frida capture script.
 */
bool staticdata_load_frida_capture(void) {
    const char* capture_file = g_manager_configs[STATICDATA_FEAT].capture_file;
    log_message("[StaticData] Attempting to load Frida capture from %s", capture_file);
    return load_captured_featmanager();
}

/**
 * Load captured manager pointers for a specific type.
 */
bool staticdata_load_frida_capture_type(StaticDataType type) {
    if (type < 0 || type >= STATICDATA_COUNT) {
        log_message("[StaticData] Invalid type %d for LoadFridaCapture", type);
        return false;
    }
    const char* capture_file = g_manager_configs[type].capture_file;
    log_message("[StaticData] Attempting to load %s capture from %s",
                s_type_names[type], capture_file);
    return load_captured_manager(type);
}

/**
 * Check if Frida capture is available (file exists and is recent).
 */
bool staticdata_frida_capture_available(void) {
    const char* capture_file = g_manager_configs[STATICDATA_FEAT].capture_file;
    FILE* f = fopen(capture_file, "r");
    if (f) {
        fclose(f);
        return true;
    }
    return false;
}

/**
 * Check if Frida capture is available for a specific type.
 */
bool staticdata_frida_capture_available_type(StaticDataType type) {
    if (type < 0 || type >= STATICDATA_COUNT) {
        return false;
    }
    const char* capture_file = g_manager_configs[type].capture_file;
    FILE* f = fopen(capture_file, "r");
    if (f) {
        fclose(f);
        return true;
    }
    return false;
}

// ============================================================================
// Debugging
// ============================================================================

void staticdata_try_typecontext_capture(void) {
    log_message("[StaticData] Attempting TypeContext capture...");
    int captured = capture_managers_via_typecontext();
    log_message("[StaticData] Captured %d managers via TypeContext", captured);

    // Also try to load Frida capture if available
    if (staticdata_frida_capture_available()) {
        load_captured_featmanager();
    }
}

void staticdata_dump_status(void) {
    log_message("[StaticData] Manager Status:");
    log_message("  Initialized: %s", g_staticdata.initialized ? "yes" : "no");
    log_message("  Base: %p", g_staticdata.main_binary_base);

    for (int i = 0; i < STATICDATA_COUNT; i++) {
        void* meta = g_staticdata.managers[i];
        void* real = g_staticdata.real_managers[i];

        if (real) {
            // Session manager (from hook) - flat array
            int32_t count = 0;
            void* array = NULL;
            safe_memory_read_i32((mach_vm_address_t)real + FEATMANAGER_REAL_COUNT_OFFSET, &count);
            safe_memory_read_pointer((mach_vm_address_t)real + FEATMANAGER_REAL_ARRAY_OFFSET, &array);
            log_message("  %s: SESSION %p (count=%d, flat_array=%p) [metadata=%p]",
                        s_type_names[i], real, count, array, meta);
        } else if (meta) {
            // TypeContext HashMap - pointer array (Dec 20, 2025 fix)
            int32_t count = 0;
            void* values = NULL;
            safe_memory_read_i32((mach_vm_address_t)meta + FEATMANAGER_META_COUNT_OFFSET, &count);
            safe_memory_read_pointer((mach_vm_address_t)meta + FEATMANAGER_META_VALUES_OFFSET, &values);
            log_message("  %s: HASHMAP %p (count=%d, ptr_array=%p)",
                        s_type_names[i], meta, count, values);
        } else {
            log_message("  %s: not captured", s_type_names[i]);
        }
    }
}

bool staticdata_get_raw_info(StaticDataType type, StaticDataRawInfo* out) {
    if (!out || type < 0 || type >= STATICDATA_COUNT) {
        return false;
    }

    memset(out, 0, sizeof(*out));

    void* meta = g_staticdata.managers[type];
    void* real = g_staticdata.real_managers[type];

    if (real) {
        out->manager_ptr = (uintptr_t)real;
        out->is_session = true;
        safe_memory_read_i32((mach_vm_address_t)real + FEATMANAGER_REAL_COUNT_OFFSET, &out->count);
        safe_memory_read_pointer((mach_vm_address_t)real + FEATMANAGER_REAL_ARRAY_OFFSET, (void**)&out->array_ptr);
        out->count_offset = FEATMANAGER_REAL_COUNT_OFFSET;
        out->array_offset = FEATMANAGER_REAL_ARRAY_OFFSET;
        return true;
    } else if (meta) {
        out->manager_ptr = (uintptr_t)meta;
        out->is_session = false;
        safe_memory_read_i32((mach_vm_address_t)meta + FEATMANAGER_META_COUNT_OFFSET, &out->count);
        safe_memory_read_pointer((mach_vm_address_t)meta + FEATMANAGER_META_VALUES_OFFSET, (void**)&out->array_ptr);
        out->count_offset = FEATMANAGER_META_COUNT_OFFSET;
        out->array_offset = FEATMANAGER_META_VALUES_OFFSET;
        return true;
    }

    return false;
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

/**
 * Diagnostic: Dump the first few entries of the feat array to understand memory layout.
 */
void staticdata_dump_feat_memory(void) {
    void* mgr = g_staticdata.real_managers[STATICDATA_FEAT];
    if (!mgr) {
        log_message("[StaticData] No real FeatManager captured for memory dump");
        return;
    }

    int32_t count = 0;
    void* array = NULL;

    if (!safe_memory_read_i32((mach_vm_address_t)mgr + FEATMANAGER_REAL_COUNT_OFFSET, &count)) {
        log_message("[StaticData] Cannot read count for memory dump");
        return;
    }
    if (!safe_memory_read_pointer((mach_vm_address_t)mgr + FEATMANAGER_REAL_ARRAY_OFFSET, &array)) {
        log_message("[StaticData] Cannot read array pointer for memory dump");
        return;
    }

    log_message("[StaticData] MEMORY DUMP: mgr=%p, count=%d, array=%p", mgr, count, array);
    log_message("[StaticData] FEAT_SIZE=%d (0x%X), expected array range: %p - %p",
                FEAT_SIZE, FEAT_SIZE, array, (uint8_t*)array + (count * FEAT_SIZE));

    // Check if array pointer itself is readable
    int32_t test = 0;
    if (!safe_memory_read_i32((mach_vm_address_t)array, &test)) {
        log_message("[StaticData] ARRAY BASE IS NOT READABLE at %p!", array);
        return;
    }

    // Dump first 64 bytes of array base
    log_message("[StaticData] First 64 bytes at array base %p:", array);
    for (int row = 0; row < 4; row++) {
        char hex[128] = {0};
        char* p = hex;
        for (int col = 0; col < 16; col++) {
            uint8_t byte = 0;
            mach_vm_address_t addr = (mach_vm_address_t)array + (row * 16) + col;
            if (safe_memory_read_u8(addr, &byte)) {
                p += sprintf(p, "%02X ", byte);
            } else {
                p += sprintf(p, "?? ");
            }
        }
        log_message("  +0x%02X: %s", row * 16, hex);
    }

    // Try to dump first 3 "entries" at different sizes to help identify structure
    log_message("[StaticData] Testing different entry sizes:");
    int test_sizes[] = {8, 16, 32, 64, 128, 256, FEAT_SIZE};
    for (int s = 0; s < sizeof(test_sizes)/sizeof(test_sizes[0]); s++) {
        int size = test_sizes[s];
        log_message("  Entry size=%d:", size);

        for (int i = 0; i < 3 && i < count; i++) {
            void* entry = (uint8_t*)array + (i * size);
            uint64_t val = 0;
            if (safe_memory_read_u64((mach_vm_address_t)entry, &val)) {
                log_message("    [%d] %p: first8=0x%016llx", i, entry, (unsigned long long)val);
            } else {
                log_message("    [%d] %p: UNREADABLE", i, entry);
            }
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
