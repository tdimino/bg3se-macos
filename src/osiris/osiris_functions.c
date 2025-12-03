/**
 * BG3SE-macOS - Osiris Function Cache Implementation
 */

#include "osiris_functions.h"
#include "logging.h"
#include "safe_memory.h"

#include <string.h>
#include <stdint.h>

// ============================================================================
// Internal State
// ============================================================================

// Function cache
static CachedFunction g_funcCache[MAX_CACHED_FUNCTIONS];
static int g_funcCacheCount = 0;

// Hash table for fast ID lookup (-1 = empty, else index into g_funcCache)
static int16_t g_funcIdHashTable[FUNC_HASH_SIZE];

// Tracked function IDs (for analysis)
static uint32_t g_seenFuncIds[MAX_SEEN_FUNC_IDS];
static uint8_t g_seenFuncArities[MAX_SEEN_FUNC_IDS];
static int g_seenFuncIdCount = 0;

// Runtime pointers (set by caller)
static pFunctionDataFn s_pfn_pFunctionData = NULL;
static void **s_ppOsiFunctionMan = NULL;

// Known events table (set by caller)
static KnownEvent *s_knownEvents = NULL;

// ============================================================================
// Internal Helpers
// ============================================================================

/**
 * Hash function for function ID lookup
 */
static inline int func_id_hash(uint32_t funcId) {
    // Simple hash - use lower bits, handling type flag
    return (int)((funcId ^ (funcId >> 13)) & (FUNC_HASH_SIZE - 1));
}

/**
 * Check if a pointer looks like it points to valid string data.
 * Must be in a reasonable address range for user-space memory.
 */
static int is_valid_string_ptr(void *ptr) {
    if (!ptr) return 0;
    uintptr_t addr = (uintptr_t)ptr;
    // Valid user-space addresses on macOS ARM64 are typically 0x100000000 - 0x7FFFFFFFFFFF
    return addr > 0x100000000ULL && addr < 0x800000000000ULL;
}

/**
 * Check if a character is a valid start for a function name.
 * Osiris function names start with uppercase letters, underscores, or 'PROC_'/'QRY_'/etc.
 */
static int is_valid_name_start(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

/**
 * Try to extract function name from a function definition pointer.
 * Uses safe memory APIs to prevent SIGBUS crashes on invalid pointers.
 *
 * Based on Ghidra analysis of macOS ARM64 libOsiris.dylib COsiFunctionDef:
 *
 * struct COsiFunctionDef {
 *     void* vtable;                  // 0x00: vtable pointer (PTR__COsiFunctionDef_00090568)
 *     char* Name;                    // 0x08: DIRECTLY STORES THE NAME STRING
 *     COsiValueTypeList* ParamList;  // 0x10: parameter type list
 *     void* ParamData;               // 0x18: parameter data array
 *     uint32_t ParamCount;           // 0x20: number of parameters
 * };
 *
 * The constructor copies the name string directly to offset 0x08:
 *   *(void **)(this + 8) = pvVar3;  // pvVar3 is allocated string copy
 *   _memcpy(pvVar3, param_1, sVar2);
 *
 * So: funcDef->Name = *(char **)(funcDef + 8)
 */

/* Thread-local buffer for extracted function names */
static __thread char s_extractedName[128];

/* Diagnostic counter for extract_func_name */
static int s_extractDiagCount = 0;
#define MAX_EXTRACT_DIAG 20

static const char *extract_func_name_from_def(void *funcDef) {
    if (!funcDef) return NULL;

    mach_vm_address_t funcDefAddr = (mach_vm_address_t)funcDef;
    bool shouldLog = (s_extractDiagCount < MAX_EXTRACT_DIAG);

    /* Skip GPU carveout region - these cause SIGBUS even if mapped */
    if (safe_memory_is_gpu_region(funcDefAddr)) {
        if (shouldLog) {
            log_message("[ExtractName] funcDef 0x%llx: GPU region", (unsigned long long)funcDefAddr);
            s_extractDiagCount++;
        }
        return NULL;
    }

    /* SIMPLIFIED: Skip pre-validation, just try to read directly.
     * mach_vm_read_overwrite will fail safely if address is invalid.
     * This avoids issues with mach_vm_region not returning expected regions. */

    /* Read the name pointer at offset 0x08 */
    void *namePtr = NULL;
    if (!safe_memory_read_pointer(funcDefAddr + 8, &namePtr)) {
        if (shouldLog) {
            log_message("[ExtractName] funcDef 0x%llx: failed to read namePtr at +8", (unsigned long long)funcDefAddr);
            s_extractDiagCount++;
        }
        return NULL;
    }

    /* Validate the name pointer address */
    mach_vm_address_t nameAddr = (mach_vm_address_t)namePtr;
    if (!is_valid_string_ptr(namePtr)) {
        if (shouldLog) {
            log_message("[ExtractName] funcDef 0x%llx: namePtr 0x%llx not valid string ptr",
                       (unsigned long long)funcDefAddr, (unsigned long long)nameAddr);
            s_extractDiagCount++;
        }
        return NULL;
    }

    /* Skip GPU region for name pointer too */
    if (safe_memory_is_gpu_region(nameAddr)) {
        if (shouldLog) {
            log_message("[ExtractName] funcDef 0x%llx: namePtr 0x%llx in GPU region",
                       (unsigned long long)funcDefAddr, (unsigned long long)nameAddr);
            s_extractDiagCount++;
        }
        return NULL;
    }

    /* Safely read the name string */
    if (!safe_memory_read_string(nameAddr, s_extractedName, sizeof(s_extractedName))) {
        return NULL;
    }

    /* Validate the extracted name format */
    if (!is_valid_name_start(s_extractedName[0])) {
        return NULL;
    }

    /* Validate all characters in the name */
    for (int j = 0; j < 64 && s_extractedName[j]; j++) {
        char c = s_extractedName[j];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_')) {
            return NULL;
        }
    }

    return s_extractedName;
}

// ============================================================================
// Initialization
// ============================================================================

void osi_func_cache_init(void) {
    // Initialize hash table
    for (int i = 0; i < FUNC_HASH_SIZE; i++) {
        g_funcIdHashTable[i] = -1;
    }
    g_funcCacheCount = 0;
    g_seenFuncIdCount = 0;
}

void osi_func_cache_set_runtime(pFunctionDataFn pFunctionData, void **ppOsiFunctionMan) {
    s_pfn_pFunctionData = pFunctionData;
    s_ppOsiFunctionMan = ppOsiFunctionMan;
}

void osi_func_cache_set_known_events(KnownEvent *events) {
    s_knownEvents = events;
}

// ============================================================================
// Caching
// ============================================================================

void osi_func_cache(const char *name, uint32_t funcId, uint8_t arity, uint8_t type) {
    if (g_funcCacheCount >= MAX_CACHED_FUNCTIONS) {
        return;
    }

    // Check for duplicate
    int hash = func_id_hash(funcId);
    if (g_funcIdHashTable[hash] >= 0) {
        // Linear probe to check if already exists
        for (int i = 0; i < g_funcCacheCount; i++) {
            if (g_funcCache[i].id == funcId) {
                return;  // Already cached
            }
        }
    }

    CachedFunction *cf = &g_funcCache[g_funcCacheCount];
    strncpy(cf->name, name, sizeof(cf->name) - 1);
    cf->name[sizeof(cf->name) - 1] = '\0';
    cf->id = funcId;
    cf->arity = arity;
    cf->type = type;

    // Add to hash table (simple - just store first match at hash location)
    if (g_funcIdHashTable[hash] < 0) {
        g_funcIdHashTable[hash] = (int16_t)g_funcCacheCount;
    }

    g_funcCacheCount++;
}

// Diagnostic counter to limit verbose logging
static int s_diagLogCount = 0;
static const int MAX_DIAG_LOGS = 20;

int osi_func_cache_by_id(uint32_t funcId) {
    /* Need both the function pointer and the manager instance */
    if (!s_pfn_pFunctionData || !s_ppOsiFunctionMan) {
        return 0;
    }

    /* Safely read the OsiFunctionMan pointer */
    void *funcMan = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)s_ppOsiFunctionMan, &funcMan)) {
        if (s_diagLogCount < MAX_DIAG_LOGS) {
            log_message("[FuncCache] Failed to read OsiFunctionMan pointer");
            s_diagLogCount++;
        }
        return 0;
    }

    if (!funcMan) {
        return 0;
    }

    /* Call pFunctionData to get function definition */
    void *funcDef = s_pfn_pFunctionData(funcMan, funcId);

    /* Log first few attempts to see what pFunctionData returns */
    if (s_diagLogCount < MAX_DIAG_LOGS) {
        log_message("[FuncCache] Query funcId=0x%08x: funcMan=%p, funcDef=%p", funcId, funcMan, funcDef);
        s_diagLogCount++;
    }

    if (funcDef) {
        /* extract_func_name_from_def now uses safe memory APIs */
        const char *name = extract_func_name_from_def(funcDef);
        if (name && name[0]) {
            /* Safely read arity from offset 0x20 (ParamCount from Ghidra analysis) */
            uint32_t paramCount = 0;
            if (!safe_memory_read_u32((mach_vm_address_t)funcDef + 0x20, &paramCount)) {
                paramCount = 0;
            }
            uint8_t arity = (paramCount <= 20) ? (uint8_t)paramCount : 0;

            /* Type is not directly in this struct - default to 0 (unknown) */
            uint8_t type = 0;

            /* Log success for first few */
            if (s_diagLogCount < MAX_DIAG_LOGS) {
                log_message("[FuncCache] SUCCESS: funcId=0x%08x -> '%s' (arity=%d)",
                           funcId, name, arity);
                s_diagLogCount++;
            }

            osi_func_cache(name, funcId, arity, type);
            return 1;
        } else if (s_diagLogCount < MAX_DIAG_LOGS) {
            /* Log failure - but don't try to dump memory unsafely */
            log_message("[FuncCache] Failed to extract name for funcId=0x%08x, funcDef=%p (memory inaccessible or invalid)", funcId, funcDef);
            s_diagLogCount++;
        }
    }

    return 0;
}

void osi_func_cache_from_event(uint32_t funcId) {
    /* Skip if already cached */
    if (osi_func_get_name(funcId) != NULL) {
        return;
    }

    /* Try to get the function definition using safe memory APIs
     * The extract_func_name_from_def and osi_func_cache_by_id functions
     * now use mach_vm_read for safe memory access */
    osi_func_cache_by_id(funcId);
}

// ============================================================================
// Enumeration
// ============================================================================

void osi_func_enumerate(void) {
    if (!s_pfn_pFunctionData || !s_ppOsiFunctionMan || !*s_ppOsiFunctionMan) {
        log_message("[FuncEnum] Cannot enumerate - pFunctionData or OsiFunctionMan not available");
        return;
    }

    log_message("[FuncEnum] Starting function enumeration...");
    int found_count = 0;

    // Osiris function IDs are split into two ranges:
    // 1. Regular functions: 0 to ~64K (low IDs)
    // 2. Registered functions: 0x80000000 + offset (high bit set)

    // Probe low range (regular functions) - usually 0-10000
    for (uint32_t id = 1; id < 10000 && found_count < 1000; id++) {
        if (osi_func_cache_by_id(id)) {
            found_count++;
        }
    }

    // Probe high range (registered functions) - 0x80000000 + 0 to ~30000
    for (uint32_t offset = 0; offset < 30000 && found_count < 2000; offset++) {
        uint32_t id = 0x80000000 | offset;
        if (osi_func_cache_by_id(id)) {
            found_count++;
        }
    }

    log_message("[FuncEnum] Enumeration complete: %d functions cached", found_count);

    // Log some key functions we're looking for
    const char *key_funcs[] = {
        "QRY_IsTagged", "IsTagged", "GetDistanceTo", "QRY_GetDistance",
        "DialogRequestStop", "QRY_StartDialog_Fixed", "StartDialog",
        "DB_Players", "CharacterGetDisplayName", NULL
    };

    log_message("[FuncEnum] Checking key functions:");
    for (int i = 0; key_funcs[i]; i++) {
        uint32_t fid = osi_func_lookup_id(key_funcs[i]);
        if (fid != INVALID_FUNCTION_ID) {
            log_message("  %s -> 0x%08x", key_funcs[i], fid);
        }
    }
}

// ============================================================================
// Lookup
// ============================================================================

const char *osi_func_get_name(uint32_t funcId) {
    // Check known events table first (hardcoded mappings)
    if (s_knownEvents) {
        for (int i = 0; s_knownEvents[i].name != NULL; i++) {
            if (s_knownEvents[i].funcId == funcId) {
                return s_knownEvents[i].name;
            }
        }
    }

    // Check hash table (fast path for dynamic cache)
    int hash = func_id_hash(funcId);
    int16_t idx = g_funcIdHashTable[hash];
    if (idx >= 0 && g_funcCache[idx].id == funcId) {
        return g_funcCache[idx].name;
    }

    // Linear search (for hash collisions)
    for (int i = 0; i < g_funcCacheCount; i++) {
        if (g_funcCache[i].id == funcId) {
            return g_funcCache[i].name;
        }
    }

    return NULL;
}

uint32_t osi_func_lookup_id(const char *name) {
    if (!name) return INVALID_FUNCTION_ID;

    // Check known events first (fast path for common names)
    if (s_knownEvents) {
        for (int i = 0; s_knownEvents[i].name != NULL; i++) {
            if (strcmp(s_knownEvents[i].name, name) == 0 && s_knownEvents[i].funcId != 0) {
                return s_knownEvents[i].funcId;
            }
        }
    }

    // Search dynamic cache
    for (int i = 0; i < g_funcCacheCount; i++) {
        if (strcmp(g_funcCache[i].name, name) == 0) {
            return g_funcCache[i].id;
        }
    }

    return INVALID_FUNCTION_ID;
}

int osi_func_get_info(const char *name, uint8_t *out_arity, uint8_t *out_type) {
    if (!name) return 0;

    // Check known functions table first (includes events, queries, calls)
    if (s_knownEvents) {
        for (int i = 0; s_knownEvents[i].name != NULL; i++) {
            if (strcmp(s_knownEvents[i].name, name) == 0) {
                if (out_arity) *out_arity = s_knownEvents[i].expectedArity;
                if (out_type) *out_type = s_knownEvents[i].funcType;
                return 1;
            }
        }
    }

    // Search dynamic cache
    for (int i = 0; i < g_funcCacheCount; i++) {
        if (strcmp(g_funcCache[i].name, name) == 0) {
            if (out_arity) *out_arity = g_funcCache[i].arity;
            if (out_type) *out_type = g_funcCache[i].type;
            return 1;
        }
    }

    return 0;
}

void osi_func_update_known_event_id(const char *name, uint32_t funcId) {
    if (!name || funcId == 0) return;

    // Find matching entry with funcId=0 (placeholder) and update it
    if (s_knownEvents) {
        for (int i = 0; s_knownEvents[i].name != NULL; i++) {
            if (strcmp(s_knownEvents[i].name, name) == 0 &&
                s_knownEvents[i].funcId == 0) {
                // Update the placeholder with the discovered ID
                s_knownEvents[i].funcId = funcId;
                log_message("[Osiris] Discovered event ID: %s = 0x%x", name, funcId);
                return;
            }
        }
    }
}

// ============================================================================
// Statistics
// ============================================================================

int osi_func_get_cache_count(void) {
    return g_funcCacheCount;
}

void osi_func_track_seen(uint32_t funcId, uint8_t arity) {
    // Check if already seen
    for (int i = 0; i < g_seenFuncIdCount; i++) {
        if (g_seenFuncIds[i] == funcId) return;
    }

    // Add to list
    if (g_seenFuncIdCount < MAX_SEEN_FUNC_IDS) {
        g_seenFuncIds[g_seenFuncIdCount] = funcId;
        g_seenFuncArities[g_seenFuncIdCount] = arity;
        g_seenFuncIdCount++;

        // Log new unique function ID
        log_message("[FuncID] New unique: id=%u (0x%08x), arity=%d, total_unique=%d",
                   funcId, funcId, arity, g_seenFuncIdCount);
    }
}

int osi_func_get_seen_count(void) {
    return g_seenFuncIdCount;
}
