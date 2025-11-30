/**
 * BG3SE-macOS - Osiris Function Cache Implementation
 */

#include "osiris_functions.h"
#include "logging.h"

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
 * Try to extract function name from a function definition pointer.
 * The structure layout is empirically determined.
 */
static const char *extract_func_name_from_def(void *funcDef) {
    if (!funcDef) return NULL;

    // The function definition structure varies by Osiris version
    // We'll try multiple offsets to find the name
    uint8_t *p = (uint8_t *)funcDef;

    // Try offset 8 (common for std::string* or char*)
    void *name_candidate = *(void **)(p + 8);
    if (name_candidate) {
        // Check if it's a direct char* (starts with printable ASCII)
        char *str = (char *)name_candidate;
        if (str[0] >= 'A' && str[0] <= 'z') {
            return str;
        }

        // It might be std::string (SSO or heap)
        // For small strings, data is inline at offset 0
        // For large strings, there's a pointer
        // Try reading as std::string internal layout
        char *sso_data = (char *)name_candidate;
        if (sso_data[0] >= 'A' && sso_data[0] <= 'z') {
            return sso_data;
        }
    }

    // Try offset 16
    name_candidate = *(void **)(p + 16);
    if (name_candidate) {
        char *str = (char *)name_candidate;
        if (str[0] >= 'A' && str[0] <= 'z') {
            return str;
        }
    }

    return NULL;
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

int osi_func_cache_by_id(uint32_t funcId) {
    // Need both the function pointer and the manager instance
    if (!s_pfn_pFunctionData || !s_ppOsiFunctionMan || !*s_ppOsiFunctionMan) {
        return 0;
    }

    void *funcMan = *s_ppOsiFunctionMan;
    void *funcDef = s_pfn_pFunctionData(funcMan, funcId);

    if (funcDef) {
        const char *name = extract_func_name_from_def(funcDef);
        if (name && name[0]) {
            // Determine arity from structure (offset 21 based on OsiFunctionDef)
            uint8_t *p = (uint8_t *)funcDef;
            uint8_t arity = p[21];  // numInParams
            uint8_t type = p[20];   // funcType

            osi_func_cache(name, funcId, arity, type);
            return 1;
        }
    }

    return 0;
}

void osi_func_cache_from_event(uint32_t funcId) {
    // Skip if already cached
    if (osi_func_get_name(funcId) != NULL) {
        return;
    }

    // Try to get the function definition
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
