/**
 * BG3SE-macOS - Osiris Function Cache Implementation
 */

#include "osiris_functions.h"
#include "logging.h"
#include "safe_memory.h"

#include <stdio.h>
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

// Hash table for fast name lookup (-1 = empty, else index into g_funcCache)
static int16_t g_funcNameHashTable[FUNC_NAME_HASH_SIZE];

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
 * Hash function for function name lookup (djb2 variant)
 */
static inline int func_name_hash(const char *name) {
    uint32_t h = 5381;
    for (int i = 0; name[i] && i < 64; i++) {
        h = ((h << 5) + h) + (uint8_t)name[i];
    }
    return (int)((h ^ (h >> 13)) & (FUNC_NAME_HASH_SIZE - 1));
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
 * Structure layout based on Windows BG3SE Osiris.h (lines 902-918) with
 * ARM64 8-byte alignment adjustments:
 *
 * struct OsiFunctionDef {
 *     void* VMT;                     // 0x00: Virtual method table (8 bytes)
 *     uint32_t Line;                 // 0x08: Source line number (4 bytes)
 *     uint32_t Unknown1;             // 0x0C: (4 bytes)
 *     uint32_t Unknown2;             // 0x10: (4 bytes)
 *     uint32_t _padding;             // 0x14: Alignment padding (4 bytes)
 *     FunctionSignature* Signature;  // 0x18: Pointer to signature struct (8 bytes)
 *     // ... more fields
 * };
 *
 * struct FunctionSignature {
 *     void* VMT;                     // 0x00: Virtual method table (8 bytes)
 *     const char* Name;              // 0x08: Function name string pointer
 *     // ... more fields
 * };
 *
 * To get the name: funcDef->Signature->Name
 *   1. Read Signature* at funcDef + 0x18
 *   2. Read Name* at Signature + 0x08
 *   3. Read string at Name
 *
 * IMPORTANT: Previous documentation incorrectly stated Name was at +0x08.
 * The value at +0x08 is actually Line (e.g., 0x4a8 = 1192 decimal).
 */

/* OsiFunctionDef field offsets (ARM64 macOS, 8-byte aligned) */
#define OSIFUNCDEF_VMT_OFFSET        0x00
#define OSIFUNCDEF_LINE_OFFSET       0x08  /* uint32_t Line (NOT a name pointer!) */
#define OSIFUNCDEF_SIGNATURE_OFFSET  0x18  /* FunctionSignature* */

/* FunctionSignature field offsets (from Windows Osiris.h FunctionSignature struct) */
#define FUNCSIG_VMT_OFFSET           0x00
#define FUNCSIG_NAME_OFFSET          0x08  /* const char* Name */
#define FUNCSIG_PARAMS_OFFSET        0x10  /* FunctionParamList* Params */
#define FUNCSIG_OUTPARAMLIST_OFFSET  0x18  /* FuncSigOutParamList.Params* (bitmask) */
#define FUNCSIG_OUTPARAMCOUNT_OFFSET 0x20  /* FuncSigOutParamList.Count (uint32_t) */

/* FunctionParamList field offsets */
#define PARAMLIST_VMT_OFFSET         0x00
#define PARAMLIST_HEAD_OFFSET        0x08  /* List<FunctionParamDesc>.Head* */
#define PARAMLIST_SIZE_OFFSET        0x10  /* List<FunctionParamDesc>.Size (uint32_t, total in+out) */

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
            LOG_OSIRIS_DEBUG("funcDef 0x%llx: GPU region", (unsigned long long)funcDefAddr);
            s_extractDiagCount++;
        }
        return NULL;
    }

    /*
     * Two-level indirection: funcDef->Signature->Name
     *
     * Step 1: Read FunctionSignature* from funcDef + OSIFUNCDEF_SIGNATURE_OFFSET (0x18)
     * Step 2: Read const char* Name from Signature + FUNCSIG_NAME_OFFSET (0x08)
     * Step 3: Read the actual string from Name pointer
     *
     * NOTE: The old code incorrectly read offset +0x08 which contains Line (uint32_t),
     * not a name pointer. That's why we saw values like 0x4a8 (1192 = line number).
     */

    /* Step 1: Read Signature pointer at offset 0x18 */
    void *signaturePtr = NULL;
    if (!safe_memory_read_pointer(funcDefAddr + OSIFUNCDEF_SIGNATURE_OFFSET, &signaturePtr)) {
        if (shouldLog) {
            LOG_OSIRIS_DEBUG("funcDef 0x%llx: failed to read Signature at +0x%x",
                       (unsigned long long)funcDefAddr, OSIFUNCDEF_SIGNATURE_OFFSET);
            s_extractDiagCount++;
        }
        return NULL;
    }

    /* Validate Signature pointer */
    mach_vm_address_t sigAddr = (mach_vm_address_t)signaturePtr;
    if (!is_valid_string_ptr(signaturePtr)) {  /* Reuse pointer validation */
        if (shouldLog) {
            LOG_OSIRIS_DEBUG("funcDef 0x%llx: Signature 0x%llx invalid",
                       (unsigned long long)funcDefAddr, (unsigned long long)sigAddr);
            s_extractDiagCount++;
        }
        return NULL;
    }

    /* Skip GPU region for Signature pointer */
    if (safe_memory_is_gpu_region(sigAddr)) {
        if (shouldLog) {
            LOG_OSIRIS_DEBUG("funcDef 0x%llx: Signature 0x%llx in GPU region",
                       (unsigned long long)funcDefAddr, (unsigned long long)sigAddr);
            s_extractDiagCount++;
        }
        return NULL;
    }

    /* Step 2: Read Name pointer from Signature + 0x08 */
    void *namePtr = NULL;
    if (!safe_memory_read_pointer(sigAddr + FUNCSIG_NAME_OFFSET, &namePtr)) {
        if (shouldLog) {
            LOG_OSIRIS_DEBUG("Signature 0x%llx: failed to read Name at +0x%x",
                       (unsigned long long)sigAddr, FUNCSIG_NAME_OFFSET);
            s_extractDiagCount++;
        }
        return NULL;
    }

    /* Validate the Name pointer address */
    mach_vm_address_t nameAddr = (mach_vm_address_t)namePtr;
    if (!is_valid_string_ptr(namePtr)) {
        if (shouldLog) {
            LOG_OSIRIS_DEBUG("Signature 0x%llx: Name 0x%llx not valid",
                       (unsigned long long)sigAddr, (unsigned long long)nameAddr);
            s_extractDiagCount++;
        }
        return NULL;
    }

    /* Skip GPU region for Name pointer too */
    if (safe_memory_is_gpu_region(nameAddr)) {
        if (shouldLog) {
            LOG_OSIRIS_DEBUG("Signature 0x%llx: Name 0x%llx in GPU region",
                       (unsigned long long)sigAddr, (unsigned long long)nameAddr);
            s_extractDiagCount++;
        }
        return NULL;
    }

    /* Step 3: Safely read the name string */
    if (!safe_memory_read_string(nameAddr, s_extractedName, sizeof(s_extractedName))) {
        if (shouldLog) {
            LOG_OSIRIS_DEBUG("Name 0x%llx: failed to read string",
                       (unsigned long long)nameAddr);
            s_extractDiagCount++;
        }
        return NULL;
    }

    /* Validate the extracted name format */
    if (!is_valid_name_start(s_extractedName[0])) {
        if (shouldLog) {
            LOG_OSIRIS_DEBUG("Name 0x%llx: invalid start char 0x%02x",
                       (unsigned long long)nameAddr, (unsigned char)s_extractedName[0]);
            s_extractDiagCount++;
        }
        return NULL;
    }

    /* Validate all characters in the name */
    for (int j = 0; j < 64 && s_extractedName[j]; j++) {
        char c = s_extractedName[j];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_')) {
            if (shouldLog) {
                LOG_OSIRIS_DEBUG("Name '%.*s': invalid char 0x%02x at pos %d",
                           j, s_extractedName, (unsigned char)c, j);
                s_extractDiagCount++;
            }
            return NULL;
        }
    }

    /* Success! Log first few successful extractions for verification */
    if (shouldLog) {
        LOG_OSIRIS_DEBUG("SUCCESS: funcDef 0x%llx -> Sig 0x%llx -> Name '%s'",
                   (unsigned long long)funcDefAddr, (unsigned long long)sigAddr, s_extractedName);
        s_extractDiagCount++;
    }

    return s_extractedName;
}

// ============================================================================
// Initialization
// ============================================================================

void osi_func_cache_init(void) {
    // Initialize hash tables
    for (int i = 0; i < FUNC_HASH_SIZE; i++) {
        g_funcIdHashTable[i] = -1;
    }
    for (int i = 0; i < FUNC_NAME_HASH_SIZE; i++) {
        g_funcNameHashTable[i] = -1;
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
    cf->handle = 0;

    // Add to ID hash table (simple - just store first match at hash location)
    if (g_funcIdHashTable[hash] < 0) {
        g_funcIdHashTable[hash] = (int16_t)g_funcCacheCount;
    }

    // Add to name hash table for O(1) name→index lookups
    int nameHash = func_name_hash(cf->name);
    if (g_funcNameHashTable[nameHash] < 0) {
        g_funcNameHashTable[nameHash] = (int16_t)g_funcCacheCount;
    }

    g_funcCacheCount++;
}

void osi_func_cache_set_handle(uint32_t funcId, uint32_t handle) {
    for (int i = 0; i < g_funcCacheCount; i++) {
        if (g_funcCache[i].id == funcId) {
            g_funcCache[i].handle = handle;
            return;
        }
    }
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
            LOG_OSIRIS_DEBUG("Failed to read OsiFunctionMan pointer");
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
        LOG_OSIRIS_DEBUG("Query funcId=0x%08x: funcMan=%p, funcDef=%p", funcId, funcMan, funcDef);
        s_diagLogCount++;
    }

    if (funcDef) {
        /* extract_func_name_from_def now uses safe memory APIs */
        const char *name = extract_func_name_from_def(funcDef);
        if (name && name[0]) {
            /* Read total param count (in+out) via pointer chain:
             * funcDef+0x18 → Signature → Signature+0x10 → ParamList* → ParamList+0x10 → Size
             * This gives Params.Size which includes both input AND output params.
             * Windows BG3SE uses this for query dispatch (Function.inl:OsiQuery). */
            uint8_t arity = 0;
            {
                /* We already know funcDef+0x18 → Signature works (name extraction uses it).
                 * Re-read Signature pointer for the param chain. */
                void *sigPtr = NULL;
                if (safe_memory_read_pointer((mach_vm_address_t)funcDef + OSIFUNCDEF_SIGNATURE_OFFSET, &sigPtr) && sigPtr) {
                    void *paramListPtr = NULL;
                    if (safe_memory_read_pointer((mach_vm_address_t)sigPtr + FUNCSIG_PARAMS_OFFSET, &paramListPtr) && paramListPtr) {
                        uint32_t paramSize = 0;
                        if (safe_memory_read_u32((mach_vm_address_t)paramListPtr + PARAMLIST_SIZE_OFFSET, &paramSize)) {
                            arity = (paramSize <= 20) ? (uint8_t)paramSize : 0;
                        }
                    }
                }
            }

            /* Read FunctionType from funcDef + 0x28 (Windows layout: Osiris.h)
             * Validated by safe_memory_read — same pattern as paramCount above.
             * Fallback: guess from name prefix (QRY_=Query, DB_=Database, etc.) */
            uint32_t rawType = 0;
            uint8_t type = osi_func_guess_type(name);  // Smart fallback from name prefix
            if (safe_memory_read_u32((mach_vm_address_t)funcDef + 0x28, &rawType)) {
                if (rawType == OSI_FUNC_UNKNOWN) {
                    LOG_OSIRIS_DEBUG("funcId=0x%08x '%s': type=UNKNOWN at +0x28, using guess=%s",
                                    funcId, name, osi_func_type_str(type));
                } else if (rawType >= OSI_FUNC_EVENT && rawType <= OSI_FUNC_USERQUERY) {
                    type = (uint8_t)rawType;
                } else {
                    LOG_OSIRIS_DEBUG("funcId=0x%08x '%s': invalid type %u at +0x28, using guess=%s",
                                    funcId, name, rawType, osi_func_type_str(type));
                }
            }

            /* Read Key[4] from funcDef + 0x28 to compute the real handle.
             * Key[0]=type, Key[1]=Part2, Key[2]=funcIndex, Key[3]=Part4
             * Handle = OsirisFunctionHandle(Key[0..3]) — typically equals funcId.
             *
             * NOTE: Windows layout has Key at +0x28 (after Type at +0x24).
             * Previously we read from +0x2C which was off by 4. */
            uint32_t keys[4] = {0};
            uint32_t handle = 0;
            if (safe_memory_read((mach_vm_address_t)funcDef + 0x28,
                                 keys, sizeof(keys))) {
                /* Cross-validate: Key[0] should match type from +0x24/+0x28. */
                if (keys[0] <= OSI_FUNC_USERQUERY) {
                    handle = osi_encode_handle(keys[0], keys[1], keys[2], keys[3]);
                    if (s_diagLogCount < MAX_DIAG_LOGS && keys[0] != type) {
                        LOG_OSIRIS_WARN("funcId=0x%08x '%s': Key[0]=%u != type=%u "
                                       "(using Key[0])", funcId, name, keys[0], type);
                    }
                } else {
                    if (s_diagLogCount < MAX_DIAG_LOGS) {
                        LOG_OSIRIS_WARN("funcId=0x%08x '%s': Key[0]=%u out of range, "
                                       "using funcId as handle", funcId, name, keys[0]);
                    }
                    /* Fallback: funcId IS the handle for Osiris functions */
                    handle = funcId;
                }
            } else {
                /* Fallback: funcId IS the handle (OsirisFunctionHandle(Key[0..3]) == funcId) */
                handle = funcId;
            }

            /* Log success for first few */
            if (s_diagLogCount < MAX_DIAG_LOGS) {
                LOG_OSIRIS_DEBUG("SUCCESS: funcId=0x%08x -> '%s' (arity=%d, type=%s[%d], handle=0x%08x)",
                           funcId, name, arity, osi_func_type_str(type), type, handle);
                s_diagLogCount++;
            }

            osi_func_cache(name, funcId, arity, type);
            if (handle != 0) {
                osi_func_cache_set_handle(funcId, handle);
            }
            return 1;
        } else if (s_diagLogCount < MAX_DIAG_LOGS) {
            /* Log failure - but don't try to dump memory unsafely */
            LOG_OSIRIS_DEBUG("Failed to extract name for funcId=0x%08x, funcDef=%p (memory inaccessible or invalid)", funcId, funcDef);
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
        LOG_OSIRIS_DEBUG("Cannot enumerate - pFunctionData or OsiFunctionMan not available");
        return;
    }

    LOG_OSIRIS_DEBUG("Starting function enumeration...");
    int found_count = 0;

    // Osiris function IDs are split into two ranges:
    // 1. Regular functions: 0 to ~64K (low IDs)
    // 2. Registered functions: 0x80000000 + offset (high bit set)
    //
    // Caps are kept below MAX_CACHED_FUNCTIONS (4096) to avoid overflow.
    // Databases (DB_Players, DB_PartyMembers, ...) live among the regular
    // functions but at higher IDs; the previous found_count<1000 low-range cap
    // stopped the scan before reaching them, so Osi.DB_*:Get() always returned
    // empty. Widened to 20000/found_count<4000 (low) and 50000 (high) so DB
    // nodes are captured. This function is idempotent — osi_func_cache() dedups
    // by ID, and already-cached IDs are skipped below — so it is safe to re-run
    // after the story loads (see fake_Event re-enumeration on SavegameLoaded).
    #define ENUM_CAP 4000

    // Probe low range (regular functions incl. databases)
    for (uint32_t id = 1; id < 20000 && found_count < ENUM_CAP; id++) {
        if (osi_func_get_name(id) != NULL) {  // already cached — skip expensive probe
            found_count++;
            continue;
        }
        if (osi_func_cache_by_id(id)) {
            found_count++;
        }
    }

    // Probe high range (registered functions) - 0x80000000 + 0 to ~50000
    for (uint32_t offset = 0; offset < 50000 && found_count < ENUM_CAP; offset++) {
        uint32_t id = 0x80000000 | offset;
        if (osi_func_get_name(id) != NULL) {  // already cached — skip expensive probe
            found_count++;
            continue;
        }
        if (osi_func_cache_by_id(id)) {
            found_count++;
        }
    }

    #undef ENUM_CAP

    LOG_OSIRIS_DEBUG("Enumeration complete: %d functions cached", found_count);

    // Log some key functions we're looking for
    const char *key_funcs[] = {
        "QRY_IsTagged", "IsTagged", "GetDistanceTo", "QRY_GetDistance",
        "DialogRequestStop", "QRY_StartDialog_Fixed", "StartDialog",
        "DB_Players", "CharacterGetDisplayName", NULL
    };

    LOG_OSIRIS_DEBUG("Checking key functions:");
    for (int i = 0; key_funcs[i]; i++) {
        uint32_t fid = osi_func_lookup_id(key_funcs[i]);
        if (fid != INVALID_FUNCTION_ID) {
            LOG_OSIRIS_DEBUG("  %s -> 0x%08x", key_funcs[i], fid);
        }
    }
}

/* Extract name/arity/type/handle from a resolved OsiFunctionData* and cache it
 * under funcId. Self-contained (mirrors the extraction in osi_func_cache_by_id)
 * so the name-index walk can cache defs it already holds without re-probing by
 * id. Returns 1 if a name was extracted and cached. */
static int osi_func_cache_def(void *funcDef, uint32_t funcId) {
    if (!funcDef) return 0;

    const char *name = extract_func_name_from_def(funcDef);
    if (!name || !name[0]) return 0;

    /* Arity: funcDef+0x18 → Signature → +0x10 ParamList → +0x10 Size (in+out). */
    uint8_t arity = 0;
    void *sigPtr = NULL;
    if (safe_memory_read_pointer((mach_vm_address_t)funcDef + OSIFUNCDEF_SIGNATURE_OFFSET, &sigPtr) && sigPtr) {
        void *paramListPtr = NULL;
        if (safe_memory_read_pointer((mach_vm_address_t)sigPtr + FUNCSIG_PARAMS_OFFSET, &paramListPtr) && paramListPtr) {
            uint32_t paramSize = 0;
            if (safe_memory_read_u32((mach_vm_address_t)paramListPtr + PARAMLIST_SIZE_OFFSET, &paramSize)) {
                arity = (paramSize <= 20) ? (uint8_t)paramSize : 0;
            }
        }
    }

    /* Type + Key[4] at funcDef+0x28 (same layout the id-based path uses). */
    uint8_t type = osi_func_guess_type(name);
    uint32_t keys[4] = {0};
    uint32_t handle = funcId;
    if (safe_memory_read((mach_vm_address_t)funcDef + 0x28, keys, sizeof(keys))) {
        if (keys[0] >= OSI_FUNC_EVENT && keys[0] <= OSI_FUNC_USERQUERY) {
            type = (uint8_t)keys[0];
            handle = osi_encode_handle(keys[0], keys[1], keys[2], keys[3]);
        }
    }

    osi_func_cache(name, funcId, arity, type);
    if (handle != 0) {
        osi_func_cache_set_handle(funcId, handle);
    }
    return 1;
}

// ============================================================================
// Database registry
// ============================================================================
// Osiris databases (DB_*) have OsiFunctionId==0 — they cannot be keyed in the
// id-based function cache. Instead we register name -> COsiFunctionData* so the
// Facts reader (osi_db_read_facts in main.c) can resolve them.

#define MAX_DATABASES 32768
typedef struct { char name[96]; void *def; } DbRegEntry;
static DbRegEntry g_dbReg[MAX_DATABASES];
static int g_dbRegCount = 0;

int osi_db_register(const char *name, void *def) {
    if (!name || !name[0] || !def) return 0;
    for (int i = 0; i < g_dbRegCount; i++) {
        if (strcmp(g_dbReg[i].name, name) == 0) {
            g_dbReg[i].def = def;  /* refresh on re-enumeration */
            return 0;
        }
    }
    if (g_dbRegCount >= MAX_DATABASES) return 0;
    strncpy(g_dbReg[g_dbRegCount].name, name, sizeof(g_dbReg[0].name) - 1);
    g_dbReg[g_dbRegCount].name[sizeof(g_dbReg[0].name) - 1] = '\0';
    g_dbReg[g_dbRegCount].def = def;
    g_dbRegCount++;
    return 1;
}

void *osi_db_lookup(const char *name) {
    if (!name) return NULL;
    for (int i = 0; i < g_dbRegCount; i++) {
        if (strcmp(g_dbReg[i].name, name) == 0) return g_dbReg[i].def;
    }
    return NULL;
}

int osi_db_count(void) { return g_dbRegCount; }

/* Walk the Osiris name index (CSearchIndex<COsiFunctionData*, COsiString, 1023>)
 * that lives at the start of COsiFunctionMan and cache every function BY NAME.
 *
 * Unlike osi_func_enumerate() — which brute-force probes numeric IDs via
 * COsiFunctionMan::pFunctionData(uint) and only sees the runtime id-index —
 * this walks the *name* index, which is the ONLY place Osiris databases
 * (DB_Players, DB_PartyMembers, DB_Avatars, ...) are registered. Without this,
 * Osi.DB_*:Get() can never resolve a funcId and always returns empty, breaking
 * every mod that reads an Osiris database.
 *
 * Layout reverse-engineered from COsiFunctionMan::pFunctionData(CKey const&)
 * (libOsiris arm64 @ 0x29b88):
 *   manager = *s_ppOsiFunctionMan
 *   bucket  = manager + (hash % 1023) * 0x18 ; tree root = *(bucket + 0x8)
 *   node    : left=*(n+0x00), right=*(n+0x08), value(COsiFunctionData*)=*(n+0x38)
 * All reads go through safe_memory_* so bad pointers fail gracefully; total
 * node visits are capped to bound worst-case cost against a malformed tree. */
void osi_func_enumerate_by_name(void) {
    if (!s_ppOsiFunctionMan) {
        LOG_OSIRIS_DEBUG("enumerate_by_name: OsiFunctionMan pointer not set");
        return;
    }
    void *manager = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)s_ppOsiFunctionMan, &manager) || !manager) {
        LOG_OSIRIS_DEBUG("enumerate_by_name: OsiFunctionMan is null");
        return;
    }

    LOG_OSIRIS_DEBUG("Starting name-index enumeration (databases included)...");

    #define OSI_NAME_BUCKETS   1023
    #define OSI_BUCKET_STRIDE  0x18
    #define OSI_NODE_LEFT      0x00
    #define OSI_NODE_RIGHT     0x08
    #define OSI_NODE_VALUE     0x38
    #define OSI_WALK_STACK     8192
    #define OSI_MAX_VISITS     200000

    void *stack[OSI_WALK_STACK];
    int found = 0;
    int totalVisits = 0;

    for (int b = 0; b < OSI_NAME_BUCKETS; b++) {
        mach_vm_address_t bucket = (mach_vm_address_t)manager +
                                   (mach_vm_address_t)b * OSI_BUCKET_STRIDE;
        void *root = NULL;
        if (!safe_memory_read_pointer(bucket + 0x8, &root) || !root) {
            continue;
        }

        int sp = 0;
        stack[sp++] = root;
        while (sp > 0 && totalVisits < OSI_MAX_VISITS) {
            void *node = stack[--sp];
            if (!node) continue;
            totalVisits++;

            void *def = NULL;
            if (safe_memory_read_pointer((mach_vm_address_t)node + OSI_NODE_VALUE, &def) && def) {
                uint8_t ftype = 0;
                safe_memory_read_u8((mach_vm_address_t)def + 0x24, &ftype);  /* Type @ def+0x24 */
                if (ftype == OSI_FUNC_DATABASE) {
                    /* Databases have OsiFunctionId==0 (not id-cacheable); register
                     * name -> def so the Facts reader can resolve them. */
                    const char *dbName = extract_func_name_from_def(def);
                    if (osi_db_register(dbName, def)) {
                        found++;
                    }
                } else {
                    uint32_t osiId = 0;
                    /* OsiFunctionId at def+0x38 (same field the id path caches under). */
                    if (safe_memory_read_u32((mach_vm_address_t)def + 0x38, &osiId) && osiId != 0) {
                        if (osi_func_get_name(osiId) == NULL && osi_func_cache_def(def, osiId)) {
                            found++;
                        }
                    }
                }
            }

            /* Push children (NULL-terminated leaves). Bounded by stack size. */
            if (sp < OSI_WALK_STACK - 2) {
                void *left = NULL, *right = NULL;
                if (safe_memory_read_pointer((mach_vm_address_t)node + OSI_NODE_LEFT, &left) && left) {
                    stack[sp++] = left;
                }
                if (safe_memory_read_pointer((mach_vm_address_t)node + OSI_NODE_RIGHT, &right) && right) {
                    stack[sp++] = right;
                }
            }
        }
    }

    #undef OSI_NAME_BUCKETS
    #undef OSI_BUCKET_STRIDE
    #undef OSI_NODE_LEFT
    #undef OSI_NODE_RIGHT
    #undef OSI_NODE_VALUE
    #undef OSI_WALK_STACK
    #undef OSI_MAX_VISITS

    LOG_OSIRIS_INFO("Name-index enumeration: %d new entries (%d visits); "
                    "databases registered=%d, DB_Players %s", found, totalVisits,
                    osi_db_count(), osi_db_lookup("DB_Players") ? "FOUND" : "missing");
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

    // Fast path: name hash table
    int hash = func_name_hash(name);
    int16_t idx = g_funcNameHashTable[hash];
    if (idx >= 0 && strcmp(g_funcCache[idx].name, name) == 0) {
        return g_funcCache[idx].id;
    }

    // Slow path: linear search (hash collision)
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

    // Fast path: name hash table
    int hash = func_name_hash(name);
    int16_t idx = g_funcNameHashTable[hash];
    if (idx >= 0 && strcmp(g_funcCache[idx].name, name) == 0) {
        if (out_arity) *out_arity = g_funcCache[idx].arity;
        if (out_type) *out_type = g_funcCache[idx].type;
        return 1;
    }

    // Slow path: linear search (hash collision)
    for (int i = 0; i < g_funcCacheCount; i++) {
        if (strcmp(g_funcCache[i].name, name) == 0) {
            if (out_arity) *out_arity = g_funcCache[i].arity;
            if (out_type) *out_type = g_funcCache[i].type;
            return 1;
        }
    }

    return 0;
}

uint32_t osi_func_get_handle(const char *name) {
    if (!name) return 0;

    // Fast path: name hash table
    int hash = func_name_hash(name);
    int16_t idx = g_funcNameHashTable[hash];
    if (idx >= 0 && strcmp(g_funcCache[idx].name, name) == 0) {
        return g_funcCache[idx].handle;
    }

    // Slow path: linear search (hash collision)
    for (int i = 0; i < g_funcCacheCount; i++) {
        if (strcmp(g_funcCache[i].name, name) == 0) {
            return g_funcCache[i].handle;
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
                LOG_OSIRIS_INFO("Discovered event ID: %s = 0x%x", name, funcId);
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
        LOG_OSIRIS_DEBUG("New unique: id=%u (0x%08x), arity=%d, total_unique=%d",
                   funcId, funcId, arity, g_seenFuncIdCount);
    }
}

int osi_func_get_seen_count(void) {
    return g_seenFuncIdCount;
}

// ============================================================================
// Struct Probe (on-demand layout discovery)
// ============================================================================

void osi_func_probe_layout(int count) {
    if (!s_pfn_pFunctionData || !s_ppOsiFunctionMan) {
        LOG_OSIRIS_WARN("PROBE: runtime pointers not set");
        return;
    }

    /* Read OsiFunctionMan pointer — same pattern as osi_func_cache_by_id.
     * Bug fix: was using safe_memory_read(*s_ppOsiFunctionMan, ...) which reads
     * FROM the OsiFunctionMan object (getting its VMT), not the pointer TO it.
     * That caused pFunctionData(garbage_this, ...) → PAC failure → SIGSEGV. */
    void *funcMan = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)s_ppOsiFunctionMan, &funcMan)
        || !funcMan) {
        LOG_OSIRIS_WARN("PROBE: failed to read OsiFunctionMan");
        return;
    }

    LOG_OSIRIS_INFO("PROBE: funcMan=%p, probing %d/%d cached functions",
                    funcMan, count, g_funcCacheCount);

    int probed = 0;
    for (int i = 0; i < g_funcCacheCount && probed < count; i++) {
        CachedFunction *cf = &g_funcCache[i];

        /* Validate funcId before calling pFunctionData — skip obviously invalid IDs */
        if (cf->id == 0 || cf->id == INVALID_FUNCTION_ID) {
            LOG_OSIRIS_DEBUG("PROBE: skipping invalid funcId=0x%08x for '%s'", cf->id, cf->name);
            continue;
        }

        void *funcDef = s_pfn_pFunctionData(funcMan, cf->id);
        if (!funcDef) continue;

        /* Validate funcDef pointer before reading from it */
        SafeMemoryInfo fdi = safe_memory_check_address((mach_vm_address_t)funcDef);
        if (!fdi.is_valid || !fdi.is_readable) {
            LOG_OSIRIS_WARN("PROBE: funcDef=%p not readable for '%s'", funcDef, cf->name);
            continue;
        }

        // Dump 0x80 bytes as hex (128B covers potential ARM64 padding beyond Windows layout)
        uint8_t raw[0x80];
        if (!safe_memory_read((mach_vm_address_t)funcDef, raw, sizeof(raw))) {
            LOG_OSIRIS_WARN("PROBE: can't read 0x80 bytes at %p for '%s'", funcDef, cf->name);
            continue;
        }

        // Format hex dump
        char hexline[256];
        LOG_OSIRIS_INFO("PROBE [%d] '%s' funcDef=%p id=0x%08x type=%s handle=0x%08x",
                        probed, cf->name, funcDef, cf->id,
                        osi_func_type_str(cf->type), cf->handle);

        for (int off = 0; off < 0x80; off += 16) {
            int pos = snprintf(hexline, sizeof(hexline), "  +0x%02x: ", off);
            for (int j = 0; j < 16 && off + j < 0x80; j++) {
                pos += snprintf(hexline + pos, sizeof(hexline) - pos, "%02x ", raw[off + j]);
            }
            // Annotate interesting offsets (assuming Windows layout — verify with probe)
            if (off == 0x28) {
                uint32_t type_val = *(uint32_t *)(raw + 0x28);
                pos += snprintf(hexline + pos, sizeof(hexline) - pos,
                               " | +0x28(Type?)=%u(%s)", type_val, osi_func_type_str((uint8_t)type_val));
            }
            if (off == 0x20) {
                uint32_t node_or_param = *(uint32_t *)(raw + 0x20);
                pos += snprintf(hexline + pos, sizeof(hexline) - pos,
                               " | +0x20(ParamCount?)=%u", node_or_param);
            }
            if (off == 0x30) {
                // Key[0..3] at 0x28-0x37 (verified via runtime probe)
                uint32_t k0 = *(uint32_t *)(raw + 0x28);
                uint32_t k2 = *(uint32_t *)(raw + 0x30);
                uint32_t k3 = *(uint32_t *)(raw + 0x34);
                pos += snprintf(hexline + pos, sizeof(hexline) - pos,
                               " | Key[0]=%u Key[2/funcIdx]=0x%x Key[3/part4]=%u", k0, k2, k3);
            }
            LOG_OSIRIS_INFO("%s", hexline);
        }
        probed++;
    }

    LOG_OSIRIS_INFO("PROBE: dumped %d/%d functions", probed, count);
}

void osi_func_probe_info(const char *name, void (*out)(const char *fmt, ...)) {
    if (!name || !out) return;

    /* 1. Cache lookup */
    uint32_t funcId = osi_func_lookup_id(name);
    uint8_t cachedArity = 0, cachedType = 0;
    int infoFound = osi_func_get_info(name, &cachedArity, &cachedType);
    uint32_t handle = osi_func_get_handle(name);

    out("=== !osi_info %s ===", name);
    out("  funcId: 0x%08x (%s)", funcId, funcId == INVALID_FUNCTION_ID ? "NOT FOUND" : "found");
    out("  arity: %d (from %s)", cachedArity, infoFound ? "known table or cache" : "unknown");
    out("  type: %s[%d]", osi_func_type_str(cachedType), cachedType);
    out("  handle: 0x%08x", handle);

    /* 2. Re-probe the pointer chain from live memory */
    if (funcId == INVALID_FUNCTION_ID) {
        out("  [Cannot probe pointer chain - funcId unknown]");
        return;
    }

    if (!s_pfn_pFunctionData || !s_ppOsiFunctionMan) {
        out("  [Cannot probe - runtime pointers not set]");
        return;
    }

    void *funcMan = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)s_ppOsiFunctionMan, &funcMan) || !funcMan) {
        out("  [Cannot probe - OsiFunctionMan NULL]");
        return;
    }

    void *funcDef = s_pfn_pFunctionData(funcMan, funcId);
    if (!funcDef) {
        out("  [pFunctionData returned NULL for funcId=0x%08x]", funcId);
        return;
    }
    out("  funcDef: %p", funcDef);

    /* Step 1: Signature pointer at funcDef+0x18 */
    void *sigPtr = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)funcDef + OSIFUNCDEF_SIGNATURE_OFFSET, &sigPtr) || !sigPtr) {
        out("  Signature: FAILED to read at funcDef+0x%x", OSIFUNCDEF_SIGNATURE_OFFSET);
        return;
    }
    out("  Signature: %p (at funcDef+0x%x)", sigPtr, OSIFUNCDEF_SIGNATURE_OFFSET);

    /* Step 2: Name at Signature+0x08 (sanity check) */
    void *namePtr = NULL;
    char nameBuf[64] = {0};
    if (safe_memory_read_pointer((mach_vm_address_t)sigPtr + FUNCSIG_NAME_OFFSET, &namePtr) && namePtr) {
        safe_memory_read((mach_vm_address_t)namePtr, nameBuf, sizeof(nameBuf) - 1);
        out("  Sig.Name: '%s' (at Sig+0x%x -> %p)", nameBuf, FUNCSIG_NAME_OFFSET, namePtr);
    } else {
        out("  Sig.Name: FAILED at Sig+0x%x", FUNCSIG_NAME_OFFSET);
    }

    /* Step 3: ParamList pointer at Signature+0x10 */
    void *paramListPtr = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)sigPtr + FUNCSIG_PARAMS_OFFSET, &paramListPtr)) {
        out("  ParamList: FAILED to read at Sig+0x%x", FUNCSIG_PARAMS_OFFSET);
        return;
    }
    out("  ParamList: %p (at Sig+0x%x) %s", paramListPtr, FUNCSIG_PARAMS_OFFSET,
        paramListPtr ? "" : "*** NULL ***");

    if (!paramListPtr) {
        out("  [ParamList is NULL - arity will be 0]");
        /* Try reading alternative: OutParamList.Count at Sig+0x20 */
        uint32_t outCount = 0;
        if (safe_memory_read_u32((mach_vm_address_t)sigPtr + FUNCSIG_OUTPARAMCOUNT_OFFSET, &outCount)) {
            out("  OutParamList.Count: %u (at Sig+0x%x)", outCount, FUNCSIG_OUTPARAMCOUNT_OFFSET);
        }
        return;
    }

    /* Step 4: Size at ParamList+0x10 */
    uint32_t paramSize = 0;
    if (safe_memory_read_u32((mach_vm_address_t)paramListPtr + PARAMLIST_SIZE_OFFSET, &paramSize)) {
        out("  ParamList.Size: %u (at PL+0x%x) <- THIS IS ARITY", paramSize, PARAMLIST_SIZE_OFFSET);
    } else {
        out("  ParamList.Size: FAILED to read at PL+0x%x", PARAMLIST_SIZE_OFFSET);
    }

    /* Also read OutParamList.Count for cross-reference */
    uint32_t outCount = 0;
    void *outBitmapPtr = NULL;
    if (safe_memory_read_pointer((mach_vm_address_t)sigPtr + FUNCSIG_OUTPARAMLIST_OFFSET, &outBitmapPtr)) {
        out("  OutParamList.Params: %p (bitmap at Sig+0x%x)", outBitmapPtr, FUNCSIG_OUTPARAMLIST_OFFSET);
    }
    if (safe_memory_read_u32((mach_vm_address_t)sigPtr + FUNCSIG_OUTPARAMCOUNT_OFFSET, &outCount)) {
        out("  OutParamList.Count: %u (bitmap bytes at Sig+0x%x)", outCount, FUNCSIG_OUTPARAMCOUNT_OFFSET);
    }

    /* Also probe nearby offsets for Size discovery if ParamList.Size looks wrong */
    if (paramSize == 0 || paramSize > 20) {
        out("  [ParamList.Size=%u looks wrong, probing nearby offsets:]", paramSize);
        for (int off = 0; off <= 0x20; off += 4) {
            uint32_t val = 0;
            if (safe_memory_read_u32((mach_vm_address_t)paramListPtr + off, &val)) {
                out("    PL+0x%02x: 0x%08x (%u)", off, val, val);
            }
        }
    }
}
