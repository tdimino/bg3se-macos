/**
 * BG3SE-macOS - Baldur's Gate 3 Script Extender for macOS
 *
 * This dylib is loaded via DYLD_INSERT_LIBRARIES before the game starts.
 * The constructor runs automatically when the library is loaded.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <dlfcn.h>
#include <time.h>
#include <unistd.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <dirent.h>
#include <sys/stat.h>
#include <zlib.h>

// LZ4 decompression
#include "lz4/lz4.h"

// Dobby hooking framework
#include "Dobby/include/dobby.h"

// Lua runtime (C library, needs extern "C" for C++ linkage)
#ifdef __cplusplus
extern "C" {
#endif
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#ifdef __cplusplus
}
#endif

// Version info
#define BG3SE_VERSION "0.9.5"
#define BG3SE_NAME "BG3SE-macOS"

// Log file for debugging
#define LOG_FILE "/tmp/bg3se_macos.log"

// Enable hooks (set to 0 to disable for testing)
#define ENABLE_HOOKS 1

// Forward declarations
static void log_message(const char *format, ...);
static void enumerate_loaded_images(void);
static void check_osiris_library(void);
static void install_hooks(void);
static void init_lua(void);
static void shutdown_lua(void);
static void detect_enabled_mods(void);

// Forward declarations for Osiris wrappers (defined later in file)
struct OsiArgumentDesc;  // Forward declare for function signatures
static uint32_t lookup_function_by_name(const char *name);
static struct OsiArgumentDesc *alloc_args(int count);
static void set_arg_string(struct OsiArgumentDesc *arg, const char *value, int isGuid);
static int osiris_query_by_id(uint32_t funcId, struct OsiArgumentDesc *args);
static int osi_is_tagged(const char *character, const char *tag);
static float osi_get_distance_to(const char *char1, const char *char2);
static void osi_dialog_request_stop(const char *dialog);
static void enumerate_osiris_functions(void);
static void try_cache_function_from_event(uint32_t funcId);
static const char *get_function_name(uint32_t funcId);

// Original function pointers (filled by Dobby)
static void *orig_InitGame = NULL;
static void *orig_Load = NULL;
static void *orig_Event = NULL;

// Hook call counters
static int initGame_call_count = 0;
static int load_call_count = 0;
static int event_call_count = 0;

// ============================================================================
// Osiris Data Structures (based on Windows BG3SE, validated via logging)
// ============================================================================

// Value types in Osiris
typedef enum {
    OSI_TYPE_NONE = 0,
    OSI_TYPE_INTEGER = 1,
    OSI_TYPE_INTEGER64 = 2,
    OSI_TYPE_REAL = 3,
    OSI_TYPE_STRING = 4,
    OSI_TYPE_GUIDSTRING = 5
} OsiValueType;

// Argument value - tagged union (structure layout TBD via logging)
typedef struct OsiArgumentValue {
    union {
        int32_t int32Val;
        int64_t int64Val;
        float floatVal;
        char *stringVal;
    };
    uint16_t typeId;
    uint16_t flags;
} OsiArgumentValue;

// Argument linked list node
typedef struct OsiArgumentDesc {
    struct OsiArgumentDesc *nextParam;  // offset 0 (8 bytes on ARM64)
    OsiArgumentValue value;              // offset 8
} OsiArgumentDesc;

// Function pointers for Osiris calls
typedef void (*OsiEventFn)(void *thisPtr, uint32_t funcId, OsiArgumentDesc *args);
typedef int (*InternalQueryFn)(uint32_t funcId, OsiArgumentDesc *args);
typedef int (*InternalCallFn)(uint32_t funcId, void *params);
typedef void* (*pFunctionDataFn)(void *funcMan, uint32_t funcId);

// Global function pointers (resolved at runtime)
static InternalQueryFn pfn_InternalQuery = NULL;
static InternalCallFn pfn_InternalCall = NULL;
static pFunctionDataFn pfn_pFunctionData = NULL;
static void *g_OsiFunctionMan = NULL;
static void *g_COsiris = NULL;  // Captured from hook calls

// Global pointer to OsiFunctionMan from libOsiris
static void **g_pOsiFunctionMan = NULL;  // Points to the global _OsiFunctionMan

// Captured player GUIDs from events (we learn these by observing)
#define MAX_KNOWN_PLAYERS 8
static char g_knownPlayerGuids[MAX_KNOWN_PLAYERS][128];
static int g_knownPlayerCount = 0;

// Current dialog tracking (learned from AutomatedDialogStarted events)
static char g_currentDialogResource[256] = {0};  // Dialog resource ID
static int g_currentDialogInstance = -1;         // Dialog instance ID (if known)
static int g_currentDialogPlayerCount = 1;       // Number of players in dialog (default 1)

// Dialog participants (characters currently in an active dialog)
#define MAX_DIALOG_PARTICIPANTS 8
static char g_dialogParticipants[MAX_DIALOG_PARTICIPANTS][128];
static int g_dialogParticipantCount = 0;

// Function cache for name->ID lookup
#define MAX_CACHED_FUNCTIONS 4096
#define INVALID_FUNCTION_ID 0xFFFFFFFF
#define OSI_FUNCTION_TYPE_MASK 0x80000000  // High bit indicates function type

// Function types (based on Windows BG3SE)
typedef enum {
    OSI_FUNC_EVENT = 1,
    OSI_FUNC_QUERY = 2,
    OSI_FUNC_CALL = 3,
    OSI_FUNC_DATABASE = 4,
    OSI_FUNC_PROC = 5,
    OSI_FUNC_SYSCALL = 6,
    OSI_FUNC_SYSQUERY = 7
} OsiFunctionType;

// Function definition structure (layout determined empirically)
// This is the structure returned by pFunctionData()
// Note: Layout may need adjustment based on actual memory dumps
typedef struct {
    void *vtable;           // offset 0: C++ vtable pointer
    void *name_ptr;         // offset 8: pointer to std::string or char*
    uint32_t funcId;        // offset 16: function ID
    uint8_t  funcType;      // offset 20: function type
    uint8_t  numInParams;   // offset 21: number of input parameters
    uint8_t  numOutParams;  // offset 22: number of output parameters
    uint8_t  reserved1;     // offset 23: padding
    // More fields follow but we don't need them
} OsiFunctionDef;

typedef struct {
    char name[128];
    uint8_t arity;
    uint8_t type;  // FunctionType: 1=Event, 2=Query, 3=Call, 4=Database
    uint32_t id;
} CachedFunction;

static CachedFunction g_funcCache[MAX_CACHED_FUNCTIONS];
static int g_funcCacheCount = 0;

// Reverse lookup: funcId -> cache index (for fast event dispatch)
#define FUNC_HASH_SIZE 8192
static int16_t g_funcIdHashTable[FUNC_HASH_SIZE];  // -1 = empty, else index into g_funcCache

// Known event names we want to track (for MRC compatibility)
// We'll learn the function IDs by observing events and matching patterns
typedef struct {
    const char *name;
    uint32_t funcId;        // 0 = not yet discovered
    uint8_t expectedArity;
} KnownEvent;

static KnownEvent g_knownEvents[] = {
    // Discovered via runtime observation on macOS ARM64
    {"AutomatedDialogStarted", 2147492339, 4},   // 0x800021f3 - Main event MRC uses
    {"AutomatedDialogEnded", 2147492347, 4},     // 0x800021fb - Dialog end event
    // These still need to be discovered:
    {"DialogStarted", 0, 2},
    {"DialogEnded", 0, 2},
    {"CharacterJoinedParty", 0, 1},
    {"CharacterLeftParty", 0, 1},
    {"CombatStarted", 0, 1},
    {"CombatEnded", 0, 1},
    {"TurnStarted", 0, 1},
    {"TurnEnded", 0, 1},
    {NULL, 0, 0}  // Sentinel
};

// Track unique function IDs we've seen (for analysis)
#define MAX_SEEN_FUNC_IDS 256
static uint32_t g_seenFuncIds[MAX_SEEN_FUNC_IDS];
static uint8_t g_seenFuncArities[MAX_SEEN_FUNC_IDS];
static int g_seenFuncIdCount = 0;

// Track if hooks are already installed
static int hooks_installed = 0;

// ============================================================================
// Pattern Scanning Infrastructure
// ============================================================================

// Pattern structure for byte pattern matching
// Supports Ghidra/IDA style patterns like "48 8D 05 ?? ?? ?? ?? E8"
typedef struct {
    unsigned char *bytes;   // Pattern bytes to match
    unsigned char *mask;    // Mask: 0xFF = must match, 0x00 = wildcard
    size_t length;          // Pattern length
} BytePattern;

/**
 * Parse a pattern string into a BytePattern structure.
 * Format: "48 8D 05 ?? ?? ?? ?? E8" where ?? = wildcard byte
 * Returns NULL on parse error. Caller must free with free_pattern().
 */
static BytePattern *parse_pattern(const char *pattern_str) {
    if (!pattern_str || !*pattern_str) return NULL;

    // First pass: count bytes
    size_t count = 0;
    const char *p = pattern_str;
    while (*p) {
        // Skip whitespace
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;

        // Check for wildcard or hex byte
        if (p[0] == '?' && p[1] == '?') {
            count++;
            p += 2;
        } else if ((p[0] >= '0' && p[0] <= '9') ||
                   (p[0] >= 'A' && p[0] <= 'F') ||
                   (p[0] >= 'a' && p[0] <= 'f')) {
            if ((p[1] >= '0' && p[1] <= '9') ||
                (p[1] >= 'A' && p[1] <= 'F') ||
                (p[1] >= 'a' && p[1] <= 'f')) {
                count++;
                p += 2;
            } else {
                return NULL;  // Invalid hex
            }
        } else if (*p) {
            return NULL;  // Invalid character
        }
    }

    if (count == 0) return NULL;

    // Allocate pattern structure
    BytePattern *pat = (BytePattern *)malloc(sizeof(BytePattern));
    if (!pat) return NULL;

    pat->bytes = (unsigned char *)malloc(count);
    pat->mask = (unsigned char *)malloc(count);
    pat->length = count;

    if (!pat->bytes || !pat->mask) {
        free(pat->bytes);
        free(pat->mask);
        free(pat);
        return NULL;
    }

    // Second pass: fill bytes and mask
    p = pattern_str;
    size_t i = 0;
    while (*p && i < count) {
        // Skip whitespace
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;

        if (p[0] == '?' && p[1] == '?') {
            pat->bytes[i] = 0x00;
            pat->mask[i] = 0x00;  // Wildcard
            p += 2;
            i++;
        } else {
            // Parse hex byte
            unsigned int byte = 0;
            sscanf(p, "%2x", &byte);
            pat->bytes[i] = (unsigned char)byte;
            pat->mask[i] = 0xFF;  // Must match
            p += 2;
            i++;
        }
    }

    return pat;
}

/**
 * Free a BytePattern allocated by parse_pattern()
 */
static void free_pattern(BytePattern *pat) {
    if (pat) {
        free(pat->bytes);
        free(pat->mask);
        free(pat);
    }
}

/**
 * Scan memory for a byte pattern.
 * Returns pointer to first match, or NULL if not found.
 */
static void *find_pattern(const void *start, size_t size, const BytePattern *pattern) {
    if (!start || !pattern || size < pattern->length) return NULL;

    const unsigned char *base = (const unsigned char *)start;
    size_t scan_size = size - pattern->length + 1;

    for (size_t i = 0; i < scan_size; i++) {
        int found = 1;
        for (size_t j = 0; j < pattern->length; j++) {
            // Check if byte matches or is wildcard (mask == 0)
            if (pattern->mask[j] != 0x00 && base[i + j] != pattern->bytes[j]) {
                found = 0;
                break;
            }
        }
        if (found) {
            return (void *)&base[i];
        }
    }

    return NULL;
}

/**
 * Convenience function: parse pattern string and scan in one call.
 * Returns pointer to first match, or NULL if not found.
 */
static void *find_pattern_str(const void *start, size_t size, const char *pattern_str) {
    BytePattern *pat = parse_pattern(pattern_str);
    if (!pat) return NULL;

    void *result = find_pattern(start, size, pat);
    free_pattern(pat);
    return result;
}

/**
 * Get the __TEXT,__text section bounds from a loaded Mach-O image.
 * This is where code resides in the binary.
 */
static int get_macho_text_section(const char *image_name, void **start, size_t *size) {
    if (!start || !size) return 0;
    *start = NULL;
    *size = 0;

    // Find the image by name
    uint32_t image_count = _dyld_image_count();
    const struct mach_header_64 *header = NULL;
    intptr_t slide = 0;

    for (uint32_t i = 0; i < image_count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, image_name)) {
            header = (const struct mach_header_64 *)_dyld_get_image_header(i);
            slide = _dyld_get_image_vmaddr_slide(i);
            break;
        }
    }

    if (!header) {
        return 0;  // Image not found
    }

    // Make sure it's a 64-bit Mach-O
    if (header->magic != MH_MAGIC_64) {
        return 0;
    }

    // Walk load commands to find __TEXT segment, then __text section
    const uint8_t *ptr = (const uint8_t *)header + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)ptr;

        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)ptr;

            if (strcmp(seg->segname, "__TEXT") == 0) {
                // Found __TEXT segment - now find __text section
                const struct section_64 *sections = (const struct section_64 *)(ptr + sizeof(struct segment_command_64));
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (strcmp(sections[j].sectname, "__text") == 0) {
                        *start = (void *)(sections[j].addr + slide);
                        *size = sections[j].size;
                        return 1;
                    }
                }
                // If no __text section, use whole __TEXT segment
                *start = (void *)(seg->vmaddr + slide);
                *size = seg->vmsize;
                return 1;
            }
        }

        ptr += lc->cmdsize;
    }

    return 0;
}

/**
 * Debug helper: Log a pattern scan result
 */
__attribute__((unused))
static void log_pattern_scan(const char *name, const char *pattern, void *result) {
    if (result) {
        log_message("[PatternScan] %s found at %p (pattern: %s)", name, result, pattern);
    } else {
        log_message("[PatternScan] %s NOT FOUND (pattern: %s)", name, pattern);
    }
}

// ============================================================================
// ARM64 Pattern Database for Fallback Symbol Resolution
// ============================================================================
// These patterns are unique byte sequences found in function bodies.
// They're used when dlsym fails (e.g., after game updates change symbol names).
// Pattern offset is bytes from function start where pattern is found.

typedef struct {
    const char *name;           // Function name (for logging)
    const char *symbol;         // Mangled symbol name for dlsym
    const char *pattern;        // Unique byte pattern (body, not prologue)
    int pattern_offset;         // Offset from function start where pattern appears
} FunctionPattern;

// Patterns discovered from libOsiris.dylib ARM64 (BG3 Patch 7)
// These patterns are at offset +28 (after function prologue)
static const FunctionPattern g_osirisPatterns[] = {
    {
        "InternalQuery",
        "_Z13InternalQueryjP16COsiArgumentDesc",
        "FD 43 04 91 F3 03 01 AA 15 90 01 51 BF 22 00 71 A2 04 00 54 53 1B 00 B4",
        28
    },
    {
        "InternalCall",
        "_Z12InternalCalljP18COsipParameterList",
        "F3 03 00 AA 28 20 00 91 09 04 00 51 3F 0D 00 71 E2 02 00 54 29 08 40 F9",
        28
    },
    {
        "COsiris::Event",
        "_ZN7COsiris5EventEjP16COsiArgumentDesc",
        "F4 03 02 AA F3 03 01 AA 76 02 00 D0 C8 4A 4D 39 68 02 18 36 68 02 00 D0",
        28
    },
    { NULL, NULL, NULL, 0 }  // Sentinel
};

/**
 * Try to resolve a function address using pattern scanning.
 * Returns function pointer if found, NULL otherwise.
 */
static void *resolve_by_pattern(const char *image_name, const FunctionPattern *pat) {
    void *text_start = NULL;
    size_t text_size = 0;

    if (!get_macho_text_section(image_name, &text_start, &text_size)) {
        return NULL;
    }

    void *found = find_pattern_str(text_start, text_size, pat->pattern);
    if (found) {
        // Adjust back by pattern offset to get function start
        void *func_addr = (void *)((uintptr_t)found - pat->pattern_offset);
        log_message("[PatternScan] %s found via pattern at %p", pat->name, func_addr);
        return func_addr;
    }

    return NULL;
}

/**
 * Resolve symbol with dlsym, falling back to pattern scan if needed.
 */
static void *resolve_osiris_symbol(void *handle, const FunctionPattern *pat) {
    // First try dlsym (fast path)
    void *addr = dlsym(handle, pat->symbol);
    if (addr) {
        return addr;
    }

    // Fallback to pattern scanning
    log_message("[Resolve] dlsym failed for %s, trying pattern scan...", pat->name);
    return resolve_by_pattern("libOsiris.dylib", pat);
}

// Lua state
static lua_State *L = NULL;

// Module loading state
#define MAX_LOADED_MODULES 256
#define MAX_PATH_LEN 1024
static char loaded_modules[MAX_LOADED_MODULES][MAX_PATH_LEN];
static int loaded_module_count = 0;
static char current_mod_name[256] = "";
static char current_mod_lua_base[MAX_PATH_LEN] = "";  // Base path for current mod's Lua folder
static char mods_base_path[MAX_PATH_LEN] = "";

// Detected mods from modsettings.lsx
#define MAX_MODS 128
#define MAX_MOD_NAME_LEN 256
static char detected_mods[MAX_MODS][MAX_MOD_NAME_LEN];
static int detected_mod_count = 0;

// Detected SE mods (mods with ScriptExtender/Config.json containing "Lua")
static char se_mods[MAX_MODS][MAX_MOD_NAME_LEN];
static int se_mod_count = 0;

// Current PAK file for mod loading (used by Ext.Require)
static char current_mod_pak_path[MAX_PATH_LEN] = "";

// ============================================================================
// PAK File Reading (LSPK v18 format)
// ============================================================================

// LSPK signature: "LSPK" = 0x4B50534C
#define LSPK_SIGNATURE 0x4B50534C
#define LSPK_ENTRY_SIZE 272

// PAK file entry
typedef struct {
    char name[256];
    uint64_t offset;
    uint8_t archive_part;
    uint8_t compression;  // 0=none, 1=zlib, 2=LZ4
    uint32_t disk_size;
    uint32_t uncompressed_size;
} PakEntry;

// PAK file handle
typedef struct {
    FILE *file;
    uint32_t version;
    uint64_t file_list_offset;
    uint32_t file_list_size;
    uint32_t num_files;
    PakEntry *entries;
} PakFile;

/**
 * Open a PAK file and read its header and file list
 * Returns NULL on failure
 */
static PakFile *pak_open(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    // Read header (40 bytes)
    uint8_t header[40];
    if (fread(header, 1, 40, f) != 40) {
        fclose(f);
        return NULL;
    }

    // Check signature
    uint32_t signature;
    memcpy(&signature, header, 4);
    if (signature != LSPK_SIGNATURE) {
        fclose(f);
        return NULL;
    }

    // Parse header
    uint32_t version;
    uint64_t file_list_offset;
    uint32_t file_list_size;

    memcpy(&version, header + 4, 4);
    memcpy(&file_list_offset, header + 8, 8);
    memcpy(&file_list_size, header + 16, 4);

    // Seek to file list
    fseek(f, file_list_offset, SEEK_SET);

    // Read file count and compressed size
    uint32_t num_files, compressed_size;
    if (fread(&num_files, 4, 1, f) != 1 || fread(&compressed_size, 4, 1, f) != 1) {
        fclose(f);
        return NULL;
    }

    // Read compressed file list
    uint8_t *compressed_data = (uint8_t *)malloc(compressed_size);
    if (!compressed_data) {
        fclose(f);
        return NULL;
    }

    if (fread(compressed_data, 1, compressed_size, f) != compressed_size) {
        free(compressed_data);
        fclose(f);
        return NULL;
    }

    // Decompress file list (LZ4)
    uint32_t uncompressed_size = num_files * LSPK_ENTRY_SIZE;
    uint8_t *decompressed = (uint8_t *)malloc(uncompressed_size);
    if (!decompressed) {
        free(compressed_data);
        fclose(f);
        return NULL;
    }

    int result = LZ4_decompress_safe((const char *)compressed_data, (char *)decompressed,
                                      compressed_size, uncompressed_size);
    free(compressed_data);

    if (result < 0) {
        free(decompressed);
        fclose(f);
        return NULL;
    }

    // Parse entries
    PakEntry *entries = (PakEntry *)calloc(num_files, sizeof(PakEntry));
    if (!entries) {
        free(decompressed);
        fclose(f);
        return NULL;
    }

    for (uint32_t i = 0; i < num_files; i++) {
        uint8_t *entry_data = decompressed + (i * LSPK_ENTRY_SIZE);

        // Name: 256 bytes, null-terminated
        memcpy(entries[i].name, entry_data, 255);
        entries[i].name[255] = '\0';

        // Offset: 48-bit value (bytes 256-261)
        uint32_t offset_lo;
        uint16_t offset_hi;
        memcpy(&offset_lo, entry_data + 256, 4);
        memcpy(&offset_hi, entry_data + 260, 2);
        entries[i].offset = offset_lo | ((uint64_t)offset_hi << 32);

        entries[i].archive_part = entry_data[262];
        entries[i].compression = entry_data[263] & 0x0F;

        memcpy(&entries[i].disk_size, entry_data + 264, 4);
        memcpy(&entries[i].uncompressed_size, entry_data + 268, 4);
    }

    free(decompressed);

    // Create PakFile struct
    PakFile *pak = (PakFile *)malloc(sizeof(PakFile));
    if (!pak) {
        free(entries);
        fclose(f);
        return NULL;
    }

    pak->file = f;
    pak->version = version;
    pak->file_list_offset = file_list_offset;
    pak->file_list_size = file_list_size;
    pak->num_files = num_files;
    pak->entries = entries;

    return pak;
}

/**
 * Close a PAK file and free resources
 */
static void pak_close(PakFile *pak) {
    if (pak) {
        if (pak->file) fclose(pak->file);
        if (pak->entries) free(pak->entries);
        free(pak);
    }
}

/**
 * Find an entry in a PAK file by path
 * Returns entry index or -1 if not found
 */
static int pak_find_entry(PakFile *pak, const char *path) {
    if (!pak || !path) return -1;

    for (uint32_t i = 0; i < pak->num_files; i++) {
        if (strcmp(pak->entries[i].name, path) == 0) {
            return i;
        }
    }
    return -1;
}

/**
 * Read a file from a PAK archive
 * Returns allocated buffer with file contents, or NULL on failure
 * Caller must free the returned buffer
 * Sets *out_size to the uncompressed size
 */
static char *pak_read_file(PakFile *pak, int entry_idx, size_t *out_size) {
    if (!pak || entry_idx < 0 || entry_idx >= (int)pak->num_files) return NULL;

    PakEntry *entry = &pak->entries[entry_idx];

    // Seek to file data
    fseek(pak->file, entry->offset, SEEK_SET);

    // Read compressed/raw data
    uint8_t *disk_data = (uint8_t *)malloc(entry->disk_size);
    if (!disk_data) return NULL;

    if (fread(disk_data, 1, entry->disk_size, pak->file) != entry->disk_size) {
        free(disk_data);
        return NULL;
    }

    char *content = NULL;

    if (entry->compression == 0) {
        // Uncompressed
        content = (char *)malloc(entry->uncompressed_size + 1);
        if (content) {
            memcpy(content, disk_data, entry->uncompressed_size);
            content[entry->uncompressed_size] = '\0';
            if (out_size) *out_size = entry->uncompressed_size;
        }
    } else if (entry->compression == 1) {
        // zlib
        content = (char *)malloc(entry->uncompressed_size + 1);
        if (content) {
            uLongf dest_len = entry->uncompressed_size;
            if (uncompress((Bytef *)content, &dest_len, disk_data, entry->disk_size) == Z_OK) {
                content[dest_len] = '\0';
                if (out_size) *out_size = dest_len;
            } else {
                free(content);
                content = NULL;
            }
        }
    } else if (entry->compression == 2) {
        // LZ4
        content = (char *)malloc(entry->uncompressed_size + 1);
        if (content) {
            int result = LZ4_decompress_safe((const char *)disk_data, content,
                                              entry->disk_size, entry->uncompressed_size);
            if (result > 0) {
                content[result] = '\0';
                if (out_size) *out_size = result;
            } else {
                free(content);
                content = NULL;
            }
        }
    }

    free(disk_data);
    return content;
}

/**
 * Check if a PAK file contains a specific file path
 */
__attribute__((unused))
static int pak_contains_file(PakFile *pak, const char *path) {
    return pak_find_entry(pak, path) >= 0;
}

/**
 * Check if a PAK file contains ScriptExtender/Config.json with "Lua" feature
 */
static int pak_has_script_extender(const char *pak_path, const char *mod_name) {
    PakFile *pak = pak_open(pak_path);
    if (!pak) return 0;

    // Build path to Config.json
    char config_path[512];
    snprintf(config_path, sizeof(config_path),
             "Mods/%s/ScriptExtender/Config.json", mod_name);

    int entry_idx = pak_find_entry(pak, config_path);
    if (entry_idx < 0) {
        pak_close(pak);
        return 0;
    }

    // Read and check for "Lua"
    size_t size;
    char *content = pak_read_file(pak, entry_idx, &size);
    pak_close(pak);

    if (!content) return 0;

    int has_lua = (strstr(content, "\"Lua\"") != NULL);
    free(content);

    return has_lua;
}

/**
 * Find the PAK file containing a mod in the Mods folder
 * Returns 1 if found and sets pak_path_out, 0 if not found
 */
static int find_mod_pak(const char *mod_name, char *pak_path_out, size_t pak_path_size) {
    const char *home = getenv("HOME");
    if (!home) return 0;

    char mods_dir[MAX_PATH_LEN];
    snprintf(mods_dir, sizeof(mods_dir),
             "%s/Documents/Larian Studios/Baldur's Gate 3/Mods", home);

    DIR *dir = opendir(mods_dir);
    if (!dir) return 0;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        size_t name_len = strlen(entry->d_name);
        if (name_len > 4 && strcasecmp(entry->d_name + name_len - 4, ".pak") == 0) {
            char pak_path[MAX_PATH_LEN];
            snprintf(pak_path, sizeof(pak_path), "%s/%s", mods_dir, entry->d_name);

            // Check if this PAK contains our mod
            PakFile *pak = pak_open(pak_path);
            if (pak) {
                // Look for any file with our mod name in the path
                char mod_prefix[512];
                snprintf(mod_prefix, sizeof(mod_prefix), "Mods/%s/", mod_name);

                for (uint32_t i = 0; i < pak->num_files; i++) {
                    if (strncmp(pak->entries[i].name, mod_prefix, strlen(mod_prefix)) == 0) {
                        pak_close(pak);
                        closedir(dir);
                        strncpy(pak_path_out, pak_path, pak_path_size - 1);
                        pak_path_out[pak_path_size - 1] = '\0';
                        return 1;
                    }
                }
                pak_close(pak);
            }
        }
    }

    closedir(dir);
    return 0;
}

/**
 * Load and execute a Lua file from a PAK archive
 * Returns 1 on success, 0 on failure
 */
static int load_lua_from_pak(lua_State *L, const char *pak_path, const char *lua_path) {
    PakFile *pak = pak_open(pak_path);
    if (!pak) return 0;

    int entry_idx = pak_find_entry(pak, lua_path);
    if (entry_idx < 0) {
        pak_close(pak);
        return 0;
    }

    size_t size;
    char *content = pak_read_file(pak, entry_idx, &size);
    pak_close(pak);

    if (!content) return 0;

    // Execute the Lua code
    if (luaL_dostring(L, content) != LUA_OK) {
        const char *error = lua_tostring(L, -1);
        log_message("[Lua] PAK load error (%s): %s", lua_path, error);
        lua_pop(L, 1);
        free(content);
        return 0;
    }

    free(content);
    log_message("[Lua] Loaded from PAK: %s", lua_path);
    return 1;
}

/**
 * Write to both syslog and our log file
 */
static void log_message(const char *format, ...) {
    va_list args;
    char buffer[1024];

    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    // Write to syslog
    syslog(LOG_ERR, "[%s] %s", BG3SE_NAME, buffer);

    // Write to log file
    FILE *f = fopen(LOG_FILE, "a");
    if (f) {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
                t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                t->tm_hour, t->tm_min, t->tm_sec, buffer);
        fclose(f);
    }
}

// ============================================================================
// Mod Detection
// ============================================================================

/**
 * Check if a file contains a specific string
 * Returns 1 if found, 0 if not found or file doesn't exist
 */
static int file_contains_string(const char *filepath, const char *search_str) {
    FILE *f = fopen(filepath, "r");
    if (!f) return 0;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > 1024 * 1024) {  // Sanity check: max 1MB
        fclose(f);
        return 0;
    }

    char *content = (char *)malloc(size + 1);
    if (!content) {
        fclose(f);
        return 0;
    }

    fread(content, 1, size, f);
    content[size] = '\0';
    fclose(f);

    int found = (strstr(content, search_str) != NULL);
    free(content);
    return found;
}

/**
 * Check if a mod has ScriptExtender support by looking for Config.json
 * with "Lua" in FeatureFlags. Checks multiple possible locations.
 * Returns 1 if found, 0 if not an SE mod
 */
static int check_mod_has_script_extender(const char *mod_name) {
    char config_path[MAX_PATH_LEN];

    // Location 1: Extracted mod in /tmp/<ModName>_extracted/
    snprintf(config_path, sizeof(config_path),
             "/tmp/%s_extracted/Mods/%s/ScriptExtender/Config.json",
             mod_name, mod_name);
    if (file_contains_string(config_path, "\"Lua\"")) {
        log_message("[SE] Found Config.json with Lua for %s at: %s", mod_name, config_path);
        return 1;
    }

    // Location 2: Short extracted name (e.g., mrc_extracted for MoreReactiveCompanions_Configurable)
    // Try a few common short names
    const char *short_names[] = {"mrc", "se", "mod", NULL};
    for (int i = 0; short_names[i] != NULL; i++) {
        snprintf(config_path, sizeof(config_path),
                 "/tmp/%s_extracted/Mods/%s/ScriptExtender/Config.json",
                 short_names[i], mod_name);
        if (file_contains_string(config_path, "\"Lua\"")) {
            log_message("[SE] Found Config.json with Lua for %s at: %s", mod_name, config_path);
            return 1;
        }
    }

    // Location 3: User's Mods folder (unpacked mod)
    const char *home = getenv("HOME");
    if (home) {
        snprintf(config_path, sizeof(config_path),
                 "%s/Documents/Larian Studios/Baldur's Gate 3/Mods/%s/ScriptExtender/Config.json",
                 home, mod_name);
        if (file_contains_string(config_path, "\"Lua\"")) {
            log_message("[SE] Found Config.json with Lua for %s at: %s", mod_name, config_path);
            return 1;
        }
    }

    // Location 4: PAK file in Mods folder
    // Scan for PAK files that might contain this mod
    if (home) {
        char mods_dir[MAX_PATH_LEN];
        snprintf(mods_dir, sizeof(mods_dir),
                 "%s/Documents/Larian Studios/Baldur's Gate 3/Mods", home);

        DIR *dir = opendir(mods_dir);
        if (dir) {
            struct dirent *entry;
            while ((entry = readdir(dir)) != NULL) {
                // Check if it's a PAK file
                size_t name_len = strlen(entry->d_name);
                if (name_len > 4 && strcasecmp(entry->d_name + name_len - 4, ".pak") == 0) {
                    char pak_path[MAX_PATH_LEN];
                    snprintf(pak_path, sizeof(pak_path), "%s/%s", mods_dir, entry->d_name);

                    if (pak_has_script_extender(pak_path, mod_name)) {
                        log_message("[SE] Found SE mod %s in PAK: %s", mod_name, pak_path);
                        closedir(dir);
                        return 1;
                    }
                }
            }
            closedir(dir);
        }
    }

    return 0;
}

/**
 * Parse modsettings.lsx and detect enabled mods
 * Also identifies which mods have ScriptExtender support
 * The file is XML-based, we do simple string parsing to extract mod names
 */
static void detect_enabled_mods(void) {
    // Reset detected mods
    detected_mod_count = 0;
    se_mod_count = 0;

    // Build path to modsettings.lsx
    const char *home = getenv("HOME");
    if (!home) {
        log_message("Could not get HOME environment variable");
        return;
    }

    char path[1024];
    snprintf(path, sizeof(path),
             "%s/Documents/Larian Studios/Baldur's Gate 3/PlayerProfiles/Public/modsettings.lsx",
             home);

    FILE *f = fopen(path, "r");
    if (!f) {
        log_message("Could not open modsettings.lsx at: %s", path);
        return;
    }

    // Read entire file
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *content = (char *)malloc(size + 1);
    if (!content) {
        fclose(f);
        log_message("Out of memory reading modsettings.lsx");
        return;
    }

    fread(content, 1, size, f);
    content[size] = '\0';
    fclose(f);

    // Count and extract mod names
    // Look for: attribute id="Name" type="LSString" value="ModName"
    log_message("=== Enabled Mods ===");

    int mod_count = 0;
    char *ptr = content;
    const char *name_marker = "attribute id=\"Name\" type=\"LSString\" value=\"";
    size_t marker_len = strlen(name_marker);

    while ((ptr = strstr(ptr, name_marker)) != NULL) {
        ptr += marker_len;

        // Find the closing quote
        char *end = strchr(ptr, '"');
        if (end) {
            size_t name_len = end - ptr;
            if (name_len < MAX_MOD_NAME_LEN && detected_mod_count < MAX_MODS) {
                char mod_name[MAX_MOD_NAME_LEN];
                strncpy(mod_name, ptr, name_len);
                mod_name[name_len] = '\0';

                // Store in detected mods array
                strncpy(detected_mods[detected_mod_count], mod_name, MAX_MOD_NAME_LEN - 1);
                detected_mods[detected_mod_count][MAX_MOD_NAME_LEN - 1] = '\0';
                detected_mod_count++;

                mod_count++;
                // Skip GustavX as it's the base game, but still count it
                if (strcmp(mod_name, "GustavX") == 0) {
                    log_message("  [%d] %s (base game)", mod_count, mod_name);
                } else {
                    log_message("  [%d] %s", mod_count, mod_name);
                }
            }
            ptr = end;
        }
    }

    log_message("Total mods: %d (%d user mods)", mod_count, mod_count > 0 ? mod_count - 1 : 0);
    log_message("====================");

    free(content);

    // Now check which mods have Script Extender support
    log_message("=== Scanning for SE Mods ===");
    for (int i = 0; i < detected_mod_count; i++) {
        // Skip base game
        if (strcmp(detected_mods[i], "GustavX") == 0) continue;

        if (check_mod_has_script_extender(detected_mods[i])) {
            if (se_mod_count < MAX_MODS) {
                strncpy(se_mods[se_mod_count], detected_mods[i], MAX_MOD_NAME_LEN - 1);
                se_mods[se_mod_count][MAX_MOD_NAME_LEN - 1] = '\0';
                se_mod_count++;
                log_message("  [SE] %s", detected_mods[i]);
            }
        }
    }

    if (se_mod_count == 0) {
        log_message("  No SE mods detected (ensure mods are extracted to /tmp/)");
    } else {
        log_message("Total SE mods: %d", se_mod_count);
    }
    log_message("============================");
}

// ============================================================================
// Lua API: Ext namespace functions
// ============================================================================

/**
 * Ext.Print(...) - Print to BG3SE log
 */
static int lua_ext_print(lua_State *L) {
    int n = lua_gettop(L);
    luaL_Buffer b;
    luaL_buffinit(L, &b);

    for (int i = 1; i <= n; i++) {
        size_t len;
        const char *s = luaL_tolstring(L, i, &len);
        if (i > 1) luaL_addchar(&b, '\t');
        luaL_addlstring(&b, s, len);
        lua_pop(L, 1);  // pop the string from luaL_tolstring
    }

    luaL_pushresult(&b);
    const char *msg = lua_tostring(L, -1);
    log_message("[Lua] %s", msg);

    return 0;
}

/**
 * Ext.GetVersion() - Return BG3SE version
 */
static int lua_ext_getversion(lua_State *L) {
    lua_pushstring(L, BG3SE_VERSION);
    return 1;
}

/**
 * Ext.IsServer() - Check if running on server context
 */
static int lua_ext_isserver(lua_State *L) {
    // For now, always return false (client-side)
    lua_pushboolean(L, 0);
    return 1;
}

/**
 * Ext.IsClient() - Check if running on client context
 */
static int lua_ext_isclient(lua_State *L) {
    // For now, always return true (client-side)
    lua_pushboolean(L, 1);
    return 1;
}

/**
 * Check if a module has already been loaded
 */
static int is_module_loaded(const char *full_path) {
    for (int i = 0; i < loaded_module_count; i++) {
        if (strcmp(loaded_modules[i], full_path) == 0) {
            return 1;
        }
    }
    return 0;
}

/**
 * Mark a module as loaded
 */
static void mark_module_loaded(const char *full_path) {
    if (loaded_module_count < MAX_LOADED_MODULES) {
        strncpy(loaded_modules[loaded_module_count], full_path, MAX_PATH_LEN - 1);
        loaded_modules[loaded_module_count][MAX_PATH_LEN - 1] = '\0';
        loaded_module_count++;
    }
}

/**
 * Initialize the mods base path
 * Mods can be in:
 * 1. Steam workshop: ~/Library/Application Support/Steam/steamapps/workshop/content/1086940/
 * 2. Local mods: ~/Documents/Larian Studios/Baldur's Gate 3/Mods/
 * 3. Extracted mods (for development): /tmp/<modname>_extracted/
 */
static void init_mods_base_path(void) {
    const char *home = getenv("HOME");
    if (!home) return;

    // Use local mods directory by default
    snprintf(mods_base_path, sizeof(mods_base_path),
             "%s/Documents/Larian Studios/Baldur's Gate 3/Mods", home);

    log_message("Mods base path: %s", mods_base_path);
}

/**
 * Try to find and load a Lua file from various locations
 * Returns 1 if found and loaded successfully, 0 otherwise
 */
static int try_load_lua_file(lua_State *L, const char *full_path) {
    FILE *f = fopen(full_path, "r");
    if (!f) {
        return 0;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *content = (char *)malloc(size + 1);
    if (!content) {
        fclose(f);
        return 0;
    }

    fread(content, 1, size, f);
    content[size] = '\0';
    fclose(f);

    // Load and execute the Lua code
    int status = luaL_loadbuffer(L, content, size, full_path);
    free(content);

    if (status != LUA_OK) {
        log_message("[Lua] Error loading %s: %s", full_path, lua_tostring(L, -1));
        lua_pop(L, 1);
        return 0;
    }

    // Execute the loaded chunk
    if (lua_pcall(L, 0, LUA_MULTRET, 0) != LUA_OK) {
        log_message("[Lua] Error executing %s: %s", full_path, lua_tostring(L, -1));
        lua_pop(L, 1);
        return 0;
    }

    return 1;
}

/**
 * Ext.Require(path) - Load and execute a Lua module
 * Paths are relative to the current mod's ScriptExtender/Lua/ folder
 * Modules are cached - subsequent calls return cached results
 * Supports loading from both filesystem (extracted mods) and PAK files
 */
static int lua_ext_require(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    log_message("[Lua] Ext.Require('%s')", path);

    // Try filesystem first (for extracted mods)
    if (strlen(current_mod_lua_base) > 0) {
        // Build full path using the base path from where bootstrap was loaded
        char full_path[MAX_PATH_LEN];
        snprintf(full_path, sizeof(full_path), "%s/%s", current_mod_lua_base, path);

        // Check if already loaded
        if (is_module_loaded(full_path)) {
            log_message("[Lua] Module already loaded: %s", path);
            lua_pushnil(L);
            return 1;
        }

        // Try to load from the tracked base path
        if (try_load_lua_file(L, full_path)) {
            mark_module_loaded(full_path);
            log_message("[Lua] Loaded module from: %s", full_path);
            if (lua_gettop(L) == 0) {
                lua_pushnil(L);
            }
            return 1;
        }
    }

    // Try PAK file (for non-extracted mods)
    if (strlen(current_mod_pak_path) > 0 && strlen(current_mod_name) > 0) {
        char pak_lua_path[MAX_PATH_LEN];
        snprintf(pak_lua_path, sizeof(pak_lua_path),
                 "Mods/%s/ScriptExtender/Lua/%s", current_mod_name, path);

        // Check if already loaded (use PAK path as key)
        char cache_key[MAX_PATH_LEN];
        snprintf(cache_key, sizeof(cache_key), "pak:%s:%s", current_mod_pak_path, pak_lua_path);

        if (is_module_loaded(cache_key)) {
            log_message("[Lua] Module already loaded from PAK: %s", path);
            lua_pushnil(L);
            return 1;
        }

        if (load_lua_from_pak(L, current_mod_pak_path, pak_lua_path)) {
            mark_module_loaded(cache_key);
            log_message("[Lua] Loaded module from PAK: %s", pak_lua_path);
            if (lua_gettop(L) == 0) {
                lua_pushnil(L);
            }
            return 1;
        }
    }

    // Module not found
    log_message("[Lua] Warning: Module not found: %s", path);
    if (strlen(current_mod_lua_base) > 0) {
        log_message("[Lua]   Tried filesystem: %s/%s", current_mod_lua_base, path);
    }
    if (strlen(current_mod_pak_path) > 0) {
        log_message("[Lua]   Tried PAK: %s (Mods/%s/ScriptExtender/Lua/%s)",
                    current_mod_pak_path, current_mod_name, path);
    }

    lua_pushnil(L);
    return 1;
}

// Ext.IO namespace
static int lua_ext_io_loadfile(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    log_message("[Lua] Ext.IO.LoadFile('%s')", path);

    FILE *f = fopen(path, "r");
    if (!f) {
        lua_pushnil(L);
        lua_pushstring(L, "File not found");
        return 2;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *content = (char *)malloc(size + 1);
    if (!content) {
        fclose(f);
        lua_pushnil(L);
        lua_pushstring(L, "Out of memory");
        return 2;
    }

    fread(content, 1, size, f);
    content[size] = '\0';
    fclose(f);

    lua_pushstring(L, content);
    free(content);
    return 1;
}

static int lua_ext_io_savefile(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    const char *content = luaL_checkstring(L, 2);
    log_message("[Lua] Ext.IO.SaveFile('%s')", path);

    FILE *f = fopen(path, "w");
    if (!f) {
        lua_pushboolean(L, 0);
        return 1;
    }

    fputs(content, f);
    fclose(f);

    lua_pushboolean(L, 1);
    return 1;
}

// ============================================================================
// Simple JSON Parser
// ============================================================================

// Forward declarations for recursive parsing
static const char *json_parse_value(lua_State *L, const char *json);
static const char *json_skip_whitespace(const char *json);

static const char *json_skip_whitespace(const char *json) {
    while (*json && (*json == ' ' || *json == '\t' || *json == '\n' || *json == '\r')) {
        json++;
    }
    return json;
}

static const char *json_parse_string(lua_State *L, const char *json) {
    if (*json != '"') return NULL;
    json++;  // skip opening quote

    luaL_Buffer b;
    luaL_buffinit(L, &b);

    while (*json && *json != '"') {
        if (*json == '\\' && json[1]) {
            json++;
            switch (*json) {
                case '"': luaL_addchar(&b, '"'); break;
                case '\\': luaL_addchar(&b, '\\'); break;
                case '/': luaL_addchar(&b, '/'); break;
                case 'b': luaL_addchar(&b, '\b'); break;
                case 'f': luaL_addchar(&b, '\f'); break;
                case 'n': luaL_addchar(&b, '\n'); break;
                case 'r': luaL_addchar(&b, '\r'); break;
                case 't': luaL_addchar(&b, '\t'); break;
                default: luaL_addchar(&b, *json); break;
            }
        } else {
            luaL_addchar(&b, *json);
        }
        json++;
    }

    if (*json != '"') return NULL;
    luaL_pushresult(&b);
    return json + 1;  // skip closing quote
}

static const char *json_parse_number(lua_State *L, const char *json) {
    const char *start = json;
    if (*json == '-') json++;
    while (*json >= '0' && *json <= '9') json++;
    if (*json == '.') {
        json++;
        while (*json >= '0' && *json <= '9') json++;
    }
    if (*json == 'e' || *json == 'E') {
        json++;
        if (*json == '+' || *json == '-') json++;
        while (*json >= '0' && *json <= '9') json++;
    }

    char *endptr;
    double num = strtod(start, &endptr);
    lua_pushnumber(L, num);
    return json;
}

static const char *json_parse_object(lua_State *L, const char *json) {
    if (*json != '{') return NULL;
    json = json_skip_whitespace(json + 1);

    lua_newtable(L);

    if (*json == '}') return json + 1;

    while (1) {
        json = json_skip_whitespace(json);
        if (*json != '"') return NULL;

        // Parse key
        json = json_parse_string(L, json);
        if (!json) return NULL;

        json = json_skip_whitespace(json);
        if (*json != ':') return NULL;
        json = json_skip_whitespace(json + 1);

        // Parse value
        json = json_parse_value(L, json);
        if (!json) return NULL;

        // Set table[key] = value
        lua_settable(L, -3);

        json = json_skip_whitespace(json);
        if (*json == '}') return json + 1;
        if (*json != ',') return NULL;
        json++;
    }
}

static const char *json_parse_array(lua_State *L, const char *json) {
    if (*json != '[') return NULL;
    json = json_skip_whitespace(json + 1);

    lua_newtable(L);
    int index = 1;

    if (*json == ']') return json + 1;

    while (1) {
        json = json_skip_whitespace(json);
        json = json_parse_value(L, json);
        if (!json) return NULL;

        lua_rawseti(L, -2, index++);

        json = json_skip_whitespace(json);
        if (*json == ']') return json + 1;
        if (*json != ',') return NULL;
        json++;
    }
}

static const char *json_parse_value(lua_State *L, const char *json) {
    json = json_skip_whitespace(json);

    if (*json == '"') {
        return json_parse_string(L, json);
    } else if (*json == '{') {
        return json_parse_object(L, json);
    } else if (*json == '[') {
        return json_parse_array(L, json);
    } else if (*json == 't' && strncmp(json, "true", 4) == 0) {
        lua_pushboolean(L, 1);
        return json + 4;
    } else if (*json == 'f' && strncmp(json, "false", 5) == 0) {
        lua_pushboolean(L, 0);
        return json + 5;
    } else if (*json == 'n' && strncmp(json, "null", 4) == 0) {
        lua_pushnil(L);
        return json + 4;
    } else if (*json == '-' || (*json >= '0' && *json <= '9')) {
        return json_parse_number(L, json);
    }

    return NULL;
}

// Ext.Json namespace
static int lua_ext_json_parse(lua_State *L) {
    const char *json = luaL_checkstring(L, 1);
    log_message("[Lua] Ext.Json.Parse called (len: %zu)", strlen(json));

    const char *result = json_parse_value(L, json);
    if (!result) {
        lua_pushnil(L);
        log_message("[Lua] Ext.Json.Parse failed");
    }
    return 1;
}

static int lua_ext_json_stringify(lua_State *L);  // Forward declaration

static void json_stringify_value(lua_State *L, int index, luaL_Buffer *b);

static void json_stringify_table(lua_State *L, int index, luaL_Buffer *b) {
    // Check if it's an array (sequential integer keys starting from 1)
    int is_array = 1;
    int max_index = 0;

    lua_pushnil(L);
    while (lua_next(L, index) != 0) {
        if (lua_type(L, -2) != LUA_TNUMBER || lua_tointeger(L, -2) != max_index + 1) {
            is_array = 0;
        }
        max_index++;
        lua_pop(L, 1);
    }

    if (is_array && max_index > 0) {
        luaL_addchar(b, '[');
        for (int i = 1; i <= max_index; i++) {
            if (i > 1) luaL_addchar(b, ',');
            lua_rawgeti(L, index, i);
            json_stringify_value(L, lua_gettop(L), b);
            lua_pop(L, 1);
        }
        luaL_addchar(b, ']');
    } else {
        luaL_addchar(b, '{');
        int first = 1;
        lua_pushnil(L);
        while (lua_next(L, index) != 0) {
            if (!first) luaL_addchar(b, ',');
            first = 0;

            // Key
            luaL_addchar(b, '"');
            if (lua_type(L, -2) == LUA_TSTRING) {
                luaL_addstring(b, lua_tostring(L, -2));
            } else {
                lua_pushvalue(L, -2);
                luaL_addstring(b, lua_tostring(L, -1));
                lua_pop(L, 1);
            }
            luaL_addchar(b, '"');
            luaL_addchar(b, ':');

            // Value
            json_stringify_value(L, lua_gettop(L), b);
            lua_pop(L, 1);
        }
        luaL_addchar(b, '}');
    }
}

static void json_stringify_value(lua_State *L, int index, luaL_Buffer *b) {
    int t = lua_type(L, index);
    switch (t) {
        case LUA_TSTRING: {
            const char *s = lua_tostring(L, index);
            luaL_addchar(b, '"');
            while (*s) {
                if (*s == '"' || *s == '\\') {
                    luaL_addchar(b, '\\');
                }
                luaL_addchar(b, *s);
                s++;
            }
            luaL_addchar(b, '"');
            break;
        }
        case LUA_TNUMBER: {
            char buf[64];
            snprintf(buf, sizeof(buf), "%g", lua_tonumber(L, index));
            luaL_addstring(b, buf);
            break;
        }
        case LUA_TBOOLEAN:
            luaL_addstring(b, lua_toboolean(L, index) ? "true" : "false");
            break;
        case LUA_TTABLE:
            json_stringify_table(L, index, b);
            break;
        case LUA_TNIL:
        default:
            luaL_addstring(b, "null");
            break;
    }
}

static int lua_ext_json_stringify(lua_State *L) {
    luaL_Buffer b;
    luaL_buffinit(L, &b);
    json_stringify_value(L, 1, &b);
    luaL_pushresult(&b);
    return 1;
}

/**
 * Register the Ext API in Lua
 */
static void register_ext_api(lua_State *L) {
    // Create Ext table
    lua_newtable(L);

    // Basic functions
    lua_pushcfunction(L, lua_ext_print);
    lua_setfield(L, -2, "Print");

    lua_pushcfunction(L, lua_ext_getversion);
    lua_setfield(L, -2, "GetVersion");

    lua_pushcfunction(L, lua_ext_isserver);
    lua_setfield(L, -2, "IsServer");

    lua_pushcfunction(L, lua_ext_isclient);
    lua_setfield(L, -2, "IsClient");

    lua_pushcfunction(L, lua_ext_require);
    lua_setfield(L, -2, "Require");

    // Create Ext.IO table
    lua_newtable(L);
    lua_pushcfunction(L, lua_ext_io_loadfile);
    lua_setfield(L, -2, "LoadFile");
    lua_pushcfunction(L, lua_ext_io_savefile);
    lua_setfield(L, -2, "SaveFile");
    lua_setfield(L, -2, "IO");

    // Create Ext.Json table
    lua_newtable(L);
    lua_pushcfunction(L, lua_ext_json_parse);
    lua_setfield(L, -2, "Parse");
    lua_pushcfunction(L, lua_ext_json_stringify);
    lua_setfield(L, -2, "Stringify");
    lua_setfield(L, -2, "Json");

    // Set Ext as global
    lua_setglobal(L, "Ext");

    log_message("Ext API registered in Lua");
}

// ============================================================================
// Ext.Osiris namespace - Event listener registration
// ============================================================================

// Storage for registered Osiris listeners
#define MAX_OSIRIS_LISTENERS 64
typedef struct {
    char event_name[128];
    int arity;
    char timing[16];  // "before" or "after"
    int callback_ref;  // Lua registry reference
} OsirisListener;

static OsirisListener osiris_listeners[MAX_OSIRIS_LISTENERS];
static int osiris_listener_count = 0;

/**
 * Ext.Osiris.RegisterListener(event, arity, timing, callback)
 * Registers a callback for an Osiris event
 */
static int lua_ext_osiris_registerlistener(lua_State *L) {
    const char *event = luaL_checkstring(L, 1);
    int arity = (int)luaL_checkinteger(L, 2);
    const char *timing = luaL_checkstring(L, 3);
    luaL_checktype(L, 4, LUA_TFUNCTION);

    if (osiris_listener_count >= MAX_OSIRIS_LISTENERS) {
        log_message("[Lua] Warning: Max Osiris listeners reached");
        return 0;
    }

    // Store the listener
    OsirisListener *listener = &osiris_listeners[osiris_listener_count];
    strncpy(listener->event_name, event, sizeof(listener->event_name) - 1);
    listener->arity = arity;
    strncpy(listener->timing, timing, sizeof(listener->timing) - 1);

    // Store callback reference in Lua registry
    lua_pushvalue(L, 4);  // Push the function
    listener->callback_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    osiris_listener_count++;

    log_message("[Lua] Registered Osiris listener: %s (arity=%d, timing=%s)",
                event, arity, timing);

    return 0;
}

/**
 * Register Ext.Osiris namespace
 */
static void register_ext_osiris(lua_State *L) {
    // Get Ext table
    lua_getglobal(L, "Ext");

    // Create Ext.Osiris table
    lua_newtable(L);

    lua_pushcfunction(L, lua_ext_osiris_registerlistener);
    lua_setfield(L, -2, "RegisterListener");

    lua_setfield(L, -2, "Osiris");

    lua_pop(L, 1);  // Pop Ext table

    log_message("Ext.Osiris API registered");
}

// ============================================================================
// Osi namespace - Osiris function bindings (stubs)
// ============================================================================

/**
 * GetHostCharacter() - Returns the host player's character UUID
 * For now returns a placeholder string
 */
static int lua_gethostcharacter(lua_State *L) {
    // Find the host character - it's the player GUID that doesn't match origin companions
    // Origin companions have GUIDs like "S_Player_Astarion_xxx", "S_Player_Gale_xxx", etc.
    // The custom/host character has a different pattern (e.g., "HalfElves_Male_High_Player_Dev_xxx")
    const char *hostGuid = NULL;

    for (int i = 0; i < g_knownPlayerCount; i++) {
        const char *guid = g_knownPlayerGuids[i];
        // Check if this is NOT an origin companion (origin companions start with "S_Player_")
        if (strncmp(guid, "S_Player_", 9) != 0) {
            hostGuid = guid;
            break;
        }
    }

    // Fallback: if no custom character found, return first player
    if (!hostGuid && g_knownPlayerCount > 0) {
        hostGuid = g_knownPlayerGuids[0];
    }

    if (hostGuid) {
        log_message("[Lua] GetHostCharacter() -> '%s'", hostGuid);
        lua_pushstring(L, hostGuid);
    } else {
        log_message("[Lua] GetHostCharacter() -> nil (no players discovered yet)");
        lua_pushnil(L);
    }
    return 1;
}

/**
 * Osi.IsTagged(character, tag) - Check if character has a tag
 * Uses real Osiris query when available, falls back to heuristics
 */
static int lua_osi_istagged(lua_State *L) {
    const char *character = luaL_checkstring(L, 1);
    const char *tag = luaL_checkstring(L, 2);

    int result = 0;

    // Try real Osiris query first
    if (pfn_InternalQuery) {
        int osi_result = osi_is_tagged(character, tag);
        if (osi_result >= 0) {
            // Real query succeeded
            log_message("[Lua] Osi.IsTagged('%s', '%s') -> %d (via Osiris)", character, tag, osi_result);
            lua_pushboolean(L, osi_result);
            return 1;
        }
        // Fall through to heuristic if function not found
    }

    // Fallback: heuristic for dialog-related tags
    // Tag 306b9b05-1057-4770-aa17-01af21acd650 checks dialog participation
    if (strcmp(tag, "306b9b05-1057-4770-aa17-01af21acd650") == 0) {
        // Return true for any known player character when in a dialog
        if (g_currentDialogResource[0] != '\0') {
            // We're in a dialog - check if this is a known player
            for (int i = 0; i < g_knownPlayerCount; i++) {
                if (strcmp(g_knownPlayerGuids[i], character) == 0) {
                    result = 1;
                    break;
                }
            }
        }
    }

    log_message("[Lua] Osi.IsTagged('%s', '%s') -> %d (heuristic)", character, tag, result);
    lua_pushboolean(L, result);
    return 1;
}

/**
 * Osi.GetDistanceTo(char1, char2) - Get distance between characters
 * Uses real Osiris query when available, falls back to 0
 */
static int lua_osi_getdistanceto(lua_State *L) {
    const char *char1 = luaL_checkstring(L, 1);
    const char *char2 = luaL_checkstring(L, 2);

    // Try real Osiris query first
    if (pfn_InternalQuery) {
        float distance = osi_get_distance_to(char1, char2);
        if (distance >= 0.0f) {
            log_message("[Lua] Osi.GetDistanceTo('%s', '%s') -> %.2f (via Osiris)", char1, char2, distance);
            lua_pushnumber(L, distance);
            return 1;
        }
        // Fall through if function not found
    }

    log_message("[Lua] Osi.GetDistanceTo('%s', '%s') -> 0.0 (fallback)", char1, char2);
    lua_pushnumber(L, 0.0);
    return 1;
}

/**
 * Osi.DialogGetNumberOfInvolvedPlayers(instance_id) - Get player count in dialog
 * Returns the tracked player count (default 1 for single-player)
 */
static int lua_osi_dialoggetnumberofinvolvedplayers(lua_State *L) {
    int instance_id = -1;
    if (lua_gettop(L) >= 1) {
        if (lua_isinteger(L, 1)) {
            instance_id = (int)lua_tointeger(L, 1);
        } else if (lua_isnumber(L, 1)) {
            instance_id = (int)lua_tonumber(L, 1);
        }
    }
    log_message("[Lua] Osi.DialogGetNumberOfInvolvedPlayers(%d) -> %d",
                instance_id, g_currentDialogPlayerCount);
    lua_pushinteger(L, g_currentDialogPlayerCount);
    return 1;
}

/**
 * Osi.SpeakerGetDialog(character, index) - Get dialog resource
 * Returns the current dialog resource if we've captured one
 */
static int lua_osi_speakergetdialog(lua_State *L) {
    const char *character = "";
    int index = 0;
    if (lua_gettop(L) >= 1 && lua_isstring(L, 1)) {
        character = lua_tostring(L, 1);
    }
    if (lua_gettop(L) >= 2) {
        if (lua_isinteger(L, 2)) {
            index = (int)lua_tointeger(L, 2);
        } else if (lua_isnumber(L, 2)) {
            index = (int)lua_tonumber(L, 2);
        }
    }
    log_message("[Lua] Osi.SpeakerGetDialog('%s', %d) -> '%s'",
                character, index, g_currentDialogResource);
    lua_pushstring(L, g_currentDialogResource);
    return 1;
}

/**
 * Osi.DialogRequestStop(dialog) - Stop a dialog
 * Uses real Osiris call when available
 */
static int lua_osi_dialogrequeststop(lua_State *L) {
    const char *dialog = NULL;
    if (lua_gettop(L) >= 1 && lua_isstring(L, 1)) {
        dialog = lua_tostring(L, 1);
    }

    // Try real Osiris call first
    if (pfn_InternalCall && dialog) {
        log_message("[Lua] Osi.DialogRequestStop('%s') - calling Osiris", dialog);
        osi_dialog_request_stop(dialog);
    } else {
        log_message("[Lua] Osi.DialogRequestStop() called (no-op: %s)",
                    dialog ? "InternalCall not available" : "no dialog specified");
    }

    return 0;
}

/**
 * Osi.QRY_StartDialog_Fixed(resource, character) - Start a dialog
 * Uses real Osiris query when available
 */
static int lua_osi_qry_startdialog_fixed(lua_State *L) {
    const char *resource = luaL_optstring(L, 1, NULL);
    const char *character = luaL_optstring(L, 2, NULL);

    // Try real Osiris query first
    if (pfn_InternalQuery && resource && character) {
        uint32_t funcId = lookup_function_by_name("QRY_StartDialog_Fixed");
        if (funcId != INVALID_FUNCTION_ID) {
            OsiArgumentDesc *args = alloc_args(2);
            if (args) {
                set_arg_string(&args[0], resource, 0);   // String (resource)
                set_arg_string(&args[1], character, 1);  // GUID
                int result = osiris_query_by_id(funcId, args);
                log_message("[Lua] Osi.QRY_StartDialog_Fixed('%s', '%s') -> %d (via Osiris)",
                           resource, character, result);
                lua_pushboolean(L, result);
                return 1;
            }
        }
    }

    log_message("[Lua] Osi.QRY_StartDialog_Fixed('%s', '%s') -> false (fallback)",
                resource ? resource : "nil", character ? character : "nil");
    lua_pushboolean(L, 0);
    return 1;
}

/**
 * Check if a GUID looks like a player character
 * Player GUIDs typically start with "S_Player_" in BG3
 */
static int is_player_guid(const char *guid) {
    if (!guid) return 0;
    // Player characters have "S_Player_" prefix
    if (strncmp(guid, "S_Player_", 9) == 0) return 1;
    // Also check for common player names (Tav, custom characters)
    if (strstr(guid, "_Player_") != NULL) return 1;
    return 0;
}

/**
 * Track a player GUID if we haven't seen it before
 */
static void track_player_guid(const char *guid) {
    if (!guid || !is_player_guid(guid)) return;
    if (g_knownPlayerCount >= MAX_KNOWN_PLAYERS) return;

    // Check if already tracked
    for (int i = 0; i < g_knownPlayerCount; i++) {
        if (strcmp(g_knownPlayerGuids[i], guid) == 0) return;
    }

    // Add to list
    strncpy(g_knownPlayerGuids[g_knownPlayerCount], guid,
            sizeof(g_knownPlayerGuids[0]) - 1);
    g_knownPlayerGuids[g_knownPlayerCount][sizeof(g_knownPlayerGuids[0]) - 1] = '\0';
    g_knownPlayerCount++;
    log_message("[Players] Discovered player: %s (total: %d)", guid, g_knownPlayerCount);
}

/**
 * DB_Players database accessor
 * Creates a table with a :Get() method that returns player list
 */
static int lua_osi_db_players_get(lua_State *L) {
    log_message("[Lua] Osi.DB_Players:Get() called, known players: %d", g_knownPlayerCount);

    // Return table of known players: { {guid1}, {guid2}, ... }
    lua_newtable(L);

    for (int i = 0; i < g_knownPlayerCount; i++) {
        // Each entry is a table with the GUID as first element
        lua_newtable(L);
        lua_pushstring(L, g_knownPlayerGuids[i]);
        lua_rawseti(L, -2, 1);  // t[1] = guid
        lua_rawseti(L, -2, i + 1);  // result[i+1] = {guid}
    }

    return 1;
}

/**
 * Register Osi namespace with stub functions
 */
static void register_osi_namespace(lua_State *L) {
    // Create Osi table
    lua_newtable(L);

    // Basic Osiris functions
    lua_pushcfunction(L, lua_osi_istagged);
    lua_setfield(L, -2, "IsTagged");

    lua_pushcfunction(L, lua_osi_getdistanceto);
    lua_setfield(L, -2, "GetDistanceTo");

    lua_pushcfunction(L, lua_osi_dialoggetnumberofinvolvedplayers);
    lua_setfield(L, -2, "DialogGetNumberOfInvolvedPlayers");

    lua_pushcfunction(L, lua_osi_speakergetdialog);
    lua_setfield(L, -2, "SpeakerGetDialog");

    lua_pushcfunction(L, lua_osi_dialogrequeststop);
    lua_setfield(L, -2, "DialogRequestStop");

    lua_pushcfunction(L, lua_osi_qry_startdialog_fixed);
    lua_setfield(L, -2, "QRY_StartDialog_Fixed");

    // Create DB_Players table with :Get() method
    lua_newtable(L);
    lua_pushcfunction(L, lua_osi_db_players_get);
    lua_setfield(L, -2, "Get");
    lua_setfield(L, -2, "DB_Players");

    // Set Osi as global
    lua_setglobal(L, "Osi");

    // Also register GetHostCharacter as a global function
    lua_pushcfunction(L, lua_gethostcharacter);
    lua_setglobal(L, "GetHostCharacter");

    log_message("Osi namespace registered (stubs)");
}

/**
 * _P(...) - Print debug message (BG3SE compatibility)
 * Same as Ext.Print()
 */
static int lua_global_print(lua_State *L) {
    return lua_ext_print(L);
}

/**
 * _D(value) - Dump value for debugging (BG3SE compatibility)
 * Prints a detailed representation of the value
 */
static int lua_global_dump(lua_State *L) {
    int t = lua_type(L, 1);
    const char *tname = lua_typename(L, t);

    switch (t) {
        case LUA_TNIL:
            log_message("[Lua] _D: nil");
            break;
        case LUA_TBOOLEAN:
            log_message("[Lua] _D: %s", lua_toboolean(L, 1) ? "true" : "false");
            break;
        case LUA_TNUMBER:
            log_message("[Lua] _D: %g", lua_tonumber(L, 1));
            break;
        case LUA_TSTRING:
            log_message("[Lua] _D: \"%s\"", lua_tostring(L, 1));
            break;
        case LUA_TTABLE: {
            // Use JSON stringify for tables
            luaL_Buffer b;
            luaL_buffinit(L, &b);
            json_stringify_value(L, 1, &b);
            luaL_pushresult(&b);
            log_message("[Lua] _D: %s", lua_tostring(L, -1));
            lua_pop(L, 1);
            break;
        }
        default:
            log_message("[Lua] _D: <%s: %p>", tname, lua_topointer(L, 1));
            break;
    }

    return 0;
}

/**
 * Register global debug functions (_P, _D)
 */
static void register_global_functions(lua_State *L) {
    lua_pushcfunction(L, lua_global_print);
    lua_setglobal(L, "_P");

    lua_pushcfunction(L, lua_global_dump);
    lua_setglobal(L, "_D");

    log_message("Global debug functions registered (_P, _D)");
}

/**
 * Try to load a mod's bootstrap script
 * Returns 1 if loaded successfully, 0 if not found, -1 on error
 */
static int load_mod_bootstrap(lua_State *L, const char *mod_name, const char *bootstrap_type) {
    char full_path[MAX_PATH_LEN];
    char bootstrap_file[64];

    snprintf(bootstrap_file, sizeof(bootstrap_file), "Bootstrap%s.lua", bootstrap_type);

    // Set current mod name for Ext.Require
    strncpy(current_mod_name, mod_name, sizeof(current_mod_name) - 1);
    current_mod_name[sizeof(current_mod_name) - 1] = '\0';

    // First try extracted mods in /tmp (for development)
    // Note: The extraction creates a different structure, let's check the actual path
    char lua_base[MAX_PATH_LEN];

    snprintf(lua_base, sizeof(lua_base),
             "/tmp/%s_extracted/Mods/%s/ScriptExtender/Lua",
             mod_name, mod_name);
    snprintf(full_path, sizeof(full_path), "%s/%s", lua_base, bootstrap_file);

    log_message("[Lua] Looking for %s bootstrap: %s", mod_name, full_path);

    // Check if file exists before trying to load (so we can set base path first)
    FILE *test_f = fopen(full_path, "r");
    if (test_f) {
        fclose(test_f);
        // Set base path BEFORE loading so Ext.Require works during bootstrap
        strncpy(current_mod_lua_base, lua_base, sizeof(current_mod_lua_base) - 1);
        log_message("[Lua] Set mod Lua base: %s", current_mod_lua_base);
        if (try_load_lua_file(L, full_path)) {
            log_message("[Lua] Loaded %s %s", mod_name, bootstrap_file);
            return 1;
        }
    }

    // Try alternative extraction path (mrc -> mrc_extracted structure varies)
    snprintf(lua_base, sizeof(lua_base),
             "/tmp/mrc_extracted/Mods/%s/ScriptExtender/Lua",
             mod_name);
    snprintf(full_path, sizeof(full_path), "%s/%s", lua_base, bootstrap_file);

    test_f = fopen(full_path, "r");
    if (test_f) {
        fclose(test_f);
        strncpy(current_mod_lua_base, lua_base, sizeof(current_mod_lua_base) - 1);
        log_message("[Lua] Set mod Lua base: %s", current_mod_lua_base);
        if (try_load_lua_file(L, full_path)) {
            log_message("[Lua] Loaded %s %s from mrc_extracted", mod_name, bootstrap_file);
            return 1;
        }
    }

    // Try local mods directory
    snprintf(lua_base, sizeof(lua_base),
             "%s/%s/ScriptExtender/Lua",
             mods_base_path, mod_name);
    snprintf(full_path, sizeof(full_path), "%s/%s", lua_base, bootstrap_file);

    test_f = fopen(full_path, "r");
    if (test_f) {
        fclose(test_f);
        strncpy(current_mod_lua_base, lua_base, sizeof(current_mod_lua_base) - 1);
        log_message("[Lua] Set mod Lua base: %s", current_mod_lua_base);
        if (try_load_lua_file(L, full_path)) {
            log_message("[Lua] Loaded %s %s", mod_name, bootstrap_file);
            return 1;
        }
    }

    // Try loading from PAK file in Mods folder
    char pak_path[MAX_PATH_LEN];
    if (find_mod_pak(mod_name, pak_path, sizeof(pak_path))) {
        char pak_lua_path[MAX_PATH_LEN];
        snprintf(pak_lua_path, sizeof(pak_lua_path),
                 "Mods/%s/ScriptExtender/Lua/%s", mod_name, bootstrap_file);

        log_message("[Lua] Trying to load %s from PAK: %s", bootstrap_file, pak_path);

        // Store current PAK path for Ext.Require to use
        strncpy(current_mod_pak_path, pak_path, sizeof(current_mod_pak_path) - 1);
        current_mod_pak_path[sizeof(current_mod_pak_path) - 1] = '\0';

        // Clear filesystem base path since we're loading from PAK
        current_mod_lua_base[0] = '\0';

        if (load_lua_from_pak(L, pak_path, pak_lua_path)) {
            log_message("[Lua] Loaded %s %s from PAK", mod_name, bootstrap_file);
            return 1;
        }

        // Clear PAK path on failure
        current_mod_pak_path[0] = '\0';
    }

    // Clear mod name if not found
    current_mod_name[0] = '\0';

    log_message("[Lua] Bootstrap not found for mod: %s (%s)", mod_name, bootstrap_file);
    return 0;
}

/**
 * Load all mod bootstraps for SE-enabled mods
 * Uses the dynamically detected se_mods[] array populated by detect_enabled_mods()
 */
static void load_mod_scripts(lua_State *L) {
    log_message("=== Loading Mod Scripts ===");

    // Initialize the mods base path
    init_mods_base_path();

    // Check if we have any SE mods detected
    if (se_mod_count == 0) {
        log_message("[Lua] No SE mods detected to load");
        log_message("=== Mod Script Loading Complete ===");
        return;
    }

    log_message("[Lua] Loading %d detected SE mod(s)...", se_mod_count);

    for (int i = 0; i < se_mod_count; i++) {
        const char *mod_name = se_mods[i];
        log_message("[Lua] Attempting to load SE mod: %s", mod_name);

        // Try to load server bootstrap (runs on both client and server in BG3)
        if (load_mod_bootstrap(L, mod_name, "Server") > 0) {
            log_message("[Lua] Successfully loaded server scripts for: %s", mod_name);
        }

        // Also try client bootstrap if it exists
        if (load_mod_bootstrap(L, mod_name, "Client") > 0) {
            log_message("[Lua] Successfully loaded client scripts for: %s", mod_name);
        }
    }

    log_message("=== Mod Script Loading Complete ===");
}

/**
 * Initialize Lua runtime
 */
static void init_lua(void) {
    log_message("Initializing Lua runtime...");

    L = luaL_newstate();
    if (!L) {
        log_message("ERROR: Failed to create Lua state");
        return;
    }

    // Open standard libraries
    luaL_openlibs(L);

    // Register our Ext API
    register_ext_api(L);

    // Register Ext.Osiris namespace
    register_ext_osiris(L);

    // Register Osi namespace (stub functions)
    register_osi_namespace(L);

    // Register global debug functions
    register_global_functions(L);

    // Run a test script
    const char *test_script =
        "Ext.Print('BG3SE-macOS Lua runtime initialized!')\n"
        "Ext.Print('Version: ' .. Ext.GetVersion())\n"
        "Ext.Print('IsClient: ' .. tostring(Ext.IsClient()))\n"
        "Ext.Print('IsServer: ' .. tostring(Ext.IsServer()))\n"
        "-- Test JSON parsing\n"
        "local json = '{\"name\": \"test\", \"value\": 42, \"enabled\": true}'\n"
        "local parsed = Ext.Json.Parse(json)\n"
        "if parsed then\n"
        "  Ext.Print('JSON Parse test: name=' .. tostring(parsed.name) .. ', value=' .. tostring(parsed.value))\n"
        "end\n"
        "-- Test _P and _D\n"
        "_P('Debug print test via _P')\n"
        "_D({test = 'table', num = 123})\n";

    if (luaL_dostring(L, test_script) != LUA_OK) {
        const char *error = lua_tostring(L, -1);
        log_message("Lua error: %s", error);
        lua_pop(L, 1);
    }

    log_message("Lua %s initialized", LUA_VERSION);
}

/**
 * Shutdown Lua runtime
 */
static void shutdown_lua(void) {
    if (L) {
        log_message("Shutting down Lua runtime...");
        lua_close(L);
        L = NULL;
    }
}

// ============================================================================
// Osiris Hooks
// ============================================================================

// Track if mod scripts have been loaded
static int mod_scripts_loaded = 0;

/**
 * Hooked COsiris::InitGame - called when game initializes Osiris
 * Mangled name: _ZN7COsiris8InitGameEv
 * This is a member function, so 'this' pointer is first arg
 */
static void fake_InitGame(void *thisPtr) {
    initGame_call_count++;
    log_message(">>> COsiris::InitGame called! (count: %d, this: %p)", initGame_call_count, thisPtr);

    // Capture COsiris pointer for function lookups
    if (!g_COsiris) {
        g_COsiris = thisPtr;
        log_message("  Captured COsiris instance: %p", g_COsiris);

        // Try to find function manager - it may be at a fixed offset in COsiris
        // or it may be the same object (COsiris might inherit from COsiFunctionMan)
        if (!g_OsiFunctionMan) {
            g_OsiFunctionMan = thisPtr;  // Try using COsiris directly first
            log_message("  Using COsiris as function manager: %p", g_OsiFunctionMan);
        }
    }

    // Call original
    if (orig_InitGame) {
        ((void (*)(void*))orig_InitGame)(thisPtr);
    }

    log_message(">>> COsiris::InitGame returned");

    // Enumerate Osiris functions after initialization (only once)
    static int functions_enumerated = 0;
    if (!functions_enumerated && g_pOsiFunctionMan && *g_pOsiFunctionMan) {
        functions_enumerated = 1;
        enumerate_osiris_functions();
    }

    // Notify Lua that Osiris is initialized
    if (L) {
        luaL_dostring(L, "Ext.Print('Osiris initialized!')");

        // Load mod scripts after Osiris is initialized (only once)
        if (!mod_scripts_loaded) {
            mod_scripts_loaded = 1;
            load_mod_scripts(L);
        }
    }
}

/**
 * Hooked COsiris::Load - called when loading save/story data
 * Mangled name: _ZN7COsiris4LoadER12COsiSmartBuf
 * Signature: bool COsiris::Load(COsiSmartBuf&)
 * This is a member function with a reference parameter, returns bool
 */
static int fake_Load(void *thisPtr, void *smartBuf) {
    load_call_count++;
    log_message(">>> COsiris::Load called! (count: %d, this: %p, buf: %p)", load_call_count, thisPtr, smartBuf);

    // Call original and preserve return value
    int result = 0;
    if (orig_Load) {
        result = ((int (*)(void*, void*))orig_Load)(thisPtr, smartBuf);
    }

    log_message(">>> COsiris::Load returned: %d", result);

    // Notify Lua that a save was loaded
    if (L && result) {
        luaL_dostring(L, "Ext.Print('Story/save data loaded!')");

        // Load mod scripts after save is loaded (if not already loaded)
        // This handles the case where InitGame wasn't called (loading existing save)
        if (!mod_scripts_loaded) {
            mod_scripts_loaded = 1;
            load_mod_scripts(L);
        }
    }

    return result;
}

/**
 * Initialize the function hash table
 */
static void init_func_hash_table(void) {
    for (int i = 0; i < FUNC_HASH_SIZE; i++) {
        g_funcIdHashTable[i] = -1;
    }
}

/**
 * Hash function for function ID lookup
 */
static inline int func_id_hash(uint32_t funcId) {
    // Simple hash - use lower bits, handling type flag
    return (int)((funcId ^ (funcId >> 13)) & (FUNC_HASH_SIZE - 1));
}

/**
 * Add a function to the cache
 */
static void cache_function(const char *name, uint32_t funcId, uint8_t arity, uint8_t type) {
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

/**
 * Try to extract function name from a function definition pointer
 * The structure layout is empirically determined
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

/**
 * Probe structure layout by dumping bytes from a function definition
 * This is called once during cache building for debugging
 */
__attribute__((unused))
static void probe_funcdef_structure(void *funcDef, uint32_t funcId) {
    if (!funcDef) return;

    uint8_t *p = (uint8_t *)funcDef;
    log_message("[FuncDef] Probing structure for funcId=%u at %p", funcId, funcDef);

    // Dump first 64 bytes
    log_message("  bytes[0-31]:  %02x%02x%02x%02x %02x%02x%02x%02x "
               "%02x%02x%02x%02x %02x%02x%02x%02x "
               "%02x%02x%02x%02x %02x%02x%02x%02x "
               "%02x%02x%02x%02x %02x%02x%02x%02x",
               p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
               p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15],
               p[16],p[17],p[18],p[19],p[20],p[21],p[22],p[23],
               p[24],p[25],p[26],p[27],p[28],p[29],p[30],p[31]);
    log_message("  bytes[32-63]: %02x%02x%02x%02x %02x%02x%02x%02x "
               "%02x%02x%02x%02x %02x%02x%02x%02x "
               "%02x%02x%02x%02x %02x%02x%02x%02x "
               "%02x%02x%02x%02x %02x%02x%02x%02x",
               p[32],p[33],p[34],p[35],p[36],p[37],p[38],p[39],
               p[40],p[41],p[42],p[43],p[44],p[45],p[46],p[47],
               p[48],p[49],p[50],p[51],p[52],p[53],p[54],p[55],
               p[56],p[57],p[58],p[59],p[60],p[61],p[62],p[63]);

    // Try to interpret as pointers
    void **ptrs = (void **)p;
    log_message("  ptr[0] (vtable?): %p", ptrs[0]);
    log_message("  ptr[1] (name?):   %p", ptrs[1]);
    log_message("  ptr[2]:           %p", ptrs[2]);
    log_message("  ptr[3]:           %p", ptrs[3]);

    // Try to read strings at various offsets
    for (int off = 8; off <= 32; off += 8) {
        void *candidate = *(void **)(p + off);
        if (candidate && (uintptr_t)candidate > 0x100000000ULL) {
            // Looks like a valid pointer, try to read as string
            char *str = (char *)candidate;
            // Check if first char is printable
            if (str[0] >= 0x20 && str[0] < 0x7f) {
                log_message("  offset %d -> possible string: %.40s", off, str);
            }
        }
    }
}

/**
 * Track a function ID we've seen (for analysis purposes)
 */
static void track_seen_func_id(uint32_t funcId, uint8_t arity) {
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

/**
 * Try to get function definition and cache it
 * Uses the global OsiFunctionMan if available
 */
static int try_cache_function_by_id(uint32_t funcId) {
    // Need both the function pointer and the manager instance
    if (!pfn_pFunctionData || !g_pOsiFunctionMan || !*g_pOsiFunctionMan) {
        return 0;
    }

    void *funcMan = *g_pOsiFunctionMan;
    void *funcDef = pfn_pFunctionData(funcMan, funcId);

    if (funcDef) {
        const char *name = extract_func_name_from_def(funcDef);
        if (name && name[0]) {
            // Determine arity from structure (offset 21 based on OsiFunctionDef)
            uint8_t *p = (uint8_t *)funcDef;
            uint8_t arity = p[21];  // numInParams
            uint8_t type = p[20];   // funcType

            cache_function(name, funcId, arity, type);
            return 1;
        }
    }

    return 0;
}

/**
 * Enumerate Osiris functions by probing ID ranges
 * Called once during initialization to build the function cache
 */
static void enumerate_osiris_functions(void) {
    if (!pfn_pFunctionData || !g_pOsiFunctionMan || !*g_pOsiFunctionMan) {
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
        if (try_cache_function_by_id(id)) {
            found_count++;
        }
    }

    // Probe high range (registered functions) - 0x80000000 + 0 to ~30000
    for (uint32_t offset = 0; offset < 30000 && found_count < 2000; offset++) {
        uint32_t id = 0x80000000 | offset;
        if (try_cache_function_by_id(id)) {
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
        uint32_t fid = lookup_function_by_name(key_funcs[i]);
        if (fid != INVALID_FUNCTION_ID) {
            log_message("  %s -> 0x%08x", key_funcs[i], fid);
        }
    }
}

/**
 * Cache function from observed event (called from event handler)
 * This is a fallback when enumeration didn't find everything
 */
static void try_cache_function_from_event(uint32_t funcId) {
    // Skip if already cached
    if (get_function_name(funcId) != NULL) {
        return;
    }

    // Try to get the function definition
    try_cache_function_by_id(funcId);
}

/**
 * Get function name from function ID
 * First checks known events table, then the dynamic cache
 */
static const char *get_function_name(uint32_t funcId) {
    // Check known events table first (hardcoded mappings)
    for (int i = 0; g_knownEvents[i].name != NULL; i++) {
        if (g_knownEvents[i].funcId == funcId) {
            return g_knownEvents[i].name;
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

/**
 * Look up function ID by name
 * Returns INVALID_FUNCTION_ID if not found
 */
static uint32_t lookup_function_by_name(const char *name) {
    if (!name) return INVALID_FUNCTION_ID;

    // Check known events first (fast path for common names)
    for (int i = 0; g_knownEvents[i].name != NULL; i++) {
        if (strcmp(g_knownEvents[i].name, name) == 0 && g_knownEvents[i].funcId != 0) {
            return g_knownEvents[i].funcId;
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

/**
 * Get function info (arity and type) by name
 * Returns 1 on success, 0 if not found
 */
__attribute__((unused))
static int get_function_info(const char *name, uint8_t *out_arity, uint8_t *out_type) {
    if (!name) return 0;

    // Check known events
    for (int i = 0; g_knownEvents[i].name != NULL; i++) {
        if (strcmp(g_knownEvents[i].name, name) == 0) {
            if (out_arity) *out_arity = g_knownEvents[i].expectedArity;
            if (out_type) *out_type = OSI_FUNC_EVENT;
            return 1;
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
// Osiris Direct Query/Call Wrappers
// ============================================================================

// Pool of reusable argument descriptors (avoids malloc per call)
#define ARG_POOL_SIZE 32
static OsiArgumentDesc g_argPool[ARG_POOL_SIZE];
static int g_argPoolUsed = 0;

/**
 * Allocate argument descriptors from pool
 * Returns NULL if pool exhausted
 */
static OsiArgumentDesc *alloc_args(int count) {
    if (count <= 0 || count > ARG_POOL_SIZE) return NULL;
    if (g_argPoolUsed + count > ARG_POOL_SIZE) {
        // Pool exhausted - reset (not thread safe, but BG3 is single-threaded for Osiris)
        g_argPoolUsed = 0;
    }

    OsiArgumentDesc *args = &g_argPool[g_argPoolUsed];
    g_argPoolUsed += count;

    // Initialize and link
    memset(args, 0, count * sizeof(OsiArgumentDesc));
    for (int i = 0; i < count - 1; i++) {
        args[i].nextParam = &args[i + 1];
    }
    args[count - 1].nextParam = NULL;

    return args;
}

/**
 * Set argument value as string/GUID
 */
static void set_arg_string(OsiArgumentDesc *arg, const char *value, int isGuid) {
    if (!arg) return;
    arg->value.typeId = isGuid ? OSI_TYPE_GUIDSTRING : OSI_TYPE_STRING;
    arg->value.stringVal = (char *)value;  // Note: caller must ensure lifetime
}

/**
 * Set argument value as integer
 */
__attribute__((unused))
static void set_arg_int(OsiArgumentDesc *arg, int32_t value) {
    if (!arg) return;
    arg->value.typeId = OSI_TYPE_INTEGER;
    arg->value.int32Val = value;
}

/**
 * Set argument value as real (float)
 */
__attribute__((unused))
static void set_arg_real(OsiArgumentDesc *arg, float value) {
    if (!arg) return;
    arg->value.typeId = OSI_TYPE_REAL;
    arg->value.floatVal = value;
}

/**
 * Execute an Osiris query by function ID
 * Returns 1 on success, 0 on failure
 * Output values are written back to args
 */
static int osiris_query_by_id(uint32_t funcId, OsiArgumentDesc *args) {
    if (!pfn_InternalQuery) {
        log_message("[OsiQuery] ERROR: InternalQuery not resolved");
        return 0;
    }

    int result = pfn_InternalQuery(funcId, args);
    return result;
}

/**
 * Execute an Osiris query by name
 * Returns 1 on success, 0 on failure
 */
__attribute__((unused))
static int osiris_query(const char *funcName, OsiArgumentDesc *args) {
    uint32_t funcId = lookup_function_by_name(funcName);
    if (funcId == INVALID_FUNCTION_ID) {
        log_message("[OsiQuery] Function '%s' not found in cache", funcName);
        return 0;
    }

    log_message("[OsiQuery] Calling %s (id=0x%x)", funcName, funcId);
    return osiris_query_by_id(funcId, args);
}

/**
 * Execute an Osiris call (proc/event) by function ID
 * Returns 1 on success, 0 on failure
 */
static int osiris_call_by_id(uint32_t funcId, OsiArgumentDesc *args) {
    if (!pfn_InternalCall) {
        log_message("[OsiCall] ERROR: InternalCall not resolved");
        return 0;
    }

    // Note: InternalCall takes COsipParameterList, not OsiArgumentDesc
    // For now, this may need adjustment based on actual signature
    int result = pfn_InternalCall(funcId, (void *)args);
    return result;
}

/**
 * Execute an Osiris call by name
 * Returns 1 on success, 0 on failure
 */
__attribute__((unused))
static int osiris_call(const char *funcName, OsiArgumentDesc *args) {
    uint32_t funcId = lookup_function_by_name(funcName);
    if (funcId == INVALID_FUNCTION_ID) {
        log_message("[OsiCall] Function '%s' not found in cache", funcName);
        return 0;
    }

    log_message("[OsiCall] Calling %s (id=0x%x)", funcName, funcId);
    return osiris_call_by_id(funcId, args);
}

// ============================================================================
// Convenience wrappers for common Osiris functions
// ============================================================================

/**
 * QRY_IsTagged(character, tag) - Check if character has a tag
 * Returns 1 if tagged, 0 if not or on error
 */
static int osi_is_tagged(const char *character, const char *tag) {
    // Look up QRY_IsTagged or IsTagged
    uint32_t funcId = lookup_function_by_name("QRY_IsTagged");
    if (funcId == INVALID_FUNCTION_ID) {
        funcId = lookup_function_by_name("IsTagged");
    }
    if (funcId == INVALID_FUNCTION_ID) {
        // Function not yet discovered
        return -1;  // Unknown
    }

    OsiArgumentDesc *args = alloc_args(2);
    if (!args) return -1;

    set_arg_string(&args[0], character, 1);  // GUID
    set_arg_string(&args[1], tag, 1);        // GUID

    return osiris_query_by_id(funcId, args);
}

/**
 * GetDistanceTo(char1, char2) - Get distance between characters
 * Returns distance in meters, or -1.0 on error
 */
static float osi_get_distance_to(const char *char1, const char *char2) {
    uint32_t funcId = lookup_function_by_name("QRY_GetDistance");
    if (funcId == INVALID_FUNCTION_ID) {
        funcId = lookup_function_by_name("GetDistanceTo");
    }
    if (funcId == INVALID_FUNCTION_ID) {
        return -1.0f;
    }

    // This query returns a float as out param
    OsiArgumentDesc *args = alloc_args(3);
    if (!args) return -1.0f;

    set_arg_string(&args[0], char1, 1);  // GUID
    set_arg_string(&args[1], char2, 1);  // GUID
    args[2].value.typeId = OSI_TYPE_REAL;  // Out param

    if (osiris_query_by_id(funcId, args)) {
        return args[2].value.floatVal;
    }

    return -1.0f;
}

/**
 * DialogRequestStop(dialog) - Stop a dialog
 */
static void osi_dialog_request_stop(const char *dialog) {
    uint32_t funcId = lookup_function_by_name("DialogRequestStop");
    if (funcId == INVALID_FUNCTION_ID) {
        funcId = lookup_function_by_name("Proc_DialogRequestStop");
    }
    if (funcId == INVALID_FUNCTION_ID) {
        log_message("[OsiCall] DialogRequestStop not found");
        return;
    }

    OsiArgumentDesc *args = alloc_args(1);
    if (!args) return;

    set_arg_string(&args[0], dialog, 1);
    osiris_call_by_id(funcId, args);
}

/**
 * Count arguments in an OsiArgumentDesc chain
 */
static int count_osi_args(OsiArgumentDesc *args) {
    int count = 0;
    OsiArgumentDesc *current = args;
    while (current && count < 20) {  // Safety limit
        count++;
        current = current->nextParam;
    }
    return count;
}

/**
 * Dispatch event to registered Lua callbacks
 */
static void dispatch_event_to_lua(const char *eventName, int arity,
                                   OsiArgumentDesc *args, const char *timing) {
    (void)arity;  // Currently unused - listener uses its own requested arity
    if (!L || !eventName) return;

    for (int i = 0; i < osiris_listener_count; i++) {
        OsirisListener *listener = &osiris_listeners[i];

        // Match by name and timing only - arity is how many args listener wants
        if (strcmp(listener->event_name, eventName) == 0 &&
            strcmp(listener->timing, timing) == 0) {

            // Get callback from Lua registry
            lua_rawgeti(L, LUA_REGISTRYINDEX, listener->callback_ref);
            if (!lua_isfunction(L, -1)) {
                lua_pop(L, 1);
                continue;
            }

            // Log callback dispatch
            log_message("[Osiris] Dispatching %s callback (%s, arity=%d)",
                       eventName, timing, listener->arity);

            // Push arguments (up to listener's requested arity)
            int argsToPass = listener->arity;
            int pushed = 0;
            OsiArgumentDesc *arg = args;
            while (arg && pushed < argsToPass) {
                // For now, push as strings - will refine based on type
                if (arg->value.typeId == OSI_TYPE_STRING ||
                    arg->value.typeId == OSI_TYPE_GUIDSTRING) {
                    if (arg->value.stringVal) {
                        lua_pushstring(L, arg->value.stringVal);
                    } else {
                        lua_pushnil(L);
                    }
                } else if (arg->value.typeId == OSI_TYPE_INTEGER) {
                    lua_pushinteger(L, arg->value.int32Val);
                } else if (arg->value.typeId == OSI_TYPE_INTEGER64) {
                    lua_pushinteger(L, (lua_Integer)arg->value.int64Val);
                } else if (arg->value.typeId == OSI_TYPE_REAL) {
                    lua_pushnumber(L, arg->value.floatVal);
                } else {
                    // Unknown type - try string
                    if (arg->value.stringVal) {
                        lua_pushstring(L, arg->value.stringVal);
                    } else {
                        lua_pushnil(L);
                    }
                }
                pushed++;
                arg = arg->nextParam;
            }

            // Call the callback
            if (lua_pcall(L, pushed, 0, 0) != LUA_OK) {
                log_message("[Osiris] Callback error for %s: %s",
                           eventName, lua_tostring(L, -1));
                lua_pop(L, 1);
            }
        }
    }
}

/**
 * Hooked COsiris::Event - called for all Osiris events
 * Mangled name: _ZN7COsiris5EventEjP16COsiArgumentDesc
 * Signature: void COsiris::Event(unsigned int funcId, COsiArgumentDesc* args)
 */
static void fake_Event(void *thisPtr, uint32_t funcId, OsiArgumentDesc *args) {
    event_call_count++;

    // Capture COsiris pointer if we haven't already
    if (!g_COsiris && thisPtr) {
        g_COsiris = thisPtr;
        g_OsiFunctionMan = thisPtr;  // Try using COsiris as function manager
        log_message(">>> Captured COsiris from Event: %p", g_COsiris);
    }

    // Get function name if available (may trigger cache lookup)
    const char *funcName = get_function_name(funcId);
    int arity = count_osi_args(args);

    // Try to cache this function if we don't know it yet
    if (!funcName) {
        try_cache_function_from_event(funcId);
        funcName = get_function_name(funcId);  // Try again after caching
    }

    // Track unique function IDs for analysis
    track_seen_func_id(funcId, (uint8_t)arity);

    // Track player GUIDs from event arguments (learn as we observe events)
    OsiArgumentDesc *scanArg = args;
    while (scanArg) {
        if ((scanArg->value.typeId == OSI_TYPE_STRING ||
             scanArg->value.typeId == OSI_TYPE_GUIDSTRING) &&
            scanArg->value.stringVal) {
            track_player_guid(scanArg->value.stringVal);
        }
        scanArg = scanArg->nextParam;
    }

    // Log event (limit frequency to avoid log spam)
    if (event_call_count <= 50 || (event_call_count % 100 == 0) || funcName != NULL) {
        if (funcName) {
            log_message(">>> Event[%d]: %s (id=%u, arity=%d, args=%p)",
                       event_call_count, funcName, funcId, arity, (void*)args);
        } else {
            log_message(">>> Event[%d]: id=%u (arity=%d, args=%p)",
                       event_call_count, funcId, arity, (void*)args);
        }

        // Dump first few bytes of args for structure analysis (first 10 events only)
        if (args && event_call_count <= 10) {
            uint8_t *p = (uint8_t *)args;
            log_message("    args bytes[0-31]: %02x%02x%02x%02x %02x%02x%02x%02x "
                       "%02x%02x%02x%02x %02x%02x%02x%02x "
                       "%02x%02x%02x%02x %02x%02x%02x%02x "
                       "%02x%02x%02x%02x %02x%02x%02x%02x",
                       p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
                       p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15],
                       p[16],p[17],p[18],p[19],p[20],p[21],p[22],p[23],
                       p[24],p[25],p[26],p[27],p[28],p[29],p[30],p[31]);

            // Try to read as our assumed structure
            log_message("    Assumed: nextParam=%p, typeId=%u, stringVal=%p",
                       (void*)args->nextParam, args->value.typeId,
                       (void*)args->value.stringVal);

            // If it looks like a string, try to print it
            if (args->value.typeId >= OSI_TYPE_STRING &&
                args->value.typeId <= OSI_TYPE_GUIDSTRING &&
                args->value.stringVal) {
                // Safety check - verify it's a readable address
                log_message("    String arg: %.80s", args->value.stringVal);
            }
        }
    }

    // Track dialog state from dialog events
    if (funcName) {
        if (strcmp(funcName, "AutomatedDialogStarted") == 0 && args) {
            // Clear previous participants
            g_dialogParticipantCount = 0;

            // Log and capture all 4 arguments
            OsiArgumentDesc *arg = args;
            int argIdx = 0;
            while (arg && argIdx < 4) {
                if ((arg->value.typeId == OSI_TYPE_STRING ||
                     arg->value.typeId == OSI_TYPE_GUIDSTRING) &&
                    arg->value.stringVal) {
                    log_message("[Dialog] Arg[%d]: %s", argIdx, arg->value.stringVal);

                    // Store first arg as dialog resource
                    if (argIdx == 0) {
                        strncpy(g_currentDialogResource, arg->value.stringVal,
                                sizeof(g_currentDialogResource) - 1);
                        g_currentDialogResource[sizeof(g_currentDialogResource) - 1] = '\0';
                    }

                    // Track all GUID args as potential participants
                    if (g_dialogParticipantCount < MAX_DIALOG_PARTICIPANTS) {
                        strncpy(g_dialogParticipants[g_dialogParticipantCount],
                                arg->value.stringVal,
                                sizeof(g_dialogParticipants[0]) - 1);
                        g_dialogParticipants[g_dialogParticipantCount][sizeof(g_dialogParticipants[0]) - 1] = '\0';
                        g_dialogParticipantCount++;
                    }
                } else if (arg->value.typeId == OSI_TYPE_INTEGER) {
                    log_message("[Dialog] Arg[%d]: (int) %d", argIdx, arg->value.int32Val);
                } else if (arg->value.typeId == OSI_TYPE_INTEGER64) {
                    log_message("[Dialog] Arg[%d]: (int64) %lld", argIdx, arg->value.int64Val);
                }
                arg = arg->nextParam;
                argIdx++;
            }

            g_currentDialogPlayerCount = 1;  // Single-player default
            log_message("[Dialog] Started with %d participants", g_dialogParticipantCount);
        } else if (strcmp(funcName, "AutomatedDialogEnded") == 0) {
            // Clear dialog state when dialog ends
            log_message("[Dialog] Ended: %s", g_currentDialogResource);
            g_currentDialogResource[0] = '\0';
            g_currentDialogInstance = -1;
            g_dialogParticipantCount = 0;
        }
    }

    // Dispatch to "before" callbacks if we know the function name
    if (funcName) {
        dispatch_event_to_lua(funcName, arity, args, "before");
    }

    // Call original
    if (orig_Event) {
        ((OsiEventFn)orig_Event)(thisPtr, funcId, args);
    }

    // Dispatch to "after" callbacks
    if (funcName) {
        dispatch_event_to_lua(funcName, arity, args, "after");
    }
}

/**
 * Enumerate all loaded dynamic libraries
 * This helps us understand what's loaded and find libOsiris.dylib
 */
static void enumerate_loaded_images(void) {
    uint32_t count = _dyld_image_count();
    log_message("Loaded images: %u", count);

    int interesting_count = 0;
    for (uint32_t i = 0; i < count && interesting_count < 15; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name) {
            // Only log interesting ones (not system frameworks)
            if (strstr(name, "Baldur") || strstr(name, "Osiris") ||
                strstr(name, "steam") || strstr(name, "Steam") ||
                strstr(name, "BG3") || strstr(name, "bg3se") ||
                strstr(name, "Larian") || strstr(name, "discord") ||
                strstr(name, "Bink") || strstr(name, "PlayFab") ||
                strstr(name, "Http")) {
                log_message("  [%u] %s", i, name);
                interesting_count++;
            }
        }
    }
}

/**
 * Install Dobby hooks on Osiris functions
 */
static void install_hooks(void) {
#if ENABLE_HOOKS
    // Only install hooks once
    if (hooks_installed) {
        log_message("Hooks already installed, skipping");
        return;
    }

    log_message("Installing Dobby hooks...");

    // Get libOsiris handle - try various paths
    void *osiris = dlopen("@rpath/libOsiris.dylib", RTLD_NOLOAD);
    if (!osiris) {
        // Try @executable_path relative (works when injected into BG3)
        osiris = dlopen("@executable_path/../Frameworks/libOsiris.dylib", RTLD_NOW);
    }

    if (!osiris) {
        log_message("ERROR: Could not get libOsiris handle for hooking");
        return;
    }

    // Test pattern scanner infrastructure
    log_message("=== Pattern Scanner Test ===");
    void *text_start = NULL;
    size_t text_size = 0;
    if (get_macho_text_section("libOsiris.dylib", &text_start, &text_size)) {
        log_message("  libOsiris __TEXT,__text: %p (size: 0x%zx / %zu MB)",
                    text_start, text_size, text_size / (1024 * 1024));
    } else {
        log_message("  WARNING: Could not get libOsiris __TEXT section");
    }

    // Get function addresses (C++ mangled names)
    void *initGameAddr = dlsym(osiris, "_ZN7COsiris8InitGameEv");
    void *loadAddr = dlsym(osiris, "_ZN7COsiris4LoadER12COsiSmartBuf");
    void *eventAddr = dlsym(osiris, "_ZN7COsiris5EventEjP16COsiArgumentDesc");

    // Pattern scanner verification: create pattern from known function bytes
    if (text_start && text_size > 0 && eventAddr) {
        // Read first 8 bytes of COsiris::Event and convert to pattern
        const unsigned char *event_bytes = (const unsigned char *)eventAddr;
        char test_pattern[64];
        snprintf(test_pattern, sizeof(test_pattern),
                 "%02X %02X %02X %02X %02X %02X %02X %02X",
                 event_bytes[0], event_bytes[1], event_bytes[2], event_bytes[3],
                 event_bytes[4], event_bytes[5], event_bytes[6], event_bytes[7]);

        log_message("  COsiris::Event first 8 bytes: %s", test_pattern);

        // Try to find this pattern
        void *found = find_pattern_str(text_start, text_size, test_pattern);
        if (found == eventAddr) {
            log_message("  Pattern scanner VERIFIED: found COsiris::Event at correct address");
        } else if (found) {
            log_message("  Pattern found at %p (expected %p) - multiple matches?", found, eventAddr);
        } else {
            log_message("  WARNING: Pattern scanner failed to find COsiris::Event");
        }
    }
    log_message("=== End Pattern Scanner Test ===");

    // Resolve function pointers for Osiris calls (not hooked, just called)
    // Use pattern-based fallback if dlsym fails
    log_message("Resolving Osiris function pointers...");

    // InternalQuery - try dlsym first, then pattern scan
    pfn_InternalQuery = (InternalQueryFn)resolve_osiris_symbol(osiris, &g_osirisPatterns[0]);
    if (!pfn_InternalQuery) {
        log_message("  WARNING: InternalQuery not found");
    }

    // InternalCall - try dlsym first, then pattern scan
    pfn_InternalCall = (InternalCallFn)resolve_osiris_symbol(osiris, &g_osirisPatterns[1]);
    if (!pfn_InternalCall) {
        log_message("  WARNING: InternalCall not found");
    }

    // pFunctionData - direct dlsym only (no pattern yet)
    pfn_pFunctionData = (pFunctionDataFn)dlsym(osiris, "_ZN15COsiFunctionMan13pFunctionDataEj");

    // Get the global OsiFunctionMan pointer
    g_pOsiFunctionMan = (void **)dlsym(osiris, "_OsiFunctionMan");

    log_message("Osiris function pointers:");
    log_message("  InternalQuery: %p%s", (void*)pfn_InternalQuery,
                pfn_InternalQuery ? "" : " (NOT FOUND)");
    log_message("  InternalCall: %p%s", (void*)pfn_InternalCall,
                pfn_InternalCall ? "" : " (NOT FOUND)");
    log_message("  pFunctionData: %p", (void*)pfn_pFunctionData);
    log_message("  OsiFunctionMan global: %p", (void*)g_pOsiFunctionMan);
    if (g_pOsiFunctionMan) {
        log_message("  OsiFunctionMan instance: %p", *g_pOsiFunctionMan);
    }

    int hook_count = 0;

    // Hook COsiris::InitGame
    if (initGameAddr) {
        int result = DobbyHook(initGameAddr, (void *)fake_InitGame, &orig_InitGame);
        if (result == 0) {
            log_message("  COsiris::InitGame hooked successfully (orig: %p)", orig_InitGame);
            hook_count++;
        } else {
            log_message("  ERROR: Failed to hook COsiris::InitGame (error: %d)", result);
        }
    } else {
        log_message("  COsiris::InitGame not found, skipping");
    }

    // Hook COsiris::Load
    if (loadAddr) {
        int result = DobbyHook(loadAddr, (void *)fake_Load, &orig_Load);
        if (result == 0) {
            log_message("  COsiris::Load hooked successfully (orig: %p)", orig_Load);
            hook_count++;
        } else {
            log_message("  ERROR: Failed to hook COsiris::Load (error: %d)", result);
        }
    } else {
        log_message("  COsiris::Load not found, skipping");
    }

    // Hook COsiris::Event - this is the key hook for event interception!
    if (eventAddr) {
        int result = DobbyHook(eventAddr, (void *)fake_Event, &orig_Event);
        if (result == 0) {
            log_message("  COsiris::Event hooked successfully (orig: %p)", orig_Event);
            hook_count++;
        } else {
            log_message("  ERROR: Failed to hook COsiris::Event (error: %d)", result);
        }
    } else {
        log_message("  COsiris::Event not found, skipping");
    }

    log_message("Hooks installed: %d/3", hook_count);
    hooks_installed = 1;
#else
    log_message("Hooks DISABLED (ENABLE_HOOKS=0)");
#endif
}

/**
 * Check if libOsiris.dylib is loaded and examine its exports
 */
static void check_osiris_library(void) {
    // Try to find libOsiris.dylib
    void *osiris = dlopen("@rpath/libOsiris.dylib", RTLD_NOLOAD);

    if (!osiris) {
        // Try @executable_path relative (works when injected into BG3)
        osiris = dlopen("@executable_path/../Frameworks/libOsiris.dylib", RTLD_NOW);
    }

    if (osiris) {
        log_message("libOsiris.dylib handle obtained!");

        // Look up key exported C symbols
        void *debugHook = dlsym(osiris, "DebugHook");
        void *createRule = dlsym(osiris, "CreateRule");
        void *defineFunction = dlsym(osiris, "DefineFunction");
        void *setInitSection = dlsym(osiris, "SetInitSection");

        // Try C++ mangled names for COsiris methods
        void *initGame = dlsym(osiris, "_ZN7COsiris8InitGameEv");
        void *load = dlsym(osiris, "_ZN7COsiris4LoadER12COsiSmartBuf");

        log_message("Osiris symbol addresses:");
        log_message("  DebugHook: %p", debugHook);
        log_message("  CreateRule: %p", createRule);
        log_message("  DefineFunction: %p", defineFunction);
        log_message("  SetInitSection: %p", setInitSection);
        log_message("  COsiris::InitGame: %p", initGame);
        log_message("  COsiris::Load: %p", load);

        // Count how many we found
        int found = 0;
        if (debugHook) found++;
        if (createRule) found++;
        if (defineFunction) found++;
        if (setInitSection) found++;
        if (initGame) found++;
        if (load) found++;

        log_message("Found %d/6 key Osiris symbols", found);

        // Don't close - we need this handle for hooks
        // dlclose(osiris);
    } else {
        log_message("libOsiris.dylib not yet loaded");
        log_message("  dlerror: %s", dlerror());
    }
}

/**
 * Callback for when new images are loaded
 * This lets us know when libOsiris.dylib becomes available
 */
static void image_added_callback(const struct mach_header *mh, intptr_t slide) {
    // Find the name of this image
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        if (_dyld_get_image_header(i) == mh) {
            const char *name = _dyld_get_image_name(i);
            if (name && strstr(name, "libOsiris")) {
                log_message(">>> libOsiris.dylib loaded dynamically! Slide: 0x%lx", (long)slide);
                check_osiris_library();
                // Install hooks when Osiris loads
                install_hooks();
            }
            break;
        }
    }
}

/**
 * Main constructor - runs when dylib is loaded
 */
__attribute__((constructor))
static void bg3se_init(void) {
    // Clear log file
    FILE *f = fopen(LOG_FILE, "w");
    if (f) {
        fprintf(f, "=== %s v%s ===\n", BG3SE_NAME, BG3SE_VERSION);
        fprintf(f, "Injection timestamp: %ld\n", (long)time(NULL));
        fprintf(f, "Process ID: %d\n", getpid());
        fclose(f);
    }

    // Initialize function cache hash table
    init_func_hash_table();

    log_message("=== %s v%s initialized ===", BG3SE_NAME, BG3SE_VERSION);
    log_message("Running in process: %s (PID: %d)", getprogname(), getpid());

    // Get architecture
#if defined(__arm64__)
    log_message("Architecture: ARM64 (Apple Silicon)");
#elif defined(__x86_64__)
    log_message("Architecture: x86_64 (Rosetta/Intel)");
#else
    log_message("Architecture: Unknown");
#endif

    // Log Dobby availability
    log_message("Dobby inline hooking: enabled");

    // Detect and log enabled mods
    detect_enabled_mods();

    // Initialize Lua runtime
    init_lua();

    // Enumerate loaded images
    enumerate_loaded_images();

    // Check for Osiris library
    check_osiris_library();

    // Try to install hooks now (in case Osiris is already loaded)
    install_hooks();

    // Register callback for when new images load
    _dyld_register_func_for_add_image(image_added_callback);

    log_message("Image load callback registered");
    log_message("=== Initialization complete ===");
}

/**
 * Destructor - runs when dylib is unloaded (usually at process exit)
 */
__attribute__((destructor))
static void bg3se_cleanup(void) {
    log_message("=== %s shutting down ===", BG3SE_NAME);
    log_message("Final hook call counts:");
    log_message("  COsiris::InitGame: %d calls", initGame_call_count);
    log_message("  COsiris::Load: %d calls", load_call_count);
    log_message("  COsiris::Event: %d calls", event_call_count);

    // Log unique function IDs summary
    log_message("Unique function IDs observed: %d", g_seenFuncIdCount);
    for (int i = 0; i < g_seenFuncIdCount && i < 50; i++) {
        log_message("  [%d] id=%u (0x%08x) arity=%d",
                   i, g_seenFuncIds[i], g_seenFuncIds[i], g_seenFuncArities[i]);
    }
    if (g_seenFuncIdCount > 50) {
        log_message("  ... and %d more", g_seenFuncIdCount - 50);
    }

    // Shutdown Lua
    shutdown_lua();
}
