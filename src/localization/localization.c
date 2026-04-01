/**
 * localization.c - Localization System Implementation
 *
 * Discovered offsets (macOS ARM64, Dec 2025):
 *   ls::TranslatedStringRepository::m_ptr at 0x8aed088 (from module base)
 *   ls::TranslatedStringRepository::TryGet at 0x106534d54
 *   ls::TranslatedStringRepository::Get at 0x106535148
 *
 * TranslatedStringRepository structure (from Windows BG3SE):
 *   +0x00: int field_0
 *   +0x08: TextPool* TranslatedStrings[9]  (9 language pools)
 *   +0x50: TextPool* FallbackPool
 *   +0x58: TextPool* VersionedFallbackPool
 *   ...
 *   TextPool contains: HashMap<RuntimeStringHandle, LSStringView> Texts
 *
 * RuntimeStringHandle = { FixedString Handle; uint16_t Version; }
 */

#include "localization.h"
#include "logging.h"
#include "fixed_string.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>

// ============================================================================
// Offset Constants (macOS ARM64)
// ============================================================================

// TranslatedStringRepository::m_ptr offset from main binary base
#define LOCA_REPO_OFFSET  0x8aed088

// Function offsets (from Ghidra analysis, Dec 2025)
// These are absolute Ghidra addresses - need to subtract base
#define LOCA_TRYGET_OFFSET          0x6534d54   // TryGet function
#define LOCA_FIXEDSTRING_CREATE     0x64b9ebc   // ls::FixedString::Create(char*, int)
#define LOCA_ADDTRANSLATEDSTRING    0x6532590   // AddTranslatedString(handle, value)

// TranslatedStringRepository structure offsets (to be verified)
// These are estimated from Windows x64 - may need ARM64 adjustment
#define REPO_OFFSET_TRANSLATED_STRINGS  0x08   // TextPool* TranslatedStrings[9]
#define REPO_OFFSET_FALLBACK_POOL       0x50   // TextPool* FallbackPool
#define REPO_OFFSET_VERSIONED_FALLBACK  0x58   // TextPool* VersionedFallbackPool

// TextPool structure offsets
#define TEXTPOOL_OFFSET_TEXTS           0x10   // HashMap<RuntimeStringHandle, LSStringView>

// HashMap structure (similar to other BG3 HashMaps)
// HashMap { buf*, capacity, size, ... }

// ============================================================================
// Function Pointer Types
// ============================================================================

// ls::FixedString::Create(uint32_t* out_index, char const*, int) - writes to output parameter
// NOTE: The result is written to the first parameter, not returned!
typedef void (*FixedStringCreateFn)(uint32_t *out_index, const char *str, int len);

// RuntimeStringHandle structure (8 bytes)
// { FixedString Handle (4 bytes), uint16_t Version (2 bytes), padding (2 bytes) }
typedef struct __attribute__((packed)) {
    uint32_t handle;     // FixedString index
    uint16_t version;    // Version number
    uint16_t _padding;
} RuntimeStringHandle;

// LSStringView structure (16 bytes on ARM64)
typedef struct {
    const char *data;    // Pointer to string data
    uint64_t size;       // String length
} LSStringView;

// TryGet returns an optional<StringView> - on ARM64 this is likely 24 bytes:
// { has_value (1 byte), padding (7 bytes), StringView (16 bytes) }
// But since it returns > 16 bytes, ARM64 ABI uses x8 indirect return
typedef struct __attribute__((aligned(16))) {
    LSStringView value;      // 0x00: The StringView if present
    uint8_t has_value;       // 0x10: Whether value is valid
    uint8_t _pad[15];        // Padding to 32 bytes
} TryGetResult;

// TryGet signature: optional<StringView> TryGet(RuntimeStringHandle const&, EIdentity, EIdentity) const
// On ARM64 with x8 indirect return for large structs
typedef void (*TryGetFn)(void *result, void *repo, const RuntimeStringHandle *handle, int lang1, int lang2);

// AddTranslatedString signature (from Ghidra decompilation Dec 2025):
// void ls::TranslatedStringRepository::AddTranslatedString(
//     RuntimeStringHandle* out_handle,     // x0: output handle
//     TranslatedStringRepository* repo,    // x1: this (repository)
//     RuntimeStringHandle const* in_handle,// x2: input handle
//     char* str_data,                      // x3: StringView.data (passed by value in x3)
//     uint64_t str_size,                   // x4: StringView.size (passed by value in x4)
//     TextPool* text_pool,                 // x5: TranslatedStrings[0]
//     uint32_t flags                       // x6: EAddFlags (0 = default)
// )
// NOTE: On ARM64, 16-byte structs passed by value use two registers (x3+x4)
typedef void (*AddTranslatedStringFn)(
    RuntimeStringHandle *out_handle,
    void *repo,
    const RuntimeStringHandle *in_handle,
    const char *str_data,
    uint64_t str_size,
    void *text_pool,
    uint32_t flags
);

// ============================================================================
// Module State
// ============================================================================

static struct {
    bool initialized;
    void *binary_base;
    void **repo_ptr_addr;     // Address of the m_ptr global
    void *repo;               // Cached repository pointer
    FixedStringCreateFn fs_create;  // FixedString::Create function
    void *tryget_fn;          // TryGet function address (raw, need x8 setup)
    AddTranslatedStringFn add_string_fn;  // AddTranslatedString function
} s_loca = {0};

// ============================================================================
// Initialization
// ============================================================================

void localization_init(void *main_binary_base) {
    if (s_loca.initialized) {
        return;
    }

    s_loca.binary_base = main_binary_base;

    // Calculate address of ls::TranslatedStringRepository::m_ptr
    s_loca.repo_ptr_addr = (void**)((uintptr_t)main_binary_base + LOCA_REPO_OFFSET);

    // Calculate function addresses
    s_loca.fs_create = (FixedStringCreateFn)((uintptr_t)main_binary_base + LOCA_FIXEDSTRING_CREATE);
    s_loca.tryget_fn = (void*)((uintptr_t)main_binary_base + LOCA_TRYGET_OFFSET);
    s_loca.add_string_fn = (AddTranslatedStringFn)((uintptr_t)main_binary_base + LOCA_ADDTRANSLATEDSTRING);

    LOG_CORE_INFO("LOCA: Initialized - repo_ptr at %p", (void*)s_loca.repo_ptr_addr);
    LOG_CORE_DEBUG("LOCA: FixedString::Create at %p", (void*)s_loca.fs_create);
    LOG_CORE_DEBUG("LOCA: TryGet at %p", s_loca.tryget_fn);
    LOG_CORE_DEBUG("LOCA: AddTranslatedString at %p", (void*)s_loca.add_string_fn);

    s_loca.initialized = true;
}

bool localization_ready(void) {
    if (!s_loca.initialized || !s_loca.repo_ptr_addr) {
        return false;
    }

    // Read the repository pointer (double-indirection like RPGStats)
    void *repo = *s_loca.repo_ptr_addr;
    if (repo != NULL) {
        s_loca.repo = repo;
        return true;
    }

    return false;
}

void* localization_get_raw(void) {
    if (!localization_ready()) {
        return NULL;
    }
    return s_loca.repo;
}

// ============================================================================
// ARM64 Helper for x8 Indirect Return
// ============================================================================

#if defined(__aarch64__) || defined(__arm64__)
/**
 * Call TryGet with x8 indirect return buffer.
 * ARM64 ABI: Functions returning structs > 16 bytes use x8 for return buffer.
 *
 * TryGet signature: optional<StringView> TryGet(this, RuntimeStringHandle const&, EIdentity, EIdentity)
 * - x0: this (repository pointer)
 * - x1: RuntimeStringHandle const* (pointer to handle)
 * - x2: EIdentity lang1 (int, typically 0)
 * - x3: EIdentity lang2 (int, typically 0)
 * - x8: pointer to result buffer
 */
static bool call_tryget_with_x8(void *fn, void *repo, const RuntimeStringHandle *handle,
                                 int lang1, int lang2, TryGetResult *result) {
    // Zero the result buffer
    memset(result, 0, sizeof(TryGetResult));

    // Call with x8 pointing to result buffer
    // Using minimal clobbers like arm64_call.c
    __asm__ volatile (
        "mov x8, %[buf]\n"      // x8 = result buffer (indirect return)
        "mov x0, %[repo]\n"     // x0 = this (repository)
        "mov x1, %[handle]\n"   // x1 = RuntimeStringHandle const*
        "mov x2, %[lang1]\n"    // x2 = lang1
        "mov x3, %[lang2]\n"    // x3 = lang2
        "blr %[fn]\n"           // Call TryGet
        : "+m"(*result)         // result may be modified
        : [buf] "r"(result),
          [repo] "r"(repo),
          [handle] "r"(handle),
          [lang1] "r"((uint64_t)lang1),
          [lang2] "r"((uint64_t)lang2),
          [fn] "r"(fn)
        : "x0", "x1", "x2", "x3", "x8", "x9", "x10", "x11", "x12", "x13",
          "x14", "x15", "x16", "x17", "x30", "memory"
    );

    return result->has_value != 0;
}
#else
// x86_64 stub - TryGet likely uses different calling convention
static bool call_tryget_with_x8(void *fn, void *repo, const RuntimeStringHandle *handle,
                                 int lang1, int lang2, TryGetResult *result) {
    (void)fn; (void)repo; (void)handle; (void)lang1; (void)lang2;
    memset(result, 0, sizeof(TryGetResult));
    return false;
}
#endif

// ============================================================================
// RuntimeStringHandle Helpers
// ============================================================================

/**
 * Create a FixedString from a handle string using the game's FixedString::Create.
 * Handle format: "h12345678g1234g4567g8901g123456789012"
 */
static uint32_t create_fixedstring_from_handle(const char *handle) {
    if (!handle || !s_loca.fs_create) {
        return 0xFFFFFFFF;
    }

    // Call ls::FixedString::Create(uint32_t* out, char const*, int)
    // The function writes the result to the output parameter
    uint32_t fs_index = 0xFFFFFFFF;
    s_loca.fs_create(&fs_index, handle, (int)strlen(handle));

    LOG_CORE_DEBUG("LOCA: FixedString::Create('%s') = 0x%x", handle, fs_index);
    return fs_index;
}

// ============================================================================
// Handle Creation
// ============================================================================

// Monotonically increasing counter for dynamic handles (like Windows BG3SE's
// NextDynamicStringHandleId). Protected by no lock because it's init-time only
// in practice. Use _Atomic to be correct if ever called from multiple threads.
#include <stdatomic.h>
static _Atomic uint32_t s_next_dynamic_handle_id = 1;

/**
 * Create a new unique localization handle string.
 *
 * Windows BG3SE format: "h{8hex}g{4hex}g{4hex}g{4hex}g{12hex}"
 * We use a simple monotonically-increasing counter packed into the first field
 * with the rest zeroed, matching BG3's "hXXXXXXXXg0000g0000g0000g000000000000"
 * pattern for dynamically generated handles.
 *
 * The returned handle string is written to `out` (caller-supplied buffer of
 * at least LOCA_HANDLE_BUF_SIZE bytes).
 */
bool localization_create_handle(char *out, size_t out_size) {
    if (!out || out_size < LOCA_HANDLE_BUF_SIZE) {
        return false;
    }

    uint32_t id = atomic_fetch_add(&s_next_dynamic_handle_id, 1);

    // Format: "h%08Xg0000g0000g0000g000000000000"
    int written = snprintf(out, out_size,
        "h%08Xg0000g0000g0000g000000000000", id);

    return (written > 0 && (size_t)written < out_size);
}

// ============================================================================
// String Access
// ============================================================================

// Thread-local buffer for returned strings (to avoid lifetime issues)
static __thread char s_result_buffer[4096];

const char* localization_get(const char *handle, const char *fallback) {
    // DEFERRED: TryGet crashes when looking up non-existent handles.
    // The calling convention is verified correct, but the game's TryGet
    // doesn't gracefully handle missing keys - it crashes on NULL dereference.
    //
    // To properly implement this, we need to:
    // 1. Verify the handle exists in TranslatedStrings HashMap BEFORE calling TryGet
    // 2. Or find a safer lookup function that returns optional<> correctly
    //
    // For now, return fallback to prevent crashes.
    // GetLanguage() works correctly - that's the primary localization function.

    LOG_CORE_DEBUG("LOCA: GetTranslatedString called for '%s', returning fallback (deferred)",
                   handle ? handle : "(null)");

    return fallback ? fallback : "";
}

bool localization_set(const char *handle, const char *value) {
    LOG_CORE_DEBUG("LOCA: UpdateTranslatedString called with handle='%s' value='%s'",
                   handle ? handle : "(null)", value ? value : "(null)");

    // DEFERRED: Full implementation requires HashMap insertion reverse engineering
    // The AddTranslatedString function was successfully called but only works for
    // updating EXISTING translations, not adding new ones.
    //
    // For new translations, we would need to:
    // 1. Insert into TranslatedStrings[lang].Texts HashMap
    // 2. Properly handle hash bucket allocation and collision chains
    // 3. Allocate storage for the string value
    //
    // Current status: FixedString::Create and AddTranslatedString calling conventions verified.
    // See Issue #39 for tracking.

    if (!localization_ready()) {
        LOG_CORE_DEBUG("LOCA: Repository not ready");
        return false;
    }

    if (!handle || !*handle || !value) {
        return false;
    }

    // For now, return false to indicate update not performed
    // This prevents crashes from incomplete HashMap manipulation
    LOG_CORE_INFO("LOCA: UpdateTranslatedString deferred - requires HashMap insertion support");
    return false;
}

// ============================================================================
// Language Info
// ============================================================================

// Cached language string (detected once, cached forever)
static char s_detected_language[64] = {0};
static bool s_language_detected = false;

/**
 * Try to read language from Larian's profile options.
 * Path: ~/Library/Application Support/Larian Studios/Baldur's Gate 3/PlayerProfiles/<profile>/profileOptions.lsx
 *
 * The file contains XML like:
 *   <attribute id="ActiveLanguage" value="English" type="LSString"/>
 */
static bool try_read_language_from_profile(void) {
    const char *home = getenv("HOME");
    if (!home) return false;

    // Build path to profile directory
    char profile_dir[512];
    snprintf(profile_dir, sizeof(profile_dir),
             "%s/Library/Application Support/Larian Studios/Baldur's Gate 3/PlayerProfiles",
             home);

    // Try to open directory and find profile options
    DIR *dir = opendir(profile_dir);
    if (!dir) {
        LOG_CORE_DEBUG("LOCA: Could not open profile directory: %s", profile_dir);
        return false;
    }

    struct dirent *entry;
    bool found = false;

    while ((entry = readdir(dir)) != NULL && !found) {
        if (entry->d_name[0] == '.') continue;  // Skip . and ..

        // Build path to profileOptions.lsx
        char options_path[768];
        snprintf(options_path, sizeof(options_path),
                 "%s/%s/profileOptions.lsx", profile_dir, entry->d_name);

        FILE *f = fopen(options_path, "r");
        if (!f) continue;

        // Read file and search for ActiveLanguage
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            // Look for: <attribute id="ActiveLanguage" value="..." type="LSString"/>
            const char *lang_attr = strstr(line, "id=\"ActiveLanguage\"");
            if (lang_attr) {
                const char *value_start = strstr(lang_attr, "value=\"");
                if (value_start) {
                    value_start += 7;  // Skip 'value="'
                    const char *value_end = strchr(value_start, '"');
                    if (value_end && value_end > value_start) {
                        size_t len = value_end - value_start;
                        if (len < sizeof(s_detected_language)) {
                            memcpy(s_detected_language, value_start, len);
                            s_detected_language[len] = '\0';
                            LOG_CORE_INFO("LOCA: Detected language from profile: %s", s_detected_language);
                            found = true;
                        }
                    }
                }
            }
        }
        fclose(f);
    }

    closedir(dir);
    return found;
}

/**
 * Try to detect system language from macOS locale settings.
 */
static bool try_read_system_language(void) {
    // Check LANG environment variable (e.g., "en_US.UTF-8", "de_DE.UTF-8")
    const char *lang = getenv("LANG");
    if (lang && *lang) {
        // Map common locale prefixes to BG3 language names
        static const struct { const char *prefix; const char *name; } locale_map[] = {
            {"en", "English"},
            {"de", "German"},
            {"fr", "French"},
            {"it", "Italian"},
            {"es", "Spanish"},
            {"pt_BR", "Brazilian Portuguese"},
            {"pt", "Portuguese"},
            {"pl", "Polish"},
            {"ru", "Russian"},
            {"zh_CN", "Chinese Simplified"},
            {"zh_TW", "Chinese Traditional"},
            {"zh", "Chinese Simplified"},
            {"ja", "Japanese"},
            {"ko", "Korean"},
            {"tr", "Turkish"},
            {"uk", "Ukrainian"},
            {NULL, NULL}
        };

        for (int i = 0; locale_map[i].prefix; i++) {
            if (strncmp(lang, locale_map[i].prefix, strlen(locale_map[i].prefix)) == 0) {
                strncpy(s_detected_language, locale_map[i].name, sizeof(s_detected_language) - 1);
                s_detected_language[sizeof(s_detected_language) - 1] = '\0';
                LOG_CORE_INFO("LOCA: Detected language from system locale: %s (LANG=%s)",
                             s_detected_language, lang);
                return true;
            }
        }
    }

    return false;
}

const char* localization_get_language(void) {
    // Return cached result if available
    if (s_language_detected && s_detected_language[0]) {
        return s_detected_language;
    }

    // Try detection methods in order of preference
    if (!s_language_detected) {
        s_language_detected = true;  // Mark as attempted

        // 1. Try to read from game profile (most accurate)
        if (try_read_language_from_profile()) {
            return s_detected_language;
        }

        // 2. Try to detect from system locale
        if (try_read_system_language()) {
            return s_detected_language;
        }

        // 3. Default to English
        LOG_CORE_INFO("LOCA: Could not detect language, defaulting to English");
        strncpy(s_detected_language, "English", sizeof(s_detected_language) - 1);
    }

    return s_detected_language;
}

// ============================================================================
// Debugging
// ============================================================================

void localization_dump_info(void) {
    LOG_CORE_INFO("LOCA: === Localization System Info ===");
    LOG_CORE_INFO("LOCA: Initialized: %s", s_loca.initialized ? "yes" : "no");
    LOG_CORE_INFO("LOCA: Binary base: %p", s_loca.binary_base);
    LOG_CORE_INFO("LOCA: Repo ptr addr: %p", (void*)s_loca.repo_ptr_addr);

    if (localization_ready()) {
        LOG_CORE_INFO("LOCA: Repository: %p", s_loca.repo);

        // Dump some structure info for verification
        void *repo = s_loca.repo;

        // Read TranslatedStrings[0] pointer
        void *ts0 = *(void**)((uintptr_t)repo + REPO_OFFSET_TRANSLATED_STRINGS);
        LOG_CORE_INFO("LOCA: TranslatedStrings[0]: %p", ts0);

        // Read FallbackPool pointer
        void *fallback = *(void**)((uintptr_t)repo + REPO_OFFSET_FALLBACK_POOL);
        LOG_CORE_INFO("LOCA: FallbackPool: %p", fallback);
    } else {
        LOG_CORE_INFO("LOCA: Repository: NOT READY");
    }

    LOG_CORE_INFO("LOCA: ================================");
}
