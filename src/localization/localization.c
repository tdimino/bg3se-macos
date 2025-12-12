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

// ls::FixedString::Create(char const*, int) - returns FixedString index
typedef uint32_t (*FixedStringCreateFn)(const char *str, int len);

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

    LOG_CORE_INFO("LOCA: Initialized - repo_ptr at %p", (void*)s_loca.repo_ptr_addr);
    LOG_CORE_DEBUG("LOCA: FixedString::Create at %p", (void*)s_loca.fs_create);
    LOG_CORE_DEBUG("LOCA: TryGet at %p", s_loca.tryget_fn);

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

    // Call ls::FixedString::Create(char const*, int)
    // This will look up or create the string in GlobalStringTable
    uint32_t fs_index = s_loca.fs_create(handle, (int)strlen(handle));

    LOG_CORE_DEBUG("LOCA: FixedString::Create('%s') = 0x%x", handle, fs_index);
    return fs_index;
}

// ============================================================================
// String Access
// ============================================================================

// Thread-local buffer for returned strings (to avoid lifetime issues)
static __thread char s_result_buffer[4096];

const char* localization_get(const char *handle, const char *fallback) {
    if (!localization_ready()) {
        return fallback ? fallback : "";
    }

    if (!handle || !*handle) {
        return fallback ? fallback : "";
    }

    // Validate handle format - should start with 'h' for localization handles
    if (handle[0] != 'h') {
        LOG_CORE_DEBUG("LOCA: Invalid handle format: '%s'", handle);
        return fallback ? fallback : "";
    }

    // Create FixedString from handle string
    uint32_t fs_index = create_fixedstring_from_handle(handle);
    if (fs_index == 0xFFFFFFFF || fs_index == 0) {
        LOG_CORE_DEBUG("LOCA: Failed to create FixedString for '%s'", handle);
        return fallback ? fallback : "";
    }

    // Build RuntimeStringHandle
    RuntimeStringHandle rsh = {
        .handle = fs_index,
        .version = 0,
        ._padding = 0
    };

    // Call TryGet
    TryGetResult result;
    bool found = call_tryget_with_x8(s_loca.tryget_fn, s_loca.repo, &rsh, 0, 0, &result);

    if (found && result.value.data && result.value.size > 0) {
        // Copy to thread-local buffer to ensure lifetime
        size_t copy_len = result.value.size;
        if (copy_len >= sizeof(s_result_buffer)) {
            copy_len = sizeof(s_result_buffer) - 1;
        }
        memcpy(s_result_buffer, result.value.data, copy_len);
        s_result_buffer[copy_len] = '\0';

        LOG_CORE_DEBUG("LOCA: Found translation for '%s': '%s'", handle, s_result_buffer);
        return s_result_buffer;
    }

    LOG_CORE_DEBUG("LOCA: No translation found for '%s', using fallback", handle);
    return fallback ? fallback : "";
}

bool localization_set(const char *handle __attribute__((unused)),
                      const char *value __attribute__((unused))) {
    if (!localization_ready()) {
        return false;
    }

    // TODO: Implement runtime string modification
    // This requires:
    // 1. Finding the TextPool entry for the handle
    // 2. Updating the LSStringView to point to new text
    // 3. Managing memory for the new string

    LOG_CORE_WARN("LOCA: Set() not yet implemented");
    return false;
}

// ============================================================================
// Language Info
// ============================================================================

const char* localization_get_language(void) {
    // TODO: Find the current language setting
    // This is likely stored in GlobalSwitches or a similar config structure
    // For now, return a placeholder

    return "Unknown";
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
