/**
 * fixed_string.c - FixedString Resolution Implementation
 *
 * Resolves FixedString indices to actual string values by accessing
 * the GlobalStringTable at runtime.
 *
 * Discovery Strategy:
 * 1. Try dlsym for mangled C++ symbol
 * 2. Use known offset from binary analysis (if available)
 * 3. Pattern scan for ADRP+LDR sequences (fallback)
 */

#include "fixed_string.h"
#include "../core/logging.h"
#include "../core/version.h"
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

// Cache file magic/version (file stored in data directory)
#define GST_CACHE_MAGIC 0x47535430  // "GST0"
#define GST_CACHE_VERSION 1

// ============================================================================
// Module State
// ============================================================================

static void **g_pGlobalStringTable = NULL;  // Pointer to GlobalStringTable*
static void *g_MainBinaryBase = NULL;
static bool g_Initialized = false;
static bool g_LazyDiscoveryAttempted = false;  // For deferred heavy probing

// Runtime-discovered offsets (may differ from Windows x64)
static uint32_t g_OffsetBuckets = SUBTABLE_OFFSET_BUCKETS;
static uint32_t g_OffsetNumBuckets = SUBTABLE_OFFSET_NUM_BUCKETS;
static uint32_t g_OffsetEntrySize = SUBTABLE_OFFSET_ENTRY_SIZE;
static uint32_t g_OffsetEntriesPerBucket = SUBTABLE_OFFSET_ENTRIES_PER_BKT;
static uint32_t g_SubTableSize = SUBTABLE_SIZE;

// Statistics
static uint32_t g_ResolvedCount = 0;
static uint32_t g_FailedCount = 0;

// Cached GST address (stored as offset from binary base for ASLR compatibility)
static uintptr_t g_CachedGSTOffset = 0;

// ============================================================================
// Offset Cache (persists discovered offsets across game launches)
// ============================================================================

typedef struct {
    uint32_t magic;              // GST_CACHE_MAGIC
    uint32_t version;            // GST_CACHE_VERSION
    uint64_t gst_offset;         // Offset from binary base (ASLR-safe)
    uint32_t off_buckets;        // SubTable.Buckets offset
    uint32_t off_num_buckets;    // SubTable.NumBuckets offset
    uint32_t off_entry_size;     // SubTable.EntrySize offset
    uint32_t off_entries_per_bkt;// SubTable.EntriesPerBucket offset
    uint32_t subtable_size;      // Size of each SubTable
    uint32_t checksum;           // Simple checksum for validation
} GSTOffsetCache;

static uint32_t calc_cache_checksum(const GSTOffsetCache *cache) {
    // Simple additive checksum (excluding the checksum field itself)
    const uint32_t *data = (const uint32_t *)cache;
    uint32_t sum = 0;
    for (size_t i = 0; i < (sizeof(GSTOffsetCache) - sizeof(uint32_t)) / sizeof(uint32_t); i++) {
        sum += data[i];
    }
    return sum;
}

static bool load_offset_cache(void) {
    const char *cache_path = bg3se_get_data_path(BG3SE_CACHE_FILENAME);
    FILE *f = fopen(cache_path, "rb");
    if (!f) return false;

    GSTOffsetCache cache;
    if (fread(&cache, sizeof(cache), 1, f) != 1) {
        fclose(f);
        return false;
    }
    fclose(f);

    // Validate magic and version
    if (cache.magic != GST_CACHE_MAGIC || cache.version != GST_CACHE_VERSION) {
        LOG_CORE_WARN("Cache file invalid (magic/version mismatch)");
        return false;
    }

    // Validate checksum
    uint32_t expected_checksum = calc_cache_checksum(&cache);
    if (cache.checksum != expected_checksum) {
        LOG_CORE_WARN("Cache file corrupt (checksum mismatch)");
        return false;
    }

    // Sanity check offsets
    if (cache.off_buckets == 0 || cache.subtable_size == 0 || cache.gst_offset == 0) {
        LOG_CORE_WARN("Cache file has invalid offsets");
        return false;
    }

    // Load offsets
    g_CachedGSTOffset = cache.gst_offset;
    g_OffsetBuckets = cache.off_buckets;
    g_OffsetNumBuckets = cache.off_num_buckets;
    g_OffsetEntrySize = cache.off_entry_size;
    g_OffsetEntriesPerBucket = cache.off_entries_per_bkt;
    g_SubTableSize = cache.subtable_size;

    LOG_CORE_DEBUG("Loaded cached offsets from %s", cache_path);
    LOG_CORE_DEBUG("  GST offset: 0x%llx", (unsigned long long)g_CachedGSTOffset);
    LOG_CORE_DEBUG("  Buckets: 0x%x, NumBuckets: 0x%x, EntrySize: 0x%x",
               g_OffsetBuckets, g_OffsetNumBuckets, g_OffsetEntrySize);

    return true;
}

static void save_offset_cache(uintptr_t gst_offset) {
    GSTOffsetCache cache = {
        .magic = GST_CACHE_MAGIC,
        .version = GST_CACHE_VERSION,
        .gst_offset = gst_offset,
        .off_buckets = g_OffsetBuckets,
        .off_num_buckets = g_OffsetNumBuckets,
        .off_entry_size = g_OffsetEntrySize,
        .off_entries_per_bkt = g_OffsetEntriesPerBucket,
        .subtable_size = g_SubTableSize,
    };
    cache.checksum = calc_cache_checksum(&cache);

    const char *cache_path = bg3se_get_data_path(BG3SE_CACHE_FILENAME);
    FILE *f = fopen(cache_path, "wb");
    if (!f) {
        LOG_CORE_WARN(" Could not write cache file to %s", cache_path);
        return;
    }

    if (fwrite(&cache, sizeof(cache), 1, f) == 1) {
        LOG_CORE_DEBUG("Saved discovered offsets to %s", cache_path);
    }
    fclose(f);
}

// ============================================================================
// Safe Memory Access (pattern from stats_manager.c)
// ============================================================================

static bool safe_read_ptr(void *addr, void **out) {
    if (!addr || !out) return false;

    mach_port_t task = mach_task_self();
    mach_msg_type_number_t bytes_read = 0;
    vm_offset_t buffer = 0;

    kern_return_t kr = vm_read(task, (vm_address_t)addr, sizeof(void *),
                               &buffer, &bytes_read);
    if (kr != KERN_SUCCESS || bytes_read != sizeof(void *)) {
        return false;
    }

    *out = *(void **)buffer;
    vm_deallocate(task, buffer, bytes_read);
    return true;
}

static bool safe_read_u32(void *addr, uint32_t *out) {
    if (!addr || !out) return false;

    mach_port_t task = mach_task_self();
    mach_msg_type_number_t bytes_read = 0;
    vm_offset_t buffer = 0;

    kern_return_t kr = vm_read(task, (vm_address_t)addr, sizeof(uint32_t),
                               &buffer, &bytes_read);
    if (kr != KERN_SUCCESS || bytes_read != sizeof(uint32_t)) {
        return false;
    }

    *out = *(uint32_t *)buffer;
    vm_deallocate(task, buffer, bytes_read);
    return true;
}

static bool safe_read_u64(void *addr, uint64_t *out) {
    if (!addr || !out) return false;

    mach_port_t task = mach_task_self();
    mach_msg_type_number_t bytes_read = 0;
    vm_offset_t buffer = 0;

    kern_return_t kr = vm_read(task, (vm_address_t)addr, sizeof(uint64_t),
                               &buffer, &bytes_read);
    if (kr != KERN_SUCCESS || bytes_read != sizeof(uint64_t)) {
        return false;
    }

    *out = *(uint64_t *)buffer;
    vm_deallocate(task, buffer, bytes_read);
    return true;
}

static bool safe_read_bytes(void *addr, void *out, size_t len) {
    if (!addr || !out || len == 0) return false;

    mach_port_t task = mach_task_self();
    mach_msg_type_number_t bytes_read = 0;
    vm_offset_t buffer = 0;

    kern_return_t kr = vm_read(task, (vm_address_t)addr, (vm_size_t)len,
                               &buffer, &bytes_read);
    if (kr != KERN_SUCCESS || bytes_read != len) {
        return false;
    }

    memcpy(out, (void *)buffer, len);
    vm_deallocate(task, buffer, bytes_read);
    return true;
}

// ============================================================================
// Forward Declarations
// ============================================================================

static bool is_valid_string_ptr(void *ptr);
static bool validate_string_at_entry(void *entry, uint64_t entry_size);
static bool discover_arm64_offsets(void *gst);

// ============================================================================
// Known Offsets for Probing
// ============================================================================

// Ghidra analysis shows gGlobalStringTable is typically a static pointer
#define GHIDRA_BASE_ADDRESS           0x100000000ULL

// GlobalStringTable pointer discovered via Ghidra analysis of ls::gst::Get()
// Ghidra address 0x108aeccd8 → offset 0x8aeccd8 from module base
// See ghidra/offsets/GLOBALSTRINGTABLE.md for details
#define OFFSET_GLOBAL_STRING_TABLE    0x108aeccd8ULL

// Known RPGStats offset (verified working) - GlobalStringTable is likely nearby
// This is the full Ghidra address (0x1089c5730), not just the offset
#define OFFSET_RPGSTATS               0x1089c5730ULL

// GlobalStringTable size: 11 SubTables * 0x1200 + MainTable = ~0xC600+ bytes
// Search range around RPGStats
#define PROBE_SEARCH_RANGE            0x200000ULL  // 2MB window

// ============================================================================
// Symbol Discovery
// ============================================================================

static void *try_dlsym_discovery(void) {
    void *handle = dlopen(NULL, RTLD_NOW);
    if (!handle) {
        LOG_CORE_DEBUG("dlopen(NULL) failed");
        return NULL;
    }

    // Try various mangled names for gGlobalStringTable
    const char *symbol_names[] = {
        "_ZN2ls19gGlobalStringTableE",      // ls::gGlobalStringTable
        "__ZN2ls19gGlobalStringTableE",     // macOS leading underscore
        "_ZN2ls18GlobalStringTableE",       // Alternate
        "__ZN2ls18GlobalStringTableE",
        "ls__gGlobalStringTable",           // C-style mangling
        "_ls__gGlobalStringTable",
        NULL
    };

    for (int i = 0; symbol_names[i]; i++) {
        void *sym = dlsym(handle, symbol_names[i]);
        if (sym) {
            LOG_CORE_DEBUG("Found via dlsym('%s'): %p",
                       symbol_names[i], sym);
            return sym;
        }
    }

    LOG_CORE_DEBUG("dlsym discovery failed - symbol not exported");
    return NULL;
}

// ============================================================================
// Runtime Offset Probing
// ============================================================================

/**
 * Probe a potential SubTable at the given base address.
 * Returns true if it looks like a valid SubTable.
 */
static bool probe_subtable(void *subtable_base, int *out_num_buckets,
                           uint64_t *out_entry_size, void **out_buckets) {
    if (!subtable_base) return false;

    // Try reading fields at Windows x64 offsets
    uint32_t num_buckets = 0;
    uint32_t entries_per_bucket = 0;
    uint64_t entry_size = 0;
    void *buckets = NULL;

    if (!safe_read_u32((char *)subtable_base + g_OffsetNumBuckets, &num_buckets)) {
        return false;
    }

    if (!safe_read_u64((char *)subtable_base + g_OffsetEntrySize, &entry_size)) {
        return false;
    }

    if (!safe_read_u32((char *)subtable_base + g_OffsetEntriesPerBucket, &entries_per_bucket)) {
        return false;
    }

    if (!safe_read_ptr((char *)subtable_base + g_OffsetBuckets, &buckets)) {
        return false;
    }

    // Sanity checks for valid SubTable
    if (num_buckets == 0 || num_buckets > 0x100000) return false;
    if (entry_size == 0 || entry_size > 0x1000) return false;
    if (entries_per_bucket == 0 || entries_per_bucket > 0x10000) return false;
    if (!buckets || (uintptr_t)buckets < 0x100000000ULL) return false;

    // Try to read first bucket
    void *first_bucket = NULL;
    if (!safe_read_ptr(buckets, &first_bucket) || !first_bucket) {
        return false;
    }

    if (out_num_buckets) *out_num_buckets = (int)num_buckets;
    if (out_entry_size) *out_entry_size = entry_size;
    if (out_buckets) *out_buckets = buckets;

    return true;
}

// ============================================================================
// Reference-Based Discovery (find known string, backtrack to SubTable)
// ============================================================================

// Known strings that exist in GlobalStringTable (stat/ability names)
static const char *g_KnownStrings[] = {
    "Strength",
    "Dexterity",
    "Constitution",
    "Intelligence",
    "Wisdom",
    "Charisma",
    "Armor",
    "Weapon",
    NULL
};

/**
 * Search memory for a null-terminated string.
 * Returns address of string start, or 0 if not found.
 */
static uintptr_t find_string_in_range(const char *needle, uintptr_t start, uintptr_t end) {
    size_t needle_len = strlen(needle);
    if (needle_len == 0 || needle_len > 64) return 0;

    // Search in 64KB chunks to reduce syscall overhead
    const size_t CHUNK_SIZE = 65536;
    uint8_t *buffer = malloc(CHUNK_SIZE);
    if (!buffer) return 0;

    uintptr_t found = 0;

    for (uintptr_t addr = start; addr < end && !found; addr += CHUNK_SIZE - needle_len) {
        size_t chunk_len = CHUNK_SIZE;
        if (addr + chunk_len > end) {
            chunk_len = end - addr;
        }

        if (!safe_read_bytes((void *)addr, buffer, chunk_len)) {
            continue;
        }

        // Search within chunk using Boyer-Moore-like simple search
        for (size_t i = 0; i + needle_len < chunk_len; i++) {
            if (memcmp(buffer + i, needle, needle_len) == 0) {
                // Verify null terminator
                if (buffer[i + needle_len] == '\0') {
                    found = addr + i;
                    break;
                }
            }
        }
    }

    free(buffer);
    return found;
}

/**
 * Validate a potential StringEntry by checking its header fields.
 * StringEntry layout: Hash(4), RefCount(4), Length(4), Id(4), NextFreeIndex(4), reserved(4), String[...]
 * String starts at offset 0x18 (24 bytes)
 */
static bool validate_string_entry_header(uintptr_t entry_addr, const char *expected_str) {
    // Read header fields
    uint32_t length = 0;
    uint32_t id = 0;

    if (!safe_read_u32((void *)(entry_addr + 0x08), &length)) return false;  // Length at +8
    if (!safe_read_u32((void *)(entry_addr + 0x0C), &id)) return false;       // Id at +12

    size_t expected_len = strlen(expected_str);

    // Sanity checks
    if (length != expected_len) return false;
    if (id == 0 || id == 0xFFFFFFFF) return false;

    // Verify the Id encodes to a valid SubTable
    uint32_t subtable_idx = id & 0x0F;
    if (subtable_idx >= GST_NUM_SUBTABLES) return false;

    return true;
}

/**
 * Try to find GlobalStringTable by searching for known strings and backtracking.
 * This is more robust than guessing offsets because it works regardless of
 * ARM64 vs x64 structure layout differences.
 */
static bool try_reference_based_discovery(void) {
    if (!g_MainBinaryBase) return false;

    uintptr_t base = (uintptr_t)g_MainBinaryBase;
    uintptr_t data_start = base + 0x8000000ULL;
    uintptr_t data_end = base + 0xC000000ULL;

    LOG_CORE_DEBUG("Trying reference-based discovery (searching for known strings)...");

    // Try each known string
    for (int str_idx = 0; g_KnownStrings[str_idx] != NULL; str_idx++) {
        const char *needle = g_KnownStrings[str_idx];

        LOG_CORE_DEBUG("Searching for \"%s\"...", needle);
        uintptr_t str_addr = find_string_in_range(needle, data_start, data_end);

        if (str_addr == 0) {
            LOG_CORE_DEBUG("  Not found in __DATA range");
            continue;
        }

        LOG_CORE_DEBUG("  Found at 0x%llx", (unsigned long long)str_addr);

        // StringEntry header is 24 bytes before string data
        uintptr_t entry_addr = str_addr - STRING_ENTRY_HEADER_SIZE;

        // Validate this looks like a StringEntry
        if (!validate_string_entry_header(entry_addr, needle)) {
            LOG_CORE_DEBUG("  Invalid StringEntry header at 0x%llx", (unsigned long long)entry_addr);
            continue;
        }

        // Read the FixedString Id
        uint32_t fs_id = 0;
        if (!safe_read_u32((void *)(entry_addr + 0x0C), &fs_id)) continue;

        uint32_t subtable_idx = fs_id & 0x0F;
        uint32_t bucket_idx = (fs_id >> 4) & 0xFFFF;
        uint32_t entry_idx = fs_id >> 20;

        LOG_CORE_DEBUG("  FixedString Id: 0x%08x (sub=%u, bucket=%u, entry=%u)",
                   fs_id, subtable_idx, bucket_idx, entry_idx);

        // The entry lives in a bucket. The bucket is an array of entries.
        // We need to find the Buckets array, which contains pointers to bucket arrays.
        // The SubTable.Buckets[bucket_idx] should point to a memory region containing our entry.

        // Search backwards for a pointer that could be SubTable.Buckets
        // The pointer at SubTable+off_buckets should point to an array where
        // array[bucket_idx] eventually leads to our entry

        // Heuristic: The SubTable is likely aligned to 0x100 or 0x1000 boundaries
        // and should be within 64MB before the string

        uintptr_t search_start = (entry_addr > 0x4000000) ? entry_addr - 0x4000000 : data_start;

        for (uintptr_t probe = entry_addr & ~0xFFFULL; probe >= search_start; probe -= 0x1000) {
            // Try various potential Buckets offsets
            static const uint32_t try_offsets[] = {
                0x1030, 0x1038, 0x1040, 0x1048, 0x1050, 0x1058, 0x1060, 0x1068,
                0x1070, 0x1078, 0x1080, 0x1088, 0x1090, 0x1098, 0x10A0, 0x10A8,
                0x1140, 0  // Windows offset last
            };

            for (int off_idx = 0; try_offsets[off_idx] != 0; off_idx++) {
                uint32_t off_buckets = try_offsets[off_idx];

                void *buckets_ptr = NULL;
                if (!safe_read_ptr((void *)(probe + off_buckets), &buckets_ptr)) continue;
                if (!is_valid_string_ptr(buckets_ptr)) continue;

                // Read bucket at bucket_idx
                void *bucket = NULL;
                if (!safe_read_ptr((char *)buckets_ptr + bucket_idx * sizeof(void *), &bucket)) continue;
                if (!is_valid_string_ptr(bucket)) continue;

                // Check if this bucket contains our entry
                // Entry should be at bucket + entry_idx * entry_size
                // We don't know entry_size yet, so try common values

                static const uint64_t try_entry_sizes[] = { 48, 56, 64, 72, 80, 88, 96, 104, 112, 0 };
                for (int es_idx = 0; try_entry_sizes[es_idx] != 0; es_idx++) {
                    uint64_t entry_size = try_entry_sizes[es_idx];
                    uintptr_t calc_entry = (uintptr_t)bucket + entry_idx * entry_size;

                    // Does this calculated entry match our found entry?
                    if (calc_entry == entry_addr) {
                        // Found it! Now verify SubTable[1] exists
                        uint32_t subtable_size = ((off_buckets + 0x100) & ~0xFFULL);

                        void *buckets1 = NULL;
                        if (safe_read_ptr((void *)(probe + subtable_size + off_buckets), &buckets1) &&
                            is_valid_string_ptr(buckets1)) {

                            LOG_CORE_INFO("*** FOUND via reference discovery! ***");
                            LOG_CORE_DEBUG("  SubTable[%u] at: 0x%llx",
                                       subtable_idx, (unsigned long long)(probe - subtable_idx * subtable_size));
                            LOG_CORE_DEBUG("  Buckets offset: 0x%x", off_buckets);
                            LOG_CORE_DEBUG("  Entry size: %llu", entry_size);
                            LOG_CORE_DEBUG("  SubTable size: 0x%x", subtable_size);

                            // Calculate GlobalStringTable base (SubTable[0])
                            uintptr_t gst_addr = probe - subtable_idx * subtable_size;

                            // Store offsets
                            g_OffsetBuckets = off_buckets;
                            g_SubTableSize = subtable_size;

                            // Try to find NumBuckets offset (should be near Buckets)
                            for (uint32_t off_nb = off_buckets - 0x80; off_nb < off_buckets; off_nb += 4) {
                                uint32_t num_buckets = 0;
                                if (safe_read_u32((void *)(probe + off_nb), &num_buckets) &&
                                    num_buckets > bucket_idx && num_buckets < 500000) {
                                    g_OffsetNumBuckets = off_nb;
                                    LOG_CORE_DEBUG("  NumBuckets offset: 0x%x (value=%u)",
                                               off_nb, num_buckets);
                                    break;
                                }
                            }

                            // Try to find EntrySize offset (should be near NumBuckets)
                            for (uint32_t off_es = g_OffsetNumBuckets - 0x40; off_es < g_OffsetNumBuckets; off_es += 8) {
                                uint64_t es = 0;
                                if (safe_read_u64((void *)(probe + off_es), &es) && es == entry_size) {
                                    g_OffsetEntrySize = off_es;
                                    LOG_CORE_DEBUG("  EntrySize offset: 0x%x", off_es);
                                    break;
                                }
                            }

                            // Store GST pointer
                            static void *found_gst = NULL;
                            found_gst = (void *)gst_addr;
                            g_pGlobalStringTable = &found_gst;

                            // Cache for next launch
                            save_offset_cache(gst_addr - base);

                            return true;
                        }
                    }
                }
            }
        }

        LOG_CORE_DEBUG("  Could not backtrack to SubTable from \"%s\"", needle);
    }

    LOG_CORE_DEBUG("Reference-based discovery failed");
    return false;
}

/**
 * Runtime probing: Search __DATA section for GlobalStringTable structure.
 * GlobalStringTable is a static global, not heap-allocated.
 * Returns true if found and sets g_pGlobalStringTable.
 */
static bool try_runtime_probe(void) {
    if (!g_MainBinaryBase) {
        LOG_CORE_WARN("Cannot probe - binary base not set");
        return false;
    }

    LOG_CORE_DEBUG("Starting __DATA section probe for GlobalStringTable...");

    // Calculate base addresses
    uintptr_t base = (uintptr_t)g_MainBinaryBase;

    // __DATA section for BG3 is roughly at base + 0x8000000 to base + 0xC000000
    // RPGStats is at offset 0x89C5730, so scan around that region
    uintptr_t data_start = base + 0x8000000ULL;
    uintptr_t data_end = base + 0xC000000ULL;

    LOG_CORE_DEBUG("Scanning __DATA from 0x%llx to 0x%llx (64MB)",
               (unsigned long long)data_start, (unsigned long long)data_end);

    int pages_checked = 0;
    int valid_structures = 0;

    // Potential Buckets offsets to try (ARM64 compact layout vs Windows padded)
    static const uint32_t bucket_offsets[] = {
        0x1030, 0x1038, 0x1040, 0x1048, 0x1050, 0x1058, 0x1060, 0x1068,  // ARM64 compact
        0x1070, 0x1078, 0x1080, 0x1088, 0x1090, 0x1098, 0x10A0, 0x10A8,  // ARM64 mid
        0x1140,  // Windows x64
        0
    };

    // Scan for GST structure directly in __DATA
    for (uintptr_t addr = data_start; addr < data_end; addr += 0x1000) {
        for (int i = 0; bucket_offsets[i] != 0; i++) {
            uint32_t off_buckets = bucket_offsets[i];
            void *buckets = NULL;

            if (!safe_read_ptr((void *)(addr + off_buckets), &buckets)) continue;
            if (!is_valid_string_ptr(buckets)) continue;

            // Found valid pointer - search for NumBuckets and EntrySize nearby
            for (uint32_t off_nb = off_buckets - 0x40; off_nb < off_buckets; off_nb += 4) {
                uint32_t num_buckets = 0;
                if (!safe_read_u32((void *)(addr + off_nb), &num_buckets)) continue;
                if (num_buckets < 100 || num_buckets > 500000) continue;

                for (uint32_t off_es = off_nb - 0x20; off_es < off_nb; off_es += 4) {
                    uint64_t entry_size = 0;
                    if (!safe_read_u64((void *)(addr + off_es), &entry_size)) continue;
                    if (entry_size < 32 || entry_size > 1024) continue;

                    // Validate bucket contents
                    void *first_bucket = NULL;
                    if (!safe_read_ptr(buckets, &first_bucket)) continue;
                    if (!is_valid_string_ptr(first_bucket)) continue;

                    // Check for valid string
                    if (validate_string_at_entry(first_bucket, entry_size)) {
                        valid_structures++;

                        // Estimate SubTable size and verify SubTable[1]
                        uint32_t subtable_size = ((off_buckets + 0x40) + 0xFF) & ~0xFF;
                        void *subtable1 = (void *)(addr + subtable_size);
                        void *buckets1 = NULL;
                        uint32_t num_buckets1 = 0;

                        if (safe_read_ptr((char *)subtable1 + off_buckets, &buckets1) &&
                            is_valid_string_ptr(buckets1) &&
                            safe_read_u32((char *)subtable1 + off_nb, &num_buckets1) &&
                            num_buckets1 >= 10 && num_buckets1 <= 500000) {

                            void *bucket1_first = NULL;
                            if (safe_read_ptr(buckets1, &bucket1_first) &&
                                is_valid_string_ptr(bucket1_first) &&
                                validate_string_at_entry(bucket1_first, entry_size)) {

                                // FOUND IT!
                                char sample[64] = {0};
                                safe_read_bytes((char *)first_bucket + 0x18, sample, sizeof(sample) - 1);

                                LOG_CORE_INFO("*** FOUND GlobalStringTable! ***");
                                LOG_CORE_DEBUG("  Address: 0x%llx", (unsigned long long)addr);
                                LOG_CORE_DEBUG("  Ghidra offset: 0x%llx",
                                           (unsigned long long)(addr - base + GHIDRA_BASE_ADDRESS));
                                LOG_CORE_DEBUG("  Buckets offset: 0x%x", off_buckets);
                                LOG_CORE_DEBUG("  NumBuckets offset: 0x%x", off_nb);
                                LOG_CORE_DEBUG("  EntrySize offset: 0x%x", off_es);
                                LOG_CORE_DEBUG("  SubTable size: 0x%x", subtable_size);
                                LOG_CORE_DEBUG("  SubTable[0]: NumBuckets=%u EntrySize=%llu",
                                           num_buckets, entry_size);
                                LOG_CORE_DEBUG("  SubTable[1]: NumBuckets=%u", num_buckets1);
                                LOG_CORE_DEBUG("  Sample string: \"%s\"", sample);

                                // Store offsets
                                g_OffsetBuckets = off_buckets;
                                g_OffsetNumBuckets = off_nb;
                                g_OffsetEntrySize = off_es;
                                g_SubTableSize = subtable_size;

                                // Store GST pointer
                                static void *found_gst = NULL;
                                found_gst = (void *)addr;
                                g_pGlobalStringTable = &found_gst;

                                // Cache for next launch (ASLR-safe offset)
                                uintptr_t gst_offset = addr - base;
                                save_offset_cache(gst_offset);

                                return true;
                            }
                        }
                    }
                }
            }
        }

        pages_checked++;
        if (pages_checked % 4000 == 0) {
            LOG_CORE_DEBUG("Probing __DATA... checked %d pages, %d candidates",
                       pages_checked, valid_structures);
        }
    }

    LOG_CORE_DEBUG("__DATA probe complete: checked %d pages, %d candidates, no match",
               pages_checked, valid_structures);
    return false;
}

/**
 * Try to validate a potential GST address with ARM64-aware offset discovery.
 * Returns true if this looks like a valid GlobalStringTable.
 */
static bool try_validate_gst_with_discovery(void *gst) {
    if (!gst || !is_valid_string_ptr(gst)) return false;

    // First try Windows x64 offsets
    void *buckets = NULL;
    uint32_t num_buckets = 0;
    uint64_t entry_size = 0;

    if (safe_read_ptr((char *)gst + SUBTABLE_OFFSET_BUCKETS, &buckets) &&
        is_valid_string_ptr(buckets) &&
        safe_read_u32((char *)gst + SUBTABLE_OFFSET_NUM_BUCKETS, &num_buckets) &&
        num_buckets >= 100 && num_buckets <= 500000 &&
        safe_read_u64((char *)gst + SUBTABLE_OFFSET_ENTRY_SIZE, &entry_size) &&
        entry_size >= 32 && entry_size <= 1024) {

        void *first_bucket = NULL;
        if (safe_read_ptr(buckets, &first_bucket) &&
            is_valid_string_ptr(first_bucket) &&
            validate_string_at_entry(first_bucket, entry_size)) {
            return true;
        }
    }

    // Windows offsets failed - try dynamic discovery
    return discover_arm64_offsets(gst);
}

/**
 * Probe for GlobalStringTable near a runtime pointer (like RPGStats).
 * This is more targeted than try_runtime_probe() because it uses the actual
 * runtime address of a known object rather than static __DATA offsets.
 */
bool fixed_string_probe_near_ptr(void *stats_ptr) {
    if (!stats_ptr) {
        LOG_CORE_WARN("Cannot probe - stats_ptr is NULL");
        return false;
    }

    if (g_pGlobalStringTable) {
        void *gst = NULL;
        if (safe_read_ptr(g_pGlobalStringTable, &gst) && gst) {
            LOG_CORE_DEBUG("GlobalStringTable already found at %p", gst);
            return true;  // Already found
        }
    }

    LOG_CORE_DEBUG("Probing near stats_ptr %p...", stats_ptr);

    // Search a narrower window around the stats pointer
    // GlobalStringTable is likely stored in the same data region
    uintptr_t center = (uintptr_t)stats_ptr;
    uintptr_t search_range = 0x10000000ULL;  // 256MB - data objects can be spread out

    uintptr_t search_start = center > search_range ? center - search_range : 0x100000000ULL;
    uintptr_t search_end = center + search_range;

    int candidates_checked = 0;
    int valid_pointers = 0;

    LOG_CORE_DEBUG("Searching from 0x%llx to 0x%llx",
               (unsigned long long)search_start, (unsigned long long)search_end);

    // Step by 0x1000 (4KB page alignment) for faster initial scan
    for (uintptr_t addr = search_start; addr < search_end; addr += 0x1000) {
        void *gst = NULL;

        // Try to read a pointer at this address
        if (!safe_read_ptr((void *)addr, &gst)) {
            continue;  // Can't read this address
        }

        if (!is_valid_string_ptr(gst)) {
            continue;  // Not a valid pointer
        }

        valid_pointers++;

        // Try to validate this as GlobalStringTable
        if (try_validate_gst_with_discovery(gst)) {
            LOG_CORE_INFO("*** FOUND GlobalStringTable! ***");
            LOG_CORE_DEBUG("  Pointer at: 0x%llx", (unsigned long long)addr);
            LOG_CORE_DEBUG("  GlobalStringTable: %p", gst);

            // Set the global pointer
            static void *stored_gst_ptr = NULL;
            stored_gst_ptr = gst;
            g_pGlobalStringTable = &stored_gst_ptr;

            // Cache for next launch (save GST address offset, not pointer address)
            uintptr_t base = (uintptr_t)g_MainBinaryBase;
            uintptr_t gst_offset = (uintptr_t)gst - base;
            save_offset_cache(gst_offset);

            return true;
        }

        candidates_checked++;
        if (candidates_checked % 5000 == 0) {
            LOG_CORE_DEBUG("Probing... checked %d pages, %d valid pointers",
                       candidates_checked, valid_pointers);
        }
    }

    LOG_CORE_DEBUG("Probe near stats_ptr complete: checked %d pages, %d valid pointers",
               candidates_checked, valid_pointers);

    // Last resort: Try treating stats_ptr region directly as potential GST location
    // Some games store the GST in the same data section
    LOG_CORE_DEBUG("Trying direct memory scan for GST structure...");

    // Scan for the actual GST structure (not pointer to it)
    for (uintptr_t addr = search_start; addr < search_end; addr += 0x1000) {
        // Check if this address directly contains a SubTable structure
        void *buckets = NULL;
        uint32_t num_buckets = 0;
        uint64_t entry_size = 0;

        // Try Windows x64 offsets at this address directly
        if (safe_read_ptr((void *)(addr + SUBTABLE_OFFSET_BUCKETS), &buckets) &&
            is_valid_string_ptr(buckets) &&
            safe_read_u32((void *)(addr + SUBTABLE_OFFSET_NUM_BUCKETS), &num_buckets) &&
            num_buckets >= 100 && num_buckets <= 500000 &&
            safe_read_u64((void *)(addr + SUBTABLE_OFFSET_ENTRY_SIZE), &entry_size) &&
            entry_size >= 32 && entry_size <= 1024) {

            void *first_bucket = NULL;
            if (safe_read_ptr(buckets, &first_bucket) &&
                is_valid_string_ptr(first_bucket) &&
                validate_string_at_entry(first_bucket, entry_size)) {

                LOG_CORE_INFO("*** FOUND GST directly at 0x%llx! ***",
                           (unsigned long long)addr);

                // Store this directly
                static void *direct_gst_ptr = NULL;
                direct_gst_ptr = (void *)addr;
                g_pGlobalStringTable = &direct_gst_ptr;
                return true;
            }
        }

        // Also try ARM64 compact layout (no padding after Element array)
        // Search for Buckets pointer in range 0x1008-0x1080
        for (uint32_t off = 0x1008; off <= 0x1080; off += 8) {
            if (safe_read_ptr((void *)(addr + off), &buckets) &&
                is_valid_string_ptr(buckets)) {

                // Found a valid pointer - look for num_buckets nearby
                for (uint32_t nb_off = off - 0x40; nb_off < off; nb_off += 4) {
                    if (safe_read_u32((void *)(addr + nb_off), &num_buckets) &&
                        num_buckets >= 100 && num_buckets <= 500000) {

                        // Look for entry_size
                        for (uint32_t es_off = nb_off - 0x20; es_off < nb_off; es_off += 4) {
                            if (safe_read_u64((void *)(addr + es_off), &entry_size) &&
                                entry_size >= 32 && entry_size <= 1024) {

                                void *first_bucket = NULL;
                                if (safe_read_ptr(buckets, &first_bucket) &&
                                    is_valid_string_ptr(first_bucket) &&
                                    validate_string_at_entry(first_bucket, entry_size)) {

                                    LOG_CORE_INFO("*** FOUND ARM64 GST at 0x%llx! ***",
                                               (unsigned long long)addr);
                                    LOG_CORE_DEBUG("  Buckets at +0x%x, NumBuckets at +0x%x, EntrySize at +0x%x",
                                               off, nb_off, es_off);

                                    g_OffsetBuckets = off;
                                    g_OffsetNumBuckets = nb_off;
                                    g_OffsetEntrySize = es_off;

                                    static void *arm64_gst_ptr = NULL;
                                    arm64_gst_ptr = (void *)addr;
                                    g_pGlobalStringTable = &arm64_gst_ptr;
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    LOG_CORE_DEBUG("Direct scan complete - no GST found");
    return false;
}

/**
 * Helper: Check if a pointer looks valid for string table data.
 */
static bool is_valid_string_ptr(void *ptr) {
    if (!ptr) return false;
    uintptr_t addr = (uintptr_t)ptr;
    // Valid heap/data addresses on ARM64 macOS
    return addr >= 0x100000000ULL && addr < 0x800000000000ULL;
}

/**
 * Helper: Validate string content at entry.
 */
static bool validate_string_at_entry(void *entry, uint64_t entry_size) {
    if (!entry || entry_size < 32) return false;

    // Read string length from header (offset 0x08 or 0x0C based on Header layout)
    uint32_t str_len = 0;
    if (!safe_read_u32((char *)entry + 0x08, &str_len)) {
        // Try alternate offset
        if (!safe_read_u32((char *)entry + 0x0C, &str_len)) {
            return false;
        }
    }

    // String length should be reasonable
    if (str_len == 0 || str_len > entry_size - 0x18) {
        return false;
    }

    // Try to read string content
    char sample[32] = {0};
    if (!safe_read_bytes((char *)entry + 0x18, sample, sizeof(sample) - 1)) {
        return false;
    }

    // Check if it looks like a valid ASCII string
    int printable = 0;
    for (int i = 0; i < (int)sizeof(sample) - 1 && sample[i]; i++) {
        if (sample[i] >= 32 && sample[i] < 127) {
            printable++;
        } else if (sample[i] != '\0') {
            return false;  // Invalid character
        }
    }

    return printable >= 2;  // At least 2 printable chars
}

/**
 * Dynamic offset discovery: Scan through possible field offsets.
 * ARM64 macOS doesn't have Windows cache-line padding, so offsets differ.
 */
static bool discover_arm64_offsets(void *gst) {
    LOG_CORE_DEBUG("Starting ARM64 offset discovery at %p...", gst);

    // SubTable starts with Element[64] = 64 * 64 = 0x1000 bytes
    // After that, fields are more compact on ARM64 without Windows padding

    // Search ranges for field offsets (after the 0x1000 Element array)
    // Buckets should be a pointer, so 8-byte aligned after 0x1000
    const uint32_t buckets_min = 0x1008;
    const uint32_t buckets_max = 0x1200;
    const uint32_t buckets_step = 8;

    int candidates_tested = 0;

    for (uint32_t off_buckets = buckets_min; off_buckets <= buckets_max; off_buckets += buckets_step) {
        void *buckets = NULL;
        if (!safe_read_ptr((char *)gst + off_buckets, &buckets)) continue;
        if (!is_valid_string_ptr(buckets)) continue;

        // Found a valid pointer - now find NumBuckets and EntrySize nearby
        // They should be within ~0x80 bytes before Buckets (typical structure layout)
        for (uint32_t off_num_buckets = off_buckets - 0x80; off_num_buckets < off_buckets; off_num_buckets += 4) {
            uint32_t num_buckets = 0;
            if (!safe_read_u32((char *)gst + off_num_buckets, &num_buckets)) continue;
            if (num_buckets < 100 || num_buckets > 500000) continue;

            // Look for EntrySize (uint64_t or uint32_t)
            for (uint32_t off_entry_size = off_num_buckets - 0x40; off_entry_size < off_num_buckets; off_entry_size += 4) {
                uint64_t entry_size = 0;
                // Try reading as uint64_t first
                if (!safe_read_u64((char *)gst + off_entry_size, &entry_size)) {
                    // Try as uint32_t
                    uint32_t es32 = 0;
                    if (safe_read_u32((char *)gst + off_entry_size, &es32)) {
                        entry_size = es32;
                    } else {
                        continue;
                    }
                }
                if (entry_size < 32 || entry_size > 1024) continue;

                // Look for EntriesPerBucket between EntrySize and NumBuckets
                for (uint32_t off_epb = off_entry_size + 4; off_epb < off_num_buckets; off_epb += 4) {
                    uint32_t entries_per_bucket = 0;
                    if (!safe_read_u32((char *)gst + off_epb, &entries_per_bucket)) continue;
                    if (entries_per_bucket < 1 || entries_per_bucket > 100000) continue;

                    candidates_tested++;

                    // Now validate: Read first bucket and check for valid strings
                    void *first_bucket = NULL;
                    if (!safe_read_ptr(buckets, &first_bucket) || !is_valid_string_ptr(first_bucket)) {
                        continue;
                    }

                    // Validate string at first entry
                    if (validate_string_at_entry(first_bucket, entry_size)) {
                        // Try SubTable[1] with these offsets to confirm
                        // Estimate SubTable size based on Buckets offset + some padding
                        uint32_t estimated_subtable_size = ((off_buckets + 0x40) + 0xFF) & ~0xFF;

                        void *subtable1 = (char *)gst + estimated_subtable_size;
                        void *buckets1 = NULL;
                        uint32_t num_buckets1 = 0;

                        if (safe_read_ptr((char *)subtable1 + off_buckets, &buckets1) &&
                            is_valid_string_ptr(buckets1) &&
                            safe_read_u32((char *)subtable1 + off_num_buckets, &num_buckets1) &&
                            num_buckets1 >= 10 && num_buckets1 <= 500000) {

                            // Double-check SubTable[1] has valid strings too
                            void *bucket1_first = NULL;
                            if (safe_read_ptr(buckets1, &bucket1_first) &&
                                is_valid_string_ptr(bucket1_first) &&
                                validate_string_at_entry(bucket1_first, entry_size)) {

                                // FOUND VALID OFFSETS!
                                g_OffsetBuckets = off_buckets;
                                g_OffsetNumBuckets = off_num_buckets;
                                g_OffsetEntrySize = off_entry_size;
                                g_OffsetEntriesPerBucket = off_epb;
                                g_SubTableSize = estimated_subtable_size;

                                // Read sample string for logging
                                char sample[64] = {0};
                                safe_read_bytes((char *)first_bucket + 0x18, sample, sizeof(sample) - 1);

                                LOG_CORE_INFO("*** DISCOVERED ARM64 OFFSETS! ***");
                                LOG_CORE_DEBUG("  Buckets offset: 0x%x", off_buckets);
                                LOG_CORE_DEBUG("  NumBuckets offset: 0x%x", off_num_buckets);
                                LOG_CORE_DEBUG("  EntrySize offset: 0x%x", off_entry_size);
                                LOG_CORE_DEBUG("  EntriesPerBucket offset: 0x%x", off_epb);
                                LOG_CORE_DEBUG("  SubTable size: 0x%x", estimated_subtable_size);
                                LOG_CORE_DEBUG("  SubTable[0]: NumBuckets=%u EntrySize=%llu",
                                           num_buckets, entry_size);
                                LOG_CORE_DEBUG("  SubTable[1]: NumBuckets=%u", num_buckets1);
                                LOG_CORE_DEBUG("  Sample string: \"%s\"", sample);
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }

    LOG_CORE_DEBUG("ARM64 offset discovery failed (tested %d candidates)", candidates_tested);
    return false;
}

/**
 * Try different offset configurations to find working SubTable layout.
 */
bool fixed_string_probe_offsets(void) {
    if (!g_pGlobalStringTable || !*g_pGlobalStringTable) {
        LOG_CORE_WARN("Cannot probe - GlobalStringTable not found");
        return false;
    }

    void *gst = NULL;
    if (!safe_read_ptr(g_pGlobalStringTable, &gst) || !gst) {
        LOG_CORE_WARN("Cannot read GlobalStringTable pointer");
        return false;
    }

    LOG_CORE_DEBUG("GlobalStringTable at %p", gst);

    // Try Windows x64 offsets first
    void *subtable0 = gst;  // First SubTable at offset 0

    int num_buckets = 0;
    uint64_t entry_size = 0;
    void *buckets = NULL;

    if (probe_subtable(subtable0, &num_buckets, &entry_size, &buckets)) {
        // Validate with string check
        void *first_bucket = NULL;
        if (safe_read_ptr(buckets, &first_bucket) && first_bucket &&
            validate_string_at_entry(first_bucket, entry_size)) {
            LOG_CORE_DEBUG("SubTable[0] valid with Windows x64 offsets:");
            LOG_CORE_DEBUG("  NumBuckets=%d EntrySize=%llu Buckets=%p",
                       num_buckets, entry_size, buckets);
            return true;
        }
    }

    // Windows offsets didn't work - try dynamic ARM64 offset discovery
    LOG_CORE_DEBUG("Windows x64 offsets failed, trying ARM64 discovery...");
    return discover_arm64_offsets(gst);
}

// ============================================================================
// Initialization
// ============================================================================

void fixed_string_init(void *main_binary_base) {
    if (g_Initialized) {
        LOG_CORE_DEBUG("Already initialized");
        return;
    }

    g_MainBinaryBase = main_binary_base;
    LOG_CORE_DEBUG("Initializing with binary base %p", main_binary_base);

    // Try dlsym first
    g_pGlobalStringTable = try_dlsym_discovery();

    if (g_pGlobalStringTable) {
        void *gst = NULL;
        if (safe_read_ptr(g_pGlobalStringTable, &gst) && gst) {
            LOG_CORE_DEBUG("GlobalStringTable = %p", gst);

            // Probe for correct offsets
            if (fixed_string_probe_offsets()) {
                g_Initialized = true;
                LOG_CORE_DEBUG("Initialization complete");
                return;
            }
        }
    }

    // Fallback: Use Ghidra offset if available
    if (OFFSET_GLOBAL_STRING_TABLE != 0 && g_MainBinaryBase) {
        uintptr_t runtime_addr = (uintptr_t)g_MainBinaryBase +
                                  (OFFSET_GLOBAL_STRING_TABLE - GHIDRA_BASE_ADDRESS);
        g_pGlobalStringTable = (void **)runtime_addr;
        LOG_CORE_DEBUG("Using Ghidra offset: %p (base %p + 0x%llx)",
                   (void *)g_pGlobalStringTable, g_MainBinaryBase,
                   (unsigned long long)(OFFSET_GLOBAL_STRING_TABLE - GHIDRA_BASE_ADDRESS));

        void *gst = NULL;
        if (safe_read_ptr(g_pGlobalStringTable, &gst) && gst) {
            LOG_CORE_DEBUG("GlobalStringTable = %p", gst);

            if (fixed_string_probe_offsets()) {
                g_Initialized = true;
                LOG_CORE_DEBUG("Initialization complete via Ghidra offset");
                return;
            }
        }
    }

    // Defer heavy runtime probing to first resolution attempt (lazy discovery)
    // This avoids slowing down game startup when FixedString may not be used
    LOG_CORE_DEBUG("Heavy probing deferred to first resolution (lazy discovery)");
    LOG_CORE_DEBUG("GlobalStringTable not yet found - will probe on first use");

    g_Initialized = true;  // Mark as initialized, but GST not yet found
}

// ============================================================================
// Lazy Discovery (called on first resolution attempt)
// ============================================================================

static bool try_lazy_discovery(void) {
    if (g_LazyDiscoveryAttempted) {
        return g_pGlobalStringTable != NULL;
    }
    g_LazyDiscoveryAttempted = true;

    LOG_CORE_DEBUG("Lazy discovery triggered on first resolution attempt...");

    // Strategy 1: Try to load from cache (instant - no scanning needed)
    if (load_offset_cache() && g_CachedGSTOffset != 0 && g_MainBinaryBase) {
        uintptr_t gst_addr = (uintptr_t)g_MainBinaryBase + g_CachedGSTOffset;

        // Validate the cached GST address still works
        void *gst = NULL;
        if (safe_read_ptr((void *)gst_addr, &gst) || gst_addr > 0x100000000ULL) {
            // For direct GST address (not pointer-to-pointer), use directly
            static void *cached_gst = NULL;
            cached_gst = (void *)gst_addr;
            g_pGlobalStringTable = &cached_gst;

            // Quick validation: try to read SubTable[0].Buckets
            void *buckets = NULL;
            if (safe_read_ptr((char *)gst_addr + g_OffsetBuckets, &buckets) && buckets) {
                LOG_CORE_DEBUG("Cache hit! GST at %p", (void *)gst_addr);
                return true;
            }
        }
        LOG_CORE_DEBUG("Cache invalid - will re-probe");
        g_pGlobalStringTable = NULL;
    }

    // Strategy 2: Reference-based discovery (find known string, backtrack)
    // This is faster than exhaustive scanning and works regardless of ARM64 layout
    if (try_reference_based_discovery()) {
        LOG_CORE_DEBUG("Lazy discovery succeeded via reference-based discovery");
        return true;
    }

    // Strategy 3: Exhaustive runtime memory probe (slowest fallback)
    LOG_CORE_DEBUG("Trying exhaustive memory probe as last resort...");
    if (try_runtime_probe()) {
        if (fixed_string_probe_offsets()) {
            LOG_CORE_DEBUG("Lazy discovery succeeded via runtime probe");
            return true;
        }
    }

    LOG_CORE_DEBUG("Lazy discovery failed - GlobalStringTable not found");
    return false;
}

// ============================================================================
// Resolution
// ============================================================================

const char *fixed_string_resolve(uint32_t index) {
    if (index == FS_NULL_INDEX) {
        return NULL;
    }

    // Try lazy discovery if GST not found yet
    if (!g_pGlobalStringTable) {
        if (!try_lazy_discovery()) {
            g_FailedCount++;
            return NULL;
        }
    }

    void *gst = NULL;
    if (!safe_read_ptr(g_pGlobalStringTable, &gst) || !gst) {
        g_FailedCount++;
        return NULL;
    }

    // Decode index
    uint32_t subTableIdx = index & FS_SUBTABLE_MASK;
    uint32_t bucketIdx = (index >> FS_BUCKET_SHIFT) & FS_BUCKET_MASK;
    uint32_t entryIdx = index >> FS_ENTRY_SHIFT;

    // Bounds check
    if (subTableIdx >= GST_NUM_SUBTABLES) {
        g_FailedCount++;
        return NULL;
    }

    // Calculate SubTable address
    void *subTable = (char *)gst + (subTableIdx * g_SubTableSize);

    // Read SubTable fields
    uint32_t numBuckets = 0;
    uint32_t entriesPerBucket = 0;
    uint64_t entrySize = 0;
    void *buckets = NULL;

    if (!safe_read_u32((char *)subTable + g_OffsetNumBuckets, &numBuckets) ||
        !safe_read_u32((char *)subTable + g_OffsetEntriesPerBucket, &entriesPerBucket) ||
        !safe_read_u64((char *)subTable + g_OffsetEntrySize, &entrySize) ||
        !safe_read_ptr((char *)subTable + g_OffsetBuckets, &buckets)) {
        g_FailedCount++;
        return NULL;
    }

    // Bounds check
    if (bucketIdx >= numBuckets || entryIdx >= entriesPerBucket) {
        g_FailedCount++;
        return NULL;
    }

    if (!buckets) {
        g_FailedCount++;
        return NULL;
    }

    // Get bucket pointer
    void *bucket = NULL;
    if (!safe_read_ptr((char *)buckets + bucketIdx * sizeof(void *), &bucket) || !bucket) {
        g_FailedCount++;
        return NULL;
    }

    // Calculate entry address
    void *entry = (char *)bucket + (entryIdx * entrySize);

    // Read string length from header to validate
    uint32_t strLength = 0;
    if (!safe_read_u32((char *)entry + 0x08, &strLength)) {
        g_FailedCount++;
        return NULL;
    }

    // Sanity check length
    if (strLength == 0 || strLength > 4096) {
        g_FailedCount++;
        return NULL;
    }

    // String is at entry + 0x18 (after header)
    // Return pointer to string data (caller must treat as read-only)
    g_ResolvedCount++;
    return (const char *)((char *)entry + STRING_ENTRY_HEADER_SIZE);
}

// ============================================================================
// Utility Functions
// ============================================================================

bool fixed_string_is_valid(uint32_t index) {
    return index != FS_NULL_INDEX;
}

bool fixed_string_is_ready(void) {
    return g_Initialized && g_pGlobalStringTable && *g_pGlobalStringTable;
}

void fixed_string_get_stats(uint32_t *out_resolved, uint32_t *out_failed) {
    if (out_resolved) *out_resolved = g_ResolvedCount;
    if (out_failed) *out_failed = g_FailedCount;
}

// ============================================================================
// Debug Functions
// ============================================================================

void fixed_string_dump_subtable_info(int subtable_idx) {
    if (subtable_idx < 0 || subtable_idx >= GST_NUM_SUBTABLES) {
        LOG_CORE_WARN("Invalid SubTable index: %d", subtable_idx);
        return;
    }

    if (!g_pGlobalStringTable || !*g_pGlobalStringTable) {
        LOG_CORE_WARN("GlobalStringTable not available");
        return;
    }

    void *gst = NULL;
    if (!safe_read_ptr(g_pGlobalStringTable, &gst) || !gst) {
        LOG_CORE_WARN("Cannot read GlobalStringTable");
        return;
    }

    void *subTable = (char *)gst + (subtable_idx * g_SubTableSize);

    uint32_t numBuckets = 0;
    uint32_t entriesPerBucket = 0;
    uint64_t entrySize = 0;
    void *buckets = NULL;

    safe_read_u32((char *)subTable + g_OffsetNumBuckets, &numBuckets);
    safe_read_u32((char *)subTable + g_OffsetEntriesPerBucket, &entriesPerBucket);
    safe_read_u64((char *)subTable + g_OffsetEntrySize, &entrySize);
    safe_read_ptr((char *)subTable + g_OffsetBuckets, &buckets);

    LOG_CORE_DEBUG("SubTable[%d] at %p:", subtable_idx, subTable);
    LOG_CORE_DEBUG("  NumBuckets: %u", numBuckets);
    LOG_CORE_DEBUG("  EntriesPerBucket: %u", entriesPerBucket);
    LOG_CORE_DEBUG("  EntrySize: %llu", entrySize);
    LOG_CORE_DEBUG("  Buckets: %p", buckets);

    // Try to read first string
    if (buckets && numBuckets > 0 && entrySize > 0) {
        void *firstBucket = NULL;
        if (safe_read_ptr(buckets, &firstBucket) && firstBucket) {
            // First entry in first bucket
            void *entry = firstBucket;
            char strBuf[64] = {0};

            if (safe_read_bytes((char *)entry + STRING_ENTRY_HEADER_SIZE,
                               strBuf, sizeof(strBuf) - 1)) {
                LOG_CORE_DEBUG("  First string: \"%s\"", strBuf);
            }
        }
    }
}
