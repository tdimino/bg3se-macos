/**
 * stats_manager.c - Stats System Manager for BG3SE-macOS
 *
 * Provides access to the game's RPGStats system for reading and modifying
 * game statistics (weapons, armor, spells, statuses, passives, etc.)
 *
 * The stats system uses CNamedElementManager<T> templates to store:
 * - ModifierValueLists (RPGEnumeration) - Type definitions and enums
 * - ModifierLists - Stat types (Weapon, Armor, SpellData, etc.)
 * - Objects - Actual stat entries with properties
 *
 * Properties are stored as indices into global pools (FixedStrings, Floats, etc.)
 */

#include "stats_manager.h"
#include "logging.h"
#include "../strings/fixed_string.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>

// ============================================================================
// Memory Safety
// ============================================================================

// Safely read memory using mach_vm_read (won't crash on bad addresses)
static bool safe_read_ptr(void *addr, void **out_value) {
    if (!addr || !out_value) return false;

    vm_size_t size = sizeof(void*);
    vm_offset_t data;
    kern_return_t kr = vm_read(mach_task_self(), (vm_address_t)addr,
                               size, &data, (mach_msg_type_number_t*)&size);
    if (kr != KERN_SUCCESS) return false;

    *out_value = *(void**)data;
    vm_deallocate(mach_task_self(), data, size);
    return true;
}

static bool safe_read_u8(void *addr, uint8_t *out_value) {
    if (!addr || !out_value) return false;

    vm_size_t size = sizeof(uint8_t);
    vm_offset_t data;
    kern_return_t kr = vm_read(mach_task_self(), (vm_address_t)addr,
                               size, &data, (mach_msg_type_number_t*)&size);
    if (kr != KERN_SUCCESS) return false;

    *out_value = *(uint8_t*)data;
    vm_deallocate(mach_task_self(), data, size);
    return true;
}

static bool safe_read_u32(void *addr, uint32_t *out_value) {
    if (!addr || !out_value) return false;

    vm_size_t size = sizeof(uint32_t);
    vm_offset_t data;
    kern_return_t kr = vm_read(mach_task_self(), (vm_address_t)addr,
                               size, &data, (mach_msg_type_number_t*)&size);
    if (kr != KERN_SUCCESS) return false;

    *out_value = *(uint32_t*)data;
    vm_deallocate(mach_task_self(), data, size);
    return true;
}

static bool safe_read_i32(void *addr, int32_t *out_value) {
    if (!addr || !out_value) return false;

    vm_size_t size = sizeof(int32_t);
    vm_offset_t data;
    kern_return_t kr = vm_read(mach_task_self(), (vm_address_t)addr,
                               size, &data, (mach_msg_type_number_t*)&size);
    if (kr != KERN_SUCCESS) return false;

    *out_value = *(int32_t*)data;
    vm_deallocate(mach_task_self(), data, size);
    return true;
}

static bool safe_write_i32(void *addr, int32_t value) {
    if (!addr) return false;

    kern_return_t kr = vm_write(mach_task_self(),
                                (vm_address_t)addr,
                                (vm_offset_t)&value,
                                sizeof(int32_t));
    return kr == KERN_SUCCESS;
}

// ============================================================================
// Symbol Resolution
// ============================================================================

// RPGStats::m_ptr mangled symbol name
#define RPGSTATS_M_PTR_SYMBOL "__ZN8RPGStats5m_ptrE"

// Ghidra offset (for fallback if dlsym fails)
#define GHIDRA_BASE_ADDRESS 0x100000000ULL
#define OFFSET_RPGSTATS_M_PTR 0x1089c5730ULL

// ============================================================================
// Structure Offsets (from Windows BG3SE + ARM64 alignment)
// These need to be verified with Ghidra analysis
// ============================================================================

// RPGStats structure offsets
// CNamedElementManager has: VMT(8) + Values(24) + NameToHandle(~48) + NextHandle(4)
// Approximate size per manager: ~80-88 bytes

// For ARM64, we assume 8-byte alignment
// struct RPGStats {
//     VMT;                             // +0x00 (8 bytes)
//     CNamedElementManager ModifierValueLists;  // +0x08
//     CNamedElementManager ModifierLists;       // +0x??
//     CNamedElementManager Objects;             // +0x??
//     ...
// }

// CNamedElementManager<T> offsets (ARM64)
// From BG3SE Common.h - CNamedElementManager has:
//   VMT (8 bytes) - virtual destructor
//   Array<T*> Values (16 bytes: buf_[8] + capacity_[4] + size_[4])
//   HashMap<FixedString, int32_t> NameToHandle (~48 bytes)
//   int32_t NextHandle (4 bytes)
// Total: ~80 bytes per manager

#define CNEM_OFFSET_VMT           0x00
#define CNEM_OFFSET_VALUES_BUF    0x08   // Array.buf_ (pointer to T*)
#define CNEM_OFFSET_VALUES_CAP    0x10   // Array.capacity_
#define CNEM_OFFSET_VALUES_SIZE   0x14   // Array.size_
#define CNEM_OFFSET_NAMETOHASH    0x18   // HashMap start
// NextHandle offset varies, determined at runtime

// RPGStats offsets - empirically determined from runtime probing (Dec 2025)
// Verified via console: ModifierLists has 9 entries, Objects has 15,774 entries
#define RPGSTATS_OFFSET_OBJECTS             0xC0   // CNamedElementManager<Object> Objects (verified)
#define RPGSTATS_OFFSET_MODIFIER_LISTS      0x60   // CNamedElementManager<ModifierList> ModifierLists (verified)
#define RPGSTATS_OFFSET_FIXEDSTRINGS        0x348  // TrackedCompactSet<FixedString> FixedStrings (Ghidra: StatsObject::GetFixedStringValue)

// Array<T*> offsets within CNamedElementManager
#define ARRAY_OFFSET_BUFFER       0x00
#define ARRAY_OFFSET_CAPACITY     0x08
#define ARRAY_OFFSET_SIZE         0x0C

// stats::Object offsets (VERIFIED Dec 5, 2025 via C-level memory dump)
// struct Object {
//   void* VMT;                           // +0x00 (8 bytes)
//   Vector<int32_t> IndexedProperties;   // +0x08 (24 bytes: begin_[8]+end_[8]+cap_[8])
//   FixedString Name;                    // +0x20 (8 bytes)
//   HashMap Functors;                    // +0x28 (pointer)
//   ... more fields ...
//   int32_t Using;                       // near end (offset TBD)
//   uint32_t ModifierListIndex;          // offset TBD
//   uint32_t Level;                      // offset TBD
// }
#define OBJECT_OFFSET_VMT              0x00
#define OBJECT_OFFSET_INDEXED_PROPS    0x08   // Vector<int32_t> IndexedProperties
#define OBJECT_OFFSET_NAME             0x20   // FixedString Name

// Vector<int32_t> layout on ARM64 (std::vector uses 3 pointers):
// - begin_: pointer to first element
// - end_: pointer past last element
// - capacity_: pointer to end of allocated space
// Size = (end_ - begin_) / sizeof(int32_t)
#define VECTOR_OFFSET_BEGIN     0x00   // Pointer to first element
#define VECTOR_OFFSET_END       0x08   // Pointer past last element
#define VECTOR_OFFSET_CAPACITY  0x10   // Pointer to end of allocation

// Old offset notes (may be incorrect for ARM64):
#define OBJECT_OFFSET_USING            0xa8   // int32_t Using (parent stat index, -1 if none)
#define OBJECT_OFFSET_MODIFIERLIST_IDX 0x00   // uint8_t ModifierListIndex (stat type) - verified via memory dump
#define OBJECT_OFFSET_LEVEL            0xb0   // uint32_t Level

// FixedString structure
// FixedString is typically just a const char* pointer in Larian's engine
// On ARM64 it's 8 bytes
#define FIXEDSTRING_SIZE 8

// Modifier structure offsets (VERIFIED Dec 5, 2025 via runtime probing):
// struct Modifier {
//     int32_t EnumerationIndex;   // +0x00: Type ID of this attribute (e.g., 53, 54, 15)
//     int32_t LevelMapIndex;      // +0x04: Always -1 in observed data
//     int32_t UnknownZero;        // +0x08: Always 0 in observed data
//     FixedString Name;           // +0x0C: Attribute name ("Damage", "Damage Type", etc.)
// };
// Note: ARM64 FixedString is NOT 8-byte aligned here - it's at 0x0C (packed)
#define MODIFIER_OFFSET_ENUM_INDEX    0x00
#define MODIFIER_OFFSET_LEVEL_MAP     0x04
#define MODIFIER_OFFSET_UNKNOWN       0x08
#define MODIFIER_OFFSET_NAME          0x0C   // FixedString (verified via runtime dump)

// ============================================================================
// Global State
// ============================================================================

static void *g_MainBinaryBase = NULL;
static void **g_pRPGStatsPtr = NULL;   // Pointer to RPGStats::m_ptr
static bool g_Initialized = false;

// Forward declarations for internal helpers
static void* get_objects_manager(void);
static int get_manager_count(void *manager);
static void* get_manager_element(void *manager, int index);
static const char* read_fixed_string(void *addr);

// ============================================================================
// Initialization
// ============================================================================

void stats_manager_init(void *main_binary_base) {
    if (g_Initialized) {
        LOG_STATS_DEBUG("Already initialized");
        return;
    }

    g_MainBinaryBase = main_binary_base;

    LOG_STATS_DEBUG("=== Stats Manager Initialization ===");
    LOG_STATS_DEBUG("Main binary base: %p", main_binary_base);

    // Initialize FixedString resolution system
    fixed_string_init(main_binary_base);

    // Try to resolve RPGStats::m_ptr via dlsym
    // The symbol is exported in the main binary's symbol table
    void *handle = dlopen(NULL, RTLD_NOW);  // Get handle to main executable
    if (handle) {
        g_pRPGStatsPtr = (void**)dlsym(handle, RPGSTATS_M_PTR_SYMBOL);
        if (g_pRPGStatsPtr) {
            LOG_STATS_DEBUG("Resolved %s via dlsym: %p", RPGSTATS_M_PTR_SYMBOL, (void*)g_pRPGStatsPtr);
        } else {
            LOG_STATS_DEBUG("dlsym failed for %s: %s", RPGSTATS_M_PTR_SYMBOL, dlerror());
        }
    }

    // Fallback: Calculate from Ghidra offset
    if (!g_pRPGStatsPtr && main_binary_base) {
        uintptr_t runtime_addr = (uintptr_t)main_binary_base +
                                  (OFFSET_RPGSTATS_M_PTR - GHIDRA_BASE_ADDRESS);
        g_pRPGStatsPtr = (void**)runtime_addr;
        LOG_STATS_DEBUG("Using Ghidra offset: %p (base %p + offset 0x%llx)",
                  (void*)g_pRPGStatsPtr, main_binary_base,
                  (unsigned long long)(OFFSET_RPGSTATS_M_PTR - GHIDRA_BASE_ADDRESS));
    }

    g_Initialized = true;

    // Check if stats system is ready yet
    if (stats_manager_ready()) {
        LOG_STATS_DEBUG("Stats system is READY");
        void *rpgstats = stats_manager_get_raw();
        LOG_STATS_DEBUG("RPGStats instance: %p", rpgstats);
    } else {
        LOG_STATS_DEBUG("Stats system not yet ready (m_ptr is NULL - will retry at SessionLoaded)");
    }
}

void stats_manager_on_session_loaded(void) {
    LOG_STATS_DEBUG("=== SessionLoaded: Checking Stats System ===");

    if (!g_Initialized) {
        LOG_STATS_DEBUG("ERROR: Stats manager not initialized");
        return;
    }

    if (!g_pRPGStatsPtr) {
        LOG_STATS_DEBUG("ERROR: g_pRPGStatsPtr is NULL");
        return;
    }

    // Read the pointer value
    void *stats_ptr = NULL;
    if (!safe_read_ptr(g_pRPGStatsPtr, &stats_ptr)) {
        LOG_STATS_DEBUG("ERROR: Failed to read m_ptr (bad address?)");
        return;
    }

    if (!stats_ptr) {
        LOG_STATS_DEBUG("WARNING: m_ptr is still NULL after SessionLoaded");
        return;
    }

    LOG_STATS_DEBUG("Stats system pointer (from m_ptr): %p", stats_ptr);

    // FixedString will be discovered lazily on first resolution attempt
    // This avoids slow startup - discovery uses reference-based search for speed
    if (fixed_string_is_ready()) {
        LOG_STATS_DEBUG("FixedString system: READY");
    } else {
        LOG_STATS_DEBUG("FixedString system: Will initialize on first use (lazy discovery)");
    }

    // Check if we need another level of indirection
    void *first_qword = NULL;
    if (safe_read_ptr(stats_ptr, &first_qword)) {
        LOG_STATS_DEBUG("  First qword at stats_ptr: %p", first_qword);
        // If it looks like a heap pointer (not VMT), we might need to dereference again
        if (first_qword && (uintptr_t)first_qword > 0x100000000ULL &&
            ((uintptr_t)first_qword >> 32) != 0x1) {  // Not a code pointer
            LOG_STATS_DEBUG("  First qword looks like heap ptr, using as actual RPGStats");
            stats_ptr = first_qword;
        }
    }

    // Probe for CNamedElementManager-like structures at various offsets
    LOG_STATS_DEBUG("Probing for Objects manager at various offsets:");
    for (int off = 0x00; off <= 0x180; off += 0x08) {
        void *mgr = (char*)stats_ptr + off;
        void *buf = NULL;
        if (!safe_read_ptr((char*)mgr + 0x08, &buf)) continue;

        // Check if buf looks like a valid heap pointer
        if (!buf || (uintptr_t)buf < 0x100000000ULL) continue;
        if (((uintptr_t)buf >> 32) == 0x9) continue;  // Skip garbage like 0x9XXXXXXXX

        uint32_t cap = 0, sz = 0;
        safe_read_u32((char*)mgr + 0x10, &cap);
        safe_read_u32((char*)mgr + 0x14, &sz);

        // Look for reasonable array sizes (100-50000)
        if (sz >= 100 && sz <= 50000 && cap >= sz) {
            LOG_STATS_DEBUG("  +0x%03x: buf=%p, cap=%u, size=%u", off, buf, cap, sz);

            // Try to read first element and its name (safely)
            void *elem = NULL;
            if (safe_read_ptr(buf, &elem) && elem) {
                LOG_STATS_DEBUG("    elem[0]=%p", elem);

                // Only do detailed dump for the 15774-size manager (likely Objects)
                if (sz == 15774 && off == 0xC0) {
                    // Dump first 64 bytes of element as hex
                    LOG_STATS_DEBUG("    Dumping elem[0] structure:");
                    for (int dump_off = 0; dump_off < 64; dump_off += 8) {
                        void *val = NULL;
                        if (safe_read_ptr((char*)elem + dump_off, &val)) {
                            LOG_STATS_DEBUG("      +0x%02x: %p", dump_off, val);

                            // Try to read content from heap pointers
                            if (val && (uintptr_t)val > 0x100000000ULL &&
                                ((uintptr_t)val >> 40) != 0x1) {  // Skip code pointers
                                uint8_t raw_buf[24] = {0};
                                vm_size_t raw_sz = 24;
                                vm_offset_t raw_data;
                                if (vm_read(mach_task_self(), (vm_address_t)val, raw_sz,
                                            &raw_data, (mach_msg_type_number_t*)&raw_sz) == KERN_SUCCESS) {
                                    memcpy(raw_buf, (void*)raw_data, 24);
                                    vm_deallocate(mach_task_self(), raw_data, raw_sz);
                                    // Print first 16 bytes as hex
                                    LOG_STATS_DEBUG("        -> %02x %02x %02x %02x %02x %02x %02x %02x | %02x %02x %02x %02x %02x %02x %02x %02x",
                                        raw_buf[0], raw_buf[1], raw_buf[2], raw_buf[3],
                                        raw_buf[4], raw_buf[5], raw_buf[6], raw_buf[7],
                                        raw_buf[8], raw_buf[9], raw_buf[10], raw_buf[11],
                                        raw_buf[12], raw_buf[13], raw_buf[14], raw_buf[15]);
                                    // Also try as string if printable
                                    if (raw_buf[0] >= 0x20 && raw_buf[0] < 0x7F) {
                                        raw_buf[23] = 0;
                                        LOG_STATS_DEBUG("        -> str: \"%s\"", (char*)raw_buf);
                                    }
                                }
                            }
                        }
                    }
                }

                // Try name at multiple offsets (0x08, 0x10, 0x18, 0x20, 0x28, 0x30)
                for (int name_off = 0x08; name_off <= 0x30; name_off += 0x08) {
                    void *name_ptr = NULL;
                    if (safe_read_ptr((char*)elem + name_off, &name_ptr) && name_ptr &&
                        (uintptr_t)name_ptr > 0x100000000ULL) {
                        // Safely read string content
                        char name_buf[64] = {0};
                        vm_size_t name_sz = 48;
                        vm_offset_t name_data;
                        if (vm_read(mach_task_self(), (vm_address_t)name_ptr, name_sz,
                                    &name_data, (mach_msg_type_number_t*)&name_sz) == KERN_SUCCESS) {
                            memcpy(name_buf, (void*)name_data, name_sz < 63 ? name_sz : 63);
                            vm_deallocate(mach_task_self(), name_data, name_sz);
                            // Check if it looks like a stat name (alphanumeric start)
                            if ((name_buf[0] >= 'A' && name_buf[0] <= 'Z') ||
                                (name_buf[0] >= 'a' && name_buf[0] <= 'z')) {
                                LOG_STATS_DEBUG("    elem+0x%02x -> \"%s\"", name_off, name_buf);
                            }
                        }
                    }
                }
            } else {
                LOG_STATS_DEBUG("    elem[0]=NULL or unreadable");
            }
        }
    }

    // Get the Objects manager using current offset
    void *objects_mgr = (char*)stats_ptr + RPGSTATS_OFFSET_OBJECTS;
    LOG_STATS_DEBUG("Using Objects manager at: %p (RPGStats+0x%02x)", objects_mgr, RPGSTATS_OFFSET_OBJECTS);

    // Read raw buffer pointer and count
    void *buf_ptr = NULL;
    if (safe_read_ptr((char*)objects_mgr + CNEM_OFFSET_VALUES_BUF, &buf_ptr)) {
        LOG_STATS_DEBUG("  Values.buf_: %p", buf_ptr);
    }
    uint32_t capacity = 0, size = 0;
    safe_read_u32((char*)objects_mgr + CNEM_OFFSET_VALUES_CAP, &capacity);
    safe_read_u32((char*)objects_mgr + CNEM_OFFSET_VALUES_SIZE, &size);
    LOG_STATS_DEBUG("  Values.capacity_: %u, Values.size_: %u", capacity, size);

    // Get count
    int count = get_manager_count(objects_mgr);
    LOG_STATS_DEBUG("Stats Objects count: %d", count);

    if (count <= 0 || count > 100000) {
        LOG_STATS_DEBUG("ERROR: Invalid count - offsets may be wrong");
        return;
    }

    // Try to read first stat name as a sanity check
    void *first_obj = get_manager_element(objects_mgr, 0);
    LOG_STATS_DEBUG("First element ptr: %p", first_obj);
    if (first_obj) {
        const char *name = read_fixed_string((char*)first_obj + OBJECT_OFFSET_NAME);
        if (name) {
            LOG_STATS_DEBUG("First stat: \"%s\"", name);
        } else {
            LOG_STATS_DEBUG("First stat: (name read failed at +0x%02x)", OBJECT_OFFSET_NAME);
        }
    } else {
        LOG_STATS_DEBUG("ERROR: Could not read first element from buffer");
    }

    LOG_STATS_DEBUG("Stats system READY with %d entries", count);
}

bool stats_manager_ready(void) {
    if (!g_Initialized || !g_pRPGStatsPtr) {
        return false;
    }

    // Read the pointer value safely
    void *stats_ptr = NULL;
    if (!safe_read_ptr(g_pRPGStatsPtr, &stats_ptr)) {
        return false;
    }

    return stats_ptr != NULL;
}

void* stats_manager_get_raw(void) {
    if (!g_pRPGStatsPtr) return NULL;

    void *stats_ptr = NULL;
    if (!safe_read_ptr(g_pRPGStatsPtr, &stats_ptr)) {
        return NULL;
    }

    return stats_ptr;
}

// ============================================================================
// Internal Helpers
// ============================================================================

// Get the Objects manager from RPGStats
// RPGStats layout: VMT(?), ModifierValueLists, ModifierLists, Objects, ...
// Based on runtime probing: Objects.NextHandle at +0x0E0
static void* get_objects_manager(void) {
    void *rpgstats = stats_manager_get_raw();
    if (!rpgstats) return NULL;

    // Objects is the 3rd CNamedElementManager
    // From runtime probing, NextHandle (count) is at +0x0E0
    // Working backwards: CNEM starts ~0x58 before NextHandle
    return (char*)rpgstats + RPGSTATS_OFFSET_OBJECTS;
}

// Get the ModifierLists manager from RPGStats
static void* get_modifier_lists_manager(void) {
    void *rpgstats = stats_manager_get_raw();
    if (!rpgstats) return NULL;

    // ModifierLists is the 2nd CNamedElementManager
    return (char*)rpgstats + RPGSTATS_OFFSET_MODIFIER_LISTS;
}

// Get string from RPGStats.FixedStrings array by index
// RPGStats.FixedStrings is TrackedCompactSet<FixedString>, which is like an array
static const char* get_rpgstats_fixedstring(int32_t index) {
    if (index <= 0) return NULL;  // Index 0 or negative means no value

    void *rpgstats = stats_manager_get_raw();
    if (!rpgstats) return NULL;

    // FixedStrings array is at offset RPGSTATS_OFFSET_FIXEDSTRINGS
    // TrackedCompactSet<T> has: buf_ (ptr), capacity_, size_
    void *fs_array = (char*)rpgstats + RPGSTATS_OFFSET_FIXEDSTRINGS;

    // Read buffer pointer (offset 0x00)
    void *buf = NULL;
    if (!safe_read_ptr(fs_array, &buf) || !buf) {
        LOG_STATS_DEBUG("get_rpgstats_fixedstring: failed to read buf at offset 0x%x", RPGSTATS_OFFSET_FIXEDSTRINGS);
        return NULL;
    }

    // Read size (offset 0x0C for TrackedCompactSet)
    uint32_t size = 0;
    if (!safe_read_u32((char*)fs_array + 0x0C, &size)) {
        LOG_STATS_DEBUG("get_rpgstats_fixedstring: failed to read size");
        return NULL;
    }

    // Bounds check
    if ((uint32_t)index >= size) {
        LOG_STATS_DEBUG("get_rpgstats_fixedstring: index %d out of bounds (size=%u)", index, size);
        return NULL;
    }

    // Each element is a FixedString (4 bytes on macOS)
    // Read the FixedString at buf[index]
    void *fs_addr = (char*)buf + index * sizeof(uint32_t);
    return read_fixed_string(fs_addr);
}

// Find a string value in the RPGStats.FixedStrings pool
// Returns pool index if found, -1 if not found
static int32_t find_fixedstring_pool_index(const char *value) {
    if (!value) return -1;

    void *rpgstats = stats_manager_get_raw();
    if (!rpgstats) return -1;

    void *fs_array = (char*)rpgstats + RPGSTATS_OFFSET_FIXEDSTRINGS;

    // Read buffer pointer
    void *buf = NULL;
    if (!safe_read_ptr(fs_array, &buf) || !buf) {
        return -1;
    }

    // Read size
    uint32_t size = 0;
    if (!safe_read_u32((char*)fs_array + 0x0C, &size)) {
        return -1;
    }

    // Search through the pool for matching string
    for (uint32_t i = 1; i < size; i++) {  // Start at 1 since 0 is null
        void *fs_addr = (char*)buf + i * sizeof(uint32_t);
        const char *str = read_fixed_string(fs_addr);
        if (str && strcmp(str, value) == 0) {
            return (int32_t)i;
        }
    }

    return -1;  // Not found
}

// Read FixedString - on macOS this is a 32-bit index into GlobalStringTable
static const char* read_fixed_string(void *addr) {
    if (!addr) return NULL;

    // On macOS ARM64, FixedString is a 32-bit index, not a pointer
    // Read the index value
    uint32_t fs_index = 0;
    if (!safe_read_u32(addr, &fs_index)) {
        return NULL;
    }

    // Check for null index
    if (fs_index == FS_NULL_INDEX) {
        return NULL;
    }

    // Use the fixed_string module to resolve the index to a string
    // This will trigger lazy discovery if GlobalStringTable hasn't been found yet
    return fixed_string_resolve(fs_index);
}

// Get count of elements in a CNamedElementManager
// Use Array.size_ which is more reliable than NextHandle
static int get_manager_count(void *manager) {
    if (!manager) return -1;

    // Read Values.size_ (at offset +0x14 from manager start)
    // Manager layout: VMT(8) + Values.buf_(8) + Values.cap_(4) + Values.size_(4)
    uint32_t size = 0;
    void *size_addr = (char*)manager + CNEM_OFFSET_VALUES_SIZE;
    if (!safe_read_u32(size_addr, &size)) {
        return -1;
    }

    return (int)size;
}

// Get element at index from CNamedElementManager
static void* get_manager_element(void *manager, int index) {
    if (!manager || index < 0) return NULL;

    // Read Values.buf_ pointer directly (at offset +0x08 from manager start)
    // Manager layout: VMT(8) + Values.buf_(8) + Values.cap_(4) + Values.size_(4)
    void *buffer = NULL;
    if (!safe_read_ptr((char*)manager + CNEM_OFFSET_VALUES_BUF, &buffer)) {
        return NULL;
    }

    if (!buffer) return NULL;

    // Read element at index (array of pointers)
    void *element_ptr_addr = (char*)buffer + (index * sizeof(void*));
    void *element = NULL;
    if (!safe_read_ptr(element_ptr_addr, &element)) {
        return NULL;
    }

    return element;
}

// ============================================================================
// Stat Object Access
// ============================================================================

StatsObjectPtr stats_get(const char *name) {
    if (!name || !stats_manager_ready()) {
        return NULL;
    }

    void *objects = get_objects_manager();
    if (!objects) {
        LOG_STATS_DEBUG("Failed to get Objects manager");
        return NULL;
    }

    // Linear search through all objects (inefficient but safe for now)
    // TODO: Implement hash table lookup for performance
    int count = get_manager_count(objects);
    if (count <= 0) {
        LOG_STATS_DEBUG("No stats objects found (count: %d)", count);
        return NULL;
    }

    for (int i = 0; i < count; i++) {
        void *obj = get_manager_element(objects, i);
        if (!obj) continue;

        // Read object name (FixedString at offset)
        const char *obj_name = read_fixed_string((char*)obj + OBJECT_OFFSET_NAME);
        if (obj_name && strcmp(obj_name, name) == 0) {
            return obj;
        }
    }

    return NULL;
}

const char* stats_get_type(StatsObjectPtr obj) {
    if (!obj) return NULL;

    // WORKAROUND: Use name-based type detection
    // The Object struct layout on macOS ARM64 differs significantly from Windows x64
    // due to different sizes of HashMap, Array, TrackedCompactSet, etc.
    // Until we discover the true ModifierListIndex offset, use stat name prefixes.
    const char *obj_name = read_fixed_string((char*)obj + OBJECT_OFFSET_NAME);
    if (obj_name) {
        // Common stat name prefixes map to types
        if (strncmp(obj_name, "WPN_", 4) == 0) return "Weapon";
        if (strncmp(obj_name, "ARM_", 4) == 0) return "Armor";
        if (strncmp(obj_name, "Target_", 7) == 0) return "SpellData";
        if (strncmp(obj_name, "Projectile_", 11) == 0) return "SpellData";
        if (strncmp(obj_name, "Rush_", 5) == 0) return "SpellData";
        if (strncmp(obj_name, "Shout_", 6) == 0) return "SpellData";
        if (strncmp(obj_name, "Throw_", 6) == 0) return "SpellData";
        if (strncmp(obj_name, "Zone_", 5) == 0) return "SpellData";
        if (strncmp(obj_name, "Wall_", 5) == 0) return "SpellData";
        if (strncmp(obj_name, "Teleportation_", 14) == 0) return "SpellData";
        if (strncmp(obj_name, "Passive_", 8) == 0) return "PassiveData";
        if (strncmp(obj_name, "Interrupt_", 10) == 0) return "InterruptData";
        if (strncmp(obj_name, "CriticalHit_", 12) == 0) return "CriticalHitTypeData";
        // Status names vary more, check common patterns
        if (strstr(obj_name, "_STATUS") || strstr(obj_name, "Status_")) return "StatusData";

        // Try ModifierListIndex lookup as fallback
        uint8_t modifier_list_idx = 0;
        if (safe_read_u8((char*)obj + OBJECT_OFFSET_MODIFIERLIST_IDX, &modifier_list_idx)) {
            void *modifier_lists = get_modifier_lists_manager();
            if (modifier_lists) {
                void *modifier_list = get_manager_element(modifier_lists, (uint32_t)modifier_list_idx);
                if (modifier_list) {
                    #define MODIFIERLIST_OFFSET_NAME 0x5c
                    const char *type_name = read_fixed_string((char*)modifier_list + MODIFIERLIST_OFFSET_NAME);
                    if (type_name) return type_name;
                }
            }
        }
    }

    return NULL;
}

const char* stats_get_name(StatsObjectPtr obj) {
    if (!obj) return NULL;
    return read_fixed_string((char*)obj + OBJECT_OFFSET_NAME);
}

int stats_get_level(StatsObjectPtr obj) {
    if (!obj) return -1;

    uint32_t level = 0;
    if (!safe_read_u32((char*)obj + OBJECT_OFFSET_LEVEL, &level)) {
        return -1;
    }

    return (int)level;
}

// ============================================================================
// IndexedProperties Access (VERIFIED Dec 5, 2025)
// ============================================================================

// Get the number of indexed properties for a stat object
int stats_get_property_count(StatsObjectPtr obj) {
    if (!obj) return -1;

    // Read begin_ and end_ pointers from the Vector
    void *idx_props = (char*)obj + OBJECT_OFFSET_INDEXED_PROPS;

    void *begin_ptr = NULL;
    void *end_ptr = NULL;

    if (!safe_read_ptr((char*)idx_props + VECTOR_OFFSET_BEGIN, &begin_ptr)) {
        return -1;
    }
    if (!safe_read_ptr((char*)idx_props + VECTOR_OFFSET_END, &end_ptr)) {
        return -1;
    }

    if (!begin_ptr || !end_ptr) return 0;

    // Size = (end - begin) / sizeof(int32_t)
    size_t byte_size = (size_t)end_ptr - (size_t)begin_ptr;
    return (int)(byte_size / sizeof(int32_t));
}

// Get a raw property index value at the given position
// Returns -1 on error, otherwise the int32_t value at that index
int32_t stats_get_property_raw(StatsObjectPtr obj, int property_index) {
    if (!obj || property_index < 0) return -1;

    // Read begin_ pointer
    void *idx_props = (char*)obj + OBJECT_OFFSET_INDEXED_PROPS;
    void *begin_ptr = NULL;

    if (!safe_read_ptr((char*)idx_props + VECTOR_OFFSET_BEGIN, &begin_ptr)) {
        return -1;
    }

    if (!begin_ptr) return -1;

    // Read the int32_t value at the specified index
    int32_t value = 0;
    if (!safe_read_i32((char*)begin_ptr + property_index * sizeof(int32_t), &value)) {
        return -1;
    }

    return value;
}

const char* stats_get_using(StatsObjectPtr obj) {
    if (!obj) return NULL;

    int32_t using_idx = 0;
    if (!safe_read_i32((char*)obj + OBJECT_OFFSET_USING, &using_idx)) {
        return NULL;
    }

    if (using_idx < 0) return NULL;  // No parent

    // Look up parent stat by index
    void *objects = get_objects_manager();
    if (!objects) return NULL;

    void *parent = get_manager_element(objects, using_idx);
    if (!parent) return NULL;

    return stats_get_name(parent);
}

// ============================================================================
// Property Index Lookup (finds property index by name in ModifierList)
// ============================================================================

// Get ModifierList for an object (by its ModifierListIndex)
static void* get_object_modifier_list(StatsObjectPtr obj) {
    if (!obj) return NULL;

    // ModifierListIndex is a uint8_t at offset 0x00
    uint8_t modifier_list_idx = 0;
    if (!safe_read_u8((char*)obj + OBJECT_OFFSET_MODIFIERLIST_IDX, &modifier_list_idx)) {
        LOG_STATS_DEBUG("get_object_modifier_list: failed to read ModifierListIndex at +0x%x", OBJECT_OFFSET_MODIFIERLIST_IDX);
        return NULL;
    }
    LOG_STATS_DEBUG("get_object_modifier_list: ModifierListIndex = %u", (uint32_t)modifier_list_idx);

    void *modifier_lists = get_modifier_lists_manager();
    if (!modifier_lists) return NULL;

    return get_manager_element(modifier_lists, (uint32_t)modifier_list_idx);
}

// Find property index by name in a ModifierList's Attributes
// Returns -1 if not found
static int find_property_index_by_name(void *modifier_list, const char *prop_name) {
    if (!modifier_list || !prop_name) return -1;

    // ModifierList starts with CNamedElementManager<Modifier> Attributes
    void *attrs_mgr = modifier_list;  // Attributes is at offset 0

    // Read attributes count
    uint32_t attr_count = 0;
    if (!safe_read_u32((char*)attrs_mgr + CNEM_OFFSET_VALUES_SIZE, &attr_count)) {
        LOG_STATS_DEBUG("find_property_index_by_name: failed to read attr_count");
        return -1;
    }
    LOG_STATS_DEBUG("find_property_index_by_name: attr_count = %u", attr_count);

    // Read attributes buffer
    void *attrs_buf = NULL;
    if (!safe_read_ptr((char*)attrs_mgr + CNEM_OFFSET_VALUES_BUF, &attrs_buf) || !attrs_buf) {
        LOG_STATS_DEBUG("find_property_index_by_name: failed to read attrs_buf");
        return -1;
    }
    LOG_STATS_DEBUG("find_property_index_by_name: attrs_buf = %p", attrs_buf);

    // Linear search through Modifiers to find by name
    for (uint32_t i = 0; i < attr_count && i < 5; i++) {  // Log first 5 for debug
        void *modifier_ptr = NULL;
        if (!safe_read_ptr((char*)attrs_buf + i * sizeof(void*), &modifier_ptr) || !modifier_ptr) {
            continue;
        }

        // Read the Modifier's name at offset 0x0C
        const char *mod_name = read_fixed_string((char*)modifier_ptr + MODIFIER_OFFSET_NAME);
        LOG_STATS_DEBUG("  attr[%u] = '%s'", i, mod_name ? mod_name : "(null)");
        if (mod_name && strcmp(mod_name, prop_name) == 0) {
            return (int)i;  // Found! Return the index
        }
    }

    // Continue searching without logging
    for (uint32_t i = 5; i < attr_count; i++) {
        void *modifier_ptr = NULL;
        if (!safe_read_ptr((char*)attrs_buf + i * sizeof(void*), &modifier_ptr) || !modifier_ptr) {
            continue;
        }
        const char *mod_name = read_fixed_string((char*)modifier_ptr + MODIFIER_OFFSET_NAME);
        if (mod_name && strcmp(mod_name, prop_name) == 0) {
            return (int)i;
        }
    }

    return -1;  // Not found
}

// ============================================================================
// Property Access (Read) - Implemented via IndexedProperties
// ============================================================================

// Helper: Resolve property name to index via ModifierList
// Returns -1 on failure
static int get_property_index(StatsObjectPtr obj, const char *prop) {
    void *modifier_list = get_object_modifier_list(obj);
    if (!modifier_list) return -1;
    return find_property_index_by_name(modifier_list, prop);
}

const char* stats_get_string(StatsObjectPtr obj, const char *prop) {
    if (!obj || !prop) return NULL;

    int prop_index = get_property_index(obj, prop);
    if (prop_index < 0) return NULL;

    int32_t pool_index = stats_get_property_raw(obj, prop_index);
    if (pool_index < 0) return NULL;

    return get_rpgstats_fixedstring(pool_index);
}

bool stats_get_int(StatsObjectPtr obj, const char *prop, int64_t *out_value) {
    if (!obj || !prop || !out_value) return false;

    int prop_index = get_property_index(obj, prop);
    if (prop_index < 0) return false;

    *out_value = (int64_t)stats_get_property_raw(obj, prop_index);
    return true;
}

bool stats_get_float(StatsObjectPtr obj, const char *prop, float *out_value) {
    if (!obj || !prop || !out_value) return false;

    int prop_index = get_property_index(obj, prop);
    if (prop_index < 0) return false;

    int32_t raw_value = stats_get_property_raw(obj, prop_index);
    union { int32_t i; float f; } conv;
    conv.i = raw_value;
    *out_value = conv.f;
    return true;
}

// ============================================================================
// Property Access (Write)
// ============================================================================

// Helper: Get write address for a property in IndexedProperties array
// Returns NULL on failure, logs errors with caller_name
static void *get_property_write_address(StatsObjectPtr obj, const char *prop,
                                         int *out_prop_index, const char *caller_name) {
    int prop_index = get_property_index(obj, prop);
    if (prop_index < 0) {
        LOG_STATS_DEBUG("%s: property '%s' not found", caller_name, prop);
        return NULL;
    }

    void *idx_props = (char*)obj + OBJECT_OFFSET_INDEXED_PROPS;
    void *begin_ptr = NULL;
    if (!safe_read_ptr((char*)idx_props + VECTOR_OFFSET_BEGIN, &begin_ptr) || !begin_ptr) {
        LOG_STATS_DEBUG("%s: failed to read IndexedProperties", caller_name);
        return NULL;
    }

    if (out_prop_index) *out_prop_index = prop_index;
    return (char*)begin_ptr + prop_index * sizeof(int32_t);
}

bool stats_set_string(StatsObjectPtr obj, const char *prop, const char *value) {
    if (!obj || !prop || !value) return false;

    int prop_index;
    void *write_addr = get_property_write_address(obj, prop, &prop_index, "stats_set_string");
    if (!write_addr) return false;

    int32_t pool_index = find_fixedstring_pool_index(value);
    if (pool_index < 0) {
        LOG_STATS_DEBUG("stats_set_string: value '%s' not found in FixedStrings pool", value);
        return false;
    }

    if (!safe_write_i32(write_addr, pool_index)) {
        LOG_STATS_DEBUG("stats_set_string: failed to write pool index");
        return false;
    }

    LOG_STATS_DEBUG("stats_set_string: %s = '%s' (prop_index=%d, pool_index=%d)", prop, value, prop_index, pool_index);
    return true;
}

bool stats_set_int(StatsObjectPtr obj, const char *prop, int64_t value) {
    if (!obj || !prop) return false;

    int prop_index;
    void *write_addr = get_property_write_address(obj, prop, &prop_index, "stats_set_int");
    if (!write_addr) return false;

    int32_t val32 = (int32_t)value;
    if (!safe_write_i32(write_addr, val32)) {
        LOG_STATS_DEBUG("stats_set_int: failed to write value");
        return false;
    }

    LOG_STATS_DEBUG("stats_set_int: %s = %d (index %d)", prop, val32, prop_index);
    return true;
}

bool stats_set_float(StatsObjectPtr obj, const char *prop, float value) {
    if (!obj || !prop) return false;

    int prop_index;
    void *write_addr = get_property_write_address(obj, prop, &prop_index, "stats_set_float");
    if (!write_addr) return false;

    union { float f; int32_t i; } conv;
    conv.f = value;
    if (!safe_write_i32(write_addr, conv.i)) {
        LOG_STATS_DEBUG("stats_set_float: failed to write value");
        return false;
    }

    LOG_STATS_DEBUG("stats_set_float: %s = %f (index %d)", prop, value, prop_index);
    return true;
}

// ============================================================================
// Sync - Stub implementation
// ============================================================================

bool stats_sync(const char *name) {
    if (!name) return false;

    LOG_STATS_DEBUG("stats_sync not yet implemented");
    return false;
}

// ============================================================================
// Enumeration
// ============================================================================

int stats_get_count(const char *type) {
    if (!stats_manager_ready()) return -1;

    void *objects = get_objects_manager();
    if (!objects) return -1;

    int total = get_manager_count(objects);
    if (total < 0) return -1;

    // If no type filter, return total
    if (!type) return total;

    // Count objects matching the type
    int count = 0;
    for (int i = 0; i < total; i++) {
        void *obj = get_manager_element(objects, i);
        if (!obj) continue;

        const char *obj_type = stats_get_type(obj);
        if (obj_type && strcmp(obj_type, type) == 0) {
            count++;
        }
    }

    return count;
}

const char* stats_get_name_at(const char *type, int index) {
    if (!stats_manager_ready() || index < 0) return NULL;

    void *objects = get_objects_manager();
    if (!objects) return NULL;

    int total = get_manager_count(objects);
    if (total < 0) return NULL;

    // If no type filter, direct access
    if (!type) {
        if (index >= total) return NULL;
        void *obj = get_manager_element(objects, index);
        return obj ? stats_get_name(obj) : NULL;
    }

    // Find nth object matching the type
    int count = 0;
    for (int i = 0; i < total; i++) {
        void *obj = get_manager_element(objects, i);
        if (!obj) continue;

        const char *obj_type = stats_get_type(obj);
        if (obj_type && strcmp(obj_type, type) == 0) {
            if (count == index) {
                return stats_get_name(obj);
            }
            count++;
        }
    }

    return NULL;
}

// ============================================================================
// Stat Creation - Stub implementation
// ============================================================================

StatsObjectPtr stats_create(const char *name, const char *type, const char *template_name) {
    if (!name || !type) return NULL;

    (void)template_name;  // Unused for now
    LOG_STATS_DEBUG("stats_create not yet implemented");
    return NULL;
}

// ============================================================================
// Debugging
// ============================================================================

void stats_dump(StatsObjectPtr obj) {
    if (!obj) {
        LOG_STATS_DEBUG("Cannot dump NULL stat object");
        return;
    }

    const char *name = stats_get_name(obj);
    const char *type = stats_get_type(obj);
    int level = stats_get_level(obj);
    const char *using_stat = stats_get_using(obj);

    LOG_STATS_DEBUG("=== Stat Object Dump ===");
    LOG_STATS_DEBUG("  Address: %p", obj);
    LOG_STATS_DEBUG("  Name: %s", name ? name : "(null)");
    LOG_STATS_DEBUG("  Type: %s", type ? type : "(null)");
    LOG_STATS_DEBUG("  Level: %d", level);
    LOG_STATS_DEBUG("  Using: %s", using_stat ? using_stat : "(none)");
}

void stats_dump_types(void) {
    if (!stats_manager_ready()) {
        LOG_STATS_DEBUG("Stats system not ready");
        return;
    }

    void *modifier_lists = get_modifier_lists_manager();
    if (!modifier_lists) {
        LOG_STATS_DEBUG("Failed to get ModifierLists manager");
        return;
    }

    int count = get_manager_count(modifier_lists);
    LOG_STATS_DEBUG("=== Stat Types (ModifierLists) ===");
    LOG_STATS_DEBUG("Total: %d", count);

    for (int i = 0; i < count && i < 50; i++) {  // Limit output
        void *ml = get_manager_element(modifier_lists, i);
        if (!ml) continue;

        const char *name = read_fixed_string((char*)ml + MODIFIERLIST_OFFSET_NAME);
        LOG_STATS_DEBUG("  [%d] %s", i, name ? name : "(unnamed)");
    }
}

// ============================================================================
// Modifier Attribute Enumeration (for property name mapping)
// ============================================================================

void stats_dump_modifierlist_attributes(int ml_index) {
    void *modifier_lists = get_modifier_lists_manager();
    if (!modifier_lists) {
        LOG_STATS_DEBUG("ModifierLists not available");
        return;
    }

    int ml_count = get_manager_count(modifier_lists);
    if (ml_index < 0 || ml_index >= ml_count) {
        LOG_STATS_DEBUG("Invalid ModifierList index: %d (max: %d)", ml_index, ml_count - 1);
        return;
    }

    void *ml = get_manager_element(modifier_lists, ml_index);
    if (!ml) {
        LOG_STATS_DEBUG("Failed to get ModifierList[%d]", ml_index);
        return;
    }

    const char *ml_name = read_fixed_string((char*)ml + MODIFIERLIST_OFFSET_NAME);
    LOG_STATS_DEBUG("=== ModifierList[%d] '%s' Attributes ===", ml_index, ml_name ? ml_name : "(unknown)");
    LOG_STATS_DEBUG("ModifierList ptr: %p", ml);

    // ModifierList starts with CNamedElementManager<Modifier> Attributes
    void *attrs_mgr = ml;  // Attributes is at offset 0

    // Read attributes count from different potential offsets to diagnose
    uint32_t attr_count = 0;
    if (!safe_read_u32((char*)attrs_mgr + CNEM_OFFSET_VALUES_SIZE, &attr_count)) {
        LOG_STATS_DEBUG("Failed to read attributes count at +0x%x", CNEM_OFFSET_VALUES_SIZE);
        return;
    }

    void *attrs_buf = NULL;
    if (!safe_read_ptr((char*)attrs_mgr + CNEM_OFFSET_VALUES_BUF, &attrs_buf) || !attrs_buf) {
        LOG_STATS_DEBUG("Failed to read attributes buffer at +0x%x", CNEM_OFFSET_VALUES_BUF);
        return;
    }

    LOG_STATS_DEBUG("Attributes count: %u, buf: %p (read from +0x%x, +0x%x)",
              attr_count, attrs_buf, CNEM_OFFSET_VALUES_SIZE, CNEM_OFFSET_VALUES_BUF);

    // Dump first few pointers to understand structure
    LOG_STATS_DEBUG("First 5 pointer values in attrs_buf:");
    for (int i = 0; i < 5 && (uint32_t)i < attr_count; i++) {
        void *ptr = NULL;
        safe_read_ptr((char*)attrs_buf + i * sizeof(void*), &ptr);
        LOG_STATS_DEBUG("  buf[%d] = %p", i, ptr);
    }

    // Try to enumerate first few modifiers with extra debug info
    LOG_STATS_DEBUG("Enumerating first 10 Modifier entries:");
    for (uint32_t i = 0; i < attr_count && i < 10; i++) {
        void *modifier_ptr = NULL;
        if (!safe_read_ptr((char*)attrs_buf + i * sizeof(void*), &modifier_ptr) || !modifier_ptr) {
            LOG_STATS_DEBUG("  [%u] ptr=NULL", i);
            continue;
        }

        // Read raw bytes at modifier to understand layout
        int32_t field0 = 0, field1 = 0, field2 = 0;
        void *field3 = NULL;  // potential FixedString at +0x0C
        void *field4 = NULL;  // potential FixedString at +0x10

        safe_read_i32((char*)modifier_ptr + 0x00, &field0);
        safe_read_i32((char*)modifier_ptr + 0x04, &field1);
        safe_read_i32((char*)modifier_ptr + 0x08, &field2);
        safe_read_ptr((char*)modifier_ptr + 0x0C, &field3);
        safe_read_ptr((char*)modifier_ptr + 0x10, &field4);

        const char *name_0c = read_fixed_string((char*)modifier_ptr + 0x0C);
        const char *name_10 = read_fixed_string((char*)modifier_ptr + 0x10);
        const char *name_18 = read_fixed_string((char*)modifier_ptr + 0x18);

        LOG_STATS_DEBUG("  [%u] ptr=%p: f0=%d f1=%d f2=%d | name@0C='%s' name@10='%s' name@18='%s'",
                  i, modifier_ptr, field0, field1, field2,
                  name_0c ? name_0c : "(null)",
                  name_10 ? name_10 : "(null)",
                  name_18 ? name_18 : "(null)");
    }
}

// Debug: Probe RPGStats.FixedStrings at various offsets to find the correct one
void stats_probe_fixedstrings_offset(void) {
    void *rpgstats = stats_manager_get_raw();
    if (!rpgstats) {
        LOG_STATS_DEBUG("Cannot probe: RPGStats not ready");
        return;
    }

    LOG_STATS_DEBUG("=== Probing RPGStats.FixedStrings offset ===");
    LOG_STATS_DEBUG("RPGStats base: %p", rpgstats);
    LOG_STATS_DEBUG("Expected Windows offset: 0x324 (based on field_2F0 + LegacyRefMap + TreasureRarities[7])");

    // Focus on area around expected offset 0x300-0x380
    // Show ALL data at these offsets for diagnosis
    for (uint32_t offset = 0x300; offset <= 0x380; offset += 0x10) {
        void *candidate = (char*)rpgstats + offset;

        // Read potential CompactSet fields
        void *buf = NULL;
        uint32_t cap = 0, size = 0;

        safe_read_ptr(candidate, &buf);
        safe_read_u32((char*)candidate + 0x08, &cap);
        safe_read_u32((char*)candidate + 0x0C, &size);

        LOG_STATS_DEBUG("  +0x%03x: buf=%p cap=%u size=%u", offset, buf, cap, size);

        // If buf looks like a valid pointer and size is reasonable, probe elements
        uintptr_t buf_addr = (uintptr_t)buf;
        if (buf && buf_addr > 0x100000000 && buf_addr < 0x800000000000 && size > 100 && size < 100000) {
            // Try reading a few elements as FixedStrings
            LOG_STATS_DEBUG("    Probing elements (assuming FixedString array):");
            for (int idx = 0; idx < 5; idx++) {
                void *e = (char*)buf + idx * sizeof(uint32_t);
                uint32_t raw = 0;
                safe_read_u32(e, &raw);
                const char *s = read_fixed_string(e);
                LOG_STATS_DEBUG("      [%d] raw=0x%08x str='%s'", idx, raw, s ? s : "(null)");
            }
            // Also check index 2303 (our known Damage value index)
            if (size > 2303) {
                void *e = (char*)buf + 2303 * sizeof(uint32_t);
                uint32_t raw = 0;
                safe_read_u32(e, &raw);
                const char *s = read_fixed_string(e);
                LOG_STATS_DEBUG("      [2303] raw=0x%08x str='%s' <-- Damage value", raw, s ? s : "(null)");
            }
        }
    }

    LOG_STATS_DEBUG("=== End FixedStrings probe ===");
}
