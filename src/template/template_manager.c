/**
 * template_manager.c - Template Manager Implementation for BG3SE-macOS
 *
 * Captures template manager pointers via Frida and provides access for Lua API.
 * Follows the same pattern as staticdata_manager.c.
 */

#include "template_manager.h"
#include "../core/logging.h"
#include "../core/safe_memory.h"
#include "../core/version_detect.h"
#include "../core/offset_table.h"
#include "../strings/fixed_string.h"
#include "../hooks/arm64_hook.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

// ============================================================================
// Constants and Offsets
// ============================================================================

// CacheTemplateManagerBase structure offsets (ARM64, discovered via Ghidra 2025-12-21)
// From decompilation of CacheTemplateManagerBase::GetTemplate
#define CACHE_MGR_BUCKET_PTR_OFFSET      0x50    // Hash bucket array pointer
#define CACHE_MGR_BUCKET_COUNT_OFFSET    0x58    // Bucket count
#define CACHE_MGR_NEXT_CHAIN_OFFSET      0x60    // Next chain array (for collision handling)
#define CACHE_MGR_KEY_ARRAY_OFFSET       0x70    // Key array (TemplateHandle values)
#define CACHE_MGR_VALUE_ARRAY_OFFSET     0x80    // Value array (GameObjectTemplate pointers!)
#define CACHE_MGR_COUNT_OFFSET           0x98    // Template count (verified at runtime)

// GameObjectTemplate structure offsets (ARM64, discovered via Ghidra 2025-12-21)
#define TEMPLATE_VTABLE_OFFSET           0x00    // vtable pointer
#define TEMPLATE_GUID_FS_OFFSET          0x10    // FixedString containing GUID

// Frida capture file paths
#define FRIDA_CAPTURE_DIR            "/tmp"
#define FRIDA_CAPTURE_TEMPLATES      "/tmp/bg3se_templates.txt"
#define FRIDA_CAPTURE_GLOBAL_BANK    "/tmp/bg3se_globalbank.txt"
#define FRIDA_CAPTURE_CACHE_MGR      "/tmp/bg3se_cache_mgr.txt"

// Hook offsets (ARM64, discovered via Ghidra 2025-12-20) - DISABLED due to ADRP constraints
// GlobalTemplateManager::GetTemplateRaw(FixedString const&)
#define OFFSET_GET_TEMPLATE_RAW      0x05f96304

// CacheTemplateManagerBase::CacheTemplate(GameObjectTemplate*, FixedString&, FixedString&)
#define OFFSET_CACHE_TEMPLATE        0x05d31ce4

// Global singleton pointer offsets (discovered via Ghidra CacheTemplateIfNeeded analysis)
// These can be read directly without hooking!
#define OFFSET_GLOBAL_TEMPLATE_MANAGER_PTR  0x08a88508  // ls::GlobalTemplateManager::m_ptr
#define OFFSET_CACHE_TEMPLATE_MANAGER_PTR   0x08a309a8  // CacheTemplateManager::m_ptr
#define OFFSET_LEVEL_CACHE_MANAGER_PTR      0x08a735d8  // Level::s_CacheTemplateManager
#define OFFSET_LEVEL_MANAGER_PTR            0x08a3be40  // LevelManager::m_ptr

// ============================================================================
// Type Name Tables
// ============================================================================

static const char* s_manager_type_names[TEMPLATE_MANAGER_COUNT] = {
    "GlobalTemplateBank",
    "LocalTemplateManager",
    "CacheTemplateManager",
    "LocalCacheTemplates"
};

static const char* s_template_type_names[TEMPLATE_TYPE_COUNT] = {
    "Unknown",
    "Character",
    "Item",
    "Scenery",
    "Surface",
    "Projectile",
    "Decal",
    "Trigger",
    "Prefab",
    "Light"
};

// ============================================================================
// Module State
// ============================================================================

typedef struct {
    bool initialized;
    void* main_binary_base;

    // Captured manager pointers
    void* managers[TEMPLATE_MANAGER_COUNT];

    // Cached template counts (per manager)
    int template_counts[TEMPLATE_MANAGER_COUNT];

    // Captured individual templates (from Frida script)
    void** captured_templates;
    int captured_count;
    int captured_capacity;
} TemplateManagerState;

static TemplateManagerState g_template = {0};

// ============================================================================
// Hook Functions for Auto-Capture
// ============================================================================

#include <dobby.h>

/**
 * Hook for GlobalTemplateManager::GetTemplateRaw
 * Signature: void* GetTemplateRaw(GlobalTemplateManager* this, FixedString const& fs_id)
 * On ARM64: x0 = this (GlobalTemplateManager*), x1 = fs_id (passed by value as uint32_t)
 */
typedef void* (*GetTemplateRaw_t)(void* this_ptr, uint32_t fs_id);
static GetTemplateRaw_t g_orig_GetTemplateRaw = NULL;

static void* hook_GetTemplateRaw(void* global_template_mgr, uint32_t fs_id) {
    // Capture GlobalTemplateManager on first call
    if (global_template_mgr && !g_template.managers[TEMPLATE_MANAGER_GLOBAL_BANK]) {
        g_template.managers[TEMPLATE_MANAGER_GLOBAL_BANK] = global_template_mgr;
        log_message("[Template] *** AUTO-CAPTURE *** GlobalTemplateManager: %p", global_template_mgr);

        // Mark as initialized
        g_template.initialized = true;
    }

    // Call original function
    if (g_orig_GetTemplateRaw) {
        return g_orig_GetTemplateRaw(global_template_mgr, fs_id);
    }
    return NULL;
}

/**
 * Hook for CacheTemplateManagerBase::CacheTemplate
 * Signature: long CacheTemplate(CacheTemplateManagerBase* this, GameObjectTemplate*, FixedString&, FixedString&)
 * On ARM64: x0 = this (CacheTemplateManagerBase*)
 */
typedef void* (*CacheTemplate_t)(void* this_ptr, void* tmpl, void* fs1, void* fs2);
static CacheTemplate_t g_orig_CacheTemplate = NULL;

static void* hook_CacheTemplate(void* cache_mgr, void* tmpl, void* fs1, void* fs2) {
    // Capture CacheTemplateManager on first call
    if (cache_mgr && !g_template.managers[TEMPLATE_MANAGER_CACHE]) {
        g_template.managers[TEMPLATE_MANAGER_CACHE] = cache_mgr;
        log_message("[Template] *** AUTO-CAPTURE *** CacheTemplateManager: %p", cache_mgr);
    }

    // Call original function
    if (g_orig_CacheTemplate) {
        return g_orig_CacheTemplate(cache_mgr, tmpl, fs1, fs2);
    }
    return NULL;
}

/**
 * Install a single ARM64-safe hook with ADRP detection.
 * Returns true if hook was installed successfully.
 */
static bool install_arm64_safe_hook(const char* name, void* target, void* hook_fn, void** orig_out) {
    log_message("[Template] Analyzing %s prologue at %p", name, target);
    arm64_analyze_and_log(target, name);

    if (arm64_has_prologue_adrp(target)) {
        log_message("[Template] ADRP detected in %s prologue - using ARM64 safe hook", name);

        int safe_offset = arm64_get_recommended_hook_offset(target);
        if (safe_offset < 0) {
            log_message("[Template] WARNING: No safe hook point found for %s", name);
            return false;
        }

        log_message("[Template] Safe hook point for %s at +%d (0x%x)", name, safe_offset, safe_offset);

        void* original = NULL;
        void* hook_addr = arm64_safe_hook(target, hook_fn, &original);

        if (hook_addr && original) {
            *orig_out = original;
            log_message("[Template] ARM64 safe hook installed for %s!", name);
            log_message("[Template]   Original function trampoline: %p", original);
            return true;
        } else {
            log_message("[Template] WARNING: ARM64 safe hook failed for %s", name);
            return false;
        }
    } else {
        log_message("[Template] No ADRP in %s prologue - installing standard Dobby hook", name);

        void* original = NULL;
        int result = DobbyHook(target, hook_fn, (void**)&original);

        if (result == 0 && original) {
            *orig_out = original;
            log_message("[Template] Dobby hook installed for %s at %p", name, target);
            log_message("[Template]   Original function trampoline: %p", original);
            return true;
        } else {
            log_message("[Template] WARNING: Dobby hook failed for %s (result=%d)", name, result);
            return false;
        }
    }
}

/**
 * Read template manager singletons from global pointers.
 * This is called periodically to refresh manager pointers (they may be NULL early in startup).
 * Returns true if at least one manager was captured.
 */
static bool template_read_global_pointers(void* main_binary_base) {
    (void)main_binary_base;  // addresses now sourced from offset_table

    const VersionOffsets *off = offset_table_get();
    if (!off) return false;

    int captured = 0;
    void *mgr = NULL;

    if (off->global_template_mgr_ptr && !g_template.managers[TEMPLATE_MANAGER_GLOBAL_BANK]) {
        void *slot = offset_table_resolve(off->global_template_mgr_ptr);
        if (slot && safe_memory_read_pointer((mach_vm_address_t)slot, &mgr) && mgr) {
            g_template.managers[TEMPLATE_MANAGER_GLOBAL_BANK] = mgr;
            log_message("[Template] Captured GlobalTemplateManager: %p", mgr);
            captured++;
        }
    }

    if (off->cache_template_mgr_ptr && !g_template.managers[TEMPLATE_MANAGER_CACHE]) {
        void *slot = offset_table_resolve(off->cache_template_mgr_ptr);
        if (slot && safe_memory_read_pointer((mach_vm_address_t)slot, &mgr) && mgr) {
            g_template.managers[TEMPLATE_MANAGER_CACHE] = mgr;
            log_message("[Template] Captured CacheTemplateManager: %p", mgr);
            captured++;
        }
    }

    if (off->level_cache_mgr_ptr && !g_template.managers[TEMPLATE_MANAGER_LOCAL_CACHE]) {
        void *slot = offset_table_resolve(off->level_cache_mgr_ptr);
        if (slot && safe_memory_read_pointer((mach_vm_address_t)slot, &mgr) && mgr) {
            g_template.managers[TEMPLATE_MANAGER_LOCAL_CACHE] = mgr;
            log_message("[Template] Captured Level::CacheTemplateManager: %p", mgr);
            captured++;
        }
    }

    return captured > 0;
}

/**
 * Install template manager hooks for auto-capture.
 * Should be called after main binary base is known.
 *
 * NEW APPROACH: Instead of hooking (blocked by ARM64 ADRP constraints),
 * we read the global singleton pointers directly from the binary.
 */
bool template_install_hooks(void* main_binary_base) {
    if (!main_binary_base) {
        log_message("[Template] Cannot capture: no binary base");
        return false;
    }

    g_template.main_binary_base = main_binary_base;

    const VersionOffsets *off = offset_table_get();
    log_message("[Template] Using global pointer read approach (no hooks needed)");
    if (off) {
        log_message("[Template]   GlobalTemplateManager::m_ptr offset 0x%llx",
                    (unsigned long long)off->global_template_mgr_ptr);
        log_message("[Template]   CacheTemplateManager::m_ptr offset 0x%llx",
                    (unsigned long long)off->cache_template_mgr_ptr);
        log_message("[Template]   Level::s_CacheTemplateManager offset 0x%llx",
                    (unsigned long long)off->level_cache_mgr_ptr);
    } else {
        log_message("[Template]   No offset table entry for this version — pointers may not resolve");
    }

    // Try to read managers now (may be NULL if called early)
    bool captured = template_read_global_pointers(main_binary_base);
    if (captured) {
        log_message("[Template] Initial capture successful!");
    } else {
        log_message("[Template] Managers not yet initialized, will retry on first access");
    }

    return true;  // Always "succeeds" - we'll retry on access
}

// ============================================================================
// GUID Utilities
// ============================================================================

static bool parse_guid(const char* str, TemplateGuid* out) {
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

static void format_guid(const TemplateGuid* guid, char* out, size_t size) {
    if (!guid || !out || size < 37) return;

    snprintf(out, size, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             guid->data1, guid->data2, guid->data3,
             guid->data4[0], guid->data4[1],
             guid->data4[2], guid->data4[3], guid->data4[4],
             guid->data4[5], guid->data4[6], guid->data4[7]);
}

// ============================================================================
// Frida Capture Loading
// ============================================================================

/**
 * Load captured template addresses from Frida output file.
 * File format (from discover_template_managers.js):
 *   # Captured templates
 *   count=N
 *   template[0]=0xADDRESS
 *   template[1]=0xADDRESS
 *   ...
 */
static bool load_captured_templates(void) {
    FILE* f = fopen(FRIDA_CAPTURE_TEMPLATES, "r");
    if (!f) {
        return false;
    }

    char line[256];
    int count = 0;

    // Parse header and count
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#') continue;  // Skip comments

        if (strncmp(line, "count=", 6) == 0) {
            count = atoi(line + 6);
            break;
        }
    }

    if (count <= 0 || count > 100000) {
        log_message("[Template] Invalid template count in capture file: %d", count);
        fclose(f);
        return false;
    }

    // Allocate storage for captured templates
    if (g_template.captured_templates) {
        free(g_template.captured_templates);
    }
    g_template.captured_templates = malloc(count * sizeof(void*));
    if (!g_template.captured_templates) {
        fclose(f);
        return false;
    }
    g_template.captured_capacity = count;
    g_template.captured_count = 0;

    // Parse template addresses
    while (fgets(line, sizeof(line), f) && g_template.captured_count < count) {
        if (strncmp(line, "template[", 9) == 0) {
            char* eq = strchr(line, '=');
            if (eq) {
                void* addr = NULL;
                if (sscanf(eq + 1, "%p", &addr) == 1 ||
                    sscanf(eq + 1, "0x%lx", (unsigned long*)&addr) == 1) {

                    // Validate the address is readable
                    uint64_t test = 0;
                    if (safe_memory_read_u64((mach_vm_address_t)addr, &test)) {
                        g_template.captured_templates[g_template.captured_count++] = addr;
                    }
                }
            }
        }
    }

    fclose(f);

    log_message("[Template] Loaded %d templates from Frida capture (expected %d)",
                g_template.captured_count, count);

    return g_template.captured_count > 0;
}

/**
 * Load captured manager pointer from a specific file.
 */
static void* load_manager_from_file(const char* filepath, const char* manager_name) {
    FILE* f = fopen(filepath, "r");
    if (!f) return NULL;

    char line[256];
    void* ptr = NULL;

    // First line should be the pointer address
    if (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%p", &ptr) != 1 &&
            sscanf(line, "0x%lx", (unsigned long*)&ptr) != 1) {
            ptr = NULL;
        }
    }

    fclose(f);

    if (ptr) {
        // Validate pointer is readable
        uint64_t test = 0;
        if (!safe_memory_read_u64((mach_vm_address_t)ptr, &test)) {
            log_message("[Template] %s pointer %p is not readable", manager_name, ptr);
            return NULL;
        }
        log_message("[Template] Loaded %s from capture: %p", manager_name, ptr);
    }

    return ptr;
}

// ============================================================================
// Initialization
// ============================================================================

bool template_manager_init(void* main_binary_base) {
    if (g_template.initialized) {
        return true;
    }

    g_template.main_binary_base = main_binary_base;

    // Clear manager pointers
    memset(g_template.managers, 0, sizeof(g_template.managers));
    memset(g_template.template_counts, -1, sizeof(g_template.template_counts));

    // template_install_hooks reads global singleton pointers from the offset table.
    // It is safe to call whenever a table entry exists (no code patching involved).
    if (main_binary_base && offset_table_get()) {
        bool hooks_ok = template_install_hooks(main_binary_base);
        if (hooks_ok) {
            log_message("[Template] Template pointers initialized");
        } else {
            log_message("[Template] Template pointers not yet available, will retry on first access");
        }
    } else if (main_binary_base) {
        log_message("[Template] Skipping pointer reads (no offset table entry for this version)");
    }

    g_template.initialized = true;
    log_message("[Template] Template manager initialized");

    return true;
}

bool template_manager_ready(void) {
    if (!g_template.initialized) {
        return false;
    }

    // Check if any manager is captured
    for (int i = 0; i < TEMPLATE_MANAGER_COUNT; i++) {
        if (g_template.managers[i]) {
            return true;
        }
    }

    // Try to read global pointers (lazy initialization)
    if (g_template.main_binary_base) {
        if (template_read_global_pointers(g_template.main_binary_base)) {
            return true;
        }
    }

    // Also consider ready if we have captured templates
    return g_template.captured_count > 0;
}

// ============================================================================
// Manager Access
// ============================================================================

bool template_has_manager(TemplateManagerType mgr_type) {
    if (mgr_type < 0 || mgr_type >= TEMPLATE_MANAGER_COUNT) {
        return false;
    }
    return g_template.managers[mgr_type] != NULL;
}

void* template_get_manager_ptr(TemplateManagerType mgr_type) {
    if (mgr_type < 0 || mgr_type >= TEMPLATE_MANAGER_COUNT) {
        return NULL;
    }
    return g_template.managers[mgr_type];
}

// ============================================================================
// Template Lookup
// ============================================================================

/**
 * Search captured templates for one matching the given GUID.
 * This is a linear search through Frida-captured template addresses.
 */
static GameObjectTemplate* find_in_captured(const TemplateGuid* guid) {
    if (!guid || g_template.captured_count == 0) return NULL;

    // Linear search through captured templates
    for (int i = 0; i < g_template.captured_count; i++) {
        GameObjectTemplate* tmpl = (GameObjectTemplate*)g_template.captured_templates[i];
        if (!tmpl) continue;

        // Read template's GUID (need to discover offset)
        // For now, assume GUID is at +0x10 (after VMT + tags)
        // This may need adjustment based on actual struct layout
        TemplateGuid tmpl_guid;
        if (!safe_memory_read((mach_vm_address_t)tmpl + 0x10,
                              &tmpl_guid, sizeof(tmpl_guid))) {
            continue;
        }

        if (memcmp(&tmpl_guid, guid, sizeof(TemplateGuid)) == 0) {
            return tmpl;
        }
    }

    return NULL;
}

/**
 * Search a template manager's HashMap for a template.
 * Requires knowing the HashMap layout (buckets, keys, values).
 */
static GameObjectTemplate* find_in_manager(void* manager, const TemplateGuid* guid) {
    if (!manager || !guid) return NULL;

    // TODO: Implement HashMap traversal once we understand the structure
    // For now, use captured templates only

    log_message("[Template] Manager HashMap lookup not yet implemented");
    return NULL;
}

GameObjectTemplate* template_get_by_guid(TemplateManagerType mgr_type, const char* guid_str) {
    TemplateGuid guid;
    if (!parse_guid(guid_str, &guid)) {
        return NULL;
    }
    return template_get_by_guid_struct(mgr_type, &guid);
}

GameObjectTemplate* template_get_by_guid_struct(TemplateManagerType mgr_type, const TemplateGuid* guid) {
    if (!guid) return NULL;

    // If we have a manager pointer, search it
    void* manager = template_get_manager_ptr(mgr_type);
    if (manager) {
        GameObjectTemplate* tmpl = find_in_manager(manager, guid);
        if (tmpl) return tmpl;
    }

    // Fall back to captured templates
    return find_in_captured(guid);
}

GameObjectTemplate* template_get_by_fixedstring(TemplateManagerType mgr_type, uint32_t fs_id) {
    // TODO: Implement FixedString-based lookup
    // This requires finding the manager's name->template mapping
    (void)mgr_type;
    (void)fs_id;
    return NULL;
}

GameObjectTemplate* template_get(const char* guid_str) {
    TemplateGuid guid;
    if (!parse_guid(guid_str, &guid)) {
        return NULL;
    }

    // Search order: LocalCache -> Cache -> Local -> Global
    TemplateManagerType search_order[] = {
        TEMPLATE_MANAGER_LOCAL_CACHE,
        TEMPLATE_MANAGER_CACHE,
        TEMPLATE_MANAGER_LOCAL,
        TEMPLATE_MANAGER_GLOBAL_BANK
    };

    for (int i = 0; i < 4; i++) {
        GameObjectTemplate* tmpl = template_get_by_guid_struct(search_order[i], &guid);
        if (tmpl) return tmpl;
    }

    // Also search captured templates (may not be associated with a manager)
    return find_in_captured(&guid);
}

// ============================================================================
// Enumeration
// ============================================================================

int template_get_count(TemplateManagerType mgr_type) {
    if (mgr_type < 0 || mgr_type >= TEMPLATE_MANAGER_COUNT) {
        return -1;
    }

    // If we don't have the manager, return captured count for GLOBAL_BANK
    if (!g_template.managers[mgr_type]) {
        if (mgr_type == TEMPLATE_MANAGER_GLOBAL_BANK && g_template.captured_count > 0) {
            return g_template.captured_count;
        }
        return -1;
    }

    void* mgr = g_template.managers[mgr_type];

    // CacheTemplateManager and LocalCacheTemplates use CacheTemplateManagerBase layout
    if (mgr_type == TEMPLATE_MANAGER_CACHE || mgr_type == TEMPLATE_MANAGER_LOCAL_CACHE) {
        // Read count from +0x98 offset (verified via Ghidra 2025-12-21)
        uint32_t count = 0;
        if (safe_memory_read((mach_vm_address_t)mgr + CACHE_MGR_COUNT_OFFSET,
                             &count, sizeof(count))) {
            return (int)count;
        }
    }

    // GlobalTemplateBank uses different layout - use stored count for now
    return g_template.template_counts[mgr_type];
}

GameObjectTemplate* template_get_by_index(TemplateManagerType mgr_type, int index) {
    if (index < 0) return NULL;

    // For captured templates (no manager)
    if (!g_template.managers[mgr_type]) {
        if (mgr_type == TEMPLATE_MANAGER_GLOBAL_BANK &&
            index < g_template.captured_count) {
            return (GameObjectTemplate*)g_template.captured_templates[index];
        }
        return NULL;
    }

    void* mgr = g_template.managers[mgr_type];

    // CacheTemplateManager and LocalCacheTemplates use CacheTemplateManagerBase layout
    if (mgr_type == TEMPLATE_MANAGER_CACHE || mgr_type == TEMPLATE_MANAGER_LOCAL_CACHE) {
        // Read the value array pointer from +0x80 offset
        void* value_array = NULL;
        if (!safe_memory_read((mach_vm_address_t)mgr + CACHE_MGR_VALUE_ARRAY_OFFSET,
                              &value_array, sizeof(value_array))) {
            return NULL;
        }
        if (!value_array) return NULL;

        // Read template pointer at index * 8 (pointer size)
        GameObjectTemplate* tmpl = NULL;
        if (!safe_memory_read((mach_vm_address_t)value_array + index * sizeof(void*),
                              &tmpl, sizeof(tmpl))) {
            return NULL;
        }

        // Validate the template pointer by checking its vtable
        if (tmpl) {
            void* vtable = NULL;
            if (!safe_memory_read((mach_vm_address_t)tmpl + TEMPLATE_VTABLE_OFFSET,
                                  &vtable, sizeof(vtable))) {
                return NULL;  // Can't read vtable - invalid pointer
            }
            // Vtable should be in a reasonable address range (code section)
            if (!vtable || (uintptr_t)vtable < 0x100000000 || (uintptr_t)vtable > 0x200000000) {
                return NULL;  // Invalid vtable - skip this entry
            }
        }

        return tmpl;
    }

    // GlobalTemplateBank uses different layout - not implemented yet
    return NULL;
}

int template_iterate(TemplateManagerType mgr_type, TemplateIterCallback callback, void* userdata) {
    if (!callback) return 0;

    int count = template_get_count(mgr_type);
    if (count <= 0) return 0;

    int iterated = 0;
    for (int i = 0; i < count; i++) {
        GameObjectTemplate* tmpl = template_get_by_index(mgr_type, i);
        if (tmpl) {
            iterated++;
            if (!callback(tmpl, userdata)) {
                break;  // Callback requested stop
            }
        }
    }

    return iterated;
}

// ============================================================================
// Template Property Access
// ============================================================================

bool template_get_guid_string(GameObjectTemplate* tmpl, char* out_buf, size_t buf_size) {
    if (!tmpl || !out_buf || buf_size < 37) return false;

    // GUID is stored as a FixedString at offset +0x10 (discovered via runtime probing 2025-12-21)
    // Read the FixedString index, then resolve it to get the actual GUID string
    uint32_t fs_index = 0;
    if (!safe_memory_read((mach_vm_address_t)tmpl + TEMPLATE_GUID_FS_OFFSET,
                          &fs_index, sizeof(fs_index))) {
        return false;
    }

    if (fs_index == 0) return false;

    // Resolve the FixedString to get the actual string
    const char* guid_str = fixed_string_resolve(fs_index);
    if (!guid_str || !*guid_str) return false;

    // Copy to output buffer
    strncpy(out_buf, guid_str, buf_size - 1);
    out_buf[buf_size - 1] = '\0';
    return true;
}

/**
 * Call the virtual GetType() function on a template.
 * On ARM64, this is at VMT offset 3 (destructor=0, GetName=1, DebugDump=2, GetType=3).
 * Returns a FixedString* that we can resolve.
 */
static uint32_t template_call_get_type_vfunc(GameObjectTemplate* tmpl) {
    if (!tmpl) return 0;

    // Read VMT pointer from template
    void* vmt = NULL;
    if (!safe_memory_read((mach_vm_address_t)tmpl, &vmt, sizeof(void*))) {
        return 0;
    }
    if (!vmt) return 0;

    // Read GetType function pointer from VMT[3]
    // VMT layout: [0]=destructor, [1]=GetName, [2]=DebugDump, [3]=GetType
    void* get_type_fn = NULL;
    if (!safe_memory_read((mach_vm_address_t)vmt + 3 * sizeof(void*), &get_type_fn, sizeof(void*))) {
        return 0;
    }
    if (!get_type_fn) return 0;

    // Call the virtual function
    // FixedString* GetType() const - returns pointer to FixedString
    // The return is likely a static FixedString, so we read the index from it
    typedef void* (*GetTypeFn)(GameObjectTemplate*);
    GetTypeFn fn = (GetTypeFn)get_type_fn;

    // Call the function (may return pointer to FixedString)
    void* result = fn(tmpl);
    if (!result) return 0;

    // Read the FixedString index from the returned pointer
    uint32_t fs_index = 0;
    if (safe_memory_read_u32((mach_vm_address_t)result, &fs_index)) {
        return fs_index;
    }

    return 0;
}

TemplateType template_get_type(GameObjectTemplate* tmpl) {
    if (!tmpl) return TEMPLATE_TYPE_UNKNOWN;

    // Try calling the virtual GetType() function
    uint32_t type_fs = template_call_get_type_vfunc(tmpl);
    if (type_fs && type_fs != FS_NULL_INDEX) {
        // Resolve the FixedString to get the type name
        const char* type_str = fixed_string_resolve(type_fs);
        if (type_str) {
            // Map type string to enum
            if (strcmp(type_str, "character") == 0 || strstr(type_str, "Character") != NULL) {
                return TEMPLATE_TYPE_CHARACTER;
            } else if (strcmp(type_str, "item") == 0 || strstr(type_str, "Item") != NULL) {
                return TEMPLATE_TYPE_ITEM;
            } else if (strcmp(type_str, "scenery") == 0 || strstr(type_str, "Scenery") != NULL) {
                return TEMPLATE_TYPE_SCENERY;
            } else if (strcmp(type_str, "surface") == 0 || strstr(type_str, "Surface") != NULL) {
                return TEMPLATE_TYPE_SURFACE;
            } else if (strcmp(type_str, "projectile") == 0 || strstr(type_str, "Projectile") != NULL) {
                return TEMPLATE_TYPE_PROJECTILE;
            } else if (strcmp(type_str, "decal") == 0 || strstr(type_str, "Decal") != NULL) {
                return TEMPLATE_TYPE_DECAL;
            } else if (strcmp(type_str, "trigger") == 0 || strstr(type_str, "Trigger") != NULL) {
                return TEMPLATE_TYPE_TRIGGER;
            } else if (strcmp(type_str, "prefab") == 0 || strstr(type_str, "Prefab") != NULL) {
                return TEMPLATE_TYPE_PREFAB;
            } else if (strcmp(type_str, "light") == 0 || strstr(type_str, "Light") != NULL) {
                return TEMPLATE_TYPE_LIGHT;
            }
        }
    }

    return TEMPLATE_TYPE_UNKNOWN;
}

const char* template_type_to_string(TemplateType type) {
    if (type < 0 || type >= TEMPLATE_TYPE_COUNT) {
        return "Unknown";
    }
    return s_template_type_names[type];
}

const char* template_get_type_string(GameObjectTemplate* tmpl, char* out_buf, size_t buf_size) {
    if (!tmpl || !out_buf || buf_size == 0) return NULL;

    // Try calling the virtual GetType() function
    uint32_t type_fs = template_call_get_type_vfunc(tmpl);
    if (type_fs && type_fs != FS_NULL_INDEX) {
        const char* type_str = fixed_string_resolve(type_fs);
        if (type_str) {
            strncpy(out_buf, type_str, buf_size - 1);
            out_buf[buf_size - 1] = '\0';
            return out_buf;
        }
        // Fallback: return hex representation
        snprintf(out_buf, buf_size, "FS:0x%x", type_fs);
        return out_buf;
    }

    out_buf[0] = '\0';
    return NULL;
}

uint32_t template_get_id_fs(GameObjectTemplate* tmpl) {
    if (!tmpl) return 0;

    uint32_t fs = 0;
    if (safe_memory_read_u32((mach_vm_address_t)&tmpl->id_fs, &fs)) {
        return fs;
    }
    return 0;
}

uint32_t template_get_name_fs(GameObjectTemplate* tmpl) {
    if (!tmpl) return 0;

    uint32_t fs = 0;
    if (safe_memory_read_u32((mach_vm_address_t)&tmpl->template_name_fs, &fs)) {
        return fs;
    }
    return 0;
}

uint32_t template_get_parent_template_id_fs(GameObjectTemplate* tmpl) {
    if (!tmpl) return 0;

    uint32_t fs = 0;
    if (safe_memory_read_u32((mach_vm_address_t)&tmpl->parent_template_id_fs, &fs)) {
        return fs;
    }
    return 0;
}

uint32_t template_get_handle(GameObjectTemplate* tmpl) {
    if (!tmpl) return 0;

    uint32_t handle = 0;
    if (safe_memory_read_u32((mach_vm_address_t)&tmpl->template_handle, &handle)) {
        return handle;
    }
    return 0;
}

const char* template_get_id_string(GameObjectTemplate* tmpl, char* out_buf, size_t buf_size) {
    if (!tmpl || !out_buf || buf_size == 0) return NULL;

    uint32_t fs = template_get_id_fs(tmpl);
    if (fs == 0 || fs == FS_NULL_INDEX) {
        out_buf[0] = '\0';
        return NULL;
    }

    const char* resolved = fixed_string_resolve(fs);
    if (resolved) {
        strncpy(out_buf, resolved, buf_size - 1);
        out_buf[buf_size - 1] = '\0';
        return out_buf;
    }

    // Fallback: return hex representation
    snprintf(out_buf, buf_size, "FS:0x%x", fs);
    return out_buf;
}

const char* template_get_template_name_string(GameObjectTemplate* tmpl, char* out_buf, size_t buf_size) {
    if (!tmpl || !out_buf || buf_size == 0) return NULL;

    uint32_t fs = template_get_name_fs(tmpl);
    if (fs == 0 || fs == FS_NULL_INDEX) {
        out_buf[0] = '\0';
        return NULL;
    }

    const char* resolved = fixed_string_resolve(fs);
    if (resolved) {
        strncpy(out_buf, resolved, buf_size - 1);
        out_buf[buf_size - 1] = '\0';
        return out_buf;
    }

    snprintf(out_buf, buf_size, "FS:0x%x", fs);
    return out_buf;
}

const char* template_get_parent_template_string(GameObjectTemplate* tmpl, char* out_buf, size_t buf_size) {
    if (!tmpl || !out_buf || buf_size == 0) return NULL;

    uint32_t fs = template_get_parent_template_id_fs(tmpl);
    if (fs == 0 || fs == FS_NULL_INDEX) {
        out_buf[0] = '\0';
        return NULL;
    }

    const char* resolved = fixed_string_resolve(fs);
    if (resolved) {
        strncpy(out_buf, resolved, buf_size - 1);
        out_buf[buf_size - 1] = '\0';
        return out_buf;
    }

    snprintf(out_buf, buf_size, "FS:0x%x", fs);
    return out_buf;
}

// ============================================================================
// Frida Capture Integration
// ============================================================================

bool template_load_frida_capture(void) {
    log_message("[Template] Loading Frida capture files...");

    bool loaded_any = false;

    // Load captured template addresses
    if (load_captured_templates()) {
        loaded_any = true;
    }

    // Try to load specific manager pointers
    void* global = load_manager_from_file(FRIDA_CAPTURE_GLOBAL_BANK, "GlobalTemplateBank");
    if (global) {
        g_template.managers[TEMPLATE_MANAGER_GLOBAL_BANK] = global;
        loaded_any = true;
    }

    void* cache = load_manager_from_file(FRIDA_CAPTURE_CACHE_MGR, "CacheTemplateManager");
    if (cache) {
        g_template.managers[TEMPLATE_MANAGER_CACHE] = cache;
        loaded_any = true;
    }

    if (loaded_any) {
        log_message("[Template] Frida capture loaded successfully");
    } else {
        log_message("[Template] No Frida capture files found");
    }

    return loaded_any;
}

bool template_frida_capture_available(void) {
    FILE* f = fopen(FRIDA_CAPTURE_TEMPLATES, "r");
    if (f) {
        fclose(f);
        return true;
    }

    f = fopen(FRIDA_CAPTURE_GLOBAL_BANK, "r");
    if (f) {
        fclose(f);
        return true;
    }

    return false;
}

// ============================================================================
// Debugging
// ============================================================================

void template_dump_status(void) {
    log_message("[Template] Template Manager Status:");
    log_message("  Initialized: %s", g_template.initialized ? "yes" : "no");
    log_message("  Binary Base: %p", g_template.main_binary_base);
    log_message("  Captured Templates: %d", g_template.captured_count);

    for (int i = 0; i < TEMPLATE_MANAGER_COUNT; i++) {
        void* mgr = g_template.managers[i];
        if (mgr) {
            log_message("  %s: %p", s_manager_type_names[i], mgr);
        } else {
            log_message("  %s: not captured", s_manager_type_names[i]);
        }
    }
}

void template_dump_entries(TemplateManagerType mgr_type, int max_entries) {
    int count = template_get_count(mgr_type);
    if (count < 0) {
        log_message("[Template] Manager %d not available", mgr_type);
        return;
    }

    int to_dump = (max_entries < 0 || max_entries > count) ? count : max_entries;
    log_message("[Template] Dumping %d of %d templates from %s:",
                to_dump, count, s_manager_type_names[mgr_type]);

    for (int i = 0; i < to_dump; i++) {
        GameObjectTemplate* tmpl = template_get_by_index(mgr_type, i);
        if (!tmpl) continue;

        char guid_str[40];
        if (template_get_guid_string(tmpl, guid_str, sizeof(guid_str))) {
            uint32_t id_fs = template_get_id_fs(tmpl);
            uint32_t name_fs = template_get_name_fs(tmpl);
            log_message("  [%d] %p: GUID=%s, id_fs=0x%x, name_fs=0x%x",
                        i, tmpl, guid_str, id_fs, name_fs);
        } else {
            log_message("  [%d] %p: (could not read properties)", i, tmpl);
        }
    }
}
