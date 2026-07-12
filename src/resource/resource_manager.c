/**
 * resource_manager.c - Resource Manager Implementation for BG3SE-macOS
 *
 * Provides access to the game's ResourceManager for resource lookup.
 */

#include "resource_manager.h"
#include "../core/logging.h"
#include "../core/safe_memory.h"
#include "../core/offset_table.h"
#include "../strings/fixed_string.h"
#include <string.h>
#include <strings.h>

// ============================================================================
// Constants and Offsets (Discovered via Ghidra - Dec 21, 2025)
// ============================================================================

// ls::ResourceManager::m_ptr global singleton
// Discovered from InitEngine disassembly:
//   105d197e4: adrp x25, 0x108a8f000
//   105d197e8: ldr  x28, [x25, #0x70]
#define OFFSET_RESOURCEMANAGER_PTR  0x08a8f070

// ResourceBank offsets within ResourceManager
#define RESOURCEMANAGER_BANK0_OFFSET  0x28  // Primary bank
#define RESOURCEMANAGER_BANK1_OFFSET  0x30  // Secondary bank

// ResourceContainer::GetResource function
// Takes: (ResourceContainer* this, ResourceBankType type, FixedString* id)
// Returns: Resource* or NULL
#define OFFSET_GETRESOURCE_FUNC  0x060cc608

// ResourceContainer structure offsets
#define RESOURCECONTAINER_BANKS_OFFSET  0x08  // Array of banks indexed by type

// ============================================================================
// Type Name Table
// ============================================================================

static const char* s_resource_type_names[RESOURCE_TYPE_COUNT] = {
    "Visual",
    "VisualSet",
    "Animation",
    "AnimationSet",
    "Texture",
    "Material",
    "Physics",
    "Effect",
    "Script",
    "Sound",
    "Lighting",
    "Atmosphere",
    "AnimationBlueprint",
    "MeshProxy",
    "MaterialSet",
    "BlendSpace",
    "FCurve",
    "Timeline",
    "Dialog",
    "VoiceBark",
    "TileSet",
    "IKRig",
    "Skeleton",
    "VirtualTexture",
    "TerrainBrush",
    "ColorList",
    "CharacterVisual",
    "MaterialPreset",
    "SkinPreset",
    "ClothCollider",
    "DiffusionProfile",
    "LightCookie",
    "TimelineScene",
    "SkeletonMirrorTable"
};

// ============================================================================
// Module State
// ============================================================================

static struct {
    bool initialized;
    void* main_binary_base;

    // Cached pointers (read lazily)
    void** resource_manager_ptr;  // Points to global slot
} g_resource = {0};

// ============================================================================
// Initialization
// ============================================================================

bool resource_manager_init(void *main_binary_base) {
    if (g_resource.initialized) {
        return true;
    }

    if (!main_binary_base) {
        log_message("[Resource] ERROR: main_binary_base is NULL");
        return false;
    }

    g_resource.main_binary_base = main_binary_base;

    const VersionOffsets *off = offset_table_get();
    if (off && off->resource_mgr_ptr) {
        g_resource.resource_manager_ptr = (void**)offset_table_resolve(off->resource_mgr_ptr);
    } else {
        g_resource.resource_manager_ptr = (void**)((uintptr_t)main_binary_base + OFFSET_RESOURCEMANAGER_PTR);
    }

    log_message("[Resource] Resource manager initialized");
    log_message("[Resource]   Base: %p", main_binary_base);
    log_message("[Resource]   ResourceManager::m_ptr at offset 0x%x -> %p",
                OFFSET_RESOURCEMANAGER_PTR, (void*)g_resource.resource_manager_ptr);

    g_resource.initialized = true;
    return true;
}

bool resource_manager_ready(void) {
    if (!g_resource.initialized || !g_resource.resource_manager_ptr) {
        return false;
    }

    // Check if the global pointer is valid
    void* mgr = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)g_resource.resource_manager_ptr, &mgr)) {
        return false;
    }

    return mgr != NULL;
}

// ============================================================================
// Type Utilities
// ============================================================================

const char* resource_type_name(ResourceBankType type) {
    if (type < 0 || type >= RESOURCE_TYPE_COUNT) {
        return NULL;
    }
    return s_resource_type_names[type];
}

int resource_type_from_name(const char* name) {
    if (!name) return -1;

    for (int i = 0; i < RESOURCE_TYPE_COUNT; i++) {
        if (strcasecmp(s_resource_type_names[i], name) == 0) {
            return i;
        }
    }

    return -1;
}

// ============================================================================
// Manager Access
// ============================================================================

void* resource_manager_get(void) {
    if (!g_resource.initialized || !g_resource.resource_manager_ptr) {
        return NULL;
    }

    void* mgr = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)g_resource.resource_manager_ptr, &mgr)) {
        return NULL;
    }

    return mgr;
}

void* resource_manager_get_bank(void) {
    void* mgr = resource_manager_get();
    if (!mgr) return NULL;

    void* bank = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)mgr + RESOURCEMANAGER_BANK0_OFFSET, &bank)) {
        return NULL;
    }

    return bank;
}

void* resource_manager_get_bank_secondary(void) {
    void* mgr = resource_manager_get();
    if (!mgr) return NULL;

    void* bank = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)mgr + RESOURCEMANAGER_BANK1_OFFSET, &bank)) {
        return NULL;
    }

    return bank;
}

// ============================================================================
// Resource Access
// ============================================================================

/**
 * Call ResourceContainer::GetResource function.
 * Signature: Resource* GetResource(ResourceContainer* this, uint32_t type, FixedString* id)
 */
typedef void* (*GetResourceFunc)(void* container, uint32_t type, uint32_t* fixed_string_id);

void* resource_get(ResourceBankType type, uint32_t fixed_string_id) {
    if (type < 0 || type >= RESOURCE_TYPE_COUNT) {
        return NULL;
    }

    if (!g_resource.initialized || !g_resource.main_binary_base) {
        return NULL;
    }

    void* bank = resource_manager_get_bank();
    if (!bank) {
        log_message("[Resource] ResourceBank not available");
        return NULL;
    }

    // Resolve GetResource for the running version (remap the hardcoded 6995620
    // address; 0 = no verified address for this version -> bail instead of
    // calling a stale function).
    uint64_t fn_ghidra = offset_table_remap_fn(0x100000000ULL + OFFSET_GETRESOURCE_FUNC);
    if (!fn_ghidra) {
        return NULL;
    }
    GetResourceFunc get_resource = (GetResourceFunc)((uintptr_t)g_resource.main_binary_base
                                                     + (fn_ghidra - 0x100000000ULL));

    // Note: FixedString is passed as pointer to its hash value
    void* result = get_resource(bank, (uint32_t)type, &fixed_string_id);

    return result;
}

void* resource_get_by_name(ResourceBankType type, const char* name) {
    if (!name) return NULL;

    // Try to get FixedString ID for the name
    // fixed_string_intern looks up or creates the string in the global table
    uint32_t fs_id = fixed_string_intern(name, -1);
    if (fs_id == 0 || fs_id == 0xFFFFFFFF) {
        // String not in table - resource doesn't exist
        return NULL;
    }

    return resource_get(type, fs_id);
}

// ============================================================================
// Resource Iteration (for GetAll)
// ============================================================================

/**
 * ResourceContainer structure (from Ghidra decompilation):
 *   +0x00: vtable
 *   +0x08: bank_array[34]  - array of pointers to ResourceBank per type
 *
 * Each ResourceBank has:
 *   +0x08: bucket_count
 *   +0x10: bucket_array (hash table buckets)
 *   +0x20: SRWKernelLock
 *
 * Each bucket entry has:
 *   +0x00: next_entry
 *   +0x08: hash
 *   +0x10: resource_ptr
 */

int resource_get_count(ResourceBankType type) {
    // Resource containers use hash tables, not flat arrays
    // We need to iterate to count
    if (type < 0 || type >= RESOURCE_TYPE_COUNT) {
        return -1;
    }

    void* bank = resource_manager_get_bank();
    if (!bank) {
        return -1;
    }

    // Get the type-specific bank
    // bank_array is at bank + 0x08, indexed by type * 8
    void* type_bank = NULL;
    mach_vm_address_t type_bank_addr = (mach_vm_address_t)bank + RESOURCECONTAINER_BANKS_OFFSET + (type * sizeof(void*));
    if (!safe_memory_read_pointer(type_bank_addr, &type_bank)) {
        return -1;
    }

    if (!type_bank) {
        return 0;  // No resources of this type
    }

    // Read bucket count at +0x08
    uint32_t bucket_count = 0;
    if (!safe_memory_read_u32((mach_vm_address_t)type_bank + 0x08, &bucket_count)) {
        return -1;
    }

    // Read bucket array at +0x10
    void* buckets = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)type_bank + 0x10, &buckets)) {
        return -1;
    }

    if (!buckets || bucket_count == 0) {
        return 0;
    }

    // Count entries by traversing all buckets
    int count = 0;
    for (uint32_t i = 0; i < bucket_count && i < 10000; i++) {
        void* entry = NULL;
        if (!safe_memory_read_pointer((mach_vm_address_t)buckets + (i * sizeof(void*)), &entry)) {
            continue;
        }

        // Traverse linked list in this bucket
        while (entry && count < 100000) {
            count++;

            // Read next pointer at +0x00
            void* next = NULL;
            if (!safe_memory_read_pointer((mach_vm_address_t)entry, &next)) {
                break;
            }
            entry = next;
        }
    }

    return count;
}

int resource_iterate_all(ResourceBankType type, ResourceIteratorCallback callback, void* user_data) {
    if (type < 0 || type >= RESOURCE_TYPE_COUNT || !callback) {
        return 0;
    }

    void* bank = resource_manager_get_bank();
    if (!bank) {
        return 0;
    }

    // Get the type-specific bank
    void* type_bank = NULL;
    mach_vm_address_t type_bank_addr = (mach_vm_address_t)bank + RESOURCECONTAINER_BANKS_OFFSET + (type * sizeof(void*));
    if (!safe_memory_read_pointer(type_bank_addr, &type_bank)) {
        return 0;
    }

    if (!type_bank) {
        return 0;
    }

    // Read bucket count at +0x08
    uint32_t bucket_count = 0;
    if (!safe_memory_read_u32((mach_vm_address_t)type_bank + 0x08, &bucket_count)) {
        return 0;
    }

    // Read bucket array at +0x10
    void* buckets = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)type_bank + 0x10, &buckets)) {
        return 0;
    }

    if (!buckets || bucket_count == 0) {
        return 0;
    }

    // Iterate all buckets
    int count = 0;
    for (uint32_t i = 0; i < bucket_count && i < 10000; i++) {
        void* entry = NULL;
        if (!safe_memory_read_pointer((mach_vm_address_t)buckets + (i * sizeof(void*)), &entry)) {
            continue;
        }

        // Traverse linked list in this bucket
        while (entry && count < 100000) {
            // Read resource pointer at +0x10
            void* resource = NULL;
            if (safe_memory_read_pointer((mach_vm_address_t)entry + 0x10, &resource) && resource) {
                count++;
                if (!callback(resource, type, user_data)) {
                    return count;  // Callback requested stop
                }
            }

            // Read next pointer at +0x00
            void* next = NULL;
            if (!safe_memory_read_pointer((mach_vm_address_t)entry, &next)) {
                break;
            }
            entry = next;
        }
    }

    return count;
}

// ============================================================================
// Debugging
// ============================================================================

void resource_dump_status(void) {
    log_message("[Resource] Resource Manager Status:");
    log_message("  Initialized: %s", g_resource.initialized ? "yes" : "no");
    log_message("  Base: %p", g_resource.main_binary_base);

    void* mgr = resource_manager_get();
    log_message("  ResourceManager: %p", mgr);

    if (mgr) {
        void* bank0 = resource_manager_get_bank();
        void* bank1 = resource_manager_get_bank_secondary();
        log_message("  ResourceBank[0] (primary): %p", bank0);
        log_message("  ResourceBank[1] (secondary): %p", bank1);

        // Show counts per type (first few)
        log_message("  Resource counts by type:");
        for (int i = 0; i < RESOURCE_TYPE_COUNT && i < 10; i++) {
            int count = resource_get_count((ResourceBankType)i);
            log_message("    %s: %d", s_resource_type_names[i], count);
        }
    }
}

// Callback for dump
static bool dump_resource_callback(void* resource, ResourceBankType type, void* user_data) {
    int* count_ptr = (int*)user_data;
    int max_count = count_ptr[1];
    int current = count_ptr[0];

    if (max_count >= 0 && current >= max_count) {
        return false;  // Stop iteration
    }

    // Try to get the resource ID (usually at +0x00 or +0x08)
    uint32_t id = 0;
    if (safe_memory_read_u32((mach_vm_address_t)resource + 0x08, &id)) {
        const char* name = fixed_string_resolve(id);
        if (name) {
            log_message("    [%d] %p: %s", current, resource, name);
        } else {
            log_message("    [%d] %p: (id=0x%08x)", current, resource, id);
        }
    } else {
        log_message("    [%d] %p", current, resource);
    }

    count_ptr[0]++;
    return true;
}

void resource_dump_type(ResourceBankType type, int max_count) {
    if (type < 0 || type >= RESOURCE_TYPE_COUNT) {
        log_message("[Resource] Invalid type: %d", type);
        return;
    }

    int total = resource_get_count(type);
    log_message("[Resource] Dumping %s resources (total: %d, max: %d):",
                s_resource_type_names[type], total, max_count);

    int counts[2] = {0, max_count};
    resource_iterate_all(type, dump_resource_callback, counts);
}
