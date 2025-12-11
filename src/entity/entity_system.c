/**
 * BG3SE-macOS - Entity Component System Implementation
 *
 * This module captures the EntityWorld pointer at runtime by hooking
 * a function that receives EntityWorld& as a parameter.
 */

#include "entity_system.h"
#include "component_registry.h"
#include "component_lookup.h"
#include "component_typeid.h"
#include "component_property.h"
#include "arm64_call.h"
#include "logging.h"

#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/getsect.h>
#include <mach/mach.h>
#include <sys/mman.h>

// Include Dobby for inline hooking (suppress third-party warnings)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wvariadic-macros"
#pragma clang diagnostic ignored "-Wstrict-prototypes"
#include "../../lib/Dobby/include/dobby.h"
#pragma clang diagnostic pop

// Include Lua
#include "../../lib/lua/src/lua.h"
#include "../../lib/lua/src/lauxlib.h"
#include "../../lib/lua/src/lualib.h"

// Include user variables for entity.Vars
#include "../vars/user_variables.h"

// Include lifetime for userdata scoping
#include "../lifetime/lifetime.h"

// ============================================================================
// Global State
// ============================================================================

static void *g_EoCServer = NULL;       // esv::EoCServer* singleton
static EntityWorldPtr g_EntityWorld = NULL;
static void *g_MainBinaryBase = NULL;
static bool g_Initialized = false;

// Cached GUID → EntityHandle mappings
#define GUID_CACHE_SIZE 256
static struct {
    char guid[64];
    EntityHandle handle;
} g_GuidCache[GUID_CACHE_SIZE];
static int g_GuidCacheCount = 0;

// TypeId discovery state - discovery may need to be deferred until game initializes globals
static bool g_TypeIdDiscoveryComplete = false;
static int g_TypeIdRetryCount = 0;
#define TYPEID_MAX_RETRIES 5

// ============================================================================
// ARM64 Function Addresses (relative to binary base)
// From Ghidra analysis - see ghidra/ENTITY_OFFSETS.md
// ============================================================================

// esv::EocServer::StartUp(eoc::ServerInit const&)
// Called once during server initialization - safe to hook
// First parameter (x0) is the EoCServer* this pointer
#define OFFSET_EOC_SERVER_STARTUP 0x10110f0d0

// Offset of EntityWorld* within EoCServer struct (from Windows BG3SE analysis)
// This matches the Windows offset exactly
#define OFFSET_ENTITYWORLD_IN_EOCSERVER 0x288

// esv::EocServer::m_ptr - Static member holding the EoCServer singleton pointer
// Discovered via Ghidra analysis of symbol __ZN3esv9EocServer5m_ptrE
// This is a global pointer in __DATA that we can read directly without hooks
#define OFFSET_EOCSERVER_SINGLETON_PTR 0x10898e8b8

// eoc::CombatHelpers::LEGACY_IsInCombat(EntityHandle, EntityWorld&)
// Note: Hooking this causes crashes during save load - DO NOT USE
#define OFFSET_LEGACY_IS_IN_COMBAT 0x10124f92c

// eoc::CombatHelpers::LEGACY_GetCombatFromGuid(Guid&, EntityWorld&)
#define OFFSET_LEGACY_GET_COMBAT_FROM_GUID 0x101250074

// ecs::legacy::Helper::TryGetSingleton<ls::uuid::ToHandleMappingComponent>(EntityWorld&)
// This function returns the singleton containing GUID->EntityHandle mappings
#define OFFSET_TRY_GET_UUID_MAPPING_SINGLETON 0x1010dc924

// ecs::EntityWorld::GetComponent<T> template instances
// These are direct function addresses from Ghidra analysis
//
// DISABLED: These offsets were malformed (11 hex digits instead of ~10).
// The addresses like 0x10010d5b00 cause crashes due to invalid function pointers.
// TODO: Re-verify these addresses via Ghidra and re-enable
//
// ls:: components - DISABLED until addresses verified
#define OFFSET_GET_TRANSFORM_COMPONENT 0  // Was 0x10010d5b00 - WRONG
#define OFFSET_GET_LEVEL_COMPONENT     0  // Was 0x10010d588c - WRONG
#define OFFSET_GET_PHYSICS_COMPONENT   0  // Was 0x101ba0898 - needs verification
#define OFFSET_GET_VISUAL_COMPONENT    0  // Was 0x102e56350 - needs verification

// eoc:: components - DISABLED until addresses verified
// The 11-digit hex values (0x10b2ff516 etc) are clearly wrong
#define OFFSET_GET_STATS_COMPONENT    0  // Was 0x10b2ff516 - WRONG
#define OFFSET_GET_BASEHP_COMPONENT   0  // Was 0x10b460744 - WRONG
#define OFFSET_GET_HEALTH_COMPONENT   0  // Was 0x10b2f2f47 - WRONG
#define OFFSET_GET_ARMOR_COMPONENT    0  // Was 0x10b2fe2c4 - WRONG
#define OFFSET_GET_CLASSES_COMPONENT  0  // Not yet located

// Ghidra base address (macOS ARM64) - defined in entity_storage.h
// #define GHIDRA_BASE_ADDRESS 0x100000000  // Use entity_storage.h definition

// ============================================================================
// Component Accessor Function Types
// ============================================================================

// GetComponent signature: void* GetComponent(EntityWorld*, EntityHandle)
typedef void* (*GetComponentFn)(void *entityWorld, uint64_t handle);

// Function pointers for each component type (initialized in entity_system_init)
// ls:: components (working)
static GetComponentFn g_GetTransformComponent = NULL;
static GetComponentFn g_GetLevelComponent = NULL;
static GetComponentFn g_GetPhysicsComponent = NULL;
static GetComponentFn g_GetVisualComponent = NULL;

// eoc:: components (placeholders - addresses not yet discovered)
static GetComponentFn g_GetStatsComponent = NULL;
static GetComponentFn g_GetBaseHpComponent = NULL;
static GetComponentFn g_GetHealthComponent = NULL;
static GetComponentFn g_GetArmorComponent = NULL;
static GetComponentFn g_GetClassesComponent = NULL;

// ============================================================================
// Component Type Helpers (for data structure traversal)
// ============================================================================

/**
 * Get the full component name for a ComponentType enum.
 * Used to look up component info in the registry.
 */
static const char* get_component_full_name(ComponentType type) {
    switch (type) {
        case COMPONENT_TRANSFORM:  return "ls::TransformComponent";
        case COMPONENT_LEVEL:      return "ls::LevelComponent";
        case COMPONENT_PHYSICS:    return "ls::PhysicsComponent";
        case COMPONENT_VISUAL:     return "ls::VisualComponent";
        case COMPONENT_STATS:      return "eoc::StatsComponent";
        case COMPONENT_BASE_HP:    return "eoc::BaseHpComponent";
        case COMPONENT_HEALTH:     return "eoc::HealthComponent";
        case COMPONENT_ARMOR:      return "eoc::ArmorComponent";
        case COMPONENT_DATA:       return "eoc::DataComponent";
        case COMPONENT_BASE_STATS: return "eoc::BaseStatsComponent";
        default: return NULL;
    }
}

/**
 * Get component size for data structure traversal.
 * Returns 0 if component size is unknown.
 */
static size_t get_component_size_for_type(ComponentType type) {
    switch (type) {
        case COMPONENT_HEALTH:     return 0x24;  // From component_offsets.h
        case COMPONENT_BASE_HP:    return 0x08;
        case COMPONENT_ARMOR:      return 0x10;
        case COMPONENT_STATS:      return 0xA0;
        case COMPONENT_TRANSFORM:  return 0x28;  // From component_offsets.h
        case COMPONENT_LEVEL:      return 0x10;  // From component_offsets.h
        case COMPONENT_DATA:       return 0x10;  // From component_offsets.h
        case COMPONENT_BASE_STATS: return 0x1C;  // From component_offsets.h
        case COMPONENT_PHYSICS:    return 0x30;  // Estimated
        case COMPONENT_VISUAL:     return 0x20;  // Estimated
        default: return 0;
    }
}

// ============================================================================
// TryGetSingleton Function Pointer
// ============================================================================

// Function type from arm64_call.h - use call_try_get_singleton_with_x8() to invoke
static TryGetSingletonFn g_TryGetUuidMappingSingleton = NULL;

// Cached pointer to the UUID mapping component
static void *g_UuidMappingComponent = NULL;

// ============================================================================
// Memory Scanning for EoCServer Singleton
// ============================================================================

// Helper: Check if a pointer looks like a valid heap/data address
static bool is_valid_pointer(void *ptr) {
    if (!ptr) return false;

    uintptr_t addr = (uintptr_t)ptr;

    // On macOS ARM64, valid heap/data addresses are typically in high ranges
    // Reject obviously invalid addresses
    if (addr < 0x100000000ULL) return false;  // Too low
    if (addr > 0x800000000000ULL) return false;  // Too high (beyond typical user space)

    // Try to read from the address to verify it's accessible
    // Use vm_read to safely check without crashing
    vm_size_t data_size = sizeof(void*);
    vm_offset_t data;
    mach_port_t task = mach_task_self();
    kern_return_t kr = vm_read(task, (vm_address_t)addr, data_size, &data, (mach_msg_type_number_t*)&data_size);

    if (kr == KERN_SUCCESS) {
        vm_deallocate(task, data, data_size);
        return true;
    }

    return false;
}

// Helper: Get the main binary's __DATA segment bounds
static bool get_data_segment_bounds(void *binary_base, uintptr_t *start, uintptr_t *end) {
    if (!binary_base || !start || !end) return false;

    const struct mach_header_64 *header = (const struct mach_header_64 *)binary_base;

    // Verify it's a 64-bit Mach-O
    if (header->magic != MH_MAGIC_64) {
        LOG_ENTITY_DEBUG("Not a 64-bit Mach-O binary");
        return false;
    }

    // Walk load commands to find __DATA segment
    const uint8_t *ptr = (const uint8_t *)binary_base + sizeof(struct mach_header_64);

    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command *cmd = (const struct load_command *)ptr;

        if (cmd->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)ptr;

            // Look for __DATA or __DATA_CONST segments
            if (strncmp(seg->segname, "__DATA", 6) == 0) {
                *start = (uintptr_t)binary_base + seg->vmaddr - 0x100000000ULL;
                *end = *start + seg->vmsize;
                LOG_ENTITY_DEBUG("Found %s segment: 0x%llx - 0x%llx (size: 0x%llx)",
                           seg->segname, (unsigned long long)*start,
                           (unsigned long long)*end, (unsigned long long)seg->vmsize);
                return true;
            }
        }

        ptr += cmd->cmdsize;
    }

    LOG_ENTITY_DEBUG("__DATA segment not found");
    return false;
}

// Scan memory to find EoCServer singleton pointer
// Strategy: Look for a global pointer that, when dereferenced,
// contains a pointer at offset 0x288 (EntityWorld)
static void *scan_for_eocserver_singleton(void) {
    if (!g_MainBinaryBase) {
        LOG_ENTITY_DEBUG("Cannot scan: main binary base not set");
        return NULL;
    }

    LOG_ENTITY_DEBUG("=== Scanning for EoCServer Singleton ===");

    // Get __DATA segment bounds
    uintptr_t data_start = 0, data_end = 0;
    if (!get_data_segment_bounds(g_MainBinaryBase, &data_start, &data_end)) {
        LOG_ENTITY_DEBUG("Failed to get __DATA segment bounds");
        return NULL;
    }

    // Also check __DATA_CONST and other data segments
    // For now, scan a reasonable range around the main binary
    uintptr_t scan_start = data_start;
    uintptr_t scan_end = data_end;

    LOG_ENTITY_DEBUG("Scanning range: 0x%llx - 0x%llx",
               (unsigned long long)scan_start, (unsigned long long)scan_end);

    int candidates_checked = 0;
    int valid_candidates = 0;

    // Scan for pointer-aligned addresses
    for (uintptr_t addr = scan_start; addr < scan_end; addr += sizeof(void*)) {
        // Read potential pointer from this address
        void **potential_global = (void **)addr;
        void *potential_eocserver = *potential_global;

        // Skip NULL or invalid-looking pointers
        if (!potential_eocserver) continue;
        if ((uintptr_t)potential_eocserver < 0x100000000ULL) continue;
        if ((uintptr_t)potential_eocserver > 0x800000000000ULL) continue;

        candidates_checked++;

        // Check if this looks like EoCServer by verifying offset 0x288 contains a valid pointer
        if (!is_valid_pointer(potential_eocserver)) continue;

        valid_candidates++;

        // Read what's at offset 0x288 (EntityWorld*)
        void **entityworld_ptr = (void **)((char *)potential_eocserver + OFFSET_ENTITYWORLD_IN_EOCSERVER);

        // Safely read the EntityWorld pointer
        vm_size_t data_size = sizeof(void*);
        vm_offset_t data;
        kern_return_t kr = vm_read(mach_task_self(), (vm_address_t)entityworld_ptr,
                                   data_size, &data, (mach_msg_type_number_t*)&data_size);

        if (kr != KERN_SUCCESS) continue;

        void *potential_entityworld = *(void **)data;
        vm_deallocate(mach_task_self(), data, data_size);

        // Check if EntityWorld pointer looks valid
        if (!potential_entityworld) continue;
        if ((uintptr_t)potential_entityworld < 0x100000000ULL) continue;
        if ((uintptr_t)potential_entityworld > 0x800000000000ULL) continue;

        // Further validation: EntityWorld should also be readable
        if (!is_valid_pointer(potential_entityworld)) continue;

        LOG_ENTITY_DEBUG("CANDIDATE FOUND at global 0x%llx:", (unsigned long long)addr);
        LOG_ENTITY_DEBUG("  EoCServer*: %p", potential_eocserver);
        LOG_ENTITY_DEBUG("  EntityWorld* (at +0x288): %p", potential_entityworld);

        // This looks promising! Return it
        return potential_eocserver;
    }

    LOG_ENTITY_DEBUG("Scan complete: checked %d candidates, %d had valid pointers, none matched pattern",
               candidates_checked, valid_candidates);

    return NULL;
}

// Alternative: Scan using known function patterns (ARM64 ADRP/LDR)
// This looks for the instruction pattern that loads EoCServer from a global
static void *scan_for_eocserver_via_instructions(void) {
    if (!g_MainBinaryBase) return NULL;

    LOG_ENTITY_DEBUG("=== Scanning via instruction patterns ===");

    // The StartUp function at known offset loads EoCServer
    // We can look at functions that access EoCServer+0x288 (EntityWorld)
    // Pattern: ADRP Xn, page; LDR Xn, [Xn, #offset]

    uintptr_t ghidra_base = GHIDRA_BASE_ADDRESS;
    uintptr_t actual_base = (uintptr_t)g_MainBinaryBase;

    // Address of a function we know accesses EoCServer
    // esv::EocServer::GetEntityWorld would be ideal, but we'll use StartUp
    uintptr_t startup_addr = OFFSET_EOC_SERVER_STARTUP - ghidra_base + actual_base;

    LOG_ENTITY_DEBUG("Analyzing function at 0x%llx for EoCServer global reference",
               (unsigned long long)startup_addr);

    // Read the first 64 instructions of StartUp looking for ADRP pattern
    uint32_t *instructions = (uint32_t *)startup_addr;

    for (int i = 0; i < 64; i++) {
        uint32_t instr = instructions[i];

        // Check for ADRP instruction (bits 31, 28-24 = 1x0x0)
        // ADRP Rd, label: 1|immlo|10000|immhi|Rd
        if ((instr & 0x9F000000) == 0x90000000) {
            // This is ADRP
            uint32_t rd = instr & 0x1F;
            int64_t immhi = ((int64_t)(instr >> 5) & 0x7FFFF) << 2;
            int64_t immlo = (instr >> 29) & 0x3;
            int64_t imm = (immhi | immlo) << 12;

            // Sign extend
            if (imm & (1ULL << 32)) {
                imm |= 0xFFFFFFFF00000000ULL;
            }

            uintptr_t page_addr = ((uintptr_t)&instructions[i] & ~0xFFFULL) + imm;

            // Look for following LDR that uses this register
            for (int j = i + 1; j < i + 8 && j < 64; j++) {
                uint32_t ldr_instr = instructions[j];

                // LDR (unsigned offset): 11|111|00|01|0|imm12|Rn|Rt
                if ((ldr_instr & 0xFFC00000) == 0xF9400000) {
                    uint32_t rn = (ldr_instr >> 5) & 0x1F;
                    uint32_t imm12 = ((ldr_instr >> 10) & 0xFFF) << 3;  // Scale by 8 for 64-bit

                    if (rn == rd) {
                        uintptr_t global_addr = page_addr + imm12;

                        LOG_ENTITY_DEBUG("Found ADRP+LDR pattern at instruction %d:", i);
                        LOG_ENTITY_DEBUG("  Page: 0x%llx, Offset: 0x%x",
                                   (unsigned long long)page_addr, imm12);
                        LOG_ENTITY_DEBUG("  Global address: 0x%llx", (unsigned long long)global_addr);

                        // Try to read from this global
                        if (is_valid_pointer((void *)global_addr)) {
                            void *potential_eocserver = *(void **)global_addr;
                            LOG_ENTITY_DEBUG("  Value at global: %p", potential_eocserver);

                            if (is_valid_pointer(potential_eocserver)) {
                                // Check offset 0x288
                                void *potential_ew = *(void **)((char *)potential_eocserver + 0x288);
                                LOG_ENTITY_DEBUG("  Value at +0x288: %p", potential_ew);

                                if (is_valid_pointer(potential_ew)) {
                                    LOG_ENTITY_DEBUG("  SUCCESS: Found EoCServer singleton!");
                                    return potential_eocserver;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    LOG_ENTITY_DEBUG("No EoCServer reference found via instruction analysis");
    return NULL;
}

// Direct memory read from known global address (primary method)
// This is the simplest and most reliable approach now that we have the exact address
static void *read_eocserver_from_global(void) {
    if (!g_MainBinaryBase) {
        LOG_ENTITY_DEBUG("Cannot read EoCServer: main binary base not set");
        return NULL;
    }

    // Calculate runtime address of esv::EocServer::m_ptr
    uintptr_t ghidra_base = GHIDRA_BASE_ADDRESS;
    uintptr_t actual_base = (uintptr_t)g_MainBinaryBase;
    uintptr_t global_addr = OFFSET_EOCSERVER_SINGLETON_PTR - ghidra_base + actual_base;

    LOG_ENTITY_DEBUG("Reading EoCServer from global at 0x%llx", (unsigned long long)global_addr);
    LOG_ENTITY_DEBUG("  (Ghidra offset: 0x%llx, base: %p)",
               (unsigned long long)OFFSET_EOCSERVER_SINGLETON_PTR, g_MainBinaryBase);

    // Safely read the pointer using vm_read
    vm_size_t data_size = sizeof(void*);
    vm_offset_t data;
    kern_return_t kr = vm_read(mach_task_self(), (vm_address_t)global_addr,
                               data_size, &data, (mach_msg_type_number_t*)&data_size);

    if (kr != KERN_SUCCESS) {
        LOG_ENTITY_DEBUG("Failed to read EoCServer global (kern_return: %d)", kr);
        return NULL;
    }

    void *eocserver = *(void **)data;
    vm_deallocate(mach_task_self(), data, data_size);

    if (!eocserver) {
        LOG_ENTITY_DEBUG("EoCServer global is NULL (server not yet initialized)");
        return NULL;
    }

    LOG_ENTITY_DEBUG("Read EoCServer pointer: %p", eocserver);

    // Validate the pointer
    if (!is_valid_pointer(eocserver)) {
        LOG_ENTITY_DEBUG("EoCServer pointer appears invalid");
        return NULL;
    }

    return eocserver;
}

// Public function: Try to discover EntityWorld
bool entity_discover_world(void) {
    if (g_EntityWorld) {
        LOG_ENTITY_DEBUG("EntityWorld already discovered: %p", g_EntityWorld);
        return true;
    }

    LOG_ENTITY_DEBUG("Attempting to discover EntityWorld...");

    // Method 1 (PRIMARY): Direct read from known global address
    // This is the most reliable method using the address discovered via Ghidra:
    // esv::EocServer::m_ptr at 0x10898e8b8
    void *eocserver = read_eocserver_from_global();

    // Method 2 (FALLBACK): Try instruction pattern analysis
    if (!eocserver) {
        LOG_ENTITY_DEBUG("Direct read failed, trying instruction pattern analysis...");
        eocserver = scan_for_eocserver_via_instructions();
    }

    // Method 3 (FALLBACK): Data segment scan
    if (!eocserver) {
        LOG_ENTITY_DEBUG("Pattern analysis failed, trying data segment scan...");
        eocserver = scan_for_eocserver_singleton();
    }

    if (eocserver) {
        g_EoCServer = eocserver;

        // Read EntityWorld from offset 0x288
        void *entityworld = *(void **)((char *)eocserver + OFFSET_ENTITYWORLD_IN_EOCSERVER);

        if (entityworld && is_valid_pointer(entityworld)) {
            g_EntityWorld = entityworld;
            LOG_ENTITY_DEBUG("SUCCESS: Discovered EoCServer=%p, EntityWorld=%p",
                       g_EoCServer, g_EntityWorld);

            // Initialize component registry now that we have EntityWorld
            if (component_registry_init(g_EntityWorld)) {
                LOG_ENTITY_DEBUG("Component registry initialized");
            }

            // Initialize component lookup (data structure traversal for macOS)
            if (component_lookup_init(g_EntityWorld, g_MainBinaryBase)) {
                LOG_ENTITY_DEBUG("Component lookup initialized (data structure traversal enabled)");
            } else {
                LOG_ENTITY_DEBUG("WARNING: Component lookup init failed - GetComponent may not work");
            }

            // Initialize TypeId discovery and discover component indices
            if (component_typeid_init(g_MainBinaryBase)) {
                LOG_ENTITY_DEBUG("TypeId discovery initialized");
                int discovered = component_typeid_discover();
                LOG_ENTITY_DEBUG("Discovered %d component type indices from TypeId globals", discovered);
            } else {
                LOG_ENTITY_DEBUG("WARNING: TypeId discovery init failed - indices remain UNDEFINED");
            }

            return true;
        } else {
            LOG_ENTITY_DEBUG("Found EoCServer but EntityWorld at +0x288 is NULL or invalid");
            LOG_ENTITY_DEBUG("(Server may not be fully initialized yet)");
        }
    }

    LOG_ENTITY_DEBUG("Failed to discover EntityWorld");
    return false;
}

// ============================================================================
// Original Function Pointers
// ============================================================================

// esv::EocServer::StartUp(eoc::ServerInit const&)
typedef void (*EocServerStartUpFn)(void *eocServer, void *serverInit);
static EocServerStartUpFn orig_EocServerStartUp = NULL;

// ============================================================================
// Hook: Capture EoCServer Singleton on Startup
// ============================================================================

__attribute__((unused))
static void hook_EocServerStartUp(void *eocServer, void *serverInit) {
    // Capture EoCServer pointer (this) on first call
    if (!g_EoCServer && eocServer) {
        g_EoCServer = eocServer;
        LOG_ENTITY_DEBUG("Captured EoCServer singleton: %p", eocServer);

        // Get EntityWorld from EoCServer + 0x288
        void **entityWorldPtr = (void**)((char*)eocServer + OFFSET_ENTITYWORLD_IN_EOCSERVER);
        g_EntityWorld = *entityWorldPtr;

        if (g_EntityWorld) {
            LOG_ENTITY_DEBUG("Got EntityWorld from EoCServer+0x%x: %p",
                       OFFSET_ENTITYWORLD_IN_EOCSERVER, g_EntityWorld);
        } else {
            LOG_ENTITY_DEBUG("EntityWorld at EoCServer+0x%x is NULL (not yet initialized)",
                       OFFSET_ENTITYWORLD_IN_EOCSERVER);
        }
    }

    // Call original function
    if (orig_EocServerStartUp) {
        orig_EocServerStartUp(eocServer, serverInit);
    }

    // After StartUp completes, EntityWorld should be initialized
    // Try to get it again if it was NULL before
    if (g_EoCServer && !g_EntityWorld) {
        void **entityWorldPtr = (void**)((char*)g_EoCServer + OFFSET_ENTITYWORLD_IN_EOCSERVER);
        g_EntityWorld = *entityWorldPtr;

        if (g_EntityWorld) {
            LOG_ENTITY_DEBUG("Got EntityWorld after StartUp: %p", g_EntityWorld);
        } else {
            LOG_ENTITY_DEBUG("EntityWorld still NULL after StartUp");
        }
    }
}

// Helper: Update EntityWorld from stored EoCServer
static void update_entity_world_from_server(void) {
    if (g_EoCServer && !g_EntityWorld) {
        void **entityWorldPtr = (void**)((char*)g_EoCServer + OFFSET_ENTITYWORLD_IN_EOCSERVER);
        if (entityWorldPtr && *entityWorldPtr) {
            g_EntityWorld = *entityWorldPtr;
            LOG_ENTITY_DEBUG("Updated EntityWorld from EoCServer: %p", g_EntityWorld);
        }
    }
}

// ============================================================================
// Entity System Interface
// ============================================================================

EntityWorldPtr entity_get_world(void) {
    return g_EntityWorld;
}

EntityHandle entity_get_by_guid(const char *guid_str) {
    if (!guid_str || !g_EntityWorld) {
        return ENTITY_HANDLE_INVALID;
    }

    // Extract UUID from full template GUID (e.g., "S_PLA_*_<uuid>" → "<uuid>")
    // This handles character entity GUIDs that have prefixes
    const char *uuid_str = extract_uuid_from_guid(guid_str);

    // Check cache first (use original guid_str for exact match)
    for (int i = 0; i < g_GuidCacheCount; i++) {
        if (strcmp(g_GuidCache[i].guid, guid_str) == 0) {
            return g_GuidCache[i].handle;
        }
    }

    // Try to get UUID mapping singleton if not cached
    if (!g_UuidMappingComponent && g_TryGetUuidMappingSingleton && g_EntityWorld) {
        // TryGetSingleton returns ls::Result<T,E> via x8 buffer (ARM64 ABI)
        // Use wrapper that properly sets x8 to the result buffer address
        LOG_ENTITY_DEBUG("Calling TryGetSingleton with x8 ABI wrapper...");
        g_UuidMappingComponent = call_try_get_singleton_with_x8(
            g_TryGetUuidMappingSingleton, g_EntityWorld);
        if (g_UuidMappingComponent) {
            LOG_ENTITY_DEBUG("Got UuidToHandleMappingComponent: %p", g_UuidMappingComponent);
        } else {
            LOG_ENTITY_DEBUG("Failed to get UuidToHandleMappingComponent");
        }
    }

    if (g_UuidMappingComponent) {
        // Parse the extracted UUID (not the full template GUID)
        Guid guid;
        if (!guid_parse(uuid_str, &guid)) {
            LOG_ENTITY_DEBUG("Failed to parse GUID: %s (extracted: %s)", guid_str, uuid_str);
            return ENTITY_HANDLE_INVALID;
        }

        // Debug: Log what we're searching for
        LOG_ENTITY_INFO("Searching for: %s -> hi=0x%llx lo=0x%llx",
                   uuid_str, (unsigned long long)guid.hi, (unsigned long long)guid.lo);

        // Cast to our structure
        UuidToHandleMappingComponent *mapping = (UuidToHandleMappingComponent*)g_UuidMappingComponent;
        HashMapGuidEntityHandle *hashmap = &mapping->Mappings;

        // Debug: dump HashMap stats on first lookup (DEBUG level - enable with LOG_LEVEL_DEBUG)
        static bool dumped = false;
        if (!dumped) {
            dumped = true;
            LOG_ENTITY_DEBUG("UuidToHandleMappingComponent: ptr=%p, Keys.size=%u",
                       g_UuidMappingComponent, hashmap->Keys.size);
        }

        // Validate HashMap structure
        if (!hashmap->HashKeys.buf || hashmap->HashKeys.size == 0) {
            LOG_ENTITY_DEBUG("HashMap not initialized");
            return ENTITY_HANDLE_INVALID;
        }

        // Hash the GUID: hash = lo ^ hi
        uint64_t hash = guid.lo ^ guid.hi;
        uint32_t bucket = (uint32_t)(hash % hashmap->HashKeys.size);

        // Look up in hash table
        int32_t keyIndex = hashmap->HashKeys.buf[bucket];

        while (keyIndex >= 0) {
            // Bounds check
            if ((uint32_t)keyIndex >= hashmap->Keys.size) {
                LOG_ENTITY_DEBUG("HashMap corruption: keyIndex %d >= Keys.size %u",
                           keyIndex, hashmap->Keys.size);
                break;
            }

            // Compare GUID
            Guid *key = &hashmap->Keys.buf[keyIndex];
            LOG_ENTITY_INFO("Comparing with key[%d]: hi=0x%llx lo=0x%llx",
                       keyIndex, (unsigned long long)key->hi, (unsigned long long)key->lo);
            if (key->lo == guid.lo && key->hi == guid.hi) {
                // Found it!
                EntityHandle handle = hashmap->Values.buf[keyIndex];

                // Cache for future lookups
                if (g_GuidCacheCount < GUID_CACHE_SIZE) {
                    strncpy(g_GuidCache[g_GuidCacheCount].guid, guid_str, 63);
                    g_GuidCache[g_GuidCacheCount].guid[63] = '\0';
                    g_GuidCache[g_GuidCacheCount].handle = handle;
                    g_GuidCacheCount++;
                }

                LOG_ENTITY_DEBUG("GUID lookup SUCCESS: %s -> handle=0x%llx", guid_str, (unsigned long long)handle);
                return handle;
            }

            // Follow collision chain
            if ((uint32_t)keyIndex >= hashmap->NextIds.size) {
                LOG_ENTITY_DEBUG("HashMap corruption: NextIds index out of bounds");
                break;
            }
            keyIndex = hashmap->NextIds.buf[keyIndex];
        }

        LOG_ENTITY_DEBUG("GUID not found in mapping: %s", guid_str);
    }

    return ENTITY_HANDLE_INVALID;
}

/**
 * Reverse lookup: Get GUID string for an EntityHandle from cache.
 * Returns NULL if not found in cache.
 */
static const char* entity_get_guid_from_cache(EntityHandle handle) {
    for (int i = 0; i < g_GuidCacheCount; i++) {
        if (g_GuidCache[i].handle == handle) {
            return g_GuidCache[i].guid;
        }
    }
    return NULL;
}

bool entity_is_alive(EntityHandle handle) {
    if (!entity_is_valid(handle) || !g_EntityWorld) {
        return false;
    }

    // TODO: Check entity storage for validity
    return true;
}

void* entity_get_component(EntityHandle handle, ComponentType type) {
    if (!entity_is_valid(handle) || !g_EntityWorld) {
        return NULL;
    }

    // Get the full component name for registry lookup
    const char *componentName = get_component_full_name(type);
    if (!componentName) {
        LOG_ENTITY_DEBUG("Unknown component type: %d", type);
        return NULL;
    }

    // Look up component info in the registry
    const ComponentInfo *info = component_registry_lookup(componentName);
    if (!info) {
        LOG_ENTITY_DEBUG("Component '%s' not found in registry", componentName);
        return NULL;
    }

    // Check if we have a valid type index
    if (info->index == COMPONENT_INDEX_UNDEFINED) {
        LOG_ENTITY_DEBUG("Component '%s' has undefined type index (TypeId not discovered)", componentName);
        return NULL;
    }

    // Get component size (use registry size if available, otherwise our fallback)
    size_t componentSize = info->size;
    if (componentSize == 0) {
        componentSize = get_component_size_for_type(type);
    }

    // Use data structure traversal to get the component
    void *component = component_lookup_by_index(
        handle,
        info->index,
        componentSize,
        info->is_proxy
    );

    if (component) {
        LOG_ENTITY_DEBUG("Got component %s (index=%u) for handle 0x%llx: %p",
                   componentName, info->index, (unsigned long long)handle, component);
    }

    return component;
}

const char** entity_get_component_names(EntityHandle handle, int *count) {
    (void)handle;  // Suppress unused parameter warning until implemented

    if (count) *count = 0;

    // TODO: Enumerate components on entity
    return NULL;
}

// ============================================================================
// Initialization
// ============================================================================

int entity_system_init(void *main_binary_base) {
    if (g_Initialized) {
        LOG_ENTITY_DEBUG("Already initialized");
        return 0;
    }

    if (!main_binary_base) {
        LOG_ENTITY_DEBUG("ERROR: main_binary_base is NULL");
        return -1;
    }

    g_MainBinaryBase = main_binary_base;
    LOG_ENTITY_DEBUG("Initializing with main binary base: %p", main_binary_base);

    // Calculate actual function address
    // Note: The offsets from Ghidra include the base load address (0x100000000)
    // We need to subtract that and add our actual base
    uintptr_t ghidra_base = 0x100000000;
    uintptr_t actual_base = (uintptr_t)main_binary_base;

    // NOTE: Inline hooking of main binary functions causes KERN_PROTECTION_FAILURE
    // on macOS due to Hardened Runtime memory protection. Dobby hooks in __TEXT
    // segments fail even when reported as successful.
    //
    // For now, EntityWorld must be captured via a different approach:
    // 1. Hook a function in libOsiris.dylib instead (different memory protections)
    // 2. Use Lua event callbacks to trigger EntityWorld discovery
    // 3. Scan for known patterns in memory at runtime
    //
    // The old approach of hooking EocServer::StartUp is disabled:
    // uintptr_t startup_addr = OFFSET_EOC_SERVER_STARTUP - ghidra_base + actual_base;
    // DobbyHook((void*)startup_addr, (void*)hook_EocServerStartUp, (void**)&orig_EocServerStartUp);
    LOG_ENTITY_DEBUG("Main binary hooks disabled (macOS memory protection issues)");
    LOG_ENTITY_DEBUG("EntityWorld must be set manually via Ext.Entity.SetWorldPtr() or discovered via Osiris hooks");

    // Set up function pointers for component accessors and singleton getters
    // These don't need hooks - we just need to know where to call
    g_TryGetUuidMappingSingleton = (TryGetSingletonFn)(OFFSET_TRY_GET_UUID_MAPPING_SINGLETON - ghidra_base + actual_base);

    // ls:: components - all DISABLED until addresses are verified via Ghidra
    // When offset is 0, pointer stays NULL (safe)
    if (OFFSET_GET_TRANSFORM_COMPONENT != 0) {
        g_GetTransformComponent = (GetComponentFn)(OFFSET_GET_TRANSFORM_COMPONENT - ghidra_base + actual_base);
    }
    if (OFFSET_GET_LEVEL_COMPONENT != 0) {
        g_GetLevelComponent = (GetComponentFn)(OFFSET_GET_LEVEL_COMPONENT - ghidra_base + actual_base);
    }
    if (OFFSET_GET_PHYSICS_COMPONENT != 0) {
        g_GetPhysicsComponent = (GetComponentFn)(OFFSET_GET_PHYSICS_COMPONENT - ghidra_base + actual_base);
    }
    if (OFFSET_GET_VISUAL_COMPONENT != 0) {
        g_GetVisualComponent = (GetComponentFn)(OFFSET_GET_VISUAL_COMPONENT - ghidra_base + actual_base);
    }

    // eoc:: components - all DISABLED until addresses are verified
    if (OFFSET_GET_STATS_COMPONENT != 0) {
        g_GetStatsComponent = (GetComponentFn)(OFFSET_GET_STATS_COMPONENT - ghidra_base + actual_base);
    }
    if (OFFSET_GET_BASEHP_COMPONENT != 0) {
        g_GetBaseHpComponent = (GetComponentFn)(OFFSET_GET_BASEHP_COMPONENT - ghidra_base + actual_base);
    }
    if (OFFSET_GET_HEALTH_COMPONENT != 0) {
        g_GetHealthComponent = (GetComponentFn)(OFFSET_GET_HEALTH_COMPONENT - ghidra_base + actual_base);
    }
    if (OFFSET_GET_ARMOR_COMPONENT != 0) {
        g_GetArmorComponent = (GetComponentFn)(OFFSET_GET_ARMOR_COMPONENT - ghidra_base + actual_base);
    }
    if (OFFSET_GET_CLASSES_COMPONENT != 0) {
        g_GetClassesComponent = (GetComponentFn)(OFFSET_GET_CLASSES_COMPONENT - ghidra_base + actual_base);
    }

    LOG_ENTITY_DEBUG("Function pointers initialized:");
    LOG_ENTITY_DEBUG("  TryGetUuidMappingSingleton: %p", (void*)g_TryGetUuidMappingSingleton);
    LOG_ENTITY_DEBUG("  GetTransformComponent: %p", (void*)g_GetTransformComponent);
    LOG_ENTITY_DEBUG("  GetLevelComponent: %p", (void*)g_GetLevelComponent);
    LOG_ENTITY_DEBUG("  GetStatsComponent: %p", (void*)g_GetStatsComponent);
    LOG_ENTITY_DEBUG("  GetBaseHpComponent: %p", (void*)g_GetBaseHpComponent);
    LOG_ENTITY_DEBUG("  GetHealthComponent: %p", (void*)g_GetHealthComponent);
    LOG_ENTITY_DEBUG("  GetArmorComponent: %p", (void*)g_GetArmorComponent);

    // Initialize TypeId discovery and read component indices from game memory
    // This doesn't require EntityWorld - just the binary base address
    if (component_typeid_init(main_binary_base)) {
        LOG_ENTITY_DEBUG("TypeId discovery initialized");
        int discovered = component_typeid_discover();
        LOG_ENTITY_DEBUG("Discovered %d component type indices from TypeId globals", discovered);
    } else {
        LOG_ENTITY_DEBUG("WARNING: TypeId discovery init failed");
    }

    // Initialize component property system (data-driven property layouts)
    if (component_property_init()) {
        LOG_ENTITY_DEBUG("Component property system initialized with %d layouts",
                         component_property_get_layout_count());
    } else {
        LOG_ENTITY_DEBUG("WARNING: Component property system init failed");
    }

    g_Initialized = true;

    return 0;
}

bool entity_system_ready(void) {
    // Try to get EntityWorld from EoCServer if not yet available
    if (!g_EntityWorld && g_EoCServer) {
        update_entity_world_from_server();
    }
    return g_EntityWorld != NULL;
}

void* entity_get_binary_base(void) {
    return g_MainBinaryBase;
}

// ============================================================================
// TypeId Discovery Retry
// ============================================================================

bool entity_typeid_discovery_complete(void) {
    return g_TypeIdDiscoveryComplete;
}

int entity_retry_typeid_discovery(void) {
    if (g_TypeIdDiscoveryComplete) {
        // Already done - return cached count
        return component_registry_count();
    }

    if (!g_MainBinaryBase) {
        LOG_ENTITY_DEBUG("Cannot retry TypeId discovery - binary base not set");
        return 0;
    }

    // Ensure TypeId module is initialized
    if (!component_typeid_init(g_MainBinaryBase)) {
        LOG_ENTITY_DEBUG("TypeId discovery init failed on retry");
        return 0;
    }

    int discovered = component_typeid_discover();

    // Check if any TypeIds were actually found with non-zero indices
    // The issue is that TypeIds read as 0 before the game initializes them
    if (discovered > 0) {
        // Verify at least one key component has a non-zero index
        const ComponentInfo *stats = component_registry_lookup("eoc::StatsComponent");
        const ComponentInfo *hp = component_registry_lookup("eoc::BaseHpComponent");

        bool hasValidIndex = false;
        if (stats && stats->index != COMPONENT_INDEX_UNDEFINED && stats->index != 0) {
            hasValidIndex = true;
        }
        if (hp && hp->index != COMPONENT_INDEX_UNDEFINED && hp->index != 0) {
            hasValidIndex = true;
        }

        if (hasValidIndex) {
            g_TypeIdDiscoveryComplete = true;
            LOG_ENTITY_DEBUG("TypeId discovery complete: %d components with valid indices", discovered);
        } else {
            g_TypeIdRetryCount++;
            LOG_ENTITY_DEBUG("TypeId discovery attempt %d/%d: %d components read (indices still 0)",
                      g_TypeIdRetryCount, TYPEID_MAX_RETRIES, discovered);
        }
    } else {
        g_TypeIdRetryCount++;
        LOG_ENTITY_DEBUG("TypeId discovery attempt %d/%d: no components discovered",
                  g_TypeIdRetryCount, TYPEID_MAX_RETRIES);
    }

    return discovered;
}

// Called from SessionLoaded event handler to retry TypeId discovery
void entity_on_session_loaded(void) {
    if (g_TypeIdDiscoveryComplete) {
        LOG_ENTITY_DEBUG("SessionLoaded: TypeId discovery already complete");
        return;
    }

    LOG_ENTITY_DEBUG("SessionLoaded: Retrying TypeId discovery...");
    entity_retry_typeid_discovery();
}

// ============================================================================
// Lua Bindings
// ============================================================================

// Ext.Entity.Get(guid) -> entity userdata or nil
static int lua_entity_get(lua_State *L) {
    const char *guid = luaL_checkstring(L, 1);

    if (!entity_system_ready()) {
        lua_pushnil(L);
        lua_pushstring(L, "Entity system not ready - wait for combat");
        return 2;
    }

    EntityHandle handle = entity_get_by_guid(guid);

    if (!entity_is_valid(handle)) {
        lua_pushnil(L);
        return 1;
    }

    // Create entity userdata with lifetime scoping
    EntityUserdata *ud = (EntityUserdata*)lua_newuserdata(L, sizeof(EntityUserdata));
    ud->handle = handle;
    ud->lifetime = lifetime_lua_get_current(L);

    // Set metatable
    luaL_getmetatable(L, "BG3Entity");
    lua_setmetatable(L, -2);

    return 1;
}

// Ext.Entity.GetWorld() -> true/false (for debugging)
static int lua_entity_get_world(lua_State *L) {
    if (g_EntityWorld) {
        lua_pushlightuserdata(L, g_EntityWorld);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

// Ext.Entity.IsReady() -> boolean
static int lua_entity_is_ready(lua_State *L) {
    lua_pushboolean(L, entity_system_ready());
    return 1;
}

// Ext.Entity.Discover() -> boolean
// Attempts to find EntityWorld via memory scanning
static int lua_entity_discover(lua_State *L) {
    bool success = entity_discover_world();
    lua_pushboolean(L, success);
    return 1;
}

// Ext.Entity.DumpWorld(offset, size) -> string
// Dumps bytes from EntityWorld at given offset for debugging structure layouts
// Usage: Ext.Entity.DumpWorld(0, 64) -- dump first 64 bytes
static int lua_entity_dump_world(lua_State *L) {
    if (!g_EntityWorld) {
        lua_pushnil(L);
        lua_pushstring(L, "EntityWorld not captured");
        return 2;
    }

    int offset = luaL_optinteger(L, 1, 0);
    int size = luaL_optinteger(L, 2, 64);

    // Clamp size to reasonable limits
    if (size < 0) size = 0;
    if (size > 1024) size = 1024;

    LOG_ENTITY_DEBUG("=== EntityWorld Memory Dump ===");
    LOG_ENTITY_DEBUG("EntityWorld base: %p", g_EntityWorld);
    LOG_ENTITY_DEBUG("Dumping offset 0x%x, size %d bytes:", offset, size);

    uint8_t *base = (uint8_t *)g_EntityWorld;

    // Build hex dump string
    char dump[4096] = {0};
    char *p = dump;
    int remaining = sizeof(dump) - 1;

    for (int i = 0; i < size && remaining > 50; i += 16) {
        int n = snprintf(p, remaining, "%04x: ", offset + i);
        p += n;
        remaining -= n;

        // Hex bytes
        for (int j = 0; j < 16 && i + j < size; j++) {
            uint8_t byte = base[offset + i + j];
            n = snprintf(p, remaining, "%02x ", byte);
            p += n;
            remaining -= n;
        }

        // Pad if needed
        for (int j = (i + 16 < size) ? 0 : 16 - (size - i); j < 16 && remaining > 1; j++) {
            n = snprintf(p, remaining, "   ");
            p += n;
            remaining -= n;
        }

        n = snprintf(p, remaining, " | ");
        p += n;
        remaining -= n;

        // ASCII
        for (int j = 0; j < 16 && i + j < size && remaining > 1; j++) {
            uint8_t byte = base[offset + i + j];
            char c = (byte >= 32 && byte < 127) ? byte : '.';
            *p++ = c;
            remaining--;
        }

        n = snprintf(p, remaining, "\n");
        p += n;
        remaining -= n;

        // Log each line
        char line[128];
        snprintf(line, sizeof(line), "%04x:", offset + i);
        for (int j = 0; j < 16 && i + j < size; j++) {
            char hex[4];
            snprintf(hex, sizeof(hex), " %02x", base[offset + i + j]);
            strncat(line, hex, sizeof(line) - strlen(line) - 1);
        }
        LOG_ENTITY_DEBUG("%s", line);
    }

    // Also log potential pointer values at 8-byte intervals
    LOG_ENTITY_DEBUG("Potential pointers:");
    for (int i = 0; i < size && i + 8 <= size; i += 8) {
        void *ptr = *(void **)(base + offset + i);
        // Check if it looks like a valid pointer (in reasonable address range)
        uintptr_t val = (uintptr_t)ptr;
        if (val > 0x100000000ULL && val < 0x200000000ULL) {
            LOG_ENTITY_DEBUG("  +0x%03x: %p (valid pointer)", offset + i, ptr);
        }
    }

    lua_pushstring(L, dump);
    return 1;
}

// Ext.Entity.Test() - Test component accessors with known GUIDs
static int lua_entity_test(lua_State *L) {
    LOG_ENTITY_DEBUG("=== Entity Component Test ===");

    if (!entity_system_ready()) {
        LOG_ENTITY_DEBUG("Entity system not ready - enter combat first");
        lua_pushboolean(L, 0);
        return 1;
    }

    LOG_ENTITY_DEBUG("EntityWorld: %p", g_EntityWorld);

    // Test GUIDs - use ones from HashMap dump plus template GUIDs
    const char *test_guids[] = {
        "a5eaeafe-220d-bc4d-4cc3-b94574d334c7",  // From HashMap dump [0]
        "6e250e36-614a-a8dc-4104-45dabb8405f2",  // From HashMap dump [1]
        "c7c13742-bacd-460a-8f65-f864fe41f255",  // Astarion template
        NULL
    };

    int success_count = 0;

    for (int i = 0; test_guids[i] != NULL; i++) {
        const char *guid = test_guids[i];
        LOG_ENTITY_DEBUG("Testing GUID: %s", guid);

        EntityHandle handle = entity_get_by_guid(guid);
        if (!entity_is_valid(handle)) {
            LOG_ENTITY_DEBUG("  Entity not found");
            continue;
        }

        LOG_ENTITY_DEBUG("  Handle: 0x%llx", (unsigned long long)handle);

        // Test Transform (ls:: component)
        void *transform = entity_get_component(handle, COMPONENT_TRANSFORM);
        LOG_ENTITY_DEBUG("  Transform: %s", transform ? "FOUND" : "nil");

        // Test Stats (eoc:: component)
        void *stats = entity_get_component(handle, COMPONENT_STATS);
        LOG_ENTITY_DEBUG("  Stats: %s", stats ? "FOUND" : "nil");

        // Test Health (eoc:: component)
        void *health = entity_get_component(handle, COMPONENT_HEALTH);
        LOG_ENTITY_DEBUG("  Health: %s", health ? "FOUND" : "nil");

        // Test BaseHp (eoc:: component)
        void *basehp = entity_get_component(handle, COMPONENT_BASE_HP);
        LOG_ENTITY_DEBUG("  BaseHp: %s", basehp ? "FOUND" : "nil");

        // Test Armor (eoc:: component)
        void *armor = entity_get_component(handle, COMPONENT_ARMOR);
        LOG_ENTITY_DEBUG("  Armor: %s", armor ? "FOUND" : "nil");

        if (transform || stats || health) {
            success_count++;
        }
    }

    LOG_ENTITY_DEBUG("=== Test Complete: %d entities with components ===", success_count);

    lua_pushboolean(L, success_count > 0);
    return 1;
}

// Entity:IsAlive() method
static int lua_entity_is_alive(lua_State *L) {
    EntityUserdata *ud = (EntityUserdata*)luaL_checkudata(L, 1, "BG3Entity");
    if (!lifetime_lua_is_valid(L, ud->lifetime)) {
        return lifetime_lua_expired_error(L, "Entity");
    }
    lua_pushboolean(L, entity_is_alive(ud->handle));
    return 1;
}

// Entity:GetHandle() method - returns raw handle for debugging
static int lua_entity_get_handle(lua_State *L) {
    EntityUserdata *ud = (EntityUserdata*)luaL_checkudata(L, 1, "BG3Entity");
    if (!lifetime_lua_is_valid(L, ud->lifetime)) {
        return lifetime_lua_expired_error(L, "Entity");
    }
    lua_pushinteger(L, (lua_Integer)ud->handle);
    return 1;
}

// Helper: Push TransformComponent as Lua table
static void push_transform_component(lua_State *L, void *component) {
    TransformComponent *transform = (TransformComponent*)component;

    lua_newtable(L);

    // Position subtable
    lua_newtable(L);
    lua_pushnumber(L, transform->position[0]);
    lua_setfield(L, -2, "x");
    lua_pushnumber(L, transform->position[1]);
    lua_setfield(L, -2, "y");
    lua_pushnumber(L, transform->position[2]);
    lua_setfield(L, -2, "z");
    lua_setfield(L, -2, "Position");

    // Rotation subtable (quaternion)
    lua_newtable(L);
    lua_pushnumber(L, transform->rotation[0]);
    lua_setfield(L, -2, "x");
    lua_pushnumber(L, transform->rotation[1]);
    lua_setfield(L, -2, "y");
    lua_pushnumber(L, transform->rotation[2]);
    lua_setfield(L, -2, "z");
    lua_pushnumber(L, transform->rotation[3]);
    lua_setfield(L, -2, "w");
    lua_setfield(L, -2, "Rotation");

    // Scale subtable
    lua_newtable(L);
    lua_pushnumber(L, transform->scale[0]);
    lua_setfield(L, -2, "x");
    lua_pushnumber(L, transform->scale[1]);
    lua_setfield(L, -2, "y");
    lua_pushnumber(L, transform->scale[2]);
    lua_setfield(L, -2, "z");
    lua_setfield(L, -2, "Scale");
}

// Entity:GetComponent(name) method
// Supports both short names (e.g., "Transform") and full names (e.g., "ls::TransformComponent")
static int lua_entity_get_component(lua_State *L) {
    EntityUserdata *ud = (EntityUserdata*)luaL_checkudata(L, 1, "BG3Entity");
    if (!lifetime_lua_is_valid(L, ud->lifetime)) {
        return lifetime_lua_expired_error(L, "Entity");
    }
    const char *name = luaL_checkstring(L, 2);

    // First try component_get_by_name which handles:
    // 1. Direct template calls for known components (ecl::Character, etc.)
    // 2. Registry-based lookup for discovered components
    if (g_EntityWorld) {
        void *component = component_get_by_name(g_EntityWorld, ud->handle, name);
        if (component) {
            // For Transform, use proper struct conversion
            if (strstr(name, "TransformComponent") != NULL) {
                push_transform_component(L, component);
            } else {
                // Check if we have a property layout for this component
                const ComponentLayoutDef *layout = component_property_get_layout(name);
                if (!layout) {
                    // Try short name lookup
                    layout = component_property_get_layout_by_short_name(name);
                }

                if (layout) {
                    // Return a property proxy for known components
                    component_property_push_proxy(L, component, layout);
                } else {
                    // Return raw component pointer as light userdata
                    // Mods can use this with Ext.Entity.DumpComponentRegistry() to understand the layout
                    lua_pushlightuserdata(L, component);
                }
            }
            return 1;
        }
    }

    // Fall back to legacy enum-based lookup for short names
    ComponentType type;
    bool found = true;

    // Map short component name to type
    if (strcmp(name, "Transform") == 0) {
        type = COMPONENT_TRANSFORM;
    } else if (strcmp(name, "Level") == 0) {
        type = COMPONENT_LEVEL;
    } else if (strcmp(name, "Physics") == 0) {
        type = COMPONENT_PHYSICS;
    } else if (strcmp(name, "Visual") == 0) {
        type = COMPONENT_VISUAL;
    } else if (strcmp(name, "Stats") == 0) {
        type = COMPONENT_STATS;
    } else if (strcmp(name, "BaseHp") == 0) {
        type = COMPONENT_BASE_HP;
    } else if (strcmp(name, "Health") == 0) {
        type = COMPONENT_HEALTH;
    } else if (strcmp(name, "Armor") == 0) {
        type = COMPONENT_ARMOR;
    } else if (strcmp(name, "Data") == 0) {
        type = COMPONENT_DATA;
    } else if (strcmp(name, "BaseStats") == 0) {
        type = COMPONENT_BASE_STATS;
    } else {
        found = false;
    }

    if (!found) {
        // Not found in legacy enum either
        lua_pushnil(L);
        lua_pushfstring(L, "Unknown component: %s (try full name like 'eoc::HealthComponent')", name);
        return 2;
    }

    void *component = entity_get_component(ud->handle, type);
    if (!component) {
        lua_pushnil(L);
        return 1;
    }

    // Convert component to Lua table based on type
    switch (type) {
        case COMPONENT_TRANSFORM:
            push_transform_component(L, component);
            break;

        // For components with property layouts, return proxy
        case COMPONENT_HEALTH: {
            const ComponentLayoutDef *layout = component_property_get_layout_by_short_name("Health");
            if (layout) {
                component_property_push_proxy(L, component, layout);
            } else {
                lua_pushlightuserdata(L, component);
            }
            break;
        }
        case COMPONENT_BASE_HP: {
            const ComponentLayoutDef *layout = component_property_get_layout_by_short_name("BaseHp");
            if (layout) {
                component_property_push_proxy(L, component, layout);
            } else {
                lua_pushlightuserdata(L, component);
            }
            break;
        }
        case COMPONENT_ARMOR: {
            const ComponentLayoutDef *layout = component_property_get_layout_by_short_name("Armor");
            if (layout) {
                component_property_push_proxy(L, component, layout);
            } else {
                lua_pushlightuserdata(L, component);
            }
            break;
        }
        case COMPONENT_STATS: {
            const ComponentLayoutDef *layout = component_property_get_layout_by_short_name("Stats");
            if (layout) {
                component_property_push_proxy(L, component, layout);
            } else {
                lua_pushlightuserdata(L, component);
            }
            break;
        }
        case COMPONENT_LEVEL: {
            const ComponentLayoutDef *layout = component_property_get_layout_by_short_name("Level");
            if (layout) {
                component_property_push_proxy(L, component, layout);
            } else {
                lua_pushlightuserdata(L, component);
            }
            break;
        }
        case COMPONENT_DATA: {
            const ComponentLayoutDef *layout = component_property_get_layout_by_short_name("Data");
            if (layout) {
                component_property_push_proxy(L, component, layout);
            } else {
                lua_pushlightuserdata(L, component);
            }
            break;
        }
        case COMPONENT_BASE_STATS: {
            const ComponentLayoutDef *layout = component_property_get_layout_by_short_name("BaseStats");
            if (layout) {
                component_property_push_proxy(L, component, layout);
            } else {
                lua_pushlightuserdata(L, component);
            }
            break;
        }

        // For components without full struct definitions, return light userdata
        default:
            lua_pushlightuserdata(L, component);
            break;
    }

    return 1;
}

// ============================================================================
// GetAllComponents / GetAllComponentNames
// ============================================================================

// Entity:GetAllComponentNames(requireMapped) -> { "name1", "name2", ... }
// Returns an array of component type names attached to this entity
static int lua_entity_get_all_component_names(lua_State *L) {
    EntityUserdata *ud = (EntityUserdata*)luaL_checkudata(L, 1, "BG3Entity");
    if (!lifetime_lua_is_valid(L, ud->lifetime)) {
        return lifetime_lua_expired_error(L, "Entity");
    }
    bool requireMapped = lua_toboolean(L, 2);  // optional, default false

    if (!component_lookup_ready()) {
        lua_newtable(L);
        return 1;
    }

    // Get EntityStorageData for this entity
    void *storageData = component_lookup_get_storage_data(ud->handle);
    if (!storageData) {
        lua_newtable(L);
        return 1;
    }

    // Enumerate component types
    uint16_t indices[256];
    uint8_t slots[256];
    int count = storage_data_enumerate_component_types(storageData, indices, slots, 256);

    // Build result array
    lua_createtable(L, count, 0);
    int resultIdx = 1;

    for (int i = 0; i < count; i++) {
        const ComponentInfo *info = component_registry_lookup_by_index(indices[i]);
        if (info && info->name) {
            if (!requireMapped || info->discovered) {
                lua_pushstring(L, info->name);
                lua_rawseti(L, -2, resultIdx++);
            }
        } else if (!requireMapped) {
            // Include unknown types as "Unknown_<index>"
            char buf[32];
            snprintf(buf, sizeof(buf), "Unknown_%u", indices[i]);
            lua_pushstring(L, buf);
            lua_rawseti(L, -2, resultIdx++);
        }
    }

    return 1;
}

// Entity:GetAllComponents(warnOnMissing) -> { ["ComponentName"] = componentData, ... }
// Returns a table mapping component names to their data (light userdata)
static int lua_entity_get_all_components(lua_State *L) {
    EntityUserdata *ud = (EntityUserdata*)luaL_checkudata(L, 1, "BG3Entity");
    if (!lifetime_lua_is_valid(L, ud->lifetime)) {
        return lifetime_lua_expired_error(L, "Entity");
    }
    bool warnOnMissing = lua_toboolean(L, 2);  // optional

    if (!component_lookup_ready() || !g_EntityWorld) {
        lua_newtable(L);
        return 1;
    }

    void *storageData = component_lookup_get_storage_data(ud->handle);
    if (!storageData) {
        lua_newtable(L);
        return 1;
    }

    // Enumerate component types
    uint16_t indices[256];
    uint8_t slots[256];
    int count = storage_data_enumerate_component_types(storageData, indices, slots, 256);

    lua_newtable(L);

    for (int i = 0; i < count; i++) {
        const ComponentInfo *info = component_registry_lookup_by_index(indices[i]);
        const char *name = info ? info->name : NULL;

        // Get component data
        void *component = component_lookup_by_index(
            ud->handle, indices[i],
            info ? info->size : 0,
            info ? info->is_proxy : false
        );

        if (component) {
            // Use name or fallback
            if (name) {
                lua_pushstring(L, name);
            } else {
                char buf[32];
                snprintf(buf, sizeof(buf), "Unknown_%u", indices[i]);
                lua_pushstring(L, buf);
            }

            // Push component data (light userdata for now)
            // TODO: Eventually convert to proper Lua tables like Transform
            lua_pushlightuserdata(L, component);
            lua_rawset(L, -3);
        } else if (warnOnMissing && name) {
            LOG_ENTITY_DEBUG("GetAllComponents: Failed to get %s (type %u)", name, indices[i]);
        }
    }

    return 1;
}

// Entity metatable __index
static int lua_entity_index(lua_State *L) {
    EntityUserdata *ud = (EntityUserdata*)luaL_checkudata(L, 1, "BG3Entity");
    const char *key = luaL_checkstring(L, 2);

    // Check for methods first - methods don't need lifetime check
    // (the method itself will check when invoked)
    if (strcmp(key, "IsAlive") == 0) {
        lua_pushcfunction(L, lua_entity_is_alive);
        return 1;
    }
    if (strcmp(key, "GetHandle") == 0) {
        lua_pushcfunction(L, lua_entity_get_handle);
        return 1;
    }
    if (strcmp(key, "GetComponent") == 0) {
        lua_pushcfunction(L, lua_entity_get_component);
        return 1;
    }
    if (strcmp(key, "GetAllComponents") == 0) {
        lua_pushcfunction(L, lua_entity_get_all_components);
        return 1;
    }
    if (strcmp(key, "GetAllComponentNames") == 0) {
        lua_pushcfunction(L, lua_entity_get_all_component_names);
        return 1;
    }

    // For property access (not methods), validate lifetime
    if (!lifetime_lua_is_valid(L, ud->lifetime)) {
        return lifetime_lua_expired_error(L, "Entity");
    }

    EntityHandle handle = ud->handle;

    // entity.Vars - Returns user variables proxy for this entity
    if (strcmp(key, "Vars") == 0) {
        const char *guid = entity_get_guid_from_cache(handle);
        if (guid) {
            uvar_push_entity_proxy(L, guid, handle);
        } else {
            // Entity not in cache - create empty proxy with handle string as key
            char handle_str[32];
            snprintf(handle_str, sizeof(handle_str), "0x%llx", (unsigned long long)handle);
            uvar_push_entity_proxy(L, handle_str, handle);
        }
        return 1;
    }

    // Try to get component directly by name (e.g., entity.Transform)
    ComponentType type;
    bool is_component = true;

    if (strcmp(key, "Transform") == 0) {
        type = COMPONENT_TRANSFORM;
    } else if (strcmp(key, "Level") == 0) {
        type = COMPONENT_LEVEL;
    } else if (strcmp(key, "Physics") == 0) {
        type = COMPONENT_PHYSICS;
    } else if (strcmp(key, "Visual") == 0) {
        type = COMPONENT_VISUAL;
    } else if (strcmp(key, "Stats") == 0) {
        type = COMPONENT_STATS;
    } else if (strcmp(key, "BaseHp") == 0) {
        type = COMPONENT_BASE_HP;
    } else if (strcmp(key, "Health") == 0) {
        type = COMPONENT_HEALTH;
    } else if (strcmp(key, "Armor") == 0) {
        type = COMPONENT_ARMOR;
    } else if (strcmp(key, "Data") == 0) {
        type = COMPONENT_DATA;
    } else if (strcmp(key, "BaseStats") == 0) {
        type = COMPONENT_BASE_STATS;
    } else {
        is_component = false;
    }

    if (is_component) {
        void *component = entity_get_component(handle, type);
        if (!component) {
            lua_pushnil(L);
            return 1;
        }

        // Convert component to Lua based on type
        switch (type) {
            case COMPONENT_TRANSFORM:
                push_transform_component(L, component);
                break;

            // For components with property layouts, return proxy
            case COMPONENT_HEALTH: {
                const ComponentLayoutDef *layout = component_property_get_layout_by_short_name("Health");
                if (layout) {
                    component_property_push_proxy(L, component, layout);
                } else {
                    lua_pushlightuserdata(L, component);
                }
                break;
            }
            case COMPONENT_BASE_HP: {
                const ComponentLayoutDef *layout = component_property_get_layout_by_short_name("BaseHp");
                if (layout) {
                    component_property_push_proxy(L, component, layout);
                } else {
                    lua_pushlightuserdata(L, component);
                }
                break;
            }
            case COMPONENT_ARMOR: {
                const ComponentLayoutDef *layout = component_property_get_layout_by_short_name("Armor");
                if (layout) {
                    component_property_push_proxy(L, component, layout);
                } else {
                    lua_pushlightuserdata(L, component);
                }
                break;
            }
            case COMPONENT_STATS: {
                const ComponentLayoutDef *layout = component_property_get_layout_by_short_name("Stats");
                if (layout) {
                    component_property_push_proxy(L, component, layout);
                } else {
                    lua_pushlightuserdata(L, component);
                }
                break;
            }
            case COMPONENT_LEVEL: {
                const ComponentLayoutDef *layout = component_property_get_layout_by_short_name("Level");
                if (layout) {
                    component_property_push_proxy(L, component, layout);
                } else {
                    lua_pushlightuserdata(L, component);
                }
                break;
            }
            case COMPONENT_DATA: {
                const ComponentLayoutDef *layout = component_property_get_layout_by_short_name("Data");
                if (layout) {
                    component_property_push_proxy(L, component, layout);
                } else {
                    lua_pushlightuserdata(L, component);
                }
                break;
            }
            case COMPONENT_BASE_STATS: {
                const ComponentLayoutDef *layout = component_property_get_layout_by_short_name("BaseStats");
                if (layout) {
                    component_property_push_proxy(L, component, layout);
                } else {
                    lua_pushlightuserdata(L, component);
                }
                break;
            }

            default:
                lua_pushlightuserdata(L, component);
                break;
        }
        return 1;
    }

    lua_pushnil(L);
    return 1;
}

// Entity metatable __tostring
static int lua_entity_tostring(lua_State *L) {
    EntityUserdata *ud = (EntityUserdata*)luaL_checkudata(L, 1, "BG3Entity");
    // tostring works even on expired entities (for debugging)
    bool valid = lifetime_lua_is_valid(L, ud->lifetime);
    char buf[80];
    if (valid) {
        snprintf(buf, sizeof(buf), "Entity(0x%llx)", (unsigned long long)ud->handle);
    } else {
        snprintf(buf, sizeof(buf), "Entity(0x%llx) [EXPIRED]", (unsigned long long)ud->handle);
    }
    lua_pushstring(L, buf);
    return 1;
}

// ============================================================================
// Component Registry Lua Bindings
// ============================================================================

// Iterator callback for DumpComponentRegistry
static bool dump_registry_iterator(const ComponentInfo *info, void *userdata) {
    lua_State *L = (lua_State *)userdata;

    // Create entry table
    lua_newtable(L);

    lua_pushinteger(L, info->index);
    lua_setfield(L, -2, "typeIndex");

    lua_pushinteger(L, info->size);
    lua_setfield(L, -2, "size");

    lua_pushboolean(L, info->is_proxy);
    lua_setfield(L, -2, "isProxy");

    lua_pushboolean(L, info->is_one_frame);
    lua_setfield(L, -2, "isOneFrame");

    lua_pushboolean(L, info->discovered);
    lua_setfield(L, -2, "discovered");

    // Set in result table with component name as key
    lua_setfield(L, -2, info->name);

    return true;  // Continue iteration
}

// Ext.Entity.DumpComponentRegistry() -> table
// Returns a table mapping component names to their metadata
static int lua_entity_dump_component_registry(lua_State *L) {
    // Initialize registry if not done (requires EntityWorld)
    if (!component_registry_ready() && g_EntityWorld) {
        component_registry_init(g_EntityWorld);
    }

    // Create result table
    lua_newtable(L);

    // Iterate all components
    component_registry_iterate(dump_registry_iterator, L);

    // Also add metadata
    lua_newtable(L);
    lua_pushinteger(L, component_registry_count());
    lua_setfield(L, -2, "totalComponents");
    lua_pushboolean(L, component_registry_ready());
    lua_setfield(L, -2, "initialized");
    lua_setfield(L, -2, "_meta");

    return 1;
}

// Ext.Entity.InitComponentRegistry() -> boolean
// Initializes the component registry with the current EntityWorld
static int lua_entity_init_component_registry(lua_State *L) {
    if (!g_EntityWorld) {
        lua_pushboolean(L, 0);
        lua_pushstring(L, "EntityWorld not captured yet");
        return 2;
    }

    bool success = component_registry_init(g_EntityWorld);
    lua_pushboolean(L, success);
    return 1;
}

// Ext.Entity.SetGetRawComponentAddr(addr) -> boolean
// Sets the GetRawComponent address discovered via Frida
static int lua_entity_set_get_raw_component_addr(lua_State *L) {
    lua_Integer addr = luaL_checkinteger(L, 1);

    component_set_get_raw_component_addr((void *)addr);

    LOG_ENTITY_DEBUG("GetRawComponent address set to 0x%llx via Lua", (unsigned long long)addr);
    lua_pushboolean(L, 1);
    return 1;
}

// Ext.Entity.RegisterComponent(name, index, size) -> boolean
// Registers a component discovered via Frida
static int lua_entity_register_component(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);
    lua_Integer index = luaL_checkinteger(L, 2);
    lua_Integer size = luaL_optinteger(L, 3, 0);

    bool success = component_registry_register(name, (ComponentTypeIndex)index, (uint16_t)size, false);

    lua_pushboolean(L, success);
    return 1;
}

// Ext.Entity.LookupComponent(name) -> table or nil
// Looks up a component by name and returns its info
static int lua_entity_lookup_component(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);

    const ComponentInfo *info = component_registry_lookup(name);
    if (!info) {
        lua_pushnil(L);
        return 1;
    }

    lua_newtable(L);

    lua_pushstring(L, info->name);
    lua_setfield(L, -2, "name");

    lua_pushinteger(L, info->index);
    lua_setfield(L, -2, "typeIndex");

    lua_pushinteger(L, info->size);
    lua_setfield(L, -2, "size");

    lua_pushboolean(L, info->is_proxy);
    lua_setfield(L, -2, "isProxy");

    lua_pushboolean(L, info->is_one_frame);
    lua_setfield(L, -2, "isOneFrame");

    lua_pushboolean(L, info->discovered);
    lua_setfield(L, -2, "discovered");

    return 1;
}

// Ext.Entity.DumpStorage(entityHandle) - Test TryGet and dump storage data
// Usage: local entity = Ext.Entity.Get(guid); Ext.Entity.DumpStorage(entity:GetHandle())
static int lua_entity_dump_storage(lua_State *L) {
    uint64_t handle = (uint64_t)luaL_checkinteger(L, 1);

    if (!component_lookup_ready()) {
        lua_pushnil(L);
        lua_pushstring(L, "Component lookup not initialized");
        return 2;
    }

    LOG_ENTITY_DEBUG("=== DumpStorage for handle 0x%llx ===", (unsigned long long)handle);

    // Call TryGet to get EntityStorageData
    void *storageData = component_lookup_get_storage_data(handle);
    if (!storageData) {
        lua_pushnil(L);
        lua_pushstring(L, "TryGet returned NULL - entity not found in storage");
        return 2;
    }

    // Dump storage data
    component_lookup_dump_storage_data(storageData, handle);

    lua_pushboolean(L, true);
    lua_pushfstring(L, "StorageData at %p - see log for details", storageData);
    return 2;
}

// Ext.Entity.DiscoverTypeIds() - Discover component type indices from TypeId globals
// Usage: local result = Ext.Entity.DiscoverTypeIds()
// Returns: { success = bool, count = int, complete = bool, message = string }
static int lua_entity_discover_type_ids(lua_State *L) {
    int discovered = entity_retry_typeid_discovery();
    bool complete = entity_typeid_discovery_complete();

    lua_createtable(L, 0, 4);

    lua_pushboolean(L, discovered > 0);
    lua_setfield(L, -2, "success");

    lua_pushinteger(L, discovered);
    lua_setfield(L, -2, "count");

    lua_pushboolean(L, complete);
    lua_setfield(L, -2, "complete");

    if (complete) {
        lua_pushstring(L, "TypeId discovery complete - indices are valid");
    } else if (discovered > 0) {
        lua_pushstring(L, "Components found but indices are 0 - game may not have initialized yet");
    } else {
        lua_pushstring(L, "No components discovered - check binary base");
    }
    lua_setfield(L, -2, "message");

    return 1;
}

// Ext.Entity.DumpTypeIds() - Dump all known TypeId addresses and values
// Usage: Ext.Entity.DumpTypeIds()
static int lua_entity_dump_type_ids(lua_State *L) {
    (void)L;  // Unused

    if (!component_typeid_ready()) {
        LOG_ENTITY_DEBUG("TypeId system not ready for dump");
        return 0;
    }

    component_typeid_dump();
    return 0;
}

// Ext.Entity.DumpUuidMap(maxEntries) - Dump UUID to Handle mapping entries
// Usage: Ext.Entity.DumpUuidMap(10)  -- dumps first 10 entries
static int lua_entity_dump_uuid_map(lua_State *L) {
    int maxEntries = (int)luaL_optinteger(L, 1, 10);

    if (!g_EntityWorld) {
        LOG_ENTITY_DEBUG("DumpUuidMap: EntityWorld not available");
        lua_pushinteger(L, 0);
        return 1;
    }

    // Get the UuidToHandleMappingComponent singleton
    void *mapping = NULL;
    if (g_TryGetUuidMappingSingleton) {
        mapping = call_try_get_singleton_with_x8(g_TryGetUuidMappingSingleton, g_EntityWorld);
    }

    if (!mapping) {
        LOG_ENTITY_DEBUG("DumpUuidMap: Could not get UuidToHandleMappingComponent");
        lua_pushinteger(L, 0);
        return 1;
    }

    // The HashMap is at offset 0 in UuidToHandleMappingComponent
    HashMapGuidEntityHandle *hashmap = (HashMapGuidEntityHandle *)mapping;

    LOG_ENTITY_DEBUG("=== DumpUuidMap: First %d entries (total: %u) ===",
               maxEntries, hashmap->Keys.size);

    int count = maxEntries;
    if ((uint32_t)count > hashmap->Keys.size) count = (int)hashmap->Keys.size;

    for (int i = 0; i < count; i++) {
        Guid *key = &hashmap->Keys.buf[i];
        EntityHandle value = hashmap->Values.buf[i];

        // Convert GUID to string for comparison
        char guidStr[40];
        guid_to_string(key, guidStr);

        LOG_ENTITY_DEBUG("  [%d] %s -> 0x%llx (raw: hi=0x%llx lo=0x%llx)",
                   i, guidStr, (unsigned long long)value,
                   (unsigned long long)key->hi, (unsigned long long)key->lo);
    }

    if ((int)hashmap->Keys.size > count) {
        LOG_ENTITY_DEBUG("  ... (%u more entries)", hashmap->Keys.size - count);
    }

    lua_pushinteger(L, hashmap->Keys.size);
    return 1;
}

// Ext.Entity.GetAllEntitiesWithComponent(componentName) -> { entity1, entity2, ... }
// Returns an array of all entities that have the specified component
static int lua_entity_get_all_with_component(lua_State *L) {
    const char *componentName = luaL_checkstring(L, 1);

    if (!component_lookup_ready()) {
        lua_newtable(L);  // Return empty table
        return 1;
    }

    // Look up component type index from name
    const ComponentInfo *info = component_registry_lookup(componentName);
    if (!info) {
        // Try common aliases
        if (strcmp(componentName, "ServerCharacter") == 0) {
            info = component_registry_lookup("esv::Character");
        } else if (strcmp(componentName, "ServerItem") == 0) {
            info = component_registry_lookup("esv::Item");
        }
    }

    if (!info) {
        LOG_ENTITY_DEBUG("GetAllEntitiesWithComponent: Unknown component '%s'", componentName);
        lua_newtable(L);
        return 1;
    }

    // Get all entity handles with this component
    static uint64_t handles[65536];  // Static to avoid large stack allocation
    int count = component_lookup_get_all_with_component(info->index, handles, 65536);

    LOG_ENTITY_DEBUG("GetAllEntitiesWithComponent('%s'): Found %d entities (typeIndex=%u)",
                     componentName, count, info->index);

    // Create result table of entity userdata with lifetime scoping
    lua_createtable(L, count, 0);
    LifetimeHandle currentLifetime = lifetime_lua_get_current(L);

    for (int i = 0; i < count; i++) {
        // Push entity as userdata (same pattern as lua_entity_get)
        EntityUserdata *ud = (EntityUserdata *)lua_newuserdata(L, sizeof(EntityUserdata));
        ud->handle = handles[i];
        ud->lifetime = currentLifetime;
        luaL_getmetatable(L, "BG3Entity");
        lua_setmetatable(L, -2);
        lua_rawseti(L, -2, i + 1);
    }

    return 1;
}

// Ext.Entity.CountEntitiesWithComponent(componentName) -> number
// Returns the count of entities with the specified component (faster than GetAllEntitiesWithComponent)
static int lua_entity_count_with_component(lua_State *L) {
    const char *componentName = luaL_checkstring(L, 1);

    if (!component_lookup_ready()) {
        lua_pushinteger(L, 0);
        return 1;
    }

    const ComponentInfo *info = component_registry_lookup(componentName);
    if (!info) {
        if (strcmp(componentName, "ServerCharacter") == 0) {
            info = component_registry_lookup("esv::Character");
        } else if (strcmp(componentName, "ServerItem") == 0) {
            info = component_registry_lookup("esv::Item");
        }
    }

    if (!info) {
        lua_pushinteger(L, 0);
        return 1;
    }

    int count = component_lookup_count_with_component(info->index);
    lua_pushinteger(L, count);
    return 1;
}

void entity_register_lua(lua_State *L) {
    // Create BG3Entity metatable
    luaL_newmetatable(L, "BG3Entity");

    lua_pushcfunction(L, lua_entity_index);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, lua_entity_tostring);
    lua_setfield(L, -2, "__tostring");

    lua_pop(L, 1);  // pop metatable

    // Register component property metatables
    component_property_register_lua(L);

    // Create Ext.Entity table
    lua_getglobal(L, "Ext");
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_setglobal(L, "Ext");
        lua_getglobal(L, "Ext");
    }

    lua_newtable(L);  // Ext.Entity

    lua_pushcfunction(L, lua_entity_get);
    lua_setfield(L, -2, "Get");

    lua_pushcfunction(L, lua_entity_get_world);
    lua_setfield(L, -2, "GetWorld");

    lua_pushcfunction(L, lua_entity_is_ready);
    lua_setfield(L, -2, "IsReady");

    lua_pushcfunction(L, lua_entity_discover);
    lua_setfield(L, -2, "Discover");

    lua_pushcfunction(L, lua_entity_test);
    lua_setfield(L, -2, "Test");

    lua_pushcfunction(L, lua_entity_dump_world);
    lua_setfield(L, -2, "DumpWorld");

    lua_pushcfunction(L, lua_entity_dump_storage);
    lua_setfield(L, -2, "DumpStorage");

    // TypeId Discovery API
    lua_pushcfunction(L, lua_entity_discover_type_ids);
    lua_setfield(L, -2, "DiscoverTypeIds");

    lua_pushcfunction(L, lua_entity_dump_type_ids);
    lua_setfield(L, -2, "DumpTypeIds");

    // Component Registry API
    lua_pushcfunction(L, lua_entity_dump_component_registry);
    lua_setfield(L, -2, "DumpComponentRegistry");

    lua_pushcfunction(L, lua_entity_init_component_registry);
    lua_setfield(L, -2, "InitComponentRegistry");

    lua_pushcfunction(L, lua_entity_set_get_raw_component_addr);
    lua_setfield(L, -2, "SetGetRawComponentAddr");

    lua_pushcfunction(L, lua_entity_register_component);
    lua_setfield(L, -2, "RegisterComponent");

    lua_pushcfunction(L, lua_entity_lookup_component);
    lua_setfield(L, -2, "LookupComponent");

    lua_pushcfunction(L, lua_entity_dump_uuid_map);
    lua_setfield(L, -2, "DumpUuidMap");

    // Entity enumeration API
    lua_pushcfunction(L, lua_entity_get_all_with_component);
    lua_setfield(L, -2, "GetAllEntitiesWithComponent");

    lua_pushcfunction(L, lua_entity_count_with_component);
    lua_setfield(L, -2, "CountEntitiesWithComponent");

    lua_setfield(L, -2, "Entity");  // Ext.Entity = table

    lua_pop(L, 1);  // pop Ext

    LOG_ENTITY_DEBUG("Registered Ext.Entity API");
}
