/**
 * BG3SE-macOS - Entity Component System Implementation
 *
 * This module captures the EntityWorld pointer at runtime by hooking
 * a function that receives EntityWorld& as a parameter.
 */

#include "entity_system.h"
#include "arm64_call.h"
#include "logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
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

// Logging helper for entity module
static void log_entity(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void log_entity(const char *fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    log_message("[Entity] %s", buf);
}

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

// Ghidra base address (macOS ARM64)
#define GHIDRA_BASE_ADDRESS 0x100000000

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
// TryGetSingleton Function Pointer
// ============================================================================

// Raw function type - do NOT call directly, use call_try_get_singleton_with_x8()
// from arm64_call.h module
typedef void (*TryGetSingletonRawFn)(void *entityWorld);
static TryGetSingletonRawFn g_TryGetUuidMappingSingleton = NULL;

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
        log_entity("Not a 64-bit Mach-O binary");
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
                log_entity("Found %s segment: 0x%llx - 0x%llx (size: 0x%llx)",
                           seg->segname, (unsigned long long)*start,
                           (unsigned long long)*end, (unsigned long long)seg->vmsize);
                return true;
            }
        }

        ptr += cmd->cmdsize;
    }

    log_entity("__DATA segment not found");
    return false;
}

// Scan memory to find EoCServer singleton pointer
// Strategy: Look for a global pointer that, when dereferenced,
// contains a pointer at offset 0x288 (EntityWorld)
static void *scan_for_eocserver_singleton(void) {
    if (!g_MainBinaryBase) {
        log_entity("Cannot scan: main binary base not set");
        return NULL;
    }

    log_entity("=== Scanning for EoCServer Singleton ===");

    // Get __DATA segment bounds
    uintptr_t data_start = 0, data_end = 0;
    if (!get_data_segment_bounds(g_MainBinaryBase, &data_start, &data_end)) {
        log_entity("Failed to get __DATA segment bounds");
        return NULL;
    }

    // Also check __DATA_CONST and other data segments
    // For now, scan a reasonable range around the main binary
    uintptr_t scan_start = data_start;
    uintptr_t scan_end = data_end;

    log_entity("Scanning range: 0x%llx - 0x%llx",
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

        log_entity("CANDIDATE FOUND at global 0x%llx:", (unsigned long long)addr);
        log_entity("  EoCServer*: %p", potential_eocserver);
        log_entity("  EntityWorld* (at +0x288): %p", potential_entityworld);

        // This looks promising! Return it
        return potential_eocserver;
    }

    log_entity("Scan complete: checked %d candidates, %d had valid pointers, none matched pattern",
               candidates_checked, valid_candidates);

    return NULL;
}

// Alternative: Scan using known function patterns (ARM64 ADRP/LDR)
// This looks for the instruction pattern that loads EoCServer from a global
static void *scan_for_eocserver_via_instructions(void) {
    if (!g_MainBinaryBase) return NULL;

    log_entity("=== Scanning via instruction patterns ===");

    // The StartUp function at known offset loads EoCServer
    // We can look at functions that access EoCServer+0x288 (EntityWorld)
    // Pattern: ADRP Xn, page; LDR Xn, [Xn, #offset]

    uintptr_t ghidra_base = GHIDRA_BASE_ADDRESS;
    uintptr_t actual_base = (uintptr_t)g_MainBinaryBase;

    // Address of a function we know accesses EoCServer
    // esv::EocServer::GetEntityWorld would be ideal, but we'll use StartUp
    uintptr_t startup_addr = OFFSET_EOC_SERVER_STARTUP - ghidra_base + actual_base;

    log_entity("Analyzing function at 0x%llx for EoCServer global reference",
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

                        log_entity("Found ADRP+LDR pattern at instruction %d:", i);
                        log_entity("  Page: 0x%llx, Offset: 0x%x",
                                   (unsigned long long)page_addr, imm12);
                        log_entity("  Global address: 0x%llx", (unsigned long long)global_addr);

                        // Try to read from this global
                        if (is_valid_pointer((void *)global_addr)) {
                            void *potential_eocserver = *(void **)global_addr;
                            log_entity("  Value at global: %p", potential_eocserver);

                            if (is_valid_pointer(potential_eocserver)) {
                                // Check offset 0x288
                                void *potential_ew = *(void **)((char *)potential_eocserver + 0x288);
                                log_entity("  Value at +0x288: %p", potential_ew);

                                if (is_valid_pointer(potential_ew)) {
                                    log_entity("  SUCCESS: Found EoCServer singleton!");
                                    return potential_eocserver;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    log_entity("No EoCServer reference found via instruction analysis");
    return NULL;
}

// Direct memory read from known global address (primary method)
// This is the simplest and most reliable approach now that we have the exact address
static void *read_eocserver_from_global(void) {
    if (!g_MainBinaryBase) {
        log_entity("Cannot read EoCServer: main binary base not set");
        return NULL;
    }

    // Calculate runtime address of esv::EocServer::m_ptr
    uintptr_t ghidra_base = GHIDRA_BASE_ADDRESS;
    uintptr_t actual_base = (uintptr_t)g_MainBinaryBase;
    uintptr_t global_addr = OFFSET_EOCSERVER_SINGLETON_PTR - ghidra_base + actual_base;

    log_entity("Reading EoCServer from global at 0x%llx", (unsigned long long)global_addr);
    log_entity("  (Ghidra offset: 0x%llx, base: %p)",
               (unsigned long long)OFFSET_EOCSERVER_SINGLETON_PTR, g_MainBinaryBase);

    // Safely read the pointer using vm_read
    vm_size_t data_size = sizeof(void*);
    vm_offset_t data;
    kern_return_t kr = vm_read(mach_task_self(), (vm_address_t)global_addr,
                               data_size, &data, (mach_msg_type_number_t*)&data_size);

    if (kr != KERN_SUCCESS) {
        log_entity("Failed to read EoCServer global (kern_return: %d)", kr);
        return NULL;
    }

    void *eocserver = *(void **)data;
    vm_deallocate(mach_task_self(), data, data_size);

    if (!eocserver) {
        log_entity("EoCServer global is NULL (server not yet initialized)");
        return NULL;
    }

    log_entity("Read EoCServer pointer: %p", eocserver);

    // Validate the pointer
    if (!is_valid_pointer(eocserver)) {
        log_entity("EoCServer pointer appears invalid");
        return NULL;
    }

    return eocserver;
}

// Public function: Try to discover EntityWorld
bool entity_discover_world(void) {
    if (g_EntityWorld) {
        log_entity("EntityWorld already discovered: %p", g_EntityWorld);
        return true;
    }

    log_entity("Attempting to discover EntityWorld...");

    // Method 1 (PRIMARY): Direct read from known global address
    // This is the most reliable method using the address discovered via Ghidra:
    // esv::EocServer::m_ptr at 0x10898e8b8
    void *eocserver = read_eocserver_from_global();

    // Method 2 (FALLBACK): Try instruction pattern analysis
    if (!eocserver) {
        log_entity("Direct read failed, trying instruction pattern analysis...");
        eocserver = scan_for_eocserver_via_instructions();
    }

    // Method 3 (FALLBACK): Data segment scan
    if (!eocserver) {
        log_entity("Pattern analysis failed, trying data segment scan...");
        eocserver = scan_for_eocserver_singleton();
    }

    if (eocserver) {
        g_EoCServer = eocserver;

        // Read EntityWorld from offset 0x288
        void *entityworld = *(void **)((char *)eocserver + OFFSET_ENTITYWORLD_IN_EOCSERVER);

        if (entityworld && is_valid_pointer(entityworld)) {
            g_EntityWorld = entityworld;
            log_entity("SUCCESS: Discovered EoCServer=%p, EntityWorld=%p",
                       g_EoCServer, g_EntityWorld);
            return true;
        } else {
            log_entity("Found EoCServer but EntityWorld at +0x288 is NULL or invalid");
            log_entity("(Server may not be fully initialized yet)");
        }
    }

    log_entity("Failed to discover EntityWorld");
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

static void hook_EocServerStartUp(void *eocServer, void *serverInit) {
    // Capture EoCServer pointer (this) on first call
    if (!g_EoCServer && eocServer) {
        g_EoCServer = eocServer;
        log_entity("Captured EoCServer singleton: %p", eocServer);

        // Get EntityWorld from EoCServer + 0x288
        void **entityWorldPtr = (void**)((char*)eocServer + OFFSET_ENTITYWORLD_IN_EOCSERVER);
        g_EntityWorld = *entityWorldPtr;

        if (g_EntityWorld) {
            log_entity("Got EntityWorld from EoCServer+0x%x: %p",
                       OFFSET_ENTITYWORLD_IN_EOCSERVER, g_EntityWorld);
        } else {
            log_entity("EntityWorld at EoCServer+0x%x is NULL (not yet initialized)",
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
            log_entity("Got EntityWorld after StartUp: %p", g_EntityWorld);
        } else {
            log_entity("EntityWorld still NULL after StartUp");
        }
    }
}

// Helper: Update EntityWorld from stored EoCServer
static void update_entity_world_from_server(void) {
    if (g_EoCServer && !g_EntityWorld) {
        void **entityWorldPtr = (void**)((char*)g_EoCServer + OFFSET_ENTITYWORLD_IN_EOCSERVER);
        if (entityWorldPtr && *entityWorldPtr) {
            g_EntityWorld = *entityWorldPtr;
            log_entity("Updated EntityWorld from EoCServer: %p", g_EntityWorld);
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

    // Check cache first
    for (int i = 0; i < g_GuidCacheCount; i++) {
        if (strcmp(g_GuidCache[i].guid, guid_str) == 0) {
            return g_GuidCache[i].handle;
        }
    }

    // Try to get UUID mapping singleton if not cached
    if (!g_UuidMappingComponent && g_TryGetUuidMappingSingleton && g_EntityWorld) {
        // TryGetSingleton returns ls::Result<T,E> via x8 buffer (ARM64 ABI)
        // Use wrapper that properly sets x8 to the result buffer address
        log_entity("Calling TryGetSingleton with x8 ABI wrapper...");
        g_UuidMappingComponent = call_try_get_singleton_with_x8(
            (void*)g_TryGetUuidMappingSingleton, g_EntityWorld);
        if (g_UuidMappingComponent) {
            log_entity("Got UuidToHandleMappingComponent: %p", g_UuidMappingComponent);
        } else {
            log_entity("Failed to get UuidToHandleMappingComponent");
        }
    }

    if (g_UuidMappingComponent) {
        // Parse the GUID
        Guid guid;
        if (!guid_parse(guid_str, &guid)) {
            log_entity("Failed to parse GUID: %s", guid_str);
            return ENTITY_HANDLE_INVALID;
        }

        // Cast to our structure
        UuidToHandleMappingComponent *mapping = (UuidToHandleMappingComponent*)g_UuidMappingComponent;
        HashMapGuidEntityHandle *hashmap = &mapping->Mappings;

        // Debug: dump raw bytes at component pointer
        static bool dumped = false;
        if (!dumped) {
            dumped = true;
            log_entity("=== UuidToHandleMappingComponent raw dump ===");
            log_entity("Component ptr: %p", g_UuidMappingComponent);
            uint8_t *bytes = (uint8_t*)g_UuidMappingComponent;
            for (int i = 0; i < 128; i += 8) {
                log_entity("  +0x%02x: %02x %02x %02x %02x %02x %02x %02x %02x",
                           i, bytes[i], bytes[i+1], bytes[i+2], bytes[i+3],
                           bytes[i+4], bytes[i+5], bytes[i+6], bytes[i+7]);
            }
            log_entity("=== HashMap field values ===");
            log_entity("  HashKeys.buf: %p, size: %u", (void*)hashmap->HashKeys.buf, hashmap->HashKeys.size);
            log_entity("  NextIds.buf: %p, cap: %u, size: %u", (void*)hashmap->NextIds.buf, hashmap->NextIds.capacity, hashmap->NextIds.size);
            log_entity("  Keys.buf: %p, cap: %u, size: %u", (void*)hashmap->Keys.buf, hashmap->Keys.capacity, hashmap->Keys.size);
            log_entity("  Values.buf: %p, size: %u", (void*)hashmap->Values.buf, hashmap->Values.size);

            // Dump first few keys if available
            if (hashmap->Keys.buf && hashmap->Keys.size > 0) {
                int dump_count = hashmap->Keys.size < 5 ? hashmap->Keys.size : 5;
                log_entity("  First %d keys:", dump_count);
                for (int i = 0; i < dump_count; i++) {
                    char guid_str_buf[64];
                    guid_to_string(&hashmap->Keys.buf[i], guid_str_buf);
                    log_entity("    [%d] %s (hi=0x%llx, lo=0x%llx)", i, guid_str_buf,
                               (unsigned long long)hashmap->Keys.buf[i].hi,
                               (unsigned long long)hashmap->Keys.buf[i].lo);
                }
            }
        }

        // Validate HashMap structure
        if (!hashmap->HashKeys.buf || hashmap->HashKeys.size == 0) {
            log_entity("HashMap not initialized (HashKeys.buf=%p, size=%u)",
                       (void*)hashmap->HashKeys.buf, hashmap->HashKeys.size);
            return ENTITY_HANDLE_INVALID;
        }

        // Debug: show parsed GUID
        log_entity("Looking up GUID: %s (hi=0x%llx, lo=0x%llx)", guid_str,
                   (unsigned long long)guid.hi, (unsigned long long)guid.lo);

        // Hash the GUID: hash = lo ^ hi
        uint64_t hash = guid.lo ^ guid.hi;
        uint32_t bucket = (uint32_t)(hash % hashmap->HashKeys.size);

        // Look up in hash table
        int32_t keyIndex = hashmap->HashKeys.buf[bucket];

        while (keyIndex >= 0) {
            // Bounds check
            if ((uint32_t)keyIndex >= hashmap->Keys.size) {
                log_entity("HashMap corruption: keyIndex %d >= Keys.size %u",
                           keyIndex, hashmap->Keys.size);
                break;
            }

            // Compare GUID
            Guid *key = &hashmap->Keys.buf[keyIndex];
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

                log_entity("GUID lookup success: %s -> 0x%llx", guid_str, (unsigned long long)handle);
                return handle;
            }

            // Follow collision chain
            if ((uint32_t)keyIndex >= hashmap->NextIds.size) {
                log_entity("HashMap corruption: NextIds index out of bounds");
                break;
            }
            keyIndex = hashmap->NextIds.buf[keyIndex];
        }

        log_entity("GUID not found in mapping: %s", guid_str);
    }

    return ENTITY_HANDLE_INVALID;
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

    void *component = NULL;

    switch (type) {
        case COMPONENT_TRANSFORM:
            if (g_GetTransformComponent) {
                component = g_GetTransformComponent(g_EntityWorld, handle);
            }
            break;

        case COMPONENT_LEVEL:
            if (g_GetLevelComponent) {
                component = g_GetLevelComponent(g_EntityWorld, handle);
            }
            break;

        case COMPONENT_PHYSICS:
            if (g_GetPhysicsComponent) {
                component = g_GetPhysicsComponent(g_EntityWorld, handle);
            }
            break;

        case COMPONENT_VISUAL:
            if (g_GetVisualComponent) {
                component = g_GetVisualComponent(g_EntityWorld, handle);
            }
            break;

        // eoc:: components - function pointers set when addresses discovered
        case COMPONENT_STATS:
            if (g_GetStatsComponent) {
                component = g_GetStatsComponent(g_EntityWorld, handle);
            } else {
                log_entity("GetComponent<Stats> address not yet discovered");
            }
            break;

        case COMPONENT_BASE_HP:
            if (g_GetBaseHpComponent) {
                component = g_GetBaseHpComponent(g_EntityWorld, handle);
            } else {
                log_entity("GetComponent<BaseHp> address not yet discovered");
            }
            break;

        case COMPONENT_HEALTH:
            if (g_GetHealthComponent) {
                component = g_GetHealthComponent(g_EntityWorld, handle);
            } else {
                log_entity("GetComponent<Health> address not yet discovered");
            }
            break;

        case COMPONENT_ARMOR:
            if (g_GetArmorComponent) {
                component = g_GetArmorComponent(g_EntityWorld, handle);
            } else {
                log_entity("GetComponent<Armor> address not yet discovered");
            }
            break;

        case COMPONENT_CLASSES:
            if (g_GetClassesComponent) {
                component = g_GetClassesComponent(g_EntityWorld, handle);
            } else {
                log_entity("GetComponent<Classes> address not yet discovered");
            }
            break;

        case COMPONENT_RACE:
        case COMPONENT_PLAYER:
            log_entity("GetComponent for type %d not yet implemented", type);
            break;

        default:
            log_entity("Unknown component type: %d", type);
            break;
    }

    if (component) {
        log_entity("Got component type %d for handle 0x%llx: %p",
                   type, (unsigned long long)handle, component);
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
        log_entity("Already initialized");
        return 0;
    }

    if (!main_binary_base) {
        log_entity("ERROR: main_binary_base is NULL");
        return -1;
    }

    g_MainBinaryBase = main_binary_base;
    log_entity("Initializing with main binary base: %p", main_binary_base);

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
    log_entity("Main binary hooks disabled (macOS memory protection issues)");
    log_entity("EntityWorld must be set manually via Ext.Entity.SetWorldPtr() or discovered via Osiris hooks");

    // Set up function pointers for component accessors and singleton getters
    // These don't need hooks - we just need to know where to call
    g_TryGetUuidMappingSingleton = (TryGetSingletonRawFn)(OFFSET_TRY_GET_UUID_MAPPING_SINGLETON - ghidra_base + actual_base);

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

    log_entity("Function pointers initialized:");
    log_entity("  TryGetUuidMappingSingleton: %p", (void*)g_TryGetUuidMappingSingleton);
    log_entity("  GetTransformComponent: %p", (void*)g_GetTransformComponent);
    log_entity("  GetLevelComponent: %p", (void*)g_GetLevelComponent);
    log_entity("  GetStatsComponent: %p", (void*)g_GetStatsComponent);
    log_entity("  GetBaseHpComponent: %p", (void*)g_GetBaseHpComponent);
    log_entity("  GetHealthComponent: %p", (void*)g_GetHealthComponent);
    log_entity("  GetArmorComponent: %p", (void*)g_GetArmorComponent);

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

    // Create entity userdata
    EntityHandle *ud = (EntityHandle*)lua_newuserdata(L, sizeof(EntityHandle));
    *ud = handle;

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

    log_entity("=== EntityWorld Memory Dump ===");
    log_entity("EntityWorld base: %p", g_EntityWorld);
    log_entity("Dumping offset 0x%x, size %d bytes:", offset, size);

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
        log_entity("%s", line);
    }

    // Also log potential pointer values at 8-byte intervals
    log_entity("Potential pointers:");
    for (int i = 0; i < size && i + 8 <= size; i += 8) {
        void *ptr = *(void **)(base + offset + i);
        // Check if it looks like a valid pointer (in reasonable address range)
        uintptr_t val = (uintptr_t)ptr;
        if (val > 0x100000000ULL && val < 0x200000000ULL) {
            log_entity("  +0x%03x: %p (valid pointer)", offset + i, ptr);
        }
    }

    lua_pushstring(L, dump);
    return 1;
}

// Ext.Entity.Test() - Test component accessors with known GUIDs
static int lua_entity_test(lua_State *L) {
    log_entity("=== Entity Component Test ===");

    if (!entity_system_ready()) {
        log_entity("Entity system not ready - enter combat first");
        lua_pushboolean(L, 0);
        return 1;
    }

    log_entity("EntityWorld: %p", g_EntityWorld);

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
        log_entity("Testing GUID: %s", guid);

        EntityHandle handle = entity_get_by_guid(guid);
        if (!entity_is_valid(handle)) {
            log_entity("  Entity not found");
            continue;
        }

        log_entity("  Handle: 0x%llx", (unsigned long long)handle);

        // Test Transform (ls:: component)
        void *transform = entity_get_component(handle, COMPONENT_TRANSFORM);
        log_entity("  Transform: %s", transform ? "FOUND" : "nil");

        // Test Stats (eoc:: component)
        void *stats = entity_get_component(handle, COMPONENT_STATS);
        log_entity("  Stats: %s", stats ? "FOUND" : "nil");

        // Test Health (eoc:: component)
        void *health = entity_get_component(handle, COMPONENT_HEALTH);
        log_entity("  Health: %s", health ? "FOUND" : "nil");

        // Test BaseHp (eoc:: component)
        void *basehp = entity_get_component(handle, COMPONENT_BASE_HP);
        log_entity("  BaseHp: %s", basehp ? "FOUND" : "nil");

        // Test Armor (eoc:: component)
        void *armor = entity_get_component(handle, COMPONENT_ARMOR);
        log_entity("  Armor: %s", armor ? "FOUND" : "nil");

        if (transform || stats || health) {
            success_count++;
        }
    }

    log_entity("=== Test Complete: %d entities with components ===", success_count);

    lua_pushboolean(L, success_count > 0);
    return 1;
}

// Entity:IsAlive() method
static int lua_entity_is_alive(lua_State *L) {
    EntityHandle *ud = (EntityHandle*)luaL_checkudata(L, 1, "BG3Entity");
    lua_pushboolean(L, entity_is_alive(*ud));
    return 1;
}

// Entity:GetHandle() method - returns raw handle for debugging
static int lua_entity_get_handle(lua_State *L) {
    EntityHandle *ud = (EntityHandle*)luaL_checkudata(L, 1, "BG3Entity");
    lua_pushinteger(L, (lua_Integer)*ud);
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
static int lua_entity_get_component(lua_State *L) {
    EntityHandle *ud = (EntityHandle*)luaL_checkudata(L, 1, "BG3Entity");
    const char *name = luaL_checkstring(L, 2);

    ComponentType type;
    bool found = true;

    // Map component name to type
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
    } else {
        found = false;
    }

    if (!found) {
        lua_pushnil(L);
        lua_pushfstring(L, "Unknown component: %s", name);
        return 2;
    }

    void *component = entity_get_component(*ud, type);
    if (!component) {
        lua_pushnil(L);
        return 1;
    }

    // Convert component to Lua table based on type
    switch (type) {
        case COMPONENT_TRANSFORM:
            push_transform_component(L, component);
            break;

        // For components without full struct definitions, return light userdata
        default:
            lua_pushlightuserdata(L, component);
            break;
    }

    return 1;
}

// Entity metatable __index
static int lua_entity_index(lua_State *L) {
    EntityHandle *ud = (EntityHandle*)luaL_checkudata(L, 1, "BG3Entity");
    const char *key = luaL_checkstring(L, 2);

    // Check for methods first
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
    } else {
        is_component = false;
    }

    if (is_component) {
        void *component = entity_get_component(*ud, type);
        if (!component) {
            lua_pushnil(L);
            return 1;
        }

        // Convert component to Lua based on type
        switch (type) {
            case COMPONENT_TRANSFORM:
                push_transform_component(L, component);
                break;
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
    EntityHandle *ud = (EntityHandle*)luaL_checkudata(L, 1, "BG3Entity");
    lua_pushfstring(L, "Entity(0x%llx)", (unsigned long long)*ud);
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

    lua_setfield(L, -2, "Entity");  // Ext.Entity = table

    lua_pop(L, 1);  // pop Ext

    log_entity("Registered Ext.Entity API");
}
