/**
 * BG3SE-macOS - Component Registry Implementation
 *
 * Runtime component discovery and index-based component access.
 * On macOS, GetRawComponent is not available - we use direct template calls instead.
 */

#include "component_registry.h"
#include "component_templates.h"
#include "component_lookup.h"
#include "arm64_call.h"
#include "entity_system.h"
#include "../core/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

// ============================================================================
// Logging
// ============================================================================

static void log_registry(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void log_registry(const char *fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    log_message("[ComponentRegistry] %s", buf);
}

// ============================================================================
// Global State
// ============================================================================

// Component registry storage
static ComponentInfo g_Components[COMPONENT_REGISTRY_MAX_COMPONENTS];
static int g_ComponentCount = 0;

// Hash table for name lookups (simple chaining)
#define HASH_TABLE_SIZE 512
static int g_NameHashTable[HASH_TABLE_SIZE];  // Index into g_Components, -1 = empty

// Index lookup table (direct indexing by ComponentTypeIndex)
static int g_IndexLookup[65536];  // Maps ComponentTypeIndex -> g_Components index

// GetRawComponent function pointer (raw address, called via arm64_call wrapper)
static void *g_GetRawComponentAddr = NULL;

// State flags
static bool g_Initialized = false;
static void *g_EntityWorld = NULL;

// ============================================================================
// Hash Functions
// ============================================================================

static uint32_t hash_string(const char *str) {
    uint32_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;  // hash * 33 + c
    }
    return hash;
}

static int hash_bucket(const char *name) {
    return hash_string(name) % HASH_TABLE_SIZE;
}

// ============================================================================
// Forward Declarations
// ============================================================================

static void component_registry_register_known_components(void);

// ============================================================================
// Registry Initialization
// ============================================================================

bool component_registry_init(void *entityWorld) {
    if (g_Initialized) {
        log_registry("Already initialized");
        return true;
    }

    if (!entityWorld) {
        log_registry("ERROR: entityWorld is NULL");
        return false;
    }

    log_registry("Initializing component registry...");

    g_EntityWorld = entityWorld;

    // Initialize hash table to empty
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        g_NameHashTable[i] = -1;
    }

    // Initialize index lookup to empty
    for (int i = 0; i < 65536; i++) {
        g_IndexLookup[i] = -1;
    }

    g_ComponentCount = 0;

    // Pre-register known components with placeholder indices
    // These will be updated when discovered at runtime via Frida or pattern scanning
    component_registry_register_known_components();

    g_Initialized = true;
    log_registry("Initialized with %d pre-registered components", g_ComponentCount);

    return true;
}

bool component_registry_ready(void) {
    return g_Initialized && g_EntityWorld != NULL;
}

// ============================================================================
// Component Registration
// ============================================================================

bool component_registry_register(const char *name, ComponentTypeIndex index,
                                  uint16_t size, bool is_proxy) {
    if (!name) return false;

    // Check if already registered
    const ComponentInfo *existing = component_registry_lookup(name);
    if (existing) {
        // Update existing entry
        int idx = (int)(existing - g_Components);
        g_Components[idx].index = index;
        g_Components[idx].size = size;
        g_Components[idx].is_proxy = is_proxy;
        g_Components[idx].is_one_frame = component_is_one_frame(index);
        g_Components[idx].discovered = (index != COMPONENT_INDEX_UNDEFINED);

        // Update index lookup
        if (index != COMPONENT_INDEX_UNDEFINED) {
            g_IndexLookup[index] = idx;
        }

        log_registry("Updated component: %s -> index=%u, size=%u",
                     name, (unsigned)index, (unsigned)size);
        return true;
    }

    // Add new entry
    if (g_ComponentCount >= COMPONENT_REGISTRY_MAX_COMPONENTS) {
        log_registry("ERROR: Registry full, cannot add %s", name);
        return false;
    }

    int idx = g_ComponentCount++;
    ComponentInfo *info = &g_Components[idx];

    // Allocate and copy name
    size_t name_len = strlen(name);
    if (name_len >= COMPONENT_MAX_NAME_LEN) {
        name_len = COMPONENT_MAX_NAME_LEN - 1;
    }

    char *name_copy = (char *)malloc(name_len + 1);
    if (!name_copy) {
        g_ComponentCount--;
        return false;
    }
    memcpy(name_copy, name, name_len);
    name_copy[name_len] = '\0';

    info->name = name_copy;
    info->index = index;
    info->size = size;
    info->is_proxy = is_proxy;
    info->is_one_frame = component_is_one_frame(index);
    info->discovered = (index != COMPONENT_INDEX_UNDEFINED);

    // Add to hash table
    int bucket = hash_bucket(name);
    // Simple: just overwrite (collision handling would need linked list)
    g_NameHashTable[bucket] = idx;

    // Add to index lookup
    if (index != COMPONENT_INDEX_UNDEFINED) {
        g_IndexLookup[index] = idx;
    }

    log_registry("Registered component: %s -> index=%u, size=%u, proxy=%d",
                 name, (unsigned)index, (unsigned)size, is_proxy);
    return true;
}

// ============================================================================
// Pre-registration of Known Components
// ============================================================================

// Known component names from bg3se and game analysis
static void component_registry_register_known_components(void) {
    // ls:: namespace components (Larian Studios base)
    component_registry_register("ls::TransformComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("ls::LevelComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("ls::PhysicsComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("ls::VisualComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("ls::AnimationBlueprintComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("ls::BoundComponent", COMPONENT_INDEX_UNDEFINED, 0, false);

    // eoc:: namespace components (Engine of Combat - BG3 specific)
    component_registry_register("eoc::StatsComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::BaseHpComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::HealthComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::ArmorComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::ArmorClassBoostComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::ClassesComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::RaceComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::PlayerComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::CharacterComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::ItemComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::InventoryComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::InventoryContainerComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::EquipmentComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::ActionResourcesComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::SpellBookComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::SpellContainerComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::PassiveContainerComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::StatusContainerComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::UseComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::ValueComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::WeaponComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::ObjectSizeComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::BaseDataComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::DataComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::UuidComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::DisplayNameComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::IconComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::ActiveComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::SpeakerComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::OriginComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::OriginTagComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::TagComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::FactionComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::CanTravelComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::MovementComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::LockComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::KeyComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::SummonContainerComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("eoc::StealthComponent", COMPONENT_INDEX_UNDEFINED, 0, false);

    // esv:: namespace (server-side)
    component_registry_register("esv::CharacterComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("esv::ItemComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("esv::StatusComponent", COMPONENT_INDEX_UNDEFINED, 0, false);

    // ecl:: namespace (client-side)
    component_registry_register("ecl::CharacterComponent", COMPONENT_INDEX_UNDEFINED, 0, false);
    component_registry_register("ecl::ItemComponent", COMPONENT_INDEX_UNDEFINED, 0, false);

    log_registry("Pre-registered %d known component names", g_ComponentCount);
}

// ============================================================================
// Lookup Functions
// ============================================================================

const ComponentInfo *component_registry_lookup(const char *name) {
    if (!name) return NULL;

    int bucket = hash_bucket(name);
    int idx = g_NameHashTable[bucket];

    if (idx >= 0 && idx < g_ComponentCount) {
        // Verify name matches (handle hash collisions)
        if (strcmp(g_Components[idx].name, name) == 0) {
            return &g_Components[idx];
        }
    }

    // Linear search fallback for hash collisions
    for (int i = 0; i < g_ComponentCount; i++) {
        if (strcmp(g_Components[i].name, name) == 0) {
            return &g_Components[i];
        }
    }

    return NULL;
}

const ComponentInfo *component_registry_lookup_by_index(ComponentTypeIndex index) {
    if (index == COMPONENT_INDEX_UNDEFINED) return NULL;

    int idx = g_IndexLookup[index];
    if (idx >= 0 && idx < g_ComponentCount) {
        return &g_Components[idx];
    }

    return NULL;
}

int component_registry_count(void) {
    return g_ComponentCount;
}

void component_registry_iterate(ComponentIteratorFn callback, void *userdata) {
    if (!callback) return;

    for (int i = 0; i < g_ComponentCount; i++) {
        if (!callback(&g_Components[i], userdata)) {
            break;
        }
    }
}

// ============================================================================
// GetRawComponent Implementation
// ============================================================================

void *component_get_raw(void *entityWorld, uint64_t entityHandle,
                        ComponentTypeIndex typeIndex, size_t componentSize,
                        bool isProxy) {
    if (!entityWorld || typeIndex == COMPONENT_INDEX_UNDEFINED) {
        return NULL;
    }

    if (!g_GetRawComponentAddr) {
        log_registry("GetRawComponent not discovered - cannot access components");
        return NULL;
    }

    // Call the game's GetRawComponent function via ARM64 wrapper
    return call_get_raw_component(g_GetRawComponentAddr, entityWorld, entityHandle,
                                   typeIndex, componentSize, isProxy);
}

void *component_get_by_name(void *entityWorld, uint64_t entityHandle,
                            const char *componentName) {
    if (!entityWorld || !componentName) {
        return NULL;
    }

    // Strategy 1: Data structure traversal (macOS primary method)
    // This is the ONLY reliable method on macOS since template functions are inlined.
    // We traverse: EntityWorld->Storage->TryGet(handle)->HashMap lookups->component buffer
    if (component_lookup_ready()) {
        const ComponentInfo *info = component_registry_lookup(componentName);
        if (info && info->discovered && info->index != COMPONENT_INDEX_UNDEFINED) {
            log_registry("Using data structure traversal for %s (index=%u, size=%u)",
                         componentName, (unsigned)info->index, (unsigned)info->size);

            void *result = component_lookup_by_index(entityHandle, info->index,
                                                      info->size, info->is_proxy);
            if (result) {
                log_registry("Data structure lookup succeeded: %s -> %p", componentName, result);
                return result;
            }
            // Fall through to try other methods if this fails
            log_registry("Data structure lookup returned NULL for %s", componentName);
        } else {
            log_registry("Component %s not in registry (discovered=%d, index=%u)",
                         componentName, info ? info->discovered : 0,
                         info ? (unsigned)info->index : 0xFFFF);
        }
    }

    // Strategy 2: Try direct template call if we have a known address
    // Note: On macOS, template functions are inlined so this DOES NOT WORK.
    // Keeping for potential future use if we find non-inlined templates.
    uintptr_t ghidra_addr = component_template_lookup(componentName);
    if (ghidra_addr != 0) {
        void *binary_base = entity_get_binary_base();
        if (binary_base) {
            // Calculate runtime address: ghidra_addr - GHIDRA_BASE + actual_base
            uintptr_t runtime_addr = ghidra_addr - GHIDRA_BASE_ADDRESS + (uintptr_t)binary_base;

            log_registry("Trying template call (likely to fail on macOS) GetComponent<%s> at %p",
                         componentName, (void*)runtime_addr);

            void *result = call_get_component_template((void*)runtime_addr,
                                                        entityWorld, entityHandle);
            if (result) {
                log_registry("Template call succeeded (unexpected!): %s -> %p", componentName, result);
                return result;
            }
        }
    }

    // Strategy 3: Try registered component via GetRawComponent (Windows fallback)
    // On macOS this won't work since GetRawComponent doesn't exist.
    const ComponentInfo *info = component_registry_lookup(componentName);
    if (info && info->discovered) {
        void *result = component_get_raw(entityWorld, entityHandle,
                                         info->index, info->size, info->is_proxy);
        if (result) {
            log_registry("GetRawComponent succeeded: %s -> %p", componentName, result);
            return result;
        }
    }

    // Component not found via any method
    log_registry("Component not accessible: %s", componentName);
    return NULL;
}

// ============================================================================
// Discovery Functions
// ============================================================================

bool component_discover_get_raw_component(void *binaryBase) {
    if (!binaryBase) return false;

    log_registry("Attempting to discover GetRawComponent...");

    // TODO: Implement pattern scanning for GetRawComponent
    //
    // Strategy 1: Pattern scan for function signature
    // GetRawComponent takes (EntityHandle, uint16_t, size_t, bool) and returns void*
    // Look for:
    //   - Function that reads from entity storage
    //   - Checks IsOneFrame flag
    //   - Falls back to cache on miss
    //
    // Strategy 2: Hook EntityStorageData::GetComponent and trace callers
    //
    // Strategy 3: Use Frida (see tools/frida/discover_components.js)

    if (g_GetRawComponentAddr) {
        log_registry("GetRawComponent set to Frida-discovered address: %p",
                     g_GetRawComponentAddr);
        return true;
    }

    log_registry("GetRawComponent discovery not yet implemented");
    log_registry("Use Frida script to discover at runtime");
    return false;
}

bool component_discover_registry(void *entityWorld) {
    if (!entityWorld) return false;

    log_registry("Attempting to discover ComponentRegistry in EntityWorld...");

    // TODO: Implement registry discovery
    //
    // The ComponentRegistry is located within EntityWorld at some offset.
    // It contains:
    //   - Array of ComponentTypeEntry structs
    //   - Each entry has: TypeId, InlineSize, ComponentSize, Replicated, OneFrame
    //
    // Discovery approach:
    // 1. Dump EntityWorld memory at various offsets
    // 2. Look for array patterns with uint16_t TypeIds
    // 3. Validate by checking known component indices match names

    log_registry("ComponentRegistry discovery not yet implemented");
    log_registry("Use Ext.Entity.DumpWorld() to explore EntityWorld structure");
    return false;
}

void component_registry_dump(void) {
    log_registry("=== Component Registry Dump ===");
    log_registry("Total components: %d", g_ComponentCount);
    log_registry("GetRawComponent: %p", g_GetRawComponentAddr);

    int discovered = 0;
    for (int i = 0; i < g_ComponentCount; i++) {
        const ComponentInfo *info = &g_Components[i];
        if (info->discovered) {
            discovered++;
            log_registry("  [%d] %s: index=%u, size=%u, proxy=%d, oneframe=%d",
                         i, info->name, (unsigned)info->index, (unsigned)info->size,
                         info->is_proxy, info->is_one_frame);
        }
    }

    log_registry("Discovered: %d / %d components", discovered, g_ComponentCount);

    if (discovered == 0) {
        log_registry("No components discovered yet!");
        log_registry("Use Frida script or manual discovery to populate indices");
    }
}

// ============================================================================
// Frida Integration
// ============================================================================

void component_set_get_raw_component_addr(void *addr) {
    g_GetRawComponentAddr = addr;
    if (addr) {
        log_registry("GetRawComponent address set via Frida: %p", addr);
    }
}

void component_add_frida_discovery(const char *name, ComponentTypeIndex index,
                                    uint16_t size) {
    log_registry("Frida discovery: %s -> index=%u, size=%u",
                 name, (unsigned)index, (unsigned)size);

    // Update or register the component
    component_registry_register(name, index, size, false);
}
