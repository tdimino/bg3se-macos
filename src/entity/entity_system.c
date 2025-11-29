/**
 * BG3SE-macOS - Entity Component System Implementation
 *
 * This module captures the EntityWorld pointer at runtime by hooking
 * a function that receives EntityWorld& as a parameter.
 */

#include "entity_system.h"
#include "logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>

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

// eoc::CombatHelpers::LEGACY_IsInCombat(EntityHandle, EntityWorld&)
// This is called frequently during combat, gives us EntityWorld
#define OFFSET_LEGACY_IS_IN_COMBAT 0x10124f92c

// eoc::CombatHelpers::LEGACY_GetCombatFromGuid(Guid&, EntityWorld&)
#define OFFSET_LEGACY_GET_COMBAT_FROM_GUID 0x101250074

// ecs::legacy::Helper::TryGetSingleton<ls::uuid::ToHandleMappingComponent>(EntityWorld&)
// This function returns the singleton containing GUID->EntityHandle mappings
#define OFFSET_TRY_GET_UUID_MAPPING_SINGLETON 0x1010dc924

// ecs::EntityWorld::GetComponent<T> template instances
// These are direct function addresses from Ghidra analysis
#define OFFSET_GET_TRANSFORM_COMPONENT 0x10010d5b00
#define OFFSET_GET_LEVEL_COMPONENT     0x10010d588c
#define OFFSET_GET_PHYSICS_COMPONENT   0x101ba0898
#define OFFSET_GET_VISUAL_COMPONENT    0x102e56350

// Ghidra base address (macOS ARM64)
#define GHIDRA_BASE_ADDRESS 0x100000000

// ============================================================================
// Component Accessor Function Types
// ============================================================================

// GetComponent signature: void* GetComponent(EntityWorld*, EntityHandle)
typedef void* (*GetComponentFn)(void *entityWorld, uint64_t handle);

// Function pointers for each component type (initialized in entity_system_init)
static GetComponentFn g_GetTransformComponent = NULL;
static GetComponentFn g_GetLevelComponent = NULL;
static GetComponentFn g_GetPhysicsComponent = NULL;
static GetComponentFn g_GetVisualComponent = NULL;

// ============================================================================
// HashMap Memory Layout (from Windows BG3SE reference)
// ============================================================================

// StaticArray<T> layout (16 bytes on 64-bit):
//   offset 0x00: T* buf_ (8 bytes)
//   offset 0x08: uint32_t size_ (4 bytes)
//   offset 0x0C: padding (4 bytes)

// Array<T> layout (16 bytes on 64-bit):
//   offset 0x00: T* buf_ (8 bytes)
//   offset 0x08: uint32_t capacity_ (4 bytes)
//   offset 0x0C: uint32_t size_ (4 bytes)

// HashMap<Guid, EntityHandle> layout (64 bytes total):
//   offset 0x00: StaticArray<int32_t> HashKeys   (bucket table)
//   offset 0x10: Array<int32_t> NextIds          (collision chain)
//   offset 0x20: Array<Guid> Keys                (key storage)
//   offset 0x30: UninitializedStaticArray<EntityHandle> Values

typedef struct {
    int32_t *buf;
    uint32_t size;
    uint32_t _pad;
} StaticArrayInt32;

typedef struct {
    int32_t *buf;
    uint32_t capacity;
    uint32_t size;
} ArrayInt32;

typedef struct {
    Guid *buf;
    uint32_t capacity;
    uint32_t size;
} ArrayGuid;

typedef struct {
    EntityHandle *buf;
    uint32_t size;
    uint32_t _pad;
} StaticArrayEntityHandle;

// HashMap<Guid, EntityHandle> structure
typedef struct {
    StaticArrayInt32 HashKeys;         // offset 0x00
    ArrayInt32 NextIds;                // offset 0x10
    ArrayGuid Keys;                    // offset 0x20
    StaticArrayEntityHandle Values;    // offset 0x30
} HashMapGuidEntityHandle;

// UuidToHandleMappingComponent contains HashMap<Guid, EntityHandle> Mappings
// The Mappings field is at offset 0 (first field after vtable if any)
// Note: May need adjustment if there's a vtable pointer
typedef struct {
    HashMapGuidEntityHandle Mappings;
} UuidToHandleMappingComponent;

// TryGetSingleton returns a ls::Result<ComponentPtr, ls::Error>
// In practice, this appears to return the component pointer directly
// or NULL on failure (based on ARM64 calling convention)
typedef void* (*TryGetSingletonFn)(void *entityWorld);
static TryGetSingletonFn g_TryGetUuidMappingSingleton = NULL;

// Cached pointer to the UUID mapping component
static void *g_UuidMappingComponent = NULL;

// ============================================================================
// Original Function Pointers
// ============================================================================

typedef bool (*IsInCombatFn)(uint64_t handle, void *entityWorld);
static IsInCombatFn orig_IsInCombat = NULL;

// ============================================================================
// Hook: Capture EntityWorld Pointer
// ============================================================================

static bool hook_IsInCombat(uint64_t handle, void *entityWorld) {
    // Capture EntityWorld on first call
    if (!g_EntityWorld && entityWorld) {
        g_EntityWorld = entityWorld;
        log_entity("Captured EntityWorld pointer: %p", entityWorld);
    }

    // Call original function
    if (orig_IsInCombat) {
        return orig_IsInCombat(handle, entityWorld);
    }
    return false;
}

// ============================================================================
// GUID Parsing
// ============================================================================

bool guid_parse(const char *str, Guid *out) {
    if (!str || !out) return false;

    // Format: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    // Total length: 36 characters
    if (strlen(str) != 36) return false;

    // Parse as two 64-bit values
    // First 16 hex chars (with dashes) = high
    // Last 20 hex chars (with dashes) = low

    uint32_t a;
    uint16_t b, c, d;
    uint64_t e;

    if (sscanf(str, "%08x-%04hx-%04hx-%04hx-%012llx",
               &a, &b, &c, &d, &e) != 5) {
        return false;
    }

    // Pack into Guid structure
    // Note: Byte order matches Windows BG3SE
    out->hi = ((uint64_t)a << 32) | ((uint64_t)b << 16) | c;
    out->lo = ((uint64_t)d << 48) | e;

    return true;
}

void guid_to_string(const Guid *guid, char *out) {
    if (!guid || !out) return;

    uint32_t a = (uint32_t)(guid->hi >> 32);
    uint16_t b = (uint16_t)((guid->hi >> 16) & 0xFFFF);
    uint16_t c = (uint16_t)(guid->hi & 0xFFFF);
    uint16_t d = (uint16_t)(guid->lo >> 48);
    uint64_t e = guid->lo & 0xFFFFFFFFFFFFULL;

    snprintf(out, 37, "%08x-%04hx-%04hx-%04hx-%012llx",
             a, b, c, d, e);
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
        // Attempt to get the singleton component
        // Note: TryGetSingleton returns ls::Result which may need unpacking
        g_UuidMappingComponent = g_TryGetUuidMappingSingleton(g_EntityWorld);
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

        // Validate HashMap structure
        if (!hashmap->HashKeys.buf || hashmap->HashKeys.size == 0) {
            log_entity("HashMap not initialized (HashKeys.buf=%p, size=%u)",
                       (void*)hashmap->HashKeys.buf, hashmap->HashKeys.size);
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

        // Not yet implemented - need to find GetComponent addresses
        case COMPONENT_STATS:
        case COMPONENT_BASE_HP:
        case COMPONENT_HEALTH:
        case COMPONENT_ARMOR:
        case COMPONENT_CLASSES:
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

    uintptr_t is_in_combat_addr = OFFSET_LEGACY_IS_IN_COMBAT - ghidra_base + actual_base;

    log_entity("Installing hook at IsInCombat: %p", (void*)is_in_combat_addr);

    // Install Dobby hook
    int result = DobbyHook(
        (void*)is_in_combat_addr,
        (void*)hook_IsInCombat,
        (void**)&orig_IsInCombat
    );

    if (result != 0) {
        log_entity("ERROR: Failed to install IsInCombat hook (result: %d)", result);
        return -1;
    }

    log_entity("Hook installed successfully");

    // Set up function pointers for component accessors and singleton getters
    // These don't need hooks - we just need to know where to call
    g_TryGetUuidMappingSingleton = (TryGetSingletonFn)(OFFSET_TRY_GET_UUID_MAPPING_SINGLETON - ghidra_base + actual_base);
    g_GetTransformComponent = (GetComponentFn)(OFFSET_GET_TRANSFORM_COMPONENT - ghidra_base + actual_base);
    g_GetLevelComponent = (GetComponentFn)(OFFSET_GET_LEVEL_COMPONENT - ghidra_base + actual_base);
    g_GetPhysicsComponent = (GetComponentFn)(OFFSET_GET_PHYSICS_COMPONENT - ghidra_base + actual_base);
    g_GetVisualComponent = (GetComponentFn)(OFFSET_GET_VISUAL_COMPONENT - ghidra_base + actual_base);

    log_entity("Function pointers initialized:");
    log_entity("  TryGetUuidMappingSingleton: %p", (void*)g_TryGetUuidMappingSingleton);
    log_entity("  GetTransformComponent: %p", (void*)g_GetTransformComponent);
    log_entity("  GetLevelComponent: %p", (void*)g_GetLevelComponent);

    g_Initialized = true;

    return 0;
}

bool entity_system_ready(void) {
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

    lua_setfield(L, -2, "Entity");  // Ext.Entity = table

    lua_pop(L, 1);  // pop Ext

    log_entity("Registered Ext.Entity API");
}
