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

// ecs::EntityWorld::GetComponent<ls::TransformComponent>
#define OFFSET_GET_TRANSFORM_COMPONENT 0x10010d5b00

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

    // TODO: Implement actual GUID lookup via ToHandleMappingComponent
    // For now, return invalid - will implement once we have EntityWorld access

    log_entity("GUID lookup not yet implemented: %s", guid_str);
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
    (void)type;  // Suppress unused parameter warning until implemented

    if (!entity_is_valid(handle) || !g_EntityWorld) {
        return NULL;
    }

    // TODO: Call GetComponent with proper type index
    // This requires knowing the component type → function address mapping

    return NULL;
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

// Entity metatable __index
static int lua_entity_index(lua_State *L) {
    // Validate this is a BG3Entity userdata (will throw if not)
    (void)luaL_checkudata(L, 1, "BG3Entity");
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

    // TODO: Try to get component by name
    // e.g., entity.Stats, entity.Transform, etc.

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
