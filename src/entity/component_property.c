/**
 * BG3SE-macOS - Component Property Access Implementation
 *
 * Provides safe, data-driven property access for ECS components.
 */

#include "component_property.h"
#include "component_offsets.h"
#include "../core/safe_memory.h"
#include "../core/logging.h"
#include "../lifetime/lifetime.h"

#include <string.h>
#include <stdlib.h>

// Lua headers
#include "../../lib/lua/src/lua.h"
#include "../../lib/lua/src/lauxlib.h"
#include "../../lib/lua/src/lualib.h"

// ============================================================================
// Constants
// ============================================================================

#define MAX_COMPONENT_LAYOUTS 128
#define COMPONENT_PROXY_METATABLE "bg3se.ComponentProxy"
#define ARRAY_PROXY_METATABLE "bg3se.ArrayProxy"

// Array<T> memory layout on ARM64
#define ARRAY_BUF_OFFSET    0x00   // T* buf_
#define ARRAY_CAP_OFFSET    0x08   // uint32_t capacity_
#define ARRAY_SIZE_OFFSET   0x0C   // uint32_t size_

// ============================================================================
// Global State
// ============================================================================

static ComponentLayoutDef g_Layouts[MAX_COMPONENT_LAYOUTS];
static int g_LayoutCount = 0;
static bool g_Initialized = false;

// ============================================================================
// Initialization
// ============================================================================

bool component_property_init(void) {
    if (g_Initialized) return true;

    g_LayoutCount = 0;

    // Register built-in layouts from component_offsets.h
    for (int i = 0; g_AllComponentLayouts[i] != NULL; i++) {
        if (!component_property_register_layout(g_AllComponentLayouts[i])) {
            LOG_ENTITY_DEBUG("Failed to register layout: %s",
                           g_AllComponentLayouts[i]->componentName);
        }
    }

    g_Initialized = true;
    LOG_ENTITY_DEBUG("Component property system initialized with %d layouts", g_LayoutCount);
    return true;
}

// ============================================================================
// Layout Registration & Lookup
// ============================================================================

bool component_property_register_layout(const ComponentLayoutDef *layout) {
    if (!layout || !layout->componentName) return false;
    if (g_LayoutCount >= MAX_COMPONENT_LAYOUTS) {
        LOG_ENTITY_DEBUG("Component layout registry full");
        return false;
    }

    // Copy layout
    g_Layouts[g_LayoutCount] = *layout;
    g_LayoutCount++;

    LOG_ENTITY_DEBUG("Registered component layout: %s (%s) with %d properties",
                   layout->componentName, layout->shortName, layout->propertyCount);
    return true;
}

const ComponentLayoutDef *component_property_get_layout(const char *componentName) {
    if (!componentName) return NULL;

    for (int i = 0; i < g_LayoutCount; i++) {
        if (strcmp(g_Layouts[i].componentName, componentName) == 0) {
            return &g_Layouts[i];
        }
    }
    return NULL;
}

const ComponentLayoutDef *component_property_get_layout_by_short_name(const char *shortName) {
    if (!shortName) return NULL;

    for (int i = 0; i < g_LayoutCount; i++) {
        if (g_Layouts[i].shortName &&
            strcmp(g_Layouts[i].shortName, shortName) == 0) {
            return &g_Layouts[i];
        }
    }
    return NULL;
}

const ComponentLayoutDef *component_property_get_layout_by_index(uint16_t typeIndex) {
    if (typeIndex == 0) return NULL;

    for (int i = 0; i < g_LayoutCount; i++) {
        if (g_Layouts[i].componentTypeIndex == typeIndex) {
            return &g_Layouts[i];
        }
    }
    return NULL;
}

void component_property_set_type_index(const char *componentName, uint16_t typeIndex) {
    if (!componentName) return;

    for (int i = 0; i < g_LayoutCount; i++) {
        if (strcmp(g_Layouts[i].componentName, componentName) == 0) {
            g_Layouts[i].componentTypeIndex = typeIndex;
            LOG_ENTITY_DEBUG("Set TypeIndex for %s: %u",
                           componentName, typeIndex);
            return;
        }
    }
}

// ============================================================================
// Property Reading - Helper Functions
// ============================================================================

static const ComponentPropertyDef *find_property(const ComponentLayoutDef *layout,
                                                  const char *name) {
    if (!layout || !name) return NULL;

    for (int i = 0; i < layout->propertyCount; i++) {
        if (strcmp(layout->properties[i].name, name) == 0) {
            return &layout->properties[i];
        }
    }
    return NULL;
}

// ============================================================================
// Property Reading
// ============================================================================

int component_property_read_def(lua_State *L, void *componentPtr,
                                const ComponentPropertyDef *prop) {
    if (!L || !componentPtr || !prop) {
        lua_pushnil(L);
        return 1;
    }

    uintptr_t addr = (uintptr_t)componentPtr + prop->offset;

    switch (prop->type) {
        case FIELD_TYPE_INT8: {
            int8_t val = 0;
            if (safe_memory_read((mach_vm_address_t)addr, &val, sizeof(val))) {
                lua_pushinteger(L, val);
            } else {
                lua_pushnil(L);
            }
            return 1;
        }

        case FIELD_TYPE_UINT8: {
            uint8_t val = 0;
            if (safe_memory_read((mach_vm_address_t)addr, &val, sizeof(val))) {
                lua_pushinteger(L, val);
            } else {
                lua_pushnil(L);
            }
            return 1;
        }

        case FIELD_TYPE_INT16: {
            int16_t val = 0;
            if (safe_memory_read((mach_vm_address_t)addr, &val, sizeof(val))) {
                lua_pushinteger(L, val);
            } else {
                lua_pushnil(L);
            }
            return 1;
        }

        case FIELD_TYPE_UINT16: {
            uint16_t val = 0;
            if (safe_memory_read((mach_vm_address_t)addr, &val, sizeof(val))) {
                lua_pushinteger(L, val);
            } else {
                lua_pushnil(L);
            }
            return 1;
        }

        case FIELD_TYPE_INT32: {
            int32_t val = 0;
            if (safe_memory_read_i32((mach_vm_address_t)addr, &val)) {
                lua_pushinteger(L, val);
            } else {
                lua_pushnil(L);
            }
            return 1;
        }

        case FIELD_TYPE_UINT32: {
            uint32_t val = 0;
            if (safe_memory_read_u32((mach_vm_address_t)addr, &val)) {
                lua_pushinteger(L, val);
            } else {
                lua_pushnil(L);
            }
            return 1;
        }

        case FIELD_TYPE_INT64: {
            int64_t val = 0;
            if (safe_memory_read((mach_vm_address_t)addr, &val, sizeof(val))) {
                lua_pushinteger(L, val);
            } else {
                lua_pushnil(L);
            }
            return 1;
        }

        case FIELD_TYPE_UINT64: {
            uint64_t val = 0;
            if (safe_memory_read((mach_vm_address_t)addr, &val, sizeof(val))) {
                lua_pushinteger(L, (lua_Integer)val);
            } else {
                lua_pushnil(L);
            }
            return 1;
        }

        case FIELD_TYPE_BOOL: {
            uint8_t val = 0;
            if (safe_memory_read((mach_vm_address_t)addr, &val, sizeof(val))) {
                lua_pushboolean(L, val != 0);
            } else {
                lua_pushnil(L);
            }
            return 1;
        }

        case FIELD_TYPE_FLOAT: {
            float val = 0.0f;
            if (safe_memory_read((mach_vm_address_t)addr, &val, sizeof(val))) {
                lua_pushnumber(L, val);
            } else {
                lua_pushnil(L);
            }
            return 1;
        }

        case FIELD_TYPE_DOUBLE: {
            double val = 0.0;
            if (safe_memory_read((mach_vm_address_t)addr, &val, sizeof(val))) {
                lua_pushnumber(L, val);
            } else {
                lua_pushnil(L);
            }
            return 1;
        }

        case FIELD_TYPE_VEC3: {
            float vals[3] = {0};
            if (safe_memory_read((mach_vm_address_t)addr, vals, sizeof(vals))) {
                lua_createtable(L, 0, 3);
                lua_pushnumber(L, vals[0]); lua_setfield(L, -2, "x");
                lua_pushnumber(L, vals[1]); lua_setfield(L, -2, "y");
                lua_pushnumber(L, vals[2]); lua_setfield(L, -2, "z");
            } else {
                lua_pushnil(L);
            }
            return 1;
        }

        case FIELD_TYPE_VEC4: {
            float vals[4] = {0};
            if (safe_memory_read((mach_vm_address_t)addr, vals, sizeof(vals))) {
                lua_createtable(L, 0, 4);
                lua_pushnumber(L, vals[0]); lua_setfield(L, -2, "x");
                lua_pushnumber(L, vals[1]); lua_setfield(L, -2, "y");
                lua_pushnumber(L, vals[2]); lua_setfield(L, -2, "z");
                lua_pushnumber(L, vals[3]); lua_setfield(L, -2, "w");
            } else {
                lua_pushnil(L);
            }
            return 1;
        }

        case FIELD_TYPE_INT32_ARRAY: {
            if (prop->arraySize == 0) {
                lua_pushnil(L);
                return 1;
            }
            lua_createtable(L, prop->arraySize, 0);
            for (int i = 0; i < prop->arraySize; i++) {
                int32_t val = 0;
                if (safe_memory_read_i32((mach_vm_address_t)(addr + i * sizeof(int32_t)), &val)) {
                    lua_pushinteger(L, val);
                } else {
                    lua_pushnil(L);
                }
                lua_rawseti(L, -2, i + 1);  // 1-indexed
            }
            return 1;
        }

        case FIELD_TYPE_FLOAT_ARRAY: {
            if (prop->arraySize == 0) {
                lua_pushnil(L);
                return 1;
            }
            lua_createtable(L, prop->arraySize, 0);
            for (int i = 0; i < prop->arraySize; i++) {
                float val = 0.0f;
                if (safe_memory_read((mach_vm_address_t)(addr + i * sizeof(float)), &val, sizeof(val))) {
                    lua_pushnumber(L, val);
                } else {
                    lua_pushnil(L);
                }
                lua_rawseti(L, -2, i + 1);
            }
            return 1;
        }

        case FIELD_TYPE_GUID: {
            // GUID is 16 bytes, format as string
            uint8_t guid[16] = {0};
            if (safe_memory_read((mach_vm_address_t)addr, guid, 16)) {
                char buf[64];
                snprintf(buf, sizeof(buf),
                        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                        guid[0], guid[1], guid[2], guid[3],
                        guid[4], guid[5], guid[6], guid[7],
                        guid[8], guid[9], guid[10], guid[11],
                        guid[12], guid[13], guid[14], guid[15]);
                lua_pushstring(L, buf);
            } else {
                lua_pushnil(L);
            }
            return 1;
        }

        case FIELD_TYPE_ENTITY_HANDLE: {
            uint64_t val = 0;
            if (safe_memory_read((mach_vm_address_t)addr, &val, sizeof(val))) {
                // Return as hex string for debugging
                char buf[32];
                snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)val);
                lua_pushstring(L, buf);
            } else {
                lua_pushnil(L);
            }
            return 1;
        }

        case FIELD_TYPE_FIXEDSTRING: {
            // FixedString is a uint32_t index into GlobalStringTable
            // For now, return the raw index - full resolution requires GST access
            uint32_t val = 0;
            if (safe_memory_read_u32((mach_vm_address_t)addr, &val)) {
                lua_pushinteger(L, val);
            } else {
                lua_pushnil(L);
            }
            return 1;
        }

        case FIELD_TYPE_DYNAMIC_ARRAY: {
            // Dynamic Array<T> - return an array proxy
            component_property_push_array_proxy(L, (void *)addr, prop);
            return 1;
        }

        default:
            LOG_ENTITY_DEBUG("Unsupported field type: %d", prop->type);
            lua_pushnil(L);
            return 1;
    }
}

int component_property_read(lua_State *L, void *componentPtr,
                            const ComponentLayoutDef *layout,
                            const char *propertyName) {
    const ComponentPropertyDef *prop = find_property(layout, propertyName);
    if (!prop) {
        return 0;  // Property not found
    }
    return component_property_read_def(L, componentPtr, prop);
}

// ============================================================================
// Property Writing (Stub)
// ============================================================================

bool component_property_write(lua_State *L, void *componentPtr,
                              const ComponentLayoutDef *layout,
                              const char *propertyName, int valueIndex) {
    (void)L;
    (void)componentPtr;
    (void)layout;
    (void)propertyName;
    (void)valueIndex;

    LOG_ENTITY_DEBUG("Component property writes not yet implemented");
    return false;
}

// ============================================================================
// Component Proxy Userdata
// ============================================================================

typedef struct {
    void *componentPtr;
    const ComponentLayoutDef *layout;
    LifetimeHandle lifetime;
} ComponentProxy;

static int component_proxy_index(lua_State *L) {
    ComponentProxy *proxy = (ComponentProxy *)luaL_checkudata(L, 1, COMPONENT_PROXY_METATABLE);
    if (!lifetime_lua_is_valid(L, proxy->lifetime)) {
        return lifetime_lua_expired_error(L, "Component");
    }
    const char *key = luaL_checkstring(L, 2);

    // Special properties
    if (strcmp(key, "__type") == 0) {
        lua_pushstring(L, proxy->layout->componentName);
        return 1;
    }
    if (strcmp(key, "__shortname") == 0) {
        lua_pushstring(L, proxy->layout->shortName);
        return 1;
    }
    if (strcmp(key, "__ptr") == 0) {
        lua_pushlightuserdata(L, proxy->componentPtr);
        return 1;
    }

    // Look up property
    int result = component_property_read(L, proxy->componentPtr, proxy->layout, key);
    if (result > 0) {
        return result;
    }

    // Property not found
    lua_pushnil(L);
    return 1;
}

static int component_proxy_newindex(lua_State *L) {
    ComponentProxy *proxy = (ComponentProxy *)luaL_checkudata(L, 1, COMPONENT_PROXY_METATABLE);
    if (!lifetime_lua_is_valid(L, proxy->lifetime)) {
        return lifetime_lua_expired_error(L, "Component");
    }
    const char *key = luaL_checkstring(L, 2);

    const ComponentPropertyDef *prop = find_property(proxy->layout, key);
    if (!prop) {
        return luaL_error(L, "Unknown property: %s", key);
    }
    if (prop->readOnly) {
        return luaL_error(L, "Property %s is read-only", key);
    }

    // Property writes not yet implemented
    return luaL_error(L, "Component property writes not yet implemented");
}

static int component_proxy_tostring(lua_State *L) {
    ComponentProxy *proxy = (ComponentProxy *)luaL_checkudata(L, 1, COMPONENT_PROXY_METATABLE);
    // tostring works even on expired components (for debugging)
    bool valid = lifetime_lua_is_valid(L, proxy->lifetime);
    if (valid) {
        lua_pushfstring(L, "Component<%s>(%p)",
                       proxy->layout->shortName ? proxy->layout->shortName : proxy->layout->componentName,
                       proxy->componentPtr);
    } else {
        lua_pushfstring(L, "Component<%s>(%p) [EXPIRED]",
                       proxy->layout->shortName ? proxy->layout->shortName : proxy->layout->componentName,
                       proxy->componentPtr);
    }
    return 1;
}

static int component_proxy_pairs_iter(lua_State *L) {
    ComponentProxy *proxy = (ComponentProxy *)lua_touserdata(L, lua_upvalueindex(1));
    int *index = (int *)lua_touserdata(L, lua_upvalueindex(2));

    // Validate lifetime on each iteration
    if (!lifetime_lua_is_valid(L, proxy->lifetime)) {
        return lifetime_lua_expired_error(L, "Component");
    }

    if (*index >= proxy->layout->propertyCount) {
        return 0;  // End of iteration
    }

    const ComponentPropertyDef *prop = &proxy->layout->properties[*index];
    lua_pushstring(L, prop->name);
    component_property_read_def(L, proxy->componentPtr, prop);

    (*index)++;
    return 2;
}

static int component_proxy_pairs(lua_State *L) {
    ComponentProxy *proxy = (ComponentProxy *)luaL_checkudata(L, 1, COMPONENT_PROXY_METATABLE);
    if (!lifetime_lua_is_valid(L, proxy->lifetime)) {
        return lifetime_lua_expired_error(L, "Component");
    }

    // Create upvalues: proxy and index
    lua_pushlightuserdata(L, proxy);
    int *index = (int *)lua_newuserdata(L, sizeof(int));
    *index = 0;

    lua_pushcclosure(L, component_proxy_pairs_iter, 2);
    lua_pushvalue(L, 1);  // table (proxy)
    lua_pushnil(L);       // initial key
    return 3;
}

void component_property_push_proxy(lua_State *L, void *componentPtr,
                                   const ComponentLayoutDef *layout) {
    if (!componentPtr || !layout) {
        lua_pushnil(L);
        return;
    }

    ComponentProxy *proxy = (ComponentProxy *)lua_newuserdata(L, sizeof(ComponentProxy));
    proxy->componentPtr = componentPtr;
    proxy->layout = layout;
    proxy->lifetime = lifetime_lua_get_current(L);

    luaL_getmetatable(L, COMPONENT_PROXY_METATABLE);
    lua_setmetatable(L, -2);
}

const ComponentLayoutDef *component_property_check_proxy(lua_State *L, int index) {
    void *ud = luaL_testudata(L, index, COMPONENT_PROXY_METATABLE);
    if (ud) {
        ComponentProxy *proxy = (ComponentProxy *)ud;
        return proxy->layout;
    }
    return NULL;
}

// ============================================================================
// Array Proxy Userdata
// ============================================================================

typedef struct {
    void *arrayPtr;             // Pointer to Array<T> struct (buf_/capacity_/size_)
    ArrayElementType elemType;  // Element type for formatting
    uint16_t elemSize;          // Element size in bytes
    LifetimeHandle lifetime;    // For validity checking
} ArrayProxy;

// Read array metadata from memory
static bool array_proxy_read_metadata(ArrayProxy *proxy, void **buf_out, uint32_t *size_out) {
    if (!proxy || !proxy->arrayPtr) return false;

    uintptr_t base = (uintptr_t)proxy->arrayPtr;

    // Read buf_ pointer
    void *buf = NULL;
    if (!safe_memory_read((mach_vm_address_t)(base + ARRAY_BUF_OFFSET), &buf, sizeof(buf))) {
        return false;
    }

    // Read size_
    uint32_t size = 0;
    if (!safe_memory_read_u32((mach_vm_address_t)(base + ARRAY_SIZE_OFFSET), &size)) {
        return false;
    }

    if (buf_out) *buf_out = buf;
    if (size_out) *size_out = size;
    return true;
}

// Push a single array element to Lua stack
static int array_proxy_push_element(lua_State *L, ArrayProxy *proxy, void *buf, uint32_t index) {
    if (!buf || proxy->elemSize == 0) {
        lua_pushnil(L);
        return 1;
    }

    uintptr_t elemAddr = (uintptr_t)buf + (index * proxy->elemSize);

    switch (proxy->elemType) {
        case ELEM_TYPE_GUID: {
            uint8_t guid[16] = {0};
            if (safe_memory_read((mach_vm_address_t)elemAddr, guid, 16)) {
                char buf[64];
                snprintf(buf, sizeof(buf),
                        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                        guid[0], guid[1], guid[2], guid[3],
                        guid[4], guid[5], guid[6], guid[7],
                        guid[8], guid[9], guid[10], guid[11],
                        guid[12], guid[13], guid[14], guid[15]);
                lua_pushstring(L, buf);
            } else {
                lua_pushnil(L);
            }
            return 1;
        }

        case ELEM_TYPE_FIXED_STRING: {
            uint32_t val = 0;
            if (safe_memory_read_u32((mach_vm_address_t)elemAddr, &val)) {
                lua_pushinteger(L, val);
            } else {
                lua_pushnil(L);
            }
            return 1;
        }

        case ELEM_TYPE_ENTITY_HANDLE: {
            uint64_t val = 0;
            if (safe_memory_read((mach_vm_address_t)elemAddr, &val, sizeof(val))) {
                char buf[32];
                snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)val);
                lua_pushstring(L, buf);
            } else {
                lua_pushnil(L);
            }
            return 1;
        }

        case ELEM_TYPE_CLASS_INFO: {
            // ClassInfo: ClassUUID(16) + SubClassUUID(16) + Level(4)
            lua_createtable(L, 0, 5);

            // ClassUUID at offset 0
            uint8_t classGuid[16] = {0};
            if (safe_memory_read((mach_vm_address_t)elemAddr, classGuid, 16)) {
                char guidBuf[64];
                snprintf(guidBuf, sizeof(guidBuf),
                        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                        classGuid[0], classGuid[1], classGuid[2], classGuid[3],
                        classGuid[4], classGuid[5], classGuid[6], classGuid[7],
                        classGuid[8], classGuid[9], classGuid[10], classGuid[11],
                        classGuid[12], classGuid[13], classGuid[14], classGuid[15]);
                lua_pushstring(L, guidBuf);
                lua_setfield(L, -2, "ClassUUID");
            }

            // SubClassUUID at offset 16
            uint8_t subclassGuid[16] = {0};
            if (safe_memory_read((mach_vm_address_t)(elemAddr + 16), subclassGuid, 16)) {
                char guidBuf[64];
                snprintf(guidBuf, sizeof(guidBuf),
                        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                        subclassGuid[0], subclassGuid[1], subclassGuid[2], subclassGuid[3],
                        subclassGuid[4], subclassGuid[5], subclassGuid[6], subclassGuid[7],
                        subclassGuid[8], subclassGuid[9], subclassGuid[10], subclassGuid[11],
                        subclassGuid[12], subclassGuid[13], subclassGuid[14], subclassGuid[15]);
                lua_pushstring(L, guidBuf);
                lua_setfield(L, -2, "SubClassUUID");
            }

            // Level at offset 32
            int32_t level = 0;
            if (safe_memory_read((mach_vm_address_t)(elemAddr + 32), &level, sizeof(level))) {
                lua_pushinteger(L, level);
                lua_setfield(L, -2, "Level");
            }

            // Debug info
            lua_pushinteger(L, index + 1);
            lua_setfield(L, -2, "__index");

            return 1;
        }

        case ELEM_TYPE_BOOST_ENTRY: {
            // BoostEntry: BoostType(4) + padding(4) + Array<EntityHandle>(buf:8 + cap:4 + size:4)
            lua_createtable(L, 0, 4);

            // BoostType at offset 0
            uint32_t boostType = 0;
            if (safe_memory_read_u32((mach_vm_address_t)elemAddr, &boostType)) {
                lua_pushinteger(L, boostType);
                lua_setfield(L, -2, "Type");
            }

            // Array<EntityHandle> at offset 8 - size is at offset 8+8+4 = 20
            uint32_t boostCount = 0;
            if (safe_memory_read_u32((mach_vm_address_t)(elemAddr + 20), &boostCount)) {
                lua_pushinteger(L, boostCount);
                lua_setfield(L, -2, "BoostCount");
            }

            // Debug info
            lua_pushinteger(L, index + 1);
            lua_setfield(L, -2, "__index");

            char addrBuf[32];
            snprintf(addrBuf, sizeof(addrBuf), "0x%llx", (unsigned long long)elemAddr);
            lua_pushstring(L, addrBuf);
            lua_setfield(L, -2, "__ptr");

            return 1;
        }

        case ELEM_TYPE_SPELL_DATA:
        case ELEM_TYPE_SPELL_META:
        case ELEM_TYPE_STATUS_INFO:
        case ELEM_TYPE_UNKNOWN:
        default: {
            // For complex types, return a table with the element address and basic info
            // This allows further introspection
            lua_createtable(L, 0, 3);

            // __ptr: raw address for debugging
            char addrBuf[32];
            snprintf(addrBuf, sizeof(addrBuf), "0x%llx", (unsigned long long)elemAddr);
            lua_pushstring(L, addrBuf);
            lua_setfield(L, -2, "__ptr");

            // __index: 1-based index
            lua_pushinteger(L, index + 1);
            lua_setfield(L, -2, "__index");

            // __size: element size
            lua_pushinteger(L, proxy->elemSize);
            lua_setfield(L, -2, "__size");

            // For SpellData, try to extract the SpellId (first field is SpellId struct)
            if (proxy->elemType == ELEM_TYPE_SPELL_DATA) {
                // SpellId is at offset 0, contains FixedString at 0x00
                uint32_t spellId = 0;
                if (safe_memory_read_u32((mach_vm_address_t)elemAddr, &spellId)) {
                    lua_pushinteger(L, spellId);
                    lua_setfield(L, -2, "SpellId");
                }
            }

            return 1;
        }
    }
}

static int array_proxy_index(lua_State *L) {
    ArrayProxy *proxy = (ArrayProxy *)luaL_checkudata(L, 1, ARRAY_PROXY_METATABLE);
    if (!lifetime_lua_is_valid(L, proxy->lifetime)) {
        return lifetime_lua_expired_error(L, "Array");
    }

    // Get index (1-based in Lua)
    if (!lua_isinteger(L, 2)) {
        lua_pushnil(L);
        return 1;
    }

    lua_Integer luaIndex = lua_tointeger(L, 2);
    if (luaIndex < 1) {
        lua_pushnil(L);
        return 1;
    }

    // Read array metadata
    void *buf = NULL;
    uint32_t size = 0;
    if (!array_proxy_read_metadata(proxy, &buf, &size)) {
        lua_pushnil(L);
        return 1;
    }

    // Convert to 0-based index and check bounds
    uint32_t index = (uint32_t)(luaIndex - 1);
    if (index >= size) {
        lua_pushnil(L);
        return 1;
    }

    return array_proxy_push_element(L, proxy, buf, index);
}

static int array_proxy_len(lua_State *L) {
    ArrayProxy *proxy = (ArrayProxy *)luaL_checkudata(L, 1, ARRAY_PROXY_METATABLE);
    if (!lifetime_lua_is_valid(L, proxy->lifetime)) {
        return lifetime_lua_expired_error(L, "Array");
    }

    uint32_t size = 0;
    if (array_proxy_read_metadata(proxy, NULL, &size)) {
        lua_pushinteger(L, size);
    } else {
        lua_pushinteger(L, 0);
    }
    return 1;
}

static int array_proxy_tostring(lua_State *L) {
    ArrayProxy *proxy = (ArrayProxy *)luaL_checkudata(L, 1, ARRAY_PROXY_METATABLE);
    bool valid = lifetime_lua_is_valid(L, proxy->lifetime);

    if (valid) {
        uint32_t size = 0;
        array_proxy_read_metadata(proxy, NULL, &size);
        lua_pushfstring(L, "Array[%d](%p)", (int)size, proxy->arrayPtr);
    } else {
        lua_pushfstring(L, "Array(%p) [EXPIRED]", proxy->arrayPtr);
    }
    return 1;
}

static int array_proxy_pairs_iter(lua_State *L) {
    ArrayProxy *proxy = (ArrayProxy *)lua_touserdata(L, lua_upvalueindex(1));
    int *index = (int *)lua_touserdata(L, lua_upvalueindex(2));

    if (!lifetime_lua_is_valid(L, proxy->lifetime)) {
        return lifetime_lua_expired_error(L, "Array");
    }

    void *buf = NULL;
    uint32_t size = 0;
    if (!array_proxy_read_metadata(proxy, &buf, &size)) {
        return 0;
    }

    if (*index >= (int)size) {
        return 0;  // End of iteration
    }

    // Push 1-based key
    lua_pushinteger(L, *index + 1);

    // Push value
    array_proxy_push_element(L, proxy, buf, *index);

    (*index)++;
    return 2;
}

static int array_proxy_pairs(lua_State *L) {
    ArrayProxy *proxy = (ArrayProxy *)luaL_checkudata(L, 1, ARRAY_PROXY_METATABLE);
    if (!lifetime_lua_is_valid(L, proxy->lifetime)) {
        return lifetime_lua_expired_error(L, "Array");
    }

    // Create upvalues: proxy and index
    lua_pushlightuserdata(L, proxy);
    int *index = (int *)lua_newuserdata(L, sizeof(int));
    *index = 0;

    lua_pushcclosure(L, array_proxy_pairs_iter, 2);
    lua_pushvalue(L, 1);  // table (proxy)
    lua_pushnil(L);       // initial key
    return 3;
}

void component_property_push_array_proxy(lua_State *L, void *arrayPtr,
                                         const ComponentPropertyDef *prop) {
    if (!arrayPtr || !prop) {
        lua_pushnil(L);
        return;
    }

    ArrayProxy *proxy = (ArrayProxy *)lua_newuserdata(L, sizeof(ArrayProxy));
    proxy->arrayPtr = arrayPtr;
    proxy->elemType = prop->elemType;
    proxy->elemSize = prop->elemSize;
    proxy->lifetime = lifetime_lua_get_current(L);

    luaL_getmetatable(L, ARRAY_PROXY_METATABLE);
    lua_setmetatable(L, -2);
}

// ============================================================================
// Lua Registration
// ============================================================================

void component_property_register_lua(lua_State *L) {
    // Create ComponentProxy metatable
    luaL_newmetatable(L, COMPONENT_PROXY_METATABLE);

    lua_pushcfunction(L, component_proxy_index);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, component_proxy_newindex);
    lua_setfield(L, -2, "__newindex");

    lua_pushcfunction(L, component_proxy_tostring);
    lua_setfield(L, -2, "__tostring");

    lua_pushcfunction(L, component_proxy_pairs);
    lua_setfield(L, -2, "__pairs");

    lua_pop(L, 1);

    LOG_ENTITY_DEBUG("Registered ComponentProxy metatable");

    // Create ArrayProxy metatable
    luaL_newmetatable(L, ARRAY_PROXY_METATABLE);

    lua_pushcfunction(L, array_proxy_index);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, array_proxy_len);
    lua_setfield(L, -2, "__len");

    lua_pushcfunction(L, array_proxy_tostring);
    lua_setfield(L, -2, "__tostring");

    lua_pushcfunction(L, array_proxy_pairs);
    lua_setfield(L, -2, "__pairs");

    // __ipairs uses same iterator as __pairs (1-based keys)
    lua_pushcfunction(L, array_proxy_pairs);
    lua_setfield(L, -2, "__ipairs");

    lua_pop(L, 1);

    LOG_ENTITY_DEBUG("Registered ArrayProxy metatable");
}

// ============================================================================
// Debugging
// ============================================================================

int component_property_get_layout_count(void) {
    return g_LayoutCount;
}

void component_property_dump_layouts(void) {
    LOG_ENTITY_DEBUG("=== Component Property Layouts (%d total) ===", g_LayoutCount);
    for (int i = 0; i < g_LayoutCount; i++) {
        const ComponentLayoutDef *layout = &g_Layouts[i];
        LOG_ENTITY_DEBUG("  %s (%s): TypeIndex=%u, Size=0x%x, Properties=%d",
                       layout->componentName,
                       layout->shortName ? layout->shortName : "?",
                       layout->componentTypeIndex,
                       layout->componentSize,
                       layout->propertyCount);
    }
}
