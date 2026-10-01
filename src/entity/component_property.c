/**
 * BG3SE-macOS - Component Property Access Implementation
 *
 * Provides safe, data-driven property access for ECS components.
 */

#include "component_property.h"

// Generated layout records intentionally rely on zero-initialization for the
// optional array metadata fields and use empty arrays for tag components.
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-field-initializers"
#pragma clang diagnostic ignored "-Wzero-length-array"
#endif
#include "component_offsets.h"
#include "generated_property_defs.h"  // 504 generated component layouts
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#include "guid_lookup.h"       // guid_to_string: the engine's canonical GUID text
#include "../core/safe_memory.h"
#include "../core/logging.h"
#include "../lifetime/lifetime.h"
#include "../strings/fixed_string.h"

#include <limits.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

// Push a 16-byte engine Guid at addr as its canonical string, or nil if the
// read fails. One formatter for every GUID-typed field and element: the
// engine's text form is little-endian per group (guid_to_string, the inverse
// of guid_parse). Printing the bytes in memory order produced a string with
// every group byte-reversed ("831cd0b4-e925-..." for host b4d01c83-25e9-...),
// which no Osi.* or Ext.Entity.* call would accept (2026-09-14 live session).
static void push_guid_at(lua_State *L, uintptr_t addr) {
    Guid guid;
    if (safe_memory_read((mach_vm_address_t)addr, &guid, sizeof(guid))) {
        char buf[64];
        guid_to_string(&guid, buf);
        lua_pushstring(L, buf);
    } else {
        lua_pushnil(L);
    }
}

// Push a FixedString index as its string (Windows semantics): the null index
// is "", an index that resolves is its text, and one that does not stays the
// raw integer rather than being lost.
static void push_fixed_string_index(lua_State *L, uint32_t val) {
    if (val == FS_NULL_INDEX) {
        lua_pushstring(L, "");
        return;
    }
    const char *str = fixed_string_resolve(val);
    if (str) {
        lua_pushstring(L, str);
    } else {
        lua_pushinteger(L, val);
    }
}

// Lua headers
#include "../../lib/lua/src/lua.h"
#include "../../lib/lua/src/lauxlib.h"
#include "../../lib/lua/src/lualib.h"

// ============================================================================
// Constants
// ============================================================================

#define MAX_COMPONENT_LAYOUTS 1024  // Enough for all 1,999 components
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

static bool component_property_register_layout_internal(
    const ComponentLayoutDef *layout, bool generated);

// ============================================================================
// Initialization
// ============================================================================

bool component_property_init(void) {
    if (g_Initialized) return true;

    g_LayoutCount = 0;

    // Register built-in layouts from component_offsets.h (hand-verified)
    int verified_count = 0;
    for (int i = 0; g_AllComponentLayouts[i] != NULL; i++) {
        if (component_property_register_layout(g_AllComponentLayouts[i])) {
            verified_count++;
        }
    }
    LOG_ENTITY_DEBUG("Registered %d verified component layouts", verified_count);

    // Register generated layouts from Windows BG3SE headers (unverified offsets)
    int generated_count = 0;
    for (int i = 0; i < GENERATED_COMPONENT_COUNT; i++) {
        const ComponentLayoutDef* layout = g_GeneratedComponentLayouts[i];
        if (!layout) continue;

        // Skip if already registered (from g_AllComponentLayouts)
        if (component_property_get_layout(layout->componentName)) continue;

        if (component_property_register_layout_internal(layout, true)) {
            generated_count++;
        }
    }
    LOG_ENTITY_DEBUG("Registered %d generated component layouts (Windows offsets)", generated_count);

    g_Initialized = true;
    LOG_ENTITY_DEBUG("Component property system initialized with %d total layouts", g_LayoutCount);
    return true;
}

// ============================================================================
// Layout Registration & Lookup
// ============================================================================

static bool component_property_register_layout_internal(
    const ComponentLayoutDef *layout, bool generated) {
    if (!layout || !layout->componentName) return false;
    if (g_LayoutCount >= MAX_COMPONENT_LAYOUTS) {
        LOG_ENTITY_DEBUG("Component layout registry full");
        return false;
    }

    // Copy layout
    g_Layouts[g_LayoutCount] = *layout;
    g_Layouts[g_LayoutCount].generated = generated;
    g_LayoutCount++;

    LOG_ENTITY_DEBUG("Registered component layout: %s (%s) with %d properties",
                   layout->componentName, layout->shortName, layout->propertyCount);
    return true;
}

bool component_property_register_layout(const ComponentLayoutDef *layout) {
    return component_property_register_layout_internal(layout, false);
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
            push_guid_at(L, (uintptr_t)addr);
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
            // FixedString is a uint32_t index into the GlobalStringTable.
            uint32_t val = 0;
            if (safe_memory_read_u32((mach_vm_address_t)addr, &val)) {
                push_fixed_string_index(L, val);
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

static uint64_t g_read_bounds_refused = 0;

bool component_property_read_in_bounds(const ComponentLayoutDef *layout,
                                       const ComponentPropertyDef *prop) {
    /* 0 means the size was never recorded, not that the component is empty:
     * nothing to check against. */
    if (!layout || !prop || layout->componentSize == 0) return true;
    size_t width = component_field_type_width(prop);
    if ((size_t)prop->offset > layout->componentSize ||
        width > (size_t)layout->componentSize - prop->offset) {
        g_read_bounds_refused++;
        LOG_ENTITY_DEBUG(
            "Refusing component read: %s.%s range [0x%x, 0x%zx) exceeds layout size 0x%x",
            layout->componentName, prop->name, prop->offset,
            (size_t)prop->offset + width, layout->componentSize);
        return false;
    }
    return true;
}

uint64_t component_property_read_bounds_refused(void) {
    return g_read_bounds_refused;
}

/* A read that leaves the component returns the neighbouring component's
 * bytes as if they were the field. Refuse it (nil), as writes already are. */
static int component_property_read_checked(lua_State *L, void *componentPtr,
                                           const ComponentLayoutDef *layout,
                                           const ComponentPropertyDef *prop) {
    if (!component_property_read_in_bounds(layout, prop)) {
        lua_pushnil(L);
        return 1;
    }
    return component_property_read_def(L, componentPtr, prop);
}

int component_property_read(lua_State *L, void *componentPtr,
                            const ComponentLayoutDef *layout,
                            const char *propertyName) {
    const ComponentPropertyDef *prop = find_property(layout, propertyName);
    if (!prop) {
        return 0;  // Property not found
    }
    return component_property_read_checked(L, componentPtr, layout, prop);
}

// ============================================================================
// Property Writing
// ============================================================================

static size_t component_property_field_size(const ComponentPropertyDef *prop) {
    if (!prop) return 0;

    switch (prop->type) {
        case FIELD_TYPE_UINT8:
        case FIELD_TYPE_BOOL:
            return sizeof(uint8_t);

        case FIELD_TYPE_INT32:
        case FIELD_TYPE_FLOAT:
        case FIELD_TYPE_FIXEDSTRING:
            return sizeof(uint32_t);

        case FIELD_TYPE_INT32_ARRAY:
            if (prop->arraySize == 0) return 0;
            return (size_t)prop->arraySize * sizeof(int32_t);

        case FIELD_TYPE_FLOAT_ARRAY:
            if (prop->arraySize == 0) return 0;
            return (size_t)prop->arraySize * sizeof(float);

        default:
            return 0;
    }
}

static bool component_property_is_pointer_typed(const ComponentPropertyDef *prop) {
    /*
     * Dynamic Array<T> embeds a game-owned buffer pointer.  Replacing any part
     * of that header would be a pointer write and arrays of structs additionally
     * require ownership/lifetime operations that this layer cannot provide.
     */
    return prop && prop->type == FIELD_TYPE_DYNAMIC_ARRAY;
}

static bool component_property_bounds_valid(const ComponentLayoutDef *layout,
                                            const ComponentPropertyDef *prop,
                                            size_t fieldSize) {
    /* Unknown component size means no boundary to validate against — refuse
     * writes for verified layouts too, not just generated ones, or a size-0
     * verified layout would let writes past the component silently corrupt
     * adjacent ECS memory. */
    if (layout->componentSize == 0) {
        LOG_ENTITY_DEBUG(
            "Refusing component write: layout %s has unknown size%s",
            layout->componentName, layout->generated ? " (generated)" : "");
        return false;
    }

    if (layout->componentSize != 0
        && ((size_t)prop->offset > layout->componentSize
            || fieldSize > (size_t)layout->componentSize - prop->offset)) {
        LOG_ENTITY_DEBUG(
            "Refusing component write: %s.%s range [0x%x, 0x%zx) exceeds layout size 0x%x%s",
            layout->componentName, prop->name, prop->offset,
            (size_t)prop->offset + fieldSize, layout->componentSize,
            layout->generated ? " (generated)" : "");
        return false;
    }

    return true;
}

bool component_property_write(lua_State *L, void *componentPtr,
                              const ComponentLayoutDef *layout,
                              const char *propertyName, int valueIndex) {
    if (!L || !componentPtr || !layout || !layout->componentName || !propertyName) {
        LOG_ENTITY_DEBUG(
            "Refusing component write: invalid arguments (L=%p component=%p layout=%p property=%s)",
            (void *)L, componentPtr, (const void *)layout,
            propertyName ? propertyName : "<null>");
        return false;
    }

    const ComponentPropertyDef *prop = find_property(layout, propertyName);
    if (!prop) {
        LOG_ENTITY_DEBUG("Refusing component write: unknown property %s.%s",
                         layout->componentName, propertyName);
        return false;
    }

    if (strstr(layout->componentName, "OneFrame") != NULL
        || strstr(layout->componentName, "Request") != NULL) {
        LOG_ENTITY_DEBUG("Refusing component write: transient component %s is blacklisted",
                         layout->componentName);
        return false;
    }

    // Interning itself works (fixed_string_intern); the unresolved piece is
    // ownership transfer — swapping an index in place without DecRef'ing the
    // old entry leaks it, and DecRef's macOS entry point is not yet recovered.
    if (prop->type == FIELD_TYPE_FIXEDSTRING) {
        LOG_ENTITY_DEBUG(
            "Refusing component write: %s.%s is FixedString (old-value DecRef/"
            "ownership transfer unverified; interning itself is available)",
            layout->componentName, propertyName);
        return false;
    }

    if (component_property_is_pointer_typed(prop)) {
        LOG_ENTITY_DEBUG("Refusing component write: %s.%s is pointer-typed",
                         layout->componentName, propertyName);
        return false;
    }

    size_t fieldSize = component_property_field_size(prop);
    if (fieldSize == 0) {
        LOG_ENTITY_DEBUG("Refusing component write: unsupported field type %d for %s.%s",
                         prop->type, layout->componentName, propertyName);
        return false;
    }

    if (!component_property_bounds_valid(layout, prop, fieldSize)) {
        return false;
    }

    if (prop->readOnly) {
        LOG_ENTITY_DEBUG("Refusing component write: %s.%s is read-only",
                         layout->componentName, propertyName);
        return false;
    }

    uintptr_t componentAddress = (uintptr_t)componentPtr;
    if (componentAddress > UINTPTR_MAX - prop->offset) {
        LOG_ENTITY_DEBUG("Refusing component write: address overflow for %s.%s",
                         layout->componentName, propertyName);
        return false;
    }

    mach_vm_address_t address =
        (mach_vm_address_t)(componentAddress + prop->offset);
    bool wrote = false;

    switch (prop->type) {
        case FIELD_TYPE_INT32: {
            lua_Integer raw = luaL_checkinteger(L, valueIndex);
            if (raw < INT32_MIN || raw > INT32_MAX) {
                luaL_error(L, "Value for %s.%s is outside int32 range",
                           layout->componentName, propertyName);
                return false;
            }
            int32_t value = (int32_t)raw;
            wrote = safe_memory_write(address, &value, sizeof(value));
            break;
        }

        case FIELD_TYPE_UINT8: {
            lua_Integer raw = luaL_checkinteger(L, valueIndex);
            if (raw < 0 || raw > UINT8_MAX) {
                luaL_error(L, "Value for %s.%s is outside uint8 range",
                           layout->componentName, propertyName);
                return false;
            }
            uint8_t value = (uint8_t)raw;
            wrote = safe_memory_write(address, &value, sizeof(value));
            break;
        }

        case FIELD_TYPE_BOOL: {
            luaL_checktype(L, valueIndex, LUA_TBOOLEAN);
            uint8_t value = lua_toboolean(L, valueIndex) ? 1 : 0;
            wrote = safe_memory_write(address, &value, sizeof(value));
            break;
        }

        case FIELD_TYPE_FLOAT: {
            float value = (float)luaL_checknumber(L, valueIndex);
            wrote = safe_memory_write(address, &value, sizeof(value));
            break;
        }

        case FIELD_TYPE_INT32_ARRAY: {
            int absoluteIndex = lua_absindex(L, valueIndex);
            luaL_checktype(L, absoluteIndex, LUA_TTABLE);
            size_t suppliedSize = lua_rawlen(L, absoluteIndex);
            if (suppliedSize != prop->arraySize) {
                luaL_error(L, "Value for %s.%s must contain exactly %u elements",
                           layout->componentName, propertyName, prop->arraySize);
                return false;
            }

            int32_t values[UINT8_MAX];
            for (uint8_t i = 0; i < prop->arraySize; i++) {
                lua_rawgeti(L, absoluteIndex, (lua_Integer)i + 1);
                lua_Integer raw = luaL_checkinteger(L, -1);
                if (raw < INT32_MIN || raw > INT32_MAX) {
                    luaL_error(L, "Element %u for %s.%s is outside int32 range",
                               (unsigned)i + 1, layout->componentName, propertyName);
                    return false;
                }
                values[i] = (int32_t)raw;
                lua_pop(L, 1);
            }

            wrote = safe_memory_write(address, values, fieldSize);
            break;
        }

        case FIELD_TYPE_FLOAT_ARRAY: {
            // Mirrors the INT32_ARRAY contract: exact length, per-element
            // validation (NaN/infinity refused — the engine treats both as
            // corrupt data), staged buffer, one atomic write. Wave 7 A7:
            // no verified layout carries this type yet, so the path is
            // exercised only once a real field lands (ls::EffectComponent::
            // OverrideFadeCapacity is the verification candidate).
            int absoluteIndex = lua_absindex(L, valueIndex);
            luaL_checktype(L, absoluteIndex, LUA_TTABLE);
            size_t suppliedSize = lua_rawlen(L, absoluteIndex);
            if (suppliedSize != prop->arraySize) {
                luaL_error(L, "Value for %s.%s must contain exactly %u elements",
                           layout->componentName, propertyName, prop->arraySize);
                return false;
            }

            float values[UINT8_MAX];
            for (uint8_t i = 0; i < prop->arraySize; i++) {
                lua_rawgeti(L, absoluteIndex, (lua_Integer)i + 1);
                double raw = (double)luaL_checknumber(L, -1);
                if (isnan(raw) || isinf(raw)) {
                    luaL_error(L, "Element %u for %s.%s is NaN or infinity",
                               (unsigned)i + 1, layout->componentName, propertyName);
                    return false;
                }
                values[i] = (float)raw;
                lua_pop(L, 1);
            }

            wrote = safe_memory_write(address, values, fieldSize);
            break;
        }

        default:
            /* component_property_field_size() rejects every other type. */
            break;
    }

    if (!wrote) {
        LOG_ENTITY_DEBUG("Component write failed safely: %s.%s at %p (%zu bytes)",
                         layout->componentName, propertyName, (void *)(uintptr_t)address,
                         fieldSize);
        return false;
    }

    LOG_ENTITY_DEBUG("Component write succeeded: %s.%s (%zu bytes)",
                     layout->componentName, propertyName, fieldSize);
    return true;
}

// ============================================================================
// Component Proxy Userdata
// ============================================================================

typedef struct {
    void *componentPtr;
    const ComponentLayoutDef *layout;
    LifetimeHandle lifetime;
} ComponentProxy;

// Custom properties currently extend component proxies only; StatsObject and
// other userdata keep their existing metatable behavior.
static bool component_proxy_push_custom_type(lua_State *L,
                                             const char *component_name) {
    int base = lua_gettop(L);
    lua_getfield(L, LUA_REGISTRYINDEX, BG3SE_CUSTOM_PROPS_REGISTRY_KEY);
    if (!lua_istable(L, -1)) {
        lua_settop(L, base);
        return false;
    }

    lua_getfield(L, -1, component_name);
    if (!lua_istable(L, -1)) {
        lua_settop(L, base);
        return false;
    }

    lua_remove(L, base + 1);
    return true;
}

static int component_proxy_custom_index(lua_State *L,
                                        const char *component_name,
                                        const char *key) {
    int base = lua_gettop(L);
    if (!component_proxy_push_custom_type(L, component_name)) {
        return 0;
    }

    lua_getfield(L, -1, "functions");
    if (lua_istable(L, -1)) {
        lua_getfield(L, -1, key);
        if (lua_isfunction(L, -1)) {
            lua_replace(L, base + 1);
            lua_settop(L, base + 1);
            return 1;
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1);

    lua_getfield(L, -1, "properties");
    if (lua_istable(L, -1)) {
        lua_getfield(L, -1, key);
        if (lua_istable(L, -1)) {
            lua_getfield(L, -1, "getter");
            if (lua_isfunction(L, -1)) {
                lua_replace(L, base + 1);
                lua_settop(L, base + 1);
                lua_pushvalue(L, 1);
                lua_call(L, 1, 1);
                return 1;
            }
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
    }

    lua_settop(L, base);
    return 0;
}

static int component_proxy_custom_newindex(lua_State *L,
                                           const char *component_name,
                                           const char *key) {
    int base = lua_gettop(L);
    if (!component_proxy_push_custom_type(L, component_name)) {
        return 0;
    }

    lua_getfield(L, -1, "properties");
    if (!lua_istable(L, -1)) {
        lua_settop(L, base);
        return 0;
    }

    lua_getfield(L, -1, key);
    if (!lua_istable(L, -1)) {
        lua_settop(L, base);
        return 0;
    }

    lua_getfield(L, -1, "setter");
    if (!lua_isfunction(L, -1)) {
        lua_settop(L, base);
        return luaL_error(L, "Property '%s' is read-only", key);
    }

    lua_replace(L, base + 1);
    lua_settop(L, base + 1);
    lua_pushvalue(L, 1);
    lua_pushvalue(L, 3);
    lua_call(L, 2, 0);
    return 1;
}

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

    result = component_proxy_custom_index(
        L, proxy->layout->componentName, key);
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

    const ComponentPropertyDef *property = find_property(proxy->layout, key);
    if (!property) {
        int result = component_proxy_custom_newindex(
            L, proxy->layout->componentName, key);
        if (result > 0) {
            return 0;
        }
    }

    /*
     * Norbyte's Windows LightObjectProxyMetatable::NewIndex translates every
     * non-Success property-map result into luaL_error (including read-only and
     * unsupported types).  Keep the same UX: never silently ignore a refused
     * game-memory write.
     */
    if (!property || !component_property_write(
            L, proxy->componentPtr, proxy->layout, key, 3)) {
        return luaL_error(L, "Cannot set component property %s.%s",
                          proxy->layout->componentName, key);
    }

    return 0;
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
    component_property_read_checked(L, proxy->componentPtr, proxy->layout, prop);

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
            push_guid_at(L, (uintptr_t)elemAddr);
            return 1;
        }

        case ELEM_TYPE_FIXED_STRING: {
            uint32_t val = 0;
            if (safe_memory_read_u32((mach_vm_address_t)elemAddr, &val)) {
                push_fixed_string_index(L, val);
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
            push_guid_at(L, (uintptr_t)elemAddr);
            if (!lua_isnil(L, -1)) {
                lua_setfield(L, -2, "ClassUUID");
            } else {
                lua_pop(L, 1);
            }

            // SubClassUUID at offset 16
            push_guid_at(L, (uintptr_t)(elemAddr + 16));
            if (!lua_isnil(L, -1)) {
                lua_setfield(L, -2, "SubClassUUID");
            } else {
                lua_pop(L, 1);
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

            // SpellData and SpellMeta both start with a SpellId struct whose
            // first field is the prototype FixedString: expose its index.
            if (proxy->elemType == ELEM_TYPE_SPELL_DATA ||
                proxy->elemType == ELEM_TYPE_SPELL_META) {
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

static void serialize_array_proxy(lua_State *L, ArrayProxy *proxy) {
    if (!proxy || proxy->elemSize == 0) {
        lua_pushnil(L);
        return;
    }

    void *buf = NULL;
    uint32_t size = 0;
    if (!array_proxy_read_metadata(proxy, &buf, &size) || (size > 0 && !buf)) {
        lua_pushnil(L);
        return;
    }
    if (size > (uint32_t)INT_MAX) {
        LOG_ENTITY_DEBUG("Refusing to serialize implausibly large array (%u elements)",
                         size);
        lua_pushnil(L);
        return;
    }

    lua_createtable(L, (int)size, 0);
    for (uint32_t i = 0; i < size; i++) {
        array_proxy_push_element(L, proxy, buf, i);
        lua_rawseti(L, -2, (lua_Integer)i + 1);
    }
}

bool component_property_serialize_proxy(lua_State *L, int index) {
    int absoluteIndex = lua_absindex(L, index);
    ComponentProxy *component = (ComponentProxy *)luaL_testudata(
        L, absoluteIndex, COMPONENT_PROXY_METATABLE);
    if (component) {
        if (!lifetime_lua_is_valid(L, component->lifetime)) {
            lifetime_lua_expired_error(L, "Component");
            return true;
        }

        lua_createtable(L, 0, component->layout->propertyCount);
        for (int i = 0; i < component->layout->propertyCount; i++) {
            const ComponentPropertyDef *prop = &component->layout->properties[i];
            if (!component_property_read_in_bounds(component->layout, prop)) {
                continue;
            }
            if (prop->type == FIELD_TYPE_DYNAMIC_ARRAY) {
                ArrayProxy array = {
                    .arrayPtr = (char *)component->componentPtr + prop->offset,
                    .elemType = prop->elemType,
                    .elemSize = prop->elemSize,
                    .lifetime = component->lifetime
                };
                serialize_array_proxy(L, &array);
            } else {
                component_property_read_def(
                    L, component->componentPtr, prop);
            }

            if (lua_isnil(L, -1)) {
                lua_pop(L, 1);
            } else {
                lua_setfield(L, -2, prop->name);
            }
        }
        return true;
    }

    ArrayProxy *array = (ArrayProxy *)luaL_testudata(
        L, absoluteIndex, ARRAY_PROXY_METATABLE);
    if (array) {
        if (!lifetime_lua_is_valid(L, array->lifetime)) {
            lifetime_lua_expired_error(L, "Array");
            return true;
        }
        serialize_array_proxy(L, array);
        return true;
    }

    return false;
}

static bool property_can_unserialize(const ComponentLayoutDef *layout,
                                     const ComponentPropertyDef *prop) {
    if (!layout || !prop || prop->readOnly) return false;
    if (strstr(layout->componentName, "OneFrame") != NULL
        || strstr(layout->componentName, "Request") != NULL) {
        return false;
    }
    if (prop->type == FIELD_TYPE_FIXEDSTRING
        || component_property_is_pointer_typed(prop)) {
        return false;
    }
    return component_property_field_size(prop) > 0;
}

bool component_property_unserialize_proxy(lua_State *L, int proxyIndex,
                                          int tableIndex) {
    int absoluteProxy = lua_absindex(L, proxyIndex);
    int absoluteTable = lua_absindex(L, tableIndex);
    ComponentProxy *component = (ComponentProxy *)luaL_testudata(
        L, absoluteProxy, COMPONENT_PROXY_METATABLE);
    if (!component) {
        return false;
    }

    if (!lifetime_lua_is_valid(L, component->lifetime)) {
        lifetime_lua_expired_error(L, "Component");
        return true;
    }

    luaL_checktype(L, absoluteTable, LUA_TTABLE);
    for (int i = 0; i < component->layout->propertyCount; i++) {
        const ComponentPropertyDef *prop = &component->layout->properties[i];
        if (!property_can_unserialize(component->layout, prop)) {
            continue;
        }

        lua_getfield(L, absoluteTable, prop->name);
        if (!lua_isnil(L, -1)
            && !component_property_write(
                L, component->componentPtr, component->layout, prop->name, -1)) {
            return luaL_error(
                L, "Cannot unserialize component property %s.%s",
                component->layout->componentName, prop->name);
        }
        lua_pop(L, 1);
    }

    return true;
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

const ComponentLayoutDef *component_property_get_layout_at(int index) {
    if (index < 0 || index >= g_LayoutCount) {
        return NULL;
    }
    return &g_Layouts[index];
}

void component_property_iterate_layouts(ComponentLayoutIteratorFn callback, void *userdata) {
    if (!callback) return;

    for (int i = 0; i < g_LayoutCount; i++) {
        if (!callback(&g_Layouts[i], userdata)) {
            break;  // Callback returned false, stop iteration
        }
    }
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

const ComponentLayoutDef *component_property_check_proxy_ex(lua_State *L, int index,
                                                            void **outPtr) {
    void *ud = luaL_testudata(L, index, COMPONENT_PROXY_METATABLE);
    if (!ud) return NULL;
    ComponentProxy *proxy = (ComponentProxy *)ud;
    if (!lifetime_lua_is_valid(L, proxy->lifetime)) return NULL;
    if (outPtr) *outPtr = proxy->componentPtr;
    return proxy->layout;
}
