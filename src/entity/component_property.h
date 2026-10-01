/**
 * BG3SE-macOS - Component Property Access System
 *
 * Provides data-driven property access for ECS components.
 * Components are wrapped in proxy userdata with __index metamethods
 * that safely read memory at defined offsets.
 */

#ifndef COMPONENT_PROPERTY_H
#define COMPONENT_PROPERTY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// Forward declare lua_State
struct lua_State;
typedef struct lua_State lua_State;

#define BG3SE_CUSTOM_PROPS_REGISTRY_KEY "BG3SE_CustomProps"

// ============================================================================
// Field Types
// ============================================================================

typedef enum {
    FIELD_TYPE_INT8,
    FIELD_TYPE_UINT8,
    FIELD_TYPE_INT16,
    FIELD_TYPE_UINT16,
    FIELD_TYPE_INT32,
    FIELD_TYPE_UINT32,
    FIELD_TYPE_INT64,
    FIELD_TYPE_UINT64,
    FIELD_TYPE_BOOL,
    FIELD_TYPE_FLOAT,
    FIELD_TYPE_DOUBLE,
    FIELD_TYPE_FIXEDSTRING,     // uint32_t index -> resolve to string
    FIELD_TYPE_GUID,            // 16-byte UUID
    FIELD_TYPE_ENTITY_HANDLE,   // uint64_t
    FIELD_TYPE_VEC3,            // float[3]
    FIELD_TYPE_VEC4,            // float[4]
    FIELD_TYPE_INT32_ARRAY,     // Fixed-size int32 array
    FIELD_TYPE_FLOAT_ARRAY,     // Fixed-size float array
    FIELD_TYPE_DYNAMIC_ARRAY,   // Dynamic Array<T> with runtime size
} FieldType;

// ============================================================================
// Element Types for Dynamic Arrays
// ============================================================================

typedef enum {
    ELEM_TYPE_UNKNOWN = 0,      // Raw bytes (element size required)
    ELEM_TYPE_SPELL_DATA,       // spell::SpellData (0x68 bytes on ARM64)
    ELEM_TYPE_SPELL_META,       // spell::SpellMeta (96 bytes / 0x60 on ARM64, live-verified 7398727)
    ELEM_TYPE_STATUS_INFO,      // Generic status info
    ELEM_TYPE_GUID,             // Array of GUIDs
    ELEM_TYPE_FIXED_STRING,     // Array of FixedStrings (indices)
    ELEM_TYPE_ENTITY_HANDLE,    // Array of EntityHandles
    ELEM_TYPE_CLASS_INFO,       // ClassInfo (40 bytes: ClassUUID + SubClassUUID + Level)
    ELEM_TYPE_BOOST_ENTRY,      // BoostEntry (24 bytes: BoostType + Array<EntityHandle>)
} ArrayElementType;

// ============================================================================
// Property Definition
// ============================================================================

typedef struct {
    const char *name;       // Property name (e.g., "Hp", "MaxHp")
    uint16_t offset;        // Byte offset from component base
    FieldType type;         // Data type
    uint8_t arraySize;      // For fixed array types (0 = not fixed array)
    bool readOnly;          // Prevent writes
    // For FIELD_TYPE_DYNAMIC_ARRAY:
    ArrayElementType elemType;  // Element type for formatting
    uint16_t elemSize;          // Element size in bytes
} ComponentPropertyDef;

// ============================================================================
// Component Layout Definition
// ============================================================================

typedef struct {
    const char *componentName;              // Full name (e.g., "eoc::HealthComponent")
    const char *shortName;                  // Short name for Lua access (e.g., "Health")
    uint16_t componentTypeIndex;            // From TypeId discovery (0 = not set)
    uint16_t componentSize;                 // Total struct size (for bounds checking)
    const ComponentPropertyDef *properties;
    int propertyCount;
    bool generated;                         // Unverified generated-property layout
} ComponentLayoutDef;

// ============================================================================
// Initialization
// ============================================================================

/**
 * Initialize the component property system.
 * Registers all built-in component layouts from component_offsets.h.
 * Call once during startup.
 */
bool component_property_init(void);

/**
 * Register Lua metatables for component proxies.
 * Must be called after lua_State is created.
 */
void component_property_register_lua(lua_State *L);

// ============================================================================
// Layout Registration & Lookup
// ============================================================================

/**
 * Register a component layout.
 * Returns true on success, false if registry is full.
 */
bool component_property_register_layout(const ComponentLayoutDef *layout);

/**
 * Look up layout by full component name (e.g., "eoc::HealthComponent").
 * Returns NULL if not found.
 */
const ComponentLayoutDef *component_property_get_layout(const char *componentName);

/**
 * Look up layout by short name (e.g., "Health").
 * Returns NULL if not found.
 */
const ComponentLayoutDef *component_property_get_layout_by_short_name(const char *shortName);

/**
 * Look up layout by TypeId index.
 * Returns NULL if not found.
 */
const ComponentLayoutDef *component_property_get_layout_by_index(uint16_t typeIndex);

/**
 * Update a layout's TypeId index (called when TypeIds are discovered).
 */
void component_property_set_type_index(const char *componentName, uint16_t typeIndex);

// ============================================================================
// Property Reading
// ============================================================================

/**
 * Read a property value from component data and push to Lua stack.
 *
 * @param L           Lua state
 * @param componentPtr Raw pointer to component data
 * @param layout      Component layout definition
 * @param propertyName Property name to read
 * @return Number of values pushed to stack (0 = property not found)
 */
int component_property_read(lua_State *L, void *componentPtr,
                            const ComponentLayoutDef *layout,
                            const char *propertyName);

/**
 * Read a property by definition (faster, no name lookup).
 */
int component_property_read_def(lua_State *L, void *componentPtr,
                                const ComponentPropertyDef *prop);

/** Bytes a property occupies (0 = unknown width). Shared by the reader
 * and the tier-0 bounds sweep so both check the same widths. */
static inline size_t component_field_type_width(const ComponentPropertyDef *prop) {
    if (!prop) return 0;
    switch (prop->type) {
        case FIELD_TYPE_INT8: case FIELD_TYPE_UINT8: case FIELD_TYPE_BOOL:
            return 1;
        case FIELD_TYPE_INT16: case FIELD_TYPE_UINT16:
            return 2;
        case FIELD_TYPE_INT32: case FIELD_TYPE_UINT32:
        case FIELD_TYPE_FLOAT: case FIELD_TYPE_FIXEDSTRING:
            return 4;
        case FIELD_TYPE_INT64: case FIELD_TYPE_UINT64:
        case FIELD_TYPE_DOUBLE: case FIELD_TYPE_ENTITY_HANDLE:
            return 8;
        case FIELD_TYPE_VEC3:
            return 12;
        case FIELD_TYPE_GUID: case FIELD_TYPE_VEC4:
        case FIELD_TYPE_DYNAMIC_ARRAY:   // buf + capacity + size header
            return 16;
        case FIELD_TYPE_INT32_ARRAY: case FIELD_TYPE_FLOAT_ARRAY:
            return (size_t)prop->arraySize * 4;
        default:
            return 0;
    }
}

/** False (and counted) when a read would leave the layout's recorded size. */
bool component_property_read_in_bounds(const ComponentLayoutDef *layout,
                                       const ComponentPropertyDef *prop);

/** How many reads were refused for leaving their component. */
uint64_t component_property_read_bounds_refused(void);

// ============================================================================
// Property Writing
// ============================================================================

/**
 * Write a property value from Lua stack to component data.
 * Returns false when the property is missing, unsafe, read-only, unsupported,
 * out of bounds, or the safe-memory write fails.
 */
bool component_property_write(lua_State *L, void *componentPtr,
                              const ComponentLayoutDef *layout,
                              const char *propertyName, int valueIndex);

// ============================================================================
// Component Proxy Userdata
// ============================================================================

/**
 * Create a component proxy userdata and push to Lua stack.
 * The proxy wraps the raw component pointer and provides __index access.
 */
void component_property_push_proxy(lua_State *L, void *componentPtr,
                                   const ComponentLayoutDef *layout);

/**
 * Check if a value on the Lua stack is a component proxy.
 * Returns the layout if it is, NULL otherwise.
 */
const ComponentLayoutDef *component_property_check_proxy(lua_State *L, int index);

/**
 * Serialize a component or dynamic-array proxy to a plain Lua table.
 *
 * @return true when index is a supported proxy and one table was pushed;
 *         false when index is not a supported proxy.
 */
bool component_property_serialize_proxy(lua_State *L, int index);

/**
 * Apply fields from a Lua table to a component proxy.
 *
 * Read-only and ownership-bearing fields are skipped. Writable scalar fields
 * use the same bounds-checked path as ComponentProxy.__newindex.
 *
 * @return true when proxyIndex is a component proxy; false otherwise.
 *         A refused field write raises a Lua error.
 */
bool component_property_unserialize_proxy(lua_State *L, int proxyIndex,
                                          int tableIndex);

// ============================================================================
// Array Proxy (for FIELD_TYPE_DYNAMIC_ARRAY)
// ============================================================================

/**
 * Create an array proxy userdata and push to Lua stack.
 * The proxy wraps a dynamic Array<T> and provides __index/__len/__pairs.
 *
 * @param L           Lua state
 * @param arrayPtr    Pointer to the Array<T> (buf_/capacity_/size_ struct)
 * @param prop        Property definition with element type/size info
 */
void component_property_push_array_proxy(lua_State *L, void *arrayPtr,
                                         const ComponentPropertyDef *prop);

// ============================================================================
// Debugging
// ============================================================================

/**
 * Get the number of registered layouts.
 */
int component_property_get_layout_count(void);

/**
 * Get layout by index (for iteration).
 * Returns NULL if index out of bounds.
 */
const ComponentLayoutDef *component_property_get_layout_at(int index);

/**
 * Iterate over all registered layouts.
 * Callback returns true to continue, false to stop.
 */
typedef bool (*ComponentLayoutIteratorFn)(const ComponentLayoutDef *layout, void *userdata);
void component_property_iterate_layouts(ComponentLayoutIteratorFn callback, void *userdata);

/**
 * Dump all registered layouts to log.
 */
void component_property_dump_layouts(void);

#endif // COMPONENT_PROPERTY_H
