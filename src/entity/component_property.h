/**
 * BG3SE-macOS - Component Property Access System
 *
 * Provides data-driven property access for ECS components.
 * Components are wrapped in proxy userdata with __index metamethods
 * that safely read memory at defined offsets.
 */

#ifndef COMPONENT_PROPERTY_H
#define COMPONENT_PROPERTY_H

#include <stdint.h>
#include <stdbool.h>

// Forward declare lua_State
struct lua_State;
typedef struct lua_State lua_State;

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
    ELEM_TYPE_SPELL_DATA,       // spell::SpellData (88 bytes on ARM64)
    ELEM_TYPE_SPELL_META,       // spell::SpellMeta (80 bytes)
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

// ============================================================================
// Property Writing (Future)
// ============================================================================

/**
 * Write a property value from Lua stack to component data.
 * Currently not implemented - returns false.
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
 * Dump all registered layouts to log.
 */
void component_property_dump_layouts(void);

#endif // COMPONENT_PROPERTY_H
