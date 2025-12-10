/**
 * BG3SE-macOS - Custom Osiris Function Registry
 *
 * Allows Lua mods to register custom Osiris functions (calls, queries, events)
 * that can be invoked via the Osi.* namespace.
 */

#ifndef BG3SE_CUSTOM_FUNCTIONS_H
#define BG3SE_CUSTOM_FUNCTIONS_H

#include <stdint.h>
#include <stdbool.h>
#include <lua.h>
#include "osiris_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Constants
// ============================================================================

#define MAX_CUSTOM_FUNCTIONS 256
#define MAX_CUSTOM_FUNC_PARAMS 16
#define MAX_CUSTOM_FUNC_NAME_LEN 128
#define MAX_CUSTOM_PARAM_NAME_LEN 64

// Custom function IDs start at this base to avoid collision with game IDs
// Game function IDs observed in range 0-2M, so 0xF0000000+ is safe
#define CUSTOM_FUNC_ID_BASE 0xF0000000

// ============================================================================
// Types
// ============================================================================

/**
 * Custom function type
 */
typedef enum {
    CUSTOM_FUNC_CALL = 1,    // No return value, like Osi calls
    CUSTOM_FUNC_QUERY = 2,   // Returns values via OUT params
    CUSTOM_FUNC_EVENT = 3    // Can be raised from Lua, triggers Osiris event
} CustomFuncType;

/**
 * Parameter direction
 */
typedef enum {
    CUSTOM_PARAM_IN = 0,     // Input parameter
    CUSTOM_PARAM_OUT = 1     // Output parameter (for queries)
} CustomParamDirection;

/**
 * Custom function parameter definition
 */
typedef struct {
    char name[MAX_CUSTOM_PARAM_NAME_LEN];
    uint8_t type;            // OsiValueType (INTEGER, STRING, etc.)
    uint8_t direction;       // CustomParamDirection
} CustomFuncParam;

/**
 * Custom function definition
 */
typedef struct {
    char name[MAX_CUSTOM_FUNC_NAME_LEN];
    CustomFuncType type;
    int callback_ref;        // Lua registry reference (-1 if no callback, e.g., events)
    uint32_t arity;          // Total number of parameters
    uint32_t num_in_params;  // Number of IN parameters
    uint32_t num_out_params; // Number of OUT parameters
    CustomFuncParam params[MAX_CUSTOM_FUNC_PARAMS];
    uint32_t assigned_id;    // Assigned Osiris function ID
    bool registered;         // Is this slot in use?
} CustomFunction;

// ============================================================================
// Initialization
// ============================================================================

/**
 * Initialize the custom function system.
 * Call once at startup.
 */
void custom_func_init(void);

// ============================================================================
// Registration
// ============================================================================

/**
 * Register a custom Osiris function.
 *
 * @param name Function name (e.g., "MyMod_GetHealth")
 * @param type Function type (CALL, QUERY, or EVENT)
 * @param callback_ref Lua registry reference for callback (-1 for events)
 * @param signature Windows BG3SE style signature, e.g.:
 *                  "[in](GUIDSTRING)_Target,[out](INTEGER)_Health"
 * @return Assigned function ID, or 0 on failure
 */
uint32_t custom_func_register(const char *name, CustomFuncType type,
                              int callback_ref, const char *signature);

/**
 * Unregister a custom function by ID.
 *
 * @param funcId Function ID to unregister
 * @return true if found and unregistered, false otherwise
 */
bool custom_func_unregister(uint32_t funcId);

// ============================================================================
// Lookup
// ============================================================================

/**
 * Check if a function ID is a custom function.
 *
 * @param funcId Function ID to check
 * @return true if this is a custom function ID
 */
bool custom_func_is_custom(uint32_t funcId);

/**
 * Get a custom function by its assigned ID.
 *
 * @param funcId Function ID
 * @return Pointer to function definition, or NULL if not found
 */
CustomFunction *custom_func_get_by_id(uint32_t funcId);

/**
 * Get a custom function by name.
 *
 * @param name Function name
 * @return Pointer to function definition, or NULL if not found
 */
CustomFunction *custom_func_get_by_name(const char *name);

// ============================================================================
// Invocation
// ============================================================================

/**
 * Invoke a custom call function.
 * Calls the Lua callback with IN parameters.
 *
 * @param L Lua state
 * @param funcId Custom function ID
 * @param args Osiris argument list
 * @return 1 on success, 0 on failure
 */
int custom_func_call(lua_State *L, uint32_t funcId, OsiArgumentDesc *args);

/**
 * Invoke a custom query function.
 * Calls the Lua callback with IN parameters, fills OUT params with return values.
 *
 * @param L Lua state
 * @param funcId Custom function ID
 * @param args Osiris argument list (OUT params will be filled)
 * @return 1 on success, 0 on failure
 */
int custom_func_query(lua_State *L, uint32_t funcId, OsiArgumentDesc *args);

// ============================================================================
// Lifecycle
// ============================================================================

/**
 * Clear all registered custom functions.
 * Should be called on session reset.
 *
 * @param L Lua state (to release callback references)
 */
void custom_func_clear(lua_State *L);

/**
 * Get the count of registered custom functions.
 */
int custom_func_get_count(void);

// ============================================================================
// Debugging
// ============================================================================

/**
 * Log all registered custom functions.
 */
void custom_func_dump(void);

#ifdef __cplusplus
}
#endif

#endif // BG3SE_CUSTOM_FUNCTIONS_H
