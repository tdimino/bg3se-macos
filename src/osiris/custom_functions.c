/**
 * BG3SE-macOS - Custom Osiris Function Registry Implementation
 */

#include "custom_functions.h"
#include "logging.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <lauxlib.h>

// ============================================================================
// Internal State
// ============================================================================

static CustomFunction g_custom_functions[MAX_CUSTOM_FUNCTIONS];
static int g_custom_func_count = 0;
static uint32_t g_next_custom_id = CUSTOM_FUNC_ID_BASE;

// ============================================================================
// Internal Helpers
// ============================================================================

/**
 * Parse an Osiris type string to OsiValueType.
 */
static uint8_t parse_osi_type(const char *type_str) {
    if (strcmp(type_str, "INTEGER") == 0) return OSI_TYPE_INTEGER;
    if (strcmp(type_str, "INTEGER64") == 0) return OSI_TYPE_INTEGER64;
    if (strcmp(type_str, "REAL") == 0) return OSI_TYPE_REAL;
    if (strcmp(type_str, "STRING") == 0) return OSI_TYPE_STRING;
    if (strcmp(type_str, "GUIDSTRING") == 0) return OSI_TYPE_GUIDSTRING;
    return OSI_TYPE_NONE;
}

/**
 * Parse a Windows BG3SE style signature.
 * Format: "[in](TYPE)_Name,[out](TYPE)_Name,..."
 *
 * Examples:
 *   "[in](GUIDSTRING)_Target,[out](INTEGER)_Health"
 *   "(STRING)_Message"  -- defaults to [in]
 *   "[out](INTEGER)_Value"
 */
static bool parse_signature(const char *signature, CustomFunction *func) {
    if (!signature || !func) return false;

    func->arity = 0;
    func->num_in_params = 0;
    func->num_out_params = 0;

    // Empty signature is valid (no params)
    if (signature[0] == '\0') {
        return true;
    }

    char sig_copy[512];
    strncpy(sig_copy, signature, sizeof(sig_copy) - 1);
    sig_copy[sizeof(sig_copy) - 1] = '\0';

    char *saveptr = NULL;
    char *token = strtok_r(sig_copy, ",", &saveptr);

    while (token && func->arity < MAX_CUSTOM_FUNC_PARAMS) {
        CustomFuncParam *param = &func->params[func->arity];

        // Skip leading whitespace
        while (*token && isspace(*token)) token++;

        // Parse direction: [in] or [out], defaults to [in]
        CustomParamDirection dir = CUSTOM_PARAM_IN;
        if (strncmp(token, "[in]", 4) == 0) {
            dir = CUSTOM_PARAM_IN;
            token += 4;
        } else if (strncmp(token, "[out]", 5) == 0) {
            dir = CUSTOM_PARAM_OUT;
            token += 5;
        }
        param->direction = dir;

        // Parse type: (TYPE)
        if (*token != '(') {
            LOG_OSIRIS_ERROR("Invalid signature: expected '(' at '%s'", token);
            return false;
        }
        token++;  // Skip '('

        char *type_end = strchr(token, ')');
        if (!type_end) {
            LOG_OSIRIS_ERROR("Invalid signature: missing ')' in type");
            return false;
        }

        // Extract type string
        size_t type_len = type_end - token;
        char type_str[32];
        if (type_len >= sizeof(type_str)) type_len = sizeof(type_str) - 1;
        strncpy(type_str, token, type_len);
        type_str[type_len] = '\0';

        param->type = parse_osi_type(type_str);
        if (param->type == OSI_TYPE_NONE) {
            LOG_OSIRIS_ERROR("Invalid signature: unknown type '%s'", type_str);
            return false;
        }

        token = type_end + 1;  // Skip ')'

        // Parse name: _Name
        if (*token == '_') token++;  // Skip optional '_'

        // Copy name until end or whitespace
        size_t name_len = 0;
        while (token[name_len] && !isspace(token[name_len]) && token[name_len] != ',') {
            name_len++;
        }
        if (name_len >= MAX_CUSTOM_PARAM_NAME_LEN) {
            name_len = MAX_CUSTOM_PARAM_NAME_LEN - 1;
        }
        strncpy(param->name, token, name_len);
        param->name[name_len] = '\0';

        // Update counts
        if (dir == CUSTOM_PARAM_IN) {
            func->num_in_params++;
        } else {
            func->num_out_params++;
        }
        func->arity++;

        token = strtok_r(NULL, ",", &saveptr);
    }

    return true;
}

/**
 * Push an Osiris argument value onto the Lua stack.
 */
static void push_osi_value_to_lua(lua_State *L, OsiArgumentValue *val) {
    switch (val->typeId) {
        case OSI_TYPE_INTEGER:
            lua_pushinteger(L, val->int32Val);
            break;
        case OSI_TYPE_INTEGER64:
            lua_pushinteger(L, val->int64Val);
            break;
        case OSI_TYPE_REAL:
            lua_pushnumber(L, val->floatVal);
            break;
        case OSI_TYPE_STRING:
        case OSI_TYPE_GUIDSTRING:
            if (val->stringVal) {
                lua_pushstring(L, val->stringVal);
            } else {
                lua_pushnil(L);
            }
            break;
        default:
            lua_pushnil(L);
            break;
    }
}

/**
 * Pop a Lua value and store it in an Osiris argument.
 */
static bool pop_lua_to_osi_value(lua_State *L, int idx, OsiArgumentValue *val, uint8_t expected_type) {
    val->typeId = expected_type;

    switch (expected_type) {
        case OSI_TYPE_INTEGER:
            if (!lua_isinteger(L, idx) && !lua_isnumber(L, idx)) {
                LOG_OSIRIS_ERROR("Expected integer at return position %d", idx);
                return false;
            }
            val->int32Val = (int32_t)lua_tointeger(L, idx);
            break;

        case OSI_TYPE_INTEGER64:
            if (!lua_isinteger(L, idx) && !lua_isnumber(L, idx)) {
                LOG_OSIRIS_ERROR("Expected integer64 at return position %d", idx);
                return false;
            }
            val->int64Val = lua_tointeger(L, idx);
            break;

        case OSI_TYPE_REAL:
            if (!lua_isnumber(L, idx)) {
                LOG_OSIRIS_ERROR("Expected number at return position %d", idx);
                return false;
            }
            val->floatVal = (float)lua_tonumber(L, idx);
            break;

        case OSI_TYPE_STRING:
        case OSI_TYPE_GUIDSTRING:
            if (!lua_isstring(L, idx) && !lua_isnil(L, idx)) {
                LOG_OSIRIS_ERROR("Expected string at return position %d", idx);
                return false;
            }
            if (lua_isnil(L, idx)) {
                val->stringVal = NULL;
            } else {
                // Note: Osiris expects a persistent string; we'll need to handle
                // memory management carefully here. For now, duplicate the string.
                const char *str = lua_tostring(L, idx);
                val->stringVal = strdup(str);
            }
            break;

        default:
            LOG_OSIRIS_ERROR("Unknown type %d at return position %d", expected_type, idx);
            return false;
    }

    return true;
}

// ============================================================================
// Public API - Initialization
// ============================================================================

void custom_func_init(void) {
    memset(g_custom_functions, 0, sizeof(g_custom_functions));
    g_custom_func_count = 0;
    g_next_custom_id = CUSTOM_FUNC_ID_BASE;
    LOG_OSIRIS_INFO("Custom function registry initialized");
}

// ============================================================================
// Public API - Registration
// ============================================================================

uint32_t custom_func_register(const char *name, CustomFuncType type,
                              int callback_ref, const char *signature) {
    if (!name || name[0] == '\0') {
        LOG_OSIRIS_ERROR("custom_func_register: name is required");
        return 0;
    }

    if (g_custom_func_count >= MAX_CUSTOM_FUNCTIONS) {
        LOG_OSIRIS_ERROR("custom_func_register: max functions reached (%d)",
                        MAX_CUSTOM_FUNCTIONS);
        return 0;
    }

    // Check for duplicate name
    if (custom_func_get_by_name(name) != NULL) {
        LOG_OSIRIS_ERROR("custom_func_register: function '%s' already registered", name);
        return 0;
    }

    // Find a free slot
    CustomFunction *func = NULL;
    for (int i = 0; i < MAX_CUSTOM_FUNCTIONS; i++) {
        if (!g_custom_functions[i].registered) {
            func = &g_custom_functions[i];
            break;
        }
    }

    if (!func) {
        LOG_OSIRIS_ERROR("custom_func_register: no free slots");
        return 0;
    }

    // Initialize the function
    memset(func, 0, sizeof(CustomFunction));
    strncpy(func->name, name, MAX_CUSTOM_FUNC_NAME_LEN - 1);
    func->name[MAX_CUSTOM_FUNC_NAME_LEN - 1] = '\0';
    func->type = type;
    func->callback_ref = callback_ref;
    func->assigned_id = g_next_custom_id++;

    // Parse signature
    if (signature && !parse_signature(signature, func)) {
        LOG_OSIRIS_ERROR("custom_func_register: failed to parse signature '%s'", signature);
        return 0;
    }

    // Validate: queries must have at least one OUT param
    if (type == CUSTOM_FUNC_QUERY && func->num_out_params == 0) {
        LOG_OSIRIS_WARN("custom_func_register: query '%s' has no OUT params", name);
    }

    // Validate: events should not have OUT params
    if (type == CUSTOM_FUNC_EVENT && func->num_out_params > 0) {
        LOG_OSIRIS_ERROR("custom_func_register: event '%s' cannot have OUT params", name);
        return 0;
    }

    func->registered = true;
    g_custom_func_count++;

    const char *type_str = (type == CUSTOM_FUNC_CALL) ? "Call" :
                          (type == CUSTOM_FUNC_QUERY) ? "Query" : "Event";
    LOG_OSIRIS_INFO("Registered custom %s: %s (ID=0x%x, arity=%d, in=%d, out=%d)",
                   type_str, name, func->assigned_id, func->arity,
                   func->num_in_params, func->num_out_params);

    return func->assigned_id;
}

bool custom_func_unregister(uint32_t funcId) {
    CustomFunction *func = custom_func_get_by_id(funcId);
    if (!func) return false;

    LOG_OSIRIS_INFO("Unregistered custom function: %s (ID=0x%x)", func->name, funcId);
    func->registered = false;
    g_custom_func_count--;
    return true;
}

// ============================================================================
// Public API - Lookup
// ============================================================================

bool custom_func_is_custom(uint32_t funcId) {
    return funcId >= CUSTOM_FUNC_ID_BASE;
}

CustomFunction *custom_func_get_by_id(uint32_t funcId) {
    if (!custom_func_is_custom(funcId)) return NULL;

    for (int i = 0; i < MAX_CUSTOM_FUNCTIONS; i++) {
        if (g_custom_functions[i].registered &&
            g_custom_functions[i].assigned_id == funcId) {
            return &g_custom_functions[i];
        }
    }
    return NULL;
}

CustomFunction *custom_func_get_by_name(const char *name) {
    if (!name) return NULL;

    for (int i = 0; i < MAX_CUSTOM_FUNCTIONS; i++) {
        if (g_custom_functions[i].registered &&
            strcmp(g_custom_functions[i].name, name) == 0) {
            return &g_custom_functions[i];
        }
    }
    return NULL;
}

// ============================================================================
// Public API - Invocation
// ============================================================================

int custom_func_call(lua_State *L, uint32_t funcId, OsiArgumentDesc *args) {
    CustomFunction *func = custom_func_get_by_id(funcId);
    if (!func) {
        LOG_OSIRIS_ERROR("custom_func_call: unknown function ID 0x%x", funcId);
        return 0;
    }

    if (func->callback_ref == LUA_NOREF || func->callback_ref == LUA_REFNIL) {
        LOG_OSIRIS_ERROR("custom_func_call: no callback for '%s'", func->name);
        return 0;
    }

    // Push the callback function
    lua_rawgeti(L, LUA_REGISTRYINDEX, func->callback_ref);
    if (!lua_isfunction(L, -1)) {
        LOG_OSIRIS_ERROR("custom_func_call: callback for '%s' is not a function", func->name);
        lua_pop(L, 1);
        return 0;
    }

    // Push IN arguments
    int nargs = 0;
    OsiArgumentDesc *arg = args;
    for (uint32_t i = 0; i < func->arity && arg; i++) {
        if (func->params[i].direction == CUSTOM_PARAM_IN) {
            push_osi_value_to_lua(L, &arg->value);
            nargs++;
        }
        arg = arg->nextParam;
    }

    // Call the function
    if (lua_pcall(L, nargs, 0, 0) != LUA_OK) {
        const char *err = lua_tostring(L, -1);
        LOG_OSIRIS_ERROR("custom_func_call '%s' error: %s", func->name, err ? err : "(unknown)");
        lua_pop(L, 1);
        return 0;
    }

    return 1;
}

int custom_func_query(lua_State *L, uint32_t funcId, OsiArgumentDesc *args) {
    CustomFunction *func = custom_func_get_by_id(funcId);
    if (!func) {
        LOG_OSIRIS_ERROR("custom_func_query: unknown function ID 0x%x", funcId);
        return 0;
    }

    if (func->callback_ref == LUA_NOREF || func->callback_ref == LUA_REFNIL) {
        LOG_OSIRIS_ERROR("custom_func_query: no callback for '%s'", func->name);
        return 0;
    }

    // Push the callback function
    lua_rawgeti(L, LUA_REGISTRYINDEX, func->callback_ref);
    if (!lua_isfunction(L, -1)) {
        LOG_OSIRIS_ERROR("custom_func_query: callback for '%s' is not a function", func->name);
        lua_pop(L, 1);
        return 0;
    }

    // Push IN arguments
    int nargs = 0;
    OsiArgumentDesc *arg = args;
    for (uint32_t i = 0; i < func->arity && arg; i++) {
        if (func->params[i].direction == CUSTOM_PARAM_IN) {
            push_osi_value_to_lua(L, &arg->value);
            nargs++;
        }
        arg = arg->nextParam;
    }

    // Call the function, expecting num_out_params return values
    int nresults = func->num_out_params;
    if (lua_pcall(L, nargs, nresults, 0) != LUA_OK) {
        const char *err = lua_tostring(L, -1);
        LOG_OSIRIS_ERROR("custom_func_query '%s' error: %s", func->name, err ? err : "(unknown)");
        lua_pop(L, 1);
        return 0;
    }

    // Return values are left on the Lua stack for the caller to use
    // The caller (osi_dynamic_call) will return them to the Lua script
    // Note: We don't fill OsiArgumentDesc OUT params here since we're
    // returning directly to Lua, not to Osiris

    return 1;  // Success - results are on Lua stack
}

// ============================================================================
// Public API - Lifecycle
// ============================================================================

void custom_func_clear(lua_State *L) {
    int cleared = 0;
    for (int i = 0; i < MAX_CUSTOM_FUNCTIONS; i++) {
        if (g_custom_functions[i].registered) {
            // Release Lua callback reference
            if (L && g_custom_functions[i].callback_ref != LUA_NOREF &&
                g_custom_functions[i].callback_ref != LUA_REFNIL) {
                luaL_unref(L, LUA_REGISTRYINDEX, g_custom_functions[i].callback_ref);
            }
            g_custom_functions[i].registered = false;
            cleared++;
        }
    }

    g_custom_func_count = 0;
    // Note: Don't reset g_next_custom_id to avoid ID reuse issues

    if (cleared > 0) {
        LOG_OSIRIS_INFO("Cleared %d custom functions", cleared);
    }
}

int custom_func_get_count(void) {
    return g_custom_func_count;
}

// ============================================================================
// Public API - Debugging
// ============================================================================

void custom_func_dump(void) {
    LOG_OSIRIS_INFO("=== Custom Functions (%d registered) ===", g_custom_func_count);
    for (int i = 0; i < MAX_CUSTOM_FUNCTIONS; i++) {
        CustomFunction *func = &g_custom_functions[i];
        if (!func->registered) continue;

        const char *type_str = (func->type == CUSTOM_FUNC_CALL) ? "Call" :
                              (func->type == CUSTOM_FUNC_QUERY) ? "Query" : "Event";

        LOG_OSIRIS_INFO("  [%d] %s %s (ID=0x%x, in=%d, out=%d)",
                       i, type_str, func->name, func->assigned_id,
                       func->num_in_params, func->num_out_params);

        for (uint32_t j = 0; j < func->arity; j++) {
            CustomFuncParam *p = &func->params[j];
            const char *dir_str = (p->direction == CUSTOM_PARAM_IN) ? "in" : "out";
            const char *type_name = "";
            switch (p->type) {
                case OSI_TYPE_INTEGER: type_name = "INTEGER"; break;
                case OSI_TYPE_INTEGER64: type_name = "INTEGER64"; break;
                case OSI_TYPE_REAL: type_name = "REAL"; break;
                case OSI_TYPE_STRING: type_name = "STRING"; break;
                case OSI_TYPE_GUIDSTRING: type_name = "GUIDSTRING"; break;
                default: type_name = "UNKNOWN"; break;
            }
            LOG_OSIRIS_INFO("      [%s](%s) %s", dir_str, type_name, p->name);
        }
    }
    LOG_OSIRIS_INFO("=======================================");
}
