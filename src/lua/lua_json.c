/**
 * BG3SE-macOS - Lua JSON Module Implementation
 *
 * Simple JSON parser and stringifier for Lua integration.
 */

#include "lua_json.h"
#include "logging.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// ============================================================================
// Internal Helpers
// ============================================================================

static const char *json_skip_whitespace(const char *json) {
    while (*json && (*json == ' ' || *json == '\t' || *json == '\n' || *json == '\r')) {
        json++;
    }
    return json;
}

static const char *json_parse_string(lua_State *L, const char *json) {
    if (*json != '"') return NULL;
    json++;  // skip opening quote

    luaL_Buffer b;
    luaL_buffinit(L, &b);

    while (*json && *json != '"') {
        if (*json == '\\' && json[1]) {
            json++;
            switch (*json) {
                case '"': luaL_addchar(&b, '"'); break;
                case '\\': luaL_addchar(&b, '\\'); break;
                case '/': luaL_addchar(&b, '/'); break;
                case 'b': luaL_addchar(&b, '\b'); break;
                case 'f': luaL_addchar(&b, '\f'); break;
                case 'n': luaL_addchar(&b, '\n'); break;
                case 'r': luaL_addchar(&b, '\r'); break;
                case 't': luaL_addchar(&b, '\t'); break;
                default: luaL_addchar(&b, *json); break;
            }
        } else {
            luaL_addchar(&b, *json);
        }
        json++;
    }

    if (*json != '"') return NULL;
    luaL_pushresult(&b);
    return json + 1;  // skip closing quote
}

static const char *json_parse_number(lua_State *L, const char *json) {
    const char *start = json;
    if (*json == '-') json++;
    while (*json >= '0' && *json <= '9') json++;
    if (*json == '.') {
        json++;
        while (*json >= '0' && *json <= '9') json++;
    }
    if (*json == 'e' || *json == 'E') {
        json++;
        if (*json == '+' || *json == '-') json++;
        while (*json >= '0' && *json <= '9') json++;
    }

    char *endptr;
    double num = strtod(start, &endptr);
    lua_pushnumber(L, num);
    return json;
}

static const char *json_parse_object(lua_State *L, const char *json) {
    if (*json != '{') return NULL;
    json = json_skip_whitespace(json + 1);

    lua_newtable(L);

    if (*json == '}') return json + 1;

    while (1) {
        json = json_skip_whitespace(json);
        if (*json != '"') return NULL;

        // Parse key
        json = json_parse_string(L, json);
        if (!json) return NULL;

        json = json_skip_whitespace(json);
        if (*json != ':') return NULL;
        json = json_skip_whitespace(json + 1);

        // Parse value
        json = json_parse_value(L, json);
        if (!json) return NULL;

        // Set table[key] = value
        lua_settable(L, -3);

        json = json_skip_whitespace(json);
        if (*json == '}') return json + 1;
        if (*json != ',') return NULL;
        json++;
    }
}

static const char *json_parse_array(lua_State *L, const char *json) {
    if (*json != '[') return NULL;
    json = json_skip_whitespace(json + 1);

    lua_newtable(L);
    int index = 1;

    if (*json == ']') return json + 1;

    while (1) {
        json = json_skip_whitespace(json);
        json = json_parse_value(L, json);
        if (!json) return NULL;

        lua_rawseti(L, -2, index++);

        json = json_skip_whitespace(json);
        if (*json == ']') return json + 1;
        if (*json != ',') return NULL;
        json++;
    }
}

// ============================================================================
// Public Parsing Functions
// ============================================================================

const char *json_parse_value(lua_State *L, const char *json) {
    json = json_skip_whitespace(json);

    if (*json == '"') {
        return json_parse_string(L, json);
    } else if (*json == '{') {
        return json_parse_object(L, json);
    } else if (*json == '[') {
        return json_parse_array(L, json);
    } else if (*json == 't' && strncmp(json, "true", 4) == 0) {
        lua_pushboolean(L, 1);
        return json + 4;
    } else if (*json == 'f' && strncmp(json, "false", 5) == 0) {
        lua_pushboolean(L, 0);
        return json + 5;
    } else if (*json == 'n' && strncmp(json, "null", 4) == 0) {
        lua_pushnil(L);
        return json + 4;
    } else if (*json == '-' || (*json >= '0' && *json <= '9')) {
        return json_parse_number(L, json);
    }

    return NULL;
}

// ============================================================================
// Stringify Functions
// ============================================================================

static void json_stringify_table(lua_State *L, int index, luaL_Buffer *b) {
    // Check if it's an array (sequential integer keys starting from 1)
    int is_array = 1;
    int max_index = 0;

    lua_pushnil(L);
    while (lua_next(L, index) != 0) {
        if (lua_type(L, -2) != LUA_TNUMBER || lua_tointeger(L, -2) != max_index + 1) {
            is_array = 0;
        }
        max_index++;
        lua_pop(L, 1);
    }

    if (is_array && max_index > 0) {
        luaL_addchar(b, '[');
        for (int i = 1; i <= max_index; i++) {
            if (i > 1) luaL_addchar(b, ',');
            lua_rawgeti(L, index, i);
            json_stringify_value(L, lua_gettop(L), b);
            lua_pop(L, 1);
        }
        luaL_addchar(b, ']');
    } else {
        luaL_addchar(b, '{');
        int first = 1;
        lua_pushnil(L);
        while (lua_next(L, index) != 0) {
            if (!first) luaL_addchar(b, ',');
            first = 0;

            // Key
            luaL_addchar(b, '"');
            if (lua_type(L, -2) == LUA_TSTRING) {
                luaL_addstring(b, lua_tostring(L, -2));
            } else {
                lua_pushvalue(L, -2);
                luaL_addstring(b, lua_tostring(L, -1));
                lua_pop(L, 1);
            }
            luaL_addchar(b, '"');
            luaL_addchar(b, ':');

            // Value
            json_stringify_value(L, lua_gettop(L), b);
            lua_pop(L, 1);
        }
        luaL_addchar(b, '}');
    }
}

void json_stringify_value(lua_State *L, int index, luaL_Buffer *b) {
    int t = lua_type(L, index);
    switch (t) {
        case LUA_TSTRING: {
            const char *s = lua_tostring(L, index);
            luaL_addchar(b, '"');
            while (*s) {
                if (*s == '"' || *s == '\\') {
                    luaL_addchar(b, '\\');
                }
                luaL_addchar(b, *s);
                s++;
            }
            luaL_addchar(b, '"');
            break;
        }
        case LUA_TNUMBER: {
            char buf[64];
            snprintf(buf, sizeof(buf), "%g", lua_tonumber(L, index));
            luaL_addstring(b, buf);
            break;
        }
        case LUA_TBOOLEAN:
            luaL_addstring(b, lua_toboolean(L, index) ? "true" : "false");
            break;
        case LUA_TTABLE:
            json_stringify_table(L, index, b);
            break;
        case LUA_TNIL:
        default:
            luaL_addstring(b, "null");
            break;
    }
}

// ============================================================================
// Lua C API Functions
// ============================================================================

int lua_ext_json_parse(lua_State *L) {
    const char *json = luaL_checkstring(L, 1);
    LOG_LUA_DEBUG("Ext.Json.Parse called (len: %zu)", strlen(json));

    const char *result = json_parse_value(L, json);
    if (!result) {
        lua_pushnil(L);
        LOG_LUA_DEBUG("Ext.Json.Parse failed");
    }
    return 1;
}

int lua_ext_json_stringify(lua_State *L) {
    luaL_Buffer b;
    luaL_buffinit(L, &b);
    json_stringify_value(L, 1, &b);
    luaL_pushresult(&b);
    return 1;
}

// ============================================================================
// Registration
// ============================================================================

void lua_json_register(lua_State *L, int ext_table_index) {
    // Convert negative index to absolute since we'll be pushing onto stack
    if (ext_table_index < 0) {
        ext_table_index = lua_gettop(L) + ext_table_index + 1;
    }

    // Create Ext.Json table
    lua_newtable(L);
    lua_pushcfunction(L, lua_ext_json_parse);
    lua_setfield(L, -2, "Parse");
    lua_pushcfunction(L, lua_ext_json_stringify);
    lua_setfield(L, -2, "Stringify");
    lua_setfield(L, ext_table_index, "Json");
}
