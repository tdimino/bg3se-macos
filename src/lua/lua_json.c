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

// A plain growable byte buffer. The stringifier builds into this instead of a
// luaL_Buffer: luaL_Buffer keeps a box userdata on the Lua stack once it grows,
// and interleaving arbitrary stack pushes/pops (as table iteration requires) with
// buffer appends corrupts it (SIGSEGV in luaL_prepbuffsize). Building into a
// malloc'd buffer sidesteps that entirely; the result is copied into the caller's
// luaL_Buffer in a single, safe append at the top level.
typedef struct { char *data; size_t len; size_t cap; int oom; } JsonBuf;

// Cap recursion so a cyclic/self-referential table (possible now that mod tables
// carry an { __index = _G } metatable) fails gracefully instead of overflowing.
#define JSON_MAX_DEPTH 200

static void jb_init(JsonBuf *jb) {
    jb->cap = 256; jb->len = 0; jb->oom = 0;
    jb->data = (char *)malloc(jb->cap);
    if (!jb->data) jb->oom = 1; else jb->data[0] = '\0';
}
static void jb_free(JsonBuf *jb) { free(jb->data); jb->data = NULL; }
static void jb_reserve(JsonBuf *jb, size_t extra) {
    if (jb->oom) return;
    if (jb->len + extra + 1 <= jb->cap) return;
    size_t nc = jb->cap ? jb->cap : 256;
    while (nc < jb->len + extra + 1) nc *= 2;
    char *nd = (char *)realloc(jb->data, nc);
    if (!nd) { jb->oom = 1; return; }
    jb->data = nd; jb->cap = nc;
}
static void jb_addlstring(JsonBuf *jb, const char *s, size_t n) {
    if (jb->oom || !s || n == 0) return;
    jb_reserve(jb, n);
    if (jb->oom) return;
    memcpy(jb->data + jb->len, s, n);
    jb->len += n; jb->data[jb->len] = '\0';
}
static void jb_addstring(JsonBuf *jb, const char *s) { if (s) jb_addlstring(jb, s, strlen(s)); }
static void jb_addchar(JsonBuf *jb, char c) {
    jb_reserve(jb, 1);
    if (jb->oom) return;
    jb->data[jb->len++] = c; jb->data[jb->len] = '\0';
}

static void json_sb_value(lua_State *L, int index, JsonBuf *jb, int depth);

static void json_sb_table(lua_State *L, int index, JsonBuf *jb, int depth) {
    if (depth > JSON_MAX_DEPTH) { jb_addstring(jb, "null"); return; }

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
        jb_addchar(jb, '[');
        for (int i = 1; i <= max_index; i++) {
            if (i > 1) jb_addchar(jb, ',');
            lua_rawgeti(L, index, i);
            json_sb_value(L, lua_gettop(L), jb, depth + 1);
            lua_pop(L, 1);
        }
        jb_addchar(jb, ']');
    } else {
        jb_addchar(jb, '{');
        int first = 1;
        lua_pushnil(L);
        while (lua_next(L, index) != 0) {
            if (!first) jb_addchar(jb, ',');
            first = 0;

            // Key (guard against lua_tostring returning NULL for non-string,
            // non-number keys, which would crash the buffer append).
            jb_addchar(jb, '"');
            if (lua_type(L, -2) == LUA_TSTRING) {
                jb_addstring(jb, lua_tostring(L, -2));
            } else {
                lua_pushvalue(L, -2);
                const char *ks = lua_tostring(L, -1);
                jb_addstring(jb, ks ? ks : "?");
                lua_pop(L, 1);
            }
            jb_addchar(jb, '"');
            jb_addchar(jb, ':');

            // Value
            json_sb_value(L, lua_gettop(L), jb, depth + 1);
            lua_pop(L, 1);
        }
        jb_addchar(jb, '}');
    }
}

static void json_sb_value(lua_State *L, int index, JsonBuf *jb, int depth) {
    int t = lua_type(L, index);
    switch (t) {
        case LUA_TSTRING: {
            const char *s = lua_tostring(L, index);
            jb_addchar(jb, '"');
            for (; s && *s; s++) {
                if (*s == '"' || *s == '\\') jb_addchar(jb, '\\');
                jb_addchar(jb, *s);
            }
            jb_addchar(jb, '"');
            break;
        }
        case LUA_TNUMBER: {
            char buf[64];
            snprintf(buf, sizeof(buf), "%g", lua_tonumber(L, index));
            jb_addstring(jb, buf);
            break;
        }
        case LUA_TBOOLEAN:
            jb_addstring(jb, lua_toboolean(L, index) ? "true" : "false");
            break;
        case LUA_TTABLE:
            json_sb_table(L, index, jb, depth);
            break;
        case LUA_TNIL:
        default:
            jb_addstring(jb, "null");
            break;
    }
}

// Public entry point kept for existing callers (user_variables, persistentvars,
// main). Builds into a private malloc buffer, then appends the whole result to
// the caller's luaL_Buffer in one safe operation.
void json_stringify_value(lua_State *L, int index, luaL_Buffer *b) {
    JsonBuf jb;
    jb_init(&jb);
    json_sb_value(L, index, &jb, 0);
    if (!jb.oom && jb.data && jb.len > 0) {
        luaL_addlstring(b, jb.data, jb.len);
    } else if (jb.oom) {
        luaL_addstring(b, "null");
    }
    jb_free(&jb);
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
