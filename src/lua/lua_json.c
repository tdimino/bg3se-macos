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

/* Append one code point as UTF-8. */
static void json_add_utf8(luaL_Buffer *b, unsigned long cp) {
    if (cp < 0x80) {
        luaL_addchar(b, (char)cp);
    } else if (cp < 0x800) {
        luaL_addchar(b, (char)(0xC0 | (cp >> 6)));
        luaL_addchar(b, (char)(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        luaL_addchar(b, (char)(0xE0 | (cp >> 12)));
        luaL_addchar(b, (char)(0x80 | ((cp >> 6) & 0x3F)));
        luaL_addchar(b, (char)(0x80 | (cp & 0x3F)));
    } else {
        luaL_addchar(b, (char)(0xF0 | (cp >> 18)));
        luaL_addchar(b, (char)(0x80 | ((cp >> 12) & 0x3F)));
        luaL_addchar(b, (char)(0x80 | ((cp >> 6) & 0x3F)));
        luaL_addchar(b, (char)(0x80 | (cp & 0x3F)));
    }
}

static int json_hex4(const char *p, unsigned *out) {
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        char c = p[i];
        v <<= 4;
        if (c >= '0' && c <= '9')      v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
        else return 0;
    }
    *out = v;
    return 1;
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
                case 'u': {
                    /* \uXXXX was copied through verbatim, so "A" read
                     * back as the literal text u0041. */
                    unsigned cp = 0;
                    if (!json_hex4(json + 1, &cp)) {
                        luaL_addchar(&b, *json);
                        break;
                    }
                    json += 4;
                    if (cp >= 0xD800 && cp <= 0xDBFF &&
                        json[1] == '\\' && json[2] == 'u') {
                        unsigned lo = 0;
                        if (json_hex4(json + 3, &lo) && lo >= 0xDC00 && lo <= 0xDFFF) {
                            json += 6;
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        }
                    }
                    json_add_utf8(&b, cp);
                    break;
                }
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

// Cap recursion so a cyclic/self-referential table (possible now that mod tables
// carry an { __index = _G } metatable) fails gracefully instead of overflowing.
#define JSON_MAX_DEPTH 200

typedef struct {
    char *data; size_t len; size_t cap; int oom;
    // Containers (tables, __pairs userdata) on the active serialization path,
    // indexed by depth. Reaching a container that is already on the path is a
    // back-edge: it serializes as null instead of recursing, so a cycle costs
    // one node rather than JSON_MAX_DEPTH levels (or, for a branching cycle
    // such as t.a = t; t.b = t, an exponential expansion).
    const void *active[JSON_MAX_DEPTH + 1];
} JsonBuf;

static void jb_init(JsonBuf *jb) {
    jb->cap = 256; jb->len = 0; jb->oom = 0;
    jb->data = (char *)malloc(jb->cap);
    if (!jb->data) jb->oom = 1; else jb->data[0] = '\0';
    memset(jb->active, 0, sizeof(jb->active));
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

// True when `self` is already being serialized at a shallower depth.
static int jb_on_active_path(const JsonBuf *jb, const void *self, int depth) {
    for (int d = 0; d < depth; d++) {
        if (jb->active[d] == self) return 1;
    }
    return 0;
}

static void json_sb_value(lua_State *L, int index, JsonBuf *jb, int depth);

// Emit an object key. Guards against lua_tostring returning NULL for
// non-string, non-number keys, which would crash the buffer append.
static void json_sb_key(lua_State *L, int index, JsonBuf *jb) {
    index = lua_absindex(L, index);
    jb_addchar(jb, '"');
    if (lua_type(L, index) == LUA_TSTRING) {
        jb_addstring(jb, lua_tostring(L, index));
    } else {
        lua_pushvalue(L, index);
        const char *ks = lua_tostring(L, -1);
        jb_addstring(jb, ks ? ks : "?");
        lua_pop(L, 1);
    }
    jb_addchar(jb, '"');
}

// Error object at the top of the stack as loggable text. A mod may raise a
// table (error({code=1})): lua_tostring() returns NULL for it, and handing
// that to "%s" is undefined. Name the type instead; no metamethods are run.
static const char *jb_errmsg(lua_State *L) {
    if (lua_type(L, -1) == LUA_TSTRING) return lua_tostring(L, -1);
    return lua_typename(L, lua_type(L, -1));
}

// Every recursion level parks a few values on the Lua stack (lua_next's
// key/value, an iterator triple for __pairs userdata). A C function is only
// guaranteed LUA_MINSTACK free slots, so reserve per level and fail soft to
// null when the stack cannot grow, rather than trip an API-check assert or
// run on incidental headroom.
#define JSON_STACK_PER_LEVEL 8

static void json_sb_table(lua_State *L, int index, JsonBuf *jb, int depth) {
    if (depth > JSON_MAX_DEPTH || !lua_checkstack(L, JSON_STACK_PER_LEVEL)) { jb_addstring(jb, "null"); return; }
    const void *self = lua_topointer(L, index);
    if (jb_on_active_path(jb, self, depth)) { jb_addstring(jb, "null"); return; }
    jb->active[depth] = self;

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
            json_sb_key(L, -2, jb);
            jb_addchar(jb, ':');
            json_sb_value(L, lua_gettop(L), jb, depth + 1);
            lua_pop(L, 1);
        }
        jb_addchar(jb, '}');
    }
}

// Userdata that exposes __pairs (component proxies, entity proxies, any
// object a mod can walk with pairs()) serializes as an object by iterating it
// in place, through the same depth cap and cycle guard as tables. Opaque
// userdata stays null. A __pairs or iterator that raises is fail-soft: the
// error is logged, that node becomes null, and serialization of its siblings
// continues, so a single bad proxy inside PersistentVars cannot abort a save.
static void json_sb_userdata(lua_State *L, int index, JsonBuf *jb, int depth) {
    if (depth > JSON_MAX_DEPTH || !lua_checkstack(L, JSON_STACK_PER_LEVEL)) {
        jb_addstring(jb, "null");
        return;
    }
    if (luaL_getmetafield(L, index, "__pairs") == LUA_TNIL) {
        jb_addstring(jb, "null");
        return;
    }
    const void *self = lua_topointer(L, index);
    if (jb_on_active_path(jb, self, depth)) {
        lua_pop(L, 1);                          // __pairs
        jb_addstring(jb, "null");
        return;
    }
    jb->active[depth] = self;

    int base = lua_gettop(L) - 1;               // slot below __pairs
    lua_pushvalue(L, index);                    // [__pairs, ud]
    if (lua_pcall(L, 1, 3, 0) != LUA_OK) {      // [iter, state, ctrl]
        LOG_LUA_WARN("Json.Stringify: __pairs raised: %s", jb_errmsg(L));
        lua_settop(L, base);
        jb_addstring(jb, "null");
        return;
    }
    int iter = base + 1, state = base + 2, ctrl = base + 3;

    size_t mark = jb->len;                      // rewind point on iterator error
    jb_addchar(jb, '{');
    int first = 1;
    for (;;) {
        lua_pushvalue(L, iter);
        lua_pushvalue(L, state);
        lua_pushvalue(L, ctrl);
        if (lua_pcall(L, 2, 2, 0) != LUA_OK) {  // [iter, state, ctrl, key, value]
            LOG_LUA_WARN("Json.Stringify: __pairs iterator raised: %s", jb_errmsg(L));
            lua_settop(L, base);
            if (!jb->oom) { jb->len = mark; jb->data[mark] = '\0'; }
            jb_addstring(jb, "null");
            return;
        }
        if (lua_isnil(L, -2)) {
            lua_pop(L, 2);
            break;
        }
        if (!first) jb_addchar(jb, ',');
        first = 0;
        json_sb_key(L, -2, jb);
        jb_addchar(jb, ':');
        json_sb_value(L, lua_gettop(L), jb, depth + 1);
        lua_pop(L, 1);                          // value
        lua_replace(L, ctrl);                   // key becomes the control variable
    }
    jb_addchar(jb, '}');
    lua_settop(L, base);
}

static void json_sb_value(lua_State *L, int index, JsonBuf *jb, int depth) {
    int t = lua_type(L, index);
    switch (t) {
        case LUA_TSTRING: {
            size_t len = 0;
            const char *s = lua_tolstring(L, index, &len);
            jb_addchar(jb, '"');
            for (size_t i = 0; s && i < len; i++) {
                unsigned char c = (unsigned char)s[i];
                /* Raw control characters (and NUL, which also truncated the
                 * string) are invalid inside a JSON string per RFC 8259. */
                switch (c) {
                    case '"':  jb_addstring(jb, "\\\""); continue;
                    case '\\': jb_addstring(jb, "\\\\"); continue;
                    case '\b': jb_addstring(jb, "\\b");  continue;
                    case '\f': jb_addstring(jb, "\\f");  continue;
                    case '\n': jb_addstring(jb, "\\n");  continue;
                    case '\r': jb_addstring(jb, "\\r");  continue;
                    case '\t': jb_addstring(jb, "\\t");  continue;
                    default: break;
                }
                if (c < 0x20) {
                    char esc[7];
                    snprintf(esc, sizeof(esc), "\\u%04x", c);
                    jb_addstring(jb, esc);
                } else {
                    jb_addchar(jb, (char)c);
                }
            }
            jb_addchar(jb, '"');
            break;
        }
        case LUA_TNUMBER: {
            // "%g" keeps 6 significant digits: 1755460000 became 1.75546e+09
            // and 1/3 became 0.333333, so a timestamp, entity id or gold total
            // in PersistentVars was rewritten on every save. Integers print
            // exactly; floats use %.17g (round-trip exact for IEEE-754).
            char buf[64];
            if (lua_isinteger(L, index)) {
                snprintf(buf, sizeof(buf), "%lld", (long long)lua_tointeger(L, index));
            } else {
                snprintf(buf, sizeof(buf), "%.17g", lua_tonumber(L, index));
            }
            jb_addstring(jb, buf);
            break;
        }
        case LUA_TBOOLEAN:
            jb_addstring(jb, lua_toboolean(L, index) ? "true" : "false");
            break;
        case LUA_TTABLE:
            json_sb_table(L, index, jb, depth);
            break;
        case LUA_TUSERDATA:
            json_sb_userdata(L, index, jb, depth);
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
    index = lua_absindex(L, index);
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
