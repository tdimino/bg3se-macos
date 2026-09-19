/*
 * Tier 0 tests: src/lua/lua_json.c — Ext.Json.Parse / Ext.Json.Stringify.
 *
 * This is the single most-used pure-logic path a mod author touches: MCM and
 * every config-driven mod round-trips its settings through Ext.Json, and
 * PersistentVars / user variables serialize through json_stringify_value().
 * Everything here runs on a bare luaL_newstate() — no game, no hooks.
 *
 * The assertions state what JSON *means*, not what the current code happens to
 * emit, so a red test here is a real defect and not a churn magnet.
 */

#include "test_harness.h"
#include "lua_json.h"

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <unistd.h>
#include <sys/wait.h>

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

static lua_State *js_new(void) {
    lua_State *L = luaL_newstate();
    if (L) luaL_openlibs(L);
    return L;
}

/* Parse `s`; on success the value is left on the stack top.
 * Returns the parser's "next char" pointer (NULL on failure). */
static const char *js_parse(lua_State *L, const char *s) {
    return json_parse_value(L, s);
}

/* Stringify the value on the stack top, replacing it with the JSON string. */
static const char *js_stringify(lua_State *L) {
    lua_pushcfunction(L, lua_ext_json_stringify);
    lua_insert(L, -2);
    lua_call(L, 1, 1);
    return lua_tostring(L, -1);
}

/* Stringify a Lua expression, e.g. "return {1,2,3}". */
static const char *js_stringify_expr(lua_State *L, const char *chunk) {
    ASSERT_TRUE(luaL_dostring(L, chunk) == LUA_OK);
    return js_stringify(L);
}

/* --- isolated (cold-process) execution ------------------------------------
 *
 * Some cases below leave the Lua heap corrupted: the call *returns a value*,
 * then the process hangs or faults later, somewhere unrelated. Running them
 * in-process poisons every test that follows (that is how this class of defect
 * was found here). They must be isolated.
 *
 * fork() alone is NOT enough: the child inherits the parent's warm heap, so the
 * out-of-bounds writes land in already-mapped memory and the child exits 0 —
 * a green test over a live defect. So the child re-execs this same binary with
 * `--json-selftest <mode>`, which reproduces the cold-process conditions where
 * the fault is deterministic. alarm() bounds the hang case.
 *
 * Returns 1 if the child exited 0, 0 if it faulted/hung/exited non-zero,
 * -1 if isolation is unavailable (caller then skips). */

static const char *g_json_argv0 = NULL;

void lua_json_tests_set_argv0(const char *argv0);
void lua_json_tests_set_argv0(const char *argv0) { g_json_argv0 = argv0; }

static int js_run_isolated(const char *mode) {
    if (!g_json_argv0) return -1;
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        alarm(5);                        /* survives exec; a hang becomes SIGALRM */
        execl(g_json_argv0, g_json_argv0, "--json-selftest", mode, (char *)NULL);
        _exit(127);                      /* exec failed */
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 127) return -1;  /* no exec */
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* Parsing — structure                                                 */
/* ------------------------------------------------------------------ */

TEST(parse_empty_object) {
    lua_State *L = js_new();
    ASSERT_NOT_NULL(js_parse(L, "{}"));
    ASSERT_TRUE(lua_istable(L, -1));
    lua_pushnil(L);
    ASSERT_EQ(lua_next(L, -2), 0);   /* no keys */
    lua_close(L);
}

TEST(parse_empty_array) {
    lua_State *L = js_new();
    ASSERT_NOT_NULL(js_parse(L, "[]"));
    ASSERT_TRUE(lua_istable(L, -1));
    ASSERT_EQ((int)lua_rawlen(L, -1), 0);
    lua_close(L);
}

TEST(parse_flat_object_values) {
    lua_State *L = js_new();
    ASSERT_NOT_NULL(js_parse(L, "{\"s\":\"hi\",\"n\":42,\"b\":true,\"z\":null}"));
    ASSERT_TRUE(lua_istable(L, -1));

    lua_getfield(L, -1, "s");
    ASSERT_STR_EQ(lua_tostring(L, -1), "hi");
    lua_pop(L, 1);

    lua_getfield(L, -1, "n");
    ASSERT_EQ((int)lua_tointeger(L, -1), 42);
    lua_pop(L, 1);

    lua_getfield(L, -1, "b");
    ASSERT_TRUE(lua_isboolean(L, -1) && lua_toboolean(L, -1));
    lua_pop(L, 1);

    /* JSON null becomes an absent key (Lua has no nil-valued fields). */
    lua_getfield(L, -1, "z");
    ASSERT_TRUE(lua_isnil(L, -1));
    lua_pop(L, 1);

    lua_close(L);
}

TEST(parse_nested_object_and_array) {
    lua_State *L = js_new();
    ASSERT_NOT_NULL(js_parse(L, "{\"a\":{\"b\":[10,20,{\"c\":\"deep\"}]}}"));

    lua_getfield(L, -1, "a");
    lua_getfield(L, -1, "b");
    ASSERT_EQ((int)lua_rawlen(L, -1), 3);

    lua_rawgeti(L, -1, 2);
    ASSERT_EQ((int)lua_tointeger(L, -1), 20);
    lua_pop(L, 1);

    lua_rawgeti(L, -1, 3);
    lua_getfield(L, -1, "c");
    ASSERT_STR_EQ(lua_tostring(L, -1), "deep");
    lua_close(L);
}

TEST(parse_array_order_preserved) {
    lua_State *L = js_new();
    ASSERT_NOT_NULL(js_parse(L, "[\"a\",\"b\",\"c\"]"));
    ASSERT_EQ((int)lua_rawlen(L, -1), 3);
    const char *expect[3] = { "a", "b", "c" };
    for (int i = 0; i < 3; i++) {
        lua_rawgeti(L, -1, i + 1);
        ASSERT_STR_EQ(lua_tostring(L, -1), expect[i]);
        lua_pop(L, 1);
    }
    lua_close(L);
}

TEST(parse_skips_surrounding_whitespace) {
    lua_State *L = js_new();
    ASSERT_NOT_NULL(js_parse(L, "  \t\r\n  {\"k\" : \n 1 }"));
    lua_getfield(L, -1, "k");
    ASSERT_EQ((int)lua_tointeger(L, -1), 1);
    lua_close(L);
}

TEST(parse_returns_cursor_past_value) {
    lua_State *L = js_new();
    const char *src = "[1,2]  trailing";
    const char *end = js_parse(L, src);
    ASSERT_NOT_NULL(end);
    ASSERT_EQ(end - src, 5);         /* stops right after the ']' */
    lua_close(L);
}

TEST(parse_moderate_nesting_ok) {
    /* 20 nested arrays parse, survive a full GC, and close cleanly. */
    enum { DEPTH = 20 };
    char buf[2 * DEPTH + 8];
    int p = 0;
    for (int i = 0; i < DEPTH; i++) buf[p++] = '[';
    buf[p++] = '1';
    for (int i = 0; i < DEPTH; i++) buf[p++] = ']';
    buf[p] = '\0';

    lua_State *L = js_new();
    ASSERT_NOT_NULL(js_parse(L, buf));
    ASSERT_TRUE(lua_istable(L, -1));
    lua_gc(L, LUA_GCCOLLECT);
    lua_close(L);
}

static int parse_nested_body(int depth) {
    char *buf = (char *)malloc((size_t)depth * 2 + 8);
    if (!buf) return 2;
    int p = 0;
    for (int i = 0; i < depth; i++) buf[p++] = '[';
    buf[p++] = '1';
    for (int i = 0; i < depth; i++) buf[p++] = ']';
    buf[p] = '\0';

    lua_State *L = js_new();
    const char *r = json_parse_value(L, buf);
    free(buf);
    if (!r) { lua_close(L); return 3; }
    lua_gc(L, LUA_GCCOLLECT);   /* corruption shows up here */
    lua_close(L);
    return 0;
}


TEST(parse_deep_nesting_does_not_corrupt_heap) {
    /* An Ext.Net payload or a mod config can nest this far. The parser
     * recurses one Lua-stack frame per level and never calls lua_checkstack,
     * so past LUA_MINSTACK (20 guaranteed slots) it writes past the stack. */
    int rc = js_run_isolated("parse64");
    if (rc < 0) return;                  /* fork unavailable */
    ASSERT_EQ(rc, 1);
}

TEST(parse_very_deep_nesting_does_not_corrupt_heap) {
    int rc = js_run_isolated("parse256");
    if (rc < 0) return;
    ASSERT_EQ(rc, 1);
}

/* ------------------------------------------------------------------ */
/* Parsing — scalars and escapes                                       */
/* ------------------------------------------------------------------ */

TEST(parse_number_forms) {
    struct { const char *src; double want; } cases[] = {
        { "0",        0.0 },
        { "42",       42.0 },
        { "-7",       -7.0 },
        { "3.5",      3.5 },
        { "-0.25",    -0.25 },
        { "1e3",      1000.0 },
        { "1E+3",     1000.0 },
        { "2.5e-2",   0.025 },
    };
    lua_State *L = js_new();
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        ASSERT_NOT_NULL(js_parse(L, cases[i].src));
        ASSERT_TRUE(lua_isnumber(L, -1));
        double got = lua_tonumber(L, -1);
        ASSERT_TRUE(got > cases[i].want - 1e-9 && got < cases[i].want + 1e-9);
        lua_pop(L, 1);
    }
    lua_close(L);
}

TEST(parse_large_integer_is_exact) {
    /* Entity handles, timestamps and mod-defined ids are routinely > 2^31. */
    lua_State *L = js_new();
    ASSERT_NOT_NULL(js_parse(L, "1755460000"));
    ASSERT_EQ((long long)lua_tonumber(L, -1), 1755460000LL);
    lua_close(L);
}

TEST(parse_literals) {
    lua_State *L = js_new();

    ASSERT_NOT_NULL(js_parse(L, "true"));
    ASSERT_TRUE(lua_isboolean(L, -1) && lua_toboolean(L, -1));
    lua_pop(L, 1);

    ASSERT_NOT_NULL(js_parse(L, "false"));
    ASSERT_TRUE(lua_isboolean(L, -1) && !lua_toboolean(L, -1));
    lua_pop(L, 1);

    ASSERT_NOT_NULL(js_parse(L, "null"));
    ASSERT_TRUE(lua_isnil(L, -1));
    lua_pop(L, 1);

    lua_close(L);
}

TEST(parse_empty_string_value) {
    lua_State *L = js_new();
    ASSERT_NOT_NULL(js_parse(L, "\"\""));
    size_t n = 1;
    const char *s = lua_tolstring(L, -1, &n);
    ASSERT_NOT_NULL(s);
    ASSERT_EQ((int)n, 0);
    lua_close(L);
}

TEST(parse_simple_escapes) {
    lua_State *L = js_new();
    ASSERT_NOT_NULL(js_parse(L, "\"q\\\"b\\\\s\\/n\\nr\\rt\\tf\\fbs\\b\""));
    ASSERT_STR_EQ(lua_tostring(L, -1), "q\"b\\s/n\nr\rt\tf\fbs\b");
    lua_close(L);
}

TEST(parse_unicode_escape_ascii) {
    /* RFC 8259 \uXXXX. Windows BG3SE decodes this; a mod that stores an
     * escaped string (any JSON emitted by a strict encoder) must read back
     * the character, not the escape text. */
    lua_State *L = js_new();
    ASSERT_NOT_NULL(js_parse(L, "\"\\u0041\\u0042\""));
    ASSERT_STR_EQ(lua_tostring(L, -1), "AB");
    lua_close(L);
}

TEST(parse_unicode_escape_non_ascii) {
    /* U+00E9 (e-acute) -> 2-byte UTF-8. Localized mod strings hit this. */
    lua_State *L = js_new();
    ASSERT_NOT_NULL(js_parse(L, "\"caf\\u00e9\""));
    ASSERT_STR_EQ(lua_tostring(L, -1), "caf\xC3\xA9");
    lua_close(L);
}

TEST(parse_raw_utf8_passthrough) {
    /* Non-escaped UTF-8 must survive byte-for-byte. */
    lua_State *L = js_new();
    ASSERT_NOT_NULL(js_parse(L, "\"caf\xC3\xA9 \xE2\x9A\x94\""));
    ASSERT_STR_EQ(lua_tostring(L, -1), "caf\xC3\xA9 \xE2\x9A\x94");
    lua_close(L);
}

/* ------------------------------------------------------------------ */
/* Parsing — malformed input must be rejected, not half-accepted       */
/* ------------------------------------------------------------------ */

TEST(parse_rejects_empty_input) {
    lua_State *L = js_new();
    int top = lua_gettop(L);
    ASSERT_NULL(js_parse(L, ""));
    ASSERT_EQ(lua_gettop(L), top);   /* nothing pushed on failure */
    lua_close(L);
}

TEST(parse_rejects_whitespace_only) {
    lua_State *L = js_new();
    ASSERT_NULL(js_parse(L, "   \n\t "));
    lua_close(L);
}

TEST(parse_rejects_unterminated_string) {
    lua_State *L = js_new();
    ASSERT_NULL(js_parse(L, "\"abc"));
    lua_close(L);
}

TEST(parse_rejects_unterminated_object) {
    lua_State *L = js_new();
    ASSERT_NULL(js_parse(L, "{\"a\":1"));
    lua_close(L);
}

TEST(parse_rejects_unterminated_array) {
    lua_State *L = js_new();
    ASSERT_NULL(js_parse(L, "[1,2"));
    lua_close(L);
}

TEST(parse_rejects_missing_colon) {
    lua_State *L = js_new();
    ASSERT_NULL(js_parse(L, "{\"a\" 1}"));
    lua_close(L);
}

TEST(parse_rejects_trailing_comma_in_array) {
    lua_State *L = js_new();
    ASSERT_NULL(js_parse(L, "[1,]"));
    lua_close(L);
}

TEST(parse_rejects_bare_word) {
    lua_State *L = js_new();
    ASSERT_NULL(js_parse(L, "nope"));
    ASSERT_NULL(js_parse(L, "tru"));
    ASSERT_NULL(js_parse(L, "undefined"));
    lua_close(L);
}

TEST(parse_rejects_unquoted_key) {
    lua_State *L = js_new();
    ASSERT_NULL(js_parse(L, "{a:1}"));
    lua_close(L);
}

/* ------------------------------------------------------------------ */
/* Stringify                                                           */
/* ------------------------------------------------------------------ */

TEST(stringify_primitives) {
    lua_State *L = js_new();

    lua_pushboolean(L, 1);
    ASSERT_STR_EQ(js_stringify(L), "true");
    lua_pop(L, 1);

    lua_pushboolean(L, 0);
    ASSERT_STR_EQ(js_stringify(L), "false");
    lua_pop(L, 1);

    lua_pushnil(L);
    ASSERT_STR_EQ(js_stringify(L), "null");
    lua_pop(L, 1);

    lua_pushstring(L, "hi");
    ASSERT_STR_EQ(js_stringify(L), "\"hi\"");
    lua_pop(L, 1);

    lua_close(L);
}

TEST(stringify_escapes_quote_and_backslash) {
    lua_State *L = js_new();
    lua_pushstring(L, "a\"b\\c");
    ASSERT_STR_EQ(js_stringify(L), "\"a\\\"b\\\\c\"");
    lua_close(L);
}

TEST(stringify_escapes_control_characters) {
    /* A raw newline/tab inside a JSON string is invalid per RFC 8259. Any
     * strict consumer (Windows BG3SE, an external tool reading a mod's saved
     * config) rejects the whole document. Multi-line description strings are
     * common in MCM settings. */
    lua_State *L = js_new();
    lua_pushstring(L, "line1\nline2\ttab");
    ASSERT_STR_EQ(js_stringify(L), "\"line1\\nline2\\ttab\"");
    lua_close(L);
}

TEST(stringify_preserves_embedded_nul) {
    /* Lua strings are length-counted; a binary Ext.Net payload can contain
     * NUL. Truncating here silently drops the rest of the message. */
    lua_State *L = js_new();
    lua_pushlstring(L, "a\0b", 3);
    lua_pushcfunction(L, lua_ext_json_stringify);
    lua_insert(L, -2);
    lua_call(L, 1, 1);
    size_t n = 0;
    const char *out = lua_tolstring(L, -1, &n);
    ASSERT_NOT_NULL(out);
    /* The property that matters is NO TRUNCATION at the NUL. The byte itself
     * must be escaped, not emitted raw: a raw control character inside a JSON
     * string is invalid per RFC 8259, so asserting on the raw bytes here would
     * pin non-conforming output. Quoted: " a \u0000 b " = 1+1+6+1+1 = 10. */
    ASSERT_EQ((int)n, 10);
    ASSERT_NOT_NULL(strstr(out, "\\u0000"));
    ASSERT_EQ(out[1], 'a');
    ASSERT_EQ(out[n - 2], 'b');

    /* And it must survive the round-trip with the NUL intact. */
    const char *js = lua_tostring(L, -1);
    ASSERT_NOT_NULL(json_parse_value(L, js));
    size_t rn = 0;
    const char *back = lua_tolstring(L, -1, &rn);
    ASSERT_EQ((int)rn, 3);
    ASSERT_EQ(back[0], 'a');
    ASSERT_EQ(back[1], '\0');
    ASSERT_EQ(back[2], 'b');
    lua_close(L);
}

TEST(stringify_large_integer_is_exact) {
    /* %g with default precision keeps 6 significant digits, so any integer
     * above 999999 comes back mangled. Mods put os.time() timestamps, entity
     * ids and gold totals through Ext.Json.Stringify and PersistentVars. */
    lua_State *L = js_new();
    lua_pushinteger(L, 1755460000);
    ASSERT_STR_EQ(js_stringify(L), "1755460000");
    lua_close(L);
}

TEST(stringify_small_integer_has_no_decimal_point) {
    lua_State *L = js_new();
    lua_pushinteger(L, 42);
    ASSERT_STR_EQ(js_stringify(L), "42");
    lua_close(L);
}

TEST(stringify_detects_dense_array) {
    lua_State *L = js_new();
    ASSERT_STR_EQ(js_stringify_expr(L, "return {10,20,30}"), "[10,20,30]");
    lua_close(L);
}

TEST(stringify_empty_table_is_object) {
    lua_State *L = js_new();
    ASSERT_STR_EQ(js_stringify_expr(L, "return {}"), "{}");
    lua_close(L);
}

TEST(stringify_sparse_table_is_object) {
    lua_State *L = js_new();
    const char *out = js_stringify_expr(L, "return {[1]='a',[3]='c'}");
    ASSERT_NOT_NULL(out);
    ASSERT_EQ(out[0], '{');
    lua_close(L);
}

TEST(stringify_nested_structure) {
    lua_State *L = js_new();
    ASSERT_STR_EQ(js_stringify_expr(L, "return {a={1,2}}"), "{\"a\":[1,2]}");
    lua_close(L);
}

static int stringify_chain_body(int depth) {
    lua_State *L = js_new();
    char chunk[192];
    snprintf(chunk, sizeof chunk,
             "local t = {} local r = t for i = 1, %d do t.n = {} t = t.n end return r",
             depth);
    if (luaL_dostring(L, chunk) != LUA_OK) { lua_close(L); return 2; }
    lua_pushcfunction(L, lua_ext_json_stringify);
    lua_insert(L, -2);
    lua_call(L, 1, 1);
    if (!lua_tostring(L, -1)) { lua_close(L); return 3; }
    lua_gc(L, LUA_GCCOLLECT);
    lua_close(L);                        /* corruption faults here */
    return 0;
}


static int stringify_cyclic_body(void) {
    lua_State *L = js_new();
    if (luaL_dostring(L, "local t = {} t.self = t return t") != LUA_OK) {
        lua_close(L); return 2;
    }
    lua_pushcfunction(L, lua_ext_json_stringify);
    lua_insert(L, -2);
    lua_call(L, 1, 1);
    if (!lua_tostring(L, -1)) { lua_close(L); return 3; }
    lua_gc(L, LUA_GCCOLLECT);
    lua_close(L);
    return 0;
}

TEST(stringify_shallow_nesting_is_clean) {
    /* Baseline: a 6-deep chain serializes and tears down cleanly. */
    lua_State *L = js_new();
    ASSERT_TRUE(luaL_dostring(L,
        "local t = {} local r = t for i = 1, 6 do t.n = {} t = t.n end "
        "return r") == LUA_OK);
    ASSERT_NOT_NULL(js_stringify(L));
    lua_gc(L, LUA_GCCOLLECT);
    lua_close(L);
}

TEST(stringify_16_deep_does_not_corrupt_heap) {
    /* 16 levels is an ordinary MCM/PersistentVars settings tree. */
    int rc = js_run_isolated("str16");
    if (rc < 0) return;
    ASSERT_EQ(rc, 1);
}

TEST(stringify_64_deep_does_not_corrupt_heap) {
    int rc = js_run_isolated("str64");
    if (rc < 0) return;
    ASSERT_EQ(rc, 1);
}

TEST(stringify_self_referential_table_does_not_corrupt_heap) {
    /* Ext.Json.Stringify(t) where t.self == t, or any mod table carrying an
     * { __index = _G } metatable backlink. The depth cap makes it *return*,
     * but the recursion has already run past the Lua stack. */
    int rc = js_run_isolated("cyclic");
    if (rc < 0) return;
    ASSERT_EQ(rc, 1);
}

/* ------------------------------------------------------------------ */
/* Round trip                                                          */
/* ------------------------------------------------------------------ */

TEST(roundtrip_object_of_scalars) {
    lua_State *L = js_new();
    ASSERT_TRUE(luaL_dostring(L,
        "return {name='Tav', level=5, alive=true}") == LUA_OK);
    const char *json = js_stringify(L);
    ASSERT_NOT_NULL(json);

    lua_State *L2 = js_new();
    ASSERT_NOT_NULL(js_parse(L2, json));
    lua_getfield(L2, -1, "name");
    ASSERT_STR_EQ(lua_tostring(L2, -1), "Tav");
    lua_pop(L2, 1);
    lua_getfield(L2, -1, "level");
    ASSERT_EQ((int)lua_tointeger(L2, -1), 5);
    lua_pop(L2, 1);
    lua_getfield(L2, -1, "alive");
    ASSERT_TRUE(lua_toboolean(L2, -1));

    lua_close(L2);
    lua_close(L);
}

TEST(roundtrip_string_with_escapes) {
    lua_State *L = js_new();
    lua_pushstring(L, "quote\" back\\ slash/");
    const char *json = js_stringify(L);
    ASSERT_NOT_NULL(json);

    lua_State *L2 = js_new();
    ASSERT_NOT_NULL(js_parse(L2, json));
    ASSERT_STR_EQ(lua_tostring(L2, -1), "quote\" back\\ slash/");
    lua_close(L2);
    lua_close(L);
}

/* ------------------------------------------------------------------ */
/* Cold-process entry point used by js_run_isolated().                  */
/* Invoked as: bg3se_test_tier0 --json-selftest <mode>                  */
/* ------------------------------------------------------------------ */

int lua_json_selftest_main(const char *mode);
int lua_json_selftest_main(const char *mode) {
    if (strcmp(mode, "parse64")  == 0) return parse_nested_body(64);
    if (strcmp(mode, "parse256") == 0) return parse_nested_body(256);
    if (strcmp(mode, "str16")    == 0) return stringify_chain_body(16);
    if (strcmp(mode, "str64")    == 0) return stringify_chain_body(64);
    if (strcmp(mode, "cyclic")   == 0) return stringify_cyclic_body();
    return 64;   /* unknown mode */
}

/* ------------------------------------------------------------------ */

void register_lua_json_tests(void);
void register_lua_json_tests(void) {
    printf("[lua_json]\n");
    RUN_TEST(parse_empty_object);
    RUN_TEST(parse_empty_array);
    RUN_TEST(parse_flat_object_values);
    RUN_TEST(parse_nested_object_and_array);
    RUN_TEST(parse_array_order_preserved);
    RUN_TEST(parse_skips_surrounding_whitespace);
    RUN_TEST(parse_returns_cursor_past_value);
    RUN_TEST(parse_moderate_nesting_ok);
    RUN_TEST(parse_deep_nesting_does_not_corrupt_heap);
    RUN_TEST(parse_very_deep_nesting_does_not_corrupt_heap);
    RUN_TEST(parse_number_forms);
    RUN_TEST(parse_large_integer_is_exact);
    RUN_TEST(parse_literals);
    RUN_TEST(parse_empty_string_value);
    RUN_TEST(parse_simple_escapes);
    RUN_TEST(parse_unicode_escape_ascii);
    RUN_TEST(parse_unicode_escape_non_ascii);
    RUN_TEST(parse_raw_utf8_passthrough);
    RUN_TEST(parse_rejects_empty_input);
    RUN_TEST(parse_rejects_whitespace_only);
    RUN_TEST(parse_rejects_unterminated_string);
    RUN_TEST(parse_rejects_unterminated_object);
    RUN_TEST(parse_rejects_unterminated_array);
    RUN_TEST(parse_rejects_missing_colon);
    RUN_TEST(parse_rejects_trailing_comma_in_array);
    RUN_TEST(parse_rejects_bare_word);
    RUN_TEST(parse_rejects_unquoted_key);
    RUN_TEST(stringify_primitives);
    RUN_TEST(stringify_escapes_quote_and_backslash);
    RUN_TEST(stringify_escapes_control_characters);
    RUN_TEST(stringify_preserves_embedded_nul);
    RUN_TEST(stringify_large_integer_is_exact);
    RUN_TEST(stringify_small_integer_has_no_decimal_point);
    RUN_TEST(stringify_detects_dense_array);
    RUN_TEST(stringify_empty_table_is_object);
    RUN_TEST(stringify_sparse_table_is_object);
    RUN_TEST(stringify_nested_structure);
    RUN_TEST(stringify_shallow_nesting_is_clean);
    RUN_TEST(stringify_16_deep_does_not_corrupt_heap);
    RUN_TEST(stringify_64_deep_does_not_corrupt_heap);
    RUN_TEST(stringify_self_referential_table_does_not_corrupt_heap);
    RUN_TEST(roundtrip_object_of_scalars);
    RUN_TEST(roundtrip_string_with_escapes);
}
