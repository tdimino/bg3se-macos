/**
 * lua_debug.c - Debug/Introspection API for BG3SE-macOS
 *
 * Provides low-level memory reading and struct probing utilities.
 * Uses safe_memory APIs for crash-safe memory access.
 */

#include "lua_debug.h"
#include "lua_events.h"
#include "../core/logging.h"
#include "../core/safe_memory.h"
#include "../strings/fixed_string.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>

// Session start time (set once at init)
static time_t g_session_start_time = 0;

// ============================================================================
// Helper: Parse address from Lua (integer or hex string)
// ============================================================================

static uintptr_t parse_address(lua_State *L, int idx) {
    if (lua_isinteger(L, idx)) {
        return (uintptr_t)lua_tointeger(L, idx);
    } else if (lua_isnumber(L, idx)) {
        return (uintptr_t)lua_tonumber(L, idx);
    } else if (lua_isstring(L, idx)) {
        const char *s = lua_tostring(L, idx);
        return (uintptr_t)strtoull(s, NULL, 0);  // Handles 0x prefix
    }
    return 0;
}

// ============================================================================
// Low-level Memory Reading
// ============================================================================

int lua_debug_read_ptr(lua_State *L) {
    uintptr_t addr = parse_address(L, 1);
    if (addr == 0) {
        lua_pushnil(L);
        return 1;
    }

    void *result = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)addr, &result)) {
        lua_pushnil(L);
        return 1;
    }

    lua_pushinteger(L, (lua_Integer)(uintptr_t)result);
    return 1;
}

int lua_debug_read_u32(lua_State *L) {
    uintptr_t addr = parse_address(L, 1);
    if (addr == 0) {
        lua_pushnil(L);
        return 1;
    }

    uint32_t value = 0;
    if (!safe_memory_read_u32((mach_vm_address_t)addr, &value)) {
        lua_pushnil(L);
        return 1;
    }

    lua_pushinteger(L, (lua_Integer)value);
    return 1;
}

int lua_debug_read_u64(lua_State *L) {
    uintptr_t addr = parse_address(L, 1);
    if (addr == 0) {
        lua_pushnil(L);
        return 1;
    }

    uint64_t value = 0;
    if (!safe_memory_read_u64((mach_vm_address_t)addr, &value)) {
        lua_pushnil(L);
        return 1;
    }

    lua_pushinteger(L, (lua_Integer)value);
    return 1;
}

int lua_debug_read_i32(lua_State *L) {
    uintptr_t addr = parse_address(L, 1);
    if (addr == 0) {
        lua_pushnil(L);
        return 1;
    }

    int32_t value = 0;
    if (!safe_memory_read_i32((mach_vm_address_t)addr, &value)) {
        lua_pushnil(L);
        return 1;
    }

    lua_pushinteger(L, (lua_Integer)value);
    return 1;
}

int lua_debug_read_float(lua_State *L) {
    uintptr_t addr = parse_address(L, 1);
    if (addr == 0) {
        lua_pushnil(L);
        return 1;
    }

    float value = 0.0f;
    if (!safe_memory_read((mach_vm_address_t)addr, &value, sizeof(float))) {
        lua_pushnil(L);
        return 1;
    }

    lua_pushnumber(L, (lua_Number)value);
    return 1;
}

int lua_debug_read_string(lua_State *L) {
    uintptr_t addr = parse_address(L, 1);
    int maxLen = (int)luaL_optinteger(L, 2, 256);

    if (addr == 0 || maxLen < 1) {
        lua_pushnil(L);
        return 1;
    }

    if (maxLen > 4096) maxLen = 4096;

    char *buffer = (char *)malloc(maxLen + 1);
    if (!buffer) {
        lua_pushnil(L);
        return 1;
    }

    if (!safe_memory_read_string((mach_vm_address_t)addr, buffer, maxLen)) {
        free(buffer);
        lua_pushnil(L);
        return 1;
    }

    buffer[maxLen] = '\0';
    lua_pushstring(L, buffer);
    free(buffer);
    return 1;
}

int lua_debug_read_fixedstring(lua_State *L) {
    uintptr_t addr = parse_address(L, 1);
    if (addr == 0) {
        lua_pushnil(L);
        return 1;
    }

    // Read the FixedString index at the address
    uint32_t fs_index = 0;
    if (!safe_memory_read_u32((mach_vm_address_t)addr, &fs_index)) {
        lua_pushnil(L);
        return 1;
    }

    // Resolve via GlobalStringTable
    const char *str = fixed_string_resolve(fs_index);
    if (str) {
        lua_pushstring(L, str);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

// ============================================================================
// Struct Probing Utilities
// ============================================================================

int lua_debug_probe_struct(lua_State *L) {
    uintptr_t base = parse_address(L, 1);
    int startOffset = (int)luaL_optinteger(L, 2, 0);
    int endOffset = (int)luaL_optinteger(L, 3, 0x100);
    int stride = (int)luaL_optinteger(L, 4, 8);

    if (base == 0 || stride < 1 || endOffset <= startOffset) {
        lua_newtable(L);
        return 1;
    }

    // Limit scan range
    if (endOffset - startOffset > 0x10000) {
        endOffset = startOffset + 0x10000;
    }

    lua_newtable(L);

    for (int offset = startOffset; offset < endOffset; offset += stride) {
        uintptr_t addr = base + offset;

        // Create subtable for this offset
        lua_pushinteger(L, offset);
        lua_newtable(L);

        // Try to read as pointer
        void *ptr_val = NULL;
        if (safe_memory_read_pointer((mach_vm_address_t)addr, &ptr_val)) {
            lua_pushstring(L, "ptr");
            lua_pushinteger(L, (lua_Integer)(uintptr_t)ptr_val);
            lua_settable(L, -3);
        }

        // Try to read as u32
        uint32_t u32_val = 0;
        if (safe_memory_read_u32((mach_vm_address_t)addr, &u32_val)) {
            lua_pushstring(L, "u32");
            lua_pushinteger(L, (lua_Integer)u32_val);
            lua_settable(L, -3);
        }

        // Try to read as i32
        int32_t i32_val = 0;
        if (safe_memory_read_i32((mach_vm_address_t)addr, &i32_val)) {
            lua_pushstring(L, "i32");
            lua_pushinteger(L, (lua_Integer)i32_val);
            lua_settable(L, -3);
        }

        // Try to read as float
        float float_val = 0.0f;
        if (safe_memory_read((mach_vm_address_t)addr, &float_val, sizeof(float))) {
            // Only include if it looks like a reasonable float
            if (float_val != 0.0f && float_val > -1e10 && float_val < 1e10) {
                lua_pushstring(L, "float");
                lua_pushnumber(L, (lua_Number)float_val);
                lua_settable(L, -3);
            }
        }

        // If reading at offset+8 gives a capacity-like value, note it
        if (stride >= 8) {
            uint32_t cap_val = 0, size_val = 0;
            if (safe_memory_read_u32((mach_vm_address_t)(addr + 8), &cap_val) &&
                safe_memory_read_u32((mach_vm_address_t)(addr + 12), &size_val)) {
                if (cap_val > 0 && cap_val < 0x100000 && size_val <= cap_val) {
                    lua_pushstring(L, "cap");
                    lua_pushinteger(L, (lua_Integer)cap_val);
                    lua_settable(L, -3);

                    lua_pushstring(L, "size");
                    lua_pushinteger(L, (lua_Integer)size_val);
                    lua_settable(L, -3);
                }
            }
        }

        lua_settable(L, -3);  // Set results[offset] = subtable
    }

    return 1;
}

int lua_debug_find_array_pattern(lua_State *L) {
    uintptr_t base = parse_address(L, 1);
    int range = (int)luaL_optinteger(L, 2, 0x1000);

    if (base == 0) {
        lua_newtable(L);
        return 1;
    }

    // Limit range
    if (range > 0x10000) range = 0x10000;

    lua_newtable(L);
    int result_index = 1;

    // Scan for array patterns: (ptr, u32 capacity, u32 size) or (ptr, u32 size, u32 capacity)
    for (int offset = 0; offset < range; offset += 8) {
        uintptr_t addr = base + offset;

        void *ptr_val = NULL;
        uint32_t val1 = 0, val2 = 0;

        if (!safe_memory_read_pointer((mach_vm_address_t)addr, &ptr_val)) continue;
        if (!safe_memory_read_u32((mach_vm_address_t)(addr + 8), &val1)) continue;
        if (!safe_memory_read_u32((mach_vm_address_t)(addr + 12), &val2)) continue;

        // Check if this looks like an array: valid pointer, reasonable size/capacity
        uintptr_t ptr_int = (uintptr_t)ptr_val;
        if (ptr_int < 0x100000000ULL) continue;  // Pointer should be in high memory
        if (ptr_int > 0x800000000000ULL) continue;  // Not too high

        // Check for (ptr, capacity, size) pattern where size <= capacity
        bool is_array = false;
        uint32_t cap = 0, size = 0;

        if (val1 > 0 && val1 < 0x100000 && val2 <= val1) {
            // (ptr, capacity, size)
            cap = val1;
            size = val2;
            is_array = true;
        } else if (val2 > 0 && val2 < 0x100000 && val1 <= val2) {
            // (ptr, size, capacity)
            size = val1;
            cap = val2;
            is_array = true;
        }

        if (is_array && size > 0) {
            lua_pushinteger(L, result_index++);
            lua_newtable(L);

            lua_pushstring(L, "offset");
            lua_pushinteger(L, offset);
            lua_settable(L, -3);

            lua_pushstring(L, "ptr");
            lua_pushinteger(L, (lua_Integer)ptr_int);
            lua_settable(L, -3);

            lua_pushstring(L, "capacity");
            lua_pushinteger(L, (lua_Integer)cap);
            lua_settable(L, -3);

            lua_pushstring(L, "size");
            lua_pushinteger(L, (lua_Integer)size);
            lua_settable(L, -3);

            lua_settable(L, -3);  // Set results[index] = entry
        }
    }

    return 1;
}

int lua_debug_probe_fixedstring_array(lua_State *L) {
    uintptr_t base = parse_address(L, 1);
    int offset = (int)luaL_optinteger(L, 2, 0);
    int count = (int)luaL_optinteger(L, 3, 10);

    if (base == 0 || count < 1) {
        lua_newtable(L);
        return 1;
    }

    if (count > 1000) count = 1000;  // Limit for safety

    lua_newtable(L);

    uintptr_t array_addr = base + offset;
    for (int i = 0; i < count; i++) {
        uint32_t fs_index = 0;
        if (!safe_memory_read_u32((mach_vm_address_t)(array_addr + i * 4), &fs_index)) {
            break;  // Stop on read failure
        }

        // Skip null/invalid indices
        if (fs_index == 0 || fs_index == 0xFFFFFFFF) {
            continue;
        }

        const char *str = fixed_string_resolve(fs_index);
        if (str) {
            lua_pushinteger(L, i + 1);  // 1-indexed
            lua_newtable(L);

            lua_pushstring(L, "index");
            lua_pushinteger(L, i);
            lua_settable(L, -3);

            lua_pushstring(L, "fs_index");
            lua_pushinteger(L, fs_index);
            lua_settable(L, -3);

            lua_pushstring(L, "value");
            lua_pushstring(L, str);
            lua_settable(L, -3);

            lua_settable(L, -3);
        }
    }

    return 1;
}

int lua_debug_hex_dump(lua_State *L) {
    uintptr_t addr = parse_address(L, 1);
    int size = (int)luaL_optinteger(L, 2, 64);

    if (addr == 0) {
        lua_pushnil(L);
        return 1;
    }

    if (size < 1) size = 64;
    if (size > 1024) size = 1024;

    // Allocate buffer for formatted output
    // Each line: "ADDR: XX XX XX XX ... | ASCII...\n"
    size_t out_size = (size / 16 + 1) * 80;
    char *output = (char *)malloc(out_size);
    if (!output) {
        lua_pushnil(L);
        return 1;
    }
    output[0] = '\0';

    char line[128];
    unsigned char bytes[16];

    for (int i = 0; i < size; i += 16) {
        int line_size = (size - i > 16) ? 16 : (size - i);

        // Read bytes safely
        bool valid = safe_memory_read((mach_vm_address_t)(addr + i), bytes, line_size);

        // Format address
        int pos = snprintf(line, sizeof(line), "%012llx: ", (unsigned long long)(addr + i));

        // Format hex
        for (int j = 0; j < 16; j++) {
            if (j < line_size && valid) {
                pos += snprintf(line + pos, sizeof(line) - pos, "%02x ", bytes[j]);
            } else {
                pos += snprintf(line + pos, sizeof(line) - pos, "   ");
            }
        }

        // ASCII representation
        pos += snprintf(line + pos, sizeof(line) - pos, "| ");
        for (int j = 0; j < line_size && valid; j++) {
            char c = (bytes[j] >= 32 && bytes[j] < 127) ? (char)bytes[j] : '.';
            pos += snprintf(line + pos, sizeof(line) - pos, "%c", c);
        }
        pos += snprintf(line + pos, sizeof(line) - pos, "\n");

        strncat(output, line, out_size - strlen(output) - 1);
    }

    lua_pushstring(L, output);
    free(output);
    return 1;
}

// ============================================================================
// Time and Session Utilities
// ============================================================================

/**
 * Ext.Debug.Time() - Get current time as HH:MM:SS string
 * Helps correlate console commands with log output
 */
int lua_debug_time(lua_State *L) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);

    char buffer[32];
    strftime(buffer, sizeof(buffer), "%H:%M:%S", tm_info);

    lua_pushstring(L, buffer);
    return 1;
}

/**
 * Ext.Debug.Timestamp() - Get current Unix timestamp (seconds)
 */
int lua_debug_timestamp(lua_State *L) {
    lua_pushinteger(L, (lua_Integer)time(NULL));
    return 1;
}

/**
 * Ext.Debug.SessionStart() - Get session start time as HH:MM:SS
 */
int lua_debug_session_start(lua_State *L) {
    if (g_session_start_time == 0) {
        g_session_start_time = time(NULL);
    }

    struct tm *tm_info = localtime(&g_session_start_time);
    char buffer[32];
    strftime(buffer, sizeof(buffer), "%H:%M:%S", tm_info);

    lua_pushstring(L, buffer);
    return 1;
}

/**
 * Ext.Debug.SessionAge() - Get seconds since session started
 */
int lua_debug_session_age(lua_State *L) {
    if (g_session_start_time == 0) {
        g_session_start_time = time(NULL);
    }

    lua_pushinteger(L, (lua_Integer)(time(NULL) - g_session_start_time));
    return 1;
}

// ============================================================================
// Pointer Validation and Classification
// ============================================================================

/**
 * Ext.Debug.IsValidPointer(addr) - Check if pointer looks valid
 * Returns true if the address is in a readable memory region
 */
int lua_debug_is_valid_pointer(lua_State *L) {
    uintptr_t addr = parse_address(L, 1);

    if (addr == 0) {
        lua_pushboolean(L, 0);
        return 1;
    }

    // Quick range check - valid pointers on macOS are typically:
    // - Above 0x100000000 (4GB, ASLR base)
    // - Below 0x800000000000 (high limit)
    if (addr < 0x100000000ULL || addr > 0x800000000000ULL) {
        lua_pushboolean(L, 0);
        return 1;
    }

    // Try to read a single byte to verify
    uint8_t test = 0;
    bool readable = safe_memory_read((mach_vm_address_t)addr, &test, 1);

    lua_pushboolean(L, readable ? 1 : 0);
    return 1;
}

/* Pointer type classification - currently using inline strings in ClassifyPointer */

/**
 * Ext.Debug.ClassifyPointer(addr) - Classify what a pointer likely points to
 * Returns: { type = "heap"|"code"|"string"|etc, readable = bool, info = string }
 */
int lua_debug_classify_pointer(lua_State *L) {
    uintptr_t addr = parse_address(L, 1);

    lua_newtable(L);

    // Null check
    if (addr == 0) {
        lua_pushstring(L, "null");
        lua_setfield(L, -2, "type");
        lua_pushboolean(L, 0);
        lua_setfield(L, -2, "readable");
        return 1;
    }

    // Small integer check (likely not a pointer)
    if (addr < 0x10000) {
        lua_pushstring(L, "small_int");
        lua_setfield(L, -2, "type");
        lua_pushboolean(L, 0);
        lua_setfield(L, -2, "readable");
        lua_pushinteger(L, (lua_Integer)addr);
        lua_setfield(L, -2, "value");
        return 1;
    }

    // Check if readable
    uint8_t test_bytes[16];
    bool readable = safe_memory_read((mach_vm_address_t)addr, test_bytes, sizeof(test_bytes));

    lua_pushboolean(L, readable ? 1 : 0);
    lua_setfield(L, -2, "readable");

    if (!readable) {
        lua_pushstring(L, "invalid");
        lua_setfield(L, -2, "type");
        return 1;
    }

    // Check for string (mostly printable ASCII)
    int printable = 0;
    int total = 0;
    for (int i = 0; i < 16 && test_bytes[i] != 0; i++) {
        total++;
        if (test_bytes[i] >= 32 && test_bytes[i] < 127) {
            printable++;
        }
    }
    if (total >= 4 && printable * 100 / total >= 80) {
        lua_pushstring(L, "string");
        lua_setfield(L, -2, "type");

        // Read and include the string preview
        char preview[64];
        if (safe_memory_read_string((mach_vm_address_t)addr, preview, sizeof(preview) - 1)) {
            preview[sizeof(preview) - 1] = '\0';
            lua_pushstring(L, preview);
            lua_setfield(L, -2, "preview");
        }
        return 1;
    }

    // Check for vtable pattern (first 8 bytes point to code-like address)
    void *first_ptr = NULL;
    if (safe_memory_read_pointer((mach_vm_address_t)addr, &first_ptr)) {
        uintptr_t fp = (uintptr_t)first_ptr;
        // Code typically in 0x100000000 - 0x108000000 range for main binary
        if (fp >= 0x100000000ULL && fp < 0x110000000ULL) {
            // Could be vtable - check if the pointer points to more pointers
            void *second_ptr = NULL;
            if (safe_memory_read_pointer((mach_vm_address_t)(addr + 8), &second_ptr)) {
                uintptr_t sp = (uintptr_t)second_ptr;
                if (sp >= 0x100000000ULL && sp < 0x110000000ULL) {
                    lua_pushstring(L, "vtable");
                    lua_setfield(L, -2, "type");
                    return 1;
                }
            }
        }
    }

    // Classify by address range
    if (addr >= 0x100000000ULL && addr < 0x110000000ULL) {
        lua_pushstring(L, "data");  // Main binary data section
        lua_setfield(L, -2, "type");
    } else if (addr >= 0x600000000000ULL && addr < 0x700000000000ULL) {
        lua_pushstring(L, "heap");  // Typical heap range
        lua_setfield(L, -2, "type");
    } else if (addr >= 0x700000000000ULL) {
        lua_pushstring(L, "stack");  // Stack area
        lua_setfield(L, -2, "type");
    } else {
        lua_pushstring(L, "heap");  // Default to heap for other ranges
        lua_setfield(L, -2, "type");
    }

    return 1;
}

/**
 * Ext.Debug.PrintTime(msg) - Print message with timestamp prefix
 * Shortcut for: Ext.Print("[" .. Ext.Debug.Time() .. "] " .. msg)
 */
int lua_debug_print_time(lua_State *L) {
    const char *msg = luaL_checkstring(L, 1);

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", tm_info);

    log_message("[%s] %s", time_buf, msg);

    return 0;
}

// ============================================================================
// Event Tracing
// ============================================================================

/**
 * Ext.Debug.TraceEvents(enabled) - Enable/disable event tracing
 *
 * When enabled, logs detailed info about one-frame component polling
 * and event dispatching. Useful for debugging why events aren't firing.
 *
 * @param enabled Boolean to enable/disable tracing
 */
static int lua_debug_trace_events(lua_State *L) {
    bool enabled = lua_toboolean(L, 1);
    events_set_trace_enabled(enabled);
    return 0;
}

/**
 * Ext.Debug.IsTracingEvents() - Check if event tracing is enabled
 * @return Boolean
 */
static int lua_debug_is_tracing_events(lua_State *L) {
    lua_pushboolean(L, events_get_trace_enabled());
    return 1;
}

// ============================================================================
// Mod Health Diagnostics (for !mod_diag)
// ============================================================================

/**
 * Ext.Debug.ModHealthCount() - Get number of tracked mods
 * @return integer
 */
static int lua_debug_mod_health_count(lua_State *L) {
    lua_pushinteger(L, events_get_mod_health_count());
    return 1;
}

/**
 * Ext.Debug.ModHealthAll() - Get all mod health entries
 * @return table of {name, handlers, errors, handled, disabled, last_error}
 */
static int lua_debug_mod_health_all(lua_State *L) {
    int count = events_get_mod_health_count();
    lua_createtable(L, count, 0);

    for (int i = 0; i < count; i++) {
        const char *name = events_get_mod_health_name(i);
        uint32_t handlers = 0, errors = 0, handled = 0;
        bool disabled = false;
        events_get_mod_health_stats(i, &handlers, &errors, &handled, &disabled);
        const char *last_error = events_get_mod_last_error(i);

        lua_createtable(L, 0, 6);

        lua_pushstring(L, name ? name : "unknown");
        lua_setfield(L, -2, "name");

        lua_pushinteger(L, handlers);
        lua_setfield(L, -2, "handlers");

        lua_pushinteger(L, errors);
        lua_setfield(L, -2, "errors");

        lua_pushinteger(L, handled);
        lua_setfield(L, -2, "handled");

        lua_pushboolean(L, disabled);
        lua_setfield(L, -2, "disabled");

        if (last_error) {
            lua_pushstring(L, last_error);
        } else {
            lua_pushnil(L);
        }
        lua_setfield(L, -2, "last_error");

        lua_rawseti(L, -2, i + 1);
    }

    return 1;
}

/**
 * Ext.Debug.ModDisable(mod_name, disabled) - Soft-disable/enable a mod
 * @param mod_name string
 * @param disabled boolean
 * @return boolean (true if mod found)
 */
static int lua_debug_mod_disable(lua_State *L) {
    const char *mod_name = luaL_checkstring(L, 1);
    bool disabled = lua_toboolean(L, 2);
    bool found = events_set_mod_disabled(mod_name, disabled);
    lua_pushboolean(L, found);
    return 1;
}

// ============================================================================
// Registration
// ============================================================================

void lua_ext_register_debug(lua_State *L, int ext_table_index) {
    // Initialize session start time
    if (g_session_start_time == 0) {
        g_session_start_time = time(NULL);
    }
    // Convert negative index to absolute since we'll be pushing onto stack
    if (ext_table_index < 0) {
        ext_table_index = lua_gettop(L) + ext_table_index + 1;
    }

    // Create Ext.Debug table
    lua_newtable(L);

    // Register functions
    lua_pushcfunction(L, lua_debug_read_ptr);
    lua_setfield(L, -2, "ReadPtr");

    lua_pushcfunction(L, lua_debug_read_u32);
    lua_setfield(L, -2, "ReadU32");

    lua_pushcfunction(L, lua_debug_read_u64);
    lua_setfield(L, -2, "ReadU64");

    lua_pushcfunction(L, lua_debug_read_i32);
    lua_setfield(L, -2, "ReadI32");

    lua_pushcfunction(L, lua_debug_read_float);
    lua_setfield(L, -2, "ReadFloat");

    lua_pushcfunction(L, lua_debug_read_string);
    lua_setfield(L, -2, "ReadString");

    lua_pushcfunction(L, lua_debug_read_fixedstring);
    lua_setfield(L, -2, "ReadFixedString");

    lua_pushcfunction(L, lua_debug_probe_struct);
    lua_setfield(L, -2, "ProbeStruct");

    lua_pushcfunction(L, lua_debug_find_array_pattern);
    lua_setfield(L, -2, "FindArrayPattern");

    lua_pushcfunction(L, lua_debug_probe_fixedstring_array);
    lua_setfield(L, -2, "ProbeFixedStringArray");

    lua_pushcfunction(L, lua_debug_hex_dump);
    lua_setfield(L, -2, "HexDump");

    // Time and session utilities
    lua_pushcfunction(L, lua_debug_time);
    lua_setfield(L, -2, "Time");

    lua_pushcfunction(L, lua_debug_timestamp);
    lua_setfield(L, -2, "Timestamp");

    lua_pushcfunction(L, lua_debug_session_start);
    lua_setfield(L, -2, "SessionStart");

    lua_pushcfunction(L, lua_debug_session_age);
    lua_setfield(L, -2, "SessionAge");

    lua_pushcfunction(L, lua_debug_print_time);
    lua_setfield(L, -2, "PrintTime");

    // Pointer validation and classification
    lua_pushcfunction(L, lua_debug_is_valid_pointer);
    lua_setfield(L, -2, "IsValidPointer");

    lua_pushcfunction(L, lua_debug_classify_pointer);
    lua_setfield(L, -2, "ClassifyPointer");

    // Event tracing
    lua_pushcfunction(L, lua_debug_trace_events);
    lua_setfield(L, -2, "TraceEvents");

    lua_pushcfunction(L, lua_debug_is_tracing_events);
    lua_setfield(L, -2, "IsTracingEvents");

    // Mod health diagnostics
    lua_pushcfunction(L, lua_debug_mod_health_count);
    lua_setfield(L, -2, "ModHealthCount");

    lua_pushcfunction(L, lua_debug_mod_health_all);
    lua_setfield(L, -2, "ModHealthAll");

    lua_pushcfunction(L, lua_debug_mod_disable);
    lua_setfield(L, -2, "ModDisable");

    // Set Ext.Debug = table
    lua_setfield(L, ext_table_index, "Debug");

    LOG_LUA_INFO("Registered Ext.Debug namespace (session started at %s)",
                 ctime(&g_session_start_time));
}
