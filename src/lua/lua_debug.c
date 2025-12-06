/**
 * lua_debug.c - Debug/Introspection API for BG3SE-macOS
 *
 * Provides low-level memory reading and struct probing utilities.
 * Uses safe_memory APIs for crash-safe memory access.
 */

#include "lua_debug.h"
#include "../core/logging.h"
#include "../core/safe_memory.h"
#include "../strings/fixed_string.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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
// Registration
// ============================================================================

void lua_ext_register_debug(lua_State *L, int ext_table_index) {
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

    lua_pushcfunction(L, lua_debug_hex_dump);
    lua_setfield(L, -2, "HexDump");

    // Set Ext.Debug = table
    lua_setfield(L, ext_table_index, "Debug");

    log_message("[Lua] Registered Ext.Debug namespace");
}
