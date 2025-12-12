/**
 * BG3SE-macOS - Lua Ext Namespace Core Implementation
 *
 * Core Ext.* API functions.
 */

#include "lua_ext.h"
#include "version.h"
#include "logging.h"
#include "../console/console.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/vm_map.h>

// ============================================================================
// Ext Core Functions
// ============================================================================

int lua_ext_print(lua_State *L) {
    int n = lua_gettop(L);
    luaL_Buffer b;
    luaL_buffinit(L, &b);

    for (int i = 1; i <= n; i++) {
        size_t len;
        const char *s = luaL_tolstring(L, i, &len);
        if (i > 1) luaL_addchar(&b, '\t');
        luaL_addlstring(&b, s, len);
        lua_pop(L, 1);  // pop the string from luaL_tolstring
    }

    luaL_pushresult(&b);
    const char *msg = lua_tostring(L, -1);
    LOG_LUA_INFO("%s", msg);

    // Forward to connected console clients
    console_send_output(msg, false);

    return 0;
}

int lua_ext_getversion(lua_State *L) {
    lua_pushstring(L, BG3SE_VERSION);
    return 1;
}

int lua_ext_isserver(lua_State *L) {
    // For now, always return false (client-side)
    lua_pushboolean(L, 0);
    return 1;
}

int lua_ext_isclient(lua_State *L) {
    // For now, always return true (client-side)
    lua_pushboolean(L, 1);
    return 1;
}

// ============================================================================
// Ext.IO Functions
// ============================================================================

int lua_ext_io_loadfile(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    LOG_LUA_INFO("Ext.IO.LoadFile('%s')", path);

    FILE *f = fopen(path, "r");
    if (!f) {
        lua_pushnil(L);
        lua_pushstring(L, "File not found");
        return 2;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *content = (char *)malloc(size + 1);
    if (!content) {
        fclose(f);
        lua_pushnil(L);
        lua_pushstring(L, "Out of memory");
        return 2;
    }

    fread(content, 1, size, f);
    content[size] = '\0';
    fclose(f);

    lua_pushstring(L, content);
    free(content);
    return 1;
}

int lua_ext_io_savefile(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    const char *content = luaL_checkstring(L, 2);
    LOG_LUA_INFO("Ext.IO.SaveFile('%s')", path);

    FILE *f = fopen(path, "w");
    if (!f) {
        lua_pushboolean(L, 0);
        return 1;
    }

    fputs(content, f);
    fclose(f);

    lua_pushboolean(L, 1);
    return 1;
}

// ============================================================================
// Ext.Memory Functions
// ============================================================================

// Helper: Parse address from Lua (integer or hex string like "0x12345678")
static uintptr_t parse_address(lua_State *L, int idx) {
    if (lua_isinteger(L, idx)) {
        return (uintptr_t)lua_tointeger(L, idx);
    } else if (lua_isstring(L, idx)) {
        const char *s = lua_tostring(L, idx);
        return (uintptr_t)strtoull(s, NULL, 0);  // Handles 0x prefix
    }
    return 0;
}

// Helper: Check if memory is readable using vm_read
static int is_memory_readable(uintptr_t addr, size_t size) {
    mach_msg_type_number_t read_size = 0;
    vm_offset_t data = 0;
    kern_return_t kr = vm_read(mach_task_self(), (vm_address_t)addr, size, &data, &read_size);
    if (kr == KERN_SUCCESS) {
        vm_deallocate(mach_task_self(), data, read_size);
        return 1;
    }
    return 0;
}

int lua_ext_memory_read(lua_State *L) {
    uintptr_t addr = parse_address(L, 1);
    int size = (int)luaL_optinteger(L, 2, 16);

    if (addr == 0) {
        lua_pushnil(L);
        lua_pushstring(L, "Invalid address");
        return 2;
    }

    if (size < 1 || size > 4096) {
        lua_pushnil(L);
        lua_pushstring(L, "Size must be 1-4096");
        return 2;
    }

    // Check if memory is readable
    if (!is_memory_readable(addr, (size_t)size)) {
        lua_pushnil(L);
        lua_pushfstring(L, "Memory at 0x%llx is not readable", (unsigned long long)addr);
        return 2;
    }

    // Read memory via vm_read for safety
    mach_msg_type_number_t read_size = 0;
    vm_offset_t data = 0;
    kern_return_t kr = vm_read(mach_task_self(), (vm_address_t)addr, size, &data, &read_size);
    if (kr != KERN_SUCCESS) {
        lua_pushnil(L);
        lua_pushstring(L, "Failed to read memory");
        return 2;
    }

    // Format as hex string
    luaL_Buffer b;
    luaL_buffinit(L, &b);
    unsigned char *bytes = (unsigned char *)data;
    for (mach_msg_type_number_t i = 0; i < read_size; i++) {
        char hex[4];
        snprintf(hex, sizeof(hex), "%02X ", bytes[i]);
        luaL_addstring(&b, hex);
    }
    luaL_pushresult(&b);

    vm_deallocate(mach_task_self(), data, read_size);
    return 1;
}

int lua_ext_memory_readstring(lua_State *L) {
    uintptr_t addr = parse_address(L, 1);
    int maxLen = (int)luaL_optinteger(L, 2, 256);

    if (addr == 0) {
        lua_pushnil(L);
        return 1;
    }

    if (maxLen < 1 || maxLen > 4096) {
        maxLen = 256;
    }

    // Check if memory is readable
    if (!is_memory_readable(addr, 1)) {
        lua_pushnil(L);
        return 1;
    }

    // Read memory
    mach_msg_type_number_t read_size = 0;
    vm_offset_t data = 0;
    kern_return_t kr = vm_read(mach_task_self(), (vm_address_t)addr, maxLen, &data, &read_size);
    if (kr != KERN_SUCCESS) {
        lua_pushnil(L);
        return 1;
    }

    // Find null terminator
    char *str = (char *)data;
    mach_msg_type_number_t len = 0;
    while (len < read_size && str[len] != '\0') {
        len++;
    }

    lua_pushlstring(L, str, len);
    vm_deallocate(mach_task_self(), data, read_size);
    return 1;
}

// Helper: Parse hex pattern like "53 74 72" or "5 74 72" into bytes
static int parse_hex_pattern(const char *pattern, unsigned char *out, int maxLen) {
    int count = 0;
    const char *p = pattern;

    while (*p && count < maxLen) {
        // Skip whitespace
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;

        // Parse hex byte (1 or 2 hex digits)
        char *end;
        unsigned long val = strtoul(p, &end, 16);
        if (end == p) break;  // No valid hex found
        if (val > 255) break;  // Invalid byte value

        out[count++] = (unsigned char)val;
        p = end;
    }
    return count;
}

int lua_ext_memory_search(lua_State *L) {
    const char *pattern = luaL_checkstring(L, 1);
    uintptr_t startAddr = parse_address(L, 2);
    lua_Integer searchSize = luaL_optinteger(L, 3, 64 * 1024 * 1024);  // 64MB default

    // Parse pattern
    unsigned char patternBytes[64];
    int patternLen = parse_hex_pattern(pattern, patternBytes, 64);
    if (patternLen == 0) {
        lua_newtable(L);
        return 1;
    }

    // If no start address, get main binary base
    if (startAddr == 0) {
        startAddr = (uintptr_t)_dyld_get_image_header(0);
    }

    LOG_MEMORY_DEBUG("Searching for %d-byte pattern from 0x%llx, size %lld",
                patternLen, (unsigned long long)startAddr, (long long)searchSize);

    // Create result table
    lua_newtable(L);
    int resultIdx = 1;
    int maxResults = 100;

    // Search in chunks
    size_t chunkSize = 1024 * 1024;  // 1MB chunks
    for (uintptr_t offset = 0; offset < (uintptr_t)searchSize && resultIdx <= maxResults; offset += chunkSize) {
        uintptr_t chunkAddr = startAddr + offset;
        size_t thisChunk = chunkSize;
        if (offset + thisChunk > (uintptr_t)searchSize) {
            thisChunk = (size_t)(searchSize - offset);
        }

        // Try to read this chunk
        mach_msg_type_number_t read_size = 0;
        vm_offset_t data = 0;
        kern_return_t kr = vm_read(mach_task_self(), (vm_address_t)chunkAddr, thisChunk, &data, &read_size);
        if (kr != KERN_SUCCESS) {
            continue;  // Skip unreadable regions
        }

        // Search within chunk
        unsigned char *bytes = (unsigned char *)data;
        for (mach_msg_type_number_t i = 0; i + patternLen <= read_size && resultIdx <= maxResults; i++) {
            if (memcmp(bytes + i, patternBytes, patternLen) == 0) {
                lua_pushinteger(L, (lua_Integer)(chunkAddr + i));
                lua_rawseti(L, -2, resultIdx++);
            }
        }

        vm_deallocate(mach_task_self(), data, read_size);
    }

    LOG_MEMORY_DEBUG("Found %d matches", resultIdx - 1);
    return 1;
}

int lua_ext_memory_getmodulebase(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (imageName && strstr(imageName, name)) {
            const struct mach_header *header = _dyld_get_image_header(i);
            lua_pushinteger(L, (lua_Integer)(uintptr_t)header);
            LOG_MEMORY_DEBUG("Module '%s' base: 0x%llx", name, (unsigned long long)(uintptr_t)header);
            return 1;
        }
    }

    lua_pushnil(L);
    return 1;
}

// ============================================================================
// Registration
// ============================================================================

void lua_ext_register_basic(lua_State *L, int ext_table_index) {
    // Convert negative index to absolute since we'll be pushing onto stack
    if (ext_table_index < 0) {
        ext_table_index = lua_gettop(L) + ext_table_index + 1;
    }

    lua_pushcfunction(L, lua_ext_print);
    lua_setfield(L, ext_table_index, "Print");

    lua_pushcfunction(L, lua_ext_getversion);
    lua_setfield(L, ext_table_index, "GetVersion");

    lua_pushcfunction(L, lua_ext_isserver);
    lua_setfield(L, ext_table_index, "IsServer");

    lua_pushcfunction(L, lua_ext_isclient);
    lua_setfield(L, ext_table_index, "IsClient");

    lua_pushcfunction(L, console_register_command);
    lua_setfield(L, ext_table_index, "RegisterConsoleCommand");
}

void lua_ext_register_io(lua_State *L, int ext_table_index) {
    // Convert negative index to absolute since we'll be pushing onto stack
    if (ext_table_index < 0) {
        ext_table_index = lua_gettop(L) + ext_table_index + 1;
    }

    // Create Ext.IO table
    lua_newtable(L);
    lua_pushcfunction(L, lua_ext_io_loadfile);
    lua_setfield(L, -2, "LoadFile");
    lua_pushcfunction(L, lua_ext_io_savefile);
    lua_setfield(L, -2, "SaveFile");
    lua_setfield(L, ext_table_index, "IO");
}

void lua_ext_register_memory(lua_State *L, int ext_table_index) {
    // Convert negative index to absolute since we'll be pushing onto stack
    if (ext_table_index < 0) {
        ext_table_index = lua_gettop(L) + ext_table_index + 1;
    }

    // Create Ext.Memory table
    lua_newtable(L);
    lua_pushcfunction(L, lua_ext_memory_read);
    lua_setfield(L, -2, "Read");
    lua_pushcfunction(L, lua_ext_memory_readstring);
    lua_setfield(L, -2, "ReadString");
    lua_pushcfunction(L, lua_ext_memory_search);
    lua_setfield(L, -2, "Search");
    lua_pushcfunction(L, lua_ext_memory_getmodulebase);
    lua_setfield(L, -2, "GetModuleBase");
    lua_setfield(L, ext_table_index, "Memory");

    LOG_LUA_INFO("Ext.Memory namespace registered");
}

// ============================================================================
// Ext.Types Namespace (Type Introspection)
// ============================================================================

// Known userdata type names (metatables we register)
static const char* const s_known_types[] = {
    "bg3se.StatsObject",
    "bg3se.Entity",
    "bg3se.EntityHandle",
    NULL
};

// Ext.Types.GetObjectType(obj) -> string
// Returns the internal type name of a userdata object
static int lua_types_getobjecttype(lua_State *L) {
    if (!lua_isuserdata(L, 1)) {
        lua_pushstring(L, lua_typename(L, lua_type(L, 1)));
        return 1;
    }

    // Get metatable of the userdata
    if (!lua_getmetatable(L, 1)) {
        lua_pushstring(L, "userdata (no metatable)");
        return 1;
    }

    // Check against known metatables
    for (int i = 0; s_known_types[i] != NULL; i++) {
        luaL_getmetatable(L, s_known_types[i]);
        if (lua_rawequal(L, -1, -2)) {
            lua_pop(L, 2);  // Pop both metatables
            lua_pushstring(L, s_known_types[i]);
            return 1;
        }
        lua_pop(L, 1);  // Pop the known metatable
    }

    // Try to get __name field from metatable
    lua_getfield(L, -1, "__name");
    if (lua_isstring(L, -1)) {
        const char *name = lua_tostring(L, -1);
        lua_pop(L, 2);  // Pop __name and metatable
        lua_pushstring(L, name);
        return 1;
    }
    lua_pop(L, 2);  // Pop __name (nil) and metatable

    lua_pushstring(L, "userdata (unknown type)");
    return 1;
}

// Ext.Types.Validate(obj) -> boolean
// Checks if an object reference is still valid
static int lua_types_validate(lua_State *L) {
    if (lua_isnil(L, 1)) {
        lua_pushboolean(L, 0);
        return 1;
    }

    if (!lua_isuserdata(L, 1)) {
        // Non-userdata types are always valid
        lua_pushboolean(L, 1);
        return 1;
    }

    // For userdata, check if it has a metatable (basic validity check)
    if (!lua_getmetatable(L, 1)) {
        lua_pushboolean(L, 0);
        return 1;
    }
    lua_pop(L, 1);

    // For StatsObject, check if the internal pointer is valid
    luaL_getmetatable(L, "bg3se.StatsObject");
    int has_mt = lua_getmetatable(L, 1);
    if (has_mt && lua_rawequal(L, -1, -2)) {
        lua_pop(L, 2);
        // StatsObject has a pointer member - check it
        void **ptr = (void **)lua_touserdata(L, 1);
        if (ptr && *ptr != NULL) {
            lua_pushboolean(L, 1);
        } else {
            lua_pushboolean(L, 0);
        }
        return 1;
    }
    if (has_mt) lua_pop(L, 1);
    lua_pop(L, 1);

    // For other userdata, assume valid if has metatable
    lua_pushboolean(L, 1);
    return 1;
}

// Ext.Types.GetTypeInfo(typeName) -> table
// Returns metadata about a registered type
static int lua_types_gettypeinfo(lua_State *L) {
    const char *type_name = luaL_checkstring(L, 1);

    lua_newtable(L);

    lua_pushstring(L, type_name);
    lua_setfield(L, -2, "Name");

    // Check if this is a known type
    int found = 0;
    for (int i = 0; s_known_types[i] != NULL; i++) {
        if (strcmp(s_known_types[i], type_name) == 0) {
            found = 1;
            break;
        }
    }

    lua_pushboolean(L, found);
    lua_setfield(L, -2, "Registered");

    // Try to get the metatable
    luaL_getmetatable(L, type_name);
    if (!lua_isnil(L, -1)) {
        lua_pushboolean(L, 1);
        lua_setfield(L, -3, "HasMetatable");

        // Count methods in metatable
        int method_count = 0;
        lua_pushnil(L);
        while (lua_next(L, -2) != 0) {
            method_count++;
            lua_pop(L, 1);  // Pop value, keep key
        }
        lua_pushinteger(L, method_count);
        lua_setfield(L, -3, "MethodCount");
    } else {
        lua_pushboolean(L, 0);
        lua_setfield(L, -3, "HasMetatable");
    }
    lua_pop(L, 1);  // Pop metatable (or nil)

    return 1;
}

// Ext.Types.GetAllTypes() -> table
// Returns list of all known/registered types
static int lua_types_getalltypes(lua_State *L) {
    lua_newtable(L);

    for (int i = 0; s_known_types[i] != NULL; i++) {
        lua_pushstring(L, s_known_types[i]);
        lua_rawseti(L, -2, i + 1);
    }

    return 1;
}

void lua_ext_register_types(lua_State *L, int ext_table_index) {
    // Convert negative index to absolute
    if (ext_table_index < 0) {
        ext_table_index = lua_gettop(L) + ext_table_index + 1;
    }

    // Create Ext.Types table
    lua_newtable(L);

    lua_pushcfunction(L, lua_types_getobjecttype);
    lua_setfield(L, -2, "GetObjectType");

    lua_pushcfunction(L, lua_types_validate);
    lua_setfield(L, -2, "Validate");

    lua_pushcfunction(L, lua_types_gettypeinfo);
    lua_setfield(L, -2, "GetTypeInfo");

    lua_pushcfunction(L, lua_types_getalltypes);
    lua_setfield(L, -2, "GetAllTypes");

    lua_setfield(L, ext_table_index, "Types");

    LOG_LUA_INFO("Ext.Types namespace registered");
}

// ============================================================================
// Global Helper Registration (for rapid debugging)
// ============================================================================

// _H(n) - Format number as hex string
static int lua_helper_hex(lua_State *L) {
    lua_Integer n = luaL_checkinteger(L, 1);
    lua_pushfstring(L, "0x%x", (unsigned int)n);
    return 1;
}

// _PTR(base, offset) - Pointer arithmetic helper
static int lua_helper_ptr(lua_State *L) {
    lua_Integer base = luaL_checkinteger(L, 1);
    lua_Integer offset = luaL_checkinteger(L, 2);
    lua_pushinteger(L, base + offset);
    return 1;
}

void lua_ext_register_global_helpers(lua_State *L) {
    // _P = Ext.Print (alias)
    lua_pushcfunction(L, lua_ext_print);
    lua_setglobal(L, "_P");

    // _H = hex formatter
    lua_pushcfunction(L, lua_helper_hex);
    lua_setglobal(L, "_H");

    // _PTR = pointer arithmetic
    lua_pushcfunction(L, lua_helper_ptr);
    lua_setglobal(L, "_PTR");

    // _D will be set in Lua to wrap Ext.Json.Stringify + Ext.Print
    // We'll define it as a Lua function after Ext is registered
    const char *dump_func =
        "_D = function(obj, depth)\n"
        "  if type(obj) == 'userdata' then\n"
        "    Ext.Print(tostring(obj))\n"
        "    return\n"
        "  end\n"
        "  local ok, json = pcall(function() return Ext.Json.Stringify(obj, depth or 2) end)\n"
        "  if ok then\n"
        "    Ext.Print(json)\n"
        "  else\n"
        "    Ext.Print(tostring(obj))\n"
        "  end\n"
        "end\n"
        "_DS = function(obj) _D(obj, 1) end\n"
        "_PE = function(...) Ext.Print('[ERROR]', ...) end\n";

    if (luaL_dostring(L, dump_func) != LUA_OK) {
        const char *err = lua_tostring(L, -1);
        LOG_LUA_WARN(" Failed to register dump helpers: %s", err ? err : "(unknown)");
        lua_pop(L, 1);
    }

    // Debug helper library (for reverse engineering acceleration)
    static const char *debug_lib =
        "Debug = Debug or {}\n"
        "function Debug.ProbeRefMap(mgr_addr, target_fs)\n"
        "  local cap = Ext.Debug.ReadU32(mgr_addr + 0x10) or 0\n"
        "  local keys = Ext.Debug.ReadPtr(mgr_addr + 0x28)\n"
        "  local vals = Ext.Debug.ReadPtr(mgr_addr + 0x38)\n"
        "  if not keys or not vals then return nil end\n"
        "  for i = 0, math.min(cap, 15000) - 1 do\n"
        "    local k = Ext.Debug.ReadU32(keys + i * 4)\n"
        "    if k == target_fs then\n"
        "      local v = Ext.Debug.ReadPtr(vals + i * 8)\n"
        "      return {index = i, key = k, value = v}\n"
        "    end\n"
        "  end\n"
        "  return nil\n"
        "end\n"
        "function Debug.ProbeStructSpec(base, spec)\n"
        "  local result = {}\n"
        "  for _, field in ipairs(spec) do\n"
        "    local name, off, typ = field[1], field[2], field[3]\n"
        "    if typ == 'ptr' then result[name] = Ext.Debug.ReadPtr(base + off)\n"
        "    elseif typ == 'u32' then result[name] = Ext.Debug.ReadU32(base + off)\n"
        "    elseif typ == 'u64' then result[name] = Ext.Debug.ReadU64(base + off)\n"
        "    elseif typ == 'i32' then result[name] = Ext.Debug.ReadI32(base + off)\n"
        "    elseif typ == 'float' then result[name] = Ext.Debug.ReadFloat(base + off)\n"
        "    elseif typ == 'str' then result[name] = Ext.Debug.ReadString(base + off, 64)\n"
        "    elseif typ == 'fs' then result[name] = Ext.Debug.ReadFixedString(base + off)\n"
        "    end\n"
        "  end\n"
        "  return result\n"
        "end\n"
        "function Debug.Hex(n) return string.format('0x%X', n or 0) end\n"
        "function Debug.HexMath(base, offset) return string.format('0x%X', (base or 0) + (offset or 0)) end\n"
        "function Debug.ProbeManager(mgr)\n"
        "  return {\n"
        "    buckets = Ext.Debug.ReadPtr(mgr + 0x08),\n"
        "    capacity = Ext.Debug.ReadU32(mgr + 0x10),\n"
        "    next_chain = Ext.Debug.ReadPtr(mgr + 0x18),\n"
        "    keys = Ext.Debug.ReadPtr(mgr + 0x28),\n"
        "    values = Ext.Debug.ReadPtr(mgr + 0x38)\n"
        "  }\n"
        "end\n";

    if (luaL_dostring(L, debug_lib) != LUA_OK) {
        const char *err = lua_tostring(L, -1);
        LOG_LUA_WARN(" Failed to register Debug library: %s", err ? err : "(unknown)");
        lua_pop(L, 1);
    }

    // Register built-in console commands (split into smaller chunks to avoid
    // exceeding the 4095 char limit that ISO C99 requires compilers to support)
    static const char *console_cmd_probe =
        "Ext.RegisterConsoleCommand('probe', function(cmd, addr, range)\n"
        "  local base = tonumber(addr, 16) or tonumber(addr) or 0\n"
        "  local r = tonumber(range) or 256\n"
        "  if base == 0 then Ext.Print('Usage: !probe <addr> [range]') return end\n"
        "  Ext.Print('Probing ' .. _H(base) .. ' range=' .. r)\n"
        "  local results = Ext.Debug.ProbeStruct(base, 0, r, 8)\n"
        "  for offset, data in pairs(results) do\n"
        "    local line = string.format('+0x%x:', offset)\n"
        "    if data.ptr and data.ptr ~= 0 then line = line .. ' ptr=' .. _H(data.ptr) end\n"
        "    if data.u32 then line = line .. ' u32=' .. data.u32 end\n"
        "    if data.float and data.float ~= 0 then line = line .. string.format(' f=%.3f', data.float) end\n"
        "    Ext.Print(line)\n"
        "  end\n"
        "end)\n";

    static const char *console_cmd_dumpstat =
        "Ext.RegisterConsoleCommand('dumpstat', function(cmd, name)\n"
        "  if not name then Ext.Print('Usage: !dumpstat <statName>') return end\n"
        "  local stat = Ext.Stats.Get(name)\n"
        "  if not stat then Ext.Print('Stat not found: ' .. name) return end\n"
        "  Ext.Print('=== ' .. name .. ' ===')\n"
        "  Ext.Print('Type: ' .. (stat.Type or 'unknown'))\n"
        "  Ext.Print('Level: ' .. (stat.Level or 0))\n"
        "  if stat.Using then Ext.Print('Using: ' .. stat.Using) end\n"
        "  local raw = Ext.Stats.GetObjectRaw(name)\n"
        "  if raw then\n"
        "    Ext.Print('Address: ' .. _H(raw.Address))\n"
        "    Ext.Print('PropertyCount: ' .. raw.PropertyCount)\n"
        "  end\n"
        "end)\n";

    static const char *console_cmd_findstr =
        "Ext.RegisterConsoleCommand('findstr', function(cmd, pattern)\n"
        "  if not pattern then Ext.Print('Usage: !findstr <pattern>') return end\n"
        "  Ext.Print('Searching for: ' .. pattern)\n"
        "  local hex = ''\n"
        "  for i = 1, #pattern do hex = hex .. string.format('%02x ', string.byte(pattern, i)) end\n"
        "  Ext.Print('Pattern: ' .. hex)\n"
        "  local results = Ext.Memory.Search(hex)\n"
        "  if #results == 0 then Ext.Print('No matches found')\n"
        "  else\n"
        "    Ext.Print('Found ' .. #results .. ' matches:')\n"
        "    for i, addr in ipairs(results) do if i <= 20 then Ext.Print('  ' .. _H(addr)) end end\n"
        "    if #results > 20 then Ext.Print('  ... and ' .. (#results - 20) .. ' more') end\n"
        "  end\n"
        "end)\n";

    static const char *console_cmd_hexdump =
        "Ext.RegisterConsoleCommand('hexdump', function(cmd, addr, size)\n"
        "  local base = tonumber(addr, 16) or tonumber(addr) or 0\n"
        "  local sz = tonumber(size) or 64\n"
        "  if base == 0 then Ext.Print('Usage: !hexdump <addr> [size]') return end\n"
        "  local dump = Ext.Debug.HexDump(base, sz)\n"
        "  if dump then Ext.Print(dump) else Ext.Print('Failed to read memory at ' .. _H(base)) end\n"
        "end)\n";

    static const char *console_cmd_types =
        "Ext.RegisterConsoleCommand('types', function(cmd)\n"
        "  Ext.Print('Registered types:')\n"
        "  for i, t in ipairs(Ext.Types.GetAllTypes()) do Ext.Print('  ' .. t) end\n"
        "end)\n";

    static const char *console_cmd_pv =
        "Ext.RegisterConsoleCommand('pv_dump', function(cmd)\n"
        "  Ext.Print('=== PersistentVars ===')\n"
        "  local found = false\n"
        "  for modTable, mod in pairs(Mods or {}) do\n"
        "    if mod.PersistentVars then\n"
        "      found = true\n"
        "      Ext.Print(modTable .. ':')\n"
        "      Ext.Print('  ' .. Ext.Json.Stringify(mod.PersistentVars))\n"
        "    end\n"
        "  end\n"
        "  if not found then Ext.Print('No mods have PersistentVars set') end\n"
        "end)\n"
        "Ext.RegisterConsoleCommand('pv_set', function(cmd, modTable, key, value)\n"
        "  if not modTable or not key then Ext.Print('Usage: !pv_set <modTable> <key> <value>') return end\n"
        "  Mods = Mods or {} Mods[modTable] = Mods[modTable] or {}\n"
        "  Mods[modTable].PersistentVars = Mods[modTable].PersistentVars or {}\n"
        "  Mods[modTable].PersistentVars[key] = value or ''\n"
        "  Ext.Vars.MarkDirty()\n"
        "  Ext.Print('Set Mods.' .. modTable .. '.PersistentVars.' .. key .. ' = ' .. tostring(value or ''))\n"
        "end)\n"
        "Ext.RegisterConsoleCommand('pv_save', function(cmd)\n"
        "  Ext.Print('Saving...') Ext.Vars.SyncPersistentVars() Ext.Print('Save complete')\n"
        "end)\n"
        "Ext.RegisterConsoleCommand('pv_reload', function(cmd)\n"
        "  Ext.Print('Reloading...') Ext.Vars.ReloadPersistentVars() Ext.Print('Reload complete')\n"
        "end)\n";

    // Test suite command (!test)
    static const char *console_cmd_test =
        "Ext.RegisterConsoleCommand('test', function(cmd, filter)\n"
        "  local TestRunner = {tests = {}, passed = 0, failed = 0}\n"
        "  -- Stats tests\n"
        "  TestRunner.tests['Stats.Get returns table'] = function()\n"
        "    local s = Ext.Stats.Get('WPN_Longsword')\n"
        "    assert(type(s) == 'table', 'Expected table')\n"
        "    assert(s.Name == 'WPN_Longsword', 'Wrong name: ' .. tostring(s.Name))\n"
        "  end\n"
        "  TestRunner.tests['Stats.Get property access'] = function()\n"
        "    local s = Ext.Stats.Get('WPN_Longsword')\n"
        "    assert(s.Damage, 'Damage should be readable')\n"
        "    assert(s.Type == 'Weapon', 'Expected Weapon type')\n"
        "  end\n"
        "  TestRunner.tests['Stats.Sync no crash'] = function()\n"
        "    local s = Ext.Stats.Get('Projectile_FireBolt')\n"
        "    s.Damage = '2d6'\n"
        "    Ext.Stats.Sync('Projectile_FireBolt') -- Should not crash\n"
        "  end\n"
        "  -- JSON tests\n"
        "  TestRunner.tests['JSON roundtrip'] = function()\n"
        "    local orig = {a=1, b='test', c={nested=true}}\n"
        "    local json = Ext.Json.Stringify(orig)\n"
        "    local parsed = Ext.Json.Parse(json)\n"
        "    assert(parsed.a == 1, 'a mismatch')\n"
        "    assert(parsed.b == 'test', 'b mismatch')\n"
        "    assert(parsed.c.nested == true, 'nested mismatch')\n"
        "  end\n"
        "  -- Timer tests\n"
        "  TestRunner.tests['Timer.WaitFor returns handle'] = function()\n"
        "    local handle = Ext.Timer.WaitFor(99999, function() end)\n"
        "    assert(type(handle) == 'number', 'Expected number handle')\n"
        "    Ext.Timer.Cancel(handle)\n"
        "  end\n"
        "  -- Events tests\n"
        "  TestRunner.tests['Events.Subscribe returns ID'] = function()\n"
        "    local id = Ext.Events.Subscribe('Tick', function() end)\n"
        "    assert(type(id) == 'number', 'Expected number ID')\n"
        "    Ext.Events.Unsubscribe('Tick', id)\n"
        "  end\n"
        "  -- Debug tests\n"
        "  TestRunner.tests['Debug.ReadPtr safe'] = function()\n"
        "    local v = Ext.Debug.ReadPtr(0)  -- Invalid addr returns nil\n"
        "    assert(v == nil, 'Expected nil for invalid address')\n"
        "  end\n"
        "  -- Enums tests\n"
        "  TestRunner.tests['Enums accessible'] = function()\n"
        "    assert(Ext.Enums.DamageType, 'DamageType should exist')\n"
        "    assert(Ext.Enums.DamageType.Fire, 'Fire damage should exist')\n"
        "  end\n"
        "  -- Run tests\n"
        "  Ext.Print('\\n=== BG3SE Test Suite ===')\n"
        "  for name, test in pairs(TestRunner.tests) do\n"
        "    if not filter or name:find(filter) then\n"
        "      local ok, err = pcall(test)\n"
        "      if ok then\n"
        "        Ext.Print('  PASS: ' .. name)\n"
        "        TestRunner.passed = TestRunner.passed + 1\n"
        "      else\n"
        "        Ext.Print('  FAIL: ' .. name .. ' - ' .. tostring(err))\n"
        "        TestRunner.failed = TestRunner.failed + 1\n"
        "      end\n"
        "    end\n"
        "  end\n"
        "  Ext.Print(string.format('\\nResults: %d passed, %d failed', TestRunner.passed, TestRunner.failed))\n"
        "  if TestRunner.failed > 0 then Ext.Print('SOME TESTS FAILED') else Ext.Print('ALL TESTS PASSED') end\n"
        "end)\n";

    // Execute each command registration chunk
    const char *console_cmds[] = {
        console_cmd_probe, console_cmd_dumpstat, console_cmd_findstr,
        console_cmd_hexdump, console_cmd_types, console_cmd_pv, console_cmd_test
    };
    for (size_t i = 0; i < sizeof(console_cmds) / sizeof(console_cmds[0]); i++) {
        if (luaL_dostring(L, console_cmds[i]) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            LOG_LUA_WARN(" Failed to register console command: %s", err ? err : "(unknown)");
            lua_pop(L, 1);
        }
    }

    LOG_LUA_INFO("Global helpers registered (_P, _D, _DS, _H, _PTR, _PE, Debug.*)");
    LOG_LUA_INFO("Console commands: !probe !dumpstat !findstr !hexdump !types !pv_* !test");
}
