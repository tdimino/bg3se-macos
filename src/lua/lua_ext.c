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
    log_message("[Lua] %s", msg);

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
    log_message("[Lua] Ext.IO.LoadFile('%s')", path);

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
    log_message("[Lua] Ext.IO.SaveFile('%s')", path);

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

    log_message("[Memory] Searching for %d-byte pattern from 0x%llx, size %lld",
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

    log_message("[Memory] Found %d matches", resultIdx - 1);
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
            log_message("[Memory] Module '%s' base: 0x%llx", name, (unsigned long long)(uintptr_t)header);
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

    log_message("[Lua] Ext.Memory namespace registered");
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

    log_message("[Lua] Ext.Types namespace registered");
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
        log_message("[Lua] Warning: Failed to register dump helpers: %s", err ? err : "(unknown)");
        lua_pop(L, 1);
    }

    // Register built-in console commands
    const char *console_commands =
        "-- !probe <addr> [range] - Probe memory at address\n"
        "Ext.RegisterConsoleCommand('probe', function(cmd, addr, range)\n"
        "  local base = tonumber(addr, 16) or tonumber(addr) or 0\n"
        "  local r = tonumber(range) or 256\n"
        "  if base == 0 then\n"
        "    Ext.Print('Usage: !probe <addr> [range]')\n"
        "    return\n"
        "  end\n"
        "  Ext.Print('Probing ' .. _H(base) .. ' range=' .. r)\n"
        "  local results = Ext.Debug.ProbeStruct(base, 0, r, 8)\n"
        "  for offset, data in pairs(results) do\n"
        "    local line = string.format('+0x%x:', offset)\n"
        "    if data.ptr and data.ptr ~= 0 then line = line .. ' ptr=' .. _H(data.ptr) end\n"
        "    if data.u32 then line = line .. ' u32=' .. data.u32 end\n"
        "    if data.float and data.float ~= 0 then line = line .. string.format(' f=%.3f', data.float) end\n"
        "    Ext.Print(line)\n"
        "  end\n"
        "end)\n"
        "\n"
        "-- !dumpstat <name> - Dump stat object details\n"
        "Ext.RegisterConsoleCommand('dumpstat', function(cmd, name)\n"
        "  if not name then\n"
        "    Ext.Print('Usage: !dumpstat <statName>')\n"
        "    return\n"
        "  end\n"
        "  local stat = Ext.Stats.Get(name)\n"
        "  if not stat then\n"
        "    Ext.Print('Stat not found: ' .. name)\n"
        "    return\n"
        "  end\n"
        "  Ext.Print('=== ' .. name .. ' ===')\n"
        "  Ext.Print('Type: ' .. (stat.Type or 'unknown'))\n"
        "  Ext.Print('Level: ' .. (stat.Level or 0))\n"
        "  if stat.Using then Ext.Print('Using: ' .. stat.Using) end\n"
        "  -- Get raw data\n"
        "  local raw = Ext.Stats.GetObjectRaw(name)\n"
        "  if raw then\n"
        "    Ext.Print('Address: ' .. _H(raw.Address))\n"
        "    Ext.Print('PropertyCount: ' .. raw.PropertyCount)\n"
        "  end\n"
        "end)\n"
        "\n"
        "-- !findstr <pattern> - Search memory for string\n"
        "Ext.RegisterConsoleCommand('findstr', function(cmd, pattern)\n"
        "  if not pattern then\n"
        "    Ext.Print('Usage: !findstr <pattern>')\n"
        "    return\n"
        "  end\n"
        "  Ext.Print('Searching for: ' .. pattern)\n"
        "  -- Convert string to hex pattern\n"
        "  local hex = ''\n"
        "  for i = 1, #pattern do\n"
        "    hex = hex .. string.format('%02x ', string.byte(pattern, i))\n"
        "  end\n"
        "  Ext.Print('Pattern: ' .. hex)\n"
        "  local results = Ext.Memory.Search(hex)\n"
        "  if #results == 0 then\n"
        "    Ext.Print('No matches found')\n"
        "  else\n"
        "    Ext.Print('Found ' .. #results .. ' matches:')\n"
        "    for i, addr in ipairs(results) do\n"
        "      if i <= 20 then\n"
        "        Ext.Print('  ' .. _H(addr))\n"
        "      end\n"
        "    end\n"
        "    if #results > 20 then\n"
        "      Ext.Print('  ... and ' .. (#results - 20) .. ' more')\n"
        "    end\n"
        "  end\n"
        "end)\n"
        "\n"
        "-- !hexdump <addr> [size] - Hex dump memory\n"
        "Ext.RegisterConsoleCommand('hexdump', function(cmd, addr, size)\n"
        "  local base = tonumber(addr, 16) or tonumber(addr) or 0\n"
        "  local sz = tonumber(size) or 64\n"
        "  if base == 0 then\n"
        "    Ext.Print('Usage: !hexdump <addr> [size]')\n"
        "    return\n"
        "  end\n"
        "  local dump = Ext.Debug.HexDump(base, sz)\n"
        "  if dump then\n"
        "    Ext.Print(dump)\n"
        "  else\n"
        "    Ext.Print('Failed to read memory at ' .. _H(base))\n"
        "  end\n"
        "end)\n"
        "\n"
        "-- !types - List registered types\n"
        "Ext.RegisterConsoleCommand('types', function(cmd)\n"
        "  Ext.Print('Registered types:')\n"
        "  for i, t in ipairs(Ext.Types.GetAllTypes()) do\n"
        "    Ext.Print('  ' .. t)\n"
        "  end\n"
        "end)\n";

    if (luaL_dostring(L, console_commands) != LUA_OK) {
        const char *err = lua_tostring(L, -1);
        log_message("[Lua] Warning: Failed to register console commands: %s", err ? err : "(unknown)");
        lua_pop(L, 1);
    }

    log_message("[Lua] Global helpers registered (_P, _D, _DS, _H, _PTR, _PE)");
    log_message("[Lua] Built-in console commands registered (!probe, !dumpstat, !findstr, !hexdump, !types)");
}
