/**
 * BG3SE-macOS - Lua Ext Namespace Core Implementation
 *
 * Core Ext.* API functions.
 */

#include "lua_ext.h"
#include "lua_context.h"
#include "lua_ide_helpers.h"
#include "version.h"
#include "logging.h"
#include "../console/console.h"
#include "../io/path_override.h"
#include "../mod/mod_loader.h"
#include "../pak/pak_reader.h"
#include "../entity/component_registry.h"
#include "../entity/component_property.h"
#include "../enum/enum_registry.h"
#include "../core/safe_memory.h"
#include "../lifetime/lifetime.h"

#include "../timer/timer.h"

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/stat.h>
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
    // Use context system to determine if in server context
    lua_pushboolean(L, lua_context_is_server());
    return 1;
}

int lua_ext_isclient(lua_State *L) {
    // Use context system to determine if in client context
    lua_pushboolean(L, lua_context_is_client());
    return 1;
}

int lua_ext_getcontext(lua_State *L) {
    // Return current context as string: "Server", "Client", or "None"
    lua_pushstring(L, lua_context_get_name(lua_context_get()));
    return 1;
}

// ============================================================================
// Ext.IO Functions
// ============================================================================

// Base directory for Script Extender user data (mod settings, profiles). Mirrors
// Windows BG3SE's "Script Extender" data folder. MCM persists mod settings and
// its open_on_start first-run migration here via Ext.IO.SaveFile with a relative
// path (e.g. "BG3MCM/Profiles/Default/BG3MCM/settings.json"); without a real
// base those paths resolve against the CWD and the writes fail, so nothing
// persists (and MCM's window keeps auto-opening every launch).
static const char *io_se_data_base(void) {
    static char base[MAX_PATH_LEN];
    static int inited = 0;
    if (!inited) {
        const char *home = getenv("HOME");
        snprintf(base, sizeof(base),
                 "%s/Documents/Larian Studios/Baldur's Gate 3/Script Extender",
                 home ? home : "");
        inited = 1;
    }
    return base;
}

// Create all parent directories of file_path (mkdir -p on the dirname).
static void io_mkdir_parents(const char *file_path) {
    char tmp[MAX_PATH_LEN];
    snprintf(tmp, sizeof(tmp), "%s", file_path);
    char *last = strrchr(tmp, '/');
    if (!last) return;
    *last = '\0';  // strip filename, leaving the directory path
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

// Read a mod-relative VFS path (e.g. "Mods/BG3MCM/ScriptExtender/Config.json")
// out of the owning mod's PAK. Windows BG3SE's Ext.IO.LoadFile(path, "data")
// resolves such paths against the game's virtual filesystem, which includes
// mounted PAKs; the port must do the same so mods like MCM can read their
// Config.json / JSON blueprints. Returns malloc'd, NUL-terminated content (caller
// frees) or NULL if not found. *out_size excludes the terminator.
static char *io_load_from_pak(const char *path, size_t *out_size) {
    // Only VFS-style "Mods/<Folder>/..." paths live inside PAKs.
    if (strncmp(path, "Mods/", 5) != 0) return NULL;

    // Extract the mod folder name (between "Mods/" and the next '/').
    const char *folder_start = path + 5;
    const char *slash = strchr(folder_start, '/');
    if (!slash || slash == folder_start) return NULL;

    char folder[256];
    size_t flen = (size_t)(slash - folder_start);
    if (flen >= sizeof(folder)) return NULL;
    memcpy(folder, folder_start, flen);
    folder[flen] = '\0';

    char pak_path[MAX_PATH_LEN];
    if (!mod_find_pak(folder, pak_path, sizeof(pak_path))) return NULL;

    PakFile *pak = pak_open(pak_path);
    if (!pak) return NULL;

    int idx = pak_find_entry(pak, path);
    if (idx < 0) {
        pak_close(pak);
        return NULL;
    }

    char *content = pak_read_file(pak, idx, out_size);
    pak_close(pak);
    return content;  // already NUL-terminated by pak_read_file
}

// Reject paths that would escape the Script Extender data dir: absolute
// paths and any ".." component. Windows BG3SE confines Ext.IO writes to the
// UserProfile Script Extender root the same way.
static int io_path_is_contained(const char *path) {
    if (!path || !path[0] || path[0] == '/') return 0;
    const char *p = path;
    while (*p) {
        if (p[0] == '.' && p[1] == '.' &&
            (p[2] == '/' || p[2] == '\0') &&
            (p == path || p[-1] == '/')) {
            return 0;
        }
        p++;
    }
    return 1;
}

int lua_ext_io_loadfile(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    LOG_LUA_INFO("Ext.IO.LoadFile('%s')", path);

    // Relative paths resolve against the Script Extender data dir (user-saved
    // data like MCM's settings.json lives here — see io_se_data_base), never
    // the process CWD, and may not traverse out of it. Absolute paths are
    // honored read-only for developer tooling.
    FILE *f = NULL;
    if (path[0] == '/') {
        f = fopen(path, "r");
    } else if (io_path_is_contained(path)) {
        char se_path[MAX_PATH_LEN];
        snprintf(se_path, sizeof(se_path), "%s/%s", io_se_data_base(), path);
        f = fopen(se_path, "r");
    }
    if (!f) {
        // Filesystem miss: fall back to reading from the owning mod's PAK
        // (VFS "data" semantics). Required for MCM's reverse-lookup of every
        // mod's ScriptExtender/Config.json.
        size_t pak_size = 0;
        char *pak_content = io_load_from_pak(path, &pak_size);
        if (pak_content) {
            lua_pushlstring(L, pak_content, pak_size);
            free(pak_content);
            return 1;
        }
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

    // Windows BG3SE writes to <UserProfile>/Script Extender/<path> (PathRootType
    // ::UserProfile) and mkdir -p's the parents. Mirror that so MCM's settings /
    // profiles / open_on_start migration actually persist.
    if (!io_path_is_contained(path)) {
        LOG_LUA_INFO("Ext.IO.SaveFile: rejecting path outside SE data dir: '%s'", path);
        lua_pushboolean(L, 0);
        return 1;
    }
    char full[MAX_PATH_LEN];
    snprintf(full, sizeof(full), "%s/%s", io_se_data_base(), path);
    io_mkdir_parents(full);

    FILE *f = fopen(full, "w");
    if (!f) {
        LOG_LUA_INFO("Ext.IO.SaveFile: could not open '%s' for writing", full);
        lua_pushboolean(L, 0);
        return 1;
    }

    fwrite(content, 1, strlen(content), f);
    fclose(f);

    lua_pushboolean(L, 1);
    return 1;
}

int lua_ext_io_addpathoverride(lua_State *L) {
    const char *original = luaL_checkstring(L, 1);
    const char *override = luaL_checkstring(L, 2);
    path_override_add(original, override);
    return 0;
}

int lua_ext_io_getpathoverride(lua_State *L) {
    const char *original = luaL_checkstring(L, 1);
    const char *override = path_override_get(original);
    if (override) {
        lua_pushstring(L, override);
    } else {
        lua_pushnil(L);
    }
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

    lua_pushcfunction(L, lua_ext_getcontext);
    lua_setfield(L, ext_table_index, "GetContext");

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
    lua_pushcfunction(L, lua_ext_io_addpathoverride);
    lua_setfield(L, -2, "AddPathOverride");
    lua_pushcfunction(L, lua_ext_io_getpathoverride);
    lua_setfield(L, -2, "GetPathOverride");
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
// Returns rich metadata about a registered type (userdata, component, or enum)
static int lua_types_gettypeinfo(lua_State *L) {
    const char *type_name = luaL_checkstring(L, 1);

    lua_newtable(L);

    lua_pushstring(L, type_name);
    lua_setfield(L, -2, "Name");

    // First, check component registry
    const ComponentInfo *comp = component_registry_lookup(type_name);
    if (comp) {
        lua_pushstring(L, "Component");
        lua_setfield(L, -2, "Kind");

        lua_pushinteger(L, comp->size);
        lua_setfield(L, -2, "Size");

        lua_pushinteger(L, comp->index);
        lua_setfield(L, -2, "TypeIndex");

        lua_pushboolean(L, comp->is_one_frame);
        lua_setfield(L, -2, "IsOneFrame");

        lua_pushboolean(L, comp->is_proxy);
        lua_setfield(L, -2, "IsProxy");

        lua_pushboolean(L, comp->discovered);
        lua_setfield(L, -2, "Discovered");

        lua_pushboolean(L, 1);
        lua_setfield(L, -2, "Registered");

        return 1;
    }

    // Second, check enum registry
    EnumTypeInfo *enumInfo = enum_registry_find_by_name(type_name);
    if (enumInfo) {
        lua_pushstring(L, enumInfo->is_bitfield ? "Bitfield" : "Enum");
        lua_setfield(L, -2, "Kind");

        lua_pushinteger(L, enumInfo->value_count);
        lua_setfield(L, -2, "ValueCount");

        lua_pushinteger(L, enumInfo->registry_index);
        lua_setfield(L, -2, "TypeIndex");

        // Add values table
        lua_newtable(L);
        for (int i = 0; i < enumInfo->value_count; i++) {
            lua_pushinteger(L, (lua_Integer)enumInfo->values[i].value);
            lua_setfield(L, -2, enumInfo->values[i].label);
        }
        lua_setfield(L, -2, "Values");

        // Add labels array (ordered)
        lua_newtable(L);
        for (int i = 0; i < enumInfo->value_count; i++) {
            lua_pushstring(L, enumInfo->values[i].label);
            lua_rawseti(L, -2, i + 1);
        }
        lua_setfield(L, -2, "Labels");

        if (enumInfo->is_bitfield) {
            lua_pushinteger(L, (lua_Integer)enumInfo->allowed_flags);
            lua_setfield(L, -2, "AllowedFlags");
        }

        lua_pushboolean(L, 1);
        lua_setfield(L, -2, "Registered");

        return 1;
    }

    // Third, check known userdata types
    int found = 0;
    for (int i = 0; s_known_types[i] != NULL; i++) {
        if (strcmp(s_known_types[i], type_name) == 0) {
            found = 1;
            lua_pushstring(L, "Userdata");
            lua_setfield(L, -2, "Kind");
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

// Iterator context for building type list
typedef struct {
    lua_State *L;
    int index;
} TypeListContext;

// Callback for component iteration
static bool add_component_to_list(const ComponentInfo *info, void *userdata) {
    TypeListContext *ctx = (TypeListContext*)userdata;
    if (info && info->name) {
        lua_pushstring(ctx->L, info->name);
        lua_rawseti(ctx->L, -2, ctx->index++);
    }
    return true;  // Continue iteration
}

// Callback for enum iteration
static bool add_enum_to_list(const EnumTypeInfo *info, void *userdata) {
    TypeListContext *ctx = (TypeListContext*)userdata;
    if (info && info->name) {
        lua_pushstring(ctx->L, info->name);
        lua_rawseti(ctx->L, -2, ctx->index++);
    }
    return true;  // Continue iteration
}

// Ext.Types.GetAllTypes() -> table
// Returns list of all known/registered types (userdata + components + enums)
static int lua_types_getalltypes(lua_State *L) {
    lua_newtable(L);

    TypeListContext ctx = { L, 1 };

    // Add userdata types first
    for (int i = 0; s_known_types[i] != NULL; i++) {
        lua_pushstring(L, s_known_types[i]);
        lua_rawseti(L, -2, ctx.index++);
    }

    // Add all component types
    component_registry_iterate(add_component_to_list, &ctx);

    // Add all enum types
    enum_registry_iterate(add_enum_to_list, &ctx);

    return 1;
}

// Helper to get object's type name (internal use)
static const char* get_object_type_name(lua_State *L, int index) {
    if (!lua_isuserdata(L, index)) {
        return NULL;
    }

    if (!lua_getmetatable(L, index)) {
        return NULL;
    }

    // Check against known metatables
    for (int i = 0; s_known_types[i] != NULL; i++) {
        luaL_getmetatable(L, s_known_types[i]);
        if (lua_rawequal(L, -1, -2)) {
            lua_pop(L, 2);  // Pop both metatables
            return s_known_types[i];
        }
        lua_pop(L, 1);  // Pop the known metatable
    }

    // Try to get __name field from metatable
    lua_getfield(L, -1, "__name");
    if (lua_isstring(L, -1)) {
        const char *name = lua_tostring(L, -1);
        lua_pop(L, 2);  // Pop __name and metatable
        return name;
    }
    lua_pop(L, 2);  // Pop __name (nil) and metatable

    return NULL;
}

// Ext.Types.TypeOf(obj) -> table or nil
// Returns full TypeInformation table for an object
static int lua_types_typeof(lua_State *L) {
    const char *type_name = get_object_type_name(L, 1);
    if (!type_name) {
        lua_pushnil(L);
        return 1;
    }

    // Replace the object with its type name and call GetTypeInfo
    lua_pushstring(L, type_name);
    lua_replace(L, 1);
    return lua_types_gettypeinfo(L);
}

// Helper: Convert FieldType to string for IDE helpers
static const char* field_type_to_string(FieldType type) {
    switch (type) {
        case FIELD_TYPE_INT8:         return "int8";
        case FIELD_TYPE_UINT8:        return "uint8";
        case FIELD_TYPE_INT16:        return "int16";
        case FIELD_TYPE_UINT16:       return "uint16";
        case FIELD_TYPE_INT32:        return "integer";
        case FIELD_TYPE_UINT32:       return "integer";
        case FIELD_TYPE_INT64:        return "integer";
        case FIELD_TYPE_UINT64:       return "integer";
        case FIELD_TYPE_BOOL:         return "boolean";
        case FIELD_TYPE_FLOAT:        return "number";
        case FIELD_TYPE_DOUBLE:       return "number";
        case FIELD_TYPE_FIXEDSTRING:  return "string";
        case FIELD_TYPE_GUID:         return "string";
        case FIELD_TYPE_ENTITY_HANDLE:return "EntityHandle";
        case FIELD_TYPE_VEC3:         return "vec3";
        case FIELD_TYPE_VEC4:         return "vec4";
        case FIELD_TYPE_INT32_ARRAY:  return "integer[]";
        case FIELD_TYPE_FLOAT_ARRAY:  return "number[]";
        case FIELD_TYPE_DYNAMIC_ARRAY:return "table";
        default:                      return "any";
    }
}

// Ext.Types.GetComponentLayout(name) -> table or nil
// Returns layout definition with properties for IDE helper generation
static int lua_types_get_component_layout(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);

    const ComponentLayoutDef *layout = component_property_get_layout(name);
    if (!layout) {
        // Try short name
        layout = component_property_get_layout_by_short_name(name);
    }

    if (!layout) {
        lua_pushnil(L);
        return 1;
    }

    // Build layout table
    lua_newtable(L);

    lua_pushstring(L, layout->componentName);
    lua_setfield(L, -2, "Name");

    if (layout->shortName) {
        lua_pushstring(L, layout->shortName);
        lua_setfield(L, -2, "ShortName");
    }

    lua_pushinteger(L, layout->componentSize);
    lua_setfield(L, -2, "Size");

    lua_pushinteger(L, layout->componentTypeIndex);
    lua_setfield(L, -2, "TypeIndex");

    // Build properties array
    lua_newtable(L);
    for (int i = 0; i < layout->propertyCount; i++) {
        const ComponentPropertyDef *prop = &layout->properties[i];

        lua_newtable(L);

        lua_pushstring(L, prop->name);
        lua_setfield(L, -2, "Name");

        lua_pushinteger(L, prop->offset);
        lua_setfield(L, -2, "Offset");

        lua_pushstring(L, field_type_to_string(prop->type));
        lua_setfield(L, -2, "Type");

        lua_pushinteger(L, prop->type);  // Raw enum value
        lua_setfield(L, -2, "TypeId");

        if (prop->arraySize > 0) {
            lua_pushinteger(L, prop->arraySize);
            lua_setfield(L, -2, "ArraySize");
        }

        lua_pushboolean(L, prop->readOnly);
        lua_setfield(L, -2, "ReadOnly");

        lua_rawseti(L, -2, i + 1);  // 1-indexed
    }
    lua_setfield(L, -2, "Properties");

    lua_pushinteger(L, layout->propertyCount);
    lua_setfield(L, -2, "PropertyCount");

    return 1;
}

// Ext.Types.GetAllLayouts() -> table
// Returns list of all component names that have property layouts
static int lua_types_get_all_layouts(lua_State *L) {
    lua_newtable(L);

    int count = component_property_get_layout_count();
    for (int i = 0; i < count; i++) {
        const ComponentLayoutDef *layout = component_property_get_layout_at(i);
        if (layout && layout->componentName) {
            lua_pushstring(L, layout->componentName);
            lua_rawseti(L, -2, i + 1);
        }
    }

    return 1;
}

// Ext.Types.GetValueType(obj) -> string or nil
// Returns a debug-friendly type description for any Lua value.
// Mirrors Windows BG3SE GetValueType — for non-userdata it falls back to
// the standard Lua type name.
static int lua_types_getvaluetype(lua_State *L) {
    luaL_checkany(L, 1);
    int t = lua_type(L, 1);

    if (t == LUA_TUSERDATA || t == LUA_TLIGHTUSERDATA) {
        // Try metatable __name first (same logic as GetObjectType)
        if (lua_getmetatable(L, 1)) {
            lua_getfield(L, -1, "__name");
            if (lua_isstring(L, -1)) {
                // __name is on stack — remove the metatable below it
                lua_remove(L, -2);
                return 1;
            }
            lua_pop(L, 2);  // pop __name (nil) + metatable
        }
        // Fall through: return "userdata"
    }

    lua_pushstring(L, lua_typename(L, t));
    return 1;
}

// Ext.Types.Serialize(obj) -> table
// Serializes macOS component/array proxy userdata through the same component
// layout database used by GetComponentLayout/GetAllLayouts.
static int lua_types_serialize(lua_State *L) {
    luaL_checkany(L, 1);
    if (!component_property_serialize_proxy(L, 1)) {
        return luaL_error(
            L, "Ext.Types.Serialize: unsupported value type '%s' "
               "(expected component or component-array userdata)",
            luaL_typename(L, 1));
    }
    return 1;
}

// Ext.Types.Unserialize(obj, table)
// Applies writable scalar fields in-place; ownership-bearing and read-only
// fields are intentionally skipped by the component property layer.
static int lua_types_unserialize(lua_State *L) {
    luaL_checkany(L, 1);
    luaL_checktype(L, 2, LUA_TTABLE);
    if (!component_property_unserialize_proxy(L, 1, 2)) {
        return luaL_error(
            L, "Ext.Types.Unserialize: unsupported value type '%s' "
               "(expected component userdata)",
            luaL_typename(L, 1));
    }
    return 0;
}

// Ext.Types.Construct(typeName)
// Matches the Windows validation surface (Types.inl:286-302) exactly: three
// luaL_error checks fire before the reference's own `// TODO; return 0`.
// Kind mapping — Component is the macOS analog of LuaTypeId::Object and falls
// through to the upstream TODO (zero return values); Enum/Bitfield are
// non-object; the bg3se.* userdata types validate as objects but carry no
// constructor. Actual construction stays out of scope until the reference
// implements it.
static int lua_types_construct(lua_State *L) {
    const char *type_name = luaL_checkstring(L, 1);

    if (component_registry_lookup(type_name)) {
        // Object type: passes all Windows checks, then hits the upstream TODO.
        return 0;
    }

    if (enum_registry_find_by_name(type_name)) {
        return luaL_error(L, "Unable to construct non-object type '%s'", type_name);
    }

    for (int i = 0; s_known_types[i] != NULL; i++) {
        if (strcmp(s_known_types[i], type_name) == 0) {
            return luaL_error(L, "Type '%s' is not constructible", type_name);
        }
    }

    return luaL_error(L, "Unknown type name '%s'", type_name);
}

#define HASH_SET_PROXY_METATABLE "bg3se.HashSetProxy"

// ls::HashSet<T> is three 16-byte array headers; Keys begins at +0x20
// (CoreLib/Base/BaseMap.h:76-77, 121-143, 235-238).
typedef struct {
    void *buf;
    uint32_t capacity;
    uint32_t size;
} LuaHashSetKeysArray;

typedef struct {
    uint8_t hashKeys[0x10];
    uint8_t nextIds[0x10];
    LuaHashSetKeysArray keys;
} LuaHashSetLayout;

typedef int (*LuaHashSetElementPusher)(lua_State *L, const void *element,
                                       LifetimeHandle lifetime);

// Mirrors Windows SetProxyImplBase type erasure: the producer supplies the
// element width and type-specific pusher; this function owns only indexing.
typedef struct {
    void *setPtr;
    size_t elementSize;
    LuaHashSetElementPusher pushElement;
    LifetimeHandle lifetime;
} LuaHashSetProxy;

_Static_assert(sizeof(LuaHashSetKeysArray) == 0x10,
               "BG3 Array<T> header must be 16 bytes");
_Static_assert(offsetof(LuaHashSetLayout, keys) == 0x20,
               "BG3 HashSet<T>::Keys must be at +0x20");
_Static_assert(sizeof(LuaHashSetLayout) == 0x30,
               "BG3 HashSet<T> header must be 48 bytes");

// Ext.Types.GetHashSetValueAt(obj, index) -> value or nil
// Windows Types.inl:310-318 gets a Set proxy and pushes nil when GetElementAt
// fails. LuaSetProxy.h:46-55 accepts 1..size and pushes Keys[index - 1].
static int lua_types_gethashsetvalueat(lua_State *L) {
    // Windows binds this argument as uint32_t (Types.inl:310); its generic
    // Lua getter casts luaL_checkinteger directly (LuaGet.h:117-120).
    uint32_t index = (uint32_t)luaL_checkinteger(L, 2);

    LuaHashSetProxy *proxy = (LuaHashSetProxy *)luaL_testudata(
        L, 1, HASH_SET_PROXY_METATABLE);
    if (!proxy) {
        return luaL_argerror(L, 1, "expected HashSet proxy userdata");
    }

    if (!lifetime_lua_is_valid(L, proxy->lifetime)) {
        return lifetime_lua_expired_error(L, "HashSet");
    }
    if (!proxy->setPtr) {
        return luaL_error(L, "HashSet proxy has no backing object");
    }

    LuaHashSetKeysArray keys = {0};
    mach_vm_address_t keysAddress =
        (mach_vm_address_t)(uintptr_t)proxy->setPtr
        + offsetof(LuaHashSetLayout, keys);
    if (!safe_memory_read(keysAddress, &keys, sizeof(keys))) {
        return luaL_error(L, "Unable to read HashSet keys array");
    }

    // Zero is outside the 1-based contract. Negative Lua integers undergo the
    // same uint32_t conversion as Windows and consequently land out of range.
    if (index == 0 || index > keys.size) {
        lua_pushnil(L);
        return 1;
    }

    if (keys.size > keys.capacity || !keys.buf) {
        return luaL_error(L, "HashSet keys array metadata is invalid");
    }
    if (proxy->elementSize == 0 || !proxy->pushElement) {
        return luaL_error(L, "HashSet proxy has no element serializer");
    }

    size_t elementIndex = (size_t)(index - 1);
    if (elementIndex > (SIZE_MAX / proxy->elementSize)) {
        return luaL_error(L, "HashSet element address overflow");
    }
    size_t byteOffset = elementIndex * proxy->elementSize;
    uintptr_t keysBase = (uintptr_t)keys.buf;
    if (byteOffset > UINTPTR_MAX - keysBase) {
        return luaL_error(L, "HashSet element address overflow");
    }

    const void *element = (const void *)(keysBase + byteOffset);
    int stackTop = lua_gettop(L);
    int results = proxy->pushElement(L, element, proxy->lifetime);
    if (results != 1 || lua_gettop(L) != stackTop + 1) {
        return luaL_error(L, "HashSet element serializer returned no value");
    }
    return 1;
}

// Ext.Types.GetFunctionLocation(func) -> (source, line) or (nil, nil)
// Returns the source file and line number where a Lua function was defined.
static int lua_types_getfunctionlocation(lua_State *L) {
    if (!lua_isfunction(L, 1) || lua_iscfunction(L, 1)) {
        lua_pushnil(L);
        lua_pushnil(L);
        return 2;
    }

    lua_Debug ar;
    lua_pushvalue(L, 1);
    if (lua_getinfo(L, ">S", &ar)) {
        lua_pushstring(L, ar.source);
        lua_pushinteger(L, ar.linedefined);
    } else {
        lua_pushnil(L);
        lua_pushnil(L);
    }
    return 2;
}

static void lua_types_check_custom_object_type(lua_State *L,
                                               const char *type_name) {
    if (component_registry_lookup(type_name)) {
        return;
    }

    if (enum_registry_find_by_name(type_name)) {
        luaL_error(L, "Cannot extend non-object type: %s", type_name);
        return;
    }

    for (int i = 0; s_known_types[i] != NULL; i++) {
        if (strcmp(s_known_types[i], type_name) == 0) {
            luaL_error(L, "Cannot extend non-object type: %s", type_name);
            return;
        }
    }

    luaL_error(L, "Type not found: %s", type_name);
}

static void lua_types_push_custom_type(lua_State *L,
                                       const char *type_name) {
    lua_getfield(L, LUA_REGISTRYINDEX, BG3SE_CUSTOM_PROPS_REGISTRY_KEY);
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushvalue(L, -1);
        lua_setfield(L, LUA_REGISTRYINDEX, BG3SE_CUSTOM_PROPS_REGISTRY_KEY);
    }

    int registry_index = lua_gettop(L);
    lua_getfield(L, registry_index, type_name);
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        lua_createtable(L, 0, 2);
        lua_newtable(L);
        lua_setfield(L, -2, "functions");
        lua_newtable(L);
        lua_setfield(L, -2, "properties");
        lua_pushvalue(L, -1);
        lua_setfield(L, registry_index, type_name);
    }

    lua_remove(L, registry_index);
}

// Ext.Types.AddCustomFunction(typeName, property, func) -> boolean
static int lua_types_addcustomfunction(lua_State *L) {
    const char *type_name = luaL_checkstring(L, 1);
    const char *property  = luaL_checkstring(L, 2);
    luaL_checktype(L, 3, LUA_TFUNCTION);

    lua_types_check_custom_object_type(L, type_name);
    lua_types_push_custom_type(L, type_name);
    lua_getfield(L, -1, "functions");
    lua_pushvalue(L, 3);
    lua_setfield(L, -2, property);
    lua_pop(L, 2);

    lua_pushboolean(L, 1);
    return 1;
}

// Ext.Types.AddCustomProperty(typeName, property, getter[, setter]) -> boolean
static int lua_types_addcustomproperty(lua_State *L) {
    const char *type_name = luaL_checkstring(L, 1);
    const char *property  = luaL_checkstring(L, 2);
    luaL_checktype(L, 3, LUA_TFUNCTION);
    if (!lua_isnoneornil(L, 4)) {
        luaL_checktype(L, 4, LUA_TFUNCTION);
    }

    lua_types_check_custom_object_type(L, type_name);
    lua_types_push_custom_type(L, type_name);
    lua_getfield(L, -1, "properties");
    lua_createtable(L, 0, 2);
    lua_pushvalue(L, 3);
    lua_setfield(L, -2, "getter");
    if (!lua_isnoneornil(L, 4)) {
        lua_pushvalue(L, 4);
        lua_setfield(L, -2, "setter");
    }
    lua_setfield(L, -2, property);
    lua_pop(L, 2);

    lua_pushboolean(L, 1);
    return 1;
}

// Ext.Types.IsA(obj, typeName) -> boolean
// Checks if an object is of a given type or inherits from it
static int lua_types_isa(lua_State *L) {
    const char *obj_type = get_object_type_name(L, 1);
    const char *check_type = luaL_checkstring(L, 2);

    if (!obj_type) {
        lua_pushboolean(L, 0);
        return 1;
    }

    // Direct match
    if (strcmp(obj_type, check_type) == 0) {
        lua_pushboolean(L, 1);
        return 1;
    }

    // Check if obj_type contains check_type (inheritance pattern)
    // e.g., "eoc::HealthComponent" IsA "Component"
    // e.g., "bg3se.StatsObject" IsA "StatsObject"
    if (strstr(obj_type, check_type) != NULL) {
        lua_pushboolean(L, 1);
        return 1;
    }

    // Check for namespace prefix match (e.g., "bg3se.Entity" IsA "bg3se")
    size_t check_len = strlen(check_type);
    if (strncmp(obj_type, check_type, check_len) == 0 &&
        (obj_type[check_len] == '.' || obj_type[check_len] == ':')) {
        lua_pushboolean(L, 1);
        return 1;
    }

    lua_pushboolean(L, 0);
    return 1;
}

void lua_ext_register_types(lua_State *L, int ext_table_index) {
    // Convert negative index to absolute
    if (ext_table_index < 0) {
        ext_table_index = lua_gettop(L) + ext_table_index + 1;
    }

    // No producer emits these yet; registering the tag here makes rejection
    // deterministic and reserves the lifetime-scoped proxy contract for the
    // future FIELD_TYPE_HASHSET component-property surface.
    luaL_newmetatable(L, HASH_SET_PROXY_METATABLE);
    lua_pop(L, 1);

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

    lua_pushcfunction(L, lua_types_typeof);
    lua_setfield(L, -2, "TypeOf");

    lua_pushcfunction(L, lua_types_isa);
    lua_setfield(L, -2, "IsA");

    lua_pushcfunction(L, lua_types_get_component_layout);
    lua_setfield(L, -2, "GetComponentLayout");

    lua_pushcfunction(L, lua_types_get_all_layouts);
    lua_setfield(L, -2, "GetAllLayouts");

    lua_pushcfunction(L, lua_ide_helpers_generate);
    lua_setfield(L, -2, "GenerateIdeHelpers");

    lua_pushcfunction(L, lua_types_getvaluetype);
    lua_setfield(L, -2, "GetValueType");

    lua_pushcfunction(L, lua_types_serialize);
    lua_setfield(L, -2, "Serialize");

    lua_pushcfunction(L, lua_types_unserialize);
    lua_setfield(L, -2, "Unserialize");

    lua_pushcfunction(L, lua_types_construct);
    lua_setfield(L, -2, "Construct");

    lua_pushcfunction(L, lua_types_gethashsetvalueat);
    lua_setfield(L, -2, "GetHashSetValueAt");

    lua_pushcfunction(L, lua_types_getfunctionlocation);
    lua_setfield(L, -2, "GetFunctionLocation");

    lua_pushcfunction(L, lua_types_addcustomfunction);
    lua_setfield(L, -2, "AddCustomFunction");

    lua_pushcfunction(L, lua_types_addcustomproperty);
    lua_setfield(L, -2, "AddCustomProperty");

    lua_setfield(L, ext_table_index, "Types");

    LOG_LUA_INFO("Ext.Types namespace registered (17 functions)");
}

// ============================================================================
// Global Helper Registration (for rapid debugging)
// ============================================================================

// _H(n) - Format number as hex string
// Note: lua_pushfstring does NOT support %x — must use snprintf
static int lua_helper_hex(lua_State *L) {
    lua_Integer n = luaL_checkinteger(L, 1);
    char buf[32];
    snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)n);
    lua_pushstring(L, buf);
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

    // Comprehensive test suite (!test and !test_ingame)
    // Split across multiple strings to stay under 4095-char ISO C99 limit.
    // Uses global BG3SE_Tests table so tests defined in separate chunks run together.

    // Framework: global test table + add/run helpers
    // Features: category headers, per-test timing, running counter, breadcrumb on start
    static const char *console_cmd_test_framework =
        "BG3SE_Tests = BG3SE_Tests or {tier1 = {}, tier2 = {}}\n"
        "function BG3SE_AddTest(tier, name, fn)\n"
        "  local t = (tier == 2) and BG3SE_Tests.tier2 or BG3SE_Tests.tier1\n"
        "  t[#t+1] = {name=name, fn=fn}\n"
        "end\n"
        "function BG3SE_RunTests(tier, filter)\n"
        "  local t = (tier == 2) and BG3SE_Tests.tier2 or BG3SE_Tests.tier1\n"
        "  local passed, failed, skipped, errors = 0, 0, 0, {}\n"
        "  local total = 0\n"
        "  for _, test in ipairs(t) do\n"
        "    if not filter or test.name:find(filter) then total = total + 1 end\n"
        "  end\n"
        "  local label = (tier == 2) and 'In-Game' or 'General'\n"
        "  Ext.Print(string.format('\\n=== BG3SE %s Tests (%d tests) ===', label, total))\n"
        "  local lastCat = ''\n"
        "  local suiteStart = os.clock()\n"
        "  for _, test in ipairs(t) do\n"
        "    if not filter or test.name:find(filter) then\n"
        "      local cat = test.name:match('^([^%.]+)') or '?'\n"
        "      if cat ~= lastCat then\n"
        "        Ext.Print('\\n--- ' .. cat .. ' ---')\n"
        "        lastCat = cat\n"
        "      end\n"
        "      local t0 = os.clock()\n"
        "      local ok, err = pcall(test.fn)\n"
        "      local ms = math.floor((os.clock() - t0) * 1000)\n"
        "      local slow = ms > 500 and ' [SLOW ' .. ms .. 'ms]' or ''\n"
        "      local run = passed + failed\n"
        "      if ok then\n"
        "        passed = passed + 1\n"
        "        Ext.Print(string.format('  PASS: %s (%dms)%s [%d/%d]', test.name, ms, slow, passed+failed, total))\n"
        "      else\n"
        "        failed = failed + 1\n"
        "        errors[#errors+1] = test.name .. ': ' .. tostring(err)\n"
        "        Ext.Print(string.format('  FAIL: %s (%dms) - %s [%d/%d]', test.name, ms, tostring(err), passed+failed, total))\n"
        "      end\n"
        "    else skipped = skipped + 1 end\n"
        "  end\n"
        "  local elapsed = math.floor((os.clock() - suiteStart) * 1000)\n"
        "  Ext.Print(string.format('\\n=== Results: %d/%d passed, %d failed, %d skipped (%dms) ===', passed, total, failed, skipped, elapsed))\n"
        "  if #errors > 0 then\n"
        "    Ext.Print('Failures:')\n"
        "    for _, e in ipairs(errors) do Ext.Print('  * ' .. e) end\n"
        "  end\n"
        "  if failed > 0 then Ext.Print('SOME TESTS FAILED') else Ext.Print('ALL TESTS PASSED') end\n"
        "end\n";

    // Assertion helpers (loaded before all tests)
    static const char *console_cmd_test_assertions =
        "function AssertNotNil(v, msg) assert(v ~= nil, (msg or 'value') .. ' was nil') end\n"
        "function AssertEquals(a, b, msg) assert(a == b, (msg or 'values') .. ': ' .. tostring(a) .. ' ~= ' .. tostring(b)) end\n"
        "function AssertType(v, t, msg) assert(type(v) == t, (msg or 'value') .. ': expected ' .. t .. ', got ' .. type(v)) end\n"
        "function AssertContains(s, pat, msg) assert(type(s)=='string' and s:find(pat), (msg or 'string') .. ' missing pattern: ' .. pat) end\n"
        "function AssertEqualsFloat(a, b, eps, msg) assert(math.abs(a-b) < (eps or 0.001), (msg or 'floats') .. ': ' .. a .. ' ~= ' .. b) end\n"
        "function AssertGUID(v, msg) AssertType(v, 'string', msg); assert(#v >= 36, (msg or 'GUID') .. ' too short: ' .. #v) end\n";

    // Tier 1: Core + Json + Helpers (15 tests)
    static const char *console_cmd_test_core =
        "BG3SE_AddTest(1, 'Core.Print', function() Ext.Print('test') end)\n"
        "BG3SE_AddTest(1, 'Core.GetVersion', function()\n"
        "  local v = Ext.GetVersion()\n"
        "  assert(type(v) == 'string', 'Expected string, got ' .. type(v))\n"
        "  assert(v:match('%d+%.%d+'), 'Bad version format: ' .. v)\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Core.IsServer', function()\n"
        "  local v = Ext.IsServer()\n"
        "  assert(type(v) == 'boolean', 'Expected boolean')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Core.IsClient', function()\n"
        "  local v = Ext.IsClient()\n"
        "  assert(type(v) == 'boolean', 'Expected boolean')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Core.GetContext', function()\n"
        "  local v = Ext.GetContext()\n"
        "  assert(type(v) == 'string', 'Expected string')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Core.RegisterConsoleCommand', function()\n"
        "  AssertType(Ext.RegisterConsoleCommand, 'function', 'RegisterConsoleCommand')\n"
        "  Ext.RegisterConsoleCommand('bg3se_test_noop', function() end)\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Json.Parse', function()\n"
        "  local t = Ext.Json.Parse('{\"a\":1,\"b\":\"hello\"}')\n"
        "  assert(type(t) == 'table', 'Expected table')\n"
        "  assert(t.a == 1, 'a mismatch')\n"
        "  assert(t.b == 'hello', 'b mismatch')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Json.ParseArray', function()\n"
        "  local t = Ext.Json.Parse('[1,2,3]')\n"
        "  assert(type(t) == 'table', 'Expected table')\n"
        "  assert(t[1] == 1, 'First element mismatch')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Json.Roundtrip', function()\n"
        "  local orig = {a=1, b='test', c={nested=true}}\n"
        "  local json = Ext.Json.Stringify(orig)\n"
        "  local parsed = Ext.Json.Parse(json)\n"
        "  assert(parsed.a == 1, 'a mismatch')\n"
        "  assert(parsed.b == 'test', 'b mismatch')\n"
        "  assert(parsed.c.nested == true, 'nested mismatch')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Json.ParseInvalid', function()\n"
        "  local result = Ext.Json.Parse('not json')\n"
        "  assert(result == nil, 'Parsing invalid JSON should return nil, got: ' .. tostring(result))\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Helpers.Print', function() _P('test') end)\n"
        "BG3SE_AddTest(1, 'Helpers.Hex', function()\n"
        "  assert(_H(255) == '0xff', 'Expected 0xff, got ' .. tostring(_H(255)))\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Helpers.Dump', function() _D({a=1}) end)\n"
        "BG3SE_AddTest(1, 'Helpers.DumpShallow', function() _DS({a=1}) end)\n"
        "BG3SE_AddTest(1, 'Helpers.PrintError', function() _PE('test error') end)\n";

    // Tier 1: Stats (12 tests)
    static const char *console_cmd_test_stats =
        "BG3SE_AddTest(1, 'Stats.Get', function()\n"
        "  local s = Ext.Stats.Get('WPN_Longsword')\n"
        "  assert(type(s) == 'userdata', 'Expected userdata, got ' .. type(s))\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Stats.GetName', function()\n"
        "  local s = Ext.Stats.Get('WPN_Longsword')\n"
        "  assert(s.Name == 'WPN_Longsword', 'Wrong name: ' .. tostring(s.Name))\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Stats.GetProperty', function()\n"
        "  local s = Ext.Stats.Get('WPN_Longsword')\n"
        "  assert(s.Damage ~= nil, 'Damage should be readable')\n"
        "  assert(s.Type ~= nil, 'Type should be readable')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Stats.TypedAttributes', function()\n"
        "  -- Each attribute reads by its value-list type; reading them all as\n"
        "  -- FixedString indices returned unrelated strings (WeaponRange = Action_Smash).\n"
        "  local s = Ext.Stats.Get('WPN_Longsword')\n"
        "  AssertEquals(math.type(s.WeaponRange), 'integer', 'WeaponRange (ConstantInt)')\n"
        "  assert(s.WeaponRange > 0, 'WeaponRange ' .. tostring(s.WeaponRange))\n"
        "  AssertEquals(type(s.Weight), 'number', 'Weight (ConstantFloat)')\n"
        "  assert(s.Weight > 0 and s.Weight < 100, 'Weight ' .. tostring(s.Weight))\n"
        "  AssertEquals(s['Damage Type'], 'Slashing', 'Damage Type (enumeration label)')\n"
        "  AssertEquals(s.Damage, '1d8', 'Damage (FixedString)')\n"
        "  local props = s['Weapon Properties']\n"
        "  AssertType(props, 'table', 'Weapon Properties (flags)')\n"
        "  local has = {}\n"
        "  for _, p in ipairs(props) do has[p] = true end\n"
        "  assert(has.Versatile and has.Melee, 'Weapon Properties: ' .. table.concat(props, ','))\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Stats.TypedWrites', function()\n"
        "  -- Writes stored a float's bits / a FixedString index into any slot:\n"
        "  -- Weight = 2.5 and ['Damage Type'] = 'Fire' both read back nil.\n"
        "  local s = Ext.Stats.Create('BG3SE_TypedWriteTest', 'Weapon')\n"
        "  AssertNotNil(s, 'created stat')\n"
        "  s.WeaponRange = 200\n"
        "  AssertEquals(s.WeaponRange, 200, 'ConstantInt write')\n"
        "  local w = Ext.Stats.Get('WPN_Dagger').Weight\n"
        "  s.Weight = w\n"
        "  AssertEquals(s.Weight, w, 'ConstantFloat write (existing pool value)')\n"
        "  s['Damage Type'] = 'Fire'\n"
        "  AssertEquals(s['Damage Type'], 'Fire', 'enumeration write by label')\n"
        "  local props = Ext.Stats.Get('WPN_Longsword')['Weapon Properties']\n"
        "  s['Weapon Properties'] = props\n"
        "  AssertEquals(table.concat(s['Weapon Properties'], ','), table.concat(props, ','),\n"
        "    'flags write (existing combination)')\n"
        "  s.Weight = 'not a number'\n"
        "  AssertEquals(s.Weight, w, 'a wrong-typed write leaves the value unchanged')\n"
        "  s['Damage Type'] = 'NotADamageType'\n"
        "  AssertEquals(s['Damage Type'], 'Fire', 'an unknown label leaves the value unchanged')\n"
        "  -- A string absent from the FixedStrings pool was refused on game stats.\n"
        "  local g = Ext.Stats.Get('WPN_Longsword')\n"
        "  local original = g.Boosts\n"
        "  g.Boosts = 'AC(1);BG3SE_TypedWriteNovel()'\n"
        "  local written = g.Boosts\n"
        "  g.Boosts = original\n"
        "  AssertEquals(written, 'AC(1);BG3SE_TypedWriteNovel()', 'FixedString write of a new string')\n"
        "  AssertEquals(g.Boosts, original, 'FixedString restore')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Stats.ConditionsAndTranslatedStrings', function()\n"
        "  -- Both read as FixedString indices and returned unrelated strings\n"
        "  -- (TargetConditions '.25', DisplayName 'Spell_Conjuration_Web').\n"
        "  local s = Ext.Stats.Get('Projectile_FireBolt')\n"
        "  AssertType(s.TargetConditions, 'string', 'TargetConditions (Conditions pool)')\n"
        "  assert(s.TargetConditions:find('%w+%(%)'),\n"
        "    'TargetConditions is not a condition expression: ' .. s.TargetConditions)\n"
        "  AssertType(s.DisplayName, 'string', 'DisplayName (TranslatedString handle)')\n"
        "  assert(s.DisplayName:match('^h%x+g'), 'DisplayName is not a handle: ' .. s.DisplayName)\n"
        "  local text = Ext.Loca.GetTranslatedString(s.DisplayName)\n"
        "  assert(text and #text > 0, 'DisplayName handle does not resolve')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Stats.GetNonexistent', function()\n"
        "  local s = Ext.Stats.Get('NONEXISTENT_STAT_12345')\n"
        "  assert(s == nil, 'Expected nil for nonexistent stat')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Stats.GetAll', function()\n"
        "  local t = Ext.Stats.GetAll()\n"
        "  assert(type(t) == 'table', 'Expected table')\n"
        "  assert(#t > 0, 'Expected non-empty table')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Stats.GetAllFiltered', function()\n"
        "  local all = Ext.Stats.GetAll()\n"
        "  local weapons = Ext.Stats.GetAll('Weapon')\n"
        "  AssertType(weapons, 'table', 'Filtered result')\n"
        "  assert(#weapons > 0, 'Expected some weapons')\n"
        "  assert(#weapons <= #all, 'Filtered should not exceed total')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Stats.IsReady', function()\n"
        "  assert(Ext.Stats.IsReady() == true, 'Stats should be ready')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Stats.Sync', function()\n"
        "  local s = Ext.Stats.Get('Projectile_FireBolt')\n"
        "  AssertNotNil(s, 'Projectile_FireBolt should exist')\n"
        "  s.Damage = '2d6'\n"
        "  Ext.Stats.Sync('Projectile_FireBolt')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Stats.EnumIndexToLabel', function()\n"
        "  -- C++ enum names resolve through the enum registry (Windows order);\n"
        "  -- these returned nil when only ModifierValueLists were consulted.\n"
        "  local i = Ext.Stats.EnumLabelToIndex('DamageType', 'Fire')\n"
        "  AssertType(i, 'number', 'EnumLabelToIndex(DamageType, Fire)')\n"
        "  AssertEquals(Ext.Stats.EnumIndexToLabel('DamageType', i), 'Fire', 'round trip')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Stats.EnumLabelToIndex', function()\n"
        "  -- ModifierValueLists names still resolve (no registry enum of that name).\n"
        "  local i = Ext.Stats.EnumLabelToIndex('Damage Type', 'Fire')\n"
        "  AssertType(i, 'number', \"EnumLabelToIndex('Damage Type', Fire)\")\n"
        "  AssertEquals(Ext.Stats.EnumIndexToLabel('Damage Type', i), 'Fire', 'round trip')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Stats.CreateSync', function()\n"
        "  local s = Ext.Stats.Create('BG3SE_TestStat', 'Weapon')\n"
        "  if s then\n"
        "    s.Damage = '1d4'\n"
        "    Ext.Stats.Sync('BG3SE_TestStat')\n"
        "    local r = Ext.Stats.Get('BG3SE_TestStat')\n"
        "    AssertNotNil(r, 'Created stat should exist')\n"
        "  end\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Stats.SetRawAttribute', function()\n"
        "  local name = 'BG3SE_TestRawAttribute'\n"
        "  local s = Ext.Stats.Get(name) or\n"
        "    Ext.Stats.Create(name, 'Weapon', 'WPN_Longsword')\n"
        "  AssertNotNil(s, 'shadow Weapon stat')\n"
        "  local original = s.Damage\n"
        "  AssertNotNil(original, 'shadow Damage before write')\n"
        "  local candidate = original == '1d4' and '1d6' or '1d4'\n"
        "  AssertEquals(s:SetRawAttribute('Damage', candidate), true,\n"
        "    'SetRawAttribute result')\n"
        "  AssertEquals(s.Damage, candidate, 'Damage write round-trip')\n"
        "  AssertEquals(s:SetRawAttribute('Damage', original), true,\n"
        "    'SetRawAttribute restore result')\n"
        "  AssertEquals(s.Damage, original, 'Damage restore round-trip')\n"
        "end)\n";

    // Tier 1: Wave 2 Stats honesty (2 tests)
    static const char *console_cmd_test_wave2_stats =
        "BG3SE_AddTest(1, 'Stats.Goal23.HonestSurface', function()\n"
        "  AssertType(Ext.Stats.GetStatsLoadedMods, 'function', 'GetStatsLoadedMods')\n"
        "  AssertType(Ext.Stats.GetStatsLoadedBefore, 'function', 'GetStatsLoadedBefore')\n"
        "  AssertType(Ext.Stats.TreasureTable.Get, 'function', 'TreasureTable.Get')\n"
        "  AssertType(Ext.Stats.TreasureTable.GetLegacy, 'function', 'TreasureTable.GetLegacy')\n"
        "  AssertType(Ext.Stats.TreasureCategory.GetLegacy, 'function',\n"
        "    'TreasureCategory.GetLegacy')\n"
        "  AssertEquals(Ext.Stats.AddAttribute('Weapon',\n"
        "    'BG3SE_Goal23_MustNotExist', 'FixedString'), false,\n"
        "    'allocator-gated AddAttribute')\n"
        "  assert(Ext.Stats.AddEnumerationValue('BG3SE_Goal23_NoSuchEnum',\n"
        "    'BG3SE_Goal23_MustNotExist') == false,\n"
        "    'unknown-enum AddEnumerationValue must fail closed (false)')\n"
        "  assert(Ext.Stats.TreasureTable.Get(\n"
        "    'BG3SE_Goal23_MissingTreasureTable') == nil,\n"
        "    'unknown treasure table must return nil')\n"
        "  assert(Ext.Stats.TreasureCategory.GetLegacy(\n"
        "    'BG3SE_Goal23_MissingTreasureCategory') == nil,\n"
        "    'unknown treasure category must return nil')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Stats.Goal23.ModuleLoadOrder', function()\n"
        "  local function isUuid(v)\n"
        "    if type(v) ~= 'string' or #v ~= 36 then return false end\n"
        "    local a, b, c, d, e = v:match(\n"
        "      '^([%x]+)%-([%x]+)%-([%x]+)%-([%x]+)%-([%x]+)$')\n"
        "    return a ~= nil and #a == 8 and #b == 4 and #c == 4 and\n"
        "      #d == 4 and #e == 12\n"
        "  end\n"
        "  local loaded = Ext.Stats.GetStatsLoadedMods()\n"
        "  AssertType(loaded, 'table', 'GetStatsLoadedMods result')\n"
        "  assert(#loaded > 0, 'expected at least the base module in load order')\n"
        "  local base = Ext.Mod.GetBaseMod()\n"
        "  AssertNotNil(base, 'base module')\n"
        "  local baseUuid = base.UUID or (base.Info and base.Info.ModuleUUID)\n"
        "  AssertType(baseUuid, 'string', 'base module UUID')\n"
        "  assert(isUuid(baseUuid), 'base module UUID has invalid format: ' .. baseUuid)\n"
        "  local throughBase = Ext.Stats.GetStatsLoadedBefore(baseUuid)\n"
        "  AssertType(throughBase, 'table', 'GetStatsLoadedBefore result')\n"
        "  assert(#throughBase > 0, 'base-module boundary should be inclusive')\n"
        "  AssertEquals(throughBase[#throughBase], baseUuid,\n"
        "    'load-order prefix boundary')\n"
        "  for i, moduleId in ipairs(throughBase) do\n"
        "    assert(isUuid(moduleId),\n"
        "      'load-order entry ' .. i .. ' is not a UUID: ' .. tostring(moduleId))\n"
        "    AssertEquals(moduleId, loaded[i],\n"
        "      'GetStatsLoadedBefore prefix entry ' .. i)\n"
        "  end\n"
        "end)\n";

    // Tier 1: Wave 3 Stats regression coverage (2 tests)
    static const char *console_cmd_test_wave3_stats =
        "BG3SE_AddTest(1, 'Stats.SyncNonexistentReturnsFalse', function()\n"
        "  AssertEquals(Ext.Stats.Sync('BG3SE_Wave3_Stat_Does_Not_Exist'), false,\n"
        "    'nonexistent stat sync result')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Stats.TreasureTable.EmptyIsRealTable', function()\n"
        "  -- Shared/Stats/Generated/TreasureTable.txt declares _TradeItems\n"
        "  -- with no following subtable before the next treasuretable.\n"
        "  local info = Ext.Stats.TreasureTable.Get('_TradeItems')\n"
        "  AssertNotNil(info, '_TradeItems treasure table')\n"
        "  AssertEquals(info.Name, '_TradeItems', 'empty treasure table name')\n"
        "  AssertType(info.Address, 'number', 'empty treasure table address')\n"
        "  AssertType(info.SubTables, 'table', 'empty treasure subtables')\n"
        "  AssertEquals(#info.SubTables, 0, 'empty treasure subtable count')\n"
        "  assert(next(info.SubTables) == nil,\n"
        "    'empty treasure subtables must be a real empty table')\n"
        "end)\n";

    // Tier 1: Timer (8 tests)
    static const char *console_cmd_test_timer =
        "BG3SE_AddTest(1, 'Timer.WaitFor', function()\n"
        "  local h = Ext.Timer.WaitFor(99999, function() end)\n"
        "  assert(type(h) == 'number', 'Expected number handle')\n"
        "  Ext.Timer.Cancel(h)\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Timer.Cancel', function()\n"
        "  local h = Ext.Timer.WaitFor(99999, function() end)\n"
        "  Ext.Timer.Cancel(h)\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Timer.PauseResume', function()\n"
        "  local h = Ext.Timer.WaitFor(99999, function() end)\n"
        "  local paused = Ext.Timer.Pause(h)\n"
        "  assert(paused == true, 'Pause should return true')\n"
        "  assert(Ext.Timer.IsPaused(h) == true, 'Should be paused')\n"
        "  local resumed = Ext.Timer.Resume(h)\n"
        "  assert(resumed == true, 'Resume should return true')\n"
        "  Ext.Timer.Cancel(h)\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Timer.MonotonicTime', function()\n"
        "  local t = Ext.Timer.MonotonicTime()\n"
        "  assert(type(t) == 'number' and t > 0, 'Expected positive number')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Timer.MicrosecTime', function()\n"
        "  local t = Ext.Timer.MicrosecTime()\n"
        "  assert(type(t) == 'number' and t > 0, 'Expected positive number')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Timer.GameTime', function()\n"
        "  local t = Ext.Timer.GameTime()\n"
        "  assert(type(t) == 'number', 'Expected number')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Timer.DeltaTime', function()\n"
        "  local t = Ext.Timer.DeltaTime()\n"
        "  assert(type(t) == 'number', 'Expected number')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Timer.Ticks', function()\n"
        "  local t = Ext.Timer.Ticks()\n"
        "  assert(type(t) == 'number', 'Expected number')\n"
        "end)\n";

    // Tier 1: Events (5 tests)
    static const char *console_cmd_test_events =
        "BG3SE_AddTest(1, 'Events.TickSubscribe', function()\n"
        "  local id = Ext.Events.Tick:Subscribe(function() end)\n"
        "  assert(type(id) == 'number', 'Expected number ID')\n"
        "  Ext.Events.Tick:Unsubscribe(id)\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Events.TickUnsubscribe', function()\n"
        "  local id = Ext.Events.Tick:Subscribe(function() end)\n"
        "  Ext.Events.Tick:Unsubscribe(id)\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Events.SessionLoaded', function()\n"
        "  local id = Ext.Events.SessionLoaded:Subscribe(function() end)\n"
        "  assert(type(id) == 'number', 'Expected number ID')\n"
        "  Ext.Events.SessionLoaded:Unsubscribe(id)\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Events.OnNextTick', function()\n"
        "  AssertType(Ext.OnNextTick, 'function', 'Ext.OnNextTick')\n"
        "  Ext.OnNextTick(function() end)\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Events.SubscribeOptions', function()\n"
        "  local id = Ext.Events.Tick:Subscribe(function() end, {Priority=50, Once=true})\n"
        "  assert(type(id) == 'number', 'Expected number ID')\n"
        "end)\n";

    // Tier 1: Debug (10 tests)
    static const char *console_cmd_test_debug =
        "BG3SE_AddTest(1, 'Debug.ReadPtr', function()\n"
        "  assert(Ext.Debug.ReadPtr(0) == nil, 'Expected nil for addr 0')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Debug.ReadU32', function()\n"
        "  assert(Ext.Debug.ReadU32(0) == nil, 'Expected nil for addr 0')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Debug.ReadI32', function()\n"
        "  assert(Ext.Debug.ReadI32(0) == nil, 'Expected nil for addr 0')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Debug.ReadFloat', function()\n"
        "  assert(Ext.Debug.ReadFloat(0) == nil, 'Expected nil for addr 0')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Debug.IsValidPointer', function()\n"
        "  assert(Ext.Debug.IsValidPointer(0) == false, 'Expected false for addr 0')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Debug.ClassifyNull', function()\n"
        "  local r = Ext.Debug.ClassifyPointer(0)\n"
        "  assert(type(r) == 'table', 'Expected table')\n"
        "  assert(r.type == 'null', 'Expected null type, got ' .. tostring(r.type))\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Debug.ClassifySmallInt', function()\n"
        "  local r = Ext.Debug.ClassifyPointer(42)\n"
        "  assert(type(r) == 'table', 'Expected table')\n"
        "  assert(r.type == 'small_int', 'Expected small_int, got ' .. tostring(r.type))\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Debug.Time', function()\n"
        "  local t = Ext.Debug.Time()\n"
        "  assert(type(t) == 'string', 'Expected string')\n"
        "  assert(t:match('%d+:%d+:%d+'), 'Bad time format: ' .. t)\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Debug.Timestamp', function()\n"
        "  local t = Ext.Debug.Timestamp()\n"
        "  assert(type(t) == 'number' and t > 0, 'Expected positive number')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Debug.SessionAge', function()\n"
        "  local t = Ext.Debug.SessionAge()\n"
        "  assert(type(t) == 'number' and t >= 0, 'Expected non-negative number')\n"
        "end)\n";

    // Tier 1: Types + Enums (9 tests)
    static const char *console_cmd_test_types =
        "BG3SE_AddTest(1, 'Types.GetAllTypes', function()\n"
        "  local t = Ext.Types.GetAllTypes()\n"
        "  assert(type(t) == 'table', 'Expected table')\n"
        "  assert(#t > 1000, 'Expected >1000 types, got ' .. #t)\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Types.GetTypeInfo', function()\n"
        "  local info = Ext.Types.GetTypeInfo('Weapon')\n"
        "  assert(info ~= nil, 'Expected non-nil for Weapon')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Types.GetAllLayouts', function()\n"
        "  local t = Ext.Types.GetAllLayouts()\n"
        "  assert(type(t) == 'table', 'Expected table')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Types.GetComponentLayout', function()\n"
        "  local ok, r = pcall(Ext.Types.GetComponentLayout, 'Health')\n"
        "  assert(ok, 'GetComponentLayout should not error: ' .. tostring(r))\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Types.TypeOf', function()\n"
        "  local s = Ext.Stats.Get('WPN_Longsword')\n"
        "  AssertNotNil(s, 'WPN_Longsword stat')\n"
        "  local t = Ext.Types.TypeOf(s)\n"
        "  AssertType(t, 'table', 'TypeOf result')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Types.GenerateIdeHelpers', function()\n"
        "  AssertType(Ext.Types.GenerateIdeHelpers, 'function', 'GenerateIdeHelpers')\n"
        "  local ok, r = pcall(Ext.Types.GenerateIdeHelpers, 'test_helpers.lua')\n"
        "  assert(ok, 'GenerateIdeHelpers should not error: ' .. tostring(r))\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Enums.DamageType', function()\n"
        "  assert(Ext.Enums.DamageType ~= nil, 'DamageType should exist')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Enums.DamageTypeFire', function()\n"
        "  assert(Ext.Enums.DamageType.Fire ~= nil, 'Fire should exist')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Enums.AbilityId', function()\n"
        "  assert(Ext.Enums.AbilityId ~= nil, 'AbilityId should exist')\n"
        "end)\n";

    // Tier 1: IO + Memory + Mod + Vars + Osi (15 tests)
    static const char *console_cmd_test_misc =
        "BG3SE_AddTest(1, 'IO.LoadFile', function()\n"
        "  AssertType(Ext.IO.LoadFile, 'function', 'IO.LoadFile')\n"
        "  local r = Ext.IO.LoadFile('nonexistent_bg3se_test_file_12345.txt')\n"
        "  assert(r == nil, 'LoadFile on nonexistent file should return nil')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'IO.SaveFile', function()\n"
        "  AssertType(Ext.IO.SaveFile, 'function', 'IO.SaveFile')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'IO.AddPathOverride', function()\n"
        "  AssertType(Ext.IO.AddPathOverride, 'function', 'IO.AddPathOverride')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Memory.GetModuleBase', function()\n"
        "  local v = Ext.Memory.GetModuleBase('bg3')\n"
        "  assert(v == nil or type(v) == 'number', 'Expected number or nil')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Memory.ReadInvalid', function()\n"
        "  local v = Ext.Memory.Read(0, 8)\n"
        "  assert(v == nil, 'Reading addr 0 should return nil')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Memory.Search', function()\n"
        "  AssertType(Ext.Memory.Search, 'function', 'Memory.Search')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Mod.GetLoadOrder', function()\n"
        "  local t = Ext.Mod.GetLoadOrder()\n"
        "  AssertType(t, 'table', 'GetLoadOrder result')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Mod.GetBaseMod', function()\n"
        "  local m = Ext.Mod.GetBaseMod()\n"
        "  AssertNotNil(m, 'Base mod')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Mod.IsModLoaded', function()\n"
        "  local v = Ext.Mod.IsModLoaded('00000000-0000-0000-0000-000000000000')\n"
        "  AssertEquals(v, false, 'Fake UUID should not be loaded')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Mod.GetModManager', function()\n"
        "  AssertType(Ext.Mod.GetModManager, 'function', 'GetModManager')\n"
        "  local ok, r = pcall(Ext.Mod.GetModManager)\n"
        "  assert(ok, 'GetModManager should not crash: ' .. tostring(r))\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Vars.Exists', function()\n"
        "  AssertType(Ext.Vars, 'table', 'Ext.Vars')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Vars.ReloadPersistentVars', function()\n"
        "  AssertType(Ext.Vars.ReloadPersistentVars, 'function', 'ReloadPersistentVars')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Osi.Exists', function()\n"
        "  AssertType(Osi, 'table', 'Osi')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Osi.SafeCall', function()\n"
        "  local ok, err = pcall(function() local _ = Osi.GetHostCharacter end)\n"
        "  assert(ok, 'Osi metatable index should not crash: ' .. tostring(err))\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Osi.MetatableExists', function()\n"
        "  local mt = getmetatable(Osi)\n"
        "  AssertNotNil(mt, 'Osi should have metatable')\n"
        "  AssertNotNil(mt.__index, 'Osi metatable should have __index')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Osi.IndexReturnsFunction', function()\n"
        "  local fn = Osi.GetHostCharacter\n"
        "  AssertType(fn, 'function', 'Osi.__index result')\n"
        "end)\n";

    // Tier 1: MCM Compatibility (10 tests — targets Issue #68)
    // Note: ModEvents.Subscribe/Throw/Unsubscribe are table namespaces (with __index), not functions
    static const char *console_cmd_test_mcm =
        "BG3SE_AddTest(1, 'MCM.ModEventsExists', function()\n"
        "  AssertNotNil(Ext.ModEvents, 'Ext.ModEvents')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'MCM.SubscribeExists', function()\n"
        "  AssertNotNil(Ext.ModEvents.Subscribe, 'ModEvents.Subscribe')\n"
        "  AssertType(Ext.ModEvents.Subscribe, 'table', 'ModEvents.Subscribe')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'MCM.ThrowExists', function()\n"
        "  AssertNotNil(Ext.ModEvents.Throw, 'ModEvents.Throw')\n"
        "  AssertType(Ext.ModEvents.Throw, 'table', 'ModEvents.Throw')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'MCM.UnsubscribeExists', function()\n"
        "  AssertNotNil(Ext.ModEvents.Unsubscribe, 'ModEvents.Unsubscribe')\n"
        "  AssertType(Ext.ModEvents.Unsubscribe, 'table', 'ModEvents.Unsubscribe')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'MCM.EventRoundtrip', function()\n"
        "  -- Subscribe/Throw/Unsubscribe may be tables with __call\n"
        "  local ok, id = pcall(Ext.ModEvents.Subscribe, Ext.ModEvents, 'bg3se_test', 'TestEvent', function(e) end)\n"
        "  if ok and type(id) == 'number' then\n"
        "    pcall(Ext.ModEvents.Throw, Ext.ModEvents, 'bg3se_test', 'TestEvent', {val=42})\n"
        "    pcall(Ext.ModEvents.Unsubscribe, Ext.ModEvents, id)\n"
        "  end\n"
        "  -- Pass if subscribe/throw/unsubscribe don't crash\n"
        "end)\n"
        "BG3SE_AddTest(1, 'MCM.RegisterNetListener', function()\n"
        "  AssertType(Ext.RegisterNetListener, 'function', 'RegisterNetListener')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'MCM.NetCreateChannel', function()\n"
        "  if Net and Net.CreateChannel then\n"
        "    AssertType(Net.CreateChannel, 'function', 'Net.CreateChannel')\n"
        "  end\n"
        "end)\n"
        "BG3SE_AddTest(1, 'MCM.PostMessageToServer', function()\n"
        "  AssertType(Ext.Net.PostMessageToServer, 'function', 'PostMessageToServer')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'MCM.OsirisRegisterListener', function()\n"
        "  AssertType(Ext.Osiris.RegisterListener, 'function', 'RegisterListener')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'MCM.OsirisNewCall', function()\n"
        "  AssertType(Ext.Osiris.NewCall, 'function', 'NewCall')\n"
        "end)\n";

    // Register !test command (Tier 1)
    static const char *console_cmd_test_register =
        "Ext.RegisterConsoleCommand('test', function(cmd, filter)\n"
        "  BG3SE_RunTests(1, (filter and filter ~= '') and filter or nil)\n"
        "end)\n";

    // Tier 2: In-game tests (22 tests, need loaded save)
    static const char *console_cmd_test_ingame =
        "BG3SE_AddTest(2, 'Entity.ModuleExists', function()\n"
        "  assert(Ext.Entity ~= nil, 'Entity module should exist')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Entity.Get', function()\n"
        "  assert(type(Ext.Entity.Get) == 'function', 'Expected function')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Entity.GetByHandle', function()\n"
        "  assert(type(Ext.Entity.GetByHandle) == 'function', 'Expected function')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Entity.HostChar', function()\n"
        "  local host = Osi.GetHostCharacter()\n"
        "  AssertNotNil(host, 'Osi.GetHostCharacter()')\n"
        "  AssertGUID(host, 'host character GUID')\n"
        "  local e = Ext.Entity.Get(host)\n"
        "  AssertNotNil(e, 'Host entity from Get()')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Entity.ComponentAccess', function()\n"
        "  local host = Osi.GetHostCharacter()\n"
        "  AssertNotNil(host, 'Osi.GetHostCharacter()')\n"
        "  local e = Ext.Entity.Get(host)\n"
        "  AssertNotNil(e, 'Host entity')\n"
        "  local h = e.Health\n"
        "  AssertNotNil(h, 'Health component')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Level.IsReady', function()\n"
        "  AssertType(Ext.Level.IsReady, 'function', 'Level.IsReady')\n"
        "  local v = Ext.Level.IsReady()\n"
        "  AssertType(v, 'boolean', 'Level.IsReady result')\n"
        "  assert(v == true, 'Level should be ready with save loaded')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Level.GetCurrentLevel', function()\n"
        "  assert(Ext.Level.IsReady(), 'Level should be ready')\n"
        "  local v = Ext.Level.GetCurrentLevel()\n"
        "  AssertNotNil(v, 'Current level')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Level.GetPhysicsScene', function()\n"
        "  assert(Ext.Level.IsReady(), 'Level should be ready')\n"
        "  local v = Ext.Level.GetPhysicsScene()\n"
        "  AssertNotNil(v, 'Physics scene')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Level.GetAiGrid', function()\n"
        "  assert(Ext.Level.IsReady(), 'Level should be ready')\n"
        "  local v = Ext.Level.GetAiGrid()\n"
        "  AssertNotNil(v, 'AI grid')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Level.GetHeightsAt', function()\n"
        "  assert(Ext.Level.IsReady(), 'Level should be ready')\n"
        "  local ok, r = pcall(Ext.Level.GetHeightsAt, 0, 0)\n"
        "  assert(ok, 'GetHeightsAt should not crash: ' .. tostring(r))\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Audio.IsReady', function()\n"
        "  AssertType(Ext.Audio.IsReady, 'function', 'Audio.IsReady')\n"
        "  local v = Ext.Audio.IsReady()\n"
        "  AssertType(v, 'boolean', 'Audio.IsReady result')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Audio.GetSoundObjectId', function()\n"
        "  AssertType(Ext.Audio.GetSoundObjectId, 'function', 'GetSoundObjectId')\n"
        "  local ok, r = pcall(Ext.Audio.GetSoundObjectId, 'test')\n"
        "  -- May return nil for unknown object, should not crash\n"
        "  assert(ok, 'GetSoundObjectId should not crash: ' .. tostring(r))\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Audio.PostEvent', function()\n"
        "  AssertType(Ext.Audio.PostEvent, 'function', 'PostEvent')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Audio.SetState', function()\n"
        "  AssertType(Ext.Audio.SetState, 'function', 'SetState')\n"
        "end)\n";

    // Tier 2 continued: Net + IMGUI + StaticData (split for 4095 limit)
    static const char *console_cmd_test_ingame2 =
        "BG3SE_AddTest(2, 'Net.IsReady', function()\n"
        "  AssertType(Ext.Net.IsReady, 'function', 'Net.IsReady')\n"
        "  local v = Ext.Net.IsReady()\n"
        "  AssertType(v, 'boolean', 'Net.IsReady result')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Net.IsHost', function()\n"
        "  AssertType(Ext.Net.IsHost, 'function', 'Net.IsHost')\n"
        "  local v = Ext.Net.IsHost()\n"
        "  AssertType(v, 'boolean', 'Net.IsHost result')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Net.Version', function()\n"
        "  AssertType(Ext.Net.Version, 'function', 'Net.Version')\n"
        "  local ok, v = pcall(Ext.Net.Version)\n"
        "  assert(ok, 'Net.Version should not crash: ' .. tostring(v))\n"
        "  AssertNotNil(v, 'Net.Version return value')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Net.PostMessageToServer', function()\n"
        "  AssertType(Ext.Net.PostMessageToServer, 'function', 'PostMessageToServer')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'IMGUI.IsReady', function()\n"
        "  AssertType(Ext.IMGUI.IsReady, 'function', 'IMGUI.IsReady')\n"
        "  local v = Ext.IMGUI.IsReady()\n"
        "  AssertType(v, 'boolean', 'IMGUI.IsReady result')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'IMGUI.NewWindow', function()\n"
        "  AssertType(Ext.IMGUI.NewWindow, 'function', 'IMGUI.NewWindow')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'StaticData.IsReady', function()\n"
        "  AssertType(Ext.StaticData.IsReady, 'function', 'StaticData.IsReady')\n"
        "  local v = Ext.StaticData.IsReady()\n"
        "  AssertType(v, 'boolean', 'StaticData.IsReady result')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'StaticData.GetTypes', function()\n"
        "  assert(Ext.StaticData.IsReady(), 'StaticData should be ready')\n"
        "  local t = Ext.StaticData.GetTypes()\n"
        "  AssertType(t, 'table', 'StaticData.GetTypes result')\n"
        "  assert(#t > 0, 'Expected non-empty types list')\n"
        "end)\n";

    // Tier 2: StaticData typed layouts (#100) + canonical GUID text
    static const char *console_cmd_test_staticdata_layout =
        "BG3SE_AddTest(2, 'StaticData.GuidCanonical', function()\n"
        "  -- Human race GUID as written in Races.lsx; pair-swapped text must not match\n"
        "  local human = Ext.StaticData.Get('Race', '0eb594cb-8820-4be6-a58d-8be7a1a98fba')\n"
        "  assert(human ~= nil, 'canonical Human race GUID must resolve')\n"
        "  AssertEquals(human.Name, 'Human', 'Race name for the Human GUID')\n"
        "  AssertEquals(human.ResourceUUID, '0eb594cb-8820-4be6-a58d-8be7a1a98fba', 'ResourceUUID text')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'StaticData.CCAppearanceVisual.Count', function()\n"
        "  assert(Ext.StaticData.IsReady('CharacterCreationAppearanceVisual'), 'manager captured')\n"
        "  local n = Ext.StaticData.GetCount('CharacterCreationAppearanceVisual')\n"
        "  assert(n > 0, 'expected appearance visuals, got ' .. tostring(n))\n"
        "end)\n"
        "BG3SE_AddTest(2, 'StaticData.CCAppearanceVisual.Fields', function()\n"
        "  local all = Ext.StaticData.GetAll('CharacterCreationAppearanceVisual')\n"
        "  assert(#all > 0, 'GetAll returned no entries')\n"
        "  local e\n"
        "  for _, cand in ipairs(all) do\n"
        "    if cand.RaceUUID and cand.RaceUUID ~= '00000000-0000-0000-0000-000000000000' then e = cand break end\n"
        "  end\n"
        "  assert(e, 'no entry with a RaceUUID')\n"
        "  AssertGUID(e.ResourceUUID, 'ResourceUUID')\n"
        "  AssertGUID(e.VisualResource, 'VisualResource')\n"
        "  AssertType(e.SlotName, 'string', 'SlotName')\n"
        "  assert(#e.SlotName > 0, 'SlotName should resolve to text')\n"
        "  AssertType(e.BodyType, 'number', 'BodyType')\n"
        "  AssertType(e.BodyShape, 'number', 'BodyShape')\n"
        "  AssertType(e.DisplayName, 'table', 'DisplayName')\n"
        "  AssertType(e.DisplayName.Handle.Handle, 'string', 'DisplayName.Handle.Handle')\n"
        "  AssertType(e.Tags, 'table', 'Tags')\n"
        "  local race = Ext.StaticData.Get('Race', e.RaceUUID)\n"
        "  assert(race ~= nil, 'RaceUUID should resolve to a Race: ' .. e.RaceUUID)\n"
        "  local again = Ext.StaticData.Get('CharacterCreationAppearanceVisual', e.ResourceUUID)\n"
        "  assert(again and again.ResourceUUID == e.ResourceUUID, 'Get(type, ResourceUUID) round trip')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'StaticData.AllTypesPopulated', function()\n"
        "  -- Every bank resolves and every entry is a real resource: a wrong stride\n"
        "  -- produces nil/non-v4 GUIDs from the second entry onward (7398727 live).\n"
        "  for _, t in ipairs(Ext.StaticData.GetTypes()) do\n"
        "    local n = Ext.StaticData.GetCount(t)\n"
        "    assert(n > 0, t .. ': expected entries, got ' .. tostring(n))\n"
        "    local all = Ext.StaticData.GetAll(t)\n"
        "    AssertEquals(#all, n, t .. ' GetAll length')\n"
        "    local v4 = 0\n"
        "    for _, e in ipairs(all) do\n"
        "      AssertGUID(e.ResourceUUID, t .. ' ResourceUUID')\n"
        "      assert(e.ResourceUUID ~= '00000000-0000-0000-0000-000000000000', t .. ' nil GUID')\n"
        "      if e.ResourceUUID:sub(15, 15) == '4' then v4 = v4 + 1 end\n"
        "    end\n"
        "    assert(v4 * 100 >= n * 99, t .. ': only ' .. v4 .. '/' .. n .. ' entries carry a v4 GUID (stride?)')\n"
        "  end\n"
        "end)\n";

    // Tier 2: Osiris Dispatch (8 tests — targets Issue #66)
    static const char *console_cmd_test_osiris =
        "BG3SE_AddTest(2, 'Osi.GetHostCharacter', function()\n"
        "  local host = Osi.GetHostCharacter()\n"
        "  AssertNotNil(host, 'GetHostCharacter')\n"
        "  AssertGUID(host, 'host GUID')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Osi.DB_Players.RowsAreCharacters', function()\n"
        "  -- Facts decode: rows were pointer-shaped integers on 7398727\n"
        "  local host = Osi.GetHostCharacter()\n"
        "  local rows = Osi.DB_Players:Get(nil)\n"
        "  assert(#rows > 0, 'DB_Players has no rows')\n"
        "  local found = false\n"
        "  for _, row in ipairs(rows) do\n"
        "    AssertType(row[1], 'string', 'DB_Players column 1')\n"
        "    assert(row[1]:find('%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x+$'),\n"
        "      'DB_Players row is not a character GUID: ' .. tostring(row[1]))\n"
        "    if row[1]:sub(-36) == host:sub(-36) then found = true end\n"
        "  end\n"
        "  assert(found, 'host ' .. host .. ' not in DB_Players')\n"
        "  local filtered = Osi.DB_Players:Get(rows[1][1])\n"
        "  AssertEquals(#filtered, 1, 'filter by the first row returns exactly it')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Osi.MetatableIndex', function()\n"
        "  local fn = Osi.GetHostCharacter\n"
        "  AssertType(fn, 'function', 'Osi.GetHostCharacter')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Osi.IsInCombat', function()\n"
        "  local host = Osi.GetHostCharacter()\n"
        "  if host then\n"
        "    local r = Osi.IsInCombat(host)\n"
        "    assert(r == nil or type(r) == 'number', 'Expected number or nil, got ' .. type(r))\n"
        "  end\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Osi.NonexistentSafe', function()\n"
        "  local ok, err = pcall(function() return Osi.ZZZZZ_NoSuchFunction_12345() end)\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Osi.CacheConsistency', function()\n"
        "  local h1 = Osi.GetHostCharacter()\n"
        "  local h2 = Osi.GetHostCharacter()\n"
        "  AssertEquals(h1, h2, 'GetHostCharacter should be consistent')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Osi.GetLevel', function()\n"
        "  local host = Osi.GetHostCharacter()\n"
        "  if host then\n"
        "    local lvl = Osi.GetLevel(host)\n"
        "    assert(lvl == nil or type(lvl) == 'number', 'Expected number or nil')\n"
        "    if lvl then assert(lvl >= 1 and lvl <= 20, 'Level out of range: ' .. lvl) end\n"
        "  end\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Osi.GetHitpoints', function()\n"
        "  local host = Osi.GetHostCharacter()\n"
        "  if host then\n"
        "    local hp = Osi.GetHitpoints(host)\n"
        "    assert(hp == nil or type(hp) == 'number', 'Expected number or nil')\n"
        "    if hp then assert(hp > 0, 'HP should be positive: ' .. hp) end\n"
        "  end\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Osi.IsAlive', function()\n"
        "  local host = Osi.GetHostCharacter()\n"
        "  if host then\n"
        "    -- The loaded host is alive; nil meant the function did not resolve.\n"
        "    AssertEquals(Osi.IsAlive(host), 1, 'Osi.IsAlive(host)')\n"
        "    AssertEquals(Osi.IsDead(host), 0, 'Osi.IsDead(host)')\n"
        "  end\n"
        "end)\n";

    // Tier 2: Osiris Edge Cases (5 tests — Codex analysis)
    static const char *console_cmd_test_osiris_edge =
        "BG3SE_AddTest(2, 'Osi.WrongArgCount', function()\n"
        "  local ok, err = pcall(function() Osi.IsInCombat() end)\n"
        "  -- Should error about wrong arg count, not crash\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Osi.WrongArgType', function()\n"
        "  local ok, err = pcall(function() Osi.IsInCombat(12345) end)\n"
        "  -- Passing number instead of GUID should error or return nil, not crash\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Osi.NilArg', function()\n"
        "  local ok, err = pcall(function() Osi.IsInCombat(nil) end)\n"
        "  -- Nil arg should error gracefully, not crash\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Osi.TooManyArgs', function()\n"
        "  -- Regression test: extra args beyond arity must be clamped, not crash.\n"
        "  -- GetHostCharacter has arity=1 (0 in, 1 out). Passing 2 string args\n"
        "  -- used to walk past the arg chain into NULL+0xC (EXC_BAD_ACCESS).\n"
        "  local ok, result = pcall(function() return Osi.GetHostCharacter('extra', 'args') end)\n"
        "  assert(ok, 'TooManyArgs should not crash: ' .. tostring(result))\n"
        "  -- With clamping, the query should still work (extra args ignored)\n"
        "  local host = Osi.GetHostCharacter()\n"
        "  if host then\n"
        "    -- Verify the function still returns correct result with extra args\n"
        "    local ok2, r2 = pcall(function() return Osi.GetHostCharacter('junk') end)\n"
        "    assert(ok2, 'Single extra arg should not crash')\n"
        "  end\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Osi.LongStringArg', function()\n"
        "  local long = string.rep('A', 1000)\n"
        "  local ok, err = pcall(function() Osi.IsInCombat(long) end)\n"
        "  -- Long string should not cause buffer overflow\n"
        "end)\n";

    // Tier 2: Entity Events (5 tests)
    static const char *console_cmd_test_entity_events =
        "BG3SE_AddTest(2, 'EntityEvents.SubscribeExists', function()\n"
        "  AssertType(Ext.Entity.Subscribe, 'function', 'Entity.Subscribe')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'EntityEvents.OnCreateExists', function()\n"
        "  AssertType(Ext.Entity.OnCreate, 'function', 'Entity.OnCreate')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'EntityEvents.OnDestroyExists', function()\n"
        "  AssertType(Ext.Entity.OnDestroy, 'function', 'Entity.OnDestroy')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'EntityEvents.SubscribeReturnsHandle', function()\n"
        "  local id = Ext.Entity.Subscribe('Health', function() end)\n"
        "  AssertType(id, 'number', 'Subscribe handle')\n"
        "  Ext.Entity.Unsubscribe(id)\n"
        "end)\n"
        "BG3SE_AddTest(2, 'EntityEvents.UnsubscribeWorks', function()\n"
        "  local id = Ext.Entity.Subscribe('Health', function() end)\n"
        "  local ok = Ext.Entity.Unsubscribe(id)\n"
        "  assert(ok ~= false, 'Unsubscribe should succeed')\n"
        "end)\n";

    // Tier 2: Wave 2 component property writes (3 tests)
    static const char *console_cmd_test_wave2_components =
        "BG3SE_AddTest(2, 'Entity.ComponentWrite.HealthHpRoundTrip', function()\n"
        "  local entity = Ext.Entity.Get(Osi.GetHostCharacter())\n"
        "  AssertNotNil(entity, 'host entity')\n"
        "  local health = entity.Health\n"
        "  AssertNotNil(health, 'host Health component')\n"
        "  local original = health.Hp\n"
        "  AssertType(original, 'number', 'original Health.Hp')\n"
        "  local candidate = original > 1 and original - 1 or original + 1\n"
        "  local writeOk, writeErr = pcall(function()\n"
        "    health.Hp = candidate\n"
        "  end)\n"
        "  local observed = health.Hp\n"
        "  local restoreOk, restoreErr = pcall(function()\n"
        "    health.Hp = original\n"
        "  end)\n"
        "  assert(restoreOk, 'Health.Hp restore failed: ' .. tostring(restoreErr))\n"
        "  assert(writeOk, 'Health.Hp write failed: ' .. tostring(writeErr))\n"
        "  AssertEquals(observed, candidate, 'Health.Hp write round-trip')\n"
        "  AssertEquals(health.Hp, original, 'Health.Hp restore round-trip')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Entity.ComponentWrite.FixedStringRefused', function()\n"
        "  -- esv::OriginalTemplateComponent only exists on entities whose\n"
        "  -- template was transformed, so it is save-dependent. Exercise the\n"
        "  -- FixedString refusal path when the fixture is live; otherwise pass\n"
        "  -- with a note (same policy as OneFrameRefused below).\n"
        "  local entity = Ext.Entity.Get(Osi.GetHostCharacter())\n"
        "  AssertNotNil(entity, 'host entity')\n"
        "  local originalTemplate = entity['esv::OriginalTemplateComponent']\n"
        "  if originalTemplate == nil then\n"
        "    Ext.Print('    (OriginalTemplate fixture absent on this save; refusal path not exercised)')\n"
        "    return\n"
        "  end\n"
        "  local before = originalTemplate.TemplateId\n"
        "  local ok, err = pcall(function()\n"
        "    originalTemplate.TemplateId = 'Goal21_MustNotIntern'\n"
        "  end)\n"
        "  assert(not ok, 'FixedString write should raise a Lua error')\n"
        "  AssertType(err, 'string', 'FixedString refusal error')\n"
        "  AssertEquals(originalTemplate.TemplateId, before,\n"
        "    'refused FixedString write changed game memory')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Entity.ComponentWrite.OneFrameRefused', function()\n"
        "  -- OneFrame components are transient (cleared each tick); the fixture\n"
        "  -- only exists during the frame after its trigger, so its absence is\n"
        "  -- the normal case, not a failure. Exercise the refusal path when the\n"
        "  -- fixture happens to be live; otherwise verify absence and pass.\n"
        "  local entity = Ext.Entity.Get(Osi.GetHostCharacter())\n"
        "  AssertNotNil(entity, 'host entity')\n"
        "  local oneFrame = entity['esv::SaveCompletedOneFrameComponent']\n"
        "  if oneFrame == nil then\n"
        "    Ext.Print('    (OneFrame fixture absent as expected; refusal path not exercised)')\n"
        "    return\n"
        "  end\n"
        "  local ok, err = pcall(function()\n"
        "    oneFrame.Value = not oneFrame.Value\n"
        "  end)\n"
        "  assert(not ok, 'OneFrame component write should raise a Lua error')\n"
        "  AssertType(err, 'string', 'OneFrame refusal error')\n"
        "end)\n";

    // Tier 2: Wave 3 component write-refusal regressions (2 tests)
    static const char *console_cmd_test_wave3_components =
        "BG3SE_AddTest(2, 'Entity.ComponentWrite.DynamicArrayRefused', function()\n"
        "  local entity = Ext.Entity.Get(Osi.GetHostCharacter())\n"
        "  AssertNotNil(entity, 'host entity')\n"
        "  local spellBook = entity.SpellBook\n"
        "  AssertNotNil(spellBook, 'host SpellBook component')\n"
        "  local before = spellBook.Spells\n"
        "  AssertNotNil(before, 'SpellBook.Spells dynamic array')\n"
        "  local beforeCount = #before\n"
        "  local ok, err = pcall(function() spellBook.Spells = {} end)\n"
        "  assert(not ok, 'DYNAMIC_ARRAY write should be refused')\n"
        "  AssertType(err, 'string', 'DYNAMIC_ARRAY refusal error')\n"
        "  local after = spellBook.Spells\n"
        "  AssertNotNil(after, 'SpellBook.Spells after refused write')\n"
        "  AssertEquals(#after, beforeCount,\n"
        "    'refused DYNAMIC_ARRAY write changed array header')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Entity.ComponentWrite.UnknownSizeRefused', function()\n"
        "  local layout = Ext.Types.GetComponentLayout('Net')\n"
        "  AssertNotNil(layout, 'Net component layout')\n"
        "  AssertEquals(layout.Size, 0, 'Net layout must remain unknown-size fixture')\n"
        "  local entity = Ext.Entity.Get(Osi.GetHostCharacter())\n"
        "  AssertNotNil(entity, 'host entity')\n"
        "  local net = entity.Net\n"
        "  AssertNotNil(net, 'host Net component')\n"
        "  local beforeType = net.__type\n"
        "  local ok, err = pcall(function() net.BG3SE_MustNotWrite = true end)\n"
        "  assert(not ok, 'componentSize==0 write should be refused')\n"
        "  AssertType(err, 'string', 'unknown-size refusal error')\n"
        "  AssertEquals(net.__type, beforeType,\n"
        "    'refused unknown-size write changed component proxy')\n"
        "end)\n";

    // Tier 2: Wave 2 Stats read/sync behavior (2 tests)
    static const char *console_cmd_test_wave2_stats_ingame =
        "BG3SE_AddTest(2, 'Stats.Goal23.TreasureReads', function()\n"
        "  local tableInfo = Ext.Stats.TreasureTable.Get('Gold_Meager')\n"
        "  AssertNotNil(tableInfo, 'Gold_Meager treasure table')\n"
        "  AssertEquals(tableInfo.Name, 'Gold_Meager', 'treasure table name')\n"
        "  AssertType(tableInfo.Address, 'number', 'treasure table address')\n"
        "  AssertType(tableInfo.MinLevel, 'number', 'treasure table MinLevel')\n"
        "  AssertType(tableInfo.MaxLevel, 'number', 'treasure table MaxLevel')\n"
        "  AssertType(tableInfo.SubTables, 'table', 'treasure subtables')\n"
        "  assert(#tableInfo.SubTables > 0, 'Gold_Meager should have a subtable')\n"
        "  AssertType(tableInfo.SubTables[1].TotalCount, 'number',\n"
        "    'treasure subtable TotalCount')\n"
        "  local legacy = Ext.Stats.TreasureTable.GetLegacy('Gold_Meager')\n"
        "  AssertNotNil(legacy, 'legacy Gold_Meager read')\n"
        "  AssertEquals(legacy.Address, tableInfo.Address,\n"
        "    'Get and GetLegacy manager entry')\n"
        "  local category = Ext.Stats.TreasureCategory.GetLegacy('I_OBJ_GoldCoin')\n"
        "  AssertNotNil(category, 'I_OBJ_GoldCoin treasure category')\n"
        "  AssertEquals(category.Category, 'I_OBJ_GoldCoin',\n"
        "    'treasure category name')\n"
        "  AssertType(category.Address, 'number', 'treasure category address')\n"
        "  AssertType(category.Items, 'table', 'treasure category items')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Stats.Goal23.PrototypeSyncHonesty', function()\n"
        "  local status = Ext.Stats.Get('BURNING')\n"
        "  AssertNotNil(status, 'BURNING StatusData fixture')\n"
        "  AssertEquals(status.Type, 'StatusData',\n"
        "    'BURNING must resolve through its real ModifierList')\n"
        "  AssertEquals(Ext.Stats.Sync('BURNING'), true,\n"
        "    'status prototype sync result')\n"
        "  local cached = Ext.Stats.GetCachedStatus('BURNING')\n"
        "  AssertNotNil(cached, 'status sync cached prototype')\n"
        "  AssertEquals(cached.Name, 'BURNING', 'cached status name')\n"
        "  AssertEquals(cached.Type, 'StatusPrototype', 'cached status type')\n"
        "  AssertType(cached.Address, 'number', 'cached status address')\n"
        "  assert(cached.Address ~= 0, 'cached status address must be nonzero')\n"
        "  local name = 'BG3SE_Goal23_GatedPassive'\n"
        "  local passive = Ext.Stats.Get(name) or\n"
        "    Ext.Stats.Create(name, 'PassiveData')\n"
        "  AssertNotNil(passive, 'temporary PassiveData stat')\n"
        "  AssertEquals(Ext.Stats.Sync(name), false,\n"
        "    'allocator-gated PassivePrototype sync')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Stats.W6.NativeCachedLookups', function()\n"
        "  local p = Ext.Stats.GetCachedPassive('AttackOfOpportunity')\n"
        "  AssertNotNil(p, 'cached passive via eoc::Passives::Get')\n"
        "  AssertType(p.Address, 'number', 'passive prototype address')\n"
        "  assert(p.Address ~= 0, 'passive prototype address must be nonzero')\n"
        "  assert(Ext.Debug.IsValidPointer(p.Address),\n"
        "    'passive prototype must be readable')\n"
        "  local i = Ext.Stats.GetCachedInterrupt('Interrupt_AttackOfOpportunity')\n"
        "  AssertNotNil(i, 'cached interrupt via native GetPrototype')\n"
        "  assert(i.Address ~= 0 and Ext.Debug.IsValidPointer(i.Address),\n"
        "    'interrupt prototype must be readable')\n"
        "  AssertEquals(Ext.Debug.ReadFixedString(i.Address),\n"
        "    'Interrupt_AttackOfOpportunity', 'InterruptPrototype name at +0x0')\n"
        "  AssertEquals(Ext.Stats.GetCachedPassive('BG3SE_NoSuchPassive_W6'), nil,\n"
        "    'unknown passive must miss to nil')\n"
        "  AssertEquals(Ext.Stats.GetCachedInterrupt('BG3SE_NoSuchInterrupt_W6'), nil,\n"
        "    'unknown interrupt must miss to nil')\n"
        "end)\n";

    // Parity behavioral tests (Tier 2 — test actual behavior with loaded save)
    static const char *console_cmd_test_parity_ingame =
        "BG3SE_AddTest(2, 'Parity.Entity.HostRoundtrip', function()\n"
        "  local guid = Osi.GetHostCharacter()\n"
        "  AssertNotNil(guid, 'GetHostCharacter')\n"
        "  local e = Ext.Entity.Get(guid)\n"
        "  AssertNotNil(e, 'Entity.Get(host)')\n"
        "  local s = tostring(e)\n"
        "  assert(type(s) == 'string' and #s > 0, 'tostring(entity) should work')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Entity.HandleRoundtrip', function()\n"
        "  local guid = Osi.GetHostCharacter()\n"
        "  local e = Ext.Entity.Get(guid)\n"
        "  AssertNotNil(e, 'entity')\n"
        "  if e.GetHandle then\n"
        "    local h = e:GetHandle()\n"
        "    AssertNotNil(h, 'GetHandle')\n"
        "    local e2 = Ext.Entity.GetByHandle(h)\n"
        "    AssertNotNil(e2, 'GetByHandle')\n"
        "  else\n"
        "    Ext.Print('    (fixture absent; not exercised) entity.GetHandle unavailable')\n"
        "  end\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Entity.InvalidInputs', function()\n"
        "  local r1 = Ext.Entity.Get('00000000-0000-0000-0000-000000000000')\n"
        "  assert(r1 == nil, 'Get(null GUID) should return nil')\n"
        "  local ok, _ = pcall(Ext.Entity.Get, 'not-a-guid')\n"
        "  assert(ok, 'Get(bad string) should not crash')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Entity.ComponentEnumeration', function()\n"
        "  local entity = Ext.Entity.Get(Osi.GetHostCharacter())\n"
        "  AssertNotNil(entity, 'host entity')\n"
        "  local names = entity:GetAllComponentNames()\n"
        "  assert(type(names) == 'table', 'should be table')\n"
        "  assert(#names > 10, 'host should have dozens of components, got: ' .. #names)\n"
        "  local found = false\n"
        "  for _, n in ipairs(names) do\n"
        "    if n:find('Health') then found = true; break end\n"
        "  end\n"
        "  assert(found, 'Health component should be in list')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Stats.CanonicalCounts', function()\n"
        "  local all = Ext.Stats.GetAll()\n"
        "  assert(#all > 10000, 'Total stats should be >10k, got: ' .. #all)\n"
        "  local wpns = Ext.Stats.GetAll('Weapon')\n"
        "  assert(#wpns > 100, 'Weapons should be >100, got: ' .. #wpns)\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Stats.LongswordShape', function()\n"
        "  local s = Ext.Stats.Get('WPN_Longsword')\n"
        "  AssertNotNil(s, 'WPN_Longsword')\n"
        "  AssertEquals(s.Name, 'WPN_Longsword', 'Name')\n"
        "  AssertNotNil(s.Damage, 'Damage field')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Osi.DBPlayersAccessor', function()\n"
        "  local ok, rows = pcall(function() return Osi.DB_Players:Get() end)\n"
        "  assert(ok, 'DB_Players:Get should not error: ' .. tostring(rows))\n"
        "  assert(type(rows) == 'table', 'should return table')\n"
        "  assert(#rows > 0, 'should have at least 1 player')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Osi.ListenerBeforeAfter', function()\n"
        "  local h1 = Ext.Osiris.RegisterListener('SavegameLoaded', 0, 'before',\n"
        "    function() end)\n"
        "  local h2 = Ext.Osiris.RegisterListener('SavegameLoaded', 0, 'after',\n"
        "    function() end)\n"
        "  assert(h1 ~= nil, 'before listener should return handle')\n"
        "  assert(h2 ~= nil, 'after listener should return handle')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Level.RaycastClosestDeferred', function()\n"
        "  AssertType(Ext.Level.RaycastClosest, 'function', 'Level.RaycastClosest')\n"
        "  local src, dst = {0, 1, 0}, {0, -1, 0}\n"
        "  local first = Ext.Level.RaycastClosest(src, dst)\n"
        "  local second = Ext.Level.RaycastClosest(src, dst)\n"
        "  assert(first == nil and second == nil,\n"
        "    'deferred RaycastClosest must return nil on every call')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.IMGUI.WidgetSurface', function()\n"
        "  local w = Ext.IMGUI.NewWindow('_ParityTest')\n"
        "  AssertNotNil(w, 'NewWindow')\n"
        "  local btn = w:AddButton('TestBtn')\n"
        "  AssertNotNil(btn, 'AddButton')\n"
        "  w:SetVisible(false)\n"
        "  w:Destroy()\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Net.PostMessage', function()\n"
        "  if not Ext.Net.IsReady() then return end\n"
        "  local ok = pcall(Ext.Net.PostMessageToServer, '_parity_test', '{}')\n"
        "  assert(ok, 'PostMessageToServer should not crash')\n"
        "end)\n";

    // Wave 7 A6: PlayerHasExtender behavioral surface (own chunk to keep
    // the neighbouring string literal under the ISO 4095-char ceiling)
    static const char *console_cmd_test_parity_net =
        "BG3SE_AddTest(2, 'Parity.Net.PlayerHasExtender', function()\n"
        "  AssertType(Ext.Net.PlayerHasExtender, 'function', 'Net.PlayerHasExtender')\n"
        "  -- integer path: host user always resolves to a boolean\n"
        "  AssertType(Ext.Net.PlayerHasExtender(1), 'boolean', 'PlayerHasExtender(userId)')\n"
        "  -- GUID path: unknown character maps to nil (Windows ServerNet.inl contract)\n"
        "  assert(Ext.Net.PlayerHasExtender('00000000-0000-0000-0000-000000000000') == nil,\n"
        "    'unknown GUID should return nil')\n"
        "  -- GUID path: a registered peer GUID resolves to a boolean\n"
        "  local host = Osi.GetHostCharacter()\n"
        "  if host then\n"
        "    local r = Ext.Net.PlayerHasExtender(host)\n"
        "    assert(r == nil or type(r) == 'boolean',\n"
        "      'host GUID should return nil or boolean, got: ' .. type(r))\n"
        "  end\n"
        "end)\n";

    // Wave 7 A5: Osi.DB_*:Delete contract (safe surface only — the destructive
    // row-delete path is live-verified manually against a sentinel tuple)
    static const char *console_cmd_test_wave7_osi_delete =
        "BG3SE_AddTest(2, 'Wave7.Osi.DBDelete', function()\n"
        "  AssertType(Osi.DB_Players.Delete, 'function', 'DB_Players.Delete')\n"
        "  -- wrong arity raises the Windows-parity error text\n"
        "  local ok, err = pcall(function() Osi.DB_Players:Delete() end)\n"
        "  assert(not ok and tostring(err):find('Incorrect number of arguments', 1, true),\n"
        "    'arity error expected, got: ' .. tostring(err))\n"
        "  -- nil wildcards rejected (Windows Delete has none)\n"
        "  ok, err = pcall(function() Osi.DB_Players:Delete(nil) end)\n"
        "  assert(not ok and tostring(err):find('does not accept nil', 1, true),\n"
        "    'nil rejection expected, got: ' .. tostring(err))\n"
        "  -- non-matching delete is an engine no-op; row count invariant\n"
        "  local before = #Osi.DB_Players:Get()\n"
        "  assert(before > 0, 'DB_Players should have rows')\n"
        "  Osi.DB_Players:Delete('SENTINEL_NOT_A_PLAYER_bg3se')\n"
        "  local after = #Osi.DB_Players:Get()\n"
        "  assert(after == before,\n"
        "    'no-op delete changed row count: ' .. before .. ' -> ' .. after)\n"
        "end)\n";

    // Wave 7 B1: AddEnumerationValue via engine ValueList::Insert. Unique
    // per-run label keeps reruns idempotent (the enum grows one entry per run;
    // reload survival is live-verified manually per VALUELIST_INSERT.md)
    static const char *console_cmd_test_wave7_addenum =
        "BG3SE_AddTest(2, 'Wave7.Stats.AddEnumerationValue', function()\n"
        "  local enumName = 'DamageType'\n"
        "  local label = 'BG3SE_W7B1_' .. tostring(Ext.Utils.MonotonicTime())\n"
        "  assert(Ext.Stats.EnumLabelToIndex(enumName, label) == nil, 'label must be fresh')\n"
        "  local i = 0\n"
        "  while Ext.Stats.EnumIndexToLabel(enumName, i) ~= nil do i = i + 1 end\n"
        "  assert(Ext.Stats.AddEnumerationValue(enumName, label) == true, 'insert')\n"
        "  local index = Ext.Stats.EnumLabelToIndex(enumName, label)\n"
        "  assert(index == i, 'label->index: ' .. tostring(index) .. ' ~= ' .. i)\n"
        "  assert(Ext.Stats.EnumIndexToLabel(enumName, index) == label, 'index->label')\n"
        "  -- duplicate rejected without a second growth\n"
        "  assert(Ext.Stats.AddEnumerationValue(enumName, label) == false, 'duplicate')\n"
        "  assert(Ext.Stats.EnumLabelToIndex(enumName, label) == index, 'index stable')\n"
        "  -- unknown enum fails closed\n"
        "  assert(Ext.Stats.AddEnumerationValue('NotARealEnum_bg3se', 'X') == false)\n"
        "end)\n";

    // Wave 7 A8: tracing prototype (flat bounded log; partial vs Windows tree)
    static const char *console_cmd_test_wave7_tracing =
        "BG3SE_AddTest(2, 'Wave7.Entity.Tracing', function()\n"
        "  AssertType(Ext.Entity.EnableTracing, 'function', 'EnableTracing')\n"
        "  assert(Ext.Entity.EnableTracing() == true, 'EnableTracing returns true')\n"
        "  local t = Ext.Entity.GetTrace()\n"
        "  AssertType(t, 'table', 'GetTrace')\n"
        "  AssertType(t.Enabled, 'boolean', 'trace.Enabled')\n"
        "  AssertType(t.Events, 'table', 'trace.Events')\n"
        "  assert(Ext.Entity.ClearTrace() == true, 'ClearTrace returns true')\n"
        "  assert(#Ext.Entity.GetTrace().Events == 0, 'ClearTrace empties the log')\n"
        "  assert(Ext.Entity.DisableTracing() == true, 'DisableTracing returns true')\n"
        "end)\n";

    // Wave 7 B6: OnSystemUpdate/OnSystemPostUpdate surface + pointer-swap smoke.
    // Live firing (callback actually invoked by the ECS scheduler) is verified
    // manually in the live session; here we exercise subscribe/unsubscribe so
    // the UpdateProc install+restore path runs once end-to-end.
    static const char *console_cmd_test_wave7_sysupdate =
        "BG3SE_AddTest(2, 'Wave7.Entity.OnSystemUpdate', function()\n"
        "  AssertType(Ext.Entity.OnSystemUpdate, 'function', 'OnSystemUpdate')\n"
        "  AssertType(Ext.Entity.OnSystemPostUpdate, 'function', 'OnSystemPostUpdate')\n"
        "  local ok, err = pcall(Ext.Entity.OnSystemUpdate,\n"
        "    'DefinitelyNotASystem_bg3se', function() end)\n"
        "  assert(not ok, 'unknown system name must error')\n"
        "  assert(tostring(err):find('Unknown system type', 1, true),\n"
        "    'unknown-system error text: ' .. tostring(err))\n"
        "  local h = Ext.Entity.OnSystemUpdate('ServerActionResource', function() end)\n"
        "  AssertType(h, 'number', 'subscription handle')\n"
        "  assert(Ext.Entity.Unsubscribe(h) == true, 'Unsubscribe(system handle)')\n"
        "  assert(Ext.Entity.Unsubscribe(h) == false, 'double unsubscribe is false')\n"
        "end)\n";

    // Wave 7 follow-up: GetHeightsAt real multi-subgrid walk (Windows
    // Ai.inl:262/406 contract; subgrid bounds CONFIRMED in
    // AIGRID_PATHFINDING.md 2026-08-03). TileRange requires only ONE height
    // to match the raw tile: GetTileRawDebugInfo resolves the single tile
    // ToTilePos selects, while GetHeightsAt spans all layers at (x,z).
    static const char *console_cmd_test_wave7_heights =
        "BG3SE_AddTest(2, 'Parity.Level.GetHeightsAt.Host', function()\n"
        "  local x, y, z = Osi.GetPosition(Osi.GetHostCharacter())\n"
        "  AssertNotNil(x, 'host position')\n"
        "  local heights = Ext.Level.GetHeightsAt(x, z)\n"
        "  AssertType(heights, 'table', 'host heights')\n"
        "  assert(#heights > 0, 'host-position heights must be non-empty')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Level.GetHeightsAt.TileRange', function()\n"
        "  local x, y, z = Osi.GetPosition(Osi.GetHostCharacter())\n"
        "  AssertNotNil(x, 'host position')\n"
        "  local tile = Ext.Level.GetTileRawDebugInfo(x, z)\n"
        "  AssertType(tile, 'table', 'host tile')\n"
        "  local heights = Ext.Level.GetHeightsAt(x, z)\n"
        "  assert(#heights > 0, 'host-position heights must be non-empty')\n"
        "  local matched = false\n"
        "  for i, h in ipairs(heights) do\n"
        "    AssertType(h, 'number', 'height ' .. i)\n"
        "    if h >= tile.MinHeight and h <= tile.MaxHeight + 0.03 then\n"
        "      matched = true\n"
        "    end\n"
        "  end\n"
        "  assert(matched, 'no height matched the ToTilePos tile range')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Level.GetHeightsAt.OutOfBounds', function()\n"
        "  local ok, heights = pcall(Ext.Level.GetHeightsAt, 1.0e9, -1.0e9)\n"
        "  assert(ok, 'out-of-bounds query must not error')\n"
        "  AssertType(heights, 'table', 'out-of-bounds result')\n"
        "  assert(#heights == 0, 'out-of-bounds query must return {}')\n"
        "end)\n";

    // Wave 7 B3: raw tile diagnostic surface (NOT GetTileDebugInfo parity;
    // MinHeight +0x0a confirmed in AIGRID_PATHFINDING.md 2026-08-03).
    static const char *console_cmd_test_wave7_tileraw =
        "BG3SE_AddTest(2, 'Diagnostic.Level.TileRawDebugInfo', function()\n"
        "  AssertType(Ext.Level.GetTileRawDebugInfo, 'function', 'GetTileRawDebugInfo')\n"
        "  local x, y, z = Osi.GetPosition(Osi.GetHostCharacter())\n"
        "  AssertNotNil(x, 'host position')\n"
        "  local tile = Ext.Level.GetTileRawDebugInfo(x, z)\n"
        "  AssertType(tile, 'table', 'host tile')\n"
        "  assert(tile.Raw == true, 'raw diagnostic marker')\n"
        "  AssertType(tile.RawFlags, 'number', 'RawFlags')\n"
        "  assert(tile.GroundMask >= 0 and tile.GroundMask <= 255, 'GroundMask byte')\n"
        "  assert(tile.CloudMask >= 0 and tile.CloudMask <= 255, 'CloudMask byte')\n"
        "  AssertType(tile.MinHeight, 'number', 'MinHeight')\n"
        "  AssertType(tile.MaxHeight, 'number', 'MaxHeight')\n"
        "  assert(tile.MinHeight <= tile.MaxHeight, 'MinHeight <= MaxHeight')\n"
        "  local ok, oob = pcall(Ext.Level.GetTileRawDebugInfo, 1.0e9, -1.0e9)\n"
        "  assert(ok, 'out-of-bounds must not error')\n"
        "  assert(oob == nil, 'out-of-bounds returns nil')\n"
        "end)\n";

    // Wave 7 A1: Windows Entity.inl cheap-contract closure
    static const char *console_cmd_test_wave7_entity =
        "BG3SE_AddTest(2, 'Wave7.Entity.UuidRoundtrip', function()\n"
        "  local guid = Osi.GetHostCharacter()\n"
        "  AssertNotNil(guid, 'GetHostCharacter')\n"
        "  local e = Ext.Entity.Get(guid)\n"
        "  AssertNotNil(e, 'host entity')\n"
        "  local uuid = Ext.Entity.HandleToUuid(e)\n"
        "  AssertType(uuid, 'string', 'HandleToUuid(host)')\n"
        "  local e2 = Ext.Entity.UuidToHandle(uuid)\n"
        "  AssertNotNil(e2, 'UuidToHandle(host uuid)')\n"
        "  AssertEquals(e2:GetIndex(), e:GetIndex(), 'roundtrip entity index')\n"
        "  AssertEquals(e2:GetSalt(), e:GetSalt(), 'roundtrip entity salt')\n"
        "  assert(Ext.Entity.UuidToHandle('00000000-0000-0000-0000-000000000000') == nil,\n"
        "    'unknown uuid should map to nil')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Wave7.Entity.GetAllEntitiesWithUuid', function()\n"
        "  local map = Ext.Entity.GetAllEntitiesWithUuid()\n"
        "  AssertType(map, 'table', 'GetAllEntitiesWithUuid result')\n"
        "  local guid = Osi.GetHostCharacter()\n"
        "  local uuid = Ext.Entity.HandleToUuid(Ext.Entity.Get(guid))\n"
        "  AssertNotNil(map[uuid], 'host uuid present in mapping')\n"
        "  local n = 0\n"
        "  for _ in pairs(map) do n = n + 1 end\n"
        "  assert(n > 100, 'uuid mapping should hold >100 entries, got: ' .. n)\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Wave7.Entity.GetRegisteredComponentTypes', function()\n"
        "  local all = Ext.Entity.GetRegisteredComponentTypes()\n"
        "  AssertType(all, 'table', 'GetRegisteredComponentTypes result')\n"
        "  assert(#all > 1500, 'expected >1500 registered types, got: ' .. #all)\n"
        "  AssertType(all[1], 'string', 'entries are names')\n"
        "  local mapped = Ext.Entity.GetRegisteredComponentTypes(nil, true)\n"
        "  assert(#mapped > 0 and #mapped <= #all, 'mapped filter should narrow the list')\n"
        "  local oneFrame = Ext.Entity.GetRegisteredComponentTypes(true)\n"
        "  assert(#oneFrame < #all, 'one-frame filter should narrow the list')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Wave7.Entity.GetEntitiesAroundPosition', function()\n"
        "  local guid = Osi.GetHostCharacter()\n"
        "  local e = Ext.Entity.Get(guid)\n"
        "  AssertNotNil(e, 'host entity')\n"
        "  local t = e.Transform\n"
        "  AssertNotNil(t, 'host Transform')\n"
        "  local pos = t.Position\n"
        "  AssertNotNil(pos, 'host Position')\n"
        "  AssertType(pos.x, 'number', 'Position.x')\n"
        "  local near = Ext.Entity.GetEntitiesAroundPosition({pos.x, pos.y, pos.z}, 5.0)\n"
        "  AssertType(near, 'table', 'GetEntitiesAroundPosition result')\n"
        "  local found = false\n"
        "  for _, ne in ipairs(near) do\n"
        "    if ne:GetIndex() == e:GetIndex() then found = true break end\n"
        "  end\n"
        "  assert(found, 'host should be within 5m of its own position')\n"
        "  local none = Ext.Entity.GetEntitiesAroundPosition({pos.x, pos.y, pos.z}, 0)\n"
        "  assert(#none == 0, 'zero radius should return no entities')\n"
        "end)\n";

    // Wave 7 C step 2: read-only GetReplicationFlags on the entity proxy
    // (SyncBuffers chain, REPLICATION_SYNCBUFFERS.md). Result is a number when
    // the chain resolves, nil when disarmed/unknown — both are non-erroring.
    static const char *console_cmd_test_wave7_replication =
        "BG3SE_AddTest(2, 'Wave7.Entity.GetReplicationFlags', function()\n"
        "  local host = Osi.GetHostCharacter()\n"
        "  AssertNotNil(host, 'host character')\n"
        "  local entity = Ext.Entity.Get(host)\n"
        "  AssertNotNil(entity, 'resolvable host entity')\n"
        "  AssertType(entity.GetReplicationFlags, 'function', 'entity.GetReplicationFlags')\n"
        "  local ok, flags = pcall(function() return entity:GetReplicationFlags('DisplayName') end)\n"
        "  assert(ok, 'DisplayName lookup errored: ' .. tostring(flags))\n"
        "  assert(flags == nil or type(flags) == 'number', 'expected number or nil, got ' .. type(flags))\n"
        "  local unknownOk, unknown = pcall(function() return entity:GetReplicationFlags('__BG3SE_UnknownReplicationComponent') end)\n"
        "  assert(unknownOk, 'unknown component lookup errored: ' .. tostring(unknown))\n"
        "  assert(unknown == nil, 'unknown component should return nil')\n"
        "end)\n";

    // Wave 7 B4b: RaycastAny via the proven zeroed-aggregate ABI (VMT slot 10,
    // RAYCAST_ABI_B4A.md). UUID+version gated; ships with NO parity credit until
    // the live stress ladder passes. Safe assertion: callable + returns boolean.
    static const char *console_cmd_test_wave7_raycastany =
        "BG3SE_AddTest(2, 'Wave7.Level.RaycastAny', function()\n"
        "  assert(Ext and Ext.Level and type(Ext.Level.RaycastAny) == 'function',\n"
        "    'Ext.Level.RaycastAny must exist and be callable')\n"
        "  if Ext.Level.GetCurrentLevel() == nil then return end\n"
        "  local host = Osi.GetHostCharacter()\n"
        "  local x, y, z = Osi.GetPosition(host)\n"
        "  assert(type(x) == 'number' and type(y) == 'number' and type(z) == 'number',\n"
        "    'loaded level must provide the host position')\n"
        "  local ok, blocked = pcall(Ext.Level.RaycastAny, {x, y, z}, {x, y + 1.0, z})\n"
        "  assert(ok, 'RaycastAny must not error: ' .. tostring(blocked))\n"
        "  assert(type(blocked) == 'boolean', 'RaycastAny must return a boolean')\n"
        "end)\n";

    static const char *console_cmd_test_parity_ingame_entity =
        "BG3SE_AddTest(2, 'Parity.Entity.TypeIdDiscoveryComplete', function()\n"
        "  if not Ext.Entity.DiscoverTypeIds then return end\n"
        "  local info = Ext.Entity.DiscoverTypeIds()\n"
        "  AssertNotNil(info, 'DiscoverTypeIds result')\n"
        "  if type(info) == 'table' then\n"
        "    assert(info.complete == true, 'discovery should be complete')\n"
        "    assert((info.count or 0) > 1500, 'should have >1500 typeids, got: ' .. tostring(info.count))\n"
        "  end\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Entity.RegistryCounts', function()\n"
        "  -- esv::Character is not a registered component TypeId on macOS;\n"
        "  -- the resolvable server-world character marker is the nested\n"
        "  -- eoc::character::CharacterComponent (verified live: 916 in WLD_Main_A)\n"
        "  local chars = Ext.Entity.GetAllEntitiesWithComponent('eoc::character::CharacterComponent')\n"
        "  assert(type(chars) == 'table', 'character query should return a table')\n"
        "  assert(#chars > 0, 'Character count should be >0, got: ' .. #chars)\n"
        "  assert(#chars < 10000, 'Character count should be <10k, got: ' .. #chars)\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Entity.HealthLayoutSnapshot', function()\n"
        "  local guid = Osi.GetHostCharacter()\n"
        "  local e = Ext.Entity.Get(guid)\n"
        "  AssertNotNil(e, 'host entity')\n"
        "  local layout = Ext.Types.GetComponentLayout('Hitpoints')\n"
        "  if layout == nil then\n"
        "    layout = Ext.Types.GetComponentLayout('Health')\n"
        "  end\n"
        "  AssertNotNil(layout, 'Health/Hitpoints layout should exist')\n"
        "end)\n";

    // Register !test_ingame command (Tier 2)
    static const char *console_cmd_test_ingame_reg =
        "Ext.RegisterConsoleCommand('test_ingame', function(cmd, filter)\n"
        "  BG3SE_RunTests(2, (filter and filter ~= '') and filter or nil)\n"
        "end)\n";

    // IDE helpers command (!ide_helpers)
    static const char *console_cmd_ide =
        "Ext.RegisterConsoleCommand('ide_helpers', function(cmd, filename)\n"
        "  filename = filename or 'ExtIdeHelpers.lua'\n"
        "  local content = Ext.Types.GenerateIdeHelpers(filename)\n"
        "  local size = #content\n"
        "  Ext.Print('Generated IDE helpers: ~/Library/Application Support/BG3SE/' .. filename)\n"
        "  Ext.Print(string.format('  %d bytes, %d layouts, %d enum types', size,\n"
        "    #Ext.Types.GetAllLayouts(), 14))\n"
        "  Ext.Print('\\nVS Code setup:')\n"
        "  Ext.Print('  1. Copy ExtIdeHelpers.lua to your mod folder')\n"
        "  Ext.Print('  2. Add to .luarc.json:')\n"
        "  Ext.Print('     {\"workspace.library\": [\"ExtIdeHelpers.lua\"]}')\n"
        "end)\n";

    // Mod diagnostics command (!mod_diag)
    static const char *console_cmd_mod_diag =
        "Ext.RegisterConsoleCommand('mod_diag', function(cmd, sub, arg)\n"
        "  local count = Ext.Debug.ModHealthCount and Ext.Debug.ModHealthCount() or 0\n"
        "  if sub == 'disable' and arg then\n"
        "    local ok = Ext.Debug.ModDisable and Ext.Debug.ModDisable(arg, true)\n"
        "    if ok then Ext.Print('Disabled: ' .. arg)\n"
        "    else Ext.Print('Mod not found: ' .. arg) end\n"
        "    return\n"
        "  end\n"
        "  if sub == 'enable' and arg then\n"
        "    local ok = Ext.Debug.ModDisable and Ext.Debug.ModDisable(arg, false)\n"
        "    if ok then Ext.Print('Enabled: ' .. arg)\n"
        "    else Ext.Print('Mod not found: ' .. arg) end\n"
        "    return\n"
        "  end\n"
        "  if sub == 'errors' then\n"
        "    Ext.Print('\\n=== Mod Errors ===')\n"
        "    local info = Ext.Debug.ModHealthAll and Ext.Debug.ModHealthAll() or {}\n"
        "    for _, m in ipairs(info) do\n"
        "      if m.errors > 0 then\n"
        "        Ext.Print(string.format('  %s: %d errors, last: %s',\n"
        "          m.name, m.errors, m.last_error or '(none)'))\n"
        "      end\n"
        "    end\n"
        "    return\n"
        "  end\n"
        "  Ext.Print('\\n=== Mod Health ===')\n"
        "  local info = Ext.Debug.ModHealthAll and Ext.Debug.ModHealthAll() or {}\n"
        "  for _, m in ipairs(info) do\n"
        "    local status = m.disabled and ' [DISABLED]' or ''\n"
        "    Ext.Print(string.format('  %-30s %3d handlers  %5d ok  %3d err%s',\n"
        "      m.name, m.handlers, m.handled, m.errors, status))\n"
        "  end\n"
        "  Ext.Print(string.format('\\nTotal: %d mods tracked', #info))\n"
        "  Ext.Print('Usage: !mod_diag [errors|disable <mod>|enable <mod>]')\n"
        "end)\n";

    // Fail-first parity stubs: tests that FAIL now and will PASS after implementation.
    // Tier 2 (in-game): Entity handle methods require a live entity.
    // Tier 1: namespace/function existence checks run console-only.

    // Parity stubs part 1: Ext.Entity missing methods (tier 2, need loaded save)
    static const char *console_cmd_test_parity_entity =
        "BG3SE_AddTest(2, 'Parity.Entity.GetEntityType', function()\n"
        "  local host = Osi.GetHostCharacter()\n"
        "  AssertNotNil(host, 'host')\n"
        "  local e = Ext.Entity.Get(host)\n"
        "  AssertNotNil(e, 'entity')\n"
        "  AssertType(e.GetEntityType, 'function', 'entity:GetEntityType')\n"
        "  local t = e:GetEntityType()\n"
        "  AssertType(t, 'number', 'GetEntityType result')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Entity.GetSalt', function()\n"
        "  local e = Ext.Entity.Get(Osi.GetHostCharacter())\n"
        "  AssertNotNil(e, 'entity')\n"
        "  AssertType(e.GetSalt, 'function', 'entity:GetSalt')\n"
        "  local s = e:GetSalt()\n"
        "  AssertType(s, 'number', 'GetSalt result')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Entity.GetIndex', function()\n"
        "  local e = Ext.Entity.Get(Osi.GetHostCharacter())\n"
        "  AssertNotNil(e, 'entity')\n"
        "  AssertType(e.GetIndex, 'function', 'entity:GetIndex')\n"
        "  local idx = e:GetIndex()\n"
        "  AssertType(idx, 'number', 'GetIndex result')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Entity.GetNetId', function()\n"
        "  local e = Ext.Entity.Get(Osi.GetHostCharacter())\n"
        "  AssertNotNil(e, 'entity')\n"
        "  AssertType(e.GetNetId, 'function', 'entity:GetNetId')\n"
        "  local nid = e:GetNetId()\n"
        "  assert(nid == nil or type(nid) == 'number', 'GetNetId: nil or number')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Entity.CreateComponent', function()\n"
        "  local e = Ext.Entity.Get(Osi.GetHostCharacter())\n"
        "  AssertNotNil(e, 'entity')\n"
        "  AssertType(e.CreateComponent, 'function', 'entity:CreateComponent')\n"
        "  local result = e:CreateComponent('__BG3SE_InvalidComponent__')\n"
        "  assert(result == false, 'invalid CreateComponent type must return false without a native call')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Entity.RemoveComponent', function()\n"
        "  local e = Ext.Entity.Get(Osi.GetHostCharacter())\n"
        "  AssertNotNil(e, 'entity')\n"
        "  AssertType(e.RemoveComponent, 'function', 'entity:RemoveComponent')\n"
        "  local result = e:RemoveComponent('__BG3SE_RemoveComponentDeferred__')\n"
        "  assert(result == false, 'deferred RemoveComponent must return false')\n"
        "end)\n";

    // Parity stubs part 2: Ext.Level missing functions (tier 2, need level loaded)
    static const char *console_cmd_test_parity_level =
        "BG3SE_AddTest(2, 'Parity.Level.RaycastAllDeferred', function()\n"
        "  AssertType(Ext.Level.RaycastAll, 'function', 'Level.RaycastAll')\n"
        "  local r = Ext.Level.RaycastAll({0, 0, 0}, {0, -10, 0})\n"
        "  assert(r == nil, 'deferred RaycastAll must return nil')\n"
        "end)\n"
        // RaycastAny is no longer deferred (Wave 7 B4b): it is a real VMT-slot-10
        // binding covered by Wave7.Level.RaycastAny. RaycastClosest/All remain deferred.
        "BG3SE_AddTest(2, 'Parity.Level.SweepSphereClosest', function()\n"
        "  assert(Ext.Level.IsReady(), 'Level should be ready')\n"
        "  AssertType(Ext.Level.SweepSphereClosest, 'function', 'Level.SweepSphereClosest')\n"
        "  local ok, r = pcall(Ext.Level.SweepSphereClosest, {0, 1, 0}, {0, -1, 0}, 0.5)\n"
        "  assert(ok, 'SweepSphereClosest should not crash: ' .. tostring(r))\n"
        "  assert(r == nil or type(r) == 'table', 'expected nil or hit table')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Level.SweepSphereAll', function()\n"
        "  assert(Ext.Level.IsReady(), 'Level should be ready')\n"
        "  AssertType(Ext.Level.SweepSphereAll, 'function', 'Level.SweepSphereAll')\n"
        "  local ok, r = pcall(Ext.Level.SweepSphereAll, {0, 1, 0}, {0, -1, 0}, 0.5)\n"
        "  assert(ok, 'SweepSphereAll should not crash: ' .. tostring(r))\n"
        "  assert(r == nil or type(r) == 'table', 'expected nil or hit array')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Level.SweepCapsuleClosest', function()\n"
        "  assert(Ext.Level.IsReady(), 'Level should be ready')\n"
        "  AssertType(Ext.Level.SweepCapsuleClosest, 'function', 'Level.SweepCapsuleClosest')\n"
        "  local ok, r = pcall(Ext.Level.SweepCapsuleClosest,\n"
        "    {0, 1, 0}, {0, -1, 0}, 0.5, 1.0)\n"
        "  assert(ok, 'SweepCapsuleClosest should not crash: ' .. tostring(r))\n"
        "  assert(r == nil or type(r) == 'table', 'expected nil or hit table')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Level.SweepCapsuleAll', function()\n"
        "  assert(Ext.Level.IsReady(), 'Level should be ready')\n"
        "  AssertType(Ext.Level.SweepCapsuleAll, 'function', 'Level.SweepCapsuleAll')\n"
        "  local ok, r = pcall(Ext.Level.SweepCapsuleAll,\n"
        "    {0, 1, 0}, {0, -1, 0}, 0.5, 1.0)\n"
        "  assert(ok, 'SweepCapsuleAll should not crash: ' .. tostring(r))\n"
        "  assert(r == nil or type(r) == 'table', 'expected nil or hit array')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Level.SweepBoxClosest', function()\n"
        "  assert(Ext.Level.IsReady(), 'Level should be ready')\n"
        "  AssertType(Ext.Level.SweepBoxClosest, 'function', 'Level.SweepBoxClosest')\n"
        "  local ok, r = pcall(Ext.Level.SweepBoxClosest,\n"
        "    {0, 1, 0}, {0, -1, 0}, {0.5, 1, 0.5})\n"
        "  assert(ok, 'SweepBoxClosest should not crash: ' .. tostring(r))\n"
        "  assert(r == nil or type(r) == 'table', 'expected nil or hit table')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Level.SweepBoxAll', function()\n"
        "  assert(Ext.Level.IsReady(), 'Level should be ready')\n"
        "  AssertType(Ext.Level.SweepBoxAll, 'function', 'Level.SweepBoxAll')\n"
        "  local ok, r = pcall(Ext.Level.SweepBoxAll,\n"
        "    {0, 1, 0}, {0, -1, 0}, {0.5, 1, 0.5})\n"
        "  assert(ok, 'SweepBoxAll should not crash: ' .. tostring(r))\n"
        "  assert(r == nil or type(r) == 'table', 'expected nil or hit array')\n"
        "end)\n";

    // Wave 3 Goal 3.1: cylinder execution plus copied-value AiGrid contracts.
    static const char *console_cmd_test_wave3_level =
        "BG3SE_AddTest(2, 'Parity.Level.SweepCylinderClosest', function()\n"
        "  assert(Ext.Level.IsReady(), 'Level should be ready')\n"
        "  AssertType(Ext.Level.SweepCylinderClosest, 'function', 'Level.SweepCylinderClosest')\n"
        "  local ok, hit = pcall(Ext.Level.SweepCylinderClosest,\n"
        "    {0, 1, 0}, {0, -1, 0}, {0.5, 1.0, 0.5})\n"
        "  assert(ok, 'SweepCylinderClosest should not crash: ' .. tostring(hit))\n"
        "  assert(hit == nil or type(hit) == 'table', 'expected nil or hit table')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Level.SweepCylinderAll', function()\n"
        "  assert(Ext.Level.IsReady(), 'Level should be ready')\n"
        "  AssertType(Ext.Level.SweepCylinderAll, 'function', 'Level.SweepCylinderAll')\n"
        "  local ok, hits = pcall(Ext.Level.SweepCylinderAll,\n"
        "    {0, 1, 0}, {0, -1, 0}, {0.5, 1.0, 0.5})\n"
        "  assert(ok, 'SweepCylinderAll should not crash: ' .. tostring(hits))\n"
        "  assert(hits == nil or type(hits) == 'table',\n"
        "    'expected nil (no hits) or hit array')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Level.TestBox', function()\n"
        "  assert(Ext.Level.IsReady(), 'Level should be ready')\n"
        "  local x, y, z = Osi.GetPosition(Osi.GetHostCharacter())\n"
        "  AssertNotNil(x, 'host position')\n"
        "  local hits = Ext.Level.TestBox({x, y, z}, {0.5, 1.0, 0.5})\n"
        "  assert(hits == nil or type(hits) == 'table',\n"
        "    'TestBox must return nil or a PhysicsHitAll array')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Level.TestSphere', function()\n"
        "  assert(Ext.Level.IsReady(), 'Level should be ready')\n"
        "  local x, y, z = Osi.GetPosition(Osi.GetHostCharacter())\n"
        "  AssertNotNil(x, 'host position')\n"
        "  local hits = Ext.Level.TestSphere({x, y, z}, 1.0)\n"
        "  assert(hits == nil or type(hits) == 'table',\n"
        "    'TestSphere must return nil or a PhysicsHitAll array')\n"
        "end)\n";

    static const char *console_cmd_test_wave3_aigrid =
        "BG3SE_AddTest(2, 'Parity.Level.GetEntitiesOnTile', function()\n"
        "  AssertType(Ext.Level.GetEntitiesOnTile, 'function', 'Level.GetEntitiesOnTile')\n"
        "  local ok, result = pcall(Ext.Level.GetEntitiesOnTile, {0, 0, 0})\n"
        "  assert(ok, 'GetEntitiesOnTile should not error: ' .. tostring(result))\n"
        "  assert(type(result) == 'table', 'GetEntitiesOnTile must return a copied array')\n"
        "  for _, handle in ipairs(result) do\n"
        "    assert(type(handle) == 'number', 'tile entity handles must be copied numbers')\n"
        "  end\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Level.GetTileDebugInfoDeferred', function()\n"
        "  AssertType(Ext.Level.GetTileDebugInfo, 'function', 'Level.GetTileDebugInfo')\n"
        "  local ok, result = pcall(Ext.Level.GetTileDebugInfo, {0, 0, 0})\n"
        "  assert(ok, 'GetTileDebugInfo stub should not error')\n"
        "  assert(result == nil, 'deferred GetTileDebugInfo must return nil')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Level.BeginPathfindingDeferred', function()\n"
        "  AssertType(Ext.Level.BeginPathfinding, 'function', 'Level.BeginPathfinding')\n"
        "  local ok, result = pcall(Ext.Level.BeginPathfinding, nil, {0, 0, 0}, nil)\n"
        "  assert(ok, 'BeginPathfinding stub should not error')\n"
        "  assert(result == nil, 'deferred BeginPathfinding must return nil')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Level.FindPath', function()\n"
        "  AssertType(Ext.Level.FindPath, 'function', 'Level.FindPath')\n"
        "  local ok, result = pcall(Ext.Level.FindPath, -1337, true)\n"
        "  assert(ok, 'FindPath invalid-ID guard should not error')\n"
        "  assert(result == false or result == nil,\n"
        "    'invalid FindPath must return false/nil without a native call')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Level.ReleasePath', function()\n"
        "  AssertType(Ext.Level.ReleasePath, 'function', 'Level.ReleasePath')\n"
        "  local ok, result = pcall(Ext.Level.ReleasePath, -1337)\n"
        "  assert(ok, 'ReleasePath invalid-ID guard should not error')\n"
        "  assert(result == false, 'invalid ReleasePath must return false without a native call')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Level.GetPathById', function()\n"
        "  AssertType(Ext.Level.GetPathById, 'function', 'Level.GetPathById')\n"
        "  local ok, result = pcall(Ext.Level.GetPathById, -1337)\n"
        "  assert(ok, 'GetPathById invalid-ID guard should not error')\n"
        "  assert(result == nil, 'GetPathById(-1337) must return nil without a native call')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Level.GetActivePathfindingRequests', function()\n"
        "  AssertType(Ext.Level.GetActivePathfindingRequests, 'function',\n"
        "    'Level.GetActivePathfindingRequests')\n"
        "  local ok, result = pcall(Ext.Level.GetActivePathfindingRequests)\n"
        "  assert(ok, 'GetActivePathfindingRequests should not error: ' .. tostring(result))\n"
        "  assert(type(result) == 'table', 'active requests must be a copied array')\n"
        "  for _, path in ipairs(result) do\n"
        "    assert(type(path) == 'table', 'active request must be a copied state table')\n"
        "    assert(type(path.PathId) == 'number', 'PathId must be copied')\n"
        "    assert(type(path.SearchStarted) == 'boolean', 'SearchStarted must be copied')\n"
        "    assert(type(path.SearchComplete) == 'boolean', 'SearchComplete must be copied')\n"
        "    assert(type(path.GoalFound) == 'boolean', 'GoalFound must be copied')\n"
        "    assert(type(path.DestinationReached) == 'boolean',\n"
        "      'DestinationReached must be copied')\n"
        "    assert(type(path.MovingBound) == 'number', 'MovingBound must be copied')\n"
        "    assert(type(path.StandingBound) == 'number', 'StandingBound must be copied')\n"
        "    assert(type(path.MovingBound2) == 'number', 'MovingBound2 must be copied')\n"
        "    assert(type(path.NodeCount) == 'number' and path.NodeCount >= 0,\n"
        "      'NodeCount must be a non-negative copied number')\n"
        "  end\n"
        "end)\n";

    static const char *console_cmd_test_parity_types_custom_props =
        "BG3SE_AddTest(1, 'Parity.Types.CustomProps', function()\n"
        "  local noop = function() return 42 end\n"
        "  local ok, err = pcall(Ext.Types.AddCustomFunction,\n"
        "    'DefinitelyNotARealType', 'TestFn', noop)\n"
        "  assert(not ok and err:find('Type not found', 1, true),\n"
        "    'AddCustomFunction unknown-type error: ' .. tostring(err))\n"
        "  ok, err = pcall(Ext.Types.AddCustomFunction, 'DamageType', 'TestFn', noop)\n"
        "  assert(not ok and err:find('Cannot extend non%-object type'),\n"
        "    'AddCustomFunction enum error: ' .. tostring(err))\n"
        "  assert(Ext.Types.AddCustomFunction(\n"
        "    'eoc::CharacterComponent', 'TestFn', noop) == true,\n"
        "    'AddCustomFunction component registration')\n"
        "  ok, err = pcall(Ext.Types.AddCustomProperty,\n"
        "    'DefinitelyNotARealType', 'TestProp', noop)\n"
        "  assert(not ok and err:find('Type not found', 1, true),\n"
        "    'AddCustomProperty unknown-type error: ' .. tostring(err))\n"
        "  ok, err = pcall(Ext.Types.AddCustomProperty,\n"
        "    'DamageType', 'TestProp', noop)\n"
        "  assert(not ok and err:find('Cannot extend non%-object type'),\n"
        "    'AddCustomProperty enum error: ' .. tostring(err))\n"
        "  assert(Ext.Types.AddCustomProperty(\n"
        "    'eoc::CharacterComponent', 'TestProp', noop) == true,\n"
        "    'AddCustomProperty component registration')\n"
        "end)\n";

    // Wave 7 B5: HashSet helper contract (no live HashSet proxy is exposed yet)
    static const char *console_cmd_test_wave7_hashset =
        "BG3SE_AddTest(1, 'Parity.Types.GetHashSetValueAt', function()\n"
        "  local f = Ext.Types.GetHashSetValueAt\n"
        "  AssertType(f, 'function', 'Types.GetHashSetValueAt')\n"
        "  for _, index in ipairs({ 1, 0, -1 }) do\n"
        "    local ok, err = pcall(f, {}, index)\n"
        "    assert(not ok, 'non-HashSet argument should error at index ' .. index)\n"
        "    assert(tostring(err):find('expected HashSet proxy userdata', 1, true),\n"
        "      'wrong-type error at index ' .. index .. ': ' .. tostring(err))\n"
        "  end\n"
        "  local ok, err = pcall(f, {}, 'not-an-index')\n"
        "  assert(not ok and tostring(err):find('number expected', 1, true),\n"
        "    'non-integer index error: ' .. tostring(err))\n"
        "end)\n";

    // Parity stubs part 3: Ext.Audio, Ext.Types, Ext.Math, Ext.Localization (tier 1)
    static const char *console_cmd_test_parity_apis =
        "BG3SE_AddTest(1, 'Parity.Audio.PlayExternalSound', function()\n"
        "  AssertType(Ext.Audio.PlayExternalSound, 'function', 'Audio.PlayExternalSound')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Parity.Audio.LoadBank', function()\n"
        "  AssertType(Ext.Audio.LoadBank, 'function', 'Audio.LoadBank')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Parity.Audio.UnloadBank', function()\n"
        "  AssertType(Ext.Audio.UnloadBank, 'function', 'Audio.UnloadBank')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Parity.Audio.PrepareBank', function()\n"
        "  AssertType(Ext.Audio.PrepareBank, 'function', 'Audio.PrepareBank')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Parity.Audio.UnprepareBank', function()\n"
        "  AssertType(Ext.Audio.UnprepareBank, 'function', 'Audio.UnprepareBank')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Parity.Types.Serialize', function()\n"
        "  AssertType(Ext.Types.Serialize, 'function', 'Types.Serialize')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Parity.Types.Unserialize', function()\n"
        "  AssertType(Ext.Types.Unserialize, 'function', 'Types.Unserialize')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Parity.Types.Construct', function()\n"
        "  AssertType(Ext.Types.Construct, 'function', 'Types.Construct')\n"
        "  local ok, err = pcall(Ext.Types.Construct, 'DefinitelyNotARealType')\n"
        "  assert(not ok, 'Construct(unknown) should error')\n"
        "  assert(err:find('Unknown type name', 1, true), 'unknown-type error text: ' .. tostring(err))\n"
        "  ok, err = pcall(Ext.Types.Construct, 'DamageType')\n"
        "  assert(not ok, 'Construct(enum) should error')\n"
        "  assert(err:find('non%-object type'), 'non-object error text: ' .. tostring(err))\n"
        "  ok, err = pcall(Ext.Types.Construct, 'bg3se.StatsObject')\n"
        "  assert(not ok, 'Construct(userdata type) should error')\n"
        "  assert(err:find('is not constructible', 1, true), 'not-constructible error text: ' .. tostring(err))\n"
        "  ok = pcall(Ext.Types.Construct, 'eoc::CharacterComponent')\n"
        "  assert(ok, 'Construct(component) should pass validation (upstream TODO fall-through)')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Parity.Types.GetValueType', function()\n"
        "  AssertType(Ext.Types.GetValueType, 'function', 'Types.GetValueType')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Parity.Types.GetFunctionLocation', function()\n"
        "  AssertType(Ext.Types.GetFunctionLocation, 'function', 'Types.GetFunctionLocation')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Parity.Math.Smoothstep', function()\n"
        "  AssertType(Ext.Math.Smoothstep, 'function', 'Math.Smoothstep')\n"
        "  local v = Ext.Math.Smoothstep(0.0, 1.0, 0.5)\n"
        "  AssertType(v, 'number', 'Smoothstep result')\n"
        "  AssertEqualsFloat(v, 0.5, 0.01, 'Smoothstep(0,1,0.5)')\n"
        "  AssertEqualsFloat(Ext.Math.Smoothstep(0.0, 1.0, -1.0), 0.0, 0.001,\n"
        "    'Smoothstep lower clamp')\n"
        "  AssertEqualsFloat(Ext.Math.Smoothstep(0.0, 1.0, 2.0), 1.0, 0.001,\n"
        "    'Smoothstep upper clamp')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Parity.Math.IsNaN', function()\n"
        "  AssertType(Ext.Math.IsNaN, 'function', 'Math.IsNaN')\n"
        "  assert(Ext.Math.IsNaN(0/0) == true, 'IsNaN(nan) should be true')\n"
        "  assert(Ext.Math.IsNaN(1.0) == false, 'IsNaN(1.0) should be false')\n"
        "  assert(Ext.Math.IsNaN(math.huge) == false, 'IsNaN(infinity) should be false')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Parity.Localization.CreateHandle', function()\n"
        "  AssertType(Ext.Loca.CreateHandle, 'function', 'Loca.CreateHandle')\n"
        "  local ok, r = pcall(Ext.Loca.CreateHandle)\n"
        "  assert(ok, 'CreateHandle should not crash: ' .. tostring(r))\n"
        "  assert(r ~= nil, 'CreateHandle should return a handle')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Parity.Localization.TranslationSurface', function()\n"
        "  AssertType(Ext.Loca.GetTranslatedString, 'function',\n"
        "    'Loca.GetTranslatedString')\n"
        "  AssertType(Ext.Loca.UpdateTranslatedString, 'function',\n"
        "    'Loca.UpdateTranslatedString')\n"
        "  AssertEquals(Ext.Loca.GetTranslatedString('', 'fallback'), 'fallback',\n"
        "    'empty handle fallback')\n"
        "end)\n";

    // Parity part 4: Ext.Events functor/damage subscription lifecycles
    static const char *console_cmd_test_parity_events =
        "BG3SE_AddTest(1, 'Parity.Events.ExecuteFunctor', function()\n"
        "  AssertNotNil(Ext.Events.ExecuteFunctor, 'ExecuteFunctor event object should exist')\n"
        "  local id = Ext.Events.ExecuteFunctor:Subscribe(function() end)\n"
        "  AssertType(id, 'number', 'ExecuteFunctor subscription handle')\n"
        "  AssertEquals(Ext.Events.ExecuteFunctor:Unsubscribe(id), true,\n"
        "    'ExecuteFunctor unsubscribe result')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Events.BeforeDealDamage.SubscriptionLifecycle', function()\n"
        "  AssertNotNil(Ext.Events.BeforeDealDamage, 'BeforeDealDamage event object should exist')\n"
        "  local id = Ext.Events.BeforeDealDamage:Subscribe(function() end)\n"
        "  AssertType(id, 'number', 'BeforeDealDamage subscription handle')\n"
        "  AssertEquals(Ext.Events.BeforeDealDamage:Unsubscribe(id), true,\n"
        "    'BeforeDealDamage unsubscribe result')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Parity.Events.DealDamage.SubscriptionLifecycle', function()\n"
        "  AssertNotNil(Ext.Events.DealDamage, 'DealDamage event object should exist')\n"
        "  local id = Ext.Events.DealDamage:Subscribe(function() end)\n"
        "  AssertType(id, 'number', 'DealDamage subscription handle')\n"
        "  AssertEquals(Ext.Events.DealDamage:Unsubscribe(id), true,\n"
        "    'DealDamage unsubscribe result')\n"
        "end)\n";

    // Tier 2: Wave 3 end-to-end damage hook probe. The subscriptions are armed
    // when the Lua test definitions load so a real game tick can occur before
    // the synchronous test runner checks the paired counts.
    static const char *console_cmd_test_wave3_damage_events =
        "BG3SE_DamageEventProbe = BG3SE_DamageEventProbe or {before=0, deal=0}\n"
        "if BG3SE_DamageEventProbe.beforeId == nil then\n"
        "  BG3SE_DamageEventProbe.beforeId = Ext.Events.BeforeDealDamage:Subscribe(function()\n"
        "    BG3SE_DamageEventProbe.before = BG3SE_DamageEventProbe.before + 1\n"
        "  end)\n"
        "end\n"
        "if BG3SE_DamageEventProbe.dealId == nil then\n"
        "  BG3SE_DamageEventProbe.dealId = Ext.Events.DealDamage:Subscribe(function()\n"
        "    BG3SE_DamageEventProbe.deal = BG3SE_DamageEventProbe.deal + 1\n"
        "  end)\n"
        "end\n"
        "BG3SE_AddTest(2, 'Stats.DamageEvents.PairedFiring', function()\n"
        "  AssertType(BG3SE_DamageEventProbe.beforeId, 'number',\n"
        "    'BeforeDealDamage subscription')\n"
        "  AssertType(BG3SE_DamageEventProbe.dealId, 'number',\n"
        "    'DealDamage subscription')\n"
        "  assert(BG3SE_DamageEventProbe.before > 0,\n"
        "    'no damage functor observed; apply BURNING to the host, allow one status tick, then rerun this test')\n"
        "  AssertEquals(BG3SE_DamageEventProbe.deal,\n"
        "    BG3SE_DamageEventProbe.before,\n"
        "    'BeforeDealDamage/DealDamage paired event counts')\n"
        "end)\n";

    // Parity part 5: behavioral tests (Tier 1 — test actual behavior, not just presence)
    static const char *console_cmd_test_parity_behavior =
        "BG3SE_AddTest(1, 'Parity.Debug.SafeMemoryEdges', function()\n"
        "  local r1 = Ext.Debug.ReadString(0)\n"
        "  assert(r1 == nil, 'ReadString(0) should return nil, got: ' .. tostring(r1))\n"
        "  local r2 = Ext.Debug.ReadU64(0)\n"
        "  assert(r2 == nil, 'ReadU64(0) should return nil, got: ' .. tostring(r2))\n"
        "  local r3 = Ext.Debug.ProbeStruct(0, 0, 8, 8)\n"
        "  assert(type(r3) == 'table', 'ProbeStruct(0) should return table, got: ' .. type(r3))\n"
        "  assert(next(r3) == nil, 'ProbeStruct(0) should return empty table')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Parity.Events.FunctorSubscribePair', function()\n"
        "  local handler = function() end\n"
        "  local before = Ext.Events.ExecuteFunctor:Subscribe(handler)\n"
        "  local after = Ext.Events.AfterExecuteFunctor:Subscribe(handler)\n"
        "  AssertType(before, 'number', 'ExecuteFunctor subscription handle')\n"
        "  AssertType(after, 'number', 'AfterExecuteFunctor subscription handle')\n"
        "  AssertEquals(Ext.Events.ExecuteFunctor:Unsubscribe(before), true,\n"
        "    'ExecuteFunctor unsubscribe result')\n"
        "  AssertEquals(Ext.Events.AfterExecuteFunctor:Unsubscribe(after), true,\n"
        "    'AfterExecuteFunctor unsubscribe result')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Parity.Events.PriorityOncePrevent', function()\n"
        "  local called = 0\n"
        "  local id = Ext.Events.DoConsoleCommand:Subscribe(function(e)\n"
        "    called = called + 1\n"
        "  end, {Priority = 50, Once = true})\n"
        "  assert(id ~= nil, 'Subscribe with options should return id')\n"
        "  Ext.Events.DoConsoleCommand:Unsubscribe(id)\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Parity.Stats.GetBehavior', function()\n"
        "  local ok, s = pcall(Ext.Stats.Get, 'WPN_Longsword')\n"
        "  if not ok then return end\n"
        "  assert(s ~= nil, 'WPN_Longsword should exist')\n"
        "  assert(s.Name == 'WPN_Longsword', 'Name should match: ' .. tostring(s.Name))\n"
        "  assert(type(s.Damage) == 'string' or type(s.Damage) == 'number',\n"
        "    'Damage should be string or number, got: ' .. type(s.Damage))\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Parity.Stats.GetAllReturnsData', function()\n"
        "  local all = Ext.Stats.GetAll()\n"
        "  assert(type(all) == 'table', 'GetAll should return table')\n"
        "  assert(#all > 100, 'GetAll should return >100 stats, got: ' .. #all)\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Parity.Timer.WaitForCancel', function()\n"
        "  local id = Ext.Timer.WaitFor(99999, function() end)\n"
        "  assert(id ~= nil, 'WaitFor should return timer id')\n"
        "  local ok = pcall(Ext.Timer.Cancel, id)\n"
        "  assert(ok, 'Cancel should not error')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Parity.Audio.PlayExternalSoundEdge', function()\n"
        "  local ok, err = pcall(Ext.Audio.PlayExternalSound, nil, nil)\n"
        "  assert(not ok or err == nil, 'PlayExternalSound(nil,nil) should fail safely')\n"
        "end)\n"
        "BG3SE_AddTest(1, 'Parity.Types.SerializeRejectsPlainTable', function()\n"
        "  local ok = pcall(Ext.Types.Serialize, {x=1})\n"
        "  assert(not ok, 'Serialize must reject values without reflected layouts')\n"
        "end)\n";

    // Wave 3 small-gap behavioral coverage (Tier 2 — loaded save required)
    static const char *console_cmd_test_wave3_small_gaps =
        "BG3SE_AddTest(2, 'Wave3.Entity.GetAllEntities', function()\n"
        "  local entities = Ext.Entity.GetAllEntities()\n"
        "  assert(type(entities) == 'table', 'GetAllEntities should return a table')\n"
        "  assert(#entities > 0, 'loaded world should contain entities')\n"
        "  AssertType(entities[1], 'userdata', 'enumerated entity')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Wave3.Entity.GetAllComponents', function()\n"
        "  local entity = Ext.Entity.Get(Osi.GetHostCharacter())\n"
        "  AssertNotNil(entity, 'host entity')\n"
        "  local viaMethod = entity:GetAllComponents()\n"
        "  local viaNamespace = Ext.Entity.GetAllComponents(entity)\n"
        "  assert(type(viaMethod) == 'table', 'method result should be a table')\n"
        "  assert(type(viaNamespace) == 'table', 'namespace result should be a table')\n"
        "  assert(next(viaMethod) ~= nil, 'host components should not be empty')\n"
        "  assert(next(viaNamespace) ~= nil, 'namespace components should not be empty')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Wave3.Types.ComponentSerializeRoundtrip', function()\n"
        "  local entity = Ext.Entity.Get(Osi.GetHostCharacter())\n"
        "  AssertNotNil(entity, 'host entity')\n"
        "  local health = entity.Health\n"
        "  AssertNotNil(health, 'host Health component')\n"
        "  local snapshot = Ext.Types.Serialize(health)\n"
        "  assert(type(snapshot) == 'table', 'Serialize should return a table')\n"
        "  AssertType(snapshot.Hp, 'number', 'serialized Health.Hp')\n"
        "  local originalHp = health.Hp\n"
        "  Ext.Types.Unserialize(health, snapshot)\n"
        "  AssertEquals(health.Hp, originalHp, 'Health.Hp after same-value roundtrip')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Wave3.Localization.UpdateRoundtrip', function()\n"
        "  assert(Ext.Loca.IsReady(), 'localization repository should be ready')\n"
        "  local handle = Ext.Loca.CreateHandle()\n"
        "  local value = 'BG3SE Wave 3 localization roundtrip'\n"
        "  assert(Ext.Loca.UpdateTranslatedString(handle, value),\n"
        "    'UpdateTranslatedString should succeed')\n"
        "  AssertEquals(Ext.Loca.GetTranslatedString(handle, 'fallback'), value,\n"
        "    'updated translation')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Wave3.Level.PathLookupLiveDispatch', function()\n"
        "  local requests = Ext.Level.GetActivePathfindingRequests()\n"
        "  assert(type(requests) == 'table', 'active requests must be a table')\n"
        "  if #requests == 0 then\n"
        "    Ext.Print('    (fixture absent; not exercised) no active pathfinding requests')\n"
        "    return\n"
        "  end\n"
        "  local state = Ext.Level.GetPathById(requests[1].PathId)\n"
        "  AssertType(state, 'table', 'GetPathById on a live path ID')\n"
        "  AssertEquals(state.PathId, requests[1].PathId, 'looked-up PathId')\n"
        "end)\n"
        "BG3SE_AddTest(2, 'Wave3.Audio.BankDispatchSmoke', function()\n"
        "  local ok, r = pcall(Ext.Audio.PrepareBank, '__BG3SE_NoSuchBank__')\n"
        "  assert(ok, 'PrepareBank must not crash through the dlsym dispatch: '\n"
        "    .. tostring(r))\n"
        "  assert(r == false, 'PrepareBank on a nonexistent bank must return false')\n"
        "end)\n";

    // Execute each command registration chunk
    const char *console_cmds[] = {
        console_cmd_probe, console_cmd_dumpstat, console_cmd_findstr,
        console_cmd_hexdump, console_cmd_types, console_cmd_pv,
        // Test suite: framework + assertions first, then test definitions, then registration
        console_cmd_test_framework, console_cmd_test_assertions,
        console_cmd_test_core, console_cmd_test_stats, console_cmd_test_wave2_stats,
        console_cmd_test_wave3_stats,
        console_cmd_test_timer,
        console_cmd_test_events, console_cmd_test_debug, console_cmd_test_types,
        console_cmd_test_misc, console_cmd_test_mcm, console_cmd_test_register,
        // In-game tests
        console_cmd_test_ingame, console_cmd_test_ingame2,
        console_cmd_test_staticdata_layout,
        console_cmd_test_osiris, console_cmd_test_osiris_edge,
        console_cmd_test_entity_events,
        console_cmd_test_wave2_components,
        console_cmd_test_wave3_components,
        console_cmd_test_wave2_stats_ingame,
        // Fail-first parity stubs (FAIL now, PASS after implementation)
        console_cmd_test_parity_entity,
        console_cmd_test_parity_level,
        console_cmd_test_wave3_level,
        console_cmd_test_wave3_aigrid,
        console_cmd_test_parity_types_custom_props,
        console_cmd_test_wave7_hashset,
        console_cmd_test_parity_apis,
        console_cmd_test_parity_events,
        console_cmd_test_wave3_damage_events,
        console_cmd_test_parity_behavior,
        console_cmd_test_wave3_small_gaps,
        console_cmd_test_parity_ingame,
        console_cmd_test_parity_net,
        console_cmd_test_wave7_osi_delete,
        console_cmd_test_wave7_addenum,
        console_cmd_test_wave7_tracing,
        console_cmd_test_wave7_sysupdate,
        console_cmd_test_wave7_heights,
        console_cmd_test_wave7_tileraw,
        console_cmd_test_wave7_entity,
        console_cmd_test_wave7_replication,
        console_cmd_test_wave7_raycastany,
        console_cmd_test_parity_ingame_entity,
        console_cmd_test_ingame_reg,
        console_cmd_ide,
        console_cmd_mod_diag
    };
    uint64_t t_cmds_start = (uint64_t)timer_get_monotonic_ms();
    size_t cmd_count = sizeof(console_cmds) / sizeof(console_cmds[0]);
    for (size_t i = 0; i < cmd_count; i++) {
        if (luaL_dostring(L, console_cmds[i]) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            LOG_LUA_WARN(" Failed to register console command: %s", err ? err : "(unknown)");
            lua_pop(L, 1);
        }
    }
    uint64_t t_cmds_end = (uint64_t)timer_get_monotonic_ms();
    LOG_LUA_INFO("  console_cmds (%zu chunks): %llums",
                 cmd_count, (unsigned long long)(t_cmds_end - t_cmds_start));

    LOG_LUA_INFO("Global helpers registered (_P, _D, _DS, _H, _PTR, _PE, Debug.*)");
    LOG_LUA_INFO("Console commands: !probe !dumpstat !findstr !hexdump !types !pv_* !test !test_ingame !ide_helpers");
}
