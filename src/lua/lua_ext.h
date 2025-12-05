/**
 * BG3SE-macOS - Lua Ext Namespace Core Module
 *
 * Provides core Ext.* API functions for Lua integration.
 * - Ext.Print, Ext.GetVersion, Ext.IsServer, Ext.IsClient
 * - Ext.IO.LoadFile, Ext.IO.SaveFile
 */

#ifndef BG3SE_LUA_EXT_H
#define BG3SE_LUA_EXT_H

#include <lua.h>
#include <lauxlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Lua C API Functions (for Ext namespace)
// ============================================================================

/**
 * Ext.Print(...) - Print to BG3SE log
 */
int lua_ext_print(lua_State *L);

/**
 * Ext.GetVersion() - Return BG3SE version string
 */
int lua_ext_getversion(lua_State *L);

/**
 * Ext.IsServer() - Check if running on server context
 */
int lua_ext_isserver(lua_State *L);

/**
 * Ext.IsClient() - Check if running on client context
 */
int lua_ext_isclient(lua_State *L);

// ============================================================================
// Ext.IO Functions
// ============================================================================

/**
 * Ext.IO.LoadFile(path) - Load file contents as string
 * @return content string on success, or nil+error on failure
 */
int lua_ext_io_loadfile(lua_State *L);

/**
 * Ext.IO.SaveFile(path, content) - Save string to file
 * @return true on success, false on failure
 */
int lua_ext_io_savefile(lua_State *L);

// ============================================================================
// Registration
// ============================================================================

/**
 * Register basic Ext.* functions in a table (Print, GetVersion, IsServer, IsClient)
 * @param L Lua state
 * @param ext_table_index Stack index of Ext table
 */
void lua_ext_register_basic(lua_State *L, int ext_table_index);

/**
 * Register Ext.IO namespace functions
 * @param L Lua state
 * @param ext_table_index Stack index of Ext table
 */
void lua_ext_register_io(lua_State *L, int ext_table_index);

// ============================================================================
// Ext.Memory Functions (for interactive memory probing)
// ============================================================================

/**
 * Ext.Memory.Read(addr, size) - Read bytes from memory
 * @param addr Address as integer or hex string
 * @param size Number of bytes to read (default 16, max 4096)
 * @return Hex string of bytes, or nil+error on failure
 */
int lua_ext_memory_read(lua_State *L);

/**
 * Ext.Memory.ReadString(addr, maxLen) - Read null-terminated string from memory
 * @param addr Address as integer or hex string
 * @param maxLen Maximum length to read (default 256)
 * @return String, or nil on failure
 */
int lua_ext_memory_readstring(lua_State *L);

/**
 * Ext.Memory.Search(pattern, startAddr, size) - Search for byte pattern
 * @param pattern Hex string like "53 74 72 65 6E 67 74 68" (Strength)
 * @param startAddr Start address (default: binary base)
 * @param size Bytes to search (default: 64MB)
 * @return Table of matching addresses, or empty table
 */
int lua_ext_memory_search(lua_State *L);

/**
 * Ext.Memory.GetModuleBase(name) - Get base address of loaded module
 * @param name Module name (e.g., "BaldursGate3" or "libOsiris")
 * @return Address as integer, or nil if not found
 */
int lua_ext_memory_getmodulebase(lua_State *L);

/**
 * Register Ext.Memory namespace functions
 * @param L Lua state
 * @param ext_table_index Stack index of Ext table
 */
void lua_ext_register_memory(lua_State *L, int ext_table_index);

#ifdef __cplusplus
}
#endif

#endif // BG3SE_LUA_EXT_H
