/**
 * BG3SE-macOS - PersistentVars Module
 *
 * Provides savegame persistence for mod variables.
 * Variables stored in Mods[ModTable].PersistentVars survive game restarts.
 *
 * Storage: ~/Library/Application Support/BG3SE/persistentvars/{ModTable}.json
 *
 * API:
 *   Ext.Vars.SyncPersistentVars()       - Force immediate save
 *   Ext.Vars.IsPersistentVarsLoaded()   - Check if vars are loaded
 *   Ext.Vars.ReloadPersistentVars()     - Force reload from disk
 */

#ifndef BG3SE_LUA_PERSISTENTVARS_H
#define BG3SE_LUA_PERSISTENTVARS_H

#include <lua.h>
#include <lauxlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Initialization
// ============================================================================

/**
 * Initialize the persistentvars module.
 * Creates the storage directory if needed.
 * Should be called once at startup.
 */
void persist_init(void);

// ============================================================================
// Core Operations
// ============================================================================

/**
 * Restore all persistent variables from disk.
 * Loads JSON files from storage directory and populates Mods[ModTable].PersistentVars.
 * Should be called BEFORE SessionLoaded event fires.
 *
 * @param L Lua state
 */
void persist_restore_all(lua_State *L);

/**
 * Save all dirty persistent variables to disk.
 * Enumerates Mods with PersistentVars and writes to JSON files.
 * Uses atomic write pattern (temp file + rename) for safety.
 *
 * @param L Lua state
 */
void persist_save_all(lua_State *L);

/**
 * Check for dirty vars and save periodically.
 * Should be called from tick/event hook.
 * Only saves if interval has elapsed and vars are dirty.
 *
 * @param L Lua state
 */
void persist_tick(lua_State *L);

// ============================================================================
// Lua API Registration
// ============================================================================

/**
 * Register Ext.Vars namespace functions:
 *   SyncPersistentVars()       - Force immediate save
 *   IsPersistentVarsLoaded()   - Check if loaded
 *   ReloadPersistentVars()     - Force reload from disk
 *
 * @param L Lua state
 * @param ext_table_index Stack index of Ext table
 */
void lua_persistentvars_register(lua_State *L, int ext_table_index);

// ============================================================================
// State Queries
// ============================================================================

/**
 * Check if persistent variables have been loaded this session.
 * @return 1 if loaded, 0 if not
 */
int persist_is_loaded(void);

/**
 * Mark that persistent variables need saving.
 * Called when mod sets PersistentVars.
 */
void persist_mark_dirty(void);

#ifdef __cplusplus
}
#endif

#endif // BG3SE_LUA_PERSISTENTVARS_H
