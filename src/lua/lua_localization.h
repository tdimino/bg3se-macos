/**
 * lua_localization.h - Lua Bindings for Ext.Loca (Localization API)
 *
 * Provides Lua access to the game's localization/translation system.
 *
 * API (matching Windows BG3SE):
 *   Ext.Loca.GetTranslatedString(handle, [fallback])
 *   Ext.Loca.UpdateTranslatedString(handle, value)
 */

#ifndef LUA_LOCALIZATION_H
#define LUA_LOCALIZATION_H

#include <lua.h>
#include <lauxlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Lua C API Functions
// ============================================================================

/**
 * Ext.Loca.GetTranslatedString(handle, [fallback]) -> string
 *
 * Get a translated string by its localization handle.
 *
 * @param handle Localization handle (e.g., "h12345678g1234g4567g8901g123456789012")
 * @param fallback Optional fallback text if handle not found
 * @return Translated text, or fallback, or empty string
 */
int lua_loca_get_translated_string(lua_State *L);

/**
 * Ext.Loca.UpdateTranslatedString(handle, value) -> boolean
 *
 * Update a translated string at runtime (session-only).
 *
 * @param handle Localization handle
 * @param value New translated text
 * @return true on success, false on error
 */
int lua_loca_update_translated_string(lua_State *L);

// ============================================================================
// Debug/Info Functions
// ============================================================================

/**
 * Ext.Loca.GetLanguage() -> string
 *
 * Get the current game language.
 *
 * @return Language name (e.g., "English")
 */
int lua_loca_get_language(lua_State *L);

/**
 * Ext.Loca.IsReady() -> boolean
 *
 * Check if the localization system is ready.
 */
int lua_loca_is_ready(lua_State *L);

/**
 * Ext.Loca.DumpInfo()
 *
 * Dump localization system info to log.
 */
int lua_loca_dump_info(lua_State *L);

// ============================================================================
// Registration
// ============================================================================

/**
 * Register Ext.Loca namespace functions.
 *
 * @param L Lua state
 * @param ext_table_index Stack index of Ext table
 */
void lua_ext_register_loca(lua_State *L, int ext_table_index);

#ifdef __cplusplus
}
#endif

#endif // LUA_LOCALIZATION_H
