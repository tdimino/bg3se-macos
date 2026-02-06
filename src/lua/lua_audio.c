/**
 * lua_audio.c - Lua bindings for Ext.Audio API
 *
 * Provides Lua access to WWise audio engine control.
 *
 * API:
 *   Ext.Audio.IsReady() -> boolean
 *   Ext.Audio.PostEvent(soundObject, eventName) -> boolean
 *   Ext.Audio.Stop(soundObject) -> boolean
 *   Ext.Audio.PauseAllSounds() -> boolean
 *   Ext.Audio.ResumeAllSounds() -> boolean
 *   Ext.Audio.SetSwitch(soundObject, switchGroup, state) -> boolean
 *   Ext.Audio.SetState(stateGroup, state) -> boolean
 *   Ext.Audio.SetRTPC(soundObject, name, value) -> boolean
 *   Ext.Audio.GetRTPC(soundObject, name) -> number
 *   Ext.Audio.ResetRTPC(soundObject, name) -> boolean
 *   Ext.Audio.LoadEvent(eventName) -> boolean
 *   Ext.Audio.UnloadEvent(eventName) -> boolean
 *   Ext.Audio.GetSoundObjectId(name) -> integer
 */

#include "lua_audio.h"
#include "../audio/audio_manager.h"
#include "../core/logging.h"
#include <lua.h>
#include <lauxlib.h>

// ============================================================================
// Helper: Resolve sound object from Lua arg
// ============================================================================

/**
 * Get a sound object ID from a Lua argument.
 * Accepts: nil/none (global), integer (direct ID), string (name resolution)
 */
static uint64_t get_sound_object(lua_State *L, int idx) {
    if (lua_isnoneornil(L, idx)) {
        return 1;  // Global/default sound object
    }

    if (lua_isinteger(L, idx)) {
        return (uint64_t)lua_tointeger(L, idx);
    }

    if (lua_isstring(L, idx)) {
        const char *name = lua_tostring(L, idx);
        return audio_resolve_sound_object(name);
    }

    return 1;  // Default to global
}

// ============================================================================
// Status
// ============================================================================

/**
 * Ext.Audio.IsReady() -> boolean
 */
static int lua_audio_is_ready(lua_State *L) {
    lua_pushboolean(L, audio_manager_ready());
    return 1;
}

// ============================================================================
// Sound Object Resolution
// ============================================================================

/**
 * Ext.Audio.GetSoundObjectId(name) -> integer
 *   name: string ("Global", "Music", "Listener0", "Ambient1", or numeric string)
 *   Returns: sound object ID (0 = invalid)
 */
static int lua_audio_get_sound_object_id(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);
    uint64_t id = audio_resolve_sound_object(name);
    lua_pushinteger(L, (lua_Integer)id);
    return 1;
}

// ============================================================================
// Playback Control
// ============================================================================

/**
 * Ext.Audio.PostEvent(soundObject, eventName) -> boolean
 *   soundObject: nil (global), integer (id), or string (name)
 *   eventName: string
 */
static int lua_audio_post_event(lua_State *L) {
    uint64_t obj = get_sound_object(L, 1);
    const char *event_name = luaL_checkstring(L, 2);
    lua_pushboolean(L, audio_post_event(obj, event_name));
    return 1;
}

/**
 * Ext.Audio.Stop(soundObject) -> boolean
 */
static int lua_audio_stop(lua_State *L) {
    uint64_t obj = get_sound_object(L, 1);
    lua_pushboolean(L, audio_stop(obj));
    return 1;
}

/**
 * Ext.Audio.PauseAllSounds() -> boolean
 */
static int lua_audio_pause_all(lua_State *L) {
    lua_pushboolean(L, audio_pause_all());
    return 1;
}

/**
 * Ext.Audio.ResumeAllSounds() -> boolean
 */
static int lua_audio_resume_all(lua_State *L) {
    lua_pushboolean(L, audio_resume_all());
    return 1;
}

// ============================================================================
// State/Switch Control
// ============================================================================

/**
 * Ext.Audio.SetSwitch(soundObject, switchGroup, state) -> boolean
 */
static int lua_audio_set_switch(lua_State *L) {
    uint64_t obj = get_sound_object(L, 1);
    const char *switch_group = luaL_checkstring(L, 2);
    const char *state = luaL_checkstring(L, 3);
    lua_pushboolean(L, audio_set_switch(obj, switch_group, state));
    return 1;
}

/**
 * Ext.Audio.SetState(stateGroup, state) -> boolean
 */
static int lua_audio_set_state(lua_State *L) {
    const char *state_group = luaL_checkstring(L, 1);
    const char *state = luaL_checkstring(L, 2);
    lua_pushboolean(L, audio_set_state(state_group, state));
    return 1;
}

// ============================================================================
// RTPC (Real-Time Parameter Control)
// ============================================================================

/**
 * Ext.Audio.SetRTPC(soundObject, name, value) -> boolean
 */
static int lua_audio_set_rtpc(lua_State *L) {
    uint64_t obj = get_sound_object(L, 1);
    const char *name = luaL_checkstring(L, 2);
    float value = (float)luaL_checknumber(L, 3);
    lua_pushboolean(L, audio_set_rtpc(obj, name, value));
    return 1;
}

/**
 * Ext.Audio.GetRTPC(soundObject, name) -> number
 */
static int lua_audio_get_rtpc(lua_State *L) {
    uint64_t obj = get_sound_object(L, 1);
    const char *name = luaL_checkstring(L, 2);
    lua_pushnumber(L, audio_get_rtpc(obj, name));
    return 1;
}

/**
 * Ext.Audio.ResetRTPC(soundObject, name) -> boolean
 */
static int lua_audio_reset_rtpc(lua_State *L) {
    uint64_t obj = get_sound_object(L, 1);
    const char *name = luaL_checkstring(L, 2);
    lua_pushboolean(L, audio_reset_rtpc(obj, name));
    return 1;
}

// ============================================================================
// Event/Bank Management
// ============================================================================

/**
 * Ext.Audio.LoadEvent(eventName) -> boolean
 */
static int lua_audio_load_event(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);
    lua_pushboolean(L, audio_load_event(name));
    return 1;
}

/**
 * Ext.Audio.UnloadEvent(eventName) -> boolean
 */
static int lua_audio_unload_event(lua_State *L) {
    const char *name = luaL_checkstring(L, 1);
    lua_pushboolean(L, audio_unload_event(name));
    return 1;
}

// ============================================================================
// Registration
// ============================================================================

static const struct luaL_Reg audio_functions[] = {
    {"IsReady",            lua_audio_is_ready},
    {"GetSoundObjectId",   lua_audio_get_sound_object_id},
    {"PostEvent",          lua_audio_post_event},
    {"Stop",               lua_audio_stop},
    {"PauseAllSounds",     lua_audio_pause_all},
    {"ResumeAllSounds",    lua_audio_resume_all},
    {"SetSwitch",          lua_audio_set_switch},
    {"SetState",           lua_audio_set_state},
    {"SetRTPC",            lua_audio_set_rtpc},
    {"GetRTPC",            lua_audio_get_rtpc},
    {"ResetRTPC",          lua_audio_reset_rtpc},
    {"LoadEvent",          lua_audio_load_event},
    {"UnloadEvent",        lua_audio_unload_event},
    {NULL, NULL}
};

void lua_audio_register(lua_State *L, int ext_table_idx) {
    lua_newtable(L);

    for (const struct luaL_Reg *fn = audio_functions; fn->name != NULL; fn++) {
        lua_pushcfunction(L, fn->func);
        lua_setfield(L, -2, fn->name);
    }

    lua_setfield(L, ext_table_idx - 1, "Audio");
}
