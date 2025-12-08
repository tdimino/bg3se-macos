/**
 * lua_timer.c - Ext.Timer Lua bindings
 *
 * Provides:
 * - Ext.Timer.WaitFor(delay, callback, [repeat]) - Create timer
 * - Ext.Timer.Cancel(handle) - Cancel timer
 * - Ext.Timer.Pause(handle) - Pause timer
 * - Ext.Timer.Resume(handle) - Resume timer
 * - Ext.Timer.IsPaused(handle) - Check if paused
 * - Ext.Timer.MonotonicTime() - Get monotonic clock
 */

#include "lua_timer.h"
#include "../timer/timer.h"
#include "../core/logging.h"

#include <lauxlib.h>
#include <math.h>

// Maximum timer delay (24 hours in milliseconds)
#define TIMER_MAX_DELAY_MS 86400000.0

// ============================================================================
// Ext.Timer.WaitFor(delay, callback, [repeat])
// ============================================================================

static int lua_timer_waitfor(lua_State *L) {
    // Arg 1: delay in milliseconds
    double delay_ms = luaL_checknumber(L, 1);

    // Validate delay
    if (delay_ms < 0 || !isfinite(delay_ms)) {
        return luaL_error(L, "delay must be >= 0 and finite (got %f)", delay_ms);
    }
    if (delay_ms > TIMER_MAX_DELAY_MS) {
        return luaL_error(L, "delay must be <= %fms (24 hours)", TIMER_MAX_DELAY_MS);
    }

    // Arg 2: callback function
    luaL_checktype(L, 2, LUA_TFUNCTION);

    // Arg 3: optional repeat interval in milliseconds
    double repeat_ms = 0;
    if (lua_gettop(L) >= 3 && !lua_isnil(L, 3)) {
        repeat_ms = luaL_checknumber(L, 3);

        // Validate repeat interval
        if (repeat_ms < 0 || !isfinite(repeat_ms)) {
            return luaL_error(L, "repeat must be >= 0 and finite (got %f)", repeat_ms);
        }
        if (repeat_ms > 0 && repeat_ms < 1.0) {
            return luaL_error(L, "repeat interval must be >= 1ms or 0 (got %f)", repeat_ms);
        }
        if (repeat_ms > TIMER_MAX_DELAY_MS) {
            return luaL_error(L, "repeat must be <= %fms (24 hours)", TIMER_MAX_DELAY_MS);
        }
    }

    // Store callback in registry
    lua_pushvalue(L, 2);
    int callback_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // Create timer
    uint64_t handle = timer_create(L, delay_ms, callback_ref, repeat_ms);

    if (handle == 0) {
        return luaL_error(L, "Failed to create timer (pool exhausted)");
    }

    lua_pushinteger(L, (lua_Integer)handle);
    return 1;
}

// ============================================================================
// Ext.Timer.Cancel(handle)
// ============================================================================

static int lua_timer_cancel(lua_State *L) {
    uint64_t handle = (uint64_t)luaL_checkinteger(L, 1);

    bool result = timer_cancel(L, handle);

    lua_pushboolean(L, result);
    return 1;
}

// ============================================================================
// Ext.Timer.Pause(handle)
// ============================================================================

static int lua_timer_pause(lua_State *L) {
    uint64_t handle = (uint64_t)luaL_checkinteger(L, 1);

    bool result = timer_pause(handle);

    lua_pushboolean(L, result);
    return 1;
}

// ============================================================================
// Ext.Timer.Resume(handle)
// ============================================================================

static int lua_timer_resume(lua_State *L) {
    uint64_t handle = (uint64_t)luaL_checkinteger(L, 1);

    bool result = timer_resume(handle);

    lua_pushboolean(L, result);
    return 1;
}

// ============================================================================
// Ext.Timer.IsPaused(handle)
// ============================================================================

static int lua_timer_is_paused(lua_State *L) {
    uint64_t handle = (uint64_t)luaL_checkinteger(L, 1);

    bool result = timer_is_paused(handle);

    lua_pushboolean(L, result);
    return 1;
}

// ============================================================================
// Ext.Timer.MonotonicTime()
// ============================================================================

static int lua_timer_monotonic_time(lua_State *L) {
    double ms = timer_get_monotonic_ms();

    lua_pushnumber(L, ms);
    return 1;
}

// ============================================================================
// Registration
// ============================================================================

void lua_timer_register(lua_State *L, int ext_table_idx) {
    // Convert negative index to absolute since we'll be pushing onto stack
    if (ext_table_idx < 0) {
        ext_table_idx = lua_gettop(L) + ext_table_idx + 1;
    }

    // Create Ext.Timer table
    lua_newtable(L);

    // Register functions
    lua_pushcfunction(L, lua_timer_waitfor);
    lua_setfield(L, -2, "WaitFor");

    lua_pushcfunction(L, lua_timer_cancel);
    lua_setfield(L, -2, "Cancel");

    lua_pushcfunction(L, lua_timer_pause);
    lua_setfield(L, -2, "Pause");

    lua_pushcfunction(L, lua_timer_resume);
    lua_setfield(L, -2, "Resume");

    lua_pushcfunction(L, lua_timer_is_paused);
    lua_setfield(L, -2, "IsPaused");

    lua_pushcfunction(L, lua_timer_monotonic_time);
    lua_setfield(L, -2, "MonotonicTime");

    // Set as Ext.Timer
    lua_setfield(L, ext_table_idx, "Timer");

    LOG_TIMER_INFO("Registered Ext.Timer namespace");
}
