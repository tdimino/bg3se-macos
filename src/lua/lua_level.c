/**
 * lua_level.c - Lua bindings for Ext.Level API
 *
 * Provides Lua access to level physics and tile queries.
 *
 * API:
 *   Ext.Level.GetCurrentLevel() - Get current level pointer (or nil)
 *   Ext.Level.GetPhysicsScene() - Get physics scene pointer (or nil)
 *   Ext.Level.GetAiGrid() - Get AI grid pointer (or nil)
 *   Ext.Level.IsReady() - Check if LevelManager is available
 *   Ext.Level.RaycastClosest(src, dst, physType, includeGroup, excludeGroup, context) -> hit table or nil
 *   Ext.Level.RaycastAny(src, dst, physType, includeGroup, excludeGroup, context) -> boolean
 *   Ext.Level.TestBox(pos, extents, physType, includeGroup, excludeGroup) -> boolean
 *   Ext.Level.TestSphere(pos, radius, physType, includeGroup, excludeGroup) -> boolean
 *   Ext.Level.GetHeightsAt(x, z) -> array of heights
 */

#include "lua_level.h"
#include "../level/level_manager.h"
#include "../core/logging.h"
#include <lua.h>
#include <lauxlib.h>
#include <string.h>

// ============================================================================
// Helper: Read vec3 from Lua table at stack index
// ============================================================================

static bool read_vec3(lua_State *L, int idx, float out[3]) {
    if (!lua_istable(L, idx)) return false;

    for (int i = 0; i < 3; i++) {
        lua_rawgeti(L, idx, i + 1);
        if (!lua_isnumber(L, -1)) {
            lua_pop(L, 1);
            return false;
        }
        out[i] = (float)lua_tonumber(L, -1);
        lua_pop(L, 1);
    }
    return true;
}

// ============================================================================
// Singleton Accessors
// ============================================================================

/**
 * Ext.Level.IsReady() -> boolean
 */
static int lua_level_is_ready(lua_State *L) {
    lua_pushboolean(L, level_manager_ready());
    return 1;
}

/**
 * Ext.Level.GetCurrentLevel() -> lightuserdata or nil
 */
static int lua_level_get_current(lua_State *L) {
    void *level = level_get_current();
    if (level) {
        lua_pushlightuserdata(L, level);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

/**
 * Ext.Level.GetPhysicsScene() -> lightuserdata or nil
 */
static int lua_level_get_physics_scene(lua_State *L) {
    void *physics = level_get_physics_scene();
    if (physics) {
        lua_pushlightuserdata(L, physics);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

/**
 * Ext.Level.GetAiGrid() -> lightuserdata or nil
 */
static int lua_level_get_aigrid(lua_State *L) {
    void *aigrid = level_get_aigrid();
    if (aigrid) {
        lua_pushlightuserdata(L, aigrid);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

// ============================================================================
// Physics Raycasting
// ============================================================================

/**
 * Ext.Level.RaycastClosest(src, dst, physType, includeGroup, excludeGroup, context)
 *   src: {x, y, z} table
 *   dst: {x, y, z} table
 *   physType: integer (physics type flags)
 *   includeGroup: integer (group mask)
 *   excludeGroup: integer (group mask)
 *   context: integer (raycast context)
 *   Returns: hit table {Normal={x,y,z}, Position={x,y,z}, Distance=n, PhysicsGroup=n} or nil
 */
static int lua_level_raycast_closest(lua_State *L) {
    float src[3], dst[3];

    if (!read_vec3(L, 1, src)) {
        return luaL_error(L, "Ext.Level.RaycastClosest: src must be a {x,y,z} table");
    }
    if (!read_vec3(L, 2, dst)) {
        return luaL_error(L, "Ext.Level.RaycastClosest: dst must be a {x,y,z} table");
    }

    uint32_t phys_type = (uint32_t)luaL_optinteger(L, 3, 1);
    uint32_t include_group = (uint32_t)luaL_optinteger(L, 4, 0x7FFFFFFF);
    uint32_t exclude_group = (uint32_t)luaL_optinteger(L, 5, 0);
    int context = (int)luaL_optinteger(L, 6, 0);

    LevelPhysicsHit hit;
    bool found = level_raycast_closest(src, dst, &hit, phys_type, include_group, exclude_group, context);

    if (!found) {
        lua_pushnil(L);
        return 1;
    }

    // Build result table
    lua_newtable(L);

    // Normal = {x, y, z}
    lua_newtable(L);
    for (int i = 0; i < 3; i++) {
        lua_pushnumber(L, hit.normal[i]);
        lua_rawseti(L, -2, i + 1);
    }
    lua_setfield(L, -2, "Normal");

    // Position = {x, y, z}
    lua_newtable(L);
    for (int i = 0; i < 3; i++) {
        lua_pushnumber(L, hit.position[i]);
        lua_rawseti(L, -2, i + 1);
    }
    lua_setfield(L, -2, "Position");

    // Distance
    lua_pushnumber(L, hit.distance);
    lua_setfield(L, -2, "Distance");

    // PhysicsGroup
    lua_pushinteger(L, hit.physics_group);
    lua_setfield(L, -2, "PhysicsGroup");

    return 1;
}

/**
 * Ext.Level.RaycastAny(src, dst, physType, includeGroup, excludeGroup, context)
 *   Returns: boolean (true if any hit)
 */
static int lua_level_raycast_any(lua_State *L) {
    float src[3], dst[3];

    if (!read_vec3(L, 1, src)) {
        return luaL_error(L, "Ext.Level.RaycastAny: src must be a {x,y,z} table");
    }
    if (!read_vec3(L, 2, dst)) {
        return luaL_error(L, "Ext.Level.RaycastAny: dst must be a {x,y,z} table");
    }

    uint32_t phys_type = (uint32_t)luaL_optinteger(L, 3, 1);
    uint32_t include_group = (uint32_t)luaL_optinteger(L, 4, 0x7FFFFFFF);
    uint32_t exclude_group = (uint32_t)luaL_optinteger(L, 5, 0);
    int context = (int)luaL_optinteger(L, 6, 0);

    bool hit = level_raycast_any(src, dst, phys_type, include_group, exclude_group, context);
    lua_pushboolean(L, hit);
    return 1;
}

/**
 * Ext.Level.TestBox(pos, extents, physType, includeGroup, excludeGroup)
 *   pos: {x, y, z} table (center position)
 *   extents: {x, y, z} table (half-extents)
 *   Returns: boolean
 */
static int lua_level_test_box(lua_State *L) {
    float pos[3], extents[3];

    if (!read_vec3(L, 1, pos)) {
        return luaL_error(L, "Ext.Level.TestBox: pos must be a {x,y,z} table");
    }
    if (!read_vec3(L, 2, extents)) {
        return luaL_error(L, "Ext.Level.TestBox: extents must be a {x,y,z} table");
    }

    uint32_t phys_type = (uint32_t)luaL_optinteger(L, 3, 1);
    uint32_t include_group = (uint32_t)luaL_optinteger(L, 4, 0x7FFFFFFF);
    uint32_t exclude_group = (uint32_t)luaL_optinteger(L, 5, 0);

    bool overlap = level_test_box(pos, extents, phys_type, include_group, exclude_group);
    lua_pushboolean(L, overlap);
    return 1;
}

/**
 * Ext.Level.TestSphere(pos, radius, physType, includeGroup, excludeGroup)
 *   pos: {x, y, z} table (center position)
 *   radius: number
 *   Returns: boolean
 */
static int lua_level_test_sphere(lua_State *L) {
    float pos[3];

    if (!read_vec3(L, 1, pos)) {
        return luaL_error(L, "Ext.Level.TestSphere: pos must be a {x,y,z} table");
    }

    float radius = (float)luaL_checknumber(L, 2);
    uint32_t phys_type = (uint32_t)luaL_optinteger(L, 3, 1);
    uint32_t include_group = (uint32_t)luaL_optinteger(L, 4, 0x7FFFFFFF);
    uint32_t exclude_group = (uint32_t)luaL_optinteger(L, 5, 0);

    bool overlap = level_test_sphere(pos, radius, phys_type, include_group, exclude_group);
    lua_pushboolean(L, overlap);
    return 1;
}

// ============================================================================
// Tile Queries
// ============================================================================

/**
 * Ext.Level.GetHeightsAt(x, z) -> array of heights (or empty table)
 */
static int lua_level_get_heights_at(lua_State *L) {
    float x = (float)luaL_checknumber(L, 1);
    float z = (float)luaL_checknumber(L, 2);

    float heights[4];
    int count = level_get_heights_at(x, z, heights, 4);

    lua_newtable(L);
    for (int i = 0; i < count; i++) {
        lua_pushnumber(L, heights[i]);
        lua_rawseti(L, -2, i + 1);
    }

    return 1;
}

// ============================================================================
// Registration
// ============================================================================

static const struct luaL_Reg level_functions[] = {
    {"IsReady",            lua_level_is_ready},
    {"GetCurrentLevel",    lua_level_get_current},
    {"GetPhysicsScene",    lua_level_get_physics_scene},
    {"GetAiGrid",          lua_level_get_aigrid},
    {"RaycastClosest",     lua_level_raycast_closest},
    {"RaycastAny",         lua_level_raycast_any},
    {"TestBox",            lua_level_test_box},
    {"TestSphere",         lua_level_test_sphere},
    {"GetHeightsAt",       lua_level_get_heights_at},
    {NULL, NULL}
};

void lua_level_register(lua_State *L, int ext_table_idx) {
    lua_newtable(L);

    for (const struct luaL_Reg *fn = level_functions; fn->name != NULL; fn++) {
        lua_pushcfunction(L, fn->func);
        lua_setfield(L, -2, fn->name);
    }

    lua_setfield(L, ext_table_idx - 1, "Level");
}
