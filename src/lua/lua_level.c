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
 *   Ext.Level.RaycastAll(src, dst, physType, includeGroup, excludeGroup, context) -> array of hit tables
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

/* Forward declarations for shared hit-result helpers */
static int push_hit_or_nil(lua_State *L, bool found, const LevelPhysicsHit *hit);
static int push_hit_all(lua_State *L, const LevelPhysicsHitAll *hits);

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
 * Ext.Level.RaycastAll(src, dst, physType, includeGroup, excludeGroup, context)
 *   src: {x, y, z} table
 *   dst: {x, y, z} table
 *   physType: integer (physics type flags)
 *   includeGroup: integer (group mask)
 *   excludeGroup: integer (group mask)
 *   context: integer (raycast context)
 *   Returns: array of hit tables {Normal={x,y,z}, Position={x,y,z}, Distance=n, PhysicsGroup=n}
 *            or empty table if no hits
 */
static int lua_level_raycast_all(lua_State *L) {
    float src[3], dst[3];

    if (!read_vec3(L, 1, src)) {
        return luaL_error(L, "Ext.Level.RaycastAll: src must be a {x,y,z} table");
    }
    if (!read_vec3(L, 2, dst)) {
        return luaL_error(L, "Ext.Level.RaycastAll: dst must be a {x,y,z} table");
    }

    uint32_t phys_type    = (uint32_t)luaL_optinteger(L, 3, 1);
    uint32_t include_group = (uint32_t)luaL_optinteger(L, 4, 0x7FFFFFFF);
    uint32_t exclude_group = (uint32_t)luaL_optinteger(L, 5, 0);
    int context           = (int)luaL_optinteger(L, 6, 0);

    LevelPhysicsHitAll hits;
    level_raycast_all(src, dst, &hits, phys_type, include_group, exclude_group, context);
    return push_hit_all(L, &hits);
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
// Sweep Functions
// ============================================================================

/**
 * Push a single LevelPhysicsHit as a Lua table (or nil if not found).
 */
static int push_hit_or_nil(lua_State *L, bool found, const LevelPhysicsHit *hit) {
    if (!found) {
        lua_pushnil(L);
        return 1;
    }
    lua_newtable(L);

    lua_newtable(L);
    for (int i = 0; i < 3; i++) { lua_pushnumber(L, hit->normal[i]); lua_rawseti(L, -2, i+1); }
    lua_setfield(L, -2, "Normal");

    lua_newtable(L);
    for (int i = 0; i < 3; i++) { lua_pushnumber(L, hit->position[i]); lua_rawseti(L, -2, i+1); }
    lua_setfield(L, -2, "Position");

    lua_pushnumber(L, hit->distance);
    lua_setfield(L, -2, "Distance");

    lua_pushinteger(L, hit->physics_group);
    lua_setfield(L, -2, "PhysicsGroup");

    return 1;
}

/**
 * Push a LevelPhysicsHitAll as a Lua array of hit tables.
 * VERIFIED: Normals/Positions are Array<glm::vec3> where glm::vec3 = float[3] (12 bytes, no padding).
 * Stride is 3 floats per element — confirmed from Windows BG3SE Physics.h:PhysicsHitAll.
 */
static int push_hit_all(lua_State *L, const LevelPhysicsHitAll *hits) {
    lua_newtable(L);

    uint32_t count = hits->normals_size;
    if (hits->positions_size < count) count = hits->positions_size;
    if (hits->distances_size < count) count = hits->distances_size;

    for (uint32_t i = 0; i < count; i++) {
        lua_newtable(L);

        lua_newtable(L);
        float *n = hits->normals_ptr + i * 3;
        for (int j = 0; j < 3; j++) { lua_pushnumber(L, n[j]); lua_rawseti(L, -2, j+1); }
        lua_setfield(L, -2, "Normal");

        lua_newtable(L);
        float *p = hits->positions_ptr + i * 3;
        for (int j = 0; j < 3; j++) { lua_pushnumber(L, p[j]); lua_rawseti(L, -2, j+1); }
        lua_setfield(L, -2, "Position");

        lua_pushnumber(L, hits->distances_ptr[i]);
        lua_setfield(L, -2, "Distance");

        if (hits->physics_group_ptr && i < hits->physics_group_size) {
            lua_pushinteger(L, hits->physics_group_ptr[i]);
        } else {
            lua_pushinteger(L, 0);
        }
        lua_setfield(L, -2, "PhysicsGroup");

        lua_rawseti(L, -2, (int)(i + 1));
    }
    return 1;
}

/**
 * Ext.Level.SweepSphereClosest(src, dst, radius, physType, includeGroup, excludeGroup, context)
 *   Returns: hit table or nil
 */
static int lua_level_sweep_sphere_closest(lua_State *L) {
    float src[3], dst[3];
    if (!read_vec3(L, 1, src)) return luaL_error(L, "SweepSphereClosest: src must be {x,y,z}");
    if (!read_vec3(L, 2, dst)) return luaL_error(L, "SweepSphereClosest: dst must be {x,y,z}");
    float radius           = (float)luaL_checknumber(L, 3);
    uint32_t phys_type     = (uint32_t)luaL_optinteger(L, 4, 1);
    uint32_t include_group = (uint32_t)luaL_optinteger(L, 5, 0x7FFFFFFF);
    uint32_t exclude_group = (uint32_t)luaL_optinteger(L, 6, 0);
    int context            = (int)luaL_optinteger(L, 7, 0);
    LevelPhysicsHit hit;
    bool found = level_sweep_sphere_closest(src, dst, radius, &hit,
                                             phys_type, include_group, exclude_group, context);
    return push_hit_or_nil(L, found, &hit);
}

/**
 * Ext.Level.SweepSphereAll(src, dst, radius, physType, includeGroup, excludeGroup, context)
 *   Returns: array of hit tables
 */
static int lua_level_sweep_sphere_all(lua_State *L) {
    float src[3], dst[3];
    if (!read_vec3(L, 1, src)) return luaL_error(L, "SweepSphereAll: src must be {x,y,z}");
    if (!read_vec3(L, 2, dst)) return luaL_error(L, "SweepSphereAll: dst must be {x,y,z}");
    float radius           = (float)luaL_checknumber(L, 3);
    uint32_t phys_type     = (uint32_t)luaL_optinteger(L, 4, 1);
    uint32_t include_group = (uint32_t)luaL_optinteger(L, 5, 0x7FFFFFFF);
    uint32_t exclude_group = (uint32_t)luaL_optinteger(L, 6, 0);
    int context            = (int)luaL_optinteger(L, 7, 0);
    LevelPhysicsHitAll hits;
    level_sweep_sphere_all(src, dst, radius, &hits,
                            phys_type, include_group, exclude_group, context);
    return push_hit_all(L, &hits);
}

/**
 * Ext.Level.SweepCapsuleClosest(src, dst, radius, halfHeight, physType, includeGroup, excludeGroup, context)
 *   Returns: hit table or nil
 */
static int lua_level_sweep_capsule_closest(lua_State *L) {
    float src[3], dst[3];
    if (!read_vec3(L, 1, src)) return luaL_error(L, "SweepCapsuleClosest: src must be {x,y,z}");
    if (!read_vec3(L, 2, dst)) return luaL_error(L, "SweepCapsuleClosest: dst must be {x,y,z}");
    float radius           = (float)luaL_checknumber(L, 3);
    float half_height      = (float)luaL_checknumber(L, 4);
    uint32_t phys_type     = (uint32_t)luaL_optinteger(L, 5, 1);
    uint32_t include_group = (uint32_t)luaL_optinteger(L, 6, 0x7FFFFFFF);
    uint32_t exclude_group = (uint32_t)luaL_optinteger(L, 7, 0);
    int context            = (int)luaL_optinteger(L, 8, 0);
    LevelPhysicsHit hit;
    bool found = level_sweep_capsule_closest(src, dst, radius, half_height, &hit,
                                              phys_type, include_group, exclude_group, context);
    return push_hit_or_nil(L, found, &hit);
}

/**
 * Ext.Level.SweepCapsuleAll(src, dst, radius, halfHeight, physType, includeGroup, excludeGroup, context)
 *   Returns: array of hit tables
 */
static int lua_level_sweep_capsule_all(lua_State *L) {
    float src[3], dst[3];
    if (!read_vec3(L, 1, src)) return luaL_error(L, "SweepCapsuleAll: src must be {x,y,z}");
    if (!read_vec3(L, 2, dst)) return luaL_error(L, "SweepCapsuleAll: dst must be {x,y,z}");
    float radius           = (float)luaL_checknumber(L, 3);
    float half_height      = (float)luaL_checknumber(L, 4);
    uint32_t phys_type     = (uint32_t)luaL_optinteger(L, 5, 1);
    uint32_t include_group = (uint32_t)luaL_optinteger(L, 6, 0x7FFFFFFF);
    uint32_t exclude_group = (uint32_t)luaL_optinteger(L, 7, 0);
    int context            = (int)luaL_optinteger(L, 8, 0);
    LevelPhysicsHitAll hits;
    level_sweep_capsule_all(src, dst, radius, half_height, &hits,
                             phys_type, include_group, exclude_group, context);
    return push_hit_all(L, &hits);
}

/**
 * Ext.Level.SweepBoxClosest(src, dst, extents, physType, includeGroup, excludeGroup, context)
 *   extents: {x, y, z} half-extents
 *   Returns: hit table or nil
 */
static int lua_level_sweep_box_closest(lua_State *L) {
    float src[3], dst[3], extents[3];
    if (!read_vec3(L, 1, src))     return luaL_error(L, "SweepBoxClosest: src must be {x,y,z}");
    if (!read_vec3(L, 2, dst))     return luaL_error(L, "SweepBoxClosest: dst must be {x,y,z}");
    if (!read_vec3(L, 3, extents)) return luaL_error(L, "SweepBoxClosest: extents must be {x,y,z}");
    uint32_t phys_type     = (uint32_t)luaL_optinteger(L, 4, 1);
    uint32_t include_group = (uint32_t)luaL_optinteger(L, 5, 0x7FFFFFFF);
    uint32_t exclude_group = (uint32_t)luaL_optinteger(L, 6, 0);
    int context            = (int)luaL_optinteger(L, 7, 0);
    LevelPhysicsHit hit;
    bool found = level_sweep_box_closest(src, dst, extents, &hit,
                                          phys_type, include_group, exclude_group, context);
    return push_hit_or_nil(L, found, &hit);
}

/**
 * Ext.Level.SweepBoxAll(src, dst, extents, physType, includeGroup, excludeGroup, context)
 *   extents: {x, y, z} half-extents
 *   Returns: array of hit tables
 */
static int lua_level_sweep_box_all(lua_State *L) {
    float src[3], dst[3], extents[3];
    if (!read_vec3(L, 1, src))     return luaL_error(L, "SweepBoxAll: src must be {x,y,z}");
    if (!read_vec3(L, 2, dst))     return luaL_error(L, "SweepBoxAll: dst must be {x,y,z}");
    if (!read_vec3(L, 3, extents)) return luaL_error(L, "SweepBoxAll: extents must be {x,y,z}");
    uint32_t phys_type     = (uint32_t)luaL_optinteger(L, 4, 1);
    uint32_t include_group = (uint32_t)luaL_optinteger(L, 5, 0x7FFFFFFF);
    uint32_t exclude_group = (uint32_t)luaL_optinteger(L, 6, 0);
    int context            = (int)luaL_optinteger(L, 7, 0);
    LevelPhysicsHitAll hits;
    level_sweep_box_all(src, dst, extents, &hits,
                         phys_type, include_group, exclude_group, context);
    return push_hit_all(L, &hits);
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
    {"RaycastClosest",       lua_level_raycast_closest},
    {"RaycastAll",           lua_level_raycast_all},
    {"RaycastAny",           lua_level_raycast_any},
    {"SweepSphereClosest",   lua_level_sweep_sphere_closest},
    {"SweepSphereAll",       lua_level_sweep_sphere_all},
    {"SweepCapsuleClosest",  lua_level_sweep_capsule_closest},
    {"SweepCapsuleAll",      lua_level_sweep_capsule_all},
    {"SweepBoxClosest",      lua_level_sweep_box_closest},
    {"SweepBoxAll",          lua_level_sweep_box_all},
    {"TestBox",              lua_level_test_box},
    {"TestSphere",           lua_level_test_sphere},
    {"GetHeightsAt",         lua_level_get_heights_at},
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
