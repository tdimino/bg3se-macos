/**
 * level_manager.h - Level Manager for BG3SE-macOS
 *
 * Provides access to the game's LevelManager, PhysicsScene, and AiGrid
 * for Ext.Level API (raycasting, tile queries, pathfinding).
 */

#ifndef LEVEL_MANAGER_H
#define LEVEL_MANAGER_H

#include <stdbool.h>
#include <stdint.h>

// ============================================================================
// Initialization
// ============================================================================

bool level_manager_init(void *main_binary_base);
bool level_manager_ready(void);

// ============================================================================
// Singleton Access (lazy pointer refresh)
// ============================================================================

void* level_get_manager(void);        // LevelManager*
void* level_get_current(void);        // EoCLevel*
void* level_get_physics_scene(void);  // PhysicsSceneBase*
void* level_get_aigrid(void);         // AiGrid*

// ============================================================================
// Physics Raycast Results
// ============================================================================

typedef struct {
    float normal[3];
    float position[3];
    float distance;
    uint32_t physics_group;
} LevelPhysicsHit;

/**
 * PhysicsHitAll — mirrors phx::PhysicsHitAll from Windows BG3SE.
 * Each field is an Array<T>: ptr (8) + size (4) + capacity (4) = 16 bytes per field.
 * 6 fields × 16 = 96 bytes total. Passed by pointer to RaycastAll VMT function.
 * The callee populates ptr/size (heap-allocated by game engine).
 * Caller must NOT free the inner arrays — they are owned by the game.
 */
typedef struct {
    /* Array<vec3> Normals */
    float   *normals_ptr;
    uint32_t normals_size;
    uint32_t normals_capacity;
    /* Array<vec3> Positions */
    float   *positions_ptr;
    uint32_t positions_size;
    uint32_t positions_capacity;
    /* Array<float> Distances */
    float   *distances_ptr;
    uint32_t distances_size;
    uint32_t distances_capacity;
    /* Array<uint32_t> PhysicsGroup */
    uint32_t *physics_group_ptr;
    uint32_t  physics_group_size;
    uint32_t  physics_group_capacity;
    /* Array<uint32_t> PhysicsExtraFlags */
    uint32_t *extra_flags_ptr;
    uint32_t  extra_flags_size;
    uint32_t  extra_flags_capacity;
    /* Array<void*> Shapes */
    void   **shapes_ptr;
    uint32_t shapes_size;
    uint32_t shapes_capacity;
} LevelPhysicsHitAll;

// ============================================================================
// Physics Functions
// ============================================================================

/**
 * Cast a ray and return the closest hit.
 * @return true if hit found
 */
bool level_raycast_closest(const float src[3], const float dst[3],
                           LevelPhysicsHit *hit,
                           uint32_t physics_type,
                           uint32_t include_group,
                           uint32_t exclude_group,
                           int context);

/**
 * Cast a ray and return all hits.
 * @param out Pre-zeroed LevelPhysicsHitAll; inner arrays are game-owned, do not free.
 * @return true if any hits found (out->normals_size > 0)
 */
bool level_raycast_all(const float src[3], const float dst[3],
                       LevelPhysicsHitAll *out,
                       uint32_t physics_type,
                       uint32_t include_group,
                       uint32_t exclude_group,
                       int context);

/**
 * Cast a ray and check if anything is hit (boolean).
 */
bool level_raycast_any(const float src[3], const float dst[3],
                       uint32_t physics_type,
                       uint32_t include_group,
                       uint32_t exclude_group,
                       int context);

// ============================================================================
// Sweep Functions (VMT[10]-[16])
// ============================================================================

/** Sweep sphere along path, return closest hit. */
bool level_sweep_sphere_closest(const float src[3], const float dst[3],
                                 float radius,
                                 LevelPhysicsHit *hit,
                                 uint32_t physics_type,
                                 uint32_t include_group,
                                 uint32_t exclude_group,
                                 int context);

/** Sweep capsule along path, return closest hit. */
bool level_sweep_capsule_closest(const float src[3], const float dst[3],
                                  float radius, float half_height,
                                  LevelPhysicsHit *hit,
                                  uint32_t physics_type,
                                  uint32_t include_group,
                                  uint32_t exclude_group,
                                  int context);

/** Sweep box along path, return closest hit. */
bool level_sweep_box_closest(const float src[3], const float dst[3],
                              const float extents[3],
                              LevelPhysicsHit *hit,
                              uint32_t physics_type,
                              uint32_t include_group,
                              uint32_t exclude_group,
                              int context);

/** Sweep sphere along path, return all hits. */
bool level_sweep_sphere_all(const float src[3], const float dst[3],
                             float radius,
                             LevelPhysicsHitAll *out,
                             uint32_t physics_type,
                             uint32_t include_group,
                             uint32_t exclude_group,
                             int context);

/** Sweep capsule along path, return all hits. */
bool level_sweep_capsule_all(const float src[3], const float dst[3],
                              float radius, float half_height,
                              LevelPhysicsHitAll *out,
                              uint32_t physics_type,
                              uint32_t include_group,
                              uint32_t exclude_group,
                              int context);

/** Sweep box along path, return all hits. */
bool level_sweep_box_all(const float src[3], const float dst[3],
                          const float extents[3],
                          LevelPhysicsHitAll *out,
                          uint32_t physics_type,
                          uint32_t include_group,
                          uint32_t exclude_group,
                          int context);

/**
 * Test if a box overlaps any physics objects.
 */
bool level_test_box(const float pos[3], const float extents[3],
                    uint32_t physics_type,
                    uint32_t include_group,
                    uint32_t exclude_group);

/**
 * Test if a sphere overlaps any physics objects.
 */
bool level_test_sphere(const float pos[3], float radius,
                       uint32_t physics_type,
                       uint32_t include_group,
                       uint32_t exclude_group);

// ============================================================================
// Tile Queries
// ============================================================================

/**
 * Get ground heights at a position.
 * @param out_heights Output array (caller provides, max 4 entries)
 * @return Number of heights written
 */
int level_get_heights_at(float x, float z, float *out_heights, int max_heights);

#endif // LEVEL_MANAGER_H
