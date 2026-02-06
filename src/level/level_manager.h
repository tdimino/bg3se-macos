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
 * Cast a ray and check if anything is hit (boolean).
 */
bool level_raycast_any(const float src[3], const float dst[3],
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
