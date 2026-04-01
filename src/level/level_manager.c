/**
 * level_manager.c - Level Manager for BG3SE-macOS
 *
 * Provides access to the game's LevelManager, PhysicsScene, and AiGrid
 * for Ext.Level API (raycasting, tile queries, pathfinding).
 *
 * Access chain:
 *   LevelManager::m_ptr -> LevelManager* -> CurrentLevel (+0x90)
 *     -> EoCLevel* -> PhysicsScene (+0x30), AiGrid (+0x80)
 *
 * Note: PhysicsScene and AiGrid offsets are from Windows BG3SE and need
 * runtime verification on ARM64. These are best-effort values.
 */

#include "level_manager.h"
#include "../core/logging.h"
#include "../core/safe_memory.h"
#include <string.h>

// ============================================================================
// Constants and Offsets
// ============================================================================

// LevelManager::m_ptr global singleton
// Same address used in template_manager.c
#define OFFSET_LEVEL_MANAGER_PTR    0x08a3be40

// LevelManager internal offsets (need ARM64 runtime verification)
#define LEVELMANAGER_CURRENT_LEVEL_OFFSET   0x90   // EoCLevel* CurrentLevel

// EoCLevel offsets (need ARM64 runtime verification)
#define EOCLEVEL_PHYSICS_SCENE_OFFSET       0x30   // PhysicsSceneBase*
#define EOCLEVEL_AIGRID_OFFSET              0x80   // AiGrid*

// PhysicsScene VMT indices (from Windows BG3SE Physics.h vtable layout)
// Derived from sequential vtable: dtor(0), InstantiateReadLock(1), Unload(2),
// AddPhysicsObjects(3), RemovePhysicsObjects(4), AddPhysicsShape(5),
// RemovePhysicsShape(6), then Raycast/Sweep/Test in declaration order.
#define PHYSICS_VMT_RAYCAST_CLOSEST     7
#define PHYSICS_VMT_RAYCAST_ALL         8
#define PHYSICS_VMT_RAYCAST_ANY         9
#define PHYSICS_VMT_SWEEP_SPHERE_CLOSEST    10
#define PHYSICS_VMT_SWEEP_CAPSULE_CLOSEST   11
#define PHYSICS_VMT_SWEEP_BOX_CLOSEST       12
#define PHYSICS_VMT_SWEEP_CYLINDER_CLOSEST  13   /* SweepCylinderClosest — not exposed in Lua */
#define PHYSICS_VMT_SWEEP_SPHERE_ALL        14
#define PHYSICS_VMT_SWEEP_CAPSULE_ALL       15
#define PHYSICS_VMT_SWEEP_BOX_ALL           16
#define PHYSICS_VMT_SWEEP_CYLINDER_ALL      17   /* SweepCylinderAll — not exposed in Lua */
#define PHYSICS_VMT_SWEEP_SHAPE_ALL         18   /* SweepShapeAll — not exposed in Lua */
#define PHYSICS_VMT_TEST_BOX           20
#define PHYSICS_VMT_TEST_SPHERE        24

// ============================================================================
// Module State
// ============================================================================

static struct {
    bool initialized;
    void *main_binary_base;
    void **level_manager_ptr;  // Points to global slot
} g_level = {0};

// ============================================================================
// Initialization
// ============================================================================

bool level_manager_init(void *main_binary_base) {
    if (g_level.initialized) {
        return true;
    }

    if (!main_binary_base) {
        log_message("[Level] ERROR: main_binary_base is NULL");
        return false;
    }

    g_level.main_binary_base = main_binary_base;
    g_level.level_manager_ptr = (void **)((uintptr_t)main_binary_base + OFFSET_LEVEL_MANAGER_PTR);

    log_message("[Level] Level manager initialized");
    log_message("[Level]   Base: %p", main_binary_base);
    log_message("[Level]   LevelManager::m_ptr at offset 0x%x -> %p",
                OFFSET_LEVEL_MANAGER_PTR, (void *)g_level.level_manager_ptr);

    g_level.initialized = true;
    return true;
}

bool level_manager_ready(void) {
    if (!g_level.initialized || !g_level.level_manager_ptr) {
        return false;
    }

    void *mgr = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)g_level.level_manager_ptr, &mgr)) {
        return false;
    }

    return mgr != NULL;
}

// ============================================================================
// Singleton Access
// ============================================================================

void *level_get_manager(void) {
    if (!g_level.initialized || !g_level.level_manager_ptr) {
        return NULL;
    }

    void *mgr = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)g_level.level_manager_ptr, &mgr)) {
        return NULL;
    }

    return mgr;
}

void *level_get_current(void) {
    void *mgr = level_get_manager();
    if (!mgr) return NULL;

    void *current = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)mgr + LEVELMANAGER_CURRENT_LEVEL_OFFSET, &current)) {
        return NULL;
    }

    return current;
}

void *level_get_physics_scene(void) {
    void *level = level_get_current();
    if (!level) return NULL;

    void *physics = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)level + EOCLEVEL_PHYSICS_SCENE_OFFSET, &physics)) {
        return NULL;
    }

    return physics;
}

void *level_get_aigrid(void) {
    void *level = level_get_current();
    if (!level) return NULL;

    void *aigrid = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)level + EOCLEVEL_AIGRID_OFFSET, &aigrid)) {
        return NULL;
    }

    return aigrid;
}

// ============================================================================
// VMT Call Helper
// ============================================================================

/**
 * Read a function pointer from a VMT at a given index.
 */
static void *read_vmt_entry(void *object, int index) {
    if (!object) return NULL;

    // Read VMT pointer at +0x00
    void *vmt = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)object, &vmt)) {
        return NULL;
    }

    // Read function pointer at VMT[index]
    void *func = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)vmt + (index * sizeof(void *)), &func)) {
        return NULL;
    }

    return func;
}

// ============================================================================
// Physics Functions
// ============================================================================

/**
 * PhysicsScene::RaycastClosest signature (from Windows):
 *   bool RaycastClosest(PhysicsHit* hit, vec3 src, vec3 dst,
 *                       uint32_t physType, uint32_t includeGroup,
 *                       uint32_t excludeGroup, int context)
 *
 * On ARM64 with >16 byte return or many params, some may go on stack.
 * For now these are stub implementations that return false until
 * offsets are verified at runtime.
 */

typedef bool (*PhysicsRaycastClosestFn)(void *this_, LevelPhysicsHit *hit,
                                         float sx, float sy, float sz,
                                         float dx, float dy, float dz,
                                         uint32_t physType,
                                         uint32_t includeGroup,
                                         uint32_t excludeGroup,
                                         int context);

/**
 * PhysicsScene::RaycastAll signature (from Windows, VMT[8]):
 *   bool RaycastAll(vec3 src, vec3 dst, PhysicsHitAll& hits,
 *                   uint32_t physType, uint32_t includeGroup,
 *                   uint32_t excludeGroup, int context,
 *                   int physObjIdx, int excludePhysObjIdx,
 *                   optional<ScopedReadLock*>)
 *
 * PhysicsHitAll is passed by reference (pointer), so no x8 indirect return needed.
 * The bool return fits in x0 directly.
 */
typedef bool (*PhysicsRaycastAllFn)(void *this_,
                                     float sx, float sy, float sz,
                                     float dx, float dy, float dz,
                                     LevelPhysicsHitAll *hits,
                                     uint32_t physType,
                                     uint32_t includeGroup,
                                     uint32_t excludeGroup,
                                     int context,
                                     int physObjIdx,
                                     int excludePhysObjIdx,
                                     void *optLock);  /* std::optional<ScopedReadLock*> = nullptr */

typedef bool (*PhysicsRaycastAnyFn)(void *this_,
                                     float sx, float sy, float sz,
                                     float dx, float dy, float dz,
                                     uint32_t physType,
                                     uint32_t includeGroup,
                                     uint32_t excludeGroup,
                                     int context);

typedef bool (*PhysicsTestBoxFn)(void *this_,
                                  float px, float py, float pz,
                                  float ex, float ey, float ez,
                                  uint32_t physType,
                                  uint32_t includeGroup,
                                  uint32_t excludeGroup);

typedef bool (*PhysicsTestSphereFn)(void *this_,
                                     float px, float py, float pz,
                                     float radius,
                                     uint32_t physType,
                                     uint32_t includeGroup,
                                     uint32_t excludeGroup);

// ============================================================================
// Sweep Function Types
// ============================================================================

/**
 * SweepSphereClosest — VMT[10]
 * Windows: bool SweepSphereClosest(float radius, vec3 src, vec3 dst,
 *                                  PhysicsHit& hit, physType, include, exclude,
 *                                  context, physObjIdx, excludePhysObjIdx)
 * Single hit by reference — no x8 indirect needed (bool return).
 */
typedef bool (*PhysicsSweepSphereClosestFn)(void *this_,
                                             float radius,
                                             float sx, float sy, float sz,
                                             float dx, float dy, float dz,
                                             LevelPhysicsHit *hit,
                                             uint32_t physType,
                                             uint32_t includeGroup,
                                             uint32_t excludeGroup,
                                             int context,
                                             int physObjIdx,
                                             int excludePhysObjIdx);

typedef bool (*PhysicsSweepCapsuleClosestFn)(void *this_,
                                              float radius, float halfHeight,
                                              float sx, float sy, float sz,
                                              float dx, float dy, float dz,
                                              LevelPhysicsHit *hit,
                                              uint32_t physType,
                                              uint32_t includeGroup,
                                              uint32_t excludeGroup,
                                              int context,
                                              int physObjIdx,
                                              int excludePhysObjIdx);

typedef bool (*PhysicsSweepBoxClosestFn)(void *this_,
                                          float ex, float ey, float ez,   /* extents */
                                          float sx, float sy, float sz,
                                          float dx, float dy, float dz,
                                          LevelPhysicsHit *hit,
                                          uint32_t physType,
                                          uint32_t includeGroup,
                                          uint32_t excludeGroup,
                                          int context,
                                          int physObjIdx,
                                          int excludePhysObjIdx);

/**
 * SweepSphereAll — VMT[14]
 * Windows: bool SweepSphereAll(float radius, vec3 src, vec3 dst,
 *                              PhysicsHitAll& hits, physType, include, exclude,
 *                              context, physObjIdx, excludePhysObjIdx)
 */
typedef bool (*PhysicsSweepSphereAllFn)(void *this_,
                                         float radius,
                                         float sx, float sy, float sz,
                                         float dx, float dy, float dz,
                                         LevelPhysicsHitAll *hits,
                                         uint32_t physType,
                                         uint32_t includeGroup,
                                         uint32_t excludeGroup,
                                         int context,
                                         int physObjIdx,
                                         int excludePhysObjIdx);

typedef bool (*PhysicsSweepCapsuleAllFn)(void *this_,
                                          float radius, float halfHeight,
                                          float sx, float sy, float sz,
                                          float dx, float dy, float dz,
                                          LevelPhysicsHitAll *hits,
                                          uint32_t physType,
                                          uint32_t includeGroup,
                                          uint32_t excludeGroup,
                                          int context,
                                          int physObjIdx,
                                          int excludePhysObjIdx);

typedef bool (*PhysicsSweepBoxAllFn)(void *this_,
                                      float ex, float ey, float ez,   /* extents */
                                      float sx, float sy, float sz,
                                      float dx, float dy, float dz,
                                      LevelPhysicsHitAll *hits,
                                      uint32_t physType,
                                      uint32_t includeGroup,
                                      uint32_t excludeGroup,
                                      int context,
                                      int physObjIdx,
                                      int excludePhysObjIdx);

// ============================================================================
// Sweep Implementations — Closest (single hit)
// ============================================================================

bool level_sweep_sphere_closest(const float src[3], const float dst[3],
                                 float radius,
                                 LevelPhysicsHit *hit,
                                 uint32_t physics_type,
                                 uint32_t include_group,
                                 uint32_t exclude_group,
                                 int context) {
    if (!hit) return false;
    memset(hit, 0, sizeof(*hit));

    void *physics = level_get_physics_scene();
    if (!physics) return false;

    void *func = read_vmt_entry(physics, PHYSICS_VMT_SWEEP_SPHERE_CLOSEST);
    if (!func) {
        log_message("[Level] SweepSphereClosest VMT entry not found at index %d",
                    PHYSICS_VMT_SWEEP_SPHERE_CLOSEST);
        return false;
    }

    PhysicsSweepSphereClosestFn sweep = (PhysicsSweepSphereClosestFn)func;
    return sweep(physics,
                 radius,
                 src[0], src[1], src[2],
                 dst[0], dst[1], dst[2],
                 hit,
                 physics_type, include_group, exclude_group,
                 context, -1, -1);
}

bool level_sweep_capsule_closest(const float src[3], const float dst[3],
                                  float radius, float half_height,
                                  LevelPhysicsHit *hit,
                                  uint32_t physics_type,
                                  uint32_t include_group,
                                  uint32_t exclude_group,
                                  int context) {
    if (!hit) return false;
    memset(hit, 0, sizeof(*hit));

    void *physics = level_get_physics_scene();
    if (!physics) return false;

    void *func = read_vmt_entry(physics, PHYSICS_VMT_SWEEP_CAPSULE_CLOSEST);
    if (!func) {
        log_message("[Level] SweepCapsuleClosest VMT entry not found at index %d",
                    PHYSICS_VMT_SWEEP_CAPSULE_CLOSEST);
        return false;
    }

    PhysicsSweepCapsuleClosestFn sweep = (PhysicsSweepCapsuleClosestFn)func;
    return sweep(physics,
                 radius, half_height,
                 src[0], src[1], src[2],
                 dst[0], dst[1], dst[2],
                 hit,
                 physics_type, include_group, exclude_group,
                 context, -1, -1);
}

bool level_sweep_box_closest(const float src[3], const float dst[3],
                              const float extents[3],
                              LevelPhysicsHit *hit,
                              uint32_t physics_type,
                              uint32_t include_group,
                              uint32_t exclude_group,
                              int context) {
    if (!hit) return false;
    memset(hit, 0, sizeof(*hit));

    void *physics = level_get_physics_scene();
    if (!physics) return false;

    void *func = read_vmt_entry(physics, PHYSICS_VMT_SWEEP_BOX_CLOSEST);
    if (!func) {
        log_message("[Level] SweepBoxClosest VMT entry not found at index %d",
                    PHYSICS_VMT_SWEEP_BOX_CLOSEST);
        return false;
    }

    PhysicsSweepBoxClosestFn sweep = (PhysicsSweepBoxClosestFn)func;
    return sweep(physics,
                 extents[0], extents[1], extents[2],
                 src[0], src[1], src[2],
                 dst[0], dst[1], dst[2],
                 hit,
                 physics_type, include_group, exclude_group,
                 context, -1, -1);
}

// ============================================================================
// Sweep Implementations — All (multiple hits)
// ============================================================================

bool level_sweep_sphere_all(const float src[3], const float dst[3],
                             float radius,
                             LevelPhysicsHitAll *out,
                             uint32_t physics_type,
                             uint32_t include_group,
                             uint32_t exclude_group,
                             int context) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));

    void *physics = level_get_physics_scene();
    if (!physics) return false;

    void *func = read_vmt_entry(physics, PHYSICS_VMT_SWEEP_SPHERE_ALL);
    if (!func) {
        log_message("[Level] SweepSphereAll VMT entry not found at index %d",
                    PHYSICS_VMT_SWEEP_SPHERE_ALL);
        return false;
    }

    PhysicsSweepSphereAllFn sweep = (PhysicsSweepSphereAllFn)func;
    return sweep(physics,
                 radius,
                 src[0], src[1], src[2],
                 dst[0], dst[1], dst[2],
                 out,
                 physics_type, include_group, exclude_group,
                 context, -1, -1);
}

bool level_sweep_capsule_all(const float src[3], const float dst[3],
                              float radius, float half_height,
                              LevelPhysicsHitAll *out,
                              uint32_t physics_type,
                              uint32_t include_group,
                              uint32_t exclude_group,
                              int context) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));

    void *physics = level_get_physics_scene();
    if (!physics) return false;

    void *func = read_vmt_entry(physics, PHYSICS_VMT_SWEEP_CAPSULE_ALL);
    if (!func) {
        log_message("[Level] SweepCapsuleAll VMT entry not found at index %d",
                    PHYSICS_VMT_SWEEP_CAPSULE_ALL);
        return false;
    }

    PhysicsSweepCapsuleAllFn sweep = (PhysicsSweepCapsuleAllFn)func;
    return sweep(physics,
                 radius, half_height,
                 src[0], src[1], src[2],
                 dst[0], dst[1], dst[2],
                 out,
                 physics_type, include_group, exclude_group,
                 context, -1, -1);
}

bool level_sweep_box_all(const float src[3], const float dst[3],
                          const float extents[3],
                          LevelPhysicsHitAll *out,
                          uint32_t physics_type,
                          uint32_t include_group,
                          uint32_t exclude_group,
                          int context) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));

    void *physics = level_get_physics_scene();
    if (!physics) return false;

    void *func = read_vmt_entry(physics, PHYSICS_VMT_SWEEP_BOX_ALL);
    if (!func) {
        log_message("[Level] SweepBoxAll VMT entry not found at index %d",
                    PHYSICS_VMT_SWEEP_BOX_ALL);
        return false;
    }

    PhysicsSweepBoxAllFn sweep = (PhysicsSweepBoxAllFn)func;
    return sweep(physics,
                 extents[0], extents[1], extents[2],
                 src[0], src[1], src[2],
                 dst[0], dst[1], dst[2],
                 out,
                 physics_type, include_group, exclude_group,
                 context, -1, -1);
}

bool level_raycast_all(const float src[3], const float dst[3],
                       LevelPhysicsHitAll *out,
                       uint32_t physics_type,
                       uint32_t include_group,
                       uint32_t exclude_group,
                       int context) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));

    void *physics = level_get_physics_scene();
    if (!physics) {
        log_message("[Level] PhysicsScene not available for RaycastAll");
        return false;
    }

    void *func = read_vmt_entry(physics, PHYSICS_VMT_RAYCAST_ALL);
    if (!func) {
        log_message("[Level] RaycastAll VMT entry not found at index %d", PHYSICS_VMT_RAYCAST_ALL);
        return false;
    }

    PhysicsRaycastAllFn raycast = (PhysicsRaycastAllFn)func;
    bool hit = raycast(physics,
                       src[0], src[1], src[2],
                       dst[0], dst[1], dst[2],
                       out,
                       physics_type, include_group, exclude_group,
                       context,
                       -1, -1,
                       NULL);

    log_message("[Level] RaycastAll: hit=%d, count=%u", hit, out->normals_size);
    return hit;
}

bool level_raycast_closest(const float src[3], const float dst[3],
                           LevelPhysicsHit *hit,
                           uint32_t physics_type,
                           uint32_t include_group,
                           uint32_t exclude_group,
                           int context) {
    if (!hit) return false;
    memset(hit, 0, sizeof(*hit));

    void *physics = level_get_physics_scene();
    if (!physics) {
        log_message("[Level] PhysicsScene not available");
        return false;
    }

    void *func = read_vmt_entry(physics, PHYSICS_VMT_RAYCAST_CLOSEST);
    if (!func) {
        log_message("[Level] RaycastClosest VMT entry not found");
        return false;
    }

    PhysicsRaycastClosestFn raycast = (PhysicsRaycastClosestFn)func;
    return raycast(physics, hit,
                   src[0], src[1], src[2],
                   dst[0], dst[1], dst[2],
                   physics_type, include_group, exclude_group, context);
}

bool level_raycast_any(const float src[3], const float dst[3],
                       uint32_t physics_type,
                       uint32_t include_group,
                       uint32_t exclude_group,
                       int context) {
    void *physics = level_get_physics_scene();
    if (!physics) {
        log_message("[Level] PhysicsScene not available");
        return false;
    }

    void *func = read_vmt_entry(physics, PHYSICS_VMT_RAYCAST_ANY);
    if (!func) {
        log_message("[Level] RaycastAny VMT entry not found");
        return false;
    }

    PhysicsRaycastAnyFn raycast = (PhysicsRaycastAnyFn)func;
    return raycast(physics,
                   src[0], src[1], src[2],
                   dst[0], dst[1], dst[2],
                   physics_type, include_group, exclude_group, context);
}

bool level_test_box(const float pos[3], const float extents[3],
                    uint32_t physics_type,
                    uint32_t include_group,
                    uint32_t exclude_group) {
    void *physics = level_get_physics_scene();
    if (!physics) return false;

    void *func = read_vmt_entry(physics, PHYSICS_VMT_TEST_BOX);
    if (!func) return false;

    PhysicsTestBoxFn test = (PhysicsTestBoxFn)func;
    return test(physics,
                pos[0], pos[1], pos[2],
                extents[0], extents[1], extents[2],
                physics_type, include_group, exclude_group);
}

bool level_test_sphere(const float pos[3], float radius,
                       uint32_t physics_type,
                       uint32_t include_group,
                       uint32_t exclude_group) {
    void *physics = level_get_physics_scene();
    if (!physics) return false;

    void *func = read_vmt_entry(physics, PHYSICS_VMT_TEST_SPHERE);
    if (!func) return false;

    PhysicsTestSphereFn test = (PhysicsTestSphereFn)func;
    return test(physics,
                pos[0], pos[1], pos[2],
                radius,
                physics_type, include_group, exclude_group);
}

// ============================================================================
// Tile Queries
// ============================================================================

int level_get_heights_at(float x, float z, float *out_heights, int max_heights) {
    if (!out_heights || max_heights <= 0) return 0;

    void *aigrid = level_get_aigrid();
    if (!aigrid) {
        log_message("[Level] AiGrid not available");
        return 0;
    }

    // AiGrid tile height lookup requires internal structure knowledge.
    // This is a stub until AiGrid offsets are verified at runtime.
    // The AiGrid typically stores tile data in a grid indexed by (x,z) coords.
    (void)x;
    (void)z;
    log_message("[Level] GetHeightsAt: AiGrid offsets not yet verified (stub)");
    return 0;
}
