# Physics & Level System Offsets

**Platform:** macOS ARM64
**Discovered:** 2026-04-01 (Qedeshot parity swarm)
**Source:** Windows reference `Physics.h:146-184` + Ghidra verification

## PhysicsSceneBase Virtual Method Table

VMT layout confirmed from Windows `PhysicsSceneBase` declaration. RaycastAll=VMT[8] verified
via Ghidra decompilation of known RaycastClosest at VMT[7].

| VMT Index | Function | Implemented | Notes |
|-----------|----------|-------------|-------|
| 0-6 | (base vtable) | — | Destructor, unknown |
| 7 | RaycastClosest | ✅ existing | Single-hit raycast |
| 8 | RaycastAll | ✅ swarm | Multi-hit raycast |
| 9 | RaycastAny | ✅ existing | Boolean hit test |
| 10 | SweepSphereClosest | ✅ swarm | |
| 11 | SweepCapsuleClosest | ✅ swarm | |
| 12 | SweepBoxClosest | ✅ swarm | |
| 13 | (unknown) | — | |
| 14 | SweepSphereAll | ✅ swarm | Returns PhysicsHitAll |
| 15 | SweepCapsuleAll | ✅ swarm | Returns PhysicsHitAll |
| 16 | SweepBoxAll | ✅ swarm | Returns PhysicsHitAll |
| 17-19 | (unknown) | — | |
| 20 | TestBox | ✅ existing | Boolean overlap test |
| 21-23 | (unknown) | — | |
| 24 | TestSphere | ✅ existing | Boolean overlap test |

## PhysicsHitAll Return Structure

Sweep*All functions write results into a `PhysicsHitAll` struct (pass by reference, NOT
x8 indirect return — it's an input param despite being the output destination).

```c
typedef struct {
    // 6 arrays, each as (ptr, size, capacity) triple = 24 bytes each
    float* positions;      uint64_t pos_size;      uint64_t pos_cap;      // 0x00
    float* normals;        uint64_t norm_size;     uint64_t norm_cap;     // 0x18
    float* distances;      uint64_t dist_size;     uint64_t dist_cap;     // 0x30
    uint32_t* materials;   uint64_t mat_size;      uint64_t mat_cap;      // 0x48
    void** objects;        uint64_t obj_size;       uint64_t obj_cap;     // 0x60
    void** actors;         uint64_t act_size;       uint64_t act_cap;     // 0x78
} LevelPhysicsHitAll;  // 96 bytes total
```

**Stride note:** `glm::vec3 = float[3]` (12 bytes, no padding to vec4). Position/normal
arrays are tightly packed `float[3]` per element, stride = 3 floats.

## VMT Access Pattern

All physics functions use safe VMT dispatch via `read_vmt_entry()`:

```c
void* fn = read_vmt_entry(physics_scene, PHYSICS_VMT_SWEEP_SPHERE_CLOSEST);
if (fn) {
    ((SweepClosestFn)fn)(physics_scene, origin, direction, maxDist, result);
}
```

`read_vmt_entry()` calls `safe_memory_read_pointer()` for crash-safe pointer dereference.

## Level Manager Singletons

| Symbol | Address | Notes |
|--------|---------|-------|
| PhysicsScene access | via LevelManager | `level_get_physics_scene()` |
| AiGrid access | via LevelManager | `level_get_aigrid()` |

## References

- Windows BG3SE: `BG3Extender/GameDefinitions/Level/Physics.h`
- Implementation: `src/level/level_manager.c`, `src/level/level_manager.h`
- Lua bindings: `src/lua/lua_level.c`
