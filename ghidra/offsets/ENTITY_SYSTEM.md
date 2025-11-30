# Entity System Architecture

## Overview

BG3 uses an Entity Component System (ECS) with the same architecture on macOS as Windows.

## Namespace Structure

| Namespace | Purpose |
|-----------|---------|
| `ecs::` | Core ECS infrastructure (EntityWorld, EntityHandle) |
| `eoc::` | Engine of Creation - shared game components |
| `esv::` | Server-side components and systems |
| `ecl::` | Client-side components and systems |
| `ls::` | Larian Studios core (Transform, Level, etc.) |

## EntityHandle

64-bit packed value:
- **Bits 0-31**: Entity Index (within type)
- **Bits 32-47**: Salt (generation counter)
- **Bits 48-63**: Type Index (archetype)

```c
#define ENTITY_HANDLE_INVALID 0xFFFFFFFFFFFFFFFFULL

static inline uint32_t entity_get_index(EntityHandle h) {
    return (uint32_t)(h & 0xFFFFFFFF);
}
static inline uint16_t entity_get_salt(EntityHandle h) {
    return (uint16_t)((h >> 32) & 0xFFFF);
}
static inline uint16_t entity_get_type(EntityHandle h) {
    return (uint16_t)((h >> 48) & 0xFFFF);
}
```

## Capturing EntityWorld

### Approach 1: Direct Memory Read (RECOMMENDED)

**Symbol:** `esv::EocServer::m_ptr`
- **Address:** `0x10898e8b8`
- **Mangled:** `__ZN3esv9EocServer5m_ptrE`
- **Type:** Global pointer to EoCServer singleton in `__DATA` segment
- **EntityWorld offset:** `0x288` (within EoCServer struct)

This is the most reliable approach - no hooking required:

```c
#define GHIDRA_BASE_ADDRESS         0x100000000ULL
#define OFFSET_EOCSERVER_SINGLETON  0x10898e8b8ULL
#define OFFSET_ENTITYWORLD          0x288

static void *g_EoCServer = NULL;
static void *g_EntityWorld = NULL;

bool discover_entity_world(void *main_binary_base) {
    // Calculate runtime address of the global pointer
    uintptr_t global_addr = OFFSET_EOCSERVER_SINGLETON - GHIDRA_BASE_ADDRESS
                          + (uintptr_t)main_binary_base;

    // Read EoCServer pointer from global
    g_EoCServer = *(void **)global_addr;
    if (!g_EoCServer) return false;

    // Read EntityWorld from EoCServer + 0x288
    g_EntityWorld = *(void **)((char *)g_EoCServer + OFFSET_ENTITYWORLD);
    return g_EntityWorld != NULL;
}
```

**Why this works:** The `__DATA` segment is readable, unlike `__TEXT` which is
protected by macOS Hardened Runtime.

### Approach 2: Hook EocServer::StartUp (DEPRECATED - causes crashes)

**WARNING:** Hooking main binary functions causes `KERN_PROTECTION_FAILURE` due to
macOS Hardened Runtime. Dobby cannot patch `__TEXT` segments of signed binaries.

**Target:** `esv::EocServer::StartUp`
- **Address:** `0x10110f0d0`
- **Signature:** `void (this, eoc::ServerInit const&)`

```c
// DO NOT USE - crashes due to Hardened Runtime
// See docs/CRASH_ANALYSIS.md for details
```

### Approach 3: Hook LEGACY_IsInCombat (DEPRECATED - causes crashes)

**WARNING:** Same Hardened Runtime issue as Approach 2.

**Target:** `eoc::CombatHelpers::LEGACY_IsInCombat`
- **Address:** `0x10124f92c`
- **Signature:** `bool (EntityHandle, EntityWorld&)`

```c
// DO NOT USE - crashes due to Hardened Runtime
```

### Why libOsiris Hooks Work But Main Binary Hooks Don't

- **Main binary** (`BG3`) - Signed with Hardened Runtime, `__TEXT` is immutable
- **libOsiris.dylib** - Loaded at runtime, different memory protections allow patching

See `docs/CRASH_ANALYSIS.md` for full technical explanation.

## EoCServer Structure

The Windows BG3SE uses the same offset for EntityWorld:

```c
struct esv::EoCServer {
    // ... many members ...
    ecs::EntityWorld* EntityWorld;  // offset 0x288
    // ...
};
```

## GUID to EntityHandle Lookup

**Singleton:** `ls::uuid::ToHandleMappingComponent`
**TryGetSingleton Address:** `0x1010dc924`

Contains `HashMap<Guid, EntityHandle> Mappings` at offset 0x0.

### HashMap Layout (64 bytes)

```
offset 0x00: StaticArray<int32_t> HashKeys   (bucket table)
offset 0x10: Array<int32_t> NextIds          (collision chain)
offset 0x20: Array<Guid> Keys                (key storage)
offset 0x30: StaticArray<EntityHandle> Values
```

### Lookup Algorithm

```c
EntityHandle lookup(HashMap *map, Guid *guid) {
    uint64_t hash = guid->lo ^ guid->hi;
    uint32_t bucket = hash % map->HashKeys.size;
    int32_t idx = map->HashKeys.buf[bucket];

    while (idx >= 0) {
        if (map->Keys.buf[idx].lo == guid->lo &&
            map->Keys.buf[idx].hi == guid->hi) {
            return map->Values.buf[idx];
        }
        idx = map->NextIds.buf[idx];
    }
    return ENTITY_HANDLE_INVALID;
}
```

## ECS Helper Functions

| Function | Address | Signature | Notes |
|----------|---------|-----------|-------|
| `esv::EocServer::StartUp` | `0x10110f0d0` | `(this, ServerInit&)` | Safe to hook |
| `esv::EocServer::StopServer` | `0x10111205c` | `(this)` | Server shutdown |
| `esv::EocServer::GetCombatLog` | `0x101111fd4` | `(this)` | Returns CombatLog |
| `LEGACY_IsInCombat` | `0x10124f92c` | `(EntityHandle, EntityWorld&)` | **DO NOT HOOK** |
| `LEGACY_GetCombatFromGuid` | `0x101250074` | `(Guid&, EntityWorld&)` | |
| `TryGetSingleton<UuidMapping>` | `0x1010dc924` | `(EntityWorld&)` | |

## Key Offsets

| Symbol | Address | Description |
|--------|---------|-------------|
| `esv::EocServer::m_ptr` | `0x10898e8b8` | Global pointer to EoCServer singleton |
| `EoCServer + 0x288` | - | EntityWorld* within EoCServer struct |
| HashMap Mappings | `0x00` | Offset in UuidToHandleMappingComponent |
| `EocServerSDM::Init` | `0x1049b1444` | Creates EoCServer singleton |
| `EocServerSDM::Shutdown` | `0x1049ba808` | Destroys EoCServer singleton |
| `EocServerSDM::s_IsInitialized` | `0x108a374c0` | Initialization flag |
