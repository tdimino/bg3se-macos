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

### GUID Byte Order (CRITICAL)

**BG3 stores GUIDs with hi/lo swapped compared to standard parsing!**

For GUID string `"a5eaeafe-220d-bc4d-4cc3-b94574d334c7"`:
- Format: `AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE`
- **hi** = `(A << 32) | (B << 16) | C` = first 8 bytes
- **lo** = `(D << 48) | E` = last 8 bytes

This was discovered by comparing parsed GUIDs to HashMap keys (Dec 2025).

```c
bool guid_parse(const char *guid_str, Guid *out_guid) {
    // Parse sections: AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE
    uint64_t a, b, c, d, e;
    // ... parse hex sections ...

    // BG3 storage order (hi/lo swapped from intuition)
    out_guid->hi = (a << 32) | (b << 16) | c;  // First parts go to hi
    out_guid->lo = (d << 48) | e;              // Last parts go to lo
    return true;
}
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

## ARM64 Calling Convention for TryGetSingleton

### The Problem

`TryGetSingleton` at `0x1010dc924` returns `ls::Result<ComponentPtr, ls::Error>` which is a
64-byte struct. On ARM64 AAPCS64:

- Structs ≤16 bytes return in x0/x1 registers
- Structs >16 bytes require caller to pass buffer address in **x8 register**

If we call without providing x8, the function writes to garbage memory → crash.

### ls::Result Layout (64 bytes)

From Ghidra analysis of stores to x19 (saved x8 buffer):

```
offset 0x00: void* value        (8 bytes) - Component pointer on success
offset 0x08: uint64_t reserved  (8 bytes) - Zeroed on success
offset 0x10: uint64_t[4] data   (32 bytes) - Additional data
offset 0x30: uint8_t has_error  (1 byte)  - 0=success, 1=error
offset 0x31: padding            (15 bytes) - Alignment padding
```

### Key Instructions in TryGetSingleton

```asm
0x1010dc944: mov x19,x8          ; Save return buffer pointer
...
; On success path:
0x1010dca90: stp x10,xzr,[x19]   ; Store component pointer at offset 0x00
0x1010dca94: str x9,[x19, #0x18] ; Store additional data
...
; On error path:
0x1010dcab4: strb w8,[x19, #0x30]; Store error=1 at offset 0x30
```

### Correct Calling Convention

```c
typedef struct __attribute__((aligned(16))) {
    void* value;
    uint64_t reserved1;
    uint64_t reserved2[4];
    uint8_t has_error;
    uint8_t _pad[15];
} LsResult;

void* call_try_get_singleton_with_x8(void *fn, void *entityWorld) {
    LsResult result = {0};
    result.has_error = 1;

    __asm__ volatile (
        "mov x8, %[buf]\n"
        "mov x0, %[world]\n"
        "blr %[fn]\n"
        : "+m"(result)
        : [buf] "r"(&result), [world] "r"(entityWorld), [fn] "r"(fn)
        : "x0", "x1", "x8", "x9", "x10", "x11", "x12", "x13",
          "x14", "x15", "x16", "x17", "x19", "x20",
          "x21", "x22", "x23", "x24", "x25", "x26",
          "x30", "memory"
    );

    return (result.has_error == 0) ? result.value : NULL;
}
```

**Note:** Do NOT clobber x18 (platform register) or x29 (frame pointer).

## Component Access Architecture (Dec 2025)

### EntityWorld Structure Offsets

From Ghidra decompilation of `ecs::EntityWorld::GetComponent<>` templates:

| Offset | Type | Member | Notes |
|--------|------|--------|-------|
| `0x2d0` | `EntityStorageContainer*` | `Storage` | Main entity storage |
| `0x3f0` | `ImmediateWorldCache*` | `Cache` | Pending component changes |

### EntityStorageContainer::TryGet

**Address:** `0x10636b27c`
**Signature:** `EntityStorageData* TryGet(EntityHandle handle)`

ARM64 calling convention:
- x0 = this (EntityStorageContainer*)
- x1 = EntityHandle (64-bit)
- Return: x0 = EntityStorageData* or null

### Component Access Pattern (Inlined)

Analysis of `GetComponent<T>` template instantiations reveals the component access is **template-inlined** on macOS (unlike Windows which has a `GetRawComponent` dispatcher). The pattern is:

```c
// Pseudo-code for inlined GetComponent
T* EntityWorld::GetComponent<T>(EntityHandle handle) {
    // 1. Get Storage container
    EntityStorageContainer* storage = this->Storage;  // offset 0x2d0

    // 2. Extract thread index from handle
    uint32_t threadIdx = (handle >> 54) & 0x3F;  // bits 54-63

    // 3. Validate and look up entity storage
    EntityStorageData* data = storage->TryGet(handle);  // calls 0x10636b27c
    if (!data) return nullptr;

    // 4. Check ImmediateWorldCache for pending changes
    ImmediateWorldCache* cache = this->Cache;  // offset 0x3f0
    void* pending = cache->GetChange(handle, TypeId<T>::index);
    if (pending) return (T*)pending;

    // 5. Look up component in EntityStorageData
    uint16_t typeIndex = TypeId<T>::m_TypeIndex & 0x7FFF;
    return data->GetComponent(handle, typeIndex);
}
```

### EntityStorageData Offsets

From decompiled GetComponent templates, EntityStorageData has these key offsets:

| Offset | Purpose |
|--------|---------|
| `0x138` | Components array (pages of component data) |
| `0x180` | ComponentTypeToIndex hash table buckets |
| `0x188` | ComponentTypeToIndex hash table size |
| `0x190` | ComponentTypeToIndex hash table something |
| `0x1a0` | ComponentTypeToIndex values (type indices) |
| `0x1b0` | Component slot indices |
| `0x1c0` | InstanceToPageMap hash buckets |
| `0x1c8` | InstanceToPageMap size |
| `0x1d0` | InstanceToPageMap next chain |
| `0x1e0` | InstanceToPageMap keys (EntityHandle) |
| `0x1f0` | InstanceToPageMap values (storage index) |

### Implementation Strategy for macOS

Since there's no `GetRawComponent` dispatcher on macOS, we have two options:

#### Option 1: Call TryGet + Manual Component Lookup

```c
// Use discovered TryGet and implement component lookup ourselves
EntityStorageData* data = EntityStorageContainer_TryGet(world->Storage, handle);
if (data) {
    void* component = EntityStorageData_GetComponent(data, handle, typeIndex);
}
```

#### Option 2: Hook a GetComponent<T> Instantiation

We have many GetComponent instantiations we could call or reference:
- `0x100cb1644` - `GetComponent<ecl::Item>`
- `0x100cc20a8` - `GetComponent<ecl::Character>`
- etc.

### Key Function Addresses

| Function | Address | Notes |
|----------|---------|-------|
| `EntityStorageContainer::TryGet` | `0x10636b27c` | Non-const version |
| `EntityStorageContainer::TryGet (const)` | `0x10636b310` | Const version |
| `GetComponent<ecl::Item>` | `0x100cb1644` | Template instantiation |
| `GetComponent<ecl::Character>` | `0x100cc20a8` | Template instantiation |
| `GetComponent<eoc::combat::ParticipantComponent>` | `0x100cc1d7c` | Combat-related |
| `ImmediateWorldCache::GetChange` | Called at `param_1 + 0x3f0` | Cache lookup |

### TypeId Static Variables

Component type indices are stored in static globals (pattern `TypeId<T>::m_TypeIndex`):
- `ecl::Item`: `PTR___ZN2ls6TypeIdIN3ecl4ItemEN3ecs22ComponentTypeIdContextEE11m_TypeIndexE_1083c6910`
- `ecl::Character`: `PTR___ZN2ls6TypeIdIN3ecl9CharacterEN3ecs22ComponentTypeIdContextEE11m_TypeIndexE_1083c7818`

These can be read at runtime to discover component type indices.
