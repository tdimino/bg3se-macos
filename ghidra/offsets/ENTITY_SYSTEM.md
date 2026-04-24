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

64-bit packed value (confirmed from Windows EntitySystem.h, 2026-04-01):
- **Bits 0-31**: Entity Index (32-bit, within type pool)
- **Bits 32-53**: Salt (22-bit, generation counter for reuse detection)
- **Bits 54-63**: Entity Type (10-bit, archetype index, max 1023)

```c
#define ENTITY_HANDLE_INVALID 0xFFFFFFFFFFFFFFFFULL

static inline uint32_t entity_get_index(EntityHandle h) {
    return (uint32_t)(h & 0xFFFFFFFF);
}
static inline uint32_t entity_get_salt(EntityHandle h) {
    return (uint32_t)((h >> 32) & 0x3FFFFF);  // 22 bits
}
static inline uint16_t entity_get_type(EntityHandle h) {
    return (uint16_t)(h >> 54);  // top 10 bits
}
```

**Note:** The guid_lookup.h had an incorrect 16-bit salt layout (>>48). The entity_system.c
Lua bindings (GetEntityType, GetSalt, GetIndex) use the corrected decomposition above.
Pure bit arithmetic—no Ghidra needed.

## Capturing EntityWorld

### Server Singleton (esv::EocServer)

| Symbol | Address | Notes |
|--------|---------|-------|
| `esv::EocServer::m_ptr` | `0x10898e8b8` | Server-side EoCServer singleton |
| Mangled | `__ZN3esv9EocServer5m_ptrE` | Global pointer in `__DATA` segment |
| EntityWorld offset | `+0x288` | Within EoCServer struct |

### Client Singleton (ecl::EocClient)

| Symbol | Address | Notes |
|--------|---------|-------|
| `ecl::EocClient::m_ptr` | `0x10898c968` | Client-side EoCClient singleton |
| Mangled | `__ZN3ecl9EocClient5m_ptrE` | Global pointer in `__DATA` segment |
| EntityWorld offset | `+0x288` | Within EoCClient struct |

### Approach 1: Direct Memory Read (RECOMMENDED)

**Server context:**

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

### GUID Byte Order (CRITICAL - Fixed Dec 9, 2025)

**BG3 uses Windows UUID structure with additional byte swapping on Val[1]!**

The GUID format is `AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE` (36 chars).

BG3's GUID storage (from Windows BG3SE `CoreLib/Base/Base.cpp`):
1. Parse as standard Windows UUID (little-endian sections A/B/C, big-endian D/E)
2. Apply byte-pair swap to Val[1] (the second 64-bit value)

```c
// Standard UUID layout after parsing:
// bytes 0-3:   time_low (little-endian from AAAAAAAA)
// bytes 4-5:   time_mid (little-endian from BBBB)
// bytes 6-7:   time_hi_and_version (little-endian from CCCC)
// bytes 8-9:   clock_seq (DDDD - big-endian)
// bytes 10-15: node (EEEEEEEEEEEE - big-endian)
//
// Val[0] = bytes 0-7 (stored directly)
// Val[1] = bytes 8-15 (with BG3's byte-pair swap applied)

bool guid_parse(const char *guid_str, Guid *out_guid) {
    uint8_t bytes[16];

    // Section A (bytes 0-3): little-endian, so reverse byte order
    for (int i = 0; i < 4; i++) {
        bytes[3 - i] = parse_hex_pair(guid_str + i*2);
    }

    // Section B (bytes 4-5): little-endian
    for (int i = 0; i < 2; i++) {
        bytes[5 - i] = parse_hex_pair(guid_str + 9 + i*2);
    }

    // Section C (bytes 6-7): little-endian
    for (int i = 0; i < 2; i++) {
        bytes[7 - i] = parse_hex_pair(guid_str + 14 + i*2);
    }

    // Section D (bytes 8-9): big-endian (no reverse)
    for (int i = 0; i < 2; i++) {
        bytes[8 + i] = parse_hex_pair(guid_str + 19 + i*2);
    }

    // Section E (bytes 10-15): big-endian (no reverse)
    for (int i = 0; i < 6; i++) {
        bytes[10 + i] = parse_hex_pair(guid_str + 24 + i*2);
    }

    // Val[0] = bytes 0-7 (little-endian uint64_t)
    out_guid->lo = *(uint64_t*)&bytes[0];

    // Val[1] = bytes 8-15 with BG3's byte-pair swap
    // Original: 8, 9, 10, 11, 12, 13, 14, 15
    // Swapped:  9, 8, 11, 10, 13, 12, 15, 14
    out_guid->hi = ((uint64_t)bytes[9]) |
                   ((uint64_t)bytes[8] << 8) |
                   ((uint64_t)bytes[11] << 16) |
                   ((uint64_t)bytes[10] << 24) |
                   ((uint64_t)bytes[13] << 32) |
                   ((uint64_t)bytes[12] << 40) |
                   ((uint64_t)bytes[15] << 48) |
                   ((uint64_t)bytes[14] << 56);

    return true;
}
```

**Why the swap?** Windows BG3SE applies this transform in `Guid::Parse()` (Base.cpp:29-38).

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

### Verified Working (Dec 9, 2025)

**GUID lookup confirmed working** with diagnostic testing:
- HashMap contains ~23,100 entity UUIDs
- Lookup of known key `a5eaeafe-220d-bc4d-4cc3-b94574d334c7` returns `handle=0x200000100000665`
- Hash function `guid->lo ^ guid->hi` with bucket `hash % HashKeys.size` works correctly

### Template GUID Extraction (WORKING - Dec 9, 2025)

Character entities use **template GUIDs** with name prefixes:
- `S_PLA_ConflictedFlind_Gnoll_Ranger_03_81b29ac1-ba32-466b-bca8-9bb555aa3a6d`
- `S_HAG_ForestIllusion_Redcap_01_ff840420-d46a-4837-868b-ac02f45e4586`
- `S_Player_Astarion_c7c13742-bacd-460a-8f65-f864fe41f255`

The last 36 characters are the actual UUID used in `UuidToHandleMappingComponent`.

```c
// Extract UUID from template GUID
const char *extract_uuid_from_guid(const char *guid) {
    if (!guid) return guid;
    size_t len = strlen(guid);
    if (len < 36) return guid;

    const char *uuid_start = guid + len - 36;

    // Validate: preceded by underscore and has UUID format
    if (uuid_start != guid && uuid_start[-1] != '_') return guid;
    if (uuid_start[8] != '-' || uuid_start[13] != '-' ||
        uuid_start[18] != '-' || uuid_start[23] != '-') return guid;

    return uuid_start;
}
```

**Usage in `entity_get_by_guid()`:**
```c
EntityHandle entity_get_by_guid(const char *guid_str) {
    // Extract UUID from template GUID before parsing
    const char *uuid_str = extract_uuid_from_guid(guid_str);
    // ... parse uuid_str and lookup in HashMap ...
}
```

**Verified Working (Dec 9, 2025):**
```
GUID lookup SUCCESS: S_PLA_ConflictedFlind_Gnoll_Ranger_03_81b29ac1-... -> handle=0x200000100003253
GUID lookup SUCCESS: S_HAG_ForestIllusion_Redcap_01_ff840420-... -> handle=0x20000010000324e
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
| `ecl::EocClient::m_ptr` | `0x10898c968` | Global pointer to EoCClient singleton |
| `EoCServer + 0x288` | - | EntityWorld* within EoCServer struct |
| `EoCClient + 0x1B8` | - | PermissionsManager* within EoCClient struct |
| `EoCClient + 0x1B0` | - | EntityWorld* within EoCClient struct (estimated) |
| HashMap Mappings | `0x00` | Offset in UuidToHandleMappingComponent |
| `EocServerSDM::Init` | `0x1049b1444` | Creates EoCServer singleton |
| `EocServerSDM::Shutdown` | `0x1049ba808` | Destroys EoCServer singleton |
| `EocServerSDM::s_IsInitialized` | `0x108a374c0` | Initialization flag |

## Client Singleton Discovery (Dec 27, 2025)

### ecl::EocClient::m_ptr

**Address:** `0x10898c968`

Discovered via Ghidra analysis of `gui::DataContextProvider::CreateDataContextClass`:

```asm
1024f0218: adrp x8,0x10898c000
1024f021c: ldr x25,[x8, #0x968]   ; Load ecl::EocClient::m_ptr
1024f0228: add x26,x25,#0x1b8    ; PermissionsManager at EocClient+0x1b8
```

The decompiled code confirms:
```c
pEVar4 = ecl::EocClient::m_ptr;
pPVar1 = (PermissionsManager *)(ecl::EocClient::m_ptr + 0x1b8);
```

### EocClient Structure (Partial)

| Offset | Type | Member |
|--------|------|--------|
| `0x1B0` | `EntityWorld*` | Client EntityWorld (estimated from Windows) |
| `0x1B8` | `PermissionsManager*` | Permissions (verified via disassembly) |

### Usage in entity_system.c

```c
#define GHIDRA_BASE_ADDRESS            0x100000000ULL
#define OFFSET_EOCCLIENT_SINGLETON_PTR 0x10898c968ULL
#define OFFSET_ENTITYWORLD_IN_EOCCLIENT 0x1B0

static void *g_EoCClient = NULL;
static void *g_ClientEntityWorld = NULL;

bool discover_client_entity_world(void *main_binary_base) {
    uintptr_t global_addr = OFFSET_EOCCLIENT_SINGLETON_PTR - GHIDRA_BASE_ADDRESS
                          + (uintptr_t)main_binary_base;

    g_EoCClient = *(void **)global_addr;
    if (!g_EoCClient) return false;

    g_ClientEntityWorld = *(void **)((char *)g_EoCClient + OFFSET_ENTITYWORLD_IN_EOCCLIENT);
    return g_ClientEntityWorld != NULL;
}
```

### Verification

To verify the EntityWorld offset at runtime:
```lua
-- Check if client world is captured
local addrs = Ext.Entity.GetKnownAddresses()
_D(addrs)  -- Should show client.entityWorld if offset is correct

-- If client.entityWorld is nil/0, probe nearby offsets:
local cw = Ext.Entity.GetClientWorld()
if not cw then
    -- The offset 0x1B0 may need adjustment
    -- Use Ext.Debug.ProbeStruct on the EocClient pointer
end
```

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

## ComponentTypeIndex HashMap Hash Function (Fixed Dec 10, 2025)

**CRITICAL FIX:** The `ComponentTypeToIndex` HashMap uses a specific BG3 hash function for `ComponentTypeIndex`, NOT a simple modulo.

### Wrong (What we had)

```c
// WRONG - simple modulo doesn't match BG3's hash function
uint32_t bucket = typeIndex % hashKeys->size;
```

### Correct (BG3 Hash Function)

From Windows BG3SE `GameDefinitions/EntitySystem.h` lines 82-86:

```c
// ComponentMapSize = 0x880 = 2176 (constant used in the hash formula)
#define COMPONENT_MAP_SIZE 0x880

static uint64_t hash_component_type_index(uint16_t typeIndex) {
    // BG3's special hash for ComponentTypeIndex
    uint64_t h0 = ((uint64_t)typeIndex & 0x7FFF) + ((uint64_t)typeIndex >> 15) * COMPONENT_MAP_SIZE;
    return h0 | (h0 << 16);
}

// Then bucket = hash % hashKeys->size
uint64_t hash = hash_component_type_index(typeIndex);
uint32_t bucket = (uint32_t)(hash % hashKeys->size);
```

### Why This Matters

Without the correct hash function:
- `component_lookup_by_index()` would compute wrong bucket indices
- HashMap lookups would miss, returning `initial_idx = -1`
- `entity.Health` would return `nil` even when the entity has the component

### Verification (Dec 10, 2025)

After fixing the hash function:

```lua
-- BEFORE (wrong hash):
-- ComponentTypeToIndex lookup: type=575, bucket=186, initial_idx=-1
-- entity.Health = nil

-- AFTER (correct hash):
-- ComponentTypeToIndex lookup: type=575, bucket=575, initial_idx=1
local e = Ext.Entity.Get("S_PLA_...")
_P(e.Health.Hp .. "/" .. e.Health.MaxHp)  -- "12/12"
```

## ComponentOps (Add/Remove Component)

**Discovered:** 2026-04-01 (Qedeshot swarm + Ghidra research)
**Status:** Offset UNCONFIRMED — needs runtime probing

### ComponentOps VMT Layout

Confirmed from 100+ RTTI symbols in string table (e.g., `ecs::ComponentOps<esv::AnubisExecutorComponent>::AddImmediateDefaultComponent`):

| VMT Index | Function |
|-----------|----------|
| 0 | Destructor (D1) |
| 1 | Destructor (D0) |
| 2 | SendComponentAttachedSignal |
| 3 | SendComponentDetachedSignal / DefaultConstructComponents |
| 4 | **AddImmediateDefaultComponent(EntityHandle, int retryCount)** |

### EntityWorld Offset for ComponentOpsRegistry

**Original estimate:** `EntityWorld + 0x368`
**Revised estimate:** `EntityWorld + ~0x390` (from Ghidra analysis)
**Status:** UNCONFIRMED — requires runtime probing

Known EntityWorld offsets for context:

| Offset | Member | Confidence |
|--------|--------|------------|
| `0x240` | ComponentCallbackRegistry (CCR) | Ghidra-verified |
| `0x250` | RegisterPhaseEnded (bool) | Ghidra-verified |
| `0x253` | PerformingECSUpdate (bool) | Ghidra-verified |
| `0x2d0` | EntityStorageContainer* Storage | Ghidra-verified |
| `0x350-0x3B0` | **ComponentOpsRegistry** (somewhere here) | Estimated |
| `0x3c0` | ECBExecutor* | Ghidra-verified |
| `0x3f0` | ImmediateWorldCache* Cache | Ghidra-verified |

**Blocker:** FrameAllocator between Storage (0x2d0) and ComponentOps uses `alignas(64)` and
contains platform-specific `pthread_mutex_t` whose ARM64 size is uncertain.

### Runtime Probing Strategy

1. From `g_EntityWorld`, probe 0x350-0x3B0 at 8-byte intervals
2. For each candidate pointer P: check if `*(P)` has a VMT with 5 entries
3. Check if VMT[4] points into code segment (AddImmediateDefaultComponent)
4. Array size should be ~2700 (matching CCR component count)

### ImmediateWorldCache Offsets

| Offset | Member | Evidence |
|--------|--------|----------|
| +0x110 | Component data array base | `base + typeIndex * 0x80` |
| +0x240 | ComponentCallbackRegistry* | Double dereference |
| +0x248 | FrameAllocator* | Default sentinel |
| +0x250 | EntityWorld* | Passed to GetComponent |
