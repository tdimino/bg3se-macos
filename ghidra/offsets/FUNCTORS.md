# Stats Functor System Offsets

**Game Version:** Baldur's Gate 3 v4.1.1.5022896 (Patch 8)
**Platform:** macOS ARM64
**Discovered:** 2025-12-27
**Status:** ✅ Implemented (v0.36.15)

## Overview

The Stats Functor system handles damage, healing, status effects, and combat mechanics execution. Each context type has a dedicated handler function.

## Function Addresses

### Main Dispatcher

| Function | Address | Size | Notes |
|----------|---------|------|-------|
| `ExecuteStatsFunctor` | `0x105783a38` | 8363 bytes | Main dispatch by functor type |

**Signature:**
```c
void ExecuteStatsFunctor(StatsFunctorBase* functor, uint64_t functorId, AttackTargetContextData* context);
```

### Context-Specific Handlers

**Standard handlers** (8 types) share this 3-parameter signature:
```c
void ExecuteStatsFunctors(functor* self, StatsFunctorList* functors, <ContextType>* context);
```

| Context Type | Address | Body End | Size |
|-------------|---------|----------|------|
| WorldView (generic) | `0x1056e429c` | `0x1056e4643` | 935 bytes |
| AttackTargetContextData | `0x105787918` | `0x105787c07` | 751 bytes |
| AttackPositionContextData | `0x105787c6c` | `0x105789497` | 6187 bytes |
| MoveContextData | `0x10578975c` | `0x10578a77f` | 4131 bytes |
| TargetContextData | `0x10578a918` | `0x10578e09f` | 14215 bytes |
| NearbyAttackedContextData | `0x10578e4d8` | `0x10578f9eb` | 5395 bytes |
| NearbyAttackingContextData | `0x10578fba8` | `0x105790903` | 3419 bytes |
| EquipContextData | `0x105790a28` | `0x10579279f` | 7543 bytes |
| SourceContextData | `0x105792a90` | `0x1057961c7` | 14135 bytes |

**Interrupt handler** has a unique 4-parameter signature (Issue #60 fix):
```c
void ExecuteInterruptFunctors(HitResult* hit, ecs::EntityWorld* world,
                              StatsFunctorList* functors, InterruptContextData* context);
```

| Context Type | Address | Body End | Size |
|-------------|---------|----------|------|
| InterruptContextData | `0x1057965e4` | `0x10579be47` | 22627 bytes |

> **Note:** The Interrupt handler takes `HitResult*` as the first parameter, unlike all other handlers.
> This is required for combat reactions (Attack of Opportunity, Counterspell, etc.).

### Damage Processing

| Function | Address | Size | Notes |
|----------|---------|------|-------|
| `DealDamageFunctor::ApplyDamage` | `0x10538e8fc` | ~2560 bytes | Main hook target (496 lines decompiled). Matches Windows `ApplyDamageProc` — 8 reg params + stack params (18 total on Windows) |
| `ProcessDealDamageFunctors` | `0x10538f374` | 1347 bytes | Called by ApplyDamage. Processes DealDamage functor list |
| `StatsFunctorDealDamage::~D0` | `0x101fcf024` | — | Destructor (labeled via GOT) |

**DealDamageFunctor::ApplyDamage — Windows reference signature:**
```c
// From BG3Extender/GameDefinitions/Stats/Functors.h
HitResult* ApplyDamage(HitResult* result, DealDamageFunctor* functor,
    ecs::EntityRef* casterHandle, ecs::EntityRef* targetHandle,
    glm::vec3* position, bool isFromItem, SpellIdWithPrototype* spellId,
    int storyActionId, ActionOriginator* originator,
    resource::GuidResourceBankBase* classResourceMgr,
    HitDesc* hit, AttackDesc* attack, EntityHandle* sourceHandle2,
    HitWith hitWith, int conditionRollIndex,
    bool entityDamagedEventParam, __int64 a17, SpellId* spellId2);
```

**esv::StatsSystem::ThrowDamageEvent — Windows reference signature:**
```c
void ThrowDamageEvent(void* statsSystem, void* temp5,
    HitDesc* hit, AttackDesc* attack, bool a5, bool a6);
```

**ARM64 address for ThrowDamageEvent: NOT YET FOUND**
- No labeled function. Needs xref tracing from `esv::StatsSystem` TypeId or
  from callers of `DealDamage_Parent` (called via vtable/function pointer).

**RTTI/GOT entries (DealDamage):**
| Symbol | String Address | GOT Address |
|--------|---------------|-------------|
| `eoc::StatsFunctorDealDamage::~D1` | `0x10b4ad812` | `0x10993a9b0` |
| `eoc::StatsFunctorDealDamage::~D0` | `0x10b4ad837` | — |
| `eoc::StatsFunctorDealDamage::Parse` | `0x10b4ad85c` | — |
| `eoc::StatsFunctorDealDamage::Clone` | `0x10b4ad8e1` | — |
| `eoc::StatsFunctorDealDamage::C1` | `0x10b4b03a1` | `0x10993b380` |

**Decompilations saved to:** `ghidra/offsets/staging/`

**ProcessDealDamageFunctors signature (from Ghidra):**
```c
void ProcessDealDamageFunctors(
    WorldView* worldView,
    StatsFunctorBase* functor,
    ID* id,
    Optional* opt,
    StateComponent* state,
    EnumFlags* flags,
    EAbility* ability,
    ESpellAttackType* spellAttack,
    Dependency* dep1,
    Dependency* dep2,
    int param,
    DynamicArray* arr
);
```

## Context Type Enum

From Windows BG3SE reference (`Functors.h`):

```c
typedef enum {
    FUNCTOR_CTX_ATTACK_TARGET = 0,
    FUNCTOR_CTX_ATTACK_POSITION = 1,
    FUNCTOR_CTX_MOVE = 2,
    FUNCTOR_CTX_TARGET = 3,
    FUNCTOR_CTX_NEARBY_ATTACKED = 4,
    FUNCTOR_CTX_NEARBY_ATTACKING = 5,
    FUNCTOR_CTX_EQUIP = 6,
    FUNCTOR_CTX_SOURCE = 7,
    FUNCTOR_CTX_INTERRUPT = 8,
} FunctorContextType;
```

## ContextData Base Structure

```c
// Offset estimates based on Windows reference
typedef struct {
    void* vtable;                    // 0x00
    FunctorContextType Type;         // 0x08 (uint32)
    int32_t StoryActionId;           // 0x0C
    uint32_t PropertyContext;        // 0x10
    // ActionOriginator Originator;  // 0x18+ (complex, ~64 bytes)
    // ... more fields
} ContextData;  // Base size: ~0xA0 (160 bytes)
```

## AttackTargetContextData Structure

```c
typedef struct {
    ContextData base;                // 0x00
    EntityRef Caster;                // 0xA0? (16 bytes)
    EntityRef CasterProxy;           // 0xB0?
    EntityRef Target;                // 0xC0?
    EntityRef TargetProxy;           // 0xD0?
    float Position[3];               // 0xE0? (12 bytes)
    bool IsFromItem;                 // 0xEC?
    // SpellIdWithPrototype SpellId; // 0xF0+
    // HitDesc Hit;                  // Complex (~0x1B8 bytes)
    // AttackDesc Attack;            // Complex (~0x28 bytes)
    // ... more fields
} AttackTargetContextData;  // Total size: ~0x320 (800 bytes)
```

## Hook Strategy

Based on Windows BG3SE pattern:

1. **Hook each context handler** to fire pre/post events
2. **Pre-event:** `ExecuteFunctor` with functor + context
3. **Post-event:** `AfterExecuteFunctor` with functor + context + hit result

### Hook Wrapper Pattern

```c
void hook_ExecuteStatsFunctors_AttackTarget(
    void* self,
    void* functorList,
    AttackTargetContextData* context
) {
    // Fire pre-event
    fire_lua_event("ExecuteFunctor", functorList, context);

    // Call original
    orig_ExecuteStatsFunctors_AttackTarget(self, functorList, context);

    // Fire post-event with hit result
    fire_lua_event("AfterExecuteFunctor", functorList, context, &context->Hit);
}
```

## Related Offsets

| Symbol | Address | Notes |
|--------|---------|-------|
| FunctorId enum values | - | In stats data |
| HitResult struct | - | Return value for damage |

## Damage Hook Signatures (from Windows BG3SE reference)

**Discovered:** 2026-04-01 (Qedeshot swarm R2 research)
**ARM64 addresses:** NOT YET FOUND (symbols stripped, Ghidra search ongoing)

### StatsSystem::ThrowDamageEvent (BeforeDealDamage hook point)

```c
// From Functors.h:363
typedef void (*StatsSystem_ThrowDamageEventProc)(
    void* statsSystem,    // x0: StatsSystem instance
    void* temp5,          // x1: unknown/temporary
    HitDesc* hit,         // x2: damage roll descriptor
    AttackDesc* attack,   // x3: attack parameters (damage sums)
    bool a5,              // x4: unknown flag
    bool a6               // x5: unknown flag
);
```

**Hook fires:** `BeforeDealDamage` event BEFORE calling original.

### DealDamageFunctor::ApplyDamage (DealDamage hook point)

```c
// From Functors.h:369-373 — 18 parameters
typedef HitResult* (*ApplyDamageProc)(
    HitResult* result,                       // x0: return buffer (x8 indirect on ARM64)
    DealDamageFunctor* functor,              // x1: functor instance
    ecs::EntityRef* casterHandle,            // x2
    ecs::EntityRef* targetHandle,            // x3
    glm::vec3* position,                     // x4
    bool isFromItem,                         // x5
    SpellIdWithPrototype* spellId,           // x6
    int storyActionId,                       // x7
    ActionOriginator* originator,            // stack[0]
    resource::GuidResourceBankBase* classMgr,// stack[1]
    HitDesc* hit,                            // stack[2]
    AttackDesc* attack,                      // stack[3]
    EntityHandle* sourceHandle2,             // stack[4]
    HitWith hitWith,                         // stack[5]
    int conditionRollIndex,                  // stack[6]
    bool entityDamagedEventParam,            // stack[7]
    int64_t a17,                             // stack[8]
    SpellId* spellId2                        // stack[9]
);
```

**Note:** Returns HitResult* via x8 indirect return on ARM64 (struct >16 bytes).

### Search Strategy for ARM64 Addresses

Symbols are stripped. Approach:
1. Find DealDamageFunctor vtable via constructor at `0x10b4b03a1` (from prior session)
2. Trace vtable[N] entries to find ApplyDamage
3. ThrowDamageEvent: search xrefs from ProcessDealDamageFunctors (`0x10538f374`)
4. Alternative: search for string "DealDamage" xrefs, trace to callers

### Known RTTI/Data References (2026-04-01 Ghidra research)

| Type | Address | Notes |
|------|---------|-------|
| DealDamageFunctor C1 ctor (RTTI) | `0x10b4b03a1`, `0x10b4b03c6` | String table entries |
| DealDamageFunctor D0/D1 dtor (RTTI) | `0x10b4ad812`, `0x10b4ad837` | String table entries |
| DealDamageFunctor::Parse (RTTI) | `0x10b4ad85c` | String table |
| DealDamageFunctor::Clone (RTTI) | `0x10b4ad8e1` | String table |
| Default ctor GOT entry | DATA `0x10993b380` | Vtable reference |
| Param ctor GOT entry | DATA `0x10993b390` | Vtable reference |
| CalculateDamage (RTTI) | `0x10b4be46f` | Not a Ghidra function |
| EntityDamagedEventOneFrame | `0x1048f3624` | Query registration |

### Blocker RESOLVED (2026-04-01): GhidraMCP create_function

GhidraMCP HTTP bridge cannot create functions. **Workaround:** Jython scripts via
Ghidra Script Manager (`~/ghidra_scripts/CreateDamageFunctions.py`, etc.).

### Blocker (2026-04-03): ThrowDamageEvent ARM64 address

**Status:** Exhaustive static analysis failed. ThrowDamageEvent cannot be found via Ghidra.

**What we tried (2026-04-03 session):**
1. String search: No "ThrowDamageEvent" string in binary (stripped)
2. TypeId xrefs: `EntityDamagedEventOneFrameComponent` TypeId at `0x108ec3a2e` — Ghidra returns
   zero xrefs (ARM64 adrp+add page-relative refs not resolved)
3. ComponentOps destructor xrefs: Only DATA ref at `0x1097c71a3` (vtable), no code refs
4. Call chain analysis: All 36 `bl` targets in DealDamage_Parent identified and decompiled:
   - `0x1010e2600` (564 bytes) — struct constructor, NOT ThrowDamageEvent
   - `0x105782a24` (1404 bytes) — HitResult builder
   - `0x1056a2180` (1268 bytes) — spell damage handler
   - All others: utility (Acquire, Release, atexit, free, Mersenne, FixedString)
5. Caller tracing: DealDamage_Parent has zero callers in Ghidra (called via function pointer)
6. Sibling caller analysis: `0x1056a342c` and `0x105722d58` call Candidate_2 but are in unlabeled functions

**Why it's hard:** ARM64 `adrp` + `add`/`ldr` for global access generates PC-relative
page references that Ghidra doesn't resolve into xrefs for stripped binaries. Functions
that only access globals via this pattern are invisible to xref search.

**Remaining approaches:**
- Runtime probing: Hook ApplyDamage, set breakpoints on EntityDamagedEventOneFrameComponent
  TypeId reads, trap the caller
- Binary pattern search: Scan for adrp+add instruction pairs targeting the TypeId page
- Emulation: Use Ghidra's emulator to trace execution through ApplyDamage callers

**Impact:** ThrowDamageEvent is needed ONLY for `BeforeDealDamage` event.
`DealDamage` and `DealtDamage` events can be implemented using ApplyDamage alone.

## TODO

- [x] ~~Find `DealDamageFunctor::ApplyDamage`~~ — **FOUND** at `0x10538e8fc`
- [ ] Find `StatsSystem::ThrowDamageEvent` — needs runtime probing (see Blocker above)
- [ ] Implement DealDamage + DealtDamage hooks using ApplyDamage (`0x10538e8fc`)
- [ ] Verify ContextData field offsets via runtime probing
- [ ] Determine HitResult struct layout for ARM64

## References

- Windows BG3SE: `BG3Extender/Lua/Server/FunctorEvents.inl`
- Windows BG3SE: `BG3Extender/GameDefinitions/Stats/Functors.h`
- Windows BG3SE: `BG3Extender/GameDefinitions/Hit.h`
