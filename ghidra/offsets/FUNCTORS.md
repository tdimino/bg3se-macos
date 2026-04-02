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
| `ProcessDealDamageFunctors` | `0x10538f374` | 1347 bytes | Processes DealDamage functor list |

**Signature (from Ghidra):**
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

### Blocker (2026-04-01)

GhidraMCP HTTP bridge **cannot decompile addresses that aren't labeled as functions**.
All key addresses return "No function found". The `/create_function` POST endpoint
returns 404 (not supported by current plugin version).

**To unblock:** Either use Ghidra GUI to press F (create function) at `0x10538f374`
and `0x105783a38`, or upgrade GhidraMCP plugin to support `/create_function`.

## TODO

- [ ] **BLOCKED:** Find `DealDamageFunctor::ApplyDamage` — needs Ghidra GUI or plugin upgrade
- [ ] **BLOCKED:** Find `StatsSystem::ThrowDamageEvent` — needs Ghidra GUI or plugin upgrade
- [ ] Verify ContextData field offsets via runtime probing
- [ ] Determine HitResult struct layout for ARM64

## References

- Windows BG3SE: `BG3Extender/Lua/Server/FunctorEvents.inl`
- Windows BG3SE: `BG3Extender/GameDefinitions/Stats/Functors.h`
- Windows BG3SE: `BG3Extender/GameDefinitions/Hit.h`
