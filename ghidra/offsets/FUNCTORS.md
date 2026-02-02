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

## TODO

- [ ] Find `DealDamageFunctor::ApplyDamage` address
- [ ] Find `StatsSystem::ThrowDamageEvent` address
- [ ] Verify ContextData field offsets via runtime probing
- [ ] Determine HitResult struct layout for ARM64

## References

- Windows BG3SE: `BG3Extender/Lua/Server/FunctorEvents.inl`
- Windows BG3SE: `BG3Extender/GameDefinitions/Stats/Functors.h`
- Windows BG3SE: `BG3Extender/GameDefinitions/Hit.h`
