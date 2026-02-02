/**
 * functor_types.h - Stats Functor System Types
 *
 * Data structures for the game's functor execution system.
 * Used for hooking damage, healing, status effects, and combat mechanics.
 *
 * References:
 * - Windows BG3SE: BG3Extender/GameDefinitions/Stats/Functors.h
 * - Windows BG3SE: BG3Extender/GameDefinitions/Hit.h
 * - Ghidra offsets: ghidra/offsets/FUNCTORS.md
 */

#ifndef FUNCTOR_TYPES_H
#define FUNCTOR_TYPES_H

#include <stdint.h>
#include <stdbool.h>

// Forward declarations
typedef struct EntityRef EntityRef;
typedef struct HitDesc HitDesc;
typedef struct AttackDesc AttackDesc;
typedef struct HitResult HitResult;

// =============================================================================
// Functor Context Type Enum
// =============================================================================

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

// =============================================================================
// Functor Type IDs (partial list of ~50 types)
// =============================================================================

typedef enum {
    FUNCTOR_ID_CUSTOM_DESCRIPTION = 0,
    FUNCTOR_ID_APPLY_STATUS = 1,
    FUNCTOR_ID_SURFACE_CHANGE = 2,
    FUNCTOR_ID_RESURRECT = 3,
    FUNCTOR_ID_SABOTAGE = 4,
    FUNCTOR_ID_SUMMON = 5,
    FUNCTOR_ID_FORCE = 6,
    FUNCTOR_ID_DOUSE = 7,
    FUNCTOR_ID_SWAP_PLACES = 8,
    FUNCTOR_ID_PICKUP = 9,
    FUNCTOR_ID_CREATE_SURFACE = 10,
    FUNCTOR_ID_CREATE_CONE_SURFACE = 11,
    FUNCTOR_ID_REMOVE_STATUS = 12,
    FUNCTOR_ID_DEAL_DAMAGE = 13,
    FUNCTOR_ID_EXECUTE_WEAPON_FUNCTORS = 14,
    FUNCTOR_ID_REGAIN_HIT_POINTS = 15,
    FUNCTOR_ID_TELEPORT_SOURCE = 16,
    FUNCTOR_ID_SET_STATUS_DURATION = 17,
    FUNCTOR_ID_USE_SPELL = 18,
    FUNCTOR_ID_USE_ACTION_RESOURCE = 19,
    FUNCTOR_ID_USE_ATTACK = 20,
    FUNCTOR_ID_CREATE_EXPLOSION = 21,
    FUNCTOR_ID_BREAK_CONCENTRATION = 22,
    FUNCTOR_ID_APPLY_EQUIPMENT_STATUS = 23,
    FUNCTOR_ID_RESTORE_RESOURCE = 24,
    FUNCTOR_ID_SPAWN = 25,
    FUNCTOR_ID_STABILIZE = 26,
    FUNCTOR_ID_UNLOCK = 27,
    FUNCTOR_ID_RESET_COMBAT_TURN = 28,
    FUNCTOR_ID_REMOVE_AURA_BY_CHILD_STATUS = 29,
    FUNCTOR_ID_SUMMON_IN_INVENTORY = 30,
    FUNCTOR_ID_SPAWN_IN_INVENTORY = 31,
    FUNCTOR_ID_REMOVE_UNIQUE_STATUS = 32,
    FUNCTOR_ID_DISARM_WEAPON = 33,
    FUNCTOR_ID_DISARM_AND_STEAL_WEAPON = 34,
    FUNCTOR_ID_SWITCH_DEATH_TYPE = 35,
    FUNCTOR_ID_TRIGGER_RANDOM_CAST = 36,
    FUNCTOR_ID_GAIN_TEMPORARY_HIT_POINTS = 37,
    FUNCTOR_ID_FIRE_PROJECTILE = 38,
    FUNCTOR_ID_SHORT_REST = 39,
    FUNCTOR_ID_CREATE_ZONE = 40,
    FUNCTOR_ID_DO_TELEPORT = 41,
    FUNCTOR_ID_REGAIN_TEMPORARY_HIT_POINTS = 42,
    FUNCTOR_ID_REMOVE_STATUS_BY_LEVEL = 43,
    FUNCTOR_ID_SURFACE_CLEAR_LAYER = 44,
    FUNCTOR_ID_UNSUMMON = 45,
    FUNCTOR_ID_CREATE_WALL = 46,
    FUNCTOR_ID_COUNTERSPELL = 47,
    FUNCTOR_ID_ADJUST_ROLL = 48,
    FUNCTOR_ID_SPAWN_EXTRA_PROJECTILES = 49,
    FUNCTOR_ID_KILL = 50,
    FUNCTOR_ID_TUTORIAL_EVENT = 51,
    FUNCTOR_ID_DROP = 52,
    FUNCTOR_ID_RESET_COOLDOWNS = 53,
    FUNCTOR_ID_SET_ROLL = 54,
    FUNCTOR_ID_SET_DAMAGE_RESISTANCE = 55,
    FUNCTOR_ID_SET_REROLL = 56,
    FUNCTOR_ID_SET_ADVANTAGE = 57,
    FUNCTOR_ID_SET_DISADVANTAGE = 58,
    FUNCTOR_ID_MAXIMIZE_ROLL = 59,
    FUNCTOR_ID_CAMERA_WAIT = 60,
    FUNCTOR_ID_EXTENDER = 61,
} FunctorId;

// =============================================================================
// Entity Reference (16 bytes on ARM64)
// =============================================================================

struct EntityRef {
    uint64_t Handle;      // 0x00: EntityHandle (salt + index)
    void*    World;       // 0x08: EntityWorld pointer
};

// =============================================================================
// ActionOriginator - Tracks origin of an action
// Estimated ~64 bytes based on Windows reference
// =============================================================================

typedef struct {
    uint64_t ActionGuid[2];        // 0x00: 16-byte GUID
    uint64_t InterruptGuid[2];     // 0x10: 16-byte GUID
    uint64_t PassiveGuid[2];       // 0x20: 16-byte GUID
    uint32_t CanApplyConcentration;// 0x30
    uint8_t  _pad[28];             // 0x34: Alignment padding
} ActionOriginator;                // Total: ~0x50 (80 bytes)

// =============================================================================
// ContextData - Base class for all functor contexts
// =============================================================================

typedef struct {
    void*              vtable;           // 0x00: Virtual table pointer
    FunctorContextType Type;             // 0x08: Context type enum
    int32_t            StoryActionId;    // 0x0C
    uint32_t           PropertyContext;  // 0x10
    uint32_t           _pad0;            // 0x14: Alignment
    ActionOriginator   Originator;       // 0x18: ~80 bytes
    void*              ClassResources;   // 0x68: GuidResourceBankBase*
    uint64_t           HistoryEntity;    // 0x70: EntityHandle
    uint64_t           StatusSource;     // 0x78: EntityHandle
    void*              EntityToThoth;    // 0x80: HashMap pointer
    uint64_t           _pad1;            // 0x88
    int32_t            field_90;         // 0x90
    uint8_t            ConditionCategory;// 0x94
    uint8_t            _pad2[3];         // 0x95-0x97
} ContextData;                           // Total: ~0x98 (152 bytes)

// =============================================================================
// AttackTargetContextData - Most common context for attacks
// =============================================================================

typedef struct {
    ContextData base;                    // 0x00: Base fields (~0x98)

    EntityRef   Caster;                  // 0x98: 16 bytes
    EntityRef   CasterProxy;             // 0xA8: 16 bytes
    EntityRef   Target;                  // 0xB8: 16 bytes
    EntityRef   TargetProxy;             // 0xC8: 16 bytes
    float       Position[3];             // 0xD8: 12 bytes
    bool        IsFromItem;              // 0xE4: 1 byte
    uint8_t     _pad0[3];                // 0xE5-0xE7

    // SpellIdWithPrototype SpellId;     // 0xE8+: Complex, ~32 bytes
    // HitDesc Hit;                      // ~0x1B8 bytes
    // AttackDesc Attack;                // ~0x28 bytes
    // Additional fields...

    uint8_t     _reserved[0x230];        // Placeholder for remaining fields
} AttackTargetContextData;               // Total: ~0x318 (792 bytes)

// =============================================================================
// AttackPositionContextData - For area attacks targeting a position
// =============================================================================

typedef struct {
    ContextData base;                    // 0x00: Base fields

    EntityRef   Caster;                  // 0x98: 16 bytes
    float       Position[3];             // 0xA8: 12 bytes
    float       HitRadius;               // 0xB4: -1.0 default
    uint8_t     _reserved[0x200];        // Placeholder
} AttackPositionContextData;

// =============================================================================
// MoveContextData - For movement/teleport functors
// =============================================================================

typedef struct {
    ContextData base;                    // 0x00: Base fields

    EntityRef   Caster;                  // 0x98
    EntityRef   Target;                  // 0xA8
    EntityRef   Source;                  // 0xB8
    float       Position[3];             // 0xC8: 12 bytes
    float       Distance;                // 0xD4: 0.0 default
    uint8_t     _reserved[0x100];        // Placeholder
} MoveContextData;

// =============================================================================
// TargetContextData - Generic target context
// =============================================================================

typedef struct {
    ContextData base;                    // 0x00: Base fields

    EntityRef   Source;                  // 0x98
    EntityRef   SourceProxy;             // 0xA8
    float       Position[3];             // 0xB8: 12 bytes
    uint8_t     StatusExitCause;         // 0xC4: default 3
    uint8_t     field_C5;                // 0xC5
    uint8_t     field_C6;                // 0xC6: default 19
    uint8_t     _pad0;                   // 0xC7
    uint8_t     _reserved[0x200];        // Placeholder
} TargetContextData;

// =============================================================================
// EquipContextData - For equipment-related functors
// =============================================================================

typedef struct {
    ContextData base;                    // 0x00: Base fields

    EntityRef   Caster;                  // 0x98
    EntityRef   Target;                  // 0xA8
    bool        UseCasterStats;          // 0xB8: default false
    uint8_t     _reserved[0x100];        // Placeholder
} EquipContextData;

// =============================================================================
// SourceContextData - Minimal context with just source
// =============================================================================

typedef struct {
    ContextData base;                    // 0x00: Base fields

    EntityRef   Source;                  // 0x98
    EntityRef   SourceProxy;             // 0xA8
    uint8_t     _reserved[0x100];        // Placeholder
} SourceContextData;

// =============================================================================
// NearbyAttackedContextData - For reaction triggers
// =============================================================================

typedef struct {
    ContextData base;                    // 0x00: Base fields

    EntityRef   OriginalSource;          // 0x98
    EntityRef   Source;                  // 0xA8
    EntityRef   SourceProxy;             // 0xB8
    EntityRef   Target;                  // 0xC8
    EntityRef   TargetProxy;             // 0xD8
    float       Position[3];             // 0xE8: 12 bytes
    bool        IsFromItem;              // 0xF4
    uint8_t     _reserved[0x220];        // Placeholder
} NearbyAttackedContextData;

// NearbyAttackingContextData inherits from NearbyAttackedContextData
typedef NearbyAttackedContextData NearbyAttackingContextData;

// =============================================================================
// InterruptContextData - For interrupt system
// =============================================================================

typedef struct {
    ContextData base;                    // 0x00: Base fields

    bool        OnlyAllowRollAdjustments;// 0x98
    uint8_t     _pad0[7];                // 0x99-0x9F
    EntityRef   Source;                  // 0xA0
    EntityRef   SourceProxy;             // 0xB0
    EntityRef   Target;                  // 0xC0
    EntityRef   TargetProxy;             // 0xD0
    EntityRef   Observer;                // 0xE0
    EntityRef   ObserverProxy;           // 0xF0
    uint8_t     _reserved[0x340];        // Placeholder for RollAdjustments, Interrupt, Hit, Attack
} InterruptContextData;

// =============================================================================
// AttackDesc - Attack result summary
// =============================================================================

struct AttackDesc {
    int32_t     TotalDamageDone;         // 0x00
    int32_t     TotalHealDone;           // 0x04
    uint8_t     InitialHPPercentage;     // 0x08
    uint8_t     field_9;                 // 0x09
    uint8_t     _pad[6];                 // 0x0A-0x0F
    void*       DamageList;              // 0x10: Array<DamagePair>
    uint64_t    DamageListSize;          // 0x18
};                                       // Total: ~0x20 (32 bytes)

// =============================================================================
// HitDesc - Detailed hit information
// =============================================================================

struct HitDesc {
    int32_t     TotalDamageDone;         // 0x00
    uint8_t     DeathType;               // 0x04: DeathType enum
    uint8_t     DamageType;              // 0x05: DamageType enum
    uint8_t     CauseType;               // 0x06: CauseType enum
    uint8_t     _pad0;                   // 0x07
    float       ImpactPosition[3];       // 0x08: 12 bytes
    float       ImpactDirection[3];      // 0x14: 12 bytes
    float       ImpactForce;             // 0x20
    int32_t     ArmorAbsorption;         // 0x24
    int32_t     LifeSteal;               // 0x28
    uint32_t    EffectFlags;             // 0x2C: DamageFlags
    uint64_t    Inflicter;               // 0x30: EntityHandle
    uint64_t    InflicterOwner;          // 0x38: EntityHandle
    uint64_t    Throwing;                // 0x40: EntityHandle
    int32_t     StoryActionId;           // 0x48
    uint8_t     HitWith;                 // 0x4C: HitWith enum
    uint8_t     AttackRollAbility;       // 0x4D: AbilityId
    uint8_t     SaveAbility;             // 0x4E: AbilityId
    uint8_t     SpellAttackType;         // 0x4F
    // ... many more fields (~0x1B8 total)
    uint8_t     _reserved[0x160];        // Placeholder for remaining fields
};                                       // Total: ~0x1B0 (432 bytes)

// =============================================================================
// HitResult - Complete hit result with damage info
// =============================================================================

struct HitResult {
    HitDesc     Hit;                     // 0x00: ~0x1B0 bytes
    AttackDesc  Attack;                  // 0x1B0: ~0x20 bytes
    void*       Results;                 // 0x1D0: HitResultData*
    uint32_t    NumConditionRolls;       // 0x1D8
    uint8_t     _pad[4];                 // 0x1DC-0x1DF
};                                       // Total: ~0x1E0 (480 bytes)

// =============================================================================
// StatsFunctorBase - Base class for all functor types
// =============================================================================

typedef struct {
    void*       vtable;                  // 0x00: Virtual table
    uint32_t    UniqueName;              // 0x08: FixedString index
    uint32_t    _pad0;                   // 0x0C
    uint64_t    FunctorUuid[2];          // 0x10: 16-byte GUID
    void*       RollConditions;          // 0x20: Array<ExportedConditionalRoll>
    uint64_t    StatsConditions;         // 0x28: ConditionId
    uint32_t    PropertyContext;         // 0x30
    int32_t     StoryActionId;           // 0x34
    uint8_t     ObserverType;            // 0x38
    FunctorId   TypeId;                  // 0x3C: FunctorId enum
    uint32_t    Flags;                   // 0x40: FunctorFlags
    uint8_t     _reserved[0x40];         // Padding for derived types
} StatsFunctorBase;

// =============================================================================
// StatsFunctorList - Container for functor chain
// =============================================================================

typedef struct {
    void*       vtable;                  // 0x00
    void*       Elements;                // 0x08: Array<Functor*>
    uint64_t    Count;                   // 0x10
    uint32_t    UniqueName;              // 0x18: FixedString index
    uint8_t     _reserved[0x20];         // Padding
} StatsFunctorList;

// =============================================================================
// Function Addresses (ARM64 macOS)
// =============================================================================

// Main dispatcher
#define ADDR_EXECUTE_STATS_FUNCTOR             0x105783a38

// Context-specific handlers
#define ADDR_EXECUTE_FUNCTORS_ATTACK_TARGET    0x105787918
#define ADDR_EXECUTE_FUNCTORS_ATTACK_POSITION  0x105787c6c
#define ADDR_EXECUTE_FUNCTORS_MOVE             0x10578975c
#define ADDR_EXECUTE_FUNCTORS_TARGET           0x10578a918
#define ADDR_EXECUTE_FUNCTORS_NEARBY_ATTACKED  0x10578e4d8
#define ADDR_EXECUTE_FUNCTORS_NEARBY_ATTACKING 0x10578fba8
#define ADDR_EXECUTE_FUNCTORS_EQUIP            0x105790a28
#define ADDR_EXECUTE_FUNCTORS_SOURCE           0x105792a90
#define ADDR_EXECUTE_FUNCTORS_INTERRUPT        0x1057965e4

// Damage processing
#define ADDR_PROCESS_DEAL_DAMAGE_FUNCTORS      0x10538f374

// =============================================================================
// Function Type Definitions
// =============================================================================

// Context handler signature (most handlers)
typedef void (*ExecuteFunctorsProc)(
    void*              self,        // functor instance or WorldView
    StatsFunctorList*  functors,
    void*              context      // Context-specific type
);

// Interrupt handler has different signature (4 parameters, HitResult first)
// Windows BG3SE: void ExecuteInterruptFunctorProc(HitResult* hit, ecs::EntityWorld* world,
//                                                  Functors* self, InterruptContextData* params);
typedef void (*ExecuteInterruptFunctorsProc)(
    HitResult*             hit,          // Hit result being processed
    void*                  entityWorld,  // ecs::EntityWorld*
    StatsFunctorList*      functors,     // Functors object
    InterruptContextData*  context       // Context with source/target/observer
);

// Main dispatcher signature
typedef void (*ExecuteStatsFunctorProc)(
    StatsFunctorBase*  functor,
    uint64_t           functorId,
    void*              context
);

#endif // FUNCTOR_TYPES_H
