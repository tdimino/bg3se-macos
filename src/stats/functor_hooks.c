/**
 * functor_hooks.c - Stats Functor Hook System Implementation
 *
 * Hooks into the game's functor execution system to fire Lua events
 * before and after each functor runs. This enables mods to:
 * - Monitor damage, healing, status effects
 * - Modify functor parameters
 * - Prevent functor execution
 * - Track combat mechanics
 *
 * Hook Pattern (from Windows BG3SE):
 * 1. Fire "ExecuteFunctor" event with functor + context
 * 2. Call original function
 * 3. Fire "AfterExecuteFunctor" event with functor + context + hit result
 */

#include "functor_hooks.h"
#include "functor_types.h"
#include "../core/logging.h"
#include "../lua/lua_events.h"
#include "../entity/entity_storage.h"

#include <dobby.h>
#include <stdint.h>
#include <string.h>

// =============================================================================
// Module State
// =============================================================================

static lua_State* g_LuaState = NULL;
static bool g_HooksInstalled = false;
static uint64_t g_EventCount = 0;

// Original function pointers (saved by Dobby)
static ExecuteFunctorsProc g_OrigAttackTarget = NULL;
static ExecuteFunctorsProc g_OrigAttackPosition = NULL;
static ExecuteFunctorsProc g_OrigMove = NULL;
static ExecuteFunctorsProc g_OrigTarget = NULL;
static ExecuteFunctorsProc g_OrigNearbyAttacked = NULL;
static ExecuteFunctorsProc g_OrigNearbyAttacking = NULL;
static ExecuteFunctorsProc g_OrigEquip = NULL;
static ExecuteFunctorsProc g_OrigSource = NULL;
static ExecuteInterruptFunctorsProc g_OrigInterrupt = NULL;

// =============================================================================
// Helper: Get runtime address from Ghidra offset
// =============================================================================

// Entity system provides binary base access
extern void* entity_get_binary_base(void);

static uintptr_t get_runtime_addr(uintptr_t ghidra_addr) {
    void* base = entity_get_binary_base();
    if (!base) return 0;
    return ghidra_addr - GHIDRA_BASE_ADDRESS + (uintptr_t)base;
}

// =============================================================================
// Event Dispatch Helpers
// =============================================================================

static void fire_execute_functor_event(StatsFunctorList* functors, void* context, FunctorContextType ctxType) {
    if (!g_LuaState) return;
    events_fire_execute_functor(g_LuaState, (int)ctxType, (void*)functors, context);
    g_EventCount++;
}

static void fire_after_execute_functor_event(StatsFunctorList* functors, void* context, FunctorContextType ctxType) {
    if (!g_LuaState) return;
    events_fire_after_execute_functor(g_LuaState, (int)ctxType, (void*)functors, context);
    g_EventCount++;
}

// =============================================================================
// Hook Implementations
// =============================================================================

static void hook_ExecuteFunctors_AttackTarget(void* self, StatsFunctorList* functors, AttackTargetContextData* ctx) {
    fire_execute_functor_event(functors, ctx, FUNCTOR_CTX_ATTACK_TARGET);
    if (g_OrigAttackTarget) {
        g_OrigAttackTarget(self, functors, ctx);
    }
    fire_after_execute_functor_event(functors, ctx, FUNCTOR_CTX_ATTACK_TARGET);
}

static void hook_ExecuteFunctors_AttackPosition(void* self, StatsFunctorList* functors, AttackPositionContextData* ctx) {
    fire_execute_functor_event(functors, ctx, FUNCTOR_CTX_ATTACK_POSITION);
    if (g_OrigAttackPosition) {
        g_OrigAttackPosition(self, functors, ctx);
    }
    fire_after_execute_functor_event(functors, ctx, FUNCTOR_CTX_ATTACK_POSITION);
}

static void hook_ExecuteFunctors_Move(void* self, StatsFunctorList* functors, MoveContextData* ctx) {
    fire_execute_functor_event(functors, ctx, FUNCTOR_CTX_MOVE);
    if (g_OrigMove) {
        g_OrigMove(self, functors, ctx);
    }
    fire_after_execute_functor_event(functors, ctx, FUNCTOR_CTX_MOVE);
}

static void hook_ExecuteFunctors_Target(void* self, StatsFunctorList* functors, TargetContextData* ctx) {
    fire_execute_functor_event(functors, ctx, FUNCTOR_CTX_TARGET);
    if (g_OrigTarget) {
        g_OrigTarget(self, functors, ctx);
    }
    fire_after_execute_functor_event(functors, ctx, FUNCTOR_CTX_TARGET);
}

static void hook_ExecuteFunctors_NearbyAttacked(void* self, StatsFunctorList* functors, NearbyAttackedContextData* ctx) {
    fire_execute_functor_event(functors, ctx, FUNCTOR_CTX_NEARBY_ATTACKED);
    if (g_OrigNearbyAttacked) {
        g_OrigNearbyAttacked(self, functors, ctx);
    }
    fire_after_execute_functor_event(functors, ctx, FUNCTOR_CTX_NEARBY_ATTACKED);
}

static void hook_ExecuteFunctors_NearbyAttacking(void* self, StatsFunctorList* functors, NearbyAttackingContextData* ctx) {
    fire_execute_functor_event(functors, ctx, FUNCTOR_CTX_NEARBY_ATTACKING);
    if (g_OrigNearbyAttacking) {
        g_OrigNearbyAttacking(self, functors, ctx);
    }
    fire_after_execute_functor_event(functors, ctx, FUNCTOR_CTX_NEARBY_ATTACKING);
}

static void hook_ExecuteFunctors_Equip(void* self, StatsFunctorList* functors, EquipContextData* ctx) {
    fire_execute_functor_event(functors, ctx, FUNCTOR_CTX_EQUIP);
    if (g_OrigEquip) {
        g_OrigEquip(self, functors, ctx);
    }
    fire_after_execute_functor_event(functors, ctx, FUNCTOR_CTX_EQUIP);
}

static void hook_ExecuteFunctors_Source(void* self, StatsFunctorList* functors, SourceContextData* ctx) {
    fire_execute_functor_event(functors, ctx, FUNCTOR_CTX_SOURCE);
    if (g_OrigSource) {
        g_OrigSource(self, functors, ctx);
    }
    fire_after_execute_functor_event(functors, ctx, FUNCTOR_CTX_SOURCE);
}

static void hook_ExecuteFunctors_Interrupt(HitResult* hit, void* entityWorld, StatsFunctorList* functors, InterruptContextData* ctx) {
    // Note: Interrupt handler has 4 parameters (HitResult first) unlike other handlers
    fire_execute_functor_event(functors, ctx, FUNCTOR_CTX_INTERRUPT);
    if (g_OrigInterrupt) {
        g_OrigInterrupt(hit, entityWorld, functors, ctx);
    }
    fire_after_execute_functor_event(functors, ctx, FUNCTOR_CTX_INTERRUPT);
}

// =============================================================================
// Public API
// =============================================================================

bool functor_hooks_init(lua_State* L) {
    if (g_HooksInstalled) {
        LOG_HOOKS_WARN("Functor hooks already installed");
        return true;
    }

    g_LuaState = L;
    int success_count = 0;

    LOG_HOOKS_INFO("Installing functor execution hooks...");

    // Install AttackTarget hook
    uintptr_t addr = get_runtime_addr(ADDR_EXECUTE_FUNCTORS_ATTACK_TARGET);
    if (addr && DobbyHook((void*)addr, (void*)hook_ExecuteFunctors_AttackTarget, (void**)&g_OrigAttackTarget) == 0) {
        LOG_HOOKS_DEBUG("  AttackTarget hook @ 0x%llx", (unsigned long long)addr);
        success_count++;
    } else {
        LOG_HOOKS_ERROR("  Failed to hook AttackTarget @ 0x%llx", (unsigned long long)addr);
    }

    // Install AttackPosition hook
    addr = get_runtime_addr(ADDR_EXECUTE_FUNCTORS_ATTACK_POSITION);
    if (addr && DobbyHook((void*)addr, (void*)hook_ExecuteFunctors_AttackPosition, (void**)&g_OrigAttackPosition) == 0) {
        LOG_HOOKS_DEBUG("  AttackPosition hook @ 0x%llx", (unsigned long long)addr);
        success_count++;
    } else {
        LOG_HOOKS_ERROR("  Failed to hook AttackPosition @ 0x%llx", (unsigned long long)addr);
    }

    // Install Move hook
    addr = get_runtime_addr(ADDR_EXECUTE_FUNCTORS_MOVE);
    if (addr && DobbyHook((void*)addr, (void*)hook_ExecuteFunctors_Move, (void**)&g_OrigMove) == 0) {
        LOG_HOOKS_DEBUG("  Move hook @ 0x%llx", (unsigned long long)addr);
        success_count++;
    } else {
        LOG_HOOKS_ERROR("  Failed to hook Move @ 0x%llx", (unsigned long long)addr);
    }

    // Install Target hook
    addr = get_runtime_addr(ADDR_EXECUTE_FUNCTORS_TARGET);
    if (addr && DobbyHook((void*)addr, (void*)hook_ExecuteFunctors_Target, (void**)&g_OrigTarget) == 0) {
        LOG_HOOKS_DEBUG("  Target hook @ 0x%llx", (unsigned long long)addr);
        success_count++;
    } else {
        LOG_HOOKS_ERROR("  Failed to hook Target @ 0x%llx", (unsigned long long)addr);
    }

    // Install NearbyAttacked hook
    addr = get_runtime_addr(ADDR_EXECUTE_FUNCTORS_NEARBY_ATTACKED);
    if (addr && DobbyHook((void*)addr, (void*)hook_ExecuteFunctors_NearbyAttacked, (void**)&g_OrigNearbyAttacked) == 0) {
        LOG_HOOKS_DEBUG("  NearbyAttacked hook @ 0x%llx", (unsigned long long)addr);
        success_count++;
    } else {
        LOG_HOOKS_ERROR("  Failed to hook NearbyAttacked @ 0x%llx", (unsigned long long)addr);
    }

    // Install NearbyAttacking hook
    addr = get_runtime_addr(ADDR_EXECUTE_FUNCTORS_NEARBY_ATTACKING);
    if (addr && DobbyHook((void*)addr, (void*)hook_ExecuteFunctors_NearbyAttacking, (void**)&g_OrigNearbyAttacking) == 0) {
        LOG_HOOKS_DEBUG("  NearbyAttacking hook @ 0x%llx", (unsigned long long)addr);
        success_count++;
    } else {
        LOG_HOOKS_ERROR("  Failed to hook NearbyAttacking @ 0x%llx", (unsigned long long)addr);
    }

    // Install Equip hook
    addr = get_runtime_addr(ADDR_EXECUTE_FUNCTORS_EQUIP);
    if (addr && DobbyHook((void*)addr, (void*)hook_ExecuteFunctors_Equip, (void**)&g_OrigEquip) == 0) {
        LOG_HOOKS_DEBUG("  Equip hook @ 0x%llx", (unsigned long long)addr);
        success_count++;
    } else {
        LOG_HOOKS_ERROR("  Failed to hook Equip @ 0x%llx", (unsigned long long)addr);
    }

    // Install Source hook
    addr = get_runtime_addr(ADDR_EXECUTE_FUNCTORS_SOURCE);
    if (addr && DobbyHook((void*)addr, (void*)hook_ExecuteFunctors_Source, (void**)&g_OrigSource) == 0) {
        LOG_HOOKS_DEBUG("  Source hook @ 0x%llx", (unsigned long long)addr);
        success_count++;
    } else {
        LOG_HOOKS_ERROR("  Failed to hook Source @ 0x%llx", (unsigned long long)addr);
    }

    // Install Interrupt hook
    addr = get_runtime_addr(ADDR_EXECUTE_FUNCTORS_INTERRUPT);
    if (addr && DobbyHook((void*)addr, (void*)hook_ExecuteFunctors_Interrupt, (void**)&g_OrigInterrupt) == 0) {
        LOG_HOOKS_DEBUG("  Interrupt hook @ 0x%llx", (unsigned long long)addr);
        success_count++;
    } else {
        LOG_HOOKS_ERROR("  Failed to hook Interrupt @ 0x%llx", (unsigned long long)addr);
    }

    g_HooksInstalled = (success_count > 0);
    LOG_HOOKS_INFO("Functor hooks: %d/9 installed", success_count);

    return g_HooksInstalled;
}

void functor_hooks_shutdown(void) {
    if (!g_HooksInstalled) return;

    LOG_HOOKS_INFO("Removing functor hooks...");

    // Unhook all (Dobby doesn't have unhook, but we can at least clear state)
    g_OrigAttackTarget = NULL;
    g_OrigAttackPosition = NULL;
    g_OrigMove = NULL;
    g_OrigTarget = NULL;
    g_OrigNearbyAttacked = NULL;
    g_OrigNearbyAttacking = NULL;
    g_OrigEquip = NULL;
    g_OrigSource = NULL;
    g_OrigInterrupt = NULL;

    g_HooksInstalled = false;
    g_LuaState = NULL;
}

bool functor_hooks_is_active(void) {
    return g_HooksInstalled;
}

uint64_t functor_hooks_get_event_count(void) {
    return g_EventCount;
}

void* functor_hooks_get_original_proc(int ctx_type) {
    if (!g_HooksInstalled) return NULL;

    switch (ctx_type) {
    case FUNCTOR_CTX_ATTACK_TARGET:    return (void*)g_OrigAttackTarget;
    case FUNCTOR_CTX_ATTACK_POSITION:  return (void*)g_OrigAttackPosition;
    case FUNCTOR_CTX_MOVE:             return (void*)g_OrigMove;
    case FUNCTOR_CTX_TARGET:           return (void*)g_OrigTarget;
    case FUNCTOR_CTX_NEARBY_ATTACKED:  return (void*)g_OrigNearbyAttacked;
    case FUNCTOR_CTX_NEARBY_ATTACKING: return (void*)g_OrigNearbyAttacking;
    case FUNCTOR_CTX_EQUIP:            return (void*)g_OrigEquip;
    case FUNCTOR_CTX_SOURCE:           return (void*)g_OrigSource;
    case FUNCTOR_CTX_INTERRUPT:        return (void*)g_OrigInterrupt;
    default: return NULL;
    }
}
