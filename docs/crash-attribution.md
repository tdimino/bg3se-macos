# Mod Crash Attribution System

**Added in v0.36.42** | **Issue:** [#66](https://github.com/tdimino/bg3se-macos/issues/66)

When a crash occurs with many mods loaded, the hardest question is: *which mod caused it?* BG3 has no built-in crash isolation tooling (unlike Skyrim's Crash Logger + Address Library, or Minecraft's Quilt Bisect). The Mod Crash Attribution system solves this with three layers of increasingly detailed diagnostics.

---

## Layer 1: Runtime Mod Attribution

**Always active.** Every event handler knows which mod registered it.

### How It Works

1. **At subscribe time**, the source file is extracted from the Lua call stack via `lua_getinfo(L, "S", &ar)`. The path `@Mods/<ModName>/ScriptExtender/Lua/...` is parsed to extract the mod name, stored in a `char mod_name[64]` field on the `EventHandler` struct.

2. **At dispatch time**, before each handler's `lua_pcall`, the system calls `mod_set_current(h->mod_name, ...)` to set the active mod context. After the call returns (success or error), the context is cleared.

3. **All 30 dispatch paths** are covered:
   - 14 explicit `events_fire_*` functions (Tick, GameStateChanged, KeyInput, TurnStarted, StatusApplied, ExecuteFunctor, NetModMessage, etc.)
   - 15 oneframe component handlers via the `ONEFRAME_DISPATCH` macro (TurnEnded, CombatStarted, CombatLeft, StatusRemoved, EquipmentChanged, LevelUp, Died, Downed, Resurrected, SpellCast, SpellCastFinished, HitNotification, ShortRestStarted, ApprovalChanged, plus TurnStarted entity variant)
   - Console command dispatch

### Per-Mod Health Tracking

Every mod has a `ModHealthEntry` with:

| Field | Description |
|-------|-------------|
| `handlers_registered` | Total event handlers registered by this mod |
| `errors_logged` | Number of `lua_pcall` failures from this mod's handlers |
| `events_handled` | Successful dispatch count |
| `last_error` | Most recent error message (up to 256 chars) |
| `soft_disabled` | Whether the mod is currently soft-disabled |

Up to 128 mods tracked (`MAX_MOD_HEALTH`).

---

## Layer 2: Enhanced Crash Reports

When a crash occurs (Mach exception: `EXC_BAD_ACCESS`, `EXC_BAD_INSTRUCTION`, etc.), the crash report now includes mod context.

### What's in the Report

The Mach exception handler (which intercepts crashes before macOS CrashReporter) writes to `~/Library/Application Support/BG3SE/crash.log`:

```
=== BG3SE Crash Report ===
Exception: EXC_BAD_ACCESS (code=0x...)
Active mod: CombatExtender (from breadcrumb)

Breadcrumbs (most recent first):
  1. fake_Event (funcId=0x1A3, mod=CombatExtender) at T+2341
  2. events_fire (mod=CombatExtender) at T+2340
  3. osiris_dispatch (funcId=0x1A3) at T+2339
  ...

Mod event handler stats:
  CombatExtender: 12 handlers, 3 errors
  SpellFixes: 4 handlers, 0 errors
  MCM: 2 handlers, 0 errors

Register state:
  x0=0x... x1=0x... ...
```

### How Breadcrumbs Carry Mod Context

The `BreadcrumbEntry` struct has a `mod_name` field (pointer to the `EventHandler`'s static `char[64]` buffer). The `BREADCRUMB_MOD(id, mod)` macro stamps mod context onto breadcrumbs during dispatch. Since `EventHandler` memory is static (not heap-allocated), the pointer remains valid even after a crash.

### Async-Signal Safety

The Mach exception handler runs in a dedicated thread (not a signal handler), but still avoids `malloc`/`printf`. Decimal formatting uses a manual digit-extraction loop. All string output is via direct `write()` syscalls.

---

## Layer 3: `!mod_diag` Console Command

Interactive diagnostics for users to investigate and isolate mod issues at runtime.

### Commands

```
!mod_diag                     -- Per-mod health summary (handlers, errors, status)
!mod_diag errors              -- Show all mods with logged errors + last error message
!mod_diag disable <ModName>   -- Soft-disable a mod's event handlers
!mod_diag enable <ModName>    -- Re-enable a mod's event handlers
```

### Soft-Disable

When a mod is soft-disabled:
- Its registered handlers remain in the handler arrays (not removed)
- At dispatch time, the handler is **skipped** (checked via `mh->soft_disabled`)
- Re-enabling instantly restores all handlers
- **No game restart required**

This lets users narrow down which mod causes crashes by disabling mods one at a time (or in groups) and testing.

### Example Session

```
> !mod_diag
=== Mod Health Summary ===
  CombatExtender: 12 handlers, 847 handled, 3 errors [ACTIVE]
  SpellFixes: 4 handlers, 211 handled, 0 errors [ACTIVE]
  MCM: 2 handlers, 105 handled, 0 errors [ACTIVE]

> !mod_diag errors
=== Mod Errors ===
  CombatExtender (3 errors):
    Last: attempt to index a nil value (field 'DamageList')

> !mod_diag disable CombatExtender
Disabled CombatExtender (12 handlers will be skipped)

> !mod_diag
=== Mod Health Summary ===
  CombatExtender: 12 handlers, 847 handled, 3 errors [DISABLED]
  SpellFixes: 4 handlers, 211 handled, 0 errors [ACTIVE]
  MCM: 2 handlers, 105 handled, 0 errors [ACTIVE]
```

### Lua API

For mod authors who want programmatic access:

| Function | Description |
|----------|-------------|
| `Ext.Debug.ModHealthCount()` | Number of tracked mods |
| `Ext.Debug.ModHealthAll()` | Table of all mod health entries (name, handlers, errors, handled, disabled, last_error) |
| `Ext.Debug.ModDisable(modName, bool)` | Soft-disable/enable a mod; returns `true` if found |

---

## Files

| File | Role |
|------|------|
| `src/lua/lua_events.c` | EventHandler.mod_name, extract_mod_name_from_lua(), ModHealthEntry, dispatch wrapping, ONEFRAME_DISPATCH macro |
| `src/lua/lua_events.h` | Mod health public API (get_count, get_name, get_stats, set_disabled) |
| `src/lua/lua_debug.c` | Ext.Debug.ModHealthCount/ModHealthAll/ModDisable implementations |
| `src/lua/lua_ext.c` | `!mod_diag` console command registration (Lua string) |
| `src/core/crashlog.h` | BreadcrumbEntry.mod_name field, BREADCRUMB_MOD macro |
| `src/core/mach_exception.c` | Mod context + health summary in crash report output |

## Prior Art

| System | How It Works |
|--------|-------------|
| **Windows BG3SE** | SEH + `DumpLuaBacktrace` — identifies mods by script path in Lua traceback |
| **Skyrim Crash Logger SSE** | Address Library maps crash addresses to mod DLLs (75-90% hit rate) |
| **Minecraft Quilt Bisect** | Parent-process-monitors-child architecture for automated binary search |
| **BG3SE-macOS (this)** | Runtime mod attribution via Lua callstack parsing + per-handler tracking + Mach exception integration |
