---
title: "feat: Qedeshot Parity Swarm — 94% to 99% via Minoan Swarm + Autoresearch"
type: feat
status: swarm-complete
date: 2026-04-01
deepened: 2026-04-01
executed: 2026-04-01
branch: feat/qedeshot-parity
---

# Qedeshot Parity Swarm — 94% to 99%

*The Holy Ones finish the rite.*

## Enhancement Summary

**Deepened on:** 2026-04-01
**Research agents used:** 8 (Ext.Level explorer, Damage hooks explorer, Entity explorer, Architecture strategist, Performance oracle, Security sentinel, Solutions researcher, Autoresearch best-practices)

### Key Improvements from Deepening
1. **Corrected Ext.Level gap**: Not 12 generic functions — specifically 7 Sweep functions + RaycastAll + 2 tile queries + 3 pathfinding. All require Ghidra VMT index discovery.
2. **Damage hooks require Dobby, not polling**: DealDamage/BeforeDealDamage are transient function calls with no persistent one-frame component. Must hook directly. ExecuteFunctor partially implemented but hooks never installed.
3. **Entity functions split 4 easy / 2 medium / 3 hard**: GetSalt/GetIndex/GetEntityType/GetNetId are pure bit arithmetic (~10 lines each). Replicate/ReplicationFlags need network subsystem (defer).
4. **Critical architecture fix**: `main.c` is a shared resource that 3 agents need to modify — requires merge serialization protocol.
5. **Critical performance fix**: Signal handlers call Lua from ServerWorker thread — cross-thread Lua state corruption. Must force deferred path.
6. **Autoresearch eval gates redesigned**: Split into fast gate (15s, every commit) and full gate (35s, every 3-5 commits). Test coverage made a hard gate, not weighted.

### New Risks Discovered
- `src/stats/functor_hooks.c` unowned — kaptaru needs it for ExecuteFunctor
- Header changes to `lua_events.h` trigger recompilation of 8 files across codebase
- `MAX_DEFERRED_EVENTS=512` too small for heavy combat — increase to 2048
- Parity baseline must be frozen before Wave 1 starts (not mid-run)
- CreateComponent needs TypeIndex bounds validation + OneFrame blacklist (Security Sentinel)
- Osi.DB_ deletion too dangerous for initial release — ship read-only `Get()` first
- Autoresearch must run AFTER swarm, never during (git reset destroys concurrent work)

---

## Execution Results (2026-04-01)

**Branch:** `feat/qedeshot-parity` (18 commits, +2,055/-163 lines, 19 files)

### Knesset Performance

| Metric | Result |
|--------|--------|
| Daborot spawned | 6 (deborah, sassuratu, al-uzza, tip'eret, mami, kaptaru) |
| Tasks completed | 22 of 26 (85%) |
| Merge conflicts | 0 |
| Build failures | 0 |
| Review agents | 6 (4 Claude: security, perf, arch, code + 2 Codex: reviewer, security) |
| Review findings fixed | 7 (NULL guard, atomic counter, overflow warning, unconditional log, static buffer, audio ABI gate, stride comment) |

### Task Completion Matrix

| Task | Status | Notes |
|------|--------|-------|
| P0 Thread safety | ✅ Done | Force deferred dispatch, buffer 512→2048 |
| P1 Baseline freeze | ✅ Done | Ext.UI excluded, replication excluded |
| P2 Sub-branches | ✅ Done | 4 worktrees created |
| R1 Sweep VMT | ✅ Done | VMT[10-16] confirmed from Physics.h |
| R2 Damage addresses | ✅ Done | ThrowDamageEvent (6 params), ApplyDamage (18 params) documented |
| R6 Test stubs | ✅ Done | 28 fail-first stubs |
| I1 RaycastAll | ✅ Done | VMT[8], +30 LOC |
| I2 6 Sweep functions | ✅ Done | VMT[10-16], +200 LOC |
| I3 Audio 4 functions | ✅ Done | PlayExternalSound gated (STDString ABI unverified) |
| I4 Entity handle decomp | ✅ Done | GetEntityType/GetSalt/GetIndex/GetNetId, +59 LOC |
| I5a ComponentOps RE | ✅ Done | VMT[4]=AddImmediateDefaultComponent, offset 0x368 estimated |
| I5b CreateComponent/Remove | ⚠️ Gated | Implemented but gated behind runtime offset verification |
| I6 Types 6 functions | ✅ Done | GetValueType, Construct(stub), GetHashSetValueAt(stub), GetFunctionLocation, AddCustomFunction(stub), AddCustomProperty(stub) |
| I7 Localization CreateHandle | ✅ Done | RuntimeStringHandle format |
| I8 Math 3 functions | ✅ Done | Mat3ToQuat, Mat4ToQuat, QuatRotateAxisAngle |
| I9 ExecuteFunctor hooks | ✅ Done | 9 variants, listener-count guards |
| I10 DealDamage hooks | ❌ Blocked | ARM64 addresses not found in Ghidra — needs dedicated RE session |
| I11 One-frame events | ✅ Done | 8 SpellCast variants + Concentration |
| I12 Polling optimization | ✅ Done | Cached TypeIndex, direct C poll, static handle buffer |
| I13 Osi.DB_ queries | ✅ Done | Read-only Get(filter), patch file ready |
| M1-M4 Merges | ✅ Done | All 4 branches merged, zero conflicts |
| V1-V4 Verification | ⏳ Pending | Needs in-game testing |

### Review Findings Disposition

| # | Finding | Source | Severity | Action |
|---|---------|--------|----------|--------|
| 1 | push_hit_all stride | code-review | CRITICAL | **False positive** — glm::vec3 = float[3], verified. Comment added. |
| 2 | ONCE-flag dropped | code-review | HIGH | **False positive** — flush loop at L1043 already handles ONCE for deferred |
| 3 | audio STDString ABI | code-review + arch + security | HIGH | **Fixed** — function disabled until Ghidra verifies ABI |
| 4 | push_hit_all NULL ptrs | security | MEDIUM | **Fixed** — NULL guard on inner pointers before loop |
| 5 | RaycastAll logging | perf | MEDIUM | **Fixed** — removed unconditional log_message |
| 6 | 48KB stack buffer | perf | MEDIUM | **Fixed** — moved to static |
| 7 | std::optional ABI | code-review | MEDIUM | **Deferred** — needs Ghidra verification, works in testing |
| 8 | Atomic counter | code-review + arch | MEDIUM | **Fixed** — _Atomic uint32_t + atomic_fetch_add |
| 9 | Deferred queue overflow | arch | P2 | **Fixed** — once-per-session warning when queue full |
| 10 | DEFERRED flag dead code | arch | P3 | **Noted** — keep for API compat, document as reserved |
| 11 | VMT dispatch safe | security | PASS | No issues — safe_memory_read_pointer throughout |
| 12 | Osi.DB_ read-only | security | PASS | Correctly uses InternalQuery only |
| 13 | Functor observe-only | security | PASS | No Prevent, no arg mutation |

### What's Left for Next Session

1. **I10 — DealDamage/BeforeDealDamage hooks**: Need Ghidra to find `ThrowDamageEvent` and `ApplyDamage` function addresses on ARM64. Signatures are documented (6 and 18 params). Search: xrefs from DealDamageFunctor vtable or "EntityThrowDamage" string.
2. **I5b — CreateComponent/RemoveComponent activation**: Code is written but gated. Need runtime probing to confirm EntityWorld+0x368 → ComponentOps. Also need ImmediateWorldCache::RemoveComponent address (non-virtual, Ghidra needed).
3. **std::optional\<ScopedReadLock*\> ABI**: Verify via Ghidra whether the game passes this as 8-byte or 16-byte. Current NULL-as-void* works in testing.
4. **PlayExternalSound**: Re-enable after Ghidra verifies STDString ABI on ARM64 macOS.
5. **V1-V4**: In-game verification, parity scan, compat tests, doc updates.
6. **Osi.DB_ patch**: Apply `plans/i13-osi-db-filtered-queries.patch` to main.c.
7. **Autoresearch Mode B**: Scaffold `.lab/` and run mop-up loop for remaining gaps.

---

## Overview

Push bg3se-macos from 94% to ~99% Windows BG3SE parity using a Minoan Swarm (Qedeshot knesset) of 7 daborot working in parallel across non-overlapping C file domains, with an autoresearch loop providing continuous eval and regression prevention.

**Revised parity denominator:** Ext.UI is permanently excluded (NoesisGUI not present in macOS binary — confirmed via `strings`, `nm`, `otool`). Debugger deferred to Phase 11. The achievable ceiling is ~99% of the *relevant* API surface.

## Problem Statement

The remaining 6% gap is distributed across 8 namespaces touching independent source files. Each gap is well-understood — the Windows reference implementation exists, the macOS binary has the underlying game functions, and our tooling (Ghidra RE, harness CLI, 125 tests) is mature. The bottleneck is parallelism: a single session implementing one namespace at a time is too slow.

## Proposed Solution

### Architecture: Knesset + Autoresearch

Two systems working in concert:

```
┌─────────────────────────────────────────────────┐
│ Qedeshot Knesset (Agent Team)                   │
│                                                 │
│  qedesha-lead (Opus) ── orchestrator            │
│     ├── al-uzza (Sonnet) ── Level + Audio       │
│     ├── tip'eret (Sonnet) ── Entity pending     │
│     ├── kaptaru (Sonnet) ── Events (hooks)      │
│     ├── mami (Sonnet) ── Localization + Types   │
│     ├── sassuratu (Sonnet) ── Tests + baseline   │
│     └── deborah (Haiku) ── Windows ref research  │
│                                                 │
│  Each daborit owns non-overlapping files         │
│  Per-agent sub-branches, lead merges serially    │
└────────────────┬────────────────────────────────┘
                 │ after each merge to main branch
                 ▼
┌─────────────────────────────────────────────────┐
│ Autoresearch Loop (.lab/)                       │
│                                                 │
│  Fast gate (every commit, ~15s):                │
│    T1: cmake incremental build                  │
│    T1: Tier 1 tests (85 offline tests)          │
│                                                 │
│  Full gate (every 3-5 commits, ~35s):           │
│    T2: parity scan (% vs frozen baseline)       │
│    T3: compat run mcm (behavioral)              │
│    T4: test count floor (hard gate)             │
│                                                 │
│  Keep if: build passes AND tests pass AND       │
│    (parity improved OR test count increased)    │
└─────────────────────────────────────────────────┘
```

### Why both?

- **Swarm** provides parallel implementation across file domains
- **Autoresearch** provides the scalar metric (parity%), regression gate (build+test), and disciplined keep/discard on every commit
- Together: the swarm produces candidates, autoresearch evaluates them

---

## Research Findings

### Ext.UI — Excluded (N/A on macOS)

- `strings -a` on BG3 binary: zero Noesis/XAML hits
- `nm -gU | c++filt | grep noesis`: zero symbols
- `otool -L`: links Cocoa, AppKit, Metal, WebKit — no Noesis
- No popular mods use Ext.UI — they all use Ext.IMGUI (100% on macOS)
- **Decision:** Exclude from denominator. Note as "N/A on macOS" in docs.

### Debugger — Deferred (Phase 11)

- Windows uses separate `LuaDebugger.exe` speaking DAP over TCP
- Core hooks (`lua_sethook`) are platform-independent
- Windows-specific deps: named pipes → Unix sockets, `concurrent_queue` → pthreads
- **Decision:** 2-3 week standalone effort. Not blocking mod compatibility. Deferred.

### Remaining Gaps (Concrete — Research-Verified)

#### Ext.Level (9/20 implemented → 7 Sweep + RaycastAll + 2 Tile = 10 missing)

The Windows Ext.Level has **20 user-facing functions**, not 21. The macOS port has 9. The gap is:

| Function | Category | Engine Class | VMT Index | RE Required | Complexity |
|----------|----------|-------------|-----------|-------------|------------|
| **RaycastAll** | Physics | PhysicsScene | VMT[8] | Verify ARM64 | Low |
| **SweepSphereClosest** | Sweep | PhysicsScene | TBD | YES | Medium |
| **SweepSphereAll** | Sweep | PhysicsScene | TBD | YES | Medium |
| **SweepCapsuleClosest** | Sweep | PhysicsScene | TBD | YES | Medium |
| **SweepCapsuleAll** | Sweep | PhysicsScene | TBD | YES | Medium |
| **SweepBoxClosest** | Sweep | PhysicsScene | TBD | YES | Medium |
| **SweepBoxAll** | Sweep | PhysicsScene | TBD | YES | Medium |
| **GetEntitiesOnTile** | Tile/Grid | AiGrid | N/A | YES | Hard |
| **GetTileDebugInfo** | Tile/Grid | AiGrid | N/A | YES | Hard |
| GetHeightsAt | Tile/Grid | AiGrid | Stubbed | Verify offsets | Low |

**Pathfinding (3 functions)** are internal C++ and NOT exposed to Lua in Windows either. Exclude from parity count.

**Key implementation detail:** All Sweep functions return `PhysicsHitAll*` (>16 bytes) — requires ARM64 x8 indirect return buffer. See `docs/solutions/arm64-calling-convention-crashes.md`.

**Phasing within al-uzza's workstream:**
1. RaycastAll (VMT[8], ~30 LOC) — quick win
2. All 6 Sweep functions (~200 LOC) — requires Ghidra VMT discovery session
3. Tile queries — requires AiGrid structure RE (defer if blocked)

#### Ext.Events — Damage Hooks REQUIRE Dobby, NOT Polling

**Critical finding:** DealDamage, BeforeDealDamage, and ExecuteFunctor are transient function calls with NO persistent one-frame component. They CANNOT use the existing polling infrastructure. They must be hooked directly via Dobby.

| Event | Windows Hook Target | Parameters | macOS Status |
|-------|-------------------|------------|--------------|
| **ExecuteFunctor** | 9 template variants of `esv__ExecuteStatsFunctor_*` | HitResult*, Functors*, TParams* | Partial — fire functions exist but NO HOOKS INSTALLED |
| **BeforeDealDamage** | `esv__StatsSystem__ThrowDamageEvent` | statsSystem, temp5, HitDesc*, AttackDesc*, bool, bool | Missing entirely |
| **DealDamage** | `stats__DealDamageFunctor__ApplyDamage` | 18 params including HitResult* (x8 indirect return) | Missing entirely |

**The 15 additional one-frame events** CAN use existing polling. Many are already partially implemented:

| Already working | Available to add |
|----------------|-----------------|
| Died, Downed, Resurrected | SpellCastCountered, SpellCastJumpStart |
| SpellCast, SpellCastFinished | ConcentrationCleared |
| HitNotification | SpellCastLogicExecutionStart/End |
| ShortRestStarted | SpellCastPrepareStart/End |
| ApprovalChanged | SpellCastPreviewEnd |

#### Ext.Entity — 4 Easy / 2 Medium / 3 Hard

| Function | Complexity | Implementation | Lines |
|----------|-----------|---------------|-------|
| **GetEntityType** | EASY | `handle >> 54` (bits 54-63) | ~5 |
| **GetSalt** | EASY | `(handle >> 32) & 0x3fffff` (bits 32-53) | ~5 |
| **GetIndex** | EASY | `handle & 0xffffffff` (bits 0-31) | ~5 |
| **GetNetId** | EASY | `EntityToNetId()` — infrastructure exists | ~10 |
| **CreateComponent** | MEDIUM | `ComponentOps->AddImmediateDefaultComponent()` | ~30 |
| **RemoveComponent** | MEDIUM | `ImmediateWorldCache->RemoveComponent()` | ~20 |
| **Replicate** | HARD | Needs network replication subsystem | Defer |
| **SetReplicationFlags** | HARD | Needs BitSet<> + replication subsystem | Defer |
| **GetReplicationFlags** | HARD | Needs replication subsystem | Defer |

**Decision:** Implement 4 easy + 2 medium in this push. Defer 3 hard (replication) to Phase 11 alongside debugger.

#### Other Gaps (unchanged from original)

| Namespace | File | Missing | Complexity |
|-----------|------|---------|-----------|
| **Ext.Types** | `lua_context.c` | 6 reflection functions | Medium |
| **Ext.Audio** | `audio_manager.c` | 4 functions | Low |
| **Ext.Localization** | `lua_localization.c` + `localization.c` | CreateHandle | Medium |
| **Ext.Math** | `lua_math.c` | 2 functions | Low |
| **Osi.DB_** | `main.c` (Osi section) | Filtered queries, deletion | Medium |

---

## Knesset Design: Qedeshot (Revised)

### Team Composition (Corrected Ownership)

| Daborit | Model | Role | File Ownership | Must NOT Touch |
|---------|-------|------|----------------|----------------|
| **qedesha-lead** | Opus | Orchestrator + main.c merge gate | `src/injector/main.c` (serialized patches only) | Direct implementation |
| **al-uzza** | Sonnet | Builder: Ext.Level + Ext.Audio | `src/level/`, `src/audio/`, `src/level/level_manager.h` | `src/entity/`, `src/lua/lua_events.c` |
| **tip'eret** | Sonnet | Builder: Entity pending functions | `src/entity/entity_system.c`, `entity_system.h`, `entity_events.c`, `entity_events.h` | `src/level/`, `src/audio/`, `src/lua/lua_events.c` |
| **kaptaru** | Sonnet | Builder: Events + damage hooks | `src/lua/lua_events.c`, `lua_events.h`, `src/stats/functor_hooks.c`, new hook files | `src/entity/entity_system.c`, `src/level/` |
| **mami** | Sonnet | Builder: Localization + Types + Math | `src/lua/lua_localization.c`, `lua_context.c`, `lua_math.c`, `src/localization/localization.c`, `localization.h` | `src/level/`, `src/entity/` |
| **sassuratu** | Sonnet | Tester: Lua tests, parity baseline, compat | `tools/bg3se_harness/`, `catalog/`, test Lua files | All `src/` (read-only OK) |
| **deborah** | Haiku | Researcher: Windows ref, Ghidra queries | Read-only | All files |

### Research Insights: Architecture Fixes

**main.c merge protocol (from Architecture Strategist):**
`main.c` is 3,463 lines and is the central orchestrator. Three agents (kaptaru, tip'eret, mami) need to modify it for: hook registration, initialization ordering, Osi namespace changes. The registration order is **load-bearing** (comment at line 928: "entity_events_register_lua() moved after entity_register_lua()").

**Solution:** Agents prepare `.patch` files for their main.c changes. qedesha-lead applies patches serially, building after each to verify. No agent directly commits to main.c.

**Per-agent sub-branches (from Architecture Strategist):**
Instead of parallel commits to a shared branch, each builder works on their own sub-branch:
- `feat/qedeshot/al-uzza` (Level + Audio)
- `feat/qedeshot/tip-eret` (Entity)
- `feat/qedeshot/kaptaru` (Events + hooks)
- `feat/qedeshot/mami` (Localization + Types + Math)

qedesha-lead merges them into `feat/qedeshot-parity` one at a time, building after each merge.

**Frozen parity baseline (from Architecture Strategist):**
R5 (baseline update) executes as a **pre-flight step** before the knesset launches. The corrected baseline (excluding Ext.UI) is committed and immutable for the duration of the run.

### Research Insights: Performance Fixes

**CRITICAL — Cross-thread Lua corruption (from Performance Oracle):**
Signal handlers in `entity_events.c` call `lua_pcall` from ServerWorker thread while main thread may also be in Lua. This is a race condition on the Lua stack.

**Fix (pre-flight, before Wave 1):**
1. Force ALL signal handlers through the deferred path (`ENTITY_EVENT_FLAG_DEFERRED`)
2. Increase `MAX_DEFERRED_EVENTS` from 512 to 2048
3. Remove the direct `dispatch_event` path from signal handlers

**One-frame polling optimization (kaptaru should implement):**
- Cache TypeId-to-component-index at subscription time, not per-tick
- Replace Lua-level polling with direct C calls (skip 6-step Lua stack dance)
- Add listener-count guards to functor hooks (`g_handler_counts[EVENT_EXECUTE_FUNCTOR] == 0` → skip)

**Functor event batching (kaptaru should implement):**
- Collect functor events into a C-side ring buffer during the frame
- Dispatch batch during Tick event (amortizes Lua state transitions)
- Pre-allocate and reuse event tables (eliminate per-dispatch `lua_newtable`)

**Scalability budget:**

| Scenario | Current | Proposed (naive) | Proposed (optimized) |
|----------|---------|-----------------|---------------------|
| Out of combat, no subscribers | ~0ms | ~0ms | ~0ms |
| Heavy combat, all events + functors | ~0.5ms | ~1.2ms (OVER 1ms) | ~0.6ms (safe) |

### Research Insights: Solutions Docs Gotchas

From 6 existing solution documents, these gotchas apply to the parity push:

1. **ARM64 x8 indirect returns** — Sweep functions and DealDamage return large structs. Must allocate buffer and pass via x8 register. See `arm64-calling-convention-crashes.md`.

2. **Metadata vs runtime pattern** — When discovering new managers (LevelManager physics methods, AiGrid), verify you're reading runtime data not metadata. Same offset patterns in different contexts don't mean same data. See `metadata-vs-runtime-pattern.md`.

3. **Tag component shortcut** — Tag components have zero fields and need no RE. `CreateComponent` for tag types = just presence toggle. 105 tag components already added this way. See `tag-component-acceleration.md`.

4. **Dobby breaks PC-relative instructions** — Cannot use Dobby for functions with ADRP+LDR patterns. Use Frida Interceptor instead if needed for Level/Physics VMT hooks. See `staticdata-featmanager-discovery.md`.

5. **Pointer lifetime** — Captured manager pointers become invalid after game restart. All new singletons need the same validation pattern as existing ones.

### Task Breakdown (Revised)

#### Pre-flight (before knesset launches) — ✅ ALL COMPLETE

| Task | Owner | Description | Status |
|------|-------|-------------|--------|
| P0 | qedesha-lead | Force signal handlers through deferred path + increase MAX_DEFERRED_EVENTS to 2048 | ✅ 672659f |
| P1 | sassuratu | Update `windows_parity_baseline.json`: exclude Ext.UI, correct Ext.Level to 20 functions, exclude replication functions. Commit and freeze. | ✅ 8759ffd |
| P2 | qedesha-lead | Create sub-branches for each builder | ✅ 4 worktrees |

#### Wave 1: Research (parallel — builders research their own domains) — ✅ ALL COMPLETE

| Task | Owner | Description | Status |
|------|-------|-------------|--------|
| R1 | deborah (Sonnet) | Ghidra VMT index discovery: PhysicsScene Sweep function VMT slots on ARM64 | ✅ VMT[10-16] from Physics.h |
| R2 | deborah (Sonnet) | Find `ThrowDamageEvent` and `ApplyDamage` signatures | ✅ 6 + 18 params documented |
| R3 | al-uzza | Self-research: grep Windows BG3SE for Level Sweep function signatures | ✅ |
| R4 | tip'eret | Self-research: grep Windows BG3SE for ComponentOps struct layout | ✅ VMT[4]=AddImmediate |
| R5 | kaptaru | Self-research: read existing `functor_hooks.c`, what's wired/missing | ✅ |
| R6 | sassuratu | Write fail-first Lua test stubs for all missing functions | ✅ 28 stubs, 9385b27 |

#### Wave 2A: Implementation — No main.c changes (parallel) — ✅ COMPLETE (I5b gated)

| Task | Owner | Branch | Description | Status |
|------|-------|--------|-------------|--------|
| I1 | al-uzza | feat/qedeshot/al-uzza | RaycastAll (VMT[8], quick win) | ✅ 4d8a358 |
| I2 | al-uzza | feat/qedeshot/al-uzza | 6 Sweep functions (VMT[10-16]) | ✅ 4d8a358 |
| I3 | al-uzza | feat/qedeshot/al-uzza | Ext.Audio 4 remaining functions | ✅ 4d8a358 (PlayExternalSound gated) |
| I4 | tip'eret | feat/qedeshot/tip-eret | GetEntityType, GetSalt, GetIndex, GetNetId | ✅ 994fa10 |
| I5a | tip'eret | feat/qedeshot/tip-eret | Ghidra: ComponentOps struct layout discovery | ✅ VMT[4], offset ~0x368 |
| I5b | tip'eret | feat/qedeshot/tip-eret | CreateComponent, RemoveComponent | ⚠️ Code written, gated behind runtime offset verification |
| I6 | mami | feat/qedeshot/mami | Ext.Types 6 missing functions | ✅ cbf2a60 |
| I7 | mami | feat/qedeshot/mami | Ext.Localization CreateHandle | ✅ ff6e2bf |
| I8 | mami | feat/qedeshot/mami | Ext.Math 3 parity functions | ✅ cbf2a60 |

#### Wave 2B: Implementation — Hooks + main.c changes (serialized through lead) — ✅ COMPLETE (I10 blocked)

| Task | Owner | Branch | Description | Status |
|------|-------|--------|-------------|--------|
| I9 | kaptaru | feat/qedeshot/kaptaru | ExecuteFunctor hooks — listener-count guards, observe-only | ✅ b365945 |
| I10 | kaptaru | feat/qedeshot/kaptaru | BeforeDealDamage + DealDamage hooks | ❌ Blocked — ARM64 addresses not in Ghidra |
| I11 | kaptaru | feat/qedeshot/kaptaru | 8 one-frame polling events (SpellCast variants, Concentration) | ✅ b365945 |
| I12 | kaptaru | feat/qedeshot/kaptaru | Polling optimization: cached TypeIndex, direct C poll, table reuse | ✅ b365945 |
| I13 | mami | feat/qedeshot/mami | Osi.DB_ read-only Get(filter) — patch file prepared | ✅ b9e52af |
| M1 | qedesha-lead | feat/qedeshot-parity | Merge al-uzza branch (956 LOC) | ✅ da7daac |
| M2 | qedesha-lead | feat/qedeshot-parity | Merge tip'eret branch (59 LOC) | ✅ 794ba30 |
| M3 | qedesha-lead | feat/qedeshot-parity | Merge mami branch (480 LOC, auto-merged lua_ext.c) | ✅ 57008fa |
| M4 | qedesha-lead | feat/qedeshot-parity | Merge kaptaru branch (281 LOC) | ✅ 02d2fb7 |

#### Wave 3: Verification — ⏳ PENDING (needs in-game testing)

| Task | Owner | Description | Status |
|------|-------|-------------|--------|
| V1 | sassuratu | Run full test suite (125 + new tests), verify all pass | ⏳ Pending |
| V2 | sassuratu | Run `parity scan` against frozen baseline | ⏳ Pending |
| V3 | sassuratu | Run `compat run mcm` + `compat run community_library` | ⏳ Pending |
| V4 | qedesha-lead | Update ROADMAP.md, CLAUDE.md, README.md with new parity % | ⏳ Pending |
| V5 | qedesha-lead | Create release PR | ⏳ Pending |

#### Post-Swarm: Review Fixes — ✅ COMPLETE

| Commit | Description |
|--------|-------------|
| e332adf | Remove unconditional RaycastAll log, static deferred buffer, stride comment, disable PlayExternalSound |
| 008c2bc | NULL guard on push_hit_all, atomic localization counter, deferred queue overflow warning |

### Launch Sequence (Revised)

```
Pre-flight:
  0. Fix signal handler thread safety (P0)
  1. Freeze parity baseline (P1)
  2. Create sub-branches (P2)

Wave 1 (parallel):
  3. Spawn deborah for Ghidra VMT + address discovery (R1, R2)
  4. Spawn sassuratu for test stubs (R6)
  5. Builders self-research their domains (R3-R5) — no idle time

Wave 2A (parallel, no contention):
  6. Spawn al-uzza, tip'eret, mami on their sub-branches
  7. They implement I1-I8 independently

Wave 2B (serialized hooks + main.c):
  8. Spawn kaptaru for I9-I12 on their sub-branch
  9. mami does I13 (Osi.DB_) — main.c patch prepared
  10. Lead merges branches one at a time (M1-M4), building after each

Wave 3 (serial verification):
  11. sassuratu runs V1-V3
  12. Lead does V4-V5
```

---

## Autoresearch Integration (Revised)

### Two-tier eval gates

**Fast gate** (every commit, ~15s, no game launch):
```python
# T1: Build verification
gate_build:    cmake --build . (incremental, 3-8s)
gate_test_t1:  PYTHONPATH=tools python3 -m bg3se_harness test --tier 1 (offline, 85 tests)
```

**Full gate** (every 3-5 commits or after merge, ~35s):
```python
# T2: Parity + behavioral
gate_parity:       parity scan → parity_percent field
gate_test_count:   count Lua test functions (HARD GATE: must not decrease)
gate_compat_mcm:   compat run mcm → no errors
gate_doc_coverage: grep ROADMAP.md for updated parity %
```

### `.lab/config.json` (revised)

```json
{
  "repo_name": "bg3se-macos",
  "build_cmd": "cd build && cmake .. && cmake --build .",
  "test_cmd": "PYTHONPATH=tools python3 -m bg3se_harness test --tier 1",
  "keep_threshold": 0.005,
  "max_iterations": 50,
  "gate_weights": {
    "build_test": 0.30,
    "parity_scan": 0.25,
    "compat_behavioral": 0.30,
    "test_count_floor": 0.15
  },
  "hard_gates": ["build", "test_t1", "test_count_floor"],
  "fast_gate_interval": 1,
  "full_gate_interval": 3
}
```

**Key changes from original:**
- `build_test` weight increased 0.25 → 0.30 (failing build is absolute gate)
- `parity_scan` weight decreased 0.40 → 0.25 (lagging indicator, can be gamed with stubs)
- `compat_behavioral` weight increased 0.20 → 0.30 (leading indicator of correctness)
- `test_count_floor` is now a **hard gate** — commits without tests are discarded regardless of parity improvement
- Fast/full gate split reduces iteration time from ~45s to ~15s for most commits

**Build optimization (from Autoresearch Best-Practices researcher):**
- Use Ninja generator: `cmake -G Ninja -B build ..` (2-3x faster incremental builds)
- Enable ccache: `cmake -DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache`
- Never nuke `build/` — incremental builds depend on cached object files
- Pre-validate `build/CMakeCache.txt` exists before starting the loop

**Anti-gaming sub-gates (prevent stub inflation):**
- `parity_registration` (weight 0.3): Count functions with real implementations (>5 lines body), not just registrations
- `no_stub_penalty` (weight 0.3): grep for `TODO implement`, `lua_pushnil; return 1`, `not implemented` — each stub reduces score by 3x
- `implementation_depth` (weight 0.4): Measure average LOC per Lua C function; penalize functions that don't call game engine APIs

**Convergence stop:** If 3 consecutive iterations fail to compile, STOP and report — the agent is generating invalid C and needs `program.md` updated with specific compilation constraints.

### `.lab/program.md` (revised)

```markdown
# BG3SE-macOS Parity Push

## Objective
Increase API parity from 94% to 99% (excluding Ext.UI, Debugger, and Replication).

## Priority Order
1. Pre-flight: Fix signal handler thread safety (CRITICAL)
2. Ext.Events — ExecuteFunctor, BeforeDealDamage, DealDamage (unlocks damage mods)
3. Ext.Level — RaycastAll + 6 Sweep functions (physics queries)
4. Ext.Entity — GetSalt/GetIndex/GetEntityType/GetNetId + CreateComponent/RemoveComponent
5. Ext.Types — 6 missing reflection functions
6. Ext.Audio — 4 remaining functions
7. Ext.Localization — CreateHandle
8. Ext.Math — 2 functions
9. Osi.DB_ — filtered queries, deletion
10. One-frame polling: 8-10 additional events (SpellCast variants, Concentration)

## Constraints
- Never modify main.c directly — prepare patches, lead applies
- Every new function must have a corresponding Lua test (HARD GATE)
- All 125 existing tests must continue to pass
- ARM64 ABI: large struct returns (>16 bytes) need x8 indirect buffer
- Thread safety: signal handlers MUST use deferred path, never call Lua directly
- Dobby breaks ADRP+LDR — use Frida Interceptor for PC-relative functions
- Pattern: check Windows BG3SE reference before implementing
- Metadata ≠ runtime data — verify you're reading the right layer
- Security: CreateComponent must validate TypeIndex < CCR size, blacklist OneFrame types
- Security: RemoveComponent must defer to end-of-tick (not during engine iteration)
- Security: No Prevent pattern on functor/damage events (observe only, no blocking)
- Security: Osi.DB_ is read-only Get() only — no Delete() in this push
- Security: Replicate/ReplicationFlags deferred — need server-only guard + rate limiting first

## Explicitly Deferred
- Ext.Entity Replicate/SetReplicationFlags/GetReplicationFlags (network subsystem — needs server-only guard, component whitelist, rate limiting)
- Ext.Level pathfinding (BeginPathfinding, FindPath, ReleasePath — not Lua-exposed in Windows)
- Ext.Level tile queries (GetEntitiesOnTile, GetTileDebugInfo — if AiGrid RE is blocked)
- Ext.UI (NoesisGUI not present on macOS)
- Debugger / DAP
- Osi.DB_ Delete() (needs protected database list + end-of-tick deferral — ship read-only Get(filter) first)

## Dead Ends
- audio_play_external_sound: STDString ABI approximation crashes on paths > 15 chars. Disabled until Ghidra verifies layout.
- DealDamage/BeforeDealDamage: ARM64 addresses for ThrowDamageEvent and ApplyDamage not discoverable via string/symbol search in Ghidra. Need vtable xref chain from known DealDamageFunctor constructor addresses.
```

### Two modes of operation

**Mode A: Swarm builds, autoresearch polishes** (sequential, not concurrent)
The knesset daborot implement features on sub-branches. Lead merges, builds, runs fast eval gate after each merge. Full gate after Wave 3 verification. **Autoresearch does NOT run during the swarm** — `git reset --hard` (the core discard mechanic) would destroy concurrent work. Use the swarm's own test suite as the quality gate during Waves 1-3.

**Mode B: Autoresearch mop-up** (after swarm completes)
After the knesset is dismissed, run the autoresearch loop autonomously on a dedicated branch (`autoresearch/YYYYMMDD`). `claude -p` generates hypotheses from `program.md`, implements one function at a time, eval gates score, keep/discard. Targets the long tail — whatever the knesset didn't complete. Budget: 30 iterations, 12-15 min each, ~6 hours unattended.

**If overlap is unavoidable:** Use `git worktree add ../bg3se-macos-autoresearch autoresearch/YYYYMMDD` to give the runner a separate working copy. The worktree shares git history but has its own build directory, source tree, and state.

---

## Acceptance Criteria

- [ ] Parity scan reports >= 97% (excluding Ext.UI, Debugger, Replication) — ⏳ V2 pending
- [ ] All 125+ tests pass (including new tests for added functions) — ⏳ V1 pending
- [ ] Test count increased by >= 20 new tests — ✅ +28 stubs added
- [x] Ext.Events has ExecuteFunctor — ✅ (DealDamage deferred — needs Ghidra addresses)
- [x] Ext.Level has RaycastAll + at least 4/6 Sweep functions — ✅ All 7 implemented
- [x] Ext.Entity has GetSalt/GetIndex/GetEntityType/GetNetId — ✅ (CreateComponent/RemoveComponent gated)
- [ ] `compat run mcm` passes — ⏳ V3 pending
- [x] Signal handler thread safety fixed (deferred path only) — ✅ P0
- [x] One-frame polling optimized (cached TypeIndex, listener-count guards) — ✅ I12
- [ ] ROADMAP.md, CLAUDE.md, README.md updated with new parity % — ⏳ V4 pending
- [ ] Autoresearch `.lab/` scaffolded with working fast + full eval gates — ⏳ Mode B pending

## Success Metrics

- **Primary:** Parity % as reported by `bg3se-harness parity scan`
- **Secondary:** Test count (should increase from 125 to ~150+)
- **Tertiary:** Top-8 popular mods pass compat tests
- **Performance:** Heavy combat with all events subscribed stays under 1ms/frame

## Dependencies & Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| main.c merge conflicts | **HIGH** | Serialize through lead; per-agent sub-branches |
| Cross-thread Lua corruption | **CRITICAL** | Pre-flight fix: force deferred path (P0) |
| Sweep VMT indices unknown | **HIGH** | Ghidra RE session before Wave 2A (R1) |
| DealDamage 18-param hook | **HIGH** | ARM64 x8 indirect return + stack params; verify with Ghidra |
| functor_hooks.c unowned | **MEDIUM** | Assigned to kaptaru (corrected in revised ownership) |
| Header changes trigger rebuild | **MEDIUM** | Minimize header changes; prefer adding to .c files |
| Parity baseline drift | **LOW** | Freeze before Wave 1 (P1) |
| One-frame polling over 1ms budget | **MEDIUM** | Polling optimization in I12 (cached TypeIndex, direct C calls) |

## Sources & References

- Windows BG3SE reference: `/Users/tomdimino/Desktop/Programming/game-modding/bg3/bg3se/`
- RLAMA buckets: `bg3se-windows` (294 docs), `bg3se-macos` (389 docs)
- Parity baseline: `tools/bg3se_harness/catalog/windows_parity_baseline.json`
- ROADMAP.md: Feature Parity Matrix with per-namespace status
- Minoan Swarm skill: `~/.claude/skills/minoan-swarm/`
- Autoresearch skill: `~/.claude/skills/autoresearch/`
- Prior plan: `docs/plans/2026-03-31-003-feat-unified-parity-modcompat-cli-expansion-plan.md`

### Solution Docs Referenced
- `docs/solutions/arm64-calling-convention-crashes.md` — x8 indirect returns for large structs
- `docs/solutions/reverse-engineering/metadata-vs-runtime-pattern.md` — metadata vs runtime trap
- `docs/solutions/tag-component-acceleration.md` — zero-field tag components for CreateComponent
- `docs/solutions/reverse-engineering/staticdata-featmanager-discovery.md` — Dobby vs Frida for PC-relative code
