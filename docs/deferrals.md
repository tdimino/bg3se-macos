# Deferral Registry

The canonical list of every Ext.* API that exists on macOS but intentionally
does not perform its Windows behavior. Every entry fails closed: it warns once
per process and returns `nil`/`false` without touching native code it cannot
defend. A deferral is never a silent stub — if an API is listed here, calling
it tells you so in the log.

**Doctrine:** a warn-once stub returning `nil`/`false` with a documented
rationale beats a guessed offset. Deferrals convert to implementations only
when instruction-level evidence (a `ghidra/offsets/` report) proves the
layout and ABI; they are never promoted by porting Windows constants.

Last audited: 2026-08-03 (Wave 7 A/B-series close-out, v0.43.0, game build 4.1.1.7209685).

## Ext.Level

| API | Returns | Why deferred | Evidence | Unlock path |
|---|---|---|---|---|
| `RaycastClosest` | `nil` | Engine signature ends in a **by-value** `ls::Function<bool(PhysicsShape const*)>`; its C representation, construction, destruction, and ownership are unverified. Quarantined — the previous "working" binding dispatched `RemovePhysicsShape` (wrong-by-1 VMT index). | `ghidra/offsets/PHYSICS_VMT_AUDIT.md` | Prove the `ls::Function` value layout + lifecycle, or find a callable overload without it |
| `RaycastAll` | `nil` | Trailing by-value `ls::Optional<PhysicsSceneScopedReadLock&>`; value ABI unverified. | same | same |
| `RaycastAny` | boolean (gated) | Wave 7 B4b: the zeroed by-value `ls::Optional<PhysicsSceneScopedReadLock&>` ABI is now **proven GO** (`RAYCAST_ABI_B4A.md`), and a real binding dispatches physics VMT slot 10, selecting the worker's internal `lockRead → raycast → unlockRead` path. It is arm64-only and fail-closed unless BOTH `version_detect_matches()` and the audited Mach-O UUID match. **Still a scored deferral**: earns no parity credit until the live stress ladder (no-hit / one / multiple / mask-exclusion / thousands-of-calls / level reload) passes. The UUID gate names 4.1.1.7398727; the no-hit and one-hit steps pass live (Tier 2 `Wave7.Level.RaycastAny`). | `ghidra/offsets/RAYCAST_ABI_B4A.md` | Run the live stress ladder; then credit and lift the deferral |
| `GetTileDebugInfo` | `nil` | `AiGridTile::MinHeight` (+0x0a) is now **CONFIRMED** (Wave 7 B3: two independent accessor sites with the shared `/50` scaling), but the public cloud-surface enum conversion and material/extra flag decoders remain PROVISIONAL. The raw fields ship as the differently-named `GetTileRawDebugInfo(x, z)` diagnostic (no parity credit). | `ghidra/offsets/AIGRID_PATHFINDING.md` (2026-08-03 MinHeight recon) | Build the public flag conversions so the Windows-shaped table can be returned honestly |
| `BeginPathfinding` | `nil` | `AiGrid::CreatePath` is callable, but character path creation populates many `AiPath` fields beyond source/target/bounds; calling only `CreatePath` would enqueue an incompletely configured request. | same | Map the full `CreatePathForCharacter` field population (client `0x102de439c` + server callers) or find a stable high-level entry point |

Implemented for contrast: `GetPathById`, `ReleasePath`,
`GetActivePathfindingRequests`, `FindPath`, `GetEntitiesOnTile` (Wave 3,
verified live), all sweeps including cylinders, `TestBox`, `TestSphere`,
singleton accessors, `GetHeightsAt` (Wave 7: the B3 truth pass exposed the
old binding as a stub; the real multi-subgrid walk landed the same day over
CONFIRMED subgrid world-bounds offsets), plus the `GetTileRawDebugInfo`
diagnostic surface.

## Ext.Entity / entity methods

| API | Returns | Why deferred | Evidence | Unlock path |
|---|---|---|---|---|
| `entity:RemoveComponent(name)` | `false` | macOS emits only 734 `ImmediateWorldCache::RemoveComponent<T>(EntityHandle)` template instantiations, each with a hard-coded `TypeId<T>`; there is no generic runtime-TypeId entry point. Calling a specialization for a different type would remove the wrong component. | `ghidra/offsets/COMPONENT_OPS_AND_PROTO_INIT.md` ("NOT GENERICALLY UNLOCKED") | Generate a per-build type-index→specialization dispatch table, or audit a generic reimplementation of the template body (pending-change handling + destroy callbacks) |
| `Ext.Entity.EnableTracing` / `DisableTracing` | warn + `nil` | No macOS tracing infrastructure recovered. Contract note: current Windows BG3SE exposes `EnableTracing(bool)` only — `DisableTracing` is a macOS compat wrapper outside the Windows surface. | `src/injector/main.c` | RE the server tracing bookkeeping |
| `entity:GetReplicationFlags(component[,qword])` | number (gated) | Wave 7 C step 2: now a real **read-only** proxy method on the entity proxy (matching the Windows placement, `LuaEntityProxy.inl:415`), traversing the CONFIRMED SyncBuffers → HashMap → DynamicBitSet chain with fully guarded reads. Resolves only the 9 confirmed replicated-type globals; version-gated and fail-closed. **Still a scored deferral**: no parity credit until the live-probe checklist validates the runtime int32 indices and pointer chain in-game (step 2 of the 9-step Phase C plan). | `ghidra/offsets/REPLICATION_SYNCBUFFERS.md`, `src/entity/replication_flags.c` | Run the live-probe checklist; then credit and lift the deferral |
| `entity:Replicate()` | no-op | Same replication gap. **Highest-demand deferral in the registry**: 5 of 11 vetted mods call it (Community Library, 5e Spells, Expansion, Combat Extender, Transmog Enhanced) — masked in single-player, unproven in multiplayer. Cannot be reclassified as a scope exclusion. | same | same |
| Component property writes (unknown-size layouts, unsupported field types) | `false` | Writing through an unverified size or field type risks corruption; INT32, UINT8, BOOL, FLOAT, and INT32_ARRAY are proven. Wave 7 A7 added a FLOAT_ARRAY writer with exact-length validation, NaN/Inf rejection, a staged buffer, and atomic commit, but it earns no parity credit yet: the only candidate, `ls::EffectComponent::OverrideFadeCapacity`, has unverified ARM64 offsets because the Ghidra bridge was down. | `src/entity/component_property.c` | Verify `OverrideFadeCapacity` offsets in Ghidra, then exercise the writer against the live component before crediting parity |
| `Ext.Entity.GetEntitiesAroundPosition` spatial-grid backend | behavioral results | **No contract deferral:** Wave 7 A1 meets the Windows 2D XZ-circle behavior, ignores Y, and defaults includeCharacters/includeItems to true. The backend walks `eoc::character::CharacterComponent` and the item marker component, then reads `ls::TransformComponent` positions. The native spatial-grid `GridStructure` ARM64 layout remains unrecovered. | `BG3Extender/Lua/Libs/Ai.inl:502-537`; `src/entity/entity_system.c` | Recover `GridStructure` only if profiling shows the archetype fallback needs replacement |
| `Ext.Entity.Create` / `Destroy` | absent | Engine entity lifecycle (allocator + handle mint) not recovered on macOS. | `Entity.inl:305-306` | Wave 7 Phase D4 (recon first, go/no-go on allocator evidence) |
| `OnSystemUpdate` / `OnSystemPostUpdate` | absent | **Implementation-ready, but not implemented yet.** B6 proved `SystemTypeEntry::UpdateProc` is swappable at `+0x18`; entries have stride `0xf8`; the `EntityWorld` array/buffer are at `+0x28`/`+0x30`. The wrapper must safely pin the correct Lua VM on worker threads and preserve synchronous pre/original/post ordering. | [ECS_SYSTEM_UPDATE_RECON.md](../ghidra/offsets/ECS_SYSTEM_UPDATE_RECON.md) | Implement per-entry wrappers; use `ExecuteWTKernel` at `0x1063788cc` only as a diagnostic fallback |
| `GetTrace` / `ClearTrace` | absent | Tracing infrastructure not built; faithful Windows tracing scans command-buffer changes and replication dirties, so full credit is gated on the replication foundation. | `Entity.inl:322-323` | Wave 7 Phase A8 prototype → C-gated closure |

Implemented for contrast: `entity:CreateComponent` (verified ComponentOps
registry at `EntityWorld+0x390`, vptr slot 5), `GetAllEntities`,
`GetAllEntitiesWithComponent`, `GetAllComponents` (server-world archetype
walks). Note: client-world components (`ecl::*`) are not enumerated by the
walk; `esv::Character` is not a registered TypeId — use
`eoc::character::CharacterComponent` for character queries.

## Ext.Stats

| API | Returns | Why deferred | Evidence | Unlock path |
|---|---|---|---|---|
| Passive prototype sync | `false` | **PARTIAL-GO; sync stays false.** `Passives::Parse` needs no loader-private state, but only resolves names to existing prototypes. Existing-entry scalar/description refresh and all three functor-list refreshes are statically safe. `Boosts` remains blocked on an LTO-specialized closure ABI. The map uses `0x220` nodes with an inline `0x210` prototype. | [PASSIVES_PARSE_RECON.md](../ghidra/offsets/PASSIVES_PARSE_RECON.md) | Complete the five-step milestone below before returning success |
| Interrupt prototype sync | `false` | `eoc::InterruptPrototype` (0x1f0 bytes) has a `FixedString` at offset 0, not a vptr; the manager uses a hash table + contiguous 0x1f0-stride array, structurally incompatible with the generic RefMap insert helper. | `ghidra/offsets/COMPONENT_OPS_AND_PROTO_INIT.md` | Map the inlined object move/build path at `0x103063f94` onward |
| `AddAttribute` | `false` | Runtime modifier-list allocation and construction remain unverified. | `src/stats/stats_manager.c` | Recover the pre-load modifier allocation path |
| `ExecuteFunctors` | partial | Full param-block construction unverified for all functor types. | `src/stats/functor_hooks.c` | Extend per-functor param evidence |

Passive sync future milestone:

1. Keep `sync_passive_prototype()` false.
2. Prove the `ParseStaticBoosts` closure ABI or find a safe wrapper.
3. Build an exact-version-gated existing-entry refresher.
4. Live-validate scalar, `Boosts`, and three functor-list updates.
5. Attempt new insertion only with validation and rollback.

Implemented for contrast: `AddEnumerationValue` (Wave 7 B1) calls engine
`ValueList::Insert` at `0x101c44920`. It uses the existing engine-backed
FixedString intern path and verifies both lookup directions plus count growth.

## Ext.Types

| API | Returns | Why deferred | Evidence | Unlock path |
|---|---|---|---|---|
| `Construct(typeName)` | errors or 0 values | **Matched contract, not a gap**: Wave 7 A3 now matches Windows Types.inl:286-302 exactly. It raises `Unknown type name '%s'`, `Unable to construct non-object type '%s'`, or `Type '%s' is not constructible`; valid object types pass all checks and reach the shared upstream `// TODO`, returning 0 values. Removed from the parity denominator. | `src/lua/lua_ext.c`; `bg3se/BG3Extender/Lua/Libs/Types.inl:286-302` | Track upstream; per-type constructor recovery if Windows implements the TODO |
| `GetHashSetValueAt` | warn + `nil` | No hash-set proxy exists on macOS. Contract note: the Windows index is **1-based** (Lua convention); any implementation must preserve that. | same | Implement an ls::HashSet layout proxy |
| `AddCustomFunction` | warn + `false` | **Scored gap** (Wave 7 Phase 0 correction — a prior entry wrongly claimed this sits "outside the 15-function Windows baseline"; the 15 was manufactured). Windows registers it inside its 14-function Types block and implements it *functionally* as Lua-side custom-property registration (`GetCustomProperties().RegisterProperty`, `Types.inl:328`) — no engine call involved. macOS lacks the property-map layer the proxies would consult. | `bg3se/BG3Extender/Lua/Libs/Types.inl:328` | Wave 7 Phase A2: per-state custom-property registry consulted by proxy `__index`/`__newindex` |
| `AddCustomProperty` | warn + `false` | Same correction as AddCustomFunction — functional on Windows (`Types.inl:347`), scored gap here. | `bg3se/BG3Extender/Lua/Libs/Types.inl:347` | Same (Wave 7 Phase A2) |

## Excluded by scope decision (not deferrals)

These four surfaces sit outside the parity denominator. This list is now the
single authority — ROADMAP.md defers to it (Wave 6 reconciled a silent
disagreement where ROADMAP assumed exclusions this registry never named).

- **Ext.UI** — Windows NsGui/Noesis surface; compatibility stub layer only.
- **Lua Debugger / DAP** — deferred to Phase 11.
- **Virtual Textures** — no macOS GTS/GTP pipeline; no vetted-corpus caller.
  Explicit exclusion as of Wave 6 (previously assumed silently).
- **Input injection** (`Ext.Input` synthetic event injection à la Windows) —
  the macOS surface is CGEventTap capture + hotkeys; injection is excluded.
  Explicit exclusion as of Wave 6 (previously assumed silently).

**Deliberately NOT excludable: entity replication.** `entity:Replicate()` has
proven mod demand (5 of 11 vetted mods) and therefore stays a scored deferral
inside the `Ext.Entity` row, not a scope exclusion.

## History

- 2026-08-03 (v0.43.0, Wave 7 B-series): AddEnumerationValue left the
  registry after the engine insertion/growth path and readback checks were
  proved. Passive sync became PARTIAL-GO for a future implementation, but
  remains false pending the `Boosts` closure ABI and live validation. ECS
  system-update callbacks became implementation-ready; both APIs remain gaps
  until their per-entry wrappers land.
- 2026-08-02 (v0.43.0, Wave 7 A-series): the five A1 Entity registrations
  and A6 PlayerHasExtender GUID behavior left the registry. A7 FLOAT_ARRAY
  support remains verification-gated. GetEntitiesAroundPosition meets the
  public contract through an archetype-walk fallback while GridStructure RE
  remains deferred. Construct's exact Windows error surface is documented.
- 2026-08-01 (Wave 6): scope-exclusion list reconciled with ROADMAP (Virtual
  Textures + input injection made explicit; replication ruled non-excludable).
  Construct reclassified as a matched Windows contract (upstream `// TODO`)
  and removed from the parity denominator. Contract notes added for
  GetHashSetValueAt (1-based), GetReplicationFlags (entity-proxy placement),
  and DisableTracing (macOS compat wrapper). GetCachedPassive/GetCachedInterrupt
  rebound from the layout-wrong generic refmap walk to the native getters
  (`eoc::Passives::Get` 0x101c0f27c — LTO arg-promoted, index by value;
  `InterruptPrototypeManager::GetPrototype` 0x101b7adcc), live-verified.
- 2026-07-30 (v0.41.0): registry created (Wave 3 Goal 3.3). Five AiGrid APIs,
  cylinder sweeps, CreateComponent, Math ×2, Audio banks ×4, Types
  Serialize/Unserialize, and Loca update left the list; the three raycasts
  entered it (previously miscounted as implemented while dispatching the
  wrong VMT slots).
