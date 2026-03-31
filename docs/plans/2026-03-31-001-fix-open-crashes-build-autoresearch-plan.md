---
title: "fix: Resolve open crashes (#78, #73), build error (#77), and add autoresearch eval gates"
type: fix
status: completed
date: 2026-03-31
issues: [78, 77, 73]
---

# fix: Resolve open crashes, build error, and add autoresearch eval gates

## Overview

Three open bugs block v0.37.x stability: a hotbar crash on new game start (#78), a build error on CommandLineTools-only systems (#77), and a SIGSEGV after game hotfixes (#73). All three share a common theme — insufficient safety margins in the entity/component subsystem and build system. This plan fixes all three, adds Python 3.9 compatibility, improves code signing robustness, and scaffolds an autoresearch `.lab/` with eval gates to continuously verify the CLI and prevent regressions.

## Problem Statement

### #78: Hotbar crash on new game start (EXC_BAD_ACCESS / SIGBUS)

**Crash**: `AddToBar(eoc::hotbar::BarContainer&, ...)` follows a corrupted function pointer (`BR x17` to heap address `0xa1c670664`). All frames are vanilla BG3 — no bg3se frames in the crash stack. Occurs ~90s after launch on ServerWorker thread during `esv::hotbar::System::Update`.

**Root cause**: Thread-unsafe entity event signal handlers in `entity_events.c`:
1. `g_lua_state` is a bare static pointer read from signal handlers on the ServerWorker thread without synchronization — if Lua state is torn down during new game transition, handler calls into dead memory
2. `inject_connection()` frees the old connection buffer (`free(conn_buf)` at line 459) while the game's `Signal::Invoke` on ServerWorker may be iterating it — the game follows a dangling pointer
3. Component registry arrays (`g_Components[]`, `g_IndexLookup[]`) are modified during TypeId re-discovery with no coordination with worker threads

**Evidence**: Crash report shows `x8 = 0xFFFFFFFF` and `x22 = x26 = 0xFFFFFFFF` (uninitialized sentinel values), consistent with reading from a freed/reallocated buffer.

### #77: Build error (`'tuple' file not found`)

**Error**: `fatal error: 'tuple' file not found` at `vector_make.h:5922` when compiling `imgui_metal_backend.mm`.

**Root cause**: CMakeLists.txt does not set `CMAKE_OSX_SYSROOT` or detect CommandLineTools-only environments. The MetalKit framework header chain includes ModelIO which includes `<tuple>` (C++ stdlib). On systems with only CommandLineTools SDK (no full Xcode), CMake may not find the C++ stdlib headers.

### #73: SIGSEGV on game load after BG3 Hotfix 1.800.700

**Crash**: `KERN_INVALID_ADDRESS at 0x381c` (null + struct offset). Crash stack: `ls::gst::Map::Release → DynamicArray<BoostDescription>::Reallocate → BoostPrototype::~BoostPrototype → ModuleUnloadSystem → EntityWorld::Update`.

**Root cause**: 2,000+ hardcoded addresses (TypeIds, singletons, function pointers) were extracted for game version `4.1.1.6995620`. When Hotfix 1.800.700 shipped, addresses shifted. There is zero version detection — singleton pointers like `BoostPrototypeManager` at `0x108991528` now point to wrong data, and dereferencing during `ModuleUnloadSystem` crashes.

### Bonus issues (from #78 crash report)

- **Python 3.9 compat**: `flags.py` uses `str | bool` union syntax (Python 3.10+) — breaks on macOS system Python 3.9.6
- **Code signing**: `_sign_binary()` in `patch.py` may fail when non-Mach-O files (.log, .bg3se-patch-hash) exist in `Contents/MacOS/`

## Proposed Solution

### Phase 1: Build System Fix (#77)

Add CMake sysroot detection that handles both full Xcode and CommandLineTools-only environments.

**Files to modify:**
- `CMakeLists.txt` — Add sysroot detection block after project() declaration

**Approach:**
```cmake
# Detect SDK: prefer Xcode, fall back to CommandLineTools
if(NOT CMAKE_OSX_SYSROOT)
    execute_process(
        COMMAND xcrun --show-sdk-path
        OUTPUT_VARIABLE _sdk_path
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(_sdk_path)
        set(CMAKE_OSX_SYSROOT "${_sdk_path}" CACHE PATH "macOS SDK path")
        message(STATUS "Auto-detected SDK: ${_sdk_path}")
    endif()
endif()
```

This uses `xcrun --show-sdk-path` which works on both Xcode and CommandLineTools systems and resolves the correct SDK path for the active developer tools.

### Phase 2: Thread Safety for Entity Events (#78)

Fix the three race conditions in `entity_events.c`:

**Files to modify:**
- `src/entity/entity_events.c` — Thread-safe signal handler access
- `src/entity/entity_events.h` — Add atomic declarations

**Approach:**

1. **Atomic `g_lua_state`**: Replace bare pointer with `_Atomic(lua_State*)`. Signal handlers load atomically; main thread stores atomically. Null-check at handler entry gates all Lua calls.

2. **Deferred connection buffer free**: Instead of `free(conn_buf)` immediately in `inject_connection()`, push old buffers to a free-list and release them on the next main-thread tick (when no worker threads can be iterating). Pattern: "epoch-based reclamation lite."

3. **Transition guard**: Add a `_Atomic(bool) g_in_transition` flag. Set it before game state transitions (new game, load save). Signal handlers check it and return immediately without touching Lua or entity data.

**Verification**: The existing `entity_on_session_loaded()` hook provides the "transition complete" signal — clear `g_in_transition` there.

### Phase 3: Game Version Detection & Address Validation (#73)

Add version detection and singleton validation to prevent crashes from shifted addresses.

**Files to modify:**
- `src/core/version_detect.c` (NEW) — Game binary version detection
- `src/core/version_detect.h` (NEW) — Public API
- `src/entity/entity_system.c` — Validate before using singletons
- `src/stats/prototype_managers.c` — Validate before dereferencing singleton pointers
- `src/injector/main.c` — Call version detection at init, log warnings

**Approach:**

1. **Version detection**: Scan the BG3 binary's `__DATA,__const` or use `strings` at runtime to find the version string (pattern: `4.1.1.\d+`). Compare against the known-good version (`4.1.1.6995620`). If mismatch, log a prominent warning but don't abort — many features still work.

2. **Singleton validation**: Before dereferencing any singleton pointer, read the pointer value and validate it points to a plausible address range (within the binary's mapped segments). If invalid, set to NULL and log rather than crash.

3. **Graceful degradation**: When version mismatch detected, disable address-dependent features (entity component access via TypeId, prototype manager access) but keep working features alive (Lua API, Osiris hooks, console, mod loading).

### Phase 4: Python Harness Fixes (bonus)

**Files to modify:**
- `tools/bg3se_harness/flags.py` — Add `from __future__ import annotations` at line 1
- `tools/bg3se_harness/patch.py` — Clean non-Mach-O files before codesign

### Phase 5: Autoresearch Eval Gates

Scaffold `.lab/` with eval gates targeting all fixes:

**Eval gate architecture:**

| Tier | Gate | What it checks | Weight |
|------|------|----------------|--------|
| T1 | Build | `cmake --build .` succeeds (universal binary) | 0.15 |
| T1 | CLI Tests | All 67+ offline harness tests pass | 0.15 |
| T2 | Thread Safety | Static analysis: no bare `g_lua_state` reads in signal handlers | 0.15 |
| T2 | Version Guard | `version_detect.c` exists and is called from `main.c` init | 0.10 |
| T2 | Python Compat | `python3.9 -c "import bg3se_harness.flags"` succeeds | 0.10 |
| T2 | Signing | `_sign_binary()` handles non-Mach-O files | 0.10 |
| T3 | Singleton Safety | All singleton dereferences guarded by null-check + validation | 0.15 |
| T4 | Docs | CHANGELOG updated, version bumped | 0.10 |

**program.md priorities:**
1. Thread safety in entity_events.c (highest crash impact)
2. Version detection (prevents entire class of update-related crashes)
3. Build system fix (unblocks new contributors)
4. Python compat + signing (small fixes, high user impact)

## System-Wide Impact

### Interaction Graph

- **Phase 2 changes** (entity_events.c) affect: `entity_events_subscribe()`, `entity_events_unsubscribe()`, `entity_events_bind()`, `inject_connection()`, `signal_construct_handler()`, `signal_destroy_handler()`. All Lua mods using `Ext.Entity.Subscribe()` / `Ext.Entity.OnCreate()` / `Ext.Entity.OnDestroy()` flow through these paths.
- **Phase 3 changes** (version_detect) affect: `entity_system_init()`, `prototype_managers_init()`. Downstream: all `Ext.Stats.*`, `Ext.Entity.*` component access, `Ext.StaticData.*`.
- **Phase 1 changes** (CMakeLists.txt) affect build only — no runtime behavior change.

### Error Propagation

- Version mismatch: detected at init → logged as WARNING → address-dependent features disabled → graceful nil returns from Lua APIs → mods see nil instead of crash
- Signal handler race: caught by atomic null-check → handler returns early → no Lua call → no crash, but event is silently dropped (acceptable during transition)

### State Lifecycle Risks

- **Deferred free-list**: Old connection buffers accumulate until main-thread tick. Risk: memory leak if main thread stalls. Mitigation: cap free-list at 64 entries, force-free oldest if exceeded.
- **Version detection at init**: Adds ~5ms to startup (one string scan). No persistent state.

### API Surface Parity

- No API changes. All fixes are internal safety improvements.
- Mods calling `Ext.Entity.Subscribe()` will see identical behavior except: events during game state transitions may be silently dropped (instead of crashing).

### Integration Test Scenarios

1. **New game start with SE loaded**: Launch → main menu → new game → verify no crash during hotbar init (addresses #78)
2. **Game version mismatch**: Patch binary, update game via Steam, launch → verify warning logged, no crash, graceful degradation (addresses #73)
3. **Build on CommandLineTools-only Mac**: Fresh clone → cmake → build → verify imgui_metal_backend.mm compiles (addresses #77)
4. **Entity event subscribe during transition**: Subscribe to component event → start new game → verify no crash (handler returns early)
5. **Python 3.9 harness**: Run `python3.9 -m bg3se_harness flags` → verify no import error

## Acceptance Criteria

### Functional Requirements

- [ ] `cmake --build .` succeeds on CommandLineTools-only macOS (no Xcode.app)
- [ ] All 67 offline harness tests pass (`PYTHONPATH=tools python3 -m bg3se_harness.tests`)
- [ ] Game launches and reaches main menu with SE loaded (no crash)
- [ ] New game start with SE loaded does not crash during hotbar init
- [ ] Game version mismatch produces a clear log warning (not a crash)
- [ ] `python3.9 -c "from bg3se_harness import flags"` succeeds
- [ ] `_sign_binary()` succeeds even with .log files in Contents/MacOS/

### Quality Gates

- [ ] No new compiler warnings from modified files
- [ ] All `_Atomic` accesses use appropriate memory ordering (relaxed for flags, acquire/release for pointers)
- [ ] CHANGELOG.md updated with v0.37.1 entry
- [ ] Autoresearch `.lab/` scaffolded with passing baseline eval

## Dependencies & Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Atomic operations not available on older compilers | Low | High | C11 `_Atomic` is supported by all Apple Clang since macOS 10.12 |
| Version string format changes in future BG3 updates | Medium | Medium | Use regex pattern match, not exact string comparison |
| Deferred free-list causes memory pressure | Low | Low | Cap at 64 entries, force-free oldest |
| CMake sysroot detection breaks on edge-case SDK installs | Low | Medium | Fallback: user can set CMAKE_OSX_SYSROOT manually |
| Pattern scanning for critical addresses is slow | Medium | Low | Only scan for 5-10 critical singletons, cache results |

## Implementation Units

### Unit 1: CMake sysroot detection (Phase 1)
- **Goal**: Fix #77 build error
- **Files**: `CMakeLists.txt`
- **Execution note**: Test-first — verify the fix with a CommandLineTools-only build check
- **Verification**: `cmake .. && cmake --build .` succeeds; `otool -L lib/libbg3se.dylib` shows universal binary
- **Patterns to follow**: Existing CMakeLists.txt structure

### Unit 2: Python 3.9 compatibility (Phase 4)
- **Goal**: Fix import errors on system Python
- **Files**: `tools/bg3se_harness/flags.py`
- **Verification**: `python3 -c "from bg3se_harness import flags"` succeeds; all 67 offline tests pass
- **Patterns to follow**: Other harness modules (none use 3.10+ syntax)

### Unit 3: Code signing robustness (Phase 4)
- **Goal**: `_sign_binary()` handles non-Mach-O files
- **Files**: `tools/bg3se_harness/patch.py`
- **Verification**: Patch command succeeds on a BG3 install with .log files in MacOS/
- **Patterns to follow**: Existing `_sign_binary()` verification pattern

### Unit 4: Thread-safe entity events (Phase 2)
- **Goal**: Fix #78 hotbar crash
- **Files**: `src/entity/entity_events.c`, `src/entity/entity_events.h`
- **Execution note**: Characterization-first — read existing signal handler flow before modifying
- **Verification**: Game launches, new game start does not crash; entity event tests still pass (`!test Entity`)
- **Patterns to follow**: Existing `g_lua_state` nulling pattern from v0.36.47 (CHANGELOG)

### Unit 5: Game version detection (Phase 3)
- **Goal**: Fix #73 and prevent future hotfix crashes
- **Files**: `src/core/version_detect.c` (NEW), `src/core/version_detect.h` (NEW), `src/injector/main.c`, `src/entity/entity_system.c`, `src/stats/prototype_managers.c`, `CMakeLists.txt`
- **Execution note**: Test-first — write a test that detects version from current binary before implementing guards
- **Verification**: Build succeeds; version detected and logged at init; singleton access guarded; mismatched version disables dangerous features
- **Patterns to follow**: `safe_memory_check_address()` validation pattern, `component_typeid_read()` guard pattern

### Unit 6: Autoresearch scaffolding (Phase 5)
- **Goal**: `.lab/` with eval gates for continuous verification
- **Files**: `.lab/config.json`, `.lab/eval.py`, `.lab/program.md`, `.lab/runner.py`
- **Verification**: `python3 .lab/eval.py` runs and produces a valid composite score
- **Patterns to follow**: Autoresearch skill scaffold output

### Unit 7: Documentation & release
- **Goal**: Version bump, changelog, close issues
- **Files**: `docs/CHANGELOG.md`, `src/core/version.h`, `CLAUDE.md`, `README.md`
- **Verification**: All docs updated, issues commented with fix commit

## Scope Boundaries

**In scope:**
- Thread safety for entity event signal handlers
- CMake sysroot detection for CommandLineTools
- Game version detection and singleton validation
- Python 3.9 compat in harness
- Code signing robustness
- Autoresearch eval gate scaffolding

**Out of scope:**
- Pattern scanning for ALL 2,000 addresses (only critical singletons)
- Full thread safety audit of entire codebase (only entity_events.c)
- Fixing the Steam-launch + patched-binary crash (separate blocker, different root cause)
- Adding new game features or APIs
- Windows parity work

## Sources & References

### Internal References
- Crash report: `/tmp/crash_report_78.md` — Full thread stacks, register state
- Entity events: `src/entity/entity_events.c` — Signal handlers, inject_connection
- Component TypeId: `src/entity/component_typeid.c:282-348` — TypeId reading with guards
- Prototype managers: `src/stats/prototype_managers.c:159-202` — Singleton addresses
- Prior crash fix: CHANGELOG v0.36.47 — Race safety during teardown (null g_lua_state before removal)
- ARM64 hooking prevention: `docs/arm64/arm64-hooking-prevention.md`
- Crash analysis: `docs/archive/CRASH_ANALYSIS.md`

### Related Issues
- #78: Hotbar crash on new game start
- #77: `'tuple' file not found` build error
- #73: SIGSEGV on game load after hotfix
- #76: DYLD injection fails (CLOSED — fixed by insert_dylib in v0.37.0)
- #75: NativeMods question (CLOSED — Windows-only .dll mechanism)
