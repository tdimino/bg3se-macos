# Changelog

All notable changes to BG3SE-macOS are documented here.

## Format

Each entry includes:
- **Version** - Semantic version (MAJOR.MINOR.PATCH)
- **Date** - Release date
- **Parity** - Feature parity % with Windows BG3SE
- **Category** - Primary area of change
- **Issues** - Related GitHub issues

---

## [v0.36.40] - 2026-02-07

**Parity:** ~92% | **Category:** Mach Exception Handler | **Issues:** #66

### Added
- **Mach exception handler** (`src/core/mach_exception.c`): Catches `EXC_BAD_ACCESS` (PAC failures, SIGSEGV) and `EXC_BAD_INSTRUCTION` (SIGILL) via Mach exception ports **before** CrashReporter or POSIX signal handlers fire. Writes exception type, fault address, ARM64 register state (PC, LR, SP, FP, X0-X3, X8, X16-X17), and breadcrumb trail to `crash.log`. Returns `KERN_FAILURE` so CrashReporter still generates `.ips` files.
- **MIG-generated stubs** (`src/core/mach_exc_stubs/`): Pre-generated from `mach_exc.defs` via Apple's `mig` tool — no build-time dependency on MIG.

### Fixed
- **Issue #66: `!probe_osidef` crash (SIGSEGV).** `osi_func_probe_layout()` used `safe_memory_read()` instead of `safe_memory_read_pointer()` when reading through `void **ppOsiFunctionMan`, passing the VMT pointer as `this` and causing a PAC failure. Fixed to use the correct pointer indirection pattern.

### Technical
- Listener thread (`BG3SE-ExcHandler`) runs `mach_msg()` loop with MIG-generated `mach_exc_server()` dispatch
- `task_swap_exception_ports()` atomically saves old ports (CrashReporter) for forwarding
- Three-tier crash diagnostics: Mach handler (first) → POSIX signal handler (second) → CrashReporter `.ips` (third)
- `crashlog_get_crash_fd()` accessor exposes pre-opened crash file to exception handler
- Clean shutdown via `mach_port_destruct()` + `pthread_join` + old port restoration

---

## [v0.36.39] - 2026-02-07

**Parity:** ~92% | **Category:** Osiris Handle Encoding + Crash Diagnostics | **Issues:** #66

### Fixed
- **Issue #66: funcType=0 caused dangerous query-first fallback.** All dynamically discovered Osiris functions had type hardcoded to 0 (UNKNOWN), causing the dispatcher to try Query first then Call. For Call-type functions like `AddGold`, this could corrupt arguments or SIGSEGV. Fix: read `FunctionType` directly from the game's `OsiFunctionDef` struct at offset +0x28 via safe memory APIs.
- **Issue #66: Raw funcId passed instead of encoded OsirisFunctionHandle.** Windows BG3SE packs type + funcId + Key parts into a 32-bit handle for `DivFunctions::Call/Query`. Our code was passing the raw enumeration index. Fix: read `Key[0..3]` from funcDef +0x2C, encode handle via `osi_encode_handle()`, and pass to all dispatch paths.

### Added
- **Crash-resilient logging module** (`src/core/crashlog.c`): mmap'd 16KB ring buffer (MAP_SHARED, survives SIGSEGV), SIGSEGV/SIGBUS/SIGABRT signal handler with SA_ONSTACK + sigaltstack, breadcrumb trail (32-entry lock-free ring tracking dispatch path). All signal handler code is async-signal-safe.
- **OsirisFunctionHandle encoding** (`osiris_types.h`): `osi_encode_handle()`, `osi_decode_func_id()`, `osi_decode_func_type()` inline functions matching Windows BG3SE handle layout.
- **`!probe_osidef [N]` console command:** On-demand hex dump of OsiFunctionDef structs for ARM64 offset discovery and validation.
- **Breadcrumb macros** (`BREADCRUMB()`, `BREADCRUMB_ID()`): Placed at `osi_dynamic_call`, `osiris_query_by_id`, `osiris_call_by_id` for crash forensics.

### Technical
- `CachedFunction` extended with `handle` field for pre-computed dispatch handles
- `osi_func_get_handle()` / `osi_func_cache_set_handle()` for handle lookup and storage
- Ring buffer file: `~/Library/Application Support/BG3SE/crash_ring_<pid>.bin`
- Crash report file: `~/Library/Application Support/BG3SE/crash.log`
- Crashlog registered as log callback for WARN+ on Osiris/Hooks/Core modules
- Pre-load `backtrace()` at init to avoid dyld_stub_binder deadlock in signal handler

---

## [v0.36.38] - 2026-02-06

**Parity:** ~92% | **Category:** Critical Osiris Crash Fix | **Issues:** #66

### Fixed
- **Issue #66: Osiris function calls crash with SIGSEGV on ARM64.** `AddGold()`, `TemplateAddTo()`, and all Osi.* calls caused hard crashes. Root cause: `InternalCall` expects `COsipParameterList*` but we were passing `OsiArgumentDesc*` (wrong struct type). Fix: hook `COsiris::RegisterDIVFunctions` to capture `DivFunctions::Call` and `DivFunctions::Query` pointers, which correctly accept `OsiArgumentDesc*`. This matches Windows BG3SE's dispatch strategy (OsirisWrappers.cpp:38).

### Technical
- Added `DivFunctions` struct, `DivCallProc` typedef to `osiris_types.h`
- New Dobby hook on `COsiris::RegisterDIVFunctions` (exported symbol at offset 0x46348 in libOsiris.dylib)
- All Osi.* dispatch paths (Query, Call, SysCall, Event, Proc, Database) now route through `g_divQuery`/`g_divCall` with `pfn_InternalQuery`/`pfn_InternalCall` as fallback
- Hook count increased from 3 to 4 (InitGame, Load, Event, RegisterDIVFunctions)

---

## [v0.36.37] - 2026-02-06

**Parity:** ~92% | **Category:** Issue #65 Diagnostics + Net Parity | **Issues:** #65, #6

### Fixed
- **Issue #65 fallback init:** Added `deferred_session_init_tick()` fallback at end of `fake_InitGame` for machines where `fake_Event` (tick loop) never fires. On affected hardware (M4 / macOS Tahoe 26.2), the game tears down the session before Osiris events flow, so tick-based deferred init never runs.

### Added
- **`BG3SE_NO_HOOKS` diagnostic env var (Issue #65):** Set `BG3SE_NO_HOOKS=1` to skip ALL Dobby hook installation. Lua runtime remains active but Osiris/Event interception is disabled. Isolates whether inline code patching itself causes the game crash vs. other factors.
- **`bg3w.sh` env var passthrough:** Steam launch script now forwards `BG3SE_NO_HOOKS`, `BG3SE_NO_NET`, and `BG3SE_MINIMAL` environment variables to the game process.
- **Legacy `Ext.Events.NetMessage` (Issue #6):** Messages sent without a module UUID now auto-fire the legacy `NetMessage` event (Channel, Payload, UserID) in addition to `NetModMessage`. Most existing BG3SE mods use this legacy event.
- **`Ext.Net.PlayerHasExtender(userId)` (Issue #6):** Server-only function to check if a player's client has the script extender installed. Accepts userId (integer) for immediate lookup; GUID (string) returns nil pending entity component wiring.

### Technical
- `EVENT_NET_MESSAGE` added to event enum (33 → 34 events total)
- `lua_net_player_has_extender()` registered in server context only (9 functions vs 8 for client)
- Version bumped to v0.36.37

---

## [v0.36.36] - 2026-02-06

**Parity:** ~92% | **Category:** Build System | **Issues:** N/A

### Fixed
- **Build system now auto-builds all dependencies from source.** Previously, CMake linked against pre-built `.a` files (`libdobby-universal.a`, `liblua-universal.a`) that were gitignored and had no build instructions. Users who cloned the repo had no way to produce these files.

### Changed
- **Dobby** now built via `add_subdirectory(lib/Dobby)` — CMake compiles it as `dobby_static` target
- **Lua 5.4** now built as `lua_static` CMake target from source files in `lib/lua/src/`
- Removed `libdobby-universal.a` specific gitignore entry (global `*.a` pattern still covers build artifacts)
- Fresh `git clone --recursive` + `cmake .. && cmake --build .` now works with zero manual steps

---

## [v0.36.35] - 2026-02-06

**Parity:** ~92% | **Category:** Critical Bug Fix | **Issues:** #65

### Fixed
- **Game won't start with BG3SE injected (Issue #65)**
  - **Root cause 1:** Spurious `game_state_on_session_loading()` call in `fake_InitGame` (line 1876) corrupted internal state from Running→LoadSession after session was already loaded. This permanently broke deferred net init and produced misleading "bounce" in logs.
  - **Root cause 2:** ~2,800 `mach_vm_read_overwrite` kernel calls during `fake_Load` extended the timing-sensitive window after `COsiris::Load` returns, potentially triggering a game-side watchdog on some machines (especially macOS Tahoe 26.2 / M4).

### Changed
- **Deferred session init:** All heavy initialization (entity TypeId discovery ~2,200 calls, stats validation ~68 calls, static data capture ~400-600 calls) moved from `fake_Load` to tick loop (`fake_Event`). `fake_Load` now returns immediately after calling the original function + loading mod scripts.
- **State machine correctness:** `LoadSession → Running` transition now fires from tick loop after all subsystems are ready, not from `fake_Load` during the critical Load window.
- **Net hooks ordering:** Deferred net init now depends on deferred session init (Running state set correctly first).

### Added
- **Diagnostic timing:** Each deferred init step logs elapsed milliseconds (entity, stats, staticdata).
- **`BG3SE_MINIMAL` env var:** Set `BG3SE_MINIMAL=1` to skip all subsystem init (entity/stats/staticdata/net). Only Osiris hooks + basic Lua API remain active. Useful for isolating whether game failure is from init work or hooks themselves.

### Technical
- New `SessionInitState` state machine in `main.c` (IDLE → PENDING → COMPLETE)
- `request_deferred_session_init()` sets flag only (zero kernel calls in fake_Load)
- `deferred_session_init_tick()` runs in tick loop with per-step timing

---

## [v0.36.34] - 2026-02-06

**Parity:** ~92% | **Category:** Stats 100% Parity | **Issues:** Parity Push

### Added
- **Ext.Stats 100% Windows API Parity (22 new items)**
  - StatsObject `:Sync(persist?)` method — sync stat changes to game engine
  - StatsObject `:SetPersistence(persist)` method — deprecated stub with warning
  - StatsObject `:CopyFrom(parent)` method — copy IndexedProperties from another stat
  - StatsObject `:SetRawAttribute(key, value)` method — set property from raw string
  - StatsObject `ModId` property (read-only) — returns mod UUID (empty for now)
  - StatsObject `OriginalModId` property (read-only) — returns original mod UUID
  - StatsObject `ModifierList` property (read-only) — returns stat type name
  - Enhanced `Get(name, level?, warnOnError?, byRef?)` — all optional parameters
  - `GetStatsLoadedBefore(modUuid, type?)` — stub with one-time warning
  - `ExecuteFunctors(context)` — calls original game functor execution
  - `ExecuteFunctor(context)` — single functor wrapper
  - `PrepareFunctorParams(type)` — creates default functor context by type
  - `Ext.Stats.TreasureTable.Get(name)` — stub pending RE
  - `Ext.Stats.TreasureTable.GetLegacy(name)` — stub pending RE
  - `Ext.Stats.TreasureTable.Update(table)` — stub pending RE
  - `Ext.Stats.TreasureCategory.GetLegacy(name)` — stub pending RE
  - `Ext.Stats.TreasureCategory.Update(name, cat)` — stub pending RE
  - Improved `AddAttribute` / `AddEnumerationValue` stubs with parameter validation

### Technical
- New `stats_copy_from()` and `stats_set_raw_attribute()` in stats_manager
- `functor_hooks_get_original_proc()` exposes saved original function pointers
- FunctorContext userdata type (`bg3se.FunctorContext`) for type-safe Lua bindings
- TreasureTable/TreasureCategory registered as Ext.Stats subtables

---

## [v0.36.33] - 2026-02-06

**Parity:** ~90% | **Category:** Bug Fix | **Issues:** #65

### Fixed
- **Game startup failure on some machines (Issue #65)**
  - Deferred ~65 `mach_vm_read_overwrite` kernel calls from `COsiris::Load` to tick loop
  - Network initialization now waits for Running state stability (500ms) before capture
  - State machine with exponential backoff retry (3 attempts max)
  - `BG3SE_NO_NET=1` environment variable retained as manual override
  - Root cause: kernel calls during timing-sensitive save load window caused session abort

### Technical
- New `net_hooks_request_deferred_init()` / `net_hooks_deferred_tick()` / `net_hooks_is_ready()` API
- Deferred state machine: IDLE → PENDING → CAPTURING → COMPLETE/FAILED
- Ext.Net local message bus continues working during deferred initialization

---

## [v0.36.32] - 2026-02-06

**Parity:** ~90% | **Category:** Stats Expansion + Level + Audio | **Issues:** Parity Push

### Added
- **Ext.Stats Expansion (12 new functions)**
  - `GetStats(type?)` — alias for GetAll, returns array of stat names
  - `SetPersistence(name, persist)` — deprecated stub with log-once warning
  - `GetStatsManager()` — raw RPGStats pointer for debug/advanced use
  - `GetCachedSpell(name)` — prototype cache lookup via SpellPrototypeManager
  - `GetCachedStatus(name)` — prototype cache lookup via StatusPrototypeManager
  - `GetCachedPassive(name)` — prototype cache lookup via PassivePrototypeManager
  - `GetCachedInterrupt(name)` — prototype cache lookup via InterruptPrototypeManager
  - `EnumIndexToLabel(enumName, index)` — RPGEnumeration value-to-label conversion
  - `EnumLabelToIndex(enumName, label)` — RPGEnumeration label-to-value conversion
  - `GetModifierAttributes(modifierName)` — returns {attrName=typeName} table for a stat type
  - `AddAttribute(list, name, type)` — stub with warning (rare API)
  - `AddEnumerationValue(type, label)` — stub with warning (rare API)

- **Ext.Level (9 functions) — NEW NAMESPACE**
  - `IsReady()` — check if LevelManager is available
  - `GetCurrentLevel()` — current EoCLevel pointer
  - `GetPhysicsScene()` — PhysicsSceneBase pointer
  - `GetAiGrid()` — AiGrid pointer
  - `RaycastClosest(src, dst, physType, includeGroup, excludeGroup, context)` — closest hit with Normal/Position/Distance
  - `RaycastAny(src, dst, ...)` — boolean hit check
  - `TestBox(pos, extents, physType, includeGroup, excludeGroup)` — box overlap test
  - `TestSphere(pos, radius, physType, includeGroup, excludeGroup)` — sphere overlap test
  - `GetHeightsAt(x, z)` — tile height query (stub pending AiGrid offset verification)

- **Ext.Audio (13 functions) — NEW NAMESPACE**
  - `IsReady()` — check if SoundManager is available
  - `GetSoundObjectId(name)` — resolve "Global", "Music", "Listener0", etc. to ID
  - `PostEvent(soundObject, eventName)` — play a WWise event
  - `Stop(soundObject)` — stop playback on a sound object
  - `PauseAllSounds()` — pause all audio
  - `ResumeAllSounds()` — resume all audio
  - `SetSwitch(soundObject, switchGroup, state)` — set WWise switch
  - `SetState(stateGroup, state)` — set global WWise state
  - `SetRTPC(soundObject, name, value)` — set real-time parameter
  - `GetRTPC(soundObject, name)` — read real-time parameter
  - `ResetRTPC(soundObject, name)` — reset parameter to default
  - `LoadEvent(eventName)` — preload event data
  - `UnloadEvent(eventName)` — release event data

### Technical
- New modules: `src/level/level_manager.c`, `src/audio/audio_manager.c`
- New Lua bindings: `src/lua/lua_level.c`, `src/lua/lua_audio.c`
- Stats enum lookup uses RPGStats.ModifierValueLists CNEM at +0x08
- RPGEnumeration inherits CNamedElementManager — same CNEM access pattern
- Level manager shares LevelManager::m_ptr (0x08a3be40) with template_manager
- Audio manager accesses SoundManager via ResourceManager::m_ptr chain
- Physics raycasting via PhysicsScene VMT dispatch (indices need runtime verification)
- All ARM64 struct offsets are best-effort from Windows analysis; runtime RE session needed to verify

---

## [v0.36.31] - 2026-02-06

**Parity:** ~88% | **Category:** Network Handshake | **Issues:** #6

### Added
- **NetChannel API Phase 4I: ClientConnect Handshake + Version Negotiation**
  - JSON-based hello handshake: client sends `{"t":"hello","v":2}` after protocol insertion, server replies
  - `peer_manager_can_send_extender()` — gates all RakNet sends on handshake completion (proto_version > 0)
  - `Ext.Net.IsReady()` — Lua API to check if handshake is complete (server: always true, client: after hello exchange)
  - `Ext.Net.PeerVersion(userId)` — Lua API to query a peer's negotiated protocol version
  - Hello message parsing in `extender_process_msg()` — intercepts `{"t":"hello","v":N}` before routing to message bus
  - Server auto-replies to hello messages from clients
  - Host peer marked as handshake-complete on protocol insertion

### Fixed
- **ProtocolList offset corrected** — changed from `+0x2E0` to `+0x2D0`, and capacity/size fields from `uint64_t` at 16-byte stride to packed `uint32_t` at 4-byte stride. Fixes protocol insertion failing silently on all game versions. Discovered via runtime probing (45 protocols, cap=64).
- **Phase 4H critical: auto-switch timing** — moved `network_backend_set_raknet()` from `net_hooks_capture_peer()` to end of `net_hooks_insert_protocol()`, preventing message loss in the gap before protocol insertion
- **Phase 4H: hash container warning** — `net_hooks_sync_active_peers()` now logs a warning (once) when 0 of N peer IDs pass sanity check
- **Hello ping-pong prevention** — only reply to a peer's first hello (check `proto_version == 0` before replying)
- **Buffer overread in hello parsing** — `is_hello_message()` and `parse_hello_version()` now copy payload to NUL-terminated stack buffer before `strstr`/`sscanf`
- **Race condition** — `network_backend_set_raknet()` now runs before setting host peer proto_version, preventing wrong backend routing

### Technical
- `send_client_hello()` and `send_hello_reply()` bypass `raknet_send()` gating (use `net_hooks_send_message()` directly)
- `broadcast_visitor()` skips peers with `proto_version == 0`
- Implicit handshake (Phase 4H) preserved: any ExtenderMessage receipt sets `PROTO_VERSION_CURRENT`
- Ext.Net namespace now has 8 functions (added IsReady, PeerVersion)
- Added `safe_memory_write_u32()` to safe_memory API
- Larian Array layout confirmed: `{data_ptr(8), capacity_u32(4), size_u32(4)}` = 16 bytes

---

## [v0.36.30] - 2026-02-06

**Parity:** ~88% | **Category:** Network Multiplayer | **Issues:** #6

### Added
- **NetChannel API Phase 4H: Peer Resolution + Broadcast + Auto-Detect** - Completes RakNet backend for actual multiplayer
  - `peer_manager_iterate()` — callback-based iteration over all active peers
  - `peer_manager_find_by_guid()` — GUID-to-user_id lookup for `SendToClient`
  - `raknet_send_to_client()` — resolves character GUID to peer ID via PeerManager, then sends via GameServer VMT
  - `raknet_broadcast()` — iterates all non-host peers via PeerManager, sends to each (skips host + excluded character)
  - `net_hooks_sync_active_peers()` — reads GameServer ActivePeerIds array (+0x650/+0x65c) and syncs into PeerManager
  - Auto-switch to RakNet backend when GameServer is captured in `net_hooks_capture_peer()`
  - Implicit peer handshake — unknown peers auto-registered on first ExtenderMessage receipt in `extender_process_msg()`

### Technical
- `OFFSET_GAMESERVER_ACTIVE_PEERS = 0x650`, `OFFSET_GAMESERVER_ACTIVE_PEERS_COUNT = 0x65c` in protocol.h
- `PeerIterator` callback typedef and `broadcast_visitor` pattern for safe peer iteration
- ActivePeerIds sync called before broadcast to ensure PeerManager coverage
- Fallback: if ActivePeerIds is a hash container (not flat array), implicit registration provides coverage

---

## [v0.36.29] - 2026-02-06

**Parity:** ~88% | **Category:** Network Transport | **Issues:** #6

### Added
- **NetChannel API Phase 4G: Bidirectional Message Transport** - Real payload I/O via BitstreamSerializer VMT dispatch + outbound send via GameServer
  - `em_serialize` replaced diagnostic stub with real WriteBytes/ReadBytes via BitstreamSerializer VMT
  - BitstreamSerializer layout: VMT at +0x00, IsWriting (uint32) at +0x08, Bitstream* at +0x10
  - Itanium ABI VMT dispatch: WriteBytes at VMT[3], ReadBytes at VMT[4] (shifted from MSVC by +1 destructor)
  - One-time diagnostic logging on first serialize call for runtime verification
  - All VMT calls use `safe_memory_read_pointer` for crash safety
- **Outbound Send via GameServer VMT** - `net_hooks_send_message()` sends ExtenderMessages to peers
  - SendToPeer at VMT index 28 (Itanium ABI = MSVC index 27 + 1)
  - Runtime VMT probe validates function pointer before first call
  - Signature: `void (*)(AbstractPeer* this, int32_t* peerId, void* msg)` — peerId by pointer (ARM64)
  - Diagnostic logging of VMT entries around SendToPeer index for verification
- **RakNet Backend Implementation** - Full backend for real multiplayer message transport
  - JSON wire format: `{"c":"channel","m":"module","p":payload,"r":request_id,"b":binary}`
  - `raknet_send_to_server()` — client sends to peer 0 (server)
  - `raknet_send_to_user()` — server sends to specific peer by ID
  - `raknet_send_to_client()` — falls back to local (GUID resolution deferred)
  - `raknet_broadcast()` — falls back to local (peer iteration deferred)
  - `network_backend_set_raknet()` — auto-switches when GameServer is captured
  - ExtenderMessage pool allocation with controlled lifetime (pool slot intentionally held during transport)

### Technical
- `VMT_IDX_SEND_TO_PEER = 28`, `VMT_IDX_SEND_TO_MULTIPLE_PEERS = 32`, `VMT_IDX_CLIENT_SEND = 33` in protocol.h
- `OFFSET_SERIALIZER_ISWRITING = 0x08`, `VMT_IDX_WRITEBYTES = 3`, `VMT_IDX_READBYTES = 4` in protocol.h
- `net_hooks_send_message()` and `net_hooks_get_game_server()` added to net_hooks public API
- RakNet backend uses `extender_message_pool_get()` for zero-malloc send path
- Pool slots intentionally leaked during transport (game holds reference); reclamation deferred to post-send hook

---

## [v0.36.28] - 2026-02-06

**Parity:** ~88% | **Category:** Network Hooks | **Issues:** #6

### Added
- **NetChannel API Phase 4F: GetMessage Hook** - Dobby hook on `NetMessageFactory::GetMessage` intercepts message ID 400
  - ASLR-aware address resolution from Ghidra virtual address `0x1063d5998`
  - For ID 400 returns pooled ExtenderMessage; all other IDs pass through to original
  - Pre-allocated pool of 8 ExtenderMessages avoids malloc in the hot path
  - Pool falls back to heap allocation when exhausted
- **ExtenderMessage full layout** - MessageBase expanded to 40 bytes matching Windows `net::Message`
  - Added: priority, ordering_sequence, timestamped, timestamp, original_size, latency fields
  - `init_message_base()` helper initializes all fields with correct defaults
- **em_serialize diagnostic** - Dumps first 64 bytes of BitstreamSerializer for layout discovery
  - Probes candidate IsWriting offsets (0x08, 0x10, 0x18)
  - Enables runtime discovery of serializer fields without Ghidra
- **ExtenderProtocol process_msg routing** - Incoming ID 400 messages routed to message_bus
  - Extracts sender user_id from MessageContext
  - Rate-limited via `message_bus_queue_from_peer()`
  - Returns messages to pool after processing

### Technical
- `ADDR_GETMESSAGE` constant in protocol.h for Ghidra address management
- `get_runtime_addr()` helper follows established ASLR pattern from functor_hooks.c
- GetMessage hook state cleared during `net_hooks_remove()` for safe shutdown

---

## [v0.36.27] - 2026-02-05

**Parity:** ~88% | **Category:** Network Integration | **Issues:** #6

### Added
- **NetChannel API Phase 4E: Live ProtocolList Insertion** - ExtenderProtocol now injected into the game's dispatch chain
  - `net_hooks_insert_protocol()` performs insert_at(0) swap pattern into ProtocolList array
  - Idempotency guard prevents double-insertion on repeated COsiris::Event calls
  - Array growth with `malloc` fallback when capacity is full (one-time ~64 byte leak of game buffer)
  - ARM64 memory barriers (`__sync_synchronize`) ensure write ordering for concurrent readers
  - Post-insertion verification reads back data[0] to confirm
- **MessageFactory Runtime Probe** - Diagnostic probing of NetMessageFactory layout
  - Probes 32-bit and 64-bit pool array candidate layouts
  - Validates pool entries by sampling first 4 vtable pointers
  - Reports whether message ID 400 is within pool range (actual registration deferred to Phase 4F)
- **Safe Memory Write API** - `safe_memory_write()`, `safe_memory_write_pointer()`, `safe_memory_write_u64()`
  - Validates destination via `mach_vm_region`, uses `mach_vm_protect` fallback for read-only pages
  - GPU carveout region guard prevents writes to device memory

### Changed
- `net_hooks_remove()` now removes ExtenderProtocol from ProtocolList (swap-with-last pattern)
- `bg3se_cleanup()` calls `net_hooks_remove()` before ImGui/Lua shutdown
- Console Enter key bug fixed (Issue #65) — removed `insertNewline:` interception in overlay

### Technical
- ExtenderMessage vtable updated to Itanium ABI (dual destructor + preamble block)
- ProtocolList probe offsets corrected to match NETWORKING.md (+0x2E0/+0x2F0/+0x300)
- All raw pointer dereferences in net_hooks.c replaced with safe_memory API

---

## [v0.36.26] - 2026-02-05

**Parity:** ~88% | **Category:** Network RE | **Issues:** #6

### Added
- **NetChannel API Phase 4D: Ghidra RE Complete** - All network offsets verified via statistical binary analysis
  - `EocServer+0xA8 = GameServer*` — Confirmed (233 accesses across 2706 singleton loads)
  - `GameServer+0x1F8 = NetMessageFactory*` — Confirmed (74 accesses, +16 shift from Windows)
  - `GameServer+0x2E0 = ProtocolList` — Confirmed (data/capacity/size at +0x2E0/+0x2F0/+0x300)
  - `GameServer+0x310 = ProtocolMap` — Confirmed (HashMap for protocol ID lookup)
- **Itanium C++ ABI Vtable** — Correct dual-destructor vtable layout for macOS ARM64
  - `ProtocolVtableBlock` with preamble (offset_to_top=0, typeinfo=NULL) + 8 function pointers
  - ExtenderProtocol uses static vtable block, vptr points past preamble
- **Runtime ProtocolList Probing** — Tries 3 candidate array layouts at capture time
  - Validates entries by checking for vtable-like pointer at offset 0
  - Falls back to hex dump of GameServer+0x2D0..0x320 for manual analysis
- **Network Pointer Capture Pipeline** — `net_hooks_capture_peer()` reads pointers from live game
  - Captures GameServer, NetMessageFactory, and ProtocolList from EocServer
  - Integrated into main.c after EntityWorld discovery
- **RE Scripts** — `scripts/re/find_dispatch.py`, `find_processmsg.py` for binary analysis

### Technical
- `entity_get_eoc_server()` accessor added to entity_system for cross-module access
- Message dispatch: AbstractPeer iterates ProtocolList calling ProcessMsg virtual — no hooking needed
- `NetMessageFactory::GetMessage` at `0x1063d5998` (524 callers in binary)
- Windows→macOS offset shifts: +16 (NetMessageFactory), +48 (ProtocolList) due to pthread_mutex_t growth

---

## [v0.36.25] - 2026-02-04

**Parity:** ~88% | **Category:** Network API | **Issues:** #6

### Added
- **NetChannel API Phase 4A: Foundation** - Multiplayer-ready protocol and peer abstractions
  - `protocol.h` - Protocol VMT matching Windows `net::Protocol` (7 virtual functions)
  - `extender_protocol.c/h` - ExtenderProtocol with stub ProcessMsg for protocol chain
  - `network_backend.c/h` - Pluggable backend (LocalBackend now, RakNetBackend future)
  - `peer_manager.c/h` - Peer tracking with rate limiting (16 peers, 100 msg/s default)
  - Constants: `NETMSG_SCRIPT_EXTENDER = 400`, `ProtoVersion`, `ProtocolResult`
- **NetChannel API Phase 4B: ExtenderMessage** - Custom network message type
  - `extender_message.c/h` - Message struct with VMT matching Windows `net::Message`
  - Wire format: `[4-byte LE size][payload]` for network serialization
  - Create/destroy/reset/serialize/deserialize API
- **NetChannel API Phase 4E: Security Hardening** - Rate limiting and payload validation
  - `message_bus_queue_from_peer()` - Rate-limited queueing for network messages
  - Payload size validation against `MAX_MESSAGE_PAYLOAD` (64KB)
  - Channel name validation (reject empty channels)

### Changed
- `lua_net.c` - Extracted `maybe_register_callback()` and `queue_or_error()` helpers (DRY)
- `lua_net.c` - Renamed `g_*` to `s_*` for file-static variables per conventions
- `lua_net.c` - Removed unused `get_opt_bool()` (binary flag was always discarded)

### Technical
- VMT layout note added for Itanium ABI dual-destructor consideration (Phase 4D)
- Virtual destructor clears singleton to prevent dangling pointers
- `peer_manager_clear()` now properly resets `s_initialized` for full state reset
- Consistent auto-init guards across all `peer_manager_*` public functions
- `net_hooks.c/h` prepared with documented Ghidra RE targets for Phase 4D
- 4 reviewers (3 Claude agents + 1 Codex GPT-5.2): 0 critical bugs remaining

---

## [v0.36.24] - 2026-02-04

**Parity:** ~88% | **Category:** Network API | **Issues:** #6

### Added
- **NetChannel API Phase 2 Complete** - Request/reply callbacks now working!
  - `channel:SetRequestHandler(fn)` - Register handler that returns response data
  - `channel:RequestToServer(data, callback)` - Send request with reply callback
  - `channel:RequestToClient(data, user, callback)` - Server to client with callback
  - Callbacks are one-shot (automatically cleaned up after invocation)
  - 30-second timeout cleanup for stale callbacks

### Fixed
- **Critical: Lua state mismatch in callback invocation** - Three-agent review identified bug where `callback_registry_retrieve()` switched to `owner_L` internally but didn't return it to caller
  - Added `out_L` parameter to return actual Lua state used
  - `callback_registry_invoke()` now uses the correct state for stack operations
  - Prevents stack corruption when owner_L != L

- **JSON double-parsing error** - Callbacks received "bad argument #1 to 'Parse' (string expected, got table)"
  - Root cause: C code parsed JSON into table, but Lua wrapper tried to parse again
  - Fix: Pass raw JSON string to callbacks (matches Windows BG3SE behavior)

### Technical
- `callback_registry_retrieve(L, request_id, &out_L)` - Returns actual owner state via out parameter
- `callback_registry_invoke(L, request_id, payload, user_id)` - Full callback invocation with state safety
- `callback_registry_cleanup_for_state(L)` - Clean up callbacks when Lua state is destroyed
- Added owner tracking (`owner_L`) in CallbackEntry for cross-state safety
- Callbacks receive: `(payload_string, binary_flag)` - consistent with Windows BG3SE

### Verified
```
=== PHASE 2 FINAL TEST ===
Request sent, waiting for callback...
Server received: {"message":"Hello Phase 2!"}
*** CALLBACK SUCCESS! ***
Response: {"status":"ok","echo":"Hello Phase 2!"}
```

---

## [v0.36.23] - 2026-02-03

**Parity:** ~88% | **Category:** Network API | **Issues:** #6

### Added
- **Ext.Net Namespace** - Network messaging API for multiplayer mod synchronization
  - `PostMessageToServer(channel, payload, module, handler, replyId, binary)` - Client to server messaging
  - `PostMessageToUser(userId, channel, payload, module, handler, replyId, binary)` - Server to specific user
  - `PostMessageToClient(guid, channel, payload, module, handler, replyId, binary)` - Server to specific client
  - `BroadcastMessage(channel, payload, excludeChar, module, handler, replyId, binary)` - Server to all clients
  - `Version()` - Returns protocol version (2 for binary support)
  - `IsHost()` - Returns true if running as host

- **Ext.Mod Namespace** - Mod information and query functions
  - `IsModLoaded(modGuid)` - Check if a mod is loaded by UUID or name
  - `GetLoadOrder()` - Get array of mod UUIDs in load order
  - `GetMod(modGuid)` - Get mod information by UUID
  - `GetBaseMod()` - Get base game mod (GustavX)
  - `GetModManager()` - Get mod manager info (stub)

- **Net.CreateChannel API** - High-level channel abstraction for network communication
  - `Net.CreateChannel(module, channel)` - Create a network channel
  - `channel:SetHandler(fn)` - Set message handler
  - `channel:SetRequestHandler(fn)` - Set request/reply handler
  - `channel:SendToServer(data)` - Fire-and-forget to server
  - `channel:RequestToServer(data, callback)` - Request with reply callback
  - `channel:SendToClient(data, user)` - Send to specific client
  - `channel:Broadcast(data)` - Send to all clients

- **NetModMessage Event** - Event fired when network messages are received
  - Fields: Channel, Payload, Module, UserID, RequestId, ReplyId, Binary

### Technical
- New source files:
  - `src/lua/lua_mod.c/h` - Ext.Mod implementation
  - `src/lua/lua_net.c/h` - Ext.Net implementation
  - `src/lua/lua_net_scripts.h` - Embedded Lua libraries (Class, NetChannel, NetworkManager)
  - `src/network/message_bus.c/h` - In-process message routing
  - `src/network/callback_registry.c/h` - Request/reply correlation
- Added `LOG_MODULE_NET` to logging system
- Phase 1 implementation: Local in-process message routing for single-player testing
- Phase 2/3 (network hooks) planned for future release

---

## [v0.36.22] - 2026-02-02

**Parity:** ~87% | **Category:** Bug Fix | **Issues:** #60

### Fixed
- **Critical: In-Combat Reaction Crash** - Fixed crash when using combat reactions (Attack of Opportunity, Counterspell, Shield, etc.)
  - **Root cause:** `ExecuteInterruptFunctorsProc` had incorrect 3-parameter signature instead of 4-parameter
  - **Fix:** Added missing `HitResult*` as first parameter to match Windows BG3SE
  - Verified against Windows BG3SE source (`FunctorEvents.inl`)

### Technical
- `functor_types.h`: Updated `ExecuteInterruptFunctorsProc` typedef to 4 parameters
- `functor_hooks.c`: Updated `hook_ExecuteFunctors_Interrupt` to forward all 4 parameters
- Interrupt handler signature: `(HitResult*, void* entityWorld, StatsFunctorList*, InterruptContextData*)`

---

## [v0.36.21] - 2026-01-30

**Parity:** ~87% | **Category:** ImGui Widget System Complete | **Issues:** #36

### Added
- **Complete Ext.IMGUI Widget System** - All 40 widget types now implemented with full event support
  - **Input Widgets:** InputText, Combo, RadioButton with Value/SelectedIndex properties and OnChange callbacks
  - **Slider Widgets:** SliderFloat, SliderInt, DragFloat, DragInt with Min/Max/Value support
  - **Color Widgets:** ColorEdit, ColorPicker with RGBA Color property
  - **Container Widgets:** Group, Tree, Table, TabBar, TabItem, MenuBar, Menu, MenuItem
  - **Display Widgets:** Text, ProgressBar, Separator, Spacing
  - **Event System:** OnClick, OnChange, OnActivate, OnDeactivate, OnHoverEnter, OnHoverLeave, OnClose, OnExpand, OnCollapse

### Added (Tooling)
- **Standalone Test Application** - `tools/imgui_test/` for testing widgets without launching BG3
  - Metal + Cocoa rendering with full ImGui integration
  - Lua console for interactive widget testing
  - Quick test buttons for all widget types
  - Script loading from `test_scripts/` directory

### Fixed
- **Memory Leak:** Lua reference cleanup on object destruction via `lua_imgui_cleanup_refs()`
- **NULL Safety:** All child widget iterations now check for NULL before rendering
- **Malloc Safety:** Combo widget creation checks for allocation failure

### Technical
- Added `imgui_objects_get_window_count()`, `imgui_objects_get_total_count()` for statistics
- Added `imgui_metal_render_all_windows()` public API for standalone rendering
- Test tool includes stub implementations for metal backend when running standalone
- ~1,400 lines of new widget rendering code across 14 widget types

---

## [v0.36.20] - 2025-12-31

**Parity:** ~85% | **Category:** ImGui Widget System | **Issues:** #36

### Added
- **Ext.IMGUI Widget System** - Full handle-based object system for creating ImGui widgets from Lua
  - `Ext.IMGUI.NewWindow(label)` - Create windows with Open, Closeable, Visible properties
  - `win:AddText(label)` - Text widgets with optional Color property
  - `win:AddButton(label)` - Button widgets with Size property
  - `win:AddCheckbox(label, checked)` - Checkbox widgets with Checked property
  - `win:AddSeparator()`, `win:AddSpacing()` - Layout widgets
  - `win:AddGroup(label)` - Container groups for organizing widgets
  - `widget:Destroy()` - Explicit cleanup method
- **Handle-Based Object Pool** - 4096 max objects with generation counters to prevent stale reference bugs
- **Lua Userdata Metatables** - `__index`/`__newindex` for property access, `__gc` for cleanup
- **Event Callback Support** - `OnClick`, `OnChange`, `OnClose` can be assigned Lua functions

### Technical
- New files: `src/imgui/imgui_objects.h`, `src/imgui/imgui_objects.c`
- Modified: `src/lua/lua_imgui.c` (userdata system, widget methods)
- Modified: `src/imgui/imgui_metal_backend.mm` (widget rendering integration)
- Parent-child widget hierarchy with automatic cleanup
- Debug window now shows Lua window count

---

## [v0.36.19] - 2025-12-31

**Parity:** ~83% | **Category:** ImGui Input | **Issues:** #36

### Fixed
- **ImGui Mouse Input Complete** - Full mouse input now working (hover, click, drag)
  - **Root cause:** `ImGui_ImplOSX_NewFrame()` was overwriting CGEventTap mouse coordinates
  - **Fix:** Skip OSX backend NewFrame, use only CGEventTap for mouse position
  - Cache CGEventTap mouse position and apply directly to `io.MousePos` before `NewFrame()`
  - Hover detection (`WantCaptureMouse`) now works correctly
  - Button clicks register properly

### Technical
- Removed call to `ImGui_ImplOSX_NewFrame(view)` which was interfering with input
- Added `s_cgevent_mouse` cache to store last known CGEventTap coordinates
- Apply cached mouse position directly via `io.MousePos = ImVec2(x, y)` before `NewFrame()`
- Added debug display: DisplaySize, WinPos, Size in overlay for troubleshooting

---

## [v0.36.18] - 2025-12-30

**Parity:** ~83% | **Category:** ImGui Input | **Issues:** #36

### Fixed
- **ImGui Mouse Input** - Fixed coordinate conversion for macOS Cocoa games
  - Removed broken fullscreen special case that passed CG coords directly
  - Implemented proper 4-step Cocoa coordinate conversion (CG → Screen → Window → View)
  - Restored position update in click handler (was missing, causing stale positions)
  - CGEventTap mouse moves now forwarded to ImGui backend
  - Works correctly in both fullscreen and windowed modes

### Technical
- **Key Discovery:** BG3 macOS uses native Cocoa/AppKit, NOT SDL (unlike Windows)
  - Windows BG3SE hooks `SDL_PollEvent` via Detours - this approach doesn't apply
  - macOS requires CGEventTap + proper Cocoa coordinate system conversion
- Modified `convert_screen_to_window()` in `imgui_metal_backend.mm`:
  - Step 1: CG (top-left origin) → Cocoa screen (bottom-left origin)
  - Step 2: Screen coords → Window coords via `convertPointFromScreen:`
  - Step 3: Window coords → View coords via `convertPoint:fromView:`
  - Step 4: Flip Y for ImGui if view not flipped
- Added debug logging every 120th conversion to verify coordinate chain
- Updated `plans/fix-imgui-mouse-input.md` with complete implementation details
- Updated `agent_docs/architecture.md` with ImGui overlay system documentation

---

## [v0.36.17] - 2025-12-28

**Parity:** ~83% | **Category:** IDE Integration | **Issues:** #7

### Added
- **IDE Type Helpers** - Generate LuaLS annotations for VS Code IntelliSense
  - `Ext.Types.GenerateIdeHelpers(filename?)` - Generate type definitions file
  - `Ext.Types.GetComponentLayout(name)` - Get property layout for components
  - `Ext.Types.GetAllLayouts()` - List all components with property layouts
  - `!ide_helpers` console command for quick generation

### Technical
- Created `src/lua/lua_ide_helpers.c/h` - Modular IDE helper generation
- Added `component_property_get_layout_at(index)` and `component_property_iterate_layouts()` to component_property.c
- Added `component_registry_get_at(index)` to component_registry.c
- Output includes: ~2000 component classes, 534 with property annotations, 14 enum aliases, Ext.* namespace

---

## [v0.36.16] - 2025-12-27

**Parity:** ~82% | **Category:** Reflection API | **Issues:** #48

### Added
- **Ext.Types Full Reflection API** - Complete type introspection system
  - `Ext.Types.GetAllTypes()` - Returns all ~2050 registered types (userdata + 1999 components + 50+ enums)
  - `Ext.Types.GetTypeInfo(name)` - Rich metadata for components, enums, and userdata types
  - `Ext.Types.TypeOf(obj)` - Returns type info table for an object
  - `Ext.Types.IsA(obj, typeName)` - Type checking with inheritance/namespace matching

### Changed
- `Ext.Types.GetTypeInfo()` now returns rich metadata:
  - **Components**: Kind, Size, TypeIndex, IsOneFrame, IsProxy, Discovered
  - **Enums**: Kind, ValueCount, TypeIndex, Values (label→value), Labels (ordered array)
  - **Bitfields**: Same as enums plus AllowedFlags
  - **Userdata**: Kind, HasMetatable, MethodCount

### Technical
- Added `enum_registry_iterate()` callback function to `src/enum/enum_registry.c`
- Modified `lua_types_getalltypes()` to iterate component and enum registries
- Expanded `lua_types_gettypeinfo()` with component/enum metadata
- Added helper `get_object_type_name()` for internal type resolution

---

## [v0.36.15] - 2025-12-27

**Parity:** ~80% | **Category:** Stats/Events/Docs | **Issues:** #53, #46

### Added
- **Stats Functor System** - Hook into game's damage/healing/status effect execution
  - `Ext.Events.ExecuteFunctor` - Fires before each functor executes (9 context types)
  - `Ext.Events.AfterExecuteFunctor` - Fires after functor execution completes
  - All 9 context types hooked: AttackTarget, AttackPosition, Move, Target, NearbyAttacked, NearbyAttacking, Equip, Source, Interrupt

### Documentation
- **API Context Annotations** (Issue #46) - Added context column to all API tables in api-reference.md
  - **B** = Both (server and client)
  - **S** = Server-only (Ext.Osiris, Osi.*, Stats writes, combat events)
  - **C** = Client-only (Ext.Input, KeyInput events)
  - All 15+ namespaces annotated across 50+ API entries
  - Added Context Annotations legend section to api-reference.md

### Technical
- Created `src/stats/functor_types.h` with data structures
- Created `src/stats/functor_hooks.c` with Dobby hooks on 9 game functions
- Added `events_fire_execute_functor()` and `events_fire_after_execute_functor()` to lua_events.c
- Documented all Ghidra offsets in `ghidra/offsets/FUNCTORS.md`

---

## [v0.36.14] - 2025-12-27

**Parity:** ~80% | **Category:** Entity System | **Issues:** #51 (dual world complete)

### Added
- **Dual EntityWorld Infrastructure** - Full client/server world separation
  - `Ext.Entity.GetServerWorld()` - Returns server EntityWorld pointer
  - `Ext.Entity.GetClientWorld()` - Returns client EntityWorld pointer (now working!)
  - `Ext.Entity.DiscoverClientWorld()` - Attempt client world discovery
  - `Ext.Entity.SetClientSingleton(addr)` - Set runtime-discovered client address
  - `Ext.Entity.ProbeClientSingleton(base, range, offset)` - Memory scanning for client singleton
  - `Ext.Entity.GetKnownAddresses()` - Debug info for all known addresses

### Verified
- **Client EntityWorld Captured** - Both client and server worlds now auto-captured at runtime
  - Server EntityWorld: `0x15a08bc00` (at `esv::EocServer + 0x288`)
  - Client EntityWorld: `0x6000004c19a0` (at `ecl::EocClient + 0x1B0`)
  - Client singleton discovered via Ghidra: `ecl::EocClient::m_ptr` at `0x10898c968`
- **Turn Events Working** - Ext.Events.TurnStarted/TurnEnded fire correctly in combat
  - Character GUIDs passed to handlers (e.g., `S_Player_Astarion_c7c13742-...`)
  - Both player and NPC turns trigger events

### Technical
- Added `g_ServerEntityWorld` and `g_ClientEntityWorld` globals
- Added `g_RuntimeClientSingletonAddr` for Lua-configurable client address
- Added `entity_discover_client_world()` and `entity_get_world_for_context()`
- **Client singleton offset discovered:** `OFFSET_EOCCLIENT_SINGLETON_PTR = 0x10898c968`
- **EntityWorld offset verified:** `OFFSET_ENTITYWORLD_IN_EOCCLIENT = 0x1B0`
- PermissionsManager at `EocClient + 0x1B8` (confirmed via disassembly)

### Discovery Method
Found via Ghidra analysis of `gui::DataContextProvider::CreateDataContextClass` at `0x1024f008c`:
```asm
1024f0218: adrp x8,0x10898c000
1024f021c: ldr x25,[x8, #0x968]   ; Load ecl::EocClient::m_ptr
1024f0228: add x26,x25,#0x1b8    ; PermissionsManager at EocClient+0x1b8
```

---

## [v0.36.13] - 2025-12-26

**Parity:** ~80% | **Category:** Events System | **Issues:** #51 (bridge complete)

### Added
- **Osiris → Ext.Events Bridge** - Turn events now fire through both APIs
  - `Ext.Events.TurnStarted:Subscribe()` now works (was broken - polling returned 0)
  - `Ext.Events.TurnEnded:Subscribe()` now works
  - Events bridged from Osiris callbacks with `CharacterGuid` field
  - Provides Events API features: priority ordering, Once flag, handler IDs

### Technical
- Added `events_fire_turn_started_from_osiris()` and `events_fire_turn_ended_from_osiris()` in lua_events.c
- Bridge in `dispatch_event_to_lua()` detects Osiris turn events and fires Ext.Events
- Handlers receive `{CharacterGuid = "..."}` table

---

## [v0.36.12] - 2025-12-26

**Parity:** ~80% | **Category:** Logging Infrastructure | **Issues:** #8 (partial)

### Added
- **Session-Based Logging** - Each game session creates a new timestamped log file
  - Logs stored in `~/Library/Application Support/BG3SE/logs/`
  - Format: `bg3se_YYYY-MM-DD_HH-MM-SS.log`
  - `latest.log` symlink always points to current session
  - Cleaner log headers with session timestamp

- **OneFrame Component Pool Access** - Infrastructure for server-side events
  - Proper bucket-based HashMap lookup (`hashmap_find_index_u16`)
  - `get_oneframe_entities()` accesses OneFrameComponents pool at offset 0x2A0
  - `HasOneFrameComponents` flag check at offset 0x2E0
  - Debug logging for OneFrame pool traversal

### Verified
- **Osiris Turn Events** - Confirmed working in actual combat
  - `TurnStarted` fires when character's turn begins
  - `TurnEnded` fires when character's turn ends
  - Both events provide character GUID as argument
  - Note: Only fire in combat, not in force turn-based exploration

### Technical
- Session logs prevent single log file from growing indefinitely
- OneFrame pool access code runs correctly (returns 0 in client context - server EntityWorld needed for esv:: components)
- Ext.Log API verified working with module-aware logging

---

## [v0.36.11] - 2025-12-26

**Parity:** ~80% | **Category:** Events System | **Issues:** #51 (complete)

### Added
- **Engine Events Expansion Phase 2** - 11 new events (30 total, up from 19)
  - Death events: `Died`, `Downed`, `Resurrected`
  - Spell events: `SpellCast`, `SpellCastFinished`
  - Combat events: `HitNotification`
  - Rest events: `ShortRestStarted`
  - Social events: `ApprovalChanged`
  - Lifecycle events: `StatsStructureLoaded`, `ModuleResume`, `Shutdown`

- **One-Frame Component Polling** - 8 new polling handlers
  - `esv::death::ExecuteDieLogicEventOneFrameComponent`
  - `esv::death::DownedEventOneFrameComponent`
  - `esv::death::ResurrectedEventOneFrameComponent`
  - `eoc::spell_cast::CastEventOneFrameComponent`
  - `eoc::spell_cast::FinishedEventOneFrameComponent`
  - `esv::hit::HitNotificationEventOneFrameComponent`
  - `esv::rest::ShortRestResultEventOneFrameComponent`
  - `esv::approval::RatingsChangedOneFrameComponent`

- **Lifecycle Event Hooks**
  - `StatsStructureLoaded` - Fired before StatsLoaded (raw stats parsing)
  - `ModuleResume` - Fired on save game load (session resume)
  - `Shutdown` - Fired on game exit (cleanup opportunity)

### Fixed
- **TypeId Discovery for All Components** - Critical fix
  - Previously only 164 known TypeIds were discovered at runtime
  - Now discovers from all 1,999 generated component TypeId addresses
  - Enables `Ext.Entity.GetAllEntitiesWithComponent()` for all components
  - Fixes one-frame event polling (events now actually fire)

- **Unresolved TypeId Guards** - Prevents log spam and hangs
  - Skip component lookups when TypeId = 65535 (unresolved)
  - Silently return empty tables instead of spamming debug logs
  - Prevents save load hangs from excessive logging

### Technical
- Event system now has 30 events (Issue #51 complete)
- Lifecycle events integrated into destructor and COsiris::Load hook
- Event parity with Windows BG3SE core events achieved
- `component_typeid_discover_all_generated()` iterates all namespace arrays

---

## [v0.36.10] - 2025-12-26

**Parity:** ~78% | **Category:** Logging & Debugging | **Issues:** #8, #42 (partial)

### Added
- **Ext.Log Convenience Functions** - Windows BG3SE parity
  - `Ext.Log.Print(...)` - Log INFO with varargs (like print())
  - `Ext.Log.PrintWarning(...)` - Log WARN level
  - `Ext.Log.PrintError(...)` - Log ERROR level

- **Ext.Events.Log** - Log message interception for mods
  - Subscribe to intercept all log messages
  - Event data: `{Level, Module, Message, Prevent}`
  - Set `e.Prevent = true` to suppress default logging
  - Recursion prevention for log handlers that log

- **Debug Log Callback** - Infrastructure for Issue #42 debugger
  - `log_set_debug_callback()` / `log_get_debug_callback()` C API
  - Invoked for ERROR-level messages
  - Called outside mutex lock (deadlock prevention)

- **Log Monitoring Script** - `scripts/tail_log.sh`
  - `--no-osiris` flag to filter noisy Osiris events
  - `-g PATTERN` for grep filtering
  - Designed for Claude Code subagent monitoring

### Changed
- **File I/O Optimization** - Persistent log file handle
  - Log file opened once at init with line buffering
  - Eliminates fopen/fclose overhead per message

### Verified (Combat Testing)
- **Live combat event logging confirmed** - Tested Dec 26, 2025
  - Osiris events captured: EnteredCombat, CombatStarted, CombatRoundStarted, TurnStarted, TurnEnded
  - Callback dispatch logged: `[INFO ] [Osiris ] Dispatching TurnStarted callback (after, arity=1)`
  - Structured format working: `[timestamp] [LEVEL] [Module] message`
  - No errors or warnings during combat session
  - Module tags displaying correctly: `[Osiris]`, `[Events]`, `[Timer]`, etc.

### Technical
- `LOG_OUTPUT_CALLBACK` flag auto-enabled when callback registered
- Ext.Log namespace now has 12 functions (was 9)
- Event tracing available via `Ext.Debug.TraceEvents(true/false)`

---

## [v0.36.9] - 2025-12-24

**Parity:** ~78% | **Category:** Events System | **Issues:** #51

### Added
- **Engine Events Expansion** - 8 new one-frame component events
  - `TurnStarted` - Combat turn started (with Entity, Round data)
  - `TurnEnded` - Combat turn ended
  - `CombatStarted` - Combat initiated
  - `CombatEnded` - Combat resolved
  - `StatusApplied` - Status effect applied (with Entity, StatusId, Source)
  - `StatusRemoved` - Status effect removed
  - `EquipmentChanged` - Equipment slot changed
  - `LevelUp` - Character level increased

- **Event Polling System** - Tick-based polling of one-frame components
  - `events_poll_oneframe_components()` - Called every frame after tick
  - Queries entities with event marker components
  - Only polls when handlers are registered (performance optimization)

### Technical
- Events use Windows BG3SE one-frame component pattern
- Components polled: `esv::TurnStartedEventOneFrameComponent`, `esv::TurnEndedEventOneFrameComponent`, etc.
- Handler data includes relevant entity handles and event metadata
- Full event list now: 18 events (10 existing + 8 new engine events)
- **Ghidra TypeId Discovery** - Found missing TypeId addresses via RegisterType decompilation:
  - `esv::TurnStartedEventOneFrameComponent` → `0x1083f1848`
  - `esv::TurnEndedEventOneFrameComponent` → `0x1083f1810`
  - `esv::stats::LevelChangedOneFrameComponent` → `0x1083f2050`

---

## [v0.36.8] - 2025-12-24

**Parity:** ~77% | **Category:** Component System | **Issues:** #52

### Added
- **Unified Component Database** - Merged all component size sources
  - 1,577 ARM64 sizes from Ghidra decompilation (79% of TypeIds)
  - 702 Windows estimates from BG3SE C++ header parsing
  - 1,730 total components with size info (87% coverage)
  - `ghidra/offsets/COMPONENT_DATABASE.md` - Master reference merging all sources

- **New Analysis Tools**
  - `tools/extract_windows_sizes.py` - Parse Windows BG3SE C++ headers
  - `tools/compare_component_sizes.py` - Cross-reference Ghidra vs Windows vs TypeIds
  - `tools/create_unified_database.py` - Merge all sources into unified database
  - `tools/generate_layouts.py` - Generate C property layouts with ARM64-verified sizes

- **Improved Property Layout Generation**
  - 293 generated layouts (down from 504) with valid field types only
  - Ghidra-verified ARM64 sizes used where available
  - Skips complex container types (Array, HashMap) that can't be exposed to Lua

### Technical
- **Size Sources Priority**: Ghidra ARM64 > Windows estimates > TypeId only
- **Field Type Validation**: Only generates layouts with valid FIELD_TYPE_* constants
- **Cross-Platform Comparison**: 404 matches, 136 discrepancies between Windows/ARM64

---

## [v0.36.7] - 2025-12-23

**Parity:** ~77% | **Category:** Component System | **Issues:** #52

### Added
- **1,030 ARM64 Component Sizes** - Crossed 1000-component milestone via parallel Ghidra extraction
  - 51.5% coverage of all 1,999 BG3 ECS components
  - Parallel subagent extraction workflow with staging directory for persistence
  - Documented in modular namespace files under `ghidra/offsets/`

- **Component Size Documentation Expansion**
  - `COMPONENT_SIZES_EOC_NAMESPACED.md` - 520 sub-namespaced components (115 namespaces)
  - `COMPONENT_SIZES_EOC_BOOST.md` - 76 boost components
  - `COMPONENT_SIZES_LS.md` - 106 Larian engine components
  - `COMPONENT_SIZES_ESV.md` - 160 server components
  - `COMPONENT_SIZES_ECL.md` - 99 client components
  - `COMPONENT_SIZES_NAVCLOUD.md` - 17 navigation components

- **New Component Categories Discovered**
  - eoc::spell_cast:: - 15 one-frame event components (CastStart, CastHit, Finished, etc.)
  - eoc::script:: - 3 scripting bridge components
  - eoc::shapeshift:: - 3 transformation state components
  - ls::cluster:: - 5 spatial partitioning components (X/Y/Z position)
  - ls::physics:: - 6 async resource loading components

### Technical
- **Extraction Pattern**: `ComponentFrameStorageAllocRaw((ComponentFrameStorage*)(this_00 + 0x48), SIZE, ...)`
- **Staging Directory Workflow**: Agents write to `ghidra/offsets/staging/` to survive context compaction
- **Parallel Agent Strategy**: 5+ agents extracting different offset ranges concurrently
- **Size Distribution**:
  - 1 byte: Tag/presence markers (IsInCombat, Active, etc.)
  - 4-8 bytes: Simple values (handles, integers)
  - 40-64 bytes: Standard data components (Health, Armor)
  - 400-500 bytes: Large events (CastEvent, HitResult)
  - 800+ bytes: Massive containers (BoostsComponent at 832 bytes)

---

## [v0.36.6] - 2025-12-23

**Parity:** ~77% | **Category:** Component System | **Issues:** #52

### Added
- **1,999 Component Registration** - All BG3 ECS components now auto-registered from binary
  - `src/entity/generated_typeids.h` - TypeId addresses for all 1,999 components
  - Extracted via `tools/extract_typeids.py` from macOS binary symbols
  - Namespace breakdown: eoc (701), esv (596), ecl (429), ls (233), gui (26), navcloud (13), ecs (1)

- **631 Component Property Layouts** - Two-tier registration system
  - **169 verified layouts** - Hand-verified ARM64 offsets, trusted property access
  - **462 generated layouts** - Windows offsets (estimated), runtime-safe defaults
  - `src/entity/generated_property_defs.h` - 504 property definitions with `Gen_` prefix
  - `tools/parse_component_headers.py` - Header parser with symbol prefix to avoid conflicts
  - MAX_COMPONENT_LAYOUTS increased from 128 to 1024

- **Modular Component Documentation** - New `docs/components/` directory
  - `README.md` - Component system overview and property coverage
  - `eoc-components.md` - 701 eoc:: components (gameplay)
  - `esv-components.md` - 596 esv:: server components
  - `ecl-components.md` - 429 ecl:: client components
  - `ls-components.md` - 233 ls:: engine base components
  - `misc-components.md` - gui, navcloud, ecs namespaces

- **Ghidra-Based Component Size Extraction** - 70 ARM64 sizes verified
  - `ghidra/offsets/COMPONENT_SIZES.md` - Central documentation
  - `ghidra/offsets/EXTRACTION_METHODOLOGY.md` - Extraction workflow
  - Pattern: `AddComponent<T>` → `ComponentFrameStorageAllocRaw(..., SIZE, ...)`

- **Component Sizes Extracted (Sample):**
  | Component | Size | Notes |
  |-----------|------|-------|
  | `eoc::StatsComponent` | 160 bytes | Largest core component |
  | `eoc::StatusImmunitiesComponent` | 64 bytes | HashMap container |
  | `eoc::BoostInfoComponent` | 88 bytes | Complex boost data |
  | `eoc::HealthComponent` | 40 bytes | HP/MaxHP/Temp |
  | `eoc::LevelComponent` | 4 bytes | Single int32 |
  | `eoc::combat::DelayedFanfareComponent` | 1 byte | Marker component |

### Technical
- **Two-Tier Registration**: Verified layouts register first (from `g_AllComponentLayouts`), then generated layouts (from `g_GeneratedComponentLayouts`) fill gaps - verified layouts take precedence
- **Gen_ Prefix Strategy**: All auto-generated symbols use `Gen_` prefix to avoid redefinition conflicts with 42 overlapping hand-verified layouts
- **Component Categories Discovered**:
  - Marker components (1 byte): Presence IS the data (boolean tags)
  - Container components (16-64 bytes): Hash tables, dynamic arrays
  - Data components (4-160 bytes): Game state storage
- **ARM64 vs Windows**: Sizes may differ due to alignment/packing differences
- **Automated workflow**: TypeId extraction → Header parsing → Size verification → Integration

### Files Added/Modified
- `src/entity/generated_typeids.h` - 1,999 TypeId address macros
- `src/entity/generated_property_defs.h` - 504 property definitions with `Gen_` prefix
- `src/entity/component_property.c` - Two-tier registration, MAX_COMPONENT_LAYOUTS=1024
- `tools/parse_component_headers.py` - Windows header parser with `Gen_` prefix
- `tools/generate_component_entries.py` - Skeleton generator from Ghidra sizes
- `ghidra/scripts/batch_extract_component_sizes.py` - Batch size extraction
- `ghidra/offsets/EXTRACTION_METHODOLOGY.md` - Extraction documentation
- `ghidra/offsets/component_sizes.json` - 30 verified ARM64 sizes
- `docs/components/` - Modular component documentation (6 files)

---

## [v0.36.5] - 2025-12-22

**Parity:** ~77% | **Category:** Math/Timer/IO APIs | **Issues:** #47, #49, #50

### Added
- **Ext.Math Quaternion Operations** - Full quaternion math library (16 functions)
  - `QuatIdentity()` - Identity quaternion
  - `QuatFromEuler(vec3)` - Euler angles to quaternion
  - `QuatFromAxisAngle(axis, angle)` - Axis-angle to quaternion
  - `QuatFromToRotation(from, to)` - Rotation between directions
  - `QuatToMat3(quat)` / `QuatToMat4(quat)` - Convert to matrix
  - `QuatFromMat3(mat3)` / `QuatFromMat4(mat4)` - Extract from matrix
  - `QuatNormalize(quat)` / `QuatInverse(quat)` / `QuatConjugate(quat)`
  - `QuatLength(quat)` / `QuatDot(q1, q2)`
  - `QuatMul(q1, q2)` - Quaternion multiplication
  - `QuatRotate(quat, vec3)` - Rotate vector by quaternion
  - `QuatSlerp(q1, q2, t)` - Spherical linear interpolation

- **Ext.Math Scalar Functions** - Missing math utilities
  - `Smoothstep(edge0, edge1, x)` - Hermite interpolation
  - `Round(x)` - Round to nearest integer
  - `IsNaN(x)` / `IsInf(x)` - Numeric validation
  - `Random()` / `RandomRange(min, max)` - Random number generation

- **Ext.Timer Time Utilities** - Precision timing functions
  - `MicrosecTime()` - Microseconds since app start (high-precision)
  - `ClockEpoch()` - Unix timestamp in seconds
  - `ClockTime()` - Formatted datetime string "YYYY-MM-DD HH:MM:SS"
  - `WaitForRealtime(delay, callback, [repeat])` - Wall-clock timer (ignores game pause)
  - `GameTime()` - Game time in seconds (pauses when game pauses)
  - `DeltaTime()` - Last frame's delta time in seconds
  - `Ticks()` - Game tick count
  - `IsGamePaused()` - Check if game time is paused

- **Ext.Timer Persistent Timers** - Timers that survive save/load cycles
  - `RegisterPersistentHandler(name, callback)` - Register named callback for persistence
  - `UnregisterPersistentHandler(name)` - Remove persistent handler
  - `WaitForPersistent(delay, handler, [args], [repeat])` - Create persistent timer
  - `CancelPersistent(handle)` - Cancel persistent timer
  - `ExportPersistent()` - Export timer state as JSON (for saving)
  - `ImportPersistent(json)` - Restore timer state from JSON (after loading)

- **Ext.IO Path Override System** - Virtual file path mapping
  - `AddPathOverride(original, override)` - Register path redirection
  - `GetPathOverride(original)` - Query registered override

### Technical
- **Quaternion representation**: w,x,y,z (scalar-first) matching Windows BG3SE
- **Thread-safe path overrides**: pthread_rwlock_t for concurrent access
- **High-precision timing**: mach_absolute_time() for microsecond resolution
- **Persistent timers**: Named handlers with JSON-serializable args for save/load
- Uses existing math_ext.c infrastructure for vector/matrix operations

### Files Modified
- `src/math/math_ext.c/h` - Added quat type and 16 quaternion operations
- `src/math/lua_math.c` - Lua bindings for all new math functions
- `src/timer/timer.c/h` - Time utility implementations
- `src/lua/lua_timer.c` - Timer Lua bindings
- `src/io/path_override.c/h` - NEW: Path override system
- `src/lua/lua_ext.c/h` - IO path override bindings

---

## [v0.36.4] - 2025-12-22

**Parity:** ~76% | **Category:** Context System | **Issues:** #15

### Added
- **Client/Server Context Separation** - Lua execution context awareness
  - `Ext.GetContext()` - Returns "Server", "Client", or "None"
  - `Ext.IsServer()` / `Ext.IsClient()` - Now return real context state (were hardcoded stubs)
  - Context transitions through lifecycle: None → Server (BootstrapServer.lua) → Client (BootstrapClient.lua)

- **Context-Aware Bootstrap Loading** - Proper two-phase mod initialization
  - Phase 1: All BootstrapServer.lua files load in SERVER context
  - Phase 2: All BootstrapClient.lua files load in CLIENT context
  - Matches Windows BG3SE single-player behavior

- **Context Guards for Server-Only APIs**
  - Ext.Osiris operations: RegisterListener, NewCall, NewQuery, NewEvent, RaiseEvent
  - Ext.Stats write operations: SetProperty, Create, Sync
  - Guards log warnings (not errors) for backward compatibility

### Technical
- **Architecture Decision**: Single Lua state with context flag (not dual states)
  - BG3 macOS is single-player where server/client run in same process
  - Simpler to maintain while matching Windows BG3SE behavior
- **New module**: `src/lua/lua_context.c/h` - Context management
  - `LuaContext` enum: NONE, SERVER, CLIENT
  - Thread-safe static state with logging on transitions
- **Context detection**: Based on bootstrap loading phase, not runtime hooks

### Files Modified
- `src/lua/lua_context.c` - NEW: Context management implementation
- `src/lua/lua_context.h` - NEW: Context API declarations
- `src/lua/lua_ext.c` - Real IsServer/IsClient/GetContext implementations
- `src/injector/main.c` - Context init, two-phase bootstrap loading
- `src/lua/lua_osiris.c` - Context guards for Osiris operations
- `src/lua/lua_stats.c` - Context guards for Stats writes
- `CMakeLists.txt` - Added lua_context.c to build

---

## [v0.36.3] - 2025-12-22

**Parity:** ~75% | **Category:** StaticData | **Issues:** #45

### Added
- **All 9 StaticData types now working** - Complete expansion from Feat-only to full coverage
  - Background: 22 entries
  - Class: 70 entries
  - Origin: 27 entries
  - Progression: 1004 entries
  - ActionResource: 87 entries
  - Feat: 41 entries
  - Race: 156 entries
  - God: 24 entries
  - FeatDescription: 41 entries

- **Ext.StaticData.ForceCapture()** - Triggers manager capture without character creation
  - Calls Get<T> functions directly using captured ImmutableDataHeadmaster
  - Also performs hash lookup for types without Get<T> hooks

- **Ext.StaticData.HashLookup()** - Hash table lookup for remaining types
  - Uses type index from TypeContext to look up managers in ImmutableDataHeadmaster
  - Enables Race, God, FeatDescription, Feat capture

### Technical
- **Root cause identified**: TypeContext stores TYPE INDEX SLOTS (metadata), not actual manager instances
- **Dual capture strategy**:
  1. Get<T> hooks capture Background, Class, Origin, Progression, ActionResource automatically
  2. Hash lookup captures Race, God, FeatDescription, Feat via type index
- **ImmutableDataHeadmaster hash table structure** (from Ghidra decompilation):
  - `+0x00`: buckets array (uint32_t*)
  - `+0x08`: bucket_count (int32_t)
  - `+0x10`: next chain array (uint32_t*)
  - `+0x20`: keys array (int32_t*) - type indices
  - `+0x2c`: size (int32_t)
  - `+0x30`: values array (void**) - manager pointers
- **Get<T> function offsets**:
  - `Get<BackgroundManager>`: 0x02994834
  - `Get<OriginManager>`: 0x0341c42c
  - `Get<ClassDescriptions>`: 0x0262f184
  - `Get<ProgressionManager>`: 0x03697f0c
  - `Get<ActionResourceTypes>`: 0x011a4494

### Files Modified
- `src/staticdata/staticdata_manager.c` - Get<T> hooks, ForceCapture, hash lookup
- `src/staticdata/staticdata_manager.h` - New function declarations
- `src/lua/lua_staticdata.c` - ForceCapture and HashLookup Lua bindings
- `ghidra/offsets/STATICDATA.md` - TypeContext vs Manager discovery documentation
- `plans/fix-staticdata-memory-access.md` - Investigation and fix plan

---

## [v0.36.2] - 2025-12-21

**Parity:** ~73% | **Category:** Resource System | **Issues:** #41

### Added
- **Ext.Resource API** - Access to non-GUID game resources (Visual, Material, Texture, etc.)
  - `Ext.Resource.IsReady()` - Returns true when ResourceManager is available
  - `Ext.Resource.GetTypes()` - Returns all 34 resource type names
  - `Ext.Resource.GetCount(type)` - Returns count for a resource type
  - `Ext.Resource.GetAll(type)` - Returns all resources of a type
  - `Ext.Resource.Get(id, type)` - Get specific resource by FixedString ID

### Technical
- **Global pointer offset:** `ls::ResourceManager::m_ptr` at `0x08a8f070`
- **ResourceBank offsets:**
  - Primary bank at ResourceManager `+0x28`
  - Secondary bank at ResourceManager `+0x30`
- **ResourceContainer structure:**
  - Bank array at `+0x08` (indexed by type * 8)
  - Bucket count at `+0x08` within each bank
  - Bucket array at `+0x10`
- **Hash table traversal** for resource iteration
- **34 ResourceBankType values:** Visual, VisualSet, Animation, AnimationSet, Texture, Material, Physics, Effect, Script, Sound, Lighting, Atmosphere, AnimationBlueprint, MeshProxy, MaterialSet, BlendSpace, FCurve, Timeline, Dialog, VoiceBark, TileSet, IKRig, Skeleton, VirtualTexture, TerrainBrush, ColorList, CharacterVisual, MaterialPreset, SkinPreset, ClothCollider, DiffusionProfile, LightCookie, TimelineScene, SkeletonMirrorTable

### Bug Fix
- Fixed Lua stack index bug in `lua_resource_register()` - relative index must be converted to absolute before pushing new tables

### Files Added
- `src/resource/resource_manager.c` - Core resource manager implementation
- `src/resource/resource_manager.h` - Header with ResourceBankType enum
- `src/lua/lua_resource.c` - Lua bindings for Ext.Resource
- `src/lua/lua_resource.h` - Header
- `ghidra/offsets/RESOURCE.md` - Offset documentation

---

## [v0.36.1] - 2025-12-21

**Parity:** ~72% | **Category:** Template System | **Issues:** #41

### Added
- **Template Auto-Capture** - Templates now captured automatically via direct global pointer reads (no hooks needed)
  - `Ext.Template.IsReady()` - Returns true after lazy initialization
  - `Ext.Template.GetCount("Cache")` - Returns 61 templates
  - `Ext.Template.GetCount("LocalCache")` - Returns 19 templates
  - `Ext.Template.GetAllCacheTemplates()` - Iterate all cached templates with GUIDs
  - `Ext.Template.GetAllLocalCacheTemplates()` - Iterate local cache templates

### Technical
- **Global pointer offsets discovered via Ghidra:**
  - `GlobalTemplateManager::m_ptr` at `0x08a88508`
  - `CacheTemplateManager::m_ptr` at `0x08a309a8`
  - `Level::s_CacheTemplateManager` at `0x08a735d8`
- **CacheTemplateManagerBase structure:**
  - Value array (template pointers) at offset `+0x80`
  - Template count at offset `+0x98`
- **GameObjectTemplate GUID** at offset `+0x10` is a FixedString index, resolved via `fixed_string_resolve()`
- **Vtable validation** prevents crashes from invalid template pointers
- **Lazy initialization** - Global pointers are NULL at startup, retry on first API access

### Why Hooks Failed
ARM64 ADRP instruction at offset +0xC in `GetTemplateRaw` leaves only 8 bytes of safe prologue space (need 16 for absolute branch). Solution: Read singleton pointers directly instead of hooking.

### Files Modified
- `src/template/template_manager.c` - Global pointer offsets, iteration, GUID fix
- `src/lua/lua_template.c` - Simplified template-to-Lua conversion
- `ghidra/offsets/TEMPLATE.md` - Comprehensive structure documentation

---

## [v0.36.0] - 2025-12-20

**Parity:** ~72% | **Category:** Template System | **Issues:** #41

### Added
- **Ext.Template API Expansion** - Expanded from 12 to 14 functions with full property access
  - `GetAllLocalCacheTemplates()` - Returns templates from LocalCacheTemplates manager
  - `GetAllLocalTemplates()` - Returns templates from LocalTemplateManager

- **Template Property Expansion** - Templates now expose 10 properties (up from 4)
  | Property | Type | Description |
  |----------|------|-------------|
  | Guid | string | Template GUID |
  | TemplateId | string | Resolved template ID |
  | TemplateName | string | Resolved template name |
  | ParentTemplateId | string | Resolved parent template ID |
  | Type | string | Template type (Character, Item, etc.) |
  | RawType | string | Raw type from virtual function |
  | TemplateIdFs | integer | FixedString index for ID |
  | TemplateNameFs | integer | FixedString index for name |
  | ParentTemplateIdFs | integer | FixedString index for parent |
  | Handle | integer | Runtime template handle |

- **Template Type Detection** - `GetType()` now returns proper type names via virtual function call
  - Supported types: Character, Item, Scenery, Surface, Projectile, Decal, Trigger, Prefab, Light
  - Falls back to "Unknown" only for truly unrecognized types

### Technical
- Virtual function call for type detection: VMT[3] is GetType() on ARM64
- FixedString resolution via `fixed_string_resolve()` for string properties
- Safe memory reads with bounds checking for all property access
- Added `template_get_type_string()` for raw type access via virtual call

### Usage Example
```lua
-- Get a template with full properties
local tmpl = Ext.Template.Get("your-template-guid")
if tmpl then
    _P("Template: " .. (tmpl.TemplateName or "unnamed"))
    _P("Type: " .. tmpl.Type)
    _P("Parent: " .. (tmpl.ParentTemplateId or "none"))
end

-- Enumerate all local cache templates
for i, t in ipairs(Ext.Template.GetAllLocalCacheTemplates()) do
    _P(i .. ": " .. t.Guid .. " (" .. t.Type .. ")")
end
```

---

## [v0.35.0] - 2025-12-20

**Parity:** ~70% | **Category:** Entity Components | **Issues:** #33

### Added
- **Dynamic Array Support for Components** - Components with `Array<T>` fields now expose iterable Lua arrays
  - `entity.Tag.Tags` - Array of 16-byte GUIDs (category tags on entities)
  - `entity.Classes.Classes` - Array of ClassInfo with `ClassUUID`, `SubClassUUID`, `Level`
  - `entity.PassiveContainer.Passives` - Array of EntityHandle references
  - `entity.SpellBook.Spells` - Array of SpellData (88 bytes) with `SpellId`
  - `entity.SpellContainer.Spells` - Array of SpellMeta (80 bytes)
  - `entity.BoostsContainer.Boosts` - Array of BoostEntry with `Type`, `BoostCount`

- **ArrayProxy Userdata** - New Lua userdata type for dynamic arrays with full metamethod support
  - `__len` - Get array size with `#array`
  - `__index` - Access elements with 1-based indexing `array[1]`
  - `__pairs` / `__ipairs` - Standard Lua iteration
  - `__tostring` - Debug output `Array[22](0x12345678)`

- **New Element Types** for array marshaling:
  - `ELEM_TYPE_CLASS_INFO` - ClassInfo struct (40 bytes: 2× GUID + Level)
  - `ELEM_TYPE_BOOST_ENTRY` - BoostEntry struct (24 bytes: BoostType + nested Array)

### Technical
- `FIELD_TYPE_DYNAMIC_ARRAY` - New field type in ComponentPropertyDef
- `ArrayElementType` enum categorizes element types for proper marshaling
- Array memory layout: `buf_` (8 bytes) + `capacity_` (4 bytes) + `size_` (4 bytes)
- Safe memory reads with bounds checking and lifetime validation
- Element-specific field extraction (ClassUUID, SubClassUUID, Level, BoostType, etc.)

### Usage Example
```lua
local player = Ext.Entity.Get(GetHostCharacter())

-- Iterate tags
for i, tag in ipairs(player.Tag.Tags) do
    _P("Tag: " .. tag)  -- Prints GUID string
end

-- Access class info
for i, class in ipairs(player.Classes.Classes) do
    _P("Class: " .. class.ClassUUID .. " Level: " .. class.Level)
end

-- Check boost types
for i, boost in ipairs(player.BoostsContainer.Boosts) do
    _P("Boost Type " .. boost.Type .. " has " .. boost.BoostCount .. " entries")
end
```

---

## [v0.34.2] - 2025-12-20

**Parity:** ~68% | **Category:** StaticData | **Issues:** #40

### Fixed
- **Ext.StaticData.GetAll() now returns all entries** - Previously returned only 1 item, now correctly returns all feats (41 entries)
  - Root cause: `probe_for_real_manager()` searched within TypeContext metadata for wrong pattern
  - Fix: Rely on GetFeats hook to capture real FeatManager with correct structure
  - Real FeatManager uses flat array at +0x80 with count at +0x7C

### Technical
- Removed faulty probing logic from `capture_managers_via_typecontext()`
- TypeContext metadata provides type registration, not data access
- Real manager captured via hook when feat window is accessed
- Verified: GetAll, GetCount, and Get by GUID all working correctly

---

## [v0.34.1] - 2025-12-17

**Parity:** ~68% | **Category:** StaticData | **Issues:** #40

### Added
- **Auto-capture for Ext.StaticData** - Eliminates Frida requirement for basic StaticData access
  - `staticdata_post_init_capture()` - Automatic manager discovery at SessionLoaded
  - TypeContext traversal finds managers by name in ImmutableDataHeadmaster linked list
  - Real manager probing validates metadata pointers at multiple offsets
  - Frida capture as fallback if auto-capture fails
- **Ext.StaticData.TriggerCapture()** - Manual capture trigger for debugging

### Changed
- `Ext.StaticData.GetAll("Feat")` now works at main menu without Frida
- Post-init capture runs automatically after SessionLoaded event

### Technical
- Generic `looks_like_real_manager()` validates any manager type using ManagerConfig
- Generic `probe_for_real_manager()` searches metadata at offsets 0x08-0x78
- Safe memory reads via mach_vm_read prevent crashes on invalid pointers
- 3-phase capture: TypeContext → Probe metadata → Frida fallback

---

## [v0.34.0] - 2025-12-16

**Parity:** ~67% | **Category:** Hooks, StaticData | **Issues:** #44, #40

### Added
- **ARM64 Safe Hooking Infrastructure** - Complete skip-and-redirect hooking system for functions with ADRP+LDR prologues
  - `arm64_decode.h/c` - Full ARM64 instruction decoder with 20+ instruction types
  - `arm64_hook.h/c` - Safe hooking API: `arm64_safe_hook()`, `arm64_hook_at_offset()`, `arm64_unhook()`
  - `arm64_analyze_prologue()` - Detects PC-relative instruction patterns
  - Trampoline allocation within ±128MB for relative branches
- **Frida prologue analyzer** - `tools/frida/analyze_prologue.js` for runtime verification
- **ARM64_SAFE_HOOKING.md** - Comprehensive implementation documentation

### Changed
- **FeatManager::GetFeats now uses standard Dobby hook** - Frida analysis confirmed NO ADRP+LDR patterns in prologue
- `staticdata_manager.c` - Falls through to Dobby when prologue is safe (no PC-relative instructions)

### Fixed
- **Issue #40 unblocked** - StaticData can now hook FeatManager without ARM64 corruption
- Build errors: Added missing `#include <stddef.h>` and `#include <unistd.h>`
- Overlay console stability: prevent crashes when clicking overlay tabs by centralizing Lua dispatch on the tick thread (queue key events + overlay commands) and only submitting commands on Enter (not focus loss)

### Technical
- **Key Discovery**: FeatManager::GetFeats prologue is standard frame setup (STP x22,x21; STP x20,x19; STP x29,x30; ADD x29,sp,#32) - no ADRP patterns
- **ARM64 ADRP encoding**: 21-bit immediate encodes ±4GB PC-relative page offset
- **Skip-and-redirect strategy**: Hook AFTER safe instructions, let original prologue run in-place
- **Trampoline structure**: [skipped prologue] + [overwritten insn] + [branch back to target+N]

---

## [v0.33.0] - 2025-12-15

**Parity:** ~66% | **Category:** StaticData | **Issues:** #40

### Added
- **FixedString Name resolution** - Feat entries now include actual names (e.g., "Alert", "Actor", "AbilityScoreIncrease")
- **Type-specific capture loading** - `LoadFridaCapture("Race")`, `LoadFridaCapture("Origin")` etc.
- **Generic ManagerConfig infrastructure** - Per-type offsets for all resource types (Race, Origin, God, Class, Background)

### Changed
- `Ext.StaticData.GetAll("Feat")` now returns Name field in addition to ResourceUUID
- `LoadFridaCapture()` accepts optional type parameter (defaults to "Feat" for backwards compatibility)

### Technical
- **FixedString at offset +0x18** - Name field located after GuidResource base class (VMT + UUID = 24 bytes)
- **ManagerConfig struct** - Stores count_offset, array_offset, entry_size, name_offset, capture_file per type
- **Type-specific name offsets** - Race: +0x18, Origin: +0x1C, God: +0x18, Class: +0x28, Background: none (DisplayName only)

---

## [v0.32.9] - 2025-12-15

**Parity:** ~66% | **Category:** Template System | **Issues:** #41

### Added
- **Ext.Template API** - Game object template access via Frida capture workflow
  - `Ext.Template.Get(guid)` - Cascading template search
  - `Ext.Template.GetRootTemplate(guid)` - GlobalTemplateBank lookup
  - `Ext.Template.GetAllRootTemplates()` - List all root templates
  - `Ext.Template.GetCount([managerType])` - Get template counts
  - `Ext.Template.LoadFridaCapture()` - Load captured manager pointers
- **OriginalTemplateComponent** - ECS component for template GUID tracking (158 total components)
- **Template manager C implementation** - `src/template/template_manager.c` with Frida capture loading
- **Frida discovery script** - `tools/frida/discover_template_managers.js` for runtime template capture

### Technical
- **Same pattern as StaticData** - Frida runtime capture when symbols aren't exported
- **4-level template hierarchy** - GlobalTemplateBank → LocalTemplateManager → CacheTemplateManager → LocalCacheTemplates
- **GameObjectTemplate struct** - VMT, Tags, FixedString IDs, Handle at discovered offsets

---

## [v0.32.8] - 2025-12-15

**Parity:** ~65% | **Category:** Entity Components | **Issues:** #33

### Added
- **105 new tag component layouts** - Expanded from 52 to 157 components (201% increase!)
- **Automated tag component generation** - `tools/generate_tag_components.py` for batch TypeId extraction

**Client Components (ecl::) - 4 components:**
- Camera state tracking (CameraInSelectorMode, CameraSpellTracking)
- Animation flags (DummyIsCopyingFullPose, DummyLoaded)

**Common Components (eoc::) - 69 components:**
- Gameplay state: Player, SimpleCharacter, IsCharacter, IsInTurnBasedMode, IsInFTB, OffStage, PickingState
- Combat indicators: CombatDelayedFanfare, RollInProgress, Ambushing
- Progression: CanLevelUp, FTBPaused
- Environmental: IsFalling, GravityDisabled, CampPresence
- Healing: HealBlock, HealMaxIncoming, HealMaxOutgoing
- Inventory flags: CanBeWielded, CanBeInInventory, CannotBePickpocketed, CannotBeTakenOut, etc.
- Item properties: IsGold, IsDoor, IsItem, ItemInUse, NewInInventory, ItemCanMove, etc.
- Template flags: ClimbOn, Ladder, WalkOn, InteractionDisabled, IsStoryItem
- Tadpole states: Tadpoled, HalfIllithid, FullIllithid
- Character markers: Avatar, HasExclamationDialog, Trader
- Visibility: CanSeeThrough, CanShootThrough, CanWalkThrough

**Server Components (esv::) - 28 components:**
- Combat: ServerCanStartCombat, ServerFleeBlocked, ServerCombatLeaveRequest
- Visibility: ServerIsLightBlocker, ServerIsVisionBlocker, ServerDarknessActive
- Inventory: ServerInventoryIsReplicatedWith, ReadyToBeAddedToInventory
- Status: ServerStatusActive, ServerStatusAddedFromSaveLoad, ServerStatusAura
- Misc: ServerHotbarOrder, EscortHasStragglers, ServerDeathContinue

**Low-level Components (ls::) - 13 components:**
- Engine flags: IsGlobal, SavegameComponent, NetComponent
- Visual: VisualLoaded, AlwaysUpdateEffect, AnimationUpdate
- Level lifecycle: LevelIsOwner, LevelPrepareUnloadBusy, LevelUnloadBusy, LevelInstanceUnloading
- Pause: PauseComponent, PauseExcluded

### Technical
- **Tag components are zero-field** - Presence on entity IS the data (boolean flags)
- **No reverse engineering needed** - componentSize=0, properties=NULL
- **157 total components** - Massive jump from 52 (~8% parity for components)

---

## [v0.32.7] - 2025-12-14

**Parity:** ~60% | **Category:** Entity Components | **Issues:** #33

### Added
- **11 new component layouts** - Expanded from 41 to 52 components (batch acceleration)

**Combat Components:**
- `CombatParticipant` - CombatHandle, CombatGroupId, InitiativeRoll, Flags, AiHint
- `CombatState` - MyGuid (HashMaps skipped)

**Tag Components (presence = data):**
- `Avatar`, `Trader`, `CanLevelUp`, `IsGold`, `IsItem`, `IsDoor`, `IsFalling`, `IsInTurnBasedMode`, `GravityDisabled`

### Technical
- **Batch acceleration** - Tag components require no offset verification
- **52 total components** - Exceeds 50-component goal from Issue #33

---

## [v0.32.6] - 2025-12-14

**Parity:** ~58% | **Category:** Entity Components | **Issues:** #33

### Added
- **5 new component layouts** - Expanded from 36 to 41 components
  - `DeathState`, `DeathType`, `InventoryWeight`, `ThreatRange`, `IsInCombat`

---

## [v0.32.5] - 2025-12-14

**Parity:** ~57% | **Category:** Static Data, Debug API | **Issues:** #40

### Added
- **Ext.StaticData API (Foundation)** - New Lua namespace for immutable game data
- `Ext.StaticData.GetCount(type)` - Get count of entries (works for Feat: returns 37)
- `Ext.StaticData.GetTypes()` - List all supported type names
- `Ext.StaticData.IsReady(type)` - Check if manager is captured
- `Ext.StaticData.TryTypeContext()` - Debug: traverse ImmutableDataHeadmaster TypeInfo list
- Debug helpers: `DumpStatus()`, `DumpEntries()`, `Probe()`

### Added (Debug API)
- **Time utilities for RE sessions** - Correlate console commands with log timestamps
  - `Ext.Debug.Time()` - Current time as "HH:MM:SS"
  - `Ext.Debug.Timestamp()` - Unix timestamp (seconds)
  - `Ext.Debug.SessionStart()` - Time when BG3SE initialized
  - `Ext.Debug.SessionAge()` - Seconds since session started
  - `Ext.Debug.PrintTime(msg)` - Print with timestamp prefix
- **Pointer validation** - Safer memory probing for offset discovery
  - `Ext.Debug.IsValidPointer(addr)` - Check if address is readable
  - `Ext.Debug.ClassifyPointer(addr)` - Classify pointer type

### Known Limitations
- **GetAll() returns invalid GUIDs** - TypeContext gives registration metadata, not real manager data
- **GetFeats hooks disabled** - Hooks broke feat selection UI; root cause under investigation
- **Feat data access incomplete** - Count works (37), but individual feat entries need hook-based capture

### Technical Discoveries
- **TypeContext is metadata, not managers** - ImmutableDataHeadmaster TypeContext provides registration entries, not actual GuidResourceBank data
- **Real FeatManager structure** - count at +0x7C, array at +0x80 (from GetFeats @ `0x101b752b4`)
- **TypeContext structure** - count at +0x00, linked list pointer at +0x80 (NOT feat array)
- **m_State discovered**: ImmutableDataHeadmaster m_State at offset `0x083c4a68`
- **121 TypeInfo entries** scanned via linked list traversal

### Documentation
- Updated `agent_docs/development.md` with Debug API reference
- Updated `ghidra/offsets/STATICDATA.md` with structure findings

---

## [v0.32.4] - 2025-12-13

**Parity:** ~57% | **Category:** Stats System | **Issues:** #32

### Added
- **Full Stats Sync for created stats** - `Ext.Stats.Sync()` now works for both existing game stats AND newly created shadow stats
- **Shadow stat detection** - `stats_is_shadow_stat()` API for checking if a stat was created at runtime
- **FixedString interning** - `fixed_string_intern()` creates new FixedStrings via game's `ls::FixedString::Create`
- **RefMap insertion** - New prototypes can be inserted into prototype manager hash tables

### Fixed
- **SpellPrototype::Init crash** - Shadow stats now use template cloning (memcpy) instead of Init()
- **ARM64 const& calling convention** - Fixed crash by passing pointer (not value) to Init function
- **Prototype registration** - New spells properly registered with SpellPrototypeManager

### Technical
- **Shadow stats architecture**: Stats created via `Ext.Stats.Create()` exist in a separate registry, not in `RPGStats.Objects`. `Init()` can't find them, so we clone the template prototype instead.
- **SpellPrototype::Init** at `0x101f72754` - Populates prototype from stats object in RPGStats
- **FixedString::Create** at `0x1064b9ebc` - Game's function for interning new strings
- **RefMap hash** is `fs_key % capacity` (verified via Ghidra)
- **Two-path sync**: Shadow stats use memcpy clone, game stats use Init()

### Verified Working
```lua
-- Create and sync shadow spell
local spell = Ext.Stats.Create("MyTestSpell", "SpellData", "Projectile_FireBolt")
spell.Damage = "2d6"
Ext.Stats.Sync("MyTestSpell")  -- No crash, prototype registered

-- Create and sync shadow status
local status = Ext.Stats.Create("TestStatus", "StatusData", "BURNING")
Ext.Stats.Sync("TestStatus")   -- No crash, prototype registered

-- Sync existing game spell
Ext.Stats.Sync("Projectile_FireBolt")  -- Works for game stats too
```

---

## [v0.32.3] - 2025-12-12

**Parity:** ~55% | **Category:** Testing & Tooling | **Issues:** #8

### Added
- **`!test` console command** - Automated regression test suite (8 tests)
- **`Debug.*` helper library** - Preloaded Lua functions for reverse engineering
  - `Debug.ProbeRefMap(mgr, fs)` - Single-call RefMap lookup
  - `Debug.ProbeStructSpec(base, spec)` - Structured memory probing
  - `Debug.ProbeManager(mgr)` - Prototype manager inspection
  - `Debug.Hex(n)`, `Debug.HexMath(base, offset)` - Hex formatting
- **Script library system** - Reusable Lua scripts in `scripts/library/`
  - `probe_spell_refmap.lua` - SpellPrototypeManager probing
  - `dump_managers.lua` - All prototype manager states
  - `find_physics_scene.lua` - PhysicsScene discovery (Issue #37)
  - `test_audio_init.lua` - Wwise audio testing (Issue #38)
- **Frida scripts** for singleton capture
  - `capture_singletons.js` - Multi-target singleton capture
  - `capture_physics.js` - PhysicsScene capture for Issue #37
- **Meridian persona** - Reverse engineering approach documentation

### Changed
- Console command log now includes `!test`
- Global helpers log now includes `Debug.*`

### Documentation
- `agent_docs/meridian-persona.md` - RE persona with prompt template
- `plans/testing-advanced.md` - Full testing optimization plan
- Updated `tools/frida/README.md` with new scripts

---

## [v0.32.2] - 2025-12-12

**Parity:** ~55% | **Category:** Stats System | **Issues:** #32

### Added
- RefMap linear search implementation (hash function is non-trivial)
- ARM64 const& calling convention documentation

### Fixed
- **SpellPrototype::Init crash** - Fixed by passing FixedString as pointer (const& semantics)
- RefMap lookup now uses linear search after discovering hash function is proprietary

### Changed
- **`Ext.Stats.Sync()` fully working for existing spells** - Modify damage, costs, etc. and sync
- Stats modifications propagate to game prototypes without crashes

### Technical
- RefMap hash function is NOT `key % capacity` - FireBolt at FS=512753744 found in bucket 11798, not expected 7508
- ARM64 `const&` parameters must be passed as pointers: `Init(proto, &fs_key)` not `Init(proto, fs_key)`
- Linear search through ~5000 spell prototypes is sub-millisecond

### Verified Working
```lua
local spell = Ext.Stats.Get("Projectile_FireBolt")
spell.Damage = "3d10"
Ext.Stats.Sync("Projectile_FireBolt")  -- No crash, damage updated
```

---

## [v0.32.1] - 2025-12-12

**Parity:** ~54% | **Category:** Stats System | **Issues:** #32

### Added
- `eoc::SpellPrototype::Init` at `0x101f72754` - Populates prototype from stats object
- RefMap lookup implementation for prototype managers
- `sync_spell_prototype()` now calls SpellPrototype::Init on existing prototypes

### Changed
- **`Ext.Stats.Sync()` now functional for SpellData** - Modified spells re-sync with game
- Stats modifications to existing game spells now propagate to prototypes

### Technical
- Discovered SpellPrototype::Init via XREFs from ParseSpellAnimations
- RefMap structure documented: +0x08 buckets, +0x10 capacity, +0x18 next, +0x28 keys, +0x38 values
- Init function reads FixedString from stats object at offset +0x20

### Limitations
- Newly created (shadow) spells need RefMap insertion (not yet implemented)
- Status/Passive/Interrupt Init functions need discovery for those types

---

## [v0.32.0] - 2025-12-12

**Parity:** ~54% | **Category:** Stats System | **Issues:** #32

### Added
- Prototype managers infrastructure (`src/stats/prototype_managers.c/h`)
- **All 5 prototype manager singletons discovered:**
  - SpellPrototypeManager::m_ptr at `0x1089bac80`
  - StatusPrototypeManager::m_ptr at `0x1089bdb30`
  - PassivePrototypeManager at `0x108aeccd8`
  - InterruptPrototypeManager at `0x108aecce0`
  - BoostPrototypeManager at `0x108991528`
- Debug functions: `Ext.Stats.DumpPrototypeManagers()`, `ProbePrototypeManager()`, `GetPrototypeManagerPtrs()`
- Ghidra scripts: `analyze_get_spell_prototype.py`, `find_status_manager.py`

### Changed
- `Ext.Stats.Sync()` now calls all prototype managers
- Verified 16/21 component property layouts working via entity access

### Technical
- Ghidra offset discovery via ADRP+LDR pattern analysis
- GetSpellPrototype decompilation at `0x10346e740` revealed SpellPrototypeManager
- Ghidra symbol search revealed StatusPrototypeManager
- Runtime verification of manager instance pointers

---

## [v0.31.0] - 2025-12-11

**Parity:** ~53% | **Category:** Entity System | **Issues:** #33

### Added
- `Ext.Entity.GetByHandle()` for handle-based entity lookup
- 8 new component layouts: InventoryOwner, InventoryMember, InventoryIsOwned, Equipable, SpellContainer, Concentration, BoostsContainer, DisplayName

### Changed
- Component count: 28 → 36 layouts

---

## [v0.30.1] - 2025-12-11

**Parity:** ~52% | **Category:** Entity System | **Issues:** #33

### Added
- 9 new component layouts: Background, God, Value, TurnBased, SpellBook, StatusContainer, ActionResources, Weapon, InventoryContainer

### Changed
- Component count: 19 → 28 layouts

---

## [v0.30.0] - 2025-12-11

**Parity:** ~51% | **Category:** Events | **Issues:** #34

### Added
- `DoConsoleCommand` event with Prevent pattern
- `LuaConsoleInput` event with Prevent pattern

### Changed
- Event count: 8 → 10 events
- Documented combat/status events via Osiris listeners

---

## [v0.29.0] - 2025-12-10

**Parity:** ~50% | **Category:** Core | **Issues:** #28

### Added
- Userdata lifetime scoping system (`src/lifetime/lifetime.c/h`)
- LifetimePool (4096 entries) + LifetimeStack (64 nested scopes)

### Changed
- Entities, Components, StatsObjects validate lifetime on every access
- Stale objects show `[EXPIRED]` in `__tostring`

### Fixed
- Prevents use of stale userdata across scope boundaries

---

## [v0.28.0] - 2025-12-10

**Parity:** ~49% | **Category:** Variables

### Added
- `Ext.Vars.GetModVariables(uuid)` for global per-mod data
- Mod variable persistence to `modvars.json`
- Table-like access with iteration support

---

## [v0.27.0] - 2025-12-10

**Parity:** ~48% | **Category:** Variables | **Issues:** #13

### Added
- User variables via `entity.Vars`
- `Ext.Vars.RegisterUserVariable()` with Server/Persistent/SyncOnTick options
- `Ext.Vars.GetEntitiesWithVariable()`
- Persistence to `uservars.json`

---

## [v0.26.0] - 2025-12-10

**Parity:** ~47% | **Category:** Type System | **Issues:** #29

### Added
- `Ext.Enums` namespace with 14 enum/bitfield types
- Enum userdata: Label, Value, EnumName properties
- Bitfield userdata: __Labels, __Value, flag queries, bitwise operators
- Types: DamageType, AbilityId, SkillId, StatusType, SurfaceType, SpellSchoolId, WeaponType, ArmorType, ItemSlot, ItemDataRarity, SpellType, AttributeFlags, WeaponFlags, DamageFlags

---

## [v0.25.0] - 2025-12-10

**Parity:** ~45% | **Category:** Stats System | **Issues:** #27

### Added
- `Ext.Stats.Create(name, type, template)` - Create new stats
- `Ext.Stats.Sync(name)` - Mark stats as synced (placeholder)

---

## [v0.24.0] - 2025-12-10

**Parity:** ~43% | **Category:** Entity System

### Added
- Data-driven component property definitions
- 8 component layouts: Health, BaseHp, Armor, Stats, BaseStats, Transform, Level, Data

---

## [v0.23.0] - 2025-12-10

**Parity:** ~40% | **Category:** Entity/Osiris

### Added
- `entity.Health.Hp/MaxHp/TemporaryHp` property access
- `Ext.Osiris.RaiseEvent()` - Dispatch custom events
- `Ext.Osiris.GetCustomFunctions()` - Debug introspection

### Fixed
- ComponentTypeToIndex hash function (BG3-specific algorithm)

---

## [v0.22.0] - 2025-12-09

**Parity:** ~38% | **Category:** Osiris

### Added
- `Ext.Osiris.NewCall()` - Register custom Osiris calls
- `Ext.Osiris.NewQuery()` - Register custom Osiris queries
- `Ext.Osiris.NewEvent()` - Register custom Osiris events
- Signature parsing for Windows BG3SE format

---

## [v0.21.0] - 2025-12-09

**Parity:** ~36% | **Category:** Entity System

### Added
- `Ext.Entity.GetAllEntitiesWithComponent(name)` - Entity enumeration
- `Ext.Entity.CountEntitiesWithComponent(name)` - Entity counting

---

## [v0.20.0] - 2025-12-08

**Parity:** ~35% | **Category:** Core

### Added
- Structured logging system with 14 modules
- 4 log levels: DEBUG, INFO, WARN, ERROR
- Timestamps and consistent formatting

---

## [v0.19.0] - 2025-12-06

**Parity:** ~33% | **Category:** Console

### Added
- In-game console overlay (NSWindow)
- Tanit symbol with amber glow
- Ctrl+` hotkey toggle
- Command history with up/down arrows

---

## [v0.18.0] - 2025-12-06

**Parity:** ~31% | **Category:** Stats System

### Added
- Stats property write via `__newindex`
- `stat.Damage = "2d6"` modifies stats at runtime

---

## [v0.17.0] - 2025-12-06

**Parity:** ~29% | **Category:** Math

### Added
- `Ext.Math` library with 35 functions
- vec3/vec4/mat3/mat4 operations
- Transforms, decomposition, scalar functions

---

## [v0.16.0] - 2025-12-06

**Parity:** ~27% | **Category:** Input

### Added
- `Ext.Input` API with 8 macOS-specific functions
- CGEventTap keyboard capture
- Hotkey registration and key injection

---

## [v0.15.0] - 2025-12-06

**Parity:** ~25% | **Category:** Console

### Added
- Unix domain socket console (`/tmp/bg3se.sock`)
- Standalone readline client (`bg3se-console`)
- Real-time bidirectional I/O
- Up to 4 concurrent clients

---

## [v0.14.0] - 2025-12-06

**Parity:** ~23% | **Category:** Events

### Added
- `GameStateChanged` event with FromState/ToState
- Game state tracking module
- Event-based state inference for macOS

---

## [v0.13.0] - 2025-12-06

**Parity:** ~21% | **Category:** Events

### Added
- `Tick` event with DeltaTime
- `StatsLoaded` event
- `ModuleLoadStarted` event
- Priority ordering, Once flag, handler IDs
- `Ext.OnNextTick()` helper

---

## [v0.12.0] - 2025-12-06

**Parity:** ~19% | **Category:** Variables

### Added
- PersistentVars (file-based persistence)
- `Ext.Vars.SyncPersistentVars()`
- Auto-save every 30 seconds
- Per-mod isolation via ModTable

---

## [v0.11.0] - 2025-12-05

**Parity:** ~17% | **Category:** Timer/Debug/Stats

### Added
- `Ext.Timer` API: WaitFor, Cancel, Pause, Resume
- `Ext.Debug` APIs: ReadPtr, ProbeStruct, HexDump
- Stats property read via IndexedProperties + FixedStrings
- `RPGSTATS_OFFSET_FIXEDSTRINGS = 0x348`

---

## [v0.10.6] - 2025-12-03

**Parity:** ~15% | **Category:** Osiris

### Fixed
- Osiris function name caching via Signature indirection
- OsiFunctionDef structure (+0x08 is Line, not Name)

---

## [v0.10.4] - 2025-12-02

**Parity:** ~14% | **Category:** Entity System

### Added
- TypeId<T>::m_TypeIndex discovery
- ComponentTypeToIndex enumeration
- Lua bindings for runtime TypeId discovery

---

## [v0.10.3] - 2025-12-01

**Parity:** ~13% | **Category:** Entity System

### Added
- Data structure traversal for GetComponent
- TryGet + HashMap traversal (macOS-specific)

### Technical
- Discovered template calls don't work on macOS ARM64

---

## [v0.10.2] - 2025-12-01

**Parity:** ~12% | **Category:** Entity System

### Fixed
- GUID byte order (hi/lo swapped)
- Entity lookup now working

---

## [v0.10.1] - 2025-11-29

**Parity:** ~11% | **Category:** Osiris

### Added
- Function type detection (Query/Call/Event dispatch)
- 40+ pre-populated common functions

---

## [v0.10.0] - 2025-11-29

**Parity:** ~10% | **Category:** Entity System

### Added
- EntityWorld capture via LEGACY_IsInCombat hook
- GUID → EntityHandle lookup
- `Ext.Entity.Get()`, `IsReady()`, `GetHandle()`, `IsAlive()`

---

## [v0.9.9] - 2025-11-28

**Parity:** ~8% | **Category:** Osiris

### Added
- Dynamic `Osi.*` metatable
- Lazy function lookup via `__index`

---

## [v0.9.5] - 2025-11-28

**Parity:** ~6% | **Category:** Core

### Added
- Stable event observation
- MRC (More Reactive Companions) mod support

---

## [v0.9.0] - 2025-11-27

**Parity:** ~5% | **Category:** Core

### Added
- Initial Lua 5.4 runtime
- Basic `Ext.*` API structure
- DYLD injection working

---

## Legend

| Category | Description |
|----------|-------------|
| Core | Injection, logging, memory safety |
| Osiris | Osi.* namespace, event listeners |
| Entity System | Ext.Entity, components |
| Stats System | Ext.Stats, property access |
| Events | Ext.Events subscriptions |
| Variables | PersistentVars, User/Mod variables |
| Timer | Ext.Timer scheduling |
| Console | Debug console (socket/file/overlay) |
| Input | Ext.Input keyboard capture |
| Math | Ext.Math vector/matrix ops |
| Type System | Ext.Enums, type definitions |
