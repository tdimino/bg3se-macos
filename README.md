# BG3SE-macOS

**Baldur's Gate 3 Script Extender for macOS**

A native macOS implementation of the BG3 Script Extender, enabling mods that require scripting capabilities (like "More Reactive Companions") to work on Mac.

## Status

🎉 **MRC Mod Integration Working!** - SE mods load, execute, and receive real game data on macOS!

| Phase | Status | Notes |
|-------|--------|-------|
| DYLD Injection | ✅ Complete | Working via `open --env` launch method |
| Symbol Resolution | ✅ Complete | All 6/6 libOsiris symbols resolved |
| Function Hooking | ✅ Complete | Dobby inline hooking verified working |
| Lua Runtime | ✅ Complete | Lua 5.4 with Ext API |
| Mod Detection | ✅ Complete | Reads modsettings.lsx at startup |
| SE Mod Auto-Detection | ✅ Complete | Scans Config.json for "Lua" feature flag |
| PAK File Reading | ✅ Complete | Load scripts directly from .pak files |
| Ext.Require | ✅ Complete | Module loading from filesystem or PAK |
| Ext.Osiris | ✅ Complete | Event listener registration |
| Osiris Event Hook | ✅ Complete | COsiris::Event() hooked, 2000+ events captured |
| Osi.* Functions | ✅ Partial | Key functions return real data (see below) |
| Ghidra RE Analysis | ✅ Complete | Headless analysis for offset discovery |
| Function Enumeration | ✅ Complete | OsiFunctionMan offset-based lookup, function name caching |
| EntityWorld Capture | ✅ Complete | Direct memory read from `esv::EocServer::m_ptr` |
| GUID → Entity Lookup | ✅ Complete | ARM64 ABI fix for TryGetSingleton (see below) |
| TypeId Discovery | ✅ Complete | 11 component indices discovered at SessionLoaded |
| Component Access | 🔄 In Progress | Data structure traversal implemented, testing with discovered indices |

### Verified Working (Dec 3, 2025)

- ✅ Steam launch with injection via wrapper script
- ✅ Universal binary (ARM64 native + x86_64 Rosetta)
- ✅ Game runs natively on Apple Silicon with injection
- ✅ Game loads to main menu with injection active
- ✅ **Successfully loaded saved games with hooks active**
- ✅ 533 loaded images enumerated
- ✅ libOsiris.dylib symbol addresses resolved (6/6)
- ✅ **Dobby inline hooks intercepting `COsiris::Load` and `COsiris::Event` calls**
- ✅ **Hook return values properly preserved (game loads correctly)**
- ✅ **Lua 5.4 runtime initialized and executing scripts**
- ✅ **Ext API functions working (Print, GetVersion, IsClient, IsServer)**
- ✅ **Mod list detection from modsettings.lsx**
- ✅ **Auto-detection of SE mods via Config.json scanning**
- ✅ **PAK file reading - no extraction needed!**
- ✅ **Hooks triggering Lua callbacks on game events**
- ✅ **Ext.Require() loading mod modules (filesystem or PAK)**
- ✅ **Ext.Osiris.RegisterListener() registering event callbacks**
- ✅ **More Reactive Companions mod successfully loads!**
- ✅ **COsiris::Event() hook capturing 2000+ Osiris events per session**
- ✅ **Real player GUIDs discovered from events (6 party members)**
- ✅ **Dialog tracking from AutomatedDialogStarted/Ended events**
- ✅ **MRC mod receiving real game data and identifying dialog participants**
- ✅ **EntityWorld capture via direct memory read** (macOS Hardened Runtime workaround)
- ✅ **EoCServer singleton discovered at `esv::EocServer::m_ptr`** via Ghidra analysis
- ✅ **TryGetSingleton ARM64 ABI fix** - 64-byte ls::Result requires x8 register for indirect return
- ✅ **GUID → EntityHandle lookup working** - HashMap with 1873 entity GUIDs successfully queried
- ✅ **Ext.Entity Lua API registered and functional**
- ✅ **TypeId discovery with deferred retry** - 11 component indices discovered at SessionLoaded
- ✅ **Safe memory APIs** - Crash-safe memory reading via mach_vm_read
- ✅ **Function name caching** - Osiris function names extracted via Signature->Name indirection

## Compatibility

| Item | Version/Info |
|------|--------------|
| **BG3 Version** | 4.1.1.6995620 (tested Dec 2025) |
| **macOS** | 12+ (tested on macOS 15.6.1) |
| **Architecture** | ARM64 (Apple Silicon) - primary target |
| **Rosetta/Intel** | Builds but Ghidra offsets are ARM64-only |

**Note:** The Ghidra-derived memory offsets (for EntityWorld, component access, etc.) are specific to the ARM64 binary. Running under Rosetta (x86_64) will have limited functionality - only basic Osiris hooks and Lua runtime will work.

## Requirements

- macOS 12+ (tested on macOS 15.6.1)
- Apple Silicon Mac (for full functionality) or Intel Mac (limited)
- Baldur's Gate 3 (Steam version 4.1.1.6995620)
- Xcode Command Line Tools (`xcode-select --install`)
- CMake (`brew install cmake`) - for building Dobby

**For maintenance/RE work (optional):**
- Ghidra 11.x (`brew install ghidra` or download from ghidra-sre.org)
- Java 21 (`brew install openjdk@21`)

## Quick Start

### Build

```bash
cd bg3se-macos
./scripts/build.sh
```

This builds a universal binary supporting both ARM64 (native) and x86_64 (Rosetta). Dobby will be built automatically if not present.

### Install (Steam Launch)

The repo includes launcher scripts in `scripts/`:

| Script | Architecture | Use When |
|--------|--------------|----------|
| `bg3w.sh` | ARM64 (Apple Silicon) | **Recommended** - Full functionality |
| `bg3w-intel.sh` | x86_64 (Rosetta) | Intel Macs or troubleshooting |
| `launch_bg3.sh` | ARM64 | Direct terminal launch (no Steam) |

**Steam Setup (Apple Silicon - Recommended):**

1. Set Steam launch options for BG3:
```
/path/to/bg3se-macos/scripts/bg3w.sh %command%
```

4. Launch BG3 via Steam normally

See `scripts/*.example` files for reference wrapper scripts.

### Using SE Mods

SE mods work automatically - just install them like any other mod:

1. Download the mod's `.pak` file from Nexus Mods
2. Place it in `~/Documents/Larian Studios/Baldur's Gate 3/Mods/`
3. Enable the mod in the game's mod manager (or add to modsettings.lsx)
4. Launch the game and load a save

BG3SE-macOS reads scripts directly from PAK files - no extraction needed!

### Verify

Check `/tmp/bg3se_macos.log` for injection and mod loading logs:
```
=== BG3SE-macOS v0.11.0 ===
[timestamp] === BG3SE-macOS v0.11.0 initialized ===
[timestamp] Running in process: Baldur's Gate 3 (PID: XXXXX)
[timestamp] Architecture: ARM64 (Apple Silicon)
[timestamp] Dobby inline hooking: enabled
[timestamp] === Enabled Mods ===
[timestamp]   [1] GustavX (base game)
[timestamp]   [2] MoreReactiveCompanions_Configurable
[timestamp] Total mods: 2 (1 user mods)
[timestamp] ====================
[timestamp] === Scanning for SE Mods ===
[timestamp] [SE] Found SE mod MoreReactiveCompanions_Configurable in PAK: .../Mods/MoreReactiveCompanions_Configurable.pak
[timestamp]   [SE] MoreReactiveCompanions_Configurable
[timestamp] Total SE mods: 1
[timestamp] ============================
...
[timestamp] === Loading Mod Scripts ===
[timestamp] [Lua] Trying to load BootstrapServer.lua from PAK: .../MoreReactiveCompanions_Configurable.pak
[timestamp] [Lua] Loaded from PAK: Mods/.../BootstrapServer.lua
[timestamp] [Lua] HERE IN THE MOD
[timestamp] [Lua] Registered Osiris listener: AutomatedDialogStarted (arity=2, timing=before)
[timestamp] === Mod Script Loading Complete ===
```

## How It Works

BG3SE-macOS uses `DYLD_INSERT_LIBRARIES` to inject a dynamic library into the BG3 process at launch. This works because:

1. BG3 macOS has **no hardened runtime** (`flags=0x0`)
2. DYLD injection is allowed for non-hardened apps
3. libOsiris.dylib exports clean C/C++ symbols we can hook

### Key Discoveries

#### 1. Launch Method Matters

macOS apps must be launched as `.app` bundles via the `open` command:

| Method | Result |
|--------|--------|
| `exec "$APP/Contents/MacOS/Baldur's Gate 3"` | ❌ Crashes |
| `open -W "$APP"` | ✅ Works (but env not inherited) |
| `open -W --env "DYLD_INSERT_LIBRARIES=..." "$APP"` | ✅ Works perfectly |

#### 2. Environment Variable Inheritance

The `open` command does **not** inherit environment variables from the parent shell. You must use `open --env VAR=value` to pass environment variables to the launched application.

#### 3. Universal Binary Required

BG3 can run either natively (ARM64) or under Rosetta (x86_64). The `open --env` method launches natively on Apple Silicon, so our dylib must be a universal binary containing both architectures.

#### 4. Return Values Must Be Preserved

When hooking C++ member functions, the return value must be captured and returned from the hook. Failing to do so causes the game to fail silently (e.g., returning to main menu after load).

#### 5. ARM64 ABI for Large Struct Returns

Functions returning structs larger than 16 bytes on ARM64 use **indirect return** via the x8 register. The caller must:
1. Allocate a buffer for the return value
2. Pass the buffer address in x8 before calling
3. Read the result from the buffer after the call

BG3's `TryGetSingleton<T>` returns `ls::Result<ComponentPtr, ls::Error>` which is a 64-byte struct:

```c
typedef struct __attribute__((aligned(16))) {
    void* value;           // 0x00: Component pointer on success
    uint64_t reserved1;    // 0x08: Reserved
    uint64_t reserved2[4]; // 0x10-0x2F: Additional data
    uint8_t has_error;     // 0x30: Error flag (0=success, 1=error)
    uint8_t _pad[15];      // 0x31-0x3F: Padding
} LsResult;

// Correct ARM64 calling convention
void* call_with_x8_buffer(void* fn, void* arg) {
    LsResult result = {0};
    result.has_error = 1;
    __asm__ volatile (
        "mov x8, %[buf]\n"   // x8 = return buffer address
        "mov x0, %[arg]\n"   // x0 = function argument
        "blr %[fn]\n"        // call function
        : "+m"(result)
        : [buf] "r"(&result), [arg] "r"(arg), [fn] "r"(fn)
        : "x0", "x1", "x8", "x9", "x10", "x11", "x12", "x13",
          "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22",
          "x23", "x24", "x25", "x26", "x30", "memory"
    );
    return (result.has_error == 0) ? result.value : NULL;
}
```

This was discovered through Ghidra analysis of `TryGetSingleton` which saves x8 to x19 at entry (`mov x19, x8`) and writes the result via `stp x10, xzr, [x19]` and error flag via `strb w8, [x19, #0x30]`.

### Architecture

```
┌─────────────────────────────────────────────────┐
│                  BG3 Process                    │
├─────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌───────────────────────┐  │
│  │ libOsiris    │◄───│ BG3SE Hooks (Dobby)   │  │
│  │ (Scripting)  │    │ - COsiris::InitGame   │  │
│  └──────────────┘    │ - COsiris::Load       │  │
│                      └───────────────────────┘  │
│  ┌──────────────┐              ▲               │
│  │ Main Game    │              │               │
│  │ Executable   │    ┌─────────┴─────────┐    │
│  └──────────────┘    │  Lua Runtime       │    │
│                      │  (Mod Scripts)     │    │
│                      └───────────────────┘    │
└─────────────────────────────────────────────────┘
```

## Implemented APIs

### Ext Namespace

| API | Status | Description |
|-----|--------|-------------|
| `Ext.Print(...)` | ✅ Working | Print to BG3SE log |
| `Ext.GetVersion()` | ✅ Working | Returns version string |
| `Ext.IsClient()` | ✅ Working | Returns true |
| `Ext.IsServer()` | ✅ Working | Returns false |
| `Ext.Require(path)` | ✅ Working | Load Lua module relative to mod |
| `Ext.IO.LoadFile(path)` | ✅ Working | Read file contents |
| `Ext.IO.SaveFile(path, content)` | ✅ Working | Write file contents |
| `Ext.Json.Parse(json)` | ✅ Working | Parse JSON to Lua table |
| `Ext.Json.Stringify(table)` | ✅ Working | Convert Lua table to JSON |
| `Ext.Osiris.RegisterListener(event, arity, timing, callback)` | ✅ Working | Register Osiris event callback |
| `Ext.Entity.Get(guid)` | ✅ Working | Look up entity by GUID string |
| `Ext.Entity.IsReady()` | ✅ Working | Check if entity system ready |
| `entity.Transform` | ✅ Working | Get transform component (Position, Rotation, Scale) |
| `entity:GetComponent(name)` | ✅ Working | Get component by name (short or full) |
| `entity:IsAlive()` | ✅ Working | Check if entity is valid |
| `entity:GetHandle()` | ✅ Working | Get raw EntityHandle value |
| `Ext.Entity.DumpComponentRegistry()` | ✅ Working | Dump all registered components |
| `Ext.Entity.DumpStorage(handle)` | ✅ Working | Test TryGet and dump EntityStorageData |
| `Ext.Entity.DiscoverTypeIds()` | ✅ Working | Discover indices from TypeId globals |
| `Ext.Entity.DumpTypeIds()` | ✅ Working | Dump all known TypeId addresses |
| `Ext.Entity.RegisterComponent(name, idx, size)` | ✅ Working | Register discovered component |
| `Ext.Entity.LookupComponent(name)` | ✅ Working | Look up component info by name |
| `Ext.Entity.SetGetRawComponentAddr(addr)` | ✅ Working | Set GetRawComponent address from Frida |

### Ext.Stats Namespace (v0.11.0)

| API | Status | Description |
|-----|--------|-------------|
| `Ext.Stats.Get(name)` | ✅ Working | Get StatsObject by name |
| `Ext.Stats.GetAll(type?)` | ✅ Working | Get all stat names, optionally by type |
| `Ext.Stats.Create(name, type, template?)` | ✅ Working | Create new stat object |
| `Ext.Stats.Sync(name)` | ⚠️ Framework | Sync stat changes (framework exists) |
| `Ext.Stats.IsReady()` | ✅ Working | Check if stats system ready |
| `Ext.Stats.DumpTypes()` | ✅ Working | Print all stat types to log |
| `stat.Name` | ✅ Working | Read-only stat name |
| `stat.Type` | ✅ Working | Read-only stat type |
| `stat.Level` | ✅ Working | Read-only stat level |
| `stat.Using` | ✅ Working | Read-only parent stat |
| `stat:GetProperty(name)` | ✅ Working | Get property value |
| `stat:SetProperty(name, value)` | ✅ Working | Set property value |
| `stat:Dump()` | ✅ Working | Print stat contents to log |

### Ext.Events Namespace (v0.11.0)

| API | Status | Description |
|-----|--------|-------------|
| `Ext.Events.SessionLoading:Subscribe(cb)` | ✅ Working | Before save loads |
| `Ext.Events.SessionLoaded:Subscribe(cb)` | ✅ Working | After save loads |
| `Ext.Events.ResetCompleted:Subscribe(cb)` | ✅ Working | After reset command |
| `Ext.Events.GameStateChanged` | ❌ Not impl | Game state transitions |
| `Ext.Events.StatsLoaded` | ❌ Not impl | After stats loaded |
| `Ext.Events.Tick` | ❌ Not impl | Every game loop |

### Global Functions

| API | Status | Description |
|-----|--------|-------------|
| `_P(...)` | ✅ Working | Debug print (alias for Ext.Print) |
| `_D(value)` | ✅ Working | Debug dump (JSON for tables) |
| `GetHostCharacter()` | ✅ Working | Returns main player GUID (non-origin character) |

### Osi Namespace

Key Osiris functions now return real game data. Player GUIDs and dialog state are discovered by observing Osiris events.

| API | Status | Description |
|-----|--------|-------------|
| `Osi.DB_Players:Get(nil)` | ✅ Working | Returns real player GUIDs (discovered from events) |
| `Osi.IsTagged(char, tag)` | ✅ Working | Returns true for players in active dialog |
| `Osi.DialogGetNumberOfInvolvedPlayers(id)` | ✅ Working | Returns 1 (single-player) |
| `Osi.SpeakerGetDialog(char, idx)` | ✅ Working | Returns current dialog resource |
| `Osi.GetDistanceTo(char1, char2)` | ⏳ Stub | Always returns 0 |
| `Osi.DialogRequestStop(char)` | ⏳ Stub | No-op |
| `Osi.QRY_StartDialog_Fixed(res, char)` | ⏳ Stub | Returns false |

## File Structure

```
bg3se-macos/
├── src/
│   ├── core/                   # Core utilities
│   │   ├── logging.c/h         # Log output to /tmp/bg3se_macos.log
│   │   ├── safe_memory.c/h     # Crash-safe memory reading (mach_vm_read)
│   │   └── version.h           # Version constants
│   ├── entity/                 # Entity Component System (modular)
│   │   ├── entity_system.c/h   # Core ECS, EntityWorld capture, Lua bindings
│   │   ├── guid_lookup.c/h     # GUID parsing, HashMap operations
│   │   ├── arm64_call.c/h      # ARM64 ABI wrappers (x8 indirect return)
│   │   ├── component_registry.c/h  # Index-based component discovery & access
│   │   ├── component_lookup.c/h    # TryGet + HashMap traversal (macOS-specific)
│   │   ├── component_typeid.c/h    # TypeId<T>::m_TypeIndex discovery
│   │   └── entity_storage.h    # ECS structure definitions and offsets
│   ├── injector/               # Main injection logic (main.c)
│   ├── lua/                    # Lua API modules
│   │   ├── lua_ext.c/h         # Core Ext.* API (Print, Require, IO)
│   │   ├── lua_json.c/h        # Ext.Json.Parse/Stringify
│   │   ├── lua_osiris.c/h      # Ext.Osiris.RegisterListener
│   │   └── lua_stats.c/h       # Ext.Stats.* API (v0.11.0)
│   ├── mod/                    # Mod detection and loading
│   ├── osiris/                 # Osiris scripting engine
│   │   ├── osiris_functions.c/h # Function enumeration and caching
│   │   ├── osiris_types.h      # Osiris type definitions
│   │   └── pattern_scan.c/h    # Pattern-based symbol resolution
│   ├── pak/                    # PAK file reading (LSPK v18)
│   ├── stats/                  # RPGStats system (v0.11.0)
│   │   └── stats_manager.c/h   # RPGStats discovery and access
│   └── strings/                # String handling
│       └── fixed_string.c/h    # FixedString resolution
├── lib/
│   ├── fishhook/               # Symbol rebinding (for imported symbols)
│   ├── Dobby/                  # Inline hooking (for internal functions)
│   ├── lz4/                    # LZ4 decompression (for PAK file reading)
│   └── lua/                    # Lua 5.4 source and build scripts
├── ghidra/                     # Reverse engineering analysis
│   ├── scripts/                # 12+ Ghidra Python scripts for offset discovery
│   └── offsets/                # Modular offset documentation
│       ├── OSIRIS.md           # Osiris function offsets
│       ├── ENTITY_SYSTEM.md    # ECS architecture, EntityWorld
│       ├── COMPONENTS.md       # GetComponent addresses
│       ├── STATS.md            # RPGStats system offsets
│       ├── STATS_SYSTEM.md     # RPGStats global pointers
│       ├── GLOBAL_STRING_TABLE.md  # FixedString resolution
│       └── STRUCTURES.md       # C structure definitions
├── plans/                      # Implementation plans and analysis
│   └── bg3se-docs-gap-analysis.md  # Feature parity roadmap
├── scripts/
│   ├── build.sh                # Build script (universal binary)
│   ├── bg3w.sh                 # Steam launcher wrapper (ARM64)
│   └── *.example               # Example wrapper scripts
├── tools/
│   ├── automation/             # Claude Code MCP configs & skills
│   ├── frida/                  # Frida scripts for runtime analysis
│   └── extract_pak.py          # BG3 PAK file extractor (Python)
├── build/
│   └── lib/
│       └── libbg3se.dylib      # Built dylib (universal: arm64 + x86_64)
├── CLAUDE.md                   # Development guide for Claude Code
├── ROADMAP.md                  # Feature parity tracking (~30%)
└── README.md
```

## Technical Details

### Why This Works

| Factor | Value |
|--------|-------|
| Hardened Runtime | `flags=0x0` (none) |
| Code Signing | Developer ID signed, but not hardened |
| DYLD Injection | Allowed |
| libOsiris Exports | 1,013 symbols |

### Hooking Strategy

- **Dobby**: Inline hooking for internal library functions (C++ methods)
- **fishhook**: Available for imported symbols (PLT/GOT rebinding) if needed

Osiris functions like `COsiris::Load`, `COsiris::InitGame`, etc. are internal to `libOsiris.dylib`, requiring inline hooking via Dobby.

### Pattern Scanning (Cross-Version Support)

BG3SE-macOS includes a pattern scanning infrastructure for resilience across game updates:

- **Pattern Database**: Unique ARM64 byte sequences for key Osiris functions
- **Fallback Resolution**: If `dlsym` fails, pattern scanning locates functions by signature
- **Mach-O Support**: Scans `__TEXT,__text` section of loaded dylibs

Example patterns (BG3 Patch 7):
```
InternalQuery: FD 43 04 91 F3 03 01 AA 15 90 01 51 ...
InternalCall:  F3 03 00 AA 28 20 00 91 09 04 00 51 ...
```

When Larian updates the game, if symbol names change but function code remains similar, pattern scanning can still locate the functions.

### Key libOsiris Symbols

```
_DebugHook                      - Debug interface
_CreateRule                     - Script rule creation
_DefineFunction                 - Function registration
_SetInitSection                 - Initialization hook
_ZN7COsiris8InitGameEv          - COsiris::InitGame()
_ZN7COsiris4LoadER12COsiSmartBuf - COsiris::Load(COsiSmartBuf&)
```

## Test Mod

We maintain a custom test mod for validating BG3SE-macOS functionality. See [tools/test-mods/README.md](tools/test-mods/README.md) for details.

**Quick Start:**
```bash
# Copy test mod to auto-detection path
cp -r tools/test-mods/EntityTest /tmp/EntityTest_extracted

# Launch game - mod loads automatically
./scripts/bg3w.sh  # or via Steam

# Watch for test output
tail -f /tmp/bg3se_macos.log | grep EntityTest
```

The EntityTest mod validates:
- Entity system initialization (`Ext.Entity.IsReady()`)
- GUID → Entity lookup (`Ext.Entity.Get()`)
- Component access (`entity.Transform`, `entity:GetComponent()`)
- Session lifecycle events (`SessionLoaded`)

## Tools

### Automated Testing (Claude Code)

The `tools/automation/` folder contains MCP server configs and a Claude Code skill for automated BG3 testing:

```bash
# Install MCP servers
claude mcp add macos-automator -- npx -y @steipete/macos-automator-mcp@latest
claude mcp add peekaboo -- npx -y @steipete/peekaboo-mcp@beta

# Copy skill
cp -r tools/automation/skills/bg3-steam-launcher ~/.claude/skills/
```

Then use `skill: "bg3-steam-launcher"` in Claude Code to automate launching BG3, loading saves, and checking SE logs.

### PAK Extractor

A Python tool to extract BG3 mod `.pak` files (LSPK v18 format):

```bash
# Install dependency
pip3 install lz4

# Extract a mod
python3 tools/extract_pak.py path/to/mod.pak [output_dir]
```

This is useful for examining mod structure and Lua scripts. Note: BG3SE-macOS now reads PAK files directly, so extraction is only needed for debugging.

## Roadmap

See [GitHub Issues](https://github.com/tdimino/bg3se-macos/issues) for detailed task tracking.

### Critical Priority (Most Mods Need These)

1. **[#11 - Ext.Events API](https://github.com/tdimino/bg3se-macos/issues/11)** - Engine lifecycle events (⚠️ 3/10+ events implemented)
2. **[#12 - PersistentVars](https://github.com/tdimino/bg3se-macos/issues/12)** - Savegame data persistence
3. **[#13 - Ext.Vars](https://github.com/tdimino/bg3se-macos/issues/13)** - Entity-attached custom data with sync
4. **[#3 - Stats System](https://github.com/tdimino/bg3se-macos/issues/3)** - Full property read/write (⚠️ 60% complete)

### High Priority

- **[#14 - Timer API](https://github.com/tdimino/bg3se-macos/issues/14)** - Delayed/repeating callbacks
- **[#15 - Client Lua State](https://github.com/tdimino/bg3se-macos/issues/15)** - Dual client/server Lua states
- **[#5 - Debug Console](https://github.com/tdimino/bg3se-macos/issues/5)** - In-game Lua REPL

### Future Phases

- **[#4 - Custom Osiris Functions](https://github.com/tdimino/bg3se-macos/issues/4)** - Register functions callable from story scripts
- **[#6 - Networking API](https://github.com/tdimino/bg3se-macos/issues/6)** - Multiplayer mod state sync (NetChannel)
- **[#16 - Ext.Math Library](https://github.com/tdimino/bg3se-macos/issues/16)** - Vector/matrix operations
- **[#7 - Type System](https://github.com/tdimino/bg3se-macos/issues/7)** - IDE integration and autocomplete
- **[#8 - Technical Debt](https://github.com/tdimino/bg3se-macos/issues/8)** - Stability, testing, documentation

### Completed

- ✅ **[#10 - Osiris Function Name Caching](https://github.com/tdimino/bg3se-macos/issues/10)** - Fixed funcDef->Signature->Name indirection (v0.10.6)
- ✅ **[#2 - Component Discovery](https://github.com/tdimino/bg3se-macos/issues/2)** - TypeId discovery with deferred retry (v0.10.5)
- ✅ **[#1 - TryGetSingleton ARM64 ABI fix](https://github.com/tdimino/bg3se-macos/issues/1)** - GUID → EntityHandle lookup working (v0.10.3)
- ✅ EntityWorld capture via direct memory read - bypasses Hardened Runtime (v0.10.2)
- ✅ Entity/Component System - Ext.Entity API, component accessors (v0.10.0)
- ✅ Ghidra headless RE analysis - discovered OsiFunctionMan offset (v0.9.8)
- ✅ Offset-based symbol resolution for unexported symbols (v0.9.8)
- ✅ Function enumeration via pFunctionData (v0.9.8)
- ✅ Direct Osiris query/call wrappers - real Osi.* function calls (v0.9.4)
- ✅ ARM64 pattern database with fallback symbol resolution (v0.9.3)
- ✅ Pattern scanning infrastructure for cross-version compatibility (v0.9.3)
- ✅ Real Osiris bindings via event observation (v0.9.2)
- ✅ COsiris::Event() hook with callback dispatch (v0.9.1)
- ✅ PAK file reading - load scripts directly from .pak files (v0.9.0)
- ✅ Auto-detection of SE mods via Config.json scanning (v0.8.0)

## Troubleshooting

### Injection Not Working

1. Check `/tmp/bg3se_macos.log` for errors
2. Verify the dylib is built: `file build/lib/libbg3se.dylib`
3. Ensure it's universal: should show both `x86_64` and `arm64`
4. Ensure wrapper uses `open --env` (not just `export`)

### Game Crashes at Launch

1. Make sure wrapper script uses `open -W --env "DYLD_INSERT_LIBRARIES=..." "$1"`
2. Verify dylib is universal binary (check with `file` command)
3. Try running without injection: clear Steam launch options
4. Check Console.app for crash reports

### Game Returns to Menu After Loading

If the game loads but immediately returns to the main menu:
1. This usually means a hook isn't preserving the return value
2. Check that hooked functions return the original function's return value
3. Review `/tmp/bg3se_macos.log` for hook call/return messages

### Mod Not Loading

1. Ensure the mod is enabled in modsettings.lsx (use in-game mod manager or BG3 Mod Manager)
2. Ensure the mod's `.pak` file is in `~/Documents/Larian Studios/Baldur's Gate 3/Mods/`
3. Check that the mod has `ScriptExtender/Config.json` with `"Lua"` in FeatureFlags
4. Check that the path structure inside PAK is: `Mods/<ModName>/ScriptExtender/Lua/BootstrapServer.lua`
5. Review the log for "Scanning for SE Mods" and "Loading Mod Scripts" sections
6. For debugging, extract with `tools/extract_pak.py` to inspect mod structure

### Architecture Mismatch Error

If you see "incompatible architecture" in crash reports:
1. Rebuild with `./scripts/build.sh` (creates universal binary)
2. Verify with: `file build/lib/libbg3se.dylib`
3. Should show: `Mach-O universal binary with 2 architectures: [x86_64] [arm64]`

## Maintenance

When BG3 updates:

1. Run `nm -gU` on the new libOsiris.dylib to check exported symbols
2. If offsets have changed, re-run Ghidra headless analysis:

```bash
# For the 1GB+ BG3 binary, use the optimized workflow with prescript
JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
~/ghidra/support/analyzeHeadless ~/ghidra_projects BG3Analysis \
  -process BG3_arm64_thin \
  -scriptPath /path/to/bg3se-macos/ghidra/scripts \
  -preScript optimize_analysis.py \
  -postScript quick_component_search.py

# The prescript disables slow analyzers (Stack, Decompiler Parameter ID, etc.)
# that would cause analysis to hang on large binaries.
# The postscript finds XREFs to component strings for GetComponent discovery.
```

For libOsiris.dylib (smaller binary), the standard workflow works:

```bash
# Extract ARM64 slice from universal binary
lipo -thin arm64 \
  "/Users/$USER/Library/Application Support/Steam/steamapps/common/Baldurs Gate 3/Baldur's Gate 3.app/Contents/Frameworks/libOsiris.dylib" \
  -output ~/ghidra_projects/libOsiris_arm64_thin.dylib

# Run Ghidra headless analysis
JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
~/ghidra/support/analyzeHeadless \
  ~/ghidra_projects BG3Analysis \
  -import ~/ghidra_projects/libOsiris_arm64_thin.dylib \
  -processor "AARCH64:LE:64:v8A" \
  -postScript ghidra/scripts/find_osiris_offsets.py \
  -analysisTimeoutPerFile 300
```

3. Update offsets in `src/injector/main.c`:
   - `OSIFUNCMAN_OFFSET` - `_OsiFunctionMan` global variable
   - `PFUNCTIONDATA_OFFSET` - `COsiFunctionMan::pFunctionData()` method
   - `COSIRIS_EVENT_OFFSET` - `COsiris::Event()` method
   - `COSIRIS_INITGAME_OFFSET` - `COsiris::InitGame()` method

4. Rebuild and test

## License

MIT License

## Authors

- Tom di Mino (the artist formerly known as [Pnutmaster](https://wiki.twcenter.net/index.php?title=Blood_Broads_%26_Bastards) / [Nexus](https://next.nexusmods.com/profile/Pnutmaster/mods?gameId=130))
- [Claude Code](https://claude.ai/claude-code) (Anthropic)

## Acknowledgments

### Special Thanks

This project would not be possible without **[Norbyte](https://github.com/Norbyte)** and their pioneering work on the original [BG3 Script Extender](https://github.com/Norbyte/bg3se) for Windows. Their reverse engineering of Larian's Osiris scripting engine, comprehensive API design, and years of dedication to the modding community laid the foundation that made this macOS port conceivable. We are deeply grateful for their open-source contribution to the BG3 modding ecosystem.

### Credits

- [Norbyte's BG3SE](https://github.com/Norbyte/bg3se) - The original Windows Script Extender
- [Dobby](https://github.com/jmpews/Dobby) - Inline hooking framework for ARM64/x86_64
- [fishhook](https://github.com/facebook/fishhook) - Symbol rebinding library
- [LZ4](https://github.com/lz4/lz4) - Fast compression for PAK file reading
- Test mod: [More Reactive Companions](https://www.nexusmods.com/baldursgate3/mods/5447) by LightningLarryL

## Support This Project

If BG3SE-macOS has helped you enjoy mods on your Mac, consider buying me a matcha:

[![PayPal](https://img.shields.io/badge/PayPal-Donate-blue?logo=paypal)](https://www.paypal.com/donate?business=contact@tomdimino.com&currency_code=USD)

Donations help fund continued development, testing across game updates, and expanding mod compatibility. Every contribution is appreciated!

### P.S.

I also want to extend my thanks to the OP and commenters of this BG3SE issue: **["[Feature Bounty - $350] MacOS Supported Version of BG3 SE"](https://github.com/Norbyte/bg3se/issues/162)**. You kicked off the quest :)
