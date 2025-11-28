# BG3SE-macOS

**Baldur's Gate 3 Script Extender for macOS**

A native macOS implementation of the BG3 Script Extender, enabling mods that require scripting capabilities (like "More Reactive Companions") to work on Mac.

## Status

🚧 **Work in Progress** - Lua Runtime Working!

| Phase | Status | Notes |
|-------|--------|-------|
| DYLD Injection | ✅ Complete | Working via `open --env` launch method |
| Symbol Resolution | ✅ Complete | All 6/6 libOsiris symbols resolved |
| Function Hooking | ✅ Complete | Dobby inline hooking verified working |
| Lua Runtime | ✅ Complete | Lua 5.4 with Ext API |
| Mod Detection | ✅ Complete | Reads modsettings.lsx at startup |
| Mod Compatibility | ⏳ Pending | Target: More Reactive Companions |

### Verified Working (Nov 27, 2025)

- ✅ Steam launch with injection via wrapper script
- ✅ Universal binary (ARM64 native + x86_64 Rosetta)
- ✅ Game runs natively on Apple Silicon with injection
- ✅ Game loads to main menu with injection active
- ✅ **Successfully loaded saved games with hooks active**
- ✅ 533 loaded images enumerated
- ✅ libOsiris.dylib symbol addresses resolved (6/6)
- ✅ **Dobby inline hooks intercepting `COsiris::Load` calls**
- ✅ **Hook return values properly preserved (game loads correctly)**
- ✅ **Lua 5.4 runtime initialized and executing scripts**
- ✅ **Ext API functions working (Print, GetVersion, IsClient, IsServer)**
- ✅ **Mod list detection from modsettings.lsx**
- ✅ **Hooks triggering Lua callbacks on game events**

## Requirements

- macOS 12+ (tested on macOS 15.6.1)
- Apple Silicon or Intel Mac
- Baldur's Gate 3 (Steam version)
- Xcode Command Line Tools (`xcode-select --install`)
- CMake (`brew install cmake`) - for building Dobby

## Quick Start

### Build

```bash
cd bg3se-macos
./scripts/build.sh
```

This builds a universal binary supporting both ARM64 (native) and x86_64 (Rosetta). Dobby will be built automatically if not present.

### Install

1. Create wrapper script `/tmp/bg3w.sh`:

```bash
#!/bin/bash
DYLIB_PATH="/path/to/bg3se-macos/build/lib/libbg3se.dylib"
exec open -W --env "DYLD_INSERT_LIBRARIES=$DYLIB_PATH" "$1"
```

2. Make executable:
```bash
chmod +x /tmp/bg3w.sh
```

3. Set Steam launch options for BG3:
```
/tmp/bg3w.sh %command%
```

4. Launch BG3 via Steam normally

See `scripts/*.example` files for reference wrapper scripts.

### Verify

Check `/tmp/bg3se_macos.log` for injection logs:
```
=== BG3SE-macOS v0.5.0 ===
[timestamp] === BG3SE-macOS v0.5.0 initialized ===
[timestamp] Running in process: Baldur's Gate 3 (PID: XXXXX)
[timestamp] Architecture: ARM64 (Apple Silicon)
[timestamp] Dobby inline hooking: enabled
[timestamp] === Enabled Mods ===
[timestamp]   [1] GustavX (base game)
[timestamp]   [2] YourMod1
[timestamp]   [3] YourMod2
[timestamp] Total mods: 3 (2 user mods)
[timestamp] ====================
[timestamp] Initializing Lua runtime...
[timestamp] [Lua] BG3SE-macOS Lua runtime initialized!
[timestamp] [Lua] Version: 0.5.0
[timestamp] Found 6/6 key Osiris symbols
[timestamp] Hooks installed: 2/2
...
[timestamp] >>> COsiris::Load called! (count: 1, this: 0x..., buf: 0x...)
[timestamp] >>> COsiris::Load returned: 1
[timestamp] [Lua] Story/save data loaded!
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

## File Structure

```
bg3se-macos/
├── src/
│   └── injector/
│       └── main.c              # Entry point, hooks, Lua runtime & Ext API
├── lib/
│   ├── fishhook/               # Symbol rebinding (for imported symbols)
│   ├── Dobby/                  # Inline hooking (for internal functions)
│   └── lua/                    # Lua 5.4 source and build scripts
│       ├── src/                # Lua 5.4.7 source code
│       └── build_universal.sh  # Builds universal static library
├── scripts/
│   ├── build.sh                # Build script (universal binary)
│   ├── bg3-wrapper.sh.example  # Example Steam wrapper
│   ├── launch_bg3.sh.example   # Example direct launcher
│   └── launch_via_steam.sh.example  # Example Steam setup helper
├── tools/
│   └── extract_pak.py          # BG3 PAK file extractor (Python)
├── build/
│   └── lib/
│       └── libbg3se.dylib      # Built dylib (universal: arm64 + x86_64)
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

### Key libOsiris Symbols

```
_DebugHook                      - Debug interface
_CreateRule                     - Script rule creation
_DefineFunction                 - Function registration
_SetInitSection                 - Initialization hook
_ZN7COsiris8InitGameEv          - COsiris::InitGame()
_ZN7COsiris4LoadER12COsiSmartBuf - COsiris::Load(COsiSmartBuf&)
```

### Sample Log Output (v0.5.0)

```
=== BG3SE-macOS v0.5.0 ===
Injection timestamp: 1764288141
Process ID: 53033
[2025-11-27 19:02:21] === BG3SE-macOS v0.5.0 initialized ===
[2025-11-27 19:02:21] Running in process: Baldur's Gate 3 (PID: 53033)
[2025-11-27 19:02:21] Architecture: ARM64 (Apple Silicon)
[2025-11-27 19:02:21] Dobby inline hooking: enabled
[2025-11-27 19:02:21] === Enabled Mods ===
[2025-11-27 19:02:21]   [1] GustavX (base game)
[2025-11-27 19:02:21]   [2] LIX_OriginDialogTags
[2025-11-27 19:02:21]   [3] Facial Animations
[2025-11-27 19:02:21]   [4] ACT1 Capes and Cloaks
[2025-11-27 19:02:21]   [5] Better Inventory UI
[2025-11-27 19:02:21]   [6] HT_Camp Event Overhaul
[2025-11-27 19:02:21]   [7] IN_Core_1_03
[2025-11-27 19:02:21] Total mods: 7 (6 user mods)
[2025-11-27 19:02:21] ====================
[2025-11-27 19:02:21] Initializing Lua runtime...
[2025-11-27 19:02:21] Ext API registered in Lua
[2025-11-27 19:02:21] [Lua] BG3SE-macOS Lua runtime initialized!
[2025-11-27 19:02:21] [Lua] Version: 0.5.0
[2025-11-27 19:02:21] [Lua] IsClient: true
[2025-11-27 19:02:21] [Lua] IsServer: false
[2025-11-27 19:02:21] Lua Lua 5.4 initialized
[2025-11-27 19:02:21] Found 6/6 key Osiris symbols
[2025-11-27 19:02:21] Installing Dobby hooks...
[2025-11-27 19:02:21]   COsiris::InitGame hooked successfully (orig: 0x110e08000)
[2025-11-27 19:02:21]   COsiris::Load hooked successfully (orig: 0x110e08020)
[2025-11-27 19:02:21] Hooks installed: 2/2
[2025-11-27 19:02:45] >>> COsiris::Load called! (count: 1, this: 0x600019f34080, buf: 0x44d5ea098)
[2025-11-27 19:02:45] >>> COsiris::Load returned: 1
[2025-11-27 19:02:45] [Lua] Story/save data loaded!
```

## Target Mod

Primary goal: Enable **"More Reactive Companions"** to work on macOS.

**Test Mod:** [More Reactive Companions (Configurable)](https://www.nexusmods.com/baldursgate3/mods/5447) by [LightningLarryL](https://next.nexusmods.com/profile/LightningLarryL?gameId=3474)

This mod redirects ambient party dialogue to random nearby companions instead of always using the player character, making the party feel more alive. It requires Script Extender APIs and serves as our primary compatibility target.

### Required SE APIs

| API | Status | Notes |
|-----|--------|-------|
| `Ext.Require()` | ⏳ Stub | Module loading |
| `Ext.IO.LoadFile()` | ✅ Done | File reading |
| `Ext.Json.Parse()` | ✅ Done | JSON parsing |
| `Ext.Json.Stringify()` | ✅ Done | JSON serialization |
| `_P()` / `_D()` | ✅ Done | Debug print/dump |
| `Ext.Osiris.RegisterListener()` | ⏳ Pending | Event hooks |
| `Osi.*` functions | ⏳ Pending | Osiris bindings |

## Tools

### PAK Extractor

A Python tool to extract BG3 mod `.pak` files (LSPK v18 format):

```bash
# Install dependency
pip3 install lz4

# Extract a mod
python3 tools/extract_pak.py path/to/mod.pak [output_dir]
```

This is useful for examining mod structure and Lua scripts.

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

### Architecture Mismatch Error

If you see "incompatible architecture" in crash reports:
1. Rebuild with `./scripts/build.sh` (creates universal binary)
2. Verify with: `file build/lib/libbg3se.dylib`
3. Should show: `Mach-O universal binary with 2 architectures: [x86_64] [arm64]`

## Maintenance

When BG3 updates:

1. Run `nm -gU` on the new libOsiris.dylib
2. Compare with previous symbol addresses
3. Update any hardcoded offsets
4. Rebuild and test

## License

MIT License

## Credits

- Inspired by [Norbyte's BG3SE](https://github.com/Norbyte/bg3se)
- [Dobby](https://github.com/jmpews/Dobby) - Inline hooking framework
- [fishhook](https://github.com/facebook/fishhook) - Symbol rebinding library
