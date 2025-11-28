# BG3SE-macOS

**Baldur's Gate 3 Script Extender for macOS**

A native macOS implementation of the BG3 Script Extender, enabling mods that require scripting capabilities (like "More Reactive Companions") to work on Mac.

## Status

🎉 **Mod Loading Working!** - SE mods now load and execute on macOS!

| Phase | Status | Notes |
|-------|--------|-------|
| DYLD Injection | ✅ Complete | Working via `open --env` launch method |
| Symbol Resolution | ✅ Complete | All 6/6 libOsiris symbols resolved |
| Function Hooking | ✅ Complete | Dobby inline hooking verified working |
| Lua Runtime | ✅ Complete | Lua 5.4 with Ext API |
| Mod Detection | ✅ Complete | Reads modsettings.lsx at startup |
| Ext.Require | ✅ Complete | Module loading from mod directories |
| Ext.Osiris | ✅ Complete | Event listener registration |
| Osi.* Functions | ⏳ Stubs | Osiris bindings (stubs only) |

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
- ✅ **Ext.Require() loading mod modules**
- ✅ **Ext.Osiris.RegisterListener() registering event callbacks**
- ✅ **More Reactive Companions mod successfully loads!**

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

### Testing SE Mods (Current Method)

Until PAK reading is implemented, extract SE mods manually:

```bash
# Extract a mod's PAK file
python3 tools/extract_pak.py path/to/ModName.pak /tmp/ModName_extracted

# The mod will be loaded from /tmp/ModName_extracted/Mods/ModName/ScriptExtender/Lua/
```

### Verify

Check `/tmp/bg3se_macos.log` for injection and mod loading logs:
```
=== BG3SE-macOS v0.7.0 ===
[timestamp] === BG3SE-macOS v0.7.0 initialized ===
[timestamp] Running in process: Baldur's Gate 3 (PID: XXXXX)
[timestamp] Architecture: ARM64 (Apple Silicon)
[timestamp] Dobby inline hooking: enabled
[timestamp] === Enabled Mods ===
[timestamp]   [1] GustavX (base game)
[timestamp]   [2] YourMod1
[timestamp] Total mods: 2 (1 user mods)
[timestamp] ====================
[timestamp] Initializing Lua runtime...
[timestamp] Ext API registered in Lua
[timestamp] Ext.Osiris API registered
[timestamp] Osi namespace registered (stubs)
[timestamp] [Lua] BG3SE-macOS Lua runtime initialized!
...
[timestamp] >>> COsiris::Load called! (count: 1, this: 0x..., buf: 0x...)
[timestamp] >>> COsiris::Load returned: 1
[timestamp] [Lua] Story/save data loaded!
[timestamp] === Loading Mod Scripts ===
[timestamp] [Lua] Ext.Require('Server/YourMod.lua')
[timestamp] [Lua] HERE IN THE MOD
[timestamp] [Lua] Registered Osiris listener: SomeEvent (arity=2, timing=before)
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

### Global Functions

| API | Status | Description |
|-----|--------|-------------|
| `_P(...)` | ✅ Working | Debug print (alias for Ext.Print) |
| `_D(value)` | ✅ Working | Debug dump (JSON for tables) |
| `GetHostCharacter()` | ⏳ Stub | Returns placeholder UUID |

### Osi Namespace (Stubs)

These functions are registered but return placeholder values. Real Osiris integration is planned.

| API | Status | Description |
|-----|--------|-------------|
| `Osi.IsTagged(char, tag)` | ⏳ Stub | Always returns false |
| `Osi.GetDistanceTo(char1, char2)` | ⏳ Stub | Always returns 0 |
| `Osi.DialogGetNumberOfInvolvedPlayers(id)` | ⏳ Stub | Always returns 1 |
| `Osi.SpeakerGetDialog(char, idx)` | ⏳ Stub | Returns empty string |
| `Osi.DialogRequestStop(char)` | ⏳ Stub | No-op |
| `Osi.QRY_StartDialog_Fixed(res, char)` | ⏳ Stub | Returns false |
| `Osi.DB_Players:Get(nil)` | ⏳ Stub | Returns empty table |

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

## Target Mod

Primary goal: Enable **"More Reactive Companions"** to work on macOS.

**Test Mod:** [More Reactive Companions (Configurable)](https://www.nexusmods.com/baldursgate3/mods/5447) by [LightningLarryL](https://next.nexusmods.com/profile/LightningLarryL?gameId=3474)

This mod redirects ambient party dialogue to random nearby companions instead of always using the player character, making the party feel more alive. It requires Script Extender APIs and serves as our primary compatibility target.

**Current Status:** The mod **loads successfully** and registers its event listeners. Full functionality requires implementing real Osiris bindings (currently stubs).

## Tools

### PAK Extractor

A Python tool to extract BG3 mod `.pak` files (LSPK v18 format):

```bash
# Install dependency
pip3 install lz4

# Extract a mod
python3 tools/extract_pak.py path/to/mod.pak [output_dir]
```

This is useful for examining mod structure and Lua scripts, and currently required for testing SE mods until PAK reading is implemented.

## Roadmap

### Next Steps

1. **Real Osiris Bindings** - Hook into Osiris database to implement real `Osi.*` functions
2. **PAK File Reading** - Load scripts directly from .pak files without extraction
3. **Steam Workshop Support** - Auto-detect mods from workshop folder
4. **Auto-detection** - Scan for SE-enabled mods via Config.json

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

1. Ensure the mod is extracted to `/tmp/<ModName>_extracted/`
2. Check that the path structure is: `Mods/<ModName>/ScriptExtender/Lua/BootstrapServer.lua`
3. Review the log for "Loading Mod Scripts" section
4. Verify the mod name matches what's hardcoded (currently `MoreReactiveCompanions_Configurable`)

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
- Test mod: [More Reactive Companions](https://www.nexusmods.com/baldursgate3/mods/5447) by LightningLarryL
