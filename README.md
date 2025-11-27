# BG3SE-macOS

**Baldur's Gate 3 Script Extender for macOS**

A native macOS implementation of the BG3 Script Extender, enabling mods that require scripting capabilities (like "More Reactive Companions") to work on Mac.

## Status

🚧 **Work in Progress** - Proof of Concept Working!

| Phase | Status | Notes |
|-------|--------|-------|
| DYLD Injection | ✅ Complete | Working via `open -W` launch method |
| Symbol Resolution | ✅ Complete | All libOsiris symbols resolved |
| Function Hooking | 🔄 In Progress | Dobby inline hooking integrated |
| Lua Runtime | ⏳ Pending | |
| Mod Compatibility | ⏳ Pending | Target: More Reactive Companions |

### Verified Working (Nov 27, 2025)

- ✅ Steam launch with injection via wrapper script
- ✅ Game loads to main menu with injection active
- ✅ **Successfully loaded saved games with injection active**
- ✅ libOsiris.dylib symbol addresses resolved:
  - `DebugHook`, `CreateRule`, `DefineFunction`, `SetInitSection`
  - `COsiris::InitGame`, `COsiris::Load`

## Requirements

- macOS 12+ (tested on macOS 15.6.1)
- Apple Silicon or Intel Mac (game runs under Rosetta)
- Baldur's Gate 3 (Steam version)
- Xcode Command Line Tools (`xcode-select --install`)

## Quick Start

### Build

```bash
cd bg3se-macos
./scripts/build.sh
```

### Install

1. Create wrapper script `/tmp/bg3w.sh`:

```bash
#!/bin/bash
export DYLD_INSERT_LIBRARIES="/path/to/bg3se-macos/build/lib/libbg3se.dylib"
exec open -W "$1"
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

### Verify

Check `/tmp/bg3se_macos.log` for injection logs:
```
=== BG3SE-macOS v0.2.1 ===
[timestamp] === BG3SE-macOS v0.2.1 initialized ===
[timestamp] Running in process: Baldur's Gate 3 (PID: XXXXX)
```

## How It Works

BG3SE-macOS uses `DYLD_INSERT_LIBRARIES` to inject a dynamic library into the BG3 process at launch. This works because:

1. BG3 macOS has **no hardened runtime** (`flags=0x0`)
2. DYLD injection is allowed for non-hardened apps
3. libOsiris.dylib exports clean C symbols we can hook

### Key Discovery: Launch Method Matters

⚠️ **Important:** macOS apps must be launched as `.app` bundles, not by running the executable directly.

| Method | Result |
|--------|--------|
| `exec "$APP/Contents/MacOS/Baldur's Gate 3"` | ❌ Crashes |
| `open -W "$APP"` | ✅ Works |

The `open -W` command properly initializes the app bundle and inherits `DYLD_INSERT_LIBRARIES`.

### Architecture

```
┌─────────────────────────────────────────────────┐
│                  BG3 Process                    │
├─────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌───────────────────────┐  │
│  │ libOsiris    │◄───│ BG3SE Hooks           │  │
│  │ (Scripting)  │    │ - COsiris::InitGame   │  │
│  └──────────────┘    │ - CreateRule          │  │
│                      │ - DefineFunction      │  │
│  ┌──────────────┐    └───────────────────────┘  │
│  │ Main Game    │              ▲               │
│  │ Executable   │              │               │
│  └──────────────┘    ┌─────────┴─────────┐    │
│                      │  Lua Runtime       │    │
│                      │  (Mod Scripts)     │    │
│                      └───────────────────┘    │
└─────────────────────────────────────────────────┘
```

## File Structure

```
bg3se-macos/
├── src/
│   └── injector/
│       └── main.c          # Entry point & initialization
├── lib/
│   ├── fishhook/           # Symbol rebinding (for imported symbols)
│   └── Dobby/              # Inline hooking (for internal functions)
├── scripts/
│   └── build.sh            # Build script (x86_64 for Rosetta)
├── build/
│   └── lib/
│       └── libbg3se.dylib  # Built dylib
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

- **fishhook**: For imported symbols (PLT/GOT rebinding)
- **Dobby**: For internal library functions (inline hooking)

Osiris functions like `DebugHook`, `CreateRule`, etc. are internal to `libOsiris.dylib`, requiring inline hooking via Dobby.

### Key libOsiris Symbols

```
_DebugHook           - Debug interface
_CreateRule          - Script rule creation
_DefineFunction      - Function registration
_SetInitSection      - Initialization hook
_ZN7COsiris8InitGameEv    - COsiris::InitGame
_ZN7COsiris4LoadER12COsiSmartBuf - COsiris::Load
```

## Target Mod

Primary goal: Enable **"More Reactive Companions"** ([Nexusmods #5447](https://www.nexusmods.com/baldursgate3/mods/5447)) to work on macOS.

Required SE APIs:
- `Ext.Require()`
- `Ext.IO.LoadFile()`
- `Ext.Json.Parse()`
- `Osi.*` functions

## Troubleshooting

### Injection Not Working

1. Check `/tmp/bg3se_macos.log` for errors
2. Verify the dylib is built: `file build/lib/libbg3se.dylib`
3. Ensure wrapper uses `open -W` (not direct executable)

### Game Crashes at Launch

1. Make sure wrapper script uses `open -W "$1"` (not `exec "$1/Contents/MacOS/..."`)
2. Try running without injection: clear Steam launch options
3. Check Console.app for crash reports

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
