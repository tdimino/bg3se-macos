# BG3SE-macOS

**Baldur's Gate 3 Script Extender for macOS**

A native macOS implementation of the BG3 Script Extender, enabling mods that require scripting capabilities (like "More Reactive Companions") to work on Mac.

## Status

🚧 **Work in Progress**

| Phase | Status | Notes |
|-------|--------|-------|
| DYLD Injection | ✅ Complete | Verified working via Steam |
| Symbol Resolution | ✅ Complete | All libOsiris symbols resolved |
| Function Hooking | 🔄 In Progress | Using fishhook library |
| Lua Runtime | ⏳ Pending | |
| Mod Compatibility | ⏳ Pending | Target: More Reactive Companions |

### Verified Working (Nov 27, 2025)
- Steam launch with injection via wrapper script
- libOsiris.dylib symbol addresses resolved:
  - `DebugHook`, `CreateRule`, `DefineFunction`, `SetInitSection`
  - `COsiris::InitGame`, `COsiris::Load`
- Game runs normally at main menu with injection active

## Requirements

- macOS 12+ (tested on macOS 15)
- Apple Silicon or Intel Mac
- Baldur's Gate 3 (Steam version)
- Xcode Command Line Tools

## Quick Start

### Build

```bash
cd bg3se-macos
./scripts/build.sh
```

### Test Injection

```bash
./scripts/launch_bg3.sh
```

Check `/tmp/bg3se_macos.log` for output.

## How It Works

BG3SE-macOS uses `DYLD_INSERT_LIBRARIES` to inject a dynamic library into the BG3 process at launch. This works because:

1. BG3 macOS has **no hardened runtime** (`flags=0x0`)
2. DYLD injection is allowed for non-hardened apps
3. libOsiris.dylib exports clean C symbols we can hook

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
│   ├── injector/
│   │   └── main.c          # Entry point & initialization
│   ├── hooks/              # Function hooking (TODO)
│   ├── lua/                # Lua integration (TODO)
│   └── osiris/             # Osiris engine bindings (TODO)
├── scripts/
│   ├── build.sh            # Build script
│   └── launch_bg3.sh       # Launch with injection
├── build/
│   └── lib/
│       └── libbg3se.dylib  # Built dylib
└── README.md
```

## Target Mod

Primary goal: Enable **"More Reactive Companions"** (Nexusmods #5447) to work on macOS.

## Technical Details

### Why This Works

| Factor | Value |
|--------|-------|
| Hardened Runtime | `flags=0x0` (none) |
| Code Signing | Developer ID signed, but not hardened |
| DYLD Injection | Allowed |
| libOsiris Exports | 1,013 symbols |

### Key libOsiris Symbols

```
_COsiris_InitGame    - Game initialization hook
_COsiris_Load        - Save/story loading
_CreateRule          - Script rule creation
_DefineFunction      - Function registration
_DebugHook           - Debug interface
```

## Troubleshooting

### Injection Not Working

1. Check `/tmp/bg3se_macos.log` for errors
2. Verify the dylib is built: `file build/lib/libbg3se.dylib`
3. Ensure BG3 path is correct in `launch_bg3.sh`

### Game Crashes

1. Check if BG3 updated (may need new symbol mappings)
2. Try running without injection to verify base game works
3. Check Console.app for crash reports

## Maintenance

When BG3 updates:

1. Run `nm -gU` on the new libOsiris.dylib
2. Compare with previous symbol addresses
3. Update any hardcoded offsets
4. Rebuild and test

## License

MIT License - See LICENSE file.

## Credits

- Inspired by [Norbyte's BG3SE](https://github.com/Norbyte/bg3se)
- $670 bounty exists on GitHub issue #162 for macOS support
