# Getting Started

This guide covers installation, building, and running BG3SE-macOS.

## Requirements

### For Using SE Mods

- macOS 12+ (tested on macOS 15.6.1)
- Apple Silicon Mac (for full functionality) or Intel Mac (limited)
- Baldur's Gate 3 (Steam version 4.1.1.6995620)
- Xcode Command Line Tools: `xcode-select --install`
- CMake: `brew install cmake`

### For Development/Maintenance (Optional)

- Ghidra 11.x: `brew install ghidra` or download from [ghidra-sre.org](https://ghidra-sre.org)
- Java 21: `brew install openjdk@21`

## Compatibility

| Item | Version/Info |
|------|--------------|
| **BG3 Version** | 4.1.1.6995620 (tested Dec 2025) |
| **macOS** | 12+ (tested on macOS 15.6.1) |
| **Architecture** | ARM64 (Apple Silicon) - primary target |
| **Rosetta/Intel** | Builds but Ghidra offsets are ARM64-only |

> **Note:** The Ghidra-derived memory offsets are specific to the ARM64 binary. Running under Rosetta (x86_64) will have limited functionality—only basic Osiris hooks and Lua runtime will work.

## Building

```bash
cd bg3se-macos
./scripts/build.sh
```

This builds a universal binary supporting both ARM64 (native) and x86_64 (Rosetta). Dobby will be built automatically if not present.

Output: `build/lib/libbg3se.dylib`

## Installation (Steam)

### Available Launch Scripts

| Script | Architecture | Use When |
|--------|--------------|----------|
| `bg3w.sh` | ARM64 (Apple Silicon) | **Recommended** - Full functionality |
| `bg3w-intel.sh` | x86_64 (Rosetta) | Intel Macs or troubleshooting |
| `launch_bg3.sh` | ARM64 | Direct terminal launch (no Steam) |

### Steam Setup (Apple Silicon - Recommended)

1. Open Steam and go to BG3's Properties
2. Set launch options:
```
/path/to/bg3se-macos/scripts/bg3w.sh %command%
```
3. Launch BG3 via Steam normally

See `scripts/*.example` files for reference wrapper scripts.

## Using SE Mods

SE mods work automatically—just install them like any other mod:

1. Download the mod's `.pak` file from Nexus Mods
2. Place it in `~/Documents/Larian Studios/Baldur's Gate 3/Mods/`
3. Enable the mod in the game's mod manager (or add to modsettings.lsx)
4. Launch the game and load a save

**BG3SE-macOS reads scripts directly from PAK files—no extraction needed!**

## Verifying Installation

Check `~/Library/Application Support/BG3SE/bg3se.log` for injection and mod loading logs:

```
=== BG3SE-macOS v0.19.0 initialized ===
Running in process: Baldur's Gate 3 (PID: XXXXX)
Architecture: ARM64 (Apple Silicon)
Dobby inline hooking: enabled
=== Enabled Mods ===
  [1] GustavX (base game)
  [2] MoreReactiveCompanions_Configurable
Total mods: 2 (1 user mods)
====================
=== Scanning for SE Mods ===
  [SE] MoreReactiveCompanions_Configurable
Total SE mods: 1
============================
=== Loading Mod Scripts ===
[Lua] Loaded from PAK: Mods/.../BootstrapServer.lua
=== Mod Script Loading Complete ===
```

## Live Console Options

BG3SE-macOS provides three ways to interact with the Lua runtime:

### 1. In-Game Overlay (v0.19.0)

Press **Ctrl+`** to toggle the console overlay directly in-game:
- Floating NSWindow above fullscreen game
- Tanit symbol with warm amber/gold glow
- Scrollable output area with command history
- Up/down arrows for command recall

### 2. Socket Console (Recommended for Development)

Real-time bidirectional communication:

```bash
# In another terminal while game is running
./build/bin/bg3se-console

# Or use socat/nc directly
socat - UNIX-CONNECT:/tmp/bg3se.sock
```

Features:
- Real-time output from `Ext.Print()`
- Command history with readline
- Multi-line input with `--[[` and `]]--` delimiters
- ANSI color output

### 3. File-Based Console (Automation)

```bash
# Watch output
tail -f ~/Library/Application\ Support/BG3SE/bg3se.log

# Send commands
echo 'Ext.Print("Hello!")' > ~/Library/Application\ Support/BG3SE/commands.txt
```

## Next Steps

- **Mod Developers:** See [API Reference](api-reference.md) for available Lua APIs
- **Contributors:** See [Development Guide](development.md) for build workflows
- **Issues?** See [Troubleshooting](troubleshooting.md)
