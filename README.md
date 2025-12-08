<p align="center">
  <img src="assets/tanit.svg" alt="Symbol of Tanit" width="80" height="100"/>
</p>

# BG3SE-macOS

**Baldur's Gate 3 Script Extender for macOS**

A native macOS implementation of the BG3 Script Extender, working toward full feature parity with Norbyte's Windows BG3SE. Enables mods that require scripting capabilities to work on Mac—including companion mods, gameplay tweaks, UI enhancements, and more.

> **Note:** This is a ground-up rebuild, not a port—the Windows BG3SE uses x86_64 assembly and Windows APIs that don't exist on macOS ARM64. We use the Windows codebase as architectural reference while reverse-engineering the macOS binary via Ghidra.

## Quick Start

### Requirements

- macOS 12+ (tested on macOS 15.6.1)
- Apple Silicon Mac (recommended) or Intel Mac (limited functionality)
- Baldur's Gate 3 (Steam)
- Xcode Command Line Tools: `xcode-select --install`
- CMake: `brew install cmake`

### Build & Install

```bash
# Build
cd bg3se-macos
./scripts/build.sh

# Set Steam launch options for BG3:
/path/to/bg3se-macos/scripts/bg3w.sh %command%
```

### Using SE Mods

SE mods work automatically—just install them like any other mod:

1. Download the mod's `.pak` file from Nexus Mods
2. Place it in `~/Documents/Larian Studios/Baldur's Gate 3/Mods/`
3. Enable the mod in the game's mod manager
4. Launch via Steam

**BG3SE-macOS reads scripts directly from PAK files—no extraction needed!**

## Status

**Version:** v0.19.0 | **Feature Parity:** ~55%

| Feature | Status |
|---------|--------|
| DYLD Injection | ✅ Complete |
| Lua Runtime | ✅ Lua 5.4 with Ext API |
| Mod Loading | ✅ PAK file reading, auto-detection |
| Ext.Osiris | ✅ Event listeners |
| Ext.Entity | ✅ GUID lookup, components |
| Ext.Stats | ✅ 15,774 stats, property read/write |
| Ext.Events | ✅ 8 events with GameStateChanged |
| Ext.Timer | ✅ WaitFor, Cancel, Pause, Resume |
| Ext.Vars | ✅ PersistentVars |
| Ext.Input | ✅ Hotkeys, key injection |
| Ext.Math | ✅ Vector/matrix operations |
| Debug Console | ✅ Socket + file + in-game overlay |

See [ROADMAP.md](ROADMAP.md) for detailed progress.

## Documentation

| Document | Description |
|----------|-------------|
| **[docs/getting-started.md](docs/getting-started.md)** | Installation, building, first launch |
| **[docs/api-reference.md](docs/api-reference.md)** | Complete Ext.* and Osi.* API docs |
| **[docs/architecture.md](docs/architecture.md)** | Technical deep-dive: injection, hooks, ARM64 |
| **[docs/development.md](docs/development.md)** | Contributing, building features, debugging |
| **[docs/troubleshooting.md](docs/troubleshooting.md)** | Common issues and solutions |
| **[docs/reverse-engineering.md](docs/reverse-engineering.md)** | Ghidra workflows, offset discovery |

## Live Console

Three ways to interact with the Lua runtime:

1. **In-Game Overlay** - Press **Ctrl+`** to toggle
2. **Socket Console** - `./build/bin/bg3se-console`
3. **File-Based** - Write to `~/Library/Application Support/BG3SE/commands.txt`

```bash
# Socket console (recommended for development)
./build/bin/bg3se-console

# Or via socat
socat - UNIX-CONNECT:/tmp/bg3se.sock
```

## File Structure

```
bg3se-macos/
├── src/                    # Source code
│   ├── injector/main.c     # Core injection, hooks, Lua state
│   ├── lua/                # Ext.* API implementations
│   ├── entity/             # Entity Component System
│   ├── stats/              # RPGStats system
│   └── ...
├── docs/                   # Documentation
├── ghidra/                 # Reverse engineering
│   ├── scripts/            # Ghidra Python scripts
│   └── offsets/            # Offset documentation
├── tools/                  # PAK extractor, Frida, test mods
└── scripts/                # Build and launch scripts
```

## Acknowledgments

### Special Thanks

This project would not be possible without **[Norbyte](https://github.com/Norbyte)** and their pioneering work on the original [BG3 Script Extender](https://github.com/Norbyte/bg3se) for Windows. Their reverse engineering of Larian's Osiris scripting engine, comprehensive API design, and years of dedication to the modding community laid the foundation that made this macOS port conceivable. We are deeply grateful for their open-source contribution to the BG3 modding ecosystem.

### Credits

- [Norbyte's BG3SE](https://github.com/Norbyte/bg3se) - The original Windows Script Extender
- [Dobby](https://github.com/jmpews/Dobby) - Inline hooking framework for ARM64/x86_64
- [fishhook](https://github.com/facebook/fishhook) - Symbol rebinding library
- [LZ4](https://github.com/lz4/lz4) - Fast compression for PAK file reading
- Test mod: [More Reactive Companions](https://www.nexusmods.com/baldursgate3/mods/5447) by LightningLarryL

## License

MIT License

## Authors

- Tom di Mino (the artist formerly known as [Pnutmaster](https://wiki.twcenter.net/index.php?title=Blood_Broads_%26_Bastards) / [Nexus](https://next.nexusmods.com/profile/Pnutmaster/mods?gameId=130))
- [Claude Code](https://claude.ai/claude-code) (Anthropic)

## Support This Project

If you love exceptionally well-crafted RPGs like Baldur's Gate 3, and the ability to extend its gameplay through mods and scripting, you're more than welcome to toss me some coin.

[![PayPal](https://img.shields.io/badge/PayPal-Donate-blue?logo=paypal)](https://www.paypal.com/donate?business=contact@tomdimino.com&currency_code=USD)

Donations help fund continued development, testing across game updates, and expanding mod compatibility. Every contribution is appreciated!

### P.S.

I'd also like to extend my thanks to the OP and commentators of this BG3SE issue: **["[Feature Bounty - $350] MacOS Supported Version of BG3 SE"](https://github.com/Norbyte/bg3se/issues/162)**. You kicked off this quest :)
