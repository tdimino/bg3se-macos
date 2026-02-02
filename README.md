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
# Clone with submodules
git clone --recursive https://github.com/tdimino/bg3se-macos.git
cd bg3se-macos

# If you already cloned without --recursive:
git submodule update --init --recursive

# Build
./scripts/build.sh
```

### Verify Build Succeeded

```bash
# Check output exists (should be ~3MB universal binary)
ls -la build/lib/libbg3se.dylib

# Verify architecture (should show arm64 and x86_64)
file build/lib/libbg3se.dylib
```

### Configure Steam Launch Options

1. Right-click **Baldur's Gate 3** in Steam → **Properties**
2. Under **General** → **Launch Options**, enter:
   ```
   /full/path/to/bg3se-macos/scripts/bg3w.sh %command%
   ```
   Replace `/full/path/to` with the actual path where you cloned the repo.

### Troubleshooting Build Issues

| Problem | Solution |
|---------|----------|
| `cmake: command not found` | Install CMake: `brew install cmake` |
| `CMake Error: could not find compiler` | Install Xcode tools: `xcode-select --install` |
| Missing Dobby/Lua/lz4 errors | Initialize submodules: `git submodule update --init --recursive` |
| Build succeeds but no dylib | Check `build/lib/` directory; ensure build completed |
| `CMake Error: source directory does not exist` | Stale cache after moving repo. Delete `build/` and rebuild: `rm -rf build && mkdir build && cd build && cmake .. && cmake --build .` |
| Code changes don't appear in game | Stale CMake cache. Delete `build/` directory and rebuild from scratch |

### Using Script Extender Mods

Script Extender (SE) mods are mods that require BG3SE to function—they use Lua scripting to add features that aren't possible with standard modding. With BG3SE-macOS installed, these mods work just like any other mod:

1. **Download** the mod's `.pak` file from [Nexus Mods](https://www.nexusmods.com/baldursgate3)
2. **Install** by placing it in `~/Documents/Larian Studios/Baldur's Gate 3/Mods/`
3. **Enable** the mod using the in-game mod manager (or a mod manager like [BG3 Mod Manager](https://github.com/LaughingLeader/BG3ModManager))
4. **Launch** the game via Steam (using the launch options configured above)

> **Tip:** BG3SE-macOS reads Lua scripts directly from PAK files—no manual extraction required. If a mod page says "requires Script Extender," it should work automatically once you've set up BG3SE-macOS.

### Mod Compatibility

Most SE mods designed for the Windows Script Extender will work on macOS. We're actively testing popular mods and tracking compatibility:

| Mod | Author | Status | Notes |
|-----|--------|--------|-------|
| [More Reactive Companions](https://www.nexusmods.com/baldursgate3/mods/5447) | LightningLarryL | ✅ Working | Party banter, companion reactions |

This is just a sample—many more mods work out of the box. See **[docs/supported-mods.md](docs/supported-mods.md)** for the full compatibility list, testing notes, and known issues.

**Tested a mod?** Help the community by [reporting your results](https://github.com/tdimino/bg3se-macos/issues/new?template=mod-compatibility.md)! Whether it works perfectly or has issues, your feedback helps other Mac players.

## Status

**Version:** v0.36.21 | **Feature Parity:** ~87%

| Feature | Status |
|---------|--------|
| DYLD Injection | ✅ Complete |
| Lua Runtime | ✅ Lua 5.4 with Ext API |
| Mod Loading | ✅ PAK file reading, auto-detection |
| Ext.Osiris | ✅ Event listeners, custom functions (NewCall/NewQuery/NewEvent/RaiseEvent/GetCustomFunctions), **server context guards** |
| Ext.Entity | ✅ GUID lookup, **Dual EntityWorld** (client + server), **1,999 components registered** (534 layouts: 169 verified + 365 generated), **1,577 ARM64 sizes** + **702 Windows estimates** = **1,730 total** (87% coverage) |
| Ext.Stats | ✅ 15,774 stats, property read/write, **Sync complete (created + existing stats)** |
| Ext.Events | ✅ 32 events (13 lifecycle + 17 engine + 2 functor) with Prevent pattern |
| Ext.IO | ✅ LoadFile, SaveFile, **AddPathOverride, GetPathOverride** |
| Ext.Timer | ✅ WaitFor, WaitForRealtime, Cancel, Pause, Resume, **MicrosecTime, ClockEpoch, ClockTime, GameTime, DeltaTime, Ticks, Persistent timers (6 functions)** |
| Ext.Vars | ✅ PersistentVars + User Variables + Mod Variables |
| Ext.Input | ✅ Hotkeys, key injection |
| Ext.Math | ✅ Vector/matrix operations, **16 quaternion functions**, scalar utils |
| Ext.Enums | ✅ 14 enum/bitfield types |
| Ext.Types | ✅ Full reflection API (9 functions), **GenerateIdeHelpers** for VS Code IntelliSense |
| Ext.StaticData | ✅ **All 9 types** (Feat, Race, Background, Origin, God, Class, Progression, ActionResource, FeatDescription) via ForceCapture |
| Ext.Resource | ✅ Get, GetAll, GetTypes, GetCount (34 resource types) |
| Ext.Template | ✅ **Auto-capture**, iteration (Cache/LocalCache), GUID resolution |
| Lifetime Scoping | ✅ Prevents stale object access |
| Context System | ✅ **Server/Client context awareness**, Ext.IsServer/IsClient/GetContext, two-phase bootstrap |
| Debug Console | ✅ Socket + file + in-game overlay |
| Testing | ✅ `!test` suite, Debug.* helpers, Frida scripts |

See [ROADMAP.md](ROADMAP.md) for detailed progress.

## Documentation

| Document | Description |
|----------|-------------|
| **[docs/supported-mods.md](docs/supported-mods.md)** | Tested mod compatibility list |
| **[docs/getting-started.md](docs/getting-started.md)** | Installation, building, first launch |
| **[docs/api-reference.md](docs/api-reference.md)** | Complete Ext.* and Osi.* API docs |
| **[docs/architecture.md](docs/architecture.md)** | Technical deep-dive: injection, hooks, ARM64 |
| **[docs/development.md](docs/development.md)** | Contributing, building features, debugging |
| **[docs/contributor-workflow.md](docs/contributor-workflow.md)** | End-to-end guide: research, Ghidra, implementation |
| **[docs/reverse-engineering.md](docs/reverse-engineering.md)** | Ghidra workflows, offset discovery |
| **[docs/troubleshooting.md](docs/troubleshooting.md)** | Common issues and solutions |
| **[docs/arm64/](docs/arm64/)** | ARM64 hooking patterns, prevention strategies |
| **[docs/solutions/](docs/solutions/)** | Documented problem solutions |

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
├── src/
│   ├── injector/
│   │   └── main.c              # Core injection, Dobby hooks, Lua state init
│   ├── core/
│   │   ├── logging.c/h         # Structured logging (14 modules, 4 levels)
│   │   ├── safe_memory.c/h     # Safe memory read/write (mach_vm)
│   │   └── version.h           # Version info, data paths
│   ├── lua/
│   │   ├── lua_ext.c/h         # Ext.Print, Ext.Utils, Ext.Memory
│   │   ├── lua_stats.c/h       # Ext.Stats API
│   │   ├── lua_events.c/h      # Ext.Events system
│   │   ├── lua_timer.c/h       # Ext.Timer API
│   │   ├── lua_osiris.c/h      # Osi.* namespace bindings
│   │   ├── lua_debug.c/h       # Ext.Debug memory introspection
│   │   ├── lua_json.c/h        # JSON encode/decode
│   │   ├── lua_resource.c/h    # Ext.Resource bindings
│   │   ├── lua_template.c/h    # Ext.Template bindings
│   │   ├── lua_staticdata.c/h  # Ext.StaticData bindings
│   │   └── lua_persistentvars.c/h  # Ext.Vars persistence
│   ├── entity/
│   │   ├── entity_system.c/h   # Core ECS, Lua bindings
│   │   ├── guid_lookup.c/h     # GUID parsing, HashMap ops
│   │   ├── arm64_call.c/h      # ARM64 ABI wrappers (x8 indirect return)
│   │   ├── component_*.c/h     # Component registry, lookup, TypeId
│   │   ├── generated_typeids.h # Auto-generated 1,999 TypeId addresses
│   │   ├── generated_component_registry.c  # Auto-registration code
│   │   └── entity_storage.h    # Storage structures, Ghidra base addr
│   ├── stats/
│   │   └── stats_manager.c/h   # RPGStats access, property resolution
│   ├── strings/
│   │   └── fixed_string.c/h    # GlobalStringTable resolution
│   ├── osiris/
│   │   ├── osiris_functions.c/h    # Osiris function lookup/call
│   │   ├── osiris_types.h      # FuncDef, OsiArgumentDesc structs
│   │   ├── custom_functions.c/h    # Custom Osiris function registration
│   │   └── pattern_scan.c/h    # Memory pattern scanning
│   ├── console/
│   │   └── console.c/h         # Socket + file-based console
│   ├── input/
│   │   ├── input_hooks.m       # macOS input event hooks
│   │   └── lua_input.c         # Ext.Input API
│   ├── overlay/
│   │   └── overlay.m/h         # In-game debug overlay (NSWindow)
│   ├── timer/
│   │   └── timer.c/h           # Timer system implementation
│   ├── game/
│   │   └── game_state.c/h      # Game state tracking
│   ├── mod/
│   │   └── mod_loader.c/h      # Mod detection, PAK loading
│   ├── pak/
│   │   └── pak_reader.c/h      # LSPK v18 PAK file parsing
│   ├── math/
│   │   └── math_ext.c/h        # Ext.Math vector/matrix ops
│   ├── resource/
│   │   └── resource_manager.c/h  # Ext.Resource (34 resource types)
│   ├── staticdata/
│   │   └── staticdata_manager.c/h  # Ext.StaticData (Feats, etc.)
│   ├── template/
│   │   └── template_manager.c/h  # Ext.Template (auto-capture)
│   └── hooks/
│       └── osiris_hooks.c/h    # Osiris event interception
│
├── ghidra/
│   ├── scripts/                # Ghidra Python analysis scripts
│   │   ├── run_analysis.sh     # Headless analyzer wrapper
│   │   ├── find_rpgstats.py    # Discover gRPGStats global
│   │   ├── find_entity_offsets.py
│   │   └── ...
│   └── offsets/                # Discovered offset documentation
│       ├── STATS.md            # RPGStats, FixedStrings (0x348)
│       ├── ENTITY_SYSTEM.md    # ECS architecture
│       ├── RESOURCE.md         # ResourceManager (0x08a8f070)
│       ├── TEMPLATE.md         # Template managers
│       └── ...
│
├── docs/
│   ├── components/             # Component documentation by namespace
│   │   ├── README.md           # Component reference overview
│   │   ├── eoc-components.md   # 701 eoc:: components
│   │   ├── esv-components.md   # 596 esv:: components
│   │   ├── ecl-components.md   # 429 ecl:: components
│   │   └── ls-components.md    # 233 ls:: components
│   └── ...                     # Other user-facing documentation
│
├── tools/
│   ├── bg3se-console.c         # Standalone readline console client
│   ├── extract_pak.py          # PAK file extractor
│   ├── extract_typeids.py      # Generate TypeId header from binary
│   └── frida/                  # Frida instrumentation scripts
│
├── scripts/
│   ├── build.sh                # Build script
│   ├── bg3w.sh                 # Steam launch wrapper (ARM64)
│   ├── bg3w-intel.sh           # Steam launch wrapper (Intel)
│   └── launch_bg3.sh           # Direct launch for testing
│
├── lib/                        # Third-party libraries
│   ├── Dobby/                  # Inline hooking framework
│   ├── lua/                    # Lua 5.4
│   └── lz4/                    # Compression for PAK files
│
├── agent_docs/                 # Claude Code context docs
├── plans/                      # Implementation plans
└── test-mods/                  # Test mod examples
```

## Acknowledgments

### Special Thanks

This project would not be possible without **[Norbyte](https://github.com/Norbyte)** and their pioneering work on the original [BG3 Script Extender](https://github.com/Norbyte/bg3se) for Windows. Their reverse engineering of Larian's Osiris scripting engine, comprehensive API design, and years of dedication to the modding community laid the foundation that made this macOS port conceivable. We are deeply grateful for their open-source contribution to the BG3 modding ecosystem.

### Credits

- [Norbyte's BG3SE](https://github.com/Norbyte/bg3se) - The original Windows Script Extender
- [Dobby](https://github.com/jmpews/Dobby) - Inline hooking framework for ARM64/x86_64
- [fishhook](https://github.com/facebook/fishhook) - Symbol rebinding library
- [LZ4](https://github.com/lz4/lz4) - Fast compression for PAK file reading
- [Dear ImGui](https://github.com/ocornut/imgui) - Debug overlay UI framework

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

---

## Inscriptions

> *"πολλοὶ μὲν ναρθηκοφόροι, παῦροι δέ τε βάκχοι."*
> — "Many are the wand-bearers, but few the Bacchoi." (Plato)

> *"ἀπιστίῃ διαφυγγάνει μὴ γιγνώσκεσθαι."*
> — "Divine things escape recognition through disbelief." (Herakleitos)

> *"μνάσεσθαί τινά φαμι καὶ ὕστερον ἀμμέων."*
> — "Someone, I tell you, will remember us." (Sappho)
