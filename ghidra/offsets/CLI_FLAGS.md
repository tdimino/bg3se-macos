# BG3 CLI Flags (macOS ARM64)

Extracted from macOS BG3 binary. No public documentation exists for these flags.

## Discovery Method

```bash
BG3="$HOME/Library/Application Support/Steam/steamapps/common/Baldurs Gate 3/Baldur's Gate 3.app/Contents/MacOS/Baldur's Gate 3"
strings -a "$BG3" | grep -E "^-[a-z][a-zA-Z]{3,}" | sort -u
```

Flags appear in two slices (ARM64 + x86_64) since the binary is universal.

## Mutual Exclusivity

The binary enforces that `-loadSaveGame` and `-continueGame` cannot be used together:

```
Source: EoCClient/Client/GameStateInitConnection.cpp
"These commands should be mutually exclusive"
```

Validated at `GameStateInit` before the game state machine proceeds.

## Noesis UI Bridge

The flags connect to a JavaScript bridge (Noesis UI framework) embedded in the binary:

```javascript
continueGame: function(args) {
    if (typeof args === 'undefined') {
        window.webkit.messageHandlers.call.postMessage('continueGame');
    }
    else window.webkit.messageHandlers.call.postMessage('continueGame:' + args);
},
```

Architecture-specific entry points: `runGame:arm64`, `continueGame:arm64`

The ObjC implementation at `0x100bb53d8` (`-[LariLauncherViewController continueGame]`) sets `_s_GameIsLaunching = 1` and closes the launcher modal.

## Flag Inventory

### Launch & Save Control (P0)

| Flag | ARM64 Offset | x86_64 Offset | Arg | Purpose |
|------|-------------|---------------|-----|---------|
| `-continueGame` | `0x108502635` | `0x107c03b3a` | No | Auto-continue most recent save |
| `-loadSaveGame` | `0x108502627` | `0x107c03b2c` | Yes (name) | Load specific save game |
| `-load` | `0x10846a562` | `0x107b6b86c` | Unknown | Generic load |
| `-testLoadLevel` | `0x10846a546` | `0x107b6b850` | Unknown | Test level loading |

### Mod & Story (P1)

| Flag | ARM64 Offset | Arg | Purpose |
|------|-------------|-----|---------|
| `-module` | `0x10846a53e` | Yes | Specify module to load |
| `-modded` | `0x1084508a7` | No | Enable modded mode |
| `-storylog` | `0x10845088e` | No | Enable story logging |
| `-dynamicStory` | `0x1085aba61` | No | Dynamic story mode |
| `-saveStoryState` | — | No | Save story state on exit |
| `-modEnv` | — | Yes | Mod environment |

### Debug & Developer (P1-P2)

| Flag | ARM64 Offset | Arg | Purpose |
|------|-------------|-----|---------|
| `-stats` | `0x1084508a0` | No | Stats output |
| `-json` | `0x10844a210` | No | JSON output mode |
| `-osi` | `0x1085c4c16` | No | Osiris debug |
| `-crash` | — | No | Crash reporting mode |
| `-syslog` | — | No | System logging |
| `-combatTimelines` | — | No | Combat timeline debug |
| `-toggleCrowds` | — | No | Toggle NPC crowds |
| `-testAIStart` | — | No | Test AI start |

### System & Graphics (P2)

| Flag | ARM64 Offset | Arg | Purpose |
|------|-------------|-----|---------|
| `-detailLevel` | `0x10844a1fe` | Yes | Graphics detail level |
| `-startInControllerMode` | — | No | Controller mode |
| `-enableClientNewECSScheduler` | — | No | New ECS scheduler |
| `-mediaPath` | — | Yes | Media/assets path |
| `-photoModeScreenshotsPath` | — | Yes | Screenshot save path |

### Localization (P2-P3)

| Flag | ARM64 Offset | Arg | Purpose |
|------|-------------|-----|---------|
| `-locaLanguage` | `0x108639e63` | Yes | Language setting |
| `-locaCloseOnErrors` | — | No | Close on localization errors |
| `-locaupdater` | — | No | Localization updater |

### Save System Debug / ECB Checker (P2-P3)

| Flag | ARM64 Offset | Arg | Purpose |
|------|-------------|-----|---------|
| `-useSaveSystemECBChecker` | `0x1084508f7` | No | Enable ECB checker |
| `-saveSystemECBCheckerEnableLogging` | — | No | ECB logging |
| `-saveSystemECBCheckerEnableDetailedLogging` | — | No | Detailed ECB logging |
| `-saveSystemECBCheckerAllowSaveOnFailure` | — | No | Allow save on ECB fail |
| `-saveSystemECBCheckerLogSuccessfulAttempts` | — | No | Log successful saves |
| `-saveSystemECBCheckNumberOfFramesToWait` | — | Yes | Frames before check |

### Double-Dash Flags

| Flag | ARM64 Offset | Arg | Purpose |
|------|-------------|-----|---------|
| ~~`--skip-launcher`~~ | N/A | N/A | **Does NOT exist in macOS binary.** Use `defaults write com.larian.bg3 NoLauncher 1` instead. |
| `--logPath` | `0x10865bd0f` | Yes | Log file path |
| `--cpuLimit` | — | Yes | CPU usage limit |
| `--closeOnErrors` | — | No | Close on errors |
| `--nodb` | — | No | No database |
| `--noxml` | — | No | No XML |

## Game State Components (Related Strings)

From binary string analysis — useful for understanding the state machine:

- `eoc::gamestate::RunningComponent`
- `eoc::gamestate::MainMenuComponent`
- `eoc::gamestate::SavegameLoadComponent`
- `ecl::GameStateLoadSessionComponent`
- `ecl::GameStateUnloadSessionComponent`
- `ecl::gamestate::StateSingletonComponent`

## Ghidra Analysis TODO

- [ ] Decompile full flag parsing function (XREF chain from `-continueGame` string → GameStateInit)
- [ ] Determine exact format expected by `-loadSaveGame` (save name vs full path vs slot index)
- [ ] Map the GameStateInit state machine (MainMenu → SavegameLoad → Running)
- [ ] Determine `-load` flag behavior (may be same as `-loadSaveGame`)
- [ ] Determine `-testLoadLevel` argument format

## Related Files

- `tools/bg3se_harness/flags.py` — Python registry of all 40 flags with validation
- `tools/bg3se_harness/ghidra.py` — Ghidra HTTP bridge client
- `ghidra/offsets/GAMESTATE.md` — Game state tracking offsets
