# True Headless Feasibility

## Status

Classification: `possible-with-RE`

As of 2026-05-16, there is not enough evidence for a BG3 macOS "true headless" mode that boots to a useful Script Extender socket without creating a normal Cocoa/Metal window. The practical default should remain temporary windowed launch plus offscreen/hide after socket readiness while reverse engineering continues.

## Evidence Checked

### CLI Flags

`PYTHONPATH=tools python3 -m bg3se_harness flags --verify` confirms the known flag registry exists in the current binary. Relevant launch/system flags found:

- `-continueGame`
- `-loadSaveGame`
- `-load`
- `-testLoadLevel`
- `-detailLevel`
- `-mediaPath`
- `--nodb`
- `--noxml`
- `--cpuLimit`
- `--logPath`

No verified flag in the harness registry is named `headless`, `dedicated`, `server`, `null-renderer`, or equivalent.

### Binary Strings

Targeted string search found rendering/window concepts:

- `CAMetalLayer`
- `Windowed`
- `WindowedMode`
- `Fullscreen`
- `FullScreen`
- `FakeFullScreen`
- `FakeFullscreenEnabled`
- `Offscreen`
- `Offscreen%d`
- `Max number of offscreen surfaces reached`
- Noesis offscreen UI strings such as `N6Noesis9OffscreenE`

These strings prove the binary contains fullscreen/windowed settings and Noesis offscreen surfaces, but they do not prove a full game-engine no-window mode. The `Offscreen` strings appear tied to UI/render surfaces, not an obvious process mode.

### Current Runtime Evidence

Previous headless attempts showed:

- Hiding or minimizing too early can stall Metal drawable creation.
- Moving a normal window offscreen is less disruptive than AX minimize or `visible=false` during boot.
- The socket can listen before Lua responds; a responding socket still requires game progression past menu/save load.
- Direct `LSMTLView keyDown:` injection can log `direct_view=yes`, but that is not proof of menu consumption.
- Foreground CGEvent mouse clicks at measured Continue-button coordinates do not advance the menu, even with Retina-corrected coordinates, prior mouse-move events, and click-state fields.
- System Events `click at` fails against the BG3 window with macOS error `-25200`.
- Vision OCR can capture a valid menu screenshot but currently returns no text for BG3's stylized menu labels.

## Candidate Paths

### Practical Default: Windowed Offscreen

Keep this as the accepted CLI default unless a stronger headless path is proven:

1. Snapshot `graphicSettings.lsx`.
2. Force normal windowed `1280x720`.
3. Launch BG3.
4. Let Metal create a drawable.
5. Automate splash/menu/save load.
6. Hide or move offscreen after socket response.
7. Restore graphics settings.

### RE Candidate: Direct Game-State Save Load

This may be more promising than renderer replacement. If the harness can trigger `continueGame` / `loadSaveGame` behavior directly in the game state machine after init, it may avoid menu input entirely while still allowing a normal render path.

Needed evidence:

- Xrefs/decompile for `-continueGame`, `-loadSaveGame`, `-load`, and `-testLoadLevel`.
- Identify whether save load can be invoked after the socket starts listening.
- Runtime proof that game state transitions from menu to save loading without UI input.

Current string clues:

- `StartGameCommand`
- `MainMenuCommand`
- `MainMenuConfirm`
- `LoadSaveGames`
- `OpenSaveGameDialogCommand`
- `SaveGameOpen`
- `-loadSaveGame`
- `-continueGame`
- `loadSaveGame: `
- `continueGame: `
- `eoc::gamestate::MainMenuComponent`
- `eoc::gamestate::LoadMainMenuComponent`
- `eoc::gamestate::MainMenuPostInstantiateComponent`
- `eoc::gamestate::PrepareRunningComponent`
- `eoc::gamestate::RunningComponent`

The local `bg3se-harness ghidra status` check returned `{"alive": false, "error": "Bridge not reachable"}`, so this path needs a running Ghidra/GhidraMCP bridge or a separate local disassembly workflow before implementation.

### RE Candidate: Null/Offscreen Metal Surface

Potentially high risk. This would require proving that BG3 can run simulation and Script Extender with an offscreen or fake `CAMetalLayer`/drawable.

Needed evidence:

- Locate Metal view/layer creation.
- Determine whether game state requires successful drawable presentation.
- Prototype only after practical CLI mode is reliable.

## Current Recommendation

Do not block CLI functionality on true headless rendering. Continue with windowed/offscreen mode and focus first on deterministic save-load/socket readiness. Continue RE on direct game-state save load as the next true-headless-adjacent path, because it may remove the need for fragile menu input without replacing Metal.
