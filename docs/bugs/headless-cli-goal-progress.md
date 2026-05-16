# Headless CLI Goal Progress

## Objective

Make the `tools/bg3se_harness` CLI functional for autonomous BG3SE macOS mod vetting, with a reliable build/patch/launch/test path that reaches a loaded-save socket session without manual input. The source prompt is `bg3se-cli-goal.md`.

## 2026-05-16 — Coordinate Diagnostics Pass

### Context

The game was closed by the user before this pass, so no live click probe was run. The current work focuses on offline-safe diagnostics for the suspected CGEvent mouse-click failure and Retina coordinate mismatch.

### Changes

- Added `bg3se-harness menu geometry [--capture]`.
- Added `bg3se-harness menu detect --debug-image PATH`.
- Added geometry metadata to `menu detect` output:
  - BG3 PID and Quartz window ID.
  - Quartz owner/window metadata and bounds.
  - System Events bounds.
  - Screenshot pixel dimensions.
  - Main screen backing scale when available.
  - Screenshot-to-bounds scale for Quartz and System Events.
- Added per-button `coordinate_debug` data:
  - OCR bbox.
  - Normalized and pixel-space center.
  - Selected coordinate basis.
  - System Events point-space candidate.
  - Quartz scaled candidate.
  - Quartz pixel-space candidate.
  - Bounds containment checks.
- Added `menu click` JSON fields for the selected coordinate basis, coordinate debug data, and geometry snapshot.
- Documented the new menu diagnostics in `docs/harness.md`.
- Added offline tests in `tests/harness/test_menu.py`.

### Validation

Commands run:

```bash
PYTHONPATH=tools python3 -m py_compile tools/bg3se_harness/menu.py tools/bg3se_harness/cli.py
PYTHONPATH=tools python3 -m bg3se_harness menu --help
PYTHONPATH=tools python3 -m bg3se_harness menu geometry
PYTHONPATH=tools python3 -m pytest tests/harness -q
PYTHONPATH=tools python3 -m bg3se_harness.tests_nexus
PYTHONPATH=tools python3 -m bg3se_harness.tests_wiki
build/bin/bg3se_test_tier0
PYTHONPATH=tools python3 -m bg3se_harness flags --verify
```

Observed:

- `py_compile` passed.
- `menu --help` lists `detect`, `click`, `wait`, `dismiss`, and `geometry`.
- With BG3 closed, `menu geometry` returns structured JSON with `"error": "BG3 process not found"`.
- `pytest tests/harness -q` passed: 34 tests.
- Nexus tests passed: 23 tests.
- Wiki tests passed: 23 tests.
- Tier 0 C tests passed: 41/41.
- `flags --verify` confirmed the known launch/system flags exist in the current BG3 binary.

### True Headless Feasibility

Created `docs/bugs/true-headless-feasibility.md` with current classification `possible-with-RE`. No verified CLI flag currently indicates a no-window/headless renderer mode. The recommended default remains temporary windowed/offscreen mode while reverse engineering continues on direct game-state save-load and offscreen Metal possibilities.

### Remaining

- Run a live geometry capture after relaunch:

```bash
PYTHONPATH=tools python3 -m bg3se_harness menu geometry --capture
PYTHONPATH=tools python3 -m bg3se_harness menu detect --debug-image .screenshots/menu-debug.png
PYTHONPATH=tools python3 -m bg3se_harness menu click "Continue"
```

- Confirm whether the click failure is a Retina pixel/point mismatch, offscreen-window issue, stale window ID, or BG3 focus/input-consumption issue.
- Continue Track A from `bg3se-cli-goal.md`: prove input reaches game state, not just event-post APIs.
- Continue Track C from `bg3se-cli-goal.md`: document true headless feasibility.

## 2026-05-16 — Live Menu Stall and Watchdog

### Live Attempt

Command:

```bash
PYTHONPATH=tools python3 -m bg3se_harness launch --headless --continue --timeout 180
```

Observed phases:

```text
process_launched pid=8348
dylib_loaded at 0.0s
socket_listening at 0.5s
timeout at 180120ms
```

The user confirmed BG3 was visibly at the main menu during the run. The harness did not record `menu_detected` or `continue_clicked`, so the Python-side OCR/menu branch never progressed.

Live diagnostics run outside the sandbox:

```bash
PYTHONPATH=tools python3 -m bg3se_harness menu geometry --capture
PYTHONPATH=tools python3 -m bg3se_harness menu detect --debug-image .screenshots/menu-debug.png
```

Findings:

- BG3 PID: `8348`
- Quartz window ID: `49463`
- Quartz owner: `bg3`
- Window title: `Baldur's Gate 3 (1280x720) - (Metal) - (6 + 6 WT)`
- Quartz bounds: `224,185 1280x748`
- System Events bounds: `224,185 1280x748`
- Screenshot pixels: `2560x1496`
- Main screen scale: `2.0`
- Screenshot-to-window scale: `2.0` on both axes for both Quartz and System Events
- `menu detect` captured a valid image, but Vision OCR returned no raw text and no buttons.

Interpretation:

- Retina scaling is confirmed and measured, not guessed.
- Quartz and System Events agree on bounds.
- The immediate failure is OCR returning zero text, not a window-id or Retina coordinate mismatch.
- Direct `LSMTLView` input continues to report `direct_view=yes` in logs, but does not change game state.

### Changes

- Added a socket-listening stall watchdog in `wait_for_socket`.
- After the socket listens but does not respond, the watchdog retries menu progress with:
  - System Events Return key via `cg_key_to_pid`.
  - A reported coordinate fallback click at the stable Continue button fraction (`x=0.5`, `y=0.62`) using live window bounds.
- Each watchdog action records method, timestamp, stalled duration, menu detection output, geometry, key result, and click coordinates.
- After repeated watchdog attempts and a bounded stall period, `wait_for_socket` returns early with `stage: "menu_stalled"` instead of burning the full launch timeout.
- `menu_stalled` failure returns boot diagnostics, including latest log tail and menu geometry/detection data.
- Foreground and background headless failures now force-quit BG3 unless the process already exited, so a failed autonomous run does not leave the game sitting at the menu.

### Validation

Commands run:

```bash
PYTHONPATH=tools python3 -m pytest tests/harness/test_launch.py -q
PYTHONPATH=tools python3 -m pytest tests/harness/test_launch.py tests/harness/test_menu.py -q
PYTHONPATH=tools python3 -m py_compile tools/bg3se_harness/launch.py tools/bg3se_harness/cli.py tools/bg3se_harness/_monitor.py tools/bg3se_harness/menu.py
PYTHONPATH=tools python3 -m bg3se_harness launch --headless --continue --timeout 180
```

Observed:

- `test_launch.py`: 5 passed.
- Combined launch/menu focused suite: 9 passed after adding explicit timeout-stage coverage.
- Live launch pid `29430` reached `socket_listening` at `0.5s`.
- Watchdog retries ran at about `28.6s`, `41.1s`, and `53.2s`.
- The harness returned early at `71.986s` with `stage: "menu_stalled"` instead of waiting the full `180s`.
- Headless failure restored graphics and force-quit BG3:
  - `graphics_restore.success: true`
  - `headless.cancel.success: true`
  - `headless.cancel.method: "force"`
- A post-run process check found no BG3 or harness process still running.

Live watchdog evidence:

- Each retry reported successful System Events Return delivery.
- Each retry reported a successful coordinate click at `(864, 648)`, computed from the live BG3 window bounds with fraction `{x=0.5, y=0.62}`.
- Geometry remained consistent:
  - Window bounds: `224,185 1280x748`
  - Screenshot pixels: `2560x1496`
  - Main screen scale: `2.0`
  - Screenshot/window scale: `2.0` in both axes
- `menu detect` still returned no OCR text (`buttons: []`, `raw_ocr: []`).
- The BG3SE log tail showed direct `LSMTLView keyDown:` calls for Escape, Space, and Return through attempt `#35`, all reporting `direct_view=yes`, but game state did not advance.

Implementation follow-up:

- Plain socket timeout responses now include `stage: "timeout"`.
- Background headless monitor failures now force-quit BG3 after restoring the JSON health result, matching foreground cleanup behavior.

### Remaining

- Run the full offline validation suite again.
- The timeout/retry/cancel/log-diagnostics mechanism is now proven live; the remaining blocker is that both direct view key events and CGEvent coordinate clicks report delivery but do not change BG3 menu state.
- Next input experiments should focus on foreground activation, true content-area y-offset click probes, and direct Noesis/game-state invocation instead of Retina scale corrections.

## 2026-05-16 — Foreground Fraction Click Probe

### Changes

- Added `bg3se-harness menu click-fraction X Y [--method cgevent|system-events|both]`.
- The command activates BG3, computes a point from live window bounds, and reports:
  - selected point and fraction
  - selected bounds basis
  - activation result
  - CGEvent click result
  - System Events `click at` result
  - geometry/screenshot scale
- Updated the watchdog to use measured Continue-button fractions from the captured menu screenshot:
  - attempt 1: `{x=0.473, y=0.557}` (`observed_continue_center`)
  - attempt 2: `{x=0.500, y=0.557}` (`observed_continue_center_x_mid`)
  - attempt 3: `{x=0.473, y=0.620}` (`legacy_low_fallback`)

### Validation

Offline gate:

```bash
PYTHONPATH=tools python3 -m pytest tests/harness -q
build/bin/bg3se_test_tier0
PYTHONPATH=tools python3 -m bg3se_harness.tests_nexus
PYTHONPATH=tools python3 -m bg3se_harness.tests_wiki
```

Observed:

- Harness pytest: 36 passed.
- Tier 0 C tests: 41/41 passed.
- Nexus tests: 23 passed.
- Wiki tests: 23 passed.

Live command:

```bash
PYTHONPATH=tools python3 -m bg3se_harness launch --headless --continue --timeout 180
```

Observed:

- BG3 pid `32434`.
- `socket_listening` at `0.5s`.
- Watchdog attempts at about `30.5s`, `44.1s`, and `56.5s`.
- Attempt 1 clicked `(829, 601)` from `{x=0.473, y=0.557}`.
- Attempt 2 clicked `(864, 601)` from `{x=0.500, y=0.557}`.
- Attempt 3 clicked `(829, 648)` from `{x=0.473, y=0.620}`.
- Each attempt activated BG3 successfully.
- CGEvent click returned success for each attempt.
- System Events `click at` failed each time with macOS error `-25200`.
- `menu_stalled` returned at `70.657s`.
- Headless graphics restored and BG3 was force-quit.
- A post-run process check found no BG3 or harness process still running.

Interpretation:

- The previous click target was low, but correcting the target and foregrounding BG3 still did not change menu state.
- Retina scaling remains measured and not the cause.
- System Events coordinate clicking is not usable here (`-25200`), while CGEvent posting returns success but still does not prove game consumption.
- The next viable path is to bypass UI input by reverse engineering the `continueGame` / `loadSaveGame` / `MainMenuConfirm` game-state path.

### RE Clues

Targeted binary strings include:

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

## 2026-05-16 — Enhanced CGEvent Click Probe

### Change

Updated `cg_click` to post a mouse-move event before mouse down/up and to set CoreGraphics mouse event fields:

- `kCGMouseEventButtonNumber = left`
- `kCGMouseEventClickState = 1`

Rationale: BG3/Noesis may track hover/cursor state from mouse-move events rather than trusting only the down-event location.

### Validation

Offline gate:

```bash
PYTHONPATH=tools python3 -m pytest tests/harness -q
build/bin/bg3se_test_tier0
PYTHONPATH=tools python3 -m bg3se_harness.tests_nexus
PYTHONPATH=tools python3 -m bg3se_harness.tests_wiki
```

Observed:

- Harness pytest: 36 passed.
- Tier 0 C tests: 41/41 passed.
- Nexus tests: 23 passed.
- Wiki tests: 23 passed.

Live command:

```bash
PYTHONPATH=tools python3 -m bg3se_harness launch --headless --continue --timeout 180
```

Observed:

- BG3 pid `34345`.
- `socket_listening` at `0.5s`.
- Watchdog attempts at about `30.3s`, `44.1s`, and `56.5s`.
- Attempted the same measured Continue coordinates:
  - `(829, 601)` from `{x=0.473, y=0.557}`
  - `(864, 601)` from `{x=0.500, y=0.557}`
  - `(829, 648)` from `{x=0.473, y=0.620}`
- CGEvent delivery still returned success.
- System Events `click at` still failed with `-25200`.
- Game state still did not advance; `menu_stalled` returned at `70.763s`.
- Headless graphics restored and BG3 was force-quit.
- A post-run process check found no BG3 or harness process still running.

Interpretation:

- Synthetic mouse delivery is now tested with activation, corrected coordinates, mouse move, click-state fields, and live Retina geometry. It still does not cause a menu state change.
- This satisfies the current click-diagnostics track enough to reject Retina scaling and simple CGEvent construction as the root cause.
- Remaining work should prioritize direct `continueGame` / `loadSaveGame` / `MainMenuConfirm` game-state invocation. The local Ghidra bridge was checked with `bg3se-harness ghidra status` and was not reachable, so xref work requires starting Ghidra/GhidraMCP or using another local disassembly route.

## 2026-05-16 — Boot Retry, Cancel, and Log Analysis

### Change

Added a higher-level boot attempt loop for foreground `launch` and `test`.

- `--headless` now defaults to one full boot retry (`--boot-retries 1`).
- Non-headless mode defaults to zero retries unless `--boot-retries N` is provided.
- `--timeout` is now accepted by `test` as a per-attempt socket health timeout.
- `--retry-delay` controls the pause between cancelled attempts.
- Retryable stages are `timeout` and `menu_stalled`.

When a retryable attempt fails, the harness now:

- captures the latest BG3SE log tail;
- extracts likely error/failure lines into `latest_log_analysis`;
- records menu geometry and OCR diagnostics;
- force-quits BG3;
- restores temporary headless graphics settings;
- relaunches cleanly.

JSON output now includes `boot_retries` and `boot_attempts`. Failed retry attempts include `retrying: true`, `diagnostics`, and `retry_cleanup` with cancel/restore results.

### Validation

Commands run:

```bash
PYTHONPATH=tools python3 -m py_compile tools/bg3se_harness/launch.py tools/bg3se_harness/cli.py tests/harness/test_cli.py
PYTHONPATH=tools python3 -m pytest tests/harness/test_launch.py tests/harness/test_cli.py -q
PYTHONPATH=tools python3 -m pytest tests/harness -q
build/bin/bg3se_test_tier0
PYTHONPATH=tools python3 -m bg3se_harness.tests_nexus
PYTHONPATH=tools python3 -m bg3se_harness.tests_wiki
```

Observed:

- Focused launch/CLI tests: 13 passed.
- Full harness pytest suite: 38 passed.
- Tier 0 C tests: 41/41 passed.
- Nexus client tests: 23 passed.
- Wiki client tests: 23 passed.
- Added unit coverage for `menu_stalled -> cancel -> restore -> relaunch -> socket_ready`.

### Remaining

This improves autonomous recovery and observability, but it does not solve the live BG3 menu-consumption blocker. The next functional step remains bypassing synthetic UI input via direct game-state save-load / Continue invocation.

## 2026-05-16 — Mod Inventory and Save-Load Preflight

### Context

The UI automation path now reaches the Mod Verification flow and can start a
save after the dialog's required mods are checked, but BG3 crashes after the save
loads. The faulting stack is in `gui::HotbarSystem::Update`, after `LevelLoaded`
and `GainedControl`, with no `libbg3se.dylib` frame on the top faulting stack.
The working hypothesis is inconsistent save/mod state, not a click-coordinate
problem.

### Changes

- Extended PAK `meta.lsx` parsing to include `Folder` and dependency
  `ModuleShortDesc` records.
- Added optional zstd CLI decompression for LSPK entries using compression type
  `3`; this allows save `.lsv` archives to expose `SaveInfo.json`.
- Added `save mods [--continue|NAME]` to infer save-required mods from
  decompressed `.lsv` archive markers.
- Added `mod verify --modsettings [--continue|--save NAME]` to verify active
  modsettings state against registry/install state and save-required markers.
- Added `mod verify --modsettings --expected-order order.json` for exact UUID
  order checks against a known expected order.
- Added `tools/bg3se_harness/mod_manager/inventory.py`.
- Added installed PAK scan:

```bash
PYTHONPATH=tools python3 -m bg3se_harness mod scan --installed
```

- Added registry reconciliation:

```bash
PYTHONPATH=tools python3 -m bg3se_harness mod reconcile --installed
PYTHONPATH=tools python3 -m bg3se_harness mod reconcile --installed --write
```

- Added mod-state preflight:

```bash
PYTHONPATH=tools python3 -m bg3se_harness mod preflight
```

- Wired preflight into real CLI `launch --continue`, `launch --save`, and
  `test` flows before build/patch/launch.
- Added `--no-mod-preflight` and debug-only `--accept-mod-verification`.
- Enhanced `crashlog` to parse macOS `.ips` crash reports, match the crashed PID
  to the right BG3SE session log, extract the enabled-mod block, and classify
  the hotbar crash phase.

### Live Findings

`mod scan --installed` found 14 installed PAKs and parsed all 14 successfully.

`mod reconcile --installed` reported:

- installed mods: 14
- registry-known mods: 4
- active `modsettings.lsx` entries: 11
- installed-but-unregistered mods: 10

Before registry reconciliation, `mod preflight` blocked the current save-load
state because six active mods were present in `modsettings.lsx` but missing from
the harness registry:

- `IN_Core_1_03`
- `HT_Camp Event Overhaul`
- `Better Inventory UI`
- `ACT1 Capes and Cloaks`
- `LIX_OriginDialogTags`
- `Facial Animations`

This confirmed the prior hypothesis in a form the harness can enforce: the save
load was not deterministic from the harness's point of view.

After running:

```bash
PYTHONPATH=tools python3 -m bg3se_harness mod reconcile --installed --write
```

the registry contains all 14 installed PAKs. `mod preflight` now exits 0 with:

- installed PAKs: 14
- registry-known mods: 14
- active `modsettings.lsx` entries: 11
- issues: 0

`save mods --continue` now identifies six high-confidence save-required mods
from UUID/folder markers in `meta.lsf`, `Globals.lsf`, and
`LevelCache/WLD_Main_A.lsf`:

- `IN_Core_1_03`
- `HT_Camp Event Overhaul`
- `Better Inventory UI`
- `ACT1 Capes and Cloaks`
- `LIX_OriginDialogTags`
- `Facial Animations`

It also reports `Waypoints` as a low-confidence candidate because only the
display name appeared in `Globals.lsf`; name-only hits are not treated as
required.

`mod verify --modsettings --continue` exits 0. It confirms the six
high-confidence save-required mods are active. It reports warnings, not errors,
for active dependency/SE mods that were not detected as direct save markers:
`Mod Configuration Menu`, `CommunityLibrary`, `5eSpells`, and
`Combat Extender`.

`crashlog --tail 10` now reports:

- latest `.ips`: `Baldur's Gate 3-2026-05-16-104739.ips`
- exception: `EXC_BAD_ACCESS / SIGSEGV`
- fault address: `0x10`
- faulting thread: `GameThread`
- top symbol: `gui::HotbarSystem::Update(...)`
- faulting stack contains `Baldur's Gate 3`, not `libbg3se.dylib`
- matched BG3SE log: `bg3se_2026-05-16_10-47-03.log`
- enabled mods extracted from that log: 11
- crash phase: `post_level_loaded_hotbar_update`

### Validation

Commands run:

```bash
PYTHONPATH=tools python3 -m pytest tests/harness/test_mod.py -q
PYTHONPATH=tools python3 -m pytest tests/harness/test_crashlog.py -q
PYTHONPATH=tools python3 -m pytest tests/harness -q
PYTHONPATH=tools python3 -m py_compile tools/bg3se_harness/mod_cli.py tools/bg3se_harness/cli.py tools/bg3se_harness/mod_manager/inventory.py tools/bg3se_harness/mod_manager/pak_inspector.py tools/bg3se_harness/mod_manager/installer.py
PYTHONPATH=tools python3 -m bg3se_harness mod scan --installed
PYTHONPATH=tools python3 -m bg3se_harness mod reconcile --installed
PYTHONPATH=tools python3 -m bg3se_harness mod reconcile --installed --write
PYTHONPATH=tools python3 -m bg3se_harness mod preflight
PYTHONPATH=tools python3 -m bg3se_harness save mods --continue
PYTHONPATH=tools python3 -m bg3se_harness mod verify --modsettings --continue
PYTHONPATH=tools python3 -m bg3se_harness crashlog --tail 10
```

Observed:

- Focused mod tests: 12 passed.
- Focused crashlog tests: 3 passed.
- Full harness pytest suite: 55 passed.
- Compilation check passed.
- `mod scan --installed`: exit 0, 14/14 PAKs parsed.
- `mod reconcile --installed`: exit 0, registry mismatch reported.
- `mod reconcile --installed --write`: exit 0, wrote 10 missing registry
  entries.
- `mod preflight`: exit 0 after reconciliation.
- `save mods --continue`: exit 0, six high-confidence save-required mods found,
  zero missing from active.
- `mod verify --modsettings --continue`: exit 0, zero issues and four warnings.
- `crashlog --tail 10`: exit 0, crash classified as
  `post_level_loaded_hotbar_update`.

### Remaining

- Add deterministic `modsettings.lsx` writer for a supplied exact UUID order.
- Re-run the headless save-load after preflight reports a complete mod state.
