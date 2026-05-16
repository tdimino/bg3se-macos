# Reconcile Mod State and Diagnose Hotbar Save-Load Crash

This ExecPlan is a living document. Sections Progress, Surprises &
Discoveries, Decision Log, and Outcomes & Retrospective must be kept up to date
as work proceeds.

## Purpose / Big Picture

The BG3SE macOS harness can now drive BG3 far enough to click through the main
menu and the Mod Verification dialog, but the loaded save crashes shortly after
control is gained. The evidence points away from coordinate automation and toward
an inconsistent mod state: BG3 enabled more mods from the Mod Verification dialog
than the harness registry knows about, then crashed in the vanilla UI hotbar
update path after the save loaded.

The goal of this plan is to make the harness deterministic about mod state before
launching a save. The harness should inventory installed `.pak` files, reconcile
them with its registry, generate or verify `modsettings.lsx`, compare that state
against the save's required mods, and fail early with a structured report when
the save cannot be loaded safely. The Mod Verification checkbox flow should
remain available only as an explicit debug escape hatch, not the default source
of truth.

The end-to-end target remains:

```bash
PYTHONPATH=tools python3 -m bg3se_harness test --headless --continue --tier 1
```

That command must either pass against a reconciled known-good save/mod set, or
fail before BG3 launch with a precise mod-state report. It must not require
manual checkbox clicks and must not silently continue into a known unsafe mod
configuration.

## Progress

- [x] (2026-05-16) Confirmed Retina/window geometry was not the remaining blocker.
- [x] (2026-05-16) Confirmed the harness can click the main-menu Continue button.
- [x] (2026-05-16) Confirmed the harness can click the Mod Verification Start Game button.
- [x] (2026-05-16) Confirmed the save proceeds only after Mod Verification entries are check-marked.
- [x] (2026-05-16) Captured crash evidence showing post-load `gui::HotbarSystem::Update` null dereference.
- [x] (2026-05-16) Implement installed `.pak` metadata scanning.
- [x] (2026-05-16) Reconcile installed mods with the harness registry.
- [x] (2026-05-16) Verify deterministic `modsettings.lsx` state, including exact UUID order when an expected-order JSON file is provided.
- [x] (2026-05-16) Extract or infer save-required mods and compare them to installed/enabled state.
- [x] (2026-05-16) Add launch preflight gate for unsafe mod state.
- [x] (2026-05-16) Add crash attribution for post-load hotbar crashes.
- [ ] Add compatibility bisection tasks for the suspect mod set.
- [ ] Re-run the end-to-end Tier 1 headless test with a reconciled mod/save set.

## Current Evidence

The crash reports at
`~/Library/Logs/DiagnosticReports/Baldur's Gate 3-2026-05-16-104432.ips` and
`~/Library/Logs/DiagnosticReports/Baldur's Gate 3-2026-05-16-104739.ips` both
show `EXC_BAD_ACCESS / SIGSEGV` on the BG3 GameThread, with top frames in
`gui::HotbarSystem::Update(...)`, `gui::GameUI::Update(...)`,
`ecl::UISystem`, `ecs::EntityWorld::Update`, and `App::Update`. The faulting
stack did not include `libbg3se.dylib`.

The matching BG3SE log showed the save loaded far enough for post-load game
events, including `LevelLoaded`, `GainedControl`, and discovery of six player
UUIDs. The crash occurred after the save was live, not while the harness was
clicking through menus.

The harness registry currently reports only four known mods:

- `5eSpells`
- `Combat Extender`
- `CommunityLibrary`
- `Mod Configuration Menu`

The BG3SE log for the successful click-through attempt reported eleven enabled
mods:

- `GustavX`
- `Mod Configuration Menu`
- `CommunityLibrary`
- `5eSpells`
- `Combat Extender`
- `IN_Core_1_03`
- `HT_Camp Event Overhaul`
- `Better Inventory UI`
- `ACT1 Capes and Cloaks`
- `LIX_OriginDialogTags`
- `Facial Animations`

The local Mods directory contains more installed `.pak` files than either list,
including additional likely participants such as `BetterTooltips`,
`MoreReactiveCompanions_Configurable`, `Highlight_North`, and `Waypoints`.

## Decision Log

Decision: Treat Mod Verification checkboxes as a symptom, not a fix.
Rationale: Clicking every checkbox lets BG3 mutate mod state at runtime, but the
harness cannot then explain or reproduce the state that loaded the save. The
default path must prepare `modsettings.lsx` deterministically before launch.
Date/Author: 2026-05-16 / Codex

Decision: Classify the observed crash as a post-load UI/mod-state crash until
new evidence shows otherwise.
Rationale: The faulting stack is in BG3's hotbar UI update after `LevelLoaded`
and `GainedControl`, with no Script Extender frame on the top faulting stack.
That strongly suggests missing, incompatible, or badly ordered hotbar/spell/item
references in the save.
Date/Author: 2026-05-16 / Codex

Decision: Keep the checkbox automation behind an explicit debug flag.
Rationale: The current flow is useful for exploration, but it should not mask
incomplete registry, missing dependencies, or unsafe save/mod combinations in
the autonomous test path.
Date/Author: 2026-05-16 / Codex

## Task Breakdown

### Task 1: Installed PAK Inventory

Implement a scanner that opens every `.pak` under
`~/Documents/Larian Studios/Baldur's Gate 3/Mods`, reads each package's
`Mods/<Folder>/meta.lsx`, and extracts at least UUID, folder, display name,
version, author, dependencies, and source path.

Implementation notes:

- Put parsing code near the existing mod-management modules under
  `tools/bg3se_harness/`.
- Prefer structured Larian LSX parsing over ad hoc text matching.
- Add fixture `.pak` or fixture `meta.lsx` tests so the scanner does not need
  the user's real Mods directory during unit tests.
- Expose a CLI shape such as:

```bash
PYTHONPATH=tools python3 -m bg3se_harness mod scan --installed
```

Acceptance criteria:

- The scan reports all locally installed `.pak` files, not just the four
  registry-known mods.
- Duplicate UUIDs, duplicate folders, missing `meta.lsx`, and unreadable
  packages are reported in structured JSON.

### Task 2: Registry Reconciliation

Add a reconciliation command that compares installed PAK metadata to the harness
registry and can write missing entries when requested.

Suggested CLI:

```bash
PYTHONPATH=tools python3 -m bg3se_harness mod reconcile --installed
PYTHONPATH=tools python3 -m bg3se_harness mod reconcile --installed --write
```

Acceptance criteria:

- The command identifies registry-known, installed-but-unregistered, and
  registry-orphaned mods.
- The registry can represent all mods BG3 enabled in the observed crash run.
- `mod list` clearly distinguishes `installed`, `registered`, and
  `in_load_order` state.

### Task 3: Deterministic `modsettings.lsx` Writer

Generate `modsettings.lsx` from a desired ordered UUID list and installed
metadata instead of relying on BG3's Mod Verification dialog.

Implementation notes:

- Preserve base game module entries such as `GustavX`.
- Write name, folder, UUID, version, and MD5 fields in the shape BG3 expects.
- Back up the user's previous `modsettings.lsx` before writing.
- Add a dry-run mode that reports the exact order and diff without writing.

Suggested CLI:

```bash
PYTHONPATH=tools python3 -m bg3se_harness mod order --write desired-mods.json
PYTHONPATH=tools python3 -m bg3se_harness mod verify --modsettings
```

Acceptance criteria:

- A launch after writing produces a BG3SE "Enabled Mods" block that exactly
  matches the desired order.
- BG3 does not present the Mod Verification dialog for a reconciled save.
- Load-order reset or unresolved-mod warnings are captured and surfaced as
  harness failures.

### Task 4: Save-Required Mod Extraction

Add a command that determines which mods a save requires and compares that list
to installed and enabled state.

Implementation notes:

- First attempt direct save metadata extraction from `.lsv` archives.
- If direct extraction is blocked, fall back to a documented inference path from
  BG3 logs, Mod Verification screenshots, or other available metadata.
- Report required, installed, enabled, missing, extra, and version-mismatched
  mods separately.

Suggested CLI:

```bash
PYTHONPATH=tools python3 -m bg3se_harness save mods --continue
PYTHONPATH=tools python3 -m bg3se_harness mod verify --save "Ebonlake Grotto - 27h 19m"
```

Acceptance criteria:

- The command identifies the eleven enabled mods observed in the 2026-05-16
  crash run, or explicitly states which entries could only be inferred.
- Extra installed PAKs that are not required by the save are reported without
  being enabled by default.

### Task 5: Launch Preflight Gate

Before `launch --continue`, `launch --save`, or `test --headless --continue`,
verify that the desired mod state is complete and deterministic.

Implementation notes:

- Abort before BG3 launch when required mods are missing, unregistered, disabled,
  duplicated, or in an unverified order.
- Print a structured remediation report with exact commands to scan, reconcile,
  and write the desired mod state.
- Keep current Mod Verification checkbox automation only behind an explicit flag
  such as `--accept-mod-verification`.

Acceptance criteria:

- The default headless launch refuses to proceed if the Mod Verification dialog
  is expected.
- The debug flag can still exercise the current checkbox path for research.
- Failed preflight does not start BG3, does not mutate `modsettings.lsx`, and
  exits with actionable JSON.

### Task 6: Crash Attribution for Hotbar Failures

Extend crash diagnostics so the harness can classify this failure mode without
manual `.ips` inspection.

Implementation notes:

- Parse the newest relevant `.ips` crash report.
- Extract faulting thread, exception type, top symbols, whether `libbg3se.dylib`
  appears on the faulting stack, and the nearest BG3SE log's enabled mod list.
- Parse recent Osiris/game milestones from the BG3SE log tail.
- Add a phase classifier for `post_level_loaded_hotbar_update`.

Suggested CLI:

```bash
PYTHONPATH=tools python3 -m bg3se_harness crashlog --json
```

Acceptance criteria:

- The 2026-05-16 crash is classified as a post-load hotbar UI crash.
- The report includes the enabled mod list and flags likely mod-state suspects
  without claiming proof beyond the evidence.

### Task 7: Compatibility Matrix and Bisection

Create repeatable mod-set scenarios to isolate whether the crash is caused by a
missing mod, a UI mod, a spell/combat mod, dependency order, or the save itself.

Suggested scenarios:

- Base game plus Script Extender only.
- Core dependency set: `Mod Configuration Menu`, `CommunityLibrary`, `IN_Core`.
- UI set: `Better Inventory UI`, `BetterTooltips`, and related UI mods.
- Spell/combat set: `5eSpells`, `Combat Extender`.
- Save-required set exactly as extracted from the save.
- Full installed set as a separate non-default stress run.

Suggested CLI:

```bash
PYTHONPATH=tools python3 -m bg3se_harness compat run hotbar-core
PYTHONPATH=tools python3 -m bg3se_harness compat matrix --save "Ebonlake Grotto - 27h 19m"
```

Acceptance criteria:

- Each run records mod order, BG3SE enabled-mod block, load milestone, crash
  classification, and exit status in JSON.
- The matrix can distinguish "save requires missing mod" from "specific enabled
  mod subset crashes after load."

### Task 8: Documentation Updates

Update the investigation docs so the next agent does not re-litigate coordinate
automation or load order relevance.

Required docs:

- `docs/bugs/headless-cli-goal-progress.md`
- New bug note, suggested path:
  `docs/bugs/hotbar-crash-after-mod-verification.md`
- This plan document.

Acceptance criteria:

- The docs record the exact crash signature, enabled mod list, registry mismatch,
  installed PAK count mismatch, and why the next work is mod-state reconciliation.
- The docs state that the mouse automation worked well enough to launch the save;
  the remaining crash is a post-load game/UI failure.

### Task 9: End-to-End Acceptance

Run the autonomous command after Tasks 1-8 are implemented:

```bash
PYTHONPATH=tools python3 -m bg3se_harness test --headless --continue --tier 1
```

Acceptance criteria:

- On a reconciled known-good save/mod set, the command reaches a loaded save,
  establishes socket responsiveness, runs Tier 1 checks, and exits cleanly.
- On an unsafe save/mod set, the command fails before launch with a structured
  mod-state report.
- The command no longer depends on manual Mod Verification checkbox clicks.

## Concrete Steps

Run all commands from
`/Users/tomdimino/Desktop/Programming/game-modding/bg3/bg3se-macos`.

Step 1: Re-read current mod-management code and tests.

```bash
rg -n "def cmd_mod|mod list|modsettings|registry|compat run|crashlog" tools tests docs
rg --files tools/bg3se_harness tests/harness | sort
```

Expected result: identify the exact modules to extend for scanning,
reconciliation, modsettings writing, crash attribution, and compatibility runs.

Step 2: Capture current state as JSON fixtures where possible.

```bash
PYTHONPATH=tools python3 -m bg3se_harness mod list --json
PYTHONPATH=tools python3 -m bg3se_harness crashlog --json
```

Expected result: baseline reports can be stored under a temporary artifact path
and used to verify that later commands report more complete mod state.

Step 3: Implement Task 1 and its unit tests.

Expected result: installed PAK scanning works without launching BG3 and reports
all installed mod packages.

Step 4: Implement Task 2 and update `mod list`.

Expected result: all installed PAKs can be represented in the harness registry,
with clear warnings for anything that cannot be safely enabled.

Step 5: Implement Task 3 with a dry run first.

Expected result: the harness can show the exact `modsettings.lsx` it intends to
write before touching the user's profile.

Step 6: Implement Task 4 and connect it to launch preflight.

Expected result: `launch --continue` can explain save-required mod mismatches
without starting BG3.

Step 7: Implement Task 5, preserving the existing checkbox path behind a debug
flag.

Expected result: the autonomous path stops treating the Mod Verification dialog
as a normal recovery step.

Step 8: Implement Tasks 6 and 7.

Expected result: when BG3 still crashes, the harness reports a classified
failure and can run a smaller compatibility matrix to isolate the suspect mod
subset.

Step 9: Update docs and run offline validation.

```bash
PYTHONPATH=tools python3 -m pytest tests/harness -q
PYTHONPATH=tools python3 -m py_compile tools/bg3se_harness/*.py
```

Expected result: tests pass and docs contain enough evidence for another agent
to continue without relying on chat history.

Step 10: Run live end-to-end validation only after preflight reports a complete
mod state.

```bash
PYTHONPATH=tools python3 -m bg3se_harness test --headless --continue --tier 1
```

Expected result: either a clean Tier 1 result or an early structured mod-state
failure. A post-load crash should now include a crash attribution report and a
specific compatibility matrix follow-up.

## Outcomes & Retrospective

Partial implementation is complete for the inventory, reconciliation, preflight,
and crash-attribution foundation.

Implemented commands:

```bash
PYTHONPATH=tools python3 -m bg3se_harness mod scan --installed
PYTHONPATH=tools python3 -m bg3se_harness mod reconcile --installed
PYTHONPATH=tools python3 -m bg3se_harness mod reconcile --installed --write
PYTHONPATH=tools python3 -m bg3se_harness mod preflight
PYTHONPATH=tools python3 -m bg3se_harness crashlog --tail 20
PYTHONPATH=tools python3 -m bg3se_harness save mods --continue
PYTHONPATH=tools python3 -m bg3se_harness mod verify --modsettings --continue
```

`launch` and `test` now run mod preflight before `--continue` or `--save` by
default when invoked through the real CLI parser. Use `--no-mod-preflight` to
skip this gate, or `--accept-mod-verification` as a debug escape hatch that
reports issues but does not block.

Live local validation showed:

- `mod scan --installed` found 14 installed PAKs.
- All 14 PAKs were parsed successfully from `meta.lsx`.
- `mod reconcile --installed` reported 14 installed mods, 4 registered mods,
  11 active mods in `modsettings.lsx`, and 10 installed-but-unregistered mods.
- `mod preflight` initially blocked the current save-load state because six
  active mods were present in `modsettings.lsx` but not known to the harness
  registry: `IN_Core_1_03`, `HT_Camp Event Overhaul`, `Better Inventory UI`,
  `ACT1 Capes and Cloaks`, `LIX_OriginDialogTags`, and `Facial Animations`.
- After running `mod reconcile --installed --write`, the registry contains all
  14 installed PAKs and `mod preflight` exits successfully with 14 registered
  mods, 11 active mods, and zero issues.
- `crashlog --tail 20` matched the latest macOS `.ips` report to
  `bg3se_2026-05-16_10-47-03.log`, extracted the 11 enabled mods, confirmed
  `libbg3se.dylib` was not on the faulting stack, and classified the crash as
  `post_level_loaded_hotbar_update`.
- The LSPK reader now supports compression type `3` via the local `zstd`
  binary, which is enough to extract `SaveInfo.json` from `.lsv` save archives.
  `SaveInfo.json` did not contain save-required mod metadata, but decompressed
  `.lsf` entries did contain UUID/folder markers.
- `save mods --continue` now infers six high-confidence save-required mods from
  `meta.lsf`, `Globals.lsf`, and `LevelCache/WLD_Main_A.lsf`: `IN_Core_1_03`,
  `HT_Camp Event Overhaul`, `Better Inventory UI`, `ACT1 Capes and Cloaks`,
  `LIX_OriginDialogTags`, and `Facial Animations`. The current active
  `modsettings.lsx` contains all six.
- `mod verify --modsettings --continue` exits successfully. It reports four
  warnings for active mods not detected as save markers (`Mod Configuration
  Menu`, `CommunityLibrary`, `5eSpells`, `Combat Extender`), which is expected
  for dependency/SE mods that are active but not found as direct save markers.
- `mod verify --modsettings --expected-order order.json` can now enforce exact
  UUID order against a user-provided JSON list.

Offline validation passed:

```bash
PYTHONPATH=tools python3 -m pytest tests/harness/test_mod.py -q
PYTHONPATH=tools python3 -m pytest tests/harness/test_crashlog.py -q
PYTHONPATH=tools python3 -m pytest tests/harness/test_savegames.py -q
PYTHONPATH=tools python3 -m pytest tests/harness -q
PYTHONPATH=tools python3 -m py_compile tools/bg3se_harness/mod_cli.py tools/bg3se_harness/cli.py tools/bg3se_harness/crashlog.py tools/bg3se_harness/mod_manager/inventory.py tools/bg3se_harness/mod_manager/pak_inspector.py tools/bg3se_harness/mod_manager/installer.py
```

Remaining work starts with a deterministic writer for exact `modsettings.lsx`
order and a live retest under the verified state. The harness can now explain
the save-required set and verify that all high-confidence save-required mods are
active before launch.
