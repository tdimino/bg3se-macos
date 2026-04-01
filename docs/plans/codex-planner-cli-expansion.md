# Expand bg3se-harness into a parity, compatibility, and mod-manager control plane

This ExecPlan is a living document. Sections Progress, Surprises &
Discoveries, Decision Log, and Outcomes & Retrospective must be
kept up to date as work proceeds.

## Purpose / Big Picture

The repository already has a real harness, not a placeholder: `tools/bg3se_harness/cli.py` registers 23 top-level commands, `tools/bg3se_harness/launch.py` can already launch with save-related flags, and `tools/bg3se_harness/menu.py` already automates part of the menu flow. The missing piece is that these features are still separate tools instead of one coherent control plane for parity closure, mod installation, save orchestration, compatibility testing, and developer ergonomics.

After this plan is implemented, a macOS mod author should be able to do four concrete things from one CLI. First, audit the remaining Windows parity gap with a machine-readable report instead of relying on memory. Second, install and enable a mod and its dependencies in a repeatable way. Third, restore a deterministic save, launch the game, run a scripted compatibility suite for a popular mod such as MCM, Community Library, 5e Spells, or Improved UI, and collect logs, screenshots, crashes, and assertions into a report bundle. Fourth, scaffold and preflight-check a macOS-targeted mod without needing to know the extender internals.

The easiest way to see the finished system working is this command sequence, all from the repository root: `PYTHONPATH=tools python3 -m bg3se_harness parity scan`, then `PYTHONPATH=tools python3 -m bg3se_harness mod install ...`, then `PYTHONPATH=tools python3 -m bg3se_harness save restore Harness_Base_Camp`, then `PYTHONPATH=tools python3 -m bg3se_harness compat run mcm`, then `PYTHONPATH=tools python3 -m bg3se_harness report bundle --latest`. Each command should emit JSON to standard output and leave a durable artifact on disk that a novice can inspect.

## Progress

- [x] (2026-04-01 03:03Z) Audited the current harness surface and confirmed that `tools/bg3se_harness/cli.py` defines 23 top-level commands.
- [x] (2026-04-01 03:03Z) Verified current repository evidence for menu automation, mod loading, `Ext.IO`, and `Ext.Json` so this plan does not propose duplicate work.
- [x] (2026-04-01 03:03Z) Identified developer-experience gaps that are not obvious from the user summary, including the missing packaged entry point for `bg3se-harness`.
- [x] (2026-04-01 03:03Z) Wrote this integrated execution plan to `docs/plans/codex-planner-cli-expansion.md`.
- [ ] Implement Phase 0 packaging, manifests, and baseline documentation updates.
- [ ] Implement Phase 1 `mod` and `save` primitives.
- [ ] Implement Phase 2 `compat` suites and scenario runner for popular mods.
- [ ] Implement Phase 3 parity-audit automation, remaining native hooks, and multiplayer sync coverage.
- [ ] Implement Phase 4 `doctor`, `author`, and reporting polish.
- [ ] Run end-to-end acceptance against at least MCM, Community Library, 5e Spells, and Improved UI.

## Surprises & Discoveries

Observation: the repository already contains working `Ext.IO` and `Ext.Json` implementations, so the gap is not a complete absence of these namespaces.
Evidence: `src/lua/lua_ext.c` implements `Ext.IO.LoadFile`, `Ext.IO.SaveFile`, `Ext.IO.AddPathOverride`, and `Ext.IO.GetPathOverride`; `src/lua/lua_json.c` implements `Ext.Json.Parse` and `Ext.Json.Stringify`; `src/injector/main.c` registers both modules during Lua initialization.

Observation: the harness already includes more save-launch automation than the user summary suggests.
Evidence: `tools/bg3se_harness/launch.py` already handles `-continueGame` and `-loadSaveGame`, and `tools/bg3se_harness/menu.py` already provides OCR-based detection, button clicks, waiting, and splash dismissal.

Observation: the mod manager work is planned in detail but does not yet exist as code.
Evidence: `docs/plans/2026-03-31-002-feat-menu-automation-mod-manager-plan.md` describes a `tools/bg3se_harness/mod_manager/` package, but that directory does not currently exist.

Observation: the CLI is described as `bg3se-harness`, but the repository does not currently provide a clean packaged entry point.
Evidence: `tools/bg3se_harness/__main__.py` imports `from bg3se_harness.cli import main`, yet `python3 -m tools.bg3se_harness --help` fails with `ModuleNotFoundError: No module named 'bg3se_harness'`, which means current usage depends on `PYTHONPATH=tools`.

Observation: implementation work must assume the harness files are already in flight and should not be overwritten casually.
Evidence: `git status --short` reports local modifications in `tools/bg3se_harness/cli.py`, `tools/bg3se_harness/launch.py`, and `tools/bg3se_harness/menu.py`.

## Decision Log

Decision: treat this document as the umbrella plan for CLI expansion instead of adding another isolated feature plan.
Rationale: the user asked for one proposal that covers parity closure, popular-mod automation, mod manager workflow, and macOS authoring experience; those concerns share the same command surface and artifacts.
Date/Author: 2026-04-01 / Codex

Decision: add distinct top-level command families instead of overloading the existing `test` command with every new responsibility.
Rationale: parity auditing, save management, mod installation, compatibility execution, and author tooling are different jobs with different failure modes and different JSON contracts.
Date/Author: 2026-04-01 / Codex

Decision: define parity as observable Windows-equivalent behavior, not just “there is a function with the right name.”
Rationale: the repository already demonstrates that docs and summaries can overstate coverage; the harness must verify function signatures, option handling, lifecycle timing, and save or network behavior in a live game session.
Date/Author: 2026-04-01 / Codex

Decision: make the compatibility system manifest-driven.
Rationale: MCM, Community Library, 5e Spells, and Improved UI require different save states, dependencies, assertions, and artifacts. Putting that knowledge in data files keeps Python orchestration small and keeps test cases reviewable.
Date/Author: 2026-04-01 / Codex

Decision: solve the packaging and entry-point issue early.
Rationale: a novice-guiding CLI cannot depend on remembering `PYTHONPATH=tools`, and every later phase becomes easier to test in CI once `bg3se-harness` is a real executable entry point.
Date/Author: 2026-04-01 / Codex

## Outcomes & Retrospective

This planning pass produced a single implementation narrative that incorporates the existing harness, the active menu and mod-manager design work, and the repository’s current native API state. The main correction made during planning is that `Ext.IO` and `Ext.Json` should be treated as parity-verification targets and signature-audit targets, not as greenfield module work.

Implementation is still pending. The next person who executes this plan should update Progress after every phase, add new discoveries as concrete evidence appears, and keep this file as the handoff artifact if the work spans multiple sessions.

## Context and Orientation

In this plan, the “harness” means the Python CLI under `tools/bg3se_harness/`. “Parity” means matching the Windows BG3 Script Extender behavior that Lua mods can observe. A “scenario” means a named automated play state made of a save, launch options, scripted Lua actions, and assertions. A “fixture” means an input artifact such as a `.pak` archive, an extracted mod tree, a baseline save, or an expected JSON result. A “catalog” means a machine-readable file that tells the harness where a mod comes from, which dependencies it has, which scenario it needs, and what success looks like.

The current command registration lives in `tools/bg3se_harness/cli.py`. Any new family such as `parity`, `mod`, `save`, `compat`, `report`, `doctor`, or `author` must be added there. The current launch and socket-health orchestration lives in `tools/bg3se_harness/launch.py`. The current regression-test parser lives in `tools/bg3se_harness/test_runner.py`. The current flag registry lives in `tools/bg3se_harness/flags.py`. The current menu automation lives in `tools/bg3se_harness/menu.py`. The current harness documentation lives in `docs/harness.md`.

The native mod detection and archive inspection logic already exists in `src/mod/mod_loader.c`, which reads `modsettings.lsx`, inspects the user Mods folder, and can look inside `.pak` archives for `ScriptExtender/Config.json`. The core Lua namespace implementation lives in `src/lua/lua_ext.c`. The JSON implementation lives in `src/lua/lua_json.c`. The main Lua module registration happens in `src/injector/main.c`. These native files matter because the CLI work is only useful if it can verify and, when necessary, drive the remaining native parity work.

The repository already contains useful seeds for automated mod testing. `test-mods/EntityTest/ScriptExtender/README.md` documents an in-repo diagnostic mod. `test-mods/MoreReactiveCompanions_Configurable.pak` is a real packaged mod artifact. `docs/supported-mods.md` documents current compatibility claims. `docs/crash-attribution.md` documents the runtime crash-attribution system that the planned reporting layer should consume instead of duplicating.

There is no packaged Python entry point at the root of the repository today. There is also no `tools/bg3se_harness/mod_manager/` package, no CLI save-management module, no compatibility catalog, no scenario manifest directory, and no report-bundling module. Those are the main missing code surfaces this plan adds.

## Plan of Work

Phase 0 establishes the control-plane foundation. Add a packaging file at the repository root such as `pyproject.toml` so `bg3se-harness` becomes a real console script while preserving `PYTHONPATH=tools python3 -m bg3se_harness` as the compatibility path during rollout. Add `tools/bg3se_harness/parity.py`, `tools/bg3se_harness/catalog/windows_parity_baseline.json`, `tools/bg3se_harness/catalog/popular_mods.json`, `tools/bg3se_harness/scenarios/`, and `tools/bg3se_harness/report_schema.json`. Extend `tools/bg3se_harness/config.py` with save, mod, cache, and report paths. Update `docs/harness.md` so the command list stops lagging behind the codebase.

The new command surface should be explicit and small enough to memorize. The intended shape is:

```text
bg3se-harness parity scan|missing|verify|record
bg3se-harness mod list|install|enable|disable|remove|order|info|search|pipeline
bg3se-harness save list|info|snapshot|restore|clone|delete|export|import
bg3se-harness compat list|prepare|run|matrix|resume
bg3se-harness report bundle|compare|publish
bg3se-harness doctor
bg3se-harness author new|check|package|watch|smoke
```

Phase 1 adds the mod-manager and save primitives that every later phase depends on. Implement `tools/bg3se_harness/mod_manager/__init__.py`, `tools/bg3se_harness/mod_manager/installer.py`, `tools/bg3se_harness/mod_manager/modsettings.py`, `tools/bg3se_harness/mod_manager/pak_inspector.py`, `tools/bg3se_harness/mod_manager/registry.py`, and `tools/bg3se_harness/savegames.py`. Reuse the existing ideas in `docs/plans/2026-03-31-002-feat-menu-automation-mod-manager-plan.md` instead of inventing a second design. The `mod` commands must install local artifacts first, support optional Nexus-backed search later, back up `modsettings.lsx` before every write, preserve the GustavX invariant, and emit JSON that can be consumed by `compat` and `report`. The `save` commands must treat saves as named fixtures, never overwrite a user save without making a backup copy, and support deterministic restore so the same mod suite can be rerun.

Phase 2 builds the autonomous compatibility runner. Implement `tools/bg3se_harness/compat.py` and teach it to compose `mod`, `save`, `launch`, `menu`, `test`, `events`, `screenshot`, and `crashlog`. The runner should execute a scenario manifest from `tools/bg3se_harness/scenarios/` and a mod catalog entry from `tools/bg3se_harness/catalog/popular_mods.json`. Each run should produce a report directory with the resolved mod list, the save used, the launch flags, the console transcript, recent event samples, screenshots, crash data if any, and the final pass or fail summary.

The first curated suites should cover the four mods the user named because they stress different parts of the extender. The MCM suite should verify IMGUI and event fallback behavior, mod-event round trips, and setting persistence across save restore. The Community Library suite should verify broad API compatibility claims, especially entity, template, and utility behavior that other mods inherit. The 5e Spells suite should restore a combat-capable save, verify added stats and passive data, cast a known spell list, and assert expected statuses or damage events. The Improved UI suite should verify that the mod loads cleanly, that the target UI state renders without obvious breakage, and that the report includes screenshots for human review because some UI failures are visual rather than textual.

Phase 3 turns the CLI into the parity-closing instrument rather than only a launcher. `tools/bg3se_harness/parity.py` should compare the live `Ext` table against `tools/bg3se_harness/catalog/windows_parity_baseline.json`, classify every expected function as implemented, stubbed, signature-mismatched, timing-sensitive, or missing, and then run targeted probes through the console to prove behavior. This phase is where the remaining native work gets driven. The parity report should call out exact owner files, such as `src/lua/lua_ext.c`, `src/lua/lua_json.c`, `src/network/`, `src/mod/mod_loader.c`, or other module sources, so the missing six percent stops being a vague backlog.

This phase also needs explicit coverage for multiplayer synchronization edge cases. Extend `tools/bg3se_harness/launch.py` and `tools/bg3se_harness/config.py` so the harness understands named profiles and can prepare host and client state separately. The first acceptable version may still run serially on one machine if true simultaneous dual-instance launch is unstable on macOS, but the CLI must at least record and compare mod manifests, script-extender versions, and network-relevant assertions so sync failures become reproducible. Once profile separation is stable, add a `compat run ... --multiplayer` mode that records host and client reports together.

Phase 4 improves the experience for macOS mod authors directly. Add `tools/bg3se_harness/doctor.py` to verify prerequisites such as BG3 paths, accessibility permissions, save paths, socket reachability, packaged entry point health, and writable report directories. Add `tools/bg3se_harness/authoring.py` with `author new` to scaffold `ScriptExtender/Config.json`, bootstrap Lua files, and a macOS-friendly folder layout; `author check` to lint for unsupported Windows-only APIs, missing dependencies, server or client context mistakes, and bad packaging; `author package` to validate a mod artifact before install; and `author smoke` to run a tiny launch-and-eval test against a chosen scenario. Extend `tools/bg3se_harness/watch.py` so it can optionally restore a scenario save and rerun a smoke suite on change instead of only re-evaluating a file.

Phase 5 is stabilization and acceptance. Wire all new JSON outputs into `tools/bg3se_harness/reporting.py` or a similarly named module so every command can attach a run ID and artifact directory. Add repository documentation under `docs/mod-compatibility/` explaining how to add a new mod catalog entry and a new scenario manifest. Update `docs/supported-mods.md` so compatibility claims are tied to recorded harness runs instead of manual notes.

## Concrete Steps

Run every command in this section from `/Users/tomdimino/Desktop/Programming/game-modding/bg3/bg3se-macos`.

The first step is to establish the baseline and fix the entry point. Create the packaging file, then confirm the old path and the new path both work.

```bash
cd /Users/tomdimino/Desktop/Programming/game-modding/bg3/bg3se-macos
PYTHONPATH=tools python3 -m bg3se_harness status
bg3se-harness status
```

The expected result is JSON from both commands with keys such as `game_running`, `socket_alive`, and `patched`. The second command currently fails before implementation and should become the proof that packaging is complete.

The second step is to add the parity manifest and reporting skeleton before adding more commands.

```bash
cd /Users/tomdimino/Desktop/Programming/game-modding/bg3/bg3se-macos
PYTHONPATH=tools python3 -m bg3se_harness parity scan --format json
PYTHONPATH=tools python3 -m bg3se_harness parity missing
```

The expected result is a JSON document that includes a total expected function count, implemented count, missing count, and a per-namespace breakdown. The text form should call out exact functions and owner files instead of saying only “some gaps remain.”

The third step is to add save and mod primitives and prove they are safe.

```bash
cd /Users/tomdimino/Desktop/Programming/game-modding/bg3/bg3se-macos
PYTHONPATH=tools python3 -m bg3se_harness save list
PYTHONPATH=tools python3 -m bg3se_harness save snapshot Harness_Base_Camp
PYTHONPATH=tools python3 -m bg3se_harness mod install test-mods/MoreReactiveCompanions_Configurable.pak
PYTHONPATH=tools python3 -m bg3se_harness mod enable MoreReactiveCompanions_Configurable
PYTHONPATH=tools python3 -m bg3se_harness mod list
```

The expected result is that the save commands report a fixture path and backup path, and the mod commands report install status, UUID or folder identity if known, enabled state, dependency status, and the backed-up `modsettings.lsx` path.

The fourth step is to wire in compatibility scenarios.

```bash
cd /Users/tomdimino/Desktop/Programming/game-modding/bg3/bg3se-macos
PYTHONPATH=tools python3 -m bg3se_harness compat list
PYTHONPATH=tools python3 -m bg3se_harness compat prepare mcm
PYTHONPATH=tools python3 -m bg3se_harness compat run mcm --scenario Harness_Base_Camp
PYTHONPATH=tools python3 -m bg3se_harness report bundle --latest
```

The expected result is JSON that names the scenario, the mods installed for the run, the assertions executed, the pass or fail summary, and the artifact directory. The report bundle should contain logs, console output, screenshots if configured, crash data if any, and a machine-readable summary file.

The fifth step is to extend coverage to the named popular mods and then to a matrix.

```bash
cd /Users/tomdimino/Desktop/Programming/game-modding/bg3/bg3se-macos
PYTHONPATH=tools python3 -m bg3se_harness compat run community-library --scenario Harness_Base_Camp
PYTHONPATH=tools python3 -m bg3se_harness compat run 5e-spells --scenario Harness_Combat_Spellcast
PYTHONPATH=tools python3 -m bg3se_harness compat run improved-ui --scenario Harness_UI_Inventory
PYTHONPATH=tools python3 -m bg3se_harness compat matrix --suite popular
```

The expected result is one report per run plus a matrix summary that says which mods passed, which failed, which assertions failed, and whether the failure looks native, packaging-related, or visual-only.

The sixth step is to ship the author-facing tooling and prove the novice path.

```bash
cd /Users/tomdimino/Desktop/Programming/game-modding/bg3/bg3se-macos
PYTHONPATH=tools python3 -m bg3se_harness doctor
PYTHONPATH=tools python3 -m bg3se_harness author new MyMacTestMod
PYTHONPATH=tools python3 -m bg3se_harness author check MyMacTestMod
PYTHONPATH=tools python3 -m bg3se_harness author smoke MyMacTestMod --scenario Harness_Base_Camp
```

The expected result is that `doctor` reports a clean environment or explicit actionable failures, `author new` creates a valid mod skeleton, `author check` emits zero errors for the scaffold, and `author smoke` produces a short pass or fail report against a deterministic scenario.

## Validation and Acceptance

The plan is successful only if the CLI makes the remaining parity gap observable, repeatable, and actionable. `PYTHONPATH=tools python3 -m bg3se_harness parity scan` must produce a stable JSON snapshot that can be compared across commits and that distinguishes between missing functions, stubs, and signature or timing mismatches. A namespace cannot be called “complete” anymore unless `parity verify --namespace <name>` passes.

The mod-manager pipeline is accepted only if a novice can install a mod from a local artifact, enable it, restore the required save, launch the game, run the suite, and obtain a bundle without hand-editing `modsettings.lsx`. `mod install`, `mod enable`, `save restore`, `compat run`, and `report bundle` must compose without requiring shell glue code.

Autonomous popular-mod testing is accepted only if there are first-class catalog entries and scenarios for MCM, Community Library, 5e Spells, and Improved UI, and each one has a deterministic report. MCM must prove event and settings behavior. Community Library must prove shared dependency behavior. 5e Spells must prove spell-data and combat assertions. Improved UI must prove load health and capture screenshots so UI regressions can be reviewed by a human.

Developer experience is accepted only if a fresh user can run `bg3se-harness doctor`, then `bg3se-harness author new`, then `bg3se-harness author check`, then `bg3se-harness author smoke`, and receive explicit next steps instead of silent failure. The final documentation in `docs/harness.md` and `docs/supported-mods.md` must reference these commands directly.

## Idempotence and Recovery

Every write path in this plan must be safely repeatable. `mod install` must hash or otherwise identify the artifact and skip duplicate installs unless the user asks for replacement. Any command that edits `modsettings.lsx` must create a timestamped backup first and must be able to restore the previous file if validation fails. `save snapshot` must create new fixture directories rather than mutating a baseline in place. `save restore` must copy from a fixture into the active save location and preserve the overwritten save as a backup unless the user explicitly asks for destructive mode.

Reporting must be additive. A new report run should create a new run directory under a harness-owned reports path and then update a `latest` symlink or pointer, not overwrite prior evidence. Compatibility runs should preserve enough metadata to be rerun later with the same mod artifacts, save fixture, and launch flags.

Rollback paths must be obvious. `mod disable` and `mod remove` should restore the previous mod state. `save restore --from-backup` should reverse the last save operation. `report bundle --latest` should never destroy a prior run. The existing `patch` and `unpatch` commands remain the recovery mechanism for the binary itself and should be referenced by the new commands rather than duplicated.

## Interfaces and Dependencies

The implementation should stay mostly in the Python standard library. `argparse`, `json`, `pathlib`, `subprocess`, `shutil`, `hashlib`, `tempfile`, `xml.etree.ElementTree`, `zipfile`, and `plistlib` are sufficient for most of the command surface. Optional dependencies should remain optional. A Nexus API key may unlock remote install flows, but the local-artifact path must work with no network. An optional `lz4` helper may be useful for some `.pak` internals, but the CLI should degrade gracefully when only metadata extraction is needed.

The key Python interfaces that must exist at completion are small and explicit:

```python
def scan_parity() -> dict: ...
def verify_namespace(namespace: str) -> dict: ...
def install_mod(source: str, enable: bool = True) -> dict: ...
def set_mod_enabled(name: str, enabled: bool) -> dict: ...
def snapshot_save(name: str) -> dict: ...
def restore_save(name: str) -> dict: ...
def run_compat_suite(mod_id: str, scenario: str, multiplayer: bool = False) -> dict: ...
def bundle_report(run_id: str | None = None) -> dict: ...
def doctor() -> dict: ...
def scaffold_mod(name: str) -> dict: ...
def check_mod(path: str) -> dict: ...
```

The machine-readable files should also have stable contracts. `tools/bg3se_harness/catalog/windows_parity_baseline.json` should define expected namespaces, functions, signatures, and notes about Windows-only behavior. `tools/bg3se_harness/catalog/popular_mods.json` should define each mod’s display name, local artifact path or resolver, dependencies, required scenario, and assertions. `tools/bg3se_harness/scenarios/*.json` should define the save fixture, launch flags, menu actions if any, Lua probes, screenshot checkpoints, and pass or fail rules. The report summary file should record the git revision, active mods, save fixture, command line, assertion results, and artifact paths.

The native side dependencies are the existing sources already responsible for mod loading and Lua APIs. If the parity scan exposes missing `Ext.*` behavior, the likely owner files are `src/lua/lua_ext.c`, `src/lua/lua_json.c`, the relevant namespace sources under `src/lua/`, `src/mod/mod_loader.c`, and the networking sources under `src/network/`. The CLI should always name those owner files in its parity output so the next fix is obvious.
