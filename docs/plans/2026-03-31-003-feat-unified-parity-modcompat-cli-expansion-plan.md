---
title: "feat: Unified parity closure, mod compatibility, and CLI expansion"
type: feat
status: active
date: 2026-03-31
---

# feat: Unified parity closure, mod compatibility, and CLI expansion

## Overview

One plan to rule them all. Consolidates three research streams into a single actionable roadmap:

1. **CLI expansion** — 7 new command families (~35 subcommands) completing the bg3se-harness as a full modding control plane
2. **Mod compatibility** — Priority testing of MCM (the gate for 500+ configurable mods), Community Library, Combat Extender, and the top 20 BG3SE mods
3. **Mod manager integration** — CLI wrapping ShaiLaric's BG3MacModManager repo (not reimplementing), with pure-Python fallback for headless/CI use

The end state: `bg3se-harness mod install mcm && bg3se-harness compat run mcm && bg3se-harness report bundle` — fully autonomous mod testing from one CLI.

## Problem Statement

**At 94% Windows BG3SE parity, the remaining 6% is invisible.** No machine-readable audit exists. The `docs/supported-mods.md` file says ~82% parity (stale — CLAUDE.md says ~94%). Compatibility claims are manual notes, not test results.

**MCM is the gate.** 8 of the top 20 mods require it. Hundreds more depend on it. MCM is pure Lua (18,000 lines) — if our Metal IMGUI backend works, the entire configurable mod ecosystem opens up. But we've never tested it.

**No mod lifecycle from the CLI.** Installing, enabling, and testing mods requires manual file copying and XML editing. ShaiLaric's BG3MacModManager provides a GUI, but there's no headless path for CI or autonomous pipelines.

**ShaiLaric maintains BG3MacModManager independently.** Our CLI should delegate to the upstream binary (when installed) rather than reimplementing PAK reading and modsettings.lsx manipulation. This keeps ShaiLaric's repo as the source of truth for mod management logic, and our CLI as the automation layer on top.

## Proposed Solution

### Architecture: Delegate to BG3MacModManager, Fallback to Pure Python

```
bg3se-harness mod install <source>
    │
    ├── BG3MacModManager installed?
    │   ├── YES → delegate to BG3MacModManager CLI/binary
    │   │         (same paths, same modsettings.lsx format, same conventions)
    │   │
    │   └── NO → pure Python fallback
    │            (pak_inspector.py, modsettings.py — stdlib only)
    │
    └── Either path → update mod_registry.json + emit JSON to stdout
```

**Why this architecture:**
- ShaiLaric can update BG3MacModManager independently; our CLI picks up changes
- Pure Python fallback ensures headless/CI works without the GUI app
- Shared conventions (paths, modsettings.lsx format, registry location) prevent conflicts
- The C-side PAK reader (`src/pak/pak_reader.c`) is the reference for the Python port

### New CLI Surface (7 command families)

```
bg3se-harness parity scan              # Compare live Ext table vs Windows baseline → JSON
bg3se-harness parity missing           # List functions present in Windows but absent here
bg3se-harness parity verify <ns>       # Deep-verify a namespace (run Lua probes)

bg3se-harness mod list                 # Installed mods with enabled/SE status
bg3se-harness mod install <source>     # Local .pak, directory, or nexus:ID
bg3se-harness mod enable <name>        # Toggle in modsettings.lsx
bg3se-harness mod disable <name>       # Toggle in modsettings.lsx
bg3se-harness mod remove <name>        # Uninstall + cleanup
bg3se-harness mod order --move X --before Y  # Reorder load order
bg3se-harness mod info <name>          # Metadata from PAK + registry
bg3se-harness mod search <query>       # Nexus Mods API search
bg3se-harness mod backup               # Backup modsettings.lsx

bg3se-harness save list                # Available saves with timestamps
bg3se-harness save snapshot <name>     # Create named fixture from current save
bg3se-harness save restore <name>      # Restore a fixture (backup first)
bg3se-harness save clone <src> <dst>   # Copy save under new name

bg3se-harness compat list              # Available test scenarios
bg3se-harness compat run <scenario>    # Install mods + restore save + launch + test + report
bg3se-harness compat matrix            # Run all scenarios, output summary table

bg3se-harness report bundle [--latest] # Bundle logs, screenshots, crash data into report dir
bg3se-harness report compare <a> <b>   # Diff two report bundles

bg3se-harness doctor                   # Verify paths, permissions, SE status, saves, socket

bg3se-harness author new <name>        # Scaffold mod (Config.json + BootstrapServer.lua)
bg3se-harness author check <path>      # Lint for Windows-only APIs, missing deps
bg3se-harness author smoke <path>      # Quick launch-and-eval test
```

## Technical Approach

### Mod Manager: Two-Tier Architecture

**Tier 1 — BG3MacModManager delegation** (preferred when available):

```python
# tools/bg3se_harness/mod_manager/__init__.py
def get_backend():
    """Return BG3MacModManager backend if installed, else pure Python."""
    mmgr_path = _find_bg3macmodmanager()
    if mmgr_path:
        return MacModManagerBackend(mmgr_path)
    return PythonBackend()
```

The CLI wraps BG3MacModManager's binary for PAK install, modsettings.lsx manipulation, and profile management. ShaiLaric's repo is the upstream — we depend on it, not fork it. The CLI adds:
- JSON output (BG3MacModManager is GUI-focused)
- Headless operation for CI
- Integration with compat/parity/report commands

**Tier 2 — Pure Python fallback** (headless/CI, no GUI app):

```
tools/bg3se_harness/
├── mod_manager/
│   ├── __init__.py          # Backend selection + public API facade
│   ├── backend_mmgr.py      # BG3MacModManager delegation
│   ├── backend_python.py    # Pure Python fallback
│   ├── pak_inspector.py     # LSPK v18 reader (port from src/pak/pak_reader.c)
│   ├── modsettings.py       # ElementTree XML r/w (backup-before-write)
│   ├── registry.py          # JSON mod registry (~200 entries max)
│   ├── nexus.py             # Nexus Mods API (urllib, premium-gate fallback)
│   └── resolver.py          # Single-level dependency resolution
```

**Key paths** (shared with BG3MacModManager):
- Mods: `~/Documents/Larian Studios/Baldur's Gate 3/Mods/`
- modsettings.lsx: `~/Documents/.../PlayerProfiles/Public/modsettings.lsx`
- Registry: `~/.config/bg3se-harness/mod_registry.json`
- SE dylib: `...Baldur's Gate 3.app/Contents/MacOS/libbg3se.dylib`
- SE logs: `~/Library/Application Support/BG3SE/logs/`

**modsettings.lsx invariant:** GustavX (`28ac9ce2-2aba-8cda-b3b5-6e922f71b6b8`) is never removed, always at position 0.

### Parity Audit

```
tools/bg3se_harness/
├── parity.py                # Compare live Ext table vs baseline
├── catalog/
│   ├── windows_parity_baseline.json  # Expected Windows API surface
│   └── popular_mods.json             # MCM, CL, Combat Extender, etc.
```

The parity scan works in two modes:
1. **Static** (`parity scan`): Introspect the live `Ext` table via console (`Ext.Types.GetAllTypes()`) and compare against `windows_parity_baseline.json`
2. **Deep** (`parity verify <namespace>`): Run targeted Lua probes through the console to verify behavior, not just function existence

**Discovery from this session:** `Ext.IO` (4 functions) and `Ext.Json` (2 functions) are already fully implemented in `src/lua/lua_ext.c` and `src/lua/lua_json.c`. They're audit targets, not greenfield work.

### Compatibility Runner

```
tools/bg3se_harness/
├── compat.py                # Scenario orchestrator
├── scenarios/
│   ├── mcm.json             # MCM: IMGUI widgets, keybinds, config persistence
│   ├── community_library.json  # CL: entity, stats, template, utility APIs
│   ├── combat_extender.json    # CE: stats mutation + MCM settings
│   └── improved_ui.json        # ImpUI: clean load + screenshot comparison
```

Each scenario manifest specifies:
- Required mods (resolved via `mod install`)
- Save fixture to restore
- Launch flags
- Lua assertions to run post-load
- Screenshot checkpoints for visual verification
- Pass/fail criteria

The runner composes existing commands: `mod install` → `save restore` → `launch` → `menu click` → `test` → `events` → `screenshot` → `crashlog` → `report bundle`.

### Doctor

Single command verifying all prerequisites:
- BG3 app bundle exists at expected path
- SE dylib deployed and signed
- Accessibility permission granted (for menu automation)
- Screen Recording permission (for screenshots)
- Socket path writable
- Save directory accessible
- modsettings.lsx readable
- BG3MacModManager installed? (optional, reports version)

## Mod Compatibility Priority Matrix

### The Gates (P0)

| Mod | Endorsements | SE APIs | Why P0 |
|-----|-------------|---------|--------|
| MCM | 12,100+ | **Ext.IMGUI** (heavy), Ext.Net, Ext.Vars, Ext.ModEvents | 500+ mods depend on it |
| Community Library | 13,351 | Ext.Stats, Entity, Osiris, Events, ModEvents | Dependency for hundreds of mods |

### High Priority (P1)

| Mod | Endorsements | SE APIs | Risk |
|-----|-------------|---------|------|
| Combat Extender | 8,000+ | Stats, Entity, Osiris + MCM | Most popular gameplay mod |
| Camp Event Notifications | 4,000+ | Events, Osiris, **IMGUI** | Tests IMGUI notifications |
| Auto Send Food To Camp | 3,000+ | Osiris, Events, Vars + MCM | Simple MCM smoke test |

### Standard Priority (P2)

| Mod | SE APIs | Notes |
|-----|---------|-------|
| Configurable Enemies | Stats, Entity + MCM | Stress-tests Stats + MCM |
| Smart Autosaving | Timer, Events, Vars + MCM | Tests Timer persistence |
| Randomised Equipment Loot | Stats, Entity + MCM | Stats mutation under load |
| Spell Points 5e | Stats, Entity + MCM | Alternative spell system |

### Low Risk (P3 — likely work already)

Always Show Approvals, AI Allies, Additional Spell Interactions, Extend Party Limit, Ambient AI, Preemptively Label Containers — all use only foundational APIs (Osiris, Entity, Events) where we have strong parity.

## API Risk Assessment

| Subsystem | Risk | Reason | Mitigation |
|-----------|------|--------|------------|
| Ext.IMGUI on Metal | **MEDIUM** | MCM uses 15+ widget types, dynamic layouts | `compat run mcm` with screenshot comparison |
| Keyboard input (CGEventTap) | **MEDIUM** | MCM keybinding system, INSERT default | Test INSERT + custom rebinding in MCM |
| Generated component offsets | **SILENT** | 293 layouts may have ARM64 mismatches | `parity verify entity` with field value assertions |
| Ext.Net (multiplayer) | **MEDIUM** | RakNet backend minimally tested | `compat run mcm --multiplayer` (Phase 3) |
| Ext.Timer persistence | **LOW** | Smart Autosaving depends on save/load | `compat run smart_autosaving` |
| CJK font rendering | **LOW** | MCM localization may show boxes | Visual screenshot check |

## Acceptance Criteria

### Mod Manager
- [ ] `mod list` shows installed mods with enabled/SE status, JSON output
- [ ] `mod install <path.pak>` installs local PAK, updates modsettings.lsx (backup first)
- [ ] `mod enable/disable <name>` toggles mod in modsettings.lsx
- [ ] `mod info <name>` shows metadata from PAK (meta.lsx)
- [ ] `mod search <query>` searches Nexus Mods API (Premium: download; Free: browser URL)
- [ ] `mod order --move X --before Y` reorders load order
- [ ] `mod backup` creates timestamped modsettings.lsx backup
- [ ] GustavX invariant preserved in all modsettings.lsx writes
- [ ] Delegates to BG3MacModManager when installed; pure Python fallback when not
- [ ] All output is JSON to stdout

### Parity Audit
- [ ] `parity scan` returns JSON with implemented/missing/stubbed function counts per namespace
- [ ] `parity missing` lists specific missing functions with owner file paths
- [ ] `parity verify <ns>` runs Lua probes and reports behavioral mismatches
- [ ] `windows_parity_baseline.json` covers all Ext.* namespaces from Windows BG3SE

### Compatibility Runner
- [ ] `compat run mcm` autonomously: install MCM → restore save → launch → verify IMGUI → report
- [ ] `compat run community_library` tests entity, stats, template APIs
- [ ] `compat matrix` runs all scenarios, outputs pass/fail summary table
- [ ] Each run produces a report directory with logs, screenshots, crash data, assertions

### Save Management
- [ ] `save list` shows saves with timestamps and sizes
- [ ] `save snapshot <name>` creates named fixture (never overwrites without backup)
- [ ] `save restore <name>` restores fixture for deterministic testing

### Doctor
- [ ] `doctor` verifies all prerequisites and outputs JSON diagnostic report
- [ ] Reports BG3MacModManager installation status and version

### Author Tools
- [ ] `author new <name>` scaffolds mod with Config.json + BootstrapServer.lua
- [ ] `author check <path>` lints for Windows-only APIs and missing dependencies

### Infrastructure
- [ ] Pure Python, stdlib only (except optional LZ4 for some PAK files)
- [ ] All commands follow existing pattern: JSON stdout, stderr narration, return 0/1
- [ ] CLI registration follows ghidra/menu subcommand group pattern

## Implementation Units

### Unit 1: Config + packaging + catalog structure
- **Goal**: Extend config.py with save/mod/report paths, create catalog/ and scenarios/ directories
- **Files**: `config.py` (extend), `catalog/windows_parity_baseline.json` (NEW), `catalog/popular_mods.json` (NEW), `scenarios/` (NEW dir)
- **Verification**: `import bg3se_harness` works; catalog files parseable

### Unit 2: PAK inspector (pure Python LSPK v18 reader)
- **Goal**: Python port of `src/pak/pak_reader.c` — read PAK metadata, list files, extract meta.lsx
- **Files**: `mod_manager/pak_inspector.py` (NEW)
- **Patterns to follow**: `src/pak/pak_reader.c` for format details, `lib/lz4/lz4.c` for decompression
- **Verification**: Read `test-mods/MoreReactiveCompanions_Configurable.pak` metadata

### Unit 3: modsettings.lsx manipulation
- **Goal**: ElementTree-based modsettings.lsx reader/writer with backup-before-write
- **Files**: `mod_manager/modsettings.py` (NEW)
- **Execution note**: Use `xml.etree.ElementTree` (proper XML), not string parsing like the C side
- **Verification**: Add/remove a mod, verify GustavX stays at position 0, backup created

### Unit 4: Mod registry + BG3MacModManager backend
- **Goal**: JSON registry for state tracking + delegation layer for BG3MacModManager
- **Files**: `mod_manager/__init__.py` (NEW), `mod_manager/registry.py` (NEW), `mod_manager/backend_mmgr.py` (NEW), `mod_manager/backend_python.py` (NEW)
- **Verification**: `mod list` works with both backends; `mod install local.pak` succeeds

### Unit 5: Register `mod` CLI command group
- **Goal**: All mod subcommands wired in cli.py
- **Files**: `cli.py` (extend)
- **Patterns to follow**: `ghidra` and `menu` subcommand group patterns
- **Verification**: `bg3se-harness mod --help` shows all subcommands; end-to-end install+enable+list

### Unit 6: Nexus Mods API client
- **Goal**: Search, download (Premium), URL fallback (free)
- **Files**: `mod_manager/nexus.py` (NEW)
- **Verification**: `mod search "Community Library"` returns results

### Unit 7: Save management
- **Goal**: List, snapshot, restore, clone saves as named fixtures
- **Files**: `savegames.py` (NEW), `cli.py` (extend)
- **Verification**: `save list` returns saves; `save snapshot` + `save restore` round-trips

### Unit 8: Parity audit
- **Goal**: Compare live Ext table against Windows baseline, report gaps
- **Files**: `parity.py` (NEW), `catalog/windows_parity_baseline.json` (populate), `cli.py` (extend)
- **Execution note**: Requires running game for live scan; static analysis of baseline is offline
- **Verification**: `parity scan` returns JSON with per-namespace counts; `parity missing` lists gaps

### Unit 9: Compatibility runner
- **Goal**: Scenario orchestrator composing mod+save+launch+test+report
- **Files**: `compat.py` (NEW), `scenarios/mcm.json` (NEW), `scenarios/community_library.json` (NEW), `cli.py` (extend)
- **Verification**: `compat run mcm` executes end-to-end (may fail on IMGUI — that's useful data)

### Unit 10: Doctor + report bundle
- **Goal**: Prerequisite verifier + report aggregator
- **Files**: `doctor.py` (NEW), `reporting.py` (NEW), `cli.py` (extend)
- **Verification**: `doctor` returns JSON with all checks; `report bundle` creates directory

### Unit 11: Author tools
- **Goal**: Scaffold mod, lint for macOS issues, quick smoke test
- **Files**: `authoring.py` (NEW), `cli.py` (extend)
- **Patterns to follow**: `test-mods/EntityTest/` for scaffold template
- **Verification**: `author new TestMod` creates valid mod skeleton; `author check` finds planted issues

### Unit 12: Documentation + skill update
- **Goal**: Update CLAUDE.md (30+ commands), SKILL.md, supported-mods.md, CHANGELOG.md
- **Files**: CLAUDE.md, SKILL.md, docs/supported-mods.md, docs/CHANGELOG.md
- **Verification**: All new commands documented; parity percentage updated

## Scope Boundaries

**In scope:**
- All 7 command families and ~35 subcommands
- BG3MacModManager delegation + pure Python fallback
- P0/P1 mod compatibility scenarios (MCM, Community Library, Combat Extender)
- Parity audit against Windows baseline
- Save fixture management
- Doctor and report bundling
- Mod authoring scaffold + lint

**Out of scope:**
- Full GUI mod manager (BG3MacModManager covers this)
- Transitive dependency resolution (single-level only)
- Mod compilation or PAK creation (author tools scaffold only)
- Steam Workshop integration
- Mixed-platform multiplayer testing (macOS + Windows simultaneous)
- Vortex mod manager integration (not on macOS)
- Native Mod Loader compatibility (Windows-only DLL injection)

## Dependencies & Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| MCM fails on Metal IMGUI | Medium | **Critical** — blocks 500+ mods | `compat run mcm` with screenshots; fix IMGUI issues first |
| BG3MacModManager binary not available | High | Medium | Pure Python fallback is full-featured |
| BG3MacModManager API changes | Low | Medium | Pin to known version; fallback to Python |
| LZ4-compressed PAK entries | Medium | Low | Optional LZ4; graceful skip for compressed entries |
| Nexus API rate limiting | Low | Low | Track X-RL-Remaining headers; warn at <10 |
| modsettings.lsx format changes | Low | High | Always backup; validate after write |
| Component offset mismatches (silent) | Medium | Medium | `parity verify entity` with field assertions |
| Windows baseline incomplete | Medium | Medium | Start with documented APIs; expand iteratively |

## Sources & References

### Research (this session)
- **Codex Planner** (GPT-5.4-pro): 7 command families, 5-phase roadmap, discovered Ext.IO/Json already implemented → `docs/plans/codex-planner-cli-expansion.md`
- **Nomos mod research**: Top 20 BG3SE mods, MCM deep analysis, BG3MacModManager integration → `.subdaimon-output/nomos-mod-compatibility-blueprint.md`
- **Repo research analyst**: Full CLI pattern analysis, test infrastructure, config patterns, existing plan consolidation

### Prior Plans (consolidated into this one)
- `docs/plans/2026-03-31-002-feat-menu-automation-mod-manager-plan.md` — mod manager package design (6 files)
- `docs/plans/codex-planner-cli-expansion.md` — 7 command families, 5-phase implementation

### Internal References
- `tools/bg3se_harness/cli.py` — CLI registration pattern (ghidra/menu subcommand groups)
- `src/pak/pak_reader.c` — C-side LSPK v18 reader (reference for Python port)
- `src/mod/mod_loader.c` — C-side mod detection (modsettings.lsx parsing)
- `src/lua/lua_ext.c:83-148` — Ext.IO implementation (LoadFile, SaveFile, AddPathOverride, GetPathOverride)
- `src/lua/lua_json.c` — Ext.Json implementation (Parse, Stringify)
- `test-mods/EntityTest/` — Mod scaffold template
- `test-mods/MoreReactiveCompanions_Configurable.pak` — Test PAK artifact
- `docs/crash-attribution.md` — Crash attribution system (compat reports should consume this)

### External References
- ShaiLaric/BG3MacModManager: https://github.com/ShaiLaric/BG3MacModManager
- Nexus Mods API: https://app.swaggerhub.com/apis-docs/NexusMods/nexus-mods_public_api_params_in_form_data/1.0
- AtilioA/BG3-MCM: https://github.com/AtilioA/BG3-MCM (18,000 lines Lua, AGPL-3.0)
- LSPK v18 format: documented in `src/pak/pak_reader.c`
