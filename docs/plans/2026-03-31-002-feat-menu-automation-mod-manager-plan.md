---
title: "feat: Menu automation + mod manager CLI integration"
type: feat
status: active
date: 2026-03-31
---

# feat: Menu automation + mod manager CLI integration

## Overview

Two features that complete the autonomous modding pipeline: (1) programmatic BG3 main menu interaction from CLI, and (2) a mod manager subsystem integrated into bg3se-harness. Together, these enable a fully autonomous workflow: install mods → launch game → navigate menus → load save → test → report — all from a single CLI command with zero human interaction.

## Problem Statement

**Menu automation:** The harness can launch BG3 and auto-dismiss the "Click to Continue" splash, but cannot navigate the main menu (New Game, Load Game, Continue, etc.) without human clicks. The `-continueGame` flag loads the most recent save but doesn't work for specific saves or new game starts. Testing issue #78 (new game crash) required manual menu clicking.

**Mod management:** Installing, enabling, and managing BG3 mods on macOS currently requires manual file copying and XML editing. ShaiLaric's `BG3MacModManager` (native Swift/SwiftUI) provides a GUI solution, but there's no CLI integration for autonomous pipelines. The harness needs `mod install/list/enable/disable` commands.

## Proposed Solution

### Part 1: Menu Automation (`menu.py`)

Detect menu state via macOS Vision OCR (stdlib, no pip deps), click buttons via ctypes + Quartz CGEvent API. Three-layer approach:
1. **Vision OCR** via osascript — detect which buttons are visible
2. **Coordinate mapping** — resolution-relative button positions (calibrated once)
3. **CGEvent clicks** via ctypes — send mouse events targeted at BG3 window

### Part 2: Mod Manager (`mod_manager/`)

A 6-file Python package within the harness (Nomos blueprint), using stdlib only:
- Pure Python LSPK v18 PAK reader (~150 LOC)
- ElementTree-based `modsettings.lsx` manipulation (backup-before-write)
- Nexus Mods API client (urllib, graceful premium-gate degradation)
- JSON mod registry for state tracking
- Single-level dependency resolution

Integrates with ShaiLaric's `BG3MacModManager` — shares path conventions (`FileLocations.swift`), understands the same `modsettings.lsx` format, and respects `ModCrashSanityCheck/` (Patch 8 footgun).

## Technical Approach

### Menu Automation Architecture

```
screenshot (screencapture -x -m) → Vision OCR (VNRecognizeTextRequest via osascript)
    → detected buttons ["Continue", "New Game", "Load Game", ...]
    → coordinate lookup (resolution-relative, calibrated)
    → CGEvent click (ctypes + Quartz, activate window first)
```

**CGEvent click** (stdlib, zero deps):
```python
import ctypes, ctypes.util
_quartz = ctypes.CDLL(ctypes.util.find_library("ApplicationServices"))

def cg_click(x, y):
    point = (ctypes.c_double * 2)(float(x), float(y))
    ev_down = _quartz.CGEventCreateMouseEvent(None, 1, point, 0)  # kCGEventLeftMouseDown
    _quartz.CGEventPost(0, ev_down)  # kCGHIDEventTap
    _quartz.CFRelease(ev_down)
    # ... ev_up similarly
```

**Vision OCR** (macOS 12+, no pip deps):
```applescript
use framework "Vision"
set request to current application's VNRecognizeTextRequest's alloc()'s init()
-- ... returns recognized text strings from screenshot
```

### Mod Manager Architecture (Nomos Blueprint)

```
tools/bg3se_harness/
├── mod_manager/
│   ├── __init__.py          # Public API facade
│   ├── registry.py          # JSON mod registry (~200 entries max)
│   ├── installer.py         # Download + install (local, URL, Nexus)
│   ├── modsettings.py       # modsettings.lsx XML manipulation
│   ├── nexus.py             # Nexus Mods API client (urllib)
│   ├── resolver.py          # Dependency resolution + conflict detection
│   └── pak_inspector.py     # Pure Python LSPK v18 reader
```

**Key paths** (shared with BG3MacModManager):
- Mods: `~/Documents/Larian Studios/Baldur's Gate 3/Mods/`
- modsettings.lsx: `~/Documents/.../PlayerProfiles/Public/modsettings.lsx`
- Registry: `~/.config/bg3se-harness/mod_registry.json`

**modsettings.lsx invariant:** GustavX (`28ac9ce2-2aba-8cda-b3b5-6e922f71b6b8`) is never removed, always at position 0.

**Nexus free users:** Cannot use download API (Premium only). Graceful fallback returns browser URL + hint to download manually, then `mod install /path/to/file.pak`.

## Acceptance Criteria

### Menu Automation
- [ ] `bg3se-harness menu detect` — returns JSON with visible menu buttons via OCR
- [ ] `bg3se-harness menu click "New Game"` — clicks the specified button
- [ ] `bg3se-harness menu wait` — polls until main menu is visible
- [ ] `bg3se-harness launch --continue` auto-dismisses splash AND navigates menu
- [ ] Works at any display resolution (coordinate scaling)
- [ ] Requires only macOS Accessibility permission (already needed for harness)

### Mod Manager
- [ ] `bg3se-harness mod list` — lists installed mods with enabled/SE status
- [ ] `bg3se-harness mod install <path>` — installs local .pak, updates modsettings.lsx
- [ ] `bg3se-harness mod enable/disable <name>` — toggles mod in modsettings.lsx
- [ ] `bg3se-harness mod info <name>` — shows mod metadata from PAK
- [ ] `bg3se-harness mod search <query>` — searches Nexus Mods API
- [ ] `bg3se-harness mod install nexus:1234` — downloads from Nexus (Premium) or returns URL (free)
- [ ] `bg3se-harness mod order --move X --before Y` — reorders load order
- [ ] `bg3se-harness mod backup` — backs up modsettings.lsx
- [ ] Pure Python, stdlib only (except optional LZ4 for some PAK files)
- [ ] All output is JSON to stdout

## Implementation Units

### Unit 1: CGEvent click module + Vision OCR detection
- **Goal**: `menu.py` with `cg_click()`, `detect_menu()`, `click_menu_button()`
- **Files**: `tools/bg3se_harness/menu.py` (NEW)
- **Verification**: `bg3se-harness menu detect` returns recognized text from a BG3 screenshot
- **Patterns to follow**: `screenshot.py` for window capture, `launch.py` for osascript

### Unit 2: Calibrate menu button coordinates
- **Goal**: Resolution-relative coordinate map for all main menu buttons
- **Files**: `tools/bg3se_harness/menu.py` (extend with `MENU_POSITIONS`)
- **Execution note**: Requires taking a BG3 screenshot at the main menu and measuring coordinates
- **Verification**: `menu click "Continue"` clicks the right spot at the test machine's resolution

### Unit 3: Register `menu` CLI command
- **Goal**: `menu detect`, `menu click`, `menu wait` subcommands
- **Files**: `tools/bg3se_harness/cli.py`, `tools/bg3se_harness/menu.py`
- **Verification**: `bg3se-harness menu --help` shows all subcommands; `menu detect` returns JSON
- **Patterns to follow**: `ghidra` subcommand group in `cli.py`

### Unit 4: Integrate menu automation into launch flow
- **Goal**: `launch --continue` auto-dismisses splash + navigates menu if needed
- **Files**: `tools/bg3se_harness/launch.py`
- **Verification**: Full autonomous pipeline: `bg3se-harness launch --continue` reaches loaded save with zero interaction

### Unit 5: PAK inspector + modsettings.lsx manipulation
- **Goal**: Pure Python LSPK v18 reader + ElementTree modsettings.lsx r/w
- **Files**: `tools/bg3se_harness/mod_manager/__init__.py`, `pak_inspector.py`, `modsettings.py`
- **Verification**: Read a .pak file's meta.lsx; add/remove a mod from modsettings.lsx

### Unit 6: Mod registry + installer
- **Goal**: JSON registry, local file install, enable/disable
- **Files**: `tools/bg3se_harness/mod_manager/registry.py`, `installer.py`
- **Verification**: `mod install local.pak && mod list && mod disable ModName && mod list`

### Unit 7: Nexus Mods API integration
- **Goal**: Search, download (Premium), URL fallback (free)
- **Files**: `tools/bg3se_harness/mod_manager/nexus.py`
- **Verification**: `mod search "Community Library"` returns results; `mod install nexus:1234` works or returns browser URL

### Unit 8: Register `mod` CLI command group
- **Goal**: All mod subcommands wired in cli.py
- **Files**: `tools/bg3se_harness/cli.py`
- **Verification**: `bg3se-harness mod --help` shows all subcommands; end-to-end install+enable+list

### Unit 9: Documentation + skill update
- **Goal**: Update SKILL.md, CLAUDE.md, agent_docs/tools.md with menu + mod commands
- **Files**: SKILL.md, CLAUDE.md, tools.md
- **Verification**: All new commands documented

## Scope Boundaries

**In scope:**
- Menu OCR detection and coordinate-based clicking
- Local mod install/uninstall/enable/disable
- modsettings.lsx manipulation
- Nexus API search + download (with premium gate)
- CLI commands for both features

**Out of scope:**
- Full GUI mod manager (ShaiLaric's BG3MacModManager covers this)
- Mod conflict resolution at file level (only UUID-level)
- Mod compilation or PAK creation
- Steam Workshop integration
- Transitive dependency resolution (single-level only)
- Save game management (separate feature)

## Dependencies & Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Menu button coordinates vary by resolution | High | Medium | Resolution-relative positions, calibrate at runtime |
| Vision OCR misreads button text | Medium | Low | Fuzzy matching, fallback to hardcoded positions |
| BG3 updates change menu layout | Medium | Medium | OCR adapts; coordinates may need recalibration |
| Nexus API rate limiting | Low | Low | Track headers, warn at <10 remaining |
| modsettings.lsx format changes | Low | High | Always backup before write, validate after |
| LZ4 compression in some PAKs | Medium | Low | Optional LZ4, graceful fallback for LZ4-compressed entries |

## Sources & References

### Research (this session)
- **Exa/Scholiast**: macOS game menu automation — CGEvent via ctypes, Vision OCR via osascript, cliclick
- **Sopher**: ShaiLaric/BG3MacModManager — native Swift/SwiftUI mod manager with bg3se-macos integration
- **Nomos**: Full mod manager blueprint — 6-file Python package, 4 implementation phases

### Internal References
- `tools/bg3se_harness/screenshot.py` — existing window capture
- `tools/bg3se_harness/launch.py` — existing auto-dismiss pattern
- `tools/bg3se_harness/cli.py` — CLI registration pattern (ghidra subcommand)
- `src/mod/mod_loader.c` — C-side mod detection (reads modsettings.lsx at boot)
- `src/pak/pak_reader.c` — C-side LSPK v18 reader (reference for Python port)

### External References
- ShaiLaric/BG3MacModManager: https://github.com/ShaiLaric/BG3MacModManager
- Nexus Mods API: https://app.swaggerhub.com/apis-docs/NexusMods/nexus-mods_public_api_params_in_form_data/1.0
- LSPK v18 format: documented in `src/pak/pak_reader.c`
