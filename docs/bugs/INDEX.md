# Bug Investigations

Active and resolved bug investigations for the BG3SE-macOS headless/harness pipeline.

## Documents

| File | Description | Status | Date |
|------|-------------|--------|------|
| [headless-cli-goal-progress.md](headless-cli-goal-progress.md) | Headless CLI goal progress — menu automation, Mod Verification handling, save-load preflight, and hotbar crash attribution | In-progress | 2026-05-16 |
| [noesis-input-bypass-re.md](noesis-input-bypass-re.md) | Noesis GUI input bypass — Ghidra RE of input pipeline, focus gate discovery, 5 ranked bypass approaches | In-progress | 2026-05-16 |
| [headless-boot-debug-log.md](headless-boot-debug-log.md) | Headless boot attempt log — 7 attempts documenting splash dismiss, menu detection, and input delivery failures | In-progress | 2026-05-13 |

## Summary

Headless CLI launch, menu detection, and Mod Verification automation are working. The current blocker is the post-save-load crash classified as `post_level_loaded_hotbar_update`; the harness now has installed PAK scanning, registry reconciliation, save-required mod inference, modsettings verification, and `.ips` crash attribution to narrow the remaining cause.

## Related

- `docs/re/` — Reverse engineering reference docs
- `ghidra/offsets/NOESIS_UI_FRAMEWORK.md` — Noesis input pipeline offsets
- `src/game/focus_hack.c` — Focus bypass implementation
- `src/input/focusless_input.m` — Direct LSMTLView input injection
- `docs/harness.md` — `bg3se_harness` command reference for the current preflight and diagnostics workflow
