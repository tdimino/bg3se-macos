---
title: "Headless Boot Debug Log"
date: 2026-05-13
status: in-progress
---

# Headless Boot Debug Log

## Goal
Confirm headless CLI mode works end-to-end: launch → splash dismiss → Continue click → save load → socket connect → hide window → audio mute.

## Attempt 1 (pid 19340) — Pre-session (from summary)
- **Result:** Socket never connected, user quit before save loaded
- **Issues found:**
  - AXMinimized stalls Metal (game freezes)
  - `visible=false` during boot also stalls Metal
  - Terminal key leaking from `dismiss_splash_aggressive` using `CGEventPost(kCGHIDEventTap)`
- **Fix applied:** Off-screen window move to (-10000, -10000) instead of minimize/hide

## Attempt 2 (pid 83175) — 14:34:00
- **Config:** `--headless --continue --timeout 180`
- **Logger output:**
  ```
  socket_listening at 0.5s
  44 dismiss attempts, all "pre-Metal"
  Metal=no on every attempt (imgui_metal_first_drawable_seen() returns false)
  NSApp sendEvent NOT dispatched (gated on Metal readiness)
  ```
- **Screenshot:** Main menu visible at 1280x720. Title bar: "(Metal) - (6 + 6 WT)". Continue highlighted but never clicked.
- **Issues found:**
  1. `focusless_input.m:132` — `try_cgevent_hid()` leaked keys to terminal via global HID tap
  2. `imgui_metal_first_drawable_seen()` checks ImGui overlay, not game's Metal — wrong gate
  3. `try_nsapp_send_event()` hardcoded `characters:@" "` for all keyCodes (Enter got space char)
  4. `CGEventPostToPid(getpid())` doesn't reach BG3's custom Metal UI when app isn't frontmost
- **Fixes applied:**
  - Removed `try_cgevent_hid()` from `focusless_input_post_key_press()`
  - Removed Metal gate on NSEvent dispatch (always dispatch to main queue)
  - Added `chars_for_keycode()` mapping (Return→`\r`, Space→`" "`, Escape→`\x1b`)
  - Added Enter key (0x24) to in-process dismiss sequence
  - **Terminal leak confirmed fixed** (user: "terminal is safe now")

## Attempt 3 (pid ~83xxx) — 14:37:xx
- **Logger output:**
  ```
  NSApp=dispatched on every attempt (gate removed)
  20+ attempts, still "pre-Metal"
  No SessionLoaded, no fake_Event, no save loading
  ```
- **Issue:** Neither `CGEventPostToPid(getpid())` nor `[NSApp sendEvent:]` reaches BG3's custom Metal UI. Game stuck at main menu.
- **Conclusion:** In-process key injection cannot click BG3's menu buttons. BG3 uses a custom game engine UI, not standard AppKit responders.

## Attempt 4 (pid 84417) — 14:40:xx
- **Config:** Re-enabled Python-side System Events Enter after OCR menu detection
- **Logger output:**
  ```
  socket_listening at 0.5s
  timeout at 180716ms
  dismiss_attempts: 0
  NO menu_detected phase
  NO continue_clicked phase
  ```
- **Issue:** `_detect_main_menu()` → `detect_menu()` → `get_window_id()` returned None
  - `get_window_id()` uses System Events `get id of window 1 of process "Baldur's Gate 3"` → error -1728
  - CGWindowList shows owner as `bg3`, not `Baldur's Gate 3`
  - Window exists: CGWindowID=41979, title="Baldur's Gate 3 (1280x720) - (Metal)"
- **Fix applied:** Rewrote `get_window_id()` to use Quartz CGWindowListCopyWindowInfo by PID match

## Current State (post-attempt 4)
- **Terminal leak:** FIXED (no HID tap in C code, no external key sending for splash)
- **Window ID lookup:** FIXED (Quartz PID-based, not System Events name-based)
- **OCR menu detection:** UNTESTED with new window ID fix
- **Continue click via System Events:** UNTESTED (OCR never found menu → never sent Enter)
- **Save loading / socket response:** NEVER REACHED
- **Audio mute:** NEVER REACHED (deferred to fake_Event, which requires loaded save)
- **Window hiding:** NEVER REACHED (requires socket connection)
- **BG3 still running:** pid 84417

## Key Architecture Decisions
1. **Splash dismiss (Esc+Space):** Handled in-process by `focusless_input.m` via `CGEventPostToPid(getpid())` — safe (no terminal leak), but doesn't reach game UI
2. **Continue click (Enter):** Must use Python-side System Events `key code` — the only method that reaches BG3's custom Metal UI
3. **Window ID:** Must use Quartz `CGWindowListCopyWindowInfo` by PID — System Events can't get ID for BG3's Metal windows
4. **OCR:** Uses `screencapture -l <wid>` + Vision `VNRecognizeTextRequest` via JXA

## Attempt 5 — Ghidra RE + Direct View Injection

### Ghidra RE Findings
- **`LSMTLView::keyDown:` (0x100bd798c):** ObjC method on BG3's Metal view
  - Reads `InputManager*` from ivar at offset **104** (0x68) on the view
  - Translates macOS keyCode via `cocoa::CocoaInputTranslator::s_KeyboardKeys[]` (uint16_t[0xb4])
  - Builds `InputRawChange` struct (20 bytes): `{uint32_t keyId, float[2] value, uint8_t pressed}`
  - Calls `ls::InputManager::InjectInput(&change, false)` at 0x1064c4f14
  - Also pushes text characters into a separate `InjectDeviceEvent` array at `InputManager+0x398`
- **`LSMTLView::keyUp:` at otool offset 0x100d61ff0** — mirror for key release
- **`ls::InputManager::InjectInput` (0x1064c4f14):** Appends to dynamic array at `this+0x3a8`, size 0x14 per entry
- **BG3 uses Noesis GUI:** `Noesis::Keyboard::KeyDown` (0x10054fec4) receives translated events downstream
- **LSMTLView class:** 115 bytes, extends NSView, implements NSWindowDelegate, 43 instance methods
- **ObjC ivar:** `_OBJC_IVAR_$_LSMTLView.inputManager` confirmed at offset 104

### Fix Applied
Rewrote `focusless_input.m` to call `[LSMTLView keyDown:]` / `[LSMTLView keyUp:]` directly:
1. `find_lsmtlview()` — iterates `[NSApp windows]`, finds contentView that `isKindOfClass:LSMTLView`
2. Constructs proper `NSEvent` with correct keyCode and characters
3. Calls `[view keyDown:event]` then `[view keyUp:event]` on the main thread
4. Removed: `try_cgevent_hid()`, `try_cgevent_to_self()`, `try_nsapp_send_event()`
5. No CGEvent usage at all — zero risk of terminal key leaking

### Why This Works When Previous Attempts Failed
- `[NSApp sendEvent:]` → goes through AppKit dispatch → requires key window status → fails
- `CGEventPostToPid(getpid())` → enters Mach port event queue → doesn't reach ObjC responder chain → fails
- `[view keyDown:event]` → directly calls `LSMTLView::keyDown_` implementation → calls `InjectInput` → works regardless of focus

### Status (pre-test)
- Build: PASS (universal binary, 6.0M)
- Offline tests: 71/71 pass (41 C + 30 pytest)
- Live test: PENDING

## Remaining Questions
- Is `screencapture -l <wid>` able to capture the windowed BG3 window for OCR?

## Attempt 6 (pid 29430) — Watchdog Retry and Auto-Cancel

- **Config:** `--headless --continue --timeout 180`
- **Result:** Early structured failure, BG3 auto-quit
- **Harness phases:**
  ```
  dylib_loaded at 0.0s
  socket_listening at 0.5s
  menu_watchdog_action #1 at 28.6s
  menu_watchdog_action #2 at 41.1s
  menu_watchdog_action #3 at 53.2s
  menu_stalled at 71.986s
  ```
- **Retry behavior:** Each watchdog attempt sent System Events Return and a fallback coordinate click at `(864, 648)` based on window fraction `{x=0.5, y=0.62}`.
- **Cleanup behavior:** Headless graphics restored, then BG3 was force-quit. A post-run `pgrep` found no BG3 or harness process.
- **Diagnostics captured in JSON:**
  - Latest BG3SE log path and tail
  - Quartz/System Events window geometry
  - Screenshot dimensions and Retina scale
  - OCR result (`buttons: []`, `raw_ocr: []`)
  - Key and click delivery results for every watchdog action
- **Key finding:** Retina scaling is measured and stable (`1280x748` point window, `2560x1496` screenshot, scale `2.0`). The remaining blocker is not scale conversion; delivered key/click attempts still do not change BG3 menu state, and Vision OCR returns no text from the valid menu screenshot.

## Attempt 7 — Full Boot Retry Wrapper

- **Scope:** Harness behavior change; no new live BG3 run in this entry.
- **Change:** `launch` and `test` now support a full boot retry loop with `--boot-retries N` and `--retry-delay N`.
- **Default:** `--headless` uses one retry by default; non-headless uses zero retries unless requested.
- **Retryable failures:** `timeout` and `menu_stalled`.
- **Cancel/retry behavior:** On retryable failure, the harness reads the latest BG3SE log tail, extracts likely problem lines, captures menu geometry/OCR diagnostics, force-quits BG3, restores temporary headless graphics settings, waits the retry delay, and relaunches.
- **JSON observability:** Results include `boot_retries`, `boot_attempts`, per-attempt `diagnostics`, and `retry_cleanup`.
- **Unit validation:** `PYTHONPATH=tools python3 -m pytest tests/harness/test_launch.py tests/harness/test_cli.py -q` returned `13 passed`, including simulated `menu_stalled -> cancel -> relaunch -> socket_ready`. Full `tests/harness` returned `38 passed`. Offline gates also passed: Tier 0 C `41/41`, Nexus `23`, Wiki `23`.
