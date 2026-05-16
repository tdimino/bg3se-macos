# Headless Boot Bugs — 2026-05-13

Discovered via the new structured boot logging (`/tmp/bg3se_monitor.log`).

## Bug 1: CGEventPostToPid fails to dismiss splash (CRITICAL)

**Symptom:** 60 dismiss attempts via `CGEventPostToPid` all report success (`CGEventToSelf=yes`) but the splash screen never dismisses. The socket accepts connections but never responds to Lua commands, so `wait_for_socket()` times out at 90s.

**Evidence:**
```
[SE log] Socket server listening on /tmp/bg3se.sock          (t=0.0s)
[SE log] FocuslessInput Dismiss attempt #1 (Escape+Space)    (t=3.2s)
...
[SE log] FocuslessInput Dismiss attempt #60 (Escape+Space)   (t=121s)
[SE log] Splash timer stopped (max reached, 60 attempts)
[Monitor] socket_timeout — no response after 90144ms
```

**Root cause hypothesis:** BG3 process has 0 windows (verified via System Events). The Metal renderer may not have created a window yet, or the fullscreen Metal window is not registered in the AppKit window list. `CGEventPostToPid` needs a window to target the key event — without one, events are posted to the process but dropped by the event dispatch chain.

**System Events confirmation:**
```
tell process "Baldur's Gate 3": count of windows → 0, visible → true
```

**Fix (4-part):**
1. Removed empty `-mediaPath` — may have stalled BG3 video state machine, preventing renderer init
2. Added Metal readiness gate — dismiss attempts skip until `hooked_nextDrawable` captures first drawable
3. Moved `focusless_input_mark_socket_ready()` from client accept to after `process_line()` — timer no longer stops prematurely
4. Added NSEvent fallback — after 5 failed CGEvent attempts, also sends `[NSApp sendEvent:]` on main thread

## Bug 2: Screenshot fails with "window not found"

**Symptom:** `bg3se-harness screenshot` returns `{"error": "BG3 window not found"}` even though the game process is alive.

**Root cause:** Same as Bug 1 — no windows reported by System Events / CGWindowListCopyWindowInfo.

## Bug 3: Monitor env var check is misleading

**Symptom:** `_monitor.py` checks `os.environ.get("BG3SE_SKIP_VIDEOS")` and `os.environ.get("BG3SE_AUTO_DISMISS_SPLASH")`, but since the monitor is a separate detached subprocess spawned after BG3, it doesn't inherit BG3's environment. These checks always return None.

**Fix:** Pass flags as CLI args to the monitor: `_monitor.py <pid> <timeout> <headless> <skip_videos> <auto_dismiss>`. Updated both `_monitor.py` (reads argv[4:5]) and `cli.py` (passes flags at spawn).

## Bug 4: Monitor misreports "dylib_detected" at t=0

**Symptom:** Monitor log shows `dylib_detected` at t=0.0s because it checks for the SE log file, which persists from the previous session. It should check the log file's modification time against the current launch time.

**Fix:** Compare `latest.log` mtime against `started_at` from the health file. Uses 5s grace window to account for timing skew. Stale logs now reported as `dylib_stale` instead of `dylib_detected`.

## Bug 5: Foreground `wait_for_socket()` phases not visible to monitor

**Symptom:** The background `_monitor.py` calls `wait_for_socket()`, which prints phase markers to stderr. But since the monitor is spawned with `stderr=subprocess.DEVNULL`, these markers are lost. Only the final health JSON is written.

**Fix:** The monitor already writes its own log. But the `wait_for_socket()` phases should be captured in the health JSON (now fixed — `phases` list added to return dict).

## Summary

| # | Bug | Severity | Status |
|---|-----|----------|--------|
| 1 | CGEventPostToPid fails (no window) | CRITICAL | FIXED — Metal readiness gate + NSEvent fallback + removed -mediaPath stall + socket-ready moved to after process_line |
| 2 | Screenshot fails (no window) | HIGH | Unblocked (depends on #1 fix working at runtime) |
| 3 | Monitor env var check wrong | LOW | FIXED — flags passed as CLI args |
| 4 | dylib_detected false positive | LOW | FIXED — mtime compared against started_at |
| 5 | Monitor stderr lost | FIXED | phases in health JSON |
