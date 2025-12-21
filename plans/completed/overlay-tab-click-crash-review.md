# Review: BG3SE-macOS Overlay Console Crashes When Clicking Tabs

## Summary
Clicking any tab in the in-game overlay console (toggled via Ctrl+`) can crash the game even though the tab UI itself is straightforward AppKit view switching. The most likely root cause is **unsynchronized, multi-threaded access to a single `lua_State*`**, triggered by:

- Game-thread/engine hook tick work calling into Lua (console polling, timers, events)
- Main-runloop input capture (CGEventTap) also calling into Lua
- Potential overlay command execution path calling Lua from AppKit interaction timing

This combination can produce timing-sensitive crashes that *appear* tied to clicking tabs, because clicking inside the overlay changes focus/first responder and can overlap with tick processing.

## Where the Tab Click Happens
The overlay is an AppKit `NSWindow` + custom `NSView` UI:

- `bg3se-macos/src/overlay/overlay.m`
  - `BG3SEConsoleView` contains the tab bar
  - `BG3SETabButton` is the custom tab button
  - `- (void)tabClicked:(BG3SETabButton *)sender` handles tab switching

**Tab switching is UI-only**: it deselects/selects buttons, toggles `.hidden` on views, and (for the Mods tab) calls `updateModsList` which currently uses placeholder data.

## Why a Simple Tab Click Can Still Crash
### 1) Lua is driven from the game hook tick path
In `bg3se-macos/src/injector/main.c`, the Osiris `Event` hook runs periodic work:

- `fake_Event(...)` calls:
  - `console_poll(L)`
  - `timer_update(L)`
  - `persist_tick(L)`
  - `events_fire_tick(L, ...)`

This suggests Lua execution happens on whatever thread the engine invokes `COsiris::Event` on (often not the AppKit main thread).

### 2) Lua is also driven from the main run loop input capture path
Despite comments in `input.h` about “NSEvent swizzling”, the implementation is CGEventTap-based:

- `bg3se-macos/src/input/input_hooks.m`
  - `input_init()` installs a `CGEventTap` and adds it to `CFRunLoopGetMain()`
  - The event tap callback calls `events_fire_key_input(s_lua_state, ...)` directly

This means Lua can be entered from a different execution context than the engine hook tick.

### 3) Overlay command execution calls Lua directly (no serialization)
The overlay command callback in `bg3se-macos/src/injector/main.c` calls `console_execute_lua(command)`, which runs `luaL_dostring` against the shared `s_lua_state`.

- `bg3se-macos/src/console/console.c`
  - `console_execute_lua()` calls `luaL_dostring(s_lua_state, command)`

Even if tab-clicking isn’t directly executing commands, AppKit focus changes can affect text editing callbacks (`controlTextDidEndEditing:`) and timing.

## Primary Hypothesis (Most Likely)
**Data race / concurrent re-entrancy into the same `lua_State*`**.

Lua is not thread-safe. If one thread is running Lua (tick/Osiris hook) while another thread runs `events_fire_key_input` or `console_execute_lua`, the VM stack and GC can be corrupted, yielding `EXC_BAD_ACCESS` or other hard crashes.

This fits the symptom pattern:
- Crash correlates with interaction (“click tab”) because interaction changes event timing.
- Crash may be intermittent or depend on current tick load.

## Secondary Observations / Smells
- `bg3se-macos/src/input/input.h` documents “NSEvent swizzling”, but the code uses CGEventTap.
  - Not necessarily a crash source, but indicates drift in assumptions.
- Overlay uses AppKit main-queue async for UI updates (good), but Lua is not similarly centralized.

## Recommended Fix Strategy (High-Leverage)
### 1) Make Lua single-threaded
Pick exactly one thread/context that owns Lua execution (typically the engine hook tick path).

- Do **not** call `events_fire_key_input` from the CGEventTap callback.
- Instead, enqueue input events into a lock-free or mutex-protected queue.
- Drain the queue and fire Lua events from within `fake_Event()` (or any single known Lua-owning tick).

### 2) Serialize overlay command execution
Similarly, do not call `console_execute_lua()` directly from the overlay/UI callback.

- Enqueue overlay commands and execute them from the same Lua-owning tick.

### 3) Tighten overlay input submit semantics
In `BG3SEConsoleView`, command submission is currently driven by `controlTextDidEndEditing:` which can fire on focus loss (e.g., clicking tabs).

- Prefer submitting only on Enter (e.g., gate on `NSTextMovement == NSReturnTextMovement`).
- This reduces the chance of “tab click triggers Lua execution” overlap.

## Debugging / Verification Checklist
To confirm definitively:

- Capture the macOS crash report backtrace for Baldur’s Gate 3 and check for:
  - `lua*` frames (`luaD_*`, `luaV_*`, `luaC_*`, `luaL_dostring`)
  - BG3SE frames (`console_execute_lua`, `events_fire_key_input`, `events_fire_tick`, etc.)
  - `CGEventTap` / `CFRunLoop` frames
- Check `~/Library/Application Support/BG3SE/bg3se.log` around the crash for overlapping activity:
  - KeyInput events firing while tick work is running
  - Overlay command execution logs near tick logs

## Files Reviewed
- `bg3se-macos/src/overlay/overlay.m`
- `bg3se-macos/src/overlay/overlay.h`
- `bg3se-macos/src/input/input_hooks.m`
- `bg3se-macos/src/input/input.h`
- `bg3se-macos/src/injector/main.c`
- `bg3se-macos/src/console/console.c`

## Conclusion
The tab UI is unlikely to be the direct crash source. The most plausible explanation is a **Lua thread-safety violation** caused by multiple independent systems calling into the same `lua_State*` from different execution contexts (engine hook tick vs main run loop event tap vs overlay callback timing). Centralizing all Lua work onto a single thread/tick and routing input/overlay commands through queues should eliminate the crash class.
