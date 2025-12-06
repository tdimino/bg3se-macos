# Implement Timer API (Ext.Timer) - Issue #14

## Overview

Implement the Timer API for scheduling delayed and repeating function calls in Lua mods. This is a HIGH priority feature as many mods rely on timers for delayed actions, cooldowns, polling, and animation timing.

## Problem Statement

Mod authors need a way to schedule callbacks to run after a delay or at regular intervals. Currently there's no timer mechanism, forcing mods to rely on polling or other workarounds.

**Use cases:**
- Delayed actions (e.g., apply status effect after 2 seconds)
- Repeating tasks (e.g., check condition every 500ms)
- Cooldown management (e.g., ability usable again after 5 seconds)
- Animation/effect timing
- Polling for game state changes

## Target API Surface

Based on Windows BG3SE reference (`BG3Extender/Lua/Libs/Timer.h`, `Timer.inl`):

```lua
-- Create a one-shot timer (fires once after delay in milliseconds)
local handle = Ext.Timer.WaitFor(delayMs, function(handle)
    Ext.Print("Timer fired!")
end)

-- Create a repeating timer (fires every intervalMs)
local handle = Ext.Timer.WaitFor(delayMs, callback, repeatMs)

-- Alternative explicit repeat API
local handle = Ext.Timer.RegisterTimer(intervalMs, callback)

-- Cancel a timer
Ext.Timer.Cancel(handle)

-- Pause/Resume (nice-to-have)
Ext.Timer.Pause(handle)
Ext.Timer.Resume(handle)

-- Time utilities
Ext.Timer.MonotonicTime()  -- High-resolution monotonic clock (ms)
Ext.Timer.GameTime()       -- Game world time
```

## Technical Approach

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Lua API Layer                            │
│  Ext.Timer.WaitFor() / Cancel() / MonotonicTime()           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Timer Manager (C)                          │
│  - Priority queue ordered by fire time                       │
│  - Timer storage with handles                                │
│  - Callback references via luaL_ref                          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Tick Integration                          │
│  - Hook into fake_Event() (already polled per Osiris event) │
│  - Check expired timers, fire callbacks                      │
└─────────────────────────────────────────────────────────────┘
```

### Key Design Decisions

1. **Tick Source**: Use the existing `fake_Event()` hook which already calls `console_poll(L)`. This fires frequently during gameplay and provides a natural update point.

2. **Time Source**: Use `mach_absolute_time()` for high-resolution monotonic time on macOS.

3. **Callback Storage**: Use `luaL_ref(L, LUA_REGISTRYINDEX)` to prevent Lua callbacks from being garbage collected.

4. **Handle Design**: 64-bit integer handle encoding:
   - Bits 0-31: Timer pool index
   - Bit 32: Persistent flag (for future savegame support)
   - Bit 33: Realtime vs game-time flag

5. **Data Structure**: Priority queue (min-heap) for efficient "get next timer to fire" operations.

### Implementation Details

**Timer Structure:**
```c
typedef struct {
    double fire_time;        // Monotonic time when timer should fire
    double repeat_interval;  // 0 for one-shot, >0 for repeating
    int callback_ref;        // Lua registry reference
    uint32_t invoke_id;      // Incremented on pause/resume to invalidate stale queue entries
    bool paused;
    bool active;             // Slot in use
} Timer;
```

**Priority Queue Entry:**
```c
typedef struct {
    double fire_time;
    uint64_t handle;
    uint32_t invoke_id;      // Must match timer's invoke_id to be valid
} TimerQueueEntry;
```

**Update Loop (in fake_Event or dedicated tick):**
```c
void timer_update(lua_State *L) {
    double now = get_monotonic_time_ms();

    while (!queue_empty() && queue_top().fire_time <= now) {
        TimerQueueEntry entry = queue_pop();
        Timer *timer = timer_get(entry.handle);

        // Validate: timer exists, not paused, invoke_id matches
        if (timer && timer->active && !timer->paused
            && timer->invoke_id == entry.invoke_id) {

            // Fire callback
            lua_rawgeti(L, LUA_REGISTRYINDEX, timer->callback_ref);
            lua_pushinteger(L, entry.handle);
            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                log_message("[Timer] Callback error: %s", lua_tostring(L, -1));
                lua_pop(L, 1);
            }

            // Repeat or release
            if (timer->repeat_interval > 0) {
                timer->fire_time = now + timer->repeat_interval;
                queue_push(timer->fire_time, entry.handle, timer->invoke_id);
            } else {
                timer_free(entry.handle);
            }
        }
    }
}
```

## Implementation Phases

### Phase 1: Core Timer Infrastructure
**Files:** `src/timer/timer.c`, `src/timer/timer.h`

- [ ] Create timer module with static state
- [ ] Implement timer pool (fixed-size array, reusable slots)
- [ ] Implement min-heap priority queue
- [ ] Implement `get_monotonic_time_ms()` using `mach_absolute_time()`
- [ ] Implement `timer_update()` tick function

### Phase 2: Lua Bindings
**Files:** `src/lua/lua_timer.c`, `src/lua/lua_timer.h`

- [ ] `Ext.Timer.WaitFor(delay, callback, [repeat])` → handle
- [ ] `Ext.Timer.Cancel(handle)` → boolean
- [ ] `Ext.Timer.MonotonicTime()` → number (ms since process start)
- [ ] Register `Ext.Timer` namespace in `lua_ext.c`

### Phase 3: Integration
**Files:** `src/injector/main.c`, `CMakeLists.txt`

- [ ] Call `timer_update(L)` from `fake_Event()` (same place as `console_poll`)
- [ ] Initialize timer system in `init_lua()`
- [ ] Cleanup timer refs on Lua state reset
- [ ] Add to CMakeLists.txt

### Phase 4: Nice-to-Have Features
**Files:** `src/timer/timer.c`, `src/lua/lua_timer.c`

- [ ] `Ext.Timer.Pause(handle)` / `Resume(handle)`
- [ ] `Ext.Timer.IsPaused(handle)` → boolean
- [ ] `Ext.Timer.GameTime()` (requires game time tracking)
- [ ] Context parameter support (optional table passed to callback)

## File Structure

```
src/
├── timer/
│   ├── timer.c          # NEW: Timer manager implementation
│   └── timer.h          # NEW: Timer API declarations
├── lua/
│   ├── lua_timer.c      # NEW: Ext.Timer Lua bindings
│   ├── lua_timer.h      # NEW: Lua timer declarations
│   └── lua_ext.c        # UPDATE: Register Ext.Timer namespace
├── injector/
│   └── main.c           # UPDATE: Call timer_update() in fake_Event
CMakeLists.txt           # UPDATE: Add new source files
```

## API Reference

### Ext.Timer.WaitFor

```lua
-- One-shot timer
local handle = Ext.Timer.WaitFor(1000, function(h)
    Ext.Print("1 second passed!")
end)

-- Repeating timer (fires at 0ms, 500ms, 1000ms, ...)
local handle = Ext.Timer.WaitFor(0, function(h)
    Ext.Print("Tick!")
end, 500)
```

**Parameters:**
- `delay` (number): Initial delay in milliseconds
- `callback` (function): Called with timer handle as argument
- `repeat` (number, optional): Repeat interval in milliseconds

**Returns:** Timer handle (integer)

### Ext.Timer.Cancel

```lua
local success = Ext.Timer.Cancel(handle)
```

**Parameters:**
- `handle` (integer): Timer handle from WaitFor

**Returns:** `true` if timer was cancelled, `false` if not found

### Ext.Timer.MonotonicTime

```lua
local ms = Ext.Timer.MonotonicTime()
```

**Returns:** Milliseconds since process start (high-resolution monotonic clock)

## Acceptance Criteria

### Functional Requirements
- [ ] `Ext.Timer.WaitFor(delay, callback)` fires callback after delay
- [ ] `Ext.Timer.WaitFor(delay, callback, repeat)` fires repeatedly
- [ ] `Ext.Timer.Cancel(handle)` stops pending timer
- [ ] Callbacks receive timer handle as first argument
- [ ] Multiple concurrent timers work correctly
- [ ] Timers fire in correct order based on fire time

### Non-Functional Requirements
- [ ] Timer accuracy within ~16ms (one game frame at 60fps)
- [ ] No memory leaks (callbacks properly unreferenced on cancel/fire)
- [ ] Cancelled timers don't fire
- [ ] Timer system doesn't cause game stutter

### Quality Gates
- [ ] Lua callback references properly stored via `luaL_ref`
- [ ] Callback errors caught and logged (don't crash game)
- [ ] Timers cleaned up on Lua state reset
- [ ] Follows existing module patterns (`timer.h`/`.c`)

## Testing Plan

### Manual Testing via Console

```bash
# Test one-shot timer
echo 'local h = Ext.Timer.WaitFor(2000, function() _P("2 seconds!") end); _P("Timer started:", h)' > ~/Library/Application\ Support/BG3SE/commands.txt

# Test repeating timer
cat > ~/Library/Application\ Support/BG3SE/commands.txt << 'EOF'
--[[
local count = 0
local h = Ext.Timer.WaitFor(0, function(handle)
    count = count + 1
    _P("Tick", count)
    if count >= 5 then
        Ext.Timer.Cancel(handle)
        _P("Cancelled after 5 ticks")
    end
end, 1000)
_P("Started repeating timer:", h)
]]--
EOF

# Test cancel
cat > ~/Library/Application\ Support/BG3SE/commands.txt << 'EOF'
--[[
local h = Ext.Timer.WaitFor(5000, function()
    _P("This should NOT print!")
end)
_P("Created timer:", h)
Ext.Timer.WaitFor(1000, function()
    local result = Ext.Timer.Cancel(h)
    _P("Cancelled:", result)
end)
]]--
EOF

# Test MonotonicTime
echo '_P("Time:", Ext.Timer.MonotonicTime(), "ms")' > ~/Library/Application\ Support/BG3SE/commands.txt
```

## Dependencies & Risks

### Dependencies
- Existing `fake_Event()` hook for tick updates
- Lua registry for callback storage
- `mach_absolute_time()` for high-resolution timing

### Risks

| Risk | Mitigation |
|------|------------|
| Timer drift if fake_Event not called frequently | Accept ~16ms accuracy; timers are not meant for frame-precise timing |
| Memory leak from uncancelled timers | Clear all timers on Lua state reset |
| Callback errors crash game | Wrap in lua_pcall with error logging |
| Too many timers cause performance issues | Limit to 256 concurrent timers initially |

## References

### Internal References
- Console polling pattern: `src/console/console.c:194` (`console_poll`)
- Event hook: `src/injector/main.c:2093` (`fake_Event`)
- Lua callback refs: `src/console/console.c:97` (`luaL_ref` pattern)
- Module pattern: `src/lua/lua_debug.c/h`

### External References
- Windows BG3SE Timer: `BG3Extender/Lua/Libs/Timer.h`, `Timer.inl`
- Lua C API references: `luaL_ref`, `lua_rawgeti`, `lua_pcall`
- macOS timing: `mach_absolute_time`, `mach_timebase_info`

### Related Issues
- Issue #14: Timer API (Ext.Timer)
- Issue #11: Ext.Events API (could share tick infrastructure)
