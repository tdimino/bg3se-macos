# Game State Tracking (macOS ARM64)

## Overview

The game state system tracks transitions between different game states (Loading, Running, Paused, etc.) and fires `Ext.Events.GameStateChanged` events to Lua handlers.

## Windows BG3SE Approach

On Windows, BG3SE hooks `GameStateEventManager` directly by:
1. Pattern scanning for "SERVER STATE SWAP" and "CLIENT STATE SWAP" debug strings
2. Finding XREF to `GameStateEventManager::OnSwap` function
3. Hooking the swap function to capture state transitions

## macOS Challenge

**The macOS binary has stripped debug strings.** Neither "SERVER STATE SWAP" nor "CLIENT STATE SWAP" exists in the binary:

```bash
strings -a "bg3_Data/Plugins/libOsiris.dylib" | grep -i "state swap"
# (no output)

strings -a "/Applications/Baldur's Gate 3.app/.../Baldur's Gate 3" | grep -i "state swap"
# (no output)
```

This means we cannot directly hook `GameStateEventManager` using pattern matching.

## Alternative: Event-Based State Inference

Instead of hooking the state manager directly, we infer game state from observable events:

### State Transitions

| Observable Event | Inferred State |
|-----------------|----------------|
| `game_state_init()` | Init (startup) |
| `game_state_on_session_loading()` | LoadSession |
| `game_state_on_session_loaded()` | Running |
| `game_state_on_reset()` | Idle |
| `game_state_on_save_start()` | Save |
| `game_state_on_save_complete()` | Running |
| `game_state_on_pause()` | Paused |
| `game_state_on_unpause()` | Running |

### State Enum (Windows BG3SE Compatible)

```c
typedef enum {
    SERVER_STATE_UNKNOWN = 0,
    SERVER_STATE_UNINITIALIZED = 1,
    SERVER_STATE_INIT = 2,
    SERVER_STATE_IDLE = 3,
    SERVER_STATE_EXIT = 4,
    SERVER_STATE_LOAD_LEVEL = 5,
    SERVER_STATE_LOAD_MODULE = 6,
    SERVER_STATE_LOAD_SESSION = 7,
    SERVER_STATE_UNLOAD_LEVEL = 8,
    SERVER_STATE_UNLOAD_MODULE = 9,
    SERVER_STATE_UNLOAD_SESSION = 10,
    SERVER_STATE_SYNC = 11,
    SERVER_STATE_PAUSED = 12,
    SERVER_STATE_RUNNING = 13,
    SERVER_STATE_SAVE = 14,
    SERVER_STATE_DISCONNECT = 15,
    SERVER_STATE_BUILD_STORY = 16,
    SERVER_STATE_RELOAD_STORY = 17,
    SERVER_STATE_MAX
} ServerGameState;
```

## Implementation

### Files

- `src/game/game_state.h` - Public API and state enum
- `src/game/game_state.c` - State tracking implementation
- `src/lua/lua_events.c` - `events_fire_game_state_changed()` function

### Integration Points (main.c)

```c
// In init_lua()
game_state_init();

// In InitGame hook (before loading mod scripts)
game_state_on_session_loading(g_lua);

// In Load hook (after session is fully loaded)
game_state_on_session_loaded(g_lua);
```

### Lua API

```lua
-- Register handler for state changes
Ext.Events.GameStateChanged:Subscribe(function(e)
    print("State changed: " .. e.FromState .. " -> " .. e.ToState)
end)
```

Event data table contains:
- `FromState` (integer) - Previous state value
- `ToState` (integer) - New state value

## Limitations

1. **Not all states detectable** - Some states (LoadLevel, LoadModule, BuildStory, etc.) cannot be reliably detected without direct hooks
2. **Timing may differ** - State transitions are inferred from observable hooks, which may fire slightly before/after the actual game state change
3. **No client state** - Only server state is tracked (sufficient for most modding use cases)

## Future Improvements

If future macOS builds include debug strings, or if we discover alternative patterns to locate `GameStateEventManager`, we could implement direct hooking for more precise state tracking.

### Potential Pattern Alternatives

- Look for `GameStateEventManager` vtable patterns
- Hook `ServerGameStateMachine::Update` (if discoverable)
- Pattern match on state machine switch/jump table structures

## Ghidra Script

`ghidra/scripts/find_gamestate_manager.py` attempts to find GameStateEventManager but currently returns no matches due to stripped strings.

## Related Files

- Windows BG3SE: `BG3Extender/Osiris/ServerStates.h` - State enum definitions
- Windows BG3SE: `BG3Extender/GameDefinitions/GameState.h` - GameStateEventManager hooks
