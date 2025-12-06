# Plan: Implement GameStateChanged Event via Ghidra Analysis

## Overview

Implement the `Ext.Events.GameStateChanged` event by discovering and hooking the GameStateEventManager on macOS ARM64. This event fires when the game transitions between states (Menu, Loading, Running, Paused, etc.).

## Background Research (Completed)

### Windows BG3SE Implementation

From Windows BG3SE reference code:

1. **Global Symbols** (`BG3Extender/GameDefinitions/Symbols.h:60-61`):
```cpp
GameStateEventManager** ecl__gGameStateEventManager{ nullptr };  // Client
GameStateEventManager** esv__gGameStateEventManager{ nullptr };  // Server
```

2. **GameStateEventManager Structure** (`BG3Extender/GameDefinitions/GameState.h:74-78`):
```cpp
struct GameStateEventManager {
    void* VMT;
    Array<void*> Callbacks;  // Array of callback pointers
};
```

3. **Hooking Pattern** (`BG3Extender/Extender/ScriptExtender.cpp:482-491`):
```cpp
auto serverEvtMgr = GetStaticSymbols().esv__gGameStateEventManager;
if (serverEvtMgr && *serverEvtMgr) {
    auto server = GameAlloc<ServerEventManagerHook>();
    (*serverEvtMgr)->Callbacks.push_back(&server->dummy);
}
```

4. **Pattern Matching** (`BG3Extender/GameHooks/BinaryMappings.xml:221-246`):
   - **Client**: Search for string `"CLIENT STATE SWAP - from: %s, to: %s"`
   - **Server**: Search for string `"SERVER STATE SWAP - from: %s, to: %s\n"`

   The GameStateEventManager global is accessed via `mov rax, cs:xxx__gGameStateEventManager` near these strings.

5. **Game States** (from IdeHelpers):
   - **ServerGameState**: Unknown(0), Uninitialized(1), Init(2), Idle(3), Exit(4), LoadLevel(5), LoadModule(6), LoadSession(7), UnloadLevel(8), UnloadModule(9), UnloadSession(10), Sync(11), Paused(12), Running(13), Save(14), Disconnect(15), BuildStory(16), ReloadStory(17)
   - **ClientGameState**: Unknown(0), Init(1), InitMenu(2), InitNetwork(3), InitConnection(4), Idle(5), LoadMenu(6), Menu(7), Exit(8), SwapLevel(9), LoadLevel(10), LoadModule(11), LoadSession(12), LoadGMCampaign(13), UnloadLevel(14), UnloadModule(15), UnloadSession(16), Paused(17), Running(18), Disconnect(19)

## Implementation Plan

### Phase 1: Ghidra String Search for Pattern Discovery

**Objective**: Find the GameStateEventManager global pointer addresses on macOS ARM64.

#### Step 1.1: Create Ghidra Script

Create `ghidra/scripts/find_gamestate_manager.py`:

```python
# Search for state swap log strings
# Pattern: "SERVER STATE SWAP - from: %s, to: %s"
# Pattern: "CLIENT STATE SWAP - from: %s, to: %s"

# For each string found:
# 1. Find XREF (function that uses string)
# 2. In that function, look for ADRP/ADD or LDR sequence loading global
# 3. The global before the callback loop is gGameStateEventManager
```

**ARM64-specific patterns to search for**:
- `adrp x0, #string_page` followed by `add x0, x0, #string_offset` (loading string)
- `adrp xN, #global_page` followed by `ldr xM, [xN, #offset]` (loading global pointer)

#### Step 1.2: Run Analysis

```bash
./ghidra/scripts/run_analysis.sh find_gamestate_manager.py
```

**Expected output**:
- `esv__gGameStateEventManager` address
- `ecl__gGameStateEventManager` address
- GameStateMachine::Update function addresses (for fallback hooking)

### Phase 2: Verify Structure Layout on ARM64

**Objective**: Confirm GameStateEventManager struct matches Windows.

#### Step 2.1: Runtime Memory Probe

Once Ghidra finds the addresses, probe at runtime:

```lua
-- Get module base
local base = Ext.Memory.GetModuleBase("Baldur")

-- Probe server event manager (offset TBD from Ghidra)
local svr_evtmgr_ptr = Ext.Debug.ReadPtr(base + SERVER_EVTMGR_OFFSET)
if svr_evtmgr_ptr then
    local vmt = Ext.Debug.ReadPtr(svr_evtmgr_ptr + 0x00)      -- VMT
    local callbacks_buf = Ext.Debug.ReadPtr(svr_evtmgr_ptr + 0x08)  -- Array.buf_
    local callbacks_cap = Ext.Debug.ReadU32(svr_evtmgr_ptr + 0x10)  -- Array.cap_
    local callbacks_size = Ext.Debug.ReadU32(svr_evtmgr_ptr + 0x14) -- Array.size_

    _P(string.format("VMT=0x%x, Callbacks: buf=0x%x, cap=%d, size=%d",
        vmt, callbacks_buf, callbacks_cap, callbacks_size))
end
```

#### Step 2.2: Expected Layout

```c
// macOS ARM64 GameStateEventManager (expected)
struct GameStateEventManager {
    void* VMT;           // +0x00 (8 bytes)
    void** buf_;         // +0x08 (8 bytes) - Callbacks array start
    uint32_t cap_;       // +0x10 (4 bytes) - Capacity
    uint32_t size_;      // +0x14 (4 bytes) - Current count
};
// Total: 0x18 bytes (24 bytes)
```

### Phase 3: Hook Implementation Strategy

**Option A: Vtable Hook (Preferred)**

Similar to Windows, inject our callback into the Callbacks array:

```c
// In main.c or new game_state.c module

typedef struct {
    void* VMT;            // Point to our custom vtable
    void* dummy;          // Padding to match expected layout
} GameStateHook;

// Custom vtable with OnGameStateChanged
static void* g_hook_vtable[] = {
    NULL,                           // [0] destructor (unused)
    hook_on_game_state_changed,     // [1] OnGameStateChanged callback
};

static void hook_on_game_state_changed(void* self, int fromState, int toState) {
    // Fire Lua event
    events_fire_game_state_changed(g_lua_state, fromState, toState);
}

void install_gamestate_hook(void) {
    GameStateEventManager** evtmgr_ptr = (void*)(g_module_base + OFFSET);
    if (evtmgr_ptr && *evtmgr_ptr) {
        GameStateHook* hook = malloc(sizeof(GameStateHook));
        hook->VMT = g_hook_vtable;

        // Add to Callbacks array
        // Need to call into game's array push or manipulate directly
    }
}
```

**Option B: Direct Function Hook (Fallback)**

Hook `GameStateMachine::Update` which is called on state transitions:

```c
// Hook GameStateMachine::Update
// typedef void (*GameStateMachine_Update)(void* self, GameTime* time);

static GameStateMachine_Update orig_gsm_update = NULL;
static int last_state = -1;

void hooked_gsm_update(void* self, void* time) {
    // Read current state from GameStateMachine
    int current_state = *(int*)((char*)self + STATE_OFFSET);

    if (current_state != last_state && last_state != -1) {
        events_fire_game_state_changed(g_lua_state, last_state, current_state);
    }
    last_state = current_state;

    orig_gsm_update(self, time);
}
```

**Option C: String Log Hook (Simplest)**

Hook the function that logs "SERVER STATE SWAP" since it already has fromState/toState:

```c
// Hook the log function that receives the state transition
// This function is called right before the actual state change
```

### Phase 4: Event System Integration

#### Step 4.1: Add Fire Function

In `lua_events.c`:

```c
/**
 * Fire the GameStateChanged event with FromState and ToState.
 */
void events_fire_game_state_changed(lua_State *L, int fromState, int toState) {
    if (!L) return;

    int count = g_handler_counts[EVENT_GAME_STATE_CHANGED];
    if (count == 0) return;

    log_message("[Events] Firing GameStateChanged (from=%d, to=%d)", fromState, toState);

    g_dispatch_depth[EVENT_GAME_STATE_CHANGED]++;

    for (int i = 0; i < g_handler_counts[EVENT_GAME_STATE_CHANGED]; i++) {
        EventHandler *h = &g_handlers[EVENT_GAME_STATE_CHANGED][i];
        if (h->callback_ref == LUA_NOREF) continue;

        lua_rawgeti(L, LUA_REGISTRYINDEX, h->callback_ref);
        if (!lua_isfunction(L, -1)) {
            lua_pop(L, 1);
            continue;
        }

        // Create event data table
        lua_newtable(L);
        lua_pushinteger(L, fromState);
        lua_setfield(L, -2, "FromState");
        lua_pushinteger(L, toState);
        lua_setfield(L, -2, "ToState");

        // Protected call
        if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            log_message("[Events] GameStateChanged handler error: %s", err ? err : "unknown");
            lua_pop(L, 1);
        }

        // Handle Once flag
        if (h->once) {
            if (g_deferred_unsub_count < MAX_DEFERRED_OPERATIONS) {
                g_deferred_unsubs[g_deferred_unsub_count++] =
                    (DeferredUnsubscribe){EVENT_GAME_STATE_CHANGED, h->handler_id};
            }
        }
    }

    g_dispatch_depth[EVENT_GAME_STATE_CHANGED]--;

    if (g_dispatch_depth[EVENT_GAME_STATE_CHANGED] == 0) {
        process_deferred_unsubscribes(L, EVENT_GAME_STATE_CHANGED);
    }
}
```

#### Step 4.2: Add State Name Resolution

```c
static const char* get_server_state_name(int state) {
    static const char* names[] = {
        "Unknown", "Uninitialized", "Init", "Idle", "Exit",
        "LoadLevel", "LoadModule", "LoadSession", "UnloadLevel", "UnloadModule",
        "UnloadSession", "Sync", "Paused", "Running", "Save",
        "Disconnect", "BuildStory", "ReloadStory"
    };
    if (state >= 0 && state < sizeof(names)/sizeof(names[0])) {
        return names[state];
    }
    return "Unknown";
}
```

#### Step 4.3: Lua Usage

```lua
-- Subscribe to game state changes
Ext.Events.GameStateChanged:Subscribe(function(e)
    _P(string.format("Game state: %d -> %d", e.FromState, e.ToState))

    if e.ToState == 13 then  -- Running
        _P("Game is now running!")
    elseif e.ToState == 12 then  -- Paused
        _P("Game is paused")
    end
end)
```

### Phase 5: Ghidra Script Implementation

Create `ghidra/scripts/find_gamestate_manager.py`:

```python
#!/usr/bin/env python
# Find GameStateEventManager global pointers for macOS ARM64
# Searches for "SERVER STATE SWAP" and "CLIENT STATE SWAP" strings

from ghidra.program.model.symbol import SymbolType
from ghidra.app.decompiler import DecompInterface
import ghidra.program.model.address as addr

def find_string_refs(search_str):
    """Find all references to a string in the binary."""
    results = []

    # Search in all defined strings
    for data in currentProgram.getListing().getDefinedData(True):
        if data.hasStringValue():
            val = data.getValue()
            if val and search_str in str(val):
                # Found the string, now find XREFs to it
                refs = getReferencesTo(data.getAddress())
                for ref in refs:
                    results.append({
                        'string_addr': data.getAddress(),
                        'string_val': str(val),
                        'ref_addr': ref.getFromAddress(),
                        'ref_type': str(ref.getReferenceType())
                    })
    return results

def analyze_function_for_global(func_addr):
    """Analyze function to find global pointer loads near string reference."""
    func = getFunctionContaining(func_addr)
    if not func:
        return None

    # Get instructions in the function
    inst_iter = currentProgram.getListing().getInstructions(func.getBody(), True)

    globals_found = []
    for inst in inst_iter:
        mnemonic = inst.getMnemonicString()

        # Look for ADRP + LDR pattern (ARM64 global access)
        if mnemonic == "adrp":
            # Check next instruction for ldr
            next_inst = inst.getNext()
            if next_inst and next_inst.getMnemonicString() == "ldr":
                # This might be loading a global
                for ref in next_inst.getReferencesFrom():
                    if ref.getReferenceType().isData():
                        globals_found.append({
                            'addr': ref.getToAddress(),
                            'inst_addr': inst.getAddress()
                        })

    return globals_found

def main():
    print("=" * 60)
    print("GameStateEventManager Discovery Script")
    print("=" * 60)

    # Search for server state swap string
    print("\n[1] Searching for 'SERVER STATE SWAP'...")
    server_refs = find_string_refs("SERVER STATE SWAP")

    if server_refs:
        print(f"    Found {len(server_refs)} references")
        for ref in server_refs:
            print(f"    String at {ref['string_addr']}, ref from {ref['ref_addr']}")

            # Analyze the function containing this reference
            globals_found = analyze_function_for_global(ref['ref_addr'])
            if globals_found:
                print(f"    Potential globals:")
                for g in globals_found:
                    print(f"      {g['addr']} (accessed at {g['inst_addr']})")
    else:
        print("    No references found")

    # Search for client state swap string
    print("\n[2] Searching for 'CLIENT STATE SWAP'...")
    client_refs = find_string_refs("CLIENT STATE SWAP")

    if client_refs:
        print(f"    Found {len(client_refs)} references")
        for ref in client_refs:
            print(f"    String at {ref['string_addr']}, ref from {ref['ref_addr']}")

            globals_found = analyze_function_for_global(ref['ref_addr'])
            if globals_found:
                print(f"    Potential globals:")
                for g in globals_found:
                    print(f"      {g['addr']} (accessed at {g['inst_addr']})")
    else:
        print("    No references found")

    print("\n" + "=" * 60)
    print("Script complete. Review output for GameStateEventManager addresses.")
    print("=" * 60)

main()
```

## Testing Plan

### Test 1: Ghidra Script Execution
```bash
./ghidra/scripts/run_analysis.sh find_gamestate_manager.py
```

### Test 2: Runtime Verification
```lua
-- Verify event fires on state transitions
Ext.Events.GameStateChanged:Subscribe(function(e)
    _P("STATE CHANGE: " .. e.FromState .. " -> " .. e.ToState)
end)
```

### Test 3: Integration Test
1. Start game, wait for main menu
2. Load a save
3. Pause/unpause game
4. Exit to menu
5. Verify all transitions logged

## Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `ghidra/scripts/find_gamestate_manager.py` | CREATE | Ghidra analysis script |
| `src/game/game_state.c` | CREATE | GameState hooking module |
| `src/game/game_state.h` | CREATE | Header with declarations |
| `src/lua/lua_events.c` | MODIFY | Add `events_fire_game_state_changed()` |
| `src/lua/lua_events.h` | MODIFY | Declare new function |
| `src/injector/main.c` | MODIFY | Install hook at startup |
| `CMakeLists.txt` | MODIFY | Add new source files |
| `ghidra/offsets/GAMESTATE.md` | CREATE | Document discovered offsets |

## Success Criteria

1. Ghidra script finds both server and client GameStateEventManager addresses
2. Runtime probing confirms structure layout matches Windows
3. Hook successfully captures state transitions
4. `Ext.Events.GameStateChanged` fires with correct FromState/ToState
5. No crashes or memory corruption during state transitions
6. Works in both single-player and (if applicable) co-op scenarios

## Risk Assessment

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| String not found in binary | Low | Strings are present in debug logs; search with partial match |
| Structure layout differs | Medium | Runtime probe before full implementation |
| Hook installation crashes | Medium | Start with Option C (log hook), validate before vtable manipulation |
| ARM64 calling convention issues | Medium | Test with simple logging first, add x8 buffer handling if needed |

## Estimated Effort

- Phase 1 (Ghidra Script): 2-3 hours
- Phase 2 (Structure Verification): 1-2 hours
- Phase 3 (Hook Implementation): 4-6 hours
- Phase 4 (Event Integration): 1-2 hours
- Phase 5 (Testing): 2-3 hours

**Total: ~12-16 hours**

## References

- Windows BG3SE: `BG3Extender/GameDefinitions/GameState.h`
- Windows BG3SE: `BG3Extender/GameHooks/BinaryMappings.xml` (lines 221-247)
- Windows BG3SE: `BG3Extender/Extender/ScriptExtender.cpp` (lines 478-491)
- Existing pattern: `ghidra/scripts/find_rpgstats.py` (similar string search)
