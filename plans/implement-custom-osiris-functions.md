# Plan: Custom Osiris Function Registration (ROADMAP Phase 4.1)

## Overview

Implement `Ext.Osiris.RegisterCall()` and `Ext.Osiris.RegisterQuery()` APIs to allow mods to register custom Osiris functions callable via the `Osi.*` namespace.

## Target API (from ROADMAP.md)

```lua
-- Register a custom query (returns value)
Ext.Osiris.RegisterQuery("MyMod_IsPlayerNearby", 2, function(x, y)
    -- x, y are input parameters
    -- Return value(s) become output
    return distance < 10
end)

-- Register a custom call (no return)
Ext.Osiris.RegisterCall("MyMod_SpawnEffect", 3, function(effect, x, y)
    _P("[MyMod] Spawning " .. effect .. " at " .. x .. ", " .. y)
end)

-- Use registered functions via Osi.* namespace
local isNearby = Osi.MyMod_IsPlayerNearby(100, 200)
Osi.MyMod_SpawnEffect("fire", 100, 200)
```

## Architecture

### Approach: Lua-Side Custom Function Registry

Unlike Windows BG3SE which injects into story compilation, we'll use a **Lua-side interception** approach:

1. Custom functions are registered in a C-side registry (name → handler)
2. When `osi_dynamic_call` dispatches a function, it checks the custom registry FIRST
3. If found, execute the Lua handler directly (bypass InternalQuery/InternalCall)
4. If not found, fall through to normal Osiris dispatch

This approach:
- Works without story recompilation
- Enables Lua-to-Lua custom functions via Osi.* namespace
- Simpler than Windows BG3SE's approach
- Covers 90% of use cases (mod-internal custom functions)

### Limitation

Custom functions registered this way are NOT callable from story scripts (.goal files) since those are pre-compiled. This matches what most mods actually need - they use custom Osiris functions for Lua-to-Lua communication, not story script integration.

## Implementation

### Phase 1: Custom Function Registry (src/osiris/custom_functions.c)

```c
// Data structures
typedef enum {
    CUSTOM_FUNC_CALL = 1,   // No return value
    CUSTOM_FUNC_QUERY = 2   // Returns value(s)
} CustomFuncType;

typedef struct {
    char name[128];
    CustomFuncType type;
    int arity;           // Number of input parameters
    int callback_ref;    // Lua registry reference (luaL_ref)
    bool active;
} CustomFunction;

// Registry (max 256 custom functions)
#define MAX_CUSTOM_FUNCTIONS 256
static CustomFunction g_customFunctions[MAX_CUSTOM_FUNCTIONS];
static int g_customFunctionCount = 0;

// API
int custom_func_register(const char* name, CustomFuncType type, int arity, int callback_ref);
CustomFunction* custom_func_find(const char* name);
int custom_func_dispatch(lua_State* L, CustomFunction* func);  // Returns nresults
void custom_func_reset(void);  // Clear all on session reset
```

### Phase 2: Lua Bindings (src/lua/lua_osiris.c)

Add to existing lua_osiris.c:

```c
// Ext.Osiris.RegisterCall(name, arity, handler)
static int lua_ext_osiris_registercall(lua_State *L);

// Ext.Osiris.RegisterQuery(name, arity, handler)
static int lua_ext_osiris_registerquery(lua_State *L);
```

Simple signature: `(name, arity, callback)` - matches ROADMAP.md
- `name` - Function name (e.g., "MyMod_Log")
- `arity` - Number of input parameters
- `callback` - Lua function to call

### Phase 3: Dispatch Integration (src/injector/main.c)

Modify `osi_dynamic_call()` to check custom registry:

```c
static int osi_dynamic_call(lua_State *L) {
    const char *funcName = lua_tostring(L, lua_upvalueindex(1));

    // CHECK CUSTOM FUNCTIONS FIRST
    CustomFunction* custom = custom_func_find(funcName);
    if (custom) {
        return custom_func_dispatch(L, custom);
    }

    // Fall through to normal Osiris dispatch...
    uint32_t funcId = osi_func_lookup_id(funcName);
    // ... existing code ...
}
```

## Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `src/osiris/custom_functions.c` | CREATE | Registry implementation |
| `src/osiris/custom_functions.h` | CREATE | Public API |
| `src/lua/lua_osiris.c` | MODIFY | Add RegisterCall/RegisterQuery bindings |
| `src/lua/lua_osiris.h` | MODIFY | Declare new functions |
| `src/injector/main.c` | MODIFY | Integrate custom dispatch in osi_dynamic_call |
| `CMakeLists.txt` | MODIFY | Add new source file |

## Key Implementation Details

### Dispatch Implementation

```c
int custom_func_dispatch(lua_State *L, CustomFunction* func) {
    int nargs = lua_gettop(L);

    // Push handler from registry
    lua_rawgeti(L, LUA_REGISTRYINDEX, func->callback_ref);

    // Push all arguments
    for (int i = 1; i <= nargs; i++) {
        lua_pushvalue(L, i);
    }

    // Call handler - use LUA_MULTRET for queries
    int nresults = (func->type == CUSTOM_FUNC_QUERY) ? LUA_MULTRET : 0;
    if (lua_pcall(L, nargs, nresults, 0) != 0) {
        LOG_OSIRIS_ERROR("Custom %s %s failed: %s",
            func->type == CUSTOM_FUNC_CALL ? "call" : "query",
            func->name, lua_tostring(L, -1));
        lua_pop(L, 1);
        return 0;
    }

    // For queries, return however many values the handler returned
    // For calls, return 0
    return (func->type == CUSTOM_FUNC_QUERY) ? (lua_gettop(L) - nargs) : 0;
}
```

### Session Reset

Clear custom functions on session reset to prevent stale handlers:

```c
// In session reset handler
custom_func_reset();
lua_osiris_reset_listeners();
```

## Testing

1. **Basic Call**: Register `MyMod_Log`, call `Osi.MyMod_Log("test")`, verify output
2. **Basic Query**: Register `MyMod_Add`, call `local sum = Osi.MyMod_Add(1, 2)`, verify returns 3
3. **Multi-return Query**: Register `MyMod_GetPos`, return x, y, z, verify all values returned
4. **Error Handling**: Invalid params, missing handler, wrong arity
5. **Session Reset**: Verify functions cleared on reload
6. **No Regression**: Existing `Osi.*` functions still work

## Success Criteria

- [ ] `Ext.Osiris.RegisterCall()` registers callable functions
- [ ] `Ext.Osiris.RegisterQuery()` registers queries with return values
- [ ] Custom functions accessible via `Osi.*` namespace
- [ ] Existing Osiris functions still work (no regression)
- [ ] Functions cleared on session reset
- [ ] Error handling for invalid registration/calls

## Implementation Order

1. Create `src/osiris/custom_functions.c/h` with registry
2. Add `lua_ext_osiris_registercall()` to `lua_osiris.c`
3. Add `lua_ext_osiris_registerquery()` to `lua_osiris.c`
4. Modify `osi_dynamic_call()` in `main.c` to check custom registry first
5. Add reset call in session reset handler
6. Test with console commands
