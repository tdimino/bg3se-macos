# Testing Optimization Plan

## Overview

Improvements to the BG3SE console and testing workflow to reduce friction during debugging sessions. Based on learnings from Issue #32 Stats Sync debugging where iterative probing was slow and error-prone.

## Problem Statement

Current debugging workflow requires:
- Sending one command at a time via `echo 'cmd' | nc -U /tmp/bg3se.sock`
- Re-typing complex probe sequences for each iteration
- Losing context between commands (Lua state persists but no helper functions)
- Manual calculation of offsets and address math

This makes debugging sessions like RefMap structure discovery take 20+ iterations when it could take 3-5.

---

## Proposed Improvements

### Priority 1: Preloaded Debug Helpers

**Description:** Auto-load a debug helper module on console connect that provides common probing functions.

**Functions to implement:**

```lua
-- Search a RefMap linearly for a key, return index + prototype address
function SearchRefMap(manager_addr, fs_key)
    -- Iterate through entries, return {index=N, key=K, value=V}
end

-- Probe struct fields with automatic hex formatting
function ProbeFields(base, offsets)
    -- offsets = {{name="buckets", off=0x08, size=8}, ...}
    -- Returns formatted table
end

-- Read array slice
function ReadArray(base, elem_size, start_idx, count)
    -- Returns array of values
end

-- Find FixedString by name (searches GlobalStringTable)
function FindFS(name)
    -- Returns FS index or nil
end
```

**Implementation:**
- Create `src/lua/lua_debug_helpers.c` with these functions
- Register as `_G.Debug.*` namespace
- Auto-load when console connects

**Effort:** ~2 hours

---

### Priority 2: Script File Execution

**Description:** Execute Lua scripts from files, enabling saved debug sequences.

**API:**
```lua
-- In console:
dofile("/path/to/probe_refmap.lua")

-- Or from command line:
echo 'dofile("/tmp/test.lua")' | nc -U /tmp/bg3se.sock
```

**Implementation:**
- `dofile()` is standard Lua, should already work
- Add `Ext.IO.LoadScript(path)` for sandboxed variant
- Support relative paths from `~/Library/Application Support/BG3SE/scripts/`

**Effort:** ~1 hour (mostly testing existing `dofile`)

---

### Priority 3: Result Buffering

**Description:** Accumulate results in a global table for batch inspection.

**Usage:**
```lua
-- During probing
_R = _R or {}
_R.spell_mgr = Ext.Debug.ReadPtr(0x1089bac80)
_R.capacity = Ext.Debug.ReadU32(_R.spell_mgr + 0x10)
_R.keys = Ext.Debug.ReadPtr(_R.spell_mgr + 0x28)

-- Inspect all at once
_D(_R)
```

**Implementation:**
- Already works with standard Lua! Just document the pattern.
- Optionally add `Ext.Debug.DumpResults()` helper

**Effort:** ~30 min (documentation + optional helper)

---

### Priority 4: Multi-Command Batching

**Description:** Send multiple commands in one socket message, executed sequentially.

**Usage:**
```bash
cat << 'EOF' | nc -U /tmp/bg3se.sock
local mgr = Ext.Debug.ReadPtr(0x1089bac80)
local cap = Ext.Debug.ReadU32(mgr + 0x10)
print("Capacity:", cap)
EOF
```

**Implementation:**
- Console already supports multi-line via `--[[ ... ]]--`
- Could add delimiter-based batching (e.g., `---NEXT---`)

**Effort:** ~1 hour

---

### Priority 5: Address Calculator

**Description:** Built-in hex math functions to reduce manual calculation.

**Functions:**
```lua
-- Hex string to number
function hex(s) return tonumber(s, 16) end

-- Number to hex string
function tohex(n) return string.format("0x%X", n) end

-- Add with hex output
function hexadd(base, offset) return tohex(hex(base) + offset) end
```

**Implementation:**
- Simple Lua functions, preload with debug helpers

**Effort:** ~15 min

---

## Implementation Order

| Phase | Items | Time |
|-------|-------|------|
| 1 | Priority 3 (document result buffering) | 30 min |
| 2 | Priority 5 (address calculator) | 15 min |
| 3 | Priority 2 (verify dofile works) | 1 hour |
| 4 | Priority 1 (debug helpers module) | 2 hours |
| 5 | Priority 4 (multi-command batching) | 1 hour |

**Total:** ~5 hours

---

## Success Criteria

- [ ] `_R = {}` pattern documented and working
- [ ] `hex()` and `tohex()` available in console
- [ ] `dofile("/path/to/script.lua")` works
- [ ] `Debug.SearchRefMap(mgr, key)` finds entries in one call
- [ ] Complex probe sequences can be saved and replayed

---

## Example: Optimized RefMap Debugging

**Before (20+ commands):**
```bash
echo 'local m=Ext.Debug.ReadPtr(0x1089bac80); print(m)' | nc -U /tmp/bg3se.sock
echo 'local c=Ext.Debug.ReadU32(105553168907680+0x10); print(c)' | nc -U /tmp/bg3se.sock
# ... repeat 18 more times
```

**After (1 command):**
```bash
cat ~/scripts/probe_spell_refmap.lua | nc -U /tmp/bg3se.sock
```

Where `probe_spell_refmap.lua` contains:
```lua
_R = {}
_R.mgr = Ext.Debug.ReadPtr(0x1089bac80)
_R.capacity = Ext.Debug.ReadU32(_R.mgr + 0x10)
_R.keys = Ext.Debug.ReadPtr(_R.mgr + 0x28)
_R.values = Ext.Debug.ReadPtr(_R.mgr + 0x38)

-- Find FireBolt
local fs_key = 512753744
local result = Debug.SearchRefMap(_R.mgr, fs_key)
if result then
    print("Found at index", result.index, "prototype:", tohex(result.value))
end

_D(_R)
```
