# Development Workflow

## Building

```bash
cd build && cmake .. && cmake --build .
# Output: build/lib/libbg3se.dylib
```

## Testing

```bash
./scripts/launch_bg3.sh  # Launch BG3 with dylib injected
tail -f "/Users/tomdimino/Library/Application Support/BG3SE/bg3se.log"
```

## Live Console (Rapid Iteration)

Send Lua commands to the running game without restart.

### Socket Console (Recommended)

The interactive socket console provides real-time bidirectional communication:

```bash
# Launch the game with BG3SE
./scripts/launch_bg3.sh

# In another terminal, connect with the console client
./build/bin/bg3se-console

# Or use socat/nc directly
socat - UNIX-CONNECT:/tmp/bg3se.sock
nc -U /tmp/bg3se.sock
```

Features:

- Real-time output (Ext.Print goes directly to console)
- Command history with arrow keys (readline)
- Multi-line input with `--[[` and `]]--` delimiters
- Tab completion (if configured in readline)
- ANSI color output for errors
- Automatic reconnection on disconnect

### File-Based Console (Fallback)

For simpler use cases or automation:

```bash
# Terminal 1: Watch output
tail -f "/Users/tomdimino/Library/Application Support/BG3SE/bg3se.log"

# Terminal 2: Send commands
echo 'Ext.Print("test")' > "/Users/tomdimino/Library/Application Support/BG3SE/commands.txt"
```

### Single-line Commands

```bash
# Memory inspection
echo 'Ext.Print(Ext.Memory.Read(Ext.Memory.GetModuleBase("Baldur"), 16))' > ~/Library/Application\ Support/BG3SE/commands.txt

# Stats inspection
echo 'local s = Ext.Stats.Get("WPN_Longsword"); Ext.Print(s.Damage)' > ~/Library/Application\ Support/BG3SE/commands.txt

# Debug memory probing (returns integer address)
echo '_P(_H(Ext.Stats.GetRawPtr()))' > ~/Library/Application\ Support/BG3SE/commands.txt
```

### Multi-line Blocks

Use `--[[` and `]]--` delimiters for multi-line Lua:

```bash
cat > ~/Library/Application\ Support/BG3SE/commands.txt << 'EOF'
--[[
local stat = Ext.Stats.Get("WPN_Longsword")
for k,v in pairs(stat) do
    Ext.Print(k .. " = " .. tostring(v))
end
]]--
EOF
```

### Console Commands (! prefix)

Register custom commands from Lua, then invoke with `!`:

```lua
-- In your mod's BootstrapServer.lua
Ext.RegisterConsoleCommand("probe", function(cmd, addr, range)
    local base = tonumber(addr, 16) or tonumber(addr)
    local results = Ext.Debug.ProbeStruct(base, 0, tonumber(range) or 256, 8)
    for offset, data in pairs(results) do
        if data.ptr then
            Ext.Print(string.format("+0x%x: ptr=0x%x", offset, data.ptr))
        end
    end
end)
```

Then use:

```bash
echo '!probe 0x12345678 0x100' > ~/Library/Application\ Support/BG3SE/commands.txt
echo '!help' > ~/Library/Application\ Support/BG3SE/commands.txt
```

### Global Debug Helpers

These shortcuts are available in the console:

| Helper | Description | Example |
|--------|-------------|---------|
| `_P(...)` | Print (alias for Ext.Print) | `_P("hello")` |
| `_D(obj)` | Dump object as JSON | `_D(Ext.Stats.Get("WPN_Longsword"))` |
| `_DS(obj)` | Dump shallow (depth=1) | `_DS(someTable)` |
| `_H(n)` | Format as hex | `_H(255)` → "0xff" |
| `_PTR(base, off)` | Pointer arithmetic | `_PTR(base, 0x10)` |
| `_PE(...)` | Print error | `_PE("failed!")` |

### Ext.Debug API (Memory Introspection)

Safe memory reading for offset discovery:

```lua
-- Read primitives (returns nil on bad address, never crashes)
Ext.Debug.ReadPtr(addr)         -- Read pointer
Ext.Debug.ReadU32(addr)         -- Read uint32
Ext.Debug.ReadU64(addr)         -- Read uint64
Ext.Debug.ReadI32(addr)         -- Read int32
Ext.Debug.ReadFloat(addr)       -- Read float
Ext.Debug.ReadString(addr, max) -- Read C string
Ext.Debug.ReadFixedString(addr) -- Read FixedString index

-- Struct probing (bulk offset discovery)
Ext.Debug.ProbeStruct(base, start, end, stride)
-- Returns: { [offset] = { ptr=..., u32=..., i32=..., float=... } }

-- Find array patterns (ptr, capacity, size)
Ext.Debug.FindArrayPattern(base, range)

-- Hex dump
Ext.Debug.HexDump(addr, size)
```

**Console Syntax:**

- Lines starting with `#` are comments (outside multi-line blocks)
- Use `>` (overwrite) not `>>` (append)
- File is deleted after processing
- Multi-line state resets on file end or error

## Debugging

- Logs: `/Users/tomdimino/Library/Application Support/BG3SE/bg3se.log`
- Cache: `/Users/tomdimino/Library/Application Support/BG3SE/`
- Use `log_message()` for consistent logging
- Osiris events logged with `[Osiris]` prefix

## Adding New APIs

### New Ext.* Function

1. Implement in `src/lua/lua_ext.c`
2. Declare in `src/lua/lua_ext.h`
3. Register in `lua_ext_register_*()` function

### New Osi.* Function

Dynamic Osi.* uses metatable `__index`. For explicit stubs:

1. Add to `register_osi_namespace()` in main.c
2. Implement the Lua C function

## Mod Loading

Mods loaded from:

1. `/tmp/<ModName>_extracted/` - Extracted mods for development
2. `~/Documents/Larian Studios/Baldur's Gate 3/Mods/` - User mods
3. PAK files - Compressed mods

## End-of-Session Checklist

When completing a feature or ending a session, update these files:

| File | What to Update |
|------|----------------|
| `docs/CHANGELOG.md` | Add entry for new version with Added/Changed/Technical sections |
| `src/core/version.h` | Bump `BG3SE_VERSION` if releasing |
| `CLAUDE.md` | Version number, API status summary, key offsets |
| `README.md` | Version number, feature status table |
| `ROADMAP.md` | Version number, feature details, version history table |

**Version history format** (in ROADMAP.md):
```
| v0.X.Y | YYYY-MM-DD | Brief description of changes (Issue #N) |
```

**Component count locations** (when adding components):
- `CLAUDE.md`: "X component property layouts" in Ext.Entity line
- `README.md`: "X component layouts" in status table
- `ROADMAP.md`: Section 2.2 status, component table, version history

**Parity percentage** (recalculate when adding significant features):
- `CLAUDE.md`: "Parity: ~XX%" in header line
- `README.md`: "Feature Parity: ~XX%" in Status section
- `ROADMAP.md`: "Overall Feature Parity: ~XX%" at top
- Calculation: Based on Feature Parity Matrix in ROADMAP.md (weighted by namespace importance)

**Technical documentation to update:**
- `ghidra/offsets/*.md` - New offsets discovered via reverse engineering
- `agent_docs/architecture.md` - New modules or structural changes
- `src/entity/component_offsets.h` - Component property layouts (self-documenting)
- `src/entity/component_typeid.c` - TypeId addresses with game version comments

## Component Generation Tools

Tools for accelerating component implementation (reaching Windows BG3SE parity).

### TypeId Extraction (`tools/extract_typeids.py`)

Extracts all component TypeId addresses from the macOS BG3 binary:

```bash
# Generate header with all TypeId addresses
python3 tools/extract_typeids.py > src/entity/generated_typeids.h

# Output includes:
# - 1,999 total component TypeIds
# - Categorized by namespace (eoc, esv, ecl, ls)
# - Ready-to-use C #define macros
```

### Component Stub Generator (`tools/generate_component_stubs.py`)

Generates C stubs from Windows BG3SE headers:

```bash
# List all eoc:: components
python3 tools/generate_component_stubs.py --namespace eoc --list

# Generate stubs for high-priority components
python3 tools/generate_component_stubs.py --high-priority > stubs.c

# Generate all components in a namespace
python3 tools/generate_component_stubs.py --namespace eoc > eoc_stubs.c
```

**Output includes:**
- Field names and types from Windows headers
- Estimated offsets (MUST be verified for ARM64)
- Registry entries for `g_AllComponentLayouts`

### Adding a New Component (Workflow)

1. **Find TypeId address:**
   ```bash
   nm -gU "/path/to/BG3" 2>/dev/null | c++filt | grep "TypeId.*YourComponent.*ComponentTypeIdContext"
   ```

2. **Generate stub from Windows header:**
   ```bash
   python3 tools/generate_component_stubs.py --namespace eoc --list | grep YourComponent
   ```

3. **Verify ARM64 offsets** (choose one method):
   - **Ghidra:** Analyze accessor functions for the component
   - **Runtime probing:** Use `Ext.Debug.ProbeStruct()` on a live entity
   - **Pattern matching:** Compare with similar verified components

4. **Add to codebase:**
   - `src/entity/component_typeid.c` - Add TypeIdEntry
   - `src/entity/component_offsets.h` - Add property definitions and registry entry

5. **Build and test:**
   ```bash
   cd build && cmake --build .
   # In game console:
   local e = Ext.Entity.Get("GUID"); _D(e.YourComponent)
   ```

### Component Coverage Statistics

| Namespace | Available | Implemented | Coverage |
|-----------|-----------|-------------|----------|
| eoc::     | 701       | ~30         | ~4%      |
| esv::     | 596       | 0           | 0%       |
| ecl::     | 429       | 2           | <1%      |
| ls::      | 233       | 4           | ~2%      |
| **Total** | **1,999** | **36**      | **~1.8%**|

**High-priority target:** 100-150 eoc:: components (~5-7% coverage) to support most mods.
