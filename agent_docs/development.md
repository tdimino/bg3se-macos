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

Send Lua commands to the running game without restart:

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
