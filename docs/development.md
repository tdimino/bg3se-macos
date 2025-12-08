# Development Guide

Guide for contributors working on BG3SE-macOS.

## Building

```bash
cd bg3se-macos
./scripts/build.sh
# Output: build/lib/libbg3se.dylib
```

Or manually:
```bash
cd build && cmake .. && cmake --build .
```

## Testing

```bash
# Launch BG3 with dylib injected
./scripts/launch_bg3.sh

# Watch logs (check system time first to filter old entries)
date && tail -f ~/Library/Application\ Support/BG3SE/bg3se.log
```

## Live Console (Rapid Iteration)

Send Lua commands to the running game without restart.

### Socket Console (Recommended)

Real-time bidirectional communication:

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
- ANSI color output for errors
- Automatic reconnection on disconnect

### File-Based Console (Fallback)

```bash
# Terminal 1: Watch output
tail -f ~/Library/Application\ Support/BG3SE/bg3se.log

# Terminal 2: Send commands
echo 'Ext.Print("test")' > ~/Library/Application\ Support/BG3SE/commands.txt
```

### Multi-line Blocks

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

```bash
echo '!help' > ~/Library/Application\ Support/BG3SE/commands.txt
echo '!probe 0x12345678 256' > ~/Library/Application\ Support/BG3SE/commands.txt
echo '!dumpstat WPN_Longsword' > ~/Library/Application\ Support/BG3SE/commands.txt
```

### Global Debug Helpers

| Helper | Description | Example |
|--------|-------------|---------|
| `_P(...)` | Print (alias for Ext.Print) | `_P("hello")` |
| `_D(obj)` | Dump object as JSON | `_D(Ext.Stats.Get("WPN_Longsword"))` |
| `_DS(obj)` | Dump shallow (depth=1) | `_DS(someTable)` |
| `_H(n)` | Format as hex | `_H(255)` → "0xff" |
| `_PTR(base, off)` | Pointer arithmetic | `_PTR(base, 0x10)` |
| `_PE(...)` | Print error | `_PE("failed!")` |

## Debugging

- **Logs:** `~/Library/Application Support/BG3SE/bg3se.log`
- **Cache:** `~/Library/Application Support/BG3SE/`
- Use `log_message()` or structured logging macros for output
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

Mods loaded from (in order):

1. `/tmp/<ModName>_extracted/` - Extracted mods for development
2. `~/Documents/Larian Studios/Baldur's Gate 3/Mods/` - User mods
3. PAK files - Compressed mods (read directly)

## Test Mod

We maintain a custom test mod for validating functionality. See [tools/test-mods/README.md](../tools/test-mods/README.md).

```bash
# Copy test mod to auto-detection path
cp -r tools/test-mods/EntityTest /tmp/EntityTest_extracted

# Launch game - mod loads automatically
./scripts/bg3w.sh

# Watch for test output
tail -f ~/Library/Application\ Support/BG3SE/bg3se.log | grep EntityTest
```

The EntityTest mod validates:
- Entity system initialization (`Ext.Entity.IsReady()`)
- GUID → Entity lookup (`Ext.Entity.Get()`)
- Component access (`entity.Transform`, `entity:GetComponent()`)
- Session lifecycle events (`SessionLoaded`)

## Conventions

- Modular design: each subsystem is header+source pair with static state
- Prefix public functions with module name (`stats_get_string()`)
- Extract from main.c when code exceeds ~100 lines with isolated state
- Use structured logging macros (`LOG_LUA_INFO`, `LOG_OSIRIS_DEBUG`, etc.)

## Structured Logging

Use module-specific macros instead of raw `log_message()`:

```c
// Log levels: DEBUG, INFO, WARN, ERROR
LOG_LUA_INFO("Loaded script: %s", path);
LOG_OSIRIS_DEBUG("Function %s called", funcName);
LOG_ENTITY_WARN("Component not found: %s", name);
LOG_STATS_ERROR("Failed to load stat: %s", statName);
```

Available modules: `CORE`, `CONSOLE`, `LUA`, `OSIRIS`, `ENTITY`, `EVENTS`, `STATS`, `TIMER`, `HOOKS`, `MOD`, `MEMORY`, `PERSIST`, `GAME`, `INPUT`

## Codebase Search (osgrep)

Use semantic search for finding code:

```bash
# Search this project
osgrep "how does event dispatch work"
osgrep "where are stats properties resolved"
osgrep "ARM64 indirect return pattern"

# Search Windows BG3SE reference
osgrep "entity manager" -p /Users/tomdimino/Desktop/Programming/bg3se
osgrep "Lua component binding" -p /Users/tomdimino/Desktop/Programming/bg3se
```

## Tools

### Claude Code Skills

Install the BG3SE development skill:
```bash
cp -r tools/skills/bg3se-macos-ghidra ~/.claude/skills/
# Then: skill: "bg3se-macos-ghidra"
```

### PAK Extractor

```bash
pip3 install lz4
python3 tools/extract_pak.py path/to/mod.pak [output_dir]
```

### Frida Scripts

Runtime analysis scripts in `tools/frida/`.
