# Development Workflow

## Building

```bash
cd build && cmake .. && cmake --build .
# Output: build/lib/libbg3se.dylib
```

### After Moving the Repository

If you move the repository to a new directory, **you must regenerate the CMake cache**:

```bash
# Delete stale cache and rebuild
cd /path/to/new/location
rm -rf build
mkdir build && cd build
cmake .. && cmake --build .
```

**Why?** CMake caches absolute paths in `build/CMakeCache.txt`. A stale cache pointing to the old directory will cause:
- Silent build failures
- Code changes not being compiled
- Outdated dylib being deployed

**Symptoms of stale cache:**
- `CMake Error: The source directory "..." does not exist`
- Changes to source files don't appear in the running game
- Build completes but behavior doesn't match code

## Testing

```bash
./scripts/launch_bg3.sh  # Launch BG3 with dylib injected
tail -f "/Users/tomdimino/Library/Application Support/BG3SE/bg3se.log"
```

### Log Monitoring

Filter logs for specific patterns:

```bash
# Exclude noisy Osiris events
tail -f "/Users/tomdimino/Library/Application Support/BG3SE/bg3se.log" | grep -v "\[Osiris\]"

# Filter for errors/warnings only
tail -f "/Users/tomdimino/Library/Application Support/BG3SE/bg3se.log" | grep -E "ERROR|WARN"

# Session-based logs (v0.36.12+)
tail -f "/Users/tomdimino/Library/Application Support/BG3SE/logs/latest.log"
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

### Built-in Console Commands

| Command | Description |
|---------|-------------|
| `!help` | Show all available commands |
| `!events` | Show event handler counts |
| `!status` | Show BG3SE status (socket, clients, commands) |
| `!typeids` | Show TypeId resolution status |
| `!probe_osidef [N]` | Hex dump OsiFunctionDef layout for N functions (default 5) |

### Crash Diagnostics (v0.36.39+)

Crash-safe files in `~/Library/Application Support/BG3SE/`:

| File | Purpose |
|------|---------|
| `crash_ring_<pid>.bin` | mmap'd 16KB ring buffer (survives SIGSEGV) |
| `crash.log` | Signal handler output: signal, fault addr, breadcrumbs, backtrace |

```bash
# After a crash, check these:
hexdump -C ~/Library/Application\ Support/BG3SE/crash_ring_*.bin | tail -40
cat ~/Library/Application\ Support/BG3SE/crash.log
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

-- Time utilities (correlate console with logs)
Ext.Debug.Time()                -- Current time "HH:MM:SS"
Ext.Debug.Timestamp()           -- Unix timestamp (seconds)
Ext.Debug.SessionStart()        -- Session start time "HH:MM:SS"
Ext.Debug.SessionAge()          -- Seconds since session started
Ext.Debug.PrintTime(msg)        -- Print with timestamp prefix

-- Pointer validation (prevent invalid derefs)
Ext.Debug.IsValidPointer(addr)  -- Returns true if readable
Ext.Debug.ClassifyPointer(addr) -- Returns { type, readable, preview? }
-- Types: "null", "small_int", "invalid", "string", "vtable", "heap", "data", "stack"
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
   - `src/entity/generated_typeids.h` - Add TYPEID_* macro (auto-generated)
   - `src/entity/generated_component_registry.c` - Add to namespace array (auto-generated)
   - `src/entity/component_offsets.h` - Add property definitions and registry entry (manual)

5. **Build and test:**
   ```bash
   cd build && cmake --build .
   # In game console:
   local e = Ext.Entity.Get("GUID"); _D(e.YourComponent)
   ```

### Component Coverage Statistics (Dec 2025)

**Unified Size Database:**
- **1,577 ARM64 sizes** - Ghidra MCP decompilation (AddComponent pattern)
- **702 Windows estimates** - Parsed from C++ headers
- **1,730 total with size info** (87% of 1,999 TypeIds)

| Namespace | TypeIds | Ghidra | Windows | Missing | % Gap |
|-----------|---------|--------|---------|---------|-------|
| eoc::     | 913     | 758    | 367     | 126     | 14%   |
| esv::     | 889     | 512    | 222     | 298     | 34%   |
| ecl::     | 542     | 155    | 56      | 351     | 65%   |
| ls::      | 263     | 130    | 57      | 118     | 45%   |
| gui::     | 26      | 0      | 0       | 26      | 100%  |
| navcloud::| 18      | 16     | 0       | 2       | 11%   |
| **Total** | **2,652** | **1,577** | **702** | **922** | **35%** |

**Phase 3 Priority:** ecl:: (351 gaps, 65%) > esv:: (298) > ls:: (118) > eoc:: (126)

**Note:** Total exceeds 1,999 TypeIds due to sub-namespace variants discovered in Ghidra.

**Implementation notes:**
- Verified layouts from `g_AllComponentLayouts` take precedence over generated
- Generated layouts use `Gen_` prefix to avoid symbol conflicts
- MAX_COMPONENT_LAYOUTS = 1024 (increased from 128)

### TypeId Discovery Flow

At runtime, TypeId globals are read to discover component type indices:

1. **Registration** (`component_registry_register_all_generated()`)
   - All 1,999 components registered with `COMPONENT_INDEX_UNDEFINED` (65535)
   - TypeId addresses stored but not yet read

2. **Discovery** (`component_typeid_discover()`)
   - Reads known TypeIds from `g_KnownTypeIds` (164 manually verified)
   - Calls `component_typeid_discover_all_generated()` for remaining 1,835
   - Iterates all namespace arrays in `generated_component_registry.c`
   - Updates registry with actual TypeIndex values

3. **Result**
   - Components with valid TypeIndex (0-65534) → can be queried
   - Components with TypeIndex 65535 → address wrong or not initialized

**Key files:**
- `src/entity/generated_typeids.h` - TYPEID_* macros (Ghidra addresses)
- `src/entity/generated_component_registry.c` - Component arrays + discovery
- `src/entity/component_typeid.c` - Memory reading logic

## Ghidra MCP Batch Extraction Workflow

For bulk component size extraction using Ghidra MCP and parallel subagents.

### Prerequisites

1. **Ghidra with MCP plugin** - Ghidra 11.3+ with pyghidra-mcp installed
2. **BG3 binary loaded** - ARM64 slice of Baldur's Gate 3 analyzed
3. **Claude Code** - With Task tool for launching subagents

### The Pattern

Component sizes are extracted from `AddComponent<T>` template functions:

```c
// Ghidra decompilation shows:
ComponentFrameStorageAllocRaw((ComponentFrameStorage*)(this_00 + 0x48), SIZE, ...)
//                                                                      ^^^^
//                                                        Second argument = component size in bytes
```

### Parallel Agent Workflow

**Step 1: Search for AddComponent functions**
```
mcp__ghidra__search_functions_by_name(query="AddComponent", offset=0, limit=50)
```

**Step 2: Launch parallel extraction agents**
```
Task tool with subagent_type="general-purpose":
- Agent 1: Extract components at offset 0-50
- Agent 2: Extract components at offset 50-100
- Agent 3: Extract components at offset 100-150
... (8-10 agents in parallel)
```

**Step 3: Each agent decompiles and extracts sizes**
```python
# For each function in range:
mcp__ghidra__decompile_function(name="AddComponent<eoc::HealthComponent>")
# Parse output for ComponentFrameStorageAllocRaw SIZE parameter
# Return results in markdown table format
```

**Step 4: Agents write to staging (prevents context loss)**
Include in each agent prompt:
```
Write your final results to: ghidra/offsets/staging/AGENT_NAME.md
```

Agents write directly to staging:
```
ghidra/offsets/staging/
├── alpha_eoc_1500-1600.md
├── bravo_eoc_1600-1700.md
├── charlie_esv_500-600.md
└── ...
```

**Fallback:** If an agent fails to write, the primary session writes the output manually after TaskOutput retrieval.

This prevents losing agent outputs during context compaction. The staging directory persists even if the conversation resets.

**Step 5: Consolidate to main docs**
After all agents complete, merge staging files into documentation:
- eoc:: namespaced → ghidra/offsets/COMPONENT_SIZES_EOC_NAMESPACED.md
- eoc:: boost → ghidra/offsets/COMPONENT_SIZES_EOC_BOOST.md
- ls:: → ghidra/offsets/COMPONENT_SIZES_LS.md
- esv:: → ghidra/offsets/COMPONENT_SIZES_ESV.md
- ecl:: → ghidra/offsets/COMPONENT_SIZES_ECL.md

Then wipe staging: `rm ghidra/offsets/staging/*.md`

### Documentation Structure

Results organized by namespace in `ghidra/offsets/`:

| File | Contents |
|------|----------|
| `COMPONENT_SIZES.md` | Master index with statistics |
| `COMPONENT_SIZES_EOC_CORE.md` | Core eoc:: components |
| `COMPONENT_SIZES_EOC_BOOST.md` | All boost components |
| `COMPONENT_SIZES_EOC_NAMESPACED.md` | Sub-namespaced components |
| `COMPONENT_SIZES_LS.md` | Larian engine components |
| `COMPONENT_SIZES_ESV.md` | Server components |
| `COMPONENT_SIZES_ECL.md` | Client components |
| `COMPONENT_SIZES_NAVCLOUD.md` | Navigation components |

### Tips for Effective Extraction

1. **Use pagination** - There are 2000+ AddComponent functions; process in batches
2. **Skip failures silently** - Not all functions decompile cleanly
3. **Match namespace patterns** - Group by prefix (eoc::, esv::, ls::, etc.)
4. **Note heap allocations** - Some sizes show malloc size, not inline size
5. **Document new namespaces** - Create new files when discovering new prefixes
