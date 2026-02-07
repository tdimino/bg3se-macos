# Debugging Strategies for Reverse Engineering

Proven debugging patterns extracted from successful bug fixes in BG3SE-macOS.

## Hypothesis-Driven Probing

**Don't explore randomly. Form hypotheses, then test them.**

### Workflow

1. **State hypothesis before probing**
   ```
   "TypeContext metadata should have count=37 at +0x00"
   ```

2. **Design minimal test**
   ```lua
   local ptr = <captured_pointer>
   _P("Count at +0x00: " .. Ext.Debug.ReadU32(ptr))
   ```

3. **Record result with timestamp**
   ```
   12:34:56 - Hypothesis CONFIRMED: count=37 at +0x00
   ```

4. **Form next hypothesis based on result**
   ```
   "Array pointer at +0x80 should point to feat entries"
   ```

### Why This Works

- Each hypothesis tested in isolation
- Results build confidence incrementally
- Failed hypotheses documented (prevents revisiting)
- Creates audit trail for future reference

## Multi-Layer Verification

**Never trust a single verification method. Use three independent layers.**

| Layer | Method | Confirms |
|-------|--------|----------|
| **Static** | Ghidra decompilation | Code structure, offsets |
| **Runtime** | Hook capture / console probing | Actual values at runtime |
| **Behavioral** | Lua API testing | End-to-end functionality |

### Example: Issue #40 Fix

```c
// Layer 1: Ghidra showed GetFeats reads +0x7C and +0x80
ldr w1,[x1, #0x7c]      ; count
ldr x20,[x20, #0x80]    ; array

// Layer 2: Hook confirmed real values
[Hook] FeatManager: 0x600001936b20, count=41, array=0x14badd800

// Layer 3: Lua API verified end-to-end
local feats = Ext.StaticData.GetAll("Feat")
print(#feats)  -- 41 ✓
```

### When Layers Disagree

If static and runtime disagree:
- Check if you're looking at different structures (metadata vs runtime)
- Verify game state (session active?)
- Confirm hook is on correct function

## Session-State Awareness

**Some data only exists during specific game states.**

### Common Session-Scoped Data

| Data | Available When |
|------|----------------|
| FeatManager (real) | Character creation / respec window open |
| Entity components | Entity exists in world |
| Combat data | Combat active |
| Dialogue state | Dialogue scene running |

### Debugging Pattern

```lua
-- Before testing session-scoped APIs
_P("Is manager ready: " .. tostring(Ext.StaticData.IsReady("Feat")))

-- If not ready, trigger the game state
-- (open feat window, enter combat, etc.)

-- Then retry
```

### Hook Timing

Hooks on session-scoped functions only fire during relevant sessions:

```c
// This hook ONLY fires when feat window is accessed
void hook_GetFeats(void* output, void* feat_manager) {
    g_real_feat_manager = feat_manager;  // Capture during session
}
```

## Safe Memory Probing

**Layer your safety checks. Don't crash on bad pointers.**

### Three-Layer Safety

```c
// Layer 1: Is address readable?
if (!safe_memory_read_ptr(addr, &value)) {
    return "unreadable";
}

// Layer 2: Is value semantically valid?
if (value == 0 || value > 0x7FFFFFFFFFFF) {
    return "invalid pointer";
}

// Layer 3: Can we read the target?
if (!safe_memory_read_u32(value, &data)) {
    return "target unreadable";
}

return data;
```

### Console Probing Pattern

```lua
-- Safe probe with validation
local function safe_probe(addr, offset)
    local ptr = Ext.Debug.ReadPtr(addr + offset)
    if not ptr or ptr == 0 then
        return nil, "null pointer"
    end
    if ptr < 0x100000000 then
        return nil, "looks like integer, not pointer"
    end
    return ptr
end
```

## Documentation-As-Verification

**Write documentation DURING investigation, not after.**

### Benefits

1. **Forces clarity** - Can't document what you don't understand
2. **Catches errors** - Writing reveals logical gaps
3. **Creates audit trail** - Future you will thank present you
4. **Enables review** - Others can spot mistakes

### Format That Works

```markdown
## Discovery: [What you found] (Date)

### Hypothesis
What you expected to find

### Method
How you tested it

### Result
What you actually found

### Implication
What this means for the fix
```

### Example

```markdown
## Discovery: TypeContext has count=37 at +0x00 (Dec 20, 2025)

### Hypothesis
FeatManager count should be at +0x7C based on Ghidra

### Method
Runtime probe via console: Ext.Debug.ReadU32(metadata + 0x00)

### Result
Count is at +0x00, not +0x7C. This is TypeContext METADATA, not FeatManager.

### Implication
We're probing the wrong structure. Need to capture real FeatManager via hook.
```

## Offset Discovery Workflow

### 1. Start with Static Analysis

```bash
# Find symbol
nm -gU "BG3" | c++filt | grep "FeatManager"

# Decompile in Ghidra
mcp__ghidra__decompile_function("GetFeats")
```

### 2. Identify Access Patterns

Look for:
```asm
ldr [reg], [base, #OFFSET]   ; Read from offset
str [reg], [base, #OFFSET]   ; Write to offset
add reg, base, #OFFSET       ; Calculate address
```

### 3. Document in Table Format

```markdown
| Field | Offset | Size | Verified | Method |
|-------|--------|------|----------|--------|
| count | +0x7C  | 4    | ✓        | Ghidra decompilation |
| array | +0x80  | 8    | ✓        | Ghidra + runtime |
| size  | 0x128  | -    | ✓        | MUL instruction |
```

### 4. Runtime Verify

```lua
local manager = <captured_ptr>
local count = Ext.Debug.ReadU32(manager + 0x7C)
local array = Ext.Debug.ReadPtr(manager + 0x80)
_P(string.format("count=%d, array=0x%x", count, array))
```

## ARM64-Specific Patterns

### const& Parameters = Pointers

C++ `const&` becomes pointer on ARM64:

```c
// C++ signature
void Init(const FixedString& name);

// ARM64 reality - x1 is POINTER to FixedString
void Init(FixedString* name_ptr);

// Correct call
g_Init(prototype, &name);  // Pass address, not value
```

### Implicit Register Passing

Functions can inherit parameters from callers:

```asm
GetAllFeats:
  mov x0, sp        ; setup output
  bl GetFeats       ; x1 already set by OUR caller!
```

Hook on GetFeats captures x1 even though GetAllFeats doesn't explicitly pass it.

### Large Struct Returns (>16 bytes)

Use x8 indirect return:

```c
LsResult result = {0};
__asm__ volatile (
    "mov x8, %[buf]\n"   // x8 = buffer for result
    "mov x0, %[arg]\n"   // x0 = first arg
    "blr %[fn]\n"        // call function
    : "+m"(result)
    : [buf] "r"(&result), [arg] "r"(arg), [fn] "r"(fn)
    : "x0", "x1", "x8", "memory"
);
```

## Debugging Checklist

When stuck on a reverse engineering problem:

```
□ Have I formed a specific hypothesis?
□ Am I testing the right structure (metadata vs runtime)?
□ Is the game in the correct state for this data?
□ Have I verified with multiple methods (static + runtime)?
□ Am I documenting as I go?
□ Have I checked ARM64 calling conventions?
□ Did I add safety checks before dereferencing?
```

## Crash Diagnostics (v0.36.39+)

BG3SE includes crash-resilient logging that survives SIGSEGV/SIGBUS/SIGABRT crashes.

### Crash Files

| File | Location | Purpose |
|------|----------|---------|
| `crash.log` | `~/Library/Application Support/BG3SE/crash.log` | Signal handler output (backtrace, breadcrumbs) |
| `crash_ring_<pid>.bin` | `~/Library/Application Support/BG3SE/crash_ring_*.bin` | mmap'd ring buffer (WARN+ log messages, survives crash) |
| `latest.log` | `~/Library/Application Support/BG3SE/logs/latest.log` | Normal session log (may be incomplete if crash) |

### Post-Crash Investigation

```bash
# 1. Check crash log for signal info + backtrace
cat ~/Library/Application\ Support/BG3SE/crash.log

# 2. Inspect ring buffer for last messages before crash
hexdump -C ~/Library/Application\ Support/BG3SE/crash_ring_*.bin | tail -40

# 3. Look for breadcrumb trail (shows exact dispatch path)
grep "Breadcrumb" ~/Library/Application\ Support/BG3SE/crash.log
```

### Breadcrumb Trail

The crash handler dumps a breadcrumb ring showing the last 32 function entries before the crash. Each entry includes `__func__` name, a funcId/handle, and a timestamp. Useful for tracing which Osiris dispatch path was active when the crash occurred.

### OsiFunctionDef Probe (`!probe_osidef`)

On-demand console command to dump raw OsiFunctionDef structs:

```bash
echo '!probe_osidef 10' | nc -U /tmp/bg3se.sock
```

Outputs hex dumps with annotated Type (+0x28) and Key[2]/funcId (+0x30) fields. Use to verify ARM64 struct layout matches Windows offsets.

### Osiris Handle Encoding

DivFunctions::Call/Query expect encoded 32-bit `OsirisFunctionHandle`, not raw funcId:
- Bits 0-2: FunctionType (1=Event, 2=Query, 3=Call, 4=Database, 5=Proc)
- Bits 3-27: funcId (for type < 4, 25-bit)
- Bit 31: Part4

If a crash occurs in the Osiris dispatch path, check:
1. Is the handle correctly encoded? (look for `handle=0x` in logs)
2. Does the funcType match the function? (`type=0` is the old bug)
3. Are Key[0..3] offsets correct for ARM64? (use `!probe_osidef` to verify)

## Related Documentation

- `agent_docs/meridian-persona.md` - RE persona and approach
- `agent_docs/ghidra.md` - Ghidra workflow and MCP usage
- `docs/solutions/reverse-engineering/` - Specific solved problems
- `ghidra/offsets/` - Discovered offset documentation
