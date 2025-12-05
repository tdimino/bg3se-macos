# GlobalStringTable Discovery - ARM64 macOS

## Current Status: Incomplete

The GlobalStringTable is needed to resolve FixedString indices (like `0x20200011`) to actual string values (like `"Strength"`).

## What We Know

### FixedString Encoding (ARM64)
On macOS ARM64, FixedString is a 32-bit index, not a pointer:
```
uint32_t index = 0x20200011
subTableIdx = index & 0x0F          = 1  (0-10 for 11 subtables)
bucketIdx   = (index >> 4) & 0xFFFF = 0x2001
entryIdx    = index >> 20           = 0x20
```

### StringEntry Structure (Windows Reference)
From BG3SE Windows code, StringEntry layout is:
```c
struct StringEntry {
    uint32_t Hash;          // +0x00
    uint32_t RefCount;      // +0x04
    uint32_t Length;        // +0x08
    uint32_t Id;            // +0x0C (FixedString index)
    uint32_t NextFreeIndex; // +0x10
    uint32_t Reserved;      // +0x14
    char     String[];      // +0x18 (24 bytes header)
};
```

### SubTable Structure (Windows Reference)
```c
struct SubTable {
    uint32_t NumBuckets;        // +0x00 on Windows
    uint32_t EntriesPerBucket;  // +0x04 on Windows
    uint64_t EntrySize;         // +0x08 on Windows
    void*    Buckets;           // +0x10 on Windows
    // ... other fields
};
```

**Note:** ARM64 offsets may differ due to alignment.

## Discovery Attempts

### 1. dlsym Lookup - FAILED
Symbol `_ZN8GlobalStringTable5m_ptrE` is not exported.

### 2. Reference-Based Discovery - PARTIALLY SUCCESSFUL
Searched for known strings ("Strength", "Dexterity", etc.) in `__DATA` section:
- Found "Strength" at `0x10cd3f34b`
- Found "Weapon" at `0x10d6e3348`

However, header validation failed. These strings are **literal string constants** in the binary, NOT GlobalStringTable entries.

**Key Insight:** GlobalStringTable entries are in **heap memory**, not the binary `__DATA` section.

### 3. Exhaustive __DATA Probe - FAILED
Scanned 64MB of `__DATA` section looking for SubTable structure signatures. Found 0 candidates.

### 4. Interactive Console Exploration (Dec 5, 2025)

Using the new `Ext.Memory.*` API via file-based console:

**Module bases discovered:**
- `Baldur` (main game): `0x100f9c000`
- `libOsiris`: `0x10fa50000`
- `bg3se` (our dylib): `0x10fc3c000`

**String searches:**
- "Weapon" in binary range (`0x100f9c000` + 512MB): **62 matches**
- Sample addresses: `0x1087e41a9`, `0x1087e46c0`, `0x1087e61db`
- Bytes before strings show adjacent strings (packed string table), NOT GST headers

**Finding:** Strings at `0x1087e*` are **constant strings** in a read-only section, likely `__TEXT` or `__RODATA`. They're packed sequentially without the 24-byte GST header structure.

**"ProficiencyBonus" search:**
- Found at `0x1087e5160`
- Bytes before: `ls.thoth.shared.Entity.Get...` (Lua method path)
- Confirms these are Lua/script-related constant strings, not GST entries

## Next Steps

### Option A: Heap Memory Scanning (Most Promising)
The GlobalStringTable is allocated on the heap at runtime. Strategy:
1. Search higher memory ranges (`0x600000000+`) for GST header patterns
2. Look for the 24-byte header structure: `[Hash:4][RefCount:4][Length:4][Id:4][Next:4][Reserved:4][String...]`
3. Validate by checking if Id matches the expected FixedString index

**Console command for heap exploration:**
```lua
-- Search for potential GST entries with specific header patterns
local results = Ext.Memory.Search("XX XX XX XX 01 00 00 00", 0x600000000, 0x200000000)
```

### Option B: Function Hooking
Hook a function that uses FixedString resolution:
- `FixedString::GetString()`
- `FixedString::CreateFromRaw()`
- Capture the GlobalStringTable pointer when the function is called

### Option C: Ghidra Analysis
Find the GlobalStringTable via static analysis:
1. Search for XREF to "Strength" string
2. Find the code that creates FixedString("Strength")
3. Trace the GlobalStringTable access pattern

### Option D: Trace RPGStats String Access
Since RPGStats has FixedString fields:
1. Find the function that reads stat names
2. Hook it to capture GST pointer during string resolution

## Related Files
- `src/strings/fixed_string.c` - Current implementation
- `src/strings/fixed_string.h` - API declarations
- `src/stats/stats_manager.c` - Uses `fixed_string_resolve()`

## RPGStats Integration Status
- RPGStats pointer: FOUND at offset `0x89c5730`
- Stats Objects count: 15,774 entries
- Stats names: Showing as `<FSIdx:0x...>` (FixedString not resolved)
- `Ext.Stats.GetAll()`: Returns empty because type comparison fails without string resolution
