# Plan: Ghidra Script for Modifier Attribute Discovery

## Overview

Create a targeted Ghidra script to discover the remaining offsets needed to implement `stats_get_string()` and complete Issue #3 (Ext.Stats API). The script will focus on finding the correct Modifier structure layout and property pool offsets on ARM64.

## Problem Statement

We can read raw `IndexedProperties` values (61 int32_t indices for WPN_Longsword), but cannot:
1. Map property names ("Damage", "DamageType") to IndexedProperty indices
2. Resolve pool indices to actual values (strings, floats, etc.)

**Root cause:** The Modifier structure offsets are wrong on ARM64. Our current dump shows garbage strings instead of attribute names like "Damage".

**Evidence from logs:**
```
[Stats] === ModifierList[8] 'Weapon' Attributes ===
[Stats] Attributes count: 61, buf: 0x50286d390
[Stats]   [0] 'Public/Shared/Assets/Buildings/...' (enum_idx=53)  # GARBAGE!
[Stats]   [10] 'Delay' (enum_idx=54)  # This looks correct!
[Stats]   [38] 'OFFHAND' (enum_idx=53)  # This looks correct!
```

Some entries show valid-looking names, but most are garbage - indicating the Modifier struct layout differs from our assumptions.

## Technical Background

### Windows BG3SE Property Access Flow

```
PropertyName: "Damage"
    ↓
Object.ModifierListIndex → ModifierList (e.g., "Weapon")
    ↓
ModifierList.Attributes.GetHandleByName("Damage")
    ↓
Returns: attributeIndex (e.g., 12)
    ↓
Object.IndexedProperties[12] → value or pool_index
    ↓
If pool_index: RPGStats.Floats[pool_index] → actual float value
```

### Modifier Structure (Windows)

```cpp
struct Modifier {
    int32_t EnumerationIndex;  // +0x00: Index into ModifierValueLists
    int32_t LevelMapIndex;     // +0x04: For level scaling
    int32_t UnknownZero;       // +0x08: Always 0
    FixedString Name;          // +0x0C (x86) or +0x10 (ARM64 aligned)
};
```

### What We've Verified
- RPGStats::m_ptr: `0x1089c5730` (via dlsym)
- ModifierLists offset: `+0x60` (9 entries)
- Objects offset: `+0xC0` (15,774 entries)
- CNamedElementManager layout: buf_=+0x08, size_=+0x14
- Object.IndexedProperties: Vector at +0x08, 61 entries for weapons

### What's Missing
1. **Modifier.Name offset** - Assumed +0x10, but getting garbage
2. **Property pool offsets** in RPGStats (FixedStrings, Floats, Int64s, GUIDs)
3. **Object.ModifierListIndex offset** - Currently reading 0 at +0xAC

## Proposed Solution

Write `find_modifier_attributes.py` - a targeted Ghidra script that:

1. **Searches for known attribute name strings** ("Damage", "DamageType", "WeaponRange", "ValueScale")
2. **Traces XREFs** to find functions that use these strings
3. **Analyzes instruction patterns** to discover:
   - How attribute names are stored (inline vs pointer)
   - The offset within Modifier where Name resides
   - How CNamedElementManager<Modifier> looks up by name
4. **Dumps raw memory** at known Modifier array locations to inspect actual layout

## Implementation Steps

### Phase 1: String Search for Attribute Names

```python
# Search for known weapon attribute names
ATTRIBUTE_NAMES = [
    "Damage",           # Primary weapon property
    "DamageType",       # Fire, Cold, etc.
    "WeaponRange",      # Melee/Ranged distance
    "ValueScale",       # Level scaling factor
    "WeaponProperties", # Property flags
    "Boosts",           # Stat boosts
    "DefaultBoosts",    # Default stat boosts
]

def find_attribute_strings():
    """Find addresses of known attribute name strings."""
    results = {}
    for name in ATTRIBUTE_NAMES:
        addr = find_string_in_memory(name)
        if addr:
            results[name] = addr
            xrefs = get_xrefs_to(addr)
            # Log XREF locations for analysis
    return results
```

### Phase 2: XREF Analysis to Find Modifier Access

```python
def analyze_attribute_xrefs(string_addr, attr_name):
    """
    Find functions that reference this attribute string.
    These are likely GetAttributeInfo or property accessor functions.
    """
    refs = get_references_to(string_addr)
    for ref in refs:
        func = get_function_containing(ref.getFromAddress())
        if func:
            # Analyze function for offset patterns
            analyze_modifier_access_pattern(func, attr_name)
```

### Phase 3: Instruction Pattern Analysis

```python
def analyze_modifier_access_pattern(func, attr_name):
    """
    Look for patterns that reveal Modifier structure layout:

    Pattern 1: Direct comparison (string at known offset)
      ADRP X8, #page
      ADD  X8, X8, #offset      ; Load "Damage" string address
      LDR  X9, [X0, #0x10]      ; Load Modifier.Name  <-- THIS OFFSET!
      CMP  X8, X9               ; Compare strings

    Pattern 2: HashMap lookup
      ADRP X8, #page
      LDR  X8, [X8, #offset]    ; Load NameToHandle hashmap
      ; ... hash function call ...
      LDR  W0, [X8, #result]    ; Load index result
    """
    instructions = list(func.getBody().getAddresses(True))
    offsets_used = []

    for inst in get_instructions(func):
        if inst.getMnemonicString() == "ldr":
            # Extract [reg, #offset] pattern
            offset = extract_immediate_offset(inst)
            if offset:
                offsets_used.append(offset)

    return offsets_used
```

### Phase 4: Raw Memory Dump at Known Locations

```python
def dump_modifier_array_raw():
    """
    We know ModifierLists[8] (Weapon) has 61 Modifier entries.
    Dump raw bytes at those addresses to understand actual layout.
    """
    # From our C code: attrs_buf = 0x50286d390 (runtime address)
    # This is a pointer array - each entry is a Modifier*

    # Dump first 10 Modifier entries as raw hex
    for i in range(10):
        modifier_ptr = read_ptr(attrs_buf + i * 8)
        if modifier_ptr:
            # Dump 64 bytes at this modifier
            raw_bytes = read_memory(modifier_ptr, 64)
            log_hex_dump(f"Modifier[{i}]", modifier_ptr, raw_bytes)

            # Try to identify FixedString at various offsets
            for offset in [0x00, 0x08, 0x0C, 0x10, 0x18, 0x20]:
                try_read_fixedstring(modifier_ptr + offset, f"offset +0x{offset:02x}")
```

### Phase 5: Property Pool Discovery

```python
def find_property_pools():
    """
    After Objects at +0xC0, find the property pools.
    These should be Array<T> structures with known patterns.

    Expected RPGStats layout (estimate):
      +0x00: VMT
      +0x08: ModifierValueLists (CNamedElementManager)
      +0x60: ModifierLists (CNamedElementManager)
      +0xC0: Objects (CNamedElementManager)
      +0x120?: FixedStrings (Array<FixedString>)
      +0x140?: Int64s (Array<int64_t*>)
      +0x160?: GUIDs (Array<Guid>)
      +0x180?: Floats (Array<float>)
    """
    rpgstats = read_global_ptr(0x1089c5730)

    # Scan for Array-like structures after Objects
    for offset in range(0x120, 0x300, 0x10):
        candidate = rpgstats + offset
        # Check if it looks like an Array (buf ptr, cap, size)
        buf = read_ptr(candidate + 0x00)
        cap = read_u32(candidate + 0x08)
        size = read_u32(candidate + 0x0C)

        if is_valid_heap_ptr(buf) and 0 < size < 100000 and size <= cap:
            log(f"Potential Array at +0x{offset:x}: size={size}, cap={cap}")
```

## Acceptance Criteria

- [ ] Script finds at least 3 known attribute name strings in binary
- [ ] Script identifies XREFs to attribute strings
- [ ] Script extracts offset patterns from accessor functions
- [ ] Script dumps raw Modifier memory to reveal actual layout
- [ ] Script identifies potential property pool locations
- [ ] Output includes concrete offset recommendations for:
  - `MODIFIER_OFFSET_NAME` (currently 0x10, likely wrong)
  - Property pool offsets in RPGStats (currently unknown)

## Output Format

```
=== Modifier Attribute Discovery ===

String Search Results:
  "Damage" found at 0x107xxxxxx
    XREF from 0x101xxxxxx (function: FUN_101xxxxxx)
    XREF from 0x102xxxxxx (function: GetAttributeInfo)

Instruction Analysis:
  FUN_101xxxxxx accesses offsets: [0x08, 0x10, 0x18, 0x20]
  GetAttributeInfo accesses offsets: [0x00, 0x08, 0x10]

Raw Modifier Memory Dump:
  Modifier[0] at 0x50xxxxxxxx:
    +0x00: 00000003 (int32: EnumerationIndex=3)
    +0x04: FFFFFFFF (int32: LevelMapIndex=-1)
    +0x08: 00000000 (int32: UnknownZero=0)
    +0x0C: 07000000 (padding?)
    +0x10: xxxxxxxx -> "Damage" (FixedString)

Property Pool Candidates:
  +0x120: Array size=47326 - likely FixedStrings pool
  +0x180: Array size=8521 - likely Floats pool

RECOMMENDATIONS:
  MODIFIER_OFFSET_NAME = 0x10 (confirmed) or 0x18 (if aligned differently)
  RPGSTATS_OFFSET_FIXEDSTRINGS = 0x120
  RPGSTATS_OFFSET_FLOATS = 0x180
```

## Files to Create/Modify

### New Files
- `ghidra/scripts/find_modifier_attributes.py` - Main discovery script

### Files to Update After Discovery
- `src/stats/stats_manager.c` - Update offset constants
- `ghidra/offsets/STATS.md` - Document new findings

## Testing

1. Run script: `./ghidra/scripts/run_analysis.sh find_modifier_attributes.py`
2. Monitor: `tail -f /tmp/ghidra_progress.log`
3. Review output in `/tmp/ghidra_output.log`
4. Update C code with discovered offsets
5. Rebuild and test: `Ext.Stats.Get("WPN_Longsword").Damage`

## Risk Analysis

| Risk | Mitigation |
|------|------------|
| Attribute strings not found | Use partial matching, search for substrings |
| XREF analysis inconclusive | Fall back to raw memory dump analysis |
| ARM64 alignment differs from x86 | Test multiple offset candidates (+0x10, +0x18, +0x20) |
| Script timeout on large binary | Use -noanalysis flag, work with cached analysis |

## Dependencies

- Existing Ghidra project with BG3 binary analyzed
- `run_analysis.sh` wrapper script
- `progress_utils.py` for progress tracking

## Success Metrics

1. **Immediate:** Script produces actionable offset recommendations
2. **Short-term:** `Ext.Stats.Get("WPN_Longsword").Damage` returns "1d8" or similar
3. **Complete:** All stats properties readable via Lua (Issue #3 closed)

## References

- Issue #3: https://github.com/[repo]/issues/3
- Windows BG3SE Stats.h: `/bg3se/BG3Extender/GameDefinitions/Stats/Stats.h`
- Existing offset docs: `ghidra/offsets/STATS.md`
- Related scripts: `find_property_access.py`, `find_modifierlist_offsets.py`
