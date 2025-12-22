# Implementation Plan: Fix Ext.StaticData.GetAll() for Issue #40

## Problem

`Ext.StaticData.GetAll("Feat")` returns only 1 item instead of 37 feats. The current implementation's `probe_for_real_manager()` looks for wrong offsets.

## Root Cause (from STATICDATA.md Dec 20, 2025)

The TypeContext metadata captured from ImmutableDataHeadmaster **DOES have count=37 at +0x00**. The bug is in `probe_for_real_manager()` which tries to find a structure with:
- count at +0x7C (Session FeatManager pattern)
- within the TypeContext metadata

This finds an unrelated structure at metadata+0xC0 with count=1 instead.

**Key insight:** TypeContext metadata IS a GuidResourceBank-like structure with HashMap. We need to parse this HashMap correctly rather than probing for a different structure.

## TypeContext HashMap Offsets (from Ghidra GetObjectByKey @ 0x100c1cc64)

```
HashMap<TKey, TValue>:
+0x00: HashKeys.data_ (8 bytes)    - hash bucket array
+0x08: HashKeys.size_ (4 bytes)    - bucket count
+0x0C: padding (4 bytes)
+0x10: NextIds.data_ (8 bytes)     - chain links
+0x18: NextIds.size_ (4 bytes)     - chain array size
+0x1C: NextIds.capacity_ (4 bytes)
+0x20: Keys.data_ (8 bytes)        - keys array pointer
+0x28: Keys.size_ (4 bytes)        ← ENTRY COUNT
+0x2C: Keys.capacity_ (4 bytes)
+0x30: Values.data_ (8 bytes)      ← VALUES ARRAY POINTER
+0x38: Values.size_ (4 bytes)
Total: 0x40 bytes (64 bytes)
```

## GuidResourceBank<T> Structure

```
GuidResourceBankBase:
+0x00: VMT
+0x08: LSXRegionName (FixedString)
+0x10: LSXResourceNodeName (FixedString)
+0x18: ResourceGuidsByMod (HashMap) - 0x40 bytes
= 0x58 total

GuidResourceBank<T> (extends GuidResourceBankBase):
+0x58: Resources (HashMap<Guid, T>) - 0x40 bytes
+0x98: Path (STDString)
...
```

## Implementation Steps

### Step 1: Find eoc__gGuidResourceManager symbol

```bash
nm -gU "/Applications/Baldur's Gate 3.app/Contents/MacOS/Baldur's Gate 3" | c++filt | grep gGuidResourceManager
```

If not exported, use Ghidra to find it via xrefs to `GetRawResourceManager` or similar.

### Step 2: Determine StaticDataTypeIndex for Feat

Either:
- Find the `ExtResourceManagerType` enum values in macOS binary
- Or probe at runtime to find which index corresponds to "Feat"

### Step 3: Update staticdata_manager.c

Replace the TypeContext-based approach with GuidResourceManager lookup:

```c
// New offsets for GuidResourceBank
#define GUIDRESOURCEBANK_RESOURCES_OFFSET    0x58
#define HASHMAP_KEYS_DATA_OFFSET            0x20
#define HASHMAP_KEYS_SIZE_OFFSET            0x28
#define HASHMAP_VALUES_DATA_OFFSET          0x30

// New function to get GuidResourceBank for a type
void* get_guid_resource_bank(StaticDataType type) {
    // 1. Get GuidResourceManager singleton via dlsym or offset
    void* manager = get_guid_resource_manager();
    if (!manager) return NULL;

    // 2. Get Definitions HashMap at manager+0x00
    // 3. Look up bank by StaticDataTypeIndex
    int32_t type_index = g_static_data_type_indices[type];
    return hashmap_try_get(manager->Definitions, type_index);
}

// Updated GetAll implementation
int staticdata_get_all(StaticDataType type, void** out_entries, int max_entries) {
    void* bank = get_guid_resource_bank(type);
    if (!bank) return 0;

    // Resources HashMap is at bank + 0x58
    void* resources = bank + GUIDRESOURCEBANK_RESOURCES_OFFSET;

    // Get count from Keys.size_ at +0x28
    int32_t count = *(int32_t*)(resources + HASHMAP_KEYS_SIZE_OFFSET);

    // Get values array from Values.data_ at +0x30
    void** values = *(void***)(resources + HASHMAP_VALUES_DATA_OFFSET);

    // Copy entries (up to max)
    int n = (count < max_entries) ? count : max_entries;
    for (int i = 0; i < n; i++) {
        out_entries[i] = values[i];
    }
    return n;
}
```

### Step 4: Update Get() to use GuidResourceBank

```c
void* staticdata_get(StaticDataType type, const char* guid_or_name) {
    void* bank = get_guid_resource_bank(type);
    if (!bank) return NULL;

    // Parse GUID
    Guid guid;
    if (!parse_guid(guid_or_name, &guid)) {
        // Try name-based lookup if GUID parse fails
        return NULL;
    }

    // Call virtual GetObjectByKey
    void* (*get_by_key)(void*, const Guid*) = bank->VMT[5];
    return get_by_key(bank, &guid);
}
```

## Files to Modify

1. **`src/staticdata/staticdata_manager.c`**
   - Replace TypeContext-based capture with GuidResourceManager lookup
   - Update GetAll/Get to use HashMap iteration
   - Add new offsets for GuidResourceBank and HashMap

2. **`src/staticdata/staticdata_manager.h`**
   - Update structure definitions if needed

3. **`ghidra/offsets/STATICDATA.md`**
   - Document GuidResourceManager singleton address
   - Document StaticDataTypeIndex enum values
   - Document GuidResourceBank layout verification

## Verification

```lua
local feats = Ext.StaticData.GetAll("Feat")
print("Feat count: " .. #feats)  -- Should print 37

for i, feat in ipairs(feats) do
    print(feat.Name)  -- Should print feat names
end
```

## Alternative Approach (if eoc__gGuidResourceManager not found)

Hook `GuidResourceBank::Load` or `GuidResourceBank::PostInit` to capture bank pointers at load time. This is more complex but doesn't require finding the manager singleton.

## Risk Assessment

- **Low**: HashMap structure is well-understood from Windows BG3SE
- **Medium**: Need to find/verify GuidResourceManager singleton address
- **Low**: Iteration pattern is simple once structure is correct
