# Localization System Offsets (macOS ARM64)

## Overview

The localization system manages translated game text through `TranslatedStringRepository`. Text is looked up by `RuntimeStringHandle` which wraps a `FixedString` handle plus version.

## Key Symbols

| Symbol | Address | Description |
|--------|---------|-------------|
| `ls::TranslatedStringRepository::m_ptr` | `0x108aed088` | Static pointer to singleton |
| `ls::TranslatedStringRepository::TryGet` | `0x106534d54` | Lookup function (safe, returns optional) |
| `ls::TranslatedStringRepository::Get` | `0x106535148` | Lookup function (asserts on failure) |
| `ls::TranslatedStringRepository::s_HandleUnknown` | `0x108aed078` | Default unknown handle |
| `ls::TranslatedStringRepository::AddTranslatedString` | `0x106532590` | Add new translation |
| `ls::TranslatedStringRepository::LoadFromBinaryFile` | `0x1065338d8` | Load .loca files |

### Other Related Functions

| Function | Address | Notes |
|----------|---------|-------|
| `GetTranslatedArgumentString` | `0x1065360a8` | For parameterized strings |
| `GetOrCreateTranslatedArgumentString` | `0x106536254` | Create if missing |
| `CleanUpArgumentString` | `0x10653664c` | Cleanup |
| `LoadFromXmlFile` | `0x106533fdc` | XML localization loading |
| `LoadFromContextFolder` | `0x1065342a0` | Folder-based loading |
| `Unload` | `0x10653131c` | Unload translations |
| `GetDontTranslate` | `0x1065359fc` | Skip translation marker |

## TranslatedStringRepository Structure

Based on Windows BG3SE (`BG3Extender/GameDefinitions/TranslatedString.h`) and runtime verification:

```c
struct TranslatedStringRepository {
    int field_0;                                    // +0x00
    TextPool* TranslatedStrings[9];                 // +0x08 (9 language pools)
    TextPool* FallbackPool;                         // +0x50
    TextPool* VersionedFallbackPool;                // +0x58
    Array<void*> field_60;                          // +0x60
    HashMap<FixedString, TranslatedArgumentStringBuffer> ArgumentStrings;
    HashMap<FixedString, RuntimeStringHandle> TextToStringKey;
    SRWSpinLock Lock;
    bool IsLoaded;
};
```

### Runtime-Verified Values (Dec 2025)

From `Ext.Loca.DumpInfo()` after loading a save:

| Field | Offset | Value | Notes |
|-------|--------|-------|-------|
| m_ptr (singleton) | - | `0x14c77bd40` | Valid heap pointer |
| TranslatedStrings[0] | +0x08 | `0x600000949fe0` | Main English pool |
| FallbackPool | +0x50 | `0x600000949d60` | Fallback (mostly empty) |

## TextPool Structure

```c
struct TextPool {
    Array<STDString*> Strings;                      // +0x00 (16 bytes)
    HashMap<RuntimeStringHandle, LSStringView> Texts; // +0x10
};
```

### Array<T> Layout (ARM64)

```c
struct Array<T> {
    T* buf_;           // +0x00: Pointer to elements
    uint32_t cap_;     // +0x08: Capacity
    uint32_t size_;    // +0x0C: Current count
};  // Total: 16 bytes
```

### Runtime-Verified TextPool[0] (Dec 2025)

| Field | Offset | Value | Notes |
|-------|--------|-------|-------|
| Strings.buf_ | +0x00 | `0x14e544400` | Pointer to STDString* array |
| Strings.cap_ | +0x08 | 256 | Capacity |
| Strings.size_ | +0x0C | 206 | **206 translated strings loaded** |
| Texts (HashMap) | +0x10 | ... | HashMap for handle→text lookup |

## RuntimeStringHandle Structure

```c
struct RuntimeStringHandle {
    FixedString Handle;    // +0x00: FixedString index (4 bytes on ARM64)
    uint16_t Version;      // +0x04: Version number
    // 2 bytes padding
};  // Total: 8 bytes
```

Handle format in string form: `"h12345678g1234g4567g8901g123456789012"`

## Implementation Notes

### Current State (v0.32.0+)

- `Ext.Loca` namespace registered ✓
- Repository pointer accessible ✓
- DumpInfo() shows valid pools ✓
- **GetTranslatedString lookup implemented** ✓

### Implementation Details

**Native Function Calls Used:**

1. `ls::FixedString::Create(char*, int)` at `0x64b9ebc`
   - Converts handle string to FixedString index
   - Handles GlobalStringTable lookup/creation

2. `ls::TranslatedStringRepository::TryGet` at `0x6534d54`
   - ARM64 signature with x8 indirect return
   - Returns `optional<StringView>` (>16 bytes, uses x8)

**ARM64 Calling Convention:**
```c
// TryGet uses x8 indirect return for large struct
// x0: this (repository pointer)
// x1: RuntimeStringHandle const* (8 bytes: FixedString + version)
// x2: EIdentity lang1 (0 for default)
// x3: EIdentity lang2 (0 for default)
// x8: pointer to result buffer (TryGetResult)

typedef struct {
    LSStringView value;  // 16 bytes: {data*, size}
    uint8_t has_value;   // 1 byte
    uint8_t _pad[15];    // padding
} TryGetResult;  // 32 bytes total
```

**Flow:**
```
Ext.Loca.GetTranslatedString("h12345678g...", fallback)
    ↓
localization_get(handle, fallback)
    ↓
1. ls::FixedString::Create(handle, len) → fs_index
2. Build RuntimeStringHandle { fs_index, version=0 }
3. Call TryGet via x8 indirect return
    ↓
Return translated text or fallback
```

## Related Files

### Windows BG3SE Reference
- `BG3Extender/GameDefinitions/TranslatedString.h` - Struct definitions
- `BG3Extender/Lua/Libs/Localization.inl` - Lua bindings (~70 lines)
- `BG3Extender/GameDefinitions/Symbols.h:58` - `ls__gTranslatedStringRepository`

### macOS Implementation
- `src/localization/localization.c/h` - Core module
- `src/lua/lua_localization.c/h` - Lua bindings

## Testing Commands

```lua
-- Check if system is ready
Ext.Loca.IsReady()  -- returns true after save loaded

-- Dump system info
Ext.Loca.DumpInfo()

-- Test lookup with a real handle from the game
-- Handles can be found in .loca files or by inspecting game data
local text = Ext.Loca.GetTranslatedString("h12345678g1234g4567g8901g123456789012", "fallback")
Ext.Print("Translation: " .. text)

-- Get a translation from an entity's display name
local entity = Ext.Entity.Get("some_guid")
if entity and entity.DisplayName then
    local nameHandle = entity.DisplayName.NameKey
    local name = Ext.Loca.GetTranslatedString(nameHandle, "(no name)")
    Ext.Print("Entity name: " .. name)
end
```

## Version History

| Date | Change |
|------|--------|
| 2025-12-11 | Initial discovery, module created, structure verified |
| 2025-12-11 | Implemented native lookup via FixedString::Create + TryGet |
