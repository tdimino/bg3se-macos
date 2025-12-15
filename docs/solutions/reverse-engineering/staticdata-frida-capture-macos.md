# StaticData Frida Capture Workflow (macOS)

## Problem Summary

**Component:** Ext.StaticData API
**Issue:** [#40](https://github.com/tdimino/bg3se-macos/issues/40)
**Date:** December 15, 2025
**Severity:** Medium (API incomplete without workaround)

### Symptom

`Ext.StaticData.GetAll("Feat")` returned empty tables despite TypeContext capture showing 37 feats registered.

### Root Cause

On macOS, `FeatManager` (and other static data managers) are **NOT accessible via global symbols**. Unlike Windows BG3SE which uses the exported `eoc__gGuidResourceManager` symbol, macOS has two distinct structures:

1. **TypeContext Metadata** - Registration info only (count at +0x00)
2. **Real GuidResourceBank** - Actual data (count at +0x7C, array at +0x80)

The real FeatManager is accessed via `Environment+0x130` at runtime, not as a singleton.

### Failed Approaches

| Approach | Result |
|----------|--------|
| Dobby hooks on GetFeats | Broke feat selection UI (PC-relative instruction corruption) |
| TypeContext traversal | Only returns metadata, not actual feat data |
| Symbol resolution (`dlsym`) | `eoc__gGuidResourceManager` not exported on macOS |

---

## Solution: File-Based Frida Capture

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 3: Lua API                                           │
│  Ext.StaticData.LoadFridaCapture()                          │
│  Ext.StaticData.GetAll("Feat") / Get("Feat", guid)          │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  Layer 2: C Manager (staticdata_manager.c)                  │
│  load_captured_featmanager() - parses capture file          │
│  Stores in real_managers[STATICDATA_FEAT]                   │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│  Layer 1: Frida Script                                      │
│  Hooks GetFeats @ 0x01b752b4                                │
│  Captures FeatManager* from x1 register                     │
│  Writes to /tmp/bg3se_featmanager.txt                       │
└─────────────────────────────────────────────────────────────┘
```

### Key Offsets

| Offset | Purpose |
|--------|---------|
| `0x01b752b4` | FeatManager::GetFeats function |
| `+0x7C` | FeatManager count field |
| `+0x80` | FeatManager array pointer |
| `0x128` | Feat struct size (296 bytes) |
| `+0x08` | Feat GUID offset (after VMT) |

### Workflow

1. **Launch BG3 with BG3SE:**
   ```bash
   ./scripts/launch_bg3.sh
   ```

2. **Run Frida capture script:**
   ```bash
   pgrep -f "Baldur's Gate 3"  # Get PID
   frida -p <PID> -l tools/frida/capture_featmanager_live.js
   ```

3. **In-game:** Navigate to feat selection (level-up or respec)

4. **Frida outputs:**
   ```
   [+] GetFeats called with FeatManager: 0x600002820d20
   [+] Count (+0x7C) = 41
   [+] Array (+0x80) = 0x121213600
   [+] Wrote FeatManager info to /tmp/bg3se_featmanager.txt
   ```

5. **In BG3SE console:**
   ```lua
   Ext.StaticData.LoadFridaCapture()  -- Returns true
   local feats = Ext.StaticData.GetAll("Feat")
   print("#feats = " .. #feats)  -- Output: 41
   ```

---

## Implementation Files

| File | Purpose |
|------|---------|
| `tools/frida/capture_featmanager_live.js` | Frida hook script |
| `src/staticdata/staticdata_manager.c` | C manager + file parsing |
| `src/staticdata/staticdata_manager.h` | Manager header |
| `src/lua/lua_staticdata.c` | Lua bindings |

### Frida Script (Key Section)

```javascript
Interceptor.attach(getFeatsAddr, {
    onEnter: function(args) {
        var featMgr = args[1];  // x1 = FeatManager*
        var count = featMgr.add(0x7C).readU32();
        var array = featMgr.add(0x80).readPointer();

        if (count > 0 && count < 1000 && !array.isNull()) {
            var file = new File("/tmp/bg3se_featmanager.txt", "w");
            file.write(featMgr.toString() + "\n");
            file.write(count.toString() + "\n");
            file.write(array.toString() + "\n");
            file.close();
        }
    }
});
```

### C Manager (Key Section)

```c
static bool load_captured_featmanager(void) {
    FILE* f = fopen("/tmp/bg3se_featmanager.txt", "r");
    if (!f) return false;

    // Parse: FeatManager ptr, count, array ptr
    void* feat_mgr = NULL;
    int count = 0;
    void* array = NULL;

    // ... parsing code ...

    // Validate pointers are still valid
    if (!safe_memory_read_i32(feat_mgr + 0x7C, &verify_count))
        return false;

    g_staticdata.real_managers[STATICDATA_FEAT] = feat_mgr;
    return true;
}
```

---

## Results

| API | Status | Notes |
|-----|--------|-------|
| `Ext.StaticData.GetAll("Feat")` | ✅ Working | Returns 41 feats with GUIDs |
| `Ext.StaticData.Get("Feat", guid)` | ✅ Working | Returns single feat by GUID |
| `Ext.StaticData.LoadFridaCapture()` | ✅ Working | Loads captured manager |
| `Ext.StaticData.FridaCaptureAvailable()` | ✅ Working | Checks capture file |

### Sample Output

```lua
#feats = 41
Feat[1]: d215b9ad-9753-4d74-f98f-bf24ce1dd653
Feat[2]: cdcbc538-883b-401c-eda8-73136dfb2017
Feat[3]: f57bd72c-be64-4855-3a9e-7dbb657656e6
```

---

## Limitations

- **Per-session:** Capture must be redone after game restart (pointers change)
- **Feat only:** Currently only FeatManager supported; pattern can extend to Race, Background, etc.
- **Manual trigger:** Requires user to navigate to feat selection in-game

## Future Improvements

1. **Auto-capture:** Hook game initialization to capture managers without user interaction
2. **Expand types:** Apply same pattern to Race, Background, Origin, God, Class managers
3. **Name extraction:** Discover name string offsets in Feat structure

---

## Cross-References

- [Issue #40](https://github.com/tdimino/bg3se-macos/issues/40) - Ext.StaticData implementation
- [ghidra/offsets/STATICDATA_MANAGERS.md](../../../ghidra/offsets/STATICDATA_MANAGERS.md) - Offset documentation
- [agent_docs/acceleration.md](../../../agent_docs/acceleration.md) - Windows BG3SE pattern reference
