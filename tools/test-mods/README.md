# BG3SE-macOS Test Mods

This folder contains test mods for validating BG3SE-macOS functionality.

## EntityTest

A simple test mod that validates the Entity Component System works correctly.

### Purpose

This mod was created to test the newly discovered `eoc::` GetComponent addresses:
- `eoc::StatsComponent` → `0x10b2ff516`
- `eoc::BaseHpComponent` → `0x10b460744`
- `eoc::HealthComponent` → `0x10b2f2f47`
- `eoc::ArmorComponent` → `0x10b2fe2c4`

### What It Tests

1. **Entity System Ready**: Checks if `Ext.Entity.IsReady()` returns true
2. **Entity Lookup**: Tests `Ext.Entity.Get(guid)` with known player GUIDs
3. **ls:: Components**: Tests `entity.Transform` (should work)
4. **eoc:: Components**: Tests `entity:GetComponent("Stats")`, `"Health"`, `"BaseHp"`, `"Armor"`

### How to Use

1. **Copy to /tmp for auto-detection**:
   ```bash
   cp -r tools/test-mods/EntityTest /tmp/EntityTest_extracted
   ```

   The mod loader automatically scans `/tmp/` for directories ending in `_extracted` that contain `ScriptExtender/Config.json` with `"Lua"`.

2. **Launch BG3 with the dylib**:
   ```bash
   ./scripts/launch_bg3.sh
   ```

   You should see in the logs:
   ```
   === Scanning for Dev Test Mods ===
     [DEV] EntityTest (from /tmp/EntityTest_extracted/)
   ```

3. **Load a save with party members** (Astarion, ShadowHeart, or Lae'zel)

4. **Watch the logs**:
   ```bash
   tail -f /tmp/bg3se_macos.log | grep EntityTest
   ```

### Expected Output

```
[EntityTest] BootstrapServer loading...
[EntityTest] BootstrapServer loaded - waiting for SessionLoaded event
[EntityTest] SessionLoaded event fired
[EntityTest] Testing entity component access...
[EntityTest] Entity system is ready!
[EntityTest] Testing GUID: c7c13742-bacd-460a-8f65-f864fe41f255
[EntityTest]   Entity found! Handle: 12345678
[EntityTest]   Transform: found
[EntityTest]   Stats: FOUND!
[EntityTest]   Health: FOUND!
[EntityTest]   BaseHp: FOUND!
[EntityTest]   Armor: FOUND!
[EntityTest] Component test complete!
```

### Troubleshooting

- **Entity system not ready**: Make sure you've entered combat at least once (triggers EntityWorld capture)
- **Entity not found**: The GUID may not match your party composition - check logs for actual player GUIDs
- **Component nil**: The GetComponent address may need adjustment for your game version

### Adding New Tests

To test additional components:

1. Find the GetComponent address using Ghidra:
   ```bash
   grep "EntityWorld12GetComponent" /tmp/component_search.txt | grep YourComponent
   ```

2. Add the offset to `src/entity/entity_system.c`

3. Add a test call in `BootstrapServer.lua`
