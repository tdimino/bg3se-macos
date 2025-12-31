# Officially Supported Mods

This page tracks mods that have been explicitly tested with BG3SE-macOS. Many Script Extender mods will work out of the box—this list documents those we've confirmed.

## Compatibility Status Legend

| Status | Meaning |
|--------|---------|
| ✅ Working | Fully functional, all features tested |
| ⚠️ Partial | Core features work, some limitations |
| 🔧 Workaround | Works with manual configuration |
| ❌ Not Working | Known incompatibility (see notes) |
| 🧪 Untested | Not yet verified |

## Confirmed Working Mods

### Companion & NPC Mods

| Mod | Author | Version Tested | BG3SE Version | Status | Notes |
|-----|--------|----------------|---------------|--------|-------|
| [More Reactive Companions](https://www.nexusmods.com/baldursgate3/mods/5447) | LightningLarryL | Latest | v0.36.17 | ✅ Working | Party banter, companion reactions to player choices |

### Gameplay Mods

*None tested yet—help us expand this list!*

### UI Mods

*None tested yet—help us expand this list!*

### Quality of Life Mods

*None tested yet—help us expand this list!*

## Known Incompatibilities

| Mod | Issue | Reason | Workaround |
|-----|-------|--------|------------|
| *None documented yet* | — | — | — |

## Reporting Mod Compatibility

### If a Mod Works

1. **Open an issue** with the `mod-compatibility` label, or
2. **Submit a PR** adding the mod to this list

Include:
- Mod name and Nexus link
- Version tested
- BG3SE-macOS version used
- Any configuration needed
- Brief description of features tested

### If a Mod Doesn't Work

1. **Check the logs** at `~/Library/Application Support/BG3SE/logs/latest.log`
2. **Open an issue** with:
   - Mod name and version
   - Error messages from logs
   - Steps to reproduce
   - Expected vs actual behavior

## Testing a Mod

To test if an SE mod works:

1. Install the mod normally (PAK file in Mods folder)
2. Enable it in the game's mod manager
3. Launch the game via Steam (with BG3SE configured)
4. Check the log for loading messages:
   ```
   [Mod] Loaded mod: YourModName
   [Mod] Executing BootstrapServer.lua
   ```
5. Test the mod's features in-game
6. Check for errors in the log

### Common Issues

| Symptom | Likely Cause | Solution |
|---------|--------------|----------|
| Mod doesn't load | PAK not detected | Check file path, ensure `.pak` extension |
| Lua errors on load | Missing API | Check if mod uses unimplemented Ext.* functions |
| Mod loads but no effect | Server vs Client context | Some mods only run in specific contexts |
| Crash on load | Incompatible API usage | Report as issue with log attached |

## API Coverage

BG3SE-macOS currently implements ~82% of the Windows BG3SE API. Mods using these namespaces should work:

| Namespace | Status | Coverage |
|-----------|--------|----------|
| Ext.Osiris | ✅ Full | Event listeners, custom functions |
| Ext.Entity | ✅ Full | GUID lookup, 1,999 components |
| Ext.Stats | ✅ Full | Property read/write, Sync |
| Ext.Events | ✅ Full | 32 events with priority |
| Ext.Timer | ✅ Full | All timer functions |
| Ext.Vars | ✅ Full | PersistentVars, User/Mod vars |
| Ext.IO | ✅ Full | File operations |
| Ext.Json | ✅ Full | Parse/Stringify |
| Ext.Math | ✅ Full | Vector/matrix/quaternion |
| Ext.Types | ✅ Full | Reflection API |
| Ext.StaticData | ✅ Full | All 9 data types |
| Ext.Resource | ✅ Full | 34 resource types |
| Ext.Template | ✅ Full | Template access |
| Ext.IMGUI | 🔧 Beta | Debug overlay (input WIP) |
| Ext.ClientUI | ❌ None | Not implemented |
| Ext.ServerUI | ❌ None | Not implemented |

See [ROADMAP.md](../ROADMAP.md) for implementation details.

## Contributing

We welcome mod compatibility reports! The more mods we test, the better we can ensure broad compatibility.

**Ways to help:**
- Test your favorite SE mods and report results
- Document workarounds for partially-working mods
- Report bugs with detailed logs
- Submit PRs to update this list
