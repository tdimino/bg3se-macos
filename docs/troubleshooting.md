# Troubleshooting

Common issues and solutions for BG3SE-macOS.

## Injection Not Working

**Symptoms:** Game launches but mods don't load, no SE output in logs.

**Solutions:**

1. Check `~/Library/Application Support/BG3SE/bg3se.log` for errors
2. Verify the dylib is built:
   ```bash
   file build/lib/libbg3se.dylib
   ```
3. Ensure it's universal (should show both `x86_64` and `arm64`):
   ```bash
   file build/lib/libbg3se.dylib
   # Should show: Mach-O universal binary with 2 architectures
   ```
4. Ensure wrapper uses `open --env` (not just `export`)

## Game Crashes at Launch

**Symptoms:** Game crashes immediately on launch with injection.

**Solutions:**

1. Make sure wrapper script uses:
   ```bash
   open -W --env "DYLD_INSERT_LIBRARIES=/path/to/libbg3se.dylib" "$1"
   ```
2. Verify dylib is universal binary (check with `file` command)
3. Try running without injection: clear Steam launch options
4. Check Console.app for crash reports

## Game Returns to Menu After Loading

**Symptoms:** Game loads a save but immediately returns to the main menu.

**Cause:** Usually means a hook isn't preserving the return value.

**Solutions:**

1. Check that hooked functions return the original function's return value
2. Review `~/Library/Application Support/BG3SE/bg3se.log` for hook call/return messages
3. Look for `COsiris::Load returned: X` messages

## Mod Not Loading

**Symptoms:** Mod is installed but doesn't appear to be running.

**Checklist:**

1. Ensure the mod is enabled in modsettings.lsx (use in-game mod manager or BG3 Mod Manager)
2. Ensure the mod's `.pak` file is in:
   ```
   ~/Documents/Larian Studios/Baldur's Gate 3/Mods/
   ```
3. Check that the mod has `ScriptExtender/Config.json` with `"Lua"` in FeatureFlags:
   ```json
   {
     "FeatureFlags": ["Lua"]
   }
   ```
4. Check that the path structure inside PAK is:
   ```
   Mods/<ModName>/ScriptExtender/Lua/BootstrapServer.lua
   ```
5. Review the log for "Scanning for SE Mods" and "Loading Mod Scripts" sections
6. For debugging, extract with `tools/extract_pak.py` to inspect mod structure

## Architecture Mismatch Error

**Symptoms:** Crash reports mention "incompatible architecture".

**Solutions:**

1. Rebuild with universal binary support:
   ```bash
   ./scripts/build.sh
   ```
2. Verify with:
   ```bash
   file build/lib/libbg3se.dylib
   # Should show: Mach-O universal binary with 2 architectures: [x86_64] [arm64]
   ```

## Console Not Connecting

**Symptoms:** `bg3se-console` can't connect to the game.

**Solutions:**

1. Ensure the game is running with BG3SE injected
2. Check if socket exists:
   ```bash
   ls -la /tmp/bg3se.sock
   ```
3. Try connecting with socat:
   ```bash
   socat - UNIX-CONNECT:/tmp/bg3se.sock
   ```
4. Check log for "Socket console listening" message

## Stats API Returns nil

**Symptoms:** `Ext.Stats.Get("StatName")` returns nil.

**Solutions:**

1. Check if stats system is ready:
   ```lua
   Ext.Print(tostring(Ext.Stats.IsReady()))
   ```
2. Wait for SessionLoaded event:
   ```lua
   Ext.Events.SessionLoaded:Subscribe(function()
       local stat = Ext.Stats.Get("WPN_Longsword")
       -- Now it should work
   end)
   ```
3. Verify the stat name is correct with `Ext.Stats.GetAll()`

## Entity API Returns nil

**Symptoms:** `Ext.Entity.Get(guid)` returns nil for valid GUIDs.

**Solutions:**

1. Check if entity system is ready:
   ```lua
   Ext.Print(tostring(Ext.Entity.IsReady()))
   ```
2. Wait for SessionLoaded event before querying entities
3. Verify GUID format is correct (with or without hyphens)
4. On Intel/Rosetta: Entity system has limited functionality

## Limited Functionality on Intel/Rosetta

**Symptoms:** Some features don't work when running under Rosetta.

**Cause:** The Ghidra-derived memory offsets are specific to the ARM64 binary.

**What works on Intel/Rosetta:**
- Basic Osiris hooks
- Lua runtime
- Mod loading

**What doesn't work:**
- Entity system (wrong offsets)
- Component access
- Stats property access (may crash or return wrong data)

**Solution:** Use Apple Silicon Mac for full functionality.

## Log File Not Found

**Symptoms:** Can't find the log file.

**Location:** `~/Library/Application Support/BG3SE/bg3se.log`

**Quick access:**
```bash
tail -f ~/Library/Application\ Support/BG3SE/bg3se.log
```

If the directory doesn't exist, BG3SE hasn't been run yet. Launch the game with injection.

## Getting Help

If you're still stuck:

1. Check [GitHub Issues](https://github.com/tdimino/bg3se-macos/issues) for similar problems
2. Include relevant log output when reporting issues
3. Mention your macOS version, architecture (Apple Silicon or Intel), and BG3 version
