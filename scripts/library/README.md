# BG3SE Script Library

Reusable Lua scripts for reverse engineering and debugging.

## Installation

Copy these scripts to your BG3SE data directory:
```bash
cp scripts/library/*.lua ~/Library/Application\ Support/BG3SE/scripts/
```

## Usage

From the BG3SE console:
```lua
dofile(Ext.IO.GetDataPath() .. "/scripts/probe_spell_refmap.lua")
```

## Scripts

| Script | Purpose |
|--------|---------|
| `probe_spell_refmap.lua` | Probe SpellPrototypeManager for spell entries |
| `dump_managers.lua` | Dump all prototype manager states |
| `find_physics_scene.lua` | Discovery script for PhysicsScene (Issue #37) |
| `test_audio_init.lua` | Test Wwise audio system (Issue #38) |

## Adding Scripts

Scripts should be self-contained and print results via `Ext.Print()`.
Use the preloaded `Debug.*` helpers for memory probing.
