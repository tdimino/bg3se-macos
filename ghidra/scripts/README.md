# Ghidra Analysis Scripts

Scripts for reverse engineering the BG3 macOS ARM64 binary.

## Usage

**Recommended: Use the wrapper script:**

```bash
# Run script on already-analyzed project (fast, read-only)
./ghidra/scripts/run_analysis.sh find_rpgstats.py

# Force re-analysis with optimized settings (slow, only if needed)
./ghidra/scripts/run_analysis.sh find_rpgstats.py -analyze

# Monitor progress
tail -f /tmp/ghidra_progress.log
```

**Manual invocation:**

```bash
JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
  ~/ghidra/support/analyzeHeadless ~/ghidra_projects BG3Analysis \
  -process BG3_arm64_thin \
  -noanalysis \
  -scriptPath /Users/tomdimino/Desktop/Programming/bg3se-macos/ghidra/scripts \
  -postScript <script_name.py>
```

## Script Categories

### Core Utilities

| Script | Purpose |
|--------|---------|
| `run_analysis.sh` | **Wrapper script** - handles JAVA_HOME, logging, -noanalysis default |
| `optimize_analysis.py` | **Pre-script** - disables slow analyzers for faster runs |
| `progress_utils.py` | Progress reporting helper for long-running scripts |

### Stats System

| Script | Purpose |
|--------|---------|
| `find_rpgstats.py` | Find RPGStats singleton and structure offsets |
| `find_property_access.py` | Discover stat property access patterns and FixedStrings pool offset |
| `find_modifierlist_offsets.py` | Find ModifierList structure offsets |
| `find_modifier_attributes.py` | Discover Modifier attribute names and structure layout |
| `find_getfixedstring.py` | Find GetFixedString functions for string resolution |

### Entity System

| Script | Purpose |
|--------|---------|
| `analyze_entity_storage.py` | Analyze EntityWorld and entity storage |
| `find_entity_offsets.py` | Discover Entity system offsets |
| `find_uuid_mapping.py` | Find UuidToHandleMappingComponent for GUID lookup |

### Components

| Script | Purpose |
|--------|---------|
| `find_getrawcomponent_v4.py` | Find GetRawComponent template instances |
| `find_component_strings_fresh.py` | Search for component type strings |
| `decompile_getcomponent.py` | Decompile GetComponent functions |
| `quick_component_search.py` | Fast component XREF search |

### Osiris Functions

| Script | Purpose |
|--------|---------|
| `analyze_osiris_functions.py` | Enumerate and analyze Osiris function registration |
| `find_osiris_offsets.py` | Find Osiris-related memory offsets |

## Archived Scripts

Scripts in `archive/` are kept for reference but no longer actively used:

- **GlobalStringTable exploration** (solved via FixedStrings pool at RPGStats+0x348):
  - `find_global_string_table.py`, `find_arm64_global_string_table.py`
  - `find_globalstringtable.py`, `find_incref_function.py`
  - `analyze_gst_access.py`, `analyze_gst_get.py`, `analyze_lsf_stringtable.py`
- **Entity system exploration** (completed):
  - `find_entityworld_access.py`, `find_eocserver_singleton.py`
  - `find_singleton_wrapper.py`, `analyze_eocserver_startup.py`
- **Other**:
  - `find_c600_offset.py` - Confirmed ARM64 doesn't use direct 0xC600 add
  - `analyze_lsresult_return.py` - LsResult return value analysis

## Key Findings

See `/ghidra/offsets/` for documented offsets:
- `STATS.md` - RPGStats structure, FixedStrings pool at offset 0x348
- `ENTITY_SYSTEM.md` - ECS architecture, EntityWorld capture
- `COMPONENTS.md` - GetComponent addresses
- `STRUCTURES.md` - C structure definitions

## Notes

- **Binary base in Ghidra:** `0x100000000`
- **__DATA section:** `0x108970000 - 0x108af7fff` (1.5MB)
- **Use `-noanalysis` flag** (default in wrapper) to run scripts on already-analyzed binary
- **Wrapper logs:** `/tmp/ghidra_progress.log` (progress), `/tmp/ghidra_output.log` (full)
