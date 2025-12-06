# Ghidra Analysis

For the 1GB+ BG3 binary, **always use the wrapper script**:

```bash
# Run script on already-analyzed project (read-only, fast)
./ghidra/scripts/run_analysis.sh find_modifierlist_offsets.py

# Force re-analysis with optimized settings (slow, only if needed)
./ghidra/scripts/run_analysis.sh find_modifierlist_offsets.py -analyze

# Monitor progress:
tail -f /tmp/ghidra_progress.log
```

## Wrapper Script Behavior
- **Default mode**: Uses `-noanalysis` for fast read-only script execution
- **With `-analyze`**: Applies `optimize_analysis.py` prescript for re-analysis
- Logs to `/tmp/ghidra_progress.log` (progress) and `/tmp/ghidra_output.log` (full output)

## Available Scripts
| Script | Purpose |
|--------|---------|
| `find_modifierlist_offsets.py` | ModifierList structure offsets |
| `find_property_access.py` | Stats property access offsets |
| `find_rpgstats.py` | gRPGStats global pointer |
| `find_getfixedstring.py` | FixedStrings pool offset |
| `find_uuid_mapping.py` | UuidToHandleMappingComponent |
| `find_entity_offsets.py` | Entity system offsets |
| `quick_component_search.py` | XREFs to component strings |

## Offset Documentation
Detailed findings in `ghidra/offsets/`:
- `STATS.md` - RPGStats system, FixedStrings pool (0x348)
- `ENTITY_SYSTEM.md` - ECS architecture, EntityWorld capture
- `COMPONENTS.md` - GetComponent addresses
- `STRUCTURES.md` - C structure definitions

## Key Discovered Offsets

### Stats System (from STATS.md)
- `RPGSTATS_OFFSET_FIXEDSTRINGS = 0x348` - FixedStrings pool (verified via Ghidra)
- Property resolution: `stat.Name` → IndexedProperties → FixedStrings[pool_index]

### Entity System
- `LEGACY_IsInCombat` hook at `0x10124f92c` captures EntityWorld&
- `TryGetSingleton<UuidToHandleMappingComponent>` at `0x1010dc924`

**Note:** The optimizer prescript disables slow analyzers that would cause analysis to take hours.
