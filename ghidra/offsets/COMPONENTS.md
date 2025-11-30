# Component Addresses

## Status Summary

**IMPORTANT:** The GetComponent addresses discovered earlier were **INVALID** - they had 11 hex digits
(e.g., `0x10010d5b00`) instead of the expected 10 digits. These have been disabled in `entity_system.c`
until correct addresses are verified.

Valid macOS ARM64 addresses should be 10 hex digits: `0x1XXXXXXXX` (40-bit virtual address space).

## Known Component String Addresses (Verified)

These string addresses are confirmed correct (10 digits):

| Component | String Address | Notes |
|-----------|----------------|-------|
| `ls::TransformComponent` | `0x107b619cc` | ✅ Verified |
| `ls::LevelComponent` | `0x107b4e44c` | ✅ Verified |
| `ls::PhysicsComponent` | `0x107b685dd` | ✅ Verified |
| `ls::VisualComponent` | `0x107b7fad0` | ✅ Verified |
| `eoc::StatsComponent` | `0x107b7ca22` | ✅ Verified |
| `eoc::BaseHpComponent` | `0x107b84c63` | ✅ Verified |
| `eoc::HealthComponent` | `0x107ba9b5c` | ✅ Verified |
| `eoc::ArmorComponent` | `0x107b7c9e7` | ✅ Verified |
| `eoc::ActionResourcesComponent` | `0x107b4c17d` | ✅ Verified |

## GetComponent Addresses (DISABLED)

These addresses were malformed and have been disabled in `entity_system.c`:

| Component | Old Address | Problem | New Address |
|-----------|-------------|---------|-------------|
| `ls::TransformComponent` | `0x10010d5b00` | 11 digits | **TBD** |
| `ls::LevelComponent` | `0x10010d588c` | 11 digits | **TBD** |
| `ls::PhysicsComponent` | `0x101ba0898` | 10 digits - needs verification | **TBD** |
| `ls::VisualComponent` | `0x102e56350` | 10 digits - needs verification | **TBD** |

## Discovery Strategy

### Current Approach: Index-Based GetComponent

The Windows BG3SE uses `ComponentTypeIndex` (uint16_t) to identify components at runtime,
not direct function pointer addresses. The macOS port should adopt the same approach:

1. **Find EntityWorld::GetRawComponent** - single function that takes (handle, typeIndex, size, isProxy)
2. **Find ComponentRegistry** - within EntityWorld, contains component metadata
3. **Discover type indices at runtime** - iterate ComponentRegistry to map names → indices

### Why Direct GetComponent<T> Addresses Were Wrong

The original approach tried to find `GetComponent<T>` template instantiation addresses.
The 11-digit hex values (e.g., `0x10010d5b00`) suggest:
- A transcription error (extra `0`)
- Or misidentification of code vs data sections

### Alternative Approaches

1. **Runtime Hook Discovery**
   - Hook functions that use components (combat, damage calc)
   - Log function addresses that access component data

2. **Pattern Scanning**
   - Search for ARM64 instruction patterns that match GetComponent behavior
   - Look for ADRP+ADD sequences referencing component strings

3. **Ghidra XRef Analysis**
   - Run Ghidra WITH analysis enabled (slow but finds references)
   - Trace XREFs from component strings to registration/access code

## Related Files

- `entity_system.c` - Contains disabled `OFFSET_GET_*_COMPONENT` defines (all set to 0)
- `find_component_indices.py` - Ghidra script for component discovery
- `quick_component_search.py` - Simplified Ghidra script for rapid iteration

## Next Steps

1. Add `Ext.Entity.DumpComponentRegistry()` Lua function for runtime exploration
2. Run game and dump registry to discover actual type indices
3. Implement index-based component access
4. Update this document with verified findings
