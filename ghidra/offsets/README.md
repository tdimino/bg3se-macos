# BG3SE-macOS: Offset Documentation

**Game Version:** Baldur's Gate 3 (macOS ARM64)
**Last Updated:** 2026-02-05

## Overview

This directory contains reverse-engineered offsets and memory layouts for the macOS ARM64 port of BG3.

## Documents

| File | Description |
|------|-------------|
| [OSIRIS.md](OSIRIS.md) | libOsiris.dylib offsets (OsiFunctionMan, Event dispatch) |
| [ENTITY_SYSTEM.md](ENTITY_SYSTEM.md) | ECS architecture, EntityWorld capture, GUID lookup |
| [COMPONENTS.md](COMPONENTS.md) | GetComponent addresses and discovery status |
| [STRUCTURES.md](STRUCTURES.md) | C structure definitions for game components |
| [NETWORKING.md](NETWORKING.md) | Network system: EocServer, GameServer, AbstractPeer, ProtocolList, MessageFactory |
| [STATS.md](STATS.md) | RPGStats system offsets |
| [GAMESTATE.md](GAMESTATE.md) | Game state machine and transitions |
| [PROTOTYPE_MANAGERS.md](PROTOTYPE_MANAGERS.md) | Spell/Status/Passive/etc prototype managers |

## Quick Reference

### Working Offsets

| Symbol | Address | Library |
|--------|---------|---------|
| `OsiFunctionMan` | `0x0009f348` | libOsiris.dylib |
| `COsiris::Event` | `0x000513cc` | libOsiris.dylib |
| `LEGACY_IsInCombat` | `0x10124f92c` | Main binary |
| `TryGetSingleton<UuidMapping>` | `0x1010dc924` | Main binary |
| `GetComponent<Transform>` | `0x10010d5b00` | Main binary |

### Pending Discovery

| Component | String Address | GetComponent | Status |
|-----------|----------------|--------------|--------|
| `eoc::StatsComponent` | `0x107b7ca22` | TBD | Pending |
| `eoc::BaseHpComponent` | `0x107b84c63` | TBD | Pending |
| `eoc::HealthComponent` | `0x107ba9b5c` | TBD | Pending |
| `eoc::ArmorComponent` | `0x107b7c9e7` | TBD | Pending |

## Ghidra Scripts

| Script | Purpose |
|--------|---------|
| `find_entity_offsets.py` | General entity system discovery |
| `find_eoc_components.py` | eoc:: component string analysis |
| `find_nearby_getcomponent.py` | Pattern search near known addresses |

## Architecture Notes

- **Image Base:** `0x100000000`
- **Namespace Prefixes:** `ls::` (core), `eoc::` (game), `esv::` (server), `ecl::` (client)
- **Same ECS as Windows:** Component names and EntityWorld structure match
