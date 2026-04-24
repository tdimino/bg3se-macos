# ghidra/offsets/ Index

Reverse-engineered offset documentation from Ghidra analysis of the BG3 macOS binary.

## Osiris & Scripting
| File | Description |
|------|-------------|
| [OSIRIS.md](OSIRIS.md) | Osiris engine offsets |
| [OSIRIS_FUNCTIONS.md](OSIRIS_FUNCTIONS.md) | Function discovery, dispatch |

## Stats & Data
| File | Description |
|------|-------------|
| [STATS.md](STATS.md) | RPGStats key offsets |
| [STATS_SYSTEM.md](STATS_SYSTEM.md) | Stats system architecture |
| [STATICDATA.md](STATICDATA.md) | Static data system |
| [STATICDATA_MANAGERS.md](STATICDATA_MANAGERS.md) | Manager singletons |
| [GLOBALSTRINGTABLE.md](GLOBALSTRINGTABLE.md) | String table offsets |

## Entity & Components
| File | Description |
|------|-------------|
| [ENTITY_SYSTEM.md](ENTITY_SYSTEM.md) | EntityWorld, component access |
| [COMPONENTS.md](COMPONENTS.md) | Component type reference |
| [COMPONENT_DATABASE.md](COMPONENT_DATABASE.md) | Component size database |
| [COMPONENT_SIZES.md](COMPONENT_SIZES.md) | Size extraction results |
| [SIGNAL_INTEGRATION.md](SIGNAL_INTEGRATION.md) | Entity event signal hooks |
| `components/` | Per-namespace component docs |

## Game Systems
| File | Description |
|------|-------------|
| [STRUCTURES.md](STRUCTURES.md) | Core data structures |
| [PROTOTYPE_MANAGERS.md](PROTOTYPE_MANAGERS.md) | Spell/Status/Passive prototypes |
| [TEMPLATE.md](TEMPLATE.md) | Game object templates |
| [RESOURCE.md](RESOURCE.md) | Resource manager |
| [FUNCTORS.md](FUNCTORS.md) | Stat functor system + damage hook signatures + RTTI refs |
| [PHYSICS_LEVEL.md](PHYSICS_LEVEL.md) | PhysicsScene VMT, Sweep/Raycast, PhysicsHitAll struct |
| [STDSTRING_ABI.md](STDSTRING_ABI.md) | ls::STDString 16-byte layout, SSO threshold, safe construction |
| [GAMESTATE.md](GAMESTATE.md) | Game state machine |
| [LOCALIZATION.md](LOCALIZATION.md) | Localization system |
| [NOESIS_UI_FRAMEWORK.md](NOESIS_UI_FRAMEWORK.md) | UI framework analysis |
| [NETWORKING.md](NETWORKING.md) | Network layer offsets |

## Methodology
| File | Description |
|------|-------------|
| [EXTRACTION_METHODOLOGY.md](EXTRACTION_METHODOLOGY.md) | How offsets are extracted |
| [ARM64_SAFE_HOOKING.md](ARM64_SAFE_HOOKING.md) | ARM64 hooking patterns |
| [MULTI_ISSUE.md](MULTI_ISSUE.md) | Multi-issue tracking |
| [README.md](README.md) | Overview |

## Data
| File | Description |
|------|-------------|
| [windows_reference_sizes.json](windows_reference_sizes.json) | Windows component sizes for comparison |
| `staging/` | Work-in-progress extraction results |
