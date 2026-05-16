---
title: "BG3 macOS Global Singletons"
date: 2026-05-16
status: verified
---

# BG3 macOS Global Singletons

All addresses are virtual addresses (VA) in the ARM64 slice. At runtime, add ASLR slide (`base - 0x100000000`).

## Discovery Method

```bash
nm -a "<BG3 binary>" | c++filt | grep "<symbol>"
```

Symbols are in the local symbol table (type `b` = BSS, `d` = DATA, `s` = small data).

## Singletons

| Symbol (demangled) | Mangled | VA | Segment | Used By |
|--------------------|---------|-----|---------|---------|
| `BaseApp::s_AppInstance` | `__ZN7BaseApp13s_AppInstanceE` | `0x108ac0278` | BSS | `focus_hack.c` |
| `ls::InputManager::m_ptr` | `__ZN2ls12InputManager5m_ptrE` | `0x108af4cf8` | BSS | `OnFocusChange`, `InjectInput` |
| `ls::ThreadManager::m_ptr` | `__ZN2ls13ThreadManager5m_ptrE` | `0x108af4f68` | BSS | `OnFocusChange` prologue |
| `_Global` | `_Global` | `0x108af4f30` | BSS | `OnFocusChange` (engine flag check) |
| `gEngine.0` | `_gEngine.0` | `0x108abbcf8` | BSS | Engine instance |
| `gEngine.1` | `_gEngine.1` | `0x108abbd00` | BSS | Engine instance (alt) |
| `ecl::EocClient::m_ptr` | (stripped) | `0x10898c968` | BSS | Entity system, game state |
| `esv::EocServer::m_ptr` | (stripped) | `0x10898e8b8` | BSS | Server-side entity/state |
| `GlobalSwitches (ptr)` | (stripped) | `0x108b18f30` | BSS | `global_switches.c` |
| `SpellPrototypeManager::m_ptr` | (stripped) | `0x1089bac80` | BSS | Stats system |
| `StatusPrototypeManager::m_ptr` | (stripped) | `0x1089bdb30` | BSS | Stats system |
| `PassivePrototypeManager` | (stripped) | `0x108aeccd8` | BSS | Stats system |
| `InterruptPrototypeManager` | (stripped) | `0x108aecce0` | BSS | Stats system |
| `BoostPrototypeManager` | (stripped) | `0x108991528` | BSS | Stats system |
| `ResourceManager::m_ptr` | (stripped) | `0x108a8f070` | BSS | Resource system |
| `gui::ViewModelProvider::m_GlobalManagers` | `__ZN3gui17ViewModelProvider16m_GlobalManagersE` | `0x1089e04f0` | BSS | Noesis UI system |

## Struct Layouts (Partial)

### BaseApp (at *s_AppInstance)

| Offset | Size | Field | Source |
|--------|------|-------|--------|
| +0x000 | 8 | vtable ptr | Ghidra destructor |
| +0x008 | 8 | vtable ptr (second base) | Ghidra destructor |
| +0x050 | 8 | focus_listener_array (param_1[10]) | `OnFocusChange` decompilation |
| +0x05c | 4 | focus_listener_count | `OnFocusChange` decompilation |
| +0x142 | 1 | **focus_flag** (bool) | `OnFocusChange`: `*(char*)(this + 0x142) = focused` |
| +0x144 | 2 | target_fps | `OnFocusChange` framecap logic |
| +0x146 | 2 | active_fps | `OnFocusChange` framecap logic |
| +0x148 | 8 | (param_1[0x29]) fps alt | `OnFocusChange` |
| +0x0D0 | 8 | param_1[0x1a] — frame interval (µs) | `OnFocusChange`: `1e6 / fps` |
| +0x150 | 8 | param_1[0x2a] — log file handle | destructor: `fclose` check |
| +0x158 | 8 | param_1[0x2b] — allocated buffer | destructor: freed |
| +0x160 | 8 | param_1[0x2c] — allocated buffer | destructor: freed |

### ls::InputManager (at *m_ptr)

| Offset | Size | Field | Source |
|--------|------|-------|--------|
| +0x014 | ~40 | CriticalSection | `InjectInput` locks here |
| +0x0A0 | 8 | device_list_ptr (short[]) | `OnFocusChange` iterates devices |
| +0x0AC | 4 | device_count | `OnFocusChange` loop bound |
| +0x398 | 8 | text_inject_array | `LSMTLView::keyDown_` InjectDeviceEvent |
| +0x3A8 | 8 | input_queue_array (InputRawChange[]) | `InjectInput` appends here |
| +0x3B0 | 4 | input_queue_size | `InjectInput` |
| +0x3B4 | 4 | input_queue_capacity | `InjectInput` |

### Noesis::View (0x140 bytes total)

| Offset | Size | Field | Source |
|--------|------|-------|--------|
| +0x088 | 8 | Keyboard* | `View::GetKeyboard()` at 0x10060fb74 |

## Usage in Code

```c
// Pattern: read global pointer with ASLR slide
uintptr_t base = (uintptr_t)_dyld_get_image_header(bg3_index);
uintptr_t slide = base - 0x100000000;
void *instance = *(void **)(SINGLETON_VA + slide);
```

## Cross-References

- `src/game/focus_hack.c` — uses BaseApp::s_AppInstance
- `src/game/global_switches.c` — uses GlobalSwitches pointer
- `src/injector/main.c` — uses EocServer/EocClient
- `docs/bugs/noesis-input-bypass-re.md` — full OnFocusChange analysis
- `ghidra/offsets/` — per-subsystem offset docs
