---
title: "Noesis GUI Input Bypass - Ghidra RE Findings"
date: 2026-05-16
status: in-progress
---

# Noesis GUI Input Bypass — Ghidra RE Findings

## Problem Statement

BG3's Continue button on the main menu cannot be activated programmatically. Every public macOS input API fails:
- System Events key code (requires frontmost app)
- CGEventPost / CGEventPostToPid (doesn't reach Noesis)
- Direct `[LSMTLView keyDown:]` with valid InputManager (input queued but not consumed)
- Direct `[LSMTLView mouseDown:]` (same: queued but ignored by Noesis)
- AXUIElement accessibility API (BG3 not accessible)

The `-continueGame` CLI flag highlights the Continue button but does NOT auto-activate it.

## Architecture (from Ghidra RE)

### Input Pipeline
```
[LSMTLView keyDown:] (0x100bd798c)
    ↓ reads inputManager ivar at offset 104
    ↓ translates macOS keyCode via s_KeyboardKeys[keyCode] → Noesis::Key
    ↓ builds InputRawChange: {uint32 noesisKey, float[2]{1.0,?}, uint8 pressed=1}
    ↓
ls::InputManager::InjectInput (0x1064c4f14)
    ↓ locks CriticalSection at +0x14
    ↓ appends to array at +0x3a8 (size at +0x3b0, cap at +0x3b4)
    ↓
[Game main loop processes queue]
    ↓
Noesis::Keyboard::KeyDown (0x10054fec4)
    ↓ updates key state at keyboard + key*4 + 0xc
    ↓ gets focused element from keyboard + 0x310
    ↓ raises PreviewKeyDownEvent then KeyDownEvent on focused UIElement
    ↓
Noesis::CommandManager::ProcessInput (0x10048bcc4)
    ↓ FindInputBinding / FindCommandBinding on the target element
    ↓ checks CanExecute, then calls Execute
```

### Key Translation Table
- Global: `cocoa::CocoaInputTranslator::s_KeyboardKeys` (uint16_t[0xb4])
- macOS keyCode 0x24 (Return) → Noesis::Key value (likely 6)
- macOS keyCode 0x31 (Space) → Noesis::Key value (likely 18)
- macOS keyCode 0x35 (Escape) → Noesis::Key value

### Noesis View Architecture
- `Noesis::GUI::CreateView(FrameworkElement*)` at 0x100535de4 — allocates 0x140 bytes
- `Noesis::View::GetKeyboard()` at 0x10060fb74 — returns `*(this + 0x88)`
- `Noesis::View::GetMouse()` — returns from another offset
- `Noesis::View::Update(double)` at 0x10061063c — called every frame
- View constructor: `Noesis::View::View(FrameworkElement*)` at 0x10060f008

### Button Activation Rules (Noesis Framework)
- **Space key** → activates any FOCUSED button (Button.OnKeyDown handler)
- **Return key** → activates only buttons with `IsDefault=true`
- `-continueGame` likely sets visual highlight WITHOUT keyboard focus
- Result: neither Return nor Space activates Continue button

## Critical Finding: Focus Gate

`BaseApp::OnFocusChange(bool focused)` at 0x105d148f8:

1. Stores focus state at `BaseApp + 0x142`
2. When focus is **LOST** (param_2 == 0):
   - Iterates device list at `InputManager + 0xa0` (count at `+0xac`)
   - Calls `func_0x1064c71f4(inputMgr, deviceId, -1)` for each device
   - This likely **resets/releases all keys** — clearing the input queue
3. When focus is gained, notifies registered listeners at `BaseApp[10]` array

**Implication:** Even if input is injected while BG3 isn't frontmost, the `OnFocusChange(false)` call may have already cleared/disabled the input processing pipeline.

## Global Singletons Discovered

| Global | Purpose |
|--------|---------|
| `ls::InputManager::m_ptr` | InputManager singleton |
| `BaseApp::s_AppInstance` | Main app instance, focus flag at +0x142 |
| `ecl::EocClient::m_ptr` (0x10898c968) | Client singleton |
| `esv::EocServer::m_ptr` (0x10898e8b8) | Server singleton |
| `ls::ThreadManager::m_ptr` | Thread manager |
| `_Global` / `_gEngine_0` | Engine instance |

## DCMainMenu / Continue Game Flow

### Key Functions
| Function | Address | Role |
|----------|---------|------|
| `gui::DCMainMenu::~DCMainMenu` | 0x1023f6410 | Destructor (vtable anchor) |
| `gui::DCMainMenu::OnContinueGameCommand` | NOT IN FUNC LIST | Continue button handler |
| `ecl::GameStateMachine::SetTargetState` | 0x102fcd1a4 | Client state machine transition |
| `esv::GameStateMachine::SetTargetState` | 0x104a26258 | Server state machine transition |
| `ecl::GameStateMenu::Exit` | 0x102fcddc0 | Removes MainMenuComponent entities |
| `esv::GameStateLoadSession::Enter` | 0x104a256fc | Server-side save load entry |
| `Noesis::Keyboard::KeyDown(Key)` | 0x10054fec4 | Direct keyboard event injection |
| `Noesis::CommandManager::ProcessInput` | 0x10048bcc4 | Finds and executes command bindings |

### Launcher Flow (bypassed with NoLauncher=1)
- WebKit launcher JS calls `window.webkit.messageHandlers.call.postMessage('continueGame')`
- ObjC handler at 0x100bb507c dispatches to `[self continueGame]`
- `LariLauncherViewController::continueGame` (0x100bb53d8): sets `_s_GameIsLaunching=1`, stops modal

### ECS Game State Components
- `eoc::gamestate::MainMenuComponent` — present while in main menu
- `eoc::gamestate::SavegameLoadComponent` — triggers save loading
- `ecl::GameStateLoadSessionComponent` — client load session state
- `esv::GameStateLoadSessionComponent` — server load session state

## Viable Bypass Approaches (Ranked)

### 1. Force Focus Flag (SIMPLEST)
Write `1` to `BaseApp::s_AppInstance + 0x142` to fake "focused" state, preventing the input pipeline from being disabled. Then our existing `[LSMTLView keyDown:]` injection should work.

**Requires:** Finding BaseApp::s_AppInstance address (referenced in decompiled code but not exported).

### 2. Direct Noesis::Keyboard::KeyDown Call
Hook `Noesis::View::Update` (called every frame), capture `this` pointer, get Keyboard from `this+0x88`, call `KeyDown(Key::Space)` and/or `KeyDown(Key::Return)`.

**Requires:** Hooking View::Update, one-shot injection after menu is ready.

### 3. Hook Game State Machine
After detecting MainMenu state via our existing ECS access, directly call `ecl::GameStateMachine::SetTargetState` with a LoadSession GameState.

**Requires:** Constructing a valid GameState object, finding the state machine within EocClient.

### 4. Direct Command Execute
Find the DCMainMenu instance at runtime, locate its ContinueGameCommand delegate, and call Execute() on it.

**Requires:** Finding DCMainMenu instance (no obvious global), complex Noesis reflection.

### 5. ECS Component Injection
Create an `eoc::gamestate::SavegameLoadComponent` entity to trigger the load pipeline.

**Requires:** Correct component data format, save game identification.

## Confirmed Global Addresses (nm -a)

| Symbol | Address | Type | Notes |
|--------|---------|------|-------|
| `BaseApp::s_AppInstance` | `0x108ac0278` | BSS | Pointer to singleton |
| `ls::InputManager::m_ptr` | `0x108af4cf8` | BSS | Pointer to InputManager |
| `ls::ThreadManager::m_ptr` | `0x108af4f68` | BSS | Pointer to ThreadManager |
| `_Global` | `0x108af4f30` | BSS | Engine global |
| `gEngine.0` | `0x108abbcf8` | BSS | Engine instance |
| `gEngine.1` | `0x108abbd00` | BSS | Engine instance (alt) |

Found via: `nm -a <BG3 binary> | c++filt | grep <symbol>`

## Implementation: focus_hack.c (Approach 1)

**Status:** Implemented, pending live test.

**Module:** `src/game/focus_hack.c` / `src/game/focus_hack.h`

**Mechanism:**
1. Read `BaseApp::s_AppInstance` (0x108ac0278 + ASLR slide) → get BaseApp*
2. Write `1` to `BaseApp* + 0x142` (focus flag byte)
3. Deferred polling (500ms intervals, max 30 attempts) for early-boot timing

**API:**
- `focus_hack_init()` — resolve BaseApp singleton
- `focus_hack_force_focused()` — write 1 to focus flag
- `focus_hack_is_focused()` — read current focus state
- `focus_hack_deferred_force_focus()` — poll until BaseApp appears, then force

**Integration point:** Called alongside `focusless_input_start_splash_autodismiss()` when `BG3SE_AUTO_DISMISS_SPLASH=1`.

**Theory:** With focus forced to 1, `BaseApp::OnFocusChange(false)` never fires its device-clearing loop, so input injected via `[LSMTLView keyDown:]` should survive through to `Noesis::Keyboard::KeyDown` and activate the focused/default button.

## Next Steps

1. ~~Find `BaseApp::s_AppInstance` address~~ ✓ (0x108ac0278)
2. ~~Implement Approach 1: force focus flag~~ ✓ (src/game/focus_hack.c)
3. Wire focus_hack into main.c auto-dismiss path
4. Live test: verify input reaches Noesis with focus forced
5. If Approach 1 fails: implement Approach 2 (hook View::Update)
6. Determine correct Noesis::Key values for Return (6?) and Space (18?)
