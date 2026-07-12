# Noesis UI / Ext.UI Reverse Engineering (macOS)

Goal: implement `Ext.UI` so MCM's pause-menu **"Mod Configuration Menu" button** opens MCM.

## Address convention
- Ghidra base `0x100000000`, runtime base `0x100088000`, **slide `0x88000`**.
- `runtime = ghidra + 0x88000`. Bridge (`http://[::1]:8080`) returns/takes **ghidra** addresses.
- Bridge is IPv6-only (`[::1]`) — IPv4:8080 is held by user's `sarajevo-gateway`.

## Live-traced (previous session, confirmed at runtime)
- ResourceManager object = `0x9637ac500` (via `ResourceManager::m_ptr` file 0x8a8f070 → ptr addr 0x108b17070)
- **UIManager = *(RM + 0x28) = `0x963c1d380`** (vtable `0x1088bcd00`; RM+0x28 & RM+0x30 both point at UIManager/UIManagerSwap)

## 1. UIManager storage
- `gui::VMDOEntry::ProvideUIManager(NoesisUIManager*)` @ ghidra `0x1024f174c` (rt `0x102577f74`)
  - Body: `*(NoesisUIManager**)(this + 0x98) = param_1;` — VMDOEntry holds UIManager at **+0x98**.
- `ui::NoesisUIManager::~NoesisUIManager()` @ ghidra `0x102544134` (rt `0x1025cc134`)
  - Member hints from dtor: semaphore at `+0x198`, counter `+0x19c`/`+0x1a4`, a list/ptr walked from `+0x158`.
  - **TODO**: find the root Canvas / UICanvas member offset within NoesisUIManager (Windows = Sub70.Canvas ~+0x70). Not yet extracted.

## 2. Noesis API symbols present (UNSTRIPPED — huge win)
All confirmed via `/searchFunctions`. Ghidra addresses:

| Symbol | Ghidra addr | Notes |
|--------|-------------|-------|
| `FindName` | `0x1004d8f00` (+ many overloads 0x1004eb2d8, 0x10055306c, 0x100609100…) | Noesis FrameworkElement::FindName — resolve element by x:Name |
| `GetDataContext` | `0x1004d7730` | read DataContext |
| `DataContextChanged` | `0x1004da920` | |
| `GetDataContextChangedEvent` | `0x1004e00a8` | |
| `CreateDataContextClass` | `0x1024d5654` | **BG3 helper** — game's own DataContext class builder |
| `GetCustomDataContext` | `0x1028c8348` | **BG3 helper** — likely how game attaches custom DCs |
| `IsGlobalDataContext` | `0x1024d477c` | |
| `Noesis::BaseCommand` (ctor/vtable) | `0x10044b638` | subclass this for LuaDelegateCommand (Execute/CanExecute) |
| `Create<Noesis::BaseCommand>` | `0x10044b758` | |
| `Noesis::TypeClass` machinery | `Meta<CommandData,TypeClass*>` `0x100444ad8`, `Meta<DependencyData,TypeClass*>` `0x1002ef178` | for RegisterType |
| `Noesis::Canvas` ctor | `0x10046e8b0`, `0x10046e8e0` | `Create<Noesis::Canvas>` `0x10046ec98` |
| `Create<ui::Canvas>` | `0x10380580c` | |

Not found by name: `VisualTreeHelper` (Noesis may inline; use FindName + GetLogicalChildren instead).

## Ext.UI implementation plan (macOS, Windows-parity)
MCM's `Client/Helpers/Noesis.lua` does:
1. `Ext.UI.RegisterType("GameMenuMCMButtonDC", {CustomEvent={Type="Command"}})` — build a Noesis TypeClass with one Command property (via `Meta<CommandData,TypeClass*>` + BaseCommand).
2. `ctx = Ext.UI.Instantiate("GameMenuMCMButtonDC")` — instantiate that DC object.
3. `ctx.CustomEvent:SetHandler(fn)` — store Lua ref; the BaseCommand::Execute subclass queues fn → Lua-thread pump → `IMGUIAPI:ToggleMCMWindow`.
4. `MCMButton.DataContext = ctx` — get the injected button element (via GetRoot→FindName "MCMButton") and set its DataContext (`GetCustomDataContext`/DependencyObject::SetValue).

### Remaining RE (next session)
- [ ] NoesisUIManager → root Canvas/FrameworkElement offset (decompile UIManager methods that touch `+0x70`-ish; check `Create<Noesis::Canvas>` xrefs into UIManager).
- [ ] `FindName` exact signature (which overload is FrameworkElement::FindName(Symbol)) + how to build a Noesis::Symbol from a string ("MCMButton").
- [ ] `Noesis::BaseCommand` vtable layout (Execute/CanExecute slots) to subclass.
- [ ] `DependencyObject::SetValue` / the DataContext DependencyProperty to set `element.DataContext`.
- [ ] `RegisterType`/`TypeClass` build sequence (`Meta<CommandData,...>`).

### GhidraMCP bridge cheat-sheet
```
B="http://[::1]:8080"
curl -s "$B/searchFunctions?query=NAME&limit=N"
curl -s "$B/decompile_function?address=0xGHIDRA_ADDR"
curl -s "$B/xrefs_to?address=0xGHIDRA_ADDR"
```
`methods` endpoint is server-capped (~32 rows) — use `searchFunctions` instead.
