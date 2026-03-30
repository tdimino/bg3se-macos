# API Status (v0.36.50)

Full namespace-by-namespace parity status with Windows BG3SE.

- **Osi.*** - Dynamic metatable (40+ functions), **OsirisFunctionHandle encoding** (v0.36.39), crash-resilient dispatch with breadcrumbs
- **Ext.Osiris** - RegisterListener, NewCall/NewQuery/NewEvent (server context guards)
- **Context System** - Ext.IsServer/IsClient/GetContext, two-phase bootstrap (v0.36.4)
- **Ext.Entity** - GUID lookup, **1,999 components registered** (462 layouts: 169 verified + 293 generated), **1,730 sizes** (1,577 Ghidra + 153 Windows-only, 87% coverage), GetByHandle, **Dual EntityWorld Complete** (client + server auto-captured), **Entity Events** (Subscribe/OnCreate/OnDestroy + 8 variants, Unsubscribe — salted pool, deferred queue, per-entity hooks)
- **Ext.Stats** - **100% Windows API parity** (52 functions): Get/GetAll/Create/Sync, CopyFrom, SetRawAttribute, ExecuteFunctors, TreasureTable/TreasureCategory stubs, all StatsObject methods
- **Ext.Events** - 33 events with priority ordering, Once flag, Prevent pattern (13 lifecycle + 17 engine + 2 functor + 1 network events), **runtime mod attribution** (per-handler mod tracking, soft-disable, health stats)
- **Ext.Timer** - **20 functions**: WaitFor, WaitForRealtime, Cancel/Pause/Resume, GameTime/DeltaTime/Ticks, **Persistent timers** (save/load support)
- **Ext.Vars** - PersistentVars, User Variables, Mod Variables
- **Ext.StaticData** - Immutable game data (**All 9 types**: Feat, Race, Background, Origin, God, Class, Progression, ActionResource, FeatDescription via ForceCapture)
- **Ext.Resource** - Non-GUID resources (34 types: Visual, Material, Texture, Dialog, etc.)
- **Ext.Template** - Game object templates (14 functions, 10 properties, type detection via VMT)
- **Ext.Types** - Full reflection API (9 functions): GetAllTypes (~2050), GetTypeInfo, GetObjectType, TypeOf, IsA, Validate, GetComponentLayout, GetAllLayouts, **GenerateIdeHelpers** (VS Code IntelliSense)
- **Ext.Debug** - Memory introspection (ReadPtr, ProbeStruct, HexDump), **mod diagnostics** (ModHealthCount, ModHealthAll, ModDisable)
- **Ext.IMGUI** - **Complete widget system** (40 widget types): NewWindow, AddText, AddButton, AddCheckbox, AddInputText, AddCombo, AddSlider, AddColorEdit, AddProgressBar, AddTree, AddTable, AddTabBar, AddMenu, handle-based objects, event callbacks (OnClick, OnChange, OnClose, OnExpand, OnCollapse)
- **Ext.Mod** - Mod information (5 functions): IsModLoaded, GetLoadOrder, GetMod, GetBaseMod, GetModManager
- **Ext.Level** - **9 functions**: RaycastClosest, RaycastAny, TestBox, TestSphere, GetHeightsAt, GetCurrentLevel, GetPhysicsScene, GetAiGrid, IsReady
- **Ext.Audio** - **13 functions**: PostEvent, Stop, PauseAllSounds, ResumeAllSounds, SetSwitch, SetState, SetRTPC, GetRTPC, ResetRTPC, LoadEvent, UnloadEvent, GetSoundObjectId, IsReady
- **Ext.Net** - Network messaging (8 functions): PostMessageToServer, PostMessageToUser, PostMessageToClient, BroadcastMessage, Version, IsHost, IsReady, PeerVersion, **Request/Reply Callbacks**, **RakNet Backend** (Phase 4I)
- **Ext.RegisterNetListener** - Per-channel network message listener (MCM backbone)
- **Net.CreateChannel** - High-level NetChannel API for multiplayer mod sync (SetHandler, **SetRequestHandler**, SendToServer, **RequestToServer with callbacks**, SendToClient, Broadcast)
- **Ext.Utils** - Compatibility aliases (6 functions): Print, PrintWarning, PrintError, Version, MonotonicTime, GetGameState
- **Ext.Math** - Math utilities: Random
- **Ext.ModEvents** - Per-mod cross-mod event system: Subscribe, Throw, Unsubscribe (MCM compat)
