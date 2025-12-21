# BG3SE-macOS: Deep Audit & Issue Acceleration Plan

## Objective
Deep osgrep + Exa MCP audit to find acceleration strategies for ALL remaining issues to reach 100% Windows BG3SE parity.

---

## Current State Summary

**Version:** v0.31.0 | **Claimed Parity:** ~53%

### All Open Feature Issues (15 total)
| Issue | Feature | Priority | Acceleration Level |
|-------|---------|----------|-------------------|
| #6 | NetChannel API | Critical | Low (~30%) |
| #7 | Type System & IDE | Medium | Medium (~50%) |
| #15 | Client Lua State | High | Medium (~50%) |
| #32 | Stats Sync | Medium | Medium (~40%) |
| #33 | Component Layouts | Medium | **High (~80%)** |
| #35 | Ext.UI (Noesis) | Nice | Low (~25%) |
| #36 | Ext.IMGUI | Nice | **High (~70%)** |
| #37 | Ext.Level (Physics) | Nice | Medium (~50%) |
| #38 | Ext.Audio | Nice | Medium (~45%) |
| #39 | Ext.Localization | Nice | **High (~75%)** |
| #40 | Ext.StaticData | Medium | **High (~70%)** |
| #41 | Ext.Resource/Template | Medium | **High (~65%)** |
| #42 | Debugger (VS Code) | Nice | Medium (~60%) |

### Non-Feature Issues
- #8 - Technical debt: stability, testing, documentation
- #24 - Meta: How-to process / Claude usage

---

## DEEP AUDIT FINDINGS (osgrep + Exa MCP)

### Issue #40: Ext.StaticData - **HIGH ACCELERATION (70%)**

**osgrep Discovery - Key Pattern:**
```cpp
// BG3Extender/GameDefinitions/EntitySystem.cpp:1364
resource::GuidResourceBankBase* EntitySystemHelpersBase::GetRawResourceManager(ExtResourceManagerType type)
{
    auto index = staticDataIndices_[(unsigned)type];
    auto defns = GetStaticSymbols().eoc__gGuidResourceManager;
    auto res = (*defns)->Definitions.try_get(index);
    // ...
}
```

**Acceleration Strategy:**
1. **Symbol exists:** `eoc__gGuidResourceManager` is exported - can dlsym directly
2. **ExtResourceManagerType enum** - find in macOS binary via string search
3. **Port StaticData.inl directly** - well-documented template pattern
4. **Lua tests exist:** `BG3Extender/LuaScripts/Tests/StaticDataTests.lua` - copy test patterns

**Reference Files:**
- `BG3Extender/Lua/Libs/StaticData.inl`
- `BG3Extender/GameDefinitions/Resources.h` (ResourceBank, ResourcePackage structs)
- `BG3Extender/LuaScripts/Libs/DevelopmentHelpers.lua:313` (validation examples)

---

### Issue #6: NetChannel API - **LOW ACCELERATION (30%)**

**osgrep Discovery - Key Pattern:**
```cpp
// BG3Extender/Extender/Shared/ExtenderNet.cpp:104
void ExtenderMessage::Serialize(BitstreamSerializer & serializer)
{
    auto& msg = GetMessage();
    uint32_t size = (uint32_t)msg.ByteSizeLong();
    serializer.WriteBytes(&size, sizeof(size));
    msg.SerializeToArray(buf, size);
    // ...
}
```

**Key Files Found:**
- `BG3Extender/GameDefinitions/Net.h` - Message base class, BitstreamSerializer
- `BG3Extender/Extender/Shared/ExtenderNet.h` - ProtoVersion enum, ExtenderMessage
- `BG3Extender/Extender/Client/ClientNetworking.h` - ExtenderProtocol (ProtocolId=100)
- `BG3Extender/LuaScripts/Libs/NetChannel.lua` - Pure Lua wrapper (can port directly!)
- `BG3Extender/LuaScripts/Libs/NetworkManager.lua` - Channel management

**Acceleration Strategy:**
1. **Lua layer is pure Lua** - `NetChannel.lua` and `NetworkManager.lua` can port directly
2. **Protobuf serialization** - Uses `ExtenderProtocol.pb.h` - need to reverse engineer
3. **Hook points:** `OnClientConnectMessage` in Hooks.cpp
4. **Exa research:** Steam NetHook2 for message format inspection

**Complexity:** Network stack analysis required, but Lua wrapper simplifies API layer.

---

### Issue #15: Client Lua State - **MEDIUM ACCELERATION (50%)**

**osgrep Discovery - Key Pattern:**
```cpp
// BG3Extender/Lua/Client/LuaClient.cpp:80
void ClientState::Initialize()
{
    State::Initialize();
    library_.Register(L);
    gExtender->GetClient().GetExtensionState().LuaLoadBuiltinFile("ClientStartup.lua");
    gExtender->GetClient().GetExtensionState().LuaLoadBuiltinFile("SandboxStartup.lua");
    // ...
}

// BG3Extender/Extender/Client/ExtensionStateClient.cpp:62
void ExtensionState::InitializeLuaState()
{
    Lua = std::make_unique<lua::ClientState>(*this, nextGenerationId_++);
    Lua->Initialize();
}
```

**Key Architecture:**
- `ClientState` vs `ServerState` - separate classes, share `State` base
- `ExtensionState` manages lifecycle
- Context detection via `GetCurrentContextType() == ContextType::Client`
- `ClientStartup.lua` and `SandboxStartup.lua` - builtin scripts

**Acceleration Strategy:**
1. **Mirror server pattern** - our server state works, client follows same structure
2. **Hook client-side game state** - `ecl::GameStateThreaded::GameStateWorker::DoWork`
3. **Exa research:** pLua hooking pattern - find client lua_State* via function hooks
4. **Separate API registration** - client-only APIs (Ext.UI, Ext.IMGUI)

---

### Issue #36: Ext.IMGUI - **HIGH ACCELERATION (70%)**

**Exa MCP Discovery:**
- **ImGui has official Metal backend** - `imgui_impl_metal.h` exists
- **macOS example:** `examples/example_sdl_opengl3` shows macOS integration
- **hudhook library** - Rust library for injecting ImGui into games (DirectX/OpenGL/Metal)

**Key Pattern from Exa:**
```cpp
// imgui_impl_metal example
ImGui_ImplMetal_Init(device);
ImGui_ImplMetal_NewFrame(renderPassDescriptor);
ImGui::NewFrame();
// ... render widgets ...
ImGui::Render();
ImGui_ImplMetal_RenderDrawData(ImGui::GetDrawData(), commandBuffer, renderEncoder);
```

**Acceleration Strategy:**
1. **Use official Metal backend** - no custom rendering needed
2. **Hook MTKView or CAMetalLayer** - inject into game's render loop
3. **Port Windows IMGUI Lua bindings** - `BG3Extender/Lua/Client/IMGUI*.h`
4. **Standalone implementation** - no dependency on Client Lua State

---

### Issue #39: Ext.Localization - **HIGH ACCELERATION (75%)**

**Exa MCP Discovery - Simple Pattern:**
```lua
-- Common game localization pattern
locale.gettext("String Key")
locale.pgettext("context", "String Key")
```

**Windows BG3SE Reference:**
- `BG3Extender/Lua/Libs/Localization.inl` - minimal API surface

**Acceleration Strategy:**
1. **Find localization string table** in macOS binary
2. **Simple hash lookup** - FixedString → localized text
3. **Small API surface** - just Get, GetAll functions
4. **Low effort, high impact** for translation mods

---

### Issue #32: Stats Sync (Prototype Managers) - **MEDIUM ACCELERATION (40%)**

**osgrep Discovery - Pattern in STATS.md:**
```cpp
// Prototype manager pattern
SpellPrototypeManager::SyncStat()
StatusPrototypeManager::SyncStat()
PassivePrototypeManager::SyncStat()
```

**ghidra/offsets/STATS.md already documents:**
- `GetPassivePrototype` at `0x102655c14`
- `GetPassivePrototypes` at `0x102014284`

**Acceleration Strategy:**
1. **Frida for singleton discovery** - hook Get*Prototype functions, trace to manager
2. **Use existing Ghidra findings** - prototype addresses known
3. **ARM64 struct analysis** - `Ext.Debug.ProbeStruct()` for layout

---

### Issue #37: Ext.Level (Physics/Raycasting) - **MEDIUM ACCELERATION (50%)**

**Exa MCP Discovery - Common Patterns:**
```cpp
// PhysX-style API (common in games)
sweepSingle(scene, geometry, pose, unitDir, distance, outputFlags, hit, filterData);
raycast(scene, origin, direction, maxDistance, hit);
```

**Windows BG3SE Reference:**
- `BG3Extender/Lua/Server/LevelLib*.inl` - Lua bindings

**Acceleration Strategy:**
1. **Find physics engine** - likely Havok or custom
2. **Hook raycast/sweep functions** - export names may exist
3. **Port LevelLib.inl** - Lua bindings are straightforward

---

### Issue #38: Ext.Audio - **MEDIUM ACCELERATION (45%)**

**Exa MCP Discovery:**
- BG3 uses **Wwise** audio engine (common in AAA games)
- Wwise has documented API: `AK::SoundEngine::PostEvent()`, `SetPosition()`

**Acceleration Strategy:**
1. **Find Wwise SDK symbols** - often exported
2. **Hook `PostEvent`** - main audio trigger function
3. **Port audio Lua bindings** - `BG3Extender/Lua/Client/ClientAudio*.h`

---

### Issue #42: Debugger (VS Code) - **MEDIUM ACCELERATION (60%)**

**osgrep Discovery:**
```csharp
// LuaDebugger/DAPProtocol.cs - DAP implementation exists!
public class DAPInitializeRequest : IDAPMessagePayload
{
    public String clientID { get; set; }
    public String clientName { get; set; }
    // ...
}
```

**Exa MCP Discovery:**
- **Debug Adapter Protocol (DAP)** is standardized
- **local-lua-debugger-vscode** - pure Lua implementation
- **LuaPanda** - Tencent's debugger with architecture patterns

**Acceleration Strategy:**
1. **Port existing DAP code** - `LuaDebugger/*.cs` shows protocol
2. **Use Lua's debug.sethook()** - standard breakpoint mechanism
3. **Reference pure Lua debuggers** - simpler than C implementation

---

### Issue #33: Component Layouts - **HIGH ACCELERATION (80%)**

**Already have tools:**
- `tools/extract_typeids.py` - extracts all 1,999 TypeId addresses
- `tools/generate_component_stubs.py` - generates C stubs from Windows headers

**Automation workflow:**
1. Run `extract_typeids.py` → get TypeId address
2. Run `generate_component_stubs.py` → get field names
3. Verify offsets with `Ext.Debug.ProbeStruct()`
4. Add to `component_offsets.h`

---

### Issue #35: Ext.UI (Noesis) - **LOW ACCELERATION (25%)**

**Exa MCP Discovery:**
- Noesis UI uses WPF/XAML-style data binding
- Complex ViewModel/INotifyPropertyChanged pattern
- Requires deep integration with game's UI system

**Complexity:** High - requires understanding game's Noesis integration, not just Noesis itself.

---

### Issue #41: Ext.Resource/Template - **HIGH ACCELERATION (65%)**

**osgrep Discovery:**
```lua
-- BG3Extender/LuaScripts/Libs/DevelopmentHelpers.lua:313
Ext.Template.GetAllLocalCacheTemplates()
```

**Key Files:**
- `BG3Extender/Lua/Libs/Resource.inl`
- `BG3Extender/Lua/Libs/Template.inl`
- `BG3Extender/GameDefinitions/Resources.h` - ResourceBank, ResourcePackage

**Acceleration Strategy:**
1. **Similar to StaticData** - uses same resource bank pattern
2. **Template cache** - find via symbol search
3. **Port Resource.inl + Template.inl** together

---

## PRIORITIZED IMPLEMENTATION ORDER (by Acceleration Level)

### Tier 1: HIGH ACCELERATION (70-80%) - Do First
| Issue | Feature | Acceleration | Key Technique |
|-------|---------|--------------|---------------|
| #33 | Component Layouts | 80% | Existing tools: extract_typeids.py + generate_component_stubs.py |
| #39 | Ext.Localization | 75% | Simple string table lookup, minimal API |
| #36 | Ext.IMGUI | 70% | Official Metal backend exists, hudhook patterns |
| #40 | Ext.StaticData | 70% | Symbol `eoc__gGuidResourceManager` exported |
| #41 | Ext.Resource/Template | 65% | Same pattern as StaticData |

### Tier 2: MEDIUM ACCELERATION (40-60%) - Second Priority
| Issue | Feature | Acceleration | Key Technique |
|-------|---------|--------------|---------------|
| #42 | Debugger (VS Code) | 60% | Port DAP protocol, use debug.sethook() |
| #15 | Client Lua State | 50% | Mirror server pattern, hook game state |
| #7 | Type System | 50% | Port Ext.Types introspection |
| #37 | Ext.Level (Physics) | 50% | Find physics engine, port LevelLib.inl |
| #38 | Ext.Audio | 45% | Wwise SDK has documented API |
| #32 | Stats Sync | 40% | Frida for singleton discovery, Ghidra findings |

### Tier 3: LOW ACCELERATION (25-30%) - Complex/Long-term
| Issue | Feature | Acceleration | Key Challenge |
|-------|---------|--------------|---------------|
| #6 | NetChannel | 30% | Network stack analysis, protobuf RE |
| #35 | Ext.UI (Noesis) | 25% | Deep game UI integration required |

---

## ACTION ITEMS

### Immediate (This Session):
1. ✅ Copy this plan to `/Users/tomdimino/Desktop/Programming/bg3se-macos/plans/`
2. Update all GitHub issues with acceleration findings
3. Update ROADMAP.md with new priority matrix
4. Update agent_docs/acceleration.md with full findings

### Issue Update Template:
For each issue, add a new section:
```markdown
## Acceleration Research (Dec 2025)

**Acceleration Level:** XX%
**Key Technique:** [summary]

**osgrep Findings:**
- [key files discovered]

**Exa MCP Findings:**
- [external patterns/libraries]

**Implementation Steps:**
1. [step 1]
2. [step 2]
...
```

---

## SUMMARY

**Total Open Feature Issues:** 15
**High Acceleration (70%+):** 5 issues
**Medium Acceleration (40-60%):** 6 issues
**Low Acceleration (<40%):** 2 issues

**Recommended Focus:**
1. **Ext.StaticData (#40)** - High impact, high acceleration, clear pattern
2. **Ext.Localization (#39)** - Quick win, high acceleration, small API
3. **Component Layouts (#33)** - Tools ready, incremental progress
4. **Ext.IMGUI (#36)** - Official Metal backend, standalone

This plan supersedes the previous gap analysis and provides actionable acceleration strategies for each remaining issue.
