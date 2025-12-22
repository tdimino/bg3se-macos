# Acceleration Strategies for BG3SE-macOS

Research and tools for reaching Windows BG3SE parity faster.

## Philosophy: Port-the-Pattern

**Treat Windows BG3SE as spec + reference implementation.** The biggest multiplier is recognizing that Windows BG3SE achieves breadth via a small number of reusable "primitive engines":

| Primitive | Windows Implementation | macOS Approach |
|-----------|------------------------|----------------|
| **ECS Mapping** | `EntitySystemHelpersBase` + `GenericPropertyMap` | TypeId-based traversal (no monolithic dispatcher) |
| **Guid Resource Banks** | `GuidResourceBankHelper<T>` template | TypeContext traversal + hook-based capture |
| **Networking** | `Ext.Net.*` + `NetChannel.lua` | Minimal C bridge + port Lua wrappers |

**Key insight:** Port the *API contract* and *data model* (platform-independent), replace only the *mechanism* (ARM64/macOS-specific).

**Intentional divergence:** On macOS ARM64, templates are often inlined with no stable dispatcher function. Use traversal-based approaches rather than searching for a single "GetRawComponent" anchor.

---

## Component Parity (Issue #33)

### Statistics

| Metric | Count |
|--------|-------|
| Total TypeIds in macOS binary | 1,999 |
| `eoc::` namespace (mod-relevant) | 701 |
| `esv::` namespace (server) | 596 |
| `ecl::` namespace (client) | 429 |
| `ls::` namespace (base) | 233 |
| Currently implemented | 158 (~8%) |

### Automation Tools

**1. TypeId Extraction (`tools/extract_typeids.py`)**

Extracts all component TypeId addresses from the macOS binary:

```bash
# Generate C header with all TypeIds
python3 tools/extract_typeids.py > src/entity/generated_typeids.h

# Search for specific component
python3 tools/extract_typeids.py 2>&1 | grep HealthComponent
```

Output format:
```c
#define TYPEID_EOC_HEALTHCOMPONENT 0x10890a360ULL
```

**2. Component Stub Generator (`tools/generate_component_stubs.py`)**

Parses Windows BG3SE headers to extract field names and types:

```bash
# List all eoc:: components with field counts
python3 tools/generate_component_stubs.py --namespace eoc --list

# Generate stubs for high-priority components
python3 tools/generate_component_stubs.py --high-priority > stubs.c

# Generate all stubs for a namespace
python3 tools/generate_component_stubs.py --namespace eoc > eoc_stubs.c
```

### Why Full Automation Isn't Possible

Windows BG3SE uses `make_property_map.py` to auto-generate Lua bindings because they have:
- **Compile-time access** to C++ struct definitions
- **PropertyMap macros** resolved by the compiler
- **Automatic offset calculation** by the C++ compiler

We're working with:
- **Stripped binary** - no debug symbols
- **ARM64 architecture** - different alignment than x64
- **Runtime verification needed** - must probe memory or analyze disassembly

### Recommended Workflow

For each component:

1. **Get TypeId address:**
   ```bash
   nm -gU "/path/to/BG3" | c++filt | grep "TypeId.*ComponentName.*ComponentTypeIdContext"
   ```

2. **Get field names from Windows headers:**
   ```bash
   python3 tools/generate_component_stubs.py --namespace eoc --list | grep ComponentName
   ```

3. **Verify ARM64 offsets** (choose one):
   - **Ghidra:** Analyze accessor functions
   - **Runtime probing:** `Ext.Debug.ProbeStruct()` on live entity
   - **Pattern matching:** Similar components often have similar layouts

4. **Add to codebase:**
   - `src/entity/component_typeid.c` - TypeId entry
   - `src/entity/component_offsets.h` - Property definitions + registry

5. **Test:**
   ```lua
   local e = Ext.Entity.Get("GUID")
   _D(e.YourComponent)
   ```

## Static Data & Resources (Issues #40, #41)

### Windows Pattern (from `StaticData.inl`)

Windows BG3SE uses template-based helpers:

```cpp
template <class T>
class GuidResourceBankHelper : public GuidResourceBankHelperBase {
    bool Push(lua_State* L, Guid resourceGuid) override {
        auto resource = bank_->Resources.try_get(resourceGuid);
        if (resource) {
            MakeObjectRef(L, resource, LifetimeHandle{});
            return true;
        }
        return false;
    }
    Array<Guid> GetAll() { return bank_->Resources.keys(); }
};
```

### Implementation Strategy

1. **Find resource manager singletons** via Ghidra
2. **Discover `ExtResourceManagerType` enum values** in macOS binary
3. **Port the helper pattern** using C equivalents
4. **Register Lua bindings** for `Ext.StaticData.Get()`, `GetAll()`

## Stats Sync (Issue #32)

### Windows Pattern

```cpp
RPGStats::SyncWithPrototypeManager(Object* object) {
    switch (object->ModifierListIndex) {
        case SpellData:
            SpellPrototypeManager::SyncStat();
            break;
        case StatusData:
            StatusPrototypeManager::SyncStat();
            break;
        // ...
    }
}
```

### Required Discoveries

| Component | What to Find |
|-----------|--------------|
| SpellPrototypeManager | Singleton address, `SyncStat` function |
| StatusPrototypeManager | Singleton address, `SyncStat` function |
| PassivePrototypeManager | Singleton address, `SyncStat` function |
| InterruptPrototypeManager | Singleton address, `SyncStat` function |

### Ghidra Research

```bash
# Search for prototype manager references
./ghidra/scripts/run_analysis.sh find_prototype_managers.py
```

## Client Lua State (Issue #15)

### Windows Architecture

- `ServerExtensionState` - Server-side Lua state
- `ClientExtensionState` - Client-side Lua state
- Context switching based on thread/caller

### Implementation Approach

1. **Find client-side hooks** - Different from server Osiris hooks
2. **Create separate Lua state** - With client-specific APIs
3. **Implement context detection** - Determine which state to use
4. **Port client-only APIs** - `Ext.UI`, `Ext.IMGUI`, etc.

## NetChannel API (Issue #6)

### Complexity

This is the most complex remaining feature:
- Requires network stack analysis
- Platform-specific socket handling differences
- Message serialization/deserialization
- No easy automation path

### Research Needed

1. Find `NetChannel` class in macOS binary
2. Analyze message format
3. Hook send/receive functions
4. Implement Lua bindings

## Exa MCP Research Findings (Dec 2025)

Comprehensive research using Exa MCP server for automation strategies.

### Debugger Support (Issue #42)

**Key Finding:** The Debug Adapter Protocol (DAP) is the standard for VS Code integration.

**Discovered Implementations:**
| Project | Description | Relevance |
|---------|-------------|-----------|
| `tomblind/local-lua-debugger-vscode` | Pure Lua debugger for VS Code | Best reference - no C dependencies |
| `LuaPanda` | Tencent's Lua debugger | Architecture patterns for breakpoints |
| `lua-debug` | actboy168's debugger | Hook-based debugging |
| `one-small-step-for-vimkind` | nvim-lua/lsp integration | Debug hooks example |
| `Emmy Debugger` | IntelliJ Lua plugin | Production-quality implementation |

**Acceleration Strategy:**
1. **Use DAP reference implementations** - Don't reinvent the protocol
2. **Start with local-lua-debugger** - Pure Lua, easy to port
3. **Hook `debug.sethook()`** - Standard Lua debug hooks
4. Port existing DAP JSON message handling

**Estimated Effort Reduction:** ~60% (vs building from scratch)

### NetChannel API (Issue #6)

**Key Finding:** Steam network interception has established patterns.

**Discovered Techniques:**
| Technique | Source | Applicability |
|-----------|--------|---------------|
| Steam NetHook2 | SteamRE project | Message format inspection |
| Unity Netcode | Unity docs | Serialization patterns |
| Source engine netcode | Valve RE | Packet structure analysis |
| Frida for network hooks | Various | Runtime interception |

**Acceleration Strategy:**
1. **Use Frida for initial exploration** - Hook send/receive functions
2. **Analyze message format first** - Before implementing Lua API
3. **Study Windows BG3SE `NetChannel` class** - Port serialization logic
4. **Focus on common message types** - Chat, sync, custom

**Estimated Effort Reduction:** ~30% (still very complex)

### Stats Sync / Prototype Managers (Issue #32)

**Key Finding:** Frida dynamic instrumentation can discover singletons at runtime.

**Discovered Techniques:**
```javascript
// Frida pattern for singleton discovery
Interceptor.attach(Module.findExportByName(null, "SomeManagerFunction"), {
    onEnter: function(args) {
        console.log("Manager ptr: " + this.context.x0);
    }
});
```

**Acceleration Strategy:**
1. **Hook known prototype functions** - `GetSpellPrototype`, `GetStatusPrototype`
2. **Trace back to singleton** - Follow this pointer to manager
3. **Dump `Init` function** - Decompile to understand property parsing
4. **ARM64 struct analysis** - Use `Ext.Debug.ProbeStruct()` for layout

**Estimated Effort Reduction:** ~40%

### Client Lua State (Issue #15)

**Key Finding:** Game modding projects use hook-based state injection.

**Discovered Patterns:**
```c
// From pLua - inject into existing Lua state
// 1. Find lua_State* via function hooking
hookso arg $PID xxx.so lua_settop 1  // Gets first arg (lua_State*)

// 2. Inject custom code
hookso call $PID libplua.so lrealstart i=$LUA_STATE
```

**Acceleration Strategy:**
1. **Hook client-side Lua functions** - Find client lua_State*
2. **Mirror server state pattern** - Reuse existing infrastructure
3. **Separate API registration** - Client-only vs server-only APIs
4. **Use thread-local storage** - For context detection

**Recommended Implementation Order:**
1. Find client Lua state pointer via hooks
2. Create `ClientExtensionState` mirroring server
3. Register client-specific APIs (Ext.UI, Ext.IMGUI)
4. Implement context switching

**Estimated Effort Reduction:** ~50%

### Static Data / Resources (Issue #40)

**Key Finding:** Windows BG3SE `GuidResourceBankHelper` is well-documented.

**Acceleration Strategy:**
1. **Find `ExtResourceManagerType` enum** - Search binary for resource type strings
2. **Locate resource bank singletons** - Pattern scan for VMT addresses
3. **Port `StaticData.inl` directly** - C equivalent of template helpers
4. **Test with common resources** - Backgrounds, Feats, Origins first

**Estimated Effort Reduction:** ~70% (clearest Windows pattern)

## ARM64 Reverse Engineering Patterns

### Common Offset Patterns in Assembly

```asm
; Load from struct offset
LDR x8, [x19, #0x348]    ; x8 = struct->field_at_0x348

; Store to struct offset
STR x0, [x20, #0x14C]    ; struct->field_at_0x14C = x0

; Pointer arithmetic (array access)
ADD x0, x8, x9, LSL #3   ; x0 = base + (index * 8)

; VMT call
LDR x8, [x0]             ; x8 = object->vtable
LDR x9, [x8, #0x10]      ; x9 = vtable[2] (method at offset 0x10)
BLR x9                   ; call method
```

### Ghidra Python for Offset Discovery

```python
# Find all functions that access a specific offset
for func in currentProgram.getFunctionManager().getFunctions(True):
    for instr in func.getBody().getAddresses(True):
        inst = getInstructionAt(instr)
        if inst and "LDR" in str(inst) and "#0x348" in str(inst):
            print(f"Found at {func.getName()}: {inst}")
```

## osgrep Research Queries

Useful queries for Windows BG3SE exploration:

```bash
cd /Users/tomdimino/Desktop/Programming/bg3se

# Component system
osgrep "how are component properties registered"
osgrep "entity system initialization TypeId"
osgrep "component binding to Lua"

# Prototype managers
osgrep "prototype manager sync"
osgrep "SpellPrototypeManager singleton"

# Resource system
osgrep "GuidResourceBank initialization"
osgrep "ExtResourceManagerType enum"

# Network
osgrep "NetChannel message serialization"
osgrep "multiplayer synchronization"

# Client state
osgrep "ClientExtensionState initialization"
osgrep "client vs server Lua context"

# Debugger
osgrep "debug adapter protocol DAP"
osgrep "Lua breakpoint implementation"
```

## Issue Acceleration Matrix (Dec 2025 Deep Audit)

| Issue | Feature | Acceleration | Key Technique |
|-------|---------|--------------|---------------|
| #33 Components | Component Layouts | **80%** | ✅ 158 components (43 with properties, 115 tag). Verified working Dec 2025 |
| #39 Localization | Ext.Localization | **75%** | Simple string table lookup, minimal API surface |
| #36 IMGUI | Ext.IMGUI | **70%** | Official ImGui Metal backend exists |
| #40 StaticData | Ext.StaticData | **70%** | ✅ CLOSED - Hook-based capture working (Dec 2025) |
| #41 Resource | Ext.Resource/Template | **65%** | Same pattern as StaticData |
| #42 Debugger | VS Code Debugger | **60%** | DAP protocol has reference implementations |
| #15 Client State | Client Lua State | **50%** | Mirror server pattern, hook game state |
| #37 Level | Ext.Level (Physics) | **50%** | Find physics engine, port LevelLib.inl |
| #38 Audio | Ext.Audio | **45%** | Wwise SDK has documented API |
| #32 Stats Sync | Prototype Managers | **40%** | ✅ CLOSED - All 5 managers working (Dec 2025) |
| #6 NetChannel | NetChannel API | **30%** | Network stack analysis needed, but Lua wrappers portable |
| #35 Ext.UI | Noesis UI | **25%** | Deep game UI integration required |

## Prioritized Implementation Order

### Tier 1: High Acceleration (70-80%) - Do First
1. ~~**#33 Components**~~ - ✅ 158 components verified working
2. **#39 Localization** - Quick win, small API (~2 hours)
3. **#36 IMGUI** - Official Metal backend, standalone implementation
4. ~~**#40 StaticData**~~ - ✅ CLOSED (Issue #40 fixed Dec 2025)

### Tier 2: Medium Acceleration (40-60%) - Second Priority
5. **#42 Debugger** - DAP reference implementations available
6. **#15 Client State** - Mirror existing server state pattern
7. ~~**#32 Stats Sync**~~ - ✅ CLOSED (all 5 prototype managers working)

### Tier 3: Lower Acceleration (25-30%) - Complex
8. **#6 NetChannel** - Complex, but Lua wrappers (`NetChannel.lua`, `NetworkManager.lua`) portable
9. **#35 Ext.UI** - Deep Noesis integration required

## osgrep Key Findings (Dec 2025)

### StaticData (#40) - Key Pattern
```cpp
// BG3Extender/GameDefinitions/EntitySystem.cpp:1364
resource::GuidResourceBankBase* EntitySystemHelpersBase::GetRawResourceManager(ExtResourceManagerType type)
{
    auto index = staticDataIndices_[(unsigned)type];
    auto defns = GetStaticSymbols().eoc__gGuidResourceManager;  // <- EXPORTED!
    auto res = (*defns)->Definitions.try_get(index);
}
```

### Client State (#15) - Key Pattern
```cpp
// BG3Extender/Lua/Client/LuaClient.cpp:80
void ClientState::Initialize()
{
    State::Initialize();
    library_.Register(L);
    gExtender->GetClient().GetExtensionState().LuaLoadBuiltinFile("ClientStartup.lua");
}
```

### NetChannel (#6) - Lua Wrappers Available
- `BG3Extender/LuaScripts/Libs/NetChannel.lua` - Pure Lua, can port directly
- `BG3Extender/LuaScripts/Libs/NetworkManager.lua` - Channel management

### IMGUI (#36) - Official Metal Backend
```cpp
// From imgui_impl_metal example
ImGui_ImplMetal_Init(device);
ImGui_ImplMetal_NewFrame(renderPassDescriptor);
ImGui::NewFrame();
ImGui::Render();
ImGui_ImplMetal_RenderDrawData(ImGui::GetDrawData(), commandBuffer, renderEncoder);
```

## Reference Files by Issue

| Issue | Key Reference Files |
|-------|---------------------|
| #40 StaticData | `BG3Extender/Lua/Libs/StaticData.inl`, `GameDefinitions/Resources.h` |
| #39 Localization | `BG3Extender/Lua/Libs/Localization.inl` (~100 lines) |
| #36 IMGUI | `BG3Extender/Lua/Client/IMGUI/Objects.h`, `IMGUIManager.h` |
| #15 Client State | `BG3Extender/Lua/Client/LuaClient.cpp`, `ExtensionStateClient.cpp` |
| #6 NetChannel | `BG3Extender/LuaScripts/Libs/NetChannel.lua`, `NetworkManager.lua` |
| #32 Stats Sync | `BG3Extender/GameDefinitions/Stats/Stats.cpp` - `SyncWithPrototypeManager()` |
| #42 Debugger | `LuaDebugger/DAPProtocol.cs` - DAP implementation |

## Recommended Next Steps

1. **#39 Localization** - Quick win (~2 hours), high acceleration
2. **#36 IMGUI** - Include ImGui + Metal backend, hook render loop
3. **#41 Ext.Resource/Template** - Same pattern as #40 StaticData
4. **#15 Client State** - Mirror server pattern, unlock ecl:: components
5. **Document NetChannel message format** - Long-term research task

### Recently Completed
- ✅ **#40 StaticData** - Hook-based capture working (Dec 2025)
- ✅ **#32 Stats Sync** - All 5 prototype managers working (Dec 2025)
- ✅ **#33 Components** - 158 components verified (Dec 2025)

---

## TypeId Discovery Acceleration (Dec 2025)

Research into accelerating component coverage from 52 to 1,950+ TypeIds using algorithmic analysis of Windows BG3SE.

### Key Discovery: `make_property_map.py`

Windows BG3SE uses a **772-line Python script** (`BG3Extender/make_property_map.py`) to auto-generate all component bindings from C++ headers:

```
Source Code Flow:
50+ header files → make_property_map.py → PropertyMaps.inl + ComponentTypes.inl
```

**Critical insight:** TypeIds are assigned via monotonically incrementing counter (`next_struct_id`) during sequential header parsing. Parsing the same sources in the same order **always produces identical IDs**.

### Tag Components: Zero-Verification Batch

**BREAKTHROUGH:** 115 components defined with `DEFINE_TAG_COMPONENT` require **NO offset verification** - they have zero fields.

```cpp
// Tag component = boolean flag, no fields
DEFINE_TAG_COMPONENT(eoc::combat, IsInCombat, IsInCombat)
DEFINE_TAG_COMPONENT(eoc::death, Dying, Dying)
DEFINE_TAG_COMPONENT(eoc::inventory, IsContainer, IsContainer)
// ... 115 total
```

**Impact:** 115 components can be added TODAY with zero RE work (52 → 167 components, ~8% coverage jump).

### Current Coverage Statistics

| Metric | Count |
|--------|-------|
| Target TypeIds | 1,950+ |
| Currently extracted (macOS) | 701 |
| Currently implemented | 158 |
| Tag components (zero fields) | 115 |
| Regular components (need offsets) | ~485+ |

### Five Strategic Approaches

#### Strategy 1: Header Parsing Algorithm (80% acceleration)

Parse all `DEFINE_COMPONENT` and `DEFINE_TAG_COMPONENT` macros from Windows headers, cross-reference with macOS TypeId addresses via `nm`.

**Execution:**
```bash
# 1. Extract all component definitions from Windows headers
grep -r "DEFINE_TAG_COMPONENT\|DEFINE_COMPONENT" ~/bg3se/BG3Extender/GameDefinitions/Components/

# 2. Cross-reference with macOS binary
nm -gU "BG3" | c++filt | grep "TypeId.*ComponentName"

# 3. Batch-add tag components (zero offset verification needed)
```

**Status:** ✅ COMPLETE - 115 tag components already added (158 total)

#### Strategy 2: Prerequisite Issues (#44, #15)

Complete ARM64 hooking infrastructure and client state to unlock runtime struct dumping:

| Issue | Unlock |
|-------|--------|
| #44 ARM64 Hooking | Runtime component memory dumps |
| #15 Client State | Access to `ecl::` namespace (429 additional TypeIds) |

**Impact:** Enables Frida-based verification for ALL regular components.

#### Strategy 3: Frida Runtime Dump Harness

Hook `GetComponent<T>` variants to dump component memory during gameplay:

```javascript
// Frida script for component memory capture
Interceptor.attach(Module.findExportByName(null, "GetComponent"), {
    onLeave: function(retval) {
        if (retval.isNull()) return;
        console.log("Component ptr: " + retval);
        console.log(hexdump(retval, { length: 256 }));
    }
});
```

**Workflow:**
1. Trigger gameplay that uses target component
2. Capture memory dump
3. Correlate with Windows header field names
4. Verify ARM64 alignment adjustments

#### Strategy 4: LLM-Augmented RE Pipeline

Use Claude + GhidraMCP for accelerated struct layout deduction:

```
Input: Windows header struct + Ghidra decompilation of accessor
Output: ARM64-corrected field offsets

Example prompt:
"Given this Windows struct and this ARM64 decompilation of its accessor,
deduce the ARM64 field offsets accounting for alignment differences."
```

**Token economics:**
- ~500 tokens per component analysis
- ~250k tokens for 500 components
- ROI: Eliminates manual Ghidra analysis time

#### Strategy 5: Fork `make_property_map.py`

Maximum-effort port of Windows automation to emit macOS format:

```python
# Modifications needed:
# 1. Change output format from C++ to C
# 2. Add ARM64 offset estimation (stricter alignment)
# 3. Mark fields requiring verification
# 4. Generate component_offsets.h entries
```

**Output:** Bulk generation of ~485 regular component stubs with estimated offsets.

### Recommended Execution Order

| Phase | Action | Coverage |
|-------|--------|----------|
| 1 | ~~Batch-add 115 tag components~~ | ✅ DONE (158 total) |
| 2 | Implement Frida dump harness | Enables verification |
| 3 | Add high-priority combat/inventory components | 167 → 200 (~10%) |
| 4 | LLM-assisted analysis for remaining | 200 → 400 (~20%) |
| 5 | Fork make_property_map.py for bulk | 400+ (~20%+) |

### Component Source Files (Windows BG3SE)

Key header files in `BG3Extender/GameDefinitions/Components/`:

| File | Component Types |
|------|-----------------|
| `CharacterCreation.h` | Character creation UI components |
| `Combat.h` | Combat state, initiative, threat |
| `Inventory.h` | Containers, items, stacks |
| `Progression.h` | Levels, XP, feats, abilities |
| `Projectile.h` | Projectile physics, effects |
| `Roll.h` | Dice rolls, advantage/disadvantage |
| `Sound.h` | Audio triggers, music state |
| `SpellCast.h` | Spell state, targets, effects |
| `Status.h` | Status effects, durations |

### DEFINE_COMPONENT Pattern

```cpp
// Regular component with fields (needs ARM64 offset verification)
DEFINE_COMPONENT(eoc::health, Health, HealthComponent)
struct HealthComponent {
    int32_t CurrentHP;      // +0x00
    int32_t MaxHP;          // +0x04
    int32_t TempHP;         // +0x08
    // ... more fields
};

// Tag component (zero fields, presence-only)
DEFINE_TAG_COMPONENT(eoc::combat, IsInCombat, IsInCombat)
// No struct body - entity has this or doesn't
```

### Tools Reference

| Tool | Location | Purpose |
|------|----------|---------|
| `extract_typeids.py` | `tools/` | Extract TypeId addresses from macOS binary |
| `generate_component_stubs.py` | `tools/` | Generate C stubs from Windows headers |
| `make_property_map.py` | Windows BG3SE | Original automation script (reference) |
| Frida | External | Runtime memory instrumentation |
| GhidraMCP | MCP server | On-demand decompilation |

### Related Issues

- **Issue #33** - Component Property Layouts Expansion (main tracking issue)
- **Issue #44** - ARM64 Hooking Infrastructure
- **Issue #15** - Client Lua State (unlocks ecl:: components)
