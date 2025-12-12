# Advanced Testing & Reverse Engineering Optimization Plan

## Overview

This plan extends `/plans/testing-optimization.md` with advanced techniques discovered through MCP research (Exa, Perplexity, Context7). Focus: accelerate remaining issues (#37 Ext.Level, #38 Ext.Audio, #32 completion) through smarter tooling.

## Current State

| Issue | Feature | Status | Blocking Factor |
|-------|---------|--------|-----------------|
| #32 | Stats Sync | 90% ✅ | New spell RefMap insertion |
| #37 | Ext.Level (Physics) | 0% | PhysicsScene pointer capture |
| #38 | Ext.Audio (Wwise) | 0% | Function signature verification |

---

## Part 1: Advanced Testing Optimizations (Building on testing-optimization.md)

### Tier 1: Hot Reload System (HIGH IMPACT)

**Research Finding:** Games like Love2D (lurker/livelove), Factorio, and Unity use hot-reload patterns that preserve state across code changes.

**Implementation:**
```lua
-- Auto-reload debug scripts when file changes
Ext.Debug.WatchFile("/path/to/probe.lua", function(path)
    dofile(path)
    Ext.Print("Hot-reloaded: " .. path)
end)
```

**Files to create:**
- `src/lua/lua_hotreload.c` - File watcher using FSEvents (macOS native)
- Register `Ext.Debug.WatchFile(path, callback)`

**Effort:** ~3 hours | **Impact:** Eliminates game restarts for script iteration

---

### Tier 2: Frida Integration for Singleton Discovery

**Research Finding:** Frida enables non-invasive runtime hooking without binary modification. Can intercept functions to capture singleton pointers.

**Implementation:**
```javascript
// frida-script.js - Capture PhysicsScene pointer
Interceptor.attach(ptr("0x10116fd20"), {  // AiGrid constructor
    onEnter: function(args) {
        console.log("PhysicsScene: " + args[1]);  // Captured!
        send({type: "singleton", name: "PhysicsScene", addr: args[1].toString()});
    }
});
```

**Workflow:**
1. Create `tools/frida/capture_singletons.js`
2. Run: `frida -U -n "Baldur's Gate 3" -l capture_singletons.js`
3. Results feed into `ghidra/offsets/` documentation

**Effort:** ~2 hours | **Impact:** 10x faster singleton discovery than manual Ghidra

---

### Tier 3: Automated Regression Test Suite

**Research Finding:** Bethesda modding (AutoTest) and Factorio (FactorioTest) have in-game test frameworks.

**Implementation:**
```lua
-- test-mods/bg3se-tests/BootstrapServer.lua
local TestRunner = {}

TestRunner.tests = {
    ["Stats.Get returns table"] = function()
        local s = Ext.Stats.Get("WPN_Longsword")
        assert(type(s) == "table", "Expected table")
        assert(s.Name == "WPN_Longsword", "Wrong name")
    end,

    ["Stats.Sync doesn't crash"] = function()
        local s = Ext.Stats.Get("Projectile_FireBolt")
        s.Damage = "2d6"
        Ext.Stats.Sync("Projectile_FireBolt")  -- Should not crash
    end,

    ["Entity.Get returns valid entity"] = function()
        local player = Osi.GetHostCharacter()
        local e = Ext.Entity.Get(player)
        assert(e ~= nil, "Entity should exist")
    end
}

function TestRunner.RunAll()
    local passed, failed = 0, 0
    for name, test in pairs(TestRunner.tests) do
        local ok, err = pcall(test)
        if ok then
            Ext.Print("✅ " .. name)
            passed = passed + 1
        else
            Ext.Print("❌ " .. name .. ": " .. tostring(err))
            failed = failed + 1
        end
    end
    Ext.Print(string.format("\n%d passed, %d failed", passed, failed))
end

-- Run via console: !test
Ext.RegisterConsoleCommand("test", function() TestRunner.RunAll() end)
```

**Effort:** ~1 hour | **Impact:** Catch regressions before they ship

---

### Tier 4: Structured Probe Library

**Research Finding:** Lua debug libraries in games (Civ5, Total War) preload helper functions.

**Implementation - Preloaded at console connect:**
```lua
-- Auto-loaded debug helpers (registered in C)
Debug = Debug or {}

function Debug.ProbeRefMap(mgr_addr, target_fs)
    local cap = Ext.Debug.ReadU32(mgr_addr + 0x10)
    local keys = Ext.Debug.ReadPtr(mgr_addr + 0x28)
    local vals = Ext.Debug.ReadPtr(mgr_addr + 0x38)

    for i = 0, math.min(cap, 10000) - 1 do
        local k = Ext.Debug.ReadU32(keys + i * 4)
        if k == target_fs then
            local v = Ext.Debug.ReadPtr(vals + i * 8)
            return {index = i, key = k, value = v}
        end
    end
    return nil
end

function Debug.ProbeStruct(base, spec)
    -- spec = {{"name", offset, "ptr"|"u32"|"i32"|"str"}, ...}
    local result = {}
    for _, field in ipairs(spec) do
        local name, off, typ = field[1], field[2], field[3]
        if typ == "ptr" then
            result[name] = Ext.Debug.ReadPtr(base + off)
        elseif typ == "u32" then
            result[name] = Ext.Debug.ReadU32(base + off)
        elseif typ == "str" then
            result[name] = Ext.Debug.ReadString(base + off, 64)
        end
    end
    return result
end

function Debug.HexMath(base, offset)
    return string.format("0x%X", base + offset)
end
```

**Effort:** ~2 hours | **Impact:** Single-call struct discovery

---

### Tier 5: Script Library System

**Implementation:**
```
~/Library/Application Support/BG3SE/
├── scripts/
│   ├── probe_spell_refmap.lua
│   ├── find_physics_scene.lua
│   └── test_audio_init.lua
└── autoload/
    └── debug_helpers.lua  # Loaded on console connect
```

**Console usage:**
```bash
echo 'dofile(Ext.IO.GetDataPath() .. "/scripts/probe_spell_refmap.lua")' | nc -U /tmp/bg3se.sock
```

**Effort:** ~30 min | **Impact:** Reusable probe sequences

---

## Part 2: Ideal Reverse Engineering Persona

### Persona: "Meridian" - ARM64 Game Systems Archaeologist

**Core Identity:**
A methodical systems engineer who combines low-level reverse engineering intuition with pragmatic shipping mentality. Treats each binary analysis session as an archaeological dig - patient, systematic, documenting everything.

**Key Traits:**

| Trait | Description |
|-------|-------------|
| **Hypothesis-Driven** | Forms specific predictions before probing: "I expect FixedString at +0x20 based on Windows layout" |
| **Document-As-You-Go** | Every discovery immediately goes to `ghidra/offsets/*.md` |
| **Minimum Viable Hook** | Ships working features over perfect ones; iterates |
| **Pattern Recognition** | Recognizes ARM64 idioms (ADRP+LDR, x8 indirect return) instantly |
| **Empathy for Modders** | Understands what mod authors actually need, not just what's technically interesting |

**Decision Framework:**
```
1. Can I solve this with runtime probing? (fastest)
   → Use Ext.Debug.ProbeStruct() / console commands

2. Do I need static analysis?
   → Ghidra headless script, document in offsets/*.md

3. Is this a calling convention issue?
   → Check ARM64 ABI: const& = pointer, >16 byte return = x8

4. Am I blocked on a singleton?
   → Frida hook or probe EntityWorld chain
```

### Prompt Template for Persona Activation

```markdown
# Reverse Engineering Session: [FEATURE NAME]

You are Meridian, an ARM64 game systems archaeologist working on BG3SE-macOS.

## Context
- Project: macOS port of Norbyte's Script Extender for Baldur's Gate 3
- Architecture: ARM64 (Apple Silicon)
- Reference: Windows BG3SE at /Users/tomdimino/Desktop/Programming/bg3se
- Binary: /Applications/Baldur's Gate 3.app (1GB+, partially stripped)

## Your Approach
1. **Hypothesis First**: State what you expect to find before probing
2. **Runtime Before Static**: Try Ext.Debug.* probing before Ghidra
3. **Document Immediately**: Update ghidra/offsets/*.md with every finding
4. **ARM64 Awareness**: Watch for const& (pointer), x8 indirect return, alignment
5. **Ship Incrementally**: Working partial > perfect theoretical

## Available Tools
- Console: `echo 'cmd' | nc -U /tmp/bg3se.sock`
- Ghidra: `./ghidra/scripts/run_analysis.sh script.py`
- Frida: `frida -U -n "Baldur's Gate 3" -l script.js`
- osgrep: Semantic code search across both repos

## Current Task
[DESCRIBE SPECIFIC GOAL]

## Known Offsets (from ghidra/offsets/STATS.md)
- RPGStats::m_ptr: 0x1089c5730
- SpellPrototypeManager: 0x1089bac80
- SpellPrototype::Init: 0x101f72754

Begin by stating your hypothesis, then probe systematically.
```

---

## Part 3: Implementation Priority Matrix

| Priority | Item | Time | Impact |
|----------|------|------|--------|
| **P0** | Preloaded Debug.* helpers | 2h | Every session faster |
| **P0** | Test suite (!test command) | 1h | Catch regressions |
| **P1** | Hot reload for scripts | 3h | No game restarts |
| **P1** | Frida singleton capture | 2h | Unblock #37, #38 |
| **P2** | Script library system | 30m | Reusable probes |
| **P2** | Persona prompt in CLAUDE.md | 15m | Consistent approach |

**Total: ~9 hours for full testing optimization**

---

## Part 4: Remaining Issues Acceleration

### Issue #32 (Stats Sync) - 90% Complete
**Remaining:** RefMap insertion for NEW spells
**Approach:**
1. Find `RefMap::Insert` or `operator[]` that allocates
2. Intern spell name to GlobalStringTable
3. Allocate SpellPrototype struct
4. Call Init

### Issue #37 (Ext.Level/Physics) - 0%
**Blocker:** PhysicsScene pointer
**Approach:**
1. Frida hook `AiGrid` constructor at `0x10116fd20`
2. Capture `PhysicsSceneBase*` from args[1]
3. Store globally, expose via `get_physics_scene()`

### Issue #38 (Ext.Audio/Wwise) - 0%
**Blocker:** Function signature verification
**Approach:**
1. Call `IsInitialized()` at `0x10019d594` (no args, returns bool)
2. If works, proceed with `PostEvent`, `StopAll`
3. Wwise uses static functions - no singleton needed

---

## Success Metrics

- [ ] `!test` runs 10+ automated tests without crashes
- [ ] Hot reload updates probe scripts without game restart
- [ ] Frida captures PhysicsScene in <5 minutes
- [ ] Debug.ProbeRefMap finds entries in 1 call (was 20+)
- [ ] New issues use Meridian persona for consistent approach
