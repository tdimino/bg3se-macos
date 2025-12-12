# Unexplored Reverse Engineering Techniques

## Overview

Techniques discovered via Exa MCP research (2025-12-12) that we haven't yet employed for remaining issues (#32 RefMap insertion, #37 Physics, #38 Audio).

---

## Technique Matrix

| Technique | Tool | Issue Impact | Effort | Status |
|-----------|------|--------------|--------|--------|
| GhidraMCP integration | MCP server | All issues | 2h setup | ✅ COMPLETE |
| Frida Stalker | Frida | #32 (hash function) | 1h | NOT STARTED |
| frida-itrace | Frida | Complex flows | 2h | NOT STARTED |
| Parallel Ghidra | Bash/Scripts | Init discovery | 1h | NOT STARTED |
| pyghidra-mcp | MCP server | Multi-binary | 3h | NOT STARTED |

---

## 1. GhidraMCP Integration (HIGHEST IMPACT)

MCP server by LaurieWired enabling Claude to directly query Ghidra.

**Source:** https://github.com/LaurieWired/GhidraMCP

**Capabilities:**
- Decompile functions on demand
- List functions, classes, namespaces
- Search for symbols and strings
- Auto-rename methods and data

### Installation

**Step 1: Download and install Ghidra plugin (headless)**

```bash
# Download release
curl -LO https://github.com/LaurieWired/GhidraMCP/releases/download/1.4/GhidraMCP-release-1-4.zip

# Extract to Ghidra Extensions directory
unzip GhidraMCP-release-1-4.zip -d ~/ghidra/Ghidra/Extensions/
cd ~/ghidra/Ghidra/Extensions/
unzip GhidraMCP-release-1-4/GhidraMCP-1-4.zip
rm -rf GhidraMCP-release-1-4
```

Result: `~/ghidra/Ghidra/Extensions/GhidraMCP/` with extension.properties, lib/GhidraMCP.jar

**Step 2: Enable plugin (one-time in GUI)**

In Ghidra: File → Configure → Developer → check GhidraMCPPlugin

**Step 3: Install Python MCP bridge**

```bash
pip install mcp requests
git clone https://github.com/LaurieWired/GhidraMCP ~/ghidra/GhidraMCP
```

**Step 4: Configure Claude Code MCP**

**IMPORTANT:** Claude Code uses per-project MCP config in `~/.claude.json`, NOT `~/.claude/settings.json`.

Add to `~/.claude.json` under your project's entry:

```json
{
  "projects": {
    "/path/to/your/project": {
      "mcpServers": {
        "ghidra": {
          "type": "stdio",
          "command": "python",
          "args": [
            "/path/to/GhidraMCP/bridge_mcp_ghidra.py",
            "--ghidra-server",
            "http://127.0.0.1:8080/"
          ]
        }
      }
    }
  }
}
```

Or use the CLI: `claude mcp add ghidra --command python --args /path/to/bridge_mcp_ghidra.py --args --ghidra-server --args http://127.0.0.1:8080/`

**Step 5: Restart Claude Code**

**Impact:** Query decompilation directly during conversation - no context switching.

---

## 2. Frida Stalker (HIGH IMPACT for #32)

**What it is:** Instruction-level code tracing in Frida. Can trace every instruction through a function.

**Use case:** Discover RefMap hash function algorithm by tracing execution when we look up a known key.

**Implementation:**
```javascript
// tools/frida/stalker_refmap_hash.js
const BASE = Process.findModuleByName("Baldur's Gate 3").base;
const REFMAP_FIND = BASE.add(0x...);  // RefMap::Find or operator[]

Stalker.follow(Process.getCurrentThreadId(), {
    events: { call: true, ret: true },

    onReceive: function(events) {
        const parsed = Stalker.parse(events);
        for (const event of parsed) {
            if (event[0] === 'call') {
                console.log(`CALL ${event[1]} -> ${event[2]}`);
            }
        }
    }
});

// Trigger a RefMap lookup
Interceptor.attach(REFMAP_FIND, {
    onEnter: function(args) {
        console.log("RefMap lookup with key:", args[1]);
        // Stalker will trace the hash calculation
    }
});
```

**Expected output:** Sequence of instructions that compute hash from FixedString index.

---

## 3. frida-itrace / TraceBuffer

**What it is:** Extended tracing with detailed instruction capture.

**Use case:** Complex control flow analysis where we need to see every branch decision.

**Example:**
```javascript
// Trace all calls within a specific address range
const ranges = [
    { base: BASE.add(0x101f70000), size: 0x10000 }  // SpellPrototype area
];

Stalker.follow({
    transform: function(iterator) {
        let instruction;
        while ((instruction = iterator.next()) !== null) {
            console.log(instruction.address + ": " + instruction.mnemonic + " " + instruction.opStr);
            iterator.keep();
        }
    }
});
```

---

## 4. Parallel Ghidra Analysis

**What it is:** Running multiple headless Ghidra scripts simultaneously for faster offset discovery.

**Implementation:**
```bash
#!/bin/bash
# scripts/parallel_ghidra.sh

SCRIPTS=(
    "find_status_init.py"
    "find_passive_init.py"
    "find_interrupt_init.py"
    "find_boost_init.py"
)

for script in "${SCRIPTS[@]}"; do
    ./ghidra/scripts/run_analysis.sh "$script" &
done

wait
echo "All analyses complete"
```

**Use case:** Finding Init functions for Status, Passive, Interrupt, Boost prototype managers (needed for full Stats.Sync).

---

## 5. Hooah-Trace (iGio90)

**What it is:** Frida-based instruction tracing library with visualization.

**Source:** https://github.com/AeonLucid/frida-hooah-trace

**Features:**
- Color-coded trace output
- Register state at each instruction
- Memory access tracking

---

## Implementation Priority

### Phase 1: Quick Wins (Today)
1. **Frida Stalker for RefMap hash** - Could finally solve #32 completely
2. **Parallel Ghidra scripts** - Find remaining Init functions

### Phase 2: Infrastructure (This Week)
3. **GhidraMCP setup** - Transform future RE sessions
4. **frida-itrace integration** - Complex flow analysis

### Phase 3: Advanced (As Needed)
5. **pyghidra-mcp** - Multi-binary analysis
6. **Hooah-Trace** - Visual debugging

---

## Blocking Issues Mapping

### Issue #32 (Stats Sync) - 90% Complete
**Remaining:** RefMap insertion for NEW spells
**Best technique:** Frida Stalker to discover hash function, then implement in C

### Issue #37 (Ext.Level/Physics) - 0%
**Blocking:** PhysicsScene singleton capture
**Best technique:** Already have Frida script (`capture_physics.js`), needs runtime execution

### Issue #38 (Ext.Audio/Wwise) - 0%
**Blocking:** Function signature verification
**Best technique:** Frida Interceptor to test `IsInitialized()` call

---

## Next Actions

1. [ ] Create `tools/frida/stalker_refmap_hash.js`
2. [ ] Run Frida Stalker during SpellPrototypeManager lookup
3. [ ] Document discovered hash algorithm
4. [ ] Implement hash function in C for RefMap insertion
5. [ ] Test creating new spell with full prototype sync
