# Unexplored Reverse Engineering Techniques

## Overview

Techniques discovered via Exa MCP research (2025-12-12) that we haven't yet employed for remaining issues (#32 RefMap insertion, #37 Physics, #38 Audio).

---

## Technique Matrix

| Technique | Tool | Issue Impact | Effort | Status |
|-----------|------|--------------|--------|--------|
| GhidraMCP integration | MCP server | All issues | 2h setup | ✅ COMPLETE |
| Frida Stalker | Frida | #32 (hash function) | 1h | ⚠️ CRASHES BG3 |
| frida-itrace | Frida | Complex flows | 2h | NOT STARTED |
| Parallel Ghidra | Bash/Scripts | Init discovery | 1h | ✅ COMPLETE |
| pyghidra-mcp | MCP server | Multi-binary | 3h | ✅ VERIFIED WORKING |

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

### ⚠️ Connection Stability (Dec 12, 2025)

**Root Causes of Connection Drops:**

1. **GUI Dialog Blocking** - If Ghidra shows ANY error dialog (via `Msg.showError`), the HTTP server HANGS waiting for user to close it. Watch for popups!

2. **Default Timeout Too Short** - The Python bridge uses 5-second read timeout, which is insufficient for large binary operations (BG3 is 500MB+)

3. **Memory Pressure** - Analyzing large binaries can exhaust Ghidra's heap, causing the server to become unresponsive

4. **CodeBrowser Window Closed** - Server ONLY runs when CodeBrowser is open with plugin enabled

**Stability Best Practices:**

```bash
# 1. Increase Ghidra heap for large binaries
# Edit ~/ghidra/support/launch.properties:
MAXMEM=8G  # (default is often 2G or 4G)

# 2. Test server responsiveness before queries
curl -s http://localhost:8080/sse | head -1

# 3. Keep Ghidra console visible to catch error dialogs
```

**Preventing Drops During Session:**
- Keep Ghidra window visible (not minimized) to catch any dialogs
- Don't switch to other Ghidra tools (stay in CodeBrowser)
- For very large queries, consider using headless pyghidra-mcp instead

**Alternative: pyghidra-mcp (Headless) - ✅ INSTALLED**

For more stable operation with large binaries, we now have [pyghidra-mcp](https://github.com/clearbluejar/pyghidra-mcp):
- Runs headless (no GUI dialogs to block)
- Supports multi-binary analysis
- Better suited for automation

**Full Installation Guide (Dec 12, 2025):**

**Prerequisites:**
- Ghidra **11.3+** (PyGhidra module not included in earlier versions)
- Java 17+ (OpenJDK via Homebrew works)
- Python 3.10+ with uv package manager

**Step 1: Upgrade Ghidra to 11.3+ (if needed)**
```bash
# Check current version
cat ~/ghidra/Ghidra/application.properties | grep version

# If < 11.3, upgrade:
cd ~/Downloads
curl -LO https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.2_build/ghidra_11.3.2_PUBLIC_20250415.zip

# Backup old installation
mv ~/ghidra ~/ghidra-11.2.1-backup

# Extract new version
unzip ghidra_11.3.2_PUBLIC_20250415.zip -d ~/
mv ~/ghidra_11.3.2_PUBLIC ~/ghidra

# Copy extensions from backup (e.g., GhidraMCP)
cp -r ~/ghidra-11.2.1-backup/Ghidra/Extensions/GhidraMCP ~/ghidra/Ghidra/Extensions/
```

**Step 2: Verify PyGhidra exists**
```bash
ls ~/ghidra/Ghidra/Features/PyGhidra/lib/PyGhidra.jar
# Should show the JAR file
```

**Step 3: Install pyghidra-mcp**
```bash
uvx pyghidra-mcp --version  # v0.1.12
```

**Step 4: Configure Claude Code MCP** (`.mcp.json`)

First, create a thinned ARM64 binary (see "CRITICAL: BG3 Binary is Universal" below).

```json
{
  "mcpServers": {
    "pyghidra-mcp": {
      "type": "stdio",
      "command": "uvx",
      "args": [
        "pyghidra-mcp",
        "-t",
        "stdio",
        "/Users/tomdimino/ghidra_projects/BG3_arm64_current.thin"
      ],
      "env": {
        "GHIDRA_INSTALL_DIR": "/Users/tomdimino/ghidra",
        "JAVA_HOME": "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"
      }
    }
  }
}
```

**Or add via CLI:**
```bash
claude mcp add --transport stdio pyghidra-mcp \
  --env GHIDRA_INSTALL_DIR=/Users/tomdimino/ghidra \
  --env JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
  -- uvx pyghidra-mcp -t stdio /Users/tomdimino/ghidra_projects/BG3_arm64_current.thin
```

**Common Issues:**
| Error | Solution |
|-------|----------|
| `PyGhidra.jar does not exist` | Upgrade Ghidra to 11.3+ |
| `Unable to locate a Java Runtime` | Set `JAVA_HOME` in .mcp.json env |
| `--project-path` bug | Known issue in v0.1.12, use binary path instead |
| `No load spec found` | BG3 is a universal (fat) binary - must thin first! |
| `Path does not exist` | Check Steam path vs /Applications path |

**⚠️ CRITICAL: BG3 Binary is Universal (Dec 12, 2025)**

The BG3 binary from Steam is a **universal binary** (fat binary with both x86_64 + arm64). PyGhidra/Ghidra **cannot import universal binaries directly**. You must extract the ARM64 slice first:

```bash
# Check if binary is universal (will show "2 architectures")
file "/path/to/Baldur's Gate 3"

# Extract ARM64 slice using lipo
lipo -thin arm64 \
  "/Users/tomdimino/Library/Application Support/Steam/steamapps/common/Baldurs Gate 3/Baldur's Gate 3.app/Contents/MacOS/Baldur's Gate 3" \
  -output ~/ghidra_projects/BG3_arm64_current.thin

# Verify it's a single-architecture binary
file ~/ghidra_projects/BG3_arm64_current.thin
# Should show: "Mach-O 64-bit executable arm64" (NOT "universal binary")
```

**Usage with BG3 Binary:**
```bash
# WRONG: Universal binary will fail with "No load spec found"
uvx pyghidra-mcp -t stdio "/path/to/Baldur's Gate 3.app/.../Baldur's Gate 3"

# CORRECT: Use thinned ARM64 binary
uvx pyghidra-mcp -t stdio ~/ghidra_projects/BG3_arm64_current.thin

# Or use HTTP transport for direct queries:
uvx pyghidra-mcp -t streamable-http -p 8000 ~/ghidra_projects/BG3_arm64_current.thin
# Then query: curl http://localhost:8000/mcp
```

**Note:** First analysis of 500MB BG3 binary will take 30-60+ minutes. Results are cached in `pyghidra_mcp_projects/`.

### ✅ Verified Working (Dec 12, 2025)

PyGhidra-MCP was successfully used to:
- List 1000s of BG3 functions (Curl, Graphine/Granite, Wwise audio, game logic)
- Search for `SpellPrototype`, `RefMap`, `XXH3` functions
- Decompile `XXH_INLINE_XXH3_64bits_withSeed` to verify hash algorithm
- Discover `DEPRECATED_RefMapImpl::GetOrAdd` function addresses

**Key Discovery - GetOrAdd Functions (for RefMap insertion):**

| Template Specialization | Address |
|------------------------|---------|
| `GetOrAdd<FixedString, eoc::ai::ActionResourceMappingComponent*>` | `0x1003da9bc` |
| `GetOrAdd<FixedString, eoc::AbilityDistributionPresetMappingComponent*>` | `0x1003dd014` |
| `GetOrAdd<FixedString, eoc::AnimationSetMappingComponent*>` | `0x100401a9c` |
| `GetOrAdd<FixedString, eoc::spell::SpellPrototype*>` | (search pending) |

**Note:** `claude mcp list` may show "Failed to connect" but the actual MCP tools work correctly - this is a status display quirk.

---

## 2. Frida Stalker (⚠️ CRASHES BG3 - USE INTERCEPTOR INSTEAD)

**What it is:** Instruction-level code tracing in Frida. Can trace every instruction through a function.

**Use case:** Discover RefMap hash function algorithm by tracing execution when we look up a known key.

### ⚠️ CRITICAL LESSON LEARNED (Dec 12, 2025)

**Stalker.follow() crashes BG3.** The Stalker API recompiles every instruction the traced thread executes. For a 1GB game binary like BG3, this causes:

1. **Massive memory overhead** - JIT buffer exhaustion
2. **Code recompilation lag** - game expects tight timing
3. **Thread timing violations** - leads to crash

**Solution:** Use `Interceptor.attach()` only (lightweight hooks, no recompilation).

**Working script:** `tools/frida/trace_refmap_light.js` - Interceptor-only, no Stalker.

**Deprecated script:** `tools/frida/stalker_refmap_hash.js` - Kept for reference, DO NOT USE.

### Safe Approach (Interceptor-only)

```javascript
// tools/frida/trace_refmap_light.js
const REFMAP_GET_OR_ADD = BASE.add(0x1011bbc5c - 0x100000000);

// Hook specific function - much lighter than Stalker
Interceptor.attach(REFMAP_GET_OR_ADD, {
    onEnter: function(args) {
        const fsValue = args[1].readU32();
        const capacity = this.context.x0.add(0x10).readU32();
        console.log(`Key: ${fsValue}, Simple mod: ${fsValue % capacity}`);
    },
    onLeave: function(retval) {
        console.log(`Result slot: ${retval}`);
    }
});
```

**For hash algorithm discovery:** Use GhidraMCP to decompile `DEPRECATED_RefMapImpl::GetOrAdd` at `0x1011bbc5c` instead of runtime tracing.

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

## 4. Parallel Ghidra Analysis ✅ COMPLETE

**What it is:** Running multiple headless Ghidra scripts simultaneously for faster offset discovery.

**Script:** `ghidra/scripts/parallel_ghidra.sh`

**Usage:**
```bash
# Run multiple scripts in parallel (default: 2 concurrent jobs)
./ghidra/scripts/parallel_ghidra.sh find_status_manager.py find_prototype_managers.py find_localization.py

# Increase concurrency (requires more RAM - ~4GB per job)
./ghidra/scripts/parallel_ghidra.sh --max-jobs 4 script1.py script2.py script3.py script4.py

# Show help and available scripts
./ghidra/scripts/parallel_ghidra.sh --help
```

**Features:**
- Job limiting to prevent OOM (default: 2 concurrent, configurable via `--max-jobs`)
- Per-script logging to `/tmp/ghidra_parallel/<script>.log`
- Summary report at `/tmp/ghidra_parallel/summary.txt`
- Real-time progress output with timestamps
- Exit code reflects success/failure

**Use case:** Finding Init functions for Status, Passive, Interrupt, Boost prototype managers (needed for full Stats.Sync).

**RAM Warning:** Each Ghidra instance loads the full BG3 binary (~500MB). With 4 concurrent jobs, expect ~8GB RAM usage.

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

### Issue #32 (Stats Sync) - 95% Complete
**Remaining:** RefMap insertion for NEW spells
**Hash function:** ✅ DISCOVERED - BG3 uses XXH3 (XXHash 3) - standard library available
**Next step:** Implement `XXH3_64bits(&fs_key, 4) % capacity` in C, add xxhash dependency

### Issue #37 (Ext.Level/Physics) - 0%
**Blocking:** PhysicsScene singleton capture
**Best technique:** Already have Frida script (`capture_physics.js`), needs runtime execution

### Issue #38 (Ext.Audio/Wwise) - 0%
**Blocking:** Function signature verification
**Best technique:** Frida Interceptor to test `IsInitialized()` call

---

## Next Actions

1. [x] ~~Create `tools/frida/stalker_refmap_hash.js`~~ - Created but crashes BG3
2. [x] ~~Run Frida Stalker during SpellPrototypeManager lookup~~ - Stalker too heavy
3. [x] **Document discovered hash algorithm** - ✅ XXH3 discovered via GhidraMCP! (see STATS.md)
4. [ ] Implement XXH3 hash function in C for RefMap insertion
5. [ ] Test creating new spell with full prototype sync
6. [ ] Run `capture_physics.js` for PhysicsScene singleton (when BG3 running)
7. [ ] Search for Wwise/Audio functions in main binary via GhidraMCP
