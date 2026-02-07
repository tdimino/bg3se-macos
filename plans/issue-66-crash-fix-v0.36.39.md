# v0.36.39: Issue #66 Crash Fix + Crash-Resilient Logging

## Enhancement Summary

**Deepened on:** 2026-02-07
**Research agents used:** Exa search, rlama (bg3se-windows + bg3se-macos), Firecrawl (PLCrashReporter, signal-safety docs, Breakpad), architecture-strategist
**Key improvements from research:**
1. funcType=0 is the PRIMARY crash cause — default to OSI_FUNC_CALL, not UNKNOWN
2. Ring buffer should be 16KB (one ARM64 page), not 64KB
3. Don't hook crashlog into every log_write() — use LogCallback with min_level=WARN
4. Remove fflush() from dispatch path — line-buffered log already flushes on newline
5. Use SA_ONSTACK + sigaltstack (PLCrashReporter gold standard pattern)
6. Pre-load backtrace() at init to avoid dyld_stub_binder deadlock
7. Move struct probe to on-demand console command, not enumeration path
8. OsiFunctionDef Windows layout confirmed: VMT, Line, Unknown1, Unknown2, Signature, Node, Type, Key[4], OsiFunctionId

## Context

**Issue #66:** `Osi.AddGold()` / `Osi.TemplateAddTo()` crash the game with SIGSEGV when called from the BG3SE console. v0.36.38 hooked `RegisterDIVFunctions` and captured correct `DivFunctions::Call/Query` pointers, but the crash persists. ShaiLaric's logs show `Call=0x105d81744, Query=0x105d81998` captured successfully, then the game dies so fast that the "Overlay execute:" log line never flushes.

**Root Causes Identified (3 agents):**

### Bug A: Raw funcId vs Encoded OsirisFunctionHandle
Windows BG3SE passes `function_->GetHandle()` (encoded 32-bit handle) to `DivFunctions::Call/Query`, NOT a raw function ID. The handle packs 4 Key values:
```
Handle = (Key[0_type] & 7) | (Key[3_part4] << 31) | (Key[2_funcId] << 3)
```
Our code passes the raw enumeration index from `osi_func_cache_by_id()`. The game's DivFunctions dispatcher decodes `Handle & 7` for type, `Handle >> 3` for funcId — with our raw value, it reads garbage.

### Bug B: funcType hardcoded to 0 (HIGHEST PRIORITY FIX)
`osiris_functions.c:350-351`: All dynamically discovered functions get `type=0` (UNKNOWN). The dispatch switch falls to default case which tries query-first, then call. For `AddGold` (a Call type), this means `queryFn(funcId, args)` runs first. If the query dispatcher interprets arguments differently, this corrupts the argument chain before the call fallback.

**Research insight:** Defaulting to `OSI_FUNC_CALL` (type=3) instead of `OSI_FUNC_UNKNOWN` (type=0) alone likely fixes the AddGold SIGSEGV, because it routes directly to `DivFunctions::Call` without the dangerous query-first fallback.

### Bug C: No crash diagnostics
No SIGSEGV handler, no crash-safe logging. When the crash happens, buffered log (`_IOLBF`) doesn't flush. We lose all evidence of what happened.

### Research Insight: ARM64 Calling Convention Learning
`docs/solutions/arm64-calling-convention-crashes.md` documents a prior crash (Issue #39) where wrong function signatures caused SIGSEGV. Same pattern here — wrong argument (raw ID vs handle) causes the engine to dereference garbage.

## Implementation Plan

### Part 1: Crash-Resilient Logging (`src/core/crashlog.c/.h`)

New module alongside existing `logging.c`. Provides three crash-survival mechanisms.

**1a. mmap'd Ring Buffer (crash-safe log)**
- `MAP_SHARED` file-backed mmap at `~/Library/Application Support/BG3SE/crash_ring_<pid>.bin`
- **16KB ring buffer** (one ARM64 page — Apple Silicon uses 16KB pages, not 4KB)
- Atomic write cursor (`__atomic_fetch_add`) for thread safety
- Pre-allocated at init — mmap() is NOT async-signal-safe, must not call in handler
- File permissions: 0600 (user-only, contains function names and entity GUIDs)

```c
// API
void crashlog_init(void);              // Create mmap'd ring buffer + pre-open crash fd
void crashlog_write(const char *msg, size_t len);  // Signal-safe write to ring
void crashlog_hexdump(const char *label, const void *data, size_t len);  // Hex dump to ring
void crashlog_shutdown(void);          // Cleanup
```

**Research insights:**
- Pre-open the crash file fd at init time (open() is signal-safe, but snprintf for path building is NOT)
- Force-resolve `write()` symbol at init: `(void)write(crash_fd, "", 0)` to avoid dyld_stub_binder deadlock
- Include PID in ring buffer filename to handle multiple game instances
- `msync()` is advisory on macOS — the kernel may flush dirty pages at any time
- 16KB stores ~60 log messages at ~256 bytes each — sufficient for crash context

**1b. SIGSEGV Signal Handler**
- Install via `sigaction()` with `SA_SIGINFO | SA_ONSTACK` (PLCrashReporter uses this pattern)
- Set up sigaltstack with 64KB alternate stack (handles stack overflow crashes)
- Captures: signal number, fault address (`si_addr`), stack trace via `backtrace_symbols_fd()`
- Writes to pre-opened crash file fd (signal-safe: `write()` only, no stdio)
- Dumps breadcrumb trail
- Re-raises signal via `signal(signo, SIG_DFL); raise(signo);` for core dump/CrashReporter

```c
void crash_handler_install(void);  // Call once at init

// Signal handler setup (at init):
static void crash_handler(int signo, siginfo_t *info, void *uap) {
    int saved_errno = errno;
    // write() + backtrace_symbols_fd() + fsync() — all async-signal-safe
    // Dump breadcrumbs, ring buffer tail, backtrace
    errno = saved_errno;
    signal(signo, SIG_DFL);
    raise(signo);
}
```

**Research insights (PLCrashReporter + Firecrawl):**
- Pre-load backtrace machinery at init: `void *dummy[1]; backtrace(dummy, 1);` — forces libgcc/libunwind to load before crash
- `backtrace()` is safe IF libgcc pre-loaded; `backtrace_symbols_fd()` is safe (no malloc); `backtrace_symbols()` is NEVER safe (malloc deadlock)
- Block other crash signals during handler: `sigaddset(&sa.sa_mask, SIGSEGV/SIGBUS/SIGABRT/SIGFPE/SIGILL)`
- Save old handlers for chaining: `sigaction(SIGSEGV, &sa, &g_old_actions[SIGSEGV])`
- Use `O_CLOEXEC` on crash fd to prevent inheritance by child processes
- Pre-allocate hex formatting buffer at file scope (no malloc in handler)

**1c. Breadcrumb System**
- Lock-free ring of 32 entries, each 16 bytes: `const char* func` (8) + `uint32_t extra` (4) + `uint32_t timestamp_low` (4)
- `BREADCRUMB()` macro: one atomic increment + atomic pointer store per call
- Pointer store MUST use `__atomic_store_n` with `__ATOMIC_RELEASE` (not just assignment)
- Near-zero overhead (~10-15ns per call)

```c
typedef struct {
    const char *func;       // __func__ string literal (always valid, read-only data)
    uint32_t extra;         // funcId being dispatched (or 0)
    uint32_t timestamp_low; // low 32 bits of mach_absolute_time()
} BreadcrumbEntry;

static BreadcrumbEntry g_breadcrumbs[32];
static uint32_t g_bc_idx;

#define BREADCRUMB() breadcrumb_mark(__func__, 0)
#define BREADCRUMB_ID(id) breadcrumb_mark(__func__, (id))

static inline void breadcrumb_mark(const char *func, uint32_t extra) {
    uint32_t idx = __atomic_fetch_add(&g_bc_idx, 1, __ATOMIC_RELAXED) & 31;
    g_breadcrumbs[idx].extra = extra;
    g_breadcrumbs[idx].timestamp_low = (uint32_t)mach_absolute_time();
    __atomic_store_n(&g_breadcrumbs[idx].func, func, __ATOMIC_RELEASE);
}
```

**Place BREADCRUMB() only in dispatch-path functions:**
- `osi_call_handler()` — entry point for all Osi.* Lua calls
- `osiris_call_by_id()` — DivFunctions::Call dispatch
- `osiris_query_by_id()` — DivFunctions::Query dispatch

**Do NOT place in enumeration functions** (called 40,000+ times at init — would uselessly overwrite ring).

### Part 2: OsiFunctionDef Struct Probe (On-Demand Console Command)

**Changed from original plan:** Move hex dump probe to an explicit console command, NOT during enumeration. Enumeration already probes 40,000 IDs; adding hex dumps adds latency to the timing-sensitive Load window.

**2a. Console command `!probe_osidef`**

Add a new console command that dumps the first N funcDefs on demand:
```c
// In custom_functions.c or osiris_functions.c:
void osi_func_probe_layout(int count) {
    // For the first `count` cached functions, dump 0x60 bytes of their funcDef
    // Log via crashlog_hexdump (writes to ring buffer AND normal log)
}
```

**2b. Windows OsiFunctionDef layout (from rlama research)**

Windows BG3SE defines (`Osiris.h`):
```cpp
struct OsiFunctionDef {
    void* VMT;                  // 0x00
    uint32_t Line;              // 0x08
    uint32_t Unknown1;          // 0x0C
    uint32_t Unknown2;          // 0x10
    // padding                  // 0x14
    FunctionSignature* Signature; // 0x18
    NodeRef Node;               // 0x20
    FunctionType Type;          // 0x28
    uint32_t Key[4];            // 0x2C: Key[0]=type, Key[1]=Part2, Key[2]=funcId, Key[3]=Part4
    uint32_t OsiFunctionId;     // 0x3C
};
```

**ARM64 may have different padding/alignment.** The probe will confirm offsets.

**2c. Known-function correlation**

For functions with KNOWN types (from known events table), compare the probed type offset with the expected type. This validates our offset discovery.

### Part 3: OsirisFunctionHandle Encoding

**3a. Add handle encoding as inline functions to osiris_types.h**

Co-locate with existing `osi_func_type_str()` inline and `CachedFunction` struct:

```c
// Encode: pack Key[0..3] into a 32-bit handle
static inline uint32_t osi_encode_handle(uint32_t type, uint32_t part2,
                                          uint32_t funcId, uint32_t part4) {
    uint32_t h = (type & 7) | (part4 << 31);
    if (type < 4)
        h |= (funcId & 0x1FFFFFF) << 3;       // 25-bit funcId
    else
        h |= ((funcId & 0x1FFFF) << 3) | ((part2 & 0xFF) << 20);  // 17-bit funcId + 8-bit Part2
    return h;
}

// Decode: extract components from packed handle
static inline uint32_t osi_decode_func_id(uint32_t handle) {
    uint8_t type = handle & 7;
    return (type < 4) ? (handle >> 3) & 0x1FFFFFF : (handle >> 3) & 0x1FFFF;
}

static inline uint8_t osi_decode_func_type(uint32_t handle) {
    return handle & 7;
}
```

**Research confirmation (rlama + Exa):**
- For type < 4 (Event=1, Query=2, Call=3): 25-bit funcId at bits 3-27
- For type >= 4 (Database=4, Proc=5, SysQuery=6, SysCall=7, UserQuery=8): 17-bit funcId at bits 3-19, 8-bit Part2 at bits 20-27
- Bit 31: Part4 (always)
- Bits 0-2: TypeId (always)
- FunctionDb uses `id % 0x3FF` (1023 buckets) for hash lookup

**3b. Cache handle alongside funcId**

Extend `CachedFunction` with a `handle` field (4 bytes added to 136-byte struct):
```c
typedef struct {
    char name[128];
    uint8_t arity;
    uint8_t type;
    uint32_t id;
    uint32_t handle;  // NEW: encoded OsirisFunctionHandle
} CachedFunction;
```

Add `osi_func_get_handle()` lookup function in `osiris_functions.h`.

**3c. Read Key[0..3] during enumeration (future — after probe confirms offsets)**

Once `!probe_osidef` confirms the ARM64 Key layout, read Key[0..3] from funcDef and compute handle during enumeration.

**3d. Initial approach (before offset discovery)**

For v0.36.39, use a **fallback heuristic** based on type + funcId:
- Compute handle from guessed type (via name heuristic or known events) + raw funcId
- Part2=0, Part4=0 as defaults (safe for type < 4 functions)
- `BG3SE_OSI_RAW_ID=1` env var to bypass handle encoding (debug escape hatch)
- Log warning at startup when env var is detected

**Research insight (rlama):** For IDs with high bit set (0x80000000+), the engine decodes `type = rawId & 7`. For `0x80002E93`, this accidentally gives type=3 (Call), which may explain why some functions work while others crash — it depends on whether the raw ID's bottom 3 bits happen to match the correct type.

### Part 4: Fix Dispatch Path (HIGHEST PRIORITY)

**4a. Fix funcType=0 as the primary fix**

Replace the hardcoded `uint8_t type = 0` in `osi_func_cache_by_id()` with `osi_func_guess_type()`:

```c
// In osiris_functions.c — separate testable function
uint8_t osi_func_guess_type(const char *name) {
    if (strncmp(name, "QRY_", 4) == 0) return OSI_FUNC_QUERY;
    if (strncmp(name, "PROC_", 5) == 0) return OSI_FUNC_PROC;
    if (strncmp(name, "DB_", 3) == 0) return OSI_FUNC_DATABASE;
    // Default to CALL, not UNKNOWN — the unknown-type heuristic path
    // (try query then call) is the DANGEROUS path that can SIGSEGV
    return OSI_FUNC_CALL;
}
```

**This alone likely fixes AddGold SIGSEGV.** Default CALL ensures `AddGold` dispatches via `DivFunctions::Call` without first trying the query dispatcher.

**4b. Pass handle to DivFunctions::Call/Query**

In `osi_dynamic_call()` (main.c), replace:
```c
result = callFn(funcId, args);  // WRONG: raw ID
```
With:
```c
uint32_t handle = osi_func_get_handle(funcName);
if (handle == 0) handle = funcId;  // Fallback if handle not yet computed
result = callFn(handle, args);
```

Same for queryFn calls.

**4c. Remove pre-dispatch fflush (CHANGED FROM ORIGINAL)**

**Do NOT add fflush() to the dispatch path.** The log file is already line-buffered (`setvbuf(g_log_file, NULL, _IOLBF, 0)` at logging.c:312). Every `fprintf(g_log_file, "%s\n", ...)` flushes at the newline. Adding explicit `fflush()` is redundant and adds 1-5 microsecond syscall overhead per Osiris call.

Instead, the mmap'd ring buffer provides crash-safe logging without any fflush:
```c
LOG_OSIRIS_INFO(">>> Osi.%s: dispatching via %s (handle=0x%x, funcId=0x%x, type=%d)",
                funcName, g_divCall ? "DivCall" : "Internal", handle, funcId, funcType);
// Ring buffer write happens automatically via LogCallback — survives crash
```

### Part 5: Integration with Existing Logging (CHANGED FROM ORIGINAL)

**5a. Register crashlog as LogCallback — NOT hook into every log_write()**

Use the existing `log_register_callback()` mechanism (logging.c:414) with filtering:
```c
// At init, register crashlog as a callback:
log_register_callback(crashlog_callback, NULL,
                      LOG_LEVEL_WARN,  // Only WARN and above
                      (1 << LOG_MODULE_OSIRIS) | (1 << LOG_MODULE_HOOKS) | (1 << LOG_MODULE_CORE));
```

This means crashlog_write fires only for warnings/errors in crash-relevant modules, NOT for every debug message during combat (which fires 100s/sec).

**Research insight (architecture review):** Hooking into every log_write() adds ~60-90ns per message. During enumeration (40,000 probes), this adds 3.6ms — dangerously close to the 42ms timing window that caused Issue #65.

**5b. Add LOG_MODULE_CRASH**

New module for crash-handler-specific messages. Always enabled at ERROR level.

## Files to Create/Modify

| File | Action | Changes |
|------|--------|---------|
| `src/core/crashlog.c` | **CREATE** | mmap ring buffer, signal handler, breadcrumbs, sigaltstack |
| `src/core/crashlog.h` | **CREATE** | Public API: crashlog_init/write/shutdown, BREADCRUMB macros |
| `src/core/logging.c` | MODIFY | Add log_get_file_handle(), expose callback registration |
| `src/core/logging.h` | MODIFY | Add LOG_MODULE_CRASH, log_get_file_handle() |
| `src/osiris/osiris_types.h` | MODIFY | Add osi_encode_handle/decode inline functions, CachedFunction.handle |
| `src/osiris/osiris_functions.c` | MODIFY | Add osi_func_guess_type(), fix type=0 bug, compute handle during cache |
| `src/osiris/osiris_functions.h` | MODIFY | Add osi_func_get_handle(), osi_func_guess_type(), osi_func_probe_layout() |
| `src/injector/main.c` | MODIFY | Pass handle to DivFunctions, breadcrumbs, install crash handler at init |
| `src/console/console.c` | MODIFY | Add BREADCRUMB() before luaL_dostring |
| `CMakeLists.txt` | MODIFY | Add crashlog.c to build |
| `src/core/version.h` | MODIFY | Bump to v0.36.39 |
| `docs/CHANGELOG.md` | MODIFY | Add v0.36.39 entry |

## Verification

### 1. Build
```bash
cd build && cmake .. && cmake --build .
```

### 2. Crash handler test
```bash
# After launch, the crash_ring_<pid>.bin should exist:
ls -la ~/Library/Application\ Support/BG3SE/crash_ring_*.bin

# Test with AddGold (should NOT crash with funcType fix):
echo 'Osi.AddGold("S_Player_Tav", 100)' | nc -U /tmp/bg3se.sock

# If it still crashes, check crash log:
cat ~/Library/Application\ Support/BG3SE/crash.log
# Should show: signal, fault address, breadcrumbs, backtrace

# Check ring buffer for last messages before crash:
hexdump -C ~/Library/Application\ Support/BG3SE/crash_ring_*.bin | tail -40
```

### 3. Struct probe (on demand)
```bash
# In-game console:
echo '!probe_osidef' | nc -U /tmp/bg3se.sock
# Check log for hex dumps of OsiFunctionDef structs
grep "PROBE" ~/Library/Application\ Support/BG3SE/logs/latest.log
```

### 4. Handle encoding validation
```bash
# After console works without crash:
echo 'Osi.AddGold("S_Player_Tav", 100)' | nc -U /tmp/bg3se.sock
# Should NOT crash, gold should be added
```

### 5. Ship to ShaiLaric
Tag v0.36.39, ship. Even if handle encoding isn't perfect yet, the crash handler + ring buffer will give us the exact stack trace and funcDef layout to iterate on.

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Key offset guess wrong | Medium | Struct probe via `!probe_osidef`; iterate with ShaiLaric's data |
| Ring buffer adds latency | **Very Low** | Only fires on WARN+; memcpy ~50ns; not in hot path |
| Signal handler interferes with game | Low | Only fires on crash; SA_ONSTACK uses separate stack; re-raises for default behavior |
| Handle encoding wrong for some function types | Medium | Fallback to raw funcId with warning; env var to disable |
| Type heuristic misclassifies functions | Low | Default CALL is safer than default UNKNOWN; known events override heuristic |
| dyld_stub_binder deadlock in handler | **Eliminated** | Pre-load backtrace() + force-resolve write() at init |
| Multiple game instances conflict | **Eliminated** | PID in ring buffer filename |

## Research Sources

- [PLCrashReporter (Microsoft)](https://github.com/microsoft/plcrashreporter) — gold standard macOS crash reporting
- [Mike Ash: Ring Buffers and Mirrored Memory](https://www.mikeash.com/pyblog/friday-qa-2012-02-03-ring-buffers-and-mirrored-memory-part-i.html) — macOS Mach VM ring buffer technique
- [POSIX signal-safety(7)](https://man7.org/linux/man-pages/man7/signal-safety.7.html) — complete async-signal-safe function list
- [backtrace(3) man page](https://man7.org/linux/man-pages/man3/backtrace.3.html) — backtrace_symbols_fd safety
- [Google Wuffs mmap-ring-buffer.c](https://github.com/google/wuffs/blob/main/script/mmap-ring-buffer.c) — virtual memory double-mapping
- [Norbyte/bg3se Osiris.h](https://github.com/Norbyte/bg3se/blob/main/BG3Extender/GameDefinitions/Osiris.h) — OsirisFunctionHandle encoding
- [Norbyte/bg3se OsirisWrappers.cpp](https://github.com/Norbyte/bg3se/blob/main/BG3Extender/GameHooks/OsirisWrappers.cpp) — RegisterDIVFunctions hook pattern
- [Apple Developer Forums: Implementing Crash Reporter](https://developer.apple.com/forums/thread/113742)
- [docs/solutions/arm64-calling-convention-crashes.md](docs/solutions/arm64-calling-convention-crashes.md) — prior ARM64 crash pattern
