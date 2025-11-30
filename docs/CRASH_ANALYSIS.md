# Crash Analysis: macOS Hardened Runtime and BG3SE

This document explains the crashes encountered during BG3SE-macOS development and the underlying macOS security mechanisms that caused them.

## Summary

During development, we encountered two distinct types of crashes:

1. **KERN_PROTECTION_FAILURE** - Caused by attempting to hook main binary functions
2. **Metal Renderer Crashes** - Unrelated to BG3SE, caused by BG3's macOS rendering instability

## The Problem: Hooking Main Binary Functions

### What We Tried

The original approach was to hook `esv::EocServer::StartUp` at address `0x10110f0d0` using Dobby (an inline hooking framework). This would capture the `EoCServer*` this pointer when the function is called, giving us access to `EntityWorld` at offset `0x288`.

```c
// Attempted hook (caused crashes)
uintptr_t startup_addr = OFFSET_EOC_SERVER_STARTUP - ghidra_base + actual_base;
DobbyHook((void*)startup_addr, (void*)hook_EocServerStartUp, (void**)&orig_EocServerStartUp);
```

### What Happened

The game crashed with `KERN_PROTECTION_FAILURE` at addresses in the main binary's `__TEXT` segment:

```
Exception Type:  EXC_BAD_ACCESS (SIGBUS)
Exception Codes: KERN_PROTECTION_FAILURE at 0x1039d8934
```

### Why It Failed: macOS Hardened Runtime

macOS enforces **Hardened Runtime** protections on signed applications. Key restrictions:

1. **Code Signing Enforcement**: The `__TEXT` segment of signed binaries is read-only and execute-only
2. **Memory Protection**: `mprotect(PROT_WRITE)` fails on `__TEXT` segments
3. **No Self-Modification**: Even with `DYLD_INSERT_LIBRARIES`, you cannot modify the main binary's code pages

When Dobby tries to install an inline hook, it:
1. Attempts to make the target page writable via `mprotect()`
2. Writes a trampoline/jump instruction to the function prologue
3. Restores execute permissions

On Hardened Runtime binaries, step 1 fails silently or with `KERN_PROTECTION_FAILURE`.

### Why libOsiris Hooks Work

Our hooks on `COsiris::InitGame`, `COsiris::Load`, and `COsiris::Event` work successfully because:

1. **libOsiris.dylib is loaded at runtime** by the game (not a pre-linked framework)
2. **Different memory protections** apply to dynamically loaded libraries
3. **Dobby can successfully patch** these pages without triggering Hardened Runtime restrictions

The key difference:
- **Main binary** (`BG3`) - Signed, Hardened Runtime enabled, `__TEXT` is immutable
- **libOsiris.dylib** - Loaded at runtime, different protection flags, writable with `mprotect()`

## The Solution: Direct Memory Read

Instead of hooking, we discovered the exact address of the `EoCServer` singleton pointer via Ghidra analysis:

```
Symbol: __ZN3esv9EocServer5m_ptrE
Address: 0x10898e8b8
Meaning: esv::EocServer::m_ptr (static member pointer)
```

This is a **global pointer in the `__DATA` segment** that holds the `EoCServer*` singleton. The `__DATA` segment is readable (unlike `__TEXT` which caused issues).

### Implementation

```c
// Direct read from known global address
uintptr_t global_addr = OFFSET_EOCSERVER_SINGLETON_PTR - ghidra_base + actual_base;
void *eocserver = *(void **)global_addr;  // Safe read from __DATA
void *entityworld = *(void **)((char *)eocserver + 0x288);  // EntityWorld at offset
```

Benefits:
- No hooking required
- No memory protection issues
- Works on Hardened Runtime binaries
- Deterministic and fast

## Unrelated Crashes: Metal Renderer

### Symptoms

Random crashes during game startup with stack traces like:

```
Thread 27 Crashed:
__bzero + 48
... (Metal/rendering code)
```

These crashes:
- Happen **BEFORE** SessionLoaded fires
- Occur with or without BG3SE enabled
- Are in worker threads doing graphics work
- Show no BG3SE code in the stack trace

### Cause

These are **BG3 macOS port instability issues**, not BG3SE bugs. The macOS version of BG3 has known issues with:
- Metal rendering initialization
- Multi-threaded resource loading
- Memory management during startup

### Evidence

1. Same crashes occur with BG3SE completely disabled
2. Crashes happen before any mod code executes
3. Stack traces show only Apple/Larian code, no BG3SE

### Mitigation

None from our side - these are game bugs. Workarounds:
- Retry launching the game (usually works on 2nd or 3rd try)
- Reduce graphics settings
- Ensure macOS and BG3 are updated

## Technical Details

### Hardened Runtime Background

Apple's Hardened Runtime (introduced in macOS 10.14) provides:
- **Library Validation**: Only Apple-signed or team-signed libraries can be loaded
- **Code Signing Enforcement**: Prevents code modification at runtime
- **Memory Protections**: Enforces W^X (write xor execute) policy

BG3 is signed with Hardened Runtime enabled, which means:
```bash
$ codesign -d --entitlements :- /path/to/BG3
# Shows hardened runtime flags
```

### DYLD_INSERT_LIBRARIES Limitations

While `DYLD_INSERT_LIBRARIES` allows loading our dylib before main(), it does NOT:
- Bypass Hardened Runtime restrictions
- Allow modifying the main binary's code
- Disable code signing enforcement

It DOES allow:
- Loading custom code into the process
- Hooking dynamically loaded libraries
- Reading/writing `__DATA` segments
- Interposing symbols (but not inline hooks)

### Alternative Approaches Considered

1. **fishhook** - Symbol interposition library
   - Only works for dynamically linked symbols
   - BG3's internal functions are not exported

2. **Memory scanning** - Find pointers at runtime
   - Implemented as fallback
   - Less reliable than direct address

3. **Osiris callbacks** - Use scripting system
   - Would require finding a callback that receives EntityWorld
   - libOsiris functions don't directly expose EntityWorld

4. **Direct address lookup** (CHOSEN)
   - Most reliable approach
   - Uses Ghidra-discovered global pointer address
   - No hooking or memory modification required

## Files Modified

- `src/entity/entity_system.c` - Updated with direct memory read approach
- `ghidra/scripts/find_sdm_global.py` - Script that helped discover the address
- `ghidra/scripts/analyze_eocserver_startup.py` - Found symbol `__ZN3esv9EocServer5m_ptrE`

## References

- [Apple Hardened Runtime Documentation](https://developer.apple.com/documentation/security/hardened_runtime)
- [Code Signing Requirements](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Introduction/Introduction.html)
- [Dobby Hooking Framework](https://github.com/jmpews/Dobby)
- [Windows BG3SE Reference](https://github.com/Norbyte/bg3se)
