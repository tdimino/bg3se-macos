# Architecture

## Injection Method
- `DYLD_INSERT_LIBRARIES` loads dylib before game starts
- Dobby framework for inline function hooking (ARM64 + x86_64 universal)
- Hooks into libOsiris.dylib for Osiris scripting integration

## Module Structure
```
src/
├── core/           # Logging, version info
├── entity/         # Entity Component System (modular)
│   ├── entity_system.c/h  # Core ECS, Lua bindings
│   ├── guid_lookup.c/h    # GUID parsing, HashMap operations
│   └── arm64_call.c/h     # ARM64 ABI wrappers (x8 indirect return)
├── hooks/          # Legacy hook stubs (actual hooks in main.c)
├── imgui/          # Dear ImGui overlay system
│   ├── imgui_metal_backend.mm  # Metal rendering, coord conversion
│   ├── imgui_input_hooks.mm    # NSView method swizzling
│   └── lua_imgui.c             # Ext.IMGUI Lua bindings
├── injector/       # Main injection logic (main.c)
├── input/          # System-level input capture
│   └── input_hooks.m           # CGEventTap for keyboard/mouse
├── lua/            # Lua API modules (lua_ext, lua_json, lua_osiris, lua_stats, lua_events, lua_logging)
├── mod/            # Mod detection and loading
├── osiris/         # Osiris types, functions, pattern scanning
├── pak/            # LSPK v18 PAK file reading
└── stats/          # RPGStats system access (stats_manager)
```

## Key Files
- `src/injector/main.c` - Core injection, Dobby hooks, Osi.* namespace, Lua state
- `src/mod/mod_loader.c` - Mod detection from modsettings.lsx, PAK loading
- `src/lua/lua_*.c` - Ext.* API implementations
- `src/stats/stats_manager.c` - RPGStats global access, stat property resolution
- `ghidra/offsets/` - Modular offset documentation

## Modular Design Pattern

Each subsystem is self-contained:
- **Header file** (`.h`) - Public API declarations, constants, type definitions
- **Source file** (`.c`) - Implementation with static (private) helpers
- **Minimal coupling** - Modules communicate through well-defined interfaces

```c
// module.h - Public interface
#ifndef MODULE_H
#define MODULE_H
void module_init(void);
int module_get_count(void);
#endif

// module.c - Implementation
#include "module.h"
static int item_count = 0;  // Private state
void module_init(void) { ... }
```

### When to Extract from main.c
1. Code exceeds ~100 lines with related functionality
2. State (static variables) can be isolated
3. Multiple source files need the functionality

## Platform Notes
- Game binary is ARM64 on Apple Silicon, Rosetta for Intel
- libOsiris.dylib contains the Osiris scripting engine
- Some symbols stripped - pattern scanning is the fallback
- EntityWorld/EoCServer singletons not exported - must capture via hooks
- **BG3 macOS uses native Cocoa/AppKit, NOT SDL** (unlike Windows)

## ImGui Overlay System

The debug overlay uses Dear ImGui with Metal rendering and CGEventTap input.

### Key Difference from Windows BG3SE
- **Windows**: Hooks `SDL_PollEvent` via Detours, uses `ImGui_ImplSDL2`
- **macOS**: Uses CGEventTap + NSView swizzling, uses `ImGui_ImplOSX` + `ImGui_ImplMetal`

### Input Architecture
```
CGEventTap (system-level)
    │
    ├── Keyboard events → F11 toggle, key forwarding
    │
    └── Mouse events → Quartz screen coords
                            │
                            ▼
                   Cocoa Coordinate Conversion
                   (4-step: CG → Screen → Window → View)
                            │
                            ▼
                   ImGui Input API
                   (AddMousePosEvent, AddMouseButtonEvent)
```

### Coordinate Conversion (CGEventTap → ImGui)
CGEventTap provides Quartz coordinates (origin at top-left of main display).
Must convert through Cocoa APIs:
1. CG (top-left) → Cocoa screen (bottom-left): `screenHeight - y`
2. Screen → Window: `convertPointFromScreen:`
3. Window → View: `convertPoint:fromView:`
4. Flip Y if view not flipped: `viewHeight - y`

### Key Files
- `src/imgui/imgui_metal_backend.mm` - Metal rendering, coordinate conversion
- `src/imgui/imgui_input_hooks.mm` - NSView method swizzling (fallback)
- `src/input/input_hooks.m` - CGEventTap for keyboard/mouse
- `lib/imgui/backends/imgui_impl_osx.mm` - Official ImGui OSX backend

## ARM64 ABI Critical Pattern

**Large struct returns (>16 bytes) require x8 indirect return:**

Functions returning structs larger than 16 bytes on ARM64 use indirect return via x8:

1. Caller allocates buffer for return value
2. Caller passes buffer address in x8 before call
3. Callee writes result to buffer
4. Caller reads from buffer

Example: `TryGetSingleton<T>` returns 64-byte `ls::Result`:

```c
typedef struct __attribute__((aligned(16))) {
    void* value;           // 0x00: Result on success
    uint64_t reserved[5];  // 0x08-0x2F
    uint8_t has_error;     // 0x30: Error flag
    uint8_t _pad[15];
} LsResult;

// Correct ARM64 call with x8
void* call_with_x8_buffer(void* fn, void* arg) {
    LsResult result = {0};
    result.has_error = 1;
    __asm__ volatile (
        "mov x8, %[buf]\n"
        "mov x0, %[arg]\n"
        "blr %[fn]\n"
        : "+m"(result)
        : [buf] "r"(&result), [arg] "r"(arg), [fn] "r"(fn)
        : "x0", "x1", "x8", "x9", "x10", "x11", "x12", "x13",
          "x14", "x15", "x16", "x17", "x19", "x20", "x21",
          "x22", "x23", "x24", "x25", "x26", "x30", "memory"
    );
    return (result.has_error == 0) ? result.value : NULL;
}
```

See `src/entity/arm64_call.c` for implementation.
