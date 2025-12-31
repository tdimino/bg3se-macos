# Fix ImGui Mouse Input for macOS Cocoa Games

## Problem Summary
Mouse clicks don't work on ImGui buttons because `io.MousePos` was not being updated correctly.
The coordinate conversion from CGEventTap screen coordinates to ImGui view coordinates was broken.

## Key Discovery: BG3 macOS Uses Native Cocoa, NOT SDL

**Critical finding:** Unlike Windows BG3 which uses SDL, the macOS port uses native Cocoa/AppKit:
- No SDL framework in the app bundle
- Links against Cocoa.framework, AppKit.framework, Metal.framework
- The Windows BG3SE approach of hooking `SDL_PollEvent` does NOT apply

This means we need macOS-native input handling via CGEventTap with proper Cocoa coordinate conversion.

## Root Causes (Original Issues)

1. **Broken fullscreen coordinate conversion** - We had a special case for fullscreen that passed CG coords directly, but this doesn't account for window position or title bars
2. **Click handler didn't update position** - CGEventTap clicks weren't updating mouse position
3. **Multiple input sources conflicting** - CGEventTap, NSView swizzling, and ImGui_ImplOSX monitor could overwrite each other

## Solution: Proper Cocoa Coordinate Conversion

CGEventTap provides system-level mouse events with Quartz coordinates (origin at top-left of main display).
These must be converted to ImGui view coordinates using standard Cocoa APIs.

### Coordinate Conversion (4-Step Process)

```cpp
// CGEventGetLocation gives Quartz coords (origin top-left of display) in POINTS
// Step 1: Convert from CG (top-left origin) to Cocoa screen coords (bottom-left origin)
CGFloat mainScreenHeight = [[NSScreen mainScreen] frame].size.height;
float cocoaScreenY = mainScreenHeight - screenY;
NSPoint screenPoint = NSMakePoint(screenX, cocoaScreenY);

// Step 2: Convert from screen coords to window coords
NSPoint windowPoint = [s_state.gameWindow convertPointFromScreen:screenPoint];

// Step 3: Convert from window coords to view coords
windowPoint = [contentView convertPoint:windowPoint fromView:nil];

// Step 4: Flip Y for ImGui (top-left origin) if view uses bottom-left origin
if (![contentView isFlipped]) {
    windowPoint.y = contentView.bounds.size.height - windowPoint.y;
}
```

This works for BOTH fullscreen and windowed modes - no special cases needed.

## Files Modified

### src/imgui/imgui_metal_backend.mm

1. **`convert_screen_to_window()`** - Fixed to use proper 4-step Cocoa coordinate conversion
   - Removed broken fullscreen special case
   - Now uses standard Cocoa APIs for all modes

2. **`imgui_metal_process_mouse()`** - Restored position update
   - Clicks now update mouse position using corrected conversion
   - Both moves and clicks use the same conversion path

### src/input/input_hooks.m

- CGEventTap mouse move handling enabled
- Forwards all mouse events (moves, clicks, drags) to ImGui backend

## Input Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      macOS Event Sources                      │
├─────────────────────────────────────────────────────────────┤
│  CGEventTap (System-level)                                   │
│  - Receives ALL mouse/keyboard events                        │
│  - Works regardless of how game handles events               │
│  - Provides Quartz screen coordinates                        │
├─────────────────────────────────────────────────────────────┤
│  NSView Method Swizzling (App-level)                         │
│  - Hooks mouseDown/mouseUp/mouseMoved on game view          │
│  - Provides window-relative coordinates directly             │
│  - May not receive events if game bypasses NSView methods    │
├─────────────────────────────────────────────────────────────┤
│  ImGui_ImplOSX NSEvent Monitor (App-level)                   │
│  - Uses addLocalMonitorForEventsMatchingMask:               │
│  - Part of official ImGui OSX backend                        │
│  - May not receive events if game polls directly             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   Coordinate Conversion                       │
│  CGEventTap coords → Cocoa Screen → Window → View → ImGui   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                        ImGui Input                            │
│  io.AddMousePosEvent(x, y)                                   │
│  io.AddMouseButtonEvent(button, down)                        │
└─────────────────────────────────────────────────────────────┘
```

## Testing

1. Build: `cd build && cmake --build .`
2. Launch game
3. Press **F11** to show overlay
4. Move mouse - position should update in debug window (not -FLT_MAX)
5. Hover over "Test Button" - should highlight
6. Click button - should register click

## Debug Logging

The coordinate conversion logs every 120th conversion:
```
CoordConvert: CG(x,y) -> Cocoa(x,y) -> View(x,y) [winOrigin, winSize, viewSize]
```

This helps verify the conversion chain is working correctly.

## Comparison: Windows vs macOS BG3SE Input Handling

| Aspect | Windows BG3SE | macOS BG3SE |
|--------|---------------|-------------|
| Game windowing | SDL2 | Native Cocoa |
| Input hook | SDL_PollEvent via Detours | CGEventTap + NSView swizzling |
| ImGui backend | ImGui_ImplSDL2 | ImGui_ImplOSX + ImGui_ImplMetal |
| Coord conversion | SDL provides window coords | Manual CG→Cocoa→View conversion |

## References

- Official ImGui OSX backend: `lib/imgui/backends/imgui_impl_osx.mm`
- ImGui OSX backend improvements PR: https://github.com/ocornut/imgui/pull/4759
- Apple CGEventTap documentation
- Apple Cocoa coordinate system documentation

## Status: IMPLEMENTED

- [x] Fixed coordinate conversion for all window modes
- [x] Restored position update in click handler
- [x] CGEventTap mouse moves enabled
- [ ] Pending user testing to verify fix
