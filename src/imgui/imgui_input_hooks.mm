/**
 * @file imgui_input_hooks.mm
 * @brief Input event hooks for ImGui overlay
 *
 * Hooks NSView event methods to capture keyboard and mouse input
 * and forward them to ImGui.
 */

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <objc/runtime.h>

#include "imgui_input_hooks.h"
#include "imgui_metal_backend.h"
#include "logging.h"

// ============================================================================
// Static State
// ============================================================================

static struct {
    bool initialized;
    NSView *gameView;

    // Original method implementations
    IMP original_keyDown;
    IMP original_keyUp;
    IMP original_flagsChanged;
    IMP original_mouseDown;
    IMP original_mouseUp;
    IMP original_rightMouseDown;
    IMP original_rightMouseUp;
    IMP original_mouseMoved;
    IMP original_mouseDragged;
    IMP original_scrollWheel;

    // Class we hooked
    Class viewClass;
} s_input = {0};

// ============================================================================
// Hooked Methods
// ============================================================================

static void hooked_keyDown(id self, SEL _cmd, NSEvent *event) {
    uint16_t keycode = [event keyCode];
    uint32_t modifiers = (uint32_t)[event modifierFlags];

    // Forward to ImGui
    bool consumed = imgui_metal_process_key(keycode, true, modifiers);

    // Also handle character input for text fields
    if (imgui_metal_is_capturing_input()) {
        NSString *chars = [event characters];
        for (NSUInteger i = 0; i < [chars length]; i++) {
            unichar c = [chars characterAtIndex:i];
            if (c >= 32 && c != 127) {  // Printable characters
                imgui_metal_process_char(c);
            }
        }
    }

    // Pass to game if not consumed
    if (!consumed && s_input.original_keyDown) {
        ((void(*)(id, SEL, NSEvent*))s_input.original_keyDown)(self, _cmd, event);
    }
}

static void hooked_keyUp(id self, SEL _cmd, NSEvent *event) {
    uint16_t keycode = [event keyCode];
    uint32_t modifiers = (uint32_t)[event modifierFlags];

    bool consumed = imgui_metal_process_key(keycode, false, modifiers);

    if (!consumed && s_input.original_keyUp) {
        ((void(*)(id, SEL, NSEvent*))s_input.original_keyUp)(self, _cmd, event);
    }
}

static void hooked_flagsChanged(id self, SEL _cmd, NSEvent *event) {
    // Modifier keys (shift, ctrl, alt, cmd) come through flagsChanged
    uint16_t keycode = [event keyCode];
    uint32_t modifiers = (uint32_t)[event modifierFlags];

    // Determine if key is pressed or released based on modifier flags
    bool down = false;
    switch (keycode) {
        case 0x38: down = (modifiers & NSEventModifierFlagShift) != 0; break;      // Left Shift
        case 0x3C: down = (modifiers & NSEventModifierFlagShift) != 0; break;      // Right Shift
        case 0x3B: down = (modifiers & NSEventModifierFlagControl) != 0; break;    // Left Ctrl
        case 0x3E: down = (modifiers & NSEventModifierFlagControl) != 0; break;    // Right Ctrl
        case 0x3A: down = (modifiers & NSEventModifierFlagOption) != 0; break;     // Left Alt
        case 0x3D: down = (modifiers & NSEventModifierFlagOption) != 0; break;     // Right Alt
        case 0x37: down = (modifiers & NSEventModifierFlagCommand) != 0; break;    // Left Cmd
        case 0x36: down = (modifiers & NSEventModifierFlagCommand) != 0; break;    // Right Cmd
        default: break;
    }

    imgui_metal_process_key(keycode, down, modifiers);

    // Always pass modifier changes to game
    if (s_input.original_flagsChanged) {
        ((void(*)(id, SEL, NSEvent*))s_input.original_flagsChanged)(self, _cmd, event);
    }
}

static void hooked_mouseDown(id self, SEL _cmd, NSEvent *event) {
    NSPoint loc = [event locationInWindow];
    NSView *view = (NSView *)self;
    NSPoint viewLoc = [view convertPoint:loc fromView:nil];

    // Flip Y coordinate (NSView origin is bottom-left, ImGui is top-left)
    float x = viewLoc.x;
    float y = view.bounds.size.height - viewLoc.y;

    // Use _direct since coords are already in ImGui space
    bool consumed = imgui_metal_process_mouse_direct(x, y, 0, true);  // Button 0 = left

    if (!consumed && s_input.original_mouseDown) {
        ((void(*)(id, SEL, NSEvent*))s_input.original_mouseDown)(self, _cmd, event);
    }
}

static void hooked_mouseUp(id self, SEL _cmd, NSEvent *event) {
    NSPoint loc = [event locationInWindow];
    NSView *view = (NSView *)self;
    NSPoint viewLoc = [view convertPoint:loc fromView:nil];

    float x = viewLoc.x;
    float y = view.bounds.size.height - viewLoc.y;

    bool consumed = imgui_metal_process_mouse_direct(x, y, 0, false);

    if (!consumed && s_input.original_mouseUp) {
        ((void(*)(id, SEL, NSEvent*))s_input.original_mouseUp)(self, _cmd, event);
    }
}

static void hooked_rightMouseDown(id self, SEL _cmd, NSEvent *event) {
    NSPoint loc = [event locationInWindow];
    NSView *view = (NSView *)self;
    NSPoint viewLoc = [view convertPoint:loc fromView:nil];

    float x = viewLoc.x;
    float y = view.bounds.size.height - viewLoc.y;

    bool consumed = imgui_metal_process_mouse_direct(x, y, 1, true);  // Button 1 = right

    if (!consumed && s_input.original_rightMouseDown) {
        ((void(*)(id, SEL, NSEvent*))s_input.original_rightMouseDown)(self, _cmd, event);
    }
}

static void hooked_rightMouseUp(id self, SEL _cmd, NSEvent *event) {
    NSPoint loc = [event locationInWindow];
    NSView *view = (NSView *)self;
    NSPoint viewLoc = [view convertPoint:loc fromView:nil];

    float x = viewLoc.x;
    float y = view.bounds.size.height - viewLoc.y;

    bool consumed = imgui_metal_process_mouse_direct(x, y, 1, false);

    if (!consumed && s_input.original_rightMouseUp) {
        ((void(*)(id, SEL, NSEvent*))s_input.original_rightMouseUp)(self, _cmd, event);
    }
}

static void hooked_mouseMoved(id self, SEL _cmd, NSEvent *event) {
    NSPoint loc = [event locationInWindow];
    NSView *view = (NSView *)self;
    NSPoint viewLoc = [view convertPoint:loc fromView:nil];

    float x = viewLoc.x;
    float y = view.bounds.size.height - viewLoc.y;

    imgui_metal_process_mouse_move_direct(x, y);

    // Always pass mouse movement to game
    if (s_input.original_mouseMoved) {
        ((void(*)(id, SEL, NSEvent*))s_input.original_mouseMoved)(self, _cmd, event);
    }
}

static void hooked_mouseDragged(id self, SEL _cmd, NSEvent *event) {
    NSPoint loc = [event locationInWindow];
    NSView *view = (NSView *)self;
    NSPoint viewLoc = [view convertPoint:loc fromView:nil];

    float x = viewLoc.x;
    float y = view.bounds.size.height - viewLoc.y;

    imgui_metal_process_mouse_move_direct(x, y);

    if (s_input.original_mouseDragged) {
        ((void(*)(id, SEL, NSEvent*))s_input.original_mouseDragged)(self, _cmd, event);
    }
}

static void hooked_scrollWheel(id self, SEL _cmd, NSEvent *event) {
    float dx = [event scrollingDeltaX];
    float dy = [event scrollingDeltaY];

    // Normalize for non-pixel scroll events
    if (![event hasPreciseScrollingDeltas]) {
        dx *= 10.0f;
        dy *= 10.0f;
    }

    imgui_metal_process_scroll(dx * 0.1f, dy * 0.1f);

    // Always pass scroll to game (ImGui doesn't consume scroll events exclusively)
    if (s_input.original_scrollWheel) {
        ((void(*)(id, SEL, NSEvent*))s_input.original_scrollWheel)(self, _cmd, event);
    }
}

// ============================================================================
// Hook Installation Helper
// ============================================================================

static IMP hook_method(Class cls, SEL selector, IMP newImpl) {
    Method method = class_getInstanceMethod(cls, selector);
    if (!method) {
        return NULL;
    }
    return method_setImplementation(method, newImpl);
}

// ============================================================================
// Public API
// ============================================================================

bool imgui_input_hooks_init(void *nsview) {
    if (s_input.initialized) {
        return true;
    }

    if (!nsview) {
        LOG_IMGUI_ERROR("Cannot init input hooks: view is NULL");
        return false;
    }

    NSView *view = (__bridge NSView *)nsview;
    s_input.gameView = view;
    s_input.viewClass = object_getClass(view);

    LOG_IMGUI_INFO("Installing input hooks on %s", class_getName(s_input.viewClass));

    // Hook keyboard events
    s_input.original_keyDown = hook_method(s_input.viewClass, @selector(keyDown:), (IMP)hooked_keyDown);
    s_input.original_keyUp = hook_method(s_input.viewClass, @selector(keyUp:), (IMP)hooked_keyUp);
    s_input.original_flagsChanged = hook_method(s_input.viewClass, @selector(flagsChanged:), (IMP)hooked_flagsChanged);

    // Hook mouse events
    s_input.original_mouseDown = hook_method(s_input.viewClass, @selector(mouseDown:), (IMP)hooked_mouseDown);
    s_input.original_mouseUp = hook_method(s_input.viewClass, @selector(mouseUp:), (IMP)hooked_mouseUp);
    s_input.original_rightMouseDown = hook_method(s_input.viewClass, @selector(rightMouseDown:), (IMP)hooked_rightMouseDown);
    s_input.original_rightMouseUp = hook_method(s_input.viewClass, @selector(rightMouseUp:), (IMP)hooked_rightMouseUp);
    s_input.original_mouseMoved = hook_method(s_input.viewClass, @selector(mouseMoved:), (IMP)hooked_mouseMoved);
    s_input.original_mouseDragged = hook_method(s_input.viewClass, @selector(mouseDragged:), (IMP)hooked_mouseDragged);
    s_input.original_scrollWheel = hook_method(s_input.viewClass, @selector(scrollWheel:), (IMP)hooked_scrollWheel);

    s_input.initialized = true;
    LOG_IMGUI_INFO("Input hooks installed successfully");

    return true;
}

void imgui_input_hooks_shutdown(void) {
    if (!s_input.initialized || !s_input.viewClass) {
        return;
    }

    LOG_IMGUI_INFO("Removing input hooks...");

    // Restore original methods
    if (s_input.original_keyDown) {
        hook_method(s_input.viewClass, @selector(keyDown:), s_input.original_keyDown);
    }
    if (s_input.original_keyUp) {
        hook_method(s_input.viewClass, @selector(keyUp:), s_input.original_keyUp);
    }
    if (s_input.original_flagsChanged) {
        hook_method(s_input.viewClass, @selector(flagsChanged:), s_input.original_flagsChanged);
    }
    if (s_input.original_mouseDown) {
        hook_method(s_input.viewClass, @selector(mouseDown:), s_input.original_mouseDown);
    }
    if (s_input.original_mouseUp) {
        hook_method(s_input.viewClass, @selector(mouseUp:), s_input.original_mouseUp);
    }
    if (s_input.original_rightMouseDown) {
        hook_method(s_input.viewClass, @selector(rightMouseDown:), s_input.original_rightMouseDown);
    }
    if (s_input.original_rightMouseUp) {
        hook_method(s_input.viewClass, @selector(rightMouseUp:), s_input.original_rightMouseUp);
    }
    if (s_input.original_mouseMoved) {
        hook_method(s_input.viewClass, @selector(mouseMoved:), s_input.original_mouseMoved);
    }
    if (s_input.original_mouseDragged) {
        hook_method(s_input.viewClass, @selector(mouseDragged:), s_input.original_mouseDragged);
    }
    if (s_input.original_scrollWheel) {
        hook_method(s_input.viewClass, @selector(scrollWheel:), s_input.original_scrollWheel);
    }

    memset(&s_input, 0, sizeof(s_input));
    LOG_IMGUI_INFO("Input hooks removed");
}
