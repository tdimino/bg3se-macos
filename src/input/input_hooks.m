/**
 * input_hooks.m - CGEventTap for Input Capture
 *
 * Uses Core Graphics event tap to intercept keyboard events
 * system-wide. This works with SDL-based games like BG3 that
 * don't use standard Cocoa event handling.
 *
 * Note: Requires Accessibility permissions on macOS.
 */

#import <AppKit/AppKit.h>
#import <Carbon/Carbon.h>
#import <pthread.h>

#include "input.h"
#include "../core/logging.h"
#include "../lua/lua_events.h"
#include "../imgui/imgui_metal_backend.h"

// ============================================================================
// Static State
// ============================================================================

static bool s_initialized = false;
static lua_State *s_lua_state = NULL;

// Key state tracking (256 possible key codes)
static bool s_key_states[256] = {0};
static uint32_t s_current_modifiers = 0;

// Hotkey registry
#define MAX_HOTKEYS 64
static Hotkey s_hotkeys[MAX_HOTKEYS];
static int s_hotkey_count = 0;
static int s_next_hotkey_handle = 1;

// CGEventTap
static CFMachPortRef s_event_tap = NULL;
static CFRunLoopSourceRef s_run_loop_source = NULL;

// ============================================================================
// Thread-safe Key Event Queue (drained from Lua-owning tick thread)
// ============================================================================

#define INPUT_EVENT_QUEUE_CAPACITY 256

typedef struct {
    int keyCode;
    bool pressed;
    int modifiers;
    char character[8];
} QueuedKeyEvent;

static pthread_mutex_t s_event_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static QueuedKeyEvent s_event_queue[INPUT_EVENT_QUEUE_CAPACITY];
static uint32_t s_event_queue_head = 0;
static uint32_t s_event_queue_tail = 0;

/**
 * Enqueue a key event for later Lua dispatch.
 */
static void enqueue_key_event(int keyCode, bool pressed, int modifiers, const char *character) {
    pthread_mutex_lock(&s_event_queue_mutex);

    uint32_t next_tail = (s_event_queue_tail + 1) % INPUT_EVENT_QUEUE_CAPACITY;
    if (next_tail == s_event_queue_head) {
        // Queue full: drop oldest to preserve most recent input
        s_event_queue_head = (s_event_queue_head + 1) % INPUT_EVENT_QUEUE_CAPACITY;
    }

    QueuedKeyEvent *dst = &s_event_queue[s_event_queue_tail];
    dst->keyCode = keyCode;
    dst->pressed = pressed;
    dst->modifiers = modifiers;
    dst->character[0] = '\0';
    if (character && character[0]) {
        strncpy(dst->character, character, sizeof(dst->character) - 1);
        dst->character[sizeof(dst->character) - 1] = '\0';
    }

    s_event_queue_tail = next_tail;
    pthread_mutex_unlock(&s_event_queue_mutex);
}

/**
 * Drain queued key events and fire Lua events on the calling thread.
 */
void input_poll(lua_State *L) {
    if (!L) return;
    if (!s_initialized) return;

    // Ensure we use the same Lua state pointer the rest of the system expects.
    // This also avoids dispatching events if Lua was torn down.
    s_lua_state = L;

    // Drain without holding the lock during Lua calls.
    while (1) {
        QueuedKeyEvent ev;
        bool have_event = false;

        pthread_mutex_lock(&s_event_queue_mutex);
        if (s_event_queue_head != s_event_queue_tail) {
            ev = s_event_queue[s_event_queue_head];
            s_event_queue_head = (s_event_queue_head + 1) % INPUT_EVENT_QUEUE_CAPACITY;
            have_event = true;
        }
        pthread_mutex_unlock(&s_event_queue_mutex);

        if (!have_event) break;

        events_fire_key_input(L, ev.keyCode, ev.pressed, ev.modifiers, ev.character);
    }
}

// ============================================================================
// Forward Declarations
// ============================================================================

static CGEventRef event_tap_callback(CGEventTapProxy proxy, CGEventType type,
                                     CGEventRef event, void *refcon);
static bool check_hotkeys(uint16_t keyCode, uint32_t modifiers);
static uint32_t convert_cg_modifiers(CGEventFlags flags);

// ============================================================================
// CGEventTap Callback
// ============================================================================

static CGEventRef event_tap_callback(CGEventTapProxy proxy, CGEventType type,
                                     CGEventRef event, void *refcon) {
    (void)proxy;
    (void)refcon;

    // Handle tap being disabled (happens if we take too long)
    if (type == kCGEventTapDisabledByTimeout ||
        type == kCGEventTapDisabledByUserInput) {
        if (s_event_tap) {
            CGEventTapEnable(s_event_tap, true);
        }
        return event;
    }

    // Forward mouse events to ImGui
    // Note: SDL-based games may not trigger NSEvent local monitors, so we
    // forward events directly from CGEventTap
    CGPoint screenLoc = CGEventGetLocation(event);

    switch (type) {
        case kCGEventLeftMouseDown:
            imgui_metal_process_mouse((float)screenLoc.x, (float)screenLoc.y, 0, true);
            break;
        case kCGEventLeftMouseUp:
            imgui_metal_process_mouse((float)screenLoc.x, (float)screenLoc.y, 0, false);
            break;
        case kCGEventRightMouseDown:
            imgui_metal_process_mouse((float)screenLoc.x, (float)screenLoc.y, 1, true);
            break;
        case kCGEventRightMouseUp:
            imgui_metal_process_mouse((float)screenLoc.x, (float)screenLoc.y, 1, false);
            break;
        case kCGEventMouseMoved:
        case kCGEventLeftMouseDragged:
        case kCGEventRightMouseDragged:
            // CGEventTap is the ONLY reliable input source for SDL games
            // NSView swizzling doesn't receive events from SDL
            imgui_metal_process_mouse_move((float)screenLoc.x, (float)screenLoc.y);
            break;
        case kCGEventScrollWheel: {
            double deltaX = CGEventGetDoubleValueField(event, kCGScrollWheelEventDeltaAxis2);
            double deltaY = CGEventGetDoubleValueField(event, kCGScrollWheelEventDeltaAxis1);
            imgui_metal_process_scroll((float)deltaX, (float)deltaY);
            break;
        }
        default:
            break;
    }

    // Only handle keyboard events beyond this point
    if (type != kCGEventKeyDown && type != kCGEventKeyUp &&
        type != kCGEventFlagsChanged) {
        return event;
    }

    uint16_t keyCode = (uint16_t)CGEventGetIntegerValueField(event, kCGKeyboardEventKeycode);
    CGEventFlags cgFlags = CGEventGetFlags(event);
    uint32_t modifiers = convert_cg_modifiers(cgFlags);
    bool isDown = (type == kCGEventKeyDown);
    bool isUp = (type == kCGEventKeyUp);
    bool isFlagsChanged = (type == kCGEventFlagsChanged);

    // Update modifier state
    s_current_modifiers = modifiers;

    // Handle flags changed (modifier keys)
    if (isFlagsChanged) {
        // Determine if this modifier key went down or up
        bool wasDown = s_key_states[keyCode];

        // Check the specific modifier bit for this key
        bool nowDown = false;
        switch (keyCode) {
            case kVK_Shift:
            case kVK_RightShift:
                nowDown = (cgFlags & kCGEventFlagMaskShift) != 0;
                break;
            case kVK_Control:
            case kVK_RightControl:
                nowDown = (cgFlags & kCGEventFlagMaskControl) != 0;
                break;
            case kVK_Option:
            case kVK_RightOption:
                nowDown = (cgFlags & kCGEventFlagMaskAlternate) != 0;
                break;
            case kVK_Command:
            case kVK_RightCommand:
                nowDown = (cgFlags & kCGEventFlagMaskCommand) != 0;
                break;
            case kVK_CapsLock:
                nowDown = (cgFlags & kCGEventFlagMaskAlphaShift) != 0;
                break;
            default:
                return event;
        }

        if (nowDown != wasDown) {
            isDown = nowDown;
            isUp = !nowDown;
            s_key_states[keyCode] = nowDown;
        } else {
            return event;
        }
    }

    // Update key state
    if (keyCode < 256) {
        if (isDown) {
            s_key_states[keyCode] = true;
        } else if (isUp) {
            s_key_states[keyCode] = false;
        }
    }

    // Forward keyboard events to ImGui
    // Note: In listen-only mode, we can't consume events - they always pass to game
    imgui_metal_process_key(keyCode, isDown, modifiers);

    // Check for hotkeys on key down
    if (isDown && check_hotkeys(keyCode, modifiers)) {
        // Hotkey was triggered - still let event pass through
    }

    // Get character
    UniChar chars[4] = {0};
    UniCharCount actualLength = 0;
    CGEventKeyboardGetUnicodeString(event, 4, &actualLength, chars);

    char charStr[8] = {0};
    if (actualLength > 0 && chars[0] >= 32 && chars[0] < 127) {
        charStr[0] = (char)chars[0];
    }

    // Fire Lua KeyInput event
    if (s_lua_state && (isDown || isUp)) {
        // IMPORTANT: Do not call into Lua from the event tap callback.
        // Queue the event and let the Lua-owning tick thread drain it.
        enqueue_key_event((int)keyCode, isDown, (int)modifiers, charStr);
    }

    return event;
}

// ============================================================================
// Helper: Convert CG modifier flags to our format
// ============================================================================

static uint32_t convert_cg_modifiers(CGEventFlags flags) {
    uint32_t mods = INPUT_MOD_NONE;

    if (flags & kCGEventFlagMaskShift)     mods |= INPUT_MOD_SHIFT;
    if (flags & kCGEventFlagMaskControl)   mods |= INPUT_MOD_CTRL;
    if (flags & kCGEventFlagMaskAlternate) mods |= INPUT_MOD_ALT;
    if (flags & kCGEventFlagMaskCommand)   mods |= INPUT_MOD_CMD;
    if (flags & kCGEventFlagMaskAlphaShift) mods |= INPUT_MOD_CAPS;

    return mods;
}

// ============================================================================
// Helper: Check and fire hotkeys
// ============================================================================

static bool check_hotkeys(uint16_t keyCode, uint32_t modifiers) {
    for (int i = 0; i < s_hotkey_count; i++) {
        Hotkey *hk = &s_hotkeys[i];

        if (hk->keyCode != keyCode) continue;

        // Check modifiers (mask out caps lock for comparison)
        uint32_t hkMods = hk->modifiers & ~INPUT_MOD_CAPS;
        uint32_t curMods = modifiers & ~INPUT_MOD_CAPS;

        if (hkMods != curMods) {
            continue;
        }

        // Match found!
        LOG_INPUT_INFO("Hotkey triggered: %s", hk->name ? hk->name : "(unnamed)");

        if (hk->callback) {
            hk->callback(hk->userData);
        }

        return true;
    }
    return false;
}

// ============================================================================
// Public API - Initialization
// ============================================================================

bool input_init(void) {
    if (s_initialized) {
        return true;
    }

    LOG_INPUT_INFO("Initializing input system (CGEventTap)...");

    // Create event tap for keyboard and mouse events
    CGEventMask eventMask = (1 << kCGEventKeyDown) |
                            (1 << kCGEventKeyUp) |
                            (1 << kCGEventFlagsChanged) |
                            (1 << kCGEventLeftMouseDown) |
                            (1 << kCGEventLeftMouseUp) |
                            (1 << kCGEventRightMouseDown) |
                            (1 << kCGEventRightMouseUp) |
                            (1 << kCGEventMouseMoved) |
                            (1 << kCGEventLeftMouseDragged) |
                            (1 << kCGEventRightMouseDragged) |
                            (1 << kCGEventScrollWheel);

    // Note: Using kCGEventTapOptionListenOnly - doesn't require Accessibility permissions
    // but means we can't consume events (F10 will also go to game)
    // TODO: Consider using a different hotkey that doesn't conflict with game
    s_event_tap = CGEventTapCreate(kCGSessionEventTap,
                                   kCGHeadInsertEventTap,
                                   kCGEventTapOptionListenOnly,
                                   eventMask,
                                   event_tap_callback,
                                   NULL);

    if (!s_event_tap) {
        LOG_INPUT_ERROR("Failed to create CGEventTap. Check Accessibility permissions.");
        LOG_INPUT_ERROR("System Preferences > Security & Privacy > Privacy > Accessibility");
        return false;
    }

    // Create run loop source
    s_run_loop_source = CFMachPortCreateRunLoopSource(kCFAllocatorDefault,
                                                       s_event_tap, 0);
    if (!s_run_loop_source) {
        LOG_INPUT_ERROR("Failed to create run loop source");
        CFRelease(s_event_tap);
        s_event_tap = NULL;
        return false;
    }

    // Add to main run loop
    CFRunLoopAddSource(CFRunLoopGetMain(), s_run_loop_source, kCFRunLoopCommonModes);

    // Enable the tap
    CGEventTapEnable(s_event_tap, true);

    s_initialized = true;
    LOG_INPUT_INFO("Input system initialized (CGEventTap active)");

    return true;
}

void input_shutdown(void) {
    if (!s_initialized) {
        return;
    }

    LOG_INPUT_INFO("Shutting down input system...");

    // Remove from run loop and release
    if (s_run_loop_source) {
        CFRunLoopRemoveSource(CFRunLoopGetMain(), s_run_loop_source, kCFRunLoopCommonModes);
        CFRelease(s_run_loop_source);
        s_run_loop_source = NULL;
    }

    if (s_event_tap) {
        CGEventTapEnable(s_event_tap, false);
        CFRelease(s_event_tap);
        s_event_tap = NULL;
    }

    // Clear hotkeys
    for (int i = 0; i < s_hotkey_count; i++) {
        if (s_hotkeys[i].name) {
            free((void *)s_hotkeys[i].name);
        }
    }
    s_hotkey_count = 0;
    s_lua_state = NULL;

    s_initialized = false;
    LOG_INPUT_INFO("Input system shut down");
}

bool input_is_initialized(void) {
    return s_initialized;
}

// ============================================================================
// Public API - Hotkey Registration
// ============================================================================

int input_register_hotkey(uint16_t keyCode, uint32_t modifiers,
                          HotkeyCallback callback, void *userData,
                          const char *name) {
    if (s_hotkey_count >= MAX_HOTKEYS) {
        LOG_INPUT_ERROR("Hotkey registry full (max %d)", MAX_HOTKEYS);
        return 0;
    }

    int handle = s_next_hotkey_handle++;
    Hotkey *hk = &s_hotkeys[s_hotkey_count++];
    hk->keyCode = keyCode;
    hk->modifiers = modifiers;
    hk->callback = callback;
    hk->userData = userData;
    hk->name = name ? strdup(name) : NULL;

    LOG_INPUT_INFO("Registered hotkey: %s (key=%d, mods=0x%x) -> handle %d",
             name ? name : "(unnamed)", keyCode, modifiers, handle);

    return handle;
}

void input_unregister_hotkey(int handle) {
    // TODO: Implement proper removal by handle
    for (int i = 0; i < s_hotkey_count; i++) {
        // For now, we don't track handles per-hotkey
        // A more robust implementation would add a handle field to Hotkey
    }
    LOG_INPUT_DEBUG("Unregister hotkey %d (not fully implemented)", handle);
}

void input_clear_hotkeys(void) {
    for (int i = 0; i < s_hotkey_count; i++) {
        if (s_hotkeys[i].name) {
            free((void *)s_hotkeys[i].name);
        }
    }
    s_hotkey_count = 0;
    LOG_INPUT_INFO("Cleared all hotkeys");
}

// ============================================================================
// Public API - Key State
// ============================================================================

bool input_is_key_pressed(uint16_t keyCode) {
    if (keyCode >= 256) return false;
    return s_key_states[keyCode];
}

uint32_t input_get_modifiers(void) {
    return s_current_modifiers;
}

// ============================================================================
// Public API - Key Injection
// ============================================================================

void input_inject_key_down(uint16_t keyCode, uint32_t modifiers) {
    CGEventRef event = CGEventCreateKeyboardEvent(NULL, keyCode, true);
    if (!event) {
        LOG_INPUT_ERROR("Failed to create key down event");
        return;
    }

    // Set modifier flags
    CGEventFlags flags = 0;
    if (modifiers & INPUT_MOD_SHIFT) flags |= kCGEventFlagMaskShift;
    if (modifiers & INPUT_MOD_CTRL)  flags |= kCGEventFlagMaskControl;
    if (modifiers & INPUT_MOD_ALT)   flags |= kCGEventFlagMaskAlternate;
    if (modifiers & INPUT_MOD_CMD)   flags |= kCGEventFlagMaskCommand;

    CGEventSetFlags(event, flags);
    CGEventPost(kCGHIDEventTap, event);
    CFRelease(event);

    LOG_INPUT_DEBUG("Injected key down: code=%d mods=0x%x", keyCode, modifiers);
}

void input_inject_key_up(uint16_t keyCode, uint32_t modifiers) {
    CGEventRef event = CGEventCreateKeyboardEvent(NULL, keyCode, false);
    if (!event) {
        LOG_INPUT_ERROR("Failed to create key up event");
        return;
    }

    // Set modifier flags
    CGEventFlags flags = 0;
    if (modifiers & INPUT_MOD_SHIFT) flags |= kCGEventFlagMaskShift;
    if (modifiers & INPUT_MOD_CTRL)  flags |= kCGEventFlagMaskControl;
    if (modifiers & INPUT_MOD_ALT)   flags |= kCGEventFlagMaskAlternate;
    if (modifiers & INPUT_MOD_CMD)   flags |= kCGEventFlagMaskCommand;

    CGEventSetFlags(event, flags);
    CGEventPost(kCGHIDEventTap, event);
    CFRelease(event);

    LOG_INPUT_DEBUG("Injected key up: code=%d mods=0x%x", keyCode, modifiers);
}

void input_inject_key_press(uint16_t keyCode, uint32_t modifiers) {
    input_inject_key_down(keyCode, modifiers);
    usleep(10000);  // 10ms delay
    input_inject_key_up(keyCode, modifiers);
}

// ============================================================================
// Lua State Management
// ============================================================================

void input_set_lua_state(lua_State *L) {
    s_lua_state = L;
}
