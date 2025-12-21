/**
 * input.h - BG3SE Input System
 *
 * Keyboard and mouse input handling for macOS.
 * Uses NSEvent swizzling to intercept input events.
 *
 * Features:
 * - Keyboard event capture (KeyDown, KeyUp, FlagsChanged)
 * - Mouse button and wheel events
 * - Hotkey registration with modifier support
 * - Lua event dispatch (Ext.Events.KeyInput)
 * - Input injection via CGEventPost
 */

#ifndef INPUT_H
#define INPUT_H

#include <lua.h>
#include <stdbool.h>
#include <stdint.h>

// ============================================================================
// Modifier Flags (compatible with Windows BG3SE)
// ============================================================================

typedef enum {
    INPUT_MOD_NONE    = 0,
    INPUT_MOD_SHIFT   = (1 << 0),
    INPUT_MOD_CTRL    = (1 << 1),
    INPUT_MOD_ALT     = (1 << 2),   // Option key on macOS
    INPUT_MOD_CMD     = (1 << 3),   // Command key (macOS-specific)
    INPUT_MOD_CAPS    = (1 << 4),
} InputModifiers;

// ============================================================================
// Key Event Structure
// ============================================================================

typedef struct {
    uint16_t keyCode;        // macOS virtual key code
    uint16_t scanCode;       // SDL-compatible scan code
    uint32_t modifiers;      // InputModifiers flags
    bool pressed;            // true for KeyDown, false for KeyUp
    bool repeat;             // true if key repeat
    char character[8];       // UTF-8 character (if printable)
} KeyEvent;

// ============================================================================
// Mouse Event Structure
// ============================================================================

typedef struct {
    int button;              // 0=Left, 1=Right, 2=Middle, 3-4=Extra
    bool pressed;            // true for down, false for up
    double x, y;             // Screen coordinates
    uint32_t modifiers;      // InputModifiers flags
} MouseButtonEvent;

typedef struct {
    double deltaX;           // Horizontal scroll
    double deltaY;           // Vertical scroll
    double x, y;             // Cursor position
    uint32_t modifiers;      // InputModifiers flags
} MouseWheelEvent;

// ============================================================================
// Hotkey Callback
// ============================================================================

typedef void (*HotkeyCallback)(void *userData);

typedef struct {
    uint16_t keyCode;        // Virtual key code to match
    uint32_t modifiers;      // Required modifiers
    HotkeyCallback callback;
    void *userData;
    const char *name;        // For debugging
} Hotkey;

// ============================================================================
// Initialization
// ============================================================================

/**
 * Initialize the input system.
 * Sets up NSEvent swizzling to intercept keyboard/mouse events.
 * Must be called after the application run loop starts.
 *
 * @return true on success, false on failure
 */
bool input_init(void);

/**
 * Shutdown the input system.
 * Restores original NSEvent handling.
 */
void input_shutdown(void);

/**
 * Check if input system is initialized.
 */
bool input_is_initialized(void);

// ============================================================================
// Event Dispatch (Thread-safe queue -> single-thread Lua dispatch)
// ============================================================================

/**
 * Drain queued input events and fire corresponding Lua events.
 * Call this from the Lua-owning thread/tick (e.g. Osiris Event hook).
 */
void input_poll(lua_State *L);

// ============================================================================
// Hotkey Registration
// ============================================================================

/**
 * Register a hotkey.
 *
 * @param keyCode   macOS virtual key code (or 0 for any)
 * @param modifiers Required modifier flags
 * @param callback  Function to call when hotkey is pressed
 * @param userData  User data passed to callback
 * @param name      Hotkey name for debugging (copied internally)
 * @return Hotkey handle (>0) on success, 0 on failure
 */
int input_register_hotkey(uint16_t keyCode, uint32_t modifiers,
                          HotkeyCallback callback, void *userData,
                          const char *name);

/**
 * Unregister a hotkey by handle.
 */
void input_unregister_hotkey(int handle);

/**
 * Unregister all hotkeys.
 */
void input_clear_hotkeys(void);

// ============================================================================
// Key State Queries
// ============================================================================

/**
 * Check if a key is currently pressed.
 *
 * @param keyCode macOS virtual key code
 * @return true if key is pressed
 */
bool input_is_key_pressed(uint16_t keyCode);

/**
 * Get current modifier state.
 *
 * @return InputModifiers flags
 */
uint32_t input_get_modifiers(void);

// ============================================================================
// Input Injection
// ============================================================================

/**
 * Inject a key press event (down + up).
 *
 * @param keyCode   macOS virtual key code
 * @param modifiers Modifier flags to apply
 */
void input_inject_key_press(uint16_t keyCode, uint32_t modifiers);

/**
 * Inject a key down event.
 */
void input_inject_key_down(uint16_t keyCode, uint32_t modifiers);

/**
 * Inject a key up event.
 */
void input_inject_key_up(uint16_t keyCode, uint32_t modifiers);

// ============================================================================
// Lua Integration
// ============================================================================

/**
 * Set the Lua state for event dispatch.
 * Key events will fire Ext.Events.KeyInput.
 *
 * @param L Lua state (or NULL to disable)
 */
void input_set_lua_state(lua_State *L);

/**
 * Register the Ext.Input namespace.
 *
 * @param L               Lua state
 * @param ext_table_index Stack index of Ext table
 */
void lua_input_register(lua_State *L, int ext_table_index);

// ============================================================================
// macOS Virtual Key Codes (common keys)
// ============================================================================

// Letters (same position on all keyboards)
#define kVK_ANSI_A        0x00
#define kVK_ANSI_S        0x01
#define kVK_ANSI_D        0x02
#define kVK_ANSI_F        0x03
#define kVK_ANSI_H        0x04
#define kVK_ANSI_G        0x05
#define kVK_ANSI_Z        0x06
#define kVK_ANSI_X        0x07
#define kVK_ANSI_C        0x08
#define kVK_ANSI_V        0x09
#define kVK_ANSI_B        0x0B
#define kVK_ANSI_Q        0x0C
#define kVK_ANSI_W        0x0D
#define kVK_ANSI_E        0x0E
#define kVK_ANSI_R        0x0F
#define kVK_ANSI_Y        0x10
#define kVK_ANSI_T        0x11
#define kVK_ANSI_O        0x1F
#define kVK_ANSI_U        0x20
#define kVK_ANSI_I        0x22
#define kVK_ANSI_P        0x23
#define kVK_ANSI_L        0x25
#define kVK_ANSI_J        0x26
#define kVK_ANSI_K        0x28
#define kVK_ANSI_N        0x2D
#define kVK_ANSI_M        0x2E

// Numbers
#define kVK_ANSI_1        0x12
#define kVK_ANSI_2        0x13
#define kVK_ANSI_3        0x14
#define kVK_ANSI_4        0x15
#define kVK_ANSI_5        0x17
#define kVK_ANSI_6        0x16
#define kVK_ANSI_7        0x1A
#define kVK_ANSI_8        0x1C
#define kVK_ANSI_9        0x19
#define kVK_ANSI_0        0x1D

// Special keys
#define kVK_Return        0x24
#define kVK_Tab           0x30
#define kVK_Space         0x31
#define kVK_Delete        0x33  // Backspace
#define kVK_Escape        0x35
#define kVK_Command       0x37
#define kVK_Shift         0x38
#define kVK_CapsLock      0x39
#define kVK_Option        0x3A  // Alt
#define kVK_Control       0x3B
#define kVK_RightShift    0x3C
#define kVK_RightOption   0x3D
#define kVK_RightControl  0x3E
#define kVK_Function      0x3F

// Function keys
#define kVK_F1            0x7A
#define kVK_F2            0x78
#define kVK_F3            0x63
#define kVK_F4            0x76
#define kVK_F5            0x60
#define kVK_F6            0x61
#define kVK_F7            0x62
#define kVK_F8            0x64
#define kVK_F9            0x65
#define kVK_F10           0x6D
#define kVK_F11           0x67
#define kVK_F12           0x6F

// Arrow keys
#define kVK_LeftArrow     0x7B
#define kVK_RightArrow    0x7C
#define kVK_DownArrow     0x7D
#define kVK_UpArrow       0x7E

// Punctuation
#define kVK_ANSI_Grave    0x32  // ` (backtick/tilde)
#define kVK_ANSI_Minus    0x1B
#define kVK_ANSI_Equal    0x18
#define kVK_ANSI_LeftBracket  0x21
#define kVK_ANSI_RightBracket 0x1E
#define kVK_ANSI_Backslash    0x2A
#define kVK_ANSI_Semicolon    0x29
#define kVK_ANSI_Quote        0x27
#define kVK_ANSI_Comma        0x2B
#define kVK_ANSI_Period       0x2F
#define kVK_ANSI_Slash        0x2C

#endif /* INPUT_H */
