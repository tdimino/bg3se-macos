/**
 * @file imgui_metal_backend.h
 * @brief Metal rendering backend for ImGui overlay on macOS BG3
 *
 * Hooks into the game's Metal rendering pipeline via CAMetalLayer swizzling
 * to inject ImGui debug overlay rendering.
 */

#ifndef IMGUI_METAL_BACKEND_H
#define IMGUI_METAL_BACKEND_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __OBJC__
#import <Metal/Metal.h>
#import <QuartzCore/CAMetalLayer.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Current state of the ImGui Metal backend
 */
typedef enum {
    IMGUI_METAL_STATE_UNINITIALIZED = 0,
    IMGUI_METAL_STATE_WAITING_FOR_DEVICE,  // Waiting for game to create Metal device
    IMGUI_METAL_STATE_INITIALIZING,         // Setting up ImGui
    IMGUI_METAL_STATE_READY,                // Ready to render
    IMGUI_METAL_STATE_ERROR                 // Initialization failed
} ImguiMetalState;

/**
 * Initialize the Metal backend for ImGui.
 * This sets up method swizzling and waits for the game's Metal device.
 * Should be called early in injection (e.g., from main.c constructor).
 *
 * @return true if initialization started successfully
 */
bool imgui_metal_init(void);

/**
 * Shut down the Metal backend and restore original methods.
 * Call this during cleanup/unloading.
 */
void imgui_metal_shutdown(void);

/**
 * Check if ImGui Metal backend is ready to render.
 *
 * @return true if the backend is initialized and ready
 */
bool imgui_metal_is_ready(void);

/**
 * Get the current state of the Metal backend.
 *
 * @return Current initialization state
 */
ImguiMetalState imgui_metal_get_state(void);

/**
 * Toggle ImGui overlay visibility.
 * When hidden, no rendering is performed (performance optimization).
 *
 * @param visible true to show overlay, false to hide
 */
void imgui_metal_set_visible(bool visible);

/**
 * Check if ImGui overlay is currently visible.
 *
 * @return true if visible
 */
bool imgui_metal_is_visible(void);

/**
 * Toggle ImGui input capture mode.
 * When capturing, ImGui consumes keyboard/mouse input.
 *
 * @param capture true to capture input, false to pass through
 */
void imgui_metal_set_input_capture(bool capture);

/**
 * Check if ImGui is capturing input.
 *
 * @return true if capturing input
 */
bool imgui_metal_is_capturing_input(void);

/**
 * Process a keyboard event for ImGui.
 * Called from input_hooks.m when a key event occurs.
 *
 * @param keycode macOS virtual keycode
 * @param down true if key pressed, false if released
 * @param modifiers Modifier flags (shift, control, option, command)
 * @return true if ImGui consumed the event
 */
bool imgui_metal_process_key(uint16_t keycode, bool down, uint32_t modifiers);

/**
 * Process a mouse event for ImGui (screen coordinates from CGEventTap).
 * Coordinates will be converted from screen space to ImGui space.
 *
 * @param x X position in screen coordinates
 * @param y Y position in screen coordinates
 * @param button Mouse button (0=left, 1=right, 2=middle)
 * @param down true if pressed, false if released
 * @return true if ImGui consumed the event
 */
bool imgui_metal_process_mouse(float x, float y, int button, bool down);

/**
 * Process a mouse event for ImGui (direct coordinates from NSView).
 * Coordinates are already in ImGui space (origin top-left of view).
 *
 * @param x X position in view coordinates (0 = left)
 * @param y Y position in view coordinates (0 = top, already flipped)
 * @param button Mouse button (0=left, 1=right, 2=middle)
 * @param down true if pressed, false if released
 * @return true if ImGui consumed the event
 */
bool imgui_metal_process_mouse_direct(float x, float y, int button, bool down);

/**
 * Process mouse move event (screen coordinates from CGEventTap).
 *
 * @param x X position in screen coordinates
 * @param y Y position in screen coordinates
 */
void imgui_metal_process_mouse_move(float x, float y);

/**
 * Process mouse move event (direct coordinates from NSView).
 *
 * @param x X position in view coordinates
 * @param y Y position in view coordinates (already flipped)
 */
void imgui_metal_process_mouse_move_direct(float x, float y);

/**
 * Process scroll event.
 *
 * @param dx Horizontal scroll delta
 * @param dy Vertical scroll delta
 */
void imgui_metal_process_scroll(float dx, float dy);

/**
 * Process character input for text fields.
 *
 * @param c Unicode character
 */
void imgui_metal_process_char(unsigned int c);

#ifdef __cplusplus
}
#endif

#endif /* IMGUI_METAL_BACKEND_H */
