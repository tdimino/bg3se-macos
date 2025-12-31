/**
 * @file imgui_input_hooks.h
 * @brief Input event hooks for ImGui overlay
 */

#ifndef IMGUI_INPUT_HOOKS_H
#define IMGUI_INPUT_HOOKS_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize input hooks on the game view.
 * Call this after ImGui is ready and the game window is found.
 *
 * @param nsview Pointer to NSView (the game's content view)
 * @return true if hooks installed successfully
 */
bool imgui_input_hooks_init(void *nsview);

/**
 * Remove input hooks and restore original methods.
 * Call this during shutdown.
 */
void imgui_input_hooks_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* IMGUI_INPUT_HOOKS_H */
