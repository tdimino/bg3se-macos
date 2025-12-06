// overlay.h - In-game console overlay API
// NSWindow-based floating console with Tanit symbol

#ifndef OVERLAY_H
#define OVERLAY_H

#include <stdbool.h>

// Initialize the overlay system (call once at startup)
void overlay_init(void);

// Shutdown the overlay system
void overlay_shutdown(void);

// Toggle overlay visibility
void overlay_toggle(void);

// Show/hide overlay explicitly
void overlay_show(void);
void overlay_hide(void);

// Check if overlay is currently visible
bool overlay_is_visible(void);

// Append text to the output area
void overlay_append_output(const char *text);

// Clear the output area
void overlay_clear_output(void);

// Set the command callback (called when user submits input)
typedef void (*overlay_command_callback)(const char *command);
void overlay_set_command_callback(overlay_command_callback callback);

// Focus the input field (for hotkey activation)
void overlay_focus_input(void);

#endif // OVERLAY_H
