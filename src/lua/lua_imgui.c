/**
 * @file lua_imgui.c
 * @brief Lua bindings for Ext.IMGUI namespace
 *
 * Provides ImGui overlay functionality to Lua mods.
 *
 * API:
 *   Ext.IMGUI.Show() - Show the overlay
 *   Ext.IMGUI.Hide() - Hide the overlay
 *   Ext.IMGUI.Toggle() - Toggle overlay visibility
 *   Ext.IMGUI.IsVisible() - Check if overlay is visible
 *   Ext.IMGUI.IsReady() - Check if ImGui backend is initialized
 *   Ext.IMGUI.NewWindow(label) - Create a new window (returns handle)
 */

#include "lua_imgui.h"
#include "imgui_metal_backend.h"
#include "logging.h"
#include "lauxlib.h"

// ============================================================================
// Basic Visibility Control
// ============================================================================

/**
 * Ext.IMGUI.Show()
 * Show the ImGui overlay.
 * Initializes the Metal backend on first call (lazy initialization).
 */
static int lua_imgui_show(lua_State *L) {
    // Lazy initialization - init Metal backend on first Show() call
    if (imgui_metal_get_state() == IMGUI_METAL_STATE_UNINITIALIZED) {
        LOG_IMGUI_INFO("Lazy-initializing ImGui Metal backend...");
        if (!imgui_metal_init()) {
            lua_pushboolean(L, false);
            return 1;
        }
    }

    imgui_metal_set_visible(true);
    lua_pushboolean(L, true);
    return 1;
}

/**
 * Ext.IMGUI.Hide()
 * Hide the ImGui overlay.
 */
static int lua_imgui_hide(lua_State *L) {
    (void)L;
    imgui_metal_set_visible(false);
    return 0;
}

/**
 * Ext.IMGUI.Toggle()
 * Toggle overlay visibility.
 */
static int lua_imgui_toggle(lua_State *L) {
    (void)L;
    bool visible = imgui_metal_is_visible();
    imgui_metal_set_visible(!visible);
    lua_pushboolean(L, !visible);
    return 1;
}

/**
 * Ext.IMGUI.IsVisible() -> boolean
 * Check if overlay is currently visible.
 */
static int lua_imgui_is_visible(lua_State *L) {
    lua_pushboolean(L, imgui_metal_is_visible());
    return 1;
}

/**
 * Ext.IMGUI.IsReady() -> boolean
 * Check if ImGui backend is initialized and ready.
 */
static int lua_imgui_is_ready(lua_State *L) {
    lua_pushboolean(L, imgui_metal_is_ready());
    return 1;
}

/**
 * Ext.IMGUI.GetState() -> string
 * Get the current state of the ImGui backend.
 */
static int lua_imgui_get_state(lua_State *L) {
    ImguiMetalState state = imgui_metal_get_state();
    const char *state_str;

    switch (state) {
        case IMGUI_METAL_STATE_UNINITIALIZED:
            state_str = "Uninitialized";
            break;
        case IMGUI_METAL_STATE_WAITING_FOR_DEVICE:
            state_str = "WaitingForDevice";
            break;
        case IMGUI_METAL_STATE_INITIALIZING:
            state_str = "Initializing";
            break;
        case IMGUI_METAL_STATE_READY:
            state_str = "Ready";
            break;
        case IMGUI_METAL_STATE_ERROR:
            state_str = "Error";
            break;
        default:
            state_str = "Unknown";
            break;
    }

    lua_pushstring(L, state_str);
    return 1;
}

/**
 * Ext.IMGUI.SetInputCapture(capture)
 * Enable/disable input capture mode.
 * When capturing, ImGui consumes keyboard/mouse input.
 */
static int lua_imgui_set_input_capture(lua_State *L) {
    bool capture = lua_toboolean(L, 1);
    imgui_metal_set_input_capture(capture);
    return 0;
}

/**
 * Ext.IMGUI.IsCapturingInput() -> boolean
 * Check if ImGui is capturing input.
 */
static int lua_imgui_is_capturing_input(lua_State *L) {
    lua_pushboolean(L, imgui_metal_is_capturing_input());
    return 1;
}

// ============================================================================
// Window Creation (Placeholder - will be expanded in Phase 3)
// ============================================================================

/**
 * Ext.IMGUI.NewWindow(label) -> window handle
 * Create a new ImGui window.
 *
 * Note: This is a placeholder. Full widget system will be implemented in Phase 3.
 */
static int lua_imgui_new_window(lua_State *L) {
    const char *label = luaL_checkstring(L, 1);
    LOG_IMGUI_INFO("NewWindow requested: %s (placeholder)", label);

    // For now, just return nil with a message
    // Full implementation will create a window handle object
    lua_pushnil(L);
    return 1;
}

// ============================================================================
// Registration
// ============================================================================

static const luaL_Reg imgui_functions[] = {
    {"Show", lua_imgui_show},
    {"Hide", lua_imgui_hide},
    {"Toggle", lua_imgui_toggle},
    {"IsVisible", lua_imgui_is_visible},
    {"IsReady", lua_imgui_is_ready},
    {"GetState", lua_imgui_get_state},
    {"SetInputCapture", lua_imgui_set_input_capture},
    {"IsCapturingInput", lua_imgui_is_capturing_input},
    {"NewWindow", lua_imgui_new_window},
    {NULL, NULL}
};

void lua_imgui_register(lua_State *L, int ext_idx) {
    // Convert to absolute index before pushing new values
    if (ext_idx < 0) {
        ext_idx = lua_gettop(L) + ext_idx + 1;
    }

    // Create Ext.IMGUI table
    lua_newtable(L);

    // Register all functions
    for (const luaL_Reg *reg = imgui_functions; reg->name != NULL; reg++) {
        lua_pushcfunction(L, reg->func);
        lua_setfield(L, -2, reg->name);
    }

    // Set as Ext.IMGUI
    lua_setfield(L, ext_idx, "IMGUI");

    LOG_IMGUI_INFO("Registered Ext.IMGUI with %d functions",
                   (int)(sizeof(imgui_functions) / sizeof(imgui_functions[0]) - 1));
}
