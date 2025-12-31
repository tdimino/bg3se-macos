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
 *
 * Widget System:
 *   Windows and widgets are represented as userdata with metatables.
 *   Properties are accessed via __index/__newindex metamethods.
 *   Methods (AddButton, AddText, etc.) are found via __index on the metatable.
 */

#include "lua_imgui.h"
#include "imgui_metal_backend.h"
#include "imgui_objects.h"
#include "logging.h"
#include "lauxlib.h"
#include <string.h>

// ============================================================================
// Lua Userdata Types
// ============================================================================

// Metatable names for each widget type
#define IMGUI_WINDOW_MT   "ImguiWindow"
#define IMGUI_GROUP_MT    "ImguiGroup"
#define IMGUI_BUTTON_MT   "ImguiButton"
#define IMGUI_TEXT_MT     "ImguiText"
#define IMGUI_CHECKBOX_MT "ImguiCheckbox"
#define IMGUI_WIDGET_MT   "ImguiWidget"  // Generic fallback

// Userdata structure that wraps an ImguiHandle
typedef struct {
    ImguiHandle handle;
    ImguiObjectType type;
} ImguiUserdata;

// Helper to get metatable name for an object type
static const char* imgui_get_metatable_name(ImguiObjectType type) {
    switch (type) {
        case IMGUI_OBJ_WINDOW: return IMGUI_WINDOW_MT;
        case IMGUI_OBJ_GROUP: return IMGUI_GROUP_MT;
        case IMGUI_OBJ_BUTTON: return IMGUI_BUTTON_MT;
        case IMGUI_OBJ_TEXT: return IMGUI_TEXT_MT;
        case IMGUI_OBJ_CHECKBOX: return IMGUI_CHECKBOX_MT;
        default: return IMGUI_WIDGET_MT;
    }
}

// ============================================================================
// Userdata Creation and Validation
// ============================================================================

/**
 * Push a new ImGui handle as userdata onto the Lua stack.
 * Returns the userdata pointer, or NULL if failed.
 */
static ImguiUserdata* imgui_push_handle(lua_State *L, ImguiHandle handle, ImguiObjectType type) {
    if (handle == IMGUI_INVALID_HANDLE) {
        lua_pushnil(L);
        return NULL;
    }

    ImguiUserdata *ud = (ImguiUserdata*)lua_newuserdata(L, sizeof(ImguiUserdata));
    ud->handle = handle;
    ud->type = type;

    // Set the appropriate metatable
    const char *mt_name = imgui_get_metatable_name(type);
    luaL_getmetatable(L, mt_name);
    if (lua_isnil(L, -1)) {
        // Fallback to generic widget metatable
        lua_pop(L, 1);
        luaL_getmetatable(L, IMGUI_WIDGET_MT);
    }
    lua_setmetatable(L, -2);

    return ud;
}

/**
 * Check if the value at the given index is an ImGui userdata.
 * Returns the userdata pointer, or NULL if not valid.
 */
static ImguiUserdata* imgui_check_userdata(lua_State *L, int idx) {
    void *ud = lua_touserdata(L, idx);
    if (ud == NULL) {
        return NULL;
    }

    // Check if it has one of our metatables
    if (lua_getmetatable(L, idx)) {
        // Try each known metatable
        static const char* mt_names[] = {
            IMGUI_WINDOW_MT, IMGUI_GROUP_MT, IMGUI_BUTTON_MT,
            IMGUI_TEXT_MT, IMGUI_CHECKBOX_MT, IMGUI_WIDGET_MT, NULL
        };

        for (const char **name = mt_names; *name != NULL; name++) {
            luaL_getmetatable(L, *name);
            if (lua_rawequal(L, -1, -2)) {
                lua_pop(L, 2);  // Pop both metatables
                return (ImguiUserdata*)ud;
            }
            lua_pop(L, 1);  // Pop the test metatable
        }
        lua_pop(L, 1);  // Pop the userdata's metatable
    }

    return NULL;
}

/**
 * Like imgui_check_userdata but raises an error if not valid.
 */
static ImguiUserdata* imgui_to_userdata(lua_State *L, int idx) {
    ImguiUserdata *ud = imgui_check_userdata(L, idx);
    if (ud == NULL) {
        luaL_error(L, "expected ImGui widget at argument %d", idx);
    }
    return ud;
}

// ============================================================================
// Property Access Helpers
// ============================================================================

/**
 * Helper to push a vec2 as a table {x, y} or {[1], [2]}
 */
static void imgui_push_vec2(lua_State *L, float x, float y) {
    lua_createtable(L, 2, 0);
    lua_pushnumber(L, x);
    lua_rawseti(L, -2, 1);
    lua_pushnumber(L, y);
    lua_rawseti(L, -2, 2);
}

/**
 * Helper to push a vec4 as a table
 */
static void imgui_push_vec4(lua_State *L, float x, float y, float z, float w) {
    lua_createtable(L, 4, 0);
    lua_pushnumber(L, x);
    lua_rawseti(L, -2, 1);
    lua_pushnumber(L, y);
    lua_rawseti(L, -2, 2);
    lua_pushnumber(L, z);
    lua_rawseti(L, -2, 3);
    lua_pushnumber(L, w);
    lua_rawseti(L, -2, 4);
}

/**
 * Helper to get a vec2 from a table at the given stack index
 */
static bool imgui_get_vec2(lua_State *L, int idx, float *x, float *y) {
    if (!lua_istable(L, idx)) return false;

    lua_rawgeti(L, idx, 1);
    *x = (float)lua_tonumber(L, -1);
    lua_pop(L, 1);

    lua_rawgeti(L, idx, 2);
    *y = (float)lua_tonumber(L, -1);
    lua_pop(L, 1);

    return true;
}

/**
 * Helper to get a vec4 from a table at the given stack index
 */
static bool imgui_get_vec4(lua_State *L, int idx, float *x, float *y, float *z, float *w) {
    if (!lua_istable(L, idx)) return false;

    lua_rawgeti(L, idx, 1);
    *x = (float)lua_tonumber(L, -1);
    lua_pop(L, 1);

    lua_rawgeti(L, idx, 2);
    *y = (float)lua_tonumber(L, -1);
    lua_pop(L, 1);

    lua_rawgeti(L, idx, 3);
    *z = (float)lua_tonumber(L, -1);
    lua_pop(L, 1);

    lua_rawgeti(L, idx, 4);
    *w = (float)lua_tonumber(L, -1);
    lua_pop(L, 1);

    return true;
}

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
// Window Property Access
// ============================================================================

// Forward declarations for widget methods
static int imgui_window_add_text(lua_State *L);
static int imgui_window_add_button(lua_State *L);
static int imgui_window_add_checkbox(lua_State *L);
static int imgui_window_add_separator(lua_State *L);
static int imgui_window_add_spacing(lua_State *L);
static int imgui_window_add_group(lua_State *L);
static int imgui_widget_destroy(lua_State *L);
static int imgui_widget_set_visible(lua_State *L);

// Method table for window objects
static const luaL_Reg window_methods[] = {
    {"AddText", imgui_window_add_text},
    {"AddButton", imgui_window_add_button},
    {"AddCheckbox", imgui_window_add_checkbox},
    {"AddSeparator", imgui_window_add_separator},
    {"AddSpacing", imgui_window_add_spacing},
    {"AddGroup", imgui_window_add_group},
    {"Destroy", imgui_widget_destroy},
    {"SetVisible", imgui_widget_set_visible},
    {NULL, NULL}
};

/**
 * __index metamethod for window objects.
 * First checks for methods, then checks for properties.
 */
static int imgui_window_index(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *key = luaL_checkstring(L, 2);

    // First check method table
    for (const luaL_Reg *method = window_methods; method->name != NULL; method++) {
        if (strcmp(key, method->name) == 0) {
            lua_pushcfunction(L, method->func);
            return 1;
        }
    }

    // Get the object to read properties
    ImguiObject *obj = imgui_object_get(ud->handle);
    if (obj == NULL) {
        return luaL_error(L, "invalid window handle");
    }

    // Window-specific properties
    if (strcmp(key, "Open") == 0) {
        lua_pushboolean(L, obj->data.window.open);
        return 1;
    }
    if (strcmp(key, "Closeable") == 0) {
        lua_pushboolean(L, obj->data.window.closeable);
        return 1;
    }
    if (strcmp(key, "Flags") == 0) {
        lua_pushinteger(L, obj->data.window.flags);
        return 1;
    }
    if (strcmp(key, "Collapsed") == 0) {
        lua_pushboolean(L, obj->data.window.collapsed);
        return 1;
    }

    // Common styled properties
    if (strcmp(key, "Label") == 0) {
        lua_pushstring(L, obj->styled.label);
        return 1;
    }
    if (strcmp(key, "Visible") == 0) {
        lua_pushboolean(L, obj->styled.visible);
        return 1;
    }
    if (strcmp(key, "SameLine") == 0) {
        lua_pushboolean(L, obj->styled.same_line);
        return 1;
    }

    // Handle property
    if (strcmp(key, "Handle") == 0) {
        lua_pushinteger(L, (lua_Integer)ud->handle);
        return 1;
    }

    // Type property
    if (strcmp(key, "Type") == 0) {
        lua_pushstring(L, imgui_object_type_name(obj->type));
        return 1;
    }

    // Unknown property
    lua_pushnil(L);
    return 1;
}

/**
 * __newindex metamethod for window objects.
 * Sets properties on the window.
 */
static int imgui_window_newindex(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *key = luaL_checkstring(L, 2);

    ImguiObject *obj = imgui_object_get(ud->handle);
    if (obj == NULL) {
        return luaL_error(L, "invalid window handle");
    }

    // Window-specific properties
    if (strcmp(key, "Open") == 0) {
        obj->data.window.open = lua_toboolean(L, 3);
        return 0;
    }
    if (strcmp(key, "Closeable") == 0) {
        obj->data.window.closeable = lua_toboolean(L, 3);
        return 0;
    }
    if (strcmp(key, "Flags") == 0) {
        obj->data.window.flags = (uint32_t)luaL_checkinteger(L, 3);
        return 0;
    }
    if (strcmp(key, "Collapsed") == 0) {
        obj->data.window.collapsed = lua_toboolean(L, 3);
        return 0;
    }

    // Common styled properties
    if (strcmp(key, "Visible") == 0) {
        obj->styled.visible = lua_toboolean(L, 3);
        return 0;
    }
    if (strcmp(key, "SameLine") == 0) {
        obj->styled.same_line = lua_toboolean(L, 3);
        return 0;
    }
    if (strcmp(key, "Label") == 0) {
        const char *label = luaL_checkstring(L, 3);
        strncpy(obj->styled.label, label, IMGUI_LABEL_MAX - 1);
        obj->styled.label[IMGUI_LABEL_MAX - 1] = '\0';
        return 0;
    }

    // Event callbacks (stored as Lua refs)
    if (strcmp(key, "OnClose") == 0) {
        if (lua_isfunction(L, 3)) {
            lua_pushvalue(L, 3);
            int ref = luaL_ref(L, LUA_REGISTRYINDEX);
            imgui_object_set_event(ud->handle, IMGUI_EVENT_ON_CLOSE, ref);
        } else if (lua_isnil(L, 3)) {
            imgui_object_clear_event(ud->handle, IMGUI_EVENT_ON_CLOSE);
        }
        return 0;
    }
    if (strcmp(key, "OnClick") == 0) {
        if (lua_isfunction(L, 3)) {
            lua_pushvalue(L, 3);
            int ref = luaL_ref(L, LUA_REGISTRYINDEX);
            imgui_object_set_event(ud->handle, IMGUI_EVENT_ON_CLICK, ref);
        } else if (lua_isnil(L, 3)) {
            imgui_object_clear_event(ud->handle, IMGUI_EVENT_ON_CLICK);
        }
        return 0;
    }

    return luaL_error(L, "unknown property: %s", key);
}

/**
 * __gc metamethod for all ImGui objects.
 * Marks the object as orphaned when Lua GC's the userdata.
 */
static int imgui_widget_gc(lua_State *L) {
    ImguiUserdata *ud = imgui_check_userdata(L, 1);
    if (ud != NULL && ud->handle != IMGUI_INVALID_HANDLE) {
        // Don't destroy immediately - let render loop clean up
        // Just log for now
        LOG_IMGUI_DEBUG("GC: handle 0x%llx", (unsigned long long)ud->handle);
    }
    return 0;
}

/**
 * __tostring metamethod for ImGui objects.
 */
static int imgui_widget_tostring(lua_State *L) {
    ImguiUserdata *ud = imgui_check_userdata(L, 1);
    if (ud == NULL) {
        lua_pushstring(L, "ImguiWidget(invalid)");
        return 1;
    }

    ImguiObject *obj = imgui_object_get(ud->handle);
    if (obj == NULL) {
        // lua_pushfstring doesn't support %llx, use snprintf
        char buf[64];
        snprintf(buf, sizeof(buf), "ImguiWidget(0x%llx, stale)",
                (unsigned long long)ud->handle);
        lua_pushstring(L, buf);
        return 1;
    }

    // lua_pushfstring doesn't support %llx, use snprintf
    char buf[256];
    snprintf(buf, sizeof(buf), "ImguiWidget(%s, \"%s\", 0x%llx)",
            imgui_object_type_name(obj->type),
            obj->styled.label,
            (unsigned long long)ud->handle);
    lua_pushstring(L, buf);
    return 1;
}

// ============================================================================
// Widget Creation Methods
// ============================================================================

/**
 * window:AddText(label) -> text widget
 */
static int imgui_window_add_text(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_TEXT, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create text widget");
    }

    imgui_push_handle(L, child, IMGUI_OBJ_TEXT);
    return 1;
}

/**
 * window:AddButton(label) -> button widget
 */
static int imgui_window_add_button(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_BUTTON, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create button widget");
    }

    imgui_push_handle(L, child, IMGUI_OBJ_BUTTON);
    return 1;
}

/**
 * window:AddCheckbox(label, checked) -> checkbox widget
 */
static int imgui_window_add_checkbox(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    bool checked = lua_toboolean(L, 3);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_CHECKBOX, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create checkbox widget");
    }

    // Set initial checked state
    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.checkbox.checked = checked;
    }

    imgui_push_handle(L, child, IMGUI_OBJ_CHECKBOX);
    return 1;
}

/**
 * window:AddSeparator() -> separator widget
 */
static int imgui_window_add_separator(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_SEPARATOR, "");
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create separator widget");
    }

    imgui_push_handle(L, child, IMGUI_OBJ_SEPARATOR);
    return 1;
}

/**
 * window:AddSpacing() -> spacing widget
 */
static int imgui_window_add_spacing(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_SPACING, "");
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create spacing widget");
    }

    imgui_push_handle(L, child, IMGUI_OBJ_SPACING);
    return 1;
}

/**
 * window:AddGroup(label) -> group widget
 */
static int imgui_window_add_group(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_optstring(L, 2, "");

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_GROUP, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create group widget");
    }

    imgui_push_handle(L, child, IMGUI_OBJ_GROUP);
    return 1;
}

/**
 * widget:Destroy()
 * Explicitly destroy a widget and all its children.
 */
static int imgui_widget_destroy(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    imgui_object_destroy(ud->handle);
    ud->handle = IMGUI_INVALID_HANDLE;
    return 0;
}

/**
 * widget:SetVisible(visible)
 */
static int imgui_widget_set_visible(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    bool visible = lua_toboolean(L, 2);

    ImguiObject *obj = imgui_object_get(ud->handle);
    if (obj) {
        obj->styled.visible = visible;
    }

    return 0;
}

// ============================================================================
// Generic Widget Metamethods
// ============================================================================

/**
 * Generic __index for non-window widgets
 */
static int imgui_widget_index(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *key = luaL_checkstring(L, 2);

    ImguiObject *obj = imgui_object_get(ud->handle);
    if (obj == NULL) {
        return luaL_error(L, "invalid widget handle");
    }

    // Common methods
    if (strcmp(key, "Destroy") == 0) {
        lua_pushcfunction(L, imgui_widget_destroy);
        return 1;
    }
    if (strcmp(key, "SetVisible") == 0) {
        lua_pushcfunction(L, imgui_widget_set_visible);
        return 1;
    }

    // Common styled properties
    if (strcmp(key, "Label") == 0) {
        lua_pushstring(L, obj->styled.label);
        return 1;
    }
    if (strcmp(key, "Visible") == 0) {
        lua_pushboolean(L, obj->styled.visible);
        return 1;
    }
    if (strcmp(key, "SameLine") == 0) {
        lua_pushboolean(L, obj->styled.same_line);
        return 1;
    }
    if (strcmp(key, "Handle") == 0) {
        lua_pushinteger(L, (lua_Integer)ud->handle);
        return 1;
    }
    if (strcmp(key, "Type") == 0) {
        lua_pushstring(L, imgui_object_type_name(obj->type));
        return 1;
    }

    // Type-specific properties
    switch (obj->type) {
        case IMGUI_OBJ_CHECKBOX:
            if (strcmp(key, "Checked") == 0) {
                lua_pushboolean(L, obj->data.checkbox.checked);
                return 1;
            }
            break;

        case IMGUI_OBJ_BUTTON:
            if (strcmp(key, "Size") == 0) {
                imgui_push_vec2(L, obj->data.button.size.x, obj->data.button.size.y);
                return 1;
            }
            break;

        case IMGUI_OBJ_TEXT:
            if (strcmp(key, "Color") == 0) {
                if (obj->data.text.has_color) {
                    imgui_push_vec4(L, obj->data.text.color.x, obj->data.text.color.y,
                                   obj->data.text.color.z, obj->data.text.color.w);
                } else {
                    lua_pushnil(L);
                }
                return 1;
            }
            break;

        default:
            break;
    }

    lua_pushnil(L);
    return 1;
}

/**
 * Generic __newindex for non-window widgets
 */
static int imgui_widget_newindex(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *key = luaL_checkstring(L, 2);

    ImguiObject *obj = imgui_object_get(ud->handle);
    if (obj == NULL) {
        return luaL_error(L, "invalid widget handle");
    }

    // Common styled properties
    if (strcmp(key, "Visible") == 0) {
        obj->styled.visible = lua_toboolean(L, 3);
        return 0;
    }
    if (strcmp(key, "SameLine") == 0) {
        obj->styled.same_line = lua_toboolean(L, 3);
        return 0;
    }
    if (strcmp(key, "Label") == 0) {
        const char *label = luaL_checkstring(L, 3);
        strncpy(obj->styled.label, label, IMGUI_LABEL_MAX - 1);
        obj->styled.label[IMGUI_LABEL_MAX - 1] = '\0';
        return 0;
    }

    // Event callbacks
    if (strcmp(key, "OnClick") == 0) {
        if (lua_isfunction(L, 3)) {
            lua_pushvalue(L, 3);
            int ref = luaL_ref(L, LUA_REGISTRYINDEX);
            imgui_object_set_event(ud->handle, IMGUI_EVENT_ON_CLICK, ref);
        } else if (lua_isnil(L, 3)) {
            imgui_object_clear_event(ud->handle, IMGUI_EVENT_ON_CLICK);
        }
        return 0;
    }
    if (strcmp(key, "OnChange") == 0) {
        if (lua_isfunction(L, 3)) {
            lua_pushvalue(L, 3);
            int ref = luaL_ref(L, LUA_REGISTRYINDEX);
            imgui_object_set_event(ud->handle, IMGUI_EVENT_ON_CHANGE, ref);
        } else if (lua_isnil(L, 3)) {
            imgui_object_clear_event(ud->handle, IMGUI_EVENT_ON_CHANGE);
        }
        return 0;
    }

    // Type-specific properties
    switch (obj->type) {
        case IMGUI_OBJ_CHECKBOX:
            if (strcmp(key, "Checked") == 0) {
                obj->data.checkbox.checked = lua_toboolean(L, 3);
                return 0;
            }
            break;

        case IMGUI_OBJ_BUTTON:
            if (strcmp(key, "Size") == 0) {
                float x, y;
                if (imgui_get_vec2(L, 3, &x, &y)) {
                    obj->data.button.size.x = x;
                    obj->data.button.size.y = y;
                    obj->data.button.has_size = true;
                }
                return 0;
            }
            break;

        case IMGUI_OBJ_TEXT:
            if (strcmp(key, "Color") == 0) {
                if (lua_istable(L, 3)) {
                    float x, y, z, w;
                    if (imgui_get_vec4(L, 3, &x, &y, &z, &w)) {
                        obj->data.text.color.x = x;
                        obj->data.text.color.y = y;
                        obj->data.text.color.z = z;
                        obj->data.text.color.w = w;
                        obj->data.text.has_color = true;
                    }
                } else if (lua_isnil(L, 3)) {
                    obj->data.text.has_color = false;
                }
                return 0;
            }
            break;

        default:
            break;
    }

    return luaL_error(L, "unknown property: %s", key);
}

// ============================================================================
// Window Creation
// ============================================================================

/**
 * Ext.IMGUI.NewWindow(label) -> window handle
 * Create a new ImGui window.
 */
static int lua_imgui_new_window(lua_State *L) {
    const char *label = luaL_checkstring(L, 1);

    // Initialize object system if needed
    static bool objects_initialized = false;
    if (!objects_initialized) {
        imgui_objects_init();
        objects_initialized = true;
    }

    // Create window object
    ImguiHandle handle = imgui_object_create(IMGUI_OBJ_WINDOW, label);
    if (handle == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create window");
    }

    // Set default window properties
    ImguiObject *obj = imgui_object_get(handle);
    if (obj) {
        obj->data.window.open = true;
        obj->data.window.closeable = true;
        obj->styled.visible = true;
    }

    // Register as a top-level window for rendering
    imgui_register_window(handle);

    LOG_IMGUI_INFO("Created window '%s' with handle 0x%llx",
                   label, (unsigned long long)handle);

    imgui_push_handle(L, handle, IMGUI_OBJ_WINDOW);
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

/**
 * Create a metatable for an ImGui widget type
 */
static void create_widget_metatable(lua_State *L, const char *name,
                                   lua_CFunction index_fn,
                                   lua_CFunction newindex_fn) {
    luaL_newmetatable(L, name);

    // __index
    lua_pushcfunction(L, index_fn);
    lua_setfield(L, -2, "__index");

    // __newindex
    lua_pushcfunction(L, newindex_fn);
    lua_setfield(L, -2, "__newindex");

    // __gc
    lua_pushcfunction(L, imgui_widget_gc);
    lua_setfield(L, -2, "__gc");

    // __tostring
    lua_pushcfunction(L, imgui_widget_tostring);
    lua_setfield(L, -2, "__tostring");

    // __type (for type identification)
    lua_pushstring(L, name);
    lua_setfield(L, -2, "__type");

    lua_pop(L, 1);  // Pop metatable
}

void lua_imgui_register(lua_State *L, int ext_idx) {
    // Convert to absolute index before pushing new values
    if (ext_idx < 0) {
        ext_idx = lua_gettop(L) + ext_idx + 1;
    }

    // Create metatables for each widget type
    create_widget_metatable(L, IMGUI_WINDOW_MT, imgui_window_index, imgui_window_newindex);
    create_widget_metatable(L, IMGUI_GROUP_MT, imgui_widget_index, imgui_widget_newindex);
    create_widget_metatable(L, IMGUI_BUTTON_MT, imgui_widget_index, imgui_widget_newindex);
    create_widget_metatable(L, IMGUI_TEXT_MT, imgui_widget_index, imgui_widget_newindex);
    create_widget_metatable(L, IMGUI_CHECKBOX_MT, imgui_widget_index, imgui_widget_newindex);
    create_widget_metatable(L, IMGUI_WIDGET_MT, imgui_widget_index, imgui_widget_newindex);

    LOG_IMGUI_DEBUG("Created ImGui metatables");

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
