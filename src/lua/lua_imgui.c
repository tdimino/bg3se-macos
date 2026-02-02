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
#include <stdarg.h>
#include <stdlib.h>

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

// ============================================================================
// Event Callback Helper (eliminates ~100 lines of duplication)
// ============================================================================

/**
 * Event name to enum mapping
 */
typedef struct {
    const char *name;
    ImguiEventType type;
} EventMapping;

static const EventMapping g_event_mappings[] = {
    {"OnClick", IMGUI_EVENT_ON_CLICK},
    {"OnChange", IMGUI_EVENT_ON_CHANGE},
    {"OnClose", IMGUI_EVENT_ON_CLOSE},
    {"OnHoverEnter", IMGUI_EVENT_ON_HOVER_ENTER},
    {"OnHoverLeave", IMGUI_EVENT_ON_HOVER_LEAVE},
    {"OnActivate", IMGUI_EVENT_ON_ACTIVATE},
    {"OnDeactivate", IMGUI_EVENT_ON_DEACTIVATE},
    {"OnExpand", IMGUI_EVENT_ON_EXPAND},
    {"OnCollapse", IMGUI_EVENT_ON_COLLAPSE},
    {"OnSortChanged", IMGUI_EVENT_ON_SORT_CHANGED},
    {NULL, 0}
};

/**
 * Set an event callback on a widget (handles old ref cleanup).
 * Returns true if the key matched an event name.
 */
static bool imgui_try_set_event(lua_State *L, ImguiHandle handle, const char *key, int value_idx) {
    for (const EventMapping *m = g_event_mappings; m->name != NULL; m++) {
        if (strcmp(key, m->name) == 0) {
            // Release old ref if exists
            int old_ref = imgui_object_get_event(handle, m->type);
            if (old_ref != -1 && old_ref != LUA_NOREF && old_ref != LUA_REFNIL) {
                luaL_unref(L, LUA_REGISTRYINDEX, old_ref);
            }
            if (lua_isfunction(L, value_idx)) {
                lua_pushvalue(L, value_idx);
                int ref = luaL_ref(L, LUA_REGISTRYINDEX);
                imgui_object_set_event(handle, m->type, ref);
            } else if (lua_isnil(L, value_idx)) {
                imgui_object_set_event(handle, m->type, -1);
            }
            return true;
        }
    }
    return false;
}

// ============================================================================
// Vector Helpers
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
static int imgui_window_add_inputtext(lua_State *L);
static int imgui_window_add_combo(lua_State *L);
static int imgui_window_add_slider(lua_State *L);
static int imgui_window_add_sliderint(lua_State *L);
static int imgui_window_add_collapsingheader(lua_State *L);
static int imgui_window_add_bullettext(lua_State *L);
static int imgui_window_add_separatortext(lua_State *L);
static int imgui_window_add_progressbar(lua_State *L);
static int imgui_window_add_radiobutton(lua_State *L);
static int imgui_window_add_coloredit(lua_State *L);
static int imgui_window_add_colorpicker(lua_State *L);
static int imgui_window_add_drag(lua_State *L);
static int imgui_window_add_dragint(lua_State *L);
static int imgui_window_add_inputint(lua_State *L);
static int imgui_window_add_tree(lua_State *L);
static int imgui_window_add_selectable(lua_State *L);
static int imgui_window_add_table(lua_State *L);
static int imgui_window_add_tablerow(lua_State *L);
static int imgui_window_add_tablecell(lua_State *L);
static int imgui_window_add_tabbar(lua_State *L);
static int imgui_window_add_tabitem(lua_State *L);
static int imgui_window_add_menubar(lua_State *L);
static int imgui_window_add_menu(lua_State *L);
static int imgui_window_add_menuitem(lua_State *L);
static int imgui_window_add_popup(lua_State *L);
static int imgui_window_add_tooltip(lua_State *L);
static int imgui_window_add_childwindow(lua_State *L);
static int imgui_window_add_image(lua_State *L);
static int imgui_widget_destroy(lua_State *L);
static int imgui_widget_set_visible(lua_State *L);
static int imgui_widget_set_style(lua_State *L);
static int imgui_widget_set_color(lua_State *L);
static int imgui_widget_clear_style(lua_State *L);

// Method table for window objects
static const luaL_Reg window_methods[] = {
    {"AddText", imgui_window_add_text},
    {"AddBulletText", imgui_window_add_bullettext},
    {"AddSeparatorText", imgui_window_add_separatortext},
    {"AddButton", imgui_window_add_button},
    {"AddCheckbox", imgui_window_add_checkbox},
    {"AddRadioButton", imgui_window_add_radiobutton},
    {"AddInputText", imgui_window_add_inputtext},
    {"AddCombo", imgui_window_add_combo},
    {"AddSlider", imgui_window_add_slider},
    {"AddSliderInt", imgui_window_add_sliderint},
    {"AddColorEdit", imgui_window_add_coloredit},
    {"AddColorPicker", imgui_window_add_colorpicker},
    {"AddDrag", imgui_window_add_drag},
    {"AddDragInt", imgui_window_add_dragint},
    {"AddInputInt", imgui_window_add_inputint},
    {"AddProgressBar", imgui_window_add_progressbar},
    {"AddCollapsingHeader", imgui_window_add_collapsingheader},
    {"AddSeparator", imgui_window_add_separator},
    {"AddSpacing", imgui_window_add_spacing},
    {"AddGroup", imgui_window_add_group},
    {"AddTree", imgui_window_add_tree},
    {"AddSelectable", imgui_window_add_selectable},
    {"AddTable", imgui_window_add_table},
    {"AddTableRow", imgui_window_add_tablerow},
    {"AddTableCell", imgui_window_add_tablecell},
    {"AddTabBar", imgui_window_add_tabbar},
    {"AddTabItem", imgui_window_add_tabitem},
    {"AddMenuBar", imgui_window_add_menubar},
    {"AddMenu", imgui_window_add_menu},
    {"AddMenuItem", imgui_window_add_menuitem},
    {"AddPopup", imgui_window_add_popup},
    {"AddTooltip", imgui_window_add_tooltip},
    {"AddChildWindow", imgui_window_add_childwindow},
    {"AddImage", imgui_window_add_image},
    {"Destroy", imgui_widget_destroy},
    {"SetVisible", imgui_widget_set_visible},
    {"SetStyle", imgui_widget_set_style},
    {"SetColor", imgui_widget_set_color},
    {"ClearStyle", imgui_widget_clear_style},
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

    // Event callbacks - use helper to avoid duplication
    if (imgui_try_set_event(L, ud->handle, key, 3)) {
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
 * Helper for simple widget creation (reduces ~50% of widget creation boilerplate).
 * Returns handle on success, IMGUI_INVALID_HANDLE on failure (error already set).
 */
static ImguiHandle imgui_create_simple_widget(lua_State *L, ImguiObjectType type, const char *type_name) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = lua_isstring(L, 2) ? lua_tostring(L, 2) : "";

    ImguiHandle child = imgui_object_create_child(ud->handle, type, label);
    if (child == IMGUI_INVALID_HANDLE) {
        luaL_error(L, "failed to create %s widget", type_name);
        return IMGUI_INVALID_HANDLE;
    }

    imgui_push_handle(L, child, type);
    return child;
}

// Macro for simple widgets that only need label (or no args)
#define IMGUI_SIMPLE_WIDGET(func_name, obj_type, type_str) \
static int func_name(lua_State *L) { \
    imgui_create_simple_widget(L, obj_type, type_str); \
    return 1; \
}

// Simple widgets using the macro (requires label argument)
IMGUI_SIMPLE_WIDGET(imgui_window_add_text, IMGUI_OBJ_TEXT, "text")
IMGUI_SIMPLE_WIDGET(imgui_window_add_button, IMGUI_OBJ_BUTTON, "button")
IMGUI_SIMPLE_WIDGET(imgui_window_add_bullettext, IMGUI_OBJ_BULLET_TEXT, "bullet text")
IMGUI_SIMPLE_WIDGET(imgui_window_add_separatortext, IMGUI_OBJ_SEPARATOR_TEXT, "separator text")
IMGUI_SIMPLE_WIDGET(imgui_window_add_menu, IMGUI_OBJ_MENU, "menu")

// Widgets with fixed hidden labels (no label arg required)
#define IMGUI_HIDDEN_LABEL_WIDGET(func_name, obj_type, fixed_label, type_str) \
static int func_name(lua_State *L) { \
    ImguiUserdata *ud = imgui_to_userdata(L, 1); \
    ImguiHandle child = imgui_object_create_child(ud->handle, obj_type, fixed_label); \
    if (child == IMGUI_INVALID_HANDLE) { \
        return luaL_error(L, "failed to create " type_str " widget"); \
    } \
    imgui_push_handle(L, child, obj_type); \
    return 1; \
}

IMGUI_HIDDEN_LABEL_WIDGET(imgui_window_add_separator, IMGUI_OBJ_SEPARATOR, "", "separator")
IMGUI_HIDDEN_LABEL_WIDGET(imgui_window_add_spacing, IMGUI_OBJ_SPACING, "", "spacing")
IMGUI_HIDDEN_LABEL_WIDGET(imgui_window_add_tooltip, IMGUI_OBJ_TOOLTIP, "##tooltip", "tooltip")
IMGUI_HIDDEN_LABEL_WIDGET(imgui_window_add_menubar, IMGUI_OBJ_MENU_BAR, "##menubar", "menu bar")
IMGUI_HIDDEN_LABEL_WIDGET(imgui_window_add_tablecell, IMGUI_OBJ_TABLE_CELL, "##cell", "table cell")

// Widgets that need additional initialization still use explicit functions

/**
 * window:AddGroup(label) -> group widget
 */
static int imgui_window_add_group(lua_State *L) {
    imgui_create_simple_widget(L, IMGUI_OBJ_GROUP, "group");
    return 1;
}

/**
 * window:AddCheckbox(label, checked) -> checkbox widget
 */
static int imgui_window_add_checkbox(lua_State *L) {
    ImguiHandle child = imgui_create_simple_widget(L, IMGUI_OBJ_CHECKBOX, "checkbox");
    if (child == IMGUI_INVALID_HANDLE) return 0;

    // Set initial checked state
    bool checked = lua_toboolean(L, 3);
    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.checkbox.checked = checked;
    }
    return 1;
}

/**
 * window:AddInputText(label, [default_value]) -> input text widget
 */
static int imgui_window_add_inputtext(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    const char *default_value = luaL_optstring(L, 3, "");

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_INPUT_TEXT, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create input text widget");
    }

    // Set default value
    ImguiObject *obj = imgui_object_get(child);
    if (obj && default_value[0]) {
        strncpy(obj->data.input_text.text, default_value, sizeof(obj->data.input_text.text) - 1);
        obj->data.input_text.text[sizeof(obj->data.input_text.text) - 1] = '\0';
    }

    imgui_push_handle(L, child, IMGUI_OBJ_INPUT_TEXT);
    return 1;
}

/**
 * window:AddCombo(label, options, [selected_index]) -> combo widget
 * options is a table of strings
 */
static int imgui_window_add_combo(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    luaL_checktype(L, 3, LUA_TTABLE);
    int selected = (int)luaL_optinteger(L, 4, 1) - 1;  // Lua 1-indexed to C 0-indexed

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_COMBO, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create combo widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        // Count options
        int count = (int)lua_rawlen(L, 3);
        if (count > 0) {
            obj->data.combo.options = (char**)malloc(sizeof(char*) * count);
            if (!obj->data.combo.options) {
                imgui_object_destroy(child);
                return luaL_error(L, "failed to allocate memory for combo options");
            }
            obj->data.combo.option_count = count;

            for (int i = 0; i < count; i++) {
                lua_rawgeti(L, 3, i + 1);
                const char *opt = lua_tostring(L, -1);
                obj->data.combo.options[i] = opt ? strdup(opt) : strdup("");
                lua_pop(L, 1);
            }
        }
        obj->data.combo.selected_index = (selected >= 0 && selected < count) ? selected : 0;
    }

    imgui_push_handle(L, child, IMGUI_OBJ_COMBO);
    return 1;
}

/**
 * window:AddSlider(label, value, min, max) -> slider widget
 */
static int imgui_window_add_slider(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    float value = (float)luaL_optnumber(L, 3, 0.0);
    float min_val = (float)luaL_optnumber(L, 4, 0.0);
    float max_val = (float)luaL_optnumber(L, 5, 1.0);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_SLIDER_SCALAR, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create slider widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.slider.value.x = value;
        obj->data.slider.min.x = min_val;
        obj->data.slider.max.x = max_val;
        obj->data.slider.components = 1;
    }

    imgui_push_handle(L, child, IMGUI_OBJ_SLIDER_SCALAR);
    return 1;
}

/**
 * window:AddSliderInt(label, value, min, max) -> slider int widget
 */
static int imgui_window_add_sliderint(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    int value = (int)luaL_optinteger(L, 3, 0);
    int min_val = (int)luaL_optinteger(L, 4, 0);
    int max_val = (int)luaL_optinteger(L, 5, 100);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_SLIDER_INT, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create slider int widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.slider_int.value[0] = value;
        obj->data.slider_int.min[0] = min_val;
        obj->data.slider_int.max[0] = max_val;
        obj->data.slider_int.components = 1;
    }

    imgui_push_handle(L, child, IMGUI_OBJ_SLIDER_INT);
    return 1;
}

/**
 * window:AddCollapsingHeader(label, [default_open]) -> collapsing header widget
 */
static int imgui_window_add_collapsingheader(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    bool default_open = lua_toboolean(L, 3);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_COLLAPSING_HEADER, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create collapsing header widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.collapsing_header.is_open = default_open;
        if (default_open) {
            obj->data.collapsing_header.flags = 0x20;  // ImGuiTreeNodeFlags_DefaultOpen
        }
    }

    imgui_push_handle(L, child, IMGUI_OBJ_COLLAPSING_HEADER);
    return 1;
}

/**
 * window:AddProgressBar([value], [overlay]) -> progress bar widget
 */
static int imgui_window_add_progressbar(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    float value = (float)luaL_optnumber(L, 2, 0.0);
    const char *overlay = luaL_optstring(L, 3, NULL);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_PROGRESS_BAR, "");
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create progress bar widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.progress_bar.value = value;
        if (overlay) {
            strncpy(obj->data.progress_bar.overlay, overlay, sizeof(obj->data.progress_bar.overlay) - 1);
            obj->data.progress_bar.overlay[sizeof(obj->data.progress_bar.overlay) - 1] = '\0';
        }
    }

    imgui_push_handle(L, child, IMGUI_OBJ_PROGRESS_BAR);
    return 1;
}

/**
 * window:AddRadioButton(label, [active]) -> radio button widget
 */
static int imgui_window_add_radiobutton(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    bool active = lua_toboolean(L, 3);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_RADIO_BUTTON, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create radio button widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.radio_button.active = active;
    }

    imgui_push_handle(L, child, IMGUI_OBJ_RADIO_BUTTON);
    return 1;
}

/**
 * window:AddColorEdit(label, [r, g, b, a]) -> color edit widget
 */
static int imgui_window_add_coloredit(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    float r = (float)luaL_optnumber(L, 3, 1.0);
    float g = (float)luaL_optnumber(L, 4, 1.0);
    float b = (float)luaL_optnumber(L, 5, 1.0);
    float a = (float)luaL_optnumber(L, 6, 1.0);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_COLOR_EDIT, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create color edit widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.color.color = (ImguiVec4){r, g, b, a};
    }

    imgui_push_handle(L, child, IMGUI_OBJ_COLOR_EDIT);
    return 1;
}

/**
 * window:AddColorPicker(label, [r, g, b, a]) -> color picker widget
 */
static int imgui_window_add_colorpicker(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    float r = (float)luaL_optnumber(L, 3, 1.0);
    float g = (float)luaL_optnumber(L, 4, 1.0);
    float b = (float)luaL_optnumber(L, 5, 1.0);
    float a = (float)luaL_optnumber(L, 6, 1.0);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_COLOR_PICKER, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create color picker widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.color.color = (ImguiVec4){r, g, b, a};
    }

    imgui_push_handle(L, child, IMGUI_OBJ_COLOR_PICKER);
    return 1;
}

/**
 * window:AddDrag(label, value, [min, max]) -> drag float widget
 */
static int imgui_window_add_drag(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    float value = (float)luaL_optnumber(L, 3, 0.0);
    float min_val = (float)luaL_optnumber(L, 4, 0.0);
    float max_val = (float)luaL_optnumber(L, 5, 1.0);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_DRAG_SCALAR, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create drag widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.slider.value.x = value;
        obj->data.slider.min.x = min_val;
        obj->data.slider.max.x = max_val;
        obj->data.slider.components = 1;
    }

    imgui_push_handle(L, child, IMGUI_OBJ_DRAG_SCALAR);
    return 1;
}

/**
 * window:AddDragInt(label, value, [min, max]) -> drag int widget
 */
static int imgui_window_add_dragint(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    int value = (int)luaL_optinteger(L, 3, 0);
    int min_val = (int)luaL_optinteger(L, 4, 0);
    int max_val = (int)luaL_optinteger(L, 5, 100);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_DRAG_INT, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create drag int widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.slider_int.value[0] = value;
        obj->data.slider_int.min[0] = min_val;
        obj->data.slider_int.max[0] = max_val;
        obj->data.slider_int.components = 1;
    }

    imgui_push_handle(L, child, IMGUI_OBJ_DRAG_INT);
    return 1;
}

/**
 * window:AddInputInt(label, [value]) -> input int widget
 */
static int imgui_window_add_inputint(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    int value = (int)luaL_optinteger(L, 3, 0);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_INPUT_INT, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create input int widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.slider_int.value[0] = value;
        obj->data.slider_int.components = 1;
    }

    imgui_push_handle(L, child, IMGUI_OBJ_INPUT_INT);
    return 1;
}

/**
 * window:AddTree(label, [default_open]) -> tree node widget
 */
static int imgui_window_add_tree(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    bool default_open = lua_toboolean(L, 3);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_TREE, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create tree widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.tree.is_open = default_open;
        if (default_open) {
            obj->data.tree.flags = 0x20; // ImGuiTreeNodeFlags_DefaultOpen
        }
    }

    imgui_push_handle(L, child, IMGUI_OBJ_TREE);
    return 1;
}

/**
 * window:AddSelectable(label, [selected]) -> selectable widget
 */
static int imgui_window_add_selectable(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    bool selected = lua_toboolean(L, 3);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_SELECTABLE, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create selectable widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.selectable.selected = selected;
    }

    imgui_push_handle(L, child, IMGUI_OBJ_SELECTABLE);
    return 1;
}

/**
 * window:AddTable(label, columns, [flags]) -> table widget
 */
static int imgui_window_add_table(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    int columns = (int)luaL_checkinteger(L, 3);
    uint32_t flags = (uint32_t)luaL_optinteger(L, 4, 0);

    if (columns < 1 || columns > 64) {
        return luaL_error(L, "table columns must be between 1 and 64");
    }

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_TABLE, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create table widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.table.columns = columns;
        obj->data.table.flags = flags;
    }

    imgui_push_handle(L, child, IMGUI_OBJ_TABLE);
    return 1;
}

/**
 * table:AddTableRow([flags]) -> table row widget
 */
static int imgui_window_add_tablerow(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    uint32_t flags = (uint32_t)luaL_optinteger(L, 2, 0);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_TABLE_ROW, "##row");
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create table row widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.table_row.flags = flags;
    }

    imgui_push_handle(L, child, IMGUI_OBJ_TABLE_ROW);
    return 1;
}

/**
 * window:AddTabBar(label, [flags]) -> tab bar widget
 */
static int imgui_window_add_tabbar(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    uint32_t flags = (uint32_t)luaL_optinteger(L, 3, 0);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_TAB_BAR, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create tab bar widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.tab_bar.flags = flags;
    }

    imgui_push_handle(L, child, IMGUI_OBJ_TAB_BAR);
    return 1;
}

/**
 * tabbar:AddTabItem(label, [flags]) -> tab item widget
 */
static int imgui_window_add_tabitem(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    uint32_t flags = (uint32_t)luaL_optinteger(L, 3, 0);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_TAB_ITEM, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create tab item widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.tab_item.flags = flags;
    }

    imgui_push_handle(L, child, IMGUI_OBJ_TAB_ITEM);
    return 1;
}

/**
 * menu:AddMenuItem(label, [shortcut]) -> menu item widget
 */
static int imgui_window_add_menuitem(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    const char *shortcut = luaL_optstring(L, 3, NULL);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_MENU_ITEM, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create menu item widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.menu_item.enabled = true;
        if (shortcut) {
            strncpy(obj->data.menu_item.shortcut, shortcut, sizeof(obj->data.menu_item.shortcut) - 1);
            obj->data.menu_item.shortcut[sizeof(obj->data.menu_item.shortcut) - 1] = '\0';
        }
    }

    imgui_push_handle(L, child, IMGUI_OBJ_MENU_ITEM);
    return 1;
}

/**
 * window:AddPopup(label, [flags]) -> popup widget
 */
static int imgui_window_add_popup(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    uint32_t flags = (uint32_t)luaL_optinteger(L, 3, 0);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_POPUP, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create popup widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.popup.flags = flags;
        obj->data.popup.is_open = false;
    }

    imgui_push_handle(L, child, IMGUI_OBJ_POPUP);
    return 1;
}

/**
 * window:AddChildWindow(label, [width, height, flags]) -> child window widget
 */
static int imgui_window_add_childwindow(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *label = luaL_checkstring(L, 2);
    float width = (float)luaL_optnumber(L, 3, 0.0);
    float height = (float)luaL_optnumber(L, 4, 0.0);
    uint32_t flags = (uint32_t)luaL_optinteger(L, 5, 0);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_CHILD_WINDOW, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create child window widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        obj->data.child_window.size.x = width;
        obj->data.child_window.size.y = height;
        obj->data.child_window.has_size = (width > 0 || height > 0);
        obj->data.child_window.flags = flags;
    }

    imgui_push_handle(L, child, IMGUI_OBJ_CHILD_WINDOW);
    return 1;
}

/**
 * window:AddImage(path, [width], [height]) -> image widget
 * Adds an image widget. Currently renders as placeholder text until
 * texture loading backend is implemented (requires stb_image).
 */
static int imgui_window_add_image(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    const char *path = luaL_checkstring(L, 2);
    float width = (float)luaL_optnumber(L, 3, 100.0);
    float height = (float)luaL_optnumber(L, 4, 100.0);

    ImguiHandle child = imgui_object_create_child(ud->handle, IMGUI_OBJ_IMAGE, "##image");
    if (child == IMGUI_INVALID_HANDLE) {
        return luaL_error(L, "failed to create image widget");
    }

    ImguiObject *obj = imgui_object_get(child);
    if (obj) {
        strncpy(obj->data.image.image_path, path, sizeof(obj->data.image.image_path) - 1);
        obj->data.image.image_path[sizeof(obj->data.image.image_path) - 1] = '\0';
        obj->data.image.size.x = width;
        obj->data.image.size.y = height;
        obj->data.image.uv0 = (ImguiVec2){0, 0};
        obj->data.image.uv1 = (ImguiVec2){1, 1};
        obj->data.image.tint = (ImguiVec4){1, 1, 1, 1};
        obj->data.image.border = (ImguiVec4){0, 0, 0, 0};
    }

    imgui_push_handle(L, child, IMGUI_OBJ_IMAGE);
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

/**
 * widget:SetStyle(styleVar, value1, [value2])
 * Sets a style variable override for this widget.
 * styleVar: GuiStyleVar enum value
 * value1, value2: float values (value2 only for ImVec2 styles like padding)
 */
static int imgui_widget_set_style(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    int style_var = (int)luaL_checkinteger(L, 2);
    float value1 = (float)luaL_checknumber(L, 3);
    float value2 = (float)luaL_optnumber(L, 4, 0.0);

    imgui_object_set_style_var(ud->handle, style_var, value1, value2);
    return 0;
}

/**
 * widget:SetColor(colorId, r, g, b, [a])
 * Sets a color override for this widget.
 * colorId: GuiCol enum value
 * r, g, b, a: color components (0.0-1.0)
 */
static int imgui_widget_set_color(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    int color_id = (int)luaL_checkinteger(L, 2);
    float r = (float)luaL_checknumber(L, 3);
    float g = (float)luaL_checknumber(L, 4);
    float b = (float)luaL_checknumber(L, 5);
    float a = (float)luaL_optnumber(L, 6, 1.0);

    ImguiVec4 color = {r, g, b, a};
    imgui_object_set_style_color(ud->handle, color_id, color);
    return 0;
}

/**
 * widget:ClearStyle()
 * Clears all style overrides for this widget.
 */
static int imgui_widget_clear_style(lua_State *L) {
    ImguiUserdata *ud = imgui_to_userdata(L, 1);
    imgui_object_clear_style(ud->handle);
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
    if (strcmp(key, "SetStyle") == 0) {
        lua_pushcfunction(L, imgui_widget_set_style);
        return 1;
    }
    if (strcmp(key, "SetColor") == 0) {
        lua_pushcfunction(L, imgui_widget_set_color);
        return 1;
    }
    if (strcmp(key, "ClearStyle") == 0) {
        lua_pushcfunction(L, imgui_widget_clear_style);
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

    // Check for Add* methods on container widgets
    for (const luaL_Reg *method = window_methods; method->name != NULL; method++) {
        if (strcmp(key, method->name) == 0) {
            lua_pushcfunction(L, method->func);
            return 1;
        }
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

        case IMGUI_OBJ_INPUT_TEXT:
            if (strcmp(key, "Value") == 0 || strcmp(key, "Text") == 0) {
                lua_pushstring(L, obj->data.input_text.text);
                return 1;
            }
            if (strcmp(key, "Hint") == 0) {
                lua_pushstring(L, obj->data.input_text.hint);
                return 1;
            }
            if (strcmp(key, "Flags") == 0) {
                lua_pushinteger(L, obj->data.input_text.flags);
                return 1;
            }
            break;

        case IMGUI_OBJ_COMBO:
            if (strcmp(key, "SelectedIndex") == 0) {
                lua_pushinteger(L, obj->data.combo.selected_index + 1);  // Lua 1-indexed
                return 1;
            }
            if (strcmp(key, "Flags") == 0) {
                lua_pushinteger(L, obj->data.combo.flags);
                return 1;
            }
            break;

        case IMGUI_OBJ_SLIDER_SCALAR:
        case IMGUI_OBJ_DRAG_SCALAR:
            if (strcmp(key, "Value") == 0) {
                lua_pushnumber(L, obj->data.slider.value.x);
                return 1;
            }
            if (strcmp(key, "Min") == 0) {
                lua_pushnumber(L, obj->data.slider.min.x);
                return 1;
            }
            if (strcmp(key, "Max") == 0) {
                lua_pushnumber(L, obj->data.slider.max.x);
                return 1;
            }
            break;

        case IMGUI_OBJ_SLIDER_INT:
        case IMGUI_OBJ_DRAG_INT:
        case IMGUI_OBJ_INPUT_INT:
            if (strcmp(key, "Value") == 0) {
                lua_pushinteger(L, obj->data.slider_int.value[0]);
                return 1;
            }
            if (strcmp(key, "Min") == 0) {
                lua_pushinteger(L, obj->data.slider_int.min[0]);
                return 1;
            }
            if (strcmp(key, "Max") == 0) {
                lua_pushinteger(L, obj->data.slider_int.max[0]);
                return 1;
            }
            break;

        case IMGUI_OBJ_COLOR_EDIT:
        case IMGUI_OBJ_COLOR_PICKER:
            if (strcmp(key, "Color") == 0 || strcmp(key, "Value") == 0) {
                imgui_push_vec4(L, obj->data.color.color.x, obj->data.color.color.y,
                               obj->data.color.color.z, obj->data.color.color.w);
                return 1;
            }
            if (strcmp(key, "Flags") == 0) {
                lua_pushinteger(L, obj->data.color.flags);
                return 1;
            }
            break;

        case IMGUI_OBJ_PROGRESS_BAR:
            if (strcmp(key, "Value") == 0) {
                lua_pushnumber(L, obj->data.progress_bar.value);
                return 1;
            }
            if (strcmp(key, "Overlay") == 0) {
                lua_pushstring(L, obj->data.progress_bar.overlay);
                return 1;
            }
            break;

        case IMGUI_OBJ_RADIO_BUTTON:
            if (strcmp(key, "Active") == 0) {
                lua_pushboolean(L, obj->data.radio_button.active);
                return 1;
            }
            break;

        case IMGUI_OBJ_TREE:
            if (strcmp(key, "IsOpen") == 0 || strcmp(key, "Open") == 0) {
                lua_pushboolean(L, obj->data.tree.is_open);
                return 1;
            }
            if (strcmp(key, "Flags") == 0) {
                lua_pushinteger(L, obj->data.tree.flags);
                return 1;
            }
            break;

        case IMGUI_OBJ_SELECTABLE:
            if (strcmp(key, "Selected") == 0) {
                lua_pushboolean(L, obj->data.selectable.selected);
                return 1;
            }
            if (strcmp(key, "Flags") == 0) {
                lua_pushinteger(L, obj->data.selectable.flags);
                return 1;
            }
            break;

        case IMGUI_OBJ_TABLE:
            if (strcmp(key, "Columns") == 0) {
                lua_pushinteger(L, obj->data.table.columns);
                return 1;
            }
            if (strcmp(key, "Flags") == 0) {
                lua_pushinteger(L, obj->data.table.flags);
                return 1;
            }
            break;

        case IMGUI_OBJ_TAB_ITEM:
            if (strcmp(key, "IsSelected") == 0 || strcmp(key, "Selected") == 0) {
                lua_pushboolean(L, obj->data.tab_item.is_selected);
                return 1;
            }
            if (strcmp(key, "Flags") == 0) {
                lua_pushinteger(L, obj->data.tab_item.flags);
                return 1;
            }
            break;

        case IMGUI_OBJ_MENU:
            if (strcmp(key, "IsOpen") == 0 || strcmp(key, "Open") == 0) {
                lua_pushboolean(L, obj->data.menu.is_open);
                return 1;
            }
            break;

        case IMGUI_OBJ_MENU_ITEM:
            if (strcmp(key, "Enabled") == 0) {
                lua_pushboolean(L, obj->data.menu_item.enabled);
                return 1;
            }
            if (strcmp(key, "Shortcut") == 0) {
                lua_pushstring(L, obj->data.menu_item.shortcut);
                return 1;
            }
            break;

        case IMGUI_OBJ_POPUP:
            if (strcmp(key, "IsOpen") == 0 || strcmp(key, "Open") == 0) {
                lua_pushboolean(L, obj->data.popup.is_open);
                return 1;
            }
            if (strcmp(key, "Flags") == 0) {
                lua_pushinteger(L, obj->data.popup.flags);
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

    // Event callbacks - use helper to avoid duplication
    if (imgui_try_set_event(L, ud->handle, key, 3)) {
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

        case IMGUI_OBJ_INPUT_TEXT:
            if (strcmp(key, "Value") == 0 || strcmp(key, "Text") == 0) {
                const char *text = luaL_checkstring(L, 3);
                strncpy(obj->data.input_text.text, text, sizeof(obj->data.input_text.text) - 1);
                obj->data.input_text.text[sizeof(obj->data.input_text.text) - 1] = '\0';
                return 0;
            }
            if (strcmp(key, "Hint") == 0) {
                const char *hint = luaL_checkstring(L, 3);
                strncpy(obj->data.input_text.hint, hint, sizeof(obj->data.input_text.hint) - 1);
                obj->data.input_text.hint[sizeof(obj->data.input_text.hint) - 1] = '\0';
                return 0;
            }
            if (strcmp(key, "Flags") == 0) {
                obj->data.input_text.flags = (uint32_t)luaL_checkinteger(L, 3);
                return 0;
            }
            break;

        case IMGUI_OBJ_COMBO:
            if (strcmp(key, "SelectedIndex") == 0) {
                obj->data.combo.selected_index = (int)luaL_checkinteger(L, 3) - 1;  // Lua 1-indexed
                return 0;
            }
            if (strcmp(key, "Flags") == 0) {
                obj->data.combo.flags = (uint32_t)luaL_checkinteger(L, 3);
                return 0;
            }
            break;

        case IMGUI_OBJ_SLIDER_SCALAR:
        case IMGUI_OBJ_DRAG_SCALAR:
            if (strcmp(key, "Value") == 0) {
                obj->data.slider.value.x = (float)luaL_checknumber(L, 3);
                return 0;
            }
            if (strcmp(key, "Min") == 0) {
                obj->data.slider.min.x = (float)luaL_checknumber(L, 3);
                return 0;
            }
            if (strcmp(key, "Max") == 0) {
                obj->data.slider.max.x = (float)luaL_checknumber(L, 3);
                return 0;
            }
            break;

        case IMGUI_OBJ_SLIDER_INT:
        case IMGUI_OBJ_DRAG_INT:
        case IMGUI_OBJ_INPUT_INT:
            if (strcmp(key, "Value") == 0) {
                obj->data.slider_int.value[0] = (int)luaL_checkinteger(L, 3);
                return 0;
            }
            if (strcmp(key, "Min") == 0) {
                obj->data.slider_int.min[0] = (int)luaL_checkinteger(L, 3);
                return 0;
            }
            if (strcmp(key, "Max") == 0) {
                obj->data.slider_int.max[0] = (int)luaL_checkinteger(L, 3);
                return 0;
            }
            break;

        case IMGUI_OBJ_COLOR_EDIT:
        case IMGUI_OBJ_COLOR_PICKER:
            if (strcmp(key, "Color") == 0 || strcmp(key, "Value") == 0) {
                if (lua_istable(L, 3)) {
                    float x, y, z, w;
                    if (imgui_get_vec4(L, 3, &x, &y, &z, &w)) {
                        obj->data.color.color.x = x;
                        obj->data.color.color.y = y;
                        obj->data.color.color.z = z;
                        obj->data.color.color.w = w;
                    }
                }
                return 0;
            }
            if (strcmp(key, "Flags") == 0) {
                obj->data.color.flags = (uint32_t)luaL_checkinteger(L, 3);
                return 0;
            }
            break;

        case IMGUI_OBJ_PROGRESS_BAR:
            if (strcmp(key, "Value") == 0) {
                obj->data.progress_bar.value = (float)luaL_checknumber(L, 3);
                return 0;
            }
            if (strcmp(key, "Overlay") == 0) {
                const char *overlay = luaL_checkstring(L, 3);
                strncpy(obj->data.progress_bar.overlay, overlay, sizeof(obj->data.progress_bar.overlay) - 1);
                obj->data.progress_bar.overlay[sizeof(obj->data.progress_bar.overlay) - 1] = '\0';
                return 0;
            }
            break;

        case IMGUI_OBJ_RADIO_BUTTON:
            if (strcmp(key, "Active") == 0) {
                obj->data.radio_button.active = lua_toboolean(L, 3);
                return 0;
            }
            break;

        case IMGUI_OBJ_TREE:
            if (strcmp(key, "IsOpen") == 0 || strcmp(key, "Open") == 0) {
                obj->data.tree.is_open = lua_toboolean(L, 3);
                return 0;
            }
            if (strcmp(key, "Flags") == 0) {
                obj->data.tree.flags = (uint32_t)luaL_checkinteger(L, 3);
                return 0;
            }
            break;

        case IMGUI_OBJ_SELECTABLE:
            if (strcmp(key, "Selected") == 0) {
                obj->data.selectable.selected = lua_toboolean(L, 3);
                return 0;
            }
            if (strcmp(key, "Flags") == 0) {
                obj->data.selectable.flags = (uint32_t)luaL_checkinteger(L, 3);
                return 0;
            }
            break;

        case IMGUI_OBJ_TABLE:
            if (strcmp(key, "Flags") == 0) {
                obj->data.table.flags = (uint32_t)luaL_checkinteger(L, 3);
                return 0;
            }
            break;

        case IMGUI_OBJ_TAB_ITEM:
            if (strcmp(key, "Flags") == 0) {
                obj->data.tab_item.flags = (uint32_t)luaL_checkinteger(L, 3);
                return 0;
            }
            break;

        case IMGUI_OBJ_MENU_ITEM:
            if (strcmp(key, "Enabled") == 0) {
                obj->data.menu_item.enabled = lua_toboolean(L, 3);
                return 0;
            }
            if (strcmp(key, "Shortcut") == 0) {
                const char *shortcut = luaL_checkstring(L, 3);
                strncpy(obj->data.menu_item.shortcut, shortcut, sizeof(obj->data.menu_item.shortcut) - 1);
                obj->data.menu_item.shortcut[sizeof(obj->data.menu_item.shortcut) - 1] = '\0';
                return 0;
            }
            break;

        case IMGUI_OBJ_POPUP:
            if (strcmp(key, "IsOpen") == 0 || strcmp(key, "Open") == 0) {
                obj->data.popup.is_open = lua_toboolean(L, 3);
                return 0;
            }
            if (strcmp(key, "Flags") == 0) {
                obj->data.popup.flags = (uint32_t)luaL_checkinteger(L, 3);
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

    // Note: imgui_object_create() already registers windows internally

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

    // ========================================================================
    // Register ImGui enum tables
    // ========================================================================

    // GuiWindowFlags
    lua_newtable(L);
    lua_pushinteger(L, 0); lua_setfield(L, -2, "None");
    lua_pushinteger(L, 1 << 0); lua_setfield(L, -2, "NoTitleBar");
    lua_pushinteger(L, 1 << 1); lua_setfield(L, -2, "NoResize");
    lua_pushinteger(L, 1 << 2); lua_setfield(L, -2, "NoMove");
    lua_pushinteger(L, 1 << 3); lua_setfield(L, -2, "NoScrollbar");
    lua_pushinteger(L, 1 << 4); lua_setfield(L, -2, "NoScrollWithMouse");
    lua_pushinteger(L, 1 << 5); lua_setfield(L, -2, "NoCollapse");
    lua_pushinteger(L, 1 << 6); lua_setfield(L, -2, "AlwaysAutoResize");
    lua_pushinteger(L, 1 << 7); lua_setfield(L, -2, "NoBackground");
    lua_pushinteger(L, 1 << 8); lua_setfield(L, -2, "NoSavedSettings");
    lua_pushinteger(L, 1 << 9); lua_setfield(L, -2, "NoMouseInputs");
    lua_pushinteger(L, 1 << 10); lua_setfield(L, -2, "MenuBar");
    lua_pushinteger(L, 1 << 11); lua_setfield(L, -2, "HorizontalScrollbar");
    lua_pushinteger(L, 1 << 12); lua_setfield(L, -2, "NoFocusOnAppearing");
    lua_pushinteger(L, 1 << 13); lua_setfield(L, -2, "NoBringToFrontOnFocus");
    lua_pushinteger(L, 1 << 14); lua_setfield(L, -2, "AlwaysVerticalScrollbar");
    lua_pushinteger(L, 1 << 15); lua_setfield(L, -2, "AlwaysHorizontalScrollbar");
    lua_pushinteger(L, 1 << 18); lua_setfield(L, -2, "NoNavInputs");
    lua_pushinteger(L, 1 << 19); lua_setfield(L, -2, "NoNavFocus");
    lua_pushinteger(L, 1 << 20); lua_setfield(L, -2, "UnsavedDocument");
    lua_setfield(L, -2, "GuiWindowFlags");

    // GuiInputTextFlags
    lua_newtable(L);
    lua_pushinteger(L, 0); lua_setfield(L, -2, "None");
    lua_pushinteger(L, 1 << 0); lua_setfield(L, -2, "CharsDecimal");
    lua_pushinteger(L, 1 << 1); lua_setfield(L, -2, "CharsHexadecimal");
    lua_pushinteger(L, 1 << 2); lua_setfield(L, -2, "CharsUppercase");
    lua_pushinteger(L, 1 << 3); lua_setfield(L, -2, "CharsNoBlank");
    lua_pushinteger(L, 1 << 4); lua_setfield(L, -2, "AutoSelectAll");
    lua_pushinteger(L, 1 << 5); lua_setfield(L, -2, "EnterReturnsTrue");
    lua_pushinteger(L, 1 << 6); lua_setfield(L, -2, "CallbackCompletion");
    lua_pushinteger(L, 1 << 7); lua_setfield(L, -2, "CallbackHistory");
    lua_pushinteger(L, 1 << 8); lua_setfield(L, -2, "CallbackAlways");
    lua_pushinteger(L, 1 << 9); lua_setfield(L, -2, "CallbackCharFilter");
    lua_pushinteger(L, 1 << 10); lua_setfield(L, -2, "AllowTabInput");
    lua_pushinteger(L, 1 << 11); lua_setfield(L, -2, "CtrlEnterForNewLine");
    lua_pushinteger(L, 1 << 12); lua_setfield(L, -2, "NoHorizontalScroll");
    lua_pushinteger(L, 1 << 13); lua_setfield(L, -2, "AlwaysOverwrite");
    lua_pushinteger(L, 1 << 14); lua_setfield(L, -2, "ReadOnly");
    lua_pushinteger(L, 1 << 15); lua_setfield(L, -2, "Password");
    lua_setfield(L, -2, "GuiInputTextFlags");

    // GuiTreeNodeFlags
    lua_newtable(L);
    lua_pushinteger(L, 0); lua_setfield(L, -2, "None");
    lua_pushinteger(L, 1 << 0); lua_setfield(L, -2, "Selected");
    lua_pushinteger(L, 1 << 1); lua_setfield(L, -2, "Framed");
    lua_pushinteger(L, 1 << 2); lua_setfield(L, -2, "AllowOverlap");
    lua_pushinteger(L, 1 << 3); lua_setfield(L, -2, "NoTreePushOnOpen");
    lua_pushinteger(L, 1 << 4); lua_setfield(L, -2, "NoAutoOpenOnLog");
    lua_pushinteger(L, 1 << 5); lua_setfield(L, -2, "DefaultOpen");
    lua_pushinteger(L, 1 << 6); lua_setfield(L, -2, "OpenOnDoubleClick");
    lua_pushinteger(L, 1 << 7); lua_setfield(L, -2, "OpenOnArrow");
    lua_pushinteger(L, 1 << 8); lua_setfield(L, -2, "Leaf");
    lua_pushinteger(L, 1 << 9); lua_setfield(L, -2, "Bullet");
    lua_pushinteger(L, 1 << 10); lua_setfield(L, -2, "FramePadding");
    lua_pushinteger(L, 1 << 11); lua_setfield(L, -2, "SpanAvailWidth");
    lua_pushinteger(L, 1 << 12); lua_setfield(L, -2, "SpanFullWidth");
    lua_pushinteger(L, 1 << 13); lua_setfield(L, -2, "SpanAllColumns");
    lua_setfield(L, -2, "GuiTreeNodeFlags");

    // GuiSelectableFlags
    lua_newtable(L);
    lua_pushinteger(L, 0); lua_setfield(L, -2, "None");
    lua_pushinteger(L, 1 << 0); lua_setfield(L, -2, "DontClosePopups");
    lua_pushinteger(L, 1 << 1); lua_setfield(L, -2, "SpanAllColumns");
    lua_pushinteger(L, 1 << 2); lua_setfield(L, -2, "AllowDoubleClick");
    lua_pushinteger(L, 1 << 3); lua_setfield(L, -2, "Disabled");
    lua_pushinteger(L, 1 << 4); lua_setfield(L, -2, "AllowOverlap");
    lua_setfield(L, -2, "GuiSelectableFlags");

    // GuiTableFlags
    lua_newtable(L);
    lua_pushinteger(L, 0); lua_setfield(L, -2, "None");
    lua_pushinteger(L, 1 << 0); lua_setfield(L, -2, "Resizable");
    lua_pushinteger(L, 1 << 1); lua_setfield(L, -2, "Reorderable");
    lua_pushinteger(L, 1 << 2); lua_setfield(L, -2, "Hideable");
    lua_pushinteger(L, 1 << 3); lua_setfield(L, -2, "Sortable");
    lua_pushinteger(L, 1 << 4); lua_setfield(L, -2, "NoSavedSettings");
    lua_pushinteger(L, 1 << 5); lua_setfield(L, -2, "ContextMenuInBody");
    lua_pushinteger(L, 1 << 6); lua_setfield(L, -2, "RowBg");
    lua_pushinteger(L, 1 << 7); lua_setfield(L, -2, "BordersInnerH");
    lua_pushinteger(L, 1 << 8); lua_setfield(L, -2, "BordersOuterH");
    lua_pushinteger(L, 1 << 9); lua_setfield(L, -2, "BordersInnerV");
    lua_pushinteger(L, 1 << 10); lua_setfield(L, -2, "BordersOuterV");
    lua_pushinteger(L, (1 << 7) | (1 << 8)); lua_setfield(L, -2, "BordersH");
    lua_pushinteger(L, (1 << 9) | (1 << 10)); lua_setfield(L, -2, "BordersV");
    lua_pushinteger(L, (1 << 9) | (1 << 7)); lua_setfield(L, -2, "BordersInner");
    lua_pushinteger(L, (1 << 10) | (1 << 8)); lua_setfield(L, -2, "BordersOuter");
    lua_pushinteger(L, (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10)); lua_setfield(L, -2, "Borders");
    lua_pushinteger(L, 1 << 11); lua_setfield(L, -2, "NoBordersInBody");
    lua_pushinteger(L, 1 << 12); lua_setfield(L, -2, "NoBordersInBodyUntilResize");
    lua_pushinteger(L, 1 << 13); lua_setfield(L, -2, "SizingFixedFit");
    lua_pushinteger(L, 1 << 14); lua_setfield(L, -2, "SizingFixedSame");
    lua_pushinteger(L, 1 << 15); lua_setfield(L, -2, "SizingStretchProp");
    lua_pushinteger(L, 1 << 16); lua_setfield(L, -2, "SizingStretchSame");
    lua_pushinteger(L, 1 << 17); lua_setfield(L, -2, "NoHostExtendX");
    lua_pushinteger(L, 1 << 18); lua_setfield(L, -2, "NoHostExtendY");
    lua_pushinteger(L, 1 << 19); lua_setfield(L, -2, "NoKeepColumnsVisible");
    lua_pushinteger(L, 1 << 20); lua_setfield(L, -2, "PreciseWidths");
    lua_pushinteger(L, 1 << 21); lua_setfield(L, -2, "NoClip");
    lua_pushinteger(L, 1 << 22); lua_setfield(L, -2, "PadOuterX");
    lua_pushinteger(L, 1 << 23); lua_setfield(L, -2, "NoPadOuterX");
    lua_pushinteger(L, 1 << 24); lua_setfield(L, -2, "NoPadInnerX");
    lua_pushinteger(L, 1 << 25); lua_setfield(L, -2, "ScrollX");
    lua_pushinteger(L, 1 << 26); lua_setfield(L, -2, "ScrollY");
    lua_pushinteger(L, 1 << 27); lua_setfield(L, -2, "SortMulti");
    lua_pushinteger(L, 1 << 28); lua_setfield(L, -2, "SortTristate");
    lua_setfield(L, -2, "GuiTableFlags");

    // GuiTabBarFlags
    lua_newtable(L);
    lua_pushinteger(L, 0); lua_setfield(L, -2, "None");
    lua_pushinteger(L, 1 << 0); lua_setfield(L, -2, "Reorderable");
    lua_pushinteger(L, 1 << 1); lua_setfield(L, -2, "AutoSelectNewTabs");
    lua_pushinteger(L, 1 << 2); lua_setfield(L, -2, "TabListPopupButton");
    lua_pushinteger(L, 1 << 3); lua_setfield(L, -2, "NoCloseWithMiddleMouseButton");
    lua_pushinteger(L, 1 << 4); lua_setfield(L, -2, "NoTabListScrollingButtons");
    lua_pushinteger(L, 1 << 5); lua_setfield(L, -2, "NoTooltip");
    lua_pushinteger(L, 1 << 6); lua_setfield(L, -2, "FittingPolicyResizeDown");
    lua_pushinteger(L, 1 << 7); lua_setfield(L, -2, "FittingPolicyScroll");
    lua_setfield(L, -2, "GuiTabBarFlags");

    // GuiTabItemFlags
    lua_newtable(L);
    lua_pushinteger(L, 0); lua_setfield(L, -2, "None");
    lua_pushinteger(L, 1 << 0); lua_setfield(L, -2, "UnsavedDocument");
    lua_pushinteger(L, 1 << 1); lua_setfield(L, -2, "SetSelected");
    lua_pushinteger(L, 1 << 2); lua_setfield(L, -2, "NoCloseWithMiddleMouseButton");
    lua_pushinteger(L, 1 << 3); lua_setfield(L, -2, "NoPushId");
    lua_pushinteger(L, 1 << 4); lua_setfield(L, -2, "NoTooltip");
    lua_pushinteger(L, 1 << 5); lua_setfield(L, -2, "NoReorder");
    lua_pushinteger(L, 1 << 6); lua_setfield(L, -2, "Leading");
    lua_pushinteger(L, 1 << 7); lua_setfield(L, -2, "Trailing");
    lua_setfield(L, -2, "GuiTabItemFlags");

    // GuiColorEditFlags
    lua_newtable(L);
    lua_pushinteger(L, 0); lua_setfield(L, -2, "None");
    lua_pushinteger(L, 1 << 1); lua_setfield(L, -2, "NoAlpha");
    lua_pushinteger(L, 1 << 2); lua_setfield(L, -2, "NoPicker");
    lua_pushinteger(L, 1 << 3); lua_setfield(L, -2, "NoOptions");
    lua_pushinteger(L, 1 << 4); lua_setfield(L, -2, "NoSmallPreview");
    lua_pushinteger(L, 1 << 5); lua_setfield(L, -2, "NoInputs");
    lua_pushinteger(L, 1 << 6); lua_setfield(L, -2, "NoTooltip");
    lua_pushinteger(L, 1 << 7); lua_setfield(L, -2, "NoLabel");
    lua_pushinteger(L, 1 << 8); lua_setfield(L, -2, "NoSidePreview");
    lua_pushinteger(L, 1 << 9); lua_setfield(L, -2, "NoDragDrop");
    lua_pushinteger(L, 1 << 10); lua_setfield(L, -2, "NoBorder");
    lua_pushinteger(L, 1 << 16); lua_setfield(L, -2, "AlphaBar");
    lua_pushinteger(L, 1 << 17); lua_setfield(L, -2, "AlphaPreview");
    lua_pushinteger(L, 1 << 18); lua_setfield(L, -2, "AlphaPreviewHalf");
    lua_pushinteger(L, 1 << 19); lua_setfield(L, -2, "HDR");
    lua_pushinteger(L, 1 << 20); lua_setfield(L, -2, "DisplayRGB");
    lua_pushinteger(L, 1 << 21); lua_setfield(L, -2, "DisplayHSV");
    lua_pushinteger(L, 1 << 22); lua_setfield(L, -2, "DisplayHex");
    lua_pushinteger(L, 1 << 23); lua_setfield(L, -2, "Uint8");
    lua_pushinteger(L, 1 << 24); lua_setfield(L, -2, "Float");
    lua_pushinteger(L, 1 << 25); lua_setfield(L, -2, "PickerHueBar");
    lua_pushinteger(L, 1 << 26); lua_setfield(L, -2, "PickerHueWheel");
    lua_pushinteger(L, 1 << 27); lua_setfield(L, -2, "InputRGB");
    lua_pushinteger(L, 1 << 28); lua_setfield(L, -2, "InputHSV");
    lua_setfield(L, -2, "GuiColorEditFlags");

    // GuiPopupFlags
    lua_newtable(L);
    lua_pushinteger(L, 0); lua_setfield(L, -2, "None");
    lua_pushinteger(L, 0); lua_setfield(L, -2, "MouseButtonLeft");
    lua_pushinteger(L, 1); lua_setfield(L, -2, "MouseButtonRight");
    lua_pushinteger(L, 2); lua_setfield(L, -2, "MouseButtonMiddle");
    lua_pushinteger(L, 1 << 5); lua_setfield(L, -2, "NoOpenOverExistingPopup");
    lua_pushinteger(L, 1 << 6); lua_setfield(L, -2, "NoOpenOverItems");
    lua_pushinteger(L, 1 << 7); lua_setfield(L, -2, "AnyPopupId");
    lua_pushinteger(L, 1 << 8); lua_setfield(L, -2, "AnyPopupLevel");
    lua_pushinteger(L, (1 << 7) | (1 << 8)); lua_setfield(L, -2, "AnyPopup");
    lua_setfield(L, -2, "GuiPopupFlags");

    // GuiStyleVar - Style variable identifiers for PushStyleVar/PopStyleVar
    lua_newtable(L);
    lua_pushinteger(L, 0); lua_setfield(L, -2, "Alpha");
    lua_pushinteger(L, 1); lua_setfield(L, -2, "DisabledAlpha");
    lua_pushinteger(L, 2); lua_setfield(L, -2, "WindowPadding");
    lua_pushinteger(L, 3); lua_setfield(L, -2, "WindowRounding");
    lua_pushinteger(L, 4); lua_setfield(L, -2, "WindowBorderSize");
    lua_pushinteger(L, 5); lua_setfield(L, -2, "WindowMinSize");
    lua_pushinteger(L, 6); lua_setfield(L, -2, "WindowTitleAlign");
    lua_pushinteger(L, 7); lua_setfield(L, -2, "ChildRounding");
    lua_pushinteger(L, 8); lua_setfield(L, -2, "ChildBorderSize");
    lua_pushinteger(L, 9); lua_setfield(L, -2, "PopupRounding");
    lua_pushinteger(L, 10); lua_setfield(L, -2, "PopupBorderSize");
    lua_pushinteger(L, 11); lua_setfield(L, -2, "FramePadding");
    lua_pushinteger(L, 12); lua_setfield(L, -2, "FrameRounding");
    lua_pushinteger(L, 13); lua_setfield(L, -2, "FrameBorderSize");
    lua_pushinteger(L, 14); lua_setfield(L, -2, "ItemSpacing");
    lua_pushinteger(L, 15); lua_setfield(L, -2, "ItemInnerSpacing");
    lua_pushinteger(L, 16); lua_setfield(L, -2, "IndentSpacing");
    lua_pushinteger(L, 17); lua_setfield(L, -2, "CellPadding");
    lua_pushinteger(L, 18); lua_setfield(L, -2, "ScrollbarSize");
    lua_pushinteger(L, 19); lua_setfield(L, -2, "ScrollbarRounding");
    lua_pushinteger(L, 20); lua_setfield(L, -2, "ScrollbarPadding");
    lua_pushinteger(L, 21); lua_setfield(L, -2, "GrabMinSize");
    lua_pushinteger(L, 22); lua_setfield(L, -2, "GrabRounding");
    lua_pushinteger(L, 23); lua_setfield(L, -2, "ImageBorderSize");
    lua_pushinteger(L, 24); lua_setfield(L, -2, "TabRounding");
    lua_pushinteger(L, 25); lua_setfield(L, -2, "TabBorderSize");
    lua_pushinteger(L, 26); lua_setfield(L, -2, "TabMinWidthBase");
    lua_pushinteger(L, 27); lua_setfield(L, -2, "TabMinWidthShrink");
    lua_pushinteger(L, 28); lua_setfield(L, -2, "TabBarBorderSize");
    lua_pushinteger(L, 29); lua_setfield(L, -2, "TabBarOverlineSize");
    lua_pushinteger(L, 30); lua_setfield(L, -2, "TableAngledHeadersAngle");
    lua_pushinteger(L, 31); lua_setfield(L, -2, "TableAngledHeadersTextAlign");
    lua_pushinteger(L, 32); lua_setfield(L, -2, "TreeLinesSize");
    lua_pushinteger(L, 33); lua_setfield(L, -2, "TreeLinesRounding");
    lua_pushinteger(L, 34); lua_setfield(L, -2, "ButtonTextAlign");
    lua_pushinteger(L, 35); lua_setfield(L, -2, "SelectableTextAlign");
    lua_pushinteger(L, 36); lua_setfield(L, -2, "SeparatorTextBorderSize");
    lua_pushinteger(L, 37); lua_setfield(L, -2, "SeparatorTextAlign");
    lua_pushinteger(L, 38); lua_setfield(L, -2, "SeparatorTextPadding");
    lua_setfield(L, -2, "GuiStyleVar");

    // GuiCol - Color identifiers for PushStyleColor/PopStyleColor
    lua_newtable(L);
    lua_pushinteger(L, 0); lua_setfield(L, -2, "Text");
    lua_pushinteger(L, 1); lua_setfield(L, -2, "TextDisabled");
    lua_pushinteger(L, 2); lua_setfield(L, -2, "WindowBg");
    lua_pushinteger(L, 3); lua_setfield(L, -2, "ChildBg");
    lua_pushinteger(L, 4); lua_setfield(L, -2, "PopupBg");
    lua_pushinteger(L, 5); lua_setfield(L, -2, "Border");
    lua_pushinteger(L, 6); lua_setfield(L, -2, "BorderShadow");
    lua_pushinteger(L, 7); lua_setfield(L, -2, "FrameBg");
    lua_pushinteger(L, 8); lua_setfield(L, -2, "FrameBgHovered");
    lua_pushinteger(L, 9); lua_setfield(L, -2, "FrameBgActive");
    lua_pushinteger(L, 10); lua_setfield(L, -2, "TitleBg");
    lua_pushinteger(L, 11); lua_setfield(L, -2, "TitleBgActive");
    lua_pushinteger(L, 12); lua_setfield(L, -2, "TitleBgCollapsed");
    lua_pushinteger(L, 13); lua_setfield(L, -2, "MenuBarBg");
    lua_pushinteger(L, 14); lua_setfield(L, -2, "ScrollbarBg");
    lua_pushinteger(L, 15); lua_setfield(L, -2, "ScrollbarGrab");
    lua_pushinteger(L, 16); lua_setfield(L, -2, "ScrollbarGrabHovered");
    lua_pushinteger(L, 17); lua_setfield(L, -2, "ScrollbarGrabActive");
    lua_pushinteger(L, 18); lua_setfield(L, -2, "CheckMark");
    lua_pushinteger(L, 19); lua_setfield(L, -2, "SliderGrab");
    lua_pushinteger(L, 20); lua_setfield(L, -2, "SliderGrabActive");
    lua_pushinteger(L, 21); lua_setfield(L, -2, "Button");
    lua_pushinteger(L, 22); lua_setfield(L, -2, "ButtonHovered");
    lua_pushinteger(L, 23); lua_setfield(L, -2, "ButtonActive");
    lua_pushinteger(L, 24); lua_setfield(L, -2, "Header");
    lua_pushinteger(L, 25); lua_setfield(L, -2, "HeaderHovered");
    lua_pushinteger(L, 26); lua_setfield(L, -2, "HeaderActive");
    lua_pushinteger(L, 27); lua_setfield(L, -2, "Separator");
    lua_pushinteger(L, 28); lua_setfield(L, -2, "SeparatorHovered");
    lua_pushinteger(L, 29); lua_setfield(L, -2, "SeparatorActive");
    lua_pushinteger(L, 30); lua_setfield(L, -2, "ResizeGrip");
    lua_pushinteger(L, 31); lua_setfield(L, -2, "ResizeGripHovered");
    lua_pushinteger(L, 32); lua_setfield(L, -2, "ResizeGripActive");
    lua_pushinteger(L, 33); lua_setfield(L, -2, "InputTextCursor");
    lua_pushinteger(L, 34); lua_setfield(L, -2, "TabHovered");
    lua_pushinteger(L, 35); lua_setfield(L, -2, "Tab");
    lua_pushinteger(L, 36); lua_setfield(L, -2, "TabSelected");
    lua_pushinteger(L, 37); lua_setfield(L, -2, "TabSelectedOverline");
    lua_pushinteger(L, 38); lua_setfield(L, -2, "TabDimmed");
    lua_pushinteger(L, 39); lua_setfield(L, -2, "TabDimmedSelected");
    lua_pushinteger(L, 40); lua_setfield(L, -2, "TabDimmedSelectedOverline");
    lua_pushinteger(L, 41); lua_setfield(L, -2, "PlotLines");
    lua_pushinteger(L, 42); lua_setfield(L, -2, "PlotLinesHovered");
    lua_pushinteger(L, 43); lua_setfield(L, -2, "PlotHistogram");
    lua_pushinteger(L, 44); lua_setfield(L, -2, "PlotHistogramHovered");
    lua_pushinteger(L, 45); lua_setfield(L, -2, "TableHeaderBg");
    lua_pushinteger(L, 46); lua_setfield(L, -2, "TableBorderStrong");
    lua_pushinteger(L, 47); lua_setfield(L, -2, "TableBorderLight");
    lua_pushinteger(L, 48); lua_setfield(L, -2, "TableRowBg");
    lua_pushinteger(L, 49); lua_setfield(L, -2, "TableRowBgAlt");
    lua_pushinteger(L, 50); lua_setfield(L, -2, "TextLink");
    lua_pushinteger(L, 51); lua_setfield(L, -2, "TextSelectedBg");
    lua_pushinteger(L, 52); lua_setfield(L, -2, "TreeLines");
    lua_pushinteger(L, 53); lua_setfield(L, -2, "DragDropTarget");
    lua_pushinteger(L, 54); lua_setfield(L, -2, "DragDropTargetBg");
    lua_pushinteger(L, 55); lua_setfield(L, -2, "UnsavedMarker");
    lua_pushinteger(L, 56); lua_setfield(L, -2, "NavCursor");
    lua_pushinteger(L, 57); lua_setfield(L, -2, "NavWindowingHighlight");
    lua_pushinteger(L, 58); lua_setfield(L, -2, "NavWindowingDimBg");
    lua_pushinteger(L, 59); lua_setfield(L, -2, "ModalWindowDimBg");
    lua_setfield(L, -2, "GuiCol");

    // Set as Ext.IMGUI
    lua_setfield(L, ext_idx, "IMGUI");

    LOG_IMGUI_INFO("Registered Ext.IMGUI with %d functions",
                   (int)(sizeof(imgui_functions) / sizeof(imgui_functions[0]) - 1));
}

// ============================================================================
// Event Firing System
// ============================================================================

// Lua state for event callbacks (set during console_poll or game tick)
static lua_State *s_imgui_lua_state = NULL;

void lua_imgui_set_lua_state(lua_State *L) {
    s_imgui_lua_state = L;
}

lua_State *lua_imgui_get_lua_state(void) {
    return s_imgui_lua_state;
}

void lua_imgui_fire_event(ImguiHandle handle, ImguiEventType event, ...) {
    if (!s_imgui_lua_state) {
        LOG_IMGUI_DEBUG("No Lua state set, skipping event fire");
        return;
    }

    // Get the callback reference for this event
    int callback_ref = imgui_object_get_event(handle, event);
    if (callback_ref == -1 || callback_ref == LUA_NOREF || callback_ref == LUA_REFNIL) {
        // No callback registered for this event
        return;
    }

    lua_State *L = s_imgui_lua_state;

    // Get the callback function from registry
    lua_rawgeti(L, LUA_REGISTRYINDEX, callback_ref);
    if (!lua_isfunction(L, -1)) {
        LOG_IMGUI_WARN("Event callback is not a function (ref=%d)", callback_ref);
        lua_pop(L, 1);
        return;
    }

    // Push handle as first argument (userdata)
    ImguiObject *obj = imgui_object_get(handle);
    if (obj) {
        imgui_push_handle(L, handle, obj->type);
    } else {
        lua_pushnil(L);
    }

    // Push event-specific arguments
    int nargs = 1;  // Handle is always first arg
    va_list args;
    va_start(args, event);

    switch (event) {
        case IMGUI_EVENT_ON_CLICK:
        case IMGUI_EVENT_ON_CLOSE:
            // No additional arguments
            break;

        case IMGUI_EVENT_ON_CHANGE: {
            // For checkbox: push the new boolean value
            int new_value = va_arg(args, int);
            lua_pushboolean(L, new_value);
            nargs++;
            break;
        }

        default:
            break;
    }

    va_end(args);

    // Call the callback with protected call
    const char *event_name = (event == IMGUI_EVENT_ON_CLICK) ? "OnClick" :
                             (event == IMGUI_EVENT_ON_CLOSE) ? "OnClose" :
                             (event == IMGUI_EVENT_ON_CHANGE) ? "OnChange" : "Unknown";

    if (lua_pcall(L, nargs, 0, 0) != LUA_OK) {
        const char *err = lua_tostring(L, -1);
        LOG_IMGUI_ERROR("Error in %s callback: %s", event_name, err ? err : "(unknown error)");
        lua_pop(L, 1);
    } else {
        LOG_IMGUI_DEBUG("Fired %s event for handle 0x%llx", event_name, (unsigned long long)handle);
    }
}

void lua_imgui_cleanup_refs(ImguiHandle handle) {
    if (!s_imgui_lua_state) {
        return;
    }

    ImguiObject *obj = imgui_object_get(handle);
    if (!obj) {
        return;
    }

    lua_State *L = s_imgui_lua_state;

    // Release all event callback references
    for (int i = 0; i < IMGUI_EVENT_COUNT; i++) {
        int ref = obj->events[i].lua_ref;
        if (ref != -1 && ref != LUA_NOREF && ref != LUA_REFNIL) {
            luaL_unref(L, LUA_REGISTRYINDEX, ref);
            obj->events[i].lua_ref = -1;
            obj->events[i].enabled = false;
        }
    }

    // Release user data reference
    if (obj->user_data_ref != -1 && obj->user_data_ref != LUA_NOREF && obj->user_data_ref != LUA_REFNIL) {
        luaL_unref(L, LUA_REGISTRYINDEX, obj->user_data_ref);
        obj->user_data_ref = -1;
    }

    LOG_IMGUI_DEBUG("Cleaned up Lua refs for handle 0x%llx", (unsigned long long)handle);
}
