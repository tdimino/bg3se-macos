/**
 * imgui_objects.c - ImGui Object System Implementation
 *
 * Handle-based object pool with generation tracking for safe Lua bindings.
 */

#include "imgui_objects.h"
#include "../lua/lua_imgui.h"
#include "logging.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

// Global object pool
static ImguiObjectPool g_pool = {0};
static bool g_initialized = false;
static pthread_mutex_t g_pool_mutex = PTHREAD_MUTEX_INITIALIZER;

// Type name lookup
static const char* g_type_names[] = {
    [IMGUI_OBJ_NONE] = "None",
    [IMGUI_OBJ_WINDOW] = "Window",
    [IMGUI_OBJ_GROUP] = "Group",
    [IMGUI_OBJ_COLLAPSING_HEADER] = "CollapsingHeader",
    [IMGUI_OBJ_CHILD_WINDOW] = "ChildWindow",
    [IMGUI_OBJ_POPUP] = "Popup",
    [IMGUI_OBJ_TOOLTIP] = "Tooltip",
    [IMGUI_OBJ_MENU_BAR] = "MenuBar",
    [IMGUI_OBJ_MENU] = "Menu",
    [IMGUI_OBJ_TAB_BAR] = "TabBar",
    [IMGUI_OBJ_TAB_ITEM] = "TabItem",
    [IMGUI_OBJ_TABLE] = "Table",
    [IMGUI_OBJ_TABLE_ROW] = "TableRow",
    [IMGUI_OBJ_TABLE_CELL] = "TableCell",
    [IMGUI_OBJ_TREE] = "Tree",
    [IMGUI_OBJ_TEXT] = "Text",
    [IMGUI_OBJ_TEXT_LINK] = "TextLink",
    [IMGUI_OBJ_BULLET_TEXT] = "BulletText",
    [IMGUI_OBJ_SEPARATOR_TEXT] = "SeparatorText",
    [IMGUI_OBJ_IMAGE] = "Image",
    [IMGUI_OBJ_MENU_ITEM] = "MenuItem",
    [IMGUI_OBJ_SPACING] = "Spacing",
    [IMGUI_OBJ_DUMMY] = "Dummy",
    [IMGUI_OBJ_NEW_LINE] = "NewLine",
    [IMGUI_OBJ_SEPARATOR] = "Separator",
    [IMGUI_OBJ_BUTTON] = "Button",
    [IMGUI_OBJ_IMAGE_BUTTON] = "ImageButton",
    [IMGUI_OBJ_SELECTABLE] = "Selectable",
    [IMGUI_OBJ_CHECKBOX] = "Checkbox",
    [IMGUI_OBJ_RADIO_BUTTON] = "RadioButton",
    [IMGUI_OBJ_INPUT_TEXT] = "InputText",
    [IMGUI_OBJ_COMBO] = "Combo",
    [IMGUI_OBJ_DRAG_SCALAR] = "DragScalar",
    [IMGUI_OBJ_DRAG_INT] = "DragInt",
    [IMGUI_OBJ_SLIDER_SCALAR] = "SliderScalar",
    [IMGUI_OBJ_SLIDER_INT] = "SliderInt",
    [IMGUI_OBJ_INPUT_SCALAR] = "InputScalar",
    [IMGUI_OBJ_INPUT_INT] = "InputInt",
    [IMGUI_OBJ_COLOR_EDIT] = "ColorEdit",
    [IMGUI_OBJ_COLOR_PICKER] = "ColorPicker",
    [IMGUI_OBJ_PROGRESS_BAR] = "ProgressBar",
};

// Forward declarations
static void clear_object(ImguiObject* obj);
static void destroy_object_recursive(ImguiHandle handle);
static void imgui_register_window_internal(ImguiHandle handle);

void imgui_objects_init(void) {
    if (g_initialized) return;

    memset(&g_pool, 0, sizeof(g_pool));

    // Initialize all objects as free
    for (int i = 0; i < MAX_IMGUI_OBJECTS; i++) {
        g_pool.objects[i].in_use = false;
        g_pool.objects[i].handle = IMGUI_INVALID_HANDLE;
        g_pool.generations[i] = 1;  // Start at 1 so handle 0 is always invalid
        g_pool.free_indices[i] = MAX_IMGUI_OBJECTS - 1 - i;  // Stack order
    }
    g_pool.free_count = MAX_IMGUI_OBJECTS;
    g_pool.active_count = 0;

    // Initialize window tracking
    g_pool.window_capacity = 64;
    g_pool.windows = (ImguiHandle*)malloc(sizeof(ImguiHandle) * g_pool.window_capacity);
    g_pool.window_count = 0;

    g_initialized = true;
    LOG_IMGUI_DEBUG("Object pool initialized (max %d objects)", MAX_IMGUI_OBJECTS);
}

void imgui_objects_shutdown(void) {
    if (!g_initialized) return;

    // Destroy all active objects, cleaning up Lua refs first
    for (int i = 0; i < MAX_IMGUI_OBJECTS; i++) {
        if (g_pool.objects[i].in_use) {
            // Clean up Lua references before clearing
            lua_imgui_cleanup_refs(g_pool.objects[i].handle);
            clear_object(&g_pool.objects[i]);
        }
    }

    // Free window tracking
    if (g_pool.windows) {
        free(g_pool.windows);
        g_pool.windows = NULL;
    }

    g_initialized = false;
    LOG_IMGUI_DEBUG("Object pool shutdown");
}

static void clear_object(ImguiObject* obj) {
    if (!obj) return;

    // Free children array
    if (obj->children) {
        free(obj->children);
        obj->children = NULL;
    }
    obj->child_count = 0;
    obj->child_capacity = 0;

    // Free combo options if applicable
    if (obj->type == IMGUI_OBJ_COMBO && obj->data.combo.options) {
        for (int i = 0; i < obj->data.combo.option_count; i++) {
            if (obj->data.combo.options[i]) {
                free(obj->data.combo.options[i]);
            }
        }
        free(obj->data.combo.options);
        obj->data.combo.options = NULL;
        obj->data.combo.option_count = 0;
    }

    // Clear style overrides
    if (obj->style_overrides.style_vars) {
        free(obj->style_overrides.style_vars);
        obj->style_overrides.style_vars = NULL;
    }
    if (obj->style_overrides.style_values) {
        free(obj->style_overrides.style_values);
        obj->style_overrides.style_values = NULL;
    }
    if (obj->style_overrides.color_vars) {
        free(obj->style_overrides.color_vars);
        obj->style_overrides.color_vars = NULL;
    }
    if (obj->style_overrides.color_values) {
        free(obj->style_overrides.color_values);
        obj->style_overrides.color_values = NULL;
    }
    obj->style_overrides.style_count = 0;
    obj->style_overrides.color_count = 0;

    // Clear event callbacks (caller must handle Lua refs)
    for (int i = 0; i < IMGUI_EVENT_COUNT; i++) {
        obj->events[i].lua_ref = -1;  // LUA_REFNIL
        obj->events[i].enabled = false;
    }

    obj->user_data_ref = -1;

    // Reset object state
    obj->in_use = false;
    obj->destroyed = true;
    obj->type = IMGUI_OBJ_NONE;
    obj->parent = IMGUI_INVALID_HANDLE;
    memset(&obj->styled, 0, sizeof(obj->styled));
    memset(&obj->data, 0, sizeof(obj->data));
}

static void init_object_defaults(ImguiObject* obj, ImguiObjectType type) {
    // Common styled properties
    obj->styled.visible = true;
    obj->styled.same_line = false;
    obj->styled.same_position = false;
    obj->styled.was_hovered = false;
    obj->styled.can_drag = false;
    obj->styled.has_position_offset = false;
    obj->styled.has_absolute_position = false;
    obj->styled.has_item_width = false;
    obj->styled.has_text_wrap_pos = false;

    // Type-specific defaults
    switch (type) {
        case IMGUI_OBJ_WINDOW:
            obj->data.window.open = true;
            obj->data.window.closeable = true;
            obj->data.window.flags = 0;
            obj->data.window.has_size_constraints = false;
            obj->data.window.has_content_size = false;
            obj->data.window.collapsed = false;
            obj->data.window.has_bg_alpha = false;
            obj->data.window.scaling = 0;  // Absolute
            break;

        case IMGUI_OBJ_COLLAPSING_HEADER:
            obj->data.collapsing_header.flags = 0;
            obj->data.collapsing_header.is_open = true;
            break;

        case IMGUI_OBJ_CHILD_WINDOW:
            obj->data.child_window.has_size = false;
            obj->data.child_window.flags = 0;
            obj->data.child_window.child_flags = 0;
            break;

        case IMGUI_OBJ_BUTTON:
            obj->data.button.has_size = false;
            obj->data.button.flags = 0;
            break;

        case IMGUI_OBJ_TEXT:
            obj->data.text.has_color = false;
            break;

        case IMGUI_OBJ_CHECKBOX:
            obj->data.checkbox.checked = false;
            break;

        case IMGUI_OBJ_RADIO_BUTTON:
            obj->data.radio_button.active = false;
            break;

        case IMGUI_OBJ_INPUT_TEXT:
            obj->data.input_text.text[0] = '\0';
            obj->data.input_text.hint[0] = '\0';
            obj->data.input_text.has_size_hint = false;
            obj->data.input_text.flags = 0;
            break;

        case IMGUI_OBJ_COMBO:
            obj->data.combo.options = NULL;
            obj->data.combo.option_count = 0;
            obj->data.combo.selected_index = 0;
            obj->data.combo.flags = 0;
            break;

        case IMGUI_OBJ_SLIDER_SCALAR:
        case IMGUI_OBJ_DRAG_SCALAR:
        case IMGUI_OBJ_INPUT_SCALAR:
            obj->data.slider.value = (ImguiVec4){0, 0, 0, 0};
            obj->data.slider.min = (ImguiVec4){0, 0, 0, 0};
            obj->data.slider.max = (ImguiVec4){1, 1, 1, 1};
            obj->data.slider.components = 1;
            obj->data.slider.flags = 0;
            obj->data.slider.is_vertical = false;
            break;

        case IMGUI_OBJ_SLIDER_INT:
        case IMGUI_OBJ_DRAG_INT:
        case IMGUI_OBJ_INPUT_INT:
            memset(obj->data.slider_int.value, 0, sizeof(obj->data.slider_int.value));
            memset(obj->data.slider_int.min, 0, sizeof(obj->data.slider_int.min));
            obj->data.slider_int.max[0] = 100;
            obj->data.slider_int.max[1] = 100;
            obj->data.slider_int.max[2] = 100;
            obj->data.slider_int.max[3] = 100;
            obj->data.slider_int.components = 1;
            obj->data.slider_int.flags = 0;
            obj->data.slider_int.is_vertical = false;
            break;

        case IMGUI_OBJ_COLOR_EDIT:
        case IMGUI_OBJ_COLOR_PICKER:
            obj->data.color.color = (ImguiVec4){1, 1, 1, 1};
            obj->data.color.flags = 0;
            break;

        case IMGUI_OBJ_PROGRESS_BAR:
            obj->data.progress_bar.value = 0.0f;
            obj->data.progress_bar.size = (ImguiVec2){-1, 0};  // Auto width
            obj->data.progress_bar.overlay[0] = '\0';
            break;

        case IMGUI_OBJ_TREE:
            obj->data.tree.flags = 0;
            obj->data.tree.is_open = false;
            break;

        case IMGUI_OBJ_TABLE:
            obj->data.table.columns = 1;
            obj->data.table.flags = 0;
            obj->data.table.freeze_rows = 0;
            obj->data.table.freeze_cols = 0;
            obj->data.table.show_header = false;
            obj->data.table.angled_header = false;
            obj->data.table.optimized_draw = false;
            obj->data.table.has_size = false;
            break;

        case IMGUI_OBJ_TABLE_ROW:
            obj->data.table_row.flags = 0;
            break;

        case IMGUI_OBJ_TAB_BAR:
            obj->data.tab_bar.flags = 0;
            break;

        case IMGUI_OBJ_TAB_ITEM:
            obj->data.tab_item.flags = 0;
            obj->data.tab_item.is_selected = false;
            break;

        case IMGUI_OBJ_MENU:
            obj->data.menu.is_open = false;
            break;

        case IMGUI_OBJ_MENU_ITEM:
            obj->data.menu_item.enabled = true;
            obj->data.menu_item.shortcut[0] = '\0';
            break;

        case IMGUI_OBJ_SELECTABLE:
            obj->data.selectable.has_size = false;
            obj->data.selectable.flags = 0;
            obj->data.selectable.selected = false;
            break;

        case IMGUI_OBJ_DUMMY:
            obj->data.dummy.width = 0;
            obj->data.dummy.height = 0;
            break;

        case IMGUI_OBJ_IMAGE:
            obj->data.image.image_path[0] = '\0';
            obj->data.image.size = (ImguiVec2){0, 0};
            obj->data.image.uv0 = (ImguiVec2){0, 0};
            obj->data.image.uv1 = (ImguiVec2){1, 1};
            obj->data.image.tint = (ImguiVec4){1, 1, 1, 1};
            obj->data.image.border = (ImguiVec4){0, 0, 0, 0};
            break;

        case IMGUI_OBJ_POPUP:
            obj->data.popup.flags = 0;
            obj->data.popup.popup_flags = 0;
            obj->data.popup.is_open = false;
            break;

        default:
            break;
    }

    // Initialize event callbacks as not set
    for (int i = 0; i < IMGUI_EVENT_COUNT; i++) {
        obj->events[i].lua_ref = -1;
        obj->events[i].enabled = false;
    }
    obj->user_data_ref = -1;
}

ImguiHandle imgui_object_create(ImguiObjectType type, const char* label) {
    if (!g_initialized) {
        imgui_objects_init();
    }

    pthread_mutex_lock(&g_pool_mutex);

    if (g_pool.free_count == 0) {
        pthread_mutex_unlock(&g_pool_mutex);
        LOG_IMGUI_ERROR("Object pool exhausted (max %d)", MAX_IMGUI_OBJECTS);
        return IMGUI_INVALID_HANDLE;
    }

    // Get a free index
    int index = g_pool.free_indices[--g_pool.free_count];
    ImguiObject* obj = &g_pool.objects[index];

    // Increment generation to invalidate old handles
    uint32_t generation = ++g_pool.generations[index];

    // Initialize object
    memset(obj, 0, sizeof(ImguiObject));
    obj->handle = IMGUI_MAKE_HANDLE(index, generation);
    obj->type = type;
    obj->generation = generation;
    obj->in_use = true;
    obj->destroyed = false;
    obj->parent = IMGUI_INVALID_HANDLE;

    // Copy label
    if (label) {
        strncpy(obj->styled.label, label, IMGUI_LABEL_MAX - 1);
        obj->styled.label[IMGUI_LABEL_MAX - 1] = '\0';
    }

    // Set type-specific defaults
    init_object_defaults(obj, type);

    g_pool.active_count++;

    // If it's a window, register it (while still holding lock)
    if (type == IMGUI_OBJ_WINDOW) {
        imgui_register_window_internal(obj->handle);
    }

    pthread_mutex_unlock(&g_pool_mutex);

    LOG_IMGUI_DEBUG("Created %s '%s' (handle=0x%llx, idx=%d, gen=%u)",
        imgui_object_type_name(type), label ? label : "", obj->handle, index, generation);

    return obj->handle;
}

ImguiHandle imgui_object_create_child(ImguiHandle parent, ImguiObjectType type, const char* label) {
    ImguiObject* parent_obj = imgui_object_get(parent);
    if (!parent_obj) {
        LOG_IMGUI_ERROR("Cannot create child: invalid parent handle 0x%llx", parent);
        return IMGUI_INVALID_HANDLE;
    }

    ImguiHandle child = imgui_object_create(type, label);
    if (child == IMGUI_INVALID_HANDLE) {
        return IMGUI_INVALID_HANDLE;
    }

    ImguiObject* child_obj = imgui_object_get(child);
    if (child_obj) {
        child_obj->parent = parent;
        imgui_object_add_child(parent, child);
    }

    return child;
}

static void destroy_object_recursive(ImguiHandle handle) {
    ImguiObject* obj = imgui_object_get(handle);
    if (!obj) return;

    // Destroy children first
    if (obj->children && obj->child_count > 0) {
        // Copy children array since it will be modified
        int count = obj->child_count;
        ImguiHandle* children = (ImguiHandle*)malloc(sizeof(ImguiHandle) * count);
        if (children) {
            memcpy(children, obj->children, sizeof(ImguiHandle) * count);

            for (int i = 0; i < count; i++) {
                destroy_object_recursive(children[i]);
            }
            free(children);
        }
    }

    // Unregister window if applicable
    if (obj->type == IMGUI_OBJ_WINDOW) {
        imgui_unregister_window(handle);
    }

    // Remove from parent
    if (obj->parent != IMGUI_INVALID_HANDLE) {
        imgui_object_remove_child(obj->parent, handle);
    }

    // Clean up Lua references before clearing the object
    lua_imgui_cleanup_refs(handle);

    // Return to free list
    int index = IMGUI_HANDLE_INDEX(handle);
    clear_object(obj);
    g_pool.free_indices[g_pool.free_count++] = index;
    g_pool.active_count--;

    LOG_IMGUI_DEBUG("Destroyed object handle=0x%llx", handle);
}

void imgui_object_destroy(ImguiHandle handle) {
    if (handle == IMGUI_INVALID_HANDLE) return;
    destroy_object_recursive(handle);
}

void imgui_object_destroy_children(ImguiHandle handle) {
    ImguiObject* obj = imgui_object_get(handle);
    if (!obj || !obj->children) return;

    // Copy children array since destroy modifies it
    int count = obj->child_count;
    ImguiHandle* children = (ImguiHandle*)malloc(sizeof(ImguiHandle) * count);
    memcpy(children, obj->children, sizeof(ImguiHandle) * count);

    for (int i = 0; i < count; i++) {
        imgui_object_destroy(children[i]);
    }
    free(children);
}

ImguiObject* imgui_object_get(ImguiHandle handle) {
    if (handle == IMGUI_INVALID_HANDLE) return NULL;

    uint32_t index = IMGUI_HANDLE_INDEX(handle);
    uint32_t generation = IMGUI_HANDLE_GEN(handle);

    if (index >= MAX_IMGUI_OBJECTS) return NULL;

    ImguiObject* obj = &g_pool.objects[index];
    if (!obj->in_use || obj->generation != generation) {
        return NULL;  // Stale handle
    }

    return obj;
}

bool imgui_object_is_valid(ImguiHandle handle) {
    return imgui_object_get(handle) != NULL;
}

const char* imgui_object_type_name(ImguiObjectType type) {
    if (type < 0 || type >= IMGUI_OBJ_TYPE_COUNT) {
        return "Unknown";
    }
    return g_type_names[type];
}

bool imgui_object_add_child(ImguiHandle parent, ImguiHandle child) {
    ImguiObject* parent_obj = imgui_object_get(parent);
    if (!parent_obj) return false;

    // Grow children array if needed
    if (parent_obj->child_count >= parent_obj->child_capacity) {
        int new_cap = parent_obj->child_capacity == 0 ? 8 : parent_obj->child_capacity * 2;
        if (new_cap > MAX_IMGUI_CHILDREN) new_cap = MAX_IMGUI_CHILDREN;

        ImguiHandle* new_children = (ImguiHandle*)realloc(
            parent_obj->children, sizeof(ImguiHandle) * new_cap);
        if (!new_children) return false;

        parent_obj->children = new_children;
        parent_obj->child_capacity = new_cap;
    }

    parent_obj->children[parent_obj->child_count++] = child;
    return true;
}

bool imgui_object_remove_child(ImguiHandle parent, ImguiHandle child) {
    ImguiObject* parent_obj = imgui_object_get(parent);
    if (!parent_obj || !parent_obj->children) return false;

    for (int i = 0; i < parent_obj->child_count; i++) {
        if (parent_obj->children[i] == child) {
            // Shift remaining children
            for (int j = i; j < parent_obj->child_count - 1; j++) {
                parent_obj->children[j] = parent_obj->children[j + 1];
            }
            parent_obj->child_count--;
            return true;
        }
    }
    return false;
}

bool imgui_object_detach_child(ImguiHandle parent, ImguiHandle child) {
    ImguiObject* child_obj = imgui_object_get(child);
    if (!child_obj) return false;

    if (imgui_object_remove_child(parent, child)) {
        child_obj->parent = IMGUI_INVALID_HANDLE;
        return true;
    }
    return false;
}

bool imgui_object_attach_child(ImguiHandle parent, ImguiHandle child) {
    ImguiObject* child_obj = imgui_object_get(child);
    if (!child_obj) return false;

    // Detach from current parent if any
    if (child_obj->parent != IMGUI_INVALID_HANDLE) {
        imgui_object_detach_child(child_obj->parent, child);
    }

    child_obj->parent = parent;
    return imgui_object_add_child(parent, child);
}

ImguiHandle* imgui_object_get_children(ImguiHandle parent, int* count) {
    ImguiObject* obj = imgui_object_get(parent);
    if (!obj) {
        if (count) *count = 0;
        return NULL;
    }
    if (count) *count = obj->child_count;
    return obj->children;
}

ImguiHandle* imgui_get_all_windows(int* count) {
    pthread_mutex_lock(&g_pool_mutex);
    if (count) *count = g_pool.window_count;
    ImguiHandle* result = g_pool.windows;
    pthread_mutex_unlock(&g_pool_mutex);
    return result;
}

// Internal version without locking (called while lock is held)
static void imgui_register_window_internal(ImguiHandle handle) {
    // Grow window array if needed
    if (g_pool.window_count >= g_pool.window_capacity) {
        int new_cap = g_pool.window_capacity * 2;
        ImguiHandle* new_windows = (ImguiHandle*)realloc(
            g_pool.windows, sizeof(ImguiHandle) * new_cap);
        if (!new_windows) return;

        g_pool.windows = new_windows;
        g_pool.window_capacity = new_cap;
    }

    g_pool.windows[g_pool.window_count++] = handle;
    LOG_IMGUI_DEBUG("Registered window 0x%llx (total: %d)", handle, g_pool.window_count);
}

void imgui_register_window(ImguiHandle handle) {
    pthread_mutex_lock(&g_pool_mutex);
    imgui_register_window_internal(handle);
    pthread_mutex_unlock(&g_pool_mutex);
}

void imgui_unregister_window(ImguiHandle handle) {
    for (int i = 0; i < g_pool.window_count; i++) {
        if (g_pool.windows[i] == handle) {
            for (int j = i; j < g_pool.window_count - 1; j++) {
                g_pool.windows[j] = g_pool.windows[j + 1];
            }
            g_pool.window_count--;
            LOG_IMGUI_DEBUG("Unregistered window 0x%llx (remaining: %d)",
                handle, g_pool.window_count);
            return;
        }
    }
}

void imgui_object_set_event(ImguiHandle handle, ImguiEventType event, int lua_ref) {
    ImguiObject* obj = imgui_object_get(handle);
    if (!obj || event < 0 || event >= IMGUI_EVENT_COUNT) return;

    obj->events[event].lua_ref = lua_ref;
    obj->events[event].enabled = (lua_ref != -1);
}

int imgui_object_get_event(ImguiHandle handle, ImguiEventType event) {
    ImguiObject* obj = imgui_object_get(handle);
    if (!obj || event < 0 || event >= IMGUI_EVENT_COUNT) return -1;
    return obj->events[event].lua_ref;
}

void imgui_object_clear_event(ImguiHandle handle, ImguiEventType event) {
    imgui_object_set_event(handle, event, -1);
}

void imgui_object_set_user_data(ImguiHandle handle, int lua_ref) {
    ImguiObject* obj = imgui_object_get(handle);
    if (obj) obj->user_data_ref = lua_ref;
}

int imgui_object_get_user_data(ImguiHandle handle) {
    ImguiObject* obj = imgui_object_get(handle);
    return obj ? obj->user_data_ref : -1;
}

void imgui_object_set_style_var(ImguiHandle handle, int var, float value1, float value2) {
    ImguiObject* obj = imgui_object_get(handle);
    if (!obj) return;

    // Find existing or add new
    for (int i = 0; i < obj->style_overrides.style_count; i++) {
        if (obj->style_overrides.style_vars[i] == var) {
            obj->style_overrides.style_values[i * 2] = value1;
            obj->style_overrides.style_values[i * 2 + 1] = value2;
            return;
        }
    }

    // Add new
    int new_count = obj->style_overrides.style_count + 1;
    int* new_vars = (int*)realloc(obj->style_overrides.style_vars, sizeof(int) * new_count);
    float* new_vals = (float*)realloc(obj->style_overrides.style_values, sizeof(float) * new_count * 2);
    if (!new_vars || !new_vals) return;

    obj->style_overrides.style_vars = new_vars;
    obj->style_overrides.style_values = new_vals;
    obj->style_overrides.style_vars[obj->style_overrides.style_count] = var;
    obj->style_overrides.style_values[obj->style_overrides.style_count * 2] = value1;
    obj->style_overrides.style_values[obj->style_overrides.style_count * 2 + 1] = value2;
    obj->style_overrides.style_count = new_count;
}

void imgui_object_set_style_color(ImguiHandle handle, int color, ImguiVec4 value) {
    ImguiObject* obj = imgui_object_get(handle);
    if (!obj) return;

    // Find existing or add new
    for (int i = 0; i < obj->style_overrides.color_count; i++) {
        if (obj->style_overrides.color_vars[i] == color) {
            obj->style_overrides.color_values[i] = value;
            return;
        }
    }

    // Add new
    int new_count = obj->style_overrides.color_count + 1;
    int* new_vars = (int*)realloc(obj->style_overrides.color_vars, sizeof(int) * new_count);
    ImguiVec4* new_vals = (ImguiVec4*)realloc(obj->style_overrides.color_values, sizeof(ImguiVec4) * new_count);
    if (!new_vars || !new_vals) return;

    obj->style_overrides.color_vars = new_vars;
    obj->style_overrides.color_values = new_vals;
    obj->style_overrides.color_vars[obj->style_overrides.color_count] = color;
    obj->style_overrides.color_values[obj->style_overrides.color_count] = value;
    obj->style_overrides.color_count = new_count;
}

void imgui_object_clear_style(ImguiHandle handle) {
    ImguiObject* obj = imgui_object_get(handle);
    if (!obj) return;

    if (obj->style_overrides.style_vars) {
        free(obj->style_overrides.style_vars);
        obj->style_overrides.style_vars = NULL;
    }
    if (obj->style_overrides.style_values) {
        free(obj->style_overrides.style_values);
        obj->style_overrides.style_values = NULL;
    }
    if (obj->style_overrides.color_vars) {
        free(obj->style_overrides.color_vars);
        obj->style_overrides.color_vars = NULL;
    }
    if (obj->style_overrides.color_values) {
        free(obj->style_overrides.color_values);
        obj->style_overrides.color_values = NULL;
    }
    obj->style_overrides.style_count = 0;
    obj->style_overrides.color_count = 0;
}

void imgui_objects_dump_stats(void) {
    LOG_IMGUI_INFO("Object Pool Stats:");
    LOG_IMGUI_INFO("  Active: %d / %d", g_pool.active_count, MAX_IMGUI_OBJECTS);
    LOG_IMGUI_INFO("  Free: %d", g_pool.free_count);
    LOG_IMGUI_INFO("  Windows: %d", g_pool.window_count);

    // Count by type
    int type_counts[IMGUI_OBJ_TYPE_COUNT] = {0};
    for (int i = 0; i < MAX_IMGUI_OBJECTS; i++) {
        if (g_pool.objects[i].in_use) {
            type_counts[g_pool.objects[i].type]++;
        }
    }

    for (int t = 1; t < IMGUI_OBJ_TYPE_COUNT; t++) {
        if (type_counts[t] > 0) {
            LOG_IMGUI_INFO("  %s: %d", g_type_names[t], type_counts[t]);
        }
    }
}

int imgui_objects_get_window_count(void) {
    return g_pool.window_count;
}

int imgui_objects_get_total_count(void) {
    return g_pool.active_count;
}
