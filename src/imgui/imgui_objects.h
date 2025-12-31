/**
 * imgui_objects.h - ImGui Object System for BG3SE-macOS
 *
 * Handle-based object management for ImGui widgets exposed to Lua.
 * Implements generation-based handles to prevent stale reference bugs.
 */

#ifndef IMGUI_OBJECTS_H
#define IMGUI_OBJECTS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Configuration
#define MAX_IMGUI_OBJECTS 4096
#define MAX_IMGUI_CHILDREN 256
#define IMGUI_LABEL_MAX 256
#define IMGUI_INVALID_HANDLE 0

// Object types - matches Windows BG3SE widget hierarchy
typedef enum {
    IMGUI_OBJ_NONE = 0,

    // Container widgets (TreeParent)
    IMGUI_OBJ_WINDOW,
    IMGUI_OBJ_GROUP,
    IMGUI_OBJ_COLLAPSING_HEADER,
    IMGUI_OBJ_CHILD_WINDOW,
    IMGUI_OBJ_POPUP,
    IMGUI_OBJ_TOOLTIP,
    IMGUI_OBJ_MENU_BAR,
    IMGUI_OBJ_MENU,

    // Tab widgets
    IMGUI_OBJ_TAB_BAR,
    IMGUI_OBJ_TAB_ITEM,

    // Table widgets
    IMGUI_OBJ_TABLE,
    IMGUI_OBJ_TABLE_ROW,
    IMGUI_OBJ_TABLE_CELL,

    // Tree widget
    IMGUI_OBJ_TREE,

    // Display widgets
    IMGUI_OBJ_TEXT,
    IMGUI_OBJ_TEXT_LINK,
    IMGUI_OBJ_BULLET_TEXT,
    IMGUI_OBJ_SEPARATOR_TEXT,
    IMGUI_OBJ_IMAGE,
    IMGUI_OBJ_MENU_ITEM,

    // Layout widgets
    IMGUI_OBJ_SPACING,
    IMGUI_OBJ_DUMMY,
    IMGUI_OBJ_NEW_LINE,
    IMGUI_OBJ_SEPARATOR,

    // Button widgets
    IMGUI_OBJ_BUTTON,
    IMGUI_OBJ_IMAGE_BUTTON,
    IMGUI_OBJ_SELECTABLE,

    // Input widgets
    IMGUI_OBJ_CHECKBOX,
    IMGUI_OBJ_RADIO_BUTTON,
    IMGUI_OBJ_INPUT_TEXT,
    IMGUI_OBJ_COMBO,

    // Slider/Drag widgets
    IMGUI_OBJ_DRAG_SCALAR,
    IMGUI_OBJ_DRAG_INT,
    IMGUI_OBJ_SLIDER_SCALAR,
    IMGUI_OBJ_SLIDER_INT,
    IMGUI_OBJ_INPUT_SCALAR,
    IMGUI_OBJ_INPUT_INT,

    // Color widgets
    IMGUI_OBJ_COLOR_EDIT,
    IMGUI_OBJ_COLOR_PICKER,

    // Progress widget
    IMGUI_OBJ_PROGRESS_BAR,

    IMGUI_OBJ_TYPE_COUNT
} ImguiObjectType;

// Handle: 64-bit value (32-bit index + 32-bit generation)
// Generation prevents use-after-free bugs
typedef uint64_t ImguiHandle;

// Extract index and generation from handle
#define IMGUI_HANDLE_INDEX(h) ((uint32_t)((h) & 0xFFFFFFFF))
#define IMGUI_HANDLE_GEN(h) ((uint32_t)(((h) >> 32) & 0xFFFFFFFF))
#define IMGUI_MAKE_HANDLE(idx, gen) (((uint64_t)(gen) << 32) | (uint64_t)(idx))

// Event types
typedef enum {
    IMGUI_EVENT_NONE = 0,
    IMGUI_EVENT_ON_CLICK,
    IMGUI_EVENT_ON_RIGHT_CLICK,
    IMGUI_EVENT_ON_ACTIVATE,
    IMGUI_EVENT_ON_DEACTIVATE,
    IMGUI_EVENT_ON_HOVER_ENTER,
    IMGUI_EVENT_ON_HOVER_LEAVE,
    IMGUI_EVENT_ON_CHANGE,
    IMGUI_EVENT_ON_CLOSE,
    IMGUI_EVENT_ON_EXPAND,
    IMGUI_EVENT_ON_COLLAPSE,
    IMGUI_EVENT_ON_SORT_CHANGED,
    IMGUI_EVENT_ON_DRAG_START,
    IMGUI_EVENT_ON_DRAG_END,
    IMGUI_EVENT_ON_DRAG_DROP,
    IMGUI_EVENT_COUNT
} ImguiEventType;

// Forward declarations
struct ImguiObject;
struct lua_State;

// Event callback info (stores Lua function reference)
typedef struct {
    int lua_ref;        // LUA_REFNIL if not set
    bool enabled;
} ImguiEventCallback;

// Vec2 for positions/sizes
typedef struct {
    float x;
    float y;
} ImguiVec2;

// Vec4 for colors
typedef struct {
    float x, y, z, w;
} ImguiVec4;

// Common properties for all styled widgets (StyledRenderable base)
typedef struct {
    char label[IMGUI_LABEL_MAX];
    char id_context[64];
    bool visible;
    bool same_line;
    bool same_position;
    bool was_hovered;
    bool can_drag;
    char font[64];
    ImguiVec2 position_offset;
    bool has_position_offset;
    ImguiVec2 absolute_position;
    bool has_absolute_position;
    float item_width;
    bool has_item_width;
    float text_wrap_pos;
    bool has_text_wrap_pos;
    uint32_t item_flags;
    uint32_t status_flags;
    uint32_t drag_flags;
    uint32_t drop_flags;
} ImguiStyledProps;

// Window-specific data
typedef struct {
    bool open;
    bool closeable;
    uint32_t flags;  // ImGuiWindowFlags
    ImguiVec2 size;
    ImguiVec2 pos;
    ImguiVec2 size_constraints_min;
    ImguiVec2 size_constraints_max;
    bool has_size_constraints;
    ImguiVec2 content_size;
    bool has_content_size;
    bool collapsed;
    float bg_alpha;
    bool has_bg_alpha;
    int scaling;  // GuiMeasureScaling enum
} ImguiWindowData;

// Group-specific data (minimal)
typedef struct {
    // Groups have no special properties beyond StyledProps
    uint8_t _padding;
} ImguiGroupData;

// CollapsingHeader-specific data
typedef struct {
    uint32_t flags;  // ImGuiTreeNodeFlags
    bool is_open;
} ImguiCollapsingHeaderData;

// ChildWindow-specific data
typedef struct {
    ImguiVec2 size;
    bool has_size;
    uint32_t flags;       // ImGuiWindowFlags
    uint32_t child_flags; // ImGuiChildFlags
} ImguiChildWindowData;

// Button-specific data
typedef struct {
    ImguiVec2 size;
    bool has_size;
    uint32_t flags;  // ImGuiButtonFlags
} ImguiButtonData;

// Text-specific data
typedef struct {
    ImguiVec4 color;
    bool has_color;
} ImguiTextData;

// Checkbox-specific data
typedef struct {
    bool checked;
} ImguiCheckboxData;

// RadioButton-specific data
typedef struct {
    bool active;
} ImguiRadioButtonData;

// InputText-specific data
typedef struct {
    char text[4096];
    char hint[256];
    ImguiVec2 size_hint;
    bool has_size_hint;
    uint32_t flags;  // ImGuiInputTextFlags
} ImguiInputTextData;

// Combo-specific data
typedef struct {
    char** options;
    int option_count;
    int selected_index;
    uint32_t flags;  // ImGuiComboFlags
} ImguiComboData;

// Slider/Drag-specific data (float version)
typedef struct {
    ImguiVec4 value;
    ImguiVec4 min;
    ImguiVec4 max;
    int components;  // 1-4
    uint32_t flags;
    bool is_vertical;
    ImguiVec2 vertical_size;
} ImguiSliderData;

// Slider/Drag-specific data (int version)
typedef struct {
    int value[4];
    int min[4];
    int max[4];
    int components;
    uint32_t flags;
    bool is_vertical;
    ImguiVec2 vertical_size;
} ImguiSliderIntData;

// ColorEdit/ColorPicker-specific data
typedef struct {
    ImguiVec4 color;
    uint32_t flags;  // ImGuiColorEditFlags
} ImguiColorData;

// ProgressBar-specific data
typedef struct {
    float value;
    ImguiVec2 size;
    char overlay[128];
} ImguiProgressBarData;

// Tree-specific data
typedef struct {
    uint32_t flags;  // ImGuiTreeNodeFlags
    bool is_open;
} ImguiTreeData;

// Table-specific data
typedef struct {
    int columns;
    uint32_t flags;  // ImGuiTableFlags
    int freeze_rows;
    int freeze_cols;
    bool show_header;
    bool angled_header;
    bool optimized_draw;
    ImguiVec2 size;
    bool has_size;
} ImguiTableData;

// TableRow-specific data
typedef struct {
    uint32_t flags;  // ImGuiTableRowFlags
} ImguiTableRowData;

// TabBar-specific data
typedef struct {
    uint32_t flags;  // ImGuiTabBarFlags
} ImguiTabBarData;

// TabItem-specific data
typedef struct {
    uint32_t flags;  // ImGuiTabItemFlags
    bool is_selected;
} ImguiTabItemData;

// Menu-specific data
typedef struct {
    bool is_open;
} ImguiMenuData;

// MenuItem-specific data
typedef struct {
    bool enabled;
    char shortcut[32];
} ImguiMenuItemData;

// Selectable-specific data
typedef struct {
    ImguiVec2 size;
    bool has_size;
    uint32_t flags;
    bool selected;
} ImguiSelectableData;

// Dummy-specific data
typedef struct {
    float width;
    float height;
} ImguiDummyData;

// Image-specific data
typedef struct {
    char image_path[256];
    ImguiVec2 size;
    ImguiVec2 uv0;
    ImguiVec2 uv1;
    ImguiVec4 tint;
    ImguiVec4 border;
} ImguiImageData;

// Popup-specific data
typedef struct {
    uint32_t flags;  // ImGuiWindowFlags
    uint32_t popup_flags;  // ImGuiPopupFlags
    bool is_open;
} ImguiPopupData;

// Union of all type-specific data
typedef union {
    ImguiWindowData window;
    ImguiGroupData group;
    ImguiCollapsingHeaderData collapsing_header;
    ImguiChildWindowData child_window;
    ImguiButtonData button;
    ImguiTextData text;
    ImguiCheckboxData checkbox;
    ImguiRadioButtonData radio_button;
    ImguiInputTextData input_text;
    ImguiComboData combo;
    ImguiSliderData slider;
    ImguiSliderIntData slider_int;
    ImguiColorData color;
    ImguiProgressBarData progress_bar;
    ImguiTreeData tree;
    ImguiTableData table;
    ImguiTableRowData table_row;
    ImguiTabBarData tab_bar;
    ImguiTabItemData tab_item;
    ImguiMenuData menu;
    ImguiMenuItemData menu_item;
    ImguiSelectableData selectable;
    ImguiDummyData dummy;
    ImguiImageData image;
    ImguiPopupData popup;
} ImguiTypeData;

// Main object structure
typedef struct ImguiObject {
    ImguiHandle handle;
    ImguiObjectType type;
    uint32_t generation;  // For handle validation
    bool in_use;
    bool destroyed;       // Marked for cleanup

    // Parent-child relationships
    ImguiHandle parent;
    ImguiHandle* children;
    int child_count;
    int child_capacity;

    // Common styled properties
    ImguiStyledProps styled;

    // Type-specific data
    ImguiTypeData data;

    // Event callbacks (Lua function references)
    ImguiEventCallback events[IMGUI_EVENT_COUNT];

    // User data (Lua reference to arbitrary table)
    int user_data_ref;

    // Style overrides
    struct {
        int* style_vars;      // Array of style var indices
        float* style_values;  // Corresponding values (2 per var for vec2)
        int style_count;
        int* color_vars;      // Array of color indices
        ImguiVec4* color_values;
        int color_count;
    } style_overrides;

} ImguiObject;

// Object pool
typedef struct {
    ImguiObject objects[MAX_IMGUI_OBJECTS];
    uint32_t generations[MAX_IMGUI_OBJECTS];
    int free_indices[MAX_IMGUI_OBJECTS];
    int free_count;
    int active_count;

    // Track top-level windows for render loop
    ImguiHandle* windows;
    int window_count;
    int window_capacity;
} ImguiObjectPool;

// Initialization
void imgui_objects_init(void);
void imgui_objects_shutdown(void);

// Object creation
ImguiHandle imgui_object_create(ImguiObjectType type, const char* label);
ImguiHandle imgui_object_create_child(ImguiHandle parent, ImguiObjectType type, const char* label);

// Object destruction
void imgui_object_destroy(ImguiHandle handle);
void imgui_object_destroy_children(ImguiHandle handle);

// Object access
ImguiObject* imgui_object_get(ImguiHandle handle);
bool imgui_object_is_valid(ImguiHandle handle);
const char* imgui_object_type_name(ImguiObjectType type);

// Parent-child management
bool imgui_object_add_child(ImguiHandle parent, ImguiHandle child);
bool imgui_object_remove_child(ImguiHandle parent, ImguiHandle child);
bool imgui_object_detach_child(ImguiHandle parent, ImguiHandle child);
bool imgui_object_attach_child(ImguiHandle parent, ImguiHandle child);
ImguiHandle* imgui_object_get_children(ImguiHandle parent, int* count);

// Window management
ImguiHandle* imgui_get_all_windows(int* count);
void imgui_register_window(ImguiHandle handle);
void imgui_unregister_window(ImguiHandle handle);

// Event callbacks
void imgui_object_set_event(ImguiHandle handle, ImguiEventType event, int lua_ref);
int imgui_object_get_event(ImguiHandle handle, ImguiEventType event);
void imgui_object_clear_event(ImguiHandle handle, ImguiEventType event);

// User data
void imgui_object_set_user_data(ImguiHandle handle, int lua_ref);
int imgui_object_get_user_data(ImguiHandle handle);

// Style overrides
void imgui_object_set_style_var(ImguiHandle handle, int var, float value1, float value2);
void imgui_object_set_style_color(ImguiHandle handle, int color, ImguiVec4 value);
void imgui_object_clear_style(ImguiHandle handle);

// Render support
void imgui_object_push_style(ImguiObject* obj);
void imgui_object_pop_style(ImguiObject* obj);

// Debug
void imgui_objects_dump_stats(void);

#ifdef __cplusplus
}
#endif

#endif // IMGUI_OBJECTS_H
