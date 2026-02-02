/**
 * @file main.mm
 * @brief Standalone ImGui test application for BG3SE widget system
 *
 * Tests the Ext.IMGUI widget system without launching BG3.
 * Uses Metal + Cocoa for rendering, integrates with our imgui_objects
 * and Lua bindings for testing.
 */

#import <Foundation/Foundation.h>
#import <Cocoa/Cocoa.h>
#import <Metal/Metal.h>
#import <MetalKit/MetalKit.h>

#include "imgui.h"
#include "imgui_impl_metal.h"
#include "imgui_impl_osx.h"

extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "imgui_objects.h"
#include "lua_imgui.h"

// Stub implementations for standalone test app
// These replace the BG3-specific implementations

// Logging stubs
typedef enum { LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR } LogLevel;
bool log_should_write(LogLevel level) { (void)level; return true; }
void log_write(LogLevel level, const char* fmt, ...) {
    (void)level;
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

// Metal backend stubs (for standalone, ImGui is always ready and visible)
typedef enum {
    IMGUI_METAL_STATE_UNINITIALIZED = 0,
    IMGUI_METAL_STATE_WAITING,
    IMGUI_METAL_STATE_READY,
    IMGUI_METAL_STATE_ERROR
} ImguiMetalState;

static bool g_metal_visible = true;
static bool g_metal_capturing = false;

bool imgui_metal_init(void) { return true; }
void imgui_metal_shutdown(void) {}
bool imgui_metal_is_ready(void) { return true; }
ImguiMetalState imgui_metal_get_state(void) { return IMGUI_METAL_STATE_READY; }
void imgui_metal_set_visible(bool visible) { g_metal_visible = visible; }
bool imgui_metal_is_visible(void) { return g_metal_visible; }
void imgui_metal_set_input_capture(bool capture) { g_metal_capturing = capture; }
bool imgui_metal_is_capturing_input(void) { return g_metal_capturing; }
}

// Forward declarations
@interface TestViewController : NSViewController<MTKViewDelegate, NSWindowDelegate>
@property (nonatomic, readonly) MTKView *mtkView;
@property (nonatomic, strong) id<MTLDevice> device;
@property (nonatomic, strong) id<MTLCommandQueue> commandQueue;
@end

@interface TestAppDelegate : NSObject<NSApplicationDelegate>
@property (nonatomic, strong) NSWindow *window;
@end

// Global Lua state
static lua_State *g_LuaState = NULL;
static bool g_ShowDemoWindow = true;
static bool g_ShowTestWindow = true;
static ImVec4 g_ClearColor = ImVec4(0.1f, 0.1f, 0.12f, 1.0f);

//-----------------------------------------------------------------------------------
// Widget Rendering (standalone implementation for test app)
//-----------------------------------------------------------------------------------

static void render_widget(ImguiObject *obj);

static void render_children(ImguiObject *obj) {
    if (!obj || !obj->children) return;
    for (int i = 0; i < obj->child_count; i++) {
        ImguiObject *child = imgui_object_get(obj->children[i]);
        if (child) render_widget(child);
    }
}

static void render_widget(ImguiObject *obj) {
    if (!obj || !obj->styled.visible) return;

    switch (obj->type) {
        case IMGUI_OBJ_TEXT:
            if (obj->data.text.has_color) {
                ImGui::TextColored(ImVec4(obj->data.text.color.x, obj->data.text.color.y,
                                          obj->data.text.color.z, obj->data.text.color.w),
                                   "%s", obj->styled.label);
            } else {
                ImGui::Text("%s", obj->styled.label);
            }
            break;

        case IMGUI_OBJ_BUTTON:
            if (ImGui::Button(obj->styled.label)) {
                lua_imgui_fire_event(obj->handle, IMGUI_EVENT_ON_CLICK);
            }
            break;

        case IMGUI_OBJ_CHECKBOX:
            if (ImGui::Checkbox(obj->styled.label, &obj->data.checkbox.checked)) {
                lua_imgui_fire_event(obj->handle, IMGUI_EVENT_ON_CHANGE);
            }
            break;

        case IMGUI_OBJ_SEPARATOR:
            ImGui::Separator();
            break;

        case IMGUI_OBJ_INPUT_TEXT: {
            if (ImGui::InputText(obj->styled.label, obj->data.input_text.text,
                                 sizeof(obj->data.input_text.text), obj->data.input_text.flags)) {
                lua_imgui_fire_event(obj->handle, IMGUI_EVENT_ON_CHANGE);
            }
            break;
        }

        case IMGUI_OBJ_COMBO: {
            ImguiComboData *d = &obj->data.combo;
            const char *preview = (d->options && d->selected_index >= 0 && d->selected_index < d->option_count)
                                  ? d->options[d->selected_index] : "";
            if (ImGui::BeginCombo(obj->styled.label, preview, d->flags)) {
                for (int i = 0; i < d->option_count; i++) {
                    bool selected = (i == d->selected_index);
                    if (ImGui::Selectable(d->options[i], selected)) {
                        d->selected_index = i;
                        lua_imgui_fire_event(obj->handle, IMGUI_EVENT_ON_CHANGE);
                    }
                }
                ImGui::EndCombo();
            }
            break;
        }

        case IMGUI_OBJ_SLIDER_SCALAR: {
            ImguiSliderData *d = &obj->data.slider;
            if (ImGui::SliderFloat(obj->styled.label, &d->value.x, d->min.x, d->max.x)) {
                lua_imgui_fire_event(obj->handle, IMGUI_EVENT_ON_CHANGE);
            }
            break;
        }

        case IMGUI_OBJ_COLOR_EDIT: {
            float col[4] = {obj->data.color.color.x, obj->data.color.color.y,
                           obj->data.color.color.z, obj->data.color.color.w};
            if (ImGui::ColorEdit4(obj->styled.label, col, obj->data.color.flags)) {
                obj->data.color.color = {col[0], col[1], col[2], col[3]};
                lua_imgui_fire_event(obj->handle, IMGUI_EVENT_ON_CHANGE);
            }
            break;
        }

        case IMGUI_OBJ_PROGRESS_BAR: {
            ImguiProgressBarData *d = &obj->data.progress_bar;
            ImGui::ProgressBar(d->value, ImVec2(d->size.x, d->size.y),
                              d->overlay[0] ? d->overlay : NULL);
            break;
        }

        case IMGUI_OBJ_TREE: {
            bool open = ImGui::TreeNodeEx(obj->styled.label, obj->data.tree.flags);
            if (open != obj->data.tree.is_open) {
                obj->data.tree.is_open = open;
                lua_imgui_fire_event(obj->handle, open ? IMGUI_EVENT_ON_EXPAND : IMGUI_EVENT_ON_COLLAPSE);
            }
            if (open) {
                render_children(obj);
                ImGui::TreePop();
            }
            break;
        }

        case IMGUI_OBJ_GROUP:
            ImGui::BeginGroup();
            render_children(obj);
            ImGui::EndGroup();
            break;

        case IMGUI_OBJ_TAB_BAR:
            if (ImGui::BeginTabBar(obj->styled.label, obj->data.tab_bar.flags)) {
                render_children(obj);
                ImGui::EndTabBar();
            }
            break;

        case IMGUI_OBJ_TAB_ITEM:
            if (ImGui::BeginTabItem(obj->styled.label, NULL, obj->data.tab_item.flags)) {
                obj->data.tab_item.is_selected = true;
                render_children(obj);
                ImGui::EndTabItem();
            } else {
                obj->data.tab_item.is_selected = false;
            }
            break;

        case IMGUI_OBJ_TABLE: {
            ImguiTableData *d = &obj->data.table;
            ImVec2 size = d->has_size ? ImVec2(d->size.x, d->size.y) : ImVec2(0, 0);
            if (ImGui::BeginTable(obj->styled.label, d->columns, d->flags, size)) {
                render_children(obj);
                ImGui::EndTable();
            }
            break;
        }

        case IMGUI_OBJ_TABLE_ROW:
            ImGui::TableNextRow(obj->data.table_row.flags);
            render_children(obj);
            break;

        case IMGUI_OBJ_TABLE_CELL:
            ImGui::TableNextColumn();
            render_children(obj);
            break;

        default:
            // Unsupported widget type
            ImGui::Text("[Unsupported: %s]", imgui_object_type_name(obj->type));
            break;
    }
}

static void render_window(ImguiObject *win) {
    if (!win || win->type != IMGUI_OBJ_WINDOW) return;
    if (!win->data.window.open || !win->styled.visible) return;

    uint32_t flags = win->data.window.flags;
    bool *p_open = win->data.window.closeable ? &win->data.window.open : NULL;

    ImGui::SetNextWindowPos(ImVec2(550, 100), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(ImVec2(400, 500), ImGuiCond_FirstUseEver);

    if (ImGui::Begin(win->styled.label, p_open, flags)) {
        render_children(win);
    }
    ImGui::End();

    // Fire close event if window was closed
    if (p_open && !win->data.window.open) {
        lua_imgui_fire_event(win->handle, IMGUI_EVENT_ON_CLOSE);
    }
}

void imgui_render_all_windows(void) {
    int window_count = 0;
    ImguiHandle *windows = imgui_get_all_windows(&window_count);

    if (windows && window_count > 0) {
        for (int i = 0; i < window_count; i++) {
            ImguiObject *win = imgui_object_get(windows[i]);
            render_window(win);
        }
    }
}

//-----------------------------------------------------------------------------------
// Lua Integration
//-----------------------------------------------------------------------------------

static void setup_lua_state(void) {
    g_LuaState = luaL_newstate();
    if (!g_LuaState) {
        NSLog(@"Failed to create Lua state");
        return;
    }

    luaL_openlibs(g_LuaState);

    // Create Ext table
    lua_newtable(g_LuaState);

    // Register Ext.IMGUI
    lua_imgui_register(g_LuaState, lua_gettop(g_LuaState));

    // Add Ext.Print for debugging
    lua_pushcfunction(g_LuaState, [](lua_State *L) -> int {
        int n = lua_gettop(L);
        for (int i = 1; i <= n; i++) {
            if (i > 1) printf("\t");
            if (lua_isstring(L, i)) {
                printf("%s", lua_tostring(L, i));
            } else if (lua_isnil(L, i)) {
                printf("nil");
            } else if (lua_isboolean(L, i)) {
                printf("%s", lua_toboolean(L, i) ? "true" : "false");
            } else if (lua_isnumber(L, i)) {
                printf("%g", lua_tonumber(L, i));
            } else {
                printf("%s:%p", luaL_typename(L, i), lua_topointer(L, i));
            }
        }
        printf("\n");
        return 0;
    });
    lua_setfield(g_LuaState, -2, "Print");

    // Set global Ext
    lua_setglobal(g_LuaState, "Ext");

    // Set up IMGUI Lua state for callbacks
    lua_imgui_set_lua_state(g_LuaState);

    NSLog(@"Lua state initialized with Ext.IMGUI");
}

static void cleanup_lua_state(void) {
    if (g_LuaState) {
        lua_imgui_set_lua_state(NULL);
        lua_close(g_LuaState);
        g_LuaState = NULL;
    }
}

static bool run_lua_script(const char *path) {
    if (!g_LuaState) return false;

    int result = luaL_dofile(g_LuaState, path);
    if (result != LUA_OK) {
        const char *error = lua_tostring(g_LuaState, -1);
        NSLog(@"Lua error: %s", error ? error : "unknown");
        lua_pop(g_LuaState, 1);
        return false;
    }
    return true;
}

static bool run_lua_string(const char *code) {
    if (!g_LuaState) return false;

    int result = luaL_dostring(g_LuaState, code);
    if (result != LUA_OK) {
        const char *error = lua_tostring(g_LuaState, -1);
        NSLog(@"Lua error: %s", error ? error : "unknown");
        lua_pop(g_LuaState, 1);
        return false;
    }
    return true;
}

//-----------------------------------------------------------------------------------
// Test Window (demonstrates Lua widget creation)
//-----------------------------------------------------------------------------------

static char s_LuaInput[4096] = "local win = Ext.IMGUI.NewWindow(\"Test\")\nwin:AddText(\"Hello from Lua!\")\nwin:AddButton(\"Click Me\").OnClick = function()\n    Ext.Print(\"Button clicked!\")\nend";
static char s_ScriptPath[256] = "test_scripts/demo.lua";

static void render_test_control_window(void) {
    if (!g_ShowTestWindow) return;

    ImGui::SetNextWindowSize(ImVec2(600, 500), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("BG3SE ImGui Test Console", &g_ShowTestWindow)) {
        ImGui::Text("Test the Ext.IMGUI widget system");
        ImGui::Separator();

        // Statistics
        if (ImGui::CollapsingHeader("Statistics", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::Text("Active Windows: %d", imgui_objects_get_window_count());
            ImGui::Text("Total Objects: %d", imgui_objects_get_total_count());
            ImGui::Text("Lua State: %s", g_LuaState ? "Active" : "NULL");
        }

        // Lua Script Runner
        if (ImGui::CollapsingHeader("Run Lua Script", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::InputText("Script Path", s_ScriptPath, sizeof(s_ScriptPath));
            if (ImGui::Button("Load & Run Script")) {
                NSLog(@"Running script: %s", s_ScriptPath);
                run_lua_script(s_ScriptPath);
            }
            ImGui::SameLine();
            if (ImGui::Button("List Scripts")) {
                system("ls -la test_scripts/");
            }
        }

        // Lua Console
        if (ImGui::CollapsingHeader("Lua Console", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::InputTextMultiline("##lua_input", s_LuaInput, sizeof(s_LuaInput),
                                       ImVec2(-1, 200));
            if (ImGui::Button("Execute")) {
                NSLog(@"Executing Lua:\n%s", s_LuaInput);
                run_lua_string(s_LuaInput);
            }
            ImGui::SameLine();
            if (ImGui::Button("Clear")) {
                s_LuaInput[0] = '\0';
            }
            ImGui::SameLine();
            if (ImGui::Button("Reset All Windows")) {
                imgui_objects_shutdown();
                imgui_objects_init();
            }
        }

        // Quick Test Buttons
        if (ImGui::CollapsingHeader("Quick Tests")) {
            if (ImGui::Button("Create Empty Window")) {
                run_lua_string("Ext.IMGUI.NewWindow(\"Empty Window\")");
            }
            ImGui::SameLine();
            if (ImGui::Button("Create Text Widget")) {
                run_lua_string("local w = Ext.IMGUI.NewWindow(\"Text Test\")\nw:AddText(\"Hello World!\")");
            }

            if (ImGui::Button("Create Button Test")) {
                run_lua_string(
                    "local w = Ext.IMGUI.NewWindow(\"Button Test\")\n"
                    "local counter = 0\n"
                    "local btn = w:AddButton(\"Click me!\")\n"
                    "btn.OnClick = function()\n"
                    "    counter = counter + 1\n"
                    "    Ext.Print(\"Clicked \" .. counter .. \" times\")\n"
                    "end"
                );
            }
            ImGui::SameLine();
            if (ImGui::Button("Create Checkbox Test")) {
                run_lua_string(
                    "local w = Ext.IMGUI.NewWindow(\"Checkbox Test\")\n"
                    "local cb = w:AddCheckbox(\"Enable Feature\", false)\n"
                    "cb.OnChange = function(widget)\n"
                    "    Ext.Print(\"Checkbox is now: \" .. tostring(widget.Checked))\n"
                    "end"
                );
            }

            if (ImGui::Button("Create Input Text")) {
                run_lua_string(
                    "local w = Ext.IMGUI.NewWindow(\"Input Test\")\n"
                    "local input = w:AddInputText(\"Name\", \"default value\")\n"
                    "input.OnChange = function(widget)\n"
                    "    Ext.Print(\"Input changed to: \" .. widget.Value)\n"
                    "end"
                );
            }
            ImGui::SameLine();
            if (ImGui::Button("Create Combo Test")) {
                run_lua_string(
                    "local w = Ext.IMGUI.NewWindow(\"Combo Test\")\n"
                    "local combo = w:AddCombo(\"Select\", {\"Option A\", \"Option B\", \"Option C\"}, 1)\n"
                    "combo.OnChange = function(widget)\n"
                    "    Ext.Print(\"Selected index: \" .. widget.SelectedIndex)\n"
                    "end"
                );
            }

            if (ImGui::Button("Create Slider Test")) {
                run_lua_string(
                    "local w = Ext.IMGUI.NewWindow(\"Slider Test\")\n"
                    "local slider = w:AddSlider(\"Value\", 50, 0, 100)\n"
                    "slider.OnChange = function(widget)\n"
                    "    Ext.Print(\"Slider value: \" .. widget.Value)\n"
                    "end"
                );
            }
            ImGui::SameLine();
            if (ImGui::Button("Create Color Picker")) {
                run_lua_string(
                    "local w = Ext.IMGUI.NewWindow(\"Color Test\")\n"
                    "local color = w:AddColorEdit(\"Color\", 1, 0.5, 0.2, 1)\n"
                    "color.OnChange = function(widget)\n"
                    "    local c = widget.Color\n"
                    "    Ext.Print(string.format(\"Color: %.2f, %.2f, %.2f, %.2f\", c[1], c[2], c[3], c[4]))\n"
                    "end"
                );
            }

            if (ImGui::Button("Create Tree Test")) {
                run_lua_string(
                    "local w = Ext.IMGUI.NewWindow(\"Tree Test\")\n"
                    "local tree = w:AddTree(\"Root Node\")\n"
                    "tree:AddText(\"Child 1\")\n"
                    "tree:AddText(\"Child 2\")\n"
                    "local subtree = tree:AddTree(\"Subtree\")\n"
                    "subtree:AddText(\"Nested child\")"
                );
            }
            ImGui::SameLine();
            if (ImGui::Button("Create Tab Test")) {
                run_lua_string(
                    "local w = Ext.IMGUI.NewWindow(\"Tab Test\")\n"
                    "local tabs = w:AddTabBar(\"Tabs\")\n"
                    "local tab1 = tabs:AddTabItem(\"Tab 1\")\n"
                    "tab1:AddText(\"Content of Tab 1\")\n"
                    "local tab2 = tabs:AddTabItem(\"Tab 2\")\n"
                    "tab2:AddText(\"Content of Tab 2\")"
                );
            }

            if (ImGui::Button("Create Progress Bar")) {
                run_lua_string(
                    "local w = Ext.IMGUI.NewWindow(\"Progress Test\")\n"
                    "local progress = w:AddProgressBar(\"Loading\", 0.65)"
                );
            }
            ImGui::SameLine();
            if (ImGui::Button("Create Table Test")) {
                run_lua_string(
                    "local w = Ext.IMGUI.NewWindow(\"Table Test\")\n"
                    "local tbl = w:AddTable(\"Data\", 3)\n"
                    "local row1 = tbl:AddTableRow()\n"
                    "row1:AddTableCell():AddText(\"A1\")\n"
                    "row1:AddTableCell():AddText(\"B1\")\n"
                    "row1:AddTableCell():AddText(\"C1\")\n"
                    "local row2 = tbl:AddTableRow()\n"
                    "row2:AddTableCell():AddText(\"A2\")\n"
                    "row2:AddTableCell():AddText(\"B2\")\n"
                    "row2:AddTableCell():AddText(\"C2\")"
                );
            }

            if (ImGui::Button("Full Widget Demo")) {
                run_lua_script("test_scripts/demo.lua");
            }
        }

        // Settings
        if (ImGui::CollapsingHeader("Settings")) {
            ImGui::Checkbox("Show ImGui Demo", &g_ShowDemoWindow);
            ImGui::ColorEdit3("Background", (float*)&g_ClearColor);
        }
    }
    ImGui::End();
}

//-----------------------------------------------------------------------------------
// TestViewController
//-----------------------------------------------------------------------------------

@implementation TestViewController

- (instancetype)initWithNibName:(nullable NSString *)nibNameOrNil bundle:(nullable NSBundle *)nibBundleOrNil {
    self = [super initWithNibName:nibNameOrNil bundle:nibBundleOrNil];

    _device = MTLCreateSystemDefaultDevice();
    _commandQueue = [_device newCommandQueue];

    if (!self.device) {
        NSLog(@"Metal is not supported on this device");
        abort();
    }

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    // Setup style
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 5.0f;
    style.FrameRounding = 3.0f;
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.12f, 0.12f, 0.14f, 0.94f);

    // Setup renderer backend
    ImGui_ImplMetal_Init(_device);

    // Initialize our widget system
    imgui_objects_init();

    // Setup Lua
    setup_lua_state();

    NSLog(@"TestViewController initialized");
    return self;
}

- (MTKView *)mtkView {
    return (MTKView *)self.view;
}

- (void)loadView {
    self.view = [[MTKView alloc] initWithFrame:CGRectMake(0, 0, 1400, 900)];
}

- (void)viewDidLoad {
    [super viewDidLoad];

    self.mtkView.device = self.device;
    self.mtkView.delegate = self;
    self.mtkView.clearColor = MTLClearColorMake(g_ClearColor.x, g_ClearColor.y,
                                                  g_ClearColor.z, g_ClearColor.w);

    ImGui_ImplOSX_Init(self.view);
    [NSApp activateIgnoringOtherApps:YES];
}

- (void)drawInMTKView:(MTKView *)view {
    ImGuiIO& io = ImGui::GetIO();
    io.DisplaySize.x = view.bounds.size.width;
    io.DisplaySize.y = view.bounds.size.height;

    CGFloat framebufferScale = view.window.screen.backingScaleFactor ?: NSScreen.mainScreen.backingScaleFactor;
    io.DisplayFramebufferScale = ImVec2(framebufferScale, framebufferScale);

    id<MTLCommandBuffer> commandBuffer = [self.commandQueue commandBuffer];

    MTLRenderPassDescriptor* renderPassDescriptor = view.currentRenderPassDescriptor;
    if (renderPassDescriptor == nil) {
        [commandBuffer commit];
        return;
    }

    // Start the ImGui frame
    ImGui_ImplMetal_NewFrame(renderPassDescriptor);
    ImGui_ImplOSX_NewFrame(view);
    ImGui::NewFrame();

    // 1. Show ImGui demo window (for reference)
    if (g_ShowDemoWindow) {
        ImGui::ShowDemoWindow(&g_ShowDemoWindow);
    }

    // 2. Show our test control window
    render_test_control_window();

    // 3. Render all BG3SE IMGUI windows (from Lua)
    imgui_render_all_windows();

    // Rendering
    ImGui::Render();
    ImDrawData* drawData = ImGui::GetDrawData();

    renderPassDescriptor.colorAttachments[0].clearColor = MTLClearColorMake(
        g_ClearColor.x * g_ClearColor.w,
        g_ClearColor.y * g_ClearColor.w,
        g_ClearColor.z * g_ClearColor.w,
        g_ClearColor.w
    );

    id<MTLRenderCommandEncoder> renderEncoder = [commandBuffer renderCommandEncoderWithDescriptor:renderPassDescriptor];
    [renderEncoder pushDebugGroup:@"ImGui rendering"];
    ImGui_ImplMetal_RenderDrawData(drawData, commandBuffer, renderEncoder);
    [renderEncoder popDebugGroup];
    [renderEncoder endEncoding];

    [commandBuffer presentDrawable:view.currentDrawable];
    [commandBuffer commit];
}

- (void)mtkView:(MTKView *)view drawableSizeWillChange:(CGSize)size {
    // Handle resize if needed
}

- (void)viewWillAppear {
    [super viewWillAppear];
    self.view.window.delegate = self;
}

- (void)windowWillClose:(NSNotification *)notification {
    cleanup_lua_state();
    imgui_objects_shutdown();
    ImGui_ImplMetal_Shutdown();
    ImGui_ImplOSX_Shutdown();
    ImGui::DestroyContext();
    NSLog(@"Cleanup complete");
}

@end

//-----------------------------------------------------------------------------------
// TestAppDelegate
//-----------------------------------------------------------------------------------

@implementation TestAppDelegate

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender {
    return YES;
}

- (instancetype)init {
    if (self = [super init]) {
        NSViewController *rootViewController = [[TestViewController alloc] initWithNibName:nil bundle:nil];

        self.window = [[NSWindow alloc] initWithContentRect:NSZeroRect
                                                  styleMask:NSWindowStyleMaskTitled |
                                                            NSWindowStyleMaskClosable |
                                                            NSWindowStyleMaskResizable |
                                                            NSWindowStyleMaskMiniaturizable
                                                    backing:NSBackingStoreBuffered
                                                      defer:NO];

        self.window.title = @"BG3SE ImGui Widget Test";
        self.window.contentViewController = rootViewController;
        [self.window center];
        [self.window makeKeyAndOrderFront:self];
    }
    return self;
}

@end

//-----------------------------------------------------------------------------------
// Main
//-----------------------------------------------------------------------------------

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

        TestAppDelegate *appDelegate = [[TestAppDelegate alloc] init];
        [NSApp setDelegate:appDelegate];

        // Create menu bar
        NSMenu *menuBar = [[NSMenu alloc] init];
        NSMenuItem *appMenuItem = [[NSMenuItem alloc] init];
        [menuBar addItem:appMenuItem];

        NSMenu *appMenu = [[NSMenu alloc] init];
        [appMenu addItemWithTitle:@"Quit" action:@selector(terminate:) keyEquivalent:@"q"];
        [appMenuItem setSubmenu:appMenu];

        [NSApp setMainMenu:menuBar];

        NSLog(@"BG3SE ImGui Widget Test starting...");
        NSLog(@"Use the test console to create windows via Lua");

        [NSApp activateIgnoringOtherApps:YES];
        [NSApp run];
    }
    return 0;
}
