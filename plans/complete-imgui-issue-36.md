# Complete Resolution of Issue #36: Ext.IMGUI Debug Overlay

## Executive Summary

**Current State:** 80% complete (Metal backend + input handling)
**Target:** Full Windows BG3SE Ext.IMGUI API parity (~40 widget types, handle-based system)
**Estimated Effort:** 3-4 weeks of focused development

## What's Already Working (v0.36.19)

- Metal rendering backend with CAMetalLayer hook
- CGEventTap input capture with proper Cocoa coordinate conversion
- Mouse input: hover, click, drag all functional
- F11 hotkey toggle
- Basic Lua bindings: Show/Hide/Toggle/IsVisible/IsReady/GetState

## Gap Analysis: Windows vs macOS

| Category | Windows BG3SE | macOS BG3SE | Gap |
|----------|---------------|-------------|-----|
| Global Functions | 7 | 9 | Covered |
| Widget Types | 40 | 0 | Major |
| Object Lifecycle | Handle-based | None | Major |
| Events/Callbacks | Full delegate system | None | Major |
| Property System | RTTI reflection | None | Major |

## Implementation Plan

### Phase 1: Core Infrastructure (Week 1)

#### 1.1 Handle-Based Object System
**Files to create:**
- `src/imgui/imgui_objects.h` - Object types, handle management
- `src/imgui/imgui_objects.c` - Object pool, lifecycle management

**Object Pool:**
- Fixed-size array (MAX_IMGUI_OBJECTS = 4096)
- Generation counter prevents stale handle use
- Parent-child relationship tracking
- Automatic cleanup when parent destroyed

#### 1.2 Lua Userdata System
**Files to modify:**
- `src/lua/lua_imgui.c` - Add userdata metatables

**Implementation:**
- `ImguiHandleUserdata` wraps handle for Lua
- `__index` metamethod for property access
- `__newindex` for property setting
- `__gc` for cleanup (mark as orphaned, not immediate destroy)
- Type checking via `__type` field

#### 1.3 Property Map System
**Files to create:**
- `src/imgui/imgui_properties.h` - Property definitions
- `src/imgui/imgui_properties.c` - Property access

### Phase 2: Container Widgets (Week 2)

#### 2.1 Window Widget
**Priority:** CRITICAL - All other widgets require a window

**API:**
```lua
local win = Ext.IMGUI.NewWindow("My Window")
win.Open = true
win.Closeable = true
win:SetPos({100, 100})
win:SetSize({400, 300})
win.OnClose = function(handle) print("Window closed") end
```

#### 2.2 Group Widget
#### 2.3 CollapsingHeader
#### 2.4 ChildWindow

### Phase 3: Basic Widgets (Week 2-3)

#### 3.1 Display Widgets
- `AddText(label)` - ImGui::Text
- `AddBulletText(label)` - ImGui::BulletText
- `AddSeparatorText(label)` - ImGui::SeparatorText
- `AddSeparator()` - ImGui::Separator
- `AddSpacing()` - ImGui::Spacing
- `AddDummy(w, h)` - ImGui::Dummy
- `AddNewLine()` - ImGui::NewLine

#### 3.2 Button Widgets
- `AddButton(label)` - ImGui::Button
- `AddImageButton(label, icon, size)` - ImGui::ImageButton
- `AddSelectable(label, flags, size)` - ImGui::Selectable

#### 3.3 Input Widgets
- `AddCheckbox(label, checked)` - ImGui::Checkbox
- `AddRadioButton(label, active)` - ImGui::RadioButton
- `AddInputText(label, value)` - ImGui::InputText
- `AddCombo(label)` - ImGui::Combo

### Phase 4: Advanced Widgets (Week 3)

#### 4.1 Slider/Drag Widgets
- `AddSlider(label, value, min, max)` - ImGui::SliderFloat
- `AddSliderInt(label, value, min, max)` - ImGui::SliderInt
- `AddDrag(label, value, min, max)` - ImGui::DragFloat
- `AddDragInt(label, value, min, max)` - ImGui::DragInt

#### 4.2 Color Widgets
- `AddColorEdit(label, color)` - ImGui::ColorEdit4
- `AddColorPicker(label, color)` - ImGui::ColorPicker4

#### 4.3 Progress Widget

### Phase 5: Table & Tree Widgets (Week 3-4)

#### 5.1 Table Widget
#### 5.2 Tree Widget

### Phase 6: Menu & Tab Widgets (Week 4)

#### 6.1 Menu System
#### 6.2 Tab System

### Phase 7: Event & Styling System (Week 4)

#### 7.1 Event Delegates
**Supported Events:**
- OnClick, OnRightClick
- OnActivate, OnDeactivate
- OnHoverEnter, OnHoverLeave
- OnChange (for inputs)
- OnClose (for windows)
- OnExpand, OnCollapse (for trees)
- OnSortChanged (for tables)
- OnDragStart, OnDragEnd, OnDragDrop

#### 7.2 Style System
- GuiStyleVar enum (34 values)
- GuiColor enum (53 values)
- Per-object style overrides via ImGui::PushStyleVar/Color

### Phase 8: Polish & Testing (Week 4+)

#### 8.1 Enum Bindings
Add to `src/enum/enum_definitions.c`:
- GuiWindowFlags, GuiChildFlags, GuiTreeNodeFlags
- GuiTabBarFlags, GuiTabItemFlags, GuiTableFlags
- GuiInputTextFlags, GuiComboFlags, GuiSliderFlags
- GuiColorEditFlags, GuiButtonFlags, GuiSelectableFlags
- GuiStyleVar, GuiColor, GuiCond, GuiSortDirection

#### 8.2 Documentation
#### 8.3 Testing

## File Structure

```
src/imgui/
├── imgui_metal_backend.mm   # Existing - Metal + coord conversion
├── imgui_input_hooks.mm     # Existing - NSView swizzling
├── imgui_objects.h          # NEW - Object types, handles
├── imgui_objects.c          # NEW - Object pool, lifecycle
├── imgui_properties.h       # NEW - Property definitions
├── imgui_properties.c       # NEW - Property access
├── imgui_events.h           # NEW - Event delegate system
├── imgui_events.c           # NEW - Event callbacks
├── imgui_widgets.h          # NEW - Widget rendering
├── imgui_widgets.c          # NEW - Widget implementations
└── imgui_enums.h            # NEW - ImGui flag enums

src/lua/
└── lua_imgui.c              # MODIFY - Full widget API bindings
```

## Critical Files to Modify

1. `src/lua/lua_imgui.c` - Add all widget creation functions
2. `src/imgui/imgui_metal_backend.mm` - Integrate widget rendering loop
3. `src/enum/enum_definitions.c` - Add GUI-related enums
4. `CMakeLists.txt` - Add new source files

## Success Criteria

- [ ] All 40 widget types implemented
- [ ] Handle-based object system working
- [ ] Event callbacks functional for all events
- [ ] Style system with per-object overrides
- [ ] Table widget with sorting and freeze
- [ ] Tree widget with expand/collapse events
- [ ] Menu/Tab system functional
- [ ] No memory leaks on repeated create/destroy
- [ ] Parity with Windows BG3SE Ext.IMGUI API
