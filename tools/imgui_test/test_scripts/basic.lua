-- basic.lua: Simple test for core widget functionality

Ext.Print("=== Basic Widget Test ===")

-- Test 1: Create window
local win = Ext.IMGUI.NewWindow("Basic Test")
Ext.Print("Created window")

-- Test 2: Add text
win:AddText("This is a text widget")
Ext.Print("Added text")

-- Test 3: Add button with callback
local btn = win:AddButton("Test Button")
btn.OnClick = function()
    Ext.Print("Button callback fired!")
end
Ext.Print("Added button with callback")

-- Test 4: Add checkbox
local cb = win:AddCheckbox("Test Checkbox", true)
cb.OnChange = function(widget)
    Ext.Print("Checkbox is now: " .. tostring(widget.Checked))
end
Ext.Print("Added checkbox")

-- Test 5: Add separator
win:AddSeparator()
Ext.Print("Added separator")

-- Test 6: Test property access
Ext.Print("Window title: " .. win.Title)
Ext.Print("Checkbox checked: " .. tostring(cb.Checked))

Ext.Print("=== Basic Test Complete ===")
