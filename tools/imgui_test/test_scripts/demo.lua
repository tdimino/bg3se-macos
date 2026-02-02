-- demo.lua: Full widget demonstration for BG3SE Ext.IMGUI
-- Run this script to test all widget types

Ext.Print("=== BG3SE ImGui Widget Demo ===")

-- Create main demo window
local win = Ext.IMGUI.NewWindow("Widget Demo")

-- Add header text
win:AddText("Welcome to the BG3SE ImGui Widget System!")
win:AddSeparator()

-- Section: Basic Widgets
win:AddText("--- Basic Widgets ---")

-- Button with click counter
local clickCount = 0
local btn = win:AddButton("Click Counter: 0")
btn.OnClick = function(widget)
    clickCount = clickCount + 1
    widget.Label = "Click Counter: " .. clickCount
    Ext.Print("Button clicked! Count: " .. clickCount)
end

-- Checkbox
local checkbox = win:AddCheckbox("Enable Feature", false)
checkbox.OnChange = function(widget)
    Ext.Print("Checkbox changed to: " .. tostring(widget.Checked))
end

win:AddSeparator()

-- Section: Input Widgets
win:AddText("--- Input Widgets ---")

-- Input Text
local input = win:AddInputText("Name", "Enter your name")
input.OnChange = function(widget)
    Ext.Print("Name changed to: " .. widget.Value)
end

-- Combo Box
local combo = win:AddCombo("Class", {"Fighter", "Wizard", "Rogue", "Cleric"}, 1)
combo.OnChange = function(widget)
    local classes = {"Fighter", "Wizard", "Rogue", "Cleric"}
    Ext.Print("Selected class: " .. classes[widget.SelectedIndex])
end

win:AddSeparator()

-- Section: Numeric Widgets
win:AddText("--- Numeric Widgets ---")

-- Slider
local slider = win:AddSlider("Health", 100, 0, 200)
slider.OnChange = function(widget)
    Ext.Print("Health: " .. widget.Value)
end

-- Progress Bar
local progress = win:AddProgressBar("Loading Progress", 0.45)

win:AddSeparator()

-- Section: Color Widgets
win:AddText("--- Color Widgets ---")

-- Color Editor
local color = win:AddColorEdit("Highlight Color", 0.2, 0.6, 0.9, 1.0)
color.OnChange = function(widget)
    local c = widget.Color
    Ext.Print(string.format("Color: R=%.2f G=%.2f B=%.2f A=%.2f", c[1], c[2], c[3], c[4]))
end

win:AddSeparator()

-- Section: Container Widgets
win:AddText("--- Container Widgets ---")

-- Group
local group = win:AddGroup("Settings Group")
group:AddText("Grouped content here")
group:AddCheckbox("Group Option 1", true)
group:AddCheckbox("Group Option 2", false)

-- Tree
local tree = win:AddTree("Inventory")
tree:AddText("Gold: 1500")
tree:AddText("Potions: 5")
local weapons = tree:AddTree("Weapons")
weapons:AddText("Longsword +2")
weapons:AddText("Dagger of Venom")

win:AddSeparator()

-- Section: Tab Widget
win:AddText("--- Tabs ---")

local tabBar = win:AddTabBar("MainTabs")

local tab1 = tabBar:AddTabItem("Character")
tab1:AddText("Character information here")
tab1:AddText("Level: 10")
tab1:AddText("XP: 45,000 / 50,000")

local tab2 = tabBar:AddTabItem("Equipment")
tab2:AddText("Equipment slots")
tab2:AddText("Helmet: Crown of Wisdom")
tab2:AddText("Armor: Plate Mail +1")

local tab3 = tabBar:AddTabItem("Spells")
tab3:AddText("Available spells")
tab3:AddText("Fireball (Level 3)")
tab3:AddText("Magic Missile (Level 1)")

Ext.Print("Demo window created with all widget types!")

-- Create a second window to test multiple windows
local win2 = Ext.IMGUI.NewWindow("Debug Info")
win2:AddText("Frame: 0")
win2:AddText("Active widgets: counting...")
win2:AddSeparator()
win2:AddButton("Close").OnClick = function()
    win2.Open = false
end

Ext.Print("=== Demo Complete ===")
