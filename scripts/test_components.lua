-- Component Verification Test Script for Issue #33
-- Run with: !exec scripts/test_components.lua
-- Or paste directly into console
--
-- Last verified: 2025-12-20 (v0.35.0)
-- All tests passing on player entity

local function test_component(entity, name)
    local comp = entity[name]
    if not comp then
        _P("❌ " .. name .. ": NOT FOUND (component not present on entity)")
        return false
    end

    local count = 0
    local sample = {}
    local ok, err = pcall(function()
        for k, v in pairs(comp) do
            count = count + 1
            if count <= 3 then
                table.insert(sample, k .. "=" .. tostring(v))
            end
        end
    end)

    if not ok then
        _P("❌ " .. name .. ": ERROR - " .. tostring(err))
        return false
    elseif count == 0 then
        _P("⚠️ " .. name .. ": Empty (0 properties returned)")
        return true  -- Component exists but has no data
    else
        _P("✅ " .. name .. ": " .. count .. " props [" .. table.concat(sample, ", ") .. "]")
        return true
    end
end

local function test_array(entity, compName, arrayName)
    local comp = entity[compName]
    if not comp then
        _P("❌ " .. compName .. "." .. arrayName .. ": Component not found")
        return false
    end

    local arr = comp[arrayName]
    if not arr then
        _P("❌ " .. compName .. "." .. arrayName .. ": Array property not found")
        return false
    end

    local count = #arr
    local sample = ""
    if count > 0 then
        local first = arr[1]
        if type(first) == "table" then
            local parts = {}
            for k, v in pairs(first) do
                if not k:match("^__") then
                    table.insert(parts, k .. "=" .. tostring(v))
                end
            end
            sample = table.concat(parts, ", ")
        else
            sample = tostring(first)
        end
    end

    _P("✅ " .. compName .. "." .. arrayName .. ": " .. count .. " elements" ..
       (sample ~= "" and " [" .. sample:sub(1, 60) .. "]" or ""))
    return true
end

local function run_tests()
    _P("========================================")
    _P("Component Verification Test - Issue #33")
    _P("v0.35.0 - Last verified: 2025-12-20")
    _P("========================================")

    local player = Ext.Entity.Get(GetHostCharacter())
    if not player then
        _P("ERROR: Could not get player entity")
        return
    end
    _P("Testing on: " .. tostring(GetHostCharacter()))
    _P("")

    -- High-priority components (from Issue #33 acceptance criteria)
    _P("=== HIGH PRIORITY (Issue #33 Acceptance Criteria) ===")
    local high_priority = {
        "Health", "ActionResources", "SpellBook", "StatusContainer",
        "EocLevel", "AvailableLevel", "Stats", "InventoryOwner"
    }
    for _, name in ipairs(high_priority) do
        test_component(player, name)
    end

    _P("")
    _P("=== ARRAY COMPONENTS (v0.35.0) ===")
    test_array(player, "Tag", "Tags")
    test_array(player, "Classes", "Classes")
    test_array(player, "SpellBook", "Spells")
    test_array(player, "SpellContainer", "Spells")
    test_array(player, "PassiveContainer", "Passives")
    test_array(player, "BoostsContainer", "Boosts")

    _P("")
    _P("=== CORE COMPONENTS ===")
    local core = {
        "BaseHp", "Armor", "BaseStats", "Resistances", "Transform",
        "Level", "Data"
    }
    for _, name in ipairs(core) do
        test_component(player, name)
    end

    _P("")
    _P("=== CHARACTER COMPONENTS ===")
    local character = {
        "Race", "Origin", "Background", "God", "Classes",
        "Passive", "PassiveContainer", "Movement"
    }
    for _, name in ipairs(character) do
        test_component(player, name)
    end

    _P("")
    _P("=== COMBAT COMPONENTS ===")
    local combat = {
        "CombatParticipant", "CombatState", "TurnBased",
        "DeathState", "DeathType", "ThreatRange", "IsInCombat"
    }
    for _, name in ipairs(combat) do
        test_component(player, name)
    end

    _P("")
    _P("=== INVENTORY/ITEM COMPONENTS ===")
    local inventory = {
        "InventoryOwner", "InventoryMember", "InventoryIsOwned",
        "InventoryWeight", "Equipable", "Weapon", "Value"
    }
    for _, name in ipairs(inventory) do
        test_component(player, name)
    end

    _P("")
    _P("=== SPELL/BOOST COMPONENTS ===")
    local spells = {
        "SpellContainer", "Concentration", "BoostsContainer"
    }
    for _, name in ipairs(spells) do
        test_component(player, name)
    end

    _P("")
    _P("=== MISC COMPONENTS ===")
    local misc = {
        "Tag", "DisplayName", "OriginalTemplate"
    }
    for _, name in ipairs(misc) do
        test_component(player, name)
    end

    _P("")
    _P("========================================")
    _P("Test complete!")
    _P("========================================")
end

run_tests()
