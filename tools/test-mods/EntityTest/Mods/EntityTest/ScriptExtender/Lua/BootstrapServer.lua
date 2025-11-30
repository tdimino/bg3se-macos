-- EntityTest - Test eoc:: component access
-- This mod tests the newly discovered GetComponent addresses

Ext.Print("[EntityTest] BootstrapServer loading...")

-- Test function to check entity components
local function TestEntityComponents()
    Ext.Print("[EntityTest] Testing entity component access...")

    -- Known player GUIDs from combat logs
    local testGuids = {
        "c7c13742-bacd-460a-8f65-f864fe41f255", -- Astarion
        "3ed74f06-3c60-42dc-83f6-f034cb47c679", -- ShadowHeart
        "58a69333-40bf-8358-1d17-fff240d7fb12", -- Lae'zel
    }

    -- Check if entity system is ready
    if not Ext.Entity.IsReady() then
        Ext.Print("[EntityTest] Entity system not ready yet")
        return
    end

    Ext.Print("[EntityTest] Entity system is ready!")

    for _, guid in ipairs(testGuids) do
        Ext.Print("[EntityTest] Testing GUID: " .. guid)

        local entity = Ext.Entity.Get(guid)
        if entity then
            local handle = entity:GetHandle()
            Ext.Print("[EntityTest]   Entity found! Handle: " .. tostring(handle))

            -- Test Transform (ls:: component - should work)
            local transform = entity.Transform
            if transform then
                Ext.Print("[EntityTest]   Transform: found")
            else
                Ext.Print("[EntityTest]   Transform: nil")
            end

            -- Test Stats (eoc:: component - newly discovered)
            local stats = entity:GetComponent("Stats")
            if stats then
                Ext.Print("[EntityTest]   Stats: FOUND!")
            else
                Ext.Print("[EntityTest]   Stats: nil (may need different access)")
            end

            -- Test Health (eoc:: component - newly discovered)
            local health = entity:GetComponent("Health")
            if health then
                Ext.Print("[EntityTest]   Health: FOUND!")
            else
                Ext.Print("[EntityTest]   Health: nil")
            end

            -- Test BaseHp (eoc:: component - newly discovered)
            local basehp = entity:GetComponent("BaseHp")
            if basehp then
                Ext.Print("[EntityTest]   BaseHp: FOUND!")
            else
                Ext.Print("[EntityTest]   BaseHp: nil")
            end

            -- Test Armor (eoc:: component - newly discovered)
            local armor = entity:GetComponent("Armor")
            if armor then
                Ext.Print("[EntityTest]   Armor: FOUND!")
            else
                Ext.Print("[EntityTest]   Armor: nil")
            end

        else
            Ext.Print("[EntityTest]   Entity not found for GUID")
        end
    end

    Ext.Print("[EntityTest] Component test complete!")
end

-- Run test when session loads
Ext.Events.SessionLoaded:Subscribe(function()
    Ext.Print("[EntityTest] SessionLoaded event fired")
    -- Run test immediately - entity system should be ready by now
    TestEntityComponents()
end)

-- Also run built-in test if entity system is ready
if Ext.Entity.IsReady() then
    Ext.Print("[EntityTest] Entity system ready - running Ext.Entity.Test()...")
    local result = Ext.Entity.Test()
    Ext.Print("[EntityTest] Test result: " .. tostring(result))
else
    Ext.Print("[EntityTest] Entity system not ready - enter combat, then run: Ext.Entity.Test()")
end

Ext.Print("[EntityTest] BootstrapServer loaded")
