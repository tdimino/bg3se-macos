-- find_physics_scene.lua
-- Attempt to find PhysicsScene pointer for Issue #37

-- Known offsets from Windows BG3SE research
local AIGRID_OFFSET = 0x10116fd20  -- AiGrid constructor (takes PhysicsScene*)

local function find_physics_scene()
    Ext.Print("\n=== PhysicsScene Discovery ===")
    Ext.Print("NOTE: This requires Frida hook or EntityWorld traversal")
    Ext.Print("")

    -- Approach 1: Probe via EntityWorld (if captured)
    if Ext.Entity.IsReady and Ext.Entity.IsReady() then
        Ext.Print("EntityWorld is ready - attempting component probe...")

        -- Try to find physics-related components on player entity
        local player = Osi.GetHostCharacter()
        if player then
            local entity = Ext.Entity.Get(player)
            if entity then
                Ext.Print("Player entity: " .. tostring(entity))
                -- Check for physics-related components
                local comps = {"Transform", "Movement", "AiGrid"}
                for _, comp in ipairs(comps) do
                    local c = entity[comp]
                    if c then
                        Ext.Print("  Has " .. comp .. ": " .. tostring(c))
                    end
                end
            end
        end
    else
        Ext.Print("EntityWorld not ready - need game to be loaded")
    end

    Ext.Print("")
    Ext.Print("Alternative: Use Frida to hook AiGrid constructor:")
    Ext.Print("  frida -U -n 'Baldur's Gate 3' -l capture_physics.js")
end

find_physics_scene()
