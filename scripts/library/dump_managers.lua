-- dump_managers.lua
-- Dump all prototype manager states

local MANAGERS = {
    {name = "SpellPrototypeManager", offset = 0x1089bac80},
    {name = "StatusPrototypeManager", offset = 0x1089bdb30},
    {name = "PassivePrototypeManager", offset = 0x108aeccd8},
    {name = "InterruptPrototypeManager", offset = 0x108aecce0},
    {name = "BoostPrototypeManager", offset = 0x108991528},
}

local function dump_managers()
    local base = Ext.Memory.GetModuleBase("Baldur")
    if not base then
        Ext.Print("[ERROR] Could not get module base")
        return
    end

    Ext.Print("\n=== Prototype Managers ===")
    Ext.Print("Module base: " .. Debug.Hex(base))

    for _, mgr in ipairs(MANAGERS) do
        local ptr = Ext.Debug.ReadPtr(base + mgr.offset)
        local status = "NULL"
        local info = ""

        if ptr and ptr ~= 0 then
            status = Debug.Hex(ptr)
            local refmap = Debug.ProbeManager(ptr)
            if refmap.capacity then
                info = string.format(" (capacity=%d)", refmap.capacity)
            end
        end

        Ext.Print(string.format("  %s: %s%s", mgr.name, status, info))
    end
end

dump_managers()
