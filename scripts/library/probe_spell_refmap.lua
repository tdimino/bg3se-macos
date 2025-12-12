-- probe_spell_refmap.lua
-- Probe SpellPrototypeManager's RefMap for a given spell name

local SPELL_MGR_OFFSET = 0x1089bac80
local function probe_spell_refmap(spell_name)
    -- Get game module base
    local base = Ext.Memory.GetModuleBase("Baldur")
    if not base then
        Ext.Print("[ERROR] Could not get module base")
        return
    end

    -- Read SpellPrototypeManager singleton
    local mgr_ptr = Ext.Debug.ReadPtr(base + SPELL_MGR_OFFSET)
    if not mgr_ptr or mgr_ptr == 0 then
        Ext.Print("[ERROR] SpellPrototypeManager not initialized")
        return
    end
    Ext.Print("SpellPrototypeManager: " .. Debug.Hex(mgr_ptr))

    -- Get the spell's FixedString
    local stat = Ext.Stats.Get(spell_name)
    if not stat then
        Ext.Print("[ERROR] Stat not found: " .. spell_name)
        return
    end

    local raw = Ext.Stats.GetObjectRaw(spell_name)
    if not raw then
        Ext.Print("[ERROR] Could not get raw stats object")
        return
    end

    local fs_key = raw.FixedString
    Ext.Print("FixedString key: " .. fs_key)

    -- Probe the RefMap
    local refmap = Debug.ProbeManager(mgr_ptr)
    Ext.Print("RefMap:")
    Ext.Print("  capacity: " .. (refmap.capacity or 0))
    Ext.Print("  keys: " .. Debug.Hex(refmap.keys or 0))
    Ext.Print("  values: " .. Debug.Hex(refmap.values or 0))

    -- Search for the spell
    local result = Debug.ProbeRefMap(mgr_ptr, fs_key)
    if result then
        Ext.Print("FOUND:")
        Ext.Print("  index: " .. result.index)
        Ext.Print("  prototype: " .. Debug.Hex(result.value))
    else
        Ext.Print("NOT FOUND in RefMap (may be new/shadow stat)")
    end
end

-- Run with argument or default
local spell = "Projectile_FireBolt"
if arg and arg[1] then spell = arg[1] end
probe_spell_refmap(spell)
