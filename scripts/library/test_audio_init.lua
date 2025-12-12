-- test_audio_init.lua
-- Test Wwise audio initialization for Issue #38

-- Known Wwise function offsets (need verification)
local WWISE_IS_INITIALIZED = 0x10019d594  -- IsInitialized()

local function test_audio()
    Ext.Print("\n=== Wwise Audio Test ===")

    local base = Ext.Memory.GetModuleBase("Baldur")
    if not base then
        Ext.Print("[ERROR] Could not get module base")
        return
    end

    Ext.Print("Module base: " .. Debug.Hex(base))
    Ext.Print("")

    -- Try to read around the IsInitialized function
    local func_addr = base + WWISE_IS_INITIALIZED
    Ext.Print("IsInitialized expected at: " .. Debug.Hex(func_addr))

    -- Probe memory around the function
    local bytes = Ext.Debug.HexDump(func_addr, 32)
    if bytes then
        Ext.Print("Function prologue:")
        Ext.Print(bytes)
    end

    Ext.Print("")
    Ext.Print("NOTE: Calling Wwise functions requires proper setup.")
    Ext.Print("See Windows BG3SE Audio.inl for reference.")
    Ext.Print("")
    Ext.Print("Key Wwise functions to locate:")
    Ext.Print("  - AK::SoundEngine::IsInitialized()")
    Ext.Print("  - AK::SoundEngine::PostEvent()")
    Ext.Print("  - AK::SoundEngine::StopAll()")
    Ext.Print("  - AK::SoundEngine::SetRTPCValue()")
end

test_audio()
