# Ghidra Script: Analyze ls::gst::Get function - THE key to GlobalStringTable
# Run with: -postScript analyze_gst_get.py

print("=" * 70)
print("Analyzing ls::gst::Get - GlobalStringTable Lookup Function")
print("=" * 70)

# Address of ls::gst::Get(uint32_t)
GST_GET_ADDR = 0x1064bb224

def get_function_disasm(addr, num_instrs=100):
    """Get disassembly of function starting at addr."""
    listing = currentProgram.getListing()
    func = getFunctionAt(toAddr(addr))

    if func:
        print("\nFunction: {} at {}".format(func.getName(), func.getEntryPoint()))
        print("Function body size: {} bytes".format(func.getBody().getNumAddresses()))
    else:
        print("\nNo function at {}, showing raw instructions".format(hex(addr)))

    instr_iter = listing.getInstructions(toAddr(addr), True)
    count = 0
    global_refs = []

    for instr in instr_iter:
        count += 1
        if count > num_instrs:
            break

        # Look for interesting patterns
        mnemonic = instr.getMnemonicString()
        refs = list(instr.getReferencesFrom())

        marker = "  "
        if mnemonic == "adrp":
            marker = ">A"  # ADRP - page address load
        elif mnemonic == "ldr" and refs:
            marker = ">L"  # LDR with reference
            for ref in refs:
                global_refs.append({
                    'instr_addr': instr.getAddress(),
                    'target': ref.getToAddress(),
                    'type': 'LDR'
                })
        elif mnemonic == "bl":
            # Function call
            if refs:
                target = refs[0].getToAddress()
                target_func = getFunctionAt(target)
                if target_func:
                    print("  {} {} {}  ; calls {}".format(
                        marker, instr.getAddress(), instr, target_func.getName()))
                    continue
        elif mnemonic == "ret":
            print("  {} {} {}".format(marker, instr.getAddress(), instr))
            break  # End of function

        print("  {} {} {}".format(marker, instr.getAddress(), instr))

        # Print references inline
        for ref in refs:
            ref_addr = ref.getToAddress()
            # Try to read data at reference
            mem = currentProgram.getMemory()
            data_str = ""
            try:
                val = mem.getLong(ref_addr)
                data_str = " [value: 0x{:x}]".format(val)
            except:
                pass
            print("       REF-> {}{}".format(ref_addr, data_str))

    return global_refs

print("\n--- ls::gst::Get(uint32_t) ---")
refs = get_function_disasm(GST_GET_ADDR)

print("\n" + "=" * 70)
print("GLOBAL REFERENCES FOUND:")
print("=" * 70)
for ref in refs:
    print("  {} -> {}".format(ref['instr_addr'], ref['target']))

# The GlobalStringTable pointer is likely loaded in this function
# Look for the first ADRP+LDR pattern which loads the GST base
