# Ghidra Script: Analyze ls::LSFStringTable::Add for GST access pattern
# Run with: -postScript analyze_lsf_stringtable.py

print("=" * 70)
print("Analyzing ls::LSFStringTable::Add for GlobalStringTable access")
print("=" * 70)

# Address of ls::LSFStringTable::Add(FixedString&)
LSF_ADD_ADDR = 0x1064e3c04

def get_function_disasm(addr, num_instrs=50):
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
    for instr in instr_iter:
        count += 1
        if count > num_instrs:
            break

        # Look for interesting patterns
        mnemonic = instr.getMnemonicString()
        refs = list(instr.getReferencesFrom())

        marker = "  "
        if mnemonic == "adrp":
            marker = ">>"
        elif mnemonic == "ldr" and refs:
            marker = ">>"
        elif mnemonic == "bl":
            # Function call - check what it calls
            if refs:
                target = refs[0].getToAddress()
                target_func = getFunctionAt(target)
                if target_func:
                    print("  {} {} {}  ; calls {}".format(
                        marker, instr.getAddress(), instr, target_func.getName()))
                    continue

        print("  {} {} {}".format(marker, instr.getAddress(), instr))

        # Print references
        for ref in refs:
            print("      -> {}".format(ref.getToAddress()))

print("\n--- ls::LSFStringTable::Add ---")
get_function_disasm(LSF_ADD_ADDR)

# Also look at ls::DefaultObjectVisitor::AddToFixedStringTable
DEFAULT_VISITOR_ADDR = 0x1064fc0e4
print("\n--- ls::DefaultObjectVisitor::AddToFixedStringTable ---")
get_function_disasm(DEFAULT_VISITOR_ADDR)

print("\n" + "=" * 70)
print("Look for ADRP+LDR patterns that load global pointers")
print("These may reference ls__gGlobalStringTable")
print("=" * 70)
