# Ghidra Script: Find GlobalStringTable in ARM64 macOS BG3 binary
# Run AFTER analysis with: -postScript find_globalstringtable.py
#
# Strategy:
# 1. Find XREFs to known constant strings (e.g., "Strength", "Dexterity")
# 2. Trace back to find where FixedString is created from string literal
# 3. Look for ADRP+LDR pattern that loads gGlobalStringTable pointer
# 4. Verify by checking for the 0xC600 offset to MainTable
#
# Windows BG3SE reference pattern:
#   mov rcx, cs:ls__gGlobalStringTable   ; Load GST pointer
#   add rcx, 0C600h                       ; Add offset to MainTable
#
# ARM64 equivalent:
#   adrp x0, page_of_gGlobalStringTable
#   ldr  x0, [x0, page_offset]            ; Load GST pointer

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.address import Address
from ghidra.app.decompiler import DecompInterface
import re

print("=" * 70)
print("GlobalStringTable Discovery Script for ARM64 macOS")
print("=" * 70)

# Target strings that are likely used as FixedStrings early in game init
TARGET_STRINGS = [
    "Strength",
    "Dexterity",
    "Constitution",
    "Intelligence",
    "Wisdom",
    "Charisma",
    "ProficiencyBonus",
    "Weapon",
    "Armor",
    "Shield",
]

# Results storage
found_strings = {}
candidate_gst_addrs = []

def find_string_addresses(string_table_targets):
    """Find addresses of target strings in the binary."""
    results = {}

    # Search in defined strings
    string_iterator = currentProgram.getListing().getDefinedData(True)
    for data in string_iterator:
        if data.hasStringValue():
            val = data.getValue()
            if val in string_table_targets:
                results[val] = data.getAddress()
                print("  Found '{}' at {}".format(val, data.getAddress()))

    return results

def find_xrefs_to_address(addr):
    """Find all code references to an address."""
    refs = []
    ref_iter = currentProgram.getReferenceManager().getReferencesTo(addr)
    while ref_iter.hasNext():
        ref = ref_iter.next()
        if ref.isMemoryReference():
            refs.append(ref.getFromAddress())
    return refs

def analyze_function_for_gst(func_addr, depth=0):
    """
    Analyze a function for GlobalStringTable access patterns.
    Look for:
    - ADRP instructions loading high bits of address
    - LDR instructions loading from page + offset
    - Patterns that look like GST pointer loading
    """
    if depth > 3:  # Don't recurse too deep
        return []

    candidates = []
    listing = currentProgram.getListing()

    # Get the function containing this address
    func = getFunctionContaining(func_addr)
    if func is None:
        return []

    print("    Analyzing function at {} (depth={})".format(func.getEntryPoint(), depth))

    # Look for ADRP+LDR patterns in the function
    instr_iter = listing.getInstructions(func.getBody(), True)
    adrp_cache = {}  # Track ADRP instructions for pairing

    for instr in instr_iter:
        mnemonic = instr.getMnemonicString()
        addr = instr.getAddress()

        if mnemonic == "adrp":
            # ADRP loads page address into register
            # Format: adrp x0, #page
            reg = instr.getRegister(0)
            if reg:
                adrp_cache[reg.getName()] = {
                    'addr': addr,
                    'page': instr.getScalar(1) if instr.getNumOperands() > 1 else None
                }

        elif mnemonic == "ldr" and len(adrp_cache) > 0:
            # LDR might be loading from ADRP result
            # Check if it references a global pointer
            for ref in instr.getReferencesFrom():
                ref_addr = ref.getToAddress()
                # Check if this could be a pointer to heap
                mem = currentProgram.getMemory()
                if mem.contains(ref_addr):
                    try:
                        # Try to read the value at this address
                        val = mem.getLong(ref_addr)
                        # Heuristic: heap addresses on macOS are typically > 0x100000000
                        if val > 0x100000000 and val < 0x800000000000:
                            candidates.append({
                                'instr_addr': addr,
                                'ptr_addr': ref_addr,
                                'ptr_value': val,
                                'context': 'ADRP+LDR pattern'
                            })
                            print("      Found potential GST pointer at {} -> 0x{:x}".format(
                                ref_addr, val))
                    except:
                        pass

    return candidates

def search_for_main_table_offset():
    """
    Search for the 0xC600 offset that indicates MainTable access.
    On ARM64 this would be: add xN, xN, #0xc600
    """
    print("\nSearching for MainTable offset (0xC600)...")

    # Search for immediate value 0xC600 in instructions
    listing = currentProgram.getListing()
    results = []

    # This is expensive - limit search to __TEXT segment
    text_block = None
    for block in currentProgram.getMemory().getBlocks():
        if block.getName() == "__TEXT" or block.isExecute():
            text_block = block
            break

    if text_block:
        print("  Searching in {} segment...".format(text_block.getName()))
        instr_iter = listing.getInstructions(text_block.getStart(), True)
        count = 0
        for instr in instr_iter:
            count += 1
            if count % 1000000 == 0:
                print("    Processed {} instructions...".format(count))

            # Look for ADD with immediate 0xC600
            mnemonic = instr.getMnemonicString()
            if mnemonic == "add":
                for i in range(instr.getNumOperands()):
                    scalar = instr.getScalar(i)
                    if scalar and scalar.getValue() == 0xC600:
                        results.append(instr.getAddress())
                        print("    Found add with 0xC600 at {}".format(instr.getAddress()))
                        if len(results) >= 10:  # Limit results
                            return results

            # Also check for MOVK which might set upper bits
            if count > 50000000:  # Safety limit
                print("    Search limit reached")
                break

    return results

def main():
    print("\nPhase 1: Finding target string addresses...")
    string_addrs = find_string_addresses(TARGET_STRINGS)

    if not string_addrs:
        print("ERROR: No target strings found. Try running ASCII Strings analyzer first.")
        return

    print("\nPhase 2: Finding XREFs to string addresses...")
    all_xrefs = {}
    for string_val, string_addr in string_addrs.items():
        xrefs = find_xrefs_to_address(string_addr)
        if xrefs:
            all_xrefs[string_val] = xrefs
            print("  '{}' has {} XREFs".format(string_val, len(xrefs)))
            for xref in xrefs[:3]:  # Show first 3
                print("    -> {}".format(xref))

    print("\nPhase 3: Analyzing functions with string XREFs...")
    gst_candidates = []
    for string_val, xrefs in all_xrefs.items():
        print("\n  Analyzing XREFs for '{}'...".format(string_val))
        for xref in xrefs[:5]:  # Analyze first 5 XREFs per string
            candidates = analyze_function_for_gst(xref)
            gst_candidates.extend(candidates)

    print("\nPhase 4: Searching for MainTable offset pattern...")
    offset_addrs = search_for_main_table_offset()

    print("\n" + "=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)

    print("\nStrings found: {}".format(len(string_addrs)))
    for s, addr in string_addrs.items():
        print("  {} -> {}".format(s, addr))

    print("\nPotential GST pointer candidates: {}".format(len(gst_candidates)))
    for c in gst_candidates:
        print("  Instruction at {}: ptr_addr={}, ptr_value=0x{:x}".format(
            c['instr_addr'], c['ptr_addr'], c['ptr_value']))

    print("\nMainTable offset (0xC600) locations: {}".format(len(offset_addrs)))
    for addr in offset_addrs:
        print("  {}".format(addr))

    print("\n" + "=" * 70)
    print("Next Steps:")
    print("1. Examine GST pointer candidates in Ghidra decompiler")
    print("2. Look for 0xC600 offset near GST loads")
    print("3. Verify structure matches Windows BG3SE GlobalStringTable")
    print("=" * 70)

# Run the script
main()
