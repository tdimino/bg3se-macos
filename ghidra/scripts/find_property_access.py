#!/usr/bin/env python3
"""
find_property_access.py - Discover stats property access offsets

Goal: Find offsets needed for reading stat properties like Damage, AC, etc.

Key structures from Windows BG3SE:
- Object.IndexedProperties: Vector<int32_t> at some offset in Object
- Object.GetAttributeInfo(name) -> returns Modifier* and sets attributeIndex
- RPGStats pools: FixedStrings, Floats, Int64s, GUIDs

Strategy:
1. Find functions with "GetString", "GetInt", "GetFloat" in stats context
2. Search for Object:: method symbols
3. Analyze ADRP/LDR patterns to find global pool accesses
4. Look for Vector access patterns (buf_[index])
"""

from ghidra.program.model.symbol import SymbolType
from progress_utils import init_progress, progress, finish_progress

def log(msg):
    print("[PropertyAccess] " + str(msg))

def search_symbols(pattern, limit=50):
    """Search for symbols containing pattern."""
    results = []
    symbol_table = currentProgram.getSymbolTable()
    for sym in symbol_table.getAllSymbols(False):
        name = sym.getName()
        if pattern.lower() in name.lower():
            results.append((name, sym.getAddress()))
            if len(results) >= limit:
                break
    return results

def find_string_in_memory(search_str, start_addr=None):
    """Find a string in memory."""
    memory = currentProgram.getMemory()
    if start_addr is None:
        start_addr = toAddr(0x100000000)

    search_bytes = search_str.encode('ascii') + b'\x00'
    addr = memory.findBytes(start_addr, search_bytes, None, True, monitor)
    return addr

def analyze_function(func_addr, depth=30):
    """Analyze function instructions for offset patterns."""
    listing = currentProgram.getListing()
    func = getFunctionContaining(func_addr)

    if not func:
        return []

    offsets_found = []
    body = func.getBody()
    inst_iter = listing.getInstructions(body, True)

    count = 0
    for inst in inst_iter:
        if count >= depth:
            break
        count += 1

        mnemonic = inst.getMnemonicString()

        # Look for LDR with offset (loading from struct field)
        if mnemonic == "ldr":
            num_ops = inst.getNumOperands()
            for op_idx in range(num_ops):
                try:
                    op_str = inst.getDefaultOperandRepresentation(op_idx)
                    # Pattern: [reg, #0xNN] - accessing struct field
                    if "[" in op_str and "#0x" in op_str:
                        # Extract offset
                        import re
                        match = re.search(r'#0x([0-9a-fA-F]+)', op_str)
                        if match:
                            offset = int(match.group(1), 16)
                            if offset > 0 and offset < 0x400:  # Reasonable struct offset
                                offsets_found.append((inst.getAddress(), offset, op_str))
                except:
                    pass

        # Look for ADD with immediate (calculating field address)
        if mnemonic == "add":
            num_ops = inst.getNumOperands()
            for op_idx in range(num_ops):
                try:
                    op_str = inst.getDefaultOperandRepresentation(op_idx)
                    if "#0x" in op_str:
                        import re
                        match = re.search(r'#0x([0-9a-fA-F]+)', op_str)
                        if match:
                            offset = int(match.group(1), 16)
                            if offset > 0 and offset < 0x400:
                                offsets_found.append((inst.getAddress(), offset, "ADD " + op_str))
                except:
                    pass

    return offsets_found

def main():
    init_progress("find_property_access.py")
    log("=== Stats Property Access Offset Discovery ===\n")

    # Phase 1: Search for Object method symbols
    progress("Phase 1: Searching Object:: method symbols", 10)

    object_patterns = [
        "Object::GetString",
        "Object::GetInt",
        "Object::GetFloat",
        "GetAttributeInfo",
        "IndexedProperties",
        "CRPGStats_Object",
    ]

    log("--- Object Method Symbols ---")
    for pattern in object_patterns:
        results = search_symbols(pattern, 10)
        if results:
            log("Pattern '%s' found %d matches:" % (pattern, len(results)))
            for name, addr in results:
                log("  0x%x: %s" % (addr.getOffset(), name[:80]))
                # Analyze first match
                offsets = analyze_function(addr, 50)
                if offsets:
                    log("    Offsets accessed:")
                    for inst_addr, offset, context in offsets[:10]:
                        log("      0x%x: offset 0x%x (%s)" % (inst_addr.getOffset(), offset, context))

    # Phase 2: Search for stats::Modifier symbols
    progress("Phase 2: Searching Modifier symbols", 30)

    modifier_patterns = [
        "Modifier::GetValue",
        "CRPGStats_Modifier",
        "ModifierValueList",
        "RPGEnumeration",
    ]

    log("\n--- Modifier Symbols ---")
    for pattern in modifier_patterns:
        results = search_symbols(pattern, 10)
        if results:
            log("Pattern '%s' found %d matches:" % (pattern, len(results)))
            for name, addr in results[:5]:
                log("  0x%x: %s" % (addr.getOffset(), name[:80]))

    # Phase 3: Look for pool-related strings
    progress("Phase 3: Searching pool-related strings", 50)

    pool_strings = [
        "FixedStrings",
        "ConstantInt",
        "ConstantFloat",
        "TranslatedString",
        "ExtraData",
    ]

    log("\n--- Pool-Related Strings ---")
    for s in pool_strings:
        addr = find_string_in_memory(s)
        if addr:
            log("Found '%s' at 0x%x" % (s, addr.getOffset()))
            # Look for XREFs
            refs = list(getReferencesTo(addr))
            log("  %d references" % len(refs))
            for ref in refs[:3]:
                log("    From 0x%x" % ref.getFromAddress().getOffset())

    # Phase 4: Search for RPGStats field access patterns
    progress("Phase 4: Analyzing RPGStats access patterns", 70)

    log("\n--- RPGStats Pool Offset Analysis ---")

    # We know RPGStats::m_ptr is at 0x1089c5730 from STATS.md
    # ModifierLists at +0x60, Objects at +0xC0
    # We need to find pools which should be after these

    # Look for functions that access RPGStats and use offsets
    rpgstats_syms = search_symbols("RPGStats", 20)

    # Find functions that are likely pool accessors
    accessor_patterns = [
        "GetFixedString",
        "GetFloat",
        "GetInt64",
        "GetGUID",
    ]

    for pattern in accessor_patterns:
        results = search_symbols(pattern, 5)
        if results:
            log("\nPattern '%s':" % pattern)
            for name, addr in results[:2]:
                log("  0x%x: %s" % (addr.getOffset(), name[:60]))
                offsets = analyze_function(addr, 80)
                if offsets:
                    # Group offsets by value
                    offset_counts = {}
                    for _, offset, _ in offsets:
                        offset_counts[offset] = offset_counts.get(offset, 0) + 1
                    log("    Common offsets: %s" % sorted(offset_counts.items(), key=lambda x: -x[1])[:5])

    # Phase 5: Decompile key functions if available
    progress("Phase 5: Looking for GetAttribute pattern", 85)

    log("\n--- GetAttribute Analysis ---")

    # Search for functions that might be GetAttributeInfo
    attr_syms = search_symbols("GetAttribute", 10)
    attr_syms.extend(search_symbols("GetProperty", 10))

    if attr_syms:
        for name, addr in attr_syms[:5]:
            log("Found: 0x%x %s" % (addr.getOffset(), name[:60]))
    else:
        log("No direct GetAttribute symbols found")
        log("Will need to find via XREF from string comparisons")

    # Look for comparison with property names
    log("\nSearching for property name strings...")
    prop_names = ["Damage", "DamageType", "Level", "ValueScale"]
    for pname in prop_names:
        addr = find_string_in_memory(pname)
        if addr:
            log("  '%s' at 0x%x" % (pname, addr.getOffset()))
            refs = list(getReferencesTo(addr))
            if refs:
                log("    Referenced from %d locations" % len(refs))

    progress("Analysis complete", 95)

    log("\n=== Summary ===")
    log("Next steps:")
    log("1. Use live console probing with discovered offsets")
    log("2. Verify IndexedProperties offset in Object (likely +0x08 after VMT)")
    log("3. Find ModifierValueLists offset in RPGStats (likely +0x00)")
    log("4. Discover pool offsets via incremental probing")

    finish_progress()

if __name__ == "__main__":
    main()
