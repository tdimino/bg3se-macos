#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
find_modifier_attributes.py - Discover Modifier structure layout for stats property access

Purpose:
    Find the correct offsets for Modifier struct fields on ARM64, enabling
    property name -> IndexedProperties index mapping for Ext.Stats API.

Strategy:
    1. Search for known attribute name strings ("Damage", "DamageType", etc.)
    2. Find XREFs to those strings
    3. Analyze instruction patterns to discover Modifier.Name offset
    4. Dump raw memory at known Modifier array to verify layout
    5. Scan for property pool Arrays after Objects in RPGStats

Known facts:
    - RPGStats::m_ptr at 0x1089c5730
    - ModifierLists at +0x60 (9 entries)
    - Objects at +0xC0 (15,774 entries)
    - ModifierList[8] = "Weapon" with 61 attributes
    - CNamedElementManager: buf_=+0x08, size_=+0x14

Problem:
    Current Modifier.Name offset (0x10) produces garbage - need correct offset.
"""

from __future__ import print_function
import sys
import re

# Ghidra imports
from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

# Progress tracking
PROGRESS_FILE = "/tmp/ghidra_progress.log"

def progress(msg, pct=None):
    """Log progress to file and console."""
    line = "[{:3d}%] {}".format(int(pct) if pct else 0, msg) if pct is not None else msg
    print(line)
    try:
        with open(PROGRESS_FILE, "a") as f:
            f.write(line + "\n")
    except:
        pass

def init_progress():
    """Clear progress file."""
    try:
        with open(PROGRESS_FILE, "w") as f:
            f.write("=== find_modifier_attributes.py ===\n")
    except:
        pass

# ============================================================================
# Memory Reading Utilities
# ============================================================================

def read_memory_bytes(addr, size):
    """Read raw bytes from memory."""
    try:
        memory = currentProgram.getMemory()
        data = bytearray(size)
        memory.getBytes(addr, data)
        return bytes(data)
    except:
        return None

def read_u32(addr):
    """Read uint32_t at address."""
    data = read_memory_bytes(addr, 4)
    if data:
        return int.from_bytes(data, byteorder='little', signed=False)
    return None

def read_u64(addr):
    """Read uint64_t at address."""
    data = read_memory_bytes(addr, 8)
    if data:
        return int.from_bytes(data, byteorder='little', signed=False)
    return None

def read_i32(addr):
    """Read int32_t at address."""
    data = read_memory_bytes(addr, 4)
    if data:
        return int.from_bytes(data, byteorder='little', signed=True)
    return None

def read_ptr(addr):
    """Read pointer at address."""
    val = read_u64(addr)
    if val:
        return toAddr(val)
    return None

def hex_dump(addr, size=64, prefix=""):
    """Dump memory as hex."""
    data = read_memory_bytes(addr, size)
    if not data:
        return "Failed to read memory at {}".format(addr)

    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join('{:02x}'.format(b) for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append("{}{}: {}  {}".format(prefix, addr.add(i), hex_part.ljust(48), ascii_part))
    return '\n'.join(lines)

# ============================================================================
# String Search
# ============================================================================

def find_string_in_memory(search_str):
    """Find a string in memory blocks."""
    memory = currentProgram.getMemory()
    search_bytes = search_str.encode('utf-8')

    for block in memory.getBlocks():
        if not block.isInitialized():
            continue

        start = block.getStart()
        try:
            data = bytearray(block.getSize())
            block.getBytes(start, data)

            idx = bytes(data).find(search_bytes)
            if idx >= 0:
                # Verify null terminator or reasonable boundary
                found_addr = start.add(idx)
                return found_addr
        except:
            continue

    return None

def find_all_string_occurrences(search_str, max_results=10):
    """Find all occurrences of a string."""
    memory = currentProgram.getMemory()
    search_bytes = search_str.encode('utf-8')
    results = []

    for block in memory.getBlocks():
        if not block.isInitialized():
            continue

        start = block.getStart()
        try:
            data = bytearray(block.getSize())
            block.getBytes(start, data)
            data_bytes = bytes(data)

            idx = 0
            while idx < len(data_bytes) and len(results) < max_results:
                found = data_bytes.find(search_bytes, idx)
                if found < 0:
                    break
                results.append(start.add(found))
                idx = found + 1
        except:
            continue

    return results

# ============================================================================
# XREF Analysis
# ============================================================================

def get_xrefs_to(addr):
    """Get all cross-references to an address."""
    refs = []
    ref_manager = currentProgram.getReferenceManager()

    for ref in ref_manager.getReferencesTo(addr):
        refs.append({
            'from': ref.getFromAddress(),
            'type': ref.getReferenceType().getName()
        })

    return refs

def get_function_containing(addr):
    """Get the function containing an address."""
    fm = currentProgram.getFunctionManager()
    return fm.getFunctionContaining(addr)

# ============================================================================
# Instruction Analysis
# ============================================================================

def analyze_function_offsets(func):
    """
    Analyze a function for memory access patterns.
    Returns list of offsets used in LDR/STR instructions.
    """
    offsets = []
    listing = currentProgram.getListing()

    try:
        for inst in listing.getInstructions(func.getBody(), True):
            mnemonic = inst.getMnemonicString().lower()

            if mnemonic.startswith('ldr') or mnemonic.startswith('str'):
                # Extract operands
                num_ops = inst.getNumOperands()
                for i in range(num_ops):
                    try:
                        op_str = inst.getDefaultOperandRepresentation(i)
                        # Look for [Xn, #0xNN] pattern
                        match = re.search(r'\[.*#0x([0-9a-fA-F]+)\]', op_str)
                        if match:
                            offset = int(match.group(1), 16)
                            offsets.append({
                                'offset': offset,
                                'addr': inst.getAddress(),
                                'instr': str(inst)
                            })
                    except:
                        pass
    except:
        pass

    return offsets

def find_adrp_patterns(func):
    """
    Find ADRP + LDR/ADD patterns that load global pointers.
    """
    patterns = []
    listing = currentProgram.getListing()

    try:
        instructions = list(listing.getInstructions(func.getBody(), True))

        for i, inst in enumerate(instructions):
            if inst.getMnemonicString().lower() == 'adrp':
                # Get the page address
                try:
                    op_str = inst.getDefaultOperandRepresentation(1)
                    if '#' in op_str:
                        page_match = re.search(r'#?0x([0-9a-fA-F]+)', op_str)
                        if page_match:
                            page_addr = int(page_match.group(1), 16)

                            # Check next instruction
                            if i + 1 < len(instructions):
                                next_inst = instructions[i + 1]
                                next_mnem = next_inst.getMnemonicString().lower()

                                if next_mnem in ['ldr', 'add']:
                                    patterns.append({
                                        'adrp_addr': inst.getAddress(),
                                        'page': hex(page_addr),
                                        'next_instr': str(next_inst)
                                    })
                except:
                    pass
    except:
        pass

    return patterns

# ============================================================================
# Main Analysis
# ============================================================================

def phase1_search_attribute_strings():
    """Phase 1: Search for stats system strings that ARE in the binary."""
    progress("Phase 1: Searching for stats system strings...", 5)

    # Strings that ARE in the binary (not loaded from data files)
    # Attribute names like "Damage" are loaded from Stats/*.txt at runtime
    STATS_STRINGS = [
        # Type names (these ARE in the binary)
        "Weapon",
        "Armor",
        "Character",
        "SpellData",
        "StatusData",
        "PassiveData",
        "InterruptData",
        "CriticalHitTypeData",
        "Object",
        # Pool type names
        "ConstantInt",
        "ConstantFloat",
        "FixedString",
        "TranslatedString",
        "GUID",
        # Component strings
        "RPGStats",
        "ModifierList",
        "ModifierValueList",
        "EnumerationIndex",
        # Method names (might be in RTTI)
        "GetAttributeInfo",
        "GetHandleByName",
        "IndexedProperties",
    ]

    results = {}

    for i, name in enumerate(STATS_STRINGS):
        progress("  Searching for '{}'...".format(name), 5 + (i * 2))

        addrs = find_all_string_occurrences(name, max_results=5)

        if addrs:
            results[name] = addrs
            progress("    Found '{}' at {} locations".format(name, len(addrs)))
            for addr in addrs[:3]:
                progress("      {}".format(addr))
        else:
            progress("    '{}' not found".format(name))

    return results

def phase2_analyze_xrefs(string_results):
    """Phase 2: Analyze XREFs to attribute strings."""
    progress("Phase 2: Analyzing XREFs to attribute strings...", 30)

    xref_results = {}

    for attr_name, addrs in string_results.items():
        if not addrs:
            continue

        progress("  Analyzing XREFs for '{}'...".format(attr_name))

        all_xrefs = []
        for addr in addrs:
            xrefs = get_xrefs_to(addr)
            all_xrefs.extend(xrefs)

        if all_xrefs:
            xref_results[attr_name] = all_xrefs
            progress("    Found {} XREFs for '{}'".format(len(all_xrefs), attr_name))

            # Analyze first few XREFs
            for xref in all_xrefs[:3]:
                func = get_function_containing(xref['from'])
                func_name = func.getName() if func else "unknown"
                progress("      {} from {} ({})".format(
                    xref['from'], func_name, xref['type']))

    return xref_results

def phase3_analyze_accessor_functions(xref_results):
    """Phase 3: Analyze functions that use attribute strings for offset patterns."""
    progress("Phase 3: Analyzing accessor function patterns...", 50)

    all_offsets = {}
    analyzed_funcs = set()

    for attr_name, xrefs in xref_results.items():
        progress("  Analyzing functions referencing '{}'...".format(attr_name))

        for xref in xrefs[:5]:  # Limit to first 5
            func = get_function_containing(xref['from'])
            if not func:
                continue

            func_addr = func.getEntryPoint()
            if func_addr in analyzed_funcs:
                continue
            analyzed_funcs.add(func_addr)

            offsets = analyze_function_offsets(func)

            if offsets:
                func_name = func.getName()
                progress("    {} ({} offset accesses)".format(func_name, len(offsets)))

                # Group by offset value
                offset_counts = {}
                for off in offsets:
                    val = off['offset']
                    offset_counts[val] = offset_counts.get(val, 0) + 1

                # Show most common offsets
                sorted_offsets = sorted(offset_counts.items(), key=lambda x: -x[1])
                for offset_val, count in sorted_offsets[:10]:
                    progress("      +0x{:02x}: {} occurrences".format(offset_val, count))

                    if offset_val not in all_offsets:
                        all_offsets[offset_val] = []
                    all_offsets[offset_val].append({
                        'func': func_name,
                        'attr': attr_name,
                        'count': count
                    })

    return all_offsets

def phase4_dump_modifier_memory():
    """
    Phase 4: Dump raw memory at known ModifierList[8] (Weapon) location.

    We know from C code:
    - ModifierLists at RPGStats+0x60
    - ModifierList[8] = Weapon
    - Attributes count = 61
    """
    progress("Phase 4: Dumping Modifier memory (requires runtime data)...", 70)

    # These are Ghidra static addresses, not runtime
    # The actual pointers need to come from running game

    # But we CAN search for the strings that should be attribute names
    # and see how they're referenced

    progress("  Note: Raw memory dump requires runtime game data")
    progress("  Searching for ModifierList-related symbols instead...")

    # Search for symbols related to ModifierList
    symbol_table = currentProgram.getSymbolTable()
    fm = currentProgram.getFunctionManager()

    modifier_symbols = []
    for sym in symbol_table.getAllSymbols(True):
        name = sym.getName()
        if 'Modifier' in name or 'modifier' in name:
            modifier_symbols.append({
                'name': name,
                'addr': sym.getAddress(),
                'type': str(sym.getSymbolType())
            })

    progress("  Found {} Modifier-related symbols".format(len(modifier_symbols)))
    for sym in modifier_symbols[:20]:  # Show first 20
        progress("    {} at {} ({})".format(sym['name'], sym['addr'], sym['type']))

    # Look for GetAttributeInfo or similar functions
    getattr_funcs = []
    for func in fm.getFunctions(True):
        name = func.getName()
        if 'GetAttribute' in name or 'getAttribute' in name:
            getattr_funcs.append(func)

    progress("  Found {} GetAttribute* functions".format(len(getattr_funcs)))
    for func in getattr_funcs[:10]:
        progress("    {} at {}".format(func.getName(), func.getEntryPoint()))

        # Analyze this function for offsets
        offsets = analyze_function_offsets(func)
        if offsets:
            offset_set = set(off['offset'] for off in offsets)
            progress("      Offsets used: {}".format(
                ', '.join('0x{:02x}'.format(o) for o in sorted(offset_set)[:15])))

    return modifier_symbols, getattr_funcs

def phase5_find_property_pools():
    """
    Phase 5: Search for property pool symbols and estimate RPGStats layout.
    """
    progress("Phase 5: Searching for property pool patterns...", 85)

    # Search for pool-related strings
    POOL_STRINGS = [
        "FixedStrings",
        "ConstantInt",
        "ConstantFloat",
        "TranslatedString",
        "GUID",
        "Requirements",
        "Conditions",
    ]

    pool_results = {}

    for pool_name in POOL_STRINGS:
        addrs = find_all_string_occurrences(pool_name, max_results=3)
        if addrs:
            pool_results[pool_name] = addrs
            progress("  '{}' found at {}".format(pool_name, addrs[0]))

            # Get XREFs
            xrefs = get_xrefs_to(addrs[0])
            if xrefs:
                progress("    {} XREFs".format(len(xrefs)))
                for xref in xrefs[:2]:
                    func = get_function_containing(xref['from'])
                    if func:
                        progress("      Referenced from {} at {}".format(
                            func.getName(), xref['from']))

    # Search for RPGStats symbols
    progress("  Searching for RPGStats symbols...")
    symbol_table = currentProgram.getSymbolTable()

    rpgstats_symbols = []
    for sym in symbol_table.getAllSymbols(True):
        name = sym.getName()
        if 'RPGStats' in name or 'rpgstats' in name.lower():
            rpgstats_symbols.append({
                'name': name,
                'addr': sym.getAddress()
            })

    progress("  Found {} RPGStats symbols".format(len(rpgstats_symbols)))
    for sym in rpgstats_symbols[:15]:
        progress("    {} at {}".format(sym['name'], sym['addr']))

    return pool_results

def generate_summary(string_results, offset_results):
    """Generate summary with recommendations."""
    progress("\n" + "=" * 60, 95)
    progress("SUMMARY AND RECOMMENDATIONS")
    progress("=" * 60)

    # Summarize found strings
    progress("\nAttribute Strings Found:")
    for attr_name, addrs in string_results.items():
        if addrs:
            progress("  '{}': {} occurrences".format(attr_name, len(addrs)))

    # Summarize common offsets
    if offset_results:
        progress("\nCommon Offsets in Accessor Functions:")
        sorted_offsets = sorted(offset_results.items(), key=lambda x: -len(x[1]))
        for offset_val, occurrences in sorted_offsets[:15]:
            funcs = set(o['func'] for o in occurrences)
            progress("  +0x{:02x}: used in {} functions".format(offset_val, len(funcs)))

    progress("\nPotential Modifier.Name Offsets to Test:")
    progress("  Current (failing): 0x10")
    progress("  Candidates: 0x0C, 0x10, 0x18, 0x20")

    progress("\nNext Steps:")
    progress("  1. Update stats_manager.c MODIFIER_OFFSET_NAME")
    progress("  2. Test each candidate offset via Ext.Stats.DumpAttributes(8)")
    progress("  3. Verify attribute names appear correctly")

    progress("\n" + "=" * 60, 100)

def main():
    """Main entry point."""
    init_progress()
    progress("=" * 60)
    progress("find_modifier_attributes.py - Modifier Structure Discovery")
    progress("=" * 60)
    progress("Binary: {}".format(currentProgram.getName()))
    progress("")

    # Phase 1: Search for attribute strings
    string_results = phase1_search_attribute_strings()

    # Phase 2: Analyze XREFs
    xref_results = phase2_analyze_xrefs(string_results)

    # Phase 3: Analyze accessor functions
    offset_results = phase3_analyze_accessor_functions(xref_results)

    # Phase 4: Dump modifier memory
    modifier_syms, getattr_funcs = phase4_dump_modifier_memory()

    # Phase 5: Find property pools
    pool_results = phase5_find_property_pools()

    # Generate summary
    generate_summary(string_results, offset_results)

    progress("\nScript complete!")

# Run
if __name__ == "__main__":
    main()
else:
    main()
