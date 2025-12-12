# Find StatusPrototypeManager singleton
#
# Run: ./ghidra/scripts/run_analysis.sh find_status_manager.py

from ghidra.app.decompiler import DecompInterface
from progress_utils import init_progress, progress, finish_progress
import time
import re

start_time = time.time()
init_progress("StatusPrototypeManager Discovery")

# Search for GetStatusPrototype-like functions
def find_status_prototype_functions():
    """Search for functions that access StatusPrototypeManager"""
    symbol_table = currentProgram.getSymbolTable()
    matches = []

    for sym in symbol_table.getAllSymbols(True):
        name = sym.getName()
        # Look for functions that might access StatusPrototypeManager
        if ('GetStatusPrototype' in name or
            'StatusPrototype' in name and '::' in name and 'Get' in name or
            'StatusPrototypeManager' in name and 'm_ptr' in name):
            matches.append({
                'name': name,
                'address': sym.getAddress().getOffset(),
            })

    return matches

def decompile_function(func_addr, timeout=60):
    """Decompile a function"""
    func = getFunctionAt(toAddr(func_addr))
    if not func:
        return None

    try:
        decomp = DecompInterface()
        decomp.openProgram(currentProgram)
        result = decomp.decompileFunction(func, timeout, monitor)
        if result.decompileCompleted():
            return result.getDecompiledFunction().getC()
    except:
        pass
    return None

def get_disassembly(func_addr, max_instructions=50):
    """Get disassembly of a function"""
    lines = []
    func = getFunctionAt(toAddr(func_addr))
    if not func:
        return lines

    listing = currentProgram.getListing()
    body = func.getBody()

    count = 0
    addr_iter = body.getAddresses(True)
    while addr_iter.hasNext() and count < max_instructions:
        addr = addr_iter.next()
        inst = listing.getInstructionAt(addr)
        if inst:
            lines.append("0x{:x}: {}".format(addr.getOffset(), str(inst)))
            count += 1
    return lines

def find_globals_in_function(func_addr):
    """Find global address loads (ADRP+LDR pattern)"""
    func = getFunctionAt(toAddr(func_addr))
    if not func:
        return []

    listing = currentProgram.getListing()
    body = func.getBody()

    prev_adrp = {}
    globals_found = []

    addr_iter = body.getAddresses(True)
    while addr_iter.hasNext():
        addr = addr_iter.next()
        inst = listing.getInstructionAt(addr)
        if not inst:
            continue

        inst_str = str(inst)

        # Track ADRP
        match = re.match(r'adrp\s+(\w+),\s*0x([0-9a-fA-F]+)', inst_str)
        if match:
            reg = match.group(1)
            page = int(match.group(2), 16)
            prev_adrp[reg] = page

        # Look for LDR using ADRP result
        for reg, page in prev_adrp.items():
            if reg in inst_str and ('ldr' in inst_str.lower()):
                offset_match = re.search(r'#0x([0-9a-fA-F]+)', inst_str)
                if offset_match:
                    offset = int(offset_match.group(1), 16)
                    global_addr = page + offset
                    if 0x108900000 <= global_addr <= 0x108c00000:
                        globals_found.append(global_addr)

    return list(set(globals_found))

def main():
    output = []
    output.append("# StatusPrototypeManager Discovery\n")
    output.append("**Date:** {}\n".format(time.strftime('%Y-%m-%d %H:%M')))
    output.append("---\n\n")

    # Already confirmed
    output.append("## Already Confirmed\n")
    output.append("- **SpellPrototypeManager::m_ptr** = `0x1089bac80`\n\n")

    # Search for StatusPrototype functions
    output.append("## Symbol Search for StatusPrototype\n\n")
    matches = find_status_prototype_functions()

    if matches:
        output.append("| Name | Address |\n")
        output.append("|------|----------|\n")
        for m in matches[:20]:
            output.append("| `{}` | `0x{:x}` |\n".format(m['name'][:50], m['address']))
    else:
        output.append("No direct StatusPrototypeManager symbols found.\n")
    output.append("\n")

    # Analyze functions known to use StatusPrototypeManager
    # From earlier analysis: GetHitAnimationType uses both managers
    output.append("## Analyzing Functions That Use StatusPrototypeManager\n\n")

    # Analyze the CreateBoostSourceInfo function which references StatusPrototypeManager
    status_funcs = [
        ("eoc::active_roll::CreateBoostSourceInfo", 0x101c7b764),
        ("eoc::spell_cast::ValidateRange", 0x101f2ca34),
    ]

    for name, addr in status_funcs:
        progress("Analyzing {}...".format(name))

        func = getFunctionAt(toAddr(addr))
        if not func:
            output.append("### {} (0x{:x})\n".format(name, addr))
            output.append("Function not found\n\n")
            continue

        output.append("### {} (0x{:x})\n".format(name, addr))
        output.append("**Actual name:** `{}`\n".format(func.getName()))

        # Find globals
        globals_found = find_globals_in_function(addr)
        if globals_found:
            output.append("\n**Potential Manager Addresses:**\n")
            for g in sorted(globals_found):
                output.append("- `0x{:x}`\n".format(g))

        # Get first 30 lines of disassembly
        disasm = get_disassembly(addr, 40)
        if disasm:
            output.append("\n**Disassembly (first 40 instructions):**\n```asm\n")
            for line in disasm[:40]:
                output.append(line + "\n")
            output.append("```\n")

        output.append("\n---\n\n")

    # Look at functions that are KNOWN to use StatusPrototypeManager by looking
    # at the caller analysis results (RegisterSystems function loads many globals)
    output.append("## Analysis from RegisterSystems\n")
    output.append("From earlier analysis, RegisterSystems loads these addresses:\n")
    output.append("- `0x1089bac80` - **SpellPrototypeManager::m_ptr** (confirmed)\n")
    output.append("- `0x1089bdb30` - Near StatusPrototypeManager static init addresses\n")
    output.append("- `0x108a88b38` - Unknown (heavily used)\n")
    output.append("\n")

    # Summary
    output.append("## Summary\n\n")
    output.append("**Confirmed:**\n")
    output.append("- SpellPrototypeManager::m_ptr = `0x1089bac80`\n\n")
    output.append("**Candidates for StatusPrototypeManager::m_ptr:**\n")
    output.append("- `0x1089bdb30` - Near StatusPrototypeManager.cpp static init addresses\n")
    output.append("- Pattern suggests singleton at `0x1089bdb30` (0x7B0 after SpellPrototypeManager)\n")

    duration = time.time() - start_time
    output.append("\n**Duration:** {:.1f} seconds\n".format(duration))

    output_path = "/tmp/status_manager_discovery.md"
    with open(output_path, 'w') as f:
        f.writelines(output)

    print("Results written to {}".format(output_path))
    finish_progress()

if __name__ == "__main__":
    main()
