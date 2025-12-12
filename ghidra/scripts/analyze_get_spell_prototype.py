# Analyze GetSpellPrototype function to find SpellPrototypeManager singleton
#
# Run: ./ghidra/scripts/run_analysis.sh analyze_get_spell_prototype.py

from ghidra.app.decompiler import DecompInterface
from progress_utils import init_progress, progress, finish_progress
import time
import re

start_time = time.time()
init_progress("GetSpellPrototype Analysis")

# Function addresses from symbol search
TARGET_FUNCTIONS = {
    "SpellCastWrapper::GetSpellPrototype": 0x10346e740,
    "SpawnSystemHelper::GetSpellPrototype": 0x104dcdf40,
    "WallSystemHelper::GetSpellPrototype": 0x1054c20f0,
    "__GLOBAL__sub_I_SpellPrototype.cpp": 0x1066e389c,
    "__GLOBAL__sub_I_StatusPrototypeManager.cpp": 0x106704ad4,
}

def decompile_function(func_addr, timeout=120):
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
    except Exception as e:
        return "Error: " + str(e)
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
            lines.append({
                'addr': addr.getOffset(),
                'disasm': str(inst),
            })
            count += 1
    return lines

def find_adrp_patterns(disasm):
    """Find ADRP+LDR/ADD patterns in disassembly"""
    patterns = []
    prev_adrp = {}

    for i, line in enumerate(disasm):
        inst = line['disasm']

        # Track ADRP instructions
        match = re.match(r'adrp\s+(\w+),\s*0x([0-9a-fA-F]+)', inst)
        if match:
            reg = match.group(1)
            page = int(match.group(2), 16)
            prev_adrp[reg] = {'page': page, 'addr': line['addr'], 'line': i}

        # Look for LDR/ADD using ADRP result
        for reg, adrp_info in prev_adrp.items():
            if reg in inst:
                offset_match = re.search(r'#0x([0-9a-fA-F]+)', inst)
                if offset_match:
                    offset = int(offset_match.group(1), 16)
                    global_addr = adrp_info['page'] + offset

                    if 'ldr' in inst.lower() or 'add' in inst.lower():
                        patterns.append({
                            'register': reg,
                            'page': adrp_info['page'],
                            'offset': offset,
                            'global_addr': global_addr,
                            'adrp_line': adrp_info['line'],
                            'use_line': i,
                            'use_inst': inst,
                        })

    return patterns

def main():
    output = []
    output.append("# GetSpellPrototype Analysis\n")
    output.append("**Date:** {}\n".format(time.strftime('%Y-%m-%d %H:%M')))
    output.append("---\n\n")

    for name, addr in TARGET_FUNCTIONS.items():
        progress("Analyzing {}...".format(name))

        func = getFunctionAt(toAddr(addr))
        if not func:
            output.append("## {} (0x{:x})\n".format(name, addr))
            output.append("**Error:** Function not found\n\n")
            continue

        output.append("## {} (0x{:x})\n".format(name, addr))
        output.append("- **Actual name:** `{}`\n".format(func.getName()))
        output.append("- **Size:** {} bytes\n\n".format(func.getBody().getNumAddresses()))

        # Get disassembly
        disasm = get_disassembly(addr, 100)

        # Find global address patterns
        patterns = find_adrp_patterns(disasm)

        # Filter to likely manager range
        manager_patterns = [p for p in patterns if 0x108900000 <= p['global_addr'] <= 0x108b00000]

        if manager_patterns:
            output.append("### Potential Manager Addresses\n")
            output.append("| Global Address | Register | Instruction |\n")
            output.append("|----------------|----------|-------------|\n")
            for p in manager_patterns:
                output.append("| `0x{:x}` | {} | `{}` |\n".format(
                    p['global_addr'], p['register'], p['use_inst']))
            output.append("\n")

        # Get decompiled output
        decomp = decompile_function(addr)
        if decomp:
            output.append("### Decompiled Code\n")
            output.append("```c\n")
            # Truncate if too long
            if len(decomp) > 4000:
                output.append(decomp[:4000] + "\n... (truncated)\n")
            else:
                output.append(decomp)
            output.append("```\n\n")

        # Show first 30 lines of disassembly
        output.append("### Disassembly (first 30 instructions)\n")
        output.append("```asm\n")
        for line in disasm[:30]:
            output.append("0x{:x}: {}\n".format(line['addr'], line['disasm']))
        output.append("```\n\n")

        output.append("---\n\n")

    # Summary
    output.append("## Summary\n\n")
    output.append("Look for ADRP+LDR patterns loading addresses in 0x108xxxxxx range.\n")
    output.append("The global that gets dereferenced twice (double-pointer) is likely the manager singleton.\n")

    duration = time.time() - start_time
    output.append("\n**Duration:** {:.1f} seconds\n".format(duration))

    output_path = "/tmp/get_spell_prototype_analysis.md"
    with open(output_path, 'w') as f:
        f.writelines(output)

    print("Results written to {}".format(output_path))
    finish_progress()

if __name__ == "__main__":
    main()
