# Find SpellPrototypeManager and StatusPrototypeManager singletons
# Analyzes GetHitAnimationType which takes both managers as parameters
#
# Run: ./ghidra/scripts/run_analysis.sh find_spell_status_managers.py

from ghidra.app.decompiler import DecompInterface
from progress_utils import init_progress, progress, finish_progress
import time
import re

start_time = time.time()
init_progress("SpellPrototypeManager & StatusPrototypeManager Discovery")

# Key function that uses both managers
TARGET_FUNCTIONS = {
    "GetHitAnimationType": 0x101b90378,
    "LEGACY_GetSpellDamage_Call": 0x101107498,
    "RegisterGameAnalyticsSystem": 0x100f97de0,
}

# Additional functions that may reference managers
ADDITIONAL_TARGETS = {
    "CharacterManager_RegisterSystem": 0x101020a94,
    "ReplaceDefaultValues_SpellPrototype": 0x100c48e18,
}

def get_instructions(func, max_instructions=200):
    """Get all instructions in a function"""
    instructions = []
    listing = currentProgram.getListing()
    body = func.getBody()

    addr_iter = body.getAddresses(True)
    count = 0
    while addr_iter.hasNext() and count < max_instructions:
        addr = addr_iter.next()
        inst = listing.getInstructionAt(addr)
        if inst:
            instructions.append({
                'addr': addr.getOffset(),
                'mnemonic': inst.getMnemonicString(),
                'full': str(inst),
            })
            count += 1
    return instructions

def find_adrp_ldr_globals(instructions):
    """Find ADRP+LDR/ADD patterns that load global addresses"""
    globals_found = []

    for i, inst in enumerate(instructions):
        if inst['mnemonic'] == 'adrp':
            # Parse ADRP instruction to get page address
            # Format: "adrp x8,0x108aec000"
            match = re.search(r'adrp\s+(\w+),\s*0x([0-9a-fA-F]+)', inst['full'])
            if match:
                reg = match.group(1)
                page = int(match.group(2), 16)

                # Look for following LDR or ADD using same register
                for j in range(i+1, min(i+5, len(instructions))):
                    next_inst = instructions[j]

                    # LDR pattern: "ldr x8,[x8, #0xcd8]"
                    if next_inst['mnemonic'] == 'ldr' and reg in next_inst['full']:
                        offset_match = re.search(r'#0x([0-9a-fA-F]+)', next_inst['full'])
                        if offset_match:
                            offset = int(offset_match.group(1), 16)
                            global_addr = page + offset
                            globals_found.append({
                                'type': 'ldr',
                                'register': reg,
                                'page': page,
                                'offset': offset,
                                'global_addr': global_addr,
                                'adrp_addr': inst['addr'],
                                'ldr_addr': next_inst['addr'],
                                'adrp': inst['full'],
                                'ldr': next_inst['full'],
                            })

                    # ADD pattern: "add x8, x8, #0xcd8"
                    elif next_inst['mnemonic'] == 'add' and reg in next_inst['full']:
                        offset_match = re.search(r'#0x([0-9a-fA-F]+)', next_inst['full'])
                        if offset_match:
                            offset = int(offset_match.group(1), 16)
                            global_addr = page + offset
                            globals_found.append({
                                'type': 'add',
                                'register': reg,
                                'page': page,
                                'offset': offset,
                                'global_addr': global_addr,
                                'adrp_addr': inst['addr'],
                                'add_addr': next_inst['addr'],
                                'adrp': inst['full'],
                                'add': next_inst['full'],
                            })

    return globals_found

def decompile_function(func):
    """Get decompiled output for a function"""
    try:
        decomp = DecompInterface()
        decomp.openProgram(currentProgram)
        result = decomp.decompileFunction(func, 60, monitor)
        if result.decompileCompleted():
            return result.getDecompiledFunction().getC()
    except Exception as e:
        return "Decompilation failed: " + str(e)
    return None

def analyze_function(name, addr):
    """Analyze a function for singleton patterns"""
    progress("Analyzing {} at 0x{:x}...".format(name, addr))

    func = getFunctionAt(toAddr(addr))
    if not func:
        return {'name': name, 'address': addr, 'error': 'Function not found'}

    result = {
        'name': name,
        'address': addr,
        'func_name': func.getName(),
        'func_size': func.getBody().getNumAddresses(),
        'globals': [],
        'decompiled': None,
    }

    # Get instructions and find globals
    instructions = get_instructions(func)
    result['globals'] = find_adrp_ldr_globals(instructions)

    # Get decompiled output
    result['decompiled'] = decompile_function(func)

    return result

def main():
    output = []
    output.append("# SpellPrototypeManager & StatusPrototypeManager Discovery\n")
    output.append("**Date:** {}\n".format(time.strftime('%Y-%m-%d %H:%M')))
    output.append("---\n\n")

    # Known singleton addresses for reference
    output.append("## Known Singletons (for reference)\n\n")
    output.append("| Manager | Global Address | Source |\n")
    output.append("|---------|----------------|--------|\n")
    output.append("| RPGStats::m_ptr | `0x1089c5730` | Exported |\n")
    output.append("| PassivePrototypeManager* | `0x108aeccd8` | GetPassivePrototype ADRP+LDR |\n")
    output.append("| BoostPrototypeManager::m_ptr | `0x108991528` | Previous analysis |\n")
    output.append("\n")

    # Analyze target functions
    output.append("## Target Function Analysis\n\n")

    all_globals = {}  # Track unique globals across all functions

    for name, addr in TARGET_FUNCTIONS.items():
        result = analyze_function(name, addr)

        output.append("### {}\n".format(name))
        output.append("- **Address:** `0x{:x}`\n".format(addr))

        if 'error' in result:
            output.append("- **Error:** {}\n\n".format(result['error']))
            continue

        output.append("- **Function name:** `{}`\n".format(result['func_name']))
        output.append("- **Size:** {} bytes\n".format(result['func_size']))
        output.append("- **Globals found:** {}\n\n".format(len(result['globals'])))

        if result['globals']:
            output.append("| Global Address | Page | Offset | Type | Pattern |\n")
            output.append("|----------------|------|--------|------|----------|\n")
            for g in result['globals']:
                pattern = g['adrp'] + " + " + g.get('ldr', g.get('add', ''))
                output.append("| `0x{:x}` | `0x{:x}` | `0x{:x}` | {} | `{}` |\n".format(
                    g['global_addr'], g['page'], g['offset'], g['type'], pattern[:50]))

                # Track unique globals
                if g['global_addr'] not in all_globals:
                    all_globals[g['global_addr']] = []
                all_globals[g['global_addr']].append(name)

        # Include partial decompiled output
        if result['decompiled']:
            decomp = result['decompiled']
            # Find lines mentioning 'Spell' or 'Status'
            relevant_lines = [l for l in decomp.split('\n')
                           if 'spell' in l.lower() or 'status' in l.lower() or 'prototype' in l.lower()]
            if relevant_lines:
                output.append("\n**Relevant decompiled lines:**\n```c\n")
                for line in relevant_lines[:15]:
                    output.append(line + "\n")
                output.append("```\n")

            # Also look for global pointer loads
            ptr_lines = [l for l in decomp.split('\n') if '0x108' in l]
            if ptr_lines:
                output.append("\n**Lines with potential singleton addresses:**\n```c\n")
                for line in ptr_lines[:10]:
                    output.append(line + "\n")
                output.append("```\n")

        output.append("\n---\n\n")

    # Summary of unique globals
    output.append("## Summary: Unique Global Addresses\n\n")
    output.append("| Address | Referenced By | Candidate For |\n")
    output.append("|---------|---------------|---------------|\n")

    # Filter to likely singleton range (0x108900000 - 0x108b00000)
    for addr in sorted(all_globals.keys()):
        if 0x108900000 <= addr <= 0x108b00000:
            funcs = ", ".join(all_globals[addr])
            candidate = ""
            if addr == 0x1089c5730:
                candidate = "RPGStats::m_ptr (known)"
            elif addr == 0x108aeccd8:
                candidate = "PassivePrototypeManager (known)"
            elif addr == 0x108991528:
                candidate = "BoostPrototypeManager (known)"
            else:
                candidate = "**NEW - investigate**"

            output.append("| `0x{:x}` | {} | {} |\n".format(addr, funcs, candidate))

    duration = time.time() - start_time
    output.append("\n**Duration:** {:.1f} seconds\n".format(duration))

    # Write output
    output_path = "/tmp/spell_status_managers.md"
    with open(output_path, 'w') as f:
        f.writelines(output)

    print("Results written to {}".format(output_path))
    print("\n=== Quick Summary ===")
    print("Analyzed {} functions".format(len(TARGET_FUNCTIONS)))
    print("Found {} unique global addresses in singleton range".format(
        len([a for a in all_globals if 0x108900000 <= a <= 0x108b00000])))

    finish_progress()

if __name__ == "__main__":
    main()
