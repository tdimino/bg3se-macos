# Find callers of functions that take SpellPrototypeManager/StatusPrototypeManager
# and trace where those parameters come from
#
# Run: ./ghidra/scripts/run_analysis.sh find_spell_manager_callers.py

from ghidra.app.decompiler import DecompInterface
from progress_utils import init_progress, progress, finish_progress
import time
import re

start_time = time.time()
init_progress("SpellPrototypeManager/StatusPrototypeManager Caller Analysis")

# Functions that take managers as parameters
TARGET_FUNCTIONS = {
    "RegisterGameAnalyticsSystem": 0x100f97de0,
    "GetHitAnimationType": 0x101b90378,
}

# Additional candidates to analyze - functions that might PROVIDE managers
POTENTIAL_PROVIDERS = [
    # Look for initializers or getters
    ("__GLOBAL__sub_I_SpellPrototype.cpp", None),  # Static initializer
    ("SpellPrototypeManager::Get", None),
    ("StatusPrototypeManager::Get", None),
]

def search_for_symbol(pattern):
    """Search symbol table for pattern"""
    symbol_table = currentProgram.getSymbolTable()
    matches = []
    for sym in symbol_table.getAllSymbols(True):
        name = sym.getName()
        if pattern.lower() in name.lower():
            matches.append({
                'name': name,
                'address': sym.getAddress().getOffset(),
            })
    return matches

def get_callers(func_addr):
    """Get all callers of a function"""
    callers = []
    func = getFunctionAt(toAddr(func_addr))
    if not func:
        return callers

    ref_mgr = currentProgram.getReferenceManager()
    refs = ref_mgr.getReferencesTo(func.getEntryPoint())

    for ref in refs:
        if ref.getReferenceType().isCall():
            from_addr = ref.getFromAddress()
            from_func = getFunctionContaining(from_addr)
            if from_func:
                callers.append({
                    'address': from_addr.getOffset(),
                    'func_name': from_func.getName(),
                    'func_addr': from_func.getEntryPoint().getOffset(),
                })
    return callers

def decompile_function(func_addr):
    """Get decompiled output"""
    func = getFunctionAt(toAddr(func_addr))
    if not func:
        return None

    try:
        decomp = DecompInterface()
        decomp.openProgram(currentProgram)
        result = decomp.decompileFunction(func, 60, monitor)
        if result.decompileCompleted():
            return result.getDecompiledFunction().getC()
    except:
        pass
    return None

def find_global_loads_in_function(func_addr):
    """Find all global address loads in a function via ADRP+LDR pattern"""
    globals_found = []
    func = getFunctionAt(toAddr(func_addr))
    if not func:
        return globals_found

    listing = currentProgram.getListing()
    body = func.getBody()

    prev_adrp = {}  # Track ADRP by register

    addr_iter = body.getAddresses(True)
    while addr_iter.hasNext():
        addr = addr_iter.next()
        inst = listing.getInstructionAt(addr)
        if not inst:
            continue

        inst_str = str(inst)
        mnem = inst.getMnemonicString()

        # Track ADRP instructions
        if mnem == 'adrp':
            match = re.search(r'adrp\s+(\w+),\s*0x([0-9a-fA-F]+)', inst_str)
            if match:
                reg = match.group(1)
                page = int(match.group(2), 16)
                prev_adrp[reg] = {'page': page, 'addr': addr.getOffset()}

        # Look for LDR that uses previous ADRP
        elif mnem == 'ldr':
            for reg, adrp_info in prev_adrp.items():
                if reg in inst_str:
                    offset_match = re.search(r'#0x([0-9a-fA-F]+)', inst_str)
                    if offset_match:
                        offset = int(offset_match.group(1), 16)
                        global_addr = adrp_info['page'] + offset
                        globals_found.append({
                            'global_addr': global_addr,
                            'adrp_addr': adrp_info['addr'],
                            'ldr_addr': addr.getOffset(),
                        })

    return globals_found

def main():
    output = []
    output.append("# SpellPrototypeManager/StatusPrototypeManager Caller Analysis\n")
    output.append("**Date:** {}\n".format(time.strftime('%Y-%m-%d %H:%M')))
    output.append("---\n\n")

    # 1. Search for relevant symbols
    output.append("## Symbol Search\n\n")

    search_patterns = [
        "SpellPrototypeManager",
        "StatusPrototypeManager",
        "GetSpellPrototype",
        "GetStatusPrototype",
        "__GLOBAL__sub_I_SpellPrototype",
        "__GLOBAL__sub_I_StatusPrototype",
    ]

    for pattern in search_patterns:
        matches = search_for_symbol(pattern)
        if matches:
            output.append("### {}\n".format(pattern))
            output.append("| Name | Address |\n")
            output.append("|------|----------|\n")
            for m in matches[:10]:
                output.append("| `{}` | `0x{:x}` |\n".format(m['name'][:60], m['address']))
            output.append("\n")

    # 2. Analyze callers of target functions
    output.append("## Caller Analysis\n\n")

    for name, addr in TARGET_FUNCTIONS.items():
        progress("Finding callers of {}...".format(name))
        callers = get_callers(addr)

        output.append("### {} (0x{:x})\n".format(name, addr))
        output.append("Callers: {}\n\n".format(len(callers)))

        if callers:
            output.append("| Caller Function | Call Site | Function Start |\n")
            output.append("|-----------------|-----------|----------------|\n")
            for c in callers[:20]:
                output.append("| `{}` | `0x{:x}` | `0x{:x}` |\n".format(
                    c['func_name'][:40], c['address'], c['func_addr']))
            output.append("\n")

            # Analyze first few callers for global loads
            output.append("**Global loads in callers:**\n\n")
            for c in callers[:5]:
                progress("Analyzing caller {} at 0x{:x}...".format(c['func_name'][:30], c['func_addr']))
                globals_in_caller = find_global_loads_in_function(c['func_addr'])

                # Filter to likely singleton range
                manager_globals = [g for g in globals_in_caller
                                 if 0x108900000 <= g['global_addr'] <= 0x108b00000]

                if manager_globals:
                    output.append("**{}** (0x{:x}):\n".format(c['func_name'][:40], c['func_addr']))
                    for g in manager_globals:
                        output.append("- `0x{:x}` (loaded at 0x{:x})\n".format(
                            g['global_addr'], g['ldr_addr']))
                    output.append("\n")

    # 3. Summary
    output.append("## Candidate Manager Addresses\n\n")
    output.append("Based on analysis, these addresses in the 0x108xxxxxx range may be prototype managers:\n\n")

    output.append("| Address | Source | Candidate |\n")
    output.append("|---------|--------|----------|\n")
    output.append("| `0x108aeccd8` | GetPassivePrototype | PassivePrototypeManager (confirmed) |\n")
    output.append("| `0x108aecce0` | EvaluateInterrupt | InterruptPrototypeManager (likely) |\n")
    output.append("| `0x108991528` | Symbol table | BoostPrototypeManager (confirmed) |\n")

    # Add newly discovered candidates
    output.append("| `0x108aeccf8` | RegisterGameAnalyticsSystem | **SpellPrototypeManager?** |\n")
    output.append("| `0x108aefa98` | Multiple spell functions | **Memory allocator or manager?** |\n")

    output.append("\n**Recommendation:** Test 0x108aeccf8 as SpellPrototypeManager at runtime.\n")

    duration = time.time() - start_time
    output.append("\n**Duration:** {:.1f} seconds\n".format(duration))

    output_path = "/tmp/spell_manager_callers.md"
    with open(output_path, 'w') as f:
        f.writelines(output)

    print("Results written to {}".format(output_path))
    finish_progress()

if __name__ == "__main__":
    main()
