# Find GetRawComponent function by searching for 0x8000 bit test pattern
# @category BG3SE
# @description Searches for GetRawComponent by finding functions that test bit 15 (one-frame flag)

"""
GetRawComponent signature:
    void* GetRawComponent(EntityWorld* world, EntityHandle handle,
                          ComponentTypeIndex type, size_t componentSize, bool isProxy)

Key identifying characteristic:
    - Tests bit 15 of ComponentTypeIndex: (type & 0x8000) to check IsOneFrame
    - ARM64: TST W2, #0x8000 or AND W?, W2, #0x8000

This script finds all functions containing this pattern as candidates.
"""

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor


def analyze_function_params(func):
    """Attempt to count function parameters from calling convention"""
    params = func.getParameters()
    return len(params) if params else -1


def get_function_complexity(func, listing):
    """Count branches and returns to estimate function complexity"""
    branches = 0
    returns = 0
    calls = 0

    for instr in listing.getInstructions(func.getBody(), True):
        mnemonic = instr.getMnemonicString().lower()
        if mnemonic.startswith('b') and mnemonic not in ['bl', 'blr']:
            branches += 1
        if mnemonic == 'ret':
            returns += 1
        if mnemonic in ['bl', 'blr']:
            calls += 1

    return {'branches': branches, 'returns': returns, 'calls': calls}


def main():
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    monitor = ConsoleTaskMonitor()

    print("=" * 60)
    print("BG3SE GetRawComponent Finder")
    print("=" * 60)
    print("")
    print("Searching for functions with TST/AND #0x8000 pattern...")
    print("This identifies the one-frame component check in GetRawComponent")
    print("")

    candidates = []
    total_funcs = 0

    for func in fm.getFunctions(True):
        if monitor.isCancelled():
            break

        total_funcs += 1
        body = func.getBody()
        size = body.getNumAddresses()

        # Size filter: GetRawComponent is medium-sized (50-500 instructions)
        # But on ARM64 with different encoding, allow wider range
        if size < 100 or size > 4000:
            continue

        found_pattern = False
        pattern_addr = None
        pattern_instr = None

        for instr in listing.getInstructions(body, True):
            mnemonic = instr.getMnemonicString().lower()

            # Look for TST, AND, ANDS instructions
            if mnemonic in ["tst", "and", "ands"]:
                # Get string representation and check for 0x8000
                instr_str = str(instr).lower()

                # Check various representations of 32768
                if "0x8000" in instr_str or "#32768" in instr_str or "#0x8000" in instr_str:
                    # Additional check: should involve w2 (ComponentTypeIndex param)
                    # But also consider w-registers in general for flexibility
                    found_pattern = True
                    pattern_addr = instr.getAddress()
                    pattern_instr = str(instr)
                    break

        if found_pattern:
            complexity = get_function_complexity(func, listing)
            param_count = analyze_function_params(func)

            candidates.append({
                'func': func,
                'addr': func.getEntryPoint(),
                'size': size,
                'pattern_addr': pattern_addr,
                'pattern_instr': pattern_instr,
                'complexity': complexity,
                'param_count': param_count
            })

    print("Scanned {} functions".format(total_funcs))
    print("")

    # Sort candidates by likelihood (prefer medium-sized functions with good complexity)
    def score_candidate(c):
        score = 0
        # Prefer functions with multiple returns (fallback logic)
        score += min(c['complexity']['returns'], 5) * 10
        # Prefer functions with several branches
        score += min(c['complexity']['branches'], 20) * 2
        # Prefer medium-sized functions
        if 200 < c['size'] < 1000:
            score += 50
        # Prefer functions with 5 parameters
        if c['param_count'] == 5:
            score += 100
        return score

    candidates.sort(key=score_candidate, reverse=True)

    print("=" * 60)
    print("Found {} candidates with 0x8000 bit test pattern".format(len(candidates)))
    print("=" * 60)
    print("")

    # Show top candidates
    for i, c in enumerate(candidates[:20]):  # Show top 20
        print("[{:2d}] Address: {}".format(i, c['addr']))
        print("     Name: {}".format(c['func'].getName()))
        print("     Size: {} bytes".format(c['size']))
        print("     Pattern at: {}".format(c['pattern_addr']))
        print("     Instruction: {}".format(c['pattern_instr']))
        print("     Params: {}".format(c['param_count'] if c['param_count'] >= 0 else "unknown"))
        print("     Complexity: {} branches, {} returns, {} calls".format(
            c['complexity']['branches'],
            c['complexity']['returns'],
            c['complexity']['calls']
        ))
        print("")

    # Print summary for easy copying
    print("=" * 60)
    print("Top 5 candidates (most likely GetRawComponent):")
    print("=" * 60)
    for i, c in enumerate(candidates[:5]):
        print("  {}  ({})".format(c['addr'], c['func'].getName()))

    print("")
    print("=" * 60)
    print("Next Steps:")
    print("=" * 60)
    print("1. Open each candidate in Ghidra GUI")
    print("2. Check decompiled signature for:")
    print("   - 5 parameters: (void*, uint64_t, uint16_t, size_t, bool)")
    print("   - Returns void*")
    print("3. Look for fallback logic (storage -> write cache -> read cache)")
    print("4. Verify with Frida:")
    print("   setGetRawComponent('0xADDRESS')")
    print("   // Play game, access character")
    print("   dumpDiscoveries()")
    print("")


if __name__ == "__main__":
    main()
