# Find GetRawComponent - refined search for exact w2 register pattern
# @category BG3SE
# @description Searches for GetRawComponent by finding TST/AND on w2 register with 0x8000

"""
GetRawComponent signature:
    void* GetRawComponent(EntityWorld* world, EntityHandle handle,
                          ComponentTypeIndex type, size_t componentSize, bool isProxy)

ARM64 ABI: type parameter is in w2 (32-bit view of x2)
Key pattern: TST w2, #0x8000 or AND w?, w2, #0x8000

This version specifically looks for operations on w2.
"""

from ghidra.program.model.listing import CodeUnit


def get_function_complexity(func, listing):
    """Count key instruction types"""
    branches = 0
    returns = 0
    calls = 0
    loads = 0

    for instr in listing.getInstructions(func.getBody(), True):
        mnemonic = instr.getMnemonicString().lower()
        if mnemonic.startswith('b') and mnemonic not in ['bl', 'blr']:
            branches += 1
        if mnemonic == 'ret':
            returns += 1
        if mnemonic in ['bl', 'blr']:
            calls += 1
        if mnemonic.startswith('ldr'):
            loads += 1

    return {'branches': branches, 'returns': returns, 'calls': calls, 'loads': loads}


def main():
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()

    print("=" * 70)
    print("BG3SE GetRawComponent Finder v2 - Refined w2 Register Search")
    print("=" * 70)
    print("")
    print("Looking for: TST w2, #0x8000  or  AND w?, w2, #0x8000")
    print("Also searching for: operations involving 0x8000 and w2")
    print("")

    exact_w2_matches = []      # Exact w2, #0x8000 pattern
    related_matches = []       # Other 0x8000 patterns that might be relevant
    entity_namespace = []      # Functions in eoc/ecs/ls namespace

    for func in fm.getFunctions(True):
        body = func.getBody()
        size = body.getNumAddresses()

        # Size filter
        if size < 80 or size > 3000:
            continue

        func_name = func.getName()

        # Track if function is in entity-related namespace
        is_entity_related = any(ns in func_name.lower() for ns in ['entity', 'ecs', 'component', 'storage', 'eoc::', 'esv::', 'ecl::', 'ls::'])

        for instr in listing.getInstructions(body, True):
            mnemonic = instr.getMnemonicString().lower()
            instr_str = str(instr).lower()

            # Check for exact w2 + 0x8000 pattern
            if mnemonic in ["tst", "and", "ands"]:
                # Exact match: w2 with 0x8000
                if "w2" in instr_str and ("0x8000" in instr_str or "#32768" in instr_str):
                    # Make sure it's exactly 0x8000, not 0x80000000
                    if "0x80000000" not in instr_str and "0x800000" not in instr_str:
                        exact_w2_matches.append({
                            'func': func,
                            'addr': func.getEntryPoint(),
                            'size': size,
                            'pattern_addr': instr.getAddress(),
                            'pattern_instr': str(instr),
                            'is_entity': is_entity_related
                        })
                        break

                # Related: any 0x8000 in entity-related function
                elif is_entity_related and "0x8000" in instr_str:
                    if "0x80000000" not in instr_str:
                        related_matches.append({
                            'func': func,
                            'addr': func.getEntryPoint(),
                            'size': size,
                            'pattern_addr': instr.getAddress(),
                            'pattern_instr': str(instr),
                        })
                        break

        # Also collect entity-related functions for manual inspection
        if is_entity_related and size > 200:
            entity_namespace.append({
                'func': func,
                'addr': func.getEntryPoint(),
                'size': size,
                'name': func_name
            })

    # Print exact matches (highest priority)
    print("=" * 70)
    print("EXACT MATCHES: TST/AND w2, #0x8000")
    print("=" * 70)
    if exact_w2_matches:
        for i, c in enumerate(exact_w2_matches):
            complexity = get_function_complexity(c['func'], listing)
            print("[{:2d}] {}".format(i, c['addr']))
            print("     Name: {}".format(c['func'].getName()))
            print("     Size: {} bytes".format(c['size']))
            print("     Pattern: {} at {}".format(c['pattern_instr'], c['pattern_addr']))
            print("     Complexity: {} branches, {} returns, {} calls, {} loads".format(
                complexity['branches'], complexity['returns'],
                complexity['calls'], complexity['loads']))
            print("     Entity-related: {}".format(c['is_entity']))
            print("")
    else:
        print("No exact w2 + 0x8000 matches found")
        print("")

    # Print entity-related matches
    print("=" * 70)
    print("ENTITY-RELATED FUNCTIONS with 0x8000 pattern")
    print("=" * 70)
    if related_matches:
        for i, c in enumerate(related_matches[:15]):
            print("[{:2d}] {} - {}".format(i, c['addr'], c['func'].getName()))
            print("     Pattern: {}".format(c['pattern_instr']))
            print("")
    else:
        print("No entity-related 0x8000 matches found")
        print("")

    # Print large entity-namespace functions (might contain GetRawComponent)
    print("=" * 70)
    print("LARGE ENTITY-NAMESPACE FUNCTIONS (manual inspection candidates)")
    print("=" * 70)

    # Sort by size, show functions that might contain component access
    entity_namespace.sort(key=lambda x: x['size'], reverse=True)
    component_funcs = [f for f in entity_namespace if 'component' in f['name'].lower()]
    storage_funcs = [f for f in entity_namespace if 'storage' in f['name'].lower()]

    print("\nComponent-related functions:")
    for f in component_funcs[:10]:
        print("  {} ({} bytes) - {}".format(f['addr'], f['size'], f['name'][:80]))

    print("\nStorage-related functions:")
    for f in storage_funcs[:10]:
        print("  {} ({} bytes) - {}".format(f['addr'], f['size'], f['name'][:80]))

    # Summary
    print("")
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("Exact w2+0x8000 matches: {}".format(len(exact_w2_matches)))
    print("Entity-related 0x8000 matches: {}".format(len(related_matches)))
    print("Entity namespace functions: {}".format(len(entity_namespace)))
    print("")
    print("If no exact matches, GetRawComponent may:")
    print("1. Use different register allocation (compiler optimization)")
    print("2. Inline the bit check differently")
    print("3. Be found via storage/component function analysis")


if __name__ == "__main__":
    main()
