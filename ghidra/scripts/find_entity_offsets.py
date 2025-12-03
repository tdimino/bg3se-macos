# Find EntityWorld->Storage offset and EntityStorageData::GetComponent
# @category BG3SE
# @description Analyze EntityWorld storage and component access functions
# Run with: analyzeHeadless ... -noanalysis -postScript find_entity_offsets.py

"""
Goal: Find the critical offsets for component access:

1. EntityWorld->Storage offset (EntityStorageContainer*)
2. EntityStorageData::GetComponent function address

KNOWN:
- EntityStorageContainer::TryGet: 0x10636b27c
- TryGet signature: EntityStorageData* TryGet(EntityHandle handle)
- TryGet returns EntityStorageData* from Entities[EntityClassIndex]

Strategy:
1. Decompile TryGet callers to see how EntityWorld accesses Storage
2. Find EntityStorageData methods that take type index parameter
"""

from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface


def get_decompiled(func, decomp, timeout=60):
    """Get decompiled C code for a function"""
    result = decomp.decompileFunction(func, timeout, None)
    if result and result.decompileCompleted():
        return result.getDecompiledFunction().getC()
    return None


def find_xrefs_to(addr_str):
    """Find all references to an address"""
    addr = toAddr(addr_str)
    refs = getReferencesTo(addr)

    callers = []
    for ref in refs:
        from_addr = ref.getFromAddress()
        from_func = getFunctionContaining(from_addr)
        if from_func:
            callers.append({
                'addr': from_addr,
                'func': from_func,
                'name': from_func.getName(),
                'entry': from_func.getEntryPoint()
            })

    return callers


def analyze_tryget_callers(decomp):
    """Analyze callers of TryGet to find Storage access pattern"""
    print("\n" + "=" * 70)
    print("ANALYZING TryGet CALLERS")
    print("=" * 70)

    tryget_addr = "0x10636b27c"
    callers = find_xrefs_to(tryget_addr)

    print("Found {} callers of TryGet at {}".format(len(callers), tryget_addr))

    # Sort by address
    callers.sort(key=lambda x: x['entry'].getOffset())

    analyzed = 0
    for c in callers[:15]:  # First 15 callers
        print("\n--- Caller: {} at {} ---".format(c['name'][:60], c['entry']))

        code = get_decompiled(c['func'], decomp, 30)
        if code:
            lines = code.split('\n')

            # Print first 50 lines to see the access pattern
            print("Decompiled ({} lines total):".format(len(lines)))
            for line in lines[:50]:
                # Highlight interesting lines
                if 'TryGet' in line or '0x10636b27c' in line:
                    print(" >> {}".format(line[:100]))
                elif 'param' in line or 'this' in line:
                    print("    {}".format(line[:100]))
                else:
                    print("    {}".format(line[:100]))

            analyzed += 1
            if analyzed >= 5:
                break


def find_entity_storage_data_methods():
    """Find EntityStorageData methods that could be GetComponent"""
    fm = currentProgram.getFunctionManager()

    print("\n" + "=" * 70)
    print("ENTITYSTORAGEDATA METHODS")
    print("=" * 70)

    methods = []

    for func in fm.getFunctions(True):
        name = func.getName()

        if 'EntityStorageData' in name:
            addr = func.getEntryPoint()
            size = func.getBody().getNumAddresses()
            params = func.getParameterCount()

            methods.append({
                'addr': addr,
                'name': name,
                'size': size,
                'params': params,
                'func': func
            })

    # Sort by size (GetComponent is a medium-sized function)
    methods.sort(key=lambda x: -x['size'])

    print("Found {} EntityStorageData methods:".format(len(methods)))
    for m in methods[:25]:
        print("  {} ({} bytes, {} params) - {}".format(
            m['addr'], m['size'], m['params'], m['name'][:70]))

    return methods


def analyze_getcomponent_candidates(decomp, methods):
    """Analyze functions that could be EntityStorageData::GetComponent"""
    print("\n" + "=" * 70)
    print("ANALYZING GetComponent CANDIDATES")
    print("=" * 70)

    # Look for functions with:
    # - 4+ parameters (this, handle, type, size, isProxy)
    # - Medium size (100-500 bytes)
    # - Name containing Get, Component, or At

    candidates = []
    for m in methods:
        name = m['name']
        if ('Get' in name or 'At' in name) and m['size'] > 50:
            candidates.append(m)

    print("Found {} GetComponent candidates:".format(len(candidates)))

    for c in candidates[:8]:
        print("\n--- {} at {} ({} bytes) ---".format(
            c['name'][:50], c['addr'], c['size']))

        code = get_decompiled(c['func'], decomp, 30)
        if code:
            # Print first 60 lines
            lines = code.split('\n')
            for line in lines[:60]:
                print("  {}".format(line[:100]))
            if len(lines) > 60:
                print("  ... ({} more lines)".format(len(lines) - 60))

    return candidates


def find_storage_offset_pattern(decomp):
    """Look for pattern accessing EntityWorld->Storage"""
    print("\n" + "=" * 70)
    print("SEARCHING FOR EntityWorld->Storage OFFSET PATTERN")
    print("=" * 70)

    # Look at functions that call TryGet and see how they get the EntityStorageContainer
    tryget_addr = "0x10636b27c"
    callers = find_xrefs_to(tryget_addr)

    print("Examining {} callers for Storage offset pattern...".format(len(callers)))

    offsets_found = {}

    for c in callers[:30]:
        code = get_decompiled(c['func'], decomp, 30)
        if code:
            # Look for patterns like:
            # *(undefined8 *)(param1 + 0x1f8) - accessing Storage pointer
            # this + offset
            import re

            # Pattern for offset access before TryGet call
            patterns = [
                r'\(param\d+ \+ (0x[0-9a-f]+)\)',
                r'\(this \+ (0x[0-9a-f]+)\)',
                r'\*\([^)]*\*\)\([^)]*\+ (0x[0-9a-f]+)\)',
            ]

            for pattern in patterns:
                matches = re.findall(pattern, code)
                for offset in matches:
                    if offset not in offsets_found:
                        offsets_found[offset] = []
                    if c['name'] not in offsets_found[offset]:
                        offsets_found[offset].append(c['name'][:50])

    print("\nOffsets found near TryGet calls (sorted by frequency):")
    for offset, funcs in sorted(offsets_found.items(), key=lambda x: -len(x[1]))[:20]:
        print("  {} - found in {} functions".format(offset, len(funcs)))
        for f in funcs[:3]:
            print("    - {}".format(f))


def analyze_known_functions(decomp):
    """Decompile known key functions"""
    print("\n" + "=" * 70)
    print("KNOWN KEY FUNCTIONS DECOMPILATION")
    print("=" * 70)

    known = [
        ("0x10636b27c", "EntityStorageContainer::TryGet"),
        ("0x10636b310", "EntityStorageContainer::TryGet_const"),
    ]

    for addr_str, name in known:
        addr = toAddr(addr_str)
        func = getFunctionAt(addr)

        if func:
            print("\n--- {} at {} ---".format(name, addr_str))
            code = get_decompiled(func, decomp, 60)
            if code:
                lines = code.split('\n')
                for line in lines[:80]:
                    print("  {}".format(line[:100]))
                if len(lines) > 80:
                    print("  ... ({} more lines)".format(len(lines) - 80))
        else:
            print("Function not found at {}".format(addr_str))


def main():
    print("=" * 70)
    print("BG3SE Entity Offset Finder")
    print("=" * 70)

    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    # 1. Decompile known functions
    analyze_known_functions(decomp)

    # 2. Find EntityStorageData methods
    methods = find_entity_storage_data_methods()

    # 3. Analyze GetComponent candidates
    analyze_getcomponent_candidates(decomp, methods)

    # 4. Analyze TryGet callers for Storage access pattern
    analyze_tryget_callers(decomp)

    # 5. Find Storage offset pattern
    find_storage_offset_pattern(decomp)

    decomp.dispose()

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("KNOWN:")
    print("  - EntityStorageContainer::TryGet: 0x10636b27c")
    print("  - EntityStorageContainer::TryGet_const: 0x10636b310")
    print("  - TryGet returns EntityStorageData*")
    print("")
    print("NEED TO FIND:")
    print("  - EntityWorld->Storage offset")
    print("  - EntityStorageData::GetComponent address")
    print("")
    print("Look for offset patterns above that appear frequently!")


if __name__ == "__main__":
    main()
