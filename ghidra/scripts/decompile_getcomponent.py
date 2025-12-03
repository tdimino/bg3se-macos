# Decompile GetComponent template instantiation to find Storage offset
# @category BG3SE
# Run: analyzeHeadless ... -noanalysis -postScript decompile_getcomponent.py

from ghidra.app.decompiler import DecompInterface

def main():
    print("=" * 70)
    print("Decompiling EntityWorld::GetComponent template")
    print("=" * 70)

    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    # Pick a few GetComponent instantiations to analyze
    targets = [
        ("0x100cb1644", "ecs::EntityWorld::GetComponent<ecl::Item const, true>"),
        ("0x100cc20a8", "ecs::EntityWorld::GetComponent<ecl::Character const, true>"),
        ("0x100c8ec50", "ecs::EntityWorld::GetComponent<ls::anubis::TreeComponent const, false>"),
    ]

    for addr_str, name in targets:
        addr = toAddr(addr_str)
        func = getFunctionAt(addr)

        if not func:
            print("Function not found at {}".format(addr_str))
            continue

        print("\n" + "=" * 70)
        print("{} at {}".format(name, addr_str))
        print("=" * 70)

        result = decomp.decompileFunction(func, 60, None)
        if result and result.decompileCompleted():
            code = result.getDecompiledFunction().getC()
            print(code)
        else:
            print("Decompilation failed")

        print("\n")

    decomp.dispose()

    print("=" * 70)
    print("KEY: Look for patterns like:")
    print("  - this->Storage or param1->field_xxx (Storage offset)")
    print("  - Calls to TryGet (0x10636b27c)")
    print("  - ComponentTypeIndex usage")
    print("=" * 70)

if __name__ == "__main__":
    main()
