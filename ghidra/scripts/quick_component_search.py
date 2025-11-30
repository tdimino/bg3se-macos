# Quick search for functions near component string addresses
# No analysis required - just memory pattern search

fm = currentProgram.getFunctionManager()
memory = currentProgram.getMemory()
refManager = currentProgram.getReferenceManager()

print("=" * 60)
print("Quick Component Function Search")
print("=" * 60)

# Known component string addresses from previous searches
component_strings = {
    "ls::TransformComponent": 0x107b619cc,
    "ls::LevelComponent": 0x107b4e44c,
    "eoc::StatsComponent": 0x107b7ca22,
    "eoc::BaseHpComponent": 0x107b84c63,
    "eoc::HealthComponent": 0x107ba9b5c,
    "eoc::ArmorComponent": 0x107b7c9e7,
}

print("\nSearching for references to component strings...")

for name, addr_val in component_strings.items():
    addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr_val)
    print("\n=== {} @ 0x{:x} ===".format(name, addr_val))

    # Get references TO this string
    refs = refManager.getReferencesTo(addr)
    ref_count = 0

    for ref in refs:
        from_addr = ref.getFromAddress()
        func = fm.getFunctionContaining(from_addr)

        if func:
            func_addr = func.getEntryPoint().getOffset()
            func_name = func.getName()
            func_size = func.getBody().getNumAddresses()

            print("  XREF from 0x{:x} in {} @ 0x{:x} (size={})".format(
                from_addr.getOffset(), func_name, func_addr, func_size))

            # This could be a GetComponent registration or call site
            ref_count += 1
            if ref_count >= 10:
                print("  ... more refs ...")
                break
        else:
            print("  XREF from 0x{:x} (no function)".format(from_addr.getOffset()))
            ref_count += 1
            if ref_count >= 10:
                break

    if ref_count == 0:
        print("  No references found")

# Collect functions that reference component strings
# These are likely GetComponent implementations or registration sites
print("\n=== Functions Referencing Multiple Component Strings ===")

func_component_refs = {}  # func_addr -> list of component names

for name, addr_val in component_strings.items():
    addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr_val)
    refs = refManager.getReferencesTo(addr)

    for ref in refs:
        from_addr = ref.getFromAddress()
        func = fm.getFunctionContaining(from_addr)
        if func:
            func_addr = func.getEntryPoint().getOffset()
            if func_addr not in func_component_refs:
                func_component_refs[func_addr] = []
            if name not in func_component_refs[func_addr]:
                func_component_refs[func_addr].append(name)

# Functions referencing multiple component strings are likely GetComponent dispatchers
multi_ref_funcs = [(addr, comps) for addr, comps in func_component_refs.items() if len(comps) >= 2]
multi_ref_funcs.sort(key=lambda x: -len(x[1]))  # Sort by most references first

print("Found {} functions referencing 2+ component strings:".format(len(multi_ref_funcs)))
for func_addr, comps in multi_ref_funcs[:20]:  # Limit to top 20
    func = fm.getFunctionAt(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(func_addr))
    if func:
        print("  0x{:x} {} - refs {} components: {}".format(
            func_addr, func.getName(), len(comps), ", ".join(comps[:3])))

print("\n" + "=" * 60)
print("Search complete")
print("=" * 60)
