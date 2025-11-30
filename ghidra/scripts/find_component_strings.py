# Find all *Component strings in the binary
#
# This searches for strings matching patterns like:
# - eoc::*Component
# - ls::*Component
# - esv::*Component
#
# Run with:
# JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
#   ~/ghidra/support/analyzeHeadless ~/ghidra_projects BG3Analysis \
#   -process BG3_arm64_thin \
#   -postScript find_component_strings.py \
#   -noanalysis

import re

def main():
    print("=" * 60)
    print("Searching for *Component strings in binary")
    print("=" * 60)

    # Get all defined strings
    data_mgr = currentProgram.getListing()
    mem = currentProgram.getMemory()

    # Track found component strings
    component_strings = []

    # Search through defined data
    print("\nSearching defined data for Component strings...")
    data_iter = data_mgr.getDefinedData(True)
    count = 0
    for data in data_iter:
        count += 1
        if count % 100000 == 0:
            print("  Processed {} data items...".format(count))

        if data.hasStringValue():
            try:
                value = data.getValue()
                if value and "Component" in str(value):
                    addr = data.getAddress().getOffset()
                    component_strings.append((addr, str(value)))
            except:
                pass

    print("\nFound {} Component strings:".format(len(component_strings)))
    print("-" * 60)

    # Sort by address
    component_strings.sort(key=lambda x: x[0])

    # Group by namespace
    eoc_strings = []
    ls_strings = []
    esv_strings = []
    other_strings = []

    for addr, s in component_strings:
        if "eoc::" in s:
            eoc_strings.append((addr, s))
        elif "ls::" in s:
            ls_strings.append((addr, s))
        elif "esv::" in s:
            esv_strings.append((addr, s))
        else:
            other_strings.append((addr, s))

    print("\n=== eoc:: Components ({}) ===".format(len(eoc_strings)))
    for addr, s in eoc_strings[:50]:  # Limit output
        print("  0x{:x}: {}".format(addr, s[:80]))

    print("\n=== ls:: Components ({}) ===".format(len(ls_strings)))
    for addr, s in ls_strings[:30]:
        print("  0x{:x}: {}".format(addr, s[:80]))

    print("\n=== esv:: Components ({}) ===".format(len(esv_strings)))
    for addr, s in esv_strings[:30]:
        print("  0x{:x}: {}".format(addr, s[:80]))

    if len(other_strings) < 50:
        print("\n=== Other Components ({}) ===".format(len(other_strings)))
        for addr, s in other_strings:
            print("  0x{:x}: {}".format(addr, s[:80]))

    # Now look for references to key eoc:: strings
    print("\n" + "=" * 60)
    print("Looking for GetComponent candidates")
    print("=" * 60)

    # Find specific components we care about
    target_components = ["StatsComponent", "BaseHpComponent", "HealthComponent", "ArmorComponent"]

    for target in target_components:
        print("\nSearching for {}...".format(target))
        for addr, s in component_strings:
            if target in s:
                print("  Found at 0x{:x}: {}".format(addr, s[:60]))

                # Find references to this address
                ref_mgr = currentProgram.getReferenceManager()
                target_addr = toAddr(addr)
                refs = ref_mgr.getReferencesTo(target_addr)
                ref_count = 0
                for ref in refs:
                    ref_count += 1
                    from_addr = ref.getFromAddress()
                    func = getFunctionContaining(from_addr)
                    func_name = func.getName() if func else "???"
                    func_entry = func.getEntryPoint().getOffset() if func else 0
                    print("    <- 0x{:x} in {} (entry 0x{:x})".format(
                        from_addr.getOffset(), func_name, func_entry))
                if ref_count == 0:
                    print("    (no references)")

    print("\n" + "=" * 60)
    print("Done!")
    print("=" * 60)

if __name__ == "__main__":
    main()
