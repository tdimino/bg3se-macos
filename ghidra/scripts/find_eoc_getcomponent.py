# Find GetComponent<eoc::*> template instantiations
#
# Strategy: For each known component string, find:
# 1. Code references to the string (not data references)
# 2. Functions that contain those references
# 3. Filter for functions matching GetComponent pattern
#
# Run with:
# JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
#   ~/ghidra/support/analyzeHeadless ~/ghidra_projects BG3Analysis \
#   -process BG3_arm64_thin \
#   -postScript find_eoc_getcomponent.py \
#   -noanalysis

from ghidra.program.model.symbol import RefType
from ghidra.program.model.address import AddressSet

# Known eoc:: component string addresses
EOC_COMPONENTS = {
    "eoc::StatsComponent":   0x107b7ca22,
    "eoc::BaseHpComponent":  0x107b84c63,
    "eoc::HealthComponent":  0x107ba9b5c,
    "eoc::ArmorComponent":   0x107b7c9e7,
    "eoc::ClassesComponent": 0x107b7ca5d,
}

# Known working ls:: GetComponent addresses for pattern matching
LS_GETCOMPONENT_ADDRS = [
    0x10010d5b00,  # TransformComponent
    0x10010d588c,  # LevelComponent
]

def get_function_at(addr):
    """Get the function containing an address"""
    func = getFunctionContaining(addr)
    return func

def find_references_to_addr(target_addr):
    """Find all code references to an address"""
    refs = []
    addr = toAddr(target_addr)
    ref_mgr = currentProgram.getReferenceManager()

    # Get all references TO this address
    ref_iter = ref_mgr.getReferencesTo(addr)
    for ref in ref_iter:
        if ref.getReferenceType().isFlow() or ref.getReferenceType().isData():
            refs.append(ref.getFromAddress())

    return refs

def analyze_function_pattern(func_addr):
    """Analyze if a function looks like GetComponent<T>"""
    func = getFunctionAt(toAddr(func_addr))
    if not func:
        return None

    # GetComponent typically:
    # 1. Takes EntityWorld* and EntityHandle as params
    # 2. Returns void* (component pointer)
    # 3. Is relatively small (< 200 instructions)

    body = func.getBody()
    size = body.getNumAddresses()

    return {
        "address": func.getEntryPoint(),
        "name": func.getName(),
        "size": size,
    }

def search_near_string(string_addr, search_range=0x10000):
    """Search for function entries near a string address"""
    results = []

    # Search in a range around the string address for function entries
    start = toAddr(string_addr - search_range)
    end = toAddr(string_addr + search_range)

    func_mgr = currentProgram.getFunctionManager()
    funcs = func_mgr.getFunctions(start, True)  # Forward iterator

    for func in funcs:
        entry = func.getEntryPoint()
        if entry.getOffset() > string_addr + search_range:
            break
        results.append(func)

    return results

def main():
    print("=" * 60)
    print("Searching for eoc:: GetComponent template instantiations")
    print("=" * 60)

    # First, verify we can find the string addresses
    print("\nVerifying string addresses...")
    for name, addr in EOC_COMPONENTS.items():
        str_addr = toAddr(addr)
        try:
            data = getDataAt(str_addr)
            if data:
                print("  {} at 0x{:x}: {}".format(name, addr, data.getValue()))
            else:
                # Try reading as string directly
                mem = currentProgram.getMemory()
                buf = bytearray(64)
                mem.getBytes(str_addr, buf)
                s = bytes(buf).split(b'\x00')[0].decode('utf-8', errors='ignore')
                print("  {} at 0x{:x}: '{}'".format(name, addr, s))
        except Exception as e:
            print("  {} at 0x{:x}: ERROR - {}".format(name, addr, str(e)))

    # Find references to each string
    print("\nFinding code references to component strings...")
    for name, addr in EOC_COMPONENTS.items():
        refs = find_references_to_addr(addr)
        print("\n{} (0x{:x}): {} references".format(name, addr, len(refs)))
        for ref in refs[:10]:  # Limit to first 10
            func = get_function_at(ref)
            func_name = func.getName() if func else "???"
            func_entry = func.getEntryPoint() if func else "???"
            print("    0x{:x} in {} (entry: {})".format(ref.getOffset(), func_name, func_entry))

    # Analyze ls:: GetComponent functions as reference
    print("\n" + "=" * 60)
    print("Reference: Known ls:: GetComponent functions")
    print("=" * 60)
    for addr in LS_GETCOMPONENT_ADDRS:
        info = analyze_function_pattern(addr)
        if info:
            print("  0x{:x}: {} ({} bytes)".format(
                info["address"].getOffset(), info["name"], info["size"]))

    # Search for functions near eoc:: strings
    print("\n" + "=" * 60)
    print("Searching for functions near eoc:: strings")
    print("=" * 60)

    # Look for functions in the same general area as ls:: GetComponent
    # ls:: GetComponent functions are around 0x10010d5xxx
    # Let's search that region for more GetComponent-like functions
    search_start = 0x10010d0000
    search_end = 0x10010e0000

    print("\nSearching 0x{:x} - 0x{:x}...".format(search_start, search_end))
    func_mgr = currentProgram.getFunctionManager()
    funcs = func_mgr.getFunctions(toAddr(search_start), True)

    getcomponent_candidates = []
    for func in funcs:
        entry = func.getEntryPoint().getOffset()
        if entry > search_end:
            break

        name = func.getName()
        # Look for functions with "GetComponent" in name or similar pattern
        if "GetComponent" in name or "Component" in name:
            getcomponent_candidates.append((entry, name, func.getBody().getNumAddresses()))

    print("Found {} Component-related functions:".format(len(getcomponent_candidates)))
    for addr, name, size in sorted(getcomponent_candidates):
        print("  0x{:x}: {} ({} bytes)".format(addr, name, size))

    print("\n" + "=" * 60)
    print("Done!")
    print("=" * 60)

if __name__ == "__main__":
    main()
