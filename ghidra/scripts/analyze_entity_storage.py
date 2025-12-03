# Analyze EntityStorageContainer and EntityWorld structures
# @category BG3SE
# @description Trace EntityWorld storage organization for component access

"""
Goal: Understand how to access components given:
- EntityWorld* (captured via LEGACY_IsInCombat hook)
- EntityHandle (from GUID lookup)
- ComponentTypeIndex (uint16_t)

We know:
- EntityStorageContainer::TryGet at 0x10636b27c
- TryGet takes (this=EntityStorageContainer*, EntityHandle)
- Returns EntityStorageData* or null

We need to find:
1. EntityWorld layout - where is the storage container array?
2. How to get EntityStorageContainer* from EntityWorld + ComponentTypeIndex
3. EntityStorageData layout - where is the component data pointer?
"""

from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface


def get_decompiled(func):
    """Get decompiled C code for a function"""
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    result = decomp.decompileFunction(func, 30, None)
    if result and result.decompileCompleted():
        return result.getDecompiledFunction().getC()
    return None


def analyze_function_at(addr_str, name):
    """Analyze a function at the given address"""
    addr = toAddr(addr_str)
    func = getFunctionAt(addr)

    if not func:
        print("Function not found at {}".format(addr_str))
        return None

    print("\n" + "=" * 70)
    print("{} at {}".format(name, addr_str))
    print("=" * 70)
    print("Name: {}".format(func.getName()))
    print("Size: {} bytes".format(func.getBody().getNumAddresses()))
    print("Params: {}".format(func.getParameterCount()))

    # Get parameters
    for i, param in enumerate(func.getParameters()):
        print("  Param {}: {} ({})".format(i, param.getName(), param.getDataType()))

    # Get return type
    print("Return: {}".format(func.getReturnType()))

    # Decompile
    decomp_code = get_decompiled(func)
    if decomp_code:
        print("\nDecompiled:")
        print("-" * 70)
        # Print first 100 lines
        lines = decomp_code.split('\n')
        for line in lines[:100]:
            print(line)
        if len(lines) > 100:
            print("... ({} more lines)".format(len(lines) - 100))

    return func


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
                'name': from_func.getName()
            })

    return callers


def analyze_entity_world_methods():
    """Find EntityWorld methods that access storage"""
    fm = currentProgram.getFunctionManager()

    print("\n" + "=" * 70)
    print("ENTITYWORLD METHODS")
    print("=" * 70)

    storage_methods = []

    for func in fm.getFunctions(True):
        name = func.getName()

        # Look for EntityWorld methods related to storage/components
        if 'EntityWorld' in name and any(kw in name.lower() for kw in ['storage', 'component', 'get', 'container']):
            addr = func.getEntryPoint()
            size = func.getBody().getNumAddresses()
            storage_methods.append({
                'addr': addr,
                'name': name,
                'size': size
            })

    # Sort by size
    storage_methods.sort(key=lambda x: x['size'], reverse=True)

    print("Found {} EntityWorld storage/component methods:".format(len(storage_methods)))
    for m in storage_methods[:30]:
        print("  {} ({} bytes) - {}".format(m['addr'], m['size'], m['name'][:80]))

    return storage_methods


def analyze_storage_container_methods():
    """Find all EntityStorageContainer methods"""
    fm = currentProgram.getFunctionManager()

    print("\n" + "=" * 70)
    print("ENTITYSTORAGECONTAINER METHODS")
    print("=" * 70)

    methods = []

    for func in fm.getFunctions(True):
        name = func.getName()

        if 'EntityStorageContainer' in name:
            addr = func.getEntryPoint()
            size = func.getBody().getNumAddresses()
            methods.append({
                'addr': addr,
                'name': name,
                'size': size
            })

    methods.sort(key=lambda x: x['size'], reverse=True)

    print("Found {} EntityStorageContainer methods:".format(len(methods)))
    for m in methods[:20]:
        print("  {} ({} bytes) - {}".format(m['addr'], m['size'], m['name'][:80]))

    return methods


def analyze_storage_data_methods():
    """Find all EntityStorageData methods"""
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
            methods.append({
                'addr': addr,
                'name': name,
                'size': size
            })

    methods.sort(key=lambda x: x['size'], reverse=True)

    print("Found {} EntityStorageData methods:".format(len(methods)))
    for m in methods[:20]:
        print("  {} ({} bytes) - {}".format(m['addr'], m['size'], m['name'][:80]))

    return methods


def main():
    print("=" * 70)
    print("BG3SE Entity Storage Analyzer")
    print("=" * 70)

    # Analyze TryGet
    print("\n>>> Analyzing EntityStorageContainer::TryGet")
    analyze_function_at("0x10636b27c", "EntityStorageContainer::TryGet")

    # Analyze TryGet (const)
    print("\n>>> Analyzing EntityStorageContainer::TryGet (const)")
    analyze_function_at("0x10636b310", "EntityStorageContainer::TryGet (const)")

    # Find callers of TryGet
    print("\n>>> Finding callers of TryGet")
    callers = find_xrefs_to("0x10636b27c")
    print("Found {} callers of TryGet:".format(len(callers)))
    for c in callers[:20]:
        print("  {} - {}".format(c['addr'], c['name'][:70]))

    # List EntityWorld methods
    analyze_entity_world_methods()

    # List EntityStorageContainer methods
    analyze_storage_container_methods()

    # List EntityStorageData methods
    analyze_storage_data_methods()

    print("\n" + "=" * 70)
    print("NEXT STEPS")
    print("=" * 70)
    print("1. Examine TryGet decompilation to understand EntityStorageData layout")
    print("2. Find EntityWorld::GetStorage or similar method")
    print("3. Determine offset from EntityWorld to storage container array")


if __name__ == "__main__":
    main()
