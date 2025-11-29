# Ghidra script to find Entity System offsets in BG3 main binary
# Run with: analyzeHeadless ... -postScript find_entity_offsets.py

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.data import StringDataType

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()

print("=" * 60)
print("BG3 Entity System Offset Discovery")
print("=" * 60)

# Search for component name strings to find component registration
component_names = [
    "eoc::StatsComponent",
    "eoc::BaseHpComponent",
    "eoc::ArmorComponent",
    "eoc::DataComponent",
    "ls::TransformComponent",
    "esv::Character",
    "ecs::EntityWorld"
]

print("\n=== Searching for Component Name Strings ===")
found_strings = {}

for block in memory.getBlocks():
    if not block.isInitialized():
        continue

    start = block.getStart()
    end = block.getEnd()

    for name in component_names:
        try:
            addr = memory.findBytes(start, end, name.encode('utf-8'), None, True, monitor)
            if addr:
                found_strings[name] = addr
                print("Found '{}' at 0x{:x}".format(name, addr.getOffset()))
        except:
            pass

print("\n=== Searching for EntityWorld References ===")

# Look for functions that might be EntityWorld::GetRawComponent
# Pattern: Functions with "Component" in decompiled output or that reference component strings
for func in fm.getFunctions(True):
    name = func.getName()
    name_lower = name.lower()

    # Look for entity/component related function names
    if any(keyword in name_lower for keyword in ['entity', 'component', 'ecs', 'world', 'storage']):
        print("Candidate function: {} @ 0x{:x} (size: {})".format(
            name, func.getEntryPoint().getOffset(), func.getBody().getNumAddresses()))

print("\n=== Looking for Global Pointers ===")

# Search for global data that might be EntityWorld singleton
symTable = currentProgram.getSymbolTable()
for sym in symTable.getAllSymbols(True):
    name = sym.getName()
    name_lower = name.lower()

    if any(keyword in name_lower for keyword in ['entityworld', 'ecsworld', 'gameworld', 'world_']):
        print("Candidate global: {} @ 0x{:x}".format(name, sym.getAddress().getOffset()))

print("\n=== Analyzing References to Component Strings ===")

# For each found string, find what references it (these are likely component registration functions)
refManager = currentProgram.getReferenceManager()
for name, addr in found_strings.items():
    print("\nReferences to '{}' at 0x{:x}:".format(name, addr.getOffset()))
    refs = refManager.getReferencesTo(addr)
    count = 0
    for ref in refs:
        if count >= 5:
            print("  ... (more references)")
            break
        from_addr = ref.getFromAddress()
        from_func = fm.getFunctionContaining(from_addr)
        func_name = from_func.getName() if from_func else "???"
        print("  <- 0x{:x} in {}".format(from_addr.getOffset(), func_name))
        count += 1

print("\n=== Searching for ECS Patterns ===")

# Look for characteristic ECS patterns in code
# Pattern 1: Functions that take EntityHandle (uint64_t) as first param
# Pattern 2: Functions with ComponentTypeIndex (uint16_t) parameters

# Search for functions with specific signature patterns
for func in fm.getFunctions(True):
    # Check if function signature matches component access pattern
    params = func.getParameters()
    if len(params) >= 2:
        # Look for functions with (void*, uint64_t, uint16_t) pattern
        # which could be (this, entityHandle, componentType)
        entry = func.getEntryPoint()
        body_size = func.getBody().getNumAddresses()

        if 100 < body_size < 2000:  # Component access functions are typically medium-sized
            # Check first few instructions for characteristic patterns
            instr = getInstructionAt(entry)
            if instr:
                # Look for ldr with specific offsets that match ECS structures
                mnem = instr.getMnemonicString()
                if 'ldr' in mnem.lower() or 'adrp' in mnem.lower():
                    # Check if function name suggests component access
                    name = func.getName()
                    if 'FUN_' in name:  # Unnamed functions are candidates
                        # Log functions that could be GetRawComponent
                        pass  # Too many to log, would need decompilation

print("\n=== Summary ===")
print("Found {} component name strings".format(len(found_strings)))
print("\nNext steps:")
print("1. Examine references to component strings to find ComponentRegistry")
print("2. Trace back from ComponentRegistry to find EntityWorld")
print("3. Look for GetRawComponent by finding functions that:")
print("   - Take EntityHandle (uint64_t) parameter")
print("   - Take ComponentTypeIndex (uint16_t) parameter")
print("   - Access storage arrays")
print("=" * 60)
