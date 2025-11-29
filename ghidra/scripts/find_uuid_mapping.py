# Ghidra script to find UuidToHandleMappingComponent singleton for GUID->EntityHandle lookup
# Run with: analyzeHeadless ... -postScript find_uuid_mapping.py

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.address import AddressSet

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
refManager = currentProgram.getReferenceManager()

print("=" * 70)
print("BG3 UUID to EntityHandle Mapping Discovery")
print("=" * 70)

# Search strings related to UUID/GUID mapping
uuid_strings = [
    "ls::uuid::ToHandleMappingComponent",
    "ToHandleMappingComponent",
    "UuidToHandle",
    "ls::uuid::Component",
    "EntityUuid",
    "UuidMapping",
    "GetEntityHandle",
]

print("\n=== Searching for UUID Mapping Strings ===")
found_strings = {}

for block in memory.getBlocks():
    if not block.isInitialized():
        continue

    start = block.getStart()
    end = block.getEnd()

    for search_str in uuid_strings:
        try:
            addr = start
            while addr and addr.compareTo(end) < 0:
                addr = memory.findBytes(addr, end, search_str.encode('utf-8'), None, True, monitor)
                if addr:
                    if search_str not in found_strings:
                        found_strings[search_str] = []
                    found_strings[search_str].append(addr)
                    print("Found '{}' at 0x{:x}".format(search_str, addr.getOffset()))
                    addr = addr.add(1)  # Continue search after this match
        except Exception as e:
            pass

print("\n=== Analyzing References to UUID Strings ===")

# For each found string, find what code references it
for search_str, addrs in found_strings.items():
    print("\n--- References to '{}' ---".format(search_str))
    for addr in addrs[:3]:  # Limit to first 3 occurrences
        refs = refManager.getReferencesTo(addr)
        for ref in refs:
            from_addr = ref.getFromAddress()
            from_func = fm.getFunctionContaining(from_addr)
            func_name = from_func.getName() if from_func else "???"
            func_addr = from_func.getEntryPoint().getOffset() if from_func else 0
            print("  <- 0x{:x} in {} (func @ 0x{:x})".format(
                from_addr.getOffset(), func_name, func_addr))

            # If this is in a named function, it might be GetComponent<UuidToHandleMappingComponent>
            if from_func and "uuid" in func_name.lower():
                print("    *** CANDIDATE: {} ***".format(func_name))

print("\n=== Searching for Singleton Access Patterns ===")

# Look for functions that match GetSingleton pattern:
# - Small to medium size (50-500 instructions)
# - Take no parameters or just EntityWorld*
# - Return a pointer

singleton_candidates = []

for func in fm.getFunctions(True):
    name = func.getName()
    name_lower = name.lower()

    # Direct matches
    if any(kw in name_lower for kw in ['getsingletoncomponent', 'getsingleton', 'uuidtohandle']):
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        singleton_candidates.append((name, entry, size))
        print("Direct match: {} @ 0x{:x} (size: {})".format(name, entry, size))

print("\n=== Searching for HashMap Access Patterns ===")

# UuidToHandleMappingComponent contains HashMap<Guid, EntityHandle>
# Look for functions that access hash map methods
hashmap_keywords = [
    "try_get",
    "HashMap",
    "find",
    "Mappings",
]

for search_str in hashmap_keywords:
    try:
        for block in memory.getBlocks():
            if not block.isInitialized():
                continue
            addr = memory.findBytes(block.getStart(), block.getEnd(),
                                    search_str.encode('utf-8'), None, True, monitor)
            if addr:
                print("Found '{}' at 0x{:x}".format(search_str, addr.getOffset()))
    except:
        pass

print("\n=== Searching for GUID/UUID Structure Usage ===")

# Search for functions that take Guid as parameter (16 bytes / 128 bits)
# Look for functions referencing Guid parsing or comparison

guid_related_funcs = []
for func in fm.getFunctions(True):
    name = func.getName()
    if any(kw in name for kw in ['Guid', 'guid', 'UUID', 'uuid', 'GUID']):
        entry = func.getEntryPoint().getOffset()
        guid_related_funcs.append((name, entry))

print("\nGUID-related functions found: {}".format(len(guid_related_funcs)))
for name, addr in guid_related_funcs[:20]:  # First 20
    print("  {} @ 0x{:x}".format(name, addr))

print("\n=== Summary and Next Steps ===")
print("Found {} UUID-related strings".format(sum(len(v) for v in found_strings.values())))
print("Found {} singleton candidates".format(len(singleton_candidates)))
print("Found {} GUID-related functions".format(len(guid_related_funcs)))

print("\n=== Key Offsets to Investigate ===")
print("Look for:")
print("1. Functions referencing 'ls::uuid::ToHandleMappingComponent' string")
print("2. Functions that call GetSingleton with component type for UUID mapping")
print("3. Functions that access a HashMap<Guid, EntityHandle> structure")
print("=" * 70)
