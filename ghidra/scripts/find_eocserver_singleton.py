# Ghidra script to find esv::EoCServer singleton pointer for EntityWorld access
# Run with: analyzeHeadless ... -postScript find_eocserver_singleton.py
#
# The Windows BG3SE accesses EntityWorld via:
#   (*esv__EoCServer)->EntityWorld
# This is more stable than hooking game functions.

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.address import AddressSet

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
refManager = currentProgram.getReferenceManager()

print("=" * 70)
print("BG3 EoCServer Singleton Discovery")
print("=" * 70)

# ============================================================================
# Step 1: Search for EoCServer-related strings
# ============================================================================

eoc_server_strings = [
    "esv::EoCServer",
    "EoCServer",
    "EocServer",  # Alternative casing
    "esv::Server",
    "eoc::Server",
    "EntityWorld",
    "ServerWorld",
    "GameServer",
]

print("\n=== Searching for EoCServer Strings ===")
found_strings = {}

for block in memory.getBlocks():
    if not block.isInitialized():
        continue

    start = block.getStart()
    end = block.getEnd()
    block_name = block.getName()

    for search_str in eoc_server_strings:
        try:
            addr = start
            while addr and addr.compareTo(end) < 0:
                addr = memory.findBytes(addr, end, search_str.encode('utf-8'), None, True, monitor)
                if addr:
                    if search_str not in found_strings:
                        found_strings[search_str] = []
                    found_strings[search_str].append((addr, block_name))
                    print("Found '{}' at 0x{:x} in {}".format(search_str, addr.getOffset(), block_name))
                    addr = addr.add(1)
        except Exception as e:
            pass

# ============================================================================
# Step 2: Find references to EoCServer strings (to locate related code)
# ============================================================================

print("\n=== Analyzing References to EoCServer Strings ===")

candidate_functions = set()

for search_str, locations in found_strings.items():
    if "EoCServer" in search_str or "Server" in search_str:
        print("\n--- References to '{}' ---".format(search_str))
        for addr, block_name in locations[:5]:
            refs = refManager.getReferencesTo(addr)
            for ref in refs:
                from_addr = ref.getFromAddress()
                from_func = fm.getFunctionContaining(from_addr)
                if from_func:
                    func_name = from_func.getName()
                    func_addr = from_func.getEntryPoint().getOffset()
                    print("  <- 0x{:x} in {} (func @ 0x{:x})".format(
                        from_addr.getOffset(), func_name, func_addr))
                    candidate_functions.add((func_name, func_addr))
                else:
                    print("  <- 0x{:x} (no function)".format(from_addr.getOffset()))

# ============================================================================
# Step 3: Search for functions with EoCServer/Server in name
# ============================================================================

print("\n=== Searching for EoCServer Functions ===")

eoc_funcs = []
for func in fm.getFunctions(True):
    name = func.getName()
    name_lower = name.lower()

    if any(kw in name_lower for kw in ['eocserver', 'gameserver', 'serverinstance', 'getserver']):
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        eoc_funcs.append((name, entry, size))
        print("  {} @ 0x{:x} (size: {})".format(name, entry, size))

# ============================================================================
# Step 4: Search for GetSingleton pattern instantiations
# ============================================================================

print("\n=== Searching for Singleton Access Patterns ===")

singleton_keywords = [
    "GetSingleton",
    "TryGetSingleton",
    "GetInstance",
    "Instance",
    "g_Server",
    "s_Server",
    "gServer",
    "sServer",
]

singleton_funcs = []
for func in fm.getFunctions(True):
    name = func.getName()
    if any(kw in name for kw in singleton_keywords):
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        singleton_funcs.append((name, entry, size))

print("\nSingleton-related functions: {}".format(len(singleton_funcs)))
for name, addr, size in singleton_funcs[:30]:
    print("  {} @ 0x{:x} (size: {})".format(name, addr, size))

# ============================================================================
# Step 5: Search for global pointers in __DATA segment
# ============================================================================

print("\n=== Searching for Global Pointers in __DATA ===")

# Look for DATA segment blocks that might contain global pointers
data_blocks = []
for block in memory.getBlocks():
    name = block.getName()
    if "DATA" in name.upper() or "data" in name or "bss" in name.lower():
        data_blocks.append(block)
        print("  Data segment: {} (0x{:x} - 0x{:x})".format(
            name, block.getStart().getOffset(), block.getEnd().getOffset()))

# ============================================================================
# Step 6: Look for EntityWorld access patterns
# ============================================================================

print("\n=== Searching for EntityWorld Access Patterns ===")

# Windows BG3SE pattern: reads EoCServer pointer, then dereferences to get EntityWorld
# Looking for functions that:
# 1. Load a global pointer
# 2. Check for null
# 3. Dereference to get EntityWorld at offset ~0x288

entityworld_funcs = []
for func in fm.getFunctions(True):
    name = func.getName()
    name_lower = name.lower()

    if any(kw in name_lower for kw in ['entityworld', 'getworld', 'serverentityworld', 'getentityworld']):
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        entityworld_funcs.append((name, entry, size))
        print("  {} @ 0x{:x} (size: {})".format(name, entry, size))

# ============================================================================
# Step 7: Search for RTTI type info strings
# ============================================================================

print("\n=== Searching for RTTI Type Info ===")

rtti_strings = [
    "esv::EoCServer",
    "16esv10EoCServerE",  # Mangled name pattern
    "EoCServerVMT",
    "esv::EoCServer::VMT",
    "10EoCServer",  # Partial mangled
    "ecs::EntityWorld",
    "EntityWorld",
]

for search_str in rtti_strings:
    try:
        for block in memory.getBlocks():
            if not block.isInitialized():
                continue
            addr = memory.findBytes(block.getStart(), block.getEnd(),
                                    search_str.encode('utf-8'), None, True, monitor)
            if addr:
                print("Found RTTI '{}' at 0x{:x}".format(search_str, addr.getOffset()))
    except:
        pass

# ============================================================================
# Step 8: Look for double-pointer dereference patterns
# ============================================================================

print("\n=== Looking for Global Server Pointer Candidates ===")

# Look for references to addresses in DATA segment from code
# These could be global pointer loads

global_ptr_candidates = []

for block in data_blocks:
    start = block.getStart()
    end = block.getEnd()

    # Check what references this data region
    addr = start
    checked = 0
    while addr and addr.compareTo(end) < 0 and checked < 1000:
        refs = refManager.getReferencesTo(addr)
        ref_count = 0
        for ref in refs:
            ref_count += 1

        # Global pointers typically have multiple references
        if ref_count > 3:
            global_ptr_candidates.append((addr.getOffset(), ref_count))

        addr = addr.add(8)  # Pointer size
        checked += 1

print("\nHigh-reference global pointer candidates:")
global_ptr_candidates.sort(key=lambda x: -x[1])  # Sort by reference count
for addr, count in global_ptr_candidates[:20]:
    print("  0x{:x} ({} refs)".format(addr, count))

# ============================================================================
# Summary
# ============================================================================

print("\n" + "=" * 70)
print("SUMMARY - EoCServer Singleton Discovery")
print("=" * 70)

print("\nStrings found:")
for s, locs in found_strings.items():
    print("  '{}': {} locations".format(s, len(locs)))

print("\nEoCServer-related functions: {}".format(len(eoc_funcs)))
print("Singleton-related functions: {}".format(len(singleton_funcs)))
print("EntityWorld-related functions: {}".format(len(entityworld_funcs)))
print("Candidate functions from string refs: {}".format(len(candidate_functions)))

print("\n=== NEXT STEPS ===")
print("1. Examine functions referencing 'EoCServer' strings")
print("2. Look for global pointer loads followed by member access")
print("3. Check offset ~0x288 for EntityWorld member")
print("4. Verify by finding code that null-checks the pointer")

# Output candidate functions for manual inspection
print("\n=== CANDIDATES FOR MANUAL INSPECTION ===")
all_candidates = list(candidate_functions) + [(n, a) for n, a, s in eoc_funcs]
for name, addr in all_candidates[:20]:
    print("  {} @ 0x{:x}".format(name, addr))

print("\n" + "=" * 70)
