# Ghidra script to analyze esv::EocServer::StartUp and find the global singleton pointer
# The startup function should reference the global EoCServer* pointer

from ghidra.program.model.symbol import RefType
from ghidra.app.decompiler import DecompInterface, DecompileOptions

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
refManager = currentProgram.getReferenceManager()
addressFactory = currentProgram.getAddressFactory()
defaultSpace = addressFactory.getDefaultAddressSpace()

print("=" * 70)
print("EoCServer Singleton Pointer Analysis")
print("=" * 70)

# Key addresses found in previous scan
STARTUP_ADDR = 0x10110f0d0  # esv::EocServer::StartUp
STOPSERVER_ADDR = 0x10111205c  # esv::EocServer::StopServer

# High-reference global pointers
CANDIDATE_PTRS = [0x10885d068, 0x10885d018]

# ============================================================================
# Step 1: Analyze EocServer::StartUp function
# ============================================================================

print("\n=== Analyzing esv::EocServer::StartUp at 0x{:x} ===".format(STARTUP_ADDR))

startup_func = fm.getFunctionAt(defaultSpace.getAddress(STARTUP_ADDR))
if startup_func:
    print("Function: {}".format(startup_func.getName()))
    print("Size: {} bytes".format(startup_func.getBody().getNumAddresses()))

    # Get references FROM this function (what it accesses)
    print("\n--- References FROM StartUp function ---")
    body = startup_func.getBody()
    refs_from = []

    # Iterate through the function's address range
    addr_iter = body.getAddresses(True)
    while addr_iter.hasNext():
        addr = addr_iter.next()
        refs = refManager.getReferencesFrom(addr)
        for ref in refs:
            to_addr = ref.getToAddress()
            ref_type = ref.getReferenceType()
            # Look for DATA references (global variable access)
            if ref_type.isData() or ref_type.isRead() or ref_type.isWrite():
                refs_from.append((addr.getOffset(), to_addr.getOffset(), str(ref_type)))

    # Sort by destination address and deduplicate
    seen_addrs = set()
    for from_addr, to_addr, ref_type in sorted(refs_from, key=lambda x: x[1]):
        if to_addr not in seen_addrs:
            seen_addrs.add(to_addr)
            # Check if this is in __DATA segment (global variables)
            block = memory.getBlock(defaultSpace.getAddress(to_addr))
            block_name = block.getName() if block else "???"
            print("  0x{:x} -> 0x{:x} ({}) [{}]".format(from_addr, to_addr, ref_type, block_name))
else:
    print("ERROR: Could not find StartUp function")

# ============================================================================
# Step 2: Analyze StopServer function
# ============================================================================

print("\n=== Analyzing esv::EocServer::StopServer at 0x{:x} ===".format(STOPSERVER_ADDR))

stop_func = fm.getFunctionAt(defaultSpace.getAddress(STOPSERVER_ADDR))
if stop_func:
    print("Function: {}".format(stop_func.getName()))
    print("Size: {} bytes".format(stop_func.getBody().getNumAddresses()))

    # Get references FROM this function
    print("\n--- Global References FROM StopServer function ---")
    body = stop_func.getBody()

    addr_iter = body.getAddresses(True)
    seen_addrs = set()
    while addr_iter.hasNext():
        addr = addr_iter.next()
        refs = refManager.getReferencesFrom(addr)
        for ref in refs:
            to_addr = ref.getToAddress()
            ref_type = ref.getReferenceType()
            if ref_type.isData() or ref_type.isRead() or ref_type.isWrite():
                to_offset = to_addr.getOffset()
                if to_offset not in seen_addrs:
                    seen_addrs.add(to_offset)
                    block = memory.getBlock(to_addr)
                    block_name = block.getName() if block else "???"
                    if "DATA" in block_name or "bss" in block_name.lower():
                        print("  0x{:x} ({}) [{}]".format(to_offset, ref_type, block_name))

# ============================================================================
# Step 3: Check candidate global pointers
# ============================================================================

print("\n=== Checking Candidate Global Pointers ===")

for ptr_addr in CANDIDATE_PTRS:
    addr = defaultSpace.getAddress(ptr_addr)
    print("\nPointer at 0x{:x}:".format(ptr_addr))

    # Get block info
    block = memory.getBlock(addr)
    if block:
        print("  Block: {}".format(block.getName()))

    # Get references TO this address (who reads/writes it)
    refs = refManager.getReferencesTo(addr)
    ref_count = 0
    ref_funcs = set()
    for ref in refs:
        ref_count += 1
        from_addr = ref.getFromAddress()
        func = fm.getFunctionContaining(from_addr)
        if func:
            ref_funcs.add((func.getName(), func.getEntryPoint().getOffset()))

    print("  Total references: {}".format(ref_count))
    print("  Functions referencing this pointer:")
    for name, func_addr in sorted(ref_funcs, key=lambda x: x[1])[:15]:
        print("    {} @ 0x{:x}".format(name, func_addr))

# ============================================================================
# Step 4: Search for 'esv__EoCServer' or similar global name
# ============================================================================

print("\n=== Searching for Named Symbols ===")

symbol_table = currentProgram.getSymbolTable()
for sym in symbol_table.getAllSymbols(True):
    name = sym.getName()
    name_lower = name.lower()
    if 'eocserver' in name_lower or 'eoc_server' in name_lower or 'g_server' in name_lower:
        print("  {} @ 0x{:x}".format(name, sym.getAddress().getOffset()))

# ============================================================================
# Step 5: Look for GetServer() function
# ============================================================================

print("\n=== Looking for GetServer Functions ===")

for func in fm.getFunctions(True):
    name = func.getName()
    if 'GetServer' in name or 'GetEoCServer' in name or 'GetInstance' in name:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        # Small functions (under 100 bytes) are likely simple getters
        if size < 100:
            print("  {} @ 0x{:x} (size: {})".format(name, entry, size))

# ============================================================================
# Step 6: Decompile the StartUp function to find singleton assignment
# ============================================================================

print("\n=== Decompiling StartUp function ===")

try:
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)

    result = decompiler.decompileFunction(startup_func, 60, monitor)
    if result and result.decompileCompleted():
        decomp = result.getDecompiledFunction()
        if decomp:
            c_code = decomp.getC()
            # Print first 100 lines of decompiled code
            lines = c_code.split('\n')[:100]
            for line in lines:
                print(line)
except Exception as e:
    print("Decompilation failed: {}".format(e))

print("\n" + "=" * 70)
print("Analysis Complete")
print("=" * 70)
