# Ghidra script to find EntityWorld access pattern
# The EntityWorld member is at offset ~0x288 in EoCServer struct
# Look for code that:
# 1. Loads a global pointer (ADRP + LDR pattern)
# 2. Dereferences to get EoCServer*
# 3. Then loads EntityWorld at offset around 0x280-0x290

from ghidra.program.model.lang import OperandType
from ghidra.program.model.address import AddressSet

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
refManager = currentProgram.getReferenceManager()
addressFactory = currentProgram.getAddressFactory()
defaultSpace = addressFactory.getDefaultAddressSpace()

print("=" * 70)
print("EntityWorld Access Pattern Search")
print("=" * 70)

# Key addresses from earlier discovery
STARTUP_ADDR = 0x10110f0d0  # esv::EocServer::StartUp
STOP_ADDR = 0x10111205c     # esv::EocServer::StopServer

# EntityWorld offset range (Windows is 0x288)
# ARM64 may differ, search around this range
ENTITYWORLD_OFFSET_MIN = 0x200
ENTITYWORLD_OFFSET_MAX = 0x300

# ============================================================================
# Step 1: Look for TryGetSingleton<EoCServer> or similar
# ============================================================================

print("\n=== Looking for EoCServer Singleton Getter Functions ===")

# Small functions (< 100 bytes) that reference EoCServer are likely getters
for func in fm.getFunctions(True):
    name = func.getName()
    size = func.getBody().getNumAddresses()

    # Small function with EocServer in name
    if size < 200 and ('EocServer' in name or 'GetServer' in name):
        entry = func.getEntryPoint().getOffset()
        print("  {} @ 0x{:x} (size: {})".format(name, entry, size))

        # Look at what globals this function references
        body = func.getBody()
        addr_iter = body.getAddresses(True)
        while addr_iter.hasNext():
            addr = addr_iter.next()
            refs = refManager.getReferencesFrom(addr)
            for ref in refs:
                to_addr = ref.getToAddress()
                block = memory.getBlock(to_addr)
                if block and ('DATA' in block.getName() or 'bss' in block.getName().lower()):
                    print("    -> Global ref at 0x{:x} [{}]".format(to_addr.getOffset(), block.getName()))

# ============================================================================
# Step 2: Disassemble StartUp function to find where singleton is stored
# ============================================================================

print("\n=== Analyzing esv::EocServer::StartUp prologue ===")

startup_func = fm.getFunctionAt(defaultSpace.getAddress(STARTUP_ADDR))
if startup_func:
    # The first parameter (x0/rcx) is "this" pointer
    # Look for store to global in the prologue

    body = startup_func.getBody()
    instr_count = 0
    max_instrs = 50  # Look at first 50 instructions

    addr = startup_func.getEntryPoint()
    while addr and instr_count < max_instrs:
        instr = listing.getInstructionAt(addr)
        if not instr:
            break

        mnemonic = instr.getMnemonicString()
        # In ARM64, storing to a global involves ADRP + STR pattern
        if mnemonic in ['ADRP', 'STR', 'STP', 'STUR']:
            print("  0x{:x}: {} {}".format(addr.getOffset(), mnemonic, instr.toString()))

        addr = instr.getNext()
        if addr:
            addr = addr.getAddress()
        instr_count += 1

# ============================================================================
# Step 3: Search for LDR with offset in EntityWorld range
# ============================================================================

print("\n=== Searching for EntityWorld Access Patterns ===")
print("Looking for LDR with offset 0x{:x}-0x{:x}".format(ENTITYWORLD_OFFSET_MIN, ENTITYWORLD_OFFSET_MAX))

# Search EntityWorld-related functions for access patterns
entityworld_funcs = []
for func in fm.getFunctions(True):
    name = func.getName()
    if 'EntityWorld' in name and 'Get' in name:
        entityworld_funcs.append((func, name))

print("\nAnalyzing {} EntityWorld getter functions".format(len(entityworld_funcs)))

for func, name in entityworld_funcs[:10]:
    entry = func.getEntryPoint()
    print("\n  {} @ 0x{:x}:".format(name, entry.getOffset()))

    body = func.getBody()
    addr = entry
    instr_count = 0
    max_instrs = 30

    while addr and instr_count < max_instrs:
        instr = listing.getInstructionAt(addr)
        if not instr:
            break

        mnemonic = instr.getMnemonicString()
        instr_str = str(instr)

        # Look for LDR with hex offsets
        if 'LDR' in mnemonic or 'ADRP' in mnemonic:
            print("    0x{:x}: {}".format(addr.getOffset(), instr_str))

        addr = instr.getNext()
        if addr:
            addr = addr.getAddress()
        instr_count += 1

# ============================================================================
# Step 4: Look for specific global data addresses
# ============================================================================

print("\n=== Looking for __DATA/__bss Global Pointers ===")

# Get DATA segments
data_segments = []
for block in memory.getBlocks():
    name = block.getName()
    if 'DATA' in name or 'data' in name or 'bss' in name.lower():
        data_segments.append((name, block.getStart().getOffset(), block.getEnd().getOffset()))
        print("  {} : 0x{:x} - 0x{:x}".format(name, block.getStart().getOffset(), block.getEnd().getOffset()))

# ============================================================================
# Step 5: Look for functions with "Singleton" pattern that return EoCServer
# ============================================================================

print("\n=== Looking for Singleton Pattern Functions ===")

singleton_candidates = []
for func in fm.getFunctions(True):
    name = func.getName()
    size = func.getBody().getNumAddresses()

    # Common singleton patterns
    if any(pattern in name for pattern in ['GetSingleton', 'TryGetSingleton', 'GetInstance', 'Instance']):
        if 'Server' in name or 'Eoc' in name or 'esv' in name:
            entry = func.getEntryPoint().getOffset()
            singleton_candidates.append((name, entry, size))

print("\nServer Singleton Candidates:")
for name, addr, size in singleton_candidates[:20]:
    print("  {} @ 0x{:x} (size: {})".format(name, addr, size))

# ============================================================================
# Step 6: Check if there's a simple getter that returns g_EocServer
# ============================================================================

print("\n=== Checking for Simple EocServer Getter ===")

# Look for very small functions (under 40 bytes) that might just return a global
for func in fm.getFunctions(True):
    name = func.getName()
    size = func.getBody().getNumAddresses()

    if size < 40 and ('EocServer' in name or 'eocserver' in name.lower()):
        entry = func.getEntryPoint().getOffset()
        print("\nSmall function: {} @ 0x{:x} (size: {})".format(name, entry, size))

        # Disassemble it
        addr = func.getEntryPoint()
        instr_count = 0
        while addr and instr_count < 20:
            instr = listing.getInstructionAt(addr)
            if not instr:
                break
            print("    0x{:x}: {}".format(addr.getOffset(), str(instr)))
            addr = instr.getNext()
            if addr:
                addr = addr.getAddress()
            instr_count += 1

print("\n" + "=" * 70)
print("Analysis Complete")
print("=" * 70)
