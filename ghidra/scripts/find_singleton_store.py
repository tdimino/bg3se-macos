# Ghidra script to find where EoCServer::StartUp stores the singleton pointer
# In ARM64, the "this" pointer is passed in X0
# We look for patterns that store X0 to a global address

from ghidra.program.model.lang import OperandType

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
refManager = currentProgram.getReferenceManager()
addressFactory = currentProgram.getAddressFactory()
defaultSpace = addressFactory.getDefaultAddressSpace()

print("=" * 70)
print("EoCServer Singleton Store Pattern Search")
print("=" * 70)

# EoCServer::StartUp
STARTUP_ADDR = 0x10110f0d0

# ============================================================================
# Step 1: Look for ADRP+STR pattern in StartUp that stores X0
# ============================================================================

print("\n=== Disassembling esv::EocServer::StartUp first 200 instructions ===")

startup_func = fm.getFunctionAt(defaultSpace.getAddress(STARTUP_ADDR))
if not startup_func:
    print("ERROR: Could not find StartUp function")
else:
    print("Function: {}".format(startup_func.getName()))

    addr = startup_func.getEntryPoint()
    instr_count = 0
    max_instrs = 200

    # Track potential ADRP addresses
    adrp_targets = {}

    while addr and instr_count < max_instrs:
        instr = listing.getInstructionAt(addr)
        if not instr:
            break

        mnemonic = instr.getMnemonicString()
        instr_str = str(instr)

        # Print all instructions for first 50
        if instr_count < 50:
            print("  {:3d}: 0x{:x}: {}".format(instr_count, addr.getOffset(), instr_str))

        # Track ADRP instructions
        if mnemonic == 'adrp':
            # Try to get the target address
            try:
                num_ops = instr.getNumOperands()
                if num_ops >= 2:
                    # Operand 0 is dest register, operand 1 is address
                    dest_reg = instr.getRegister(0)
                    if dest_reg:
                        reg_name = dest_reg.getName()
                        # Try to get the computed address
                        refs = refManager.getReferencesFrom(addr)
                        for ref in refs:
                            target = ref.getToAddress().getOffset()
                            adrp_targets[reg_name] = target
                            print("    ADRP {} -> 0x{:x}".format(reg_name, target))
            except:
                pass

        # Look for STR instructions (storing to memory)
        if mnemonic in ['str', 'stp', 'stur']:
            print("  {:3d}: 0x{:x}: {} ***".format(instr_count, addr.getOffset(), instr_str))

            # Get references from this instruction
            refs = refManager.getReferencesFrom(addr)
            for ref in refs:
                target = ref.getToAddress()
                block = memory.getBlock(target)
                if block:
                    print("        -> Store to 0x{:x} [{}]".format(target.getOffset(), block.getName()))

        addr = instr.getNext()
        if addr:
            addr = addr.getAddress()
        instr_count += 1

# ============================================================================
# Step 2: Look for any function that has "GetServer" pattern
# ============================================================================

print("\n\n=== Looking for GetServer-type functions ===")

# Search for functions that might return the server singleton
for func in fm.getFunctions(True):
    name = func.getName()
    size = func.getBody().getNumAddresses()

    # Very small functions are likely simple getters
    if size < 50 and any(kw in name for kw in ['GetServer', 'Server', 'EocServer']):
        entry = func.getEntryPoint().getOffset()
        print("\n  {} @ 0x{:x} (size: {}):".format(name, entry, size))

        # Disassemble
        addr = func.getEntryPoint()
        ic = 0
        while addr and ic < 20:
            instr = listing.getInstructionAt(addr)
            if not instr:
                break
            print("    0x{:x}: {}".format(addr.getOffset(), str(instr)))
            addr = instr.getNext()
            if addr:
                addr = addr.getAddress()
            ic += 1

# ============================================================================
# Step 3: Search __data segment for references from EoCServer functions
# ============================================================================

print("\n\n=== Searching for global pointers referenced by EoCServer functions ===")

# Get all EoCServer function addresses
eoc_func_addrs = set()
for func in fm.getFunctions(True):
    name = func.getName()
    if 'EocServer' in name or 'eocserver' in name.lower():
        eoc_func_addrs.add(func.getEntryPoint().getOffset())

# Get __data segment range
data_start = 0x10885d4a0
data_end = 0x10894e397

print("__data segment: 0x{:x} - 0x{:x}".format(data_start, data_end))
print("EoCServer functions found: {}".format(len(eoc_func_addrs)))

# Look for addresses in __data that are referenced by EoCServer functions
global_candidates = {}

# Sample some addresses in __data
sample_step = 0x1000  # Check every 4KB
addr_val = data_start
while addr_val < data_end:
    addr = defaultSpace.getAddress(addr_val)
    refs = refManager.getReferencesTo(addr)

    ref_count = 0
    eoc_refs = 0
    for ref in refs:
        ref_count += 1
        from_func = fm.getFunctionContaining(ref.getFromAddress())
        if from_func:
            from_addr = from_func.getEntryPoint().getOffset()
            if from_addr in eoc_func_addrs:
                eoc_refs += 1

    if ref_count > 0 and eoc_refs > 0:
        global_candidates[addr_val] = (ref_count, eoc_refs)

    addr_val += sample_step

print("\nGlobal pointers referenced by EoCServer functions:")
for addr, (total, eoc) in sorted(global_candidates.items(), key=lambda x: -x[1][1])[:20]:
    print("  0x{:x}: {} total refs, {} from EoCServer funcs".format(addr, total, eoc))

# ============================================================================
# Step 4: Check esv::EocServer::GetCombatLog
# ============================================================================

print("\n\n=== Analyzing esv::EocServer::GetCombatLog @ 0x101111fd4 ===")

combatlog_func = fm.getFunctionAt(defaultSpace.getAddress(0x101111fd4))
if combatlog_func:
    print("Function: {}".format(combatlog_func.getName()))
    print("Size: {} bytes".format(combatlog_func.getBody().getNumAddresses()))

    addr = combatlog_func.getEntryPoint()
    ic = 0
    while addr and ic < 30:
        instr = listing.getInstructionAt(addr)
        if not instr:
            break
        print("  0x{:x}: {}".format(addr.getOffset(), str(instr)))

        # Check references
        refs = refManager.getReferencesFrom(addr)
        for ref in refs:
            target = ref.getToAddress()
            block = memory.getBlock(target)
            if block:
                print("      -> Ref to 0x{:x} [{}]".format(target.getOffset(), block.getName()))

        addr = instr.getNext()
        if addr:
            addr = addr.getAddress()
        ic += 1

print("\n" + "=" * 70)
print("Analysis Complete")
print("=" * 70)
