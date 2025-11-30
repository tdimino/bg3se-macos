# Ghidra script to find the global EoCServer pointer
# Strategy: Look for patterns that store to a global after creating the EoCServer object

from ghidra.program.model.lang import OperandType

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
refManager = currentProgram.getReferenceManager()
addressFactory = currentProgram.getAddressFactory()
defaultSpace = addressFactory.getDefaultAddressSpace()

print("=" * 70)
print("EoCServer Global Pointer Search")
print("=" * 70)

# Key finding: EntityWorld is at EoCServer + 0x288

# ============================================================================
# Step 1: Look for functions that access EoCServer at offset 0x288
# These are likely accessing EntityWorld
# ============================================================================

print("\n=== Looking for code that accesses offset 0x288 ===")

# Sample addresses to check
sample_addrs = []

# Look for LDR instructions with offset 0x288
# This will find code that accesses EntityWorld from EoCServer
entityworld_accessors = []

for func in fm.getFunctions(True):
    name = func.getName()

    # Skip huge functions
    size = func.getBody().getNumAddresses()
    if size > 5000:
        continue

    body = func.getBody()
    addr = func.getEntryPoint()
    instr_count = 0

    while addr and instr_count < 200:
        instr = listing.getInstructionAt(addr)
        if not instr:
            break

        instr_str = str(instr)
        # Look for access at offset 0x288
        if '#0x288' in instr_str or ',#0x288' in instr_str:
            entityworld_accessors.append((name, func.getEntryPoint().getOffset(), addr.getOffset(), instr_str))

        addr = instr.getNext()
        if addr:
            addr = addr.getAddress()
        instr_count += 1

print("Found {} instructions accessing offset 0x288:".format(len(entityworld_accessors)))
for name, func_addr, instr_addr, instr_str in entityworld_accessors[:30]:
    print("  {} @ 0x{:x}: 0x{:x} {}".format(name[:50], func_addr, instr_addr, instr_str))

# ============================================================================
# Step 2: For functions that access 0x288, find where they get EoCServer from
# ============================================================================

print("\n\n=== Analyzing functions that access EntityWorld (offset 0x288) ===")

# Pick some representative functions
for name, func_addr, instr_addr, instr_str in entityworld_accessors[:5]:
    print("\n--- {} @ 0x{:x} ---".format(name[:60], func_addr))

    func = fm.getFunctionAt(defaultSpace.getAddress(func_addr))
    if not func:
        continue

    # Disassemble first 30 instructions to see where EoCServer comes from
    addr = func.getEntryPoint()
    ic = 0
    while addr and ic < 30:
        instr = listing.getInstructionAt(addr)
        if not instr:
            break

        mnemonic = instr.getMnemonicString()
        instr_str = str(instr)

        # Highlight ADRP (page address loading) and LDR (load from global)
        highlight = ""
        if mnemonic == 'adrp':
            highlight = " <-- PAGE LOAD"
        elif 'ldr' in mnemonic.lower() and '#0x' in instr_str:
            highlight = " <-- LOAD"
        elif '#0x288' in instr_str:
            highlight = " <-- ENTITYWORLD ACCESS"

        print("  {:3d}: 0x{:x}: {}{}".format(ic, addr.getOffset(), instr_str, highlight))

        addr = instr.getNext()
        if addr:
            addr = addr.getAddress()
        ic += 1

# ============================================================================
# Step 3: Look for a static GetEoCServer or similar function
# ============================================================================

print("\n\n=== Looking for GetEoCServer / GetServerWorld functions ===")

for func in fm.getFunctions(True):
    name = func.getName()
    name_lower = name.lower()
    size = func.getBody().getNumAddresses()

    # Small functions with relevant names
    if size < 100 and any(kw in name_lower for kw in ['geteocserver', 'getserver', 'serverworld']):
        if 'entityworld' not in name_lower:  # Skip EntityWorld specific ones
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

                # Get references from ADRP instructions
                if instr.getMnemonicString() == 'adrp':
                    refs = refManager.getReferencesFrom(addr)
                    for ref in refs:
                        target = ref.getToAddress().getOffset()
                        print("        -> Page base: 0x{:x}".format(target))

                addr = instr.getNext()
                if addr:
                    addr = addr.getAddress()
                ic += 1

# ============================================================================
# Step 4: Check EocServerSDM Init/Shutdown - likely manages singleton
# ============================================================================

print("\n\n=== Analyzing EocServerSDM functions (singleton manager) ===")

sdm_funcs = [
    (0x1049b1444, "EocServerSDM::Init"),
    (0x1049ba808, "EocServerSDM::Shutdown"),
]

for addr, name in sdm_funcs:
    print("\n--- {} @ 0x{:x} ---".format(name, addr))

    func = fm.getFunctionAt(defaultSpace.getAddress(addr))
    if not func:
        print("  Function not found")
        continue

    # Disassemble first 50 instructions
    faddr = func.getEntryPoint()
    ic = 0
    while faddr and ic < 50:
        instr = listing.getInstructionAt(faddr)
        if not instr:
            break

        mnemonic = instr.getMnemonicString()
        instr_str = str(instr)

        # Look for global stores/loads
        highlight = ""
        if mnemonic == 'adrp':
            refs = refManager.getReferencesFrom(faddr)
            for ref in refs:
                target = ref.getToAddress().getOffset()
                highlight = " --> PAGE 0x{:x}".format(target)
        elif mnemonic in ['str', 'stp']:
            highlight = " <-- STORE"
        elif 'ldr' in mnemonic.lower():
            highlight = " <-- LOAD"

        print("  {:3d}: 0x{:x}: {}{}".format(ic, faddr.getOffset(), instr_str, highlight))

        faddr = instr.getNext()
        if faddr:
            faddr = faddr.getAddress()
        ic += 1

print("\n" + "=" * 70)
print("Key Finding: EntityWorld is at EoCServer + 0x288")
print("Next: Need to find global EoCServer** pointer")
print("=" * 70)
