# Ghidra script to find the global EoCServer* pointer from EocServerSDM functions
#
# Usage:
#   JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
#   ~/ghidra/support/analyzeHeadless ~/ghidra_projects BG3Analysis \
#   -process BG3_arm64_thin -postScript find_sdm_global.py -noanalysis
#
# Key Discovery:
#   This script helped identify esv::EocServer::m_ptr at 0x10898e8b8
#   (symbol: __ZN3esv9EocServer5m_ptrE)
#
# The EocServerSDM (Server Data Manager) manages the EoCServer singleton lifecycle:
#   - EocServerSDM::Init creates the singleton and stores to m_ptr
#   - EocServerSDM::Shutdown destroys the singleton
#
# See: docs/CRASH_ANALYSIS.md for why we use direct memory read instead of hooks

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
refManager = currentProgram.getReferenceManager()
addressFactory = currentProgram.getAddressFactory()
defaultSpace = addressFactory.getDefaultAddressSpace()

print("=" * 70)
print("Finding EoCServer Global from SDM Functions")
print("=" * 70)

# EocServerSDM::Init typically creates the singleton and stores it to global
SDM_INIT = 0x1049b1444
SDM_SHUTDOWN = 0x1049ba808

def analyze_function(addr, name):
    print("\n=== {} @ 0x{:x} ===".format(name, addr))

    func = fm.getFunctionAt(defaultSpace.getAddress(addr))
    if not func:
        print("Function not found")
        return

    print("Disassembly (first 100 instructions):")

    faddr = func.getEntryPoint()
    ic = 0

    adrp_regs = {}  # Track ADRP page addresses

    while faddr and ic < 100:
        instr = listing.getInstructionAt(faddr)
        if not instr:
            break

        mnemonic = instr.getMnemonicString()
        instr_str = str(instr)

        note = ""

        # Track ADRP instructions
        if mnemonic == 'adrp':
            # Extract register and page from reference
            refs = refManager.getReferencesFrom(faddr)
            for ref in refs:
                page = ref.getToAddress().getOffset() & ~0xFFF
                rd = instr_str.split()[1].replace(',', '')
                adrp_regs[rd] = page
                note = " --> PAGE 0x{:x}".format(page)

        # Look for STR instructions that store to global
        elif mnemonic in ['str', 'stp']:
            # Check if this is storing to a global address
            if '[' in instr_str:
                note = " <-- STORE (potential global write)"

        # Look for LDR from global
        elif 'ldr' in mnemonic.lower():
            if '[' in instr_str:
                note = " <-- LOAD"

        # BL calls
        elif mnemonic == 'bl':
            note = " <-- CALL"

        # New allocator calls often precede singleton creation
        if 'new' in instr_str.lower() or 'alloc' in instr_str.lower():
            note += " (ALLOCATOR)"

        print("  {:3d}: 0x{:x}: {}{}".format(ic, faddr.getOffset(), instr_str, note))

        faddr = instr.getNext()
        if faddr:
            faddr = faddr.getAddress()
        ic += 1

    # Get all data references from this function
    print("\n  DATA references from {}:".format(name))
    body = func.getBody()
    addr_iter = body.getAddresses(True)
    seen = set()

    while addr_iter.hasNext():
        a = addr_iter.next()
        refs = refManager.getReferencesFrom(a)
        for ref in refs:
            to_addr = ref.getToAddress().getOffset()
            ref_type = ref.getReferenceType()
            if ref_type.isData() or ref_type.isWrite():
                if to_addr not in seen and to_addr > 0x108000000:  # Data segment range
                    seen.add(to_addr)
                    print("    0x{:x} ({})".format(to_addr, ref_type))

# Analyze both functions
analyze_function(SDM_INIT, "EocServerSDM::Init")
analyze_function(SDM_SHUTDOWN, "EocServerSDM::Shutdown")

print("\n" + "=" * 70)
print("Look for global pointers in __DATA segment (0x108xxxxxx range)")
print("The Init function creates EoCServer and stores to global")
print("The Shutdown function loads from global and destroys it")
print("=" * 70)
