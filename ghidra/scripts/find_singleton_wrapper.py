# Ghidra script to find callers of TryGetSingleton<UuidToHandleMappingComponent>
# and identify potential wrapper functions that return a raw pointer.
#
# Usage:
#   JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
#   ~/ghidra/support/analyzeHeadless ~/ghidra_projects BG3Analysis \
#   -process BG3_arm64_thin -postScript find_singleton_wrapper.py -noanalysis
#
# Problem: TryGetSingleton returns ls::Result<T,E> which is 16-24 bytes.
# On ARM64 this either returns in x0:x1 (<=16 bytes) or via x8 buffer (>16 bytes).
# We're looking for a wrapper that unwraps the result and returns just the pointer.

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
refManager = currentProgram.getReferenceManager()
addressFactory = currentProgram.getAddressFactory()
defaultSpace = addressFactory.getDefaultAddressSpace()

TRYGETSINGLETON_ADDR = 0x1010dc924

print("=" * 70)
print("Finding callers of TryGetSingleton<UuidToHandleMappingComponent>")
print("Target address: 0x{:x}".format(TRYGETSINGLETON_ADDR))
print("=" * 70)

# Get the target address
target = defaultSpace.getAddress(TRYGETSINGLETON_ADDR)

# Find all references TO the target address
refs_to_target = refManager.getReferencesTo(target)
callers = []

for ref in refs_to_target:
    from_addr = ref.getFromAddress()
    func = fm.getFunctionContaining(from_addr)
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        name = func.getName()
        call_site = from_addr.getOffset()

        # Avoid duplicates (same function might call multiple times)
        if not any(c[1] == entry for c in callers):
            callers.append((name, entry, size, call_site))

print("\nFound {} callers:".format(len(callers)))
callers.sort(key=lambda x: x[2])  # Sort by size

# Track potential wrappers
wrappers = []

for name, entry, size, call_site in callers:
    is_small = size < 100
    marker = "*** SMALL ***" if is_small else ""
    print("\n{} @ 0x{:x} (size: {} bytes) {}".format(name, entry, size, marker))
    print("  Call site: 0x{:x}".format(call_site))

    if is_small:
        wrappers.append((name, entry, size))

        # Disassemble the function to see if it's a wrapper pattern
        func = fm.getFunctionAt(defaultSpace.getAddress(entry))
        if func:
            addr = func.getEntryPoint()
            print("  Disassembly:")

            ic = 0
            found_bl = False
            found_ret = False
            x8_referenced = False

            while addr and ic < 40:
                instr = listing.getInstructionAt(addr)
                if not instr:
                    break

                mnemonic = instr.getMnemonicString().lower()
                instr_str = str(instr)

                note = ""
                if 'bl' in mnemonic:
                    found_bl = True
                    note = " <-- CALL"
                    # Check if calling our target
                    refs = refManager.getReferencesFrom(addr)
                    for ref in refs:
                        if ref.getToAddress().getOffset() == TRYGETSINGLETON_ADDR:
                            note = " <-- CALLS TryGetSingleton!"
                elif 'ret' in mnemonic:
                    found_ret = True
                    note = " <-- RETURN"
                elif 'x8' in instr_str.lower():
                    x8_referenced = True
                    note = " <-- x8 REFERENCED"
                elif 'ldr' in mnemonic and 'x0' in instr_str.lower():
                    note = " <-- loads into x0 (return value)"
                elif 'cbz' in mnemonic or 'cbnz' in mnemonic:
                    note = " <-- conditional branch (error check?)"

                print("    {:3d}: 0x{:x}: {}{}".format(ic, addr.getOffset(), instr_str, note))

                addr = instr.getNext()
                if addr:
                    addr = addr.getAddress()
                ic += 1

            # Analyze pattern
            if found_bl and found_ret and not x8_referenced:
                print("\n  ANALYSIS: Simple call+return pattern, NO x8 usage")
                print("  >>> LIKELY WRAPPER - returns value from TryGetSingleton")
            elif x8_referenced:
                print("\n  ANALYSIS: Uses x8 register (indirect return convention)")
                print("  >>> May handle ls::Result directly")

print("\n" + "=" * 70)
print("=== WRAPPER CANDIDATES (functions < 100 bytes) ===")
print("=" * 70)

for name, entry, size in wrappers:
    print("  {} @ 0x{:x} (size: {})".format(name, entry, size))

print("\n" + "=" * 70)
print("=== ANALYZING TryGetSingleton ITSELF ===")
print("=" * 70)

# Also analyze the TryGetSingleton function to understand its return convention
func = fm.getFunctionAt(target)
if func:
    print("TryGetSingleton function:")
    print("  Name: {}".format(func.getName()))
    print("  Size: {} bytes".format(func.getBody().getNumAddresses()))

    # Look at first 30 instructions
    addr = func.getEntryPoint()
    print("\n  First 30 instructions:")

    ic = 0
    x8_stores = []

    while addr and ic < 30:
        instr = listing.getInstructionAt(addr)
        if not instr:
            break

        mnemonic = instr.getMnemonicString().lower()
        instr_str = str(instr)

        note = ""
        # Look for stores to x8 (indirect return buffer)
        if 'str' in mnemonic and 'x8' in instr_str.lower():
            x8_stores.append((addr.getOffset(), instr_str))
            note = " <-- STORE TO x8 BUFFER"
        elif 'stp' in mnemonic and 'x8' in instr_str.lower():
            x8_stores.append((addr.getOffset(), instr_str))
            note = " <-- STORE PAIR TO x8 BUFFER"

        print("    {:3d}: 0x{:x}: {}{}".format(ic, addr.getOffset(), instr_str, note))

        addr = instr.getNext()
        if addr:
            addr = addr.getAddress()
        ic += 1

    print("\n  Return convention analysis:")
    if x8_stores:
        print("  >>> INDIRECT RETURN via x8")
        print("  Found {} stores to x8 buffer:".format(len(x8_stores)))
        for off, instr in x8_stores:
            print("    0x{:x}: {}".format(off, instr))
    else:
        print("  >>> Likely REGISTER RETURN via x0(:x1)")
        print("  No stores to x8 buffer found in first 30 instructions")

else:
    print("Function not found at target address")

print("\n" + "=" * 70)
print("=== RECOMMENDATIONS ===")
print("=" * 70)

if wrappers:
    print("Small wrapper functions found. Test these first:")
    for name, entry, size in wrappers[:5]:  # Top 5
        print("  - 0x{:x} ({}, {} bytes)".format(entry, name, size))
    print("\nUpdate entity_system.c to use wrapper address instead of TryGetSingleton")
else:
    print("No small wrapper functions found.")
    print("Need to either:")
    print("1. Fix ARM64 ABI handling for TryGetSingleton (see return convention above)")
    print("2. Implement direct ECS query access like Windows BG3SE")

print("=" * 70)
