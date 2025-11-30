# Ghidra script to analyze ls::Result<T,E> return convention from TryGetSingleton
#
# Usage:
#   JAVA_HOME="/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home" \
#   ~/ghidra/support/analyzeHeadless ~/ghidra_projects BG3Analysis \
#   -process BG3_arm64_thin -postScript analyze_lsresult_return.py -noanalysis
#
# The function saves x8 (return buffer) to x19 early in prologue.
# We need to find all stores to [x19, #offset] to understand ls::Result layout.

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
refManager = currentProgram.getReferenceManager()
addressFactory = currentProgram.getAddressFactory()
defaultSpace = addressFactory.getDefaultAddressSpace()

TRYGETSINGLETON_ADDR = 0x1010dc924

print("=" * 70)
print("Analyzing ls::Result<T,E> return buffer layout")
print("TryGetSingleton @ 0x{:x}".format(TRYGETSINGLETON_ADDR))
print("=" * 70)

func = fm.getFunctionAt(defaultSpace.getAddress(TRYGETSINGLETON_ADDR))
if not func:
    print("Function not found!")
    exit()

print("\nFunction: {}".format(func.getName()))
print("Size: {} bytes".format(func.getBody().getNumAddresses()))

# Analyze all instructions looking for stores to x19 (saved x8 return buffer)
addr = func.getEntryPoint()
body = func.getBody()

ic = 0
x19_stores = []  # Stores to [x19, #offset]
ret_instructions = []
all_stores = []

print("\n=== FULL DISASSEMBLY (stores to x19 highlighted) ===")

while addr and body.contains(addr) and ic < 500:
    instr = listing.getInstructionAt(addr)
    if not instr:
        break

    mnemonic = instr.getMnemonicString().lower()
    instr_str = str(instr)
    note = ""

    # Track stores to x19 (the saved return buffer pointer)
    if ('str' in mnemonic or 'stp' in mnemonic) and 'x19' in instr_str.lower():
        # Check if it's storing TO x19's memory (not storing x19 as value)
        if '[x19' in instr_str.lower():
            x19_stores.append((ic, addr.getOffset(), instr_str))
            note = " <-- STORE TO RETURN BUFFER [x19]"
        elif ',x19' in instr_str.lower() or ', x19' in instr_str.lower():
            # Might be storing x19 to memory or paired store
            if '[' in instr_str.lower():
                all_stores.append((ic, addr.getOffset(), instr_str))
                note = " <-- stores x19 somewhere"

    # Track return instructions
    if 'ret' in mnemonic:
        ret_instructions.append((ic, addr.getOffset(), instr_str))
        note = " <-- RETURN"

    # Also look for stores to sp-relative addresses that might be the result
    if ('str' in mnemonic or 'stp' in mnemonic) and '[sp' in instr_str.lower():
        all_stores.append((ic, addr.getOffset(), instr_str))

    # Show instruction (selective - only show interesting ones)
    if note or ic < 50 or 'x19' in instr_str.lower():
        print("{:4d}: 0x{:x}: {}{}".format(ic, addr.getOffset(), instr_str, note))

    addr = instr.getNext()
    if addr:
        addr = addr.getAddress()
    ic += 1

print("\n" + "=" * 70)
print("=== STORES TO RETURN BUFFER [x19] ===")
print("=" * 70)

if x19_stores:
    for idx, off, instr in x19_stores:
        print("  {:4d}: 0x{:x}: {}".format(idx, off, instr))

        # Try to extract offset from instruction
        if '#' in instr:
            # Extract offset like [x19, #0x8] or [x19]
            import re
            match = re.search(r'\[x19(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]', instr)
            if match:
                offset = match.group(1)
                if offset:
                    print("       Offset: {}".format(offset))
                else:
                    print("       Offset: 0x0")
else:
    print("No direct stores to [x19] found!")
    print("Checking for indirect stores...")

# Look at end of function for return value setup
print("\n" + "=" * 70)
print("=== FUNCTION EPILOGUE (last 30 instructions before RET) ===")
print("=" * 70)

# Re-scan to get to last 30 instructions
addr = func.getEntryPoint()
instructions = []
while addr and body.contains(addr):
    instr = listing.getInstructionAt(addr)
    if not instr:
        break
    instructions.append((addr.getOffset(), str(instr)))
    addr = instr.getNext()
    if addr:
        addr = addr.getAddress()

# Print last 40 instructions
print("\nLast 40 instructions:")
for i, (off, instr_str) in enumerate(instructions[-40:]):
    note = ""
    if 'x19' in instr_str.lower():
        note = " <-- x19 (return buffer)"
    if 'ret' in instr_str.lower():
        note = " <-- RETURN"
    if 'x0' in instr_str.lower() and ('mov' in instr_str.lower() or 'ldr' in instr_str.lower()):
        note = " <-- sets x0 (return value)"
    print("  0x{:x}: {}{}".format(off, instr_str, note))

print("\n" + "=" * 70)
print("=== ANALYSIS SUMMARY ===")
print("=" * 70)

print("\nls::Result<T,E> structure layout hypothesis:")
print("  Based on ARM64 ABI, the function stores result via x8 (saved in x19)")
print("  Typical ls::Result layout:")
print("    offset 0x00: T value (pointer, 8 bytes)")
print("    offset 0x08: Error/success indicator")
print("    Total size: 16 bytes minimum")
print("")
print("If x0 is returned as well, it often contains:")
print("  - The buffer address (same as x8)")
print("  - Or a copy of the success/error indicator")

# Search for mov x0, x19 pattern near return
print("\n=== CHECKING FOR x0=x19 BEFORE RETURN ===")
for i, (off, instr_str) in enumerate(instructions[-20:]):
    if 'mov x0,x19' in instr_str.lower() or 'mov x0, x19' in instr_str.lower():
        print("  FOUND: 0x{:x}: {} -- x0 gets return buffer address".format(off, instr_str))

print("\n" + "=" * 70)
print("=== RECOMMENDED C STRUCT ===")
print("=" * 70)
print("""
typedef struct __attribute__((aligned(16))) {
    void* value;           // offset 0x00: Component pointer (or NULL on error)
    uint64_t error_code;   // offset 0x08: Error code (0 = success)
} LsResult;

// ARM64 calling convention: x8 must contain buffer address
void* call_try_get_singleton(void* fn, void* entityWorld) {
    LsResult result = {0};

    __asm__ volatile (
        "mov x8, %[buf]\\n"     // x8 = return buffer
        "mov x0, %[world]\\n"   // x0 = entityWorld
        "blr %[fn]\\n"          // call function
        : "+m"(result)
        : [buf] "r"(&result),
          [world] "r"(entityWorld),
          [fn] "r"(fn)
        : "x0", "x1", "x8", "x9", "x10", "x11", "x12", "x13",
          "x14", "x15", "x16", "x17", "x18", "x19", "x20",
          "x21", "x22", "x23", "x24", "x25", "x26",
          "x29", "x30", "memory"
    );

    // Check if result is valid
    if (result.error_code == 0 && result.value != NULL) {
        return result.value;
    }
    return NULL;
}
""")

print("=" * 70)
