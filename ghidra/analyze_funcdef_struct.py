# Ghidra script to analyze COsiFunctionDef structure layout
# The constructor at 0x00026bb8 will show member initialization

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

print("=" * 60)
print("Analyzing COsiFunctionDef structure")
print("=" * 60)

# Key addresses from previous analysis
FUNCDEF_CTOR = toAddr(0x00026bb8)  # COsiFunctionDef constructor
FUNCDATA_CTOR = toAddr(0x000273ac)  # COsiFunctionData constructor
PFUNCTIONDATA = toAddr(0x0002a04c)  # pFunctionData(uint32_t)
OSIFUNCMAN_GLOBAL = 0x0009f348  # _OsiFunctionMan global offset

print("\nKey Offsets:")
print("  _OsiFunctionMan global: 0x{:08x}".format(OSIFUNCMAN_GLOBAL))
print("  COsiFunctionMan::pFunctionData: 0x{:08x}".format(PFUNCTIONDATA.getOffset()))
print("  COsiFunctionDef constructor: 0x{:08x}".format(FUNCDEF_CTOR.getOffset()))

# Analyze the constructor to understand structure layout
func = fm.getFunctionAt(FUNCDEF_CTOR)
if func:
    print("\nCOsiFunctionDef Constructor Analysis:")
    print("  Function: {}".format(func.getName()))
    print("  Size: {} bytes".format(func.getBody().getNumAddresses()))

    # Look at store instructions to understand member offsets
    print("\n  Member access patterns (str/stp instructions):")
    instr = getInstructionAt(FUNCDEF_CTOR)
    stores = []
    count = 0
    while instr and count < 200:
        mnem = instr.getMnemonicString()
        if mnem in ['str', 'stp', 'stur']:
            stores.append("    0x{:x}: {}".format(instr.getAddress().getOffset(), instr))
        instr = instr.getNext()
        count += 1

    for s in stores[:30]:  # First 30 stores
        print(s)

# Analyze pFunctionData to see how it accesses function data
pfunc = fm.getFunctionAt(PFUNCTIONDATA)
if pfunc:
    print("\npFunctionData Analysis:")
    print("  Function: {}".format(pfunc.getName()))
    print("  Size: {} bytes".format(pfunc.getBody().getNumAddresses()))

    # Look at how it accesses the function manager
    print("\n  Instructions (first 40):")
    instr = getInstructionAt(PFUNCTIONDATA)
    count = 0
    while instr and count < 40:
        print("    0x{:x}: {}".format(instr.getAddress().getOffset(), instr))
        instr = instr.getNext()
        count += 1

# Look for the global OsiFunctionMan reference
print("\n_OsiFunctionMan global at 0x{:08x}:".format(OSIFUNCMAN_GLOBAL))
data = listing.getDataAt(toAddr(OSIFUNCMAN_GLOBAL))
if data:
    print("  Type: {}".format(data.getDataType()))
    print("  Value: {}".format(data.getValue()))
else:
    print("  (No data defined at this address)")

# Check references to OsiFunctionMan
print("\nReferences TO _OsiFunctionMan:")
refs = getReferencesTo(toAddr(OSIFUNCMAN_GLOBAL))
for ref in refs[:10]:
    print("  {} -> 0x{:x}".format(ref.getReferenceType(), ref.getFromAddress().getOffset()))

print("\n" + "=" * 60)
print("Summary for main.c update:")
print("=" * 60)
print("""
#define OSIFUNCMAN_OFFSET 0x{:08x}  // _OsiFunctionMan global in libOsiris.dylib

// To get OsiFunctionMan at runtime:
// 1. Get libOsiris base address from any hook
// 2. Add OSIFUNCMAN_OFFSET to get pointer location
// 3. Dereference to get actual OsiFunctionMan instance
""".format(OSIFUNCMAN_GLOBAL))
