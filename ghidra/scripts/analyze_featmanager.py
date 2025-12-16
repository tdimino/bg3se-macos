# Ghidra script to analyze FeatManager structure layout
# Run with: ./ghidra/scripts/run_analysis.sh analyze_featmanager.py
#
# Goals:
# 1. Verify FeatManager structure offsets (+0x7C count, +0x80 array)
# 2. Determine actual FEAT_SIZE on ARM64
# 3. Understand array structure (inline vs pointer array)

from ghidra.program.model.symbol import SymbolType
from ghidra.app.decompiler import DecompInterface

program = getCurrentProgram()
fm = program.getFunctionManager()
listing = program.getListing()
base = program.getImageBase().getOffset()

print("\n" + "="*60)
print("FeatManager Structure Analysis")
print("="*60)

# Known offsets from Frida script
OFFSET_GETFEATS = 0x01b752b4
OFFSET_GETALLFEATS = 0x0120b3e8
OFFSET_GETFROMUISELECTABLEFEATS = 0x022b0f44
OFFSET_SETUPFEATS = 0x022fd8cc

print("\n[1] Analyzing FeatManager::GetFeats at 0x%x" % OFFSET_GETFEATS)
print("-" * 40)

# Get the function
getfeats_addr = program.getImageBase().add(OFFSET_GETFEATS)
getfeats_func = fm.getFunctionAt(getfeats_addr)

if getfeats_func:
    print("Function: %s" % getfeats_func.getName())
    print("Entry: %s" % getfeats_func.getEntryPoint())
    print("Signature: %s" % getfeats_func.getSignature())

    # Decompile to see structure access
    decomp = DecompInterface()
    decomp.openProgram(program)
    results = decomp.decompileFunction(getfeats_func, 60, None)

    if results and results.decompileCompleted():
        decompiled = results.getDecompiledFunction()
        if decompiled:
            c_code = decompiled.getC()
            print("\nDecompiled code:")
            print("-" * 40)
            # Print first 100 lines
            lines = c_code.split('\n')
            for i, line in enumerate(lines[:100]):
                print(line)
            if len(lines) > 100:
                print("... (%d more lines)" % (len(lines) - 100))
else:
    print("ERROR: Could not find function at 0x%x" % OFFSET_GETFEATS)

# Look for offset patterns in assembly
print("\n[2] Analyzing assembly for offset patterns")
print("-" * 40)

if getfeats_func:
    body = getfeats_func.getBody()
    instr_iter = listing.getInstructions(body, True)

    offset_accesses = []

    for instr in instr_iter:
        mnemonic = instr.getMnemonicString()
        operands = str(instr)

        # Look for LDR/STR with offsets that might be structure accesses
        if mnemonic in ["LDR", "STR", "LDUR", "STUR"]:
            # Check for hex offsets in operands
            if "#0x" in operands or ", #" in operands:
                offset_accesses.append((str(instr.getAddress()), operands))

    print("Found %d memory access instructions:" % len(offset_accesses))
    for addr, op in offset_accesses[:30]:
        print("  %s: %s" % (addr, op))
    if len(offset_accesses) > 30:
        print("  ... (%d more)" % (len(offset_accesses) - 30))

# Search for Feat-related strings to find structure info
print("\n[3] Searching for Feat-related strings")
print("-" * 40)

from ghidra.program.model.data import StringDataType
from ghidra.program.model.listing import Data

# Search defined strings
found_strings = []
data_iter = listing.getDefinedData(True)
for data in data_iter:
    if data.hasStringValue():
        s = str(data.getValue())
        if "Feat" in s and len(s) < 100:
            found_strings.append((str(data.getAddress()), s))

print("Found %d Feat-related strings:" % len(found_strings))
for addr, s in found_strings[:20]:
    print("  %s: %s" % (addr, s[:60]))

# Look for functions that might reveal Feat structure size
print("\n[4] Searching for Feat allocation/copy functions")
print("-" * 40)

feat_funcs = []
for func in fm.getFunctions(True):
    name = func.getName()
    if "Feat" in name and ("alloc" in name.lower() or "copy" in name.lower() or
                           "size" in name.lower() or "new" in name.lower()):
        addr = func.getEntryPoint().getOffset()
        offset = addr - base
        feat_funcs.append((name, hex(offset)))

print("Found %d potential Feat structure functions:" % len(feat_funcs))
for name, offset in feat_funcs[:20]:
    print("  %s: %s" % (offset, name))

# Analyze GetAllFeats to see how array is iterated
print("\n[5] Analyzing GetAllFeats at 0x%x" % OFFSET_GETALLFEATS)
print("-" * 40)

getallfeats_addr = program.getImageBase().add(OFFSET_GETALLFEATS)
getallfeats_func = fm.getFunctionAt(getallfeats_addr)

if getallfeats_func:
    print("Function: %s" % getallfeats_func.getName())

    decomp = DecompInterface()
    decomp.openProgram(program)
    results = decomp.decompileFunction(getallfeats_func, 60, None)

    if results and results.decompileCompleted():
        decompiled = results.getDecompiledFunction()
        if decompiled:
            c_code = decompiled.getC()
            print("\nDecompiled code:")
            print("-" * 40)
            lines = c_code.split('\n')
            for i, line in enumerate(lines[:80]):
                print(line)
            if len(lines) > 80:
                print("... (%d more lines)" % (len(lines) - 80))
else:
    print("Could not find function at 0x%x" % OFFSET_GETALLFEATS)

# Look for sizeof patterns (multiply by constant for array indexing)
print("\n[6] Looking for array indexing patterns (LSL/MUL with constants)")
print("-" * 40)

if getfeats_func:
    body = getfeats_func.getBody()
    instr_iter = listing.getInstructions(body, True)

    index_patterns = []

    for instr in instr_iter:
        mnemonic = instr.getMnemonicString()
        operands = str(instr)

        # Look for LSL (shift left) and MUL operations
        if mnemonic in ["LSL", "MUL", "MADD", "ADD"] and "#" in operands:
            index_patterns.append((str(instr.getAddress()), operands))

    print("Found %d potential indexing operations:" % len(index_patterns))
    for addr, op in index_patterns[:20]:
        print("  %s: %s" % (addr, op))

print("\n" + "="*60)
print("Analysis complete")
print("="*60)
print("\nKey offsets to verify:")
print("  FeatManager.count: expected +0x7C")
print("  FeatManager.array: expected +0x80")
print("  FEAT_SIZE: expected 0x128 (296 bytes)")
print("\nCheck decompiled code for actual offset usage.")
