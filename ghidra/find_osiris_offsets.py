# Ghidra script to find COsiris and OsiFunctionMan structures
# Run with: analyzeHeadless ... -postScript find_osiris_offsets.py

# Get the function manager
fm = currentProgram.getFunctionManager()
sm = currentProgram.getSymbolTable()
mem = currentProgram.getMemory()

print("=" * 60)
print("BG3SE-macOS: Searching for Osiris structures")
print("=" * 60)

# Search for functions containing relevant names
osiris_functions = []
funcman_functions = []
other_interesting = []

for func in fm.getFunctions(True):
    name = func.getName()
    addr = str(func.getEntryPoint())
    size = func.getBody().getNumAddresses()

    if "COsiris" in name:
        osiris_functions.append({'name': name, 'addr': addr, 'size': size})
    elif "OsiFunctionMan" in name or "FunctionMan" in name:
        funcman_functions.append({'name': name, 'addr': addr, 'size': size})
    elif "Osiris" in name or "Osi" in name:
        other_interesting.append({'name': name, 'addr': addr, 'size': size})

print("\n[COsiris Functions]")
for f in sorted(osiris_functions, key=lambda x: x['name']):
    print("  {} @ {} (size: {})".format(f['name'], f['addr'], f['size']))

print("\n[OsiFunctionMan Functions]")
for f in sorted(funcman_functions, key=lambda x: x['name']):
    print("  {} @ {} (size: {})".format(f['name'], f['addr'], f['size']))

print("\n[Other Osiris-related]")
for f in sorted(other_interesting, key=lambda x: x['name'])[:20]:
    print("  {} @ {} (size: {})".format(f['name'], f['addr'], f['size']))

# Search for symbols
print("\n[Symbols containing 'Osiris' or 'FunctionMan']")
for sym in sm.getAllSymbols(True):
    name = sym.getName()
    if "Osiris" in name or "FunctionMan" in name or "OsiFunc" in name:
        print("  {} @ {} (type: {})".format(name, sym.getAddress(), sym.getSymbolType()))

# Look for string references
print("\n[String references to 'COsiris' or 'OsiFunctionMan']")
strings = currentProgram.getListing().getDefinedData(True)
count = 0
for data in strings:
    if data.hasStringValue():
        val = data.getValue()
        if val and ("COsiris" in str(val) or "OsiFunctionMan" in str(val) or "pFunctionData" in str(val)):
            print("  {} @ {}".format(val, data.getAddress()))
            count += 1
            if count > 20:
                break

print("\n" + "=" * 60)
print("Total functions found: {}".format(fm.getFunctionCount()))
print("COsiris: {}, FunctionMan: {}, Other: {}".format(
    len(osiris_functions), len(funcman_functions), len(other_interesting)))
print("=" * 60)
