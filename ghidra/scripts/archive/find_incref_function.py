# Ghidra Script: Find FixedString::IncRef and related GST access functions
# Run AFTER analysis with: -postScript find_incref_function.py

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.listing import CodeUnit
from ghidra.app.decompiler import DecompInterface

print("=" * 70)
print("FixedString Function Discovery Script for ARM64 macOS")
print("=" * 70)

# Search for mangled symbol names related to FixedString
TARGET_SYMBOLS = [
    "IncRef",
    "DecRef",
    "FixedString",
    "GlobalStringTable",
    "StringTable",
    "FromString",
    "GetString",
    "CreateFromString",
]

def find_symbols_by_name():
    """Search for symbols containing target names."""
    results = []
    symbol_table = currentProgram.getSymbolTable()

    for target in TARGET_SYMBOLS:
        print("\nSearching for symbols containing '%s'..." % target)

        # Search all symbols
        for symbol in symbol_table.getAllSymbols(True):
            name = symbol.getName()
            if target.lower() in name.lower():
                results.append({
                    'name': name,
                    'address': symbol.getAddress(),
                    'type': symbol.getSymbolType()
                })
                print("  Found: %s at %s (%s)" % (name, symbol.getAddress(), symbol.getSymbolType()))

    return results

def find_strings_by_pattern():
    """Search for specific strings that might be used with FixedString."""
    print("\nSearching for marker strings...")

    # Strings that are often created as FixedStrings early
    marker_strings = [
        "h14884b44gc0bcg4fe7gbd6eg40ccb7063607",  # GUID pattern from Windows BG3SE
        "STORY_FROZEN",
        "Credits/credits.txt",
        "ComboCategory",
    ]

    string_iterator = currentProgram.getListing().getDefinedData(True)
    for data in string_iterator:
        if data.hasStringValue():
            val = data.getValue()
            for marker in marker_strings:
                if marker in val:
                    print("  Found '%s' at %s" % (val[:50], data.getAddress()))
                    # Find XREFs to this string
                    refs = currentProgram.getReferenceManager().getReferencesTo(data.getAddress())
                    for ref in refs:
                        print("    XREF from: %s" % ref.getFromAddress())

def find_add_instructions():
    """Find ADD instructions with specific immediates that might indicate GST access."""
    print("\nSearching for ADD instructions with GST-related immediates...")

    # On ARM64, adding to get MainTable (0xC600) would use:
    # add xN, xN, #0xC600
    # But ARM64 can't encode 0xC600 directly - it would need:
    # movk xN, #0xC600 or multiple adds

    # Look for patterns accessing large structures
    listing = currentProgram.getListing()
    text_block = None
    for block in currentProgram.getMemory().getBlocks():
        if block.isExecute():
            text_block = block
            break

    if not text_block:
        print("  No executable segment found")
        return

    count = 0
    instr_iter = listing.getInstructions(text_block.getStart(), True)

    interesting_finds = []

    for instr in instr_iter:
        count += 1
        if count % 5000000 == 0:
            print("  Scanned %d instructions..." % count)
        if count > 50000000:
            break

        mnemonic = instr.getMnemonicString()

        # Look for MOV with immediate that could be 0xC600
        if mnemonic in ["movk", "movz", "mov"]:
            for i in range(instr.getNumOperands()):
                scalar = instr.getScalar(i)
                if scalar:
                    val = scalar.getValue()
                    # 0xC600 = 50688
                    if val == 0xC600 or val == 50688:
                        interesting_finds.append({
                            'addr': instr.getAddress(),
                            'instr': str(instr),
                            'type': 'GST_OFFSET'
                        })
                        print("  Found 0xC600 at %s: %s" % (instr.getAddress(), instr))

    print("\nFound %d interesting instructions" % len(interesting_finds))
    return interesting_finds

def main():
    print("\nPhase 1: Finding symbols...")
    symbols = find_symbols_by_name()

    print("\nPhase 2: Finding marker strings...")
    find_strings_by_pattern()

    print("\nPhase 3: Finding GST offset patterns...")
    patterns = find_add_instructions()

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("Found %d relevant symbols" % len(symbols))

    # Print unique symbol names
    unique_names = set()
    for s in symbols:
        unique_names.add(s['name'])
    print("\nUnique symbol names:")
    for name in sorted(unique_names)[:20]:
        print("  - %s" % name)

main()
