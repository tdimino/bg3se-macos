# find_arm64_global_string_table.py
# Search for GlobalStringTable on macOS ARM64
#
# Strategy:
# 1. Find functions that deal with FixedString creation/lookup
# 2. Look for ADRP+LDR patterns accessing global pointers
# 3. Check for structures with 11 SubTables (~0x1200 bytes each)
# 4. Look for the 0xC600 offset (MainTable) being added

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.listing import CodeUnit
from ghidra.app.decompiler import DecompileOptions, DecompInterface
import re

def log(msg):
    print("[GST] " + msg)

def search_for_fixedstring_functions():
    """Find functions related to FixedString operations"""
    log("=== Searching for FixedString-related functions ===")

    funcMgr = currentProgram.getFunctionManager()
    funcs = funcMgr.getFunctions(True)

    keywords = ["FixedString", "CreateString", "GetString", "StringTable",
                "InternString", "FromString", "ToString"]

    found = []
    for func in funcs:
        name = func.getName()
        for kw in keywords:
            if kw.lower() in name.lower():
                log("  Found: %s at %s" % (name, func.getEntryPoint()))
                found.append(func)
                break

    log("  Total: %d functions found" % len(found))
    return found

def analyze_adrp_patterns(func):
    """Analyze a function for ADRP+LDR patterns that access globals"""
    listing = currentProgram.getListing()
    body = func.getBody()

    # Track ADRP targets
    adrp_targets = {}

    instIter = listing.getInstructions(body, True)
    while instIter.hasNext():
        inst = instIter.next()
        mnemonic = inst.getMnemonicString()

        if mnemonic == "adrp":
            # ADRP loads page address into register
            # Format: adrp x0, 0x12345000
            try:
                reg = inst.getRegister(0)
                # Get the target address from the operand
                ops = inst.getOpObjects(1)
                if ops and len(ops) > 0:
                    target = ops[0]
                    if reg:
                        adrp_targets[reg.getName()] = (inst.getAddress(), target)
            except:
                pass

        elif mnemonic == "ldr" and len(adrp_targets) > 0:
            # LDR might reference ADRP target with offset
            # Format: ldr x0, [x0, #0x730]
            try:
                dest_reg = inst.getRegister(0)
                # Check if using a register we tracked from ADRP
                num_ops = inst.getNumOperands()
                if num_ops >= 2:
                    ref = inst.getOperandReferences(1)
                    if ref and len(ref) > 0:
                        target_addr = ref[0].getToAddress()
                        log("    LDR target: %s (from %s)" % (target_addr, inst.getAddress()))
            except:
                pass

        elif mnemonic == "add":
            # ADD might add 0xC600 offset for MainTable
            try:
                ops = inst.getOpObjects(2)
                if ops and len(ops) > 0:
                    imm = ops[0]
                    if hasattr(imm, 'getValue'):
                        val = imm.getValue()
                        if val == 0xC600:
                            log("  *** Found ADD with 0xC600 (MainTable offset) at %s" % inst.getAddress())
                            log("      In function: %s" % func.getName())
                    elif hasattr(imm, 'getUnsignedValue'):
                        val = imm.getUnsignedValue()
                        if val == 0xC600:
                            log("  *** Found ADD with 0xC600 (MainTable offset) at %s" % inst.getAddress())
                            log("      In function: %s" % func.getName())
            except:
                pass

def search_for_c600_offset():
    """Search for instructions that add 0xC600 (MainTable offset)"""
    log("\n=== Searching for 0xC600 offset (MainTable) ===")

    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()

    # Get code section
    textBlock = memory.getBlock("__TEXT")
    if not textBlock:
        log("  No __TEXT section found")
        return

    log("  Scanning %s to %s" % (textBlock.getStart(), textBlock.getEnd()))

    instIter = listing.getInstructions(textBlock.getStart(), True)
    count = 0
    found_addrs = []

    while instIter.hasNext() and count < 10000000:
        count += 1
        try:
            inst = instIter.next()
            mnemonic = inst.getMnemonicString()

            # Look for ADD with immediate 0xC600
            if mnemonic == "add":
                inst_str = inst.toString()
                if "0xc600" in inst_str.lower() or "#50688" in inst_str:
                    log("  Found: %s at %s" % (inst_str, inst.getAddress()))
                    found_addrs.append(inst.getAddress())

                    # Get containing function
                    func = currentProgram.getFunctionManager().getFunctionContaining(inst.getAddress())
                    if func:
                        log("    In function: %s" % func.getName())
        except:
            pass

    log("  Scanned %d instructions, found %d matches" % (count, len(found_addrs)))
    return found_addrs

def search_for_subtable_size():
    """Search for code using SubTable size 0x1200"""
    log("\n=== Searching for SubTable size 0x1200 ===")

    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()

    textBlock = memory.getBlock("__TEXT")
    if not textBlock:
        return

    instIter = listing.getInstructions(textBlock.getStart(), True)
    count = 0

    while instIter.hasNext() and count < 10000000:
        count += 1
        try:
            inst = instIter.next()
            inst_str = inst.toString().lower()

            # Look for 0x1200 (SubTable size) or related values
            if "0x1200" in inst_str or "#4608" in inst_str:
                log("  Found 0x1200: %s at %s" % (inst.toString(), inst.getAddress()))
                func = currentProgram.getFunctionManager().getFunctionContaining(inst.getAddress())
                if func:
                    log("    In function: %s" % func.getName())
        except:
            pass

def search_data_sections():
    """Search for large structures in data sections that could be GlobalStringTable"""
    log("\n=== Searching data sections for GlobalStringTable candidates ===")

    memory = currentProgram.getMemory()

    # GlobalStringTable is huge: 11 SubTables * 0x1200 + MainTable
    # Total size ~0xC600 + sizeof(MainTable) = ~50KB+

    for block in memory.getBlocks():
        name = block.getName()
        if "DATA" in name.upper() or "BSS" in name.upper() or "COMMON" in name.upper():
            log("  Block: %s (%s to %s, size=%d)" % (
                name, block.getStart(), block.getEnd(), block.getSize()))

def search_for_bucket_access():
    """Search for patterns accessing Buckets array (offset 0x1140 in SubTable)"""
    log("\n=== Searching for Bucket access patterns (offset 0x1140) ===")

    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()

    textBlock = memory.getBlock("__TEXT")
    if not textBlock:
        return

    instIter = listing.getInstructions(textBlock.getStart(), True)
    count = 0

    while instIter.hasNext() and count < 10000000:
        count += 1
        try:
            inst = instIter.next()
            inst_str = inst.toString().lower()

            # Look for 0x1140 (Buckets offset)
            if "0x1140" in inst_str or "#4416" in inst_str:
                log("  Found 0x1140: %s at %s" % (inst.toString(), inst.getAddress()))
                func = currentProgram.getFunctionManager().getFunctionContaining(inst.getAddress())
                if func:
                    log("    In function: %s" % func.getName())
        except:
            pass

def search_for_string_xrefs():
    """Search for strings that might be used near GlobalStringTable"""
    log("\n=== Searching for marker strings ===")

    # These strings appear in code that uses GlobalStringTable
    markers = [
        "GlobalStringTable",
        "FixedString",
        "StringTable",
        "SubTable",
    ]

    symbolTable = currentProgram.getSymbolTable()
    listing = currentProgram.getListing()

    for marker in markers:
        log("  Searching for '%s'..." % marker)
        # Search in defined strings
        dataIter = listing.getDefinedData(True)
        while dataIter.hasNext():
            try:
                data = dataIter.next()
                if data.hasStringValue():
                    val = data.getValue()
                    if val:
                        try:
                            val_str = str(val).encode('ascii', 'replace').decode('ascii')
                            if marker.lower() in val_str.lower():
                                safe_val = val_str[:60]
                                log("    Found: '%s' at %s" % (safe_val, data.getAddress()))
                                # Get XREFs to this string
                                refs = getReferencesTo(data.getAddress())
                                for ref in refs:
                                    log("      XREF from: %s" % ref.getFromAddress())
                        except:
                            pass
            except:
                pass

def analyze_known_rpgstats_offset():
    """Use known RPGStats offset to find nearby globals"""
    log("\n=== Analyzing area near known RPGStats global ===")

    # RPGStats::m_ptr is at offset 0x89c5730 from base
    # GlobalStringTable might be nearby
    rpgstats_offset = 0x89c5730

    log("  RPGStats::m_ptr offset: 0x%x" % rpgstats_offset)
    log("  Searching nearby for pointer-like values...")

    # GlobalStringTable is likely in the same data section
    # Try to find it within +/- 0x10000 of RPGStats

    memory = currentProgram.getMemory()
    listing = currentProgram.getListing()

    # Calculate runtime address (assuming base = 0x100000000)
    base = 0x100000000
    rpgstats_addr = currentProgram.getAddressFactory().getAddress("0x%x" % (base + rpgstats_offset))

    log("  RPGStats at: %s" % rpgstats_addr)

    # Search nearby addresses
    search_start = base + rpgstats_offset - 0x10000
    search_end = base + rpgstats_offset + 0x10000

    for offset in range(0, 0x20000, 8):
        addr = currentProgram.getAddressFactory().getAddress("0x%x" % (search_start + offset))
        data = listing.getDataAt(addr)
        if data:
            try:
                val = data.getValue()
                # Look for pointer values
                if val and "0x1" in str(val)[:5]:
                    log("    0x%x: %s" % (search_start + offset - base, val))
            except:
                pass

# Main execution
print("=" * 70)
print("GlobalStringTable ARM64 Search")
print("=" * 70)

# Run searches
fs_funcs = search_for_fixedstring_functions()

# Analyze first few FixedString functions for patterns
log("\n=== Analyzing FixedString functions for global access ===")
for func in fs_funcs[:10]:
    log("Analyzing: %s" % func.getName())
    analyze_adrp_patterns(func)

search_for_c600_offset()
search_for_subtable_size()
search_for_bucket_access()
search_data_sections()
search_for_string_xrefs()
analyze_known_rpgstats_offset()

print("\n" + "=" * 70)
print("Search complete.")
print("Next steps:")
print("  1. If 0xC600 offset found, trace back to find global pointer")
print("  2. Check functions with ADRP+LDR patterns near FixedString code")
print("  3. Look at data section near RPGStats for large structures")
print("=" * 70)
