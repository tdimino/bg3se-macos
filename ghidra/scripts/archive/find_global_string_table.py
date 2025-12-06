#@category BG3SE
#@description Find GlobalStringTable on ARM64 by analyzing ADRP+LDR patterns and structure validation
#@author BG3SE-macOS

"""
GlobalStringTable Discovery Script for ARM64

This script finds the gGlobalStringTable global variable by:
1. Searching for known string references ("FixedString", etc.)
2. Analyzing ADRP+ADD/LDR instruction patterns near those references
3. Validating candidate pointers against known SubTable structure

From Windows BG3SE reference:
- GlobalStringTable contains 11 SubTables + MainTable
- SubTable offsets: EntrySize=0x1088, EntriesPerBucket=0x1090, NumBuckets=0x10C0, Buckets=0x1140
- MainTable at offset 0xC600
- Each SubTable is ~0x1200 bytes

ARM64 global access pattern:
    ADRP Xn, #page
    LDR  Xn, [Xn, #offset]  ; Load pointer from GOT/data section
    ; or
    ADD  Xn, Xn, #offset    ; Calculate address directly
"""

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import RefType
from ghidra.program.util import DefinedDataIterator
from ghidra.app.util import XReferenceUtil
import struct

# Windows x64 SubTable offsets (baseline for validation)
SUBTABLE_OFFSET_ENTRY_SIZE = 0x1088
SUBTABLE_OFFSET_ENTRIES_PER_BKT = 0x1090
SUBTABLE_OFFSET_NUM_BUCKETS = 0x10C0
SUBTABLE_OFFSET_BUCKETS = 0x1140
SUBTABLE_SIZE = 0x1200
GST_NUM_SUBTABLES = 11
GST_OFFSET_MAINTABLE = 0xC600

def get_bytes_at(addr, length):
    """Safely read bytes from address"""
    try:
        mem = currentProgram.getMemory()
        buf = bytearray(length)
        if mem.getBytes(addr, buf) == length:
            return bytes(buf)
    except:
        pass
    return None

def read_u32(addr):
    """Read uint32 from address"""
    data = get_bytes_at(addr, 4)
    if data:
        return struct.unpack('<I', data)[0]
    return None

def read_u64(addr):
    """Read uint64 from address"""
    data = get_bytes_at(addr, 8)
    if data:
        return struct.unpack('<Q', data)[0]
    return None

def read_ptr(addr):
    """Read pointer (64-bit) from address"""
    return read_u64(addr)

def is_valid_pointer(val):
    """Check if value looks like a valid heap/data pointer"""
    if val is None:
        return False
    # Valid pointers should be in reasonable range
    return val > 0x100000000 and val < 0x800000000000

def validate_subtable_at(base_addr, offset_buckets, offset_num_buckets, offset_entry_size):
    """Check if memory at base_addr looks like a valid SubTable"""
    try:
        addr = toAddr(base_addr)

        # Read SubTable fields at given offsets
        buckets = read_ptr(addr.add(offset_buckets))
        num_buckets = read_u32(addr.add(offset_num_buckets))
        entry_size = read_u64(addr.add(offset_entry_size))

        if buckets is None or num_buckets is None or entry_size is None:
            return False

        # Validation criteria
        if not is_valid_pointer(buckets):
            return False
        if num_buckets < 10 or num_buckets > 500000:
            return False
        if entry_size < 24 or entry_size > 1024:
            return False

        # Try to read first bucket
        bucket_addr = toAddr(buckets)
        first_bucket = read_ptr(bucket_addr)
        if not is_valid_pointer(first_bucket):
            return False

        return True
    except:
        return False

def validate_gst_candidate(ptr_value):
    """Validate if ptr_value points to GlobalStringTable structure"""
    if not is_valid_pointer(ptr_value):
        return None

    # Try Windows x64 offsets first
    offset_configs = [
        ("Windows x64", SUBTABLE_OFFSET_BUCKETS, SUBTABLE_OFFSET_NUM_BUCKETS, SUBTABLE_OFFSET_ENTRY_SIZE, SUBTABLE_SIZE),
        # ARM64 might have different alignment - try some variants
        ("ARM64 compact", 0x0B40, 0x0AC0, 0x0A88, 0x0C00),
        ("ARM64 aligned", 0x1180, 0x1100, 0x10C0, 0x1280),
    ]

    for name, off_buckets, off_num_buckets, off_entry_size, subtable_size in offset_configs:
        # Check SubTable[0]
        if validate_subtable_at(ptr_value, off_buckets, off_num_buckets, off_entry_size):
            # Also check SubTable[1]
            subtable1_addr = ptr_value + subtable_size
            if validate_subtable_at(subtable1_addr, off_buckets, off_num_buckets, off_entry_size):
                return {
                    'config': name,
                    'off_buckets': off_buckets,
                    'off_num_buckets': off_num_buckets,
                    'off_entry_size': off_entry_size,
                    'subtable_size': subtable_size
                }
    return None

def find_adrp_target(instr):
    """Extract target address from ADRP instruction"""
    if instr is None:
        return None
    mnemonic = instr.getMnemonicString()
    if mnemonic != "adrp":
        return None

    # Get the second operand (page address)
    try:
        ops = instr.getOpObjects(1)
        if ops and len(ops) > 0:
            return ops[0]
    except:
        pass
    return None

def analyze_instruction_sequence(addr):
    """Analyze ADRP+LDR/ADD sequence to find loaded global address"""
    listing = currentProgram.getListing()
    instr = listing.getInstructionAt(addr)
    if instr is None:
        return None

    mnemonic = instr.getMnemonicString()
    if mnemonic != "adrp":
        return None

    # Get ADRP target (page address)
    try:
        page_addr = None
        refs = instr.getReferencesFrom()
        for ref in refs:
            if ref.getReferenceType().isData():
                page_addr = ref.getToAddress()
                break

        if page_addr is None:
            return None

        # Look at next instruction for LDR or ADD
        next_instr = instr.getNext()
        if next_instr is None:
            return None

        next_mnem = next_instr.getMnemonicString()

        if next_mnem == "ldr":
            # LDR Xn, [Xn, #offset] - loading from GOT
            refs = next_instr.getReferencesFrom()
            for ref in refs:
                return ref.getToAddress()
        elif next_mnem == "add":
            # ADD Xn, Xn, #offset - calculating address directly
            # The result is page_addr + offset
            refs = next_instr.getReferencesFrom()
            for ref in refs:
                return ref.getToAddress()
    except Exception as e:
        pass

    return None

def search_by_string_xrefs():
    """Find GlobalStringTable by searching for string references"""
    results = []

    # Strings that might appear near GlobalStringTable usage
    search_strings = [
        "gGlobalStringTable",
        "GlobalStringTable",
        "FixedString",
        "StringEntry",
        "SubTable",
    ]

    print("\n=== Searching for GlobalStringTable by string XREFs ===")

    for search_str in search_strings:
        print("\nSearching for string: '%s'" % search_str)

        # Search in defined strings
        for string in DefinedDataIterator.definedStrings(currentProgram):
            try:
                str_val = string.getValue()
                if str_val and search_str.lower() in str(str_val).lower():
                    print("  Found string at %s: %s" % (string.getAddress(), str_val[:50]))

                    # Get XREFs to this string
                    for ref in XReferenceUtil.getXRefList(string):
                        ref_addr = ref.getFromAddress()
                        print("    XREF from: %s" % ref_addr)

                        # Analyze nearby code for ADRP patterns
                        listing = currentProgram.getListing()
                        # Search +/- 64 bytes for ADRP instructions
                        for offset in range(-64, 65, 4):
                            check_addr = ref_addr.add(offset)
                            instr = listing.getInstructionAt(check_addr)
                            if instr and instr.getMnemonicString() == "adrp":
                                target = analyze_instruction_sequence(check_addr)
                                if target:
                                    print("      ADRP target at +%d: %s" % (offset, target))
                                    # Check if this looks like a GST pointer
                                    ptr_val = read_ptr(target)
                                    if ptr_val:
                                        validation = validate_gst_candidate(ptr_val)
                                        if validation:
                                            print("      *** VALID GST CANDIDATE! Config: %s ***" % validation['config'])
                                            results.append({
                                                'ptr_addr': target,
                                                'gst_addr': ptr_val,
                                                'source': search_str,
                                                'validation': validation
                                            })
            except Exception as e:
                pass

    return results

def scan_data_section():
    """Scan __DATA section for potential GlobalStringTable pointers"""
    results = []

    print("\n=== Scanning __DATA section for GST pointers ===")

    mem = currentProgram.getMemory()
    blocks = mem.getBlocks()

    for block in blocks:
        name = block.getName()
        if "__DATA" in name or ".data" in name.lower() or ".got" in name.lower():
            print("\nScanning block: %s (%s - %s)" % (name, block.getStart(), block.getEnd()))

            start = block.getStart()
            size = block.getSize()

            # Read in chunks and look for pointers
            checked = 0
            found = 0

            addr = start
            while addr.compareTo(block.getEnd()) < 0:
                ptr_val = read_ptr(addr)
                if ptr_val and is_valid_pointer(ptr_val):
                    validation = validate_gst_candidate(ptr_val)
                    if validation:
                        found += 1
                        print("  Found candidate at %s -> 0x%x (config: %s)" % (addr, ptr_val, validation['config']))
                        results.append({
                            'ptr_addr': addr,
                            'gst_addr': ptr_val,
                            'source': 'data_scan',
                            'validation': validation
                        })

                addr = addr.add(8)
                checked += 1

                if checked % 100000 == 0:
                    print("    Checked %d pointers, found %d candidates..." % (checked, found))

    return results

def scan_for_0xc600_add():
    """Search for ADD instruction with 0xC600 immediate (MainTable offset)"""
    results = []

    print("\n=== Searching for ADD with 0xC600 immediate ===")

    listing = currentProgram.getListing()
    instr_iter = listing.getInstructions(True)

    count = 0
    found = 0

    while instr_iter.hasNext() and count < 50000000:
        instr = instr_iter.next()
        count += 1

        if count % 5000000 == 0:
            print("  Checked %d instructions, found %d..." % (count, found))

        try:
            mnemonic = instr.getMnemonicString()

            # Look for ADD with immediate
            if mnemonic == "add":
                # Check if any operand is 0xC600
                for i in range(instr.getNumOperands()):
                    ops = instr.getOpObjects(i)
                    for op in ops:
                        try:
                            val = int(str(op), 0)
                            if val == 0xC600:
                                found += 1
                                print("  Found ADD with 0xC600 at %s: %s" % (instr.getAddress(), instr))
                                results.append({
                                    'addr': instr.getAddress(),
                                    'instr': str(instr),
                                    'type': 'add_0xc600'
                                })
                        except:
                            pass
        except:
            pass

    print("  Total: checked %d instructions, found %d ADD 0xC600" % (count, found))
    return results

def main():
    print("=" * 70)
    print("GlobalStringTable Discovery Script for ARM64")
    print("=" * 70)
    print("\nProgram: %s" % currentProgram.getName())
    print("Base address: %s" % currentProgram.getImageBase())

    all_results = []

    # Method 1: Search by string XREFs
    results = search_by_string_xrefs()
    all_results.extend(results)

    # Method 2: Scan data section
    results = scan_data_section()
    all_results.extend(results)

    # Method 3: Search for 0xC600 ADD instruction
    add_results = scan_for_0xc600_add()

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    if all_results:
        print("\n*** FOUND %d GlobalStringTable CANDIDATES ***\n" % len(all_results))
        for i, result in enumerate(all_results):
            print("Candidate %d:" % (i+1))
            print("  Pointer address: %s" % result['ptr_addr'])
            print("  GST address: 0x%x" % result['gst_addr'])
            print("  Source: %s" % result['source'])
            print("  Config: %s" % result['validation']['config'])
            print("  Offsets:")
            print("    Buckets: 0x%x" % result['validation']['off_buckets'])
            print("    NumBuckets: 0x%x" % result['validation']['off_num_buckets'])
            print("    EntrySize: 0x%x" % result['validation']['off_entry_size'])
            print("    SubTableSize: 0x%x" % result['validation']['subtable_size'])

            # Calculate Ghidra offset for CLAUDE.md
            base = currentProgram.getImageBase()
            ptr_offset = result['ptr_addr'].subtract(base)
            print("  Ghidra offset: 0x%x" % ptr_offset)
            print()
    else:
        print("\nNo GlobalStringTable candidates found via validation.")
        print("The ARM64 SubTable structure may have different offsets than Windows x64.")
        print("\nTry these manual approaches:")
        print("1. Search for 'gGlobalStringTable' or 'GlobalStringTable' symbol")
        print("2. Look for XREF chains from FixedString resolution functions")
        print("3. Search for ADRP+ADD patterns loading 0xC600 offset")

    if add_results:
        print("\n*** FOUND %d ADD 0xC600 INSTRUCTIONS ***" % len(add_results))
        print("These may be MainTable access points - investigate manually:")
        for r in add_results[:10]:  # Show first 10
            print("  %s: %s" % (r['addr'], r['instr']))

    print("\n" + "=" * 70)
    print("Script complete.")

if __name__ == "__main__":
    main()
