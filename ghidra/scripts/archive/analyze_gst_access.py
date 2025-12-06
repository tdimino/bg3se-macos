# Ghidra Script: Analyze GlobalStringTable access patterns at 0xC600 locations
# Run AFTER analysis with: -postScript analyze_gst_access.py
#
# Based on discovery that MOV with 0xC600 immediate is used for MainTable offset

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.listing import CodeUnit

print("=" * 70)
print("GST Access Pattern Analysis - 0xC600 MainTable Offset")
print("=" * 70)

# Key addresses found with 0xC600 pattern
# Focus on the clustered areas which likely have GST access
KEY_ADDRESSES = [
    # Clustered area 1: 0x100bd*
    0x100bd00d4,
    0x100bd0118,
    0x100bd050c,
    0x100bd0fc0,
    0x100bd1788,
    0x100bd30f8,

    # Clustered area 2: 0x100be8*-0x100bea*
    0x100be8cac,
    0x100be8f00,
    0x100be9024,
    0x100be9398,
    0x100be970c,

    # First few from 0x100baa* area
    0x100baa98c,
    0x100baa9b4,
]

def get_function_info(addr):
    """Get function containing this address."""
    func = getFunctionContaining(toAddr(addr))
    if func:
        return {
            'name': func.getName(),
            'entry': func.getEntryPoint(),
            'size': func.getBody().getNumAddresses()
        }
    return None

def get_surrounding_instructions(addr, count=10):
    """Get instructions before and after the target address."""
    listing = currentProgram.getListing()
    target = toAddr(addr)

    # Get instructions before
    before = []
    current = target
    for i in range(count):
        instr = listing.getInstructionBefore(current)
        if instr is None:
            break
        before.insert(0, {
            'addr': str(instr.getAddress()),
            'instr': str(instr),
            'mnemonic': instr.getMnemonicString()
        })
        current = instr.getAddress()

    # Get the target instruction
    target_instr = listing.getInstructionAt(target)

    # Get instructions after
    after = []
    if target_instr:
        current = target_instr.getAddress()
        for i in range(count):
            instr = listing.getInstructionAfter(current)
            if instr is None:
                break
            after.append({
                'addr': str(instr.getAddress()),
                'instr': str(instr),
                'mnemonic': instr.getMnemonicString()
            })
            current = instr.getAddress()

    return before, str(target_instr) if target_instr else "???", after

def find_adrp_patterns(before_instrs):
    """Look for ADRP instructions that might load GST pointer."""
    adrp_refs = []
    for instr_info in before_instrs:
        if instr_info['mnemonic'] == 'adrp':
            adrp_refs.append(instr_info)
        elif instr_info['mnemonic'] == 'ldr':
            adrp_refs.append(instr_info)
    return adrp_refs

def analyze_location(addr):
    """Analyze a single 0xC600 location."""
    print("\n" + "-" * 60)
    print("Analyzing 0x{:x}".format(addr))
    print("-" * 60)

    # Function info
    func_info = get_function_info(addr)
    if func_info:
        print("Function: {} at {}".format(func_info['name'], func_info['entry']))
    else:
        print("Function: <not in function>")

    # Surrounding instructions
    before, target, after = get_surrounding_instructions(addr, 15)

    print("\nInstruction context:")
    for instr in before[-8:]:  # Show last 8 before
        marker = "  "
        if instr['mnemonic'] in ['adrp', 'ldr']:
            marker = ">>"  # Highlight potential GST pointer loads
        print("  {} {} {}".format(marker, instr['addr'], instr['instr']))

    print("  ** {} **".format(target))  # The MOV with 0xC600

    for instr in after[:8]:  # Show first 8 after
        marker = "  "
        if instr['mnemonic'] == 'add':
            marker = ">>"  # Highlight adds that might compute final address
        print("  {} {} {}".format(marker, instr['addr'], instr['instr']))

    # Look for ADRP patterns
    adrp_patterns = find_adrp_patterns(before)
    if adrp_patterns:
        print("\nPotential GST pointer loads:")
        for p in adrp_patterns:
            print("  {} {}".format(p['addr'], p['instr']))

def main():
    print("\nAnalyzing {} key locations with 0xC600 pattern\n".format(len(KEY_ADDRESSES)))

    for addr in KEY_ADDRESSES[:10]:  # Analyze first 10
        analyze_location(addr)

    print("\n" + "=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)
    print("\nLook for patterns where:")
    print("1. ADRP loads a page address")
    print("2. LDR loads a pointer from that page")
    print("3. MOV w9, #0xc600 sets the offset")
    print("4. ADD computes final address")
    print("\nThe LDR target is likely ls__gGlobalStringTable")

main()
