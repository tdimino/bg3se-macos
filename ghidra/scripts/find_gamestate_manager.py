#!/usr/bin/env python3
"""
find_gamestate_manager.py - Find GameStateEventManager global pointers

Strategy:
1. Search for "SERVER STATE SWAP" and "CLIENT STATE SWAP" strings
2. Find XREFs to these strings (functions that log state transitions)
3. Analyze those functions for global pointer loads (ADRP+LDR pattern)
4. The global accessed before the callback loop is gGameStateEventManager

Windows BG3SE Reference (BinaryMappings.xml):
- Server: "SERVER STATE SWAP - from: %s, to: %s\n"
- Client: "CLIENT STATE SWAP - from: %s, to: %s"
- Global is accessed via: mov rax, cs:esv__gGameStateEventManager (or ecl__)
"""

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.address import AddressSet
from progress_utils import init_progress, progress, finish_progress
import re

def find_string_address(search_str):
    """Find address of a string in the binary."""
    memory = currentProgram.getMemory()

    # Search in all memory blocks
    for block in memory.getBlocks():
        if not block.isInitialized():
            continue

        start = block.getStart()

        try:
            data = bytearray(block.getSize())
            block.getBytes(start, data)
            data_str = bytes(data)

            # Search for string (case-sensitive)
            idx = data_str.find(search_str.encode('utf-8'))
            if idx >= 0:
                addr = start.add(idx)
                print("[+] Found '{}' at {}".format(search_str[:50], addr))
                return addr
        except:
            continue

    return None

def find_xrefs(addr):
    """Find cross-references to an address."""
    refs = []
    refManager = currentProgram.getReferenceManager()

    iterator = refManager.getReferencesTo(addr)
    for ref in iterator:
        refs.append(ref.getFromAddress())

    return refs

def analyze_function_for_globals(func_addr):
    """Analyze a function to find global pointer accesses via ADRP+LDR pattern."""
    listing = currentProgram.getListing()
    func = getFunctionContaining(func_addr)

    if not func:
        print("  [!] No function found at {}".format(func_addr))
        return []

    print("\n[*] Analyzing function: {} at {}".format(func.getName(), func.getEntryPoint()))

    body = func.getBody()
    inst_iter = listing.getInstructions(body, True)

    globals_found = []
    last_adrp_reg = None
    last_adrp_addr = None

    for inst in inst_iter:
        mnemonic = inst.getMnemonicString().lower()
        addr = inst.getAddress()

        # Track ADRP instructions (ARM64 page-based addressing)
        if mnemonic == "adrp":
            ops = inst.getDefaultOperandRepresentationList(0)
            if ops:
                last_adrp_reg = str(ops[0]) if hasattr(ops[0], '__str__') else str(ops)
            last_adrp_addr = addr

        # Look for LDR following ADRP (loading global pointer)
        elif mnemonic == "ldr" and last_adrp_addr:
            # Check if this LDR is close to the ADRP (within 4 instructions)
            dist = addr.subtract(last_adrp_addr)
            if 0 < dist <= 16:  # Within 4 ARM64 instructions (4 bytes each)
                # Get the operand representation to see what's being loaded
                op_str = inst.toString()

                # Check references from this instruction
                refs = inst.getReferencesFrom()
                for ref in refs:
                    if ref.getReferenceType().isData():
                        target = ref.getToAddress()

                        # Read the pointer value at this address (for offset calculation)
                        try:
                            ptr_value = currentProgram.getMemory().getLong(target)
                        except:
                            ptr_value = 0

                        globals_found.append({
                            'global_addr': target,
                            'access_addr': addr,
                            'instruction': op_str.strip(),
                            'ptr_value': ptr_value
                        })
                        print("  [+] Global access at {}: {} -> {}".format(
                            addr, op_str.strip(), target))

    return globals_found

def find_gamestate_offset(global_addr):
    """Calculate the offset from module base for the global."""
    # Get module base (first memory block in __TEXT)
    memory = currentProgram.getMemory()
    min_addr = None

    for block in memory.getBlocks():
        if block.isExecute() and ("__TEXT" in block.getName() or block.getName() == ".text"):
            if min_addr is None or block.getStart().compareTo(min_addr) < 0:
                min_addr = block.getStart()

    if min_addr is None:
        # Fall back to image base
        min_addr = currentProgram.getImageBase()

    offset = global_addr.subtract(min_addr)
    return offset, min_addr

def analyze_gamestate_manager_struct(global_addr):
    """Analyze the GameStateEventManager structure at runtime."""
    print("\n  [*] Structure Analysis for GameStateEventManager:")
    print("  Expected layout:")
    print("    +0x00: void* VMT")
    print("    +0x08: void** Callbacks.buf_")
    print("    +0x10: uint32_t Callbacks.cap_")
    print("    +0x14: uint32_t Callbacks.size_")
    print("  Total: 0x18 bytes")

def search_for_state_swap_strings():
    """Search for state swap log strings and analyze their users."""

    print("=" * 70)
    print("GameStateEventManager Discovery Script")
    print("=" * 70)

    results = {
        'server': [],
        'client': []
    }

    # Server state swap patterns (try variations)
    server_patterns = [
        "SERVER STATE SWAP - from: %s, to: %s",
        "SERVER STATE SWAP",
        "server state swap",
    ]

    # Client state swap patterns
    client_patterns = [
        "CLIENT STATE SWAP - from: %s, to: %s",
        "CLIENT STATE SWAP",
        "client state swap",
    ]

    # Search for server patterns
    progress("Searching for SERVER STATE SWAP", 20)
    print("\n[1] Searching for SERVER STATE SWAP strings...")

    for pattern in server_patterns:
        addr = find_string_address(pattern)
        if addr:
            xrefs = find_xrefs(addr)
            print("    XREFs: {}".format(len(xrefs)))

            for xref in xrefs[:3]:  # Analyze first 3 XREFs
                globals_found = analyze_function_for_globals(xref)
                if globals_found:
                    results['server'].extend(globals_found)
            break  # Found a match, stop searching patterns
    else:
        print("    No server state swap strings found")

    # Search for client patterns
    progress("Searching for CLIENT STATE SWAP", 50)
    print("\n[2] Searching for CLIENT STATE SWAP strings...")

    for pattern in client_patterns:
        addr = find_string_address(pattern)
        if addr:
            xrefs = find_xrefs(addr)
            print("    XREFs: {}".format(len(xrefs)))

            for xref in xrefs[:3]:
                globals_found = analyze_function_for_globals(xref)
                if globals_found:
                    results['client'].extend(globals_found)
            break
    else:
        print("    No client state swap strings found")

    # Search for GameStateMachine::Update patterns
    progress("Searching for GameStateMachine patterns", 70)
    print("\n[3] Searching for GameStateMachine-related patterns...")

    gsm_patterns = [
        "GameStateMachine",
        "esv::GameStateMachine",
        "ecl::GameStateMachine",
        "GameState",
    ]

    for pattern in gsm_patterns:
        addr = find_string_address(pattern)
        if addr:
            xrefs = find_xrefs(addr)
            if xrefs:
                print("[+] Found '{}' with {} XREFs".format(pattern, len(xrefs)))
                for xref in xrefs[:2]:
                    func = getFunctionContaining(xref)
                    if func:
                        print("    -> {} in {}".format(xref, func.getName()))

    return results

def print_summary(results):
    """Print summary of discovered addresses."""

    progress("Generating summary", 90)
    print("\n" + "=" * 70)
    print("SUMMARY - GameStateEventManager Candidates")
    print("=" * 70)

    # Server candidates
    print("\n[SERVER] esv__gGameStateEventManager candidates:")
    if results['server']:
        seen = set()
        for g in results['server']:
            addr = g['global_addr']
            if addr not in seen:
                seen.add(addr)
                offset, base = find_gamestate_offset(addr)
                print("  Global: {} (base + 0x{:x})".format(addr, offset))
                print("    Accessed at: {}".format(g['access_addr']))
    else:
        print("  None found - try running with -analyze flag")

    # Client candidates
    print("\n[CLIENT] ecl__gGameStateEventManager candidates:")
    if results['client']:
        seen = set()
        for g in results['client']:
            addr = g['global_addr']
            if addr not in seen:
                seen.add(addr)
                offset, base = find_gamestate_offset(addr)
                print("  Global: {} (base + 0x{:x})".format(addr, offset))
                print("    Accessed at: {}".format(g['access_addr']))
    else:
        print("  None found - try running with -analyze flag")

    # Structure info
    if results['server'] or results['client']:
        analyze_gamestate_manager_struct(None)

    print("\n" + "=" * 70)
    print("NEXT STEPS")
    print("=" * 70)
    print("""
1. Verify offsets at runtime using Ext.Debug.ReadPtr():

   local base = Ext.Memory.GetModuleBase("Baldur")
   local svr_evtmgr = Ext.Debug.ReadPtr(base + SERVER_OFFSET)
   _P(string.format("Server EventManager: 0x%x", svr_evtmgr))

2. Probe structure layout:

   local vmt = Ext.Debug.ReadPtr(svr_evtmgr + 0x00)
   local buf = Ext.Debug.ReadPtr(svr_evtmgr + 0x08)
   local cap = Ext.Debug.ReadU32(svr_evtmgr + 0x10)
   local size = Ext.Debug.ReadU32(svr_evtmgr + 0x14)
   _P(string.format("VMT=0x%x, Callbacks: buf=0x%x, cap=%d, size=%d",
       vmt, buf, cap, size))

3. If structure matches, implement hook in game_state.c
""")

def main():
    """Main entry point."""
    init_progress("find_gamestate_manager.py")

    print("\n" + "=" * 70)
    print("GameStateEventManager Global Pointer Finder")
    print("For BG3SE-macOS ARM64")
    print("=" * 70 + "\n")

    progress("Starting GameStateEventManager search", 10)

    # Search for patterns and analyze
    results = search_for_state_swap_strings()

    # Print summary
    print_summary(results)

    finish_progress()

if __name__ == "__main__":
    main()
