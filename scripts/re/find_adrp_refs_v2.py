"""Search for all references to 'GameServer Peer Activate' string in the BG3 binary."""
import struct, os

BG3_BIN = os.path.expanduser("~/Library/Application Support/Steam/steamapps/common/Baldurs Gate 3/Baldur's Gate 3.app/Contents/MacOS/Baldur's Gate 3")
base_addr = 0x100000000
TEXT_SIZE = 0x8398000  # Full __TEXT segment

targets = {
    'GameServer Peer Activate': (0x107ced000, 0xee2),
    'PeerActivateMessage':      (0x107b98000, 0x7f0),
    'AbstractPeer::Protocols':  (0x107b64000, 0x331),
    'NETMSG_HANDSHAKE':         (0x107b98000, 0x2ab),
}

with open(BG3_BIN, 'rb') as f:
    data = f.read(TEXT_SIZE + 4)

print(f"Loaded {len(data)} bytes of __TEXT segment")

for name, (target_page, page_offset) in targets.items():
    print(f"\n=== Searching for references to {name} (page=0x{target_page:x}, off=0x{page_offset:x}) ===")
    count = 0
    for i in range(0, len(data) - 4, 4):
        insn = struct.unpack_from('<I', data, i)[0]

        if (insn & 0x9F000000) != 0x90000000:
            continue

        rd = insn & 0x1F
        immlo = (insn >> 29) & 0x3
        immhi = (insn >> 5) & 0x7FFFF
        imm21 = (immhi << 2) | immlo
        if imm21 & (1 << 20):
            imm21 -= (1 << 21)

        pc = base_addr + i
        pc_page = pc & ~0xFFF
        result_page = pc_page + (imm21 << 12)

        if result_page != target_page:
            continue

        # Found ADRP to target page. Check next instructions for ADD or LDR with the offset
        adrp_addr = base_addr + i
        for j in range(1, 8):
            next_off = i + (j * 4)
            if next_off + 4 > len(data):
                break
            next_insn = struct.unpack_from('<I', data, next_off)[0]

            # Check ADD immediate (64-bit): 1001000100 imm12 Rn Rd
            if (next_insn & 0xFFC00000) == 0x91000000:
                imm12 = (next_insn >> 10) & 0xFFF
                rn = (next_insn >> 5) & 0x1F
                rd2 = next_insn & 0x1F
                if imm12 == page_offset and rn == rd:
                    add_addr = base_addr + next_off
                    count += 1
                    print(f"  ADD MATCH at 0x{adrp_addr:x}: ADRP X{rd} + ADD X{rd2}, X{rd}, #0x{page_offset:x} (at 0x{add_addr:x})")

            # Check LDR (unsigned offset): size=11 opc=01 imm12 Rn Rt
            # LDR Xt, [Xn, #imm] where Xn was set by ADRP
            if (next_insn & 0xFFC00000) == 0xF9400000:  # LDR 64-bit unsigned offset
                imm12_raw = (next_insn >> 10) & 0xFFF
                ldr_offset = imm12_raw * 8  # Scale by 8 for 64-bit LDR
                rn = (next_insn >> 5) & 0x1F
                rt = next_insn & 0x1F
                if ldr_offset == page_offset and rn == rd:
                    ldr_addr = base_addr + next_off
                    count += 1
                    print(f"  LDR MATCH at 0x{adrp_addr:x}: ADRP X{rd} + LDR X{rt}, [X{rd}, #0x{ldr_offset:x}] (at 0x{ldr_addr:x})")

    if count == 0:
        # Also report all ADRP hits to this page (maybe different offset pattern)
        adrp_hits = 0
        for i in range(0, len(data) - 4, 4):
            insn = struct.unpack_from('<I', data, i)[0]
            if (insn & 0x9F000000) != 0x90000000:
                continue
            rd = insn & 0x1F
            immlo = (insn >> 29) & 0x3
            immhi = (insn >> 5) & 0x7FFFF
            imm21 = (immhi << 2) | immlo
            if imm21 & (1 << 20):
                imm21 -= (1 << 21)
            pc = base_addr + i
            pc_page = pc & ~0xFFF
            result_page = pc_page + (imm21 << 12)
            if result_page == target_page:
                adrp_hits += 1
                if adrp_hits <= 10:
                    print(f"  ADRP to page at 0x{pc:x} (X{rd}) — no matching ADD/LDR with offset 0x{page_offset:x}")
        print(f"  Total ADRP hits to page: {adrp_hits}")
