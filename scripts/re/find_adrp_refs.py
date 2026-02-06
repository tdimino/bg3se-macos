"""Correct ADRP search accounting for fat binary ARM64 slice offset."""
import struct, os, subprocess

BG3_BIN = os.path.expanduser("~/Library/Application Support/Steam/steamapps/common/Baldurs Gate 3/Baldur's Gate 3.app/Contents/MacOS/Baldur's Gate 3")

# Find ARM64 slice offset in fat binary
result = subprocess.run(['lipo', '-detailed_info', BG3_BIN], capture_output=True, text=True, timeout=10)
fat_offset = 0
in_arm64 = False
for line in result.stdout.split('\n'):
    if 'arm64' in line:
        in_arm64 = True
    if in_arm64 and 'offset' in line:
        parts = line.strip().split()
        for i, p in enumerate(parts):
            if p == 'offset':
                fat_offset = int(parts[i+1])
                break
        break

print(f"Fat binary ARM64 slice offset: 0x{fat_offset:x}")

base_addr = 0x100000000
TEXT_SIZE = 0x8398000

with open(BG3_BIN, 'rb') as f:
    f.seek(fat_offset)
    data = f.read(TEXT_SIZE)

print(f"Read {len(data)} bytes starting from fat offset 0x{fat_offset:x}")

# Verify: the string should be at file offset 0x7cedee2 within the slice
test_off = 0x7cedee2
if test_off < len(data):
    test_str = data[test_off:test_off+30]
    print(f"Verification: data at 0x{test_off:x} = {test_str}")
else:
    print(f"WARNING: offset 0x{test_off:x} is beyond data length 0x{len(data):x}")

targets = {
    'GameServer Peer Activate': (0x107ced000, 0xee2),
    'GameServer Peer Deactivate': (0x107ced000, 0xf0e),
    'PeerActivateMessage':      (0x107b98000, 0x7f0),
    'NETMSG_PEER_ACTIVATE':     (0x107b98000, 0x80c),
    'AbstractPeer::Protocols':  (0x107b64000, 0x331),
    'NETMSG_HANDSHAKE':         (0x107b98000, 0x2ab),
    'HandshakeMessage':         (0x107b98000, 0x295),
}

for name, (target_page, page_offset) in targets.items():
    print(f"\n=== {name} (page=0x{target_page:x}, off=0x{page_offset:x}) ===")
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

        adrp_addr = pc
        # Check next instructions for ADD with matching offset
        for j in range(1, 8):
            next_off = i + (j * 4)
            if next_off + 4 > len(data):
                break
            next_insn = struct.unpack_from('<I', data, next_off)[0]

            # ADD immediate 64-bit
            if (next_insn & 0xFFC00000) == 0x91000000:
                imm12 = (next_insn >> 10) & 0xFFF
                rn = (next_insn >> 5) & 0x1F
                rd2 = next_insn & 0x1F
                if imm12 == page_offset and rn == rd:
                    add_addr = base_addr + next_off
                    count += 1
                    print(f"  ADD: ADRP X{rd} at 0x{adrp_addr:x} + ADD X{rd2}, X{rd}, #0x{page_offset:x} at 0x{add_addr:x}")

            # LDR 64-bit unsigned offset
            if (next_insn & 0xFFC00000) == 0xF9400000:
                imm12_raw = (next_insn >> 10) & 0xFFF
                ldr_offset = imm12_raw * 8
                rn = (next_insn >> 5) & 0x1F
                rt = next_insn & 0x1F
                if ldr_offset == page_offset and rn == rd:
                    ldr_addr = base_addr + next_off
                    count += 1
                    print(f"  LDR: ADRP X{rd} at 0x{adrp_addr:x} + LDR X{rt}, [X{rd}, #0x{ldr_offset:x}] at 0x{ldr_addr:x}")

    if count == 0:
        # Count ADRP hits to this page
        adrp_count = 0
        for i in range(0, len(data) - 4, 4):
            insn = struct.unpack_from('<I', data, i)[0]
            if (insn & 0x9F000000) != 0x90000000:
                continue
            immlo = (insn >> 29) & 0x3
            immhi = (insn >> 5) & 0x7FFFF
            imm21 = (immhi << 2) | immlo
            if imm21 & (1 << 20):
                imm21 -= (1 << 21)
            pc_page = (base_addr + i) & ~0xFFF
            if pc_page + (imm21 << 12) == target_page:
                adrp_count += 1
        print(f"  No ADD/LDR matches. Total ADRP hits to page: {adrp_count}")
    else:
        print(f"  Total: {count} references")
