"""Find Protocol::ProcessMsg dispatch by analyzing ProtocolList iteration patterns.

Strategy:
1. Find all sites that access ProtocolList (+0x2E0) and trace the loop
2. Find all callers of NetMessageFactory::GetMessage (0x1063d5998)
3. Look for virtual calls (BLR) after loading from ProtocolList entries
"""
import struct, os

BG3_BIN = os.path.expanduser("~/Library/Application Support/Steam/steamapps/common/Baldurs Gate 3/Baldur's Gate 3.app/Contents/MacOS/Baldur's Gate 3")
FAT_OFFSET = 0xf534000
BASE = 0x100000000

def decode(insn, addr):
    if (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1F
        immlo = (insn >> 29) & 0x3; immhi = (insn >> 5) & 0x7FFFF
        imm21 = (immhi << 2) | immlo
        if imm21 & (1 << 20): imm21 -= (1 << 21)
        result = (addr & ~0xFFF) + (imm21 << 12)
        return f"ADRP X{rd}, 0x{result:x}"
    if (insn & 0xFFC00000) == 0x91000000:
        rd = insn & 0x1F; rn = (insn >> 5) & 0x1F; imm = (insn >> 10) & 0xFFF
        sh = (insn >> 22) & 1
        if sh: imm <<= 12
        return f"ADD X{rd}, X{rn}, #0x{imm:x}"
    if (insn & 0xFFC00000) == 0xD1000000:
        rd = insn & 0x1F; rn = (insn >> 5) & 0x1F; imm = (insn >> 10) & 0xFFF
        return f"SUB X{rd}, X{rn}, #0x{imm:x}"
    if (insn & 0xFFC00000) == 0xF9400000:
        rt = insn & 0x1F; rn = (insn >> 5) & 0x1F; imm = ((insn >> 10) & 0xFFF) * 8
        return f"LDR X{rt}, [X{rn}, #0x{imm:x}]"
    if (insn & 0xFFC00000) == 0xB9400000:
        rt = insn & 0x1F; rn = (insn >> 5) & 0x1F; imm = ((insn >> 10) & 0xFFF) * 4
        return f"LDR W{rt}, [X{rn}, #0x{imm:x}]"
    if (insn & 0xFFC00000) == 0xF9000000:
        rt = insn & 0x1F; rn = (insn >> 5) & 0x1F; imm = ((insn >> 10) & 0xFFF) * 8
        return f"STR X{rt}, [X{rn}, #0x{imm:x}]"
    if (insn & 0xFFC00000) == 0xB9000000:
        rt = insn & 0x1F; rn = (insn >> 5) & 0x1F; imm = ((insn >> 10) & 0xFFF) * 4
        return f"STR W{rt}, [X{rn}, #0x{imm:x}]"
    if (insn & 0xFC000000) == 0x94000000:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25): imm26 -= (1 << 26)
        return f"BL 0x{addr + (imm26 << 2):x}"
    if (insn & 0xFC000000) == 0x14000000:
        imm26 = insn & 0x3FFFFFF
        if imm26 & (1 << 25): imm26 -= (1 << 26)
        return f"B 0x{addr + (imm26 << 2):x}"
    if (insn & 0xFF000000) == 0x54000000:
        imm19 = (insn >> 5) & 0x7FFFF
        if imm19 & (1 << 18): imm19 -= (1 << 19)
        cond = insn & 0xF
        conds = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV']
        return f"B.{conds[cond]} 0x{addr + (imm19 << 2):x}"
    if (insn & 0xFFE0FFE0) == 0xAA0003E0:
        rd = insn & 0x1F; rm = (insn >> 16) & 0x1F
        return f"MOV X{rd}, X{rm}"
    if insn == 0xD65F03C0:
        return "RET"
    if (insn & 0xFFFFFC1F) == 0xD63F0000:
        rn = (insn >> 5) & 0x1F
        return f"BLR X{rn}"
    if (insn & 0xFFFFFC1F) == 0xD61F0000:
        rn = (insn >> 5) & 0x1F
        return f"BR X{rn}"
    if (insn & 0xFF800000) == 0xD2800000:
        rd = insn & 0x1F; imm = (insn >> 5) & 0xFFFF; hw = (insn >> 21) & 0x3
        return f"MOV X{rd}, #0x{imm << (hw*16):x}"
    if (insn & 0xFF800000) == 0x52800000:
        rd = insn & 0x1F; imm = (insn >> 5) & 0xFFFF; hw = (insn >> 21) & 0x3
        return f"MOV W{rd}, #0x{imm << (hw*16):x}"
    if (insn & 0xFFC0001F) == 0xF100001F:
        rn = (insn >> 5) & 0x1F; imm = (insn >> 10) & 0xFFF
        return f"CMP X{rn}, #0x{imm:x}"
    if (insn & 0xFFC0001F) == 0x6B00001F:
        rn = (insn >> 5) & 0x1F; rm = (insn >> 16) & 0x1F
        return f"CMP W{rn}, W{rm}"
    if (insn & 0xFFE0FC00) == 0xEB00001F:
        rn = (insn >> 5) & 0x1F; rm = (insn >> 16) & 0x1F
        return f"CMP X{rn}, X{rm}"
    if (insn & 0x7F800000) == 0x6B000000 and (insn & 0x1F) != 0x1F:
        rd = insn & 0x1F; rn = (insn >> 5) & 0x1F; rm = (insn >> 16) & 0x1F
        return f"SUBS W{rd}, W{rn}, W{rm}"
    if (insn & 0xFFC00000) == 0x8B000000:
        rd = insn & 0x1F; rn = (insn >> 5) & 0x1F; rm = (insn >> 16) & 0x1F
        return f"ADD X{rd}, X{rn}, X{rm}"
    return f".word 0x{insn:08x}"

with open(BG3_BIN, 'rb') as f:
    f.seek(FAT_OFFSET)
    data = f.read(0x8398000)

# === 1. Find all callers of NetMessageFactory::GetMessage (0x1063d5998) ===
print("=== Callers of NetMessageFactory::GetMessage (0x1063d5998) ===\n")
target_fn = 0x1063d5998
callers = []
for i in range(0, len(data) - 4, 4):
    insn = struct.unpack_from('<I', data, i)[0]
    if (insn & 0xFC000000) != 0x94000000:
        continue
    imm26 = insn & 0x3FFFFFF
    if imm26 & (1 << 25):
        imm26 -= (1 << 26)
    pc = BASE + i
    target = pc + (imm26 << 2)
    if target == target_fn:
        callers.append(pc)

print(f"Found {len(callers)} callers\n")
for c in callers[:15]:
    print(f"  BL at 0x{c:x}")

# === 2. Disassemble around ProtocolList iteration site ===
# The big site at 0x104862b0c - trace the FULL function
print("\n\n=== Full function containing ProtocolList iteration (0x104862b0c area) ===")
# Find prologue by scanning back
target_area = 0x104862b0c - BASE
found_prologue = None
for i in range(target_area, max(target_area - 0x2000, 0), -4):
    insn = struct.unpack_from('<I', data, i)[0]
    # STP X29, X30, [SP, #imm]!  (pre-index)
    if (insn & 0xFFC003E0) == 0xA98003E0:
        rt2 = (insn >> 10) & 0x1F
        rt = insn & 0x1F
        if rt == 29 and rt2 == 30:
            found_prologue = i
            break

if found_prologue:
    prologue_addr = BASE + found_prologue
    print(f"Function prologue at 0x{prologue_addr:x} (delta={target_area - found_prologue} bytes)\n")

    # Disassemble the first 200 instructions of the function
    for j in range(0, min(800, len(data) - found_prologue), 4):
        off = found_prologue + j
        raw = struct.unpack_from('<I', data, off)[0]
        addr = BASE + off
        d = decode(raw, addr)
        marker = ""

        # Highlight key patterns
        if "+0x2e0" in d.lower():
            marker = " *** PROTOCOLLIST.data"
        elif "+0x2f0" in d.lower():
            marker = " *** PROTOCOLLIST.capacity"
        elif "+0x300" in d.lower():
            marker = " *** PROTOCOLLIST.size"
        elif "+0x310" in d.lower():
            marker = " *** PROTOCOLMAP"
        elif "+0x1f8" in d.lower():
            marker = " *** NETMSGFACTORY"
        elif "+0xa8" in d.lower():
            marker = " [GameServer]"
        elif "BLR" in d:
            marker = " *** INDIRECT CALL (vtable?)"
        elif "+0x8b8" in d.lower():
            marker = " [EocServer singleton]"
        elif "0x1063d5998" in d:
            marker = " *** GetMessage()"

        print(f"  0x{addr:x}: {d}{marker}")

        # Stop at RET
        if d == "RET":
            print("  --- function end ---")
            break
else:
    print("Could not find prologue!")

# === 3. Disassemble NetMessageFactory::GetMessage itself ===
print("\n\n=== NetMessageFactory::GetMessage at 0x1063d5998 ===")
fn_off = target_fn - BASE
for j in range(0, 200, 4):
    off = fn_off + j
    if off + 4 > len(data):
        break
    raw = struct.unpack_from('<I', data, off)[0]
    addr = BASE + off
    d = decode(raw, addr)
    marker = ""
    if "BLR" in d:
        marker = " *** INDIRECT CALL"
    print(f"  0x{addr:x}: {d}{marker}")
    if d == "RET":
        print("  --- function end ---")
        break
