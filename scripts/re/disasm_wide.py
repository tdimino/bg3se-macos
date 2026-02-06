"""Disassemble wider range around GameServer Peer Activate to find function start."""
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
    if (insn & 0xFF800000) == 0xD2800000:
        rd = insn & 0x1F; imm = (insn >> 5) & 0xFFFF; hw = (insn >> 21) & 0x3
        return f"MOV X{rd}, #0x{imm << (hw*16):x}"
    if (insn & 0xFFC0001F) == 0xF100001F:
        rn = (insn >> 5) & 0x1F; imm = (insn >> 10) & 0xFFF
        return f"CMP X{rn}, #0x{imm:x}"
    return f".word 0x{insn:08x}"

# Read 4KB before the target to find function start
target = 0x104abc3ec
with open(BG3_BIN, 'rb') as f:
    slice_off = target - BASE - 4096
    f.seek(FAT_OFFSET + slice_off)
    chunk = f.read(8192)

# Find function prologues (STP X29, X30 / SUB SP)
prologues = []
base_va = target - 4096
for i in range(0, len(chunk), 4):
    raw = struct.unpack_from('<I', chunk, i)[0]
    addr = base_va + i
    # STP X29, X30, [SP, #imm]! (pre-indexed store pair, saving frame pointer + LR)
    # Encoding: x010100110 imm7 11110 11111 11101
    if (raw & 0xFFE003FF) == 0xA98003FD or (raw & 0xFFE003FF) == 0xA98003E0:
        prologues.append(addr)
    # Also match STP Xn, X30, [SP, #imm]!
    if (raw & 0xFFC003E0) == 0xA98003E0:
        rt2 = (raw >> 10) & 0x1F
        if rt2 == 30:  # X30 = LR
            prologues.append(addr)

# Find the prologue closest to but before our target
fn_start = None
for p in reversed(prologues):
    if p < target:
        fn_start = p
        break

if fn_start:
    print(f"Function prologue at 0x{fn_start:x} (target 0x{target:x}, delta={target-fn_start} bytes)")
    # Print from fn_start to target + 200
    start_idx = fn_start - base_va
    end_idx = min(start_idx + (target - fn_start) + 400, len(chunk))
    for i in range(start_idx, end_idx, 4):
        raw = struct.unpack_from('<I', chunk, i)[0]
        addr = base_va + i
        d = decode(raw, addr)
        marker = ""
        if addr == target: marker = " <<< GameServer Peer Activate"
        if addr == target + 4: marker = " <<< ADD #0xEE2"
        # Annotate interesting offsets
        if "X24, #0x" in d or "X25, #0x" in d:
            marker += " *** FIELD ACCESS"
        if "0x10898" in d:
            marker += " *** SINGLETON"
        print(f"  0x{addr:x}: {d}{marker}")
else:
    print("No function prologue found")
    # Still print around target
    for i in range(3800, min(4600, len(chunk)), 4):
        raw = struct.unpack_from('<I', chunk, i)[0]
        addr = base_va + i
        print(f"  0x{addr:x}: {decode(raw, addr)}")
