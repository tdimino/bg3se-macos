"""Disassemble key functions in BG3 binary around network string references."""
import struct, os

BG3_BIN = os.path.expanduser("~/Library/Application Support/Steam/steamapps/common/Baldurs Gate 3/Baldur's Gate 3.app/Contents/MacOS/Baldur's Gate 3")
FAT_OFFSET = 0xf534000
BASE = 0x100000000

targets = [
    ('GameServer Peer Activate', 0x104abc3ec),
    ('AbstractPeer::Protocols', 0x1010a8648),
]

def decode(insn, addr):
    if (insn & 0x9F000000) == 0x90000000:
        rd = insn & 0x1F
        immlo = (insn >> 29) & 0x3
        immhi = (insn >> 5) & 0x7FFFF
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
    if (insn & 0x7FC00000) == 0x29800000 or (insn & 0xFFC00000) == 0xA9800000:
        rt = insn & 0x1F; rt2 = (insn >> 10) & 0x1F; rn = (insn >> 5) & 0x1F
        imm7 = (insn >> 15) & 0x7F
        if imm7 & 0x40: imm7 -= 128
        sf = (insn >> 31) & 1; scale = 8 if sf else 4
        return f"STP X{rt}, X{rt2}, [X{rn}, #{imm7*scale}]!"
    if (insn & 0xFFC00000) == 0xA9000000:
        rt = insn & 0x1F; rt2 = (insn >> 10) & 0x1F; rn = (insn >> 5) & 0x1F
        imm7 = (insn >> 15) & 0x7F
        if imm7 & 0x40: imm7 -= 128
        return f"STP X{rt}, X{rt2}, [X{rn}, #{imm7*8}]"
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
    if (insn & 0xFF000010) == 0x54000010:
        return f"B.cond ..."
    if (insn & 0xFFE0FC00) == 0xEB00FC00:
        rn = (insn >> 5) & 0x1F; rm = (insn >> 16) & 0x1F
        return f"CMP X{rn}, X{rm}"
    if (insn & 0xFFC0001F) == 0xF100001F:
        rn = (insn >> 5) & 0x1F; imm = (insn >> 10) & 0xFFF
        return f"CMP X{rn}, #0x{imm:x}"
    if (insn & 0xFF800000) == 0xD2800000:
        rd = insn & 0x1F; imm = (insn >> 5) & 0xFFFF; hw = (insn >> 21) & 0x3
        return f"MOV X{rd}, #0x{imm << (hw*16):x}"
    return f".word 0x{insn:08x}"

with open(BG3_BIN, 'rb') as f:
    for name, va in targets:
        slice_off = va - BASE
        fat_off = FAT_OFFSET + slice_off

        # Read 512 bytes before, 1024 after (to capture full function)
        start = fat_off - 512
        f.seek(start)
        chunk = f.read(2048)

        print(f"\n{'='*70}")
        print(f"=== {name} at VA 0x{va:x} ===")
        print(f"{'='*70}")

        chunk_base = va - 512
        for i in range(0, len(chunk), 4):
            raw = struct.unpack_from('<I', chunk, i)[0]
            addr = chunk_base + i
            d = decode(raw, addr)
            marker = " <<<" if addr == va or addr == va + 4 else ""
            # Only print 80 instructions centered on target
            if abs(i - 512) <= 320:
                print(f"  0x{addr:012x}: {d}{marker}")
