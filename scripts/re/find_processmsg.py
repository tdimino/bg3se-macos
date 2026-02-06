"""Find Protocol::ProcessMsg by looking for virtual dispatch patterns near ProtocolList access.

Strategy: Find functions that:
1. Load ProtocolList (+0x2E0) from GameServer
2. Iterate through protocol entries
3. Call virtual methods on each protocol (BLR through vtable)

Also find the message receive/dispatch function by looking for patterns
where message data is decoded and forwarded to protocols.
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
    if (insn & 0xFFE0FC1F) == 0xEB00001F:
        rn = (insn >> 5) & 0x1F; rm = (insn >> 16) & 0x1F
        return f"CMP X{rn}, X{rm}"
    if (insn & 0xFFE0FC1F) == 0x6B00001F:
        rn = (insn >> 5) & 0x1F; rm = (insn >> 16) & 0x1F
        return f"CMP W{rn}, W{rm}"
    if (insn & 0xFFC00000) == 0x8B000000:
        rd = insn & 0x1F; rn = (insn >> 5) & 0x1F; rm = (insn >> 16) & 0x1F
        return f"ADD X{rd}, X{rn}, X{rm}"
    if (insn & 0xFF200000) == 0xEB200000:
        rd = insn & 0x1F; rn = (insn >> 5) & 0x1F; rm = (insn >> 16) & 0x1F
        shift_type = (insn >> 22) & 0x3
        shift_amt = (insn >> 10) & 0x3F
        return f"SUBS X{rd}, X{rn}, X{rm} (shift={shift_amt})"
    return f".word 0x{insn:08x}"

with open(BG3_BIN, 'rb') as f:
    f.seek(FAT_OFFSET)
    data = f.read(0x8398000)

# === Find functions that access BOTH ProtocolList (+0x2E0) AND have BLR ===
# This pattern indicates protocol dispatch: iterate protocols, call virtual method

print("=== Scanning for ProtocolList dispatch patterns ===\n")
print("Looking for functions that load ProtocolList.data (+0x2E0) near BLR calls...\n")

# Track all +0x2E0 accesses with their surrounding BLR calls
protocollist_sites = []
for i in range(0, len(data) - 4, 4):
    insn = struct.unpack_from('<I', data, i)[0]
    # LDR Xrt, [Xrn, #0x2E0]
    if (insn & 0xFFC00000) == 0xF9400000:
        imm = ((insn >> 10) & 0xFFF) * 8
        if imm == 0x2E0:
            addr = BASE + i
            # Check if there's a BLR within ±40 instructions
            has_blr = False
            blr_addr = 0
            for j in range(-40, 40):
                check_off = i + j * 4
                if check_off < 0 or check_off + 4 > len(data):
                    continue
                check_insn = struct.unpack_from('<I', data, check_off)[0]
                if (check_insn & 0xFFFFFC1F) == 0xD63F0000:  # BLR
                    has_blr = True
                    blr_addr = BASE + check_off
                    break
            protocollist_sites.append((addr, has_blr, blr_addr))

print(f"Found {len(protocollist_sites)} ProtocolList (+0x2E0) accesses:")
for addr, has_blr, blr_addr in protocollist_sites:
    blr_info = f"  BLR at 0x{blr_addr:x}" if has_blr else "  (no BLR nearby)"
    print(f"  0x{addr:x}{blr_info}")

# === Disassemble the most promising sites (those with BLR = dispatch) ===
for addr, has_blr, blr_addr in protocollist_sites:
    if not has_blr:
        continue
    print(f"\n\n=== Dispatch site at 0x{addr:x} (BLR at 0x{blr_addr:x}) ===")
    # Find prologue
    file_off = addr - BASE
    prologue_off = None
    for k in range(file_off, max(file_off - 0x1000, 0), -4):
        p_insn = struct.unpack_from('<I', data, k)[0]
        # Various STP patterns with X30
        if (p_insn & 0x7FC003E0) == 0x298003E0:  # STP with pre-index to SP
            rt2 = (p_insn >> 10) & 0x1F
            if rt2 == 30:
                prologue_off = k
                break
        # SUB SP, SP (stack frame setup)
        if (p_insn & 0xFFC003FF) == 0xD10003FF:
            prologue_off = k
            break

    start_off = prologue_off if prologue_off else (addr - BASE - 80)
    end_off = min(start_off + 400, len(data) - 4)

    for j in range(start_off, end_off, 4):
        raw = struct.unpack_from('<I', data, j)[0]
        a = BASE + j
        d = decode(raw, a)
        marker = ""
        if "+0x2e0" in d.lower(): marker = " *** PROTOCOLLIST.data"
        elif "+0x2f0" in d.lower(): marker = " *** PROTOCOLLIST.capacity"
        elif "+0x300" in d.lower(): marker = " *** PROTOCOLLIST.size"
        elif "+0x310" in d.lower(): marker = " *** PROTOCOLMAP"
        elif "+0x1f8" in d.lower(): marker = " *** NETMSGFACTORY"
        elif "+0xa8" in d.lower(): marker = " [GameServer]"
        elif "BLR" in d: marker = " *** VIRTUAL DISPATCH"
        elif "+0x8b8" in d.lower(): marker = " [EocServer singleton]"
        elif "0x1063d5998" in d: marker = " *** GetMessage()"
        if a == addr: marker += " <<< PROTOCOLLIST ACCESS"
        if a == blr_addr: marker += " <<< BLR TARGET"

        print(f"  0x{a:x}: {d}{marker}")
        if d == "RET":
            break
