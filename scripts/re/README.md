# Reverse Engineering Scripts

ARM64 binary analysis tools for the BG3 macOS binary. These scripts work directly on the fat Mach-O binary without requiring Ghidra.

## Prerequisites

- Python 3 (no external dependencies)
- BG3 macOS binary at: `~/Library/Application Support/Steam/steamapps/common/Baldurs Gate 3/Baldur's Gate 3.app/Contents/MacOS/Baldur's Gate 3`

## Constants

All scripts use these constants for the current BG3 build:

| Constant | Value | Description |
|----------|-------|-------------|
| `FAT_OFFSET` | `0xf534000` | ARM64 slice offset in the fat binary |
| `BASE` | `0x100000000` | ARM64 virtual address base |
| `TEXT_SIZE` | `0x8398000` | Size of __TEXT segment |

## Scripts

### `find_adrp_refs.py`

Search for all ADRP+ADD/LDR instruction pairs that reference target strings. This is the primary tool for finding code that references known strings.

**Usage:** `python3 find_adrp_refs.py`

**Targets:** Configurable dict at top of file. Default targets include:
- `GameServer Peer Activate` (page 0x107ced000, offset 0xee2)
- `GameServer Peer Deactivate` (page 0x107ced000, offset 0xf0e)
- `PeerActivateMessage` (page 0x107b98000, offset 0x7f0)
- `NETMSG_PEER_ACTIVATE` (page 0x107b98000, offset 0x80c)
- `AbstractPeer::Protocols` (page 0x107b64000, offset 0x331)
- `NETMSG_HANDSHAKE` (page 0x107b98000, offset 0x2ab)

**How it works:** Scans the entire __TEXT segment for ADRP instructions that compute a target page address, then checks the next 7 instructions for an ADD or LDR with the matching page offset.

### `find_adrp_refs_v2.py`

Earlier version of the ADRP reference finder. Less comprehensive but useful as reference.

### `disasm_wide.py`

Disassemble a wide range (4KB before, 4KB after) around a target address to find function prologues and understand function boundaries.

**Usage:** `python3 disasm_wide.py`

**Target:** `0x104abc3ec` (GameServer Peer Activate string reference)

**Features:**
- Searches for STP X29, X30 function prologues
- Annotates field accesses and singleton references
- Custom ARM64 instruction decoder (ADRP, ADD, SUB, LDR, STR, BL, B, B.cond, MOV, CMP, RET)

### `disasm_targets.py`

Disassemble centered regions around multiple target addresses. Useful for comparing code patterns at different string references.

**Usage:** `python3 disasm_targets.py`

**Targets:** GameServer Peer Activate and AbstractPeer::Protocols.

### `find_dispatch.py`

Find the Protocol::ProcessMsg dispatch by analyzing ProtocolList iteration patterns. Identifies all callers of `NetMessageFactory::GetMessage` (0x1063d5998), disassembles the ProtocolList iteration function, and analyzes virtual dispatch patterns.

**Usage:** `python3 find_dispatch.py`

**Outputs:**
- All 524 callers of GetMessage
- Full function disassembly of ProtocolList iteration site
- GetMessage function disassembly with vtable dispatch annotation

### `find_processmsg.py`

Find functions that access ProtocolList (+0x2E0) near BLR (virtual call) instructions — indicators of protocol dispatch loops. Scans for all `LDR X, [X, #0x2E0]` accesses and checks for BLR within ±40 instructions.

**Usage:** `python3 find_processmsg.py`

**Outputs:**
- All ProtocolList access sites with nearby BLR presence
- Full disassembly of dispatch sites (BLR + ProtocolList access)

### `find_string_ptrs.py`

Search data sections (__DATA_CONST, __DATA) for 64-bit pointers to target string addresses. Useful when ADRP patterns don't find code references (e.g., vtable entries, static initializers).

**Usage:** `python3 find_string_ptrs.py`

## Adding New Targets

To analyze a new string reference:

1. Find the string's virtual address: `strings -arch arm64 -t x BG3_BINARY | grep "your string"`
2. Add the (page, offset) tuple to `find_adrp_refs.py`
3. Run to get code addresses
4. Use `disasm_wide.py` or `disasm_targets.py` to analyze the code

## ARM64 Instruction Patterns

### ADRP+ADD (string/data reference)
```
ADRP Xn, page    ; Load page address (4KB aligned)
ADD  Xn, Xn, #off ; Add page offset to get full address
```

### Function prologue
```
STP X29, X30, [SP, #-imm]!  ; Save frame pointer and link register
ADD X29, SP, #offset         ; Set up frame pointer
```

### EocServer singleton access
```
ADRP X8, 0x10898e000
LDR  X8, [X8, #0x8b8]    ; X8 = EocServer* (from 0x10898e8b8)
```
