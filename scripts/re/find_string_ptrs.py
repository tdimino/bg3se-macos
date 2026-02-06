"""Search data sections for pointers to key strings."""
import struct, os

BG3_BIN = os.path.expanduser("~/Library/Application Support/Steam/steamapps/common/Baldurs Gate 3/Baldur's Gate 3.app/Contents/MacOS/Baldur's Gate 3")

# Segment layout from otool
segments = [
    {'name': '__TEXT',       'vmaddr': 0x100000000, 'vmsize': 0x8398000, 'fileoff': 0, 'filesize': 0x8398000},
    {'name': '__DATA_CONST', 'vmaddr': 0x108398000, 'vmsize': 0x4bc000,  'fileoff': 0x8398000, 'filesize': 0x4bc000},  # ~4.9MB
    {'name': '__DATA',       'vmaddr': 0x108854000, 'vmsize': 0x2a4000,  'fileoff': 0x8854000, 'filesize': 0x11c000},   # ~1.1MB
]

# Target string VAs
target_strings = {
    'GameServer Peer Activate: %d': 0x107cedee2,
    'GameServer Peer Deactivate: %d': 0x107cedf0e,
    'eocnet::PeerActivateMessage': 0x107b987f0,
    'eocnet::NETMSG_PEER_ACTIVATE': 0x107b9880c,
    'net::AbstractPeer::Protocols': 0x107b64331,
    'net::NETMSG_HANDSHAKE': 0x107b982ab,
    'AbstractPeer.cpp': 0x107d53f0f,
}

with open(BG3_BIN, 'rb') as f:
    data = f.read()

print("Searching data sections for pointers to target strings...\n")

for sname, sva in target_strings.items():
    # Pack as 64-bit little-endian pointer
    needle = struct.pack('<Q', sva)

    # Search in __DATA_CONST and __DATA
    for seg in segments[1:]:  # Skip __TEXT
        seg_start = seg['fileoff']
        seg_end = seg_start + seg['filesize']
        seg_data = data[seg_start:seg_end]

        pos = 0
        while True:
            idx = seg_data.find(needle, pos)
            if idx < 0:
                break
            # Must be 8-byte aligned
            file_off = seg_start + idx
            va = seg['vmaddr'] + idx
            print(f"  PTR to '{sname}' (0x{sva:x}) found at VA 0x{va:x} in {seg['name']} (file 0x{file_off:x})")
            pos = idx + 8

# Also search for nearby pointers (the string might be at a slightly different address due to alignment)
print("\n=== Searching for any pointers into the string regions ===")
for region_name, region_start in [('GameServer strings', 0x107cede00), ('NETMSG strings', 0x107b98000)]:
    region_end = region_start + 0x1000
    count = 0
    for seg in segments[1:]:
        seg_start = seg['fileoff']
        seg_end = seg_start + seg['filesize']
        for off in range(seg_start, seg_end - 8, 8):
            val = struct.unpack_from('<Q', data, off)[0]
            if region_start <= val < region_end:
                va = seg['vmaddr'] + (off - seg_start)
                count += 1
                if count <= 20:
                    print(f"  PTR 0x{val:x} at VA 0x{va:x} in {seg['name']} ({region_name})")
    if count == 0:
        print(f"  No pointers to {region_name} range found in data sections")
    elif count > 20:
        print(f"  ... and {count - 20} more")
