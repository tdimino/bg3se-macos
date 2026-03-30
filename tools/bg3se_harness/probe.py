"""Memory inspection via Ext.Debug API.

    bg3se-harness probe 0x10898e8b8                    # hex dump
    bg3se-harness probe 0x10898e8b8 --range 256        # struct probe
    bg3se-harness probe 0x10898e8b8 --classify         # pointer classification
"""

import json

from .console import Console

LUA_HEXDUMP = '''
local addr = {address}
local size = {size}
local result = Ext.Debug.HexDump(addr, size)
if result then
    _P(result)
else
    _P(Ext.Json.Stringify({{error = "HexDump failed at " .. string.format("0x%x", addr)}}))
end
'''

LUA_PROBE_STRUCT = '''
local addr = {address}
local start_off = {start}
local end_off = {end_off}
local stride = {stride}
local result = Ext.Debug.ProbeStruct(addr, start_off, end_off, stride)
if result then
    _P(Ext.Json.Stringify(result, {{Beautify = true}}))
else
    _P(Ext.Json.Stringify({{error = "ProbeStruct failed"}}))
end
'''

LUA_CLASSIFY = '''
local addr = {address}
local result = Ext.Debug.ClassifyPointer(addr)
if result then
    _P(Ext.Json.Stringify(result, {{Beautify = true}}))
else
    _P(Ext.Json.Stringify({{error = "ClassifyPointer failed"}}))
end
'''


def hexdump(address, size=64):
    """Hex dump at address. Returns raw string."""
    addr_int = int(address, 0) if isinstance(address, str) else address
    with Console() as c:
        return c.send_lua(LUA_HEXDUMP.format(address=addr_int, size=size))


def probe_struct(address, start=0, end_off=256, stride=8):
    """Probe struct fields at address. Returns JSON string."""
    addr_int = int(address, 0) if isinstance(address, str) else address
    with Console() as c:
        return c.send_lua(LUA_PROBE_STRUCT.format(
            address=addr_int, start=start, end_off=end_off, stride=stride
        ))


def classify_pointer(address):
    """Classify a pointer. Returns JSON string."""
    addr_int = int(address, 0) if isinstance(address, str) else address
    with Console() as c:
        return c.send_lua(LUA_CLASSIFY.format(address=addr_int))


def cmd_probe(args):
    """CLI handler."""
    address = args.address
    try:
        if getattr(args, "classify", False):
            output = classify_pointer(address)
        elif getattr(args, "range", None):
            stride = getattr(args, "stride", 8) or 8
            output = probe_struct(address, end_off=args.range, stride=stride)
        else:
            size = getattr(args, "size", 64) or 64
            output = hexdump(address, size=size)
        print(output)
        return 0
    except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
        print(json.dumps({"error": f"Socket connection failed: {e}"}))
        return 1
