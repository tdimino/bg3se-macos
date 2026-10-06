"""eoc::CanTravelComponent's declared fields match the engine's own save routine.

ls::savegame::Framework::Ops<eoc::CanTravelComponent, esv::capabilities::Loader>::Save
fetches the component with GetComponent and then loads each field from x0. Every
declared property must sit at one of those load offsets with the load's width.
The binary check reads the installed game (skipped when absent, e.g. CI).
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from bg3se_harness.config import BG3_EXEC

REPO = Path(__file__).resolve().parents[2]
COMPONENT_OFFSETS_H = REPO / "src/entity/component_offsets.h"
SAVE = ("__ZN2ls8savegame9Framework3OpsIN3eoc18CanTravelComponentEN3esv12capabilities"
        "6LoaderEE4SaveERNS_5model6WriterERKNS_4SpanIKNS_2IDIN3ecs18EntityHandleTraitsEEEEE")
GET_COMPONENT = ("__ZN3ecs11EntityWorld12GetComponentIKN3eoc18CanTravelComponentELb1EEEPT_"
                 "N2ls2IDINS_18EntityHandleTraitsEEENSt3__117integral_constantIbLb0EEE")
INSN_RE = re.compile(r"^\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+\t?(\S+)\s*(.*)$")
LOAD_RE = re.compile(r"[wx]\d+, \[x0(?:, #(0x[0-9a-f]+|\d+))?\]")
LOAD_WIDTH = {"ldrb": 1, "ldrsb": 1, "ldrh": 2, "ldrsh": 2, "ldr": None}
FIELD_WIDTH = {"BOOL": 1, "UINT8": 1, "INT8": 1, "UINT16": 2, "INT16": 2,
               "UINT32": 4, "INT32": 4, "FLOAT": 4, "UINT64": 8, "INT64": 8}


def _declared_fields():
    text = COMPONENT_OFFSETS_H.read_text(encoding="utf-8")
    block = re.search(r"g_eoc_CanTravelComponent_Properties\[\] = \{(.*?)\};", text, re.S)
    assert block, "CanTravelComponent properties not found"
    fields = re.findall(r'\{\s*"(\w+)",\s*(0x[0-9a-fA-F]+),\s*FIELD_TYPE_(\w+)', block.group(1))
    assert fields, "no CanTravelComponent properties parsed"
    return [(name, int(off, 16), FIELD_WIDTH[ftype]) for name, off, ftype in fields]


def _save_loads(tmp_path):
    thin = tmp_path / "bg3.arm64"
    subprocess.run(["lipo", "-thin", "arm64", "-output", str(thin), str(BG3_EXEC)],
                   check=True, capture_output=True, timeout=300)
    nm = subprocess.run(["nm", str(thin)], capture_output=True, text=True, timeout=300)
    syms = {}
    for line in nm.stdout.splitlines():
        parts = line.split(maxsplit=2)
        if len(parts) == 3 and parts[2] in (SAVE, GET_COMPONENT):
            syms[parts[2]] = int(parts[0], 16)
    assert SAVE in syms and GET_COMPONENT in syms, sorted(syms)

    start = syms[SAVE]
    out = subprocess.run(["objdump", "-d", f"--start-address=0x{start:x}",
                          f"--stop-address=0x{start + 0x800:x}", str(thin)],
                         capture_output=True, text=True, timeout=300).stdout
    insns = [(m.group(2), m.group(3))
             for m in map(INSN_RE.match, out.splitlines()) if m]
    call = next(i for i, (mn, ops) in enumerate(insns)
                if mn == "bl" and int(ops.split()[0], 16) == syms[GET_COMPONENT])
    loads = {}
    for mn, ops in insns[call + 1:]:
        m = LOAD_RE.match(ops)
        if mn not in LOAD_WIDTH or not m:
            break
        width = LOAD_WIDTH[mn] or (8 if ops.startswith("x") else 4)
        loads[int(m.group(1) or "0", 0)] = width
    assert loads, "no loads from x0 after GetComponent<CanTravelComponent>"
    return loads


def test_declared_fields_match_the_save_routine(tmp_path):
    if not BG3_EXEC.exists():
        pytest.skip("BG3 binary not installed")
    for tool in ("lipo", "nm", "objdump"):
        if shutil.which(tool) is None:
            pytest.skip(f"`{tool}` not on PATH")
    loads = _save_loads(tmp_path)
    for name, offset, width in _declared_fields():
        assert offset in loads, f"{name} @0x{offset:x}: Save loads {sorted(loads)}"
        assert width == loads[offset], (
            f"{name} @0x{offset:x} is {width} bytes; Save loads {loads[offset]}")
