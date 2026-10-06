"""Pin OFFSET_ENTITYWORLD_IN_EOCCLIENT (src/entity/entity_system.c).

ecl::EocClient::ConfigureECS opens with `mov x19,x0; ldr x0,[x0,#off];
bl ecl::RegisterComponents(ecs::EntityWorld&)`, so the immediate of that load
is the EocClient field holding the client ecs::EntityWorld*. The binary check
reads it from the installed game (skipped when absent, e.g. CI); the static
check pins the define everywhere.
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from bg3se_harness.config import BG3_EXEC

REPO = Path(__file__).resolve().parents[2]
ENTITY_SYSTEM_C = REPO / "src/entity/entity_system.c"
CONFIGURE_ECS = "__ZN3ecl9EocClient12ConfigureECSEv"
REGISTER_COMPONENTS = "__ZN3ecl18RegisterComponentsERN3ecs11EntityWorldE"
INSN_RE = re.compile(r"^\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+\t?(\S+)\s*(.*)$")


def _define() -> int:
    m = re.search(r"^#define OFFSET_ENTITYWORLD_IN_EOCCLIENT (0x[0-9a-fA-F]+)\s*$",
                  ENTITY_SYSTEM_C.read_text(encoding="utf-8"), re.M)
    assert m, "OFFSET_ENTITYWORLD_IN_EOCCLIENT define not found"
    return int(m.group(1), 16)


def test_define_is_the_ghidra_value():
    assert _define() == 0x1A0


def test_configure_ecs_loads_the_world_at_the_define(tmp_path):
    if not BG3_EXEC.exists():
        pytest.skip("BG3 binary not installed")
    for tool in ("lipo", "nm", "objdump"):
        if shutil.which(tool) is None:
            pytest.skip(f"`{tool}` not on PATH")
    thin = tmp_path / "bg3.arm64"
    subprocess.run(["lipo", "-thin", "arm64", "-output", str(thin), str(BG3_EXEC)],
                   check=True, capture_output=True, timeout=300)
    nm = subprocess.run(["nm", str(thin)], capture_output=True, text=True, timeout=300)
    syms = {}
    for line in nm.stdout.splitlines():
        parts = line.split(maxsplit=2)
        if len(parts) == 3 and parts[2] in (CONFIGURE_ECS, REGISTER_COMPONENTS):
            syms[parts[2]] = int(parts[0], 16)
    assert CONFIGURE_ECS in syms and REGISTER_COMPONENTS in syms, sorted(syms)

    start = syms[CONFIGURE_ECS]
    out = subprocess.run(["objdump", "-d", f"--start-address=0x{start:x}",
                          f"--stop-address=0x{start + 0x60:x}", str(thin)],
                         capture_output=True, text=True, timeout=300).stdout
    insns = [(int(m.group(1), 16), m.group(2), m.group(3))
             for m in map(INSN_RE.match, out.splitlines()) if m]
    call = next(i for i, (_, mn, ops) in enumerate(insns)
                if mn == "bl" and int(ops.split()[0], 16) == syms[REGISTER_COMPONENTS])
    addr, mn, ops = insns[call - 1]
    m = re.match(r"x0, \[x0, #(0x[0-9a-f]+)\]", ops)
    assert mn == "ldr" and m, f"{addr:#x}: {mn} {ops}"
    assert int(m.group(1), 16) == _define(), (
        f"ConfigureECS passes EocClient+{m.group(1)} to RegisterComponents "
        f"(@{addr:#x}); the define is {_define():#x}")
