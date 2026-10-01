"""Offline guards for macOS ARM64 PhysXScene virtual dispatch.

The installed game check is deliberately read-only and skips when BG3 is not
present.  It derives the arm64 slice offset from the universal Mach-O header,
maps the nm-located PhysXScene vtable VA through the thin slice's segment
commands, and joins each raw vtable target to its demangled nm symbol.
"""

import re
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from bg3se_harness.config import BG3_EXEC


REPO_ROOT = Path(__file__).resolve().parents[2]
LEVEL_MANAGER_C = REPO_ROOT / "src/level/level_manager.c"
LUA_LEVEL_C = REPO_ROOT / "src/lua/lua_level.c"
LUA_EXT_C = REPO_ROOT / "src/lua/lua_ext.c"

CPU_TYPE_ARM64 = 0x0100000C
LC_SEGMENT_64 = 0x19
PHYSX_VTABLE_SYMBOL = "__ZTVN3phx10PhysXSceneE"

EXPECTED_DISPATCH = {
    "PHYSICS_VMT_RAYCAST_CLOSEST": "RaycastClosest",
    "PHYSICS_VMT_RAYCAST_ALL": "RaycastAll",
    "PHYSICS_VMT_RAYCAST_ANY": "RaycastAny",
    "PHYSICS_VMT_SWEEP_SPHERE_CLOSEST": "SweepSphereClosest",
    "PHYSICS_VMT_SWEEP_CAPSULE_CLOSEST": "SweepCapsuleClosest",
    "PHYSICS_VMT_SWEEP_BOX_CLOSEST": "SweepBoxClosest",
    "PHYSICS_VMT_SWEEP_CYLINDER_CLOSEST": "SweepCylinderClosest",
    "PHYSICS_VMT_SWEEP_SPHERE_ALL": "SweepSphereAll",
    "PHYSICS_VMT_SWEEP_CAPSULE_ALL": "SweepCapsuleAll",
    "PHYSICS_VMT_SWEEP_BOX_ALL": "SweepBoxAll",
    "PHYSICS_VMT_SWEEP_CYLINDER_ALL": "SweepCylinderAll",
    "PHYSICS_VMT_SWEEP_SHAPE_ALL": "SweepShapeAll",
    "PHYSICS_VMT_TEST_BOX": "TestBox",
    "PHYSICS_VMT_TEST_SPHERE": "TestSphere",
}

EXPECTED_INDICES = {
    "PHYSICS_VMT_RAYCAST_CLOSEST": 8,
    "PHYSICS_VMT_RAYCAST_ALL": 9,
    "PHYSICS_VMT_RAYCAST_ANY": 10,
    "PHYSICS_VMT_SWEEP_SPHERE_CLOSEST": 11,
    "PHYSICS_VMT_SWEEP_CAPSULE_CLOSEST": 12,
    "PHYSICS_VMT_SWEEP_BOX_CLOSEST": 13,
    "PHYSICS_VMT_SWEEP_CYLINDER_CLOSEST": 14,
    "PHYSICS_VMT_SWEEP_SPHERE_ALL": 15,
    "PHYSICS_VMT_SWEEP_CAPSULE_ALL": 16,
    "PHYSICS_VMT_SWEEP_BOX_ALL": 17,
    "PHYSICS_VMT_SWEEP_CYLINDER_ALL": 18,
    "PHYSICS_VMT_SWEEP_SHAPE_ALL": 19,
    "PHYSICS_VMT_TEST_BOX": 20,
    "PHYSICS_VMT_TEST_SPHERE": 24,
}


def _parse_physics_indices() -> dict[str, int]:
    constants = {}
    for name, value in re.findall(
            r"^#define\s+(PHYSICS_VMT_\w+)\s+(\d+)\b",
            LEVEL_MANAGER_C.read_text(), re.MULTILINE):
        constants[name] = int(value)
    return constants


def _arm64_fat_slice(binary: Path) -> tuple[int, int]:
    """Return (offset, size) for arm64 by parsing the universal header."""
    with binary.open("rb") as stream:
        magic = stream.read(4)
        formats = {
            b"\xca\xfe\xba\xbe": (">", False),
            b"\xbe\xba\xfe\xca": ("<", False),
            b"\xca\xfe\xba\xbf": (">", True),
            b"\xbf\xba\xfe\xca": ("<", True),
        }
        if magic not in formats:
            pytest.skip("installed BG3 binary is not a universal Mach-O")

        endian, is_64 = formats[magic]
        count_raw = stream.read(4)
        assert len(count_raw) == 4, "truncated Mach-O fat header"
        count = struct.unpack(f"{endian}I", count_raw)[0]
        arch_format = f"{endian}iiQQII" if is_64 else f"{endian}iiIII"
        arch_size = struct.calcsize(arch_format)

        for _ in range(count):
            entry = stream.read(arch_size)
            assert len(entry) == arch_size, "truncated Mach-O fat arch table"
            fields = struct.unpack(arch_format, entry)
            cpu_type = fields[0] & 0xFFFFFFFF
            if is_64:
                offset, size = fields[2], fields[3]
            else:
                offset, size = fields[2], fields[3]
            if cpu_type == CPU_TYPE_ARM64:
                return offset, size

    pytest.skip("installed BG3 universal binary has no arm64 slice")


def _arm64_segments(binary: Path, slice_offset: int):
    """Parse LC_SEGMENT_64 mappings from the thin arm64 slice."""
    with binary.open("rb") as stream:
        stream.seek(slice_offset)
        header = stream.read(32)
        assert len(header) == 32, "truncated arm64 Mach-O header"
        magic, cpu_type, _subtype, _filetype, command_count, _size, _flags, _reserved = (
            struct.unpack("<IiiIIIII", header)
        )
        assert magic == 0xFEEDFACF, f"unexpected arm64 Mach-O magic {magic:#x}"
        assert cpu_type & 0xFFFFFFFF == CPU_TYPE_ARM64

        segments = []
        for _ in range(command_count):
            command_start = stream.tell()
            command_header = stream.read(8)
            assert len(command_header) == 8, "truncated Mach-O load command"
            command, command_size = struct.unpack("<II", command_header)
            assert command_size >= 8, f"invalid Mach-O command size {command_size}"
            stream.seek(command_start)
            command_data = stream.read(command_size)
            assert len(command_data) == command_size, "truncated Mach-O command"

            if command == LC_SEGMENT_64:
                fields = struct.unpack("<II16sQQQQiiII", command_data[:72])
                segments.append({
                    "name": fields[2].rstrip(b"\0").decode("ascii"),
                    "vmaddr": fields[3],
                    "vmsize": fields[4],
                    "fileoff": fields[5],
                    "filesize": fields[6],
                })

        return segments


def _va_to_file_offset(va: int, slice_offset: int, segments) -> int:
    for segment in segments:
        start = segment["vmaddr"]
        end = start + segment["filesize"]
        if start <= va < end:
            return slice_offset + segment["fileoff"] + (va - start)
    raise AssertionError(f"VA {va:#x} is not backed by a Mach-O segment")


def _nm_symbols(binary: Path):
    result = subprocess.run(
        ["nm", "-arch", "arm64", "-n", str(binary)],
        capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        pytest.skip(f"nm could not inspect installed BG3: {result.stderr[:200]}")

    by_address: dict[int, list[str]] = {}
    for line in result.stdout.splitlines():
        match = re.match(r"^([0-9a-fA-F]{16})\s+\S\s+(\S.*)$", line)
        if match:
            by_address.setdefault(int(match.group(1), 16), []).append(line)
    return by_address


def _demangle_symbol_lines(lines: list[str]) -> list[str]:
    result = subprocess.run(
        ["c++filt"], input="\n".join(lines), capture_output=True,
        text=True, timeout=60,
    )
    assert result.returncode == 0, f"c++filt failed: {result.stderr[:200]}"
    return result.stdout.splitlines()


def _function_body(source: str, name: str) -> str:
    definition = re.search(
        rf"\b(?:static\s+int|bool)\s+{re.escape(name)}\s*\([^)]*\)\s*\{{",
        source,
    )
    assert definition, f"{name} definition missing"
    start = definition.end() - 1
    depth = 0
    for position in range(start, len(source)):
        if source[position] == "{":
            depth += 1
        elif source[position] == "}":
            depth -= 1
            if depth == 0:
                return source[start + 1:position]
    raise AssertionError(f"{name} has no closing brace")


def test_physics_vmt_constants_match_audited_indices():
    assert _parse_physics_indices() == EXPECTED_INDICES


def test_quarantined_raycast_bindings_warn_once_and_fail_closed():
    # RaycastClosest/All remain deferred; RaycastAny is implemented in Wave 7 B4b
    # (real VMT-slot-10 binding, gated) and is covered by the contract below.
    source = LUA_LEVEL_C.read_text()
    contracts = {
        "lua_level_raycast_closest": ("RaycastClosest", "lua_pushnil(L)"),
        "lua_level_raycast_all": ("RaycastAll", "lua_pushnil(L)"),
    }
    for function, (api_name, result_statement) in contracts.items():
        body = _function_body(source, function)
        assert "static bool warned = false;" in body
        assert "warn_deferred_once(" in body
        assert f'"{api_name}"' in body
        assert result_statement in body
        assert f"level_{function.removeprefix('lua_level_')}(" not in body

    # RaycastAny is no longer a deferred stub: it must dispatch its real helper
    # and must NOT warn-once or fail-closed unconditionally.
    any_body = _function_body(source, "lua_level_raycast_any")
    assert "level_raycast_any(" in any_body
    assert "warn_deferred_once(" not in any_body

    tier2 = LUA_EXT_C.read_text()
    assert "Parity.Level.RaycastClosestDeferred" in tier2
    assert "deferred RaycastClosest must return nil" in tier2
    assert "Parity.Level.RaycastAllDeferred" in tier2
    assert "deferred RaycastAll must return nil" in tier2
    # RaycastAny deferral test retired; the real binding is exercised by
    # Wave7.Level.RaycastAny (callable + returns boolean without crashing).
    assert "Parity.Level.RaycastAnyDeferred" not in tier2
    assert "Wave7.Level.RaycastAny" in tier2


def test_repaired_query_calls_use_arm64_reference_shapes():
    source = LEVEL_MANAGER_C.read_text()

    assert "float sx" not in source
    assert "float px" not in source
    assert "return sweep(physics, radius, src, dst, hit," in source
    assert "return sweep(physics, radius, half_height, src, dst, hit," in source
    assert "return sweep(physics, extents, src, dst, hit," in source
    assert "return sweep(physics, radius, src, dst, out," in source
    assert "return sweep(physics, radius, half_height, src, dst, out," in source
    assert "return sweep(physics, extents, src, dst, out," in source
    assert "return test(physics, pos, extents, out," in source
    assert "return test(physics, pos, radius, out," in source

    # Closest/All are still deferred stubs and must not dispatch a VMT entry.
    # RaycastAny (Wave 7 B4b) is intentionally excluded: it dispatches the real
    # VMT slot 10 and is validated by test_raycast_any_binding_is_gated below.
    for function in ("level_raycast_closest", "level_raycast_all"):
        body = _function_body(source, function)
        assert "read_vmt_entry" not in body


def test_raycast_any_binding_is_gated():
    """Wave 7 B4b: the real RaycastAny binding must dispatch VMT slot 10 (never a
    hardcoded worker address), be arm64-only, and fail closed unless BOTH the game
    version and the audited Mach-O UUID match (RAYCAST_ABI_B4A.md)."""
    source = LEVEL_MANAGER_C.read_text()
    body = _function_body(source, "level_raycast_any")

    # Dispatches via the VMT slot constant, not a literal address.
    assert "read_vmt_entry(" in body
    assert "PHYSICS_VMT_RAYCAST_ANY" in body

    # Version + UUID gate; arm64-only with an x86_64 fail-closed fallback.
    assert "version_detect_matches()" in source
    assert "0x0c, 0x51, 0xca, 0xed" in source  # 7398727 arm64 LC_UUID gate bytes
    assert "#if defined(__aarch64__)" in source

    # The audited RaycastAny VMT index is slot 10.
    assert _parse_physics_indices()["PHYSICS_VMT_RAYCAST_ANY"] == 10


def test_raycast_any_gate_uuid_is_the_installed_binary():
    """The RaycastAny gate must name the build its signature was checked on."""
    if not BG3_EXEC.exists():
        pytest.skip("BG3 binary not installed")
    if not shutil.which("dwarfdump"):
        pytest.skip("dwarfdump unavailable")
    out = subprocess.run(["dwarfdump", "--uuid", str(BG3_EXEC)],
                         capture_output=True, text=True).stdout
    m = re.search(r"UUID: ([0-9A-F-]+) \(arm64\)", out)
    assert m, out
    installed = bytes.fromhex(m.group(1).replace("-", ""))
    block = re.search(r"s_raycast_any_verified_uuid\[16\] = \{(.*?)\};",
                      LEVEL_MANAGER_C.read_text(), re.S).group(1)
    gate = bytes(int(b, 16) for b in re.findall(r"0x([0-9a-fA-F]{2})", block))
    assert gate == installed, (
        f"RaycastAny gate UUID {gate.hex()} != installed arm64 {installed.hex()}; "
        "re-check phx::PhysXScene::RaycastAny's signature before moving the gate")


def test_installed_arm64_physxscene_vtable_dispatch():
    if not BG3_EXEC.exists():
        pytest.skip("BG3 binary not installed")
    if not (shutil.which("nm") and shutil.which("c++filt")):
        pytest.skip("nm/c++filt unavailable")

    slice_offset, slice_size = _arm64_fat_slice(BG3_EXEC)
    assert slice_offset > 0
    assert slice_size > 0
    segments = _arm64_segments(BG3_EXEC, slice_offset)
    symbols = _nm_symbols(BG3_EXEC)

    vtable_matches = [
        address for address, lines in symbols.items()
        if any(line.endswith(f" {PHYSX_VTABLE_SYMBOL}") for line in lines)
    ]
    assert len(vtable_matches) == 1, (
        f"expected one {PHYSX_VTABLE_SYMBOL}, found {vtable_matches}"
    )
    address_point = vtable_matches[0] + 0x10

    constants = _parse_physics_indices()
    target_by_constant = {}
    with BG3_EXEC.open("rb") as stream:
        for constant, index in constants.items():
            word_va = address_point + index * 8
            stream.seek(_va_to_file_offset(word_va, slice_offset, segments))
            word = stream.read(8)
            assert len(word) == 8, f"truncated vtable word for {constant}"
            target_by_constant[constant] = struct.unpack("<Q", word)[0]

    target_lines = []
    for constant, target in target_by_constant.items():
        lines = symbols.get(target, [])
        assert lines, (
            f"{constant} VMT[{constants[constant]}] target {target:#x} has no "
            "exact arm64 nm symbol"
        )
        target_lines.extend(lines)

    demangled_by_address: dict[int, list[str]] = {}
    for line in _demangle_symbol_lines(target_lines):
        match = re.match(r"^([0-9a-fA-F]{16})\s+\S\s+(\S.*)$", line)
        assert match, f"unexpected c++filt output: {line}"
        demangled_by_address.setdefault(
            int(match.group(1), 16), []).append(match.group(2))

    for constant, expected_method in EXPECTED_DISPATCH.items():
        target = target_by_constant[constant]
        names = demangled_by_address.get(target, [])
        expected = f"phx::PhysXScene::{expected_method}("
        assert any(expected in name for name in names), (
            f"{constant}={constants[constant]} dispatches to {names}, "
            f"expected {expected_method}"
        )
