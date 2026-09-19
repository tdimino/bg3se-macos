"""Offline audit for the RPGStats ModifierValueLists layout.

The fake-memory tests exercise the documented pointer arithmetic without
loading BG3. Frozen-binary byte checks are supplementary and skip when the
migration binaries are not present (for example in CI).
"""

from dataclasses import dataclass
from pathlib import Path
import re
import struct

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
STATS_C = REPO_ROOT / "src/stats/stats_manager.c"
STATS_H = REPO_ROOT / "src/stats/stats_manager.h"
LUA_STATS_C = REPO_ROOT / "src/lua/lua_stats.c"
VERSION_H = REPO_ROOT / "src/core/version_detect.h"
EVIDENCE = REPO_ROOT / "ghidra/offsets/VALUELIST_REGISTRY_7398727.md"

PTR_SIZE = 8
MANAGER_BUFFER = 0x08
MANAGER_CAPACITY = 0x10
MANAGER_COUNT = 0x14
ELEMENT_NAME = 0x00
ELEMENT_BUCKET_COUNT = 0x08
ELEMENT_BUCKETS = 0x10
ELEMENT_ITEM_COUNT = 0x18
MAX_MANAGER_ENTRIES = 4096
MAX_BUCKETS = 1_048_576
MAX_ITEMS = 1_048_576

BUILDS = {
    "4.1.1.7209685": {
        "slot": 0x1089CD730,
        "slice": 0x0F558000,
        "insert": 0x101C44920,
        "raw_insert": 0x1119C920,
    },
    "4.1.1.7398727": {
        "slot": 0x1089FDDD0,
        "slice": 0x0F5C0000,
        "insert": 0x101C42014,
        "raw_insert": 0x11202014,
    },
}


class FakeMemory:
    def __init__(self):
        self.data: dict[int, int] = {}

    def write(self, address: int, value: bytes) -> None:
        self.data.update((address + index, byte) for index, byte in enumerate(value))

    def write_u32(self, address: int, value: int) -> None:
        self.write(address, struct.pack("<I", value))

    def write_ptr(self, address: int, value: int) -> None:
        self.write(address, struct.pack("<Q", value))

    def read(self, address: int, size: int) -> bytes:
        try:
            return bytes(self.data[address + index] for index in range(size))
        except KeyError as error:
            raise ValueError(f"unmapped read at 0x{address:x} size {size}") from error

    def read_u32(self, address: int) -> int:
        return struct.unpack("<I", self.read(address, 4))[0]

    def read_ptr(self, address: int) -> int:
        return struct.unpack("<Q", self.read(address, PTR_SIZE))[0]


@dataclass(frozen=True)
class ValueListShape:
    address: int
    name_index: int
    bucket_count: int
    buckets: int
    item_count: int


def walk_registry(memory: FakeMemory, singleton_slot: int) -> tuple[int, list[ValueListShape]]:
    """Pure-Python model of the production read path and its bounds."""
    manager = memory.read_ptr(singleton_slot)  # manager is RPGStats + 0x00
    if not manager:
        raise ValueError("null RPGStats pointer")

    buffer = memory.read_ptr(manager + MANAGER_BUFFER)
    capacity = memory.read_u32(manager + MANAGER_CAPACITY)
    count = memory.read_u32(manager + MANAGER_COUNT)
    if count > capacity or capacity > MAX_MANAGER_ENTRIES:
        raise ValueError("malformed registry count/capacity")
    if count and not buffer:
        raise ValueError("null registry buffer")

    result = []
    for index in range(count):
        element = memory.read_ptr(buffer + index * PTR_SIZE)
        if not element:
            continue
        bucket_count = memory.read_u32(element + ELEMENT_BUCKET_COUNT)
        buckets = memory.read_ptr(element + ELEMENT_BUCKETS)
        item_count = memory.read_u32(element + ELEMENT_ITEM_COUNT)
        if not 0 < bucket_count <= MAX_BUCKETS:
            raise ValueError("malformed bucket count")
        if not buckets:
            raise ValueError("null bucket array")
        if item_count > MAX_ITEMS:
            raise ValueError("malformed item count")
        result.append(ValueListShape(
            address=element,
            name_index=memory.read_u32(element + ELEMENT_NAME),
            bucket_count=bucket_count,
            buckets=buckets,
            item_count=item_count,
        ))
    return manager, result


def valid_memory(version: str) -> tuple[FakeMemory, int, int]:
    memory = FakeMemory()
    slot = BUILDS[version]["slot"]
    manager = 0x120000000
    buffer = 0x120001000
    memory.write_ptr(slot, manager)
    memory.write_ptr(manager + MANAGER_BUFFER, buffer)
    memory.write_u32(manager + MANAGER_CAPACITY, 128)
    memory.write_u32(manager + MANAGER_COUNT, 2)

    for index, name_index in enumerate((101, 202)):
        element = 0x120002000 + index * 0x100
        buckets = 0x120004000 + index * 0x100
        memory.write_ptr(buffer + index * PTR_SIZE, element)
        memory.write_u32(element + ELEMENT_NAME, name_index)
        memory.write_u32(element + ELEMENT_BUCKET_COUNT, 16)
        memory.write_ptr(element + ELEMENT_BUCKETS, buckets)
        memory.write_u32(element + ELEMENT_ITEM_COUNT, 3 + index)
    return memory, slot, manager


@pytest.mark.parametrize("version", BUILDS)
def test_complete_layout_chain_for_both_builds(version):
    memory, slot, expected_manager = valid_memory(version)
    manager, entries = walk_registry(memory, slot)
    assert manager == expected_manager
    assert [entry.name_index for entry in entries] == [101, 202]
    assert [entry.bucket_count for entry in entries] == [16, 16]
    assert [entry.item_count for entry in entries] == [3, 4]


@pytest.mark.parametrize(
    ("capacity", "count"),
    [
        (1, 2),
        (MAX_MANAGER_ENTRIES + 1, 1),
        (128, 0xFFFFFFFF),
    ],
)
def test_malformed_manager_counts_are_rejected(capacity, count):
    memory, slot, manager = valid_memory("4.1.1.7398727")
    memory.write_u32(manager + MANAGER_CAPACITY, capacity)
    memory.write_u32(manager + MANAGER_COUNT, count)
    with pytest.raises(ValueError, match="count/capacity"):
        walk_registry(memory, slot)


def test_null_manager_buffer_is_rejected_when_nonempty():
    memory, slot, manager = valid_memory("4.1.1.7398727")
    memory.write_ptr(manager + MANAGER_BUFFER, 0)
    with pytest.raises(ValueError, match="null registry buffer"):
        walk_registry(memory, slot)


def test_null_manager_buffer_is_allowed_when_empty():
    memory, slot, manager = valid_memory("4.1.1.7398727")
    memory.write_ptr(manager + MANAGER_BUFFER, 0)
    memory.write_u32(manager + MANAGER_COUNT, 0)
    resolved_manager, entries = walk_registry(memory, slot)
    assert resolved_manager == manager
    assert entries == []


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        (ELEMENT_BUCKET_COUNT, 0, "bucket count"),
        (ELEMENT_BUCKET_COUNT, MAX_BUCKETS + 1, "bucket count"),
        (ELEMENT_BUCKETS, 0, "bucket array"),
        (ELEMENT_ITEM_COUNT, MAX_ITEMS + 1, "item count"),
    ],
)
def test_malformed_value_list_shapes_are_rejected(field, value, message):
    memory, slot, manager = valid_memory("4.1.1.7398727")
    buffer = memory.read_ptr(manager + MANAGER_BUFFER)
    element = memory.read_ptr(buffer)
    if field == ELEMENT_BUCKETS:
        memory.write_ptr(element + field, value)
    else:
        memory.write_u32(element + field, value)
    with pytest.raises(ValueError, match=message):
        walk_registry(memory, slot)


def test_production_walk_matches_evidence_and_is_bounded():
    source = STATS_C.read_text()
    header = STATS_H.read_text()
    evidence = EVIDENCE.read_text()
    assert re.search(r"RPGSTATS_OFFSET_MODIFIER_VALUE_LISTS\s+0x00\b", source)
    assert re.search(r"VALUELIST_REGISTRY_MAX_ENTRIES\s+4096U", source)
    assert re.search(r"VALUELIST_DIAGNOSTIC_SCAN_LIMIT\s+32U", source)
    assert "STATS_VALUELIST_DIAGNOSTIC_MAX_NAMES 8" in header
    for offset in ("+ 0x14", "+ 0x08", "+ 0x10", "+ 0x18"):
        assert offset in evidence


def test_insert_uses_typed_function_id_and_gate_is_the_live_verified_build():
    """Mutation is open only on the build where the live round trip passed.

    The insert path carries its own gate constant, separate from
    BG3_KNOWN_VERSION. It moved to 7398727 with live evidence: on that build
    GetValueListRegistryDiagnostic read 112 valid lists, and the Tier 2
    Wave7.Stats.AddEnumerationValue round trip (insert, label<->index,
    duplicate rejected, unknown enum fails closed) passed. No live insert ever
    succeeded on 7209685."""
    source = STATS_C.read_text()
    assert "offset_table_game_fn(GAME_FN_VALUELIST_INSERT)" in source
    assert "VALUELIST_INSERT_ADDRESS" not in source
    assert (
        '#define VALUELIST_INSERT_VERIFIED_BUILD "4.1.1.7398727"' in source
    )
    assert re.search(
        r"strcmp\(version,\s*VALUELIST_INSERT_VERIFIED_BUILD\)", source
    )


def test_read_only_diagnostic_is_exposed_before_mutation_bindings():
    source = LUA_STATS_C.read_text()
    diagnostic = source.index(
        '{"GetValueListRegistryDiagnostic", lua_stats_get_valuelist_registry_diagnostic}'
    )
    assert diagnostic < source.index('{"AddAttribute", lua_stats_add_attribute}')
    assert diagnostic < source.index(
        '{"AddEnumerationValue", lua_stats_add_enumeration_value}'
    )
    assert "lua_pushboolean(L, valid)" in source
    assert 'lua_setfield(L, -2, "Manager")' in source
    assert 'lua_setfield(L, -2, "Count")' in source
    assert 'lua_setfield(L, -2, "Names")' in source


@pytest.mark.parametrize("version", BUILDS)
def test_frozen_insert_prologue_matches_versioned_slice_math(version):
    binary = (
        REPO_ROOT / "build/migration-binaries" / version / "Baldur's Gate 3"
    )
    if not binary.exists():
        pytest.skip(f"frozen BG3 {version} binary is unavailable")
    claim = BUILDS[version]
    assert claim["raw_insert"] == claim["slice"] + claim["insert"] - 0x100000000
    with binary.open("rb") as stream:
        stream.seek(claim["raw_insert"])
        prologue = stream.read(16)
    assert prologue == bytes.fromhex(
        "ff 43 01 d1 f8 5f 01 a9 f6 57 02 a9 f4 4f 03 a9"
    )
