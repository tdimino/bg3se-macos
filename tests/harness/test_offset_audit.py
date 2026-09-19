"""Audit hardcoded offsets and the per-version offset table against the
installed game binary.

Dobby code patches and singleton reads aimed at the main BG3 binary use
hardcoded addresses derived from one specific game build. The version-detect
sentinels only validate three *data* addresses, so a game update can silently
invalidate *code* offsets — a stale ``OFFSET_GET_CLASS`` once landed in the
middle of ``gui::HotbarSystem::Update`` and crashed every session ~30s after
save load (docs/bugs/codex-debugger-nohooks-2026-07-28.md).

Three audit layers, all skipped when the game binary is absent (CI):

1. ``BASELINE_DIRECT_CHECKS`` — the original 35 named source-address checks,
   resolved through the installed version's central address claim.
2. The installed version's row of ``src/core/offset_table.c`` — every field except
   the documented exclusions must resolve to its claimed symbol.
   Exclusions: ``staticdata_mstate_ptr`` is a ``__DATA_CONST,__got`` slot
   (validated GOT-aware via ``otool -Iv`` instead — nm cannot see it);
   ``global_switches_ptr`` is an anonymous __common slot with no symbol
   (verified 2026-07-29 by disassembly: 916 refs across 593 functions incl.
   App::CreateGlobalSwitches; runtime read-back guard in global_switches.c);
   ``component_data_shift`` is a delta, not an address.
3. The typed ``GameFunctionId`` array — every nonzero installed-version
   address must resolve to its exact demangled symbol and IDs must be unique.

The named legacy baseline remains 68 address-sensitive pytest cases:
35 direct-source recipes + 30 VersionOffsets fields + one typed-function-table
case + one GOT-slot case + one Osiris disassembly-slot case. New coverage is
reported separately and does not silently redefine that baseline.

FUNCTOR GATE: the eleven functor-hook addresses in
``src/stats/functor_types.h`` ARE nm-visible local symbols on 7209685 (the
old "stripped locals" premise was wrong), but the 7209685 Interrupt variant
gained a leading ``ecs::EntityWorld&`` parameter — address validity is not
ABI validity. The family therefore stays gated at install time on
``FUNCTOR_ADDRS_VERIFIED_BUILD`` — an exact match against the build its
addresses AND wrapper ABIs were verified on, independent of
``BG3_KNOWN_VERSION`` (see test_functor_gate_is_independent below).
"""

import json
import plistlib
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from bg3se_harness.config import BG3_APP_BUNDLE, BG3_EXEC

REPO_ROOT = Path(__file__).resolve().parents[2]
OFFSET_TABLE_C = REPO_ROOT / "src/core/offset_table.c"
OFFSET_TABLE_H = REPO_ROOT / "src/core/offset_table.h"
OFFSET_MANIFEST = REPO_ROOT / "tools/offset_manifest.json"
GENERATED_TYPEIDS_H = REPO_ROOT / "src/entity/generated_typeids.h"

BASELINE_DIRECT_CHECKS = [
    ("ADDR_GETMESSAGE", "net::MessageFactory::GetFreeMessage(int)"),
    ("VA_BINK_LOAD_VIDEO", "bik::BinkManager::LoadVideo(ls::Path const&)"),
    ("OFFSET_RPGSTATS_M_PTR", "RPGStats::m_ptr"),
    ("OFFSET_RPGSTATS", "RPGStats::m_ptr"),
    ("GHIDRA_FIXEDSTRING_CREATE", "ls::FixedString::Create(char const*, int)"),
    ("OFFSET_EOCSERVER_SINGLETON_PTR", "esv::EocServer::m_ptr"),
    ("OFFSET_EOCCLIENT_SINGLETON_PTR", "ecl::EocClient::m_ptr"),
    ("OFFSET_LEGACY_IS_IN_COMBAT", "eoc::CombatHelpers::LEGACY_IsInCombat(ls::ID<ecs::EntityHandleTraits> const&, ecs::EntityWorld&)"),
    ("OFFSET_LEGACY_GET_COMBAT_FROM_GUID", "eoc::CombatHelpers::LEGACY_GetCombatFromGuid(ls::Guid const&, ecs::EntityWorld&)"),
    ("ADDR_STORAGE_CONTAINER_TRYGET", "ecs::EntityStorageContainer::TryGet(ls::ID<ecs::EntityHandleTraits>)"),
    ("OFFSET_BOOST_PROTOTYPE_MANAGER_PTR", "eoc::BoostPrototypeManager::m_ptr"),
    ("OFFSET_PASSIVE_PROTOTYPE_MANAGER_PTR", "eoc::Passives::m_ptr"),
    ("OFFSET_INTERRUPT_PROTOTYPE_MANAGER_PTR", "eoc::InterruptPrototypeManager::m_ptr"),
    ("OFFSET_SPELL_PROTOTYPE_MANAGER_PTR", "eoc::SpellPrototypeManager::m_ptr"),
    ("OFFSET_STATUS_PROTOTYPE_MANAGER_PTR", "eoc::StatusPrototypeManager::m_ptr"),
    ("OFFSET_SPELL_PROTOTYPE_INIT", "eoc::SpellPrototype::Init(ls::FixedString const&)"),
    ("BASEAPP_S_APPINSTANCE_VA", "BaseApp::s_AppInstance"),
    ("OFFSET_RESOURCEMANAGER_PTR", "ls::ResourceManager::m_ptr"),
    ("OFFSET_GETRESOURCE_FUNC", "ls::ResourceContainer::GetResource(ls::EResourceType, ls::FixedString const&) const"),
    ("LOCA_REPO_OFFSET", "ls::TranslatedStringRepository::m_ptr"),
    ("LOCA_TRYGET_OFFSET", "ls::TranslatedStringRepository::TryGet(ls::RuntimeStringHandle const&, ls::identity::EIdentity, ls::identity::EIdentity) const"),
    ("LOCA_FIXEDSTRING_CREATE", "ls::FixedString::Create(char const*, int)"),
    ("LOCA_ADDTRANSLATEDSTRING", "ls::TranslatedStringRepository::AddTranslatedString(ls::RuntimeStringHandle, ls::_StringView<char>, ls::TranslatedMapRepo<ls::RuntimeStringNoVersionHashOps>*, ls::EnumFlags<ls::EAddFlags>)"),
    ("OFFSET_STDSTRING_CTOR", "ls::STDString::STDString(char const*)"),
    ("ADDR_EXECUTE_STATS_FUNCTOR", "ExecuteStatsFunctor(eoc::StatsFunctorBase const*, unsigned long, esv::functor::AttackTargetContextData&)"),
    ("ADDR_EXECUTE_FUNCTORS_ATTACK_TARGET", "esv::functor::ExecuteStatsFunctors(eoc::StatsFunctorList const*, esv::functor::AttackTargetContextData&)"),
    ("ADDR_EXECUTE_FUNCTORS_ATTACK_POSITION", "esv::functor::ExecuteStatsFunctors(eoc::StatsFunctorList const*, esv::functor::AttackPositionContextData&)"),
    ("ADDR_EXECUTE_FUNCTORS_MOVE", "esv::functor::ExecuteStatsFunctors(eoc::StatsFunctorList const*, esv::functor::MoveContextData&)"),
    ("ADDR_EXECUTE_FUNCTORS_TARGET", "esv::functor::ExecuteStatsFunctors(eoc::StatsFunctorList const*, esv::functor::TargetContextData&)"),
    ("ADDR_EXECUTE_FUNCTORS_NEARBY_ATTACKED", "esv::functor::ExecuteStatsFunctors(eoc::StatsFunctorList const*, esv::functor::NearbyAttackedContextData&)"),
    ("ADDR_EXECUTE_FUNCTORS_NEARBY_ATTACKING", "esv::functor::ExecuteStatsFunctors(eoc::StatsFunctorList const*, esv::functor::NearbyAttackingContextData&)"),
    ("ADDR_EXECUTE_FUNCTORS_EQUIP", "esv::functor::ExecuteStatsFunctors(eoc::StatsFunctorList const*, esv::functor::EquipContextData&)"),
    ("ADDR_EXECUTE_FUNCTORS_SOURCE", "esv::functor::ExecuteStatsFunctors(eoc::StatsFunctorList const*, esv::functor::SourceContextData&)"),
    ("ADDR_EXECUTE_FUNCTORS_INTERRUPT", "esv::functor::ExecuteStatsFunctors(ecs::EntityWorld&, eoc::StatsFunctorList const*, esv::functor::InterruptContextData&)"),
    ("ADDR_PROCESS_DEAL_DAMAGE_FUNCTORS", "(anonymous namespace)::ProcessDealDamageFunctors(ecs::WorldView<eoc::repose::StateComponent const, ls::PhysicsComponent const, ls::TransformComponent const, ls::uuid::Component const>&, eoc::StatsFunctorBase const&, ls::ID<ecs::EntityHandleTraits> const&, ls::Optional<Vector3f> const&, eoc::spell_cast::StateComponent const&, ls::EnumFlags<eoc::EDamageEffectFlag> const&, EAbility const&, ESpellAttackType const&, eoc::interrupt::Dependency const&, eoc::interrupt::Dependency const&, int, ls::DynamicArray<eoc::interrupt::InterruptEvent, ls::TaggedAllocator<int>>&)"),
]

BASELINE_ADDRESS_CHECK_COUNT = 68

MANIFEST = json.loads(OFFSET_MANIFEST.read_text())
TABLE_FIELD_SYMBOLS = {
    entry["field"]: entry["symbol"]
    for entry in MANIFEST["data_singletons"]
    if entry.get("method", "symbol") == "symbol"
}
TABLE_FIELD_SYMBOLS.update({
    entry["field"]: entry["symbol"]
    for entry in MANIFEST["offset_table_functions"]
})

BASELINE_TABLE_FIELDS = (
    "eocserver_ptr", "eocclient_ptr", "spell_proto_mgr_ptr", "rpgstats_ptr",
    "resource_mgr_ptr", "level_mgr_ptr", "global_template_mgr_ptr",
    "cache_template_mgr_ptr", "level_cache_mgr_ptr", "gst_ptr",
    "fn_feat_getfeats", "fn_getallfeats", "fn_get_background",
    "fn_get_origin", "fn_get_class", "fn_get_progression",
    "fn_get_actionresource", "fn_get_template_raw", "fn_cache_template",
    "fn_aigrid_to_tile_pos", "fn_aigrid_get_metadata",
    "fn_aigrid_remove_path", "fn_aigrid_find_path",
    "fn_aigrid_find_path_immediate", "fn_try_get_uuid_mapping",
    "fn_storage_tryget", "fn_spell_proto_init", "fn_status_proto_init",
    "fn_interrupt_proto_get", "fn_passives_get",
)
ADDITIONAL_TABLE_FIELDS = (
    "translated_string_repo_ptr",
    # Moved out of hardcoded consumer defines 2026-08-04 (Wave 2 lead):
    # prototype_managers.c singletons + focus_hack.c BaseApp slot.
    "status_proto_mgr_ptr", "passives_ptr", "interrupt_proto_mgr_ptr",
    "boost_proto_mgr_ptr", "baseapp_instance_ptr",
    "wwise_manager_vtable",
)
EXPECTED_MANUAL_FIELDS = ("global_switches_ptr", "osiris_interface_ptr")
NON_SYMBOL_FIELDS = {
    "staticdata_mstate_ptr", "global_switches_ptr", "osiris_interface_ptr",
    "component_data_shift", "component_data_shift_valid", "game_functions",
}

MSTATE_GOT_SYMBOL = "__ZN2ls11TypeContextINS_23ImmutableDataHeadmasterEE7m_StateE"

IMAGE_BASE = 0x100000000


def _parse_system_typeids() -> list[tuple[str, str, int]]:
    """Parse (public_name, engine_class, va) from GENERATED_SYSTEM_TYPEID_ENTRIES."""
    text = GENERATED_TYPEIDS_H.read_text()
    results = []
    for m in re.finditer(
            r'X\("([^"]+)",\s*"([^"]+)",\s*(0x[0-9a-fA-F]+)ULL\)',
            text):
        results.append((m.group(1), m.group(2), int(m.group(3), 16)))
    return results


SYSTEM_TYPEIDS = _parse_system_typeids() if GENERATED_TYPEIDS_H.exists() else []


def _installed_version() -> str:
    plist = BG3_APP_BUNDLE / "Contents/Info.plist"
    if not plist.exists():
        pytest.skip("BG3 Info.plist not installed")
    with plist.open("rb") as stream:
        version = plistlib.load(stream).get("CFBundleShortVersionString")
    assert version, f"CFBundleShortVersionString missing from {plist}"
    return version


def _extract_table_block(version: str) -> str:
    text = OFFSET_TABLE_C.read_text()
    marker = re.search(rf'\.version\s*=\s*"{re.escape(version)}"', text)
    assert marker, f"no {version} row in offset_table.c"
    start = text.rfind("{", 0, marker.start())
    depth = 0
    for pos in range(start, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[start:pos + 1]
    raise AssertionError(f"unterminated {version} row in offset_table.c")


def _parse_table_row(version: str) -> dict[str, int]:
    """Parse one VersionOffsets struct literal out of offset_table.c."""
    fields = {}
    for m in re.finditer(
            r"\.(\w+)\s*=\s*(-?0x[0-9a-fA-F]+|\d+|true|false)",
            _extract_table_block(version)):
        raw = m.group(2)
        fields[m.group(1)] = (
            raw == "true" if raw in ("true", "false")
            else int(raw, 16 if "0x" in raw else 10)
        )
    return fields


def _parse_game_functions(version: str) -> dict[str, int]:
    functions = {
        match.group(1): int(match.group(2), 16)
        for match in re.finditer(
            r"\[(GAME_FN_[A-Z0-9_]+)\]\s*=\s*(0x[0-9a-fA-F]+|0)",
            _extract_table_block(version),
        )
    }
    assert functions, f"no GameFunctionId entries in {version} row"
    return functions


def _claimed_va_for_symbol(version: str, symbol: str) -> int:
    row = _parse_table_row(version)
    for field, expected_symbol in TABLE_FIELD_SYMBOLS.items():
        if expected_symbol == symbol:
            assert row.get(field), f"{field} is zero/missing in {version} row"
            return row[field] + IMAGE_BASE

    game = _parse_game_functions(version)
    for entry in MANIFEST["game_functions"]:
        if entry["symbol"] == symbol:
            offset = game.get(entry["id"])
            assert offset, f"{entry['id']} is zero/missing in {version} row"
            return offset + IMAGE_BASE

    for entry in MANIFEST["source_addresses"]:
        if entry["symbol"] == symbol:
            claimed = entry["addresses"].get(version)
            assert claimed, f"{entry['name']} has no {version} address claim"
            return int(claimed, 16)

    raise AssertionError(f"exact symbol has no installed-version address recipe: {symbol}")


def _all_audited_vas() -> set[int]:
    version = _installed_version()
    vas = {
        _claimed_va_for_symbol(version, symbol)
        for _name, symbol in BASELINE_DIRECT_CHECKS
    }
    row = _parse_table_row(version)
    for field in BASELINE_TABLE_FIELDS + ADDITIONAL_TABLE_FIELDS:
        if row.get(field):
            vas.add(row[field] + IMAGE_BASE)
    vas.update(
        offset + IMAGE_BASE
        for offset in _parse_game_functions(version).values()
        if offset
    )
    vas.update(
        int(anchor["addresses"][version], 16)
        for anchor in MANIFEST["typeid_shift_anchors"]
        if version in anchor.get("addresses", {})
    )
    vas.update(va for _, _, va in SYSTEM_TYPEIDS)
    return vas


@pytest.fixture(scope="module")
def nm_symbols():
    """Map VA -> demangled symbols for every audited address (one nm pass)."""
    if not BG3_EXEC.exists():
        pytest.skip("BG3 binary not installed")
    if not (shutil.which("nm") and shutil.which("c++filt")):
        pytest.skip("nm/c++filt unavailable")

    wanted = {f"{va:016x}" for va in _all_audited_vas()}
    nm = subprocess.run(
        ["nm", "-arch", "arm64", str(BG3_EXEC)],
        capture_output=True, text=True, timeout=300,
    )
    if nm.returncode != 0:
        pytest.skip(f"nm failed: {nm.stderr[:200]}")

    matched = [line for line in nm.stdout.splitlines() if line[:16] in wanted]
    demangled = subprocess.run(
        ["c++filt"], input="\n".join(matched), capture_output=True,
        text=True, timeout=60,
    ).stdout.splitlines()

    found: dict[int, list[str]] = {}
    for line in demangled:
        parts = line.split(maxsplit=2)
        if len(parts) == 3:
            found.setdefault(int(parts[0], 16), []).append(parts[2])
    return found


def _assert_symbol_at(found, va, name, symbol):
    symbols_here = found.get(va, [])
    assert symbols_here, (
        f"{name}: no symbol at VA {va:#x} in the installed binary — the game "
        f"likely updated and this offset is STALE. Re-derive it via: "
        f"nm <BG3 binary> | c++filt | grep '{symbol}'"
    )
    assert symbol in symbols_here, (
        f"{name}: VA {va:#x} resolves to {symbols_here}, expected a symbol "
        f"exactly equal to '{symbol}' — offset is aimed at the WRONG target. "
        f"Patching/reading it would corrupt behavior."
    )


@pytest.mark.parametrize(
    "name,symbol",
    BASELINE_DIRECT_CHECKS,
    ids=[entry[0] for entry in BASELINE_DIRECT_CHECKS],
)
def test_baseline_direct_address_matches_symbol(nm_symbols, name, symbol):
    va = _claimed_va_for_symbol(_installed_version(), symbol)
    _assert_symbol_at(nm_symbols, va, name, symbol)


@pytest.mark.parametrize(
    "field",
    BASELINE_TABLE_FIELDS,
)
def test_baseline_offset_table_installed_row(nm_symbols, field):
    version = _installed_version()
    row = _parse_table_row(version)
    assert field in row, f"{field} missing from {version} row"
    value = row[field]
    assert value, f"{field} is 0 in the {version} row (feature silently disabled)"
    _assert_symbol_at(
        nm_symbols, value + IMAGE_BASE,
        f"offset_table[{version}].{field}", TABLE_FIELD_SYMBOLS[field])


@pytest.mark.parametrize("field", ADDITIONAL_TABLE_FIELDS)
def test_new_offset_table_field_matches_symbol(nm_symbols, field):
    version = _installed_version()
    row = _parse_table_row(version)
    assert row.get(field), f"{field} is zero/missing in {version} row"
    _assert_symbol_at(
        nm_symbols, row[field] + IMAGE_BASE,
        f"offset_table[{version}].{field}", TABLE_FIELD_SYMBOLS[field])


def test_offset_table_row_fields_complete():
    """Every struct field must be classified: either audited or excluded."""
    header = (REPO_ROOT / "src/core/offset_table.h").read_text()
    struct = re.search(r"typedef struct \{(.*?)\} VersionOffsets;", header,
                       re.DOTALL)
    assert struct
    declared = set(re.findall(
        r"(?:u?intptr_t|bool)\s+(\w+)(?:\[[^]]+\])?;", struct.group(1)))
    classified = set(TABLE_FIELD_SYMBOLS) | NON_SYMBOL_FIELDS
    assert declared == classified, (
        f"offset_table.h fields not classified in TABLE_FIELD_SYMBOLS: "
        f"{declared - classified or classified - declared} — every new field "
        f"needs an audit entry or a documented exclusion"
    )


def test_offset_manifest_covers_all_function_fields():
    """Every function pointer needed by VersionOffsets must have a migration
    recipe.  Otherwise a future resolver can emit a compiling zero that silently
    disables the feature even though the current-build symbol audit is green."""
    header = OFFSET_TABLE_H.read_text()
    struct = re.search(r"typedef struct \{(.*?)\} VersionOffsets;", header,
                       re.DOTALL)
    assert struct
    declared = set(re.findall(r"uintptr_t\s+(fn_\w+);", struct.group(1)))

    entries = MANIFEST["offset_table_functions"]
    fields = [entry["field"] for entry in entries]
    assert len(fields) == len(set(fields)), (
        "duplicate offset_table_functions fields in offset_manifest.json"
    )
    assert set(fields) == declared, (
        "offset_manifest.json function recipes do not match VersionOffsets: "
        f"missing={sorted(declared - set(fields))}, "
        f"stale={sorted(set(fields) - declared)}"
    )
    for entry in entries:
        assert entry.get("baseline", "").startswith("0x")
        assert entry.get("symbol"), (
            f"{entry['field']} has no symbol recipe; next migration would "
            "silently emit zero"
        )


def test_baseline_game_function_table(nm_symbols):
    """The legacy remap-table case, now using typed installed-version IDs.

    It covers the original 18 functions plus BinkManager::LoadVideo and
    CRPGStats_Modifier_ValueList::Insert as ordinary IDs.
    """
    version = _installed_version()
    functions = _parse_game_functions(version)
    for entry in MANIFEST["game_functions"]:
        offset = functions.get(entry["id"])
        assert offset, f"{entry['id']} is zero/missing in {version} row"
        _assert_symbol_at(
            nm_symbols, offset + IMAGE_BASE,
            f"offset_table[{version}].{entry['id']}", entry["symbol"])


def test_game_function_ids_and_version_addresses_are_unique():
    """Stable IDs and nonzero addresses must be unique within each version."""
    header = OFFSET_TABLE_H.read_text()
    enum = re.search(r"typedef enum GameFunctionId \{(.*?)\} GameFunctionId;",
                     header, re.DOTALL)
    assert enum, "GameFunctionId enum missing"
    declared = re.findall(r"\b(GAME_FN_[A-Z0-9_]+)\b", enum.group(1))
    declared.remove("GAME_FN_COUNT")
    manifest_ids = [entry["id"] for entry in MANIFEST["game_functions"]]
    assert declared == manifest_ids, "GameFunctionId enum and manifest differ"

    text = OFFSET_TABLE_C.read_text()
    versions = re.findall(r'\.version\s*=\s*"([\d.]+)"', text)
    for version in versions:
        functions = _parse_game_functions(version)
        assert set(functions) == set(declared), (
            f"{version} function IDs incomplete: "
            f"missing={sorted(set(declared) - set(functions))}")
        nonzero = [value for value in functions.values() if value]
        assert len(nonzero) == len(set(nonzero)), (
            f"{version} has duplicate nonzero GameFunctionId addresses")


def test_mstate_got_slot():
    """staticdata_mstate_ptr is a __DATA_CONST,__got slot: nm cannot see it.
    Validate GOT-aware — otool -Iv must map the slot to the
    TypeContext<ImmutableDataHeadmaster>::m_State symbol."""
    if not BG3_EXEC.exists():
        pytest.skip("BG3 binary not installed")
    if not shutil.which("otool"):
        pytest.skip("otool unavailable")

    version = _installed_version()
    row = _parse_table_row(version)
    va = row["staticdata_mstate_ptr"] + IMAGE_BASE
    out = subprocess.run(
        ["otool", "-arch", "arm64", "-Iv", str(BG3_EXEC)],
        capture_output=True, text=True, timeout=600,
    )
    if out.returncode != 0:
        pytest.skip(f"otool failed: {out.stderr[:200]}")
    line = next((ln for ln in out.stdout.splitlines()
                 if ln.startswith(f"0x{va:016x}")), None)
    assert line, (
        f"staticdata_mstate_ptr {va:#x}: not an indirect-symbol slot in the "
        f"installed binary — the __got layout changed; re-derive via "
        f"otool -Iv | grep m_StateE"
    )
    assert MSTATE_GOT_SYMBOL in line, (
        f"staticdata_mstate_ptr {va:#x} maps to the wrong symbol: {line} — "
        f"expected {MSTATE_GOT_SYMBOL}. The StaticData traversal would walk "
        f"garbage."
    )


OSIRIS_QUERY_MANGLED = "__ZN3osi15OsirisInterface11OsirisQueryEjP16COsiArgumentDesc"


def test_global_switches_expected_manual_field():
    version = _installed_version()
    row = _parse_table_row(version)
    if not row.get("global_switches_ptr"):
        pytest.xfail(
            f"expected-manual: offset_table[{version}].global_switches_ptr "
            "is zero pending Wave 2A disassembly"
        )
    assert row["global_switches_ptr"] > 0


def test_scalar_typeid_shift_rejected(nm_symbols):
    """A multi-delta TypeId family must never claim one scalar migration."""
    version = _installed_version()
    deltas = set()
    for anchor in MANIFEST["typeid_shift_anchors"]:
        claimed = int(anchor["addresses"][version], 16)
        _assert_symbol_at(
            nm_symbols, claimed, "component_data_shift anchor", anchor["symbol"])
        deltas.add(claimed - int(anchor["baseline"], 16))

    row = _parse_table_row(version)
    if len(deltas) > 1:
        assert row["component_data_shift"] == 0, (
            f"{version} has {len(deltas)} TypeId deltas but claims scalar "
            f"{row['component_data_shift']:#x}")
        assert row["component_data_shift_valid"] is False
    else:
        assert row["component_data_shift_valid"] is True


def test_osiris_interface_slot_matches_disasm():
    """osiris_interface_ptr (the osi::OsirisInterface global instance slot,
    used by osi_read_param_defs in main.c) has no nm symbol. Its authoritative
    reference is OsirisQuery's own load of the global — the first
    ``adrp xN, <page>`` / ``ldr xM, [xN, #off]`` pair in the function prologue
    after the stack-guard load. Disassemble it and require the computed target
    to equal the table value (2026-07-29 on 7209685: adrp 0x108a86000 +
    ldr #0x128 -> 0x108a86128)."""
    if not BG3_EXEC.exists():
        pytest.skip("BG3 binary not installed")
    if not shutil.which("otool"):
        pytest.skip("otool unavailable")

    version = _installed_version()
    row = _parse_table_row(version)
    if not row.get("osiris_interface_ptr"):
        pytest.xfail(
            f"expected-manual: offset_table[{version}].osiris_interface_ptr "
            "is zero pending Wave 2A disassembly"
        )
    expected = row["osiris_interface_ptr"] + IMAGE_BASE
    out = subprocess.run(
        ["otool", "-arch", "arm64", "-tV", "-p", OSIRIS_QUERY_MANGLED,
         str(BG3_EXEC)],
        capture_output=True, text=True, timeout=600,
    )
    if out.returncode != 0:
        pytest.skip(f"otool failed: {out.stderr[:200]}")
    lines = out.stdout.splitlines()[:40]
    assert any(OSIRIS_QUERY_MANGLED in ln for ln in lines), (
        "osi::OsirisInterface::OsirisQuery symbol not found — signature "
        "changed in a game update; re-derive the instance slot"
    )
    targets = []
    page = None
    page_reg = None
    for ln in lines:
        m = re.search(r"adrp\s+(x\d+),\s+\S+\s+;\s+0x([0-9a-f]+)", ln)
        if m:
            page_reg, page = m.group(1), int(m.group(2), 16)
            continue
        m = re.search(r"ldr\s+x\d+,\s+\[(x\d+)(?:,\s+#0x([0-9a-f]+))?\]", ln)
        if m and page is not None and m.group(1) == page_reg:
            off = int(m.group(2), 16) if m.group(2) else 0
            targets.append(page + off)
            page = page_reg = None
    assert expected in targets, (
        f"osiris_interface_ptr {expected:#x} not among OsirisQuery's "
        f"adrp+ldr targets {[hex(t) for t in targets]} — the instance slot "
        f"moved in a game update; osi_read_param_defs would read garbage. "
        f"Re-derive from the disasm and update offset_table.c."
    )


def test_functor_gate_is_independent():
    """The functor Dobby family's addresses are nm-auditable, but its ABI is
    not: the 7209685 Interrupt ExecuteStatsFunctors gained a leading
    ecs::EntityWorld& parameter. The install gate must therefore compare
    against FUNCTOR_ADDRS_VERIFIED_BUILD — the build whose addresses AND
    wrapper signatures were verified — never the global version match. This
    guards against a refactor quietly re-coupling it to BG3_KNOWN_VERSION,
    which would enable eleven ABI-unverified code patches on every version
    bump.
    """
    functor_types = (REPO_ROOT / "src/stats/functor_types.h").read_text()
    m = re.search(
        r'#define\s+FUNCTOR_ADDRS_VERIFIED_BUILD\s+"([\d.]+)"', functor_types
    )
    assert m, "FUNCTOR_ADDRS_VERIFIED_BUILD missing from functor_types.h"

    main_c = (REPO_ROOT / "src/injector/main.c").read_text()
    gate = re.search(
        r"if\s*\(!no_hooks[^)]*FUNCTOR_ADDRS_VERIFIED_BUILD[^)]*\)\s*==\s*0\)",
        main_c,
    )
    assert gate, (
        "main.c functor install gate no longer compares the detected version "
        "against FUNCTOR_ADDRS_VERIFIED_BUILD — eleven ABI-unverified code "
        "patches would install on unverified builds"
    )
    assert "version_detect_matches()) {\n                        if (functor_hooks_init" \
        not in main_c, "functor install re-coupled to global version match"


def test_interrupt_game_function_uses_entity_world_wrapper():
    """The enabled 7209685 Interrupt target must carry the full machine ABI:
    hidden result_out first (esv::functor::Result output storage, invisible in
    demangled names), then ecs::EntityWorld&. Dropping result_out shifts every
    register and crashes in the original body (2026-07-29 SIGSEGV,
    docs/bugs/wave2-functor-crash-analysis.md)."""
    functions = _parse_game_functions("4.1.1.7209685")
    assert functions["GAME_FN_EXECUTE_FUNCTORS_INTERRUPT"] == 0x05786548, (
        "Interrupt ID must target the nm-verified 7209685 overload")
    wrappers = (REPO_ROOT / "src/stats/functor_hooks.c").read_text()
    assert re.search(
        r"hook_ExecuteFunctors_Interrupt\s*\(\s*void\s*\*\s*result_out\s*,"
        r"\s*EntityWorld\s*\*",
        wrappers,
    ), (
        "Interrupt wrapper must accept (result_out, EntityWorld*, ...) — "
        "anything else is ABI-mismatched against the 7209685 binary"
    )
    assert re.search(
        r"hook_ExecuteFunctors_Target\s*\(\s*void\s*\*\s*result_out\s*,",
        wrappers,
    ), (
        "Ordinary ExecuteStatsFunctors wrappers must accept the hidden "
        "result_out leading argument (see wave2-functor-crash-analysis.md)"
    )


@pytest.mark.parametrize(
    "public_name,engine_class,va",
    SYSTEM_TYPEIDS,
    ids=[entry[0] for entry in SYSTEM_TYPEIDS],
)
def test_system_typeid_matches_symbol(nm_symbols, public_name, engine_class, va):
    expected = f"ls::TypeId<{engine_class}, ecs::SystemsContext>::m_TypeIndex"
    _assert_symbol_at(nm_symbols, va, f"SystemTypeId[{public_name}]", expected)
