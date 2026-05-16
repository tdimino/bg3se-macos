"""Tier H tests for mod_cli name→UUID resolution.

Regression: mod_cli.py passed raw names to enable_mod() which expects UUIDs.
"""
import json
from types import SimpleNamespace

import pytest


@pytest.fixture
def fake_registry(monkeypatch, tmp_path):
    """Provide a fake mod registry with 3 mods."""
    registry = {
        "aaaa-bbbb-cccc-dddd": {"name": "Mod Configuration Menu", "folder": "MCM"},
        "1111-2222-3333-4444": {"name": "Party Limit Begone", "folder": "PLB"},
        "5555-6666-7777-8888": {"name": "Mod Fixer", "folder": "MF"},
    }
    from bg3se_harness.mod_manager import registry as reg_mod
    monkeypatch.setattr(reg_mod, "load_registry", lambda: registry)
    return registry


def test_resolve_uuid_by_exact_uuid(fake_registry, monkeypatch):
    from bg3se_harness.mod_cli import _resolve_uuid
    assert _resolve_uuid("aaaa-bbbb-cccc-dddd") == "aaaa-bbbb-cccc-dddd"


def test_resolve_uuid_by_name_substring(fake_registry, monkeypatch):
    from bg3se_harness.mod_cli import _resolve_uuid
    assert _resolve_uuid("Configuration Menu") == "aaaa-bbbb-cccc-dddd"


def test_resolve_uuid_case_insensitive(fake_registry, monkeypatch):
    from bg3se_harness.mod_cli import _resolve_uuid
    assert _resolve_uuid("party limit begone") == "1111-2222-3333-4444"


def test_resolve_uuid_ambiguous_returns_error(fake_registry, monkeypatch):
    from bg3se_harness.mod_cli import _resolve_uuid
    result = _resolve_uuid("Mod")
    assert isinstance(result, dict)
    assert "error" in result
    assert "Ambiguous" in result["error"]


def test_resolve_uuid_not_found_returns_error(fake_registry, monkeypatch):
    from bg3se_harness.mod_cli import _resolve_uuid
    result = _resolve_uuid("Nonexistent Mod")
    assert isinstance(result, dict)
    assert "error" in result
    assert "not found" in result["error"]


def test_cmd_mod_enable_adds_missing_registry_mod(fake_registry, monkeypatch, capsys):
    from bg3se_harness import mod_cli
    from bg3se_harness.mod_manager import modsettings, registry

    calls = {}

    def fake_add_mod(**kwargs):
        calls["add_mod"] = kwargs
        return {"added": True, "uuid": kwargs["uuid"], "name": kwargs["name"]}

    def fake_set_enabled(uuid, enabled):
        calls["set_enabled"] = (uuid, enabled)
        return {"updated": True}

    monkeypatch.setattr(modsettings, "add_mod", fake_add_mod)
    monkeypatch.setattr(registry, "set_mod_enabled", fake_set_enabled)

    args = SimpleNamespace(mod_command="enable", name="Configuration Menu")
    assert mod_cli.cmd_mod(args) == 0

    output = json.loads(capsys.readouterr().out)
    assert output["enabled"] is True
    assert calls["add_mod"] == {
        "uuid": "aaaa-bbbb-cccc-dddd",
        "name": "Mod Configuration Menu",
        "folder": "MCM",
        "version": "36028797018963968",
        "md5": "",
    }
    assert calls["set_enabled"] == ("aaaa-bbbb-cccc-dddd", True)


def test_list_mods_reports_actual_load_order_state(monkeypatch):
    from bg3se_harness.mod_manager import registry
    from bg3se_harness.mod_manager import modsettings

    monkeypatch.setattr(registry, "load_registry", lambda: {
        "active-uuid": {
            "uuid": "active-uuid",
            "name": "Active Mod",
            "enabled": True,
        },
        "reset-uuid": {
            "uuid": "reset-uuid",
            "name": "Reset Mod",
            "enabled": True,
        },
    })
    monkeypatch.setattr(modsettings, "read_mod_order", lambda: [
        {"uuid": "active-uuid", "name": "Active Mod"},
    ])

    mods = registry.list_mods()
    by_uuid = {m["uuid"]: m for m in mods}

    assert by_uuid["active-uuid"]["enabled"] is True
    assert by_uuid["active-uuid"]["registered_enabled"] is True
    assert by_uuid["reset-uuid"]["enabled"] is False
    assert by_uuid["reset-uuid"]["registered_enabled"] is True


def test_pak_lsx_parser_extracts_folder_and_dependencies():
    from bg3se_harness.mod_manager.pak_inspector import _extract_mod_info_from_lsx

    lsx = b"""<?xml version="1.0" encoding="UTF-8"?>
<save>
  <region id="Config">
    <node id="root">
      <children>
        <node id="ModuleInfo">
          <attribute id="Author" type="LSString" value="Author Name"/>
          <attribute id="Description" type="LSString" value="Description"/>
          <attribute id="Folder" type="LSString" value="RealFolder"/>
          <attribute id="Name" type="LSString" value="Real Name"/>
          <attribute id="UUID" type="FixedString" value="mod-uuid"/>
          <attribute id="Version64" type="int64" value="1234"/>
        </node>
        <node id="Dependencies">
          <children>
            <node id="ModuleShortDesc">
              <attribute id="Folder" type="LSString" value="DepFolder"/>
              <attribute id="Name" type="LSString" value="Dependency"/>
              <attribute id="UUID" type="FixedString" value="dep-uuid"/>
              <attribute id="Version64" type="int64" value="5678"/>
            </node>
          </children>
        </node>
      </children>
    </node>
  </region>
</save>
"""

    info = _extract_mod_info_from_lsx(lsx)

    assert info["uuid"] == "mod-uuid"
    assert info["folder"] == "RealFolder"
    assert info["version"] == "1234"
    assert info["dependencies"] == [{
        "uuid": "dep-uuid",
        "name": "Dependency",
        "folder": "DepFolder",
        "version": "5678",
        "md5": None,
    }]


def test_zstd_decompress_uses_system_binary(monkeypatch):
    from types import SimpleNamespace
    from bg3se_harness.mod_manager import pak_inspector

    calls = {}
    monkeypatch.setattr(pak_inspector.shutil, "which", lambda name: "/opt/homebrew/bin/zstd")

    def fake_run(cmd, input, stdout, stderr, check):
        calls["cmd"] = cmd
        calls["input"] = input
        return SimpleNamespace(returncode=0, stdout=b"decoded", stderr=b"")

    monkeypatch.setattr(pak_inspector.subprocess, "run", fake_run)

    assert pak_inspector._decompress_zstd(b"encoded") == b"decoded"
    assert calls["cmd"] == ["/opt/homebrew/bin/zstd", "-dcq"]
    assert calls["input"] == b"encoded"


def test_scan_installed_paks_reports_all_paks(monkeypatch, tmp_path):
    from bg3se_harness.mod_manager import inventory

    (tmp_path / "A.pak").write_bytes(b"")
    (tmp_path / "B.pak").write_bytes(b"")

    class FakePak:
        def __init__(self, path):
            self.path = path

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get_mod_info(self):
            if self.path.endswith("A.pak"):
                return {
                    "uuid": "uuid-a",
                    "name": "Mod A",
                    "folder": "FolderA",
                    "version": "1",
                    "author": None,
                    "description": None,
                    "dependencies": [],
                    "meta_path": "Mods/FolderA/meta.lsx",
                }
            return {
                "uuid": "uuid-b",
                "name": "Mod B",
                "folder": None,
                "version": "2",
                "author": None,
                "description": None,
                "dependencies": [],
                "meta_path": "Mods/FolderB/meta.lsx",
            }

        def contains_script_extender(self):
            return self.path.endswith("B.pak")

    monkeypatch.setattr(inventory, "PakReader", FakePak)

    report = inventory.scan_installed_paks(mods_dir=tmp_path)

    assert report["summary"]["pak_count"] == 2
    assert report["summary"]["ok_count"] == 2
    by_uuid = {mod["uuid"]: mod for mod in report["mods"]}
    assert by_uuid["uuid-a"]["folder"] == "FolderA"
    assert by_uuid["uuid-b"]["folder"] == "FolderB"
    assert by_uuid["uuid-b"]["se_mod"] is True


def test_reconcile_registry_write_adds_missing_installed_mod(monkeypatch):
    from bg3se_harness.mod_manager import inventory

    saved = {}
    scan = {
        "mods": [{
            "uuid": "uuid-a",
            "name": "Mod A",
            "folder": "FolderA",
            "version": "1",
            "author": "Author",
            "description": "Desc",
            "dependencies": [],
            "pak_path": "/mods/A.pak",
            "meta_path": "Mods/FolderA/meta.lsx",
            "se_mod": False,
            "status": "ok",
        }],
        "summary": {"pak_count": 1, "ok_count": 1, "error_count": 0},
        "duplicates": {"uuid": [], "folder": []},
    }

    monkeypatch.setattr(inventory, "scan_installed_paks", lambda mods_dir=None: scan)
    monkeypatch.setattr(inventory, "load_registry", lambda: {})
    monkeypatch.setattr(inventory, "read_mod_order", lambda: [{"uuid": "uuid-a", "name": "Mod A"}])
    monkeypatch.setattr(inventory, "save_registry", lambda registry: saved.update(registry))

    result = inventory.reconcile_registry(write=True)

    assert result["written"] == ["uuid-a"]
    assert saved["uuid-a"]["name"] == "Mod A"
    assert saved["uuid-a"]["enabled"] is True
    assert saved["uuid-a"]["registry_source"] == "installed_pak_scan"


def test_preflight_blocks_active_unregistered_mod(monkeypatch):
    from bg3se_harness.mod_manager import inventory

    scan = {
        "mods": [{
            "uuid": "uuid-a",
            "name": "Mod A",
            "folder": "FolderA",
            "pak_name": "A.pak",
            "status": "ok",
        }],
        "summary": {"pak_count": 1, "ok_count": 1, "error_count": 0},
        "duplicates": {"uuid": [], "folder": []},
    }

    monkeypatch.setattr(inventory, "scan_installed_paks", lambda mods_dir=None: scan)
    monkeypatch.setattr(inventory, "load_registry", lambda: {})
    monkeypatch.setattr(inventory, "read_mod_order", lambda: [{"uuid": "uuid-a", "name": "Mod A"}])

    result = inventory.preflight_mod_state()

    assert result["success"] is False
    assert result["blocking"] is True
    assert result["issues"][0]["code"] == "active_mod_unregistered"


def test_preflight_accept_mod_verification_makes_issues_nonblocking(monkeypatch):
    from bg3se_harness.mod_manager import inventory

    monkeypatch.setattr(inventory, "scan_installed_paks", lambda mods_dir=None: {
        "mods": [],
        "summary": {"pak_count": 0, "ok_count": 0, "error_count": 0},
        "duplicates": {"uuid": [], "folder": []},
    })
    monkeypatch.setattr(inventory, "load_registry", lambda: {})
    monkeypatch.setattr(inventory, "read_mod_order", lambda: [{"uuid": "uuid-a", "name": "Mod A"}])

    result = inventory.preflight_mod_state(accept_mod_verification=True)

    assert result["success"] is True
    assert result["blocking"] is False
    assert {issue["code"] for issue in result["issues"]} == {
        "active_mod_not_installed",
        "active_mod_unregistered",
    }


def test_verify_modsettings_compares_save_required_mods(monkeypatch):
    from bg3se_harness.mod_manager import inventory

    monkeypatch.setattr(inventory, "load_registry", lambda: {
        "uuid-a": {"uuid": "uuid-a", "name": "Mod A", "folder": "FolderA", "version": "1"},
    })
    monkeypatch.setattr(inventory, "scan_installed_paks", lambda: {
        "mods": [{
            "uuid": "uuid-a",
            "name": "Mod A",
            "folder": "FolderA",
            "version": "1",
            "status": "ok",
        }],
        "summary": {"pak_count": 1, "ok_count": 1, "error_count": 0},
        "duplicates": {"uuid": [], "folder": []},
    })
    monkeypatch.setattr(inventory, "read_mod_order", lambda: [
        {"uuid": "base", "name": "GustavX", "folder": "GustavX"},
        {"uuid": "uuid-a", "name": "Mod A", "folder": "FolderA", "version": "1"},
    ])

    result = inventory.verify_modsettings()

    assert result["success"] is True
    assert result["summary"]["active_count"] == 2
    assert result["issues"] == []


def test_verify_modsettings_reports_save_required_inactive(monkeypatch):
    from bg3se_harness.mod_manager import inventory

    monkeypatch.setattr(inventory, "load_registry", lambda: {
        "uuid-a": {"uuid": "uuid-a", "name": "Mod A", "folder": "FolderA", "version": "1"},
        "uuid-b": {"uuid": "uuid-b", "name": "Mod B", "folder": "FolderB", "version": "1"},
    })
    monkeypatch.setattr(inventory, "scan_installed_paks", lambda: {
        "mods": [
            {"uuid": "uuid-a", "name": "Mod A", "folder": "FolderA", "version": "1"},
            {"uuid": "uuid-b", "name": "Mod B", "folder": "FolderB", "version": "1"},
        ],
        "summary": {"pak_count": 2, "ok_count": 2, "error_count": 0},
        "duplicates": {"uuid": [], "folder": []},
    })
    monkeypatch.setattr(inventory, "read_mod_order", lambda: [
        {"uuid": "base", "name": "GustavX", "folder": "GustavX"},
        {"uuid": "uuid-a", "name": "Mod A", "folder": "FolderA", "version": "1"},
    ])

    import bg3se_harness.savegames as sg
    monkeypatch.setattr(sg, "save_mods", lambda save_name=None, continue_latest=False: {
        "required_mods": [
            {"uuid": "uuid-a", "name": "Mod A"},
            {"uuid": "uuid-b", "name": "Mod B"},
        ],
    })

    result = inventory.verify_modsettings(continue_latest=True)

    assert result["success"] is False
    assert result["issues"][0]["code"] == "save_required_mod_inactive"
    assert result["issues"][0]["uuid"] == "uuid-b"


def test_verify_modsettings_exact_expected_order(monkeypatch, tmp_path):
    from bg3se_harness.mod_manager import inventory

    monkeypatch.setattr(inventory, "load_registry", lambda: {
        "uuid-a": {"uuid": "uuid-a", "name": "Mod A", "folder": "FolderA", "version": "1"},
    })
    monkeypatch.setattr(inventory, "scan_installed_paks", lambda: {
        "mods": [{"uuid": "uuid-a", "name": "Mod A", "folder": "FolderA", "version": "1"}],
        "summary": {"pak_count": 1, "ok_count": 1, "error_count": 0},
        "duplicates": {"uuid": [], "folder": []},
    })
    monkeypatch.setattr(inventory, "read_mod_order", lambda: [
        {"uuid": "base", "name": "GustavX", "folder": "GustavX"},
        {"uuid": "uuid-a", "name": "Mod A", "folder": "FolderA", "version": "1"},
    ])

    expected = tmp_path / "order.json"
    expected.write_text('["base", "uuid-a"]', encoding="utf-8")

    result = inventory.verify_modsettings(expected_order_path=str(expected))

    assert result["success"] is True
    assert result["expected_order"] == ["base", "uuid-a"]

    expected.write_text('["uuid-a", "base"]', encoding="utf-8")
    result = inventory.verify_modsettings(expected_order_path=str(expected))

    assert result["success"] is False
    assert result["issues"][0]["code"] == "modsettings_order_mismatch"
