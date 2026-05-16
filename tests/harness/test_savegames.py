"""Tier H tests for savegames.restore() backup behavior.

Regression: restore() destroyed existing saves via shutil.rmtree without backup.
"""
import shutil
from pathlib import Path

import pytest


@pytest.fixture
def save_env(monkeypatch, tmp_path):
    """Set up fake save dirs and fixture."""
    saves_dir = tmp_path / "saves"
    saves_dir.mkdir()
    fixtures_dir = tmp_path / "fixtures"
    fixtures_dir.mkdir()

    fixture = fixtures_dir / "test_fixture"
    fixture.mkdir()
    (fixture / "save.lsv").write_text("fixture_data")

    import bg3se_harness.savegames as sg
    monkeypatch.setattr(sg, "SAVES_DIR", saves_dir)
    monkeypatch.setattr(sg, "SAVE_FIXTURES_DIR", fixtures_dir)
    return saves_dir, fixtures_dir


def test_restore_backs_up_existing_save(save_env):
    saves_dir, _ = save_env
    import bg3se_harness.savegames as sg

    existing = saves_dir / "Harness__test_fixture"
    existing.mkdir()
    (existing / "save.lsv").write_text("original_data")

    result = sg.restore("test_fixture")
    assert result.get("success") is True

    backups = [d for d in saves_dir.iterdir() if "__backup_" in d.name]
    assert len(backups) == 1
    assert (backups[0] / "save.lsv").read_text() == "original_data"

    assert (existing / "save.lsv").read_text() == "fixture_data"


def test_restore_works_without_existing_save(save_env):
    saves_dir, _ = save_env
    import bg3se_harness.savegames as sg

    result = sg.restore("test_fixture")
    assert result.get("success") is True

    dest = saves_dir / "Harness__test_fixture"
    assert dest.exists()
    assert (dest / "save.lsv").read_text() == "fixture_data"


def test_scan_archive_for_mod_markers_separates_high_and_low_confidence(monkeypatch, tmp_path):
    import bg3se_harness.savegames as sg

    lsv = tmp_path / "save.lsv"
    lsv.write_bytes(b"")

    class FakePak:
        def __init__(self, path):
            self.path = path

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def list_files(self):
            return ["meta.lsf", "Globals.lsf"]

        def read_file(self, name):
            if name == "meta.lsf":
                return b"FolderA_uuid-a and uuid-a"
            return b"Waypoints"

    monkeypatch.setattr(sg, "PakReader", FakePak)

    result = sg._scan_archive_for_mod_markers(lsv, {
        "uuid-a": {
            "uuid": "uuid-a",
            "name": "Mod A",
            "folder": "FolderA_uuid-a",
            "version": "1",
        },
        "uuid-way": {
            "uuid": "uuid-way",
            "name": "Waypoints",
            "folder": "Waypoints_uuid-way",
            "version": "1",
        },
    })

    by_uuid = {mod["uuid"]: mod for mod in result["mods"]}
    assert by_uuid["uuid-a"]["confidence"] == "high"
    assert by_uuid["uuid-way"]["confidence"] == "low"


def test_save_mods_uses_only_high_confidence_markers_for_required(monkeypatch, tmp_path):
    import bg3se_harness.savegames as sg

    save_dir = tmp_path / "Char__Save"
    save_dir.mkdir()
    lsv = save_dir / "Save.lsv"
    lsv.write_bytes(b"")

    monkeypatch.setattr(sg, "_find_save_dir", lambda name=None, continue_latest=False: save_dir)
    monkeypatch.setattr(sg, "_load_known_mods", lambda: {
        "uuid-a": {"uuid": "uuid-a", "name": "Mod A", "folder": "FolderA_uuid-a"},
        "uuid-way": {"uuid": "uuid-way", "name": "Waypoints", "folder": "Waypoints_uuid-way"},
    })
    monkeypatch.setattr(sg, "_read_save_info_json", lambda path: {"Save Name": "Save"})
    monkeypatch.setattr(sg, "_scan_archive_for_mod_markers", lambda path, known: {
        "scanned_files": ["meta.lsf"],
        "unreadable_files": [],
        "mods": [
            {"uuid": "uuid-a", "name": "Mod A", "confidence": "high", "markers": []},
            {"uuid": "uuid-way", "name": "Waypoints", "confidence": "low", "markers": []},
        ],
    })

    from bg3se_harness.mod_manager import modsettings
    monkeypatch.setattr(modsettings, "read_mod_order", lambda: [
        {"uuid": "uuid-a", "name": "Mod A"},
    ])

    result = sg.save_mods(continue_latest=True)

    assert result["required_count"] == 1
    assert [mod["uuid"] for mod in result["required_mods"]] == ["uuid-a"]
    assert [mod["uuid"] for mod in result["low_confidence_candidates"]] == ["uuid-way"]
    assert result["comparison"]["missing_from_active"] == []
