import json


def test_parse_ips_extracts_faulting_thread(tmp_path):
    from bg3se_harness import crashlog

    report = tmp_path / "Baldur's Gate 3-test.ips"
    report.write_text(
        json.dumps({"timestamp": "2026-05-16 10:47:39.00 -0400", "app_version": "4.1"})
        + "\n"
        + json.dumps({
            "pid": 123,
            "faultingThread": 1,
            "exception": {
                "type": "EXC_BAD_ACCESS",
                "signal": "SIGSEGV",
                "subtype": "KERN_INVALID_ADDRESS at 0x0000000000000010",
            },
            "threads": [
                {"frames": [{"symbol": "other", "imageIndex": 0}]},
                {"name": "GameThread", "frames": [
                    {"symbol": "gui::HotbarSystem::Update()", "imageIndex": 0},
                    {"symbol": "gui::GameUI::Update()", "imageIndex": 0},
                ]},
            ],
            "usedImages": [
                {"name": "Baldur's Gate 3", "path": "/app/Baldur's Gate 3"},
            ],
        }),
        encoding="utf-8",
    )

    parsed = crashlog._parse_latest_ips(report)

    assert parsed["pid"] == 123
    assert parsed["exception_type"] == "EXC_BAD_ACCESS"
    assert parsed["faulting_thread"] == 1
    assert parsed["faulting_thread_name"] == "GameThread"
    assert parsed["faulting_frames"][0]["symbol"] == "gui::HotbarSystem::Update()"
    assert parsed["libbg3se_on_faulting_stack"] is False


def test_classify_hotbar_crash_after_level_loaded():
    from bg3se_harness import crashlog

    ips = {
        "exception_type": "EXC_BAD_ACCESS",
        "faulting_frames": [{"symbol": "gui::HotbarSystem::Update()"}],
    }
    log_lines = [
        "[DEBUG] [Osiris ] >>> Event[1889]: GainedControl (id=1, arity=1)",
        "[DEBUG] [Osiris ] >>> Event[1904]: LevelLoaded (id=2, arity=1)",
    ]

    assert crashlog._classify_crash(ips, log_lines) == "post_level_loaded_hotbar_update"


def test_extract_enabled_mods_from_log_block():
    from bg3se_harness import crashlog

    lines = [
        "[INFO ] [Mod    ] === Enabled Mods ===",
        "[INFO ] [Mod    ]   [1] GustavX (base game)",
        "[INFO ] [Mod    ]   [2] Mod Configuration Menu",
        "[INFO ] [Mod    ] Total mods: 2 (1 user mods)",
    ]

    assert crashlog._extract_enabled_mods(lines) == [
        {"index": 1, "name": "GustavX"},
        {"index": 2, "name": "Mod Configuration Menu"},
    ]
