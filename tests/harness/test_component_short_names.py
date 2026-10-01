"""src/entity/component_short_names.h is exactly what the generator emits."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
WINDOWS_REF = Path(os.environ.get("BG3SE_WINDOWS_REF", Path.home() / "projects/bg3se"))


def test_generated_table_is_current():
    if not (WINDOWS_REF / "BG3Extender/GameDefinitions").is_dir():
        pytest.skip(f"SKIP: Windows BG3SE checkout not found at {WINDOWS_REF} "
                    "(set BG3SE_WINDOWS_REF)")
    out = subprocess.run(
        [sys.executable, str(REPO / "tools/gen_component_short_names.py"), str(WINDOWS_REF)],
        capture_output=True, text=True, check=True).stdout
    assert out == (REPO / "src/entity/component_short_names.h").read_text(), (
        "regenerate: tools/gen_component_short_names.py <bg3se> > "
        "src/entity/component_short_names.h")


def test_table_is_sorted_for_binary_search():
    import re
    names = re.findall(r'\{ "([^"]+)", "', (REPO / "src/entity/component_short_names.h").read_text())
    assert len(names) > 700
    assert names == sorted(names), "component_engine_name() binary-searches this table"
    assert len(names) == len(set(names))
