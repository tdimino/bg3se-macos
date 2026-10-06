"""A field named field_XX asserts its own offset; that claim is checkable.

The Windows headers name an unknown field after its offset in the Windows
struct (`field_5C` sits at 0x5C). Our tables inherit those names, so a
declaration that puts `field_5C` anywhere else is either a packing mistake or a
place where MSVC and libc++ widths genuinely diverge. Both are worth knowing;
only the first is a bug.

64 such fields were corrected against offsets computed by compiling upstream's
declarations for arm64 (clang -fdump-record-layouts). The rest are pinned here:
the count may only go down, so a new disagreement fails rather than joining the
pile. Shrinking the pile means editing the baseline, which is the point.
"""

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ENTITY = REPO / "src/entity"
BASELINE = Path(__file__).parent / "selfnamed_offsets_baseline.json"

PROP = re.compile(r'\{\s*"(field_[0-9A-Fa-f]+)",\s*(0x[0-9a-fA-F]+|\d+),')
ARRAY = re.compile(
    r'static const ComponentPropertyDef (\w+)\[\]\s*=\s*\{(.*?)\n\};', re.S)
LAYOUT = re.compile(
    r'static const ComponentLayoutDef (\w+)\s*=\s*\{(.*?)\n\};', re.S)


def _disagreements():
    """(component, field, declared offset) for every self-named field that is
    not at the offset its name encodes."""
    found = []
    for name in ("generated_property_defs.h", "component_offsets.h"):
        text = (ENTITY / name).read_text()
        arrays = {m.group(1): m.group(2) for m in ARRAY.finditer(text)}
        owner = {}
        for m in LAYOUT.finditer(text):
            comp = re.search(r'\.componentName\s*=\s*"([^"]+)"', m.group(2))
            props = re.search(r'\.properties\s*=\s*(\w+)', m.group(2))
            if comp and props:
                owner[props.group(1)] = comp.group(1)
        for arr, body in arrays.items():
            comp = owner.get(arr)
            if not comp:
                continue
            for field, off in PROP.findall(body):
                if int(off, 0) != int(field[6:], 16):
                    found.append([comp, field, int(off, 0)])
    return sorted(found)


def test_no_new_selfnamed_offset_disagreements():
    pinned = {tuple(e) for e in json.loads(BASELINE.read_text())}
    current = {tuple(e) for e in _disagreements()}
    new = sorted(current - pinned)
    assert not new, (
        f"{len(new)} self-named field(s) moved away from the offset their name "
        f"encodes: {new[:10]}. Either the offset is wrong, or MSVC and libc++ "
        f"widths diverge here and the entry belongs in "
        f"{BASELINE.name} with that reason."
    )


def test_baseline_does_not_pin_what_is_already_fixed():
    pinned = {tuple(e) for e in json.loads(BASELINE.read_text())}
    current = {tuple(e) for e in _disagreements()}
    stale = sorted(pinned - current)
    assert not stale, (
        f"{len(stale)} baseline entr(ies) no longer disagree; drop them from "
        f"{BASELINE.name} so the ratchet keeps its grip: {stale[:10]}"
    )
