"""Image addresses reach code only through the per-version offset table.

A hardcoded image address is correct for exactly one game build. On 7398727
three survived the migration to the offset table and were still used:
video_skip.c hooked a 7209685 LoadVideo address that now lies inside a UI sort
routine, entity_system.c read EocClient from __thread_bss, and fixed_string.c
pointed the GlobalStringTable at an unrelated global. test_offset_audit.py
passed throughout, because it validates the table and manifest, not the
literal the code used.

These checks read the source, not the binary, so they run everywhere:

* no code references a macro whose value is an image address (unused anchors
  documenting old builds are fine; using one is not)
* no bare image-address literal appears in code, other than round range bounds
* every offset-table field has a reader (eocclient_ptr had none, which is how
  the stale EocClient literal went unnoticed)
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src"

# The table itself, and the generated TypeId tables (gated on their build id
# at runtime and checked against nm by the offset audit).
EXCLUDED = {
    "src/core/offset_table.c",
    "src/entity/generated_typeids.h",
    "src/entity/generated_component_registry.c",
}

# Macros that hold an image address AND are referenced by code, each with the
# reason that use is safe on every build.
ALLOWED_MACRO_USES = {
    "SAVEGAME_HOOK_VISIT_VA": "savegame_hook.c installs only when BG3SE_SAVEGAME_SPIKE=1 "
                              "and the build equals SAVEGAME_HOOK_VERIFIED_BUILD",
}

# Files allowed to contain bare image-address literals in code, with the reason.
ALLOWED_BARE_LITERALS = {
    "src/core/version_detect.c": "sentinel addresses, probed only on a version mismatch "
                                 "to diagnose it; never used as a known slot",
    "src/entity/component_templates.h": "included by no translation unit "
                                        "(test_unincluded_literal_headers_stay_unincluded)",
}

# Offset-table fields with no reader outside offset_table.c, with the reason.
UNREAD_FIELDS = {
    "game_functions": "read inside offset_table.c by offset_table_game_fn()",
    "component_data_shift": "retired: __DATA moved non-uniformly; kept for old rows",
    "component_data_shift_valid": "retired with component_data_shift",
    "fn_getallfeats": "no consumer",
    "fn_get_origin": "no consumer",
    "fn_get_class": "no consumer",
    "fn_get_progression": "no consumer",
    "fn_get_actionresource": "no consumer",
    "fn_get_template_raw": "no consumer",
    "fn_cache_template": "no consumer",
}

IMAGE_LITERAL = re.compile(r"\b0x1[0-9a-fA-F]{8}(?:[uU]?[lL]{0,2}|[lL]{1,2}[uU])?\b")
DEFINE = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+(\w+)[ \t]+(?:UINT64_C\()?[ \t]*(0x1[0-9a-fA-F]{8})", re.M)


def _is_range_bound(literal: str) -> bool:
    # 0x100000000, 0x110000000, 0x200000000 ...: bounds and bases, not symbols.
    value = int(re.match(r"0x[0-9a-fA-F]+", literal).group(0), 16)
    return value & 0xFFFFFFF == 0


def _code_only(text: str) -> str:
    """Blank comments and string literals, preserving line numbers."""
    text = re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    return re.sub(r'"(?:\\.|[^"\\\n])*"', '""', text)


def _sources():
    for path in sorted(SRC.rglob("*")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if path.suffix in {".c", ".h", ".m", ".mm", ".cpp"} and rel not in EXCLUDED:
            yield rel, _code_only(path.read_text(errors="ignore"))


def _image_macros(sources):
    macros = {}
    for rel, code in sources:
        for m in DEFINE.finditer(code):
            if not _is_range_bound(m.group(2)):
                macros[m.group(1)] = rel
    return macros


def test_no_code_uses_an_image_address_macro():
    sources = list(_sources())
    macros = _image_macros(sources)
    assert macros, "found no image-address macros at all — the scanner is broken"

    uses = []
    for rel, code in sources:
        for lineno, line in enumerate(code.splitlines(), 1):
            if re.match(r"\s*#\s*define\b", line):
                continue
            for name in macros:
                if name not in ALLOWED_MACRO_USES and re.search(rf"\b{name}\b", line):
                    uses.append(f"{rel}:{lineno}: {name} (defined in {macros[name]})")
    assert not uses, (
        "Code uses a hardcoded image address. It is right for one game build only; "
        "resolve it through the offset table (offset_table_game_fn / a VersionOffsets "
        "field) and fail closed when the running version has no entry:\n  "
        + "\n  ".join(uses))


def test_no_bare_image_literals_in_code():
    hits = []
    for rel, code in _sources():
        if rel in ALLOWED_BARE_LITERALS:
            continue
        for lineno, line in enumerate(code.splitlines(), 1):
            if re.match(r"\s*#\s*define\b", line):
                continue
            for m in IMAGE_LITERAL.finditer(line):
                if not _is_range_bound(m.group(0)):
                    hits.append(f"{rel}:{lineno}: {line.strip()[:100]}")
    assert not hits, (
        "Bare image address in code — it is right for one game build only; move it "
        "into the offset table:\n  " + "\n  ".join(hits))


def _table_fields():
    header = _code_only((SRC / "core/offset_table.h").read_text())
    body = header[header.index("typedef struct"):header.index("} VersionOffsets;")]
    return re.findall(r"\b(\w+)\s*(?:\[[^\]]*\])?;", body)


def test_every_offset_table_field_has_a_reader():
    fields = _table_fields()
    assert "eocserver_ptr" in fields and "gst_ptr" in fields, fields
    code = "\n".join(c for rel, c in _sources()
                     if not rel.startswith("src/core/offset_table."))
    unread = {f for f in fields if not re.search(rf"(->|\.){f}\b", code)}

    new = sorted(unread - UNREAD_FIELDS.keys())
    assert not new, (
        f"Offset-table fields with no reader: {new}. A field nobody reads usually "
        "means the code still uses a hardcoded address for the same thing "
        "(eocclient_ptr was unread while entity_system.c read a stale literal).")
    now_read = sorted(UNREAD_FIELDS.keys() - unread)
    assert not now_read, f"now read — remove from UNREAD_FIELDS: {now_read}"


def test_allowlisted_macros_still_exist():
    macros = _image_macros(list(_sources()))
    assert set(ALLOWED_MACRO_USES) <= set(macros), set(ALLOWED_MACRO_USES) - set(macros)


def _sources_raw():
    for path in sorted(SRC.rglob("*")):
        if path.suffix in {".c", ".h", ".m", ".mm", ".cpp"}:
            yield path.relative_to(REPO_ROOT).as_posix(), path.read_text(errors="ignore")


def test_unincluded_literal_headers_stay_unincluded():
    """A header allowlisted for being dead must not quietly come back to life."""
    for rel, reason in ALLOWED_BARE_LITERALS.items():
        if "included by no translation unit" not in reason:
            continue
        name = re.escape(Path(rel).name)
        includers = [r for r, text in _sources_raw() if r != rel
                     and re.search(rf'#\s*include\s*[<"][^>"]*{name}[>"]', text)]
        assert not includers, f"{rel} is now included by {includers}; its addresses are live"
