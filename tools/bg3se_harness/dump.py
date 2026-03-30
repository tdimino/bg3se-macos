"""Bulk game data extraction.

Extracts game data (feats, races, classes, spells, weapons, etc.) from
the running game via Lua API calls and writes to JSON files.
"""

import json
import os
import sys
from pathlib import Path

from .console import Console


CATEGORIES = {
    "feats": ('Ext.StaticData.GetAll("Feat")', "StaticData"),
    "races": ('Ext.StaticData.GetAll("Race")', "StaticData"),
    "classes": ('Ext.StaticData.GetAll("Class")', "StaticData"),
    "backgrounds": ('Ext.StaticData.GetAll("Background")', "StaticData"),
    "origins": ('Ext.StaticData.GetAll("Origin")', "StaticData"),
    "gods": ('Ext.StaticData.GetAll("God")', "StaticData"),
    "spells": ('Ext.Stats.GetAll("SpellData")', "Stats"),
    "weapons": ('Ext.Stats.GetAll("Weapon")', "Stats"),
    "armor": ('Ext.Stats.GetAll("Armor")', "Stats"),
    "statuses": ('Ext.Stats.GetAll("StatusData")', "Stats"),
    "passives": ('Ext.Stats.GetAll("PassiveData")', "Stats"),
}


def _make_dump_lua(api_call, api_type):
    """Generate Lua code for dumping a category."""
    if api_type == "StaticData":
        return f"""
local ok, result = pcall(function()
    local items = {api_call}
    local data = {{}}
    for _, id in ipairs(items) do
        local entry = Ext.StaticData.Get(id, nil)
        if entry then
            table.insert(data, entry)
        end
    end
    return Ext.Json.Stringify(data, {{Beautify = true}})
end)
if ok then _P(result) else _P('{{"error": "' .. tostring(result) .. '"}}') end
"""
    else:
        # Stats API — GetAll returns names, Get returns full objects
        return f"""
local ok, result = pcall(function()
    local names = {api_call}
    return Ext.Json.Stringify(names)
end)
if ok then _P(result) else _P('{{"error": "' .. tostring(result) .. '"}}') end
"""


def dump_category(category, output_dir=None):
    """Dump a single category. Returns (category, data_string, error)."""
    if category not in CATEGORIES:
        return category, None, f"Unknown category: {category}. Valid: {', '.join(sorted(CATEGORIES))}"

    api_call, api_type = CATEGORIES[category]
    lua_code = _make_dump_lua(api_call, api_type)

    try:
        with Console() as c:
            output = c.send_lua(lua_code)
    except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
        return category, None, f"Socket: {e}"

    if output_dir:
        out_path = Path(output_dir) / f"{category}.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output)
        return category, str(out_path), None

    return category, output, None


def cmd_dump(args):
    """CLI handler for dump command."""
    category = args.category
    output_dir = getattr(args, "output", None)

    if category == "all":
        categories = sorted(CATEGORIES.keys())
    else:
        categories = [category]

    results = {}
    errors = []

    for cat in categories:
        print(f"[dump] Extracting {cat}...", file=sys.stderr)
        cat_name, data, error = dump_category(cat, output_dir)
        if error:
            errors.append({"category": cat_name, "error": error})
        elif output_dir:
            results[cat_name] = {"file": data}
        else:
            # Print each category's data directly
            if len(categories) == 1:
                print(data)
                return 0
            results[cat_name] = json.loads(data) if data else None

    if errors and not results:
        print(json.dumps({"errors": errors}, indent=2))
        return 1

    if len(categories) > 1 or output_dir:
        output = {"categories": results}
        if errors:
            output["errors"] = errors
        print(json.dumps(output, indent=2))

    return 0 if not errors else 1
