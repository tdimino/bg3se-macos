"""RPGStats inspection via the BG3SE live console.

Three commands:
  stat <name>
      Dump a single stat entry as pretty JSON.

  stats --type TYPE
      List all stat names of the given type (e.g. "Weapon", "Armor", "SpellData").

  diff <name1> <name2>
      Show only the properties that differ between two stat entries.
      Each differing key maps to {"left": <value in name1>, "right": <value in name2>}.

Lua blocks use _P() for output and are sent via Console.send_lua().
"""

import json
import sys

from .console import Console


# ---------------------------------------------------------------------------
# Lua templates
# ---------------------------------------------------------------------------

LUA_STAT_GET = '''
local stat = Ext.Stats.Get("{name}")
if stat == nil then
    _P(Ext.Json.Stringify({{error = "Stat not found: {name}"}}))
    return
end
_P(Ext.Json.Stringify(stat, {{Beautify = true, MaxDepth = 3}}))
'''

LUA_STAT_ALL = '''
local all = Ext.Stats.GetAll("{stat_type}")
_P(Ext.Json.Stringify(all))
'''

LUA_STAT_DIFF = '''
local a = Ext.Stats.Get("{name1}")
local b = Ext.Stats.Get("{name2}")
if a == nil then _P(Ext.Json.Stringify({{error = "Stat not found: {name1}"}})); return end
if b == nil then _P(Ext.Json.Stringify({{error = "Stat not found: {name2}"}})); return end
local diff = {{}}
local seen = {{}}
for k, v in pairs(a) do
    seen[k] = true
    local bv = b[k]
    if tostring(v) ~= tostring(bv) then
        diff[k] = {{left = v, right = bv}}
    end
end
for k, v in pairs(b) do
    if not seen[k] then
        diff[k] = {{left = nil, right = v}}
    end
end
_P(Ext.Json.Stringify(diff, {{Beautify = true}}))
'''


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_stat(name):
    """Dump a stat entry as JSON. Returns the parsed dict or raises."""
    with Console() as c:
        return c.send_lua(LUA_STAT_GET.format(name=name))


def get_all_stats(stat_type):
    """List all stat names of a given type. Returns the raw response string."""
    with Console() as c:
        return c.send_lua(LUA_STAT_ALL.format(stat_type=stat_type))


def diff_stats(name1, name2):
    """Return only the fields that differ between two stat entries."""
    with Console() as c:
        return c.send_lua(LUA_STAT_DIFF.format(name1=name1, name2=name2))


# ---------------------------------------------------------------------------
# CLI handler
# ---------------------------------------------------------------------------

def cmd_stats(args):
    """CLI handler for the `stats` subcommand."""
    try:
        if getattr(args, "all_type", None):
            raw = get_all_stats(args.all_type)
        elif getattr(args, "diff", None):
            raw = diff_stats(args.name, args.diff)
        else:
            if not args.name:
                print(json.dumps({"error": "Provide a stat name, or use --all TYPE / --diff OTHER"}))
                return 1
            raw = get_stat(args.name)

        # Find the first JSON value in the console output and pretty-print it
        for i, ch in enumerate(raw):
            if ch in ("{", "["):
                parsed = json.loads(raw[i:])
                if isinstance(parsed, dict) and "error" in parsed:
                    print(json.dumps(parsed, indent=2))
                    return 1
                print(json.dumps(parsed, indent=2))
                return 0

        # No JSON found — print raw output as a fallback
        print(raw)
        return 0

    except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
        print(json.dumps({"error": f"Socket connection failed: {e}"}))
        return 1
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON from console: {e}"}))
        return 1
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        return 1
