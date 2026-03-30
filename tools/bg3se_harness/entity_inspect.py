"""Entity and component inspection via the BG3SE live console.

Two commands:
  entity <guid> [--component NAME] [--depth N]
      Inspect a live entity. Without --component, lists all component names.
      With --component, dumps the component's fields as pretty JSON.

  components [--namespace NS] [--search PATTERN] [--count]
      List all registered component types. Optionally filter by namespace
      prefix or a substring pattern. --count prints only the total.

All Lua is wrapped in pcall so a bad GUID or missing component returns a
structured error rather than crashing the console.
"""

import json
import sys

from .console import Console


# ---------------------------------------------------------------------------
# Lua templates
# ---------------------------------------------------------------------------

_LUA_LIST_COMPONENTS = """
local ok, result = pcall(function()
    local e = Ext.Entity.Get("{GUID}")
    if e == nil then error("Entity not found: {GUID}") end
    local names = {{}}
    for name, _ in pairs(e:GetAllComponents()) do
        table.insert(names, name)
    end
    table.sort(names)
    return Ext.Json.Stringify(names)
end)
if ok then
    _P(result)
else
    _P(Ext.Json.Stringify({{error = result}})
end
"""

_LUA_DUMP_COMPONENT = """
local ok, result = pcall(function()
    local e = Ext.Entity.Get("{GUID}")
    if e == nil then error("Entity not found: {GUID}") end
    local c = e.{COMPONENT}
    if c == nil then error("Component not found: {COMPONENT}") end
    return Ext.Json.Stringify(c, {{Beautify = true, MaxDepth = {DEPTH}}})
end)
if ok then
    _P(result)
else
    _P(Ext.Json.Stringify({{error = result}})
end
"""

_LUA_ALL_COMPONENT_TYPES = """
local ok, result = pcall(function()
    local types = Ext.Types.GetAllTypes()
    local components = {{}}
    for _, t in ipairs(types) do
        local info = Ext.Types.GetTypeInfo(t)
        if info and info.Kind == "Component" then
            table.insert(components, {{Name = t, Kind = info.Kind}})
        end
    end
    table.sort(components, function(a, b) return a.Name < b.Name end)
    return Ext.Json.Stringify(components)
end)
if ok then
    _P(result)
else
    _P(Ext.Json.Stringify({{error = result}})
end
"""

# search_entities: fetch all entities with a given component, return GUIDs + summary.
# Lua limit is enforced server-side to avoid flooding the socket.
_LUA_SEARCH_BY_COMPONENT = """
local ok, result = pcall(function()
    local limit = {LIMIT}
    local entities = Ext.Entity.GetAllEntitiesWithComponent("{COMPONENT}")
    if entities == nil then
        return Ext.Json.Stringify({{error = "GetAllEntitiesWithComponent returned nil for: {COMPONENT}"}})
    end
    local out = {{}}
    for i, e in ipairs(entities) do
        if i > limit then break end
        local guid = tostring(e)
        table.insert(out, {{guid = guid}})
    end
    return Ext.Json.Stringify(out)
end)
if ok then
    _P(result)
else
    _P(Ext.Json.Stringify({{error = result}})
end
"""

# search_entities without component filter: iterate all entity UUIDs.
# BG3SE does not expose a "get all entities" API directly; we use the component
# filter path exclusively when a component is specified.  When no component is
# given we return an informative error rather than attempting an unbounded walk.
_LUA_SEARCH_ALL_ENTITIES = """
_P(Ext.Json.Stringify({{error = "entity-search requires --component when no name-pattern is given; unbounded entity iteration is not supported"}}))
"""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _send_lua(code):
    """Send Lua to the running game and return the raw output string.

    Raises OSError / ConnectionRefusedError / FileNotFoundError on socket
    failure — callers decide how to surface this.
    """
    with Console() as c:
        return c.send_lua(code)


def _parse_response(raw):
    """Parse the JSON string returned by the Lua block.

    Returns the decoded object. Raises ValueError if the raw output is not
    valid JSON (e.g. the console echoed extra lines before the payload).
    """
    # The console may prepend a blank line or an echo; find the first '['
    # or '{' and parse from there.
    for i, ch in enumerate(raw):
        if ch in ("{", "["):
            return json.loads(raw[i:])
    raise ValueError(f"No JSON found in console output: {raw!r}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def inspect_entity(guid, component=None, depth=3):
    """Inspect an entity by GUID.

    Parameters
    ----------
    guid : str
        The entity GUID (e.g. "S_Player_Tav_...").
    component : str or None
        If given, dump this component's fields. If None, list all component
        names attached to the entity.
    depth : int
        MaxDepth for Ext.Json.Stringify when dumping a component. Ignored
        when listing component names.

    Returns
    -------
    str
        A JSON string. Either a sorted list of component names, or the
        component object with Beautify=true, or {"error": "..."} on failure.
    """
    if component is None:
        lua = _LUA_LIST_COMPONENTS.replace("{GUID}", guid)
    else:
        lua = (
            _LUA_DUMP_COMPONENT
            .replace("{GUID}", guid)
            .replace("{COMPONENT}", component)
            .replace("{DEPTH}", str(depth))
        )
    return _send_lua(lua)


def search_entities(component=None, name_pattern=None, limit=20):
    """Search live entities, optionally filtered by component type and name pattern.

    Parameters
    ----------
    component : str or None
        If given, restrict to entities that have this component attached.
        Uses ``Ext.Entity.GetAllEntitiesWithComponent``. Required when
        *name_pattern* is None (unbounded iteration is not supported).
    name_pattern : str or None
        Case-insensitive substring to match against entity GUIDs. Applied
        in Python after the Lua query returns.
    limit : int
        Maximum number of results to return (enforced both in Lua and Python).

    Returns
    -------
    str
        A JSON string: list of ``{"guid": "..."}`` objects, or
        ``{"error": "..."}`` on failure.
    """
    if component is None:
        raw = _send_lua(_LUA_SEARCH_ALL_ENTITIES)
    else:
        lua = (
            _LUA_SEARCH_BY_COMPONENT
            .replace("{COMPONENT}", component)
            .replace("{LIMIT}", str(limit))
        )
        raw = _send_lua(lua)

    try:
        items = _parse_response(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        return json.dumps({"error": str(exc)})

    if isinstance(items, dict) and "error" in items:
        return json.dumps(items)

    # Python-side name_pattern filter (GUIDs are the only text we have)
    if name_pattern:
        pat = name_pattern.lower()
        items = [i for i in items if pat in i.get("guid", "").lower()]

    # Honour limit after Python filter
    items = items[:limit]
    return json.dumps(items)


def list_components(namespace=None, search=None, count=False):
    """List all registered component types.

    Parameters
    ----------
    namespace : str or None
        Filter to types whose Name starts with this prefix (e.g. "eoc::").
    search : str or None
        Filter to types whose Name contains this substring (case-insensitive).
    count : bool
        If True, return a JSON object with just {"count": N} rather than the
        full list.

    Returns
    -------
    str
        A JSON string: list of {Name, Kind} objects, or {"count": N}, or
        {"error": "..."} on failure.
    """
    raw = _send_lua(_LUA_ALL_COMPONENT_TYPES)
    try:
        items = _parse_response(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        return json.dumps({"error": str(exc)})

    if isinstance(items, dict) and "error" in items:
        return json.dumps(items)

    # Apply filters
    if namespace:
        items = [i for i in items if i.get("Name", "").startswith(namespace)]
    if search:
        pattern = search.lower()
        items = [i for i in items if pattern in i.get("Name", "").lower()]

    if count:
        return json.dumps({"count": len(items)})

    return json.dumps(items)


# ---------------------------------------------------------------------------
# CLI handlers
# ---------------------------------------------------------------------------

def cmd_entity(args):
    """CLI handler for the `entity` subcommand."""
    guid = args.guid
    component = getattr(args, "component", None)
    depth = getattr(args, "depth", 3) or 3

    print(f"Inspecting entity {guid}...", file=sys.stderr)
    try:
        raw = inspect_entity(guid, component=component, depth=depth)
    except (ConnectionRefusedError, FileNotFoundError, OSError) as exc:
        print(json.dumps({"error": f"Socket connection failed: {exc}"}))
        return 1

    # Try to pretty-print the result
    try:
        parsed = _parse_response(raw)
        if isinstance(parsed, dict) and "error" in parsed:
            print(json.dumps(parsed, indent=2))
            return 1
        if component:
            # Component dump already has Beautify=true from Lua; print as-is
            print(raw)
        else:
            print(json.dumps(parsed, indent=2))
    except (ValueError, json.JSONDecodeError):
        # Fall back to raw output if we can't parse it
        print(raw)

    return 0


def cmd_entity_search(args):
    """CLI handler for the ``entity-search`` subcommand."""
    component = getattr(args, "component", None)
    name_pattern = getattr(args, "name_pattern", None)
    limit = getattr(args, "limit", 20) or 20

    print("Searching entities...", file=sys.stderr)
    try:
        result = search_entities(component=component, name_pattern=name_pattern, limit=limit)
    except (ConnectionRefusedError, FileNotFoundError, OSError) as exc:
        print(json.dumps({"error": f"Socket connection failed: {exc}"}))
        return 1

    try:
        parsed = json.loads(result)
        if isinstance(parsed, dict) and "error" in parsed:
            print(json.dumps(parsed, indent=2))
            return 1
        print(json.dumps(parsed, indent=2))
    except json.JSONDecodeError:
        print(result)

    return 0


def cmd_components(args):
    """CLI handler for the `components` subcommand."""
    namespace = getattr(args, "namespace", None)
    search = getattr(args, "search", None)
    count_only = getattr(args, "count", False)

    print("Querying component registry...", file=sys.stderr)
    try:
        result = list_components(namespace=namespace, search=search, count=count_only)
    except (ConnectionRefusedError, FileNotFoundError, OSError) as exc:
        print(json.dumps({"error": f"Socket connection failed: {exc}"}))
        return 1

    try:
        parsed = json.loads(result)
        if isinstance(parsed, dict) and "error" in parsed:
            print(json.dumps(parsed, indent=2))
            return 1
        print(json.dumps(parsed, indent=2))
    except json.JSONDecodeError:
        print(result)

    return 0
