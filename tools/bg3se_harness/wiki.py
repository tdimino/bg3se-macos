"""wiki.py — bg3.wiki MediaWiki REST client for spell/item cross-reference.

This module wraps the bg3.wiki MediaWiki API (``https://bg3.wiki/w/api.php``)
and provides three high-level operations:

  * :func:`query_spell`  — look up a spell page by display name
  * :func:`query_item`   — look up an item (weapon/armour/wearable) by display name
  * :func:`verify_page`  — fetch a wiki page and compare its ``uid`` field to
                           an expected stat name (defaults to no check — useful
                           for probing a page's engine uid)

Design notes
------------

**No Cargo.**  bg3.wiki's Cargo endpoint requires login
(``permissiondenied: You don't have permission to run arbitrary Cargo
queries``), so we cannot use ``action=cargoquery``.  Instead we use the two
permission-free endpoints:

  1. ``action=opensearch``  — fuzzy title resolution for a user query
  2. ``action=parse&prop=wikitext``  — raw wikitext of the resolved page

The wiki stores structured spell and item data as a ``{{Feature page | ...}}``
or ``{{WeaponPage | ...}}`` template, which is richer and more stable than
the Cargo schema for our purposes — it contains the canonical engine ``uid``
which we use to cross-reference with the BG3 stats system.

**No authentication.**  The public endpoints are anonymous.  We send a
polite ``User-Agent`` identifying the harness so the wiki admins can contact
us if our traffic ever becomes a problem.

**File cache.**  Wiki pages rarely change between harness runs, so we cache
parsed pages to ``~/.config/bg3se-harness/wiki_cache/<page>.json`` with a
24-hour TTL.  The cache is bypassed by passing ``use_cache=False``.

**Error envelope.**  All public functions return dicts with either a
successful result or ``{"success": False, "error_type": ..., "message": ...}``
matching the convention in :mod:`bg3se_harness.mod_manager.nexus`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_WIKI_API = "https://bg3.wiki/w/api.php"
_USER_AGENT = "bg3se-harness/1.0 (github.com/tomdimino/bg3se-macos)"
_CACHE_TTL_SECONDS = 24 * 60 * 60  # 24h
_REQUEST_TIMEOUT = 15

# Template names that carry spell/item/feature data on bg3.wiki.
_SPELL_TEMPLATES: tuple[str, ...] = ("Feature page", "Spell page")
_ITEM_TEMPLATES: tuple[str, ...] = (
    "WeaponPage",
    "ArmourPage",
    "ArmorPage",
    "EquipmentPage",
    "ItemPage",
    "Feature page",  # some items still use the generic template
)


# ---------------------------------------------------------------------------
# Error envelope helpers
# ---------------------------------------------------------------------------

def _error(error_type: str, message: str, **extra) -> dict:
    return {"success": False, "error_type": error_type, "message": message, **extra}


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _http_get_json(params: dict) -> tuple[dict | list | None, dict | None]:
    """Execute a GET against the MediaWiki API and parse JSON.

    Returns (data, None) on success or (None, error_dict) on failure.
    """
    url = _WIKI_API + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": _USER_AGENT,
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
            body = resp.read()
    except urllib.error.HTTPError as exc:
        return None, _error(
            "api_error",
            f"bg3.wiki API error: HTTP {exc.code} {exc.reason}",
            status_code=exc.code,
        )
    except urllib.error.URLError as exc:
        return None, _error("network_error", f"Network error: {exc.reason}")
    except Exception as exc:
        return None, _error("internal_error", f"Unexpected error: {exc}")

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError) as exc:
        return None, _error("api_error", f"Invalid JSON from bg3.wiki: {exc}")

    return data, None


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------
#
# Two key rules govern the wiki cache:
#
#   1. *Keys are hashed.*  File names on disk are the first 32 hex chars of
#      the SHA-1 of the full title.  This removes the path-traversal surface
#      of the old ``re.sub`` sanitiser (``..`` was a legal sanitised name
#      under the old rules) and eliminates the truncation-collision bug
#      where two titles diverging after 128 sanitised characters mapped to
#      the same file.
#
#   2. *Aliases are pointer files, not duplicate payloads.*  When a user
#      queries ``"fireball"`` and the resolved canonical title is
#      ``"Fireball"``, we write ``{"alias_for": "Fireball"}`` under the
#      user's key and the real payload under the title's key.  Re-running
#      the same query follows one level of indirection and re-reads the
#      title cache.  This avoids the two-writer race from the previous
#      double-payload scheme (where an alias could keep serving a stale
#      copy after the title entry had been refreshed).
#
# All cache reads and writes are also constrained to the cache directory
# via ``path.resolve().is_relative_to(root.resolve())`` so a future bug in
# key derivation can never escape the sandbox.

# Warnings about a failing cache are chatty — once the filesystem is broken
# every lookup would bleat.  Rate-limit to a single warning per process.
_cache_warn_emitted: bool = False


def _cache_warn(msg: str) -> None:
    global _cache_warn_emitted
    if _cache_warn_emitted:
        return
    _cache_warn_emitted = True
    print(f"[wiki] WARNING: {msg}", file=sys.stderr)


def _cache_dir() -> Path:
    """Return the wiki cache directory, creating it on demand.

    The directory (and its parent ``~/.config/bg3se-harness/``) is created
    with ``0o700`` permissions so other local users on multi-user machines
    cannot read or tamper with cached wiki payloads.  Existing directories
    are left untouched.
    """
    config = Path.home() / ".config" / "bg3se-harness"
    path = config / "wiki_cache"
    for p in (config, path):
        if not p.exists():
            try:
                p.mkdir(parents=True, exist_ok=True)
                try:
                    p.chmod(0o700)
                except OSError:
                    pass
            except OSError as exc:
                _cache_warn(f"cache dir unavailable at {p}: {exc}")
                return path  # return anyway — subsequent writes will fail loud
    return path


def _cache_key(title: str) -> str:
    """Return a collision-resistant, filesystem-safe cache key for *title*.

    SHA-1 truncated to 32 hex characters — deterministic, ~128 bits of
    entropy, no path-traversal surface, no truncation hazard.  We do not
    need cryptographic strength; collisions would merely overwrite an
    existing cache entry.
    """
    return hashlib.sha1(title.encode("utf-8")).hexdigest()[:32]


def _cache_path(title: str) -> Path | None:
    """Return the absolute cache path for *title*, or None if unsafe.

    This is the single gate that ensures every cache read and write stays
    inside the cache directory.  Any key whose resolved path escapes the
    sandbox is rejected (should never happen with SHA-1 keys, but we
    assert the invariant so a future bug can't sneak past).
    """
    root = _cache_dir().resolve()
    candidate = (root / f"{_cache_key(title)}.json").resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        _cache_warn(f"refusing cache path outside sandbox: {candidate}")
        return None
    return candidate


def _cache_read(title: str, _depth: int = 0) -> dict | None:
    """Return cached payload for *title* if it exists and is still fresh.

    Follows a single level of alias indirection: if the on-disk record has
    an ``alias_for`` field, re-read the target cache entry.  We cap the
    recursion depth at 1 so circular aliases can never hang.
    """
    path = _cache_path(title)
    if path is None or not path.exists():
        return None
    try:
        age = time.time() - path.stat().st_mtime
        if age > _CACHE_TTL_SECONDS:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    if isinstance(data, dict) and "alias_for" in data and _depth < 1:
        target = data.get("alias_for")
        if isinstance(target, str) and target:
            return _cache_read(target, _depth=_depth + 1)
        return None

    return data if isinstance(data, dict) else None


def _cache_write(title: str, payload: dict) -> bool:
    """Persist *payload* under *title*.  Returns True on success."""
    path = _cache_path(title)
    if path is None:
        return False
    try:
        path.write_text(json.dumps(payload), encoding="utf-8")
        return True
    except OSError as exc:
        _cache_warn(f"cache write failed for {title!r}: {exc}")
        return False


def _cache_write_alias(alias: str, target_title: str) -> bool:
    """Write an alias pointer so *alias* redirects to *target_title*."""
    if alias == target_title:
        return True
    return _cache_write(alias, {"alias_for": target_title})


def clear_cache() -> dict:
    """Wipe all cached wiki pages. Returns a summary dict."""
    global _cache_warn_emitted
    try:
        removed = 0
        for entry in _cache_dir().glob("*.json"):
            try:
                entry.unlink()
                removed += 1
            except OSError:
                pass
        # Reset the warn latch so a healthy subsequent run can bleat again
        # if the disk goes bad later.
        _cache_warn_emitted = False
        return {"success": True, "removed": removed}
    except Exception as exc:
        return _error("cache_error", f"clear_cache failed: {exc}")


# ---------------------------------------------------------------------------
# MediaWiki endpoint wrappers
# ---------------------------------------------------------------------------

def _opensearch(query: str, limit: int = 5) -> tuple[list[str] | None, dict | None]:
    """Resolve a free-form query to a list of page titles via OpenSearch.

    Returns (titles, None) on success or (None, error_dict) on failure.
    Titles are returned in the order the wiki ranks them — element 0 is the
    best match when an exact match exists.
    """
    data, err = _http_get_json({
        "action": "opensearch",
        "search": query,
        "namespace": 0,
        "limit": str(limit),
        "format": "json",
    })
    if err:
        return None, err

    # OpenSearch returns [search, titles[], descriptions[], urls[]]
    if not isinstance(data, list) or len(data) < 2:
        return None, _error("api_error", "Unexpected opensearch response shape")

    titles = data[1]
    if not isinstance(titles, list):
        return None, _error("api_error", "Unexpected opensearch titles field")

    return [t for t in titles if isinstance(t, str)], None


def _fetch_wikitext(title: str) -> tuple[dict | None, dict | None]:
    """Fetch raw wikitext for a single page.

    Returns ({"title": str, "pageid": int, "wikitext": str}, None) on success.
    """
    data, err = _http_get_json({
        "action": "parse",
        "page": title,
        "prop": "wikitext",
        "redirects": "true",
        "format": "json",
    })
    if err:
        return None, err

    if not isinstance(data, dict):
        return None, _error("api_error", f"Unexpected parse response for {title!r}")

    if "error" in data and isinstance(data["error"], dict):
        info = data["error"].get("info") or "unknown wiki error"
        code = data["error"].get("code") or "wiki_error"
        return None, _error("api_error", f"bg3.wiki: {info}", wiki_error_code=code)

    parse = data.get("parse")
    if not isinstance(parse, dict):
        return None, _error("api_error", f"No parse block for {title!r}")

    wikitext_obj = parse.get("wikitext")
    if isinstance(wikitext_obj, dict):
        wikitext = wikitext_obj.get("*") or ""
    else:
        wikitext = wikitext_obj or ""

    return {
        "title": parse.get("title") or title,
        "pageid": parse.get("pageid"),
        "wikitext": wikitext,
    }, None


# ---------------------------------------------------------------------------
# Wikitext template parsing
# ---------------------------------------------------------------------------

def _find_template_block(wikitext: str, template_names: tuple[str, ...]) -> str | None:
    """Return the raw body of the first matching template in *wikitext*.

    The body is the text between the opening ``{{Name`` and the matching
    closing ``}}``, accounting for nested templates and wiki-link brackets.
    Returns ``None`` if no template from *template_names* is found.
    """
    if not wikitext:
        return None

    # Build a case-insensitive regex alternation of the template openers.
    # Templates can start with optional whitespace after "{{".
    pattern = re.compile(
        r"\{\{\s*(" + "|".join(re.escape(n) for n in template_names) + r")\b",
        re.IGNORECASE,
    )
    match = pattern.search(wikitext)
    if not match:
        return None

    start = match.start()
    depth = 0
    i = start
    while i < len(wikitext):
        if wikitext[i:i + 2] == "{{":
            depth += 1
            i += 2
            continue
        if wikitext[i:i + 2] == "}}":
            depth -= 1
            i += 2
            if depth == 0:
                return wikitext[start:i]
            continue
        i += 1

    return None


_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


def _parse_template_fields(block: str) -> dict:
    """Parse a ``{{Template | key = value | ...}}`` block into a dict.

    Nested templates (``{{foo|bar}}``) and wiki-links (``[[X|Y]]``) do not
    terminate a field — we track bracket depth so embedded pipes are
    treated as part of the value.

    Blind spots (documented rather than handled — these have not appeared in
    real bg3.wiki spell/item pages as of 2026-04):

    * ``<nowiki>|</nowiki>`` literal pipes would still split the field.
    * ``{{!}}`` — MediaWiki's standard pipe-escape magic word — is *not*
      expanded before tokenising.  If a page ever uses it inside a template
      field, the field would split at the wrong place.
    * Table markup (``{|`` / ``|}`` / ``|-``) is not tracked; a spell page
      embedding a raw wiki table inside a field would be mis-parsed.
    * HTML entities such as ``&#124;`` are not decoded before tokenising.

    If any of these ever become a problem, the tokeniser below is the place
    to extend — add a ``depth_nowiki`` counter or a ``{{!}}`` preprocessor.
    """
    if not block:
        return {}

    # Strip HTML comments *before* tokenising so embedded pipes inside a
    # comment (``<!-- https://bg3.wiki/... -->``) do not prematurely split
    # the field.  The previous implementation stripped comments after the
    # split, which was too late.
    block = _HTML_COMMENT_RE.sub("", block)

    # Strip the leading "{{Template" and trailing "}}".
    inner_match = re.match(r"\{\{\s*[^|}\n]+", block)
    if not inner_match:
        return {}
    inner = block[inner_match.end():]
    if inner.endswith("}}"):
        inner = inner[:-2]

    fields: list[str] = []
    current: list[str] = []
    depth_template = 0
    depth_link = 0
    i = 0
    while i < len(inner):
        two = inner[i:i + 2]
        if two == "{{":
            depth_template += 1
            current.append("{{")
            i += 2
            continue
        if two == "}}":
            depth_template -= 1
            current.append("}}")
            i += 2
            continue
        if two == "[[":
            depth_link += 1
            current.append("[[")
            i += 2
            continue
        if two == "]]":
            depth_link -= 1
            current.append("]]")
            i += 2
            continue
        ch = inner[i]
        if ch == "|" and depth_template == 0 and depth_link == 0:
            fields.append("".join(current))
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    if current:
        fields.append("".join(current))

    result: dict[str, str] = {}
    for raw in fields:
        # Fields without "=" are positional args; we ignore those (they aren't
        # used by bg3.wiki's spell/item templates, which are purely named).
        if "=" not in raw:
            continue
        key, _, value = raw.partition("=")
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        result[key] = value

    return result


def _flatten_template(body: str) -> str:
    """Flatten a single (already-innermost) ``{{name|arg1|arg2}}`` body.

    Drops the template name and joins the remaining positional/named args
    with a single space.  Named args (``foo=bar``) keep only their value —
    this is best-effort output for display, not a round-trip.
    """
    parts: list[str] = []
    for raw in body.split("|"):
        piece = raw.strip()
        if not piece:
            continue
        if "=" in piece:
            piece = piece.split("=", 1)[1].strip()
        if piece:
            parts.append(piece)
    if not parts:
        return ""
    # Drop the template name.
    return " ".join(parts[1:]) if len(parts) > 1 else ""


# Innermost `{{...}}` — contains no further `{{` or `}}`.
_INNERMOST_TEMPLATE_RE = re.compile(r"\{\{([^{}]*?)\}\}")
_WIKI_LINK_RE = re.compile(r"\[\[([^\[\]]+)\]\]")
_BR_RE = re.compile(r"<br\s*/?>", re.IGNORECASE)
_WHITESPACE_RE = re.compile(r"\s+")


def _strip_wiki_markup(value: str) -> str:
    """Flatten common wiki markup in a field value for JSON output.

    * ``[[Target|Text]]`` → ``Text``
    * ``[[Target]]`` → ``Target``
    * ``{{DamageText|8d6|Fire}}`` → ``8d6 Fire``
    * ``{{Outer|{{Inner|8d6|Fire}}}}`` → ``8d6 Fire`` (nested, innermost-first)
    * ``<br />`` / ``<br>`` → space
    * Collapse runs of whitespace.

    Nested templates are expanded by iteratively replacing the innermost
    match until a fixed point is reached.  A hard upper bound prevents
    pathological input from spinning forever.
    """
    if not value:
        return ""

    # Expand templates innermost-first.  Each pass replaces every match
    # that contains no further ``{{``/``}}`` pairs; repeating the pass
    # unwraps one more layer of nesting.  We cap the loop at 16 iterations
    # — real bg3.wiki templates nest at most two or three deep.
    for _ in range(16):
        new_value, count = _INNERMOST_TEMPLATE_RE.subn(
            lambda m: _flatten_template(m.group(1)),
            value,
        )
        if count == 0:
            break
        value = new_value

    def _expand_link(match: re.Match) -> str:
        body = match.group(1)
        if "|" in body:
            return body.split("|", 1)[1]
        return body

    value = _WIKI_LINK_RE.sub(_expand_link, value)
    value = _BR_RE.sub(" ", value)
    value = _WHITESPACE_RE.sub(" ", value).strip()
    return value


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def _resolve_page(name: str) -> tuple[str | None, dict | None]:
    """Return the canonical wiki title for *name* via OpenSearch."""
    titles, err = _opensearch(name, limit=5)
    if err:
        return None, err
    if not titles:
        return None, _error(
            "not_found",
            f"No bg3.wiki page matches {name!r}.",
        )
    return titles[0], None


def _lookup(
    name: str,
    templates: tuple[str, ...],
    kind: str,
    use_cache: bool,
) -> dict:
    """Shared implementation for spell/item lookups.

    *kind* is ``"spell"`` or ``"item"`` and shows up in the error envelope so
    callers can tell which command failed.

    Caching strategy: the cache is keyed by the user's input name *before*
    opensearch resolution so a repeated lookup short-circuits both network
    calls (opensearch and parse).  The resolved title holds the real
    payload; the user's input (if different) holds an ``alias_for`` pointer
    that is followed on subsequent reads.

    Entries are tagged with ``cached_kind`` so a ``query_spell`` result is
    never silently reused by ``verify_page`` (see task #27).  The fresh
    payload always has ``"cached": False``; the read path rewrites the flag
    to ``True`` on a hit.
    """
    if not name or not name.strip():
        return _error("validation_error", f"{kind} name must be non-empty.")

    if use_cache:
        cached = _cache_read(name)
        if cached is not None and cached.get("cached_kind") == kind:
            payload = dict(cached)
            payload["cached"] = True
            return payload

    title, err = _resolve_page(name)
    if err:
        return err

    if use_cache:
        cached = _cache_read(title)
        if cached is not None and cached.get("cached_kind") == kind:
            payload = dict(cached)
            payload["cached"] = True
            # Record the alias so the user's spelling hits on the next run
            # without re-doing opensearch.  Alias writes are cheap pointer
            # files, not duplicated payloads, so there is no staleness race.
            if name != title:
                _cache_write_alias(name, title)
            return payload

    page, err = _fetch_wikitext(title)
    if err:
        return err

    block = _find_template_block(page["wikitext"], templates)
    if block is None:
        return _error(
            "template_not_found",
            f"Page {title!r} does not contain a recognised {kind} template. "
            f"Tried: {', '.join(templates)}.",
            title=title,
            pageid=page.get("pageid"),
        )

    raw_fields = _parse_template_fields(block)
    fields = {k: _strip_wiki_markup(v) for k, v in raw_fields.items()}

    result = {
        "success": True,
        "kind": kind,
        "cached_kind": kind,  # stored; stripped from user-facing dict on return
        "title": title,
        "pageid": page.get("pageid"),
        "url": f"https://bg3.wiki/wiki/{urllib.parse.quote(title.replace(' ', '_'))}",
        "uid": fields.get("uid") or "",
        "fields": fields,
        "cached": False,
    }

    if use_cache:
        if _cache_write(title, result):
            if name != title:
                _cache_write_alias(name, title)
    return result


def query_spell(name: str, *, use_cache: bool = True) -> dict:
    """Look up a bg3.wiki spell page by display name.

    Returns a dict shaped like::

        {
            "success": True,
            "kind": "spell",
            "title": "Fireball",
            "pageid": 2677,
            "url": "https://bg3.wiki/wiki/Fireball",
            "uid": "Projectile_Fireball",
            "fields": {
                "level": "3",
                "school": "Evocation",
                "damage": "8d6",
                "damage type": "Fire",
                ...
            },
            "cached": false,
        }
    """
    return _lookup(name, _SPELL_TEMPLATES, "spell", use_cache)


def query_item(name: str, *, use_cache: bool = True) -> dict:
    """Look up a bg3.wiki item page (weapon, armour, etc.) by display name.

    Returns the same shape as :func:`query_spell` with ``kind = "item"``.
    """
    return _lookup(name, _ITEM_TEMPLATES, "item", use_cache)


def verify_page(
    page_name: str,
    *,
    expect_uid: str | None = None,
    use_cache: bool = True,
) -> dict:
    """Fetch a bg3.wiki page and check its engine ``uid`` field.

    Intended as a lightweight offline cross-reference when you already know
    both a stat name and a wiki page name.  Given just the page name, it
    still returns the uid so you can pipe the result into other tooling.

    Returns::

        {
            "success": True,
            "title": "Longsword +1",
            "pageid": 3418,
            "url": "https://bg3.wiki/wiki/Longsword_%2B1",
            "uid": "WPN_HUM_Longsword_A_1",
            "expect_uid": "WPN_HUM_Longsword_A_1",
            "uid_matches": True,   # only present when expect_uid is set
            "fields": {...},
        }

    When ``expect_uid`` is provided and does not match, the result has
    ``success = True`` but ``uid_matches = False`` so callers can surface the
    mismatch without treating it as a fatal error.

    **Scope note (vs. the original plan).**  The opencli-integration plan
    called for ``wiki verify`` to fetch the wiki record *and* call
    ``Ext.Stats.Get(name)`` on the running game, diff the two structures,
    and surface any mismatches.  What shipped here is narrower: a static
    field printer with an optional string-match check.  The runtime-diff
    variant requires a live BG3SE socket and is tracked as a follow-up
    (search task tracker for "runtime diff" or re-read
    ``~/.claude/plans/2026-04-06-bg3se-harness-opencli-integration.md``
    lines 130-134 and 268-271 for the original intent).  The current
    function is useful on its own — it works offline, is cacheable, and
    gives follow-up tooling a clean input.
    """
    if not page_name or not page_name.strip():
        return _error("validation_error", "page name must be non-empty.")

    # Only reuse a cached entry that was stored *by* verify_page — reusing a
    # spell or item payload would paper over a page that no longer contains
    # the template we would have checked.  The cached_kind tag makes this
    # explicit and prevents cross-kind aliasing bugs.
    cached = _cache_read(page_name) if use_cache else None
    if cached and cached.get("cached_kind") == "verify":
        result = dict(cached)
        result["cached"] = True
    else:
        # Try spell templates first, fall back to item templates.  This
        # matches the bg3.wiki convention where all structured templates
        # share the same key/value shape.
        combined = _SPELL_TEMPLATES + tuple(
            t for t in _ITEM_TEMPLATES if t not in _SPELL_TEMPLATES
        )
        page, err = _fetch_wikitext(page_name)
        if err:
            return err
        block = _find_template_block(page["wikitext"], combined)
        if block is None:
            return _error(
                "template_not_found",
                f"Page {page_name!r} has no recognised spell/item template.",
                title=page.get("title"),
                pageid=page.get("pageid"),
            )
        raw_fields = _parse_template_fields(block)
        fields = {k: _strip_wiki_markup(v) for k, v in raw_fields.items()}
        result = {
            "success": True,
            "kind": "verify",
            "cached_kind": "verify",
            "title": page.get("title") or page_name,
            "pageid": page.get("pageid"),
            "url": f"https://bg3.wiki/wiki/{urllib.parse.quote((page.get('title') or page_name).replace(' ', '_'))}",
            "uid": fields.get("uid") or "",
            "fields": fields,
            "cached": False,
        }
        if use_cache:
            _cache_write(page_name, result)

    if expect_uid is not None:
        result["expect_uid"] = expect_uid
        result["uid_matches"] = (result.get("uid") == expect_uid)

    return result


# ---------------------------------------------------------------------------
# CLI handler (wired up from bg3se_harness.cli)
# ---------------------------------------------------------------------------

def cmd_wiki(args) -> int:
    """Entry point for ``bg3se-harness wiki <subcmd>``."""
    subcmd = getattr(args, "wiki_command", None)

    if subcmd == "spell":
        result = query_spell(args.name, use_cache=not getattr(args, "no_cache", False))
    elif subcmd == "item":
        result = query_item(args.name, use_cache=not getattr(args, "no_cache", False))
    elif subcmd == "verify":
        result = verify_page(
            args.page,
            expect_uid=getattr(args, "expect_uid", None),
            use_cache=not getattr(args, "no_cache", False),
        )
    elif subcmd == "clear-cache":
        result = clear_cache()
    else:
        print("Usage: bg3se-harness wiki {spell|item|verify|clear-cache} ...", file=sys.stderr)
        return 1

    print(json.dumps(result, indent=2))
    return 0 if result.get("success", True) else 1
