"""nexus.py — Nexus Mods API v1 client for BG3SE harness.

Game domain: baldursgate3
Base URL:    https://api.nexusmods.com/v1

Authentication: API key, read from environment variable NEXUS_API_KEY or
from the file ~/.config/bg3se-harness/nexus_api_key (first non-empty line).

Rate limiting: Nexus enforces hourly and daily request caps.  The client
tracks the X-RL-Hourly-Remaining and X-RL-Daily-Remaining response headers
and emits a stderr warning when either drops below 10.

Premium gate: The download_link endpoint requires a Nexus Premium account.
Free users receive a structured error dict with a browser URL so they can
download manually.

All public functions return dicts.  Errors are indicated by a top-level
"success": False key combined with an "error_type" string and a human-readable
"message".  Network-level exceptions never propagate to the caller.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_API_BASE = "https://api.nexusmods.com/v1"
_DEFAULT_GAME = "baldursgate3"
_RATE_WARN_THRESHOLD = 10

# ---------------------------------------------------------------------------
# API key resolution
# ---------------------------------------------------------------------------

def _load_api_key() -> str | None:
    """Return the Nexus API key, or None if not configured.

    Resolution order:
    1. NEXUS_API_KEY environment variable
    2. ~/.config/bg3se-harness/nexus_api_key (first non-empty line)
    """
    key = os.environ.get("NEXUS_API_KEY", "").strip()
    if key:
        return key

    key_file = Path.home() / ".config" / "bg3se-harness" / "nexus_api_key"
    if key_file.exists():
        try:
            for line in key_file.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    return stripped
        except OSError:
            pass

    return None


# ---------------------------------------------------------------------------
# Rate-limit tracking (module-level state, reset per process)
# ---------------------------------------------------------------------------

_rate_state: dict[str, int | None] = {
    "hourly_remaining": None,
    "daily_remaining": None,
    "hourly_limit": None,
    "daily_limit": None,
}


def _update_rate_state(headers) -> None:
    """Update module-level rate state from urllib response headers."""
    mapping = {
        "X-RL-Hourly-Remaining": "hourly_remaining",
        "X-RL-Daily-Remaining": "daily_remaining",
        "X-RL-Hourly-Limit": "hourly_limit",
        "X-RL-Daily-Limit": "daily_limit",
    }
    for header, key in mapping.items():
        raw = headers.get(header)
        if raw is not None:
            try:
                _rate_state[key] = int(raw)
            except ValueError:
                pass

    # Warn when running low
    for label, key in (("Hourly", "hourly_remaining"), ("Daily", "daily_remaining")):
        val = _rate_state[key]
        if val is not None and val < _RATE_WARN_THRESHOLD:
            print(
                f"[nexus] WARNING: {label} API requests remaining: {val}",
                file=sys.stderr,
            )


# ---------------------------------------------------------------------------
# Internal HTTP helpers
# ---------------------------------------------------------------------------

def _make_request(
    path: str,
    params: dict | None = None,
    api_key: str | None = None,
) -> tuple[dict | list, int]:
    """Perform a GET request against the Nexus API.

    Returns (parsed_json, status_code).
    Raises urllib.error.HTTPError / urllib.error.URLError on failure —
    callers convert these to error dicts.

    The api_key argument, if provided, overrides _load_api_key().
    """
    key = api_key or _load_api_key()
    if not key:
        raise RuntimeError("no_api_key")

    url = _API_BASE + path
    if params:
        url = url + "?" + urllib.parse.urlencode(params)

    req = urllib.request.Request(
        url,
        headers={
            "apikey": key,
            "Accept": "application/json",
            "User-Agent": "bg3se-harness/1.0 (github.com/tomdimino/bg3se-macos)",
        },
    )

    with urllib.request.urlopen(req, timeout=15) as resp:
        _update_rate_state(resp.headers)
        body = resp.read()
        status = resp.status
        return json.loads(body), status


def _error(error_type: str, message: str, **extra) -> dict:
    """Build a canonical error dict."""
    return {"success": False, "error_type": error_type, "message": message, **extra}


# Strong content-restriction markers — any of these in the 403 body forces
# classification as content_restricted regardless of path.  Keep these specific:
# generic phrases like "not available" are too broad (they also match "Service
# not available" or "Endpoint not available" auth-key errors).
_CONTENT_RESTRICTION_MARKERS: tuple[str, ...] = (
    "adult",
    "content blocking",
    "content filter",
    "content warning",
    "blocked content",
    "permission to view",
    "not allowed to view",
    "restricted content",
    "hidden by the author",
    "mod not available",  # Nexus's canonical phrase for hidden / blocked mods
)

# Auth-only paths: a 403 here is definitively an API key problem, never a
# per-mod content block.
_AUTH_PATH_PREFIXES: tuple[str, ...] = (
    "/users/",
)

# Per-mod detail paths.  A 403 here means Nexus is blocking a specific mod for
# this user, not that the API key is bad.  Matches ``/mods/<digits>`` in both
# ``/v1/games/<game>/mods/1234.json`` and ``/v1/games/<game>/mods/1234/files/...``
# while excluding collection endpoints like ``/mods/search.json`` or
# ``/mods/updated.json``.
_MOD_DETAIL_PATH_RE = re.compile(r"/mods/\d+(?:[/.]|$)")

_MOD_CONTENT_RESTRICTED_HINT = (
    "This mod is hidden by Nexus content filters (adult content, per-mod "
    "content blocking, hidden-by-author, or moderation). Adjust your "
    "preferences at https://www.nexusmods.com/users/myaccount?tab=content+blocking "
    "or view the mod in a logged-in browser."
)

_AUTH_FALLBACK_HINT = (
    "Nexus API authentication failed (HTTP 403). "
    "Verify your API key at https://www.nexusmods.com/users/myaccount?tab=api."
)


def _classify_403(
    path: str,
    body_text: str,
    body_json: dict | None,
) -> tuple[str, str]:
    """Classify a 403 response as either content-restricted or auth failure.

    Returns ``(error_type, message)`` where ``error_type`` is either
    ``content_restricted`` or ``auth_error``.

    Classification strategy (first match wins):

    1. Path whitelisted as auth-only (``/users/...``)     → ``auth_error``
    2. Body text contains any strong restriction marker   → ``content_restricted``
    3. Path targets a specific mod (``/mods/<id>``)       → ``content_restricted``
    4. Fallback                                           → ``auth_error``

    The per-mod path rule is the critical fix: a successfully-authenticated
    call that receives 403 on a specific mod almost always means Nexus is
    blocking that mod for this user (hidden, moderated, adult content, etc.),
    not that the API key is bad.  If the key were bad, the auth would have
    failed at the validation endpoint long before we reached mod-detail paths.

    Rule 3 deliberately uses a strict ``/mods/\\d+`` regex so that collection
    endpoints such as ``/mods/search.json`` and ``/mods/updated.json`` fall
    through to the auth fallback — a 403 on a collection endpoint is always
    an API key problem.
    """
    api_message = ""
    if isinstance(body_json, dict):
        raw_msg = body_json.get("message")
        if isinstance(raw_msg, str):
            api_message = raw_msg

    haystack = f"{api_message} {body_text or ''}".lower()

    # Rule 1: auth-only paths always mean bad key.
    if any(path.startswith(prefix) for prefix in _AUTH_PATH_PREFIXES):
        return "auth_error", api_message or _AUTH_FALLBACK_HINT

    # Rule 2: strong body markers force content-restricted classification.
    if any(marker in haystack for marker in _CONTENT_RESTRICTION_MARKERS):
        message = api_message or _MOD_CONTENT_RESTRICTED_HINT
        if api_message:
            # Pair Nexus's terse phrase with our actionable hint.
            message = f"{api_message} — {_MOD_CONTENT_RESTRICTED_HINT}"
        return "content_restricted", message

    # Rule 3: per-mod detail paths → content-restricted by default.
    if _MOD_DETAIL_PATH_RE.search(path):
        message = _MOD_CONTENT_RESTRICTED_HINT
        if api_message:
            message = f"{api_message} — {_MOD_CONTENT_RESTRICTED_HINT}"
        return "content_restricted", message

    # Rule 4: fallback to auth failure.
    return "auth_error", api_message or _AUTH_FALLBACK_HINT


def _try_request(path: str, params: dict | None = None) -> tuple[dict | list | None, dict | None]:
    """Execute _make_request and translate exceptions to error dicts.

    Returns (data, None) on success or (None, error_dict) on failure.
    """
    try:
        data, _ = _make_request(path, params)
        return data, None
    except RuntimeError as exc:
        if str(exc) == "no_api_key":
            return None, _error(
                "auth_error",
                "No Nexus API key found. Set NEXUS_API_KEY or create "
                "~/.config/bg3se-harness/nexus_api_key.",
            )
        return None, _error("internal_error", str(exc))
    except urllib.error.HTTPError as exc:
        # Read the body once — multiple branches below want to sniff it.
        # HTTPError exposes a file-like object; reading it can raise OSError
        # (network truncation) or AttributeError (if ``fp`` is None, as in
        # some synthetic tests).  We deliberately don't swallow arbitrary
        # exceptions here so real bugs surface in logs.
        body_text = ""
        body_json: dict | None = None
        try:
            raw = exc.read()
        except (OSError, AttributeError, ValueError):
            raw = b""
        if raw:
            body_text = raw.decode("utf-8", errors="replace")
            try:
                parsed = json.loads(body_text)
                if isinstance(parsed, dict):
                    body_json = parsed
            except (json.JSONDecodeError, ValueError):
                pass

        if exc.code == 401:
            return None, _error(
                "auth_error",
                "Nexus API authentication failed (HTTP 401). "
                "Verify your API key at https://www.nexusmods.com/users/myaccount?tab=api.",
                status_code=exc.code,
            )

        if exc.code == 403:
            error_type, message = _classify_403(path, body_text, body_json)
            return None, _error(error_type, message, status_code=exc.code)

        api_message = (body_json or {}).get("message") if body_json else None
        msg = api_message or str(exc)
        return None, _error("api_error", msg, status_code=exc.code)
    except urllib.error.URLError as exc:
        return None, _error("network_error", f"Network error: {exc.reason}")
    except Exception as exc:
        return None, _error("internal_error", f"Unexpected error: {exc}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_api_status() -> dict:
    """Check API key validity and current rate limit status.

    Returns::

        {
            "valid": bool,
            "name": str,           # Nexus username
            "is_premium": bool,
            "hourly_limit": int,
            "hourly_remaining": int,
            "daily_limit": int,
            "daily_remaining": int,
        }

    On failure returns ``{"success": False, "error_type": ..., "message": ...}``.
    """
    data, err = _try_request("/users/validate.json")
    if err:
        return err

    return {
        "valid": True,
        "name": data.get("name", ""),
        "is_premium": bool(data.get("is_premium")),
        "hourly_limit": _rate_state["hourly_limit"],
        "hourly_remaining": _rate_state["hourly_remaining"],
        "daily_limit": _rate_state["daily_limit"],
        "daily_remaining": _rate_state["daily_remaining"],
    }


def search_mods(query: str, game: str = _DEFAULT_GAME) -> dict:
    """Search Nexus Mods for mods matching *query*.

    The Nexus search API is limited (no full-text search on free tier).
    This function calls /mods/search.json when available and falls back to
    /mods/updated.json with client-side name filtering.

    Returns::

        {
            "results": [
                {
                    "name": str,
                    "mod_id": int,
                    "summary": str,
                    "author": str,
                    "endorsements": int,
                    "downloads": int,
                }
            ],
            "count": int,
        }

    On failure returns ``{"success": False, ...}``.
    """
    # Try the search endpoint first.  The Nexus API exposes this for Nexus
    # site search but not all API keys support it — fall through gracefully.
    # The server applies its own ranking, so we skip the client-side substring
    # filter and trust the endpoint's result set.
    data, err = _try_request(
        f"/games/{game}/mods/search.json",
        params={"q": query},
    )
    if err is None and isinstance(data, list):
        return _format_search_results(data, query_filter="")

    # Fallback: fetch recently-updated mods and filter client-side by the
    # raw user query.
    data, err = _try_request(
        f"/games/{game}/mods/updated.json",
        params={"period": "1m"},
    )
    if err:
        return err

    if not isinstance(data, list):
        return {"results": [], "count": 0}

    return _format_search_results(data, query_filter=query)


def _format_search_results(raw: list, query_filter: str = "") -> dict:
    """Normalise a raw Nexus mod list, optionally filtering by query string.

    When *query_filter* is empty the raw list is returned as-is (used for
    server-ranked search results).  When non-empty, each entry is kept only
    if the query substring appears in the mod name or summary.
    """
    query_lower = query_filter.lower()
    results = []
    for mod in raw:
        if not isinstance(mod, dict):
            continue
        name = mod.get("name") or ""
        summary = mod.get("summary") or ""
        # When data comes from the search endpoint the caller passes an empty
        # filter, so the substring check is skipped.  For the updated-mods
        # fallback we filter by name/summary substring.
        if query_lower and query_lower not in name.lower() and query_lower not in summary.lower():
            continue
        endorsement_count = mod.get("endorsement_count") or 0
        results.append({
            "name": name,
            "mod_id": mod.get("mod_id"),
            "summary": summary,
            "author": mod.get("uploaded_by") or mod.get("author") or "",
            "endorsements": endorsement_count,
            "downloads": mod.get("mod_downloads") or mod.get("downloads") or 0,
        })
    return {"results": results, "count": len(results)}


def get_mod_info(mod_id: int, game: str = _DEFAULT_GAME) -> dict:
    """Fetch detailed information for a single mod.

    Returns::

        {
            "name": str,
            "mod_id": int,
            "summary": str,
            "description": str,   # HTML; may be lengthy
            "author": str,
            "version": str,
            "endorsements": int,
            "downloads": int,
            "game": str,
            "picture_url": str | None,
            "nexus_url": str,
        }

    On failure returns ``{"success": False, ...}``.
    """
    data, err = _try_request(f"/games/{game}/mods/{mod_id}.json")
    if err:
        return err

    if not isinstance(data, dict):
        return _error("api_error", f"Unexpected response format for mod {mod_id}.")

    endorsement_count = data.get("endorsement_count") or 0
    return {
        "name": data.get("name") or "",
        "mod_id": mod_id,
        "summary": data.get("summary") or "",
        "description": data.get("description") or "",
        "author": data.get("uploaded_by") or data.get("author") or "",
        "version": data.get("version") or "",
        "endorsements": endorsement_count,
        "downloads": data.get("mod_downloads") or data.get("downloads") or 0,
        "game": data.get("game_id") or game,
        "picture_url": data.get("picture_url"),
        "nexus_url": f"https://www.nexusmods.com/{game}/mods/{mod_id}",
    }


def get_download_links(
    mod_id: int,
    file_id: int | None = None,
    game: str = _DEFAULT_GAME,
) -> dict:
    """Get download links for a mod file.

    Premium users receive a list of CDN download URLs.  Free users are
    directed to the Nexus Mods browser page—the download API is
    Premium-only per Nexus ToS.

    If *file_id* is None, the files list is fetched first and the most
    recent primary file is selected automatically.

    Returns (Premium)::

        {
            "success": True,
            "file_id": int,
            "links": [{"name": str, "short_name": str, "uri": str}, ...],
        }

    Returns (Free / no Premium)::

        {
            "success": False,
            "error_type": "premium_required",
            "nexus_url": "https://www.nexusmods.com/baldursgate3/mods/<mod_id>",
            "message": "Download requires Nexus Premium. Visit the URL to download manually.",
        }

    Returns (other errors)::

        {"success": False, "error_type": ..., "message": ...}
    """
    # Resolve file_id if not provided.
    if file_id is None:
        file_id, err = _pick_primary_file(mod_id, game)
        if err:
            return err

    nexus_url = f"https://www.nexusmods.com/{game}/mods/{mod_id}"

    data, err = _try_request(
        f"/games/{game}/mods/{mod_id}/files/{file_id}/download_link.json"
    )

    if err:
        # HTTP 403 from the download endpoint means Premium required.
        if err.get("error_type") == "auth_error" or err.get("status_code") == 403:
            return _error(
                "premium_required",
                "Download requires Nexus Premium. Visit the URL to download manually.",
                nexus_url=nexus_url,
            )
        return err

    if not isinstance(data, list):
        return _error("api_error", "Unexpected response format from download_link endpoint.")

    links = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        links.append({
            "name": entry.get("name") or "",
            "short_name": entry.get("short_name") or "",
            "uri": entry.get("URI") or entry.get("uri") or "",
        })

    return {"success": True, "file_id": file_id, "links": links}


# ---------------------------------------------------------------------------
# Internal helpers for file selection
# ---------------------------------------------------------------------------

def _pick_primary_file(mod_id: int, game: str) -> tuple[int | None, dict | None]:
    """Return the file_id of the most recent primary/main file for *mod_id*.

    Returns (file_id, None) on success or (None, error_dict) on failure.
    """
    data, err = _try_request(f"/games/{game}/mods/{mod_id}/files.json")
    if err:
        return None, err

    if not isinstance(data, dict):
        return None, _error("api_error", "Unexpected response format for files list.")

    files = data.get("files")
    if not isinstance(files, list) or not files:
        return None, _error("api_error", f"No files found for mod {mod_id}.")

    # Prefer category_name "MAIN"; fall back to the file with the highest id.
    main_files = [
        f for f in files
        if isinstance(f, dict) and (
            (f.get("category_name") or "").upper() == "MAIN"
            or f.get("category_id") == 1
        )
    ]
    candidates = main_files if main_files else [f for f in files if isinstance(f, dict)]
    if not candidates:
        return None, _error("api_error", f"No usable files found for mod {mod_id}.")

    # Most recent = highest file_id.
    best = max(candidates, key=lambda f: f.get("file_id", 0))
    fid = best.get("file_id")
    if not fid:
        return None, _error("api_error", "Could not determine file_id from files list.")

    return fid, None


# ---------------------------------------------------------------------------
# HTML stripping (for changelog text)
# ---------------------------------------------------------------------------

class _HTMLStripper(HTMLParser):
    """Collect text content from an HTML fragment, dropping all tags.

    Tags that semantically introduce a line break are handled symmetrically —
    ``<br>`` is treated as a self-closing newline and ``<p>``, ``<li>``,
    ``<div>`` insert a newline at the close boundary only.  This prevents
    doubled gaps between list items (the previous version emitted a newline
    at both the start and end of every ``<li>``).
    """

    # Tags that contribute a trailing newline when their end tag fires.
    _BLOCK_TAGS = frozenset(("p", "li", "div"))

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []

    def handle_data(self, data: str) -> None:
        self._chunks.append(data)

    def handle_starttag(self, tag, attrs) -> None:
        # ``<br>`` is void: emit one newline and no matching end-tag handler.
        if tag == "br":
            self._chunks.append("\n")

    def handle_startendtag(self, tag, attrs) -> None:
        # XHTML-style ``<br />`` — same as the start tag form.
        if tag == "br":
            self._chunks.append("\n")

    def handle_endtag(self, tag) -> None:
        if tag in self._BLOCK_TAGS:
            self._chunks.append("\n")

    def get_text(self) -> str:
        joined = "".join(self._chunks)
        # Collapse runs of whitespace within lines, preserve line breaks.
        lines = [" ".join(line.split()) for line in joined.splitlines()]
        return "\n".join(line for line in lines if line).strip()


def _strip_html(text: str) -> str:
    """Convert an HTML changelog fragment to clean plain text.

    ``HTMLParser.feed`` on modern CPython tolerates malformed input without
    raising, so we do not need a fallback branch.
    """
    if not text:
        return ""
    parser = _HTMLStripper()
    parser.feed(text)
    parser.close()
    return parser.get_text()


# ---------------------------------------------------------------------------
# Version sort key (handles SemVer, ISO dates, and date-with-month-name)
# ---------------------------------------------------------------------------

_MONTH_NAMES: dict[str, int] = {
    "january": 1, "jan": 1,
    "february": 2, "feb": 2,
    "march": 3, "mar": 3,
    "april": 4, "apr": 4,
    "may": 5,
    "june": 6, "jun": 6,
    "july": 7, "jul": 7,
    "august": 8, "aug": 8,
    "september": 9, "sep": 9, "sept": 9,
    "october": 10, "oct": 10,
    "november": 11, "nov": 11,
    "december": 12, "dec": 12,
}

_VERSION_SPLIT_RE = re.compile(r"[.\-_/\s]+")
_VERSION_CHUNK_RE = re.compile(r"\d+|[A-Za-z]+")


def _version_sort_key(version: str) -> tuple:
    """Return a sort-safe numeric tuple for a version string.

    Handles three common patterns:

    1. SemVer / numeric: ``1.2.3``, ``0.36.50``
    2. ISO date: ``2024-04-30``, ``2024.04.30``
    3. Date with month name: ``2024April-30``, ``April 2024``, ``Feb-2024``

    The previous implementation cast every non-numeric chunk to ``0``, which
    silently destroyed the chronology of date-style versions (every month name
    collapsed to the same value).  This variant tokenises mixed alphanumeric
    chunks (``2024April`` → ``2024``, ``April``) and resolves month names via
    :data:`_MONTH_NAMES`.

    Unknown alphabetic tokens still collapse to ``0`` so pre-release tags and
    build metadata do not crash the sort.

    Limitations (not SemVer-compliant):

    * Pre-release tags (``1.2.3-alpha`` < ``1.2.3``) are not ordered correctly —
      ``alpha`` collapses to ``0`` and gets appended as a trailing zero, so
      ``1.2.3-alpha`` sorts *after* ``1.2.3``.
    * Build metadata (``1.2.3+20230101``) is treated as an extra version chunk
      instead of being ignored.
    * Unknown pre-release labels (``beta`` vs ``rc``) do not preserve ordering.

    These cases do not occur in Nexus changelogs for BG3 mods (the two real
    patterns seen in the wild are SemVer and month-name dates), so we trade
    strict SemVer compliance for a single key that handles both.
    """
    if not version:
        return ()

    parts: list[int] = []
    for raw_chunk in _VERSION_SPLIT_RE.split(version.strip()):
        if not raw_chunk:
            continue
        for token in _VERSION_CHUNK_RE.findall(raw_chunk):
            if token.isdigit():
                parts.append(int(token))
                continue
            month = _MONTH_NAMES.get(token.lower())
            if month is not None:
                parts.append(month)
                continue
            parts.append(0)

    return tuple(parts)


# ---------------------------------------------------------------------------
# Mod files / changelog / updated endpoints
# ---------------------------------------------------------------------------

def get_mod_files(mod_id: int, game: str = _DEFAULT_GAME) -> dict:
    """Fetch the file list for a single mod.

    Wraps ``/games/{game}/mods/{mod_id}/files.json``.  Each entry is
    flattened to the fields a harness consumer typically wants.

    Returns::

        {
            "mod_id": int,
            "game": str,
            "files": [
                {
                    "file_id": int,
                    "name": str,
                    "version": str,
                    "category": str,        # MAIN / OPTIONAL / OLD_VERSION / ...
                    "category_id": int,
                    "is_primary": bool,     # category == MAIN
                    "size_kb": int,
                    "uploaded_timestamp": int,
                    "uploaded_at": str,     # ISO timestamp from API
                    "description": str,
                    "changelog_html": str,
                    "external_virus_scan_url": str,
                }
            ],
            "count": int,
        }

    On failure returns ``{"success": False, ...}``.
    """
    data, err = _try_request(f"/games/{game}/mods/{mod_id}/files.json")
    if err:
        return err

    if not isinstance(data, dict):
        return _error("api_error", f"Unexpected response format for files of mod {mod_id}.")

    raw_files = data.get("files")
    if not isinstance(raw_files, list):
        raw_files = []

    files = []
    for entry in raw_files:
        if not isinstance(entry, dict):
            continue
        category = (entry.get("category_name") or "").upper()
        files.append({
            "file_id": entry.get("file_id"),
            "name": entry.get("name") or entry.get("file_name") or "",
            "version": entry.get("version") or "",
            "category": category,
            "category_id": entry.get("category_id"),
            "is_primary": category == "MAIN" or entry.get("category_id") == 1,
            "size_kb": entry.get("size_kb") or entry.get("size") or 0,
            "uploaded_timestamp": entry.get("uploaded_timestamp") or 0,
            "uploaded_at": entry.get("uploaded_time") or "",
            "description": entry.get("description") or "",
            "changelog_html": entry.get("changelog_html") or "",
            "external_virus_scan_url": entry.get("external_virus_scan_url") or "",
        })

    return {
        "mod_id": mod_id,
        "game": game,
        "files": files,
        "count": len(files),
    }


def get_changelogs(mod_id: int, game: str = _DEFAULT_GAME) -> dict:
    """Fetch all version changelogs for a single mod.

    Wraps ``/games/{game}/mods/{mod_id}/changelogs.json``.  The Nexus API
    returns a JSON object whose keys are version strings and whose values
    are lists of HTML-fragment changelog entries.  Each entry is converted
    to plain text via :func:`_strip_html`.

    Returns::

        {
            "mod_id": int,
            "game": str,
            "versions": [
                {
                    "version": str,
                    "entries": [str, ...],   # plain-text bullet points
                    "entries_html": [str, ...],  # original HTML
                }
            ],
            "count": int,
        }

    On failure returns ``{"success": False, ...}``.
    """
    data, err = _try_request(f"/games/{game}/mods/{mod_id}/changelogs.json")
    if err:
        return err

    if not isinstance(data, dict):
        return _error("api_error", f"Unexpected response format for changelogs of mod {mod_id}.")

    versions = []
    for version, entries in data.items():
        if not isinstance(entries, list):
            continue
        plain = [_strip_html(e) for e in entries if isinstance(e, str)]
        versions.append({
            "version": version,
            "entries": [e for e in plain if e],
            "entries_html": [e for e in entries if isinstance(e, str)],
        })

    # Sort newest version first.  See :func:`_version_sort_key` for the
    # tolerant cascade that handles SemVer, ISO dates, and date-with-month-name
    # formats (mod 2172's ``2024April-30`` style).
    versions.sort(key=lambda v: _version_sort_key(v.get("version") or ""), reverse=True)

    return {
        "mod_id": mod_id,
        "game": game,
        "versions": versions,
        "count": len(versions),
    }


def get_updated(period: str = "1w", game: str = _DEFAULT_GAME) -> dict:
    """List recently-updated mods for the given game.

    Wraps ``/games/{game}/mods/updated.json?period=...``.  The valid period
    values are ``1d``, ``1w``, and ``1m`` per the Nexus public API.

    Returns::

        {
            "game": str,
            "period": str,
            "mods": [
                {
                    "mod_id": int,
                    "latest_file_update": int,    # unix timestamp
                    "latest_mod_activity": int,   # unix timestamp
                }
            ],
            "count": int,
        }

    On failure returns ``{"success": False, ...}``.
    """
    if period not in ("1d", "1w", "1m"):
        return _error(
            "validation_error",
            f"Invalid period {period!r}; must be one of 1d, 1w, 1m.",
        )

    data, err = _try_request(
        f"/games/{game}/mods/updated.json",
        params={"period": period},
    )
    if err:
        return err

    if not isinstance(data, list):
        return _error("api_error", "Unexpected response format from updated endpoint.")

    mods = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        mods.append({
            "mod_id": entry.get("mod_id"),
            "latest_file_update": entry.get("latest_file_update") or 0,
            "latest_mod_activity": entry.get("latest_mod_activity") or 0,
        })

    # Most recently updated first.
    mods.sort(key=lambda m: m.get("latest_file_update") or 0, reverse=True)

    return {
        "game": game,
        "period": period,
        "mods": mods,
        "count": len(mods),
    }


# ---------------------------------------------------------------------------
# CLI entry point (JSON to stdout, matching harness convention)
# ---------------------------------------------------------------------------

def main(argv=None) -> int:  # pragma: no cover
    import argparse

    parser = argparse.ArgumentParser(
        prog="nexus",
        description="Nexus Mods API client for bg3se-harness",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("status", help="Check API key and rate limit status")

    p_search = sub.add_parser("search", help="Search for mods")
    p_search.add_argument("query")

    p_info = sub.add_parser("info", help="Get mod info")
    p_info.add_argument("mod_id", type=int)

    p_dl = sub.add_parser("download-links", help="Get download links (Premium only)")
    p_dl.add_argument("mod_id", type=int)
    p_dl.add_argument("--file-id", type=int, default=None)

    args = parser.parse_args(argv)

    if args.command == "status":
        result = check_api_status()
    elif args.command == "search":
        result = search_mods(args.query)
    elif args.command == "info":
        result = get_mod_info(args.mod_id)
    elif args.command == "download-links":
        result = get_download_links(args.mod_id, file_id=args.file_id)
    else:
        parser.print_help()
        return 1

    print(json.dumps(result, indent=2))
    return 0 if result.get("success", True) else 1


if __name__ == "__main__":
    sys.exit(main())
