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
        return None, _error("network_error", str(exc))
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            return None, _error(
                "auth_error",
                f"Nexus API authentication failed (HTTP {exc.code}). "
                "Verify your API key at https://www.nexusmods.com/users/myaccount?tab=api.",
                status_code=exc.code,
            )
        try:
            body = json.loads(exc.read())
            msg = body.get("message") or str(exc)
        except Exception:
            msg = str(exc)
        return None, _error("api_error", msg, status_code=exc.code)
    except urllib.error.URLError as exc:
        return None, _error("network_error", f"Network error: {exc.reason}")
    except Exception as exc:
        return None, _error("network_error", f"Unexpected error: {exc}")


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
    data, err = _try_request(
        f"/games/{game}/mods/search.json",
        params={"q": query},
    )
    if err is None and isinstance(data, list):
        return _format_search_results(data, query)

    # Fallback: fetch recently-updated mods and filter client-side.
    data, err = _try_request(
        f"/games/{game}/mods/updated.json",
        params={"period": "1m"},
    )
    if err:
        return err

    if not isinstance(data, list):
        return {"results": [], "count": 0}

    return _format_search_results(data, query)


def _format_search_results(raw: list, query: str) -> dict:
    """Normalise raw Nexus mod list, optionally filtering by query string."""
    query_lower = query.lower()
    results = []
    for mod in raw:
        if not isinstance(mod, dict):
            continue
        name = mod.get("name") or ""
        summary = mod.get("summary") or ""
        # When data comes from search endpoint it already matches; from the
        # updated endpoint we filter by name/summary substring.
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
    """Collect text content from an HTML fragment, dropping all tags."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []

    def handle_data(self, data: str) -> None:
        self._chunks.append(data)

    def handle_starttag(self, tag, attrs) -> None:
        if tag in ("br", "p", "li", "div"):
            self._chunks.append("\n")

    def handle_endtag(self, tag) -> None:
        if tag in ("p", "li", "div"):
            self._chunks.append("\n")

    def get_text(self) -> str:
        joined = "".join(self._chunks)
        # Collapse runs of whitespace within lines, preserve line breaks.
        lines = [" ".join(line.split()) for line in joined.splitlines()]
        return "\n".join(line for line in lines if line).strip()


def _strip_html(text: str) -> str:
    """Convert an HTML changelog fragment to clean plain text."""
    if not text:
        return ""
    parser = _HTMLStripper()
    try:
        parser.feed(text)
        parser.close()
    except Exception:
        return text
    return parser.get_text()


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

    # Sort newest version first using a tolerant numeric key.
    def _version_key(v: dict) -> tuple:
        parts = []
        for chunk in (v.get("version") or "").replace("-", ".").split("."):
            try:
                parts.append(int(chunk))
            except ValueError:
                parts.append(0)
        return tuple(parts)

    versions.sort(key=_version_key, reverse=True)

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
