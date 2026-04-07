"""Unit tests for the Nexus REST client (mod_manager.nexus).

These tests use canned JSON fixtures and monkey-patch urllib.request.urlopen,
so they require no network access and no NEXUS_API_KEY.

Run::

    PYTHONPATH=tools python3 -m bg3se_harness.tests_nexus
"""

from __future__ import annotations

import io
import json
import os
import sys
import unittest
from unittest import mock

from bg3se_harness.mod_manager import nexus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeResponse:
    """Mimic the urllib response context manager interface."""

    def __init__(self, payload, status: int = 200, headers: dict | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self._buf = io.BytesIO(body)
        self.status = status
        self.headers = headers or {
            "X-RL-Hourly-Limit": "100",
            "X-RL-Hourly-Remaining": "98",
            "X-RL-Daily-Limit": "2500",
            "X-RL-Daily-Remaining": "2400",
        }

    def read(self) -> bytes:
        return self._buf.read()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._buf.close()


def _patch_urlopen(payload, status: int = 200, headers: dict | None = None):
    """Return a mock that always yields the same fake response."""
    return mock.patch.object(
        nexus.urllib.request,
        "urlopen",
        return_value=_FakeResponse(payload, status=status, headers=headers),
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FILES_FIXTURE = {
    "files": [
        {
            "file_id": 9001,
            "name": "Norbyte's Script Extender",
            "file_name": "BG3SE-9001.zip",
            "version": "0.36.50",
            "category_name": "MAIN",
            "category_id": 1,
            "size_kb": 4096,
            "uploaded_timestamp": 1_700_000_000,
            "uploaded_time": "2024-11-14T12:00:00.000+00:00",
            "description": "Latest stable",
            "changelog_html": "<p>Fixed <b>everything</b></p>",
            "external_virus_scan_url": "https://virustotal.example/9001",
        },
        {
            "file_id": 9000,
            "name": "Older release",
            "file_name": "BG3SE-9000.zip",
            "version": "0.36.49",
            "category_name": "OLD_VERSION",
            "category_id": 4,
            "size_kb": 4000,
            "uploaded_timestamp": 1_690_000_000,
            "uploaded_time": "2024-07-22T12:00:00.000+00:00",
        },
    ],
    "file_updates": [],
}

CHANGELOG_FIXTURE = {
    "0.36.50": [
        "<p>Added <b>Ext.Foo</b> namespace</p>",
        "<ul><li>Fixed crash on save</li><li>Fixed Lua dispatch</li></ul>",
    ],
    "0.36.49": [
        "Initial release of new dispatcher",
    ],
    "0.10.0-beta": [
        "<p>Beta only</p>",
    ],
}

UPDATED_FIXTURE = [
    {"mod_id": 17, "latest_file_update": 1_700_000_900, "latest_mod_activity": 1_700_001_000},
    {"mod_id": 42, "latest_file_update": 1_700_000_500, "latest_mod_activity": 1_700_000_600},
    {"mod_id": 7,  "latest_file_update": 1_700_000_700, "latest_mod_activity": 1_700_000_700},
]


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class NexusClientTests(unittest.TestCase):

    def setUp(self) -> None:
        # Force a stable API key so _load_api_key never touches disk.
        self._env_patch = mock.patch.dict(os.environ, {"NEXUS_API_KEY": "test-key"})
        self._env_patch.start()
        # Reset rate state between tests so warnings are deterministic.
        for k in nexus._rate_state:
            nexus._rate_state[k] = None

    def tearDown(self) -> None:
        self._env_patch.stop()

    # -- get_mod_files -----------------------------------------------------

    def test_get_mod_files_normalises_entries(self) -> None:
        with _patch_urlopen(FILES_FIXTURE):
            result = nexus.get_mod_files(123)

        self.assertEqual(result["mod_id"], 123)
        self.assertEqual(result["game"], "baldursgate3")
        self.assertEqual(result["count"], 2)

        primary = result["files"][0]
        self.assertEqual(primary["file_id"], 9001)
        self.assertEqual(primary["category"], "MAIN")
        self.assertTrue(primary["is_primary"])
        self.assertEqual(primary["version"], "0.36.50")
        self.assertEqual(primary["size_kb"], 4096)
        self.assertEqual(primary["uploaded_timestamp"], 1_700_000_000)

        secondary = result["files"][1]
        self.assertEqual(secondary["category"], "OLD_VERSION")
        self.assertFalse(secondary["is_primary"])

    def test_get_mod_files_handles_missing_files_key(self) -> None:
        with _patch_urlopen({"unrelated": "data"}):
            result = nexus.get_mod_files(123)
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["files"], [])

    # -- get_changelogs ----------------------------------------------------

    def test_get_changelogs_strips_html_and_sorts_versions(self) -> None:
        with _patch_urlopen(CHANGELOG_FIXTURE):
            result = nexus.get_changelogs(123)

        self.assertEqual(result["mod_id"], 123)
        self.assertEqual(result["count"], 3)
        versions = [v["version"] for v in result["versions"]]
        self.assertEqual(versions[0], "0.36.50")
        self.assertEqual(versions[1], "0.36.49")
        self.assertEqual(versions[2], "0.10.0-beta")

        first = result["versions"][0]
        self.assertEqual(len(first["entries"]), 2)
        self.assertNotIn("<", first["entries"][0])
        self.assertNotIn(">", first["entries"][0])
        self.assertIn("Ext.Foo", first["entries"][0])
        self.assertIn("Fixed crash on save", first["entries"][1])
        self.assertIn("Fixed Lua dispatch", first["entries"][1])
        self.assertEqual(len(first["entries_html"]), 2)
        self.assertIn("<b>", first["entries_html"][0])

    def test_get_changelogs_handles_unexpected_payload(self) -> None:
        with _patch_urlopen([1, 2, 3]):
            result = nexus.get_changelogs(123)
        self.assertFalse(result.get("success", True))
        self.assertEqual(result["error_type"], "api_error")

    # -- get_updated -------------------------------------------------------

    def test_get_updated_sorts_by_recency(self) -> None:
        with _patch_urlopen(UPDATED_FIXTURE):
            result = nexus.get_updated()

        self.assertEqual(result["period"], "1w")
        self.assertEqual(result["count"], 3)
        ids = [m["mod_id"] for m in result["mods"]]
        self.assertEqual(ids, [17, 7, 42])

    def test_get_updated_rejects_invalid_period(self) -> None:
        # Should fail before any HTTP request happens.
        result = nexus.get_updated(period="6m")
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "validation_error")

    def test_get_updated_propagates_http_error(self) -> None:
        import urllib.error
        err = urllib.error.HTTPError(
            url="https://api.nexusmods.com/v1/games/baldursgate3/mods/updated.json",
            code=429,
            msg="Too Many Requests",
            hdrs=None,
            fp=io.BytesIO(b'{"message":"rate limited"}'),
        )
        with mock.patch.object(nexus.urllib.request, "urlopen", side_effect=err):
            result = nexus.get_updated(period="1d")

        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "api_error")
        self.assertEqual(result["status_code"], 429)

    # -- HTML stripper -----------------------------------------------------

    def test_strip_html_preserves_paragraph_breaks(self) -> None:
        text = nexus._strip_html("<p>One</p><p>Two</p><br>Three")
        # We collapse whitespace within lines but preserve newlines.
        lines = text.splitlines()
        self.assertIn("One", lines)
        self.assertIn("Two", lines)
        self.assertIn("Three", lines)

    def test_strip_html_handles_empty(self) -> None:
        self.assertEqual(nexus._strip_html(""), "")
        self.assertEqual(nexus._strip_html(None or ""), "")

    # -- Version sort key --------------------------------------------------

    def test_version_sort_key_semver_ordering(self) -> None:
        versions = ["0.36.49", "0.36.50", "0.10.0-beta", "1.2.3"]
        versions.sort(key=nexus._version_sort_key, reverse=True)
        self.assertEqual(versions, ["1.2.3", "0.36.50", "0.36.49", "0.10.0-beta"])

    def test_version_sort_key_handles_month_names(self) -> None:
        # Mod 2172's real pattern: the old impl turned "April" into 0 and
        # couldn't distinguish consecutive months within the same year.
        versions = ["2024April-30", "2024May-1", "2024March-15", "2023December-31"]
        versions.sort(key=nexus._version_sort_key, reverse=True)
        self.assertEqual(
            versions,
            ["2024May-1", "2024April-30", "2024March-15", "2023December-31"],
        )

    def test_version_sort_key_handles_abbreviated_months_within_year(self) -> None:
        # Within a fixed year, abbreviated months must sort chronologically.
        versions = ["2024Mar-15", "2024Feb-1", "2024Jan-1", "2024Dec-31"]
        versions.sort(key=nexus._version_sort_key, reverse=True)
        self.assertEqual(
            versions,
            ["2024Dec-31", "2024Mar-15", "2024Feb-1", "2024Jan-1"],
        )

    def test_version_sort_key_handles_iso_dates(self) -> None:
        versions = ["2024-04-30", "2024-05-01", "2023-12-31"]
        versions.sort(key=nexus._version_sort_key, reverse=True)
        self.assertEqual(versions, ["2024-05-01", "2024-04-30", "2023-12-31"])

    def test_version_sort_key_handles_empty_and_unknown(self) -> None:
        self.assertEqual(nexus._version_sort_key(""), ())
        # Unknown alphabetic tokens collapse to 0 but don't crash.
        self.assertEqual(nexus._version_sort_key("beta"), (0,))
        self.assertEqual(nexus._version_sort_key("1.0-rc1"), (1, 0, 0, 1))

    def test_get_changelogs_sorts_month_name_versions_chronologically(self) -> None:
        payload = {
            "2024April-30": ["<p>April release</p>"],
            "2024May-1":    ["<p>May release</p>"],
            "2024March-15": ["<p>March release</p>"],
        }
        with _patch_urlopen(payload):
            result = nexus.get_changelogs(2172)

        versions = [v["version"] for v in result["versions"]]
        self.assertEqual(versions, ["2024May-1", "2024April-30", "2024March-15"])

    # -- 403 disambiguation ------------------------------------------------

    def _make_http_error(self, code: int, body: bytes) -> "urllib.error.HTTPError":
        import urllib.error
        return urllib.error.HTTPError(
            url="https://api.nexusmods.com/v1/games/baldursgate3/mods/99999.json",
            code=code,
            msg="Forbidden" if code == 403 else "Unauthorized",
            hdrs=None,
            fp=io.BytesIO(body),
        )

    def test_403_content_restricted_from_json_message(self) -> None:
        body = json.dumps({
            "message": "You do not have permission to view this mod. "
                       "Adult content is hidden by your content blocking preferences.",
        }).encode("utf-8")
        err = self._make_http_error(403, body)
        with mock.patch.object(nexus.urllib.request, "urlopen", side_effect=err):
            result = nexus.get_mod_info(99999)

        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "content_restricted")
        self.assertEqual(result["status_code"], 403)
        # The Nexus-provided message should be preserved.
        self.assertIn("permission to view", result["message"])

    def test_403_content_restricted_from_plain_text_body(self) -> None:
        # Not all Nexus error pages are JSON — sniff raw body too.
        body = b"<html><body>This mod is hidden by content blocking.</body></html>"
        err = self._make_http_error(403, body)
        with mock.patch.object(nexus.urllib.request, "urlopen", side_effect=err):
            result = nexus.get_mod_info(99999)

        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "content_restricted")
        # No JSON message → synthesised default should mention content blocking.
        self.assertIn("content", result["message"].lower())

    def test_403_on_mod_path_defaults_to_content_restricted(self) -> None:
        # Even when the body has no explicit content-block marker, a 403 on a
        # per-mod path (after successful HTTP auth) means Nexus is blocking
        # that specific mod, not that the API key is invalid.
        body = json.dumps({"message": "Mod not available: 22324"}).encode("utf-8")
        err = self._make_http_error(403, body)
        with mock.patch.object(nexus.urllib.request, "urlopen", side_effect=err):
            result = nexus.get_mod_info(22324)

        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "content_restricted")
        self.assertEqual(result["status_code"], 403)
        # Nexus's terse phrase should be preserved verbatim.
        self.assertIn("Mod not available", result["message"])

    def test_403_on_users_validate_is_auth_error(self) -> None:
        # A 403 on /users/validate.json is definitively an API key problem.
        import urllib.error
        err = urllib.error.HTTPError(
            url="https://api.nexusmods.com/v1/users/validate.json",
            code=403,
            msg="Forbidden",
            hdrs=None,
            fp=io.BytesIO(b'{"message":"Invalid API key."}'),
        )
        with mock.patch.object(nexus.urllib.request, "urlopen", side_effect=err):
            result = nexus.check_api_status()

        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "auth_error")
        self.assertEqual(result["status_code"], 403)

    def test_401_always_auth_error(self) -> None:
        # 401 should never be reclassified as content-restricted.
        body = b'{"message":"This mod has adult content blocking enabled."}'
        err = self._make_http_error(401, body)
        with mock.patch.object(nexus.urllib.request, "urlopen", side_effect=err):
            result = nexus.get_mod_info(99999)

        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "auth_error")
        self.assertEqual(result["status_code"], 401)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
