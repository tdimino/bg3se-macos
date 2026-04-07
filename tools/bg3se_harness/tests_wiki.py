"""Unit tests for the bg3.wiki client (mod_manager.wiki).

Uses canned MediaWiki API fixtures and monkey-patches urllib.request.urlopen
so the tests run fully offline.  A per-test temporary cache directory keeps
the real ``~/.config/bg3se-harness/wiki_cache/`` untouched.

Run::

    PYTHONPATH=tools python3 -m bg3se_harness.tests_wiki
"""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from bg3se_harness.mod_manager import wiki


# ---------------------------------------------------------------------------
# Fake HTTP response helpers (mirrors tests_nexus.py)
# ---------------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, payload, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self._buf = io.BytesIO(body)
        self.status = status
        self.headers: dict[str, str] = {}

    def read(self) -> bytes:
        return self._buf.read()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._buf.close()


def _route_response(url: str, route_map: dict[str, object]) -> _FakeResponse:
    """Dispatch a mocked urlopen call based on substring matches in *url*.

    route_map keys are substrings; the first matching key wins.  Values
    may be payload dicts/lists or callables that receive the URL.
    """
    for needle, payload in route_map.items():
        if needle in url:
            value = payload(url) if callable(payload) else payload
            return _FakeResponse(value)
    raise AssertionError(f"No route matched URL: {url}")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIREBALL_WIKITEXT = (
    "{{hatnote|For the equivalent Monk spell, see {{SAI|Flames}}.}}\n"
    "{{Feature page\n"
    "| type = spell\n"
    "| level = 3\n"
    "| school = Evocation\n"
    "| summary = It allows spellcasters to unleash fire.\n"
    "| description = Shoot a bright flame that explodes for "
    "{{DamageText|8d6|Fire}} damage.\n"
    "| damage = 8d6\n"
    "| damage type = Fire\n"
    "| cost = action, spell3\n"
    "| save = DEX\n"
    "| classes = Sorcerer, Wizard\n"
    "| uid = Projectile_Fireball\n"
    "}}\n"
    "\n"
    "== External links ==\n"
    "* {{FRWiki|Fireball|long}}\n"
    "[[Category:Sources of Fire damage]]"
)

LONGSWORD_WIKITEXT = (
    "{{WeaponPage\n"
    "| <!-- See here for tips: https://bg3.wiki/wiki/Template:WeaponPage -->\n"
    "| image = Longsword +1 Icon.png\n"
    "| uid = WPN_HUM_Longsword_A_1\n"
    "| uuid = 3fc2ba50-3070-4caa-abe8-3bf885969bde\n"
    "| category = martial\n"
    "| melee or ranged = melee\n"
    "| handedness = versatile\n"
    "| type = Longswords\n"
    "| rarity = uncommon\n"
    "| enchantment = +1\n"
    "| damage = 1d8 + 1\n"
    "| damage type = Slashing\n"
    "| versatile damage = 1d10 + 1\n"
    "| weapon actions = Lacerate, Rush Attack, Pommel Strike\n"
    "| where to find = Sold by the [[Magic Melee Weapon Trader Table|magic melee]] traders\n"
    "}}\n"
    "[[Category:Sources of Slashing damage]]"
)

BARE_PAGE_WIKITEXT = "This is just a redirect stub with no template."


def _opensearch_payload(query: str, titles: list[str]) -> list:
    """Build a MediaWiki OpenSearch response: [search, titles, descs, urls]."""
    return [
        query,
        titles,
        ["" for _ in titles],
        [f"https://bg3.wiki/wiki/{t.replace(' ', '_')}" for t in titles],
    ]


def _parse_payload(title: str, wikitext: str, pageid: int) -> dict:
    """Build a MediaWiki ``action=parse`` response."""
    return {
        "parse": {
            "title": title,
            "pageid": pageid,
            "wikitext": {"*": wikitext},
        }
    }


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class WikiClientTests(unittest.TestCase):

    def setUp(self) -> None:
        # Redirect the cache to a throwaway temp dir so tests never touch
        # the real ~/.config/bg3se-harness/wiki_cache/.
        self._tmp = tempfile.TemporaryDirectory()
        self._cache_patch = mock.patch.object(
            wiki, "_cache_dir", return_value=Path(self._tmp.name)
        )
        self._cache_patch.start()

    def tearDown(self) -> None:
        self._cache_patch.stop()
        self._tmp.cleanup()

    # -- Template parsing --------------------------------------------------

    def test_find_template_block_matches_nested_braces(self) -> None:
        block = wiki._find_template_block(FIREBALL_WIKITEXT, ("Feature page",))
        self.assertIsNotNone(block)
        self.assertTrue(block.startswith("{{Feature page"))
        self.assertTrue(block.endswith("}}"))
        # The hatnote's inner template must not be confused with ours.
        self.assertNotIn("hatnote", block)

    def test_find_template_block_returns_none_when_absent(self) -> None:
        block = wiki._find_template_block(BARE_PAGE_WIKITEXT, ("Feature page",))
        self.assertIsNone(block)

    def test_parse_template_fields_splits_on_top_level_pipes(self) -> None:
        block = wiki._find_template_block(FIREBALL_WIKITEXT, ("Feature page",))
        fields = wiki._parse_template_fields(block)
        self.assertEqual(fields["type"], "spell")
        self.assertEqual(fields["level"], "3")
        self.assertEqual(fields["uid"], "Projectile_Fireball")
        # Nested {{DamageText|8d6|Fire}} must not fragment the "description" field.
        self.assertIn("DamageText", fields["description"])

    def test_parse_template_fields_handles_comments(self) -> None:
        block = wiki._find_template_block(LONGSWORD_WIKITEXT, ("WeaponPage",))
        fields = wiki._parse_template_fields(block)
        # The HTML comment must not appear in any value.
        for v in fields.values():
            self.assertNotIn("<!--", v)
        self.assertEqual(fields["uid"], "WPN_HUM_Longsword_A_1")

    def test_strip_wiki_markup_expands_links_and_templates(self) -> None:
        self.assertEqual(
            wiki._strip_wiki_markup("[[Magic Melee Weapon Trader Table|magic melee]]"),
            "magic melee",
        )
        self.assertEqual(
            wiki._strip_wiki_markup("{{DamageText|8d6|Fire}}"),
            "8d6 Fire",
        )
        self.assertEqual(
            wiki._strip_wiki_markup("line one<br />line two"),
            "line one line two",
        )

    # -- query_spell -------------------------------------------------------

    def test_query_spell_happy_path(self) -> None:
        routes = {
            "action=opensearch": _opensearch_payload("Fireball", ["Fireball"]),
            "action=parse": _parse_payload("Fireball", FIREBALL_WIKITEXT, 2677),
        }
        with mock.patch.object(
            wiki.urllib.request,
            "urlopen",
            side_effect=lambda req, timeout=None: _route_response(req.full_url, routes),
        ):
            result = wiki.query_spell("Fireball", use_cache=False)

        self.assertTrue(result["success"])
        self.assertEqual(result["kind"], "spell")
        self.assertEqual(result["title"], "Fireball")
        self.assertEqual(result["pageid"], 2677)
        self.assertEqual(result["uid"], "Projectile_Fireball")
        self.assertEqual(result["fields"]["school"], "Evocation")
        self.assertEqual(result["fields"]["damage"], "8d6")
        self.assertEqual(result["url"], "https://bg3.wiki/wiki/Fireball")
        self.assertFalse(result["cached"])

    def test_query_spell_not_found(self) -> None:
        routes = {
            "action=opensearch": _opensearch_payload("Nonesuch", []),
        }
        with mock.patch.object(
            wiki.urllib.request,
            "urlopen",
            side_effect=lambda req, timeout=None: _route_response(req.full_url, routes),
        ):
            result = wiki.query_spell("Nonesuch", use_cache=False)

        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "not_found")

    def test_query_spell_validates_empty_name(self) -> None:
        result = wiki.query_spell("   ", use_cache=False)
        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "validation_error")

    def test_query_spell_missing_template_is_reported(self) -> None:
        routes = {
            "action=opensearch": _opensearch_payload("Stub", ["Stub"]),
            "action=parse": _parse_payload("Stub", BARE_PAGE_WIKITEXT, 9),
        }
        with mock.patch.object(
            wiki.urllib.request,
            "urlopen",
            side_effect=lambda req, timeout=None: _route_response(req.full_url, routes),
        ):
            result = wiki.query_spell("Stub", use_cache=False)

        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "template_not_found")
        self.assertEqual(result["title"], "Stub")

    # -- query_item --------------------------------------------------------

    def test_query_item_matches_weapon_page_template(self) -> None:
        routes = {
            "action=opensearch": _opensearch_payload("Longsword +1", ["Longsword +1"]),
            "action=parse": _parse_payload("Longsword +1", LONGSWORD_WIKITEXT, 3418),
        }
        with mock.patch.object(
            wiki.urllib.request,
            "urlopen",
            side_effect=lambda req, timeout=None: _route_response(req.full_url, routes),
        ):
            result = wiki.query_item("Longsword +1", use_cache=False)

        self.assertTrue(result["success"])
        self.assertEqual(result["kind"], "item")
        self.assertEqual(result["uid"], "WPN_HUM_Longsword_A_1")
        self.assertEqual(result["fields"]["damage"], "1d8 + 1")
        self.assertEqual(result["fields"]["rarity"], "uncommon")
        # Percent-encoded spaces and plus signs in the URL.
        self.assertIn("Longsword", result["url"])

    # -- verify_page -------------------------------------------------------

    def test_verify_page_without_expectation_returns_uid(self) -> None:
        routes = {
            "action=parse": _parse_payload("Longsword +1", LONGSWORD_WIKITEXT, 3418),
        }
        with mock.patch.object(
            wiki.urllib.request,
            "urlopen",
            side_effect=lambda req, timeout=None: _route_response(req.full_url, routes),
        ):
            result = wiki.verify_page("Longsword +1", use_cache=False)

        self.assertTrue(result["success"])
        self.assertEqual(result["uid"], "WPN_HUM_Longsword_A_1")
        self.assertNotIn("uid_matches", result)

    def test_verify_page_with_matching_expect_uid(self) -> None:
        routes = {
            "action=parse": _parse_payload("Longsword +1", LONGSWORD_WIKITEXT, 3418),
        }
        with mock.patch.object(
            wiki.urllib.request,
            "urlopen",
            side_effect=lambda req, timeout=None: _route_response(req.full_url, routes),
        ):
            result = wiki.verify_page(
                "Longsword +1",
                expect_uid="WPN_HUM_Longsword_A_1",
                use_cache=False,
            )

        self.assertTrue(result["success"])
        self.assertTrue(result["uid_matches"])
        self.assertEqual(result["expect_uid"], "WPN_HUM_Longsword_A_1")

    def test_verify_page_with_mismatched_expect_uid(self) -> None:
        routes = {
            "action=parse": _parse_payload("Longsword +1", LONGSWORD_WIKITEXT, 3418),
        }
        with mock.patch.object(
            wiki.urllib.request,
            "urlopen",
            side_effect=lambda req, timeout=None: _route_response(req.full_url, routes),
        ):
            result = wiki.verify_page(
                "Longsword +1",
                expect_uid="WPN_WRONG",
                use_cache=False,
            )

        # Mismatch is not a fatal error — success stays True but uid_matches is False.
        self.assertTrue(result["success"])
        self.assertFalse(result["uid_matches"])

    def test_verify_page_missing_template(self) -> None:
        routes = {
            "action=parse": _parse_payload("Stub", BARE_PAGE_WIKITEXT, 9),
        }
        with mock.patch.object(
            wiki.urllib.request,
            "urlopen",
            side_effect=lambda req, timeout=None: _route_response(req.full_url, routes),
        ):
            result = wiki.verify_page("Stub", use_cache=False)

        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "template_not_found")

    # -- Cache -------------------------------------------------------------

    def test_cache_roundtrip(self) -> None:
        routes = {
            "action=opensearch": _opensearch_payload("Fireball", ["Fireball"]),
            "action=parse": _parse_payload("Fireball", FIREBALL_WIKITEXT, 2677),
        }
        call_count = {"n": 0}

        def counting_urlopen(req, timeout=None):
            call_count["n"] += 1
            return _route_response(req.full_url, routes)

        with mock.patch.object(wiki.urllib.request, "urlopen", side_effect=counting_urlopen):
            first = wiki.query_spell("Fireball", use_cache=True)
            second = wiki.query_spell("Fireball", use_cache=True)

        self.assertTrue(first["success"])
        self.assertTrue(second["success"])
        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        # Second call should not hit the network at all.  Opensearch (1) and
        # parse (2) were the only calls from the first invocation.
        self.assertEqual(call_count["n"], 2)

    def test_clear_cache_removes_files(self) -> None:
        (Path(self._tmp.name) / "Fireball.json").write_text(
            json.dumps({"success": True}), encoding="utf-8"
        )
        (Path(self._tmp.name) / "Longsword__1.json").write_text(
            json.dumps({"success": True}), encoding="utf-8"
        )
        result = wiki.clear_cache()
        self.assertTrue(result["success"])
        self.assertEqual(result["removed"], 2)
        self.assertEqual(list(Path(self._tmp.name).glob("*.json")), [])

    # -- Network errors ----------------------------------------------------

    def test_http_error_propagates_as_api_error(self) -> None:
        import urllib.error
        err = urllib.error.HTTPError(
            url="https://bg3.wiki/w/api.php",
            code=502,
            msg="Bad Gateway",
            hdrs=None,
            fp=io.BytesIO(b""),
        )
        with mock.patch.object(wiki.urllib.request, "urlopen", side_effect=err):
            result = wiki.query_spell("Anything", use_cache=False)

        self.assertFalse(result["success"])
        self.assertEqual(result["error_type"], "api_error")
        self.assertEqual(result["status_code"], 502)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
