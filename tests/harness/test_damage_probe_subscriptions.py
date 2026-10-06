"""The Tier-2 damage probe must not subscribe to ExecuteFunctor when Lua loads.

console_cmd_test_wave3_damage_events runs from lua_ext_register_global_helpers
in every Lua state. While anything is subscribed to Ext.Events.ExecuteFunctor,
every functor dispatch builds e.Params, so the probe's recorder may subscribe
only inside BG3SE_PrimeDamageProbe().

The static check runs everywhere. The behavioural check runs the real chunk in
a `lua` interpreter (skipped when none is installed, e.g. CI) with stubbed
Ext/Osi tables and counts subscriptions.
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
LUA_EXT_C = REPO / "src/lua/lua_ext.c"
CHUNK_NAME = "console_cmd_test_wave3_damage_events"
PRIME = "function BG3SE_PrimeDamageProbe()"
SUBSCRIBE = "Ext.Events.ExecuteFunctor:Subscribe"


def _chunk() -> str:
    lines = LUA_EXT_C.read_text(encoding="utf-8").splitlines()
    start = next(i for i, l in enumerate(lines) if f"*{CHUNK_NAME} =" in l)
    parts = []
    for line in lines[start + 1:]:
        m = re.match(r'\s*"(.*)"(;?)\s*$', line)
        assert m, f"unexpected line in {CHUNK_NAME}: {line!r}"
        parts.append(m.group(1))
        if m.group(2):
            break
    return "".join(parts).encode().decode("unicode_escape")


def test_execute_functor_is_subscribed_only_inside_the_prime_function():
    chunk = _chunk()
    before, _, rest = chunk.partition(PRIME)
    assert rest, f"{PRIME} not found"
    body = rest[:rest.index("\nend\n")]
    assert SUBSCRIBE not in before, "the chunk subscribes to ExecuteFunctor at load"
    assert SUBSCRIBE in body, "BG3SE_PrimeDamageProbe does not subscribe the recorder"


STUBS = r"""
local function event()
  return { n = 0,
    Subscribe = function(self, fn) self.n = self.n + 1; return self.n end,
    Unsubscribe = function(self, id) self.n = self.n - 1; return true end }
end
local host = 'Host_' .. string.rep('1', 36)
local other = 'Other_' .. string.rep('2', 36)
Ext = { Events = { BeforeDealDamage = event(), DealDamage = event(),
                   ExecuteFunctor = event() },
        Entity = { Get = function() return {} end },
        Debug = { ReadFixedString = function() return nil end } }
Osi = { GetHostCharacter = function() return host end,
        DB_Players = { Get = function(self) return { { host }, { other } } end },
        GetDistanceTo = function() return 1 end,
        PurgeOsirisQueue = function() end,
        UseSpell = function() end }
function BG3SE_AddTest() end
"""

DRIVER = r"""
print('load', Ext.Events.ExecuteFunctor.n)
print('prime', BG3SE_PrimeDamageProbe() ~= nil, Ext.Events.ExecuteFunctor.n)
BG3SE_PrimeDamageProbe()
print('again', Ext.Events.ExecuteFunctor.n)
"""


def test_loading_the_chunk_leaves_execute_functor_unsubscribed(tmp_path):
    lua = shutil.which("lua")
    if lua is None:
        pytest.skip("no `lua` interpreter on PATH")
    script = tmp_path / "probe.lua"
    script.write_text(STUBS + _chunk() + DRIVER, encoding="utf-8")
    out = subprocess.run([lua, str(script)], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    assert out.stdout.split("\n")[:3] == ["load\t0", "prime\ttrue\t1", "again\t1"], out.stdout
