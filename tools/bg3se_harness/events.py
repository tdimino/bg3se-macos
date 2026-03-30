"""Subscribe to game events and stream as JSONL.

    bg3se-harness events --list                        # list all events
    bg3se-harness events --subscribe SessionLoaded     # stream occurrences
    bg3se-harness events --subscribe SessionLoaded --listen 30
"""

import json
import select
import signal
import sys
import time

from .console import Console

LUA_LIST_EVENTS = '''
local events = {}
-- Known BG3SE events (compiled list)
local names = {
    "SessionLoading", "SessionLoaded", "GameStateChanged",
    "ResetCompleted", "Tick", "StatsLoaded", "StatsStructureLoaded",
    "ModuleLoading", "ModuleLoadStarted", "ModuleResume",
    "BeforeLevelLoad", "AfterLevelLoad",
    "BeforeSessionEnd", "SessionEnded",
    "BeforeReset", "AfterReset",
    "DoConsoleCommand",
    "NetMessageReceived",
    "BeforeDealDamage", "DealDamage", "AfterDealDamage",
    "BeforeStatusApplied", "StatusApplied", "BeforeStatusDelete",
    "DownedChanged", "DyingChanged", "DeathChanged",
    "BeforeAttack", "Attack", "AfterAttack",
    "BeforeShortRest", "ShortRest",
    "BeforeLongRest", "LongRest",
}
for _, name in ipairs(names) do
    local ok = pcall(function() return Ext.Events[name] end)
    table.insert(events, {name = name, available = ok})
end
_P(Ext.Json.Stringify(events))
'''

LUA_SUBSCRIBE = '''
local handler = Ext.Events.{event_name}:Subscribe(function(e)
    local data = {{}}
    for k, v in pairs(e) do
        data[k] = tostring(v)
    end
    data._event = "{event_name}"
    data._time = Ext.Utils.MonotonicTime()
    _P("EVENT:" .. Ext.Json.Stringify(data))
end)
_P("SUBSCRIBED:{event_name}")
'''

LUA_UNSUBSCRIBE = '''
-- Cleanup handled by session end
_P("UNSUBSCRIBED")
'''


def list_events():
    """List all known game events. Returns JSON string."""
    with Console() as c:
        return c.send_lua(LUA_LIST_EVENTS)


def subscribe(event_name, duration=None):
    """Subscribe to an event and stream JSONL to stdout."""
    with Console() as c:
        # Subscribe
        result = c.send_lua(LUA_SUBSCRIBE.format(event_name=event_name))
        if "SUBSCRIBED" not in result:
            return json.dumps({"error": f"Failed to subscribe: {result}"})

        print(f"Subscribed to {event_name}, streaming...", file=sys.stderr)

        # Stream events
        start = time.monotonic()
        try:
            while True:
                if duration and (time.monotonic() - start) >= duration:
                    break
                # Read from socket with timeout
                try:
                    data = c._sock.recv(4096)
                    if not data:
                        break
                    text = c._clean(data.decode("utf-8", errors="replace"))
                    for line in text.splitlines():
                        if line.startswith("EVENT:"):
                            print(line[6:])  # JSONL to stdout
                            sys.stdout.flush()
                except Exception:
                    time.sleep(0.1)
        except KeyboardInterrupt:
            pass
        finally:
            print(f"\nStopped after {time.monotonic() - start:.1f}s", file=sys.stderr)

    return None


def cmd_events(args):
    """CLI handler."""
    if getattr(args, "list_events", False):
        try:
            output = list_events()
            print(output)
            return 0
        except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
            print(json.dumps({"error": str(e)}))
            return 1

    event_name = getattr(args, "subscribe", None)
    if not event_name:
        print(json.dumps({"error": "Specify --list or --subscribe NAME"}))
        return 1

    duration = getattr(args, "listen", None)
    try:
        subscribe(event_name, duration=duration)
        return 0
    except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
        print(json.dumps({"error": str(e)}))
        return 1
