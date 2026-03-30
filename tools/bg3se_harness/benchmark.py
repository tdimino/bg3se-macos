"""Benchmark Lua code execution inside the game engine.

    bg3se-harness benchmark "Ext.Stats.Get('WPN_Longsword')" --iterations 1000
    bg3se-harness benchmark --file perf_suite.lua --warmup 10
"""

import json
import sys

from .console import Console

LUA_BENCHMARK = '''
local code_fn = function()
    {code}
end

local warmup = {warmup}
local iterations = {iterations}

-- Warmup
for i = 1, warmup do code_fn() end

-- Timed run
local times = {{}}
for i = 1, iterations do
    local t0 = Ext.Utils.MonotonicTime()
    code_fn()
    local t1 = Ext.Utils.MonotonicTime()
    times[i] = t1 - t0
end

-- Sort for percentiles
table.sort(times)

local sum = 0
for _, t in ipairs(times) do sum = sum + t end

local function percentile(p)
    local idx = math.ceil(p / 100 * #times)
    if idx < 1 then idx = 1 end
    if idx > #times then idx = #times end
    return times[idx]
end

_P(Ext.Json.Stringify({{
    iterations = iterations,
    warmup = warmup,
    min_ms = times[1],
    max_ms = times[#times],
    mean_ms = sum / #times,
    p50_ms = percentile(50),
    p95_ms = percentile(95),
    p99_ms = percentile(99),
    total_ms = sum
}}))
'''


def benchmark(code=None, file=None, iterations=100, warmup=5):
    """Benchmark Lua code. Returns JSON result string."""
    if file:
        with open(file) as f:
            code = f.read()
    if not code:
        return json.dumps({"error": "No code provided"})

    # Escape user Lua braces to prevent str.format() from interpreting them
    safe_code = code.replace("{", "{{").replace("}", "}}")
    lua = LUA_BENCHMARK.format(code=safe_code, iterations=iterations, warmup=warmup)
    with Console() as c:
        return c.send_lua(lua)


def cmd_benchmark(args):
    """CLI handler."""
    code = getattr(args, "code", None)
    file = getattr(args, "file", None)
    iterations = getattr(args, "iterations", 100) or 100
    warmup = getattr(args, "warmup", 5) or 5

    if not code and not file:
        print(json.dumps({"error": "Provide code or --file"}))
        return 1

    try:
        output = benchmark(code=code, file=file, iterations=iterations, warmup=warmup)
        print(output)
        return 0
    except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
        print(json.dumps({"error": f"Socket connection failed: {e}"}))
        return 1
