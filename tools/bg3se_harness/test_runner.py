import json
import re
import sys

from .console import Console

# Matches: "  PASS: Core.Print (2ms) [1/85]"
# or:      "  FAIL: Stats.Bad (5ms) - Expected string, got nil [3/85]"
TEST_LINE_RE = re.compile(
    r'(PASS|FAIL):\s+(\S+)\s+\((\d+)ms\)(?:\s+-\s+(.+?))?\s+\[(\d+)/(\d+)\]'
)

# Matches: "=== Results: 83/85 passed, 2 failed, 0 skipped (142ms) ==="
SUMMARY_RE = re.compile(
    r'Results:\s+(\d+)/(\d+)\s+passed,\s+(\d+)\s+failed,\s+(\d+)\s+skipped\s+\((\d+)ms\)'
)


def parse_test_output(raw):
    """Parse BG3SE test output into structured results."""
    tests = []
    summary = None

    for line in raw.splitlines():
        m = TEST_LINE_RE.search(line)
        if m:
            tests.append({
                "name": m.group(2),
                "status": m.group(1).lower(),
                "ms": int(m.group(3)),
                "error": m.group(4) if m.group(4) else None,
                "index": int(m.group(5)),
                "total": int(m.group(6)),
            })
            continue

        m = SUMMARY_RE.search(line)
        if m:
            summary = {
                "passed": int(m.group(1)),
                "total": int(m.group(2)),
                "failed": int(m.group(3)),
                "skipped": int(m.group(4)),
                "elapsed_ms": int(m.group(5)),
            }

    return tests, summary


def run_tests(tier=1, filter_pattern=None):
    """Run BG3SE regression tests and return structured JSON results."""
    cmd = "!test" if tier == 1 else "!test_ingame"
    if filter_pattern:
        cmd += f" {filter_pattern}"

    try:
        with Console(timeout=30) as c:
            print(f"Sending: {cmd}", file=sys.stderr)
            raw = c.send(cmd, timeout=20)

        tests, summary = parse_test_output(raw)

        result = {
            "tier": tier,
            "filter": filter_pattern,
            "tests": tests,
            "summary": summary or {
                "passed": sum(1 for t in tests if t["status"] == "pass"),
                "failed": sum(1 for t in tests if t["status"] == "fail"),
                "skipped": 0,
                "total": len(tests),
                "elapsed_ms": sum(t["ms"] for t in tests),
            },
            "all_passed": all(t["status"] == "pass" for t in tests) if tests else False,
            "raw_output": raw,
        }

        return result

    except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
        return {
            "tier": tier,
            "filter": filter_pattern,
            "error": f"Socket connection failed: {e}",
            "tests": [],
            "summary": None,
            "all_passed": False,
        }
