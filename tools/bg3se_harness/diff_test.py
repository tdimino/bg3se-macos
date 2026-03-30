"""Compare test results against a saved baseline.

    bg3se-harness test > baseline.json
    # ... make changes ...
    bg3se-harness test > current.json
    bg3se-harness diff-test baseline.json current.json --threshold 50

Pure Python — no socket needed.
"""

import json
import sys


def diff_results(baseline_path, current_path, threshold_pct=None):
    """Compare two test result JSON files. Returns diff dict."""
    with open(baseline_path) as f:
        baseline = json.load(f)
    with open(current_path) as f:
        current = json.load(f)

    base_tests = {t["name"]: t for t in baseline.get("tests", [])}
    curr_tests = {t["name"]: t for t in current.get("tests", [])}

    base_names = set(base_tests.keys())
    curr_names = set(curr_tests.keys())

    new_failures = []
    new_passes = []
    timing_regressions = []
    missing_tests = sorted(base_names - curr_names)
    new_tests = sorted(curr_names - base_names)

    for name in base_names & curr_names:
        bt = base_tests[name]
        ct = curr_tests[name]

        # Status changes
        if bt["status"] == "pass" and ct["status"] == "fail":
            new_failures.append(name)
        elif bt["status"] == "fail" and ct["status"] == "pass":
            new_passes.append(name)

        # Timing regressions
        if threshold_pct and bt.get("ms") and ct.get("ms") and bt["ms"] > 0:
            regression = ((ct["ms"] - bt["ms"]) / bt["ms"]) * 100
            if regression > threshold_pct:
                timing_regressions.append({
                    "name": name,
                    "baseline_ms": bt["ms"],
                    "current_ms": ct["ms"],
                    "regression_pct": round(regression, 1),
                })

    has_regression = bool(new_failures) or bool(timing_regressions)
    verdict = "REGRESSION" if has_regression else "OK"

    return {
        "verdict": verdict,
        "new_failures": sorted(new_failures),
        "new_passes": sorted(new_passes),
        "timing_regressions": timing_regressions,
        "missing_tests": missing_tests,
        "new_tests": new_tests,
        "baseline_summary": baseline.get("summary", {}),
        "current_summary": current.get("summary", {}),
    }


def cmd_diff_test(args):
    """CLI handler."""
    try:
        threshold = getattr(args, "threshold", None)
        result = diff_results(args.baseline, args.current, threshold_pct=threshold)
        print(json.dumps(result, indent=2))
        return 0 if result["verdict"] == "OK" else 1
    except FileNotFoundError as e:
        print(json.dumps({"error": str(e)}))
        return 1
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON: {e}"}))
        return 1
