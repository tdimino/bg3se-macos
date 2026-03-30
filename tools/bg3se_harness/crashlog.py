"""Crash diagnostics parser.

Reads BG3SE crash data from ~/Library/Application Support/BG3SE/:
- crash_ring_<pid>.bin (mmap'd 16KB ring buffer)
- crash.log (signal handler output)
- logs/latest.log (session log)

No socket needed — the game is crashed.
"""

import glob
import json
import os
import re
import sys
from pathlib import Path


BG3SE_DIR = Path.home() / "Library/Application Support/BG3SE"
CRASH_LOG = BG3SE_DIR / "crash.log"
LATEST_LOG = BG3SE_DIR / "logs/latest.log"
RING_PATTERN = str(BG3SE_DIR / "crash_ring_*.bin")


def _find_latest_ring():
    """Find the most recent crash ring buffer file."""
    rings = sorted(glob.glob(RING_PATTERN), key=os.path.getmtime, reverse=True)
    return Path(rings[0]) if rings else None


def _parse_crash_log():
    """Parse crash.log for signal, fault address, breadcrumbs, backtrace."""
    if not CRASH_LOG.exists():
        return None

    text = CRASH_LOG.read_text(errors="replace")
    result = {}

    # Signal
    m = re.search(r"Signal:\s*(\w+)", text)
    if m:
        result["signal"] = m.group(1)

    # Fault address
    m = re.search(r"(?:Fault|Address):\s*(0x[0-9a-fA-F]+)", text)
    if m:
        result["fault_address"] = m.group(1)

    # Breadcrumbs
    breadcrumbs = []
    for m in re.finditer(r"\[(\d{2}:\d{2}:\d{2})\]\s*(.+)", text):
        breadcrumbs.append({"timestamp": m.group(1), "message": m.group(2).strip()})
    if breadcrumbs:
        result["breadcrumbs"] = breadcrumbs

    # Backtrace frames
    frames = []
    for m in re.finditer(r"(\d+)\s+(0x[0-9a-fA-F]+)\s+(.+)", text):
        frames.append({
            "frame": int(m.group(1)),
            "address": m.group(2),
            "symbol": m.group(3).strip(),
        })
    if frames:
        result["backtrace"] = frames

    # File modification time as crash time
    result["crash_time"] = os.path.getmtime(str(CRASH_LOG))

    return result


def _read_ring_buffer(path):
    """Read and decode the crash ring buffer (16KB mmap'd circular buffer)."""
    if not path or not path.exists():
        return None

    data = path.read_bytes()
    # Ring buffer is ASCII text with null padding
    text = data.replace(b"\x00", b"").decode("utf-8", errors="replace").strip()
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines if lines else None


def _read_log_tail(n=50):
    """Read last N lines from the latest session log."""
    if not LATEST_LOG.exists():
        return None

    with open(LATEST_LOG, errors="replace") as f:
        lines = f.readlines()

    return [line.rstrip() for line in lines[-n:]]


def get_crash_report(ring=False, tail=50):
    """Build a structured crash report."""
    result = {}

    # Parse crash.log
    crash_data = _parse_crash_log()
    if crash_data:
        result.update(crash_data)

    # Ring buffer
    if ring:
        ring_path = _find_latest_ring()
        ring_data = _read_ring_buffer(ring_path)
        if ring_data:
            result["ring_buffer"] = ring_data
            if ring_path:
                result["ring_file"] = str(ring_path)

    # Session log tail
    log_lines = _read_log_tail(tail)
    if log_lines:
        result["last_log_lines"] = log_lines

    if not result:
        return {"error": "No crash data found", "search_paths": [
            str(CRASH_LOG), str(LATEST_LOG), RING_PATTERN,
        ]}

    return result


def cmd_crashlog(args):
    """CLI handler for crashlog command."""
    ring = getattr(args, "ring", False)
    tail = getattr(args, "tail", 50) or 50

    result = get_crash_report(ring=ring, tail=tail)
    print(json.dumps(result, indent=2, default=str))
    return 0 if "error" not in result else 1
