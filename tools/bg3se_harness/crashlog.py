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
LOGS_DIR = BG3SE_DIR / "logs"
RING_PATTERN = str(BG3SE_DIR / "crash_ring_*.bin")
DIAGNOSTIC_REPORTS_DIR = Path.home() / "Library/Logs/DiagnosticReports"


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


def _read_log_lines(path):
    if not path or not Path(path).exists():
        return []
    with open(path, errors="replace") as f:
        return [line.rstrip() for line in f]


def _find_log_for_pid(pid):
    if not pid or not LOGS_DIR.exists():
        return LATEST_LOG if LATEST_LOG.exists() else None
    needle = f"PID: {pid}"
    for path in sorted(LOGS_DIR.glob("bg3se_*.log"), key=os.path.getmtime, reverse=True):
        try:
            with open(path, errors="replace") as f:
                for line in f:
                    if needle in line:
                        return path
        except OSError:
            continue
    return LATEST_LOG if LATEST_LOG.exists() else None


def _find_latest_ips():
    pattern = str(DIAGNOSTIC_REPORTS_DIR / "Baldur's Gate 3*.ips")
    reports = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    return Path(reports[0]) if reports else None


def _load_ips_json(path):
    """Load an Apple .ips report, which is header JSON plus body JSON."""
    text = Path(path).read_text(errors="replace")
    parts = text.splitlines()
    if not parts:
        return None
    try:
        header = json.loads(parts[0])
    except json.JSONDecodeError:
        header = {}
    body_text = "\n".join(parts[1:]).strip()
    if not body_text:
        return {"header": header, "body": {}}
    try:
        body = json.loads(body_text)
    except json.JSONDecodeError:
        return {"header": header, "body": {}, "error": "Could not parse .ips body JSON"}
    return {"header": header, "body": body}


def _frame_image_name(frame, images):
    idx = frame.get("imageIndex")
    if isinstance(idx, int) and 0 <= idx < len(images):
        image = images[idx]
        return image.get("name") or image.get("path")
    return None


def _parse_latest_ips(path=None):
    ips_path = Path(path) if path else _find_latest_ips()
    if not ips_path or not ips_path.exists():
        return None

    loaded = _load_ips_json(ips_path)
    if not loaded:
        return None
    header = loaded.get("header", {})
    body = loaded.get("body", {})
    images = body.get("usedImages") or []
    faulting_index = body.get("faultingThread")
    threads = body.get("threads") or []
    faulting_thread = None
    if isinstance(faulting_index, int) and 0 <= faulting_index < len(threads):
        faulting_thread = threads[faulting_index]

    frames = []
    if faulting_thread:
        for i, frame in enumerate(faulting_thread.get("frames") or []):
            symbol = frame.get("symbol") or ""
            image_name = _frame_image_name(frame, images)
            frames.append({
                "frame": i,
                "symbol": symbol,
                "image": image_name,
                "image_index": frame.get("imageIndex"),
                "image_offset": frame.get("imageOffset"),
                "symbol_location": frame.get("symbolLocation"),
            })

    all_frames = []
    for thread in threads:
        for frame in thread.get("frames") or []:
            all_frames.append({
                "symbol": frame.get("symbol") or "",
                "image": _frame_image_name(frame, images),
            })

    exception = body.get("exception") or {}
    libbg3se_on_faulting_stack = any(
        "libbg3se" in str(frame.get("image", "")).lower()
        for frame in frames
    )
    libbg3se_any_thread = any(
        "libbg3se" in str(frame.get("image", "")).lower()
        for frame in all_frames
    )

    return {
        "path": str(ips_path),
        "timestamp": header.get("timestamp") or body.get("captureTime"),
        "app_version": header.get("app_version") or body.get("bundleInfo", {}).get("CFBundleShortVersionString"),
        "pid": body.get("pid"),
        "exception_type": exception.get("type"),
        "exception_signal": exception.get("signal"),
        "exception_subtype": exception.get("subtype"),
        "fault_address": "0x10" if "0x0000000000000010" in str(exception) else None,
        "faulting_thread": faulting_index,
        "faulting_thread_name": faulting_thread.get("name") if faulting_thread else None,
        "faulting_frames": frames[:16],
        "top_symbol": frames[0].get("symbol") if frames else None,
        "libbg3se_on_faulting_stack": libbg3se_on_faulting_stack,
        "libbg3se_any_thread": libbg3se_any_thread,
        "parse_error": loaded.get("error"),
    }


def _extract_enabled_mods(log_lines):
    mods = []
    in_block = False
    for line in log_lines or []:
        if "=== Enabled Mods ===" in line:
            in_block = True
            continue
        if not in_block:
            continue
        if "====================" in line or "Total mods:" in line:
            break
        m = re.search(r"\[Mod\s+\]\s+\[(\d+)\]\s+(.+)$", line)
        if not m:
            continue
        name = m.group(2).strip()
        if name.endswith("(base game)"):
            name = name.removesuffix("(base game)").strip()
        mods.append({"index": int(m.group(1)), "name": name})
    return mods


def _extract_log_milestones(log_lines):
    milestones = []
    for line in log_lines or []:
        if re.search(r"(>>> Event\[\d+\]:|Dispatching) (LevelLoaded|GainedControl)\b", line):
            milestones.append(line)
        elif "continueGame" in line or "loadSaveGame" in line:
            milestones.append(line)
    return milestones[-50:]


def _classify_crash(ips_report, log_lines):
    if not ips_report:
        return None
    symbols = " ".join(
        frame.get("symbol") or ""
        for frame in ips_report.get("faulting_frames", [])
    )
    milestones = _extract_log_milestones(log_lines)
    reached_loaded_save = any(
        "LevelLoaded" in line or "GainedControl" in line
        for line in milestones
    )
    if "HotbarSystem::Update" in symbols:
        if reached_loaded_save:
            return "post_level_loaded_hotbar_update"
        return "hotbar_update_crash"
    if ips_report.get("exception_type") == "EXC_BAD_ACCESS":
        return "native_bad_access"
    return "unknown"


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

    ips_report = _parse_latest_ips()
    if ips_report:
        result["macos_ips"] = ips_report
        matched_log = _find_log_for_pid(ips_report.get("pid"))
        all_log_lines = _read_log_lines(matched_log)
        if matched_log:
            result["matched_log"] = str(matched_log)
        enabled_mods = _extract_enabled_mods(all_log_lines)
        milestones = _extract_log_milestones(all_log_lines)
        if enabled_mods:
            result["enabled_mods"] = enabled_mods
        if milestones:
            result["log_milestones"] = milestones
        result["crash_phase"] = _classify_crash(ips_report, all_log_lines)
        if result["crash_phase"] == "post_level_loaded_hotbar_update":
            result["likely_cause"] = (
                "Loaded-save UI/mod-state crash: BG3 reached the save, then "
                "faulted in HotbarSystem::Update. Verify save-required mods, "
                "load order, and hotbar/spell/item-providing mods."
            )

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
