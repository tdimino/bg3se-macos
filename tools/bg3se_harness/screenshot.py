"""BG3 game window screenshot capture.

Captures the BG3 window via screencapture and resizes to JPEG for
Claude Code safety (Claude's vision token limit: ~1568px max dimension,
~(w*h)/750 tokens per image).

Usage:
    python3 -m bg3se_harness screenshot [--raw] [--output PATH]

Output (stdout JSON):
    {"path": "...", "width": N, "height": N, "tokens_est": N, "size_bytes": N}

Errors:
    {"error": "BG3 window not found"}
    {"error": "Screenshot capture failed"}
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from .config import PROJECT_ROOT

SCREENSHOTS_DIR = PROJECT_ROOT / ".screenshots"
MAX_DIMENSION = 1568  # Claude Code safe limit
JPEG_QUALITY = 80


def get_window_id():
    """Get BG3 window ID via osascript. Returns str or None."""
    script = (
        'tell application "System Events" to '
        'get id of window 1 of process "Baldur\'s Gate 3"'
    )
    try:
        result = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            wid = result.stdout.strip()
            if wid:
                return wid
    except Exception:
        pass
    return None


def get_image_dimensions(path):
    """Get (width, height) of an image via sips. Returns (int, int)."""
    try:
        result = subprocess.run(
            ["sips", "-g", "pixelWidth", "-g", "pixelHeight", str(path)],
            capture_output=True,
            text=True,
        )
        width = height = 0
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("pixelWidth:"):
                width = int(line.split(":")[1].strip())
            elif line.startswith("pixelHeight:"):
                height = int(line.split(":")[1].strip())
        return width, height
    except Exception:
        return 0, 0


def capture(output=None, raw=False):
    """Capture BG3 window and return result dict.

    Args:
        output: Optional Path or str for destination file. Defaults to
                SCREENSHOTS_DIR / "latest.jpg" (or "latest.png" if raw).
        raw:    If True, skip resize; keep original PNG.

    Returns:
        dict with keys: path, width, height, tokens_est, size_bytes, format
        On error: dict with key: error
    """
    window_id = get_window_id()
    if window_id is None:
        return {"error": "BG3 window not found"}

    SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)

    if raw:
        if output is None:
            dest = SCREENSHOTS_DIR / "latest.png"
        else:
            dest = Path(output)
        dest.parent.mkdir(parents=True, exist_ok=True)

        result = subprocess.run(
            ["screencapture", "-l", window_id, "-x", "-o", str(dest)],
            capture_output=True,
        )
        if result.returncode != 0 or not dest.exists():
            return {"error": "Screenshot capture failed"}

        width, height = get_image_dimensions(dest)
        tokens_est = (width * height) // 750
        size_bytes = dest.stat().st_size
        print(f"[screenshot: ~{tokens_est} tokens, {width}x{height}]", file=sys.stderr)
        return {
            "path": str(dest),
            "width": width,
            "height": height,
            "tokens_est": tokens_est,
            "size_bytes": size_bytes,
            "format": "png",
        }

    # Capture to a temp PNG first, then resize to JPEG
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".png", prefix="bg3se_shot_")
    os.close(tmp_fd)
    tmp_png = Path(tmp_path)

    try:
        result = subprocess.run(
            ["screencapture", "-l", window_id, "-x", "-o", str(tmp_png)],
            capture_output=True,
        )
        if result.returncode != 0 or not tmp_png.exists():
            return {"error": "Screenshot capture failed"}

        if output is None:
            dest = SCREENSHOTS_DIR / "latest.jpg"
        else:
            dest = Path(output)
        dest.parent.mkdir(parents=True, exist_ok=True)

        # Resize + convert to JPEG
        resize_result = subprocess.run(
            [
                "sips",
                "--resampleHeightWidthMax", str(MAX_DIMENSION),
                "-s", "format", "jpeg",
                "-s", "formatOptions", str(JPEG_QUALITY),
                str(tmp_png),
                "--out", str(dest),
            ],
            capture_output=True,
        )
        if resize_result.returncode != 0 or not dest.exists():
            return {"error": "Screenshot capture failed"}

    finally:
        try:
            tmp_png.unlink(missing_ok=True)
        except Exception:
            pass

    width, height = get_image_dimensions(dest)
    tokens_est = (width * height) // 750
    size_bytes = dest.stat().st_size
    print(f"[screenshot: ~{tokens_est} tokens, {width}x{height}]", file=sys.stderr)
    return {
        "path": str(dest),
        "width": width,
        "height": height,
        "tokens_est": tokens_est,
        "size_bytes": size_bytes,
        "format": "jpeg",
    }


def cmd_screenshot(args):
    """CLI handler for the screenshot command."""
    output = getattr(args, "output", None)
    raw = getattr(args, "raw", False)
    result = capture(output=output, raw=raw)
    print(json.dumps(result, indent=2))
    return 0 if "error" not in result else 1
