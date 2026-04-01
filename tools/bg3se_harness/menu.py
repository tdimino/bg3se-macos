"""BG3 main menu automation via macOS Vision OCR + CGEvent clicks.

Detects menu state by running Vision OCR (VNRecognizeTextRequest) on a
window screenshot, then clicks buttons via Quartz CGEvent API. All stdlib,
no pip dependencies required.

Architecture:
    screencapture -l <wid> -> Vision OCR (osascript JXA) -> detected buttons
        -> CGEvent click (ctypes + ApplicationServices) targeted at BG3 window

Usage:
    python3 -m bg3se_harness menu detect       # JSON: visible buttons
    python3 -m bg3se_harness menu click "Continue"
    python3 -m bg3se_harness menu wait         # Poll until menu visible
"""

from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .screenshot import get_window_id, get_image_dimensions


# ============================================================================
# CGEvent Click (ctypes + Quartz -- stdlib, zero deps)
# ============================================================================

_appservices = None


def _get_appservices():
    global _appservices
    if _appservices is None:
        lib = ctypes.util.find_library("ApplicationServices")
        if not lib:
            raise RuntimeError("ApplicationServices framework not found")
        _appservices = ctypes.CDLL(lib)
    return _appservices


class CGPoint(ctypes.Structure):
    _fields_ = [("x", ctypes.c_double), ("y", ctypes.c_double)]


_kCGEventLeftMouseDown = 1
_kCGEventLeftMouseUp = 2
_kCGMouseButtonLeft = 0
_kCGHIDEventTap = 0


def cg_click(x, y):
    """Send a mouse click at global screen coordinates (x, y) via CGEvent."""
    qs = _get_appservices()
    point = CGPoint(float(x), float(y))

    qs.CGEventCreateMouseEvent.restype = ctypes.c_void_p
    qs.CGEventCreateMouseEvent.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, CGPoint, ctypes.c_uint32,
    ]
    qs.CGEventPost.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
    qs.CFRelease.argtypes = [ctypes.c_void_p]

    ev_down = qs.CGEventCreateMouseEvent(
        None, _kCGEventLeftMouseDown, point, _kCGMouseButtonLeft,
    )
    ev_up = qs.CGEventCreateMouseEvent(
        None, _kCGEventLeftMouseUp, point, _kCGMouseButtonLeft,
    )
    if not ev_down or not ev_up:
        return False

    qs.CGEventPost(_kCGHIDEventTap, ev_down)
    time.sleep(0.05)
    qs.CGEventPost(_kCGHIDEventTap, ev_up)

    qs.CFRelease(ev_down)
    qs.CFRelease(ev_up)
    return True


# ============================================================================
# Window geometry
# ============================================================================

def _get_window_bounds():
    """Get BG3 window bounds {x, y, width, height} via osascript."""
    script = (
        'tell application "System Events"\n'
        '  set bgProc to first process whose name is "Baldur\'s Gate 3"\n'
        '  set {x, y} to position of window 1 of bgProc\n'
        '  set {w, h} to size of window 1 of bgProc\n'
        '  return (x as text) & "," & (y as text) & "," '
        '& (w as text) & "," & (h as text)\n'
        'end tell'
    )
    try:
        result = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return None
        parts = result.stdout.strip().split(",")
        if len(parts) != 4:
            return None
        return {
            "x": int(parts[0].strip()),
            "y": int(parts[1].strip()),
            "width": int(parts[2].strip()),
            "height": int(parts[3].strip()),
        }
    except (subprocess.TimeoutExpired, ValueError, OSError):
        return None


# ============================================================================
# Vision OCR (macOS 12+, stdlib -- runs via osascript JXA)
# ============================================================================

_VISION_OCR_JXA = r'''
ObjC.import("Vision");
ObjC.import("AppKit");

function run(argv) {
    var imagePath = argv[0];
    var url = $.NSURL.fileURLWithPath(imagePath);
    var image = $.NSImage.alloc.initWithContentsOfURL(url);
    if (!image || !image.isValid) {
        return JSON.stringify({"error": "Could not load image"});
    }

    var cgRef = image.CGImageForProposedRect(null, null, null);
    if (!cgRef) {
        return JSON.stringify({"error": "Could not get CGImage"});
    }

    var request = $.VNRecognizeTextRequest.alloc.init;
    request.recognitionLevel = 1;
    request.usesLanguageCorrection = true;

    var handler = $.VNImageRequestHandler.alloc.initWithCGImageOptions(cgRef, null);
    handler.performRequestsError($.NSArray.arrayWithObject(request), null);

    var results = request.results;
    var items = [];
    var count = results.count;

    for (var i = 0; i < count; i++) {
        var obs = results.objectAtIndex(i);
        var text = obs.topCandidates(1).objectAtIndex(0).string.js;
        var box = obs.boundingBox;

        items.push({
            "text": text,
            "confidence": obs.confidence,
            "bbox": {
                "x": box.origin.x,
                "y": box.origin.y,
                "width": box.size.width,
                "height": box.size.height
            }
        });
    }

    return JSON.stringify({"results": items});
}
'''


def _ocr_screenshot(image_path):
    """Run Vision OCR on an image file.

    Returns list of {text, confidence, bbox}. bbox uses Vision's normalized
    coordinates: origin bottom-left, values 0-1.
    """
    try:
        result = subprocess.run(
            ["osascript", "-l", "JavaScript", "-e", _VISION_OCR_JXA, str(image_path)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return []
        data = json.loads(result.stdout.strip())
        if "error" in data:
            print(f"[menu] OCR error: {data['error']}", file=sys.stderr)
            return []
        return data.get("results", [])
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
        print(f"[menu] OCR failed: {e}", file=sys.stderr)
        return []


def _capture_window_screenshot():
    """Capture BG3 window to a temp PNG. Returns path or None."""
    wid = get_window_id()
    if not wid:
        return None

    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".png", prefix="bg3se_menu_")
    os.close(tmp_fd)

    result = subprocess.run(
        ["screencapture", "-l", wid, "-x", "-o", tmp_path],
        capture_output=True,
    )
    if result.returncode != 0 or not Path(tmp_path).exists():
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return None
    return tmp_path


# ============================================================================
# Known BG3 menu button labels
# ============================================================================

KNOWN_BUTTONS = [
    "Continue",
    "New Game",
    "Load Game",
    "Multiplayer",
    "Options",
    "Credits",
    "Quit Game",
    "Honour Mode",
    "Click to Continue",
    "Press Any Key",
]


def _normalize(text):
    return text.lower().strip().replace("  ", " ")


def _fuzzy_match(ocr_text, target):
    """Check if OCR text is a fuzzy match for a target button label."""
    norm_ocr = _normalize(ocr_text)
    norm_target = _normalize(target)
    if norm_ocr == norm_target:
        return True
    if norm_target in norm_ocr or norm_ocr in norm_target:
        return True
    cleaned = norm_ocr.replace("0", "o").replace("l", "i")
    cleaned_target = norm_target.replace("0", "o").replace("l", "i")
    return cleaned == cleaned_target


# ============================================================================
# Public API
# ============================================================================

def detect_menu():
    """Detect which menu buttons are visible via OCR.

    Returns dict with buttons (matched known labels with screen coords),
    raw_ocr (all recognized text), and window bounds.
    """
    screenshot_path = _capture_window_screenshot()
    if not screenshot_path:
        return {"error": "BG3 window not found", "buttons": []}

    bounds = _get_window_bounds()
    ocr_results = _ocr_screenshot(screenshot_path)
    img_w, img_h = get_image_dimensions(screenshot_path)

    try:
        os.unlink(screenshot_path)
    except OSError:
        pass

    buttons = []
    raw_ocr = []
    for item in ocr_results:
        text = item["text"]
        conf = item.get("confidence", 0)
        bbox = item.get("bbox", {})

        raw_ocr.append({"text": text, "confidence": round(conf, 3)})

        matched_label = None
        for known in KNOWN_BUTTONS:
            if _fuzzy_match(text, known):
                matched_label = known
                break

        if matched_label and bounds and img_w and img_h:
            # Vision bbox: origin bottom-left, normalized 0-1
            center_x_norm = bbox.get("x", 0) + bbox.get("width", 0) / 2
            center_y_norm = bbox.get("y", 0) + bbox.get("height", 0) / 2

            # Convert to pixel coords (flip Y: Vision bottom-up, screen top-down)
            px_x = center_x_norm * img_w
            px_y = (1.0 - center_y_norm) * img_h

            # Retina: image pixels vs window points
            scale_x = img_w / bounds["width"] if bounds["width"] else 1
            scale_y = img_h / bounds["height"] if bounds["height"] else 1

            screen_x = bounds["x"] + int(px_x / scale_x)
            screen_y = bounds["y"] + int(px_y / scale_y)

            buttons.append({
                "text": matched_label,
                "screen_x": screen_x,
                "screen_y": screen_y,
                "confidence": round(conf, 3),
            })

    result = {"buttons": buttons, "raw_ocr": raw_ocr}
    if bounds:
        result["window"] = bounds
    return result


def click_menu_button(button_name):
    """Click a specific menu button by name.

    Activates BG3 window, runs OCR to find the button, clicks via CGEvent.
    """
    # Activate BG3 window
    try:
        subprocess.run(
            ["osascript", "-e",
             'tell application "System Events" to '
             'set frontmost of process "Baldur\'s Gate 3" to true'],
            capture_output=True, timeout=5,
        )
        time.sleep(0.3)
    except (subprocess.TimeoutExpired, OSError):
        pass

    detection = detect_menu()
    if "error" in detection and not detection.get("buttons"):
        return {"success": False, "error": detection["error"]}

    target = None
    for btn in detection["buttons"]:
        if _fuzzy_match(btn["text"], button_name):
            target = btn
            break

    if not target:
        available = [b["text"] for b in detection["buttons"]]
        return {
            "success": False,
            "error": f"Button '{button_name}' not found",
            "available_buttons": available,
            "raw_ocr": [r["text"] for r in detection.get("raw_ocr", [])],
        }

    clicked = cg_click(target["screen_x"], target["screen_y"])
    return {
        "success": clicked,
        "button": target["text"],
        "screen_x": target["screen_x"],
        "screen_y": target["screen_y"],
    }


def wait_for_menu(timeout=60, poll_interval=3):
    """Poll until the main menu is visible (any known button detected)."""
    start = time.monotonic()
    attempts = 0

    while (time.monotonic() - start) < timeout:
        attempts += 1
        detection = detect_menu()
        if detection.get("buttons"):
            detection["wait_elapsed_s"] = round(time.monotonic() - start, 1)
            detection["attempts"] = attempts
            return detection
        time.sleep(poll_interval)

    return {
        "error": "Timed out waiting for menu",
        "timeout": timeout,
        "attempts": attempts,
        "buttons": [],
    }


def dismiss_splash():
    """Dismiss the 'Click to Continue' splash screen via Space key."""
    try:
        subprocess.run(
            ["osascript", "-e",
             'tell application "System Events"\n'
             '  set frontmost of process "Baldur\'s Gate 3" to true\n'
             '  delay 0.5\n'
             '  key code 49\n'
             'end tell'],
            capture_output=True, timeout=10,
        )
        return {"success": True, "action": "sent_space"}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "osascript timed out"}
    except (FileNotFoundError, OSError) as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# CLI handler
# ============================================================================

def cmd_menu(args):
    """CLI handler for menu subcommands."""
    subcmd = args.menu_command

    if subcmd == "detect":
        result = detect_menu()
        print(json.dumps(result, indent=2))
        return 0 if result.get("buttons") else 1

    elif subcmd == "click":
        result = click_menu_button(args.button)
        print(json.dumps(result, indent=2))
        return 0 if result.get("success") else 1

    elif subcmd == "wait":
        timeout = getattr(args, "timeout", 60) or 60
        result = wait_for_menu(timeout=timeout)
        print(json.dumps(result, indent=2))
        return 0 if result.get("buttons") else 1

    elif subcmd == "dismiss":
        result = dismiss_splash()
        print(json.dumps(result, indent=2))
        return 0 if result.get("success") else 1

    return 1
