from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

from .config import (
    BG3_EXEC, GRAPHIC_SETTINGS_PATH, HEALTH_TIMEOUT, HEALTH_TIMEOUT_CONTINUE,
    SOCKET_PATH,
)
from .flags import build_flag_args


def kill_existing():
    subprocess.run(
        ["pkill", "-f", "Baldur's Gate 3"],
        capture_output=True,
    )
    time.sleep(1)


def clean_socket():
    try:
        os.unlink(SOCKET_PATH)
    except FileNotFoundError:
        pass


def ensure_no_launcher():
    """Set com.larian.bg3 NoLauncher=1 to bypass the Larian WebKit launcher."""
    subprocess.run(
        ["defaults", "write", "com.larian.bg3", "NoLauncher", "1"],
        capture_output=True,
    )


def ensure_skip_videos():
    """Set SkipVideo + SkipSplashScreen via defaults and graphicSettings.lsx.

    Best-effort — never blocks launch on failure.
    """
    try:
        # Layer 1: macOS UserDefaults (mirrors ensure_no_launcher pattern)
        subprocess.run(
            ["defaults", "write", "com.larian.bg3", "SkipVideo", "-bool", "true"],
            capture_output=True,
        )

        # Layer 2: graphicSettings.lsx ConfigEntry injection
        _upsert_graphic_settings({"SkipVideo": 1, "SkipSplashScreen": 1})
    except Exception as exc:
        print(f"Warning: skip-videos setup failed: {exc}", file=sys.stderr)


def _upsert_graphic_settings(entries: dict[str, int]) -> None:
    """Insert or update ConfigEntry nodes in graphicSettings.lsx."""
    path = GRAPHIC_SETTINGS_PATH
    if not path.exists():
        return

    try:
        tree = ET.parse(path)
    except (ET.ParseError, OSError) as exc:
        print(f"Warning: could not parse {path}: {exc}", file=sys.stderr)
        return

    root = tree.getroot()

    # Find the <children> node that holds ConfigEntry nodes
    config_children = None
    for children in root.iter("children"):
        for node in children.findall("node"):
            if node.get("id") == "ConfigEntry":
                config_children = children
                break
        if config_children is not None:
            break

    if config_children is None:
        return

    # Index existing entries by MapKey
    existing = {}
    for node in config_children.findall("node"):
        if node.get("id") != "ConfigEntry":
            continue
        for attr in node.findall("attribute"):
            if attr.get("id") == "MapKey":
                existing[attr.get("value")] = node
                break

    changed = False
    for key, value in entries.items():
        if key in existing:
            # Update existing entry's Value attribute
            for attr in existing[key].findall("attribute"):
                if attr.get("id") == "Value":
                    if attr.get("value") != str(value):
                        attr.set("value", str(value))
                        changed = True
                    break
        else:
            # Create new ConfigEntry node
            entry = ET.SubElement(config_children, "node", id="ConfigEntry")
            ET.SubElement(entry, "attribute", id="MapKey", type="FixedString", value=key)
            ET.SubElement(entry, "attribute", id="Type", type="int32", value="0")
            ET.SubElement(entry, "attribute", id="Value", type="int32", value=str(value))
            changed = True

    if changed:
        # Backup before first write
        bak = path.with_suffix(".lsx.bak")
        if not bak.exists():
            shutil.copy2(path, bak)
        tree.write(path, xml_declaration=True, encoding="unicode")


def launch(continue_game=False, load_save=None, extra_flags=None, skip_videos=True):
    kill_existing()
    clean_socket()
    ensure_no_launcher()
    if skip_videos:
        ensure_skip_videos()

    # NoLauncher defaults key bypasses the Larian WebKit launcher.
    # insert_dylib bakes LC_LOAD_WEAK_DYLIB into the binary, so SE loads
    # automatically — no DYLD env vars needed.
    # Note: --skip-launcher does NOT exist in the macOS binary (confirmed via strings).
    cmd = ["arch", "-arm64", str(BG3_EXEC)]

    # -continueGame and -loadSaveGame are mutually exclusive
    # (enforced by GameStateInit in the binary).
    if continue_game:
        cmd.append("-continueGame")
    elif load_save:
        cmd.extend(["-loadSaveGame", load_save])

    if extra_flags:
        cmd.extend(build_flag_args(extra_flags))

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    flags_desc = " ".join(cmd[4:]) if len(cmd) > 4 else "(no extra flags)"
    print(f"Launched BG3 (pid {proc.pid}) [{flags_desc}]", file=sys.stderr)

    return proc


def default_timeout(continue_game=False, load_save=None):
    """Return appropriate timeout — loading a save takes longer."""
    if continue_game or load_save:
        return HEALTH_TIMEOUT_CONTINUE
    return HEALTH_TIMEOUT


_MAX_DISMISS_ATTEMPTS = 8


def wait_for_socket(timeout=HEALTH_TIMEOUT, dismiss_splash=False):
    """Wait for the SE socket to respond to Lua commands.

    When dismiss_splash is True, periodically sends a CGEvent Space key
    to dismiss the BG3 'Press Any Key' splash screen while waiting.
    Dismissal stops as soon as the socket accepts a connection (splash
    is gone at that point) or after _MAX_DISMISS_ATTEMPTS, whichever
    comes first. Only returns success when the socket responds to a
    command, not merely when it accepts a connection.
    """
    start = time.monotonic()
    interval = 0.5
    dismiss_delay = 5.0
    dismiss_interval = 3.0
    last_dismiss = 0.0
    dismiss_count = 0
    socket_ever_connected = False

    while (time.monotonic() - start) < timeout:
        elapsed = time.monotonic() - start

        if (dismiss_splash
                and not socket_ever_connected
                and dismiss_count < _MAX_DISMISS_ATTEMPTS
                and elapsed >= dismiss_delay):
            since_last = elapsed - last_dismiss
            if last_dismiss == 0 or since_last >= dismiss_interval:
                last_dismiss = elapsed
                dismiss_count += 1
                _try_dismiss_splash(dismiss_count)

        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect(SOCKET_PATH)
            socket_ever_connected = True

            time.sleep(0.3)
            try:
                sock.recv(4096)
            except socket.timeout:
                pass

            sock.sendall(b"Ext.GetVersion()\n")
            time.sleep(0.5)

            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            sock.close()

            if response:
                text = re.sub(rb'\033\[[0-9;]*m', b'', response).decode(
                    "utf-8", errors="replace").strip()
                elapsed_ms = int((time.monotonic() - start) * 1000)
                return {
                    "socket_connected": True,
                    "se_version": text if text else "connected",
                    "elapsed_ms": elapsed_ms,
                }

        except (ConnectionRefusedError, FileNotFoundError, OSError):
            pass

        time.sleep(interval)

    elapsed_ms = int((time.monotonic() - start) * 1000)
    return {"socket_connected": False, "elapsed_ms": elapsed_ms}


def _try_dismiss_splash(attempt):
    """Send CGEvent key + click to dismiss the splash screen."""
    try:
        from .menu import dismiss_splash_aggressive
        result = dismiss_splash_aggressive()
        if result.get("success"):
            methods = result.get("methods", {})
            parts = [k for k, v in methods.items() if v]
            print(f"Splash dismiss #{attempt} ({', '.join(parts)})",
                  file=sys.stderr)
    except Exception:
        pass


def is_running():
    result = subprocess.run(
        ["pgrep", "-f", "Baldur's Gate 3"],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def quit_game(force=False):
    """Quit BG3. Tries graceful AppleScript first, falls back to SIGTERM."""
    if not is_running():
        return {"success": True, "method": "not_running"}

    if not force:
        # Graceful: AppleScript quit
        result = subprocess.run(
            ["osascript", "-e", 'quit app "Baldur\'s Gate 3"'],
            capture_output=True, text=True,
        )
        # Wait up to 10s for graceful exit
        for _ in range(10):
            time.sleep(1)
            if not is_running():
                return {"success": True, "method": "graceful"}

    # Force: pkill
    kill_existing()
    if not is_running():
        return {"success": True, "method": "force"}
    return {"success": False, "method": "failed"}


def socket_alive():
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(SOCKET_PATH)
        sock.close()
        return True
    except (ConnectionRefusedError, FileNotFoundError, OSError):
        return False
