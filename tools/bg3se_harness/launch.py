from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time

from .config import BG3_EXEC, HEALTH_TIMEOUT, HEALTH_TIMEOUT_CONTINUE, SOCKET_PATH
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


def launch(continue_game=False, load_save=None, extra_flags=None):
    kill_existing()
    clean_socket()
    ensure_no_launcher()

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

    # Auto-dismiss "Press to Continue" splash screen.
    # BG3 shows a Noesis UI modal after launcher close that blocks even with
    # -continueGame. The SE socket isn't available yet, so we send a keypress
    # via osascript after a delay. Runs in a daemon thread to not block.
    if continue_game or load_save:
        _dismiss_continue_screen(proc)

    return proc


def _dismiss_continue_screen(proc, delay=8, retries=5):
    """Dismiss 'Click to Continue' by activating BG3 window and sending input.

    The splash is a Noesis UI modal that only responds to input directed at
    the BG3 window. We must: (1) activate the window, (2) send Space/Enter.
    Retries every 3s because the splash may appear at different times
    depending on system load.
    """
    def dismisser():
        for attempt in range(retries):
            time.sleep(delay if attempt == 0 else 3)
            if proc.poll() is not None:
                return  # Process exited

            # Activate BG3 window and send Space key targeted at it
            subprocess.run(
                ["osascript", "-e",
                 'tell application "System Events"\n'
                 '  set frontmost of process "Baldur\'s Gate 3" to true\n'
                 '  delay 0.5\n'
                 '  key code 49\n'  # Space
                 'end tell'],
                capture_output=True,
            )
            print(f"Sent Space to BG3 window (attempt {attempt + 1}/{retries})",
                  file=sys.stderr)

            # Check if socket is now alive (splash dismissed)
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect(SOCKET_PATH)
                s.close()
                print("SE socket alive — splash dismissed", file=sys.stderr)
                return
            except (ConnectionRefusedError, FileNotFoundError, OSError):
                pass

    thread = threading.Thread(target=dismisser, daemon=True)
    thread.start()


def default_timeout(continue_game=False, load_save=None):
    """Return appropriate timeout — loading a save takes longer."""
    if continue_game or load_save:
        return HEALTH_TIMEOUT_CONTINUE
    return HEALTH_TIMEOUT


def wait_for_socket(timeout=HEALTH_TIMEOUT):
    start = time.monotonic()
    interval = 0.5

    while (time.monotonic() - start) < timeout:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect(SOCKET_PATH)

            # Drain welcome message / prompt
            time.sleep(0.3)
            try:
                sock.recv(4096)
            except socket.timeout:
                pass

            # Send version query
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
            elapsed = int((time.monotonic() - start) * 1000)

            # Strip ANSI codes for parsing
            import re
            text = re.sub(rb'\033\[[0-9;]*m', b'', response).decode("utf-8", errors="replace").strip()

            return {
                "socket_connected": True,
                "se_version": text if text else "connected",
                "elapsed_ms": elapsed,
            }

        except (ConnectionRefusedError, FileNotFoundError, OSError):
            time.sleep(interval)

    elapsed = int((time.monotonic() - start) * 1000)
    return {"socket_connected": False, "elapsed_ms": elapsed}


def is_running():
    result = subprocess.run(
        ["pgrep", "-f", "Baldur's Gate 3"],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def socket_alive():
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(SOCKET_PATH)
        sock.close()
        return True
    except (ConnectionRefusedError, FileNotFoundError, OSError):
        return False
