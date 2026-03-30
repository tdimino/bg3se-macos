import re
import select
import socket
import time

from .config import SOCKET_PATH

ANSI_RE = re.compile(r'\033\[[0-9;]*m')
PROMPT_RE = re.compile(r'(?:bg3se)?> $')


class Console:
    """Python client for the BG3SE Unix domain socket console."""

    def __init__(self, path=SOCKET_PATH, timeout=5):
        self._path = path
        self._timeout = timeout
        self._sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    def connect(self):
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(self._timeout)
        self._sock.connect(self._path)
        # Drain welcome message and initial prompt
        time.sleep(0.3)
        self._drain()

    def close(self):
        if self._sock:
            self._sock.close()
            self._sock = None

    def is_connected(self):
        if not self._sock:
            return False
        try:
            # Zero-byte send to check connection
            self._sock.sendall(b"")
            return True
        except OSError:
            return False

    def _drain(self):
        """Read and discard any pending data."""
        self._sock.setblocking(False)
        try:
            while True:
                data = self._sock.recv(4096)
                if not data:
                    break
        except BlockingIOError:
            pass
        finally:
            self._sock.settimeout(self._timeout)

    def _read_response(self, timeout=None):
        """Read until we see a prompt or timeout."""
        timeout = timeout or self._timeout
        buf = b""
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            ready, _, _ = select.select([self._sock], [], [], min(remaining, 0.1))
            if ready:
                try:
                    chunk = self._sock.recv(4096)
                    if not chunk:
                        break
                    buf += chunk

                    # Check if we've received a prompt (end of response)
                    text = buf.decode("utf-8", errors="replace")
                    if PROMPT_RE.search(text):
                        # Remove the trailing prompt
                        text = PROMPT_RE.sub("", text)
                        return self._clean(text)
                except socket.timeout:
                    break

        return self._clean(buf.decode("utf-8", errors="replace"))

    def _clean(self, text):
        """Strip ANSI escape codes and trailing whitespace."""
        return ANSI_RE.sub("", text).strip()

    def send(self, command, timeout=None):
        """Send a single-line command and return the response."""
        self._sock.sendall((command + "\n").encode("utf-8"))
        time.sleep(0.1)  # Give server time to process
        return self._read_response(timeout=timeout)

    def send_lua(self, code, timeout=None):
        """Send a multi-line Lua block using --[[ ]]-- delimiters."""
        block = f"--[[\n{code}\n]]--\n"
        self._sock.sendall(block.encode("utf-8"))
        time.sleep(0.2)
        return self._read_response(timeout=timeout)
