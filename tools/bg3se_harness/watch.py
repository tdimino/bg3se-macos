"""Hot-reload Lua files on change.

Watches a file for modifications and re-executes it in the running game
via socket IPC whenever the file is saved.
"""

import json
import os
import sys
import time

from .console import Console


def watch_file(path, once=False, interval=0.5):
    """Watch a Lua file and execute on change.

    Args:
        path: Path to Lua file.
        once: If True, execute once and exit.
        interval: Poll interval in seconds.

    Yields:
        (iteration, output) tuples on each execution.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")

    last_mtime = 0
    iteration = 0

    while True:
        try:
            mtime = os.stat(path).st_mtime
        except OSError as e:
            print(f"[watch] Error reading {path}: {e}", file=sys.stderr)
            if once:
                return
            time.sleep(interval)
            continue

        if mtime != last_mtime:
            last_mtime = mtime
            iteration += 1

            with open(path) as f:
                code = f.read()

            print(f"[watch] Executing {path} (#{iteration})...", file=sys.stderr)

            try:
                with Console() as c:
                    output = c.send_lua(code)
                yield iteration, output
            except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
                yield iteration, json.dumps({"error": f"Socket: {e}"})

        if once:
            return

        time.sleep(interval)


def cmd_watch(args):
    """CLI handler for watch command."""
    path = args.path
    once = getattr(args, "once", False)

    try:
        for iteration, output in watch_file(path, once=once):
            if output.strip():
                print(output)
            sys.stdout.flush()
    except KeyboardInterrupt:
        print(f"\n[watch] Stopped.", file=sys.stderr)
        return 0
    except FileNotFoundError as e:
        print(json.dumps({"error": str(e)}))
        return 1

    return 0
