import json
import sys

from .console import Console


def eval_lua(source):
    """Execute Lua from file path or '-' for stdin. Returns output string."""
    if source == "-":
        code = sys.stdin.read()
    else:
        with open(source) as f:
            code = f.read()

    with Console() as c:
        if "\n" in code:
            return c.send_lua(code)
        return c.send(code)


def cmd_eval(args):
    """CLI handler."""
    try:
        output = eval_lua(args.source)
        print(output)
        return 0
    except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
        print(json.dumps({"error": f"Socket connection failed: {e}"}))
        return 1
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        return 1
