"""Ghidra HTTP bridge client.

Wraps the GhidraMCP HTTP server (default: http://127.0.0.1:8080/) to provide
decompilation, string search, xref analysis, and function listing from the CLI.

The MCP wrapper may fail to connect to Claude Code sessions. This module hits
the HTTP bridge directly as a reliable alternative.

Endpoint reference (from GhidraMCPPlugin.java):
    /decompile, /decompile_function, /searchFunctions, /strings,
    /list_functions, /get_function_by_address, /xrefs_to, /xrefs_from,
    /function_xrefs, /methods, /segments, /classes, /data, /imports,
    /exports, /namespaces, /disassemble_function, /set_decompiler_comment,
    /rename_function_by_address, /set_function_prototype, ...
"""

import json
import urllib.parse
import urllib.request

GHIDRA_DEFAULT_URL = "http://127.0.0.1:8080"
TIMEOUT = 30


class GhidraBridge:
    def __init__(self, base_url=GHIDRA_DEFAULT_URL):
        self.base_url = base_url.rstrip("/")

    def _get(self, endpoint, params=None):
        """GET request to the bridge. Returns response text or None."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception:
            return None

    def _get_or_empty(self, endpoint, params=None):
        result = self._get(endpoint, params)
        return result if result else ""

    def status(self):
        """Check if the Ghidra bridge is alive and what program is loaded."""
        # Try /methods — it always works if the bridge is up
        text = self._get("methods", {"offset": "0", "limit": "1"})
        if text is None:
            return {"alive": False, "error": "Bridge not reachable"}

        # Try to get program info
        segments = self._get("segments")
        return {
            "alive": True,
            "url": self.base_url,
            "has_segments": segments is not None and len(segments) > 10,
        }

    def decompile(self, name_or_addr):
        """Decompile a function by name or address.

        If given a name, first resolves to address via searchFunctions,
        then uses /decompile_function (which requires address).
        Falls back to /decompile (accepts both name and address).
        """
        address = None
        name = None

        if name_or_addr.startswith("0x") or name_or_addr.startswith("FUN_"):
            address = name_or_addr
        else:
            name = name_or_addr
            # Resolve name to address via searchFunctions
            matches = self.search_functions(name)
            for match in matches:
                # Format: "funcName @ 0xADDRESS" or "funcName @ ADDRESS"
                if " @ " in match:
                    addr_part = match.split(" @ ")[-1].strip()
                    if not addr_part.startswith("0x"):
                        addr_part = "0x" + addr_part
                    address = addr_part
                    break

        # Try /decompile_function with address (richer output)
        if address:
            result = self._get("decompile_function", {"address": address})
            if result and "Function not found" not in result and "Address is required" not in result:
                return result

        # Fall back to /decompile (accepts name or address)
        params = {"address": address} if address else {"name": name_or_addr}
        result = self._get("decompile", params)
        if result and "Function not found" not in result:
            return result

        return None

    def search_strings(self, query):
        """Search strings in the binary via /strings?filter=query.

        Returns list of (address, string) tuples.
        """
        text = self._get_or_empty("strings", {"filter": query})
        results = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            # Format: "107bfc349: \"-continueGame\""
            if ": " in line:
                addr, _, rest = line.partition(": ")
                results.append((addr.strip(), rest.strip().strip('"')))
            else:
                results.append(("", line))
        return results

    def search_functions(self, query):
        """Search function names via /searchFunctions."""
        text = self._get_or_empty("searchFunctions", {"query": query})
        return [line.strip() for line in text.splitlines() if line.strip()]

    def xrefs_to(self, address):
        """Get cross-references TO an address via /xrefs_to."""
        text = self._get_or_empty("xrefs_to", {"address": address})
        return [line.strip() for line in text.splitlines() if line.strip()]

    def xrefs_from(self, address):
        """Get cross-references FROM an address via /xrefs_from."""
        text = self._get_or_empty("xrefs_from", {"address": address})
        return [line.strip() for line in text.splitlines() if line.strip()]

    def list_functions(self, offset=0, limit=50):
        """List functions with pagination via /list_functions."""
        text = self._get_or_empty("list_functions", {
            "offset": str(offset),
            "limit": str(limit),
        })
        return [line.strip() for line in text.splitlines() if line.strip()]

    def get_function_by_address(self, address):
        """Get function info at a specific address."""
        return self._get("get_function_by_address", {"address": address})

    def call_graph(self, name, depth=2):
        """Get function call graph via /function_xrefs."""
        return self._get_or_empty("function_xrefs", {"name": name})

    def disassemble(self, name_or_addr):
        """Get assembly listing for a function."""
        if name_or_addr.startswith("0x"):
            params = {"address": name_or_addr}
        else:
            params = {"name": name_or_addr}
        return self._get("disassemble_function", params)

    def methods(self, offset=0, limit=100):
        """List all method/symbol names."""
        text = self._get_or_empty("methods", {
            "offset": str(offset),
            "limit": str(limit),
        })
        return [line.strip() for line in text.splitlines() if line.strip()]
