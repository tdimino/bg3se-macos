"""LSPK v18 PAK file reader for Baldur's Gate 3.

Port of src/pak/pak_reader.c. Pure Python, stdlib only.
zlib decompression is supported natively; LZ4-compressed entries are
skipped with a clear error rather than raising.

Format reference (from pak_reader.h / pak_reader.c):
  Header (40 bytes):
    +0   u32  signature    0x4B50534C ("LSPK")
    +4   u32  version      18
    +8   u64  file_list_offset
    +16  u32  file_list_size
    +20  ... (reserved/flags, not used by reader)

  File list (at file_list_offset):
    +0  u32  num_files
    +4  u32  compressed_size
    +8  <compressed blob>

  Each entry is 272 bytes:
    +0   char[256]  name (null-terminated path within archive)
    +256 u32        offset_lo
    +260 u16        offset_hi
    +262 u8         archive_part
    +263 u8         compression  (0=none, 1=zlib, 2=LZ4)
    +264 u32        disk_size
    +268 u32        uncompressed_size
"""

import json
import struct
import zlib
import xml.etree.ElementTree as ET
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants (mirrors pak_reader.h)
# ---------------------------------------------------------------------------

LSPK_MAGIC = b"LSPK"
LSPK_VERSION = 18
LSPK_ENTRY_SIZE = 272

PAK_COMPRESSION_NONE = 0
PAK_COMPRESSION_ZLIB = 1
PAK_COMPRESSION_LZ4 = 2

# LZ4 support is optional.  We attempt import once and cache the result.
try:
    import lz4.block as _lz4_block  # type: ignore
    _HAS_LZ4 = True
except ImportError:
    _lz4_block = None  # type: ignore
    _HAS_LZ4 = False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _decompress_lz4(data: bytes, uncompressed_size: int) -> bytes:
    """Attempt LZ4 decompression; raises RuntimeError if lz4 unavailable."""
    if not _HAS_LZ4:
        raise RuntimeError(
            "lz4 is not installed — cannot decompress LZ4-compressed data. "
            "Install it with: uv pip install lz4"
        )
    return _lz4_block.decompress(data, uncompressed_size=uncompressed_size)


def _decompress_entry(data: bytes, compression: int, uncompressed_size: int) -> bytes:
    """Decompress entry data according to compression type."""
    if compression == PAK_COMPRESSION_NONE:
        return data
    if compression == PAK_COMPRESSION_ZLIB:
        return zlib.decompress(data)
    if compression == PAK_COMPRESSION_LZ4:
        return _decompress_lz4(data, uncompressed_size)
    raise ValueError(f"Unknown compression type: {compression}")


def _parse_entries(raw: bytes, num_files: int) -> list:
    """Parse the decompressed file-list blob into a list of entry dicts."""
    entries = []
    for i in range(num_files):
        base = i * LSPK_ENTRY_SIZE
        if base + LSPK_ENTRY_SIZE > len(raw):
            break

        chunk = raw[base : base + LSPK_ENTRY_SIZE]

        # Name: 256 bytes, null-terminated
        name_bytes = chunk[:256]
        name = name_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")
        # Normalise Windows-style separators
        name = name.replace("\\", "/")

        # Offset: 48-bit value packed as u32 (lo) + u16 (hi)
        offset_lo = struct.unpack_from("<I", chunk, 256)[0]
        offset_hi = struct.unpack_from("<H", chunk, 260)[0]
        offset = offset_lo | (offset_hi << 32)

        archive_part = chunk[262]
        compression = chunk[263] & 0x0F

        disk_size = struct.unpack_from("<I", chunk, 264)[0]
        uncompressed_size = struct.unpack_from("<I", chunk, 268)[0]

        entries.append({
            "name": name,
            "offset": offset,
            "archive_part": archive_part,
            "compression": compression,
            "disk_size": disk_size,
            "uncompressed_size": uncompressed_size,
        })
    return entries


def _try_decompress_file_list(compressed: bytes, num_files: int) -> bytes:
    """Try zlib first, then LZ4 for the file list table.

    The LSPK v18 spec uses LZ4 for the file list (matching the C
    implementation), but some PAK tools produce zlib-compressed lists.
    We detect by probing both codecs.
    """
    expected_size = num_files * LSPK_ENTRY_SIZE

    # zlib streams start with 0x78 (CMF byte for deflate with default
    # compression window).  Try it first—it's stdlib and fast to fail.
    if len(compressed) >= 2 and compressed[0] == 0x78:
        try:
            return zlib.decompress(compressed)
        except zlib.error:
            pass

    # Try LZ4 (frame-less block format used by LSPK).
    if _HAS_LZ4:
        try:
            return _decompress_lz4(compressed, expected_size)
        except Exception:
            pass

    # Last resort: try zlib even without the magic byte.
    try:
        return zlib.decompress(compressed)
    except zlib.error:
        pass

    raise RuntimeError(
        f"Could not decompress file list table "
        f"({len(compressed)} bytes → expected {expected_size} bytes). "
        f"lz4 available: {_HAS_LZ4}"
    )


# ---------------------------------------------------------------------------
# mod metadata helpers
# ---------------------------------------------------------------------------

def _extract_mod_info_from_lsx(content: bytes) -> dict:
    """Parse meta.lsx and return a dict with mod UUID, name, author,
    description, and version.

    meta.lsx is a Larian XML dialect.  Relevant structure:
      <save>
        <region id="Config">
          <node id="root">
            <children>
              <node id="ModuleInfo">
                <attribute id="Author" value="..." />
                <attribute id="Description" value="..." />
                <attribute id="Name" value="..." />
                <attribute id="UUID" value="..." />
                <attribute id="Version64" value="..." />  <!-- preferred -->
                <attribute id="Version" value="..." />
              </node>
            </children>
          </node>
        </region>
      </save>
    """
    info: dict = {
        "uuid": None,
        "name": None,
        "author": None,
        "description": None,
        "version": None,
    }

    try:
        root = ET.fromstring(content.decode("utf-8", errors="replace"))
    except ET.ParseError:
        return info

    # Walk all <attribute> nodes; collect the first ModuleInfo we find.
    for node in root.iter("node"):
        if node.get("id") != "ModuleInfo":
            continue
        attrs: dict = {}
        for attr in node.findall("attribute"):
            aid = attr.get("id", "")
            val = attr.get("value", "")
            attrs[aid] = val

        info["uuid"] = attrs.get("UUID") or attrs.get("ModuleUUID")
        info["name"] = attrs.get("Name")
        info["author"] = attrs.get("Author")
        info["description"] = attrs.get("Description")
        # Prefer Version64 (numeric), fall back to Version string
        info["version"] = attrs.get("Version64") or attrs.get("Version")
        break

    return info


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class PakInspectorError(Exception):
    """Raised for PAK format or decompression errors."""


class PakReader:
    """LSPK v18 PAK archive reader.

    Usage::

        with PakReader("/path/to/mod.pak") as pak:
            files = pak.list_files()
            data  = pak.read_file("Mods/MyMod/meta.lsx")
            info  = pak.get_mod_info()
    """

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._fh = open(self._path, "rb")
        try:
            self._entries: list = []
            self._index: dict = {}       # name → list-index
            self._version: int = 0
            self._read_header()
        except Exception:
            self._fh.close()
            raise

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "PakReader":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def close(self) -> None:
        if self._fh and not self._fh.closed:
            self._fh.close()

    # ------------------------------------------------------------------
    # Internal initialisation
    # ------------------------------------------------------------------

    def _read_header(self) -> None:
        raw = self._fh.read(40)
        if len(raw) < 40:
            raise PakInspectorError("File too small to be a valid PAK archive.")

        magic = raw[:4]
        if magic != LSPK_MAGIC:
            raise PakInspectorError(
                f"Not an LSPK archive (magic={magic.hex()!r}, expected {LSPK_MAGIC.hex()!r})."
            )

        version = struct.unpack_from("<I", raw, 4)[0]
        if version != LSPK_VERSION:
            raise PakInspectorError(
                f"Unsupported LSPK version {version} (expected {LSPK_VERSION})."
            )
        self._version = version

        file_list_offset = struct.unpack_from("<Q", raw, 8)[0]
        # file_list_size at +16 is stored but we use the compressed_size
        # field inside the file list table itself, same as the C impl.

        self._fh.seek(file_list_offset)
        header2 = self._fh.read(8)
        if len(header2) < 8:
            raise PakInspectorError("Truncated file list header.")

        num_files = struct.unpack_from("<I", header2, 0)[0]
        compressed_size = struct.unpack_from("<I", header2, 4)[0]

        compressed = self._fh.read(compressed_size)
        if len(compressed) < compressed_size:
            raise PakInspectorError(
                f"Truncated file list data: read {len(compressed)}/{compressed_size} bytes."
            )

        raw_entries = _try_decompress_file_list(compressed, num_files)
        self._entries = _parse_entries(raw_entries, num_files)

        # Build name index for O(1) lookup
        for idx, entry in enumerate(self._entries):
            self._index[entry["name"]] = idx

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def list_files(self) -> list:
        """Return sorted list of all internal file paths in the archive."""
        return sorted(e["name"] for e in self._entries)

    def read_file(self, internal_path: str) -> bytes:
        """Read and decompress a file from the archive.

        Args:
            internal_path: File path as stored in the PAK (case-sensitive,
                forward-slash separated).

        Returns:
            Raw file contents as bytes.

        Raises:
            KeyError: If the path is not found in the archive.
            RuntimeError: If the entry uses LZ4 and lz4 is not installed.
            PakInspectorError: On read or decompression failure.
        """
        if internal_path not in self._index:
            # Try case-insensitive fallback before raising
            lower = internal_path.lower()
            for name in self._index:
                if name.lower() == lower:
                    internal_path = name
                    break
            else:
                raise KeyError(f"File not found in PAK: {internal_path!r}")

        entry = self._entries[self._index[internal_path]]

        self._fh.seek(entry["offset"])
        disk_data = self._fh.read(entry["disk_size"])
        if len(disk_data) < entry["disk_size"]:
            raise PakInspectorError(
                f"Truncated entry data for {internal_path!r}: "
                f"read {len(disk_data)}/{entry['disk_size']} bytes."
            )

        try:
            return _decompress_entry(disk_data, entry["compression"], entry["uncompressed_size"])
        except RuntimeError:
            raise
        except Exception as exc:
            raise PakInspectorError(
                f"Decompression failed for {internal_path!r}: {exc}"
            ) from exc

    def get_mod_info(self) -> dict:
        """Extract mod metadata from the archive's meta.lsx.

        Searches for any entry whose name ends with 'meta.lsx' (case-insensitive).

        Returns:
            dict with keys: uuid, name, author, description, version, meta_path.
            Values are None when not found.
        """
        meta_path = None
        for name in self._index:
            if name.lower().endswith("meta.lsx"):
                meta_path = name
                break

        if meta_path is None:
            return {
                "uuid": None, "name": None, "author": None,
                "description": None, "version": None, "meta_path": None,
            }

        try:
            content = self.read_file(meta_path)
        except (KeyError, PakInspectorError, RuntimeError):
            return {
                "uuid": None, "name": None, "author": None,
                "description": None, "version": None,
                "meta_path": meta_path,
            }

        info = _extract_mod_info_from_lsx(content)
        info["meta_path"] = meta_path
        return info


# ---------------------------------------------------------------------------
# CLI entry point (JSON to stdout, matching harness convention)
# ---------------------------------------------------------------------------

def _cmd_list(args) -> int:
    try:
        with PakReader(args.pak) as pak:
            files = pak.list_files()
    except (PakInspectorError, OSError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    print(json.dumps({"files": files, "count": len(files)}, indent=2))
    return 0


def _cmd_info(args) -> int:
    try:
        with PakReader(args.pak) as pak:
            info = pak.get_mod_info()
    except (PakInspectorError, OSError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    print(json.dumps(info, indent=2))
    return 0


def _cmd_extract(args) -> int:
    try:
        with PakReader(args.pak) as pak:
            data = pak.read_file(args.file)
    except KeyError as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    except (PakInspectorError, OSError, RuntimeError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    # Write to stdout as raw bytes
    import sys
    sys.stdout.buffer.write(data)
    return 0


def main(argv=None) -> int:
    import argparse, sys as _sys

    parser = argparse.ArgumentParser(
        prog="pak_inspector",
        description="LSPK v18 PAK file inspector",
    )
    sub = parser.add_subparsers(dest="command")

    p_list = sub.add_parser("list", help="List all files in a PAK")
    p_list.add_argument("pak")

    p_info = sub.add_parser("info", help="Extract mod metadata from meta.lsx")
    p_info.add_argument("pak")

    p_ext = sub.add_parser("extract", help="Extract a single file (raw to stdout)")
    p_ext.add_argument("pak")
    p_ext.add_argument("file")

    args = parser.parse_args(argv)

    if args.command == "list":
        return _cmd_list(args)
    if args.command == "info":
        return _cmd_info(args)
    if args.command == "extract":
        return _cmd_extract(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
