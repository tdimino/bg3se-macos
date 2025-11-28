#!/usr/bin/env python3
"""
BG3 PAK (LSPK v18) Extractor for macOS
Extracts .pak files from Baldur's Gate 3 mods

Part of the BG3SE-macOS project.

Usage:
    python3 extract_pak.py <file.pak> [output_dir]

Requirements:
    pip3 install lz4

Based on LSPK format documentation:
- Signature: "LSPK" (0x4b50534c)
- Version: 18 for BG3
- File list is LZ4 compressed
- Individual files may be uncompressed, zlib, or LZ4 compressed
"""

import struct
import sys
import os

try:
    import lz4.block
except ImportError:
    print("Error: lz4 module not found. Install it with: pip3 install lz4")
    sys.exit(1)

import zlib


def read_header(f):
    """Read LSPK header (40 bytes)"""
    data = f.read(40)
    if len(data) < 40:
        raise ValueError("File too small for header")

    signature = struct.unpack('<I', data[0:4])[0]
    if signature != 0x4b50534c:  # "LSPK"
        raise ValueError(f"Invalid signature: {hex(signature)}, expected LSPK")

    version = struct.unpack('<I', data[4:8])[0]
    file_list_offset = struct.unpack('<Q', data[8:16])[0]
    file_list_size = struct.unpack('<I', data[16:20])[0]
    flags = data[20]
    priority = data[21]
    md5 = data[22:38]
    num_parts = struct.unpack('<H', data[38:40])[0]

    return {
        'version': version,
        'file_list_offset': file_list_offset,
        'file_list_size': file_list_size,
        'flags': flags,
        'priority': priority,
        'num_parts': num_parts
    }


def read_file_list(f, header):
    """Read and decompress file list"""
    f.seek(header['file_list_offset'])

    num_files = struct.unpack('<I', f.read(4))[0]
    compressed_size = struct.unpack('<I', f.read(4))[0]

    compressed_data = f.read(compressed_size)

    # File list is LZ4 compressed
    # Each entry is 272 bytes
    uncompressed_size = num_files * 272

    try:
        decompressed = lz4.block.decompress(compressed_data, uncompressed_size=uncompressed_size)
    except Exception as e:
        raise ValueError(f"LZ4 decompression of file list failed: {e}")

    entries = []
    for i in range(num_files):
        offset = i * 272
        entry_data = decompressed[offset:offset + 272]

        # Name: 256 bytes UTF-8, null-terminated
        name_bytes = entry_data[0:256]
        name = name_bytes.split(b'\x00')[0].decode('utf-8', errors='replace')

        # Offset: 48-bit value split across bytes 256-261
        offset_lo = struct.unpack('<I', entry_data[256:260])[0]
        offset_hi = struct.unpack('<H', entry_data[260:262])[0]
        file_offset = offset_lo | (offset_hi << 32)

        archive_part = entry_data[262]
        flags = entry_data[263]
        compression = flags & 0x0F  # Lower 4 bits

        disk_size = struct.unpack('<I', entry_data[264:268])[0]
        uncompressed_size = struct.unpack('<I', entry_data[268:272])[0]

        entries.append({
            'name': name,
            'offset': file_offset,
            'archive_part': archive_part,
            'compression': compression,
            'disk_size': disk_size,
            'uncompressed_size': uncompressed_size
        })

    return entries


def extract_file(f, entry, output_dir):
    """Extract a single file from the archive"""
    f.seek(entry['offset'])
    data = f.read(entry['disk_size'])

    compression_names = {0: 'none', 1: 'zlib', 2: 'LZ4'}

    if entry['compression'] == 0:
        # Uncompressed
        content = data
    elif entry['compression'] == 1:
        # zlib
        try:
            content = zlib.decompress(data)
        except zlib.error as e:
            raise ValueError(f"zlib decompression failed: {e}")
    elif entry['compression'] == 2:
        # LZ4
        try:
            content = lz4.block.decompress(data, uncompressed_size=entry['uncompressed_size'])
        except Exception as e:
            raise ValueError(f"LZ4 decompression failed: {e}")
    else:
        print(f"  WARNING: Unknown compression type {entry['compression']} for {entry['name']}, saving raw")
        content = data

    # Create output path
    output_path = os.path.join(output_dir, entry['name'])
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, 'wb') as out:
        out.write(content)

    return len(content), compression_names.get(entry['compression'], f"unknown({entry['compression']})")


def main():
    if len(sys.argv) < 2:
        print("BG3 PAK Extractor")
        print("Usage: extract_pak.py <file.pak> [output_dir]")
        print("")
        print("Extracts .pak files from Baldur's Gate 3 mods (LSPK v18 format)")
        sys.exit(1)

    pak_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else pak_file.replace('.pak', '_extracted')

    if not os.path.exists(pak_file):
        print(f"Error: File not found: {pak_file}")
        sys.exit(1)

    print(f"Extracting: {pak_file}")
    print(f"Output: {output_dir}")
    print("")

    with open(pak_file, 'rb') as f:
        header = read_header(f)
        print(f"LSPK version: {header['version']}")
        print(f"File list offset: {header['file_list_offset']}")
        print("")

        entries = read_file_list(f, header)
        print(f"Files: {len(entries)}")
        print("-" * 60)

        os.makedirs(output_dir, exist_ok=True)

        success_count = 0
        error_count = 0

        for entry in entries:
            try:
                size, compression = extract_file(f, entry, output_dir)
                print(f"  [{compression:4}] {entry['name']} ({size:,} bytes)")
                success_count += 1
            except Exception as e:
                print(f"  ERROR: {entry['name']}: {e}")
                error_count += 1

        print("-" * 60)
        print(f"Extracted: {success_count}/{len(entries)} files")
        if error_count > 0:
            print(f"Errors: {error_count}")


if __name__ == '__main__':
    main()
