#!/bin/bash
#
# Build script for BG3SE-macOS
# Builds x86_64 binary (BG3 runs under Rosetta)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_ROOT}/build"
SRC_DIR="${PROJECT_ROOT}/src"
LIB_DIR="${PROJECT_ROOT}/lib"

echo "=========================================="
echo "Building BG3SE-macOS"
echo "=========================================="

# Create build directory
mkdir -p "${BUILD_DIR}/lib"
mkdir -p "${BUILD_DIR}/obj"

# Source files - minimal build
SOURCES=(
    "${SRC_DIR}/injector/main.c"
)

echo ""
echo "Compiling sources for x86_64..."
for src in "${SOURCES[@]}"; do
    echo "  - $(basename "$src")"
done

# Compile for x86_64 (BG3 runs under Rosetta)
clang \
    -arch x86_64 \
    -dynamiclib \
    -o "${BUILD_DIR}/lib/libbg3se.dylib" \
    -I"${SRC_DIR}" \
    -I"${LIB_DIR}" \
    -Wall -Wextra \
    -O2 \
    -fvisibility=hidden \
    -undefined dynamic_lookup \
    "${SOURCES[@]}"

echo ""
echo "Build successful!"
echo ""

# Show info about the built dylib
echo "=== Build Output ==="
echo "Location: ${BUILD_DIR}/lib/libbg3se.dylib"
echo ""
echo "Architecture:"
file "${BUILD_DIR}/lib/libbg3se.dylib"
echo ""
echo "Size: $(ls -lh "${BUILD_DIR}/lib/libbg3se.dylib" | awk '{print $5}')"
echo ""
echo "Dependencies:"
otool -L "${BUILD_DIR}/lib/libbg3se.dylib" | head -10
echo ""
echo "=========================================="
echo "To test: Launch BG3 via Steam with wrapper"
echo "Steam launch options: /tmp/bg3w.sh %command%"
echo "=========================================="
