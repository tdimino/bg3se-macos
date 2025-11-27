#!/bin/bash
#
# Build script for BG3SE-macOS
# Builds universal binary (arm64 + x86_64)
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

# Source files
SOURCES=(
    "${SRC_DIR}/injector/main.c"
    "${SRC_DIR}/hooks/osiris_hooks.c"
    "${LIB_DIR}/fishhook/fishhook.c"
)

# Compile for universal binary
echo "Compiling sources..."
for src in "${SOURCES[@]}"; do
    echo "  - $(basename "$src")"
done

clang \
    -arch arm64 \
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
echo "To test: ./scripts/launch_bg3.sh"
echo "=========================================="
