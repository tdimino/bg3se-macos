#!/bin/bash
#
# Build script for BG3SE-macOS
# Builds universal binary (ARM64 + x86_64)
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

# Check for git submodules
if [ ! -f "${LIB_DIR}/Dobby/CMakeLists.txt" ]; then
    echo ""
    echo "ERROR: Dobby submodule not initialized!"
    echo ""
    echo "Run: git submodule update --init --recursive"
    echo ""
    echo "Or clone with: git clone --recursive https://github.com/tdimino/bg3se-macos.git"
    exit 1
fi

# NOTE: This script is deprecated. Use CMake instead:
#   mkdir -p build && cd build && cmake .. && cmake --build .
echo ""
echo "NOTE: Consider using CMake for a full build:"
echo "  mkdir -p build && cd build && cmake .. && cmake --build ."
echo ""

# Create build directory
mkdir -p "${BUILD_DIR}/lib"
mkdir -p "${BUILD_DIR}/obj"

# Check for Lua library
LUA_LIB="${LIB_DIR}/lua/liblua-universal.a"
if [ ! -f "$LUA_LIB" ]; then
    echo ""
    echo "Lua universal library not found. Building..."
    cd "${LIB_DIR}/lua"
    chmod +x build_universal.sh
    ./build_universal.sh
    cd "${PROJECT_ROOT}"
fi

# Check for Dobby library
DOBBY_LIB="${LIB_DIR}/Dobby/libdobby-universal.a"
if [ ! -f "$DOBBY_LIB" ]; then
    echo ""
    echo "Dobby universal library not found. Building..."

    # Build ARM64
    echo "  Building Dobby for ARM64..."
    cd "${LIB_DIR}/Dobby"
    mkdir -p build-arm64
    cd build-arm64
    cmake .. -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_BUILD_TYPE=Release > /dev/null 2>&1
    make -j8 > /dev/null 2>&1

    # Build x86_64
    echo "  Building Dobby for x86_64..."
    cd "${LIB_DIR}/Dobby"
    mkdir -p build-x86_64
    cd build-x86_64
    cmake .. -DCMAKE_OSX_ARCHITECTURES=x86_64 -DCMAKE_BUILD_TYPE=Release > /dev/null 2>&1
    make -j8 > /dev/null 2>&1

    # Create universal library
    echo "  Creating universal library..."
    cd "${LIB_DIR}/Dobby"
    lipo -create build-arm64/libdobby.a build-x86_64/libdobby.a -output libdobby-universal.a

    echo "  Dobby built successfully!"
    cd "${PROJECT_ROOT}"
fi

# Source files
SOURCES=(
    "${SRC_DIR}/injector/main.c"
)

echo ""
echo "Compiling sources for universal binary (ARM64 + x86_64)..."
for src in "${SOURCES[@]}"; do
    echo "  - $(basename "$src")"
done

# Compile universal binary with Dobby, Lua, and LZ4
clang++ \
    -arch x86_64 \
    -arch arm64 \
    -dynamiclib \
    -o "${BUILD_DIR}/lib/libbg3se.dylib" \
    -I"${SRC_DIR}" \
    -I"${LIB_DIR}" \
    -I"${LIB_DIR}/lua/src" \
    -L"${LIB_DIR}/Dobby" \
    -Wall -Wextra \
    -O2 \
    -fvisibility=hidden \
    "${SOURCES[@]}" \
    "${LIB_DIR}/lz4/lz4.c" \
    "${DOBBY_LIB}" \
    "${LUA_LIB}" \
    -lz \
    -lc++

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
