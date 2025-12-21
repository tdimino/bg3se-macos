#!/bin/bash
#
# Force rebuild BG3SE-macOS (bypasses CMake cache)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${PROJECT_ROOT}/build"

cd "$BUILD_DIR"

# Touch all source files to force recompilation
echo "Forcing recompilation of all sources..."
find "$PROJECT_ROOT/src" -name "*.c" -o -name "*.m" | xargs touch

# Build
echo "Building..."
cmake --build . 2>&1 | tail -20

echo ""
echo "Done! Restart game to load new dylib."
