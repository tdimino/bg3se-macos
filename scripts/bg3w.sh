#!/bin/bash
# BG3SE-macOS Steam Launch Script
# Steam launch options: /Users/tomdimino/Desktop/Programming/bg3se-macos/scripts/bg3w.sh %command%
#
# Steam passes the .app bundle path, but we need to run the actual executable
# inside Contents/MacOS/ for DYLD_INSERT_LIBRARIES to work.

# Debug output
echo "=== BG3W Launch Script ===" >> /tmp/bg3w_debug.log
echo "Date: $(date)" >> /tmp/bg3w_debug.log
echo "Args: $@" >> /tmp/bg3w_debug.log

# Get the first argument (should be the .app bundle path)
APP_PATH="$1"
shift  # Remove first arg, keep any additional args

# If it's a .app bundle, extract the actual executable
if [[ "$APP_PATH" == *.app ]]; then
    EXEC_PATH="${APP_PATH}/Contents/MacOS/Baldur's Gate 3"
    echo "Detected .app bundle, using executable: $EXEC_PATH" >> /tmp/bg3w_debug.log
else
    EXEC_PATH="$APP_PATH"
    echo "Using path directly: $EXEC_PATH" >> /tmp/bg3w_debug.log
fi

# Verify executable exists
if [[ ! -f "$EXEC_PATH" ]]; then
    echo "ERROR: Executable not found: $EXEC_PATH" >> /tmp/bg3w_debug.log
    exit 1
fi

DYLIB="/Users/tomdimino/Desktop/Programming/bg3se-macos/build/lib/libbg3se.dylib"

echo "DYLIB exists: $(ls -la $DYLIB 2>&1)" >> /tmp/bg3w_debug.log
echo "Forcing ARM64 architecture with inline DYLD_INSERT_LIBRARIES" >> /tmp/bg3w_debug.log
echo "===========================" >> /tmp/bg3w_debug.log

# Force ARM64 architecture with inline env var (export doesn't work with arch)
exec arch -arm64 env DYLD_INSERT_LIBRARIES="$DYLIB" "$EXEC_PATH" "$@"
